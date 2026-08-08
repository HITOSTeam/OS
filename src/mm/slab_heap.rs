//! Small-object slab layer backed by the kernel buddy heap.
//!
//! Linux routes small `kmalloc` allocations through size-class caches and
//! obtains their backing slabs from the page allocator.  Keep the same split
//! here without reproducing unrelated NUMA/debug machinery: each heap shard
//! owns partial-page lists, free objects store an intrusive one-way link, and
//! a completely empty page is returned to the buddy immediately.

use super::buddy_heap::BuddyHeap;
use core::{alloc::Layout, ptr::NonNull};

pub(crate) const SLAB_PAGE_SIZE: usize = 4096;
pub(crate) const SLAB_CLASS_SIZES: [usize; 11] =
    [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048];
pub(crate) const SLAB_CLASS_COUNT: usize = SLAB_CLASS_SIZES.len();

/// Per-page state analogous to Linux's `struct slab` essentials.
///
/// Page and object links are one-based so the all-zero value is an inactive
/// page and remains in `.bss`.  A heap shard has at most 16,384 pages and a
/// 4-KiB slab has at most 512 objects, so `u16` covers both link domains.
#[derive(Clone, Copy)]
struct SlabPage {
    next_partial: u16,
    prev_partial: u16,
    free_head: u16,
    in_use: u16,
    class_plus_one: u8,
    on_partial: u8,
}

impl SlabPage {
    const fn empty() -> Self {
        Self {
            next_partial: 0,
            prev_partial: 0,
            free_head: 0,
            in_use: 0,
            class_plus_one: 0,
            on_partial: 0,
        }
    }

    fn class_index(self) -> Option<usize> {
        (self.class_plus_one != 0).then(|| self.class_plus_one as usize - 1)
    }
}

const _: () = assert!(size_of::<SlabPage>() <= 12);
const _: () = assert!(SLAB_CLASS_COUNT < u8::MAX as usize);
const _: () = assert!(SLAB_PAGE_SIZE.is_power_of_two());
const _: () = assert!(SLAB_PAGE_SIZE / SLAB_CLASS_SIZES[0] <= u16::MAX as usize);

/// A Linux-style small-object slab front-end over an O(1) buddy allocator.
pub(crate) struct SlabHeap<const FREE_BITMAP_WORDS: usize, const PAGE_METADATA_COUNT: usize> {
    buddy: BuddyHeap<FREE_BITMAP_WORDS>,
    pages: [SlabPage; PAGE_METADATA_COUNT],
    partial_heads: [u16; SLAB_CLASS_COUNT],
    slab_live: [usize; SLAB_CLASS_COUNT],
    slab_user: [usize; SLAB_CLASS_COUNT],
    slab_pages: [usize; SLAB_CLASS_COUNT],
    start: usize,
    end: usize,
}

impl<const FREE_BITMAP_WORDS: usize, const PAGE_METADATA_COUNT: usize>
    SlabHeap<FREE_BITMAP_WORDS, PAGE_METADATA_COUNT>
{
    pub(crate) const fn new() -> Self {
        Self {
            buddy: BuddyHeap::new(),
            pages: [SlabPage::empty(); PAGE_METADATA_COUNT],
            partial_heads: [0; SLAB_CLASS_COUNT],
            slab_live: [0; SLAB_CLASS_COUNT],
            slab_user: [0; SLAB_CLASS_COUNT],
            slab_pages: [0; SLAB_CLASS_COUNT],
            start: 0,
            end: 0,
        }
    }

    /// Initialize this allocator over a page-aligned exclusive range.
    ///
    /// # Safety
    ///
    /// The range must remain exclusively owned by this heap until every
    /// allocation has been returned.
    pub(crate) unsafe fn init(&mut self, start: usize, size: usize) {
        assert_eq!(
            start % SLAB_PAGE_SIZE,
            0,
            "slab heap start is not page aligned"
        );
        assert_eq!(
            size % SLAB_PAGE_SIZE,
            0,
            "slab heap size is not page aligned"
        );
        let page_count = size / SLAB_PAGE_SIZE;
        assert!(
            page_count <= PAGE_METADATA_COUNT,
            "slab page metadata array is too small"
        );
        assert!(
            PAGE_METADATA_COUNT < u16::MAX as usize,
            "slab page links exceed u16 capacity"
        );
        let end = start
            .checked_add(size)
            .expect("slab heap range overflows usize");

        // SAFETY: the caller gives this wrapper exclusive ownership of the
        // same range passed to its backing buddy allocator.
        unsafe {
            self.buddy.init(start, size);
        }
        self.pages.fill(SlabPage::empty());
        self.partial_heads = [0; SLAB_CLASS_COUNT];
        self.slab_live = [0; SLAB_CLASS_COUNT];
        self.slab_user = [0; SLAB_CLASS_COUNT];
        self.slab_pages = [0; SLAB_CLASS_COUNT];
        self.start = start;
        self.end = end;
    }

    pub(crate) fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        if let Some(class_index) = Self::class_for_layout(layout) {
            self.alloc_slab(class_index, layout.size())
        } else {
            self.buddy.alloc(layout)
        }
    }

    /// Return one allocation obtained from [`Self::alloc`].
    ///
    /// # Safety
    ///
    /// `ptr` must be a live allocation from this heap and `layout` must be the
    /// same layout used for that allocation.
    pub(crate) unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) {
        if let Some(class_index) = Self::class_for_layout(layout) {
            // SAFETY: the caller supplies the original pointer and layout;
            // deterministic class selection routes it to its slab page.
            unsafe {
                self.dealloc_slab(ptr, class_index, layout.size());
            }
        } else {
            // SAFETY: non-slab layouts are allocated directly by this buddy.
            unsafe {
                self.buddy.dealloc(ptr, layout);
            }
        }
    }

    pub(crate) fn stats_alloc_user(&self) -> usize {
        let slab_backing = self
            .slab_pages
            .iter()
            .copied()
            .sum::<usize>()
            .saturating_mul(SLAB_PAGE_SIZE);
        let direct_user = self
            .buddy
            .stats_alloc_user()
            .checked_sub(slab_backing)
            .expect("slab backing exceeds buddy user accounting");
        direct_user.saturating_add(self.slab_user.iter().copied().sum::<usize>())
    }

    /// Physical heap bytes reserved by direct buddy blocks and slab pages.
    pub(crate) fn stats_alloc_actual(&self) -> usize {
        self.buddy.stats_alloc_actual()
    }

    pub(crate) fn stats_total_bytes(&self) -> usize {
        self.buddy.stats_total_bytes()
    }

    pub(crate) fn stats_order(&self, order: usize) -> (usize, usize, usize) {
        self.buddy.stats_order(order)
    }

    pub(crate) fn stats_slab_class(&self, class_index: usize) -> (usize, usize, usize) {
        (
            self.slab_live[class_index],
            self.slab_user[class_index],
            self.slab_pages[class_index],
        )
    }

    fn class_for_layout(layout: Layout) -> Option<usize> {
        SLAB_CLASS_SIZES
            .iter()
            .position(|&class_size| class_size >= layout.size() && class_size % layout.align() == 0)
    }

    fn page_layout() -> Layout {
        // SAFETY: 4096 is a non-zero power of two and the size is its multiple.
        unsafe { Layout::from_size_align_unchecked(SLAB_PAGE_SIZE, SLAB_PAGE_SIZE) }
    }

    fn alloc_slab(&mut self, class_index: usize, requested_size: usize) -> Result<NonNull<u8>, ()> {
        if self.partial_heads[class_index] == 0 {
            self.allocate_slab_page(class_index)?;
        }

        let page_index = Self::index_for_page_link(self.partial_heads[class_index]);
        let page = self.pages[page_index];
        debug_assert_eq!(page.class_index(), Some(class_index));
        debug_assert_ne!(page.on_partial, 0);
        assert_ne!(page.free_head, 0, "partial slab page has no free object");

        let class_size = SLAB_CLASS_SIZES[class_index];
        let page_start = self.start + page_index * SLAB_PAGE_SIZE;
        let object_index = page.free_head as usize - 1;
        let object_address = page_start + object_index * class_size;
        // SAFETY: a free object is exclusively owned by the allocator and its
        // first two bytes contain the next one-based object link.
        let next_free = unsafe { (object_address as *const u16).read() };

        self.pages[page_index].free_head = next_free;
        self.pages[page_index].in_use = self.pages[page_index]
            .in_use
            .checked_add(1)
            .expect("slab in-use count overflow");
        if next_free == 0 {
            self.remove_partial(class_index, page_index);
        }
        self.slab_live[class_index] = self.slab_live[class_index].saturating_add(1);
        self.slab_user[class_index] = self.slab_user[class_index].saturating_add(requested_size);

        // SAFETY: the selected free object is inside a live backing page and
        // has just been removed from its free list.
        Ok(unsafe { NonNull::new_unchecked(object_address as *mut u8) })
    }

    fn allocate_slab_page(&mut self, class_index: usize) -> Result<(), ()> {
        let page_ptr = self.buddy.alloc(Self::page_layout())?;
        let page_start = page_ptr.as_ptr() as usize;
        assert_eq!(
            page_start % SLAB_PAGE_SIZE,
            0,
            "buddy returned unaligned slab page"
        );
        let page_index = self.page_index_for_address(page_start);
        assert_eq!(
            self.pages[page_index].class_index(),
            None,
            "buddy returned an active slab page"
        );

        let class_size = SLAB_CLASS_SIZES[class_index];
        let capacity = SLAB_PAGE_SIZE / class_size;
        assert!(capacity > 0 && capacity <= u16::MAX as usize);
        for object_index in 0..capacity {
            let object_address = page_start + object_index * class_size;
            let next = if object_index + 1 < capacity {
                (object_index + 2) as u16
            } else {
                0
            };
            // SAFETY: the newly allocated page is exclusive, every class is
            // at least 8-byte aligned, and these object starts are disjoint.
            unsafe {
                (object_address as *mut u16).write(next);
            }
        }

        self.pages[page_index] = SlabPage {
            next_partial: 0,
            prev_partial: 0,
            free_head: 1,
            in_use: 0,
            class_plus_one: (class_index + 1) as u8,
            on_partial: 0,
        };
        self.slab_pages[class_index] = self.slab_pages[class_index].saturating_add(1);
        self.insert_partial(class_index, page_index);
        Ok(())
    }

    unsafe fn dealloc_slab(&mut self, ptr: NonNull<u8>, class_index: usize, requested_size: usize) {
        let address = ptr.as_ptr() as usize;
        let page_start = address & !(SLAB_PAGE_SIZE - 1);
        let page_index = self.page_index_for_address(page_start);
        let page = self.pages[page_index];
        assert_eq!(
            page.class_index(),
            Some(class_index),
            "slab deallocation class does not match its page"
        );

        let class_size = SLAB_CLASS_SIZES[class_index];
        let object_offset = address
            .checked_sub(page_start)
            .expect("slab object precedes its page");
        assert_eq!(
            object_offset % class_size,
            0,
            "slab deallocation is not at an object boundary"
        );
        let object_index = object_offset / class_size;
        assert!(
            object_index < SLAB_PAGE_SIZE / class_size,
            "slab deallocation is outside the page's objects"
        );

        let was_full = page.free_head == 0;
        // SAFETY: the caller gives back exclusive ownership of this live
        // object, so its first two bytes may again hold the freelist link.
        unsafe {
            (address as *mut u16).write(page.free_head);
        }
        self.pages[page_index].free_head = (object_index + 1) as u16;
        self.pages[page_index].in_use = page
            .in_use
            .checked_sub(1)
            .expect("slab in-use count underflow");
        self.slab_live[class_index] = self.slab_live[class_index]
            .checked_sub(1)
            .expect("slab live count underflow");
        self.slab_user[class_index] = self.slab_user[class_index]
            .checked_sub(requested_size)
            .expect("slab user-byte count underflow");

        if was_full {
            self.insert_partial(class_index, page_index);
        }
        if self.pages[page_index].in_use == 0 {
            self.remove_partial(class_index, page_index);
            self.pages[page_index] = SlabPage::empty();
            self.slab_pages[class_index] = self.slab_pages[class_index]
                .checked_sub(1)
                .expect("slab page count underflow");
            // SAFETY: the page contains no live slab objects and is the exact
            // page allocation obtained from this backing buddy.
            unsafe {
                self.buddy.dealloc(
                    NonNull::new_unchecked(page_start as *mut u8),
                    Self::page_layout(),
                );
            }
        }
    }

    fn insert_partial(&mut self, class_index: usize, page_index: usize) {
        assert_eq!(
            self.pages[page_index].on_partial, 0,
            "slab page inserted into partial list twice"
        );
        let page_link = Self::page_link_for_index(page_index);
        let old_head = self.partial_heads[class_index];
        self.pages[page_index].prev_partial = 0;
        self.pages[page_index].next_partial = old_head;
        self.pages[page_index].on_partial = 1;
        if old_head != 0 {
            let old_head_index = Self::index_for_page_link(old_head);
            self.pages[old_head_index].prev_partial = page_link;
        }
        self.partial_heads[class_index] = page_link;
    }

    fn remove_partial(&mut self, class_index: usize, page_index: usize) {
        assert_ne!(
            self.pages[page_index].on_partial, 0,
            "slab page removed while absent from partial list"
        );
        let page = self.pages[page_index];
        if page.prev_partial == 0 {
            assert_eq!(
                self.partial_heads[class_index],
                Self::page_link_for_index(page_index)
            );
            self.partial_heads[class_index] = page.next_partial;
        } else {
            let prev_index = Self::index_for_page_link(page.prev_partial);
            self.pages[prev_index].next_partial = page.next_partial;
        }
        if page.next_partial != 0 {
            let next_index = Self::index_for_page_link(page.next_partial);
            self.pages[next_index].prev_partial = page.prev_partial;
        }
        self.pages[page_index].next_partial = 0;
        self.pages[page_index].prev_partial = 0;
        self.pages[page_index].on_partial = 0;
    }

    fn page_index_for_address(&self, address: usize) -> usize {
        let offset = address
            .checked_sub(self.start)
            .expect("slab page precedes heap start");
        assert!(address < self.end, "slab page is beyond heap end");
        assert_eq!(offset % SLAB_PAGE_SIZE, 0, "slab page is not aligned");
        let index = offset / SLAB_PAGE_SIZE;
        assert!(
            index < PAGE_METADATA_COUNT,
            "slab page metadata index overflow"
        );
        index
    }

    fn page_link_for_index(index: usize) -> u16 {
        u16::try_from(index + 1).expect("slab page link exceeds u16")
    }

    fn index_for_page_link(link: u16) -> usize {
        assert_ne!(link, 0, "null slab page link has no index");
        link as usize - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buddy_heap::MIN_BLOCK_SIZE;
    use std::alloc::{alloc_zeroed, dealloc};

    const REGION_SIZE: usize = 1 << 20;
    const REGION_PAGES: usize = REGION_SIZE / SLAB_PAGE_SIZE;
    const BITMAP_WORDS: usize = REGION_SIZE / MIN_BLOCK_SIZE / u64::BITS as usize;

    struct TestRegion {
        ptr: NonNull<u8>,
        layout: Layout,
    }

    impl TestRegion {
        fn new() -> Self {
            let layout = Layout::from_size_align(REGION_SIZE, REGION_SIZE).expect("test layout");
            // SAFETY: the layout is valid and non-zero.
            let ptr = unsafe { NonNull::new(alloc_zeroed(layout)) }
                .expect("host allocation for slab test failed");
            Self { ptr, layout }
        }
    }

    impl Drop for TestRegion {
        fn drop(&mut self) {
            // SAFETY: this is the original host allocation and layout.
            unsafe {
                dealloc(self.ptr.as_ptr(), self.layout);
            }
        }
    }

    fn new_heap(region: &TestRegion) -> SlabHeap<BITMAP_WORDS, REGION_PAGES> {
        let mut heap = SlabHeap::new();
        // SAFETY: the region remains live and exclusively owned by the test.
        unsafe {
            heap.init(region.ptr.as_ptr() as usize, REGION_SIZE);
        }
        heap
    }

    #[test]
    fn follows_linux_kmalloc_classes_and_layout_alignment() {
        let cases = [
            (1, 1, 8),
            (24, 8, 32),
            (65, 8, 96),
            (97, 8, 128),
            (129, 8, 192),
            (193, 8, 256),
            (65, 64, 128),
            (129, 128, 256),
            (1025, 1024, 2048),
        ];
        for (size, align, expected) in cases {
            let layout = Layout::from_size_align(size, align).expect("valid layout");
            let class = SlabHeap::<BITMAP_WORDS, REGION_PAGES>::class_for_layout(layout)
                .expect("small layout has a slab class");
            assert_eq!(SLAB_CLASS_SIZES[class], expected);
        }

        let page_aligned = Layout::from_size_align(1, SLAB_PAGE_SIZE).expect("valid layout");
        assert_eq!(
            SlabHeap::<BITMAP_WORDS, REGION_PAGES>::class_for_layout(page_aligned),
            None
        );
    }

    #[test]
    fn packs_objects_and_returns_empty_pages_to_buddy() {
        let region = TestRegion::new();
        let mut heap = new_heap(&region);
        let layout = Layout::from_size_align(33, 8).expect("valid layout");
        let mut allocations = Vec::new();
        for _ in 0..70 {
            allocations.push(heap.alloc(layout).expect("slab allocation"));
        }

        let class = SlabHeap::<BITMAP_WORDS, REGION_PAGES>::class_for_layout(layout).unwrap();
        assert_eq!(SLAB_CLASS_SIZES[class], 64);
        assert_eq!(heap.stats_slab_class(class), (70, 70 * 33, 2));
        assert_eq!(heap.stats_alloc_user(), 70 * 33);
        assert_eq!(heap.stats_alloc_actual(), 2 * SLAB_PAGE_SIZE);

        for allocation in allocations.into_iter().rev() {
            // SAFETY: every pointer is live and uses its original layout.
            unsafe {
                heap.dealloc(allocation, layout);
            }
        }
        assert_eq!(heap.stats_alloc_user(), 0);
        assert_eq!(heap.stats_alloc_actual(), 0);

        let whole = Layout::from_size_align(REGION_SIZE, REGION_SIZE).expect("whole layout");
        let allocation = heap.alloc(whole).expect("fully coalesced buddy range");
        assert_eq!(allocation, region.ptr);
    }

    #[test]
    fn full_page_reenters_partial_list_on_first_free() {
        let region = TestRegion::new();
        let mut heap = new_heap(&region);
        let layout = Layout::from_size_align(64, 8).expect("valid layout");
        let capacity = SLAB_PAGE_SIZE / 64;
        let mut allocations = Vec::new();
        for _ in 0..=capacity {
            allocations.push(heap.alloc(layout).expect("slab allocation"));
        }

        let first = allocations[0];
        // SAFETY: `first` is a live object in the now-full first page.
        unsafe {
            heap.dealloc(first, layout);
        }
        let replacement = heap.alloc(layout).expect("reuse first free from full page");
        assert_eq!(replacement, first);

        // SAFETY: replacement owns the first slot; every remaining original
        // allocation is distinct and still live.
        unsafe {
            heap.dealloc(replacement, layout);
            for allocation in allocations.into_iter().skip(1) {
                heap.dealloc(allocation, layout);
            }
        }
        assert_eq!(heap.stats_alloc_actual(), 0);
    }

    #[test]
    fn mixed_slab_and_buddy_churn_preserves_objects_and_coalesces() {
        let region = TestRegion::new();
        let mut heap = new_heap(&region);
        let layouts = [
            Layout::from_size_align(1, 1).unwrap(),
            Layout::from_size_align(24, 8).unwrap(),
            Layout::from_size_align(65, 8).unwrap(),
            Layout::from_size_align(97, 64).unwrap(),
            Layout::from_size_align(129, 8).unwrap(),
            Layout::from_size_align(193, 128).unwrap(),
            Layout::from_size_align(511, 8).unwrap(),
            Layout::from_size_align(1000, 256).unwrap(),
            Layout::from_size_align(1500, 1024).unwrap(),
            Layout::from_size_align(2049, 4096).unwrap(),
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut live = Vec::new();

        for step in 0..20_000usize {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let should_free = !live.is_empty() && (state >> 61) == 0;
            if should_free {
                let index = (state as usize) % live.len();
                let (ptr, layout, pattern): (NonNull<u8>, Layout, u8) = live.swap_remove(index);
                // SAFETY: the allocation is live; its requested range was
                // initialized with `pattern` and has not been freed yet.
                unsafe {
                    assert_eq!(ptr.as_ptr().read(), pattern);
                    assert_eq!(ptr.as_ptr().add(layout.size() - 1).read(), pattern);
                    heap.dealloc(ptr, layout);
                }
                continue;
            }

            let layout = layouts[(state as usize) % layouts.len()];
            if let Ok(ptr) = heap.alloc(layout) {
                assert_eq!(ptr.as_ptr() as usize % layout.align(), 0);
                let pattern = (step as u8).wrapping_mul(37).wrapping_add(11);
                // SAFETY: the allocator returned at least `layout.size()`
                // writable bytes exclusively to this test.
                unsafe {
                    ptr.as_ptr().write_bytes(pattern, layout.size());
                }
                live.push((ptr, layout, pattern));
            } else if !live.is_empty() {
                let (ptr, layout, pattern): (NonNull<u8>, Layout, u8) = live.swap_remove(0);
                // SAFETY: this is a live allocation with its original layout.
                unsafe {
                    assert_eq!(ptr.as_ptr().read(), pattern);
                    heap.dealloc(ptr, layout);
                }
            }
        }

        for (ptr, layout, pattern) in live.into_iter().rev() {
            // SAFETY: every remaining allocation is live and freed once.
            unsafe {
                assert_eq!(ptr.as_ptr().read(), pattern);
                assert_eq!(ptr.as_ptr().add(layout.size() - 1).read(), pattern);
                heap.dealloc(ptr, layout);
            }
        }
        assert_eq!(heap.stats_alloc_user(), 0);
        assert_eq!(heap.stats_alloc_actual(), 0);

        let whole = Layout::from_size_align(REGION_SIZE, REGION_SIZE).unwrap();
        assert_eq!(
            heap.alloc(whole).expect("coalesced whole region"),
            region.ptr
        );
    }
}
