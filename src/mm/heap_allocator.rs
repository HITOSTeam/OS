//! The global allocator.

use crate::{
    config::{KERNEL_HEAP_SIZE, MAX_HARTS, PAGE_SIZE},
    mm::{
        buddy_heap::{BuddyHeap, MIN_BLOCK_SIZE, ORDER_COUNT},
        slab_heap::{SLAB_CLASS_COUNT, SLAB_CLASS_SIZES, SLAB_PAGE_SIZE},
    },
    println,
    sync::LocalIrqSaveGuard,
};
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ptr::{NonNull, addr_of, addr_of_mut},
};
use spin::mutex::SpinMutex;

const HEAP_PAGE_COUNT: usize = KERNEL_HEAP_SIZE / PAGE_SIZE;
const HEAP_ZONE_FREE_BITMAP_WORDS: usize =
    (KERNEL_HEAP_SIZE / MIN_BLOCK_SIZE).div_ceil(u64::BITS as usize);
const PAGE_ALLOC_COSTLY_ORDER: usize = 3;
const COSTLY_ALLOCATION_THRESHOLD: usize = PAGE_SIZE << (PAGE_ALLOC_COSTLY_ORDER + 1);
/// Retain one completely empty slab per class and hart. This is the bounded
/// refill cache; a second empty slab is drained to the shared zone.
const EMPTY_SLAB_PAGES_PER_CLASS: usize = 1;
const _: () = assert!(PAGE_SIZE == SLAB_PAGE_SIZE);
const _: () = assert!(KERNEL_HEAP_SIZE % PAGE_SIZE == 0);
const _: () = assert!(HEAP_PAGE_COUNT < u32::MAX as usize);
const _: () = assert!(SLAB_CLASS_COUNT < u8::MAX as usize);
const _: () = assert!(MAX_HARTS < u8::MAX as usize);
const _: () = assert!(COSTLY_ALLOCATION_THRESHOLD.is_power_of_two());

type KernelZone = BuddyHeap<HEAP_ZONE_FREE_BITMAP_WORDS>;

/// Per-page slab metadata, indexed by the page's position in `HEAP_SPACE`.
///
/// This is the small subset of Linux `struct slab` needed here. Page links are
/// one-based so zero remains the inactive value in `.bss`. Metadata is
/// protected by the owning hart cache lock while a page is active.
#[derive(Clone, Copy)]
struct SlabPageMeta {
    next_partial: u32,
    prev_partial: u32,
    free_head: u16,
    in_use: u16,
    class_plus_one: u8,
    owner_plus_one: u8,
    on_partial: u8,
    _padding: u8,
}

impl SlabPageMeta {
    const fn empty() -> Self {
        Self {
            next_partial: 0,
            prev_partial: 0,
            free_head: 0,
            in_use: 0,
            class_plus_one: 0,
            owner_plus_one: 0,
            on_partial: 0,
            _padding: 0,
        }
    }

    fn class_index(self) -> Option<usize> {
        (self.class_plus_one != 0).then(|| self.class_plus_one as usize - 1)
    }

    fn owner(self) -> Option<usize> {
        (self.owner_plus_one != 0).then(|| self.owner_plus_one as usize - 1)
    }
}

const _: () = assert!(size_of::<SlabPageMeta>() <= 16);

/// The hot per-hart portion of the allocator. It owns no address range: each
/// slab page was refilled from, and can be drained back to, the shared zone.
#[derive(Clone, Copy)]
struct HartSlabCache {
    partial_heads: [u32; SLAB_CLASS_COUNT],
    empty_pages: [u8; SLAB_CLASS_COUNT],
    slab_live: [usize; SLAB_CLASS_COUNT],
    slab_user: [usize; SLAB_CLASS_COUNT],
    slab_pages: [usize; SLAB_CLASS_COUNT],
}

impl HartSlabCache {
    const fn empty() -> Self {
        Self {
            partial_heads: [0; SLAB_CLASS_COUNT],
            empty_pages: [0; SLAB_CLASS_COUNT],
            slab_live: [0; SLAB_CLASS_COUNT],
            slab_user: [0; SLAB_CLASS_COUNT],
            slab_pages: [0; SLAB_CLASS_COUNT],
        }
    }
}

/// A Linux-shaped shared page zone with refillable per-hart slab caches.
///
/// Small allocations normally touch only one hart cache. A cache obtains or
/// returns a whole 4-KiB slab under the zone lock, while larger allocations go
/// directly to the full 512-MiB buddy. Consequently there is no fixed 96-MiB
/// costly arena, no permanent memory ownership by a hart, and no all-shard
/// fallback scan with interrupts disabled.
struct ZoneHeap {
    zone: SpinMutex<KernelZone>,
    caches: [SpinMutex<HartSlabCache>; MAX_HARTS],
    slab_pages: [UnsafeCell<SlabPageMeta>; HEAP_PAGE_COUNT],
}

// Every active metadata entry is serialized by its stable owning cache lock;
// initialization and retirement happen under that same lock before the page is
// made available to the shared buddy again.
unsafe impl Sync for ZoneHeap {}

impl ZoneHeap {
    const fn empty() -> Self {
        Self {
            zone: SpinMutex::new(KernelZone::new()),
            caches: [const { SpinMutex::new(HartSlabCache::empty()) }; MAX_HARTS],
            slab_pages: [const { UnsafeCell::new(SlabPageMeta::empty()) }; HEAP_PAGE_COUNT],
        }
    }

    unsafe fn init(&self, start: usize, size: usize) {
        debug_assert_eq!(size, KERNEL_HEAP_SIZE);
        let _irq_guard = LocalIrqSaveGuard::new();
        let mut zone = self.zone.lock();
        // SAFETY: init_heap calls this once before secondary harts start, and
        // HEAP_SPACE stays exclusively owned by this allocator.
        unsafe {
            zone.init(start, size);
        }
    }

    fn class_for_layout(layout: Layout) -> Option<usize> {
        SLAB_CLASS_SIZES
            .iter()
            .position(|&class_size| class_size >= layout.size() && class_size % layout.align() == 0)
    }

    fn layout_is_costly(layout: Layout) -> bool {
        layout.size().max(layout.align()) >= COSTLY_ALLOCATION_THRESHOLD
    }

    fn slab_page_layout() -> Layout {
        // SAFETY: PAGE_SIZE is a non-zero power of two.
        unsafe { Layout::from_size_align_unchecked(PAGE_SIZE, PAGE_SIZE) }
    }

    fn heap_start() -> usize {
        addr_of!(HEAP_SPACE) as usize
    }

    fn page_index_for_address(address: usize) -> usize {
        let offset = address
            .checked_sub(Self::heap_start())
            .expect("slab object precedes HEAP_SPACE");
        assert!(
            offset < KERNEL_HEAP_SIZE,
            "slab object is outside HEAP_SPACE"
        );
        offset / PAGE_SIZE
    }

    fn page_link_for_index(index: usize) -> u32 {
        u32::try_from(index + 1).expect("slab page link exceeds u32")
    }

    fn index_for_page_link(link: u32) -> usize {
        assert_ne!(link, 0, "null slab page link has no index");
        link as usize - 1
    }

    unsafe fn page_meta(&self, index: usize) -> &mut SlabPageMeta {
        assert!(index < HEAP_PAGE_COUNT, "slab page metadata index overflow");
        // SAFETY: callers hold the stable owner cache lock, or initialize a
        // fresh page that is not reachable from another cache yet.
        unsafe { &mut *self.slab_pages[index].get() }
    }

    fn insert_partial(&self, cache: &mut HartSlabCache, class_index: usize, page_index: usize) {
        let old_head = cache.partial_heads[class_index];
        let page_link = Self::page_link_for_index(page_index);
        // SAFETY: the caller holds this page's owner cache lock.
        let page = unsafe { self.page_meta(page_index) };
        assert_eq!(page.on_partial, 0, "slab page inserted twice");
        page.prev_partial = 0;
        page.next_partial = old_head;
        page.on_partial = 1;
        if old_head != 0 {
            let old_index = Self::index_for_page_link(old_head);
            // SAFETY: all pages on one partial list share this cache lock.
            unsafe {
                self.page_meta(old_index).prev_partial = page_link;
            }
        }
        cache.partial_heads[class_index] = page_link;
    }

    fn remove_partial(&self, cache: &mut HartSlabCache, class_index: usize, page_index: usize) {
        // SAFETY: the caller holds this page's owner cache lock.
        let page = *unsafe { self.page_meta(page_index) };
        assert_ne!(page.on_partial, 0, "slab page is absent from partial list");
        if page.prev_partial == 0 {
            assert_eq!(
                cache.partial_heads[class_index],
                Self::page_link_for_index(page_index)
            );
            cache.partial_heads[class_index] = page.next_partial;
        } else {
            let prev = Self::index_for_page_link(page.prev_partial);
            // SAFETY: linked pages share the same owner cache lock.
            unsafe {
                self.page_meta(prev).next_partial = page.next_partial;
            }
        }
        if page.next_partial != 0 {
            let next = Self::index_for_page_link(page.next_partial);
            // SAFETY: linked pages share the same owner cache lock.
            unsafe {
                self.page_meta(next).prev_partial = page.prev_partial;
            }
        }
        // SAFETY: the caller holds the owner cache lock.
        let page = unsafe { self.page_meta(page_index) };
        page.next_partial = 0;
        page.prev_partial = 0;
        page.on_partial = 0;
    }

    fn allocate_slab_page(
        &self,
        cache: &mut HartSlabCache,
        owner: usize,
        class_index: usize,
    ) -> bool {
        let layout = Self::slab_page_layout();
        let (allocation, actual_before, actual_after) = {
            let mut zone = self.zone.lock();
            let actual_before = if crate::perf::enabled() {
                zone.stats_alloc_actual()
            } else {
                0
            };
            let allocation = zone.alloc(layout).ok();
            let actual_after = if crate::perf::enabled() {
                zone.stats_alloc_actual()
            } else {
                0
            };
            (allocation, actual_before, actual_after)
        };
        crate::perf::record_heap_actual_transition(actual_before, actual_after);
        let Some(page_ptr) = allocation else {
            return false;
        };
        let page_start = page_ptr.as_ptr() as usize;
        let page_index = Self::page_index_for_address(page_start);
        assert_eq!(
            page_start % PAGE_SIZE,
            0,
            "zone returned an unaligned slab page"
        );

        // SAFETY: the page was just removed from the shared buddy and is not
        // reachable from any cache.
        let meta = unsafe { self.page_meta(page_index) };
        assert!(
            meta.class_index().is_none(),
            "zone returned an active slab page"
        );
        let class_size = SLAB_CLASS_SIZES[class_index];
        let capacity = PAGE_SIZE / class_size;
        assert!(capacity > 0 && capacity <= u16::MAX as usize);
        for object_index in 0..capacity {
            let object_address = page_start + object_index * class_size;
            let next = if object_index + 1 < capacity {
                (object_index + 2) as u16
            } else {
                0
            };
            // SAFETY: every object in the fresh slab page is exclusively
            // owned and at least two-byte aligned.
            unsafe {
                (object_address as *mut u16).write(next);
            }
        }
        *meta = SlabPageMeta {
            next_partial: 0,
            prev_partial: 0,
            free_head: 1,
            in_use: 0,
            class_plus_one: (class_index + 1) as u8,
            owner_plus_one: (owner + 1) as u8,
            on_partial: 0,
            _padding: 0,
        };
        cache.slab_pages[class_index] = cache.slab_pages[class_index].saturating_add(1);
        self.insert_partial(cache, class_index, page_index);
        true
    }

    fn alloc_small(&self, layout: Layout, class_index: usize, owner: usize) -> Option<NonNull<u8>> {
        let _irq_guard = LocalIrqSaveGuard::new();
        let mut cache = self.caches[owner].lock();
        if cache.partial_heads[class_index] == 0
            && !self.allocate_slab_page(&mut cache, owner, class_index)
        {
            return None;
        }

        let page_index = Self::index_for_page_link(cache.partial_heads[class_index]);
        // SAFETY: this page belongs to the locked owner cache.
        let snapshot = *unsafe { self.page_meta(page_index) };
        debug_assert_eq!(snapshot.owner(), Some(owner));
        debug_assert_eq!(snapshot.class_index(), Some(class_index));
        assert_ne!(
            snapshot.free_head, 0,
            "partial slab page has no free object"
        );
        if snapshot.in_use == 0 && cache.empty_pages[class_index] != 0 {
            cache.empty_pages[class_index] -= 1;
        }

        let class_size = SLAB_CLASS_SIZES[class_index];
        let page_start = Self::heap_start() + page_index * PAGE_SIZE;
        let object_index = snapshot.free_head as usize - 1;
        let object_address = page_start + object_index * class_size;
        // SAFETY: the selected object is on this page's free list.
        let next_free = unsafe { (object_address as *const u16).read() };
        // SAFETY: the owner cache lock protects this metadata.
        let meta = unsafe { self.page_meta(page_index) };
        meta.free_head = next_free;
        meta.in_use = meta
            .in_use
            .checked_add(1)
            .expect("slab in-use count overflow");
        if next_free == 0 {
            self.remove_partial(&mut cache, class_index, page_index);
        }
        cache.slab_live[class_index] = cache.slab_live[class_index].saturating_add(1);
        cache.slab_user[class_index] = cache.slab_user[class_index].saturating_add(layout.size());
        debug_assert_eq!(object_address % layout.align(), 0);
        // SAFETY: the object was removed from the free list under its lock.
        Some(unsafe { NonNull::new_unchecked(object_address as *mut u8) })
    }

    unsafe fn dealloc_small(&self, ptr: NonNull<u8>, layout: Layout, class_index: usize) {
        let address = ptr.as_ptr() as usize;
        let page_index = Self::page_index_for_address(address);
        // Reading owner/class is safe while this object is live: the page
        // cannot become empty or return to the buddy before this deallocation.
        let initial = *unsafe { self.page_meta(page_index) };
        let owner = initial.owner().expect("slab object has no owner");
        assert_eq!(initial.class_index(), Some(class_index));

        let _irq_guard = LocalIrqSaveGuard::new();
        let mut cache = self.caches[owner].lock();
        // SAFETY: the stable owner lock now protects the page metadata.
        let snapshot = *unsafe { self.page_meta(page_index) };
        assert_eq!(snapshot.owner(), Some(owner));
        assert_eq!(snapshot.class_index(), Some(class_index));
        let page_start = Self::heap_start() + page_index * PAGE_SIZE;
        let class_size = SLAB_CLASS_SIZES[class_index];
        let object_offset = address
            .checked_sub(page_start)
            .expect("slab object precedes its page");
        assert_eq!(
            object_offset % class_size,
            0,
            "invalid slab object boundary"
        );
        let object_index = object_offset / class_size;
        assert!(object_index < PAGE_SIZE / class_size);

        let was_full = snapshot.free_head == 0;
        // SAFETY: the caller returns exclusive ownership of this live object.
        unsafe {
            (address as *mut u16).write(snapshot.free_head);
        }
        let meta = unsafe { self.page_meta(page_index) };
        meta.free_head = (object_index + 1) as u16;
        meta.in_use = meta
            .in_use
            .checked_sub(1)
            .expect("slab in-use count underflow");
        cache.slab_live[class_index] = cache.slab_live[class_index]
            .checked_sub(1)
            .expect("slab live count underflow");
        cache.slab_user[class_index] = cache.slab_user[class_index]
            .checked_sub(layout.size())
            .expect("slab user-byte count underflow");
        if was_full {
            self.insert_partial(&mut cache, class_index, page_index);
        }

        if unsafe { self.page_meta(page_index) }.in_use != 0 {
            return;
        }
        if cache.empty_pages[class_index] < EMPTY_SLAB_PAGES_PER_CLASS as u8 {
            cache.empty_pages[class_index] += 1;
            return;
        }

        self.remove_partial(&mut cache, class_index, page_index);
        // Mark the page inactive before making it available to the zone.
        *unsafe { self.page_meta(page_index) } = SlabPageMeta::empty();
        cache.slab_pages[class_index] = cache.slab_pages[class_index]
            .checked_sub(1)
            .expect("slab page count underflow");
        let page_ptr = unsafe { NonNull::new_unchecked(page_start as *mut u8) };
        let page_layout = Self::slab_page_layout();
        let (actual_before, actual_after) = {
            let mut zone = self.zone.lock();
            let actual_before = if crate::perf::enabled() {
                zone.stats_alloc_actual()
            } else {
                0
            };
            // SAFETY: this slab is empty and no cache references it now.
            unsafe {
                zone.dealloc(page_ptr, page_layout);
            }
            let actual_after = if crate::perf::enabled() {
                zone.stats_alloc_actual()
            } else {
                0
            };
            (actual_before, actual_after)
        };
        crate::perf::record_heap_actual_transition(actual_before, actual_after);
    }

    fn alloc_direct(&self, layout: Layout) -> Option<NonNull<u8>> {
        let (allocation, actual_before, actual_after) = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let mut zone = self.zone.lock();
            let actual_before = if crate::perf::enabled() {
                zone.stats_alloc_actual()
            } else {
                0
            };
            let allocation = zone.alloc(layout).ok();
            let actual_after = if crate::perf::enabled() {
                zone.stats_alloc_actual()
            } else {
                0
            };
            (allocation, actual_before, actual_after)
        };
        crate::perf::record_heap_actual_transition(actual_before, actual_after);
        if Self::layout_is_costly(layout) && allocation.is_some() {
            crate::perf::record_heap_shared_actual_transition(actual_before, actual_after);
            crate::perf::record_heap_shared_allocation(false);
        }
        allocation
    }

    unsafe fn dealloc_direct(&self, ptr: NonNull<u8>, layout: Layout) {
        let (actual_before, actual_after) = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let mut zone = self.zone.lock();
            let actual_before = if crate::perf::enabled() {
                zone.stats_alloc_actual()
            } else {
                0
            };
            // SAFETY: the caller supplies the original direct allocation.
            unsafe {
                zone.dealloc(ptr, layout);
            }
            let actual_after = if crate::perf::enabled() {
                zone.stats_alloc_actual()
            } else {
                0
            };
            (actual_before, actual_after)
        };
        crate::perf::record_heap_actual_transition(actual_before, actual_after);
        if Self::layout_is_costly(layout) {
            crate::perf::record_heap_shared_actual_transition(actual_before, actual_after);
        }
    }

    fn slab_summary(&self) -> (usize, usize, usize) {
        self.caches
            .iter()
            .fold((0usize, 0usize, 0usize), |(live, user, pages), cache| {
                let _irq_guard = LocalIrqSaveGuard::new();
                let cache = cache.lock();
                (
                    live.saturating_add(cache.slab_live.iter().copied().sum::<usize>()),
                    user.saturating_add(cache.slab_user.iter().copied().sum::<usize>()),
                    pages.saturating_add(cache.slab_pages.iter().copied().sum::<usize>()),
                )
            })
    }

    fn stats(&self) -> (usize, usize, usize) {
        let (_, slab_user, slab_pages) = self.slab_summary();
        let _irq_guard = LocalIrqSaveGuard::new();
        let zone = self.zone.lock();
        let slab_backing = slab_pages.saturating_mul(PAGE_SIZE);
        let direct_user = zone.stats_alloc_user().saturating_sub(slab_backing);
        (
            direct_user.saturating_add(slab_user),
            zone.stats_alloc_actual(),
            zone.stats_total_bytes(),
        )
    }

    fn order_stats(&self, order: usize) -> (usize, usize, usize) {
        let _irq_guard = LocalIrqSaveGuard::new();
        self.zone.lock().stats_order(order)
    }

    fn slab_stats(&self, class_index: usize) -> (usize, usize, usize) {
        self.caches
            .iter()
            .fold((0usize, 0usize, 0usize), |(live, user, pages), cache| {
                let _irq_guard = LocalIrqSaveGuard::new();
                let cache = cache.lock();
                (
                    live.saturating_add(cache.slab_live[class_index]),
                    user.saturating_add(cache.slab_user[class_index]),
                    pages.saturating_add(cache.slab_pages[class_index]),
                )
            })
    }
}

unsafe impl GlobalAlloc for ZoneHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let allocation = if let Some(class_index) = Self::class_for_layout(layout) {
            let owner = crate::arch::hart_id() % MAX_HARTS;
            self.alloc_small(layout, class_index, owner)
        } else {
            self.alloc_direct(layout)
        };
        if let Some(allocation) = allocation {
            return allocation.as_ptr();
        }
        crate::perf::record_heap_allocation_failure();
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let ptr = unsafe { NonNull::new_unchecked(ptr) };
        if let Some(class_index) = Self::class_for_layout(layout) {
            // SAFETY: GlobalAlloc guarantees that this pointer/layout pair is
            // the live small allocation returned by alloc_small.
            unsafe {
                self.dealloc_small(ptr, layout, class_index);
            }
        } else {
            // SAFETY: this is the original direct allocation and layout.
            unsafe {
                self.dealloc_direct(ptr, layout);
            }
        }
    }
}

#[global_allocator]
static HEAP_ALLOCATOR: ZoneHeap = ZoneHeap::empty();

#[alloc_error_handler]
/// panic when heap allocation error occurs
pub fn handle_alloc_error(layout: core::alloc::Layout) -> ! {
    let (id, args) = crate::syscall::last_syscall_snapshot();
    let (alloc_user, alloc_actual, total_bytes) = HEAP_ALLOCATOR.stats();
    let frame_refs = crate::mm::frame_refcount_entries();
    crate::println!(
        "[oom] heap alloc failed: layout={:?} user={} actual={} total={} frame_refs={} last_syscall={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
        layout,
        alloc_user,
        alloc_actual,
        total_bytes,
        frame_refs,
        id,
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5]
    );
    crate::println!(
        "[oom][heap-zone] user={} actual={} total={} free={} empty_slabs_per_class={}",
        alloc_user,
        alloc_actual,
        total_bytes,
        total_bytes.saturating_sub(alloc_actual),
        EMPTY_SLAB_PAGES_PER_CLASS
    );
    crate::fs::debug_net_socket_atomic_heap_state();
    for order in 0..ORDER_COUNT {
        let (live, user, free) = HEAP_ALLOCATOR.order_stats(order);
        if live == 0 && free == 0 {
            continue;
        }
        let block_size = 1usize << order;
        crate::println!(
            "[oom][heap-order] order={} block={} live={} user={} actual={} free_blocks={} free_bytes={}",
            order,
            block_size,
            live,
            user,
            live.saturating_mul(block_size),
            free,
            free.saturating_mul(block_size)
        );
    }
    for class_index in 0..SLAB_CLASS_COUNT {
        let (live, user, pages) = HEAP_ALLOCATOR.slab_stats(class_index);
        if live == 0 && pages == 0 {
            continue;
        }
        let class_size = SLAB_CLASS_SIZES[class_index];
        let capacity = pages.saturating_mul(SLAB_PAGE_SIZE / class_size);
        crate::println!(
            "[oom][heap-slab] class={} live={} user={} object_bytes={} pages={} reserved={} free_objects={}",
            class_size,
            live,
            user,
            live.saturating_mul(class_size),
            pages,
            pages.saturating_mul(SLAB_PAGE_SIZE),
            capacity.saturating_sub(live)
        );
    }
    panic!("Heap allocation error, layout = {:?}", layout);
}

#[repr(C, align(4096))]
struct HeapSpace([u8; KERNEL_HEAP_SIZE]);

/// Page-aligned heap space owned by one shared buddy zone. Per-hart caches
/// borrow and return slab pages rather than owning fixed address ranges.
#[allow(dead_code)]
static mut HEAP_SPACE: HeapSpace = HeapSpace([0; KERNEL_HEAP_SIZE]);

/// initiate heap allocator
/// 这个部分初始化的是rust的动态分配内容,测试发现几乎就是bss段(还有一些别的全局变量啥的),
/// 初始化之后rust的大部分和堆内存有关的数据结构都会从这里分配
#[allow(dead_code)]
pub fn init_heap() {
    unsafe {
        HEAP_ALLOCATOR.init(addr_of_mut!(HEAP_SPACE) as usize, KERNEL_HEAP_SIZE);
    }
}

#[allow(unused)]
pub fn heap_test() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    unsafe extern "C" {
        safe fn sbss();
        safe fn ebss();
    }
    let bss_range = sbss as *const () as usize..ebss as *const () as usize;
    let a = Box::new(5);
    assert_eq!(*a, 5);
    assert!(bss_range.contains(&(a.as_ref() as *const _ as usize)));
    drop(a);
    let mut v: Vec<usize> = Vec::new();
    for i in 0..500 {
        v.push(i);
    }
    for (i, val) in v.iter().take(500).enumerate() {
        assert_eq!(*val, i);
    }
    assert!(bss_range.contains(&(v.as_ptr() as usize)));
    drop(v);
    println!("heap_test passed!");
}
