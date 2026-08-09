//! Intrusive buddy allocator used by the kernel heap shards.
//!
//! Linux records `PageBuddy` plus the free block order in the page metadata,
//! then removes a known buddy from its order list in O(1).  Keep the same
//! property here: one bitmap bit marks each free block head, while the free
//! memory itself stores an intrusive doubly-linked list node and its order.

use core::{alloc::Layout, ptr::NonNull};

/// Match the previous kernel allocator's minimum allocation granularity.
pub(crate) const MIN_BLOCK_SIZE: usize = 8;
const MIN_ORDER: usize = MIN_BLOCK_SIZE.trailing_zeros() as usize;
pub(crate) const ORDER_COUNT: usize = usize::BITS as usize;
// A full 512-MiB kernel zone contains 2^26 minimum-size slots. Links are
// one-based, so 27 bits are required to represent the final slot as well.
const LINK_BITS: usize = 27;
const LINK_MASK: u64 = (1u64 << LINK_BITS) - 1;
const NEXT_LINK_SHIFT: usize = LINK_BITS;
const ORDER_SHIFT: usize = LINK_BITS * 2;
const ORDER_BITS: usize = 6;
const ORDER_MASK: u64 = (1u64 << ORDER_BITS) - 1;
const MAX_LINK: usize = LINK_MASK as usize;

/// Intrusive free-list metadata packed into one minimum-sized block.
///
/// Links are one-based indices of 8-byte slots relative to the zone start;
/// zero is the null link. A 27-bit link covers the full 512-MiB kernel zone,
/// including the final one-based slot. Six order bits cover every order on a
/// 64-bit target.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct FreeNode(u64);

impl FreeNode {
    fn new(prev: u32, next: u32, order: usize) -> Self {
        debug_assert!(prev as u64 <= LINK_MASK);
        debug_assert!(next as u64 <= LINK_MASK);
        debug_assert!(order as u64 <= ORDER_MASK);
        Self((prev as u64) | ((next as u64) << NEXT_LINK_SHIFT) | ((order as u64) << ORDER_SHIFT))
    }

    fn prev(self) -> u32 {
        (self.0 & LINK_MASK) as u32
    }

    fn next(self) -> u32 {
        ((self.0 >> NEXT_LINK_SHIFT) & LINK_MASK) as u32
    }

    fn order(self) -> usize {
        ((self.0 >> ORDER_SHIFT) & ORDER_MASK) as usize
    }

    fn with_prev(self, prev: u32) -> Self {
        debug_assert!(prev as u64 <= LINK_MASK);
        Self((self.0 & !LINK_MASK) | prev as u64)
    }

    fn with_next(self, next: u32) -> Self {
        debug_assert!(next as u64 <= LINK_MASK);
        let next_mask = LINK_MASK << NEXT_LINK_SHIFT;
        Self((self.0 & !next_mask) | ((next as u64) << NEXT_LINK_SHIFT))
    }
}

const _: () = assert!(size_of::<FreeNode>() == MIN_BLOCK_SIZE);
const _: () = assert!(ORDER_COUNT <= 1usize << ORDER_BITS);

#[derive(Clone, Copy)]
struct FreeList {
    head: u32,
}

impl FreeList {
    const fn empty() -> Self {
        Self { head: 0 }
    }
}

/// A fixed-range buddy heap with O(1) membership checks and list removal.
///
/// `FREE_BITMAP_WORDS` supplies one bit for every [`MIN_BLOCK_SIZE`] bytes in
/// the largest shard.  The bitmap marks only free block heads; the order in
/// the intrusive node distinguishes a same-address block at another order.
pub(crate) struct BuddyHeap<const FREE_BITMAP_WORDS: usize> {
    free_lists: [FreeList; ORDER_COUNT],
    free_heads: [u64; FREE_BITMAP_WORDS],
    start: usize,
    end: usize,
    alloc_user: usize,
    alloc_actual: usize,
    live_allocations: [usize; ORDER_COUNT],
    alloc_user_by_order: [usize; ORDER_COUNT],
    free_blocks: [usize; ORDER_COUNT],
    total_bytes: usize,
}

impl<const FREE_BITMAP_WORDS: usize> BuddyHeap<FREE_BITMAP_WORDS> {
    pub(crate) const fn new() -> Self {
        Self {
            free_lists: [FreeList::empty(); ORDER_COUNT],
            free_heads: [0; FREE_BITMAP_WORDS],
            start: 0,
            end: 0,
            alloc_user: 0,
            alloc_actual: 0,
            live_allocations: [0; ORDER_COUNT],
            alloc_user_by_order: [0; ORDER_COUNT],
            free_blocks: [0; ORDER_COUNT],
            total_bytes: 0,
        }
    }

    /// Initialize this allocator over an otherwise unused memory range.
    ///
    /// # Safety
    ///
    /// The aligned portion of `start..start + size` must remain exclusively
    /// owned by this allocator until every allocation has been returned.
    pub(crate) unsafe fn init(&mut self, start: usize, size: usize) {
        let raw_end = start
            .checked_add(size)
            .expect("buddy heap range overflows usize");
        let aligned_start = start
            .checked_add(MIN_BLOCK_SIZE - 1)
            .expect("buddy heap alignment overflows usize")
            & !(MIN_BLOCK_SIZE - 1);
        let aligned_end = raw_end & !(MIN_BLOCK_SIZE - 1);
        assert!(aligned_start < aligned_end, "buddy heap range is empty");

        let block_slots = (aligned_end - aligned_start) / MIN_BLOCK_SIZE;
        assert!(
            block_slots <= FREE_BITMAP_WORDS.saturating_mul(u64::BITS as usize),
            "buddy heap free-head bitmap is too small"
        );
        assert!(
            block_slots <= MAX_LINK,
            "buddy heap range exceeds packed free-list link capacity"
        );

        self.free_lists = [FreeList::empty(); ORDER_COUNT];
        self.free_heads.fill(0);
        self.start = aligned_start;
        self.end = aligned_end;
        self.alloc_user = 0;
        self.alloc_actual = 0;
        self.live_allocations = [0; ORDER_COUNT];
        self.alloc_user_by_order = [0; ORDER_COUNT];
        self.free_blocks = [0; ORDER_COUNT];
        self.total_bytes = aligned_end - aligned_start;

        let mut current = aligned_start;
        while current < aligned_end {
            let remaining = aligned_end - current;
            let alignment_order = current.trailing_zeros() as usize;
            let remaining_order = (usize::BITS - 1 - remaining.leading_zeros()) as usize;
            let order = alignment_order.min(remaining_order).max(MIN_ORDER);
            // SAFETY: the range is exclusive and partitioned into disjoint,
            // naturally aligned power-of-two blocks by this loop.
            unsafe {
                self.push_free(current, order);
            }
            current += 1usize << order;
        }
    }

    pub(crate) fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        let order = Self::layout_order(layout).ok_or(())?;
        let mut source_order = order;
        while source_order < ORDER_COUNT && self.free_lists[source_order].head == 0 {
            source_order += 1;
        }
        if source_order == ORDER_COUNT {
            return Err(());
        }

        let address = self.address_for_link(self.free_lists[source_order].head);
        // SAFETY: `address` is the head of this order's free list.
        unsafe {
            self.remove_free(address, source_order);
        }
        while source_order > order {
            source_order -= 1;
            let right_buddy = address + (1usize << source_order);
            // SAFETY: splitting the removed block produces a disjoint right
            // buddy that is naturally aligned and still inside the heap.
            unsafe {
                self.push_free(right_buddy, source_order);
            }
        }

        let actual = 1usize << order;
        self.alloc_user = self.alloc_user.saturating_add(layout.size());
        self.alloc_actual = self.alloc_actual.saturating_add(actual);
        self.live_allocations[order] = self.live_allocations[order].saturating_add(1);
        self.alloc_user_by_order[order] =
            self.alloc_user_by_order[order].saturating_add(layout.size());
        // SAFETY: initialized heap addresses are non-zero, and this block has
        // just been removed from the allocator's free state.
        Ok(unsafe { NonNull::new_unchecked(address as *mut u8) })
    }

    /// Return one allocation obtained from [`Self::alloc`].
    ///
    /// # Safety
    ///
    /// `ptr` must be a live allocation from this heap and `layout` must be the
    /// same layout used for that allocation.
    pub(crate) unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let mut order = Self::layout_order(layout).expect("invalid buddy deallocation layout");
        let mut address = ptr.as_ptr() as usize;
        let actual = 1usize << order;
        assert!(
            address >= self.start
                && address
                    .checked_add(actual)
                    .is_some_and(|end| end <= self.end),
            "buddy deallocation is outside this heap"
        );
        assert_eq!(
            address & (actual - 1),
            0,
            "buddy deallocation has invalid alignment"
        );

        self.alloc_user = self.alloc_user.saturating_sub(layout.size());
        self.alloc_actual = self.alloc_actual.saturating_sub(actual);
        self.live_allocations[order] = self.live_allocations[order]
            .checked_sub(1)
            .expect("buddy live-allocation count underflow");
        self.alloc_user_by_order[order] = self.alloc_user_by_order[order]
            .checked_sub(layout.size())
            .expect("buddy per-order user-byte count underflow");

        while order + 1 < ORDER_COUNT {
            let block_size = 1usize << order;
            let buddy = address ^ block_size;
            let buddy_in_heap = buddy >= self.start
                && buddy
                    .checked_add(block_size)
                    .is_some_and(|end| end <= self.end);
            if !buddy_in_heap || !self.is_free_head(buddy) {
                break;
            }

            // The bitmap is checked before touching free memory. A larger
            // free block can share this address, so its recorded order must
            // also match before it is removed and merged.
            let buddy_node = buddy as *mut FreeNode;
            // SAFETY: `is_free_head` proves that `buddy` currently contains a
            // live intrusive free-list node owned by this heap.
            if unsafe { buddy_node.read().order() } != order {
                break;
            }
            // SAFETY: the matching node belongs to this order's list.
            unsafe {
                self.remove_free(buddy, order);
            }
            address = address.min(buddy);
            order += 1;
        }

        // SAFETY: the merged block is disjoint from every remaining free
        // block and stays within this heap's initialized range.
        unsafe {
            self.push_free(address, order);
        }
    }

    pub(crate) fn stats_alloc_user(&self) -> usize {
        self.alloc_user
    }

    pub(crate) fn stats_alloc_actual(&self) -> usize {
        self.alloc_actual
    }

    pub(crate) fn stats_total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(crate) fn stats_order(&self, order: usize) -> (usize, usize, usize) {
        (
            self.live_allocations[order],
            self.alloc_user_by_order[order],
            self.free_blocks[order],
        )
    }

    fn layout_order(layout: Layout) -> Option<usize> {
        let required = layout.size().max(layout.align()).max(MIN_BLOCK_SIZE);
        let block_size = required.checked_next_power_of_two()?;
        let order = block_size.trailing_zeros() as usize;
        (order < ORDER_COUNT).then_some(order)
    }

    fn bitmap_position(&self, address: usize) -> Option<(usize, u64)> {
        let offset = address.checked_sub(self.start)?;
        if address >= self.end || offset % MIN_BLOCK_SIZE != 0 {
            return None;
        }
        let slot = offset / MIN_BLOCK_SIZE;
        let word = slot / u64::BITS as usize;
        (word < FREE_BITMAP_WORDS).then_some((word, 1u64 << (slot % u64::BITS as usize)))
    }

    fn link_for_address(&self, address: usize) -> u32 {
        let offset = address
            .checked_sub(self.start)
            .expect("free-list address precedes buddy heap");
        assert_eq!(
            offset % MIN_BLOCK_SIZE,
            0,
            "free-list address is not slot aligned"
        );
        let link = offset / MIN_BLOCK_SIZE + 1;
        assert!(link <= MAX_LINK, "free-list link exceeds packed capacity");
        link as u32
    }

    fn address_for_link(&self, link: u32) -> usize {
        assert_ne!(link, 0, "null free-list link has no address");
        let address = self.start + (link as usize - 1) * MIN_BLOCK_SIZE;
        assert!(address < self.end, "free-list link is outside buddy heap");
        address
    }

    fn is_free_head(&self, address: usize) -> bool {
        self.bitmap_position(address)
            .is_some_and(|(word, mask)| self.free_heads[word] & mask != 0)
    }

    fn mark_free_head(&mut self, address: usize) {
        let (word, mask) = self
            .bitmap_position(address)
            .expect("free block head is outside buddy heap");
        assert_eq!(
            self.free_heads[word] & mask,
            0,
            "buddy block inserted twice"
        );
        self.free_heads[word] |= mask;
    }

    fn clear_free_head(&mut self, address: usize) {
        let (word, mask) = self
            .bitmap_position(address)
            .expect("free block head is outside buddy heap");
        assert_ne!(
            self.free_heads[word] & mask,
            0,
            "buddy block removed while allocated"
        );
        self.free_heads[word] &= !mask;
    }

    /// Insert a free block at the front of its order list.
    ///
    /// # Safety
    ///
    /// The block must be exclusively owned, correctly aligned, and large
    /// enough for `FreeNode`.
    unsafe fn push_free(&mut self, address: usize, order: usize) {
        debug_assert!(order >= MIN_ORDER && order < ORDER_COUNT);
        debug_assert_eq!(address & ((1usize << order) - 1), 0);
        debug_assert!(address >= self.start && address + (1usize << order) <= self.end);

        let node = address as *mut FreeNode;
        let node_link = self.link_for_address(address);
        let old_head = self.free_lists[order].head;
        // SAFETY: the caller gives exclusive ownership of at least one
        // minimum-sized free block at `address`.
        unsafe {
            node.write(FreeNode::new(0, old_head, order));
            if old_head != 0 {
                let old_head_node = self.address_for_link(old_head) as *mut FreeNode;
                old_head_node.write(old_head_node.read().with_prev(node_link));
            }
        }
        self.free_lists[order].head = node_link;
        self.mark_free_head(address);
        self.free_blocks[order] = self.free_blocks[order].saturating_add(1);
    }

    /// Remove a known free block from its order list in O(1).
    ///
    /// # Safety
    ///
    /// `address` must be a live node in the specified order list.
    unsafe fn remove_free(&mut self, address: usize, order: usize) {
        debug_assert!(self.is_free_head(address));
        let node = address as *mut FreeNode;
        // SAFETY: the caller proves that `node` is a live intrusive node.
        let (prev, next) = unsafe {
            let node = node.read();
            debug_assert_eq!(node.order(), order);
            (node.prev(), node.next())
        };
        if prev == 0 {
            debug_assert_eq!(self.free_lists[order].head, self.link_for_address(address));
            self.free_lists[order].head = next;
        } else {
            // SAFETY: list invariants make `prev` another live free node.
            unsafe {
                let prev_node = self.address_for_link(prev) as *mut FreeNode;
                prev_node.write(prev_node.read().with_next(next));
            }
        }
        if next != 0 {
            // SAFETY: list invariants make `next` another live free node.
            unsafe {
                let next_node = self.address_for_link(next) as *mut FreeNode;
                next_node.write(next_node.read().with_prev(prev));
            }
        }
        self.clear_free_head(address);
        self.free_blocks[order] = self.free_blocks[order]
            .checked_sub(1)
            .expect("buddy free-block count underflow");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc_zeroed, dealloc};

    const ONE_MIB_BITMAP_WORDS: usize = (1 << 20) / MIN_BLOCK_SIZE / u64::BITS as usize;

    struct TestRegion {
        ptr: NonNull<u8>,
        layout: Layout,
    }

    impl TestRegion {
        fn new(size: usize, align: usize) -> Self {
            let layout = Layout::from_size_align(size, align).expect("valid test region layout");
            // SAFETY: the layout is non-zero and valid.
            let ptr = unsafe { NonNull::new(alloc_zeroed(layout)) }
                .expect("host allocation for buddy test failed");
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

    #[test]
    fn coalesces_back_to_the_largest_block() {
        const REGION_SIZE: usize = 1 << 20;
        let region = TestRegion::new(REGION_SIZE, REGION_SIZE);
        let small = Layout::from_size_align(24, 8).expect("valid layout");
        let mut heap = BuddyHeap::<ONE_MIB_BITMAP_WORDS>::new();
        // SAFETY: the test region remains alive and exclusively owned here.
        unsafe {
            heap.init(region.ptr.as_ptr() as usize, REGION_SIZE);
        }
        let mut all = Vec::new();
        for _ in 0..4096 {
            all.push(heap.alloc(small).expect("small allocation"));
        }
        for index in (0..all.len()).step_by(2) {
            // SAFETY: this pointer is live and uses its original layout.
            unsafe {
                heap.dealloc(all[index], small);
            }
        }
        for index in (1..all.len()).rev().step_by(2) {
            // SAFETY: this pointer is live and uses its original layout.
            unsafe {
                heap.dealloc(all[index], small);
            }
        }

        let whole = Layout::from_size_align(REGION_SIZE, REGION_SIZE).expect("valid layout");
        let allocation = heap.alloc(whole).expect("fully coalesced block");
        assert_eq!(allocation, region.ptr);
        assert_eq!(heap.stats_alloc_user(), REGION_SIZE);
        assert_eq!(heap.stats_alloc_actual(), REGION_SIZE);
        assert_eq!(heap.stats_total_bytes(), REGION_SIZE);
        // SAFETY: this is the live whole-region allocation.
        unsafe {
            heap.dealloc(allocation, whole);
        }
        assert_eq!(heap.stats_alloc_user(), 0);
        assert_eq!(heap.stats_alloc_actual(), 0);
    }

    #[test]
    fn mixed_layouts_are_aligned_disjoint_and_reusable() {
        const REGION_SIZE: usize = 1 << 20;
        let region = TestRegion::new(REGION_SIZE, REGION_SIZE);
        let mut heap = BuddyHeap::<ONE_MIB_BITMAP_WORDS>::new();
        // SAFETY: the test region remains alive and exclusively owned here.
        unsafe {
            heap.init(region.ptr.as_ptr() as usize, REGION_SIZE);
        }

        let layouts = [
            Layout::from_size_align(1, 1).expect("layout"),
            Layout::from_size_align(33, 8).expect("layout"),
            Layout::from_size_align(65, 128).expect("layout"),
            Layout::from_size_align(4097, 4096).expect("layout"),
            Layout::from_size_align(8192, 16384).expect("layout"),
        ];
        let mut live = Vec::new();
        for index in 0..100 {
            let layout = layouts[index % layouts.len()];
            let allocation = heap.alloc(layout).expect("mixed allocation");
            let address = allocation.as_ptr() as usize;
            assert_eq!(address % layout.align(), 0);
            let actual = 1usize
                << BuddyHeap::<ONE_MIB_BITMAP_WORDS>::layout_order(layout).expect("layout order");
            for (other_address, other_actual, _) in &live {
                assert!(
                    address + actual <= *other_address || *other_address + *other_actual <= address,
                    "allocations overlap"
                );
            }
            live.push((address, actual, layout));
        }

        for index in (0..live.len()).step_by(3) {
            let (address, _, layout) = live[index];
            // SAFETY: each selected allocation is live and freed once.
            unsafe {
                heap.dealloc(NonNull::new_unchecked(address as *mut u8), layout);
            }
        }
        for index in (0..live.len()).rev() {
            if index % 3 == 0 {
                continue;
            }
            let (address, _, layout) = live[index];
            // SAFETY: each remaining allocation is live and freed once.
            unsafe {
                heap.dealloc(NonNull::new_unchecked(address as *mut u8), layout);
            }
        }

        let whole = Layout::from_size_align(REGION_SIZE, REGION_SIZE).expect("valid layout");
        assert_eq!(heap.alloc(whole).expect("reused whole region"), region.ptr);
    }

    #[test]
    fn retains_eight_byte_minimum_allocation_granularity() {
        const REGION_SIZE: usize = 1 << 20;
        let region = TestRegion::new(REGION_SIZE, REGION_SIZE);
        let mut heap = BuddyHeap::<ONE_MIB_BITMAP_WORDS>::new();
        // SAFETY: the test region remains alive and exclusively owned here.
        unsafe {
            heap.init(region.ptr.as_ptr() as usize, REGION_SIZE);
        }

        let tiny = Layout::from_size_align(1, 1).expect("valid tiny layout");
        let allocation = heap.alloc(tiny).expect("tiny allocation");
        assert_eq!(heap.stats_alloc_user(), 1);
        assert_eq!(heap.stats_alloc_actual(), MIN_BLOCK_SIZE);
        let (live, user, _) = heap.stats_order(MIN_ORDER);
        assert_eq!((live, user), (1, 1));
        // SAFETY: this is the live tiny allocation with its original layout.
        unsafe {
            heap.dealloc(allocation, tiny);
        }
        assert_eq!(heap.stats_alloc_user(), 0);
        assert_eq!(heap.stats_alloc_actual(), 0);
        let (live, user, _) = heap.stats_order(MIN_ORDER);
        assert_eq!((live, user), (0, 0));
    }

    #[test]
    fn does_not_merge_across_an_unaligned_heap_boundary() {
        const REGION_SIZE: usize = 1 << 18;
        let backing = TestRegion::new(REGION_SIZE * 2, REGION_SIZE * 2);
        let start = backing.ptr.as_ptr() as usize + MIN_BLOCK_SIZE;
        let mut heap = BuddyHeap::<1024>::new();
        // SAFETY: this strict subrange remains exclusively owned by the test.
        unsafe {
            heap.init(start, REGION_SIZE);
        }

        let layout = Layout::from_size_align(4096, 4096).expect("valid layout");
        let mut allocations = Vec::new();
        while let Ok(allocation) = heap.alloc(layout) {
            let address = allocation.as_ptr() as usize;
            assert!(address >= start && address + 4096 <= start + REGION_SIZE);
            allocations.push(allocation);
        }
        assert!(!allocations.is_empty());
        for allocation in allocations {
            // SAFETY: each allocation is returned once with its original layout.
            unsafe {
                heap.dealloc(allocation, layout);
            }
        }
        assert_eq!(heap.stats_alloc_actual(), 0);
    }

    #[test]
    fn deterministic_churn_preserves_allocation_state() {
        const REGION_SIZE: usize = 1 << 20;
        let region = TestRegion::new(REGION_SIZE, REGION_SIZE);
        let mut heap = BuddyHeap::<ONE_MIB_BITMAP_WORDS>::new();
        // SAFETY: the test region remains alive and exclusively owned here.
        unsafe {
            heap.init(region.ptr.as_ptr() as usize, REGION_SIZE);
        }

        let layouts = [
            Layout::from_size_align(8, 8).expect("layout"),
            Layout::from_size_align(48, 16).expect("layout"),
            Layout::from_size_align(255, 64).expect("layout"),
            Layout::from_size_align(1025, 32).expect("layout"),
            Layout::from_size_align(4096, 4096).expect("layout"),
        ];
        let mut state = 0x4d59_5df4_d0f3_3173u64;
        let mut live = Vec::new();
        for _ in 0..20_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            if state & 3 != 0 && live.len() < 512 {
                let layout = layouts[state as usize % layouts.len()];
                if let Ok(allocation) = heap.alloc(layout) {
                    let actual = 1usize
                        << BuddyHeap::<ONE_MIB_BITMAP_WORDS>::layout_order(layout)
                            .expect("layout order");
                    let address = allocation.as_ptr() as usize;
                    for (other, other_actual, _) in &live {
                        assert!(
                            address + actual <= *other || *other + *other_actual <= address,
                            "churn allocations overlap"
                        );
                    }
                    live.push((address, actual, layout));
                }
            } else if !live.is_empty() {
                let index = state as usize % live.len();
                let (address, _, layout) = live.swap_remove(index);
                // SAFETY: swap_remove selects one live allocation and retains
                // its original layout for this single deallocation.
                unsafe {
                    heap.dealloc(NonNull::new_unchecked(address as *mut u8), layout);
                }
            }
        }

        while let Some((address, _, layout)) = live.pop() {
            // SAFETY: every remaining allocation is live and freed once.
            unsafe {
                heap.dealloc(NonNull::new_unchecked(address as *mut u8), layout);
            }
        }
        let whole = Layout::from_size_align(REGION_SIZE, REGION_SIZE).expect("valid layout");
        assert_eq!(
            heap.alloc(whole).expect("coalesced after churn"),
            region.ptr
        );
    }

    #[test]
    fn shared_high_order_arena_survives_fragmented_local_heaps() {
        const LOCAL_SIZE: usize = 1 << 20;
        const SHARED_SIZE: usize = 1 << 21;
        // Match Linux's largest PCP-eligible order: 32 KiB for 4-KiB pages.
        const SMALL_BLOCK: usize = 1 << 15;
        const LARGE_BLOCK: usize = 1 << 18;
        const LOCAL_COUNT: usize = 4;
        const LOCAL_BITMAP_WORDS: usize = LOCAL_SIZE / MIN_BLOCK_SIZE / u64::BITS as usize;
        const SHARED_BITMAP_WORDS: usize = SHARED_SIZE / MIN_BLOCK_SIZE / u64::BITS as usize;

        let local_regions =
            core::array::from_fn::<_, LOCAL_COUNT, _>(|_| TestRegion::new(LOCAL_SIZE, LOCAL_SIZE));
        let shared_region = TestRegion::new(SHARED_SIZE, SHARED_SIZE);
        let mut local_heaps = core::array::from_fn::<_, LOCAL_COUNT, _>(|index| {
            let mut heap = BuddyHeap::<LOCAL_BITMAP_WORDS>::new();
            // SAFETY: every test region is disjoint and remains alive for the
            // whole test.
            unsafe {
                heap.init(local_regions[index].ptr.as_ptr() as usize, LOCAL_SIZE);
            }
            heap
        });
        let mut shared_heap = BuddyHeap::<SHARED_BITMAP_WORDS>::new();
        // SAFETY: the shared test region is disjoint and remains alive.
        unsafe {
            shared_heap.init(shared_region.ptr.as_ptr() as usize, SHARED_SIZE);
        }

        let small = Layout::from_size_align(SMALL_BLOCK, SMALL_BLOCK).expect("small layout");
        let large = Layout::from_size_align(LARGE_BLOCK, LARGE_BLOCK).expect("large layout");
        let mut local_allocations = core::array::from_fn::<_, LOCAL_COUNT, _>(|_| Vec::new());
        for (heap, allocations) in local_heaps.iter_mut().zip(local_allocations.iter_mut()) {
            while let Ok(allocation) = heap.alloc(small) {
                allocations.push(allocation);
            }
            assert_eq!(allocations.len(), LOCAL_SIZE / SMALL_BLOCK);
            for index in (0..allocations.len()).step_by(2) {
                // SAFETY: alternating live allocations are returned exactly
                // once, leaving isolated 64-KiB holes between live blocks.
                unsafe {
                    heap.dealloc(allocations[index], small);
                }
            }
        }

        let aggregate_local_free = LOCAL_COUNT * LOCAL_SIZE / 2;
        assert!(aggregate_local_free >= SHARED_SIZE);
        assert!(
            local_heaps
                .iter_mut()
                .all(|heap| heap.alloc(large).is_err())
        );

        let allocation = shared_heap
            .alloc(large)
            .expect("shared arena must preserve a high-order block");
        assert_eq!(allocation.as_ptr() as usize % LARGE_BLOCK, 0);
        // SAFETY: this is the live shared-arena allocation.
        unsafe {
            shared_heap.dealloc(allocation, large);
        }

        for (heap, allocations) in local_heaps.iter_mut().zip(local_allocations) {
            for (index, allocation) in allocations.into_iter().enumerate() {
                if index % 2 == 0 {
                    continue;
                }
                // SAFETY: every remaining local allocation is live and is
                // returned exactly once with its original layout.
                unsafe {
                    heap.dealloc(allocation, small);
                }
            }
            assert_eq!(heap.stats_alloc_actual(), 0);
        }
        assert_eq!(shared_heap.stats_alloc_actual(), 0);
    }
}
