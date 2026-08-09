//! The global allocator.

use crate::{
    config::{KERNEL_HEAP_SIZE, MAX_HARTS, PAGE_SIZE},
    mm::{
        buddy_heap::{BuddyHeap, MIN_BLOCK_SIZE, ORDER_COUNT},
        slab_heap::{SLAB_CLASS_COUNT, SLAB_CLASS_SIZES, SLAB_PAGE_SIZE, SlabHeap},
    },
    println,
    sync::LocalIrqSaveGuard,
};
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::{NonNull, addr_of, addr_of_mut},
};
use spin::mutex::SpinMutex;

const HEAP_PAGE_COUNT: usize = KERNEL_HEAP_SIZE / PAGE_SIZE;
/// Keep costly allocations out of the per-hart heaps so small slab pages
/// cannot fragment every possible high-order block. Linux makes orders above
/// `PAGE_ALLOC_COSTLY_ORDER` bypass PCP lists and use the shared zone buddy.
const SHARED_HIGH_ORDER_BYTES: usize = 96 * 1024 * 1024;
const SHARED_HIGH_ORDER_PAGES: usize = SHARED_HIGH_ORDER_BYTES / PAGE_SIZE;
const LOCAL_HEAP_PAGE_COUNT: usize = HEAP_PAGE_COUNT - SHARED_HIGH_ORDER_PAGES;
/// Linux permits orders through `PAGE_ALLOC_COSTLY_ORDER` on the per-CPU page
/// lists and sends only larger orders to the shared zone buddy. Preserve the
/// same boundary: with 4-KiB pages, orders 0..=3 remain local and order 4
/// (64 KiB) is the first allocation routed to the shared arena.
const PAGE_ALLOC_COSTLY_ORDER: usize = 3;
const SHARED_HIGH_ORDER_THRESHOLD: usize = PAGE_SIZE << (PAGE_ALLOC_COSTLY_ORDER + 1);

const HEAP_SHARD_BASE_PAGES: usize = LOCAL_HEAP_PAGE_COUNT / MAX_HARTS;
const HEAP_SHARD_EXTRA_PAGES: usize = LOCAL_HEAP_PAGE_COUNT % MAX_HARTS;
const HEAP_SHARD_MAX_PAGES: usize = HEAP_SHARD_BASE_PAGES + (HEAP_SHARD_EXTRA_PAGES != 0) as usize;
const HEAP_SHARD_FREE_BITMAP_WORDS: usize =
    (HEAP_SHARD_MAX_PAGES * PAGE_SIZE / MIN_BLOCK_SIZE).div_ceil(u64::BITS as usize);
const SHARED_HEAP_FREE_BITMAP_WORDS: usize =
    (SHARED_HIGH_ORDER_BYTES / MIN_BLOCK_SIZE).div_ceil(u64::BITS as usize);
const _: () = assert!(PAGE_SIZE == SLAB_PAGE_SIZE);
const _: () = assert!(KERNEL_HEAP_SIZE % PAGE_SIZE == 0);
const _: () = assert!(SHARED_HIGH_ORDER_BYTES % PAGE_SIZE == 0);
const _: () = assert!(SHARED_HIGH_ORDER_BYTES < KERNEL_HEAP_SIZE);
const _: () = assert!(SHARED_HIGH_ORDER_THRESHOLD.is_power_of_two());

type KernelHeap = SlabHeap<HEAP_SHARD_FREE_BITMAP_WORDS, HEAP_SHARD_MAX_PAGES>;
type SharedHeap = BuddyHeap<SHARED_HEAP_FREE_BITMAP_WORDS>;

const fn heap_shard_page_offset(index: usize) -> usize {
    index * HEAP_SHARD_BASE_PAGES
        + if index < HEAP_SHARD_EXTRA_PAGES {
            index
        } else {
            HEAP_SHARD_EXTRA_PAGES
        }
}

const fn heap_shard_page_count(index: usize) -> usize {
    HEAP_SHARD_BASE_PAGES + if index < HEAP_SHARD_EXTRA_PAGES { 1 } else { 0 }
}

/// Per-hart slab/buddy heaps plus a shared high-order buddy arena.
///
/// Rust's `buddy_system_allocator::LockedHeap` serializes every allocation and
/// free through one ticket lock.  Fork-heavy builds create and destroy enough
/// Arcs and vectors for that lock to dominate all harts. Linux uses per-CPU
/// allocator fast paths for the same reason, but PCP lists are caches backed by
/// a shared zone rather than permanent memory partitions. Keep the hot small
/// allocation path sharded, reserve one shared buddy for costly allocations,
/// and retain cross-tier fallback only for genuine exhaustion. Deallocation
/// routes by address, so tasks may migrate freely between operations.
struct ShardedHeap {
    shards: [SpinMutex<KernelHeap>; MAX_HARTS],
    shared_high_order: SpinMutex<SharedHeap>,
}

impl ShardedHeap {
    const fn empty() -> Self {
        Self {
            // Use the non-ticket spin mutex explicitly. A global allocator
            // cannot sleep, and ticket head-of-line blocking is especially
            // costly when QEMU schedules virtual harts cooperatively.
            shards: [const { SpinMutex::new(KernelHeap::new()) }; MAX_HARTS],
            shared_high_order: SpinMutex::new(SharedHeap::new()),
        }
    }

    unsafe fn init(&self, start: usize, size: usize) {
        debug_assert_eq!(size, KERNEL_HEAP_SIZE);
        debug_assert_eq!(size % PAGE_SIZE, 0);
        debug_assert!(HEAP_SHARD_BASE_PAGES > 0);
        for (index, shard) in self.shards.iter().enumerate() {
            let shard_start = start + heap_shard_page_offset(index) * PAGE_SIZE;
            let shard_size = heap_shard_page_count(index) * PAGE_SIZE;
            // SAFETY: init_heap calls this once before secondary harts and
            // userspace start. Whole pages left by division are distributed
            // over the first shards. Their ranges are disjoint and cover the
            // local-allocation portion of HEAP_SPACE.
            let _irq_guard = LocalIrqSaveGuard::new();
            let mut shard = shard.lock();
            unsafe {
                shard.init(shard_start, shard_size);
            }
        }
        let shared_start = start + LOCAL_HEAP_PAGE_COUNT * PAGE_SIZE;
        let _irq_guard = LocalIrqSaveGuard::new();
        let mut shared = self.shared_high_order.lock();
        // SAFETY: this final range is disjoint from every local shard and is
        // exclusively owned by the allocator for the kernel lifetime.
        unsafe {
            shared.init(shared_start, SHARED_HIGH_ORDER_BYTES);
        }
    }

    fn stats(&self) -> (usize, usize, usize) {
        let local =
            self.shards
                .iter()
                .fold((0usize, 0usize, 0usize), |(user, actual, total), shard| {
                    let _irq_guard = LocalIrqSaveGuard::new();
                    let shard = shard.lock();
                    (
                        user.saturating_add(shard.stats_alloc_user()),
                        actual.saturating_add(shard.stats_alloc_actual()),
                        total.saturating_add(shard.stats_total_bytes()),
                    )
                });
        let shared = self.shared_stats();
        (
            local.0.saturating_add(shared.0),
            local.1.saturating_add(shared.1),
            local.2.saturating_add(shared.2),
        )
    }

    fn shared_stats(&self) -> (usize, usize, usize) {
        let _irq_guard = LocalIrqSaveGuard::new();
        let shared = self.shared_high_order.lock();
        (
            shared.stats_alloc_user(),
            shared.stats_alloc_actual(),
            shared.stats_total_bytes(),
        )
    }

    fn order_stats(&self, order: usize) -> (usize, usize, usize) {
        let local =
            self.shards
                .iter()
                .fold((0usize, 0usize, 0usize), |(live, user, free), shard| {
                    let _irq_guard = LocalIrqSaveGuard::new();
                    let shard = shard.lock();
                    let (shard_live, shard_user, shard_free) = shard.stats_order(order);
                    (
                        live.saturating_add(shard_live),
                        user.saturating_add(shard_user),
                        free.saturating_add(shard_free),
                    )
                });
        let shared = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let shared = self.shared_high_order.lock();
            shared.stats_order(order)
        };
        (
            local.0.saturating_add(shared.0),
            local.1.saturating_add(shared.1),
            local.2.saturating_add(shared.2),
        )
    }

    fn slab_stats(&self, class_index: usize) -> (usize, usize, usize) {
        self.shards
            .iter()
            .fold((0usize, 0usize, 0usize), |(live, user, pages), shard| {
                let _irq_guard = LocalIrqSaveGuard::new();
                let shard = shard.lock();
                let (shard_live, shard_user, shard_pages) = shard.stats_slab_class(class_index);
                (
                    live.saturating_add(shard_live),
                    user.saturating_add(shard_user),
                    pages.saturating_add(shard_pages),
                )
            })
    }

    fn shard_for_ptr(&self, ptr: *mut u8) -> Option<&SpinMutex<KernelHeap>> {
        let heap_start = addr_of!(HEAP_SPACE) as usize;
        let offset = (ptr as usize).checked_sub(heap_start)?;
        if offset >= LOCAL_HEAP_PAGE_COUNT * PAGE_SIZE {
            return None;
        }
        let page_offset = offset / PAGE_SIZE;
        let larger_shard_pages = HEAP_SHARD_BASE_PAGES + 1;
        let larger_shards_end = HEAP_SHARD_EXTRA_PAGES * larger_shard_pages;
        let index = if page_offset < larger_shards_end {
            page_offset / larger_shard_pages
        } else {
            HEAP_SHARD_EXTRA_PAGES + (page_offset - larger_shards_end) / HEAP_SHARD_BASE_PAGES
        };
        self.shards.get(index)
    }

    fn ptr_is_shared(&self, ptr: *mut u8) -> bool {
        let heap_start = addr_of!(HEAP_SPACE) as usize;
        let shared_start = heap_start + LOCAL_HEAP_PAGE_COUNT * PAGE_SIZE;
        let address = ptr as usize;
        address >= shared_start && address < heap_start + KERNEL_HEAP_SIZE
    }

    fn layout_prefers_shared(layout: Layout) -> bool {
        layout.size().max(layout.align()) >= SHARED_HIGH_ORDER_THRESHOLD
    }

    fn alloc_from_shared(&self, layout: Layout) -> Option<NonNull<u8>> {
        let (allocation, actual_before, actual_after) = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let mut shared = self.shared_high_order.lock();
            let actual_before = if crate::perf::enabled() {
                shared.stats_alloc_actual()
            } else {
                0
            };
            let allocation = shared.alloc(layout).ok();
            let actual_after = if crate::perf::enabled() {
                shared.stats_alloc_actual()
            } else {
                0
            };
            (allocation, actual_before, actual_after)
        };
        crate::perf::record_heap_actual_transition(actual_before, actual_after);
        crate::perf::record_heap_shared_actual_transition(actual_before, actual_after);
        allocation
    }

    fn alloc_from_shards(&self, layout: Layout, local: usize) -> Option<NonNull<u8>> {
        for offset in 0..MAX_HARTS {
            let index = (local + offset) % MAX_HARTS;
            // Linux spin_lock() disables preemption, and allocator locks that
            // are reachable from hardirq paths use irq-save semantics. Keep
            // the owning task on this hart until the shard lock is released;
            // otherwise a timer interrupt could schedule it out permanently
            // while another hart spins on the same allocator shard.
            let (allocation, actual_before, actual_after) = {
                let _irq_guard = LocalIrqSaveGuard::new();
                let mut shard = self.shards[index].lock();
                let actual_before = if crate::perf::enabled() {
                    shard.stats_alloc_actual()
                } else {
                    0
                };
                let allocation = shard.alloc(layout).ok();
                let actual_after = if crate::perf::enabled() {
                    shard.stats_alloc_actual()
                } else {
                    0
                };
                (allocation, actual_before, actual_after)
            };
            if allocation.is_some() {
                crate::perf::record_heap_actual_transition(actual_before, actual_after);
                return allocation;
            }
        }
        None
    }
}

unsafe impl GlobalAlloc for ShardedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let local = crate::arch::hart_id() % MAX_HARTS;
        if Self::layout_prefers_shared(layout) {
            if let Some(allocation) = self.alloc_from_shared(layout) {
                crate::perf::record_heap_shared_allocation(false);
                return allocation.as_ptr();
            }
            if let Some(allocation) = self.alloc_from_shards(layout, local) {
                crate::perf::record_heap_large_shard_fallback();
                return allocation.as_ptr();
            }
        } else {
            if let Some(allocation) = self.alloc_from_shards(layout, local) {
                return allocation.as_ptr();
            }
            // This is an emergency capacity fallback, analogous to draining a
            // PCP cache and retrying the zone rather than treating reserved
            // local capacity as a hard partition.
            if let Some(allocation) = self.alloc_from_shared(layout) {
                crate::perf::record_heap_shared_allocation(true);
                return allocation.as_ptr();
            }
        }
        crate::perf::record_heap_allocation_failure();
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.ptr_is_shared(ptr) {
            // SAFETY: GlobalAlloc requires `ptr` and `layout` to match a live
            // allocation. Address routing selects the shared arena that owns
            // this range, independent of the allocating hart.
            let (actual_before, actual_after) = {
                let _irq_guard = LocalIrqSaveGuard::new();
                let mut shared = self.shared_high_order.lock();
                let actual_before = if crate::perf::enabled() {
                    shared.stats_alloc_actual()
                } else {
                    0
                };
                unsafe {
                    shared.dealloc(NonNull::new_unchecked(ptr), layout);
                }
                let actual_after = if crate::perf::enabled() {
                    shared.stats_alloc_actual()
                } else {
                    0
                };
                (actual_before, actual_after)
            };
            crate::perf::record_heap_actual_transition(actual_before, actual_after);
            crate::perf::record_heap_shared_actual_transition(actual_before, actual_after);
            return;
        }

        let shard = self
            .shard_for_ptr(ptr)
            .expect("global allocator received a pointer outside HEAP_SPACE");
        // SAFETY: address routing selects the allocation's original local
        // shard, even if the task migrated after allocation.
        let (actual_before, actual_after) = {
            let _irq_guard = LocalIrqSaveGuard::new();
            let mut shard = shard.lock();
            let actual_before = if crate::perf::enabled() {
                shard.stats_alloc_actual()
            } else {
                0
            };
            unsafe {
                shard.dealloc(NonNull::new_unchecked(ptr), layout);
            }
            let actual_after = if crate::perf::enabled() {
                shard.stats_alloc_actual()
            } else {
                0
            };
            (actual_before, actual_after)
        };
        crate::perf::record_heap_actual_transition(actual_before, actual_after);
    }
}

#[global_allocator]
static HEAP_ALLOCATOR: ShardedHeap = ShardedHeap::empty();

#[alloc_error_handler]
/// panic when heap allocation error occurs
pub fn handle_alloc_error(layout: core::alloc::Layout) -> ! {
    let (id, args) = crate::syscall::last_syscall_snapshot();
    let (alloc_user, alloc_actual, total_bytes) = HEAP_ALLOCATOR.stats();
    let (shared_user, shared_actual, shared_total) = HEAP_ALLOCATOR.shared_stats();
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
        "[oom][heap-shared] threshold={} user={} actual={} total={} free={}",
        SHARED_HIGH_ORDER_THRESHOLD,
        shared_user,
        shared_actual,
        shared_total,
        shared_total.saturating_sub(shared_actual)
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

/// Page-aligned heap space split into local small-object shards and one shared
/// high-order arena.
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
    let bss_range = sbss as usize..ebss as usize;
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
