//! The global allocator.

use crate::{
    config::{KERNEL_HEAP_SIZE, MAX_HARTS, PAGE_SIZE},
    mm::{
        buddy_heap::{MIN_BLOCK_SIZE, ORDER_COUNT},
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
const HEAP_SHARD_BASE_PAGES: usize = HEAP_PAGE_COUNT / MAX_HARTS;
const HEAP_SHARD_EXTRA_PAGES: usize = HEAP_PAGE_COUNT % MAX_HARTS;
const HEAP_SHARD_MAX_PAGES: usize = HEAP_SHARD_BASE_PAGES + (HEAP_SHARD_EXTRA_PAGES != 0) as usize;
const HEAP_SHARD_FREE_BITMAP_WORDS: usize =
    (HEAP_SHARD_MAX_PAGES * PAGE_SIZE / MIN_BLOCK_SIZE).div_ceil(u64::BITS as usize);
const _: () = assert!(PAGE_SIZE == SLAB_PAGE_SIZE);

type KernelHeap = SlabHeap<HEAP_SHARD_FREE_BITMAP_WORDS, HEAP_SHARD_MAX_PAGES>;

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

/// Per-hart slab/buddy heaps.
///
/// Rust's `buddy_system_allocator::LockedHeap` serializes every allocation and
/// free through one ticket lock.  Fork-heavy builds create and destroy enough
/// Arcs and vectors for that lock to dominate all harts.  Linux uses per-CPU
/// allocator fast paths for the same reason.  Keep buddy allocation semantics,
/// but partition the fixed heap into independently locked arenas.  Allocation
/// falls back to another arena when the local one is full; deallocation routes
/// by address, so tasks may migrate freely between the two operations.
struct ShardedHeap {
    shards: [SpinMutex<KernelHeap>; MAX_HARTS],
}

impl ShardedHeap {
    const fn empty() -> Self {
        Self {
            // Use the non-ticket spin mutex explicitly. A global allocator
            // cannot sleep, and ticket head-of-line blocking is especially
            // costly when QEMU schedules virtual harts cooperatively.
            shards: [const { SpinMutex::new(KernelHeap::new()) }; MAX_HARTS],
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
            // over the first shards, so ranges are disjoint and cover all of
            // HEAP_SPACE even when MAX_HARTS does not divide 512 MiB.
            let _irq_guard = LocalIrqSaveGuard::new();
            let mut shard = shard.lock();
            unsafe {
                shard.init(shard_start, shard_size);
            }
        }
    }

    fn stats(&self) -> (usize, usize, usize) {
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
            })
    }

    fn order_stats(&self, order: usize) -> (usize, usize, usize) {
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
            })
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
        if offset >= KERNEL_HEAP_SIZE {
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
}

unsafe impl GlobalAlloc for ShardedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let local = crate::arch::hart_id() % MAX_HARTS;
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
                let allocation = shard.alloc(layout);
                let actual_after = if crate::perf::enabled() {
                    shard.stats_alloc_actual()
                } else {
                    0
                };
                (allocation, actual_before, actual_after)
            };
            if let Ok(allocation) = allocation {
                crate::perf::record_heap_actual_transition(actual_before, actual_after);
                return allocation.as_ptr();
            }
        }
        crate::perf::record_heap_allocation_failure();
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let shard = self
            .shard_for_ptr(ptr)
            .expect("global allocator received a pointer outside HEAP_SPACE");
        // SAFETY: GlobalAlloc requires `ptr` to come from a previous successful
        // allocation with the same layout. Address routing selects that
        // allocation's original, disjoint buddy arena.
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

/// Page-aligned heap space, partitioned into page-aligned per-hart shards.
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
