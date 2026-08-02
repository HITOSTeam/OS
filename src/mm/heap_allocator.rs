//! The global allocator.

use crate::{
    config::{KERNEL_HEAP_SIZE, MAX_HARTS, PAGE_SIZE},
    println,
    sync::LocalIrqSaveGuard,
};
use buddy_system_allocator::Heap;
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::{NonNull, addr_of, addr_of_mut},
};
use spin::mutex::SpinMutex;

const HEAP_PAGE_COUNT: usize = KERNEL_HEAP_SIZE / PAGE_SIZE;
const HEAP_SHARD_BASE_PAGES: usize = HEAP_PAGE_COUNT / MAX_HARTS;
const HEAP_SHARD_EXTRA_PAGES: usize = HEAP_PAGE_COUNT % MAX_HARTS;

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

/// Per-hart buddy heaps.
///
/// Rust's `buddy_system_allocator::LockedHeap` serializes every allocation and
/// free through one ticket lock.  Fork-heavy builds create and destroy enough
/// Arcs and vectors for that lock to dominate all harts.  Linux uses per-CPU
/// allocator fast paths for the same reason.  Keep buddy allocation semantics,
/// but partition the fixed heap into independently locked arenas.  Allocation
/// falls back to another arena when the local one is full; deallocation routes
/// by address, so tasks may migrate freely between the two operations.
struct ShardedHeap {
    shards: [SpinMutex<Heap>; MAX_HARTS],
}

impl ShardedHeap {
    const fn empty() -> Self {
        Self {
            // Use the non-ticket spin mutex explicitly. A global allocator
            // cannot sleep, and ticket head-of-line blocking is especially
            // costly when QEMU schedules virtual harts cooperatively.
            shards: [const { SpinMutex::new(Heap::new()) }; MAX_HARTS],
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

    fn shard_for_ptr(&self, ptr: *mut u8) -> Option<&SpinMutex<Heap>> {
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
            let allocation = {
                let _irq_guard = LocalIrqSaveGuard::new();
                let mut shard = self.shards[index].lock();
                shard.alloc(layout)
            };
            if let Ok(allocation) = allocation {
                return allocation.as_ptr();
            }
        }
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let shard = self
            .shard_for_ptr(ptr)
            .expect("global allocator received a pointer outside HEAP_SPACE");
        // SAFETY: GlobalAlloc requires `ptr` to come from a previous successful
        // allocation with the same layout. Address routing selects that
        // allocation's original, disjoint buddy arena.
        let _irq_guard = LocalIrqSaveGuard::new();
        let mut shard = shard.lock();
        shard.dealloc(unsafe { NonNull::new_unchecked(ptr) }, layout);
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
