//! Implementation of [`FrameAllocator`] which
//! controls all the frames in the operating system.

use super::{PhysAddr, PhysPageNum};
use crate::{config::phys_mem_end, println};
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    fmt::{self, Debug, Formatter},
    sync::atomic::{AtomicUsize, Ordering},
};
use lazy_static::*;
use spin::Mutex;

static FRAME_ALLOC_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);
static FRAME_OWNER_COUNT: AtomicUsize = AtomicUsize::new(0);

struct FrameOwner {
    ppn: PhysPageNum,
}

impl Drop for FrameOwner {
    fn drop(&mut self) {
        FRAME_OWNER_COUNT.fetch_sub(1, Ordering::Relaxed);
        frame_dealloc(self.ppn);
    }
}

/// manage a frame which has the same lifecycle as the tracker
#[derive(Clone)]
pub struct FrameTracker {
    pub ppn: PhysPageNum,
    owner: Arc<FrameOwner>,
}

impl FrameTracker {
    pub fn new(ppn: PhysPageNum) -> Self {
        // page cleaning
        let bytes_array = ppn.get_bytes_array();
        for i in bytes_array {
            *i = 0;
        }
        FRAME_OWNER_COUNT.fetch_add(1, Ordering::Relaxed);
        Self {
            ppn,
            owner: Arc::new(FrameOwner { ppn }),
        }
    }

    pub fn refcount(&self) -> usize {
        Arc::strong_count(&self.owner)
    }
}

impl Debug for FrameTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("FrameTracker:PPN={:#x}", self.ppn.0))
    }
}

trait FrameAllocator {
    fn new() -> Self;
    fn alloc(&mut self) -> Option<PhysPageNum>;
    fn dealloc(&mut self, ppn: PhysPageNum);
}

/// an implementation for frame allocator
pub struct StackFrameAllocator {
    current: usize,
    end: usize,
    recycled: Vec<usize>,
    recycled_set: BTreeSet<usize>,
    managed_pages: usize,
}

#[allow(dead_code)]
impl StackFrameAllocator {
    pub fn init(&mut self, l: PhysPageNum, r: PhysPageNum) {
        self.current = l.0;
        self.end = r.0;
        self.managed_pages = r.0.saturating_sub(l.0);
    }

    pub fn add_range(&mut self, l: PhysPageNum, r: PhysPageNum) {
        if r <= l {
            return;
        }
        self.managed_pages = self.managed_pages.saturating_add(r.0.saturating_sub(l.0));
        for ppn in l.0..r.0 {
            if !self.recycled_set.insert(ppn) {
                panic!("Frame ppn={:#x} has already been recycled!", ppn);
            }
            self.recycled.push(ppn);
        }
    }

    pub fn alloc_contiguous(&mut self, pages: usize) -> Option<PhysPageNum> {
        if pages == 0 {
            return None;
        }
        if self.current.saturating_add(pages) > self.end {
            return None;
        }
        let start = self.current;
        self.current += pages;
        Some(start.into())
    }
}
impl FrameAllocator for StackFrameAllocator {
    fn new() -> Self {
        Self {
            current: 0,
            end: 0,
            recycled: Vec::new(),
            recycled_set: BTreeSet::new(),
            managed_pages: 0,
        }
    }
    fn alloc(&mut self) -> Option<PhysPageNum> {
        if let Some(ppn) = self.recycled.pop() {
            self.recycled_set.remove(&ppn);
            Some(ppn.into())
        } else if self.current == self.end {
            None
        } else {
            self.current += 1;
            Some((self.current - 1).into())
        }
    }
    fn dealloc(&mut self, ppn: PhysPageNum) {
        let ppn = ppn.0;
        // validity check
        if ppn >= self.current || self.recycled_set.contains(&ppn) {
            panic!("Frame ppn={:#x} has not been allocated!", ppn);
        }
        // recycle
        self.recycled_set.insert(ppn);
        self.recycled.push(ppn);
    }
}

type FrameAllocatorImpl = StackFrameAllocator;

lazy_static! {
    /// frame allocator instance through lazy_static!
    pub static ref FRAME_ALLOCATOR: Mutex<FrameAllocatorImpl> = Mutex::new(FrameAllocatorImpl::new());
}

/// initiate the frame allocator using `ekernel` and detected physical memory end
#[allow(dead_code)]
pub fn init_frame_allocator() {
    #[allow(dead_code)]
    unsafe extern "C" {
        safe fn ekernel();
        safe fn stext();
    }
    let kernel_end = PhysAddr::from(ekernel as usize).ceil();
    let mut allocator = FRAME_ALLOCATOR.lock();
    allocator.init(kernel_end, PhysAddr::from(phys_mem_end()).floor());
    #[cfg(target_arch = "loongarch64")]
    {
        use crate::config::phys_mem_start;
        let low_start = PhysAddr::from(phys_mem_start()).ceil();
        let kernel_start = PhysAddr::from(stext as usize).floor();
        allocator.add_range(low_start, kernel_start);
    }
}

/// allocate a frame
/// 优先分配，分配失败 尝试回收
pub fn frame_alloc() -> Option<FrameTracker> {
    // Keep the allocator lock around free-list metadata only.  In particular,
    // do not zero the 4 KiB page or allocate the Arc control block while every
    // other faulting hart is waiting for FRAME_ALLOCATOR.  Linux follows the
    // same split: rmqueue() removes a page under allocator locking, then
    // prep_new_page()/post_alloc_hook() initialize it after the free-list
    // operation has completed.
    let ppn = FRAME_ALLOCATOR.lock().alloc();
    if let Some(ppn) = ppn {
        return Some(FrameTracker::new(ppn));
    }

    let reclaimed = super::memory_set::reclaim_shared_file_page_cache();
    if reclaimed > 0 {
        let ppn = FRAME_ALLOCATOR.lock().alloc();
        if let Some(ppn) = ppn {
            return Some(FrameTracker::new(ppn));
        }
    }

    if crate::debug_config::DEBUG_PERF {
        let allocator = FRAME_ALLOCATOR.lock();
        let fails = FRAME_ALLOC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        let current = allocator.current;
        let end = allocator.end;
        let recycled = allocator.recycled.len();
        drop(allocator);
        let refcnt_entries = FRAME_OWNER_COUNT.load(Ordering::Relaxed);
        println!(
            "[mm-debug] frame_alloc failed count={} current={:#x} end={:#x} recycled={} refcnt_entries={}",
            fails, current, end, recycled, refcnt_entries
        );
    }
    None
}

pub fn frame_refcount_entries() -> usize {
    FRAME_OWNER_COUNT.load(Ordering::Relaxed)
}

pub fn frame_available_pages() -> usize {
    let allocator = FRAME_ALLOCATOR.lock();
    allocator.recycled.len() + allocator.end.saturating_sub(allocator.current)
}

pub fn frame_managed_pages() -> usize {
    FRAME_ALLOCATOR.lock().managed_pages
}

pub fn frame_alloc_contiguous(pages: usize) -> Option<Vec<FrameTracker>> {
    let start = FRAME_ALLOCATOR.lock().alloc_contiguous(pages)?;
    let mut frames = Vec::with_capacity(pages);
    for i in 0..pages {
        frames.push(FrameTracker::new(PhysPageNum(start.0 + i)));
    }
    Some(frames)
}

/// deallocate a frame
pub fn frame_dealloc(ppn: PhysPageNum) {
    FRAME_ALLOCATOR.lock().dealloc(ppn);
}

#[allow(unused)]
/// a simple test for frame allocator
pub fn frame_allocator_test() {
    let mut v: Vec<FrameTracker> = Vec::new();
    for i in 0..5 {
        let frame = frame_alloc().unwrap();
        println!("{:?}", frame);
        v.push(frame);
    }
    v.clear();
    for i in 0..5 {
        let frame = frame_alloc().unwrap();
        println!("{:?}", frame);
        v.push(frame);
    }
    drop(v);
    println!("frame_allocator_test passed!");
}
