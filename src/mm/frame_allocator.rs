//! Implementation of [`FrameAllocator`] which
//! controls all the frames in the operating system.

use super::{PhysAddr, PhysPageNum};
use crate::{
    config::{MAX_RESERVED_MEMORY_REGIONS, for_each_phys_mem_range, for_each_reserved_range},
    println,
};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::{
    fmt::{self, Debug, Formatter},
    sync::atomic::{AtomicUsize, Ordering},
};
use lazy_static::*;
use spin::Mutex;

lazy_static! {
    /// Reference counts for physical frames (for COW/shared mappings).
    static ref FRAME_REFCOUNTS: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
}

static FRAME_ALLOC_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// manage a frame which has the same lifecycle as the tracker
pub struct FrameTracker {
    pub ppn: PhysPageNum,
}

impl FrameTracker {
    pub fn new(ppn: PhysPageNum) -> Self {
        // page cleaning
        let bytes_array = ppn.get_bytes_array();
        for i in bytes_array {
            *i = 0;
        }
        {
            let mut rc = FRAME_REFCOUNTS.lock();
            rc.insert(ppn.0, 1);
        }
        Self { ppn }
    }
}

impl Clone for FrameTracker {
    fn clone(&self) -> Self {
        let mut rc = FRAME_REFCOUNTS.lock();
        let e = rc.entry(self.ppn.0).or_insert(0);
        *e += 1;
        Self { ppn: self.ppn }
    }
}

impl Debug for FrameTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("FrameTracker:PPN={:#x}", self.ppn.0))
    }
}

impl Drop for FrameTracker {
    fn drop(&mut self) {
        let mut rc = FRAME_REFCOUNTS.lock();
        let Some(cnt) = rc.get_mut(&self.ppn.0) else {
            // Should not happen, but avoid double-free.
            return;
        };
        if *cnt <= 1 {
            rc.remove(&self.ppn.0);
            drop(rc);
            frame_dealloc(self.ppn);
        } else {
            *cnt -= 1;
        }
    }
}

trait FrameAllocator {
    fn new() -> Self;
    fn alloc(&mut self) -> Option<PhysPageNum>;
    fn dealloc(&mut self, ppn: PhysPageNum);
}

/// an implementation for frame allocator
#[derive(Clone, Copy)]
struct FrameRange {
    start: usize,
    current: usize,
    end: usize,
}

/// 按 DTB 报告的多段物理内存管理页帧。
pub struct StackFrameAllocator {
    ranges: Vec<FrameRange>,
    recycled: Vec<usize>,
    recycled_set: BTreeSet<usize>,
    managed_pages: usize,
}

#[allow(dead_code)]
impl StackFrameAllocator {
    pub fn init(&mut self, l: PhysPageNum, r: PhysPageNum) {
        self.ranges.clear();
        self.recycled.clear();
        self.recycled_set.clear();
        self.managed_pages = 0;
        self.add_range(l, r);
    }

    /// 向分配器登记一段左闭右开的连续物理页号区间。
    pub fn add_range(&mut self, l: PhysPageNum, r: PhysPageNum) {
        if r <= l {
            return;
        }
        self.managed_pages = self.managed_pages.saturating_add(r.0.saturating_sub(l.0));
        self.ranges.push(FrameRange {
            start: l.0,
            current: l.0,
            end: r.0,
        });
    }

    /// 从任意单个物理内存段的未分配尾部取出连续页，不跨越内存空洞。
    pub fn alloc_contiguous(&mut self, pages: usize) -> Option<PhysPageNum> {
        if pages == 0 {
            return None;
        }
        for range in self.ranges.iter_mut() {
            if range.current.saturating_add(pages) <= range.end {
                let start = range.current;
                range.current += pages;
                return Some(start.into());
            }
        }
        None
    }

    /// 判断页帧是否已经从某个内存段的线性分配区取出。
    fn was_allocated(&self, ppn: usize) -> bool {
        self.ranges
            .iter()
            .any(|range| range.start <= ppn && ppn < range.current)
    }
}
impl FrameAllocator for StackFrameAllocator {
    fn new() -> Self {
        Self {
            ranges: Vec::new(),
            recycled: Vec::new(),
            recycled_set: BTreeSet::new(),
            managed_pages: 0,
        }
    }
    fn alloc(&mut self) -> Option<PhysPageNum> {
        if let Some(ppn) = self.recycled.pop() {
            self.recycled_set.remove(&ppn);
            Some(ppn.into())
        } else {
            for range in self.ranges.iter_mut() {
                if range.current < range.end {
                    let ppn = range.current;
                    range.current += 1;
                    return Some(ppn.into());
                }
            }
            None
        }
    }
    fn dealloc(&mut self, ppn: PhysPageNum) {
        let ppn = ppn.0;
        // validity check
        if !self.was_allocated(ppn) || self.recycled_set.contains(&ppn) {
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
    let mut exclusions = [(0usize, 0usize); MAX_RESERVED_MEMORY_REGIONS + 1];
    let mut exclusion_count = 0usize;
    let mut add_exclusion = |start: usize, end: usize| {
        let start = PhysAddr::from(start).floor().0;
        let end = PhysAddr::from(end).ceil().0;
        if end <= start {
            return;
        }
        assert!(
            exclusion_count < exclusions.len(),
            "too many frame allocator exclusion ranges"
        );
        exclusions[exclusion_count] = (start, end);
        exclusion_count += 1;
    };
    add_exclusion(stext as usize, ekernel as usize);
    for_each_reserved_range(|start, end| add_exclusion(start, end));
    drop(add_exclusion);

    exclusions[..exclusion_count].sort_unstable_by_key(|range| range.0);
    let mut merged_count = 0usize;
    for index in 0..exclusion_count {
        let (start, end) = exclusions[index];
        if merged_count != 0 && start <= exclusions[merged_count - 1].1 {
            exclusions[merged_count - 1].1 = exclusions[merged_count - 1].1.max(end);
        } else {
            exclusions[merged_count] = (start, end);
            merged_count += 1;
        }
    }
    let mut allocator = FRAME_ALLOCATOR.lock();
    allocator.init(PhysPageNum(0), PhysPageNum(0));
    for_each_phys_mem_range(|start, end| {
        let start_ppn = PhysAddr::from(start).ceil().0;
        let end_ppn = PhysAddr::from(end).floor().0;
        if end_ppn <= start_ppn {
            return;
        }
        let mut cursor = start_ppn;
        for &(excluded_start, excluded_end) in &exclusions[..merged_count] {
            if excluded_end <= cursor {
                continue;
            }
            if excluded_start >= end_ppn {
                break;
            }
            if cursor < excluded_start {
                allocator.add_range(
                    PhysPageNum(cursor),
                    PhysPageNum(excluded_start.min(end_ppn)),
                );
            }
            cursor = cursor.max(excluded_end);
            if cursor >= end_ppn {
                break;
            }
        }
        if cursor < end_ppn {
            allocator.add_range(PhysPageNum(cursor), PhysPageNum(end_ppn));
        }
    });
}

/// allocate a frame
/// 优先分配，分配失败 尝试回收
pub fn frame_alloc() -> Option<FrameTracker> {
    let mut allocator = FRAME_ALLOCATOR.lock();
    if let Some(ppn) = allocator.alloc() {
        return Some(FrameTracker::new(ppn));
    }
    drop(allocator);

    let reclaimed = super::memory_set::reclaim_shared_file_page_cache();
    if reclaimed > 0 {
        let mut allocator = FRAME_ALLOCATOR.lock();
        if let Some(ppn) = allocator.alloc() {
            return Some(FrameTracker::new(ppn));
        }
        drop(allocator);
    }

    if crate::debug_config::DEBUG_PERF {
        let allocator = FRAME_ALLOCATOR.lock();
        let fails = FRAME_ALLOC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        let remaining = allocator
            .ranges
            .iter()
            .map(|range| range.end.saturating_sub(range.current))
            .sum::<usize>();
        let recycled = allocator.recycled.len();
        drop(allocator);
        let refcnt_entries = FRAME_REFCOUNTS.lock().len();
        println!(
            "[mm-debug] frame_alloc failed count={} remaining={} recycled={} refcnt_entries={}",
            fails, remaining, recycled, refcnt_entries
        );
    }
    None
}

pub fn frame_refcount_entries() -> usize {
    FRAME_REFCOUNTS.lock().len()
}

pub(crate) fn frame_refcount(ppn: PhysPageNum) -> usize {
    FRAME_REFCOUNTS.lock().get(&ppn.0).copied().unwrap_or(0)
}

pub fn frame_available_pages() -> usize {
    let allocator = FRAME_ALLOCATOR.lock();
    allocator.recycled.len()
        + allocator
            .ranges
            .iter()
            .map(|range| range.end.saturating_sub(range.current))
            .sum::<usize>()
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
