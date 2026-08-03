//! Implementation of [`FrameAllocator`] which
//! controls all the frames in the operating system.

use super::{PhysAddr, PhysPageNum};
use crate::{config::phys_mem_end, println, sync::LocalIrqSaveGuard};
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
    writable_uaccess_pins: AtomicUsize,
    /// Serializes short-lived kernel views created for pinned user buffers.
    ///
    /// A physical page can be mapped at more than one user virtual address and
    /// can consequently appear in overlapping `UserBuffer`s.  Keeping this
    /// lock in the shared owner makes those views mutually exclusive without
    /// manufacturing long-lived aliased Rust references.
    user_buffer_access: Mutex<()>,
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
            owner: Arc::new(FrameOwner {
                ppn,
                writable_uaccess_pins: AtomicUsize::new(0),
                user_buffer_access: Mutex::new(()),
            }),
        }
    }

    pub fn refcount(&self) -> usize {
        Arc::strong_count(&self.owner)
    }

    pub fn writable_uaccess_pins(&self) -> usize {
        self.owner.writable_uaccess_pins.load(Ordering::Acquire)
    }

    pub fn pin_user_buffer(&self, writable: bool) -> UserFramePin {
        if writable {
            self.owner
                .writable_uaccess_pins
                .fetch_add(1, Ordering::AcqRel);
        }
        UserFramePin {
            frame: self.clone(),
            writable,
        }
    }
}

/// A physical-page lifetime pin held by a potentially sleeping uaccess.
/// Writable pins are visible to fork so it can snapshot the child eagerly
/// instead of sharing a page that the blocked syscall may later modify.
pub struct UserFramePin {
    frame: FrameTracker,
    writable: bool,
}

impl UserFramePin {
    /// Borrow a page fragment only while its per-frame access lock is held.
    pub(crate) fn with_bytes<R>(
        &self,
        page_offset: usize,
        len: usize,
        f: impl FnOnce(&[u8]) -> R,
    ) -> R {
        debug_assert!(page_offset <= crate::config::PAGE_SIZE);
        debug_assert!(len <= crate::config::PAGE_SIZE.saturating_sub(page_offset));
        let _access = self.frame.owner.user_buffer_access.lock();
        let page: PhysAddr = self.frame.ppn.into();
        // SAFETY: the pin keeps the frame allocated, bounds were validated by
        // the UserBuffer constructor, and the owner lock excludes every other
        // UserBuffer view of this physical page for the duration of `f`.
        let bytes =
            unsafe { core::slice::from_raw_parts((page.0 + page_offset) as *const u8, len) };
        f(bytes)
    }

    /// Mutably borrow a page fragment only while its per-frame access lock is
    /// held.  The slice cannot escape the closure through this safe API.
    pub(crate) fn with_bytes_mut<R>(
        &self,
        page_offset: usize,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> R {
        debug_assert!(page_offset <= crate::config::PAGE_SIZE);
        debug_assert!(len <= crate::config::PAGE_SIZE.saturating_sub(page_offset));
        let _access = self.frame.owner.user_buffer_access.lock();
        let page: PhysAddr = self.frame.ppn.into();
        // SAFETY: as in `with_bytes`; the exclusive owner lock additionally
        // ensures no other pinned UserBuffer creates a simultaneous view.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut((page.0 + page_offset) as *mut u8, len) };
        f(bytes)
    }
}

impl Drop for UserFramePin {
    fn drop(&mut self) {
        if self.writable {
            let previous = self
                .frame
                .owner
                .writable_uaccess_pins
                .fetch_sub(1, Ordering::AcqRel);
            debug_assert!(previous > 0, "writable uaccess pin underflow");
        }
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
    /// One bit per physical page, set while the page is on `recycled`.
    ///
    /// The old BTreeSet allocated and freed one heap node for every frame
    /// recycle operation while holding FRAME_ALLOCATOR. Linux keeps buddy/free
    /// state in preallocated `struct page` metadata; this bitmap is the minimal
    /// equivalent needed for O(1) double-free validation in this allocator.
    recycled_bitmap: Vec<usize>,
    managed_pages: usize,
}

#[allow(dead_code)]
impl StackFrameAllocator {
    pub fn init(&mut self, l: PhysPageNum, r: PhysPageNum) {
        self.current = l.0;
        self.end = r.0;
        self.managed_pages = r.0.saturating_sub(l.0);
        self.ensure_recycled_bitmap(r.0);
    }

    pub fn add_range(&mut self, l: PhysPageNum, r: PhysPageNum) {
        if r <= l {
            return;
        }
        let pages = r.0.saturating_sub(l.0);
        self.managed_pages = self.managed_pages.saturating_add(pages);
        self.ensure_recycled_bitmap(r.0);
        self.recycled.reserve(pages);
        for ppn in l.0..r.0 {
            if !self.mark_recycled(ppn) {
                panic!("Frame ppn={:#x} has already been recycled!", ppn);
            }
            self.recycled.push(ppn);
        }
    }

    fn ensure_recycled_bitmap(&mut self, end_ppn: usize) {
        const BITS: usize = usize::BITS as usize;
        let words = end_ppn.saturating_add(BITS - 1) / BITS;
        self.recycled_bitmap.resize(words, 0);
    }

    fn is_recycled(&self, ppn: usize) -> bool {
        const BITS: usize = usize::BITS as usize;
        let word = ppn / BITS;
        let mask = 1usize << (ppn % BITS);
        self.recycled_bitmap
            .get(word)
            .is_some_and(|bits| (*bits & mask) != 0)
    }

    /// Mark `ppn` free, returning false when it was already on the free stack.
    fn mark_recycled(&mut self, ppn: usize) -> bool {
        const BITS: usize = usize::BITS as usize;
        let word = ppn / BITS;
        let mask = 1usize << (ppn % BITS);
        let bits = self
            .recycled_bitmap
            .get_mut(word)
            .expect("frame ppn lies outside recycled bitmap");
        let was_free = (*bits & mask) != 0;
        *bits |= mask;
        !was_free
    }

    /// Mark a recycled page allocated, returning false on free-stack corruption.
    fn take_recycled(&mut self, ppn: usize) -> bool {
        const BITS: usize = usize::BITS as usize;
        let word = ppn / BITS;
        let mask = 1usize << (ppn % BITS);
        let bits = self
            .recycled_bitmap
            .get_mut(word)
            .expect("frame ppn lies outside recycled bitmap");
        let was_free = (*bits & mask) != 0;
        *bits &= !mask;
        was_free
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
            recycled_bitmap: Vec::new(),
            managed_pages: 0,
        }
    }
    fn alloc(&mut self) -> Option<PhysPageNum> {
        if let Some(ppn) = self.recycled.pop() {
            assert!(
                self.take_recycled(ppn),
                "Frame ppn={:#x} was on the free stack without a free bit!",
                ppn
            );
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
        if ppn >= self.current || self.is_recycled(ppn) {
            panic!("Frame ppn={:#x} has not been allocated!", ppn);
        }
        // recycle
        assert!(self.mark_recycled(ppn));
        self.recycled.push(ppn);
    }
}

type FrameAllocatorImpl = StackFrameAllocator;

lazy_static! {
    /// frame allocator instance through lazy_static!
    pub static ref FRAME_ALLOCATOR: Mutex<FrameAllocatorImpl> = Mutex::new(FrameAllocatorImpl::new());
}

/// Run a frame free-list operation with Linux-style irq-save spinlock
/// semantics.  The `spin` crate lock alone does not disable timer preemption,
/// so its owner could otherwise be switched out while other harts spin on the
/// ticket lock.
fn with_frame_allocator<R>(f: impl FnOnce(&mut FrameAllocatorImpl) -> R) -> R {
    let _irq_guard = LocalIrqSaveGuard::new();
    let mut allocator = FRAME_ALLOCATOR.lock();
    f(&mut allocator)
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
    with_frame_allocator(|allocator| {
        allocator.init(kernel_end, PhysAddr::from(phys_mem_end()).floor());
        #[cfg(target_arch = "loongarch64")]
        {
            use crate::config::phys_mem_start;
            let low_start = PhysAddr::from(phys_mem_start()).ceil();
            let kernel_start = PhysAddr::from(stext as usize).floor();
            allocator.add_range(low_start, kernel_start);
        }
    });
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
    let ppn = with_frame_allocator(|allocator| allocator.alloc());
    if let Some(ppn) = ppn {
        return Some(FrameTracker::new(ppn));
    }

    let reclaimed = super::memory_set::reclaim_file_page_cache();
    if reclaimed > 0 {
        let ppn = with_frame_allocator(|allocator| allocator.alloc());
        if let Some(ppn) = ppn {
            return Some(FrameTracker::new(ppn));
        }
    }

    if crate::debug_config::DEBUG_PERF {
        let (current, end, recycled) = with_frame_allocator(|allocator| {
            (allocator.current, allocator.end, allocator.recycled.len())
        });
        let fails = FRAME_ALLOC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
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
    with_frame_allocator(|allocator| {
        allocator.recycled.len() + allocator.end.saturating_sub(allocator.current)
    })
}

pub fn frame_managed_pages() -> usize {
    with_frame_allocator(|allocator| allocator.managed_pages)
}

pub fn frame_alloc_contiguous(pages: usize) -> Option<Vec<FrameTracker>> {
    let start = with_frame_allocator(|allocator| allocator.alloc_contiguous(pages))?;
    let mut frames = Vec::with_capacity(pages);
    for i in 0..pages {
        frames.push(FrameTracker::new(PhysPageNum(start.0 + i)));
    }
    Some(frames)
}

/// deallocate a frame
pub fn frame_dealloc(ppn: PhysPageNum) {
    with_frame_allocator(|allocator| allocator.dealloc(ppn));
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
