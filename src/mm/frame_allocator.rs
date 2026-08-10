//! Implementation of [`FrameAllocator`] which
//! controls all the frames in the operating system.

use super::{PhysAddr, PhysPageNum};
use crate::{
    config::{phys_mem_end, phys_mem_start},
    println,
    sync::LocalIrqSaveGuard,
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::{
    fmt::{self, Debug, Formatter},
    hint::spin_loop,
    ptr,
    sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering, fence},
};
use lazy_static::*;
use spin::{Mutex, Once};

static FRAME_ALLOC_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);
static FRAME_LIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
static PAGE_DESC_CHUNK_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_arch = "riscv64")]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameIcacheState {
    /// Frames outside the ordinary inode page cache stay untracked.
    ///
    /// Anonymous/COW and memfd/tmpfs frames keep using their existing explicit
    /// per-mm I-cache flush boundaries; this state machine never claims their
    /// contents have completed the reusable file-page synchronization.
    Untracked,
    Dirty,
    Clean,
}

#[cfg(target_arch = "riscv64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcacheSyncOutcome {
    Hit,
    Miss,
    Bypass,
}

const PAGE_DESC_CHUNK_SHIFT: usize = 9;
const PAGE_DESCS_PER_CHUNK: usize = 1 << PAGE_DESC_CHUNK_SHIFT;
const PAGE_DESC_CHUNK_MASK: usize = PAGE_DESCS_PER_CHUNK - 1;

const PAGE_STATE_USER_LOCK: u32 = 1 << 0;
const PAGE_STATE_ICACHE_LOCK: u32 = 1 << 1;
#[cfg(target_arch = "riscv64")]
const PAGE_STATE_ICACHE_SHIFT: u32 = 2;
#[cfg(target_arch = "riscv64")]
const PAGE_STATE_ICACHE_MASK: u32 = 0b11 << PAGE_STATE_ICACHE_SHIFT;
const PAGE_STATE_PIN_SHIFT: u32 = 4;
const PAGE_STATE_PIN_ONE: u32 = 1 << PAGE_STATE_PIN_SHIFT;
const PAGE_STATE_PIN_MASK: u32 = !((1 << PAGE_STATE_PIN_SHIFT) - 1);
const PAGE_STATE_PIN_MAX: u32 = PAGE_STATE_PIN_MASK >> PAGE_STATE_PIN_SHIFT;

/// Compact Linux-like metadata for one managed physical page.
///
/// Linux keeps refcount and page flags in a preallocated `struct page`
/// array.  The two low lock bits here replace the much larger per-page ticket
/// mutexes that used to live in every `Arc<FrameOwner>` allocation. Writable
/// uaccess pins occupy the high 28 bits of `state`; RISC-V uses two remaining
/// bits for its PG_dcache_clean-equivalent state.
struct PageDesc {
    refcount: AtomicU32,
    state: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<PageDesc>() == 8);

impl PageDesc {
    const fn new() -> Self {
        Self {
            refcount: AtomicU32::new(0),
            state: AtomicU32::new(0),
        }
    }

    fn claim(&self) {
        assert_eq!(
            self.state.load(Ordering::Acquire),
            0,
            "claiming a frame with stale PageDesc state"
        );
        assert!(
            self.refcount
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "claiming a frame whose PageDesc is still referenced"
        );
    }

    fn get(&self) {
        let mut current = self.refcount.load(Ordering::Relaxed);
        loop {
            assert!(
                current > 0 && current < u32::MAX,
                "invalid PageDesc refcount increment from {}",
                current
            );
            match self.refcount.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    /// Drop one reference and return true when the physical page may be freed.
    fn put(&self) -> bool {
        let previous = self.refcount.fetch_sub(1, Ordering::Release);
        assert!(previous > 0, "PageDesc refcount underflow");
        if previous != 1 {
            return false;
        }
        fence(Ordering::Acquire);
        let state = self.state.swap(0, Ordering::AcqRel);
        let busy = PAGE_STATE_USER_LOCK | PAGE_STATE_ICACHE_LOCK | PAGE_STATE_PIN_MASK;
        assert_eq!(state & busy, 0, "freeing a pinned or locked PageDesc");
        true
    }

    fn refcount(&self) -> usize {
        self.refcount.load(Ordering::Acquire) as usize
    }

    fn writable_uaccess_pins(&self) -> usize {
        ((self.state.load(Ordering::Acquire) & PAGE_STATE_PIN_MASK) >> PAGE_STATE_PIN_SHIFT)
            as usize
    }

    fn pin_writable_uaccess(&self) {
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            let pins = (current & PAGE_STATE_PIN_MASK) >> PAGE_STATE_PIN_SHIFT;
            assert!(pins < PAGE_STATE_PIN_MAX, "writable uaccess pin overflow");
            let next = current + PAGE_STATE_PIN_ONE;
            match self.state.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn unpin_writable_uaccess(&self) {
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            let pins = (current & PAGE_STATE_PIN_MASK) >> PAGE_STATE_PIN_SHIFT;
            assert!(pins > 0, "writable uaccess pin underflow");
            match self.state.compare_exchange_weak(
                current,
                current - PAGE_STATE_PIN_ONE,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn lock_user_access(&self) -> PageStateBitGuard<'_> {
        self.lock_state_bit(PAGE_STATE_USER_LOCK)
    }

    #[cfg(target_arch = "riscv64")]
    fn lock_icache_state(&self) -> PageStateBitGuard<'_> {
        self.lock_state_bit(PAGE_STATE_ICACHE_LOCK)
    }

    fn lock_state_bit(&self, bit: u32) -> PageStateBitGuard<'_> {
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            if current & bit != 0 {
                while self.state.load(Ordering::Relaxed) & bit != 0 {
                    spin_loop();
                }
                current = self.state.load(Ordering::Relaxed);
                continue;
            }
            match self.state.compare_exchange_weak(
                current,
                current | bit,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return PageStateBitGuard { desc: self, bit },
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(target_arch = "riscv64")]
    fn icache_state_locked(&self) -> FrameIcacheState {
        match (self.state.load(Ordering::Relaxed) & PAGE_STATE_ICACHE_MASK)
            >> PAGE_STATE_ICACHE_SHIFT
        {
            0 => FrameIcacheState::Untracked,
            1 => FrameIcacheState::Dirty,
            2 => FrameIcacheState::Clean,
            value => panic!("invalid PageDesc I-cache state {}", value),
        }
    }

    #[cfg(target_arch = "riscv64")]
    fn set_icache_state_locked(&self, value: FrameIcacheState) {
        let encoded = (value as u32) << PAGE_STATE_ICACHE_SHIFT;
        let _ = self
            .state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                Some((state & !PAGE_STATE_ICACHE_MASK) | encoded)
            });
    }
}

struct PageStateBitGuard<'a> {
    desc: &'a PageDesc,
    bit: u32,
}

impl Drop for PageStateBitGuard<'_> {
    fn drop(&mut self) {
        let previous = self.desc.state.fetch_and(!self.bit, Ordering::Release);
        debug_assert_ne!(previous & self.bit, 0);
    }
}

struct PageDescChunk {
    entries: [PageDesc; PAGE_DESCS_PER_CHUNK],
}

impl PageDescChunk {
    fn new() -> Self {
        Self {
            entries: [const { PageDesc::new() }; PAGE_DESCS_PER_CHUNK],
        }
    }
}

const _: () = assert!(core::mem::size_of::<PageDescChunk>() == crate::config::PAGE_SIZE);

/// Sparse vmemmap-style PFN index. The top table is fixed at boot; one 4-KiB
/// descriptor chunk is allocated on first use for each 2-MiB physical range.
struct PageDescTable {
    start_ppn: usize,
    end_ppn: usize,
    chunks: Box<[AtomicPtr<PageDescChunk>]>,
}

impl PageDescTable {
    fn new(start_ppn: usize, end_ppn: usize) -> Self {
        assert!(end_ppn > start_ppn);
        let pages = end_ppn - start_ppn;
        let chunk_count = pages.div_ceil(PAGE_DESCS_PER_CHUNK);
        let mut chunks = Vec::with_capacity(chunk_count);
        chunks.resize_with(chunk_count, || AtomicPtr::new(ptr::null_mut()));
        Self {
            start_ppn,
            end_ppn,
            chunks: chunks.into_boxed_slice(),
        }
    }

    fn get_or_init(&self, ppn: PhysPageNum) -> &'static PageDesc {
        assert!(
            ppn.0 >= self.start_ppn && ppn.0 < self.end_ppn,
            "PPN {:#x} lies outside PageDesc table [{:#x}, {:#x})",
            ppn.0,
            self.start_ppn,
            self.end_ppn
        );
        let relative = ppn.0 - self.start_ppn;
        let chunk_index = relative >> PAGE_DESC_CHUNK_SHIFT;
        let entry_index = relative & PAGE_DESC_CHUNK_MASK;
        let slot = &self.chunks[chunk_index];
        let mut chunk = slot.load(Ordering::Acquire);
        if chunk.is_null() {
            let candidate = Box::into_raw(Box::new(PageDescChunk::new()));
            match slot.compare_exchange(
                ptr::null_mut(),
                candidate,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    PAGE_DESC_CHUNK_COUNT.fetch_add(1, Ordering::Relaxed);
                    chunk = candidate;
                }
                Err(existing) => {
                    // SAFETY: this allocation was never published; the CAS
                    // winner owns the distinct chunk stored in `slot`.
                    unsafe {
                        drop(Box::from_raw(candidate));
                    }
                    chunk = existing;
                }
            }
        }
        // SAFETY: descriptor chunks are leaked for the kernel lifetime after
        // publication, and `entry_index` is masked to the array bounds.
        unsafe { &(*chunk).entries[entry_index] }
    }

    fn top_level_bytes(&self) -> usize {
        self.chunks
            .len()
            .saturating_mul(core::mem::size_of::<AtomicPtr<PageDescChunk>>())
    }
}

static PAGE_DESC_TABLE: Once<PageDescTable> = Once::new();

fn init_page_desc_table(start_ppn: PhysPageNum, end_ppn: PhysPageNum) {
    PAGE_DESC_TABLE.call_once(|| PageDescTable::new(start_ppn.0, end_ppn.0));
}

fn page_desc(ppn: PhysPageNum) -> &'static PageDesc {
    PAGE_DESC_TABLE
        .get()
        .expect("PageDesc table is not initialized")
        .get_or_init(ppn)
}

/// manage a frame which has the same lifecycle as the tracker
pub struct FrameTracker {
    pub ppn: PhysPageNum,
    desc: &'static PageDesc,
}

impl FrameTracker {
    pub fn new(ppn: PhysPageNum) -> Self {
        let desc = page_desc(ppn);
        desc.claim();
        FRAME_LIVE_COUNT.fetch_add(1, Ordering::Relaxed);
        // page cleaning
        let bytes_array = ppn.get_bytes_array();
        for i in bytes_array {
            *i = 0;
        }
        Self { ppn, desc }
    }

    pub fn refcount(&self) -> usize {
        self.desc.refcount()
    }

    pub fn writable_uaccess_pins(&self) -> usize {
        self.desc.writable_uaccess_pins()
    }

    pub fn pin_user_buffer(&self, writable: bool) -> UserFramePin {
        if writable {
            self.desc.pin_writable_uaccess();
        }
        UserFramePin {
            frame: self.clone(),
            writable,
        }
    }

    /// Start tracking a fully initialized ordinary inode page-cache frame.
    ///
    /// Linux guarantees that `PG_arch_1` is clear when a folio enters the page
    /// cache. `Dirty` is the equivalent initial state here.
    pub(crate) fn enable_file_icache_tracking(&self) {
        #[cfg(target_arch = "riscv64")]
        {
            let _state_guard = self.desc.lock_icache_state();
            if self.desc.icache_state_locked() == FrameIcacheState::Untracked {
                self.desc.set_icache_state_locked(FrameIcacheState::Dirty);
            }
        }
    }

    /// Apply Linux RISC-V's `flush_icache_pte()` ordering to one leaf PTE.
    ///
    /// The owner lock substitutes for the folio lock that serializes Linux
    /// page-cache mutation against PTE installation. It prevents a writer from
    /// clearing the clean state between the flush and the leaf-PTE store.
    #[cfg(target_arch = "riscv64")]
    pub(crate) fn with_executable_mapping<R>(
        &self,
        sync: impl FnOnce(),
        publish: impl FnOnce() -> R,
    ) -> (IcacheSyncOutcome, R) {
        let _state_guard = self.desc.lock_icache_state();
        let outcome = match self.desc.icache_state_locked() {
            FrameIcacheState::Clean => IcacheSyncOutcome::Hit,
            FrameIcacheState::Dirty => {
                sync();
                self.desc.set_icache_state_locked(FrameIcacheState::Clean);
                IcacheSyncOutcome::Miss
            }
            FrameIcacheState::Untracked => {
                // Keep anonymous, COW, tmpfs, and other non-page-cache frames
                // on the existing per-mm synchronization path.
                sync();
                IcacheSyncOutcome::Bypass
            }
        };
        let result = publish();
        (outcome, result)
    }

    /// Perform a controlled frame mutation while the owner locks are held.
    fn with_bytes_mut_locked<R>(
        &self,
        page_offset: usize,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> R,
        #[cfg(target_arch = "riscv64")] _icache_guard: &PageStateBitGuard<'_>,
    ) -> R {
        debug_assert!(page_offset <= crate::config::PAGE_SIZE);
        debug_assert!(len <= crate::config::PAGE_SIZE.saturating_sub(page_offset));
        let page: PhysAddr = self.ppn.into();
        // SAFETY: the tracker keeps the frame allocated, the range is bounded
        // to this page, and user_buffer_access excludes every UserBuffer view.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut((page.0 + page_offset) as *mut u8, len) };
        let result = f(bytes);

        #[cfg(target_arch = "riscv64")]
        {
            // Linux calls flush_dcache_folio() after the kernel store and only
            // clears PG_dcache_clean. The next executable PTE publication
            // performs the deferred per-mm I-cache synchronization.
            if self.desc.icache_state_locked() != FrameIcacheState::Untracked {
                self.desc.set_icache_state_locked(FrameIcacheState::Dirty);
            }
        }
        result
    }

    /// Mutably borrow a frame fragment while maintaining tracked executable
    /// aliases. The slice cannot escape this safe closure API.
    pub(crate) fn with_bytes_mut<R>(
        &self,
        page_offset: usize,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> R {
        let _user_access = self.desc.lock_user_access();
        #[cfg(target_arch = "riscv64")]
        let icache_state = self.desc.lock_icache_state();
        self.with_bytes_mut_locked(
            page_offset,
            len,
            f,
            #[cfg(target_arch = "riscv64")]
            &icache_state,
        )
    }
}

impl Clone for FrameTracker {
    fn clone(&self) -> Self {
        self.desc.get();
        Self {
            ppn: self.ppn,
            desc: self.desc,
        }
    }
}

impl Drop for FrameTracker {
    fn drop(&mut self) {
        if self.desc.put() {
            FRAME_LIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
            frame_dealloc(self.ppn);
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
        let _access = self.frame.desc.lock_user_access();
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
        let _user_access = self.frame.desc.lock_user_access();
        #[cfg(target_arch = "riscv64")]
        let icache_state = self.frame.desc.lock_icache_state();
        self.frame.with_bytes_mut_locked(
            page_offset,
            len,
            f,
            #[cfg(target_arch = "riscv64")]
            &icache_state,
        )
    }
}

impl Drop for UserFramePin {
    fn drop(&mut self) {
        if self.writable {
            self.frame.desc.unpin_writable_uaccess();
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
    let memory_start = PhysAddr::from(phys_mem_start()).ceil();
    let memory_end = PhysAddr::from(phys_mem_end()).floor();
    init_page_desc_table(memory_start, memory_end);
    let kernel_end = PhysAddr::from(ekernel as usize).ceil();
    with_frame_allocator(|allocator| {
        allocator.init(kernel_end, memory_end);
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
        let refcnt_entries = FRAME_LIVE_COUNT.load(Ordering::Relaxed);
        println!(
            "[mm-debug] frame_alloc failed count={} current={:#x} end={:#x} recycled={} refcnt_entries={}",
            fails, current, end, recycled, refcnt_entries
        );
    }
    None
}

pub fn frame_refcount_entries() -> usize {
    FRAME_LIVE_COUNT.load(Ordering::Relaxed)
}

pub fn frame_metadata_chunks() -> usize {
    PAGE_DESC_CHUNK_COUNT.load(Ordering::Relaxed)
}

pub fn frame_metadata_bytes() -> usize {
    let top_level = PAGE_DESC_TABLE
        .get()
        .map(PageDescTable::top_level_bytes)
        .unwrap_or(0);
    top_level.saturating_add(
        frame_metadata_chunks().saturating_mul(core::mem::size_of::<PageDescChunk>()),
    )
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
