//! Memory management implementation
//!
//! SV39 page-based virtual-memory architecture for RV64 systems, and
//! everything about memory management, like frame allocator, page table,
//! map area and memory set, is implemented here.
//!
//! Every task or process has a memory_set to control its virtual memory.

mod address;
mod dtb;
mod elf_loader;
mod frame_allocator;
mod heap_allocator;
mod memory_set;
#[cfg(target_arch = "loongarch64")]
pub use crate::arch::loongarch64::mm::page_table;
#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::mm::page_table;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::println;
pub use address::StepByOne;
use address::VPNRange;
pub use address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use alloc::vec::Vec;
#[allow(unused_imports)]
pub use dtb::HartTopology;
#[allow(unused_imports)]
pub use dtb::hart_topology_from_dtb;
#[allow(unused_imports)]
pub use dtb::init_phys_mem_from_dtb;
pub use frame_allocator::{
    FrameTracker, UserFramePin, frame_alloc, frame_alloc_contiguous, frame_available_pages,
    frame_managed_pages, frame_refcount_entries,
};
pub use memory_set::kernel_token;
/// Cached kernel SATP after `init` so secondary harts don't borrow `KERNEL_SPACE`.
#[allow(dead_code)]
static KERNEL_SATP: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "loongarch64")]
pub(crate) fn cached_kernel_token() -> usize {
    KERNEL_SATP.load(Ordering::Acquire)
}
#[allow(dead_code)]
pub fn activate_kernel_space() {
    let cached = KERNEL_SATP.load(Ordering::Acquire);
    if cached != 0 {
        #[cfg(target_arch = "riscv64")]
        if riscv::register::satp::read().bits() == cached {
            // RISC-V SATP switches require sfence.vma in activate_token(); skip
            // that cost when the caller is already running on the kernel root.
            return;
        }
        memory_set::activate_token(cached);
    } else {
        let token = memory_set::kernel_token();
        KERNEL_SATP.store(token, Ordering::Release);
        #[cfg(target_arch = "riscv64")]
        if riscv::register::satp::read().bits() == token {
            // First caller may already be on KERNEL_SPACE during boot/init.
            return;
        }
        memory_set::activate_token(token);
    }
}

#[cfg(target_arch = "riscv64")]
/// Temporarily switch to the full kernel page table for code that needs the
/// physical direct map beyond the roots shared into user page tables.
pub struct KernelPageTableGuard {
    previous_satp: usize,
    switched: bool,
}

#[cfg(target_arch = "riscv64")]
impl KernelPageTableGuard {
    pub fn enter() -> Self {
        let previous_satp = riscv::register::satp::read().bits();
        let kernel_satp = {
            let cached = KERNEL_SATP.load(Ordering::Acquire);
            if cached != 0 {
                cached
            } else {
                let token = memory_set::kernel_token();
                KERNEL_SATP.store(token, Ordering::Release);
                token
            }
        };
        let switched = previous_satp != kernel_satp;
        if switched {
            memory_set::activate_token(kernel_satp);
        }
        Self {
            previous_satp,
            switched,
        }
    }
}

#[cfg(target_arch = "riscv64")]
impl Drop for KernelPageTableGuard {
    fn drop(&mut self) {
        if self.switched {
            // The ASID layer keeps this mm in its resident-hart mask while a
            // syscall temporarily uses the kernel SATP, so synchronous page
            // table invalidations still cover the saved context.
            memory_set::activate_token(self.previous_satp);
        }
    }
}

#[cfg(target_arch = "riscv64")]
pub fn flush_kernel_shared_tlb() {
    // SAFETY: sfence.vma is valid in S-mode. Kernel stack page-table entries
    // are shared into user page tables, so stale translations must be dropped
    // before a freed stack frame can be reused.
    unsafe {
        core::arch::asm!("sfence.vma");
    }
    let remote_hart_mask =
        crate::task::manager::online_hart_mask() & !(1usize << crate::arch::hart_id());
    if remote_hart_mask != 0 {
        crate::sbi::remote_sfence_vma_all(remote_hart_mask);
    }
}

#[cfg(target_arch = "loongarch64")]
pub fn flush_kernel_shared_tlb() {
    // Kernel mappings are global and shared by every page-table root. Wait for
    // every online hart to invalidate before a removed kernel frame is reused.
    // Publish the PTE stores before sampling online CPUs. A newly-online CPU
    // publishes itself before its final local flush, so either this snapshot
    // includes it or that post-publication flush observes our update.
    crate::arch::loongarch64::memory_barrier();
    let online = crate::task::manager::online_hart_mask();
    if online != 0 {
        crate::arch::loongarch64::shootdown_kernel_tlb(online);
    } else {
        crate::arch::loongarch64::mm::local_flush_tlb_all();
    }
}
pub(crate) use elf_loader::{
    ElfArchAbi, elf_arch_abi_from_bytes, elf_load_info_from_reader, validate_elf_interp_abi,
};
#[allow(unused_imports)]
pub use memory_set::remap_test;
pub use memory_set::{
    BrkUpdate, ElfAux, KERNEL_SPACE, LazyFaultResult, MapPermission, MapType, MemorySet, MmRef,
    MprotectError, ShmAttach, ShmAttachRef, VmRegion, VmRegionKind, VmaInsertArea,
};
pub(crate) use memory_set::{
    allocate_shared_anon_id, mirror_file_mmap_write, reclaim_file_page_cache, register_file_mmap,
    resize_file_page_cache, update_file_mmap_sizes, update_file_page_cache,
};
pub use page_table::{PTEFlags, PageTable, PageWalkCache};
pub use page_table::{
    PageTableEntry, read_user_value, translated_byte_buffer, translated_mutref,
    translated_single_address, try_prepare_user_buffer, write_user_value,
};
pub use page_table::{
    try_compare_exchange_user_u32, try_copy_from_user, try_copy_to_user,
    try_copy_to_user_unchecked, try_read_user_value, try_write_user_value,
};
enum UserBufferFrame {
    Managed(UserFramePin),
    /// The signal-return trampoline is the only permanent user mapping outside
    /// a MemorySet area.  It cannot be recycled, but still needs serialization
    /// if userspace supplies it as a readable syscall buffer.
    Permanent(PhysPageNum),
}

struct UserBufferSegment {
    frame: UserBufferFrame,
    page_offset: usize,
    len: usize,
}

static PERMANENT_USER_BUFFER_ACCESS: spin::Mutex<()> = spin::Mutex::new(());

impl UserBufferSegment {
    fn managed(pin: UserFramePin, page_offset: usize, len: usize) -> Self {
        Self {
            frame: UserBufferFrame::Managed(pin),
            page_offset,
            len,
        }
    }

    fn permanent(ppn: PhysPageNum, page_offset: usize, len: usize) -> Self {
        Self {
            frame: UserBufferFrame::Permanent(ppn),
            page_offset,
            len,
        }
    }

    fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        match &self.frame {
            UserBufferFrame::Managed(pin) => pin.with_bytes(self.page_offset, self.len, f),
            UserBufferFrame::Permanent(ppn) => {
                let _access = PERMANENT_USER_BUFFER_ACCESS.lock();
                let page: PhysAddr = (*ppn).into();
                // SAFETY: this mapping is backed by a permanent kernel-image
                // page, the segment is page-bounded, and the lock serializes
                // all UserBuffer views of the sole unowned user page.
                let bytes = unsafe {
                    core::slice::from_raw_parts((page.0 + self.page_offset) as *const u8, self.len)
                };
                f(bytes)
            }
        }
    }

    fn with_bytes_mut<R>(&self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        match &self.frame {
            UserBufferFrame::Managed(pin) => pin.with_bytes_mut(self.page_offset, self.len, f),
            UserBufferFrame::Permanent(ppn) => {
                let _access = PERMANENT_USER_BUFFER_ACCESS.lock();
                let page: PhysAddr = (*ppn).into();
                // SAFETY: as in `with_bytes`; callers can only reach this path
                // after normal writable-PTE validation.
                let bytes = unsafe {
                    core::slice::from_raw_parts_mut(
                        (page.0 + self.page_offset) as *mut u8,
                        self.len,
                    )
                };
                f(bytes)
            }
        }
    }
}

/// A scatter/gather user buffer whose physical frames remain pinned across
/// sleeping file operations.
///
/// No byte slice or pointer is stored or returned.  Every access creates a
/// page-bounded view under the physical frame's shared access lock and destroys
/// that view before releasing the lock.
pub struct UserBuffer {
    segments: Vec<UserBufferSegment>,
    readable: bool,
    writable: bool,
}

impl UserBuffer {
    pub fn empty() -> Self {
        Self {
            segments: Vec::new(),
            readable: false,
            writable: false,
        }
    }

    fn from_segments(segments: Vec<UserBufferSegment>, access: MapPermission) -> Self {
        Self {
            segments,
            readable: access.contains(MapPermission::R),
            writable: access.contains(MapPermission::W),
        }
    }

    pub fn len(&self) -> usize {
        self.segments.iter().map(|segment| segment.len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Visit readable page fragments one at a time.  Returning `false` stops
    /// the walk.  The slice is valid only for the closure invocation.
    pub fn for_each_chunk(&self, mut f: impl FnMut(&[u8]) -> bool) {
        if !self.readable {
            return;
        }
        for segment in &self.segments {
            if !segment.with_bytes(|bytes| f(bytes)) {
                break;
            }
        }
    }

    /// Visit writable page fragments one at a time.  Returning `false` stops
    /// the walk.  The mutable slice cannot escape this safe API.
    pub fn for_each_chunk_mut(&mut self, mut f: impl FnMut(&mut [u8]) -> bool) {
        if !self.writable {
            return;
        }
        for segment in &self.segments {
            if !segment.with_bytes_mut(|bytes| f(bytes)) {
                break;
            }
        }
    }

    /// Copy bytes from this user buffer into `dst`, starting at a logical
    /// scatter/gather offset.  Returns the number of bytes copied.
    pub fn copy_to_slice_at(&self, mut offset: usize, dst: &mut [u8]) -> usize {
        let mut copied = 0usize;
        self.for_each_chunk(|chunk| {
            if offset >= chunk.len() {
                offset -= chunk.len();
                return true;
            }
            let available = &chunk[offset..];
            let count = core::cmp::min(available.len(), dst.len() - copied);
            dst[copied..copied + count].copy_from_slice(&available[..count]);
            copied += count;
            offset = 0;
            copied < dst.len()
        });
        copied
    }

    pub fn copy_to_slice(&self, dst: &mut [u8]) -> usize {
        self.copy_to_slice_at(0, dst)
    }

    /// Copy bytes from `src` into this user buffer at a logical offset.
    pub fn copy_from_slice_at(&mut self, mut offset: usize, src: &[u8]) -> usize {
        let mut copied = 0usize;
        self.for_each_chunk_mut(|chunk| {
            if offset >= chunk.len() {
                offset -= chunk.len();
                return true;
            }
            let available = &mut chunk[offset..];
            let count = core::cmp::min(available.len(), src.len() - copied);
            available[..count].copy_from_slice(&src[copied..copied + count]);
            copied += count;
            offset = 0;
            copied < src.len()
        });
        copied
    }

    pub fn copy_from_slice(&mut self, src: &[u8]) -> usize {
        self.copy_from_slice_at(0, src)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len());
        self.for_each_chunk(|chunk| {
            bytes.extend_from_slice(chunk);
            true
        });
        bytes
    }
}

/// Resolve lazy/COW pages, then pin the resulting physical frames under this
/// process's mmap lock.  The returned object may safely survive a blocking
/// file operation even when another thread concurrently changes the VMA.
pub fn try_current_user_buffer(
    ptr: *const u8,
    len: usize,
    access: MapPermission,
) -> Result<UserBuffer, ()> {
    if len == 0 {
        return Ok(UserBuffer::empty());
    }
    let memory_set = crate::task::processor::current_process().memory_set();
    let token = memory_set.token();
    // A concurrent mprotect/COW transition can invalidate the first snapshot
    // between fault-in and mmap-lock acquisition. Retry once from the new PTE
    // state rather than exposing an unowned physical slice.
    for _ in 0..2 {
        try_prepare_user_buffer(token, ptr, len, access)?;
        if let Ok(buffer) = memory_set.try_pin_user_buffer(ptr, len, access) {
            return Ok(buffer);
        }
    }
    Err(())
}

/// initiate heap allocator, frame allocator and kernel space
#[allow(dead_code)]
pub fn init() {
    heap_allocator::init_heap();
    println!("[kernel] heap initialized.");
    frame_allocator::init_frame_allocator();
    println!("[kernel] frame allocator initialized.");
    KERNEL_SPACE.lock().activate();
    KERNEL_SATP.store(kernel_token(), Ordering::Release);
    println!("[kernel] kernel space activated.");
}
