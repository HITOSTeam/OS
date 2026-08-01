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
    FrameTracker, frame_alloc, frame_alloc_contiguous, frame_available_pages, frame_managed_pages,
    frame_refcount_entries,
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
            crate::arch::riscv64::mm::leave_user_mm();
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
    #[cfg(target_arch = "riscv64")]
    // The hart can no longer consume user translations. This is the
    // `switch_mm()` point where Linux clears the previous mm's CPU mask.
    crate::arch::riscv64::mm::leave_user_mm();
}

#[cfg(target_arch = "riscv64")]
/// Temporarily switch to the full kernel page table for code that needs the
/// physical direct map beyond the roots shared into user page tables.
pub struct KernelPageTableGuard {
    previous_satp: usize,
    switched: bool,
    previous_user_mm: Option<alloc::sync::Arc<crate::arch::riscv64::mm::AsidContext>>,
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
        let previous_user_mm = switched
            .then(crate::arch::riscv64::mm::pin_local_user_mm)
            .flatten();
        if switched {
            memory_set::activate_token(kernel_satp);
        }
        Self {
            previous_satp,
            switched,
            previous_user_mm,
        }
    }
}

#[cfg(target_arch = "riscv64")]
impl Drop for KernelPageTableGuard {
    fn drop(&mut self) {
        if self.switched {
            // The async block path may have scheduled while this guard was
            // alive. `activate_kernel_space()` then cleared the old active-mm
            // bit. Republish it before making the saved user SATP observable.
            if let Some(ctx) = self.previous_user_mm.as_ref() {
                crate::arch::riscv64::mm::restore_pinned_user_mm(ctx);
            }
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
    allocate_shared_anon_id, reclaim_shared_file_page_cache, resize_shared_file_page_cache,
    update_shared_file_page_cache,
};
pub use page_table::{PTEFlags, PageTable, PageWalkCache};
pub use page_table::{
    PageTableEntry, read_user_value, translated_byte_buffer, translated_mutref,
    translated_single_address, try_translated_byte_buffer, write_user_value,
};
pub use page_table::{
    try_compare_exchange_user_u32, try_copy_from_user, try_copy_to_user,
    try_copy_to_user_unchecked, try_read_user_value, try_write_user_value,
};
pub struct UserBuffer {
    pub buffers: Vec<&'static mut [u8]>,
}

impl UserBuffer {
    pub fn new(buffers: Vec<&'static mut [u8]>) -> Self {
        Self { buffers }
    }
    pub fn len(&self) -> usize {
        let mut total: usize = 0;
        for b in self.buffers.iter() {
            total += b.len();
        }
        total
    }
    pub fn into_iter(self) -> UserBufferIterator {
        UserBufferIterator {
            buffers: self.buffers,
            buffer_index: 0,
            offset_in_buffer: 0,
        }
    }
}
pub struct UserBufferIterator {
    buffers: Vec<&'static mut [u8]>,
    buffer_index: usize,
    offset_in_buffer: usize,
}
impl Iterator for UserBufferIterator {
    type Item = *mut u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer_index >= self.buffers.len() {
            return None;
        }

        if self.offset_in_buffer >= self.buffers[self.buffer_index].len() {
            self.buffer_index += 1;
            self.offset_in_buffer = 0;
            return self.next();
        }

        // SAFETY: buffer_index and offset_in_buffer are bounds-checked above;
        // the underlying slice is valid for the lifetime of the iterator.
        let ptr = unsafe {
            self.buffers[self.buffer_index]
                .as_mut_ptr()
                .add(self.offset_in_buffer)
        };

        self.offset_in_buffer += 1;
        Some(ptr)
    }
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
