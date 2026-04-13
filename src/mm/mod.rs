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
pub use dtb::init_phys_mem_from_dtb;
pub use frame_allocator::{
    FrameTracker, frame_alloc, frame_alloc_contiguous, frame_available_pages, frame_dealloc,
    frame_refcount_entries,
};
pub use memory_set::kernel_token;
/// Cached kernel SATP after `init` so secondary harts don't borrow `KERNEL_SPACE`.
static KERNEL_SATP: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "loongarch64")]
pub(crate) fn cached_kernel_token() -> usize {
    KERNEL_SATP.load(Ordering::Acquire)
}
pub fn activate_kernel_space() {
    let cached = KERNEL_SATP.load(Ordering::Acquire);
    if cached != 0 {
        memory_set::activate_token(cached);
    } else {
        let token = memory_set::kernel_token();
        KERNEL_SATP.store(token, Ordering::Release);
        memory_set::activate_token(token);
    }
}
pub(crate) use elf_loader::elf_interp_path_from_reader;
pub use memory_set::remap_test;
pub use memory_set::{ElfAux, KERNEL_SPACE, LazyFaultResult, MapPermission, MemorySet};
pub use page_table::{PTEFlags, PageTable, PageWalkCache};
pub use page_table::{
    PageTableEntry, copy_from_user, copy_to_user, read_user_value, translated_byte_buffer,
    translated_mutref, translated_single_address, translated_str, try_translated_byte_buffer,
    write_user_value,
};
pub use page_table::{
    try_copy_from_user, try_copy_to_user, try_copy_to_user_unchecked, try_read_user_value,
    try_write_user_value,
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
pub fn init() {
    heap_allocator::init_heap();
    println!("[kernel] heap initialized.");
    frame_allocator::init_frame_allocator();
    println!("[kernel] frame allocator initialized.");
    KERNEL_SPACE.lock().activate();
    KERNEL_SATP.store(kernel_token(), Ordering::Release);
    println!("[kernel] kernel space activated.");
}
