//! Minimal supervisor PLIC support for VirtIO completion interrupts.
//!
//! This follows Linux's PLIC model: configure a per-hart S-mode context,
//! claim a source, run the device handler, then complete that source.

use core::ptr::{read_volatile, write_volatile};
use riscv::register::sie;
use spin::Mutex;

const PLIC_BASE: usize = crate::config::mmio_va(0x0c00_0000);
const PLIC_PRIORITY_BASE: usize = PLIC_BASE;
const PLIC_ENABLE_BASE: usize = PLIC_BASE + 0x2000;
const PLIC_ENABLE_CONTEXT_STRIDE: usize = 0x80;
const PLIC_CONTEXT_BASE: usize = PLIC_BASE + 0x20_0000;
const PLIC_CONTEXT_STRIDE: usize = 0x1000;
const PLIC_THRESHOLD_OFFSET: usize = 0;
const PLIC_CLAIM_OFFSET: usize = 4;
const DEFAULT_PRIORITY: u32 = 1;

static CONFIG_LOCK: Mutex<()> = Mutex::new(());

fn supervisor_context(hart_id: usize) -> usize {
    // QEMU virt exposes M-mode then S-mode for each hart.
    hart_id * 2 + 1
}

fn read32(address: usize) -> u32 {
    // SAFETY: addresses are within the PLIC MMIO mapping.
    unsafe { read_volatile(address as *const u32) }
}

fn write32(address: usize, value: u32) {
    // SAFETY: addresses are within the PLIC MMIO mapping.
    unsafe { write_volatile(address as *mut u32, value) }
}

fn context_base() -> usize {
    PLIC_CONTEXT_BASE + supervisor_context(crate::arch::hart_id()) * PLIC_CONTEXT_STRIDE
}

pub fn init_external_interrupts() {
    write32(context_base() + PLIC_THRESHOLD_OFFSET, 0);
    // SAFETY: enable the supervisor-external interrupt in the local SIE CSR.
    unsafe { sie::set_sext() };
}

pub fn enable_external_irq(source: usize) {
    assert!(source != 0);
    let _guard = CONFIG_LOCK.lock();
    write32(PLIC_PRIORITY_BASE + source * 4, DEFAULT_PRIORITY);
    let context = supervisor_context(crate::arch::hart_id());
    let enable_word = PLIC_ENABLE_BASE + context * PLIC_ENABLE_CONTEXT_STRIDE + (source / 32) * 4;
    write32(enable_word, read32(enable_word) | 1u32 << (source % 32));
}

fn claim() -> Option<usize> {
    let source = read32(context_base() + PLIC_CLAIM_OFFSET) as usize;
    (source != 0).then_some(source)
}

fn complete(source: usize) {
    write32(context_base() + PLIC_CLAIM_OFFSET, source as u32);
}

pub fn handle_external_interrupt() {
    // Linux's hardirq entry keeps the interrupted address space resident
    // (`irq_enter()` never touches `mm`); with the shared MMIO window and
    // direct map the PLIC claim/complete and VirtIO DMA drains all work on the
    // current SATP.  What *does* require the switch is this kernel's blocking
    // block-queue wakeup, which takes `spin::Mutex`es that are also held with
    // local interrupts disabled on the syscall path.  A ticket waiter holds an
    // acquired-but-unserved ticket across an interrupt only while the handler
    // keeps running on the user SATP, so a same-hart re-lock from the
    // completion path deadlocks the virtqueue.  Linux avoids the equivalent by
    // never sleeping or taking a contended scheduler lock in hardirq context.
    //
    // Keep the SATP switch (and its ASID-local `sfence.vma`) strictly around
    // the PLIC dispatch until the block completion path is made
    // hardirq-safe (defer wakeups to softirq/timer context).  All other guard
    // sites are gone: submission, polling and driver entry points now rely on
    // the shared mappings like Linux does.
    let _kernel_page_table = crate::mm::KernelPageTableGuard::enter();
    while let Some(source) = claim() {
        let _ = crate::drivers::block::handle_irq(source);
        complete(source);
    }
}
