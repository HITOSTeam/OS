pub mod mm;
pub mod trap;

use alloc::sync::Arc;
use core::arch::asm;

use riscv::register::sstatus;
use spin::MutexGuard;

use crate::task::task_block::{TaskControlBlock, TaskControlBlockInner};

#[allow(dead_code)]
fn detect_timebase_frequency(dtb_pa: usize) -> Option<usize> {
    if dtb_pa == 0 {
        return None;
    }
    let fdt = unsafe { fdt::Fdt::from_ptr(dtb_pa as *const u8).ok()? };
    fdt.find_node("/cpus")
        .and_then(|node| node.property("timebase-frequency"))
        .and_then(|property| property.as_usize())
        .filter(|freq| *freq != 0)
}

#[allow(dead_code)]
pub fn bootstrap_init(dtb_pa: usize) {
    if let Some(freq) = detect_timebase_frequency(dtb_pa) {
        crate::config::set_clock_freq(freq);
        crate::println!("[kernel] riscv timebase frequency: {} Hz", freq);
    }
}

pub const REG_SP: usize = 2;
pub const REG_RA: usize = 1;
pub const REG_GP: usize = 3;
pub const REG_TP: usize = 4;
pub const REG_T0: usize = 5;
pub const REG_T1: usize = 6;
pub const REG_T2: usize = 7;
pub const REG_S0: usize = 8;
pub const REG_S1: usize = 9;
pub const REG_A0: usize = 10;
pub const REG_A1: usize = 11;
pub const REG_A2: usize = 12;
pub const REG_A3: usize = 13;
pub const REG_A4: usize = 14;
pub const REG_A5: usize = 15;
pub const REG_A6: usize = 16;
pub const REG_A7: usize = 17;

pub fn disable_interrupts() -> bool {
    let prev = sstatus::read().sie();
    // SAFETY: sstatus CSR write is valid in S-mode.
    unsafe { sstatus::clear_sie() };
    prev
}

pub fn restore_interrupts(prev: bool) {
    if prev {
        // SAFETY: sstatus CSR write is valid in S-mode.
        unsafe { sstatus::set_sie() };
    }
}

pub fn enable_interrupts() {
    // SAFETY: sstatus CSR write is valid in S-mode.
    unsafe { sstatus::set_sie() };
}

pub fn wait_for_interrupt() {
    // SAFETY: wfi is valid in S-mode; suspends until an interrupt.
    unsafe { asm!("wfi") };
}

pub fn hart_id() -> usize {
    let mut id: usize;
    // SAFETY: tp register holds the current hart ID in our convention.
    unsafe {
        asm!("mv {}, tp", out(reg) id);
    }
    id
}

pub fn set_tp(hart_id: usize) {
    // SAFETY: tp register write is valid; used to store hart ID.
    unsafe { asm!("mv tp, {}", in(reg) hart_id) };
}

pub fn console_putchar(c: usize) {
    crate::sbi::console_putchar(c);
}

#[allow(dead_code)]
pub fn console_flush() {
    // SBI console doesn't need an explicit flush.
}

pub fn console_getchar() -> usize {
    crate::sbi::console_getchar()
}

pub fn set_timer(timer: usize) {
    crate::sbi::set_timer(timer);
}

pub fn send_ipi(hart_id: usize) {
    crate::sbi::send_ipi(hart_id);
}

pub fn shutdown() -> ! {
    crate::sbi::shutdown();
}

#[allow(dead_code)]
pub fn hart_start(hart_id: usize, start_addr: usize, opaque: usize) -> usize {
    crate::sbi::hart_start(hart_id, start_addr, opaque)
}

pub fn read_time() -> usize {
    riscv::register::time::read()
}

#[inline]
fn ensure_fs_enabled() {
    // sstatus.FS = Dirty, so S-mode can execute floating-point save/restore ops.
    const SSTATUS_FS_DIRTY: usize = 0x6000;
    // SAFETY: sstatus CSR read/write is valid in S-mode; FS field controls FPU access.
    unsafe {
        let mut sstatus_bits: usize;
        asm!("csrr {}, sstatus", out(reg) sstatus_bits, options(nostack));
        if (sstatus_bits & SSTATUS_FS_DIRTY) != SSTATUS_FS_DIRTY {
            sstatus_bits |= SSTATUS_FS_DIRTY;
            asm!("csrw sstatus, {}", in(reg) sstatus_bits, options(nostack));
        }
    }
}

#[inline]
fn save_fp_registers(inner: &mut MutexGuard<'_, TaskControlBlockInner>) {
    ensure_fs_enabled();
    let ptr = inner.fp_regs.as_mut_ptr();
    // SAFETY: ptr points to a valid fp_regs array in the task control block;
    // FPU is enabled via ensure_fs_enabled(); all 32 FP registers are saved.
    unsafe {
        asm!(
            "fsd f0, 0({base})",
            "fsd f1, 8({base})",
            "fsd f2, 16({base})",
            "fsd f3, 24({base})",
            "fsd f4, 32({base})",
            "fsd f5, 40({base})",
            "fsd f6, 48({base})",
            "fsd f7, 56({base})",
            "fsd f8, 64({base})",
            "fsd f9, 72({base})",
            "fsd f10, 80({base})",
            "fsd f11, 88({base})",
            "fsd f12, 96({base})",
            "fsd f13, 104({base})",
            "fsd f14, 112({base})",
            "fsd f15, 120({base})",
            "fsd f16, 128({base})",
            "fsd f17, 136({base})",
            "fsd f18, 144({base})",
            "fsd f19, 152({base})",
            "fsd f20, 160({base})",
            "fsd f21, 168({base})",
            "fsd f22, 176({base})",
            "fsd f23, 184({base})",
            "fsd f24, 192({base})",
            "fsd f25, 200({base})",
            "fsd f26, 208({base})",
            "fsd f27, 216({base})",
            "fsd f28, 224({base})",
            "fsd f29, 232({base})",
            "fsd f30, 240({base})",
            "fsd f31, 248({base})",
            base = in(reg) ptr,
            options(nostack)
        );
        let fcsr: u32;
        asm!("frcsr {}", out(reg) fcsr, options(nostack));
        inner.fp_fcsr = fcsr;
        inner.fp_valid = true;
    }
}

#[inline]
fn restore_fp_registers(inner: &MutexGuard<'_, TaskControlBlockInner>) {
    if !inner.fp_valid {
        return;
    }
    ensure_fs_enabled();
    let ptr = inner.fp_regs.as_ptr();
    // SAFETY: ptr points to a valid fp_regs array in the task control block;
    // FPU is enabled via ensure_fs_enabled(); all 32 FP registers are restored.
    unsafe {
        asm!(
            "fld f0, 0({base})",
            "fld f1, 8({base})",
            "fld f2, 16({base})",
            "fld f3, 24({base})",
            "fld f4, 32({base})",
            "fld f5, 40({base})",
            "fld f6, 48({base})",
            "fld f7, 56({base})",
            "fld f8, 64({base})",
            "fld f9, 72({base})",
            "fld f10, 80({base})",
            "fld f11, 88({base})",
            "fld f12, 96({base})",
            "fld f13, 104({base})",
            "fld f14, 112({base})",
            "fld f15, 120({base})",
            "fld f16, 128({base})",
            "fld f17, 136({base})",
            "fld f18, 144({base})",
            "fld f19, 152({base})",
            "fld f20, 160({base})",
            "fld f21, 168({base})",
            "fld f22, 176({base})",
            "fld f23, 184({base})",
            "fld f24, 192({base})",
            "fld f25, 200({base})",
            "fld f26, 208({base})",
            "fld f27, 216({base})",
            "fld f28, 224({base})",
            "fld f29, 232({base})",
            "fld f30, 240({base})",
            "fld f31, 248({base})",
            base = in(reg) ptr,
            options(nostack)
        );
        asm!("fscsr {}", in(reg) inner.fp_fcsr, options(nostack));
    }
}

pub fn save_user_fp_state(task: &Arc<TaskControlBlock>) {
    let mut inner = task.borrow_mut();
    save_fp_registers(&mut inner);
}

pub fn restore_user_fp_state(task: &Arc<TaskControlBlock>) {
    let inner = task.borrow_mut();
    restore_fp_registers(&inner);
}
