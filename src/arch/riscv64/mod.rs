pub mod dtb;
mod irq;
pub mod mm;
pub mod task;
pub mod trap;

// 此重导出仅在内核二进制目标中调用；库目标会将其判定为未使用。
#[allow(unused_imports)]
pub use irq::{enable_external_irq, handle_external_interrupt, init_external_interrupts};

use alloc::sync::Arc;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use riscv::register::sstatus::{self, FS};
use spin::MutexGuard;

use crate::task::task_block::{TaskControlBlock, TaskControlBlockInner};

static RISCV_HAS_SSTC: AtomicBool = AtomicBool::new(false);
static RISCV_HAS_SVVPTC: AtomicBool = AtomicBool::new(false);
// Detect Sstc for future use, but keep SBI set_timer as the active clockevent
// path while this branch is focused on scheduler/mm latency changes.
const RISCV_USE_SSTC_CLOCKEVENT: bool = false;

#[allow(dead_code)]
pub fn bootstrap_init(dtb_pa: usize) {
    crate::sbi::init();
    dtb::init(dtb_pa);
    if let Some(freq) = dtb::timebase_frequency() {
        crate::config::set_clock_freq(freq);
        crate::println!("[kernel] riscv timebase frequency: {} Hz", freq);
    }
    let has_sstc = dtb::all_harts_have_sstc();
    RISCV_HAS_SSTC.store(has_sstc, Ordering::Release);
    if has_sstc {
        crate::println!("[kernel] riscv sstc timer enabled");
    }
    let has_svvptc = dtb::all_harts_have_svvptc();
    RISCV_HAS_SVVPTC.store(has_svvptc, Ordering::Release);
    if has_svvptc {
        crate::println!("[kernel] riscv svvptc enabled");
    }
}

#[inline]
pub(crate) fn has_svvptc() -> bool {
    RISCV_HAS_SVVPTC.load(Ordering::Acquire)
}

/// Discard firmware/boot-time translations and instruction-cache state before
/// a secondary hart becomes visible to the scheduler.
pub fn init_secondary_mmu_state() {
    // SAFETY: both fences are privileged architectural synchronization
    // operations valid in S-mode during per-hart initialization.
    unsafe {
        asm!("sfence.vma", "fence.i", options(nostack));
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

#[inline]
fn program_timer_deadline(timer: usize) {
    if RISCV_USE_SSTC_CLOCKEVENT && RISCV_HAS_SSTC.load(Ordering::Acquire) {
        // SAFETY: Sstc exposes stimecmp (CSR 0x14d) to S-mode. The flag is set
        // only after the DTB advertises the extension; otherwise we keep using SBI.
        unsafe { asm!("csrw 0x14d, {}", in(reg) timer, options(nostack)) };
    } else {
        crate::sbi::set_timer(timer);
    }
}

pub fn set_timer(timer: usize) {
    program_timer_deadline(timer);
}

#[allow(dead_code)]
pub fn stop_timer() {
    program_timer_deadline(usize::MAX);
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
fn disable_fp() {
    const SSTATUS_FS_MASK: usize = 0x6000;
    // SAFETY: clearing sstatus.FS disables S-mode floating point access until
    // the next explicit save/restore. User FS is restored from TrapContext by
    // the trampoline, so this only gates accidental kernel FP use.
    unsafe {
        let mut sstatus_bits: usize;
        asm!("csrr {}, sstatus", out(reg) sstatus_bits, options(nostack));
        if (sstatus_bits & SSTATUS_FS_MASK) != 0 {
            sstatus_bits &= !SSTATUS_FS_MASK;
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
    let fs = inner.get_trap_cx().sstatus.fs();
    if fs == FS::Dirty {
        // RISC-V FS=Dirty is the architectural "hardware fstate changed"
        // signal. Clean/Initial states can be left in the saved TrapContext.
        save_fp_registers(&mut inner);
        inner.get_trap_cx().sstatus.set_fs(FS::Clean);
    }
    drop(inner);
    disable_fp();
}

pub fn restore_user_fp_state(task: &Arc<TaskControlBlock>) {
    let inner = task.borrow_mut();
    if inner.get_trap_cx().sstatus.fs() != FS::Off {
        restore_fp_registers(&inner);
        inner.get_trap_cx().sstatus.set_fs(FS::Clean);
    }
    drop(inner);
    disable_fp();
}

pub fn discard_user_fp_state() {
    disable_fp();
}

pub fn handle_user_fp_disabled() -> bool {
    let Some(task) = crate::task::processor::current_task() else {
        return false;
    };
    let mut inner = task.borrow_mut();
    if inner.get_trap_cx().sstatus.fs() != FS::Off {
        return false;
    }
    if !inner.fp_valid {
        // First FP use after exec starts from a clean zeroed fstate.
        inner.fp_regs = [0; 32];
        inner.fp_fcsr = 0;
        inner.fp_fcc = 0;
        inner.fp_valid = true;
    }
    restore_fp_registers(&inner);
    inner.fp_used = true;
    inner.get_trap_cx().sstatus.set_fs(FS::Clean);
    drop(inner);
    disable_fp();
    true
}
