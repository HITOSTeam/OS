pub mod csr_defs;
pub mod mm;
pub mod task;
pub mod trap;

use crate::task::task_block::{TaskControlBlock, TaskControlBlockInner};
use alloc::sync::Arc;
use core::arch::{asm, global_asm};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::MutexGuard;

use csr_defs::{
    CRMD_DA, CRMD_IE, CRMD_PG, ECFG_LIE_IPI, ECFG_LIE_TI, ECFG_VS_MASK, ECFG_VS_SHIFT,
    IOCSR_IPI_CLEAR, IOCSR_IPI_EN, IOCSR_IPI_SEND, IOCSR_IPI_SEND_BLOCKING,
    IOCSR_IPI_SEND_CPU_SHIFT, IOCSR_IPI_STATUS, IPI_ACTION_RESCHEDULE, TCFG_EN, TCFG_INITVAL_MASK,
};

global_asm!(include_str!("tlb_refill.S"));

pub const REG_RA: usize = 1;
pub const REG_SP: usize = 3;
pub const REG_GP: usize = 0;
pub const REG_TP: usize = 2;
pub const REG_T0: usize = 12;
pub const REG_T1: usize = 13;
pub const REG_T2: usize = 14;
pub const REG_S0: usize = 21;
pub const REG_S1: usize = 22;
pub const REG_A0: usize = 4;
pub const REG_A1: usize = 5;
pub const REG_A2: usize = 6;
pub const REG_A3: usize = 7;
pub const REG_A4: usize = 8;
pub const REG_A5: usize = 9;
pub const REG_A6: usize = 10;
pub const REG_A7: usize = 11;

const EUEN_FPEN: usize = 1 << 0;

#[cfg(feature = "loongarch_board")]
const UART_BASE: usize = 0x8000_0000_1fe2_0000;
#[cfg(not(feature = "loongarch_board"))]
const UART_BASE: usize = 0x1fe0_01e0;

const UART_RBR_THR: usize = UART_BASE + 0x0;
const UART_FCR: usize = UART_BASE + 0x2;
const UART_LCR: usize = UART_BASE + 0x3;
const UART_LSR: usize = UART_BASE + 0x5;
pub const UART_FIFO_DEPTH: usize = 16;

static UART_INITED: AtomicBool = AtomicBool::new(false);

fn uart_init_once() {
    if UART_INITED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // SAFETY: UART_LCR and UART_FCR are MMIO addresses for 16550-compatible UART.
        unsafe {
            // 8N1 + enable FIFO, clear RX/TX queues.
            write_volatile(UART_LCR as *mut u8, 0x03);
            write_volatile(UART_FCR as *mut u8, 0x07);
        }
    }
}

pub fn console_putchar(c: usize) {
    uart_init_once();
    // SAFETY: UART_RBR_THR is the MMIO address for UART transmit hold register.
    unsafe {
        write_volatile(UART_RBR_THR as *mut u8, c as u8);
    }
}

pub fn console_flush() {
    uart_init_once();
    // SAFETY: UART_LSR is the MMIO address for UART line status register.
    unsafe { while read_volatile(UART_LSR as *const u8) & 0x20 == 0 {} }
}

pub fn console_getchar() -> usize {
    uart_init_once();
    // SAFETY: UART_LSR and UART_RBR_THR are MMIO addresses for UART status and data registers.
    unsafe {
        if read_volatile(UART_LSR as *const u8) & 0x01 == 0 {
            return usize::MAX;
        }
        read_volatile(UART_RBR_THR as *const u8) as usize
    }
}

pub fn disable_interrupts() -> bool {
    let mut crmd: usize;
    // SAFETY: CRMD (CSR 0x0) read/write is valid in kernel mode on LoongArch.
    unsafe { asm!("csrrd {}, 0x0", out(reg) crmd) };
    let prev = (crmd & CRMD_IE) != 0;
    crmd &= !CRMD_IE;
    // SAFETY: CRMD write disables interrupts.
    unsafe { asm!("csrwr {}, 0x0", inout(reg) crmd => _) };
    prev
}

pub fn restore_interrupts(prev: bool) {
    if prev {
        enable_interrupts();
    }
}

pub fn enable_interrupts() {
    let mut crmd: usize;
    // SAFETY: CRMD (CSR 0x0) read/write is valid in kernel mode on LoongArch.
    unsafe { asm!("csrrd {}, 0x0", out(reg) crmd) };
    crmd |= CRMD_IE;
    // SAFETY: This writes the updated interrupt-enable bit back to CRMD in kernel mode. Writing
    // an invalid value would leave interrupts misconfigured for the current hart.
    unsafe { asm!("csrwr {}, 0x0", inout(reg) crmd => _) };
}

pub fn wait_for_interrupt() {
    core::hint::spin_loop();
}

pub fn disable_direct_map_windows() {
    // SAFETY: DMW0/DMW1 (CSR 0x180/0x181) write and invtlb are valid in kernel mode.
    unsafe {
        asm!("csrwr {}, 0x180", inout(reg) 0usize => _);
        asm!("csrwr {}, 0x181", inout(reg) 0usize => _);
        asm!("invtlb 0x0, $r0, $r0");
    }
}

pub fn hart_id() -> usize {
    let mut id: usize;
    // SAFETY: CPUID (CSR 0x20) read is valid in kernel mode on LoongArch.
    unsafe { asm!("csrrd {}, 0x20", out(reg) id) };
    id
}

pub fn set_tp(hart_id: usize) {
    // SAFETY: $r2 (tp) register write is valid; used to store hart ID.
    unsafe {
        asm!("add.d $r2, {}, $r0", in(reg) hart_id);
    }
}

#[inline(always)]
fn iocsr_write32(reg: usize, value: u32) {
    // SAFETY: IOCSR writes are privileged LoongArch operations. Callers pass
    // kernel-selected register offsets and values matching Linux's CSR-IPI ABI.
    unsafe {
        asm!("iocsrwr.w {}, {}", in(reg) value, in(reg) reg, options(nostack));
    }
}

#[inline(always)]
fn iocsr_read32(reg: usize) -> u32 {
    let value: u32;
    // SAFETY: IOCSR reads are privileged LoongArch operations. The register
    // offset is controlled by the kernel.
    unsafe {
        asm!("iocsrrd.w {}, {}", out(reg) value, in(reg) reg, options(nostack));
    }
    value
}

pub fn send_ipi(hart_id: usize) {
    // We only need Linux's reschedule action for now: it breaks a remote hart
    // out of user/kernel execution so pending scheduler work is observed.
    let value = (IOCSR_IPI_SEND_BLOCKING
        | IPI_ACTION_RESCHEDULE
        | (hart_id << IOCSR_IPI_SEND_CPU_SHIFT)) as u32;
    iocsr_write32(IOCSR_IPI_SEND, value);
}

pub fn enable_ipi_interrupt() {
    let mut ecfg: usize;
    // SAFETY: ECFG read/write is valid in kernel mode.
    unsafe { asm!("csrrd {}, 0x4", out(reg) ecfg) };
    ecfg &= !(ECFG_VS_MASK << ECFG_VS_SHIFT);
    ecfg |= ECFG_LIE_IPI;
    // SAFETY: This only changes the local IPI interrupt-enable bit.
    unsafe { asm!("csrwr {}, 0x4", inout(reg) ecfg => _) };
    iocsr_write32(IOCSR_IPI_EN, u32::MAX);
}

pub fn clear_ipi_interrupt() -> u32 {
    let action = iocsr_read32(IOCSR_IPI_STATUS);
    if action != 0 {
        iocsr_write32(IOCSR_IPI_CLEAR, action);
    }
    action
}

pub fn hart_start(_hart_id: usize, _start_addr: usize, _opaque: usize) -> usize {
    1
}

pub fn shutdown() -> ! {
    // SAFETY: 0x100e_001c is the power control MMIO address on LoongArch QEMU virt.
    unsafe {
        (0x100e_001c as *mut u8).write_volatile(0x34);
    }
    loop {}
}

pub fn enable_timer_interrupt() {
    let mut ecfg: usize;
    // SAFETY: ECFG (CSR 0x4) read/write is valid in kernel mode on LoongArch.
    unsafe { asm!("csrrd {}, 0x4", out(reg) ecfg) };
    // Ensure vector spacing (VS) is zero so timer interrupts use the base entry.
    ecfg &= !(ECFG_VS_MASK << ECFG_VS_SHIFT);
    ecfg |= ECFG_LIE_TI;
    // SAFETY: This writes back a kernel-constructed ECFG value that only changes timer interrupt
    // delivery bits. A malformed write would route interrupts incorrectly on this hart.
    unsafe { asm!("csrwr {}, 0x4", inout(reg) ecfg => _) };
    enable_ipi_interrupt();
}

pub fn clear_timer_interrupt() {
    // SAFETY: TIClr (CSR 0x44) write is valid in kernel mode; clears timer interrupt.
    unsafe {
        asm!("csrwr {}, 0x44", inout(reg) 1usize => _);
    }
}
/// riscv 是设置绝对触发时间,设置某个tick处发生中断
/// loongarch是设置倒数 delta 个tick之后产生时钟中断
pub fn set_timer(timer: usize) {
    // For LoongArch, TCFG holds a relative countdown value in bits [2..].,
    //至少4个tick之后执行一次时钟中断
    let delta = timer.max(4);
    let tcfg = (delta & TCFG_INITVAL_MASK) | TCFG_EN;
    // SAFETY: TCFG (CSR 0x41) write is valid in kernel mode; configures timer countdown.
    unsafe {
        asm!("csrwr {}, 0x41", inout(reg) tcfg => _);
    }
}

pub fn read_time() -> usize {
    let mut counter: usize;
    // SAFETY: rdtime.d is a valid instruction to read the stable counter.
    unsafe {
        asm!("rdtime.d {},{}", out(reg) counter, out(reg) _);
    }
    counter
}

/// Enable LoongArch floating-point unit (EUEN.FPE = 1, CSR 0x2 bit 0).
#[inline]
fn ensure_fp_enabled() {
    // SAFETY: EUEN (CSR 0x2) read/write is valid in kernel mode; FPE bit controls FPU access.
    unsafe {
        let mut euen: usize;
        asm!("csrrd {}, 0x2", out(reg) euen, options(nostack));
        if (euen & EUEN_FPEN) == 0 {
            euen |= EUEN_FPEN;
            asm!("csrwr {}, 0x2", inout(reg) euen => _, options(nostack));
        }
    }
}

#[inline]
fn disable_fp() {
    // SAFETY: Clearing EUEN.FPEN is the LoongArch lazy-FPU gate. User FP instructions will trap
    // with FPDIS until the task first owns FPU state.
    unsafe {
        let mut euen: usize;
        asm!("csrrd {}, 0x2", out(reg) euen, options(nostack));
        if (euen & EUEN_FPEN) != 0 {
            euen &= !EUEN_FPEN;
            asm!("csrwr {}, 0x2", inout(reg) euen => _, options(nostack));
        }
    }
}

#[inline]
fn save_fp_registers(inner: &mut MutexGuard<'_, TaskControlBlockInner>) {
    ensure_fp_enabled();
    let ptr = inner.fp_regs.as_mut_ptr();
    // SAFETY: ptr points to a valid fp_regs array in the task control block;
    // FPU is enabled via ensure_fp_enabled(); all 32 FP registers are saved.
    unsafe {
        asm!(
            "fst.d $f0, {base}, 0",
            "fst.d $f1, {base}, 8",
            "fst.d $f2, {base}, 16",
            "fst.d $f3, {base}, 24",
            "fst.d $f4, {base}, 32",
            "fst.d $f5, {base}, 40",
            "fst.d $f6, {base}, 48",
            "fst.d $f7, {base}, 56",
            "fst.d $f8, {base}, 64",
            "fst.d $f9, {base}, 72",
            "fst.d $f10, {base}, 80",
            "fst.d $f11, {base}, 88",
            "fst.d $f12, {base}, 96",
            "fst.d $f13, {base}, 104",
            "fst.d $f14, {base}, 112",
            "fst.d $f15, {base}, 120",
            "fst.d $f16, {base}, 128",
            "fst.d $f17, {base}, 136",
            "fst.d $f18, {base}, 144",
            "fst.d $f19, {base}, 152",
            "fst.d $f20, {base}, 160",
            "fst.d $f21, {base}, 168",
            "fst.d $f22, {base}, 176",
            "fst.d $f23, {base}, 184",
            "fst.d $f24, {base}, 192",
            "fst.d $f25, {base}, 200",
            "fst.d $f26, {base}, 208",
            "fst.d $f27, {base}, 216",
            "fst.d $f28, {base}, 224",
            "fst.d $f29, {base}, 232",
            "fst.d $f30, {base}, 240",
            "fst.d $f31, {base}, 248",
            base = in(reg) ptr,
            options(nostack)
        );
        // Save FCSR (floating-point control/status register).
        let fcsr: u32;
        asm!("movfcsr2gr {}, $fcsr0", out(reg) fcsr, options(nostack));
        inner.fp_fcsr = fcsr;
        // Save FCC0-FCC7 (condition code registers, 1 bit each).
        let fcc0: u32;
        let fcc1: u32;
        let fcc2: u32;
        let fcc3: u32;
        let fcc4: u32;
        let fcc5: u32;
        let fcc6: u32;
        let fcc7: u32;
        asm!(
            "movcf2gr {fcc0}, $fcc0",
            "movcf2gr {fcc1}, $fcc1",
            "movcf2gr {fcc2}, $fcc2",
            "movcf2gr {fcc3}, $fcc3",
            "movcf2gr {fcc4}, $fcc4",
            "movcf2gr {fcc5}, $fcc5",
            "movcf2gr {fcc6}, $fcc6",
            "movcf2gr {fcc7}, $fcc7",
            fcc0 = out(reg) fcc0,
            fcc1 = out(reg) fcc1,
            fcc2 = out(reg) fcc2,
            fcc3 = out(reg) fcc3,
            fcc4 = out(reg) fcc4,
            fcc5 = out(reg) fcc5,
            fcc6 = out(reg) fcc6,
            fcc7 = out(reg) fcc7,
            options(nostack)
        );
        inner.fp_fcc = ((fcc0 & 1)
            | ((fcc1 & 1) << 1)
            | ((fcc2 & 1) << 2)
            | ((fcc3 & 1) << 3)
            | ((fcc4 & 1) << 4)
            | ((fcc5 & 1) << 5)
            | ((fcc6 & 1) << 6)
            | ((fcc7 & 1) << 7)) as u8;
        inner.fp_valid = true;
    }
}

#[inline]
fn restore_fp_registers(inner: &MutexGuard<'_, TaskControlBlockInner>) {
    if !inner.fp_valid {
        return;
    }
    ensure_fp_enabled();
    let ptr = inner.fp_regs.as_ptr();
    // SAFETY: ptr points to a valid fp_regs array in the task control block;
    // FPU is enabled via ensure_fp_enabled(); all 32 FP registers are restored.
    unsafe {
        asm!(
            "fld.d $f0, {base}, 0",
            "fld.d $f1, {base}, 8",
            "fld.d $f2, {base}, 16",
            "fld.d $f3, {base}, 24",
            "fld.d $f4, {base}, 32",
            "fld.d $f5, {base}, 40",
            "fld.d $f6, {base}, 48",
            "fld.d $f7, {base}, 56",
            "fld.d $f8, {base}, 64",
            "fld.d $f9, {base}, 72",
            "fld.d $f10, {base}, 80",
            "fld.d $f11, {base}, 88",
            "fld.d $f12, {base}, 96",
            "fld.d $f13, {base}, 104",
            "fld.d $f14, {base}, 112",
            "fld.d $f15, {base}, 120",
            "fld.d $f16, {base}, 128",
            "fld.d $f17, {base}, 136",
            "fld.d $f18, {base}, 144",
            "fld.d $f19, {base}, 152",
            "fld.d $f20, {base}, 160",
            "fld.d $f21, {base}, 168",
            "fld.d $f22, {base}, 176",
            "fld.d $f23, {base}, 184",
            "fld.d $f24, {base}, 192",
            "fld.d $f25, {base}, 200",
            "fld.d $f26, {base}, 208",
            "fld.d $f27, {base}, 216",
            "fld.d $f28, {base}, 224",
            "fld.d $f29, {base}, 232",
            "fld.d $f30, {base}, 240",
            "fld.d $f31, {base}, 248",
            base = in(reg) ptr,
            options(nostack)
        );
        // Restore FCSR.
        asm!("movgr2fcsr $fcsr0, {}", in(reg) inner.fp_fcsr, options(nostack));
        // Restore FCC0-FCC7.
        let fcc = inner.fp_fcc;
        let fcc0 = (fcc & 1) as u32;
        let fcc1 = ((fcc >> 1) & 1) as u32;
        let fcc2 = ((fcc >> 2) & 1) as u32;
        let fcc3 = ((fcc >> 3) & 1) as u32;
        let fcc4 = ((fcc >> 4) & 1) as u32;
        let fcc5 = ((fcc >> 5) & 1) as u32;
        let fcc6 = ((fcc >> 6) & 1) as u32;
        let fcc7 = ((fcc >> 7) & 1) as u32;
        asm!(
            "movgr2cf $fcc0, {fcc0}",
            "movgr2cf $fcc1, {fcc1}",
            "movgr2cf $fcc2, {fcc2}",
            "movgr2cf $fcc3, {fcc3}",
            "movgr2cf $fcc4, {fcc4}",
            "movgr2cf $fcc5, {fcc5}",
            "movgr2cf $fcc6, {fcc6}",
            "movgr2cf $fcc7, {fcc7}",
            fcc0 = in(reg) fcc0,
            fcc1 = in(reg) fcc1,
            fcc2 = in(reg) fcc2,
            fcc3 = in(reg) fcc3,
            fcc4 = in(reg) fcc4,
            fcc5 = in(reg) fcc5,
            fcc6 = in(reg) fcc6,
            fcc7 = in(reg) fcc7,
            options(nostack)
        );
    }
}

pub fn save_user_fp_state(task: &Arc<TaskControlBlock>) {
    let mut inner = task.borrow_mut();
    if !inner.fp_used {
        // Lazy-FPU tasks that never trapped on FP have no live hardware state.
        return;
    }
    save_fp_registers(&mut inner);
    inner.fp_used = false;
    drop(inner);
    disable_fp();
}

pub fn restore_user_fp_state(task: &Arc<TaskControlBlock>) {
    let inner = task.borrow_mut();
    if inner.fp_used {
        restore_fp_registers(&inner);
    } else {
        drop(inner);
        disable_fp();
    }
}

pub fn handle_user_fp_disabled() {
    let task = crate::task::processor::current_task().unwrap();
    let mut inner = task.borrow_mut();
    if !inner.fp_valid {
        // First FP use after exec starts from the architectural zeroed state.
        inner.fp_regs = [0; 32];
        inner.fp_fcsr = 0;
        inner.fp_fcc = 0;
        inner.fp_valid = true;
    }
    restore_fp_registers(&inner);
    inner.fp_used = true;
}

pub fn prepare_user_fp_state(task: &Arc<TaskControlBlock>) {
    if task.borrow_mut().fp_used {
        ensure_fp_enabled();
    } else {
        disable_fp();
    }
}

fn read_cpucfg(index: u32) -> u32 {
    let mut value = index;
    // SAFETY: cpucfg is a valid instruction to read CPU configuration on LoongArch.
    unsafe {
        asm!("cpucfg {}, {}", out(reg) value, in(reg) value);
    }
    value
}

fn detect_clock_freq() -> Option<usize> {
    let base = read_cpucfg(4) as u64;
    let cfg5 = read_cpucfg(5) as u64;
    let mul = (cfg5 & 0xffff) as u64;
    let div = (cfg5 >> 16) as u64;
    if base == 0 || mul == 0 || div == 0 {
        return None;
    }
    base.checked_mul(mul)
        .map(|freq| freq / div)
        .filter(|freq| *freq != 0)
        .map(|freq| freq as usize)
}

pub fn bootstrap_init() {
    unsafe extern "C" {
        fn __rfill();
    }
    // Configure paging and TLB refill to match the Sv39-style page tables we build.
    // SAFETY: Bootstrap runs in kernel mode before user execution, so these CSR/TLB updates
    // target machine-defined paging state for the current hart. Programming inconsistent values
    // here would break address translation or trap refill before the kernel can recover.
    unsafe {
        // Start with FP disabled. User FP instructions trap once and lazily acquire state.
        let mut euen: usize;
        asm!("csrrd {}, 0x2", out(reg) euen);
        euen &= !EUEN_FPEN;
        asm!("csrwr {}, 0x2", inout(reg) euen => _);

        // Clear pending timer interrupt and disable timer while bootstrapping.
        asm!("csrwr {}, 0x44", inout(reg) 1usize => _); // TIClr
        asm!("csrwr {}, 0x41", inout(reg) 0usize => _); // TCFG

        // Enable paging: CRMD.PG=1, CRMD.DA=0, CRMD.IE=0.
        let mut crmd: usize;
        asm!("csrrd {}, 0x0", out(reg) crmd);
        crmd &= !CRMD_IE;
        crmd &= !CRMD_DA;
        crmd |= CRMD_PG;
        asm!("csrwr {}, 0x0", inout(reg) crmd => _);

        // TLB refill entry (must be 4K aligned).
        asm!("csrwr {}, 0x88", inout(reg) __rfill as usize => _);

        // STLB page size and refill page size (4KB).
        let page_bits = crate::config::PAGE_SIZE_BITS;
        asm!("csrwr {}, 0x1e", inout(reg) page_bits => _);
        asm!("csrwr {}, 0x8e", inout(reg) page_bits => _);

        // Configure page walk controller for 3-level, 4KB pages, 8-byte PTEs.
        let dir_width = crate::config::PAGE_SIZE_BITS - 3;
        let ptbase = crate::config::PAGE_SIZE_BITS;
        let dir1_base = ptbase + dir_width;
        let dir2_base = ptbase + dir_width * 2;
        let mut pwcl: usize = 0;
        pwcl |= (ptbase & 0x1f) << 0;
        pwcl |= (dir_width & 0x1f) << 5;
        pwcl |= (dir1_base & 0x1f) << 10;
        pwcl |= (dir_width & 0x1f) << 15;
        pwcl |= (dir2_base & 0x1f) << 20;
        pwcl |= (dir_width & 0x1f) << 25;
        // PTE width: 8 bytes -> 0
        pwcl |= 0 << 30;
        asm!("csrwr {}, 0x1c", inout(reg) pwcl => _);
        asm!("csrwr {}, 0x1d", inout(reg) 0usize => _);

        asm!("invtlb 0x0, $r0, $r0");
    }

    if let Some(freq) = detect_clock_freq() {
        crate::config::set_clock_freq(freq);
    }
    enable_ipi_interrupt();
}
