pub mod csr_defs;
pub mod dtb;
mod irq;
pub mod mm;
pub mod task;
pub mod trap;

pub use irq::{enable_external_irq, handle_external_interrupt, init_external_interrupts};

use crate::task::task_block::{
    LoongArchFpState, LoongArchFpWidth, TaskControlBlock, TaskControlBlockInner,
};
use alloc::sync::Arc;
use core::arch::{asm, global_asm};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::MutexGuard;

use crate::config::MAX_HARTS;
use csr_defs::{
    CRMD_DA, CRMD_IE, CRMD_PG, ECFG_LIE_IPI, ECFG_LIE_TI, ECFG_VS_MASK, ECFG_VS_SHIFT, INVTLB_ALL,
    IOCSR_IPI_CLEAR, IOCSR_IPI_EN, IOCSR_IPI_SEND, IOCSR_IPI_SEND_BLOCKING,
    IOCSR_IPI_SEND_CPU_SHIFT, IOCSR_IPI_STATUS, IOCSR_MBUF_SEND, IOCSR_MBUF_SEND_BLOCKING,
    IOCSR_MBUF_SEND_BOX_SHIFT, IOCSR_MBUF_SEND_BUF_SHIFT, IOCSR_MBUF_SEND_CPU_SHIFT,
    IOCSR_MBUF_SEND_H32_MASK, IPI_ACTION_BOOT_CPU, IPI_ACTION_RESCHEDULE, IPI_ACTION_TLB_SHOOTDOWN,
    TCFG_EN, TCFG_INITVAL_MASK,
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
const EUEN_LSXEN: usize = 1 << 1;
const EUEN_LASXEN: usize = 1 << 2;
const CPUCFG2_FP: u32 = 1 << 0;
const CPUCFG2_LSX: u32 = 1 << 6;
const HWCAP_CPUCFG: usize = 1 << 0;
const HWCAP_FPU: usize = 1 << 3;
const HWCAP_LSX: usize = 1 << 4;
const ELF_HWCAP_FEATURE_MASK: usize = HWCAP_CPUCFG | HWCAP_FPU | HWCAP_LSX;
const ELF_HWCAP_FROZEN: usize = 1usize << (usize::BITS as usize - 1);

const FPU_CSR_INV_X: u32 = 0x1000_0000;
const FPU_CSR_DIV_X: u32 = 0x0800_0000;
const FPU_CSR_OVF_X: u32 = 0x0400_0000;
const FPU_CSR_UDF_X: u32 = 0x0200_0000;
const FPU_CSR_INE_X: u32 = 0x0100_0000;
const FPU_CSR_ALL_E: u32 = 0x0000_001f;

// Nonzero initialization keeps this in .data so boot-time BSS clearing does
// not erase it. Candidate harts intersect their CPUCFG-derived capabilities
// before the boot hart freezes the set exposed through AT_HWCAP.
static ELF_HWCAP_INTERSECTION: AtomicUsize = AtomicUsize::new(ELF_HWCAP_FEATURE_MASK);

#[cfg(feature = "loongarch_board")]
const UART_BASE: usize = 0x8000_0000_1fe2_0000;
#[cfg(not(feature = "loongarch_board"))]
const UART_BASE: usize = 0x1fe0_01e0;

const UART_RBR_THR: usize = 0;
const UART_FCR: usize = 2;
const UART_LCR: usize = 3;
const UART_LSR: usize = 5;
pub const UART_FIFO_DEPTH: usize = 16;

static UART_INITED: AtomicBool = AtomicBool::new(false);

/// Write a CSR while declaring `csrwr`'s architectural old-value output.
/// Treating its register operand as input-only lets LLVM reuse a value that
/// the instruction has overwritten.
#[inline(always)]
pub(crate) unsafe fn csr_write<const CSR: usize>(value: usize) {
    unsafe {
        asm!(
            "csrwr {value}, {csr}",
            value = inout(reg) value => _,
            csr = const CSR,
            options(nostack)
        );
    }
}

/// 根据 DTB 的寄存器间距和访问宽度计算 UART MMIO 地址。
fn uart_address(console: dtb::ConsoleInfo, register: usize) -> usize {
    let offset = register
        .checked_shl(console.reg_shift as u32)
        .expect("DTB UART register offset overflows");
    let end = offset
        .checked_add(console.reg_io_width as usize)
        .expect("DTB UART register width overflows");
    assert!(end <= console.size, "DTB UART register lies outside its reg range");
    console.base.checked_add(offset).expect("DTB UART address overflows")
}

/// 按 DTB 指定宽度写入 16550 UART 的一个寄存器。
fn uart_write(console: dtb::ConsoleInfo, register: usize, value: u8) {
    let address = uart_address(console, register);
    unsafe {
        match console.reg_io_width {
            1 => write_volatile(address as *mut u8, value),
            2 => write_volatile(address as *mut u16, value as u16),
            4 => write_volatile(address as *mut u32, value as u32),
            _ => unreachable!(),
        }
    }
}

/// 按 DTB 指定宽度读取 16550 UART 的一个寄存器。
fn uart_read(console: dtb::ConsoleInfo, register: usize) -> u8 {
    let address = uart_address(console, register);
    unsafe {
        match console.reg_io_width {
            1 => read_volatile(address as *const u8),
            2 => read_volatile(address as *const u16) as u8,
            4 => read_volatile(address as *const u32) as u8,
            _ => unreachable!(),
        }
    }
}

/// 仅由首次访问串口的 hart 初始化 16550 的 8N1 和 FIFO 设置。
fn uart_init_once(console: dtb::ConsoleInfo) {
    if UART_INITED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // 8N1 + enable FIFO, clear RX/TX queues.
        uart_write(console, UART_LCR, 0x03);
        uart_write(console, UART_FCR, 0x07);
    }
}

pub fn console_putchar(c: usize) {
    let console = dtb::console_info().unwrap_or(dtb::ConsoleInfo {
        base: UART_BASE, size: 0x1000, reg_shift: 0, reg_io_width: 1,
    });
    uart_init_once(console);
    uart_write(console, UART_RBR_THR, c as u8);
}

pub fn console_flush() {
    let console = dtb::console_info().unwrap_or(dtb::ConsoleInfo {
        base: UART_BASE, size: 0x1000, reg_shift: 0, reg_io_width: 1,
    });
    uart_init_once(console);
    while uart_read(console, UART_LSR) & 0x20 == 0 {}
}

pub fn console_getchar() -> usize {
    let console = dtb::console_info().unwrap_or(dtb::ConsoleInfo {
        base: UART_BASE, size: 0x1000, reg_shift: 0, reg_io_width: 1,
    });
    uart_init_once(console);
    if uart_read(console, UART_LSR) & 0x01 == 0 { usize::MAX } else { uart_read(console, UART_RBR_THR) as usize }
}

pub fn disable_interrupts() -> bool {
    let mut crmd: usize;
    // SAFETY: CRMD (CSR 0x0) read/write is valid in kernel mode on LoongArch.
    unsafe { asm!("csrrd {}, 0x0", out(reg) crmd) };
    let prev = (crmd & CRMD_IE) != 0;
    crmd &= !CRMD_IE;
    // SAFETY: CRMD write disables interrupts.
    unsafe { csr_write::<0x0>(crmd) };
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
    unsafe { csr_write::<0x0>(crmd) };
}

pub fn wait_for_interrupt() {
    // SAFETY: the scheduler enables local interrupts before entering idle.
    unsafe { asm!("idle 0", options(nostack)) };
}

pub fn disable_direct_map_windows() {
    // SAFETY: DMW0/DMW1 (CSR 0x180/0x181) write and invtlb are valid in kernel mode.
    unsafe {
        csr_write::<0x180>(0);
        csr_write::<0x181>(0);
        asm!("invtlb {op}, $r0, $r0", op = const INVTLB_ALL);
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

#[inline(always)]
fn iocsr_write64(reg: usize, value: u64) {
    // SAFETY: IOCSR writes are privileged LoongArch operations. This helper is
    // used for the architected 64-bit cross-core mailbox send register.
    unsafe {
        asm!("iocsrwr.d {}, {}", in(reg) value, in(reg) reg, options(nostack));
    }
}

pub(crate) const MAX_TLB_BATCH_RANGES: usize = 8;

const TLB_REQUEST_USER_RANGES: usize = 1;
const TLB_REQUEST_USER_ASID: usize = 2;
const TLB_REQUEST_USER_ALL: usize = 3;
const TLB_REQUEST_FULL: usize = 4;

/// One source hart owns one slot in every target hart's request table.
///
/// The source never reuses a slot until the target acknowledges its sequence,
/// so payload fields can be published with a release store to `request` and
/// consumed after an acquire load without a global shootdown lock.
struct TlbShootdownRequest {
    request: AtomicUsize,
    ack: AtomicUsize,
    kind: AtomicUsize,
    asid: AtomicUsize,
    range_count: AtomicUsize,
    range_starts: [AtomicUsize; MAX_TLB_BATCH_RANGES],
    range_ends: [AtomicUsize; MAX_TLB_BATCH_RANGES],
}

impl TlbShootdownRequest {
    const fn new() -> Self {
        Self {
            request: AtomicUsize::new(0),
            ack: AtomicUsize::new(0),
            kind: AtomicUsize::new(0),
            asid: AtomicUsize::new(0),
            range_count: AtomicUsize::new(0),
            range_starts: [const { AtomicUsize::new(0) }; MAX_TLB_BATCH_RANGES],
            range_ends: [const { AtomicUsize::new(0) }; MAX_TLB_BATCH_RANGES],
        }
    }
}

static TLB_SHOOTDOWN_SEQUENCE: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_HARTS];
static TLB_SHOOTDOWN_IN_FLIGHT: [AtomicBool; MAX_HARTS] =
    [const { AtomicBool::new(false) }; MAX_HARTS];
static TLB_SHOOTDOWN_REQUESTS: [[TlbShootdownRequest; MAX_HARTS]; MAX_HARTS] =
    [const { [const { TlbShootdownRequest::new() }; MAX_HARTS] }; MAX_HARTS];

#[inline(always)]
pub(crate) fn memory_barrier() {
    // SAFETY: DBAR 0 is the full ordering barrier required before publishing
    // page-table updates and before acknowledging a completed invalidation.
    unsafe {
        asm!("dbar 0", options(nostack));
    }
}

#[inline(always)]
fn send_ipi_action(hart_id: usize, action: usize) {
    if hart_id >= MAX_HARTS {
        return;
    }
    let value = (IOCSR_IPI_SEND_BLOCKING | action | (hart_id << IOCSR_IPI_SEND_CPU_SHIFT)) as u32;
    iocsr_write32(IOCSR_IPI_SEND, value);
}

pub fn send_ipi(hart_id: usize) {
    // Break a remote hart out of user/kernel execution so pending scheduler
    // work or a newly non-empty run queue is observed.
    send_ipi_action(hart_id, IPI_ACTION_RESCHEDULE);
}

pub fn enable_ipi_interrupt() {
    let mut ecfg: usize;
    // SAFETY: ECFG read/write is valid in kernel mode.
    unsafe { asm!("csrrd {}, 0x4", out(reg) ecfg) };
    ecfg &= !(ECFG_VS_MASK << ECFG_VS_SHIFT);
    ecfg |= ECFG_LIE_IPI;
    // SAFETY: This only changes the local IPI interrupt-enable bit.
    unsafe { csr_write::<0x4>(ecfg) };
    iocsr_write32(IOCSR_IPI_EN, u32::MAX);
}

pub fn clear_ipi_interrupt() -> u32 {
    let action = iocsr_read32(IOCSR_IPI_STATUS);
    if action != 0 {
        iocsr_write32(IOCSR_IPI_CLEAR, action);
        memory_barrier();
    }
    action
}

/// Drain TLB invalidation requests addressed to this hart.
///
/// Requests from different source harts have independent slots. The target
/// coalesces a full flush over user-only work and a user-wide flush over exact
/// ranges, then acknowledges the exact request sequence it consumed.
pub fn service_pending_tlb_shootdowns() {
    let hart_id = hart_id();
    if hart_id >= MAX_HARTS {
        return;
    }
    // This consumer snapshots requests and later publishes matching acks. It
    // must not be re-entered by an IPI between those two phases, otherwise an
    // inner invocation can acknowledge a newer sequence and the outer one can
    // incorrectly move the ack backwards to its stale snapshot.
    let interrupts_were_enabled = disable_interrupts();

    loop {
        let mut pending = [0usize; MAX_HARTS];
        let mut has_full = false;
        let mut has_user_all = false;
        let mut malformed = false;
        for source_hart in 0..MAX_HARTS {
            let slot = &TLB_SHOOTDOWN_REQUESTS[hart_id][source_hart];
            let request = slot.request.load(Ordering::Acquire);
            if request != slot.ack.load(Ordering::Acquire) {
                pending[source_hart] = request;
                match slot.kind.load(Ordering::Relaxed) {
                    TLB_REQUEST_FULL => has_full = true,
                    TLB_REQUEST_USER_ALL => has_user_all = true,
                    TLB_REQUEST_USER_RANGES | TLB_REQUEST_USER_ASID => {}
                    _ => malformed = true,
                }
            }
        }

        if pending.iter().all(|request| *request == 0) {
            break;
        }

        if has_full || malformed {
            mm::local_flush_tlb_all();
        } else if has_user_all {
            mm::local_flush_tlb_user();
        } else {
            for source_hart in 0..MAX_HARTS {
                if pending[source_hart] == 0 {
                    continue;
                }
                let slot = &TLB_SHOOTDOWN_REQUESTS[hart_id][source_hart];
                let asid = slot.asid.load(Ordering::Relaxed);
                match slot.kind.load(Ordering::Relaxed) {
                    TLB_REQUEST_USER_ASID => mm::local_flush_tlb_asid(asid),
                    TLB_REQUEST_USER_RANGES => {
                        let range_count = slot
                            .range_count
                            .load(Ordering::Relaxed)
                            .min(MAX_TLB_BATCH_RANGES);
                        for range_idx in 0..range_count {
                            let start = slot.range_starts[range_idx].load(Ordering::Relaxed);
                            let end = slot.range_ends[range_idx].load(Ordering::Relaxed);
                            mm::local_flush_tlb_range(asid, start, end);
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }

        memory_barrier();
        for source_hart in 0..MAX_HARTS {
            if pending[source_hart] != 0 {
                TLB_SHOOTDOWN_REQUESTS[hart_id][source_hart]
                    .ack
                    .store(pending[source_hart], Ordering::Release);
            }
        }

        // The outer loop drains requests published while this snapshot ran.
    }
    restore_interrupts(interrupts_were_enabled);
}

/// Clear the local IPI source and execute any call-function-style work.
pub fn handle_ipi_interrupt() -> u32 {
    // Clear first, then drain requests. If another sender publishes while this
    // action bit is already pending, either the request is observed by the
    // drain loop or the later send leaves a fresh pending bit.
    let action = clear_ipi_interrupt();
    service_pending_tlb_shootdowns();
    action
}

fn next_tlb_shootdown_sequence(source_hart: usize) -> usize {
    let previous = TLB_SHOOTDOWN_SEQUENCE[source_hart]
        .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            Some(if value == usize::MAX { 1 } else { value + 1 })
        })
        .unwrap();
    if previous == usize::MAX {
        1
    } else {
        previous + 1
    }
}

fn shootdown_tlb(
    hart_mask: usize,
    kind: usize,
    target_asids: &[usize; MAX_HARTS],
    ranges: &[(usize, usize)],
) {
    let configured_mask = if MAX_HARTS >= usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << MAX_HARTS) - 1
    };
    let targets = hart_mask & configured_mask;
    if targets == 0 {
        return;
    }

    // Pin the source request slot to this execution context. Incoming
    // shootdowns are polled while waiting, so disabling local interrupts does
    // not prevent progress and avoids a nested local invalidation reusing it.
    let interrupts_were_enabled = disable_interrupts();
    let source_hart = hart_id();
    assert!(
        source_hart < MAX_HARTS,
        "TLB shootdown source hart {} exceeds MAX_HARTS",
        source_hart
    );
    assert!(
        !TLB_SHOOTDOWN_IN_FLIGHT[source_hart].swap(true, Ordering::AcqRel),
        "nested TLB shootdown on hart {}",
        source_hart
    );

    // Page-table stores must be globally visible before a target invalidates
    // and acknowledges them.
    memory_barrier();
    let sequence = next_tlb_shootdown_sequence(source_hart);
    let local_bit = 1usize << source_hart;
    let remote_targets = targets & !local_bit;

    for target_hart in 0..MAX_HARTS {
        if remote_targets & (1usize << target_hart) == 0 {
            continue;
        }
        let slot = &TLB_SHOOTDOWN_REQUESTS[target_hart][source_hart];
        while slot.request.load(Ordering::Acquire) != slot.ack.load(Ordering::Acquire) {
            service_pending_tlb_shootdowns();
            core::hint::spin_loop();
        }
        slot.kind.store(kind, Ordering::Relaxed);
        slot.asid
            .store(target_asids[target_hart], Ordering::Relaxed);
        slot.range_count
            .store(ranges.len().min(MAX_TLB_BATCH_RANGES), Ordering::Relaxed);
        for (range_idx, &(start, end)) in ranges.iter().take(MAX_TLB_BATCH_RANGES).enumerate() {
            slot.range_starts[range_idx].store(start, Ordering::Relaxed);
            slot.range_ends[range_idx].store(end, Ordering::Relaxed);
        }
        slot.request.store(sequence, Ordering::Release);
    }
    memory_barrier();
    let wait_start = if remote_targets != 0 && crate::perf::enabled() {
        read_time()
    } else {
        0
    };
    for target_hart in 0..MAX_HARTS {
        if remote_targets & (1usize << target_hart) != 0 {
            send_ipi_action(target_hart, IPI_ACTION_TLB_SHOOTDOWN);
        }
    }

    if targets & local_bit != 0 {
        match kind {
            TLB_REQUEST_USER_RANGES => {
                for &(start, end) in ranges {
                    mm::local_flush_tlb_range(target_asids[source_hart], start, end);
                }
            }
            TLB_REQUEST_USER_ASID => mm::local_flush_tlb_asid(target_asids[source_hart]),
            TLB_REQUEST_USER_ALL => mm::local_flush_tlb_user(),
            TLB_REQUEST_FULL => mm::local_flush_tlb_all(),
            _ => mm::local_flush_tlb_all(),
        }
        memory_barrier();
    }

    // Keep servicing requests for this hart while waiting. This breaks the
    // cross-shootdown cycle where two CPUs invalidate each other at once.
    loop {
        service_pending_tlb_shootdowns();
        let complete = (0..MAX_HARTS).all(|target_hart| {
            if remote_targets & (1usize << target_hart) == 0 {
                return true;
            }
            TLB_SHOOTDOWN_REQUESTS[target_hart][source_hart]
                .ack
                .load(Ordering::Acquire)
                == sequence
        });
        if complete {
            break;
        }
        core::hint::spin_loop();
    }
    let wait_cycles = if remote_targets != 0 && crate::perf::enabled() {
        read_time().wrapping_sub(wait_start)
    } else {
        0
    };
    crate::perf::record_tlb_shootdown(remote_targets.count_ones() as usize, wait_cycles);
    TLB_SHOOTDOWN_IN_FLIGHT[source_hart].store(false, Ordering::Release);
    restore_interrupts(interrupts_were_enabled);
}

pub(crate) fn shootdown_user_tlb(hart_mask: usize) {
    shootdown_tlb(hart_mask, TLB_REQUEST_USER_ALL, &[0; MAX_HARTS], &[]);
}

pub(crate) fn shootdown_user_tlb_ranges(
    hart_mask: usize,
    target_asids: &[usize; MAX_HARTS],
    ranges: &[(usize, usize)],
) {
    shootdown_tlb(hart_mask, TLB_REQUEST_USER_RANGES, target_asids, ranges);
}

pub(crate) fn shootdown_user_tlb_asids(hart_mask: usize, target_asids: &[usize; MAX_HARTS]) {
    shootdown_tlb(hart_mask, TLB_REQUEST_USER_ASID, target_asids, &[]);
}

pub(crate) fn shootdown_kernel_tlb(hart_mask: usize) {
    shootdown_tlb(hart_mask, TLB_REQUEST_FULL, &[0; MAX_HARTS], &[]);
}

pub fn hart_start(hart_id: usize, start_addr: usize, _opaque: usize) -> usize {
    if hart_id >= MAX_HARTS {
        return 1;
    }

    // QEMU's direct-boot ROM parks auxiliary CPUs at VIRT_FLASH0_BASE. It
    // consumes mailbox 0 after receiving Linux's SMP_BOOT_CPU action. Match
    // Linux csr_mail_send(): write the high and low halves separately through
    // IOCSR_MBUF_SEND, then ring the target IPI.
    let mailbox = 0u64;
    let box_low = mailbox << 1;
    let box_high = box_low + 1;
    let cpu = (hart_id as u64) << IOCSR_MBUF_SEND_CPU_SHIFT;
    let data = start_addr as u64;

    let high = IOCSR_MBUF_SEND_BLOCKING
        | (box_high << IOCSR_MBUF_SEND_BOX_SHIFT)
        | cpu
        | (data & IOCSR_MBUF_SEND_H32_MASK);
    iocsr_write64(IOCSR_MBUF_SEND, high);

    let low = IOCSR_MBUF_SEND_BLOCKING
        | (box_low << IOCSR_MBUF_SEND_BOX_SHIFT)
        | cpu
        | (data << IOCSR_MBUF_SEND_BUF_SHIFT);
    iocsr_write64(IOCSR_MBUF_SEND, low);
    memory_barrier();
    send_ipi_action(hart_id, IPI_ACTION_BOOT_CPU);
    0
}

pub fn shutdown() -> ! {
    let poweroff = dtb::poweroff_info().unwrap_or(dtb::PoweroffInfo {
        base: 0x100e_0000, offset: 0x1c, value: 0x34, reg_io_width: 1,
    });
    let address = poweroff.base + poweroff.offset;
    // 访问宽度和值已由 DTB 校验；固定地址仅是无 DTB 时的旧平台回退。
    unsafe {
        match poweroff.reg_io_width {
            1 => write_volatile(address as *mut u8, poweroff.value as u8),
            2 => write_volatile(address as *mut u16, poweroff.value as u16),
            4 => write_volatile(address as *mut u32, poweroff.value as u32),
            8 => write_volatile(address as *mut u64, poweroff.value as u64),
            _ => unreachable!(),
        }
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
    unsafe { csr_write::<0x4>(ecfg) };
    enable_ipi_interrupt();
}

pub fn clear_timer_interrupt() {
    // SAFETY: TIClr (CSR 0x44) write is valid in kernel mode; clears timer interrupt.
    unsafe {
        csr_write::<0x44>(1);
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
        csr_write::<0x41>(tcfg);
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

#[inline]
fn set_extension_width(width: LoongArchFpWidth) {
    let wanted = match width {
        LoongArchFpWidth::None => 0,
        LoongArchFpWidth::Scalar => EUEN_FPEN,
        LoongArchFpWidth::Lsx => EUEN_FPEN | EUEN_LSXEN,
    };
    // SAFETY: EUEN is a per-hart privileged CSR. Keep LASX disabled until its
    // 256-bit context path exists, and enable FP whenever LSX is enabled.
    unsafe {
        let mut euen: usize;
        asm!("csrrd {}, 0x2", out(reg) euen, options(nostack));
        euen &= !(EUEN_FPEN | EUEN_LSXEN | EUEN_LASXEN);
        euen |= wanted;
        csr_write::<0x2>(euen);
    }
}

#[inline]
fn disable_fp_extensions() {
    set_extension_width(LoongArchFpWidth::None);
}

#[inline(never)]
unsafe fn save_scalar_registers(base: *mut [u64; 4]) {
    // Each register has a Linux-compatible 32-byte slot. Scalar FP occupies
    // lane zero and must leave the saved LSX/LASX upper lanes untouched.
    unsafe {
        asm!(
            "fst.d $f0, {base}, 0", "fst.d $f1, {base}, 32",
            "fst.d $f2, {base}, 64", "fst.d $f3, {base}, 96",
            "fst.d $f4, {base}, 128", "fst.d $f5, {base}, 160",
            "fst.d $f6, {base}, 192", "fst.d $f7, {base}, 224",
            "fst.d $f8, {base}, 256", "fst.d $f9, {base}, 288",
            "fst.d $f10, {base}, 320", "fst.d $f11, {base}, 352",
            "fst.d $f12, {base}, 384", "fst.d $f13, {base}, 416",
            "fst.d $f14, {base}, 448", "fst.d $f15, {base}, 480",
            "fst.d $f16, {base}, 512", "fst.d $f17, {base}, 544",
            "fst.d $f18, {base}, 576", "fst.d $f19, {base}, 608",
            "fst.d $f20, {base}, 640", "fst.d $f21, {base}, 672",
            "fst.d $f22, {base}, 704", "fst.d $f23, {base}, 736",
            "fst.d $f24, {base}, 768", "fst.d $f25, {base}, 800",
            "fst.d $f26, {base}, 832", "fst.d $f27, {base}, 864",
            "fst.d $f28, {base}, 896", "fst.d $f29, {base}, 928",
            "fst.d $f30, {base}, 960", "fst.d $f31, {base}, 992",
            base = in(reg) base,
            options(nostack)
        );
    }
}

#[inline(never)]
unsafe fn restore_scalar_registers(base: *const [u64; 4]) {
    unsafe {
        asm!(
            "fld.d $f0, {base}, 0", "fld.d $f1, {base}, 32",
            "fld.d $f2, {base}, 64", "fld.d $f3, {base}, 96",
            "fld.d $f4, {base}, 128", "fld.d $f5, {base}, 160",
            "fld.d $f6, {base}, 192", "fld.d $f7, {base}, 224",
            "fld.d $f8, {base}, 256", "fld.d $f9, {base}, 288",
            "fld.d $f10, {base}, 320", "fld.d $f11, {base}, 352",
            "fld.d $f12, {base}, 384", "fld.d $f13, {base}, 416",
            "fld.d $f14, {base}, 448", "fld.d $f15, {base}, 480",
            "fld.d $f16, {base}, 512", "fld.d $f17, {base}, 544",
            "fld.d $f18, {base}, 576", "fld.d $f19, {base}, 608",
            "fld.d $f20, {base}, 640", "fld.d $f21, {base}, 672",
            "fld.d $f22, {base}, 704", "fld.d $f23, {base}, 736",
            "fld.d $f24, {base}, 768", "fld.d $f25, {base}, 800",
            "fld.d $f26, {base}, 832", "fld.d $f27, {base}, 864",
            "fld.d $f28, {base}, 896", "fld.d $f29, {base}, 928",
            "fld.d $f30, {base}, 960", "fld.d $f31, {base}, 992",
            base = in(reg) base,
            options(nostack)
        );
    }
}

#[target_feature(enable = "lsx")]
#[inline(never)]
unsafe fn save_lsx_registers(base: *mut [u64; 4]) {
    unsafe {
        asm!(
            "vst $vr0, {base}, 0", "vst $vr1, {base}, 32",
            "vst $vr2, {base}, 64", "vst $vr3, {base}, 96",
            "vst $vr4, {base}, 128", "vst $vr5, {base}, 160",
            "vst $vr6, {base}, 192", "vst $vr7, {base}, 224",
            "vst $vr8, {base}, 256", "vst $vr9, {base}, 288",
            "vst $vr10, {base}, 320", "vst $vr11, {base}, 352",
            "vst $vr12, {base}, 384", "vst $vr13, {base}, 416",
            "vst $vr14, {base}, 448", "vst $vr15, {base}, 480",
            "vst $vr16, {base}, 512", "vst $vr17, {base}, 544",
            "vst $vr18, {base}, 576", "vst $vr19, {base}, 608",
            "vst $vr20, {base}, 640", "vst $vr21, {base}, 672",
            "vst $vr22, {base}, 704", "vst $vr23, {base}, 736",
            "vst $vr24, {base}, 768", "vst $vr25, {base}, 800",
            "vst $vr26, {base}, 832", "vst $vr27, {base}, 864",
            "vst $vr28, {base}, 896", "vst $vr29, {base}, 928",
            "vst $vr30, {base}, 960", "vst $vr31, {base}, 992",
            base = in(reg) base,
            options(nostack)
        );
    }
}

#[target_feature(enable = "lsx")]
#[inline(never)]
unsafe fn restore_lsx_registers(base: *const [u64; 4]) {
    unsafe {
        asm!(
            "vld $vr0, {base}, 0", "vld $vr1, {base}, 32",
            "vld $vr2, {base}, 64", "vld $vr3, {base}, 96",
            "vld $vr4, {base}, 128", "vld $vr5, {base}, 160",
            "vld $vr6, {base}, 192", "vld $vr7, {base}, 224",
            "vld $vr8, {base}, 256", "vld $vr9, {base}, 288",
            "vld $vr10, {base}, 320", "vld $vr11, {base}, 352",
            "vld $vr12, {base}, 384", "vld $vr13, {base}, 416",
            "vld $vr14, {base}, 448", "vld $vr15, {base}, 480",
            "vld $vr16, {base}, 512", "vld $vr17, {base}, 544",
            "vld $vr18, {base}, 576", "vld $vr19, {base}, 608",
            "vld $vr20, {base}, 640", "vld $vr21, {base}, 672",
            "vld $vr22, {base}, 704", "vld $vr23, {base}, 736",
            "vld $vr24, {base}, 768", "vld $vr25, {base}, 800",
            "vld $vr26, {base}, 832", "vld $vr27, {base}, 864",
            "vld $vr28, {base}, 896", "vld $vr29, {base}, 928",
            "vld $vr30, {base}, 960", "vld $vr31, {base}, 992",
            base = in(reg) base,
            options(nostack)
        );
    }
}

#[inline]
fn save_fp_control(state: &mut LoongArchFpState) {
    // SAFETY: callers have enabled FP and pinned the current task to this hart.
    unsafe {
        asm!("movfcsr2gr {}, $fcsr0", out(reg) state.fcsr, options(nostack));
        let mut fcc = [0u32; 8];
        asm!(
            "movcf2gr {fcc0}, $fcc0", "movcf2gr {fcc1}, $fcc1",
            "movcf2gr {fcc2}, $fcc2", "movcf2gr {fcc3}, $fcc3",
            "movcf2gr {fcc4}, $fcc4", "movcf2gr {fcc5}, $fcc5",
            "movcf2gr {fcc6}, $fcc6", "movcf2gr {fcc7}, $fcc7",
            fcc0 = out(reg) fcc[0], fcc1 = out(reg) fcc[1],
            fcc2 = out(reg) fcc[2], fcc3 = out(reg) fcc[3],
            fcc4 = out(reg) fcc[4], fcc5 = out(reg) fcc[5],
            fcc6 = out(reg) fcc[6], fcc7 = out(reg) fcc[7],
            options(nostack)
        );
        state.fcc = fcc.iter().enumerate().fold(0u64, |packed, (index, value)| {
            packed | (u64::from(*value & 1) << (index * 8))
        });
    }
}

#[inline]
fn restore_fp_control(state: &LoongArchFpState) {
    // SAFETY: callers have enabled FP and pass a kernel-owned snapshot.
    unsafe {
        asm!("movgr2fcsr $fcsr0, {}", in(reg) state.fcsr, options(nostack));
        let fcc0 = (state.fcc & 1) as u32;
        let fcc1 = ((state.fcc >> 8) & 1) as u32;
        let fcc2 = ((state.fcc >> 16) & 1) as u32;
        let fcc3 = ((state.fcc >> 24) & 1) as u32;
        let fcc4 = ((state.fcc >> 32) & 1) as u32;
        let fcc5 = ((state.fcc >> 40) & 1) as u32;
        let fcc6 = ((state.fcc >> 48) & 1) as u32;
        let fcc7 = ((state.fcc >> 56) & 1) as u32;
        asm!(
            "movgr2cf $fcc0, {fcc0}", "movgr2cf $fcc1, {fcc1}",
            "movgr2cf $fcc2, {fcc2}", "movgr2cf $fcc3, {fcc3}",
            "movgr2cf $fcc4, {fcc4}", "movgr2cf $fcc5, {fcc5}",
            "movgr2cf $fcc6, {fcc6}", "movgr2cf $fcc7, {fcc7}",
            fcc0 = in(reg) fcc0, fcc1 = in(reg) fcc1,
            fcc2 = in(reg) fcc2, fcc3 = in(reg) fcc3,
            fcc4 = in(reg) fcc4, fcc5 = in(reg) fcc5,
            fcc6 = in(reg) fcc6, fcc7 = in(reg) fcc7,
            options(nostack)
        );
    }
}

fn initialize_scalar_snapshot(state: &mut LoongArchFpState) {
    // Linux initializes unused FPRs to a signaling-NaN bit pattern rather
    // than inheriting stale values from the previous task.
    for reg in &mut state.regs {
        reg[0] = u64::MAX;
    }
    state.fcc = 0;
    state.fcsr = 0;
    state.width = LoongArchFpWidth::Scalar;
}

fn upgrade_snapshot_to_lsx(state: &mut LoongArchFpState) {
    for reg in &mut state.regs {
        reg[1] = u64::MAX;
    }
    state.width = LoongArchFpWidth::Lsx;
}

fn restore_snapshot(state: &LoongArchFpState) {
    set_extension_width(state.width);
    // SAFETY: state is aligned to 32 bytes and the selected extension is on.
    unsafe {
        match state.width {
            LoongArchFpWidth::None => return,
            LoongArchFpWidth::Scalar => restore_scalar_registers(state.regs.as_ptr()),
            LoongArchFpWidth::Lsx => restore_lsx_registers(state.regs.as_ptr()),
        }
    }
    restore_fp_control(state);
}

pub fn save_user_fp_state(task: &Arc<TaskControlBlock>) {
    let interrupts_were_enabled = disable_interrupts();
    let mut inner: MutexGuard<'_, TaskControlBlockInner> = task.borrow_mut();
    let state = &mut inner.loongarch_fp;
    if state.hardware_live {
        set_extension_width(state.width);
        // SAFETY: only the current task can be hardware-live, and scheduling
        // paths invoke this with local interrupts disabled.
        unsafe {
            match state.width {
                LoongArchFpWidth::None => {}
                LoongArchFpWidth::Scalar => save_scalar_registers(state.regs.as_mut_ptr()),
                LoongArchFpWidth::Lsx => save_lsx_registers(state.regs.as_mut_ptr()),
            }
        }
        if state.width != LoongArchFpWidth::None {
            save_fp_control(state);
        }
        state.hardware_live = false;
    }
    drop(inner);
    disable_fp_extensions();
    restore_interrupts(interrupts_were_enabled);
}

pub fn restore_user_fp_state(_task: &Arc<TaskControlBlock>) {
    // Linux leaves an incoming task gated and restores lazily on its first
    // FP/LSX instruction. The outgoing path already wrote any live state.
    let interrupts_were_enabled = disable_interrupts();
    disable_fp_extensions();
    restore_interrupts(interrupts_were_enabled);
}

pub fn handle_user_fp_disabled() -> bool {
    if read_cpucfg(2) & CPUCFG2_FP == 0 {
        return false;
    }
    let Some(task) = crate::task::processor::current_task() else {
        return false;
    };
    let mut inner = task.borrow_mut();
    let state = &mut inner.loongarch_fp;
    if state.width == LoongArchFpWidth::None {
        initialize_scalar_snapshot(state);
    }
    restore_snapshot(state);
    state.hardware_live = true;
    true
}

/// Gate all user FP/SIMD units without preserving the outgoing owner.
/// Scheduler exit paths use this after the task has become unrecoverable.
pub fn discard_user_fp_state() {
    disable_fp_extensions();
}

fn take_fcsr_exception(fcsr: &mut u32) -> Option<i32> {
    let pending = *fcsr & ((*fcsr & FPU_CSR_ALL_E) << 24);
    *fcsr &= !pending;
    let code = if pending & FPU_CSR_INV_X != 0 {
        7 // FPE_FLTINV
    } else if pending & FPU_CSR_DIV_X != 0 {
        3 // FPE_FLTDIV
    } else if pending & FPU_CSR_OVF_X != 0 {
        4 // FPE_FLTOVF
    } else if pending & FPU_CSR_UDF_X != 0 {
        5 // FPE_FLTUND
    } else if pending & FPU_CSR_INE_X != 0 {
        6 // FPE_FLTRES
    } else {
        return None;
    };
    Some(code)
}

/// Apply Linux's sigreturn rule: enabled cause bits are cleared and produce a
/// fresh SIGFPE after the supplied user context has been installed.
pub fn sanitize_user_fcsr(fcsr: &mut u32) -> Option<i32> {
    take_fcsr_exception(fcsr)
}

/// Clear the enabled hardware FCSR cause bits and return Linux's SIGFPE code.
pub fn handle_user_fp_exception() -> i32 {
    let mut fcsr: u32;
    // SAFETY: an FP/vector exception can only be reported with the shared FCSR
    // register file enabled for the faulting user task.
    unsafe {
        asm!("movfcsr2gr {}, $fcsr0", out(reg) fcsr, options(nostack));
    }
    let code = take_fcsr_exception(&mut fcsr).unwrap_or(7);
    unsafe {
        asm!("movgr2fcsr $fcsr0, {}", in(reg) fcsr, options(nostack));
    }
    code
}

pub fn handle_user_lsx_disabled() -> bool {
    if read_cpucfg(2) & CPUCFG2_LSX == 0 {
        return false;
    }
    let Some(task) = crate::task::processor::current_task() else {
        return false;
    };
    let mut inner = task.borrow_mut();
    let state = &mut inner.loongarch_fp;

    if state.width == LoongArchFpWidth::None {
        initialize_scalar_snapshot(state);
    } else if state.hardware_live && state.width == LoongArchFpWidth::Scalar {
        // The low halves may be newer than memory. Snapshot them before the
        // first LSX restore initializes the overlapping upper halves.
        set_extension_width(LoongArchFpWidth::Scalar);
        // SAFETY: scalar state is live for the current task on this hart.
        unsafe { save_scalar_registers(state.regs.as_mut_ptr()) };
        save_fp_control(state);
    }
    if state.width == LoongArchFpWidth::Scalar {
        upgrade_snapshot_to_lsx(state);
    }
    restore_snapshot(state);
    state.hardware_live = true;
    true
}

pub fn prepare_user_fp_state(task: &Arc<TaskControlBlock>) {
    let state = task.borrow_mut().loongarch_fp;
    if state.hardware_live {
        set_extension_width(state.width);
    } else {
        disable_fp_extensions();
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

fn local_elf_hwcap() -> usize {
    let cpucfg2 = read_cpucfg(2);
    let mut hwcap = HWCAP_CPUCFG;
    if cpucfg2 & CPUCFG2_FP != 0 {
        hwcap |= HWCAP_FPU;
    }
    if cpucfg2 & CPUCFG2_LSX != 0 {
        hwcap |= HWCAP_LSX;
    }
    hwcap
}

pub fn elf_hwcap() -> usize {
    ELF_HWCAP_INTERSECTION.load(Ordering::Acquire) & ELF_HWCAP_FEATURE_MASK
}

/// Freeze the capability set before the first user image is created.
///
/// A CPU that misses the SMP admission barrier must not lower the intersection
/// after an executable has already consumed AT_HWCAP. The frozen bit is part
/// of the same atomic word as the feature intersection, so an intersecting
/// CAS is ordered either wholly before or wholly after the freeze.
pub fn freeze_elf_hwcap() {
    ELF_HWCAP_INTERSECTION.fetch_or(ELF_HWCAP_FROZEN, Ordering::AcqRel);
}

fn intersect_elf_hwcap(local: usize) {
    let mut observed = ELF_HWCAP_INTERSECTION.load(Ordering::Acquire);
    loop {
        if observed & ELF_HWCAP_FROZEN != 0 {
            return;
        }
        let updated = (observed & local) & ELF_HWCAP_FEATURE_MASK;
        match ELF_HWCAP_INTERSECTION.compare_exchange_weak(
            observed,
            updated,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(current) => observed = current,
        }
    }
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
        // Start with all overlapping FP/SIMD units disabled. User instructions
        // trap once and lazily acquire the task's saved width.
        let mut euen: usize;
        asm!("csrrd {}, 0x2", out(reg) euen);
        euen &= !(EUEN_FPEN | EUEN_LSXEN | EUEN_LASXEN);
        csr_write::<0x2>(euen);

        // Clear pending timer interrupt and disable timer while bootstrapping.
        csr_write::<0x44>(1); // TIClr
        csr_write::<0x41>(0); // TCFG

        // Enable paging: CRMD.PG=1, CRMD.DA=0, CRMD.IE=0.
        let mut crmd: usize;
        asm!("csrrd {}, 0x0", out(reg) crmd);
        crmd &= !CRMD_IE;
        crmd &= !CRMD_DA;
        crmd |= CRMD_PG;
        csr_write::<0x0>(crmd);

        // TLB refill entry (must be 4K aligned).
        csr_write::<0x88>(__rfill as usize);

        // STLB page size and refill page size (4KB).
        let page_bits = crate::config::PAGE_SIZE_BITS;
        csr_write::<0x1e>(page_bits);
        csr_write::<0x8e>(page_bits);

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
        csr_write::<0x1c>(pwcl);
        csr_write::<0x1d>(0);

        asm!("invtlb {op}, $r0, $r0", op = const INVTLB_ALL);
    }

    intersect_elf_hwcap(local_elf_hwcap());
    if let Some(freq) = detect_clock_freq() {
        crate::config::set_clock_freq(freq);
    }
    mm::init_local_tlb_capabilities();
    enable_ipi_interrupt();
}
