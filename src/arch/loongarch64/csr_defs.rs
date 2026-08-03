//! Named constants for LoongArch64 CSR (Control/Status Register) fields.
//!
//! Reference: LoongArch Architecture Reference Manual, Volume 1.
//! This file replaces magic numbers scattered across trap and init code with
//! self-documenting constants.  No behavioural change is intended.

// ── PRMD (Previous Mode, CSR 0x1) ──────────────────────────────────────────
/// Bits [1:0] — Previous Privilege Level (mask).
pub const PRMD_PPLV_MASK: usize = 0x3;
/// Bit [2] — Previous Interrupt Enable.
pub const PRMD_PIE: usize = 1 << 2;
/// Combined: PLV=3 (user mode) + PIE=1.  Written to PRMD before returning to
/// user space so that the CPU restores user privilege and re-enables interrupts.
pub const PRMD_USER_IE: usize = PRMD_PPLV_MASK | PRMD_PIE; // 0x7
/// Mask covering all bits that PRMD_USER_IE touches (PPLV + PIE).
pub const PRMD_USER_IE_MASK: usize = PRMD_USER_IE; // 0x7

// ── CRMD (Current Mode, CSR 0x0) ──────────────────────────────────────────
/// Bit [2] — Global Interrupt Enable.
pub const CRMD_IE: usize = 1 << 2;
/// Bit [3] — Direct Address translation (DA).
pub const CRMD_DA: usize = 1 << 3;
/// Bit [4] — Paging enable (PG).
pub const CRMD_PG: usize = 1 << 4;

// ── ECFG (Exception Config, CSR 0x4) ──────────────────────────────────────
/// Bits [18:16] — Vector Spacing field shift.
pub const ECFG_VS_SHIFT: usize = 16;
/// 3-bit mask for the VS field.
pub const ECFG_VS_MASK: usize = 0x7;
/// Bit [11] — Timer Interrupt local enable (LIE.TI).
pub const ECFG_LIE_TI: usize = 1 << 11;
/// Bit [12] — IPI local enable (LIE.IPI).
pub const ECFG_LIE_IPI: usize = 1 << 12;
/// Bit [3] — external EIOINTC delivery.
pub const ECFG_LIE_EIOINTC: usize = 1 << 3;

// ── ESTAT (Exception Status, CSR 0x5) ─────────────────────────────────────
/// Bits [12:0] — interrupt-pending bitmap.
pub const ESTAT_INTERRUPT_MASK: usize = (1 << 13) - 1;
/// Bits [21:16] — Exception Code shift.
pub const ESTAT_ECODE_SHIFT: usize = 16;
/// 6-bit mask for the exception code field.
pub const ESTAT_ECODE_MASK: usize = 0x3f;
/// Bit [11] — Timer interrupt pending.
pub const ESTAT_IS_TIMER: usize = 1 << 11;
/// Bit [12] — IPI interrupt pending.
pub const ESTAT_IS_IPI: usize = 1 << 12;
/// Bit [3] — EIOINTC interrupt pending.
pub const ESTAT_IS_EIOINTC: usize = 1 << 3;

// ── IOCSR IPI registers ─────────────────────────────────────────────────
/// Per-core IPI pending action register.
pub const IOCSR_IPI_STATUS: usize = 0x1000;
/// Per-core IPI enable register.
pub const IOCSR_IPI_EN: usize = 0x1004;
/// Per-core IPI clear register.
pub const IOCSR_IPI_CLEAR: usize = 0x100c;
/// Cross-core IPI send register.
pub const IOCSR_IPI_SEND: usize = 0x1040;
/// IPI send payload bit 31, matching Linux's IOCSR_IPI_SEND_BLOCKING.
pub const IOCSR_IPI_SEND_BLOCKING: usize = 1 << 31;
/// IPI send target CPU shift.
pub const IOCSR_IPI_SEND_CPU_SHIFT: usize = 16;
/// Cross-core mailbox send register and Linux-compatible payload fields.
pub const IOCSR_MBUF_SEND: usize = 0x1048;
pub const IOCSR_MBUF_SEND_BLOCKING: u64 = 1 << 31;
pub const IOCSR_MBUF_SEND_BOX_SHIFT: usize = 2;
pub const IOCSR_MBUF_SEND_CPU_SHIFT: usize = 16;
pub const IOCSR_MBUF_SEND_BUF_SHIFT: usize = 32;
pub const IOCSR_MBUF_SEND_H32_MASK: u64 = 0xffff_ffff_0000_0000;

/// IOCSR_IPI_SEND takes an action index. IOCSR_IPI_STATUS reports the
/// corresponding bit, so keep these indices separate from status masks.
pub const IPI_ACTION_BOOT_CPU: usize = 0;
pub const IPI_ACTION_RESCHEDULE: usize = 1;
pub const IPI_ACTION_TLB_SHOOTDOWN: usize = 2;
pub const IPI_STATUS_RESCHEDULE: u32 = 1 << IPI_ACTION_RESCHEDULE;
pub const IPI_STATUS_TLB_SHOOTDOWN: u32 = 1 << IPI_ACTION_TLB_SHOOTDOWN;

// ── ASID / TLB configuration and invalidation ─────────────────────────────
pub const CSR_ASID: usize = 0x18;
pub const CSR_ASID_VALUE_MASK: usize = 0x3ff;
pub const CSR_ASID_BITS_SHIFT: usize = 16;
pub const CSR_ASID_BITS_MASK: usize = 0xff;

pub const CSR_PRCFG3: usize = 0x23;
pub const PRCFG3_TLB_TYPE_MASK: usize = 0xf;
pub const PRCFG3_MTLB_SIZE_SHIFT: usize = 4;
pub const PRCFG3_MTLB_SIZE_MASK: usize = 0xff;
pub const PRCFG3_STLB_WAYS_SHIFT: usize = 12;
pub const PRCFG3_STLB_WAYS_MASK: usize = 0xff;
pub const PRCFG3_STLB_INDEX_SHIFT: usize = 20;
pub const PRCFG3_STLB_INDEX_MASK: usize = 0x3f;

pub const INVTLB_ALL: usize = 0x0;
pub const INVTLB_CURRENT_ALL: usize = 0x1;
pub const INVTLB_CURRENT_GFALSE: usize = 0x3;
pub const INVTLB_GFALSE_AND_ASID: usize = 0x4;
pub const INVTLB_ADDR_GFALSE_AND_ASID: usize = 0x5;
pub const INVTLB_ADDR_GTRUE_OR_ASID: usize = 0x6;

// ── TCFG (Timer Config, CSR 0x41) ─────────────────────────────────────────
/// Bit [0] — Timer Enable (also doubles as periodic-mode flag on some revisions).
pub const TCFG_EN: usize = 0x1;
/// Mask to clear bits [1:0] (reserved / control), keeping only the initial
/// countdown value in bits [63:2].
pub const TCFG_INITVAL_MASK: usize = !0x3;
