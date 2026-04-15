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

// ── ESTAT (Exception Status, CSR 0x5) ─────────────────────────────────────
/// Bits [21:16] — Exception Code shift.
pub const ESTAT_ECODE_SHIFT: usize = 16;
/// 6-bit mask for the exception code field.
pub const ESTAT_ECODE_MASK: usize = 0x3f;

// ── TCFG (Timer Config, CSR 0x41) ─────────────────────────────────────────
/// Bit [0] — Timer Enable (also doubles as periodic-mode flag on some revisions).
pub const TCFG_EN: usize = 0x1;
/// Mask to clear bits [1:0] (reserved / control), keeping only the initial
/// countdown value in bits [63:2].
pub const TCFG_INITVAL_MASK: usize = !0x3;
