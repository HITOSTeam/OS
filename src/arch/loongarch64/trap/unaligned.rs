//! Integer load/store emulation for LoongArch address-alignment exceptions.
//!
//! LA264 raises ECODE 9 for naturally unaligned word and doubleword accesses.
//! Rust code built for the generic LoongArch target, as well as third-party
//! userspace, may still contain such accesses.  Decode the same base integer
//! instruction families handled by Linux, StarryOS, and RocketOS, then perform
//! the transfer byte-by-byte.

use core::ptr::{read_volatile, write_volatile};

use super::context::TrapContext;

const LDH_OP: u32 = 0xa1;
const LDW_OP: u32 = 0xa2;
const LDD_OP: u32 = 0xa3;
const STH_OP: u32 = 0xa5;
const STW_OP: u32 = 0xa6;
const STD_OP: u32 = 0xa7;
const LDHU_OP: u32 = 0xa9;
const LDWU_OP: u32 = 0xaa;

const LDPTRW_OP: u32 = 0x24;
const STPTRW_OP: u32 = 0x25;
const LDPTRD_OP: u32 = 0x26;
const STPTRD_OP: u32 = 0x27;

const LDXH_OP: u32 = 0x7008;
const LDXW_OP: u32 = 0x7010;
const LDXD_OP: u32 = 0x7018;
const STXH_OP: u32 = 0x7028;
const STXW_OP: u32 = 0x7030;
const STXD_OP: u32 = 0x7038;
const LDXHU_OP: u32 = 0x7048;
const LDXWU_OP: u32 = 0x7050;

#[derive(Clone, Copy)]
struct DecodedAccess {
    reg: usize,
    size: usize,
    signed: bool,
    store: bool,
}

impl DecodedAccess {
    const fn load(reg: usize, size: usize, signed: bool) -> Self {
        Self {
            reg,
            size,
            signed,
            store: false,
        }
    }

    const fn store(reg: usize, size: usize) -> Self {
        Self {
            reg,
            size,
            signed: false,
            store: true,
        }
    }
}

fn decode(insn: u32) -> Option<DecodedAccess> {
    let reg = (insn & 0x1f) as usize;
    let access = match insn >> 22 {
        LDH_OP => Some(DecodedAccess::load(reg, 2, true)),
        LDHU_OP => Some(DecodedAccess::load(reg, 2, false)),
        LDW_OP => Some(DecodedAccess::load(reg, 4, true)),
        LDWU_OP => Some(DecodedAccess::load(reg, 4, false)),
        LDD_OP => Some(DecodedAccess::load(reg, 8, true)),
        STH_OP => Some(DecodedAccess::store(reg, 2)),
        STW_OP => Some(DecodedAccess::store(reg, 4)),
        STD_OP => Some(DecodedAccess::store(reg, 8)),
        _ => None,
    };
    if access.is_some() {
        return access;
    }

    let access = match insn >> 24 {
        LDPTRW_OP => Some(DecodedAccess::load(reg, 4, true)),
        LDPTRD_OP => Some(DecodedAccess::load(reg, 8, true)),
        STPTRW_OP => Some(DecodedAccess::store(reg, 4)),
        STPTRD_OP => Some(DecodedAccess::store(reg, 8)),
        _ => None,
    };
    if access.is_some() {
        return access;
    }

    match insn >> 15 {
        LDXH_OP => Some(DecodedAccess::load(reg, 2, true)),
        LDXHU_OP => Some(DecodedAccess::load(reg, 2, false)),
        LDXW_OP => Some(DecodedAccess::load(reg, 4, true)),
        LDXWU_OP => Some(DecodedAccess::load(reg, 4, false)),
        LDXD_OP => Some(DecodedAccess::load(reg, 8, true)),
        STXH_OP => Some(DecodedAccess::store(reg, 2)),
        STXW_OP => Some(DecodedAccess::store(reg, 4)),
        STXD_OP => Some(DecodedAccess::store(reg, 8)),
        _ => None,
    }
}

fn decode_loaded_value(bytes: &[u8; 8], size: usize, signed: bool) -> usize {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().copied().enumerate().take(size) {
        value |= u64::from(byte) << (index * 8);
    }
    if !signed {
        return value as usize;
    }
    match size {
        2 => (value as u16 as i16 as isize) as usize,
        4 => (value as u32 as i32 as isize) as usize,
        8 => value as usize,
        _ => unreachable!(),
    }
}

fn finish_load(trap_cx: &mut TrapContext, access: DecodedAccess, bytes: &[u8; 8]) {
    if access.reg != 0 {
        trap_cx.x[access.reg] = decode_loaded_value(bytes, access.size, access.signed);
    }
    trap_cx.sepc = trap_cx.sepc.wrapping_add(4);
}

fn store_bytes(value: usize, bytes: &mut [u8; 8], size: usize) {
    for (index, byte) in bytes.iter_mut().enumerate().take(size) {
        *byte = (value >> (index * 8)) as u8;
    }
}

/// Emulate a kernel-mode integer alignment fault.
///
/// Byte-wide volatile accesses prevent LLVM from folding the transfer back
/// into the same unaligned word operation that caused the exception.
pub(super) fn emulate_kernel(trap_cx: &mut TrapContext, badv: usize, insn: u32) -> bool {
    let Some(access) = decode(insn) else {
        return false;
    };
    if badv.checked_add(access.size.saturating_sub(1)).is_none() {
        return false;
    }

    let mut bytes = [0u8; 8];
    if access.store {
        let value = if access.reg == 0 {
            0
        } else {
            trap_cx.x[access.reg]
        };
        store_bytes(value, &mut bytes, access.size);
        for (index, byte) in bytes.iter().copied().enumerate().take(access.size) {
            // SAFETY: BADV identifies the architecturally faulting kernel
            // address. The checked range cannot wrap, and volatile u8 stores
            // preserve byte accesses on strict-alignment CPUs.
            unsafe { write_volatile((badv + index) as *mut u8, byte) };
        }
        trap_cx.sepc = trap_cx.sepc.wrapping_add(4);
    } else {
        for (index, byte) in bytes.iter_mut().enumerate().take(access.size) {
            // SAFETY: As above, but for byte-wide reads from the faulting
            // kernel address.
            *byte = unsafe { read_volatile((badv + index) as *const u8) };
        }
        finish_load(trap_cx, access, &bytes);
    }
    true
}

/// Emulate a user-mode integer alignment fault through the checked user-copy
/// path. Unsupported instructions or inaccessible pages remain SIGBUS faults.
pub(super) fn emulate_user(
    trap_cx: &mut TrapContext,
    token: usize,
    badv: usize,
    insn: u32,
) -> bool {
    let Some(access) = decode(insn) else {
        return false;
    };
    if badv.checked_add(access.size.saturating_sub(1)).is_none() {
        return false;
    }

    let mut bytes = [0u8; 8];
    if access.store {
        let value = if access.reg == 0 {
            0
        } else {
            trap_cx.x[access.reg]
        };
        store_bytes(value, &mut bytes, access.size);
        if crate::mm::try_copy_to_user(token, badv as *mut u8, &bytes[..access.size]).is_err() {
            return false;
        }
        trap_cx.sepc = trap_cx.sepc.wrapping_add(4);
    } else {
        if crate::mm::try_copy_from_user(token, badv as *const u8, &mut bytes[..access.size])
            .is_err()
        {
            return false;
        }
        finish_load(trap_cx, access, &bytes);
    }
    true
}
