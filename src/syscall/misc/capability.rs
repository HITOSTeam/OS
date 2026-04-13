use crate::{
    mm::{try_read_user_value, try_write_user_value},
    syscall::error::{SyscallError, err},
    task::processor::current_process,
    trap::get_current_token,
};
use core::mem::size_of;

use super::current_linux_tid;

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
pub(super) const CAP_LAST_CAP: usize = 63;
pub(super) const CAP_SETPCAP: usize = 8;

fn cap_data_u32s(version: u32) -> Option<usize> {
    match version {
        LINUX_CAPABILITY_VERSION_1 => Some(1),
        LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3 => Some(2),
        _ => None,
    }
}

fn cap_pid_matches_current(pid: i32) -> bool {
    if pid == 0 {
        return true;
    }
    let pid = pid as usize;
    // Linux capability operations are per-thread (TID-based pid field).
    pid == current_process().getpid() || pid == current_linux_tid()
}

pub(super) fn cap_bit(cap: usize) -> u64 {
    1u64 << cap
}

/// Linux `capget(2)` (syscall 90 on riscv64).
///
/// Minimal support used by LTP capability helpers.
pub fn syscall_capget(hdrp: usize, datap: usize) -> isize {
    if hdrp == 0 || datap == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let mut hdr = match try_read_user_value(token, hdrp as *const CapUserHeader) {
        Some(v) => v,
        None => return err(SyscallError::EFAULT),
    };

    let Some(n_u32s) = cap_data_u32s(hdr.version) else {
        hdr.version = LINUX_CAPABILITY_VERSION_3;
        if try_write_user_value(token, hdrp as *mut CapUserHeader, &hdr).is_err() {
            return err(SyscallError::EFAULT);
        }
        return err(SyscallError::EINVAL);
    };
    if hdr.pid < 0 {
        return err(SyscallError::EINVAL);
    }

    if !cap_pid_matches_current(hdr.pid) {
        return err(SyscallError::ESRCH);
    }
    let (effective, permitted, inheritable) = {
        let process = current_process();
        let inner = process.borrow_mut();
        (
            inner.cap_effective,
            inner.cap_permitted,
            inner.cap_inheritable,
        )
    };
    for i in 0..n_u32s {
        let shift = i * 32;
        let data = CapUserData {
            effective: ((effective >> shift) & u32::MAX as u64) as u32,
            permitted: ((permitted >> shift) & u32::MAX as u64) as u32,
            inheritable: ((inheritable >> shift) & u32::MAX as u64) as u32,
        };
        let ptr = (datap + i * size_of::<CapUserData>()) as *mut CapUserData;
        if try_write_user_value(token, ptr, &data).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    0
}

/// Linux `capset(2)` (syscall 91 on riscv64).
///
/// Minimal support used by LTP capability helpers.
pub fn syscall_capset(hdrp: usize, datap: usize) -> isize {
    if hdrp == 0 || datap == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let mut hdr = match try_read_user_value(token, hdrp as *const CapUserHeader) {
        Some(v) => v,
        None => return err(SyscallError::EFAULT),
    };

    let Some(n_u32s) = cap_data_u32s(hdr.version) else {
        hdr.version = LINUX_CAPABILITY_VERSION_3;
        if try_write_user_value(token, hdrp as *mut CapUserHeader, &hdr).is_err() {
            return err(SyscallError::EFAULT);
        }
        return err(SyscallError::EINVAL);
    };
    if hdr.pid < 0 {
        return err(SyscallError::EINVAL);
    }

    if !cap_pid_matches_current(hdr.pid) {
        return err(SyscallError::EPERM);
    }

    let mut payload = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    for i in 0..n_u32s {
        let ptr = (datap + i * size_of::<CapUserData>()) as *const CapUserData;
        let Some(data) = try_read_user_value(token, ptr) else {
            return err(SyscallError::EFAULT);
        };
        payload[i] = data;
    }
    let mut new_effective = 0u64;
    let mut new_permitted = 0u64;
    let mut new_inheritable = 0u64;
    for (i, entry) in payload.iter().take(n_u32s).enumerate() {
        let shift = i * 32;
        new_effective |= (entry.effective as u64) << shift;
        new_permitted |= (entry.permitted as u64) << shift;
        new_inheritable |= (entry.inheritable as u64) << shift;
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    if (new_effective & !new_permitted) != 0 {
        return err(SyscallError::EPERM);
    }
    if (new_permitted & !inner.cap_permitted) != 0 {
        return err(SyscallError::EPERM);
    }
    if (new_inheritable & !inner.cap_inheritable) != 0 {
        return err(SyscallError::EPERM);
    }
    if (new_inheritable & !inner.cap_bounding) != 0 {
        return err(SyscallError::EPERM);
    }
    inner.cap_effective = new_effective;
    inner.cap_permitted = new_permitted;
    inner.cap_inheritable = new_inheritable;
    0
}
