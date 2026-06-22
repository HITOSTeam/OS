use crate::{
    mm::{try_copy_from_user, try_copy_to_user, try_write_user_value},
    syscall::error::{SyscallError, err},
    task::processor::current_process,
    trap::get_current_token,
};
use alloc::string::String;

use super::capability::{CAP_LAST_CAP, CAP_SETPCAP, cap_bit};

const PR_SET_PDEATHSIG: usize = 1;
const PR_GET_PDEATHSIG: usize = 2;
const PR_GET_DUMPABLE: usize = 3;
const PR_SET_DUMPABLE: usize = 4;
const PR_GET_KEEPCAPS: usize = 7;
const PR_SET_KEEPCAPS: usize = 8;
const PR_SET_NAME: usize = 15;
const PR_GET_NAME: usize = 16;
const PR_GET_SECUREBITS: usize = 27;
const PR_SET_SECUREBITS: usize = 28;
const PR_SET_TIMERSLACK: usize = 29;
const PR_GET_TIMERSLACK: usize = 30;
const PR_CAPBSET_READ: usize = 23;
const PR_CAPBSET_DROP: usize = 24;

const SECBIT_KEEP_CAPS: usize = 1 << 4;

/// Linux `prctl(2)` subset needed by credential/capability tests.
pub fn syscall_prctl(option: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> isize {
    const MAX_SIGNAL_NUM: usize = 64;
    match option {
        PR_SET_PDEATHSIG => {
            if arg2 > MAX_SIGNAL_NUM {
                return err(SyscallError::EINVAL);
            }
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.pdeath_signal = arg2 as i32;
            0
        }
        PR_GET_PDEATHSIG => {
            if arg2 == 0 {
                return err(SyscallError::EFAULT);
            }
            let process = current_process();
            let sig = process.borrow_mut().pdeath_signal;
            let token = get_current_token();
            if try_write_user_value(token, arg2 as *mut i32, &sig).is_err() {
                return err(SyscallError::EFAULT);
            }
            0
        }
        PR_GET_DUMPABLE => 1,
        PR_SET_DUMPABLE => {
            if arg2 > 1 {
                err(SyscallError::EINVAL)
            } else {
                0
            }
        }
        PR_GET_KEEPCAPS => {
            let process = current_process();
            let inner = process.borrow_mut();
            if inner.keep_caps { 1 } else { 0 }
        }
        PR_SET_KEEPCAPS => {
            if arg2 > 1 {
                return err(SyscallError::EINVAL);
            }
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.keep_caps = arg2 != 0;
            0
        }
        PR_SET_NAME => {
            if arg2 == 0 {
                return err(SyscallError::EFAULT);
            }
            let token = get_current_token();
            let mut raw = [0u8; 16];
            for (i, byte) in raw.iter_mut().enumerate() {
                let ptr = arg2.saturating_add(i) as *const u8;
                if try_copy_from_user(token, ptr, core::slice::from_mut(byte)).is_err() {
                    return err(SyscallError::EFAULT);
                }
            }
            let mut comm = String::new();
            for b in raw.iter().copied().take(15) {
                if b == 0 {
                    break;
                }
                comm.push(b as char);
            }
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.comm = comm;
            0
        }
        PR_GET_NAME => {
            if arg2 == 0 {
                return err(SyscallError::EFAULT);
            }
            let process = current_process();
            let comm = process.borrow_mut().comm.clone();
            let mut out = [0u8; 16];
            let name = comm.as_bytes();
            let n = core::cmp::min(name.len(), 15);
            out[..n].copy_from_slice(&name[..n]);
            let token = get_current_token();
            if try_copy_to_user(token, arg2 as *mut u8, &out).is_err() {
                return err(SyscallError::EFAULT);
            }
            0
        }
        PR_SET_TIMERSLACK => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if arg2 == 0 {
                inner.timer_slack_ns = inner.timer_slack_default_ns;
            } else {
                inner.timer_slack_ns = arg2 as u64;
            }
            0
        }
        PR_GET_TIMERSLACK => {
            let process = current_process();
            let inner = process.borrow_mut();
            let value = inner.timer_slack_ns;
            if value > isize::MAX as u64 {
                isize::MAX
            } else {
                value as isize
            }
        }
        PR_GET_SECUREBITS => {
            let process = current_process();
            let inner = process.borrow_mut();
            if inner.keep_caps {
                SECBIT_KEEP_CAPS as isize
            } else {
                0
            }
        }
        PR_SET_SECUREBITS => {
            if arg3 != 0 || arg4 != 0 || arg5 != 0 {
                return err(SyscallError::EINVAL);
            }
            let process = current_process();
            let mut inner = process.borrow_mut();
            if inner.euid != 0 || (inner.cap_effective & cap_bit(CAP_SETPCAP)) == 0 {
                return err(SyscallError::EPERM);
            }
            inner.keep_caps = (arg2 & SECBIT_KEEP_CAPS) != 0;
            0
        }
        PR_CAPBSET_READ => {
            if arg2 > CAP_LAST_CAP {
                return err(SyscallError::EINVAL);
            }
            let process = current_process();
            let inner = process.borrow_mut();
            if (inner.cap_bounding & cap_bit(arg2)) != 0 {
                1
            } else {
                0
            }
        }
        PR_CAPBSET_DROP => {
            if arg2 > CAP_LAST_CAP {
                return err(SyscallError::EINVAL);
            }
            let process = current_process();
            let mut inner = process.borrow_mut();
            if inner.euid != 0 || (inner.cap_effective & cap_bit(CAP_SETPCAP)) == 0 {
                return err(SyscallError::EPERM);
            }
            inner.cap_bounding &= !cap_bit(arg2);
            0
        }
        _ => err(SyscallError::EINVAL),
    }
}
