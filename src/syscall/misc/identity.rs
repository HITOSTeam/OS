use crate::{
    mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value},
    syscall::error::{SyscallError, err},
    task::processor::{current_process, current_task},
    trap::get_current_token,
};
use alloc::vec::Vec;
use core::mem::size_of;

const NGROUPS_MAX: usize = 65536;

pub fn syscall_getuid() -> isize {
    let process = current_process();
    process.borrow_mut().uid as isize
}
pub fn syscall_geteuid() -> isize {
    let process = current_process();
    process.borrow_mut().euid as isize
}
pub fn syscall_getgid() -> isize {
    let process = current_process();
    process.borrow_mut().gid as isize
}
pub fn syscall_getegid() -> isize {
    let process = current_process();
    process.borrow_mut().egid as isize
}

/// Linux `getgroups(2)` (syscall 158 on riscv64).
pub fn syscall_getgroups(size: isize, list: usize) -> isize {
    if size < 0 {
        return err(SyscallError::EINVAL);
    }
    let size = size as usize;
    let groups = {
        let process = current_process();
        let inner = process.borrow_mut();
        inner.supplementary_gids.clone()
    };
    let ngroups = groups.len();
    if size == 0 {
        return ngroups as isize;
    }
    if size < ngroups {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    for (idx, gid) in groups.iter().enumerate() {
        let dst = (list + idx * size_of::<u32>()) as *mut u32;
        if try_write_user_value(token, dst, gid).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    ngroups as isize
}

/// Linux `setgroups(2)` (syscall 159 on riscv64).
pub fn syscall_setgroups(size: usize, list: usize) -> isize {
    if size > NGROUPS_MAX {
        return err(SyscallError::EINVAL);
    }
    {
        let process = current_process();
        let inner = process.borrow_mut();
        if inner.euid != 0 {
            return err(SyscallError::EPERM);
        }
    }
    let token = get_current_token();
    let mut groups = Vec::with_capacity(size);
    for idx in 0..size {
        let src = (list + idx * size_of::<u32>()) as *const u32;
        let Some(gid) = try_read_user_value(token, src) else {
            return err(SyscallError::EFAULT);
        };
        groups.push(gid);
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    inner.supplementary_gids = groups;
    0
}

pub fn current_real_uid_gid() -> (u32, u32) {
    let process = current_process();
    let inner = process.borrow_mut();
    (inner.uid, inner.gid)
}

pub fn current_effective_uid_gid() -> (u32, u32) {
    let process = current_process();
    let inner = process.borrow_mut();
    (inner.euid, inner.egid)
}

pub fn current_fsuid_gid() -> (u32, u32) {
    let process = current_process();
    let inner = process.borrow_mut();
    (inner.fsuid, inner.fsgid)
}

fn uid_allowed(uid: u32, ruid: u32, euid: u32, suid: u32) -> bool {
    uid == ruid || uid == euid || uid == suid
}

fn gid_allowed(gid: u32, rgid: u32, egid: u32, sgid: u32) -> bool {
    gid == rgid || gid == egid || gid == sgid
}

fn parse_uid_opt(uid: usize) -> Option<u32> {
    if uid == usize::MAX || uid == u32::MAX as usize {
        None
    } else {
        Some(uid as u32)
    }
}

fn parse_gid_opt(gid: usize) -> Option<u32> {
    if gid == usize::MAX || gid == u32::MAX as usize {
        None
    } else {
        Some(gid as u32)
    }
}

/// Linux `setuid(2)` (syscall 146 on riscv64).
pub fn syscall_setuid(uid: usize) -> isize {
    let uid = uid as u32;
    let process = current_process();
    let mut inner = process.borrow_mut();
    if inner.euid == 0 {
        inner.uid = uid;
        inner.euid = uid;
        inner.suid = uid;
        inner.fsuid = uid;
        return 0;
    }
    if uid_allowed(uid, inner.uid, inner.euid, inner.suid) {
        inner.euid = uid;
        inner.suid = uid;
        inner.fsuid = uid;
        return 0;
    }
    err(SyscallError::EPERM)
}

/// Linux `setgid(2)` (syscall 144 on riscv64).
pub fn syscall_setgid(gid: usize) -> isize {
    let gid = gid as u32;
    let process = current_process();
    let mut inner = process.borrow_mut();
    if inner.euid == 0 {
        inner.gid = gid;
        inner.egid = gid;
        inner.sgid = gid;
        inner.fsgid = gid;
        return 0;
    }
    if gid_allowed(gid, inner.gid, inner.egid, inner.sgid) {
        inner.egid = gid;
        inner.sgid = gid;
        inner.fsgid = gid;
        return 0;
    }
    err(SyscallError::EPERM)
}

/// Linux `setreuid(2)` (syscall 145 on riscv64).
pub fn syscall_setreuid(ruid: usize, euid: usize) -> isize {
    let new_ruid = parse_uid_opt(ruid);
    let new_euid = parse_uid_opt(euid);
    let process = current_process();
    let mut inner = process.borrow_mut();
    let old_ruid = inner.uid;
    let old_euid = inner.euid;
    let old_suid = inner.suid;
    if inner.euid != 0 {
        if let Some(r) = new_ruid {
            if r != old_ruid && r != old_euid {
                return err(SyscallError::EPERM);
            }
        }
        if let Some(e) = new_euid {
            if !uid_allowed(e, old_ruid, old_euid, old_suid) {
                return err(SyscallError::EPERM);
            }
        }
    }
    let next_ruid = new_ruid.unwrap_or(old_ruid);
    let next_euid = new_euid.unwrap_or(old_euid);
    inner.uid = next_ruid;
    inner.euid = next_euid;
    if new_euid.is_some() {
        inner.fsuid = next_euid;
    }
    // Linux: saved-set-uid changes if real uid changed, or if effective uid
    // changes to a value different from the old real uid.
    if new_ruid.is_some() || (new_euid.is_some() && next_euid != old_ruid) {
        inner.suid = next_euid;
    }
    0
}

/// Linux `setregid(2)` (syscall 143 on riscv64).
pub fn syscall_setregid(rgid: usize, egid: usize) -> isize {
    let new_rgid = parse_gid_opt(rgid);
    let new_egid = parse_gid_opt(egid);
    let process = current_process();
    let mut inner = process.borrow_mut();
    let old_rgid = inner.gid;
    let old_egid = inner.egid;
    let old_sgid = inner.sgid;
    if inner.euid != 0 {
        if let Some(r) = new_rgid {
            if r != old_rgid && r != old_egid {
                return err(SyscallError::EPERM);
            }
        }
        if let Some(e) = new_egid {
            if !gid_allowed(e, old_rgid, old_egid, old_sgid) {
                return err(SyscallError::EPERM);
            }
        }
    }
    let next_rgid = new_rgid.unwrap_or(old_rgid);
    let next_egid = new_egid.unwrap_or(old_egid);
    inner.gid = next_rgid;
    inner.egid = next_egid;
    if new_egid.is_some() {
        inner.fsgid = next_egid;
    }
    // Linux: saved-set-gid changes if real gid changed, or if effective gid
    // changes to a value different from the old real gid.
    if new_rgid.is_some() || (new_egid.is_some() && next_egid != old_rgid) {
        inner.sgid = next_egid;
    }
    0
}

/// Linux `setresuid(2)` (syscall 147 on riscv64).
pub fn syscall_setresuid(ruid: usize, euid: usize, suid: usize) -> isize {
    let new_ruid = parse_uid_opt(ruid);
    let new_euid = parse_uid_opt(euid);
    let new_suid = parse_uid_opt(suid);
    let process = current_process();
    let mut inner = process.borrow_mut();
    if inner.euid != 0 {
        for cand in [new_ruid, new_euid, new_suid] {
            if let Some(v) = cand {
                if !uid_allowed(v, inner.uid, inner.euid, inner.suid) {
                    return err(SyscallError::EPERM);
                }
            }
        }
    }
    if let Some(r) = new_ruid {
        inner.uid = r;
    }
    if let Some(e) = new_euid {
        inner.euid = e;
        inner.fsuid = e;
    }
    if let Some(s) = new_suid {
        inner.suid = s;
    }
    0
}

/// Linux `setresgid(2)` (syscall 149 on riscv64).
pub fn syscall_setresgid(rgid: usize, egid: usize, sgid: usize) -> isize {
    let new_rgid = parse_gid_opt(rgid);
    let new_egid = parse_gid_opt(egid);
    let new_sgid = parse_gid_opt(sgid);
    let process = current_process();
    let mut inner = process.borrow_mut();
    if inner.euid != 0 {
        for cand in [new_rgid, new_egid, new_sgid] {
            if let Some(v) = cand {
                if !gid_allowed(v, inner.gid, inner.egid, inner.sgid) {
                    return err(SyscallError::EPERM);
                }
            }
        }
    }
    if let Some(r) = new_rgid {
        inner.gid = r;
    }
    if let Some(e) = new_egid {
        inner.egid = e;
        inner.fsgid = e;
    }
    if let Some(s) = new_sgid {
        inner.sgid = s;
    }
    0
}

/// Linux `setfsuid(2)` (syscall 151 on riscv64).
pub fn syscall_setfsuid(uid: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    let prev = inner.fsuid;
    if uid == usize::MAX || uid == u32::MAX as usize {
        return prev as isize;
    }
    let uid = uid as u32;
    if inner.euid == 0 || uid_allowed(uid, inner.uid, inner.euid, inner.suid) || uid == inner.fsuid
    {
        inner.fsuid = uid;
    }
    prev as isize
}

/// Linux `setfsgid(2)` (syscall 152 on riscv64).
pub fn syscall_setfsgid(gid: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    let prev = inner.fsgid;
    if gid == usize::MAX || gid == u32::MAX as usize {
        return prev as isize;
    }
    let gid = gid as u32;
    if inner.euid == 0 || gid_allowed(gid, inner.gid, inner.egid, inner.sgid) || gid == inner.fsgid
    {
        inner.fsgid = gid;
    }
    prev as isize
}

/// Linux `getresuid(2)` (syscall 148 on riscv64).
pub fn syscall_getresuid(ruid: usize, euid: usize, suid: usize) -> isize {
    let process = current_process();
    let (uid, euid_v, suid_v) = {
        let inner = process.borrow_mut();
        (inner.uid, inner.euid, inner.suid)
    };
    let token = get_current_token();
    if ruid != 0 && try_write_user_value(token, ruid as *mut u32, &uid).is_err() {
        return err(SyscallError::EFAULT);
    }
    if euid != 0 && try_write_user_value(token, euid as *mut u32, &euid_v).is_err() {
        return err(SyscallError::EFAULT);
    }
    if suid != 0 && try_write_user_value(token, suid as *mut u32, &suid_v).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// Linux `getresgid(2)` (syscall 150 on riscv64).
pub fn syscall_getresgid(rgid: usize, egid: usize, sgid: usize) -> isize {
    let process = current_process();
    let (gid, egid_v, sgid_v) = {
        let inner = process.borrow_mut();
        (inner.gid, inner.egid, inner.sgid)
    };
    let token = get_current_token();
    if rgid != 0 && try_write_user_value(token, rgid as *mut u32, &gid).is_err() {
        return err(SyscallError::EFAULT);
    }
    if egid != 0 && try_write_user_value(token, egid as *mut u32, &egid_v).is_err() {
        return err(SyscallError::EFAULT);
    }
    if sgid != 0 && try_write_user_value(token, sgid as *mut u32, &sgid_v).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn current_umask() -> usize {
    let process = current_process();
    let inner = process.borrow_mut();
    inner.umask & 0o777
}

/// Linux `umask(2)` (syscall 166 on riscv64).
///
/// A minimal implementation for daemon() and common utilities.
pub fn syscall_umask(mask: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    let prev = inner.umask & 0o777;
    inner.umask = mask & 0o777;
    prev as isize
}

/// Linux `seteuid(2)` — convenience wrapper used by some LTP tests.
pub fn syscall_seteuid(euid: usize) -> isize {
    syscall_setreuid(usize::MAX, euid)
}

/// Linux `setegid(2)` — convenience wrapper used by some LTP tests.
pub fn syscall_setegid(egid: usize) -> isize {
    syscall_setregid(usize::MAX, egid)
}
