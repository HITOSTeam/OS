use crate::{
    arch,
    config::clock_freq,
    debug_config::DEBUG_PTHREAD,
    fs::ext4_lock,
    mm::{
        read_user_value, translated_byte_buffer, translated_str, try_copy_from_user,
        try_read_user_value, try_write_user_value, write_user_value, MapPermission,
    },
    syscall::{
        filesystem::{normalize_path, register_rofs_mount, unregister_rofs_mount},
        robust_list::ROBUST_LIST_HEAD_LEN,
    },
    task::{
        manager::{pid2process, refresh_process_runqueues, PID2PCB},
        processor::{
            block_current_and_run_next, current_files_process, current_process, current_task,
        },
        signal::{
            has_unmasked_pending, queue_process_signal, signal_bit, SIGKILL_NUM, SIGSTOP_NUM,
            SIGXCPU_NUM,
        },
    },
    time::{get_time, get_time_ms},
    trap::get_current_token,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use lazy_static::lazy_static;
use spin::Mutex;

// ---- Linux-like TID encoding ------------------------------------------------
//
// Internally, CongCore uses a small per-process `tid` index for locating per-thread resources
// (trap context pages, optional kernel-managed stacks). glibc expects a Linux-style `gettid()`
// that is:
// - equal to `getpid()` for the main thread, and
// - unique across all threads in the system.
//
// To avoid refactoring the internal resource indexing, we encode non-main thread IDs into
// a 32-bit range derived from (tgid << 15) | tid_index, keeping bit 30 clear so
// futex owner bits (OWNER_DIED/WAITERS) remain usable.
// (tgid << 15) occupies bits [15..29] for typical OSComp PID ranges (< 32768).
const LINUX_TID_PID_SHIFT: usize = 15;

const EPERM: isize = -1;
const EACCES: isize = -13;
const EFAULT: isize = -14;
const ENAMETOOLONG: isize = -36;
const ENOENT: isize = -2;
const ENODEV: isize = -19;
const ENOTDIR: isize = -20;
const ESRCH: isize = -3;
const EINVAL: isize = -22;
const NGROUPS_MAX: usize = 65536;

pub(crate) fn encode_linux_tid(tgid: usize, tid_index: usize) -> usize {
    if tid_index == 0 {
        tgid
    } else {
        (tgid << LINUX_TID_PID_SHIFT) | (tid_index & 0x7fff)
    }
}

pub(crate) fn decode_linux_tid(tgid: usize, tid: usize) -> Option<usize> {
    // Strip futex owner/waiter bits that user space may OR into the TID word.
    let tid = tid & 0x3fff_ffff;
    if tid == tgid {
        return Some(0);
    }
    let pid_part = tid >> LINUX_TID_PID_SHIFT;
    if pid_part != tgid {
        return None;
    }
    Some(tid & 0x7fff)
}

fn current_tid_index() -> usize {
    current_task()
        .unwrap()
        .borrow_mut()
        .res
        .as_ref()
        .unwrap()
        .tid
}

fn current_linux_tid() -> usize {
    encode_linux_tid(current_process().getpid(), current_tid_index())
}

// -----------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[derive(Clone, Copy)]
struct UtsConfig {
    nodename: [u8; 65],
    domainname: [u8; 65],
}

impl UtsConfig {
    fn new() -> Self {
        let mut cfg = Self {
            nodename: [0; 65],
            domainname: [0; 65],
        };
        write_name_field(&mut cfg.nodename, b"localhost");
        write_name_field(&mut cfg.domainname, b"localdomain");
        cfg
    }
}

lazy_static! {
    static ref UTS_CONFIG: Mutex<UtsConfig> = Mutex::new(UtsConfig::new());
}

fn write_name_field(dst: &mut [u8; 65], src: &[u8]) {
    dst.fill(0);
    let n = src.len().min(64);
    dst[..n].copy_from_slice(&src[..n]);
}

fn read_name_from_user(name: usize, len: usize) -> Result<[u8; 65], isize> {
    if len > 64 {
        return Err(EINVAL);
    }
    let mut field = [0u8; 65];
    if len == 0 {
        return Ok(field);
    }
    let token = get_current_token();
    if try_copy_from_user(token, name as *const u8, &mut field[..len]).is_err() {
        return Err(EFAULT);
    }
    Ok(field)
}

pub fn syscall_sethostname(name: usize, len: usize) -> isize {
    if current_process().borrow_mut().euid != 0 {
        return EPERM;
    }
    let new_name = match read_name_from_user(name, len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    UTS_CONFIG.lock().nodename = new_name;
    0
}

pub fn syscall_setdomainname(name: usize, len: usize) -> isize {
    if current_process().borrow_mut().euid != 0 {
        return EPERM;
    }
    let new_name = match read_name_from_user(name, len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    UTS_CONFIG.lock().domainname = new_name;
    0
}

/// Linux `personality(2)`:
/// - `persona == -1UL` queries current personality
/// - otherwise set personality and return previous value
pub fn syscall_personality(persona: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    let old = inner.personality;
    if persona == usize::MAX {
        return old as isize;
    }
    inner.personality = persona as u32;
    old as isize
}

pub fn syscall_uname(buf: usize) -> isize {
    if buf == 0 {
        return EFAULT;
    }
    let mut un = UtsName {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    write_name_field(&mut un.sysname, b"Linux");
    // glibc/busybox may abort early if the reported kernel release is "too old".
    // Report a modern Linux-like release string for compatibility.
    write_name_field(&mut un.release, b"5.15.0");
    write_name_field(&mut un.version, b"CongCore");
    let machine = if cfg!(target_arch = "loongarch64") {
        b"loongarch64".as_slice()
    } else {
        b"riscv64".as_slice()
    };
    write_name_field(&mut un.machine, machine);
    {
        let cfg = UTS_CONFIG.lock();
        un.nodename = cfg.nodename;
        un.domainname = cfg.domainname;
    }

    let token = get_current_token();
    if try_write_user_value(token, buf as *mut UtsName, &un).is_err() {
        return EFAULT;
    }
    0
}

/// Linux-compatible gethostname behavior used by some musl paths:
/// return ENAMETOOLONG if the provided buffer cannot hold the full name.
pub fn syscall_gethostname(name: usize, len: usize) -> isize {
    if name == 0 {
        return EFAULT;
    }
    let nodename = {
        let cfg = UTS_CONFIG.lock();
        cfg.nodename
    };
    let host_len = nodename.iter().position(|&c| c == 0).unwrap_or(64);
    let token = get_current_token();

    if len == 0 {
        return ENAMETOOLONG;
    }

    if len <= host_len {
        for i in 0..len {
            if try_write_user_value(token, (name + i) as *mut u8, &nodename[i]).is_err() {
                return EFAULT;
            }
        }
        return ENAMETOOLONG;
    }

    for i in 0..host_len {
        if try_write_user_value(token, (name + i) as *mut u8, &nodename[i]).is_err() {
            return EFAULT;
        }
    }
    let zero: u8 = 0;
    if try_write_user_value(token, (name + host_len) as *mut u8, &zero).is_err() {
        return EFAULT;
    }
    0
}

pub fn syscall_mount(
    _special: usize,
    _dir: usize,
    _fstype: usize,
    _flags: usize,
    _data: usize,
) -> isize {
    const MS_RDONLY: usize = 0x1;
    if current_process().borrow_mut().euid != 0 {
        return EPERM;
    }
    let token = get_current_token();
    let fstype = if _fstype == 0 {
        alloc::string::String::new()
    } else {
        translated_str(token, _fstype as *const u8)
    };
    if fstype == "cgroup" || fstype == "cgroup2" {
        return ENODEV;
    }
    let dir = translated_str(token, _dir as *const u8);
    if dir.is_empty() {
        return ENOENT;
    }
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let abs = normalize_path(&cwd, &dir);
    let _ext4_guard = ext4_lock();
    let inode = match crate::fs::find_path_in_roots(&abs) {
        Some(v) => v,
        None => return ENOENT,
    };
    if !inode.is_dir() {
        return ENOTDIR;
    }
    if (_flags & MS_RDONLY) != 0 {
        register_rofs_mount(&abs);
    } else {
        unregister_rofs_mount(&abs);
    }
    0
}

pub fn syscall_umount2(_special: usize, _flags: usize) -> isize {
    if current_process().borrow_mut().euid != 0 {
        return EPERM;
    }
    let token = get_current_token();
    let path = translated_str(token, _special as *const u8);
    if path.is_empty() {
        return ENOENT;
    }
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let abs = normalize_path(&cwd, &path);
    unregister_rofs_mount(&abs);
    0
}

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
const CAP_LAST_CAP: usize = 63;
const CAP_SETPCAP: usize = 8;
const PR_GET_DUMPABLE: usize = 3;
const PR_SET_DUMPABLE: usize = 4;
const PR_CAPBSET_READ: usize = 23;
const PR_CAPBSET_DROP: usize = 24;

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

fn cap_bit(cap: usize) -> u64 {
    1u64 << cap
}

/// Linux `capget(2)` (syscall 90 on riscv64).
///
/// Minimal support used by LTP capability helpers.
pub fn syscall_capget(hdrp: usize, datap: usize) -> isize {
    if hdrp == 0 || datap == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let mut hdr = match try_read_user_value(token, hdrp as *const CapUserHeader) {
        Some(v) => v,
        None => return EFAULT,
    };

    let Some(n_u32s) = cap_data_u32s(hdr.version) else {
        hdr.version = LINUX_CAPABILITY_VERSION_3;
        if try_write_user_value(token, hdrp as *mut CapUserHeader, &hdr).is_err() {
            return EFAULT;
        }
        return EINVAL;
    };
    if hdr.pid < 0 {
        return EINVAL;
    }

    if !cap_pid_matches_current(hdr.pid) {
        return ESRCH;
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
            return EFAULT;
        }
    }
    0
}

/// Linux `capset(2)` (syscall 91 on riscv64).
///
/// Minimal support used by LTP capability helpers.
pub fn syscall_capset(hdrp: usize, datap: usize) -> isize {
    if hdrp == 0 || datap == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let mut hdr = match try_read_user_value(token, hdrp as *const CapUserHeader) {
        Some(v) => v,
        None => return EFAULT,
    };

    let Some(n_u32s) = cap_data_u32s(hdr.version) else {
        hdr.version = LINUX_CAPABILITY_VERSION_3;
        if try_write_user_value(token, hdrp as *mut CapUserHeader, &hdr).is_err() {
            return EFAULT;
        }
        return EINVAL;
    };
    if hdr.pid < 0 {
        return EINVAL;
    }

    if !cap_pid_matches_current(hdr.pid) {
        return EPERM;
    }

    let mut payload = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    for i in 0..n_u32s {
        let ptr = (datap + i * size_of::<CapUserData>()) as *const CapUserData;
        let Some(data) = try_read_user_value(token, ptr) else {
            return EFAULT;
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
        return EPERM;
    }
    if (new_permitted & !inner.cap_permitted) != 0 {
        return EPERM;
    }
    if (new_inheritable & !inner.cap_inheritable) != 0 {
        return EPERM;
    }
    if (new_inheritable & !inner.cap_bounding) != 0 {
        return EPERM;
    }
    inner.cap_effective = new_effective;
    inner.cap_permitted = new_permitted;
    inner.cap_inheritable = new_inheritable;
    0
}

/// Linux `prctl(2)` subset needed by credential/capability tests.
pub fn syscall_prctl(
    option: usize,
    arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
) -> isize {
    match option {
        PR_GET_DUMPABLE => 1,
        PR_SET_DUMPABLE => {
            if arg2 > 1 {
                EINVAL
            } else {
                0
            }
        }
        PR_CAPBSET_READ => {
            if arg2 > CAP_LAST_CAP {
                return EINVAL;
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
                return EINVAL;
            }
            let process = current_process();
            let mut inner = process.borrow_mut();
            if inner.euid != 0 || (inner.cap_effective & cap_bit(CAP_SETPCAP)) == 0 {
                return EPERM;
            }
            inner.cap_bounding &= !cap_bit(arg2);
            0
        }
        _ => EINVAL,
    }
}

/// Linux `unshare(2)` (syscall 97 on riscv64).
///
/// Minimal support:
/// - `CLONE_FILES`: unshare file descriptor table from CLONE_FILES owner.
/// - `CLONE_FS`: currently a no-op (cwd/umask are already process-local).
/// - `CLONE_NEWNS`: requires root and is treated as successful no-op namespace split.
pub fn syscall_unshare(flags: usize) -> isize {
    const CLONE_FS: usize = 0x0000_0200;
    const CLONE_FILES: usize = 0x0000_0400;
    const CLONE_NEWNS: usize = 0x0002_0000;
    let valid = CLONE_FILES | CLONE_FS | CLONE_NEWNS;
    if (flags & !valid) != 0 {
        return EINVAL;
    }
    if (flags & CLONE_NEWNS) != 0 {
        let process = current_process();
        if process.borrow_mut().euid != 0 {
            return EPERM;
        }
    }
    if (flags & CLONE_FILES) != 0 {
        let process = current_process();
        process.unshare_files();
    }
    0
}

pub fn syscall_reboot(_magic1: usize, _magic2: usize, _cmd: usize, _arg: usize) -> isize {
    if current_process().borrow_mut().euid != 0 {
        return EPERM;
    }
    arch::shutdown();
}

pub fn syscall_getppid() -> isize {
    let process = current_process();
    let parent = {
        process
            .borrow_mut()
            .parent
            .as_ref()
            .and_then(|p| p.upgrade())
    };
    parent.map(|p| p.getpid() as isize).unwrap_or(0)
}

fn normalized_pgid(pid: usize, pgid: usize) -> usize {
    if pgid == 0 && pid != 0 {
        pid
    } else {
        pgid
    }
}

fn normalized_sid(pid: usize, sid: usize, pgid: usize) -> usize {
    if sid != 0 {
        sid
    } else {
        normalized_pgid(pid, pgid)
    }
}

/// Linux `setpgid(2)` (syscall 154 on riscv64).
///
/// Minimal process-group support for waitpid job-control tests.
pub fn syscall_setpgid(pid: usize, pgid: usize) -> isize {
    if (pid as isize) < 0 || (pgid as isize) < 0 {
        return EINVAL;
    }

    let cur = current_process();
    let cur_pid = cur.getpid();
    let target_pid = if pid == 0 { cur_pid } else { pid };
    let new_pgid = if pgid == 0 { target_pid } else { pgid };

    let target = if target_pid == cur_pid {
        Some(Arc::clone(&cur))
    } else {
        let child = {
            let inner = cur.borrow_mut();
            inner
                .children
                .iter()
                .find(|c| c.getpid() == target_pid)
                .cloned()
        };
        child
    };

    let Some(target) = target else {
        return ESRCH;
    };

    let cur_sid = {
        let inner = cur.borrow_mut();
        normalized_sid(cur_pid, inner.sid, inner.pgid)
    };

    let (target_sid, target_is_session_leader, target_did_exec) = {
        let inner = target.borrow_mut();
        (
            normalized_sid(target_pid, inner.sid, inner.pgid),
            inner.sid != 0 && inner.sid == target_pid,
            inner.did_exec,
        )
    };

    if target_pid != cur_pid && target_did_exec {
        return EACCES;
    }
    if target_sid != cur_sid || target_is_session_leader {
        return EPERM;
    }

    if new_pgid != target_pid {
        let Some(group_leader) = pid2process(new_pgid) else {
            return EPERM;
        };
        let group_sid = {
            let inner = group_leader.borrow_mut();
            normalized_sid(new_pgid, inner.sid, inner.pgid)
        };
        if group_sid != target_sid {
            return EPERM;
        }
    }

    let mut inner = target.borrow_mut();
    inner.pgid = new_pgid;
    0
}

/// Linux `getpgid(2)` (syscall 155 on riscv64).
pub fn syscall_getpgid(pid: usize) -> isize {
    let cur = current_process();
    let cur_pid = cur.getpid();
    let target_pid = if pid == 0 { cur_pid } else { pid };
    if target_pid == cur_pid {
        let inner = cur.borrow_mut();
        return normalized_pgid(cur_pid, inner.pgid) as isize;
    }
    let Some(target) = pid2process(target_pid) else {
        return ESRCH;
    };
    let inner = target.borrow_mut();
    normalized_pgid(target_pid, inner.pgid) as isize
}

/// Linux `getsid(2)` (syscall 156 on riscv64).
pub fn syscall_getsid(pid: usize) -> isize {
    let cur = current_process();
    let cur_pid = cur.getpid();
    let target_pid = if pid == 0 { cur_pid } else { pid };
    if target_pid == cur_pid {
        let inner = cur.borrow_mut();
        return normalized_sid(cur_pid, inner.sid, inner.pgid) as isize;
    }
    let Some(target) = pid2process(target_pid) else {
        return ESRCH;
    };
    let inner = target.borrow_mut();
    normalized_sid(target_pid, inner.sid, inner.pgid) as isize
}

/// Linux `setsid(2)` (syscall 157 on riscv64).
///
/// Create a new session unless a process group with ID equal to caller PID
/// already exists.
pub fn syscall_setsid() -> isize {
    let process = current_process();
    let pid = process.getpid();
    {
        let map = PID2PCB.lock();
        for proc in map.values() {
            let inner = proc.borrow_mut();
            if normalized_pgid(proc.getpid(), inner.pgid) == pid {
                return EPERM;
            }
        }
    }
    let mut inner = process.borrow_mut();
    inner.sid = pid;
    inner.pgid = pid;
    pid as isize
}

const PRIO_PROCESS: isize = 0;
const PRIO_PGRP: isize = 1;
const PRIO_USER: isize = 2;

fn clamp_nice(prio: isize) -> i32 {
    prio.clamp(-20, 19) as i32
}

fn collect_priority_targets(
    which: isize,
    who: isize,
) -> Result<Vec<Arc<crate::task::ProcessControlBlock>>, isize> {
    let caller = current_process();
    let caller_pid = caller.getpid();
    let (caller_pgid, caller_uid) = {
        let inner = caller.borrow_mut();
        (normalized_pgid(caller_pid, inner.pgid), inner.uid)
    };

    if who < 0 {
        return Err(ESRCH);
    }

    match which {
        PRIO_PROCESS => {
            let target_pid = if who == 0 { caller_pid } else { who as usize };
            let Some(proc) = pid2process(target_pid) else {
                return Err(ESRCH);
            };
            let mut out = Vec::new();
            out.push(proc);
            Ok(out)
        }
        PRIO_PGRP => {
            let target_pgid = if who == 0 { caller_pgid } else { who as usize };
            let map = PID2PCB.lock();
            let mut out = Vec::new();
            for proc in map.values() {
                let pgid = {
                    let inner = proc.borrow_mut();
                    normalized_pgid(proc.getpid(), inner.pgid)
                };
                if pgid == target_pgid {
                    out.push(Arc::clone(proc));
                }
            }
            if out.is_empty() {
                return Err(ESRCH);
            }
            Ok(out)
        }
        PRIO_USER => {
            let target_uid = if who == 0 { caller_uid } else { who as u32 };
            let map = PID2PCB.lock();
            let mut out = Vec::new();
            for proc in map.values() {
                let uid = {
                    let inner = proc.borrow_mut();
                    inner.uid
                };
                if uid == target_uid {
                    out.push(Arc::clone(proc));
                }
            }
            if out.is_empty() {
                return Err(ESRCH);
            }
            Ok(out)
        }
        _ => Err(EINVAL),
    }
}

/// Linux `setpriority(2)` (syscall 140 on riscv64).
pub fn syscall_setpriority(which: isize, who: isize, prio: isize) -> isize {
    if which == PRIO_PROCESS && who == 0 {
        let new_nice = clamp_nice(prio);
        let caller = current_process();
        let caller_euid = {
            let inner = caller.borrow_mut();
            inner.euid
        };
        let task = current_task().unwrap();
        let (cur_nice, from_nice_wrapper) = {
            let mut inner = task.borrow_mut();
            let cur_nice = inner.nice;
            let from_nice_wrapper = inner.nice_query_hint;
            inner.nice_query_hint = false;
            (cur_nice, from_nice_wrapper)
        };
        if caller_euid != 0 && new_nice < cur_nice {
            // libc `nice()` is often emulated by getpriority()+setpriority().
            // Linux reports EPERM for nice(-N), while plain setpriority() keeps EACCES.
            return if from_nice_wrapper { EPERM } else { EACCES };
        }
        {
            let mut inner = task.borrow_mut();
            inner.nice = new_nice;
        }
        // Keep process-level default nice in sync for newly created threads.
        caller.borrow_mut().nice = new_nice;
        refresh_process_runqueues(&caller);
        return 0;
    }

    if let Some(task) = current_task() {
        task.borrow_mut().nice_query_hint = false;
    }

    let targets = match collect_priority_targets(which, who) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_nice = clamp_nice(prio);
    let caller = current_process();
    let (caller_uid, caller_euid) = {
        let inner = caller.borrow_mut();
        (inner.uid, inner.euid)
    };

    if caller_euid != 0 {
        for proc in targets.iter() {
            let (uid, cur_nice) = {
                let inner = proc.borrow_mut();
                (inner.uid, inner.nice)
            };
            if uid != caller_uid && uid != caller_euid {
                return EPERM;
            }
            if new_nice < cur_nice {
                return EACCES;
            }
        }
    }

    for proc in targets {
        let mut inner = proc.borrow_mut();
        inner.nice = new_nice;
        drop(inner);
        refresh_process_runqueues(&proc);
    }
    0
}

/// Linux `getpriority(2)` (syscall 141 on riscv64).
///
/// Return kernel-internal encoded value (1..40); libc converts it back to
/// user-visible nice range (-20..19).
pub fn syscall_getpriority(which: isize, who: isize) -> isize {
    if which == PRIO_PROCESS && who == 0 {
        let task = current_task().unwrap();
        let nice = {
            let mut inner = task.borrow_mut();
            inner.nice_query_hint = true;
            inner.nice
        };
        return (20 - nice as isize) as isize;
    }

    let targets = match collect_priority_targets(which, who) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut best = 19i32;
    for proc in targets {
        let nice = {
            let inner = proc.borrow_mut();
            inner.nice
        };
        if nice < best {
            best = nice;
        }
    }
    (20 - best as isize) as isize
}

/// Linux `set_tid_address(2)` (syscall 96 on riscv64).
///
/// We currently run a single-threaded process model for glibc apps; we accept the
/// pointer and return a Linux-like TID (use PID as TID).
pub fn syscall_set_tid_address(_tidptr: usize) -> isize {
    let task = current_task().unwrap();
    let tid_index = {
        let mut inner = task.borrow_mut();
        if _tidptr != 0 {
            inner.clear_child_tid = Some(_tidptr);
        }
        inner.res.as_ref().unwrap().tid
    };
    if DEBUG_PTHREAD {
        log::debug!(
            "[set_tid_address] tidptr={:#x} tid_index={}",
            _tidptr,
            tid_index
        );
    }
    encode_linux_tid(current_process().getpid(), tid_index) as isize
}

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
        return EINVAL;
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
        return EINVAL;
    }
    let token = get_current_token();
    for (idx, gid) in groups.iter().enumerate() {
        let dst = (list + idx * size_of::<u32>()) as *mut u32;
        if try_write_user_value(token, dst, gid).is_err() {
            return EFAULT;
        }
    }
    ngroups as isize
}

/// Linux `setgroups(2)` (syscall 159 on riscv64).
pub fn syscall_setgroups(size: usize, list: usize) -> isize {
    if size > NGROUPS_MAX {
        return EINVAL;
    }
    {
        let process = current_process();
        let inner = process.borrow_mut();
        if inner.euid != 0 {
            return EPERM;
        }
    }
    let token = get_current_token();
    let mut groups = Vec::with_capacity(size);
    for idx in 0..size {
        let src = (list + idx * size_of::<u32>()) as *const u32;
        let Some(gid) = try_read_user_value(token, src) else {
            return EFAULT;
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
    EPERM
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
    EPERM
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
                return EPERM;
            }
        }
        if let Some(e) = new_euid {
            if !uid_allowed(e, old_ruid, old_euid, old_suid) {
                return EPERM;
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
                return EPERM;
            }
        }
        if let Some(e) = new_egid {
            if !gid_allowed(e, old_rgid, old_egid, old_sgid) {
                return EPERM;
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
                    return EPERM;
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
                    return EPERM;
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
        return EFAULT;
    }
    if euid != 0 && try_write_user_value(token, euid as *mut u32, &euid_v).is_err() {
        return EFAULT;
    }
    if suid != 0 && try_write_user_value(token, suid as *mut u32, &suid_v).is_err() {
        return EFAULT;
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
        return EFAULT;
    }
    if egid != 0 && try_write_user_value(token, egid as *mut u32, &egid_v).is_err() {
        return EFAULT;
    }
    if sgid != 0 && try_write_user_value(token, sgid as *mut u32, &sgid_v).is_err() {
        return EFAULT;
    }
    0
}

/// Linux `gettid(2)` (syscall 178 on riscv64).
pub fn syscall_gettid_linux() -> isize {
    current_linux_tid() as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RUsageTimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RUsage64 {
    ru_utime: RUsageTimeVal,
    ru_stime: RUsageTimeVal,
    ru_maxrss: i64,
    ru_ixrss: i64,
    ru_idrss: i64,
    ru_isrss: i64,
    ru_minflt: i64,
    ru_majflt: i64,
    ru_nswap: i64,
    ru_inblock: i64,
    ru_oublock: i64,
    ru_msgsnd: i64,
    ru_msgrcv: i64,
    ru_nsignals: i64,
    ru_nvcsw: i64,
    ru_nivcsw: i64,
}

fn ms_to_rusage_timeval(ms: usize) -> RUsageTimeVal {
    RUsageTimeVal {
        tv_sec: (ms / 1000) as i64,
        tv_usec: ((ms % 1000) * 1000) as i64,
    }
}

/// Linux `getrusage(2)` (syscall 165 on riscv64).
///
/// Provide basic accounting for current process/thread elapsed wall time.
pub fn syscall_getrusage(who: isize, usage: usize) -> isize {
    const RUSAGE_SELF: isize = 0;
    const RUSAGE_CHILDREN: isize = -1;
    const RUSAGE_THREAD: isize = 1;

    if usage == 0 {
        return EFAULT;
    }

    let now_ms = get_time_ms();
    let (utime, stime) = match who {
        RUSAGE_SELF | RUSAGE_THREAD => {
            let process = current_process();
            let start_ms = process.borrow_mut().start_time_ms;
            (
                ms_to_rusage_timeval(now_ms.saturating_sub(start_ms)),
                ms_to_rusage_timeval(0),
            )
        }
        RUSAGE_CHILDREN => (ms_to_rusage_timeval(0), ms_to_rusage_timeval(0)),
        _ => return EINVAL,
    };

    let ru = RUsage64 {
        ru_utime: utime,
        ru_stime: stime,
        ru_maxrss: 0,
        ru_ixrss: 0,
        ru_idrss: 0,
        ru_isrss: 0,
        ru_minflt: 0,
        ru_majflt: 0,
        ru_nswap: 0,
        ru_inblock: 0,
        ru_oublock: 0,
        ru_msgsnd: 0,
        ru_msgrcv: 0,
        ru_nsignals: 0,
        ru_nvcsw: 0,
        ru_nivcsw: 0,
    };
    let token = get_current_token();
    if try_write_user_value(token, usage as *mut RUsage64, &ru).is_err() {
        return EFAULT;
    }
    0
}

/// Linux `set_robust_list(2)` (syscall 99 on riscv64).
///
/// glibc uses this for mutex robustness; we store the head pointer for
/// best-effort cleanup on thread exit.
pub fn syscall_set_robust_list(_head: usize, _len: usize) -> isize {
    if _len != ROBUST_LIST_HEAD_LEN {
        return EINVAL;
    }
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    inner.robust_list_head = _head;
    inner.robust_list_len = _len;
    0
}

/// Linux `get_robust_list(2)` (syscall 100 on riscv64).
///
/// We only support querying the current thread (pid=0).
pub fn syscall_get_robust_list(pid: usize, head_ptr: usize, len_ptr: usize) -> isize {
    if head_ptr == 0 || len_ptr == 0 {
        return EFAULT;
    }
    let caller = current_process();
    let caller_pid = caller.getpid();
    let caller_euid = {
        let inner = caller.borrow_mut();
        inner.euid
    };

    let task = if pid == 0 {
        current_task().unwrap()
    } else {
        // Linux permits querying self, but querying another task without
        // privilege should fail with EPERM.
        if caller_euid != 0 && pid != caller_pid {
            return EPERM;
        }
        let Some(target_proc) = pid2process(pid) else {
            return ESRCH;
        };
        let inner = target_proc.borrow_mut();
        let Some(task) = inner.tasks.first().and_then(|t| t.as_ref()).cloned() else {
            return ESRCH;
        };
        task
    };

    let (robust_head, robust_len) = {
        let inner = task.borrow_mut();
        (inner.robust_list_head, inner.robust_list_len)
    };
    let token = get_current_token();
    if try_write_user_value(token, head_ptr as *mut usize, &robust_head).is_err() {
        return EFAULT;
    }
    if try_write_user_value(token, len_ptr as *mut usize, &robust_len).is_err() {
        return EFAULT;
    }
    0
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

const RLIM_INFINITY: u64 = u64::MAX;
const RLIMIT_CPU: usize = 0;
const RLIMIT_FSIZE: usize = 1;
const RLIMIT_DATA: usize = 2;
const RLIMIT_STACK: usize = 3;
const RLIMIT_CORE: usize = 4;
const RLIMIT_RSS: usize = 5;
const RLIMIT_NPROC: usize = 6;
const RLIMIT_NOFILE: usize = 7;
const RLIMIT_MEMLOCK: usize = 8;
const RLIMIT_AS: usize = 9;
const RLIMIT_LOCKS: usize = 10;
const RLIMIT_SIGPENDING: usize = 11;
const RLIMIT_MSGQUEUE: usize = 12;
const RLIMIT_NICE: usize = 13;
const RLIMIT_RTPRIO: usize = 14;
const RLIMIT_RTTIME: usize = 15;
const FS_NR_OPEN: u64 = 1024 * 1024;

fn rlimit_for_resource(
    process: &Arc<crate::task::ProcessControlBlock>,
    resource: usize,
) -> Option<(u64, u64)> {
    let inner = process.borrow_mut();
    match resource {
        RLIMIT_CPU => Some((inner.rlimit_cpu_cur, inner.rlimit_cpu_max)),
        RLIMIT_FSIZE => Some((inner.rlimit_fsize_cur, inner.rlimit_fsize_max)),
        RLIMIT_DATA => Some((inner.rlimit_data_cur, inner.rlimit_data_max)),
        RLIMIT_STACK => Some((inner.rlimit_stack_cur, inner.rlimit_stack_max)),
        RLIMIT_CORE => Some((inner.rlimit_core_cur, inner.rlimit_core_max)),
        RLIMIT_RSS => Some((inner.rlimit_rss_cur, inner.rlimit_rss_max)),
        RLIMIT_NPROC => Some((inner.rlimit_nproc_cur, inner.rlimit_nproc_max)),
        RLIMIT_NOFILE => Some((inner.rlimit_nofile_cur, inner.rlimit_nofile_max)),
        RLIMIT_MEMLOCK => Some((inner.rlimit_memlock_cur, inner.rlimit_memlock_max)),
        RLIMIT_AS => Some((inner.rlimit_as_cur, inner.rlimit_as_max)),
        RLIMIT_LOCKS => Some((inner.rlimit_locks_cur, inner.rlimit_locks_max)),
        RLIMIT_SIGPENDING => Some((inner.rlimit_sigpending_cur, inner.rlimit_sigpending_max)),
        RLIMIT_MSGQUEUE => Some((inner.rlimit_msgqueue_cur, inner.rlimit_msgqueue_max)),
        RLIMIT_NICE => Some((inner.rlimit_nice_cur, inner.rlimit_nice_max)),
        RLIMIT_RTPRIO => Some((inner.rlimit_rtprio_cur, inner.rlimit_rtprio_max)),
        RLIMIT_RTTIME => Some((inner.rlimit_rttime_cur, inner.rlimit_rttime_max)),
        _ => None,
    }
}

fn apply_rlimit_to_resource(
    process: &Arc<crate::task::ProcessControlBlock>,
    resource: usize,
    new: RLimit64,
) -> isize {
    let mut inner = process.borrow_mut();
    match resource {
        RLIMIT_CPU => {
            inner.rlimit_cpu_cur = new.rlim_cur;
            inner.rlimit_cpu_max = new.rlim_max;
            inner.rlimit_cpu_start_ms = get_time_ms();
            inner.rlimit_cpu_soft_sent = false;
        }
        RLIMIT_FSIZE => {
            inner.rlimit_fsize_cur = new.rlim_cur;
            inner.rlimit_fsize_max = new.rlim_max;
        }
        RLIMIT_DATA => {
            inner.rlimit_data_cur = new.rlim_cur;
            inner.rlimit_data_max = new.rlim_max;
        }
        RLIMIT_STACK => {
            inner.rlimit_stack_cur = new.rlim_cur;
            inner.rlimit_stack_max = new.rlim_max;
        }
        RLIMIT_CORE => {
            inner.rlimit_core_cur = new.rlim_cur;
            inner.rlimit_core_max = new.rlim_max;
        }
        RLIMIT_RSS => {
            inner.rlimit_rss_cur = new.rlim_cur;
            inner.rlimit_rss_max = new.rlim_max;
        }
        RLIMIT_NPROC => {
            inner.rlimit_nproc_cur = new.rlim_cur;
            inner.rlimit_nproc_max = new.rlim_max;
        }
        RLIMIT_NOFILE => {
            inner.rlimit_nofile_cur = new.rlim_cur;
            inner.rlimit_nofile_max = new.rlim_max;
        }
        RLIMIT_MEMLOCK => {
            inner.rlimit_memlock_cur = new.rlim_cur;
            inner.rlimit_memlock_max = new.rlim_max;
        }
        RLIMIT_AS => {
            inner.rlimit_as_cur = new.rlim_cur;
            inner.rlimit_as_max = new.rlim_max;
        }
        RLIMIT_LOCKS => {
            inner.rlimit_locks_cur = new.rlim_cur;
            inner.rlimit_locks_max = new.rlim_max;
        }
        RLIMIT_SIGPENDING => {
            inner.rlimit_sigpending_cur = new.rlim_cur;
            inner.rlimit_sigpending_max = new.rlim_max;
        }
        RLIMIT_MSGQUEUE => {
            inner.rlimit_msgqueue_cur = new.rlim_cur;
            inner.rlimit_msgqueue_max = new.rlim_max;
        }
        RLIMIT_NICE => {
            inner.rlimit_nice_cur = new.rlim_cur;
            inner.rlimit_nice_max = new.rlim_max;
        }
        RLIMIT_RTPRIO => {
            inner.rlimit_rtprio_cur = new.rlim_cur;
            inner.rlimit_rtprio_max = new.rlim_max;
        }
        RLIMIT_RTTIME => {
            inner.rlimit_rttime_cur = new.rlim_cur;
            inner.rlimit_rttime_max = new.rlim_max;
        }
        _ => return EINVAL,
    }
    0
}

fn set_rlimit_checked(
    process: &Arc<crate::task::ProcessControlBlock>,
    resource: usize,
    new: RLimit64,
    caller_euid: u32,
) -> isize {
    if new.rlim_cur > new.rlim_max {
        return EINVAL;
    }
    let Some((_, old_max)) = rlimit_for_resource(process, resource) else {
        return EINVAL;
    };
    if caller_euid != 0 && new.rlim_max > old_max {
        return EPERM;
    }
    if resource == RLIMIT_NOFILE && new.rlim_max > FS_NR_OPEN {
        return EPERM;
    }
    if resource == RLIMIT_NOFILE && new.rlim_cur > FS_NR_OPEN {
        return EINVAL;
    }
    apply_rlimit_to_resource(process, resource, new)
}

/// Linux `prlimit64(2)` (syscall 261 on riscv64).
///
/// Provide a permissive "unlimited" answer for common queries (e.g. RLIMIT_STACK).
pub fn syscall_prlimit64(pid: usize, resource: usize, new_limit: usize, old_limit: usize) -> isize {
    let caller = current_process();
    let caller_pid = caller.getpid();
    let caller_euid = {
        let inner = caller.borrow_mut();
        inner.euid
    };

    let target = if pid == 0 || pid == caller_pid {
        caller.clone()
    } else {
        if caller_euid != 0 {
            return EPERM;
        }
        let Some(p) = pid2process(pid) else {
            return ESRCH;
        };
        p
    };

    if new_limit != 0 {
        let token = get_current_token();
        let Some(new) = try_read_user_value(token, new_limit as *const RLimit64) else {
            return EFAULT;
        };
        let ret = set_rlimit_checked(&target, resource, new, caller_euid);
        if ret != 0 {
            return ret;
        }
    }
    if old_limit != 0 {
        let Some((rlim_cur, rlim_max)) = rlimit_for_resource(&target, resource) else {
            return EINVAL;
        };
        let token = get_current_token();
        let rl = RLimit64 { rlim_cur, rlim_max };
        if try_write_user_value(token, old_limit as *mut RLimit64, &rl).is_err() {
            return EFAULT;
        }
    }
    0
}

/// Linux `getrlimit(2)` (syscall 163 on riscv64).
pub fn syscall_getrlimit(resource: usize, rlim: usize) -> isize {
    if rlim == 0 {
        return EFAULT;
    }
    let process = current_process();
    let Some((rlim_cur, rlim_max)) = rlimit_for_resource(&process, resource) else {
        return EINVAL;
    };
    let token = get_current_token();
    let rl = RLimit64 { rlim_cur, rlim_max };
    if try_write_user_value(token, rlim as *mut RLimit64, &rl).is_err() {
        return EFAULT;
    }
    0
}

/// Linux `setrlimit(2)` (syscall 164 on riscv64).
pub fn syscall_setrlimit(resource: usize, rlim: usize) -> isize {
    if rlim == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let Some(new) = try_read_user_value(token, rlim as *const RLimit64) else {
        return EFAULT;
    };
    let process = current_process();
    let caller_euid = {
        let inner = process.borrow_mut();
        inner.euid
    };
    set_rlimit_checked(&process, resource, new, caller_euid)
}

/// Approximate RLIMIT_CPU accounting using timer ticks.
///
/// LTP setrlimit06 spins in userspace; checking on every timer interrupt is
/// sufficient to emulate Linux behavior (SIGXCPU then SIGKILL).
pub fn check_current_rlimit_cpu() {
    let process = current_process();
    let pid = process.getpid();
    let now_ms = get_time_ms();

    let mut send_soft = false;
    let mut send_hard = false;
    {
        let mut inner = process.borrow_mut();
        let soft = inner.rlimit_cpu_cur;
        let hard = inner.rlimit_cpu_max;
        if soft == RLIM_INFINITY && hard == RLIM_INFINITY {
            return;
        }
        let elapsed_sec = (now_ms.saturating_sub(inner.rlimit_cpu_start_ms) / 1000) as u64;
        if soft != RLIM_INFINITY && elapsed_sec >= soft && !inner.rlimit_cpu_soft_sent {
            inner.rlimit_cpu_soft_sent = true;
            send_soft = true;
        } else if hard != RLIM_INFINITY && elapsed_sec >= hard {
            if soft != RLIM_INFINITY && !inner.rlimit_cpu_soft_sent {
                // If we reached hard limit before ever observing soft limit, queue
                // SIGXCPU first and let the next tick deliver SIGKILL.
                inner.rlimit_cpu_soft_sent = true;
                send_soft = true;
            } else {
                send_hard = true;
            }
        }
    }
    if send_soft {
        queue_process_signal(pid, SIGXCPU_NUM);
    }
    if send_hard {
        queue_process_signal(pid, SIGKILL_NUM);
    }
}

/// Linux `getrandom(2)` (syscall 278 on riscv64).
///
/// Fill the buffer with a simple xorshift PRNG seeded from time and pid/tid.
pub fn syscall_getrandom(buf: usize, len: usize, _flags: u32) -> isize {
    const GRND_NONBLOCK: u32 = 0x0001;
    const GRND_RANDOM: u32 = 0x0002;

    if (_flags & !(GRND_NONBLOCK | GRND_RANDOM)) != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if buf == 0 {
        return EFAULT;
    }

    let token = get_current_token();
    let mut seed = (get_time() as u64)
        ^ ((current_process().getpid() as u64) << 32)
        ^ (current_linux_tid() as u64);
    for i in 0..len {
        // xorshift64*
        let mut x = seed;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x = x.wrapping_mul(0x2545F4914F6CDD1D);
        seed = x;
        let byte = (x & 0xff) as u8;
        if try_write_user_value(token, (buf + i) as *mut u8, &byte).is_err() {
            return EFAULT;
        }
    }
    len as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PollTimeSpec {
    sec: i64,
    nsec: i64,
}

const NSEC_PER_SEC: u64 = 1_000_000_000;

fn ppoll_now_ns() -> u64 {
    (get_time() as u64)
        .saturating_mul(NSEC_PER_SEC)
        .saturating_div(clock_freq() as u64)
}

fn ppoll_timespec_to_ns(ts: PollTimeSpec) -> Option<u64> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= NSEC_PER_SEC as i64 {
        return None;
    }
    Some(
        (ts.sec as u64)
            .saturating_mul(NSEC_PER_SEC)
            .saturating_add(ts.nsec as u64),
    )
}

fn ppoll_write_back(token: usize, fds_ptr: usize, pfds: &[PollFd]) -> Result<(), isize> {
    for (i, pfd) in pfds.iter().enumerate() {
        let pfd_ptr = (fds_ptr + i * size_of::<PollFd>()) as *mut PollFd;
        if try_write_user_value(token, pfd_ptr, pfd).is_err() {
            return Err(EFAULT);
        }
    }
    Ok(())
}

/// Linux `ppoll(2)` (syscall 73 on riscv64).
///
/// Minimal readiness reporting for shells (busybox/ash) and glibc helpers.
/// We conservatively mark fds as ready if they are readable/writable.
pub fn syscall_ppoll(
    fds_ptr: usize,
    nfds: usize,
    _tmo_p: usize,
    _sigmask: usize,
    _sigsetsize: usize,
) -> isize {
    const POLLIN: i16 = 0x0001;
    const POLLOUT: i16 = 0x0004;
    const POLLNVAL: i16 = 0x0020;
    const EINTR: isize = -4;
    if (nfds as isize) < 0 {
        return EINVAL;
    }
    if nfds > i32::MAX as usize {
        return EINVAL;
    }
    if nfds > 0 && fds_ptr == 0 {
        return EFAULT;
    }

    let token = get_current_token();
    let process = current_files_process();
    let deadline_ns = if _tmo_p == 0 {
        None
    } else {
        let Some(ts) = try_read_user_value::<PollTimeSpec>(token, _tmo_p as *const PollTimeSpec)
        else {
            return EFAULT;
        };
        let Some(delta_ns) = ppoll_timespec_to_ns(ts) else {
            return EINVAL;
        };
        Some(ppoll_now_ns().saturating_add(delta_ns))
    };

    let task = current_task().unwrap();
    let mut restore_mask = None;
    if _sigmask != 0 {
        if _sigsetsize < size_of::<u64>() {
            return EINVAL;
        }
        let Some(mut new_mask) = try_read_user_value::<u64>(token, _sigmask as *const u64) else {
            return EFAULT;
        };
        let sigkill_bit = signal_bit(SIGKILL_NUM).unwrap_or(0);
        let sigstop_bit = signal_bit(SIGSTOP_NUM).unwrap_or(0);
        new_mask &= !(sigkill_bit | sigstop_bit);
        let old_mask = {
            let mut inner = task.borrow_mut();
            let old = inner.signal_mask;
            inner.signal_mask = new_mask;
            old
        };
        restore_mask = Some(old_mask);
    }

    let mut pfds = Vec::with_capacity(nfds);
    for i in 0..nfds {
        let pfd_ptr = (fds_ptr + i * size_of::<PollFd>()) as *const PollFd;
        let Some(mut pfd) = try_read_user_value::<PollFd>(token, pfd_ptr) else {
            if let Some(old_mask) = restore_mask {
                let mut inner = task.borrow_mut();
                inner.signal_mask = old_mask;
            }
            return EFAULT;
        };
        pfd.revents = 0;
        pfds.push(pfd);
    }

    let ret = loop {
        let (pending, mask) = {
            let inner = task.borrow_mut();
            (inner.pending_signals, inner.signal_mask)
        };
        if has_unmasked_pending(pending, mask, false) {
            break EINTR;
        }

        let mut ready = 0isize;
        for pfd in pfds.iter_mut() {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            let fd = pfd.fd as usize;
            let file = {
                let inner = process.borrow_mut();
                if fd >= inner.fd_table.len() {
                    None
                } else {
                    inner.fd_table[fd].clone()
                }
            };
            let Some(file) = file else {
                pfd.revents = POLLNVAL;
                ready += 1;
                continue;
            };

            let mut revents: i16 = 0;
            let (readable, writable) = crate::syscall::net::poll_file_read_write(&file);
            if (pfd.events & POLLIN) != 0 && readable {
                revents |= POLLIN;
            }
            if (pfd.events & POLLOUT) != 0 && writable {
                revents |= POLLOUT;
            }
            pfd.revents = revents;
            if revents != 0 {
                ready += 1;
            }
        }

        if ready != 0 {
            break ready;
        }
        if let Some(deadline) = deadline_ns {
            let now = ppoll_now_ns();
            if now >= deadline {
                break 0;
            }
            if nfds == 0 {
                let remain_ns = deadline.saturating_sub(now);
                let mut sleep_ms = ((remain_ns.saturating_add(999_999)) / 1_000_000) as usize;
                if sleep_ms == 0 {
                    sleep_ms = 1;
                }
                let r = crate::syscall::thread::sys_sleep(sleep_ms);
                if r == EINTR {
                    break EINTR;
                }
            } else {
                crate::task::processor::suspend_current_and_run_next();
            }
        } else if nfds == 0 {
            block_current_and_run_next();
        } else {
            crate::task::processor::suspend_current_and_run_next();
        }
    };

    if ret >= 0 || ret == EINTR {
        if ppoll_write_back(token, fds_ptr, &pfds).is_err() {
            if let Some(old_mask) = restore_mask {
                let mut inner = task.borrow_mut();
                inner.signal_mask = old_mask;
            }
            return EFAULT;
        }
    }

    if let Some(old_mask) = restore_mask {
        let mut inner = task.borrow_mut();
        inner.signal_mask = old_mask;
    }

    ret
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

/// Linux `ioctl(2)` (syscall 29 on riscv64).
///
/// We don't model TTYs yet; return `ENOTTY` for most requests to avoid `ENOSYS`
/// aborts in busybox/glibc helpers.
pub fn syscall_ioctl(fd: usize, _request: usize, _argp: usize) -> isize {
    const EBADF: isize = -9;
    const ENOTTY: isize = -25;
    const EFAULT: isize = -14;
    const FIONREAD: usize = 0x541B;
    const BLKGETSIZE: usize = 0x1260;
    const BLKSSZGET: usize = 0x1268;
    const BLKGETSIZE64: usize = 0x8008_1272;
    // Some libc builds issue BLKGETSIZE64 with a 32-bit size encoding.
    const BLKGETSIZE64_COMPAT: usize = 0x8004_1272;
    const BLKPBSZGET: usize = 0x127b;
    const FS_IOC_GETFLAGS: usize = 0x8008_6601;
    const FS_IOC_SETFLAGS: usize = 0x4008_6602;
    const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
    const FS_APPEND_FL: u32 = 0x0000_0020;
    const FS_NODUMP_FL: u32 = 0x0000_0040;
    const SIOCATMARK: usize = 0x8905;
    const SIOCGIFCONF: usize = 0x8912;
    const SIOCGIFFLAGS: usize = 0x8913;
    const SIOCSIFFLAGS: usize = 0x8914;
    const IFF_UP: i16 = 0x1;
    const IFF_LOOPBACK: i16 = 0x8;
    const IFF_RUNNING: i16 = 0x40;
    const AF_INET: u16 = 2;
    const PSEUDO_ROOT_DEV_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
    const PSEUDO_ROOT_DEV_SECTOR_SIZE: u32 = 512;
    const PSEUDO_ROOT_DEV_PHYS_BLOCK_SIZE: u32 = 4096;

    let process = current_files_process();
    let file = {
        let inner = process.borrow_mut();
        if fd >= inner.fd_table.len() {
            None
        } else {
            inner.fd_table[fd].clone()
        }
    };
    let Some(file) = file else {
        return EBADF;
    };
    // Some libcs pass ioctl request as signed int (sign-extended on rv64).
    // Compare on low 32 bits to accept both calling conventions.
    let request = _request & 0xffff_ffffusize;
    let token = get_current_token();

    if request == FIONREAD {
        if _argp == 0 {
            return EFAULT;
        }
        if let Some(pipe) = file.as_any().downcast_ref::<crate::fs::Pipe>() {
            // Linux reports unread bytes for both read and write pipe fds.
            let readable = pipe.queued_bytes() as i32;
            if try_write_user_value(token, _argp as *mut i32, &readable).is_err() {
                return EFAULT;
            }
            return 0;
        }
    }

    if let Some(os_inode) = file.as_any().downcast_ref::<crate::fs::OSInode>() {
        let ino = os_inode.ext4_inode().inode_num() as u64;
        match request {
            FS_IOC_GETFLAGS => {
                if _argp == 0 {
                    return EFAULT;
                }
                let flags = crate::syscall::filesystem::inode_fs_flags(ino) as i32;
                if try_write_user_value(token, _argp as *mut i32, &flags).is_err() {
                    return EFAULT;
                }
                return 0;
            }
            FS_IOC_SETFLAGS => {
                if _argp == 0 {
                    return EFAULT;
                }
                let Some(raw_flags) = try_read_user_value(token, _argp as *const i32) else {
                    return EFAULT;
                };
                let allowed = (raw_flags as u32) & (FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL);
                crate::syscall::filesystem::set_inode_fs_flags(ino, allowed);
                return 0;
            }
            _ => {}
        }
    }

    if let Some(sock) = file.as_any().downcast_ref::<crate::fs::NetSocketFile>() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Ifconf {
            ifc_len: i32,
            _pad: i32,
            ifc_buf: usize,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct SockAddr {
            sa_family: u16,
            sa_data: [u8; 14],
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct IfreqAddr {
            ifr_name: [u8; 16],
            ifr_addr: SockAddr,
        }

        return match request {
            SIOCATMARK => {
                if _argp == 0 {
                    EFAULT
                } else if sock.kind() == crate::fs::NetSocketKind::Udp {
                    ENOTTY
                } else if try_write_user_value(token, _argp as *mut i32, &0i32).is_err() {
                    EFAULT
                } else {
                    0
                }
            }
            SIOCGIFCONF => {
                if _argp == 0 {
                    return EFAULT;
                }
                let Some(mut ifc) = try_read_user_value(token, _argp as *const Ifconf) else {
                    return EFAULT;
                };
                if ifc.ifc_buf == 0 {
                    return EFAULT;
                }
                let mut ifr_name = [0u8; 16];
                ifr_name[0] = b'l';
                ifr_name[1] = b'o';
                let mut sa_data = [0u8; 14];
                sa_data[2] = 127;
                sa_data[5] = 1;
                let ifr = IfreqAddr {
                    ifr_name,
                    ifr_addr: SockAddr {
                        sa_family: AF_INET,
                        sa_data,
                    },
                };
                if (ifc.ifc_len as usize) >= size_of::<IfreqAddr>() {
                    if try_write_user_value(token, ifc.ifc_buf as *mut IfreqAddr, &ifr).is_err() {
                        return EFAULT;
                    }
                    ifc.ifc_len = size_of::<IfreqAddr>() as i32;
                } else {
                    ifc.ifc_len = 0;
                }
                if try_write_user_value(token, _argp as *mut Ifconf, &ifc).is_err() {
                    return EFAULT;
                }
                0
            }
            SIOCGIFFLAGS => {
                if _argp == 0 {
                    EFAULT
                } else {
                    let flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
                    if try_write_user_value(token, (_argp + 16) as *mut i16, &flags).is_err() {
                        EFAULT
                    } else {
                        0
                    }
                }
            }
            SIOCSIFFLAGS => {
                if _argp == 0 {
                    EFAULT
                } else {
                    0
                }
            }
            _ => ENOTTY,
        };
    }

    // Minimal block-device ioctls so LTP can use /dev/root as LTP_DEV.
    if file
        .as_any()
        .downcast_ref::<crate::fs::PseudoBlock>()
        .is_some()
    {
        if _argp == 0 {
            return EFAULT;
        }
        match request {
            BLKGETSIZE64 | BLKGETSIZE64_COMPAT => {
                if try_write_user_value(token, _argp as *mut u64, &PSEUDO_ROOT_DEV_BYTES).is_err() {
                    return EFAULT;
                }
                return 0;
            }
            BLKGETSIZE => {
                let sectors: usize =
                    (PSEUDO_ROOT_DEV_BYTES / PSEUDO_ROOT_DEV_SECTOR_SIZE as u64) as usize;
                if try_write_user_value(token, _argp as *mut usize, &sectors).is_err() {
                    return EFAULT;
                }
                return 0;
            }
            BLKSSZGET => {
                if try_write_user_value(token, _argp as *mut u32, &PSEUDO_ROOT_DEV_SECTOR_SIZE)
                    .is_err()
                {
                    return EFAULT;
                }
                return 0;
            }
            BLKPBSZGET => {
                if try_write_user_value(token, _argp as *mut u32, &PSEUDO_ROOT_DEV_PHYS_BLOCK_SIZE)
                    .is_err()
                {
                    return EFAULT;
                }
                return 0;
            }
            _ => return ENOTTY,
        }
    }

    // Best-effort support for `/dev/misc/rtc` (busybox `hwclock`).
    if file.as_any().downcast_ref::<crate::fs::RtcFile>().is_some() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct RtcTime {
            tm_sec: i32,
            tm_min: i32,
            tm_hour: i32,
            tm_mday: i32,
            tm_mon: i32,
            tm_year: i32,
            tm_wday: i32,
            tm_yday: i32,
            tm_isdst: i32,
        }

        if _argp != 0 {
            let secs = (crate::time::get_time_ms() / 1000) as i64;
            let tm_sec = (secs % 60) as i32;
            let tm_min = ((secs / 60) % 60) as i32;
            let tm_hour = ((secs / 3600) % 24) as i32;
            let tm_mday = 1 + (secs / 86400) as i32;
            let rt = RtcTime {
                tm_sec,
                tm_min,
                tm_hour,
                tm_mday,
                tm_mon: 0,
                tm_year: 70,
                tm_wday: 4,
                tm_yday: 0,
                tm_isdst: 0,
            };
            let token = get_current_token();
            write_user_value(token, _argp as *mut RtcTime, &rt);
        }
        return 0;
    }

    ENOTTY
}

/// Linux `syslog(2)` / `klogctl(2)` (syscall 116 on riscv64).
///
/// Busybox `dmesg` calls this. We don't maintain a kernel log buffer for userspace;
/// return success and (for read requests) an empty buffer.
pub fn syscall_syslog(_type: usize, bufp: usize, len: usize) -> isize {
    const EINVAL: isize = -22;

    // `klogctl` actions (Linux uapi).
    const SYSLOG_ACTION_READ: usize = 2;
    const SYSLOG_ACTION_READ_ALL: usize = 3;
    const SYSLOG_ACTION_READ_CLEAR: usize = 4;
    const SYSLOG_ACTION_CLEAR: usize = 5;
    const SYSLOG_ACTION_SIZE_BUFFER: usize = 10;
    const SYSLOG_ACTION_SIZE_UNREAD: usize = 11;

    match _type {
        SYSLOG_ACTION_SIZE_BUFFER => return crate::klog::capacity() as isize,
        SYSLOG_ACTION_SIZE_UNREAD => return crate::klog::len() as isize,
        SYSLOG_ACTION_CLEAR => {
            crate::klog::clear();
            return 0;
        }
        _ => {}
    }

    if bufp == 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }

    let data = match _type {
        SYSLOG_ACTION_READ | SYSLOG_ACTION_READ_ALL => crate::klog::snapshot(len),
        SYSLOG_ACTION_READ_CLEAR => crate::klog::snapshot_and_clear(len),
        _ => return EINVAL,
    };

    let token = get_current_token();
    let bufs = translated_byte_buffer(token, bufp as *mut u8, len, MapPermission::W);
    let mut off = 0usize;
    for b in bufs {
        if off >= data.len() {
            break;
        }
        let n = core::cmp::min(b.len(), data.len() - off);
        b[..n].copy_from_slice(&data[off..off + n]);
        off += n;
        if n < b.len() {
            break;
        }
    }
    data.len() as isize
}
