use crate::{
    arch,
    debug_config::DEBUG_PTHREAD,
    fs::ext4_lock,
    mm::{
        MapPermission, read_user_value, translated_byte_buffer, translated_str,
        try_write_user_value, write_user_value,
    },
    syscall::{
        filesystem::{normalize_path, register_rofs_mount, unregister_rofs_mount},
        robust_list::ROBUST_LIST_HEAD_LEN,
    },
    task::processor::{current_process, current_task},
    time::get_time,
    trap::get_current_token,
};
use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};

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

static UMASK: AtomicUsize = AtomicUsize::new(0);

const EPERM: isize = -1;
const EFAULT: isize = -14;
const ENOENT: isize = -2;
const ENODEV: isize = -19;
const ENOTDIR: isize = -20;

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

fn write_cstr(dst: &mut [u8; 65], s: &str) {
    dst.fill(0);
    let bytes = s.as_bytes();
    let n = bytes.len().min(64);
    dst[..n].copy_from_slice(&bytes[..n]);
}

pub fn syscall_uname(buf: usize) -> isize {
    if buf == 0 {
        return -1;
    }
    let mut un = UtsName {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    write_cstr(&mut un.sysname, "CongCore");
    write_cstr(&mut un.nodename, "localhost");
    // glibc/busybox may abort early if the reported kernel release is "too old".
    // Report a modern Linux-like release string for compatibility.
    write_cstr(&mut un.release, "5.15.0");
    write_cstr(&mut un.version, "CongCore");
    let machine = if cfg!(target_arch = "loongarch64") {
        "loongarch64"
    } else {
        "riscv64"
    };
    write_cstr(&mut un.machine, machine);
    write_cstr(&mut un.domainname, "localdomain");

    let token = get_current_token();
    write_user_value(token, buf as *mut UtsName, &un);
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

/// Linux `setpgid(2)` (syscall 154 on riscv64).
///
/// Process groups are not modeled; accept and return success for compatibility.
pub fn syscall_setpgid(_pid: usize, _pgid: usize) -> isize {
    0
}

/// Linux `getsid(2)` (syscall 156 on riscv64).
pub fn syscall_getsid(pid: usize) -> isize {
    if pid == 0 {
        current_process().getpid() as isize
    } else {
        pid as isize
    }
}

/// Linux `setsid(2)` (syscall 157 on riscv64).
///
/// We don't model sessions; treat the process PID as SID and return it.
pub fn syscall_setsid() -> isize {
    current_process().getpid() as isize
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
    let new_ruid = if ruid == usize::MAX {
        None
    } else {
        Some(ruid as u32)
    };
    let new_euid = if euid == usize::MAX {
        None
    } else {
        Some(euid as u32)
    };
    let process = current_process();
    let mut inner = process.borrow_mut();
    if inner.euid != 0 {
        if let Some(r) = new_ruid {
            if r != inner.uid && r != inner.euid {
                return EPERM;
            }
        }
        if let Some(e) = new_euid {
            if !uid_allowed(e, inner.uid, inner.euid, inner.suid) {
                return EPERM;
            }
        }
    }
    if let Some(r) = new_ruid {
        inner.uid = r;
    }
    if let Some(e) = new_euid {
        inner.euid = e;
        inner.suid = e;
        inner.fsuid = e;
    }
    0
}

/// Linux `setregid(2)` (syscall 143 on riscv64).
pub fn syscall_setregid(rgid: usize, egid: usize) -> isize {
    let new_rgid = if rgid == usize::MAX {
        None
    } else {
        Some(rgid as u32)
    };
    let new_egid = if egid == usize::MAX {
        None
    } else {
        Some(egid as u32)
    };
    let process = current_process();
    let mut inner = process.borrow_mut();
    if inner.euid != 0 {
        if let Some(r) = new_rgid {
            if r != inner.gid && r != inner.egid {
                return EPERM;
            }
        }
        if let Some(e) = new_egid {
            if !gid_allowed(e, inner.gid, inner.egid, inner.sgid) {
                return EPERM;
            }
        }
    }
    if let Some(r) = new_rgid {
        inner.gid = r;
    }
    if let Some(e) = new_egid {
        inner.egid = e;
        inner.sgid = e;
        inner.fsgid = e;
    }
    0
}

/// Linux `setresuid(2)` (syscall 147 on riscv64).
pub fn syscall_setresuid(ruid: usize, euid: usize, suid: usize) -> isize {
    let new_ruid = if ruid == usize::MAX {
        None
    } else {
        Some(ruid as u32)
    };
    let new_euid = if euid == usize::MAX {
        None
    } else {
        Some(euid as u32)
    };
    let new_suid = if suid == usize::MAX {
        None
    } else {
        Some(suid as u32)
    };
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
    } else if new_euid.is_some() {
        inner.suid = inner.euid;
    }
    0
}

/// Linux `setresgid(2)` (syscall 149 on riscv64).
pub fn syscall_setresgid(rgid: usize, egid: usize, sgid: usize) -> isize {
    let new_rgid = if rgid == usize::MAX {
        None
    } else {
        Some(rgid as u32)
    };
    let new_egid = if egid == usize::MAX {
        None
    } else {
        Some(egid as u32)
    };
    let new_sgid = if sgid == usize::MAX {
        None
    } else {
        Some(sgid as u32)
    };
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
    } else if new_egid.is_some() {
        inner.sgid = inner.egid;
    }
    0
}

/// Linux `setfsuid(2)` (syscall 151 on riscv64).
pub fn syscall_setfsuid(uid: usize) -> isize {
    let uid = uid as u32;
    let process = current_process();
    let mut inner = process.borrow_mut();
    let prev = inner.fsuid;
    if inner.euid == 0 || uid_allowed(uid, inner.uid, inner.euid, inner.suid) {
        inner.fsuid = uid;
    }
    prev as isize
}

/// Linux `setfsgid(2)` (syscall 152 on riscv64).
pub fn syscall_setfsgid(gid: usize) -> isize {
    let gid = gid as u32;
    let process = current_process();
    let mut inner = process.borrow_mut();
    let prev = inner.fsgid;
    if inner.euid == 0 || gid_allowed(gid, inner.gid, inner.egid, inner.sgid) {
        inner.fsgid = gid;
    }
    prev as isize
}

/// Linux `getresuid(2)` (syscall 148 on riscv64).
pub fn syscall_getresuid(ruid: usize, euid: usize, suid: usize) -> isize {
    let process = current_process();
    let inner = process.borrow_mut();
    let token = get_current_token();
    if ruid != 0 && try_write_user_value(token, ruid as *mut u32, &inner.uid).is_err() {
        return EFAULT;
    }
    if euid != 0 && try_write_user_value(token, euid as *mut u32, &inner.euid).is_err() {
        return EFAULT;
    }
    if suid != 0 && try_write_user_value(token, suid as *mut u32, &inner.suid).is_err() {
        return EFAULT;
    }
    0
}

/// Linux `getresgid(2)` (syscall 150 on riscv64).
pub fn syscall_getresgid(rgid: usize, egid: usize, sgid: usize) -> isize {
    let process = current_process();
    let inner = process.borrow_mut();
    let token = get_current_token();
    if rgid != 0 && try_write_user_value(token, rgid as *mut u32, &inner.gid).is_err() {
        return EFAULT;
    }
    if egid != 0 && try_write_user_value(token, egid as *mut u32, &inner.egid).is_err() {
        return EFAULT;
    }
    if sgid != 0 && try_write_user_value(token, sgid as *mut u32, &inner.sgid).is_err() {
        return EFAULT;
    }
    0
}

/// Linux `gettid(2)` (syscall 178 on riscv64).
pub fn syscall_gettid_linux() -> isize {
    current_linux_tid() as isize
}

const EINVAL: isize = -22;

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
    const ESRCH: isize = -3;
    if pid != 0 {
        return ESRCH;
    }
    let task = current_task().unwrap();
    let inner = task.borrow_mut();
    let token = get_current_token();
    if head_ptr != 0 {
        write_user_value(token, head_ptr as *mut usize, &inner.robust_list_head);
    }
    if len_ptr != 0 {
        write_user_value(token, len_ptr as *mut usize, &inner.robust_list_len);
    }
    0
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

const RLIMIT_STACK: usize = 3;
const RLIMIT_CORE: usize = 4;
const RLIMIT_NOFILE: usize = 7;

fn rlimit_for_resource(resource: usize) -> (u64, u64) {
    if resource == RLIMIT_STACK {
        // Keep default thread stacks modest to avoid huge eager mmap costs.
        (1 * 1024 * 1024, 1 * 1024 * 1024)
    } else if resource == RLIMIT_CORE {
        let process = current_process();
        let inner = process.borrow_mut();
        (inner.rlimit_core_cur, inner.rlimit_core_max)
    } else if resource == RLIMIT_NOFILE {
        let process = current_process();
        let inner = process.borrow_mut();
        (inner.rlimit_nofile_cur, inner.rlimit_nofile_max)
    } else {
        (u64::MAX, u64::MAX)
    }
}

/// Linux `prlimit64(2)` (syscall 261 on riscv64).
///
/// Provide a permissive "unlimited" answer for common queries (e.g. RLIMIT_STACK).
pub fn syscall_prlimit64(
    _pid: usize,
    _resource: usize,
    _new_limit: usize,
    old_limit: usize,
) -> isize {
    if _new_limit != 0 {
        let token = get_current_token();
        let new = read_user_value(token, _new_limit as *const RLimit64);
        if new.rlim_cur > new.rlim_max {
            return EINVAL;
        }
        if _resource == RLIMIT_CORE {
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.rlimit_core_cur = new.rlim_cur;
            inner.rlimit_core_max = new.rlim_max;
        } else if _resource == RLIMIT_NOFILE {
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.rlimit_nofile_cur = new.rlim_cur;
            inner.rlimit_nofile_max = new.rlim_max;
        }
    }
    if old_limit != 0 {
        let token = get_current_token();
        let (rlim_cur, rlim_max) = rlimit_for_resource(_resource);
        let rl = RLimit64 { rlim_cur, rlim_max };
        write_user_value(token, old_limit as *mut RLimit64, &rl);
    }
    0
}

/// Linux `getrlimit(2)` (syscall 163 on riscv64).
pub fn syscall_getrlimit(resource: usize, rlim: usize) -> isize {
    if rlim != 0 {
        let token = get_current_token();
        let (rlim_cur, rlim_max) = rlimit_for_resource(resource);
        let rl = RLimit64 { rlim_cur, rlim_max };
        write_user_value(token, rlim as *mut RLimit64, &rl);
    }
    0
}

/// Linux `setrlimit(2)` (syscall 164 on riscv64).
///
/// We currently ignore the new limits and return success.
pub fn syscall_setrlimit(_resource: usize, _rlim: usize) -> isize {
    if _rlim != 0 {
        let token = get_current_token();
        let new = read_user_value(token, _rlim as *const RLimit64);
        if new.rlim_cur > new.rlim_max {
            return EINVAL;
        }
        if _resource == RLIMIT_CORE {
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.rlimit_core_cur = new.rlim_cur;
            inner.rlimit_core_max = new.rlim_max;
        } else if _resource == RLIMIT_NOFILE {
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.rlimit_nofile_cur = new.rlim_cur;
            inner.rlimit_nofile_max = new.rlim_max;
        }
    }
    0
}

/// Linux `getrandom(2)` (syscall 278 on riscv64).
///
/// Fill the buffer with a simple xorshift PRNG seeded from time and pid/tid.
pub fn syscall_getrandom(buf: usize, len: usize, _flags: u32) -> isize {
    if buf == 0 {
        return 0;
    }
    let token = get_current_token();
    let mut seed = (get_time() as u64)
        ^ ((current_process().getpid() as u64) << 32)
        ^ (current_linux_tid() as u64);
    let chunks = translated_byte_buffer(token, buf as *mut u8, len, MapPermission::W);
    let mut written = 0usize;
    for chunk in chunks {
        for b in chunk {
            // xorshift64*
            let mut x = seed;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x = x.wrapping_mul(0x2545F4914F6CDD1D);
            seed = x;
            *b = (x & 0xff) as u8;
            written += 1;
        }
    }
    written as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
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
    const EBADF: isize = -9;

    if nfds == 0 || fds_ptr == 0 {
        return 0;
    }

    let token = get_current_token();
    let process = current_process();

    // `ppoll(NULL)` means "wait forever" (no timeout). Many libc `poll(-1)` wrappers
    // map to `ppoll(..., NULL, ...)`.
    let infinite = _tmo_p == 0;

    loop {
        let mut ready = 0isize;
        for i in 0..nfds {
            let pfd_ptr = (fds_ptr + i * size_of::<PollFd>()) as *mut PollFd;
            let mut pfd = read_user_value(token, pfd_ptr as *const PollFd);
            if pfd.fd < 0 {
                pfd.revents = 0;
                write_user_value(token, pfd_ptr, &pfd);
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
                pfd.revents = 0;
                return EBADF;
            };

            let mut revents: i16 = 0;

            // Pipes and our socketpair endpoints need real readiness (buffer-based),
            // not just "is readable/writable" capability.
            if let Some(pipe) = file.as_any().downcast_ref::<crate::fs::Pipe>() {
                if (pfd.events & POLLIN) != 0 && pipe.poll_readable() {
                    revents |= POLLIN;
                }
                if (pfd.events & POLLOUT) != 0 && pipe.poll_writable() {
                    revents |= POLLOUT;
                }
            } else if let Some(sp) = file.as_any().downcast_ref::<crate::fs::SocketPairEnd>() {
                if (pfd.events & POLLIN) != 0 && sp.poll_readable() {
                    revents |= POLLIN;
                }
                if (pfd.events & POLLOUT) != 0 && sp.poll_writable() {
                    revents |= POLLOUT;
                }
            } else if let Some(ns) = file.as_any().downcast_ref::<crate::fs::NetSocketFile>() {
                if (pfd.events & POLLIN) != 0 && ns.poll_readable() {
                    revents |= POLLIN;
                }
                if (pfd.events & POLLOUT) != 0 && ns.poll_writable() {
                    revents |= POLLOUT;
                }
            } else {
                if (pfd.events & POLLIN) != 0 && file.readable() {
                    revents |= POLLIN;
                }
                if (pfd.events & POLLOUT) != 0 && file.writable() {
                    revents |= POLLOUT;
                }
            }

            pfd.revents = revents;
            write_user_value(token, pfd_ptr, &pfd);
            if revents != 0 {
                ready += 1;
            }
        }

        if ready != 0 || !infinite {
            return ready;
        }

        // Block (best-effort): yield and retry until something becomes ready.
        crate::task::processor::suspend_current_and_run_next();
    }
}

pub fn current_umask() -> usize {
    UMASK.load(Ordering::Relaxed)
}

/// Linux `umask(2)` (syscall 166 on riscv64).
///
/// A minimal implementation for daemon() and common utilities.
pub fn syscall_umask(mask: usize) -> isize {
    let prev = UMASK.swap(mask & 0o777, Ordering::Relaxed);
    prev as isize
}

/// Linux `ioctl(2)` (syscall 29 on riscv64).
///
/// We don't model TTYs yet; return `ENOTTY` for most requests to avoid `ENOSYS`
/// aborts in busybox/glibc helpers.
pub fn syscall_ioctl(fd: usize, _request: usize, _argp: usize) -> isize {
    const EBADF: isize = -9;
    const ENOTTY: isize = -25;

    let process = current_process();
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
