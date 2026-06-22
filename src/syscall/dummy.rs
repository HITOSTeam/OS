use crate::syscall::error::{SyscallError, err};
use alloc::sync::Arc;

use crate::{
    fs::{
        DummyFile, EventFdFile, File, PidFdFile, PseudoShmFile, SignalfdFile, TimerFdFile,
        UserfaultfdFile, shm_create_anonymous,
    },
    mm::{try_copy_from_user, try_read_user_value, try_write_user_value},
    task::{
        manager::pid2process,
        processor::{current_files, current_files_and_nofile_limit},
    },
    trap::get_current_token,
};

const O_NONBLOCK: u32 = 0x800;
#[allow(dead_code)]
const O_PATH: u32 = 0x200000;
const FD_CLOEXEC: u32 = 1;

const CLOEXEC_FLAG: usize = 0x80000;
const NONBLOCK_FLAG: usize = 0x800;
const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const TFD_TIMER_ABSTIME: usize = 0x1;
const TFD_TIMER_CANCEL_ON_SET: usize = 0x2;

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ITimerSpec {
    it_interval: TimeSpec,
    it_value: TimeSpec,
}

fn alloc_fd(file: Arc<dyn File + Send + Sync>, descriptor_flags: u32) -> isize {
    let (files, limit) = current_files_and_nofile_limit();
    files
        .lock()
        .install_fd(file, descriptor_flags, limit)
        .map(|fd| fd as isize)
        .unwrap_or_else(|| err(SyscallError::EMFILE))
}

// this function allocates a dummy file descriptor with given flags
fn alloc_dummy_fd(descriptor_flags: u32) -> isize {
    alloc_fd(Arc::new(DummyFile::new(true, true)), descriptor_flags)
}

fn validate_user_cstr(name: usize, max_len: usize) -> Result<(), isize> {
    if name == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut byte = [0u8; 1];
    for i in 0..=max_len {
        let ptr = name.checked_add(i).ok_or(err(SyscallError::EFAULT))? as *const u8;
        if try_copy_from_user(token, ptr, &mut byte).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        if byte[0] == 0 {
            return Ok(());
        }
    }
    // Linux memfd_create rejects unterminated or overlong names with err(SyscallError::EINVAL).
    Err(err(SyscallError::EINVAL))
}

fn timespec_to_ns(ts: TimeSpec) -> Option<u64> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= 1_000_000_000 {
        return None;
    }
    Some(
        (ts.sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.nsec as u64),
    )
}

fn ns_to_timespec(ns: u64) -> TimeSpec {
    TimeSpec {
        sec: (ns / 1_000_000_000) as i64,
        nsec: (ns % 1_000_000_000) as i64,
    }
}

#[allow(dead_code)]
pub fn syscall_epoll_create(size: isize) -> isize {
    if size <= 0 {
        return err(SyscallError::EINVAL);
    }
    alloc_dummy_fd(0)
}

#[allow(dead_code)]
pub fn syscall_epoll_create1(flags: usize) -> isize {
    const EPOLL_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !EPOLL_CLOEXEC) != 0 {
        return err(SyscallError::EINVAL);
    }
    let mut descriptor_flags = 0u32;
    if (flags & EPOLL_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    alloc_dummy_fd(descriptor_flags)
}

pub fn syscall_eventfd2(_count: u64, flags: usize) -> isize {
    const EFD_SEMAPHORE: usize = 0x1;
    const EFD_NONBLOCK: usize = NONBLOCK_FLAG;
    const EFD_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC)) != 0 {
        return err(SyscallError::EINVAL);
    }
    let mut descriptor_flags = 0u32;
    if (flags & EFD_NONBLOCK) != 0 {
        descriptor_flags |= O_NONBLOCK;
    }
    if (flags & EFD_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    alloc_fd(
        Arc::new(EventFdFile::new(
            _count,
            (flags & EFD_SEMAPHORE) != 0,
            (flags & EFD_NONBLOCK) != 0,
        )),
        descriptor_flags,
    )
}

pub fn syscall_signalfd4(_fd: isize, _mask: usize, _sigsetsize: usize, flags: usize) -> isize {
    const SFD_NONBLOCK: usize = NONBLOCK_FLAG;
    const SFD_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !(SFD_NONBLOCK | SFD_CLOEXEC)) != 0 {
        return err(SyscallError::EINVAL);
    }
    let mut descriptor_flags = 0u32;
    if (flags & SFD_NONBLOCK) != 0 {
        descriptor_flags |= O_NONBLOCK;
    }
    if (flags & SFD_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    if _fd >= 0 {
        let fd = _fd as usize;
        let files = current_files();
        let mut files = files.lock();
        if !files.is_fd_open(fd) {
            return err(SyscallError::EBADF);
        }
        let _ = files.set_flags(fd, descriptor_flags);
        return fd as isize;
    }
    if _fd != -1 {
        return err(SyscallError::EINVAL);
    }
    alloc_fd(Arc::new(SignalfdFile::new()), descriptor_flags)
}

pub fn syscall_timerfd_create(clockid: usize, flags: usize) -> isize {
    const TFD_NONBLOCK: usize = NONBLOCK_FLAG;
    const TFD_CLOEXEC: usize = CLOEXEC_FLAG;
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return err(SyscallError::EINVAL);
    }
    if (flags & !(TFD_NONBLOCK | TFD_CLOEXEC)) != 0 {
        return err(SyscallError::EINVAL);
    }
    let mut descriptor_flags = 0u32;
    if (flags & TFD_NONBLOCK) != 0 {
        descriptor_flags |= O_NONBLOCK;
    }
    if (flags & TFD_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    alloc_fd(TimerFdFile::new(clockid), descriptor_flags)
}

pub fn syscall_timerfd_gettime(fd: usize, curr_value: usize) -> isize {
    let Some(file) = current_files().lock().get_file(fd) else {
        return err(SyscallError::EBADF);
    };
    let Some(timerfd) = file.as_any().downcast_ref::<TimerFdFile>() else {
        return err(SyscallError::EINVAL);
    };
    if curr_value == 0 {
        return err(SyscallError::EFAULT);
    }
    let Ok((remain_ns, interval_ns)) = timerfd.get_time() else {
        return err(SyscallError::EINVAL);
    };
    let spec = ITimerSpec {
        it_interval: ns_to_timespec(interval_ns),
        it_value: ns_to_timespec(remain_ns),
    };
    let token = get_current_token();
    if try_write_user_value(token, curr_value as *mut ITimerSpec, &spec).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_timerfd_settime(
    fd: usize,
    flags: usize,
    new_value: usize,
    old_value: usize,
) -> isize {
    if (flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)) != 0 {
        return err(SyscallError::EINVAL);
    }
    let Some(file) = current_files().lock().get_file(fd) else {
        return err(SyscallError::EBADF);
    };
    let Some(timerfd) = file.as_any().downcast_ref::<TimerFdFile>() else {
        return err(SyscallError::EINVAL);
    };
    if new_value == 0 {
        return err(SyscallError::EFAULT);
    }
    if (flags & TFD_TIMER_CANCEL_ON_SET) != 0
        && ((flags & TFD_TIMER_ABSTIME) == 0 || timerfd.clock_id() != CLOCK_REALTIME)
    {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let Some(new_spec) = try_read_user_value(token, new_value as *const ITimerSpec) else {
        return err(SyscallError::EFAULT);
    };
    let Some(value_ns) = timespec_to_ns(new_spec.it_value) else {
        return err(SyscallError::EINVAL);
    };
    let Some(interval_ns) = timespec_to_ns(new_spec.it_interval) else {
        return err(SyscallError::EINVAL);
    };
    let now_ns = crate::syscall::timer_clock_now_ns(timerfd.clock_id(), 0, None)
        .ok_or(err(SyscallError::EINVAL));
    let Ok(now_ns) = now_ns else {
        return err(SyscallError::EINVAL);
    };
    let deadline_ns = if value_ns == 0 {
        None
    } else if (flags & TFD_TIMER_ABSTIME) != 0 {
        Some(value_ns)
    } else {
        Some(now_ns.saturating_add(value_ns))
    };
    let Ok((prev_remain_ns, prev_interval_ns, was_canceled)) = timerfd.set_time(
        deadline_ns,
        interval_ns,
        (flags & TFD_TIMER_CANCEL_ON_SET) != 0,
    ) else {
        return err(SyscallError::EINVAL);
    };
    if old_value != 0 {
        let spec = ITimerSpec {
            it_interval: ns_to_timespec(prev_interval_ns),
            it_value: ns_to_timespec(prev_remain_ns),
        };
        if try_write_user_value(token, old_value as *mut ITimerSpec, &spec).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    if was_canceled {
        err(SyscallError::ECANCELED)
    } else {
        0
    }
}

pub fn syscall_inotify_init1(flags: usize) -> isize {
    const IN_NONBLOCK: usize = NONBLOCK_FLAG;
    const IN_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !(IN_NONBLOCK | IN_CLOEXEC)) != 0 {
        return err(SyscallError::EINVAL);
    }
    err(SyscallError::ENOSYS)
}

pub fn syscall_pidfd_open(pid: usize, flags: usize) -> isize {
    const PIDFD_NONBLOCK: usize = NONBLOCK_FLAG;
    if (flags & !PIDFD_NONBLOCK) != 0 {
        return err(SyscallError::EINVAL);
    }
    if pid == 0 || (pid as isize) < 0 {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = pid2process(pid) else {
        return err(SyscallError::ESRCH);
    };
    let mut descriptor_flags = 0u32;
    // Linux pidfds are always close-on-exec.
    descriptor_flags |= FD_CLOEXEC;
    if (flags & PIDFD_NONBLOCK) != 0 {
        descriptor_flags |= O_NONBLOCK;
    }
    alloc_fd(Arc::new(PidFdFile::new(&process)), descriptor_flags)
}

pub fn syscall_fanotify_init(_flags: usize, _event_f_flags: usize) -> isize {
    // We do not implement the fanotify subsystem yet. Linux reports err(SyscallError::ENOSYS)
    // when the syscall is unavailable, which lets LTP treat fanotify cases as
    // TCONF instead of tripping later on a dummy fd.
    err(SyscallError::ENOSYS)
}

pub fn syscall_userfaultfd(flags: usize) -> isize {
    const UFFD_USER_MODE_ONLY: usize = 0x1;
    let known = CLOEXEC_FLAG | NONBLOCK_FLAG | UFFD_USER_MODE_ONLY;
    if (flags & !known) != 0 {
        return err(SyscallError::EINVAL);
    }
    let mut descriptor_flags = 0u32;
    if (flags & NONBLOCK_FLAG) != 0 {
        descriptor_flags |= O_NONBLOCK;
    }
    if (flags & CLOEXEC_FLAG) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    alloc_fd(Arc::new(UserfaultfdFile::new()), descriptor_flags)
}

pub fn try_handle_userfaultfd_page_fault(addr: usize, is_write: bool) -> bool {
    let files = current_files().lock().iter_files_snapshot();
    for (_fd, file) in files {
        let Some(uffd) = file.as_any().downcast_ref::<UserfaultfdFile>() else {
            continue;
        };
        if uffd.handle_page_fault(addr, is_write) {
            return true;
        }
    }
    false
}

pub fn syscall_perf_event_open(
    _attr: usize,
    _pid: isize,
    _cpu: isize,
    _group_fd: isize,
    _flags: usize,
) -> isize {
    alloc_dummy_fd(0)
}

pub fn syscall_io_uring_setup(_entries: usize, _params: usize) -> isize {
    err(SyscallError::ENOSYS)
}

pub fn syscall_bpf(cmd: usize, attr: usize, size: usize) -> isize {
    crate::bpf::syscall_bpf(cmd, attr, size)
}

#[allow(dead_code)]
pub fn syscall_fsopen(_fsname: usize, _flags: usize) -> isize {
    alloc_dummy_fd(0)
}

#[allow(dead_code)]
pub fn syscall_fspick(_dirfd: isize, _path: usize, _flags: usize) -> isize {
    alloc_dummy_fd(0)
}

#[allow(dead_code)]
pub fn syscall_open_tree(_dirfd: isize, _path: usize, _flags: usize) -> isize {
    alloc_dummy_fd(O_PATH)
}

pub fn syscall_memfd_create(name: usize, flags: usize) -> isize {
    const MFD_CLOEXEC: usize = 0x0001;
    const MFD_ALLOW_SEALING: usize = 0x0002;
    const MEMFD_NAME_MAX: usize = 249;
    const KNOWN_FLAGS: usize = MFD_CLOEXEC | MFD_ALLOW_SEALING;
    if (flags & !KNOWN_FLAGS) != 0 {
        return err(SyscallError::EINVAL);
    }
    if let Err(e) = validate_user_cstr(name, MEMFD_NAME_MAX) {
        return e;
    }
    let mut descriptor_flags = 0u32;
    if (flags & MFD_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    let allow_sealing = (flags & MFD_ALLOW_SEALING) != 0;
    let file: Arc<dyn File + Send + Sync> =
        Arc::new(PseudoShmFile::new(shm_create_anonymous(allow_sealing)));
    alloc_fd(file, descriptor_flags)
}

pub fn syscall_memfd_secret(_flags: usize) -> isize {
    alloc_dummy_fd(0)
}
