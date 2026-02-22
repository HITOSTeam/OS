use alloc::sync::Arc;

use crate::fs::DummyFile;
use crate::task::processor::current_files_process;

const EINVAL: isize = -22;
const EMFILE: isize = -24;

const O_NONBLOCK: u32 = 0x800;
const O_PATH: u32 = 0x200000;
const FD_CLOEXEC: u32 = 1;

const CLOEXEC_FLAG: usize = 0x80000;
const NONBLOCK_FLAG: usize = 0x800;

// this function allocates a dummy file descriptor with given flags
fn alloc_dummy_fd(fd_flags: u32) -> isize {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[fd] = Some(Arc::new(DummyFile::new(true, true)));
    inner.fd_flags[fd] = fd_flags;
    fd as isize
}

pub fn syscall_epoll_create(size: isize) -> isize {
    if size <= 0 {
        return EINVAL;
    }
    alloc_dummy_fd(0)
}

pub fn syscall_epoll_create1(flags: usize) -> isize {
    const EPOLL_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !EPOLL_CLOEXEC) != 0 {
        return EINVAL;
    }
    let mut fd_flags = 0u32;
    if (flags & EPOLL_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_dummy_fd(fd_flags)
}

pub fn syscall_eventfd2(_count: u64, flags: usize) -> isize {
    const EFD_SEMAPHORE: usize = 0x1;
    const EFD_NONBLOCK: usize = NONBLOCK_FLAG;
    const EFD_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC)) != 0 {
        return EINVAL;
    }
    let mut fd_flags = 0u32;
    if (flags & EFD_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK;
    }
    if (flags & EFD_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_dummy_fd(fd_flags)
}

pub fn syscall_signalfd4(_fd: isize, _mask: usize, _sigsetsize: usize, flags: usize) -> isize {
    const SFD_NONBLOCK: usize = NONBLOCK_FLAG;
    const SFD_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !(SFD_NONBLOCK | SFD_CLOEXEC)) != 0 {
        return EINVAL;
    }
    let mut fd_flags = 0u32;
    if (flags & SFD_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK;
    }
    if (flags & SFD_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_dummy_fd(fd_flags)
}

pub fn syscall_timerfd_create(_clockid: usize, flags: usize) -> isize {
    const TFD_NONBLOCK: usize = NONBLOCK_FLAG;
    const TFD_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !(TFD_NONBLOCK | TFD_CLOEXEC)) != 0 {
        return EINVAL;
    }
    let mut fd_flags = 0u32;
    if (flags & TFD_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK;
    }
    if (flags & TFD_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_dummy_fd(fd_flags)
}

pub fn syscall_inotify_init1(flags: usize) -> isize {
    const IN_NONBLOCK: usize = NONBLOCK_FLAG;
    const IN_CLOEXEC: usize = CLOEXEC_FLAG;
    if (flags & !(IN_NONBLOCK | IN_CLOEXEC)) != 0 {
        return EINVAL;
    }
    let mut fd_flags = 0u32;
    if (flags & IN_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK;
    }
    if (flags & IN_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_dummy_fd(fd_flags)
}

pub fn syscall_pidfd_open(_pid: usize, flags: usize) -> isize {
    const PIDFD_NONBLOCK: usize = NONBLOCK_FLAG;
    if (flags & !PIDFD_NONBLOCK) != 0 {
        return EINVAL;
    }
    let mut fd_flags = 0u32;
    if (flags & PIDFD_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK;
    }
    alloc_dummy_fd(fd_flags)
}

pub fn syscall_fanotify_init(_flags: usize, _event_f_flags: usize) -> isize {
    alloc_dummy_fd(0)
}

pub fn syscall_userfaultfd(_flags: usize) -> isize {
    alloc_dummy_fd(0)
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
    alloc_dummy_fd(0)
}

pub fn syscall_bpf(_cmd: usize, _attr: usize, _size: usize) -> isize {
    alloc_dummy_fd(0)
}

pub fn syscall_fsopen(_fsname: usize, _flags: usize) -> isize {
    alloc_dummy_fd(0)
}

pub fn syscall_fspick(_dirfd: isize, _path: usize, _flags: usize) -> isize {
    alloc_dummy_fd(0)
}

pub fn syscall_open_tree(_dirfd: isize, _path: usize, _flags: usize) -> isize {
    alloc_dummy_fd(O_PATH)
}

pub fn syscall_memfd_create(_name: usize, flags: usize) -> isize {
    const MFD_CLOEXEC: usize = 0x0001;
    let mut fd_flags = 0u32;
    if (flags & MFD_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_dummy_fd(fd_flags)
}

pub fn syscall_memfd_secret(_flags: usize) -> isize {
    alloc_dummy_fd(0)
}
