use crate::{
    config::PAGE_SIZE,
    fs::{
        LinuxTermio, LinuxTermios, LinuxWinSize, PseudoKindTag, PtyMasterFile, PtySlaveFile,
        TtyFile, UserfaultfdFile, pseudo_block_is_read_only, pseudo_block_read_ahead,
        pseudo_block_set_read_ahead, pseudo_block_set_read_only,
    },
    mm::{
        MapPermission, VirtAddr, try_copy_from_user, try_copy_to_user, try_read_user_value,
        try_write_user_value, write_user_value,
    },
    syscall::{
        error::{SyscallError, err},
        filesystem::O_NONBLOCK,
    },
    task::processor::{current_files, current_process},
    trap::get_current_token,
};
use alloc::{format, string::String};
use core::mem::size_of;

#[repr(C)]
#[derive(Clone, Copy)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UffdioRegister {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64,
}

/// Linux `ioctl(2)` (syscall 29 on riscv64).
///
/// We don't model TTYs yet; return `ENOTTY` for most requests to avoid `ENOSYS`
/// aborts in busybox/glibc helpers.
pub fn syscall_ioctl(fd: usize, _request: usize, _argp: usize) -> isize {
    const EBADF: isize = -9;
    const ENOTTY: isize = -25;
    const TCGETS: usize = 0x5401;
    const TCSETS: usize = 0x5402;
    const TCSETSW: usize = 0x5403;
    const TCSETSF: usize = 0x5404;
    const TCGETA: usize = 0x5405;
    const TCSETA: usize = 0x5406;
    const TCSETAW: usize = 0x5407;
    const TCSETAF: usize = 0x5408;
    const TCSBRK: usize = 0x5409;
    const TCXONC: usize = 0x540a;
    const TCFLSH: usize = 0x540b;
    const TIOCGWINSZ: usize = 0x5413;
    const TIOCSWINSZ: usize = 0x5414;
    const TIOCGPTN: usize = 0x8004_5430;
    const TIOCSPTLCK: usize = 0x4004_5431;
    const TIOCSETD: usize = 0x5423;
    const TIOCGETD: usize = 0x5424;
    const TCSBRKP: usize = 0x5425;
    const N_TTY: i32 = 0;
    const N_HDLC: i32 = 13;
    const UFFD_API: u64 = 0xAA;
    const UFFDIO_API: usize = 0xc018_aa3f;
    const UFFDIO_REGISTER: usize = 0xc020_aa00;
    const UFFDIO_COPY: usize = 0xc028_aa03;
    const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
    const UFFDIO_COPY_MODE_DONTWAKE: u64 = 1 << 0;
    const FIONREAD: usize = 0x541B;
    const FIONBIO: usize = 0x5421;
    const RNDGETENTCNT: usize = 0x8004_5200;
    const BLKROSET: usize = 0x125d;
    const BLKROGET: usize = 0x125e;
    const BLKRASET: usize = 0x1262;
    const BLKRAGET: usize = 0x1263;
    const BLKGETSIZE: usize = 0x1260;
    const BLKSSZGET: usize = 0x1268;
    const BLKGETSIZE64: usize = 0x8008_1272;
    // Some libc builds issue BLKGETSIZE64 with a 32-bit size encoding.
    const BLKGETSIZE64_COMPAT: usize = 0x8004_1272;
    const BLKPBSZGET: usize = 0x127b;
    const LOOP_CLR_FD: usize = 0x4c01;
    const FS_IOC_GETFLAGS: usize = 0x8008_6601;
    const FS_IOC_SETFLAGS: usize = 0x4008_6602;
    const TUNSETIFF: usize = 0x4004_54ca;
    const TUNSETPERSIST: usize = 0x4004_54cb;
    const TUNSETOWNER: usize = 0x4004_54cc;
    const TUNSETLINK: usize = 0x4004_54cd;
    const TUNSETGROUP: usize = 0x4004_54ce;
    const TUNGETFEATURES: usize = 0x8004_54cf;
    const TUNSETOFFLOAD: usize = 0x4004_54d0;
    const TUNGETIFF: usize = 0x8004_54d2;
    const TUNGETVNETHDRSZ: usize = 0x8004_54d7;
    const TUNSETVNETHDRSZ: usize = 0x4004_54d8;
    const TUNSETQUEUE: usize = 0x4004_54d9;
    const IFF_TUN: u16 = 0x0001;
    const IFF_TAP: u16 = 0x0002;
    const IFF_TUN_EXCL: u16 = 0x8000;
    const IFF_NO_PI: u16 = 0x1000;
    const IFF_ONE_QUEUE: u16 = 0x2000;
    const IFF_VNET_HDR: u16 = 0x4000;
    const TUN_SUPPORTED_IFF: u16 =
        IFF_TUN | IFF_TAP | IFF_TUN_EXCL | IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR;
    const TUN_SUPPORTED_FEATURES: u32 =
        (IFF_TUN | IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR) as u32;
    const VIRTIO_NET_HDR_LEN: i32 = 10;
    const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
    const FS_APPEND_FL: u32 = 0x0000_0020;
    const FS_NODUMP_FL: u32 = 0x0000_0040;
    const SIOCATMARK: usize = 0x8905;
    const SIOCGSTAMP_OLD: usize = 0x8906;
    const SIOCGSTAMPNS_OLD: usize = 0x8907;
    const SIOCGSTAMP_NEW: usize = 0x8010_8906;
    const SIOCGSTAMPNS_NEW: usize = 0x8010_8907;
    const SIOCADDRT: usize = 0x890b;
    const SIOCDELRT: usize = 0x890c;
    const SIOCGIFNAME: usize = 0x8910;
    const SIOCGIFCONF: usize = 0x8912;
    const SIOCGIFFLAGS: usize = 0x8913;
    const SIOCSIFFLAGS: usize = 0x8914;
    const SIOCGIFADDR: usize = 0x8915;
    const SIOCSIFADDR: usize = 0x8916;
    const SIOCDIFADDR: usize = 0x8936;
    const SIOCGIFDSTADDR: usize = 0x8917;
    const SIOCSIFDSTADDR: usize = 0x8918;
    const SIOCGIFBRDADDR: usize = 0x8919;
    const SIOCSIFBRDADDR: usize = 0x891a;
    const SIOCGIFNETMASK: usize = 0x891b;
    const SIOCSIFNETMASK: usize = 0x891c;
    const SIOCGIFMETRIC: usize = 0x891d;
    const SIOCSIFMETRIC: usize = 0x891e;
    const SIOCGIFHWADDR: usize = 0x8927;
    const SIOCGIFMTU: usize = 0x8921;
    const SIOCSIFMTU: usize = 0x8922;
    const SIOCSIFNAME: usize = 0x8923;
    const SIOCADDMULTI: usize = 0x8931;
    const SIOCDELMULTI: usize = 0x8932;
    const SIOCGIFINDEX: usize = 0x8933;
    const SIOCGIFTXQLEN: usize = 0x8942;
    const SIOCSIFTXQLEN: usize = 0x8943;
    const SIOCETHTOOL: usize = 0x8946;
    const SIOCDARP: usize = 0x8953;
    const SIOCGARP: usize = 0x8954;
    const SIOCSARP: usize = 0x8955;
    const CAP_NET_ADMIN: usize = 12;
    const SIOCGIFMAP: usize = 0x8970;
    const SIOCSIFMAP: usize = 0x8971;
    const AF_INET: u16 = 2;
    const RTF_GATEWAY: u16 = 0x0002;
    const RTF_HOST: u16 = 0x0004;
    const ATF_COM: i32 = 0x02;
    const PSEUDO_ROOT_DEV_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
    const PSEUDO_ROOT_DEV_SECTOR_SIZE: u32 = 512;
    const PSEUDO_ROOT_DEV_PHYS_BLOCK_SIZE: u32 = 4096;

    let file = current_files().lock().get_file(fd);
    let Some(file) = file else {
        return EBADF;
    };
    // Some libcs pass ioctl request as signed int (sign-extended on rv64).
    // Compare on low 32 bits to accept both calling conventions.
    let request = _request & 0xffff_ffffusize;
    let token = get_current_token();

    if request == FIONBIO {
        if _argp == 0 {
            return err(SyscallError::EFAULT);
        }
        let Some(nonblocking) = try_read_user_value::<i32>(token, _argp as *const i32) else {
            return err(SyscallError::EFAULT);
        };
        let files = current_files();
        let mut files = files.lock();
        let Some((_file, mut flags)) = files.get_file_and_flags(fd) else {
            return EBADF;
        };
        if nonblocking != 0 {
            flags |= O_NONBLOCK as u32;
        } else {
            flags &= !(O_NONBLOCK as u32);
        }
        return if files.set_flags(fd, flags) { 0 } else { EBADF };
    }

    if let Some(uffd) = file.as_any().downcast_ref::<UserfaultfdFile>() {
        match request {
            UFFDIO_API => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut api) =
                    try_read_user_value::<UffdioApi>(token, _argp as *const UffdioApi)
                else {
                    return err(SyscallError::EFAULT);
                };
                if api.api != UFFD_API {
                    return err(SyscallError::EINVAL);
                }
                api.features = 0;
                api.ioctls = uffd.enable_api();
                if try_write_user_value(token, _argp as *mut UffdioApi, &api).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            UFFDIO_REGISTER => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut reg) =
                    try_read_user_value::<UffdioRegister>(token, _argp as *const UffdioRegister)
                else {
                    return err(SyscallError::EFAULT);
                };
                if reg.mode != UFFDIO_REGISTER_MODE_MISSING {
                    return err(SyscallError::EINVAL);
                }
                let Ok(ioctls) = uffd.register_missing(
                    reg.range.start as usize,
                    reg.range.len as usize,
                    reg.mode,
                ) else {
                    return err(SyscallError::EINVAL);
                };
                reg.ioctls = ioctls;
                if try_write_user_value(token, _argp as *mut UffdioRegister, &reg).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            UFFDIO_COPY => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut copy) =
                    try_read_user_value::<UffdioCopy>(token, _argp as *const UffdioCopy)
                else {
                    return err(SyscallError::EFAULT);
                };
                let len = copy.len as usize;
                if len == 0 {
                    copy.copy = 0;
                    if try_write_user_value(token, _argp as *mut UffdioCopy, &copy).is_err() {
                        return err(SyscallError::EFAULT);
                    }
                    return 0;
                }
                if len % PAGE_SIZE != 0 {
                    return err(SyscallError::EINVAL);
                }
                const UFFDIO_COPY_MAX_LEN: usize = 64 * 1024 * 1024;
                if len > UFFDIO_COPY_MAX_LEN {
                    return err(SyscallError::ENOMEM);
                }
                let mut data = alloc::vec![0u8; len];
                if try_copy_from_user(token, copy.src as *const u8, &mut data).is_err() {
                    return err(SyscallError::EFAULT);
                }
                {
                    let process = current_process();
                    let inner = process.borrow_mut();
                    let start = copy.dst as usize & !(PAGE_SIZE - 1);
                    let end = ((copy.dst as usize)
                        .saturating_add(len)
                        .saturating_add(PAGE_SIZE - 1))
                        & !(PAGE_SIZE - 1);
                    let mut page = start;
                    while page < end {
                        let mapped = inner
                            .memory_set
                            .translate(VirtAddr::from(page).floor())
                            .map(|pte| pte.is_valid())
                            .unwrap_or(false);
                        if !mapped {
                            match inner.memory_set.resolve_lazy_fault(page, MapPermission::W) {
                                crate::mm::LazyFaultResult::Resolved => {}
                                crate::mm::LazyFaultResult::Oom => {
                                    return err(SyscallError::ENOMEM);
                                }
                                crate::mm::LazyFaultResult::Invalid => {
                                    return err(SyscallError::EFAULT);
                                }
                            }
                        }
                        page += PAGE_SIZE;
                    }
                }
                if try_copy_to_user(token, copy.dst as *mut u8, &data).is_err() {
                    return err(SyscallError::EFAULT);
                }
                copy.copy = len as i64;
                if try_write_user_value(token, _argp as *mut UffdioCopy, &copy).is_err() {
                    return err(SyscallError::EFAULT);
                }
                uffd.finish_copy(
                    copy.dst as usize,
                    len,
                    (copy.mode & UFFDIO_COPY_MODE_DONTWAKE) == 0,
                );
                return 0;
            }
            _ => return ENOTTY,
        }
    }

    if let Some(tty) = file.as_any().downcast_ref::<TtyFile>() {
        match request {
            TCGETS => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let termios = tty.termios();
                if try_write_user_value(token, _argp as *mut LinuxTermios, &termios).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TCSETS | TCSETSW | TCSETSF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(termios) =
                    try_read_user_value::<LinuxTermios>(token, _argp as *const LinuxTermios)
                else {
                    return err(SyscallError::EFAULT);
                };
                tty.set_termios(termios);
                return 0;
            }
            TCSBRK | TCSBRKP | TCXONC => return 0,
            TCGETA => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let termio = tty.termio();
                if try_write_user_value(token, _argp as *mut LinuxTermio, &termio).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TCSETA | TCSETAW | TCSETAF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(termio) =
                    try_read_user_value::<LinuxTermio>(token, _argp as *const LinuxTermio)
                else {
                    return err(SyscallError::EFAULT);
                };
                tty.set_termio(termio);
                return 0;
            }
            TCFLSH => {
                let queue_sel = _argp as i32;
                return if queue_sel == 0 || queue_sel == 1 || queue_sel == 2 {
                    0
                } else {
                    err(SyscallError::EINVAL)
                };
            }
            TIOCGWINSZ | TIOCSWINSZ | TIOCSETD | TIOCGETD => return ENOTTY,
            _ => return ENOTTY,
        }
    }

    if let Some(pty) = file.as_any().downcast_ref::<PtyMasterFile>() {
        match request {
            TCGETS => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let termios = pty.termios();
                if try_write_user_value(token, _argp as *mut LinuxTermios, &termios).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TCSETS | TCSETSW | TCSETSF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(termios) =
                    try_read_user_value::<LinuxTermios>(token, _argp as *const LinuxTermios)
                else {
                    return err(SyscallError::EFAULT);
                };
                pty.set_termios(termios);
                return 0;
            }
            TCSBRK | TCSBRKP | TCXONC => return 0,
            TCGETA => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let termio = pty.termio();
                if try_write_user_value(token, _argp as *mut LinuxTermio, &termio).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TCSETA | TCSETAW | TCSETAF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(termio) =
                    try_read_user_value::<LinuxTermio>(token, _argp as *const LinuxTermio)
                else {
                    return err(SyscallError::EFAULT);
                };
                pty.set_termio(termio);
                return 0;
            }
            TCFLSH => {
                let queue_sel = _argp as i32;
                return if pty.flush_queues(queue_sel) {
                    0
                } else {
                    err(SyscallError::EINVAL)
                };
            }
            TIOCGWINSZ => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let winsize = pty.winsize();
                if try_write_user_value(token, _argp as *mut LinuxWinSize, &winsize).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TIOCSWINSZ => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(winsize) =
                    try_read_user_value::<LinuxWinSize>(token, _argp as *const LinuxWinSize)
                else {
                    return err(SyscallError::EFAULT);
                };
                pty.set_winsize(winsize);
                return 0;
            }
            FIONREAD => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let readable = pty.queued_bytes() as i32;
                if try_write_user_value(token, _argp as *mut i32, &readable).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TIOCGETD => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let line = pty.line_discipline();
                if try_write_user_value(token, _argp as *mut i32, &line).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TIOCSETD => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(line) = try_read_user_value::<i32>(token, _argp as *const i32) else {
                    return err(SyscallError::EFAULT);
                };
                if line == N_HDLC {
                    return err(SyscallError::EINVAL);
                }
                if line != N_TTY {
                    return err(SyscallError::EINVAL);
                }
                pty.set_line_discipline(line);
                return 0;
            }
            TIOCGPTN => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let index = pty.pty_index();
                if try_write_user_value(token, _argp as *mut u32, &index).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TIOCSPTLCK => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(lock_value) = try_read_user_value::<i32>(token, _argp as *const i32)
                else {
                    return err(SyscallError::EFAULT);
                };
                pty.set_locked(lock_value != 0);
                return 0;
            }
            _ => return ENOTTY,
        }
    }

    if let Some(pty) = file.as_any().downcast_ref::<PtySlaveFile>() {
        match request {
            TCGETS => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let termios = pty.termios();
                if try_write_user_value(token, _argp as *mut LinuxTermios, &termios).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TCSETS | TCSETSW | TCSETSF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(termios) =
                    try_read_user_value::<LinuxTermios>(token, _argp as *const LinuxTermios)
                else {
                    return err(SyscallError::EFAULT);
                };
                pty.set_termios(termios);
                return 0;
            }
            TCSBRK | TCSBRKP | TCXONC => return 0,
            TCGETA => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let termio = pty.termio();
                if try_write_user_value(token, _argp as *mut LinuxTermio, &termio).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TCSETA | TCSETAW | TCSETAF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(termio) =
                    try_read_user_value::<LinuxTermio>(token, _argp as *const LinuxTermio)
                else {
                    return err(SyscallError::EFAULT);
                };
                pty.set_termio(termio);
                return 0;
            }
            TCFLSH => {
                let queue_sel = _argp as i32;
                return if pty.flush_queues(queue_sel) {
                    0
                } else {
                    err(SyscallError::EINVAL)
                };
            }
            TIOCGWINSZ => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let winsize = pty.winsize();
                if try_write_user_value(token, _argp as *mut LinuxWinSize, &winsize).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TIOCSWINSZ => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(winsize) =
                    try_read_user_value::<LinuxWinSize>(token, _argp as *const LinuxWinSize)
                else {
                    return err(SyscallError::EFAULT);
                };
                pty.set_winsize(winsize);
                return 0;
            }
            FIONREAD => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let readable = pty.queued_bytes() as i32;
                if try_write_user_value(token, _argp as *mut i32, &readable).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TIOCGETD => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let line = pty.line_discipline();
                if try_write_user_value(token, _argp as *mut i32, &line).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            TIOCSETD => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(line) = try_read_user_value::<i32>(token, _argp as *const i32) else {
                    return err(SyscallError::EFAULT);
                };
                if line == N_HDLC {
                    return err(SyscallError::EINVAL);
                }
                if line != N_TTY {
                    return err(SyscallError::EINVAL);
                }
                pty.set_line_discipline(line);
                return 0;
            }
            _ => return ENOTTY,
        }
    }

    if request == FIONREAD {
        if _argp == 0 {
            return err(SyscallError::EFAULT);
        }
        if let Some(pipe) = file.as_any().downcast_ref::<crate::fs::Pipe>() {
            // Linux reports unread bytes for both read and write pipe fds.
            let readable = pipe.queued_bytes() as i32;
            if try_write_user_value(token, _argp as *mut i32, &readable).is_err() {
                return err(SyscallError::EFAULT);
            }
            return 0;
        }
        let readable = if let Some(pty) = file.as_any().downcast_ref::<PtyMasterFile>() {
            Some(pty.queued_bytes() as i32)
        } else {
            file.as_any()
                .downcast_ref::<PtySlaveFile>()
                .map(|pty| pty.queued_bytes() as i32)
        };
        if let Some(readable) = readable {
            if try_write_user_value(token, _argp as *mut i32, &readable).is_err() {
                return err(SyscallError::EFAULT);
            }
            return 0;
        }
    }

    if let Some(pseudo) = file.as_any().downcast_ref::<crate::fs::PseudoFile>() {
        if request == RNDGETENTCNT && pseudo.kind_tag() == PseudoKindTag::Urandom {
            if _argp == 0 {
                return err(SyscallError::EFAULT);
            }
            let entropy: i32 = 256;
            if try_write_user_value(token, _argp as *mut i32, &entropy).is_err() {
                return err(SyscallError::EFAULT);
            }
            return 0;
        }
    }

    if let Some(os_inode) = file.as_any().downcast_ref::<crate::fs::OSInode>() {
        let ino = os_inode.ext4_inode().inode_num() as u64;
        match request {
            FS_IOC_GETFLAGS => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let flags = crate::syscall::filesystem::inode_fs_flags(ino) as i32;
                if try_write_user_value(token, _argp as *mut i32, &flags).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            FS_IOC_SETFLAGS => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(raw_flags) = try_read_user_value(token, _argp as *const i32) else {
                    return err(SyscallError::EFAULT);
                };
                let allowed = (raw_flags as u32) & (FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL);
                crate::syscall::filesystem::set_inode_fs_flags(ino, allowed);
                return 0;
            }
            _ => {}
        }
    }

    if let Some(tun) = file.as_any().downcast_ref::<crate::fs::TunTapFile>() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct TunIfreq {
            ifr_name: [u8; 16],
            ifr_flags: i16,
        }

        fn tun_ifreq_name(ifr_name: &[u8; 16]) -> Option<alloc::string::String> {
            let mut end = 0usize;
            while end < ifr_name.len() && ifr_name[end] != 0 {
                end += 1;
            }
            let name = core::str::from_utf8(&ifr_name[..end]).ok()?;
            if name.len() >= 16
                || name.contains('/')
                || name.contains(char::from(0))
                || name == "."
                || name == ".."
            {
                return None;
            }
            Some(alloc::string::String::from(name))
        }

        fn tun_ifname_valid(name: &str) -> bool {
            !name.is_empty()
                && name.len() < 16
                && !name.contains('/')
                && !name.contains(char::from(0))
                && name != "."
                && name != ".."
        }

        fn tun_resolve_ifname(
            kind: crate::syscall::net::netdev::NetDeviceKind,
            requested: &str,
        ) -> Result<alloc::string::String, isize> {
            let template = if requested.is_empty() {
                match kind {
                    crate::syscall::net::netdev::NetDeviceKind::Tun => "tun%d",
                    crate::syscall::net::netdev::NetDeviceKind::Tap => "tap%d",
                    _ => return Err(err(SyscallError::EINVAL)),
                }
            } else {
                requested
            };

            if let Some(pos) = template.find("%d") {
                for idx in 0..10_000usize {
                    let name = format!("{}{}{}", &template[..pos], idx, &template[pos + 2..]);
                    if tun_ifname_valid(&name)
                        && crate::syscall::net::netdev::device_snapshot_by_name(&name).is_none()
                    {
                        return Ok(name);
                    }
                }
                return Err(err(SyscallError::ENFILE));
            }

            if !tun_ifname_valid(template) {
                return Err(err(SyscallError::EINVAL));
            }
            Ok(alloc::string::String::from(template))
        }

        fn write_tun_ifreq_name(dst: &mut [u8; 16], name: &[u8]) {
            dst.fill(0);
            let copy_len = core::cmp::min(dst.len() - 1, name.len());
            dst[..copy_len].copy_from_slice(&name[..copy_len]);
        }

        fn tun_attached_name_or_err(
            tun: &crate::fs::TunTapFile,
        ) -> Result<alloc::string::String, isize> {
            tun.attached_name().ok_or_else(|| err(SyscallError::ENODEV))
        }

        fn tun_attached_ifindex_or_err(tun: &crate::fs::TunTapFile) -> Result<i32, isize> {
            tun.attached_ifindex()
                .ok_or_else(|| err(SyscallError::ENODEV))
        }

        fn tun_has_cap_net_admin() -> bool {
            let process = current_process();
            let inner = process.borrow_mut();
            (inner.cap_effective & (1u64 << CAP_NET_ADMIN)) != 0
        }

        fn tun_require_cap_net_admin() -> Result<(), isize> {
            if tun_has_cap_net_admin() {
                Ok(())
            } else {
                Err(err(SyscallError::EPERM))
            }
        }

        fn tun_can_attach_existing(name: &str) -> bool {
            if tun_has_cap_net_admin() {
                return true;
            }
            let (owner, group) = crate::fs::tuntap_link_owner_group(name).unwrap_or((None, None));
            let process = current_process();
            let inner = process.borrow_mut();
            if let Some(owner) = owner
                && inner.euid != owner
            {
                return false;
            }
            if let Some(group) = group
                && inner.egid != group
                && !inner.supplementary_gids.iter().any(|gid| *gid == group)
            {
                return false;
            }
            true
        }

        return match request {
            TUNSETIFF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const TunIfreq) else {
                    return err(SyscallError::EFAULT);
                };
                if tun.attached_ifindex().is_some() {
                    return err(SyscallError::EEXIST);
                }
                let flags = ifr.ifr_flags as u16;
                if (flags & !TUN_SUPPORTED_IFF) != 0 || (flags & (IFF_TUN | IFF_TAP)) == 0 {
                    return err(SyscallError::EINVAL);
                }
                let kind = match flags & 0x000f {
                    IFF_TUN => crate::syscall::net::netdev::NetDeviceKind::Tun,
                    IFF_TAP => crate::syscall::net::netdev::NetDeviceKind::Tap,
                    _ => return err(SyscallError::EINVAL),
                };
                let Some(requested_name) = tun_ifreq_name(&ifr.ifr_name) else {
                    return err(SyscallError::EINVAL);
                };
                let name = match tun_resolve_ifname(kind, &requested_name) {
                    Ok(name) => name,
                    Err(e) => return e,
                };
                let ifindex = if let Some(existing) =
                    crate::syscall::net::netdev::device_snapshot_by_name(&name)
                {
                    if existing.kind != kind {
                        return err(SyscallError::EINVAL);
                    }
                    if (flags & IFF_TUN_EXCL) != 0 {
                        return err(SyscallError::EBUSY);
                    }
                    if !tun_can_attach_existing(&name) {
                        return err(SyscallError::EPERM);
                    }
                    existing.ifindex
                } else {
                    if let Err(e) = tun_require_cap_net_admin() {
                        return e;
                    }
                    let rc = crate::syscall::net::netdev::create_link(&name, kind);
                    if let Err(e) = rc {
                        return e;
                    }
                    let Some(created) = crate::syscall::net::netdev::device_snapshot_by_name(&name)
                    else {
                        return err(SyscallError::ENODEV);
                    };
                    created.ifindex
                };
                tun.attach(ifindex, kind, flags);
                write_tun_ifreq_name(&mut ifr.ifr_name, name.as_bytes());
                if try_write_user_value(token, _argp as *mut TunIfreq, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            TUNSETPERSIST => {
                let _name = match tun_attached_name_or_err(tun) {
                    Ok(name) => name,
                    Err(e) => return e,
                };
                let persistent = _argp != 0;
                tun.set_persistent(persistent);
                0
            }
            TUNGETFEATURES => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                if try_write_user_value(token, _argp as *mut u32, &TUN_SUPPORTED_FEATURES).is_err()
                {
                    err(SyscallError::EFAULT)
                } else {
                    0
                }
            }
            TUNGETIFF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(dev) = tun.attached_device_snapshot() else {
                    return err(SyscallError::ENODEV);
                };
                let mut ifr = TunIfreq {
                    ifr_name: [0; 16],
                    ifr_flags: match dev.kind {
                        crate::syscall::net::netdev::NetDeviceKind::Tun => IFF_TUN as i16,
                        crate::syscall::net::netdev::NetDeviceKind::Tap => IFF_TAP as i16,
                        _ => return err(SyscallError::EINVAL),
                    },
                };
                ifr.ifr_flags |= (tun.flags() & (IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR)) as i16;
                write_tun_ifreq_name(&mut ifr.ifr_name, dev.name.as_bytes());
                if try_write_user_value(token, _argp as *mut TunIfreq, &ifr).is_err() {
                    err(SyscallError::EFAULT)
                } else {
                    0
                }
            }
            TUNGETVNETHDRSZ => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let _ = match tun_attached_name_or_err(tun) {
                    Ok(name) => name,
                    Err(e) => return e,
                };
                let size = tun.vnet_hdr_size();
                if try_write_user_value(token, _argp as *mut i32, &size).is_err() {
                    err(SyscallError::EFAULT)
                } else {
                    0
                }
            }
            TUNSETOWNER => {
                let _ = match tun_attached_name_or_err(tun) {
                    Ok(name) => name,
                    Err(e) => return e,
                };
                if _argp >= u32::MAX as usize {
                    return err(SyscallError::EINVAL);
                }
                tun.set_owner(_argp as u32);
                0
            }
            TUNSETGROUP => {
                let _ = match tun_attached_name_or_err(tun) {
                    Ok(name) => name,
                    Err(e) => return e,
                };
                if _argp >= u32::MAX as usize {
                    return err(SyscallError::EINVAL);
                }
                tun.set_group(_argp as u32);
                0
            }
            TUNSETLINK => {
                let ifindex = match tun_attached_ifindex_or_err(tun) {
                    Ok(ifindex) => ifindex,
                    Err(e) => return e,
                };
                if _argp > u16::MAX as usize {
                    return err(SyscallError::EINVAL);
                }
                match crate::syscall::net::netdev::set_link_type_by_global_ifindex(
                    ifindex,
                    _argp as u16,
                ) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            TUNSETOFFLOAD => {
                let _ = match tun_attached_name_or_err(tun) {
                    Ok(name) => name,
                    Err(e) => return e,
                };
                if _argp != 0 {
                    return err(SyscallError::EOPNOTSUPP);
                }
                tun.set_offload_flags(0);
                0
            }
            TUNSETVNETHDRSZ => {
                let _ = match tun_attached_name_or_err(tun) {
                    Ok(name) => name,
                    Err(e) => return e,
                };
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(size) = try_read_user_value::<i32>(token, _argp as *const i32) else {
                    return err(SyscallError::EFAULT);
                };
                if size < VIRTIO_NET_HDR_LEN {
                    return err(SyscallError::EINVAL);
                }
                tun.set_vnet_hdr_size(size);
                0
            }
            TUNSETQUEUE => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(_ifr) = try_read_user_value::<TunIfreq>(token, _argp as *const TunIfreq)
                else {
                    return err(SyscallError::EFAULT);
                };
                err(SyscallError::EOPNOTSUPP)
            }
            _ => ENOTTY,
        };
    }

    if crate::syscall::net::is_socket_file(file.as_ref()) {
        let net_sock = file.as_any().downcast_ref::<crate::fs::NetSocketFile>();
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
        struct RtEntry {
            rt_pad1: usize,
            rt_dst: SockAddr,
            rt_gateway: SockAddr,
            rt_genmask: SockAddr,
            rt_flags: u16,
            rt_pad2: i16,
            rt_pad3: usize,
            rt_pad4: usize,
            rt_metric: i16,
            rt_dev: usize,
            rt_mtu: usize,
            rt_window: usize,
            rt_irtt: u16,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct IfreqAddr {
            ifr_name: [u8; 16],
            ifr_addr: SockAddr,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct IfreqRaw {
            ifr_name: [u8; 16],
            ifr_ifru: [u8; 24],
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct IfreqIndex {
            ifr_name: [u8; 16],
            ifr_ifindex: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct ArpReq {
            arp_pa: SockAddr,
            arp_ha: SockAddr,
            arp_flags: i32,
            arp_netmask: SockAddr,
            arp_dev: [u8; 16],
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct SockTimeval {
            tv_sec: i64,
            tv_usec: i64,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct SockTimespec {
            tv_sec: i64,
            tv_nsec: i64,
        }

        fn has_effective_cap(cap: usize) -> bool {
            let process = current_process();
            let inner = process.borrow_mut();
            (inner.cap_effective & (1u64 << cap)) != 0
        }

        fn require_cap_net_admin() -> Result<(), isize> {
            if has_effective_cap(CAP_NET_ADMIN) {
                Ok(())
            } else {
                Err(err(SyscallError::EPERM))
            }
        }

        fn ifreq_full_name(ifr_name: &[u8; 16]) -> Option<&str> {
            let mut end = 0usize;
            while end < ifr_name.len() && ifr_name[end] != 0 {
                end += 1;
            }
            core::str::from_utf8(&ifr_name[..end]).ok()
        }

        fn ifreq_name(ifr_name: &[u8; 16]) -> Option<&str> {
            let raw = ifreq_full_name(ifr_name)?;
            let end = raw
                .as_bytes()
                .iter()
                .position(|b| *b == b':')
                .unwrap_or(raw.len());
            Some(&raw[..end])
        }

        fn ifreq_alias_name(ifr_name: &[u8; 16]) -> Option<&str> {
            let raw = ifreq_full_name(ifr_name)?;
            raw.as_bytes().contains(&b':').then_some(raw)
        }

        fn ifreq_lookup_index(ifr_name: &[u8; 16]) -> Option<i32> {
            crate::syscall::net::netdev::ifindex_by_name(ifreq_name(ifr_name)?)
        }

        fn ifreq_lookup_dev(
            ifr_name: &[u8; 16],
        ) -> Option<crate::syscall::net::netdev::NetDeviceSnapshot> {
            crate::syscall::net::netdev::device_snapshot_by_name(ifreq_name(ifr_name)?)
        }

        fn ifreq_lookup_addr<'a>(
            dev: &'a crate::syscall::net::netdev::NetDeviceSnapshot,
            ifr_name: &[u8; 16],
        ) -> Option<&'a crate::syscall::net::netdev::Ipv4AddrEntry> {
            if let Some(label) = ifreq_alias_name(ifr_name) {
                dev.addrs.iter().find(|addr| {
                    crate::syscall::net::netdev::ipv4_addr_label(&dev.name, addr) == label
                })
            } else {
                dev.addrs.first()
            }
        }

        fn sockaddr_in_addr(addr: [u8; 4]) -> SockAddr {
            let mut sa_data = [0u8; 14];
            sa_data[2..6].copy_from_slice(&addr);
            SockAddr {
                sa_family: AF_INET,
                sa_data,
            }
        }

        fn ifreq_raw_with_addr(name: &[u8], addr: SockAddr) -> IfreqRaw {
            let mut ifr_name = [0u8; 16];
            write_ifreq_name(&mut ifr_name, name);
            let mut ifr_ifru = [0u8; 24];
            ifr_ifru[..2].copy_from_slice(&addr.sa_family.to_ne_bytes());
            ifr_ifru[2..16].copy_from_slice(&addr.sa_data);
            IfreqRaw { ifr_name, ifr_ifru }
        }

        fn sockaddr_ipv4_addr(addr: &SockAddr) -> [u8; 4] {
            [
                addr.sa_data[2],
                addr.sa_data[3],
                addr.sa_data[4],
                addr.sa_data[5],
            ]
        }

        fn sockaddr_ipv4_addr_checked(addr: &SockAddr) -> Result<[u8; 4], isize> {
            if addr.sa_family != AF_INET {
                return Err(err(SyscallError::EINVAL));
            }
            Ok(sockaddr_ipv4_addr(addr))
        }

        fn sockaddr_lladdr(addr: &SockAddr) -> [u8; 6] {
            [
                addr.sa_data[0],
                addr.sa_data[1],
                addr.sa_data[2],
                addr.sa_data[3],
                addr.sa_data[4],
                addr.sa_data[5],
            ]
        }

        fn prefix_to_netmask(prefix_len: u8) -> [u8; 4] {
            let raw = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            raw.to_be_bytes()
        }

        fn netmask_to_prefix(mask: [u8; 4]) -> Option<u8> {
            let raw = u32::from_be_bytes(mask);
            let prefix = raw.leading_ones() as u8;
            let expected = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            if raw == expected { Some(prefix) } else { None }
        }

        fn route_sockaddr_ipv4(addr: &SockAddr) -> Result<[u8; 4], isize> {
            if addr.sa_family != AF_INET {
                return Err(err(SyscallError::EAFNOSUPPORT));
            }
            Ok(sockaddr_ipv4_addr(addr))
        }

        fn route_sockaddr_ipv4_optional(addr: &SockAddr) -> Result<Option<[u8; 4]>, isize> {
            let raw = sockaddr_ipv4_addr(addr);
            if addr.sa_family == 0 && raw == [0; 4] {
                return Ok(None);
            }
            if addr.sa_family != AF_INET {
                return Err(err(SyscallError::EAFNOSUPPORT));
            }
            Ok(Some(raw))
        }

        fn route_prefix_from_mask(dst: [u8; 4], mask: [u8; 4]) -> Result<u8, isize> {
            let Some(prefix_len) = netmask_to_prefix(mask) else {
                return Err(err(SyscallError::EINVAL));
            };
            let dst = u32::from_be_bytes(dst);
            let mask = u32::from_be_bytes(mask);
            if dst & !mask != 0 {
                return Err(err(SyscallError::EINVAL));
            }
            Ok(prefix_len)
        }

        fn read_route_dev_name(token: usize, user_ptr: usize) -> Result<Option<String>, isize> {
            if user_ptr == 0 {
                return Ok(None);
            }
            let mut raw = [0u8; 16];
            for (offset, byte) in raw.iter_mut().take(15).enumerate() {
                let Some(ch) = try_read_user_value(token, (user_ptr + offset) as *const u8) else {
                    return Err(err(SyscallError::EFAULT));
                };
                *byte = ch;
                if ch == 0 {
                    break;
                }
            }
            let Some(name) = ifreq_name(&raw) else {
                return Err(err(SyscallError::EINVAL));
            };
            Ok(Some(String::from(name)))
        }

        fn inet_abc_prefix(addr: [u8; 4]) -> Option<u8> {
            match addr[0] {
                0 => Some(0),
                1..=127 => Some(8),
                128..=191 => Some(16),
                192..=223 => Some(24),
                224..=239 => None,
                240..=254 => Some(32),
                255 if addr == [255; 4] => Some(0),
                255 => Some(32),
            }
        }

        fn write_ifreq_name(dst: &mut [u8; 16], name: &[u8]) {
            dst.fill(0);
            let copy_len = core::cmp::min(dst.len() - 1, name.len());
            dst[..copy_len].copy_from_slice(&name[..copy_len]);
        }

        fn arpreq_ifindex(arp_dev: &[u8; 16]) -> Result<Option<i32>, isize> {
            let Some(name) = ifreq_name(arp_dev) else {
                return Err(err(SyscallError::EINVAL));
            };
            if name.is_empty() {
                return Ok(None);
            }
            crate::syscall::net::netdev::ifindex_by_name(name)
                .map(Some)
                .ok_or_else(|| err(SyscallError::ENODEV))
        }

        fn write_socket_timestamp(
            file: &(dyn crate::fs::File + Send + Sync),
            token: usize,
            argp: usize,
            nsec: bool,
        ) -> isize {
            let Some(stamp) = crate::syscall::net::socket_last_timestamp(file) else {
                return err(SyscallError::ENOENT);
            };
            if argp == 0 {
                return err(SyscallError::EFAULT);
            }
            if nsec {
                let ts = SockTimespec {
                    tv_sec: stamp.sec,
                    tv_nsec: stamp.nsec,
                };
                if try_write_user_value(token, argp as *mut SockTimespec, &ts).is_err() {
                    err(SyscallError::EFAULT)
                } else {
                    0
                }
            } else {
                let tv = SockTimeval {
                    tv_sec: stamp.sec,
                    tv_usec: stamp.nsec / 1_000,
                };
                if try_write_user_value(token, argp as *mut SockTimeval, &tv).is_err() {
                    err(SyscallError::EFAULT)
                } else {
                    0
                }
            }
        }

        return match request {
            SIOCGSTAMP_OLD | SIOCGSTAMP_NEW => {
                write_socket_timestamp(file.as_ref(), token, _argp, false)
            }
            SIOCGSTAMPNS_OLD | SIOCGSTAMPNS_NEW => {
                write_socket_timestamp(file.as_ref(), token, _argp, true)
            }
            SIOCATMARK => {
                if _argp == 0 {
                    err(SyscallError::EFAULT)
                } else if net_sock.is_some_and(|sock| sock.kind() == crate::fs::NetSocketKind::Udp)
                {
                    ENOTTY
                } else if try_write_user_value(token, _argp as *mut i32, &0i32).is_err() {
                    err(SyscallError::EFAULT)
                } else {
                    0
                }
            }
            SIOCADDRT | SIOCDELRT => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(rt) = try_read_user_value(token, _argp as *const RtEntry) else {
                    return err(SyscallError::EFAULT);
                };
                let dst = match route_sockaddr_ipv4(&rt.rt_dst) {
                    Ok(addr) => addr,
                    Err(e) => return e,
                };
                let prefix_len = if (rt.rt_flags & RTF_HOST) != 0 {
                    32
                } else {
                    let mask = match route_sockaddr_ipv4_optional(&rt.rt_genmask) {
                        Ok(Some(mask)) => mask,
                        Ok(None) => [0; 4],
                        Err(e) => return e,
                    };
                    match route_prefix_from_mask(dst, mask) {
                        Ok(prefix_len) => prefix_len,
                        Err(e) => return e,
                    }
                };
                let gateway = match route_sockaddr_ipv4_optional(&rt.rt_gateway) {
                    Ok(gateway) => gateway,
                    Err(e) => return e,
                };
                if (rt.rt_flags & RTF_GATEWAY) != 0 && gateway.is_none() {
                    return err(SyscallError::EINVAL);
                }
                let dev_name = match read_route_dev_name(token, rt.rt_dev) {
                    Ok(name) => name,
                    Err(e) => return e,
                };
                let ifindex = if let Some(name) = dev_name.as_deref() {
                    match crate::syscall::net::netdev::ifindex_by_name(name) {
                        Some(ifindex) => Some(ifindex),
                        None => return err(SyscallError::ENODEV),
                    }
                } else {
                    let ns_id = current_process().net_namespace_id();
                    crate::syscall::net::netdev::route_ifindex_for_gateway_in_namespace(
                        ns_id, gateway,
                    )
                };
                match request {
                    SIOCADDRT => {
                        let Some(ifindex) = ifindex else {
                            return err(SyscallError::ENODEV);
                        };
                        match crate::syscall::net::netdev::add_route(
                            dst, prefix_len, gateway, ifindex, true, false, false,
                        ) {
                            Ok(()) => 0,
                            Err(e) => e,
                        }
                    }
                    SIOCDELRT => {
                        match crate::syscall::net::netdev::del_route(
                            dst, prefix_len, gateway, ifindex,
                        ) {
                            Ok(()) => 0,
                            Err(e) => e,
                        }
                    }
                    _ => err(SyscallError::EINVAL),
                }
            }
            SIOCGIFCONF => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifc) = try_read_user_value(token, _argp as *const Ifconf) else {
                    return err(SyscallError::EFAULT);
                };
                if ifc.ifc_buf == 0 {
                    return err(SyscallError::EFAULT);
                }
                let cap = core::cmp::max(ifc.ifc_len, 0) as usize / size_of::<IfreqRaw>();
                let mut written = 0usize;
                for dev in crate::syscall::net::netdev::devices_snapshot() {
                    for addr in &dev.addrs {
                        if written >= cap {
                            break;
                        }
                        let label = crate::syscall::net::netdev::ipv4_addr_label(&dev.name, addr);
                        let ifr =
                            ifreq_raw_with_addr(label.as_bytes(), sockaddr_in_addr(addr.addr));
                        let dst = (ifc.ifc_buf + written * size_of::<IfreqRaw>()) as *mut IfreqRaw;
                        if try_write_user_value(token, dst, &ifr).is_err() {
                            return err(SyscallError::EFAULT);
                        }
                        written += 1;
                    }
                    if written >= cap {
                        break;
                    }
                }
                ifc.ifc_len = (written * size_of::<IfreqRaw>()) as i32;
                if try_write_user_value(token, _argp as *mut Ifconf, &ifc).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCGIFFLAGS => {
                if _argp == 0 {
                    err(SyscallError::EFAULT)
                } else {
                    let Some(ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                        return err(SyscallError::EFAULT);
                    };
                    let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                        return err(SyscallError::ENODEV);
                    };
                    let flags = dev.flags as i16;
                    if try_write_user_value(token, (_argp + 16) as *mut i16, &flags).is_err() {
                        err(SyscallError::EFAULT)
                    } else {
                        0
                    }
                }
            }
            SIOCGIFADDR => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let Some(addr) = ifreq_lookup_addr(&dev, &ifr.ifr_name) else {
                    return err(SyscallError::EADDRNOTAVAIL);
                };
                ifr.ifr_addr = sockaddr_in_addr(addr.addr);
                if try_write_user_value(token, _argp as *mut IfreqAddr, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFADDR => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let addr = match sockaddr_ipv4_addr_checked(&ifr.ifr_addr) {
                    Ok(addr) => addr,
                    Err(e) => return e,
                };
                let Some(prefix_len) = inet_abc_prefix(addr) else {
                    return err(SyscallError::EINVAL);
                };
                let result = if let Some(label) = ifreq_alias_name(&ifr.ifr_name) {
                    crate::syscall::net::netdev::add_labeled_ipv4_addr(
                        index, label, addr, prefix_len, 0,
                    )
                } else {
                    crate::syscall::net::netdev::set_primary_ipv4_addr(index, addr, prefix_len, 0)
                };
                match result {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCDIFADDR => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let result = if let Some(label) = ifreq_alias_name(&ifr.ifr_name) {
                    crate::syscall::net::netdev::del_ipv4_addr_by_label(index, label)
                } else {
                    let addr = match sockaddr_ipv4_addr_checked(&ifr.ifr_addr) {
                        Ok(addr) => addr,
                        Err(e) => return e,
                    };
                    crate::syscall::net::netdev::del_ipv4_addr_any_prefix(index, addr)
                };
                match result {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCGIFDSTADDR => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let Some(addr) = ifreq_lookup_addr(&dev, &ifr.ifr_name) else {
                    return err(SyscallError::EADDRNOTAVAIL);
                };
                ifr.ifr_addr = sockaddr_in_addr(addr.peer_addr);
                if try_write_user_value(token, _argp as *mut IfreqAddr, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFDSTADDR => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let addr = match sockaddr_ipv4_addr_checked(&ifr.ifr_addr) {
                    Ok(addr) => addr,
                    Err(e) => return e,
                };
                if inet_abc_prefix(addr).is_none() {
                    return err(SyscallError::EINVAL);
                }
                match crate::syscall::net::netdev::set_primary_ipv4_peer_addr(index, addr) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCGIFBRDADDR => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let Some(addr) = ifreq_lookup_addr(&dev, &ifr.ifr_name) else {
                    return err(SyscallError::EADDRNOTAVAIL);
                };
                let broadcast = addr.broadcast_addr.unwrap_or([0; 4]);
                ifr.ifr_addr = sockaddr_in_addr(broadcast);
                if try_write_user_value(token, _argp as *mut IfreqAddr, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFBRDADDR => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let addr = match sockaddr_ipv4_addr_checked(&ifr.ifr_addr) {
                    Ok(addr) => addr,
                    Err(e) => return e,
                };
                match crate::syscall::net::netdev::set_primary_ipv4_broadcast_addr(index, addr) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCGIFNETMASK => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let Some(addr) = ifreq_lookup_addr(&dev, &ifr.ifr_name) else {
                    return err(SyscallError::EADDRNOTAVAIL);
                };
                let prefix_len = addr.prefix_len;
                ifr.ifr_addr = sockaddr_in_addr(prefix_to_netmask(prefix_len));
                if try_write_user_value(token, _argp as *mut IfreqAddr, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFNETMASK => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let mask = match sockaddr_ipv4_addr_checked(&ifr.ifr_addr) {
                    Ok(addr) => addr,
                    Err(e) => return e,
                };
                let Some(prefix_len) = netmask_to_prefix(mask) else {
                    return err(SyscallError::EINVAL);
                };
                let result = if let Some(label) = ifreq_alias_name(&ifr.ifr_name) {
                    crate::syscall::net::netdev::set_labeled_ipv4_prefix(index, label, prefix_len)
                } else {
                    crate::syscall::net::netdev::set_primary_ipv4_prefix(index, prefix_len)
                };
                match result {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCGIFMETRIC => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                    return err(SyscallError::EFAULT);
                };
                if ifreq_lookup_index(&ifr.ifr_name).is_none() {
                    return err(SyscallError::ENODEV);
                }
                let metric = 0i32;
                if try_write_user_value(token, (_argp + 16) as *mut i32, &metric).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFMETRIC => err(SyscallError::EOPNOTSUPP),
            SIOCGIFINDEX => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                    return err(SyscallError::EFAULT);
                };
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                ifr.ifr_ifindex = index;
                if try_write_user_value(token, _argp as *mut IfreqIndex, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCGIFNAME => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                    return err(SyscallError::EFAULT);
                };
                match ifr.ifr_ifindex {
                    index => {
                        let Some(name) = crate::syscall::net::netdev::name_by_ifindex(index) else {
                            return err(SyscallError::ENXIO);
                        };
                        write_ifreq_name(&mut ifr.ifr_name, name.as_bytes());
                    }
                }
                if try_write_user_value(token, _argp as *mut IfreqIndex, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFNAME => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqRaw) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let mut new_name_raw = [0u8; 16];
                new_name_raw.copy_from_slice(&ifr.ifr_ifru[..16]);
                let Some(new_name) = ifreq_name(&new_name_raw) else {
                    return err(SyscallError::EINVAL);
                };
                match crate::syscall::net::netdev::set_link_with_name(
                    index,
                    Some(new_name),
                    None,
                    None,
                    None,
                ) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCGIFHWADDR => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                ifr.ifr_addr.sa_family = dev.link_type;
                ifr.ifr_addr.sa_data = [0; 14];
                ifr.ifr_addr.sa_data[..6].copy_from_slice(&dev.hwaddr);
                if try_write_user_value(token, _argp as *mut IfreqAddr, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCGIFMTU => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                    return err(SyscallError::EFAULT);
                };
                let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                ifr.ifr_ifindex = dev.mtu as i32;
                if try_write_user_value(token, _argp as *mut IfreqIndex, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFMTU => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                if ifr.ifr_ifindex < 0 {
                    return err(SyscallError::EINVAL);
                }
                match crate::syscall::net::netdev::set_link(
                    index,
                    Some(ifr.ifr_ifindex as u32),
                    None,
                    None,
                ) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCGIFTXQLEN => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                    return err(SyscallError::EFAULT);
                };
                let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                ifr.ifr_ifindex = dev.tx_queue_len as i32;
                if try_write_user_value(token, _argp as *mut IfreqIndex, &ifr).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFTXQLEN => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                if ifr.ifr_ifindex < 0 {
                    return err(SyscallError::EINVAL);
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                match crate::syscall::net::netdev::set_link(
                    index,
                    None,
                    Some(ifr.ifr_ifindex as u32),
                    None,
                ) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCETHTOOL => err(SyscallError::EOPNOTSUPP),
            SIOCGIFMAP => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                    return err(SyscallError::EFAULT);
                };
                if ifreq_lookup_index(&ifr.ifr_name).is_none() {
                    return err(SyscallError::ENODEV);
                }
                let ifmap = [0u8; 24];
                if try_copy_to_user(token, (_argp + 16) as *mut u8, &ifmap).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCSIFMAP => err(SyscallError::EOPNOTSUPP),
            SIOCSIFFLAGS => {
                if _argp == 0 {
                    err(SyscallError::EFAULT)
                } else {
                    let Some(ifr) = try_read_user_value(token, _argp as *const IfreqIndex) else {
                        return err(SyscallError::EFAULT);
                    };
                    if let Err(e) = require_cap_net_admin() {
                        return e;
                    }
                    let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                        return err(SyscallError::ENODEV);
                    };
                    let Some(flags) = try_read_user_value::<i16>(token, (_argp + 16) as *const i16)
                    else {
                        return err(SyscallError::EFAULT);
                    };
                    let result = if let Some(label) = ifreq_alias_name(&ifr.ifr_name) {
                        if (flags as u16 as u32 & crate::syscall::net::netdev::IFF_UP) == 0 {
                            crate::syscall::net::netdev::del_ipv4_addr_by_label(index, label)
                        } else {
                            let Some(dev) = ifreq_lookup_dev(&ifr.ifr_name) else {
                                return err(SyscallError::ENODEV);
                            };
                            if ifreq_lookup_addr(&dev, &ifr.ifr_name).is_some() {
                                Ok(())
                            } else {
                                Err(err(SyscallError::EADDRNOTAVAIL))
                            }
                        }
                    } else {
                        crate::syscall::net::netdev::set_link(
                            index,
                            None,
                            None,
                            Some((flags as u32, 0xffff)),
                        )
                    };
                    match result {
                        Ok(()) => 0,
                        Err(e) => e,
                    }
                }
            }
            SIOCADDMULTI | SIOCDELMULTI => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ifr) = try_read_user_value(token, _argp as *const IfreqAddr) else {
                    return err(SyscallError::EFAULT);
                };
                if let Err(e) = require_cap_net_admin() {
                    return e;
                }
                let Some(index) = ifreq_lookup_index(&ifr.ifr_name) else {
                    return err(SyscallError::ENODEV);
                };
                let mac = [
                    ifr.ifr_addr.sa_data[0],
                    ifr.ifr_addr.sa_data[1],
                    ifr.ifr_addr.sa_data[2],
                    ifr.ifr_addr.sa_data[3],
                    ifr.ifr_addr.sa_data[4],
                    ifr.ifr_addr.sa_data[5],
                ];
                let result = if request == SIOCADDMULTI {
                    crate::syscall::net::netdev::add_maddr(index, mac)
                } else {
                    crate::syscall::net::netdev::del_maddr(index, mac)
                };
                match result {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            SIOCSARP | SIOCGARP | SIOCDARP => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(mut req) = try_read_user_value(token, _argp as *const ArpReq) else {
                    return err(SyscallError::EFAULT);
                };
                if matches!(request, SIOCSARP | SIOCDARP)
                    && let Err(e) = require_cap_net_admin()
                {
                    return e;
                }
                if req.arp_pa.sa_family != AF_INET {
                    return err(SyscallError::EAFNOSUPPORT);
                }
                let dst = sockaddr_ipv4_addr(&req.arp_pa);
                let ifindex = match arpreq_ifindex(&req.arp_dev) {
                    Ok(ifindex) => ifindex,
                    Err(e) => return e,
                };
                match request {
                    SIOCSARP => {
                        let Some(ifindex) = ifindex.or_else(|| {
                            crate::syscall::net::netdev::learn_ipv4_neighbor(None, dst)
                                .map(|(dev, _)| dev.ifindex)
                        }) else {
                            return err(SyscallError::ENODEV);
                        };
                        let lladdr = sockaddr_lladdr(&req.arp_ha);
                        match crate::syscall::net::netdev::add_neigh(ifindex, dst, lladdr) {
                            Ok(()) => 0,
                            Err(e) => e,
                        }
                    }
                    SIOCGARP => {
                        let Some(neigh) = crate::syscall::net::netdev::neigh_snapshot(ifindex, dst)
                        else {
                            return err(SyscallError::ENXIO);
                        };
                        let Some(dev) =
                            crate::syscall::net::netdev::device_snapshot_by_index(neigh.ifindex)
                        else {
                            return err(SyscallError::ENODEV);
                        };
                        req.arp_ha.sa_family = dev.link_type;
                        req.arp_ha.sa_data = [0; 14];
                        req.arp_ha.sa_data[..6].copy_from_slice(&neigh.lladdr);
                        req.arp_flags |= ATF_COM;
                        if req.arp_dev[0] == 0 {
                            write_ifreq_name(&mut req.arp_dev, dev.name.as_bytes());
                        }
                        if try_write_user_value(token, _argp as *mut ArpReq, &req).is_err() {
                            err(SyscallError::EFAULT)
                        } else {
                            0
                        }
                    }
                    SIOCDARP => {
                        let Some(ifindex) = ifindex.or_else(|| {
                            crate::syscall::net::netdev::neigh_snapshot(None, dst)
                                .map(|entry| entry.ifindex)
                        }) else {
                            return err(SyscallError::ENXIO);
                        };
                        match crate::syscall::net::netdev::del_neigh(ifindex, dst) {
                            Ok(()) => 0,
                            Err(e) if e == err(SyscallError::ENOENT) => err(SyscallError::ENXIO),
                            Err(e) => e,
                        }
                    }
                    _ => unreachable!(),
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
        match request {
            BLKROGET => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let ro: i32 = if pseudo_block_is_read_only() { 1 } else { 0 };
                if try_write_user_value(token, _argp as *mut i32, &ro).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            BLKROSET => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let Some(ro) = try_read_user_value::<i32>(token, _argp as *const i32) else {
                    return err(SyscallError::EFAULT);
                };
                pseudo_block_set_read_only(ro != 0);
                return 0;
            }
            BLKRAGET => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let ra = pseudo_block_read_ahead() as usize;
                if try_write_user_value(token, _argp as *mut usize, &ra).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            BLKRASET => {
                pseudo_block_set_read_ahead(_argp as u64);
                return 0;
            }
            BLKGETSIZE64 | BLKGETSIZE64_COMPAT => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                if try_write_user_value(token, _argp as *mut u64, &PSEUDO_ROOT_DEV_BYTES).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            BLKGETSIZE => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                let sectors: usize =
                    (PSEUDO_ROOT_DEV_BYTES / PSEUDO_ROOT_DEV_SECTOR_SIZE as u64) as usize;
                if try_write_user_value(token, _argp as *mut usize, &sectors).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            BLKSSZGET => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                if try_write_user_value(token, _argp as *mut u32, &PSEUDO_ROOT_DEV_SECTOR_SIZE)
                    .is_err()
                {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            BLKPBSZGET => {
                if _argp == 0 {
                    return err(SyscallError::EFAULT);
                }
                if try_write_user_value(token, _argp as *mut u32, &PSEUDO_ROOT_DEV_PHYS_BLOCK_SIZE)
                    .is_err()
                {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
            LOOP_CLR_FD => {
                // `/dev/root` is a pseudo block device, not an attached loop device.
                // Linux loop release helpers treat ENXIO here as "nothing attached".
                return err(SyscallError::ENXIO);
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
