use crate::{
    config::PAGE_SIZE,
    fs::{
        LinuxTermio, LinuxTermios, PseudoKindTag, PtyMasterFile, PtySlaveFile, TtyFile,
        UserfaultfdFile, pseudo_block_is_read_only, pseudo_block_read_ahead,
        pseudo_block_set_read_ahead, pseudo_block_set_read_only,
    },
    mm::{
        MapPermission, VirtAddr, try_copy_from_user, try_copy_to_user, try_read_user_value,
        try_write_user_value, write_user_value,
    },
    syscall::error::{SyscallError, err},
    task::processor::{current_files, current_process},
    trap::get_current_token,
};
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
    const TCFLSH: usize = 0x540b;
    const TIOCGPTN: usize = 0x8004_5430;
    const TIOCSPTLCK: usize = 0x4004_5431;
    const UFFD_API: u64 = 0xAA;
    const UFFDIO_API: usize = 0xc018_aa3f;
    const UFFDIO_REGISTER: usize = 0xc020_aa00;
    const UFFDIO_COPY: usize = 0xc028_aa03;
    const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
    const UFFDIO_COPY_MODE_DONTWAKE: u64 = 1 << 0;
    const FIONREAD: usize = 0x541B;
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

    let file = current_files().lock().get_file(fd);
    let Some(file) = file else {
        return EBADF;
    };
    // Some libcs pass ioctl request as signed int (sign-extended on rv64).
    // Compare on low 32 bits to accept both calling conventions.
    let request = _request & 0xffff_ffffusize;
    let token = get_current_token();

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
                    let mut inner = process.borrow_mut();
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
                return if queue_sel == 0 || queue_sel == 1 || queue_sel == 2 {
                    0
                } else {
                    err(SyscallError::EINVAL)
                };
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
                return if queue_sel == 0 || queue_sel == 1 || queue_sel == 2 {
                    0
                } else {
                    err(SyscallError::EINVAL)
                };
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
                    err(SyscallError::EFAULT)
                } else if sock.kind() == crate::fs::NetSocketKind::Udp {
                    ENOTTY
                } else if try_write_user_value(token, _argp as *mut i32, &0i32).is_err() {
                    err(SyscallError::EFAULT)
                } else {
                    0
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
                        return err(SyscallError::EFAULT);
                    }
                    ifc.ifc_len = size_of::<IfreqAddr>() as i32;
                } else {
                    ifc.ifc_len = 0;
                }
                if try_write_user_value(token, _argp as *mut Ifconf, &ifc).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            }
            SIOCGIFFLAGS => {
                if _argp == 0 {
                    err(SyscallError::EFAULT)
                } else {
                    let flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
                    if try_write_user_value(token, (_argp + 16) as *mut i16, &flags).is_err() {
                        err(SyscallError::EFAULT)
                    } else {
                        0
                    }
                }
            }
            SIOCSIFFLAGS => {
                if _argp == 0 {
                    err(SyscallError::EFAULT)
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
