use crate::syscall::error::{SyscallError, err};
use core::mem::size_of;

use crate::{
    fs::make_socketpair_with_type, mm::try_write_user_value,
    task::processor::current_files_and_nofile_limit, trap::get_current_token,
};

// Linux errno (negative return in kernel ABI).

const AF_UNIX: usize = 1;
const AF_INET: usize = 2;
const SOCK_STREAM: usize = 1;
const SOCK_DGRAM: usize = 2;
const SOCK_RAW: usize = 3;
const SOCK_SEQPACKET: usize = 5;
const SOCK_TYPE_MASK: usize = 0xf;
const SOCK_NONBLOCK: usize = 0x800;
const SOCK_CLOEXEC: usize = 0x80000;
const O_NONBLOCK: u32 = 0x800;
const FD_CLOEXEC: u32 = 1;

/// Linux `socketpair(2)` (syscall 199 on riscv64).
///
/// Supports connected Unix stream, datagram, and sequenced-packet pairs.
pub fn syscall_socketpair(domain: usize, type_: usize, protocol: usize, sv_ptr: usize) -> isize {
    let flags = type_ & !SOCK_TYPE_MASK;
    if (flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK)) != 0 {
        return err(SyscallError::EINVAL);
    }
    if sv_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let sock_type = type_ & SOCK_TYPE_MASK;
    if !matches!(
        sock_type,
        SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET
    ) {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    if try_write_user_value(token, sv_ptr as *mut i32, &0i32).is_err()
        || try_write_user_value(token, (sv_ptr + size_of::<i32>()) as *mut i32, &0i32).is_err()
    {
        return err(SyscallError::EFAULT);
    }
    match domain {
        AF_UNIX => {
            if protocol != 0 {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            if !matches!(sock_type, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
                return err(SyscallError::EPROTONOSUPPORT);
            }
        }
        AF_INET => {
            return match (sock_type, protocol) {
                (SOCK_STREAM, 6) | (SOCK_DGRAM, 17) => err(SyscallError::EOPNOTSUPP),
                (SOCK_DGRAM, 6) | (SOCK_STREAM, 1) | (SOCK_RAW, 0) => {
                    err(SyscallError::EPROTONOSUPPORT)
                }
                _ => err(SyscallError::EPROTONOSUPPORT),
            };
        }
        _ => return err(SyscallError::EAFNOSUPPORT),
    }
    let cloexec = (type_ & SOCK_CLOEXEC) != 0;
    let nonblock = (type_ & SOCK_NONBLOCK) != 0;

    let (end0, end1) = make_socketpair_with_type(sock_type);

    let mut descriptor_flags = 0u32;
    if cloexec {
        descriptor_flags |= FD_CLOEXEC;
    }
    if nonblock {
        descriptor_flags |= O_NONBLOCK;
    }
    let (files, limit) = current_files_and_nofile_limit();
    let mut files = files.lock();
    let fd0 = match files.install_fd(end0, descriptor_flags, limit) {
        Ok(fd) => fd,
        Err(rejected) => {
            drop(files);
            rejected.discard();
            return err(SyscallError::EMFILE);
        }
    };
    let fd1 = match files.install_fd(end1, descriptor_flags, limit) {
        Ok(fd) => fd,
        Err(rejected) => {
            let detached = files
                .clear_fd(fd0)
                .expect("newly installed socketpair fd disappeared");
            drop(files);
            rejected.discard();
            drop(detached.complete_close());
            return err(SyscallError::EMFILE);
        }
    };
    drop(files);

    // ABI: `int sv[2]` (i32). If userspace writeback fails after fd
    // installation, close both descriptors instead of reporting a leaked pair.
    if try_write_user_value(token, sv_ptr as *mut i32, &(fd0 as i32)).is_err()
        || try_write_user_value(
            token,
            (sv_ptr + size_of::<i32>()) as *mut i32,
            &(fd1 as i32),
        )
        .is_err()
    {
        let (files, _) = current_files_and_nofile_limit();
        let mut files = files.lock();
        let end0 = files.clear_fd(fd0);
        let end1 = files.clear_fd(fd1);
        drop(files);
        if let Some(end0) = end0 {
            drop(end0.complete_close());
        }
        if let Some(end1) = end1 {
            drop(end1.complete_close());
        }
        return err(SyscallError::EFAULT);
    }
    0
}
