use crate::syscall::error::{SyscallError, err};
use core::mem::size_of;

use crate::{
    fs::make_socketpair,
    mm::{try_write_user_value, write_user_value},
    task::processor::current_files_and_nofile_limit,
    trap::get_current_token,
};

// Linux errno (negative return in kernel ABI).

const AF_UNIX: usize = 1;
const AF_INET: usize = 2;
const SOCK_STREAM: usize = 1;
const SOCK_DGRAM: usize = 2;
const SOCK_RAW: usize = 3;
const SOCK_TYPE_MASK: usize = 0xf;
const SOCK_NONBLOCK: usize = 0x800;
const SOCK_CLOEXEC: usize = 0x80000;
const O_NONBLOCK: u32 = 0x800;
const FD_CLOEXEC: u32 = 1;

/// Linux `socketpair(2)` (syscall 199 on riscv64).
///
/// Minimal support for `AF_UNIX` + `SOCK_STREAM`, sufficient for rt-tests `hackbench`.
pub fn syscall_socketpair(domain: usize, type_: usize, protocol: usize, sv_ptr: usize) -> isize {
    if sv_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let sock_type = type_ & SOCK_TYPE_MASK;
    if !matches!(sock_type, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) {
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
            if !matches!(sock_type, SOCK_STREAM | SOCK_DGRAM) {
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

    let (end0, end1) = make_socketpair();

    let mut descriptor_flags = 0u32;
    if cloexec {
        descriptor_flags |= FD_CLOEXEC;
    }
    if nonblock {
        descriptor_flags |= O_NONBLOCK;
    }
    let (files, limit) = current_files_and_nofile_limit();
    let mut files = files.lock();
    let Some(fd0) = files.install_fd(end0, descriptor_flags, limit) else {
        return err(SyscallError::EMFILE);
    };
    let Some(fd1) = files.install_fd(end1, descriptor_flags, limit) else {
        let _ = files.clear_fd(fd0);
        return err(SyscallError::EMFILE);
    };
    drop(files);

    // ABI: `int sv[2]` (i32).
    write_user_value(token, sv_ptr as *mut i32, &(fd0 as i32));
    write_user_value(
        token,
        (sv_ptr + size_of::<i32>()) as *mut i32,
        &(fd1 as i32),
    );
    0
}
