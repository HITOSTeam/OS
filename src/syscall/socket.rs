use core::mem::size_of;

use crate::{
    fs::make_socketpair,
    mm::{try_write_user_value, write_user_value},
    task::processor::current_files_process,
    trap::get_current_token,
};

// Linux errno (negative return in kernel ABI).
const EINVAL: isize = -22;
const EFAULT: isize = -14;
const EAFNOSUPPORT: isize = -97;
const EPROTONOSUPPORT: isize = -93;
const EOPNOTSUPP: isize = -95;
const EMFILE: isize = -24;

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
        return EFAULT;
    }
    let sock_type = type_ & SOCK_TYPE_MASK;
    if !matches!(sock_type, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) {
        return EINVAL;
    }
    let token = get_current_token();
    if try_write_user_value(token, sv_ptr as *mut i32, &0i32).is_err()
        || try_write_user_value(token, (sv_ptr + size_of::<i32>()) as *mut i32, &0i32).is_err()
    {
        return EFAULT;
    }
    match domain {
        AF_UNIX => {
            if protocol != 0 {
                return EPROTONOSUPPORT;
            }
            if !matches!(sock_type, SOCK_STREAM | SOCK_DGRAM) {
                return EPROTONOSUPPORT;
            }
        }
        AF_INET => {
            return match (sock_type, protocol) {
                (SOCK_STREAM, 6) | (SOCK_DGRAM, 17) => EOPNOTSUPP,
                (SOCK_DGRAM, 6) | (SOCK_STREAM, 1) | (SOCK_RAW, 0) => EPROTONOSUPPORT,
                _ => EPROTONOSUPPORT,
            };
        }
        _ => return EAFNOSUPPORT,
    }
    let cloexec = (type_ & SOCK_CLOEXEC) != 0;
    let nonblock = (type_ & SOCK_NONBLOCK) != 0;

    let (end0, end1) = make_socketpair();

    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd0) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[fd0] = Some(end0);
    let Some(fd1) = inner.alloc_fd() else {
        inner.fd_table[fd0] = None;
        return EMFILE;
    };
    inner.fd_table[fd1] = Some(end1);
    let mut fd_flags = 0u32;
    if cloexec {
        fd_flags |= FD_CLOEXEC;
    }
    if nonblock {
        fd_flags |= O_NONBLOCK;
    }
    inner.fd_flags[fd0] = fd_flags;
    inner.fd_flags[fd1] = fd_flags;
    drop(inner);

    // ABI: `int sv[2]` (i32).
    write_user_value(token, sv_ptr as *mut i32, &(fd0 as i32));
    write_user_value(
        token,
        (sv_ptr + size_of::<i32>()) as *mut i32,
        &(fd1 as i32),
    );
    0
}
