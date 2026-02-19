use core::mem::size_of;

use crate::{
    fs::make_socketpair, mm::write_user_value, task::processor::current_process,
    trap::get_current_token,
};

// Linux errno (negative return in kernel ABI).
const EINVAL: isize = -22;
const EFAULT: isize = -14;
const EAFNOSUPPORT: isize = -97;
const EPROTONOSUPPORT: isize = -93;
const EMFILE: isize = -24;

const AF_UNIX: usize = 1;
const SOCK_STREAM: usize = 1;
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
    if domain != AF_UNIX {
        return EAFNOSUPPORT;
    }
    if protocol != 0 {
        return EPROTONOSUPPORT;
    }
    let sock_type = type_ & SOCK_TYPE_MASK;
    if sock_type != SOCK_STREAM {
        return EINVAL;
    }
    let cloexec = (type_ & SOCK_CLOEXEC) != 0;
    let nonblock = (type_ & SOCK_NONBLOCK) != 0;

    let (end0, end1) = make_socketpair();

    let process = current_process();
    let token = get_current_token();
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
