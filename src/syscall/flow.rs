use crate::{
    println,
    task::processor::{exit_current_and_run_next, exit_group_and_run_next, suspend_current_and_run_next},
    trap::get_current_token,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct IoVec {
    base: usize,
    len: usize,
}

pub fn syscall_read(_fd: usize, buf: *mut u8, len: usize) -> isize {
    super::filesystem::syscall_read(_fd, buf as usize, len)
}
pub fn syscall_write(fd: usize, buf: *const u8, len: usize) -> isize {
    super::filesystem::syscall_write(fd, buf as usize, len)
}

pub fn syscall_writev(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    let token = get_current_token();
    let iov_size = core::mem::size_of::<IoVec>();
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let iv = crate::mm::read_user_value(token, (iov_ptr + i * iov_size) as *const IoVec);
        if iv.len == 0 {
            continue;
        }
        let n = syscall_write(fd, iv.base as *const u8, iv.len);
        if n < 0 {
            return if total > 0 { total } else { n };
        }
        total += n;
        if n as usize != iv.len {
            break;
        }
    }
    total
}

pub fn syscall_readv(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    let token = get_current_token();
    let iov_size = core::mem::size_of::<IoVec>();
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let iv = crate::mm::read_user_value(token, (iov_ptr + i * iov_size) as *const IoVec);
        if iv.len == 0 {
            continue;
        }
        let n = syscall_read(fd, iv.base as *mut u8, iv.len);
        if n < 0 {
            return if total > 0 { total } else { n };
        }
        total += n;
        if n as usize != iv.len {
            break;
        }
    }
    total
}

pub fn syscall_exit(_code: usize) -> isize {
    let code = ((_code as i32) & 0xff) as i32;
    exit_current_and_run_next(code);
    return 0;
}

pub fn syscall_exit_group(_code: usize) -> isize {
    let code = ((_code as i32) & 0xff) as i32;
    exit_group_and_run_next(code);
    0
}
// the below one is just for testing
pub fn syscall_fortest(a: usize, b: usize) -> isize {
    println!("[kernel] syscall_fortest called with args: {}, {}", a, b);
    0
}
pub fn syscall_yield() -> isize {
    suspend_current_and_run_next();
    0
}
pub fn syscall_get_time() -> isize {
    crate::time::get_time_ms() as isize
}
