use crate::{
    mm::try_read_user_value,
    println,
    task::processor::{
        exit_current_and_run_next, exit_group_and_run_next, suspend_current_and_run_next,
    },
    trap::get_current_token,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct IoVec {
    base: usize,
    len: usize,
}

const EFAULT: isize = -14;
const EINVAL: isize = -22;
const IOV_MAX: usize = 1024;

fn validate_iovcnt(iovcnt_raw: usize) -> Result<usize, isize> {
    let iovcnt = iovcnt_raw as isize;
    if iovcnt < 0 {
        return Err(EINVAL);
    }
    let iovcnt = iovcnt as usize;
    if iovcnt > IOV_MAX {
        return Err(EINVAL);
    }
    Ok(iovcnt)
}

fn read_iovec(token: usize, iov_ptr: usize, index: usize) -> Result<IoVec, isize> {
    let iov_size = core::mem::size_of::<IoVec>();
    let Some(iov_off) = index
        .checked_mul(iov_size)
        .and_then(|v| iov_ptr.checked_add(v))
    else {
        return Err(EFAULT);
    };
    try_read_user_value(token, iov_off as *const IoVec).ok_or(EFAULT)
}

fn do_iov<F>(iov_ptr: usize, iovcnt_raw: usize, mut io_once: F) -> isize
where
    F: FnMut(usize, usize) -> isize,
{
    let Ok(iovcnt) = validate_iovcnt(iovcnt_raw) else {
        return EINVAL;
    };
    if iovcnt == 0 {
        return 0;
    }

    let token = get_current_token();
    let mut total_len = 0usize;
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let iv = match read_iovec(token, iov_ptr, i) {
            Ok(iv) => iv,
            Err(err) => return if total > 0 { total } else { err },
        };
        if iv.len > isize::MAX as usize {
            return EINVAL;
        }
        total_len = match total_len.checked_add(iv.len) {
            Some(v) if v <= isize::MAX as usize => v,
            _ => return EINVAL,
        };
        if iv.len == 0 {
            continue;
        }

        let n = io_once(iv.base, iv.len);
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

pub fn syscall_read(_fd: usize, buf: *mut u8, len: usize) -> isize {
    super::filesystem::syscall_read(_fd, buf as usize, len)
}
pub fn syscall_write(fd: usize, buf: *const u8, len: usize) -> isize {
    super::filesystem::syscall_write(fd, buf as usize, len)
}

pub fn syscall_writev(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    do_iov(iov_ptr, iovcnt, |base, len| {
        syscall_write(fd, base as *const u8, len)
    })
}

pub fn syscall_readv(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    do_iov(iov_ptr, iovcnt, |base, len| {
        syscall_read(fd, base as *mut u8, len)
    })
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
