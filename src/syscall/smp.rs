use crate::syscall::error::{SyscallError, err};
use crate::{mm::try_write_user_value, task::processor::current_process, trap::get_current_token};

pub fn sys_get_hartid() -> isize {
    crate::arch::hart_id() as isize
}

pub fn syscall_getcpu(cpu_ptr: usize, node_ptr: usize, _tcache_ptr: usize) -> isize {
    let token = get_current_token();
    let cpu = {
        let process = current_process();
        let inner = process.borrow_mut();
        let current = crate::arch::hart_id();
        if (inner.scheduling.cpu_affinity_mask & (1usize << current)) != 0 {
            current as u32
        } else {
            inner.scheduling.cpu_affinity_mask.trailing_zeros() as u32
        }
    };
    let node: u32 = 0;

    if cpu_ptr != 0 && try_write_user_value(token, cpu_ptr as *mut u32, &cpu).is_err() {
        return err(SyscallError::EFAULT);
    }
    if node_ptr != 0 && try_write_user_value(token, node_ptr as *mut u32, &node).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}
