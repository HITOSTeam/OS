use crate::syscall::error::{SyscallError, err};
use crate::{mm::try_write_user_value, task::processor::current_task, trap::get_current_token};

pub fn sys_get_hartid() -> isize {
    crate::arch::hart_id() as isize
}

pub fn syscall_getcpu(cpu_ptr: usize, node_ptr: usize, _tcache_ptr: usize) -> isize {
    let token = get_current_token();
    let cpu = {
        let task = current_task().unwrap();
        let inner = task.borrow_mut();
        let current = crate::arch::hart_id();
        let mask = if inner.scheduling.cpu_affinity_mask == 0 {
            crate::task::manager::online_hart_mask()
        } else {
            inner.scheduling.cpu_affinity_mask
        };
        if (mask & (1usize << current)) != 0 {
            current as u32
        } else {
            mask.trailing_zeros() as u32
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
