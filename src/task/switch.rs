use core::arch::global_asm;

use crate::task::task_context::TaskContext;

#[cfg(target_arch = "riscv64")]
global_asm!(include_str!("../arch/riscv64/switch.S"));
#[cfg(target_arch = "loongarch64")]
global_asm!(include_str!("../arch/loongarch64/switch.S"));
unsafe extern "C" {
    // you should pass the loc in the kernel stack
    pub fn switch(old_task_cx_ptr: *const usize, new_task_cx_ptr: *const usize);
}
