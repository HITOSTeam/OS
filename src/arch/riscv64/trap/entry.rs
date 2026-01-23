use core::arch::global_asm;

use riscv::register::sie;

global_asm!(include_str!("trap.asm"));

unsafe extern "C" {
    pub fn alltraps();
    pub fn restore();
}
/// timer interrupt enabled
pub fn enable_timer_interrupt() {
    unsafe {
        sie::set_stimer();
    }
}
