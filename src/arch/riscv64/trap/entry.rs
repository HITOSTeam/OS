use core::arch::global_asm;

use riscv::register::sie;

global_asm!(include_str!("trap.asm"));

unsafe extern "C" {
    #[allow(dead_code)]
    pub fn alltraps();
    pub fn restore();
}
/// timer interrupt enabled
#[allow(dead_code)]
pub fn enable_timer_interrupt() {
    // SAFETY: Enabling STimer in `sie` is a privileged S-mode CSR update performed during kernel
    // trap setup. Doing this in the wrong mode or at the wrong time would break interrupt delivery.
    unsafe {
        sie::set_stimer();
    }
}
