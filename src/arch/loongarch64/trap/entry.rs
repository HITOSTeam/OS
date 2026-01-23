use core::arch::global_asm;

global_asm!(include_str!("trap_loongarch64.S"));

unsafe extern "C" {
    pub fn alltraps();
    pub fn restore();
    pub fn alltraps_k();
    pub fn restore_k();
}

pub fn enable_timer_interrupt() {
    super::super::enable_timer_interrupt();
}
