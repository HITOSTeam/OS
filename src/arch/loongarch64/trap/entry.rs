use core::arch::global_asm;

global_asm!(include_str!("trap_loongarch64.S"));

unsafe extern "C" {
    // `alltraps` 在计算陷阱返回 trampoline 偏移的位置单独声明。
    // pub fn alltraps();
    pub fn restore();
    // `alltraps_k` 由 `set_kernel_trap_entry` 在本地声明。
    // pub fn alltraps_k();
    // `restore_k` 是尚无 Rust 调用者的汇编符号。
    // pub fn restore_k();
}

pub fn enable_timer_interrupt() {
    super::super::enable_timer_interrupt();
}
