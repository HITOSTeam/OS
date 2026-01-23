pub mod mm;
pub mod trap;

use core::arch::asm;

use riscv::register::sstatus;

pub const REG_SP: usize = 2;
pub const REG_RA: usize = 1;
pub const REG_GP: usize = 3;
pub const REG_TP: usize = 4;
pub const REG_T0: usize = 5;
pub const REG_T1: usize = 6;
pub const REG_T2: usize = 7;
pub const REG_S0: usize = 8;
pub const REG_S1: usize = 9;
pub const REG_A0: usize = 10;
pub const REG_A1: usize = 11;
pub const REG_A2: usize = 12;
pub const REG_A3: usize = 13;
pub const REG_A4: usize = 14;
pub const REG_A5: usize = 15;
pub const REG_A6: usize = 16;
pub const REG_A7: usize = 17;

pub fn disable_interrupts() -> bool {
    let prev = sstatus::read().sie();
    unsafe { sstatus::clear_sie() };
    prev
}

pub fn restore_interrupts(prev: bool) {
    if prev {
        unsafe { sstatus::set_sie() };
    }
}

pub fn enable_interrupts() {
    unsafe { sstatus::set_sie() };
}

pub fn wait_for_interrupt() {
    unsafe { asm!("wfi") };
}

pub fn hart_id() -> usize {
    let mut id: usize;
    unsafe {
        asm!("mv {}, tp", out(reg) id);
    }
    id
}

pub fn set_tp(hart_id: usize) {
    unsafe { asm!("mv tp, {}", in(reg) hart_id) };
}

pub fn console_putchar(c: usize) {
    crate::sbi::console_putchar(c);
}

pub fn console_getchar() -> usize {
    crate::sbi::console_getchar()
}

pub fn set_timer(timer: usize) {
    crate::sbi::set_timer(timer);
}

pub fn send_ipi(hart_id: usize) {
    crate::sbi::send_ipi(hart_id);
}

pub fn shutdown() -> ! {
    crate::sbi::shutdown();
}

pub fn hart_start(hart_id: usize, start_addr: usize, opaque: usize) -> usize {
    crate::sbi::hart_start(hart_id, start_addr, opaque)
}

pub fn read_time() -> usize {
    riscv::register::time::read()
}
