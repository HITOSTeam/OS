use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

#[cfg(feature = "loongarch_board")]
const UART_BASE: usize = 0x8000_0000_1fe2_0000;
#[cfg(not(feature = "loongarch_board"))]
const UART_BASE: usize = 0x1fe0_01e0;

const UART_RBR_THR: usize = UART_BASE + 0x0;
const UART_LSR: usize = UART_BASE + 0x5;

pub fn console_putchar(c: usize) {
    unsafe {
        while read_volatile(UART_LSR as *const u8) & 0x20 == 0 {}
        write_volatile(UART_RBR_THR as *mut u8, c as u8);
    }
}

pub fn console_getchar() -> usize {
    unsafe {
        if read_volatile(UART_LSR as *const u8) & 0x01 == 0 {
            return usize::MAX;
        }
        read_volatile(UART_RBR_THR as *const u8) as usize
    }
}

pub fn disable_interrupts() -> bool {
    let mut crmd: usize;
    unsafe { asm!("csrrd {}, 0x0", out(reg) crmd) };
    let prev = (crmd & (1 << 2)) != 0;
    crmd &= !(1 << 2);
    unsafe { asm!("csrwr {}, 0x0", in(reg) crmd) };
    prev
}

pub fn restore_interrupts(prev: bool) {
    if prev {
        enable_interrupts();
    }
}

pub fn enable_interrupts() {
    let mut crmd: usize;
    unsafe { asm!("csrrd {}, 0x0", out(reg) crmd) };
    crmd |= 1 << 2;
    unsafe { asm!("csrwr {}, 0x0", in(reg) crmd) };
}

pub fn wait_for_interrupt() {
    core::hint::spin_loop();
}

pub fn hart_id() -> usize {
    let mut id: usize;
    unsafe { asm!("csrrd {}, 0x20", out(reg) id) };
    id
}

pub fn set_tp(_hart_id: usize) {}

pub fn send_ipi(_hart_id: usize) {}

pub fn hart_start(_hart_id: usize, _start_addr: usize, _opaque: usize) -> usize {
    1
}

pub fn shutdown() -> ! {
    unsafe {
        (0x100e_001c as *mut u8).write_volatile(0x34);
    }
    loop {}
}

pub fn enable_timer_interrupt() {
    let mut ecfg: usize;
    unsafe { asm!("csrrd {}, 0x4", out(reg) ecfg) };
    ecfg |= 1 << 11;
    unsafe { asm!("csrwr {}, 0x4", in(reg) ecfg) };
}

pub fn clear_timer_interrupt() {
    unsafe {
        asm!("csrwr {}, 0x44", in(reg) 1usize);
    }
}

pub fn set_timer(timer: usize) {
    let now = read_time();
    let delta = timer.saturating_sub(now).max(4);
    let tcfg = (delta & !0x3) | 0x1;
    unsafe {
        asm!("csrwr {}, 0x41", in(reg) tcfg);
    }
}

pub fn read_time() -> usize {
    let mut counter: usize;
    unsafe {
        asm!("rdtime.d {},{}", out(reg) counter, out(reg) _);
    }
    counter
}
