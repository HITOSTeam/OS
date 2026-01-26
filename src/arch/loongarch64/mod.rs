pub mod mm;
pub mod trap;

use core::arch::{asm, global_asm};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

global_asm!(include_str!("tlb_refill.S"));

pub const REG_RA: usize = 1;
pub const REG_SP: usize = 3;
pub const REG_GP: usize = 0;
pub const REG_TP: usize = 2;
pub const REG_T0: usize = 12;
pub const REG_T1: usize = 13;
pub const REG_T2: usize = 14;
pub const REG_S0: usize = 21;
pub const REG_S1: usize = 22;
pub const REG_A0: usize = 4;
pub const REG_A1: usize = 5;
pub const REG_A2: usize = 6;
pub const REG_A3: usize = 7;
pub const REG_A4: usize = 8;
pub const REG_A5: usize = 9;
pub const REG_A6: usize = 10;
pub const REG_A7: usize = 11;

#[cfg(feature = "loongarch_board")]
const UART_BASE: usize = 0x8000_0000_1fe2_0000;
#[cfg(not(feature = "loongarch_board"))]
const UART_BASE: usize = 0x1fe0_01e0;

const UART_RBR_THR: usize = UART_BASE + 0x0;
const UART_FCR: usize = UART_BASE + 0x2;
const UART_LCR: usize = UART_BASE + 0x3;
const UART_LSR: usize = UART_BASE + 0x5;

static UART_INITED: AtomicBool = AtomicBool::new(false);

fn uart_init_once() {
    if UART_INITED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        unsafe {
            // 8N1 + enable FIFO, clear RX/TX queues.
            write_volatile(UART_LCR as *mut u8, 0x03);
            write_volatile(UART_FCR as *mut u8, 0x07);
        }
    }
}

pub fn console_putchar(c: usize) {
    uart_init_once();
    unsafe {
        write_volatile(UART_RBR_THR as *mut u8, c as u8);
    }
}

pub fn console_flush() {
    uart_init_once();
    unsafe {
        while read_volatile(UART_LSR as *const u8) & 0x20 == 0 {}
    }
}

pub fn console_getchar() -> usize {
    uart_init_once();
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

pub fn disable_direct_map_windows() {
    unsafe {
        asm!("csrwr {}, 0x180", in(reg) 0usize);
        asm!("csrwr {}, 0x181", in(reg) 0usize);
        asm!("invtlb 0x0, $r0, $r0");
    }
}

pub fn hart_id() -> usize {
    let mut id: usize;
    unsafe { asm!("csrrd {}, 0x20", out(reg) id) };
    id
}

pub fn set_tp(hart_id: usize) {
    unsafe {
        asm!("add.d $r2, {}, $r0", in(reg) hart_id);
    }
}

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

pub fn bootstrap_init() {
    unsafe extern "C" {
        fn __rfill();
    }
    // Configure paging and TLB refill to match the Sv39-style page tables we build.
    unsafe {
        // Clear pending timer interrupt and disable timer while bootstrapping.
        asm!("csrwr {}, 0x44", in(reg) 1usize); // TIClr
        asm!("csrwr {}, 0x41", in(reg) 0usize); // TCFG

        // Enable paging: CRMD.PG=1, CRMD.DA=0, CRMD.IE=0.
        let mut crmd: usize;
        asm!("csrrd {}, 0x0", out(reg) crmd);
        crmd &= !(1 << 2);
        crmd &= !(1 << 3);
        crmd |= 1 << 4;
        asm!("csrwr {}, 0x0", in(reg) crmd);

        // TLB refill entry (must be 4K aligned).
        asm!("csrwr {}, 0x88", in(reg) __rfill as usize);

        // STLB page size and refill page size (4KB).
        let page_bits = crate::config::PAGE_SIZE_BITS;
        asm!("csrwr {}, 0x1e", in(reg) page_bits);
        asm!("csrwr {}, 0x8e", in(reg) page_bits);

        // Configure page walk controller for 3-level, 4KB pages, 8-byte PTEs.
        let dir_width = crate::config::PAGE_SIZE_BITS - 3;
        let ptbase = crate::config::PAGE_SIZE_BITS;
        let dir1_base = ptbase + dir_width;
        let dir2_base = ptbase + dir_width * 2;
        let mut pwcl: usize = 0;
        pwcl |= (ptbase & 0x1f) << 0;
        pwcl |= (dir_width & 0x1f) << 5;
        pwcl |= (dir1_base & 0x1f) << 10;
        pwcl |= (dir_width & 0x1f) << 15;
        pwcl |= (dir2_base & 0x1f) << 20;
        pwcl |= (dir_width & 0x1f) << 25;
        // PTE width: 8 bytes -> 0
        pwcl |= 0 << 30;
        asm!("csrwr {}, 0x1c", in(reg) pwcl);
        asm!("csrwr {}, 0x1d", in(reg) 0usize);

        asm!("invtlb 0x0, $r0, $r0");
    }
}
