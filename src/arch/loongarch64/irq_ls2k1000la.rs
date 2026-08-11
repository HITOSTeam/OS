//! Minimal LS2K1000LA interrupt facade for the first RAM-only board boot.
//!
//! The local architectural timer remains enabled by the common LoongArch
//! backend. External IRQ routing is deliberately left untouched until the
//! LS2K interrupt-controller driver is implemented; the RAM block devices do
//! not require interrupts.

use core::arch::asm;

const ECFG_EXTERNAL_LINES_MASK: usize = (1 << 11) - 1;

pub fn init_external_interrupts() {
    let mut ecfg: usize;
    // SAFETY: ECFG is a privileged hart-local CSR. Clear only hardware
    // interrupt inputs 0..10 inherited from U-Boot; the common timer/IPI path
    // owns bits 11 and 12.
    unsafe {
        asm!("csrrd {}, 0x4", out(reg) ecfg);
        ecfg &= !ECFG_EXTERNAL_LINES_MASK;
        super::csr_write::<0x4>(ecfg);
    }
}

pub fn enable_external_irq(_irq: usize) {}

pub fn handle_external_interrupt() {}
