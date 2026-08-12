//! Destructive-operation-free LS2K1000LA bring-up payload.
//!
//! This path intentionally avoids the allocator, page tables, interrupts,
//! device tree and block devices. Its only job is to prove that U-Boot can
//! load the ELF, enter Rust on a private stack and reach the board UART.

use core::{
    arch::{asm, global_asm},
    ptr::{read_volatile, write_volatile},
};

global_asm!(include_str!("entry_smoke.S"));

const UART_BASE: usize = 0x8000_0000_1fe2_0000;
const UART_THR: usize = UART_BASE;
const UART_LSR: usize = UART_BASE + 5;
const UART_LSR_THR_EMPTY: u8 = 1 << 5;
const CRMD_IE: usize = 1 << 2;

#[inline(always)]
fn uart_put_byte(byte: u8) {
    // SAFETY: U-Boot has configured UART0 before transferring control, and the
    // uncached DMW alias is valid on LS2K1000LA at this point.
    unsafe {
        while read_volatile(UART_LSR as *const u8) & UART_LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        write_volatile(UART_THR as *mut u8, byte);
    }
}

fn uart_write(text: &str) {
    for byte in text.bytes() {
        if byte == b'\n' {
            uart_put_byte(b'\r');
        }
        uart_put_byte(byte);
    }
}

fn uart_write_hex(value: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    uart_write("0x");
    for shift in (0..usize::BITS).step_by(4).rev() {
        uart_put_byte(HEX[(value >> shift & 0xf) as usize]);
    }
}

fn uart_write_value(label: &str, value: usize) {
    uart_write(label);
    uart_write_hex(value);
    uart_write("\n");
}

#[inline(always)]
fn read_csr<const CSR: usize>() -> usize {
    let value: usize;
    // SAFETY: the smoke payload executes in privileged mode inherited from
    // U-Boot and only reads architecturally defined control registers.
    unsafe {
        asm!(
            "csrrd {value}, {csr}",
            value = out(reg) value,
            csr = const CSR,
            options(nomem, nostack)
        );
    }
    value
}

#[inline(always)]
fn disable_interrupts() -> usize {
    let original = read_csr::<0x0>();
    let disabled = original & !CRMD_IE;
    // SAFETY: clear only CRMD.IE while preserving every other firmware-provided
    // execution-mode bit. `csrwr` overwrites its register operand with the old
    // CSR value, hence the inout declaration.
    unsafe {
        asm!(
            "csrwr {value}, 0x0",
            value = inout(reg) disabled => _,
            options(nomem, nostack)
        );
    }
    original
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_main(
    boot_a0: usize,
    boot_a1: usize,
    boot_a2: usize,
    boot_a3: usize,
    hart_id: usize,
) -> ! {
    let crmd = disable_interrupts();

    uart_write("\nCongCore LS2K1000LA early smoke\n");
    uart_write("status: UART OK\n");
    uart_write_value("entry       = ", rust_main as *const () as usize);
    uart_write_value("hart_id     = ", hart_id);
    uart_write_value("boot_a0     = ", boot_a0);
    uart_write_value("boot_a1     = ", boot_a1);
    uart_write_value("boot_a2     = ", boot_a2);
    uart_write_value("boot_a3     = ", boot_a3);
    uart_write_value("crmd        = ", crmd);
    uart_write_value("dmw0        = ", read_csr::<0x180>());
    uart_write_value("dmw1        = ", read_csr::<0x181>());
    uart_write("status: parked; reset returns to factory Linux\n");

    loop {
        core::hint::spin_loop();
    }
}
