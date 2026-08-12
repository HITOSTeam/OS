//! QEMU virt entry ABI.

use core::arch::global_asm;

global_asm!(
    include_str!("entry_qemu.S"),
    max_harts = const crate::config::MAX_HARTS,
);

#[unsafe(no_mangle)]
fn rust_main(hart_id: usize) -> ! {
    super::kernel::start(hart_id, None)
}
