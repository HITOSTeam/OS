//! LS2K1000LA U-Boot entry ABI.

use core::arch::global_asm;

global_asm!(
    include_str!("entry_ls2k1000la.S"),
    max_harts = const crate::config::MAX_HARTS,
);

#[unsafe(no_mangle)]
extern "C" fn rust_main(
    boot_a0: usize,
    boot_a1: usize,
    boot_a2: usize,
    boot_a3: usize,
    hart_id: usize,
) -> ! {
    super::kernel::start(hart_id, Some([boot_a0, boot_a1, boot_a2, boot_a3]))
}
