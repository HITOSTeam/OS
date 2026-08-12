//! LoongArch platform entry selection.

#[cfg(all(
    not(feature = "loongarch_board"),
    not(feature = "loongarch_board_smoke")
))]
mod qemu;

#[cfg(all(feature = "loongarch_board", not(feature = "loongarch_board_smoke")))]
mod ls2k1000la;

#[cfg(not(feature = "loongarch_board_smoke"))]
mod kernel;

#[cfg(feature = "loongarch_board_smoke")]
mod smoke;
