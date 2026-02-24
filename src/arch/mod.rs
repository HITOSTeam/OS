#[cfg(target_arch = "loongarch64")]
pub mod loongarch64;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "loongarch64")]
pub use loongarch64::*;
#[cfg(target_arch = "riscv64")]
pub use riscv64::*;
