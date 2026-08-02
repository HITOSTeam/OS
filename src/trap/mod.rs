#[cfg(target_arch = "loongarch64")]
pub use crate::arch::loongarch64::trap;
#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::trap;

#[cfg(target_arch = "loongarch64")]
pub use crate::arch::loongarch64::trap::context;
#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::trap::context;

#[cfg(target_arch = "loongarch64")]
pub use crate::arch::loongarch64::trap::{get_current_token, init_trap, trap_handler, trap_return};
#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::trap::{get_current_token, init_trap, trap_handler, trap_return};
