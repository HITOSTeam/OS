#[cfg(target_arch = "loongarch64")]
pub mod loongarch64;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "loongarch64")]
pub use loongarch64::*;
#[cfg(target_arch = "riscv64")]
pub use riscv64::*;

// Common VM code consumes one architecture facade. The selected backend owns
// the hardware mechanism and capability checks; callers do not branch on the
// target architecture for shared MM semantics.
#[cfg(target_arch = "loongarch64")]
pub(crate) use loongarch64::mm::{
    AsidContext, UserTlbInvalidationBatch, begin_user_tlb_batch, flush_user_page,
    update_mmu_cache_for_new_pte, update_mmu_cache_for_new_pte_range,
};
#[cfg(target_arch = "riscv64")]
pub(crate) use riscv64::mm::{
    AsidContext, UserTlbInvalidationBatch, begin_user_tlb_batch, flush_user_page,
    update_mmu_cache_for_new_pte, update_mmu_cache_for_new_pte_range,
};
