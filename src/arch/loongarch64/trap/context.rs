//! LoongArch trap context

use core::arch::asm;

use super::super::{REG_SP, hart_id};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrapContext {
    /// General registers r0..r31.
    pub x: [usize; 32],
    /// PRMD (stored in the same slot as sstatus on RISC-V).
    pub sstatus: usize,
    /// ERA (stored in the same slot as sepc on RISC-V).
    pub sepc: usize,
    /// Kernel page table token (unused for LoongArch but kept for compatibility).
    pub kernel_satp: usize,
    /// Kernel stack pointer.
    pub kernel_sp: usize,
    /// Trap handler entry (unused for LoongArch but kept for compatibility).
    pub trap_handler: usize,
    /// Kernel tp (hart id) saved when returning to user.
    pub kernel_tp: usize,
}

impl TrapContext {
    pub fn set_sp(&mut self, sp: usize) {
        self.x[REG_SP] = sp;
    }

    pub fn app_init_context(
        entry: usize,
        sp: usize,
        kernel_satp: usize,
        kernel_sp: usize,
        trap_handler: usize,
    ) -> Self {
        let mut prmd: usize;
        unsafe {
            asm!("csrrd {}, 0x1", out(reg) prmd);
        }
        // PRMD[1:0]=PPLV (0b11 for user), PRMD[2]=PIE.
        prmd = (prmd & !0x7) | 0x7;
        let mut cx = Self {
            x: [0; 32],
            sstatus: prmd,
            sepc: entry,
            kernel_satp,
            kernel_sp,
            trap_handler,
            kernel_tp: hart_id(),
        };
        cx.set_sp(sp);
        cx
    }
}

pub fn push_trap_context_at(dst: usize, cx: &TrapContext) {
    unsafe {
        let dst_ptr = dst as *mut TrapContext;
        *dst_ptr = *cx;
    }
}
