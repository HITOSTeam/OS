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
    /// Kernel page table token 记得读取之后要交换PGDL/PGDH：
    pub kernel_satp: usize,
    /// Kernel stack pointer.
    pub kernel_sp: usize,
    /// Trap handler entry trap的返回地址,一般初始化为 trap_handler
    /// 位于OS_Workspace/os/src/arch/loongarch64/trap/handler.rs
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
        // SAFETY: Reading PRMD is valid in kernel mode and yields the saved privilege bits used
        // to seed a user trap context. Reading the wrong CSR would build an invalid return state.
        unsafe {
            asm!("csrrd {}, 0x1", out(reg) prmd);
        }
        use super::super::csr_defs::{PRMD_USER_IE, PRMD_USER_IE_MASK};
        // PRMD[1:0]=PPLV (0b11 for user), PRMD[2]=PIE.
        prmd = (prmd & !PRMD_USER_IE_MASK) | PRMD_USER_IE;
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

/*
 * 当前 LoongArch 陷阱汇编直接写入上下文。待某个汇编入口路径需要 Rust 侧复制
 * 时，再启用这个辅助函数。
 *
pub fn push_trap_context_at(dst: usize, cx: &TrapContext) {
    // SAFETY: Trap entry passes a writable kernel address reserved for a `TrapContext`, and `cx`
    // is fully initialized. If `dst` were not valid trap-context storage, this would corrupt memory.
    unsafe {
        let dst_ptr = dst as *mut TrapContext;
        *dst_ptr = *cx;
    }
}
*/
