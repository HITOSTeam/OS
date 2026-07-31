#![allow(unused)]

#[cfg(target_arch = "riscv64")]
mod riscv {
    const SBI_SET_TIMER: usize = 0;
    const SBI_CONSOLE_PUTCHAR: usize = 1;
    const SBI_CONSOLE_GETCHAR: usize = 2;
    const SBI_CLEAR_IPI: usize = 3;
    const SBI_SEND_IPI: usize = 4;
    const SBI_REMOTE_FENCE_I: usize = 5;
    const SBI_REMOTE_SFENCE_VMA: usize = 6;
    const SBI_REMOTE_SFENCE_VMA_ASID: usize = 7;
    const SBI_SHUTDOWN: usize = 8;
    // SBI v0.2 extension: Hart State Management
    const SBI_EXT_HSM: usize = 0x48534d;
    const SBI_EXT_HSM_HART_START: usize = 0;
    use core::arch::asm;
    use spin::Mutex;

    fn sbi_call(which: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
        let mut ret;
        // SAFETY: ecall follows RISC-V SBI calling convention; arguments in a0-a2, extension in a7.
        unsafe {
            asm!(
                "ecall",
                inlateout("x10") arg0 => ret,
                in("x11") arg1,
                in("x12") arg2,
                in("x17") which,
            );
        }
        ret
    }

    fn sbi_call_ext(
        eid: usize,
        fid: usize,
        arg0: usize,
        arg1: usize,
        arg2: usize,
    ) -> (usize, usize) {
        let mut error;
        let mut value;
        // SAFETY: ecall follows the SBI v0.2 calling convention.  Unlike the
        // legacy calls, an extension call returns both `error` in a0 and
        // `value` in a1, so both registers must be declared as outputs.
        unsafe {
            asm!(
                "ecall",
                inlateout("a0") arg0 => error,
                inlateout("a1") arg1 => value,
                in("a2") arg2,
                in("a6") fid,
                in("a7") eid,
            );
        }
        (error, value)
    }

    pub fn set_timer(timer: usize) {
        sbi_call(SBI_SET_TIMER, timer, 0, 0);
    }

    pub fn console_putchar(c: usize) {
        sbi_call(SBI_CONSOLE_PUTCHAR, c, 0, 0);
    }

    pub fn console_getchar() -> usize {
        sbi_call(SBI_CONSOLE_GETCHAR, 0, 0, 0)
    }

    static IPI_LOCK: Mutex<()> = Mutex::new(());
    static mut IPI_HART_MASK: usize = 0;

    /// Send an IPI (Supervisor Software Interrupt) to a single hart to wake it from `wfi`.
    ///
    /// This uses legacy SBI `SBI_SEND_IPI` which expects a pointer to a hart mask in memory.
    /// The mask is stored in `.bss` so the address is a low, identity-mapped physical address.
    pub fn send_ipi(hart_id: usize) {
        if hart_id >= usize::BITS as usize {
            return;
        }
        let _g = IPI_LOCK.lock();
        // SAFETY: hart_id is bounds-checked above; IPI_LOCK serializes access to IPI_HART_MASK.
        // IPI_HART_MASK is in kernel .bss with identity mapping (VA == PA), giving a valid
        // physical address for the SBI ecall.
        // IPI_HART_MASK is in .bss so its address is a low, identity-mapped physical address.
        unsafe {
            IPI_HART_MASK = 1usize << hart_id;
            let mask_ptr = &raw const IPI_HART_MASK as usize;
            // hart_mask_base = 0
            sbi_call(SBI_SEND_IPI, mask_ptr, 0, 0);
            IPI_HART_MASK = 0;
        }
    }

    /// Request a remote TLB flush for one virtual-address range on the
    /// selected harts.
    ///
    /// Legacy SBI expects a pointer to a hart mask in memory. We reuse the same
    /// low, identity-mapped `.bss` storage as `send_ipi()`.
    pub fn remote_sfence_vma(hart_mask: usize, start: usize, size: usize) {
        if hart_mask == 0 {
            return;
        }
        let _g = IPI_LOCK.lock();
        // SAFETY: IPI_LOCK serializes access to IPI_HART_MASK, which lives in
        // low identity-mapped `.bss`, so its address is a valid SBI hart-mask
        // pointer. The legacy SBI call accepts this virtual-address range
        // directly; start=0,size=0 requests a full flush.
        unsafe {
            IPI_HART_MASK = hart_mask;
            let mask_ptr = &raw const IPI_HART_MASK as usize;
            sbi_call(SBI_REMOTE_SFENCE_VMA, mask_ptr, start, size);
            IPI_HART_MASK = 0;
        }
    }

    /// Request a full remote TLB flush on the selected harts.
    pub fn remote_sfence_vma_all(hart_mask: usize) {
        remote_sfence_vma(hart_mask, 0, 0);
    }

    pub fn shutdown() -> ! {
        sbi_call(SBI_SHUTDOWN, 0, 0, 0);
        panic!("It should shutdown!");
    }

    pub fn hart_start(hart_id: usize, start_addr: usize, opaque: usize) -> usize {
        sbi_call_ext(
            SBI_EXT_HSM,
            SBI_EXT_HSM_HART_START,
            hart_id,
            start_addr,
            opaque,
        )
        .0
    }
}

#[cfg(target_arch = "riscv64")]
pub use riscv::*;

#[cfg(not(target_arch = "riscv64"))]
mod stub {
    #[inline(always)]
    fn unsupported(name: &str) -> ! {
        panic!("SBI call {} is not supported on this architecture", name);
    }

    pub fn set_timer(_timer: usize) {
        unsupported("set_timer");
    }

    pub fn console_putchar(_c: usize) {
        unsupported("console_putchar");
    }

    pub fn console_getchar() -> usize {
        unsupported("console_getchar");
    }

    pub fn send_ipi(_hart_id: usize) {
        unsupported("send_ipi");
    }

    pub fn remote_sfence_vma_all(_hart_mask: usize) {
        unsupported("remote_sfence_vma_all");
    }

    pub fn remote_sfence_vma(_hart_mask: usize, _start: usize, _size: usize) {
        unsupported("remote_sfence_vma");
    }

    pub fn shutdown() -> ! {
        unsupported("shutdown");
    }

    pub fn hart_start(_hart_id: usize, _start_addr: usize, _opaque: usize) -> usize {
        unsupported("hart_start");
    }
}

#[cfg(not(target_arch = "riscv64"))]
pub use stub::*;
