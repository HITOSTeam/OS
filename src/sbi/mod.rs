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

    fn sbi_call_ext(eid: usize, fid: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
        let mut ret;
        unsafe {
            asm!(
                "ecall",
                inlateout("a0") arg0 => ret,
                in("a1") arg1,
                in("a2") arg2,
                in("a6") fid,
                in("a7") eid,
            );
        }
        ret
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
        unsafe {
            IPI_HART_MASK = 1usize << hart_id;
            let mask_ptr = &raw const IPI_HART_MASK as usize;
            // hart_mask_base = 0
            sbi_call(SBI_SEND_IPI, mask_ptr, 0, 0);
            IPI_HART_MASK = 0;
        }
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

    pub fn shutdown() -> ! {
        unsupported("shutdown");
    }

    pub fn hart_start(_hart_id: usize, _start_addr: usize, _opaque: usize) -> usize {
        unsupported("hart_start");
    }
}

#[cfg(not(target_arch = "riscv64"))]
pub use stub::*;
