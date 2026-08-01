#![allow(unused)]

#[cfg(target_arch = "riscv64")]
mod riscv {
    use core::arch::asm;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use spin::Mutex;

    // SBI v0.1 legacy extension IDs.
    const SBI_SET_TIMER: usize = 0;
    const SBI_CONSOLE_PUTCHAR: usize = 1;
    const SBI_CONSOLE_GETCHAR: usize = 2;
    const SBI_SEND_IPI: usize = 4;
    const SBI_REMOTE_FENCE_I: usize = 5;
    const SBI_REMOTE_SFENCE_VMA: usize = 6;
    const SBI_REMOTE_SFENCE_VMA_ASID: usize = 7;
    const SBI_SHUTDOWN: usize = 8;

    // SBI v0.2+ extension IDs and function IDs.
    const SBI_EXT_BASE: usize = 0x10;
    const SBI_EXT_BASE_GET_SPEC_VERSION: usize = 0;
    const SBI_EXT_BASE_PROBE_EXTENSION: usize = 3;
    const SBI_EXT_IPI: usize = 0x7350_49;
    const SBI_EXT_IPI_SEND_IPI: usize = 0;
    const SBI_EXT_RFENCE: usize = 0x5246_4e43;
    const SBI_EXT_RFENCE_REMOTE_FENCE_I: usize = 0;
    const SBI_EXT_RFENCE_REMOTE_SFENCE_VMA: usize = 1;
    const SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID: usize = 2;
    const SBI_EXT_HSM: usize = 0x4853_4d;
    const SBI_EXT_HSM_HART_START: usize = 0;

    pub const SBI_SUCCESS: isize = 0;
    pub const SBI_ERR_NOT_SUPPORTED: isize = -2;

    /// SBI v0.2 return convention: `a0` is a signed error and `a1` is a value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SbiRet {
        pub error: isize,
        pub value: usize,
    }

    impl SbiRet {
        const fn success(value: usize) -> Self {
            Self {
                error: SBI_SUCCESS,
                value,
            }
        }

        pub const fn is_ok(self) -> bool {
            self.error == SBI_SUCCESS
        }
    }

    static SBI_SPEC_VERSION: AtomicUsize = AtomicUsize::new(0);
    static SBI_HAS_BASE: AtomicBool = AtomicBool::new(false);
    static SBI_HAS_IPI: AtomicBool = AtomicBool::new(false);
    static SBI_HAS_RFENCE: AtomicBool = AtomicBool::new(false);
    static SBI_HAS_HSM: AtomicBool = AtomicBool::new(false);

    /// Legacy SBI takes a physical pointer to a hart bitmap. Serialize that
    /// compatibility path; v0.2 mask+base calls do not use this lock.
    static LEGACY_HART_MASK_LOCK: Mutex<()> = Mutex::new(());
    static mut LEGACY_HART_MASK: usize = 0;

    fn sbi_call_legacy(which: usize, arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
        let mut ret = arg0;
        // SAFETY: the register assignment is the SBI v0.1 calling convention.
        unsafe {
            asm!(
                "ecall",
                inlateout("a0") ret,
                in("a1") arg1,
                in("a2") arg2,
                in("a3") arg3,
                in("a7") which,
                options(nostack)
            );
        }
        ret
    }

    fn sbi_call_ext(eid: usize, fid: usize, args: [usize; 6]) -> SbiRet {
        let mut a0 = args[0];
        let mut a1 = args[1];
        // SAFETY: the register assignment is the SBI v0.2+ calling convention.
        unsafe {
            asm!(
                "ecall",
                inlateout("a0") a0,
                inlateout("a1") a1,
                in("a2") args[2],
                in("a3") args[3],
                in("a4") args[4],
                in("a5") args[5],
                in("a6") fid,
                in("a7") eid,
                options(nostack)
            );
        }
        SbiRet {
            error: a0 as isize,
            value: a1,
        }
    }

    fn probe_extension(extension: usize) -> bool {
        let ret = sbi_call_ext(
            SBI_EXT_BASE,
            SBI_EXT_BASE_PROBE_EXTENSION,
            [extension, 0, 0, 0, 0, 0],
        );
        ret.is_ok() && ret.value != 0
    }

    /// Probe modern extensions once, after the boot hart has cleared BSS.
    /// A v0.1 implementation simply fails the BASE call and keeps every
    /// operation on the legacy compatibility path.
    pub fn init() {
        let version = sbi_call_ext(SBI_EXT_BASE, SBI_EXT_BASE_GET_SPEC_VERSION, [0; 6]);
        if !version.is_ok() {
            crate::println!("[sbi] legacy v0.1 interface");
            return;
        }

        SBI_HAS_BASE.store(true, Ordering::Release);
        SBI_SPEC_VERSION.store(version.value, Ordering::Release);
        let has_ipi = probe_extension(SBI_EXT_IPI);
        let has_rfence = probe_extension(SBI_EXT_RFENCE);
        let has_hsm = probe_extension(SBI_EXT_HSM);
        SBI_HAS_IPI.store(has_ipi, Ordering::Release);
        SBI_HAS_RFENCE.store(has_rfence, Ordering::Release);
        SBI_HAS_HSM.store(has_hsm, Ordering::Release);
        crate::println!(
            "[sbi] spec={:#x} ipi={} rfence={} hsm={}",
            version.value,
            has_ipi,
            has_rfence,
            has_hsm
        );
    }

    pub fn set_timer(timer: usize) {
        sbi_call_legacy(SBI_SET_TIMER, timer, 0, 0, 0);
    }

    pub fn console_putchar(c: usize) {
        sbi_call_legacy(SBI_CONSOLE_PUTCHAR, c, 0, 0, 0);
    }

    pub fn console_getchar() -> usize {
        sbi_call_legacy(SBI_CONSOLE_GETCHAR, 0, 0, 0, 0)
    }

    fn with_legacy_hart_mask(hart_mask: usize, call: impl FnOnce(usize) -> usize) -> SbiRet {
        if hart_mask == 0 {
            return SbiRet::success(0);
        }
        let _guard = LEGACY_HART_MASK_LOCK.lock();
        // SAFETY: the lock serializes the static bitmap. Kernel BSS is covered
        // by the identity mapping supplied to firmware, so the pointer is a
        // valid physical SBI v0.1 hart-mask address.
        unsafe {
            LEGACY_HART_MASK = hart_mask;
            let mask_ptr = &raw const LEGACY_HART_MASK as usize;
            let value = call(mask_ptr);
            LEGACY_HART_MASK = 0;
            SbiRet::success(value)
        }
    }

    /// Send one supervisor software interrupt to every hart selected by the
    /// physical-ID bitmap.
    pub fn send_ipi_mask(hart_mask: usize) -> SbiRet {
        if hart_mask == 0 {
            return SbiRet::success(0);
        }
        if SBI_HAS_IPI.load(Ordering::Acquire) {
            return sbi_call_ext(
                SBI_EXT_IPI,
                SBI_EXT_IPI_SEND_IPI,
                [hart_mask, 0, 0, 0, 0, 0],
            );
        }
        with_legacy_hart_mask(hart_mask, |mask_ptr| {
            sbi_call_legacy(SBI_SEND_IPI, mask_ptr, 0, 0, 0)
        })
    }

    pub fn send_ipi(hart_id: usize) {
        if hart_id < usize::BITS as usize {
            let _ = send_ipi_mask(1usize << hart_id);
        }
    }

    pub fn remote_fence_i(hart_mask: usize) -> SbiRet {
        if hart_mask == 0 {
            return SbiRet::success(0);
        }
        if SBI_HAS_RFENCE.load(Ordering::Acquire) {
            return sbi_call_ext(
                SBI_EXT_RFENCE,
                SBI_EXT_RFENCE_REMOTE_FENCE_I,
                [hart_mask, 0, 0, 0, 0, 0],
            );
        }
        with_legacy_hart_mask(hart_mask, |mask_ptr| {
            sbi_call_legacy(SBI_REMOTE_FENCE_I, mask_ptr, 0, 0, 0)
        })
    }

    pub fn remote_sfence_vma(hart_mask: usize, start: usize, size: usize) -> SbiRet {
        if hart_mask == 0 {
            return SbiRet::success(0);
        }
        if SBI_HAS_RFENCE.load(Ordering::Acquire) {
            return sbi_call_ext(
                SBI_EXT_RFENCE,
                SBI_EXT_RFENCE_REMOTE_SFENCE_VMA,
                [hart_mask, 0, start, size, 0, 0],
            );
        }
        with_legacy_hart_mask(hart_mask, |mask_ptr| {
            sbi_call_legacy(SBI_REMOTE_SFENCE_VMA, mask_ptr, start, size, 0)
        })
    }

    pub fn remote_sfence_vma_asid(
        hart_mask: usize,
        start: usize,
        size: usize,
        asid: usize,
    ) -> SbiRet {
        if hart_mask == 0 {
            return SbiRet::success(0);
        }
        if SBI_HAS_RFENCE.load(Ordering::Acquire) {
            return sbi_call_ext(
                SBI_EXT_RFENCE,
                SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID,
                [hart_mask, 0, start, size, asid, 0],
            );
        }
        with_legacy_hart_mask(hart_mask, |mask_ptr| {
            sbi_call_legacy(SBI_REMOTE_SFENCE_VMA_ASID, mask_ptr, start, size, asid)
        })
    }

    pub fn remote_sfence_vma_all(hart_mask: usize) {
        let _ = remote_sfence_vma(hart_mask, 0, usize::MAX);
    }

    pub fn shutdown() -> ! {
        sbi_call_legacy(SBI_SHUTDOWN, 0, 0, 0, 0);
        panic!("It should shutdown!");
    }

    pub fn hart_start(hart_id: usize, start_addr: usize, opaque: usize) -> usize {
        if SBI_HAS_BASE.load(Ordering::Acquire) && !SBI_HAS_HSM.load(Ordering::Acquire) {
            return SBI_ERR_NOT_SUPPORTED as usize;
        }
        sbi_call_ext(
            SBI_EXT_HSM,
            SBI_EXT_HSM_HART_START,
            [hart_id, start_addr, opaque, 0, 0, 0],
        )
        .error as usize
    }
}

#[cfg(target_arch = "riscv64")]
pub use riscv::*;

#[cfg(not(target_arch = "riscv64"))]
mod stub {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SbiRet {
        pub error: isize,
        pub value: usize,
    }

    #[inline(always)]
    fn unsupported(name: &str) -> ! {
        panic!("SBI call {} is not supported on this architecture", name);
    }

    pub fn init() {}
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
    pub fn send_ipi_mask(_hart_mask: usize) -> SbiRet {
        unsupported("send_ipi_mask");
    }
    pub fn remote_fence_i(_hart_mask: usize) -> SbiRet {
        unsupported("remote_fence_i");
    }
    pub fn remote_sfence_vma(_hart_mask: usize, _start: usize, _size: usize) -> SbiRet {
        unsupported("remote_sfence_vma");
    }
    pub fn remote_sfence_vma_asid(
        _hart_mask: usize,
        _start: usize,
        _size: usize,
        _asid: usize,
    ) -> SbiRet {
        unsupported("remote_sfence_vma_asid");
    }
    pub fn remote_sfence_vma_all(_hart_mask: usize) {
        unsupported("remote_sfence_vma_all");
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
