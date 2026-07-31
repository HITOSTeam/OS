//! LoongArch EIOINTC and PCH-PIC support for PCI INTx block interrupts.
//!
//! QEMU's virt machine routes PCI INTx through PCH-PIC inputs 16..19 into
//! EIOINTC vectors 16..19, which arrive on CPU interrupt line 3.

use core::{
    arch::asm,
    ptr::{read_volatile, write_volatile},
    sync::atomic::{AtomicBool, Ordering},
};
use spin::Mutex;

const IOCSR_MISC_FUNC: usize = 0x420;
const IOCSR_MISC_FUNC_EXT_IOI_EN: u64 = 1 << 48;
const EIOINTC_NODEMAP: usize = 0x14a0;
const EIOINTC_IPMAP: usize = 0x14c0;
const EIOINTC_ENABLE: usize = 0x1600;
const EIOINTC_BOUNCE: usize = 0x1680;
const EIOINTC_ISR: usize = 0x1800;
const EIOINTC_ROUTE: usize = 0x1c00;
const EIOINTC_VECTORS: usize = 256;

const PCH_PIC_BASE: usize = 0x1000_0000;
const PCH_PIC_MASK: usize = 0x20;
const PCH_PIC_EDGE: usize = 0x60;
const PCH_PIC_CLEAR: usize = 0x80;
const PCH_PIC_HTVEC: usize = 0x200;
const PCH_PIC_POL: usize = 0x3e0;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static CONFIG_LOCK: Mutex<()> = Mutex::new(());

fn iocsr_read64(register: usize) -> u64 {
    let value: u64;
    // SAFETY: EIOINTC registers are privileged IOCSR addresses.
    unsafe { asm!("iocsrrd.d {}, {}", out(reg) value, in(reg) register, options(nostack)) };
    value
}

fn iocsr_write64(register: usize, value: u64) {
    // SAFETY: EIOINTC registers are privileged IOCSR addresses.
    unsafe { asm!("iocsrwr.d {}, {}", in(reg) value, in(reg) register, options(nostack)) };
}

fn iocsr_write32(register: usize, value: u32) {
    // SAFETY: EIOINTC registers are privileged IOCSR addresses.
    unsafe { asm!("iocsrwr.w {}, {}", in(reg) value, in(reg) register, options(nostack)) };
}

fn pch_read32(offset: usize) -> u32 {
    // SAFETY: PCH-PIC is identity-mapped as device MMIO.
    unsafe { read_volatile((PCH_PIC_BASE + offset) as *const u32) }
}

fn pch_write32(offset: usize, value: u32) {
    // SAFETY: PCH-PIC is identity-mapped as device MMIO.
    unsafe { write_volatile((PCH_PIC_BASE + offset) as *mut u32, value) }
}

fn pch_write8(offset: usize, value: u8) {
    // SAFETY: PCH-PIC is identity-mapped as device MMIO.
    unsafe { write_volatile((PCH_PIC_BASE + offset) as *mut u8, value) }
}

fn enable_cpu_line() {
    let mut ecfg: usize;
    // SAFETY: ECFG is a privileged local interrupt-enable CSR.
    unsafe {
        asm!("csrrd {}, 0x4", out(reg) ecfg);
        ecfg |= super::csr_defs::ECFG_LIE_EIOINTC;
        asm!("csrwr {}, 0x4", in(reg) ecfg);
    }
}

pub fn init_external_interrupts() {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let misc = iocsr_read64(IOCSR_MISC_FUNC);
        iocsr_write64(IOCSR_MISC_FUNC, misc | IOCSR_MISC_FUNC_EXT_IOI_EN);

        // Route every vector group to node 0, interrupt pin 1 and CPU 0.
        for index in 0..(EIOINTC_VECTORS / 32) {
            let data = ((1u32 << (index * 2 + 1)) << 16) | (1u32 << (index * 2));
            iocsr_write32(EIOINTC_NODEMAP + index * 4, data);
        }
        for index in 0..(EIOINTC_VECTORS / 128) {
            iocsr_write32(EIOINTC_IPMAP + index * 4, 0x0202_0202);
        }
        for index in 0..(EIOINTC_VECTORS / 4) {
            iocsr_write32(EIOINTC_ROUTE + index * 4, 0x0101_0101);
        }
        for index in 0..(EIOINTC_VECTORS / 32) {
            iocsr_write32(EIOINTC_BOUNCE + index * 4, u32::MAX);
        }
        for index in 0..(EIOINTC_VECTORS / 64) {
            iocsr_write64(EIOINTC_ENABLE + index * 8, 0);
        }

        // PCI INTx is level-high in QEMU's FDT. Start with all PCH inputs
        // masked and configure level/high polarity before unmasking a device.
        pch_write32(PCH_PIC_MASK, u32::MAX);
        pch_write32(PCH_PIC_MASK + 4, u32::MAX);
        pch_write32(PCH_PIC_EDGE, 0);
        pch_write32(PCH_PIC_EDGE + 4, 0);
        pch_write32(PCH_PIC_POL, 0);
        pch_write32(PCH_PIC_POL + 4, 0);
    }
    enable_cpu_line();
}

pub fn enable_external_irq(vector: usize) {
    assert!(vector < 64);
    init_external_interrupts();
    let _guard = CONFIG_LOCK.lock();

    let pch_offset = (vector / 32) * 4;
    let pch_bit = 1u32 << (vector % 32);
    pch_write8(PCH_PIC_HTVEC + vector, vector as u8);
    // Match Linux pch_pic_unmask_irq(): clear any stale latched state before
    // exposing this level-triggered source.
    pch_write32(PCH_PIC_CLEAR + pch_offset, pch_bit);
    pch_write32(
        PCH_PIC_MASK + pch_offset,
        pch_read32(PCH_PIC_MASK + pch_offset) & !pch_bit,
    );

    let eio_offset = (vector / 64) * 8;
    let eio_bit = 1u64 << (vector % 64);
    for base in [EIOINTC_ENABLE, EIOINTC_BOUNCE] {
        let register = base + eio_offset;
        iocsr_write64(register, iocsr_read64(register) | eio_bit);
    }
}

fn claim() -> Option<usize> {
    for index in 0..(EIOINTC_VECTORS / 64) {
        let pending = iocsr_read64(EIOINTC_ISR + index * 8);
        if pending != 0 {
            return Some(index * 64 + pending.trailing_zeros() as usize);
        }
    }
    None
}

fn complete(vector: usize) {
    let offset = (vector / 64) * 8;
    iocsr_write64(EIOINTC_ISR + offset, 1u64 << (vector % 64));
}

pub fn handle_external_interrupt() {
    while let Some(vector) = claim() {
        let _ = crate::drivers::block::handle_irq(vector);
        complete(vector);
    }
}
