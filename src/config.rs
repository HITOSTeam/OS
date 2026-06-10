//! Constants used in rCore

use core::sync::atomic::{AtomicUsize, Ordering};

// Linux userland (busybox/glibc) expects a large initial stack.
pub const USER_STACK_SIZE: usize = 4096 * 256; // 1 MiB
// Keep the initial program break away from the top of the first thread stack.
// Some libc `sbrk()` paths reject growth when brk starts too close to stack.
pub const USER_HEAP_GAP: usize = 64 * 1024; // 64 KiB
pub const KERNEL_STACK_SIZE: usize = 4096 * 8; // 32KB
// Kernel heap must be large enough for fork-heavy LTP runs on glibc.
// LoongArch QEMU virt places the linked kernel near the top of the high RAM
// bank, so an oversized static heap can push `.bss` past the end of usable
// memory and fault during early `clear_bss()`.
#[cfg(target_arch = "loongarch64")]
pub const KERNEL_HEAP_SIZE: usize = 0x2000_0000; // 512 MiB
#[cfg(not(target_arch = "loongarch64"))]
pub const KERNEL_HEAP_SIZE: usize = 0x2000_0000; // 512 MiB
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;

#[cfg(not(target_arch = "loongarch64"))]
pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
/// User-accessible sigreturn trampoline page (separate from kernel trap trampoline).
#[cfg(not(target_arch = "loongarch64"))]
pub const SIGRETURN_TRAMPOLINE: usize = TRAMPOLINE - PAGE_SIZE;
#[cfg(not(target_arch = "loongarch64"))]
pub const TRAP_CONTEXT: usize = SIGRETURN_TRAMPOLINE - PAGE_SIZE;

// LoongArch64 uses split PGDL/PGDH and a 3-level (Sv39-style) page walk here,
// so keep user trap-related pages inside the low canonical user half, matching
// RocketOS and avoiding extra high-half refill assumptions in the current path.
#[cfg(target_arch = "loongarch64")]
pub const TRAMPOLINE: usize = 0x0000_003f_ffff_f000;
/// User-accessible sigreturn trampoline page (separate from kernel trap trampoline).
#[cfg(target_arch = "loongarch64")]
pub const SIGRETURN_TRAMPOLINE: usize = TRAMPOLINE - PAGE_SIZE;
#[cfg(target_arch = "loongarch64")]
pub const TRAP_CONTEXT: usize = SIGRETURN_TRAMPOLINE - PAGE_SIZE;
#[cfg(target_arch = "loongarch64")]
pub const KERNEL_STACK_TOP: usize = 0xffff_ffff_ffff_f000;
pub const MAX_HARTS: usize = 4;
#[allow(dead_code)]
pub const KERNEL_ENTRY_PA: usize = 0x8020_0000;
/// Return (bottom, top) of a kernel stack in kernel space. Bottom is smaller while top is bigger.
/// and we use top - xx to push data...
#[allow(dead_code)]
pub fn kernel_stack_position(app_id: usize) -> (usize, usize) {
    #[cfg(target_arch = "loongarch64")]
    let top = KERNEL_STACK_TOP - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    #[cfg(not(target_arch = "loongarch64"))]
    let top = TRAMPOLINE - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    (bottom, top)
}

#[cfg(target_arch = "loongarch64")]
pub const DEFAULT_CLOCK_FREQ: usize = 100_000_000;
#[cfg(target_arch = "riscv64")]
pub const DEFAULT_CLOCK_FREQ: usize = 10_000_000;

static CLOCK_FREQ: AtomicUsize = AtomicUsize::new(0);

#[allow(dead_code)]
pub fn set_clock_freq(freq: usize) {
    if freq != 0 {
        CLOCK_FREQ.store(freq, Ordering::Relaxed);
    }
}

pub fn clock_freq() -> usize {
    let freq = CLOCK_FREQ.load(Ordering::Relaxed);
    if freq == 0 { DEFAULT_CLOCK_FREQ } else { freq }
}

// QEMU virt RAM starts at 0x8000_0000. Default to 512MiB to match common `-m 512M`.
pub const DEFAULT_MEMORY_START: usize = 0x8000_0000;
pub const DEFAULT_MEMORY_END: usize = 0xA000_0000;

#[cfg(target_arch = "loongarch64")]
pub const DEVICE_TREE_ADDR: usize = 0x100000;
#[cfg(target_arch = "loongarch64")]
pub const DEVICE_TREE_MAX_SIZE: usize = 0x200000;

static PHYS_MEM_START: AtomicUsize = AtomicUsize::new(DEFAULT_MEMORY_START);
static PHYS_MEM_END: AtomicUsize = AtomicUsize::new(DEFAULT_MEMORY_END);

#[allow(dead_code)]
pub fn set_phys_mem_range(start: usize, end: usize) {
    if end > start {
        PHYS_MEM_START.store(start, Ordering::SeqCst);
        PHYS_MEM_END.store(end, Ordering::SeqCst);
    }
}

pub fn phys_mem_start() -> usize {
    PHYS_MEM_START.load(Ordering::SeqCst)
}

pub fn phys_mem_end() -> usize {
    PHYS_MEM_END.load(Ordering::SeqCst)
}

#[cfg(not(target_arch = "loongarch64"))]
pub const MMIO: &[(usize, usize)] = &[
    (0x0010_0000, 0x00_2000), // VIRT_TEST/RTC  in virt machine
    (0x1000_1000, 0x00_1000), // Virtio Block in virt machine
    (0x1000_2000, 0x00_1000), // Virtio Block (bus 1) in virt machine
];
#[cfg(all(target_arch = "loongarch64", feature = "loongarch_board"))]
const UART_MMIO_BASE: usize = 0x8000_0000_1fe2_0000;
#[cfg(all(target_arch = "loongarch64", not(feature = "loongarch_board")))]
const UART_MMIO_BASE: usize = 0x1fe0_01e0;
#[cfg(target_arch = "loongarch64")]
pub const MMIO: &[(usize, usize)] = &[
    (0x0010_0000, 0x00_2000), // VIRT_TEST/RTC  in virt machine
    (0x1000_1000, 0x00_1000), // Virtio Block in virt machine
    (0x1000_2000, 0x00_1000), // Virtio Block (bus 1) in virt machine
    (0x100e_0000, 0x00_1000), // QEMU virt poweroff device (shutdown register)
    (UART_MMIO_BASE, 0x1000), // UART for console output
];

pub const TRAP_CONTEXT_BASE: usize = TRAP_CONTEXT;
