//! Constants used in rCore

use core::sync::atomic::{AtomicUsize, Ordering};

// Linux userland can place MiB-scale buffers on the initial stack.
// Keep this modest because current user stacks are eagerly framed.
pub const USER_STACK_SIZE: usize = 4096 * 512; // 2 MiB
// Keep the initial program break away from the top of the first thread stack.
// Some libc `sbrk()` paths reject growth when brk starts too close to stack.
pub const USER_HEAP_GAP: usize = 64 * 1024; // 64 KiB
// Debug builds keep assertions and less optimized call frames; give kernel
// stacks extra headroom so syscall/fork diagnostics can run without touching
// the guard page. Release keeps the smaller footprint.
#[cfg(debug_assertions)]
pub const KERNEL_STACK_SIZE: usize = 4096 * 16; // 64 KiB
#[cfg(not(debug_assertions))]
pub const KERNEL_STACK_SIZE: usize = 4096 * 8; // 32 KiB
// Kernel heap must be large enough for fork-heavy LTP runs on glibc.
// 256 MiB reduces allocator OOMs in long `fork13` stress loops.
#[allow(dead_code)]
pub const KERNEL_HEAP_SIZE: usize = 0x2000_0000; // 512 MiB
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;
// Keep MAP_GROWSDOWN stacks separated from lower VMAs. Linux defaults this
// policy to hundreds of pages rather than a single unmapped guard page.
pub const USER_STACK_GUARD_GAP: usize = PAGE_SIZE * 256; // 1 MiB

#[cfg(not(target_arch = "loongarch64"))]
pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
/// User-accessible sigreturn trampoline page (separate from kernel trap trampoline).
#[cfg(not(target_arch = "loongarch64"))]
pub const SIGRETURN_TRAMPOLINE: usize = TRAMPOLINE - PAGE_SIZE;
#[cfg(not(target_arch = "loongarch64"))]
pub const TRAP_CONTEXT: usize = SIGRETURN_TRAMPOLINE - PAGE_SIZE;
// Keep RISC-V kernel stacks out of the top Sv39 root entry, which holds the
// per-mm trap context and trampoline pages. The stack window starts one GiB
// below TRAMPOLINE so it can be shared as kernel-only root entries.
#[cfg(target_arch = "riscv64")]
pub const KERNEL_STACK_TOP: usize = TRAMPOLINE - 0x4000_0000;

/// Kernel window that maps device MMIO into the high half, mirroring Linux
/// `ioremap()`.
///
/// Identity-mapping device registers at their low physical addresses puts them
/// in Sv39 root entry 0, which is also where user programs live, so that root
/// can never be shared into a user page table. Every driver or interrupt access
/// then has to switch SATP and flush the TLB. Linux instead keeps the whole
/// kernel half in every `pgd` (`sync_kernel_mappings()`) and places device
/// registers in the kernel `ioremap`/vmalloc range, so an MMIO access needs no
/// page-table change at all.
///
/// Root entry 509 covers `[0xffff_ffff_4000_0000, 0xffff_ffff_8000_0000)` and
/// sits just below the shared kernel-stack root (510) and the trampoline root
/// (511), so it can be shared into user page tables on its own.
#[cfg(target_arch = "riscv64")]
pub const KERNEL_MMIO_WINDOW_BASE: usize = 0xffff_ffff_4000_0000;
/// Size of the MMIO window: exactly one Sv39 root entry. Every device physical
/// address on the `virt` machine is below 1 GiB, so one root entry covers all
/// of them and the window needs no allocator.
#[cfg(target_arch = "riscv64")]
pub const KERNEL_MMIO_WINDOW_SIZE: usize = 0x4000_0000;

/// Kernel virtual address of a device physical address inside the MMIO window.
///
/// The mapping is a fixed offset, so this is usable in `const` context and no
/// per-device bookkeeping is required.
#[cfg(target_arch = "riscv64")]
pub const fn mmio_va(pa: usize) -> usize {
    debug_assert!(pa < KERNEL_MMIO_WINDOW_SIZE);
    KERNEL_MMIO_WINDOW_BASE + pa
}

// LoongArch64 uses split PGDL/PGDH and a 3-level (Sv39-style) page walk here,
// so the user-range VA width is 39 bits. Keep trap-related pages inside the
// low canonical range (max 0x0000_003f_ffff_ffff) so PGDL can translate them.
#[cfg(target_arch = "loongarch64")]
pub const TRAMPOLINE: usize = 0x0000_003f_ffff_f000;
/// User-accessible sigreturn trampoline page (separate from kernel trap trampoline).
#[cfg(target_arch = "loongarch64")]
pub const SIGRETURN_TRAMPOLINE: usize = TRAMPOLINE - PAGE_SIZE;
#[cfg(target_arch = "loongarch64")]
pub const TRAP_CONTEXT: usize = SIGRETURN_TRAMPOLINE - PAGE_SIZE;
#[cfg(target_arch = "loongarch64")]
pub const KERNEL_STACK_TOP: usize = 0xffff_ffff_ffff_f000;
#[cfg(target_arch = "riscv64")]
pub const MAX_HARTS: usize = 8;
#[cfg(target_arch = "loongarch64")]
pub const MAX_HARTS: usize = 12;
#[allow(dead_code)]
pub const KERNEL_ENTRY_PA: usize = 0x8020_0000;
/// Return (bottom, top) of a kernel stack in kernel space. Bottom is smaller while top is bigger.
/// and we use top - xx to push data...
#[allow(dead_code)]
pub fn kernel_stack_position(app_id: usize) -> (usize, usize) {
    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    let top = KERNEL_STACK_TOP - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    #[cfg(not(any(target_arch = "loongarch64", target_arch = "riscv64")))]
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

/// 启动 DTB 中允许保存的内存和设备区间上限。QEMU virt 的实际条目远少于
/// 此值；固定数组保证早期启动无需依赖动态分配。
pub const MAX_VIRTIO_MMIO_DEVICES: usize = 8;

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
    (0x0c00_0000, 0x60_0000), // RISC-V PLIC
    // QEMU virt exposes eight ordered virtio-mmio transports.
    (0x1000_1000, 0x00_8000),
];
#[cfg(all(target_arch = "loongarch64", feature = "loongarch_board"))]
const UART_MMIO_BASE: usize = 0x8000_0000_1fe2_0000;
#[cfg(all(target_arch = "loongarch64", not(feature = "loongarch_board")))]
const UART_MMIO_BASE: usize = 0x1fe0_01e0;
#[cfg(target_arch = "loongarch64")]
pub const MMIO: &[(usize, usize)] = &[
    (0x0010_0000, 0x00_2000), // VIRT_TEST/RTC  in virt machine
    (0x1000_0000, 0x00_1000), // LoongArch PCH-PIC
    (0x1000_1000, 0x00_1000), // Virtio Block in virt machine
    (0x1000_2000, 0x00_1000), // Virtio Block (bus 1) in virt machine
    (0x100e_0000, 0x00_1000), // QEMU virt poweroff device (shutdown register)
    (UART_MMIO_BASE, 0x1000), // UART for console output
];

pub const TRAP_CONTEXT_BASE: usize = TRAP_CONTEXT;
