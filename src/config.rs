//! Constants used in rCore

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Once;

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
// BuildStorm 编译需要完整的 12 核拓扑。两种架构的入口汇编都必须预留
// 相同数量的早期启动栈，并与这里的上限保持一致。
#[cfg(target_arch = "riscv64")]
pub const MAX_HARTS: usize = 12;
#[cfg(target_arch = "loongarch64")]
pub const MAX_HARTS: usize = 12;
#[cfg(target_arch = "riscv64")]
#[allow(dead_code)]
pub const KERNEL_ENTRY_PA: usize = 0x8020_0000;
#[cfg(target_arch = "loongarch64")]
#[allow(dead_code)]
pub const KERNEL_ENTRY_PA: usize = 0x8000_0000;
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

///会从DTB里面更新
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
/// DTB memory nodes may include firmware/boot-reserved memory without a
/// reserved-memory node. Keep the first 2 MiB of the lowest RAM range unused.
pub const BOOT_RESERVED_MEMORY_SIZE: usize = 0x20_0000;

#[cfg(target_arch = "loongarch64")]
pub const DEVICE_TREE_ADDR: usize = 0x100000;
#[cfg(target_arch = "loongarch64")]
pub const DEVICE_TREE_MAX_SIZE: usize = 0x200000;

pub const MAX_PHYS_MEMORY_REGIONS: usize = 3;
pub const MAX_DTB_MMIO_REGIONS: usize = 32;
pub const MAX_VIRTIO_MMIO_DEVICES: usize = 8;

/// DTB 在早期启动阶段解析出的平台资源。
///
/// 这些信息只由启动核写入一次，所以用 [`Once`] 整体发布即可，
/// 无需为每个 range 的起止地址分别维护原子变量。
struct PlatformInfo {
    phys_mem_ranges: [(usize, usize); MAX_PHYS_MEMORY_REGIONS],
    phys_mem_range_count: usize,
    dtb_mmio_ranges: [(usize, usize); MAX_DTB_MMIO_REGIONS],
    dtb_mmio_range_count: usize,
    virtio_mmio_bases: [usize; MAX_VIRTIO_MMIO_DEVICES],
    virtio_mmio_base_count: usize,
}

const DEFAULT_PLATFORM_INFO: PlatformInfo = PlatformInfo {
    phys_mem_ranges: {
        let mut ranges = [(0, 0); MAX_PHYS_MEMORY_REGIONS];
        ranges[0] = (DEFAULT_MEMORY_START, DEFAULT_MEMORY_END);
        ranges
    },
    phys_mem_range_count: 1,
    dtb_mmio_ranges: [(0, 0); MAX_DTB_MMIO_REGIONS],
    dtb_mmio_range_count: 0,
    virtio_mmio_bases: [0; MAX_VIRTIO_MMIO_DEVICES],
    virtio_mmio_base_count: 0,
};

static PLATFORM_INFO: Once<PlatformInfo> = Once::new();

/// 发布从 DTB 中解析出的物理内存、MMIO 和 virtio-mmio 资源。
///
/// 该函数必须在堆和其他 CPU 启动前由启动核调用，且只有首次调用生效。
/// 传入的物理内存列表为空时，保留 QEMU 的默认内存区间。
pub fn init_platform_info(
    phys_mem_ranges: &[(usize, usize)],
    dtb_mmio_ranges: &[(usize, usize)],
    virtio_mmio_bases: &[usize],
) {
    PLATFORM_INFO.call_once(|| {
        let mut info = PlatformInfo {
            ..DEFAULT_PLATFORM_INFO
        };

        let mut count = 0;
        for &(start, end) in phys_mem_ranges {
            if count == MAX_PHYS_MEMORY_REGIONS {
                break;
            }
            if end > start {
                info.phys_mem_ranges[count] = (start, end);
                count += 1;
            }
        }
        if count != 0 {
            info.phys_mem_range_count = count;
        }

        info.dtb_mmio_range_count = 0;
        for &(start, end) in dtb_mmio_ranges {
            if info.dtb_mmio_range_count == MAX_DTB_MMIO_REGIONS {
                break;
            }
            if end > start {
                info.dtb_mmio_ranges[info.dtb_mmio_range_count] = (start, end);
                info.dtb_mmio_range_count += 1;
            }
        }

        for &base in virtio_mmio_bases {
            if info.virtio_mmio_base_count == MAX_VIRTIO_MMIO_DEVICES {
                break;
            }
            if base != 0 && !info.virtio_mmio_bases[..info.virtio_mmio_base_count].contains(&base) {
                info.virtio_mmio_bases[info.virtio_mmio_base_count] = base;
                info.virtio_mmio_base_count += 1;
            }
        }
        info
    });
}

#[inline]
/// 读取已发布的平台信息；DTB 尚未解析时返回默认配置。
fn platform_info() -> &'static PlatformInfo {
    PLATFORM_INFO.get().unwrap_or(&DEFAULT_PLATFORM_INFO)
}

/// 返回所有物理内存段的最小起始地址。
pub fn phys_mem_start() -> usize {
    let info = platform_info();
    info.phys_mem_ranges[..info.phys_mem_range_count]
        .iter()
        .map(|&(start, _)| start)
        .min()
        .unwrap_or(DEFAULT_MEMORY_START)
}

/// 返回所有物理内存段的最大结束地址，中间可能存在空洞。
pub fn phys_mem_end() -> usize {
    let info = platform_info();
    info.phys_mem_ranges[..info.phys_mem_range_count]
        .iter()
        .map(|&(_, end)| end)
        .max()
        .unwrap_or(DEFAULT_MEMORY_END)
}

/// 依次访问 DTB 报告的每一段物理内存，不会把中间的空洞合并成 RAM。
pub fn for_each_phys_mem_range(mut f: impl FnMut(usize, usize)) {
    let info = platform_info();
    for &(start, end) in &info.phys_mem_ranges[..info.phys_mem_range_count] {
        f(start, end);
    }
}

/// 返回各段物理内存容量之和，不计入段之间的地址空洞。
pub fn phys_mem_total() -> usize {
    let info = platform_info();
    info.phys_mem_ranges[..info.phys_mem_range_count]
        .iter()
        .fold(0usize, |total, &(start, end)| {
            total.saturating_add(end - start)
        })
}

/// 检查整个物理地址区间是否落在同一段 RAM 内。
#[cfg(target_arch = "loongarch64")]
pub fn phys_range_in_ram(start: usize, len: usize) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    let info = platform_info();
    info.phys_mem_ranges[..info.phys_mem_range_count]
        .iter()
        .any(|&(range_start, range_end)| start >= range_start && end <= range_end)
}

/// 依次访问从 DTB 中发现、需要进行恒等映射的 MMIO 区间。
pub fn for_each_dtb_mmio_range(mut f: impl FnMut(usize, usize)) {
    let info = platform_info();
    for &(start, end) in &info.dtb_mmio_ranges[..info.dtb_mmio_range_count] {
        f(start, end);
    }
}

/// 依次访问 DTB 中发现的 virtio-mmio 设备基地址。
pub fn for_each_virtio_mmio_device_base(mut f: impl FnMut(usize)) {
    let info = platform_info();
    for &base in &info.virtio_mmio_bases[..info.virtio_mmio_base_count] {
        f(base);
    }
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
