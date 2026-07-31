//! Constants used in rCore

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
// 两种架构的入口汇编都为最多 12 个 hart 预留早期启动栈，并与这里的
// 静态容量保持一致。运行时实际启动的 hart 集合由 DTB 决定，可能小于该值。
#[cfg(target_arch = "riscv64")]
pub const MAX_HARTS: usize = 12;
#[cfg(target_arch = "loongarch64")]
pub const MAX_HARTS: usize = 12;

/// 编译期支持的 hart ID 位图。所有 per-hart 静态数组均以该上限分配。
pub const fn supported_hart_mask() -> usize {
    if MAX_HARTS >= usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << MAX_HARTS) - 1
    }
}

/// 返回 DTB 描述的运行时 hart 集合。
///
/// 启动 DTB 尚未发布时，架构数据访问器会直接 panic，避免以静态容量伪造拓扑。
pub fn active_hart_mask() -> usize {
    crate::arch::DTB_data::active_hart_mask()
}

pub fn active_hart_count() -> usize {
    active_hart_mask().count_ones() as usize
}
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

pub fn clock_freq() -> usize {
    crate::arch::DTB_data::clock_frequency()
}

pub const MAX_PHYS_MEMORY_REGIONS: usize = 16;
pub const MAX_DTB_MMIO_REGIONS: usize = 32;
pub const MAX_RESERVED_MEMORY_REGIONS: usize = 16;
pub const MAX_VIRTIO_MMIO_DEVICES: usize = 8;

/// 返回所有物理内存段的最小起始地址。
pub fn phys_mem_start() -> usize {
    let mut minimum = usize::MAX;
    for_each_phys_mem_range(|start, _| minimum = minimum.min(start));
    assert_ne!(minimum, usize::MAX, "DTB contains no physical memory range");
    minimum
}

/// 返回所有物理内存段的最大结束地址，中间可能存在空洞。
pub fn phys_mem_end() -> usize {
    let mut maximum = 0usize;
    for_each_phys_mem_range(|_, end| maximum = maximum.max(end));
    assert_ne!(maximum, 0, "DTB contains no physical memory range");
    maximum
}

/// 依次访问 DTB 报告的每一段物理内存，不会把中间的空洞合并成 RAM。
pub fn for_each_phys_mem_range(mut f: impl FnMut(usize, usize)) {
    crate::arch::DTB_data::for_each_phys_mem_range(|start, end| f(start, end));
}

/// 返回各段物理内存容量之和，不计入段之间的地址空洞。
pub fn phys_mem_total() -> usize {
    let mut total = 0usize;
    for_each_phys_mem_range(|start, end| total = total.saturating_add(end - start));
    total
}

/// 检查整个物理地址区间是否落在同一段 RAM 内。
#[cfg(target_arch = "loongarch64")]
pub fn phys_range_in_ram(start: usize, len: usize) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    let mut in_ram = false;
    for_each_phys_mem_range(|range_start, range_end| {
        in_ram |= start >= range_start && end <= range_end;
    });
    in_ram
}

/// 依次访问从 DTB 中发现、需要进行恒等映射的 MMIO 区间。
pub fn for_each_dtb_mmio_range(mut f: impl FnMut(usize, usize)) {
    crate::arch::DTB_data::for_each_mmio_range(|start, end| f(start, end));
}

/// 依次访问 DTB 中声明的保留物理内存区间。
pub fn for_each_reserved_range(mut f: impl FnMut(usize, usize)) {
    crate::arch::DTB_data::for_each_reserved_range(|start, end| f(start, end));
}

/// 依次访问 DTB 中发现的 virtio-mmio 设备基地址。
pub fn for_each_virtio_mmio_device_base(mut f: impl FnMut(usize)) {
    crate::arch::DTB_data::for_each_virtio_mmio_device(|base, _| f(base));
}

pub const TRAP_CONTEXT_BASE: usize = TRAP_CONTEXT;
