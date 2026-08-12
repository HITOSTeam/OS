//! LoongArch 启动 DTB 的平台设备缓存。
//!
//! 固件只在启动期提供 DTB 指针。本模块在启动屏障之前复制串口、关机和 PCI
//! 主桥信息，使普通驱动不再依赖固定 QEMU 地址或再次遍历设备树。

use fdt::{Fdt, node::FdtNode};
use spin::Once;

use crate::config::{
    MAX_DTB_MMIO_REGIONS, MAX_HARTS, MAX_PHYS_MEMORY_REGIONS, MAX_RESERVED_MEMORY_REGIONS,
};

#[derive(Clone, Copy)]
pub struct ConsoleInfo {
    pub base: usize,
    pub size: usize,
    pub reg_shift: u8,
    pub reg_io_width: u8,
}

#[derive(Clone, Copy)]
pub struct PoweroffInfo {
    pub base: usize,
    pub offset: usize,
    pub value: usize,
    pub reg_io_width: u8,
}

#[derive(Clone, Copy)]
pub struct PciHostInfo {
    pub ecam_base: usize,
    pub ecam_size: usize,
    pub mem32_base: usize,
    pub mem32_size: usize,
    pub bus_start: u8,
}

struct DtbData {
    active_hart_mask: usize,
    discovered_harts: usize,
    ignored_harts: usize,
    phys_mem_ranges: [(usize, usize); MAX_PHYS_MEMORY_REGIONS],
    phys_mem_range_count: usize,
    reserved_ranges: [(usize, usize); MAX_RESERVED_MEMORY_REGIONS],
    reserved_range_count: usize,
    mmio_ranges: [(usize, usize); MAX_DTB_MMIO_REGIONS],
    mmio_range_count: usize,
    console: Option<ConsoleInfo>,
    poweroff: Option<PoweroffInfo>,
    pci_host: Option<PciHostInfo>,
}

static DTB_DATA: Once<DtbData> = Once::new();

/// 在 NUL 分隔的 compatible 列表中查找指定兼容串。
fn compatible(node: FdtNode<'_, '_>, expected: &[u8]) -> bool {
    node.property("compatible").is_some_and(|property| {
        property
            .value
            .split(|byte| *byte == 0)
            .any(|entry| entry == expected)
    })
}

fn available(node: FdtNode<'_, '_>) -> bool {
    node.property("status")
        .map(|property| matches!(property.as_str(), Some("okay" | "ok")))
        .unwrap_or(true)
}

fn node_is_memory(node: FdtNode<'_, '_>) -> bool {
    node.name.split('@').next() == Some("memory")
        || node
            .property("device_type")
            .and_then(|property| property.as_str())
            == Some("memory")
}

fn node_should_map_mmio(node: FdtNode<'_, '_>) -> bool {
    compatible(node, b"ns16550a")
        || compatible(node, b"qemu,fw-cfg-mmio")
        || compatible(node, b"syscon")
        || compatible(node, b"pci-host-ecam-generic")
}

fn push_range<const N: usize>(
    ranges: &mut [(usize, usize); N],
    count: &mut usize,
    start: usize,
    end: usize,
    kind: &str,
) {
    assert!(end > start, "invalid {kind} range: {start:#x}-{end:#x}");
    assert!(*count < N, "too many {kind} ranges (capacity {N})");
    ranges[*count] = (start, end);
    *count += 1;
}

fn sort_and_merge<const N: usize>(ranges: &mut [(usize, usize); N], count: &mut usize) {
    ranges[..*count].sort_unstable_by_key(|range| range.0);
    let mut merged = 0usize;
    for index in 0..*count {
        let (start, end) = ranges[index];
        if merged != 0 && start <= ranges[merged - 1].1 {
            ranges[merged - 1].1 = ranges[merged - 1].1.max(end);
        } else {
            ranges[merged] = (start, end);
            merged += 1;
        }
    }
    *count = merged;
}

fn parse_boot_memory(
    fdt: &Fdt<'_>,
) -> (
    [(usize, usize); MAX_PHYS_MEMORY_REGIONS],
    usize,
    [(usize, usize); MAX_RESERVED_MEMORY_REGIONS],
    usize,
    [(usize, usize); MAX_DTB_MMIO_REGIONS],
    usize,
) {
    let mut memory = [(0usize, 0usize); MAX_PHYS_MEMORY_REGIONS];
    let mut memory_count = 0usize;
    let mut reserved = [(0usize, 0usize); MAX_RESERVED_MEMORY_REGIONS];
    let mut reserved_count = 0usize;
    let mut mmio = [(0usize, 0usize); MAX_DTB_MMIO_REGIONS];
    let mut mmio_count = 0usize;
    for entry in fdt.memory_reservations() {
        let start = entry.address() as usize;
        if entry.size() != 0 {
            let end = start
                .checked_add(entry.size())
                .expect("DTB reservation overflows address space");
            push_range(
                &mut reserved,
                &mut reserved_count,
                start,
                end,
                "memory reservation",
            );
        }
    }
    if let Some(node) = fdt.find_node("/reserved-memory") {
        for child in node.children() {
            if !available(child) {
                continue;
            }
            let regions = child
                .reg()
                .expect("reserved-memory node has no fixed reg range");
            for region in regions {
                let start = region.starting_address as usize;
                let end = start
                    .checked_add(region.size.expect("reserved-memory region has no size"))
                    .expect("DTB reserved-memory range overflows address space");
                push_range(
                    &mut reserved,
                    &mut reserved_count,
                    start,
                    end,
                    "memory reservation",
                );
            }
        }
    }
    for node in fdt.all_nodes() {
        if !available(node) {
            continue;
        }
        if node_is_memory(node) {
            let regions = node.reg().expect("DTB memory node has no usable reg");
            for region in regions {
                let start = region.starting_address as usize;
                let end = start
                    .checked_add(region.size.expect("DTB memory region has no size"))
                    .expect("DTB memory range overflows address space");
                push_range(
                    &mut memory,
                    &mut memory_count,
                    start,
                    end,
                    "physical memory",
                );
            }
        } else if node_should_map_mmio(node) {
            let regions = node.reg().expect("DTB MMIO node has no usable reg");
            for region in regions {
                let start = region.starting_address as usize;
                let end = start
                    .checked_add(region.size.expect("DTB MMIO region has no size"))
                    .expect("DTB MMIO range overflows address space");
                push_range(&mut mmio, &mut mmio_count, start, end, "MMIO");
            }
        }
    }
    assert_ne!(
        memory_count, 0,
        "DTB contains no usable physical memory range"
    );
    sort_and_merge(&mut memory, &mut memory_count);
    sort_and_merge(&mut reserved, &mut reserved_count);
    sort_and_merge(&mut mmio, &mut mmio_count);
    (
        memory,
        memory_count,
        reserved,
        reserved_count,
        mmio,
        mmio_count,
    )
}

fn parse_cpu_topology(fdt: &Fdt<'_>, boot_hart_id: usize) -> (usize, usize, usize) {
    assert!(boot_hart_id < MAX_HARTS, "boot hart exceeds MAX_HARTS");
    let mut mask = 0usize;
    let mut discovered = 0usize;
    let mut ignored = 0usize;
    for cpu in fdt.cpus() {
        discovered = discovered.saturating_add(1);
        let cpu_available = cpu
            .property("status")
            .map(|property| matches!(property.as_str(), Some("okay" | "ok")))
            .unwrap_or(true);
        if !cpu_available {
            ignored = ignored.saturating_add(1);
            continue;
        }
        let hart_id = cpu.ids().first();
        if hart_id >= MAX_HARTS || hart_id >= usize::BITS as usize {
            ignored = ignored.saturating_add(1);
            continue;
        }
        let bit = 1usize << hart_id;
        assert_eq!(mask & bit, 0, "DTB contains duplicate hart id {hart_id}");
        mask |= bit;
    }
    assert_ne!(mask, 0, "DTB contains no available CPU");
    assert_ne!(mask & (1usize << boot_hart_id), 0, "DTB excludes boot hart");
    (mask, discovered, ignored)
}

/// 取得节点第一个非空 reg 区间，并校验其地址范围不会溢出。
fn first_reg(node: FdtNode<'_, '_>) -> Option<(usize, usize)> {
    let mut regions = node.reg()?;
    let region = regions.next()?;
    let size = region.size?;
    let base = region.starting_address as usize;
    (size != 0 && base.checked_add(size).is_some()).then_some((base, size))
}

/// 通过 /chosen/stdout-path 解析实际启用的 16550 串口。
fn parse_console(fdt: &Fdt<'_>) -> Option<ConsoleInfo> {
    let stdout_path = fdt
        .find_node("/chosen")?
        .property("stdout-path")?
        .as_str()?
        .split(':')
        .next()
        .filter(|path| !path.is_empty())?;
    let uart = fdt.find_node(stdout_path)?;
    if !compatible(uart, b"ns16550a") {
        return None;
    }
    let (base, size) = first_reg(uart)?;
    let reg_shift = uart
        .property("reg-shift")
        .and_then(|property| property.as_usize())
        .unwrap_or(0);
    let reg_io_width = uart
        .property("reg-io-width")
        .and_then(|property| property.as_usize())
        .unwrap_or(1);
    if reg_shift >= usize::BITS as usize || !matches!(reg_io_width, 1 | 2 | 4) {
        return None;
    }
    let last_register = 5usize
        .checked_shl(reg_shift as u32)?
        .checked_add(reg_io_width)?;
    (last_register <= size).then_some(ConsoleInfo {
        base,
        size,
        reg_shift: reg_shift as u8,
        reg_io_width: reg_io_width as u8,
    })
}

/// 解析 syscon-poweroff 对应的寄存器、访问宽度和关机值。
fn parse_poweroff(fdt: &Fdt<'_>) -> Option<PoweroffInfo> {
    let poweroff = fdt.find_compatible(&["syscon-poweroff"])?;
    let regmap = u32::try_from(poweroff.property("regmap")?.as_usize()?).ok()?;
    let syscon = fdt.find_phandle(regmap)?;
    if !compatible(syscon, b"syscon") {
        return None;
    }
    let (base, size) = first_reg(syscon)?;
    let offset = poweroff.property("offset")?.as_usize()?;
    let value = poweroff.property("value")?.as_usize()?;
    let reg_io_width = syscon
        .property("reg-io-width")
        .and_then(|property| property.as_usize())
        .unwrap_or(4);
    if !matches!(reg_io_width, 1 | 2 | 4 | 8)
        || offset.checked_add(reg_io_width)? > size
        || (value as u128) >= (1u128 << (reg_io_width * 8))
    {
        return None;
    }
    Some(PoweroffInfo {
        base,
        offset,
        value,
        reg_io_width: reg_io_width as u8,
    })
}

/// 将设备树中的单个大端 32 位单元转换为主机整数。
fn read_be_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

/// 将设备树中的两个大端 32 位单元转换为主机整数。
fn read_be_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

/// 解析 PCI ECAM 与非预取 32 位 BAR 可分配窗口。
fn parse_pci_host(fdt: &Fdt<'_>) -> Option<PciHostInfo> {
    let pci = fdt.find_compatible(&["pci-host-ecam-generic"])?;
    let (ecam_base, ecam_size) = first_reg(pci)?;
    let bus_range = pci.property("bus-range")?.value;
    if bus_range.len() != 8 {
        return None;
    }
    let bus_start = read_be_u32(&bus_range[..4])?;
    let bus_end = read_be_u32(&bus_range[4..])?;
    if bus_start > bus_end || bus_end > u8::MAX as u32 {
        return None;
    }
    let required_ecam_size = (bus_end as usize - bus_start as usize + 1).checked_mul(1 << 20)?;
    if ecam_size < required_ecam_size {
        return None;
    }

    // QEMU generic-ECAM 的 ranges 使用 3 个 PCI 地址单元、2 个父地址单元和
    // 2 个 size 单元。选择最大的非预取 32 位可访问窗口作为 BAR 分配区。
    let ranges = pci.property("ranges")?.value;
    if ranges.len() % 28 != 0 {
        return None;
    }
    let mut mem32_base = 0usize;
    let mut mem32_size = 0usize;
    for range in ranges.chunks_exact(28) {
        let prefetchable = range[0] & 0x80 != 0;
        let range_type = range[0] & 0x03;
        if prefetchable || !matches!(range_type, 2 | 3) {
            continue;
        }
        let bus_address = read_be_u64(&range[4..12])?;
        let cpu_address = read_be_u64(&range[12..20])?;
        let size = read_be_u64(&range[20..28])?;
        if size == 0 || bus_address.checked_add(size)? > u32::MAX as u64 + 1 {
            continue;
        }
        let (Ok(base), Ok(size)) = (usize::try_from(cpu_address), usize::try_from(size)) else {
            continue;
        };
        if size > mem32_size && base.checked_add(size).is_some() {
            mem32_base = base;
            mem32_size = size;
        }
    }
    if mem32_size == 0
        || mem32_base > u32::MAX as usize
        || mem32_size > u32::MAX as usize
        || mem32_base.checked_add(mem32_size)? > u32::MAX as usize + 1
    {
        return None;
    }
    Some(PciHostInfo {
        ecam_base,
        ecam_size,
        mem32_base,
        mem32_size,
        bus_start: bus_start as u8,
    })
}

impl DtbData {
    /// 把启动期 FDT 中的固定平台资源复制到一次性缓存。
    fn parse(dtb_pa: usize, boot_hart_id: usize) -> Self {
        let fdt = unsafe { Fdt::from_ptr(dtb_pa as *const u8) }
            .expect("LoongArch firmware supplied an invalid DTB");
        let (active_hart_mask, discovered_harts, ignored_harts) =
            parse_cpu_topology(&fdt, boot_hart_id);
        let (
            phys_mem_ranges,
            phys_mem_range_count,
            reserved_ranges,
            reserved_range_count,
            mmio_ranges,
            mmio_range_count,
        ) = parse_boot_memory(&fdt);
        Self {
            active_hart_mask,
            discovered_harts,
            ignored_harts,
            phys_mem_ranges,
            phys_mem_range_count,
            reserved_ranges,
            reserved_range_count,
            mmio_ranges,
            mmio_range_count,
            console: parse_console(&fdt),
            poweroff: parse_poweroff(&fdt),
            pci_host: parse_pci_host(&fdt),
        }
    }
}

/// 在首次输出日志前完成解析；控制台路径因此可以直接使用 DTB 地址。
pub fn init(dtb_pa: usize, boot_hart_id: usize) {
    if dtb_pa != 0 {
        DTB_DATA.call_once(|| DtbData::parse(dtb_pa, boot_hart_id));
    }
}

pub fn active_hart_mask() -> usize {
    DTB_DATA
        .get()
        .expect("LoongArch DtbData accessed before initialization")
        .active_hart_mask
}
pub fn hart_counts() -> (usize, usize) {
    let data = DTB_DATA
        .get()
        .expect("LoongArch DtbData accessed before initialization");
    (data.discovered_harts, data.ignored_harts)
}
pub fn for_each_phys_mem_range(mut f: impl FnMut(usize, usize)) {
    let data = DTB_DATA
        .get()
        .expect("LoongArch DtbData accessed before initialization");
    for &(start, end) in &data.phys_mem_ranges[..data.phys_mem_range_count] {
        f(start, end);
    }
}
pub fn for_each_reserved_range(mut f: impl FnMut(usize, usize)) {
    let data = DTB_DATA
        .get()
        .expect("LoongArch DtbData accessed before initialization");
    for &(start, end) in &data.reserved_ranges[..data.reserved_range_count] {
        f(start, end);
    }
}
pub fn for_each_mmio_range(mut f: impl FnMut(usize, usize)) {
    let data = DTB_DATA
        .get()
        .expect("LoongArch DtbData accessed before initialization");
    for &(start, end) in &data.mmio_ranges[..data.mmio_range_count] {
        f(start, end);
    }
}

pub fn console_info() -> Option<ConsoleInfo> {
    DTB_DATA.get().and_then(|data| data.console)
}

/// 返回 DTB 定义的 syscon 关机寄存器信息。
pub fn poweroff_info() -> Option<PoweroffInfo> {
    DTB_DATA.get().and_then(|data| data.poweroff)
}

/// 返回 DTB 定义的 PCI ECAM 与 BAR aperture 信息。
pub fn pci_host_info() -> Option<PciHostInfo> {
    DTB_DATA.get().and_then(|data| data.pci_host)
}
