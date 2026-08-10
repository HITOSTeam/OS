//! LoongArch 启动 DTB 的平台设备缓存。
//!
//! 固件只在启动期提供 DTB 指针。本模块在启动屏障之前复制串口、关机和 PCI
//! 主桥信息，使普通驱动不再依赖固定 QEMU 地址或再次遍历设备树。

use fdt::{node::FdtNode, Fdt};
use spin::Once;

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
    fn parse(dtb_pa: usize) -> Self {
        let fdt = unsafe { Fdt::from_ptr(dtb_pa as *const u8) }
            .expect("LoongArch firmware supplied an invalid DTB");
        Self {
            console: parse_console(&fdt),
            poweroff: parse_poweroff(&fdt),
            pci_host: parse_pci_host(&fdt),
        }
    }
}

/// 在首次输出日志前完成解析；控制台路径因此可以直接使用 DTB 地址。
pub fn init(dtb_pa: usize) {
    if dtb_pa != 0 {
        DTB_DATA.call_once(|| DtbData::parse(dtb_pa));
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
