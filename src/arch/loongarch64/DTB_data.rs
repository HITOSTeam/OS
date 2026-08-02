//! 从启动 DTB 中一次性解析出的 LoongArch 平台数据。
//!
//! EFI 表只提供 DTB 指针。早期启动之后需要的全部数据都会复制到这里，
//! 从而使驱动不再重新构造或解析设备树。

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
    // `size` 已在解析 DTB 时校验；当前运行时关机只需要已校验的寄存器地址和宽度。
    // pub size: usize,
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
    // 解析器已校验完整总线范围；当前 PCI 探测只从 `bus_start` 开始，尚未支持
    // 多总线枚举。
    // pub bus_end: u8,
    // 在 DMA 映射层具备架构专用缓存维护路径前，暂不使用 DMA 一致性策略。
    // pub dma_coherent: bool,
}

/// 在内存管理初始化前构造完成、随后保持不变的 LoongArch 平台描述。
pub struct DtbData {
    active_hart_mask: usize,
    clock_frequency: usize,
    phys_mem_ranges: [(usize, usize); MAX_PHYS_MEMORY_REGIONS],
    phys_mem_range_count: usize,
    reserved_ranges: [(usize, usize); MAX_RESERVED_MEMORY_REGIONS],
    reserved_range_count: usize,
    mmio_ranges: [(usize, usize); MAX_DTB_MMIO_REGIONS],
    mmio_range_count: usize,
    console: ConsoleInfo,
    poweroff: PoweroffInfo,
    pci_host: PciHostInfo,
}

static DTB_DATA: Once<DtbData> = Once::new();

fn compatible_contains(node: FdtNode<'_, '_>, needle: &[u8]) -> bool {
    node.property("compatible").is_some_and(|property| {
        property
            .value
            .split(|byte| *byte == 0)
            .any(|entry| entry == needle)
    })
}

fn node_is_available(node: FdtNode<'_, '_>) -> bool {
    match node
        .property("status")
        .and_then(|property| property.as_str())
    {
        None | Some("okay") | Some("ok") => true,
        Some(_) => false,
    }
}

fn node_is_memory(node: FdtNode<'_, '_>) -> bool {
    node.name.split('@').next() == Some("memory")
        || node
            .property("device_type")
            .and_then(|property| property.as_str())
            == Some("memory")
}

fn node_should_map_mmio(node: FdtNode<'_, '_>) -> bool {
    compatible_contains(node, b"ns16550a")
        || compatible_contains(node, b"qemu,fw-cfg-mmio")
        || compatible_contains(node, b"syscon")
        || compatible_contains(node, b"pci-host-ecam-generic")
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

fn first_reg(node: FdtNode<'_, '_>, kind: &str) -> (usize, usize) {
    let mut regions = node
        .reg()
        .unwrap_or_else(|| panic!("{kind} node {} has no usable reg", node.name));
    let region = regions
        .next()
        .unwrap_or_else(|| panic!("{kind} node {} has an empty reg", node.name));
    let start = region.starting_address as usize;
    let size = region
        .size
        .unwrap_or_else(|| panic!("{kind} node {} has no size", node.name));
    assert_ne!(size, 0, "{kind} node {} has a zero-sized reg", node.name);
    let _ = start
        .checked_add(size)
        .expect("DTB register range overflows address space");
    (start, size)
}

fn read_be_u32(bytes: &[u8], context: &str) -> u32 {
    let bytes: [u8; 4] = bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{context} is not a 32-bit DTB cell"));
    u32::from_be_bytes(bytes)
}

fn read_be_u64(bytes: &[u8], context: &str) -> u64 {
    let bytes: [u8; 8] = bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{context} is not a 64-bit DTB cell"));
    u64::from_be_bytes(bytes)
}

fn parse_memory_ranges(fdt: &Fdt<'_>) -> ([(usize, usize); MAX_PHYS_MEMORY_REGIONS], usize) {
    let mut ranges = [(0usize, 0usize); MAX_PHYS_MEMORY_REGIONS];
    let mut count = 0usize;

    for node in fdt.find_all_nodes("/memory") {
        let regions = node
            .reg()
            .unwrap_or_else(|| panic!("DTB memory node {} has no usable reg", node.name));
        for region in regions {
            let start = region.starting_address as usize;
            let size = region
                .size
                .unwrap_or_else(|| panic!("DTB memory node {} has no size", node.name));
            let end = start
                .checked_add(size)
                .expect("DTB memory range overflows address space");
            push_range(&mut ranges, &mut count, start, end, "physical memory");
        }
    }

    assert!(count != 0, "DTB contains no usable physical memory range");
    sort_and_merge(&mut ranges, &mut count);
    (ranges, count)
}

fn parse_reserved_ranges(fdt: &Fdt<'_>) -> ([(usize, usize); MAX_RESERVED_MEMORY_REGIONS], usize) {
    let mut ranges = [(0usize, 0usize); MAX_RESERVED_MEMORY_REGIONS];
    let mut count = 0usize;

    for reservation in fdt.memory_reservations() {
        let start = reservation.address() as usize;
        let size = reservation.size();
        if size == 0 {
            continue;
        }
        let end = start
            .checked_add(size)
            .expect("DTB memory reservation overflows address space");
        push_range(&mut ranges, &mut count, start, end, "memory reservation");
    }

    if let Some(reserved_memory) = fdt.find_node("/reserved-memory") {
        for node in reserved_memory.children() {
            if !node_is_available(node) {
                continue;
            }
            let regions = node.reg().unwrap_or_else(|| {
                panic!(
                    "reserved-memory node {} has no fixed reg range; dynamic reservations are unsupported",
                    node.name
                )
            });
            for region in regions {
                let start = region.starting_address as usize;
                let size = region
                    .size
                    .unwrap_or_else(|| panic!("reserved-memory node {} has no size", node.name));
                let end = start
                    .checked_add(size)
                    .expect("DTB reserved-memory range overflows address space");
                push_range(&mut ranges, &mut count, start, end, "memory reservation");
            }
        }
    }

    sort_and_merge(&mut ranges, &mut count);
    (ranges, count)
}

fn parse_cpu_topology(fdt: &Fdt<'_>, boot_hart_id: usize) -> usize {
    assert!(
        boot_hart_id < MAX_HARTS,
        "boot hart {boot_hart_id} exceeds MAX_HARTS={MAX_HARTS}"
    );
    let cpus = fdt.find_node("/cpus").expect("DTB has no /cpus node");
    let mut active_hart_mask = 0usize;
    let mut active_hart_count = 0usize;

    for cpu in cpus.children() {
        if cpu.name.split('@').next() != Some("cpu") || !node_is_available(cpu) {
            continue;
        }
        let mut regions = cpu
            .reg()
            .unwrap_or_else(|| panic!("CPU node {} has no usable reg", cpu.name));
        let region = regions
            .next()
            .unwrap_or_else(|| panic!("CPU node {} has an empty reg", cpu.name));
        let hart_id = region.starting_address as usize;
        assert!(
            hart_id < MAX_HARTS,
            "DTB hart {hart_id} exceeds static MAX_HARTS={MAX_HARTS}"
        );
        let hart_bit = 1usize << hart_id;
        assert!(
            active_hart_mask & hart_bit == 0,
            "DTB contains duplicate hart id {hart_id}"
        );
        active_hart_mask |= hart_bit;
        active_hart_count += 1;
    }

    assert!(active_hart_count != 0, "DTB contains no available CPU");
    assert!(
        active_hart_mask & (1usize << boot_hart_id) != 0,
        "DTB CPU topology excludes boot hart {boot_hart_id}"
    );
    active_hart_mask
}

fn parse_mmio_ranges(fdt: &Fdt<'_>) -> ([(usize, usize); MAX_DTB_MMIO_REGIONS], usize) {
    let mut mmio_ranges = [(0usize, 0usize); MAX_DTB_MMIO_REGIONS];
    let mut mmio_count = 0usize;

    for node in fdt.all_nodes() {
        if !node_is_available(node) || node_is_memory(node) || !node_should_map_mmio(node) {
            continue;
        }
        let regions = node
            .reg()
            .unwrap_or_else(|| panic!("MMIO node {} has no usable reg", node.name));
        for region in regions {
            let start = region.starting_address as usize;
            let size = region
                .size
                .unwrap_or_else(|| panic!("MMIO node {} has no size", node.name));
            let end = start
                .checked_add(size)
                .expect("DTB MMIO range overflows address space");
            push_range(&mut mmio_ranges, &mut mmio_count, start, end, "MMIO");
        }
    }

    sort_and_merge(&mut mmio_ranges, &mut mmio_count);
    (mmio_ranges, mmio_count)
}

fn parse_console(fdt: &Fdt<'_>) -> ConsoleInfo {
    let chosen = fdt.find_node("/chosen").expect("DTB has no /chosen node");
    let stdout_path = chosen
        .property("stdout-path")
        .and_then(|property| property.as_str())
        .expect("DTB /chosen has no valid stdout-path");
    let stdout_path = stdout_path
        .split(':')
        .next()
        .filter(|path| !path.is_empty())
        .expect("DTB stdout-path is empty");
    let uart = fdt
        .find_node(stdout_path)
        .unwrap_or_else(|| panic!("DTB stdout-path {stdout_path:?} does not resolve to a node"));
    assert!(
        compatible_contains(uart, b"ns16550a"),
        "DTB stdout node {} is not ns16550a-compatible",
        uart.name
    );
    let (base, size) = first_reg(uart, "stdout UART");
    // 8250 的 DT 绑定规定，省略 reg-shift 和 reg-io-width 时分别取 0 和 1。
    let reg_shift = uart
        .property("reg-shift")
        .and_then(|property| property.as_usize())
        .unwrap_or(0);
    let reg_io_width = uart
        .property("reg-io-width")
        .and_then(|property| property.as_usize())
        .unwrap_or(1);
    assert!(
        reg_shift < usize::BITS as usize,
        "DTB UART reg-shift {reg_shift} is invalid"
    );
    assert!(
        matches!(reg_io_width, 1 | 2 | 4),
        "DTB UART reg-io-width {reg_io_width} is unsupported"
    );
    let last_register_end = 5usize
        .checked_shl(reg_shift as u32)
        .and_then(|offset| offset.checked_add(reg_io_width))
        .expect("DTB UART register layout overflows address space");
    assert!(
        last_register_end <= size,
        "DTB UART reg range does not cover required 16550 registers"
    );

    ConsoleInfo {
        base,
        size,
        reg_shift: reg_shift as u8,
        reg_io_width: reg_io_width as u8,
    }
}

fn parse_poweroff(fdt: &Fdt<'_>) -> PoweroffInfo {
    let poweroff = fdt
        .find_compatible(&["syscon-poweroff"])
        .expect("DTB has no syscon-poweroff node");
    let regmap = poweroff
        .property("regmap")
        .and_then(|property| property.as_usize())
        .and_then(|value| u32::try_from(value).ok())
        .expect("DTB syscon-poweroff has no valid regmap phandle");
    let syscon = fdt
        .find_phandle(regmap)
        .unwrap_or_else(|| panic!("DTB syscon-poweroff regmap phandle {regmap:#x} is unresolved"));
    assert!(
        compatible_contains(syscon, b"syscon"),
        "DTB poweroff regmap {} is not syscon-compatible",
        syscon.name
    );
    let (base, size) = first_reg(syscon, "poweroff syscon");
    let offset = poweroff
        .property("offset")
        .and_then(|property| property.as_usize())
        .expect("DTB syscon-poweroff has no valid offset");
    let value = poweroff
        .property("value")
        .and_then(|property| property.as_usize())
        .expect("DTB syscon-poweroff has no valid value");
    let reg_io_width = syscon
        .property("reg-io-width")
        .and_then(|property| property.as_usize())
        .unwrap_or(4);
    assert!(
        matches!(reg_io_width, 1 | 2 | 4 | 8),
        "DTB syscon reg-io-width {reg_io_width} is unsupported"
    );
    assert!(
        (value as u128) < (1u128 << (reg_io_width * 8)),
        "DTB syscon-poweroff value does not fit its register width"
    );
    let register_end = offset
        .checked_add(reg_io_width)
        .expect("DTB syscon offset overflows address space");
    assert!(
        register_end <= size,
        "DTB syscon-poweroff register lies outside its reg range"
    );

    PoweroffInfo {
        base,
        // 上方已用 `offset + reg_io_width` 校验 `size`；在有运行时边界检查
        // 调用者前不保存该字段。
        // size,
        offset,
        value,
        reg_io_width: reg_io_width as u8,
    }
}

fn parse_pci_host(fdt: &Fdt<'_>) -> PciHostInfo {
    let pci = fdt
        .find_compatible(&["pci-host-ecam-generic"])
        .expect("DTB has no pci-host-ecam-generic node");
    let (ecam_base, ecam_size) = first_reg(pci, "PCI ECAM");
    let bus_range = pci
        .property("bus-range")
        .expect("DTB PCI host has no bus-range");
    assert_eq!(
        bus_range.value.len(),
        8,
        "DTB PCI bus-range must contain two 32-bit cells"
    );
    let bus_start = read_be_u32(&bus_range.value[..4], "PCI bus-range start");
    let bus_end = read_be_u32(&bus_range.value[4..], "PCI bus-range end");
    assert!(
        bus_start <= bus_end && bus_end <= u8::MAX as u32,
        "DTB PCI bus-range {bus_start:#x}-{bus_end:#x} is unsupported"
    );
    let required_ecam_size = (bus_end as usize - bus_start as usize + 1)
        .checked_mul(1 << 20)
        .expect("DTB PCI bus-range overflows ECAM size");
    assert!(
        ecam_size >= required_ecam_size,
        "DTB PCI ECAM range is smaller than its bus-range"
    );

    let ranges = pci
        .property("ranges")
        .expect("DTB PCI host has no ranges property");
    // QEMU 的通用 ECAM 绑定使用 3 个 PCI 地址单元、2 个父地址单元和
    // 2 个大小单元，因此每个 range 由 7 个 32 位单元组成。
    assert_eq!(
        ranges.value.len() % 28,
        0,
        "DTB PCI ranges do not match 3/2/2 cell encoding"
    );
    let mut mem32_base = 0usize;
    let mut mem32_size = 0usize;
    for range in ranges.value.chunks_exact(28) {
        let prefetchable = range[0] & 0x80 != 0;
        let range_type = range[0] & 0x03;
        if prefetchable || !matches!(range_type, 2 | 3) {
            continue;
        }
        let bus_address = read_be_u64(&range[4..12], "PCI bus address");
        let cpu_address = read_be_u64(&range[12..20], "PCI CPU address");
        let size = read_be_u64(&range[20..28], "PCI range size");
        let bus_end = bus_address
            .checked_add(size)
            .expect("DTB PCI bus range overflows");
        if bus_end > u32::MAX as u64 + 1 || size == 0 || size <= mem32_size as u64 {
            continue;
        }
        let Ok(base) = usize::try_from(cpu_address) else {
            continue;
        };
        let Ok(size) = usize::try_from(size) else {
            continue;
        };
        if base.checked_add(size).is_none() {
            continue;
        }
        mem32_base = base;
        mem32_size = size;
    }
    assert!(
        mem32_size != 0,
        "DTB PCI host has no usable non-prefetchable 32-bit memory aperture"
    );
    assert!(
        mem32_base <= u32::MAX as usize
            && mem32_size <= u32::MAX as usize
            && mem32_base
                .checked_add(mem32_size)
                .is_some_and(|end| end <= u32::MAX as usize + 1),
        "DTB PCI memory aperture cannot be represented by the 32-bit BAR allocator"
    );

    PciHostInfo {
        ecam_base,
        ecam_size,
        mem32_base,
        mem32_size,
        bus_start: bus_start as u8,
        // 见 `PciHostInfo`：尚未实现多总线枚举。
        // bus_end: bus_end as u8,
        // 见 `PciHostInfo`：尚无 DMA 缓存维护调用者。
        // dma_coherent: pci.property("dma-coherent").is_some(),
    }
}

impl DtbData {
    fn parse(dtb_pa: usize, boot_hart_id: usize) -> Self {
        assert_ne!(
            dtb_pa, 0,
            "LoongArch boot protocol supplied a null DTB pointer"
        );
        let fdt = unsafe { Fdt::from_ptr(dtb_pa as *const u8) }
            .unwrap_or_else(|error| panic!("invalid LoongArch DTB at {dtb_pa:#x}: {error:?}"));
        let active_hart_mask = parse_cpu_topology(&fdt, boot_hart_id);
        let clock_frequency = super::detect_clock_frequency();
        let (phys_mem_ranges, phys_mem_range_count) = parse_memory_ranges(&fdt);
        let (reserved_ranges, reserved_range_count) = parse_reserved_ranges(&fdt);
        let (mmio_ranges, mmio_range_count) = parse_mmio_ranges(&fdt);
        let console = parse_console(&fdt);
        let poweroff = parse_poweroff(&fdt);
        let pci_host = parse_pci_host(&fdt);

        Self {
            active_hart_mask,
            clock_frequency,
            phys_mem_ranges,
            phys_mem_range_count,
            reserved_ranges,
            reserved_range_count,
            mmio_ranges,
            mmio_range_count,
            console,
            poweroff,
            pci_host,
        }
    }
}

/// 在分页和内存管理初始化前，恰好一次地解析并发布启动 DTB。
pub fn init(dtb_pa: usize, boot_hart_id: usize) {
    DTB_DATA.call_once(|| DtbData::parse(dtb_pa, boot_hart_id));
}

pub fn data() -> &'static DtbData {
    DTB_DATA
        .get()
        .expect("LoongArch DtbData accessed before boot DTB initialization")
}

pub fn try_data() -> Option<&'static DtbData> {
    DTB_DATA.get()
}

pub fn active_hart_mask() -> usize {
    data().active_hart_mask
}

pub fn clock_frequency() -> usize {
    data().clock_frequency
}

/*
 * 早期控制台路径必须容忍 DTB 初始化失败，因而使用 `try_console_info`。待普通
 * 驱动需要已保证初始化的控制台时，再启用这个严格访问器。
 *
pub fn console_info() -> ConsoleInfo {
    data().console
}
*/

pub fn try_console_info() -> Option<ConsoleInfo> {
    try_data().map(|data| data.console)
}

/*
 * 关机路径刻意使用 `try_poweroff_info`，避免 DTB 失败后再次触发 panic。待普通
 * 电源管理驱动需要时，再启用这个严格访问器。
 *
pub fn poweroff_info() -> PoweroffInfo {
    data().poweroff
}
*/

/// 返回关机信息；仅供 DTB 初始化失败后的 panic 路径避免再次触发 panic。
pub fn try_poweroff_info() -> Option<PoweroffInfo> {
    try_data().map(|data| data.poweroff)
}

pub fn pci_host_info() -> PciHostInfo {
    data().pci_host
}

pub fn for_each_phys_mem_range(mut f: impl FnMut(usize, usize)) {
    let data = data();
    for &(start, end) in &data.phys_mem_ranges[..data.phys_mem_range_count] {
        f(start, end);
    }
}

pub fn for_each_reserved_range(mut f: impl FnMut(usize, usize)) {
    let data = data();
    for &(start, end) in &data.reserved_ranges[..data.reserved_range_count] {
        f(start, end);
    }
}

pub fn for_each_mmio_range(mut f: impl FnMut(usize, usize)) {
    let data = data();
    for &(start, end) in &data.mmio_ranges[..data.mmio_range_count] {
        f(start, end);
    }
}

// 为架构无关的配置访问器保留；LoongArch 使用 PCI virtio 而非 virtio-mmio。
/*
 * LoongArch 当前通过 PCI 发现 virtio，因此这个空迭代器没有调用者。保留预期
 * 接口说明，供未来的 virtio-mmio 平台使用。
 *
pub fn for_each_virtio_mmio_device(_f: impl FnMut(usize, usize)) {}
*/
