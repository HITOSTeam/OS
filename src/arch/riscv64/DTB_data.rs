//! 从启动 DTB 中一次性解析出的 RISC-V 平台数据。
//!
//! 本模块会复制后续初始化所需的全部数据，调用方不会保留 `Fdt` 引用，
//! 也不应再次解析启动 DTB。核心目的是提供对DTB设备树的单次解析

use fdt::{Fdt, node::FdtNode};
use spin::Once;

use crate::config::{
    MAX_DTB_MMIO_REGIONS, MAX_HARTS, MAX_PHYS_MEMORY_REGIONS, MAX_RESERVED_MEMORY_REGIONS,
    MAX_VIRTIO_MMIO_DEVICES,
};

const VIRTIO_MMIO_COMPATIBLE: &[u8] = b"virtio,mmio";

#[derive(Clone, Copy)]
struct VirtioMmioDevice {
    /// virtio-mmio 设备控制寄存器区的物理基地址（来自 DTB 的 reg 属性）
    base: usize,
    /// virtio-mmio 设备控制寄存器区的长度（字节）
    size: usize,
}

/// 在内存管理初始化前构造完成、随后保持不变的 RISC-V 平台描述。
pub struct DtbData {
    /// 活动 hart 位图：第 n 位为 1 表示编号为 n 的 hart 存在且可用
    active_hart_mask: usize,

    /// 时基频率：RISC-V time 计数器（mtime/cycle）每秒的 tick 数，
    /// 来自 DTB /cpus 节点的 timebase-frequency 属性，用于时钟与时延换算
    timebase_frequency: usize,

    /// 是否所有活动 hart 都支持 sstc 扩展（S 态直接写 stimecmp 的时钟比较器，
    /// 支持时无需在 S 态读 mtime，且能避免陷入 M 态处理定时器）
    all_harts_have_sstc: bool,

    /// 物理内存区域数组，每项为闭区间 (起始地址, 结束地址)，
    /// 已按起始地址排序并合并相邻/重叠区域
    phys_mem_ranges: [(usize, usize); MAX_PHYS_MEMORY_REGIONS],
    /// 有效物理内存区域的数量（<= phys_mem_ranges 的容量）
    phys_mem_range_count: usize,
    /// 保留内存区域数组（启动协议保留区及 /reserved-memory 节点），
    /// 每项为 (起始地址, 结束地址)，同样已排序合并
    reserved_ranges: [(usize, usize); MAX_RESERVED_MEMORY_REGIONS],
    /// 有效保留内存区域的数量
    reserved_range_count: usize,

    /// 需要建立页表映射的 MMIO 区域数组（串口 ns16550a、fw-cfg、
    /// syscon、virtio-mmio 等），每项为 (起始地址, 结束地址)
    mmio_ranges: [(usize, usize); MAX_DTB_MMIO_REGIONS],
    /// 有效 MMIO 区域的数量
    mmio_range_count: usize,
    /// 检测到的 virtio-mmio 设备数组，按基地址排序
    virtio_mmio_devices: [VirtioMmioDevice; MAX_VIRTIO_MMIO_DEVICES],
    /// 有效 virtio-mmio 设备的数量
    virtio_mmio_device_count: usize,
}

/// DTB的数据全部保存在这个结构体里面
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
    match node.property("status").and_then(|property| property.as_str()) {
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
    compatible_contains(node, VIRTIO_MMIO_COMPATIBLE)
        || compatible_contains(node, b"ns16550a")
        || compatible_contains(node, b"qemu,fw-cfg-mmio")
        || compatible_contains(node, b"syscon")
}

fn cpu_supports_extension(node: FdtNode<'_, '_>, extension: &[u8]) -> bool {
    if node.property("riscv,isa-extensions").is_some_and(|property| {
        property
            .value
            .split(|byte| *byte == 0)
            .any(|entry| entry == extension)
    }) {
        return true;
    }

    node.property("riscv,isa").is_some_and(|property| {
        property
            .value
            .split(|byte| *byte == b'_' || *byte == 0)
            .any(|entry| entry == extension)
    })
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

fn parse_cpu_topology(fdt: &Fdt<'_>, boot_hart_id: usize) -> (usize, usize, bool) {
    assert!(
        boot_hart_id < MAX_HARTS,
        "boot hart {boot_hart_id} exceeds MAX_HARTS={MAX_HARTS}"
    );
    let cpus = fdt.find_node("/cpus").expect("DTB has no /cpus node");
    let timebase_frequency = cpus
        .property("timebase-frequency")
        .and_then(|property| property.as_usize())
        .filter(|frequency| *frequency != 0)
        .expect("DTB /cpus has no valid timebase-frequency");

    let mut active_hart_mask = 0usize;
    let mut active_hart_count = 0usize;
    let mut all_harts_have_sstc = true;
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
        all_harts_have_sstc &= cpu_supports_extension(cpu, b"sstc");
    }

    assert!(active_hart_count != 0, "DTB contains no available CPU");
    assert!(
        active_hart_mask & (1usize << boot_hart_id) != 0,
        "DTB CPU topology excludes boot hart {boot_hart_id}"
    );
    (active_hart_mask, timebase_frequency, all_harts_have_sstc)
}

fn parse_mmio_ranges(
    fdt: &Fdt<'_>,
) -> (
    [(usize, usize); MAX_DTB_MMIO_REGIONS],
    usize,
    [VirtioMmioDevice; MAX_VIRTIO_MMIO_DEVICES],
    usize,
) {
    let mut mmio_ranges = [(0usize, 0usize); MAX_DTB_MMIO_REGIONS];
    let mut mmio_count = 0usize;
    let mut virtio_devices = [VirtioMmioDevice { base: 0, size: 0 }; MAX_VIRTIO_MMIO_DEVICES];
    let mut virtio_count = 0usize;

    for node in fdt.all_nodes() {
        if !node_is_available(node) || node_is_memory(node) {
            continue;
        }
        let is_virtio_mmio = compatible_contains(node, VIRTIO_MMIO_COMPATIBLE);
        let should_map = node_should_map_mmio(node);
        if !is_virtio_mmio && !should_map {
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
            if should_map {
                push_range(&mut mmio_ranges, &mut mmio_count, start, end, "MMIO");
            }
            if is_virtio_mmio {
                assert!(
                    virtio_count < MAX_VIRTIO_MMIO_DEVICES,
                    "too many virtio-mmio devices (capacity {MAX_VIRTIO_MMIO_DEVICES})"
                );
                virtio_devices[virtio_count] = VirtioMmioDevice { base: start, size };
                virtio_count += 1;
            }
        }
    }

    sort_and_merge(&mut mmio_ranges, &mut mmio_count);
    virtio_devices[..virtio_count].sort_unstable_by_key(|device| device.base);
    (mmio_ranges, mmio_count, virtio_devices, virtio_count)
}

impl DtbData {
    fn parse(dtb_pa: usize, boot_hart_id: usize) -> Self {
        // 发现给的dtb地址是空指针
        assert_ne!(dtb_pa, 0, "RISC-V boot protocol supplied a null DTB pointer");
        // safety：输入的DTB指针是正确的，如果不是的话直接panic
        let fdt = unsafe { Fdt::from_ptr(dtb_pa as *const u8) }
            .unwrap_or_else(|error| panic!("invalid RISC-V DTB at {dtb_pa:#x}: {error:?}"));
        //查找cpu相关的部分
        let (active_hart_mask, timebase_frequency, all_harts_have_sstc) =
            parse_cpu_topology(&fdt, boot_hart_id);
        let (phys_mem_ranges, phys_mem_range_count) = parse_memory_ranges(&fdt);
        let (reserved_ranges, reserved_range_count) = parse_reserved_ranges(&fdt);
        let (mmio_ranges, mmio_range_count, virtio_mmio_devices, virtio_mmio_device_count) =
            parse_mmio_ranges(&fdt);

        Self {
            active_hart_mask,
            timebase_frequency,
            all_harts_have_sstc,
            phys_mem_ranges,
            phys_mem_range_count,
            reserved_ranges,
            reserved_range_count,
            mmio_ranges,
            mmio_range_count,
            virtio_mmio_devices,
            virtio_mmio_device_count,
        }
    }
}

/// 在堆和内存管理初始化前，恰好一次地解析并发布启动 DTB。
pub fn init(dtb_pa: usize, boot_hart_id: usize) {
    DTB_DATA.call_once(|| DtbData::parse(dtb_pa, boot_hart_id));
}

pub fn data() -> &'static DtbData {
    DTB_DATA
        .get()
        .expect("RISC-V DtbData accessed before boot DTB initialization")
}

pub fn active_hart_mask() -> usize {
    data().active_hart_mask
}

pub fn timebase_frequency() -> usize {
    data().timebase_frequency
}

/// 为架构无关的时钟配置访问器提供 RISC-V 的时基频率。
pub fn clock_frequency() -> usize {
    timebase_frequency()
}

pub fn all_harts_have_sstc() -> bool {
    data().all_harts_have_sstc
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

pub fn for_each_virtio_mmio_device(mut f: impl FnMut(usize, usize)) {
    let data = data();
    for device in &data.virtio_mmio_devices[..data.virtio_mmio_device_count] {
        f(device.base, device.size);
    }
}
