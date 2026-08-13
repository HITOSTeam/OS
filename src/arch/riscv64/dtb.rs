//! RISC-V 启动 DTB 的一次性解析与缓存。
//!
//! 固件提供的 DTB 只在启动阶段读取一次。后续的时钟、CPU 拓扑、内存、保留
//! 区间、MMIO 与 virtio 发现均只访问此处的固定容量缓存，不再持有 `Fdt` 引用。

use fdt::{Fdt, node::FdtNode};
use spin::Once;

use crate::config::{
    MAX_DTB_MMIO_REGIONS, MAX_HARTS, MAX_PHYS_MEMORY_REGIONS, MAX_RESERVED_MEMORY_REGIONS,
    MAX_VIRTIO_MMIO_DEVICES,
};

const VIRTIO_MMIO_COMPATIBLE: &[u8] = b"virtio,mmio";

#[derive(Clone, Copy)]
struct VirtioMmioDevice {
    base: usize,
    size: usize,
}

/// 在页表和堆初始化前构造、之后保持只读的平台描述。
pub struct DtbData {
    active_hart_mask: usize,
    discovered_harts: usize,
    ignored_harts: usize,
    timebase_frequency: usize,
    all_harts_have_sstc: bool,
    all_harts_have_svvptc: bool,
    phys_mem_ranges: [(usize, usize); MAX_PHYS_MEMORY_REGIONS],
    phys_mem_range_count: usize,
    reserved_ranges: [(usize, usize); MAX_RESERVED_MEMORY_REGIONS],
    reserved_range_count: usize,
    mmio_ranges: [(usize, usize); MAX_DTB_MMIO_REGIONS],
    mmio_range_count: usize,
    virtio_devices: [VirtioMmioDevice; MAX_VIRTIO_MMIO_DEVICES],
    virtio_count: usize,
}

static DTB_DATA: Once<DtbData> = Once::new();

fn available(node: FdtNode<'_, '_>) -> bool {
    node.property("status")
        .map(|property| matches!(property.as_str(), Some("okay" | "ok")))
        .unwrap_or(true)
}

fn compatible(node: FdtNode<'_, '_>, expected: &[u8]) -> bool {
    node.property("compatible").is_some_and(|property| {
        property
            .value
            .split(|byte| *byte == 0)
            .any(|entry| entry == expected)
    })
}

fn node_is_memory(node: FdtNode<'_, '_>) -> bool {
    node.name.split('@').next() == Some("memory")
        || node
            .property("device_type")
            .and_then(|property| property.as_str())
            == Some("memory")
}

fn node_should_map_mmio(node: FdtNode<'_, '_>) -> bool {
    compatible(node, VIRTIO_MMIO_COMPATIBLE)
        || compatible(node, b"ns16550a")
        || compatible(node, b"qemu,fw-cfg-mmio")
        || compatible(node, b"snps,dw-mshc")
        || compatible(node, b"snps,dw-apb-uart")
        || compatible(node, b"syscon")
        || compatible(node, b"riscv,plic0")
        || compatible(node, b"sifive,plic-1.0.0")
}

/// 兼容旧式 riscv,isa 属性，并忽略扩展名末尾的版本号。
fn isa_string_contains(value: &[u8], expected: &[u8]) -> bool {
    let value = value.strip_suffix(&[0]).unwrap_or(value);
    value.split(|byte| *byte == b'_').skip(1).any(|extension| {
        let mut name_end = extension.len();
        while name_end > 0 && extension[name_end - 1].is_ascii_digit() {
            name_end -= 1;
        }
        if name_end >= 2
            && extension[name_end - 1].eq_ignore_ascii_case(&b'p')
            && extension[name_end - 2].is_ascii_digit()
        {
            name_end -= 1;
            while name_end > 0 && extension[name_end - 1].is_ascii_digit() {
                name_end -= 1;
            }
        }
        extension[..name_end].eq_ignore_ascii_case(expected)
    })
}

fn cpu_has_extension(
    cpu: impl Fn(&str) -> Option<fdt::node::NodeProperty<'_>>,
    extension: &[u8],
) -> bool {
    cpu("riscv,isa-extensions").is_some_and(|property| {
        property
            .value
            .split(|byte| *byte == 0)
            .any(|entry| entry == extension)
    }) || cpu("riscv,isa").is_some_and(|property| isa_string_contains(property.value, extension))
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

impl DtbData {
    fn parse(dtb_pa: usize, boot_hart_id: usize) -> Self {
        assert_ne!(
            dtb_pa, 0,
            "RISC-V boot protocol supplied a null DTB pointer"
        );
        let fdt = unsafe { Fdt::from_ptr(dtb_pa as *const u8) }
            .unwrap_or_else(|error| panic!("invalid RISC-V DTB at {dtb_pa:#x}: {error:?}"));
        let cpus = fdt.find_node("/cpus").expect("DTB has no /cpus node");
        let timebase_frequency = cpus
            .property("timebase-frequency")
            .and_then(|property| property.as_usize())
            .filter(|frequency| *frequency != 0)
            .expect("DTB /cpus has no valid timebase-frequency");

        assert!(boot_hart_id < MAX_HARTS, "boot hart exceeds MAX_HARTS");
        let mut active_hart_mask = 0usize;
        let mut discovered_harts = 0usize;
        let mut ignored_harts = 0usize;
        let mut all_harts_have_sstc = true;
        let mut all_harts_have_svvptc = true;
        for cpu in fdt.cpus() {
            discovered_harts = discovered_harts.saturating_add(1);
            let cpu_available = cpu
                .property("status")
                .map(|property| matches!(property.as_str(), Some("okay" | "ok")))
                .unwrap_or(true);
            if !cpu_available {
                ignored_harts = ignored_harts.saturating_add(1);
                continue;
            }
            let hart_id = cpu.ids().first();
            if hart_id >= MAX_HARTS || hart_id >= usize::BITS as usize {
                ignored_harts = ignored_harts.saturating_add(1);
                continue;
            }
            let bit = 1usize << hart_id;
            assert_eq!(
                active_hart_mask & bit,
                0,
                "DTB contains duplicate hart id {hart_id}"
            );
            active_hart_mask |= bit;
            all_harts_have_sstc &= cpu_has_extension(|name| cpu.property(name), b"sstc");
            all_harts_have_svvptc &= cpu_has_extension(|name| cpu.property(name), b"svvptc");
        }
        assert_ne!(active_hart_mask, 0, "DTB contains no available CPU");
        assert_ne!(
            active_hart_mask & (1usize << boot_hart_id),
            0,
            "DTB excludes boot hart"
        );

        let mut phys_mem_ranges = [(0usize, 0usize); MAX_PHYS_MEMORY_REGIONS];
        let mut phys_mem_range_count = 0usize;
        let mut reserved_ranges = [(0usize, 0usize); MAX_RESERVED_MEMORY_REGIONS];
        let mut reserved_range_count = 0usize;
        let mut mmio_ranges = [(0usize, 0usize); MAX_DTB_MMIO_REGIONS];
        let mut mmio_range_count = 0usize;
        let mut virtio_devices = [VirtioMmioDevice { base: 0, size: 0 }; MAX_VIRTIO_MMIO_DEVICES];
        let mut virtio_count = 0usize;

        for reservation in fdt.memory_reservations() {
            let start = reservation.address() as usize;
            let size = reservation.size();
            if size != 0 {
                let end = start
                    .checked_add(size)
                    .expect("DTB reservation overflows address space");
                push_range(
                    &mut reserved_ranges,
                    &mut reserved_range_count,
                    start,
                    end,
                    "memory reservation",
                );
            }
        }
        if let Some(reserved_memory) = fdt.find_node("/reserved-memory") {
            for node in reserved_memory.children() {
                if !available(node) {
                    continue;
                }
                let regions = node
                    .reg()
                    .expect("reserved-memory node has no fixed reg range");
                for region in regions {
                    let size = region.size.expect("reserved-memory region has no size");
                    let start = region.starting_address as usize;
                    let end = start
                        .checked_add(size)
                        .expect("DTB reserved-memory range overflows address space");
                    push_range(
                        &mut reserved_ranges,
                        &mut reserved_range_count,
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
                    let size = region.size.expect("DTB memory region has no size");
                    let start = region.starting_address as usize;
                    let end = start
                        .checked_add(size)
                        .expect("DTB memory range overflows address space");
                    push_range(
                        &mut phys_mem_ranges,
                        &mut phys_mem_range_count,
                        start,
                        end,
                        "physical memory",
                    );
                }
                continue;
            }
            let is_virtio = compatible(node, VIRTIO_MMIO_COMPATIBLE);
            if !node_should_map_mmio(node) {
                continue;
            }
            let regions = node.reg().expect("DTB MMIO node has no usable reg");
            for region in regions {
                let size = region.size.expect("DTB MMIO region has no size");
                let start = region.starting_address as usize;
                let end = start
                    .checked_add(size)
                    .expect("DTB MMIO range overflows address space");
                push_range(&mut mmio_ranges, &mut mmio_range_count, start, end, "MMIO");
                if is_virtio {
                    assert!(
                        virtio_count < MAX_VIRTIO_MMIO_DEVICES,
                        "too many virtio-mmio devices"
                    );
                    virtio_devices[virtio_count] = VirtioMmioDevice { base: start, size };
                    virtio_count += 1;
                }
            }
        }
        assert_ne!(
            phys_mem_range_count, 0,
            "DTB contains no usable physical memory range"
        );
        sort_and_merge(&mut phys_mem_ranges, &mut phys_mem_range_count);
        sort_and_merge(&mut reserved_ranges, &mut reserved_range_count);
        sort_and_merge(&mut mmio_ranges, &mut mmio_range_count);
        virtio_devices[..virtio_count].sort_unstable_by_key(|device| device.base);

        Self {
            active_hart_mask,
            discovered_harts,
            ignored_harts,
            timebase_frequency,
            all_harts_have_sstc,
            all_harts_have_svvptc,
            phys_mem_ranges,
            phys_mem_range_count,
            reserved_ranges,
            reserved_range_count,
            mmio_ranges,
            mmio_range_count,
            virtio_devices,
            virtio_count,
        }
    }
}

pub fn init(dtb_pa: usize, boot_hart_id: usize) {
    DTB_DATA.call_once(|| DtbData::parse(dtb_pa, boot_hart_id));
}

pub fn data() -> &'static DtbData {
    DTB_DATA
        .get()
        .expect("RISC-V DtbData accessed before initialization")
}

pub fn active_hart_mask() -> usize {
    data().active_hart_mask
}
pub fn hart_counts() -> (usize, usize) {
    (data().discovered_harts, data().ignored_harts)
}
pub fn timebase_frequency() -> usize {
    data().timebase_frequency
}
pub fn all_harts_have_sstc() -> bool {
    data().all_harts_have_sstc
}
pub fn all_harts_have_svvptc() -> bool {
    data().all_harts_have_svvptc
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
    for device in &data.virtio_devices[..data.virtio_count] {
        f(device.base, device.size);
    }
}
