//! RISC-V 启动 DTB 的一次性解析与缓存。
//!
//! 启动阶段在堆初始化之前完成解析，把时钟、ISA 扩展和 virtio-mmio 信息复制到
//! 固定容量数组；后续路径不再持有或重新遍历 DTB。

use fdt::{node::FdtNode, Fdt};
use spin::Once;

use crate::config::{MAX_VIRTIO_MMIO_DEVICES, MAX_HARTS};

#[derive(Clone, Copy)]
struct VirtioMmioDevice {
    base: usize,
    size: usize,
}

struct DtbData {
    timebase_frequency: Option<usize>,
    all_harts_have_sstc: bool,
    all_harts_have_svvptc: bool,
    virtio_devices: [VirtioMmioDevice; MAX_VIRTIO_MMIO_DEVICES],
    virtio_count: usize,
}

static DTB_DATA: Once<DtbData> = Once::new();

/// 按设备树约定判断节点是否可供当前内核使用。
fn available(node: FdtNode<'_, '_>) -> bool {
    node.property("status")
        .map(|property| matches!(property.as_str(), Some("okay" | "ok")))
        .unwrap_or(true)
}

/// 在 NUL 分隔的 compatible 列表中查找指定兼容串。
fn compatible(node: FdtNode<'_, '_>, expected: &[u8]) -> bool {
    node.property("compatible").is_some_and(|property| {
        property
            .value
            .split(|byte| *byte == 0)
            .any(|entry| entry == expected)
    })
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

/// 优先读取新式扩展列表，缺失时回退到旧式 ISA 字符串。
fn cpu_has_extension(
    cpu: impl Fn(&str) -> Option<fdt::node::NodeProperty<'_>>,
    extension: &[u8],
) -> bool {
    cpu("riscv,isa-extensions")
        .is_some_and(|property| {
            property
                .value
                .split(|byte| *byte == 0)
                .any(|entry| entry == extension)
        })
        || cpu
            ("riscv,isa")
            .is_some_and(|property| isa_string_contains(property.value, extension))
}

impl DtbData {
    /// 把启动阶段所需字段复制至固定容量缓存，后续不再持有 FDT 引用。
    fn parse(dtb_pa: usize) -> Self {
        let fdt = unsafe { Fdt::from_ptr(dtb_pa as *const u8) }
            .expect("RISC-V bootloader supplied an invalid DTB");
        let timebase_frequency = fdt
            .find_node("/cpus")
            .and_then(|node| node.property("timebase-frequency"))
            .and_then(|property| property.as_usize())
            .filter(|frequency| *frequency != 0);

        let mut seen_hart = false;
        let mut all_harts_have_sstc = true;
        let mut all_harts_have_svvptc = true;
        for cpu in fdt.cpus() {
            let hart_id = cpu.ids().first();
            let cpu_available = cpu
                .property("status")
                .map(|property| matches!(property.as_str(), Some("okay" | "ok")))
                .unwrap_or(true);
            if hart_id >= MAX_HARTS || hart_id >= usize::BITS as usize || !cpu_available {
                continue;
            }
            seen_hart = true;
            all_harts_have_sstc &= cpu_has_extension(|name| cpu.property(name), b"sstc");
            all_harts_have_svvptc &= cpu_has_extension(|name| cpu.property(name), b"svvptc");
        }

        let mut virtio_devices = [VirtioMmioDevice { base: 0, size: 0 }; MAX_VIRTIO_MMIO_DEVICES];
        let mut virtio_count = 0;
        for node in fdt.all_nodes() {
            if !available(node) || !compatible(node, b"virtio,mmio") {
                continue;
            }
            let Some(regions) = node.reg() else {
                continue;
            };
            for region in regions {
                let Some(size) = region.size else {
                    continue;
                };
                if size == 0 || virtio_count == MAX_VIRTIO_MMIO_DEVICES {
                    continue;
                }
                virtio_devices[virtio_count] = VirtioMmioDevice {
                    base: region.starting_address as usize,
                    size,
                };
                virtio_count += 1;
            }
        }
        virtio_devices[..virtio_count].sort_unstable_by_key(|device| device.base);

        Self {
            timebase_frequency,
            all_harts_have_sstc: seen_hart && all_harts_have_sstc,
            all_harts_have_svvptc: seen_hart && all_harts_have_svvptc,
            virtio_devices,
            virtio_count,
        }
    }
}

/// 在启动 DTB 尚可直接访问、且次级 hart 尚未启动时完成一次解析。
pub fn init(dtb_pa: usize) {
    if dtb_pa != 0 {
        DTB_DATA.call_once(|| DtbData::parse(dtb_pa));
    }
}

pub fn timebase_frequency() -> Option<usize> {
    DTB_DATA.get().and_then(|data| data.timebase_frequency)
}

/// 返回所有可用 hart 是否共同支持 Sstc 定时器扩展。
pub fn all_harts_have_sstc() -> bool {
    DTB_DATA
        .get()
        .is_some_and(|data| data.all_harts_have_sstc)
}

/// 返回所有可用 hart 是否共同支持 Svvptc 页表遍历缓存扩展。
pub fn all_harts_have_svvptc() -> bool {
    DTB_DATA
        .get()
        .is_some_and(|data| data.all_harts_have_svvptc)
}

/// 按物理基地址顺序遍历 DTB 中声明的 virtio-mmio 设备。
pub fn for_each_virtio_mmio_device(mut f: impl FnMut(usize, usize)) {
    if let Some(data) = DTB_DATA.get() {
        for device in &data.virtio_devices[..data.virtio_count] {
            f(device.base, device.size);
        }
    }
}
