use fdt::Fdt;

use crate::config::{
    DEFAULT_MEMORY_END, DEFAULT_MEMORY_START, MAX_DTB_MMIO_REGIONS, MAX_PHYS_MEMORY_REGIONS,
    MAX_VIRTIO_MMIO_DEVICES, init_platform_info,
};

const VIRTIO_MMIO_COMPATIBLE: &[u8] = b"virtio,mmio";

/// 检查 `compatible` 属性的 NUL 分隔字符串列表中是否包含指定值。
fn compatible_contains(node: fdt::node::FdtNode<'_, '_>, needle: &[u8]) -> bool {
    node.property("compatible").is_some_and(|prop| {
        prop.value
            .split(|byte| *byte == 0)
            .any(|entry| entry == needle)
    })
}

/// 检查节点是否由 `device_type = "memory"` 声明为内存。
fn node_is_memory(node: fdt::node::FdtNode<'_, '_>) -> bool {
    node.property("device_type")
        .and_then(|prop| prop.as_str())
        .is_some_and(|device_type| device_type == "memory")
}

/// 检查节点是否是 virtio-mmio 设备。
fn node_is_virtio_mmio(node: fdt::node::FdtNode<'_, '_>) -> bool {
    compatible_contains(node, VIRTIO_MMIO_COMPATIBLE)
}

/// 判断设备的 `reg` 区间是否需要加入内核 MMIO 恒等映射。
fn node_should_map_mmio(node: fdt::node::FdtNode<'_, '_>) -> bool {
    node_is_virtio_mmio(node)
        || compatible_contains(node, b"ns16550a")
        || compatible_contains(node, b"qemu,fw-cfg-mmio")
        || compatible_contains(node, b"syscon")
}

#[allow(dead_code)]
/// 在堆初始化前解析 DTB，并一次性发布多段 RAM 与设备 MMIO 信息。
pub fn init_phys_mem_from_dtb(dtb_pa: usize) {
    if dtb_pa == 0 {
        crate::println!(
            "[mm] no dtb address provided, using default memory range: {:#x}-{:#x}",
            DEFAULT_MEMORY_START,
            DEFAULT_MEMORY_END
        );
        return;
    }
    let Ok(fdt) = (unsafe { Fdt::from_ptr(dtb_pa as *const u8) }) else {
        crate::println!(
            "[mm] failed to parse dtb @ {:#x}, using default memory range: {:#x}-{:#x}",
            dtb_pa,
            DEFAULT_MEMORY_START,
            DEFAULT_MEMORY_END
        );
        return;
    };

    let mut ranges = [(0usize, 0usize); MAX_PHYS_MEMORY_REGIONS];
    let mut count = 0usize;
    // let tmep = fdt.find_all_nodes("/memory");
    // `Fdt::memory()` 只返回第一个基础名称为 `memory` 的节点。
    // LoongArch QEMU 使用两个独立的 memory@... 节点描述低端和高端内存，
    // 因此必须遍历所有匹配节点，并收集每个节点的全部 `reg` 区间。
    for node in fdt.find_all_nodes("/memory") {
        let Some(regions) = node.reg() else {
            continue;
        };
        for region in regions {
            let region_start = region.starting_address as usize;
            let Some(size) = region.size else {
                continue;
            };
            let region_end = region_start.saturating_add(size);
            if region_end <= region_start {
                continue;
            }
            if count < ranges.len() {
                ranges[count] = (region_start, region_end);
                count += 1;
            } else {
                crate::println!(
                    "[mm] too many DTB memory ranges; ignoring {:#x}-{:#x}",
                    region_start,
                    region_end
                );
            }
        }
    }

    crate::println!("[memory] we find {} regions", count);
    // 排序并合并重叠/相邻段，避免同一物理页被分配器登记两次。
    ranges[..count].sort_unstable_by_key(|&(start, _)| start);
    let mut merged_count = 0;
    for index in 0..count {
        let (start, end) = ranges[index];
        if merged_count != 0 && start <= ranges[merged_count - 1].1 {
            ranges[merged_count - 1].1 = ranges[merged_count - 1].1.max(end);
        } else {
            ranges[merged_count] = (start, end);
            merged_count += 1;
        }
    }
    count = merged_count;

    if count > 0 {
        for &(start, end) in ranges[..count].iter() {
            crate::println!("[mm] dtb memory range: {:#x}-{:#x}", start, end);
        }
    } else {
        crate::println!(
            "[mm] dtb has no valid memory range, using default memory range: {:#x}-{:#x}",
            DEFAULT_MEMORY_START,
            DEFAULT_MEMORY_END
        );
    }

    let mut mmio_ranges = [(0usize, 0usize); MAX_DTB_MMIO_REGIONS];
    let mut mmio_count = 0usize;
    let mut virtio_bases = [0usize; MAX_VIRTIO_MMIO_DEVICES];
    let mut virtio_count = 0usize;
    // 内存节点已在上面单独收集；这里只发现需要映射或枚举的设备资源。
    for node in fdt.all_nodes() {
        if node_is_memory(node) {
            continue;
        }
        let is_virtio_mmio = node_is_virtio_mmio(node);
        let should_map_mmio = node_should_map_mmio(node);
        let Some(regions) = node.reg() else {
            continue;
        };
        for region in regions {
            let start = region.starting_address as usize;
            let Some(size) = region.size else {
                continue;
            };
            let end = start.saturating_add(size);
            if end <= start {
                continue;
            }
            if should_map_mmio && mmio_count < mmio_ranges.len() {
                mmio_ranges[mmio_count] = (start, end);
                mmio_count += 1;
            }
            if is_virtio_mmio && virtio_count < virtio_bases.len() {
                virtio_bases[virtio_count] = start;
                virtio_count += 1;
            }
        }
    }

    init_platform_info(
        &ranges[..count],
        &mmio_ranges[..mmio_count],
        &virtio_bases[..virtio_count],
    );
}
