use core::cmp::{max, min};

use fdt::Fdt;

use crate::config::MAX_HARTS;
use crate::config::{DEFAULT_MEMORY_END, DEFAULT_MEMORY_START, set_phys_mem_range};

#[derive(Clone, Copy, Debug)]
pub struct HartTopology {
    pub present_mask: usize,
    pub discovered: usize,
    pub ignored: usize,
}

impl HartTopology {
    fn boot_hart_only(boot_hart_id: usize) -> Self {
        let present_mask = if boot_hart_id < usize::BITS as usize {
            1usize << boot_hart_id
        } else {
            1
        };
        Self {
            present_mask,
            discovered: 1,
            ignored: 0,
        }
    }
}

/// Discover the physical CPU IDs advertised by QEMU's `/cpus` FDT node.
///
/// The returned mask deliberately stays physical-ID based. Both QEMU virt
/// machines advertise IDs that fit in `MAX_HARTS`; sparse IDs in that bounded
/// range remain representable without inventing a logical/physical mapping.
pub fn hart_topology_from_dtb(dtb_pa: usize, boot_hart_id: usize) -> HartTopology {
    if dtb_pa == 0 {
        return HartTopology::boot_hart_only(boot_hart_id);
    }
    let Ok(fdt) = (unsafe { Fdt::from_ptr(dtb_pa as *const u8) }) else {
        return HartTopology::boot_hart_only(boot_hart_id);
    };

    let mut present_mask = 0usize;
    let mut discovered = 0usize;
    let mut ignored = 0usize;
    for cpu in fdt.cpus() {
        discovered = discovered.saturating_add(1);
        let hart_id = cpu.ids().first();
        if hart_id < MAX_HARTS && hart_id < usize::BITS as usize {
            present_mask |= 1usize << hart_id;
        } else {
            ignored = ignored.saturating_add(1);
        }
    }

    if boot_hart_id < MAX_HARTS && boot_hart_id < usize::BITS as usize {
        present_mask |= 1usize << boot_hart_id;
    }
    if present_mask == 0 {
        return HartTopology::boot_hart_only(boot_hart_id);
    }
    HartTopology {
        present_mask,
        discovered,
        ignored,
    }
}

#[allow(dead_code)]
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

    let mut start = usize::MAX;
    let mut end = 0usize;
    for region in fdt.memory().regions() {
        let region_start = region.starting_address as usize;
        let Some(size) = region.size else {
            continue;
        };
        let region_end = region_start.saturating_add(size);
        if region_end <= region_start {
            continue;
        }
        start = min(start, region_start);
        end = max(end, region_end);
    }

    if start != usize::MAX && end > start {
        set_phys_mem_range(start, end);
        crate::println!("[mm] dtb memory range: {:#x}-{:#x}", start, end);
    } else {
        crate::println!(
            "[mm] dtb has no valid memory range, using default memory range: {:#x}-{:#x}",
            DEFAULT_MEMORY_START,
            DEFAULT_MEMORY_END
        );
    }
}
