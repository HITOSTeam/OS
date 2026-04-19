use core::cmp::{max, min};

use fdt::Fdt;

use crate::config::{DEFAULT_MEMORY_END, DEFAULT_MEMORY_START, set_phys_mem_range};

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
