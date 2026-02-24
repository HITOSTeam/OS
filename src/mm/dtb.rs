use core::cmp::{max, min};

use fdt::Fdt;

use crate::config::set_phys_mem_range;

pub fn init_phys_mem_from_dtb(dtb_pa: usize) {
    if dtb_pa == 0 {
        return;
    }
    let Ok(fdt) = (unsafe { Fdt::from_ptr(dtb_pa as *const u8) }) else {
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
    }
}
