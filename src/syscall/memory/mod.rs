mod mlock;
mod mmap;
mod unmap;

pub use mlock::*;
pub use mmap::*;
pub use unmap::*;

pub(super) use crate::syscall::error::{SyscallError, err};
pub(super) use crate::{
    config::{PAGE_SIZE, USER_HEAP_GAP},
    fs::{
        File, OSInode, PseudoShmFile, ext4_lock, vm_commit_limit_bytes, vm_committed_as_bytes,
        vm_overcommit_memory,
    },
    mm::{MapPermission, PTEFlags, frame_alloc, try_copy_to_user, try_copy_to_user_unchecked},
    task::{
        MmapRegion,
        manager::PID2PCB,
        processor::{current_files, current_process},
    },
    trap::get_current_token,
};
pub(super) use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
pub(super) use core::cmp::min;

pub(super) const PROT_READ: usize = 1;
pub(super) const PROT_WRITE: usize = 2;
pub(super) const PROT_EXEC: usize = 4;

// Linux `mmap(2)` flags (subset).
pub(super) const MAP_SHARED: usize = 0x01;
pub(super) const MAP_PRIVATE: usize = 0x02;
pub(super) const MAP_SHARED_VALIDATE: usize = 0x03;
pub(super) const MAP_FIXED: usize = 0x10;
pub(super) const MAP_ANONYMOUS: usize = 0x20;
pub(super) const MAP_GROWSDOWN: usize = 0x0100;
pub(super) const MAP_LOCKED: usize = 0x2000;
pub(super) const MAP_STACK: usize = 0x20000;
pub(super) const MAP_FIXED_NOREPLACE: usize = 0x100000;
pub(super) const MAP_TYPE_MASK: usize = 0x0f;

pub(super) const LARGE_ANON_MMAP: usize = 1 * 1024 * 1024;

pub(super) const MCL_CURRENT: usize = 0x01;
pub(super) const MCL_FUTURE: usize = 0x02;
pub(super) const MCL_ONFAULT: usize = 0x04;

pub(super) const MREMAP_MAYMOVE: usize = 0x1;
pub(super) const MREMAP_FIXED: usize = 0x2;

#[cfg(target_arch = "loongarch64")]
pub(super) const USER_VA_TOP: usize = crate::config::TRAP_CONTEXT;
// Sv39 user-space low canonical range is [0, 2^38).
// Reject higher addresses so mmap() can't wrap/alias via VirtAddr masking.
#[cfg(not(target_arch = "loongarch64"))]
pub(super) const USER_VA_TOP: usize = 1usize << 38;

pub(super) fn align_down(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

pub(super) fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

pub(super) fn user_range_valid(start: usize, end: usize) -> bool {
    start < end && end <= USER_VA_TOP
}

pub(super) fn anon_private_commit_charge(
    map_len: usize,
    prot: usize,
    is_anon: bool,
    is_shared: bool,
) -> usize {
    if is_anon && !is_shared && (prot & PROT_WRITE) != 0 {
        map_len
    } else {
        0
    }
}

pub(super) fn overcommit_limit_bytes() -> Option<usize> {
    match vm_overcommit_memory() {
        0 => None,
        1 => None,
        2 => Some(vm_commit_limit_bytes()),
        _ => None,
    }
}

pub(super) fn exceeds_overcommit_limit(additional_bytes: usize) -> bool {
    if additional_bytes == 0 {
        return false;
    }
    let Some(limit) = overcommit_limit_bytes() else {
        return false;
    };
    vm_committed_as_bytes().saturating_add(additional_bytes) > limit
}

pub(super) fn find_free_user_range(
    ranges: &[(usize, usize)],
    min_start: usize,
    len: usize,
) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let mut cursor = align_up(min_start, PAGE_SIZE);
    for (range_start, range_end) in ranges.iter().copied() {
        if range_end <= cursor {
            continue;
        }
        let end = cursor.checked_add(len)?;
        if end <= range_start {
            return user_range_valid(cursor, end).then_some(cursor);
        }
        cursor = align_up(range_end, PAGE_SIZE);
    }
    let end = cursor.checked_add(len)?;
    user_range_valid(cursor, end).then_some(cursor)
}

pub(super) fn get_fd_file(fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
    current_files().lock().get_file(fd)
}

pub(super) fn push_mmap_region_merged(
    regions: &mut alloc::vec::Vec<MmapRegion>,
    region: MmapRegion,
) {
    if region.len == 0 {
        return;
    }
    if let Some(last) = regions.last_mut() {
        if last.end() == region.start
            && last.prot == region.prot
            && last.shared == region.shared
            && last.may_write_upgrade == region.may_write_upgrade
            && last.file_backed == region.file_backed
            && last.file_dev == region.file_dev
            && last.file_ino == region.file_ino
            && last.file_offset + last.len == region.file_offset
            && last.growsdown == region.growsdown
            && last.sigbus_start == region.sigbus_start
        {
            last.len += region.len;
            return;
        }
    }
    regions.push(region);
}

pub(super) fn slice_mmap_region(region: MmapRegion, start: usize, len: usize) -> MmapRegion {
    let end = start.saturating_add(len);
    let file_delta = start.saturating_sub(region.start);
    MmapRegion {
        start,
        len,
        file_offset: region.file_offset.saturating_add(file_delta),
        sigbus_start: region.sigbus_start.clamp(start, end),
        ..region
    }
}

pub(super) fn move_mmap_region(region: MmapRegion, new_start: usize) -> MmapRegion {
    let sigbus_delta = region
        .sigbus_start
        .saturating_sub(region.start)
        .min(region.len);
    MmapRegion {
        start: new_start,
        sigbus_start: new_start.saturating_add(sigbus_delta),
        ..region
    }
}

pub(super) fn trim_mmap_regions(
    regions: &mut alloc::vec::Vec<MmapRegion>,
    start: usize,
    end: usize,
) {
    let mut next = alloc::vec::Vec::new();
    for region in regions.drain(..) {
        let r_end = region.end();
        if end <= region.start || start >= r_end {
            push_mmap_region_merged(&mut next, region);
            continue;
        }
        if start > region.start {
            push_mmap_region_merged(
                &mut next,
                slice_mmap_region(region, region.start, start - region.start),
            );
        }
        if end < r_end {
            push_mmap_region_merged(&mut next, slice_mmap_region(region, end, r_end - end));
        }
    }
    *regions = next;
}

pub(super) fn apply_mprotect_to_mmap_regions(
    regions: &mut alloc::vec::Vec<MmapRegion>,
    start: usize,
    end: usize,
    new_prot: usize,
) -> Result<(), ()> {
    let mut next = alloc::vec::Vec::new();
    for region in regions.iter().copied() {
        let r_end = region.end();
        if end <= region.start || start >= r_end {
            push_mmap_region_merged(&mut next, region);
            continue;
        }
        if start > region.start {
            push_mmap_region_merged(
                &mut next,
                slice_mmap_region(region, region.start, start - region.start),
            );
        }
        let ov_start = core::cmp::max(start, region.start);
        let ov_end = core::cmp::min(end, r_end);
        let mut mid = slice_mmap_region(region, ov_start, ov_end - ov_start);
        if (new_prot & PROT_WRITE) != 0 && (mid.prot & PROT_WRITE) == 0 && !mid.may_write_upgrade {
            return Err(());
        }
        mid.prot = new_prot;
        push_mmap_region_merged(&mut next, mid);
        if end < r_end {
            push_mmap_region_merged(&mut next, slice_mmap_region(region, end, r_end - end));
        }
    }
    *regions = next;
    Ok(())
}

pub(super) fn find_inode_file_in_snapshot(
    files: &[(usize, Arc<dyn File + Send + Sync>)],
    device_id: usize,
    inode_num: u32,
) -> Option<Arc<dyn File + Send + Sync>> {
    for (_fd, file) in files {
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            continue;
        };
        let inode = os_inode.ext4_inode();
        if inode.device_id() == device_id && inode.inode_num() == inode_num {
            return Some(Arc::clone(file));
        }
    }
    None
}

pub(super) fn find_open_inode_file(
    device_id: usize,
    inode_num: u32,
) -> Option<Arc<dyn File + Send + Sync>> {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        let files = Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        let snapshot = files.lock().iter_files_snapshot();
        if let Some(file) = find_inode_file_in_snapshot(&snapshot, device_id, inode_num) {
            return Some(file);
        }
    }
    None
}

pub(super) fn push_range_merged(
    ranges: &mut alloc::vec::Vec<(usize, usize)>,
    start: usize,
    end: usize,
) {
    if end <= start {
        return;
    }
    if let Some(last) = ranges.last_mut() {
        if start <= last.1 {
            last.1 = last.1.max(end);
            return;
        }
    }
    ranges.push((start, end));
}

pub(super) fn normalize_ranges(ranges: &mut alloc::vec::Vec<(usize, usize)>) {
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = alloc::vec::Vec::new();
    for (start, end) in ranges.drain(..) {
        push_range_merged(&mut merged, start, end);
    }
    *ranges = merged;
}

pub(super) fn trim_ranges(ranges: &mut alloc::vec::Vec<(usize, usize)>, start: usize, end: usize) {
    if end <= start {
        return;
    }
    let mut next = alloc::vec::Vec::new();
    for (r_start, r_end) in ranges.drain(..) {
        if end <= r_start || start >= r_end {
            push_range_merged(&mut next, r_start, r_end);
            continue;
        }
        if start > r_start {
            push_range_merged(&mut next, r_start, start);
        }
        if end < r_end {
            push_range_merged(&mut next, end, r_end);
        }
    }
    *ranges = next;
}

pub(super) fn ranges_total_len(ranges: &[(usize, usize)]) -> usize {
    ranges
        .iter()
        .map(|(start, end)| end.saturating_sub(*start))
        .sum()
}

pub(super) fn ranges_overlap(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    ranges
        .iter()
        .any(|(r_start, r_end)| end > *r_start && start < *r_end)
}

pub(super) fn page_overlaps_mmap_regions(page_start: usize, regions: &[MmapRegion]) -> bool {
    let page_end = page_start.saturating_add(PAGE_SIZE);
    regions
        .iter()
        .any(|region| page_end > region.start && page_start < region.end())
}

pub(super) fn page_overlaps_sysv_shm_regions(
    page_start: usize,
    attaches: &[crate::syscall::sysv_shm::ShmAttach],
) -> bool {
    let page_end = page_start.saturating_add(PAGE_SIZE);
    attaches.iter().any(|a| {
        let a_end = a.addr.saturating_add(a.len);
        page_end > a.addr && page_start < a_end
    })
}
