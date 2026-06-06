//! Implementation of [`MapArea`] and [`MemorySet`].

use super::elf_loader::{
    ENOMEM, ET_DYN, ElfHeader64, ElfPhdr64, PF_R, PF_W, PF_X, PT_LOAD, PT_PHDR, parse_elf_headers,
    read_exact_with,
};
use super::{FrameTracker, frame_alloc, try_copy_to_user_unchecked};
use super::{PTEFlags, PageTable, PageTableEntry, PageWalkCache};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
use crate::config::{
    MMIO, PAGE_SIZE, SIGRETURN_TRAMPOLINE, TRAMPOLINE, TRAP_CONTEXT, USER_HEAP_GAP,
    USER_STACK_SIZE, phys_mem_end,
};
use crate::fs::{File, cgroup_charge_anon_current};
use crate::println;
use crate::task::processor::current_process;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::*;
#[cfg(target_arch = "riscv64")]
use riscv::register::satp::{self, Satp};
use spin::Mutex;
unsafe extern "C" {
    safe fn stext();
    safe fn etext();
    safe fn srodata();
    safe fn erodata();
    safe fn sdata();
    safe fn edata();
    safe fn sbss_with_stack();
    safe fn ebss();
    safe fn ekernel();
    safe fn strampoline();
}

static COW_CLONE_DIAG_SEQ: AtomicUsize = AtomicUsize::new(0);
const DEFAULT_MMAP_BASE: usize = 0x34_0000_0000;

lazy_static! {
    /// a memory set instance through lazy_static! managing kernel space
    pub static ref KERNEL_SPACE: Mutex<MemorySet> = Mutex::new(MemorySet::new_kernel());
}

/// memory set structure, controls virtual-memory space
pub struct MemorySet {
    page_table: PageTable,
    areas: Vec<MapArea>,
    /// Linux mm_struct-style mmap metadata.  Keep syscall-level VMA identity
    /// with the address space instead of duplicating it in the process block.
    vm_regions: Vec<VmRegion>,
    mmap_backings: BTreeMap<usize, Arc<dyn File + Send + Sync>>,
    next_mmap_backing_id: usize,
    heap_start: usize,
    brk: usize,
    mmap_next: usize,
    /// Virtual ranges currently locked by mlock/mlockall.
    mlocked_ranges: Vec<(usize, usize)>,
    /// Whether MCL_FUTURE is enabled for this address space.
    mlockall_future: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmRegion {
    pub start: usize,
    pub len: usize,
    /// User-visible protection bits kept for procfs/stat-style reporting.
    pub prot: usize,
    /// Core mapping strategy for this VMA.  `MapArea` still owns the concrete
    /// frames/page-table state; this field keeps syscall-visible VMA metadata
    /// in the same object so later fault handling can stop re-deriving it.
    pub map_type: MapType,
    /// Stored as raw bits so `VmRegion` remains a plain copyable descriptor.
    pub map_perm_bits: u8,
    pub shared: bool,
    /// False for shared file mappings on descriptors without write access.
    pub may_write_upgrade: bool,
    /// File-backed mapping identity for write/mmap coherence.
    pub file_backed: bool,
    pub file_dev: usize,
    pub file_ino: u32,
    pub file_offset: usize,
    /// Number of bytes from `start` that correspond to current file contents.
    /// Bytes in the last mapped page beyond this length are zero-fill tail and
    /// must not be written back by msync.
    pub file_valid_len: usize,
    /// Stable backing entry for file-backed mmap writeback after close(fd).
    pub backing_id: usize,
    /// Non-zero for `PseudoShmFile`/memfd-backed mappings.
    pub memfd_id: u64,
    /// Whether this region should expand downward on guard-page faults.
    pub growsdown: bool,
    /// Start address (inclusive) of the SIGBUS tail for file mappings.
    /// `>= end()` means no SIGBUS tail.
    pub sigbus_start: usize,
}

impl VmRegion {
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    pub fn end(&self) -> usize {
        self.start.saturating_add(self.len)
    }

    pub fn permission_from_prot(prot: usize) -> MapPermission {
        let mut perm = MapPermission::U;
        if (prot & Self::PROT_READ) != 0 {
            perm |= MapPermission::R;
        }
        if (prot & Self::PROT_WRITE) != 0 {
            perm |= MapPermission::W;
        }
        if (prot & Self::PROT_EXEC) != 0 {
            perm |= MapPermission::X;
        }
        perm
    }

    pub fn map_permission(&self) -> MapPermission {
        MapPermission::from_bits_truncate(self.map_perm_bits)
    }

    pub fn set_prot(&mut self, prot: usize) {
        self.prot = prot;
        self.map_perm_bits = Self::permission_from_prot(prot).bits();
    }
}

fn push_range_merged(ranges: &mut Vec<(usize, usize)>, start: usize, end: usize) {
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

fn normalize_ranges(ranges: &mut Vec<(usize, usize)>) {
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = Vec::new();
    for (start, end) in ranges.drain(..) {
        push_range_merged(&mut merged, start, end);
    }
    *ranges = merged;
}

fn trim_ranges(ranges: &mut Vec<(usize, usize)>, start: usize, end: usize) {
    if end <= start {
        return;
    }
    let mut next = Vec::new();
    for (r_start, r_end) in ranges.drain(..) {
        if end <= r_start || start >= r_end {
            next.push((r_start, r_end));
            continue;
        }
        if start > r_start {
            next.push((r_start, start));
        }
        if end < r_end {
            next.push((end, r_end));
        }
    }
    normalize_ranges(&mut next);
    *ranges = next;
}

fn ranges_total_len(ranges: &[(usize, usize)]) -> usize {
    ranges
        .iter()
        .map(|(start, end)| end.saturating_sub(*start))
        .sum()
}

fn ranges_overlap(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    ranges
        .iter()
        .any(|(r_start, r_end)| end > *r_start && start < *r_end)
}

fn range_overlap_len(start: usize, end: usize, other_start: usize, other_end: usize) -> usize {
    let overlap_start = core::cmp::max(start, other_start);
    let overlap_end = core::cmp::min(end, other_end);
    overlap_end.saturating_sub(overlap_start)
}

fn sort_map_areas(areas: &mut [MapArea]) {
    areas.sort_unstable_by_key(|area| area.vpn_range.get_start().0);
}

fn normalize_vm_region_list(regions: &mut Vec<VmRegion>) {
    regions.sort_unstable_by_key(|region| region.start);
    let mut merged = Vec::new();
    for region in regions.drain(..) {
        push_vm_region_merged(&mut merged, region);
    }
    *regions = merged;
}

fn push_vm_region_merged(regions: &mut Vec<VmRegion>, region: VmRegion) {
    if region.len == 0 {
        return;
    }
    if let Some(last) = regions.last_mut() {
        if last.end() == region.start
            && last.prot == region.prot
            && last.map_type == region.map_type
            && last.map_perm_bits == region.map_perm_bits
            && last.shared == region.shared
            && last.may_write_upgrade == region.may_write_upgrade
            && last.file_backed == region.file_backed
            && last.file_dev == region.file_dev
            && last.file_ino == region.file_ino
            && last.file_offset + last.len == region.file_offset
            && last.file_valid_len == last.len
            && last.backing_id == region.backing_id
            && last.memfd_id == region.memfd_id
            && last.growsdown == region.growsdown
            && last.sigbus_start == region.sigbus_start
        {
            last.file_valid_len = last
                .file_valid_len
                .saturating_add(region.file_valid_len)
                .min(last.len.saturating_add(region.len));
            last.len += region.len;
            return;
        }
    }
    regions.push(region);
}

fn slice_vm_region(region: VmRegion, start: usize, len: usize) -> VmRegion {
    let end = start.saturating_add(len);
    let file_delta = start.saturating_sub(region.start);
    let valid_end = region
        .start
        .saturating_add(region.file_valid_len.min(region.len));
    VmRegion {
        start,
        len,
        file_offset: region.file_offset.saturating_add(file_delta),
        file_valid_len: valid_end.saturating_sub(start).min(len),
        sigbus_start: region.sigbus_start.clamp(start, end),
        ..region
    }
}

fn move_vm_region(region: VmRegion, new_start: usize) -> VmRegion {
    let sigbus_delta = region
        .sigbus_start
        .saturating_sub(region.start)
        .min(region.len);
    VmRegion {
        start: new_start,
        sigbus_start: new_start.saturating_add(sigbus_delta),
        ..region
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ElfAux {
    pub phdr: usize,
    pub phent: usize,
    pub phnum: usize,
}

impl MemorySet {
    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: Vec::new(),
            vm_regions: Vec::new(),
            mmap_backings: BTreeMap::new(),
            next_mmap_backing_id: 1,
            heap_start: 0,
            brk: 0,
            mmap_next: DEFAULT_MMAP_BASE,
            mlocked_ranges: Vec::new(),
            mlockall_future: false,
        }
    }
    pub fn token(&self) -> usize {
        self.page_table.token()
    }

    fn inherit_user_vm_metadata_from(&mut self, parent: &MemorySet) {
        self.vm_regions = parent.vm_regions.clone();
        self.normalize_vm_regions();
        self.mmap_backings = parent.mmap_backings.clone();
        self.next_mmap_backing_id = parent.next_mmap_backing_id;
        self.heap_start = parent.heap_start;
        self.brk = parent.brk;
        self.mmap_next = parent.mmap_next;
        // Do not inherit mlock/mlockall state across fork-style address-space
        // cloning; Linux clears memory locks in the child.
        self.debug_assert_user_vm_invariants();
    }

    fn sort_user_areas(&mut self) {
        sort_map_areas(&mut self.areas);
    }

    fn normalize_vm_regions(&mut self) {
        normalize_vm_region_list(&mut self.vm_regions);
    }

    #[cfg(debug_assertions)]
    fn debug_assert_user_vm_invariants(&self) {
        let mut prev_area_end = VirtPageNum(0);
        for area in self.areas.iter() {
            let start = area.vpn_range.get_start();
            let end = area.vpn_range.get_end();
            debug_assert!(
                start >= prev_area_end,
                "MapArea list is not sorted or overlaps: prev_end={:#x}, start={:#x}, end={:#x}",
                prev_area_end.0.saturating_mul(PAGE_SIZE),
                start.0.saturating_mul(PAGE_SIZE),
                end.0.saturating_mul(PAGE_SIZE)
            );
            debug_assert!(start <= end, "MapArea has inverted VPN range");
            if area.map_type == MapType::Identical {
                debug_assert!(
                    area.data_frames.is_empty(),
                    "Identical MapArea must not own frame trackers"
                );
            }
            for vpn in area.data_frames.keys() {
                debug_assert!(
                    *vpn >= start && *vpn < end,
                    "MapArea frame tracker outside owning range"
                );
            }
            prev_area_end = end;
        }

        let allowed_perm_bits = MapPermission::all().bits();
        let mut prev_region_end = 0usize;
        for region in self.vm_regions.iter() {
            let end = region.end();
            debug_assert!(region.len > 0, "VmRegion must not be empty");
            debug_assert!(end > region.start, "VmRegion end wrapped");
            debug_assert!(
                region.start >= prev_region_end,
                "VmRegion list is not sorted or overlaps: prev_end={:#x}, start={:#x}, end={:#x}",
                prev_region_end,
                region.start,
                end
            );
            debug_assert!(
                region.map_perm_bits & !allowed_perm_bits == 0,
                "VmRegion has unknown MapPermission bits"
            );
            debug_assert!(
                region.map_permission().contains(MapPermission::U),
                "VmRegion must describe a user mapping"
            );
            debug_assert!(
                region.file_valid_len <= region.len,
                "VmRegion file_valid_len exceeds mapping length"
            );
            debug_assert!(
                region.sigbus_start >= region.start && region.sigbus_start <= end,
                "VmRegion SIGBUS tail marker outside mapping"
            );
            if region.file_backed {
                debug_assert!(
                    region.backing_id != 0,
                    "file-backed VmRegion must keep a backing id"
                );
            } else {
                debug_assert!(
                    region.file_valid_len == 0 || region.file_valid_len == region.len,
                    "anonymous VmRegion should not carry a partial file_valid_len"
                );
            }
            prev_region_end = end;
        }
    }

    #[cfg(not(debug_assertions))]
    fn debug_assert_user_vm_invariants(&self) {}

    pub fn reset_user_layout(&mut self, ustack_base: usize) {
        let heap_start = ustack_base
            .saturating_add(USER_STACK_SIZE)
            .saturating_add(USER_HEAP_GAP);
        self.heap_start = heap_start;
        self.brk = heap_start;
        self.mmap_next = DEFAULT_MMAP_BASE;
        self.clear_mlock_state();
    }

    pub fn heap_start(&self) -> usize {
        self.heap_start
    }

    pub fn brk(&self) -> usize {
        self.brk
    }

    pub fn set_brk(&mut self, brk: usize) {
        self.brk = brk;
    }

    pub fn heap_size(&self) -> usize {
        self.brk.saturating_sub(self.heap_start)
    }

    pub fn mmap_next(&self) -> usize {
        self.mmap_next
    }

    pub fn note_mmap_end(&mut self, end: usize) {
        if end > self.mmap_next {
            self.mmap_next = end;
        }
    }

    pub fn mlockall_future(&self) -> bool {
        self.mlockall_future
    }

    pub fn set_mlockall_future(&mut self, enabled: bool) {
        self.mlockall_future = enabled;
    }

    pub fn locked_bytes(&self) -> usize {
        ranges_total_len(&self.mlocked_ranges)
    }

    pub fn locked_overlap_bytes(&self, start: usize, end: usize) -> usize {
        self.mlocked_ranges
            .iter()
            .map(|(lock_start, lock_end)| range_overlap_len(start, end, *lock_start, *lock_end))
            .sum()
    }

    pub fn locked_ranges_overlap(&self, start: usize, end: usize) -> bool {
        ranges_overlap(&self.mlocked_ranges, start, end)
    }

    pub fn locked_bytes_after_add(&self, start: usize, end: usize) -> usize {
        let mut next = self.mlocked_ranges.clone();
        next.push((start, end));
        normalize_ranges(&mut next);
        ranges_total_len(&next)
    }

    pub fn add_locked_range(&mut self, start: usize, end: usize) {
        self.mlocked_ranges.push((start, end));
        normalize_ranges(&mut self.mlocked_ranges);
    }

    pub fn trim_locked_ranges(&mut self, start: usize, end: usize) {
        trim_ranges(&mut self.mlocked_ranges, start, end);
    }

    pub fn move_locked_ranges(&mut self, old_addr: usize, old_len: usize, new_start: usize) {
        let old_end = old_addr.saturating_add(old_len);
        if old_end <= old_addr {
            return;
        }
        let mut next = Vec::new();
        for (lock_start, lock_end) in self.mlocked_ranges.drain(..) {
            if old_end <= lock_start || old_addr >= lock_end {
                next.push((lock_start, lock_end));
                continue;
            }
            if old_addr > lock_start {
                next.push((lock_start, old_addr));
            }
            let overlap_start = core::cmp::max(lock_start, old_addr);
            let overlap_end = core::cmp::min(lock_end, old_end);
            let moved_start = new_start.saturating_add(overlap_start.saturating_sub(old_addr));
            let moved_end = new_start.saturating_add(overlap_end.saturating_sub(old_addr));
            next.push((moved_start, moved_end));
            if old_end < lock_end {
                next.push((old_end, lock_end));
            }
        }
        normalize_ranges(&mut next);
        self.mlocked_ranges = next;
    }

    fn locked_ranges_with_current_mappings(&self) -> Vec<(usize, usize)> {
        let mut next = self.mlocked_ranges.clone();
        for (start, end) in self.user_mapped_ranges() {
            next.push((start, end));
        }
        if next.is_empty() {
            next.push((self.heap_start, self.heap_start.saturating_add(PAGE_SIZE)));
        }
        normalize_ranges(&mut next);
        next
    }

    pub fn locked_bytes_after_mlockall_current(&self) -> usize {
        let next = self.locked_ranges_with_current_mappings();
        ranges_total_len(&next)
    }

    pub fn lock_current_mappings(&mut self) {
        self.mlocked_ranges = self.locked_ranges_with_current_mappings();
    }

    pub fn clear_mlock_state(&mut self) {
        self.mlocked_ranges.clear();
        self.mlockall_future = false;
    }

    pub fn vm_regions_snapshot(&self) -> Vec<VmRegion> {
        self.vm_regions.clone()
    }

    pub fn vm_regions_total_len(&self) -> usize {
        self.vm_regions.iter().map(|region| region.len).sum()
    }

    pub fn anon_private_writable_vm_bytes(&self) -> usize {
        self.vm_regions.iter().fold(0usize, |sum, region| {
            if !region.shared
                && !region.file_backed
                && region.map_permission().contains(MapPermission::W)
            {
                sum.saturating_add(region.len)
            } else {
                sum
            }
        })
    }

    pub fn vm_regions_overlap(&self, start: usize, end: usize) -> bool {
        self.vm_regions.iter().any(|region| {
            let r_end = region.end();
            end > region.start && start < r_end
        })
    }

    pub fn shared_vm_region_overlaps(&self, start: usize, end: usize) -> bool {
        self.vm_regions
            .iter()
            .any(|region| end > region.start && start < region.end() && region.shared)
    }

    pub fn shared_file_vm_regions_overlapping(&self, start: usize, end: usize) -> Vec<VmRegion> {
        self.vm_regions
            .iter()
            .copied()
            .filter(|region| {
                region.shared && region.file_backed && end > region.start && start < region.end()
            })
            .collect()
    }

    pub fn has_writable_shared_memfd_mapping(&self, memfd_id: u64) -> bool {
        self.vm_regions.iter().any(|region| {
            region.memfd_id == memfd_id
                && region.shared
                && region.map_permission().contains(MapPermission::W)
        })
    }

    pub fn file_vm_copy_targets(
        &self,
        dev: usize,
        ino: u32,
        write_off: usize,
        len: usize,
    ) -> Vec<(usize, usize, usize)> {
        let write_end = write_off.saturating_add(len);
        let mut pending = Vec::new();
        for region in self.vm_regions.iter() {
            if !region.file_backed || region.file_dev != dev || region.file_ino != ino {
                continue;
            }
            let Some(region_file_end) = region.file_offset.checked_add(region.len) else {
                continue;
            };
            let overlap_start = core::cmp::max(write_off, region.file_offset);
            let mut overlap_end = core::cmp::min(write_end, region_file_end);
            let region_valid_len = region.file_valid_len.min(region.len);
            let region_valid_end = region.file_offset.saturating_add(region_valid_len);
            overlap_end = core::cmp::min(overlap_end, region_valid_end);
            if overlap_end <= overlap_start {
                continue;
            }
            pending.push((
                region.start + (overlap_start - region.file_offset),
                overlap_start - write_off,
                overlap_end - overlap_start,
            ));
        }
        pending
    }

    pub fn mmap_backing_file(&self, backing_id: usize) -> Option<Arc<dyn File + Send + Sync>> {
        self.mmap_backings.get(&backing_id).cloned()
    }

    pub fn allocate_mmap_backing(&mut self, file: Option<&Arc<dyn File + Send + Sync>>) -> usize {
        let Some(file) = file else {
            return 0;
        };
        let id = self.next_mmap_backing_id;
        self.next_mmap_backing_id = self.next_mmap_backing_id.saturating_add(1);
        self.mmap_backings.insert(id, Arc::clone(file));
        id
    }

    pub fn push_vm_region(&mut self, region: VmRegion) {
        push_vm_region_merged(&mut self.vm_regions, region);
        self.normalize_vm_regions();
        self.debug_assert_user_vm_invariants();
    }

    pub fn trim_vm_regions(&mut self, start: usize, end: usize) {
        let mut next = Vec::new();
        for region in self.vm_regions.drain(..) {
            let r_end = region.end();
            if end <= region.start || start >= r_end {
                push_vm_region_merged(&mut next, region);
                continue;
            }
            if start > region.start {
                push_vm_region_merged(
                    &mut next,
                    slice_vm_region(region, region.start, start - region.start),
                );
            }
            if end < r_end {
                push_vm_region_merged(&mut next, slice_vm_region(region, end, r_end - end));
            }
        }
        self.vm_regions = next;
        self.normalize_vm_regions();
        self.debug_assert_user_vm_invariants();
    }

    pub fn apply_mprotect_to_vm_regions(
        &mut self,
        start: usize,
        end: usize,
        new_prot: usize,
    ) -> Result<(), ()> {
        let mut next = Vec::new();
        for region in self.vm_regions.iter().copied() {
            let r_end = region.end();
            if end <= region.start || start >= r_end {
                push_vm_region_merged(&mut next, region);
                continue;
            }
            if start > region.start {
                push_vm_region_merged(
                    &mut next,
                    slice_vm_region(region, region.start, start - region.start),
                );
            }
            let ov_start = core::cmp::max(start, region.start);
            let ov_end = core::cmp::min(end, r_end);
            let mut mid = slice_vm_region(region, ov_start, ov_end - ov_start);
            if VmRegion::permission_from_prot(new_prot).contains(MapPermission::W)
                && !mid.map_permission().contains(MapPermission::W)
                && !mid.may_write_upgrade
            {
                return Err(());
            }
            mid.set_prot(new_prot);
            push_vm_region_merged(&mut next, mid);
            if end < r_end {
                push_vm_region_merged(&mut next, slice_vm_region(region, end, r_end - end));
            }
        }
        self.vm_regions = next;
        self.normalize_vm_regions();
        self.debug_assert_user_vm_invariants();
        Ok(())
    }

    pub fn can_mprotect_vm_regions(&self, start: usize, end: usize, new_prot: usize) -> bool {
        let asks_write = VmRegion::permission_from_prot(new_prot).contains(MapPermission::W);

        self.vm_regions.iter().all(|region| {
            let r_end = region.end();
            if end <= region.start || start >= r_end {
                return true;
            }
            !asks_write
                || region.map_permission().contains(MapPermission::W)
                || region.may_write_upgrade
        })
    }

    pub fn move_vm_region_metadata(&mut self, old_addr: usize, old_len: usize, new_start: usize) {
        let old_end = old_addr.saturating_add(old_len);
        let mut next = Vec::new();
        for region in self.vm_regions.drain(..) {
            let r_end = region.end();
            if old_end <= region.start || old_addr >= r_end {
                push_vm_region_merged(&mut next, region);
                continue;
            }
            if old_addr > region.start {
                push_vm_region_merged(
                    &mut next,
                    slice_vm_region(region, region.start, old_addr - region.start),
                );
            }
            let moved = move_vm_region(slice_vm_region(region, old_addr, old_len), new_start);
            push_vm_region_merged(&mut next, moved);
            if old_end < r_end {
                push_vm_region_merged(&mut next, slice_vm_region(region, old_end, r_end - old_end));
            }
        }
        self.vm_regions = next;
        self.normalize_vm_regions();
        self.debug_assert_user_vm_invariants();
    }

    pub fn set_vm_region_len_by_start(&mut self, start: usize, len: usize) -> bool {
        if let Some(region) = self
            .vm_regions
            .iter_mut()
            .find(|region| region.start == start)
        {
            if !region.file_backed || region.file_valid_len == region.len {
                region.file_valid_len = len;
            } else {
                region.file_valid_len = region.file_valid_len.min(len);
            }
            region.len = len;
            self.normalize_vm_regions();
            self.debug_assert_user_vm_invariants();
            true
        } else {
            false
        }
    }

    pub fn vm_region_containing(&self, start: usize, end: usize) -> Option<VmRegion> {
        self.vm_regions
            .iter()
            .copied()
            .find(|region| start >= region.start && end <= region.end())
    }

    pub fn occupied_user_ranges_with_metadata(&self) -> Vec<(usize, usize)> {
        let mut ranges = self.user_mapped_ranges();
        ranges.extend(self.vm_regions.iter().filter_map(|region| {
            let end = region.end();
            (end > region.start).then_some((region.start, end))
        }));
        normalize_ranges(&mut ranges);
        ranges
    }

    pub fn page_overlaps_vm_region(&self, page_start: usize) -> bool {
        let page_end = page_start.saturating_add(PAGE_SIZE);
        self.vm_regions
            .iter()
            .any(|region| page_end > region.start && page_start < region.end())
    }

    pub fn page_overlaps_vm_region_started_before(&self, page_start: usize, limit: usize) -> bool {
        let page_end = page_start.saturating_add(PAGE_SIZE);
        self.vm_regions.iter().any(|region| {
            region.start < limit && page_end > region.start && page_start < region.end()
        })
    }

    #[allow(dead_code)]
    pub fn fault_hits_mmap_sigbus_tail(&self, addr: usize) -> bool {
        self.vm_regions.iter().any(|region| {
            addr >= region.start && addr < region.end() && addr >= region.sigbus_start
        })
    }

    #[allow(dead_code)]
    pub fn try_expand_growsdown(
        &mut self,
        fault_va: usize,
        access: MapPermission,
    ) -> LazyFaultResult {
        let fault_page = fault_va & !(PAGE_SIZE - 1);

        for idx in 0..self.vm_regions.len() {
            let region = self.vm_regions[idx];
            if !region.growsdown {
                continue;
            }
            let Some(expected) = region.start.checked_sub(PAGE_SIZE) else {
                continue;
            };
            if fault_page != expected {
                continue;
            }

            let perm = region.map_permission();
            if !perm.contains(access) {
                return LazyFaultResult::Invalid;
            }
            if self.range_overlaps(fault_page.into(), region.start.into()) {
                return LazyFaultResult::Invalid;
            }
            // Keep one-page guard below the expanded stack segment.
            let Some(next_guard_start) = fault_page.checked_sub(PAGE_SIZE) else {
                return LazyFaultResult::Invalid;
            };
            if self.range_overlaps(next_guard_start.into(), fault_page.into()) {
                return LazyFaultResult::Invalid;
            }
            if !self.try_insert_lazy_area(fault_page.into(), region.start.into(), perm) {
                return LazyFaultResult::Invalid;
            }

            let grown = region.start - fault_page;
            self.vm_regions[idx].start = fault_page;
            self.vm_regions[idx].len += grown;
            self.normalize_vm_regions();
            self.debug_assert_user_vm_invariants();
            return self.resolve_lazy_fault(fault_va, access);
        }
        LazyFaultResult::Invalid
    }

    /// Lightweight summary used to diagnose fork/COW memory pressure.
    pub fn cow_diag_stats(&self) -> (usize, usize, usize, usize, usize, usize) {
        let mut total_data_frames = 0usize;
        let mut identical_vpns = 0usize;
        let mut lazy_areas = 0usize;
        let mut framed_areas = 0usize;
        let mut identical_areas = 0usize;
        for area in self.areas.iter() {
            total_data_frames = total_data_frames.saturating_add(area.data_frames.len());
            match area.map_type {
                MapType::Lazy => lazy_areas = lazy_areas.saturating_add(1),
                MapType::Framed => framed_areas = framed_areas.saturating_add(1),
                MapType::Identical => {
                    identical_areas = identical_areas.saturating_add(1);
                    let start = area.vpn_range.get_start().0;
                    let end = area.vpn_range.get_end().0;
                    identical_vpns = identical_vpns.saturating_add(end.saturating_sub(start));
                }
            }
        }
        (
            self.areas.len(),
            total_data_frames,
            identical_vpns,
            lazy_areas,
            framed_areas,
            identical_areas,
        )
    }
    /// Assume that no conflicts.
    #[allow(dead_code)]
    pub fn insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) {
        assert!(
            self.try_insert_framed_area(start_va, end_va, permission),
            "OOM: insert_framed_area({:?}..{:?})",
            start_va,
            end_va
        );
    }

    /// Try to insert a framed (allocated) area; returns `false` on OOM.
    pub fn try_insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        self.try_push(
            MapArea::new(start_va, end_va, MapType::Framed, permission),
            None,
        )
    }

    /// Try to insert a lazily-allocated (on-demand) anonymous area.
    pub fn try_insert_lazy_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return true;
        }
        // Refuse to insert over an existing VMA. brk()/mmap() already pre-scan
        // for free space, but this is the last-resort guard that stops a racing
        // or mis-computed range from silently overlapping a live mapping.
        if self.range_overlaps(start_va, end_va) {
            return false;
        }

        // Linux merges adjacent anonymous VMAs with identical attributes.
        // Keep this independent of Vec ordering so brk-style growth can still
        // coalesce after the area list is normalized by address.
        if let Some(idx) = self.areas.iter().position(|area| {
            area.map_type == MapType::Lazy
                && area.map_perm == permission
                && area.vpn_range.get_end() == start_vpn
        }) {
            let appended = self.areas[idx].append_to(&mut self.page_table, end_vpn);
            if appended {
                self.sort_user_areas();
                self.debug_assert_user_vm_invariants();
            }
            return appended;
        }

        self.try_push(
            MapArea::new(start_va, end_va, MapType::Lazy, permission),
            None,
        )
    }

    /// Map an identical (VA=PA) range into the address space.
    #[allow(dead_code)]
    pub fn map_identical_range(
        &mut self,
        start: usize,
        end: usize,
        permission: MapPermission,
    ) -> bool {
        if end <= start {
            return true;
        }
        self.try_push(
            MapArea::new(start.into(), end.into(), MapType::Identical, permission),
            None,
        )
    }

    /// Map an identical (VA=PA) range, skipping pages already mapped.
    #[allow(dead_code)]
    pub fn map_identical_range_skip_mapped(
        &mut self,
        start: usize,
        end: usize,
        permission: MapPermission,
    ) {
        if end <= start {
            return;
        }
        let mut vpn = VirtAddr::from(start).floor();
        let end_vpn = VirtAddr::from(end).ceil();
        while vpn < end_vpn {
            let mapped = self
                .page_table
                .translate(vpn)
                .map(|pte| pte.is_valid())
                .unwrap_or(false);
            if !mapped {
                let ppn = PhysPageNum(vpn.0);
                self.page_table.map(vpn, ppn, PTEFlags::from(permission));
            }
            vpn.step();
        }
    }

    fn push(&mut self, map_area: MapArea, data: Option<&[u8]>) {
        assert!(self.try_push(map_area, data), "OOM: mapping area failed");
    }

    fn try_push(&mut self, mut map_area: MapArea, data: Option<&[u8]>) -> bool {
        // Common choke point for every area insertion: bail out instead of
        // mapping a range that overlaps an existing VMA, which would corrupt the
        // page table and the `areas` bookkeeping.
        let start_va = VirtAddr::from(map_area.vpn_range.get_start());
        let end_va = VirtAddr::from(map_area.vpn_range.get_end());
        if self.range_overlaps(start_va, end_va) {
            return false;
        }
        if !map_area.map(&mut self.page_table) {
            return false;
        }
        if let Some(data) = data {
            map_area.copy_data(&self.page_table, data);
        }
        self.areas.push(map_area);
        self.sort_user_areas();
        self.debug_assert_user_vm_invariants();
        true
    }

    /// Push an already-mapped `MapArea` into this address space (used by COW fork).
    fn push_mapped(&mut self, map_area: MapArea) {
        self.areas.push(map_area);
        self.sort_user_areas();
        self.debug_assert_user_vm_invariants();
    }
    /// Mention that trampoline is not collected by areas.
    fn map_trampoline(&mut self) {
        self.page_table.map(
            VirtAddr::from(TRAMPOLINE).into(),
            PhysAddr::from(strampoline as usize).into(),
            PTEFlags::from(MapPermission::R | MapPermission::X),
        );
    }

    fn map_sigreturn_trampoline_user(&mut self) {
        self.page_table.map(
            VirtAddr::from(SIGRETURN_TRAMPOLINE).into(),
            PhysAddr::from(strampoline as usize).into(),
            PTEFlags::from(MapPermission::R | MapPermission::X | MapPermission::U),
        );
    }
    /// Without kernel stacks.
    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();
        // map trampoline (kernel-only)
        memory_set.map_trampoline();
        // map kernel sections
        println!(".text [{:#x}, {:#x})", stext as usize, etext as usize);
        println!(".rodata [{:#x}, {:#x})", srodata as usize, erodata as usize);
        println!(".data [{:#x}, {:#x})", sdata as usize, edata as usize);
        println!(
            ".bss [{:#x}, {:#x})",
            sbss_with_stack as usize, ebss as usize
        );
        println!("mapping .text section");
        memory_set.push(
            MapArea::new(
                (stext as usize).into(),
                (etext as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::X,
            ),
            None,
        );
        println!("mapping .rodata section");
        memory_set.push(
            MapArea::new(
                (srodata as usize).into(),
                (erodata as usize).into(),
                MapType::Identical,
                MapPermission::R,
            ),
            None,
        );
        println!("mapping .data section");
        memory_set.push(
            MapArea::new(
                (sdata as usize).into(),
                (edata as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        println!("mapping .bss section");
        memory_set.push(
            MapArea::new(
                (sbss_with_stack as usize).into(),
                (ebss as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        #[cfg(target_arch = "loongarch64")]
        {
            // Map low physical memory below the kernel image so the frame allocator
            // can safely use it on LoongArch.
            memory_set.map_identical_range(
                crate::config::phys_mem_start(),
                stext as usize,
                MapPermission::R | MapPermission::W,
            );
        }
        println!("mapping physical memory");
        memory_set.push(
            MapArea::new(
                (ekernel as usize).into(),
                phys_mem_end().into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        println!("mapping memory-mapped registers");
        for pair in MMIO {
            memory_set.push(
                MapArea::new(
                    (*pair).0.into(),
                    ((*pair).0 + (*pair).1).into(),
                    MapType::Identical,
                    MapPermission::R | MapPermission::W | MapPermission::IO,
                ),
                None,
            );
        }
        #[cfg(target_arch = "loongarch64")]
        {
            let dtb_start = crate::config::DEVICE_TREE_ADDR;
            let dtb_end = dtb_start + crate::config::DEVICE_TREE_MAX_SIZE;
            memory_set.map_identical_range_skip_mapped(dtb_start, dtb_end, MapPermission::R);
        }
        memory_set
    }
    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp and entry poremove_areeint.
    /// 用户占 被设计为 程序地址 (虚拟地址) 的最高端.
    pub fn from_elf(elf_data: &[u8]) -> Result<(Self, usize, usize, ElfAux), isize> {
        let mut memory_set = Self::new_bare();
        // map trap trampoline (kernel-only) and sigreturn trampoline (user accessible)
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();
        // map program headers of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).map_err(|_| -8isize)?;
        let load_bias: usize = match elf.header.pt2.type_().as_type() {
            // Map ET_DYN (shared objects / PIE) at a non-zero base so that:
            // - the null page stays unmapped by default, and
            // - the dynamic loader (musl) can map an ET_EXEC main program at low VAs.
            xmas_elf::header::Type::SharedObject => 0x2000_0000,
            _ => 0,
        };
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        if magic != [0x7f, 0x45, 0x4c, 0x46] {
            return Err(-8);
        }
        let ph_count = elf_header.pt2.ph_count();
        let ph_entry_size = elf_header.pt2.ph_entry_size() as usize;
        let ph_offset = elf_header.pt2.ph_offset() as usize;
        let ph_table_size = ph_entry_size.saturating_mul(ph_count as usize);
        let mut phdr_vaddr: usize = 0;
        let mut max_end_vpn = VirtPageNum(0);
        for i in 0..ph_count {
            let ph = elf.program_header(i).map_err(|_| -8isize)?;
            // Prefer explicit PHDR segment when present.
            let ph_type = match ph.get_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if phdr_vaddr == 0 && ph_type == xmas_elf::program::Type::Phdr {
                phdr_vaddr = load_bias + ph.virtual_addr() as usize;
            }
            if ph_type == xmas_elf::program::Type::Load {
                let start_va: VirtAddr = (load_bias + ph.virtual_addr() as usize).into();
                let end_va: VirtAddr =
                    (load_bias + (ph.virtual_addr() + ph.mem_size()) as usize).into();
                let mut map_perm = MapPermission::U;
                let ph_flags = ph.flags();
                if ph_flags.is_read() {
                    map_perm |= MapPermission::R;
                }
                if ph_flags.is_write() {
                    map_perm |= MapPermission::W;
                }
                if ph_flags.is_execute() {
                    map_perm |= MapPermission::X;
                }
                let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
                let seg_end = map_area.vpn_range.get_end();
                if seg_end > max_end_vpn {
                    max_end_vpn = seg_end;
                }
                memory_set.push(
                    map_area,
                    Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                );

                // Best-effort: compute AT_PHDR virtual address if PHDR table bytes are in this LOAD.
                let seg_off = ph.offset() as usize;
                let seg_filesz = ph.file_size() as usize;
                if phdr_vaddr == 0
                    && ph_offset >= seg_off
                    && ph_offset.saturating_add(ph_table_size) <= seg_off.saturating_add(seg_filesz)
                {
                    phdr_vaddr = load_bias + ph.virtual_addr() as usize + (ph_offset - seg_off);
                }
            }
        }
        // map user stack with U flags
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        // guard page
        user_stack_bottom += PAGE_SIZE;
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        // use crate::println;
        // println!(
        //     "[DEBUG] from_elf mapping user stack: bottom={:#x}, top={:#x}",
        //     user_stack_bottom, user_stack_top
        // );

        memory_set.push(
            MapArea::new(
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        let heap_base = user_stack_top + USER_HEAP_GAP;
        // used in sbrk (lazy heap to avoid eager page allocation)
        memory_set.push(
            MapArea::new(
                heap_base.into(),
                heap_base.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        memory_set.reset_user_layout(user_stack_bottom);
        // map TrapContext
        memory_set.push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                SIGRETURN_TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        // Return user_stack_bottom as ustack_base for thread allocation
        // Each thread will calculate its stack as: ustack_base + tid * (PAGE_SIZE + USER_STACK_SIZE)
        Ok((
            memory_set,
            user_stack_bottom,
            load_bias + elf.header.pt2.entry_point() as usize,
            ElfAux {
                phdr: phdr_vaddr,
                phent: ph_entry_size,
                phnum: ph_count as usize,
            },
        ))
    }

    /// Build a user address space from an ELF reader to avoid loading the full file into memory.
    pub fn from_elf_reader<F>(mut read_at: F) -> Result<(Self, usize, usize, ElfAux), isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        let (hdr, phdrs) = parse_elf_headers(&mut read_at)?;
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();

        let load_bias = if hdr.e_type == ET_DYN { 0x2000_0000 } else { 0 };
        let mut max_end_vpn = VirtPageNum(0);
        let elf_aux = Self::map_elf_segments_from_reader(
            &mut memory_set,
            &mut read_at,
            &hdr,
            &phdrs,
            load_bias,
            &mut max_end_vpn,
        )?;

        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        user_stack_bottom += PAGE_SIZE;
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        if !memory_set.try_push(
            MapArea::new(
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        ) {
            return Err(ENOMEM);
        }
        let heap_base = user_stack_top + USER_HEAP_GAP;
        if !memory_set.try_push(
            MapArea::new(
                heap_base.into(),
                heap_base.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        ) {
            return Err(ENOMEM);
        }
        memory_set.reset_user_layout(user_stack_bottom);
        if !memory_set.try_push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                SIGRETURN_TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        ) {
            return Err(ENOMEM);
        }

        Ok((
            memory_set,
            user_stack_bottom,
            load_bias + hdr.e_entry as usize,
            elf_aux,
        ))
    }

    fn map_elf_segments_into(
        memory_set: &mut MemorySet,
        elf_data: &[u8],
        load_bias: usize,
        max_end_vpn: &mut VirtPageNum,
    ) -> Result<(usize, ElfAux), isize> {
        let elf = xmas_elf::ElfFile::new(elf_data).map_err(|_| -8isize)?;
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        if magic != [0x7f, 0x45, 0x4c, 0x46] {
            return Err(-8);
        }
        let ph_count = elf_header.pt2.ph_count();
        let ph_entry_size = elf_header.pt2.ph_entry_size() as usize;
        let ph_offset = elf_header.pt2.ph_offset() as usize;
        let ph_table_size = ph_entry_size.saturating_mul(ph_count as usize);

        let mut phdr_vaddr: usize = 0;
        for i in 0..ph_count {
            let ph = elf.program_header(i).map_err(|_| -8isize)?;
            let ph_type = match ph.get_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if phdr_vaddr == 0 && ph_type == xmas_elf::program::Type::Phdr {
                phdr_vaddr = load_bias + ph.virtual_addr() as usize;
            }
            if ph_type != xmas_elf::program::Type::Load {
                continue;
            }
            let start_va: VirtAddr = (load_bias + ph.virtual_addr() as usize).into();
            let end_va: VirtAddr =
                (load_bias + (ph.virtual_addr() + ph.mem_size()) as usize).into();
            let mut map_perm = MapPermission::U;
            let ph_flags = ph.flags();
            if ph_flags.is_read() {
                map_perm |= MapPermission::R;
            }
            if ph_flags.is_write() {
                map_perm |= MapPermission::W;
            }
            if ph_flags.is_execute() {
                map_perm |= MapPermission::X;
            }
            let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
            let seg_end = map_area.vpn_range.get_end();
            if seg_end > *max_end_vpn {
                *max_end_vpn = seg_end;
            }
            memory_set.push(
                map_area,
                Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
            );

            // Best-effort: compute AT_PHDR virtual address if PHDR table bytes are in this LOAD.
            let seg_off = ph.offset() as usize;
            let seg_filesz = ph.file_size() as usize;
            if phdr_vaddr == 0
                && ph_offset >= seg_off
                && ph_offset.saturating_add(ph_table_size) <= seg_off.saturating_add(seg_filesz)
            {
                phdr_vaddr = load_bias + ph.virtual_addr() as usize + (ph_offset - seg_off);
            }
        }

        Ok((
            load_bias + elf.header.pt2.entry_point() as usize,
            ElfAux {
                phdr: phdr_vaddr,
                phent: ph_entry_size,
                phnum: ph_count as usize,
            },
        ))
    }

    fn map_elf_segments_from_reader<F>(
        memory_set: &mut MemorySet,
        read_at: &mut F,
        hdr: &ElfHeader64,
        phdrs: &[ElfPhdr64],
        load_bias: usize,
        max_end_vpn: &mut VirtPageNum,
    ) -> Result<ElfAux, isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        let ph_entry_size = hdr.e_phentsize as usize;
        let ph_count = hdr.e_phnum as usize;
        let ph_offset = hdr.e_phoff as usize;
        let ph_table_size = ph_entry_size.saturating_mul(ph_count);

        let mut phdr_vaddr: usize = 0;
        for ph in phdrs {
            if ph.p_type == PT_PHDR && phdr_vaddr == 0 {
                phdr_vaddr = load_bias + ph.p_vaddr as usize;
            }
            if ph.p_type != PT_LOAD {
                continue;
            }
            let start_va: VirtAddr = (load_bias + ph.p_vaddr as usize).into();
            let end_va: VirtAddr = (load_bias + (ph.p_vaddr + ph.p_memsz) as usize).into();
            let mut map_perm = MapPermission::U;
            if (ph.p_flags & PF_R) != 0 {
                map_perm |= MapPermission::R;
            }
            if (ph.p_flags & PF_W) != 0 {
                map_perm |= MapPermission::W;
            }
            if (ph.p_flags & PF_X) != 0 {
                map_perm |= MapPermission::X;
            }
            let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
            let seg_end = map_area.vpn_range.get_end();
            if seg_end > *max_end_vpn {
                *max_end_vpn = seg_end;
            }
            if !memory_set.try_push(map_area, None) {
                return Err(ENOMEM);
            }

            // Populate segment data from the file.
            let file_size = ph.p_filesz as usize;
            if file_size > 0 {
                let token = memory_set.token();
                let mut offset = 0usize;
                let mut tmp = [0u8; PAGE_SIZE];
                while offset < file_size {
                    let to_read = core::cmp::min(PAGE_SIZE, file_size - offset);
                    read_exact_with(read_at, ph.p_offset as usize + offset, &mut tmp[..to_read])?;
                    if try_copy_to_user_unchecked(
                        token,
                        (load_bias + ph.p_vaddr as usize + offset) as *mut u8,
                        &tmp[..to_read],
                    )
                    .is_err()
                    {
                        return Err(ENOMEM);
                    }
                    offset += to_read;
                }
            }

            // Best-effort: compute AT_PHDR when PHDR table bytes live in this segment.
            if phdr_vaddr == 0 {
                let seg_off = ph.p_offset as usize;
                let seg_filesz = ph.p_filesz as usize;
                if ph_offset >= seg_off
                    && ph_offset.saturating_add(ph_table_size) <= seg_off.saturating_add(seg_filesz)
                {
                    phdr_vaddr = load_bias + ph.p_vaddr as usize + (ph_offset - seg_off);
                }
            }
        }

        Ok(ElfAux {
            phdr: phdr_vaddr,
            phent: ph_entry_size,
            phnum: ph_count,
        })
    }

    /// Map a dynamically-linked main ELF together with its interpreter (PT_INTERP) in
    /// a single address space, and return both entry points.
    pub fn from_elf_with_interp(
        main_elf: &[u8],
        interp_elf: &[u8],
    ) -> Result<(Self, usize, usize, usize, ElfAux, usize), isize> {
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();

        let main = xmas_elf::ElfFile::new(main_elf).map_err(|_| -8isize)?;
        let _interp = xmas_elf::ElfFile::new(interp_elf).map_err(|_| -8isize)?;

        // Place PIE/shared objects away from zero so the null page stays unmapped.
        let main_bias = match main.header.pt2.type_().as_type() {
            xmas_elf::header::Type::SharedObject => 0x2000_0000,
            _ => 0,
        };
        // Keep the interpreter at a different base to avoid overlap with the main program.
        // For LoongArch, keep it under 2GiB so brk stays in 32-bit range for oscomp musl tests.
        #[cfg(target_arch = "loongarch64")]
        let interp_bias = 0x4000_0000;
        // Match exampleOS layout: put the interpreter high (but still within Sv39 user range)
        // to reduce collisions with the main program/heap/mmap allocations.
        #[cfg(not(target_arch = "loongarch64"))]
        let interp_bias = 0x30_0000_0000;

        let mut max_end_vpn = VirtPageNum(0);
        let (main_entry, main_aux) =
            Self::map_elf_segments_into(&mut memory_set, main_elf, main_bias, &mut max_end_vpn)?;
        let (interp_entry, _interp_aux) = Self::map_elf_segments_into(
            &mut memory_set,
            interp_elf,
            interp_bias,
            &mut max_end_vpn,
        )?;

        // Map user stack with U flags, placed above all mapped ELF segments.
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        // guard page
        user_stack_bottom += PAGE_SIZE;
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        memory_set.push(
            MapArea::new(
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        let heap_base = user_stack_top + USER_HEAP_GAP;
        // used in sbrk (lazy heap to avoid eager page allocation)
        memory_set.push(
            MapArea::new(
                heap_base.into(),
                heap_base.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        memory_set.reset_user_layout(user_stack_bottom);
        // map TrapContext
        memory_set.push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                SIGRETURN_TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );

        Ok((
            memory_set,
            user_stack_bottom,
            interp_entry,
            main_entry,
            main_aux,
            interp_bias,
        ))
    }

    /// Build a user address space from a main ELF reader and an in-memory interpreter.
    pub fn from_elf_with_interp_reader<F>(
        mut read_at: F,
        interp_elf: &[u8],
    ) -> Result<(Self, usize, usize, usize, ElfAux, usize), isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        let (hdr, phdrs) = parse_elf_headers(&mut read_at)?;
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();

        let main_bias = if hdr.e_type == ET_DYN { 0x2000_0000 } else { 0 };
        #[cfg(target_arch = "loongarch64")]
        let interp_bias = 0x4000_0000;
        #[cfg(not(target_arch = "loongarch64"))]
        let interp_bias = 0x30_0000_0000;

        let mut max_end_vpn = VirtPageNum(0);
        let main_aux = Self::map_elf_segments_from_reader(
            &mut memory_set,
            &mut read_at,
            &hdr,
            &phdrs,
            main_bias,
            &mut max_end_vpn,
        )?;
        let (interp_entry, _interp_aux) = Self::map_elf_segments_into(
            &mut memory_set,
            interp_elf,
            interp_bias,
            &mut max_end_vpn,
        )?;

        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        user_stack_bottom += PAGE_SIZE;
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        if !memory_set.try_push(
            MapArea::new(
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        ) {
            return Err(ENOMEM);
        }
        let heap_base = user_stack_top + USER_HEAP_GAP;
        if !memory_set.try_push(
            MapArea::new(
                heap_base.into(),
                heap_base.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        ) {
            return Err(ENOMEM);
        }
        memory_set.reset_user_layout(user_stack_bottom);
        if !memory_set.try_push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                SIGRETURN_TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        ) {
            return Err(ENOMEM);
        }

        Ok((
            memory_set,
            user_stack_bottom,
            interp_entry,
            main_bias + hdr.e_entry as usize,
            main_aux,
            interp_bias,
        ))
    }
    /// Fork a user address space using copy-on-write for user pages.
    ///
    /// - User pages (PTE.U) that were writable are remapped read-only and tagged with `PTEFlags::COW`
    ///   in both parent and child.
    /// - Kernel-only pages (e.g., TrapContext, no PTE.U) are copied eagerly.
    pub fn from_existed_user_cow(user_space: &mut MemorySet) -> MemorySet {
        let diag_enabled = crate::debug_config::DEBUG_FUTEX;
        let start_cycles = if diag_enabled {
            crate::arch::read_time()
        } else {
            0
        };
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();

        let mut parent_update_count = 0usize;
        let mut src_walk_cache = PageWalkCache::new();
        let mut dst_walk_cache = PageWalkCache::new();
        let mut area_count = 0usize;
        let mut identical_pages = 0usize;
        let mut shared_pages = 0usize;
        let mut kernel_private_pages = 0usize;

        for area in user_space.areas.iter() {
            area_count = area_count.saturating_add(1);
            src_walk_cache.reset();
            dst_walk_cache.reset();
            let mut new_area = MapArea::from_another(area);

            match area.map_type {
                MapType::Identical => {
                    for vpn in area.vpn_range {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        identical_pages = identical_pages.saturating_add(1);
                        let src_ppn = src_pte.ppn();
                        let src_flags = src_pte.flags();
                        memory_set.page_table.map_cached(
                            vpn,
                            src_ppn,
                            src_flags,
                            &mut dst_walk_cache,
                        );
                    }
                }
                // For Framed/Lazy areas we only walk materialized pages.
                // This avoids O(vma_len) scans for huge untouched lazy mappings.
                MapType::Framed | MapType::Lazy => {
                    for (&vpn, frame_tracker) in area.data_frames.iter() {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let mut src_flags = src_pte.flags();

                        // Kernel-only pages must not be shared (e.g., TrapContext is per-thread).
                        if !src_flags.contains(PTEFlags::U) {
                            let Some(frame) = frame_alloc() else {
                                continue;
                            };
                            frame
                                .ppn
                                .get_bytes_array()
                                .copy_from_slice(src_ppn.get_bytes_array());
                            memory_set.page_table.map_cached(
                                vpn,
                                frame.ppn,
                                src_flags,
                                &mut dst_walk_cache,
                            );
                            new_area.data_frames.insert(vpn, frame);
                            kernel_private_pages = kernel_private_pages.saturating_add(1);
                            continue;
                        }

                        // Share the physical page.
                        shared_pages = shared_pages.saturating_add(1);
                        let writable =
                            src_flags.contains(PTEFlags::W) || src_flags.contains(PTEFlags::D);
                        if writable && !src_flags.contains(PTEFlags::SHARED) {
                            src_flags.remove(PTEFlags::W);
                            src_flags.remove(PTEFlags::D);
                            src_flags.insert(PTEFlags::COW);
                            // Apply parent PTE demotion immediately to minimize the window where
                            // another thread could write through a still-writable PTE on another hart.
                            user_space.page_table.set_flags(vpn, src_flags);
                            parent_update_count = parent_update_count.saturating_add(1);
                        }
                        memory_set.page_table.map_cached(
                            vpn,
                            src_ppn,
                            src_flags,
                            &mut dst_walk_cache,
                        );
                        new_area.data_frames.insert(vpn, frame_tracker.clone());
                    }
                }
            }

            memory_set.push_mapped(new_area);
        }

        let before_parent_update_cycles = if diag_enabled {
            crate::arch::read_time()
        } else {
            0
        };
        if parent_update_count != 0 {
            // SAFETY: after fork demotes parent PTEs from writable to read-only+COW,
            // every hart running the parent must drop stale writable TLB entries
            // before it can resume, or it may keep writing shared pages behind COW.
            #[cfg(target_arch = "riscv64")]
            {
                let remote_hart_mask =
                    crate::task::manager::online_hart_mask() & !(1usize << crate::arch::hart_id());
                unsafe {
                    asm!("sfence.vma");
                }
                if remote_hart_mask != 0 {
                    crate::sbi::remote_sfence_vma_all(remote_hart_mask);
                }
            }
            // SAFETY: LoongArch64 currently runs single-core only (no SMP boot),
            // so a local full TLB flush is sufficient. When SMP is added, a
            // remote TLB shootdown (IPI + invtlb on each hart) will be needed.
            #[cfg(target_arch = "loongarch64")]
            unsafe {
                asm!("invtlb 0x1, $r0, $r0");
            }
        }
        if diag_enabled {
            let end_cycles = crate::arch::read_time();
            let to_us = |delta_cycles: usize| -> usize {
                let freq = crate::config::clock_freq() as u128;
                if freq == 0 {
                    0
                } else {
                    ((delta_cycles as u128).saturating_mul(1_000_000) / freq) as usize
                }
            };
            let total_us = to_us(end_cycles.wrapping_sub(start_cycles));
            let seq = COW_CLONE_DIAG_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
            if seq <= 16 || seq % 128 == 0 || total_us >= 30_000 {
                let walk_us = to_us(before_parent_update_cycles.wrapping_sub(start_cycles));
                let update_us = to_us(end_cycles.wrapping_sub(before_parent_update_cycles));
                log::warn!(
                    "[cow_clone_diag] seq={} total_us={} walk_us={} parent_update_us={} areas={} ident_pages={} shared_pages={} kernel_copy_pages={} cow_marked={} parent_updates={}",
                    seq,
                    total_us,
                    walk_us,
                    update_us,
                    area_count,
                    identical_pages,
                    shared_pages,
                    kernel_private_pages,
                    parent_update_count,
                    parent_update_count
                );
            }
        }

        memory_set.inherit_user_vm_metadata_from(user_space);
        memory_set
    }

    /// Fork a user address space by sharing mapped user frames.
    ///
    /// This is used for Linux `clone(..., CLONE_VM, ...)`-style semantics:
    /// parent and child keep separate page tables but map the same user
    /// physical frames with the same permissions.
    pub fn from_existed_user_shared(user_space: &MemorySet) -> MemorySet {
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();
        let mut src_walk_cache = PageWalkCache::new();
        let mut dst_walk_cache = PageWalkCache::new();

        for area in user_space.areas.iter() {
            src_walk_cache.reset();
            dst_walk_cache.reset();
            let mut new_area = MapArea::from_another(area);

            match area.map_type {
                MapType::Identical => {
                    for vpn in area.vpn_range {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        memory_set.page_table.map_cached(
                            vpn,
                            src_pte.ppn(),
                            src_pte.flags(),
                            &mut dst_walk_cache,
                        );
                    }
                }
                // Share only materialized pages for Framed/Lazy areas.
                MapType::Framed | MapType::Lazy => {
                    for (&vpn, frame_tracker) in area.data_frames.iter() {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let src_flags = src_pte.flags();

                        // Keep kernel-only mappings private.
                        if !src_flags.contains(PTEFlags::U) {
                            let Some(frame) = frame_alloc() else {
                                continue;
                            };
                            frame
                                .ppn
                                .get_bytes_array()
                                .copy_from_slice(src_ppn.get_bytes_array());
                            memory_set.page_table.map_cached(
                                vpn,
                                frame.ppn,
                                src_flags,
                                &mut dst_walk_cache,
                            );
                            new_area.data_frames.insert(vpn, frame);
                            continue;
                        }

                        memory_set.page_table.map_cached(
                            vpn,
                            src_ppn,
                            src_flags,
                            &mut dst_walk_cache,
                        );
                        new_area.data_frames.insert(vpn, frame_tracker.clone());
                    }
                }
            }

            memory_set.push_mapped(new_area);
        }

        memory_set.inherit_user_vm_metadata_from(user_space);
        memory_set
    }

    /// Fork a user address space by copying all mapped pages (no COW).
    ///
    /// This is slower than COW but avoids COW corner cases on some platforms.
    #[allow(dead_code)]
    pub fn from_existed_user(user_space: &MemorySet) -> MemorySet {
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();
        let mut src_walk_cache = PageWalkCache::new();
        let mut dst_walk_cache = PageWalkCache::new();

        for area in user_space.areas.iter() {
            src_walk_cache.reset();
            dst_walk_cache.reset();
            let mut new_area = MapArea::from_another(area);

            match area.map_type {
                MapType::Identical => {
                    for vpn in area.vpn_range {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let src_flags = src_pte.flags();
                        memory_set.page_table.map_cached(
                            vpn,
                            src_ppn,
                            src_flags,
                            &mut dst_walk_cache,
                        );
                    }
                }
                // Lazy areas can span terabytes with no materialized pages.
                // Copy only present pages tracked in data_frames.
                MapType::Framed | MapType::Lazy => {
                    for (&vpn, _) in area.data_frames.iter() {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let Some(frame) = frame_alloc() else {
                            continue;
                        };
                        frame
                            .ppn
                            .get_bytes_array()
                            .copy_from_slice(src_ppn.get_bytes_array());
                        let pte_flags = PTEFlags::from(area.map_perm);
                        memory_set.page_table.map_cached(
                            vpn,
                            frame.ppn,
                            pte_flags,
                            &mut dst_walk_cache,
                        );
                        new_area.data_frames.insert(vpn, frame);
                    }
                }
            }

            memory_set.push_mapped(new_area);
        }

        memory_set.inherit_user_vm_metadata_from(user_space);
        memory_set
    }

    /// Insert a user-mapped framed area backed by the provided physical frames.
    ///
    /// Used by System V shared memory (`shmat`) to map the same physical pages
    /// into multiple processes.
    pub fn insert_shared_frames_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
        frames: Vec<FrameTracker>,
    ) {
        let mut area = MapArea::new(start_va, end_va, MapType::Framed, permission);
        let pte_flags = PTEFlags::from(area.map_perm) | PTEFlags::SHARED;
        for (vpn, frame) in area.vpn_range.into_iter().zip(frames.into_iter()) {
            self.page_table.map(vpn, frame.ppn, pte_flags);
            area.data_frames.insert(vpn, frame);
        }
        self.push_mapped(area);
    }

    /// Resolve a copy-on-write fault at `fault_va` if the page is tagged COW.
    pub fn resolve_cow_fault(&mut self, fault_va: usize) -> bool {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        let Some(pte) = self.translate(vpn) else {
            return false;
        };
        let flags = pte.flags();
        if !flags.contains(PTEFlags::COW) {
            return false;
        }
        let old_ppn = pte.ppn();
        let Some(frame) = frame_alloc() else {
            return false;
        };
        frame
            .ppn
            .get_bytes_array()
            .copy_from_slice(old_ppn.get_bytes_array());

        let mut new_flags = flags;
        new_flags.remove(PTEFlags::COW);
        new_flags.insert(PTEFlags::W);
        new_flags.insert(PTEFlags::D);
        if !self.page_table.remap(vpn, frame.ppn, new_flags) {
            return false;
        }

        // Update the owning MapArea's frame tracker so the old shared frame gets its refcount decremented.
        for area in self.areas.iter_mut() {
            if area.map_type == MapType::Identical {
                continue;
            }
            if vpn < area.vpn_range.get_start() || vpn >= area.vpn_range.get_end() {
                continue;
            }
            area.data_frames.insert(vpn, frame);
            break;
        }

        // Flush TLB for this address.
        #[cfg(target_arch = "riscv64")]
        // SAFETY: sfence.vma is valid in S-mode; fault_va is the address to flush from TLB.
        unsafe {
            core::arch::asm!("sfence.vma {0}, zero", in(reg) fault_va);
        }
        #[cfg(target_arch = "loongarch64")]
        // SAFETY: invtlb is valid in S-mode; fault_va is the address to flush from TLB.
        unsafe {
            core::arch::asm!("invtlb 0x4, $r0, {}", in(reg) fault_va);
        }
        true
    }

    /// Resolve a lazy anonymous mapping fault by allocating a page on demand.
    pub fn resolve_lazy_fault(
        &mut self,
        fault_va: usize,
        access: MapPermission,
    ) -> LazyFaultResult {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        for area in self.areas.iter_mut() {
            if area.map_type != MapType::Lazy {
                continue;
            }
            if vpn < area.vpn_range.get_start() || vpn >= area.vpn_range.get_end() {
                continue;
            }
            if !area.map_perm.contains(access) {
                return LazyFaultResult::Invalid;
            }
            if let Some(pte) = self.page_table.translate(vpn) {
                if pte.is_valid() {
                    return LazyFaultResult::Invalid;
                }
            }
            let total_pages = area
                .vpn_range
                .get_end()
                .0
                .saturating_sub(area.vpn_range.get_start().0);
            let accounted_pages = area.charged_pages.max(area.data_frames.len());
            let new_charge_pages = total_pages.saturating_sub(accounted_pages);
            let Some(frame) = frame_alloc() else {
                crate::println!("[mm] OOM: lazy fault alloc failed for vpn={:?}", vpn);
                return LazyFaultResult::Oom;
            };
            // Allocate before charging so OOM in frame_alloc() cannot leak cgroup accounting;
            // if charging fails, the uninstalled frame is dropped immediately.
            if new_charge_pages > 0
                && area.map_perm.contains(MapPermission::U)
                && area.map_perm.contains(MapPermission::W)
            {
                let charge_bytes = new_charge_pages.saturating_mul(crate::config::PAGE_SIZE);
                if !cgroup_charge_anon_current(current_process().getpid(), charge_bytes) {
                    return LazyFaultResult::Oom;
                }
                area.charged_pages = accounted_pages.saturating_add(new_charge_pages);
            }
            let pte_flags = PTEFlags::from(area.map_perm);
            self.page_table.map(vpn, frame.ppn, pte_flags);
            area.data_frames.insert(vpn, frame);
            #[cfg(target_arch = "riscv64")]
            // SAFETY: sfence.vma is valid in S-mode; fault_va is the address to flush from TLB.
            unsafe {
                core::arch::asm!("sfence.vma {0}, zero", in(reg) fault_va);
            }
            #[cfg(target_arch = "loongarch64")]
            // SAFETY: invtlb is valid in S-mode; fault_va is the address to flush from TLB.
            unsafe {
                core::arch::asm!("invtlb 0x4, $r0, {}", in(reg) fault_va);
            }
            return LazyFaultResult::Resolved;
        }
        LazyFaultResult::Invalid
    }
    pub fn activate(&self) {
        #[cfg(target_arch = "riscv64")]
        {
            let satp = self.page_table.token();
            // SAFETY: satp is a valid page table token; sfence.vma flushes TLB after satp change.
            unsafe {
                satp::write(Satp::from_bits(satp));
                asm!("sfence.vma");
            }
        }
        #[cfg(target_arch = "loongarch64")]
        {
            self.page_table.activate();
        }
    }
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.page_table.translate(vpn)
    }

    pub fn set_pte_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) -> bool {
        self.page_table.set_flags(vpn, flags)
    }
    #[allow(unused)]
    pub fn shrink_to(&mut self, start: VirtAddr, new_end: VirtAddr) -> bool {
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.vpn_range.get_start() == start.floor())
        {
            area.shrink_to(&mut self.page_table, new_end.ceil());
            self.sort_user_areas();
            self.debug_assert_user_vm_invariants();
            true
        } else {
            false
        }
    }
    #[allow(unused)]
    pub fn append_to(&mut self, start: VirtAddr, new_end: VirtAddr) -> bool {
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.vpn_range.get_start() == start.floor())
        {
            let appended = area.append_to(&mut self.page_table, new_end.ceil());
            if appended {
                self.sort_user_areas();
                self.debug_assert_user_vm_invariants();
            }
            appended
        } else {
            false
        }
    }

    pub fn remove_area(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        if let Some((idx, area)) = self.areas.iter_mut().enumerate().find(|(_idx, area)| {
            area.vpn_range.get_start() == start_va.floor()
                && area.vpn_range.get_end() == end_va.ceil()
        }) {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
            self.debug_assert_user_vm_invariants();
        };
    }

    pub fn move_user_range(
        &mut self,
        old_start_va: VirtAddr,
        old_end_va: VirtAddr,
        new_start_va: VirtAddr,
    ) -> bool {
        let old_start_vpn = old_start_va.floor();
        let old_end_vpn = old_end_va.ceil();
        let new_start_vpn = new_start_va.floor();
        if old_start_vpn >= old_end_vpn {
            return true;
        }
        let delta = new_start_vpn.0 as isize - old_start_vpn.0 as isize;
        let shifted_vpn = |vpn: VirtPageNum| -> Option<VirtPageNum> {
            let next = vpn.0 as isize + delta;
            (next >= 0).then_some(VirtPageNum(next as usize))
        };

        let mut moved_ptes: Vec<(VirtPageNum, PhysPageNum, PTEFlags)> = Vec::new();
        let mut moved_areas: Vec<MapArea> = Vec::new();
        let mut new_areas: Vec<MapArea> = Vec::new();
        let mut found = false;

        let mut areas = core::mem::take(&mut self.areas);
        for mut area in areas.drain(..) {
            if !area.map_perm.contains(MapPermission::U) {
                new_areas.push(area);
                continue;
            }

            let area_start = area.vpn_range.get_start();
            let area_end = area.vpn_range.get_end();
            if old_end_vpn <= area_start || old_start_vpn >= area_end {
                new_areas.push(area);
                continue;
            }

            found = true;
            let ov_start = core::cmp::max(old_start_vpn, area_start);
            let ov_end = core::cmp::min(old_end_vpn, area_end);

            for vpn in VPNRange::new(ov_start, ov_end) {
                if let Some(pte) = self.page_table.translate(vpn) {
                    if pte.is_valid() {
                        let Some(new_vpn) = shifted_vpn(vpn) else {
                            return false;
                        };
                        moved_ptes.push((new_vpn, pte.ppn(), pte.flags()));
                        self.page_table.unmap_if_mapped(vpn);
                    }
                }
            }

            let mut left_frames = BTreeMap::new();
            let mut mid_frames = BTreeMap::new();
            let mut right_frames = BTreeMap::new();
            if area.map_type != MapType::Identical {
                let mut remaining = core::mem::take(&mut area.data_frames);
                right_frames = remaining.split_off(&ov_end);
                mid_frames = remaining.split_off(&ov_start);
                left_frames = remaining;
            }

            if area_start < ov_start {
                let mut left = MapArea::from_another(&area);
                left.vpn_range = VPNRange::new(area_start, ov_start);
                left.data_frames = left_frames;
                new_areas.push(left);
            }

            let Some(new_mid_start) = shifted_vpn(ov_start) else {
                return false;
            };
            let Some(new_mid_end) = shifted_vpn(ov_end) else {
                return false;
            };
            let mut mid = MapArea::from_another(&area);
            mid.vpn_range = VPNRange::new(new_mid_start, new_mid_end);
            if ov_start != area_start {
                mid.start_offset = 0;
            }
            if area.map_type != MapType::Identical {
                let mut remapped = BTreeMap::new();
                for (vpn, frame) in mid_frames {
                    let Some(new_vpn) = shifted_vpn(vpn) else {
                        return false;
                    };
                    remapped.insert(new_vpn, frame);
                }
                mid.data_frames = remapped;
            }
            moved_areas.push(mid);

            if ov_end < area_end {
                let mut right = MapArea::from_another(&area);
                right.vpn_range = VPNRange::new(ov_end, area_end);
                right.start_offset = 0;
                right.data_frames = right_frames;
                new_areas.push(right);
            }
        }

        if !found {
            self.areas = new_areas;
            self.sort_user_areas();
            self.debug_assert_user_vm_invariants();
            return false;
        }

        self.areas = new_areas;
        for (vpn, ppn, flags) in moved_ptes {
            self.page_table.map(vpn, ppn, flags);
        }
        self.areas.extend(moved_areas);
        self.sort_user_areas();
        self.debug_assert_user_vm_invariants();
        true
    }

    /// Unmap (best-effort) any user-mapped pages in `[start_va, end_va)`.
    ///
    /// This is primarily used to implement Linux `mmap(MAP_FIXED)` semantics, which
    /// replace existing mappings in the target range.
    pub fn unmap_user_range(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return;
        }

        // Fast path: exact-area munmap (common in tight mmap/munmap loops).
        // Avoid rebuilding the whole area list when we can remove one area directly.
        if let Some(idx) = self.areas.iter().position(|area| {
            area.map_perm.contains(MapPermission::U)
                && area.vpn_range.get_start() == start_vpn
                && area.vpn_range.get_end() == end_vpn
        }) {
            let mut area = self.areas.remove(idx);
            area.unmap(&mut self.page_table);
            self.debug_assert_user_vm_invariants();
            return;
        }

        let mut new_areas: Vec<MapArea> = Vec::new();
        let mut areas = core::mem::take(&mut self.areas);
        for mut area in areas.drain(..) {
            if !area.map_perm.contains(MapPermission::U) {
                new_areas.push(area);
                continue;
            }

            let area_start = area.vpn_range.get_start();
            let area_end = area.vpn_range.get_end();
            if end_vpn <= area_start || start_vpn >= area_end {
                new_areas.push(area);
                continue;
            }

            let ov_start = core::cmp::max(start_vpn, area_start);
            let ov_end = core::cmp::min(end_vpn, area_end);

            for vpn in VPNRange::new(ov_start, ov_end) {
                area.unmap_one_maybe(&mut self.page_table, vpn);
            }

            let mut left_frames = BTreeMap::new();
            let mut right_frames = BTreeMap::new();
            if area.map_type != MapType::Identical {
                let mut remaining = core::mem::take(&mut area.data_frames);
                right_frames = remaining.split_off(&ov_end);
                let overlap = remaining.split_off(&ov_start);
                drop(overlap);
                left_frames = remaining;
            }

            if area_start < ov_start {
                let mut left = MapArea::from_another(&area);
                left.vpn_range = VPNRange::new(area_start, ov_start);
                left.data_frames = left_frames;
                new_areas.push(left);
            }
            if ov_end < area_end {
                let mut right = MapArea::from_another(&area);
                right.vpn_range = VPNRange::new(ov_end, area_end);
                right.start_offset = 0;
                right.data_frames = right_frames;
                new_areas.push(right);
            }
        }
        self.areas = new_areas;
        self.sort_user_areas();
        self.debug_assert_user_vm_invariants();
    }

    /// Update user mapping permissions in `[start_va, end_va)`.
    ///
    /// Returns `false` if any portion of the range is not mapped as a user area.
    pub fn mprotect_user_range(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        new_perm: MapPermission,
    ) -> bool {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return true;
        }

        // Ensure the range is fully covered by user areas.
        let mut cursor = start_vpn;
        while cursor < end_vpn {
            let mut covered = false;
            let mut next = end_vpn;
            for area in self.areas.iter() {
                if !area.map_perm.contains(MapPermission::U) {
                    continue;
                }
                let area_start = area.vpn_range.get_start();
                let area_end = area.vpn_range.get_end();
                if cursor >= area_start && cursor < area_end {
                    covered = true;
                    next = core::cmp::min(area_end, end_vpn);
                    break;
                }
            }
            if !covered {
                return false;
            }
            cursor = next;
        }

        let mut new_areas: Vec<MapArea> = Vec::new();
        let mut areas = core::mem::take(&mut self.areas);
        for mut area in areas.drain(..) {
            if !area.map_perm.contains(MapPermission::U) {
                new_areas.push(area);
                continue;
            }

            let area_start = area.vpn_range.get_start();
            let area_end = area.vpn_range.get_end();
            if end_vpn <= area_start || start_vpn >= area_end {
                new_areas.push(area);
                continue;
            }

            let ov_start = core::cmp::max(start_vpn, area_start);
            let ov_end = core::cmp::min(end_vpn, area_end);

            let mut left_frames = BTreeMap::new();
            let mut mid_frames = BTreeMap::new();
            let mut right_frames = BTreeMap::new();
            if area.map_type != MapType::Identical {
                let mut remaining = core::mem::take(&mut area.data_frames);
                right_frames = remaining.split_off(&ov_end);
                let overlap = remaining.split_off(&ov_start);
                mid_frames = overlap;
                left_frames = remaining;
            }

            for vpn in VPNRange::new(ov_start, ov_end) {
                if let Some(pte) = self.page_table.translate(vpn) {
                    if pte.is_valid() {
                        if new_perm == MapPermission::U {
                            // PROT_NONE: unmap but keep the frame tracker.
                            self.page_table.unmap(vpn);
                            continue;
                        }
                        let mut pte_flags = PTEFlags::from(new_perm);
                        let old_flags = pte.flags();
                        if old_flags.contains(PTEFlags::COW) {
                            pte_flags.insert(PTEFlags::COW);
                            pte_flags.remove(PTEFlags::W);
                        }
                        if old_flags.contains(PTEFlags::SHARED) {
                            pte_flags.insert(PTEFlags::SHARED);
                        }
                        let _ = self.page_table.set_flags(vpn, pte_flags);
                        continue;
                    }
                }
                if new_perm != MapPermission::U {
                    if let Some(frame) = mid_frames.get(&vpn) {
                        let pte_flags = PTEFlags::from(new_perm);
                        self.page_table.map(vpn, frame.ppn, pte_flags);
                    }
                }
            }

            if area_start < ov_start {
                let mut left = MapArea::from_another(&area);
                left.vpn_range = VPNRange::new(area_start, ov_start);
                left.data_frames = left_frames;
                new_areas.push(left);
            }

            let mut mid = MapArea::from_another(&area);
            mid.vpn_range = VPNRange::new(ov_start, ov_end);
            if ov_start != area_start {
                mid.start_offset = 0;
            }
            mid.map_perm = new_perm;
            mid.data_frames = mid_frames;
            new_areas.push(mid);

            if ov_end < area_end {
                let mut right = MapArea::from_another(&area);
                right.vpn_range = VPNRange::new(ov_end, area_end);
                right.start_offset = 0;
                right.data_frames = right_frames;
                new_areas.push(right);
            }
        }
        self.areas = new_areas;
        self.sort_user_areas();
        self.debug_assert_user_vm_invariants();
        true
    }

    /// Discard mapped pages in lazy user areas within `[start_va, end_va)`.
    ///
    /// This keeps the virtual ranges intact but frees any physical frames
    /// so they will be re-allocated on the next fault.
    pub fn discard_lazy_user_range(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return;
        }
        for area in self.areas.iter_mut() {
            if area.map_type != MapType::Lazy {
                continue;
            }
            if !area.map_perm.contains(MapPermission::U) {
                continue;
            }
            let area_start = area.vpn_range.get_start();
            let area_end = area.vpn_range.get_end();
            if end_vpn <= area_start || start_vpn >= area_end {
                continue;
            }
            let ov_start = core::cmp::max(start_vpn, area_start);
            let ov_end = core::cmp::min(end_vpn, area_end);
            for vpn in VPNRange::new(ov_start, ov_end) {
                area.unmap_one_maybe(&mut self.page_table, vpn);
            }
        }
        self.debug_assert_user_vm_invariants();
    }

    /// Returns true if any existing mapping overlaps the range.
    pub fn range_overlaps(&self, start_va: VirtAddr, end_va: VirtAddr) -> bool {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        self.areas.iter().any(|area| {
            let area_start = area.vpn_range.get_start();
            let area_end = area.vpn_range.get_end();
            end_vpn > area_start && start_vpn < area_end
        })
    }

    /// Return merged user virtual-memory ranges from current VMAs.
    pub fn user_mapped_ranges(&self) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        for area in self.areas.iter() {
            if !area.map_perm.contains(MapPermission::U) {
                continue;
            }
            let start = area.vpn_range.get_start().0.saturating_mul(PAGE_SIZE);
            let end = area.vpn_range.get_end().0.saturating_mul(PAGE_SIZE);
            if end <= start {
                continue;
            }
            ranges.push((start, end));
        }
        ranges.sort_unstable_by_key(|(start, _)| *start);
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut() {
                if start <= last.1 {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }
        merged
    }

    /// Highest end address among current user VMAs.
    pub fn max_user_mapped_end(&self) -> usize {
        self.areas
            .iter()
            .filter(|area| area.map_perm.contains(MapPermission::U))
            .map(|area| area.vpn_range.get_end().0.saturating_mul(PAGE_SIZE))
            .max()
            .unwrap_or(0)
    }

    /// Whether every page in `[start_va, end_va)` belongs to some user VMA.
    pub fn user_range_fully_mapped(&self, start_va: VirtAddr, end_va: VirtAddr) -> bool {
        let start: usize = start_va.into();
        let end: usize = end_va.into();
        if start >= end {
            return true;
        }
        let mut cursor = start;
        for (range_start, range_end) in self.user_mapped_ranges() {
            if range_end <= cursor {
                continue;
            }
            if range_start > cursor {
                return false;
            }
            cursor = cursor.max(range_end);
            if cursor >= end {
                return true;
            }
        }
        false
    }

    pub fn remove_area_with_start_vpn(&mut self, start_va: VirtAddr) {
        if let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .find(|(_idx, area)| area.vpn_range.get_start() == start_va.floor())
        {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
            self.debug_assert_user_vm_invariants();
        };
    }

    #[allow(dead_code)]
    pub fn clone(&self) -> Self {
        let mut new_memory_set = Self::new_bare();
        let has_user = self
            .areas
            .iter()
            .any(|area| area.map_perm.contains(MapPermission::U));
        new_memory_set.map_trampoline();
        if has_user {
            new_memory_set.map_sigreturn_trampoline_user();
        }
        for area in &self.areas {
            let mut new_area = MapArea::new(
                VirtAddr::from(area.vpn_range.get_start()),
                VirtAddr::from(area.vpn_range.get_end()),
                area.map_type,
                area.map_perm,
            );
            if area.map_type == MapType::Lazy {
                let pte_flags = PTEFlags::from(new_area.map_perm);
                for vpn in area.vpn_range {
                    let Some(src_pte) = self.page_table.translate(vpn) else {
                        continue;
                    };
                    if !src_pte.is_valid() {
                        continue;
                    }
                    let src_ppn = src_pte.ppn();
                    let Some(frame) = frame_alloc() else {
                        continue;
                    };
                    frame
                        .ppn
                        .get_bytes_array()
                        .copy_from_slice(src_ppn.get_bytes_array());
                    new_memory_set.page_table.map(vpn, frame.ppn, pte_flags);
                    new_area.data_frames.insert(vpn, frame);
                }
                new_memory_set.push_mapped(new_area);
                continue;
            }

            new_memory_set.push(new_area, None);
            //then copy data

            for vpn in area.vpn_range {
                let src_ppn = self.page_table.translate(vpn).unwrap().ppn();
                let dst_ppn = new_memory_set.page_table.translate(vpn).unwrap().ppn();
                let src_bytes = src_ppn.get_bytes_array();
                let dst_bytes = dst_ppn.get_bytes_array();
                dst_bytes.copy_from_slice(&src_bytes);
            }
        }

        new_memory_set.inherit_user_vm_metadata_from(self);
        new_memory_set
    }
    #[allow(dead_code)]
    pub fn recycle_data_pages(&mut self) {
        //*self = Self::new_bare();
        self.areas.clear();
        self.debug_assert_user_vm_invariants();
    }
}

/// map area structure, controls a contiguous piece of virtual memory
pub struct MapArea {
    vpn_range: VPNRange,
    data_frames: BTreeMap<VirtPageNum, FrameTracker>,
    charged_pages: usize,
    map_type: MapType,
    map_perm: MapPermission,
    start_offset: usize,
}

impl MapArea {
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
    ) -> Self {
        let start_vpn: VirtPageNum = start_va.floor();
        let end_vpn: VirtPageNum = end_va.ceil();
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            charged_pages: 0,
            map_type,
            map_perm,
            start_offset: start_va.page_offset(),
        }
    }
    pub fn from_another(another: &MapArea) -> Self {
        Self {
            vpn_range: VPNRange::new(another.vpn_range.get_start(), another.vpn_range.get_end()),
            data_frames: BTreeMap::new(),
            charged_pages: another.charged_pages,
            map_type: another.map_type,
            map_perm: another.map_perm,
            start_offset: another.start_offset,
        }
    }
    /// map _one 两种映射类型.其中恒等映射 本人是不持有 frame 的.
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> bool {
        if self.map_type == MapType::Lazy {
            return true;
        }
        let ppn: PhysPageNum = match self.map_type {
            MapType::Identical => PhysPageNum(vpn.0),
            MapType::Framed => {
                let Some(frame) = frame_alloc() else {
                    crate::println!("[mm] OOM: frame_alloc failed for vpn={:?}", vpn);
                    return false;
                };
                let ppn = frame.ppn;
                self.data_frames.insert(vpn, frame);
                ppn
            }
            MapType::Lazy => unreachable!(),
        };
        let pte_flags = PTEFlags::from(self.map_perm);
        page_table.map(vpn, ppn, pte_flags);
        true
    }
    #[allow(unused)]
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if self.map_type != MapType::Identical {
            self.data_frames.remove(&vpn);
        }
        if self.map_type == MapType::Lazy {
            page_table.unmap_if_mapped(vpn);
        } else {
            page_table.unmap(vpn);
        }
    }

    pub fn unmap_one_maybe(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if self.map_type != MapType::Identical {
            self.data_frames.remove(&vpn);
        }
        page_table.unmap_if_mapped(vpn);
    }

    /// 清理内存,并且将内存进行映射,内部使用map_one 逐个映射.
    pub fn map(&mut self, page_table: &mut PageTable) -> bool {
        if self.map_type == MapType::Lazy {
            return true;
        }
        let mut mapped: Vec<VirtPageNum> = Vec::new();
        for vpn in self.vpn_range {
            if !self.map_one(page_table, vpn) {
                // Roll back any partial mappings to avoid leaving an invalid address space.
                for vpn in mapped {
                    self.unmap_one_maybe(page_table, vpn);
                }
                return false;
            }
            mapped.push(vpn);
        }
        true
    }
    #[allow(unused)]
    pub fn unmap(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range {
            self.unmap_one(page_table, vpn);
        }
    }
    #[allow(unused)]
    pub fn shrink_to(&mut self, page_table: &mut PageTable, new_end: VirtPageNum) {
        for vpn in VPNRange::new(new_end, self.vpn_range.get_end()) {
            self.unmap_one(page_table, vpn)
        }
        self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
    }
    #[allow(unused)]
    pub fn append_to(&mut self, page_table: &mut PageTable, new_end: VirtPageNum) -> bool {
        if self.map_type == MapType::Lazy {
            self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
            return true;
        }
        let old_end = self.vpn_range.get_end();
        let mut mapped: Vec<VirtPageNum> = Vec::new();
        for vpn in VPNRange::new(old_end, new_end) {
            if !self.map_one(page_table, vpn) {
                // Roll back the newly mapped suffix.
                for vpn in mapped {
                    self.unmap_one_maybe(page_table, vpn);
                }
                return false;
            }
            mapped.push(vpn);
        }
        self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
        true
    }
    /// data: start-aligned but maybe with shorter length
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &PageTable, data: &[u8]) {
        assert_eq!(self.map_type, MapType::Framed);
        let mut current_vpn = self.vpn_range.get_start();
        let mut src_off = 0usize;

        // First page may start at an offset within the page.
        let mut page_off = self.start_offset;
        while src_off < data.len() {
            let dst_page = page_table
                .translate(current_vpn)
                .unwrap()
                .ppn()
                .get_bytes_array();
            let cap = PAGE_SIZE - page_off;
            let to_copy = core::cmp::min(cap, data.len() - src_off);
            dst_page[page_off..page_off + to_copy]
                .copy_from_slice(&data[src_off..src_off + to_copy]);
            src_off += to_copy;
            current_vpn.step();
            page_off = 0;
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LazyFaultResult {
    Resolved,
    Oom,
    Invalid,
}

impl LazyFaultResult {
    #[allow(dead_code)]
    pub fn is_resolved(self) -> bool {
        matches!(self, Self::Resolved)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
/// map type for memory set: identical, framed, or lazy (on-demand)
pub enum MapType {
    Identical,
    Framed,
    Lazy,
}

bitflags! {
    /// map permission corresponding to that in pte: `R W X U`
    pub struct MapPermission: u8 {
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        /// Device/IO memory mapping (non-cacheable on loongarch64).
        const IO = 1 << 5;
    }
}
pub fn kernel_token() -> usize {
    KERNEL_SPACE.lock().token()
}

#[allow(dead_code)]
pub fn activate_token(token: usize) {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: token is a valid satp value; sfence.vma flushes TLB after satp change.
    unsafe {
        satp::write(Satp::from_bits(token));
        asm!("sfence.vma");
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let page_table = PageTable::from_token(token);
        page_table.activate();
    }
}
#[allow(unused)]
pub fn remap_test() {
    let mut kernel_space = KERNEL_SPACE.lock();
    let mid_text: VirtAddr = ((stext as usize + etext as usize) / 2).into();
    let mid_rodata: VirtAddr = ((srodata as usize + erodata as usize) / 2).into();
    let mid_data: VirtAddr = ((sdata as usize + edata as usize) / 2).into();
    assert!(
        !kernel_space
            .page_table
            .translate(mid_text.floor())
            .unwrap()
            .writable(),
    );
    assert!(
        !kernel_space
            .page_table
            .translate(mid_rodata.floor())
            .unwrap()
            .writable(),
    );
    assert!(
        !kernel_space
            .page_table
            .translate(mid_data.floor())
            .unwrap()
            .executable(),
    );
    println!("remap_test passed!");
}
