use super::MemorySet;
use super::backing::{MmapBacking, MmapBackingPageState, MmapWritebackChunk};
use super::map_area::{MapArea, MapPermission};
use super::range::{align_down_to_page, align_up_to_page};
use super::vma::VmRegion;
use crate::config::PAGE_SIZE;
use crate::fs::{File, OSInode};
use crate::mm::{PTEFlags, PhysAddr, PhysPageNum, VPNRange, VirtAddr, VirtPageNum};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

impl MemorySet {
    pub fn shared_file_vm_regions_overlapping(&self, start: usize, end: usize) -> Vec<VmRegion> {
        self.vm_regions
            .collect_overlaps_where(start, end, |region| region.shared && region.file_backed)
    }

    fn resident_page_for_vpn(
        &self,
        area: &MapArea,
        vpn: VirtPageNum,
    ) -> Option<(PhysPageNum, PTEFlags, bool)> {
        if let Some(pte) = self.page_table.translate(vpn) {
            if pte.is_valid() {
                return Some((pte.ppn(), pte.flags(), true));
            }
        }
        let frame = area.tracked_frame(vpn)?;
        let flags = area.saved_pte_flags(vpn)?;
        Some((frame.ppn, flags, false))
    }

    fn collect_mmap_backing_resident_pages(
        &self,
        backing_id: usize,
    ) -> BTreeMap<usize, MmapBackingPageState> {
        let mut pages = BTreeMap::new();
        for region in self
            .vm_regions
            .iter()
            .filter(|region| region.backing_id == backing_id)
        {
            let scan_start = region.start;
            let scan_end = core::cmp::min(region.end(), region.sigbus_start());
            if scan_start >= scan_end {
                continue;
            }
            let start_vpn = VirtAddr::from(scan_start).floor();
            let end_vpn = VirtAddr::from(scan_end).ceil();
            for area in self.areas.iter() {
                if !area.contains_perm(MapPermission::U)
                    || !area.overlaps_vpn_range(start_vpn, end_vpn)
                {
                    continue;
                }
                let ov_start = core::cmp::max(start_vpn, area.start_vpn());
                let ov_end = core::cmp::min(end_vpn, area.end_vpn());
                for vpn in VPNRange::new(ov_start, ov_end) {
                    let page_start = vpn.0.saturating_mul(PAGE_SIZE);
                    if page_start < scan_start || page_start >= scan_end {
                        continue;
                    }
                    let Some((_ppn, flags, _has_valid_pte)) = self.resident_page_for_vpn(area, vpn)
                    else {
                        continue;
                    };
                    let file_page = region
                        .file_offset
                        .saturating_add(page_start.saturating_sub(region.start))
                        / PAGE_SIZE;
                    let state = pages
                        .entry(file_page)
                        .or_insert_with(MmapBackingPageState::default);
                    state.dirty |= flags.contains(PTEFlags::D);
                }
            }
        }
        pages
    }

    pub(super) fn refresh_mmap_backing_resident_pages(&mut self, backing_id: usize) {
        let pages = self.collect_mmap_backing_resident_pages(backing_id);
        if let Some(backing) = self.mmap_backings.get_mut(&backing_id) {
            backing.replace_resident_pages(pages);
        }
    }

    fn refresh_all_mmap_backing_resident_pages(&mut self) {
        let backing_ids = self.mmap_backings.keys().copied().collect::<Vec<_>>();
        for backing_id in backing_ids {
            self.refresh_mmap_backing_resident_pages(backing_id);
        }
    }

    pub(super) fn mark_mmap_backing_resident_page(
        &mut self,
        backing_id: usize,
        file_page: usize,
        dirty: bool,
    ) {
        if let Some(backing) = self.mmap_backings.get_mut(&backing_id) {
            backing.mark_resident_page(file_page, dirty);
        }
    }

    fn clear_mmap_backing_dirty_page(&mut self, backing_id: usize, file_page: usize) {
        if let Some(backing) = self.mmap_backings.get_mut(&backing_id) {
            backing.clear_dirty_page(file_page);
        }
    }

    fn set_saved_pte_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) -> bool {
        for area in self.areas.iter_mut() {
            if !area.contains_vpn(vpn) {
                continue;
            }
            if area.set_saved_pte_flags(vpn, flags) {
                return true;
            }
        }
        false
    }

    fn collect_shared_file_mmap_writeback_chunks(
        &mut self,
        start: usize,
        end: usize,
    ) -> Vec<MmapWritebackChunk> {
        let mut chunks = Vec::new();
        let regions = self.shared_file_vm_regions_overlapping(start, end);
        for region in regions {
            let Some(backing) = self.mmap_backings.get(&region.backing_id) else {
                continue;
            };
            let file = backing.file();
            let seg_start = core::cmp::max(start, region.start);
            let seg_end =
                core::cmp::min(core::cmp::min(end, region.end()), region.file_valid_end());
            if seg_end <= seg_start {
                continue;
            }
            let start_vpn = VirtAddr::from(align_down_to_page(seg_start)).floor();
            let end_vpn = VirtAddr::from(seg_end).ceil();
            for area in self.areas.iter() {
                if !area.contains_perm(MapPermission::U)
                    || !area.overlaps_vpn_range(start_vpn, end_vpn)
                {
                    continue;
                }
                let ov_start = core::cmp::max(start_vpn, area.start_vpn());
                let ov_end = core::cmp::min(end_vpn, area.end_vpn());
                for vpn in VPNRange::new(ov_start, ov_end) {
                    let page_start = vpn.0.saturating_mul(PAGE_SIZE);
                    let copy_start = core::cmp::max(seg_start, page_start);
                    let copy_end = core::cmp::min(seg_end, page_start.saturating_add(PAGE_SIZE));
                    if copy_end <= copy_start {
                        continue;
                    }
                    let Some((ppn, flags, has_valid_pte)) = self.resident_page_for_vpn(area, vpn)
                    else {
                        continue;
                    };
                    let off_in_page = copy_start.saturating_sub(page_start);
                    let file_offset = region
                        .file_offset
                        .saturating_add(copy_start.saturating_sub(region.start));
                    let file_page = file_offset / PAGE_SIZE;
                    let mut data = Vec::new();
                    data.extend_from_slice(
                        &ppn.get_bytes_array()[off_in_page..off_in_page + (copy_end - copy_start)],
                    );
                    chunks.push(MmapWritebackChunk {
                        file: Arc::clone(&file),
                        backing_id: region.backing_id,
                        file_page,
                        vpn,
                        flags,
                        has_valid_pte,
                        file_offset,
                        data,
                    });
                }
            }
        }
        for chunk in chunks.iter() {
            self.mark_mmap_backing_resident_page(
                chunk.backing_id,
                chunk.file_page,
                chunk.flags.contains(PTEFlags::D),
            );
        }
        chunks
    }

    pub fn writeback_shared_file_mmap_range(
        &mut self,
        start: usize,
        end: usize,
        clear_dirty: bool,
    ) -> Result<bool, ()> {
        let chunks = self.collect_shared_file_mmap_writeback_chunks(start, end);
        let mut cleared_dirty = false;
        for chunk in chunks {
            let Some(os_inode) = chunk.file.as_any().downcast_ref::<OSInode>() else {
                continue;
            };
            if !chunk.data.is_empty()
                && os_inode
                    .pwrite_at(chunk.file_offset, chunk.data.as_slice())
                    .is_err()
            {
                return Err(());
            }
            if os_inode.flush().is_err() {
                return Err(());
            }
            if clear_dirty && chunk.flags.contains(PTEFlags::D) {
                let mut flags = chunk.flags;
                flags.remove(PTEFlags::D);
                let changed = if chunk.has_valid_pte {
                    self.set_pte_flags(chunk.vpn, flags)
                } else {
                    self.set_saved_pte_flags(chunk.vpn, flags)
                };
                if changed {
                    self.clear_mmap_backing_dirty_page(chunk.backing_id, chunk.file_page);
                    cleared_dirty = true;
                }
            }
        }
        self.debug_assert_user_vm_invariants();
        Ok(cleared_dirty)
    }

    pub fn has_writable_shared_memfd_mapping(&self, memfd_id: u64) -> bool {
        self.vm_regions.iter().any(|region| {
            region.memfd_id == memfd_id
                && region.shared
                && region.map_permission().contains(MapPermission::W)
        })
    }

    pub fn file_vm_copy_targets(
        &mut self,
        dev: usize,
        ino: u32,
        write_off: usize,
        len: usize,
    ) -> Vec<(usize, usize, usize)> {
        let pending = self.vm_regions.file_copy_targets(dev, ino, write_off, len);
        self.debug_assert_user_vm_invariants();
        pending
    }

    fn zero_mapped_user_bytes(&mut self, start: usize, end: usize) {
        let mut cur = start;
        while cur < end {
            let va = VirtAddr::from(cur);
            let vpn = va.floor();
            let page_off = va.page_offset();
            let len = core::cmp::min(PAGE_SIZE - page_off, end - cur);
            if let Some(pte) = self.page_table.translate(vpn) {
                if pte.is_valid() && pte.flags().contains(PTEFlags::U) {
                    let pa: PhysAddr = pte.ppn().into();
                    // SAFETY: The PTE is valid and user-accessible, and `len`
                    // is bounded to the translated page.
                    unsafe {
                        core::ptr::write_bytes((pa.0 + page_off) as *mut u8, 0, len);
                    }
                }
            }
            cur += len;
        }
    }

    pub fn update_file_vm_size(&mut self, dev: usize, ino: u32, file_size: usize) -> bool {
        let updates: Vec<(usize, usize, usize, usize, usize, usize, MapPermission)> = self
            .vm_regions
            .iter()
            .filter_map(|region| {
                if !region.file_backed || region.file_dev != dev || region.file_ino != ino {
                    return None;
                }
                let new_valid_len = file_size.saturating_sub(region.file_offset).min(region.len);
                let new_sigbus = region
                    .start
                    .saturating_add(align_up_to_page(new_valid_len).min(region.len));
                Some((
                    region.start,
                    region.end(),
                    region.file_valid_len(),
                    new_valid_len,
                    region.sigbus_start(),
                    new_sigbus,
                    region.map_permission(),
                ))
            })
            .collect();
        if updates.is_empty() {
            return true;
        }

        let mut ok = true;

        for (start, _end, old_valid_len, new_valid_len, old_sigbus, new_sigbus, _perm) in
            updates.iter().copied()
        {
            if new_sigbus <= old_sigbus {
                self.vm_regions.set_file_valid_by_identity(
                    start,
                    dev,
                    ino,
                    new_valid_len,
                    new_sigbus,
                );
            }

            if new_valid_len < old_valid_len {
                let zero_start = start.saturating_add(new_valid_len);
                let zero_end = start.saturating_add(
                    align_up_to_page(new_valid_len)
                        .min(align_up_to_page(old_valid_len))
                        .min(old_sigbus.saturating_sub(start)),
                );
                if zero_start < zero_end {
                    self.zero_mapped_user_bytes(zero_start, zero_end);
                }
            }
        }

        for (_start, end, _old_valid, _new_valid, old_sigbus, new_sigbus, _perm) in
            updates.iter().copied()
        {
            if new_sigbus < old_sigbus {
                self.unmap_user_range(new_sigbus.into(), end.into());
                if new_sigbus < end
                    && !self.try_insert_lazy_area_raw(
                        new_sigbus.into(),
                        end.into(),
                        MapPermission::U,
                    )
                {
                    ok = false;
                }
            }
        }

        for (start, _end, _old_valid, new_valid_len, old_sigbus, new_sigbus, perm) in
            updates.iter().copied()
        {
            if new_sigbus > old_sigbus {
                self.unmap_user_range(old_sigbus.into(), new_sigbus.into());
                // Newly valid file-backed pages are populated by the file
                // fault path, not by allocating zero-filled resident pages.
                let inserted =
                    self.try_insert_lazy_area_raw(old_sigbus.into(), new_sigbus.into(), perm);
                if !inserted {
                    ok = false;
                    continue;
                }
                self.vm_regions.set_file_valid_by_identity(
                    start,
                    dev,
                    ino,
                    new_valid_len,
                    new_sigbus,
                );
            }
        }

        self.debug_assert_user_vm_invariants();
        ok
    }

    pub fn mmap_backing_file(&self, backing_id: usize) -> Option<Arc<dyn File + Send + Sync>> {
        self.mmap_backings.get(&backing_id).map(MmapBacking::file)
    }

    pub(super) fn allocate_mmap_backing(
        &mut self,
        region: &VmRegion,
        file: Option<&Arc<dyn File + Send + Sync>>,
    ) -> usize {
        let Some(file) = file else {
            return 0;
        };
        let Some(backing) = MmapBacking::new(region, file) else {
            return 0;
        };
        let id = self.next_mmap_backing_id;
        self.next_mmap_backing_id = self.next_mmap_backing_id.saturating_add(1);
        self.mmap_backings.insert(id, backing);
        id
    }

    pub(super) fn prune_unused_mmap_backings(&mut self) {
        self.mmap_backings.retain(|backing_id, backing| {
            self.vm_regions.iter().any(|region| {
                (region.file_backed || region.memfd_id != 0)
                    && region.backing_id == *backing_id
                    && backing.kind.matches_region(region)
            })
        });
        self.refresh_all_mmap_backing_resident_pages();
    }
}
