use super::MemorySet;
use super::backing::{MmapBacking, MmapBackingPageState, MmapBackingVmState, MmapWritebackChunk};
use super::map_area::{MapArea, MapPermission};
use super::range::{align_down_to_page, align_up_to_page, normalize_ranges};
use super::vma::VmRegion;
use crate::config::PAGE_SIZE;
use crate::fs::{File, OSInode};
use crate::mm::{FrameTracker, PTEFlags, PhysAddr, PhysPageNum, VPNRange, VirtAddr, VirtPageNum};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

impl MemorySet {
    /// 收集 [start, end) 内所有共享文件映射的 VmRegion。
    pub fn shared_file_vm_regions_overlapping(&self, start: usize, end: usize) -> Vec<VmRegion> {
        self.vm_regions
            .collect_overlaps_where(start, end, |region| region.shared && region.file_backed)
    }

    /// 返回指定 vpn 的驻留 frame、PTE flags 及 PTE 是否有效。
    /// PROT_NONE 后 frame 仍保存在 MapArea，flags 从 saved_pte_flags 取。
    fn resident_page_for_vpn(
        &self,
        area: &MapArea,
        vpn: VirtPageNum,
    ) -> Option<(FrameTracker, PTEFlags, bool)> {
        // PROT_NONE 后 frame 仍保存在 MapArea，PTE flags 可能在 saved_pte_flags。
        let frame = area.tracked_frame(vpn)?;
        if let Some(pte) = self.page_table.translate(vpn) {
            if pte.is_valid() {
                debug_assert_eq!(
                    pte.ppn(),
                    frame.ppn,
                    "resident PTE ppn drifted from tracked frame for vpn {:?}",
                    vpn
                );
                return Some((frame.clone(), pte.flags(), true));
            }
        }
        let flags = area.saved_pte_flags(vpn)?;
        Some((frame.clone(), flags, false))
    }

    /// 从当前 MapArea/PTE 扫描，重建指定 backing 的 resident 页状态快照。
    /// 用于 VMA 或物理页变化后刷新 MmapBacking.resident_pages。
    fn collect_mmap_backing_resident_pages(
        &self,
        backing_id: usize,
    ) -> BTreeMap<usize, MmapBackingPageState> {
        // 从当前 VMA + MapArea/PTE 重新生成 resident 页状态，避免手写更新漂移。
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
                    let Some((frame, flags, _has_valid_pte)) =
                        self.resident_page_for_vpn(area, vpn)
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
                    state.ref_count = state.ref_count.saturating_add(1);
                    state.dirty |= self
                        .mmap_backings
                        .get(&backing_id)
                        .and_then(|backing| backing.resident_pages.get(&file_page))
                        .is_some_and(|old_state| old_state.dirty);
                    state.dirty |= flags.contains(PTEFlags::D);
                    if region.shared && region.file_backed {
                        if let Some(existing) = state.frame.as_ref() {
                            debug_assert_eq!(
                                existing.ppn, frame.ppn,
                                "mmap backing file page {} points at multiple shared frames",
                                file_page
                            );
                        } else {
                            state.frame = Some(frame);
                        }
                    }
                }
            }
        }
        pages
    }

    /// 从 VmRegionSet 派生指定 backing 的 VMA 统计状态（vma_count、mapped/valid 文件范围）。
    pub(super) fn collect_mmap_backing_vm_state(&self, backing_id: usize) -> MmapBackingVmState {
        // backing 生命周期状态只从权威 VMA 集合派生。
        let mut vm_state = MmapBackingVmState::default();
        for region in self
            .vm_regions
            .iter()
            .filter(|region| region.backing_id == backing_id)
        {
            vm_state.vma_count = vm_state.vma_count.saturating_add(1);

            let mapped_start = region.file_offset;
            let mapped_end = region.file_offset.saturating_add(region.len);
            if mapped_start < mapped_end {
                vm_state.mapped_file_ranges.push((mapped_start, mapped_end));
            }

            let valid_start = region.file_offset;
            let valid_end = region.file_offset.saturating_add(region.file_valid_len());
            if valid_start < valid_end {
                vm_state.valid_file_ranges.push((valid_start, valid_end));
            }
        }
        normalize_ranges(&mut vm_state.mapped_file_ranges);
        normalize_ranges(&mut vm_state.valid_file_ranges);
        vm_state
    }

    /// 将非零且未重复的 backing_id 追加到列表。
    pub(super) fn push_unique_backing_id(backing_ids: &mut Vec<usize>, backing_id: usize) {
        if backing_id != 0 && !backing_ids.contains(&backing_id) {
            backing_ids.push(backing_id);
        }
    }

    /// 收集 [start, end) 内所有 VmRegion 关联的 backing_id（去重）。
    pub(super) fn backing_ids_for_vma_range(&self, start: usize, end: usize) -> Vec<usize> {
        let mut backing_ids = Vec::new();
        for region in self.vm_regions.snapshot_range(start, end) {
            Self::push_unique_backing_id(&mut backing_ids, region.backing_id);
        }
        backing_ids
    }

    /// VMA 或驻留页变化后，重建指定 backing 的 resident_pages 和 vm_state。
    pub(super) fn refresh_mmap_backing_state(&mut self, backing_id: usize) {
        // VMA 或 resident 页变化后统一刷新 backing 派生状态。
        let pages = self.collect_mmap_backing_resident_pages(backing_id);
        let vm_state = self.collect_mmap_backing_vm_state(backing_id);
        if let Some(backing) = self.mmap_backings.get_mut(&backing_id) {
            backing.replace_vm_state(vm_state);
            backing.replace_resident_pages(pages);
        }
    }

    /// 仅 VMA 集合变化时刷新 backing 的范围状态。
    ///
    /// 新插入的 lazy file mapping 还没有 resident 页；只需要更新 backing
    /// 的 mapped/valid 文件范围，不应为此扫描 MapArea/PTE。
    pub(super) fn refresh_mmap_backing_vm_state(&mut self, backing_id: usize) {
        let vm_state = self.collect_mmap_backing_vm_state(backing_id);
        if let Some(backing) = self.mmap_backings.get_mut(&backing_id) {
            backing.replace_vm_state(vm_state);
        }
    }

    /// 批量刷新多个 backing 的状态。
    pub(super) fn refresh_mmap_backing_states(&mut self, backing_ids: Vec<usize>) {
        for backing_id in backing_ids {
            self.refresh_mmap_backing_state(backing_id);
        }
    }

    /// 刷新所有 backing 的状态（munmap/exec 等全量变更后使用）。
    fn refresh_all_mmap_backing_states(&mut self) {
        let backing_ids = self.mmap_backings.keys().copied().collect::<Vec<_>>();
        self.refresh_mmap_backing_states(backing_ids);
    }

    /// 返回指定 backing 中 file_page 对应的驻留共享 frame。
    pub(super) fn mmap_backing_resident_frame(
        &self,
        backing_id: usize,
        file_page: usize,
    ) -> Option<FrameTracker> {
        self.mmap_backings
            .get(&backing_id)
            .and_then(|backing| backing.resident_frame(file_page))
    }

    /// 清除指定 backing 中 file_page 的 dirty 标记（msync 写回后调用）。
    #[cfg(target_arch = "riscv64")]
    fn clear_mmap_backing_dirty_page(&mut self, backing_id: usize, file_page: usize) {
        if let Some(backing) = self.mmap_backings.get_mut(&backing_id) {
            backing.clear_dirty_page(file_page);
        }
    }

    /// 更新 vpn 在 MapArea 中的 saved_pte_flags（PTE 无效时用于保存 dirty 等标志）。
    #[cfg(target_arch = "riscv64")]
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

    fn shared_file_page_vpn_range(
        region: VmRegion,
        file_page: usize,
    ) -> Option<(VirtPageNum, VirtPageNum)> {
        let page_start = file_page.checked_mul(PAGE_SIZE)?;
        let page_end = page_start.checked_add(PAGE_SIZE)?;
        let valid_start = region.file_offset;
        let valid_end = region.file_offset.checked_add(region.file_valid_len())?;
        let overlap_start = core::cmp::max(page_start, valid_start);
        let overlap_end = core::cmp::min(page_end, valid_end);
        if overlap_start >= overlap_end {
            return None;
        }
        let va_start = region
            .start
            .checked_add(overlap_start.saturating_sub(region.file_offset))?;
        let va_end = region
            .start
            .checked_add(overlap_end.saturating_sub(region.file_offset))?;
        Some((
            VirtAddr::from(va_start).floor(),
            VirtAddr::from(va_end).ceil(),
        ))
    }

    fn shared_file_page_local_state(
        &self,
        backing_id: usize,
        file_page: usize,
        ppn: PhysPageNum,
    ) -> (usize, bool, bool) {
        let mut local_refs = 0usize;
        let mut any_dirty = false;
        let mut any_writable = false;

        for region in self
            .vm_regions
            .iter()
            .filter(|region| region.backing_id == backing_id && region.shared && region.file_backed)
        {
            let Some((start_vpn, end_vpn)) = Self::shared_file_page_vpn_range(*region, file_page)
            else {
                continue;
            };
            for area in self.areas.iter() {
                if !area.contains_perm(MapPermission::U)
                    || !area.overlaps_vpn_range(start_vpn, end_vpn)
                {
                    continue;
                }
                let ov_start = core::cmp::max(start_vpn, area.start_vpn());
                let ov_end = core::cmp::min(end_vpn, area.end_vpn());
                for vpn in VPNRange::new(ov_start, ov_end) {
                    let Some(frame) = area.tracked_frame(vpn) else {
                        continue;
                    };
                    if frame.ppn != ppn {
                        continue;
                    }
                    local_refs = local_refs.saturating_add(1);
                    any_writable |= region.map_permission().contains(MapPermission::W);
                    let flags = self
                        .page_table
                        .translate(vpn)
                        .filter(|pte| pte.is_valid())
                        .map(|pte| pte.flags())
                        .or_else(|| area.saved_pte_flags(vpn));
                    any_dirty |= flags.is_some_and(|flags| flags.contains(PTEFlags::D));
                }
            }
        }

        (local_refs, any_dirty, any_writable)
    }

    fn shared_file_page_has_external_refs(
        &self,
        backing_id: usize,
        file_page: usize,
        frame: &FrameTracker,
        local_refs: usize,
    ) -> bool {
        let backing_state_ref =
            self.mmap_backings
                .get(&backing_id)
                .and_then(|backing| backing.resident_pages.get(&file_page))
                .and_then(|state| state.frame.as_ref())
                .is_some_and(|backing_frame| backing_frame.ppn == frame.ppn) as usize;
        let expected_local_refs = local_refs
            .saturating_add(1) // global shared file page cache
            .saturating_add(backing_state_ref)
            .saturating_add(1); // resident_page_for_vpn() clone held by the caller
        frame.refcount() > expected_local_refs
    }

    fn shared_file_page_needs_writeback(
        &self,
        backing_id: usize,
        file_page: usize,
        frame: &FrameTracker,
        flags: PTEFlags,
    ) -> bool {
        if flags.contains(PTEFlags::D) {
            return true;
        }
        if self
            .mmap_backings
            .get(&backing_id)
            .and_then(|backing| backing.resident_pages.get(&file_page))
            .is_some_and(|state| state.dirty)
        {
            return true;
        }

        let (local_refs, local_dirty, local_writable) =
            self.shared_file_page_local_state(backing_id, file_page, frame.ppn);
        if local_dirty || local_writable {
            return true;
        }

        self.shared_file_page_has_external_refs(backing_id, file_page, frame, local_refs)
    }

    /// 收集 [start, end) 内所有需要写回的共享文件页数据块。
    /// 只收集 file_valid_end() 以内的真实文件字节，SIGBUS tail 不参与。
    fn collect_shared_file_mmap_writeback_chunks(
        &mut self,
        start: usize,
        end: usize,
    ) -> Vec<MmapWritebackChunk> {
        // 只回写 file_valid_end() 内的真实文件字节，避免把 EOF 零填充写回文件。
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
                    let Some((frame, flags, has_valid_pte)) = self.resident_page_for_vpn(area, vpn)
                    else {
                        continue;
                    };
                    let file_offset = region
                        .file_offset
                        .saturating_add(copy_start.saturating_sub(region.start));
                    let file_page = file_offset / PAGE_SIZE;
                    if !self.shared_file_page_needs_writeback(
                        region.backing_id,
                        file_page,
                        &frame,
                        flags,
                    ) {
                        continue;
                    }
                    let off_in_page = copy_start.saturating_sub(page_start);
                    let mut data = Vec::new();
                    data.extend_from_slice(
                        &frame.ppn.get_bytes_array()
                            [off_in_page..off_in_page + (copy_end - copy_start)],
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
        chunks
    }

    /// msync/munmap 写回路径：将 [start, end) 内共享文件映射的脏页写回文件。
    /// clear_dirty=true 时同步清除 PTE dirty 位；返回是否实际清除了 dirty。
    pub fn writeback_shared_file_mmap_range(
        &mut self,
        start: usize,
        end: usize,
        clear_dirty: bool,
    ) -> Result<bool, ()> {
        // msync/munmap 走同一收集路径；clear_dirty 只负责清 PTE/saved dirty 位。
        let chunks = self.collect_shared_file_mmap_writeback_chunks(start, end);
        let mut refreshed_backings = Vec::new();
        for chunk in chunks.iter() {
            Self::push_unique_backing_id(&mut refreshed_backings, chunk.backing_id);
        }
        #[cfg(not(target_arch = "riscv64"))]
        let _ = clear_dirty;
        #[cfg(target_arch = "riscv64")]
        let mut cleared_dirty = false;
        #[cfg(not(target_arch = "riscv64"))]
        let cleared_dirty = false;
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
            #[cfg(not(target_arch = "riscv64"))]
            let _ = (chunk.file_page, chunk.vpn, chunk.flags, chunk.has_valid_pte);
            #[cfg(target_arch = "riscv64")]
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
        self.refresh_mmap_backing_states(refreshed_backings);
        self.debug_assert_user_vm_invariants();
        Ok(cleared_dirty)
    }

    /// 检查本 MemorySet 内是否存在对指定 memfd 的可写共享映射（用于 F_SEAL_WRITE 检查）。
    pub fn has_writable_shared_memfd_mapping(&self, memfd_id: u64) -> bool {
        self.vm_regions.iter().any(|region| {
            region.shmem_id == memfd_id
                && region.shared
                && region.map_permission().contains(MapPermission::W)
        })
    }

    /// 返回需要将 fd write 数据镜像到用户内存的 (va, src_offset, len) 列表，
    /// 并同步更新对应 VmRegion 的 file_valid_len。
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

    /// 将 data 写入已驻留的用户页（仅覆盖已 fault 的页，未 fault 页由后续 lazy fault 从文件读）。
    fn copy_to_resident_user_bytes(&self, start: usize, data: &[u8]) -> bool {
        // fd 写入只镜像已经 resident 的 mmap 页；未 fault 页由后续 lazy fault 读文件/cache。
        let mut copied = 0usize;
        let mut wrote_resident = false;
        while copied < data.len() {
            let va = start.saturating_add(copied);
            let vpn = VirtAddr::from(va).floor();
            let page_off = va & (PAGE_SIZE - 1);
            let len = core::cmp::min(PAGE_SIZE - page_off, data.len() - copied);
            for area in self.areas.iter() {
                if !area.contains_perm(MapPermission::U) || !area.contains_vpn(vpn) {
                    continue;
                }
                let Some((frame, flags, _has_valid_pte)) = self.resident_page_for_vpn(area, vpn)
                else {
                    continue;
                };
                if !flags.contains(PTEFlags::U) {
                    break;
                }
                frame.ppn.get_bytes_array()[page_off..page_off + len]
                    .copy_from_slice(&data[copied..copied + len]);
                wrote_resident = true;
                break;
            }
            copied += len;
        }
        wrote_resident
    }

    /// fd write 后将数据镜像到所有共享文件映射的驻留页，保持 mmap 与文件内容一致。
    pub fn mirror_shared_file_write_to_resident_mmaps(
        &mut self,
        dev: usize,
        ino: u32,
        write_off: usize,
        data: &[u8],
    ) {
        if data.is_empty() {
            return;
        }
        let write_end = write_off.saturating_add(data.len());
        let regions = self
            .vm_regions
            .iter()
            .filter(|region| {
                region.shared
                    && region.file_backed
                    && region.file_dev == dev
                    && region.file_ino == ino
            })
            .copied()
            .collect::<Vec<_>>();
        if regions.is_empty() {
            return;
        }

        let mut refreshed_backings = Vec::new();
        let mut wrote_executable = false;
        for region in regions {
            // 只更新 VMA 中当前文件有效范围，SIGBUS tail 不参与镜像。
            let mapped_len = region.file_mapped_len();
            let Some(region_file_end) = region.file_offset.checked_add(region.len) else {
                continue;
            };
            let Some(mapped_file_end) = region.file_offset.checked_add(mapped_len) else {
                continue;
            };
            let overlap_start = core::cmp::max(write_off, region.file_offset);
            let overlap_end =
                core::cmp::min(core::cmp::min(write_end, region_file_end), mapped_file_end);
            if overlap_end <= overlap_start {
                continue;
            }

            let dst = region
                .start
                .saturating_add(overlap_start.saturating_sub(region.file_offset));
            let src_off = overlap_start.saturating_sub(write_off);
            let len = overlap_end - overlap_start;
            let wrote_resident =
                self.copy_to_resident_user_bytes(dst, &data[src_off..src_off + len]);
            wrote_executable |=
                wrote_resident && region.map_permission().contains(MapPermission::X);
            Self::push_unique_backing_id(&mut refreshed_backings, region.backing_id);
        }
        if wrote_executable {
            self.mark_user_icache_stale();
        }
        self.refresh_mmap_backing_states(refreshed_backings);
        self.debug_assert_user_vm_invariants();
    }

    /// 将 [start, end) 内已驻留的用户页清零（truncate 缩短文件后清理 EOF 残留数据）。
    fn zero_mapped_user_bytes(&mut self, start: usize, end: usize) -> bool {
        let mut cur = start;
        let mut wrote_resident = false;
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
                    wrote_resident = true;
                }
            }
            cur += len;
        }
        wrote_resident
    }

    /// 文件大小变化（truncate/write 扩展）后同步所有映射了该文件的 VMA：
    /// 更新 file_valid_len/sigbus_start，清零 EOF 残留，修正 SIGBUS tail 映射。
    pub fn update_file_vm_size(&mut self, dev: usize, ino: u32, file_size: usize) -> bool {
        // inode size 变化会移动 file_valid_len/SIGBUS tail，并修正 concrete MapArea。
        let updates: Vec<(
            usize,
            usize,
            usize,
            usize,
            usize,
            usize,
            MapPermission,
            usize,
        )> = self
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
                    region.backing_id,
                ))
            })
            .collect();
        if updates.is_empty() {
            return true;
        }

        let mut ok = true;
        let mut wrote_executable = false;

        for (
            start,
            _end,
            old_valid_len,
            new_valid_len,
            old_sigbus,
            new_sigbus,
            perm,
            _backing_id,
        ) in updates.iter().copied()
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
                // shrink 后 EOF 页尾不能暴露旧数据。
                let zero_start = start.saturating_add(new_valid_len);
                let zero_end = start.saturating_add(
                    align_up_to_page(new_valid_len)
                        .min(align_up_to_page(old_valid_len))
                        .min(old_sigbus.saturating_sub(start)),
                );
                if zero_start < zero_end {
                    wrote_executable |= self.zero_mapped_user_bytes(zero_start, zero_end)
                        && perm.contains(MapPermission::X);
                }
            }
        }

        if wrote_executable {
            self.mark_user_icache_stale();
        }

        for (_start, end, _old_valid, _new_valid, old_sigbus, new_sigbus, _perm, _backing_id) in
            updates.iter().copied()
        {
            if new_sigbus < old_sigbus {
                // 新 SIGBUS tail 改回 lazy + U，占位但不允许有效访问。
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

        for (start, _end, _old_valid, new_valid_len, old_sigbus, new_sigbus, perm, _backing_id) in
            updates.iter().copied()
        {
            if new_sigbus > old_sigbus {
                self.unmap_user_range(old_sigbus.into(), new_sigbus.into());
                // 新变有效的页保持 lazy，实际内容由 fault 从文件/cache 装入。
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

        let mut refreshed_backings = Vec::new();
        for (_start, _end, _old_valid, _new_valid, _old_sigbus, _new_sigbus, _perm, backing_id) in
            updates.iter().copied()
        {
            Self::push_unique_backing_id(&mut refreshed_backings, backing_id);
        }
        self.refresh_mmap_backing_states(refreshed_backings);

        self.debug_assert_user_vm_invariants();
        ok
    }

    /// 返回指定 backing_id 对应的文件 Arc。
    pub fn mmap_backing_file(&self, backing_id: usize) -> Option<Arc<dyn File + Send + Sync>> {
        self.mmap_backings.get(&backing_id).map(MmapBacking::file)
    }

    /// 为 region 分配或复用 mmap backing 条目，返回 backing_id（0 表示无需 backing）。
    /// 同一 mm 内相同文件身份的 region 共用同一 backing，统一管理 writeback 状态。
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
        // 同一 mm 内相同 file identity 共用 backing，便于统一 size/writeback 状态。
        if let Some((&id, _existing)) = self
            .mmap_backings
            .iter()
            .find(|(_id, existing)| existing.matches_region(region))
        {
            return id;
        }
        let id = self.next_mmap_backing_id;
        self.next_mmap_backing_id = self.next_mmap_backing_id.saturating_add(1);
        self.mmap_backings.insert(id, backing);
        id
    }

    /// 清理不再被任何 VmRegion 引用的 backing 条目，并刷新剩余 backing 状态。
    pub(super) fn prune_unused_mmap_backings(&mut self) {
        self.mmap_backings.retain(|backing_id, backing| {
            self.vm_regions.iter().any(|region| {
                (region.file_backed || region.shmem_id != 0)
                    && region.backing_id == *backing_id
                    && backing.kind.matches_region(region)
            })
        });
        self.refresh_all_mmap_backing_states();
    }
}
