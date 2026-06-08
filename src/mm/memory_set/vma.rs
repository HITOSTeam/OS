use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmRegionKind {
    Mmap,
    Heap,
    Elf,
    Stack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmRegion {
    pub kind: VmRegionKind,
    pub start: usize,
    pub len: usize,
    /// User-visible protection bits kept for procfs/stat-style reporting.
    pub prot: usize,
    /// Core mapping strategy for this VMA. `MapArea` still owns the concrete
    /// frames/page-table state; this field keeps syscall-visible VMA metadata
    /// in the same object so later fault handling can stop re-deriving it.
    pub map_type: MapType,
    pub map_perm: MapPermission,
    /// Number of bytes from `start` that correspond to current file contents.
    /// Bytes in the last mapped page beyond this length are zero-fill tail and
    /// must not be written back by msync.
    pub file_valid_len: usize,
    /// Start address (inclusive) of the SIGBUS tail for file mappings.
    /// `>= end()` means no SIGBUS tail.
    pub sigbus_start: usize,
    pub shared: bool,
    /// False for shared file mappings on descriptors without write access.
    pub may_write_upgrade: bool,
    /// File-backed mapping identity for write/mmap coherence.
    pub file_backed: bool,
    pub file_dev: usize,
    pub file_ino: u32,
    pub file_offset: usize,
    /// Stable backing entry for file-backed mmap writeback after close(fd).
    pub backing_id: usize,
    /// Non-zero for `PseudoShmFile`/memfd-backed mappings.
    pub memfd_id: u64,
    /// Non-zero for System V shared memory mappings.
    pub sysv_shmid: usize,
    /// Whether this region should expand downward on guard-page faults.
    pub growsdown: bool,
}

pub enum VmaInsertArea {
    Lazy {
        start: usize,
        end: usize,
    },
    Framed {
        start: usize,
        end: usize,
    },
    SharedFrames {
        start: usize,
        end: usize,
        frames: Vec<FrameTracker>,
    },
}

impl VmaInsertArea {
    pub(super) fn bounds(&self) -> (usize, usize) {
        match self {
            Self::Lazy { start, end, .. }
            | Self::Framed { start, end, .. }
            | Self::SharedFrames { start, end, .. } => (*start, *end),
        }
    }

    pub(super) fn map_type(&self) -> MapType {
        match self {
            Self::Lazy { .. } => MapType::Lazy,
            Self::Framed { .. } | Self::SharedFrames { .. } => MapType::Framed,
        }
    }

    pub(super) fn frame_count_matches_range(&self) -> bool {
        let (start, end) = self.bounds();
        if end <= start {
            return true;
        }
        match self {
            Self::SharedFrames { frames, .. } => {
                (end - start) % PAGE_SIZE == 0 && frames.len() == (end - start) / PAGE_SIZE
            }
            _ => true,
        }
    }

    pub(super) fn compatible_with_region(&self, region: &VmRegion) -> bool {
        let (start, end) = self.bounds();
        if end <= start {
            return true;
        }
        if start < region.start || end > region.end() || !self.frame_count_matches_range() {
            return false;
        }

        let file_like = region.file_backed || region.memfd_id != 0 || region.sysv_shmid != 0;
        if start >= region.sigbus_start() {
            return file_like && self.map_type() == MapType::Lazy;
        }
        if end > region.sigbus_start() {
            return false;
        }

        match region.map_type {
            MapType::Lazy => self.map_type() == MapType::Lazy,
            MapType::Framed => self.map_type() == MapType::Framed,
            MapType::Identical => false,
        }
    }

    pub(super) fn concrete_permission_from_region(
        &self,
        region: &VmRegion,
    ) -> Option<MapPermission> {
        self.compatible_with_region(region).then(|| {
            let (start, _end) = self.bounds();
            if start >= region.sigbus_start() {
                MapPermission::U
            } else {
                region.map_permission()
            }
        })
    }
}
#[derive(Clone, Default)]
pub(super) struct VmRegionSet {
    pub(super) regions: BTreeMap<usize, VmRegion>,
}

impl VmRegionSet {
    pub(super) fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
        }
    }

    pub(super) fn iter(&self) -> alloc::collections::btree_map::Values<'_, usize, VmRegion> {
        self.regions.values()
    }

    pub(super) fn to_vec(&self) -> Vec<VmRegion> {
        self.regions.values().copied().collect()
    }

    pub(super) fn push_merged(&mut self, region: VmRegion) {
        self.insert_merged(region);
    }

    pub(super) fn insert_unmerged(&mut self, region: VmRegion) {
        if region.len == 0 {
            return;
        }
        #[cfg(debug_assertions)]
        {
            if let Some((_key, prev)) = self.regions.range(..region.start).next_back() {
                debug_assert!(
                    prev.end() <= region.start,
                    "VmRegionSet insert overlaps predecessor: prev={:#x}..{:#x}, new={:#x}..{:#x}",
                    prev.start,
                    prev.end(),
                    region.start,
                    region.end()
                );
            }
            if let Some((_key, next)) = self.regions.range(region.start..).next() {
                debug_assert!(
                    region.end() <= next.start,
                    "VmRegionSet insert overlaps successor: new={:#x}..{:#x}, next={:#x}..{:#x}",
                    region.start,
                    region.end(),
                    next.start,
                    next.end()
                );
            }
        }
        let old = self.regions.insert(region.start, region);
        debug_assert!(old.is_none(), "VmRegionSet replaced an existing start key");
    }

    pub(super) fn insert_merged(&mut self, region: VmRegion) {
        if region.len == 0 {
            return;
        }
        let mut region = region;

        if let Some((&prev_key, prev)) = self.regions.range(..region.start).next_back() {
            let mut prev = *prev;
            if prev.merge_with(region) {
                self.regions.remove(&prev_key);
                region = prev;
            }
        }

        loop {
            let next_key = region.end();
            let Some(next) = self.regions.get(&next_key).copied() else {
                break;
            };
            if !region.merge_with(next) {
                break;
            }
            self.regions.remove(&next_key);
        }

        self.insert_unmerged(region);
    }

    pub(super) fn containing_addr(&self, addr: usize) -> Option<VmRegion> {
        self.regions
            .range(..=addr)
            .next_back()
            .and_then(|(_start, region)| (addr < region.end()).then_some(*region))
    }

    pub(super) fn overlaps_range(&self, start: usize, end: usize) -> bool {
        self.any_overlap_where(start, end, |_| true)
    }

    pub(super) fn covers_range(&self, start: usize, end: usize) -> bool {
        if end <= start {
            return true;
        }
        let mut cursor = start;
        while cursor < end {
            let Some(region) = self.containing_addr(cursor) else {
                return false;
            };
            let region_end = region.end();
            if region_end <= cursor {
                return false;
            }
            cursor = core::cmp::min(region_end, end);
        }
        true
    }

    pub(super) fn first_overlap_before_or_at(&self, start: usize, end: usize) -> Option<VmRegion> {
        if end <= start {
            return None;
        }
        self.regions
            .range(..=start)
            .next_back()
            .and_then(|(_key, region)| region.overlaps(start, end).then_some(*region))
    }

    pub(super) fn any_overlap_except(
        &self,
        start: usize,
        end: usize,
        exclude: Option<(usize, usize)>,
    ) -> bool {
        self.any_overlap_where(start, end, |region| {
            range_overlaps_except(start, end, region.start, region.end(), exclude)
        })
    }

    pub(super) fn any_overlap_where<F>(&self, start: usize, end: usize, mut pred: F) -> bool
    where
        F: FnMut(VmRegion) -> bool,
    {
        if end <= start {
            return false;
        }
        if let Some(region) = self.first_overlap_before_or_at(start, end) {
            if pred(region) {
                return true;
            }
        }
        self.regions
            .range(start.saturating_add(1)..end)
            .any(|(_key, region)| pred(*region))
    }

    pub(super) fn collect_overlaps_where<F>(
        &self,
        start: usize,
        end: usize,
        mut pred: F,
    ) -> Vec<VmRegion>
    where
        F: FnMut(VmRegion) -> bool,
    {
        let mut out = Vec::new();
        if end <= start {
            return out;
        }
        if let Some(region) = self.first_overlap_before_or_at(start, end) {
            if pred(region) {
                out.push(region);
            }
        }
        out.extend(
            self.regions
                .range(start.saturating_add(1)..end)
                .filter_map(|(_key, region)| pred(*region).then_some(*region)),
        );
        out
    }

    pub(super) fn snapshot_range(&self, start: usize, end: usize) -> Vec<VmRegion> {
        let mut out = Vec::new();
        if end <= start {
            return out;
        }
        if let Some(region) = self.first_overlap_before_or_at(start, end) {
            let ov_start = core::cmp::max(start, region.start);
            let ov_end = core::cmp::min(end, region.end());
            if ov_start < ov_end {
                out.push(region.slice(ov_start, ov_end - ov_start));
            }
        }
        for region in self
            .regions
            .range(start.saturating_add(1)..end)
            .map(|(_, region)| *region)
        {
            let ov_start = core::cmp::max(start, region.start);
            let ov_end = core::cmp::min(end, region.end());
            if ov_start < ov_end {
                out.push(region.slice(ov_start, ov_end - ov_start));
            }
        }
        out
    }

    pub(super) fn trim_range(&mut self, start: usize, end: usize) {
        let overlaps = self.collect_overlaps_where(start, end, |_| true);
        for region in overlaps {
            self.regions.remove(&region.start);
            let r_end = region.end();
            if start > region.start {
                self.insert_merged(region.slice(region.start, start - region.start));
            }
            if end < r_end {
                self.insert_merged(region.slice(end, r_end - end));
            }
        }
    }

    pub(super) fn trim_heap_range(&mut self, start: usize, end: usize) {
        let overlaps = self.collect_overlaps_where(start, end, |region| region.is_heap());
        for region in overlaps {
            self.regions.remove(&region.start);
            let r_end = region.end();
            if start > region.start {
                self.insert_merged(region.slice(region.start, start - region.start));
            }
            if end < r_end {
                self.insert_merged(region.slice(end, r_end - end));
            }
        }
    }

    pub(super) fn can_mprotect_range(&self, start: usize, end: usize, new_prot: usize) -> bool {
        let asks_write = VmRegion::permission_from_prot(new_prot).contains(MapPermission::W);

        self.iter().all(|region| {
            if !region.overlaps(start, end) {
                return true;
            }
            !asks_write
                || region.map_permission().contains(MapPermission::W)
                || region.may_write_upgrade
        })
    }

    pub(super) fn apply_mprotect_range(
        &mut self,
        start: usize,
        end: usize,
        new_prot: usize,
    ) -> Result<(), ()> {
        let overlaps = self.collect_overlaps_where(start, end, |_| true);
        for region in overlaps.iter().copied() {
            let r_end = region.end();
            let ov_start = core::cmp::max(start, region.start);
            let ov_end = core::cmp::min(end, r_end);
            let mid = region.slice(ov_start, ov_end - ov_start);
            if VmRegion::permission_from_prot(new_prot).contains(MapPermission::W)
                && !mid.map_permission().contains(MapPermission::W)
                && !mid.may_write_upgrade
            {
                return Err(());
            }
        }

        for region in overlaps {
            self.regions.remove(&region.start);
            let r_end = region.end();
            if start > region.start {
                self.insert_merged(region.slice(region.start, start - region.start));
            }
            let ov_start = core::cmp::max(start, region.start);
            let ov_end = core::cmp::min(end, r_end);
            let mut mid = region.slice(ov_start, ov_end - ov_start);
            mid.set_prot(new_prot);
            self.insert_merged(mid);
            if end < r_end {
                self.insert_merged(region.slice(end, r_end - end));
            }
        }
        Ok(())
    }

    pub(super) fn move_range_metadata_raw(
        &mut self,
        old_addr: usize,
        old_len: usize,
        new_start: usize,
    ) {
        let old_end = old_addr.saturating_add(old_len);
        let overlaps = self.collect_overlaps_where(old_addr, old_end, |_| true);
        for region in overlaps {
            self.regions.remove(&region.start);
            let r_end = region.end();
            let ov_start = core::cmp::max(old_addr, region.start);
            let ov_end = core::cmp::min(old_end, r_end);
            if ov_start > region.start {
                self.insert_merged(region.slice(region.start, ov_start - region.start));
            }
            let moved_start = new_start.saturating_add(ov_start.saturating_sub(old_addr));
            let moved = region
                .slice(ov_start, ov_end - ov_start)
                .move_to(moved_start);
            self.insert_merged(moved);
            if ov_end < r_end {
                self.insert_merged(region.slice(ov_end, r_end - ov_end));
            }
        }
    }

    pub(super) fn isolate_range_raw(&mut self, start: usize, len: usize) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        if start >= end {
            return false;
        }

        let Some(region) = self.containing_addr(start) else {
            return false;
        };
        let r_end = region.end();
        if end > r_end {
            return false;
        }

        self.regions.remove(&region.start);
        if start > region.start {
            self.insert_unmerged(region.slice(region.start, start - region.start));
        }
        self.insert_unmerged(region.slice(start, len));
        if end < r_end {
            self.insert_unmerged(region.slice(end, r_end - end));
        }
        true
    }

    pub(super) fn set_len_by_start(&mut self, start: usize, len: usize) -> bool {
        let Some(mut region) = self.regions.remove(&start) else {
            return false;
        };
        region.set_len(len);
        self.insert_merged(region);
        true
    }

    pub(super) fn set_len_and_file_valid_by_start(
        &mut self,
        start: usize,
        len: usize,
        file_valid_len: usize,
    ) -> bool {
        let Some(mut region) = self.regions.remove(&start) else {
            return false;
        };
        region.set_len_and_file_valid(len, file_valid_len);
        self.insert_merged(region);
        true
    }

    pub(super) fn set_file_valid_by_identity(
        &mut self,
        start: usize,
        dev: usize,
        ino: u32,
        file_valid_len: usize,
        sigbus_start: usize,
    ) -> bool {
        let Some(mut region) = self.regions.remove(&start) else {
            return false;
        };
        if region.file_dev != dev || region.file_ino != ino {
            self.insert_unmerged(region);
            return false;
        }
        region.file_valid_len = file_valid_len;
        region.sigbus_start = sigbus_start;
        self.insert_merged(region);
        true
    }

    pub(super) fn file_copy_targets(
        &mut self,
        dev: usize,
        ino: u32,
        write_off: usize,
        len: usize,
    ) -> Vec<(usize, usize, usize)> {
        let write_end = write_off.saturating_add(len);
        let mut pending = Vec::new();
        for region in self.regions.values_mut() {
            if !region.file_backed || region.file_dev != dev || region.file_ino != ino {
                continue;
            }
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
            let new_valid_len = write_end
                .saturating_sub(region.file_offset)
                .min(mapped_len)
                .min(region.len);
            if new_valid_len > region.file_valid_len {
                region.file_valid_len = new_valid_len;
            }
            pending.push((
                region.start + (overlap_start - region.file_offset),
                overlap_start - write_off,
                overlap_end - overlap_start,
            ));
        }
        pending
    }

    pub(super) fn growsdown_candidate_before(&self, fault_page: usize) -> Option<VmRegion> {
        let old_start = fault_page.checked_add(PAGE_SIZE)?;
        self.regions
            .get(&old_start)
            .copied()
            .filter(|region| region.growsdown)
    }

    pub(super) fn expand_growsdown_at(&mut self, old_start: usize, new_start: usize) -> bool {
        let Some(mut region) = self.regions.remove(&old_start) else {
            return false;
        };
        if !region.growsdown {
            self.regions.insert(old_start, region);
            return false;
        };
        region.expand_down_to(new_start);
        self.push_merged(region);
        true
    }
}
impl VmRegion {
    pub(super) const PROT_READ: usize = 1;
    pub(super) const PROT_WRITE: usize = 2;
    pub(super) const PROT_EXEC: usize = 4;

    pub fn end(&self) -> usize {
        self.start.saturating_add(self.len)
    }

    pub fn overlaps(&self, start: usize, end: usize) -> bool {
        end > self.start && start < self.end()
    }

    pub fn is_mmap(&self) -> bool {
        self.kind == VmRegionKind::Mmap
    }

    pub fn is_heap(&self) -> bool {
        self.kind == VmRegionKind::Heap
    }

    pub fn is_stack(&self) -> bool {
        self.kind == VmRegionKind::Stack
    }

    pub(super) fn is_file_like(&self) -> bool {
        self.file_backed || self.memfd_id != 0 || self.sysv_shmid != 0
    }

    pub(super) fn is_private_anonymous(&self) -> bool {
        !self.shared && !self.is_file_like()
    }

    pub(super) fn can_zero_fill_framed_refault(&self) -> bool {
        self.map_type == MapType::Framed && self.is_stack() && self.is_private_anonymous()
    }

    pub(super) fn can_file_framed_lazy_fault(&self) -> bool {
        self.map_type == MapType::Framed && self.file_backed && self.backing_id != 0
    }

    pub(super) fn can_file_framed_refault(&self) -> bool {
        self.can_file_framed_lazy_fault() && !self.shared
    }

    pub(super) fn can_have_lazy_concrete(&self) -> bool {
        self.map_type == MapType::Lazy
            || self.can_file_framed_lazy_fault()
            || self.can_zero_fill_framed_refault()
    }

    pub fn file_valid_len(&self) -> usize {
        self.file_valid_len.min(self.len)
    }

    pub fn file_valid_end(&self) -> usize {
        self.start.saturating_add(self.file_valid_len())
    }

    pub fn file_mapped_len(&self) -> usize {
        self.sigbus_start().saturating_sub(self.start).min(self.len)
    }

    pub fn sigbus_start(&self) -> usize {
        self.sigbus_start
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

    pub fn prot_from_permission(permission: MapPermission) -> usize {
        let mut prot = 0usize;
        if permission.contains(MapPermission::R) {
            prot |= Self::PROT_READ;
        }
        if permission.contains(MapPermission::W) {
            prot |= Self::PROT_WRITE;
        }
        if permission.contains(MapPermission::X) {
            prot |= Self::PROT_EXEC;
        }
        prot
    }

    pub fn map_permission(&self) -> MapPermission {
        self.map_perm
    }

    pub(super) fn lazy_fault_policy(
        &self,
        fault_va: usize,
        access: MapPermission,
    ) -> Option<(MapPermission, PTEFlags)> {
        if !self.can_have_lazy_concrete() || fault_va >= self.sigbus_start() {
            return None;
        }
        let perm = self.map_permission();
        perm.contains(access).then(|| {
            let mut pte_flags = PTEFlags::from(perm);
            if self.shared {
                pte_flags.insert(PTEFlags::SHARED);
            }
            (perm, pte_flags)
        })
    }

    pub(super) fn allows_cow_fault(&self, fault_va: usize) -> bool {
        fault_va < self.sigbus_start()
            && self.map_permission().contains(MapPermission::W)
            && !self.shared
    }

    pub fn set_prot(&mut self, prot: usize) {
        self.prot = prot;
        self.map_perm = Self::permission_from_prot(prot);
    }

    pub(super) fn set_len(&mut self, len: usize) {
        let old_len = self.len;
        let was_full_valid = self.file_valid_len == old_len;
        let file_like = self.file_backed || self.memfd_id != 0 || self.sysv_shmid != 0;
        if !file_like || was_full_valid {
            self.file_valid_len = len;
        } else {
            self.file_valid_len = self.file_valid_len.min(len);
        }
        self.len = len;
        if !file_like {
            self.sigbus_start = self.end();
        } else if was_full_valid {
            self.sigbus_start = self.end();
        } else {
            self.sigbus_start = self.sigbus_start.clamp(self.start, self.end());
        }
    }

    pub(super) fn set_len_and_file_valid(&mut self, len: usize, file_valid_len: usize) {
        self.set_len(len);
        if self.file_backed || self.memfd_id != 0 || self.sysv_shmid != 0 {
            let valid = file_valid_len.min(len);
            self.file_valid_len = valid;
            self.sigbus_start = self.start.saturating_add(align_up_to_page(valid).min(len));
        } else {
            self.file_valid_len = len;
            self.sigbus_start = self.end();
        }
    }

    pub(super) fn expand_down_to(&mut self, new_start: usize) {
        if new_start >= self.start {
            return;
        }
        let old_len = self.len;
        let grown = self.start - new_start;
        self.start = new_start;
        self.len = self.len.saturating_add(grown);

        if !(self.file_backed || self.memfd_id != 0 || self.sysv_shmid != 0) {
            if self.file_valid_len == old_len {
                self.file_valid_len = self.len;
            }
            self.sigbus_start = self.end();
        } else {
            self.file_valid_len = self.file_valid_len.min(self.len);
            self.sigbus_start = self.sigbus_start.clamp(self.start, self.end());
        }
    }

    pub(super) fn can_merge_with(&self, next: &Self) -> bool {
        self.end() == next.start
            && self.kind == next.kind
            && self.prot == next.prot
            && self.map_type == next.map_type
            && self.map_perm == next.map_perm
            && self.shared == next.shared
            && self.may_write_upgrade == next.may_write_upgrade
            && self.file_backed == next.file_backed
            && self.file_dev == next.file_dev
            && self.file_ino == next.file_ino
            && self.file_offset + self.len == next.file_offset
            && self.file_valid_len == self.len
            && self.backing_id == next.backing_id
            && self.memfd_id == next.memfd_id
            && self.sysv_shmid == next.sysv_shmid
            && self.growsdown == next.growsdown
            && self.sigbus_start == next.sigbus_start
    }

    pub(super) fn merge_with(&mut self, next: Self) -> bool {
        if !self.can_merge_with(&next) {
            return false;
        }
        self.file_valid_len = self
            .file_valid_len
            .saturating_add(next.file_valid_len)
            .min(self.len.saturating_add(next.len));
        self.len += next.len;
        true
    }

    pub(super) fn slice(self, start: usize, len: usize) -> Self {
        let end = start.saturating_add(len);
        let file_delta = start.saturating_sub(self.start);
        let valid_end = self.start.saturating_add(self.file_valid_len.min(self.len));
        Self {
            start,
            len,
            file_offset: self.file_offset.saturating_add(file_delta),
            file_valid_len: valid_end.saturating_sub(start).min(len),
            sigbus_start: self.sigbus_start.clamp(start, end),
            ..self
        }
    }

    pub(super) fn move_to(self, new_start: usize) -> Self {
        let sigbus_delta = self.sigbus_start.saturating_sub(self.start).min(self.len);
        Self {
            start: new_start,
            sigbus_start: new_start.saturating_add(sigbus_delta),
            ..self
        }
    }
}
