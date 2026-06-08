use super::*;
use bitflags::*;

pub(super) fn shift_vpn_by_delta(vpn: VirtPageNum, delta: isize) -> Option<VirtPageNum> {
    if delta >= 0 {
        vpn.0.checked_add(delta as usize).map(VirtPageNum)
    } else {
        vpn.0.checked_sub(delta.unsigned_abs()).map(VirtPageNum)
    }
}

pub(super) fn pte_flags_for_mprotect(
    new_perm: MapPermission,
    old_flags: Option<PTEFlags>,
) -> PTEFlags {
    let mut pte_flags = PTEFlags::from(new_perm);
    if let Some(old_flags) = old_flags {
        if old_flags.contains(PTEFlags::COW) {
            pte_flags.insert(PTEFlags::COW);
            pte_flags.remove(PTEFlags::W);
            pte_flags.remove(PTEFlags::D);
        }
        if old_flags.contains(PTEFlags::SHARED) {
            pte_flags.insert(PTEFlags::SHARED);
        }
    }
    pte_flags
}

/// map area structure, controls a contiguous piece of virtual memory
#[derive(Clone)]
pub(super) struct MapArea {
    vpn_range: VPNRange,
    data_frames: BTreeMap<VirtPageNum, FrameTracker>,
    saved_pte_flags: BTreeMap<VirtPageNum, PTEFlags>,
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
            saved_pte_flags: BTreeMap::new(),
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
            saved_pte_flags: BTreeMap::new(),
            charged_pages: another.charged_pages,
            map_type: another.map_type,
            map_perm: another.map_perm,
            start_offset: another.start_offset,
        }
    }
    pub(super) fn map_type(&self) -> MapType {
        self.map_type
    }

    pub(super) fn map_perm(&self) -> MapPermission {
        self.map_perm
    }

    pub(super) fn set_map_perm(&mut self, map_perm: MapPermission) {
        self.map_perm = map_perm;
    }

    pub(super) fn contains_perm(&self, perm: MapPermission) -> bool {
        self.map_perm.contains(perm)
    }

    pub(super) fn is_lazy(&self) -> bool {
        self.map_type == MapType::Lazy
    }

    pub(super) fn is_identical(&self) -> bool {
        self.map_type == MapType::Identical
    }

    pub(super) fn pte_flags(&self) -> PTEFlags {
        PTEFlags::from(self.map_perm)
    }

    pub(super) fn vpn_range(&self) -> VPNRange {
        self.vpn_range
    }

    pub(super) fn start_vpn(&self) -> VirtPageNum {
        self.vpn_range.get_start()
    }

    pub(super) fn end_vpn(&self) -> VirtPageNum {
        self.vpn_range.get_end()
    }

    pub(super) fn page_count(&self) -> usize {
        self.end_vpn().0.saturating_sub(self.start_vpn().0)
    }

    pub(super) fn tracked_frame_count(&self) -> usize {
        self.data_frames.len()
    }

    pub(super) fn tracked_vpns(&self) -> impl Iterator<Item = VirtPageNum> + '_ {
        self.data_frames.keys().copied()
    }

    pub(super) fn tracked_frames(&self) -> impl Iterator<Item = (VirtPageNum, &FrameTracker)> + '_ {
        self.data_frames.iter().map(|(&vpn, frame)| (vpn, frame))
    }

    #[cfg(debug_assertions)]
    pub(super) fn saved_flag_vpns(&self) -> impl Iterator<Item = VirtPageNum> + '_ {
        self.saved_pte_flags.keys().copied()
    }

    #[cfg(debug_assertions)]
    pub(super) fn saved_flag_entries(&self) -> impl Iterator<Item = (VirtPageNum, PTEFlags)> + '_ {
        self.saved_pte_flags
            .iter()
            .map(|(&vpn, &flags)| (vpn, flags))
    }

    #[cfg(debug_assertions)]
    pub(super) fn has_saved_pte_flags(&self, vpn: VirtPageNum) -> bool {
        self.saved_pte_flags.contains_key(&vpn)
    }

    pub(super) fn charged_or_tracked_pages(&self) -> usize {
        self.charged_pages.max(self.tracked_frame_count())
    }

    pub(super) fn set_charged_pages(&mut self, charged_pages: usize) {
        self.charged_pages = charged_pages;
    }

    pub(super) fn contains_vpn(&self, vpn: VirtPageNum) -> bool {
        vpn >= self.start_vpn() && vpn < self.end_vpn()
    }

    pub(super) fn overlaps_vpn_range(&self, start: VirtPageNum, end: VirtPageNum) -> bool {
        end > self.start_vpn() && start < self.end_vpn()
    }

    pub(super) fn has_exact_vpn_range(&self, start: VirtPageNum, end: VirtPageNum) -> bool {
        self.start_vpn() == start && self.end_vpn() == end
    }

    pub(super) fn tracked_frame(&self, vpn: VirtPageNum) -> Option<&FrameTracker> {
        self.data_frames.get(&vpn)
    }

    pub(super) fn insert_tracked_frame(&mut self, vpn: VirtPageNum, frame: FrameTracker) {
        self.data_frames.insert(vpn, frame);
    }

    pub(super) fn save_pte_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) {
        self.saved_pte_flags.insert(vpn, flags);
    }

    pub(super) fn take_saved_pte_flags(&mut self, vpn: VirtPageNum) -> Option<PTEFlags> {
        self.saved_pte_flags.remove(&vpn)
    }

    pub(super) fn saved_pte_flags(&self, vpn: VirtPageNum) -> Option<PTEFlags> {
        self.saved_pte_flags.get(&vpn).copied()
    }

    pub(super) fn set_saved_pte_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) -> bool {
        if let Some(saved) = self.saved_pte_flags.get_mut(&vpn) {
            *saved = flags;
            true
        } else {
            false
        }
    }

    pub(super) fn descriptor_with_state(
        &self,
        start: VirtPageNum,
        end: VirtPageNum,
        data_frames: BTreeMap<VirtPageNum, FrameTracker>,
        saved_pte_flags: BTreeMap<VirtPageNum, PTEFlags>,
    ) -> Self {
        let mut area = MapArea::from_another(self);
        area.vpn_range = VPNRange::new(start, end);
        if start != self.start_vpn() {
            area.start_offset = 0;
        }
        area.data_frames = data_frames;
        area.saved_pte_flags = saved_pte_flags;
        area
    }

    pub(super) fn split_around(
        mut self,
        start: VirtPageNum,
        end: VirtPageNum,
    ) -> (Option<Self>, Self, Option<Self>) {
        let area_start = self.start_vpn();
        let area_end = self.end_vpn();
        debug_assert!(start >= area_start && end <= area_end && start < end);

        let mut left_frames = BTreeMap::new();
        let mut mid_frames = BTreeMap::new();
        let mut right_frames = BTreeMap::new();
        if !self.is_identical() {
            let mut remaining = core::mem::take(&mut self.data_frames);
            right_frames = remaining.split_off(&end);
            mid_frames = remaining.split_off(&start);
            left_frames = remaining;
        }
        let mut remaining_flags = core::mem::take(&mut self.saved_pte_flags);
        let right_flags = remaining_flags.split_off(&end);
        let mid_flags = remaining_flags.split_off(&start);
        let left_flags = remaining_flags;

        let left = (area_start < start)
            .then(|| self.descriptor_with_state(area_start, start, left_frames, left_flags));
        let mid = self.descriptor_with_state(start, end, mid_frames, mid_flags);
        let right = (end < area_end)
            .then(|| self.descriptor_with_state(end, area_end, right_frames, right_flags));
        (left, mid, right)
    }

    pub(super) fn move_by_delta(mut self, delta: isize) -> Option<Self> {
        let new_start = shift_vpn_by_delta(self.start_vpn(), delta)?;
        let new_end = shift_vpn_by_delta(self.end_vpn(), delta)?;
        self.vpn_range = VPNRange::new(new_start, new_end);

        if !self.is_identical() {
            let mut remapped = BTreeMap::new();
            for (vpn, frame) in self.data_frames {
                remapped.insert(shift_vpn_by_delta(vpn, delta)?, frame);
            }
            self.data_frames = remapped;
        }
        let mut remapped_flags = BTreeMap::new();
        for (vpn, flags) in self.saved_pte_flags {
            remapped_flags.insert(shift_vpn_by_delta(vpn, delta)?, flags);
        }
        self.saved_pte_flags = remapped_flags;
        Some(self)
    }

    pub(super) fn unmap_range_maybe(
        &mut self,
        page_table: &mut PageTable,
        start: VirtPageNum,
        end: VirtPageNum,
    ) {
        for vpn in VPNRange::new(start, end) {
            self.unmap_one_maybe(page_table, vpn);
        }
    }

    /// map _one 两种映射类型.其中恒等映射 本人是不持有 frame 的.
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> bool {
        if self.is_lazy() {
            return true;
        }
        let ppn: PhysPageNum = match self.map_type() {
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
        let pte_flags = self.pte_flags();
        page_table.map(vpn, ppn, pte_flags);
        true
    }
    #[allow(unused)]
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if !self.is_identical() {
            self.data_frames.remove(&vpn);
        }
        self.saved_pte_flags.remove(&vpn);
        if self.is_lazy() {
            page_table.unmap_if_mapped(vpn);
        } else {
            page_table.unmap(vpn);
        }
    }

    pub fn unmap_one_maybe(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if !self.is_identical() {
            self.data_frames.remove(&vpn);
        }
        self.saved_pte_flags.remove(&vpn);
        page_table.unmap_if_mapped(vpn);
    }

    /// 清理内存,并且将内存进行映射,内部使用map_one 逐个映射.
    pub fn map(&mut self, page_table: &mut PageTable) -> bool {
        if self.is_lazy() {
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
            self.unmap_one_maybe(page_table, vpn);
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
        if self.is_lazy() {
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

    pub fn prepend_to(&mut self, _page_table: &mut PageTable, new_start: VirtPageNum) -> bool {
        if !self.is_lazy() {
            return false;
        }
        self.vpn_range = VPNRange::new(new_start, self.vpn_range.get_end());
        self.start_offset = 0;
        true
    }

    /// data: start-aligned but maybe with shorter length
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &PageTable, data: &[u8]) {
        assert_eq!(self.map_type(), MapType::Framed);
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
