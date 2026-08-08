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
            #[cfg(target_arch = "riscv64")]
            if old_flags.contains(PTEFlags::D) {
                pte_flags.insert(PTEFlags::D);
            }
        }
    }
    pte_flags
}

#[cfg(target_arch = "riscv64")]
#[derive(Clone, Copy)]
pub(super) enum UserExecutablePteMode<'a> {
    Active(&'a AsidContext),
    Inactive,
}

/// 已经物化的页范围。
///
/// `MapArea` 不决定 mmap 语义；它只保存 resident frame 和页表相关状态。
#[derive(Clone)]
pub(super) struct MapArea {
    vpn_range: VPNRange,
    /// 已经分配或共享到本地址空间的物理页。
    data_frames: BTreeMap<VirtPageNum, FrameTracker>,
    /// mprotect(PROT_NONE) 等场景下暂存被拿掉的 PTE 标志。
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

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub(super) fn replace_tracked_frame_batched(
        &mut self,
        vpn: VirtPageNum,
        frame: FrameTracker,
        batch: &mut PageTableUpdateBatch,
    ) {
        if let Some(old_frame) = self.data_frames.insert(vpn, frame) {
            batch.defer_frame(old_frame);
        }
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

    #[cfg(target_arch = "riscv64")]
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

    /// 将 MapArea 按 [start, end) 切成三段：左残段、中间段、右残段。
    /// 左/右段若为空则返回 None；中间段始终存在。
    /// data_frames 和 saved_pte_flags 按 VPN 归属分配到对应段。
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
            // Framed 映射才有独立 frame，按切割点拆分 BTreeMap。
            // split_off(key) 返回 >= key 的部分，原 map 保留 < key 的部分。
            let mut remaining = core::mem::take(&mut self.data_frames);
            right_frames = remaining.split_off(&end); // [end, ...)
            mid_frames = remaining.split_off(&start); // [start, end)
            left_frames = remaining; // [area_start, start)
        }
        // saved_pte_flags（mprotect 暂存的 PTE 标志）同样按 VPN 三分。
        let mut remaining_flags = core::mem::take(&mut self.saved_pte_flags);
        let right_flags = remaining_flags.split_off(&end);
        let mid_flags = remaining_flags.split_off(&start);
        let left_flags = remaining_flags;

        // 仅当左/右实际有页范围时才构造对应段。
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
    pub fn map_one(
        &mut self,
        page_table: &mut PageTable,
        vpn: VirtPageNum,
        #[cfg(target_arch = "riscv64")] executable_mode: UserExecutablePteMode<'_>,
    ) -> bool {
        if self.is_lazy() {
            return true;
        }
        let frame = match self.map_type() {
            MapType::Identical => None,
            MapType::Framed => {
                let Some(frame) = frame_alloc() else {
                    crate::println!("[mm] OOM: frame_alloc failed for vpn={:?}", vpn);
                    return false;
                };
                Some(frame)
            }
            MapType::Lazy => unreachable!(),
        };
        let ppn = frame
            .as_ref()
            .map_or_else(|| PhysPageNum(vpn.0), |frame| frame.ppn);
        let pte_flags = self.pte_flags();
        #[cfg(target_arch = "riscv64")]
        if pte_flags.contains(PTEFlags::U) {
            match executable_mode {
                UserExecutablePteMode::Active(asid) => {
                    if pte_flags.contains(PTEFlags::X) {
                        publish_executable_user_pte(frame.as_ref(), asid, || {
                            page_table.map(vpn, ppn, pte_flags)
                        });
                    } else {
                        page_table.map(vpn, ppn, pte_flags);
                    }
                }
                UserExecutablePteMode::Inactive => {
                    prepare_inactive_user_pte(pte_flags);
                    page_table.map(vpn, ppn, pte_flags);
                }
            }
        } else {
            page_table.map(vpn, ppn, pte_flags);
        }
        #[cfg(not(target_arch = "riscv64"))]
        page_table.map(vpn, ppn, pte_flags);
        if let Some(frame) = frame {
            self.data_frames.insert(vpn, frame);
        }
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

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub(super) fn unmap_one_maybe_batched(
        &mut self,
        page_table: &mut PageTable,
        vpn: VirtPageNum,
        batch: &mut PageTableUpdateBatch,
    ) {
        let changed = page_table.unmap_if_mapped_deferred(vpn);
        if !self.is_identical()
            && let Some(frame) = self.data_frames.remove(&vpn)
        {
            batch.defer_frame(frame);
        }
        self.saved_pte_flags.remove(&vpn);
        if changed {
            batch.record_page(vpn.0 << 12);
        }
    }

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub(super) fn unmap_range_maybe_batched(
        &mut self,
        page_table: &mut PageTable,
        start: VirtPageNum,
        end: VirtPageNum,
        batch: &mut PageTableUpdateBatch,
    ) {
        for vpn in VPNRange::new(start, end) {
            self.unmap_one_maybe_batched(page_table, vpn, batch);
        }
    }

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub(super) fn unmap_batched(
        &mut self,
        page_table: &mut PageTable,
        batch: &mut PageTableUpdateBatch,
    ) {
        for vpn in self.vpn_range {
            self.unmap_one_maybe_batched(page_table, vpn, batch);
        }
    }

    /// 清理内存,并且将内存进行映射,内部使用map_one 逐个映射.
    pub fn map(
        &mut self,
        page_table: &mut PageTable,
        #[cfg(target_arch = "riscv64")] executable_mode: UserExecutablePteMode<'_>,
    ) -> bool {
        if self.is_lazy() {
            return true;
        }
        let mut mapped: Vec<VirtPageNum> = Vec::new();
        for vpn in self.vpn_range {
            if !self.map_one(
                page_table,
                vpn,
                #[cfg(target_arch = "riscv64")]
                executable_mode,
            ) {
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

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub(super) fn map_batched(
        &mut self,
        page_table: &mut PageTable,
        batch: &mut PageTableUpdateBatch,
        #[cfg(target_arch = "riscv64")] executable_mode: UserExecutablePteMode<'_>,
    ) -> bool {
        if self.is_lazy() {
            return true;
        }
        let mut mapped: Vec<VirtPageNum> = Vec::new();
        for vpn in self.vpn_range {
            if !self.map_one(
                page_table,
                vpn,
                #[cfg(target_arch = "riscv64")]
                executable_mode,
            ) {
                // Keep frames from a partially installed mapping alive until
                // any concurrently filled translations have been evicted.
                for vpn in mapped {
                    self.unmap_one_maybe_batched(page_table, vpn, batch);
                }
                if !self.contains_perm(MapPermission::U) {
                    batch.force_kernel_full();
                }
                return false;
            }
            mapped.push(vpn);
        }
        // A newly installed PTE may replace a cached invalid translation even
        // when the mapping itself is supervisor-only.  Per-thread trap-context
        // pages are exactly such mappings: they live in each user page table
        // without `U`, and adjacent or recycled virtual slots can inherit a
        // cached invalid half-entry.  Missing this invalidation can leave a
        // LoongArch hart taking a page-invalid exception on the first trap
        // trampoline store, before it can service a synchronous shootdown IPI.
        batch.record_range(
            self.vpn_range.get_start().0 << 12,
            self.vpn_range.get_end().0 << 12,
        );
        #[cfg(target_arch = "riscv64")]
        if self.contains_perm(MapPermission::U)
            && self.contains_perm(MapPermission::X)
            && matches!(executable_mode, UserExecutablePteMode::Inactive)
        {
            // This page table is not reachable by hardware yet. Constructors
            // may populate bytes after installing the leaves, then coalesce
            // the required per-mm synchronization at the batch boundary.
            batch.mark_icache_stale();
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

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub(super) fn shrink_to_batched(
        &mut self,
        page_table: &mut PageTable,
        new_end: VirtPageNum,
        batch: &mut PageTableUpdateBatch,
    ) {
        for vpn in VPNRange::new(new_end, self.vpn_range.get_end()) {
            self.unmap_one_maybe_batched(page_table, vpn, batch);
        }
        self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
    }
    #[allow(unused)]
    pub fn append_to(
        &mut self,
        page_table: &mut PageTable,
        new_end: VirtPageNum,
        #[cfg(target_arch = "riscv64")] executable_mode: UserExecutablePteMode<'_>,
    ) -> bool {
        if self.is_lazy() {
            self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
            return true;
        }
        let old_end = self.vpn_range.get_end();
        let mut mapped: Vec<VirtPageNum> = Vec::new();
        for vpn in VPNRange::new(old_end, new_end) {
            if !self.map_one(
                page_table,
                vpn,
                #[cfg(target_arch = "riscv64")]
                executable_mode,
            ) {
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
