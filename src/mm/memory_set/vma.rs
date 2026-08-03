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
    /// VMA 类型只用于区分 mmap/heap/ELF/stack 等来源。
    pub kind: VmRegionKind,
    pub start: usize,
    pub len: usize,
    /// 用户传入的 prot 原值，用于 procfs/stat 等对外展示。
    pub prot: usize,
    /// VMA 的映射策略，fault 路径从这里推导页表权限。
    pub map_type: MapType,
    pub map_perm: MapPermission,
    /// 从 start 起有多少字节对应真实文件内容，EOF 后的零填充不能写回。
    pub file_valid_len: usize,
    /// 文件映射的 SIGBUS 尾区起点；大于等于 end() 表示没有尾区。
    pub sigbus_start: usize,
    pub shared: bool,
    /// 共享文件映射若 fd 不可写，则不能通过 mprotect 升级为可写。
    pub may_write_upgrade: bool,
    /// 普通文件映射身份，用于 write 与 mmap 常驻页保持一致。
    pub file_backed: bool,
    pub file_dev: usize,
    pub file_ino: u32,
    pub file_offset: usize,
    /// 稳定 backing 入口，fd 关闭后 msync/munmap 仍可找到文件。
    pub backing_id: usize,
    /// Non-zero for shmem-backed mappings (anonymous memfd or tmpfs inode).
    pub shmem_id: u64,
    /// Non-zero for lazy MAP_SHARED anonymous or /dev/zero mappings.
    pub anon_shared_id: u64,
    /// Non-zero for System V shared memory mappings.
    pub sysv_shmid: usize,
    /// MAP_GROWSDOWN 区域可在 guard page fault 时向下扩展。
    pub growsdown: bool,
    /// fork 继承来的私有匿名 mmap 保留边界，避免和子进程新建 mmap 合并。
    pub fork_inherited_anon: bool,
}

pub enum VmaInsertArea {
    /// 只登记虚拟范围，首次访问时再分配物理页。
    Lazy { start: usize, end: usize },
    /// 立即建立普通私有 frame 映射。
    Framed { start: usize, end: usize },
    /// 立即映射一组外部共享 frame，例如 memfd 或 SysV SHM。
    SharedFrames {
        start: usize,
        end: usize,
        frames: Vec<FrameTracker>,
    },
}

impl VmaInsertArea {
    /// 返回该插入区域的 (start, end) 地址对。
    pub(super) fn bounds(&self) -> (usize, usize) {
        match self {
            Self::Lazy { start, end, .. }
            | Self::Framed { start, end, .. }
            | Self::SharedFrames { start, end, .. } => (*start, *end),
        }
    }

    /// 返回该区域对应的 MapType（Lazy 或 Framed）。
    pub(super) fn map_type(&self) -> MapType {
        match self {
            Self::Lazy { .. } => MapType::Lazy,
            Self::Framed { .. } | Self::SharedFrames { .. } => MapType::Framed,
        }
    }

    /// SharedFrames 时检查 frames 数量是否与地址范围内的页数一致。
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

    /// 检查该区域是否与 VmRegion 兼容：地址范围在 region 内、map_type 匹配、
    /// SIGBUS 尾区只能是 Lazy、SharedFrames 帧数正确。
    pub(super) fn compatible_with_region(&self, region: &VmRegion) -> bool {
        let (start, end) = self.bounds();
        if end <= start {
            return true;
        }
        if start < region.start || end > region.end() || !self.frame_count_matches_range() {
            return false;
        }

        let file_like = region.file_backed || region.shmem_id != 0 || region.sysv_shmid != 0;
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

    /// 根据 region 推导本区域的具体页表权限；
    /// SIGBUS 尾区降为仅 U 位（不可读写，访问触发 SIGBUS）。
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
    anon_private_writable_bytes: usize,
}

impl VmRegionSet {
    pub(super) fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            anon_private_writable_bytes: 0,
        }
    }

    fn committed_charge(region: VmRegion) -> usize {
        if region.is_mmap()
            && region.is_private_anonymous()
            && region.map_permission().contains(MapPermission::W)
        {
            region.len
        } else {
            0
        }
    }

    fn remove_by_start(&mut self, start: usize) -> Option<VmRegion> {
        let region = self.regions.remove(&start)?;
        self.anon_private_writable_bytes = self
            .anon_private_writable_bytes
            .saturating_sub(Self::committed_charge(region));
        Some(region)
    }

    pub(super) fn anon_private_writable_bytes(&self) -> usize {
        self.anon_private_writable_bytes
    }

    /// 按起始地址升序遍历所有 VmRegion。
    pub(super) fn iter(&self) -> alloc::collections::btree_map::Values<'_, usize, VmRegion> {
        self.regions.values()
    }

    /// 复制所有 VmRegion 为 Vec。
    pub(super) fn to_vec(&self) -> Vec<VmRegion> {
        self.regions.values().copied().collect()
    }

    pub(super) fn mark_fork_inherited_anonymous_mmap(&mut self) {
        for region in self.regions.values_mut() {
            if region.kind == VmRegionKind::Mmap && region.is_private_anonymous() {
                region.fork_inherited_anon = true;
            }
        }
    }

    pub(super) fn count_after_insert_merged(&self, region: VmRegion) -> usize {
        if region.len == 0 {
            return self.regions.len();
        }
        let mut count = self.regions.len().saturating_add(1);
        let mut merged = region;

        if let Some((_prev_key, prev)) = self.regions.range(..region.start).next_back() {
            let mut prev = *prev;
            if prev.merge_with(merged) {
                count = count.saturating_sub(1);
                merged = prev;
            }
        }

        loop {
            let Some(next) = self.regions.get(&merged.end()).copied() else {
                break;
            };
            if !merged.merge_with(next) {
                break;
            }
            count = count.saturating_sub(1);
        }

        count
    }

    /// 插入 region 并尝试与相邻 region 合并。
    pub(super) fn push_merged(&mut self, region: VmRegion) {
        self.insert_merged(region);
    }

    /// 插入 region，不合并（debug 下断言无重叠）。
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
        if let Some(old_region) = old {
            self.anon_private_writable_bytes = self
                .anon_private_writable_bytes
                .saturating_sub(Self::committed_charge(old_region));
        }
        self.anon_private_writable_bytes = self
            .anon_private_writable_bytes
            .saturating_add(Self::committed_charge(region));
    }

    /// 插入 region，并尝试与前驱和后继合并以减少碎片。
    pub(super) fn insert_merged(&mut self, region: VmRegion) {
        if region.len == 0 {
            return;
        }
        let mut region = region;

        if let Some((&prev_key, prev)) = self.regions.range(..region.start).next_back() {
            let mut prev = *prev;
            if prev.merge_with(region) {
                self.remove_by_start(prev_key);
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
            self.remove_by_start(next_key);
        }

        self.insert_unmerged(region);
    }

    /// 返回包含 addr 的 VmRegion，若无则返回 None。
    pub(super) fn containing_addr(&self, addr: usize) -> Option<VmRegion> {
        self.regions
            .range(..=addr)
            .next_back()
            .and_then(|(_start, region)| (addr < region.end()).then_some(*region))
    }

    /// [start, end) 是否与任意 VmRegion 重叠。
    pub(super) fn overlaps_range(&self, start: usize, end: usize) -> bool {
        self.any_overlap_where(start, end, |_| true)
    }

    /// [start, end) 是否被已有 VmRegion 完全覆盖（无空洞）。
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

    /// 返回起始地址 <= start 且与 [start, end) 重叠的第一个 VmRegion（用于处理跨越左边界的 region）。
    pub(super) fn first_overlap_before_or_at(&self, start: usize, end: usize) -> Option<VmRegion> {
        if end <= start {
            return None;
        }
        self.regions
            .range(..=start)
            .next_back()
            .and_then(|(_key, region)| region.overlaps(start, end).then_some(*region))
    }

    /// [start, end) 是否与任意 VmRegion 重叠，可排除一个地址区间。
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

    /// [start, end) 是否存在满足谓词 pred 的重叠 VmRegion。
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

    /// 收集 [start, end) 内所有满足谓词的重叠 VmRegion。
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

    /// 对 [start, end) 范围内的 VmRegion 拍快照，裁剪到范围边界后返回。
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

    /// 从账簿中裁掉 [start, end)，与范围重叠的 region 被分割，超出部分保留。
    pub(super) fn trim_range(&mut self, start: usize, end: usize) {
        let overlaps = self.collect_overlaps_where(start, end, |_| true);
        for region in overlaps {
            self.remove_by_start(region.start);
            let r_end = region.end();
            if start > region.start {
                self.insert_merged(region.slice(region.start, start - region.start));
            }
            if end < r_end {
                self.insert_merged(region.slice(end, r_end - end));
            }
        }
    }

    /// 仅裁掉 [start, end) 内属于堆（Heap）的 VmRegion，非堆 region 保留。
    pub(super) fn trim_heap_range(&mut self, start: usize, end: usize) {
        let overlaps = self.collect_overlaps_where(start, end, |region| region.is_heap());
        for region in overlaps {
            self.remove_by_start(region.start);
            let r_end = region.end();
            if start > region.start {
                self.insert_merged(region.slice(region.start, start - region.start));
            }
            if end < r_end {
                self.insert_merged(region.slice(end, r_end - end));
            }
        }
    }

    /// 检查 [start, end) 内所有 region 是否都允许 mprotect 到 new_prot：
    /// 若请求写权限，region 必须原本可写或 may_write_upgrade 为 true。
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

    /// 对 [start, end) 应用 mprotect，将重叠 region 切割后更新中间段的 prot。
    /// 若任意段不允许升级为可写则回滚并返回 Err。
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
            self.remove_by_start(region.start);
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

    /// mremap 元数据迁移：将 [old_addr, old_addr+old_len) 内的 region 移动到以 new_start 开头的新地址。
    pub(super) fn move_range_metadata_raw(
        &mut self,
        old_addr: usize,
        old_len: usize,
        new_start: usize,
    ) {
        let old_end = old_addr.saturating_add(old_len);
        let overlaps = self.collect_overlaps_where(old_addr, old_end, |_| true);
        for region in overlaps {
            self.remove_by_start(region.start);
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

    /// 将 [start, start+len) 从其所在 region 中单独切出，使其成为独立条目（不合并）。
    /// 用于 mremap 等需要精确操作某一子区间的场景。
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

        self.remove_by_start(region.start);
        if start > region.start {
            self.insert_unmerged(region.slice(region.start, start - region.start));
        }
        self.insert_unmerged(region.slice(start, len));
        if end < r_end {
            self.insert_unmerged(region.slice(end, r_end - end));
        }
        true
    }

    /// 按起始地址找到对应 region 并更新其 len，更新后尝试与相邻 region 合并。
    pub(super) fn set_len_by_start(&mut self, start: usize, len: usize) -> bool {
        let Some(mut region) = self.remove_by_start(start) else {
            return false;
        };
        region.set_len(len);
        self.insert_merged(region);
        true
    }

    /// 同时更新 region 的 len 和 file_valid_len，并尝试合并。
    pub(super) fn set_len_and_file_valid_by_start(
        &mut self,
        start: usize,
        len: usize,
        file_valid_len: usize,
    ) -> bool {
        let Some(mut region) = self.remove_by_start(start) else {
            return false;
        };
        region.set_len_and_file_valid(len, file_valid_len);
        self.insert_merged(region);
        true
    }

    /// 按 (start, dev, ino) 定位 region，更新其 file_valid_len 和 sigbus_start。
    /// 用于文件写入后同步扩展文件有效范围。
    pub(super) fn set_file_valid_by_identity(
        &mut self,
        start: usize,
        dev: usize,
        ino: u32,
        file_valid_len: usize,
        sigbus_start: usize,
    ) -> bool {
        let Some(mut region) = self.remove_by_start(start) else {
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

    /// 找出所有 MAP_SHARED 映射了 (dev, ino) 文件
    /// [write_off, write_off+len) 区段的 region，并返回需要同步写入的
    /// (va, file_delta, len) 三元组列表。
    ///
    /// MAP_PRIVATE 的干净页通过 inode page cache 观察 fd write；已经 COW 的
    /// 私有页必须保持匿名快照，不能再由这个旧的虚拟地址镜像路径覆盖。
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
            if !region.shared
                || !region.file_backed
                || region.file_dev != dev
                || region.file_ino != ino
            {
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

    /// 查找紧接在 fault_page 上方（fault_page + PAGE_SIZE）且带 MAP_GROWSDOWN 的 region，
    /// 用于栈向下扩展的 guard page fault 处理。
    pub(super) fn growsdown_candidate_before(&self, fault_page: usize) -> Option<VmRegion> {
        let old_start = fault_page.checked_add(PAGE_SIZE)?;
        self.regions
            .get(&old_start)
            .copied()
            .filter(|region| region.growsdown)
    }

    /// 将 old_start 处的 growsdown region 向下扩展到 new_start。
    pub(super) fn expand_growsdown_at(&mut self, old_start: usize, new_start: usize) -> bool {
        let Some(mut region) = self.remove_by_start(old_start) else {
            return false;
        };
        if !region.growsdown {
            self.insert_unmerged(region);
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

    /// 返回 VMA 的结束地址（start + len，饱和加法）。
    pub fn end(&self) -> usize {
        self.start.saturating_add(self.len)
    }

    /// [start, end) 是否与本 VMA 重叠。
    pub fn overlaps(&self, start: usize, end: usize) -> bool {
        end > self.start && start < self.end()
    }

    pub fn is_mmap(&self) -> bool {
        self.kind == VmRegionKind::Mmap
    }

    fn has_backing_identity(&self) -> bool {
        self.file_backed
            || self.backing_id != 0
            || self.shmem_id != 0
            || self.anon_shared_id != 0
            || self.sysv_shmid != 0
    }

    pub fn is_heap(&self) -> bool {
        self.kind == VmRegionKind::Heap
    }

    pub fn is_stack(&self) -> bool {
        self.kind == VmRegionKind::Stack
    }

    /// 是否有文件或共享内存后端（file_backed / shmem / SysV shm）。
    pub(super) fn is_file_like(&self) -> bool {
        self.file_backed || self.shmem_id != 0 || self.sysv_shmid != 0
    }

    /// 是否为纯私有匿名映射（无任何后端）。
    pub(super) fn is_private_anonymous(&self) -> bool {
        !self.shared && !self.is_file_like()
    }

    /// 栈的私有匿名 Framed 映射可以在 refault 时零填充（COW 页丢失后重建）。
    pub(super) fn can_zero_fill_framed_refault(&self) -> bool {
        self.map_type == MapType::Framed && self.is_stack() && self.is_private_anonymous()
    }

    /// 文件 Framed 映射有 backing_id，可在 fault 时从文件重新装入页。
    pub(super) fn can_file_framed_lazy_fault(&self) -> bool {
        self.map_type == MapType::Framed && self.file_backed && self.backing_id != 0
    }

    /// 私有文件 Framed 映射可 refault（从文件重新装入，不写回）。
    pub(super) fn can_file_framed_refault(&self) -> bool {
        self.can_file_framed_lazy_fault() && !self.shared
    }

    /// 本 VMA 是否支持 lazy 具现化（首次访问时才分配物理页）。
    /// map 类型是lazy的支持，framed 文件映射支持，栈 支持
    pub(super) fn can_have_lazy_concrete(&self) -> bool {
        self.map_type == MapType::Lazy
            || self.can_file_framed_lazy_fault()
            || self.can_zero_fill_framed_refault()
    }

    /// 返回有效文件内容长度（不超过 VMA 总长度）。
    pub fn file_valid_len(&self) -> usize {
        self.file_valid_len.min(self.len)
    }

    /// 返回文件有效内容的结束地址。
    pub fn file_valid_end(&self) -> usize {
        self.start.saturating_add(self.file_valid_len())
    }

    /// 返回文件实际映射长度（sigbus_start 之前的部分）。
    pub fn file_mapped_len(&self) -> usize {
        self.sigbus_start().saturating_sub(self.start).min(self.len)
    }

    pub fn sigbus_start(&self) -> usize {
        self.sigbus_start
    }

    /// 将 mmap prot 标志转换为内核 MapPermission（含 U 位）。
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

    /// 将内核 MapPermission 转换回 mmap prot 标志。
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

    /// 返回 lazy fault 时应建立的 (权限, PTE标志)；
    /// 若该地址不可 lazy 具现化或访问权限不足则返回 None。
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

    /// 该地址是否允许 COW fault（私有可写映射，在 sigbus 区之前）。
    pub(super) fn allows_cow_fault(&self, fault_va: usize) -> bool {
        fault_va < self.sigbus_start()
            && self.map_permission().contains(MapPermission::W)
            && !self.shared
    }

    /// 更新 prot 及对应的 map_perm（mprotect 调用路径）。
    pub fn set_prot(&mut self, prot: usize) {
        self.prot = prot;
        self.map_perm = Self::permission_from_prot(prot);
    }

    /// 更新 VMA 长度，同步修正 file_valid_len 和 sigbus_start。
    pub(super) fn set_len(&mut self, len: usize) {
        let old_len = self.len;
        let was_full_valid = self.file_valid_len == old_len;
        let file_like = self.file_backed || self.shmem_id != 0 || self.sysv_shmid != 0;
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

    /// 同时设置 len 和 file_valid_len，用于文件截断/扩展后的精确更新。
    pub(super) fn set_len_and_file_valid(&mut self, len: usize, file_valid_len: usize) {
        self.set_len(len);
        if self.file_backed || self.shmem_id != 0 || self.sysv_shmid != 0 {
            let valid = file_valid_len.min(len);
            self.file_valid_len = valid;
            self.sigbus_start = self.start.saturating_add(align_up_to_page(valid).min(len));
        } else {
            self.file_valid_len = len;
            self.sigbus_start = self.end();
        }
    }

    /// MAP_GROWSDOWN 栈向下扩展：将 start 移动到 new_start，增大 len。
    pub(super) fn expand_down_to(&mut self, new_start: usize) {
        if new_start >= self.start {
            return;
        }
        let old_len = self.len;
        let grown = self.start - new_start;
        self.start = new_start;
        self.len = self.len.saturating_add(grown);

        if !(self.file_backed || self.shmem_id != 0 || self.sysv_shmid != 0) {
            if self.file_valid_len == old_len {
                self.file_valid_len = self.len;
            }
            self.sigbus_start = self.end();
        } else {
            self.file_valid_len = self.file_valid_len.min(self.len);
            self.sigbus_start = self.sigbus_start.clamp(self.start, self.end());
        }
    }

    /// 检查 self 和 next 是否可合并：要求地址连续且所有语义字段相同。
    pub(super) fn can_merge_with(&self, next: &Self) -> bool {
        let base_compatible = self.end() == next.start
            && self.kind == next.kind
            && self.prot == next.prot
            && self.map_type == next.map_type
            && self.map_perm == next.map_perm
            && self.shared == next.shared
            && self.may_write_upgrade == next.may_write_upgrade
            && self.file_backed == next.file_backed
            && self.file_dev == next.file_dev
            && self.file_ino == next.file_ino
            && self.backing_id == next.backing_id
            && self.shmem_id == next.shmem_id
            && self.anon_shared_id == next.anon_shared_id
            && self.sysv_shmid == next.sysv_shmid
            && self.growsdown == next.growsdown
            && self.fork_inherited_anon == next.fork_inherited_anon;
        if !base_compatible {
            return false;
        }
        if self.shared && !self.has_backing_identity() {
            return false;
        }

        if self.anon_shared_id != 0 {
            return self.file_offset + self.len == next.file_offset
                && self.file_valid_len == self.len
                && next.file_valid_len == next.len
                && self.sigbus_start >= self.end()
                && next.sigbus_start >= next.end();
        }

        if self.has_backing_identity() {
            self.file_offset + self.len == next.file_offset
                && self.file_valid_len == self.len
                && self.sigbus_start == next.sigbus_start
        } else {
            // Anonymous VMAs do not have meaningful file offsets or SIGBUS
            // tails.  Merge adjacent heap/anon pieces based on policy only.
            self.file_valid_len == self.len
                && next.file_valid_len == next.len
                && self.sigbus_start >= self.end()
                && next.sigbus_start >= next.end()
        }
    }

    /// 将 next 合并入 self（地址连续且语义相同时）。失败返回 false，self 不变。
    pub(super) fn merge_with(&mut self, next: Self) -> bool {
        if !self.can_merge_with(&next) {
            return false;
        }
        let anonymous = !self.has_backing_identity();
        self.file_valid_len = self
            .file_valid_len
            .saturating_add(next.file_valid_len)
            .min(self.len.saturating_add(next.len));
        self.len += next.len;
        if anonymous {
            self.file_valid_len = self.len;
            self.sigbus_start = self.end();
        }
        true
    }

    /// 从 VMA 中切出 [start, start+len) 子段，修正 file_offset / file_valid_len / sigbus_start。
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

    /// 将 VMA 平移到 new_start，sigbus_start 同步偏移。
    pub(super) fn move_to(self, new_start: usize) -> Self {
        let sigbus_delta = self.sigbus_start.saturating_sub(self.start).min(self.len);
        Self {
            start: new_start,
            sigbus_start: new_start.saturating_add(sigbus_delta),
            ..self
        }
    }
}
