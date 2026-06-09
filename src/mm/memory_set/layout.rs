use super::*;
use crate::config::USER_STACK_GUARD_GAP;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrkUpdate {
    pub old_brk: usize,
    pub new_brk: usize,
    pub heap_start: usize,
    pub old_end: usize,
    pub new_end: usize,
    pub success: bool,
}

impl BrkUpdate {
    /// 返回本次 brk 操作后的实际 brk 值：成功则为 new_brk，失败则保持 old_brk。
    pub fn result_brk(&self) -> usize {
        if self.success {
            self.new_brk
        } else {
            self.old_brk
        }
    }
}

impl MemorySet {
    /// exec 后重置用户地址空间布局：设置堆起始位置、brk、mmap 基址及 ASLR 偏移。
    pub fn reset_user_layout(&mut self, ustack_base: usize) {
        let heap_start = ustack_base
            .saturating_add(USER_STACK_SIZE)
            .saturating_add(USER_HEAP_GAP);
        self.heap_start = heap_start;
        self.brk = heap_start;
        self.mmap_next = DEFAULT_MMAP_BASE;
        self.mmap_topdown_cursor = 0;
        self.mmap_aslr_offset = next_mmap_aslr_offset();
        self.clear_mlock_state();
    }

    /// 返回堆区起始地址（heap_start，exec 后固定不变）。
    pub fn heap_start(&self) -> usize {
        self.heap_start
    }

    /// 返回当前 brk 指针（堆顶，随 sys_brk 移动）。
    pub fn brk(&self) -> usize {
        self.brk
    }

    /// sys_brk 的核心实现：将 brk 移动到 new_brk，跳过被 SysV shm 占用的页，
    /// 并在扩展时检查 overcommit 限制。返回 BrkUpdate 描述本次变更结果。
    pub fn try_update_brk_with_holes<ShmBlocked, OvercommitRejects>(
        &mut self,
        mut new_brk: usize,
        user_va_top: usize,
        relative_compat_max: usize,
        shm_blocks_page: ShmBlocked,
        overcommit_rejects: OvercommitRejects,
    ) -> BrkUpdate
    where
        ShmBlocked: Fn(usize) -> bool,
        OvercommitRejects: Fn(usize) -> bool,
    {
        let old_brk = self.brk;
        let heap_start = self.heap_start;
        if new_brk < heap_start && new_brk <= relative_compat_max {
            if let Some(candidate) = old_brk.checked_add(new_brk) {
                if candidate > old_brk {
                    new_brk = candidate;
                }
            }
        }

        let old_end = align_up_to_page(old_brk);
        let mut result = BrkUpdate {
            old_brk,
            new_brk,
            heap_start,
            old_end,
            new_end: old_end,
            success: false,
        };

        if new_brk < heap_start || new_brk > user_va_top {
            return result;
        }
        let new_end = align_up_to_page(new_brk);
        result.new_end = new_end;
        if new_end > user_va_top {
            return result;
        }
        if new_end > old_end && overcommit_rejects(new_end.saturating_sub(old_end)) {
            return result;
        }

        let ok = if new_end > old_end {
            self.try_grow_brk_with_holes(old_end, new_end, &shm_blocks_page)
        } else if new_end < old_end {
            self.shrink_brk_with_holes(new_end, old_end);
            true
        } else {
            true
        };
        if !ok {
            return result;
        }

        self.brk = new_brk;
        result.success = true;
        self.debug_assert_user_vm_invariants();
        result
    }

    /// 向上扩展堆：将 [old_end, new_end) 中不被 mmap/shm 占用的连续段逐段插入为 lazy heap VMA。
    /// 若任意段插入失败则回滚已插入内容并返回 false。
    fn try_grow_brk_with_holes<ShmBlocked>(
        &mut self,
        old_end: usize,
        new_end: usize,
        shm_blocks_page: &ShmBlocked,
    ) -> bool
    where
        ShmBlocked: Fn(usize) -> bool,
    {
        let perm = MapPermission::R | MapPermission::W | MapPermission::U;
        let mut cur = old_end;
        let mut pending_ranges = Vec::new();
        while cur < new_end {
            if shm_blocks_page(cur) {
                return false;
            }
            if self.page_overlaps_mmap_region_started_before(cur, old_end) {
                cur += PAGE_SIZE;
                continue;
            }
            if self.page_overlaps_mmap_region(cur)
                || self.user_range_fully_mapped(cur.into(), (cur + PAGE_SIZE).into())
            {
                return false;
            }

            let run_start = cur;
            cur += PAGE_SIZE;
            while cur < new_end
                && !shm_blocks_page(cur)
                && !self.page_overlaps_mmap_region_started_before(cur, old_end)
                && !self.page_overlaps_mmap_region(cur)
                && !self.user_range_fully_mapped(cur.into(), (cur + PAGE_SIZE).into())
            {
                cur += PAGE_SIZE;
            }
            pending_ranges.push((run_start, cur));
        }

        let rollback = UserRangeRollback::capture(self, &[(old_end, new_end)]);
        for (run_start, run_end) in pending_ranges {
            if !self.try_insert_heap_lazy_range(run_start, run_end, perm) {
                rollback.restore(self);
                return false;
            }
        }
        true
    }

    /// 向下收缩堆：逐页解除 [new_end, old_end) 中不属于 mmap 区域的堆映射。
    fn shrink_brk_with_holes(&mut self, new_end: usize, old_end: usize) {
        let mut cur = new_end;
        while cur < old_end {
            if !self.page_overlaps_mmap_region(cur) {
                self.unmap_heap_vma_range(cur.into(), (cur + PAGE_SIZE).into());
            }
            cur += PAGE_SIZE;
        }
    }

    /// 返回当前堆大小（字节），即 brk - heap_start。
    pub fn heap_size(&self) -> usize {
        self.brk.saturating_sub(self.heap_start)
    }

    /// 记录一次 mmap 结束地址，用于维护 mmap_next 水位线（top-down 搜索的下界参考）。
    pub fn note_mmap_end(&mut self, end: usize) {
        if end > self.mmap_next {
            self.mmap_next = end;
        }
    }

    /// 检查 [start, end) 是否与已有的 area（页表映射段）存在重叠，可通过 exclude 排除一个区间。
    pub(super) fn map_area_range_overlaps_except(
        &self,
        start: usize,
        end: usize,
        exclude: Option<(usize, usize)>,
    ) -> bool {
        let start_vpn = VirtAddr::from(start).floor();
        let end_vpn = VirtAddr::from(end).ceil();
        self.areas.iter().any(|area| {
            let area_start = area.start_vpn().0.saturating_mul(PAGE_SIZE);
            let area_end = area.end_vpn().0.saturating_mul(PAGE_SIZE);
            range_overlaps_except(start, end, area_start, area_end, exclude)
                && area.overlaps_vpn_range(start_vpn, end_vpn)
        })
    }

    /// 检查 [start, end) 是否与 vm_regions（VMA 账簿）存在重叠，可排除一个区间。
    pub(super) fn vm_region_range_overlaps_except(
        &self,
        start: usize,
        end: usize,
        exclude: Option<(usize, usize)>,
    ) -> bool {
        self.vm_regions.any_overlap_except(start, end, exclude)
    }

    /// 检查 [start, end) 是否与任意 growsdown VMA 的保护间隙（guard gap）重叠，可排除一个区间。
    fn growdown_guard_range_overlaps_except(
        &self,
        start: usize,
        end: usize,
        exclude: Option<(usize, usize)>,
    ) -> bool {
        self.vm_regions.iter().any(|region| {
            if !region.growsdown {
                return false;
            }
            if exclude.is_some_and(|(exclude_start, exclude_end)| {
                region.start >= exclude_start && region.end() <= exclude_end
            }) {
                return false;
            }
            let guard_start = region.start.saturating_sub(USER_STACK_GUARD_GAP);
            range_overlaps_except(start, end, guard_start, region.start, exclude)
        })
    }

    /// [start, end) 在用户地址空间中完全空闲（不与 area 或 vm_region 重叠），可排除一个区间。
    fn user_range_is_free_except(
        &self,
        start: usize,
        end: usize,
        user_va_top: usize,
        exclude: Option<(usize, usize)>,
    ) -> bool {
        let concrete_overlap = if cfg!(debug_assertions) {
            self.map_area_range_overlaps_except(start, end, exclude)
        } else {
            false
        };
        start < end
            && end <= user_va_top
            && !concrete_overlap
            && !self.vm_region_range_overlaps_except(start, end, exclude)
    }

    /// [start, end) 在用户地址空间中完全空闲（公开接口，无排除区间）。
    pub fn user_range_is_free(&self, start: usize, end: usize, user_va_top: usize) -> bool {
        self.user_range_is_free_except(start, end, user_va_top, None)
    }

    /// [start, end) 空闲且不落入任何 growsdown VMA 的 guard gap，即可安全放置新 mmap。
    fn user_range_is_mmap_placeable_except(
        &self,
        start: usize,
        end: usize,
        user_va_top: usize,
        exclude: Option<(usize, usize)>,
    ) -> bool {
        self.user_range_is_free_except(start, end, user_va_top, exclude)
            && !self.growdown_guard_range_overlaps_except(start, end, exclude)
    }

    /// 将 VmRegion 转换为 (start, end) 用户地址对；若区间为空则返回 None。
    pub(super) fn vm_region_user_range(region: VmRegion) -> Option<(usize, usize)> {
        let end = region.end();
        (end > region.start).then_some((region.start, end))
    }

    /// 按地址升序遍历所有 vm_region 的用户地址范围，回调返回 false 时提前终止。
    fn for_each_occupied_user_range_ascending<F>(&self, mut f: F) -> bool
    where
        F: FnMut(usize, usize) -> bool,
    {
        for region in self.vm_regions.iter().copied() {
            if let Some((start, end)) = Self::vm_region_user_range(region) {
                if !f(start, end) {
                    return false;
                }
            }
        }
        true
    }

    /// 按地址降序遍历所有 vm_region 的用户地址范围，回调返回 false 时提前终止。
    fn for_each_occupied_user_range_descending<F>(&self, mut f: F) -> bool
    where
        F: FnMut(usize, usize) -> bool,
    {
        for region in self.vm_regions.iter().rev().copied() {
            if let Some((start, end)) = Self::vm_region_user_range(region) {
                if !f(start, end) {
                    return false;
                }
            }
        }
        true
    }

    /// 从 min_start 开始向上扫描，找到第一个可放置 len 字节映射的空闲页对齐区间（低地址优先）。
    fn find_free_user_range_from_occupied(
        &self,
        min_start: usize,
        len: usize,
        user_va_top: usize,
        exclude: Option<(usize, usize)>,
    ) -> Option<usize> {
        if len == 0 {
            return None;
        }
        let mut cursor = align_up_to_page(min_start);
        let mut found = None;
        let mut overflowed = false;
        self.for_each_occupied_user_range_ascending(|range_start, range_end| {
            if range_end <= cursor {
                return true;
            }
            while cursor < range_start {
                let Some(end) = cursor.checked_add(len) else {
                    overflowed = true;
                    return false;
                };
                if end <= range_start {
                    if self.user_range_is_mmap_placeable_except(cursor, end, user_va_top, exclude) {
                        found = Some(cursor);
                        return false;
                    }
                    let Some(next_cursor) = cursor.checked_add(PAGE_SIZE) else {
                        overflowed = true;
                        return false;
                    };
                    cursor = next_cursor;
                } else {
                    break;
                }
            }
            cursor = align_up_to_page(range_end);
            true
        });
        if found.is_some() || overflowed {
            return found;
        }
        loop {
            let end = cursor.checked_add(len)?;
            if end > user_va_top || cursor >= end {
                return None;
            }
            if self.user_range_is_mmap_placeable_except(cursor, end, user_va_top, exclude) {
                return Some(cursor);
            }
            cursor = cursor.checked_add(PAGE_SIZE)?;
        }
    }

    /// 在 [hole_start, hole_end) 内从高地址向低地址扫描，找到可放置 len 字节的起始地址。
    fn find_placeable_user_range_in_hole_down(
        &self,
        hole_start: usize,
        hole_end: usize,
        len: usize,
        user_va_top: usize,
        exclude: Option<(usize, usize)>,
    ) -> Option<usize> {
        if len == 0 || hole_end <= hole_start || hole_end.saturating_sub(hole_start) < len {
            return None;
        }
        let mut cursor = align_down_to_page(hole_end.checked_sub(len)?);
        loop {
            let end = cursor.checked_add(len)?;
            if cursor < hole_start || end > hole_end {
                return None;
            }
            if self.user_range_is_mmap_placeable_except(cursor, end, user_va_top, exclude) {
                return Some(cursor);
            }
            if cursor < PAGE_SIZE {
                return None;
            }
            cursor = cursor.saturating_sub(PAGE_SIZE);
        }
    }

    /// 在 [min_start, max_end) 内从高地址向低地址扫描各空洞，找到可放置 len 字节的起始地址（top-down）。
    fn find_free_user_range_below_from_occupied(
        &self,
        min_start: usize,
        max_end: usize,
        len: usize,
        user_va_top: usize,
        exclude: Option<(usize, usize)>,
    ) -> Option<usize> {
        if len == 0 {
            return None;
        }
        let min_start = align_up_to_page(min_start);
        let mut cursor_end = align_down_to_page(max_end.min(user_va_top));
        if cursor_end <= min_start {
            return None;
        }
        let mut found = None;
        self.for_each_occupied_user_range_descending(|range_start, range_end| {
            if range_end <= min_start {
                return false;
            }
            if range_start >= cursor_end {
                return true;
            }
            if range_end < cursor_end {
                let hole_start = range_end.max(min_start);
                if let Some(start) = self.find_placeable_user_range_in_hole_down(
                    hole_start,
                    cursor_end,
                    len,
                    user_va_top,
                    exclude,
                ) {
                    found = Some(start);
                    return false;
                }
            }
            cursor_end = align_down_to_page(range_start.min(cursor_end));
            cursor_end > min_start
        });
        if found.is_some() {
            return found;
        }
        self.find_placeable_user_range_in_hole_down(
            min_start,
            cursor_end,
            len,
            user_va_top,
            exclude,
        )
    }

    /// 为非 MAP_FIXED 的 mmap 找一个合适的起始地址：
    /// 优先尝试 hint（若非空且空闲），否则 top-down 搜索，再回退到 brk 以上的低地址区间。
    pub fn find_free_mmap_range(
        &mut self,
        hint: Option<usize>,
        len: usize,
        user_va_top: usize,
    ) -> Option<usize> {
        if len == 0 {
            return None;
        }
        if let Some(hint) = hint.filter(|hint| *hint != 0) {
            let start = align_down_to_page(hint);
            if let Some(end) = start.checked_add(len) {
                if self.user_range_is_mmap_placeable_except(start, end, user_va_top, None) {
                    return Some(start);
                }
            }
        }
        let fallback = align_up_to_page(self.brk.saturating_add(USER_HEAP_GAP));
        let topdown_floor = fallback.max(DEFAULT_MMAP_BASE);
        let aslr_offset = self
            .mmap_aslr_offset
            .min(user_va_top.saturating_sub(topdown_floor));
        let topdown_ceiling = align_down_to_page(user_va_top.saturating_sub(aslr_offset));

        let cursor_ceiling = if self.mmap_topdown_cursor > topdown_floor
            && self.mmap_topdown_cursor <= topdown_ceiling
        {
            self.mmap_topdown_cursor
        } else {
            topdown_ceiling
        };
        if let Some(start) = cursor_ceiling
            .checked_sub(len)
            .map(align_down_to_page)
            .filter(|start| *start >= topdown_floor)
        {
            let end = start.checked_add(len)?;
            if self.user_range_is_mmap_placeable_except(start, end, user_va_top, None) {
                self.mmap_topdown_cursor = start;
                return Some(start);
            }
        }

        if let Some(start) = self.find_free_user_range_below_from_occupied(
            topdown_floor,
            topdown_ceiling,
            len,
            user_va_top,
            None,
        ) {
            self.mmap_topdown_cursor = start;
            return Some(start);
        }
        let start = self.find_free_user_range_from_occupied(fallback, len, user_va_top, None)?;
        self.mmap_topdown_cursor = start;
        Some(start)
    }
}
