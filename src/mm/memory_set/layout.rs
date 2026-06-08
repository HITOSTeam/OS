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
    pub fn result_brk(&self) -> usize {
        if self.success {
            self.new_brk
        } else {
            self.old_brk
        }
    }
}

impl MemorySet {
    pub fn reset_user_layout(&mut self, ustack_base: usize) {
        let heap_start = ustack_base
            .saturating_add(USER_STACK_SIZE)
            .saturating_add(USER_HEAP_GAP);
        self.heap_start = heap_start;
        self.brk = heap_start;
        self.mmap_next = DEFAULT_MMAP_BASE;
        self.mmap_aslr_offset = next_mmap_aslr_offset();
        self.clear_mlock_state();
    }

    pub fn heap_start(&self) -> usize {
        self.heap_start
    }

    pub fn brk(&self) -> usize {
        self.brk
    }

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

    fn shrink_brk_with_holes(&mut self, new_end: usize, old_end: usize) {
        let mut cur = new_end;
        while cur < old_end {
            if !self.page_overlaps_mmap_region(cur) {
                self.unmap_heap_vma_range(cur.into(), (cur + PAGE_SIZE).into());
            }
            cur += PAGE_SIZE;
        }
    }

    pub fn heap_size(&self) -> usize {
        self.brk.saturating_sub(self.heap_start)
    }

    pub fn note_mmap_end(&mut self, end: usize) {
        if end > self.mmap_next {
            self.mmap_next = end;
        }
    }

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

    pub(super) fn vm_region_range_overlaps_except(
        &self,
        start: usize,
        end: usize,
        exclude: Option<(usize, usize)>,
    ) -> bool {
        self.vm_regions.any_overlap_except(start, end, exclude)
    }

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

    fn user_range_is_free_except(
        &self,
        start: usize,
        end: usize,
        user_va_top: usize,
        exclude: Option<(usize, usize)>,
    ) -> bool {
        start < end
            && end <= user_va_top
            && !self.map_area_range_overlaps_except(start, end, exclude)
            && !self.vm_region_range_overlaps_except(start, end, exclude)
    }

    pub fn user_range_is_free(&self, start: usize, end: usize, user_va_top: usize) -> bool {
        self.user_range_is_free_except(start, end, user_va_top, None)
    }

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

    pub(super) fn vm_region_user_range(region: VmRegion) -> Option<(usize, usize)> {
        let end = region.end();
        (end > region.start).then_some((region.start, end))
    }

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

    pub fn find_free_mmap_range(
        &self,
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
        self.find_free_user_range_below_from_occupied(
            topdown_floor,
            topdown_ceiling,
            len,
            user_va_top,
            None,
        )
        .or_else(|| self.find_free_user_range_from_occupied(fallback, len, user_va_top, None))
    }
}
