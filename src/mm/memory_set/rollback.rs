use super::*;

pub(super) struct UserRangeSnapshot {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) areas: Vec<MapArea>,
    pub(super) vm_regions: Vec<VmRegion>,
    pub(super) locked_ranges: Vec<(usize, usize)>,
    pub(super) ptes: Vec<(VirtPageNum, PhysPageNum, PTEFlags)>,
    pub(super) backing_entries: Vec<(usize, MmapBacking)>,
    pub(super) next_mmap_backing_id: usize,
}

pub(super) struct UserRangeRollback {
    pub(super) snapshots: Vec<UserRangeSnapshot>,
}
impl UserRangeRollback {
    pub(super) fn capture(memory_set: &MemorySet, ranges: &[(usize, usize)]) -> Self {
        let mut ranges: Vec<(usize, usize)> = ranges
            .iter()
            .copied()
            .filter(|(start, end)| end > start)
            .collect();
        normalize_ranges(&mut ranges);
        let snapshots = ranges
            .into_iter()
            .map(|(start, end)| memory_set.snapshot_user_range(start, end))
            .collect();
        Self { snapshots }
    }

    pub(super) fn restore(self, memory_set: &mut MemorySet) {
        for snapshot in self.snapshots.into_iter().rev() {
            memory_set.restore_user_range(snapshot);
        }
    }
}
