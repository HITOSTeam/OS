use super::*;

pub(super) fn push_range_merged(ranges: &mut Vec<(usize, usize)>, start: usize, end: usize) {
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

pub(super) fn normalize_ranges(ranges: &mut Vec<(usize, usize)>) {
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = Vec::new();
    for (start, end) in ranges.drain(..) {
        push_range_merged(&mut merged, start, end);
    }
    *ranges = merged;
}

pub(super) fn trim_ranges(ranges: &mut Vec<(usize, usize)>, start: usize, end: usize) {
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

pub(super) fn ranges_total_len(ranges: &[(usize, usize)]) -> usize {
    ranges
        .iter()
        .map(|(start, end)| end.saturating_sub(*start))
        .sum()
}

pub(super) fn ranges_overlap(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    ranges
        .iter()
        .any(|(r_start, r_end)| end > *r_start && start < *r_end)
}

pub(super) fn range_overlap_len(
    start: usize,
    end: usize,
    other_start: usize,
    other_end: usize,
) -> usize {
    let overlap_start = core::cmp::max(start, other_start);
    let overlap_end = core::cmp::min(end, other_end);
    overlap_end.saturating_sub(overlap_start)
}

pub(super) fn range_overlaps_except(
    start: usize,
    end: usize,
    other_start: usize,
    other_end: usize,
    exclude: Option<(usize, usize)>,
) -> bool {
    if end <= other_start || start >= other_end {
        return false;
    }
    let Some((exclude_start, exclude_end)) = exclude else {
        return true;
    };
    let left_end = core::cmp::min(other_end, exclude_start);
    if other_start < left_end && end > other_start && start < left_end {
        return true;
    }
    let right_start = core::cmp::max(other_start, exclude_end);
    right_start < other_end && end > right_start && start < other_end
}

pub(super) fn align_down_to_page(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

pub(super) fn align_up_to_page(len: usize) -> usize {
    len.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE
}

pub(super) fn mix_mmap_aslr_seed(mut seed: usize) -> usize {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    seed
}

pub(super) fn next_mmap_aslr_offset() -> usize {
    let pages = MMAP_ASLR_RANGE / PAGE_SIZE;
    if pages == 0 {
        return 0;
    }
    let seq = MMAP_ASLR_SEQ
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let seed = crate::time::get_time() ^ seq.rotate_left(11);
    (mix_mmap_aslr_seed(seed) % pages) * PAGE_SIZE
}
