//! Sparse resident-page ownership indexed by virtual page number.
//!
//! Linux's XArray groups 64 slots in one node on 64-bit systems.  Keep the
//! same fan-out here, but store only present frame values in a
//! compact vector.  A per-mm file mapping therefore no longer allocates and
//! rebalances one `BTreeMap` entry for every resident 4 KiB page.

use super::VirtPageNum;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

const RESIDENT_CHUNK_SHIFT: usize = 6;
const RESIDENT_CHUNK_PAGES: usize = 1 << RESIDENT_CHUNK_SHIFT;
const RESIDENT_CHUNK_MASK: usize = RESIDENT_CHUNK_PAGES - 1;

#[derive(Clone)]
struct ResidentChunk<T> {
    present: u64,
    values: Vec<T>,
}

impl<T> ResidentChunk<T> {
    fn new() -> Self {
        Self {
            present: 0,
            values: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.present == 0
    }

    fn len(&self) -> usize {
        self.values.len()
    }

    fn rank(&self, offset: usize) -> usize {
        debug_assert!(offset < RESIDENT_CHUNK_PAGES);
        let lower = if offset == 0 {
            0
        } else {
            self.present & ((1u64 << offset) - 1)
        };
        lower.count_ones() as usize
    }

    fn get(&self, offset: usize) -> Option<&T> {
        let bit = 1u64 << offset;
        if self.present & bit == 0 {
            return None;
        }
        self.values.get(self.rank(offset))
    }

    fn insert(&mut self, offset: usize, value: T) -> Option<T> {
        let bit = 1u64 << offset;
        let rank = self.rank(offset);
        if self.present & bit != 0 {
            return Some(core::mem::replace(&mut self.values[rank], value));
        }
        self.values.insert(rank, value);
        self.present |= bit;
        None
    }

    fn remove(&mut self, offset: usize) -> Option<T> {
        let bit = 1u64 << offset;
        if self.present & bit == 0 {
            return None;
        }
        let rank = self.rank(offset);
        self.present &= !bit;
        Some(self.values.remove(rank))
    }

    /// Move offsets `[at, 64)` into a sibling chunk without cloning values.
    fn split_off(&mut self, at: usize) -> Self {
        debug_assert!(at < RESIDENT_CHUNK_PAGES);
        let left_mask = if at == 0 { 0 } else { (1u64 << at) - 1 };
        let left_present = self.present & left_mask;
        let right_present = self.present & !left_mask;
        let right_values = self.values.split_off(left_present.count_ones() as usize);
        self.present = left_present;
        Self {
            present: right_present,
            values: right_values,
        }
    }

    fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        let mut present = self.present;
        self.values.iter().map(move |value| {
            let offset = present.trailing_zeros() as usize;
            present &= present - 1;
            (offset, value)
        })
    }

    fn into_entries(self) -> impl Iterator<Item = (usize, T)> {
        let mut present = self.present;
        self.values.into_iter().map(move |value| {
            let offset = present.trailing_zeros() as usize;
            present &= present - 1;
            (offset, value)
        })
    }
}

/// A sparse page-indexed map with one ordered-tree entry per 64-page chunk.
///
/// The owning `MemorySet` lock provides synchronization.  Chunks preserve
/// ascending VPN iteration, and split/move operations keep the existing
/// `MapArea` semantics used by `munmap`, `mprotect`, `mremap`, and fork/COW.
#[derive(Clone)]
pub(super) struct ResidentPageMap<T> {
    chunks: BTreeMap<usize, ResidentChunk<T>>,
    len: usize,
}

impl<T> ResidentPageMap<T> {
    pub(super) fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            len: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn get(&self, vpn: &VirtPageNum) -> Option<&T> {
        let chunk_index = vpn.0 >> RESIDENT_CHUNK_SHIFT;
        let offset = vpn.0 & RESIDENT_CHUNK_MASK;
        self.chunks
            .get(&chunk_index)
            .and_then(|chunk| chunk.get(offset))
    }

    pub(super) fn insert(&mut self, vpn: VirtPageNum, value: T) -> Option<T> {
        let chunk_index = vpn.0 >> RESIDENT_CHUNK_SHIFT;
        let offset = vpn.0 & RESIDENT_CHUNK_MASK;
        let chunk = self.chunks.entry(chunk_index).or_insert_with(|| {
            crate::perf::record_mm_resident_chunk_allocation();
            ResidentChunk::new()
        });
        let old = chunk.insert(offset, value);
        if old.is_none() {
            self.len = self.len.saturating_add(1);
        }
        old
    }

    pub(super) fn remove(&mut self, vpn: &VirtPageNum) -> Option<T> {
        let chunk_index = vpn.0 >> RESIDENT_CHUNK_SHIFT;
        let offset = vpn.0 & RESIDENT_CHUNK_MASK;
        let (removed, empty) = {
            let chunk = self.chunks.get_mut(&chunk_index)?;
            let removed = chunk.remove(offset);
            (removed, chunk.is_empty())
        };
        if empty {
            self.chunks.remove(&chunk_index);
        }
        if removed.is_some() {
            debug_assert!(self.len > 0);
            self.len = self.len.saturating_sub(1);
        }
        removed
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (VirtPageNum, &T)> {
        self.chunks.iter().flat_map(|(&chunk_index, chunk)| {
            chunk.iter().map(move |(offset, value)| {
                (
                    VirtPageNum((chunk_index << RESIDENT_CHUNK_SHIFT) | offset),
                    value,
                )
            })
        })
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = VirtPageNum> + '_ {
        self.iter().map(|(vpn, _)| vpn)
    }

    pub(super) fn into_entries(self) -> impl Iterator<Item = (VirtPageNum, T)> {
        self.chunks.into_iter().flat_map(|(chunk_index, chunk)| {
            chunk.into_entries().map(move |(offset, value)| {
                (
                    VirtPageNum((chunk_index << RESIDENT_CHUNK_SHIFT) | offset),
                    value,
                )
            })
        })
    }

    /// Split at an arbitrary VPN while retaining whole 64-page chunks when
    /// possible.  Only the boundary chunk needs its compact vector divided.
    pub(super) fn split_off(&mut self, at: &VirtPageNum) -> Self {
        let chunk_index = at.0 >> RESIDENT_CHUNK_SHIFT;
        let offset = at.0 & RESIDENT_CHUNK_MASK;
        let mut right = Self {
            chunks: self.chunks.split_off(&chunk_index),
            len: 0,
        };

        if offset != 0
            && let Some(mut boundary) = right.chunks.remove(&chunk_index)
        {
            let right_boundary = boundary.split_off(offset);
            if !boundary.is_empty() {
                self.chunks.insert(chunk_index, boundary);
            }
            if !right_boundary.is_empty() {
                right.chunks.insert(chunk_index, right_boundary);
            }
        }

        right.len = right.chunks.values().map(ResidentChunk::len).sum();
        debug_assert!(right.len <= self.len);
        self.len = self.len.saturating_sub(right.len);
        right
    }
}

impl<T> Default for ResidentPageMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_replace_remove_across_chunks() {
        let mut pages = ResidentPageMap::new();
        assert_eq!(pages.insert(VirtPageNum(1), 10), None);
        assert_eq!(pages.insert(VirtPageNum(63), 20), None);
        assert_eq!(pages.insert(VirtPageNum(64), 30), None);
        assert_eq!(pages.insert(VirtPageNum(130), 40), None);
        assert_eq!(pages.insert(VirtPageNum(64), 31), Some(30));
        assert_eq!(pages.len(), 4);
        assert_eq!(pages.get(&VirtPageNum(64)), Some(&31));
        assert_eq!(pages.remove(&VirtPageNum(63)), Some(20));
        assert_eq!(pages.remove(&VirtPageNum(63)), None);
        assert_eq!(pages.len(), 3);
    }

    #[test]
    fn split_preserves_sorted_sparse_entries() {
        let mut pages = ResidentPageMap::new();
        for vpn in [1, 63, 64, 65, 127, 128, 130] {
            pages.insert(VirtPageNum(vpn), vpn * 10);
        }
        let right = pages.split_off(&VirtPageNum(65));
        let left_keys = pages.keys().map(|vpn| vpn.0).collect::<Vec<_>>();
        let right_entries = right
            .into_entries()
            .map(|(vpn, value)| (vpn.0, value))
            .collect::<Vec<_>>();
        assert_eq!(left_keys.as_slice(), &[1, 63, 64]);
        assert_eq!(
            right_entries.as_slice(),
            &[(65, 650), (127, 1270), (128, 1280), (130, 1300)]
        );
    }
}
