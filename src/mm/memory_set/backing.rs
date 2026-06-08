use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MmapBackingKind {
    File { dev: usize, ino: u32 },
    Memfd { id: u64 },
}

impl MmapBackingKind {
    pub(super) fn from_region(region: &VmRegion) -> Option<Self> {
        if region.memfd_id != 0 {
            Some(Self::Memfd {
                id: region.memfd_id,
            })
        } else if region.file_backed {
            Some(Self::File {
                dev: region.file_dev,
                ino: region.file_ino,
            })
        } else {
            None
        }
    }

    pub(super) fn matches_region(self, region: &VmRegion) -> bool {
        match self {
            Self::File { dev, ino } => {
                region.file_backed
                    && region.memfd_id == 0
                    && region.file_dev == dev
                    && region.file_ino == ino
            }
            Self::Memfd { id } => region.memfd_id == id,
        }
    }
}

#[derive(Clone)]
pub(super) struct MmapBacking {
    pub(super) kind: MmapBackingKind,
    pub(super) file: Arc<dyn File + Send + Sync>,
    pub(super) resident_pages: BTreeMap<usize, MmapBackingPageState>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct MmapBackingPageState {
    pub(super) dirty: bool,
}

pub(super) struct MmapWritebackChunk {
    pub(super) file: Arc<dyn File + Send + Sync>,
    pub(super) backing_id: usize,
    pub(super) file_page: usize,
    pub(super) vpn: VirtPageNum,
    pub(super) flags: PTEFlags,
    pub(super) has_valid_pte: bool,
    pub(super) file_offset: usize,
    pub(super) data: Vec<u8>,
}

impl MmapBacking {
    pub(super) fn new(region: &VmRegion, file: &Arc<dyn File + Send + Sync>) -> Option<Self> {
        Some(Self {
            kind: MmapBackingKind::from_region(region)?,
            file: Arc::clone(file),
            resident_pages: BTreeMap::new(),
        })
    }

    pub(super) fn file(&self) -> Arc<dyn File + Send + Sync> {
        Arc::clone(&self.file)
    }

    pub(super) fn mark_resident_page(&mut self, file_page: usize, dirty: bool) {
        let state = self.resident_pages.entry(file_page).or_default();
        state.dirty |= dirty;
    }

    pub(super) fn clear_dirty_page(&mut self, file_page: usize) {
        if let Some(state) = self.resident_pages.get_mut(&file_page) {
            state.dirty = false;
        }
    }

    pub(super) fn replace_resident_pages(&mut self, pages: BTreeMap<usize, MmapBackingPageState>) {
        self.resident_pages = pages;
    }
}
