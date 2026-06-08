use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SharedFilePageKey {
    dev: usize,
    ino: u32,
    file_page: usize,
}

lazy_static::lazy_static! {
    /// First-stage Linux address_space-like cache for ordinary OSInode-backed
    /// MAP_SHARED pages. Memfd/SysV shm use their own shared-frame objects, and
    /// MAP_PRIVATE must never reuse these frames.
    static ref SHARED_FILE_PAGE_CACHE: Mutex<BTreeMap<SharedFilePageKey, FrameTracker>> =
        Mutex::new(BTreeMap::new());
}

fn shared_file_page_key(dev: usize, ino: u32, file_page: usize) -> SharedFilePageKey {
    SharedFilePageKey {
        dev,
        ino,
        file_page,
    }
}

pub(super) fn shared_file_page_cache_get(
    dev: usize,
    ino: u32,
    file_page: usize,
) -> Option<FrameTracker> {
    SHARED_FILE_PAGE_CACHE
        .lock()
        .get(&shared_file_page_key(dev, ino, file_page))
        .cloned()
}

pub(super) fn shared_file_page_cache_insert_or_get(
    dev: usize,
    ino: u32,
    file_page: usize,
    frame: FrameTracker,
) -> FrameTracker {
    SHARED_FILE_PAGE_CACHE
        .lock()
        .entry(shared_file_page_key(dev, ino, file_page))
        .or_insert(frame)
        .clone()
}

pub(super) fn shared_file_page_cache_write(dev: usize, ino: u32, write_off: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let cache = SHARED_FILE_PAGE_CACHE.lock();
    let mut copied = 0usize;
    while copied < data.len() {
        let file_off = write_off.saturating_add(copied);
        let file_page = file_off / PAGE_SIZE;
        let page_off = file_off & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, data.len() - copied);
        if let Some(frame) = cache.get(&shared_file_page_key(dev, ino, file_page)) {
            frame.ppn.get_bytes_array()[page_off..page_off + chunk]
                .copy_from_slice(&data[copied..copied + chunk]);
        }
        copied += chunk;
    }
}

pub(super) fn shared_file_page_cache_resize(dev: usize, ino: u32, file_size: usize) {
    let eof_page = file_size / PAGE_SIZE;
    let eof_off = file_size & (PAGE_SIZE - 1);
    let remove_from = if eof_off == 0 {
        eof_page
    } else {
        eof_page.saturating_add(1)
    };

    let mut cache = SHARED_FILE_PAGE_CACHE.lock();
    if eof_off != 0
        && let Some(frame) = cache.get(&shared_file_page_key(dev, ino, eof_page))
    {
        frame.ppn.get_bytes_array()[eof_off..PAGE_SIZE].fill(0);
    }

    let stale_keys = cache
        .keys()
        .filter(|key| key.dev == dev && key.ino == ino && key.file_page >= remove_from)
        .copied()
        .collect::<Vec<_>>();
    for key in stale_keys {
        cache.remove(&key);
    }
}

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
    pub(super) vm_state: MmapBackingVmState,
    pub(super) resident_pages: BTreeMap<usize, MmapBackingPageState>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct MmapBackingVmState {
    pub(super) vma_count: usize,
    pub(super) mapped_file_ranges: Vec<(usize, usize)>,
    pub(super) valid_file_ranges: Vec<(usize, usize)>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct MmapBackingPageState {
    pub(super) ref_count: usize,
    pub(super) dirty: bool,
    /// Per-mm page-cache frame for shared file mappings. Private mappings may
    /// share the same backing identity for size/writeback metadata, but their
    /// resident frames must not be reused by MAP_SHARED aliases.
    pub(super) frame: Option<FrameTracker>,
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
            vm_state: MmapBackingVmState::default(),
            resident_pages: BTreeMap::new(),
        })
    }

    pub(super) fn file(&self) -> Arc<dyn File + Send + Sync> {
        Arc::clone(&self.file)
    }

    pub(super) fn matches_region(&self, region: &VmRegion) -> bool {
        self.kind.matches_region(region)
    }

    pub(super) fn resident_frame(&self, file_page: usize) -> Option<FrameTracker> {
        self.resident_pages
            .get(&file_page)
            .and_then(|state| state.frame.as_ref().cloned())
    }

    pub(super) fn add_resident_page_ref(
        &mut self,
        file_page: usize,
        frame: Option<&FrameTracker>,
        dirty: bool,
    ) {
        let state = self.resident_pages.entry(file_page).or_default();
        state.ref_count = state.ref_count.saturating_add(1);
        state.dirty |= dirty;
        if let Some(frame) = frame {
            if let Some(existing) = state.frame.as_ref() {
                debug_assert_eq!(
                    existing.ppn, frame.ppn,
                    "mmap backing file page {} points at multiple shared frames",
                    file_page
                );
            } else {
                state.frame = Some(frame.clone());
            }
        }
    }

    pub(super) fn clear_dirty_page(&mut self, file_page: usize) {
        if let Some(state) = self.resident_pages.get_mut(&file_page) {
            state.dirty = false;
        }
    }

    pub(super) fn replace_resident_pages(&mut self, pages: BTreeMap<usize, MmapBackingPageState>) {
        self.resident_pages = pages;
    }

    pub(super) fn replace_vm_state(&mut self, vm_state: MmapBackingVmState) {
        self.vm_state = vm_state;
    }
}
