//! 单个 MemorySet 内的 file-backed mmap 辅助状态。
//!
//! `VmRegion` 是 VMA 策略源，`MapArea/PTE` 是驻留页状态；这里记录二者之间
//! 需要同步的 backing、dirty 和生命周期信息。

use super::*;
use crate::sync::WaitQueue;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FilePageCacheInodeKey {
    dev: usize,
    ino: u32,
}

const FILE_PAGE_LOADING: u8 = 0;
const FILE_PAGE_READY: u8 = 1;
const FILE_PAGE_INVALIDATED: u8 = 2;

struct FilePageLoadState {
    status: AtomicU8,
    waiters: WaitQueue,
}

impl FilePageLoadState {
    fn new() -> Self {
        Self {
            status: AtomicU8::new(FILE_PAGE_LOADING),
            waiters: WaitQueue::new(),
        }
    }

    /// Wait for the page owner to finish I/O.  As with Linux's locked folio,
    /// the acquire pairs with publication of the initialized page contents.
    fn wait_ready(&self) -> bool {
        self.waiters
            .wait_until(|| self.status.load(Ordering::Acquire) != FILE_PAGE_LOADING);
        self.status.load(Ordering::Acquire) == FILE_PAGE_READY
    }

    fn finish(&self, status: u8) {
        debug_assert!(status == FILE_PAGE_READY || status == FILE_PAGE_INVALIDATED);
        self.status.store(status, Ordering::Release);
        self.waiters.wake_all();
    }
}

enum FilePageCacheSlot {
    /// The frame is already indexed, but must not be mapped until its owner
    /// finishes the filesystem read and publishes `Ready`.
    Loading {
        _frame: FrameTracker,
        state: Arc<FilePageLoadState>,
    },
    Ready(FrameTracker),
}

/// Per-inode page index, corresponding to Linux `inode->i_mapping->i_pages`.
///
/// The former single global `(dev, ino, page)` tree made unrelated rustc
/// workers serialize on every cache write and made each truncate/growth scan
/// every cached page in the system.  The outer table now only resolves the
/// inode mapping; page lookup and invalidation use this inode-local lock.
struct FilePageCacheMapping {
    pages: Mutex<BTreeMap<usize, FilePageCacheSlot>>,
    /// Weak reverse map corresponding to Linux `address_space::i_mmap`.
    /// Stale entries are pruned opportunistically; they never retain an mm.
    mmap_mms: Mutex<Vec<super::mm_ref::WeakMmRef>>,
}

impl FilePageCacheMapping {
    fn new() -> Self {
        Self {
            pages: Mutex::new(BTreeMap::new()),
            mmap_mms: Mutex::new(Vec::new()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FilePageCacheLoadError {
    Oom,
    /// A truncate invalidated the cache slot while its page was being read.
    /// The fault must rebuild its VMA/file-size snapshot before retrying.
    Invalidated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SharedAnonPageKey {
    id: u64,
    page: usize,
}

static NEXT_SHARED_ANON_ID: AtomicUsize = AtomicUsize::new(1);

lazy_static::lazy_static! {
    /// OSInode-backed regular-file address spaces, keyed by inode identity.
    ///
    /// Each value owns an inode-local page tree. Clean MAP_PRIVATE pages and
    /// MAP_SHARED pages both reference the same frame. A private write
    /// replaces that mapping through COW; memfd and SysV shm keep using their
    /// own shared-frame stores.
    static ref FILE_PAGE_MAPPINGS:
        Mutex<BTreeMap<FilePageCacheInodeKey, Arc<FilePageCacheMapping>>> =
        Mutex::new(BTreeMap::new());
    /// MAP_SHARED|MAP_ANONYMOUS 的 lazy 页缓存。
    ///
    /// Linux 对共享匿名映射先建立 VMA，实际物理页到 fault 时才分配；同一 VMA
    /// fork 后的后续 fault 仍必须落到同一共享页。
    static ref SHARED_ANON_PAGE_CACHE: Mutex<BTreeMap<SharedAnonPageKey, FrameTracker>> =
        Mutex::new(BTreeMap::new());
}

fn file_page_cache_inode_key(dev: usize, ino: u32) -> FilePageCacheInodeKey {
    FilePageCacheInodeKey { dev, ino }
}

fn file_page_cache_mapping(
    dev: usize,
    ino: u32,
    create: bool,
) -> Option<Arc<FilePageCacheMapping>> {
    let key = file_page_cache_inode_key(dev, ino);
    let mut mappings = FILE_PAGE_MAPPINGS.lock();
    if let Some(mapping) = mappings.get(&key) {
        return Some(Arc::clone(mapping));
    }
    if !create {
        return None;
    }
    let mapping = Arc::new(FilePageCacheMapping::new());
    mappings.insert(key, Arc::clone(&mapping));
    Some(mapping)
}

pub(super) fn file_page_cache_register_mm(dev: usize, ino: u32, mm: &MmRef) {
    let mapping = file_page_cache_mapping(dev, ino, true)
        .expect("creating a regular-file mmap reverse index cannot fail");
    let weak = mm.downgrade();
    let mut mms = mapping.mmap_mms.lock();
    mms.retain(super::mm_ref::WeakMmRef::is_alive);
    if !mms.iter().any(|existing| existing.ptr_eq(&weak)) {
        mms.push(weak);
    }
}

pub(super) fn file_page_cache_mapped_mms(dev: usize, ino: u32) -> Vec<super::mm_ref::WeakMmRef> {
    let Some(mapping) = file_page_cache_mapping(dev, ino, false) else {
        return Vec::new();
    };
    let mut mms = mapping.mmap_mms.lock();
    mms.retain(super::mm_ref::WeakMmRef::is_alive);
    mms.clone()
}

fn shared_anon_page_key(id: u64, page: usize) -> SharedAnonPageKey {
    SharedAnonPageKey { id, page }
}

pub(super) fn allocate_shared_anon_id() -> u64 {
    NEXT_SHARED_ANON_ID.fetch_add(1, Ordering::Relaxed) as u64
}

/// Find or read one regular-file page through the global inode page cache.
///
/// The first fault inserts a loading slot before starting I/O.  Concurrent
/// faults sleep on that slot and reuse the published frame, matching Linux's
/// `FGP_CREAT|FGP_FOR_MMAP` plus locked-folio protocol instead of issuing one
/// disk read per process.
pub(super) fn file_page_cache_get_or_load<F>(
    dev: usize,
    ino: u32,
    file_page: usize,
    fill: F,
) -> Result<FrameTracker, FilePageCacheLoadError>
where
    F: FnOnce(&mut [u8]),
{
    let mapping = file_page_cache_mapping(dev, ino, true)
        .expect("creating a regular-file page-cache mapping cannot fail");
    let mut fill = Some(fill);
    let mut must_observe_published = false;

    loop {
        let loading = {
            let cache = mapping.pages.lock();
            match cache.get(&file_page) {
                Some(FilePageCacheSlot::Ready(frame)) => return Ok(frame.clone()),
                Some(FilePageCacheSlot::Loading { state, .. }) => Some(Arc::clone(state)),
                None if must_observe_published => {
                    return Err(FilePageCacheLoadError::Invalidated);
                }
                None => None,
            }
        };
        if let Some(state) = loading {
            if !state.wait_ready() {
                return Err(FilePageCacheLoadError::Invalidated);
            }
            // Pin the ready frame under the cache lock on the next iteration.
            // If truncate removes it first, force a fresh VMA/EOF snapshot
            // rather than starting another read from this stale fault plan.
            must_observe_published = true;
            continue;
        }

        // Page allocation and zeroing stay outside the cache metadata lock.
        let candidate = frame_alloc().ok_or(FilePageCacheLoadError::Oom)?;
        let state = Arc::new(FilePageLoadState::new());
        let competing_load = {
            let mut cache = mapping.pages.lock();
            match cache.get(&file_page) {
                Some(FilePageCacheSlot::Ready(frame)) => return Ok(frame.clone()),
                Some(FilePageCacheSlot::Loading { state, .. }) => Some(Arc::clone(state)),
                None => {
                    cache.insert(
                        file_page,
                        FilePageCacheSlot::Loading {
                            _frame: candidate.clone(),
                            state: Arc::clone(&state),
                        },
                    );
                    None
                }
            }
        };
        if let Some(competing_load) = competing_load {
            if !competing_load.wait_ready() {
                return Err(FilePageCacheLoadError::Invalidated);
            }
            must_observe_published = true;
            continue;
        }

        // We own this cache miss.  Fill the zeroed frame without holding the
        // global cache lock or an mm lock.
        fill.take().expect("file page fill called more than once")(candidate.ppn.get_bytes_array());
        // Take and release the owner lock before reacquiring the inode cache
        // lock. A candidate invalidated below is simply dropped; no shared
        // winner is modified.
        candidate.enable_file_icache_tracking();

        let published = {
            let mut cache = mapping.pages.lock();
            let owns_slot = matches!(
                cache.get(&file_page),
                Some(FilePageCacheSlot::Loading { state: current, .. })
                    if Arc::ptr_eq(current, &state)
            );
            if owns_slot {
                cache.insert(file_page, FilePageCacheSlot::Ready(candidate.clone()));
            }
            owns_slot
        };
        if published {
            state.finish(FILE_PAGE_READY);
            return Ok(candidate);
        }

        // truncate removed the loading slot while filesystem I/O was in
        // progress.  Wake coalesced faults and make every caller revalidate
        // its VMA/EOF snapshot before trying again.
        state.finish(FILE_PAGE_INVALIDATED);
        return Err(FilePageCacheLoadError::Invalidated);
    }
}

pub(super) fn shared_anon_page_cache_get(id: u64, page: usize) -> Option<FrameTracker> {
    if id == 0 {
        return None;
    }
    SHARED_ANON_PAGE_CACHE
        .lock()
        .get(&shared_anon_page_key(id, page))
        .cloned()
}

pub(super) fn shared_anon_page_cache_insert_or_get(
    id: u64,
    page: usize,
    frame: FrameTracker,
) -> FrameTracker {
    if id == 0 {
        return frame;
    }
    SHARED_ANON_PAGE_CACHE
        .lock()
        .entry(shared_anon_page_key(id, page))
        .or_insert(frame)
        .clone()
}

/// 将 write 数据同步到全局缓存中已驻留的共享文件页，
/// 保证其他进程后续 fault 能看到最新内容。
pub(super) fn file_page_cache_write(dev: usize, ino: u32, write_off: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let Some(mapping) = file_page_cache_mapping(dev, ino, false) else {
        return;
    };

    let mut copied = 0usize;
    while copied < data.len() {
        let file_off = write_off.saturating_add(copied);
        let file_page = file_off / PAGE_SIZE;
        let page_off = file_off & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, data.len() - copied);
        loop {
            let (frame, loading) = {
                let cache = mapping.pages.lock();
                match cache.get(&file_page) {
                    Some(FilePageCacheSlot::Ready(frame)) => (Some(frame.clone()), None),
                    Some(FilePageCacheSlot::Loading { state, .. }) => {
                        (None, Some(Arc::clone(state)))
                    }
                    None => (None, None),
                }
            };
            if let Some(frame) = frame {
                // Match Linux's xarray/folio split: pin the page under the
                // cache index lock, then lock and mutate its contents outside.
                frame.with_bytes_mut(page_off, chunk, |bytes| {
                    bytes.copy_from_slice(&data[copied..copied + chunk]);
                });
            }
            let Some(state) = loading else {
                break;
            };
            // OSInode's inode lock orders the underlying read and write.  The
            // cache publication may still trail that I/O completion, so wait
            // here to avoid racing two mutable frame copies.
            let _ = state.wait_ready();
        }
        copied += chunk;
    }
}

/// 文件 truncate 后同步缓存：EOF 页尾部清零，超出新 file_size 的缓存页全部丢弃。
pub(super) fn file_page_cache_resize(dev: usize, ino: u32, file_size: usize) {
    let Some(mapping) = file_page_cache_mapping(dev, ino, false) else {
        return;
    };
    let eof_page = file_size / PAGE_SIZE;
    let eof_off = file_size & (PAGE_SIZE - 1);
    let remove_from = if eof_off == 0 {
        eof_page
    } else {
        eof_page.saturating_add(1)
    };

    let mut invalidated = Vec::new();
    let mut eof_frame = None;
    let mut cache = mapping.pages.lock();
    // truncate 后 EOF 页尾清零，EOF 之后的缓存页必须丢弃，避免 shrink/grow 复用旧脏页。
    if eof_off != 0 {
        match cache.get(&eof_page) {
            Some(FilePageCacheSlot::Ready(frame)) => {
                eof_frame = Some(frame.clone());
            }
            Some(FilePageCacheSlot::Loading { state, .. }) => {
                invalidated.push(Arc::clone(state));
                cache.remove(&eof_page);
            }
            None => {}
        }
    }

    // `split_off` is O(log pages-for-this-inode), unlike the former full
    // global-cache scan performed on every file growth or truncate.
    let stale = cache.split_off(&remove_from);
    for (_, slot) in stale {
        if let FilePageCacheSlot::Loading { state, .. } = slot {
            invalidated.push(state);
        }
    }
    drop(cache);
    if let Some(frame) = eof_frame {
        // The pin remains valid if a concurrent invalidation removes the slot;
        // mapped aliases retaining the page still need to observe EOF zeros.
        frame.with_bytes_mut(eof_off, PAGE_SIZE - eof_off, |bytes| bytes.fill(0));
    }
    for state in invalidated {
        state.finish(FILE_PAGE_INVALIDATED);
    }
}

/// 回收没有任何地址空间继续引用的全局共享文件页缓存。
///
/// Linux page cache 可以在内存压力下回收 clean cache page；当前内核没有完整
/// reclaim，因此在分配失败前只丢弃 refcount==1 的页，也就是仅由全局 cache
/// 自己持有、没有 resident PTE/MapArea 继续使用的页。
pub(super) fn file_page_cache_reclaim_unreferenced() -> usize {
    let mappings = {
        let mappings = FILE_PAGE_MAPPINGS.lock();
        mappings.values().cloned().collect::<Vec<_>>()
    };
    let mut reclaimed = 0usize;
    for mapping in mappings {
        let mut pages = mapping.pages.lock();
        let stale_pages = pages
            .iter()
            .filter_map(|(page, slot)| match slot {
                FilePageCacheSlot::Ready(frame) if frame.refcount() <= 1 => Some(*page),
                FilePageCacheSlot::Loading { .. } | FilePageCacheSlot::Ready(_) => None,
            })
            .collect::<Vec<_>>();
        reclaimed = reclaimed.saturating_add(stale_pages.len());
        for page in stale_pages {
            pages.remove(&page);
        }
    }
    reclaimed
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MmapBackingKind {
    File {
        dev: usize,
        ino: u32,
    },
    /// Linux shmem family: anonymous memfd and pathname-backed tmpfs.
    Shmem {
        id: u64,
    },
}

impl MmapBackingKind {
    /// 从 VmRegion 推导 backing 类型：shmem 优先，其次普通文件，匿名映射返回 None。
    pub(super) fn from_region(region: &VmRegion) -> Option<Self> {
        if region.shmem_id != 0 {
            Some(Self::Shmem {
                id: region.shmem_id,
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

    /// 检查 region 是否属于本 backing（dev/ino 或 shmem id 匹配）。
    pub(super) fn matches_region(self, region: &VmRegion) -> bool {
        match self {
            Self::File { dev, ino } => {
                region.file_backed
                    && region.shmem_id == 0
                    && region.file_dev == dev
                    && region.file_ino == ino
            }
            Self::Shmem { id } => region.shmem_id == id,
        }
    }
}

#[derive(Clone)]
pub(super) struct MmapBacking {
    pub(super) kind: MmapBackingKind,
    pub(super) file: Arc<dyn File + Send + Sync>,
    pub(super) vm_state: MmapBackingVmState,
    /// Per-mm state needed by MAP_SHARED writeback and frame accounting.
    ///
    /// Clean MAP_PRIVATE file pages live in the page table plus the inode page
    /// cache and deliberately do not get a second per-mm index here.  This
    /// mirrors Linux's split between `mm` page tables and
    /// `address_space::i_pages`/`i_mmap`, and avoids cloning a derived page
    /// tree across every fork before the child immediately execs.
    pub(super) resident_pages: BTreeMap<usize, MmapBackingPageState>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct MmapBackingVmState {
    /// 从 VmRegionSet 派生，用于检查 backing 生命周期是否过期。
    pub(super) vma_count: usize,
    pub(super) mapped_file_ranges: Vec<(usize, usize)>,
    pub(super) valid_file_ranges: Vec<(usize, usize)>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct MmapBackingPageState {
    /// 当前 mm 内该 shared file page 的驻留引用数；这是统计值，不是回收 pin。
    pub(super) ref_count: usize,
    /// dirty 提示；尚未用于过滤 writeback。
    pub(super) dirty: bool,
    /// shared file mapping 可复用的驻留 frame；MAP_PRIVATE 不使用它。
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
    /// 为 region 创建新的 MmapBacking；region 无文件后端时返回 None。
    pub(super) fn new(region: &VmRegion, file: &Arc<dyn File + Send + Sync>) -> Option<Self> {
        Some(Self {
            kind: MmapBackingKind::from_region(region)?,
            file: Arc::clone(file),
            vm_state: MmapBackingVmState::default(),
            resident_pages: BTreeMap::new(),
        })
    }

    /// 克隆 backing 文件的 Arc 引用。
    pub(super) fn file(&self) -> Arc<dyn File + Send + Sync> {
        Arc::clone(&self.file)
    }

    /// 检查 region 是否归属于本 backing。
    pub(super) fn matches_region(&self, region: &VmRegion) -> bool {
        self.kind.matches_region(region)
    }

    /// MAP_SHARED fault 路径：增加 file_page 的驻留引用计数，可选记录 frame 和 dirty 状态。
    pub(super) fn add_resident_page_ref(
        &mut self,
        file_page: usize,
        frame: Option<&FrameTracker>,
        dirty: bool,
    ) {
        // fault 快路径先增量记录；后续 refresh 会从 MapArea/PTE 重建并校验。
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

    /// msync/writeback 完成后清除 file_page 的 dirty 标记。
    #[cfg(target_arch = "riscv64")]
    pub(super) fn clear_dirty_page(&mut self, file_page: usize) {
        if let Some(state) = self.resident_pages.get_mut(&file_page) {
            state.dirty = false;
        }
    }

    /// 用 refresh 后的完整页状态替换当前 resident_pages 快照。
    pub(super) fn replace_resident_pages(&mut self, pages: BTreeMap<usize, MmapBackingPageState>) {
        self.resident_pages = pages;
    }

    /// 用 refresh 后的 VMA 统计状态替换当前 vm_state。
    pub(super) fn replace_vm_state(&mut self, vm_state: MmapBackingVmState) {
        self.vm_state = vm_state;
    }
}
