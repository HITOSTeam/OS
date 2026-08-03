//! 单个 MemorySet 内的 file-backed mmap 辅助状态。
//!
//! `VmRegion` 是 VMA 策略源，`MapArea/PTE` 是驻留页状态；这里记录二者之间
//! 需要同步的 backing、dirty 和生命周期信息。

use super::*;
use crate::sync::WaitQueue;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FilePageCacheKey {
    dev: usize,
    ino: u32,
    file_page: usize,
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
    /// OSInode-backed regular-file page cache, keyed like Linux
    /// `address_space::i_pages` by inode identity and page index.
    ///
    /// Clean MAP_PRIVATE pages and MAP_SHARED pages both reference the same
    /// frame.  A private write replaces that mapping through COW; memfd and
    /// SysV shm keep using their own shared-frame stores.
    static ref FILE_PAGE_CACHE: Mutex<BTreeMap<FilePageCacheKey, FilePageCacheSlot>> =
        Mutex::new(BTreeMap::new());
    /// MAP_SHARED|MAP_ANONYMOUS 的 lazy 页缓存。
    ///
    /// Linux 对共享匿名映射先建立 VMA，实际物理页到 fault 时才分配；同一 VMA
    /// fork 后的后续 fault 仍必须落到同一共享页。
    static ref SHARED_ANON_PAGE_CACHE: Mutex<BTreeMap<SharedAnonPageKey, FrameTracker>> =
        Mutex::new(BTreeMap::new());
}

/// 用 (dev, ino, file_page) 构造缓存键。
fn file_page_cache_key(dev: usize, ino: u32, file_page: usize) -> FilePageCacheKey {
    FilePageCacheKey {
        dev,
        ino,
        file_page,
    }
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
    let key = file_page_cache_key(dev, ino, file_page);
    let mut fill = Some(fill);
    let mut must_observe_published = false;

    loop {
        let loading = {
            let cache = FILE_PAGE_CACHE.lock();
            match cache.get(&key) {
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
            let mut cache = FILE_PAGE_CACHE.lock();
            match cache.get(&key) {
                Some(FilePageCacheSlot::Ready(frame)) => return Ok(frame.clone()),
                Some(FilePageCacheSlot::Loading { state, .. }) => Some(Arc::clone(state)),
                None => {
                    cache.insert(
                        key,
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

        let published = {
            let mut cache = FILE_PAGE_CACHE.lock();
            let owns_slot = matches!(
                cache.get(&key),
                Some(FilePageCacheSlot::Loading { state: current, .. })
                    if Arc::ptr_eq(current, &state)
            );
            if owns_slot {
                cache.insert(key, FilePageCacheSlot::Ready(candidate.clone()));
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

    let mut copied = 0usize;
    while copied < data.len() {
        let file_off = write_off.saturating_add(copied);
        let file_page = file_off / PAGE_SIZE;
        let page_off = file_off & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, data.len() - copied);
        let key = file_page_cache_key(dev, ino, file_page);
        loop {
            let loading = {
                let cache = FILE_PAGE_CACHE.lock();
                match cache.get(&key) {
                    Some(FilePageCacheSlot::Ready(frame)) => {
                        frame.ppn.get_bytes_array()[page_off..page_off + chunk]
                            .copy_from_slice(&data[copied..copied + chunk]);
                        None
                    }
                    Some(FilePageCacheSlot::Loading { state, .. }) => Some(Arc::clone(state)),
                    None => None,
                }
            };
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
    let eof_page = file_size / PAGE_SIZE;
    let eof_off = file_size & (PAGE_SIZE - 1);
    let remove_from = if eof_off == 0 {
        eof_page
    } else {
        eof_page.saturating_add(1)
    };

    let mut invalidated = Vec::new();
    let mut cache = FILE_PAGE_CACHE.lock();
    // truncate 后 EOF 页尾清零，EOF 之后的缓存页必须丢弃，避免 shrink/grow 复用旧脏页。
    if eof_off != 0 {
        let eof_key = file_page_cache_key(dev, ino, eof_page);
        match cache.get(&eof_key) {
            Some(FilePageCacheSlot::Ready(frame)) => {
                frame.ppn.get_bytes_array()[eof_off..PAGE_SIZE].fill(0);
            }
            Some(FilePageCacheSlot::Loading { state, .. }) => {
                invalidated.push(Arc::clone(state));
                cache.remove(&eof_key);
            }
            None => {}
        }
    }

    let stale_keys = cache
        .keys()
        .filter(|key| key.dev == dev && key.ino == ino && key.file_page >= remove_from)
        .copied()
        .collect::<Vec<_>>();
    for key in stale_keys {
        if let Some(FilePageCacheSlot::Loading { state, .. }) = cache.remove(&key) {
            invalidated.push(state);
        }
    }
    drop(cache);
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
    let mut cache = FILE_PAGE_CACHE.lock();
    let stale_keys = cache
        .iter()
        .filter_map(|(key, slot)| match slot {
            FilePageCacheSlot::Ready(frame) if frame.refcount() <= 1 => Some(*key),
            FilePageCacheSlot::Loading { .. } | FilePageCacheSlot::Ready(_) => None,
        })
        .collect::<Vec<_>>();
    let reclaimed = stale_keys.len();
    for key in stale_keys {
        cache.remove(&key);
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
    /// 当前 mm 内该 file page 的驻留引用数；这是统计值，不是回收 pin。
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

    /// fault 路径：增加 file_page 的驻留引用计数，可选记录 frame 和 dirty 状态。
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
