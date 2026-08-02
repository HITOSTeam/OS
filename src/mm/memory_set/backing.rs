//! 单个 MemorySet 内的 file-backed mmap 辅助状态。
//!
//! `VmRegion` 是 VMA 策略源，`MapArea/PTE` 是驻留页状态；这里记录二者之间
//! 需要同步的 backing、dirty 和生命周期信息。

use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SharedFilePageKey {
    dev: usize,
    ino: u32,
    file_page: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SharedAnonPageKey {
    id: u64,
    page: usize,
}

static NEXT_SHARED_ANON_ID: AtomicUsize = AtomicUsize::new(1);

lazy_static::lazy_static! {
    /// OSInode-backed MAP_SHARED 的第一阶段共享页缓存。
    ///
    /// 只覆盖普通文件共享映射；shmem/SysV shm 走各自的 shared-frame，
    /// MAP_PRIVATE 不能复用这里的 frame。
    static ref SHARED_FILE_PAGE_CACHE: Mutex<BTreeMap<SharedFilePageKey, FrameTracker>> =
        Mutex::new(BTreeMap::new());
    /// MAP_SHARED|MAP_ANONYMOUS 的 lazy 页缓存。
    ///
    /// Linux 对共享匿名映射先建立 VMA，实际物理页到 fault 时才分配；同一 VMA
    /// fork 后的后续 fault 仍必须落到同一共享页。
    static ref SHARED_ANON_PAGE_CACHE: Mutex<BTreeMap<SharedAnonPageKey, FrameTracker>> =
        Mutex::new(BTreeMap::new());
}

/// 用 (dev, ino, file_page) 构造缓存键。
fn shared_file_page_key(dev: usize, ino: u32, file_page: usize) -> SharedFilePageKey {
    SharedFilePageKey {
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

/// 查询全局共享文件页缓存，返回对应 FrameTracker（不存在则 None）。
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

/// 插入缓存页；若该页已存在则直接返回已有 frame（保证同一文件页全局唯一物理帧）。
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
pub(super) fn shared_file_page_cache_write(dev: usize, ino: u32, write_off: usize, data: &[u8]) {
    if data.is_empty() {
        return;
    }

    // fd 写入也更新全局缓存，保证其他 mm 后续 fault 能看到新内容。
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

/// 文件 truncate 后同步缓存：EOF 页尾部清零，超出新 file_size 的缓存页全部丢弃。
pub(super) fn shared_file_page_cache_resize(dev: usize, ino: u32, file_size: usize) {
    let eof_page = file_size / PAGE_SIZE;
    let eof_off = file_size & (PAGE_SIZE - 1);
    let remove_from = if eof_off == 0 {
        eof_page
    } else {
        eof_page.saturating_add(1)
    };

    let mut cache = SHARED_FILE_PAGE_CACHE.lock();
    // truncate 后 EOF 页尾清零，EOF 之后的缓存页必须丢弃，避免 shrink/grow 复用旧脏页。
    if eof_off != 0 {
        if let Some(frame) = cache.get(&shared_file_page_key(dev, ino, eof_page)) {
            frame.ppn.get_bytes_array()[eof_off..PAGE_SIZE].fill(0);
        }
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

/// 回收没有任何地址空间继续引用的全局共享文件页缓存。
///
/// Linux page cache 可以在内存压力下回收 clean cache page；当前内核没有完整
/// reclaim，因此在分配失败前只丢弃 refcount==1 的页，也就是仅由全局 cache
/// 自己持有、没有 resident PTE/MapArea 继续使用的页。
pub(super) fn shared_file_page_cache_reclaim_unreferenced() -> usize {
    let mut cache = SHARED_FILE_PAGE_CACHE.lock();
    let stale_keys = cache
        .iter()
        .filter(|(_, frame)| frame.refcount() <= 1)
        .map(|(key, _)| *key)
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

    /// 返回指定 file_page 的驻留共享 frame（MAP_PRIVATE 不使用）。
    pub(super) fn resident_frame(&self, file_page: usize) -> Option<FrameTracker> {
        self.resident_pages
            .get(&file_page)
            .and_then(|state| state.frame.as_ref().cloned())
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
