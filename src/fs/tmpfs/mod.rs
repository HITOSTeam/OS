//! In-memory tmpfs backend for the object-based VFS.
//!
//! Files use sparse 4 KiB pages.  Directory entries own nodes, while open
//! files and dentries keep unlinked nodes alive through `Arc`.

use crate::config::PAGE_SIZE;
use crate::fs::vfs::{
    DentryCachePolicy, VfsDirEntry, VfsError, VfsFileOperations, VfsFileSystem, VfsFileSystemState,
    VfsLink, VfsMetadata, VfsNode, VfsNodeKind, VfsOpenOptions, VfsRenameFlags, VfsResult,
    VfsStatFs, VfsTimes,
};
#[cfg(not(target_os = "none"))]
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use crate::mm::{FrameTracker, frame_alloc};

/// Linux `TMPFS_MAGIC`，由 `statfs(2)` 的 `f_type` 返回。
const TMPFS_MAGIC: u64 = 0x0102_1994;
/// `setxattr(2)`：仅当属性不存在时创建。
const XATTR_CREATE: u32 = 1;
/// `setxattr(2)`：仅当属性已经存在时替换。
const XATTR_REPLACE: u32 = 2;

/// 为每个独立 TmpFs 实例分配稳定的 filesystem ID。
static NEXT_TMPFS_ID: AtomicUsize = AtomicUsize::new(0x10000);
/// Stable identity used by VMAs backed by a TmpFs inode.
///
/// Keep the high bit set so these IDs cannot collide with the low, monotonic
/// IDs currently used by the kernel's anonymous memfd/shmem objects.
static NEXT_TMPFS_MAPPING_ID: AtomicU64 = AtomicU64::new(1);
const TMPFS_MAPPING_ID_TAG: u64 = 1 << 63;

/// One resident tmpfs page.
///
/// The kernel target stores a refcounted physical frame so MAP_SHARED can map
/// the same page into multiple address spaces, just as Linux tmpfs keeps data
/// in the page cache. Host-side unit tests retain a boxed page because there
/// is no initialized physical-frame allocator there.
struct TmpFsPage {
    #[cfg(target_os = "none")]
    frame: FrameTracker,
    #[cfg(not(target_os = "none"))]
    bytes: Box<[u8; PAGE_SIZE]>,
}

impl TmpFsPage {
    fn allocate() -> Option<Self> {
        #[cfg(target_os = "none")]
        {
            return frame_alloc().map(|frame| Self { frame });
        }
        #[cfg(not(target_os = "none"))]
        {
            Some(Self {
                bytes: Box::new([0; PAGE_SIZE]),
            })
        }
    }

    fn bytes(&self) -> &[u8] {
        #[cfg(target_os = "none")]
        {
            self.frame.ppn.get_bytes_array()
        }
        #[cfg(not(target_os = "none"))]
        {
            &self.bytes
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        #[cfg(target_os = "none")]
        {
            self.frame.ppn.get_bytes_array()
        }
        #[cfg(not(target_os = "none"))]
        {
            &mut self.bytes
        }
    }

    fn frame(&self) -> Option<FrameTracker> {
        #[cfg(target_os = "none")]
        {
            Some(self.frame.clone())
        }
        #[cfg(not(target_os = "none"))]
        {
            None
        }
    }
}

/// 创建一个 TmpFs 实例时使用的挂载参数。
#[derive(Clone, Copy, Debug)]
pub struct TmpFsOptions {
    /// 文件数据最多可以实际占用的内存字节数。
    pub size_bytes: usize,
    /// 根目录权限位，只保留低 12 位 mode。
    pub root_mode: u16,
    /// 根目录及新建节点的默认 owner UID。
    pub uid: u32,
    /// 根目录及新建节点的默认 owner GID。
    pub gid: u32,
    /// 文件系统最多允许存在的 inode 数量。
    pub inode_limit: usize,
}

impl TmpFsOptions {
    /// 根据 guest 总内存生成默认配置。
    ///
    /// 默认容量为总内存的一半，根目录 mode 为 `01777`。
    pub fn defaults_for_memory(total_memory_bytes: usize) -> Self {
        Self {
            size_bytes: total_memory_bytes / 2,
            root_mode: 0o1777,
            uid: 0,
            gid: 0,
            inode_limit: total_memory_bytes
                .checked_div(PAGE_SIZE)
                .unwrap_or(0)
                .max(1024),
        }
    }

    /// 解析 `size/mode/uid/gid/nr_inodes` 形式的逗号分隔挂载参数。total_memory: guest 内存
    /// data 是 参数
    /// 未指定的字段沿用 [`Self::defaults_for_memory`]；未知参数、非法数值
    /// 以及零容量或零 inode 上限都会返回 [`VfsError::Invalid`]。
    pub fn parse(total_memory_bytes: usize, data: &str) -> VfsResult<Self> {
        let mut options = Self::defaults_for_memory(total_memory_bytes);
        for option in data.split(',').filter(|option| !option.is_empty()) {
            let (key, value) = option.split_once('=').ok_or(VfsError::Invalid)?;
            match key {
                "size" => options.size_bytes = parse_size(value, total_memory_bytes)?,
                "mode" => {
                    options.root_mode =
                        u16::from_str_radix(value, 8).map_err(|_| VfsError::Invalid)? & 0o7777
                }
                "uid" => options.uid = value.parse().map_err(|_| VfsError::Invalid)?,
                "gid" => options.gid = value.parse().map_err(|_| VfsError::Invalid)?,
                "nr_inodes" => {
                    options.inode_limit = value.parse().map_err(|_| VfsError::Invalid)?
                }
                _ => return Err(VfsError::Invalid),
            }
        }
        if options.size_bytes == 0 || options.inode_limit == 0 {
            return Err(VfsError::Invalid);
        }
        Ok(options)
    }
}

/// 解析 TmpFs 的 `size=` 参数。
///
/// 支持裸字节数、`K/M/G` 后缀和相对于 guest 总内存的百分比。
fn parse_size(value: &str, total_memory_bytes: usize) -> VfsResult<usize> {
    if let Some(percent) = value.strip_suffix('%') {
        let percent: usize = percent.parse().map_err(|_| VfsError::Invalid)?;
        if percent > 100 {
            return Err(VfsError::Invalid);
        }
        return total_memory_bytes
            .checked_mul(percent)
            .and_then(|bytes| bytes.checked_div(100))
            .ok_or(VfsError::Invalid);
    }
    let (digits, multiplier) = match value.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&value[..value.len() - 1], 1024usize),
        Some(b'm' | b'M') => (&value[..value.len() - 1], 1024usize * 1024),
        Some(b'g' | b'G') => (&value[..value.len() - 1], 1024usize * 1024 * 1024),
        _ => (value, 1),
    };
    digits
        .parse::<usize>()
        .map_err(|_| VfsError::Invalid)?
        .checked_mul(multiplier)
        .ok_or(VfsError::Invalid)
}

/// Core code
/// 一个独立的内存文件系统实例。
///
/// 每次挂载都应创建新的 `TmpFs`，各实例拥有独立根节点、inode 空间、
/// 容量配额和目录树。
pub struct TmpFs {
    /// 供 VFS 区分文件系统实例的稳定 ID。由一个全局的 atomic 来维护
    id: u64,
    options: TmpFsOptions,
    /// 文件系统根节点，固定使用 inode 1。
    root: Arc<TmpFsNode>,
    /// Stable root dentry and positive dcache shared by every mount/walker.
    vfs_state: VfsFileSystemState,
    /// 下一个待分配的 inode 编号。
    next_inode: AtomicUsize,
    /// 当前仍存活的节点数量，包括已 unlink 但仍被打开的节点。
    used_inodes: AtomicUsize,
    /// 普通文件当前实际分配的稀疏页数量。
    used_pages: AtomicUsize,
    /// inode 到节点的弱引用索引，用于从 `&TmpFsNode` 恢复对应的 `Arc`。
    nodes: RwLock<BTreeMap<u64, Weak<TmpFsNode>>>,
    /// Serializes multi-directory mutations.  Node contents remain protected
    /// by their local locks for lookup and I/O.
    rename_lock: Mutex<()>,
}

impl TmpFs {
    /// total_memroy: 总内存 data:参数
    /// 根据 guest 总内存和挂载参数创建一个新的 TmpFs 实例。
    pub fn new(total_memory_bytes: usize, data: &str) -> VfsResult<Arc<Self>> {
        let options = TmpFsOptions::parse(total_memory_bytes, data)?;
        let id = NEXT_TMPFS_ID.fetch_add(1, Ordering::Relaxed) as u64;
        let filesystem = Arc::new_cyclic(|weak_fs| {
            let root = Arc::new(TmpFsNode::new(
                weak_fs.clone(),
                1,
                VfsNodeKind::Directory,
                options.root_mode,
                options.uid,
                options.gid,
                0,
            ));
            let vfs_state = VfsFileSystemState::new(Arc::clone(&root) as Arc<dyn VfsNode>);
            Self {
                id,
                options,
                root,
                vfs_state,
                next_inode: AtomicUsize::new(2),
                used_inodes: AtomicUsize::new(1),
                used_pages: AtomicUsize::new(0),
                nodes: RwLock::new(BTreeMap::new()),
                rename_lock: Mutex::new(()),
            }
        });
        filesystem
            .nodes
            .write()
            .insert(1, Arc::downgrade(&filesystem.root));
        Ok(filesystem)
    }

    /// 在检查 inode 配额后分配并登记一个新节点。
    fn allocate_node(
        self: &Arc<Self>,
        kind: VfsNodeKind,
        mode: u16,
        rdev: u64,
    ) -> VfsResult<Arc<TmpFsNode>> {
        // uodate inodes used
        self.used_inodes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < self.options.inode_limit).then_some(used + 1)
            })
            .map_err(|_| VfsError::NoSpace)?;
        let inode = self.next_inode.fetch_add(1, Ordering::Relaxed) as u64;
        let node = Arc::new(TmpFsNode::new(
            Arc::downgrade(self),
            inode,
            kind,
            mode,
            self.options.uid,
            self.options.gid,
            rdev,
        ));
        self.nodes.write().insert(inode, Arc::downgrade(&node));
        Ok(node)
    }

    /// 为普通文件预留一个实际内存页；达到 `size=` 上限时返回 `false`。
    fn reserve_page(&self) -> bool {
        let page_limit = self.options.size_bytes / PAGE_SIZE;
        self.used_pages
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < page_limit).then_some(used + 1)
            })
            .is_ok()
    }

    /// 归还由 truncate 或节点销毁释放的实际内存页配额。
    fn release_pages(&self, count: usize) {
        if count != 0 {
            self.used_pages.fetch_sub(count, Ordering::AcqRel);
        }
    }
}

impl VfsFileSystem for TmpFs {
    /// 返回此 TmpFs 实例的稳定 filesystem ID。
    fn filesystem_id(&self) -> u64 {
        self.id
    }

    /// 返回 mount/stat 展示使用的文件系统类型名。
    fn filesystem_type(&self) -> &'static str {
        "tmpfs"
    }

    fn vfs_state(&self) -> &VfsFileSystemState {
        &self.vfs_state
    }

    /// 根据实际分配页和存活 inode 数量生成 `statfs` 快照。
    fn statfs(&self) -> VfsResult<VfsStatFs> {
        let blocks = (self.options.size_bytes / PAGE_SIZE) as u64;
        let used_pages = self.used_pages.load(Ordering::Acquire) as u64;
        let used_inodes = self.used_inodes.load(Ordering::Acquire) as u64;
        Ok(VfsStatFs {
            magic: TMPFS_MAGIC,
            block_size: PAGE_SIZE as u64,
            blocks,
            blocks_free: blocks.saturating_sub(used_pages),
            blocks_available: blocks.saturating_sub(used_pages),
            files: self.options.inode_limit as u64,
            files_free: (self.options.inode_limit as u64).saturating_sub(used_inodes),
            name_len: 255,
        })
    }

    /// TmpFs 没有持久化后端，因此 sync 无需执行写回。
    fn sync(&self) -> VfsResult<()> {
        Ok(())
    }
}

/// 不同节点类型在内存中的具体数据。
enum TmpFsData {
    /// 目录项名称到节点对象的有序映射；多个名称可以指向同一个硬链接节点。
    Directory(BTreeMap<String, Arc<TmpFsNode>>),
    /// 稀疏普通文件：key 为页号，只为实际写入过的 4 KiB 页分配内存。
    Regular(BTreeMap<usize, TmpFsPage>),
    /// 符号链接保存未经解析的目标字符串。
    Symlink(String),
    /// FIFO、字符/块设备和 socket 等当前只保存元数据的特殊节点。
    Special,
}

/// 由节点局部 `RwLock` 保护的可变状态。
struct TmpFsNodeInner {
    /// Linux 可观察的节点类型、权限、owner、链接数、大小和时间戳。
    metadata: VfsMetadata,
    /// 与节点类型对应的目录、稀疏页、symlink 或特殊节点数据。
    data: TmpFsData,
    /// 节点的扩展属性名称和值。
    xattrs: BTreeMap<String, Vec<u8>>,
}

/// TmpFs 中具有稳定 inode 身份的文件系统节点。
///
/// 目录项、dentry 和打开文件均通过 `Arc` 持有节点，因此 unlink 只会移除
/// 名称；节点会一直存活到最后一个引用被释放。
pub struct TmpFsNode {
    /// 所属 TmpFs 的弱引用，避免文件系统与节点形成强引用环。
    fs: Weak<TmpFs>,
    /// 在所属 TmpFs 实例内稳定且唯一的 inode 编号。
    inode: u64,
    /// VM-visible identity for shared mappings of this inode.
    mapping_id: u64,
    /// 节点局部可变状态；普通 lookup/read 可以并发获取读锁。
    inner: RwLock<TmpFsNodeInner>,
}

impl TmpFsNode {
    /// 构造尚未插入目录的新节点，并初始化 metadata 与类型对应的数据。
    fn new(
        fs: Weak<TmpFs>,
        inode: u64,
        kind: VfsNodeKind,
        mode: u16,
        uid: u32,
        gid: u32,
        rdev: u64,
    ) -> Self {
        let now = crate::time::get_realtime_ns();
        let data = match kind {
            VfsNodeKind::Directory => TmpFsData::Directory(BTreeMap::new()),
            VfsNodeKind::Regular => TmpFsData::Regular(BTreeMap::new()),
            VfsNodeKind::Symlink => TmpFsData::Symlink(String::new()),
            _ => TmpFsData::Special,
        };
        Self {
            fs,
            inode,
            mapping_id: TMPFS_MAPPING_ID_TAG
                | NEXT_TMPFS_MAPPING_ID.fetch_add(1, Ordering::Relaxed),
            inner: RwLock::new(TmpFsNodeInner {
                metadata: VfsMetadata {
                    kind,
                    mode: mode & 0o7777,
                    uid,
                    gid,
                    nlink: if kind == VfsNodeKind::Directory { 2 } else { 1 },
                    size: 0,
                    rdev,
                    times: VfsTimes {
                        access_ns: now,
                        modify_ns: now,
                        change_ns: now,
                    },
                },
                data,
                xattrs: BTreeMap::new(),
            }),
        }
    }

    /// 升级所属文件系统的弱引用；文件系统已经释放时返回错误。
    fn fs(&self) -> VfsResult<Arc<TmpFs>> {
        self.fs.upgrade().ok_or(VfsError::Invalid)
    }

    /// 在当前目录中创建并插入一个新子节点。
    ///
    /// 目录变更通过 filesystem 级 `rename_lock` 串行化；节点内容仍由各自的
    /// 局部锁保护。创建子目录时同时增加父目录的链接数。
    fn insert_child(
        self: &Arc<Self>,
        name: &str,
        kind: VfsNodeKind,
        mode: u16,
        rdev: u64,
    ) -> VfsResult<Arc<TmpFsNode>> {
        validate_name(name)?;
        let fs = self.fs()?;
        let _mutation = fs.rename_lock.lock();
        let mut inner = self.inner.write();
        let TmpFsData::Directory(children) = &mut inner.data else {
            return Err(VfsError::NotDirectory);
        };
        if children.contains_key(name) {
            return Err(VfsError::Exists);
        }
        let child = fs.allocate_node(kind, mode, rdev)?;
        children.insert(name.to_string(), Arc::clone(&child));
        if kind == VfsNodeKind::Directory {
            inner.metadata.nlink = inner.metadata.nlink.saturating_add(1);
        }
        touch_modify_change(&mut inner.metadata);
        Ok(child)
    }

    /// 从普通文件的指定字节偏移读取数据，不使用打开文件的当前 offset。
    ///
    /// 未分配的稀疏区域返回零，读取越过 EOF 时只返回有效范围。
    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> VfsResult<usize> {
        let mut inner = self.inner.write();
        // 必须是可读的文件
        if inner.metadata.kind != VfsNodeKind::Regular {
            return Err(if inner.metadata.kind == VfsNodeKind::Directory {
                VfsError::IsDirectory
            } else {
                VfsError::Invalid
            });
        }
        // 超出offset  返回 0
        if offset >= inner.metadata.size {
            return Ok(0);
        }
        let available = (inner.metadata.size - offset) as usize;
        let length = output.len().min(available);
        output[..length].fill(0);
        let TmpFsData::Regular(pages) = &inner.data else {
            unreachable!();
        };
        let mut done = 0usize;
        while done < length {
            let position = offset as usize + done;
            let page_index = position / PAGE_SIZE;
            let in_page = position % PAGE_SIZE;
            let chunk = (PAGE_SIZE - in_page).min(length - done);
            // 空洞读取 暗含在这里
            if let Some(page) = pages.get(&page_index) {
                output[done..done + chunk].copy_from_slice(&page.bytes()[in_page..in_page + chunk]);
            }
            done += chunk;
        }
        inner.metadata.times.access_ns = crate::time::get_realtime_ns();
        Ok(length)
    }

    /// 向普通文件的指定字节偏移写入数据，不使用打开文件的当前 offset。
    ///
    /// 仅在首次写入某个页时分配 4 KiB 内存并消耗页配额；空间不足时允许
    /// 返回部分写入，完全无法写入时返回 [`VfsError::NoSpace`]。
    pub fn write_at(&self, offset: u64, input: &[u8]) -> VfsResult<usize> {
        let fs = self.fs()?;
        let mut inner = self.inner.write();
        Self::write_locked(&fs, &mut inner, offset, input)
    }

    fn write_locked(
        fs: &TmpFs,
        inner: &mut TmpFsNodeInner,
        offset: u64,
        input: &[u8],
    ) -> VfsResult<usize> {
        // 同上
        if inner.metadata.kind != VfsNodeKind::Regular {
            return Err(if inner.metadata.kind == VfsNodeKind::Directory {
                VfsError::IsDirectory
            } else {
                VfsError::Invalid
            });
        }
        let mut done = 0usize;
        let TmpFsData::Regular(pages) = &mut inner.data else {
            unreachable!();
        };
        while done < input.len() {
            let Some(position) = (offset as usize).checked_add(done) else {
                break;
            };
            let page_index = position / PAGE_SIZE;
            let in_page = position % PAGE_SIZE;
            let chunk = (PAGE_SIZE - in_page).min(input.len() - done);
            // 需要 新分配的页
            if !pages.contains_key(&page_index) {
                // 尝试分配
                if !fs.reserve_page() {
                    break;
                }
                let Some(page) = TmpFsPage::allocate() else {
                    fs.release_pages(1);
                    break;
                };
                pages.insert(page_index, page);
            }
            let page = pages.get_mut(&page_index).expect("page inserted");
            page.bytes_mut()[in_page..in_page + chunk].copy_from_slice(&input[done..done + chunk]);
            done += chunk;
        }
        if done == 0 && !input.is_empty() {
            return Err(VfsError::NoSpace);
        }
        inner.metadata.size = inner.metadata.size.max(offset.saturating_add(done as u64));
        touch_modify_change(&mut inner.metadata);
        Ok(done)
    }

    /// Atomically choose EOF and append while holding this inode's data lock.
    fn append_data(&self, input: &[u8]) -> VfsResult<(u64, usize)> {
        let fs = self.fs()?;
        let mut inner = self.inner.write();
        let offset = inner.metadata.size;
        let written = Self::write_locked(&fs, &mut inner, offset, input)?;
        Ok((offset, written))
    }

    /// 将普通文件调整到 `size` 字节。
    ///
    /// 缩小时释放完整页并清零最后一个保留页的截断部分；扩展时只增加逻辑
    /// 大小，不为新产生的空洞立即分配内存。
    pub fn truncate_to(&self, size: u64) -> VfsResult<()> {
        let fs = self.fs()?;
        let mut inner = self.inner.write();
        if inner.metadata.kind != VfsNodeKind::Regular {
            return Err(VfsError::Invalid);
        }
        let TmpFsData::Regular(pages) = &mut inner.data else {
            unreachable!();
        };
        let first_removed = size
            .saturating_add(PAGE_SIZE as u64 - 1)
            .checked_div(PAGE_SIZE as u64)
            .unwrap_or(u64::MAX) as usize;
        let before = pages.len();
        pages.retain(|index, _| *index < first_removed);
        fs.release_pages(before - pages.len());
        if size != 0 {
            let last_page_index = (size as usize) / PAGE_SIZE;
            let keep = (size as usize) % PAGE_SIZE;
            if keep != 0
                && let Some(page) = pages.get_mut(&last_page_index)
            {
                page.bytes_mut()[keep..].fill(0);
            }
        }
        inner.metadata.size = size;
        touch_modify_change(&mut inner.metadata);
        Ok(())
    }

    /// Return physical frames for a shared mapping, allocating pages for
    /// sparse holes without changing the inode's logical size.
    ///
    /// Linux performs this allocation lazily from `shmem_fault()`. This
    /// minimal VFS prepares only the pages covered by the mapping up front;
    /// the inode remains sparse outside that range and the same frames are
    /// reused by every MAP_SHARED mapping.
    pub fn shared_frames(&self, offset: usize, length: usize) -> VfsResult<Vec<FrameTracker>> {
        if offset % PAGE_SIZE != 0 {
            return Err(VfsError::Invalid);
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(length).ok_or(VfsError::Invalid)?;
        let fs = self.fs()?;
        let mut inner = self.inner.write();
        if inner.metadata.kind != VfsNodeKind::Regular {
            return Err(VfsError::Invalid);
        }
        let mapped_size = (inner.metadata.size as usize)
            .checked_add(PAGE_SIZE - 1)
            .map(|size| size / PAGE_SIZE * PAGE_SIZE)
            .ok_or(VfsError::Invalid)?;
        if end > mapped_size {
            return Err(VfsError::Invalid);
        }
        let TmpFsData::Regular(pages) = &mut inner.data else {
            unreachable!();
        };
        let start_page = offset / PAGE_SIZE;
        let end_page = end.div_ceil(PAGE_SIZE);
        let mut inserted = Vec::new();
        for page_index in start_page..end_page {
            if pages.contains_key(&page_index) {
                continue;
            }
            if !fs.reserve_page() {
                for index in inserted.drain(..) {
                    pages.remove(&index);
                    fs.release_pages(1);
                }
                return Err(VfsError::NoSpace);
            }
            let Some(page) = TmpFsPage::allocate() else {
                fs.release_pages(1);
                for index in inserted.drain(..) {
                    pages.remove(&index);
                    fs.release_pages(1);
                }
                return Err(VfsError::NoSpace);
            };
            pages.insert(page_index, page);
            inserted.push(page_index);
        }
        let mut frames = Vec::with_capacity(end_page.saturating_sub(start_page));
        for page_index in start_page..end_page {
            let Some(frame) = pages.get(&page_index).and_then(TmpFsPage::frame) else {
                return Err(VfsError::NotSupported);
            };
            frames.push(frame);
        }
        Ok(frames)
    }
}

impl Drop for TmpFsNode {
    /// 最后一个节点引用释放时归还数据页和 inode 配额。
    fn drop(&mut self) {
        if let Some(fs) = self.fs.upgrade() {
            let pages = match &self.inner.read().data {
                TmpFsData::Regular(pages) => pages.len(),
                _ => 0,
            };
            fs.release_pages(pages);
            fs.nodes.write().remove(&self.inode);
            fs.used_inodes.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl VfsNode for TmpFsNode {
    /// 返回 concrete node，供需要 TmpFs 专有操作的调用方安全 downcast。
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// 返回稳定 inode 编号。
    fn node_id(&self) -> u64 {
        self.inode
    }

    /// 返回所属 TmpFs 实例的 filesystem ID。
    fn filesystem_id(&self) -> u64 {
        self.fs.upgrade().map(|fs| fs.id).unwrap_or(0)
    }

    /// 返回当前节点 metadata 的快照。
    fn metadata(&self) -> VfsResult<VfsMetadata> {
        Ok(self.inner.read().metadata)
    }

    /// 每次使用正向 dentry 缓存时重新验证目录项。
    ///
    /// 当前节点操作无法直接使 namespace dcache 失效，因此以重新验证保证
    /// unlink 和 rename 后不会继续命中旧节点。
    fn dentry_cache_policy(&self) -> DentryCachePolicy {
        DentryCachePolicy::Revalidate
    }

    /// 在当前目录中按单个名称查找子节点。
    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn VfsNode>> {
        let inner = self.inner.read();
        let TmpFsData::Directory(children) = &inner.data else {
            return Err(VfsError::NotDirectory);
        };
        children
            .get(name)
            .cloned()
            .map(|node| node as Arc<dyn VfsNode>)
            .ok_or(VfsError::NoEntry)
    }

    /// 返回当前目录全部可见子项；`.` 和 `..` 由上层按 ABI 需要生成。
    fn readdir(&self) -> VfsResult<Vec<VfsDirEntry>> {
        let inner = self.inner.read();
        let TmpFsData::Directory(children) = &inner.data else {
            return Err(VfsError::NotDirectory);
        };
        Ok(children
            .iter()
            .map(|(name, node)| VfsDirEntry {
                name: name.clone(),
                node_id: node.inode,
                kind: node.inner.read().metadata.kind,
            })
            .collect())
    }

    /// 返回符号链接保存的文本目标。
    fn readlink(&self) -> VfsResult<VfsLink> {
        let inner = self.inner.read();
        let TmpFsData::Symlink(target) = &inner.data else {
            return Err(VfsError::Invalid);
        };
        Ok(VfsLink::Text(target.clone()))
    }

    /// 使用指定访问模式打开节点；顺序 offset 由 FileDescription 保存。
    fn open(self: Arc<Self>, options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        Ok(Arc::new(TmpFsFile {
            node: self,
            readable: options.readable,
            writable: options.writable,
        }))
    }

    /// 在当前目录中创建普通文件。
    fn create(&self, name: &str, mode: u16) -> VfsResult<Arc<dyn VfsNode>> {
        let this = self_arc(self)?;
        this.insert_child(name, VfsNodeKind::Regular, mode, 0)
            .map(|node| node as Arc<dyn VfsNode>)
    }

    /// 在当前目录中创建子目录。
    fn mkdir(&self, name: &str, mode: u16) -> VfsResult<Arc<dyn VfsNode>> {
        let this = self_arc(self)?;
        this.insert_child(name, VfsNodeKind::Directory, mode, 0)
            .map(|node| node as Arc<dyn VfsNode>)
    }

    /// 在当前目录中创建保存 `target` 文本的符号链接。
    fn symlink(&self, name: &str, target: &str) -> VfsResult<Arc<dyn VfsNode>> {
        let this = self_arc(self)?;
        // 插入新儿子
        let node = this.insert_child(name, VfsNodeKind::Symlink, 0o777, 0)?;
        let mut inner = node.inner.write();
        inner.metadata.size = target.len() as u64;
        // 新儿子的link目标
        inner.data = TmpFsData::Symlink(target.to_string());
        drop(inner);
        Ok(node as Arc<dyn VfsNode>)
    }

    /// 为同一 TmpFs 中的非目录节点创建硬链接。
    ///
    /// 新目录项与旧目录项共享同一个 `TmpFsNode`，并增加目标节点的 `nlink`。
    fn link(&self, name: &str, target: &Arc<dyn VfsNode>) -> VfsResult<()> {
        validate_name(name)?;
        // 先拿到tmpfs 的 node
        let target = target
            .as_any()
            .downcast_ref::<TmpFsNode>()
            .ok_or(VfsError::CrossDevice)?;
        // 应链接不准跨设备
        if target.filesystem_id() != self.filesystem_id() {
            return Err(VfsError::CrossDevice);
        }
        // 不允许 directory hard link 防止循环
        if target.inner.read().metadata.kind == VfsNodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        let target = self_arc(target)?;
        let fs = self.fs()?;
        let _mutation = fs.rename_lock.lock();
        if target.inner.read().metadata.nlink == 0 {
            return Err(VfsError::NoEntry);
        }
        let mut inner = self.inner.write();
        let TmpFsData::Directory(children) = &mut inner.data else {
            return Err(VfsError::NotDirectory);
        };
        if children.contains_key(name) {
            return Err(VfsError::Exists);
        }
        children.insert(name.to_string(), Arc::clone(&target));
        let mut target_inner = target.inner.write();
        target_inner.metadata.nlink = target_inner.metadata.nlink.saturating_add(1);
        touch_modify_change(&mut inner.metadata);
        Ok(())
    }

    /// 删除当前目录中的文件或空目录。
    ///
    /// `remove_dir` 区分 unlink 与 rmdir。操作只移除目录持有的 `Arc`；
    /// 打开的文件和缓存 dentry 仍可保持 nlink 为零的节点存活。
    fn unlink(&self, name: &str, remove_dir: bool) -> VfsResult<()> {
        validate_name(name)?;
        let fs = self.fs()?;
        let _mutation = fs.rename_lock.lock();
        let mut inner = self.inner.write();
        let TmpFsData::Directory(children) = &mut inner.data else {
            return Err(VfsError::NotDirectory);
        };
        let child = children.get(name).ok_or(VfsError::NoEntry)?;
        let child_kind = child.inner.read().metadata.kind;
        if (child_kind == VfsNodeKind::Directory) != remove_dir {
            return Err(if child_kind == VfsNodeKind::Directory {
                VfsError::IsDirectory
            } else {
                VfsError::NotDirectory
            });
        }
        if remove_dir
            && let TmpFsData::Directory(grandchildren) = &child.inner.read().data
            && !grandchildren.is_empty()
        {
            return Err(VfsError::NotEmpty);
        }
        let child = children.remove(name).expect("child checked");
        if remove_dir {
            inner.metadata.nlink = inner.metadata.nlink.saturating_sub(1);
            child.inner.write().metadata.nlink = 0;
        } else {
            let mut child_inner = child.inner.write();
            child_inner.metadata.nlink = child_inner.metadata.nlink.saturating_sub(1);
        }
        touch_modify_change(&mut inner.metadata);
        Ok(())
    }

    /// 将当前目录中的 `old_name` 移动到 `new_parent/new_name`。
    ///
    /// 只允许同一 TmpFs 实例内移动。filesystem 级 mutation 锁提供跨目录
    /// rename 的原子区间，两个目录锁再按 inode 顺序获取以避免死锁。
    fn rename(
        &self,
        old_name: &str,
        new_parent: &Arc<dyn VfsNode>,
        new_name: &str,
    ) -> VfsResult<()> {
        self.rename_with_flags(old_name, new_parent, new_name, VfsRenameFlags::default())
    }

    fn rename_with_flags(
        &self,
        old_name: &str,
        new_parent: &Arc<dyn VfsNode>,
        new_name: &str,
        flags: VfsRenameFlags,
    ) -> VfsResult<()> {
        if flags.0 & !(VfsRenameFlags::NO_REPLACE | VfsRenameFlags::EXCHANGE) != 0
            || flags.contains(VfsRenameFlags::NO_REPLACE)
                && flags.contains(VfsRenameFlags::EXCHANGE)
        {
            return Err(VfsError::Invalid);
        }
        validate_name(old_name)?;
        validate_name(new_name)?;
        let new_parent = new_parent
            .as_any()
            .downcast_ref::<TmpFsNode>()
            .ok_or(VfsError::CrossDevice)?;
        if new_parent.filesystem_id() != self.filesystem_id() {
            return Err(VfsError::CrossDevice);
        }
        let fs = self.fs()?;
        let _mutation = fs.rename_lock.lock();
        let validate_target = |source: &Arc<TmpFsNode>, target: &Arc<TmpFsNode>| {
            if flags.contains(VfsRenameFlags::NO_REPLACE) {
                return Err(VfsError::Exists);
            }
            if Arc::ptr_eq(source, target) {
                return Ok(());
            }
            let source_kind = source.inner.read().metadata.kind;
            let target_inner = target.inner.read();
            let target_kind = target_inner.metadata.kind;
            if source_kind == VfsNodeKind::Directory && target_kind != VfsNodeKind::Directory {
                return Err(VfsError::NotDirectory);
            }
            if source_kind != VfsNodeKind::Directory && target_kind == VfsNodeKind::Directory {
                return Err(VfsError::IsDirectory);
            }
            if let TmpFsData::Directory(children) = &target_inner.data
                && !children.is_empty()
            {
                return Err(VfsError::NotEmpty);
            }
            Ok(())
        };
        if self.inode == new_parent.inode {
            let mut inner = self.inner.write();
            let removed_target_directory = {
                let TmpFsData::Directory(children) = &mut inner.data else {
                    return Err(VfsError::NotDirectory);
                };
                let source = children.get(old_name).cloned().ok_or(VfsError::NoEntry)?;
                if old_name == new_name {
                    return if flags.contains(VfsRenameFlags::NO_REPLACE) {
                        Err(VfsError::Exists)
                    } else {
                        Ok(())
                    };
                }
                if flags.contains(VfsRenameFlags::EXCHANGE) {
                    let target = children.get(new_name).cloned().ok_or(VfsError::NoEntry)?;
                    if Arc::ptr_eq(&source, &target) {
                        return Ok(());
                    }
                    children.insert(old_name.to_string(), target);
                    children.insert(new_name.to_string(), source);
                    false
                } else {
                    let mut removed_target_directory = false;
                    if let Some(target) = children.get(new_name).cloned() {
                        validate_target(&source, &target)?;
                        if Arc::ptr_eq(&source, &target) {
                            return Ok(());
                        }
                        children.remove(new_name);
                        let mut target_inner = target.inner.write();
                        if target_inner.metadata.kind == VfsNodeKind::Directory {
                            target_inner.metadata.nlink = 0;
                            removed_target_directory = true;
                        } else {
                            target_inner.metadata.nlink =
                                target_inner.metadata.nlink.saturating_sub(1);
                        }
                    }
                    let node = children
                        .remove(old_name)
                        .expect("rename source checked above");
                    children.insert(new_name.to_string(), node);
                    removed_target_directory
                }
            };
            if removed_target_directory {
                inner.metadata.nlink = inner.metadata.nlink.saturating_sub(1);
            }
            touch_modify_change(&mut inner.metadata);
            return Ok(());
        }

        // The global rename lock provides deadlock freedom; take node locks in
        // stable inode order to keep the policy explicit.
        let (mut old_inner, mut new_inner) = if self.inode < new_parent.inode {
            (self.inner.write(), new_parent.inner.write())
        } else {
            let new = new_parent.inner.write();
            let old = self.inner.write();
            (old, new)
        };
        if flags.contains(VfsRenameFlags::EXCHANGE) {
            let (source_directory, target_directory) = {
                let TmpFsData::Directory(old_children) = &mut old_inner.data else {
                    return Err(VfsError::NotDirectory);
                };
                let TmpFsData::Directory(new_children) = &mut new_inner.data else {
                    return Err(VfsError::NotDirectory);
                };
                let source = old_children
                    .get(old_name)
                    .cloned()
                    .ok_or(VfsError::NoEntry)?;
                let target = new_children
                    .get(new_name)
                    .cloned()
                    .ok_or(VfsError::NoEntry)?;
                if Arc::ptr_eq(&source, &target) {
                    return Ok(());
                }
                let source_directory = source.inner.read().metadata.kind == VfsNodeKind::Directory;
                let target_directory = target.inner.read().metadata.kind == VfsNodeKind::Directory;
                old_children.insert(old_name.to_string(), target);
                new_children.insert(new_name.to_string(), source);
                (source_directory, target_directory)
            };
            if source_directory && !target_directory {
                old_inner.metadata.nlink = old_inner.metadata.nlink.saturating_sub(1);
                new_inner.metadata.nlink = new_inner.metadata.nlink.saturating_add(1);
            } else if !source_directory && target_directory {
                old_inner.metadata.nlink = old_inner.metadata.nlink.saturating_add(1);
                new_inner.metadata.nlink = new_inner.metadata.nlink.saturating_sub(1);
            }
            touch_modify_change(&mut old_inner.metadata);
            touch_modify_change(&mut new_inner.metadata);
            return Ok(());
        }
        let (moved_directory, removed_target_directory) = {
            let TmpFsData::Directory(old_children) = &mut old_inner.data else {
                return Err(VfsError::NotDirectory);
            };
            let TmpFsData::Directory(new_children) = &mut new_inner.data else {
                return Err(VfsError::NotDirectory);
            };
            let source = old_children
                .get(old_name)
                .cloned()
                .ok_or(VfsError::NoEntry)?;
            let mut removed_target_directory = false;
            if let Some(target) = new_children.get(new_name).cloned() {
                validate_target(&source, &target)?;
                if Arc::ptr_eq(&source, &target) {
                    return Ok(());
                }
                new_children.remove(new_name);
                let mut target_inner = target.inner.write();
                if target_inner.metadata.kind == VfsNodeKind::Directory {
                    target_inner.metadata.nlink = 0;
                    removed_target_directory = true;
                } else {
                    target_inner.metadata.nlink = target_inner.metadata.nlink.saturating_sub(1);
                }
            }
            let node = old_children
                .remove(old_name)
                .expect("rename source checked above");
            let moved_directory = node.inner.read().metadata.kind == VfsNodeKind::Directory;
            new_children.insert(new_name.to_string(), node);
            (moved_directory, removed_target_directory)
        };
        if removed_target_directory {
            new_inner.metadata.nlink = new_inner.metadata.nlink.saturating_sub(1);
        }
        if moved_directory {
            old_inner.metadata.nlink = old_inner.metadata.nlink.saturating_sub(1);
            new_inner.metadata.nlink = new_inner.metadata.nlink.saturating_add(1);
        }
        touch_modify_change(&mut old_inner.metadata);
        touch_modify_change(&mut new_inner.metadata);
        Ok(())
    }

    /// 实现 VFS truncate 操作。
    fn truncate(&self, size: u64) -> VfsResult<()> {
        self.truncate_to(size)
    }

    /// 读取指定扩展属性。
    fn get_xattr(&self, name: &str) -> VfsResult<Vec<u8>> {
        self.inner
            .read()
            .xattrs
            .get(name)
            .cloned()
            .ok_or(VfsError::NoEntry)
    }

    fn list_xattrs(&self) -> VfsResult<Vec<String>> {
        Ok(self.inner.read().xattrs.keys().cloned().collect())
    }

    /// 创建或替换扩展属性，并执行 `XATTR_CREATE/XATTR_REPLACE` 条件检查。
    fn set_xattr(&self, name: &str, value: &[u8], flags: u32) -> VfsResult<()> {
        if name.is_empty()
            || flags & !(XATTR_CREATE | XATTR_REPLACE) != 0
            || flags & (XATTR_CREATE | XATTR_REPLACE) == (XATTR_CREATE | XATTR_REPLACE)
        {
            return Err(VfsError::Invalid);
        }
        let mut inner = self.inner.write();
        let exists = inner.xattrs.contains_key(name);
        if flags & XATTR_CREATE != 0 && exists {
            return Err(VfsError::Exists);
        }
        if flags & XATTR_REPLACE != 0 && !exists {
            return Err(VfsError::NoEntry);
        }
        inner.xattrs.insert(name.to_string(), value.to_vec());
        inner.metadata.times.change_ns = crate::time::get_realtime_ns();
        Ok(())
    }

    /// 删除指定扩展属性。
    fn remove_xattr(&self, name: &str) -> VfsResult<()> {
        let mut inner = self.inner.write();
        inner.xattrs.remove(name).ok_or(VfsError::NoEntry)?;
        inner.metadata.times.change_ns = crate::time::get_realtime_ns();
        Ok(())
    }

    /// 创建 FIFO、字符设备、块设备或 socket 类型的特殊节点。
    ///
    /// 当前仅记录类型、mode 和 `rdev`；具体设备 file operations 由后续
    /// 设备后端接入。
    fn mknod(
        &self,
        name: &str,
        kind: VfsNodeKind,
        mode: u16,
        rdev: u64,
    ) -> VfsResult<Arc<dyn VfsNode>> {
        if !matches!(
            kind,
            VfsNodeKind::Fifo
                | VfsNodeKind::CharacterDevice
                | VfsNodeKind::BlockDevice
                | VfsNodeKind::Socket
        ) {
            return Err(VfsError::Invalid);
        }
        let this = self_arc(self)?;
        this.insert_child(name, kind, mode, rdev)
            .map(|node| node as Arc<dyn VfsNode>)
    }

    /// 修改节点权限位并更新 ctime。
    fn set_mode(&self, mode: u16) -> VfsResult<()> {
        let mut inner = self.inner.write();
        inner.metadata.mode = mode & 0o7777;
        inner.metadata.times.change_ns = crate::time::get_realtime_ns();
        Ok(())
    }

    /// 修改节点 owner UID/GID 并更新 ctime。
    fn set_owner(&self, uid: u32, gid: u32) -> VfsResult<()> {
        let mut inner = self.inner.write();
        inner.metadata.uid = uid;
        inner.metadata.gid = gid;
        inner.metadata.times.change_ns = crate::time::get_realtime_ns();
        Ok(())
    }

    fn set_mode_owner(&self, mode: u16, uid: u32, gid: u32) -> VfsResult<()> {
        let mut inner = self.inner.write();
        inner.metadata.mode = mode & 0o7777;
        inner.metadata.uid = uid;
        inner.metadata.gid = gid;
        inner.metadata.times.change_ns = crate::time::get_realtime_ns();
        Ok(())
    }

    /// Commit the selected inode timestamps under one node lock.
    fn update_times(
        &self,
        access_ns: Option<u64>,
        modify_ns: Option<u64>,
        change_ns: u64,
    ) -> VfsResult<()> {
        let mut inner = self.inner.write();
        if let Some(access_ns) = access_ns {
            inner.metadata.times.access_ns = access_ns;
        }
        if let Some(modify_ns) = modify_ns {
            inner.metadata.times.modify_ns = modify_ns;
        }
        inner.metadata.times.change_ns = change_ns;
        Ok(())
    }
}

/// 通过 filesystem 的弱引用索引取得 `node` 对应的强引用。
///
/// `VfsNode` mutation (new children)方法只接收 `&self`，创建目录项时需要用该辅助函数
/// 恢复可以存入目录树的 `Arc<TmpFsNode>`。
fn self_arc(node: &TmpFsNode) -> VfsResult<Arc<TmpFsNode>> {
    let fs = node.fs()?;
    fs.nodes
        .read()
        .get(&node.inode)
        .and_then(Weak::upgrade)
        .ok_or(VfsError::NoEntry)
}

/// 检查单个目录项名称是否合法。
fn validate_name(name: &str) -> VfsResult<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(VfsError::Invalid);
    }
    if name.len() > 255 {
        return Err(VfsError::NameTooLong);
    }
    Ok(())
}

/// 同时更新节点的 mtime 和 ctime。
fn touch_modify_change(metadata: &mut VfsMetadata) {
    let now = crate::time::get_realtime_ns();
    metadata.times.modify_ns = now;
    metadata.times.change_ns = now;
}

/// 打开一个 TmpFs 节点后得到的文件对象。
///
/// 它持有节点强引用，从而实现 open-unlinked 生命周期；对象本身无 cursor。
pub struct TmpFsFile {
    /// 被打开的稳定 TmpFs 节点。
    node: Arc<TmpFsNode>,
    /// 此次 open 是否允许读取。
    readable: bool,
    /// 此次 open 是否允许写入。
    writable: bool,
}

impl TmpFsFile {
    /// 返回文件对象持有的底层节点。
    pub fn node(&self) -> &Arc<TmpFsNode> {
        &self.node
    }

    /// 从显式偏移读取，不改变顺序 I/O 的当前 offset。
    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> VfsResult<usize> {
        self.node.read_at(offset, output)
    }

    /// 向显式偏移写入，不改变顺序 I/O 的当前 offset。
    pub fn write_at(&self, offset: u64, input: &[u8]) -> VfsResult<usize> {
        self.node.write_at(offset, input)
    }

    /// Stable identity used to reconnect an existing shared VMA to this inode.
    pub fn mapping_id(&self) -> u64 {
        self.node.mapping_id
    }

    /// Current logical length of the tmpfs inode.
    pub fn len(&self) -> usize {
        self.node.inner.read().metadata.size as usize
    }

    /// Prepare and return the inode pages covered by a shared mapping.
    pub fn shared_frames(&self, offset: usize, length: usize) -> VfsResult<Vec<FrameTracker>> {
        self.node.shared_frames(offset, length)
    }
}

impl VfsFileOperations for TmpFsFile {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// 返回该打开实例是否可读。
    fn readable(&self) -> bool {
        self.readable
    }

    /// 返回该打开实例是否可写。
    fn writable(&self) -> bool {
        self.writable
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> VfsResult<usize> {
        if !self.readable {
            return Err(VfsError::Access);
        }
        self.node.read_at(offset, output)
    }

    fn write_at(&self, offset: u64, input: &[u8]) -> VfsResult<usize> {
        if !self.writable {
            return Err(VfsError::Access);
        }
        self.node.write_at(offset, input)
    }

    fn size(&self) -> VfsResult<u64> {
        Ok(self.node.inner.read().metadata.size)
    }

    fn append(&self, input: &[u8]) -> VfsResult<(u64, usize)> {
        if !self.writable {
            return Err(VfsError::Access);
        }
        self.node.append_data(input)
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        match self.node.inner.read().metadata.kind {
            VfsNodeKind::Regular | VfsNodeKind::Directory => Ok(()),
            _ => Err(VfsError::Invalid),
        }
    }

    fn sync_range(&self, _offset: u64, _length: u64, _flags: u32) -> VfsResult<()> {
        match self.node.inner.read().metadata.kind {
            VfsNodeKind::Regular | VfsNodeKind::Directory => Ok(()),
            _ => Err(VfsError::Invalid),
        }
    }

    fn advise(&self, _offset: u64, _length: u64, _advice: u32) -> VfsResult<()> {
        if self.node.inner.read().metadata.kind == VfsNodeKind::Regular {
            Ok(())
        } else {
            Err(VfsError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpfs(size: usize, inodes: usize) -> Arc<TmpFs> {
        TmpFs::new(
            size,
            &alloc::format!("size={size},nr_inodes={inodes},mode=1777"),
        )
        .unwrap()
    }

    #[test]
    fn parses_mount_options_and_reports_capacity() {
        let fs = TmpFs::new(
            64 * 1024 * 1024,
            "size=25%,mode=0755,uid=12,gid=34,nr_inodes=99",
        )
        .unwrap();
        let stat = fs.statfs().unwrap();
        assert_eq!(stat.magic, TMPFS_MAGIC);
        assert_eq!(stat.blocks, (16 * 1024 * 1024 / PAGE_SIZE) as u64);
        assert_eq!(stat.files, 99);
        let metadata = fs.root.metadata().unwrap();
        assert_eq!(metadata.mode, 0o755);
        assert_eq!(metadata.uid, 12);
        assert_eq!(metadata.gid, 34);
        assert_eq!(
            TmpFsOptions::parse(1024, "unknown=1").err(),
            Some(VfsError::Invalid)
        );
    }

    #[test]
    fn sparse_pages_consume_only_allocated_capacity() {
        let fs = tmpfs(PAGE_SIZE * 2, 16);
        let root = fs.root_node();
        let file = root.create("sparse", 0o600).unwrap();
        let node = file.as_any().downcast_ref::<TmpFsNode>().unwrap();
        assert_eq!(
            node.write_at((PAGE_SIZE * 100) as u64, &[1, 2, 3]).unwrap(),
            3
        );
        let stat = fs.statfs().unwrap();
        assert_eq!(stat.blocks_free, 1);
        let mut hole = [0xff; 4];
        assert_eq!(
            node.read_at((PAGE_SIZE * 99) as u64, &mut hole).unwrap(),
            hole.len()
        );
        assert_eq!(hole, [0; 4]);

        node.write_at(0, &[9]).unwrap();
        assert_eq!(fs.statfs().unwrap().blocks_free, 0);
        assert_eq!(
            node.write_at((PAGE_SIZE * 50) as u64, &[8]).err(),
            Some(VfsError::NoSpace)
        );
        node.truncate_to(0).unwrap();
        assert_eq!(fs.statfs().unwrap().blocks_free, 2);
    }

    #[test]
    fn hard_links_share_nodes_but_directory_entries_do_not() {
        let fs = tmpfs(PAGE_SIZE * 4, 16);
        let root = fs.root_node();
        let file = root.create("first", 0o644).unwrap();
        root.link("second", &file).unwrap();
        let first = root.lookup("first").unwrap();
        let second = root.lookup("second").unwrap();
        assert_eq!(first.node_id(), second.node_id());
        assert_eq!(first.metadata().unwrap().nlink, 2);
        root.unlink("first", false).unwrap();
        assert_eq!(second.metadata().unwrap().nlink, 1);
        assert_eq!(root.lookup("first").err(), Some(VfsError::NoEntry));
    }

    #[test]
    fn open_unlinked_file_retains_data_until_last_reference() {
        let fs = tmpfs(PAGE_SIZE * 2, 16);
        let root = fs.root_node();
        let node = root.create("open", 0o600).unwrap();
        let opened = Arc::clone(&node)
            .open(VfsOpenOptions {
                readable: true,
                writable: true,
                append: false,
            })
            .unwrap();
        root.unlink("open", false).unwrap();
        assert_eq!(root.lookup("open").err(), Some(VfsError::NoEntry));

        let file = opened.as_any().downcast_ref::<TmpFsFile>().unwrap();
        file.write_at(0, b"still alive").unwrap();
        let mut output = [0; 11];
        file.read_at(0, &mut output).unwrap();
        assert_eq!(&output, b"still alive");
        assert_eq!(node.metadata().unwrap().nlink, 0);
    }

    #[test]
    fn file_description_is_the_only_shared_position_owner() {
        let fs = tmpfs(PAGE_SIZE * 2, 16);
        let root = fs.root_node();
        let node = root.create("description", 0o600).unwrap();
        let operations = Arc::clone(&node)
            .open(VfsOpenOptions {
                readable: true,
                writable: true,
                append: false,
            })
            .unwrap();
        let description = crate::fs::vfs::FileDescription::new(None, operations, 0);
        let duplicated = Arc::clone(&description);

        description.write(b"ab").unwrap();
        duplicated.write(b"cd").unwrap();
        assert_eq!(description.position().offset, 4);
        assert_eq!(duplicated.position().offset, 4);

        let mut all = [0; 4];
        description.read_at(0, &mut all).unwrap();
        assert_eq!(&all, b"abcd");
        // pread-style I/O must not change the shared sequential cursor.
        assert_eq!(description.position().offset, 4);
        description.set_offset(0);
        let mut first = [0; 2];
        duplicated.read(&mut first).unwrap();
        assert_eq!(&first, b"ab");
        assert_eq!(description.position().offset, 2);
    }

    #[test]
    fn append_is_atomic_in_the_backend_not_size_plus_write_at() {
        let fs = tmpfs(PAGE_SIZE * 2, 16);
        let root = fs.root_node();
        let node = root.create("append", 0o600).unwrap();
        let open = || {
            Arc::clone(&node)
                .open(VfsOpenOptions {
                    readable: true,
                    writable: true,
                    append: true,
                })
                .unwrap()
        };
        let first =
            crate::fs::vfs::FileDescription::new(None, open(), crate::fs::vfs::VFS_STATUS_APPEND);
        let second =
            crate::fs::vfs::FileDescription::new(None, open(), crate::fs::vfs::VFS_STATUS_APPEND);
        first.write(b"one").unwrap();
        second.write(b"two").unwrap();
        let mut output = [0; 6];
        first.read_at(0, &mut output).unwrap();
        assert_eq!(&output, b"onetwo");
        assert_eq!(first.position().offset, 3);
        assert_eq!(second.position().offset, 6);
        first.sync(false).unwrap();
        first.sync_range(0, 6, 0).unwrap();
        first.advise(0, 6, 2).unwrap();
    }

    #[test]
    fn rename_symlink_and_xattr_are_node_operations() {
        let fs = tmpfs(PAGE_SIZE * 2, 32);
        let root = fs.root_node();
        let left = root.mkdir("left", 0o755).unwrap();
        let right = root.mkdir("right", 0o755).unwrap();
        let file = left.create("file", 0o644).unwrap();
        left.rename("file", &right, "moved").unwrap();
        assert_eq!(left.lookup("file").err(), Some(VfsError::NoEntry));
        assert_eq!(right.lookup("moved").unwrap().node_id(), file.node_id());

        let link = right.symlink("link", "moved").unwrap();
        match link.readlink().unwrap() {
            VfsLink::Text(target) => assert_eq!(target, "moved"),
            VfsLink::Magic(_) | VfsLink::MagicDisplay { .. } => {
                panic!("tmpfs created an unexpected magic link")
            }
        }
        file.set_xattr("user.test", b"value", XATTR_CREATE).unwrap();
        assert_eq!(file.get_xattr("user.test").unwrap(), b"value");
        assert_eq!(file.list_xattrs().unwrap(), [String::from("user.test")]);
        assert_eq!(
            file.set_xattr("user.test", b"again", XATTR_CREATE).err(),
            Some(VfsError::Exists)
        );
        assert_eq!(
            file.set_xattr("user.test", b"again", XATTR_CREATE | XATTR_REPLACE,)
                .err(),
            Some(VfsError::Invalid)
        );
        file.remove_xattr("user.test").unwrap();

        let original_mtime = file.metadata().unwrap().times.modify_ns;
        file.update_times(Some(10), None, 30).unwrap();
        let times = file.metadata().unwrap().times;
        assert_eq!(times.access_ns, 10);
        assert_eq!(times.modify_ns, original_mtime);
        assert_eq!(times.change_ns, 30);
        file.update_times(None, Some(20), 31).unwrap();
        let times = file.metadata().unwrap().times;
        assert_eq!(times.access_ns, 10);
        assert_eq!(times.modify_ns, 20);
        assert_eq!(times.change_ns, 31);
    }

    #[test]
    fn rename_replaces_target_and_honors_no_replace_atomically() {
        let fs = tmpfs(PAGE_SIZE * 2, 32);
        let root = fs.root_node();
        let source = root.create("source", 0o644).unwrap();
        let target = root.create("target", 0o600).unwrap();

        assert_eq!(
            root.rename_with_flags(
                "source",
                &root,
                "target",
                VfsRenameFlags(VfsRenameFlags::NO_REPLACE),
            )
            .err(),
            Some(VfsError::Exists)
        );
        assert_eq!(root.lookup("source").unwrap().node_id(), source.node_id());
        assert_eq!(root.lookup("target").unwrap().node_id(), target.node_id());
        assert_eq!(target.metadata().unwrap().nlink, 1);

        root.rename("source", &root, "target").unwrap();
        assert_eq!(root.lookup("source").err(), Some(VfsError::NoEntry));
        assert_eq!(root.lookup("target").unwrap().node_id(), source.node_id());
        assert_eq!(source.metadata().unwrap().nlink, 1);
        assert_eq!(target.metadata().unwrap().nlink, 0);
    }

    #[test]
    fn cross_directory_rename_updates_parent_links_and_rejects_nonempty_target() {
        let fs = tmpfs(PAGE_SIZE * 2, 64);
        let root = fs.root_node();
        let left = root.mkdir("left", 0o755).unwrap();
        let right = root.mkdir("right", 0o755).unwrap();
        let moved = left.mkdir("moved", 0o755).unwrap();
        let victim = right.mkdir("victim", 0o755).unwrap();
        victim.create("child", 0o600).unwrap();
        let left_links = left.metadata().unwrap().nlink;
        let right_links = right.metadata().unwrap().nlink;

        assert_eq!(
            left.rename("moved", &right, "victim").err(),
            Some(VfsError::NotEmpty)
        );
        assert_eq!(left.lookup("moved").unwrap().node_id(), moved.node_id());

        victim.unlink("child", false).unwrap();
        left.rename("moved", &right, "victim").unwrap();
        assert_eq!(left.lookup("moved").err(), Some(VfsError::NoEntry));
        assert_eq!(right.lookup("victim").unwrap().node_id(), moved.node_id());
        assert_eq!(victim.metadata().unwrap().nlink, 0);
        assert_eq!(left.metadata().unwrap().nlink, left_links - 1);
        // Replacing one destination directory and then adding the moved one
        // leaves the destination parent's directory link count unchanged.
        assert_eq!(right.metadata().unwrap().nlink, right_links);
    }

    #[test]
    fn rename_exchange_swaps_nodes_and_directory_parent_links() {
        let fs = tmpfs(PAGE_SIZE * 2, 64);
        let root = fs.root_node();
        let left = root.mkdir("left", 0o755).unwrap();
        let right = root.mkdir("right", 0o755).unwrap();
        let directory = left.mkdir("directory", 0o755).unwrap();
        let file = right.create("file", 0o600).unwrap();
        let left_links = left.metadata().unwrap().nlink;
        let right_links = right.metadata().unwrap().nlink;

        left.rename_with_flags(
            "directory",
            &right,
            "file",
            VfsRenameFlags(VfsRenameFlags::EXCHANGE),
        )
        .unwrap();
        assert_eq!(left.lookup("directory").unwrap().node_id(), file.node_id());
        assert_eq!(right.lookup("file").unwrap().node_id(), directory.node_id());
        assert_eq!(left.metadata().unwrap().nlink, left_links - 1);
        assert_eq!(right.metadata().unwrap().nlink, right_links + 1);
        assert_eq!(directory.metadata().unwrap().nlink, 2);
        assert_eq!(file.metadata().unwrap().nlink, 1);
    }

    #[test]
    fn path_walker_revalidates_after_unlink() {
        let fs = tmpfs(PAGE_SIZE * 2, 16);
        let namespace =
            crate::fs::vfs::VfsMountNamespace::new(Arc::clone(&fs) as Arc<dyn VfsFileSystem>);
        let root_path = namespace.root_path();
        let walker = crate::fs::vfs::PathWalker::new(namespace);
        let root = fs.root_node();
        root.create("gone", 0o600).unwrap();
        assert!(
            walker
                .walk(
                    &root_path,
                    &root_path,
                    "/gone",
                    crate::fs::vfs::LookupFlags::default(),
                    crate::fs::vfs::VfsCredentials::default(),
                )
                .is_ok()
        );
        root.unlink("gone", false).unwrap();
        assert_eq!(
            walker
                .walk(
                    &root_path,
                    &root_path,
                    "/gone",
                    crate::fs::vfs::LookupFlags::default(),
                    crate::fs::vfs::VfsCredentials::default(),
                )
                .err(),
            Some(VfsError::NoEntry)
        );
    }
}
