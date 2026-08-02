//! Object-VFS backend for devtmpfs.
//!
//! Linux devtmpfs is a kernel-maintained tmpfs superblock: pathname lookup is
//! ordinary VFS lookup, while opening a device installs that driver's file
//! operations in a `struct file` that also pins `f_path`.  `DevOpenedFile`
//! implements the same boundary for this kernel.  It forwards the existing
//! device object ABI while retaining the resolved mount+dentry.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use crate::fs::vfs::{
    DentryCachePolicy, PinnedPath, VfsDirEntry, VfsError, VfsFileOperations, VfsFileSystem,
    VfsFileSystemFactory, VfsFileSystemState, VfsMetadata, VfsMountContext, VfsNode, VfsNodeKind,
    VfsOpenOptions, VfsPath, VfsResult, VfsStatFs, VfsTimes,
};
use crate::fs::{File, PseudoDir};
use crate::mm::UserBuffer;
use crate::task::task_block::TaskControlBlock;

use super::open_legacy;

const TMPFS_MAGIC: u64 = 0x0102_1994;
const DEVTMPFS_BLOCK_SIZE: u64 = 4096;
static NEXT_DEVTMPFS_ID: AtomicUsize = AtomicUsize::new(0x38_000);

lazy_static::lazy_static! {
    /// Linux's public devtmpfs mounts all take a reference to the internal
    /// kernel mount's existing superblock and root.
    static ref DEVTMPFS_INSTANCE: Arc<DevTmpFs> = DevTmpFs::new();
    /// Mutable inode attributes live with the shared devtmpfs superblock, not
    /// with transient open device objects or dentries.
    static ref DEVTMPFS_ATTRIBUTES: RwLock<BTreeMap<String, DevAttributes>> =
        RwLock::new(BTreeMap::new());
}

#[derive(Clone, Copy)]
struct DevAttributes {
    mode: u16,
    uid: u32,
    gid: u32,
}

pub(crate) struct DevTmpFs {
    id: u64,
    vfs_state: VfsFileSystemState,
}

impl DevTmpFs {
    fn new() -> Arc<Self> {
        let id = NEXT_DEVTMPFS_ID.fetch_add(1, Ordering::Relaxed) as u64;
        Arc::new_cyclic(|weak_fs| {
            let root = Arc::new(DevNode::new(weak_fs.clone(), "/dev"));
            Self {
                id,
                vfs_state: VfsFileSystemState::new(root as Arc<dyn VfsNode>),
            }
        })
    }

    fn node(self: &Arc<Self>, provider_path: &str) -> VfsResult<Arc<DevNode>> {
        let node = Arc::new(DevNode::new(Arc::downgrade(self), provider_path));
        node.kind()?;
        Ok(node)
    }
}

impl VfsFileSystem for DevTmpFs {
    fn filesystem_id(&self) -> u64 {
        self.id
    }

    fn filesystem_type(&self) -> &'static str {
        "devtmpfs"
    }

    fn vfs_state(&self) -> &VfsFileSystemState {
        &self.vfs_state
    }

    fn statfs(&self) -> VfsResult<VfsStatFs> {
        // Linux devtmpfs uses shmem/tmpfs (or ramfs without CONFIG_TMPFS), so
        // statfs exposes TMPFS_MAGIC rather than a synthetic devtmpfs magic.
        Ok(VfsStatFs {
            magic: TMPFS_MAGIC,
            block_size: DEVTMPFS_BLOCK_SIZE,
            blocks: 0,
            blocks_free: 0,
            blocks_available: 0,
            files: 0,
            files_free: 0,
            name_len: 255,
        })
    }

    fn sync(&self) -> VfsResult<()> {
        Ok(())
    }
}

pub(crate) struct DevTmpFsFactory;

impl VfsFileSystemFactory for DevTmpFsFactory {
    fn create(&self, _context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        Ok(Arc::clone(&DEVTMPFS_INSTANCE) as Arc<dyn VfsFileSystem>)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevKind {
    Directory,
    Character { rdev: u64 },
    Block { rdev: u64 },
}

impl DevKind {
    fn node_kind(self) -> VfsNodeKind {
        match self {
            Self::Directory => VfsNodeKind::Directory,
            Self::Character { .. } => VfsNodeKind::CharacterDevice,
            Self::Block { .. } => VfsNodeKind::BlockDevice,
        }
    }

    fn rdev(self) -> u64 {
        match self {
            Self::Character { rdev } | Self::Block { rdev } => rdev,
            Self::Directory => 0,
        }
    }
}

pub(crate) struct DevNode {
    fs: Weak<DevTmpFs>,
    provider_path: String,
    node_id: u64,
    created_ns: u64,
}

impl DevNode {
    fn new(fs: Weak<DevTmpFs>, provider_path: &str) -> Self {
        Self {
            fs,
            provider_path: provider_path.to_string(),
            node_id: devtmpfs_node_id(provider_path),
            created_ns: crate::time::get_realtime_ns(),
        }
    }

    fn fs(&self) -> VfsResult<Arc<DevTmpFs>> {
        self.fs.upgrade().ok_or(VfsError::Invalid)
    }

    fn kind(&self) -> VfsResult<DevKind> {
        dev_kind(&self.provider_path).ok_or(VfsError::NoEntry)
    }

    fn child_path(&self, name: &str) -> VfsResult<String> {
        if name.is_empty()
            || name.len() > 255
            || name.contains('/')
            || name.as_bytes().contains(&0)
            || matches!(name, "." | "..")
        {
            return Err(VfsError::Invalid);
        }
        let mut path = self.provider_path.clone();
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(name);
        Ok(path)
    }

    fn backing(&self) -> VfsResult<Arc<dyn File + Send + Sync>> {
        open_legacy(&self.provider_path).ok_or(VfsError::NoEntry)
    }

    fn default_attributes(&self) -> DevAttributes {
        let mode = match dev_kind(&self.provider_path) {
            Some(DevKind::Directory) => 0o755,
            Some(DevKind::Block { .. }) => 0o600,
            Some(DevKind::Character { .. }) | None => 0o666,
        };
        DevAttributes {
            mode,
            uid: 0,
            gid: 0,
        }
    }
}

impl VfsNode for DevNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn node_id(&self) -> u64 {
        self.node_id
    }

    fn filesystem_id(&self) -> u64 {
        self.fs.upgrade().map_or(0, |fs| fs.id)
    }

    fn metadata(&self) -> VfsResult<VfsMetadata> {
        let kind = self.kind()?;
        let size = 0;
        let default_mode = match kind {
            DevKind::Directory => 0o755,
            DevKind::Block { .. } => 0o600,
            DevKind::Character { .. } => 0o666,
        };
        let attributes = DEVTMPFS_ATTRIBUTES
            .read()
            .get(&self.provider_path)
            .copied()
            .unwrap_or(DevAttributes {
                mode: default_mode,
                uid: 0,
                gid: 0,
            });
        Ok(VfsMetadata {
            kind: kind.node_kind(),
            mode: attributes.mode,
            uid: attributes.uid,
            gid: attributes.gid,
            nlink: if kind == DevKind::Directory { 2 } else { 1 },
            size,
            rdev: kind.rdev(),
            times: VfsTimes {
                access_ns: self.created_ns,
                modify_ns: self.created_ns,
                change_ns: self.created_ns,
            },
        })
    }

    fn dentry_cache_policy(&self) -> DentryCachePolicy {
        // devpts instances, POSIX shm compatibility entries and dynamically
        // created mountpoint directories all have externally changing life.
        DentryCachePolicy::Revalidate
    }

    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn VfsNode>> {
        if self.kind()? != DevKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let path = self.child_path(name)?;
        Ok(self.fs()?.node(&path)? as Arc<dyn VfsNode>)
    }

    fn readdir(&self) -> VfsResult<Vec<VfsDirEntry>> {
        if self.kind()? != DevKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let file = self.backing()?;
        let directory = file
            .as_any()
            .downcast_ref::<PseudoDir>()
            .ok_or(VfsError::NotDirectory)?;
        let mut output = Vec::with_capacity(directory.entries().len().saturating_sub(2));
        for entry in directory.entries() {
            if matches!(entry.name.as_str(), "." | "..") {
                continue;
            }
            let path = self.child_path(&entry.name)?;
            let kind = dev_kind(&path)
                .map(DevKind::node_kind)
                .unwrap_or_else(|| dtype_to_kind(entry.dtype));
            output.push(VfsDirEntry {
                name: entry.name.clone(),
                node_id: devtmpfs_node_id(&path),
                kind,
            });
        }
        Ok(output)
    }

    fn open(self: Arc<Self>, options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        if self.kind()? != DevKind::Directory {
            return Err(VfsError::NotSupported);
        }
        if options.writable {
            return Err(VfsError::IsDirectory);
        }
        Ok(Arc::new(DevDirectoryOperations {
            readable: options.readable,
        }))
    }

    fn mkdir(&self, name: &str, mode: u16) -> VfsResult<Arc<dyn VfsNode>> {
        if self.provider_path != "/dev" {
            return Err(VfsError::ReadOnly);
        }
        let path = self.child_path(name)?;
        match crate::fs::pseudo_dev_dir_mkdir(&path) {
            0 => {
                DEVTMPFS_ATTRIBUTES.write().insert(
                    path.clone(),
                    DevAttributes {
                        mode: mode & 0o7777,
                        uid: 0,
                        gid: 0,
                    },
                );
                Ok(self.fs()?.node(&path)? as Arc<dyn VfsNode>)
            }
            -17 => Err(VfsError::Exists),
            -30 => Err(VfsError::ReadOnly),
            _ => Err(VfsError::Invalid),
        }
    }

    fn unlink(&self, name: &str, remove_dir: bool) -> VfsResult<()> {
        if self.provider_path != "/dev" {
            return Err(VfsError::ReadOnly);
        }
        if !remove_dir {
            return Err(VfsError::ReadOnly);
        }
        let path = self.child_path(name)?;
        match crate::fs::pseudo_dev_dir_rmdir(&path) {
            0 => {
                DEVTMPFS_ATTRIBUTES.write().remove(&path);
                Ok(())
            }
            -2 => Err(VfsError::NoEntry),
            -30 => Err(VfsError::ReadOnly),
            _ => Err(VfsError::Invalid),
        }
    }

    fn set_mode(&self, mode: u16) -> VfsResult<()> {
        self.kind()?;
        let mut attributes = DEVTMPFS_ATTRIBUTES.write();
        let entry = attributes
            .entry(self.provider_path.clone())
            .or_insert_with(|| self.default_attributes());
        entry.mode = mode & 0o7777;
        Ok(())
    }

    fn set_owner(&self, uid: u32, gid: u32) -> VfsResult<()> {
        self.kind()?;
        let mut attributes = DEVTMPFS_ATTRIBUTES.write();
        let entry = attributes
            .entry(self.provider_path.clone())
            .or_insert_with(|| self.default_attributes());
        entry.uid = uid;
        entry.gid = gid;
        Ok(())
    }
}

struct DevDirectoryOperations {
    readable: bool,
}

impl VfsFileOperations for DevDirectoryOperations {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        false
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }
}

/// Open a special node while retaining its resolved VFS path.  `None` means
/// that `path` is not a devtmpfs device (directories continue through the
/// generic `VfsOpenedFile` path).
pub(crate) fn open_devtmpfs_path(
    path: &VfsPath,
    logical_path: &str,
    readable: bool,
    writable: bool,
) -> Option<VfsResult<Arc<dyn File + Send + Sync>>> {
    let node = path.node().as_any().downcast_ref::<DevNode>()?;
    let kind = match node.kind() {
        Ok(kind) => kind,
        Err(error) => return Some(Err(error)),
    };
    if kind == DevKind::Directory {
        return None;
    }
    let backing = match node.backing() {
        Ok(backing) => backing,
        Err(error) => return Some(Err(error)),
    };
    if (readable && !backing.readable()) || (writable && !backing.writable()) {
        return Some(Err(VfsError::Access));
    }
    Some(Ok(Arc::new(DevOpenedFile {
        path: PinnedPath::new(path.clone()),
        logical_path: logical_path.to_string(),
        backing,
        readable,
        writable,
    })))
}

/// Device file-description adapter.  `as_any()` deliberately exposes the
/// driver object so existing ioctl/read/write dispatch remains type-correct;
/// path-aware VFS consumers use `object_path()` instead.
struct DevOpenedFile {
    path: PinnedPath,
    logical_path: String,
    backing: Arc<dyn File + Send + Sync>,
    readable: bool,
    writable: bool,
}

impl File for DevOpenedFile {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, buffer: UserBuffer) -> usize {
        self.backing.read(buffer)
    }

    fn write(&self, buffer: UserBuffer) -> usize {
        self.backing.write(buffer)
    }

    fn poll_mask(&self) -> i16 {
        self.backing.poll_mask()
    }

    fn fixed_poll_mask(&self) -> Option<i16> {
        self.backing.fixed_poll_mask()
    }

    fn supports_poll(&self) -> bool {
        self.backing.supports_poll()
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        self.backing.register_poll_waiter(task)
    }

    fn on_fd_install(&self) {
        self.backing.on_fd_install();
    }

    fn on_fd_close(&self) {
        self.backing.on_fd_close();
    }

    fn object_path(&self) -> Option<&VfsPath> {
        Some(self.path.path())
    }

    fn logical_path_hint(&self) -> Option<&str> {
        Some(&self.logical_path)
    }

    fn as_any(&self) -> &dyn Any {
        self.backing.as_any()
    }
}

fn dev_kind(path: &str) -> Option<DevKind> {
    if matches!(
        path.trim_end_matches('/'),
        "/dev" | "/dev/net" | "/dev/cgroup" | "/dev/pts" | "/dev/shm" | "/dev/misc"
    ) || crate::fs::pseudo_dev_dir_exists(path.trim_end_matches('/'))
    {
        return Some(DevKind::Directory);
    }
    if matches!(path, "/dev/root" | "/dev/vda" | "/dev/vdb" | "/dev/vdc") {
        return Some(DevKind::Block { rdev: 0x100 });
    }
    let rdev = match path {
        "/dev/null" => 0x103,
        "/dev/zero" => 0x105,
        "/dev/random" => 0x108,
        "/dev/urandom" => 0x109,
        "/dev/tty" => 0x500,
        "/dev/ptmx" => 0x502,
        "/dev/net/tun" => 0x0a_c8,
        "/dev/misc/rtc" => 0x0a_87,
        _ => {
            if let Some(index) = devpts_index(path) {
                if crate::fs::dev_pts_exists(index) {
                    return Some(DevKind::Character {
                        rdev: (136u64 << 8) | u64::from(index),
                    });
                }
            }
            return None;
        }
    };
    Some(DevKind::Character { rdev })
}

fn devpts_index(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("/dev/pts/")?;
    if rest.is_empty() || rest.contains('/') || !rest.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

fn dtype_to_kind(dtype: u8) -> VfsNodeKind {
    match dtype {
        4 => VfsNodeKind::Directory,
        10 => VfsNodeKind::Symlink,
        1 => VfsNodeKind::Fifo,
        2 => VfsNodeKind::CharacterDevice,
        6 => VfsNodeKind::BlockDevice,
        12 => VfsNodeKind::Socket,
        _ => VfsNodeKind::Regular,
    }
}

fn devtmpfs_node_id(path: &str) -> u64 {
    if path == "/dev" {
        return 1;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in path.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.max(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_device_kinds_and_numbers_match_linux() {
        assert_eq!(
            dev_kind("/dev/null"),
            Some(DevKind::Character { rdev: 0x103 })
        );
        assert_eq!(
            dev_kind("/dev/zero"),
            Some(DevKind::Character { rdev: 0x105 })
        );
        assert_eq!(
            dev_kind("/dev/ptmx"),
            Some(DevKind::Character { rdev: 0x502 })
        );
        assert_eq!(dev_kind("/dev/root"), Some(DevKind::Block { rdev: 0x100 }));
    }

    #[test]
    fn node_ids_are_stable_inside_the_shared_superblock() {
        assert_eq!(devtmpfs_node_id("/dev"), 1);
        assert_eq!(devtmpfs_node_id("/dev/null"), devtmpfs_node_id("/dev/null"));
        assert_ne!(devtmpfs_node_id("/dev/null"), devtmpfs_node_id("/dev/zero"));
    }
}
