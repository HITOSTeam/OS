//! Object-VFS adapter for sysfs.
//!
//! Linux exposes sysfs through kernfs inodes and dentries; the mountpoint is
//! only a `struct mount` concern.  This compact backend keeps that separation:
//! each node owns a sysfs-internal provider key rooted at `/sys`, and the VFS
//! mount graph decides where that node tree is visible.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::fs::vfs::{
    DentryCachePolicy, VfsDirEntry, VfsError, VfsFileOperations, VfsFileSystem,
    VfsFileSystemFactory, VfsFileSystemState, VfsMetadata, VfsMountContext, VfsNode, VfsNodeKind,
    VfsOpenOptions, VfsResult, VfsStatFs, VfsTimes,
};
use crate::fs::{File, PseudoDir, PseudoFile};

use super::open_legacy;

const SYSFS_MAGIC: u64 = 0x6265_6572;
const SYSFS_BLOCK_SIZE: u64 = 4096;
static NEXT_SYSFS_ID: AtomicUsize = AtomicUsize::new(0x30_000);

/// One sysfs superblock.  Nodes are generated from current kernel state, but
/// their identity and dcache belong to this filesystem instance.
pub(crate) struct SysFs {
    id: u64,
    vfs_state: VfsFileSystemState,
}

impl SysFs {
    pub(crate) fn new() -> Arc<Self> {
        let id = NEXT_SYSFS_ID.fetch_add(1, Ordering::Relaxed) as u64;
        Arc::new_cyclic(|weak_fs| {
            let root = Arc::new(SysNode::new(weak_fs.clone(), "/sys"));
            Self {
                id,
                vfs_state: VfsFileSystemState::new(root as Arc<dyn VfsNode>),
            }
        })
    }

    fn node(self: &Arc<Self>, provider_path: &str) -> VfsResult<Arc<SysNode>> {
        let node = Arc::new(SysNode::new(Arc::downgrade(self), provider_path));
        node.object()?;
        Ok(node)
    }
}

impl VfsFileSystem for SysFs {
    fn filesystem_id(&self) -> u64 {
        self.id
    }

    fn filesystem_type(&self) -> &'static str {
        "sysfs"
    }

    fn vfs_state(&self) -> &VfsFileSystemState {
        &self.vfs_state
    }

    fn statfs(&self) -> VfsResult<VfsStatFs> {
        Ok(VfsStatFs {
            magic: SYSFS_MAGIC,
            block_size: SYSFS_BLOCK_SIZE,
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

pub(crate) struct SysFsFactory;

impl VfsFileSystemFactory for SysFsFactory {
    fn create(&self, _context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        Ok(SysFs::new())
    }
}

enum SysObject {
    Directory(Arc<dyn File + Send + Sync>),
    Regular(Arc<dyn File + Send + Sync>),
}

/// A sysfs inode key.  It is independent of `/sys`'s userspace location so
/// arbitrary mounts and bind-mounted subtrees retain the same inode identity.
pub(crate) struct SysNode {
    fs: Weak<SysFs>,
    provider_path: String,
    node_id: u64,
    created_ns: u64,
}

impl SysNode {
    fn new(fs: Weak<SysFs>, provider_path: &str) -> Self {
        Self {
            fs,
            provider_path: provider_path.to_string(),
            node_id: sysfs_node_id(provider_path),
            created_ns: crate::time::get_realtime_ns(),
        }
    }

    fn fs(&self) -> VfsResult<Arc<SysFs>> {
        self.fs.upgrade().ok_or(VfsError::Invalid)
    }

    fn object(&self) -> VfsResult<SysObject> {
        let file = open_legacy(&self.provider_path).ok_or(VfsError::NoEntry)?;
        if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            Ok(SysObject::Directory(file))
        } else if file.as_any().downcast_ref::<PseudoFile>().is_some() {
            Ok(SysObject::Regular(file))
        } else {
            Err(VfsError::NotSupported)
        }
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

    fn metadata_for(&self, object: &SysObject) -> VfsMetadata {
        let (kind, mode, nlink, size) = match object {
            SysObject::Directory(_) => (VfsNodeKind::Directory, 0o555, 2, 0),
            SysObject::Regular(file) => {
                let size = file
                    .as_any()
                    .downcast_ref::<PseudoFile>()
                    .and_then(PseudoFile::len)
                    .unwrap_or(0) as u64;
                (VfsNodeKind::Regular, 0o444, 1, size)
            }
        };
        VfsMetadata {
            kind,
            mode,
            uid: 0,
            gid: 0,
            nlink,
            size,
            rdev: 0,
            times: VfsTimes {
                access_ns: self.created_ns,
                modify_ns: self.created_ns,
                change_ns: self.created_ns,
            },
        }
    }
}

impl VfsNode for SysNode {
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
        let object = self.object()?;
        Ok(self.metadata_for(&object))
    }

    fn dentry_cache_policy(&self) -> DentryCachePolicy {
        // Network devices may appear and disappear.  The minimal REF-walk has
        // no kernfs generation counter, so positive entries are revalidated.
        DentryCachePolicy::Revalidate
    }

    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn VfsNode>> {
        if !matches!(self.object()?, SysObject::Directory(_)) {
            return Err(VfsError::NotDirectory);
        }
        let path = self.child_path(name)?;
        Ok(self.fs()?.node(&path)? as Arc<dyn VfsNode>)
    }

    fn readdir(&self) -> VfsResult<Vec<VfsDirEntry>> {
        let SysObject::Directory(file) = self.object()? else {
            return Err(VfsError::NotDirectory);
        };
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
            output.push(VfsDirEntry {
                name: entry.name.clone(),
                node_id: sysfs_node_id(&path),
                kind: dtype_to_kind(entry.dtype),
            });
        }
        Ok(output)
    }

    fn open(self: Arc<Self>, options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        let object = self.object()?;
        let backing = match object {
            SysObject::Directory(file) | SysObject::Regular(file) => file,
        };
        if options.writable || (options.readable && !backing.readable()) {
            return Err(VfsError::Access);
        }
        Ok(Arc::new(SysFileOperations {
            backing,
            readable: options.readable,
        }))
    }
}

struct SysFileOperations {
    backing: Arc<dyn File + Send + Sync>,
    readable: bool,
}

impl VfsFileOperations for SysFileOperations {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        false
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> VfsResult<usize> {
        if !self.readable {
            return Err(VfsError::Access);
        }
        let offset = usize::try_from(offset).map_err(|_| VfsError::Invalid)?;
        let file = self
            .backing
            .as_any()
            .downcast_ref::<PseudoFile>()
            .ok_or(VfsError::NotSupported)?;
        file.read_at_bytes(offset, output)
            .ok_or(VfsError::NotSupported)
    }

    fn size(&self) -> VfsResult<u64> {
        Ok(self
            .backing
            .as_any()
            .downcast_ref::<PseudoFile>()
            .and_then(PseudoFile::len)
            .unwrap_or(0) as u64)
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }
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

fn sysfs_node_id(path: &str) -> u64 {
    if path == "/sys" {
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
    fn node_ids_are_mountpoint_independent() {
        assert_eq!(sysfs_node_id("/sys"), 1);
        assert_eq!(
            sysfs_node_id("/sys/devices/system/cpu/online"),
            sysfs_node_id("/sys/devices/system/cpu/online")
        );
        assert_ne!(sysfs_node_id("/sys/block"), sysfs_node_id("/sys/dev"));
    }

    #[test]
    fn dtype_mapping_matches_linux_dirent_values() {
        assert_eq!(dtype_to_kind(4), VfsNodeKind::Directory);
        assert_eq!(dtype_to_kind(8), VfsNodeKind::Regular);
        assert_eq!(dtype_to_kind(10), VfsNodeKind::Symlink);
    }
}
