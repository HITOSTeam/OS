use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::{
    VfsDirEntry, VfsError, VfsFileOperations, VfsMetadata, VfsNodeKind, VfsOpenOptions, VfsPath,
    VfsResult,
};

/// A symlink either contains text or is a proc-style magic link to an already
/// resolved object.  Magic links never synthesize an absolute pathname.
#[derive(Clone)]
pub enum VfsLink {
    Text(String),
    Magic(VfsPath),
    /// An object-valued magic link whose user-visible spelling is supplied by
    /// the backend. Linux nsfs uses this for names such as `mnt:[4026531841]`:
    /// path walking jumps to the nsfs object, while readlink returns the
    /// dynamic display name rather than an internal mount path.
    MagicDisplay {
        target: VfsPath,
        display: String,
    },
}

/// used in cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DentryCachePolicy {
    /// Namespace mutations are fully mediated by the VFS and explicitly
    /// invalidate affected dentries.
    Stable,
    /// The backend publishes a per-directory namespace generation before any
    /// child-name mutation.  A matching generation makes the cached positive
    /// authoritative without repeating the filesystem lookup.
    Versioned(usize),
    /// Dynamic namespaces whose contents can change without a local mutation
    /// notification must validate every positive lookup with the backend.
    Revalidate,
}

/// Flags for an atomic VFS rename operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsRenameFlags(pub u32);

impl VfsRenameFlags {
    pub const NO_REPLACE: u32 = 1;
    pub const EXCHANGE: u32 = 2;

    pub fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

/// Stable filesystem object operations.
///
/// Mutation methods default to Linux-like "operation not supported".  Backends
/// opt in only to operations they can implement with correct lifetime rules.
pub trait VfsNode: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn node_id(&self) -> u64;
    fn filesystem_id(&self) -> u64;
    fn metadata(&self) -> VfsResult<VfsMetadata>;

    fn dentry_cache_policy(&self) -> DentryCachePolicy {
        DentryCachePolicy::Stable
    }

    fn lookup(&self, _name: &str) -> VfsResult<Arc<dyn VfsNode>> {
        Err(VfsError::NotDirectory)
    }

    fn readdir(&self) -> VfsResult<Vec<VfsDirEntry>> {
        Err(VfsError::NotDirectory)
    }

    fn readlink(&self) -> VfsResult<VfsLink> {
        Err(VfsError::Invalid)
    }

    fn open(self: Arc<Self>, _options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        Err(VfsError::NotSupported)
    }

    fn create(&self, _name: &str, _mode: u16) -> VfsResult<Arc<dyn VfsNode>> {
        Err(VfsError::NotSupported)
    }

    fn mkdir(&self, _name: &str, _mode: u16) -> VfsResult<Arc<dyn VfsNode>> {
        Err(VfsError::NotSupported)
    }

    fn symlink(&self, _name: &str, _target: &str) -> VfsResult<Arc<dyn VfsNode>> {
        Err(VfsError::NotSupported)
    }

    fn link(&self, _name: &str, _target: &Arc<dyn VfsNode>) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn unlink(&self, _name: &str, _remove_dir: bool) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn rename(
        &self,
        _old_name: &str,
        _new_parent: &Arc<dyn VfsNode>,
        _new_name: &str,
    ) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    /// Atomic rename with Linux `renameat2` policy flags. Backends that only
    /// implement classic rename retain the existing method as their fallback.
    fn rename_with_flags(
        &self,
        old_name: &str,
        new_parent: &Arc<dyn VfsNode>,
        new_name: &str,
        flags: VfsRenameFlags,
    ) -> VfsResult<()> {
        if flags.0 != 0 {
            return Err(VfsError::NotSupported);
        }
        self.rename(old_name, new_parent, new_name)
    }

    fn truncate(&self, _size: u64) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn get_xattr(&self, _name: &str) -> VfsResult<Vec<u8>> {
        Err(VfsError::NotSupported)
    }

    fn list_xattrs(&self) -> VfsResult<Vec<String>> {
        Err(VfsError::NotSupported)
    }

    fn set_xattr(&self, _name: &str, _value: &[u8], _flags: u32) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn remove_xattr(&self, _name: &str) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn mknod(
        &self,
        _name: &str,
        _kind: VfsNodeKind,
        _mode: u16,
        _rdev: u64,
    ) -> VfsResult<Arc<dyn VfsNode>> {
        Err(VfsError::NotSupported)
    }

    fn set_mode(&self, _mode: u16) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn set_owner(&self, _uid: u32, _gid: u32) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    /// Atomically update the common ownership and permission fields. Mutable
    /// filesystems override this so chown's set-id clearing is not visible as
    /// a sequence of partially applied metadata changes.
    fn set_mode_owner(&self, mode: u16, uid: u32, gid: u32) -> VfsResult<()> {
        self.set_owner(uid, gid)?;
        self.set_mode(mode)
    }

    /// Atomically update inode timestamps selected by `utimensat(2)`.
    /// `None` preserves the corresponding atime/mtime; ctime always records
    /// the metadata change that successfully committed both selections.
    fn update_times(
        &self,
        _access_ns: Option<u64>,
        _modify_ns: Option<u64>,
        _change_ns: u64,
    ) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }
}
