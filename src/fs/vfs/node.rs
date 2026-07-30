use crate::fs::File;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::{VfsDirEntry, VfsError, VfsMetadata, VfsNodeKind, VfsOpenOptions, VfsPath, VfsResult};

/// A symlink either contains text or is a proc-style magic link to an already
/// resolved object.  Magic links never synthesize an absolute pathname.
#[derive(Clone)]
pub enum VfsLink {
    Text(String),
    Magic(VfsPath),
}

/// used in cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DentryCachePolicy {
    Stable,
    Revalidate,
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

    fn open(self: Arc<Self>, _options: VfsOpenOptions) -> VfsResult<Arc<dyn File + Send + Sync>> {
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

    fn truncate(&self, _size: u64) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn get_xattr(&self, _name: &str) -> VfsResult<Vec<u8>> {
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
}
