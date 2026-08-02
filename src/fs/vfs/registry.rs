use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::RwLock;

use super::{Dentry, PositiveDentryCache, VfsError, VfsNode, VfsResult, VfsStatFs};

/// Stable VFS identity owned by one filesystem instance.
///
/// Linux keeps the root dentry in `super_block::s_root` and shares its dcache
/// between every mount of that superblock.  Keeping both objects here gives
/// the minimal REF-walk implementation the same identity rule without a
/// global cache.
pub struct VfsFileSystemState {
    root: Arc<Dentry>,
    dcache: PositiveDentryCache,
}

impl VfsFileSystemState {
    pub fn new(root_node: Arc<dyn VfsNode>) -> Self {
        Self {
            root: Dentry::root(root_node),
            dcache: PositiveDentryCache::default(),
        }
    }

    pub fn root_dentry(&self) -> Arc<Dentry> {
        Arc::clone(&self.root)
    }

    pub fn dentry_cache(&self) -> &PositiveDentryCache {
        &self.dcache
    }
}

/// Filesystem-wide operations.  Each filesystem instance owns one stable root
/// dentry and dcache; mounts only select which dentry is exposed as their root.
pub trait VfsFileSystem: Send + Sync {
    /// use to distinguish filesystem
    fn filesystem_id(&self) -> u64;
    fn filesystem_type(&self) -> &'static str;
    fn vfs_state(&self) -> &VfsFileSystemState;

    fn root_dentry(&self) -> Arc<Dentry> {
        self.vfs_state().root_dentry()
    }

    fn root_node(&self) -> Arc<dyn VfsNode> {
        Arc::clone(self.vfs_state().root_dentry().node())
    }

    fn dentry_cache(&self) -> &PositiveDentryCache {
        self.vfs_state().dentry_cache()
    }
    /// info about the vfs
    fn statfs(&self) -> VfsResult<VfsStatFs>;
    fn sync(&self) -> VfsResult<()>;
}

///  struct used to generate the filesystem
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VfsMountContext {
    /// Used only for device selection and mountinfo display.
    pub source: Option<String>,
    /// parameters to the factory
    pub data: String,
    /// used in procfs
    pub pid_namespace_id: Option<u64>,
    /// Cgroup namespace root captured when the mount context is created.
    ///
    /// Linux stores `current->nsproxy->cgroup_ns` in
    /// `cgroup_init_fs_context()` and exposes that cgroup as the mount root.
    /// Keep the compact implementation's stable cgroup-relative identity in
    /// the same place instead of consulting the task again at lookup time.
    pub cgroup_namespace_root: Option<String>,
}

pub trait VfsFileSystemFactory: Send + Sync {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>>;

    /// Whether mounting this filesystem requires a device source.
    ///
    /// This mirrors Linux `file_system_type::fs_flags & FS_REQUIRES_DEV` and
    /// is also the source of truth for the `nodev` column in
    /// `/proc/filesystems`.
    fn requires_device(&self) -> bool {
        false
    }
}

/// Registry used by both legacy `mount(2)` and the modern fsopen/fsmount path.
/// Filesystem instances, rather than path prefixes, select backend behavior.
#[derive(Default)]
pub struct VfsFileSystemRegistry {
    factories: RwLock<BTreeMap<String, Arc<dyn VfsFileSystemFactory>>>,
}

impl VfsFileSystemRegistry {
    /// add a new kind of filesystem to the system
    pub fn register(
        &self,
        filesystem_type: &str,
        factory: Arc<dyn VfsFileSystemFactory>,
    ) -> VfsResult<()> {
        if filesystem_type.is_empty() {
            return Err(VfsError::Invalid);
        }
        let mut factories = self.factories.write();
        if factories.contains_key(filesystem_type) {
            return Err(VfsError::Exists);
        }
        factories.insert(filesystem_type.to_string(), factory);
        Ok(())
    }

    /// Given certain parameters(context),initilize a filesystem
    pub fn create(
        &self,
        filesystem_type: &str,
        context: &VfsMountContext,
    ) -> VfsResult<Arc<dyn VfsFileSystem>> {
        self.factories
            .read()
            .get(filesystem_type)
            .cloned()
            .ok_or(VfsError::NotSupported)?
            .create(context)
    }

    /// Return every registered filesystem type and its device requirement.
    pub fn filesystem_types(&self) -> Vec<(String, bool)> {
        self.factories
            .read()
            .iter()
            .map(|(name, factory)| (name.clone(), factory.requires_device()))
            .collect()
    }
}
