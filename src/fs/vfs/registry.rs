use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use spin::RwLock;

use super::{VfsError, VfsNode, VfsResult, VfsStatFs};

/// Filesystem-wide operations.  The mount owns the root dentry so that a bind
/// mount can use a non-root dentry without manufacturing another filesystem.
pub trait VfsFileSystem: Send + Sync {
    /// use to distinguish filesystem
    fn filesystem_id(&self) -> u64;
    fn filesystem_type(&self) -> &'static str;
    fn root_node(&self) -> Arc<dyn VfsNode>;
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
}

pub trait VfsFileSystemFactory: Send + Sync {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>>;
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
}
