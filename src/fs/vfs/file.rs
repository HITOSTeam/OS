use crate::fs::File;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use super::{PinnedPath, VfsPath};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilePosition {
    pub offset: u64,
    pub directory_cookie: u64,
}

/// Shared open-file description.  Descriptor duplication, fork and
/// SCM_RIGHTS share this object rather than copying status flags or position.
pub struct FileDescription {
    path: Option<PinnedPath>,
    operations: Arc<dyn File + Send + Sync>,
    status_flags: AtomicUsize,
    position: Mutex<FilePosition>,
}

impl FileDescription {
    pub fn new(
        path: Option<PinnedPath>,
        operations: Arc<dyn File + Send + Sync>,
        status_flags: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            path,
            operations,
            status_flags: AtomicUsize::new(status_flags),
            position: Mutex::new(FilePosition::default()),
        })
    }

    pub fn path(&self) -> Option<&PinnedPath> {
        self.path.as_ref()
    }

    pub fn operations(&self) -> &Arc<dyn File + Send + Sync> {
        &self.operations
    }

    pub fn status_flags(&self) -> usize {
        self.status_flags.load(Ordering::Acquire)
    }

    pub fn set_status_flags(&self, flags: usize) {
        self.status_flags.store(flags, Ordering::Release);
    }

    pub fn position(&self) -> &Mutex<FilePosition> {
        &self.position
    }
}

struct FsPaths {
    root: PinnedPath,
    cwd: PinnedPath,
}

/// Linux-style filesystem context.  Sharing the `Arc<FsStruct>` implements
/// `CLONE_FS`; `clone_private` snapshots cwd/root pins for normal fork.
pub struct FsStruct {
    paths: RwLock<FsPaths>,
}

impl FsStruct {
    pub fn new(root: VfsPath) -> Arc<Self> {
        Arc::new(Self {
            paths: RwLock::new(FsPaths {
                root: PinnedPath::new(root.clone()),
                cwd: PinnedPath::new(root),
            }),
        })
    }

    pub fn clone_private(&self) -> Arc<Self> {
        let paths = self.paths.read();
        Arc::new(Self {
            paths: RwLock::new(FsPaths {
                root: paths.root.clone(),
                cwd: paths.cwd.clone(),
            }),
        })
    }

    pub fn root(&self) -> PinnedPath {
        self.paths.read().root.clone()
    }

    pub fn cwd(&self) -> PinnedPath {
        self.paths.read().cwd.clone()
    }

    pub fn set_root(&self, root: VfsPath) {
        self.paths.write().root = PinnedPath::new(root);
    }

    pub fn set_cwd(&self, cwd: VfsPath) {
        self.paths.write().cwd = PinnedPath::new(cwd);
    }
}
