use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use super::{PinnedPath, VfsError, VfsMountNamespaceClone, VfsPath, VfsResult};

/// Linux `O_APPEND`; append state belongs to the shared description.
pub const VFS_STATUS_APPEND: usize = 0x400;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilePosition {
    pub offset: u64,
    pub directory_cookie: u64,
}

/// Stateless operations belonging to an opened VFS node.
///
/// Byte I/O always receives an explicit offset.  Sequential position lives in
/// `FileDescription`, matching Linux `struct file::f_pos`.
pub trait VfsFileOperations: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn readable(&self) -> bool;
    fn writable(&self) -> bool;

    fn read_at(&self, _offset: u64, _output: &mut [u8]) -> VfsResult<usize> {
        Err(VfsError::NotSupported)
    }

    fn write_at(&self, _offset: u64, _input: &[u8]) -> VfsResult<usize> {
        Err(VfsError::NotSupported)
    }

    fn size(&self) -> VfsResult<u64> {
        Err(VfsError::NotSupported)
    }

    /// Append under the backend inode/data lock.  A default
    /// `size()+write_at()` would not provide atomic O_APPEND semantics.
    fn append(&self, _input: &[u8]) -> VfsResult<(u64, usize)> {
        Err(VfsError::NotSupported)
    }

    /// Flush this open file's dirty data and, unless `data_only` is set,
    /// metadata required by `fsync(2)`.
    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    /// Initiate or wait for writeback in one byte range.  Filesystems without
    /// a page-cache distinction may implement this as a no-op.
    fn sync_range(&self, _offset: u64, _length: u64, _flags: u32) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    /// Apply an advisory access-pattern hint to this open description.
    fn advise(&self, _offset: u64, _length: u64, _advice: u32) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }
}

/// Shared open-file description.  dup, fork and SCM_RIGHTS share this object.
pub struct FileDescription {
    path: Option<PinnedPath>,
    operations: Arc<dyn VfsFileOperations>,
    status_flags: AtomicUsize,
    position: Mutex<FilePosition>,
}

impl FileDescription {
    pub fn new(
        path: Option<PinnedPath>,
        operations: Arc<dyn VfsFileOperations>,
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

    pub fn operations(&self) -> &Arc<dyn VfsFileOperations> {
        &self.operations
    }

    pub fn status_flags(&self) -> usize {
        self.status_flags.load(Ordering::Acquire)
    }

    pub fn set_append(&self, enabled: bool) {
        if enabled {
            self.status_flags
                .fetch_or(VFS_STATUS_APPEND, Ordering::AcqRel);
        } else {
            self.status_flags
                .fetch_and(!VFS_STATUS_APPEND, Ordering::AcqRel);
        }
    }

    pub fn position(&self) -> FilePosition {
        *self.position.lock()
    }

    pub fn set_offset(&self, offset: u64) {
        self.position.lock().offset = offset;
    }

    pub fn set_directory_cookie(&self, cookie: u64) {
        self.position.lock().directory_cookie = cookie;
    }

    pub fn read(&self, output: &mut [u8]) -> VfsResult<usize> {
        if !self.operations.readable() {
            return Err(VfsError::Access);
        }
        let mut position = self.position.lock();
        let read = self.operations.read_at(position.offset, output)?;
        position.offset = position.offset.saturating_add(read as u64);
        Ok(read)
    }

    pub fn write(&self, input: &[u8]) -> VfsResult<usize> {
        if !self.operations.writable() {
            return Err(VfsError::Access);
        }
        let mut position = self.position.lock();
        if self.status_flags() & VFS_STATUS_APPEND != 0 {
            let (offset, written) = self.operations.append(input)?;
            position.offset = offset.saturating_add(written as u64);
            return Ok(written);
        }
        let written = self.operations.write_at(position.offset, input)?;
        position.offset = position.offset.saturating_add(written as u64);
        Ok(written)
    }

    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> VfsResult<usize> {
        if !self.operations.readable() {
            return Err(VfsError::Access);
        }
        self.operations.read_at(offset, output)
    }

    pub fn write_at(&self, offset: u64, input: &[u8]) -> VfsResult<usize> {
        if !self.operations.writable() {
            return Err(VfsError::Access);
        }
        self.operations.write_at(offset, input)
    }

    pub fn sync(&self, data_only: bool) -> VfsResult<()> {
        self.operations.sync(data_only)
    }

    pub fn sync_range(&self, offset: u64, length: u64, flags: u32) -> VfsResult<()> {
        self.operations.sync_range(offset, length, flags)
    }

    pub fn advise(&self, offset: u64, length: u64, advice: u32) -> VfsResult<()> {
        self.operations.advise(offset, length, advice)
    }
}

struct FsPaths {
    root: PinnedPath,
    cwd: PinnedPath,
    root_display: String,
    cwd_display: String,
}

/// Linux-style filesystem context.  Sharing the `Arc<FsStruct>` implements
/// `CLONE_FS`; `clone_private` snapshots cwd/root pins for normal fork.
pub struct FsStruct {
    paths: RwLock<FsPaths>,
    umask: AtomicUsize,
}

impl FsStruct {
    pub fn new(root: VfsPath) -> Arc<Self> {
        Self::new_with_paths(root.clone(), root, "/", "/", 0)
    }

    pub fn new_with_paths(
        root: VfsPath,
        cwd: VfsPath,
        root_display: &str,
        cwd_display: &str,
        umask: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            paths: RwLock::new(FsPaths {
                root: PinnedPath::new(root),
                cwd: PinnedPath::new(cwd),
                root_display: root_display.to_string(),
                cwd_display: cwd_display.to_string(),
            }),
            umask: AtomicUsize::new(umask & 0o777),
        })
    }

    pub fn clone_private(&self) -> Arc<Self> {
        let paths = self.paths.read();
        Arc::new(Self {
            paths: RwLock::new(FsPaths {
                root: paths.root.clone(),
                cwd: paths.cwd.clone(),
                root_display: paths.root_display.clone(),
                cwd_display: paths.cwd_display.clone(),
            }),
            umask: AtomicUsize::new(self.umask()),
        })
    }

    pub fn clone_for_namespace(&self, namespace: &VfsMountNamespaceClone) -> VfsResult<Arc<Self>> {
        let paths = self.paths.read();
        let root = namespace.remap_path(paths.root.path())?;
        let cwd = namespace.remap_path(paths.cwd.path())?;
        Ok(Arc::new(Self {
            paths: RwLock::new(FsPaths {
                root: PinnedPath::new(root),
                cwd: PinnedPath::new(cwd),
                root_display: paths.root_display.clone(),
                cwd_display: paths.cwd_display.clone(),
            }),
            umask: AtomicUsize::new(self.umask()),
        }))
    }

    pub fn root(&self) -> PinnedPath {
        self.paths.read().root.clone()
    }

    pub fn cwd(&self) -> PinnedPath {
        self.paths.read().cwd.clone()
    }

    pub fn root_display(&self) -> String {
        self.paths.read().root_display.clone()
    }

    pub fn cwd_display(&self) -> String {
        self.paths.read().cwd_display.clone()
    }

    /// Render pwd relative to the task root for `getcwd(2)`.
    ///
    /// Root and pwd are sampled under one lock, analogous to Linux's
    /// `get_fs_root_and_pwd_rcu()`.  The stored display strings remain
    /// namespace-global because transitional path backends still need them.
    pub fn cwd_visible(&self) -> String {
        let paths = self.paths.read();
        if paths.root_display == "/" {
            return paths.cwd_display.clone();
        }
        if paths.cwd_display == paths.root_display {
            return String::from("/");
        }
        if let Some(suffix) = paths
            .cwd_display
            .strip_prefix(&paths.root_display)
            .filter(|suffix| suffix.starts_with('/'))
        {
            return String::from(suffix);
        }
        alloc::format!("(unreachable){}", paths.cwd_display)
    }

    pub fn set_root(&self, root: VfsPath) {
        self.paths.write().root = PinnedPath::new(root);
    }

    pub fn set_root_with_display(&self, root: VfsPath, display: &str) {
        let mut paths = self.paths.write();
        paths.root = PinnedPath::new(root);
        paths.root_display = display.to_string();
    }

    pub fn set_root_display(&self, display: &str) {
        self.paths.write().root_display = display.to_string();
    }

    pub fn set_cwd(&self, cwd: VfsPath) {
        self.paths.write().cwd = PinnedPath::new(cwd);
    }

    pub fn set_cwd_with_display(&self, cwd: VfsPath, display: &str) {
        let mut paths = self.paths.write();
        paths.cwd = PinnedPath::new(cwd);
        paths.cwd_display = display.to_string();
    }

    /// Transitional pseudo filesystems do not yet expose a VfsPath.  Keep the
    /// display name shared by CLONE_FS while retaining the last object path;
    /// storage lookup re-enters from root when the logical path leaves that
    /// pseudo mount.
    pub fn set_cwd_display(&self, display: &str) {
        self.paths.write().cwd_display = display.to_string();
    }

    pub fn umask(&self) -> usize {
        self.umask.load(Ordering::Acquire) & 0o777
    }

    pub fn swap_umask(&self, umask: usize) -> usize {
        self.umask.swap(umask & 0o777, Ordering::AcqRel) & 0o777
    }
}
