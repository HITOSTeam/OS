use super::{
    Any, Arc, File, MOUNT_ATTR_NOATIME, MOUNT_ATTR_NODEV, MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_NOEXEC,
    MOUNT_ATTR_NOSUID, MOUNT_ATTR_NOSYMFOLLOW, MOUNT_ATTR_RDONLY, MOUNT_ATTR_STRICTATIME,
    MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_NOSYMFOLLOW, MS_RDONLY,
    MS_STRICTATIME, Mutex, String, SyscallError, UserBuffer, current_files_and_nofile_limit, err,
    find_path_in_roots, get_current_token, mount_lookup_for_abs, read_user_cstring,
    register_rofs_mount, resolve_abs_path, unregister_rofs_mount, with_ext4_inode_read,
};
use crate::fs::vfs::{PinnedPath, VfsFileSystem, VfsMountNamespace, VfsPath};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FsContextMode {
    Create,
    Reconfigure,
}

pub(crate) struct FsContextState {
    pub(crate) mode: FsContextMode,
    pub(crate) fs_type: String,
    /// PID namespace captured when fsopen/fspick created this context.
    /// procfs consumes it when the superblock is instantiated.
    pub(crate) pid_namespace_id: u64,
    /// Cgroup namespace view captured with this fs_context, as Linux does in
    /// `cgroup_init_fs_context()`.
    pub(crate) cgroup_namespace_root: String,
    pub(crate) source_display: String,
    pub(crate) source_abs: Option<String>,
    pub(crate) target_abs: Option<String>,
    /// Filesystem-specific options accumulated by `fsconfig(2)`.
    ///
    /// The filesystem factory consumes this in the same form as legacy
    /// `mount(2)`'s monolithic data string, keeping a single parser and one
    /// set of validation rules for both mount APIs.
    pub(crate) mount_data: String,
    pub(crate) pending_flags: usize,
    pub(crate) created: bool,
    pub(crate) created_filesystem: Option<Arc<dyn VfsFileSystem>>,
}

pub(crate) struct FsContextFile {
    pub(crate) state: Mutex<FsContextState>,
}

impl FsContextFile {
    /// Creates a filesystem-context file for `fsopen(2)` create mode.
    pub(crate) fn new_create(fs_type: &str) -> Self {
        Self {
            state: Mutex::new(FsContextState {
                mode: FsContextMode::Create,
                fs_type: String::from(fs_type),
                pid_namespace_id: crate::task::processor::current_process().pid_namespace_id()
                    as u64,
                cgroup_namespace_root: crate::task::processor::current_process()
                    .cgroup_namespace_root(),
                source_display: String::from("/dev/root"),
                source_abs: None,
                target_abs: None,
                mount_data: String::new(),
                pending_flags: 0,
                created: false,
                created_filesystem: None,
            }),
        }
    }

    /// Creates a filesystem-context file bound to an existing mount for reconfiguration.
    pub(crate) fn new_reconfigure(
        fs_type: &str,
        source_display: &str,
        source_abs: &str,
        target_abs: &str,
        flags: usize,
    ) -> Self {
        Self {
            state: Mutex::new(FsContextState {
                mode: FsContextMode::Reconfigure,
                fs_type: String::from(fs_type),
                pid_namespace_id: crate::task::processor::current_process().pid_namespace_id()
                    as u64,
                cgroup_namespace_root: crate::task::processor::current_process()
                    .cgroup_namespace_root(),
                source_display: String::from(source_display),
                source_abs: Some(String::from(source_abs)),
                target_abs: Some(String::from(target_abs)),
                mount_data: String::new(),
                pending_flags: flags,
                created: false,
                created_filesystem: None,
            }),
        }
    }
}

impl File for FsContextFile {
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        false
    }
    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) enum MountHandleObject {
    Filesystem(Arc<dyn VfsFileSystem>),
    Bind {
        source: VfsPath,
        /// Keep the anonymous clone's origin graph alive without pinning the
        /// original mounted path as a busy user-visible mount.
        _source_namespace: Arc<VfsMountNamespace>,
        logical_source: String,
    },
    /// A live `open_tree()` path.  Unlike `OPEN_TREE_CLONE`, Linux returns an
    /// ordinary O_PATH file whose `f_path` still belongs to the namespace;
    /// `move_mount()` therefore moves that existing mount instead of grafting
    /// a detached copy.
    Path {
        source: VfsPath,
        _source_namespace: Arc<VfsMountNamespace>,
        logical_source: String,
    },
}

pub(crate) struct MountHandleState {
    pub(crate) source: String,
    pub(crate) source_display: String,
    pub(crate) fs_type: String,
    pub(crate) flags: usize,
    pub(crate) object: MountHandleObject,
    pub(crate) attached: bool,
}

pub(crate) struct MountHandleFile {
    pub(crate) state: Mutex<MountHandleState>,
    /// `open_tree()` without `OPEN_TREE_CLONE` is an O_PATH file for a live
    /// namespace path.  Keep that path outside the mutable handle state so
    /// the generic `File::object_path()` ABI can return a stable reference.
    path: Option<PinnedPath>,
}

impl MountHandleFile {
    pub(crate) fn new_filesystem(
        source: &str,
        source_display: &str,
        fs_type: &str,
        flags: usize,
        filesystem: Arc<dyn VfsFileSystem>,
    ) -> Self {
        Self {
            state: Mutex::new(MountHandleState {
                source: String::from(source),
                source_display: String::from(source_display),
                fs_type: String::from(fs_type),
                flags,
                object: MountHandleObject::Filesystem(filesystem),
                attached: false,
            }),
            path: None,
        }
    }

    pub(crate) fn new_bind(
        source: &str,
        source_display: &str,
        fs_type: &str,
        flags: usize,
        path: VfsPath,
        source_namespace: Arc<VfsMountNamespace>,
        logical_source: &str,
    ) -> Self {
        Self {
            state: Mutex::new(MountHandleState {
                source: String::from(source),
                source_display: String::from(source_display),
                fs_type: String::from(fs_type),
                flags,
                object: MountHandleObject::Bind {
                    source: path,
                    _source_namespace: source_namespace,
                    logical_source: String::from(logical_source),
                },
                attached: false,
            }),
            path: None,
        }
    }

    pub(crate) fn new_path(
        source: &str,
        source_display: &str,
        fs_type: &str,
        flags: usize,
        path: VfsPath,
        source_namespace: Arc<VfsMountNamespace>,
        logical_source: &str,
    ) -> Self {
        let pinned_path = PinnedPath::new(path.clone());
        Self {
            state: Mutex::new(MountHandleState {
                source: String::from(source),
                source_display: String::from(source_display),
                fs_type: String::from(fs_type),
                flags,
                object: MountHandleObject::Path {
                    source: path,
                    _source_namespace: source_namespace,
                    logical_source: String::from(logical_source),
                },
                attached: false,
            }),
            path: Some(pinned_path),
        }
    }
}

impl File for MountHandleFile {
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        false
    }
    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn object_path(&self) -> Option<&VfsPath> {
        self.path.as_ref().map(PinnedPath::path)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct KMountAttr {
    pub(crate) attr_set: u64,
    pub(crate) attr_clr: u64,
    pub(crate) propagation: u64,
    pub(crate) userns_fd: u64,
}

/// Allocates an internal fd slot for mount-api helper files.
pub(crate) fn alloc_internal_fd(
    file: Arc<dyn File + Send + Sync>,
    descriptor_flags: u32,
) -> Result<isize, isize> {
    let (files, limit) = current_files_and_nofile_limit();
    let installed = files.lock().install_fd(file, descriptor_flags, limit);
    let fd = match installed {
        Ok(fd) => fd,
        Err(rejected) => {
            rejected.discard();
            return Err(err(SyscallError::EMFILE));
        }
    };
    Ok(fd as isize)
}

/// Converts modern `mount_setattr(2)` bits into the legacy `MS_*` flag set.
pub(crate) fn mount_attr_bits_to_legacy_flags(attrs: usize) -> usize {
    let mut flags = 0usize;
    if (attrs & MOUNT_ATTR_RDONLY) != 0 {
        flags |= MS_RDONLY;
    }
    if (attrs & MOUNT_ATTR_NOSUID) != 0 {
        flags |= MS_NOSUID;
    }
    if (attrs & MOUNT_ATTR_NODEV) != 0 {
        flags |= MS_NODEV;
    }
    if (attrs & MOUNT_ATTR_NOEXEC) != 0 {
        flags |= MS_NOEXEC;
    }
    if (attrs & MOUNT_ATTR_NOATIME) != 0 {
        flags |= MS_NOATIME;
    }
    if (attrs & MOUNT_ATTR_STRICTATIME) != 0 {
        flags |= MS_STRICTATIME;
    }
    if (attrs & MOUNT_ATTR_NODIRATIME) != 0 {
        flags |= MS_NODIRATIME;
    }
    if (attrs & MOUNT_ATTR_NOSYMFOLLOW) != 0 {
        flags |= MS_NOSYMFOLLOW;
    }
    flags
}

/// Mirrors the effective read-only mount flag into the path-based rofs registry.
pub(crate) fn sync_rofs_state(target: &str, flags: usize) {
    if (flags & MS_RDONLY) != 0 {
        register_rofs_mount(target);
    } else {
        unregister_rofs_mount(target);
    }
}

/// Reads a userspace path and resolves it to an absolute path string.
pub(crate) fn read_user_path_abs(dirfd: isize, ptr: usize) -> Result<String, isize> {
    let token = get_current_token();
    let path = read_user_cstring(token, ptr)?;
    if path.is_empty() {
        return Err(err(SyscallError::ENOENT));
    }
    resolve_abs_path(dirfd, &path)?.ok_or_else(|| err(SyscallError::EBADF))
}

/// Ensures that a mount target exists and names a directory.
pub(crate) fn ensure_mount_target_dir(abs: &str) -> Result<(), isize> {
    let Some(inode) = find_path_in_roots(abs) else {
        return Err(err(SyscallError::ENOENT));
    };
    if !with_ext4_inode_read(&inode, || inode.is_dir()) {
        return Err(err(SyscallError::ENOTDIR));
    }
    Ok(())
}

/// Returns the filesystem type currently associated with an absolute mount path.
pub(crate) fn mount_fs_type_for_abs(abs: &str) -> String {
    mount_lookup_for_abs(abs)
        .map(|m| m.fs_type)
        .unwrap_or_else(|| String::from("ext4"))
}

/// Returns the source string that should be shown for an existing mount.
pub(crate) fn mount_source_display_for_abs(abs: &str) -> String {
    mount_lookup_for_abs(abs)
        .map(|m| m.source_display)
        .unwrap_or_else(|| String::from("/dev/root"))
}
