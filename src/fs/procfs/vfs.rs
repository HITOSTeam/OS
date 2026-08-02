//! Object-VFS adapter for procfs.
//!
//! Linux keeps procfs as a concrete filesystem: each superblock records the
//! PID namespace selected at mount time, while generic VFS code sees ordinary
//! inodes, dentries and file operations.  This module follows that boundary.
//! The existing content providers remain responsible for rendering kernel
//! state, but lookup is performed one component at a time and every dynamic
//! directory lookup is revalidated.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::fs::vfs::{
    DentryCachePolicy, VfsDirEntry, VfsError, VfsFileOperations, VfsFileSystem,
    VfsFileSystemFactory, VfsFileSystemState, VfsLink, VfsMetadata, VfsMountContext, VfsNode,
    VfsNodeKind, VfsOpenOptions, VfsResult, VfsStatFs, VfsTimes,
};
use crate::fs::{File, ProcPseudoFile, PseudoDir, PseudoFile};
use crate::task::processor::{current_process, current_task};

use super::{
    entries::encode_proc_linux_tid, magic_link::proc_magic_vfs_link, open_proc_pseudo_in,
    proc_magic_link_exists, proc_provider_path_for_namespace, proc_readlink,
};

const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const PROC_BLOCK_SIZE: u64 = 1024;
static NEXT_PROCFS_ID: AtomicUsize = AtomicUsize::new(0x20_000);

/// One procfs superblock, permanently bound to the PID namespace selected by
/// the mount context.  Separate mounts may share a namespace but still own
/// independent root dentries and dcache state.
pub(crate) struct ProcFs {
    id: u64,
    pid_namespace_id: usize,
    vfs_state: VfsFileSystemState,
}

impl ProcFs {
    pub(crate) fn new(pid_namespace_id: usize) -> Arc<Self> {
        let id = NEXT_PROCFS_ID.fetch_add(1, Ordering::Relaxed) as u64;
        Arc::new_cyclic(|weak_fs| {
            let root = Arc::new(ProcNode::new(weak_fs.clone(), "/proc"));
            Self {
                id,
                pid_namespace_id,
                vfs_state: VfsFileSystemState::new(root as Arc<dyn VfsNode>),
            }
        })
    }

    pub(crate) fn pid_namespace_id(&self) -> usize {
        self.pid_namespace_id
    }

    fn node(self: &Arc<Self>, path: &str) -> VfsResult<Arc<ProcNode>> {
        let node = Arc::new(ProcNode::new(Arc::downgrade(self), path));
        node.object()?;
        Ok(node)
    }
}

impl VfsFileSystem for ProcFs {
    fn filesystem_id(&self) -> u64 {
        self.id
    }

    fn filesystem_type(&self) -> &'static str {
        "proc"
    }

    fn vfs_state(&self) -> &VfsFileSystemState {
        &self.vfs_state
    }

    fn statfs(&self) -> VfsResult<VfsStatFs> {
        Ok(VfsStatFs {
            magic: PROC_SUPER_MAGIC,
            block_size: PROC_BLOCK_SIZE,
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

/// Registry factory used by both legacy mount and fsopen once procfs becomes
/// an object mount.  Requiring an explicit namespace avoids accidentally
/// exposing the initial namespace from a mount created in a child PID ns.
pub(crate) struct ProcFsFactory;

impl VfsFileSystemFactory for ProcFsFactory {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        let namespace_id = context
            .pid_namespace_id
            .ok_or(VfsError::Invalid)
            .and_then(|id| usize::try_from(id).map_err(|_| VfsError::Invalid))?;
        Ok(ProcFs::new(namespace_id))
    }
}

enum ProcObject {
    Directory(Arc<dyn File + Send + Sync>),
    Regular(Arc<dyn File + Send + Sync>),
    Symlink,
}

/// A proc inode identity.  It stores a proc-relative provider key, never the
/// userspace mountpoint.  Consequently the same backend works at `/proc`, an
/// arbitrary mountpoint, or below a bind mount without path translation.
pub(crate) struct ProcNode {
    fs: Weak<ProcFs>,
    provider_path: String,
    node_id: u64,
    created_ns: u64,
}

impl ProcNode {
    fn new(fs: Weak<ProcFs>, provider_path: &str) -> Self {
        Self {
            fs,
            provider_path: provider_path.to_string(),
            node_id: proc_node_id(provider_path),
            created_ns: crate::time::get_realtime_ns(),
        }
    }

    fn fs(&self) -> VfsResult<Arc<ProcFs>> {
        self.fs.upgrade().ok_or(VfsError::Invalid)
    }

    fn global_provider_path(&self, fs: &ProcFs) -> Option<String> {
        proc_provider_path_for_namespace(&self.provider_path, fs.pid_namespace_id)
    }

    /// Re-evaluate the current object on every dynamic lookup/metadata access.
    /// This is the REF-walk equivalent of Linux proc PID dentry revalidation.
    fn object(&self) -> VfsResult<ProcObject> {
        let fs = self.fs()?;
        if matches!(
            self.provider_path.as_str(),
            "/proc/self" | "/proc/thread-self"
        ) {
            return self
                .alias_link(&fs)
                .map(|_| ProcObject::Symlink)
                .ok_or(VfsError::NoEntry);
        }
        let global_path = self.global_provider_path(&fs).ok_or(VfsError::NoEntry)?;
        if proc_magic_link_exists(&global_path) {
            return Ok(ProcObject::Symlink);
        }
        let file = open_proc_pseudo_in(&self.provider_path, fs.pid_namespace_id)
            .ok_or(VfsError::NoEntry)?;
        if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            return Ok(ProcObject::Directory(file));
        }
        // Linux installs the generic proc_reg_file_ops for every proc entry
        // that is neither a directory nor a symlink.  Content providers are
        // deliberately free to use specialized File implementations; their
        // concrete Rust type must not decide whether the VFS inode is a
        // regular proc file.
        Ok(ProcObject::Regular(file))
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

    fn metadata_for(&self, object: &ProcObject) -> VfsMetadata {
        let (kind, mode, nlink, size) = match object {
            ProcObject::Directory(_) => (VfsNodeKind::Directory, 0o555, 2, 0),
            ProcObject::Regular(file) => {
                let writable = file.writable();
                let size = if let Some(proc_file) = file.as_any().downcast_ref::<ProcPseudoFile>() {
                    proc_file.len().unwrap_or(0) as u64
                } else if let Some(pseudo) = file.as_any().downcast_ref::<PseudoFile>() {
                    pseudo.len().unwrap_or(0) as u64
                } else {
                    0
                };
                (
                    VfsNodeKind::Regular,
                    if writable { 0o644 } else { 0o444 },
                    1,
                    size,
                )
            }
            ProcObject::Symlink => {
                let size = self
                    .fs()
                    .ok()
                    .and_then(|fs| {
                        if let Some(VfsLink::Text(target)) = self.alias_link(&fs) {
                            Some(target)
                        } else {
                            self.global_provider_path(&fs)
                                .and_then(|path| proc_readlink(&path))
                        }
                    })
                    .map_or(0, |target| target.len() as u64);
                (VfsNodeKind::Symlink, 0o777, 1, size)
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

    fn alias_link(&self, fs: &ProcFs) -> Option<VfsLink> {
        if self.provider_path == "/proc/self" {
            let process = current_process();
            let visible_pid =
                crate::task::process_pid_in_pid_namespace(&process, fs.pid_namespace_id)?;
            return Some(VfsLink::Text(alloc::format!("{visible_pid}")));
        }
        if self.provider_path == "/proc/thread-self" {
            let process = current_process();
            let visible_pid =
                crate::task::process_pid_in_pid_namespace(&process, fs.pid_namespace_id)? as u32;
            let task = current_task()?;
            let tid_index = task.borrow_mut().res.as_ref()?.tid;
            let visible_tid = encode_proc_linux_tid(visible_pid, tid_index);
            return Some(VfsLink::Text(alloc::format!(
                "{visible_pid}/task/{visible_tid}"
            )));
        }
        None
    }
}

impl VfsNode for ProcNode {
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
        // Do not keep stale positive PID/fd/task dentries.  The minimal VFS
        // deliberately has no negative cache, matching proc_lookup_de().
        DentryCachePolicy::Revalidate
    }

    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn VfsNode>> {
        if !matches!(self.object()?, ProcObject::Directory(_)) {
            return Err(VfsError::NotDirectory);
        }
        let path = self.child_path(name)?;
        let fs = self.fs()?;
        Ok(fs.node(&path)? as Arc<dyn VfsNode>)
    }

    fn readdir(&self) -> VfsResult<Vec<VfsDirEntry>> {
        let ProcObject::Directory(file) = self.object()? else {
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
                node_id: proc_node_id(&path),
                kind: proc_dtype_to_kind(entry.dtype),
            });
        }
        Ok(output)
    }

    fn readlink(&self) -> VfsResult<VfsLink> {
        if !matches!(self.object()?, ProcObject::Symlink) {
            return Err(VfsError::Invalid);
        }
        let fs = self.fs()?;
        if let Some(link) = self.alias_link(&fs) {
            return Ok(link);
        }
        let path = self.global_provider_path(&fs).ok_or(VfsError::NoEntry)?;
        // `self` and `thread-self` are ordinary relative links. cwd, exe and
        // pathname-backed fd links use an already resolved object path.
        // The proc symlink inode may outlive its dynamic target.  Linux keeps
        // `/proc/<zombie>/cwd` nameable but `proc_pid_get_link()` returns
        // ENOENT after exit_fs() clears the task's fs_struct.  `None` here is
        // therefore a vanished target, not an unsupported readlink operation.
        proc_magic_vfs_link(&path).ok_or(VfsError::NoEntry)
    }

    fn open(self: Arc<Self>, options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        let object = self.object()?;
        let backing = match object {
            ProcObject::Directory(file) | ProcObject::Regular(file) => file,
            ProcObject::Symlink => return Err(VfsError::Loop),
        };
        if (options.readable && !backing.readable()) || (options.writable && !backing.writable()) {
            return Err(VfsError::Access);
        }
        Ok(Arc::new(ProcFileOperations {
            backing,
            readable: options.readable,
            writable: options.writable,
        }))
    }
}

struct ProcFileOperations {
    backing: Arc<dyn File + Send + Sync>,
    readable: bool,
    writable: bool,
}

impl VfsFileOperations for ProcFileOperations {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> VfsResult<usize> {
        if !self.readable {
            return Err(VfsError::Access);
        }
        let offset = usize::try_from(offset).map_err(|_| VfsError::Invalid)?;
        if let Some(file) = self.backing.as_any().downcast_ref::<ProcPseudoFile>() {
            return Ok(file.pread_bytes(offset, output));
        }
        if let Some(file) = self.backing.as_any().downcast_ref::<PseudoFile>() {
            return file
                .read_at_bytes(offset, output)
                .ok_or(VfsError::NotSupported);
        }
        Err(VfsError::NotSupported)
    }

    fn write_at(&self, offset: u64, input: &[u8]) -> VfsResult<usize> {
        if !self.writable {
            return Err(VfsError::Access);
        }
        let offset = usize::try_from(offset).map_err(|_| VfsError::Invalid)?;
        if let Some(file) = self.backing.as_any().downcast_ref::<ProcPseudoFile>() {
            return file.pwrite_bytes(offset, input).map_err(proc_write_error);
        }
        if let Some(file) = self.backing.as_any().downcast_ref::<PseudoFile>() {
            return file
                .write_at_bytes(offset, input)
                .ok_or(VfsError::NotSupported);
        }
        Err(VfsError::NotSupported)
    }

    fn size(&self) -> VfsResult<u64> {
        if let Some(file) = self.backing.as_any().downcast_ref::<ProcPseudoFile>() {
            return Ok(file.len().unwrap_or(0) as u64);
        }
        if let Some(file) = self.backing.as_any().downcast_ref::<PseudoFile>() {
            return Ok(file.len().unwrap_or(0) as u64);
        }
        Ok(0)
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }
}

fn proc_write_error(error: isize) -> VfsError {
    match error {
        -1 | -13 => VfsError::Access,
        -2 => VfsError::NoEntry,
        -19 => VfsError::NoDevice,
        -28 => VfsError::NoSpace,
        -30 => VfsError::ReadOnly,
        _ => VfsError::Invalid,
    }
}

fn proc_dtype_to_kind(dtype: u8) -> VfsNodeKind {
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

/// Stable per-superblock inode key for a proc provider path.  FNV-1a keeps
/// this deterministic without a global pathname table; dentry identity still
/// remains distinct, as required for aliases and bind mounts.
fn proc_node_id(path: &str) -> u64 {
    if path == "/proc" {
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
    fn node_ids_are_path_stable_and_root_is_one() {
        assert_eq!(proc_node_id("/proc"), 1);
        assert_eq!(proc_node_id("/proc/self"), proc_node_id("/proc/self"));
        assert_ne!(proc_node_id("/proc/self"), proc_node_id("/proc/stat"));
    }

    #[test]
    fn dtype_mapping_matches_linux_dirent_values() {
        assert_eq!(proc_dtype_to_kind(4), VfsNodeKind::Directory);
        assert_eq!(proc_dtype_to_kind(8), VfsNodeKind::Regular);
        assert_eq!(proc_dtype_to_kind(10), VfsNodeKind::Symlink);
    }
}
