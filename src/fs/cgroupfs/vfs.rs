//! Object-VFS projection for cgroupfs.
//!
//! Linux builds cgroup files on kernfs: a hierarchy owns stable nodes and a
//! superblock, while each mount selects the dentry corresponding to the
//! mount-time cgroup namespace root.  This module follows that split.  The
//! existing controller/accounting state remains keyed by cgroup-relative
//! paths, but VFS nodes and open files retain inode identities and resolve the
//! current path under the registry lock.  A rename therefore does not retarget
//! an already-open directory or control file.

extern crate alloc;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

use crate::fs::vfs::{
    DentryCachePolicy, VfsDirEntry, VfsError, VfsFileOperations, VfsFileSystem,
    VfsFileSystemFactory, VfsFileSystemState, VfsMetadata, VfsMountContext, VfsNode, VfsNodeKind,
    VfsOpenOptions, VfsPath, VfsRenameFlags, VfsResult, VfsStatFs, VfsTimes,
};
use crate::task::processor::current_process;

use super::{
    CGROUP_REGISTRY, CgroupAttachTarget, CgroupFile, CgroupFileKind, CgroupHierarchyKey,
    CgroupMountKind, CgroupMountSpec, CgroupNode, EINVAL, ENODEV, ENOENT, cgroup_file_names,
    refresh_all_legacy_cpu_fair_group_caches, rename_cgroup_namespace_roots, rename_subtree_path,
};

const CGROUP_SUPER_MAGIC: u64 = 0x27e0eb;
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const CGROUP_BLOCK_SIZE: u64 = 4096;

pub(crate) struct CgroupFs {
    filesystem_id: u64,
    kind: CgroupMountKind,
    hierarchy_key: CgroupHierarchyKey,
    namespace_root_ino: u64,
    vfs_state: VfsFileSystemState,
}

impl CgroupFs {
    fn new(spec: CgroupMountSpec, namespace_root: &str) -> Arc<Self> {
        let (filesystem_id, namespace_root_ino) = CGROUP_REGISTRY
            .lock()
            .acquire_object_mount(&spec, namespace_root);
        let kind = spec.kind();
        let hierarchy_key = spec.hierarchy_key().clone();
        if kind == CgroupMountKind::LegacyCpu {
            refresh_all_legacy_cpu_fair_group_caches();
        }
        Arc::new_cyclic(|weak_fs: &Weak<Self>| {
            let root = Arc::new(CgroupVfsNode {
                fs: weak_fs.clone(),
                object: CgroupObject::Directory {
                    ino: namespace_root_ino,
                },
            });
            Self {
                filesystem_id,
                kind,
                hierarchy_key,
                namespace_root_ino,
                vfs_state: VfsFileSystemState::new(root as Arc<dyn VfsNode>),
            }
        })
    }

    fn node(self: &Arc<Self>, object: CgroupObject) -> Arc<dyn VfsNode> {
        Arc::new(CgroupVfsNode {
            fs: Arc::downgrade(self),
            object,
        })
    }
}

/// Convert an opened cgroup directory object into a stable clone3 attach
/// target.  Bind mounts and arbitrary mountpoints preserve the same VFS node,
/// so no mount-target string participates in this lookup.
pub(crate) fn attach_target_from_path(path: &VfsPath) -> Result<CgroupAttachTarget, isize> {
    let node = path
        .node()
        .as_any()
        .downcast_ref::<CgroupVfsNode>()
        .ok_or(EINVAL)?;
    let fs = node.fs().map_err(|_| ENODEV)?;
    if fs.kind != CgroupMountKind::Unified {
        return Err(EINVAL);
    }
    let directory_ino = node.directory_ino().map_err(|_| EINVAL)?;
    let registry = CGROUP_REGISTRY.lock();
    let state = registry.hierarchies.get(&fs.hierarchy_key).ok_or(ENOENT)?;
    let rel_path = state.node_path_by_ino(directory_ino).ok_or(ENOENT)?;
    let namespace_root = state
        .node_path_by_ino(fs.namespace_root_ino)
        .ok_or(ENOENT)?;
    if !super::CgroupMountState::is_descendant_or_self(&rel_path, &namespace_root) {
        return Err(ENOENT);
    }
    Ok(CgroupAttachTarget {
        hierarchy_key: fs.hierarchy_key.clone(),
        rel_path,
    })
}

impl Drop for CgroupFs {
    fn drop(&mut self) {
        CGROUP_REGISTRY
            .lock()
            .release_object_mount(&self.hierarchy_key, self.namespace_root_ino);
        if self.kind == CgroupMountKind::LegacyCpu {
            refresh_all_legacy_cpu_fair_group_caches();
        }
    }
}

impl VfsFileSystem for CgroupFs {
    fn filesystem_id(&self) -> u64 {
        self.filesystem_id
    }

    fn filesystem_type(&self) -> &'static str {
        if self.kind == CgroupMountKind::Unified {
            "cgroup2"
        } else {
            "cgroup"
        }
    }

    fn vfs_state(&self) -> &VfsFileSystemState {
        &self.vfs_state
    }

    fn statfs(&self) -> VfsResult<VfsStatFs> {
        Ok(VfsStatFs {
            magic: if self.kind == CgroupMountKind::Unified {
                CGROUP2_SUPER_MAGIC
            } else {
                CGROUP_SUPER_MAGIC
            },
            block_size: CGROUP_BLOCK_SIZE,
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

pub(crate) struct Cgroup2FsFactory;

impl VfsFileSystemFactory for Cgroup2FsFactory {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        let namespace_root = context.cgroup_namespace_root.as_deref().unwrap_or("/");
        Ok(CgroupFs::new(CgroupMountSpec::unified(), namespace_root))
    }
}

pub(crate) struct CgroupV1FsFactory;

impl VfsFileSystemFactory for CgroupV1FsFactory {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        let spec = CgroupMountSpec::parse_legacy_options(&context.data).map_err(errno_to_vfs)?;
        let namespace_root = context.cgroup_namespace_root.as_deref().unwrap_or("/");
        Ok(CgroupFs::new(spec, namespace_root))
    }
}

#[derive(Clone, Copy)]
enum CgroupObject {
    Directory {
        ino: u64,
    },
    Control {
        ino: u64,
        directory_ino: u64,
        kind: CgroupFileKind,
    },
}

struct CgroupVfsNode {
    fs: Weak<CgroupFs>,
    object: CgroupObject,
}

impl CgroupVfsNode {
    fn fs(&self) -> VfsResult<Arc<CgroupFs>> {
        self.fs.upgrade().ok_or(VfsError::NoDevice)
    }

    fn directory_ino(&self) -> VfsResult<u64> {
        match self.object {
            CgroupObject::Directory { ino } => Ok(ino),
            CgroupObject::Control { .. } => Err(VfsError::NotDirectory),
        }
    }

    fn validate_name(name: &str) -> VfsResult<()> {
        if name.is_empty() || matches!(name, "." | "..") || name.contains('/') {
            return Err(VfsError::Invalid);
        }
        if name.len() > 255 {
            return Err(VfsError::NameTooLong);
        }
        Ok(())
    }
}

impl VfsNode for CgroupVfsNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn node_id(&self) -> u64 {
        match self.object {
            CgroupObject::Directory { ino } | CgroupObject::Control { ino, .. } => ino,
        }
    }

    fn filesystem_id(&self) -> u64 {
        self.fs
            .upgrade()
            .map(|fs| fs.filesystem_id)
            .unwrap_or_default()
    }

    fn metadata(&self) -> VfsResult<VfsMetadata> {
        let fs = self.fs()?;
        let registry = CGROUP_REGISTRY.lock();
        let state = registry
            .hierarchies
            .get(&fs.hierarchy_key)
            .ok_or(VfsError::NoDevice)?;
        let (kind, mode, uid, gid, nlink) = match self.object {
            CgroupObject::Directory { ino } => {
                let path = state.node_path_by_ino(ino).ok_or(VfsError::NoEntry)?;
                let node = state.nodes.get(&path).ok_or(VfsError::NoEntry)?;
                (
                    VfsNodeKind::Directory,
                    node.mode,
                    node.uid,
                    node.gid,
                    2u32.saturating_add(state.direct_children(&path).len() as u32),
                )
            }
            CgroupObject::Control {
                directory_ino,
                kind,
                ..
            } => {
                let path = state
                    .node_path_by_ino(directory_ino)
                    .ok_or(VfsError::NoEntry)?;
                let node = state.nodes.get(&path).ok_or(VfsError::NoEntry)?;
                let name = cgroup_file_names(state.kind)
                    .iter()
                    .find(|name| CgroupFileKind::from_name(name, state.kind) == Some(kind))
                    .ok_or(VfsError::NoEntry)?;
                let control = node.control_nodes.get(*name).ok_or(VfsError::NoEntry)?;
                (
                    VfsNodeKind::Regular,
                    control.mode,
                    control.uid,
                    control.gid,
                    1,
                )
            }
        };
        Ok(VfsMetadata {
            kind,
            mode,
            uid,
            gid,
            nlink,
            size: 0,
            rdev: 0,
            times: VfsTimes::default(),
        })
    }

    fn dentry_cache_policy(&self) -> DentryCachePolicy {
        // cgroup directories and task-derived files are dynamic kernfs nodes.
        DentryCachePolicy::Revalidate
    }

    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn VfsNode>> {
        Self::validate_name(name)?;
        let fs = self.fs()?;
        let parent_ino = self.directory_ino()?;
        let object = {
            let mut registry = CGROUP_REGISTRY.lock();
            let state = registry
                .hierarchies
                .get_mut(&fs.hierarchy_key)
                .ok_or(VfsError::NoDevice)?;
            let parent = state
                .node_path_by_ino(parent_ino)
                .ok_or(VfsError::NoEntry)?;
            let child = join_rel_path(&parent, name);
            if let Some(node) = state.nodes.get(&child) {
                CgroupObject::Directory { ino: node.ino }
            } else if let Some((kind, control)) = state.ensure_control_node(&parent, name) {
                CgroupObject::Control {
                    ino: control.ino,
                    directory_ino: parent_ino,
                    kind,
                }
            } else {
                return Err(VfsError::NoEntry);
            }
        };
        Ok(fs.node(object))
    }

    fn readdir(&self) -> VfsResult<Vec<VfsDirEntry>> {
        let fs = self.fs()?;
        let parent_ino = self.directory_ino()?;
        let mut registry = CGROUP_REGISTRY.lock();
        let state = registry
            .hierarchies
            .get_mut(&fs.hierarchy_key)
            .ok_or(VfsError::NoDevice)?;
        let parent = state
            .node_path_by_ino(parent_ino)
            .ok_or(VfsError::NoEntry)?;
        let mut entries = Vec::new();
        for name in state.direct_children(&parent) {
            let path = join_rel_path(&parent, &name);
            let node = state.nodes.get(&path).ok_or(VfsError::NoEntry)?;
            entries.push(VfsDirEntry {
                name,
                node_id: node.ino,
                kind: VfsNodeKind::Directory,
            });
        }
        for name in cgroup_file_names(state.kind) {
            let (_, control) = state
                .ensure_control_node(&parent, name)
                .ok_or(VfsError::NoEntry)?;
            entries.push(VfsDirEntry {
                name: String::from(*name),
                node_id: control.ino,
                kind: VfsNodeKind::Regular,
            });
        }
        Ok(entries)
    }

    fn open(self: Arc<Self>, options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        let fs = self.fs()?;
        match self.object {
            CgroupObject::Directory { .. } => {
                if options.writable {
                    return Err(VfsError::IsDirectory);
                }
                Ok(Arc::new(CgroupDirectoryOperations {
                    readable: options.readable,
                }))
            }
            CgroupObject::Control {
                directory_ino,
                kind,
                ..
            } => {
                if options.writable && !kind.writable() {
                    return Err(VfsError::Access);
                }
                let open_euid = current_process().borrow_mut().euid;
                Ok(Arc::new(CgroupFileOperations {
                    backing: CgroupFile::new_object(
                        fs.hierarchy_key.clone(),
                        directory_ino,
                        kind,
                        open_euid,
                        fs.namespace_root_ino,
                    ),
                    readable: options.readable,
                    writable: options.writable,
                }))
            }
        }
    }

    fn mkdir(&self, name: &str, mode: u16) -> VfsResult<Arc<dyn VfsNode>> {
        Self::validate_name(name)?;
        if name.contains('\n') {
            return Err(VfsError::Invalid);
        }
        let fs = self.fs()?;
        let parent_ino = self.directory_ino()?;
        let ino = {
            let mut registry = CGROUP_REGISTRY.lock();
            let state = registry
                .hierarchies
                .get_mut(&fs.hierarchy_key)
                .ok_or(VfsError::NoDevice)?;
            let parent = state
                .node_path_by_ino(parent_ino)
                .ok_or(VfsError::NoEntry)?;
            if CgroupFileKind::from_name(name, state.kind).is_some() {
                return Err(VfsError::Exists);
            }
            let child = join_rel_path(&parent, name);
            if state.nodes.contains_key(&child) {
                return Err(VfsError::Exists);
            }
            let mut node = CgroupNode::new_with_mode(mode);
            if let Some(parent_node) = state.nodes.get(&parent) {
                node.clone_children = parent_node.clone_children;
                node.notify_on_release = parent_node.notify_on_release;
            }
            let ino = node.ino;
            state.nodes.insert(child, node);
            ino
        };
        Ok(fs.node(CgroupObject::Directory { ino }))
    }

    fn unlink(&self, name: &str, remove_dir: bool) -> VfsResult<()> {
        Self::validate_name(name)?;
        let fs = self.fs()?;
        let parent_ino = self.directory_ino()?;
        let mut registry = CGROUP_REGISTRY.lock();
        let (child, child_ino) = {
            let state = registry
                .hierarchies
                .get(&fs.hierarchy_key)
                .ok_or(VfsError::NoDevice)?;
            let parent = state
                .node_path_by_ino(parent_ino)
                .ok_or(VfsError::NoEntry)?;
            let child = join_rel_path(&parent, name);
            match state.nodes.get(&child) {
                Some(node) => (child, node.ino),
                None if CgroupFileKind::from_name(name, state.kind).is_some() => {
                    return Err(if remove_dir {
                        VfsError::NotDirectory
                    } else {
                        VfsError::Permission
                    });
                }
                None => return Err(VfsError::NoEntry),
            }
        };
        if !remove_dir {
            return Err(VfsError::IsDirectory);
        }
        if registry.object_root_is_pinned(&fs.hierarchy_key, child_ino) {
            return Err(VfsError::Busy);
        }
        let state = registry
            .hierarchies
            .get_mut(&fs.hierarchy_key)
            .ok_or(VfsError::NoDevice)?;
        if !state.direct_children(&child).is_empty() {
            return Err(VfsError::NotEmpty);
        }
        if state
            .process_assignments
            .values()
            .any(|path| path == &child)
            || state.thread_assignments.values().any(|path| path == &child)
        {
            return Err(VfsError::Busy);
        }
        state.nodes.remove(&child).ok_or(VfsError::NoEntry)?;
        Ok(())
    }

    fn truncate(&self, size: u64) -> VfsResult<()> {
        match self.object {
            // `open(..., O_TRUNC)` reaches kernfs attributes even though the
            // generated value is not ordinary stored data.  Accept the zero
            // size request used by shell redirection without mutating the
            // controller state.
            CgroupObject::Control { .. } if size == 0 => Ok(()),
            CgroupObject::Control { .. } => Err(VfsError::Invalid),
            CgroupObject::Directory { .. } => Err(VfsError::IsDirectory),
        }
    }

    fn rename(
        &self,
        old_name: &str,
        new_parent: &Arc<dyn VfsNode>,
        new_name: &str,
    ) -> VfsResult<()> {
        self.rename_with_flags(old_name, new_parent, new_name, VfsRenameFlags::default())
    }

    fn rename_with_flags(
        &self,
        old_name: &str,
        new_parent: &Arc<dyn VfsNode>,
        new_name: &str,
        flags: VfsRenameFlags,
    ) -> VfsResult<()> {
        Self::validate_name(old_name)?;
        Self::validate_name(new_name)?;
        if new_name.contains('\n') {
            return Err(VfsError::Invalid);
        }
        // kernfs_iop_rename rejects all renameat2 flags before invoking the
        // cgroup callback.
        if flags.0 != 0 {
            return Err(VfsError::Invalid);
        }
        let fs = self.fs()?;
        if fs.kind == CgroupMountKind::Unified {
            // cgroup v2 does not install a kernfs rename callback.
            return Err(VfsError::Permission);
        }
        let new_parent = new_parent
            .as_any()
            .downcast_ref::<CgroupVfsNode>()
            .ok_or(VfsError::CrossDevice)?;
        let new_fs = new_parent.fs()?;
        if !Arc::ptr_eq(&fs, &new_fs) {
            return Err(VfsError::CrossDevice);
        }
        let old_parent_ino = self.directory_ino()?;
        let new_parent_ino = new_parent.directory_ino()?;
        let (old_rel, new_rel) = {
            let mut registry = CGROUP_REGISTRY.lock();
            let state = registry
                .hierarchies
                .get_mut(&fs.hierarchy_key)
                .ok_or(VfsError::NoDevice)?;
            let old_parent = state
                .node_path_by_ino(old_parent_ino)
                .ok_or(VfsError::NoEntry)?;
            let new_parent_path = state
                .node_path_by_ino(new_parent_ino)
                .ok_or(VfsError::NoEntry)?;
            // Linux cgroup1_rename() permits only a name change in place.
            if old_parent != new_parent_path {
                return Err(VfsError::Io);
            }
            let old_rel = join_rel_path(&old_parent, old_name);
            let new_rel = join_rel_path(&new_parent_path, new_name);
            if old_rel == new_rel {
                return Ok(());
            }
            if !state.nodes.contains_key(&old_rel) {
                return Err(
                    if CgroupFileKind::from_name(old_name, state.kind).is_some() {
                        VfsError::Permission
                    } else {
                        VfsError::NoEntry
                    },
                );
            }
            if state.nodes.contains_key(&new_rel)
                || CgroupFileKind::from_name(new_name, state.kind).is_some()
            {
                return Err(VfsError::Exists);
            }
            let renamed_keys = state
                .nodes
                .keys()
                .filter(|path| super::CgroupMountState::is_descendant_or_self(path, &old_rel))
                .cloned()
                .collect::<Vec<_>>();
            let renamed_nodes = renamed_keys
                .iter()
                .filter_map(|path| state.nodes.remove(path).map(|node| (path.clone(), node)))
                .collect::<Vec<_>>();
            for (old_path, node) in renamed_nodes {
                state
                    .nodes
                    .insert(rename_subtree_path(&old_path, &old_rel, &new_rel), node);
            }
            for path in state.process_assignments.values_mut() {
                if super::CgroupMountState::is_descendant_or_self(path, &old_rel) {
                    *path = rename_subtree_path(path, &old_rel, &new_rel);
                }
            }
            for path in state.thread_assignments.values_mut() {
                if super::CgroupMountState::is_descendant_or_self(path, &old_rel) {
                    *path = rename_subtree_path(path, &old_rel, &new_rel);
                }
            }
            (old_rel, new_rel)
        };
        rename_cgroup_namespace_roots(&old_rel, &new_rel);
        Ok(())
    }

    fn set_mode(&self, mode: u16) -> VfsResult<()> {
        let fs = self.fs()?;
        let mut registry = CGROUP_REGISTRY.lock();
        let state = registry
            .hierarchies
            .get_mut(&fs.hierarchy_key)
            .ok_or(VfsError::NoDevice)?;
        match self.object {
            CgroupObject::Directory { ino } => {
                let path = state.node_path_by_ino(ino).ok_or(VfsError::NoEntry)?;
                state.nodes.get_mut(&path).ok_or(VfsError::NoEntry)?.mode = mode & 0o7777;
            }
            CgroupObject::Control {
                directory_ino,
                kind,
                ..
            } => {
                let path = state
                    .node_path_by_ino(directory_ino)
                    .ok_or(VfsError::NoEntry)?;
                let name = control_name(state.kind, kind).ok_or(VfsError::NoEntry)?;
                let (_, control) = state
                    .ensure_control_node(&path, name)
                    .ok_or(VfsError::NoEntry)?;
                state
                    .nodes
                    .get_mut(&path)
                    .and_then(|node| node.control_nodes.get_mut(name))
                    .ok_or(VfsError::NoEntry)?
                    .mode = mode & 0o7777;
                let _ = control;
            }
        }
        Ok(())
    }

    fn set_owner(&self, uid: u32, gid: u32) -> VfsResult<()> {
        let fs = self.fs()?;
        let mut registry = CGROUP_REGISTRY.lock();
        let state = registry
            .hierarchies
            .get_mut(&fs.hierarchy_key)
            .ok_or(VfsError::NoDevice)?;
        match self.object {
            CgroupObject::Directory { ino } => {
                let path = state.node_path_by_ino(ino).ok_or(VfsError::NoEntry)?;
                let node = state.nodes.get_mut(&path).ok_or(VfsError::NoEntry)?;
                node.uid = uid;
                node.gid = gid;
            }
            CgroupObject::Control {
                directory_ino,
                kind,
                ..
            } => {
                let path = state
                    .node_path_by_ino(directory_ino)
                    .ok_or(VfsError::NoEntry)?;
                let name = control_name(state.kind, kind).ok_or(VfsError::NoEntry)?;
                let _ = state
                    .ensure_control_node(&path, name)
                    .ok_or(VfsError::NoEntry)?;
                let control = state
                    .nodes
                    .get_mut(&path)
                    .and_then(|node| node.control_nodes.get_mut(name))
                    .ok_or(VfsError::NoEntry)?;
                control.uid = uid;
                control.gid = gid;
            }
        }
        Ok(())
    }
}

struct CgroupDirectoryOperations {
    readable: bool,
}

impl VfsFileOperations for CgroupDirectoryOperations {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        false
    }

    fn size(&self) -> VfsResult<u64> {
        Ok(0)
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }
}

struct CgroupFileOperations {
    backing: Arc<CgroupFile>,
    readable: bool,
    writable: bool,
}

impl VfsFileOperations for CgroupFileOperations {
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
        self.backing
            .read_at_bytes(offset, output)
            .map_err(errno_to_vfs)
    }

    fn write_at(&self, _offset: u64, input: &[u8]) -> VfsResult<usize> {
        if !self.writable {
            return Err(VfsError::Access);
        }
        // kernfs forwards ki_pos to cgroup callbacks; the supported cgroup
        // control callbacks parse one complete payload and do not reject a
        // non-zero position themselves.
        self.backing.write_payload(input).map_err(errno_to_vfs)
    }

    fn size(&self) -> VfsResult<u64> {
        Ok(self.backing.len() as u64)
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }
}

fn join_rel_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        alloc::format!("/{name}")
    } else {
        alloc::format!("{parent}/{name}")
    }
}

fn control_name(kind: CgroupMountKind, target: CgroupFileKind) -> Option<&'static str> {
    cgroup_file_names(kind)
        .iter()
        .copied()
        .find(|name| CgroupFileKind::from_name(name, kind) == Some(target))
}

fn errno_to_vfs(errno: isize) -> VfsError {
    match errno {
        -1 => VfsError::Permission,
        -2 => VfsError::NoEntry,
        -3 => VfsError::NoProcess,
        -5 => VfsError::Io,
        -13 => VfsError::Access,
        -16 => VfsError::Busy,
        -17 => VfsError::Exists,
        -19 => VfsError::NoDevice,
        -20 => VfsError::NotDirectory,
        -21 => VfsError::IsDirectory,
        -22 => VfsError::Invalid,
        -28 => VfsError::NoSpace,
        -30 => VfsError::ReadOnly,
        -39 => VfsError::NotEmpty,
        -95 => VfsError::NotSupported,
        _ => VfsError::Invalid,
    }
}
