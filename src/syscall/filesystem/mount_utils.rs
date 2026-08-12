use super::{
    AT_FDCWD, Arc, BTreeMap, BTreeSet, CgroupMountSpec, File, InodeTimes, MNT_DETACH, MNT_EXPIRE,
    MNT_FORCE, MS_BIND, MS_MOVE, MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID,
    MS_NOSYMFOLLOW, MS_PRIVATE, MS_RDONLY, MS_REC, MS_REMOUNT, MS_SHARED, MS_SLAVE, MS_STRICTATIME,
    MS_UNBINDABLE, MountBackend, MountHandleObject, MountHandleState, MountNamespace,
    MountNamespaceState, MountPropagation, MountRecord, NEXT_MOUNT_EVENT_ID,
    NEXT_MOUNT_PEER_GROUP_ID, NEXT_MOUNT_STACK_SEQ, OSInode, Ordering, PID2PCB,
    ProcessControlBlock, PseudoDir, PseudoFile, RtcFile, ST_NOSYMFOLLOW, String, SyscallError,
    UMOUNT_NOFOLLOW, Vec, VfsOpenedFile, block_device_source_path, current_fsuid_gid,
    current_process, current_timespec, err, find_path_in_roots, get_current_token, get_inode_times,
    inode_logical_path, inode_raw_logical_path, map_vfs_error, mount_namespace_id, normalize_path,
    pseudo_block_is_read_only, read_user_cstring, resolve_at_inode, resolve_at_path,
    resolve_at_vfs_path, set_inode_times, with_ext4_inode_read,
};
use crate::fs::ext4::Ext4Vfs;
use crate::fs::tmpfs::TmpFs;
use crate::fs::vfs::{
    LookupFlags, PathWalker, VfsCredentials, VfsError, VfsFileSystem, VfsFileSystemFactory,
    VfsFileSystemRegistry, VfsMountContext, VfsMountFlags, VfsMountPropagation, VfsNodeKind,
    VfsPath, VfsResult,
};
use crate::fs::{
    Cgroup2FsFactory, CgroupV1FsFactory, DevTmpFsFactory, ProcFsFactory, SysFsFactory,
    block_root_for_source,
};
use alloc::vec;
use lazy_static::lazy_static;

struct Ext4MountFactory;

impl VfsFileSystemFactory for Ext4MountFactory {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        let source = context.source.as_deref().ok_or(VfsError::Invalid)?;
        let root = block_root_for_source(source).ok_or(VfsError::NoDevice)?;
        Ok(Ext4Vfs::new(root))
    }

    fn requires_device(&self) -> bool {
        true
    }
}

struct TmpFsMountFactory;

impl VfsFileSystemFactory for TmpFsMountFactory {
    fn create(&self, context: &VfsMountContext) -> VfsResult<Arc<dyn VfsFileSystem>> {
        let memory_bytes = crate::config::phys_mem_total();
        TmpFs::new(memory_bytes, &context.data)
            .map(|filesystem| filesystem as Arc<dyn VfsFileSystem>)
    }
}

lazy_static! {
    static ref VFS_FILESYSTEM_REGISTRY: VfsFileSystemRegistry = {
        let registry = VfsFileSystemRegistry::default();
        registry
            .register("ext4", Arc::new(Ext4MountFactory))
            .expect("register ext4 VFS factory");
        registry
            .register("tmpfs", Arc::new(TmpFsMountFactory))
            .expect("register tmpfs VFS factory");
        registry
            .register("proc", Arc::new(ProcFsFactory))
            .expect("register procfs VFS factory");
        registry
            .register("sysfs", Arc::new(SysFsFactory))
            .expect("register sysfs VFS factory");
        registry
            .register("devtmpfs", Arc::new(DevTmpFsFactory))
            .expect("register devtmpfs VFS factory");
        registry
            .register("cgroup2", Arc::new(Cgroup2FsFactory))
            .expect("register cgroup2 VFS factory");
        registry
            .register("cgroup", Arc::new(CgroupV1FsFactory))
            .expect("register cgroup VFS factory");
        registry
    };
}

pub(crate) fn create_registered_vfs_filesystem(
    fs_type: &str,
    source: Option<&str>,
    data: &str,
    pid_namespace_id: u64,
    cgroup_namespace_root: &str,
) -> Result<Arc<dyn VfsFileSystem>, isize> {
    VFS_FILESYSTEM_REGISTRY
        .create(fs_type, &VfsMountContext {
            source: source.map(String::from),
            data: String::from(data),
            pid_namespace_id: Some(pid_namespace_id),
            cgroup_namespace_root: Some(String::from(cgroup_namespace_root)),
        })
        .map_err(map_vfs_error)
}

/// Render the registered filesystem types using Linux `/proc/filesystems`
/// syntax.  Device-less filesystems carry the `nodev` marker; ext4 is backed
/// by a block device and therefore has an empty first column.
pub(crate) fn proc_filesystems_snapshot() -> String {
    let mut output = String::new();
    for (filesystem_type, requires_device) in VFS_FILESYSTEM_REGISTRY.filesystem_types() {
        if requires_device {
            output.push('\t');
        } else {
            output.push_str("nodev\t");
        }
        output.push_str(&filesystem_type);
        output.push('\n');
    }
    output
}

pub(crate) fn mount_flags_to_proc_opts(flags: usize) -> String {
    let mut opts = Vec::new();
    opts.push(if (flags & MS_RDONLY) != 0 { "ro" } else { "rw" });
    if (flags & MS_NOSUID) != 0 {
        opts.push("nosuid");
    }
    if (flags & MS_NODEV) != 0 {
        opts.push("nodev");
    }
    if (flags & MS_NOEXEC) != 0 {
        opts.push("noexec");
    }
    if (flags & MS_NOATIME) != 0 {
        opts.push("noatime");
    }
    if (flags & MS_NODIRATIME) != 0 {
        opts.push("nodiratime");
    }
    if (flags & MS_STRICTATIME) != 0 {
        opts.push("strictatime");
    }
    if (flags & MS_NOSYMFOLLOW) != 0 {
        opts.push("nosymfollow");
    }
    if (flags & (MS_NOATIME | MS_STRICTATIME)) == 0 {
        opts.push("relatime");
    }
    opts.join(",")
}

pub(crate) fn mount_flags_to_statfs(flags: usize) -> i64 {
    const ST_VALID: usize = MS_REMOUNT;
    let mut out = ST_VALID;
    out |= flags
        & (MS_RDONLY
            | MS_NOSUID
            | MS_NODEV
            | MS_NOEXEC
            | MS_NOATIME
            | MS_NODIRATIME
            | MS_STRICTATIME);
    if (flags & MS_NOSYMFOLLOW) != 0 {
        out |= ST_NOSYMFOLLOW;
    }
    out as i64
}

pub(crate) fn current_mount_namespace() -> MountNamespace {
    current_process().mount_namespace()
}

pub(crate) fn mount_backend_for_fs_type(fs_type: &str) -> MountBackend {
    match fs_type {
        "proc" => MountBackend::Proc {
            pid_namespace_id: current_process().pid_namespace_id(),
        },
        "sysfs" => MountBackend::SysFs,
        "devtmpfs" => MountBackend::DevTmpFs,
        "cgroup" | "cgroup2" => MountBackend::Cgroup,
        _ => MountBackend::Storage,
    }
}

pub(crate) fn next_mount_stack_seq() -> usize {
    NEXT_MOUNT_STACK_SEQ.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn next_mount_event_id() -> usize {
    NEXT_MOUNT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn next_mount_peer_group_id() -> usize {
    NEXT_MOUNT_PEER_GROUP_ID.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn mount_lookup_for_abs(abs: &str) -> Option<MountRecord> {
    let state = current_mount_namespace();
    let state = state.lock();
    state.mount_record_for_path(abs)
}

pub(crate) fn mount_flags_for_abs(abs: &str) -> usize {
    let state = current_mount_namespace();
    let state = state.lock();
    state.mount_flags_for_path(abs)
}

pub(crate) fn with_mount_namespace_mut<R>(
    ns: &MountNamespace,
    f: impl FnOnce(&mut MountNamespaceState) -> R,
) -> R {
    let mut state = ns.lock();
    f(&mut state)
}

pub(crate) fn push_mount_record_in(
    ns: &MountNamespace,
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    backend: MountBackend,
    flags: usize,
    propagation: MountPropagation,
    peer_group_id: Option<usize>,
    master_group_id: Option<usize>,
    event_id: usize,
) {
    with_mount_namespace_mut(ns, |state| {
        let stack_seq = next_mount_stack_seq();
        state.push_record(MountRecord {
            target: String::from(target),
            source: String::from(source),
            source_display: String::from(source_display),
            fs_type: String::from(fs_type),
            backend,
            flags,
            stack_seq,
            event_id,
            propagation,
            peer_group_id,
            master_group_id,
            access_seq: 0,
            expire_mark_seq: None,
        });
    });
}

fn ensure_root_mount_record(state: &mut MountNamespaceState) {
    if state.mount_record_for_target("/").is_some() {
        return;
    }
    state.push_record(MountRecord {
        target: String::from("/"),
        source: String::from("/"),
        source_display: String::from("/dev/root"),
        fs_type: String::from("ext4"),
        backend: MountBackend::Storage,
        flags: 0,
        stack_seq: next_mount_stack_seq(),
        event_id: next_mount_event_id(),
        propagation: MountPropagation::Private,
        peer_group_id: None,
        master_group_id: None,
        access_seq: 0,
        expire_mark_seq: None,
    });
}

pub(crate) fn mount_record_for_target(target: &str) -> Option<MountRecord> {
    let state = current_mount_namespace();
    let state = state.lock();
    state.mount_record_for_target(target)
}

pub(crate) fn mount_record_for_target_in(ns: &MountNamespace, target: &str) -> Option<MountRecord> {
    let state = ns.lock();
    state.mount_record_for_target(target)
}

pub(crate) fn sync_rofs_mount_flag_in(ns: &MountNamespace, target: &str, flags: usize) {
    with_mount_namespace_mut(ns, |state| {
        state.sync_rofs_mount_flag(target, flags & MS_RDONLY);
    });
}

pub(crate) fn sync_rofs_mount_flag(target: &str, flags: usize) {
    sync_rofs_mount_flag_in(&current_mount_namespace(), target, flags);
}

pub(crate) fn sync_mount_record_rofs_in(ns: &MountNamespace, target: &str) {
    if let Some(record) = mount_record_for_target_in(ns, target) {
        sync_rofs_mount_flag_in(ns, target, record.flags);
    } else {
        sync_rofs_mount_flag_in(ns, target, 0);
    }
}

pub(crate) fn push_mount_record(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    backend: MountBackend,
    flags: usize,
    propagation: MountPropagation,
    peer_group_id: Option<usize>,
    master_group_id: Option<usize>,
    event_id: usize,
) {
    push_mount_record_in(
        &current_mount_namespace(),
        target,
        source,
        source_display,
        fs_type,
        backend,
        flags,
        propagation,
        peer_group_id,
        master_group_id,
        event_id,
    );
}

pub(crate) fn update_mount_record_flags_in(
    ns: &MountNamespace,
    target: &str,
    flags: usize,
) -> bool {
    with_mount_namespace_mut(ns, |state| state.update_top_mount_flags(target, flags))
}

pub(crate) fn update_mount_record_flags(target: &str, flags: usize) -> bool {
    update_mount_record_flags_in(&current_mount_namespace(), target, flags)
}

fn rebase_mount_path(path: &str, old_root: &str, new_root: &str) -> String {
    let suffix = mount_target_suffix(old_root, path);
    if suffix.is_empty() {
        String::from(new_root)
    } else {
        normalize_path(new_root, &suffix)
    }
}

fn mount_parent_path(target: &str) -> Option<String> {
    let target = target.trim_end_matches('/');
    if target.is_empty() || target == "/" {
        return None;
    }
    let idx = target.rfind('/')?;
    if idx == 0 {
        Some(String::from("/"))
    } else {
        Some(String::from(&target[..idx]))
    }
}

fn mount_parent_is_shared(target: &str) -> bool {
    let Some(parent) = mount_parent_path(target) else {
        return false;
    };
    mount_lookup_for_abs(&parent).is_some_and(|mount| mount.peer_group_id.is_some())
}

fn mount_subtree_contains_unbindable(target: &str) -> bool {
    let ns = current_mount_namespace();
    let state = ns.lock();
    state.mounts().iter().any(|record| {
        path_under_mount(&record.target, target)
            && record.propagation == MountPropagation::Unbindable
    })
}

fn path_strictly_under_mount(path: &str, base: &str) -> bool {
    path != base && path_under_mount(path, base)
}

pub(crate) fn move_mount_subtree_with_propagation(
    old_target: &str,
    new_target: &str,
    dest_base: Option<MountRecord>,
    stack_on_existing_target: bool,
) -> bool {
    let current_ns = current_mount_namespace();
    let Some((moved_root_stack_seq, moved_records)) =
        with_mount_namespace_mut(&current_ns, |state| {
            let root_idx = state.top_mount_index_for_target(old_target)?;
            let root_stack_seq = state.mounts()[root_idx].stack_seq;
            let moved_root_stack_seq = if stack_on_existing_target {
                next_mount_stack_seq()
            } else {
                root_stack_seq
            };
            let mut moved_records = Vec::new();
            for record in state.mounts_mut().iter_mut() {
                if !path_under_mount(&record.target, old_target) {
                    continue;
                }
                if record.target == old_target && record.stack_seq == root_stack_seq {
                    record.stack_seq = moved_root_stack_seq;
                }
                record.target = rebase_mount_path(&record.target, old_target, new_target);
                moved_records.push(record.clone());
            }
            for mount in state.rofs_mounts_mut().iter_mut() {
                if path_under_mount(mount, old_target) {
                    *mount = rebase_mount_path(mount, old_target, new_target);
                }
            }
            Some((moved_root_stack_seq, moved_records))
        })
    else {
        return false;
    };

    let Some(base) = dest_base else {
        return true;
    };
    if base.peer_group_id.is_none() {
        return true;
    }

    let moved_root = moved_records
        .iter()
        .find(|record| record.target == new_target && record.stack_seq == moved_root_stack_seq)
        .cloned();
    let preserve_moved_root_group = moved_root
        .as_ref()
        .is_some_and(|record| record.peer_group_id.is_some());
    let event_peer_group = moved_root
        .as_ref()
        .and_then(|record| record.peer_group_id)
        .unwrap_or_else(next_mount_peer_group_id);
    let origin_master_group = moved_root
        .as_ref()
        .and_then(|record| record.master_group_id)
        .filter(|_| preserve_moved_root_group);

    for dest in shared_group_destinations(&base, new_target, event_peer_group, origin_master_group)
    {
        let dest_ns_id = mount_namespace_id(&dest.ns);
        let current_ns_id = mount_namespace_id(&current_ns);
        if dest_ns_id == current_ns_id && dest.target == new_target {
            if preserve_moved_root_group {
                continue;
            }
            with_mount_namespace_mut(&current_ns, |state| {
                if let Some(record) = state.mounts_mut().iter_mut().find(|record| {
                    record.target == new_target && record.stack_seq == moved_root_stack_seq
                }) {
                    record.propagation = dest.propagation;
                    record.peer_group_id = dest.peer_group_id;
                    record.master_group_id = dest.master_group_id;
                }
            });
            continue;
        }

        let mut cloned_records = Vec::new();
        for record in &moved_records {
            let mut cloned = record.clone();
            cloned.target = rebase_mount_path(&record.target, new_target, &dest.target);
            cloned.stack_seq = next_mount_stack_seq();
            if record.target == new_target && record.stack_seq == moved_root_stack_seq {
                if preserve_moved_root_group {
                    if let Some(root) = &moved_root {
                        cloned.propagation = root.propagation;
                        cloned.peer_group_id = root.peer_group_id;
                        cloned.master_group_id = root.master_group_id;
                    }
                } else {
                    cloned.propagation = dest.propagation;
                    cloned.peer_group_id = dest.peer_group_id;
                    cloned.master_group_id = dest.master_group_id;
                }
            }
            cloned_records.push(cloned);
        }
        with_mount_namespace_mut(&dest.ns, |state| {
            for record in cloned_records {
                state.push_record(record);
            }
        });
        for record in &moved_records {
            let target = rebase_mount_path(&record.target, new_target, &dest.target);
            sync_mount_record_rofs_in(&dest.ns, &target);
        }
    }

    true
}

pub(crate) fn mount_flag_mask() -> usize {
    MS_RDONLY
        | MS_NOSUID
        | MS_NODEV
        | MS_NOEXEC
        | MS_NOSYMFOLLOW
        | MS_NOATIME
        | MS_NODIRATIME
        | MS_STRICTATIME
}

pub(crate) fn note_mount_access(abs: &str) {
    with_mount_namespace_mut(&current_mount_namespace(), |state| {
        state.note_mount_access(abs);
    });
}

pub(crate) fn current_cwd_path() -> String {
    current_process().fs_struct().cwd_display()
}

pub(crate) fn proc_self_fd_path(fd: usize) -> String {
    alloc::format!("/proc/self/fd/{}", fd)
}

/// Get the path string of the fd,if failed return the fallback
pub(crate) fn logical_path_for_open_fd(
    fd: usize,
    file: &Arc<dyn File + Send + Sync>,
    cwd_fallback: &str,
) -> String {
    if let Some(path) = file.logical_path_hint() {
        return String::from(path);
    }
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return String::from(pdir.path());
    }
    if let Some(vfs_file) = file.as_any().downcast_ref::<VfsOpenedFile>() {
        return String::from(vfs_file.logical_path());
    }
    crate::fs::proc_readlink(&proc_self_fd_path(fd)).unwrap_or_else(|| String::from(cwd_fallback))
}

pub(crate) fn mount_file_logical_path(file: &Arc<dyn File + Send + Sync>) -> Option<String> {
    if let Some(path) = file.logical_path_hint() {
        return Some(String::from(path));
    }
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Some(String::from(pdir.path()));
    }
    if let Some(vfs_file) = file.as_any().downcast_ref::<VfsOpenedFile>() {
        return Some(String::from(vfs_file.logical_path()));
    }
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        return match pf.kind_tag() {
            crate::fs::PseudoKindTag::Null => Some(String::from("/dev/null")),
            crate::fs::PseudoKindTag::Zero => Some(String::from("/dev/zero")),
            crate::fs::PseudoKindTag::Urandom => Some(String::from("/dev/urandom")),
            crate::fs::PseudoKindTag::Static => None,
        };
    }
    if file.as_any().downcast_ref::<RtcFile>().is_some() {
        return Some(String::from("/dev/misc/rtc"));
    }
    let os_inode = file.as_any().downcast_ref::<OSInode>()?;
    inode_raw_logical_path(&os_inode.ext4_inode())
}

pub(crate) fn mount_is_busy(target: &str, writable_only: bool) -> bool {
    let top_record = mount_record_for_target(target);
    let target_object_mount_id = resolve_object_vfs_absolute(target)
        .ok()
        .map(|path| path.mount().id());
    let self_bind_root = top_record
        .as_ref()
        .map(|record| record.source == target)
        .unwrap_or(false);
    let current_ns_id = current_process().mount_namespace_id();
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let (fs, namespace, files) = match process.try_borrow_mut() {
            Some(inner) => {
                if inner.is_zombie {
                    continue;
                }
                let Some(fs) = inner.fs.as_ref().map(Arc::clone) else {
                    continue;
                };
                (fs, Arc::clone(&inner.mnt_ns), Arc::clone(&inner.files))
            }
            None => continue,
        };
        if mount_namespace_id(&namespace) != current_ns_id {
            continue;
        }
        let (cwd_busy, root_busy) = if let Some(target_mount_id) = target_object_mount_id {
            (
                fs.cwd().path().mount().id() == target_mount_id,
                fs.root().path().mount().id() == target_mount_id,
            )
        } else {
            let cwd = fs.cwd_display();
            let root = fs.root_display();
            (
                path_under_mount(&cwd, target) && !(self_bind_root && cwd == target),
                path_under_mount(&root, target) && !(self_bind_root && root == target),
            )
        };
        if cwd_busy || root_busy {
            return true;
        }
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        let files_guard = files.lock();
        for (_fd, file) in files_guard.iter_files_snapshot() {
            if writable_only && !file.writable() {
                continue;
            }
            if let Some(target_mount_id) = target_object_mount_id {
                if file
                    .object_path()
                    .is_some_and(|path| path.mount().id() == target_mount_id)
                {
                    return true;
                }
                // Object mounts never infer ownership from a display string.
                // Path-backed files carry `f_path`; anonymous/control files do
                // not pin any mount.  Falling through for a console spelling
                // such as `/dev/tty` would falsely keep an overmount of `/`
                // busy even though that description belongs to the lower tree.
                continue;
            }
            let Some(path) = mount_file_logical_path(&file) else {
                continue;
            };
            if path_under_mount(&path, target) {
                return true;
            }
        }
    }
    false
}

fn resolve_object_vfs_user_path(path: &str) -> Result<VfsPath, isize> {
    let at = resolve_at_path(AT_FDCWD, path)?;
    let (uid, gid) = current_fsuid_gid();
    resolve_at_vfs_path(&at, uid, gid, true)
}

fn resolve_object_vfs_absolute(path: &str) -> Result<VfsPath, isize> {
    let namespace = current_mount_namespace().lock().vfs_namespace();
    let root = namespace.root_path();
    PathWalker::new(namespace)
        .walk(
            &root,
            &root,
            path,
            LookupFlags(LookupFlags::FOLLOW_FINAL),
            VfsCredentials::default(),
        )
        .map_err(map_vfs_error)
}

/// Attach a bind directly to the authoritative mount graph.  The presentation
/// record is updated only after the graph mutation succeeds.
fn object_vfs_bind_mount(
    target_user: &str,
    target_abs: &str,
    source_user: &str,
    source_abs: &str,
    fs_type: &str,
    flags: usize,
    recursive: bool,
) -> Result<(), isize> {
    let source = resolve_object_vfs_user_path(source_user)?;
    let target = resolve_object_vfs_user_path(target_user)?;
    let source_is_dir =
        source.node().metadata().map_err(map_vfs_error)?.kind == VfsNodeKind::Directory;
    let target_is_dir =
        target.node().metadata().map_err(map_vfs_error)?.kind == VfsNodeKind::Directory;
    if source_is_dir != target_is_dir {
        return Err(err(SyscallError::ENOTDIR));
    }
    // Bind mounts clone the source mount's per-mount restrictions.  Any
    // explicitly supplied mount-local bits are additive here; a later
    // `MS_REMOUNT|MS_BIND` can independently change the clone.
    let flags = (source.mount().flags().0 & mount_flag_mask()) | (flags & mount_flag_mask());

    let namespace = current_mount_namespace().lock().vfs_namespace();
    if recursive {
        namespace
            .bind_recursive(&target, &source, VfsMountFlags(flags))
            .map_err(map_vfs_error)?;
    } else {
        namespace
            .bind(&target, &source, VfsMountFlags(flags))
            .map_err(map_vfs_error)?;
    }
    create_object_bind_mount_record_with_propagation(
        target_abs, source_abs, source_abs, fs_type, flags, recursive,
    );
    Ok(())
}

/// Instantiate a registered filesystem and attach it directly to the mount
/// graph.  `record_source` is retained only by the transitional mountinfo
/// view; pathname lookup is rooted at the filesystem's dentry instead.
///
/// Linux's legacy `mount(2)` path creates an `fs_context`, parses the
/// monolithic data string in the selected filesystem and then grafts the
/// resulting mount (`do_new_mount()` in `fs/namespace.c`).  Keep that same
/// ordering here so filesystem-specific options never select a hidden ext4
/// backing directory.
fn object_vfs_registered_mount(
    target_user: &str,
    target_abs: &str,
    fs_type: &str,
    source_display: &str,
    record_source: &str,
    data: &str,
    flags: usize,
) -> Result<(), isize> {
    let target = resolve_object_vfs_user_path(target_user)?;
    if target.node().metadata().map_err(map_vfs_error)?.kind != VfsNodeKind::Directory {
        return Err(err(SyscallError::ENOTDIR));
    }
    let pid_namespace_id = current_process().pid_namespace_id() as u64;
    let cgroup_namespace_root = current_process().cgroup_namespace_root();
    let filesystem = create_registered_vfs_filesystem(
        fs_type,
        Some(source_display),
        data,
        pid_namespace_id,
        &cgroup_namespace_root,
    )?;
    let namespace = current_mount_namespace().lock().vfs_namespace();
    namespace
        .mount_with_source(
            &target,
            filesystem,
            VfsMountFlags(flags),
            String::from(source_display),
        )
        .map_err(map_vfs_error)?;
    create_object_mount_record_with_propagation(
        target_abs,
        record_source,
        source_display,
        fs_type,
        flags,
    );
    Ok(())
}

fn object_vfs_ext4_mount(
    target_user: &str,
    target_abs: &str,
    source_display: &str,
    legacy_source: &str,
    flags: usize,
) -> Result<(), isize> {
    object_vfs_registered_mount(
        target_user,
        target_abs,
        "ext4",
        source_display,
        legacy_source,
        "",
        flags,
    )
}

/// Attach a detached object created by `fsmount()` or
/// `open_tree(OPEN_TREE_CLONE)` to the authoritative graph.  Linux represents
/// both as anonymous mount trees and `move_mount()` performs the single
/// namespace attachment; this compact model preserves that lifetime and
/// one-shot transition without manufacturing a pathname for the source.
pub(crate) fn attach_or_move_mount_handle(
    target: &VfsPath,
    target_abs: &str,
    state: &mut MountHandleState,
) -> Result<(), isize> {
    let object = &state.object;
    let live_path = matches!(object, MountHandleObject::Path { .. });
    if state.attached && !live_path {
        return Err(err(SyscallError::EBUSY));
    }

    let target_kind = target.node().metadata().map_err(map_vfs_error)?.kind;
    let source_kind = match object {
        MountHandleObject::Filesystem(filesystem) => {
            filesystem
                .root_node()
                .metadata()
                .map_err(map_vfs_error)?
                .kind
        }
        MountHandleObject::Bind { source, .. } => {
            source.node().metadata().map_err(map_vfs_error)?.kind
        }
        MountHandleObject::Path { source, .. } => {
            source.node().metadata().map_err(map_vfs_error)?.kind
        }
    };
    if (source_kind == VfsNodeKind::Directory) != (target_kind == VfsNodeKind::Directory) {
        return Err(err(SyscallError::EINVAL));
    }

    let namespace = current_mount_namespace().lock().vfs_namespace();
    let flags = state.flags;
    let record_source = state.source.clone();
    let source_display = state.source_display.clone();
    let fs_type = state.fs_type.clone();
    match &mut state.object {
        MountHandleObject::Filesystem(filesystem) => {
            namespace
                .mount_with_source(
                    target,
                    Arc::clone(filesystem),
                    VfsMountFlags(flags),
                    source_display.clone(),
                )
                .map_err(map_vfs_error)?;
            create_object_mount_record_with_propagation(
                target_abs,
                &record_source,
                &source_display,
                &fs_type,
                flags,
            );
        }
        MountHandleObject::Bind {
            source,
            logical_source,
            ..
        } => {
            let bind_flags =
                (source.mount().flags().0 & mount_flag_mask()) | (flags & mount_flag_mask());
            namespace
                .bind(target, source, VfsMountFlags(bind_flags))
                .map_err(map_vfs_error)?;
            create_object_bind_mount_record_with_propagation(
                target_abs,
                &record_source,
                logical_source,
                &fs_type,
                bind_flags,
                false,
            );
        }
        MountHandleObject::Path {
            source,
            logical_source,
            ..
        } => {
            let old_target = logical_source.clone();
            let old_record =
                mount_record_for_target(&old_target).ok_or_else(|| err(SyscallError::EINVAL))?;
            if path_under_mount(target_abs, &old_target) || mount_parent_is_shared(&old_target) {
                return Err(err(SyscallError::EINVAL));
            }
            let destination =
                mount_lookup_for_abs(target_abs).ok_or_else(|| err(SyscallError::EINVAL))?;
            if destination.peer_group_id.is_some() {
                // The graph does not yet clone moved subtrees to every shared
                // peer.  Reject this Linux propagation corner instead of
                // letting the graph and mountinfo view diverge.
                return Err(err(SyscallError::EINVAL));
            }
            let stack_on_existing_target = mount_record_for_target(target_abs).is_some();
            if source
                .mount()
                .owner_namespace()
                .as_ref()
                .is_none_or(|owner| !Arc::ptr_eq(owner, &namespace))
            {
                return Err(err(SyscallError::EXDEV));
            }
            namespace
                .move_mount(source, target)
                .map_err(map_vfs_error)?;
            if !move_mount_subtree_with_propagation(
                &old_target,
                target_abs,
                Some(destination),
                stack_on_existing_target,
            ) {
                if let Ok(old_destination) = resolve_object_vfs_absolute(&old_target) {
                    let _ = namespace.move_mount(source, &old_destination);
                }
                return Err(err(SyscallError::EINVAL));
            }
            sync_rofs_mount_flag(&old_target, 0);
            sync_rofs_mount_flag(target_abs, old_record.flags);
            *logical_source = String::from(target_abs);
        }
    }
    if !live_path {
        state.attached = true;
    }
    Ok(())
}

/// Transactionally apply mount flags to both the object graph and the
/// transitional presentation record.  `fspick()+fsconfig(RECONFIGURE)` and
/// legacy `MS_REMOUNT` share this path so neither API can split the two views.
pub(crate) fn reconfigure_mount_flags(target: &str, flags: usize) -> Result<(), isize> {
    let Some(record) = mount_record_for_target(target) else {
        return Err(err(SyscallError::EINVAL));
    };
    let new_flags = flags & mount_flag_mask();
    if (new_flags & MS_RDONLY) != 0 && mount_is_busy(target, true) {
        return Err(err(SyscallError::EBUSY));
    }
    if record.source_display == "/dev/root"
        && (new_flags & MS_RDONLY) == 0
        && pseudo_block_is_read_only()
    {
        return Err(err(SyscallError::EACCES));
    }

    let path = resolve_object_vfs_absolute(target)?;
    let namespace = current_mount_namespace().lock().vfs_namespace();
    namespace
        .remount(&path, VfsMountFlags(new_flags))
        .map_err(map_vfs_error)?;
    if !update_mount_record_flags(target, new_flags) {
        let _ = namespace.remount(&path, VfsMountFlags(record.flags));
        return Err(err(SyscallError::EINVAL));
    }
    sync_rofs_mount_flag(target, new_flags);
    Ok(())
}

pub(crate) fn target_dir_exists(abs: &str) -> Result<(), isize> {
    // Linux validates a mountpoint through the resolved `struct path`.
    // Presentation source strings cannot represent overmount and tmpfs roots.
    let target = resolve_object_vfs_absolute(abs)?;
    if target.node().metadata().map_err(map_vfs_error)?.kind == VfsNodeKind::Directory {
        Ok(())
    } else {
        Err(err(SyscallError::ENOTDIR))
    }
}

pub(crate) fn collect_live_mount_namespaces() -> Vec<MountNamespace> {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        if inner.is_zombie {
            continue;
        }
        let ns = Arc::clone(&inner.mnt_ns);
        let ns_id = inner.mnt_ns.lock().id();
        drop(inner);
        if seen.insert(ns_id) {
            out.push(ns);
        }
    }
    out
}

#[derive(Clone)]
pub(crate) struct MountPropagationDestination {
    pub(crate) ns: MountNamespace,
    pub(crate) target: String,
    pub(crate) propagation: MountPropagation,
    pub(crate) peer_group_id: Option<usize>,
    pub(crate) master_group_id: Option<usize>,
}

pub(crate) fn inherited_mount_propagation(
    target: &str,
) -> (MountPropagation, Option<usize>, Option<usize>) {
    let Some(base) = mount_lookup_for_abs(target) else {
        return (MountPropagation::Private, None, None);
    };
    match base.propagation {
        MountPropagation::Private => (MountPropagation::Private, None, None),
        MountPropagation::Shared => (
            MountPropagation::Shared,
            base.peer_group_id,
            base.master_group_id,
        ),
        MountPropagation::Slave => (MountPropagation::Slave, None, base.master_group_id),
        MountPropagation::Unbindable => (MountPropagation::Unbindable, None, None),
    }
}

pub(crate) fn top_mounts_for_namespace(ns: &MountNamespace) -> Vec<MountRecord> {
    let state = ns.lock();
    state.top_mounts()
}

pub(crate) fn mount_target_suffix(base_target: &str, target: &str) -> String {
    if target == base_target {
        return String::new();
    }
    String::from(target[base_target.len()..].trim_start_matches('/'))
}

fn propagation_destination_target(top: &MountRecord, event_source: &str, suffix: &str) -> String {
    if path_under_mount(event_source, &top.source) {
        let source_suffix = mount_target_suffix(&top.source, event_source);
        if source_suffix.is_empty() {
            top.target.clone()
        } else {
            normalize_path(&top.target, &source_suffix)
        }
    } else if suffix.is_empty() {
        top.target.clone()
    } else {
        normalize_path(&top.target, suffix)
    }
}

#[derive(Clone)]
struct MountSubtreeClone {
    record: MountRecord,
    suffix: String,
    event_id: usize,
    propagated_peer_group_id: Option<usize>,
}

fn collect_subtree_mount_clones(
    source_display: &str,
    excluded_source_prefixes: &[String],
) -> Vec<MountSubtreeClone> {
    let ns = current_mount_namespace();
    let state = ns.lock();
    let mut out = Vec::new();
    let mut unbindable_prefixes = Vec::new();
    for record in state.mounts() {
        if record.target != source_display
            && path_under_mount(&record.target, source_display)
            && record.propagation == MountPropagation::Unbindable
        {
            unbindable_prefixes.push(record.target.clone());
        }
    }
    for record in state.mounts() {
        if record.target == source_display || !path_under_mount(&record.target, source_display) {
            continue;
        }
        if excluded_source_prefixes
            .iter()
            .any(|prefix| path_under_mount(&record.target, prefix))
        {
            continue;
        }
        if unbindable_prefixes
            .iter()
            .any(|prefix| path_under_mount(&record.target, prefix))
        {
            continue;
        }
        let needs_propagated_peer =
            record.peer_group_id.is_none() && record.master_group_id.is_none();
        out.push(MountSubtreeClone {
            record: record.clone(),
            suffix: mount_target_suffix(source_display, &record.target),
            event_id: next_mount_event_id(),
            propagated_peer_group_id: needs_propagated_peer.then(next_mount_peer_group_id),
        });
    }
    out
}

fn bind_should_clone_subtree(recursive_bind: bool) -> bool {
    // Linux's __do_loopback() uses clone_mnt() for a plain bind and only
    // copy_tree() for MS_BIND|MS_REC.
    recursive_bind
}

fn collect_bind_subtree_mount_clones(
    source_display: &str,
    excluded_source_prefixes: &[String],
    recursive_bind: bool,
) -> Vec<MountSubtreeClone> {
    if bind_should_clone_subtree(recursive_bind) {
        collect_subtree_mount_clones(source_display, excluded_source_prefixes)
    } else {
        Vec::new()
    }
}

fn bind_subtree_clone_exclusions(target: &str, source_display: &str) -> Vec<String> {
    if target == source_display {
        vec![String::from(target)]
    } else {
        Vec::new()
    }
}

fn push_subtree_mount_clones(
    ns: &MountNamespace,
    target: &str,
    source_display: &str,
    clones: &[MountSubtreeClone],
    propagation_dest: Option<&MountPropagationDestination>,
    duplicate_shared_peer_clones: bool,
) {
    if clones.is_empty() {
        return;
    }
    with_mount_namespace_mut(ns, |state| {
        for item in clones {
            let clone_target = normalize_path(target, &item.suffix);
            if clone_target == target {
                continue;
            }
            let mut record = item.record.clone();
            // Recursive object bind has already cloned the corresponding
            // mount identity in VfsMountNamespace.  These records are only a
            // mountinfo/proc presentation of that authoritative graph.
            record.target = clone_target;
            record.source_display = if path_under_mount(&record.source_display, source_display) {
                let display_suffix = mount_target_suffix(source_display, &record.source_display);
                normalize_path(target, &display_suffix)
            } else {
                record.source_display.clone()
            };
            let duplicate_shared_peer = duplicate_shared_peer_clones
                && item.record.propagation == MountPropagation::Shared
                && item.record.peer_group_id.is_some();
            record.stack_seq = next_mount_stack_seq();
            record.event_id = if duplicate_shared_peer {
                item.record.event_id
            } else {
                item.event_id
            };
            if record.peer_group_id.is_none() && record.master_group_id.is_none() {
                if let Some(dest) = propagation_dest {
                    match dest.propagation {
                        MountPropagation::Shared => {
                            record.propagation = MountPropagation::Shared;
                            record.peer_group_id = item.propagated_peer_group_id;
                            record.master_group_id = dest.master_group_id;
                        }
                        MountPropagation::Slave => {
                            record.propagation = MountPropagation::Slave;
                            record.peer_group_id = None;
                            record.master_group_id = dest.master_group_id;
                        }
                        MountPropagation::Private | MountPropagation::Unbindable => {}
                    }
                }
            }
            let duplicate_record = duplicate_shared_peer.then(|| record.clone());
            state.push_record(record);
            if let Some(mut record) = duplicate_record {
                record.stack_seq = next_mount_stack_seq();
                record.event_id = item.event_id;
                state.push_record(record);
            }
        }
    });
}

fn propagation_target_under_unbindable(ns: &MountNamespace, target: &str) -> bool {
    let state = ns.lock();
    state
        .mount_record_for_path(target)
        .is_some_and(|record| record.propagation == MountPropagation::Unbindable)
}

pub(crate) fn shared_group_destinations(
    base: &MountRecord,
    target: &str,
    event_peer_group: usize,
    origin_master_group: Option<usize>,
) -> Vec<MountPropagationDestination> {
    let Some(peer_group) = base.peer_group_id else {
        return Vec::new();
    };
    let suffix = mount_target_suffix(&base.target, target);
    let event_source = if suffix.is_empty() {
        base.source.clone()
    } else {
        normalize_path(&base.source, &suffix)
    };
    let namespaces = collect_live_mount_namespaces();
    let mut visited_groups = BTreeSet::new();
    let mut slave_child_peers = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut pending = Vec::new();
    let mut out = Vec::new();

    pending.push((peer_group, event_peer_group, origin_master_group));
    while let Some((group, child_peer_group, peer_master_group)) = pending.pop() {
        if !visited_groups.insert((group, child_peer_group)) {
            continue;
        }
        for ns in &namespaces {
            let ns_id = mount_namespace_id(ns);
            for top in top_mounts_for_namespace(ns) {
                if top.peer_group_id == Some(group) {
                    let dest_target = propagation_destination_target(&top, &event_source, &suffix);
                    if propagation_target_under_unbindable(ns, &dest_target) {
                        continue;
                    }
                    let key = (
                        ns_id,
                        dest_target.clone(),
                        MountPropagation::Shared as u8,
                        Some(child_peer_group),
                        peer_master_group,
                    );
                    if seen.insert(key) {
                        out.push(MountPropagationDestination {
                            ns: Arc::clone(ns),
                            target: dest_target,
                            propagation: MountPropagation::Shared,
                            peer_group_id: Some(child_peer_group),
                            master_group_id: peer_master_group,
                        });
                    }
                    continue;
                }

                if top.master_group_id != Some(group) {
                    continue;
                }
                let dest_target = propagation_destination_target(&top, &event_source, &suffix);
                if propagation_target_under_unbindable(ns, &dest_target) {
                    continue;
                }
                if let Some(slave_peer_group) = top.peer_group_id {
                    let propagated_peer_group = *slave_child_peers
                        .entry(slave_peer_group)
                        .or_insert_with(next_mount_peer_group_id);
                    let key = (
                        ns_id,
                        dest_target.clone(),
                        MountPropagation::Shared as u8,
                        Some(propagated_peer_group),
                        Some(child_peer_group),
                    );
                    if seen.insert(key) {
                        out.push(MountPropagationDestination {
                            ns: Arc::clone(ns),
                            target: dest_target,
                            propagation: MountPropagation::Shared,
                            peer_group_id: Some(propagated_peer_group),
                            master_group_id: Some(child_peer_group),
                        });
                    }
                    pending.push((
                        slave_peer_group,
                        propagated_peer_group,
                        Some(child_peer_group),
                    ));
                } else {
                    let key = (
                        ns_id,
                        dest_target.clone(),
                        MountPropagation::Slave as u8,
                        None,
                        Some(child_peer_group),
                    );
                    if seen.insert(key) {
                        out.push(MountPropagationDestination {
                            ns: Arc::clone(ns),
                            target: dest_target,
                            propagation: MountPropagation::Slave,
                            peer_group_id: None,
                            master_group_id: Some(child_peer_group),
                        });
                    }
                }
            }
        }
    }

    out
}

pub(crate) fn push_mount_to_destination(
    dest: &MountPropagationDestination,
    source: &str,
    source_display: &str,
    fs_type: &str,
    backend: MountBackend,
    flags: usize,
    event_id: usize,
) {
    match dest.propagation {
        MountPropagation::Shared => {
            push_mount_record_in(
                &dest.ns,
                &dest.target,
                source,
                source_display,
                fs_type,
                backend,
                flags,
                MountPropagation::Shared,
                dest.peer_group_id,
                dest.master_group_id,
                event_id,
            );
        }
        MountPropagation::Slave => {
            push_mount_record_in(
                &dest.ns,
                &dest.target,
                source,
                source_display,
                fs_type,
                backend,
                flags,
                MountPropagation::Slave,
                None,
                dest.master_group_id,
                event_id,
            );
        }
        MountPropagation::Private | MountPropagation::Unbindable => {}
    }
    sync_mount_record_rofs_in(&dest.ns, &dest.target);
}

fn clone_subtree_mount_records_for_bind(
    target: &str,
    source_display: &str,
    _event_id: usize,
    clones: &[MountSubtreeClone],
) {
    let duplicate_shared_peer_clones = path_strictly_under_mount(target, source_display);
    push_subtree_mount_clones(
        &current_mount_namespace(),
        target,
        source_display,
        clones,
        None,
        duplicate_shared_peer_clones,
    );
}

fn clone_subtree_mount_records_to_destination(
    dest: &MountPropagationDestination,
    source_display: &str,
    _event_id: usize,
    clones: &[MountSubtreeClone],
) {
    let duplicate_shared_peer_clones = path_strictly_under_mount(&dest.target, source_display);
    push_subtree_mount_clones(
        &dest.ns,
        &dest.target,
        source_display,
        clones,
        Some(dest),
        duplicate_shared_peer_clones,
    );
}

fn create_object_mount_record_with_propagation(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
) {
    let backend = mount_backend_for_fs_type(fs_type);
    create_mount_record_with_backend(target, source, source_display, fs_type, backend, flags);
}

fn create_mount_record_with_backend(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    backend: MountBackend,
    flags: usize,
) {
    let Some(base) = mount_lookup_for_abs(target) else {
        push_mount_record(
            target,
            source,
            source_display,
            fs_type,
            backend,
            flags,
            MountPropagation::Private,
            None,
            None,
            next_mount_event_id(),
        );
        sync_mount_record_rofs(target);
        return;
    };

    if base.peer_group_id.is_some() {
        let event_id = next_mount_event_id();
        let new_peer_group = next_mount_peer_group_id();
        let mut created_any = false;
        for dest in shared_group_destinations(&base, target, new_peer_group, None) {
            created_any = true;
            push_mount_to_destination(
                &dest,
                source,
                source_display,
                fs_type,
                backend.clone(),
                flags,
                event_id,
            );
        }
        if !created_any {
            push_mount_record(
                target,
                source,
                source_display,
                fs_type,
                backend,
                flags,
                MountPropagation::Shared,
                Some(new_peer_group),
                None,
                event_id,
            );
            sync_mount_record_rofs(target);
        }
        return;
    }

    let (propagation, peer_group_id, master_group_id) = inherited_mount_propagation(target);
    push_mount_record(
        target,
        source,
        source_display,
        fs_type,
        backend,
        flags,
        propagation,
        peer_group_id,
        master_group_id,
        next_mount_event_id(),
    );
    sync_mount_record_rofs(target);
}

fn create_object_bind_mount_record_with_propagation(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
    recursive_bind: bool,
) {
    create_bind_mount_record_impl(
        target,
        source,
        source_display,
        fs_type,
        flags,
        recursive_bind,
    );
}

fn create_bind_mount_record_impl(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
    recursive_bind: bool,
) {
    let source_mount = mount_lookup_for_abs(source_display);
    let backend = source_mount
        .as_ref()
        .map(|mount| mount.backend.clone())
        .unwrap_or_else(|| mount_backend_for_fs_type(fs_type));
    let source_is_exact_mount = source_mount
        .as_ref()
        .map(|mount| mount.target == source_display)
        .unwrap_or(false);
    let self_bind_of_covered_path = source_display == target && !source_is_exact_mount;
    let source_peer_group = if self_bind_of_covered_path {
        None
    } else if source_is_exact_mount {
        source_mount.as_ref().and_then(|mount| mount.peer_group_id)
    } else {
        None
    };
    let source_master_group = if source_is_exact_mount {
        source_mount
            .as_ref()
            .and_then(|mount| mount.master_group_id)
    } else {
        None
    };

    if let Some(base) = mount_lookup_for_abs(target) {
        if base.peer_group_id.is_some() {
            let event_id = next_mount_event_id();
            let excluded = bind_subtree_clone_exclusions(target, source_display);
            let subtree_clones =
                collect_bind_subtree_mount_clones(source_display, &excluded, recursive_bind);
            let event_peer_group = source_peer_group.unwrap_or_else(next_mount_peer_group_id);
            let origin_master_group = source_master_group;
            let mut created_any = false;
            for dest in
                shared_group_destinations(&base, target, event_peer_group, origin_master_group)
            {
                created_any = true;
                push_mount_to_destination(
                    &dest,
                    source,
                    source_display,
                    fs_type,
                    backend.clone(),
                    flags,
                    event_id,
                );
                clone_subtree_mount_records_to_destination(
                    &dest,
                    source_display,
                    event_id,
                    &subtree_clones,
                );
            }
            if !created_any {
                push_mount_record(
                    target,
                    source,
                    source_display,
                    fs_type,
                    backend,
                    flags,
                    MountPropagation::Shared,
                    Some(event_peer_group),
                    origin_master_group,
                    event_id,
                );
                sync_mount_record_rofs(target);
                clone_subtree_mount_records_for_bind(
                    target,
                    source_display,
                    event_id,
                    &subtree_clones,
                );
            }
            return;
        }
    }

    if let Some(peer_group) = source_peer_group {
        let event_id = next_mount_event_id();
        let excluded = bind_subtree_clone_exclusions(target, source_display);
        let subtree_clones =
            collect_bind_subtree_mount_clones(source_display, &excluded, recursive_bind);
        push_mount_record(
            target,
            source,
            source_display,
            fs_type,
            backend,
            flags,
            MountPropagation::Shared,
            Some(peer_group),
            source_master_group,
            event_id,
        );
        sync_mount_record_rofs(target);
        clone_subtree_mount_records_for_bind(target, source_display, event_id, &subtree_clones);
        return;
    }

    if source_master_group.is_some() {
        let event_id = next_mount_event_id();
        let excluded = bind_subtree_clone_exclusions(target, source_display);
        let subtree_clones =
            collect_bind_subtree_mount_clones(source_display, &excluded, recursive_bind);
        push_mount_record(
            target,
            source,
            source_display,
            fs_type,
            backend,
            flags,
            MountPropagation::Slave,
            None,
            source_master_group,
            event_id,
        );
        sync_mount_record_rofs(target);
        clone_subtree_mount_records_for_bind(target, source_display, event_id, &subtree_clones);
        return;
    }

    let event_id = next_mount_event_id();
    let excluded = bind_subtree_clone_exclusions(target, source_display);
    let subtree_clones =
        collect_bind_subtree_mount_clones(source_display, &excluded, recursive_bind);
    push_mount_record(
        target,
        source,
        source_display,
        fs_type,
        backend,
        flags,
        MountPropagation::Private,
        None,
        None,
        event_id,
    );
    sync_mount_record_rofs(target);
    clone_subtree_mount_records_for_bind(target, source_display, event_id, &subtree_clones);
}

pub(crate) fn remove_mount_record_by_stack(
    ns: &MountNamespace,
    target: &str,
    stack_seq: usize,
) -> usize {
    let mut affected_targets: BTreeMap<String, usize> = BTreeMap::new();
    let removed = with_mount_namespace_mut(ns, |state| {
        let mut remove_keys = BTreeSet::new();
        for record in state.mounts() {
            if record.target == target && record.stack_seq == stack_seq {
                affected_targets.insert(record.target.clone(), record.stack_seq);
                remove_keys.insert((record.target.clone(), record.stack_seq));
            }
        }
        if remove_keys.is_empty() {
            return 0;
        }
        for record in state.mounts() {
            if remove_keys.contains(&(record.target.clone(), record.stack_seq)) {
                continue;
            }
            if affected_targets.iter().any(|(target, stack_seq)| {
                record.stack_seq > *stack_seq && path_strictly_under_mount(&record.target, target)
            }) {
                affected_targets.insert(record.target.clone(), record.stack_seq);
                remove_keys.insert((record.target.clone(), record.stack_seq));
            }
        }
        let before = state.mounts().len();
        state
            .mounts_mut()
            .retain(|record| !remove_keys.contains(&(record.target.clone(), record.stack_seq)));
        before.saturating_sub(state.mounts().len())
    });
    if removed != 0 {
        for target in affected_targets.keys() {
            sync_mount_record_rofs_in(ns, &target);
        }
    }
    removed
}

/// Remove mountinfo records for the exact object-graph targets detached by an
/// unmount propagation event.
///
/// Linux derives propagated unmounts from the parent mounts and the covered
/// mountpoint, not from the peer group of the child being removed.  The VFS
/// graph has already made that decision; compatibility records must mirror its
/// result instead of independently guessing from `record.peer_group_id`.
fn remove_object_mount_records_by_targets(targets: &[(u64, String)]) -> usize {
    let current = current_mount_namespace();
    let mut namespaces = BTreeMap::new();
    let current_vfs_id = current.lock().vfs_namespace().id();
    namespaces.insert(current_vfs_id, current);
    for namespace in collect_live_mount_namespaces() {
        let vfs_id = namespace.lock().vfs_namespace().id();
        namespaces.entry(vfs_id).or_insert(namespace);
    }

    let mut removed = 0usize;
    for (namespace_id, target) in targets {
        let Some(namespace) = namespaces.get(namespace_id) else {
            continue;
        };
        let Some(record) = mount_record_for_target_in(namespace, target) else {
            continue;
        };
        removed = removed.saturating_add(remove_mount_record_by_stack(
            namespace,
            &record.target,
            record.stack_seq,
        ));
    }
    removed
}

fn object_vfs_propagation(
    record: &MountRecord,
    requested: MountPropagation,
    current: VfsMountPropagation,
) -> VfsMountPropagation {
    match requested {
        MountPropagation::Private => VfsMountPropagation::Private,
        MountPropagation::Unbindable => VfsMountPropagation::Unbindable,
        MountPropagation::Shared => match current {
            // Linux's set_mnt_shared() keeps an existing peer group.
            shared @ VfsMountPropagation::Shared { .. } => shared,
            _ => VfsMountPropagation::Shared {
                peer_group: record.peer_group_id.unwrap_or(record.event_id) as u64,
            },
        },
        MountPropagation::Slave => {
            let master_group = match current {
                VfsMountPropagation::Shared { peer_group } => Some(peer_group),
                VfsMountPropagation::Slave { master_group } => Some(master_group),
                _ => record.master_group_id.map(|group| group as u64),
            };
            master_group
                .map(|master_group| VfsMountPropagation::Slave { master_group })
                .unwrap_or(VfsMountPropagation::Private)
        }
    }
}

fn restore_mount_records(ns: &MountNamespace, originals: &[MountRecord]) {
    with_mount_namespace_mut(ns, |state| {
        for original in originals {
            if let Some(record) = state.mounts_mut().iter_mut().find(|record| {
                record.target == original.target && record.stack_seq == original.stack_seq
            }) {
                *record = original.clone();
            }
        }
    });
}

pub(crate) fn apply_mount_propagation_change(target: &str, flags: usize) -> Result<(), isize> {
    let propagation = match (
        (flags & MS_SHARED) != 0,
        (flags & MS_PRIVATE) != 0,
        (flags & MS_SLAVE) != 0,
        (flags & MS_UNBINDABLE) != 0,
    ) {
        (true, false, false, false) => MountPropagation::Shared,
        (false, true, false, false) => MountPropagation::Private,
        (false, false, true, false) => MountPropagation::Slave,
        (false, false, false, true) => MountPropagation::Unbindable,
        _ => return Err(err(SyscallError::EINVAL)),
    };
    let recursive = (flags & MS_REC) != 0;
    let mount_namespace = current_mount_namespace();
    let (originals, updated) = with_mount_namespace_mut(&mount_namespace, |state| {
        if target == "/" {
            ensure_root_mount_record(state);
        }
        let mut apply_keys = BTreeSet::new();
        if recursive {
            for record in state.top_mounts() {
                if path_under_mount(&record.target, target) {
                    apply_keys.insert((record.target, record.stack_seq));
                }
            }
        } else if let Some(record) = state.mount_record_for_target(target) {
            apply_keys.insert((record.target, record.stack_seq));
        }
        let mut originals = Vec::new();
        let mut updated = Vec::new();
        for record in state.mounts_mut().iter_mut() {
            if !apply_keys.contains(&(record.target.clone(), record.stack_seq)) {
                continue;
            }
            originals.push(record.clone());
            match propagation {
                MountPropagation::Shared => {
                    let peer_group = record
                        .peer_group_id
                        .unwrap_or_else(next_mount_peer_group_id);
                    record.propagation = MountPropagation::Shared;
                    record.peer_group_id = Some(peer_group);
                }
                MountPropagation::Private => {
                    record.propagation = MountPropagation::Private;
                    record.peer_group_id = None;
                    record.master_group_id = None;
                }
                MountPropagation::Slave => {
                    let master_group = record.peer_group_id.or(record.master_group_id);
                    record.propagation = MountPropagation::Slave;
                    record.peer_group_id = None;
                    record.master_group_id = master_group;
                }
                MountPropagation::Unbindable => {
                    record.propagation = MountPropagation::Unbindable;
                    record.peer_group_id = None;
                    record.master_group_id = None;
                }
            }
            updated.push(record.clone());
        }
        (originals, updated)
    });
    if updated.is_empty() {
        target_dir_exists(target)?;
        return Ok(());
    }

    let object_namespace = mount_namespace.lock().vfs_namespace();
    let object_root = object_namespace.root_path();
    let mut graph_changes = Vec::new();
    for record in &updated {
        let path = match PathWalker::new(Arc::clone(&object_namespace)).walk(
            &object_root,
            &object_root,
            &record.target,
            LookupFlags(LookupFlags::FOLLOW_FINAL),
            VfsCredentials::default(),
        ) {
            Ok(path) => path,
            Err(error) => {
                restore_mount_records(&mount_namespace, &originals);
                return Err(map_vfs_error(error));
            }
        };
        let previous = path.mount().propagation();
        let desired = object_vfs_propagation(record, propagation, previous);
        if let Err(error) = object_namespace.set_propagation(&path, desired) {
            for (path, previous) in graph_changes.into_iter().rev() {
                let _ = object_namespace.set_propagation(&path, previous);
            }
            restore_mount_records(&mount_namespace, &originals);
            return Err(map_vfs_error(error));
        }
        graph_changes.push((path, previous));
    }
    Ok(())
}

pub(crate) fn sync_mount_record_rofs(target: &str) {
    if let Some(record) = mount_record_for_target(target) {
        sync_rofs_mount_flag(target, record.flags);
    } else {
        sync_rofs_mount_flag(target, 0);
    }
}

pub(crate) fn should_update_inode_atime(
    path: &str,
    is_dir: bool,
    times: InodeTimes,
    now_sec: i64,
) -> bool {
    let flags = mount_flags_for_abs(path);
    if (flags & MS_NOATIME) != 0 {
        return false;
    }
    if is_dir && (flags & MS_NODIRATIME) != 0 {
        return false;
    }
    if (flags & MS_STRICTATIME) != 0 {
        return true;
    }
    times.atime_sec <= times.mtime_sec
        || times.atime_sec <= times.ctime_sec
        || now_sec.saturating_sub(times.atime_sec) >= 24 * 60 * 60
}

pub(crate) fn maybe_update_inode_atime(inode: &Arc<ext4_fs::Inode>, is_dir: bool) {
    let Some(logical_path) = inode_logical_path(inode) else {
        return;
    };
    let ino = inode.inode_num() as u64;
    let times = get_inode_times(ino);
    let (sec, nsec) = current_timespec();
    if !should_update_inode_atime(&logical_path, is_dir, times, sec) {
        return;
    }
    let mut next = times;
    next.atime_sec = sec;
    next.atime_nsec = nsec;
    set_inode_times(ino, next);
}

pub(crate) fn mount_note_path_access(abs: &str) {
    note_mount_access(abs);
}

pub(crate) fn syscall_mount_impl(
    special_ptr: usize,
    dir_ptr: usize,
    fstype_ptr: usize,
    flags: usize,
    data_ptr: usize,
) -> isize {
    if current_process().borrow_mut().euid != 0 {
        return err(SyscallError::EPERM);
    }
    let token = get_current_token();
    let dir = match read_user_cstring(token, dir_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if dir.is_empty() {
        return err(SyscallError::ENOENT);
    }
    let process = current_process();
    let cwd = process.fs_struct().cwd_display();
    let target = normalize_path(&cwd, &dir);

    let propagation_flags = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
    if (flags & propagation_flags) != 0 && (flags & (MS_BIND | MS_MOVE)) == 0 {
        return match apply_mount_propagation_change(&target, flags) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }

    let special = if special_ptr == 0 {
        None
    } else {
        match read_user_cstring(token, special_ptr) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };
    let fstype = if fstype_ptr == 0 {
        None
    } else {
        match read_user_cstring(token, fstype_ptr) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };
    let data = if data_ptr == 0 {
        None
    } else {
        match read_user_cstring(token, data_ptr) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };

    if let Some(fsname) = fstype.as_deref() {
        if fsname == "error" || fsname == "overlay" {
            return err(SyscallError::ENODEV);
        }
    }

    if (flags & MS_BIND) != 0 && (flags & (MS_REMOUNT | MS_MOVE)) == 0 {
        let Some(source_display) = special.as_deref() else {
            return err(SyscallError::EINVAL);
        };
        if source_display.is_empty() {
            return err(SyscallError::EINVAL);
        }
        let source_abs = normalize_path(&cwd, source_display);
        if mount_lookup_for_abs(&source_abs)
            .map(|record| record.propagation == MountPropagation::Unbindable)
            .unwrap_or(false)
        {
            return err(SyscallError::EINVAL);
        }

        let fsname = fstype.as_deref().unwrap_or("none");
        match object_vfs_bind_mount(
            &dir,
            &target,
            source_display,
            &source_abs,
            fsname,
            flags,
            (flags & MS_REC) != 0,
        ) {
            Ok(()) => {
                if (flags & propagation_flags) != 0 {
                    return match apply_mount_propagation_change(
                        &target,
                        flags & (propagation_flags | MS_REC),
                    ) {
                        Ok(()) => 0,
                        Err(e) => e,
                    };
                }
                return 0;
            }
            Err(e) => return e,
        }
    }

    if let Err(e) = target_dir_exists(&target) {
        return e;
    }

    if (flags & MS_MOVE) != 0 {
        let Some(source) = special.as_deref() else {
            return err(SyscallError::EINVAL);
        };
        if source.is_empty() {
            return err(SyscallError::EINVAL);
        }
        let old_target = normalize_path(&cwd, source);
        let Some(old_record) = mount_record_for_target(&old_target) else {
            return err(SyscallError::EINVAL);
        };
        if path_under_mount(&target, &old_target) {
            return err(SyscallError::EINVAL);
        }
        if mount_parent_is_shared(&old_target) {
            return err(SyscallError::EINVAL);
        }
        let dest_base = mount_lookup_for_abs(&target);
        if dest_base
            .as_ref()
            .is_some_and(|base| base.peer_group_id.is_some())
            && mount_subtree_contains_unbindable(&old_target)
        {
            return err(SyscallError::EINVAL);
        }
        let stack_on_existing_target = mount_record_for_target(&target).is_some();
        let Some(destination_record) = dest_base.as_ref() else {
            return err(SyscallError::EINVAL);
        };
        // Linux propagates a move into a shared destination through
        // attach_recursive_mnt().  The minimal graph does not clone a moved
        // subtree yet, so reject that one unsupported case instead of letting
        // the presentation records diverge from the graph.
        if destination_record.peer_group_id.is_some() {
            return err(SyscallError::EINVAL);
        }
        let from = match resolve_object_vfs_absolute(&old_target) {
            Ok(path) => path,
            Err(e) => return e,
        };
        let to = match resolve_object_vfs_user_path(&dir) {
            Ok(path) => path,
            Err(e) => return e,
        };
        let namespace = current_mount_namespace().lock().vfs_namespace();
        if let Err(error) = namespace.move_mount(&from, &to) {
            return map_vfs_error(error);
        }
        let object_move = (namespace, from);
        if !move_mount_subtree_with_propagation(
            &old_target,
            &target,
            dest_base,
            stack_on_existing_target,
        ) {
            let (namespace, moving) = object_move;
            if let Ok(old_destination) = resolve_object_vfs_absolute(&old_target) {
                let _ = namespace.move_mount(&moving, &old_destination);
            }
            return err(SyscallError::EINVAL);
        }
        sync_rofs_mount_flag(&old_target, 0);
        sync_rofs_mount_flag(&target, old_record.flags);
        return 0;
    }

    if (flags & MS_REMOUNT) != 0 {
        return match reconfigure_mount_flags(&target, flags) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }

    let Some(source_display) = special.as_deref() else {
        return err(SyscallError::EINVAL);
    };
    let Some(fsname) = fstype.as_deref() else {
        return err(SyscallError::EINVAL);
    };
    if source_display.is_empty() || fsname.is_empty() {
        return err(SyscallError::EINVAL);
    }
    if fsname == "tmpfs" {
        let mount_flags = flags & mount_flag_mask();
        match object_vfs_registered_mount(
            &dir,
            &target,
            fsname,
            source_display,
            source_display,
            data.as_deref().unwrap_or(""),
            mount_flags,
        ) {
            Ok(()) => return 0,
            Err(e) => return e,
        }
    }
    if matches!(fsname, "proc" | "sysfs" | "devtmpfs") {
        let mount_flags = flags & mount_flag_mask();
        match object_vfs_registered_mount(
            &dir,
            &target,
            fsname,
            source_display,
            match fsname {
                "proc" => "/proc",
                "sysfs" => "/sys",
                "devtmpfs" => "/dev",
                _ => unreachable!(),
            },
            data.as_deref().unwrap_or(""),
            mount_flags,
        ) {
            Ok(()) => return 0,
            Err(e) => return e,
        }
    }
    if fsname == "cgroup2" {
        let spec = CgroupMountSpec::unified();
        let mount_flags = flags & mount_flag_mask();
        match object_vfs_registered_mount(
            &dir,
            &target,
            fsname,
            source_display,
            spec.source_label(),
            data.as_deref().unwrap_or(""),
            mount_flags,
        ) {
            Ok(()) => return 0,
            Err(e) => return e,
        }
    }
    if fsname == "cgroup" {
        let options = data.as_deref().unwrap_or("");
        let spec = match CgroupMountSpec::parse_legacy_options(options) {
            Ok(spec) => spec,
            Err(e) => return e,
        };
        let mount_flags = flags & mount_flag_mask();
        match object_vfs_registered_mount(
            &dir,
            &target,
            fsname,
            source_display,
            spec.source_label(),
            options,
            mount_flags,
        ) {
            Ok(()) => return 0,
            Err(e) => return e,
        }
    }
    if source_display == "/dev/root" && (flags & MS_RDONLY) == 0 && pseudo_block_is_read_only() {
        return err(SyscallError::EACCES);
    }
    let special_abs = normalize_path(&cwd, source_display);
    {
        if let Some(inode) = find_path_in_roots(&special_abs) {
            if with_ext4_inode_read(&inode, || inode.is_chrdev()) {
                return err(SyscallError::ENOTBLK);
            }
        }
    }
    if fsname != "ext4" {
        // Linux asks the filesystem registry for a concrete type and returns
        // ENODEV when no driver exists.  Never manufacture an ext4 directory
        // as a pretend superblock for an unknown filesystem.
        return err(SyscallError::ENODEV);
    }
    let source = {
        let Some(source) = block_device_source_path(source_display) else {
            return err(SyscallError::ENODEV);
        };
        source
    };
    let mount_flags = flags & mount_flag_mask();
    match object_vfs_ext4_mount(&dir, &target, source_display, &source, mount_flags) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub(crate) fn syscall_umount2_impl(special_ptr: usize, flags: usize) -> isize {
    let valid = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;
    if (flags & !valid) != 0 {
        return err(SyscallError::EINVAL);
    }
    if current_process().borrow_mut().euid != 0 {
        return err(SyscallError::EPERM);
    }
    if (flags & MNT_EXPIRE) != 0 && (flags & (MNT_FORCE | MNT_DETACH)) != 0 {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, special_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    let process = current_process();
    let cwd = process.fs_struct().cwd_display();
    let abs = normalize_path(&cwd, &path);

    if (flags & UMOUNT_NOFOLLOW) != 0 {
        let at = match resolve_at_path(AT_FDCWD, &path) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (fsuid, fsgid) = current_fsuid_gid();
        if let Ok(inode) = resolve_at_inode(&at, fsuid, fsgid, false) {
            if with_ext4_inode_read(&inode, || inode.is_symlink()) {
                return err(SyscallError::EINVAL);
            }
        }
    }

    if mount_record_for_target(&abs).is_none() {
        return if find_path_in_roots(&abs).is_some() {
            err(SyscallError::EINVAL)
        } else {
            err(SyscallError::ENOENT)
        };
    }

    if (flags & MNT_EXPIRE) != 0 {
        let updated = with_mount_namespace_mut(&current_mount_namespace(), |state| {
            let Some(idx) = state.top_mount_index_for_target(&abs) else {
                return None;
            };
            let entry = &mut state.mounts_mut()[idx];
            if entry.expire_mark_seq != Some(entry.access_seq) {
                entry.expire_mark_seq = Some(entry.access_seq);
                return Some(err(SyscallError::EAGAIN));
            }
            Some(0)
        });
        match updated {
            Some(v) if v == err(SyscallError::EAGAIN) => return v,
            Some(0) => {}
            _ => return err(SyscallError::EINVAL),
        }
    }

    if (flags & MNT_DETACH) == 0 && mount_is_busy(&abs, false) {
        return err(SyscallError::EBUSY);
    }

    let path = match resolve_object_vfs_absolute(&abs) {
        Ok(path) => path,
        Err(e) => return e,
    };
    let namespace = current_mount_namespace().lock().vfs_namespace();
    let targets = match namespace.umount_with_targets(&path, (flags & MNT_DETACH) != 0) {
        Ok((_mount, targets)) => targets,
        Err(error) => return map_vfs_error(error),
    };
    let _ = remove_object_mount_records_by_targets(&targets);
    0
}

fn proc_mounts_source_name(mount: &MountRecord) -> &str {
    if mount.fs_type == "none" && mount.source_display.starts_with('/') {
        "/dev/root"
    } else if mount.source_display.is_empty() {
        mount.source.as_str()
    } else {
        mount.source_display.as_str()
    }
}

pub(crate) fn proc_mounts_snapshot_for_namespace(ns: &MountNamespace) -> String {
    let mut mounts = {
        let state = ns.lock();
        state.top_mounts()
    };
    let root = mounts.iter().find(|mount| mount.target == "/").cloned();
    let root_source = root
        .as_ref()
        .map(proc_mounts_source_name)
        .unwrap_or("/dev/root");
    let root_fs_type = root
        .as_ref()
        .map(|mount| mount.fs_type.as_str())
        .unwrap_or("ext4");
    let root_opts = root
        .as_ref()
        .map(|mount| mount_flags_to_proc_opts(mount.flags))
        .unwrap_or_else(|| String::from("rw,relatime"));
    let mut out = alloc::format!("{root_source} / {root_fs_type} {root_opts} 0 0\n");
    mounts.sort_by(|a, b| a.target.cmp(&b.target));
    for mount in mounts {
        if mount.target == "/" {
            continue;
        }
        let mut opts = mount_flags_to_proc_opts(mount.flags);
        if mount.fs_type == "cgroup" && !mount.source_display.is_empty() {
            opts.push(',');
            opts.push_str(&mount.source_display);
        }
        let source = proc_mounts_source_name(&mount);
        out.push_str(&alloc::format!(
            "{} {} {} {} 0 0\n",
            source,
            mount.target,
            mount.fs_type,
            opts
        ));
    }
    out
}

fn mountinfo_escape(input: &str) -> String {
    let mut out = String::new();
    for byte in input.bytes() {
        match byte {
            b' ' => out.push_str("\\040"),
            b'\t' => out.push_str("\\011"),
            b'\n' => out.push_str("\\012"),
            b'\\' => out.push_str("\\134"),
            _ => out.push(byte as char),
        }
    }
    out
}

fn mountinfo_optional_fields(record: &MountRecord) -> String {
    let mut fields = Vec::new();
    match record.propagation {
        MountPropagation::Shared => {
            if let Some(id) = record.peer_group_id {
                fields.push(alloc::format!("shared:{id}"));
            }
            if let Some(id) = record.master_group_id {
                fields.push(alloc::format!("master:{id}"));
            }
        }
        MountPropagation::Slave => {
            if let Some(id) = record.master_group_id {
                fields.push(alloc::format!("master:{id}"));
            }
        }
        MountPropagation::Private | MountPropagation::Unbindable => {}
    }
    fields.join(" ")
}

fn push_mountinfo_line(
    out: &mut String,
    id: usize,
    parent_id: usize,
    dev: &str,
    root: &str,
    target: &str,
    fs_type: &str,
    source: &str,
    opts: &str,
    optional: &str,
) {
    let root = mountinfo_escape(root);
    let target = mountinfo_escape(target);
    let fs_type = mountinfo_escape(fs_type);
    let source = mountinfo_escape(source);
    let opts = mountinfo_escape(opts);
    if optional.is_empty() {
        out.push_str(&alloc::format!(
            "{id} {parent_id} {dev} {root} {target} {opts} - {fs_type} {source} {opts}\n"
        ));
    } else {
        out.push_str(&alloc::format!(
            "{id} {parent_id} {dev} {root} {target} {opts} {optional} - {fs_type} {source} {opts}\n"
        ));
    }
}

pub(crate) fn proc_mountinfo_snapshot_for_namespace(ns: &MountNamespace) -> String {
    let mut out = String::new();
    let root = {
        let state = ns.lock();
        state.mount_record_for_target("/")
    };
    let root_source = root
        .as_ref()
        .map(|mount| {
            if mount.source_display.is_empty() {
                mount.source.as_str()
            } else {
                mount.source_display.as_str()
            }
        })
        .unwrap_or("/dev/root");
    let root_fs_type = root
        .as_ref()
        .map(|mount| mount.fs_type.as_str())
        .unwrap_or("ext4");
    let root_opts = root
        .as_ref()
        .map(|mount| mount_flags_to_proc_opts(mount.flags))
        .unwrap_or_else(|| String::from("rw,relatime"));
    let root_optional = root
        .as_ref()
        .map(mountinfo_optional_fields)
        .unwrap_or_default();
    push_mountinfo_line(
        &mut out,
        1,
        0,
        "8:1",
        "/",
        "/",
        root_fs_type,
        root_source,
        &root_opts,
        &root_optional,
    );

    let mut mounts = {
        let state = ns.lock();
        state.mounts().to_vec()
    };
    mounts.sort_by(|a, b| a.target.cmp(&b.target));
    let mut idx = 0;
    for mount in &mounts {
        if mount.target == "/" {
            continue;
        }
        idx += 1;
        let opts = mount_flags_to_proc_opts(mount.flags);
        let optional = mountinfo_optional_fields(mount);
        let source = if mount.source_display.is_empty() {
            mount.source.as_str()
        } else {
            mount.source_display.as_str()
        };
        push_mountinfo_line(
            &mut out,
            100 + idx,
            1,
            &alloc::format!("0:{}", mount.event_id.max(1)),
            "/",
            &mount.target,
            &mount.fs_type,
            source,
            &opts,
            &optional,
        );
    }
    out
}

pub(crate) fn proc_mounts_snapshot() -> String {
    proc_mounts_snapshot_for_namespace(&current_mount_namespace())
}

pub(crate) fn proc_mounts_snapshot_for_process(process: &Arc<ProcessControlBlock>) -> String {
    proc_mounts_snapshot_for_namespace(&process.mount_namespace())
}

pub(crate) fn proc_mountinfo_snapshot() -> String {
    proc_mountinfo_snapshot_for_namespace(&current_mount_namespace())
}

pub(crate) fn proc_mountinfo_snapshot_for_process(process: &Arc<ProcessControlBlock>) -> String {
    proc_mountinfo_snapshot_for_namespace(&process.mount_namespace())
}

pub(crate) fn path_under_mount(abs: &str, mnt: &str) -> bool {
    if mnt == "/" {
        return true;
    }
    if abs == mnt {
        return true;
    }
    abs.starts_with(mnt) && abs.as_bytes().get(mnt.len()) == Some(&b'/')
}

pub(crate) fn final_non_empty_component(path: &str) -> Option<&str> {
    path.rsplit('/').find(|comp| !comp.is_empty())
}
