use super::{
    AT_FDCWD, Arc, BTreeMap, BTreeSet, CgroupMountSpec, File, InodeTimes, MNT_DETACH, MNT_EXPIRE,
    MNT_FORCE, MS_BIND, MS_MOVE, MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID,
    MS_NOSYMFOLLOW, MS_PRIVATE, MS_RDONLY, MS_REC, MS_REMOUNT, MS_SHARED, MS_SLAVE, MS_STRICTATIME,
    MS_UNBINDABLE, MountNamespace, MountNamespaceState, MountPropagation, MountRecord, Mutex,
    NEXT_MOUNT_EVENT_ID, NEXT_MOUNT_PEER_GROUP_ID, NEXT_MOUNT_STACK_SEQ, OSInode, Ordering,
    PID2PCB, ProcessControlBlock, PseudoDir, PseudoFile, PseudoShmFile, RtcFile, ST_NOSYMFOLLOW,
    String, SyscallError, TMPFILE_SEQ, UMOUNT_NOFOLLOW, Vec, cgroup_logical_path_for_file,
    cgroup_mount, cgroup_umount, current_fsuid_gid, current_process, current_timespec, err,
    ext4_err_to_errno, ext4_lock, find_path_in_roots, get_current_token, get_inode_times,
    inode_logical_path, inode_raw_logical_path, mount_namespace_id, normalize_path, open_pseudo,
    pseudo_block_is_read_only, read_user_cstring, resolve_at_inode, resolve_at_path,
    set_inode_times,
};
use alloc::vec;
use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref DEVICE_MOUNT_SOURCES: Mutex<BTreeMap<String, String>> =
        Mutex::new(BTreeMap::new());
    pub(crate) static ref TMPFS_REATTACH_SOURCES: Mutex<BTreeMap<String, String>> =
        Mutex::new(BTreeMap::new());
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

pub(crate) fn translate_mount_abs(abs: &str) -> String {
    let state = current_mount_namespace();
    let state = state.lock();
    state.translate_mount_abs(abs)
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
    let process = current_process();
    process.borrow_mut().cwd.clone()
}

pub(crate) fn logical_path_for_inode(inode: &Arc<ext4_fs::Inode>) -> Option<String> {
    inode_logical_path(inode)
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
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return String::from(pdir.path());
    }
    crate::fs::proc_readlink(&proc_self_fd_path(fd)).unwrap_or_else(|| String::from(cwd_fallback))
}

pub(crate) fn mount_file_logical_path(file: &Arc<dyn File + Send + Sync>) -> Option<String> {
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Some(String::from(pdir.path()));
    }
    if let Some(path) = cgroup_logical_path_for_file(file) {
        return Some(path);
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
    if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
        return Some(String::from("/dev/shm"));
    }
    let os_inode = file.as_any().downcast_ref::<OSInode>()?;
    inode_raw_logical_path(&os_inode.ext4_inode())
}

pub(crate) fn pseudo_abs_for_ext4_dirfd(base: &Arc<ext4_fs::Inode>, path: &str) -> Option<String> {
    let logical_base = logical_path_for_inode(base)?;
    let abs = normalize_path(&logical_base, path);
    open_pseudo(&abs).map(|_| abs)
}

pub(crate) fn mount_is_busy(target: &str, writable_only: bool) -> bool {
    let self_bind_root = mount_record_for_target(target)
        .map(|record| record.source == target)
        .unwrap_or(false);
    let current_ns_id = current_process().mount_namespace_id();
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let (cwd, root, is_zombie, namespace, files) = match process.try_borrow_mut() {
            Some(inner) => (
                inner.cwd.clone(),
                inner.root.clone(),
                inner.is_zombie,
                Arc::clone(&inner.mnt_ns),
                Arc::clone(&inner.files),
            ),
            None => continue,
        };
        if is_zombie {
            continue;
        }
        if mount_namespace_id(&namespace) != current_ns_id {
            continue;
        }
        let cwd_busy = path_under_mount(&cwd, target) && !(self_bind_root && cwd == target);
        let root_busy = path_under_mount(&root, target) && !(self_bind_root && root == target);
        if cwd_busy || root_busy {
            return true;
        }
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        for (_fd, file) in files.lock().iter_files_snapshot() {
            if writable_only && !file.writable() {
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

pub(crate) fn ensure_mount_source_root() -> Result<Arc<ext4_fs::Inode>, isize> {
    let _ext4_guard = ext4_lock();
    let root = crate::fs::root_inode_for_path("/");
    if let Some(dir) = root.find(".ltp_mounts") {
        if dir.is_dir() {
            return Ok(dir);
        }
        return Err(err(SyscallError::ENOTDIR));
    }
    match root.create_dir(".ltp_mounts") {
        Ok(dir) => {
            dir.set_uid_gid(0, 0);
            dir.set_mode(0o700);
            Ok(dir)
        }
        Err(e) => Err(ext4_err_to_errno(e)),
    }
}

pub(crate) fn source_for_device_mount(key: &str) -> Result<String, isize> {
    let fresh_instance = key.starts_with("tmpfs:");
    if fresh_instance {
        if let Some(path) = TMPFS_REATTACH_SOURCES.lock().remove(key) {
            return Ok(path);
        }
    } else if let Some(path) = DEVICE_MOUNT_SOURCES.lock().get(key).cloned() {
        return Ok(path);
    }
    let root = ensure_mount_source_root()?;
    loop {
        let id = TMPFILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = alloc::format!("mnt.{}", id);
        let _ext4_guard = ext4_lock();
        if root.find(&name).is_some() {
            continue;
        }
        match root.create_dir(&name) {
            Ok(dir) => {
                dir.set_uid_gid(0, 0);
                if fresh_instance {
                    // Linux tmpfs defaults its root to 1777, so unprivileged
                    // tasks can traverse a freshly mounted tmpfs instance.
                    dir.set_mode(0o1777);
                } else {
                    dir.set_mode(0o755);
                }
                let path = alloc::format!("/.ltp_mounts/{}", name);
                if !fresh_instance {
                    DEVICE_MOUNT_SOURCES
                        .lock()
                        .insert(String::from(key), path.clone());
                }
                return Ok(path);
            }
            Err(e) => return Err(ext4_err_to_errno(e)),
        }
    }
}

pub(crate) fn target_dir_exists(abs: &str) -> Result<(), isize> {
    if let Some(node) = open_pseudo(abs) {
        if node.as_any().downcast_ref::<PseudoDir>().is_some() {
            return Ok(());
        }
        return Err(err(SyscallError::ENOTDIR));
    }
    let translated = translate_mount_abs(abs);
    let _ext4_guard = ext4_lock();
    let inode = find_path_in_roots(&translated).ok_or_else(|| err(SyscallError::ENOENT))?;
    if !inode.is_dir() {
        return Err(err(SyscallError::ENOTDIR));
    }
    Ok(())
}

fn bind_target_matches_source_kind(abs: &str, source_is_dir: bool) -> Result<(), isize> {
    if let Some(node) = open_pseudo(abs) {
        let target_is_dir = node.as_any().downcast_ref::<PseudoDir>().is_some();
        return if target_is_dir == source_is_dir {
            Ok(())
        } else {
            Err(err(SyscallError::ENOTDIR))
        };
    }
    let translated = translate_mount_abs(abs);
    let _ext4_guard = ext4_lock();
    let inode = find_path_in_roots(&translated).ok_or_else(|| err(SyscallError::ENOENT))?;
    if inode.is_dir() != source_is_dir {
        return Err(err(SyscallError::ENOTDIR));
    }
    Ok(())
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

fn bind_should_clone_subtree(recursive_bind: bool, source_mount: Option<&MountRecord>) -> bool {
    recursive_bind
        || source_mount
            .is_some_and(|mount| mount.peer_group_id.is_some() || mount.master_group_id.is_some())
}

fn collect_bind_subtree_mount_clones(
    source_display: &str,
    excluded_source_prefixes: &[String],
    recursive_bind: bool,
    source_mount: Option<&MountRecord>,
) -> Vec<MountSubtreeClone> {
    if bind_should_clone_subtree(recursive_bind, source_mount) {
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

pub(crate) fn create_mount_record_with_propagation(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
) {
    let Some(base) = mount_lookup_for_abs(target) else {
        push_mount_record(
            target,
            source,
            source_display,
            fs_type,
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
            push_mount_to_destination(&dest, source, source_display, fs_type, flags, event_id);
        }
        if !created_any {
            push_mount_record(
                target,
                source,
                source_display,
                fs_type,
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
        flags,
        propagation,
        peer_group_id,
        master_group_id,
        next_mount_event_id(),
    );
    sync_mount_record_rofs(target);
}

pub(crate) fn create_bind_mount_record_with_propagation(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
    recursive_bind: bool,
) {
    let source_mount = mount_lookup_for_abs(source_display);
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
            let subtree_clones = collect_bind_subtree_mount_clones(
                source_display,
                &excluded,
                recursive_bind,
                source_mount.as_ref(),
            );
            let event_peer_group = source_peer_group.unwrap_or_else(next_mount_peer_group_id);
            let origin_master_group = source_master_group;
            let mut created_any = false;
            for dest in
                shared_group_destinations(&base, target, event_peer_group, origin_master_group)
            {
                created_any = true;
                push_mount_to_destination(&dest, source, source_display, fs_type, flags, event_id);
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
        let subtree_clones = collect_bind_subtree_mount_clones(
            source_display,
            &excluded,
            recursive_bind,
            source_mount.as_ref(),
        );
        push_mount_record(
            target,
            source,
            source_display,
            fs_type,
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
        let subtree_clones = collect_bind_subtree_mount_clones(
            source_display,
            &excluded,
            recursive_bind,
            source_mount.as_ref(),
        );
        push_mount_record(
            target,
            source,
            source_display,
            fs_type,
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
    let subtree_clones = collect_bind_subtree_mount_clones(
        source_display,
        &excluded,
        recursive_bind,
        source_mount.as_ref(),
    );
    push_mount_record(
        target,
        source,
        source_display,
        fs_type,
        flags,
        MountPropagation::Private,
        None,
        None,
        event_id,
    );
    sync_mount_record_rofs(target);
    clone_subtree_mount_records_for_bind(target, source_display, event_id, &subtree_clones);
}

fn downstream_unmount_peer_groups(
    start_peer_group: usize,
    namespaces: &[MountNamespace],
) -> BTreeSet<usize> {
    let mut groups = BTreeSet::new();
    let mut pending = Vec::new();
    pending.push(start_peer_group);
    while let Some(group) = pending.pop() {
        if !groups.insert(group) {
            continue;
        }
        for ns in namespaces {
            for top in top_mounts_for_namespace(ns) {
                if top.master_group_id != Some(group) {
                    continue;
                }
                if let Some(child_peer_group) = top.peer_group_id {
                    pending.push(child_peer_group);
                }
            }
        }
    }
    groups
}

fn mount_record_in_unmount_domain(record: &MountRecord, peer_groups: &BTreeSet<usize>) -> bool {
    if record
        .peer_group_id
        .is_some_and(|peer_group| peer_groups.contains(&peer_group))
    {
        return true;
    }
    record.peer_group_id.is_none()
        && record
            .master_group_id
            .is_some_and(|master_group| peer_groups.contains(&master_group))
}

pub(crate) fn remove_top_mount_records_by_event(
    event_id: usize,
    peer_group_id: usize,
    origin_target: &str,
    origin_source: &str,
    origin_source_display: &str,
) -> usize {
    let namespaces = collect_live_mount_namespaces();
    let peer_groups = downstream_unmount_peer_groups(peer_group_id, &namespaces);
    let mut removed = 0usize;
    for ns in namespaces {
        let mut affected_targets: BTreeMap<String, usize> = BTreeMap::new();
        let removed_in_ns = with_mount_namespace_mut(&ns, |state| {
            let mut remove_keys = BTreeSet::new();
            loop {
                let before = remove_keys.len();
                for record in state.mounts() {
                    if remove_keys.contains(&(record.target.clone(), record.stack_seq)) {
                        continue;
                    }
                    let covered = state.mounts().iter().any(|other| {
                        other.target == record.target
                            && other.stack_seq > record.stack_seq
                            && !remove_keys.contains(&(other.target.clone(), other.stack_seq))
                    });
                    let same_event_top = record.event_id == event_id && !covered;
                    let rewritten_clone_source = origin_source_display == origin_target
                        && origin_source != origin_target
                        && record.source == origin_source;
                    let covered_peer = record
                        .peer_group_id
                        .is_some_and(|peer_group| peer_groups.contains(&peer_group))
                        && record.target != origin_target
                        && !path_under_mount(origin_target, &record.target)
                        && (record.source_display == origin_source_display
                            || rewritten_clone_source)
                        && covered;
                    if !(same_event_top && mount_record_in_unmount_domain(record, &peer_groups))
                        && !covered_peer
                    {
                        continue;
                    }
                    affected_targets
                        .entry(record.target.clone())
                        .and_modify(|stack_seq| *stack_seq = (*stack_seq).max(record.stack_seq))
                        .or_insert(record.stack_seq);
                    remove_keys.insert((record.target.clone(), record.stack_seq));
                }
                if remove_keys.len() == before {
                    break;
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
                    record.stack_seq > *stack_seq
                        && path_strictly_under_mount(&record.target, target)
                }) {
                    affected_targets.insert(record.target.clone(), record.stack_seq);
                    remove_keys.insert((record.target.clone(), record.stack_seq));
                }
            }
            let before = state.mounts().len();
            state
                .mounts_mut()
                .retain(|record| !remove_keys.contains(&(record.target.clone(), record.stack_seq)));
            for target in affected_targets.keys() {
                state.remove_bound_file(target);
            }
            before.saturating_sub(state.mounts().len())
        });
        if removed_in_ns == 0 {
            continue;
        }
        for target in affected_targets.keys() {
            sync_mount_record_rofs_in(&ns, &target);
        }
        removed = removed.saturating_add(removed_in_ns);
    }
    removed
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
        if before != state.mounts().len() {
            for target in affected_targets.keys() {
                state.remove_bound_file(target);
            }
        }
        before.saturating_sub(state.mounts().len())
    });
    if removed != 0 {
        for target in affected_targets.keys() {
            sync_mount_record_rofs_in(ns, &target);
        }
    }
    removed
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
    let mut changed = false;
    with_mount_namespace_mut(&current_mount_namespace(), |state| {
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
        for record in state.mounts_mut().iter_mut() {
            if !apply_keys.contains(&(record.target.clone(), record.stack_seq)) {
                continue;
            }
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
            changed = true;
        }
    });
    if !changed {
        target_dir_exists(target)?;
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
    let cwd = { process.borrow_mut().cwd.clone() };
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

        if let Some(source_file) = open_pseudo(&source_abs) {
            if source_file.as_any().downcast_ref::<PseudoDir>().is_none() {
                if let Err(e) = bind_target_matches_source_kind(&target, false) {
                    return e;
                }
                let fsname = fstype.as_deref().unwrap_or("none");
                let base_flags = mount_lookup_for_abs(&source_abs)
                    .map(|m| m.flags)
                    .unwrap_or(0);
                let bind_flags = (base_flags & mount_flag_mask()) | (flags & mount_flag_mask());
                create_bind_mount_record_with_propagation(
                    &target,
                    &source_abs,
                    &source_abs,
                    fsname,
                    bind_flags,
                    (flags & MS_REC) != 0,
                );
                with_mount_namespace_mut(&current_mount_namespace(), |state| {
                    state.bind_file(&target, Arc::clone(&source_file));
                });
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
        }

        let source = translate_mount_abs(&source_abs);
        let source_is_dir = {
            let _ext4_guard = ext4_lock();
            let Some(source_inode) = find_path_in_roots(&source) else {
                return err(SyscallError::ENOENT);
            };
            source_inode.is_dir()
        };
        if let Err(e) = bind_target_matches_source_kind(&target, source_is_dir) {
            return e;
        }
        if !source_is_dir {
            return err(SyscallError::ENOTDIR);
        }
        let fsname = fstype.as_deref().unwrap_or("none");
        let base_flags = mount_lookup_for_abs(&source_abs)
            .map(|m| m.flags)
            .unwrap_or(0);
        let bind_flags = (base_flags & mount_flag_mask()) | (flags & mount_flag_mask());
        create_bind_mount_record_with_propagation(
            &target,
            &source,
            &source_abs,
            fsname,
            bind_flags,
            (flags & MS_REC) != 0,
        );
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
        if !move_mount_subtree_with_propagation(
            &old_target,
            &target,
            dest_base,
            stack_on_existing_target,
        ) {
            return err(SyscallError::EINVAL);
        }
        sync_rofs_mount_flag(&old_target, 0);
        sync_rofs_mount_flag(&target, old_record.flags);
        return 0;
    }

    if (flags & MS_REMOUNT) != 0 {
        let Some(record) = mount_record_for_target(&target) else {
            return err(SyscallError::EINVAL);
        };
        let new_flags = flags & mount_flag_mask();
        if (new_flags & MS_RDONLY) != 0 && mount_is_busy(&target, true) {
            return err(SyscallError::EBUSY);
        }
        let _ = update_mount_record_flags(&target, new_flags);
        sync_rofs_mount_flag(&target, new_flags);
        if record.source_display == "/dev/root"
            && (new_flags & MS_RDONLY) == 0
            && pseudo_block_is_read_only()
        {
            return err(SyscallError::EACCES);
        }
        return 0;
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
    if mount_record_for_target(&target).is_some() {
        return err(SyscallError::EBUSY);
    }
    if fsname == "cgroup2" {
        let spec = CgroupMountSpec::unified();
        let rc = cgroup_mount(&target, &spec);
        if rc != 0 {
            return rc;
        }
        create_mount_record_with_propagation(
            &target,
            &target,
            "cgroup2",
            "cgroup2",
            flags & mount_flag_mask(),
        );
        return 0;
    }
    if fsname == "cgroup" {
        let options = data.as_deref().unwrap_or("");
        let spec = match CgroupMountSpec::parse_legacy_options(options) {
            Ok(spec) => spec,
            Err(e) => return e,
        };
        let rc = cgroup_mount(&target, &spec);
        if rc != 0 {
            return rc;
        }
        create_mount_record_with_propagation(
            &target,
            &target,
            spec.source_label(),
            "cgroup",
            flags & mount_flag_mask(),
        );
        return 0;
    }
    if source_display == "/dev/root" && (flags & MS_RDONLY) == 0 && pseudo_block_is_read_only() {
        return err(SyscallError::EACCES);
    }
    let special_abs = normalize_path(&cwd, source_display);
    {
        let _ext4_guard = ext4_lock();
        if let Some(inode) = find_path_in_roots(&special_abs) {
            if inode.is_chrdev() {
                return err(SyscallError::ENOTBLK);
            }
        }
    }
    let key = alloc::format!("{}:{}", fsname, source_display);
    let source = match source_for_device_mount(&key) {
        Ok(v) => v,
        Err(e) => return e,
    };
    create_mount_record_with_propagation(
        &target,
        &source,
        source_display,
        fsname,
        flags & mount_flag_mask(),
    );
    0
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
    let cwd = { process.borrow_mut().cwd.clone() };
    let abs = normalize_path(&cwd, &path);

    if (flags & UMOUNT_NOFOLLOW) != 0 {
        let at = match resolve_at_path(AT_FDCWD, &path) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (fsuid, fsgid) = current_fsuid_gid();
        let _ext4_guard = ext4_lock();
        if let Ok(inode) = resolve_at_inode(&at, fsuid, fsgid, false) {
            if inode.is_symlink() {
                return err(SyscallError::EINVAL);
            }
        }
    }

    let Some(record) = mount_record_for_target(&abs) else {
        let _ext4_guard = ext4_lock();
        return if find_path_in_roots(&abs).is_some() {
            err(SyscallError::EINVAL)
        } else {
            err(SyscallError::ENOENT)
        };
    };

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

    if (flags & MNT_DETACH) != 0 && record.fs_type == "tmpfs" {
        let key = alloc::format!("{}:{}", record.fs_type, record.source_display);
        TMPFS_REATTACH_SOURCES
            .lock()
            .insert(key, record.source.clone());
    }
    if record.fs_type == "cgroup2" || record.fs_type == "cgroup" {
        let _ = cgroup_umount(&abs);
    }
    if let Some(peer_group_id) = record.peer_group_id {
        let _ = remove_top_mount_records_by_event(
            record.event_id,
            peer_group_id,
            &record.target,
            &record.source,
            &record.source_display,
        );
    } else {
        let _ = remove_mount_record_by_stack(
            &current_mount_namespace(),
            &record.target,
            record.stack_seq,
        );
    }
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

pub(crate) fn statfs_mount_flags_for_abs(abs: &str) -> i64 {
    mount_flags_to_statfs(mount_flags_for_abs(abs))
}

pub(crate) fn register_rofs_mount(abs: &str) {
    let ns = current_mount_namespace();
    with_mount_namespace_mut(&ns, |state| {
        let mounts = state.rofs_mounts_mut();
        if !mounts.iter().any(|m| m == abs) {
            mounts.push(String::from(abs));
        }
    });
    let _ = update_mount_record_flags(abs, mount_flags_for_abs(abs) | MS_RDONLY);
}

pub(crate) fn unregister_rofs_mount(abs: &str) {
    with_mount_namespace_mut(&current_mount_namespace(), |state| {
        state.rofs_mounts_mut().retain(|m| m != abs);
    });
    if let Some(mut record) = mount_lookup_for_abs(abs) {
        if record.target == abs {
            record.flags &= !MS_RDONLY;
            let _ = update_mount_record_flags(abs, record.flags);
        }
    }
}

pub(crate) fn path_is_rofs(abs: &str) -> bool {
    if (mount_flags_for_abs(abs) & MS_RDONLY) != 0 {
        return true;
    }
    let ns = current_mount_namespace();
    let state = ns.lock();
    state.rofs_mount_covers(abs)
}

pub(crate) fn path_is_nodev(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NODEV) != 0
}

pub(crate) fn path_is_noexec(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NOEXEC) != 0
}

pub(crate) fn path_is_nosymfollow(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NOSYMFOLLOW) != 0
}

pub(crate) fn inode_is_rofs_mount_root(inode: &Arc<ext4_fs::Inode>) -> bool {
    let mounts: Vec<String> = {
        let ns = current_mount_namespace();
        let state = ns.lock();
        state.rofs_mounts().to_vec()
    };
    for mount in mounts {
        let Some(mount_inode) = find_path_in_roots(&translate_mount_abs(&mount)) else {
            continue;
        };
        if mount_inode.device_id() == inode.device_id()
            && mount_inode.inode_num() == inode.inode_num()
        {
            return true;
        }
    }
    false
}

pub(crate) fn path_is_mount_point(abs: &str) -> bool {
    if mount_record_for_target(abs).is_some() {
        return true;
    }
    let ns = current_mount_namespace();
    let state = ns.lock();
    state.rofs_mount_contains(abs)
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

pub(crate) fn rofs_mount_root_for_abs(abs: &str) -> Option<String> {
    if let Some(mount) = mount_lookup_for_abs(abs) {
        return Some(mount.target);
    }
    let ns = current_mount_namespace();
    let state = ns.lock();
    state.rofs_mount_root_for_path(abs)
}

pub(crate) fn hardlink_cross_mount(old_abs: &str, new_abs: &str) -> bool {
    match (
        rofs_mount_root_for_abs(old_abs),
        rofs_mount_root_for_abs(new_abs),
    ) {
        (None, None) => false,
        (Some(a), Some(b)) => a != b,
        _ => true,
    }
}
