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
    inode_logical_path, mount_namespace_id, normalize_path, open_pseudo, pseudo_block_is_read_only,
    read_user_cstring, resolve_at_inode, resolve_at_path, set_inode_times,
};
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
        state.push_record(MountRecord {
            target: String::from(target),
            source: String::from(source),
            source_display: String::from(source_display),
            fs_type: String::from(fs_type),
            flags,
            stack_seq: next_mount_stack_seq(),
            event_id,
            propagation,
            peer_group_id,
            master_group_id,
            access_seq: 0,
            expire_mark_seq: None,
        });
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

pub(crate) fn move_mount_record_target_in(
    ns: &MountNamespace,
    old_target: &str,
    new_target: &str,
) -> bool {
    with_mount_namespace_mut(ns, |state| {
        state.move_top_mount_target(old_target, new_target)
    })
}

pub(crate) fn move_mount_record_target(old_target: &str, new_target: &str) -> bool {
    move_mount_record_target_in(&current_mount_namespace(), old_target, new_target)
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
    logical_path_for_inode(&os_inode.ext4_inode())
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
}

pub(crate) fn inherited_mount_propagation(
    target: &str,
) -> (MountPropagation, Option<usize>, Option<usize>) {
    let Some(base) = mount_lookup_for_abs(target) else {
        return (MountPropagation::Private, None, None);
    };
    match base.propagation {
        MountPropagation::Private => (MountPropagation::Private, None, None),
        MountPropagation::Shared => (MountPropagation::Shared, base.peer_group_id, None),
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

pub(crate) fn shared_group_destinations(
    base: &MountRecord,
    target: &str,
) -> Vec<MountPropagationDestination> {
    let Some(peer_group) = base.peer_group_id else {
        return Vec::new();
    };
    let suffix = mount_target_suffix(&base.target, target);
    let namespaces = collect_live_mount_namespaces();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for ns in namespaces {
        let ns_id = mount_namespace_id(&ns);
        for top in top_mounts_for_namespace(&ns) {
            let propagation = if top.propagation == MountPropagation::Shared
                && top.peer_group_id == Some(peer_group)
            {
                MountPropagation::Shared
            } else if top.propagation == MountPropagation::Slave
                && top.master_group_id == Some(peer_group)
            {
                MountPropagation::Slave
            } else {
                continue;
            };
            let dest_target = if suffix.is_empty() {
                top.target.clone()
            } else {
                normalize_path(&top.target, &suffix)
            };
            let key = (
                ns_id,
                dest_target.clone(),
                match propagation {
                    MountPropagation::Shared => 0u8,
                    MountPropagation::Slave => 1u8,
                    MountPropagation::Private => 2u8,
                    MountPropagation::Unbindable => 3u8,
                },
            );
            if !seen.insert(key) {
                continue;
            }
            out.push(MountPropagationDestination {
                ns: Arc::clone(&ns),
                target: dest_target,
                propagation,
            });
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
    shared_peer_group: Option<usize>,
    slave_master_group: Option<usize>,
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
                shared_peer_group,
                None,
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
                slave_master_group,
                event_id,
            );
        }
        MountPropagation::Private | MountPropagation::Unbindable => {}
    }
    sync_mount_record_rofs_in(&dest.ns, &dest.target);
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

    if base.propagation == MountPropagation::Shared {
        let event_id = next_mount_event_id();
        let new_peer_group = next_mount_peer_group_id();
        let mut created_any = false;
        for dest in shared_group_destinations(&base, target) {
            created_any = true;
            match dest.propagation {
                MountPropagation::Shared => push_mount_to_destination(
                    &dest,
                    source,
                    source_display,
                    fs_type,
                    flags,
                    event_id,
                    Some(new_peer_group),
                    None,
                ),
                MountPropagation::Slave => push_mount_to_destination(
                    &dest,
                    source,
                    source_display,
                    fs_type,
                    flags,
                    event_id,
                    None,
                    Some(new_peer_group),
                ),
                MountPropagation::Private | MountPropagation::Unbindable => {}
            }
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
) {
    if let Some(source_mount) = mount_record_for_target(source_display) {
        if source_mount.propagation == MountPropagation::Shared {
            let source_peer_group = source_mount
                .peer_group_id
                .unwrap_or_else(next_mount_peer_group_id);
            let event_id = next_mount_event_id();

            if let Some(base) = mount_lookup_for_abs(target) {
                if base.propagation == MountPropagation::Shared {
                    let mut created_any = false;
                    for dest in shared_group_destinations(&base, target) {
                        created_any = true;
                        match dest.propagation {
                            MountPropagation::Shared => push_mount_to_destination(
                                &dest,
                                source,
                                source_display,
                                fs_type,
                                flags,
                                event_id,
                                Some(source_peer_group),
                                None,
                            ),
                            MountPropagation::Slave => push_mount_to_destination(
                                &dest,
                                source,
                                source_display,
                                fs_type,
                                flags,
                                event_id,
                                None,
                                Some(source_peer_group),
                            ),
                            MountPropagation::Private | MountPropagation::Unbindable => {}
                        }
                    }
                    if !created_any {
                        push_mount_record(
                            target,
                            source,
                            source_display,
                            fs_type,
                            flags,
                            MountPropagation::Shared,
                            Some(source_peer_group),
                            None,
                            event_id,
                        );
                        sync_mount_record_rofs(target);
                    }
                    return;
                }
            }

            push_mount_record(
                target,
                source,
                source_display,
                fs_type,
                flags,
                MountPropagation::Shared,
                Some(source_peer_group),
                None,
                event_id,
            );
            sync_mount_record_rofs(target);
            return;
        }
    }

    if let Some(base) = mount_lookup_for_abs(target) {
        if base.propagation == MountPropagation::Shared {
            let event_id = next_mount_event_id();
            let new_peer_group = next_mount_peer_group_id();
            let mut created_any = false;
            for dest in shared_group_destinations(&base, target) {
                created_any = true;
                match dest.propagation {
                    MountPropagation::Shared => push_mount_to_destination(
                        &dest,
                        source,
                        source_display,
                        fs_type,
                        flags,
                        event_id,
                        Some(new_peer_group),
                        None,
                    ),
                    MountPropagation::Slave => push_mount_to_destination(
                        &dest,
                        source,
                        source_display,
                        fs_type,
                        flags,
                        event_id,
                        None,
                        Some(new_peer_group),
                    ),
                    MountPropagation::Private | MountPropagation::Unbindable => {}
                }
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
    }

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
}

pub(crate) fn remove_mount_records_by_event(event_id: usize) -> usize {
    let namespaces = collect_live_mount_namespaces();
    let mut removed = 0usize;
    for ns in namespaces {
        let mut affected_targets = BTreeSet::new();
        let removed_in_ns = with_mount_namespace_mut(&ns, |state| {
            let before = state.mounts().len();
            state.mounts_mut().retain(|record| {
                if record.event_id == event_id {
                    affected_targets.insert(record.target.clone());
                    return false;
                }
                true
            });
            before.saturating_sub(state.mounts().len())
        });
        if removed_in_ns == 0 {
            continue;
        }
        for target in affected_targets {
            sync_mount_record_rofs_in(&ns, &target);
        }
        removed = removed.saturating_add(removed_in_ns);
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
        for record in state.mounts_mut().iter_mut() {
            let applies = if recursive {
                path_under_mount(&record.target, target)
            } else {
                record.target == target
            };
            if !applies {
                continue;
            }
            match propagation {
                MountPropagation::Shared => {
                    let peer_group = record
                        .peer_group_id
                        .unwrap_or_else(next_mount_peer_group_id);
                    record.propagation = MountPropagation::Shared;
                    record.peer_group_id = Some(peer_group);
                    record.master_group_id = None;
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
    if (flags & propagation_flags) != 0 {
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
        if mount_record_for_target(&target).is_some() {
            return err(SyscallError::EBUSY);
        }
        if !move_mount_record_target(&old_target, &target) {
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

    if (flags & MS_BIND) != 0 {
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
        let source = translate_mount_abs(&source_abs);
        let _ext4_guard = ext4_lock();
        if find_path_in_roots(&source).is_none() {
            return err(SyscallError::ENOENT);
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
        );
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
    let _ = remove_mount_records_by_event(record.event_id);
    0
}

pub(crate) fn proc_mounts_snapshot_for_namespace(ns: &MountNamespace) -> String {
    let mut out = String::from("/dev/root / ext4 rw,relatime 0 0\n");
    let mut mounts = {
        let state = ns.lock();
        state.mounts().to_vec()
    };
    mounts.sort_by(|a, b| a.target.cmp(&b.target));
    for mount in mounts {
        let mut opts = mount_flags_to_proc_opts(mount.flags);
        if mount.fs_type == "cgroup" && !mount.source_display.is_empty() {
            opts.push(',');
            opts.push_str(&mount.source_display);
        }
        out.push_str(&alloc::format!(
            "{} {} {} {} 0 0\n",
            mount.source_display,
            mount.target,
            mount.fs_type,
            opts
        ));
    }
    out
}

pub(crate) fn proc_mounts_snapshot() -> String {
    proc_mounts_snapshot_for_namespace(&current_mount_namespace())
}

pub(crate) fn proc_mounts_snapshot_for_process(process: &Arc<ProcessControlBlock>) -> String {
    proc_mounts_snapshot_for_namespace(&process.mount_namespace())
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
