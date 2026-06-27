use super::{
    BTreeSet, OSInode, PID2PCB, ProcessControlBlock, SyscallError, Vec, current_process, err,
};

/// Converts ext4 backend errors into Linux-style `errno` values.
pub(crate) fn ext4_err_to_errno(e: ext4_fs::Ext4Error) -> isize {
    match e {
        ext4_fs::Ext4Error::NotADirectory => err(SyscallError::ENOTDIR),
        ext4_fs::Ext4Error::NotAFile => err(SyscallError::EISDIR),
        ext4_fs::Ext4Error::AlreadyExists => err(SyscallError::EEXIST),
        ext4_fs::Ext4Error::NotFound => err(SyscallError::ENOENT),
        ext4_fs::Ext4Error::NoSpace => err(SyscallError::ENOSPC),
        ext4_fs::Ext4Error::NameTooLong => err(SyscallError::ENAMETOOLONG),
        ext4_fs::Ext4Error::Unsupported => err(SyscallError::EOPNOTSUPP),
        ext4_fs::Ext4Error::InvalidInput => err(SyscallError::EINVAL),
    }
}

/// Returns the calling task's real uid/gid pair.
pub(crate) fn current_real_uid_gid() -> (u32, u32) {
    crate::syscall::misc::current_real_uid_gid()
}

/// Returns the calling task's effective uid/gid pair.
pub(crate) fn current_effective_uid_gid() -> (u32, u32) {
    crate::syscall::misc::current_effective_uid_gid()
}

/// Returns the calling task's filesystem uid/gid pair.
pub(crate) fn current_fsuid_gid() -> (u32, u32) {
    crate::syscall::misc::current_fsuid_gid()
}

/// Checks whether the current process belongs to `gid`, including supplementary groups.
pub(crate) fn current_in_group(gid: u32) -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    gid == inner.fsgid || inner.supplementary_gids.iter().any(|g| *g == gid)
}

/// Converts Linux's `-1`/`UINT_MAX` sentinel into "leave unchanged".
pub(crate) fn parse_chown_id(id: usize) -> Option<u32> {
    if id == usize::MAX || id == u32::MAX as usize {
        None
    } else {
        Some(id as u32)
    }
}

/// Clears setuid/setgid bits after ownership changes when Linux would do so.
pub(crate) fn maybe_clear_suid_sgid_after_chown(inode: &ext4_fs::Inode, touched_owner: bool) {
    if !touched_owner || !inode.is_file() {
        return;
    }
    let mut mode = inode.mode();
    mode &= !0o4000; // Clear setuid on regular files after chown/chgrp.
    if (mode & 0o0010) != 0 {
        // Linux preserves setgid on non-group-executable regular files.
        mode &= !0o2000;
    }
    inode.set_mode(mode);
}

/// Applies `chown`/`chgrp` semantics to an inode using current credentials.
pub(crate) fn apply_chown_to_inode(inode: &ext4_fs::Inode, uid: usize, gid: usize) -> isize {
    let uid_req = parse_chown_id(uid);
    let gid_req = parse_chown_id(gid);
    let (euid, _egid) = current_effective_uid_gid();

    if euid != 0 {
        if inode.uid() != euid {
            return err(SyscallError::EPERM);
        }
        if let Some(new_uid) = uid_req {
            // Unprivileged callers cannot change file owner.
            if new_uid != inode.uid() {
                return err(SyscallError::EPERM);
            }
        }
        if let Some(new_gid) = gid_req {
            // Unprivileged owner may only chgrp into one of its groups.
            if new_gid != inode.gid() && !current_in_group(new_gid) {
                return err(SyscallError::EPERM);
            }
        }
    }

    let new_uid = uid_req.unwrap_or_else(|| inode.uid());
    let new_gid = gid_req.unwrap_or_else(|| inode.gid());
    inode.set_uid_gid(new_uid, new_gid);
    maybe_clear_suid_sgid_after_chown(inode, uid_req.is_some() || gid_req.is_some());
    0
}

/// Returns `true` when `euid` is root (0) or matches the inode owner.
pub(crate) fn is_privileged_or_owner(euid: u32, inode: &ext4_fs::Inode) -> bool {
    euid == 0 || euid == inode.uid()
}

/// Evaluates rwx permission bits for an explicit uid/gid credential pair.
pub(crate) fn inode_mode_allows_uid_gid(
    inode: &ext4_fs::Inode,
    mask: usize,
    uid: u32,
    gid: u32,
) -> bool {
    if mask == 0 {
        return true;
    }
    let mode = inode.mode() as usize;

    if uid == 0 {
        // Root bypasses read/write checks, but still needs execute bits for files.
        if (mask & 1) != 0 && !inode.is_dir() && (mode & 0o111) == 0 {
            return false;
        }
        return true;
    }

    let perm = if uid == inode.uid() {
        (mode >> 6) & 0o7
    } else if gid == inode.gid() {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    if (mask & 4) != 0 && (perm & 0o4) == 0 {
        return false;
    }
    if (mask & 2) != 0 && (perm & 0o2) == 0 {
        return false;
    }
    if (mask & 1) != 0 && (perm & 0o1) == 0 {
        return false;
    }
    true
}

/// Evaluates rwx permission bits using the caller's fsuid/fsgid.
pub(crate) fn inode_mode_allows(inode: &ext4_fs::Inode, mask: usize) -> bool {
    let (uid, gid) = current_fsuid_gid();
    inode_mode_allows_uid_gid(inode, mask, uid, gid)
}

/// Applies the current process umask to a newly created inode mode.
pub(crate) fn apply_umask(mode: usize) -> u16 {
    let umask = crate::syscall::misc::current_umask() as u16;
    let perm = (mode as u16) & 0o777;
    let special = (mode as u16) & 0o7000;
    special | (perm & !umask)
}

/// Returns whether a parent directory forces gid inheritance via `S_ISGID`.
pub(crate) fn parent_forces_gid_inherit(parent: &ext4_fs::Inode) -> bool {
    parent.is_dir() && (parent.mode() & 0o2000) != 0
}

/// Selects the gid that should be assigned to a freshly created inode.
pub(crate) fn gid_for_created_inode(parent: Option<&ext4_fs::Inode>, fallback_gid: u32) -> u32 {
    match parent {
        Some(dir) if parent_forces_gid_inherit(dir) => dir.gid(),
        _ => fallback_gid,
    }
}

/// Normalizes mode bits for a newly created regular file after gid checks.
pub(crate) fn mode_for_created_file(mut mode: u16, gid: u32) -> u16 {
    // Linux clears S_ISGID on new regular files when caller is unprivileged
    // and outside the target group.
    if (mode & 0o2000) != 0 {
        let (euid, _) = current_effective_uid_gid();
        if euid != 0 && !current_in_group(gid) {
            mode &= !0o2000;
        }
    }
    mode
}

/// Extracts the Linux major number from an encoded device id.
pub(crate) fn linux_dev_major(dev: u64) -> u32 {
    ((((dev >> 8) & 0x0fff) | ((dev >> 32) & 0xffff_f000)) & 0xffff_ffff) as u32
}

/// Extracts the Linux minor number from an encoded device id.
pub(crate) fn linux_dev_minor(dev: u64) -> u32 {
    (((dev & 0x00ff) | ((dev >> 12) & 0x0fff_ff00)) & 0xffff_ffff) as u32
}

/// Reports the largest visible size across disk state and open writable views of an inode.
pub(crate) fn inode_visible_size(inode: &ext4_fs::Inode) -> usize {
    inode_visible_size_with_disk_size(inode, inode.size() as usize)
}

/// Same as `inode_visible_size`, using an already-read on-disk size.
pub(crate) fn inode_visible_size_with_disk_size(inode: &ext4_fs::Inode, disk_size: usize) -> usize {
    let mut size = disk_size;
    let target_ino = inode.inode_num();
    let target_dev = inode.device_id();

    let processes: Vec<alloc::sync::Arc<ProcessControlBlock>> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        let table = alloc::sync::Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(alloc::sync::Arc::as_ptr(&table) as usize) {
            continue;
        }
        for (_fd, file) in table.lock().iter_files_snapshot() {
            let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
                continue;
            };
            let opened_inode = os_inode.ext4_inode();
            if opened_inode.inode_num() == target_ino && opened_inode.device_id() == target_dev {
                size = core::cmp::max(size, os_inode.pending_write_end());
            }
        }
    }
    size
}
