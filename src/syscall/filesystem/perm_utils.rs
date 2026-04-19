use super::{
    OSInode, PID2PCB, ProcessControlBlock,
    S_IFBLK, S_IFCHR, S_IFMT,
    SyscallError, Vec,
    current_process, err,
};

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

pub(crate) fn current_real_uid_gid() -> (u32, u32) {
    crate::syscall::misc::current_real_uid_gid()
}

pub(crate) fn current_effective_uid_gid() -> (u32, u32) {
    crate::syscall::misc::current_effective_uid_gid()
}

pub(crate) fn current_fsuid_gid() -> (u32, u32) {
    crate::syscall::misc::current_fsuid_gid()
}

pub(crate) fn current_in_group(gid: u32) -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    gid == inner.fsgid || inner.supplementary_gids.iter().any(|g| *g == gid)
}

pub(crate) fn parse_chown_id(id: usize) -> Option<u32> {
    if id == usize::MAX || id == u32::MAX as usize {
        None
    } else {
        Some(id as u32)
    }
}

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

pub(crate) fn inode_mode_allows_uid_gid(inode: &ext4_fs::Inode, mask: usize, uid: u32, gid: u32) -> bool {
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

pub(crate) fn inode_mode_allows(inode: &ext4_fs::Inode, mask: usize) -> bool {
    let (uid, gid) = current_fsuid_gid();
    inode_mode_allows_uid_gid(inode, mask, uid, gid)
}

pub(crate) fn apply_umask(mode: usize) -> u16 {
    let umask = crate::syscall::misc::current_umask() as u16;
    let perm = (mode as u16) & 0o777;
    let special = (mode as u16) & 0o7000;
    special | (perm & !umask)
}

pub(crate) fn parent_forces_gid_inherit(parent: &ext4_fs::Inode) -> bool {
    parent.is_dir() && (parent.mode() & 0o2000) != 0
}

pub(crate) fn gid_for_created_inode(parent: Option<&ext4_fs::Inode>, fallback_gid: u32) -> u32 {
    match parent {
        Some(dir) if parent_forces_gid_inherit(dir) => dir.gid(),
        _ => fallback_gid,
    }
}

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

pub(crate) fn inode_rdev_for_mode(inode: &ext4_fs::Inode, mode: u16) -> u64 {
    match mode & S_IFMT {
        S_IFCHR | S_IFBLK => inode.special_rdev(),
        _ => 0,
    }
}

pub(crate) fn linux_dev_major(dev: u64) -> u32 {
    ((((dev >> 8) & 0x0fff) | ((dev >> 32) & 0xffff_f000)) & 0xffff_ffff) as u32
}

pub(crate) fn linux_dev_minor(dev: u64) -> u32 {
    (((dev & 0x00ff) | ((dev >> 12) & 0x0fff_ff00)) & 0xffff_ffff) as u32
}

pub(crate) fn inode_visible_size(inode: &ext4_fs::Inode) -> usize {
    let mut size = inode.size() as usize;
    let target_ino = inode.inode_num();
    let target_dev = inode.device_id();

    let processes: Vec<alloc::sync::Arc<ProcessControlBlock>> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    for process in processes {
        if let Some(inner) = process.try_borrow_mut() {
            for file in inner.fd_table.iter().filter_map(|f| f.as_ref()) {
                let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
                    continue;
                };
                let fd_inode = os_inode.ext4_inode();
                if fd_inode.inode_num() == target_ino && fd_inode.device_id() == target_dev {
                    size = core::cmp::max(size, os_inode.pending_write_end());
                }
            }
        }
    }
    size
}
