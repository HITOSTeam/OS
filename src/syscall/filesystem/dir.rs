use super::{
    AT_EMPTY_PATH, AT_SYMLINK_FOLLOW, AtPath, MapPermission, OSInode, ProcMagicLinkFile, PseudoDir,
    S_IFBLK, S_IFCHR, S_IFIFO, S_IFMT, S_IFREG, S_IFSOCK, SyscallError, align_up, apply_umask,
    cgroup_mkdir, cgroup_rmdir, current_effective_uid_gid, current_fsuid_gid, current_process,
    defer_unlink_open_file, do_renameat, do_renameat_exchange, dt_type_from_ext4, err,
    ext4_err_to_errno, ext4_lock, final_non_empty_component, get_current_token, get_fd_file,
    gid_for_created_inode, hardlink_cross_mount, inode_is_immutable_or_append,
    inode_is_rofs_mount_root, inode_logical_path, inode_mode_allows_uid_gid,
    invalidate_ext4_path_cache_for_at, invalidate_ext4_path_cache_inode, maybe_update_inode_atime,
    min, mode_for_created_file, open_pseudo, parent_forces_gid_inherit,
    parse_proc_fd_for_current_process, path_is_mount_point, proc_path_for_at, read_u16_le,
    read_u32_le, read_user_cstring, resolve_abs_path, resolve_at_inode, resolve_at_path,
    resolve_parent_and_name, rofs_for_path, shm_object_name, shm_remove, sticky_rename_allowed,
    translated_byte_buffer, try_copy_to_user,
};

/// Reads a symlink target by pathname or, with `AT_EMPTY_PATH`, directly from an fd.
pub fn syscall_readlinkat(dirfd: isize, pathname: usize, buf: usize, bufsiz: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if bufsiz == 0 {
        return err(SyscallError::EINVAL);
    }
    if path.is_empty() {
        if dirfd < 0 {
            return err(SyscallError::ENOENT);
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return err(SyscallError::EBADF);
        };
        if let Some(link) = file.as_any().downcast_ref::<ProcMagicLinkFile>() {
            let Some(target) = link.readlink_target() else {
                return err(SyscallError::ENOENT);
            };
            let bytes = target.as_bytes();
            let len = min(bytes.len(), bufsiz);
            if try_copy_to_user(token, buf as *mut u8, &bytes[..len]).is_err() {
                return err(SyscallError::EFAULT);
            }
            return len as isize;
        }
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return err(SyscallError::EINVAL);
        };
        let _ext4_guard = ext4_lock();
        let inode = os_inode.ext4_inode();
        if !inode.is_symlink() {
            return err(SyscallError::EINVAL);
        }
        let target = inode.read_all();
        let len = min(target.len(), bufsiz);
        if try_copy_to_user(token, buf as *mut u8, &target[..len]).is_err() {
            return err(SyscallError::EFAULT);
        }
        return len as isize;
    }

    let raw_abs = match resolve_abs_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(proc_path) = proc_path_for_at(raw_abs.as_deref(), &at) {
            if let Some(target) = crate::fs::proc_readlink(proc_path) {
                let bytes = target.as_bytes();
                let len = min(bytes.len(), bufsiz);
                if try_copy_to_user(token, buf as *mut u8, &bytes[..len]).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return len as isize;
            }
        }
        if let Some(target) = crate::fs::proc_readlink(abs) {
            let bytes = target.as_bytes();
            let len = min(bytes.len(), bufsiz);
            if try_copy_to_user(token, buf as *mut u8, &bytes[..len]).is_err() {
                return err(SyscallError::EFAULT);
            }
            return len as isize;
        }
        return if open_pseudo(abs).is_some() {
            err(SyscallError::EINVAL)
        } else {
            err(SyscallError::ENOENT)
        };
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !inode.is_symlink() {
        return err(SyscallError::EINVAL);
    }
    let target = inode.read_all();
    let len = min(target.len(), bufsiz);
    if try_copy_to_user(token, buf as *mut u8, &target[..len]).is_err() {
        return err(SyscallError::EFAULT);
    }
    len as isize
}

/// Creates a symbolic link in an ext4 directory.
pub fn syscall_symlinkat(target: usize, newdirfd: isize, linkpath: usize) -> isize {
    let token = get_current_token();
    let target_path = match read_user_cstring(token, target) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let path = match read_user_cstring(token, linkpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }

    let at = match resolve_at_path(newdirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let AtPath::PseudoAbs(_) = &at {
        return err(SyscallError::EROFS);
    }
    let path_rofs = rofs_for_path(newdirfd, &path);

    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    if path_rofs {
        return err(SyscallError::EROFS);
    }

    match parent.create_symlink(&name, &target_path) {
        Ok(inode) => {
            invalidate_ext4_path_cache_for_at(&at, false);
            let gid = gid_for_created_inode(Some(&parent), fsgid);
            inode.set_uid_gid(fsuid, gid);
            inode.set_mode(0o777);
            0
        }
        Err(e) => ext4_err_to_errno(e),
    }
}

/// Creates a hard link while enforcing mount-boundary and proc-fd rules.
pub fn syscall_linkat(
    olddirfd: isize,
    oldpath: usize,
    newdirfd: isize,
    newpath: usize,
    flags: usize,
) -> isize {
    let valid_flags = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }

    let token = get_current_token();
    let old_s = match read_user_cstring(token, oldpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new_s = match read_user_cstring(token, newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if new_s.is_empty() {
        return err(SyscallError::ENOENT);
    }

    let old_at = if old_s.is_empty() {
        if (flags & AT_EMPTY_PATH) == 0 {
            return err(SyscallError::ENOENT);
        }
        None
    } else {
        match resolve_at_path(olddirfd, &old_s) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };

    let new_at = match resolve_at_path(newdirfd, &new_s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let old_abs = if old_s.is_empty() {
        None
    } else {
        match resolve_abs_path(olddirfd, &old_s) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    let new_abs = match resolve_abs_path(newdirfd, &new_s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if matches!(new_at, AtPath::PseudoAbs(_)) {
        return err(SyscallError::EROFS);
    }
    if let Some(AtPath::PseudoAbs(abs)) = &old_at {
        if parse_proc_fd_for_current_process(abs).is_none() {
            return err(SyscallError::EXDEV);
        }
    }
    let old_is_proc_fd_magic = matches!(&old_at, Some(AtPath::PseudoAbs(abs)) if parse_proc_fd_for_current_process(abs).is_some());
    if let (Some(old_abs), Some(new_abs)) = (old_abs.as_deref(), new_abs.as_deref()) {
        // `/proc/self/fd/N` is a magic link to the opened inode. Its textual
        // path is under procfs, but Linux applies EXDEV to the resolved inode.
        if !old_is_proc_fd_magic && hardlink_cross_mount(old_abs, new_abs) {
            return err(SyscallError::EXDEV);
        }
    }

    let new_path_rofs = rofs_for_path(newdirfd, &new_s);
    if new_path_rofs {
        return err(SyscallError::EROFS);
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_old = (flags & AT_SYMLINK_FOLLOW) != 0;
    let _ext4_guard = ext4_lock();

    let source = if let Some(at) = old_at {
        match at {
            AtPath::PseudoAbs(abs) => {
                let fd = match parse_proc_fd_for_current_process(&abs) {
                    Some(v) => v,
                    None => return err(SyscallError::EXDEV),
                };
                let Some(file) = get_fd_file(fd) else {
                    return err(SyscallError::EBADF);
                };
                let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
                    return err(SyscallError::EPERM);
                };
                os_inode.ext4_inode()
            }
            other => match resolve_at_inode(&other, fsuid, fsgid, follow_old) {
                Ok(v) => v,
                Err(e) => return e,
            },
        }
    } else {
        if olddirfd < 0 {
            return err(SyscallError::EBADF);
        }
        let Some(file) = get_fd_file(olddirfd as usize) else {
            return err(SyscallError::EBADF);
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return err(SyscallError::EPERM);
        };
        os_inode.ext4_inode()
    };
    if source.is_dir() {
        return err(SyscallError::EPERM);
    }

    let (parent, name) = match resolve_parent_and_name(&new_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    if parent.find(&name).is_some() {
        return err(SyscallError::EEXIST);
    }
    if parent.device_id() != source.device_id() {
        return err(SyscallError::EXDEV);
    }
    if new_path_rofs {
        return err(SyscallError::EROFS);
    }

    match parent.link_inode(&name, &source) {
        Ok(_) => {
            invalidate_ext4_path_cache_for_at(&new_at, false);
            0
        }
        Err(ext4_fs::Ext4Error::Unsupported) => err(SyscallError::EPERM),
        Err(e) => ext4_err_to_errno(e),
    }
}

/// Renames or moves a filesystem entry with classic `renameat(2)` semantics.
pub fn syscall_renameat(olddirfd: isize, oldpath: usize, newdirfd: isize, newpath: usize) -> isize {
    let token = get_current_token();
    let old_s = match read_user_cstring(token, oldpath) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_s = match read_user_cstring(token, newpath) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if old_s.is_empty() || new_s.is_empty() {
        return err(SyscallError::ENOENT);
    }
    do_renameat(olddirfd, &old_s, newdirfd, &new_s, false)
}

/// Handles `renameat2(2)` extensions such as `RENAME_NOREPLACE` and `RENAME_EXCHANGE`.
pub fn syscall_renameat2(
    olddirfd: isize,
    oldpath: usize,
    newdirfd: isize,
    newpath: usize,
    flags: usize,
) -> isize {
    const RENAME_NOREPLACE: usize = 1;
    const RENAME_EXCHANGE: usize = 2;
    const RENAME_WHITEOUT: usize = 4;

    if (flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT)) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & RENAME_EXCHANGE) != 0 && (flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & RENAME_WHITEOUT) != 0 {
        return err(SyscallError::EINVAL);
    }

    let token = get_current_token();
    let old_s = match read_user_cstring(token, oldpath) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_s = match read_user_cstring(token, newpath) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if old_s.is_empty() || new_s.is_empty() {
        return err(SyscallError::ENOENT);
    }

    if flags == 0 {
        return do_renameat(olddirfd, &old_s, newdirfd, &new_s, false);
    }
    if flags == RENAME_NOREPLACE {
        return do_renameat(olddirfd, &old_s, newdirfd, &new_s, true);
    }
    if flags == RENAME_EXCHANGE {
        return do_renameat_exchange(olddirfd, &old_s, newdirfd, &new_s);
    }
    err(SyscallError::EINVAL)
}

/// Creates regular, FIFO, socket, block, or char special nodes in ext4.
pub fn syscall_mknodat(dirfd: isize, pathname: usize, mode: usize, dev: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let AtPath::PseudoAbs(_) = &at {
        return err(SyscallError::EROFS);
    }
    let path_rofs = rofs_for_path(dirfd, &path);
    let (fsuid, fsgid) = current_fsuid_gid();

    let _ext4_guard = ext4_lock();
    let dirfd_rofs = matches!(
        &at,
        AtPath::Ext4Rel { base, .. } if inode_is_rofs_mount_root(base)
    );
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if dirfd_rofs || path_rofs {
        return err(SyscallError::EROFS);
    }
    if !parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    if parent.find(&name).is_some() {
        return err(SyscallError::EEXIST);
    }

    let mut file_type = (mode as u16) & S_IFMT;
    if file_type == 0 {
        file_type = S_IFREG;
    }
    let valid_type = matches!(file_type, S_IFREG | S_IFIFO | S_IFCHR | S_IFBLK | S_IFSOCK);
    if !valid_type {
        return err(SyscallError::EINVAL);
    }

    let gid = gid_for_created_inode(Some(&parent), fsgid);
    let perm_bits = apply_umask(mode) & 0o7777;
    let create_mode = mode_for_created_file(file_type | perm_bits, gid);

    if matches!(file_type, S_IFCHR | S_IFBLK) {
        let (euid, _) = current_effective_uid_gid();
        if euid != 0 {
            return err(SyscallError::EPERM);
        }
    }

    let create_result = match file_type {
        S_IFREG => parent.create_file(&name),
        S_IFIFO | S_IFSOCK => parent.create_special(&name, create_mode, 0),
        S_IFCHR | S_IFBLK => parent.create_special(&name, create_mode, dev as u64),
        _ => unreachable!(),
    };

    match create_result {
        Ok(inode) => {
            invalidate_ext4_path_cache_for_at(&at, false);
            inode.set_uid_gid(fsuid, gid);
            inode.set_mode(create_mode);
            0
        }
        Err(e) => ext4_err_to_errno(e),
    }
}

/// Creates a directory and applies Linux-like gid inheritance and permission checks.
pub fn syscall_mkdirat(dirfd: isize, pathname: usize, mode: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    if crate::debug_config::DEBUG_SYSCALL {
        let pid = current_process().getpid();
        crate::println!(
            "[mkdir] pid={} dirfd={} path='{}' mode=0o{:o}",
            pid,
            dirfd,
            path,
            mode
        );
    }

    let create_mode = apply_umask(mode);
    let (fsuid, fsgid) = current_fsuid_gid();

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if crate::debug_config::DEBUG_SYSCALL {
        let pid = current_process().getpid();
        match &at {
            AtPath::Ext4Abs(abs) => {
                crate::println!("[mkdir] pid={} abs='{}'", pid, abs);
            }
            AtPath::Ext4Rel { rel, .. } => {
                crate::println!("[mkdir] pid={} rel='{}'", pid, rel);
            }
            AtPath::PseudoAbs(abs) => {
                crate::println!("[mkdir] pid={} pseudo='{}'", pid, abs);
            }
        }
    }

    if let AtPath::PseudoAbs(abs) = &at {
        let cgroup_rc = cgroup_mkdir(abs);
        if cgroup_rc != err(SyscallError::EROFS) {
            return cgroup_rc;
        }
        if open_pseudo(abs).is_some() || crate::fs::proc_readlink(abs).is_some() {
            return err(SyscallError::EEXIST);
        }
        let rc = crate::fs::pseudo_dev_dir_mkdir(abs);
        if rc != err(SyscallError::EROFS) {
            return rc;
        }
        return err(SyscallError::EROFS);
    }
    let path_rofs = rofs_for_path(dirfd, &path);

    let _ext4_guard = ext4_lock();
    if matches!(at, AtPath::Ext4Abs(ref abs) if abs == "/") {
        return err(SyscallError::EEXIST);
    }
    if matches!(at, AtPath::Ext4Rel { ref rel, .. } if rel.is_empty()) {
        return err(SyscallError::EEXIST);
    }
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    if parent.find(&name).is_some() {
        return err(SyscallError::EEXIST);
    }
    if path_rofs {
        return err(SyscallError::EROFS);
    }
    match parent.create_dir(&name) {
        Ok(dir) => {
            invalidate_ext4_path_cache_for_at(&at, false);
            let gid = gid_for_created_inode(Some(&parent), fsgid);
            let mut dir_mode = create_mode;
            if parent_forces_gid_inherit(&parent) {
                dir_mode |= 0o2000;
            }
            dir.set_uid_gid(fsuid, gid);
            dir.set_mode(dir_mode);
            if crate::debug_config::DEBUG_SYSCALL {
                let pid = current_process().getpid();
                crate::println!(
                    "[mkdir] pid={} inode={} mode=0o{:o} is_dir={}",
                    pid,
                    dir.inode_num(),
                    dir.mode(),
                    dir.is_dir()
                );
            }
            0
        }
        Err(e) => {
            let err = ext4_err_to_errno(e);
            if crate::debug_config::DEBUG_SYSCALL {
                let pid = current_process().getpid();
                crate::println!("[mkdir] pid={} create_dir err={}", pid, err);
            }
            err
        }
    }
}

/// Removes a directory entry, optionally enforcing `rmdir` semantics.
pub fn syscall_unlinkat(dirfd: isize, pathname: usize, flags: usize) -> isize {
    const AT_REMOVEDIR: usize = 0x200;
    if (flags & !AT_REMOVEDIR) != 0 {
        return err(SyscallError::EINVAL);
    }

    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    let remove_dir = (flags & AT_REMOVEDIR) != 0;

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if remove_dir {
        if final_non_empty_component(&path) == Some(".") {
            return err(SyscallError::EINVAL);
        }
        if final_non_empty_component(&path) == Some("..") {
            return err(SyscallError::ENOTEMPTY);
        }
        if let AtPath::PseudoAbs(abs) = &at {
            let cgroup_rc = cgroup_rmdir(abs);
            if cgroup_rc != err(SyscallError::EROFS) {
                return cgroup_rc;
            }
        }
        if let Some(abs) = match resolve_abs_path(dirfd, &path) {
            Ok(v) => v,
            Err(e) => return e,
        } {
            if path_is_mount_point(&abs) {
                return err(SyscallError::EBUSY);
            }
        }
    }

    if let AtPath::PseudoAbs(abs) = &at {
        // Minimal `/dev/shm` support for POSIX `shm_unlink`.
        if abs == "/dev/shm" || abs == "/dev/shm/" {
            return if remove_dir {
                err(SyscallError::EROFS)
            } else {
                err(SyscallError::EISDIR)
            };
        }
        if crate::fs::is_cgroup_pseudo_path(abs) {
            return if open_pseudo(abs).is_some() {
                err(SyscallError::EISDIR)
            } else {
                err(SyscallError::ENOENT)
            };
        }
        if let Some(name) = shm_object_name(abs) {
            if remove_dir {
                return err(SyscallError::ENOTDIR);
            }
            return if shm_remove(name) {
                0
            } else {
                err(SyscallError::ENOENT)
            };
        }
        if crate::fs::pseudo_dev_dir_exists(abs) {
            return if remove_dir {
                crate::fs::pseudo_dev_dir_rmdir(abs)
            } else {
                err(SyscallError::EISDIR)
            };
        }
        return err(SyscallError::EROFS);
    }
    let path_rofs = rofs_for_path(dirfd, &path);

    let (fsuid, fsgid) = current_fsuid_gid();
    let ext4_guard = ext4_lock();
    if matches!(at, AtPath::Ext4Abs(ref abs) if abs == "/") {
        return err(SyscallError::EISDIR);
    }
    if matches!(at, AtPath::Ext4Rel { ref rel, .. } if rel.is_empty()) {
        return err(SyscallError::EISDIR);
    }
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if !parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    if remove_dir && name == "." {
        return err(SyscallError::EINVAL);
    }
    if remove_dir && name == ".." {
        return err(SyscallError::ENOTEMPTY);
    }

    // Validate target type: unlink vs rmdir semantics.
    let Some(child) = parent.find(&name) else {
        if path_rofs {
            return err(SyscallError::EROFS);
        }
        return err(SyscallError::ENOENT);
    };
    if remove_dir {
        if !child.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        if !child.ls().is_empty() {
            return err(SyscallError::ENOTEMPTY);
        }
    } else {
        if child.is_dir() {
            return err(SyscallError::EISDIR);
        }
    }
    if !sticky_rename_allowed(&parent, &child, fsuid) {
        return err(SyscallError::EPERM);
    }
    if inode_is_immutable_or_append(&child) {
        return err(SyscallError::EPERM);
    }
    if path_rofs {
        return err(SyscallError::EROFS);
    }

    // 打开文件引用检查会遍历 fd 表并读取 OSInode 内锁，不能同时持有全局
    // ext4 锁；其他读写路径按“OSInode -> ext4”顺序获取，否则会形成反向锁序。
    drop(ext4_guard);
    if !remove_dir {
        match defer_unlink_open_file(&parent, &name, &child) {
            Ok(true) => return 0,
            Ok(false) => {}
            Err(e) => return e,
        }
    }

    let _ext4_guard = ext4_lock();
    match parent.unlink(&name) {
        Ok(_) => {
            invalidate_ext4_path_cache_for_at(&at, remove_dir);
            invalidate_ext4_path_cache_inode(&child);
            0
        }
        Err(ext4_fs::Ext4Error::Unsupported) => err(SyscallError::ENOTEMPTY),
        Err(e) => ext4_err_to_errno(e),
    }
}

/// Emits Linux `dirent64` records for pseudo and ext4-backed directories.
pub fn syscall_getdents64(fd: usize, dirp: usize, len: usize) -> isize {
    // Avoid unbounded kernel heap allocations from user-provided buffer sizes.
    // Returning fewer bytes is allowed; callers will retry with the remaining entries.
    const MAX_DIRENT_BUF: usize = 256 * 1024;
    let len = len.min(MAX_DIRENT_BUF);
    if len > 0 && len < 24 {
        return err(SyscallError::EINVAL);
    }
    let Some(file) = get_fd_file(fd) else {
        return err(SyscallError::EBADF);
    };
    let token = get_current_token();

    // Pseudo directories (e.g. /sys, /dev).
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            crate::println!("[fs] getdents64(pid={}) pseudo fd={} len={}", pid, fd, len);
        }
        let entries = pdir.entries();
        let mut index = pdir.index();
        if index >= entries.len() || len == 0 {
            return 0;
        }

        let mut kbuf = alloc::vec![0u8; len];
        let mut written = 0usize;
        while index < entries.len() {
            let ent = &entries[index];
            let name_bytes = ent.name.as_bytes();
            let reclen = align_up(19 + name_bytes.len() + 1, 8);
            if written + reclen > len {
                break;
            }
            let base = written;
            kbuf[base..base + 8].copy_from_slice(&ent.ino.to_le_bytes());
            kbuf[base + 8..base + 16].copy_from_slice(&((index + 1) as i64).to_le_bytes());
            kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
            kbuf[base + 18] = ent.dtype;
            kbuf[base + 19..base + 19 + name_bytes.len()].copy_from_slice(name_bytes);
            kbuf[base + 19 + name_bytes.len()] = 0;
            for b in kbuf[base + 19 + name_bytes.len() + 1..base + reclen].iter_mut() {
                *b = 0;
            }

            written += reclen;
            index += 1;
        }

        let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written, MapPermission::W);
        let mut src_off = 0usize;
        for ub in user_bufs {
            let end = src_off + ub.len();
            ub.copy_from_slice(&kbuf[src_off..end]);
            src_off = end;
        }
        pdir.set_index(index);
        return written as isize;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::ENOTDIR);
    };
    let inode = os_inode.ext4_inode();
    if let Some(path) = inode_logical_path(&inode) {
        if let Some(node) = open_pseudo(&path) {
            if let Some(pdir) = node.as_any().downcast_ref::<PseudoDir>() {
                let entries = pdir.entries();
                let mut index = os_inode.dir_offset();
                if index >= entries.len() || len == 0 {
                    return 0;
                }

                let mut kbuf = alloc::vec![0u8; len];
                let mut written = 0usize;
                while index < entries.len() {
                    let ent = &entries[index];
                    let name_bytes = ent.name.as_bytes();
                    let reclen = align_up(19 + name_bytes.len() + 1, 8);
                    if written + reclen > len {
                        break;
                    }
                    let base = written;
                    kbuf[base..base + 8].copy_from_slice(&ent.ino.to_le_bytes());
                    kbuf[base + 8..base + 16].copy_from_slice(&((index + 1) as i64).to_le_bytes());
                    kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
                    kbuf[base + 18] = ent.dtype;
                    kbuf[base + 19..base + 19 + name_bytes.len()].copy_from_slice(name_bytes);
                    kbuf[base + 19 + name_bytes.len()] = 0;
                    for b in kbuf[base + 19 + name_bytes.len() + 1..base + reclen].iter_mut() {
                        *b = 0;
                    }

                    written += reclen;
                    index += 1;
                }

                let user_bufs =
                    translated_byte_buffer(token, dirp as *mut u8, written, MapPermission::W);
                let mut src_off = 0usize;
                for ub in user_bufs {
                    let end = src_off + ub.len();
                    ub.copy_from_slice(&kbuf[src_off..end]);
                    src_off = end;
                }
                os_inode.set_dir_offset(index);
                if written > 0 {
                    maybe_update_inode_atime(&inode, true);
                }
                return written as isize;
            }
        }
    }

    let ext4_guard = ext4_lock();
    if !inode.is_dir() {
        return err(SyscallError::ENOTDIR);
    };
    if inode.link_count() == 0 {
        // Linux keeps an opened directory fd usable after the directory entry is
        // removed.  Our ext4 layer has already detached the backing blocks, so
        // report EOF instead of surfacing ENOENT to user-space directory walkers.
        return 0;
    }

    if len == 0 {
        return 0;
    }

    // Stream ext4 directory entries from the on-disk format using a byte offset.
    //
    // This avoids rebuilding `inode.dir_entries()` on every `getdents64` call, which
    // becomes O(n^2) for large directories (busybox `du`/`find`).
    let block_size = inode.block_size();
    const EXT4_DIRENT_HDR: usize = 8; // u32 ino, u16 rec_len, u8 name_len, u8 file_type

    let dir_size = inode.size() as usize;
    let mut off = os_inode.dir_offset();
    if off >= dir_size {
        return 0;
    }

    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && (fd == 3 || fd == 4) {
            crate::println!(
                "[fs] getdents64(pid={}) fd={} len={} off={} dir_size={}",
                pid,
                fd,
                len,
                off,
                dir_size
            );
        }
    }

    let mut kbuf = alloc::vec![0u8; len];
    let mut written = 0usize;

    let mut scratch = alloc::vec![0u8; block_size];
    while off < dir_size && written + 24 <= len {
        let block_start = (off / block_size) * block_size;
        let within = off - block_start;
        let to_read = core::cmp::min(block_size, dir_size - block_start);
        if to_read < EXT4_DIRENT_HDR || within >= to_read {
            break;
        }
        inode.read_at(block_start, &mut scratch[..to_read]);

        // Parse entries within this block, starting at `within`.
        let mut pos = within;
        while pos + EXT4_DIRENT_HDR <= to_read && written + 24 <= len {
            let inode_num = read_u32_le(&scratch[pos..pos + 4]);
            let rec_len = read_u16_le(&scratch[pos + 4..pos + 6]) as usize;
            let name_len = scratch[pos + 6] as usize;
            let file_type = scratch[pos + 7];

            if rec_len < EXT4_DIRENT_HDR || pos + rec_len > to_read {
                // Corrupt/unsupported entry; stop to avoid looping.
                off = dir_size;
                break;
            }

            let next_off = block_start + pos + rec_len;
            // Skip unused entries (inode_num == 0).
            if inode_num != 0 && name_len > 0 && pos + EXT4_DIRENT_HDR + name_len <= pos + rec_len {
                let name_bytes = &scratch[pos + EXT4_DIRENT_HDR..pos + EXT4_DIRENT_HDR + name_len];
                let reclen = align_up(19 + name_len + 1, 8);
                if written + reclen > len {
                    // Caller buffer full; keep current offset for next call.
                    os_inode.set_dir_offset(block_start + pos);
                    let user_bufs =
                        translated_byte_buffer(token, dirp as *mut u8, written, MapPermission::W);
                    let mut src_off = 0usize;
                    for ub in user_bufs {
                        let end = src_off + ub.len();
                        ub.copy_from_slice(&kbuf[src_off..end]);
                        src_off = end;
                    }
                    return written as isize;
                }

                let base = written;
                kbuf[base..base + 8].copy_from_slice(&(inode_num as u64).to_le_bytes());
                kbuf[base + 8..base + 16].copy_from_slice(&(next_off as i64).to_le_bytes());
                kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
                kbuf[base + 18] = dt_type_from_ext4(file_type);
                kbuf[base + 19..base + 19 + name_len].copy_from_slice(name_bytes);
                kbuf[base + 19 + name_len] = 0;
                for b in kbuf[base + 19 + name_len + 1..base + reclen].iter_mut() {
                    *b = 0;
                }
                written += reclen;
            }

            pos += rec_len;
            off = block_start + pos;
            if off >= dir_size {
                break;
            }
        }
    }

    // Copy back to user buffer with per-page translation, avoiding per-byte translation overhead.
    let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written, MapPermission::W);
    let mut src_off = 0usize;
    for ub in user_bufs {
        let end = src_off + ub.len();
        ub.copy_from_slice(&kbuf[src_off..end]);
        src_off = end;
    }

    os_inode.set_dir_offset(off);
    drop(ext4_guard);
    if written > 0 {
        maybe_update_inode_atime(&inode, true);
    }
    written as isize
}
