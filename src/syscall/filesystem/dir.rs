use super::{
    AT_EMPTY_PATH, AT_SYMLINK_FOLLOW, MapPermission, OSInode, ProcMagicLinkFile, PseudoDir,
    S_IFBLK, S_IFCHR, S_IFIFO, S_IFMT, S_IFREG, S_IFSOCK, SyscallError, VfsOpenedFile, align_up,
    apply_umask, current_effective_uid_gid, current_fsuid_gid, current_process,
    defer_unlink_open_file, do_renameat, do_renameat_exchange, dt_type_from_ext4, err,
    ext4_begin_namespace_mutation, ext4_err_to_errno, ext4_inode_lock, final_non_empty_component,
    get_current_token, get_fd_file, gid_for_created_inode, inode_is_immutable_or_append,
    inode_mode_allows_uid_gid, invalidate_ext4_path_cache_inode, invalidate_vfs_parent_entry,
    map_vfs_error, maybe_update_inode_atime, min, mode_for_created_file, parent_forces_gid_inherit,
    read_u16_le, read_u32_le, read_user_cstring, resolve_at_inode, resolve_at_path,
    resolve_at_vfs_path, resolve_parent_and_name, resolve_parent_vfs_path, sticky_rename_allowed,
    translated_byte_buffer, try_copy_to_user, vfs_at_path_is_process_root,
};
use crate::fs::ext4::Ext4VfsNode;

fn vfs_metadata_allows(
    metadata: crate::fs::vfs::VfsMetadata,
    mask: u16,
    uid: u32,
    gid: u32,
) -> bool {
    if uid == 0 {
        return true;
    }
    let shift = if uid == metadata.uid {
        6
    } else if gid == metadata.gid {
        3
    } else {
        0
    };
    ((metadata.mode >> shift) & mask) == mask
}

fn vfs_readlink_target(path: &crate::fs::vfs::VfsPath) -> Result<alloc::string::String, isize> {
    match path.node().readlink().map_err(map_vfs_error)? {
        crate::fs::vfs::VfsLink::Text(target) => Ok(target),
        crate::fs::vfs::VfsLink::Magic(target) => path
            .mount()
            .owner_namespace()
            .ok_or_else(|| err(SyscallError::ENOENT))?
            .path_string(&target)
            .map_err(map_vfs_error),
        crate::fs::vfs::VfsLink::MagicDisplay { display, .. } => Ok(display),
    }
}

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
        if let Some(vfs_file) = file.as_any().downcast_ref::<VfsOpenedFile>() {
            let target = match vfs_readlink_target(vfs_file.path()) {
                Ok(target) => target,
                Err(error) => return error,
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
        let inode = os_inode.ext4_inode();
        let inode_lock = ext4_inode_lock(&inode);
        let _inode_guard = inode_lock.read();
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

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (fsuid, fsgid) = current_fsuid_gid();
    let vfs_path = match resolve_at_vfs_path(&at, fsuid, fsgid, false) {
        Ok(path) => path,
        Err(error) => return error,
    };
    let target = match vfs_readlink_target(&vfs_path) {
        Ok(target) => target,
        Err(error) => return error,
    };
    let bytes = target.as_bytes();
    let len = min(bytes.len(), bufsiz);
    if try_copy_to_user(token, buf as *mut u8, &bytes[..len]).is_err() {
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
    let (fsuid, fsgid) = current_fsuid_gid();
    let vfs_parent = match resolve_parent_vfs_path(&at, fsuid, fsgid) {
        Ok(parent) => parent,
        Err(error) => return error,
    };
    if vfs_parent.parent.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    if !vfs_parent.parent.node().as_any().is::<Ext4VfsNode>() {
        let parent = vfs_parent;
        let metadata = match parent.parent.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return map_vfs_error(error),
        };
        if !vfs_metadata_allows(metadata, 3, fsuid, fsgid) {
            return err(SyscallError::EACCES);
        }
        let link = match parent.parent.node().symlink(&parent.name, &target_path) {
            Ok(link) => link,
            Err(error) => return map_vfs_error(error),
        };
        let gid = if metadata.mode & 0o2000 != 0 {
            metadata.gid
        } else {
            fsgid
        };
        if let Err(error) = link.set_owner(fsuid, gid) {
            return map_vfs_error(error);
        }
        invalidate_vfs_parent_entry(&parent);
        return 0;
    }
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let parent_lock = ext4_inode_lock(&parent);
    let _parent_guard = parent_lock.write();
    if !parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    ext4_begin_namespace_mutation(&parent);
    match parent.create_symlink(&name, &target_path) {
        Ok(inode) => {
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
    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_old = (flags & AT_SYMLINK_FOLLOW) != 0;
    let source_vfs = if let Some(at) = old_at.as_ref() {
        match resolve_at_vfs_path(at, fsuid, fsgid, follow_old) {
            Ok(path) => Some(path),
            Err(error) => return error,
        }
    } else if olddirfd >= 0 {
        get_fd_file(olddirfd as usize).and_then(|file| file.object_path().cloned())
    } else {
        None
    };
    let new_parent_vfs = match resolve_parent_vfs_path(&new_at, fsuid, fsgid) {
        Ok(parent) => parent,
        Err(error) => return error,
    };
    if source_vfs
        .as_ref()
        .is_some_and(|source| source.mount().id() != new_parent_vfs.parent.mount().id())
    {
        // Linux compares vfsmount identity, not only superblock identity.
        return err(SyscallError::EXDEV);
    }
    if new_parent_vfs.parent.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    let source_is_non_ext4 = source_vfs
        .as_ref()
        .is_some_and(|path| !path.node().as_any().is::<Ext4VfsNode>());
    let parent_is_non_ext4 = !new_parent_vfs.parent.node().as_any().is::<Ext4VfsNode>();
    if source_is_non_ext4 || parent_is_non_ext4 {
        let Some(source) = source_vfs else {
            return err(SyscallError::EXDEV);
        };
        let parent = new_parent_vfs;
        if source.node().as_any().is::<Ext4VfsNode>()
            || parent.parent.node().as_any().is::<Ext4VfsNode>()
            || source.mount().id() != parent.parent.mount().id()
        {
            // Linux filename_linkat() rejects different vfsmount objects,
            // including two bind mounts of the same superblock.
            return err(SyscallError::EXDEV);
        }
        let source_metadata = match source.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return map_vfs_error(error),
        };
        if source_metadata.kind == crate::fs::vfs::VfsNodeKind::Directory {
            return err(SyscallError::EPERM);
        }
        let parent_metadata = match parent.parent.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return map_vfs_error(error),
        };
        if !vfs_metadata_allows(parent_metadata, 3, fsuid, fsgid) {
            return err(SyscallError::EACCES);
        }
        return match parent.parent.node().link(&parent.name, source.node()) {
            Ok(()) => {
                invalidate_vfs_parent_entry(&parent);
                0
            }
            Err(error) => map_vfs_error(error),
        };
    }
    let source = if let Some(at) = old_at {
        match resolve_at_inode(&at, fsuid, fsgid, follow_old) {
            Ok(v) => v,
            Err(e) => return e,
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

    let (parent, name) = match resolve_parent_and_name(&new_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let parent_lock = ext4_inode_lock(&parent);
    let _parent_guard = parent_lock.write();
    if source.is_dir() {
        return err(SyscallError::EPERM);
    }
    let source_lock = ext4_inode_lock(&source);
    let _source_guard = source_lock.write();
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
    ext4_begin_namespace_mutation(&parent);
    match parent.link_inode(&name, &source) {
        Ok(_) => 0,
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
    let (fsuid, fsgid) = current_fsuid_gid();

    let mut file_type = (mode as u16) & S_IFMT;
    if file_type == 0 {
        file_type = S_IFREG;
    }
    if !matches!(file_type, S_IFREG | S_IFIFO | S_IFCHR | S_IFBLK | S_IFSOCK) {
        return err(SyscallError::EINVAL);
    }
    if matches!(file_type, S_IFCHR | S_IFBLK) {
        let (euid, _) = current_effective_uid_gid();
        if euid != 0 {
            return err(SyscallError::EPERM);
        }
    }

    let vfs_parent = match resolve_parent_vfs_path(&at, fsuid, fsgid) {
        Ok(parent) => parent,
        Err(error) => return error,
    };
    if vfs_parent.parent.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    if !vfs_parent.parent.node().as_any().is::<Ext4VfsNode>() {
        let parent = vfs_parent;
        let parent_metadata = match parent.parent.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return map_vfs_error(error),
        };
        if parent_metadata.kind != crate::fs::vfs::VfsNodeKind::Directory {
            return err(SyscallError::ENOTDIR);
        }
        if !vfs_metadata_allows(parent_metadata, 3, fsuid, fsgid) {
            return err(SyscallError::EACCES);
        }
        let gid = if parent_metadata.mode & 0o2000 != 0 {
            parent_metadata.gid
        } else {
            fsgid
        };
        let create_mode = mode_for_created_file(file_type | apply_umask(mode), gid);
        let created = match file_type {
            S_IFREG => parent.parent.node().create(&parent.name, create_mode),
            S_IFIFO => parent.parent.node().mknod(
                &parent.name,
                crate::fs::vfs::VfsNodeKind::Fifo,
                create_mode,
                0,
            ),
            S_IFSOCK => parent.parent.node().mknod(
                &parent.name,
                crate::fs::vfs::VfsNodeKind::Socket,
                create_mode,
                0,
            ),
            S_IFCHR => parent.parent.node().mknod(
                &parent.name,
                crate::fs::vfs::VfsNodeKind::CharacterDevice,
                create_mode,
                dev as u64,
            ),
            S_IFBLK => parent.parent.node().mknod(
                &parent.name,
                crate::fs::vfs::VfsNodeKind::BlockDevice,
                create_mode,
                dev as u64,
            ),
            _ => unreachable!(),
        };
        let created = match created {
            Ok(created) => created,
            Err(error) => return map_vfs_error(error),
        };
        if let Err(error) = created.set_owner(fsuid, gid) {
            return map_vfs_error(error);
        }
        invalidate_vfs_parent_entry(&parent);
        return 0;
    }

    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let parent_lock = ext4_inode_lock(&parent);
    let _parent_guard = parent_lock.write();
    if !parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    if parent.find(&name).is_some() {
        return err(SyscallError::EEXIST);
    }

    let gid = gid_for_created_inode(Some(&parent), fsgid);
    let perm_bits = apply_umask(mode) & 0o7777;
    let create_mode = mode_for_created_file(file_type | perm_bits, gid);

    ext4_begin_namespace_mutation(&parent);
    let create_result = match file_type {
        S_IFREG => parent.create_file(&name),
        S_IFIFO | S_IFSOCK => parent.create_special(&name, create_mode, 0),
        S_IFCHR | S_IFBLK => parent.create_special(&name, create_mode, dev as u64),
        _ => unreachable!(),
    };

    match create_result {
        Ok(inode) => {
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
        crate::println!("[mkdir] pid={} vfs-path='{}'", pid, path);
    }
    match resolve_at_vfs_path(&at, fsuid, fsgid, false) {
        Ok(_) => return err(SyscallError::EEXIST),
        Err(e) if e == err(SyscallError::ENOENT) => {}
        Err(e) => return e,
    }
    let vfs_parent = match resolve_parent_vfs_path(&at, fsuid, fsgid) {
        Ok(parent) => parent,
        Err(error) => return error,
    };
    if vfs_parent.parent.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    if !vfs_parent.parent.node().as_any().is::<Ext4VfsNode>() {
        let parent = vfs_parent;
        let metadata = match parent.parent.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return map_vfs_error(error),
        };
        if metadata.kind != crate::fs::vfs::VfsNodeKind::Directory {
            return err(SyscallError::ENOTDIR);
        }
        if !vfs_metadata_allows(metadata, 3, fsuid, fsgid) {
            return err(SyscallError::EACCES);
        }
        let inherit_gid = metadata.mode & 0o2000 != 0;
        let gid = if inherit_gid { metadata.gid } else { fsgid };
        let directory_mode = if inherit_gid {
            create_mode | 0o2000
        } else {
            create_mode
        };
        let directory = match parent.parent.node().mkdir(&parent.name, directory_mode) {
            Ok(directory) => directory,
            Err(error) => return map_vfs_error(error),
        };
        if let Err(error) = directory.set_owner(fsuid, gid) {
            return map_vfs_error(error);
        }
        invalidate_vfs_parent_entry(&parent);
        return 0;
    }
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let parent_lock = ext4_inode_lock(&parent);
    let _parent_guard = parent_lock.write();
    if !parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    if parent.find(&name).is_some() {
        return err(SyscallError::EEXIST);
    }
    ext4_begin_namespace_mutation(&parent);
    match parent.create_dir(&name) {
        Ok(dir) => {
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

    match final_non_empty_component(&path) {
        // Reject self/parent names before locking the parent inode.  Otherwise
        // unlink without AT_REMOVEDIR could try to take the same i_rwsem again
        // after resolving "." or "..".
        Some(".") => {
            return err(if remove_dir {
                SyscallError::EINVAL
            } else {
                SyscallError::EISDIR
            });
        }
        Some("..") => {
            return err(if remove_dir {
                SyscallError::ENOTEMPTY
            } else {
                SyscallError::EISDIR
            });
        }
        _ => {}
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    match vfs_at_path_is_process_root(&at, fsuid, fsgid) {
        Ok(true) => return err(SyscallError::EISDIR),
        Ok(false) => {}
        Err(e) => return e,
    }
    let vfs_parent = match resolve_parent_vfs_path(&at, fsuid, fsgid) {
        Ok(parent) => parent,
        Err(error) => return error,
    };
    let target_vfs = match resolve_at_vfs_path(&at, fsuid, fsgid, false) {
        Ok(target) => target,
        Err(error) => return error,
    };
    if target_vfs.mount().id() != vfs_parent.parent.mount().id() {
        return err(SyscallError::EBUSY);
    }
    if vfs_parent.parent.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    if !vfs_parent.parent.node().as_any().is::<Ext4VfsNode>() {
        let parent = vfs_parent;
        let target = target_vfs;
        let parent_metadata = match parent.parent.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return map_vfs_error(error),
        };
        if !vfs_metadata_allows(parent_metadata, 3, fsuid, fsgid) {
            return err(SyscallError::EACCES);
        }
        let child_metadata = match target.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return map_vfs_error(error),
        };
        if parent_metadata.mode & 0o1000 != 0
            && fsuid != 0
            && fsuid != parent_metadata.uid
            && fsuid != child_metadata.uid
        {
            return err(SyscallError::EPERM);
        }
        return match parent.parent.node().unlink(&parent.name, remove_dir) {
            Ok(()) => {
                invalidate_vfs_parent_entry(&parent);
                0
            }
            Err(error) => map_vfs_error(error),
        };
    }
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let parent_lock = ext4_inode_lock(&parent);
    let _parent_guard = parent_lock.write();

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
        return err(SyscallError::ENOENT);
    };
    let child_lock = ext4_inode_lock(&child);
    let _child_guard = child_lock.write();
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
    if !remove_dir {
        match defer_unlink_open_file(&parent, &name, &child) {
            Ok(true) => return 0,
            Ok(false) => {}
            Err(e) => return e,
        }
    }

    ext4_begin_namespace_mutation(&parent);
    match parent.unlink(&name) {
        Ok(_) => {
            invalidate_ext4_path_cache_inode(&child);
            0
        }
        Err(ext4_fs::Ext4Error::Unsupported) => err(SyscallError::ENOTEMPTY),
        Err(e) => ext4_err_to_errno(e),
    }
}

fn dt_type_from_vfs(kind: crate::fs::vfs::VfsNodeKind) -> u8 {
    match kind {
        crate::fs::vfs::VfsNodeKind::Fifo => 1,
        crate::fs::vfs::VfsNodeKind::CharacterDevice => 2,
        crate::fs::vfs::VfsNodeKind::Directory => 4,
        crate::fs::vfs::VfsNodeKind::BlockDevice => 6,
        crate::fs::vfs::VfsNodeKind::Regular => 8,
        crate::fs::vfs::VfsNodeKind::Symlink => 10,
        crate::fs::vfs::VfsNodeKind::Socket => 12,
    }
}

/// Emits Linux `dirent64` records for pseudo and object/ext4-backed directories.
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

    if let Some(vfs_file) = file.as_any().downcast_ref::<VfsOpenedFile>() {
        if vfs_file.kind() != crate::fs::vfs::VfsNodeKind::Directory {
            return err(SyscallError::ENOTDIR);
        }
        if len == 0 {
            return 0;
        }
        let entries = match vfs_file.path().node().readdir() {
            Ok(entries) => entries,
            Err(error) => return map_vfs_error(error),
        };
        let mut index = vfs_file.directory_cookie() as usize;
        if index >= entries.len().saturating_add(2) {
            return 0;
        }
        let this_ino = vfs_file.path().node().node_id();
        let parent_ino = vfs_file
            .path()
            .dentry()
            .parent()
            .map(|parent| parent.node().node_id())
            .unwrap_or(this_ino);
        let mut kbuf = alloc::vec![0u8; len];
        let mut written = 0usize;
        while index < entries.len().saturating_add(2) {
            let (name, ino, dtype) = match index {
                0 => (".", this_ino, 4),
                1 => ("..", parent_ino, 4),
                _ => {
                    let entry = &entries[index - 2];
                    (
                        entry.name.as_str(),
                        entry.node_id,
                        dt_type_from_vfs(entry.kind),
                    )
                }
            };
            let name_bytes = name.as_bytes();
            let reclen = align_up(19 + name_bytes.len() + 1, 8);
            if written + reclen > len {
                break;
            }
            let next = index + 1;
            let base = written;
            kbuf[base..base + 8].copy_from_slice(&ino.to_le_bytes());
            kbuf[base + 8..base + 16].copy_from_slice(&(next as i64).to_le_bytes());
            kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
            kbuf[base + 18] = dtype;
            kbuf[base + 19..base + 19 + name_bytes.len()].copy_from_slice(name_bytes);
            kbuf[base + 19 + name_bytes.len()] = 0;
            written += reclen;
            index = next;
        }
        if try_copy_to_user(token, dirp as *mut u8, &kbuf[..written]).is_err() {
            return err(SyscallError::EFAULT);
        }
        vfs_file.set_directory_cookie(index as u64);
        return written as isize;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::ENOTDIR);
    };
    let inode = os_inode.ext4_inode();

    let inode_lock = ext4_inode_lock(&inode);
    let _inode_guard = inode_lock.read();
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
    if written > 0 {
        maybe_update_inode_atime(&inode, true);
    }
    written as isize
}
