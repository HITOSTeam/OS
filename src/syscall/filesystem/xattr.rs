use super::{
    Arc, OSInode, SyscallError, XATTR_CREATE, XATTR_REPLACE, current_fsuid_gid, do_getxattr,
    do_listxattr, do_removexattr, do_setxattr, err, fd_has_o_path, get_current_token, get_fd_file,
    map_vfs_error, read_user_cstring, read_user_xattr_name, read_user_xattr_value,
    resolve_at_inode, resolve_at_path, resolve_at_vfs_path, try_copy_to_user,
    xattr_is_user_namespace,
};
use crate::fs::vfs::{VfsError, VfsNodeKind, VfsPath};
use crate::fs::vfs_path_is_ext4;
use alloc::vec::Vec;

enum XattrTarget {
    Ext4(Arc<ext4_fs::Inode>, Option<VfsPath>),
    Vfs(VfsPath),
    Other,
}

fn resolve_xattr_path_target(path_ptr: usize, follow_final: bool) -> Result<XattrTarget, isize> {
    let token = get_current_token();
    let path = read_user_cstring(token, path_ptr)?;
    if path.is_empty() {
        return Err(err(SyscallError::ENOENT));
    }
    let at = resolve_at_path(super::AT_FDCWD, &path)?;
    let (fsuid, fsgid) = current_fsuid_gid();
    let vfs_path = match resolve_at_vfs_path(&at, fsuid, fsgid, follow_final) {
        Ok(path) if !vfs_path_is_ext4(&path) => {
            return Ok(XattrTarget::Vfs(path));
        }
        Ok(path) => path,
        Err(error) => return Err(error),
    };
    resolve_at_inode(&at, fsuid, fsgid, follow_final)
        .map(|inode| XattrTarget::Ext4(inode, Some(vfs_path)))
}

fn resolve_xattr_fd_target(fd: usize) -> Result<XattrTarget, isize> {
    if fd_has_o_path(fd) {
        return Err(err(SyscallError::EBADF));
    }
    let Some(file) = get_fd_file(fd) else {
        return Err(err(SyscallError::EBADF));
    };
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        return Ok(XattrTarget::Ext4(
            os_inode.ext4_inode(),
            os_inode.vfs_path().map(|path| path.path().clone()),
        ));
    }
    if let Some(path) = file.object_path() {
        return Ok(XattrTarget::Vfs(path.clone()));
    }
    Ok(XattrTarget::Other)
}

fn set_ext4_xattr(
    inode: &Arc<ext4_fs::Inode>,
    path: Option<&VfsPath>,
    name: &str,
    value: &[u8],
    flags: usize,
) -> isize {
    if path.is_some_and(|path| path.mount().flags().is_read_only()) {
        return err(SyscallError::EROFS);
    }
    do_setxattr(inode, name, value, flags)
}

fn remove_ext4_xattr(inode: &Arc<ext4_fs::Inode>, path: Option<&VfsPath>, name: &str) -> isize {
    if path.is_some_and(|path| path.mount().flags().is_read_only()) {
        return err(SyscallError::EROFS);
    }
    do_removexattr(inode, name)
}

fn vfs_user_xattr_supported(path: &VfsPath) -> Result<bool, isize> {
    let metadata = path.node().metadata().map_err(map_vfs_error)?;
    Ok(matches!(
        metadata.kind,
        VfsNodeKind::Regular | VfsNodeKind::Directory
    ))
}

fn set_vfs_xattr(path: &VfsPath, name: &str, value: &[u8], flags: usize) -> isize {
    let valid_flags = XATTR_CREATE | XATTR_REPLACE;
    if flags & !valid_flags != 0 || flags & valid_flags == valid_flags {
        return err(SyscallError::EINVAL);
    }
    if xattr_is_user_namespace(name) {
        match vfs_user_xattr_supported(path) {
            Ok(true) => {}
            Ok(false) => return err(SyscallError::EPERM),
            Err(error) => return error,
        }
    }
    if path.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    match path.node().set_xattr(name, value, flags as u32) {
        Ok(()) => 0,
        Err(VfsError::NoEntry) => err(SyscallError::ENODATA),
        Err(error) => map_vfs_error(error),
    }
}

fn get_vfs_xattr(path: &VfsPath, name: &str, value_ptr: usize, size: usize, token: usize) -> isize {
    if xattr_is_user_namespace(name) {
        match vfs_user_xattr_supported(path) {
            Ok(true) => {}
            Ok(false) => return err(SyscallError::ENODATA),
            Err(error) => return error,
        }
    }
    let value = match path.node().get_xattr(name) {
        Ok(value) => value,
        Err(VfsError::NoEntry) => return err(SyscallError::ENODATA),
        Err(error) => return map_vfs_error(error),
    };
    if size == 0 {
        return value.len() as isize;
    }
    if size < value.len() {
        return err(SyscallError::ERANGE);
    }
    if value_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    if try_copy_to_user(token, value_ptr as *mut u8, &value).is_err() {
        return err(SyscallError::EFAULT);
    }
    value.len() as isize
}

fn list_vfs_xattr(path: &VfsPath, list_ptr: usize, size: usize, token: usize) -> isize {
    let names = match path.node().list_xattrs() {
        Ok(names) => names,
        Err(error) => return map_vfs_error(error),
    };
    let mut data = Vec::new();
    for name in names {
        data.extend_from_slice(name.as_bytes());
        data.push(0);
    }
    if size == 0 {
        return data.len() as isize;
    }
    if size < data.len() {
        return err(SyscallError::ERANGE);
    }
    if !data.is_empty()
        && (list_ptr == 0 || try_copy_to_user(token, list_ptr as *mut u8, &data).is_err())
    {
        return err(SyscallError::EFAULT);
    }
    data.len() as isize
}

fn remove_vfs_xattr(path: &VfsPath, name: &str) -> isize {
    if xattr_is_user_namespace(name) {
        match vfs_user_xattr_supported(path) {
            Ok(true) => {}
            Ok(false) => return err(SyscallError::ENODATA),
            Err(error) => return error,
        }
    }
    if path.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    match path.node().remove_xattr(name) {
        Ok(()) => 0,
        Err(VfsError::NoEntry) => err(SyscallError::ENODATA),
        Err(error) => map_vfs_error(error),
    }
}

/// Sets an extended attribute on the target path after following the final symlink.
pub fn syscall_setxattr(
    path: usize,
    name: usize,
    value: usize,
    size: usize,
    flags: usize,
) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match read_user_xattr_value(token, value, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match resolve_xattr_path_target(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, path) => {
            set_ext4_xattr(&inode, path.as_ref(), &name, value.as_slice(), flags)
        }
        XattrTarget::Vfs(path) => set_vfs_xattr(&path, &name, value.as_slice(), flags),
        XattrTarget::Other => err(SyscallError::EOPNOTSUPP),
    }
}

/// Sets an extended attribute on the target path without following the final symlink.
pub fn syscall_lsetxattr(
    path: usize,
    name: usize,
    value: usize,
    size: usize,
    flags: usize,
) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match read_user_xattr_value(token, value, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match resolve_xattr_path_target(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, path) => {
            set_ext4_xattr(&inode, path.as_ref(), &name, value.as_slice(), flags)
        }
        XattrTarget::Vfs(path) => set_vfs_xattr(&path, &name, value.as_slice(), flags),
        XattrTarget::Other => err(SyscallError::EOPNOTSUPP),
    }
}

/// Sets an extended attribute on the inode referenced by an open file descriptor.
pub fn syscall_fsetxattr(fd: usize, name: usize, value: usize, size: usize, flags: usize) -> isize {
    let token = get_current_token();
    let target = match resolve_xattr_fd_target(fd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match read_user_xattr_value(token, value, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, path) => {
            set_ext4_xattr(&inode, path.as_ref(), &name, value.as_slice(), flags)
        }
        XattrTarget::Vfs(path) => set_vfs_xattr(&path, &name, value.as_slice(), flags),
        XattrTarget::Other => {
            return if xattr_is_user_namespace(&name) {
                err(SyscallError::EPERM)
            } else {
                err(SyscallError::EOPNOTSUPP)
            };
        }
    }
}

/// Reads an extended attribute from the target path after following the final symlink.
pub fn syscall_getxattr(path: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match resolve_xattr_path_target(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, _) => do_getxattr(&inode, &name, value, size, token),
        XattrTarget::Vfs(path) => get_vfs_xattr(&path, &name, value, size, token),
        XattrTarget::Other => err(SyscallError::ENODATA),
    }
}

/// Reads an extended attribute from the target path without following the final symlink.
pub fn syscall_lgetxattr(path: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match resolve_xattr_path_target(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, _) => do_getxattr(&inode, &name, value, size, token),
        XattrTarget::Vfs(path) => get_vfs_xattr(&path, &name, value, size, token),
        XattrTarget::Other => err(SyscallError::ENODATA),
    }
}

/// Reads an extended attribute from the inode referenced by an open file descriptor.
pub fn syscall_fgetxattr(fd: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let target = match resolve_xattr_fd_target(fd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, _) => do_getxattr(&inode, &name, value, size, token),
        XattrTarget::Vfs(path) => get_vfs_xattr(&path, &name, value, size, token),
        XattrTarget::Other => err(SyscallError::ENODATA),
    }
}

/// Lists extended attribute names for the target path after following the final symlink.
pub fn syscall_listxattr(path: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let target = match resolve_xattr_path_target(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, _) => do_listxattr(&inode, list, size, token),
        XattrTarget::Vfs(path) => list_vfs_xattr(&path, list, size, token),
        XattrTarget::Other => 0,
    }
}

/// Lists extended attribute names for the target path without following the final symlink.
pub fn syscall_llistxattr(path: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let target = match resolve_xattr_path_target(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, _) => do_listxattr(&inode, list, size, token),
        XattrTarget::Vfs(path) => list_vfs_xattr(&path, list, size, token),
        XattrTarget::Other => 0,
    }
}

/// Lists extended attribute names for the inode referenced by an open file descriptor.
pub fn syscall_flistxattr(fd: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let target = match resolve_xattr_fd_target(fd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, _) => do_listxattr(&inode, list, size, token),
        XattrTarget::Vfs(path) => list_vfs_xattr(&path, list, size, token),
        XattrTarget::Other => 0,
    }
}

/// Removes an extended attribute from the target path after following the final symlink.
pub fn syscall_removexattr(path: usize, name: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match resolve_xattr_path_target(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, path) => remove_ext4_xattr(&inode, path.as_ref(), &name),
        XattrTarget::Vfs(path) => remove_vfs_xattr(&path, &name),
        XattrTarget::Other => err(SyscallError::ENODATA),
    }
}

/// Removes an extended attribute from the target path without following the final symlink.
pub fn syscall_lremovexattr(path: usize, name: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match resolve_xattr_path_target(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, path) => remove_ext4_xattr(&inode, path.as_ref(), &name),
        XattrTarget::Vfs(path) => remove_vfs_xattr(&path, &name),
        XattrTarget::Other => err(SyscallError::ENODATA),
    }
}

/// Removes an extended attribute from the inode referenced by an open file descriptor.
pub fn syscall_fremovexattr(fd: usize, name: usize) -> isize {
    let token = get_current_token();
    let target = match resolve_xattr_fd_target(fd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match target {
        XattrTarget::Ext4(inode, path) => remove_ext4_xattr(&inode, path.as_ref(), &name),
        XattrTarget::Vfs(path) => remove_vfs_xattr(&path, &name),
        XattrTarget::Other => err(SyscallError::ENODATA),
    }
}
