use super::{
    SyscallError, err,
    get_current_token,
    do_getxattr, do_listxattr, do_removexattr, do_setxattr,
    read_user_xattr_name, read_user_xattr_value,
    resolve_xattr_fd_inode, resolve_xattr_path_inode,
    xattr_is_user_namespace,
};

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
    let inode = match resolve_xattr_path_inode(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_setxattr(&inode, &name, value.as_slice(), flags)
}

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
    let inode = match resolve_xattr_path_inode(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_setxattr(&inode, &name, value.as_slice(), flags)
}

pub fn syscall_fsetxattr(fd: usize, name: usize, value: usize, size: usize, flags: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_fd_inode(fd) {
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
    let inode = match inode {
        Some(v) => v,
        None => {
            return if xattr_is_user_namespace(&name) {
                err(SyscallError::EPERM)
            } else {
                err(SyscallError::EOPNOTSUPP)
            };
        }
    };
    do_setxattr(&inode, &name, value.as_slice(), flags)
}

pub fn syscall_getxattr(path: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_getxattr(&inode, &name, value, size, token)
}

pub fn syscall_lgetxattr(path: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_getxattr(&inode, &name, value, size, token)
}

pub fn syscall_fgetxattr(fd: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_fd_inode(fd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match inode {
        Some(v) => v,
        None => return err(SyscallError::ENODATA),
    };
    do_getxattr(&inode, &name, value, size, token)
}

pub fn syscall_listxattr(path: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_path_inode(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_listxattr(&inode, list, size, token)
}

pub fn syscall_llistxattr(path: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_path_inode(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_listxattr(&inode, list, size, token)
}

pub fn syscall_flistxattr(fd: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_fd_inode(fd) {
        Ok(Some(v)) => v,
        Ok(None) => return 0,
        Err(e) => return e,
    };
    do_listxattr(&inode, list, size, token)
}

pub fn syscall_removexattr(path: usize, name: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_removexattr(&inode, &name)
}

pub fn syscall_lremovexattr(path: usize, name: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_removexattr(&inode, &name)
}

pub fn syscall_fremovexattr(fd: usize, name: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_fd_inode(fd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match inode {
        Some(v) => v,
        None => return err(SyscallError::ENODATA),
    };
    do_removexattr(&inode, &name)
}

