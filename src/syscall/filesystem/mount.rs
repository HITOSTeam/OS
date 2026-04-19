use super::{
    alloc_internal_fd, create_mount_record_with_propagation, ensure_mount_target_dir, err,
    get_current_token, get_fd_file, mount_attr_bits_to_legacy_flags, mount_flags_for_abs,
    mount_fs_type_for_abs, mount_source_display_for_abs, read_user_cstring, read_user_path_abs,
    sync_rofs_state, syscall_mount_impl, syscall_umount2_impl, translate_mount_abs,
    try_read_user_value, update_mount_record_flags, Arc, FsContextFile, FsContextMode, KMountAttr,
    MountHandleFile, String, SyscallError, AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW,
    FD_CLOEXEC, FSCONFIG_CMD_CREATE, FSCONFIG_CMD_RECONFIGURE, FSCONFIG_SET_BINARY,
    FSCONFIG_SET_FD, FSCONFIG_SET_FLAG, FSCONFIG_SET_PATH, FSCONFIG_SET_PATH_EMPTY,
    FSCONFIG_SET_STRING, FSMOUNT_CLOEXEC, FSMOUNT_SUPPORTED_ATTRS, FSOPEN_CLOEXEC, FSPICK_CLOEXEC,
    FSPICK_EMPTY_PATH, FSPICK_NO_AUTOMOUNT, FSPICK_SYMLINK_NOFOLLOW, MOVE_MOUNT_F_EMPTY_PATH,
    MOVE_MOUNT__MASK, MS_RDONLY, OPEN_TREE_CLONE, O_CLOEXEC, O_PATH,
};

/// Creates a new filesystem context fd for the modern mount API.
pub fn syscall_fsopen(fsname: usize, flags: usize) -> isize {
    if (flags & !FSOPEN_CLOEXEC) != 0 {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let fsname = match read_user_cstring(token, fsname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if fsname.is_empty() {
        return err(SyscallError::EINVAL);
    }
    if fsname == "invalid" || fsname == "error" {
        return err(SyscallError::ENODEV);
    }
    let mut fd_flags = 0u32;
    if (flags & FSOPEN_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_internal_fd(Arc::new(FsContextFile::new_create(&fsname)), fd_flags).unwrap_or_else(|e| e)
}

/// Applies configuration commands to an `fsopen(2)` filesystem context.
pub fn syscall_fsconfig(fd: usize, cmd: usize, key: usize, value: usize, aux: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return err(SyscallError::EINVAL);
    };
    let Some(ctx_file) = file.as_any().downcast_ref::<FsContextFile>() else {
        return err(SyscallError::EINVAL);
    };
    let token = get_current_token();
    let key_s = if key == 0 {
        None
    } else {
        match read_user_cstring(token, key) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };
    let value_s = if value == 0 {
        None
    } else {
        match read_user_cstring(token, value) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };
    let mut state = ctx_file.state.lock();
    match cmd {
        FSCONFIG_SET_FLAG => {
            let Some(key_s) = key_s.as_deref() else {
                return err(SyscallError::EINVAL);
            };
            if value_s.is_some() || aux != 0 {
                return err(SyscallError::EINVAL);
            }
            match key_s {
                "rw" => state.pending_flags &= !MS_RDONLY,
                "ro" => state.pending_flags |= MS_RDONLY,
                _ => return err(SyscallError::EINVAL),
            }
            0
        }
        FSCONFIG_SET_STRING => {
            let Some(key_s) = key_s.as_deref() else {
                return err(SyscallError::EINVAL);
            };
            let Some(value_s) = value_s.as_deref() else {
                return err(SyscallError::EINVAL);
            };
            if aux != 0 || key_s.is_empty() || value_s.is_empty() {
                return err(SyscallError::EINVAL);
            }
            match key_s {
                "source" => {
                    state.source_display = String::from(value_s);
                    state.source_abs = Some(String::from("/"));
                    0
                }
                "sync" => 0,
                _ => err(SyscallError::EINVAL),
            }
        }
        FSCONFIG_SET_BINARY => err(SyscallError::EINVAL),
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY | FSCONFIG_SET_FD => {
            if key_s.as_deref().unwrap_or("").is_empty() {
                return err(SyscallError::EINVAL);
            }
            match cmd {
                FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
                    if value_s.is_none() || aux == usize::MAX {
                        return err(SyscallError::EINVAL);
                    }
                }
                FSCONFIG_SET_FD => {
                    if value_s.is_some() || aux == usize::MAX {
                        return err(SyscallError::EINVAL);
                    }
                }
                _ => {}
            }
            err(SyscallError::EOPNOTSUPP)
        }
        FSCONFIG_CMD_CREATE => {
            if key_s.is_some() || value_s.is_some() || aux != 0 {
                return err(SyscallError::EINVAL);
            }
            if state.mode != FsContextMode::Create || state.source_abs.is_none() {
                return err(SyscallError::EINVAL);
            }
            state.created = true;
            0
        }
        FSCONFIG_CMD_RECONFIGURE => {
            if key_s.is_some() || value_s.is_some() || aux != 0 {
                return err(SyscallError::EINVAL);
            }
            if state.mode != FsContextMode::Reconfigure {
                return err(SyscallError::EINVAL);
            }
            let Some(target_abs) = state.target_abs.clone() else {
                return err(SyscallError::EINVAL);
            };
            if !update_mount_record_flags(&target_abs, state.pending_flags) {
                return err(SyscallError::EINVAL);
            }
            sync_rofs_state(&target_abs, state.pending_flags);
            0
        }
        _ => err(SyscallError::EOPNOTSUPP),
    }
}

/// Materializes a configured filesystem context as a detached mount handle.
pub fn syscall_fsmount(fd: usize, flags: usize, mount_attrs: usize) -> isize {
    if (flags & !FSMOUNT_CLOEXEC) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (mount_attrs & !FSMOUNT_SUPPORTED_ATTRS) != 0 {
        return err(SyscallError::EINVAL);
    }
    let Some(file) = get_fd_file(fd) else {
        return err(SyscallError::EBADF);
    };
    let Some(ctx_file) = file.as_any().downcast_ref::<FsContextFile>() else {
        return err(SyscallError::EINVAL);
    };
    let state = ctx_file.state.lock();
    if state.mode != FsContextMode::Create || !state.created {
        return err(SyscallError::EINVAL);
    }
    let source = state
        .source_abs
        .clone()
        .unwrap_or_else(|| String::from("/"));
    let handle_flags = state.pending_flags | mount_attr_bits_to_legacy_flags(mount_attrs);
    let mut fd_flags = 0u32;
    if (flags & FSMOUNT_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_internal_fd(
        Arc::new(MountHandleFile::new(
            &source,
            &state.source_display,
            &state.fs_type,
            handle_flags,
        )),
        fd_flags,
    )
    .unwrap_or_else(|e| e)
}

/// Picks an existing mount and returns a reconfiguration-capable filesystem context.
pub fn syscall_fspick(dirfd: isize, path: usize, flags: usize) -> isize {
    let valid_flags =
        FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    let abs = if path == 0 {
        return err(SyscallError::EFAULT);
    } else {
        match read_user_path_abs(dirfd, path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    if let Err(e) = ensure_mount_target_dir(&translate_mount_abs(&abs)) {
        return e;
    }
    let fs_type = mount_fs_type_for_abs(&abs);
    let source_abs = translate_mount_abs(&abs);
    let source_display = mount_source_display_for_abs(&abs);
    let mut fd_flags = 0u32;
    if (flags & FSPICK_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_internal_fd(
        Arc::new(FsContextFile::new_reconfigure(
            &fs_type,
            &source_display,
            &source_abs,
            &abs,
            mount_flags_for_abs(&abs),
        )),
        fd_flags,
    )
    .unwrap_or_else(|e| e)
}

/// Opens a mount tree as a detached handle, optionally cloning the source tree.
pub fn syscall_open_tree(dirfd: isize, path: usize, flags: usize) -> isize {
    let valid_flags =
        OPEN_TREE_CLONE | O_CLOEXEC | AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    let abs = if path == 0 {
        return err(SyscallError::EFAULT);
    } else {
        match read_user_path_abs(dirfd, path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    if let Err(e) = ensure_mount_target_dir(&translate_mount_abs(&abs)) {
        return e;
    }
    let source_abs = translate_mount_abs(&abs);
    let source_display = mount_source_display_for_abs(&abs);
    let fs_type = mount_fs_type_for_abs(&abs);
    let mount_flags = mount_flags_for_abs(&abs);
    let mut fd_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    fd_flags |= O_PATH as u32;
    alloc_internal_fd(
        Arc::new(MountHandleFile::new(
            &source_abs,
            &source_display,
            &fs_type,
            mount_flags,
        )),
        fd_flags,
    )
    .unwrap_or_else(|e| e)
}

/// Attaches or moves a detached mount handle onto a target mountpoint.
pub fn syscall_move_mount(
    from_dirfd: isize,
    from_path: usize,
    to_dirfd: isize,
    to_path: usize,
    flags: usize,
) -> isize {
    if (flags & !MOVE_MOUNT__MASK) != 0 {
        return err(SyscallError::EINVAL);
    }
    let from_path_s = if from_path == 0 {
        return err(SyscallError::EFAULT);
    } else {
        match read_user_cstring(get_current_token(), from_path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    let to_abs = match read_user_path_abs(to_dirfd, to_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = ensure_mount_target_dir(&to_abs) {
        return e;
    }
    if from_dirfd < 0 {
        return err(SyscallError::EBADF);
    }
    let Some(file) = get_fd_file(from_dirfd as usize) else {
        return err(SyscallError::EBADF);
    };
    let Some(handle) = file.as_any().downcast_ref::<MountHandleFile>() else {
        return err(SyscallError::EBADF);
    };
    if !from_path_s.is_empty() {
        return err(SyscallError::ENOENT);
    }
    if (flags & MOVE_MOUNT_F_EMPTY_PATH) == 0 {
        return err(SyscallError::ENOENT);
    }
    let state = handle.state.lock();
    create_mount_record_with_propagation(
        &to_abs,
        &state.source,
        &state.source_display,
        &state.fs_type,
        state.flags,
    );
    0
}

/// Updates mount attribute bits on a detached mount handle.
pub fn syscall_mount_setattr(
    dirfd: isize,
    path: usize,
    flags: usize,
    attr: usize,
    size: usize,
) -> isize {
    if dirfd < 0 {
        return err(SyscallError::EBADF);
    }
    if attr == 0 || size < core::mem::size_of::<KMountAttr>() {
        return err(SyscallError::EINVAL);
    }
    let path_s = if path == 0 {
        return err(SyscallError::EFAULT);
    } else {
        match read_user_cstring(get_current_token(), path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    if (flags & AT_EMPTY_PATH) == 0 || !path_s.is_empty() {
        return err(SyscallError::EINVAL);
    }
    let Some(file) = get_fd_file(dirfd as usize) else {
        return err(SyscallError::EBADF);
    };
    let Some(handle) = file.as_any().downcast_ref::<MountHandleFile>() else {
        return err(SyscallError::EINVAL);
    };
    let mount_attr = match try_read_user_value(get_current_token(), attr as *const KMountAttr) {
        Some(v) => v,
        None => return err(SyscallError::EFAULT),
    };
    let attr_set = mount_attr.attr_set as usize;
    let attr_clr = mount_attr.attr_clr as usize;
    if (attr_set & !FSMOUNT_SUPPORTED_ATTRS) != 0 || (attr_clr & !FSMOUNT_SUPPORTED_ATTRS) != 0 {
        return err(SyscallError::EINVAL);
    }
    let mut state = handle.state.lock();
    state.flags |= mount_attr_bits_to_legacy_flags(attr_set);
    state.flags &= !mount_attr_bits_to_legacy_flags(attr_clr);
    0
}

/// Legacy `mount(2)` entry point delegated to the shared mount implementation.
pub fn syscall_mount(
    special: usize,
    dir: usize,
    fstype: usize,
    flags: usize,
    data: usize,
) -> isize {
    syscall_mount_impl(special, dir, fstype, flags, data)
}

/// Legacy `umount2(2)` entry point delegated to the shared unmount implementation.
pub fn syscall_umount2(special: usize, flags: usize) -> isize {
    syscall_umount2_impl(special, flags)
}
