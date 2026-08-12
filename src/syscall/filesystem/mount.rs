use super::{
    AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW, Arc, FD_CLOEXEC,
    FSCONFIG_CMD_CREATE, FSCONFIG_CMD_RECONFIGURE, FSCONFIG_SET_BINARY, FSCONFIG_SET_FD,
    FSCONFIG_SET_FLAG, FSCONFIG_SET_PATH, FSCONFIG_SET_PATH_EMPTY, FSCONFIG_SET_STRING,
    FSMOUNT_CLOEXEC, FSMOUNT_SUPPORTED_ATTRS, FSOPEN_CLOEXEC, FSPICK_CLOEXEC, FSPICK_EMPTY_PATH,
    FSPICK_NO_AUTOMOUNT, FSPICK_SYMLINK_NOFOLLOW, FsContextFile, FsContextMode, FsContextState,
    KMountAttr, MOUNT_ATTR__ATIME, MOUNT_ATTR_NOATIME, MOUNT_ATTR_STRICTATIME, MOVE_MOUNT__MASK,
    MOVE_MOUNT_F_EMPTY_PATH, MOVE_MOUNT_T_SYMLINKS, MS_PRIVATE, MS_RDONLY, MS_REC, MS_SHARED,
    MS_SLAVE, MS_UNBINDABLE, MountHandleFile, MountHandleObject, O_CLOEXEC, O_PATH,
    OPEN_TREE_CLONE, String, SyscallError, alloc_internal_fd, apply_mount_propagation_change,
    attach_or_move_mount_handle, block_device_source_path, current_fsuid_gid, err,
    get_current_token, get_fd_file, map_vfs_error, mount_attr_bits_to_legacy_flags,
    read_user_cstring, reconfigure_mount_flags, resolve_abs_path, resolve_at_path,
    resolve_at_vfs_path, syscall_mount_impl, syscall_umount2_impl, try_read_user_value,
};
use crate::fs::{CgroupMountSpec, create_registered_vfs_filesystem, tmpfs::TmpFsOptions};

/// Add one filesystem-specific parameter to the legacy option representation
/// shared by `fsconfig(2)` and `mount(2)`.
///
/// Linux's cgroup1 parameters are declared as flag/string `fs_parameter_spec`
/// entries and are consumed by `cgroup1_parse_param()`.  In particular,
/// util-linux sends `-o cpu` as `FSCONFIG_SET_FLAG("cpu")`, not as legacy
/// mount data.  Validate the accumulated value with the same parser used by
/// `mount(2)` so the two APIs cannot acquire different option semantics.
fn append_cgroup1_fsconfig_option(
    state: &mut FsContextState,
    key: &str,
    value: Option<&str>,
) -> Result<(), isize> {
    if key.contains(',') || value.is_some_and(|value| value.contains(',')) {
        return Err(err(SyscallError::EINVAL));
    }
    let mut candidate = state.mount_data.clone();
    if !candidate.is_empty() {
        candidate.push(',');
    }
    candidate.push_str(key);
    if let Some(value) = value {
        candidate.push('=');
        candidate.push_str(value);
    }
    CgroupMountSpec::parse_legacy_options(&candidate)?;
    state.mount_data = candidate;
    Ok(())
}

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
    let mut descriptor_flags = 0u32;
    if (flags & FSOPEN_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    alloc_internal_fd(
        Arc::new(FsContextFile::new_create(&fsname)),
        descriptor_flags,
    )
    .unwrap_or_else(|e| e)
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
            if state.created {
                return err(SyscallError::EBUSY);
            }
            let Some(key_s) = key_s.as_deref() else {
                return err(SyscallError::EINVAL);
            };
            if value_s.is_some() || aux != 0 {
                return err(SyscallError::EINVAL);
            }
            match key_s {
                "rw" => state.pending_flags &= !MS_RDONLY,
                "ro" => state.pending_flags |= MS_RDONLY,
                _ if state.fs_type == "cgroup" => {
                    if let Err(error) = append_cgroup1_fsconfig_option(&mut state, key_s, None) {
                        return error;
                    }
                }
                _ => return err(SyscallError::EINVAL),
            }
            0
        }
        FSCONFIG_SET_STRING => {
            if state.created {
                return err(SyscallError::EBUSY);
            }
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
                    state.source_abs = Some(
                        block_device_source_path(value_s).unwrap_or_else(|| String::from(value_s)),
                    );
                    0
                }
                "sync" => 0,
                "name" if state.fs_type == "cgroup" => {
                    if let Err(error) =
                        append_cgroup1_fsconfig_option(&mut state, key_s, Some(value_s))
                    {
                        return error;
                    }
                    0
                }
                "size" | "mode" | "uid" | "gid" | "nr_inodes" if state.fs_type == "tmpfs" => {
                    // Structured fsconfig values are one parameter each.  Do
                    // not let a comma in a value inject additional options
                    // into the shared legacy-data representation.
                    if value_s.contains(',') {
                        return err(SyscallError::EINVAL);
                    }
                    let mut candidate = state.mount_data.clone();
                    if !candidate.is_empty() {
                        candidate.push(',');
                    }
                    candidate.push_str(key_s);
                    candidate.push('=');
                    candidate.push_str(value_s);
                    let memory_bytes = crate::config::phys_mem_end()
                        .saturating_sub(crate::config::phys_mem_start());
                    if let Err(error) = TmpFsOptions::parse(memory_bytes, &candidate) {
                        return map_vfs_error(error);
                    }
                    state.mount_data = candidate;
                    0
                }
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
            if state.mode != FsContextMode::Create
                || state.created
                || (state.source_abs.is_none()
                    && !matches!(
                        state.fs_type.as_str(),
                        "tmpfs" | "proc" | "sysfs" | "devtmpfs" | "cgroup" | "cgroup2"
                    ))
            {
                return err(SyscallError::EINVAL);
            }
            let filesystem = match create_registered_vfs_filesystem(
                &state.fs_type,
                state
                    .source_display
                    .as_str()
                    .ne("")
                    .then_some(state.source_display.as_str()),
                &state.mount_data,
                state.pid_namespace_id,
                &state.cgroup_namespace_root,
            ) {
                Ok(filesystem) => filesystem,
                Err(error) => return map_vfs_error(error),
            };
            state.created_filesystem = Some(filesystem);
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
            match reconfigure_mount_flags(&target_abs, state.pending_flags) {
                Ok(()) => 0,
                Err(e) => e,
            }
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
    let mut descriptor_flags = 0u32;
    if (flags & FSMOUNT_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    let Some(filesystem) = state.created_filesystem.as_ref() else {
        return err(SyscallError::EINVAL);
    };
    let handle = MountHandleFile::new_filesystem(
        &source,
        &state.source_display,
        &state.fs_type,
        handle_flags,
        Arc::clone(filesystem),
    );
    alloc_internal_fd(Arc::new(handle), descriptor_flags).unwrap_or_else(|e| e)
}

/// Picks an existing mount and returns a reconfiguration-capable filesystem context.
pub fn syscall_fspick(dirfd: isize, path: usize, flags: usize) -> isize {
    let valid_flags =
        FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
    if (flags & !valid_flags) != 0 {
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
    let (abs, picked) = if path_s.is_empty() {
        if (flags & FSPICK_EMPTY_PATH) == 0 {
            return err(SyscallError::ENOENT);
        }
        if dirfd < 0 {
            return err(SyscallError::EBADF);
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return err(SyscallError::EBADF);
        };
        let Some(picked) = file.object_path().cloned() else {
            return err(SyscallError::EOPNOTSUPP);
        };
        let Some(namespace) = picked.mount().owner_namespace() else {
            return err(SyscallError::EINVAL);
        };
        let abs = match namespace.path_string(&picked) {
            Ok(path) => path,
            Err(error) => return map_vfs_error(error),
        };
        (abs, picked)
    } else {
        let abs = match resolve_abs_path(dirfd, &path_s) {
            Ok(Some(abs)) => abs,
            Ok(None) => return err(SyscallError::EBADF),
            Err(e) => return e,
        };
        let at = match resolve_at_path(dirfd, &path_s) {
            Ok(at) => at,
            Err(e) => return e,
        };
        let (uid, gid) = current_fsuid_gid();
        let follow_final = (flags & FSPICK_SYMLINK_NOFOLLOW) == 0;
        let picked = match resolve_at_vfs_path(&at, uid, gid, follow_final) {
            Ok(path) => path,
            Err(e) => return e,
        };
        (abs, picked)
    };
    // Linux fspick() accepts only the root dentry of the selected mount.
    if !Arc::ptr_eq(picked.dentry(), picked.mount().root()) {
        return err(SyscallError::EINVAL);
    }
    let fs_type = String::from(picked.mount().filesystem_type());
    let source_display = String::from(picked.mount().source_display());
    let mount_flags = picked.mount().flags().0;
    let mut descriptor_flags = 0u32;
    if (flags & FSPICK_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    alloc_internal_fd(
        Arc::new(FsContextFile::new_reconfigure(
            &fs_type,
            &source_display,
            &abs,
            &abs,
            mount_flags,
        )),
        descriptor_flags,
    )
    .unwrap_or_else(|e| e)
}

/// Opens a mount tree path, optionally creating a detached clone.
pub fn syscall_open_tree(dirfd: isize, path: usize, flags: usize) -> isize {
    let valid_flags =
        OPEN_TREE_CLONE | O_CLOEXEC | AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    if (flags & !valid_flags) != 0 {
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
    let abs = match resolve_abs_path(dirfd, &path_s) {
        Ok(Some(abs)) => abs,
        Ok(None) => return err(SyscallError::EBADF),
        Err(e) => return e,
    };
    // The handle keeps the source VfsPath below; this spelling is presentation
    // metadata only and must never be translated to a hidden canonical path.
    let source_abs = abs.clone();
    let mut descriptor_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    descriptor_flags |= O_PATH as u32;

    let at = match resolve_at_path(dirfd, &path_s) {
        Ok(at) => at,
        Err(e) => return e,
    };
    let (uid, gid) = current_fsuid_gid();
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let source = match resolve_at_vfs_path(&at, uid, gid, follow_final) {
        Ok(path) => path,
        Err(e) => return e,
    };
    let Some(source_namespace) = source.mount().owner_namespace() else {
        return err(SyscallError::EINVAL);
    };
    let source_display = String::from(source.mount().source_display());
    let source_fs_type = String::from(source.mount().filesystem_type());
    let source_flags = source.mount().flags().0;
    let handle = if (flags & OPEN_TREE_CLONE) != 0 {
        let handle = MountHandleFile::new_bind(
            &source_abs,
            &source_display,
            &source_fs_type,
            source_flags,
            source,
            source_namespace,
            &abs,
        );
        handle
    } else {
        MountHandleFile::new_path(
            &source_abs,
            &source_display,
            &source_fs_type,
            source_flags,
            source,
            source_namespace,
            &abs,
        )
    };
    alloc_internal_fd(Arc::new(handle), descriptor_flags).unwrap_or_else(|e| e)
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
    let to_path_s = if to_path == 0 {
        return err(SyscallError::EFAULT);
    } else {
        match read_user_cstring(get_current_token(), to_path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    let to_abs = match resolve_abs_path(to_dirfd, &to_path_s) {
        Ok(Some(v)) => v,
        Ok(None) => return err(SyscallError::EBADF),
        Err(e) => return e,
    };
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
    let mut state = handle.state.lock();
    let at = match resolve_at_path(to_dirfd, &to_path_s) {
        Ok(at) => at,
        Err(e) => return e,
    };
    let (uid, gid) = current_fsuid_gid();
    let follow_final = (flags & MOVE_MOUNT_T_SYMLINKS) != 0;
    let target = match resolve_at_vfs_path(&at, uid, gid, follow_final) {
        Ok(path) => path,
        Err(e) => return e,
    };
    match attach_or_move_mount_handle(&target, &to_abs, &mut state) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Updates mount attribute bits on a detached mount handle.
pub fn syscall_mount_setattr(
    dirfd: isize,
    path: usize,
    flags: usize,
    attr: usize,
    size: usize,
) -> isize {
    let valid_flags = AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
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
    let atime_set = attr_set & MOUNT_ATTR__ATIME;
    let atime_clr = attr_clr & MOUNT_ATTR__ATIME;
    if atime_clr != 0 {
        if atime_clr != MOUNT_ATTR__ATIME
            || !matches!(atime_set, 0 | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME)
        {
            return err(SyscallError::EINVAL);
        }
    } else if atime_set != 0 {
        return err(SyscallError::EINVAL);
    }

    // Linux validates this field separately from attr_set/attr_clr.  It is
    // an MS_* enum with exactly one propagation type, not a mount-attribute
    // bitmap.  In particular, util-linux 2.41 uses open_tree()+mount_setattr()
    // for `mount --make-{private,shared,slave,unbindable}`.
    let propagation_mask = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
    let propagation = mount_attr.propagation as usize;
    if (propagation & !propagation_mask) != 0 || propagation.count_ones() > 1 {
        return err(SyscallError::EINVAL);
    }

    let mut state = handle.state.lock();
    let old_flags = state.flags;
    let mut new_flags = old_flags & !mount_attr_bits_to_legacy_flags(attr_clr);
    new_flags |= mount_attr_bits_to_legacy_flags(attr_set);

    let MountHandleObject::Path { logical_source, .. } = &state.object else {
        // Attribute bits on an anonymous fsmount/open_tree clone are retained
        // until move_mount attaches it.  Propagation needs a detached mount
        // object, which this compact handle representation does not yet have;
        // fail explicitly instead of reporting a no-op success.
        if propagation != 0 {
            return err(SyscallError::EOPNOTSUPP);
        }
        state.flags = new_flags;
        return 0;
    };
    let target = logical_source.clone();

    // A live open_tree fd names the existing mount.  Updating only the
    // descriptor's cached flags would be a false success, so commit through
    // the same graph+mountinfo transaction used by legacy remount.  Recursive
    // ordinary attribute changes require walking every child mount; reject
    // that unsupported combination while still supporting recursive
    // propagation below.
    if (flags & AT_RECURSIVE) != 0 && new_flags != old_flags {
        return err(SyscallError::EOPNOTSUPP);
    }
    if new_flags != old_flags {
        if let Err(error) = reconfigure_mount_flags(&target, new_flags) {
            return error;
        }
    }
    if propagation != 0 {
        let propagation_flags = propagation
            | if (flags & AT_RECURSIVE) != 0 {
                MS_REC
            } else {
                0
            };
        if let Err(error) = apply_mount_propagation_change(&target, propagation_flags) {
            if new_flags != old_flags {
                let _ = reconfigure_mount_flags(&target, old_flags);
            }
            return error;
        }
    }
    state.flags = new_flags;
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
