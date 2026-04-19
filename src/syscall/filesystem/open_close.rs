use super::{
    apply_umask, current_effective_uid_gid, current_files_process, current_fsuid_gid,
    current_process, err, ext4_err_to_errno, ext4_lock, fd_file, fifo_pipe_state_for_inode,
    file_lock_key, file_lock_key_from_inode, get_current_token, gid_for_created_inode,
    inode_mode_allows, inode_mode_allows_uid_gid, install_open_file_fd,
    is_inode_currently_executed_locked, is_privileged_or_owner, lock_executing_inodes, make_pipe,
    maybe_signal_lease_break, mode_for_created_file, note_inode_path_hint,
    open_existing_target_path, open_pseudo, path_is_nodev, path_is_nosymfollow, path_is_rofs,
    proc_path_for_at, read_user_cstring, remove_owner_file_lease_for_key,
    remove_process_record_locks_for_key, reopen_proc_link_file, resolve_abs_path, resolve_at_inode,
    resolve_at_path, resolve_parent_and_name, secondary_root_inode, set_inode_all_times_now,
    shm_create, shm_get, shm_object_name, touch_inode_mtime_ctime_now, try_write_user_value,
    union_root_dir_entries, AtPath, BTreeSet, File, OSInode, Ordering, ProcMagicLinkFile,
    PseudoDir, PseudoShmFile, SyscallError, FD_CLOEXEC, O_ACCMODE, O_APPEND, O_CLOEXEC, O_CREAT,
    O_DIRECTORY, O_EXCL, O_NOATIME, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_TMPFILE,
    O_TRUNC, O_WRONLY, S_IFBLK, S_IFCHR, S_IFMT, TMPFILE_SEQ,
};

/// Opens or creates a filesystem object across ext4, proc, pseudo-fs, and tmpfile paths.
pub fn syscall_openat(dirfd: isize, pathname: usize, flags: usize, mode: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    let debug_close = crate::debug_config::DEBUG_FS && path.contains("test_close");
    if debug_close {
        let pid = current_process().getpid();
        crate::println!(
            "[fs] openat close-test pid={} dirfd={} path='{}' flags={:#x} mode=0o{:o}",
            pid,
            dirfd,
            path,
            flags,
            mode
        );
    }

    let o_path = (flags & O_PATH) != 0;
    let nofollow = (flags & O_NOFOLLOW) != 0;
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if path == "." || path == "/proc" || path == "/proc/" || path == "/sys" || path == "/dev" {
            crate::println!(
                "[fs] openat pid={} dirfd={} path='{}' flags={:#x}",
                pid,
                dirfd,
                path,
                flags
            );
        }
    }

    let (readable, writable) = if o_path {
        (false, false)
    } else {
        match flags & O_ACCMODE {
            O_RDONLY => (true, false),
            O_WRONLY => (false, true),
            O_RDWR => (true, true),
            _ => (true, false),
        }
    };
    let tmpfile_requested = (flags & O_TMPFILE) == O_TMPFILE;
    let write_intent = writable || (flags & (O_CREAT | O_TRUNC)) != 0 || tmpfile_requested;
    let raw_abs = match resolve_abs_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let readonly_fs = raw_abs.as_deref().map(path_is_rofs).unwrap_or(false);
    if write_intent && readonly_fs {
        return err(SyscallError::EROFS);
    }
    if !nofollow {
        if let Some(proc_path) = raw_abs
            .as_deref()
            .filter(|abs| crate::fs::is_proc_pseudo_path(abs))
        {
            if let Some(src_file) = crate::fs::proc_fd_link_file(proc_path) {
                let fd = match reopen_proc_link_file(src_file, flags, readable, writable, o_path) {
                    Ok(fd) => fd,
                    Err(e) => return e,
                };
                return fd as isize;
            }
        }
    }
    let append = !o_path && (flags & O_APPEND) != 0;

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => {
            if debug_close {
                crate::println!("[fs] openat close-test resolve_at_path err={}", e);
            }
            return e;
        }
    };
    let create_mode = apply_umask(mode);
    let mut created = false;
    let mut created_parent: Option<alloc::sync::Arc<ext4_fs::Inode>> = None;
    let mut tmpfile_cleanup_parent: Option<alloc::sync::Arc<ext4_fs::Inode>> = None;
    let mut tmpfile_cleanup_name: Option<alloc::string::String> = None;
    let (fsuid, fsgid) = current_fsuid_gid();
    if let Some(abs) = raw_abs.as_deref() {
        if path_is_nosymfollow(abs) {
            if let Ok(inode) = resolve_at_inode(&at, fsuid, fsgid, false) {
                if inode.is_symlink() {
                    return err(SyscallError::ELOOP);
                }
            }
        }
    }

    // Pseudo fs: `/sys`, `/dev`.
    if let AtPath::PseudoAbs(abs) = &at {
        if tmpfile_requested {
            return err(SyscallError::EOPNOTSUPP);
        }
        if let Some(proc_path) = proc_path_for_at(raw_abs.as_deref(), &at) {
            if crate::fs::proc_magic_link_exists(proc_path) {
                if nofollow {
                    if !o_path {
                        return err(SyscallError::ELOOP);
                    }
                    if (flags & O_DIRECTORY) != 0 {
                        return err(SyscallError::ENOTDIR);
                    }
                    let fd = match install_open_file_fd(
                        ProcMagicLinkFile::new(proc_path),
                        flags,
                        true,
                    ) {
                        Ok(fd) => fd,
                        Err(e) => return e,
                    };
                    return fd as isize;
                }
                if let Some(target) = crate::fs::proc_readlink(proc_path) {
                    if target.starts_with('/') {
                        let fd = match open_existing_target_path(
                            &target, flags, readable, writable, append, o_path,
                        ) {
                            Ok(fd) => fd,
                            Err(e) => return e,
                        };
                        return fd as isize;
                    }
                }
                let file = match open_pseudo(proc_path) {
                    Some(f) => f,
                    None => return err(SyscallError::ENOENT),
                };
                let fd = match install_open_file_fd(file, flags, o_path) {
                    Ok(fd) => fd,
                    Err(e) => return e,
                };
                return fd as isize;
            }
        }
        // Minimal `/dev/shm` support for POSIX `shm_open` users (e.g., cyclictest).
        // Must handle `O_CREAT|O_EXCL` even when the object already exists.
        let file: alloc::sync::Arc<dyn File + Send + Sync> =
            if let Some(name) = shm_object_name(abs) {
                if (flags & O_CREAT) != 0 {
                    if (flags & O_EXCL) != 0 && shm_get(name).is_some() {
                        return err(SyscallError::EEXIST);
                    }
                    let data = shm_create(name);
                    alloc::sync::Arc::new(PseudoShmFile::new_with_mode(data, readable, writable))
                } else {
                    let Some(data) = shm_get(name) else {
                        return err(SyscallError::ENOENT);
                    };
                    alloc::sync::Arc::new(PseudoShmFile::new_with_mode(data, readable, writable))
                }
            } else if let Some(f) = open_pseudo(abs) {
                f
            } else {
                return err(SyscallError::ENOENT);
            };
        let fd = match install_open_file_fd(file, flags, o_path) {
            Ok(fd) => fd,
            Err(e) => return e,
        };
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            if abs == "/proc" || abs == "/sys" || abs == "/dev" {
                crate::println!("[fs] openat(pid={}) pseudo '{}' -> fd={}", pid, abs, fd);
            }
        }
        return fd as isize;
    }

    // If we have a secondary disk, expose a merged view of `/` for directory listing.
    if let AtPath::Ext4Abs(abs) = &at {
        if abs == "/" && secondary_root_inode().is_some() {
            if write_intent && !o_path {
                return err(SyscallError::EISDIR);
            }
            let _ext4_guard = ext4_lock();
            let entries = union_root_dir_entries();
            drop(_ext4_guard);
            let file: alloc::sync::Arc<dyn File + Send + Sync> =
                alloc::sync::Arc::new(PseudoDir::new("/", entries));
            let fd = match install_open_file_fd(file, flags, o_path) {
                Ok(fd) => fd,
                Err(e) => return e,
            };
            return fd as isize;
        }
    }

    let ext4_guard = ext4_lock();

    // ext4 lookup with search permission checks and symlink resolution.
    let mut inode = match resolve_at_inode(&at, fsuid, fsgid, !nofollow) {
        Ok(v) => Some(v),
        Err(e) if e == err(SyscallError::ENOENT) => None,
        Err(e) => {
            if debug_close {
                crate::println!("[fs] openat close-test resolve_at_inode err={}", e);
            }
            return e;
        }
    };

    if !o_path && nofollow {
        if let Some(inode_ref) = inode.as_ref() {
            if inode_ref.is_symlink() {
                return err(SyscallError::ELOOP);
            }
        }
    }

    // Existing path + O_CREAT|O_EXCL must fail.
    if !tmpfile_requested && inode.is_some() && (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 {
        return err(SyscallError::EEXIST);
    }

    if tmpfile_requested {
        let dir_inode = match inode {
            Some(ref i) => alloc::sync::Arc::clone(i),
            None => return err(SyscallError::ENOENT),
        };
        if !dir_inode.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        if !inode_mode_allows_uid_gid(&dir_inode, 3, fsuid, fsgid) {
            return err(SyscallError::EACCES);
        }
        // Emulate anonymous tmpfile semantics using a hidden per-filesystem pool.
        // Use the known root inode for the same block device to avoid relying on
        // per-directory ".." lookups (which can leave stale hidden entries behind).
        let mut fs_root = crate::fs::root_inode_for_path("/");
        if fs_root.device_id() != dir_inode.device_id() {
            if let Some(sec_root) = secondary_root_inode() {
                if sec_root.device_id() == dir_inode.device_id() {
                    fs_root = sec_root;
                } else {
                    // Fallback: best effort on the opened directory's filesystem.
                    fs_root = alloc::sync::Arc::clone(&dir_inode);
                }
            } else {
                fs_root = alloc::sync::Arc::clone(&dir_inode);
            }
        }
        let pool_name = ".ltp_tmpfile_pool";
        let pool_dir = if let Some(existing) = fs_root.find(pool_name) {
            if !existing.is_dir() {
                return err(SyscallError::ENOTDIR);
            }
            existing
        } else {
            match fs_root.create_dir(pool_name) {
                Ok(d) => {
                    d.set_uid_gid(0, 0);
                    d.set_mode(0o1777);
                    d
                }
                Err(e) => return ext4_err_to_errno(e),
            }
        };

        let pid = current_process().getpid();
        let mut tmp_created = None;
        for _ in 0..64 {
            let seq = TMPFILE_SEQ.fetch_add(1, Ordering::Relaxed);
            let name = alloc::format!(".tmp.{}.{}", pid, seq);
            if pool_dir.find(&name).is_some() {
                continue;
            }
            match pool_dir.create_file(&name) {
                Ok(i) => {
                    tmp_created = Some(i);
                    tmpfile_cleanup_parent = Some(alloc::sync::Arc::clone(&pool_dir));
                    tmpfile_cleanup_name = Some(name);
                    break;
                }
                Err(e) => return ext4_err_to_errno(e),
            }
        }
        let Some(tmp_inode) = tmp_created else {
            return err(SyscallError::ENOSPC);
        };
        // Use target directory for mode/gid inheritance semantics.
        created_parent = Some(dir_inode);
        inode = Some(tmp_inode);
        created = true;
    }

    // CREATE: create file if missing (Linux: only affects the final component).
    if inode.is_none() && (flags & O_CREAT != 0) {
        match &at {
            AtPath::Ext4Abs(_) | AtPath::Ext4Rel { .. } => {
                let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if !parent.is_dir() {
                    if debug_close {
                        crate::println!("[fs] openat close-test parent not dir");
                    }
                    return err(SyscallError::ENOTDIR);
                }
                if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
                    if debug_close {
                        crate::println!("[fs] openat close-test parent no search perm");
                    }
                    return err(SyscallError::EACCES);
                }
                inode = match parent.create_file(&name) {
                    Ok(i) => {
                        created = true;
                        created_parent = Some(alloc::sync::Arc::clone(&parent));
                        Some(i)
                    }
                    Err(e) => {
                        if debug_close {
                            crate::println!("[fs] openat close-test create_file err={:?}", e);
                        }
                        return ext4_err_to_errno(e);
                    }
                };
            }
            AtPath::PseudoAbs(_) => unreachable!(),
        }
    }

    let inode = match inode {
        Some(i) => i,
        None => return err(SyscallError::ENOENT),
    };

    if !tmpfile_requested {
        if let Some(abs) = raw_abs.as_deref() {
            note_inode_path_hint(&inode, abs);
        }
    }

    if let Some(abs) = raw_abs.as_deref() {
        let mode = inode.mode() & S_IFMT;
        if path_is_nodev(abs) && matches!(mode, S_IFCHR | S_IFBLK) {
            return err(SyscallError::EACCES);
        }
    }

    if created {
        let created_gid = gid_for_created_inode(created_parent.as_deref(), fsgid);
        let created_mode = mode_for_created_file(create_mode, created_gid);
        inode.set_uid_gid(fsuid, created_gid);
        inode.set_mode(created_mode);
        set_inode_all_times_now(&inode);
    }
    if debug_close {
        crate::println!(
            "[fs] openat close-test inode={} mode=0o{:o} is_dir={} is_file={} created={}",
            inode.inode_num(),
            inode.mode(),
            inode.is_dir(),
            inode.is_file(),
            created
        );
    }

    // Linux: opening a directory for write is not allowed. Also, O_CREAT on
    // an existing directory returns err(SyscallError::EISDIR) (including symlink-to-directory).
    if !o_path && inode.is_dir() && ((flags & O_ACCMODE) != O_RDONLY || (flags & O_CREAT) != 0) {
        if debug_close {
            crate::println!(
                "[fs] openat close-test err(SyscallError::EISDIR) inode={} mode=0o{:o}",
                inode.inode_num(),
                inode.mode()
            );
        }
        return err(SyscallError::EISDIR);
    }

    // Linux `O_NOATIME`: non-owner/non-privileged callers get err(SyscallError::EPERM).
    if (flags & O_NOATIME) != 0 {
        let (euid, _egid) = current_effective_uid_gid();
        if !is_privileged_or_owner(euid, &inode) {
            return err(SyscallError::EPERM);
        }
    }

    // Basic permission check based on owner/group/other bits.
    let mut mask = 0usize;
    if readable {
        mask |= 4;
    }
    if writable {
        mask |= 2;
    }
    if !inode_mode_allows(&inode, mask) {
        if debug_close {
            crate::println!(
                "[fs] openat close-test err(SyscallError::EACCES) inode={} mode=0o{:o} mask=0o{:o}",
                inode.inode_num(),
                inode.mode(),
                mask
            );
        }
        return err(SyscallError::EACCES);
    }

    if (flags & O_DIRECTORY) != 0 && !tmpfile_requested && !inode.is_dir() {
        if debug_close {
            crate::println!(
                "[fs] openat close-test err(SyscallError::ENOTDIR) inode={} mode=0o{:o}",
                inode.inode_num(),
                inode.mode()
            );
        }
        return err(SyscallError::ENOTDIR);
    }

    let text_write_intent = writable || (flags & O_TRUNC) != 0;
    let exec_inode_guard = if !o_path && inode.is_file() && text_write_intent {
        let guard = lock_executing_inodes();
        let exec_busy =
            is_inode_currently_executed_locked(&guard, inode.device_id(), inode.inode_num());
        if exec_busy {
            return err(SyscallError::ETXTBSY);
        }
        Some(guard)
    } else {
        None
    };

    if !o_path && inode.is_file() {
        maybe_signal_lease_break(
            file_lock_key_from_inode(&inode),
            writable,
            false,
            current_process().getpid(),
        );
    }

    if !o_path && (flags & O_TRUNC) != 0 && writable && inode.is_file() {
        if let Err(e) = inode.clear() {
            return ext4_err_to_errno(e);
        }
        touch_inode_mtime_ctime_now(&inode);
    }

    if !o_path && inode.is_fifo() {
        let state = fifo_pipe_state_for_inode(inode.inode_num() as u64);
        let accmode = flags & O_ACCMODE;
        if (flags & O_NONBLOCK) != 0 && accmode == O_WRONLY && !state.has_open_readers() {
            drop(ext4_guard);
            return err(SyscallError::ENXIO);
        }
        let Some(file) = state.open_file(accmode) else {
            drop(ext4_guard);
            return err(SyscallError::EINVAL);
        };
        drop(ext4_guard);
        let fd = match install_open_file_fd(file, flags, o_path) {
            Ok(fd) => fd,
            Err(e) => return e,
        };
        return fd as isize;
    }

    let inode_num = inode.inode_num();
    let tmpfile_cleanup = if tmpfile_requested {
        match (
            tmpfile_cleanup_parent.as_ref(),
            tmpfile_cleanup_name.as_ref(),
        ) {
            (Some(parent), Some(name)) => Some((alloc::sync::Arc::clone(parent), name.clone())),
            _ => None,
        }
    } else {
        None
    };
    let os_inode = alloc::sync::Arc::new(OSInode::new_with_append_rofs_tmp_cleanup(
        readable,
        writable,
        append,
        inode,
        readonly_fs,
        false,
        tmpfile_cleanup,
    ));
    drop(exec_inode_guard);
    crate::fs::debug_track_iozone_inode(&path, inode_num);
    drop(ext4_guard);
    let fd = match install_open_file_fd(os_inode, flags, o_path) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if path == "." || path == "/proc" || path == "/proc/" {
            crate::println!("[fs] openat(pid={}) ok path='{}' -> fd={}", pid, path, fd);
        }
    }
    fd as isize
}

/// Closes a single file descriptor and releases any lock or lease state tied to it.
pub fn syscall_close(fd: usize) -> isize {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    // EBADF if fd not open (POSIX close() semantics)
    if !inner.is_fd_open(fd) {
        return err(SyscallError::EBADF);
    }
    let lock_key = inner.fd_table[fd].as_ref().and_then(file_lock_key);
    let _ = inner.clear_fd(fd);
    drop(inner);
    if let Some(key) = lock_key {
        remove_process_record_locks_for_key(current_process().getpid(), key);
        remove_owner_file_lease_for_key(current_process().getpid(), key);
    }
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && fd <= 8 {
            crate::println!("[fs] close(pid={}) fd={}", pid, fd);
        }
    }
    0
}

/// Applies `close_range(2)` semantics, including optional `UNSHARE` and `CLOEXEC`.
pub fn syscall_close_range(first: usize, last: usize, flags: usize) -> isize {
    const CLOSE_RANGE_UNSHARE: usize = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: usize = 1 << 2;
    let valid = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if first > last || (flags & !valid) != 0 {
        return err(SyscallError::EINVAL);
    }

    let set_cloexec = (flags & CLOSE_RANGE_CLOEXEC) != 0;
    let process = current_process();
    if (flags & CLOSE_RANGE_UNSHARE) != 0 {
        process.unshare_files();
    }
    let files_process = process.files_owner_process();
    let mut inner = files_process.borrow_mut();
    inner.ensure_fd_flags_len();
    if inner.fd_table.is_empty() {
        return 0;
    }
    let end = core::cmp::min(last, inner.fd_table.len() - 1);
    if first > end {
        return 0;
    }

    let mut lock_keys = BTreeSet::new();
    for fd in first..=end {
        if set_cloexec {
            if inner.is_fd_open(fd) {
                inner.fd_flags[fd] |= FD_CLOEXEC;
            }
        } else {
            if let Some(file) = inner.fd_table[fd].as_ref() {
                if let Some(key) = file_lock_key(file) {
                    lock_keys.insert(key);
                }
            }
            let _ = inner.clear_fd(fd);
        }
    }
    drop(inner);
    if !set_cloexec {
        let owner_pid = current_process().getpid();
        for key in lock_keys {
            remove_process_record_locks_for_key(owner_pid, key);
            remove_owner_file_lease_for_key(owner_pid, key);
        }
    }
    0
}

/// Creates a pipe pair and installs both ends into the caller's fd table.
pub fn syscall_pipe2(pipefd: usize, _flags: usize) -> isize {
    let process = current_files_process();
    let token = get_current_token();
    let (pipe_read, pipe_write) = make_pipe();

    let mut inner = process.borrow_mut();
    let Some(read_fd) = inner.alloc_fd() else {
        return err(SyscallError::EMFILE);
    };
    inner.fd_table[read_fd] = Some(pipe_read);
    let Some(write_fd) = inner.alloc_fd() else {
        let _ = inner.clear_fd(read_fd);
        return err(SyscallError::EMFILE);
    };
    inner.fd_table[write_fd] = Some(pipe_write);
    let mut fd_flags = 0u32;
    if (_flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    if (_flags & O_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK as u32;
    }
    inner.fd_flags[read_fd] = fd_flags;
    inner.fd_flags[write_fd] = fd_flags;
    // Drop PCB borrow before user-memory writes: uaccess may need to resolve
    // lazy/COW pages via `process.try_borrow_mut()`.
    drop(inner);

    // Linux ABI: pipefd points to `int pipefd[2]` (i32).
    if try_write_user_value(token, pipefd as *mut i32, &(read_fd as i32)).is_err()
        || try_write_user_value(
            token,
            (pipefd + core::mem::size_of::<i32>()) as *mut i32,
            &(write_fd as i32),
        )
        .is_err()
    {
        let mut inner = process.borrow_mut();
        let _ = inner.clear_fd(read_fd);
        let _ = inner.clear_fd(write_fd);
        return err(SyscallError::EFAULT);
    }
    0
}

/// Duplicates a file descriptor into the lowest-numbered free slot.
pub fn syscall_dup(oldfd: usize) -> isize {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let file = fd_file!(inner, oldfd);
    inner.ensure_fd_flags_len();
    let old_flags = inner.fd_flags[oldfd];
    let Some(newfd) = inner.alloc_fd() else {
        return err(SyscallError::EMFILE);
    };
    inner.fd_table[newfd] = Some(file);
    inner.fd_flags[newfd] = old_flags & !FD_CLOEXEC;
    newfd as isize
}

/// Duplicates or replaces a file descriptor with optional `O_CLOEXEC` handling.
pub fn syscall_dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    if (flags & !O_CLOEXEC) != 0 {
        return err(SyscallError::EINVAL);
    }
    if oldfd == newfd {
        return err(SyscallError::EINVAL);
    }
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    if newfd >= inner.rlimits.rlimit_nofile_cur as usize {
        return err(SyscallError::EBADF);
    }
    let file = fd_file!(inner, oldfd);
    let owner_pid = current_process().getpid();
    let mut replaced_lock_key = None;
    if inner.is_fd_open(newfd) {
        replaced_lock_key = inner.fd_table[newfd].as_ref().and_then(file_lock_key);
        let _ = inner.clear_fd(newfd);
    }
    if let Some(key) = replaced_lock_key {
        remove_process_record_locks_for_key(owner_pid, key);
        remove_owner_file_lease_for_key(owner_pid, key);
    }
    inner.ensure_fd_flags_len();
    let old_flags = inner.fd_flags[oldfd];
    while inner.fd_table.len() <= newfd {
        inner.fd_table.push(None);
        inner.fd_flags.push(0);
    }
    inner.fd_table[newfd] = Some(file);
    let mut new_flags = old_flags;
    if (flags & O_CLOEXEC) != 0 {
        new_flags |= FD_CLOEXEC;
    } else {
        new_flags &= !FD_CLOEXEC;
    }
    inner.fd_flags[newfd] = new_flags;
    newfd as isize
}
