use super::{
    ACCT_COMM, ACCT_STATE, AT_EACCESS, AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Acct,
    AcctState, Arc, FILE_LEASES, FileLockKey, OSInode, ProcessControlBlock, RECORD_LOCK_WAITERS,
    RECORD_LOCKS, String, SyscallError, TaskControlBlock, Vec, apply_chmod_to_vfs_path,
    apply_chown_to_inode, apply_chown_to_vfs_path, apply_process_root, busybox_exists,
    clear_ext4_path_cache, clear_record_lock_waiting, current_cwd_path, current_effective_uid_gid,
    current_fsuid_gid, current_in_group, current_process, current_real_uid_gid, do_fchmodat,
    empty_path_fd_for_at_op, err, fd_has_o_path, find_path_in_roots, get_current_token,
    get_fd_file, get_time_ms, inode_mode_allows_uid_gid, is_privileged_or_owner,
    mount_note_path_access, normalize_path, read_user_cstring, resolve_abs_path, resolve_at_inode,
    resolve_at_path, resolve_at_vfs_path, should_try_busybox_applet_path, vfs_mode_allows_uid_gid,
    wake_record_lock_waiters, with_ext4_inode_read, with_ext4_inode_write,
};
use crate::fs::vfs::{VfsNodeKind, VfsPath};
use crate::fs::vfs_path_is_ext4;

fn validate_vfs_directory(path: &VfsPath, uid: u32, gid: u32) -> Result<(), isize> {
    let metadata = path.node().metadata().map_err(super::map_vfs_error)?;
    if metadata.kind != VfsNodeKind::Directory {
        return Err(err(SyscallError::ENOTDIR));
    }
    if !vfs_mode_allows_uid_gid(metadata, 1, uid, gid) {
        return Err(err(SyscallError::EACCES));
    }
    Ok(())
}

/// Enables or disables BSD-style process accounting on an ext4 regular file.
/// Note:
/// Basically It just operates on the global ACC_STATE varaible
pub fn syscall_acct(pathname: usize) -> isize {
    // only sudo user can do this.
    if current_effective_uid_gid().0 != 0 {
        return err(SyscallError::EPERM);
    }
    // if NULL, we clear the acct state
    if pathname == 0 {
        *ACCT_STATE.lock() = None;
        return 0;
    }
    // read the pathname from the user space
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    let trailing_slash = path.len() > 1 && path.ends_with('/');
    let at = match resolve_at_path(AT_FDCWD, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (fsuid, fsgid) = current_fsuid_gid();
    let vfs_path = match resolve_at_vfs_path(&at, fsuid, fsgid, true) {
        Ok(path) => path,
        Err(error) => return error,
    };
    if vfs_path.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    let inode = match resolve_at_inode(&at, fsuid, fsgid, true) {
        Ok(inode) => inode,
        Err(e) => return e,
    };
    let validation_error = with_ext4_inode_read(&inode, || {
        if inode.is_dir() {
            return Some(err(SyscallError::EISDIR));
        }
        if trailing_slash {
            return Some(err(SyscallError::ENOTDIR));
        }
        if !inode.is_file() {
            return Some(err(SyscallError::EACCES));
        }
        if !inode_mode_allows_uid_gid(&inode, 2, fsuid, fsgid) {
            return Some(err(SyscallError::EACCES));
        }
        None
    });
    if let Some(error) = validation_error {
        return error;
    }
    *ACCT_STATE.lock() = Some(AcctState {
        inode: Arc::clone(&inode),
    });
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        crate::println!("[fs] acct(pid={}) path='{}' ok", pid, path);
    }
    0
}

/// Derives the fixed-width `ac_comm` field from the process `argv[0]`.
fn acct_comm_from_argv(argv: &[String]) -> [u8; ACCT_COMM + 1] {
    let mut out = [0u8; ACCT_COMM + 1];
    let name = argv.get(0).map(|s| s.as_str()).unwrap_or("");
    let base = name.rsplit('/').next().unwrap_or("");
    let bytes = base.as_bytes();
    let n = core::cmp::min(bytes.len(), ACCT_COMM);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Encodes a task exit status into the on-disk accounting record format.
fn acct_exitcode(exit_code: i32) -> u32 {
    if exit_code < 0 {
        (-exit_code as u32) & 0x7f
    } else {
        ((exit_code as u32) & 0xff) << 8
    }
}

/// Appends one accounting record for a process that is exiting.
/// use this to account the process
pub fn acct_process_exit(process: &Arc<ProcessControlBlock>, exit_code: i32) {
    let inode = {
        let state = ACCT_STATE.lock();
        let Some(state) = state.as_ref() else {
            return;
        };
        Arc::clone(&state.inode)
    };

    let (argv, uid, gid, start_time_ms) = {
        let inner = process.borrow_mut();
        (
            inner.argv.clone(),
            inner.uid,
            inner.gid,
            inner.start_time_ms,
        )
    };

    let now_sec = crate::syscall::time_sys::realtime_now_seconds();
    let elapsed_ms = get_time_ms().saturating_sub(start_time_ms);
    let start_sec = now_sec.saturating_sub((elapsed_ms / 1000) as u64);
    let record = Acct {
        ac_flag: 0,
        ac_uid: uid as u16,
        ac_gid: gid as u16,
        ac_tty: 0,
        ac_btime: start_sec.min(u32::MAX as u64) as u32,
        ac_utime: 0,
        ac_stime: 0,
        ac_etime: 0,
        ac_mem: 0,
        ac_io: 0,
        ac_rw: 0,
        ac_minflt: 0,
        ac_majflt: 0,
        ac_swaps: 0,
        ac_exitcode: acct_exitcode(exit_code),
        ac_comm: acct_comm_from_argv(&argv),
        ac_pad: [0; 10],
    };
    // SAFETY: record is a stack-local struct with known layout; length equals size_of::<Acct>().
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &record as *const Acct as *const u8,
            core::mem::size_of::<Acct>(),
        )
    };

    with_ext4_inode_write(&inode, || {
        let offset = inode.size() as usize;
        let _ = inode.write_at(offset, bytes);
    });
}

/// Counts how many record-lock wait queues currently reference the given task.
pub fn debug_count_record_lock_waiters_for_task(task: &Arc<TaskControlBlock>) -> usize {
    RECORD_LOCK_WAITERS
        .lock()
        .values()
        .map(|queue| {
            queue
                .iter()
                .filter(|waiter| Arc::ptr_eq(waiter, task))
                .count()
        })
        .sum()
}

/// Releases all POSIX record locks owned by the given process and wakes waiters.
pub fn release_all_record_locks_for_owner(owner_pid: usize) {
    clear_record_lock_waiting(owner_pid);
    let changed_keys = {
        let mut table = RECORD_LOCKS.lock();
        let mut changed = Vec::new();
        let keys: Vec<FileLockKey> = table.keys().copied().collect();
        for key in keys {
            let mut remove_entry = false;
            if let Some(locks) = table.get_mut(&key) {
                let before = locks.len();
                locks.retain(|lock| lock.owner_pid != owner_pid);
                if locks.len() != before {
                    changed.push(key);
                }
                remove_entry = locks.is_empty();
            }
            if remove_entry {
                table.remove(&key);
            }
        }
        changed
    };
    for key in changed_keys {
        wake_record_lock_waiters(key);
    }
}

/// Releases every file lease owned by the given process.
pub fn release_all_file_leases_for_owner(owner_pid: usize) {
    let mut table = FILE_LEASES.lock();
    table.retain(|_, lease| lease.owner_pid != owner_pid);
}

fn do_faccessat(dirfd: isize, pathname: usize, mode: usize, flags: usize) -> isize {
    let valid_flags = AT_EACCESS | AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    if mode & !0x7 != 0 {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        if (flags & AT_EMPTY_PATH) == 0 {
            return err(SyscallError::ENOENT);
        }
        if dirfd < 0 {
            return err(SyscallError::EBADF);
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return err(SyscallError::EBADF);
        };
        let (uid, gid) = if (flags & AT_EACCESS) != 0 {
            current_effective_uid_gid()
        } else {
            current_real_uid_gid()
        };
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            if mode & 2 != 0 && os_inode.readonly_fs() {
                return err(SyscallError::EROFS);
            }
            let inode = os_inode.ext4_inode();
            return if with_ext4_inode_read(&inode, || {
                inode_mode_allows_uid_gid(&inode, mode, uid, gid)
            }) {
                0
            } else {
                err(SyscallError::EACCES)
            };
        }
        let Some(path) = file.object_path() else {
            return 0;
        };
        if mode & 2 != 0 && path.mount().flags().is_read_only() {
            return err(SyscallError::EROFS);
        }
        let metadata = match path.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return super::map_vfs_error(error),
        };
        return if vfs_mode_allows_uid_gid(metadata, mode, uid, gid) {
            0
        } else {
            err(SyscallError::EACCES)
        };
    }
    if busybox_exists() && should_try_busybox_applet_path(&path, false) {
        return 0;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (uid, gid) = if (flags & AT_EACCESS) != 0 {
        current_effective_uid_gid()
    } else {
        current_real_uid_gid()
    };
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let vfs_path = match resolve_at_vfs_path(&at, uid, gid, follow_final) {
        Ok(path) if !vfs_path_is_ext4(&path) => {
            if mode & 2 != 0 && path.mount().flags().is_read_only() {
                return err(SyscallError::EROFS);
            }
            let metadata = match path.node().metadata() {
                Ok(metadata) => metadata,
                Err(error) => return super::map_vfs_error(error),
            };
            return if vfs_mode_allows_uid_gid(metadata, mode, uid, gid) {
                0
            } else {
                err(SyscallError::EACCES)
            };
        }
        Ok(path) => path,
        Err(error) => return error,
    };
    {
        let inode = match resolve_at_inode(&at, uid, gid, follow_final) {
            Ok(v) => v,
            Err(e)
                if e == err(SyscallError::ENOENT)
                    && matches!(path.as_str(), "busybox" | "./busybox") =>
            {
                let candidates = [
                    "/musl/busybox",
                    "/glibc/busybox",
                    "/bin/busybox",
                    "/busybox",
                ];
                let mut found = None;
                for cand in candidates {
                    if let Some(inode) = find_path_in_roots(cand) {
                        found = Some(inode);
                        break;
                    }
                }
                match found {
                    Some(v) => v,
                    None => return err(SyscallError::ENOENT),
                }
            }
            Err(e) => return e,
        };

        if mode & 2 != 0 && vfs_path.mount().flags().is_read_only() {
            return err(SyscallError::EROFS);
        }
        if !with_ext4_inode_read(&inode, || inode_mode_allows_uid_gid(&inode, mode, uid, gid)) {
            return err(SyscallError::EACCES);
        }
    }
    if let Some(abs) = match resolve_abs_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    } {
        mount_note_path_access(&abs);
    }
    0
}

/// Checks pathname accessibility using Linux-like `faccessat(2)` permission rules.
pub fn syscall_faccessat(dirfd: isize, pathname: usize, mode: usize, _flags: usize) -> isize {
    do_faccessat(dirfd, pathname, mode, 0)
}

/// `faccessat2(2)` adds reliable flag handling to `faccessat`.
pub fn syscall_faccessat2(dirfd: isize, pathname: usize, mode: usize, flags: usize) -> isize {
    do_faccessat(dirfd, pathname, mode, flags)
}

fn chmod_fd(fd: usize, mode: usize, allow_o_path: bool) -> isize {
    if fd_has_o_path(fd) && !allow_o_path {
        return err(SyscallError::EBADF);
    }
    let Some(file) = get_fd_file(fd) else {
        return err(SyscallError::EBADF);
    };
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if os_inode.readonly_fs() {
            return err(SyscallError::EROFS);
        }
        let inode = os_inode.ext4_inode();
        let result = with_ext4_inode_write(&inode, || {
            let (uid, _gid) = current_effective_uid_gid();
            if !is_privileged_or_owner(uid, &inode) {
                return err(SyscallError::EPERM);
            }
            let mut new_mode = (mode as u16) & 0o7777;
            // Linux clears S_ISGID when an unprivileged caller is outside file group.
            if uid != 0 && (new_mode & 0o2000) != 0 && !current_in_group(inode.gid()) {
                new_mode &= !0o2000;
            }
            inode.set_mode(new_mode);
            clear_ext4_path_cache();
            0
        });
        if result != 0 {
            return result;
        }
        return 0;
    }
    if let Some(path) = file.object_path() {
        return apply_chmod_to_vfs_path(path, mode);
    }
    0
}

/// Changes mode bits on the inode referenced by an open file descriptor.
pub fn syscall_fchmod(fd: usize, mode: usize) -> isize {
    chmod_fd(fd, mode, false)
}

pub(crate) fn fchmod_fd_for_at_empty_path(fd: usize, mode: usize) -> isize {
    chmod_fd(fd, mode, true)
}

/// Compatibility wrapper for `fchmodat(2)` that delegates to `fchmodat2`.
pub fn syscall_fchmodat(dirfd: isize, pathname: usize, mode: usize, flags: usize) -> isize {
    do_fchmodat(dirfd, pathname, mode, flags, false)
}

/// Changes mode bits on a path, including `AT_EMPTY_PATH` and symlink-control handling.
pub fn syscall_fchmodat2(dirfd: isize, pathname: usize, mode: usize, flags: usize) -> isize {
    do_fchmodat(dirfd, pathname, mode, flags, true)
}

fn chown_fd(fd: usize, uid: usize, gid: usize, allow_o_path: bool) -> isize {
    if fd_has_o_path(fd) && !allow_o_path {
        return err(SyscallError::EBADF);
    }
    let Some(file) = get_fd_file(fd) else {
        return err(SyscallError::EBADF);
    };
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if os_inode.readonly_fs() {
            return err(SyscallError::EROFS);
        }
        let inode = os_inode.ext4_inode();
        let ret = apply_chown_to_inode(&inode, uid, gid);
        if ret != 0 {
            return ret;
        }
        return 0;
    }
    if let Some(path) = file.object_path() {
        return apply_chown_to_vfs_path(path, uid, gid);
    }
    0
}

/// Changes ownership on the inode referenced by an open file descriptor.
pub fn syscall_fchown(fd: usize, uid: usize, gid: usize) -> isize {
    chown_fd(fd, uid, gid, false)
}

pub(crate) fn fchown_fd_for_at_empty_path(fd: usize, uid: usize, gid: usize) -> isize {
    chown_fd(fd, uid, gid, true)
}

/// Changes ownership on a pathname, with support for `dirfd` and proc-fd empty paths.
pub fn syscall_fchownat(
    dirfd: isize,
    pathname: usize,
    uid: usize,
    gid: usize,
    flags: usize,
) -> isize {
    let valid_flags = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };

    if path.is_empty() {
        let fd = match empty_path_fd_for_at_op(dirfd, flags) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return if (flags & AT_EMPTY_PATH) != 0 {
            fchown_fd_for_at_empty_path(fd, uid, gid)
        } else {
            syscall_fchown(fd, uid, gid)
        };
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let vfs_path = match resolve_at_vfs_path(&at, fsuid, fsgid, follow_final) {
        Ok(path) if !vfs_path_is_ext4(&path) => {
            return apply_chown_to_vfs_path(&path, uid, gid);
        }
        Ok(path) => path,
        Err(error) => return error,
    };
    let inode = match resolve_at_inode(&at, fsuid, fsgid, follow_final) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if vfs_path.mount().flags().is_read_only() {
        return err(SyscallError::EROFS);
    }
    let ret = apply_chown_to_inode(&inode, uid, gid);
    if ret != 0 {
        return ret;
    }
    0
}

/// Moves the calling process into a new filesystem root directory.
pub fn syscall_chroot(pathname: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }

    let at = match resolve_at_path(AT_FDCWD, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let process = current_process();
    let cwd = process.fs_struct().cwd_display();
    let candidate_abs = if path.starts_with('/') {
        apply_process_root(&normalize_path("/", &path))
    } else {
        normalize_path(&cwd, &path)
    };

    let (fsuid, fsgid) = current_fsuid_gid();
    let vfs_path = match resolve_at_vfs_path(&at, fsuid, fsgid, true) {
        Ok(path) => path,
        Err(e) => return e,
    };
    if let Err(e) = validate_vfs_directory(&vfs_path, fsuid, fsgid) {
        return e;
    }
    let final_root = vfs_path
        .mount()
        .owner_namespace()
        .and_then(|namespace| namespace.path_string(&vfs_path).ok())
        .unwrap_or(candidate_abs);

    // Capability check after pathname validation so permission errors surface
    // first, matching Linux/LTP expectations.
    let has_priv = {
        let inner = process.borrow_mut();
        inner.euid == 0
    };
    if !has_priv {
        return err(SyscallError::EPERM);
    }

    // Linux chroot() updates "/" for this process but does not implicitly
    // retarget "."; callers that want both semantics must chdir("/") too.
    process
        .fs_struct()
        .set_root_with_display(vfs_path, &final_root);
    0
}

/// Changes the calling process's current working directory by pathname.
pub fn syscall_chdir(pathname: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    let at = match resolve_at_path(AT_FDCWD, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let process = current_process();
    let cwd = process.fs_struct().cwd_display();
    let new_cwd = if path.starts_with('/') {
        apply_process_root(&normalize_path("/", &path))
    } else {
        normalize_path(&cwd, &path)
    };
    if crate::debug_config::DEBUG_SYSCALL {
        let pid = process.getpid();
        crate::println!(
            "[chdir] pid={} cwd='{}' path='{}' new_cwd='{}'",
            pid,
            cwd,
            path,
            new_cwd
        );
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let vfs_path = match resolve_at_vfs_path(&at, fsuid, fsgid, true) {
        Ok(path) => path,
        Err(e) => return e,
    };
    if let Err(e) = validate_vfs_directory(&vfs_path, fsuid, fsgid) {
        return e;
    }
    let final_cwd = vfs_path
        .mount()
        .owner_namespace()
        .and_then(|namespace| namespace.path_string(&vfs_path).ok())
        .unwrap_or(new_cwd);

    process
        .fs_struct()
        .set_cwd_with_display(vfs_path, &final_cwd);
    0
}

/// Changes the current working directory using an already opened directory fd.
pub fn syscall_fchdir(fd: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return err(SyscallError::EBADF);
    };

    let Some(path) = file.object_path() else {
        return err(SyscallError::ENOTDIR);
    };
    let (fsuid, fsgid) = current_fsuid_gid();
    if let Err(e) = validate_vfs_directory(path, fsuid, fsgid) {
        return e;
    }
    let display = path
        .mount()
        .owner_namespace()
        .and_then(|namespace| namespace.path_string(path).ok())
        .or_else(|| file.logical_path_hint().map(String::from))
        .unwrap_or_else(current_cwd_path);
    current_process()
        .fs_struct()
        .set_cwd_with_display(path.clone(), &display);
    0
}
