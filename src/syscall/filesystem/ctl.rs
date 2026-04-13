use super::{
    ACCT_COMM, ACCT_STATE, AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW,
    Acct, AcctState, Arc, AtPath, ClassifiedAbsPath,
    FILE_LEASES, FileLockKey,
    OSInode,
    ProcessControlBlock, PseudoDir,
    RECORD_LOCKS, RECORD_LOCK_WAITERS, String,
    SyscallError, TaskControlBlock, Vec,
    apply_chown_to_inode,
    busybox_exists, classify_current_abs_path, clear_record_lock_waiting,
    current_cwd_path, current_effective_uid_gid,
    current_fsuid_gid, current_in_group, current_process,
    current_real_uid_gid, do_fchmodat,
    empty_path_fd_for_at_op, err, ext4_lock,
    fd_has_o_path, find_path_in_roots,
    get_current_token, get_fd_file, get_time_ms,
    inode_mode_allows, inode_mode_allows_uid_gid,
    is_privileged_or_owner,
    logical_path_for_open_fd, maybe_dispatch_proc_fd_at,
    mount_note_path_access, normalize_path, open_pseudo,
    pseudo_path_exists_result, read_user_cstring,
    resolve_abs_path, resolve_at_inode, resolve_at_path, resolve_final_symlink_abs_path,
    resolve_final_symlink_abs_path_locked, rofs_for_path,
    should_try_busybox_applet_path,
    wake_record_lock_waiters,
};

pub fn syscall_acct(pathname: usize) -> isize {
    if current_effective_uid_gid().0 != 0 {
        return err(SyscallError::EPERM);
    }
    if pathname == 0 {
        *ACCT_STATE.lock() = None;
        return 0;
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    let trailing_slash = path.len() > 1 && path.ends_with('/');
    if rofs_for_path(AT_FDCWD, &path) {
        return err(SyscallError::EROFS);
    }
    let at = match resolve_at_path(AT_FDCWD, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let AtPath::PseudoAbs(_) = &at {
        return err(SyscallError::EACCES);
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, true) {
        Ok(inode) => inode,
        Err(e) => return e,
    };
    if inode.is_dir() {
        return err(SyscallError::EISDIR);
    }
    if trailing_slash {
        return err(SyscallError::ENOTDIR);
    }
    if !inode.is_file() {
        return err(SyscallError::EACCES);
    }
    if !inode_mode_allows_uid_gid(&inode, 2, fsuid, fsgid) {
        return err(SyscallError::EACCES);
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

fn acct_comm_from_argv(argv: &[String]) -> [u8; ACCT_COMM + 1] {
    let mut out = [0u8; ACCT_COMM + 1];
    let name = argv.get(0).map(|s| s.as_str()).unwrap_or("");
    let base = name.rsplit('/').next().unwrap_or("");
    let bytes = base.as_bytes();
    let n = core::cmp::min(bytes.len(), ACCT_COMM);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn acct_exitcode(exit_code: i32) -> u32 {
    if exit_code < 0 {
        (-exit_code as u32) & 0x7f
    } else {
        ((exit_code as u32) & 0xff) << 8
    }
}

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
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &record as *const Acct as *const u8,
            core::mem::size_of::<Acct>(),
        )
    };

    let _ext4_guard = ext4_lock();
    let offset = inode.size() as usize;
    let _ = inode.write_at(offset, bytes);
}

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

pub fn release_all_file_leases_for_owner(owner_pid: usize) {
    let mut table = FILE_LEASES.lock();
    table.retain(|_, lease| lease.owner_pid != owner_pid);
}


pub fn syscall_faccessat(dirfd: isize, pathname: usize, mode: usize, _flags: usize) -> isize {
    if mode & !0x7 != 0 {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    if busybox_exists() && should_try_busybox_applet_path(&path, false) {
        return 0;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if crate::fs::proc_readlink(abs).is_some() {
            return 0;
        }
        // Treat known pseudo nodes as always accessible.
        return if open_pseudo(abs).is_some() {
            0
        } else {
            err(SyscallError::ENOENT)
        };
    }

    let (uid, gid) = current_real_uid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, uid, gid, true) {
        Ok(v) => v,
        Err(e) if e == err(SyscallError::ENOENT) && matches!(path.as_str(), "busybox" | "./busybox") => {
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

    if (mode & 2) != 0 && rofs_for_path(dirfd, &path) {
        return err(SyscallError::EROFS);
    }
    if !inode_mode_allows_uid_gid(&inode, mode, uid, gid) {
        return err(SyscallError::EACCES);
    }
    if let Some(abs) = match resolve_abs_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    } {
        mount_note_path_access(&abs);
    }
    0
}

pub fn syscall_fchmod(fd: usize, mode: usize) -> isize {
    if fd_has_o_path(fd) {
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
        let _ext4_guard = ext4_lock();
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
    }
    0
}

pub fn syscall_fchmodat(dirfd: isize, pathname: usize, mode: usize, flags: usize) -> isize {
    do_fchmodat(dirfd, pathname, mode, flags, false)
}

pub fn syscall_fchmodat2(dirfd: isize, pathname: usize, mode: usize, flags: usize) -> isize {
    do_fchmodat(dirfd, pathname, mode, flags, true)
}

pub fn syscall_fchown(fd: usize, uid: usize, gid: usize) -> isize {
    if fd_has_o_path(fd) {
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
        let _ext4_guard = ext4_lock();
        let ret = apply_chown_to_inode(&inode, uid, gid);
        if ret != 0 {
            return ret;
        }
    }
    0
}

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
        return syscall_fchown(fd, uid, gid);
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(ret) = maybe_dispatch_proc_fd_at(abs, flags, |fd| syscall_fchown(fd, uid, gid))
        {
            return ret;
        }
        return pseudo_path_exists_result(abs);
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, follow_final) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if rofs_for_path(dirfd, &path) {
        return err(SyscallError::EROFS);
    }
    let ret = apply_chown_to_inode(&inode, uid, gid);
    if ret != 0 {
        return ret;
    }
    0
}

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
    if matches!(at, AtPath::PseudoAbs(_)) {
        return err(SyscallError::ENOTDIR);
    }

    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let candidate_abs = match &at {
        AtPath::Ext4Abs(abs) => abs.clone(),
        AtPath::Ext4Rel { .. } => normalize_path(&cwd, &path),
        AtPath::PseudoAbs(abs) => abs.clone(),
    };

    let (fsuid, fsgid) = current_fsuid_gid();
    let final_root = {
        let _ext4_guard = ext4_lock();
        let inode = match resolve_at_inode(&at, fsuid, fsgid, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if !inode.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        if !inode_mode_allows_uid_gid(&inode, 1, fsuid, fsgid) {
            return err(SyscallError::EACCES);
        }
        resolve_final_symlink_abs_path_locked(&candidate_abs)
    };

    // Capability check after pathname validation so permission errors surface
    // first, matching Linux/LTP expectations.
    let has_priv = {
        let inner = process.borrow_mut();
        inner.euid == 0
    };
    if !has_priv {
        return err(SyscallError::EPERM);
    }

    let mut inner = process.borrow_mut();
    // Linux chroot() updates "/" for this process but does not implicitly
    // retarget "."; callers that want both semantics must chdir("/") too.
    inner.root = final_root;
    0
}

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
    let cwd = { process.borrow_mut().cwd.clone() };
    let new_cwd = match &at {
        AtPath::Ext4Abs(abs) => abs.clone(),
        AtPath::Ext4Rel { .. } => normalize_path(&cwd, &path),
        AtPath::PseudoAbs(abs) => abs.clone(),
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

    let final_cwd = if matches!(at, AtPath::Ext4Abs(_) | AtPath::Ext4Rel { .. }) {
        let (fsuid, fsgid) = current_fsuid_gid();
        let _ext4_guard = ext4_lock();
        let inode = match resolve_at_inode(&at, fsuid, fsgid, true) {
            Ok(v) => v,
            Err(e) => {
                if crate::debug_config::DEBUG_SYSCALL {
                    let pid = process.getpid();
                    crate::println!(
                        "[chdir] pid={} resolve_at_inode err={} new_cwd='{}'",
                        pid,
                        e,
                        new_cwd
                    );
                }
                return e;
            }
        };
        if crate::debug_config::DEBUG_SYSCALL {
            let pid = process.getpid();
            crate::println!(
                "[chdir] pid={} inode={} mode=0o{:o} is_dir={} is_file={}",
                pid,
                inode.inode_num(),
                inode.mode(),
                inode.is_dir(),
                inode.is_file()
            );
        }
        if !inode.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        if !inode_mode_allows_uid_gid(&inode, 1, fsuid, fsgid) {
            return err(SyscallError::EACCES);
        }
        resolve_final_symlink_abs_path(&new_cwd)
    } else if let Some(node) = open_pseudo(&new_cwd) {
        if node.as_any().downcast_ref::<PseudoDir>().is_none() {
            return err(SyscallError::ENOTDIR);
        }
        new_cwd
    } else {
        return err(SyscallError::ENOENT);
    };

    process.borrow_mut().cwd = final_cwd;
    0
}

pub fn syscall_fchdir(fd: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return err(SyscallError::EBADF);
    };

    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        let new_cwd = String::from(pdir.path());
        current_process().borrow_mut().cwd = new_cwd;
        return 0;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::ENOTDIR);
    };
    let inode = os_inode.ext4_inode();
    {
        let _ext4_guard = ext4_lock();
        if !inode.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        if !inode_mode_allows(&inode, 1) {
            return err(SyscallError::EACCES);
        }
    }

    let fallback_cwd = current_cwd_path();
    let target_path = logical_path_for_open_fd(fd, &file, &fallback_cwd);
    let final_cwd = if matches!(classify_current_abs_path(&target_path), ClassifiedAbsPath::Pseudo(_))
    {
        target_path
    } else {
        resolve_final_symlink_abs_path(&target_path)
    };
    current_process().borrow_mut().cwd = final_cwd;
    0
}

