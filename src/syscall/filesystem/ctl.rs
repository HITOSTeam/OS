use super::{
    ACCT_COMM, ACCT_STATE, AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW,
    Acct, AcctState, Arc, AtPath, ClassifiedAbsPath, FD_CLOEXEC,
    FILE_LEASES, FcntlFlock, FcntlOwnerEx, FileLockKey,
    OSInode, O_APPEND, O_ASYNC, O_DIRECT, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_WRONLY,
    Pipe, ProcessControlBlock, PseudoDir, PseudoShmFile,
    RECORD_LOCKS, RECORD_LOCK_WAITERS, RecordLockOwner, String,
    SyscallError, TaskControlBlock, Vec, WaitingRecordLock,
    apply_chown_to_inode, apply_record_lock_for_owner, block_current_and_run_next,
    busybox_exists, classify_current_abs_path, clear_record_lock_waiting,
    collect_conflict_process_owners, current_cwd_path, current_effective_uid_gid,
    current_files_process, current_fsuid_gid, current_in_group, current_process,
    current_real_uid_gid, current_task, detect_record_lock_deadlock, do_fchmodat,
    empty_path_fd_for_at_op, enqueue_record_lock_waiter, err, ext4_lock,
    fd_has_o_path, file_lock_key, find_path_in_roots, first_conflicting_lock,
    get_current_token, get_fd_file, get_file_lease_type, get_time_ms,
    has_pending_unmasked_signal, inode_mode_allows_uid_gid, lock_conflicts,
    lock_range_from_flock, logical_path_for_open_fd, maybe_dispatch_proc_fd_at,
    mount_note_path_access, normalize_path, ofd_lock_owner_id, open_pseudo,
    pseudo_path_exists_result, read_user_cstring, remove_record_lock_waiter,
    resolve_abs_path, resolve_at_inode, resolve_at_path, resolve_final_symlink_abs_path,
    resolve_final_symlink_abs_path_locked, rofs_for_path, set_file_lease,
    set_record_lock_waiting, should_try_busybox_applet_path, try_read_user_value,
    try_write_user_value, wake_record_lock_waiters,
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

pub fn syscall_fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    // Minimal `fcntl(2)` support for busybox/ash/glibc startup.
    const F_DUPFD: usize = 0;
    const F_GETFD: usize = 1;
    const F_SETFD: usize = 2;
    const F_GETFL: usize = 3;
    const F_SETFL: usize = 4;
    const F_GETLK: usize = 5;
    const F_SETLK: usize = 6;
    const F_SETLKW: usize = 7;
    const F_SETOWN: usize = 8;
    const F_GETOWN: usize = 9;
    const F_SETSIG: usize = 10;
    const F_GETSIG: usize = 11;
    const F_SETOWN_EX: usize = 15;
    const F_GETOWN_EX: usize = 16;
    const F_OFD_GETLK: usize = 36;
    const F_OFD_SETLK: usize = 37;
    const F_OFD_SETLKW: usize = 38;
    const F_SETLEASE: usize = 1024;
    const F_GETLEASE: usize = 1025;
    const F_DUPFD_CLOEXEC: usize = 1030;
    const F_SETPIPE_SZ: usize = 1031;
    const F_GETPIPE_SZ: usize = 1032;
    const F_ADD_SEALS: usize = 1033;
    const F_GET_SEALS: usize = 1034;
    const PROT_WRITE: usize = 0x2;
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    const F_OWNER_TID: i32 = 0;
    const F_OWNER_PID: i32 = 1;
    const F_OWNER_PGRP: i32 = 2;

    let ret = match cmd {
        F_GETFD => {
            let process = current_files_process();
            let mut inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            inner.ensure_fd_flags_len();
            if (inner.fd_flags[fd] & FD_CLOEXEC) != 0 {
                FD_CLOEXEC as isize
            } else {
                0
            }
        }
        F_SETFD => {
            let process = current_files_process();
            let mut inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            inner.ensure_fd_flags_len();
            let mut cur = inner.fd_flags[fd];
            if (arg as u32 & FD_CLOEXEC) != 0 {
                cur |= FD_CLOEXEC;
            } else {
                cur &= !FD_CLOEXEC;
            }
            inner.fd_flags[fd] = cur;
            0
        }
        F_SETFL => {
            let process = current_files_process();
            let mut inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            inner.ensure_fd_flags_len();
            let mut cur = inner.fd_flags[fd];
            if (arg & O_NONBLOCK) != 0 {
                cur |= O_NONBLOCK as u32;
            } else {
                cur &= !(O_NONBLOCK as u32);
            }
            if (arg & O_ASYNC) != 0 {
                cur |= O_ASYNC as u32;
            } else {
                cur &= !(O_ASYNC as u32);
            }
            inner.fd_flags[fd] = cur;
            if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
                pipe.set_async_enabled((cur & O_ASYNC as u32) != 0);
            }
            0
        }
        F_GETFL => {
            let process = current_files_process();
            let mut inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            inner.ensure_fd_flags_len();
            let cur_flags = inner.fd_flags[fd];
            let mut flags = match (file.readable(), file.writable()) {
                (true, false) => O_RDONLY,
                (false, true) => O_WRONLY,
                (true, true) => O_RDWR,
                (false, false) => O_RDONLY,
            };
            if (cur_flags & O_NONBLOCK as u32) != 0 {
                flags |= O_NONBLOCK;
            }
            if (cur_flags & O_ASYNC as u32) != 0 {
                flags |= O_ASYNC;
            }
            if (cur_flags & O_PATH as u32) != 0 {
                flags |= O_PATH;
            }
            if (cur_flags & O_DIRECT as u32) != 0 {
                flags |= O_DIRECT;
            }
            if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
                if os_inode.append() {
                    flags |= O_APPEND;
                }
            }
            flags as isize
        }
        F_SETOWN => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            let owner = arg as i32;
            let (owner_type, owner_pid) = if owner < 0 {
                let Some(pid) = owner.checked_neg() else {
                    return err(SyscallError::EINVAL);
                };
                (F_OWNER_PGRP, pid)
            } else {
                let current_ns_id = current_process().pid_namespace_id();
                let owner_pid = if current_ns_id == 0 {
                    owner
                } else if let Some(process) =
                    crate::task::resolve_process_in_pid_namespace(current_ns_id, owner as usize)
                {
                    process.getpid() as i32
                } else {
                    return err(SyscallError::ESRCH);
                };
                (F_OWNER_PID, owner_pid)
            };
            match pipe.set_async_owner(owner_type, owner_pid) {
                Ok(()) => match pipe.set_async_fd(fd as i32) {
                    Ok(()) => 0,
                    Err(e) => e,
                },
                Err(e) => e,
            }
        }
        F_GETOWN => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            let (owner_type, owner_pid) = pipe.get_async_owner();
            if owner_type == F_OWNER_PGRP {
                -(owner_pid as isize)
            } else {
                owner_pid as isize
            }
        }
        F_SETOWN_EX => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let token = get_current_token();
            let own = match try_read_user_value::<FcntlOwnerEx>(token, arg as *const FcntlOwnerEx) {
                Some(v) => v,
                None => return err(SyscallError::EFAULT),
            };
            if !matches!(own.type_, F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP) {
                return err(SyscallError::EINVAL);
            }
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            let (owner_type, owner_pid) = if matches!(own.type_, F_OWNER_TID | F_OWNER_PID) {
                let current_ns_id = current_process().pid_namespace_id();
                let owner_pid = if current_ns_id == 0 {
                    own.pid
                } else if let Some(process) =
                    crate::task::resolve_process_in_pid_namespace(current_ns_id, own.pid as usize)
                {
                    process.getpid() as i32
                } else {
                    return err(SyscallError::ESRCH);
                };
                (own.type_, owner_pid)
            } else {
                (own.type_, own.pid)
            };
            match pipe.set_async_owner(owner_type, owner_pid) {
                Ok(()) => match pipe.set_async_fd(fd as i32) {
                    Ok(()) => 0,
                    Err(e) => e,
                },
                Err(e) => e,
            }
        }
        F_GETOWN_EX => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            let (owner_type, owner_pid) = pipe.get_async_owner();
            let own = FcntlOwnerEx {
                type_: owner_type,
                pid: owner_pid,
            };
            let token = get_current_token();
            if try_write_user_value(token, arg as *mut FcntlOwnerEx, &own).is_err() {
                return err(SyscallError::EFAULT);
            }
            0
        }
        F_SETSIG => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            let sig = arg as i32;
            match pipe.set_async_signal(sig) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        F_GETSIG => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            pipe.get_async_signal() as isize
        }
        F_SETLEASE => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(key) = file_lock_key(&file) else {
                return err(SyscallError::EINVAL);
            };
            let owner_pid = current_process().getpid();
            set_file_lease(key, owner_pid, arg as i16, &file)
        }
        F_GETLEASE => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(key) = file_lock_key(&file) else {
                return err(SyscallError::EINVAL);
            };
            let owner_pid = current_process().getpid();
            get_file_lease_type(key, owner_pid) as isize
        }
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);

            let token = get_current_token();
            let flock = match try_read_user_value::<FcntlFlock>(token, arg as *const FcntlFlock) {
                Some(v) => v,
                None => return err(SyscallError::EFAULT),
            };
            let is_ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
            if is_ofd && flock.l_pid != 0 {
                return err(SyscallError::EINVAL);
            }
            let Some(key) = file_lock_key(&file) else {
                return err(SyscallError::EINVAL);
            };
            let owner_pid = current_process().getpid();
            let owner = if is_ofd {
                RecordLockOwner::OpenFile(ofd_lock_owner_id(&file))
            } else {
                RecordLockOwner::Process(owner_pid)
            };

            let (start, end) = match lock_range_from_flock(&file, &flock) {
                Ok(range) => range,
                Err(e) => return e,
            };

            match flock.l_type {
                F_RDLCK => {
                    if !file.readable() {
                        return err(SyscallError::EBADF);
                    }
                }
                F_WRLCK => {
                    if !file.writable() {
                        return err(SyscallError::EBADF);
                    }
                }
                F_UNLCK => {}
                _ => return err(SyscallError::EINVAL),
            }

            if matches!(cmd, F_GETLK | F_OFD_GETLK) {
                let mut out = flock;
                let conflict = {
                    let table = RECORD_LOCKS.lock();
                    table.get(&key).and_then(|locks| {
                        first_conflicting_lock(locks, flock.l_type, start, end, owner)
                    })
                };
                if let Some(lock) = conflict {
                    out.l_type = lock.lock_type;
                    out.l_whence = 0;
                    out.l_start = lock.start;
                    out.l_len = match lock.end {
                        Some(lock_end) => lock_end.saturating_sub(lock.start).saturating_add(1),
                        None => 0,
                    };
                    out.l_pid = match lock.owner {
                        RecordLockOwner::Process(pid) => pid as i32,
                        RecordLockOwner::OpenFile(_) => -1,
                    };
                } else {
                    out.l_type = F_UNLCK;
                    out.l_pid = 0;
                }
                if try_write_user_value(token, arg as *mut FcntlFlock, &out).is_err() {
                    return err(SyscallError::EFAULT);
                }
                0
            } else {
                let blocking = matches!(cmd, F_SETLKW | F_OFD_SETLKW);
                if !is_ofd {
                    clear_record_lock_waiting(owner_pid);
                }
                let waiter_task = if blocking { current_task() } else { None };
                let ret = loop {
                    let mut conflict_exists = false;
                    let mut conflict_owners = Vec::new();
                    let mut should_wake_waiters = false;
                    {
                        let mut table = RECORD_LOCKS.lock();
                        let locks = table.entry(key).or_insert_with(Vec::new);
                        conflict_exists = locks
                            .iter()
                            .any(|lock| lock_conflicts(flock.l_type, start, end, owner, lock));
                        if conflict_exists && !is_ofd {
                            conflict_owners = collect_conflict_process_owners(
                                locks,
                                flock.l_type,
                                start,
                                end,
                                owner_pid,
                            );
                        }
                        if !conflict_exists {
                            should_wake_waiters = apply_record_lock_for_owner(
                                locks,
                                owner,
                                owner_pid,
                                flock.l_type,
                                start,
                                end,
                            );
                            if locks.is_empty() {
                                table.remove(&key);
                            }
                        }
                    }
                    if should_wake_waiters {
                        wake_record_lock_waiters(key);
                    }
                    if !conflict_exists {
                        break 0;
                    }
                    if !blocking {
                        break err(SyscallError::EAGAIN);
                    }
                    if !is_ofd && detect_record_lock_deadlock(owner_pid, &conflict_owners) {
                        break err(SyscallError::EDEADLK);
                    }
                    let Some(task) = waiter_task.as_ref() else {
                        break err(SyscallError::EACCES);
                    };
                    if !is_ofd {
                        set_record_lock_waiting(
                            owner_pid,
                            WaitingRecordLock {
                                key,
                                req_type: flock.l_type,
                                start,
                                end,
                            },
                        );
                    }
                    enqueue_record_lock_waiter(key, task);
                    let still_conflict = {
                        let table = RECORD_LOCKS.lock();
                        table
                            .get(&key)
                            .map(|locks| {
                                locks.iter().any(|lock| {
                                    lock_conflicts(flock.l_type, start, end, owner, lock)
                                })
                            })
                            .unwrap_or(false)
                    };
                    if !still_conflict {
                        remove_record_lock_waiter(key, task);
                        if !is_ofd {
                            clear_record_lock_waiting(owner_pid);
                        }
                        continue;
                    }
                    if has_pending_unmasked_signal() {
                        remove_record_lock_waiter(key, task);
                        if !is_ofd {
                            clear_record_lock_waiting(owner_pid);
                        }
                        break err(SyscallError::EINTR);
                    }
                    block_current_and_run_next();
                    if has_pending_unmasked_signal() {
                        remove_record_lock_waiter(key, task);
                        if !is_ofd {
                            clear_record_lock_waiting(owner_pid);
                        }
                        break err(SyscallError::EINTR);
                    }
                };
                if let Some(task) = waiter_task.as_ref() {
                    remove_record_lock_waiter(key, task);
                }
                if !is_ofd {
                    clear_record_lock_waiting(owner_pid);
                }
                ret
            }
        }
        F_SETPIPE_SZ => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            match pipe.set_pipe_size(arg) {
                Ok(sz) => sz as isize,
                Err(e) => e,
            }
        }
        F_GETPIPE_SZ => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            pipe.pipe_size() as isize
        }
        F_GET_SEALS => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() else {
                return err(SyscallError::EINVAL);
            };
            let Some(seals) = shm.memfd_seals() else {
                return err(SyscallError::EINVAL);
            };
            seals as isize
        }
        F_ADD_SEALS => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            let has_writable_shared_map =
                if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
                    let id = shm.memfd_id();
                    inner.mmap_areas.iter().any(|region| {
                        region.memfd_id == id && region.shared && (region.prot & PROT_WRITE) != 0
                    })
                } else {
                    false
                };
            drop(inner);
            if !file.writable() {
                return err(SyscallError::EPERM);
            }
            let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() else {
                return err(SyscallError::EINVAL);
            };
            let add = arg as u32;
            if (add & !PseudoShmFile::F_SEAL_ALL) != 0 {
                return err(SyscallError::EINVAL);
            }
            if (add & PseudoShmFile::F_SEAL_WRITE) != 0
                && !shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE)
                && has_writable_shared_map
            {
                return err(SyscallError::EBUSY);
            }
            match shm.add_memfd_seals(add) {
                Ok(_) => 0,
                Err(e) => e,
            }
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let process = current_files_process();
            let mut inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return err(SyscallError::EBADF);
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            inner.ensure_fd_flags_len();
            let old_flags = inner.fd_flags[fd];
            let minfd = arg;
            let limit = inner.rlimits.rlimit_nofile_cur as usize;
            if minfd >= limit {
                return err(SyscallError::EINVAL);
            }
            let mut newfd = minfd;
            while newfd < inner.fd_table.len() && inner.fd_table[newfd].is_some() {
                newfd += 1;
            }
            if newfd >= limit {
                return err(SyscallError::EMFILE);
            }
            if newfd >= inner.fd_table.len() {
                // Extend fd table to fit the selected target descriptor.
                inner.fd_table.resize(newfd + 1, None);
                inner.fd_flags.resize(newfd + 1, 0);
            }
            inner.fd_table[newfd] = Some(file);
            let mut new_flags = old_flags;
            if cmd == F_DUPFD {
                new_flags &= !FD_CLOEXEC;
            } else {
                new_flags |= FD_CLOEXEC;
            }
            inner.fd_flags[newfd] = new_flags;
            newfd as isize
        }
        _ => err(SyscallError::EINVAL),
    };

    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && fd <= 8 {
            crate::println!(
                "[fs] fcntl(pid={}) fd={} cmd={} arg={:#x} -> {}",
                pid,
                fd,
                cmd,
                arg,
                ret
            );
        }
    }
    ret
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
        if uid != 0 && inode.uid() != uid {
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
    let (fsuid, fsgid) = current_fsuid_gid();
    {
        let _ext4_guard = ext4_lock();
        if !inode.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        if !inode_mode_allows_uid_gid(&inode, 1, fsuid, fsgid) {
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

