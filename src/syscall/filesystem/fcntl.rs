use super::{
    Arc, FD_CLOEXEC, FcntlFlock, FcntlOwnerEx, File, O_APPEND, O_ASYNC, O_DIRECT, O_NONBLOCK,
    O_PATH, O_RDONLY, O_RDWR, O_WRONLY, OSInode, Pipe, PseudoShmFile, RECORD_LOCKS,
    RecordLockOwner, SyscallError, Vec, WaitingRecordLock, apply_record_lock_for_owner,
    block_current_and_run_next, clear_record_lock_waiting, collect_conflict_process_owners,
    current_files, current_files_and_nofile_limit, current_process, current_task,
    detect_record_lock_deadlock, enqueue_record_lock_waiter, err, file_lock_key,
    first_conflicting_lock, flock_has_conflict, get_current_token, get_file_lease_type,
    has_pending_unmasked_signal, lock_conflicts, lock_range_from_flock, ofd_lock_owner_id,
    release_flock_owner, remove_record_lock_waiter, set_file_lease, set_record_lock_waiting,
    try_apply_flock, try_read_user_value, try_write_user_value, wake_record_lock_waiters,
};

fn get_fcntl_file(fd: usize) -> Result<Arc<dyn File + Send + Sync>, isize> {
    current_files()
        .lock()
        .get_file(fd)
        .ok_or(err(SyscallError::EBADF))
}

/// Applies BSD whole-file locks owned by the open file description.
pub fn syscall_flock(fd: usize, operation: usize) -> isize {
    const LOCK_SH: usize = 1;
    const LOCK_EX: usize = 2;
    const LOCK_NB: usize = 4;
    const LOCK_UN: usize = 8;

    let mode = operation & !LOCK_NB;
    if !matches!(mode, LOCK_SH | LOCK_EX | LOCK_UN)
        || (operation & !(LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN)) != 0
    {
        return err(SyscallError::EINVAL);
    }

    let file = match get_fcntl_file(fd) {
        Ok(file) => file,
        Err(e) => return e,
    };
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::EOPNOTSUPP);
    };
    let Some(key) = file_lock_key(&file) else {
        return err(SyscallError::EOPNOTSUPP);
    };
    let owner = os_inode.flock_owner_id();

    if mode == LOCK_UN {
        release_flock_owner(key, owner);
        return 0;
    }

    let exclusive = mode == LOCK_EX;
    let nonblock = (operation & LOCK_NB) != 0;
    let waiter = if nonblock { None } else { current_task() };
    loop {
        let (granted, should_wake) = try_apply_flock(key, owner, exclusive);
        if should_wake {
            wake_record_lock_waiters(key);
        }
        if granted {
            if let Some(task) = waiter.as_ref() {
                remove_record_lock_waiter(key, task);
            }
            return 0;
        }
        if nonblock {
            return err(SyscallError::EAGAIN);
        }
        let Some(task) = waiter.as_ref() else {
            return err(SyscallError::EINTR);
        };
        enqueue_record_lock_waiter(key, task);
        if !flock_has_conflict(key, owner, exclusive) {
            remove_record_lock_waiter(key, task);
            continue;
        }
        if has_pending_unmasked_signal() {
            remove_record_lock_waiter(key, task);
            return err(SyscallError::EINTR);
        }
        block_current_and_run_next();
        if has_pending_unmasked_signal() {
            remove_record_lock_waiter(key, task);
            return err(SyscallError::EINTR);
        }
    }
}

/// Handles descriptor flags, record locks, leases, and async-owner state for `fcntl(2)`.
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
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    const F_OWNER_TID: i32 = 0;
    const F_OWNER_PID: i32 = 1;
    const F_OWNER_PGRP: i32 = 2;

    let ret = match cmd {
        F_GETFD => {
            let files = current_files();
            let files = files.lock();
            let Some((_file, descriptor_flags)) = files.get_file_and_flags(fd) else {
                return err(SyscallError::EBADF);
            };
            if (descriptor_flags & FD_CLOEXEC) != 0 {
                FD_CLOEXEC as isize
            } else {
                0
            }
        }
        F_SETFD => {
            let files = current_files();
            let mut files = files.lock();
            let Some((_file, mut cur)) = files.get_file_and_flags(fd) else {
                return err(SyscallError::EBADF);
            };
            if (arg as u32 & FD_CLOEXEC) != 0 {
                cur |= FD_CLOEXEC;
            } else {
                cur &= !FD_CLOEXEC;
            }
            let _ = files.set_flags(fd, cur);
            0
        }
        F_SETFL => {
            let files = current_files();
            let mut files = files.lock();
            let Some((file, mut cur)) = files.get_file_and_flags(fd) else {
                return err(SyscallError::EBADF);
            };
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
            let _ = files.set_flags(fd, cur);
            drop(files);
            if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
                pipe.set_async_enabled((cur & O_ASYNC as u32) != 0);
            }
            0
        }
        F_GETFL => {
            let files = current_files();
            let files = files.lock();
            let Some((file, cur_flags)) = files.get_file_and_flags(fd) else {
                return err(SyscallError::EBADF);
            };
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
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
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
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
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
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
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
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
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
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
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
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            pipe.get_async_signal() as isize
        }
        F_SETLEASE => {
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
            let Some(key) = file_lock_key(&file) else {
                return err(SyscallError::EINVAL);
            };
            let owner_pid = current_process().getpid();
            set_file_lease(key, owner_pid, arg as i16, &file)
        }
        F_GETLEASE => {
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
            let Some(key) = file_lock_key(&file) else {
                return err(SyscallError::EINVAL);
            };
            let owner_pid = current_process().getpid();
            get_file_lease_type(key, owner_pid) as isize
        }
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };

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
                    let conflict_exists;
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
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            match pipe.set_pipe_size(arg) {
                Ok(sz) => sz as isize,
                Err(e) => e,
            }
        }
        F_GETPIPE_SZ => {
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return err(SyscallError::EINVAL);
            };
            pipe.pipe_size() as isize
        }
        F_GET_SEALS => {
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
            let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() else {
                return err(SyscallError::EINVAL);
            };
            let Some(seals) = shm.memfd_seals() else {
                return err(SyscallError::EINVAL);
            };
            seals as isize
        }
        F_ADD_SEALS => {
            let file = match get_fcntl_file(fd) {
                Ok(file) => file,
                Err(e) => return e,
            };
            let has_writable_shared_map =
                if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
                    let id = shm.memfd_id();
                    let process = current_process();
                    let inner = process.borrow_mut();
                    inner.memory_set.has_writable_shared_memfd_mapping(id)
                } else {
                    false
                };
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
            let (files, limit) = current_files_and_nofile_limit();
            let mut files = files.lock();
            let Some((file, old_flags)) = files.get_file_and_flags(fd) else {
                return err(SyscallError::EBADF);
            };
            let mount = files.get_mount_ref(fd);
            let minfd = arg;
            if minfd >= limit {
                return err(SyscallError::EINVAL);
            }
            let mut newfd = minfd;
            while newfd < files.len() && files.is_fd_open(newfd) {
                newfd += 1;
            }
            if newfd >= limit {
                return err(SyscallError::EMFILE);
            }
            let mut new_flags = old_flags;
            if cmd == F_DUPFD {
                new_flags &= !FD_CLOEXEC;
            } else {
                new_flags |= FD_CLOEXEC;
            }
            let replace_result =
                files.replace_fd_at_with_mount(newfd, file, new_flags, mount, limit);
            drop(files);
            let replaced = match replace_result {
                Ok(replaced) => replaced,
                Err(rejected) => {
                    rejected.discard();
                    return err(SyscallError::EMFILE);
                }
            };
            if let Some(replaced) = replaced {
                // The slot was observed free above; retain a defensive close
                // path for a future allocator change without doing it under
                // FilesLock.
                drop(replaced.complete_close());
            }
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
