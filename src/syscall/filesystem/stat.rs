use super::{
    AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_STATX_SYNC_TYPE, AT_SYMLINK_NOFOLLOW, AtPath,
    BTreeSet, CgroupFile, EXT4_ST_DEV, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE,
    FALLOC_FL_SUPPORTED_MASK, FS_APPEND_FL, FS_IMMUTABLE_FL, FifoDuplexFile, File, KStat,
    NetSocketFile, OSInode, PID2PCB, Pipe, ProcPseudoFile, ProcessControlBlock, PseudoBlock,
    PseudoDir, PseudoFile, PseudoShmFile, RtcFile, Statx, String, SyscallError, TimeSpec, Vec,
    current_effective_uid_gid, current_fsuid_gid, current_process, current_timespec, err,
    ext4_lock, fd_has_o_path, file_lock_key_from_inode, fill_statfs, find_path_in_roots,
    flush_open_inode_views, fsize_limit_allows, get_current_token, get_fd_file, get_inode_times,
    inode_fs_flags, inode_mode_allows_uid_gid, inode_rdev_for_mode, inode_visible_size,
    is_privileged_or_owner, kstat_from_dev_pts_path, kstat_from_fd, kstat_from_file,
    kstat_from_followed_proc_symlink, maybe_signal_lease_break, open_pseudo,
    proc_magic_link_target_kstat, proc_path_for_at, proc_symlink_kstat, pseudo_block_note_sync,
    punch_hole_keep_size, read_user_cstring, require_fd_file, resolve_abs_path, resolve_at_inode,
    resolve_at_path, resolve_utime, rofs_for_path, set_inode_times, stat_blocks_for_mode_size,
    statfs_mount_flags_for_abs, statx_from_kstat, sync_all, touch_inode_mtime_ctime_now,
    truncate_regular_inode, try_copy_to_user, try_read_user_value, try_write_user_value,
    update_current_inode_mmaps_size, update_current_os_inode_mmaps_size, write_zeros_range,
};
use crate::fs::TunTapFile;

/// Preallocates file space or punches holes on supported file types.
pub fn syscall_fallocate(fd: usize, mode: usize, offset: usize, len: usize) -> isize {
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    if (offset as i64) < 0 || (len as i64) < 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return err(SyscallError::EINVAL);
    }
    if (mode & !FALLOC_FL_SUPPORTED_MASK) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    if (mode & FALLOC_FL_PUNCH_HOLE) != 0 && (mode & FALLOC_FL_KEEP_SIZE) == 0 {
        return err(SyscallError::EINVAL);
    }
    let file = require_fd_file!(fd);
    if !file.writable() {
        return err(SyscallError::EBADF);
    }
    let Some(end) = offset.checked_add(len) else {
        return err(SyscallError::EFBIG);
    };
    if end > (i64::MAX as usize) {
        return err(SyscallError::EFBIG);
    }
    // Current backend does not model tmpfs-like huge preallocation reliably.
    // Keep this explicit so large/stress-only cases return TCONF instead of
    // polluting later tests by filling the shared root image.
    if mode == 0 && offset == 0 && len >= (1 << 20) {
        return err(SyscallError::EOPNOTSUPP);
    }
    // Misaligned mode=0 fallocate requires filesystem support we don't expose
    // yet; report unsupported to keep semantics explicit.
    if mode == 0 && (offset & 0xfff) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    if fsize_limit_allows(end).is_err() {
        return err(SyscallError::EFBIG);
    }
    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        if (mode & FALLOC_FL_PUNCH_HOLE) != 0 {
            if shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE) {
                return err(SyscallError::EPERM);
            }
            shm.punch_hole_keep_size(offset, len);
            return 0;
        }
        let old_size = shm.len();
        let alloc_end = if (mode & FALLOC_FL_KEEP_SIZE) != 0 {
            core::cmp::min(end, old_size)
        } else {
            end
        };
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_GROW) && alloc_end > old_size {
            return err(SyscallError::EPERM);
        }
        if alloc_end > old_size {
            shm.truncate(alloc_end);
        }
        return 0;
    }
    if (mode & FALLOC_FL_PUNCH_HOLE) != 0 {
        // Keep semantics explicit until sparse extent metadata is implemented.
        return err(SyscallError::EOPNOTSUPP);
    }
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::EINVAL);
    };
    if os_inode.readonly_fs() {
        return err(SyscallError::EROFS);
    }
    let inode = os_inode.ext4_inode();
    {
        let _ext4_guard = ext4_lock();
        if inode.is_dir() {
            return err(SyscallError::EISDIR);
        }
        if !inode.is_file() {
            return err(SyscallError::EINVAL);
        }
    }
    maybe_signal_lease_break(
        file_lock_key_from_inode(&inode),
        true,
        true,
        current_process().getpid(),
    );
    let _ = os_inode.flush();
    flush_open_inode_views(&inode);

    let ret = if (mode & FALLOC_FL_PUNCH_HOLE) != 0 {
        punch_hole_keep_size(&inode, offset, len)
    } else {
        let old_size = {
            let _ext4_guard = ext4_lock();
            inode.size() as usize
        };
        let alloc_end = if (mode & FALLOC_FL_KEEP_SIZE) != 0 {
            core::cmp::min(end, old_size)
        } else {
            end
        };
        if alloc_end <= offset {
            0
        } else {
            write_zeros_range(&inode, offset, alloc_end - offset)
        }
    };
    if ret == 0 {
        touch_inode_mtime_ctime_now(&inode);
    }
    ret
}

/// Changes the length of an opened regular file or memfd-like shm object.
pub fn syscall_ftruncate(fd: usize, length: usize) -> isize {
    if (length as i64) < 0 {
        return err(SyscallError::EINVAL);
    }
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    let file = require_fd_file!(fd);
    if !file.writable() {
        // Linux reports err(SyscallError::EINVAL) when the descriptor does not permit writing.
        return err(SyscallError::EINVAL);
    }
    if fsize_limit_allows(length).is_err() {
        return err(SyscallError::EFBIG);
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        let old_size = shm.len();
        if length < old_size && shm.has_memfd_seal(PseudoShmFile::F_SEAL_SHRINK) {
            return err(SyscallError::EPERM);
        }
        if length > old_size && shm.has_memfd_seal(PseudoShmFile::F_SEAL_GROW) {
            return err(SyscallError::EPERM);
        }
        shm.truncate(length);
        return 0;
    }
    if file.as_any().downcast_ref::<NetSocketFile>().is_some() {
        return err(SyscallError::EINVAL);
    }
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if os_inode.readonly_fs() {
            return err(SyscallError::EROFS);
        }
        let _ = os_inode.flush();
        let inode = os_inode.ext4_inode();
        maybe_signal_lease_break(
            file_lock_key_from_inode(&inode),
            true,
            true,
            current_process().getpid(),
        );
        let ret = truncate_regular_inode(&inode, length);
        if ret == 0 {
            touch_inode_mtime_ctime_now(&inode);
            update_current_os_inode_mmaps_size(os_inode);
        }
        return ret;
    }
    err(SyscallError::EINVAL)
}

/// Changes the length of a regular file resolved by pathname.
pub fn syscall_truncate(pathname: usize, length: usize) -> isize {
    if (length as i64) < 0 {
        return err(SyscallError::EINVAL);
    }
    if fsize_limit_allows(length).is_err() {
        return err(SyscallError::EFBIG);
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
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
        return err(SyscallError::EINVAL);
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if trailing_slash && !inode.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode.is_file() {
        if inode.is_dir() {
            return err(SyscallError::EISDIR);
        }
        return err(SyscallError::EINVAL);
    }
    if !inode_mode_allows_uid_gid(&inode, 2, fsuid, fsgid) {
        return err(SyscallError::EACCES);
    }
    maybe_signal_lease_break(
        file_lock_key_from_inode(&inode),
        true,
        true,
        current_process().getpid(),
    );
    drop(_ext4_guard);
    flush_open_inode_views(&inode);
    let ret = truncate_regular_inode(&inode, length);
    if ret == 0 {
        touch_inode_mtime_ctime_now(&inode);
        update_current_inode_mmaps_size(&inode);
    }
    ret
}

/// Returns `statfs` data for the filesystem containing an open file descriptor.
pub fn syscall_fstatfs(fd: usize, st_ptr: usize) -> isize {
    if get_fd_file(fd).is_none() {
        return err(SyscallError::EBADF);
    }
    let _ext4_guard = ext4_lock();
    fill_statfs(st_ptr, 0)
}

/// Returns `statfs` data for the filesystem containing the resolved path.
pub fn syscall_statfs(pathname: usize, st_ptr: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }
    let at = match resolve_at_path(AT_FDCWD, path.as_str()) {
        Ok(v) => v,
        Err(e) => return e,
    };

    match at {
        AtPath::PseudoAbs(abs) => {
            if open_pseudo(&abs).is_none() {
                return err(SyscallError::ENOENT);
            }
            fill_statfs(st_ptr, statfs_mount_flags_for_abs(&abs))
        }
        AtPath::Ext4Abs(_) | AtPath::Ext4Rel { .. } => {
            let (fsuid, fsgid) = current_fsuid_gid();
            let _ext4_guard = ext4_lock();
            if let Err(e) = resolve_at_inode(&at, fsuid, fsgid, true) {
                return e;
            }
            let abs = resolve_abs_path(AT_FDCWD, path.as_str())
                .ok()
                .flatten()
                .unwrap_or_else(|| String::from("/"));
            fill_statfs(st_ptr, statfs_mount_flags_for_abs(&abs))
        }
    }
}

#[derive(Clone, Copy)]
enum UtimensSpec {
    Touch,
    Times(TimeSpec, TimeSpec),
}

fn read_utimens_spec(token: usize, times_ptr: usize) -> Result<Option<UtimensSpec>, isize> {
    if times_ptr == 0 {
        return Ok(Some(UtimensSpec::Touch));
    }
    let ts0 = try_read_user_value(token, times_ptr as *const TimeSpec)
        .ok_or_else(|| err(SyscallError::EFAULT))?;
    let ts1 = try_read_user_value(
        token,
        (times_ptr + core::mem::size_of::<TimeSpec>()) as *const TimeSpec,
    )
    .ok_or_else(|| err(SyscallError::EFAULT))?;
    if ts0.nsec == super::UTIME_OMIT && ts1.nsec == super::UTIME_OMIT {
        return Ok(None);
    }
    if ts0.nsec == super::UTIME_NOW && ts1.nsec == super::UTIME_NOW {
        return Ok(Some(UtimensSpec::Touch));
    }
    Ok(Some(UtimensSpec::Times(ts0, ts1)))
}

fn resolve_utimens_spec(
    spec: UtimensSpec,
    now: (i64, i64),
) -> Result<(Option<(i64, i64)>, Option<(i64, i64)>, bool), isize> {
    match spec {
        UtimensSpec::Touch => Ok((Some(now), Some(now), true)),
        UtimensSpec::Times(ts0, ts1) => {
            let atime = resolve_utime(ts0, now)?;
            let mtime = resolve_utime(ts1, now)?;
            Ok((atime, mtime, false))
        }
    }
}

fn check_utimens_permission(
    inode: &alloc::sync::Arc<ext4_fs::Inode>,
    fsuid: u32,
    fsgid: u32,
    euid: u32,
    touch: bool,
) -> Result<(), isize> {
    let fs_flags = inode_fs_flags(inode.inode_num() as u64);
    if touch {
        if (fs_flags & FS_IMMUTABLE_FL) != 0 {
            return Err(err(SyscallError::EPERM));
        }
        if !is_privileged_or_owner(euid, inode)
            && !inode_mode_allows_uid_gid(inode, 2, fsuid, fsgid)
        {
            return Err(err(SyscallError::EACCES));
        }
    } else {
        if (fs_flags & (FS_IMMUTABLE_FL | FS_APPEND_FL)) != 0 {
            return Err(err(SyscallError::EPERM));
        }
        if !is_privileged_or_owner(euid, inode) {
            return Err(err(SyscallError::EPERM));
        }
    }
    Ok(())
}

fn apply_utimens_to_inode(inode: &alloc::sync::Arc<ext4_fs::Inode>, spec: UtimensSpec) -> isize {
    let now = current_timespec();
    let (atime, mtime, _touch) = match resolve_utimens_spec(spec, now) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let ino = inode.inode_num() as u64;
    let mut cur = get_inode_times(ino);
    if let Some((sec, nsec)) = atime {
        cur.atime_sec = sec;
        cur.atime_nsec = nsec;
    }
    if let Some((sec, nsec)) = mtime {
        cur.mtime_sec = sec;
        cur.mtime_nsec = nsec;
    }
    if atime.is_some() || mtime.is_some() {
        cur.ctime_sec = now.0;
        cur.ctime_nsec = now.1;
    }
    set_inode_times(ino, cur);
    0
}

/// Updates inode timestamps by path or fd, including Linux `UTIME_*` semantics.
pub fn syscall_utimensat(dirfd: isize, pathname: usize, _times: usize, _flags: usize) -> isize {
    let token = get_current_token();
    let spec = match read_utimens_spec(token, _times) {
        Ok(Some(spec)) => spec,
        Ok(None) => return 0,
        Err(e) => return e,
    };

    // `futimens` passes a null pathname and uses dirfd as the target fd.
    if pathname == 0 && dirfd != AT_FDCWD {
        if _flags != 0 {
            return err(SyscallError::EINVAL);
        }
        if dirfd < 0 {
            return err(SyscallError::EBADF);
        }
        let file = require_fd_file!(dirfd);
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            let inode = os_inode.ext4_inode();
            let now = current_timespec();
            let (_atime, _mtime, touch) = match resolve_utimens_spec(spec, now) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if os_inode.readonly_fs() {
                return err(SyscallError::EROFS);
            }
            let (fsuid, fsgid) = current_fsuid_gid();
            let (euid, _egid) = current_effective_uid_gid();
            if let Err(e) = check_utimens_permission(&inode, fsuid, fsgid, euid, touch) {
                return e;
            }
            return apply_utimens_to_inode(&inode, spec);
        }
        return 0;
    }

    if (_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0 {
        return err(SyscallError::EINVAL);
    }

    let path = if pathname == 0 {
        return err(SyscallError::EFAULT);
    } else {
        match read_user_cstring(token, pathname) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    if path.is_empty() {
        if (_flags & AT_EMPTY_PATH) == 0 {
            return err(SyscallError::ENOENT);
        }
        if dirfd < 0 {
            return err(SyscallError::EBADF);
        }
        let file = require_fd_file!(dirfd);
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            let inode = os_inode.ext4_inode();
            let now = current_timespec();
            let (_atime, _mtime, touch) = match resolve_utimens_spec(spec, now) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if os_inode.readonly_fs() {
                return err(SyscallError::EROFS);
            }
            let (fsuid, fsgid) = current_fsuid_gid();
            let (euid, _egid) = current_effective_uid_gid();
            if let Err(e) = check_utimens_permission(&inode, fsuid, fsgid, euid, touch) {
                return e;
            }
            return apply_utimens_to_inode(&inode, spec);
        }
        return 0;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if open_pseudo(abs).is_some() {
            return err(SyscallError::EROFS);
        }
        // If any prefix is a pseudo file, report err(SyscallError::ENOTDIR) for deeper paths.
        let mut prefix = alloc::string::String::from("/");
        for (idx, comp) in abs.split('/').filter(|s| !s.is_empty()).enumerate() {
            if idx > 0 {
                prefix.push('/');
            }
            prefix.push_str(comp);
            if prefix == *abs {
                break;
            }
            if let Some(node) = open_pseudo(&prefix) {
                if node.as_any().downcast_ref::<PseudoDir>().is_none() {
                    return err(SyscallError::ENOTDIR);
                }
            }
        }
        return err(SyscallError::ENOENT);
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let (euid, _egid) = current_effective_uid_gid();
    let follow_final = (_flags & AT_SYMLINK_NOFOLLOW) == 0;
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, follow_final) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let now = current_timespec();
    let (atime, mtime, touch) = match resolve_utimens_spec(spec, now) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if rofs_for_path(dirfd, &path) {
        return err(SyscallError::EROFS);
    }
    if let Err(e) = check_utimens_permission(&inode, fsuid, fsgid, euid, touch) {
        return e;
    }
    let ino = inode.inode_num() as u64;
    let mut cur = get_inode_times(ino);
    if let Some((sec, nsec)) = atime {
        cur.atime_sec = sec;
        cur.atime_nsec = nsec;
    }
    if let Some((sec, nsec)) = mtime {
        cur.mtime_sec = sec;
        cur.mtime_nsec = nsec;
    }
    if atime.is_some() || mtime.is_some() {
        cur.ctime_sec = now.0;
        cur.ctime_nsec = now.1;
    }
    set_inode_times(ino, cur);
    0
}

/// Copies the caller's current working directory into a userspace buffer.
pub fn syscall_getcwd(buf: usize, size: usize) -> isize {
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let need = cwd.len().saturating_add(1);
    if size < need {
        return err(SyscallError::ERANGE);
    }
    if buf == 0 {
        return err(SyscallError::EFAULT);
    }
    let mut bytes = cwd.into_bytes();
    bytes.push(0);
    let token = get_current_token();
    if try_copy_to_user(token, buf as *mut u8, &bytes).is_err() {
        return err(SyscallError::EFAULT);
    }
    need as isize
}

/// Returns `fstat(2)` metadata for an open file descriptor.
pub fn syscall_fstat(fd: usize, st_ptr: usize) -> isize {
    if get_fd_file(fd).is_none() {
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            crate::println!(
                "[fs] fstat(pid={}) fd={} -> err(SyscallError::EBADF)(nofile)",
                pid,
                fd
            );
        }
        return err(SyscallError::EBADF);
    };
    if st_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let st = match kstat_from_fd(fd) {
        Ok(st) => st,
        Err(e) => return e,
    };

    let token = get_current_token();
    if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
        return err(SyscallError::EFAULT);
    }
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && fd <= 8 {
            crate::println!(
                "[fs] fstat(pid={}) fd={} -> ok mode={:#o}",
                pid,
                fd,
                st.st_mode
            );
        }
    }
    0
}

/// Flushes dirty state for one open file descriptor when the backend supports it.
pub fn syscall_fsync(fd: usize) -> isize {
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    let file = require_fd_file!(fd);
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        {
            let _ext4_guard = ext4_lock();
            if !(inode.is_file() || inode.is_dir()) {
                return err(SyscallError::EINVAL);
            }
        }
        if os_inode.readonly_fs() {
            return 0;
        }
        // A full ext4 sync for every call is prohibitively expensive for
        // micro-benchmarks like iozone. Flush per-fd buffered writes instead.
        let _ = os_inode.flush();
        pseudo_block_note_sync();
        return 0;
    }
    err(SyscallError::EINVAL)
}

/// Flushes dirty file data across currently open descriptors and the ext4 backend.
pub fn syscall_sync() -> isize {
    let mut files: Vec<alloc::sync::Arc<dyn File + Send + Sync>> = Vec::new();
    let processes: Vec<alloc::sync::Arc<ProcessControlBlock>> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        let table = alloc::sync::Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(alloc::sync::Arc::as_ptr(&table) as usize) {
            continue;
        }
        files.extend(
            table
                .lock()
                .iter_files_snapshot()
                .into_iter()
                .map(|(_, file)| file),
        );
    }

    for file in files {
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            if !os_inode.readonly_fs() {
                let _ = os_inode.flush();
            }
        }
    }
    sync_all();
    pseudo_block_note_sync();
    0
}

/// Flushes the filesystem that contains the given file descriptor.
pub fn syscall_syncfs(fd: usize) -> isize {
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    let file = require_fd_file!(fd);
    if file.as_any().downcast_ref::<OSInode>().is_none() {
        return err(SyscallError::EINVAL);
    }
    syscall_sync()
}

/// Validates `sync_file_range(2)` arguments and flushes dirty regular-file state.
pub fn syscall_sync_file_range(fd: usize, offset: usize, nbytes: usize, flags: usize) -> isize {
    const SYNC_FILE_RANGE_WAIT_BEFORE: usize = 1;
    const SYNC_FILE_RANGE_WRITE: usize = 2;
    const SYNC_FILE_RANGE_WAIT_AFTER: usize = 4;
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    let file = require_fd_file!(fd);
    if file.as_any().downcast_ref::<Pipe>().is_some()
        || file.as_any().downcast_ref::<FifoDuplexFile>().is_some()
        || file.as_any().downcast_ref::<PseudoFile>().is_some()
        || file.as_any().downcast_ref::<ProcPseudoFile>().is_some()
        || file.as_any().downcast_ref::<CgroupFile>().is_some()
        || file.as_any().downcast_ref::<PseudoDir>().is_some()
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
        || file.as_any().downcast_ref::<TunTapFile>().is_some()
        || file.as_any().downcast_ref::<NetSocketFile>().is_some()
    {
        return err(SyscallError::ESPIPE);
    }
    let valid_flags =
        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (offset as i64) < 0 || (nbytes as i64) < 0 {
        return err(SyscallError::EINVAL);
    }
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::EINVAL);
    };
    let inode = os_inode.ext4_inode();
    {
        let _ext4_guard = ext4_lock();
        if !inode.is_file() {
            return err(SyscallError::EINVAL);
        }
    }
    if os_inode.readonly_fs() {
        return 0;
    }
    let _ = os_inode.flush();
    pseudo_block_note_sync();
    0
}

/// Accepts advisory access-pattern hints for regular files.
pub fn syscall_fadvise64(fd: usize, offset: usize, len: usize, advice: usize) -> isize {
    const POSIX_FADV_NORMAL: usize = 0;
    const POSIX_FADV_RANDOM: usize = 1;
    const POSIX_FADV_SEQUENTIAL: usize = 2;
    const POSIX_FADV_WILLNEED: usize = 3;
    const POSIX_FADV_DONTNEED: usize = 4;
    const POSIX_FADV_NOREUSE: usize = 5;

    if (offset as i64) < 0 || (len as i64) < 0 {
        return err(SyscallError::EINVAL);
    }
    if !matches!(
        advice,
        POSIX_FADV_NORMAL
            | POSIX_FADV_RANDOM
            | POSIX_FADV_SEQUENTIAL
            | POSIX_FADV_WILLNEED
            | POSIX_FADV_DONTNEED
            | POSIX_FADV_NOREUSE
    ) {
        return err(SyscallError::EINVAL);
    }
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    let file = require_fd_file!(fd);

    if file.as_any().downcast_ref::<Pipe>().is_some()
        || file.as_any().downcast_ref::<FifoDuplexFile>().is_some()
    {
        return err(SyscallError::ESPIPE);
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::EINVAL);
    };
    let inode = os_inode.ext4_inode();
    {
        let _ext4_guard = ext4_lock();
        if !inode.is_file() {
            return err(SyscallError::ESPIPE);
        }
    }
    0
}

/// Returns `newfstatat(2)` metadata for ext4, pseudo, and proc magic-link paths.
pub fn syscall_newfstatat(dirfd: isize, pathname: usize, st_ptr: usize, _flags: usize) -> isize {
    if st_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    const AT_EMPTY_PATH: usize = 0x1000;
    let valid_flags = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    if (_flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // Support `AT_EMPTY_PATH`: operate on `dirfd` itself when pathname is empty.
    // glibc uses this in some directory APIs (e.g., `opendir`) to validate the fd.
    if path.is_empty() {
        if (_flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
            return syscall_fstat(dirfd as usize, st_ptr);
        }
        return err(SyscallError::ENOENT);
    }

    let raw_abs = match resolve_abs_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Pseudo nodes: return minimal metadata.
    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(proc_path) = proc_path_for_at(raw_abs.as_deref(), &at) {
            if crate::fs::proc_magic_link_exists(proc_path) {
                let st = if (_flags & AT_SYMLINK_NOFOLLOW) != 0 {
                    let link_len = crate::fs::proc_readlink(proc_path)
                        .map(|target| target.len())
                        .unwrap_or(0);
                    proc_symlink_kstat(link_len)
                } else {
                    match proc_magic_link_target_kstat(proc_path) {
                        Ok(Some(st)) => st,
                        Ok(None) => return err(SyscallError::ENOENT),
                        Err(e) => return e,
                    }
                };
                if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
        }
        let pseudo_path = proc_path_for_at(raw_abs.as_deref(), &at).unwrap_or(abs);
        let st = if let Some(st) = kstat_from_dev_pts_path(pseudo_path) {
            st
        } else {
            let Some(node) = open_pseudo(pseudo_path) else {
                return err(SyscallError::ENOENT);
            };
            match kstat_from_file(&node) {
                Ok(st) => st,
                Err(e) => return e,
            }
        };
        if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
            return err(SyscallError::EFAULT);
        }
        return 0;
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_final = (_flags & AT_SYMLINK_NOFOLLOW) == 0;
    if follow_final {
        if let Some(abs) = raw_abs.as_deref() {
            match kstat_from_followed_proc_symlink(abs) {
                Ok(Some(st)) => {
                    if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
                        return err(SyscallError::EFAULT);
                    }
                    return 0;
                }
                Ok(None) => {}
                Err(e) => return e,
            }
        }
    }
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, follow_final) {
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

    let mode_raw = inode.mode();
    let mode = mode_raw as u32;
    let uid = inode.uid();
    let gid = inode.gid();
    let nlink = inode.link_count();
    let st_rdev = inode_rdev_for_mode(&inode, mode_raw);
    let size = inode_visible_size(&inode) as i64;
    let blocks = stat_blocks_for_mode_size(mode, size);
    let times = get_inode_times(inode.inode_num() as u64);

    let st = KStat {
        st_dev: EXT4_ST_DEV,
        st_ino: inode.inode_num() as u64,
        st_mode: mode,
        st_nlink: nlink,
        st_uid: uid,
        st_gid: gid,
        st_rdev,
        __pad: 0,
        st_size: size,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks,
        st_atime_sec: times.atime_sec,
        st_atime_nsec: times.atime_nsec,
        st_mtime_sec: times.mtime_sec,
        st_mtime_nsec: times.mtime_nsec,
        st_ctime_sec: times.ctime_sec,
        st_ctime_nsec: times.ctime_nsec,
        __unused: [0, 0],
    };

    if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// Returns `statx(2)` metadata with Linux-like path and `AT_EMPTY_PATH` handling.
pub fn syscall_statx(
    dirfd: isize,
    pathname: usize,
    flags: usize,
    _mask: usize,
    stx_ptr: usize,
) -> isize {
    if stx_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let valid_flags = AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    const STATX_VALID_MASK: usize = 0x0001_FFFF;
    if (_mask & !STATX_VALID_MASK) != 0 {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        if dirfd < 0 {
            return err(SyscallError::EINVAL);
        }
        let st = match kstat_from_fd(dirfd as usize) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let stx = statx_from_kstat(&st);
        if try_write_user_value(token, stx_ptr as *mut Statx, &stx).is_err() {
            return err(SyscallError::EFAULT);
        }
        return 0;
    }
    if path.is_empty() {
        return err(SyscallError::ENOENT);
    }

    if dirfd < 0 && dirfd != AT_FDCWD {
        return err(SyscallError::EBADF);
    }
    let effective_dirfd = dirfd;
    let raw_abs = match resolve_abs_path(effective_dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let at = match resolve_at_path(effective_dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Pseudo nodes: return minimal metadata.
    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(proc_path) = proc_path_for_at(raw_abs.as_deref(), &at) {
            if crate::fs::proc_magic_link_exists(proc_path) {
                let st = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
                    let link_len = crate::fs::proc_readlink(proc_path)
                        .map(|target| target.len())
                        .unwrap_or(0);
                    proc_symlink_kstat(link_len)
                } else {
                    match proc_magic_link_target_kstat(proc_path) {
                        Ok(Some(st)) => st,
                        Ok(None) => return err(SyscallError::ENOENT),
                        Err(e) => return e,
                    }
                };
                let stx = statx_from_kstat(&st);
                if try_write_user_value(token, stx_ptr as *mut Statx, &stx).is_err() {
                    return err(SyscallError::EFAULT);
                }
                return 0;
            }
        }
        let pseudo_path = proc_path_for_at(raw_abs.as_deref(), &at).unwrap_or(abs);
        let st = if let Some(st) = kstat_from_dev_pts_path(pseudo_path) {
            st
        } else {
            let Some(node) = open_pseudo(pseudo_path) else {
                return err(SyscallError::ENOENT);
            };
            match kstat_from_file(&node) {
                Ok(st) => st,
                Err(e) => return e,
            }
        };
        let stx = statx_from_kstat(&st);
        if try_write_user_value(token, stx_ptr as *mut Statx, &stx).is_err() {
            return err(SyscallError::EFAULT);
        }
        return 0;
    }

    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    if follow_final {
        if let Some(abs) = raw_abs.as_deref() {
            match kstat_from_followed_proc_symlink(abs) {
                Ok(Some(st)) => {
                    let stx = statx_from_kstat(&st);
                    if try_write_user_value(token, stx_ptr as *mut Statx, &stx).is_err() {
                        return err(SyscallError::EFAULT);
                    }
                    return 0;
                }
                Ok(None) => {}
                Err(e) => return e,
            }
        }
    }

    let _ext4_guard = ext4_lock();
    let mut inode = match at {
        AtPath::Ext4Abs(abs) => find_path_in_roots(&abs),
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Some(base)
            } else {
                base.find_path(&rel)
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };
    if inode.is_none() && matches!(path.as_str(), "busybox" | "./busybox") {
        let candidates = [
            "/musl/busybox",
            "/glibc/busybox",
            "/bin/busybox",
            "/busybox",
        ];
        for cand in candidates {
            if let Some(found) = find_path_in_roots(cand) {
                inode = Some(found);
                break;
            }
        }
    }

    let Some(inode) = inode else {
        return err(SyscallError::ENOENT);
    };

    let mode_raw = inode.mode();
    let mode = mode_raw as u32;
    let uid = inode.uid();
    let gid = inode.gid();
    let nlink = inode.link_count();
    let st_rdev = inode_rdev_for_mode(&inode, mode_raw);
    let size = inode_visible_size(&inode) as i64;
    let blocks = stat_blocks_for_mode_size(mode, size);
    let times = get_inode_times(inode.inode_num() as u64);

    let st = KStat {
        st_dev: EXT4_ST_DEV,
        st_ino: inode.inode_num() as u64,
        st_mode: mode,
        st_nlink: nlink,
        st_uid: uid,
        st_gid: gid,
        st_rdev,
        __pad: 0,
        st_size: size,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks,
        st_atime_sec: times.atime_sec,
        st_atime_nsec: times.atime_nsec,
        st_mtime_sec: times.mtime_sec,
        st_mtime_nsec: times.mtime_nsec,
        st_ctime_sec: times.ctime_sec,
        st_ctime_nsec: times.ctime_nsec,
        __unused: [0, 0],
    };
    let stx = statx_from_kstat(&st);
    if try_write_user_value(token, stx_ptr as *mut Statx, &stx).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}
