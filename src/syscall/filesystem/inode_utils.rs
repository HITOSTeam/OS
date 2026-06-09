use super::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Arc, AtPath, BTreeMap, BTreeSet, FS_APPEND_FL,
    FS_IMMUTABLE_FL, Mutex, O_ACCMODE, O_CREAT, O_DIRECTORY, O_NOATIME, O_NONBLOCK, O_RDONLY,
    O_TMPFILE, O_TRUNC, O_WRONLY, OSInode, Ordering, PID2PCB, S_IFBLK, S_IFCHR, S_IFMT,
    SIGXFSZ_NUM, String, SyscallError, TMPFILE_SEQ, Vec, cgroup_rename, current_effective_uid_gid,
    current_files, current_fsuid_gid, current_in_group, current_process, current_timespec,
    empty_path_fd_for_at_op, err, ext4_err_to_errno, ext4_lock, fifo_pipe_state_for_inode,
    file_lock_key_from_inode, get_current_token, inode_mode_allows, inode_mode_allows_uid_gid,
    install_open_file_fd, is_inode_currently_executed_locked, lock_executing_inodes,
    maybe_dispatch_proc_fd_at, maybe_signal_lease_break, note_inode_path_hint, open_pseudo,
    path_is_nodev, path_is_rofs, pseudo_path_exists_result, queue_process_signal,
    read_user_cstring, register_deferred_unlink_cleanup, resolve_at_inode, resolve_at_path,
    resolve_parent_and_name, rofs_for_path, syscall_fchmod, try_copy_from_user,
    try_copy_to_user_unchecked,
};
use crate::mm::{resize_shared_file_page_cache, update_shared_file_page_cache};
use alloc::vec;
use lazy_static::lazy_static;

#[derive(Clone, Copy, Default)]
pub(crate) struct InodeTimes {
    pub(crate) atime_sec: i64,
    pub(crate) atime_nsec: i64,
    pub(crate) mtime_sec: i64,
    pub(crate) mtime_nsec: i64,
    pub(crate) ctime_sec: i64,
    pub(crate) ctime_nsec: i64,
}

pub(crate) const ACCT_COMM: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Acct {
    pub(crate) ac_flag: u8,
    pub(crate) ac_uid: u16,
    pub(crate) ac_gid: u16,
    pub(crate) ac_tty: u16,
    pub(crate) ac_btime: u32,
    pub(crate) ac_utime: u16,
    pub(crate) ac_stime: u16,
    pub(crate) ac_etime: u16,
    pub(crate) ac_mem: u16,
    pub(crate) ac_io: u16,
    pub(crate) ac_rw: u16,
    pub(crate) ac_minflt: u16,
    pub(crate) ac_majflt: u16,
    pub(crate) ac_swaps: u16,
    pub(crate) ac_exitcode: u32,
    pub(crate) ac_comm: [u8; ACCT_COMM + 1],
    pub(crate) ac_pad: [u8; 10],
}

pub(crate) struct AcctState {
    pub(crate) inode: alloc::sync::Arc<ext4_fs::Inode>,
}

lazy_static! {
    pub(crate) static ref INODE_TIMES: Mutex<BTreeMap<u64, InodeTimes>> =
        Mutex::new(BTreeMap::new());
    pub(crate) static ref INODE_XATTRS: Mutex<BTreeMap<u64, BTreeMap<String, Vec<u8>>>> =
        Mutex::new(BTreeMap::new());
    pub(crate) static ref INODE_FSFLAGS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());
    pub(crate) static ref ACCT_STATE: Mutex<Option<AcctState>> = Mutex::new(None);
}

pub(crate) fn get_inode_times(ino: u64) -> InodeTimes {
    INODE_TIMES.lock().get(&ino).copied().unwrap_or_default()
}

pub(crate) fn set_inode_times(ino: u64, times: InodeTimes) {
    INODE_TIMES.lock().insert(ino, times);
}

pub(crate) fn set_inode_all_times_now(inode: &Arc<ext4_fs::Inode>) {
    let (sec, nsec) = current_timespec();
    set_inode_times(
        inode.inode_num() as u64,
        InodeTimes {
            atime_sec: sec,
            atime_nsec: nsec,
            mtime_sec: sec,
            mtime_nsec: nsec,
            ctime_sec: sec,
            ctime_nsec: nsec,
        },
    );
}

pub(crate) fn touch_inode_mtime_ctime_now(inode: &Arc<ext4_fs::Inode>) {
    let (sec, nsec) = current_timespec();
    let ino = inode.inode_num() as u64;
    let mut times = get_inode_times(ino);
    times.mtime_sec = sec;
    times.mtime_nsec = nsec;
    times.ctime_sec = sec;
    times.ctime_nsec = nsec;
    set_inode_times(ino, times);
}

pub(crate) fn inode_fs_flags(ino: u64) -> u32 {
    INODE_FSFLAGS.lock().get(&ino).copied().unwrap_or(0)
}

pub(crate) fn set_inode_fs_flags(ino: u64, flags: u32) {
    if flags == 0 {
        INODE_FSFLAGS.lock().remove(&ino);
    } else {
        INODE_FSFLAGS.lock().insert(ino, flags);
    }
}

pub(crate) fn inode_is_immutable_or_append(inode: &Arc<ext4_fs::Inode>) -> bool {
    (inode_fs_flags(inode.inode_num() as u64) & (FS_IMMUTABLE_FL | FS_APPEND_FL)) != 0
}

pub(crate) fn open_existing_ext4_inode(
    path: &str,
    raw_abs: Option<&str>,
    inode: alloc::sync::Arc<ext4_fs::Inode>,
    flags: usize,
    readable: bool,
    writable: bool,
    append: bool,
    o_path: bool,
) -> Result<usize, isize> {
    let readonly_fs = raw_abs.map(path_is_rofs).unwrap_or(false);
    let ext4_guard = ext4_lock();

    if let Some(abs) = raw_abs {
        note_inode_path_hint(&inode, abs);
        let mode = inode.mode() & S_IFMT;
        if path_is_nodev(abs) && matches!(mode, S_IFCHR | S_IFBLK) {
            return Err(err(SyscallError::EACCES));
        }
    }

    if !o_path && inode.is_dir() && ((flags & O_ACCMODE) != O_RDONLY || (flags & O_CREAT) != 0) {
        return Err(err(SyscallError::EISDIR));
    }

    if (flags & O_NOATIME) != 0 {
        let (euid, _egid) = current_effective_uid_gid();
        if euid != 0 && euid != inode.uid() {
            return Err(err(SyscallError::EPERM));
        }
    }

    let mut mask = 0usize;
    if readable {
        mask |= 4;
    }
    if writable {
        mask |= 2;
    }
    if !inode_mode_allows(&inode, mask) {
        return Err(err(SyscallError::EACCES));
    }

    if (flags & O_DIRECTORY) != 0 && !inode.is_dir() {
        return Err(err(SyscallError::ENOTDIR));
    }

    let text_write_intent = writable || (flags & O_TRUNC) != 0;
    let exec_inode_guard = if !o_path && inode.is_file() && text_write_intent {
        let guard = lock_executing_inodes();
        let exec_busy =
            is_inode_currently_executed_locked(&guard, inode.device_id(), inode.inode_num());
        if exec_busy {
            return Err(err(SyscallError::ETXTBSY));
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
            return Err(ext4_err_to_errno(e));
        }
        touch_inode_mtime_ctime_now(&inode);
    }

    if !o_path && inode.is_fifo() {
        let state = fifo_pipe_state_for_inode(inode.inode_num() as u64);
        let accmode = flags & O_ACCMODE;
        if (flags & O_NONBLOCK) != 0 && accmode == O_WRONLY && !state.has_open_readers() {
            drop(ext4_guard);
            return Err(err(SyscallError::ENXIO));
        }
        let Some(file) = state.open_file(accmode) else {
            drop(ext4_guard);
            return Err(err(SyscallError::EINVAL));
        };
        drop(ext4_guard);
        return install_open_file_fd(file, flags, o_path);
    }

    let inode_num = inode.inode_num();
    let os_inode = alloc::sync::Arc::new(OSInode::new_with_append_rofs_tmp_cleanup(
        readable,
        writable,
        append,
        inode,
        readonly_fs,
        false,
        None,
    ));
    drop(exec_inode_guard);
    crate::fs::debug_track_iozone_inode(path, inode_num);
    drop(ext4_guard);
    install_open_file_fd(os_inode, flags, o_path)
}

pub(crate) fn open_existing_target_path(
    abs: &str,
    flags: usize,
    readable: bool,
    writable: bool,
    append: bool,
    o_path: bool,
) -> Result<usize, isize> {
    let write_intent =
        writable || (flags & (O_CREAT | O_TRUNC)) != 0 || (flags & O_TMPFILE) == O_TMPFILE;
    if write_intent && path_is_rofs(abs) {
        return Err(err(SyscallError::EROFS));
    }

    let at = resolve_at_path(AT_FDCWD, abs)?;
    if let AtPath::PseudoAbs(_) = &at {
        let Some(file) = open_pseudo(abs) else {
            return Err(err(SyscallError::ENOENT));
        };
        return install_open_file_fd(file, flags, o_path);
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = resolve_at_inode(&at, fsuid, fsgid, true)?;
    drop(_ext4_guard);
    open_existing_ext4_inode(
        abs,
        Some(abs),
        inode,
        flags,
        readable,
        writable,
        append,
        o_path,
    )
}

/// Linux `faccessat(2)` (syscall 48 on riscv64).
///
/// Used by busybox `which` and shells to locate executables.

/// Linux `fchmod(2)` (syscall 52 on riscv64).

pub(crate) fn do_fchmodat(
    dirfd: isize,
    pathname: usize,
    mode: usize,
    flags: usize,
    strict_flags: bool,
) -> isize {
    let valid_flags = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if strict_flags && (flags & !valid_flags) != 0 {
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
        return syscall_fchmod(fd, mode);
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(ret) = maybe_dispatch_proc_fd_at(abs, flags, |fd| syscall_fchmod(fd, mode)) {
            return ret;
        }
        return pseudo_path_exists_result(abs);
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let (euid, _egid) = current_effective_uid_gid();
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, follow_final) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if rofs_for_path(dirfd, &path) {
        return err(SyscallError::EROFS);
    }
    if euid != 0 && inode.uid() != euid {
        return err(SyscallError::EPERM);
    }
    let mut new_mode = (mode as u16) & 0o7777;
    if euid != 0 && (new_mode & 0o2000) != 0 && !current_in_group(inode.gid()) {
        new_mode &= !0o2000;
    }
    inode.set_mode(new_mode);
    0
}

/// Legacy Linux `fchmodat(2)` syscall entry.
///
/// The original syscall does not define a flags argument. User-space `chmod()`
/// wrappers may still route through this number and leave `a3` unspecified, so
/// the kernel must not reject non-zero garbage here. Flag validation belongs to
/// `fchmodat2(2)`.

/// Linux `fchmodat2(2)` (syscall 452 on riscv64).

/// Linux `fchown(2)` (syscall 55 on riscv64).

/// Linux `fchownat(2)` (syscall 54 on riscv64).

/// Linux `setxattr(2)` (syscall 5 on riscv64).

/// Linux `lsetxattr(2)` (syscall 6 on riscv64).

/// Linux `fsetxattr(2)` (syscall 7 on riscv64).

/// Linux `getxattr(2)` (syscall 8 on riscv64).

/// Linux `lgetxattr(2)` (syscall 9 on riscv64).

/// Linux `fgetxattr(2)` (syscall 10 on riscv64).

/// Linux `listxattr(2)` (syscall 11 on riscv64).

/// Linux `llistxattr(2)` (syscall 12 on riscv64).

/// Linux `flistxattr(2)` (syscall 13 on riscv64).

/// Linux `removexattr(2)` (syscall 14 on riscv64).

/// Linux `lremovexattr(2)` (syscall 15 on riscv64).

/// Linux `fremovexattr(2)` (syscall 16 on riscv64).

/// Linux `readlinkat(2)` (syscall 78 on riscv64).
///
/// If the path exists but is not a symlink, Linux returns `err(SyscallError::EINVAL)`.

/// Linux `symlinkat(2)` (syscall 36 on riscv64).

/// Linux `linkat(2)` (syscall 37 on riscv64).

pub(crate) fn inode_eq(a: &Arc<ext4_fs::Inode>, b: &Arc<ext4_fs::Inode>) -> bool {
    a.device_id() == b.device_id() && a.inode_num() == b.inode_num()
}

pub(crate) fn path_is_descendant_of(
    dir: Arc<ext4_fs::Inode>,
    ancestor: &Arc<ext4_fs::Inode>,
) -> bool {
    let mut cur = dir;
    for _ in 0..256 {
        if inode_eq(&cur, ancestor) {
            return true;
        }
        let Some(parent) = cur.find("..") else {
            return false;
        };
        if inode_eq(&parent, &cur) {
            return false;
        }
        cur = parent;
    }
    false
}

pub(crate) fn sticky_rename_allowed(
    parent: &Arc<ext4_fs::Inode>,
    victim: &Arc<ext4_fs::Inode>,
    fsuid: u32,
) -> bool {
    if (parent.mode() & 0o1000) == 0 {
        return true;
    }
    fsuid == 0 || fsuid == parent.uid() || fsuid == victim.uid()
}

pub(crate) fn remove_rename_target(parent: &Arc<ext4_fs::Inode>, name: &str) -> isize {
    match parent.unlink(name) {
        Ok(()) => 0,
        Err(ext4_fs::Ext4Error::Unsupported) => err(SyscallError::ENOTEMPTY),
        Err(e) => ext4_err_to_errno(e),
    }
}

pub(crate) fn do_renameat(
    olddirfd: isize,
    old_s: &str,
    newdirfd: isize,
    new_s: &str,
    no_replace: bool,
) -> isize {
    let old_at = match resolve_at_path(olddirfd, old_s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_at = match resolve_at_path(newdirfd, new_s) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let (AtPath::PseudoAbs(old_abs), AtPath::PseudoAbs(new_abs)) = (&old_at, &new_at) {
        if crate::fs::is_cgroup_pseudo_path(old_abs) && crate::fs::is_cgroup_pseudo_path(new_abs) {
            return cgroup_rename(old_abs, new_abs, no_replace);
        }
    }
    if matches!(old_at, AtPath::PseudoAbs(_)) || matches!(new_at, AtPath::PseudoAbs(_)) {
        return err(SyscallError::EROFS);
    }

    if rofs_for_path(olddirfd, old_s) || rofs_for_path(newdirfd, new_s) {
        return err(SyscallError::EROFS);
    }

    let _ext4_guard = ext4_lock();
    let (fsuid, fsgid) = current_fsuid_gid();
    let (old_parent, old_name) = match resolve_parent_and_name(&old_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (new_parent, new_name) = match resolve_parent_and_name(&new_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if old_name.is_empty() || new_name.is_empty() {
        return err(SyscallError::ENOENT);
    }
    if old_name == "." || old_name == ".." || new_name == "." || new_name == ".." {
        return err(SyscallError::EINVAL);
    }
    if old_name == new_name && inode_eq(&old_parent, &new_parent) {
        return 0;
    }
    if !old_parent.is_dir() || !new_parent.is_dir() {
        return err(SyscallError::ENOTDIR);
    }
    if !inode_mode_allows_uid_gid(&old_parent, 3, fsuid, fsgid)
        || !inode_mode_allows_uid_gid(&new_parent, 3, fsuid, fsgid)
    {
        return err(SyscallError::EACCES);
    }

    let Some(source) = old_parent.find(&old_name) else {
        return err(SyscallError::ENOENT);
    };
    if !sticky_rename_allowed(&old_parent, &source, fsuid) {
        return err(SyscallError::EPERM);
    }

    let target = new_parent.find(&new_name);
    if let Some(target_inode) = target.as_ref() {
        if !sticky_rename_allowed(&new_parent, target_inode, fsuid) {
            return err(SyscallError::EPERM);
        }
        if inode_eq(&source, target_inode) {
            return 0;
        }
        if source.is_dir() && !target_inode.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        if !source.is_dir() && target_inode.is_dir() {
            return err(SyscallError::EISDIR);
        }
        if source.is_dir() && target_inode.is_dir() && !target_inode.ls().is_empty() {
            return err(SyscallError::ENOTEMPTY);
        }
        if no_replace {
            return err(SyscallError::EEXIST);
        }
    }

    if source.is_dir() && path_is_descendant_of(new_parent.clone(), &source) {
        return err(SyscallError::EINVAL);
    }

    let same_parent = inode_eq(&old_parent, &new_parent);
    if !same_parent {
        if source.is_dir() {
            if new_parent.link_count() >= u16::MAX as u32 {
                return err(SyscallError::EMLINK);
            }
            return err(SyscallError::EXDEV);
        }

        if target.is_some() {
            let rc = remove_rename_target(&new_parent, &new_name);
            if rc != 0 {
                return rc;
            }
        }
        if let Err(e) = new_parent.link_inode(&new_name, &source) {
            return ext4_err_to_errno(e);
        }
        if let Err(e) = old_parent.unlink(&old_name) {
            let _ = new_parent.unlink(&new_name);
            return ext4_err_to_errno(e);
        }
        return 0;
    }

    if target.is_some() {
        let rc = remove_rename_target(&old_parent, &new_name);
        if rc != 0 {
            return rc;
        }
    }
    match old_parent.rename(&old_name, &new_name) {
        Ok(_) => 0,
        Err(e) => ext4_err_to_errno(e),
    }
}

pub(crate) fn do_renameat_exchange(
    olddirfd: isize,
    old_s: &str,
    newdirfd: isize,
    new_s: &str,
) -> isize {
    let old_at = match resolve_at_path(olddirfd, old_s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_at = match resolve_at_path(newdirfd, new_s) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if matches!(old_at, AtPath::PseudoAbs(_)) || matches!(new_at, AtPath::PseudoAbs(_)) {
        return err(SyscallError::EROFS);
    }
    if rofs_for_path(olddirfd, old_s) || rofs_for_path(newdirfd, new_s) {
        return err(SyscallError::EROFS);
    }

    let _ext4_guard = ext4_lock();
    let (fsuid, fsgid) = current_fsuid_gid();
    let (old_parent, old_name) = match resolve_parent_and_name(&old_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (new_parent, new_name) = match resolve_parent_and_name(&new_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if old_name.is_empty() || new_name.is_empty() {
        return err(SyscallError::ENOENT);
    }
    if old_name == "." || old_name == ".." || new_name == "." || new_name == ".." {
        return err(SyscallError::EINVAL);
    }
    if !inode_mode_allows_uid_gid(&old_parent, 3, fsuid, fsgid)
        || !inode_mode_allows_uid_gid(&new_parent, 3, fsuid, fsgid)
    {
        return err(SyscallError::EACCES);
    }

    let Some(old_inode) = old_parent.find(&old_name) else {
        return err(SyscallError::ENOENT);
    };
    let Some(new_inode) = new_parent.find(&new_name) else {
        return err(SyscallError::ENOENT);
    };

    if !sticky_rename_allowed(&old_parent, &old_inode, fsuid)
        || !sticky_rename_allowed(&new_parent, &new_inode, fsuid)
    {
        return err(SyscallError::EPERM);
    }
    if old_inode.is_dir() || new_inode.is_dir() {
        return err(SyscallError::EINVAL);
    }
    if old_inode.device_id() != new_inode.device_id() {
        return err(SyscallError::EXDEV);
    }
    if inode_eq(&old_inode, &new_inode) {
        return 0;
    }

    let pid = current_process().getpid();
    let mut tmp_name = String::new();
    for i in 0..64 {
        let candidate = alloc::format!(".rename_swap_{}.{}", pid, i);
        if old_parent.find(&candidate).is_none() && new_parent.find(&candidate).is_none() {
            tmp_name = candidate;
            break;
        }
    }
    if tmp_name.is_empty() {
        return err(SyscallError::EBUSY);
    }

    if let Err(e) = old_parent.link_inode(&tmp_name, &old_inode) {
        return ext4_err_to_errno(e);
    }
    if let Err(e) = old_parent.unlink(&old_name) {
        let _ = old_parent.unlink(&tmp_name);
        return ext4_err_to_errno(e);
    }
    if let Err(e) = old_parent.link_inode(&old_name, &new_inode) {
        let _ = old_parent.link_inode(&old_name, &old_inode);
        let _ = old_parent.unlink(&tmp_name);
        return ext4_err_to_errno(e);
    }
    if let Err(e) = new_parent.unlink(&new_name) {
        return ext4_err_to_errno(e);
    }
    if let Err(e) = new_parent.link_inode(&new_name, &old_inode) {
        let _ = new_parent.link_inode(&new_name, &new_inode);
        return ext4_err_to_errno(e);
    }
    if let Err(e) = old_parent.unlink(&tmp_name) {
        return ext4_err_to_errno(e);
    }
    0
}

/// Linux `renameat(2)` (syscall 38 on riscv64).

/// Linux `renameat2(2)` (syscall 276 on riscv64).

/// Linux `close_range(2)` (syscall 436 on riscv64/loongarch64).
///
/// Supported flags:
/// - `CLOSE_RANGE_UNSHARE` (materialize a private fd table before update)
/// - `CLOSE_RANGE_CLOEXEC`

pub(crate) fn mirror_inode_write_to_current_mmaps(
    os_inode: &OSInode,
    write_off: usize,
    user_src: usize,
    len: usize,
) {
    if len == 0 {
        return;
    }

    let inode = os_inode.ext4_inode();
    let pending_end = os_inode.pending_write_end();
    let (dev, ino, file_size) = {
        let _ext4_guard = ext4_lock();
        (
            inode.device_id(),
            inode.inode_num(),
            (inode.size() as usize).max(pending_end),
        )
    };
    update_inode_mmaps_size_all_processes(dev, ino, file_size);
    // 当前进程的 user-buffer write 可以直接按用户地址做旧路径镜像。
    let copies: Vec<(usize, usize, usize)> = {
        let process = current_process();
        let inner = process.borrow_mut();
        inner.memory_set.update_file_vm_size(dev, ino, file_size);
        inner
            .memory_set
            .file_vm_copy_targets(dev, ino, write_off, len)
    };
    if !copies.is_empty() {
        let token = get_current_token();
        let mut tmp = [0u8; 1024];
        for (dst, src_off, total) in copies {
            let mut done = 0usize;
            while done < total {
                let chunk = core::cmp::min(tmp.len(), total - done);
                if try_copy_from_user(
                    token,
                    (user_src + src_off + done) as *const u8,
                    &mut tmp[..chunk],
                )
                .is_err()
                {
                    return;
                }
                if try_copy_to_user_unchecked(token, (dst + done) as *mut u8, &tmp[..chunk])
                    .is_err()
                {
                    return;
                }
                done += chunk;
            }
        }
    }
    // 其他 mm 不能使用当前 token 写用户地址，只能先拷贝到内核缓冲再广播。
    mirror_inode_write_to_shared_mmaps_all_processes(dev, ino, write_off, user_src, len);
}

fn mirror_inode_write_to_shared_mmaps_all_processes(
    dev: usize,
    ino: u32,
    write_off: usize,
    user_src: usize,
    len: usize,
) {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    if processes.is_empty() {
        return;
    }

    let token = get_current_token();
    let mut tmp = [0u8; 1024];
    let mut done = 0usize;
    while done < len {
        let chunk = core::cmp::min(tmp.len(), len - done);
        if try_copy_from_user(token, (user_src + done) as *const u8, &mut tmp[..chunk]).is_err() {
            return;
        }
        // 同步全局 cache 和所有已 resident 的 MAP_SHARED 页。
        update_shared_file_page_cache(dev, ino, write_off + done, &tmp[..chunk]);
        for process in processes.iter() {
            let Some(inner) = process.try_borrow_mut() else {
                continue;
            };
            inner.memory_set.mirror_shared_file_write_to_resident_mmaps(
                dev,
                ino,
                write_off + done,
                &tmp[..chunk],
            );
        }
        done += chunk;
    }
}

pub(crate) fn mirror_inode_kernel_write_to_shared_mmaps(
    os_inode: &OSInode,
    write_off: usize,
    data: &[u8],
) {
    if data.is_empty() {
        return;
    }

    let inode = os_inode.ext4_inode();
    let pending_end = os_inode.pending_write_end();
    let (dev, ino, file_size) = {
        let _ext4_guard = ext4_lock();
        (
            inode.device_id(),
            inode.inode_num(),
            (inode.size() as usize).max(pending_end),
        )
    };
    update_inode_mmaps_size_all_processes(dev, ino, file_size);
    // sendfile/splice/copy_file_range 等 kernel-buffer 写入也要同步 mmap 视图。
    update_shared_file_page_cache(dev, ino, write_off, data);

    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes.iter() {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        inner
            .memory_set
            .mirror_shared_file_write_to_resident_mmaps(dev, ino, write_off, data);
    }
}

fn update_inode_mmaps_size_all_processes(dev: usize, ino: u32, file_size: usize) {
    // inode size 是全局事实，所有 mm 的 file_valid_len/SIGBUS tail 都要更新。
    resize_shared_file_page_cache(dev, ino, file_size);
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        inner.memory_set.update_file_vm_size(dev, ino, file_size);
    }
}

pub(crate) fn update_current_inode_mmaps_size(inode: &Arc<ext4_fs::Inode>) {
    let (dev, ino, file_size) = {
        let _ext4_guard = ext4_lock();
        (inode.device_id(), inode.inode_num(), inode.size() as usize)
    };
    update_inode_mmaps_size_all_processes(dev, ino, file_size);
    let process = current_process();
    let inner = process.borrow_mut();
    inner.memory_set.update_file_vm_size(dev, ino, file_size);
}

pub(crate) fn update_current_os_inode_mmaps_size(os_inode: &OSInode) {
    let pending_end = os_inode.pending_write_end();
    let inode = os_inode.ext4_inode();
    let (dev, ino, file_size) = {
        let _ext4_guard = ext4_lock();
        (
            inode.device_id(),
            inode.inode_num(),
            (inode.size() as usize).max(pending_end),
        )
    };
    update_inode_mmaps_size_all_processes(dev, ino, file_size);
    let process = current_process();
    let inner = process.borrow_mut();
    inner.memory_set.update_file_vm_size(dev, ino, file_size);
}

/// Linux `pread64(2)` (syscall 67 on riscv64).
///
/// Unlike `read(2)`, this does not update the file offset.

/// Linux `pwrite64(2)` (syscall 68 on riscv64).
///
/// Unlike `write(2)`, this does not update the file offset.

/// Linux `chroot(2)` (syscall 51 on riscv64/loongarch64).

/// Linux `fchdir(2)` (syscall 50 on riscv64/loongarch64).

pub(crate) fn fsize_limit_allows(new_len: usize) -> Result<(), isize> {
    let limit = {
        let process = current_process();
        let inner = process.borrow_mut();
        inner.rlimits.rlimit_fsize_cur
    };
    if limit != u64::MAX && (new_len as u64) > limit {
        let pid = current_process().getpid();
        queue_process_signal(pid, SIGXFSZ_NUM);
        return Err(err(SyscallError::EFBIG));
    }
    Ok(())
}

pub(crate) fn flush_open_inode_views(target: &Arc<ext4_fs::Inode>) {
    let target_ino = target.inode_num();
    let target_dev = target.device_id();
    let files = current_files().lock().iter_files_snapshot();
    for (_fd, file) in files {
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            continue;
        };
        let inode = os_inode.ext4_inode();
        if inode.inode_num() == target_ino && inode.device_id() == target_dev {
            let _ = os_inode.flush();
        }
    }
}

pub(crate) fn has_open_inode_view(target: &Arc<ext4_fs::Inode>) -> bool {
    let target_ino = target.inode_num();
    let target_dev = target.device_id();
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            // Cannot inspect this process — conservatively report the inode
            // as open so the caller defers the unlink rather than deleting
            // a file that may still be in use.
            return true;
        };
        let table = Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(Arc::as_ptr(&table) as usize) {
            continue;
        }
        if table
            .lock()
            .iter_files_snapshot()
            .into_iter()
            .any(|(_fd, file)| {
                file.as_any()
                    .downcast_ref::<OSInode>()
                    .map(|o| {
                        let inode = o.ext4_inode();
                        inode.inode_num() == target_ino && inode.device_id() == target_dev
                    })
                    .unwrap_or(false)
            })
        {
            return true;
        }
    }
    false
}

pub(crate) fn defer_unlink_open_file(
    parent: &Arc<ext4_fs::Inode>,
    name: &str,
    child: &Arc<ext4_fs::Inode>,
) -> Result<bool, isize> {
    if !child.is_file() || !has_open_inode_view(child) {
        return Ok(false);
    }
    let pid = current_process().getpid();
    for _ in 0..64 {
        let seq = TMPFILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let hidden = alloc::format!(".ltp_orphan.{}.{}", pid, seq);
        if parent.find(&hidden).is_some() {
            continue;
        }
        match parent.rename(name, &hidden) {
            Ok(_) => {
                register_deferred_unlink_cleanup(child, Arc::clone(parent), hidden);
                return Ok(true);
            }
            Err(e) => return Err(ext4_err_to_errno(e)),
        }
    }
    Err(err(SyscallError::ENOSPC))
}

pub(crate) fn truncate_regular_inode(inode: &Arc<ext4_fs::Inode>, new_len: usize) -> isize {
    let _ext4_guard = ext4_lock();
    if inode.is_dir() {
        return err(SyscallError::EISDIR);
    }
    if !inode.is_file() {
        return err(SyscallError::EINVAL);
    }
    let old_len = inode.size() as usize;
    if new_len == old_len {
        return 0;
    }
    if new_len == 0 {
        return match inode.clear() {
            Ok(_) => 0,
            Err(e) => ext4_err_to_errno(e),
        };
    }
    if new_len < old_len {
        let mut kept = vec![0u8; new_len];
        let got = inode.read_at(0, &mut kept);
        if got < new_len {
            kept[got..].fill(0);
        }
        if let Err(e) = inode.clear() {
            return ext4_err_to_errno(e);
        }
        if kept.is_empty() {
            return 0;
        }
        return match inode.write_at(0, &kept) {
            Ok(written) if written == kept.len() => 0,
            Ok(_) => err(SyscallError::EIO),
            Err(e) => ext4_err_to_errno(e),
        };
    }

    let mut off = old_len;
    let zeros = [0u8; 4096];
    while off < new_len {
        let chunk = core::cmp::min(zeros.len(), new_len - off);
        match inode.write_at(off, &zeros[..chunk]) {
            Ok(0) => return err(SyscallError::EIO),
            Ok(written) => off += written,
            Err(e) => return ext4_err_to_errno(e),
        }
    }
    0
}

pub(crate) fn read_inode_range(
    inode: &Arc<ext4_fs::Inode>,
    offset: usize,
    len: usize,
) -> Result<Vec<u8>, isize> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut out = vec![0u8; len];
    let mut done = 0usize;
    let _ext4_guard = ext4_lock();
    while done < len {
        let got = inode.read_at(offset + done, &mut out[done..]);
        if got == 0 {
            break;
        }
        done += got;
    }
    if done < len {
        out[done..].fill(0);
    }
    Ok(out)
}

pub(crate) fn write_inode_range(inode: &Arc<ext4_fs::Inode>, offset: usize, data: &[u8]) -> isize {
    if data.is_empty() {
        return 0;
    }
    let _ext4_guard = ext4_lock();
    let mut done = 0usize;
    while done < data.len() {
        match inode.write_at(offset + done, &data[done..]) {
            Ok(0) => return err(SyscallError::EIO),
            Ok(written) => done += written,
            Err(e) => return ext4_err_to_errno(e),
        }
    }
    0
}

pub(crate) fn write_zeros_range(inode: &Arc<ext4_fs::Inode>, offset: usize, len: usize) -> isize {
    if len == 0 {
        return 0;
    }
    let zeros = [0u8; 4096];
    let mut off = offset;
    let end = offset.saturating_add(len);
    let _ext4_guard = ext4_lock();
    while off < end {
        let chunk = core::cmp::min(zeros.len(), end - off);
        match inode.write_at(off, &zeros[..chunk]) {
            Ok(0) => return err(SyscallError::EIO),
            Ok(written) => off += written,
            Err(e) => return ext4_err_to_errno(e),
        }
    }
    0
}

pub(crate) fn punch_hole_keep_size(
    inode: &Arc<ext4_fs::Inode>,
    offset: usize,
    len: usize,
) -> isize {
    let old_size = {
        let _ext4_guard = ext4_lock();
        inode.size() as usize
    };
    if old_size == 0 || offset >= old_size || len == 0 {
        return 0;
    }
    let hole_end = core::cmp::min(offset.saturating_add(len), old_size);
    if hole_end <= offset {
        return 0;
    }
    let prefix = match read_inode_range(inode, 0, offset) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let suffix_len = old_size - hole_end;
    let suffix = match read_inode_range(inode, hole_end, suffix_len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    {
        let _ext4_guard = ext4_lock();
        if let Err(e) = inode.clear() {
            return ext4_err_to_errno(e);
        }
    }
    let ret = write_inode_range(inode, 0, &prefix);
    if ret != 0 {
        return ret;
    }
    write_inode_range(inode, hole_end, &suffix)
}
