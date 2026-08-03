use super::{
    AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, Arc, AtPath, BTreeMap, BTreeSet, FS_APPEND_FL,
    FS_IMMUTABLE_FL, Mutex, OSInode, Ordering, PID2PCB, SIGXFSZ_NUM, String, SyscallError,
    TMPFILE_SEQ, Vec, apply_chmod_to_vfs_path, clear_ext4_path_cache, current_effective_uid_gid,
    current_files, current_fsuid_gid, current_in_group, current_process, current_timespec,
    empty_path_fd_for_at_op, err, ext4_err_to_errno, ext4_topology_lock,
    fchmod_fd_for_at_empty_path, get_current_token, inode_mode_allows_uid_gid,
    inode_visible_size_with_disk_size, map_vfs_error, queue_process_signal, read_user_cstring,
    register_deferred_unlink_cleanup, resolve_at_inode, resolve_at_path, resolve_at_vfs_path,
    resolve_parent_and_name, resolve_parent_vfs_path, syscall_fchmod, try_copy_from_user,
    try_copy_to_user_unchecked, with_ext4_inode_write, with_ext4_inode_write_set,
};
use crate::fs::ext4::Ext4VfsNode;
use crate::fs::vfs::{VfsMetadata, VfsNodeKind, VfsPath, VfsRenameFlags};
use crate::mm::{resize_file_page_cache, update_file_page_cache};
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
    let flags = if strict_flags { flags } else { 0 };
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
            fchmod_fd_for_at_empty_path(fd, mode)
        } else {
            syscall_fchmod(fd, mode)
        };
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let (fsuid, fsgid) = current_fsuid_gid();
    let (euid, _egid) = current_effective_uid_gid();
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let vfs_path = match resolve_at_vfs_path(&at, fsuid, fsgid, follow_final) {
        Ok(path) if !path.node().as_any().is::<Ext4VfsNode>() => {
            return apply_chmod_to_vfs_path(&path, mode);
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
    with_ext4_inode_write(&inode, || {
        if euid != 0 && inode.uid() != euid {
            return err(SyscallError::EPERM);
        }
        let mut new_mode = (mode as u16) & 0o7777;
        if euid != 0 && (new_mode & 0o2000) != 0 && !current_in_group(inode.gid()) {
            new_mode &= !0o2000;
        }
        inode.set_mode(new_mode);
        clear_ext4_path_cache();
        0
    })
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
        Ok(()) => {
            clear_ext4_path_cache();
            0
        }
        Err(ext4_fs::Ext4Error::Unsupported) => err(SyscallError::ENOTEMPTY),
        Err(e) => ext4_err_to_errno(e),
    }
}

fn vfs_metadata_allows(metadata: VfsMetadata, mask: u16, uid: u32, gid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let shift = if uid == metadata.uid {
        6
    } else if gid == metadata.gid {
        3
    } else {
        0
    };
    ((metadata.mode >> shift) & mask) == mask
}

fn vfs_sticky_rename_allowed(parent: VfsMetadata, victim: VfsMetadata, fsuid: u32) -> bool {
    parent.mode & 0o1000 == 0 || fsuid == 0 || fsuid == parent.uid || fsuid == victim.uid
}

/// Test directory ancestry using the underlying dentry tree rather than a
/// reconstructed pathname. Bind mounts may expose the same dentry through a
/// different mount object, but the filesystem topology remains shared.
fn vfs_path_descends_from(path: &VfsPath, ancestor: &VfsPath) -> bool {
    if path.node().filesystem_id() != ancestor.node().filesystem_id() {
        return false;
    }
    let ancestor_id = ancestor.node().node_id();
    let mut current = Some(Arc::clone(path.dentry()));
    while let Some(dentry) = current {
        if dentry.node().node_id() == ancestor_id {
            return true;
        }
        current = dentry.parent();
    }
    false
}

/// Handle rename entirely through object identities for mutable non-ext4
/// filesystems. `None` leaves two ext4 parents on the existing inode adapter;
/// every mixed-backend case is completed here so it cannot fall through to a
/// pathname translation.
fn try_do_non_ext4_vfs_rename(
    old_at: &AtPath,
    new_at: &AtPath,
    fsuid: u32,
    fsgid: u32,
    flags: VfsRenameFlags,
) -> Option<isize> {
    let no_replace = flags.contains(VfsRenameFlags::NO_REPLACE);
    let exchange = flags.contains(VfsRenameFlags::EXCHANGE);
    let old_parent = match resolve_parent_vfs_path(old_at, fsuid, fsgid) {
        Ok(parent) => parent,
        Err(error) => return Some(error),
    };
    let new_parent = match resolve_parent_vfs_path(new_at, fsuid, fsgid) {
        Ok(parent) => parent,
        Err(error) => return Some(error),
    };
    let has_non_ext4_parent = !old_parent.parent.node().as_any().is::<Ext4VfsNode>()
        || !new_parent.parent.node().as_any().is::<Ext4VfsNode>();
    if !has_non_ext4_parent {
        return None;
    }
    if old_parent.parent.node().as_any().is::<Ext4VfsNode>()
        || new_parent.parent.node().as_any().is::<Ext4VfsNode>()
        || old_parent.parent.mount().id() != new_parent.parent.mount().id()
    {
        // Linux filename_renameat2() requires the same vfsmount, even when
        // two bind mounts happen to expose the same superblock.
        return Some(err(SyscallError::EXDEV));
    }
    if old_parent.parent.mount().flags().is_read_only()
        || new_parent.parent.mount().flags().is_read_only()
    {
        return Some(err(SyscallError::EROFS));
    }

    let source = match resolve_at_vfs_path(old_at, fsuid, fsgid, false) {
        Ok(path) => path,
        Err(error) => return Some(error),
    };
    if source.mount().id() != old_parent.parent.mount().id() {
        return Some(err(SyscallError::EBUSY));
    }
    let source_metadata = match source.node().metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Some(map_vfs_error(error)),
    };
    if source_metadata.kind != VfsNodeKind::Directory && old_parent.trailing_slash {
        return Some(err(SyscallError::ENOTDIR));
    }

    let target = match resolve_at_vfs_path(new_at, fsuid, fsgid, false) {
        Ok(path) => Some(path),
        Err(error) if error == err(SyscallError::ENOENT) => None,
        Err(error) => return Some(error),
    };
    if let Some(target) = target.as_ref() {
        if no_replace {
            return Some(err(SyscallError::EEXIST));
        }
        if target.mount().id() != new_parent.parent.mount().id() {
            return Some(err(SyscallError::EBUSY));
        }
        if target.node().filesystem_id() == source.node().filesystem_id()
            && target.node().node_id() == source.node().node_id()
        {
            return Some(0);
        }
    } else if exchange {
        return Some(err(SyscallError::ENOENT));
    }
    let target_metadata = match target.as_ref() {
        Some(target) => match target.node().metadata() {
            Ok(metadata) => Some(metadata),
            Err(error) => return Some(map_vfs_error(error)),
        },
        None => None,
    };
    if (!exchange && source_metadata.kind != VfsNodeKind::Directory
        || exchange
            && target_metadata.is_some_and(|metadata| metadata.kind != VfsNodeKind::Directory))
        && new_parent.trailing_slash
    {
        return Some(err(SyscallError::ENOTDIR));
    }

    let old_parent_metadata = match old_parent.parent.node().metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Some(map_vfs_error(error)),
    };
    let new_parent_metadata = match new_parent.parent.node().metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Some(map_vfs_error(error)),
    };
    if old_parent_metadata.kind != VfsNodeKind::Directory
        || new_parent_metadata.kind != VfsNodeKind::Directory
    {
        return Some(err(SyscallError::ENOTDIR));
    }
    if !vfs_metadata_allows(old_parent_metadata, 3, fsuid, fsgid)
        || !vfs_metadata_allows(new_parent_metadata, 3, fsuid, fsgid)
    {
        return Some(err(SyscallError::EACCES));
    }
    if !vfs_sticky_rename_allowed(old_parent_metadata, source_metadata, fsuid) {
        return Some(err(SyscallError::EPERM));
    }
    if source_metadata.kind == VfsNodeKind::Directory
        && old_parent.parent.node().node_id() != new_parent.parent.node().node_id()
        && !vfs_metadata_allows(source_metadata, 2, fsuid, fsgid)
    {
        // Moving a directory changes its `..` relationship, which Linux
        // guards with MAY_WRITE on the directory itself.
        return Some(err(SyscallError::EACCES));
    }
    if source_metadata.kind == VfsNodeKind::Directory
        && vfs_path_descends_from(&new_parent.parent, &source)
    {
        return Some(err(SyscallError::EINVAL));
    }
    if let (Some(target), Some(target_metadata)) = (target.as_ref(), target_metadata) {
        if !vfs_sticky_rename_allowed(new_parent_metadata, target_metadata, fsuid) {
            return Some(err(SyscallError::EPERM));
        }
        if exchange
            && target_metadata.kind == VfsNodeKind::Directory
            && old_parent.parent.node().node_id() != new_parent.parent.node().node_id()
            && !vfs_metadata_allows(target_metadata, 2, fsuid, fsgid)
        {
            return Some(err(SyscallError::EACCES));
        }
        if exchange
            && target_metadata.kind == VfsNodeKind::Directory
            && vfs_path_descends_from(&old_parent.parent, target)
        {
            return Some(err(SyscallError::EINVAL));
        }
    }

    let result = old_parent.parent.node().rename_with_flags(
        &old_parent.name,
        new_parent.parent.node(),
        &new_parent.name,
        flags,
    );
    match result {
        Ok(()) => {
            let cache = old_parent.parent.mount().filesystem().dentry_cache();
            cache.invalidate(old_parent.parent.dentry(), &old_parent.name);
            cache.invalidate(new_parent.parent.dentry(), &new_parent.name);
            Some(0)
        }
        Err(error) => Some(map_vfs_error(error)),
    }
}

/// Enforce mount-local rename rules for ext4 paths before entering the inode
/// adapter.  Linux compares `struct mount` identity (not only superblocks),
/// rejects renaming mounted-over objects, and obtains write access from the
/// parent mount.
fn validate_ext4_rename_mounts(
    old_at: &AtPath,
    new_at: &AtPath,
    fsuid: u32,
    fsgid: u32,
    target_required: bool,
) -> Result<(), isize> {
    let old_parent = resolve_parent_vfs_path(old_at, fsuid, fsgid)?;
    let new_parent = resolve_parent_vfs_path(new_at, fsuid, fsgid)?;
    if old_parent.parent.mount().id() != new_parent.parent.mount().id() {
        return Err(err(SyscallError::EXDEV));
    }
    if old_parent.parent.mount().flags().is_read_only()
        || new_parent.parent.mount().flags().is_read_only()
    {
        return Err(err(SyscallError::EROFS));
    }

    let source = resolve_at_vfs_path(old_at, fsuid, fsgid, false)?;
    if source.mount().id() != old_parent.parent.mount().id() {
        return Err(err(SyscallError::EBUSY));
    }
    match resolve_at_vfs_path(new_at, fsuid, fsgid, false) {
        Ok(target) => {
            if target.mount().id() != new_parent.parent.mount().id() {
                return Err(err(SyscallError::EBUSY));
            }
        }
        Err(error) if !target_required && error == err(SyscallError::ENOENT) => {}
        Err(error) => return Err(error),
    }
    Ok(())
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

    let (fsuid, fsgid) = current_fsuid_gid();
    let flags = VfsRenameFlags(if no_replace {
        VfsRenameFlags::NO_REPLACE
    } else {
        0
    });
    if let Some(result) = try_do_non_ext4_vfs_rename(&old_at, &new_at, fsuid, fsgid, flags) {
        return result;
    }
    if let Err(error) = validate_ext4_rename_mounts(&old_at, &new_at, fsuid, fsgid, false) {
        return error;
    }

    let (old_parent, old_name) = match resolve_parent_and_name(&old_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (new_parent, new_name) = match resolve_parent_and_name(&new_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let _topology_guard = (!inode_eq(&old_parent, &new_parent)).then(ext4_topology_lock);

    with_ext4_inode_write_set(&[old_parent.as_ref(), new_parent.as_ref()], || {
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
        let target = new_parent.find(&new_name);

        // Do this before taking child locks: `new_parent` can itself be the
        // source directory for `rename("a", "a/b")`, in which case nesting
        // the source i_rwsem below would recursively lock a parent semaphore.
        if source.is_dir() && path_is_descendant_of(new_parent.clone(), &source) {
            return err(SyscallError::EINVAL);
        }

        let mut changed_inodes = vec![source.as_ref()];
        if let Some(target_inode) = target.as_ref() {
            changed_inodes.push(target_inode.as_ref());
        }
        with_ext4_inode_write_set(&changed_inodes, || {
            if !sticky_rename_allowed(&old_parent, &source, fsuid) {
                return err(SyscallError::EPERM);
            }
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

            let same_parent = inode_eq(&old_parent, &new_parent);
            clear_ext4_path_cache();
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
        })
    })
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

    let (fsuid, fsgid) = current_fsuid_gid();
    if let Some(result) = try_do_non_ext4_vfs_rename(
        &old_at,
        &new_at,
        fsuid,
        fsgid,
        VfsRenameFlags(VfsRenameFlags::EXCHANGE),
    ) {
        return result;
    }
    if let Err(error) = validate_ext4_rename_mounts(&old_at, &new_at, fsuid, fsgid, true) {
        return error;
    }

    let (old_parent, old_name) = match resolve_parent_and_name(&old_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (new_parent, new_name) = match resolve_parent_and_name(&new_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let _topology_guard = (!inode_eq(&old_parent, &new_parent)).then(ext4_topology_lock);

    with_ext4_inode_write_set(&[old_parent.as_ref(), new_parent.as_ref()], || {
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

        with_ext4_inode_write_set(&[old_inode.as_ref(), new_inode.as_ref()], || {
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

            clear_ext4_path_cache();
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
        })
    })
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
    let (dev, ino, disk_size) = super::with_ext4_inode_read(&inode, || {
        (inode.device_id(), inode.inode_num(), inode.size() as usize)
    });
    let file_size = inode_visible_size_with_disk_size(&inode, disk_size);
    update_inode_mmaps_size_all_processes(dev, ino, file_size);
    // 当前进程的 user-buffer write 可以直接对 MAP_SHARED 做旧路径镜像。
    // MAP_PRIVATE 由 inode page cache + COW 保持 Linux 语义。
    let copies: Vec<(usize, usize, usize)> = {
        let process = current_process();
        let memory_set = process.memory_set();
        memory_set.update_file_vm_size(dev, ino, file_size);
        memory_set.file_vm_copy_targets(dev, ino, write_off, len)
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
        update_file_page_cache(dev, ino, write_off + done, &tmp[..chunk]);
        for process in processes.iter() {
            let Some(memory_set) = process.try_memory_set() else {
                continue;
            };
            memory_set.mirror_shared_file_write_to_resident_mmaps(
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
    let (dev, ino, disk_size) = super::with_ext4_inode_read(&inode, || {
        (inode.device_id(), inode.inode_num(), inode.size() as usize)
    });
    let file_size = inode_visible_size_with_disk_size(&inode, disk_size);
    update_inode_mmaps_size_all_processes(dev, ino, file_size);
    // sendfile/splice/copy_file_range 等 kernel-buffer 写入也要同步 mmap 视图。
    update_file_page_cache(dev, ino, write_off, data);

    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes.iter() {
        let Some(memory_set) = process.try_memory_set() else {
            continue;
        };
        memory_set.mirror_shared_file_write_to_resident_mmaps(dev, ino, write_off, data);
    }
}

fn update_inode_mmaps_size_all_processes(dev: usize, ino: u32, file_size: usize) {
    // inode size 是全局事实，所有 mm 的 file_valid_len/SIGBUS tail 都要更新。
    resize_file_page_cache(dev, ino, file_size);
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes {
        let Some(memory_set) = process.try_memory_set() else {
            continue;
        };
        memory_set.update_file_vm_size(dev, ino, file_size);
    }
}

pub(crate) fn update_current_inode_mmaps_size(inode: &Arc<ext4_fs::Inode>) {
    let (dev, ino, disk_size) = super::with_ext4_inode_read(inode, || {
        (inode.device_id(), inode.inode_num(), inode.size() as usize)
    });
    let file_size = inode_visible_size_with_disk_size(inode, disk_size);
    update_inode_mmaps_size_all_processes(dev, ino, file_size);
    let process = current_process();
    process
        .memory_set()
        .update_file_vm_size(dev, ino, file_size);
}

pub(crate) fn update_current_os_inode_mmaps_size(os_inode: &OSInode) {
    let inode = os_inode.ext4_inode();
    let (dev, ino, disk_size) = super::with_ext4_inode_read(&inode, || {
        (inode.device_id(), inode.inode_num(), inode.size() as usize)
    });
    let file_size = inode_visible_size_with_disk_size(&inode, disk_size);
    update_inode_mmaps_size_all_processes(dev, ino, file_size);
    let process = current_process();
    process
        .memory_set()
        .update_file_vm_size(dev, ino, file_size);
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
        clear_ext4_path_cache();
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
    let (device_id, inode_num, is_dir, is_file, disk_len) = {
        super::with_ext4_inode_read(inode, || {
            (
                inode.device_id(),
                inode.inode_num(),
                inode.is_dir(),
                inode.is_file(),
                inode.size() as usize,
            )
        })
    };
    if is_dir {
        return err(SyscallError::EISDIR);
    }
    if !is_file {
        return err(SyscallError::EINVAL);
    }
    let visible_len = inode_visible_size_with_disk_size(inode, disk_len);
    let shrinking_visible_size = new_len < visible_len;
    if shrinking_visible_size {
        if let Err(e) =
            crate::fs::flush_inode_pending_writes_before_truncate(device_id, inode_num, new_len)
        {
            return ext4_err_to_errno(e);
        }
    }

    let ret = with_ext4_inode_write(inode, || {
        let old_len = inode.size() as usize;
        if new_len == old_len {
            0
        } else if new_len == 0 {
            match inode.clear() {
                Ok(_) => 0,
                Err(e) => ext4_err_to_errno(e),
            }
        } else if new_len < old_len {
            let mut kept = vec![0u8; new_len];
            let got = inode.read_at(0, &mut kept);
            if got < new_len {
                kept[got..].fill(0);
            }
            if let Err(e) = inode.clear() {
                return ext4_err_to_errno(e);
            }
            if kept.is_empty() {
                0
            } else {
                match inode.write_at(0, &kept) {
                    Ok(written) if written == kept.len() => 0,
                    Ok(_) => err(SyscallError::EIO),
                    Err(e) => ext4_err_to_errno(e),
                }
            }
        } else {
            let mut off = old_len;
            let zeros = [0u8; 4096];
            let mut ret = 0;
            while off < new_len {
                let chunk = core::cmp::min(zeros.len(), new_len - off);
                match inode.write_at(off, &zeros[..chunk]) {
                    Ok(0) => {
                        ret = err(SyscallError::EIO);
                        break;
                    }
                    Ok(written) => off += written,
                    Err(e) => {
                        ret = ext4_err_to_errno(e);
                        break;
                    }
                }
            }
            ret
        }
    });
    if ret == 0 && shrinking_visible_size {
        crate::fs::discard_inode_pending_writes_after_truncate(device_id, inode_num, new_len);
    }
    ret
}

pub(crate) fn read_inode_range(
    inode: &Arc<ext4_fs::Inode>,
    offset: usize,
    len: usize,
) -> Result<Vec<u8>, isize> {
    if len == 0 {
        return Ok(Vec::new());
    }
    super::with_ext4_inode_read(inode, || read_inode_range_locked(inode, offset, len))
}

fn read_inode_range_locked(
    inode: &Arc<ext4_fs::Inode>,
    offset: usize,
    len: usize,
) -> Result<Vec<u8>, isize> {
    let mut out = vec![0u8; len];
    let mut done = 0usize;
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
    with_ext4_inode_write(inode, || write_inode_range_locked(inode, offset, data))
}

fn write_inode_range_locked(inode: &Arc<ext4_fs::Inode>, offset: usize, data: &[u8]) -> isize {
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
    with_ext4_inode_write(inode, || {
        while off < end {
            let chunk = core::cmp::min(zeros.len(), end - off);
            match inode.write_at(off, &zeros[..chunk]) {
                Ok(0) => return err(SyscallError::EIO),
                Ok(written) => off += written,
                Err(e) => return ext4_err_to_errno(e),
            }
        }
        0
    })
}

pub(crate) fn punch_hole_keep_size(
    inode: &Arc<ext4_fs::Inode>,
    offset: usize,
    len: usize,
) -> isize {
    with_ext4_inode_write(inode, || {
        let old_size = inode.size() as usize;
        if old_size == 0 || offset >= old_size || len == 0 {
            return 0;
        }
        let hole_end = core::cmp::min(offset.saturating_add(len), old_size);
        if hole_end <= offset {
            return 0;
        }
        let prefix = match read_inode_range_locked(inode, 0, offset) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let suffix_len = old_size - hole_end;
        let suffix = match read_inode_range_locked(inode, hole_end, suffix_len) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if let Err(e) = inode.clear() {
            return ext4_err_to_errno(e);
        }
        let ret = write_inode_range_locked(inode, 0, &prefix);
        if ret != 0 {
            return ret;
        }
        write_inode_range_locked(inode, hole_end, &suffix)
    })
}
