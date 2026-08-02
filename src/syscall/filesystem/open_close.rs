use alloc::vec;
use alloc::vec::Vec;

use super::{
    Arc, AtPath, BTreeSet, FD_CLOEXEC, File, MemfdFile, O_ACCMODE, O_APPEND, O_ASYNC, O_CLOEXEC,
    O_CREAT, O_DIRECT, O_DIRECTORY, O_EXCL, O_NOATIME, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY,
    O_RDWR, O_TMPFILE, O_TRUNC, O_WRONLY, OSInode, Ordering, S_IFBLK, S_IFCHR, S_IFMT,
    SyscallError, TMPFILE_SEQ, VfsOpenedFile, apply_umask, clear_ext4_path_cache,
    current_effective_uid_gid, current_files, current_files_and_nofile_limit, current_fsuid_gid,
    current_process, err, ext4_err_to_errno, ext4_inode_lock, fanotify_notify_close,
    fanotify_notify_open, fanotify_permission_open, fifo_pipe_state_for_inode, file_lock_key,
    file_lock_key_from_inode, get_current_token, gid_for_created_inode, inode_mode_allows,
    inode_mode_allows_uid_gid, install_open_file_fd, invalidate_vfs_parent_entry,
    is_privileged_or_owner, make_pipe, map_vfs_error, maybe_signal_lease_break,
    mode_for_created_file, note_inode_path_hint, pin_legacy_file_path, read_user_cstring,
    remove_owner_file_lease_for_key, remove_process_record_locks_for_key, resolve_abs_path,
    resolve_at_inode_with_vfs_path_flags, resolve_at_path, resolve_at_vfs_path_with_flags,
    resolve_openat2_path, resolve_parent_and_name_with_flags, resolve_parent_vfs_path_with_flags,
    root_inode_for_device, set_inode_all_times_now, touch_inode_mtime_ctime_now,
    truncate_regular_inode, try_copy_from_user, try_write_user_value, with_ext4_inode_read,
};
use crate::fs::ext4::Ext4VfsNode;
use crate::fs::vfs::{LookupFlags, VfsMetadata, VfsNodeKind, VfsOpenOptions, VfsPath};

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

/// Open a pathname when it belongs to a non-ext4 object filesystem.
///
/// Returning `None` means the object path is ext4 and the existing optimized
/// inode adapter should continue handling it. Every non-ext4 outcome,
/// including errors, is returned as `Some` so it cannot fall back to a hidden
/// ext4 directory or pathname translation.
fn try_open_non_ext4_vfs(
    at: &AtPath,
    logical_path: &str,
    flags: usize,
    create_mode: u16,
    fsuid: u32,
    fsgid: u32,
    readable: bool,
    writable: bool,
    append: bool,
    o_path: bool,
    nofollow: bool,
    tmpfile_requested: bool,
    lookup_flags: LookupFlags,
) -> Option<isize> {
    let mut path = match resolve_at_vfs_path_with_flags(at, fsuid, fsgid, lookup_flags) {
        Ok(path) => Some(path),
        Err(error) if error == err(SyscallError::ENOENT) => None,
        Err(error) => return Some(error),
    };
    if path
        .as_ref()
        .is_some_and(|path| path.node().as_any().is::<Ext4VfsNode>())
    {
        return None;
    }

    if path.is_none() {
        let parent = match resolve_parent_vfs_path_with_flags(at, fsuid, fsgid, lookup_flags) {
            Ok(parent) => parent,
            Err(error) => return Some(error),
        };
        if parent.parent.node().as_any().is::<Ext4VfsNode>() {
            return None;
        }
        if (flags & O_CREAT) == 0 || tmpfile_requested || parent.trailing_slash {
            return Some(err(SyscallError::ENOENT));
        }
        let parent_metadata = match parent.parent.node().metadata() {
            Ok(metadata) => metadata,
            Err(error) => return Some(map_vfs_error(error)),
        };
        if parent_metadata.kind != VfsNodeKind::Directory {
            return Some(err(SyscallError::ENOTDIR));
        }
        if !vfs_metadata_allows(parent_metadata, 3, fsuid, fsgid) {
            return Some(err(SyscallError::EACCES));
        }
        if parent.parent.mount().flags().is_read_only() {
            return Some(err(SyscallError::EROFS));
        }
        let gid = if parent_metadata.mode & 0o2000 != 0 {
            parent_metadata.gid
        } else {
            fsgid
        };
        let created_mode = mode_for_created_file(create_mode, gid);
        let node = match parent.parent.node().create(&parent.name, created_mode) {
            Ok(node) => node,
            Err(error) => return Some(map_vfs_error(error)),
        };
        if let Err(error) = node.set_owner(fsuid, gid) {
            return Some(map_vfs_error(error));
        }
        invalidate_vfs_parent_entry(&parent);
        path = match resolve_at_vfs_path_with_flags(at, fsuid, fsgid, lookup_flags) {
            Ok(path) => Some(path),
            Err(error) => return Some(error),
        };
    } else if (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 && !tmpfile_requested {
        return Some(err(SyscallError::EEXIST));
    }

    if tmpfile_requested {
        return Some(err(SyscallError::EOPNOTSUPP));
    }
    let path: VfsPath = path.expect("non-ext4 path checked above");
    let metadata = match path.node().metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Some(map_vfs_error(error)),
    };
    if !o_path && nofollow && metadata.kind == VfsNodeKind::Symlink {
        return Some(err(SyscallError::ELOOP));
    }
    if (flags & O_DIRECTORY) != 0 && metadata.kind != VfsNodeKind::Directory {
        return Some(err(SyscallError::ENOTDIR));
    }
    if !o_path
        && metadata.kind == VfsNodeKind::Directory
        && ((flags & O_ACCMODE) != O_RDONLY || (flags & O_CREAT) != 0)
    {
        return Some(err(SyscallError::EISDIR));
    }
    let mut access_mask = 0u16;
    if readable {
        access_mask |= 4;
    }
    if writable {
        access_mask |= 2;
    }
    if !o_path && !vfs_metadata_allows(metadata, access_mask, fsuid, fsgid) {
        return Some(err(SyscallError::EACCES));
    }
    if (flags & O_NOATIME) != 0 {
        let (euid, _) = current_effective_uid_gid();
        if euid != 0 && euid != metadata.uid {
            return Some(err(SyscallError::EPERM));
        }
    }
    let readonly = path.mount().flags().is_read_only();
    if readonly && (writable || (flags & O_TRUNC) != 0) {
        return Some(err(SyscallError::EROFS));
    }
    if !o_path && metadata.kind == VfsNodeKind::Fifo {
        let state = fifo_pipe_state_for_inode(path.node().filesystem_id(), path.node().node_id());
        let accmode = flags & O_ACCMODE;
        if (flags & O_NONBLOCK) != 0 && accmode == O_WRONLY && !state.has_open_readers() {
            return Some(err(SyscallError::ENXIO));
        }
        let Some(file) = state.open_file(accmode) else {
            return Some(err(SyscallError::EINVAL));
        };
        let file = pin_legacy_file_path(file, path, logical_path);
        return Some(match install_open_file_fd(file, flags, false) {
            Ok(fd) => fd as isize,
            Err(error) => error,
        });
    }
    if !o_path && (flags & O_TRUNC) != 0 && writable && metadata.kind == VfsNodeKind::Regular {
        if let Err(error) = path.node().truncate(0) {
            return Some(map_vfs_error(error));
        }
    }
    if !o_path
        && path.mount().flags().is_nodev()
        && matches!(
            metadata.kind,
            VfsNodeKind::CharacterDevice | VfsNodeKind::BlockDevice
        )
    {
        return Some(err(SyscallError::EACCES));
    }
    if !o_path && let Some((filesystem_kind, file)) = crate::fs::kernel_file_from_path(&path) {
        // Linux pipefs installs `pipeanon_fops.open`, so reopening a proc-fd
        // pipe link creates another endpoint reference.  An internal shmem
        // path reopens the same memfd inode with an independent file offset.
        // sockfs and anon_inodefs retain their no-open inode operations.
        let reopened: Arc<dyn File + Send + Sync> = match filesystem_kind {
            crate::fs::KernelFileSystemKind::Pipe => file,
            crate::fs::KernelFileSystemKind::Shmem => {
                let Some(memfd) = file.as_any().downcast_ref::<MemfdFile>() else {
                    return Some(err(SyscallError::ENXIO));
                };
                Arc::new(memfd.reopen_with_mode(readable, writable))
            }
            crate::fs::KernelFileSystemKind::Socket
            | crate::fs::KernelFileSystemKind::Anonymous => {
                return Some(err(SyscallError::ENXIO));
            }
        };
        return Some(match install_open_file_fd(reopened, flags, false) {
            Ok(fd) => fd as isize,
            Err(error) => error,
        });
    }
    if !o_path
        && let Some(result) = crate::fs::open_devtmpfs_path(&path, logical_path, readable, writable)
    {
        let file = match result {
            Ok(file) => file,
            Err(error) => return Some(map_vfs_error(error)),
        };
        return Some(match install_open_file_fd(file, flags, false) {
            Ok(fd) => fd as isize,
            Err(error) => error,
        });
    }
    if !o_path
        && !matches!(
            metadata.kind,
            VfsNodeKind::Regular | VfsNodeKind::Directory | VfsNodeKind::Symlink
        )
    {
        return Some(err(SyscallError::EOPNOTSUPP));
    }
    let opened = match VfsOpenedFile::open(
        path,
        alloc::string::String::from(logical_path),
        VfsOpenOptions {
            readable,
            writable,
            append,
        },
        o_path,
    ) {
        Ok(opened) => opened,
        Err(error) => return Some(map_vfs_error(error)),
    };
    let file: alloc::sync::Arc<dyn File + Send + Sync> = opened;
    Some(match install_open_file_fd(file, flags, o_path) {
        Ok(fd) => fd as isize,
        Err(error) => error,
    })
}

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
const VALID_RESOLVE_FLAGS: u64 = RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH
    | RESOLVE_IN_ROOT
    | RESOLVE_CACHED;

const O_NOCTTY: usize = 0x100;
const O_DSYNC: usize = 0x1000;
const O_LARGEFILE: usize = 0x8000;
const O_SYNC_INTERNAL: usize = 0x100000;
const O_TMPFILE_INTERNAL: usize = 0x400000;
const O_EMPTYPATH: usize = 1 << 26;
const VALID_OPENAT2_FLAGS: usize = O_ACCMODE
    | O_CREAT
    | O_EXCL
    | O_NOCTTY
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_DSYNC
    | O_ASYNC
    | O_DIRECT
    | O_LARGEFILE
    | O_DIRECTORY
    | O_NOFOLLOW
    | O_NOATIME
    | O_CLOEXEC
    | O_SYNC_INTERNAL
    | O_PATH
    | O_TMPFILE_INTERNAL
    | O_EMPTYPATH;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn read_open_how(how_ptr: usize, size: usize) -> Result<OpenHow, isize> {
    const OPEN_HOW_SIZE_VER0: usize = core::mem::size_of::<OpenHow>();
    const OPEN_HOW_MAX_COPY: usize = 4096;

    if size < OPEN_HOW_SIZE_VER0 {
        return Err(err(SyscallError::EINVAL));
    }
    if size > OPEN_HOW_MAX_COPY {
        return Err(err(SyscallError::E2BIG));
    }
    if how_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let mut raw = vec![0u8; size];
    if try_copy_from_user(
        get_current_token(),
        how_ptr as *const u8,
        raw.as_mut_slice(),
    )
    .is_err()
    {
        return Err(err(SyscallError::EFAULT));
    }
    if raw[OPEN_HOW_SIZE_VER0..].iter().any(|byte| *byte != 0) {
        return Err(err(SyscallError::E2BIG));
    }
    let mut how = OpenHow::default();
    unsafe {
        core::ptr::copy_nonoverlapping(
            raw.as_ptr(),
            &mut how as *mut OpenHow as *mut u8,
            OPEN_HOW_SIZE_VER0,
        );
    }
    Ok(how)
}

fn validate_open_how(how: OpenHow) -> Result<(usize, usize, LookupFlags), isize> {
    let flags = usize::try_from(how.flags).map_err(|_| err(SyscallError::EINVAL))?;
    let mode = usize::try_from(how.mode).map_err(|_| err(SyscallError::EINVAL))?;
    if flags & !VALID_OPENAT2_FLAGS != 0 || how.resolve & !VALID_RESOLVE_FLAGS != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    if how.resolve & RESOLVE_BENEATH != 0 && how.resolve & RESOLVE_IN_ROOT != 0 {
        return Err(err(SyscallError::EINVAL));
    }

    let creates = flags & (O_CREAT | O_TMPFILE_INTERNAL) != 0;
    if creates {
        if mode & !0o7777 != 0 {
            return Err(err(SyscallError::EINVAL));
        }
    } else if mode != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    if flags & (O_DIRECTORY | O_CREAT) == (O_DIRECTORY | O_CREAT) {
        return Err(err(SyscallError::EINVAL));
    }
    if flags & O_TMPFILE_INTERNAL != 0
        && (flags & O_DIRECTORY == 0 || matches!(flags & O_ACCMODE, O_RDONLY))
    {
        return Err(err(SyscallError::EINVAL));
    }
    if flags & O_PATH != 0 {
        let valid_path_flags = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_EMPTYPATH;
        if flags & !valid_path_flags != 0 {
            return Err(err(SyscallError::EINVAL));
        }
    }

    // This VFS has no RCU/dcache-only proof. Linux permits returning EAGAIN
    // whenever RESOLVE_CACHED cannot complete without a slow lookup, so use
    // that conservative result instead of claiming a false cache hit.
    if how.resolve & RESOLVE_CACHED != 0 {
        return Err(err(SyscallError::EAGAIN));
    }

    let mut lookup = 0;
    if how.resolve & RESOLVE_NO_XDEV != 0 {
        lookup |= LookupFlags::NO_XDEV;
    }
    if how.resolve & RESOLVE_NO_MAGICLINKS != 0 {
        lookup |= LookupFlags::NO_MAGIC_LINKS;
    }
    if how.resolve & RESOLVE_NO_SYMLINKS != 0 {
        lookup |= LookupFlags::NO_SYMLINKS;
    }
    if how.resolve & RESOLVE_BENEATH != 0 {
        lookup |= LookupFlags::BENEATH;
    }
    if how.resolve & RESOLVE_IN_ROOT != 0 {
        lookup |= LookupFlags::IN_ROOT;
    }
    if flags & O_EMPTYPATH != 0 {
        lookup |= LookupFlags::ALLOW_EMPTY;
    }
    Ok((flags, mode, LookupFlags(lookup)))
}

/// Opens or creates a filesystem object across ext4 and all object filesystems.
pub fn syscall_openat(dirfd: isize, pathname: usize, flags: usize, mode: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    do_openat(dirfd, path, flags, mode, LookupFlags::default(), false)
}

/// Linux `openat2(2)`: validate the extensible `open_how` ABI before carrying
/// its resolve policy into the same open implementation used by `openat(2)`.
pub fn syscall_openat2(dirfd: isize, pathname: usize, how_ptr: usize, size: usize) -> isize {
    let how = match read_open_how(how_ptr, size) {
        Ok(how) => how,
        Err(error) => return error,
    };
    let (flags, mode, lookup_flags) = match validate_open_how(how) {
        Ok(validated) => validated,
        Err(error) => return error,
    };
    let path = match read_user_cstring(get_current_token(), pathname) {
        Ok(path) => path,
        Err(error) => return error,
    };
    do_openat(dirfd, path, flags, mode, lookup_flags, true)
}

fn do_openat(
    dirfd: isize,
    path: alloc::string::String,
    flags: usize,
    mode: usize,
    mut lookup_flags: LookupFlags,
    strict_object_lookup: bool,
) -> isize {
    if path.is_empty() && !lookup_flags.contains(LookupFlags::ALLOW_EMPTY) {
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
    // Linux makes O_CREAT|O_EXCL imply O_NOFOLLOW so a final symlink is
    // tested for existence rather than followed before returning EEXIST.
    let nofollow = (flags & O_NOFOLLOW) != 0 || ((flags & O_CREAT) != 0 && (flags & O_EXCL) != 0);
    if !nofollow {
        lookup_flags.0 |= LookupFlags::FOLLOW_FINAL;
    }
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
    let raw_abs = if path.is_empty() {
        None
    } else {
        match resolve_abs_path(dirfd, &path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    let append = !o_path && (flags & O_APPEND) != 0;

    let at = match if strict_object_lookup {
        resolve_openat2_path(dirfd, &path, lookup_flags)
    } else {
        resolve_at_path(dirfd, &path)
    } {
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
    let mut tmpfile_cleanup_parent: Option<alloc::sync::Arc<ext4_fs::Inode>> = None;
    let mut tmpfile_cleanup_name: Option<alloc::string::String> = None;
    let (fsuid, fsgid) = current_fsuid_gid();
    let logical_abs = raw_abs.as_deref().unwrap_or(path.as_str());
    if let Some(result) = try_open_non_ext4_vfs(
        &at,
        logical_abs,
        flags,
        create_mode,
        fsuid,
        fsgid,
        readable,
        writable,
        append,
        o_path,
        nofollow,
        tmpfile_requested,
        lookup_flags,
    ) {
        return result;
    }

    // ext4 lookup with search permission checks and symlink resolution.
    let mut opened_vfs_path = None;
    let mut inode = match resolve_at_inode_with_vfs_path_flags(&at, fsuid, fsgid, lookup_flags) {
        Ok((inode, vfs_path)) => {
            opened_vfs_path = Some(vfs_path);
            Some(inode)
        }
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
            if with_ext4_inode_read(inode_ref, || inode_ref.is_symlink()) {
                return err(SyscallError::ELOOP);
            }
        }
    }

    // Existing path + O_CREAT|O_EXCL must fail.
    if !tmpfile_requested && inode.is_some() && (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 {
        return err(SyscallError::EEXIST);
    }

    if tmpfile_requested {
        if opened_vfs_path
            .as_ref()
            .is_some_and(|path| path.mount().flags().is_read_only())
        {
            return err(SyscallError::EROFS);
        }
        let dir_inode = match inode {
            Some(ref i) => alloc::sync::Arc::clone(i),
            None => return err(SyscallError::ENOENT),
        };
        let (created_gid, created_mode) = {
            let dir_lock = ext4_inode_lock(&dir_inode);
            let _dir_guard = dir_lock.read();
            if !dir_inode.is_dir() {
                return err(SyscallError::ENOTDIR);
            }
            if !inode_mode_allows_uid_gid(&dir_inode, 3, fsuid, fsgid) {
                return err(SyscallError::EACCES);
            }
            let gid = gid_for_created_inode(Some(&dir_inode), fsgid);
            (gid, mode_for_created_file(create_mode, gid))
        };
        // Emulate anonymous tmpfile semantics using a hidden per-filesystem pool.
        // Use the known root inode for the same block device to avoid relying on
        // per-directory ".." lookups (which can leave stale hidden entries behind).
        let fs_root = root_inode_for_device(dir_inode.device_id())
            .unwrap_or_else(|| alloc::sync::Arc::clone(&dir_inode));
        let pool_name = ".ltp_tmpfile_pool";
        let fs_root_lock = ext4_inode_lock(&fs_root);
        let fs_root_guard = fs_root_lock.write();
        let pool_dir = if let Some(existing) = fs_root.find(pool_name) {
            if !existing.is_dir() {
                return err(SyscallError::ENOTDIR);
            }
            existing
        } else {
            match fs_root.create_dir(pool_name) {
                Ok(d) => {
                    clear_ext4_path_cache();
                    d.set_uid_gid(0, 0);
                    d.set_mode(0o1777);
                    d
                }
                Err(e) => return ext4_err_to_errno(e),
            }
        };
        drop(fs_root_guard);

        let pid = current_process().getpid();
        let mut tmp_created = None;
        let pool_lock = ext4_inode_lock(&pool_dir);
        let _pool_guard = pool_lock.write();
        for _ in 0..64 {
            let seq = TMPFILE_SEQ.fetch_add(1, Ordering::Relaxed);
            let name = alloc::format!(".tmp.{}.{}", pid, seq);
            if pool_dir.find(&name).is_some() {
                continue;
            }
            match pool_dir.create_file(&name) {
                Ok(i) => {
                    let child_lock = ext4_inode_lock(&i);
                    let _child_guard = child_lock.write();
                    i.set_uid_gid(fsuid, created_gid);
                    i.set_mode(created_mode);
                    set_inode_all_times_now(&i);
                    clear_ext4_path_cache();
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
        inode = Some(tmp_inode);
        created = true;
    }

    // CREATE: create file if missing (Linux: only affects the final component).
    if inode.is_none() && (flags & O_CREAT != 0) {
        let creation_parent =
            match resolve_parent_vfs_path_with_flags(&at, fsuid, fsgid, lookup_flags) {
                Ok(parent) => parent,
                Err(error) => return error,
            };
        if creation_parent.parent.mount().flags().is_read_only() {
            return err(SyscallError::EROFS);
        }
        let (parent, name) =
            match resolve_parent_and_name_with_flags(&at, fsuid, fsgid, lookup_flags) {
                Ok(v) => v,
                Err(e) => return e,
            };
        let parent_lock = ext4_inode_lock(&parent);
        let _parent_guard = parent_lock.write();
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
                let created_gid = gid_for_created_inode(Some(&parent), fsgid);
                let created_mode = mode_for_created_file(create_mode, created_gid);
                let child_lock = ext4_inode_lock(&i);
                let _child_guard = child_lock.write();
                i.set_uid_gid(fsuid, created_gid);
                i.set_mode(created_mode);
                set_inode_all_times_now(&i);
                created = true;
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

    let inode = match inode {
        Some(i) => i,
        None => return err(SyscallError::ENOENT),
    };

    if opened_vfs_path.is_none() && !tmpfile_requested {
        opened_vfs_path = match resolve_at_vfs_path_with_flags(&at, fsuid, fsgid, lookup_flags) {
            Ok(path) => Some(path),
            Err(e) => return e,
        };
    }

    if !tmpfile_requested {
        if let Some(abs) = raw_abs.as_deref() {
            note_inode_path_hint(&inode, abs);
        }
    }

    let readonly_fs = opened_vfs_path
        .as_ref()
        .is_some_and(|path| path.mount().flags().is_read_only());
    if readonly_fs && !created && !o_path && (writable || (flags & O_TRUNC) != 0) {
        return err(SyscallError::EROFS);
    }
    if opened_vfs_path
        .as_ref()
        .is_some_and(|path| path.mount().flags().is_nodev())
    {
        let mode = with_ext4_inode_read(&inode, || inode.mode() & S_IFMT);
        if matches!(mode, S_IFCHR | S_IFBLK) {
            return err(SyscallError::EACCES);
        }
    }

    let inode_lock = ext4_inode_lock(&inode);
    let inode_guard = inode_lock.read();
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

    if !o_path && inode.is_fifo() {
        let state = fifo_pipe_state_for_inode(inode.device_id() as u64, inode.inode_num() as u64);
        let accmode = flags & O_ACCMODE;
        if (flags & O_NONBLOCK) != 0 && accmode == O_WRONLY && !state.has_open_readers() {
            drop(inode_guard);
            return err(SyscallError::ENXIO);
        }
        let Some(mut file) = state.open_file(accmode) else {
            drop(inode_guard);
            return err(SyscallError::EINVAL);
        };
        drop(inode_guard);
        let logical_abs = raw_abs.as_deref().unwrap_or("/");
        if let Some(path) = opened_vfs_path.as_ref() {
            file = pin_legacy_file_path(file, path.clone(), logical_abs);
        }
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
    let os_inode = match OSInode::new_with_append_rofs_tmp_cleanup(
        readable,
        writable,
        append,
        alloc::sync::Arc::clone(&inode),
        readonly_fs,
        false,
        tmpfile_cleanup,
    ) {
        Ok(file) => alloc::sync::Arc::new(
            file.with_fanotify_path(raw_abs.clone())
                .with_vfs_path(opened_vfs_path),
        ),
        Err(e) => return e,
    };
    let fanotify_inode = os_inode.ext4_inode();
    let fanotify_is_dir = fanotify_inode.is_dir();
    let fanotify_path = os_inode.vfs_path().map(|path| path.path().clone());

    if !o_path && inode.is_file() {
        maybe_signal_lease_break(
            file_lock_key_from_inode(&inode),
            writable,
            false,
            current_process().getpid(),
        );
    }

    let needs_trunc = !o_path && (flags & O_TRUNC) != 0 && writable && inode.is_file();
    drop(inode_guard);
    if needs_trunc {
        let ret = truncate_regular_inode(&inode, 0);
        if ret != 0 {
            return ret;
        }
        touch_inode_mtime_ctime_now(&inode);
    }

    crate::fs::debug_track_iozone_inode(&path, inode_num);
    if !o_path
        && let Err(e) = fanotify_permission_open(
            &fanotify_inode,
            false,
            fanotify_is_dir,
            fanotify_path.as_ref(),
        )
    {
        return e;
    }
    let fd = match install_open_file_fd(os_inode, flags, o_path) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    if !o_path {
        fanotify_notify_open(&fanotify_inode, fanotify_is_dir, fanotify_path.as_ref());
    }
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
    let files = current_files();
    let detached = {
        let mut files = files.lock();
        let Some(file) = files.get_file(fd) else {
            return err(SyscallError::EBADF);
        };
        // Keep the removed file alive until after `files_lock` is released.
        // Linux likewise detaches the fd under the table lock and performs
        // filesystem close work outside it.  Per-inode sleeping locks must
        // never be reached while holding this shared spin lock.
        let removed = files
            .clear_fd(fd)
            .expect("fd disappeared while files_lock was held");
        drop(file);
        removed
    };
    let file = detached.complete_close();
    let lock_key = file_lock_key(&file);
    let fanotify_close = file
        .as_any()
        .downcast_ref::<OSInode>()
        .filter(|os_inode| !os_inode.fanotify_silent())
        .map(|os_inode| {
            let inode = os_inode.ext4_inode();
            let path = os_inode.vfs_path().map(|path| path.path().clone());
            let is_dir = with_ext4_inode_read(&inode, || inode.is_dir());
            (inode, file.writable(), is_dir, path)
        });
    if let Some((inode, writable, is_dir, path)) = fanotify_close {
        fanotify_notify_close(&inode, writable, is_dir, path.as_ref());
    }
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
    let files = process.files();
    let mut files = files.lock();
    if files.is_empty() {
        return 0;
    }
    let end = core::cmp::min(last, files.len() - 1);
    if first > end {
        return 0;
    }

    let mut lock_keys = BTreeSet::new();
    let mut removed_files = Vec::new();
    for fd in first..=end {
        if set_cloexec {
            if files.is_fd_open(fd) {
                let descriptor_flags = files.get_flags(fd) | FD_CLOEXEC;
                let _ = files.set_flags(fd, descriptor_flags);
            }
        } else if let Some(file) = files.get_file(fd) {
            if let Some(key) = file_lock_key(&file) {
                lock_keys.insert(key);
            }
            if let Some(removed) = files.clear_fd(fd) {
                removed_files.push(removed);
            }
        }
    }
    drop(files);
    for removed in removed_files {
        drop(removed.complete_close());
    }
    if !set_cloexec {
        let owner_pid = current_process().getpid();
        for key in lock_keys {
            remove_process_record_locks_for_key(owner_pid, key);
            remove_owner_file_lease_for_key(owner_pid, key);
        }
    }
    0
}

const O_NOTIFICATION_PIPE: usize = O_EXCL;

/// Creates a pipe pair and installs both ends into the caller's fd table.
pub fn syscall_pipe2(pipefd: usize, flags: usize) -> isize {
    if (flags & O_NOTIFICATION_PIPE) != 0 {
        return err(SyscallError::ENOPKG);
    }
    let (files, limit) = current_files_and_nofile_limit();
    let token = get_current_token();
    let (pipe_read, pipe_write) = make_pipe();

    let mut descriptor_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    if (flags & O_NONBLOCK) != 0 {
        descriptor_flags |= O_NONBLOCK as u32;
    }
    let mut files_guard = files.lock();
    let read_fd = match files_guard.install_fd(pipe_read, descriptor_flags, limit) {
        Ok(fd) => fd,
        Err(rejected) => {
            drop(files_guard);
            rejected.discard();
            return err(SyscallError::EMFILE);
        }
    };
    let write_fd = match files_guard.install_fd(pipe_write, descriptor_flags, limit) {
        Ok(fd) => fd,
        Err(rejected) => {
            let removed = files_guard
                .clear_fd(read_fd)
                .expect("newly installed pipe fd disappeared");
            drop(files_guard);
            rejected.discard();
            drop(removed.complete_close());
            return err(SyscallError::EMFILE);
        }
    };
    // Drop PCB borrow before user-memory writes: uaccess may need to resolve
    // lazy/COW pages via `process.try_borrow_mut()`.
    drop(files_guard);

    // Linux ABI: pipefd points to `int pipefd[2]` (i32).
    if try_write_user_value(token, pipefd as *mut i32, &(read_fd as i32)).is_err()
        || try_write_user_value(
            token,
            (pipefd + core::mem::size_of::<i32>()) as *mut i32,
            &(write_fd as i32),
        )
        .is_err()
    {
        let mut files_guard = files.lock();
        let read_end = files_guard.clear_fd(read_fd);
        let write_end = files_guard.clear_fd(write_fd);
        drop(files_guard);
        if let Some(read_end) = read_end {
            drop(read_end.complete_close());
        }
        if let Some(write_end) = write_end {
            drop(write_end.complete_close());
        }
        return err(SyscallError::EFAULT);
    }
    0
}

/// Duplicates a file descriptor into the lowest-numbered free slot.
pub fn syscall_dup(oldfd: usize) -> isize {
    let (files, limit) = current_files_and_nofile_limit();
    let mut files = files.lock();
    let Some((file, old_flags)) = files.get_file_and_flags(oldfd) else {
        return err(SyscallError::EBADF);
    };
    let installed = files.install_fd(file, old_flags & !FD_CLOEXEC, limit);
    drop(files);
    let newfd = match installed {
        Ok(fd) => fd,
        Err(rejected) => {
            rejected.discard();
            return err(SyscallError::EMFILE);
        }
    };
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
    let owner_pid = current_process().getpid();
    let (files, limit) = current_files_and_nofile_limit();
    if newfd >= limit {
        return err(SyscallError::EBADF);
    }
    let mut files = files.lock();
    let Some((file, old_flags)) = files.get_file_and_flags(oldfd) else {
        return err(SyscallError::EBADF);
    };
    let mut new_flags = old_flags;
    if (flags & O_CLOEXEC) != 0 {
        new_flags |= FD_CLOEXEC;
    } else {
        new_flags &= !FD_CLOEXEC;
    }
    let replaced = files.replace_fd_at(newfd, file, new_flags, limit);
    drop(files);
    let replaced_file = match replaced {
        Ok(replaced) => replaced,
        Err(rejected) => {
            rejected.discard();
            return err(SyscallError::EBADF);
        }
    };
    if let Some(replaced_file) = replaced_file {
        let replaced_file = replaced_file.complete_close();
        if let Some(key) = file_lock_key(&replaced_file) {
            remove_process_record_locks_for_key(owner_pid, key);
            remove_owner_file_lease_for_key(owner_pid, key);
        }
        drop(replaced_file);
    }
    newfd as isize
}
