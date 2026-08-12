use super::{
    CgroupFile, FS_APPEND_FL, FS_IMMUTABLE_FL, FS_NODUMP_FL, File, MemfdFile, NamespaceFile,
    OSInode, Pipe, ProcMagicLinkFile, ProcPseudoFile, PseudoBlock, PseudoDir, PseudoFile,
    PtyMasterFile, PtySlaveFile, RtcFile, SyscallError, TtyFile, err, get_current_token,
    get_fd_file, get_inode_times, inode_fs_flags, inode_visible_size_with_disk_size,
    linux_dev_major, linux_dev_minor, translated_mutref, try_read_user_value, try_write_user_value,
    with_ext4_inode_read,
};
use crate::fs::vfs::{VfsNodeKind, VfsPath, VfsStatFs};
use crate::fs::{TunTapFile, ext4_inode_from_vfs_path};

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VmIoVec {
    pub(crate) iov_base: usize,
    pub(crate) iov_len: usize,
}

/// Reads one `iovec`/`vmsplice` segment descriptor from userspace.
pub(crate) fn read_vm_iovec(token: usize, iov_ptr: usize, index: usize) -> Result<VmIoVec, isize> {
    let iov_size = core::mem::size_of::<VmIoVec>();
    let Some(off) = index
        .checked_mul(iov_size)
        .and_then(|v| iov_ptr.checked_add(v))
    else {
        return Err(err(SyscallError::EFAULT));
    };
    try_read_user_value(token, off as *const VmIoVec).ok_or_else(|| err(SyscallError::EFAULT))
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct KStatFs {
    pub(crate) f_type: i64,
    pub(crate) f_bsize: i64,
    pub(crate) f_blocks: u64,
    pub(crate) f_bfree: u64,
    pub(crate) f_bavail: u64,
    pub(crate) f_files: u64,
    pub(crate) f_ffree: u64,
    pub(crate) f_fsid: [i32; 2],
    pub(crate) f_namelen: i64,
    pub(crate) f_frsize: i64,
    pub(crate) f_flags: i64,
    pub(crate) f_spare: [i64; 4],
}

/// Fills a userspace `statfs` buffer with best-effort ext4 superblock data.
pub(crate) fn fill_statfs(st_ptr: usize, mount_flags: i64) -> isize {
    fill_statfs_for_backend(st_ptr, crate::fs::MountBackend::Storage, mount_flags)
}

/// Copies one filesystem instance's `statfs` result to userspace.
///
/// Linux obtains the counters from `path.dentry->d_sb` and the visible flags
/// from `path.mnt`.  Keeping both inputs explicit prevents secondary ext4 and
/// tmpfs mounts from silently reporting the process-global root filesystem.
pub(crate) fn fill_statfs_from_vfs(
    st_ptr: usize,
    stat: VfsStatFs,
    filesystem_id: u64,
    mount_flags: i64,
) -> isize {
    if st_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let st = KStatFs {
        f_type: stat.magic as i64,
        f_bsize: stat.block_size as i64,
        f_blocks: stat.blocks,
        f_bfree: stat.blocks_free,
        f_bavail: stat.blocks_available,
        f_files: stat.files,
        f_ffree: stat.files_free,
        f_fsid: [filesystem_id as i32, (filesystem_id >> 32) as i32],
        f_namelen: stat.name_len as i64,
        f_frsize: stat.block_size as i64,
        f_flags: mount_flags,
        f_spare: [0; 4],
    };
    let token = get_current_token();
    if try_write_user_value(token, st_ptr as *mut KStatFs, &st).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub(crate) fn fill_statfs_for_backend(
    st_ptr: usize,
    backend: crate::fs::MountBackend,
    mount_flags: i64,
) -> isize {
    if st_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    if !matches!(backend, crate::fs::MountBackend::Storage) {
        let st = KStatFs {
            f_type: backend.statfs_magic(),
            f_bsize: 4096,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_fsid: [0, 0],
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: mount_flags,
            f_spare: [0; 4],
        };
        let token = get_current_token();
        if try_write_user_value(token, st_ptr as *mut KStatFs, &st).is_err() {
            return err(SyscallError::EFAULT);
        }
        return 0;
    }
    // ext4 statfs (best-effort; our ext4 allocator does not yet update
    // on-disk free counters, so these values may be stale after heavy writes,
    // but they are meaningful for `df`).
    let fs = crate::fs::EXT4_FS.lock();
    let sb = &fs.superblock;
    let block_size = sb.block_size() as i64;
    let total_blocks = sb.blocks_count();
    let free_blocks = ((sb.s_free_blocks_count_hi as u64) << 32) | sb.s_free_blocks_count_lo as u64;
    let reserved_blocks = ((sb.s_r_blocks_count_hi as u64) << 32) | sb.s_r_blocks_count_lo as u64;
    let bavail = free_blocks.saturating_sub(reserved_blocks);
    let st = KStatFs {
        // EXT4_SUPER_MAGIC
        f_type: 0xEF53,
        f_bsize: block_size,
        f_blocks: total_blocks,
        f_bfree: free_blocks,
        f_bavail: bavail,
        f_files: sb.s_inodes_count as u64,
        f_ffree: sb.s_free_inodes_count as u64,
        f_fsid: [0, 0],
        f_namelen: 255,
        f_frsize: block_size,
        f_flags: mount_flags,
        f_spare: [0; 4],
    };
    let token = get_current_token();
    if try_write_user_value(token, st_ptr as *mut KStatFs, &st).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct TimeSpec {
    pub(crate) sec: i64,
    pub(crate) nsec: i64,
}

pub(crate) const UTIME_OMIT: i64 = 0x3ffffffe;
pub(crate) const UTIME_NOW: i64 = 0x3fffffff;

/// Resolves one userspace `timespec` into an explicit timestamp or "leave unchanged".
pub(crate) fn resolve_utime(ts: TimeSpec, now: (i64, i64)) -> Result<Option<(i64, i64)>, isize> {
    match ts.nsec {
        UTIME_OMIT => Ok(None),
        UTIME_NOW => Ok(Some(now)),
        nsec if nsec >= 0 && nsec < 1_000_000_000 => {
            if ts.sec < 0 {
                Err(err(SyscallError::EINVAL))
            } else {
                Ok(Some((ts.sec, nsec)))
            }
        }
        _ => Err(err(SyscallError::EINVAL)),
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct KStat {
    pub(crate) st_dev: u64,
    pub(crate) st_ino: u64,
    pub(crate) st_mode: u32,
    pub(crate) st_nlink: u32,
    pub(crate) st_uid: u32,
    pub(crate) st_gid: u32,
    pub(crate) st_rdev: u64,
    pub(crate) __pad: u64,
    pub(crate) st_size: i64,
    pub(crate) st_blksize: u32,
    pub(crate) __pad2: i32,
    pub(crate) st_blocks: u64,
    pub(crate) st_atime_sec: i64,
    pub(crate) st_atime_nsec: i64,
    pub(crate) st_mtime_sec: i64,
    pub(crate) st_mtime_nsec: i64,
    pub(crate) st_ctime_sec: i64,
    pub(crate) st_ctime_nsec: i64,
    pub(crate) __unused: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StatxTimestamp {
    pub(crate) tv_sec: i64,
    pub(crate) tv_nsec: u32,
    pub(crate) __reserved: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Statx {
    pub(crate) stx_mask: u32,
    pub(crate) stx_blksize: u32,
    pub(crate) stx_attributes: u64,
    pub(crate) stx_nlink: u32,
    pub(crate) stx_uid: u32,
    pub(crate) stx_gid: u32,
    pub(crate) stx_mode: u16,
    pub(crate) __spare0: u16,
    pub(crate) stx_ino: u64,
    pub(crate) stx_size: u64,
    pub(crate) stx_blocks: u64,
    pub(crate) stx_attributes_mask: u64,
    pub(crate) stx_atime: StatxTimestamp,
    pub(crate) stx_btime: StatxTimestamp,
    pub(crate) stx_ctime: StatxTimestamp,
    pub(crate) stx_mtime: StatxTimestamp,
    pub(crate) stx_rdev_major: u32,
    pub(crate) stx_rdev_minor: u32,
    pub(crate) stx_dev_major: u32,
    pub(crate) stx_dev_minor: u32,
    pub(crate) __spare2: [u64; 14],
}

/// `statx(2)` mask selecting the basic metadata fields.
pub(crate) const STATX_BASIC_STATS: u32 = 0x07ff;
/// `statx(2)` attribute bits mirrored from inode flags.
pub(crate) const STATX_ATTR_IMMUTABLE: u64 = 0x0000_0010;
pub(crate) const STATX_ATTR_APPEND: u64 = 0x0000_0020;
pub(crate) const STATX_ATTR_NODUMP: u64 = 0x0000_0040;

pub(crate) const EXT4_ST_DEV: u64 = 1;

/// Computes Linux `st_blocks` units (512-byte sectors) for synthetic/ext4 stats.
pub(crate) fn stat_blocks_for_mode_size(mode: u32, size: i64) -> u64 {
    const S_IFMT: u32 = 0o170000;
    const S_IFLNK: u32 = 0o120000;
    if (mode & S_IFMT) == S_IFLNK || size <= 0 {
        0
    } else {
        (size as u64 + 511) / 512
    }
}

/// Maps ext4 dirent file types to Linux `DT_*` values.
pub(crate) fn dt_type_from_ext4(ftype: u8) -> u8 {
    match ftype {
        1 => 8,  // DT_REG
        2 => 4,  // DT_DIR
        3 => 2,  // DT_CHR
        4 => 6,  // DT_BLK
        5 => 1,  // DT_FIFO
        6 => 12, // DT_SOCK
        7 => 10, // DT_LNK
        _ => 0,  // DT_UNKNOWN
    }
}

/// Rounds `x` up to the next multiple of `align`.
pub(crate) fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

/// Reads a little-endian `u32` from a short byte slice.
pub(crate) fn read_u32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Reads a little-endian `u16` from a short byte slice.
pub(crate) fn read_u16_le(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[0], buf[1]])
}

/// Copies an arbitrary byte slice into userspace one byte at a time.
#[allow(dead_code)]
pub(crate) fn write_bytes_user(token: usize, mut dst: usize, bytes: &[u8]) {
    for b in bytes {
        *translated_mutref(token, dst as *mut u8) = *b;
        dst += 1;
    }
}

/// Builds a `statx_timestamp`, clamping nanoseconds into the kernel ABI range.
pub(crate) fn statx_timestamp(sec: i64, nsec: i64) -> StatxTimestamp {
    let ns = if nsec < 0 {
        0
    } else if nsec > i64::from(u32::MAX) {
        u32::MAX as i64
    } else {
        nsec
    };
    StatxTimestamp {
        tv_sec: sec,
        tv_nsec: ns as u32,
        __reserved: 0,
    }
}

/// Synthesizes `stat` metadata for a proc magic symlink from its target length.
pub(crate) fn proc_symlink_kstat(link_len: usize) -> KStat {
    let st_size = link_len as i64;
    let st_mode = 0o120777;
    KStat {
        st_dev: 0,
        st_ino: 1,
        st_mode,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad: 0,
        st_size,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: stat_blocks_for_mode_size(st_mode, st_size),
        st_atime_sec: 0,
        st_atime_nsec: 0,
        st_mtime_sec: 0,
        st_mtime_nsec: 0,
        st_ctime_sec: 0,
        st_ctime_nsec: 0,
        __unused: [0, 0],
    }
}

/// Builds ext4 `stat` metadata from a single inode metadata snapshot.
pub(crate) fn kstat_from_ext4_snapshot(
    meta: ext4_fs::InodeStatSnapshot,
    visible_size: usize,
) -> KStat {
    let mode = meta.mode as u32;
    let size = visible_size as i64;
    let blocks = stat_blocks_for_mode_size(mode, size);
    let times = get_inode_times(meta.inode_num as u64);

    KStat {
        st_dev: EXT4_ST_DEV,
        st_ino: meta.inode_num as u64,
        st_mode: mode,
        st_nlink: meta.nlink,
        st_uid: meta.uid,
        st_gid: meta.gid,
        st_rdev: meta.rdev_for_mode(),
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
    }
}

/// Build inode metadata directly from an object-VFS path.
pub(crate) fn kstat_from_vfs_path(path: &VfsPath) -> Result<KStat, isize> {
    if let Some(inode) = ext4_inode_from_vfs_path(path) {
        // Linux obtains pathname and descriptor metadata through the same
        // inode/superblock getattr path.  During this migration ext4 still
        // has a legacy stat device number, so do not leak the VFS-internal
        // filesystem identity through fstat(2) or a proc magic link.
        let meta = with_ext4_inode_read(&inode, || inode.stat_snapshot());
        let visible_size = inode_visible_size_with_disk_size(&inode, meta.size as usize);
        return Ok(kstat_from_ext4_snapshot(meta, visible_size));
    }
    let metadata = path.node().metadata().map_err(super::map_vfs_error)?;
    let kind_mode = match metadata.kind {
        VfsNodeKind::Socket => 0o140000,
        VfsNodeKind::Symlink => 0o120000,
        VfsNodeKind::Regular => 0o100000,
        VfsNodeKind::BlockDevice => 0o060000,
        VfsNodeKind::Directory => 0o040000,
        VfsNodeKind::CharacterDevice => 0o020000,
        VfsNodeKind::Fifo => 0o010000,
    };
    let size = metadata.size.min(i64::MAX as u64) as i64;
    let blocks = if metadata.kind == VfsNodeKind::Regular {
        metadata.size.saturating_add(511) / 512
    } else {
        0
    };
    let block_size = path
        .mount()
        .filesystem()
        .statfs()
        .map(|stat| stat.block_size)
        .unwrap_or(4096)
        .min(u32::MAX as u64) as u32;
    let split_time = |nanoseconds: u64| {
        (
            (nanoseconds / 1_000_000_000).min(i64::MAX as u64) as i64,
            (nanoseconds % 1_000_000_000) as i64,
        )
    };
    let (atime_sec, atime_nsec) = split_time(metadata.times.access_ns);
    let (mtime_sec, mtime_nsec) = split_time(metadata.times.modify_ns);
    let (ctime_sec, ctime_nsec) = split_time(metadata.times.change_ns);
    Ok(KStat {
        st_dev: path.mount().filesystem().filesystem_id(),
        st_ino: path.node().node_id(),
        st_mode: kind_mode | metadata.mode as u32,
        st_nlink: metadata.nlink,
        st_uid: metadata.uid,
        st_gid: metadata.gid,
        st_rdev: metadata.rdev,
        __pad: 0,
        st_size: size,
        st_blksize: block_size,
        __pad2: 0,
        st_blocks: blocks,
        st_atime_sec: atime_sec,
        st_atime_nsec: atime_nsec,
        st_mtime_sec: mtime_sec,
        st_mtime_nsec: mtime_nsec,
        st_ctime_sec: ctime_sec,
        st_ctime_nsec: ctime_nsec,
        __unused: [0, 0],
    })
}

/// Synthesizes `stat` metadata for open descriptors across pseudo, proc, and ext4 files.
pub(crate) fn kstat_from_file(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
) -> Result<KStat, isize> {
    if let Some(link) = file.as_any().downcast_ref::<ProcMagicLinkFile>() {
        return Ok(proc_symlink_kstat(link.target_len_hint()));
    }
    if let Some(path) = file.object_path() {
        return kstat_from_vfs_path(path);
    }
    if file.as_any().downcast_ref::<PseudoDir>().is_some()
        || file.as_any().downcast_ref::<PseudoFile>().is_some()
        || file.as_any().downcast_ref::<ProcPseudoFile>().is_some()
        || file.as_any().downcast_ref::<CgroupFile>().is_some()
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<MemfdFile>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
        || file.as_any().downcast_ref::<TunTapFile>().is_some()
        || file.as_any().downcast_ref::<TtyFile>().is_some()
        || file.as_any().downcast_ref::<PtyMasterFile>().is_some()
        || file.as_any().downcast_ref::<PtySlaveFile>().is_some()
        || file.as_any().downcast_ref::<Pipe>().is_some()
        || file.as_any().downcast_ref::<NamespaceFile>().is_some()
    {
        let mode: u32 = if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
            cgroup.mode()
        } else if file.as_any().downcast_ref::<Pipe>().is_some() {
            0o010600
        } else if file.as_any().downcast_ref::<PseudoBlock>().is_some() {
            0o060600
        } else if file.as_any().downcast_ref::<MemfdFile>().is_some() {
            0o100777
        } else if file.as_any().downcast_ref::<RtcFile>().is_some()
            || file.as_any().downcast_ref::<TunTapFile>().is_some()
        {
            0o100666
        } else if file.as_any().downcast_ref::<TtyFile>().is_some()
            || file.as_any().downcast_ref::<PtyMasterFile>().is_some()
            || file.as_any().downcast_ref::<PtySlaveFile>().is_some()
        {
            0o020666
        } else if file.as_any().downcast_ref::<NamespaceFile>().is_some() {
            0o100444
        } else if let Some(proc_file) = file.as_any().downcast_ref::<ProcPseudoFile>() {
            if proc_file.writable() {
                0o100644
            } else {
                0o100444
            }
        } else if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
            match pf.kind_tag() {
                crate::fs::PseudoKindTag::Null => 0o020666,
                crate::fs::PseudoKindTag::Zero | crate::fs::PseudoKindTag::Urandom => 0o020444,
                crate::fs::PseudoKindTag::Static => 0o100444,
            }
        } else {
            0o100444
        };
        let st_rdev: u64 = if file.as_any().downcast_ref::<PseudoBlock>().is_some() {
            EXT4_ST_DEV
        } else if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
            match pf.kind_tag() {
                crate::fs::PseudoKindTag::Null => 0x103,
                crate::fs::PseudoKindTag::Zero => 0x105,
                crate::fs::PseudoKindTag::Urandom => 0x109,
                crate::fs::PseudoKindTag::Static => 0,
            }
        } else if file.as_any().downcast_ref::<TunTapFile>().is_some() {
            0x0a_c8
        } else if file.as_any().downcast_ref::<TtyFile>().is_some() {
            0x500
        } else if file.as_any().downcast_ref::<PtyMasterFile>().is_some() {
            0x501
        } else if file.as_any().downcast_ref::<PtySlaveFile>().is_some() {
            0x502
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = file.as_any().downcast_ref::<MemfdFile>() {
            shm.len() as i64
        } else if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
            cgroup.len() as i64
        } else if let Some(proc_file) = file.as_any().downcast_ref::<ProcPseudoFile>() {
            proc_file.len().unwrap_or(0) as i64
        } else if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
            pf.len().unwrap_or(0) as i64
        } else {
            0
        };
        let st_blocks: u64 = if st_size <= 0 {
            0
        } else {
            ((st_size as u64 + 511) / 512) as u64
        };
        let st_ino = if let Some(memfd) = file.as_any().downcast_ref::<MemfdFile>() {
            memfd.memfd_id()
        } else if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
            pipe as *const Pipe as u64
        } else if let Some(ns) = file.as_any().downcast_ref::<NamespaceFile>() {
            ns.inode_number()
        } else {
            1
        };
        return Ok(KStat {
            st_dev: 0,
            st_ino,
            st_mode: mode,
            st_nlink: if file.as_any().downcast_ref::<MemfdFile>().is_some() {
                0
            } else {
                1
            },
            st_uid: 0,
            st_gid: 0,
            st_rdev,
            __pad: 0,
            st_size,
            st_blksize: 4096,
            __pad2: 0,
            st_blocks,
            st_atime_sec: 0,
            st_atime_nsec: 0,
            st_mtime_sec: 0,
            st_mtime_nsec: 0,
            st_ctime_sec: 0,
            st_ctime_nsec: 0,
            __unused: [0, 0],
        });
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        let perm = match (file.readable(), file.writable()) {
            (true, true) => 0o666,
            (true, false) => 0o444,
            (false, true) => 0o222,
            (false, false) => 0o000,
        };
        return Ok(KStat {
            st_dev: 0,
            st_ino: file.as_any() as *const dyn core::any::Any as *const () as u64,
            st_mode: 0o010000 | perm,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            __pad: 0,
            st_size: 0,
            st_blksize: 4096,
            __pad2: 0,
            st_blocks: 0,
            st_atime_sec: 0,
            st_atime_nsec: 0,
            st_mtime_sec: 0,
            st_mtime_nsec: 0,
            st_ctime_sec: 0,
            st_ctime_nsec: 0,
            __unused: [0, 0],
        });
    };
    let inode = os_inode.ext4_inode();

    let meta = with_ext4_inode_read(&inode, || inode.stat_snapshot());
    let disk_size = meta.size as usize;
    let visible_size = inode_visible_size_with_disk_size(&inode, disk_size);
    Ok(kstat_from_ext4_snapshot(meta, visible_size))
}

/// Converts the internal `KStat` form into the Linux `statx` ABI layout.
pub(crate) fn statx_from_kstat(st: &KStat) -> Statx {
    let stx_rdev_major = linux_dev_major(st.st_rdev);
    let stx_rdev_minor = linux_dev_minor(st.st_rdev);
    let stx_dev_major = linux_dev_major(st.st_dev);
    let stx_dev_minor = linux_dev_minor(st.st_dev);
    let fs_flags = if st.st_dev == EXT4_ST_DEV {
        inode_fs_flags(st.st_ino)
    } else {
        0
    };
    let stx_attributes = {
        let mut attrs = 0u64;
        if (fs_flags & FS_APPEND_FL) != 0 {
            attrs |= STATX_ATTR_APPEND;
        }
        if (fs_flags & FS_IMMUTABLE_FL) != 0 {
            attrs |= STATX_ATTR_IMMUTABLE;
        }
        if (fs_flags & FS_NODUMP_FL) != 0 {
            attrs |= STATX_ATTR_NODUMP;
        }
        attrs
    };
    // Keep compressed out of the advertised mask so tmpfs-backed runs match
    // Linux behavior (STATX_ATTR_COMPRESSED unsupported there).
    let stx_attributes_mask = if st.st_dev == EXT4_ST_DEV {
        STATX_ATTR_APPEND | STATX_ATTR_IMMUTABLE | STATX_ATTR_NODUMP
    } else {
        0
    };
    Statx {
        stx_mask: STATX_BASIC_STATS,
        stx_blksize: st.st_blksize,
        stx_attributes,
        stx_nlink: st.st_nlink,
        stx_uid: st.st_uid,
        stx_gid: st.st_gid,
        stx_mode: st.st_mode as u16,
        __spare0: 0,
        stx_ino: st.st_ino,
        stx_size: st.st_size.max(0) as u64,
        stx_blocks: st.st_blocks,
        stx_attributes_mask,
        stx_atime: statx_timestamp(st.st_atime_sec, st.st_atime_nsec),
        stx_btime: statx_timestamp(0, 0),
        stx_ctime: statx_timestamp(st.st_ctime_sec, st.st_ctime_nsec),
        stx_mtime: statx_timestamp(st.st_mtime_sec, st.st_mtime_nsec),
        stx_rdev_major,
        stx_rdev_minor,
        stx_dev_major,
        stx_dev_minor,
        __spare2: [0; 14],
    }
}

/// Returns `stat` metadata for an already opened descriptor.
pub(crate) fn kstat_from_fd(fd: usize) -> Result<KStat, isize> {
    let Some(file) = get_fd_file(fd) else {
        return Err(err(SyscallError::EBADF));
    };
    kstat_from_file(&file)
}
