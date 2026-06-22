use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::task::manager::{PID2PCB, wakeup_task};
use crate::{
    fs::{
        CgroupFile, CgroupMountSpec, ClassifiedAbsPath, EventFdFile, File, MountNamespace,
        MountNamespaceState, MountPropagation, MountRecord, NamespaceFile, NetSocketFile, OSInode,
        Pipe, ProcMagicLinkFile, ProcPseudoFile, PseudoBlock, PseudoDir, PseudoDirent, PseudoFile,
        PseudoShmFile, PtyMasterFile, PtySlaveFile, RtcFile, SocketPairEnd, TimerFdFile, TtyFile,
        cgroup_charge_file_write, cgroup_logical_path_for_file, cgroup_mkdir, cgroup_mount,
        cgroup_rename, cgroup_rmdir, cgroup_umount, ext4_lock, find_path_in_roots,
        inode_logical_path, inode_raw_logical_path, make_pipe, mount_namespace_id,
        note_inode_path_hint, open_pseudo, pseudo_block_is_read_only, pseudo_block_note_sync,
        register_deferred_unlink_cleanup, resolve_final_symlink_abs_path,
        resolve_final_symlink_abs_path_locked, resolve_proc_magic_intermediate_abs_path,
        secondary_root_inode, shm_create, shm_get, shm_object_name, shm_remove,
    },
    mm::{
        MapPermission, UserBuffer, translated_byte_buffer, translated_mutref, try_copy_from_user,
        try_copy_to_user, try_copy_to_user_unchecked, try_read_user_value,
        try_translated_byte_buffer, try_write_user_value,
    },
    syscall::process::{is_inode_currently_executed_locked, lock_executing_inodes},
    task::processor::{
        block_current_and_run_next, current_files, current_files_and_nofile_limit, current_process,
        current_task,
    },
    task::{
        ProcessControlBlock,
        signal::{SIGXFSZ_NUM, has_wait_interrupting_pending, queue_process_signal},
        task_block::TaskControlBlock,
    },
    time::get_time_ms,
    trap::get_current_token,
};
use ext4_fs::sync_all;

pub(crate) use crate::syscall::error::{SyscallError, err};

mod ctl;
pub use ctl::*;
mod fcntl;
pub use fcntl::*;
mod open_close;
pub use open_close::*;
mod xattr;
pub use xattr::*;
mod dir;
pub use dir::*;
mod io;
pub use io::*;
mod stat;
pub use stat::*;
mod mount;
pub use mount::*;
mod stat_utils;
pub(crate) use stat_utils::*;
mod ctx_utils;
pub(crate) use ctx_utils::*;
mod lock_utils;
pub(crate) use lock_utils::*;
mod inode_utils;
pub(crate) use inode_utils::*;
mod fd_utils;
pub(crate) use fd_utils::*;
mod perm_utils;
pub(crate) use perm_utils::*;
mod path_utils;
pub(crate) use path_utils::*;
mod mount_utils;
pub(crate) use mount_utils::*;

/// Special `dirfd` meaning "resolve relative to the caller's current working directory".
pub(crate) const AT_FDCWD: isize = -100;
/// `*at` flag: do not follow the final symbolic link.
pub(crate) const AT_SYMLINK_NOFOLLOW: usize = 0x100;
/// `faccessat2` flag: check with effective uid/gid rather than real uid/gid.
pub(crate) const AT_EACCESS: usize = 0x200;
/// `*at` flag: follow the final symbolic link when the syscall supports both modes.
pub(crate) const AT_SYMLINK_FOLLOW: usize = 0x400;
/// `*at` flag: reserved for automount control; currently accepted for compatibility.
pub(crate) const AT_NO_AUTOMOUNT: usize = 0x800;
/// `*at` flag: permit an empty path and operate directly on `dirfd`.
pub(crate) const AT_EMPTY_PATH: usize = 0x1000;
/// Mask covering the `statx(2)` sync-behavior selector bits.
pub(crate) const AT_STATX_SYNC_TYPE: usize = 0x6000;

/// Mask for extracting the access mode bits from an `open(2)` flag word.
pub(crate) const O_ACCMODE: usize = 0x3;
pub(crate) const O_RDONLY: usize = 0x0;
pub(crate) const O_WRONLY: usize = 0x1;
pub(crate) const O_RDWR: usize = 0x2;
/// Create the file if it does not already exist.
pub(crate) const O_CREAT: usize = 0x40;
/// With `O_CREAT`, fail if the path already exists.
pub(crate) const O_EXCL: usize = 0x80;
/// Truncate a regular file to length 0 on open.
pub(crate) const O_TRUNC: usize = 0x200;
/// Force writes to append at the end of file.
pub(crate) const O_APPEND: usize = 0x400;
/// Open in nonblocking mode where supported.
pub(crate) const O_NONBLOCK: usize = 0x800;
/// Request direct I/O semantics.
pub(crate) const O_DIRECT: usize = 0x4000;
/// Enable signal-driven I/O notifications.
pub(crate) const O_ASYNC: usize = 0x2000;
/// Suppress atime updates on reads when permitted.
pub(crate) const O_NOATIME: usize = 0x40000;
/// Return a path-only descriptor with minimal data access rights.
pub(crate) const O_PATH: usize = 0x200000;
/// Require the target to be a directory.
pub(crate) const O_DIRECTORY: usize = 0x10000;
/// Reject a final symbolic link component.
pub(crate) const O_NOFOLLOW: usize = 0x20000;
/// Set close-on-exec on the returned fd.
pub(crate) const O_CLOEXEC: usize = 0x80000;
// __O_TMPFILE (020000000) | O_DIRECTORY from asm-generic/fcntl.h
/// Create an unnamed temporary inode in a directory.
pub(crate) const O_TMPFILE: usize = 0x410000;

/// `fcntl(F_SETFD)` bit: close this fd across `execve`.
pub(crate) const FD_CLOEXEC: u32 = 1;

/// Mount is read-only.
pub(crate) const MS_RDONLY: usize = 0x1;
/// Ignore set-user-ID and set-group-ID bits.
pub(crate) const MS_NOSUID: usize = 0x2;
/// Disallow device special files on this mount.
pub(crate) const MS_NODEV: usize = 0x4;
/// Disallow program execution on this mount.
pub(crate) const MS_NOEXEC: usize = 0x8;
/// Change flags on an existing mount.
pub(crate) const MS_REMOUNT: usize = 0x20;
/// Do not follow symlinks during path resolution on this mount.
pub(crate) const MS_NOSYMFOLLOW: usize = 0x100;
/// Suppress atime updates.
pub(crate) const MS_NOATIME: usize = 0x400;
/// Suppress atime updates for directories.
pub(crate) const MS_NODIRATIME: usize = 0x800;
/// Create a bind mount.
pub(crate) const MS_BIND: usize = 0x1000;
/// Move an existing mount tree.
pub(crate) const MS_MOVE: usize = 0x2000;
/// Apply the operation recursively to the mount subtree.
pub(crate) const MS_REC: usize = 0x4000;
/// Set propagation type to unbindable.
pub(crate) const MS_UNBINDABLE: usize = 1 << 17;
/// Set propagation type to private.
pub(crate) const MS_PRIVATE: usize = 1 << 18;
/// Set propagation type to slave.
pub(crate) const MS_SLAVE: usize = 1 << 19;
/// Set propagation type to shared.
pub(crate) const MS_SHARED: usize = 1 << 20;
/// Always update atime strictly per POSIX rules.
pub(crate) const MS_STRICTATIME: usize = 1 << 24;

/// Force unmount, even if the target is busy.
pub(crate) const MNT_FORCE: usize = 0x1;
/// Lazy unmount: detach now and clean up later.
pub(crate) const MNT_DETACH: usize = 0x2;
/// Mark for expiry if not in active use.
pub(crate) const MNT_EXPIRE: usize = 0x4;
/// Do not follow the final symlink of the unmount target.
pub(crate) const UMOUNT_NOFOLLOW: usize = 0x8;

/// Clone the selected mount subtree into a detached tree.
pub(crate) const OPEN_TREE_CLONE: usize = 0x1;
/// Resolve symlinks in the source path of `move_mount`.
#[allow(dead_code)]
pub(crate) const MOVE_MOUNT_F_SYMLINKS: usize = 0x1;
/// Permit automount traversal in the source path of `move_mount`.
#[allow(dead_code)]
pub(crate) const MOVE_MOUNT_F_AUTOMOUNTS: usize = 0x2;
/// Allow an empty source path in `move_mount`.
pub(crate) const MOVE_MOUNT_F_EMPTY_PATH: usize = 0x4;
/// Resolve symlinks in the destination path of `move_mount`.
#[allow(dead_code)]
pub(crate) const MOVE_MOUNT_T_SYMLINKS: usize = 0x10;
/// Permit automount traversal in the destination path of `move_mount`.
#[allow(dead_code)]
pub(crate) const MOVE_MOUNT_T_AUTOMOUNTS: usize = 0x20;
/// Allow an empty destination path in `move_mount`.
#[allow(dead_code)]
pub(crate) const MOVE_MOUNT_T_EMPTY_PATH: usize = 0x40;
/// Mask of all supported `move_mount(2)` flag bits.
pub(crate) const MOVE_MOUNT__MASK: usize = 0x77;
/// Return fsopen/fsmount/fspick descriptors with close-on-exec set.
pub(crate) const FSOPEN_CLOEXEC: usize = 0x1;
pub(crate) const FSMOUNT_CLOEXEC: usize = 0x1;
pub(crate) const FSPICK_CLOEXEC: usize = 0x1;
/// `fspick(2)`: do not follow the final symbolic link.
pub(crate) const FSPICK_SYMLINK_NOFOLLOW: usize = 0x2;
/// `fspick(2)`: reserved automount control flag.
pub(crate) const FSPICK_NO_AUTOMOUNT: usize = 0x4;
/// `fspick(2)`: allow selecting directly by fd with an empty path.
pub(crate) const FSPICK_EMPTY_PATH: usize = 0x8;

/// `fsconfig(2)`: set a boolean key.
#[allow(dead_code)]
pub(crate) const FSCONFIG_SET_FLAG: usize = 0;
/// `fsconfig(2)`: set a string-valued key.
#[allow(dead_code)]
pub(crate) const FSCONFIG_SET_STRING: usize = 1;
/// `fsconfig(2)`: set raw binary data.
#[allow(dead_code)]
pub(crate) const FSCONFIG_SET_BINARY: usize = 2;
/// `fsconfig(2)`: set a key from a path argument.
pub(crate) const FSCONFIG_SET_PATH: usize = 3;
/// `fsconfig(2)`: set a key from a path argument, allowing empty path.
pub(crate) const FSCONFIG_SET_PATH_EMPTY: usize = 4;
/// `fsconfig(2)`: set a key from a file descriptor.
pub(crate) const FSCONFIG_SET_FD: usize = 5;
/// `fsconfig(2)`: finalize and create a new superblock.
#[allow(dead_code)]
pub(crate) const FSCONFIG_CMD_CREATE: usize = 6;
/// `fsconfig(2)`: reconfigure an existing mount/superblock.
#[allow(dead_code)]
pub(crate) const FSCONFIG_CMD_RECONFIGURE: usize = 7;

/// `mount_setattr(2)` attribute bits, later translated into legacy `MS_*` flags.
pub(crate) const MOUNT_ATTR_RDONLY: usize = 0x00000001;
pub(crate) const MOUNT_ATTR_NOSUID: usize = 0x00000002;
pub(crate) const MOUNT_ATTR_NODEV: usize = 0x00000004;
pub(crate) const MOUNT_ATTR_NOEXEC: usize = 0x00000008;
pub(crate) const MOUNT_ATTR_NOATIME: usize = 0x00000010;
pub(crate) const MOUNT_ATTR_STRICTATIME: usize = 0x00000020;
pub(crate) const MOUNT_ATTR_NODIRATIME: usize = 0x00000080;
pub(crate) const MOUNT_ATTR_NOSYMFOLLOW: usize = 0x00200000;
/// `statx(2)` mount attribute bit exposed to userspace.
pub(crate) const ST_NOSYMFOLLOW: usize = 0x2000;

/// The subset of mount attributes this implementation accepts on `fsmount`.
pub(crate) const FSMOUNT_SUPPORTED_ATTRS: usize = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR_NOATIME
    | MOUNT_ATTR_STRICTATIME
    | MOUNT_ATTR_NODIRATIME
    | MOUNT_ATTR_NOSYMFOLLOW;
/// Maximum normalized path length accepted by pathname syscalls.
pub(crate) const PATH_MAX: usize = 4096;
/// Maximum single path component length.
pub(crate) const NAME_MAX: usize = 255;
/// Symlink resolution cap used to break loops.
pub(crate) const MAX_SYMLINKS: usize = 40;

/// File type bitmask within `st_mode`.
pub(crate) const S_IFMT: u16 = 0o170000;
pub(crate) const S_IFSOCK: u16 = 0o140000;
pub(crate) const S_IFREG: u16 = 0o100000;
pub(crate) const S_IFBLK: u16 = 0o060000;
pub(crate) const S_IFCHR: u16 = 0o020000;
pub(crate) const S_IFIFO: u16 = 0o010000;

/// Extended-attribute set only if the name does not already exist.
pub(crate) const XATTR_CREATE: usize = 0x1;
/// Extended-attribute set only if the name already exists.
pub(crate) const XATTR_REPLACE: usize = 0x2;
/// Maximum xattr name length.
pub(crate) const XATTR_NAME_MAX: usize = 255;
/// Maximum xattr value size accepted by the kernel.
pub(crate) const XATTR_SIZE_MAX: usize = 65536;
/// Minimum atomic write size guaranteed for pipes/FIFOs.
pub(crate) const PIPE_BUF: usize = 4096;
/// Linux signal number used for `SIGIO` async I/O delivery.
pub(crate) const SIGIO_NUM: usize = 29;
/// Maximum iovec count accepted by vectored I/O syscalls.
pub(crate) const IOV_MAX: usize = 1024;

/// `splice(2)` hint flags.
pub(crate) const SPLICE_F_MOVE: usize = 0x01;
pub(crate) const SPLICE_F_NONBLOCK: usize = 0x02;
pub(crate) const SPLICE_F_MORE: usize = 0x04;
pub(crate) const SPLICE_F_GIFT: usize = 0x08;
/// Alignment used when validating direct-I/O buffers and offsets.
pub(crate) const DIRECT_IO_ALIGN: usize = 512;

// fs/ioctl.h flags consumed by setxattr03.
pub(crate) const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub(crate) const FS_APPEND_FL: u32 = 0x0000_0020;
pub(crate) const FS_NODUMP_FL: u32 = 0x0000_0040;

/// Keep the apparent file size unchanged while allocating or punching.
pub(crate) const FALLOC_FL_KEEP_SIZE: usize = 0x01;
/// Deallocate blocks in the target range.
pub(crate) const FALLOC_FL_PUNCH_HOLE: usize = 0x02;
/// Flags currently accepted by this implementation of `fallocate(2)`.
pub(crate) const FALLOC_FL_SUPPORTED_MASK: usize = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;

pub(crate) static TMPFILE_SEQ: AtomicUsize = AtomicUsize::new(0);
pub(crate) static NEXT_MOUNT_STACK_SEQ: AtomicUsize = AtomicUsize::new(1);
pub(crate) static NEXT_MOUNT_EVENT_ID: AtomicUsize = AtomicUsize::new(1);
pub(crate) static NEXT_MOUNT_PEER_GROUP_ID: AtomicUsize = AtomicUsize::new(1);
