use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::task::manager::{PID2PCB, wakeup_task};
use crate::{
    fs::{
        CgroupFile, CgroupMountSpec, ClassifiedAbsPath, EventFdFile, File, MountNamespace,
        MountNamespaceState, MountPropagation, MountRecord, NamespaceFile, NetSocketFile, OSInode,
        OpenFlags, Pipe, ProcMagicLinkFile, ProcPseudoFile, PseudoBlock, PseudoDir,
        PseudoDirent, PseudoFile, PseudoShmFile, PtyMasterFile, PtySlaveFile, RtcFile,
        SocketPairEnd, TimerFdFile, TtyFile, cgroup_charge_file_write,
        cgroup_logical_path_for_file, cgroup_mkdir, cgroup_mount, cgroup_rename, cgroup_rmdir,
        cgroup_umount, ext4_lock, find_path_in_roots, inode_logical_path, make_pipe,
        note_inode_path_hint, open_file, open_pseudo, shm_get, shm_object_name,
        mount_namespace_id, resolve_final_symlink_abs_path,
        resolve_final_symlink_abs_path_locked, resolve_proc_magic_intermediate_abs_path,
        pseudo_block_is_read_only, pseudo_block_note_sync, pseudo_block_stat_snapshot,
        register_deferred_unlink_cleanup, secondary_root_inode, shm_create, shm_remove,
    },
    mm::{
        MapPermission, UserBuffer, copy_from_user, copy_to_user, read_user_value,
        translated_byte_buffer, translated_mutref, try_copy_from_user,
        try_copy_to_user, try_copy_to_user_unchecked, try_read_user_value,
        try_translated_byte_buffer, try_write_user_value, write_user_value,
    },
    syscall::process::{is_inode_currently_executed_locked, lock_executing_inodes},
    task::processor::{
        block_current_and_run_next, current_files_process, current_process, current_task,
    },
    task::{
        ProcessControlBlock,
        signal::{SIGXFSZ_NUM, has_unmasked_pending, queue_process_signal},
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

pub(crate) const AT_FDCWD: isize = -100;
pub(crate) const AT_SYMLINK_NOFOLLOW: usize = 0x100;
pub(crate) const AT_SYMLINK_FOLLOW: usize = 0x400;
pub(crate) const AT_NO_AUTOMOUNT: usize = 0x800;
pub(crate) const AT_EMPTY_PATH: usize = 0x1000;
pub(crate) const AT_STATX_SYNC_TYPE: usize = 0x6000;

pub(crate) const O_ACCMODE: usize = 0x3;
pub(crate) const O_RDONLY: usize = 0x0;
pub(crate) const O_WRONLY: usize = 0x1;
pub(crate) const O_RDWR: usize = 0x2;
pub(crate) const O_CREAT: usize = 0x40;
pub(crate) const O_EXCL: usize = 0x80;
pub(crate) const O_TRUNC: usize = 0x200;
pub(crate) const O_APPEND: usize = 0x400;
pub(crate) const O_NONBLOCK: usize = 0x800;
pub(crate) const O_DIRECT: usize = 0x4000;
pub(crate) const O_ASYNC: usize = 0x2000;
pub(crate) const O_NOATIME: usize = 0x40000;
pub(crate) const O_PATH: usize = 0x200000;
pub(crate) const O_DIRECTORY: usize = 0x10000;
pub(crate) const O_NOFOLLOW: usize = 0x20000;
pub(crate) const O_CLOEXEC: usize = 0x80000;
// __O_TMPFILE (020000000) | O_DIRECTORY from asm-generic/fcntl.h
pub(crate) const O_TMPFILE: usize = 0x410000;

pub(crate) const FD_CLOEXEC: u32 = 1;

pub(crate) const MS_RDONLY: usize = 0x1;
pub(crate) const MS_NOSUID: usize = 0x2;
pub(crate) const MS_NODEV: usize = 0x4;
pub(crate) const MS_NOEXEC: usize = 0x8;
pub(crate) const MS_REMOUNT: usize = 0x20;
pub(crate) const MS_NOSYMFOLLOW: usize = 0x100;
pub(crate) const MS_NOATIME: usize = 0x400;
pub(crate) const MS_NODIRATIME: usize = 0x800;
pub(crate) const MS_BIND: usize = 0x1000;
pub(crate) const MS_MOVE: usize = 0x2000;
pub(crate) const MS_REC: usize = 0x4000;
pub(crate) const MS_UNBINDABLE: usize = 1 << 17;
pub(crate) const MS_PRIVATE: usize = 1 << 18;
pub(crate) const MS_SLAVE: usize = 1 << 19;
pub(crate) const MS_SHARED: usize = 1 << 20;
pub(crate) const MS_STRICTATIME: usize = 1 << 24;

pub(crate) const MNT_FORCE: usize = 0x1;
pub(crate) const MNT_DETACH: usize = 0x2;
pub(crate) const MNT_EXPIRE: usize = 0x4;
pub(crate) const UMOUNT_NOFOLLOW: usize = 0x8;

pub(crate) const OPEN_TREE_CLONE: usize = 0x1;
pub(crate) const MOVE_MOUNT_F_SYMLINKS: usize = 0x1;
pub(crate) const MOVE_MOUNT_F_AUTOMOUNTS: usize = 0x2;
pub(crate) const MOVE_MOUNT_F_EMPTY_PATH: usize = 0x4;
pub(crate) const MOVE_MOUNT_T_SYMLINKS: usize = 0x10;
pub(crate) const MOVE_MOUNT_T_AUTOMOUNTS: usize = 0x20;
pub(crate) const MOVE_MOUNT_T_EMPTY_PATH: usize = 0x40;
pub(crate) const MOVE_MOUNT__MASK: usize = 0x77;
pub(crate) const FSOPEN_CLOEXEC: usize = 0x1;
pub(crate) const FSMOUNT_CLOEXEC: usize = 0x1;
pub(crate) const FSPICK_CLOEXEC: usize = 0x1;
pub(crate) const FSPICK_SYMLINK_NOFOLLOW: usize = 0x2;
pub(crate) const FSPICK_NO_AUTOMOUNT: usize = 0x4;
pub(crate) const FSPICK_EMPTY_PATH: usize = 0x8;

pub(crate) const FSCONFIG_SET_FLAG: usize = 0;
pub(crate) const FSCONFIG_SET_STRING: usize = 1;
pub(crate) const FSCONFIG_SET_BINARY: usize = 2;
pub(crate) const FSCONFIG_SET_PATH: usize = 3;
pub(crate) const FSCONFIG_SET_PATH_EMPTY: usize = 4;
pub(crate) const FSCONFIG_SET_FD: usize = 5;
pub(crate) const FSCONFIG_CMD_CREATE: usize = 6;
pub(crate) const FSCONFIG_CMD_RECONFIGURE: usize = 7;

pub(crate) const MOUNT_ATTR_RDONLY: usize = 0x00000001;
pub(crate) const MOUNT_ATTR_NOSUID: usize = 0x00000002;
pub(crate) const MOUNT_ATTR_NODEV: usize = 0x00000004;
pub(crate) const MOUNT_ATTR_NOEXEC: usize = 0x00000008;
pub(crate) const MOUNT_ATTR_NOATIME: usize = 0x00000010;
pub(crate) const MOUNT_ATTR_STRICTATIME: usize = 0x00000020;
pub(crate) const MOUNT_ATTR_NODIRATIME: usize = 0x00000080;
pub(crate) const MOUNT_ATTR_NOSYMFOLLOW: usize = 0x00200000;
pub(crate) const ST_NOSYMFOLLOW: usize = 0x2000;

pub(crate) const FSMOUNT_SUPPORTED_ATTRS: usize = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR_NOATIME
    | MOUNT_ATTR_STRICTATIME
    | MOUNT_ATTR_NODIRATIME
    | MOUNT_ATTR_NOSYMFOLLOW;
pub(crate) const PATH_MAX: usize = 4096;
pub(crate) const NAME_MAX: usize = 255;
pub(crate) const MAX_SYMLINKS: usize = 40;

pub(crate) const S_IFMT: u16 = 0o170000;
pub(crate) const S_IFSOCK: u16 = 0o140000;
pub(crate) const S_IFREG: u16 = 0o100000;
pub(crate) const S_IFBLK: u16 = 0o060000;
pub(crate) const S_IFCHR: u16 = 0o020000;
pub(crate) const S_IFIFO: u16 = 0o010000;


pub(crate) const XATTR_CREATE: usize = 0x1;
pub(crate) const XATTR_REPLACE: usize = 0x2;
pub(crate) const XATTR_NAME_MAX: usize = 255;
pub(crate) const XATTR_SIZE_MAX: usize = 65536;
pub(crate) const PIPE_BUF: usize = 4096;
pub(crate) const SIGIO_NUM: usize = 29;
pub(crate) const IOV_MAX: usize = 1024;

pub(crate) const SPLICE_F_MOVE: usize = 0x01;
pub(crate) const SPLICE_F_NONBLOCK: usize = 0x02;
pub(crate) const SPLICE_F_MORE: usize = 0x04;
pub(crate) const SPLICE_F_GIFT: usize = 0x08;
pub(crate) const DIRECT_IO_ALIGN: usize = 512;

// fs/ioctl.h flags consumed by setxattr03.
pub(crate) const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub(crate) const FS_APPEND_FL: u32 = 0x0000_0020;
pub(crate) const FS_NODUMP_FL: u32 = 0x0000_0040;

pub(crate) const FALLOC_FL_KEEP_SIZE: usize = 0x01;
pub(crate) const FALLOC_FL_PUNCH_HOLE: usize = 0x02;
pub(crate) const FALLOC_FL_SUPPORTED_MASK: usize = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;

pub(crate) static TMPFILE_SEQ: AtomicUsize = AtomicUsize::new(0);
pub(crate) static NEXT_MOUNT_STACK_SEQ: AtomicUsize = AtomicUsize::new(1);
pub(crate) static NEXT_MOUNT_EVENT_ID: AtomicUsize = AtomicUsize::new(1);
pub(crate) static NEXT_MOUNT_PEER_GROUP_ID: AtomicUsize = AtomicUsize::new(1);

