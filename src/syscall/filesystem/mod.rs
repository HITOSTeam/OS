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

mod ctl;
pub use ctl::*;
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
pub(crate) const ETXTBSY: isize = -26;

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

// Linux errno (negative return in kernel ABI).
pub(crate) const EBADF: isize = -9;
pub(crate) const EFAULT: isize = -14;
pub(crate) const ENOTBLK: isize = -15;
pub(crate) const EFBIG: isize = -27;
pub(crate) const EAGAIN: isize = -11;
pub(crate) const EINTR: isize = -4;
pub(crate) const E2BIG: isize = -7;
pub(crate) const ELOOP: isize = -40;
pub(crate) const EPERM: isize = -1;
pub(crate) const ENOENT: isize = -2;
pub(crate) const ENODEV: isize = -19;
pub(crate) const ENODATA: isize = -61;
pub(crate) const EINVAL: isize = -22;
pub(crate) const EBUSY: isize = -16;
pub(crate) const ERANGE: isize = -34;
pub(crate) const EMFILE: isize = -24;
pub(crate) const ENOTDIR: isize = -20;
pub(crate) const EISDIR: isize = -21;
pub(crate) const EACCES: isize = -13;
pub(crate) const EEXIST: isize = -17;
pub(crate) const EXDEV: isize = -18;
pub(crate) const EIO: isize = -5;
pub(crate) const EMLINK: isize = -31;
pub(crate) const ESPIPE: isize = -29;
pub(crate) const EPIPE: isize = -32;
pub(crate) const EROFS: isize = -30;
pub(crate) const ENOSPC: isize = -28;
pub(crate) const ENOSYS: isize = -38;
pub(crate) const ENAMETOOLONG: isize = -36;
pub(crate) const EDEADLK: isize = -35;
pub(crate) const ENXIO: isize = -6;
pub(crate) const EOPNOTSUPP: isize = -95;
pub(crate) const ENOTEMPTY: isize = -39;
pub(crate) const EOVERFLOW: isize = -75;

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

#[derive(Clone, Copy, Default)]
pub(crate) struct InodeTimes {
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

pub(crate) const ACCT_COMM: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Acct {
    ac_flag: u8,
    ac_uid: u16,
    ac_gid: u16,
    ac_tty: u16,
    ac_btime: u32,
    ac_utime: u16,
    ac_stime: u16,
    ac_etime: u16,
    ac_mem: u16,
    ac_io: u16,
    ac_rw: u16,
    ac_minflt: u16,
    ac_majflt: u16,
    ac_swaps: u16,
    ac_exitcode: u32,
    ac_comm: [u8; ACCT_COMM + 1],
    ac_pad: [u8; 10],
}

pub(crate) struct AcctState {
    inode: alloc::sync::Arc<ext4_fs::Inode>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct FcntlFlock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct FcntlOwnerEx {
    type_: i32,
    pid: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileLockKey {
    dev: u64,
    ino: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordLock {
    owner: RecordLockOwner,
    owner_pid: usize,
    lock_type: i16,
    start: i64,
    end: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RecordLockOwner {
    Process(usize),
    OpenFile(usize),
}

#[derive(Clone, Copy)]
pub(crate) struct WaitingRecordLock {
    key: FileLockKey,
    req_type: i16,
    start: i64,
    end: Option<i64>,
}

#[derive(Clone, Copy)]
pub(crate) struct FileLease {
    owner_pid: usize,
    lease_type: i16,
    pending_break_write: bool,
}

pub(crate) struct FifoDuplexFile {
    read_end: Arc<Pipe>,
    write_end: Arc<Pipe>,
}

impl FifoDuplexFile {
    fn new(read_end: Arc<Pipe>, write_end: Arc<Pipe>) -> Self {
        Self {
            read_end,
            write_end,
        }
    }

    fn write_end_closed(&self) -> bool {
        self.write_end.all_read_ends_closed()
    }

    fn poll_readable(&self) -> bool {
        self.read_end.poll_readable()
    }

    fn poll_writable(&self) -> bool {
        self.write_end.poll_writable()
    }

    fn available_write(&self) -> usize {
        self.write_end.available_write()
    }
}

impl File for FifoDuplexFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        self.read_end.read(buf)
    }

    fn write(&self, buf: UserBuffer) -> usize {
        self.write_end.write(buf)
    }

    fn poll_mask(&self) -> i16 {
        let read_mask = self.read_end.poll_mask();
        let write_mask = self.write_end.poll_mask();
        (read_mask & (crate::fs::POLLIN | crate::fs::POLLHUP))
            | (write_mask & (crate::fs::POLLOUT | crate::fs::POLLERR))
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let _ = self.read_end.register_poll_waiter(task);
        let _ = self.write_end.register_poll_waiter(task);
        true
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

pub(crate) struct FifoPipeState {
    read_end: Arc<Pipe>,
    write_end: Arc<Pipe>,
}

impl FifoPipeState {
    fn new() -> Self {
        let (read_end, write_end) = make_pipe();
        // Keep one registry reference to each end, but exclude it from
        // "open-end" accounting so EOF/EPIPE semantics still track real FDs.
        read_end.set_end_ref_bias(1, 1);
        Self {
            read_end,
            write_end,
        }
    }

    fn has_open_readers(&self) -> bool {
        self.read_end.open_read_end_count() > 0
    }

    fn has_open_writers(&self) -> bool {
        self.write_end.open_write_end_count() > 0
    }

    fn open_file(&self, accmode: usize) -> Option<Arc<dyn File + Send + Sync>> {
        match accmode {
            O_RDONLY => Some(self.read_end.clone()),
            O_WRONLY => Some(self.write_end.clone()),
            O_RDWR => Some(Arc::new(FifoDuplexFile::new(
                self.read_end.clone(),
                self.write_end.clone(),
            ))),
            _ => None,
        }
    }
}

lazy_static! {
    static ref INODE_TIMES: Mutex<BTreeMap<u64, InodeTimes>> = Mutex::new(BTreeMap::new());
    static ref INODE_XATTRS: Mutex<BTreeMap<u64, BTreeMap<String, Vec<u8>>>> =
        Mutex::new(BTreeMap::new());
    static ref INODE_FSFLAGS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());
    static ref FIFO_PIPE_STATES: Mutex<BTreeMap<u64, Arc<FifoPipeState>>> =
        Mutex::new(BTreeMap::new());
    static ref DEVICE_MOUNT_SOURCES: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());
    static ref TMPFS_REATTACH_SOURCES: Mutex<BTreeMap<String, String>> =
        Mutex::new(BTreeMap::new());
    static ref ACCT_STATE: Mutex<Option<AcctState>> = Mutex::new(None);
    static ref RECORD_LOCKS: Mutex<BTreeMap<FileLockKey, Vec<RecordLock>>> =
        Mutex::new(BTreeMap::new());
    static ref RECORD_LOCK_WAITERS: Mutex<BTreeMap<FileLockKey, VecDeque<Arc<TaskControlBlock>>>> =
        Mutex::new(BTreeMap::new());
    static ref RECORD_LOCK_BLOCKED: Mutex<BTreeMap<usize, WaitingRecordLock>> =
        Mutex::new(BTreeMap::new());
    static ref FILE_LEASES: Mutex<BTreeMap<FileLockKey, FileLease>> = Mutex::new(BTreeMap::new());
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

pub(crate) fn mount_flags_to_proc_opts(flags: usize) -> String {
    let mut opts = Vec::new();
    opts.push(if (flags & MS_RDONLY) != 0 { "ro" } else { "rw" });
    if (flags & MS_NOSUID) != 0 {
        opts.push("nosuid");
    }
    if (flags & MS_NODEV) != 0 {
        opts.push("nodev");
    }
    if (flags & MS_NOEXEC) != 0 {
        opts.push("noexec");
    }
    if (flags & MS_NOATIME) != 0 {
        opts.push("noatime");
    }
    if (flags & MS_NODIRATIME) != 0 {
        opts.push("nodiratime");
    }
    if (flags & MS_STRICTATIME) != 0 {
        opts.push("strictatime");
    }
    if (flags & MS_NOSYMFOLLOW) != 0 {
        opts.push("nosymfollow");
    }
    if (flags & (MS_NOATIME | MS_STRICTATIME)) == 0 {
        opts.push("relatime");
    }
    opts.join(",")
}

pub(crate) fn mount_flags_to_statfs(flags: usize) -> i64 {
    const ST_VALID: usize = MS_REMOUNT;
    let mut out = ST_VALID;
    out |= flags
        & (MS_RDONLY
            | MS_NOSUID
            | MS_NODEV
            | MS_NOEXEC
            | MS_NOATIME
            | MS_NODIRATIME
            | MS_STRICTATIME);
    if (flags & MS_NOSYMFOLLOW) != 0 {
        out |= ST_NOSYMFOLLOW;
    }
    out as i64
}

pub(crate) fn current_mount_namespace() -> MountNamespace {
    current_process().mount_namespace()
}

pub(crate) fn next_mount_stack_seq() -> usize {
    NEXT_MOUNT_STACK_SEQ.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn next_mount_event_id() -> usize {
    NEXT_MOUNT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn next_mount_peer_group_id() -> usize {
    NEXT_MOUNT_PEER_GROUP_ID.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn mount_lookup_for_abs(abs: &str) -> Option<MountRecord> {
    let state = current_mount_namespace();
    let state = state.lock();
    state.mount_record_for_path(abs)
}

pub(crate) fn mount_flags_for_abs(abs: &str) -> usize {
    let state = current_mount_namespace();
    let state = state.lock();
    state.mount_flags_for_path(abs)
}

pub(crate) fn translate_mount_abs(abs: &str) -> String {
    let state = current_mount_namespace();
    let state = state.lock();
    state.translate_mount_abs(abs)
}

pub(crate) fn with_mount_namespace_mut<R>(
    ns: &MountNamespace,
    f: impl FnOnce(&mut MountNamespaceState) -> R,
) -> R {
    let mut state = ns.lock();
    f(&mut state)
}

pub(crate) fn push_mount_record_in(
    ns: &MountNamespace,
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
    propagation: MountPropagation,
    peer_group_id: Option<usize>,
    master_group_id: Option<usize>,
    event_id: usize,
) {
    with_mount_namespace_mut(ns, |state| {
        state.push_record(MountRecord {
            target: String::from(target),
            source: String::from(source),
            source_display: String::from(source_display),
            fs_type: String::from(fs_type),
            flags,
            stack_seq: next_mount_stack_seq(),
            event_id,
            propagation,
            peer_group_id,
            master_group_id,
            access_seq: 0,
            expire_mark_seq: None,
        });
    });
}

pub(crate) fn mount_record_for_target(target: &str) -> Option<MountRecord> {
    let state = current_mount_namespace();
    let state = state.lock();
    state.mount_record_for_target(target)
}

pub(crate) fn mount_record_for_target_in(ns: &MountNamespace, target: &str) -> Option<MountRecord> {
    let state = ns.lock();
    state.mount_record_for_target(target)
}

pub(crate) fn sync_rofs_mount_flag_in(ns: &MountNamespace, target: &str, flags: usize) {
    with_mount_namespace_mut(ns, |state| {
        state.sync_rofs_mount_flag(target, flags & MS_RDONLY);
    });
}

pub(crate) fn sync_rofs_mount_flag(target: &str, flags: usize) {
    sync_rofs_mount_flag_in(&current_mount_namespace(), target, flags);
}

pub(crate) fn sync_mount_record_rofs_in(ns: &MountNamespace, target: &str) {
    if let Some(record) = mount_record_for_target_in(ns, target) {
        sync_rofs_mount_flag_in(ns, target, record.flags);
    } else {
        sync_rofs_mount_flag_in(ns, target, 0);
    }
}

pub(crate) fn push_mount_record(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
    propagation: MountPropagation,
    peer_group_id: Option<usize>,
    master_group_id: Option<usize>,
    event_id: usize,
) {
    push_mount_record_in(
        &current_mount_namespace(),
        target,
        source,
        source_display,
        fs_type,
        flags,
        propagation,
        peer_group_id,
        master_group_id,
        event_id,
    );
}

pub(crate) fn update_mount_record_flags_in(ns: &MountNamespace, target: &str, flags: usize) -> bool {
    with_mount_namespace_mut(ns, |state| state.update_top_mount_flags(target, flags))
}

pub(crate) fn update_mount_record_flags(target: &str, flags: usize) -> bool {
    update_mount_record_flags_in(&current_mount_namespace(), target, flags)
}

pub(crate) fn move_mount_record_target_in(ns: &MountNamespace, old_target: &str, new_target: &str) -> bool {
    with_mount_namespace_mut(ns, |state| state.move_top_mount_target(old_target, new_target))
}

pub(crate) fn move_mount_record_target(old_target: &str, new_target: &str) -> bool {
    move_mount_record_target_in(&current_mount_namespace(), old_target, new_target)
}

pub(crate) fn mount_flag_mask() -> usize {
    MS_RDONLY
        | MS_NOSUID
        | MS_NODEV
        | MS_NOEXEC
        | MS_NOSYMFOLLOW
        | MS_NOATIME
        | MS_NODIRATIME
        | MS_STRICTATIME
}

pub(crate) fn note_mount_access(abs: &str) {
    with_mount_namespace_mut(&current_mount_namespace(), |state| {
        state.note_mount_access(abs);
    });
}

pub(crate) fn current_cwd_path() -> String {
    let process = current_process();
    process.borrow_mut().cwd.clone()
}

pub(crate) fn logical_path_for_inode(inode: &Arc<ext4_fs::Inode>) -> Option<String> {
    inode_logical_path(inode)
}

pub(crate) fn proc_self_fd_path(fd: usize) -> String {
    alloc::format!("/proc/self/fd/{}", fd)
}

pub(crate) fn logical_path_for_open_fd(
    fd: usize,
    file: &Arc<dyn File + Send + Sync>,
    cwd_fallback: &str,
) -> String {
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return String::from(pdir.path());
    }
    crate::fs::proc_readlink(&proc_self_fd_path(fd)).unwrap_or_else(|| String::from(cwd_fallback))
}

pub(crate) fn mount_file_logical_path(file: &Arc<dyn File + Send + Sync>) -> Option<String> {
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Some(String::from(pdir.path()));
    }
    if let Some(path) = cgroup_logical_path_for_file(file) {
        return Some(path);
    }
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        return match pf.kind_tag() {
            crate::fs::PseudoKindTag::Null => Some(String::from("/dev/null")),
            crate::fs::PseudoKindTag::Zero => Some(String::from("/dev/zero")),
            crate::fs::PseudoKindTag::Urandom => Some(String::from("/dev/urandom")),
            crate::fs::PseudoKindTag::Static => None,
        };
    }
    if file.as_any().downcast_ref::<RtcFile>().is_some() {
        return Some(String::from("/dev/misc/rtc"));
    }
    if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
        return Some(String::from("/dev/shm"));
    }
    let os_inode = file.as_any().downcast_ref::<OSInode>()?;
    logical_path_for_inode(&os_inode.ext4_inode())
}

pub(crate) fn pseudo_abs_for_ext4_dirfd(base: &Arc<ext4_fs::Inode>, path: &str) -> Option<String> {
    let logical_base = logical_path_for_inode(base)?;
    let abs = normalize_path(&logical_base, path);
    open_pseudo(&abs).map(|_| abs)
}

pub(crate) fn mount_is_busy(target: &str, writable_only: bool) -> bool {
    let self_bind_root = mount_record_for_target(target)
        .map(|record| record.source == target)
        .unwrap_or(false);
    let current_ns_id = current_process().mount_namespace_id();
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes {
        let (cwd, root, fd_table, is_zombie) = match process.try_borrow_mut() {
            Some(inner) => {
                let (fd_table, _fd_flags) = inner.snapshot_fd_state();
                (
                    inner.cwd.clone(),
                    inner.root.clone(),
                    fd_table,
                    inner.is_zombie,
                )
            }
            None => continue,
        };
        if is_zombie {
            continue;
        }
        if process.mount_namespace_id() != current_ns_id {
            continue;
        }
        let cwd_busy = path_under_mount(&cwd, target) && !(self_bind_root && cwd == target);
        let root_busy = path_under_mount(&root, target) && !(self_bind_root && root == target);
        if cwd_busy || root_busy {
            return true;
        }
        for file in fd_table.into_iter().flatten() {
            if writable_only && !file.writable() {
                continue;
            }
            let Some(path) = mount_file_logical_path(&file) else {
                continue;
            };
            if path_under_mount(&path, target) {
                return true;
            }
        }
    }
    false
}

pub(crate) fn ensure_mount_source_root() -> Result<Arc<ext4_fs::Inode>, isize> {
    let _ext4_guard = ext4_lock();
    let root = crate::fs::root_inode_for_path("/");
    if let Some(dir) = root.find(".ltp_mounts") {
        if dir.is_dir() {
            return Ok(dir);
        }
        return Err(ENOTDIR);
    }
    match root.create_dir(".ltp_mounts") {
        Ok(dir) => {
            dir.set_uid_gid(0, 0);
            dir.set_mode(0o700);
            Ok(dir)
        }
        Err(e) => Err(ext4_err_to_errno(e)),
    }
}

pub(crate) fn source_for_device_mount(key: &str) -> Result<String, isize> {
    let fresh_instance = key.starts_with("tmpfs:");
    if fresh_instance {
        if let Some(path) = TMPFS_REATTACH_SOURCES.lock().remove(key) {
            return Ok(path);
        }
    } else if let Some(path) = DEVICE_MOUNT_SOURCES.lock().get(key).cloned() {
        return Ok(path);
    }
    let root = ensure_mount_source_root()?;
    loop {
        let id = TMPFILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = alloc::format!("mnt.{}", id);
        let _ext4_guard = ext4_lock();
        if root.find(&name).is_some() {
            continue;
        }
        match root.create_dir(&name) {
            Ok(dir) => {
                dir.set_uid_gid(0, 0);
                dir.set_mode(0o755);
                let path = alloc::format!("/.ltp_mounts/{}", name);
                if !fresh_instance {
                    DEVICE_MOUNT_SOURCES
                        .lock()
                        .insert(String::from(key), path.clone());
                }
                return Ok(path);
            }
            Err(e) => return Err(ext4_err_to_errno(e)),
        }
    }
}

pub(crate) fn target_dir_exists(abs: &str) -> Result<(), isize> {
    if let Some(node) = open_pseudo(abs) {
        if node.as_any().downcast_ref::<PseudoDir>().is_some() {
            return Ok(());
        }
        return Err(ENOTDIR);
    }
    let translated = translate_mount_abs(abs);
    let _ext4_guard = ext4_lock();
    let inode = find_path_in_roots(&translated).ok_or(ENOENT)?;
    if !inode.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(())
}

pub(crate) fn collect_live_mount_namespaces() -> Vec<MountNamespace> {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        if inner.is_zombie {
            continue;
        }
        let ns = Arc::clone(&inner.mnt_ns);
        let ns_id = inner.mnt_ns.lock().id();
        drop(inner);
        if seen.insert(ns_id) {
            out.push(ns);
        }
    }
    out
}

#[derive(Clone)]
pub(crate) struct MountPropagationDestination {
    ns: MountNamespace,
    target: String,
    propagation: MountPropagation,
}

pub(crate) fn inherited_mount_propagation(target: &str) -> (MountPropagation, Option<usize>, Option<usize>) {
    let Some(base) = mount_lookup_for_abs(target) else {
        return (MountPropagation::Private, None, None);
    };
    match base.propagation {
        MountPropagation::Private => (MountPropagation::Private, None, None),
        MountPropagation::Shared => (MountPropagation::Shared, base.peer_group_id, None),
        MountPropagation::Slave => (MountPropagation::Slave, None, base.master_group_id),
        MountPropagation::Unbindable => (MountPropagation::Unbindable, None, None),
    }
}

pub(crate) fn top_mounts_for_namespace(ns: &MountNamespace) -> Vec<MountRecord> {
    let state = ns.lock();
    state.top_mounts()
}

pub(crate) fn mount_target_suffix(base_target: &str, target: &str) -> String {
    if target == base_target {
        return String::new();
    }
    String::from(target[base_target.len()..].trim_start_matches('/'))
}

pub(crate) fn shared_group_destinations(base: &MountRecord, target: &str) -> Vec<MountPropagationDestination> {
    let Some(peer_group) = base.peer_group_id else {
        return Vec::new();
    };
    let suffix = mount_target_suffix(&base.target, target);
    let namespaces = collect_live_mount_namespaces();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for ns in namespaces {
        let ns_id = mount_namespace_id(&ns);
        for top in top_mounts_for_namespace(&ns) {
            let propagation = if top.propagation == MountPropagation::Shared
                && top.peer_group_id == Some(peer_group)
            {
                MountPropagation::Shared
            } else if top.propagation == MountPropagation::Slave
                && top.master_group_id == Some(peer_group)
            {
                MountPropagation::Slave
            } else {
                continue;
            };
            let dest_target = if suffix.is_empty() {
                top.target.clone()
            } else {
                normalize_path(&top.target, &suffix)
            };
            let key = (
                ns_id,
                dest_target.clone(),
                match propagation {
                    MountPropagation::Shared => 0u8,
                    MountPropagation::Slave => 1u8,
                    MountPropagation::Private => 2u8,
                    MountPropagation::Unbindable => 3u8,
                },
            );
            if !seen.insert(key) {
                continue;
            }
            out.push(MountPropagationDestination {
                ns: Arc::clone(&ns),
                target: dest_target,
                propagation,
            });
        }
    }

    out
}

pub(crate) fn push_mount_to_destination(
    dest: &MountPropagationDestination,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
    event_id: usize,
    shared_peer_group: Option<usize>,
    slave_master_group: Option<usize>,
) {
    match dest.propagation {
        MountPropagation::Shared => {
            push_mount_record_in(
                &dest.ns,
                &dest.target,
                source,
                source_display,
                fs_type,
                flags,
                MountPropagation::Shared,
                shared_peer_group,
                None,
                event_id,
            );
        }
        MountPropagation::Slave => {
            push_mount_record_in(
                &dest.ns,
                &dest.target,
                source,
                source_display,
                fs_type,
                flags,
                MountPropagation::Slave,
                None,
                slave_master_group,
                event_id,
            );
        }
        MountPropagation::Private | MountPropagation::Unbindable => {}
    }
    sync_mount_record_rofs_in(&dest.ns, &dest.target);
}

pub(crate) fn create_mount_record_with_propagation(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
) {
    let Some(base) = mount_lookup_for_abs(target) else {
        push_mount_record(
            target,
            source,
            source_display,
            fs_type,
            flags,
            MountPropagation::Private,
            None,
            None,
            next_mount_event_id(),
        );
        sync_mount_record_rofs(target);
        return;
    };

    if base.propagation == MountPropagation::Shared {
        let event_id = next_mount_event_id();
        let new_peer_group = next_mount_peer_group_id();
        let mut created_any = false;
        for dest in shared_group_destinations(&base, target) {
            created_any = true;
            match dest.propagation {
                MountPropagation::Shared => push_mount_to_destination(
                    &dest,
                    source,
                    source_display,
                    fs_type,
                    flags,
                    event_id,
                    Some(new_peer_group),
                    None,
                ),
                MountPropagation::Slave => push_mount_to_destination(
                    &dest,
                    source,
                    source_display,
                    fs_type,
                    flags,
                    event_id,
                    None,
                    Some(new_peer_group),
                ),
                MountPropagation::Private | MountPropagation::Unbindable => {}
            }
        }
        if !created_any {
            push_mount_record(
                target,
                source,
                source_display,
                fs_type,
                flags,
                MountPropagation::Shared,
                Some(new_peer_group),
                None,
                event_id,
            );
            sync_mount_record_rofs(target);
        }
        return;
    }

    let (propagation, peer_group_id, master_group_id) = inherited_mount_propagation(target);
    push_mount_record(
        target,
        source,
        source_display,
        fs_type,
        flags,
        propagation,
        peer_group_id,
        master_group_id,
        next_mount_event_id(),
    );
    sync_mount_record_rofs(target);
}

pub(crate) fn create_bind_mount_record_with_propagation(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
) {
    if let Some(source_mount) = mount_record_for_target(source_display) {
        if source_mount.propagation == MountPropagation::Shared {
            let source_peer_group = source_mount
                .peer_group_id
                .unwrap_or_else(next_mount_peer_group_id);
            let event_id = next_mount_event_id();

            if let Some(base) = mount_lookup_for_abs(target) {
                if base.propagation == MountPropagation::Shared {
                    let mut created_any = false;
                    for dest in shared_group_destinations(&base, target) {
                        created_any = true;
                        match dest.propagation {
                            MountPropagation::Shared => push_mount_to_destination(
                                &dest,
                                source,
                                source_display,
                                fs_type,
                                flags,
                                event_id,
                                Some(source_peer_group),
                                None,
                            ),
                            MountPropagation::Slave => push_mount_to_destination(
                                &dest,
                                source,
                                source_display,
                                fs_type,
                                flags,
                                event_id,
                                None,
                                Some(source_peer_group),
                            ),
                            MountPropagation::Private | MountPropagation::Unbindable => {}
                        }
                    }
                    if !created_any {
                        push_mount_record(
                            target,
                            source,
                            source_display,
                            fs_type,
                            flags,
                            MountPropagation::Shared,
                            Some(source_peer_group),
                            None,
                            event_id,
                        );
                        sync_mount_record_rofs(target);
                    }
                    return;
                }
            }

            push_mount_record(
                target,
                source,
                source_display,
                fs_type,
                flags,
                MountPropagation::Shared,
                Some(source_peer_group),
                None,
                event_id,
            );
            sync_mount_record_rofs(target);
            return;
        }
    }

    if let Some(base) = mount_lookup_for_abs(target) {
        if base.propagation == MountPropagation::Shared {
            let event_id = next_mount_event_id();
            let new_peer_group = next_mount_peer_group_id();
            let mut created_any = false;
            for dest in shared_group_destinations(&base, target) {
                created_any = true;
                match dest.propagation {
                    MountPropagation::Shared => push_mount_to_destination(
                        &dest,
                        source,
                        source_display,
                        fs_type,
                        flags,
                        event_id,
                        Some(new_peer_group),
                        None,
                    ),
                    MountPropagation::Slave => push_mount_to_destination(
                        &dest,
                        source,
                        source_display,
                        fs_type,
                        flags,
                        event_id,
                        None,
                        Some(new_peer_group),
                    ),
                    MountPropagation::Private | MountPropagation::Unbindable => {}
                }
            }
            if !created_any {
                push_mount_record(
                    target,
                    source,
                    source_display,
                    fs_type,
                    flags,
                    MountPropagation::Shared,
                    Some(new_peer_group),
                    None,
                    event_id,
                );
                sync_mount_record_rofs(target);
            }
            return;
        }
    }

    push_mount_record(
        target,
        source,
        source_display,
        fs_type,
        flags,
        MountPropagation::Private,
        None,
        None,
        next_mount_event_id(),
    );
    sync_mount_record_rofs(target);
}

pub(crate) fn remove_mount_records_by_event(event_id: usize) -> usize {
    let namespaces = collect_live_mount_namespaces();
    let mut removed = 0usize;
    for ns in namespaces {
        let mut affected_targets = BTreeSet::new();
        let removed_in_ns = with_mount_namespace_mut(&ns, |state| {
            let before = state.mounts().len();
            state.mounts_mut().retain(|record| {
                if record.event_id == event_id {
                    affected_targets.insert(record.target.clone());
                    return false;
                }
                true
            });
            before.saturating_sub(state.mounts().len())
        });
        if removed_in_ns == 0 {
            continue;
        }
        for target in affected_targets {
            sync_mount_record_rofs_in(&ns, &target);
        }
        removed = removed.saturating_add(removed_in_ns);
    }
    removed
}

pub(crate) fn apply_mount_propagation_change(target: &str, flags: usize) -> Result<(), isize> {
    let propagation = match (
        (flags & MS_SHARED) != 0,
        (flags & MS_PRIVATE) != 0,
        (flags & MS_SLAVE) != 0,
        (flags & MS_UNBINDABLE) != 0,
    ) {
        (true, false, false, false) => MountPropagation::Shared,
        (false, true, false, false) => MountPropagation::Private,
        (false, false, true, false) => MountPropagation::Slave,
        (false, false, false, true) => MountPropagation::Unbindable,
        _ => return Err(EINVAL),
    };
    let recursive = (flags & MS_REC) != 0;
    let mut changed = false;
    with_mount_namespace_mut(&current_mount_namespace(), |state| {
        for record in state.mounts_mut().iter_mut() {
            let applies = if recursive {
                path_under_mount(&record.target, target)
            } else {
                record.target == target
            };
            if !applies {
                continue;
            }
            match propagation {
                MountPropagation::Shared => {
                    let peer_group = record
                        .peer_group_id
                        .unwrap_or_else(next_mount_peer_group_id);
                    record.propagation = MountPropagation::Shared;
                    record.peer_group_id = Some(peer_group);
                    record.master_group_id = None;
                }
                MountPropagation::Private => {
                    record.propagation = MountPropagation::Private;
                    record.peer_group_id = None;
                    record.master_group_id = None;
                }
                MountPropagation::Slave => {
                    let master_group = record.peer_group_id.or(record.master_group_id);
                    record.propagation = MountPropagation::Slave;
                    record.peer_group_id = None;
                    record.master_group_id = master_group;
                }
                MountPropagation::Unbindable => {
                    record.propagation = MountPropagation::Unbindable;
                    record.peer_group_id = None;
                    record.master_group_id = None;
                }
            }
            changed = true;
        }
    });
    if !changed {
        target_dir_exists(target)?;
    }
    Ok(())
}

pub(crate) fn sync_mount_record_rofs(target: &str) {
    if let Some(record) = mount_record_for_target(target) {
        sync_rofs_mount_flag(target, record.flags);
    } else {
        sync_rofs_mount_flag(target, 0);
    }
}

pub(crate) fn should_update_inode_atime(path: &str, is_dir: bool, times: InodeTimes, now_sec: i64) -> bool {
    let flags = mount_flags_for_abs(path);
    if (flags & MS_NOATIME) != 0 {
        return false;
    }
    if is_dir && (flags & MS_NODIRATIME) != 0 {
        return false;
    }
    if (flags & MS_STRICTATIME) != 0 {
        return true;
    }
    times.atime_sec <= times.mtime_sec
        || times.atime_sec <= times.ctime_sec
        || now_sec.saturating_sub(times.atime_sec) >= 24 * 60 * 60
}

pub(crate) fn maybe_update_inode_atime(inode: &Arc<ext4_fs::Inode>, is_dir: bool) {
    let Some(logical_path) = inode_logical_path(inode) else {
        return;
    };
    let ino = inode.inode_num() as u64;
    let times = get_inode_times(ino);
    let (sec, nsec) = current_timespec();
    if !should_update_inode_atime(&logical_path, is_dir, times, sec) {
        return;
    }
    let mut next = times;
    next.atime_sec = sec;
    next.atime_nsec = nsec;
    set_inode_times(ino, next);
}

pub(crate) fn mount_note_path_access(abs: &str) {
    note_mount_access(abs);
}

pub(crate) fn syscall_mount_impl(
    special_ptr: usize,
    dir_ptr: usize,
    fstype_ptr: usize,
    flags: usize,
    data_ptr: usize,
) -> isize {
    if current_process().borrow_mut().euid != 0 {
        return EPERM;
    }
    let token = get_current_token();
    let dir = match read_user_cstring(token, dir_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if dir.is_empty() {
        return ENOENT;
    }
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let target = normalize_path(&cwd, &dir);

    let propagation_flags = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
    if (flags & propagation_flags) != 0 {
        return match apply_mount_propagation_change(&target, flags) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }

    let special = if special_ptr == 0 {
        None
    } else {
        match read_user_cstring(token, special_ptr) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };
    let fstype = if fstype_ptr == 0 {
        None
    } else {
        match read_user_cstring(token, fstype_ptr) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };
    let data = if data_ptr == 0 {
        None
    } else {
        match read_user_cstring(token, data_ptr) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };

    if let Some(fsname) = fstype.as_deref() {
        if fsname == "error" || fsname == "overlay" {
            return ENODEV;
        }
    }

    if let Err(e) = target_dir_exists(&target) {
        return e;
    }

    if (flags & MS_MOVE) != 0 {
        let Some(source) = special.as_deref() else {
            return EINVAL;
        };
        if source.is_empty() {
            return EINVAL;
        }
        let old_target = normalize_path(&cwd, source);
        let Some(old_record) = mount_record_for_target(&old_target) else {
            return EINVAL;
        };
        if mount_record_for_target(&target).is_some() {
            return EBUSY;
        }
        if !move_mount_record_target(&old_target, &target) {
            return EINVAL;
        }
        sync_rofs_mount_flag(&old_target, 0);
        sync_rofs_mount_flag(&target, old_record.flags);
        return 0;
    }

    if (flags & MS_REMOUNT) != 0 {
        let Some(record) = mount_record_for_target(&target) else {
            return EINVAL;
        };
        let new_flags = flags & mount_flag_mask();
        if (new_flags & MS_RDONLY) != 0 && mount_is_busy(&target, true) {
            return EBUSY;
        }
        let _ = update_mount_record_flags(&target, new_flags);
        sync_rofs_mount_flag(&target, new_flags);
        if record.source_display == "/dev/root"
            && (new_flags & MS_RDONLY) == 0
            && pseudo_block_is_read_only()
        {
            return EACCES;
        }
        return 0;
    }

    if (flags & MS_BIND) != 0 {
        let Some(source_display) = special.as_deref() else {
            return EINVAL;
        };
        if source_display.is_empty() {
            return EINVAL;
        }
        let source_abs = normalize_path(&cwd, source_display);
        if mount_lookup_for_abs(&source_abs)
            .map(|record| record.propagation == MountPropagation::Unbindable)
            .unwrap_or(false)
        {
            return EINVAL;
        }
        let source = translate_mount_abs(&source_abs);
        let _ext4_guard = ext4_lock();
        if find_path_in_roots(&source).is_none() {
            return ENOENT;
        }
        let fsname = fstype.as_deref().unwrap_or("none");
        let base_flags = mount_lookup_for_abs(&source_abs)
            .map(|m| m.flags)
            .unwrap_or(0);
        let bind_flags = (base_flags & mount_flag_mask()) | (flags & mount_flag_mask());
        create_bind_mount_record_with_propagation(
            &target,
            &source,
            &source_abs,
            fsname,
            bind_flags,
        );
        return 0;
    }

    let Some(source_display) = special.as_deref() else {
        return EINVAL;
    };
    let Some(fsname) = fstype.as_deref() else {
        return EINVAL;
    };
    if source_display.is_empty() || fsname.is_empty() {
        return EINVAL;
    }
    if fsname == "cgroup2" {
        let spec = CgroupMountSpec::unified();
        let rc = cgroup_mount(&target, &spec);
        if rc != 0 {
            return rc;
        }
        create_mount_record_with_propagation(
            &target,
            &target,
            "cgroup2",
            "cgroup2",
            flags & mount_flag_mask(),
        );
        return 0;
    }
    if fsname == "cgroup" {
        let options = data.as_deref().unwrap_or("");
        let spec = match CgroupMountSpec::parse_legacy_options(options) {
            Ok(spec) => spec,
            Err(e) => return e,
        };
        let rc = cgroup_mount(&target, &spec);
        if rc != 0 {
            return rc;
        }
        create_mount_record_with_propagation(
            &target,
            &target,
            spec.source_label(),
            "cgroup",
            flags & mount_flag_mask(),
        );
        return 0;
    }
    if source_display == "/dev/root" && (flags & MS_RDONLY) == 0 && pseudo_block_is_read_only() {
        return EACCES;
    }
    let special_abs = normalize_path(&cwd, source_display);
    {
        let _ext4_guard = ext4_lock();
        if let Some(inode) = find_path_in_roots(&special_abs) {
            if inode.is_chrdev() {
                return ENOTBLK;
            }
        }
    }
    let key = alloc::format!("{}:{}", fsname, source_display);
    let source = match source_for_device_mount(&key) {
        Ok(v) => v,
        Err(e) => return e,
    };
    create_mount_record_with_propagation(
        &target,
        &source,
        source_display,
        fsname,
        flags & mount_flag_mask(),
    );
    0
}

pub(crate) fn syscall_umount2_impl(special_ptr: usize, flags: usize) -> isize {
    let valid = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;
    if (flags & !valid) != 0 {
        return EINVAL;
    }
    if current_process().borrow_mut().euid != 0 {
        return EPERM;
    }
    if (flags & MNT_EXPIRE) != 0 && (flags & (MNT_FORCE | MNT_DETACH)) != 0 {
        return EINVAL;
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, special_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
    }
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let abs = normalize_path(&cwd, &path);

    if (flags & UMOUNT_NOFOLLOW) != 0 {
        let at = match resolve_at_path(AT_FDCWD, &path) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let (fsuid, fsgid) = current_fsuid_gid();
        let _ext4_guard = ext4_lock();
        if let Ok(inode) = resolve_at_inode(&at, fsuid, fsgid, false) {
            if inode.is_symlink() {
                return EINVAL;
            }
        }
    }

    let Some(record) = mount_record_for_target(&abs) else {
        let _ext4_guard = ext4_lock();
        return if find_path_in_roots(&abs).is_some() {
            EINVAL
        } else {
            ENOENT
        };
    };

    if (flags & MNT_EXPIRE) != 0 {
        let updated = with_mount_namespace_mut(&current_mount_namespace(), |state| {
            let Some(idx) = state.top_mount_index_for_target(&abs) else {
                return None;
            };
            let entry = &mut state.mounts_mut()[idx];
            if entry.expire_mark_seq != Some(entry.access_seq) {
                entry.expire_mark_seq = Some(entry.access_seq);
                return Some(EAGAIN);
            }
            Some(0)
        });
        match updated {
            Some(EAGAIN) => return EAGAIN,
            Some(0) => {}
            _ => return EINVAL,
        }
    }

    if (flags & MNT_DETACH) == 0 && mount_is_busy(&abs, false) {
        return EBUSY;
    }

    if (flags & MNT_DETACH) != 0 && record.fs_type == "tmpfs" {
        let key = alloc::format!("{}:{}", record.fs_type, record.source_display);
        TMPFS_REATTACH_SOURCES
            .lock()
            .insert(key, record.source.clone());
    }
    if record.fs_type == "cgroup2" || record.fs_type == "cgroup" {
        let _ = cgroup_umount(&abs);
    }
    let _ = remove_mount_records_by_event(record.event_id);
    0
}

pub(crate) fn proc_mounts_snapshot_for_namespace(ns: &MountNamespace) -> String {
    let mut out = String::from("/dev/root / ext4 rw,relatime 0 0\n");
    let mut mounts = {
        let state = ns.lock();
        state.mounts().to_vec()
    };
    mounts.sort_by(|a, b| a.target.cmp(&b.target));
    for mount in mounts {
        let mut opts = mount_flags_to_proc_opts(mount.flags);
        if mount.fs_type == "cgroup" && !mount.source_display.is_empty() {
            opts.push(',');
            opts.push_str(&mount.source_display);
        }
        out.push_str(&alloc::format!(
            "{} {} {} {} 0 0\n",
            mount.source_display,
            mount.target,
            mount.fs_type,
            opts
        ));
    }
    out
}

pub(crate) fn proc_mounts_snapshot() -> String {
    proc_mounts_snapshot_for_namespace(&current_mount_namespace())
}

pub(crate) fn proc_mounts_snapshot_for_process(process: &Arc<ProcessControlBlock>) -> String {
    proc_mounts_snapshot_for_namespace(&process.mount_namespace())
}

pub(crate) fn statfs_mount_flags_for_abs(abs: &str) -> i64 {
    mount_flags_to_statfs(mount_flags_for_abs(abs))
}

pub(crate) fn register_rofs_mount(abs: &str) {
    let ns = current_mount_namespace();
    with_mount_namespace_mut(&ns, |state| {
        let mounts = state.rofs_mounts_mut();
        if !mounts.iter().any(|m| m == abs) {
            mounts.push(String::from(abs));
        }
    });
    let _ = update_mount_record_flags(abs, mount_flags_for_abs(abs) | MS_RDONLY);
}

pub(crate) fn unregister_rofs_mount(abs: &str) {
    with_mount_namespace_mut(&current_mount_namespace(), |state| {
        state.rofs_mounts_mut().retain(|m| m != abs);
    });
    if let Some(mut record) = mount_lookup_for_abs(abs) {
        if record.target == abs {
            record.flags &= !MS_RDONLY;
            let _ = update_mount_record_flags(abs, record.flags);
        }
    }
}

pub(crate) fn path_is_rofs(abs: &str) -> bool {
    if (mount_flags_for_abs(abs) & MS_RDONLY) != 0 {
        return true;
    }
    let ns = current_mount_namespace();
    let state = ns.lock();
    state.rofs_mount_covers(abs)
}

pub(crate) fn path_is_nodev(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NODEV) != 0
}

pub(crate) fn path_is_noexec(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NOEXEC) != 0
}

pub(crate) fn path_is_nosymfollow(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NOSYMFOLLOW) != 0
}

pub(crate) fn inode_is_rofs_mount_root(inode: &Arc<ext4_fs::Inode>) -> bool {
    let mounts: Vec<String> = {
        let ns = current_mount_namespace();
        let state = ns.lock();
        state.rofs_mounts().to_vec()
    };
    for mount in mounts {
        let Some(mount_inode) = find_path_in_roots(&translate_mount_abs(&mount)) else {
            continue;
        };
        if mount_inode.device_id() == inode.device_id()
            && mount_inode.inode_num() == inode.inode_num()
        {
            return true;
        }
    }
    false
}

pub(crate) fn path_is_mount_point(abs: &str) -> bool {
    if mount_record_for_target(abs).is_some() {
        return true;
    }
    let ns = current_mount_namespace();
    let state = ns.lock();
    state.rofs_mount_contains(abs)
}

pub(crate) fn path_under_mount(abs: &str, mnt: &str) -> bool {
    if mnt == "/" {
        return true;
    }
    if abs == mnt {
        return true;
    }
    abs.starts_with(mnt) && abs.as_bytes().get(mnt.len()) == Some(&b'/')
}

pub(crate) fn final_non_empty_component(path: &str) -> Option<&str> {
    path.rsplit('/').find(|comp| !comp.is_empty())
}

pub(crate) fn rofs_mount_root_for_abs(abs: &str) -> Option<String> {
    if let Some(mount) = mount_lookup_for_abs(abs) {
        return Some(mount.target);
    }
    let ns = current_mount_namespace();
    let state = ns.lock();
    state.rofs_mount_root_for_path(abs)
}

pub(crate) fn hardlink_cross_mount(old_abs: &str, new_abs: &str) -> bool {
    match (
        rofs_mount_root_for_abs(old_abs),
        rofs_mount_root_for_abs(new_abs),
    ) {
        (None, None) => false,
        (Some(a), Some(b)) => a != b,
        _ => true,
    }
}

pub(crate) fn current_timespec() -> (i64, i64) {
    crate::syscall::time_sys::realtime_now_timespec()
}

pub(crate) fn normalize_path(cwd: &str, path: &str) -> String {
    let mut parts = Vec::new();
    let absolute = path.starts_with('/');
    if !absolute {
        for seg in cwd.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                parts.pop();
                continue;
            }
            parts.push(seg);
        }
    }
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

pub(crate) fn current_process_root() -> String {
    let process = current_process();
    let inner = process.borrow_mut();
    inner.root.clone()
}

pub(crate) fn apply_process_root(abs: &str) -> String {
    let root = current_process_root();
    if root == "/" {
        return String::from(abs);
    }
    if abs == "/" {
        return root;
    }
    let mut out = root;
    if !out.ends_with('/') {
        out.push('/');
    }
    out.push_str(abs.trim_start_matches('/'));
    normalize_path("/", &out)
}

pub(crate) fn normalize_relative_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    parts.join("/")
}

pub(crate) fn validate_path_components(path: &str) -> Result<(), isize> {
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
    }
    Ok(())
}

pub(crate) fn path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub(crate) fn busybox_exists() -> bool {
    let candidates = [
        "/musl/busybox",
        "/glibc/busybox",
        "/riscv/musl/busybox",
        "/riscv/glibc/busybox",
        "/extra/riscv/musl/busybox",
        "/extra/riscv/glibc/busybox",
        "/bin/busybox",
        "/busybox",
    ];
    for cand in candidates {
        if find_path_in_roots(cand).is_some() {
            return true;
        }
    }
    false
}

pub(crate) fn should_try_busybox_applet_path(path: &str, allow_relative: bool) -> bool {
    let base = path_basename(path);
    if base.is_empty() || base == "busybox" {
        return false;
    }
    if base.ends_with(".sh") {
        return false;
    }
    if !super::busybox_applet_allowed(base) {
        return false;
    }
    if !path.contains('/') {
        return allow_relative;
    }
    path.starts_with("/bin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/sbin/")
}

pub(crate) fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(pos) => {
            let (parent, name) = trimmed.split_at(pos);
            Some((parent, &name[1..]))
        }
        None => Some(("", trimmed)),
    }
}

pub(crate) fn get_fd_file(fd: usize) -> Option<alloc::sync::Arc<dyn File + Send + Sync>> {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return None;
    }
    inner.fd_table[fd].clone()
}

pub(crate) fn try_write_proc_pseudo_file(
    file: &Arc<dyn File + Send + Sync>,
    data: &[u8],
    offset: usize,
    advance_offset: bool,
) -> Option<isize> {
    let proc_file = file.as_any().downcast_ref::<ProcPseudoFile>()?;
    if data.is_empty() {
        return Some(0);
    }
    let written = match proc_file.pwrite_bytes(offset, data) {
        Ok(written) => written,
        Err(err) => return Some(err),
    };
    if advance_offset {
        proc_file.set_offset(offset.saturating_add(written));
    }
    Some(written as isize)
}

pub(crate) fn fd_is_writable_proc_pseudo(fd: usize) -> bool {
    let Some(file) = get_fd_file(fd) else {
        return false;
    };
    file.as_any()
        .downcast_ref::<ProcPseudoFile>()
        .map(|proc_file| proc_file.writable())
        .unwrap_or(false)
}

pub(crate) fn write_proc_pseudo_fd(fd: usize, data: &[u8], offset: Option<usize>) -> Option<isize> {
    let file = get_fd_file(fd)?;
    let effective_offset = if let Some(offset) = offset {
        offset
    } else {
        file.as_any().downcast_ref::<ProcPseudoFile>()?.offset()
    };
    try_write_proc_pseudo_file(&file, data, effective_offset, offset.is_none())
}

pub(crate) fn file_is_seekable_for_preadwrite(file: &alloc::sync::Arc<dyn File + Send + Sync>) -> bool {
    if file.as_any().downcast_ref::<OSInode>().is_some() {
        return true;
    }
    if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
        return true;
    }
    if file.as_any().downcast_ref::<ProcPseudoFile>().is_some() {
        return true;
    }
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        return pf.len().is_some();
    }
    false
}

pub(crate) fn fd_has_o_path(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_PATH as u32) != 0
}

pub(crate) fn fd_has_nonblock(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_NONBLOCK as u32) != 0
}

pub(crate) fn fd_has_append(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_APPEND as u32) != 0
}

pub(crate) fn fd_has_odirect(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_DIRECT as u32) != 0
}

pub(crate) fn fd_has_noatime(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_NOATIME as u32) != 0
}

pub(crate) fn validate_direct_io_request(
    fd: usize,
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    user_ptr: usize,
    len: usize,
    offset: usize,
) -> Result<(), isize> {
    if !fd_has_odirect(fd) || len == 0 {
        return Ok(());
    }
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return Ok(());
    };
    let inode = os_inode.ext4_inode();
    let is_regular = {
        let _ext4_guard = ext4_lock();
        inode.is_file()
    };
    if !is_regular {
        return Ok(());
    }
    let mask = DIRECT_IO_ALIGN - 1;
    if (user_ptr & mask) != 0 || (len & mask) != 0 || (offset & mask) != 0 {
        return Err(EINVAL);
    }
    Ok(())
}

pub(crate) fn read_optional_offset(ptr: usize) -> Result<Option<usize>, isize> {
    if ptr == 0 {
        return Ok(None);
    }
    let Some(raw) = try_read_user_value(get_current_token(), ptr as *const i64) else {
        return Err(EFAULT);
    };
    if raw < 0 {
        return Err(EINVAL);
    }
    Ok(Some(raw as usize))
}

pub(crate) fn write_optional_offset(ptr: usize, value: usize) -> Result<(), isize> {
    if ptr == 0 {
        return Ok(());
    }
    let next = value as i64;
    if try_write_user_value(get_current_token(), ptr as *mut i64, &next).is_err() {
        return Err(EFAULT);
    }
    Ok(())
}

pub(crate) fn file_is_pipe(file: &alloc::sync::Arc<dyn File + Send + Sync>) -> bool {
    file.as_any().downcast_ref::<Pipe>().is_some()
}

pub(crate) fn pipe_read_to_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    out: &mut [u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        return pipe.read_to_slice(out, nonblock);
    }
    Err(EINVAL)
}

pub(crate) fn pipe_write_from_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    data: &[u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        return pipe.write_from_slice(data, nonblock);
    }
    Err(EINVAL)
}

pub(crate) fn socketpair_write_from_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    data: &[u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        return sock.write_from_slice(data, nonblock);
    }
    Err(EINVAL)
}

pub(crate) fn open_fd_flags(flags: usize, o_path: bool) -> u32 {
    let mut fd_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    if (flags & O_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK as u32;
    }
    if (flags & O_APPEND) != 0 {
        fd_flags |= O_APPEND as u32;
    }
    if (flags & O_DIRECT) != 0 {
        fd_flags |= O_DIRECT as u32;
    }
    if (flags & O_ASYNC) != 0 {
        fd_flags |= O_ASYNC as u32;
    }
    if (flags & O_NOATIME) != 0 {
        fd_flags |= O_NOATIME as u32;
    }
    if o_path {
        fd_flags |= O_PATH as u32;
    }
    fd_flags
}

pub(crate) fn install_open_file_fd(
    file: alloc::sync::Arc<dyn File + Send + Sync>,
    flags: usize,
    o_path: bool,
) -> Result<usize, isize> {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return Err(EMFILE);
    };
    inner.fd_table[fd] = Some(file);
    inner.fd_flags[fd] = open_fd_flags(flags, o_path);
    Ok(fd)
}

pub(crate) fn fifo_pipe_state_for_inode(inode_num: u64) -> Arc<FifoPipeState> {
    let mut states = FIFO_PIPE_STATES.lock();
    if let Some(state) = states.get(&inode_num) {
        // Drop idle state so reopened FIFOs start with an empty buffer.
        if !state.has_open_readers() && !state.has_open_writers() {
            states.remove(&inode_num);
        } else {
            return state.clone();
        }
    }
    let state = Arc::new(FifoPipeState::new());
    states.insert(inode_num, state.clone());
    state
}

pub(crate) fn get_fd_inode(fd: usize) -> Option<alloc::sync::Arc<ext4_fs::Inode>> {
    let file = get_fd_file(fd)?;
    file.as_any()
        .downcast_ref::<OSInode>()
        .map(|o| o.ext4_inode())
}

pub(crate) enum RelativeAtPathBase {
    LogicalAbs(String),
    Ext4Dir {
        base: alloc::sync::Arc<ext4_fs::Inode>,
        logical_base: Option<String>,
    },
}

pub(crate) enum AtPath {
    /// An ext4 lookup rooted at `/`.
    Ext4Abs(String),
    /// An ext4 lookup rooted at an open directory fd.
    Ext4Rel {
        base: alloc::sync::Arc<ext4_fs::Inode>,
        rel: String,
    },
    /// A pseudo filesystem lookup expressed as an absolute path.
    PseudoAbs(String),
}

pub(crate) fn classify_current_abs_path(abs: &str) -> ClassifiedAbsPath {
    let state = current_mount_namespace();
    let state = state.lock();
    state.classify_logical_abs_path(abs)
}

pub(crate) fn classify_abs_at_path(abs: String) -> AtPath {
    match classify_current_abs_path(&abs) {
        ClassifiedAbsPath::Ext4(translated) => AtPath::Ext4Abs(translated),
        ClassifiedAbsPath::Pseudo(path) => AtPath::PseudoAbs(path),
    }
}

pub(crate) fn resolve_relative_at_path_base(dirfd: isize) -> Result<RelativeAtPathBase, isize> {
    if dirfd == AT_FDCWD {
        return Ok(RelativeAtPathBase::LogicalAbs(current_cwd_path()));
    }
    if dirfd < 0 {
        return Err(EBADF);
    }
    let Some(file) = get_fd_file(dirfd as usize) else {
        return Err(EBADF);
    };
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Ok(RelativeAtPathBase::LogicalAbs(String::from(pdir.path())));
    }
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return Err(ENOTDIR);
    };
    let base = os_inode.ext4_inode();
    if !base.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(RelativeAtPathBase::Ext4Dir {
        logical_base: logical_path_for_inode(&base),
        base,
    })
}

pub(crate) fn resolve_relative_at_path_from_logical_base(base_path: &str, path: &str) -> Result<AtPath, isize> {
    let logical_abs = normalize_path(base_path, path);
    let abs = resolve_proc_magic_intermediate_abs_path(&logical_abs)?;
    let classified_abs = classify_current_abs_path(&abs);
    if matches!(classified_abs, ClassifiedAbsPath::Pseudo(_)) {
        return Ok(AtPath::PseudoAbs(abs));
    }
    if abs != logical_abs {
        let ClassifiedAbsPath::Ext4(translated) = classified_abs else {
            unreachable!();
        };
        return Ok(AtPath::Ext4Abs(translated));
    }
    let rel = if let Some(mount) = mount_lookup_for_abs(&abs) {
        let suffix = if abs == mount.target {
            String::new()
        } else {
            String::from(abs[mount.target.len()..].trim_start_matches('/'))
        };
        let _ext4_guard = ext4_lock();
        let Some(base) = find_path_in_roots(&mount.source) else {
            return Err(ENOENT);
        };
        return Ok(AtPath::Ext4Rel { base, rel: suffix });
    } else {
        normalize_relative_path(path)
    };
    let _ext4_guard = ext4_lock();
    let Some(base) = find_path_in_roots(&translate_mount_abs(base_path)) else {
        return Err(ENOENT);
    };
    Ok(AtPath::Ext4Rel { base, rel })
}

pub(crate) fn resolve_relative_at_path_from_ext4_base(
    base: alloc::sync::Arc<ext4_fs::Inode>,
    logical_base: Option<String>,
    path: &str,
) -> Result<AtPath, isize> {
    if let Some(logical_base) = logical_base {
        let logical_abs = normalize_path(&logical_base, path);
        let abs = resolve_proc_magic_intermediate_abs_path(&logical_abs)?;
        if abs != logical_abs {
            return Ok(classify_abs_at_path(abs));
        }
    }
    if let Some(abs) = pseudo_abs_for_ext4_dirfd(&base, path) {
        return Ok(AtPath::PseudoAbs(abs));
    }
    let rel = normalize_relative_path(path);
    Ok(AtPath::Ext4Rel { base, rel })
}

pub(crate) fn resolve_at_path(dirfd: isize, path: &str) -> Result<AtPath, isize> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path.len() > PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    validate_path_components(path)?;

    // Absolute path: ignore dirfd.
    if path.starts_with('/') {
        let jail_abs = normalize_path("/", path);
        let abs = resolve_proc_magic_intermediate_abs_path(&apply_process_root(&jail_abs))?;
        return Ok(classify_abs_at_path(abs));
    }

    match resolve_relative_at_path_base(dirfd)? {
        RelativeAtPathBase::LogicalAbs(base_path) => {
            resolve_relative_at_path_from_logical_base(&base_path, path)
        }
        RelativeAtPathBase::Ext4Dir { base, logical_base } => {
            resolve_relative_at_path_from_ext4_base(base, logical_base, path)
        }
    }
}

pub(crate) fn resolve_ext4_abs_path(
    path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
    depth: &mut usize,
    seen_symlinks: &mut Vec<u32>,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let abs = crate::fs::normalize_proc_magic_path(path).into_owned();

    // Prefer the secondary disk for OSComp test roots when available.
    if (abs == "/musl"
        || abs.starts_with("/musl/")
        || abs == "/glibc"
        || abs.starts_with("/glibc/"))
    {
        if let Some(secondary) = secondary_root_inode() {
            let mut sec_depth = 0usize;
            let mut sec_seen = Vec::new();
            match resolve_ext4_path(
                secondary,
                &abs,
                uid,
                gid,
                follow_final,
                &mut sec_depth,
                &mut sec_seen,
            ) {
                Ok(v) => return Ok(v),
                Err(ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
    }

    let primary = crate::fs::root_inode_for_path(&abs);
    match resolve_ext4_path(primary, &abs, uid, gid, follow_final, depth, seen_symlinks) {
        Ok(v) => Ok(v),
        Err(ENOENT) => {
            let Some(secondary) = secondary_root_inode() else {
                return Err(ENOENT);
            };
            let mut sec_depth = 0usize;
            let mut sec_seen = Vec::new();
            resolve_ext4_path(
                secondary,
                &abs,
                uid,
                gid,
                follow_final,
                &mut sec_depth,
                &mut sec_seen,
            )
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn parse_proc_fd_for_current_process(path: &str) -> Option<usize> {
    let trimmed = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };
    let parse_fd = |s: &str| -> Option<usize> {
        if s.is_empty() || s.contains('/') || !s.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse::<usize>().ok()
    };

    if let Some(rest) = trimmed.strip_prefix("/proc/self/fd/") {
        return parse_fd(rest);
    }

    let pid = current_process().getpid();
    let prefix = alloc::format!("/proc/{}/fd/", pid);
    let rest = trimmed.strip_prefix(prefix.as_str())?;
    parse_fd(rest)
}

pub(crate) fn empty_path_fd_for_at_op(dirfd: isize, flags: usize) -> Result<usize, isize> {
    if dirfd < 0 {
        return Err(ENOENT);
    }
    let fd = dirfd as usize;
    if (flags & AT_EMPTY_PATH) != 0 {
        return Ok(fd);
    }
    // Some libc fallbacks retry fd-based metadata ops via empty-path *at calls.
    // Preserve O_PATH EBADF semantics instead of leaking ENOENT.
    if fd_has_o_path(fd) {
        return Err(EBADF);
    }
    Err(ENOENT)
}

pub(crate) fn maybe_dispatch_proc_fd_at(
    abs: &str,
    flags: usize,
    op: impl FnOnce(usize) -> isize,
) -> Option<isize> {
    if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
        return None;
    }
    let fd = parse_proc_fd_for_current_process(abs)?;
    Some(op(fd))
}

pub(crate) fn proc_path_for_at<'a>(raw_abs: Option<&'a str>, at: &'a AtPath) -> Option<&'a str> {
    if let Some(abs) = raw_abs {
        if crate::fs::is_proc_pseudo_path(abs) {
            return Some(abs);
        }
    }
    match at {
        AtPath::PseudoAbs(abs) if crate::fs::is_proc_pseudo_path(abs) => Some(abs.as_str()),
        _ => None,
    }
}

pub(crate) fn reopen_proc_link_file(
    src_file: alloc::sync::Arc<dyn File + Send + Sync>,
    flags: usize,
    readable: bool,
    writable: bool,
    o_path: bool,
) -> Result<usize, isize> {
    let file: alloc::sync::Arc<dyn File + Send + Sync> =
        if let Some(shm) = src_file.as_any().downcast_ref::<PseudoShmFile>() {
            alloc::sync::Arc::new(shm.reopen_with_mode(readable, writable))
        } else {
            src_file
        };
    let fd = install_open_file_fd(file, flags, o_path)?;
    if !o_path && (flags & O_TRUNC) != 0 {
        let tr = syscall_ftruncate(fd, 0);
        if tr != 0 {
            let process = current_files_process();
            let mut inner = process.borrow_mut();
            let _ = inner.clear_fd(fd);
            return Err(tr);
        }
    }
    Ok(fd)
}

pub(crate) fn pseudo_path_exists_result(abs: &str) -> isize {
    if let Some(name) = shm_object_name(abs) {
        return if shm_get(name).is_some() { 0 } else { ENOENT };
    }
    if open_pseudo(abs).is_some() {
        0
    } else {
        ENOENT
    }
}

pub(crate) fn add_root_dir_entries(
    root: &alloc::sync::Arc<ext4_fs::Inode>,
    entries: &mut BTreeMap<String, (u64, u8)>,
) {
    for (name, ino, ftype) in root.dir_entries() {
        if name == "." || name == ".." {
            continue;
        }
        entries
            .entry(name)
            .or_insert((ino as u64, dt_type_from_ext4(ftype)));
    }
}

/// Build a merged root directory listing from the primary and secondary disks.
///
/// Caller should hold `ext4_lock`.
pub(crate) fn union_root_dir_entries() -> Vec<PseudoDirent> {
    let mut merged: BTreeMap<String, (u64, u8)> = BTreeMap::new();
    let primary = crate::fs::root_inode_for_path("/");
    add_root_dir_entries(&primary, &mut merged);
    if let Some(secondary) = secondary_root_inode() {
        add_root_dir_entries(&secondary, &mut merged);
    }

    let mut entries = Vec::with_capacity(merged.len() + 2);
    entries.push(PseudoDirent {
        name: alloc::string::String::from("."),
        ino: 1,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: alloc::string::String::from(".."),
        ino: 1,
        dtype: 4,
    });
    for (name, (ino, dtype)) in merged {
        entries.push(PseudoDirent { name, ino, dtype });
    }
    entries
}

pub(crate) fn read_user_cstring(token: usize, ptr: usize) -> Result<String, isize> {
    if ptr == 0 {
        return Err(EFAULT);
    }
    let mut out = String::new();
    for i in 0..=PATH_MAX {
        let ch = match try_read_user_value(token, (ptr + i) as *const u8) {
            Some(v) => v,
            None => return Err(EFAULT),
        };
        if ch == 0 {
            return Ok(out);
        }
        out.push(ch as char);
        if out.len() > PATH_MAX {
            return Err(ENAMETOOLONG);
        }
    }
    Err(ENAMETOOLONG)
}

pub(crate) fn validate_xattr_name(name: &str) -> Result<(), isize> {
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(ERANGE);
    }
    let Some((ns, key)) = name.split_once('.') else {
        return Err(EINVAL);
    };
    if ns.is_empty() || key.is_empty() {
        return Err(EINVAL);
    }
    Ok(())
}

pub(crate) fn read_user_xattr_name(token: usize, ptr: usize) -> Result<String, isize> {
    let name = read_user_cstring(token, ptr)?;
    validate_xattr_name(&name)?;
    Ok(name)
}

pub(crate) fn read_user_xattr_value(token: usize, value: usize, size: usize) -> Result<Vec<u8>, isize> {
    if size > XATTR_SIZE_MAX {
        return Err(E2BIG);
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    if value == 0 {
        return Err(EFAULT);
    }
    let mut out = vec![0u8; size];
    if try_copy_from_user(token, value as *const u8, out.as_mut_slice()).is_err() {
        return Err(EFAULT);
    }
    Ok(out)
}

pub(crate) fn xattr_is_user_namespace(name: &str) -> bool {
    name.starts_with("user.")
}

pub(crate) fn inode_supports_user_xattr(inode: &Arc<ext4_fs::Inode>) -> bool {
    inode.is_file() || inode.is_dir()
}

pub(crate) fn resolve_xattr_path_inode(
    path_ptr: usize,
    follow_final: bool,
) -> Result<Arc<ext4_fs::Inode>, isize> {
    let token = get_current_token();
    let path = read_user_cstring(token, path_ptr)?;
    let at = resolve_at_path(AT_FDCWD, &path)?;
    if matches!(at, AtPath::PseudoAbs(_)) {
        return Err(ENOENT);
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    resolve_at_inode(&at, fsuid, fsgid, follow_final)
}

pub(crate) fn resolve_xattr_fd_inode(fd: usize) -> Result<Option<Arc<ext4_fs::Inode>>, isize> {
    if fd_has_o_path(fd) {
        return Err(EBADF);
    }
    let Some(file) = get_fd_file(fd) else {
        return Err(EBADF);
    };
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        // Valid fd but no inode-backed xattr storage (e.g. socket/fifo wrappers).
        return Ok(None);
    };
    Ok(Some(os_inode.ext4_inode()))
}

pub(crate) fn do_setxattr(inode: &Arc<ext4_fs::Inode>, name: &str, value: &[u8], flags: usize) -> isize {
    let valid_flags = XATTR_CREATE | XATTR_REPLACE;
    if (flags & !valid_flags) != 0 || (flags & valid_flags) == valid_flags {
        return EINVAL;
    }
    if xattr_is_user_namespace(name) && !inode_supports_user_xattr(inode) {
        return EPERM;
    }
    if inode_is_immutable_or_append(inode) {
        return EPERM;
    }

    let ino = inode.inode_num() as u64;
    let mut all = INODE_XATTRS.lock();
    let attrs = all.entry(ino).or_default();
    let exists = attrs.contains_key(name);
    if (flags & XATTR_CREATE) != 0 && exists {
        return EEXIST;
    }
    if (flags & XATTR_REPLACE) != 0 && !exists {
        return ENODATA;
    }
    attrs.insert(String::from(name), value.to_vec());
    drop(all);
    touch_inode_mtime_ctime_now(inode);
    0
}

pub(crate) fn do_getxattr(
    inode: &Arc<ext4_fs::Inode>,
    name: &str,
    value_ptr: usize,
    size: usize,
    token: usize,
) -> isize {
    if xattr_is_user_namespace(name) && !inode_supports_user_xattr(inode) {
        return ENODATA;
    }
    let value = {
        let all = INODE_XATTRS.lock();
        let Some(attrs) = all.get(&(inode.inode_num() as u64)) else {
            return ENODATA;
        };
        let Some(val) = attrs.get(name) else {
            return ENODATA;
        };
        val.clone()
    };

    if size == 0 {
        return value.len() as isize;
    }
    if size < value.len() {
        return ERANGE;
    }
    if value_ptr == 0 {
        return EFAULT;
    }
    if try_copy_to_user(token, value_ptr as *mut u8, value.as_slice()).is_err() {
        return EFAULT;
    }
    value.len() as isize
}

pub(crate) fn do_listxattr(inode: &Arc<ext4_fs::Inode>, list_ptr: usize, size: usize, token: usize) -> isize {
    let data = {
        let mut out = Vec::new();
        let all = INODE_XATTRS.lock();
        if let Some(attrs) = all.get(&(inode.inode_num() as u64)) {
            for name in attrs.keys() {
                out.extend_from_slice(name.as_bytes());
                out.push(0);
            }
        }
        out
    };

    if size == 0 {
        return data.len() as isize;
    }
    if size < data.len() {
        return ERANGE;
    }
    if !data.is_empty() && list_ptr == 0 {
        return EFAULT;
    }
    if !data.is_empty() && try_copy_to_user(token, list_ptr as *mut u8, data.as_slice()).is_err() {
        return EFAULT;
    }
    data.len() as isize
}

pub(crate) fn do_removexattr(inode: &Arc<ext4_fs::Inode>, name: &str) -> isize {
    if xattr_is_user_namespace(name) && !inode_supports_user_xattr(inode) {
        return ENODATA;
    }
    if inode_is_immutable_or_append(inode) {
        return EPERM;
    }

    let ino = inode.inode_num() as u64;
    let mut all = INODE_XATTRS.lock();
    let Some(attrs) = all.get_mut(&ino) else {
        return ENODATA;
    };
    if attrs.remove(name).is_none() {
        return ENODATA;
    }
    let became_empty = attrs.is_empty();
    if became_empty {
        all.remove(&ino);
    }
    drop(all);
    touch_inode_mtime_ctime_now(inode);
    0
}

pub(crate) fn resolve_ext4_path(
    start: alloc::sync::Arc<ext4_fs::Inode>,
    path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
    depth: &mut usize,
    seen_symlinks: &mut Vec<u32>,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let mut stack: Vec<alloc::sync::Arc<ext4_fs::Inode>> = alloc::vec![start];
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut idx = 0usize;
    while idx < components.len() {
        let seg = components[idx];
        if seg == "." {
            idx += 1;
            continue;
        }
        if seg == ".." {
            let cur = stack.last().unwrap().clone();
            if !cur.is_dir() {
                return Err(ENOTDIR);
            }
            if !inode_mode_allows_uid_gid(&cur, 1, uid, gid) {
                return Err(EACCES);
            }
            if stack.len() > 1 {
                stack.pop();
            } else if let Some(parent) = cur.find("..") {
                // When walking from a non-root start inode (e.g. resolving a
                // relative symlink target), ".." must be able to climb above
                // that start directory.
                if parent.inode_num() != cur.inode_num() {
                    stack[0] = parent;
                }
            }
            idx += 1;
            continue;
        }
        let cur = stack.last().unwrap().clone();
        if !cur.is_dir() {
            return Err(ENOTDIR);
        }
        if !inode_mode_allows_uid_gid(&cur, 1, uid, gid) {
            return Err(EACCES);
        }
        let Some(next) = cur.find(seg) else {
            return Err(ENOENT);
        };
        let is_last = idx + 1 == components.len();
        if next.is_symlink() && (follow_final || !is_last) {
            if *depth >= MAX_SYMLINKS {
                return Err(ELOOP);
            }
            let inode_num = next.inode_num();
            if seen_symlinks.iter().any(|&n| n == inode_num) {
                return Err(ELOOP);
            }
            seen_symlinks.push(inode_num);
            *depth += 1;
            let target_bytes = next.read_all();
            let target = String::from_utf8_lossy(&target_bytes).into_owned();
            if target.is_empty() {
                return Err(ENOENT);
            }
            let remaining = if is_last {
                String::new()
            } else {
                components[idx + 1..].join("/")
            };
            let mut new_path = target;
            if !remaining.is_empty() {
                if !new_path.ends_with('/') {
                    new_path.push('/');
                }
                new_path.push_str(&remaining);
            }
            if new_path.starts_with('/') {
                let translated = translate_mount_abs(&new_path);
                return resolve_ext4_abs_path(
                    &translated,
                    uid,
                    gid,
                    follow_final,
                    depth,
                    seen_symlinks,
                );
            }
            return resolve_ext4_path(cur, &new_path, uid, gid, follow_final, depth, seen_symlinks);
        }
        stack.push(next);
        idx += 1;
    }
    Ok(stack.last().unwrap().clone())
}

pub(crate) fn resolve_at_inode(
    at: &AtPath,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let mut depth = 0usize;
    let mut seen_symlinks = Vec::new();
    match at {
        AtPath::Ext4Abs(abs) => {
            resolve_ext4_abs_path(abs, uid, gid, follow_final, &mut depth, &mut seen_symlinks)
        }
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Ok(alloc::sync::Arc::clone(base))
            } else {
                resolve_ext4_path(
                    alloc::sync::Arc::clone(base),
                    rel,
                    uid,
                    gid,
                    follow_final,
                    &mut depth,
                    &mut seen_symlinks,
                )
            }
        }
        AtPath::PseudoAbs(_) => Err(ENOENT),
    }
}

pub(crate) fn resolve_exec_inode(path: &str) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    if let Some(abs) = resolve_abs_path(AT_FDCWD, path)? {
        if path_is_noexec(&abs) {
            return Err(EACCES);
        }
    }
    let at = resolve_at_path(AT_FDCWD, path)?;
    if let AtPath::PseudoAbs(_) = &at {
        return Err(ENOENT);
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = resolve_at_inode(&at, fsuid, fsgid, true)?;
    if !inode.is_file() {
        return Err(EACCES);
    }
    let exec_mask = if path.ends_with(".sh") { 4 } else { 1 };
    if !inode_mode_allows_uid_gid(&inode, exec_mask, fsuid, fsgid) {
        return Err(EACCES);
    }
    Ok(inode)
}

pub(crate) fn resolve_exec_inode_at(
    dirfd: isize,
    path: &str,
    flags: usize,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let valid_flags = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;
    if (flags & !valid_flags) != 0 {
        return Err(EINVAL);
    }
    if !path.is_empty() {
        if let Some(abs) = resolve_abs_path(dirfd, path)? {
            if path_is_noexec(&abs) {
                return Err(EACCES);
            }
        }
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let inode = if path.is_empty() {
        if (flags & AT_EMPTY_PATH) == 0 {
            return Err(ENOENT);
        }
        if dirfd < 0 {
            return Err(EBADF);
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return Err(EBADF);
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return Err(ENOTDIR);
        };
        os_inode.ext4_inode()
    } else {
        let at = resolve_at_path(dirfd, path)?;
        if let AtPath::PseudoAbs(_) = &at {
            return Err(ENOENT);
        }
        // Resolve the lookup path before taking `ext4_lock()`: the AT_FDCWD
        // relative-path branch may need to reopen the base inode under the
        // same lock, and holding it here would self-deadlock.
        let _ext4_guard = ext4_lock();
        let inode = resolve_at_inode(&at, fsuid, fsgid, follow_final)?;
        if !follow_final && inode.is_symlink() {
            return Err(ELOOP);
        }
        inode
    };
    let _ext4_guard = ext4_lock();
    if !inode.is_file() {
        return Err(EACCES);
    }
    let exec_mask = if path.ends_with(".sh") { 4 } else { 1 };
    if !inode_mode_allows_uid_gid(&inode, exec_mask, fsuid, fsgid) {
        return Err(EACCES);
    }
    Ok(inode)
}

pub(crate) fn resolve_read_inode(path: &str) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let at = resolve_at_path(AT_FDCWD, path)?;
    if let AtPath::PseudoAbs(_) = &at {
        return Err(ENOENT);
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = resolve_at_inode(&at, fsuid, fsgid, true)?;
    if !inode.is_file() {
        return Err(EACCES);
    }
    if !inode_mode_allows_uid_gid(&inode, 4, fsuid, fsgid) {
        return Err(EACCES);
    }
    Ok(inode)
}

/// Linux `acct(2)` (syscall 89 on riscv64).
///
/// We only validate the path and permissions for LTP. Accounting is not enabled.

pub(crate) fn resolve_parent_and_name(
    at: &AtPath,
    uid: u32,
    gid: u32,
) -> Result<(alloc::sync::Arc<ext4_fs::Inode>, alloc::string::String), isize> {
    let mut depth = 0usize;
    let mut seen_symlinks = Vec::new();
    match at {
        AtPath::Ext4Abs(abs) => {
            if abs == "/" {
                return Err(EINVAL);
            }
            let Some((parent_path, name)) = split_parent_and_name(abs) else {
                return Err(EINVAL);
            };
            if name.is_empty() {
                return Err(EINVAL);
            }
            let parent_abs = if parent_path.is_empty() {
                alloc::string::String::from("/")
            } else {
                let mut p = alloc::string::String::from("/");
                p.push_str(parent_path);
                p
            };
            let parent =
                resolve_ext4_abs_path(&parent_abs, uid, gid, true, &mut depth, &mut seen_symlinks)?;
            Ok((parent, alloc::string::String::from(name)))
        }
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                return Err(EINVAL);
            }
            let Some((parent_path, name)) = split_parent_and_name(rel) else {
                return Err(EINVAL);
            };
            if name.is_empty() {
                return Err(EINVAL);
            }
            let parent = if parent_path.is_empty() {
                alloc::sync::Arc::clone(base)
            } else {
                resolve_ext4_path(
                    alloc::sync::Arc::clone(base),
                    parent_path,
                    uid,
                    gid,
                    true,
                    &mut depth,
                    &mut seen_symlinks,
                )?
            };
            Ok((parent, alloc::string::String::from(name)))
        }
        AtPath::PseudoAbs(_) => Err(EROFS),
    }
}

pub(crate) fn resolve_abs_path(dirfd: isize, path: &str) -> Result<Option<String>, isize> {
    if path.is_empty() {
        return Ok(None);
    }
    let abs = if path.starts_with('/') {
        normalize_path("/", path)
    } else {
        let cwd = current_cwd_path();
        if dirfd == AT_FDCWD {
            normalize_path(&cwd, path)
        } else if dirfd >= 0 {
            // If dirfd refers to a pseudo directory, resolve relative to it.
            // For ext4 dirfds, prefer procfs fd symlink target to preserve mount context.
            let Some(file) = get_fd_file(dirfd as usize) else {
                return Ok(None);
            };
            let base = logical_path_for_open_fd(dirfd as usize, &file, &cwd);
            normalize_path(&base, path)
        } else {
            return Ok(None);
        }
    };
    resolve_proc_magic_intermediate_abs_path(&abs).map(Some)
}

pub(crate) fn rofs_for_path(dirfd: isize, path: &str) -> bool {
    resolve_abs_path(dirfd, path)
        .ok()
        .flatten()
        .map(|abs| path_is_rofs(&abs))
        .unwrap_or(false)
}

pub(crate) fn ext4_err_to_errno(e: ext4_fs::Ext4Error) -> isize {
    match e {
        ext4_fs::Ext4Error::NotADirectory => ENOTDIR,
        ext4_fs::Ext4Error::NotAFile => EISDIR,
        ext4_fs::Ext4Error::AlreadyExists => EEXIST,
        ext4_fs::Ext4Error::NotFound => ENOENT,
        ext4_fs::Ext4Error::NoSpace => ENOSPC,
        ext4_fs::Ext4Error::NameTooLong => ENAMETOOLONG,
        ext4_fs::Ext4Error::Unsupported => EOPNOTSUPP,
        ext4_fs::Ext4Error::InvalidInput => EINVAL,
    }
}

pub(crate) fn current_real_uid_gid() -> (u32, u32) {
    crate::syscall::misc::current_real_uid_gid()
}

pub(crate) fn current_effective_uid_gid() -> (u32, u32) {
    crate::syscall::misc::current_effective_uid_gid()
}

pub(crate) fn current_fsuid_gid() -> (u32, u32) {
    crate::syscall::misc::current_fsuid_gid()
}

pub(crate) fn current_in_group(gid: u32) -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    gid == inner.fsgid || inner.supplementary_gids.iter().any(|g| *g == gid)
}

pub(crate) fn parse_chown_id(id: usize) -> Option<u32> {
    if id == usize::MAX || id == u32::MAX as usize {
        None
    } else {
        Some(id as u32)
    }
}

pub(crate) fn maybe_clear_suid_sgid_after_chown(inode: &ext4_fs::Inode, touched_owner: bool) {
    if !touched_owner || !inode.is_file() {
        return;
    }
    let mut mode = inode.mode();
    mode &= !0o4000; // Clear setuid on regular files after chown/chgrp.
    if (mode & 0o0010) != 0 {
        // Linux preserves setgid on non-group-executable regular files.
        mode &= !0o2000;
    }
    inode.set_mode(mode);
}

pub(crate) fn apply_chown_to_inode(inode: &ext4_fs::Inode, uid: usize, gid: usize) -> isize {
    let uid_req = parse_chown_id(uid);
    let gid_req = parse_chown_id(gid);
    let (euid, _egid) = current_effective_uid_gid();

    if euid != 0 {
        if inode.uid() != euid {
            return EPERM;
        }
        if let Some(new_uid) = uid_req {
            // Unprivileged callers cannot change file owner.
            if new_uid != inode.uid() {
                return EPERM;
            }
        }
        if let Some(new_gid) = gid_req {
            // Unprivileged owner may only chgrp into one of its groups.
            if new_gid != inode.gid() && !current_in_group(new_gid) {
                return EPERM;
            }
        }
    }

    let new_uid = uid_req.unwrap_or_else(|| inode.uid());
    let new_gid = gid_req.unwrap_or_else(|| inode.gid());
    inode.set_uid_gid(new_uid, new_gid);
    maybe_clear_suid_sgid_after_chown(inode, uid_req.is_some() || gid_req.is_some());
    0
}

pub(crate) fn inode_mode_allows_uid_gid(inode: &ext4_fs::Inode, mask: usize, uid: u32, gid: u32) -> bool {
    if mask == 0 {
        return true;
    }
    let mode = inode.mode() as usize;

    if uid == 0 {
        // Root bypasses read/write checks, but still needs execute bits for files.
        if (mask & 1) != 0 && !inode.is_dir() && (mode & 0o111) == 0 {
            return false;
        }
        return true;
    }

    let perm = if uid == inode.uid() {
        (mode >> 6) & 0o7
    } else if gid == inode.gid() {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    if (mask & 4) != 0 && (perm & 0o4) == 0 {
        return false;
    }
    if (mask & 2) != 0 && (perm & 0o2) == 0 {
        return false;
    }
    if (mask & 1) != 0 && (perm & 0o1) == 0 {
        return false;
    }
    true
}

pub(crate) fn inode_mode_allows(inode: &ext4_fs::Inode, mask: usize) -> bool {
    let (uid, gid) = current_fsuid_gid();
    inode_mode_allows_uid_gid(inode, mask, uid, gid)
}

pub(crate) fn apply_umask(mode: usize) -> u16 {
    let umask = crate::syscall::misc::current_umask() as u16;
    let perm = (mode as u16) & 0o777;
    let special = (mode as u16) & 0o7000;
    special | (perm & !umask)
}

pub(crate) fn parent_forces_gid_inherit(parent: &ext4_fs::Inode) -> bool {
    parent.is_dir() && (parent.mode() & 0o2000) != 0
}

pub(crate) fn gid_for_created_inode(parent: Option<&ext4_fs::Inode>, fallback_gid: u32) -> u32 {
    match parent {
        Some(dir) if parent_forces_gid_inherit(dir) => dir.gid(),
        _ => fallback_gid,
    }
}

pub(crate) fn mode_for_created_file(mut mode: u16, gid: u32) -> u16 {
    // Linux clears S_ISGID on new regular files when caller is unprivileged
    // and outside the target group.
    if (mode & 0o2000) != 0 {
        let (euid, _) = current_effective_uid_gid();
        if euid != 0 && !current_in_group(gid) {
            mode &= !0o2000;
        }
    }
    mode
}

pub(crate) fn inode_rdev_for_mode(inode: &ext4_fs::Inode, mode: u16) -> u64 {
    match mode & S_IFMT {
        S_IFCHR | S_IFBLK => inode.special_rdev(),
        _ => 0,
    }
}

pub(crate) fn linux_dev_major(dev: u64) -> u32 {
    ((((dev >> 8) & 0x0fff) | ((dev >> 32) & 0xffff_f000)) & 0xffff_ffff) as u32
}

pub(crate) fn linux_dev_minor(dev: u64) -> u32 {
    (((dev & 0x00ff) | ((dev >> 12) & 0x0fff_ff00)) & 0xffff_ffff) as u32
}

pub(crate) fn inode_visible_size(inode: &ext4_fs::Inode) -> usize {
    let mut size = inode.size() as usize;
    let target_ino = inode.inode_num();
    let target_dev = inode.device_id();

    let processes: Vec<alloc::sync::Arc<ProcessControlBlock>> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    for process in processes {
        if let Some(inner) = process.try_borrow_mut() {
            for file in inner.fd_table.iter().filter_map(|f| f.as_ref()) {
                let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
                    continue;
                };
                let fd_inode = os_inode.ext4_inode();
                if fd_inode.inode_num() == target_ino && fd_inode.device_id() == target_dev {
                    size = core::cmp::max(size, os_inode.pending_write_end());
                }
            }
        }
    }
    size
}

pub(crate) fn file_lock_key(file: &Arc<dyn File + Send + Sync>) -> Option<FileLockKey> {
    let os_inode = file.as_any().downcast_ref::<OSInode>()?;
    let inode = os_inode.ext4_inode();
    Some(file_lock_key_from_inode(&inode))
}

pub(crate) fn file_lock_key_from_inode(inode: &Arc<ext4_fs::Inode>) -> FileLockKey {
    FileLockKey {
        dev: inode.device_id() as u64,
        ino: inode.inode_num() as u64,
    }
}

pub(crate) fn ofd_lock_owner_id(file: &Arc<dyn File + Send + Sync>) -> usize {
    Arc::as_ptr(file) as *const () as usize
}

pub(crate) fn range_end_i128(end: Option<i64>) -> i128 {
    end.map(|v| v as i128).unwrap_or(i128::MAX)
}

pub(crate) fn ranges_overlap(a_start: i64, a_end: Option<i64>, b_start: i64, b_end: Option<i64>) -> bool {
    let a0 = a_start as i128;
    let b0 = b_start as i128;
    let a1 = range_end_i128(a_end);
    let b1 = range_end_i128(b_end);
    a0 <= b1 && b0 <= a1
}

pub(crate) fn max_range_end(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (None, _) | (_, None) => None,
        (Some(x), Some(y)) => Some(core::cmp::max(x, y)),
    }
}

pub(crate) fn ranges_touch_or_overlap_sorted(left_end: Option<i64>, right_start: i64) -> bool {
    match left_end {
        None => true,
        Some(end) => right_start <= end.saturating_add(1),
    }
}

pub(crate) fn lock_conflicts(
    req_type: i16,
    req_start: i64,
    req_end: Option<i64>,
    owner: RecordLockOwner,
    existing: &RecordLock,
) -> bool {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;

    if existing.owner == owner || existing.lock_type == F_UNLCK {
        return false;
    }
    if !ranges_overlap(req_start, req_end, existing.start, existing.end) {
        return false;
    }
    match req_type {
        F_RDLCK => existing.lock_type == F_WRLCK,
        F_WRLCK => existing.lock_type == F_RDLCK || existing.lock_type == F_WRLCK,
        _ => false,
    }
}

pub(crate) fn first_conflicting_lock(
    locks: &[RecordLock],
    req_type: i16,
    req_start: i64,
    req_end: Option<i64>,
    owner: RecordLockOwner,
) -> Option<RecordLock> {
    locks
        .iter()
        .filter(|lock| lock_conflicts(req_type, req_start, req_end, owner, lock))
        .min_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| range_end_i128(a.end).cmp(&range_end_i128(b.end)))
                .then_with(|| a.owner.cmp(&b.owner))
                .then_with(|| a.owner_pid.cmp(&b.owner_pid))
        })
        .copied()
}

pub(crate) fn normalize_record_locks(locks: &mut Vec<RecordLock>) {
    const F_UNLCK: i16 = 2;

    locks.retain(|lock| lock.lock_type != F_UNLCK);
    locks.sort_by(|a, b| {
        a.owner
            .cmp(&b.owner)
            .then_with(|| a.start.cmp(&b.start))
            .then_with(|| range_end_i128(a.end).cmp(&range_end_i128(b.end)))
            .then_with(|| a.lock_type.cmp(&b.lock_type))
            .then_with(|| a.owner_pid.cmp(&b.owner_pid))
    });

    let mut merged: Vec<RecordLock> = Vec::with_capacity(locks.len());
    for lock in locks.drain(..) {
        if let Some(last) = merged.last_mut() {
            if last.owner == lock.owner
                && last.lock_type == lock.lock_type
                && ranges_touch_or_overlap_sorted(last.end, lock.start)
            {
                last.end = max_range_end(last.end, lock.end);
                continue;
            }
        }
        merged.push(lock);
    }
    *locks = merged;
}

pub(crate) fn apply_record_lock_for_owner(
    locks: &mut Vec<RecordLock>,
    owner: RecordLockOwner,
    owner_pid: usize,
    req_type: i16,
    req_start: i64,
    req_end: Option<i64>,
) -> bool {
    const F_UNLCK: i16 = 2;

    let mut updated: Vec<RecordLock> = Vec::with_capacity(locks.len().saturating_add(2));
    for lock in locks.iter().copied() {
        if lock.owner != owner || !ranges_overlap(req_start, req_end, lock.start, lock.end) {
            updated.push(lock);
            continue;
        }

        if lock.start < req_start {
            updated.push(RecordLock {
                owner: lock.owner,
                owner_pid: lock.owner_pid,
                lock_type: lock.lock_type,
                start: lock.start,
                end: Some(req_start - 1),
            });
        }

        if let Some(req_end_value) = req_end {
            if req_end_value < i64::MAX {
                let right_start = req_end_value + 1;
                let has_right = match lock.end {
                    None => true,
                    Some(lock_end) => lock_end >= right_start,
                };
                if has_right {
                    updated.push(RecordLock {
                        owner: lock.owner,
                        owner_pid: lock.owner_pid,
                        lock_type: lock.lock_type,
                        start: right_start,
                        end: lock.end,
                    });
                }
            }
        }
    }

    if req_type != F_UNLCK {
        updated.push(RecordLock {
            owner,
            owner_pid,
            lock_type: req_type,
            start: req_start,
            end: req_end,
        });
    }

    normalize_record_locks(&mut updated);
    let changed = *locks != updated;
    *locks = updated;
    changed
}

pub(crate) fn collect_conflict_process_owners(
    locks: &[RecordLock],
    req_type: i16,
    req_start: i64,
    req_end: Option<i64>,
    owner_pid: usize,
) -> Vec<usize> {
    let owner = RecordLockOwner::Process(owner_pid);
    let mut owners = BTreeSet::new();
    for lock in locks {
        if lock_conflicts(req_type, req_start, req_end, owner, lock) {
            if let RecordLockOwner::Process(pid) = lock.owner {
                owners.insert(pid);
            }
        }
    }
    owners.into_iter().collect()
}

pub(crate) fn set_record_lock_waiting(pid: usize, waiting: WaitingRecordLock) {
    RECORD_LOCK_BLOCKED.lock().insert(pid, waiting);
}

pub(crate) fn clear_record_lock_waiting(pid: usize) {
    RECORD_LOCK_BLOCKED.lock().remove(&pid);
}

pub(crate) fn detect_record_lock_deadlock(waiter_pid: usize, conflict_owners: &[usize]) -> bool {
    let table = RECORD_LOCKS.lock();
    let blocked = RECORD_LOCK_BLOCKED.lock();
    let mut stack: Vec<usize> = conflict_owners.to_vec();
    let mut visited = BTreeSet::new();

    while let Some(pid) = stack.pop() {
        if pid == waiter_pid {
            return true;
        }
        if !visited.insert(pid) {
            continue;
        }
        let Some(waiting) = blocked.get(&pid) else {
            continue;
        };
        let Some(locks) = table.get(&waiting.key) else {
            continue;
        };
        for owner in collect_conflict_process_owners(
            locks,
            waiting.req_type,
            waiting.start,
            waiting.end,
            pid,
        ) {
            if !visited.contains(&owner) {
                stack.push(owner);
            }
        }
    }
    false
}

pub(crate) fn lock_range_from_flock(
    file: &Arc<dyn File + Send + Sync>,
    flock: &FcntlFlock,
) -> Result<(i64, Option<i64>), isize> {
    const SEEK_SET: i16 = 0;
    const SEEK_CUR: i16 = 1;
    const SEEK_END: i16 = 2;

    let base = match flock.l_whence {
        SEEK_SET => 0i64,
        SEEK_CUR => {
            let os_inode = file.as_any().downcast_ref::<OSInode>().ok_or(EINVAL)?;
            i64::try_from(os_inode.offset()).map_err(|_| EOVERFLOW)?
        }
        SEEK_END => {
            let os_inode = file.as_any().downcast_ref::<OSInode>().ok_or(EINVAL)?;
            let inode = os_inode.ext4_inode();
            i64::try_from(inode_visible_size(&inode)).map_err(|_| EOVERFLOW)?
        }
        _ => return Err(EINVAL),
    };

    let mut start = base.checked_add(flock.l_start).ok_or(EOVERFLOW)?;
    if start < 0 {
        return Err(EINVAL);
    }

    if flock.l_len > 0 {
        let end = start.checked_add(flock.l_len - 1).ok_or(EOVERFLOW)?;
        return Ok((start, Some(end)));
    }
    if flock.l_len == 0 {
        return Ok((start, None));
    }

    let neg_start = start.checked_add(flock.l_len).ok_or(EOVERFLOW)?;
    let end = start.checked_sub(1).ok_or(EOVERFLOW)?;
    if neg_start < 0 {
        return Err(EINVAL);
    }
    start = neg_start;
    Ok((start, Some(end)))
}

pub(crate) fn enqueue_record_lock_waiter(key: FileLockKey, task: &Arc<TaskControlBlock>) {
    let mut waiters = RECORD_LOCK_WAITERS.lock();
    let queue = waiters.entry(key).or_insert_with(VecDeque::new);
    if queue.iter().any(|waiter| Arc::ptr_eq(waiter, task)) {
        return;
    }
    queue.push_back(Arc::clone(task));
}

pub(crate) fn remove_record_lock_waiter(key: FileLockKey, task: &Arc<TaskControlBlock>) {
    let mut waiters = RECORD_LOCK_WAITERS.lock();
    let Some(queue) = waiters.get_mut(&key) else {
        return;
    };
    queue.retain(|waiter| !Arc::ptr_eq(waiter, task));
    if queue.is_empty() {
        waiters.remove(&key);
    }
}


pub(crate) fn take_record_lock_waiters(key: FileLockKey) -> Vec<Arc<TaskControlBlock>> {
    RECORD_LOCK_WAITERS
        .lock()
        .remove(&key)
        .map(|queue| queue.into_iter().collect())
        .unwrap_or_default()
}

pub(crate) fn wake_record_lock_waiters(key: FileLockKey) {
    for waiter in take_record_lock_waiters(key) {
        wakeup_task(waiter);
    }
}

pub(crate) fn remove_process_record_locks_for_key(owner_pid: usize, key: FileLockKey) {
    let changed = {
        let mut table = RECORD_LOCKS.lock();
        let Some(locks) = table.get_mut(&key) else {
            return;
        };
        let before = locks.len();
        locks.retain(
            |lock| !matches!(lock.owner, RecordLockOwner::Process(pid) if pid == owner_pid),
        );
        let changed = locks.len() != before;
        if locks.is_empty() {
            table.remove(&key);
        }
        changed
    };
    if changed {
        wake_record_lock_waiters(key);
    }
}


pub(crate) fn remove_owner_file_lease_for_key(owner_pid: usize, key: FileLockKey) {
    let mut table = FILE_LEASES.lock();
    if table
        .get(&key)
        .is_some_and(|lease| lease.owner_pid == owner_pid)
    {
        table.remove(&key);
    }
}


pub(crate) fn count_open_fds_for_key(key: FileLockKey) -> usize {
    let processes: Vec<alloc::sync::Arc<ProcessControlBlock>> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    let mut count = 0usize;
    for process in processes {
        if let Some(inner) = process.try_borrow_mut() {
            for file in inner.fd_table.iter().filter_map(|f| f.as_ref()) {
                if file_lock_key(file).is_some_and(|k| k == key) {
                    count += 1;
                }
            }
        }
    }
    count
}

pub(crate) fn set_file_lease(
    key: FileLockKey,
    owner_pid: usize,
    lease_type: i16,
    file: &Arc<dyn File + Send + Sync>,
) -> isize {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;

    match lease_type {
        F_RDLCK | F_WRLCK | F_UNLCK => {}
        _ => return EINVAL,
    }
    if lease_type == F_UNLCK {
        let mut table = FILE_LEASES.lock();
        match table.get(&key) {
            Some(lease) if lease.owner_pid != owner_pid => EAGAIN,
            Some(_) => {
                table.remove(&key);
                0
            }
            None => 0,
        }
    } else {
        let mut table = FILE_LEASES.lock();
        if let Some(lease) = table.get(&key) {
            if lease.owner_pid != owner_pid {
                return EAGAIN;
            }
            if lease.pending_break_write {
                return EAGAIN;
            }
        }

        if lease_type == F_RDLCK {
            // Linux read lease requires read-only open description.
            if !file.readable() || file.writable() {
                return EAGAIN;
            }
        } else if lease_type == F_WRLCK {
            // Linux write lease requires no other open descriptors.
            if count_open_fds_for_key(key) > 1 {
                return EBUSY;
            }
        }

        table.insert(
            key,
            FileLease {
                owner_pid,
                lease_type,
                pending_break_write: false,
            },
        );
        0
    }
}

pub(crate) fn get_file_lease_type(key: FileLockKey, owner_pid: usize) -> i16 {
    FILE_LEASES
        .lock()
        .get(&key)
        .filter(|lease| lease.owner_pid == owner_pid)
        .map(|lease| lease.lease_type)
        .unwrap_or(2)
}

pub(crate) fn maybe_signal_lease_break(
    key: FileLockKey,
    open_write: bool,
    truncate_op: bool,
    breaker_pid: usize,
) {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;

    let holder_pid = {
        let mut table = FILE_LEASES.lock();
        let Some(lease) = table.get_mut(&key) else {
            return;
        };
        if lease.owner_pid == breaker_pid {
            return;
        }
        let conflict = match lease.lease_type {
            F_WRLCK => true,
            F_RDLCK => open_write || truncate_op,
            _ => false,
        };
        if conflict {
            if lease.lease_type == F_RDLCK || open_write || truncate_op {
                lease.pending_break_write = true;
            }
            Some(lease.owner_pid)
        } else {
            None
        }
    };
    if let Some(pid) = holder_pid {
        queue_process_signal(pid, SIGIO_NUM);
    }
}

pub(crate) fn has_pending_unmasked_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    // Keep lock waits aligned with Linux semantics: ignored/default SIGCHLD
    // from helper children should not abort F_SETLKW with EINTR.
    has_unmasked_pending(inner.pending_signals, inner.signal_mask, true)
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
            return Err(EACCES);
        }
    }

    if !o_path && inode.is_dir() && ((flags & O_ACCMODE) != O_RDONLY || (flags & O_CREAT) != 0) {
        return Err(EISDIR);
    }

    if (flags & O_NOATIME) != 0 {
        let (euid, _egid) = current_effective_uid_gid();
        if euid != 0 && euid != inode.uid() {
            return Err(EPERM);
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
        return Err(EACCES);
    }

    if (flags & O_DIRECTORY) != 0 && !inode.is_dir() {
        return Err(ENOTDIR);
    }

    let text_write_intent = writable || (flags & O_TRUNC) != 0;
    let exec_inode_guard = if !o_path && inode.is_file() && text_write_intent {
        let guard = lock_executing_inodes();
        let exec_busy =
            is_inode_currently_executed_locked(&guard, inode.device_id(), inode.inode_num());
        if exec_busy {
            return Err(ETXTBSY);
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
            return Err(ENXIO);
        }
        let Some(file) = state.open_file(accmode) else {
            drop(ext4_guard);
            return Err(EINVAL);
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
        return Err(EROFS);
    }

    let at = resolve_at_path(AT_FDCWD, abs)?;
    if let AtPath::PseudoAbs(_) = &at {
        let Some(file) = open_pseudo(abs) else {
            return Err(ENOENT);
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
        return EINVAL;
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
        return EROFS;
    }
    if euid != 0 && inode.uid() != euid {
        return EPERM;
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
/// If the path exists but is not a symlink, Linux returns `EINVAL`.

/// Linux `symlinkat(2)` (syscall 36 on riscv64).

/// Linux `linkat(2)` (syscall 37 on riscv64).

pub(crate) fn inode_eq(a: &Arc<ext4_fs::Inode>, b: &Arc<ext4_fs::Inode>) -> bool {
    a.device_id() == b.device_id() && a.inode_num() == b.inode_num()
}

pub(crate) fn path_is_descendant_of(dir: Arc<ext4_fs::Inode>, ancestor: &Arc<ext4_fs::Inode>) -> bool {
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
        Err(ext4_fs::Ext4Error::Unsupported) => ENOTEMPTY,
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
        return EROFS;
    }

    if rofs_for_path(olddirfd, old_s) || rofs_for_path(newdirfd, new_s) {
        return EROFS;
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
        return ENOENT;
    }
    if old_name == "." || old_name == ".." || new_name == "." || new_name == ".." {
        return EINVAL;
    }
    if old_name == new_name && inode_eq(&old_parent, &new_parent) {
        return 0;
    }
    if !old_parent.is_dir() || !new_parent.is_dir() {
        return ENOTDIR;
    }
    if !inode_mode_allows_uid_gid(&old_parent, 3, fsuid, fsgid)
        || !inode_mode_allows_uid_gid(&new_parent, 3, fsuid, fsgid)
    {
        return EACCES;
    }

    let Some(source) = old_parent.find(&old_name) else {
        return ENOENT;
    };
    if !sticky_rename_allowed(&old_parent, &source, fsuid) {
        return EPERM;
    }

    let target = new_parent.find(&new_name);
    if let Some(target_inode) = target.as_ref() {
        if !sticky_rename_allowed(&new_parent, target_inode, fsuid) {
            return EPERM;
        }
        if inode_eq(&source, target_inode) {
            return 0;
        }
        if source.is_dir() && !target_inode.is_dir() {
            return ENOTDIR;
        }
        if !source.is_dir() && target_inode.is_dir() {
            return EISDIR;
        }
        if source.is_dir() && target_inode.is_dir() && !target_inode.ls().is_empty() {
            return ENOTEMPTY;
        }
        if no_replace {
            return EEXIST;
        }
    }

    if source.is_dir() && path_is_descendant_of(new_parent.clone(), &source) {
        return EINVAL;
    }

    let same_parent = inode_eq(&old_parent, &new_parent);
    if !same_parent {
        if source.is_dir() {
            if new_parent.link_count() >= u16::MAX as u32 {
                return EMLINK;
            }
            return EXDEV;
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

pub(crate) fn do_renameat_exchange(olddirfd: isize, old_s: &str, newdirfd: isize, new_s: &str) -> isize {
    let old_at = match resolve_at_path(olddirfd, old_s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_at = match resolve_at_path(newdirfd, new_s) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if matches!(old_at, AtPath::PseudoAbs(_)) || matches!(new_at, AtPath::PseudoAbs(_)) {
        return EROFS;
    }
    if rofs_for_path(olddirfd, old_s) || rofs_for_path(newdirfd, new_s) {
        return EROFS;
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
        return ENOENT;
    }
    if old_name == "." || old_name == ".." || new_name == "." || new_name == ".." {
        return EINVAL;
    }
    if !inode_mode_allows_uid_gid(&old_parent, 3, fsuid, fsgid)
        || !inode_mode_allows_uid_gid(&new_parent, 3, fsuid, fsgid)
    {
        return EACCES;
    }

    let Some(old_inode) = old_parent.find(&old_name) else {
        return ENOENT;
    };
    let Some(new_inode) = new_parent.find(&new_name) else {
        return ENOENT;
    };

    if !sticky_rename_allowed(&old_parent, &old_inode, fsuid)
        || !sticky_rename_allowed(&new_parent, &new_inode, fsuid)
    {
        return EPERM;
    }
    if old_inode.is_dir() || new_inode.is_dir() {
        return EINVAL;
    }
    if old_inode.device_id() != new_inode.device_id() {
        return EXDEV;
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
        return EBUSY;
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
    let (dev, ino) = {
        let _ext4_guard = ext4_lock();
        (inode.device_id(), inode.inode_num())
    };
    let write_end = write_off.saturating_add(len);
    let copies: Vec<(usize, usize, usize)> = {
        let process = current_process();
        let inner = process.borrow_mut();
        let mut pending = Vec::new();
        for region in inner.mmap_areas.iter() {
            if !region.file_backed || region.file_dev != dev || region.file_ino != ino {
                continue;
            }
            let Some(region_file_end) = region.file_offset.checked_add(region.len) else {
                continue;
            };
            let overlap_start = core::cmp::max(write_off, region.file_offset);
            let mut overlap_end = core::cmp::min(write_end, region_file_end);
            let region_valid_len = region
                .sigbus_start
                .saturating_sub(region.start)
                .min(region.len);
            let region_valid_end = region.file_offset.saturating_add(region_valid_len);
            overlap_end = core::cmp::min(overlap_end, region_valid_end);
            if overlap_end <= overlap_start {
                continue;
            }
            pending.push((
                region.start + (overlap_start - region.file_offset),
                overlap_start - write_off,
                overlap_end - overlap_start,
            ));
        }
        pending
    };
    if copies.is_empty() {
        return;
    }

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
            if try_copy_to_user_unchecked(token, (dst + done) as *mut u8, &tmp[..chunk]).is_err() {
                return;
            }
            done += chunk;
        }
    }
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
        inner.rlimit_fsize_cur
    };
    if limit != u64::MAX && (new_len as u64) > limit {
        let pid = current_process().getpid();
        queue_process_signal(pid, SIGXFSZ_NUM);
        return Err(EFBIG);
    }
    Ok(())
}

pub(crate) fn flush_open_inode_views(target: &Arc<ext4_fs::Inode>) {
    let target_ino = target.inode_num();
    let target_dev = target.device_id();
    let files = {
        let process = current_files_process();
        let inner = process.borrow_mut();
        inner
            .fd_table
            .iter()
            .filter_map(|f| f.as_ref().map(Arc::clone))
            .collect::<Vec<_>>()
    };
    for file in files {
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
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        if inner
            .fd_table
            .iter()
            .filter_map(|f| f.as_ref())
            .any(|file| {
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
    Err(ENOSPC)
}

pub(crate) fn truncate_regular_inode(inode: &Arc<ext4_fs::Inode>, new_len: usize) -> isize {
    let _ext4_guard = ext4_lock();
    if inode.is_dir() {
        return EISDIR;
    }
    if !inode.is_file() {
        return EINVAL;
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
            Ok(_) => EIO,
            Err(e) => ext4_err_to_errno(e),
        };
    }

    let mut off = old_len;
    let zeros = [0u8; 4096];
    while off < new_len {
        let chunk = core::cmp::min(zeros.len(), new_len - off);
        match inode.write_at(off, &zeros[..chunk]) {
            Ok(0) => return EIO,
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
            Ok(0) => return EIO,
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
            Ok(0) => return EIO,
            Ok(written) => off += written,
            Err(e) => return ext4_err_to_errno(e),
        }
    }
    0
}

pub(crate) fn punch_hole_keep_size(inode: &Arc<ext4_fs::Inode>, offset: usize, len: usize) -> isize {
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

/// Linux `fallocate(2)` (syscall 47 on riscv64).

/// Linux `ftruncate(2)` (syscall 46 on riscv64).

/// Linux `truncate(2)` (syscall 45 on riscv64).

/// Linux `sendfile(2)` (syscall 71 on riscv64).

/// Linux `splice(2)` (syscall 76 on riscv64).

/// Linux `tee(2)` (syscall 77 on riscv64).

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VmIoVec {
    iov_base: usize,
    iov_len: usize,
}

pub(crate) fn read_vm_iovec(token: usize, iov_ptr: usize, index: usize) -> Result<VmIoVec, isize> {
    let iov_size = core::mem::size_of::<VmIoVec>();
    let Some(off) = index
        .checked_mul(iov_size)
        .and_then(|v| iov_ptr.checked_add(v))
    else {
        return Err(EFAULT);
    };
    try_read_user_value(token, off as *const VmIoVec).ok_or(EFAULT)
}

/// Linux `vmsplice(2)` (syscall 75 on riscv64).

/// Linux `copy_file_range(2)` (syscall 285 on riscv64).

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct KStatFs {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [i64; 4],
}

pub(crate) fn fill_statfs(st_ptr: usize, mount_flags: i64) -> isize {
    if st_ptr == 0 {
        return EFAULT;
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
        return EFAULT;
    }
    0
}

/// Linux `fstatfs(2)` (syscall 44 on riscv64).

/// Linux `statfs(2)` (syscall 43 on riscv64).

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct TimeSpec {
    sec: i64,
    nsec: i64,
}

pub(crate) const UTIME_OMIT: i64 = 0x3ffffffe;
pub(crate) const UTIME_NOW: i64 = 0x3fffffff;

pub(crate) fn resolve_utime(ts: TimeSpec, now: (i64, i64)) -> Result<Option<(i64, i64)>, isize> {
    match ts.nsec {
        UTIME_OMIT => Ok(None),
        UTIME_NOW => Ok(Some(now)),
        nsec if nsec >= 0 && nsec < 1_000_000_000 => {
            if ts.sec < 0 {
                Err(EINVAL)
            } else {
                Ok(Some((ts.sec, nsec)))
            }
        }
        _ => Err(EINVAL),
    }
}

/// Linux `utimensat(2)` (syscall 88 on riscv64).
///
/// Update inode timestamps for compatibility (busybox `touch`, libc tests).


#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct KStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    __pad: u64,
    st_size: i64,
    st_blksize: u32,
    __pad2: i32,
    st_blocks: u64,
    st_atime_sec: i64,
    st_atime_nsec: i64,
    st_mtime_sec: i64,
    st_mtime_nsec: i64,
    st_ctime_sec: i64,
    st_ctime_nsec: i64,
    __unused: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    __spare2: [u64; 14],
}

pub(crate) const STATX_BASIC_STATS: u32 = 0x07ff;
pub(crate) const STATX_ATTR_IMMUTABLE: u64 = 0x0000_0010;
pub(crate) const STATX_ATTR_APPEND: u64 = 0x0000_0020;
pub(crate) const STATX_ATTR_NODUMP: u64 = 0x0000_0040;

pub(crate) const EXT4_ST_DEV: u64 = 1;

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

pub(crate) fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

pub(crate) fn read_u32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

pub(crate) fn read_u16_le(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[0], buf[1]])
}

pub(crate) fn write_bytes_user(token: usize, mut dst: usize, bytes: &[u8]) {
    for b in bytes {
        *translated_mutref(token, dst as *mut u8) = *b;
        dst += 1;
    }
}

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

pub(crate) fn proc_symlink_kstat(link_len: usize) -> KStat {
    let st_size = link_len as i64;
    let st_blocks = if st_size <= 0 {
        0
    } else {
        ((st_size as u64 + 511) / 512) as u64
    };
    KStat {
        st_dev: 0,
        st_ino: 1,
        st_mode: 0o120777,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
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
    }
}

pub(crate) fn kstat_from_file(file: &alloc::sync::Arc<dyn File + Send + Sync>) -> Result<KStat, isize> {
    if let Some(link) = file.as_any().downcast_ref::<ProcMagicLinkFile>() {
        return Ok(proc_symlink_kstat(link.target_len_hint()));
    }

    if file.as_any().downcast_ref::<PseudoDir>().is_some()
        || file.as_any().downcast_ref::<PseudoFile>().is_some()
        || file.as_any().downcast_ref::<ProcPseudoFile>().is_some()
        || file.as_any().downcast_ref::<CgroupFile>().is_some()
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<PseudoShmFile>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
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
        } else if file.as_any().downcast_ref::<PseudoShmFile>().is_some()
            || file.as_any().downcast_ref::<RtcFile>().is_some()
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
        } else if file.as_any().downcast_ref::<TtyFile>().is_some() {
            0x500
        } else if file.as_any().downcast_ref::<PtyMasterFile>().is_some() {
            0x501
        } else if file.as_any().downcast_ref::<PtySlaveFile>().is_some() {
            0x502
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
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
        let st_ino = if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
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
            st_nlink: 1,
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

    let _ext4_guard = ext4_lock();
    let mode_raw = inode.mode();
    let mode = mode_raw as u32;
    let uid = inode.uid();
    let gid = inode.gid();
    let nlink = inode.link_count();
    let st_rdev = inode_rdev_for_mode(&inode, mode_raw);
    let disk_size = inode.size() as usize;
    let size = core::cmp::max(disk_size, os_inode.pending_write_end()) as i64;
    let blocks = (((size as u64) + 511) / 512) as u64;
    let times = get_inode_times(inode.inode_num() as u64);

    Ok(KStat {
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
    })
}

pub(crate) fn kstat_from_abs_path(abs: &str) -> Result<KStat, isize> {
    let at = resolve_at_path(AT_FDCWD, abs)?;
    if let AtPath::PseudoAbs(_) = &at {
        let Some(file) = open_pseudo(abs) else {
            return Err(ENOENT);
        };
        return kstat_from_file(&file);
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = resolve_at_inode(&at, fsuid, fsgid, true)?;
    let mode_raw = inode.mode();
    let mode = mode_raw as u32;
    let uid = inode.uid();
    let gid = inode.gid();
    let nlink = inode.link_count();
    let st_rdev = inode_rdev_for_mode(&inode, mode_raw);
    let size = inode_visible_size(&inode) as i64;
    let blocks = (((size as u64) + 511) / 512) as u64;
    let times = get_inode_times(inode.inode_num() as u64);

    Ok(KStat {
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
    })
}

pub(crate) fn proc_magic_link_target_kstat(path: &str) -> Result<Option<KStat>, isize> {
    if !crate::fs::proc_magic_link_exists(path) {
        return Ok(None);
    }
    if let Some(file) = crate::fs::proc_fd_link_file(path) {
        return kstat_from_file(&file).map(Some);
    }
    if let Some(file) = open_pseudo(path) {
        return kstat_from_file(&file).map(Some);
    }
    let Some(target) = crate::fs::proc_readlink(path) else {
        return Err(ENOENT);
    };
    if !target.starts_with('/') {
        return Err(ENOENT);
    }
    kstat_from_abs_path(&target).map(Some)
}

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

pub(crate) fn kstat_from_fd(fd: usize) -> Result<KStat, isize> {
    let Some(file) = get_fd_file(fd) else {
        return Err(EBADF);
    };
    kstat_from_file(&file)
}


/// Linux `fsync(2)` / `fdatasync(2)` (syscalls 82/83 on riscv64).
///
/// iozone uses this heavily; keep it lightweight but flush per-fd buffered writes.

/// Linux `sync(2)` (syscall 81 on riscv64).
///
/// Flush per-fd write buffers and the ext4 block cache to disk.

/// Linux `syncfs(2)` (syscall 267 on riscv64).
///
/// We treat this as a per-filesystem sync request rooted at `fd`.

/// Linux `sync_file_range(2)` (syscall 84 on riscv64).
///
/// Minimal implementation: flush buffered data for regular files.

/// Linux `fadvise64(2)` / userspace `posix_fadvise(3)` backend.


/// Linux `statx(2)` (syscall 291 on riscv64/loongarch64).


/// Linux `lseek(2)` (syscall 62 on riscv64).
///
/// Needed by glibc directory APIs (`opendir`/`readdir`/`rewinddir`/`telldir`).
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FsContextMode {
    Create,
    Reconfigure,
}

pub(crate) struct FsContextState {
    mode: FsContextMode,
    fs_type: String,
    source_display: String,
    source_abs: Option<String>,
    target_abs: Option<String>,
    pending_flags: usize,
    created: bool,
}

pub(crate) struct FsContextFile {
    state: Mutex<FsContextState>,
}

impl FsContextFile {
    fn new_create(fs_type: &str) -> Self {
        Self {
            state: Mutex::new(FsContextState {
                mode: FsContextMode::Create,
                fs_type: String::from(fs_type),
                source_display: String::from("/dev/root"),
                source_abs: None,
                target_abs: None,
                pending_flags: 0,
                created: false,
            }),
        }
    }

    fn new_reconfigure(
        fs_type: &str,
        source_display: &str,
        source_abs: &str,
        target_abs: &str,
        flags: usize,
    ) -> Self {
        Self {
            state: Mutex::new(FsContextState {
                mode: FsContextMode::Reconfigure,
                fs_type: String::from(fs_type),
                source_display: String::from(source_display),
                source_abs: Some(String::from(source_abs)),
                target_abs: Some(String::from(target_abs)),
                pending_flags: flags,
                created: false,
            }),
        }
    }
}

impl File for FsContextFile {
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        false
    }
    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) struct MountHandleState {
    source: String,
    source_display: String,
    fs_type: String,
    flags: usize,
}

pub(crate) struct MountHandleFile {
    state: Mutex<MountHandleState>,
}

impl MountHandleFile {
    fn new(source: &str, source_display: &str, fs_type: &str, flags: usize) -> Self {
        Self {
            state: Mutex::new(MountHandleState {
                source: String::from(source),
                source_display: String::from(source_display),
                fs_type: String::from(fs_type),
                flags,
            }),
        }
    }
}

impl File for MountHandleFile {
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        false
    }
    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct KMountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

pub(crate) fn alloc_internal_fd(file: Arc<dyn File + Send + Sync>, fd_flags: u32) -> Result<isize, isize> {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return Err(EMFILE);
    };
    inner.fd_table[fd] = Some(file);
    inner.fd_flags[fd] = fd_flags;
    Ok(fd as isize)
}

pub(crate) fn mount_attr_bits_to_legacy_flags(attrs: usize) -> usize {
    let mut flags = 0usize;
    if (attrs & MOUNT_ATTR_RDONLY) != 0 {
        flags |= MS_RDONLY;
    }
    if (attrs & MOUNT_ATTR_NOSUID) != 0 {
        flags |= MS_NOSUID;
    }
    if (attrs & MOUNT_ATTR_NODEV) != 0 {
        flags |= MS_NODEV;
    }
    if (attrs & MOUNT_ATTR_NOEXEC) != 0 {
        flags |= MS_NOEXEC;
    }
    if (attrs & MOUNT_ATTR_NOATIME) != 0 {
        flags |= MS_NOATIME;
    }
    if (attrs & MOUNT_ATTR_STRICTATIME) != 0 {
        flags |= MS_STRICTATIME;
    }
    if (attrs & MOUNT_ATTR_NODIRATIME) != 0 {
        flags |= MS_NODIRATIME;
    }
    if (attrs & MOUNT_ATTR_NOSYMFOLLOW) != 0 {
        flags |= MS_NOSYMFOLLOW;
    }
    flags
}

pub(crate) fn sync_rofs_state(target: &str, flags: usize) {
    if (flags & MS_RDONLY) != 0 {
        register_rofs_mount(target);
    } else {
        unregister_rofs_mount(target);
    }
}

pub(crate) fn read_user_path_abs(dirfd: isize, ptr: usize) -> Result<String, isize> {
    let token = get_current_token();
    let path = read_user_cstring(token, ptr)?;
    if path.is_empty() {
        return Err(ENOENT);
    }
    resolve_abs_path(dirfd, &path)?.ok_or(EBADF)
}

pub(crate) fn ensure_mount_target_dir(abs: &str) -> Result<(), isize> {
    let _ext4_guard = ext4_lock();
    let Some(inode) = find_path_in_roots(abs) else {
        return Err(ENOENT);
    };
    if !inode.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(())
}

pub(crate) fn mount_fs_type_for_abs(abs: &str) -> String {
    mount_lookup_for_abs(abs)
        .map(|m| m.fs_type)
        .unwrap_or_else(|| String::from("ext4"))
}

pub(crate) fn mount_source_display_for_abs(abs: &str) -> String {
    mount_lookup_for_abs(abs)
        .map(|m| m.source_display)
        .unwrap_or_else(|| String::from("/dev/root"))
}








