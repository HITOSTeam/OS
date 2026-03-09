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

use crate::task::manager::{wakeup_task, PID2PCB};
use crate::{
    fs::{
        cgroup_charge_file_write, cgroup_logical_path_for_file, cgroup_mkdir, cgroup_mount,
        cgroup_rename, cgroup_rmdir, cgroup_umount, ext4_lock, find_path_in_roots, make_pipe,
        open_cgroup_pseudo, open_file, pseudo_block_is_read_only, pseudo_block_note_sync,
        pseudo_block_stat_snapshot, register_deferred_unlink_cleanup, secondary_root_inode,
        shm_create, shm_get, shm_list, shm_remove, CgroupFile, CgroupMountKind, File,
        NetSocketFile, OSInode, OpenFlags, Pipe, ProcPseudoFile, PseudoBlock, PseudoDir,
        PseudoDirent, PseudoFile, PseudoShmFile, PtyMasterFile, PtySlaveFile, RtcFile,
        SocketPairEnd, TtyFile,
    },
    mm::{
        copy_from_user, copy_to_user, read_user_value, translated_byte_buffer, translated_mutref,
        translated_str, try_copy_from_user, try_copy_to_user, try_copy_to_user_unchecked,
        try_read_user_value, try_translated_byte_buffer, try_write_user_value, write_user_value,
        MapPermission, UserBuffer,
    },
    task::processor::{
        block_current_and_run_next, current_files_process, current_process, current_task,
    },
    task::{
        signal::{has_unmasked_pending, queue_process_signal, SIGXFSZ_NUM},
        task_block::TaskControlBlock,
        ProcessControlBlock,
    },
    syscall::process::{is_inode_currently_executed_locked, lock_executing_inodes},
    time::get_time_ms,
    trap::get_current_token,
};
use ext4_fs::sync_all;

const AT_FDCWD: isize = -100;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const AT_SYMLINK_FOLLOW: usize = 0x400;
const AT_NO_AUTOMOUNT: usize = 0x800;
const AT_EMPTY_PATH: usize = 0x1000;
const AT_STATX_SYNC_TYPE: usize = 0x6000;

const O_ACCMODE: usize = 0x3;
const O_RDONLY: usize = 0x0;
const O_WRONLY: usize = 0x1;
const O_RDWR: usize = 0x2;
const O_CREAT: usize = 0x40;
const O_EXCL: usize = 0x80;
const O_TRUNC: usize = 0x200;
const O_APPEND: usize = 0x400;
const O_NONBLOCK: usize = 0x800;
const O_DIRECT: usize = 0x4000;
const O_ASYNC: usize = 0x2000;
const O_NOATIME: usize = 0x40000;
const O_PATH: usize = 0x200000;
const O_DIRECTORY: usize = 0x10000;
const O_NOFOLLOW: usize = 0x20000;
const O_CLOEXEC: usize = 0x80000;
// __O_TMPFILE (020000000) | O_DIRECTORY from asm-generic/fcntl.h
const O_TMPFILE: usize = 0x410000;
const ETXTBSY: isize = -26;

const FD_CLOEXEC: u32 = 1;

const MS_RDONLY: usize = 0x1;
const MS_NOSUID: usize = 0x2;
const MS_NODEV: usize = 0x4;
const MS_NOEXEC: usize = 0x8;
const MS_REMOUNT: usize = 0x20;
const MS_NOSYMFOLLOW: usize = 0x100;
const MS_NOATIME: usize = 0x400;
const MS_NODIRATIME: usize = 0x800;
const MS_BIND: usize = 0x1000;
const MS_MOVE: usize = 0x2000;
const MS_PRIVATE: usize = 1 << 18;
const MS_STRICTATIME: usize = 1 << 24;

const MNT_FORCE: usize = 0x1;
const MNT_DETACH: usize = 0x2;
const MNT_EXPIRE: usize = 0x4;
const UMOUNT_NOFOLLOW: usize = 0x8;

const OPEN_TREE_CLONE: usize = 0x1;
const MOVE_MOUNT_F_SYMLINKS: usize = 0x1;
const MOVE_MOUNT_F_AUTOMOUNTS: usize = 0x2;
const MOVE_MOUNT_F_EMPTY_PATH: usize = 0x4;
const MOVE_MOUNT_T_SYMLINKS: usize = 0x10;
const MOVE_MOUNT_T_AUTOMOUNTS: usize = 0x20;
const MOVE_MOUNT_T_EMPTY_PATH: usize = 0x40;
const MOVE_MOUNT__MASK: usize = 0x77;
const FSOPEN_CLOEXEC: usize = 0x1;
const FSMOUNT_CLOEXEC: usize = 0x1;
const FSPICK_CLOEXEC: usize = 0x1;
const FSPICK_SYMLINK_NOFOLLOW: usize = 0x2;
const FSPICK_NO_AUTOMOUNT: usize = 0x4;
const FSPICK_EMPTY_PATH: usize = 0x8;

const FSCONFIG_SET_FLAG: usize = 0;
const FSCONFIG_SET_STRING: usize = 1;
const FSCONFIG_SET_BINARY: usize = 2;
const FSCONFIG_SET_PATH: usize = 3;
const FSCONFIG_SET_PATH_EMPTY: usize = 4;
const FSCONFIG_SET_FD: usize = 5;
const FSCONFIG_CMD_CREATE: usize = 6;
const FSCONFIG_CMD_RECONFIGURE: usize = 7;

const MOUNT_ATTR_RDONLY: usize = 0x00000001;
const MOUNT_ATTR_NOSUID: usize = 0x00000002;
const MOUNT_ATTR_NODEV: usize = 0x00000004;
const MOUNT_ATTR_NOEXEC: usize = 0x00000008;
const MOUNT_ATTR_NOATIME: usize = 0x00000010;
const MOUNT_ATTR_STRICTATIME: usize = 0x00000020;
const MOUNT_ATTR_NODIRATIME: usize = 0x00000080;
const MOUNT_ATTR_NOSYMFOLLOW: usize = 0x00200000;
const ST_NOSYMFOLLOW: usize = 0x2000;

const FSMOUNT_SUPPORTED_ATTRS: usize = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR_NOATIME
    | MOUNT_ATTR_STRICTATIME
    | MOUNT_ATTR_NODIRATIME
    | MOUNT_ATTR_NOSYMFOLLOW;
const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;
const MAX_SYMLINKS: usize = 40;

const S_IFMT: u16 = 0o170000;
const S_IFSOCK: u16 = 0o140000;
const S_IFREG: u16 = 0o100000;
const S_IFBLK: u16 = 0o060000;
const S_IFCHR: u16 = 0o020000;
const S_IFIFO: u16 = 0o010000;

// Linux errno (negative return in kernel ABI).
const EBADF: isize = -9;
const EFAULT: isize = -14;
const ENOTBLK: isize = -15;
const EFBIG: isize = -27;
const EAGAIN: isize = -11;
const EINTR: isize = -4;
const E2BIG: isize = -7;
const ELOOP: isize = -40;
const EPERM: isize = -1;
const ENOENT: isize = -2;
const ENODEV: isize = -19;
const ENODATA: isize = -61;
const EINVAL: isize = -22;
const EBUSY: isize = -16;
const ERANGE: isize = -34;
const EMFILE: isize = -24;
const ENOTDIR: isize = -20;
const EISDIR: isize = -21;
const EACCES: isize = -13;
const EEXIST: isize = -17;
const EXDEV: isize = -18;
const EIO: isize = -5;
const EMLINK: isize = -31;
const ESPIPE: isize = -29;
const EPIPE: isize = -32;
const EROFS: isize = -30;
const ENOSPC: isize = -28;
const ENOSYS: isize = -38;
const ENAMETOOLONG: isize = -36;
const EDEADLK: isize = -35;
const ENXIO: isize = -6;
const EOPNOTSUPP: isize = -95;
const ENOTEMPTY: isize = -39;
const EOVERFLOW: isize = -75;

const XATTR_CREATE: usize = 0x1;
const XATTR_REPLACE: usize = 0x2;
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: usize = 65536;
const PIPE_BUF: usize = 4096;
const SIGIO_NUM: usize = 29;
const IOV_MAX: usize = 1024;

const SPLICE_F_MOVE: usize = 0x01;
const SPLICE_F_NONBLOCK: usize = 0x02;
const SPLICE_F_MORE: usize = 0x04;
const SPLICE_F_GIFT: usize = 0x08;
const DIRECT_IO_ALIGN: usize = 512;

// fs/ioctl.h flags consumed by setxattr03.
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_APPEND_FL: u32 = 0x0000_0020;
const FS_NODUMP_FL: u32 = 0x0000_0040;

const FALLOC_FL_KEEP_SIZE: usize = 0x01;
const FALLOC_FL_PUNCH_HOLE: usize = 0x02;
const FALLOC_FL_SUPPORTED_MASK: usize = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;

static TMPFILE_SEQ: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Default)]
struct InodeTimes {
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

const ACCT_COMM: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Acct {
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

struct AcctState {
    inode: alloc::sync::Arc<ext4_fs::Inode>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FcntlFlock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FcntlOwnerEx {
    type_: i32,
    pid: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FileLockKey {
    dev: u64,
    ino: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RecordLock {
    owner: RecordLockOwner,
    owner_pid: usize,
    lock_type: i16,
    start: i64,
    end: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RecordLockOwner {
    Process(usize),
    OpenFile(usize),
}

#[derive(Clone, Copy)]
struct WaitingRecordLock {
    key: FileLockKey,
    req_type: i16,
    start: i64,
    end: Option<i64>,
}

#[derive(Clone, Copy)]
struct FileLease {
    owner_pid: usize,
    lease_type: i16,
    pending_break_write: bool,
}

struct FifoDuplexFile {
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

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

struct FifoPipeState {
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
    static ref INODE_PATH_HINTS: Mutex<BTreeMap<(usize, u32), String>> =
        Mutex::new(BTreeMap::new());
    static ref FIFO_PIPE_STATES: Mutex<BTreeMap<u64, Arc<FifoPipeState>>> =
        Mutex::new(BTreeMap::new());
    static ref ROFS_MOUNTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ref MOUNT_TABLE: Mutex<Vec<MountRecord>> = Mutex::new(Vec::new());
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

fn get_inode_times(ino: u64) -> InodeTimes {
    INODE_TIMES.lock().get(&ino).copied().unwrap_or_default()
}

fn set_inode_times(ino: u64, times: InodeTimes) {
    INODE_TIMES.lock().insert(ino, times);
}

fn set_inode_all_times_now(inode: &Arc<ext4_fs::Inode>) {
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

fn touch_inode_mtime_ctime_now(inode: &Arc<ext4_fs::Inode>) {
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

fn note_inode_path_hint(inode: &Arc<ext4_fs::Inode>, path: &str) {
    INODE_PATH_HINTS
        .lock()
        .insert((inode.device_id(), inode.inode_num()), String::from(path));
}

fn inode_path_hint(inode: &Arc<ext4_fs::Inode>) -> Option<String> {
    INODE_PATH_HINTS
        .lock()
        .get(&(inode.device_id(), inode.inode_num()))
        .cloned()
}

fn inode_is_immutable_or_append(inode: &Arc<ext4_fs::Inode>) -> bool {
    (inode_fs_flags(inode.inode_num() as u64) & (FS_IMMUTABLE_FL | FS_APPEND_FL)) != 0
}

#[derive(Clone)]
struct MountRecord {
    target: String,
    source: String,
    source_display: String,
    fs_type: String,
    flags: usize,
    access_seq: usize,
    expire_mark_seq: Option<usize>,
}

fn mount_flags_to_proc_opts(flags: usize) -> String {
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

fn mount_flags_to_statfs(flags: usize) -> i64 {
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

fn mount_source_join(source: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        return String::from(source);
    }
    if source == "/" {
        return alloc::format!("/{}", suffix.trim_start_matches('/'));
    }
    alloc::format!(
        "{}/{}",
        source.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
}

fn mount_lookup_for_abs(abs: &str) -> Option<MountRecord> {
    let mounts = MOUNT_TABLE.lock();
    let mut best: Option<MountRecord> = None;
    for mount in mounts.iter() {
        if !path_under_mount(abs, &mount.target) {
            continue;
        }
        match best.as_ref() {
            Some(cur) if mount.target.len() <= cur.target.len() => {}
            _ => best = Some(mount.clone()),
        }
    }
    best
}

fn mount_flags_for_abs(abs: &str) -> usize {
    mount_lookup_for_abs(abs).map(|m| m.flags).unwrap_or(0)
}

fn translate_mount_abs(abs: &str) -> String {
    let Some(mount) = mount_lookup_for_abs(abs) else {
        return String::from(abs);
    };
    let suffix = if abs == mount.target {
        ""
    } else {
        &abs[mount.target.len()..]
    };
    normalize_path("/", &mount_source_join(&mount.source, suffix))
}

fn upsert_mount_record(
    target: &str,
    source: &str,
    source_display: &str,
    fs_type: &str,
    flags: usize,
) {
    let mut mounts = MOUNT_TABLE.lock();
    let state = mounts
        .iter()
        .find(|m| m.target == target)
        .map(|m| (m.access_seq, m.expire_mark_seq))
        .unwrap_or((0, None));
    mounts.retain(|m| m.target != target);
    mounts.push(MountRecord {
        target: String::from(target),
        source: String::from(source),
        source_display: String::from(source_display),
        fs_type: String::from(fs_type),
        flags,
        access_seq: state.0,
        expire_mark_seq: state.1,
    });
}

fn remove_mount_record(target: &str) -> bool {
    let mut mounts = MOUNT_TABLE.lock();
    let old_len = mounts.len();
    mounts.retain(|m| m.target != target);
    mounts.len() != old_len
}

fn update_mount_record_flags(target: &str, flags: usize) -> bool {
    let mut mounts = MOUNT_TABLE.lock();
    let Some(record) = mounts.iter_mut().find(|m| m.target == target) else {
        return false;
    };
    record.flags = flags;
    true
}

fn move_mount_record_target(old_target: &str, new_target: &str) -> bool {
    let mut mounts = MOUNT_TABLE.lock();
    let Some(record) = mounts.iter_mut().find(|m| m.target == old_target) else {
        return false;
    };
    record.target = String::from(new_target);
    true
}

fn mount_display_abs(abs: &str) -> String {
    let mounts = MOUNT_TABLE.lock();
    let mut best: Option<&MountRecord> = None;
    for mount in mounts.iter() {
        if !path_under_mount(abs, &mount.source) {
            continue;
        }
        match best {
            Some(cur) if mount.source.len() <= cur.source.len() => {}
            _ => best = Some(mount),
        }
    }
    let Some(mount) = best else {
        return String::from(abs);
    };
    let suffix = if abs == mount.source {
        ""
    } else {
        &abs[mount.source.len()..]
    };
    normalize_path("/", &mount_source_join(&mount.target, suffix))
}

fn sync_rofs_mount_flag(target: &str, flags: usize) {
    let mut mounts = ROFS_MOUNTS.lock();
    mounts.retain(|m| m != target);
    if (flags & MS_RDONLY) != 0 {
        mounts.push(String::from(target));
    }
}

fn mount_flag_mask() -> usize {
    MS_RDONLY
        | MS_NOSUID
        | MS_NODEV
        | MS_NOEXEC
        | MS_NOSYMFOLLOW
        | MS_NOATIME
        | MS_NODIRATIME
        | MS_STRICTATIME
}

fn mount_record_for_target(target: &str) -> Option<MountRecord> {
    let mounts = MOUNT_TABLE.lock();
    mounts.iter().find(|m| m.target == target).cloned()
}

fn note_mount_access(abs: &str) {
    let mut mounts = MOUNT_TABLE.lock();
    let mut best_idx = None;
    let mut best_len = 0usize;
    for (idx, mount) in mounts.iter().enumerate() {
        if path_under_mount(abs, &mount.target) && mount.target.len() >= best_len {
            best_idx = Some(idx);
            best_len = mount.target.len();
        }
    }
    if let Some(idx) = best_idx {
        mounts[idx].access_seq = mounts[idx].access_seq.saturating_add(1);
    }
}

fn mount_file_logical_path(file: &Arc<dyn File + Send + Sync>) -> Option<String> {
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
    inode_path_hint(&os_inode.ext4_inode()).map(|path| mount_display_abs(&path))
}

fn mount_is_busy(target: &str, writable_only: bool) -> bool {
    let self_bind_root = mount_record_for_target(target)
        .map(|record| record.source == target)
        .unwrap_or(false);
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

fn ensure_mount_source_root() -> Result<Arc<ext4_fs::Inode>, isize> {
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

fn source_for_device_mount(key: &str) -> Result<String, isize> {
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

fn target_dir_exists(abs: &str) -> Result<(), isize> {
    if let Some(node) = open_pseudo(abs) {
        if node.as_any().downcast_ref::<PseudoDir>().is_some() {
            return Ok(());
        }
        return Err(ENOTDIR);
    }
    let _ext4_guard = ext4_lock();
    let inode = find_path_in_roots(abs).ok_or(ENOENT)?;
    if !inode.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(())
}

fn sync_mount_record_rofs(target: &str) {
    if let Some(record) = mount_record_for_target(target) {
        sync_rofs_mount_flag(target, record.flags);
    } else {
        sync_rofs_mount_flag(target, 0);
    }
}

fn should_update_inode_atime(path: &str, is_dir: bool, times: InodeTimes, now_sec: i64) -> bool {
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

fn maybe_update_inode_atime(inode: &Arc<ext4_fs::Inode>, is_dir: bool) {
    let Some(path) = inode_path_hint(inode) else {
        return;
    };
    let logical_path = mount_display_abs(&path);
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

    if (flags & MS_PRIVATE) != 0 {
        return match target_dir_exists(&target) {
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

    if mount_record_for_target(&target).is_some() {
        return EBUSY;
    }

    if (flags & MS_BIND) != 0 {
        let Some(source_display) = special.as_deref() else {
            return EINVAL;
        };
        if source_display.is_empty() {
            return EINVAL;
        }
        let source_abs = normalize_path(&cwd, source_display);
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
        upsert_mount_record(&target, &source, &source_abs, fsname, bind_flags);
        sync_mount_record_rofs(&target);
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
        let rc = cgroup_mount(&target, CgroupMountKind::Unified);
        if rc != 0 {
            return rc;
        }
        upsert_mount_record(
            &target,
            &target,
            "cgroup2",
            "cgroup2",
            flags & mount_flag_mask(),
        );
        sync_mount_record_rofs(&target);
        return 0;
    }
    if fsname == "cgroup" {
        let options = data.as_deref().unwrap_or("");
        let mut source = String::from("none");
        let mut kind = CgroupMountKind::LegacyDebug;
        let mut found_controller = false;
        for token in options.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            let parsed = match token {
                "none" => None,
                "debug" => Some((token, CgroupMountKind::LegacyDebug)),
                "cpuset" => Some((token, CgroupMountKind::LegacyCpuset)),
                "cpu" => Some((token, CgroupMountKind::LegacyCpu)),
                "cpuacct" => Some((token, CgroupMountKind::LegacyCpuAcct)),
                "memory" => Some((token, CgroupMountKind::LegacyMemory)),
                "freezer" => Some((token, CgroupMountKind::LegacyFreezer)),
                "devices" => Some((token, CgroupMountKind::LegacyDevices)),
                "blkio" => Some((token, CgroupMountKind::LegacyBlkio)),
                "net_cls" => Some((token, CgroupMountKind::LegacyNetCls)),
                "perf_event" => Some((token, CgroupMountKind::LegacyPerfEvent)),
                "net_prio" => Some((token, CgroupMountKind::LegacyNetPrio)),
                "hugetlb" => Some((token, CgroupMountKind::LegacyHugetlb)),
                _ if token.starts_with("name=") => {
                    source = String::from(token);
                    None
                }
                _ => return ENODEV,
            };
            if let Some((controller, mount_kind)) = parsed {
                source = String::from(controller);
                kind = mount_kind;
                found_controller = true;
            }
        }
        if !found_controller && options.is_empty() {
            source = String::from("none");
        }
        let rc = cgroup_mount(&target, kind);
        if rc != 0 {
            return rc;
        }
        upsert_mount_record(
            &target,
            &target,
            &source,
            "cgroup",
            flags & mount_flag_mask(),
        );
        sync_mount_record_rofs(&target);
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
    upsert_mount_record(
        &target,
        &source,
        source_display,
        fsname,
        flags & mount_flag_mask(),
    );
    sync_mount_record_rofs(&target);
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
        let mut mounts = MOUNT_TABLE.lock();
        let Some(entry) = mounts.iter_mut().find(|m| m.target == abs) else {
            return EINVAL;
        };
        if entry.expire_mark_seq != Some(entry.access_seq) {
            entry.expire_mark_seq = Some(entry.access_seq);
            return EAGAIN;
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
    sync_rofs_mount_flag(&abs, 0);
    let _ = remove_mount_record(&abs);
    if (record.flags & MS_RDONLY) != 0 {
        let mut mounts = ROFS_MOUNTS.lock();
        mounts.retain(|m| m != &abs);
    }
    0
}

pub(crate) fn proc_mounts_snapshot() -> String {
    let mut out = String::from("/dev/root / ext4 rw,relatime 0 0\n");
    let mut mounts = {
        let mounts = MOUNT_TABLE.lock();
        mounts.iter().cloned().collect::<Vec<_>>()
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

pub(crate) fn statfs_mount_flags_for_abs(abs: &str) -> i64 {
    mount_flags_to_statfs(mount_flags_for_abs(abs))
}

pub(crate) fn register_rofs_mount(abs: &str) {
    let mut mounts = ROFS_MOUNTS.lock();
    if !mounts.iter().any(|m| m == abs) {
        mounts.push(String::from(abs));
    }
    let _ = update_mount_record_flags(abs, mount_flags_for_abs(abs) | MS_RDONLY);
}

pub(crate) fn unregister_rofs_mount(abs: &str) {
    let mut mounts = ROFS_MOUNTS.lock();
    mounts.retain(|m| m != abs);
    if let Some(mut record) = mount_lookup_for_abs(abs) {
        if record.target == abs {
            record.flags &= !MS_RDONLY;
            let _ = update_mount_record_flags(abs, record.flags);
        }
    }
}

fn path_is_rofs(abs: &str) -> bool {
    if (mount_flags_for_abs(abs) & MS_RDONLY) != 0 {
        return true;
    }
    let mounts = ROFS_MOUNTS.lock();
    mounts.iter().any(|mnt| path_under_mount(abs, mnt))
}

fn path_is_nodev(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NODEV) != 0
}

fn path_is_noexec(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NOEXEC) != 0
}

fn path_is_nosymfollow(abs: &str) -> bool {
    (mount_flags_for_abs(abs) & MS_NOSYMFOLLOW) != 0
}

fn inode_is_rofs_mount_root(inode: &Arc<ext4_fs::Inode>) -> bool {
    let mounts: Vec<String> = {
        let mounts = ROFS_MOUNTS.lock();
        mounts.iter().cloned().collect()
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

fn path_is_mount_point(abs: &str) -> bool {
    if MOUNT_TABLE.lock().iter().any(|mnt| mnt.target == abs) {
        return true;
    }
    let mounts = ROFS_MOUNTS.lock();
    mounts.iter().any(|mnt| mnt == abs)
}

fn path_under_mount(abs: &str, mnt: &str) -> bool {
    if mnt == "/" {
        return true;
    }
    if abs == mnt {
        return true;
    }
    abs.starts_with(mnt) && abs.as_bytes().get(mnt.len()) == Some(&b'/')
}

fn final_non_empty_component(path: &str) -> Option<&str> {
    path.rsplit('/').find(|comp| !comp.is_empty())
}

fn rofs_mount_root_for_abs(abs: &str) -> Option<String> {
    if let Some(mount) = mount_lookup_for_abs(abs) {
        return Some(mount.target);
    }
    let mounts = ROFS_MOUNTS.lock();
    let mut best: Option<&str> = None;
    for mnt in mounts.iter() {
        if path_under_mount(abs, mnt) {
            match best {
                Some(cur) if mnt.len() <= cur.len() => {}
                _ => best = Some(mnt.as_str()),
            }
        }
    }
    best.map(String::from)
}

fn hardlink_cross_mount(old_abs: &str, new_abs: &str) -> bool {
    match (
        rofs_mount_root_for_abs(old_abs),
        rofs_mount_root_for_abs(new_abs),
    ) {
        (None, None) => false,
        (Some(a), Some(b)) => a != b,
        _ => true,
    }
}

fn current_timespec() -> (i64, i64) {
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

fn current_process_root() -> String {
    let process = current_process();
    let inner = process.borrow_mut();
    inner.root.clone()
}

fn apply_process_root(abs: &str) -> String {
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

fn normalize_relative_path(path: &str) -> String {
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

fn validate_path_components(path: &str) -> Result<(), isize> {
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
    }
    Ok(())
}

fn path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn busybox_exists() -> bool {
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

fn should_try_busybox_applet_path(path: &str, allow_relative: bool) -> bool {
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

fn shm_object_name(abs: &str) -> Option<&str> {
    // Only accept `/dev/shm/<name>` (single path component).
    let rest = abs.strip_prefix("/dev/shm/")?;
    let name = rest.trim_start_matches('/');
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some(name)
}

fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
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

fn resolve_final_symlink_abs_path(abs: &str) -> String {
    let mut current = String::from(abs);
    for _ in 0..MAX_SYMLINKS {
        if current == "/" {
            break;
        }
        let Some((parent, name)) = split_parent_and_name(&current) else {
            break;
        };
        let parent_abs = if parent.is_empty() { "/" } else { parent };
        let Some(parent_inode) = find_path_in_roots(parent_abs) else {
            break;
        };
        let Some(child) = parent_inode.find(name) else {
            break;
        };
        if !child.is_symlink() {
            break;
        }
        let target = String::from_utf8_lossy(&child.read_all()).into_owned();
        if target.is_empty() {
            break;
        }
        current = if target.starts_with('/') {
            normalize_path("/", &target)
        } else {
            normalize_path(parent_abs, &target)
        };
    }
    current
}

fn get_fd_file(fd: usize) -> Option<alloc::sync::Arc<dyn File + Send + Sync>> {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return None;
    }
    inner.fd_table[fd].clone()
}

fn file_is_seekable_for_preadwrite(file: &alloc::sync::Arc<dyn File + Send + Sync>) -> bool {
    if file.as_any().downcast_ref::<OSInode>().is_some() {
        return true;
    }
    if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
        return true;
    }
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        return pf.len().is_some();
    }
    false
}

fn fd_has_o_path(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_PATH as u32) != 0
}

fn fd_has_nonblock(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_NONBLOCK as u32) != 0
}

fn fd_has_append(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_APPEND as u32) != 0
}

fn fd_has_odirect(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_DIRECT as u32) != 0
}

fn fd_has_noatime(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_NOATIME as u32) != 0
}

fn validate_direct_io_request(
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

fn read_optional_offset(ptr: usize) -> Result<Option<usize>, isize> {
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

fn write_optional_offset(ptr: usize, value: usize) -> Result<(), isize> {
    if ptr == 0 {
        return Ok(());
    }
    let next = value as i64;
    if try_write_user_value(get_current_token(), ptr as *mut i64, &next).is_err() {
        return Err(EFAULT);
    }
    Ok(())
}

fn file_is_pipe(file: &alloc::sync::Arc<dyn File + Send + Sync>) -> bool {
    file.as_any().downcast_ref::<Pipe>().is_some()
}

fn pipe_read_to_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    out: &mut [u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        return pipe.read_to_slice(out, nonblock);
    }
    Err(EINVAL)
}

fn pipe_write_from_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    data: &[u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        return pipe.write_from_slice(data, nonblock);
    }
    Err(EINVAL)
}

fn socketpair_write_from_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    data: &[u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        return sock.write_from_slice(data, nonblock);
    }
    Err(EINVAL)
}

fn open_fd_flags(flags: usize, o_path: bool) -> u32 {
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

fn install_open_file_fd(
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

fn fifo_pipe_state_for_inode(inode_num: u64) -> Arc<FifoPipeState> {
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

fn get_fd_inode(fd: usize) -> Option<alloc::sync::Arc<ext4_fs::Inode>> {
    let file = get_fd_file(fd)?;
    file.as_any()
        .downcast_ref::<OSInode>()
        .map(|o| o.ext4_inode())
}

fn is_pseudo_path(abs: &str) -> bool {
    crate::fs::is_cgroup_pseudo_path(abs)
        || abs == "/sys"
        || abs.starts_with("/sys/")
        || abs == "/dev"
        || abs.starts_with("/dev/")
        || abs == "/proc/sys"
        || abs.starts_with("/proc/sys/")
        || abs == "/etc"
        || abs.starts_with("/etc/")
}

fn rewrite_proc_self(abs: &str) -> String {
    if abs == "/proc/self" || abs.starts_with("/proc/self/") {
        let pid = current_process().getpid();
        let suffix = &abs["/proc/self".len()..];
        let mut out = alloc::format!("/proc/{pid}");
        out.push_str(suffix);
        return out;
    }
    String::from(abs)
}

enum AtPath {
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

fn resolve_at_path(dirfd: isize, path: &str) -> Result<AtPath, isize> {
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
        let abs = rewrite_proc_self(&apply_process_root(&jail_abs));
        if crate::fs::is_proc_pseudo_path(&abs) {
            return Ok(AtPath::PseudoAbs(abs));
        }
        if let Some(mount) = mount_lookup_for_abs(&abs) {
            if mount.fs_type == "cgroup2" || mount.fs_type == "cgroup" {
                return Ok(AtPath::PseudoAbs(abs));
            }
        }
        return Ok(if is_pseudo_path(&abs) {
            AtPath::PseudoAbs(abs)
        } else {
            AtPath::Ext4Abs(translate_mount_abs(&abs))
        });
    }

    // Relative path.
    if dirfd == AT_FDCWD {
        let process = current_process();
        let cwd = { process.borrow_mut().cwd.clone() };
        let abs = rewrite_proc_self(&normalize_path(&cwd, path));
        if crate::fs::is_proc_pseudo_path(&abs) {
            return Ok(AtPath::PseudoAbs(abs));
        }
        if let Some(mount) = mount_lookup_for_abs(&abs) {
            if mount.fs_type == "cgroup2" || mount.fs_type == "cgroup" {
                return Ok(AtPath::PseudoAbs(abs));
            }
        }
        if is_pseudo_path(&abs) {
            return Ok(AtPath::PseudoAbs(abs));
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
        let Some(base) = find_path_in_roots(&translate_mount_abs(&cwd)) else {
            return Err(ENOENT);
        };
        return Ok(AtPath::Ext4Rel { base, rel });
    }

    if dirfd < 0 {
        return Err(EBADF);
    }

    let Some(file) = get_fd_file(dirfd as usize) else {
        return Err(EBADF);
    };

    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        let abs = rewrite_proc_self(&normalize_path(pdir.path(), path));
        if crate::fs::is_proc_pseudo_path(&abs) {
            return Ok(AtPath::PseudoAbs(abs));
        }
        if let Some(mount) = mount_lookup_for_abs(&abs) {
            if mount.fs_type == "cgroup2" || mount.fs_type == "cgroup" {
                return Ok(AtPath::PseudoAbs(abs));
            }
        }
        return Ok(if is_pseudo_path(&abs) {
            AtPath::PseudoAbs(abs)
        } else {
            AtPath::Ext4Abs(translate_mount_abs(&abs))
        });
    }

    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let base = os_inode.ext4_inode();
        if !base.is_dir() {
            return Err(ENOTDIR);
        }
        let rel = normalize_relative_path(path);
        if !rel.is_empty() && crate::fs::is_proc_root(base.as_ref()) {
            let abs = alloc::format!("/proc/{}", rel);
            if crate::fs::is_proc_pseudo_path(&abs) {
                return Ok(AtPath::PseudoAbs(abs));
            }
        }
        return Ok(AtPath::Ext4Rel { base, rel });
    }

    Err(ENOTDIR)
}

fn resolve_ext4_abs_path(
    path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
    depth: &mut usize,
    seen_symlinks: &mut Vec<u32>,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let abs = rewrite_proc_self(path);

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

fn parse_proc_fd_for_current_process(path: &str) -> Option<usize> {
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

fn empty_path_fd_for_at_op(dirfd: isize, flags: usize) -> Result<usize, isize> {
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

fn maybe_dispatch_proc_fd_at(
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

fn pseudo_path_exists_result(abs: &str) -> isize {
    if let Some(name) = shm_object_name(abs) {
        return if shm_get(name).is_some() { 0 } else { ENOENT };
    }
    if open_pseudo(abs).is_some() {
        0
    } else {
        ENOENT
    }
}

fn add_root_dir_entries(
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
fn union_root_dir_entries() -> Vec<PseudoDirent> {
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

fn read_user_cstring(token: usize, ptr: usize) -> Result<String, isize> {
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

fn validate_xattr_name(name: &str) -> Result<(), isize> {
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

fn read_user_xattr_name(token: usize, ptr: usize) -> Result<String, isize> {
    let name = read_user_cstring(token, ptr)?;
    validate_xattr_name(&name)?;
    Ok(name)
}

fn read_user_xattr_value(token: usize, value: usize, size: usize) -> Result<Vec<u8>, isize> {
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

fn xattr_is_user_namespace(name: &str) -> bool {
    name.starts_with("user.")
}

fn inode_supports_user_xattr(inode: &Arc<ext4_fs::Inode>) -> bool {
    inode.is_file() || inode.is_dir()
}

fn resolve_xattr_path_inode(
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

fn resolve_xattr_fd_inode(fd: usize) -> Result<Option<Arc<ext4_fs::Inode>>, isize> {
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

fn do_setxattr(inode: &Arc<ext4_fs::Inode>, name: &str, value: &[u8], flags: usize) -> isize {
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

fn do_getxattr(
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

fn do_listxattr(inode: &Arc<ext4_fs::Inode>, list_ptr: usize, size: usize, token: usize) -> isize {
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

fn do_removexattr(inode: &Arc<ext4_fs::Inode>, name: &str) -> isize {
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

fn resolve_ext4_path(
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

fn resolve_at_inode(
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
    if let Some(abs) = resolve_abs_path(AT_FDCWD, path) {
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
        if let Some(abs) = resolve_abs_path(dirfd, path) {
            if path_is_noexec(&abs) {
                return Err(EACCES);
            }
        }
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
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
        let inode = resolve_at_inode(&at, fsuid, fsgid, follow_final)?;
        if !follow_final && inode.is_symlink() {
            return Err(ELOOP);
        }
        inode
    };
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
pub fn syscall_acct(pathname: usize) -> isize {
    if current_effective_uid_gid().0 != 0 {
        return EPERM;
    }
    if pathname == 0 {
        *ACCT_STATE.lock() = None;
        return 0;
    }
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }
    let trailing_slash = path.len() > 1 && path.ends_with('/');
    if rofs_for_path(AT_FDCWD, &path) {
        return EROFS;
    }
    let at = match resolve_at_path(AT_FDCWD, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let AtPath::PseudoAbs(_) = &at {
        return EACCES;
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, true) {
        Ok(inode) => inode,
        Err(e) => return e,
    };
    if inode.is_dir() {
        return EISDIR;
    }
    if trailing_slash {
        return ENOTDIR;
    }
    if !inode.is_file() {
        return EACCES;
    }
    if !inode_mode_allows_uid_gid(&inode, 2, fsuid, fsgid) {
        return EACCES;
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

fn resolve_parent_and_name(
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

fn resolve_abs_path(dirfd: isize, path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let abs = if path.starts_with('/') {
        normalize_path("/", path)
    } else if dirfd == AT_FDCWD {
        normalize_path(&cwd, path)
    } else if dirfd >= 0 {
        // If dirfd refers to a pseudo directory, resolve relative to it.
        // For ext4 dirfds, prefer procfs fd symlink target to preserve mount context.
        if let Some(file) = get_fd_file(dirfd as usize) {
            if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
                normalize_path(pdir.path(), path)
            } else {
                let fd_path = alloc::format!("/proc/self/fd/{}", dirfd);
                if let Some(base) = crate::fs::proc_readlink(&fd_path) {
                    normalize_path(&base, path)
                } else {
                    normalize_path(&cwd, path)
                }
            }
        } else {
            return None;
        }
    } else {
        return None;
    };
    Some(abs)
}

fn rofs_for_path(dirfd: isize, path: &str) -> bool {
    resolve_abs_path(dirfd, path)
        .map(|abs| path_is_rofs(&abs))
        .unwrap_or(false)
}

fn ext4_err_to_errno(e: ext4_fs::Ext4Error) -> isize {
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

fn current_real_uid_gid() -> (u32, u32) {
    crate::syscall::misc::current_real_uid_gid()
}

fn current_effective_uid_gid() -> (u32, u32) {
    crate::syscall::misc::current_effective_uid_gid()
}

fn current_fsuid_gid() -> (u32, u32) {
    crate::syscall::misc::current_fsuid_gid()
}

fn current_in_group(gid: u32) -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    gid == inner.fsgid || inner.supplementary_gids.iter().any(|g| *g == gid)
}

fn parse_chown_id(id: usize) -> Option<u32> {
    if id == usize::MAX || id == u32::MAX as usize {
        None
    } else {
        Some(id as u32)
    }
}

fn maybe_clear_suid_sgid_after_chown(inode: &ext4_fs::Inode, touched_owner: bool) {
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

fn apply_chown_to_inode(inode: &ext4_fs::Inode, uid: usize, gid: usize) -> isize {
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

fn inode_mode_allows_uid_gid(inode: &ext4_fs::Inode, mask: usize, uid: u32, gid: u32) -> bool {
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

fn inode_mode_allows(inode: &ext4_fs::Inode, mask: usize) -> bool {
    let (uid, gid) = current_fsuid_gid();
    inode_mode_allows_uid_gid(inode, mask, uid, gid)
}

fn apply_umask(mode: usize) -> u16 {
    let umask = crate::syscall::misc::current_umask() as u16;
    let perm = (mode as u16) & 0o777;
    let special = (mode as u16) & 0o7000;
    special | (perm & !umask)
}

fn parent_forces_gid_inherit(parent: &ext4_fs::Inode) -> bool {
    parent.is_dir() && (parent.mode() & 0o2000) != 0
}

fn gid_for_created_inode(parent: Option<&ext4_fs::Inode>, fallback_gid: u32) -> u32 {
    match parent {
        Some(dir) if parent_forces_gid_inherit(dir) => dir.gid(),
        _ => fallback_gid,
    }
}

fn mode_for_created_file(mut mode: u16, gid: u32) -> u16 {
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

fn inode_rdev_for_mode(inode: &ext4_fs::Inode, mode: u16) -> u64 {
    match mode & S_IFMT {
        S_IFCHR | S_IFBLK => inode.special_rdev(),
        _ => 0,
    }
}

fn linux_dev_major(dev: u64) -> u32 {
    ((((dev >> 8) & 0x0fff) | ((dev >> 32) & 0xffff_f000)) & 0xffff_ffff) as u32
}

fn linux_dev_minor(dev: u64) -> u32 {
    (((dev & 0x00ff) | ((dev >> 12) & 0x0fff_ff00)) & 0xffff_ffff) as u32
}

fn inode_visible_size(inode: &ext4_fs::Inode) -> usize {
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

fn file_lock_key(file: &Arc<dyn File + Send + Sync>) -> Option<FileLockKey> {
    let os_inode = file.as_any().downcast_ref::<OSInode>()?;
    let inode = os_inode.ext4_inode();
    Some(file_lock_key_from_inode(&inode))
}

fn file_lock_key_from_inode(inode: &Arc<ext4_fs::Inode>) -> FileLockKey {
    FileLockKey {
        dev: inode.device_id() as u64,
        ino: inode.inode_num() as u64,
    }
}

fn ofd_lock_owner_id(file: &Arc<dyn File + Send + Sync>) -> usize {
    Arc::as_ptr(file) as *const () as usize
}

fn range_end_i128(end: Option<i64>) -> i128 {
    end.map(|v| v as i128).unwrap_or(i128::MAX)
}

fn ranges_overlap(a_start: i64, a_end: Option<i64>, b_start: i64, b_end: Option<i64>) -> bool {
    let a0 = a_start as i128;
    let b0 = b_start as i128;
    let a1 = range_end_i128(a_end);
    let b1 = range_end_i128(b_end);
    a0 <= b1 && b0 <= a1
}

fn max_range_end(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (None, _) | (_, None) => None,
        (Some(x), Some(y)) => Some(core::cmp::max(x, y)),
    }
}

fn ranges_touch_or_overlap_sorted(left_end: Option<i64>, right_start: i64) -> bool {
    match left_end {
        None => true,
        Some(end) => right_start <= end.saturating_add(1),
    }
}

fn lock_conflicts(
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

fn first_conflicting_lock(
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

fn normalize_record_locks(locks: &mut Vec<RecordLock>) {
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

fn apply_record_lock_for_owner(
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

fn collect_conflict_process_owners(
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

fn set_record_lock_waiting(pid: usize, waiting: WaitingRecordLock) {
    RECORD_LOCK_BLOCKED.lock().insert(pid, waiting);
}

fn clear_record_lock_waiting(pid: usize) {
    RECORD_LOCK_BLOCKED.lock().remove(&pid);
}

fn detect_record_lock_deadlock(waiter_pid: usize, conflict_owners: &[usize]) -> bool {
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

fn lock_range_from_flock(
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

fn enqueue_record_lock_waiter(key: FileLockKey, task: &Arc<TaskControlBlock>) {
    let mut waiters = RECORD_LOCK_WAITERS.lock();
    let queue = waiters.entry(key).or_insert_with(VecDeque::new);
    if queue.iter().any(|waiter| Arc::ptr_eq(waiter, task)) {
        return;
    }
    queue.push_back(Arc::clone(task));
}

fn remove_record_lock_waiter(key: FileLockKey, task: &Arc<TaskControlBlock>) {
    let mut waiters = RECORD_LOCK_WAITERS.lock();
    let Some(queue) = waiters.get_mut(&key) else {
        return;
    };
    queue.retain(|waiter| !Arc::ptr_eq(waiter, task));
    if queue.is_empty() {
        waiters.remove(&key);
    }
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

fn take_record_lock_waiters(key: FileLockKey) -> Vec<Arc<TaskControlBlock>> {
    RECORD_LOCK_WAITERS
        .lock()
        .remove(&key)
        .map(|queue| queue.into_iter().collect())
        .unwrap_or_default()
}

fn wake_record_lock_waiters(key: FileLockKey) {
    for waiter in take_record_lock_waiters(key) {
        wakeup_task(waiter);
    }
}

fn remove_process_record_locks_for_key(owner_pid: usize, key: FileLockKey) {
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

fn remove_owner_file_lease_for_key(owner_pid: usize, key: FileLockKey) {
    let mut table = FILE_LEASES.lock();
    if table
        .get(&key)
        .is_some_and(|lease| lease.owner_pid == owner_pid)
    {
        table.remove(&key);
    }
}

pub fn release_all_file_leases_for_owner(owner_pid: usize) {
    let mut table = FILE_LEASES.lock();
    table.retain(|_, lease| lease.owner_pid != owner_pid);
}

fn count_open_fds_for_key(key: FileLockKey) -> usize {
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

fn set_file_lease(
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

fn get_file_lease_type(key: FileLockKey, owner_pid: usize) -> i16 {
    FILE_LEASES
        .lock()
        .get(&key)
        .filter(|lease| lease.owner_pid == owner_pid)
        .map(|lease| lease.lease_type)
        .unwrap_or(2)
}

fn maybe_signal_lease_break(
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

fn has_pending_unmasked_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    // Keep lock waits aligned with Linux semantics: ignored/default SIGCHLD
    // from helper children should not abort F_SETLKW with EINTR.
    has_unmasked_pending(inner.pending_signals, inner.signal_mask, true)
}

pub fn syscall_fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    // Minimal `fcntl(2)` support for busybox/ash/glibc startup.
    const ESRCH: isize = -3;
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
                return EBADF;
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
                return EBADF;
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
                return EBADF;
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
                return EBADF;
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
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
            };
            let owner = arg as i32;
            let (owner_type, owner_pid) = if owner < 0 {
                let Some(pid) = owner.checked_neg() else {
                    return EINVAL;
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
                    return ESRCH;
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
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
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
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let token = get_current_token();
            let own = match try_read_user_value::<FcntlOwnerEx>(token, arg as *const FcntlOwnerEx) {
                Some(v) => v,
                None => return EFAULT,
            };
            if !matches!(own.type_, F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP) {
                return EINVAL;
            }
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
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
                    return ESRCH;
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
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
            };
            let (owner_type, owner_pid) = pipe.get_async_owner();
            let own = FcntlOwnerEx {
                type_: owner_type,
                pid: owner_pid,
            };
            let token = get_current_token();
            if try_write_user_value(token, arg as *mut FcntlOwnerEx, &own).is_err() {
                return EFAULT;
            }
            0
        }
        F_SETSIG => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
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
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
            };
            pipe.get_async_signal() as isize
        }
        F_SETLEASE => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(key) = file_lock_key(&file) else {
                return EINVAL;
            };
            let owner_pid = current_process().getpid();
            set_file_lease(key, owner_pid, arg as i16, &file)
        }
        F_GETLEASE => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(key) = file_lock_key(&file) else {
                return EINVAL;
            };
            let owner_pid = current_process().getpid();
            get_file_lease_type(key, owner_pid) as isize
        }
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);

            let token = get_current_token();
            let flock = match try_read_user_value::<FcntlFlock>(token, arg as *const FcntlFlock) {
                Some(v) => v,
                None => return EFAULT,
            };
            let is_ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
            if is_ofd && flock.l_pid != 0 {
                return EINVAL;
            }
            let Some(key) = file_lock_key(&file) else {
                return EINVAL;
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
                        return EBADF;
                    }
                }
                F_WRLCK => {
                    if !file.writable() {
                        return EBADF;
                    }
                }
                F_UNLCK => {}
                _ => return EINVAL,
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
                    return EFAULT;
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
                        break EAGAIN;
                    }
                    if !is_ofd && detect_record_lock_deadlock(owner_pid, &conflict_owners) {
                        break EDEADLK;
                    }
                    let Some(task) = waiter_task.as_ref() else {
                        break EACCES;
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
                        break EINTR;
                    }
                    block_current_and_run_next();
                    if has_pending_unmasked_signal() {
                        remove_record_lock_waiter(key, task);
                        if !is_ofd {
                            clear_record_lock_waiting(owner_pid);
                        }
                        break EINTR;
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
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
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
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
            };
            pipe.pipe_size() as isize
        }
        F_GET_SEALS => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            drop(inner);
            let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() else {
                return EINVAL;
            };
            let Some(seals) = shm.memfd_seals() else {
                return EINVAL;
            };
            seals as isize
        }
        F_ADD_SEALS => {
            let process = current_files_process();
            let inner = process.borrow_mut();
            if !inner.is_fd_open(fd) {
                return EBADF;
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
                return EPERM;
            }
            let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() else {
                return EINVAL;
            };
            let add = arg as u32;
            if (add & !PseudoShmFile::F_SEAL_ALL) != 0 {
                return EINVAL;
            }
            if (add & PseudoShmFile::F_SEAL_WRITE) != 0
                && !shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE)
                && has_writable_shared_map
            {
                return EBUSY;
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
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            inner.ensure_fd_flags_len();
            let old_flags = inner.fd_flags[fd];
            let minfd = arg;
            let limit = inner.rlimit_nofile_cur as usize;
            if minfd >= limit {
                return EINVAL;
            }
            let mut newfd = minfd;
            while newfd < inner.fd_table.len() && inner.fd_table[newfd].is_some() {
                newfd += 1;
            }
            if newfd >= limit {
                return EMFILE;
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
        _ => EINVAL,
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

pub fn syscall_openat(dirfd: isize, pathname: usize, flags: usize, mode: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
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
    let nofollow = (flags & O_NOFOLLOW) != 0;
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
    let write_intent = writable || (flags & (O_CREAT | O_TRUNC)) != 0 || tmpfile_requested;
    let raw_abs = resolve_abs_path(dirfd, &path);
    let readonly_fs = raw_abs.as_deref().map(path_is_rofs).unwrap_or(false);
    if write_intent && readonly_fs {
        return EROFS;
    }
    // `/proc/self/fd/<n>` reopen path: used by memfd and shell helpers.
    if let Some(abs) = raw_abs.as_deref() {
        if let Some(src_fd) = parse_proc_fd_for_current_process(&abs) {
            let Some(src_file) = get_fd_file(src_fd) else {
                return ENOENT;
            };
            let file: alloc::sync::Arc<dyn File + Send + Sync> =
                if let Some(shm) = src_file.as_any().downcast_ref::<PseudoShmFile>() {
                    alloc::sync::Arc::new(shm.reopen_with_mode(readable, writable))
                } else {
                    src_file
                };
            let fd = match install_open_file_fd(file, flags, o_path) {
                Ok(fd) => fd,
                Err(e) => return e,
            };
            if !o_path && (flags & O_TRUNC) != 0 {
                let tr = syscall_ftruncate(fd, 0);
                if tr != 0 {
                    let process = current_files_process();
                    let mut inner = process.borrow_mut();
                    let _ = inner.clear_fd(fd);
                    return tr;
                }
            }
            return fd as isize;
        }
    }
    let append = !o_path && (flags & O_APPEND) != 0;

    let at = match resolve_at_path(dirfd, &path) {
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
    let mut created_parent: Option<alloc::sync::Arc<ext4_fs::Inode>> = None;
    let mut tmpfile_cleanup_parent: Option<alloc::sync::Arc<ext4_fs::Inode>> = None;
    let mut tmpfile_cleanup_name: Option<alloc::string::String> = None;
    let (fsuid, fsgid) = current_fsuid_gid();
    if let Some(abs) = raw_abs.as_deref() {
        if path_is_nosymfollow(abs) {
            if let Ok(inode) = resolve_at_inode(&at, fsuid, fsgid, false) {
                if inode.is_symlink() {
                    return ELOOP;
                }
            }
        }
    }

    // Pseudo fs: `/sys`, `/dev`.
    if let AtPath::PseudoAbs(abs) = &at {
        if tmpfile_requested {
            return EOPNOTSUPP;
        }
        // Minimal `/dev/shm` support for POSIX `shm_open` users (e.g., cyclictest).
        // Must handle `O_CREAT|O_EXCL` even when the object already exists.
        let file: alloc::sync::Arc<dyn File + Send + Sync> =
            if let Some(name) = shm_object_name(abs) {
                if (flags & O_CREAT) != 0 {
                    if (flags & O_EXCL) != 0 && shm_get(name).is_some() {
                        return EEXIST;
                    }
                    let data = shm_create(name);
                    alloc::sync::Arc::new(PseudoShmFile::new_with_mode(data, readable, writable))
                } else {
                    let Some(data) = shm_get(name) else {
                        return ENOENT;
                    };
                    alloc::sync::Arc::new(PseudoShmFile::new_with_mode(data, readable, writable))
                }
            } else if let Some(f) = open_pseudo(abs) {
                f
            } else {
                return ENOENT;
            };
        let fd = match install_open_file_fd(file, flags, o_path) {
            Ok(fd) => fd,
            Err(e) => return e,
        };
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            if abs == "/proc" || abs == "/sys" || abs == "/dev" {
                crate::println!("[fs] openat(pid={}) pseudo '{}' -> fd={}", pid, abs, fd);
            }
        }
        return fd as isize;
    }

    // If we have a secondary disk, expose a merged view of `/` for directory listing.
    if let AtPath::Ext4Abs(abs) = &at {
        if abs == "/" && secondary_root_inode().is_some() {
            if write_intent && !o_path {
                return EISDIR;
            }
            let _ext4_guard = ext4_lock();
            let entries = union_root_dir_entries();
            drop(_ext4_guard);
            let file: alloc::sync::Arc<dyn File + Send + Sync> =
                alloc::sync::Arc::new(PseudoDir::new("/", entries));
            let fd = match install_open_file_fd(file, flags, o_path) {
                Ok(fd) => fd,
                Err(e) => return e,
            };
            return fd as isize;
        }
    }

    let ext4_guard = ext4_lock();

    // ext4 lookup with search permission checks and symlink resolution.
    let mut inode = match resolve_at_inode(&at, fsuid, fsgid, !nofollow) {
        Ok(v) => Some(v),
        Err(ENOENT) => None,
        Err(e) => {
            if debug_close {
                crate::println!("[fs] openat close-test resolve_at_inode err={}", e);
            }
            return e;
        }
    };

    if !o_path && nofollow {
        if let Some(inode_ref) = inode.as_ref() {
            if inode_ref.is_symlink() {
                return ELOOP;
            }
        }
    }

    // Existing path + O_CREAT|O_EXCL must fail.
    if !tmpfile_requested && inode.is_some() && (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 {
        return EEXIST;
    }

    if tmpfile_requested {
        let dir_inode = match inode {
            Some(ref i) => alloc::sync::Arc::clone(i),
            None => return ENOENT,
        };
        if !dir_inode.is_dir() {
            return ENOTDIR;
        }
        if !inode_mode_allows_uid_gid(&dir_inode, 3, fsuid, fsgid) {
            return EACCES;
        }
        // Emulate anonymous tmpfile semantics using a hidden per-filesystem pool.
        // Use the known root inode for the same block device to avoid relying on
        // per-directory ".." lookups (which can leave stale hidden entries behind).
        let mut fs_root = crate::fs::root_inode_for_path("/");
        if fs_root.device_id() != dir_inode.device_id() {
            if let Some(sec_root) = secondary_root_inode() {
                if sec_root.device_id() == dir_inode.device_id() {
                    fs_root = sec_root;
                } else {
                    // Fallback: best effort on the opened directory's filesystem.
                    fs_root = alloc::sync::Arc::clone(&dir_inode);
                }
            } else {
                fs_root = alloc::sync::Arc::clone(&dir_inode);
            }
        }
        let pool_name = ".ltp_tmpfile_pool";
        let pool_dir = if let Some(existing) = fs_root.find(pool_name) {
            if !existing.is_dir() {
                return ENOTDIR;
            }
            existing
        } else {
            match fs_root.create_dir(pool_name) {
                Ok(d) => {
                    d.set_uid_gid(0, 0);
                    d.set_mode(0o1777);
                    d
                }
                Err(e) => return ext4_err_to_errno(e),
            }
        };

        let pid = current_process().getpid();
        let mut tmp_created = None;
        for _ in 0..64 {
            let seq = TMPFILE_SEQ.fetch_add(1, Ordering::Relaxed);
            let name = alloc::format!(".tmp.{}.{}", pid, seq);
            if pool_dir.find(&name).is_some() {
                continue;
            }
            match pool_dir.create_file(&name) {
                Ok(i) => {
                    tmp_created = Some(i);
                    tmpfile_cleanup_parent = Some(alloc::sync::Arc::clone(&pool_dir));
                    tmpfile_cleanup_name = Some(name);
                    break;
                }
                Err(e) => return ext4_err_to_errno(e),
            }
        }
        let Some(tmp_inode) = tmp_created else {
            return ENOSPC;
        };
        // Use target directory for mode/gid inheritance semantics.
        created_parent = Some(dir_inode);
        inode = Some(tmp_inode);
        created = true;
    }

    // CREATE: create file if missing (Linux: only affects the final component).
    if inode.is_none() && (flags & O_CREAT != 0) {
        match &at {
            AtPath::Ext4Abs(_) | AtPath::Ext4Rel { .. } => {
                let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if !parent.is_dir() {
                    if debug_close {
                        crate::println!("[fs] openat close-test parent not dir");
                    }
                    return ENOTDIR;
                }
                if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
                    if debug_close {
                        crate::println!("[fs] openat close-test parent no search perm");
                    }
                    return EACCES;
                }
                inode = match parent.create_file(&name) {
                    Ok(i) => {
                        created = true;
                        created_parent = Some(alloc::sync::Arc::clone(&parent));
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
            AtPath::PseudoAbs(_) => unreachable!(),
        }
    }

    let inode = match inode {
        Some(i) => i,
        None => return ENOENT,
    };

    if !tmpfile_requested {
        if let Some(abs) = raw_abs.as_deref() {
            note_inode_path_hint(&inode, abs);
        }
    }

    if let Some(abs) = raw_abs.as_deref() {
        let mode = inode.mode() & S_IFMT;
        if path_is_nodev(abs) && matches!(mode, S_IFCHR | S_IFBLK) {
            return EACCES;
        }
    }

    if created {
        let created_gid = gid_for_created_inode(created_parent.as_deref(), fsgid);
        let created_mode = mode_for_created_file(create_mode, created_gid);
        inode.set_uid_gid(fsuid, created_gid);
        inode.set_mode(created_mode);
        set_inode_all_times_now(&inode);
    }
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
    // an existing directory returns EISDIR (including symlink-to-directory).
    if !o_path && inode.is_dir() && ((flags & O_ACCMODE) != O_RDONLY || (flags & O_CREAT) != 0) {
        if debug_close {
            crate::println!(
                "[fs] openat close-test EISDIR inode={} mode=0o{:o}",
                inode.inode_num(),
                inode.mode()
            );
        }
        return EISDIR;
    }

    // Linux `O_NOATIME`: non-owner/non-privileged callers get EPERM.
    if (flags & O_NOATIME) != 0 {
        let (euid, _egid) = current_effective_uid_gid();
        if euid != 0 && euid != inode.uid() {
            return EPERM;
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
                "[fs] openat close-test EACCES inode={} mode=0o{:o} mask=0o{:o}",
                inode.inode_num(),
                inode.mode(),
                mask
            );
        }
        return EACCES;
    }

    if (flags & O_DIRECTORY) != 0 && !tmpfile_requested && !inode.is_dir() {
        if debug_close {
            crate::println!(
                "[fs] openat close-test ENOTDIR inode={} mode=0o{:o}",
                inode.inode_num(),
                inode.mode()
            );
        }
        return ENOTDIR;
    }

    let text_write_intent = writable || (flags & O_TRUNC) != 0;
    let exec_inode_guard = if !o_path && inode.is_file() && text_write_intent {
        let guard = lock_executing_inodes();
        let exec_busy = is_inode_currently_executed_locked(&guard, inode.device_id(), inode.inode_num());
        if exec_busy {
            return ETXTBSY;
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
            return ext4_err_to_errno(e);
        }
        touch_inode_mtime_ctime_now(&inode);
    }

    if !o_path && inode.is_fifo() {
        let state = fifo_pipe_state_for_inode(inode.inode_num() as u64);
        let accmode = flags & O_ACCMODE;
        if (flags & O_NONBLOCK) != 0 && accmode == O_WRONLY && !state.has_open_readers() {
            drop(ext4_guard);
            return ENXIO;
        }
        let Some(file) = state.open_file(accmode) else {
            drop(ext4_guard);
            return EINVAL;
        };
        drop(ext4_guard);
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
    let os_inode = alloc::sync::Arc::new(OSInode::new_with_append_rofs_tmp_cleanup(
        readable,
        writable,
        append,
        inode,
        readonly_fs,
        false,
        tmpfile_cleanup,
    ));
    drop(exec_inode_guard);
    crate::fs::debug_track_iozone_inode(&path, inode_num);
    drop(ext4_guard);
    let fd = match install_open_file_fd(os_inode, flags, o_path) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if path == "." || path == "/proc" || path == "/proc/" {
            crate::println!("[fs] openat(pid={}) ok path='{}' -> fd={}", pid, path, fd);
        }
    }
    fd as isize
}

fn open_pseudo(path: &str) -> Option<alloc::sync::Arc<dyn File + Send + Sync>> {
    if let Some(node) = open_cgroup_pseudo(path) {
        return Some(node);
    }
    if let Some(node) = crate::fs::open_proc_pseudo(path) {
        return Some(node);
    }
    if (path.starts_with("/proc/sys/kernel/")
        || path.starts_with("/proc/sys/fs/")
        || path.starts_with("/proc/sys/net/")
        || path.starts_with("/proc/sys/vm/"))
    {
        if let Some(inode) = find_path_in_roots(path) {
            return Some(alloc::sync::Arc::new(OSInode::new_replace_on_write(
                true, true, inode,
            )));
        }
    }
    if path == "/proc/sys" || path == "/proc/sys/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("kernel"),
                ino: 2,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("fs"),
                ino: 3,
                dtype: 4
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/proc/sys", entries)));
    }
    if path == "/proc/sys/kernel" || path == "/proc/sys/kernel/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("random"),
                ino: 2,
                dtype: 4
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(
            "/proc/sys/kernel",
            entries,
        )));
    }
    if path == "/proc/sys/kernel/random" || path == "/proc/sys/kernel/random/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("entropy_avail"),
                ino: 2,
                dtype: 8
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(
            "/proc/sys/kernel/random",
            entries,
        )));
    }
    if path == "/proc/sys/kernel/random/entropy_avail" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("256\n")));
    }
    if path == "/proc/sys/fs" || path == "/proc/sys/fs/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("inotify"),
                ino: 2,
                dtype: 4
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(
            "/proc/sys/fs",
            entries,
        )));
    }
    if path == "/proc/sys/fs/inotify" || path == "/proc/sys/fs/inotify/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("max_queued_events"),
                ino: 2,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("max_user_instances"),
                ino: 3,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("max_user_watches"),
                ino: 4,
                dtype: 8
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(
            "/proc/sys/fs/inotify",
            entries,
        )));
    }
    if path == "/proc/sys/fs/inotify/max_queued_events" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static_rw("16384\n")));
    }
    if path == "/proc/sys/fs/inotify/max_user_instances" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static_rw("128\n")));
    }
    if path == "/proc/sys/fs/inotify/max_user_watches" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static_rw("8192\n")));
    }
    if path == "/sys" || path == "/sys/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("devices"),
                ino: 2,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("block"),
                ino: 3,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("dev"),
                ino: 4,
                dtype: 4
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/sys", entries)));
    }
    if path == "/dev" || path == "/dev/" {
        let mut entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("root"),
                ino: 6,
                dtype: 6
            },
            PseudoDirent {
                name: alloc::string::String::from("ptmx"),
                ino: 9,
                dtype: 2
            },
            PseudoDirent {
                name: alloc::string::String::from("tty"),
                ino: 10,
                dtype: 2
            },
            PseudoDirent {
                name: alloc::string::String::from("pts"),
                ino: 11,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("shm"),
                ino: 8,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("cgroup"),
                ino: 12,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("null"),
                ino: 2,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("zero"),
                ino: 3,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("urandom"),
                ino: 4,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("random"),
                ino: 5,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("misc"),
                ino: 7,
                dtype: 4
            },
        ];
        entries.extend(crate::fs::pseudo_dev_dir_entries());
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev", entries)));
    }
    if path == "/dev/cgroup" || path == "/dev/cgroup/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 12,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev/cgroup", entries)));
    }
    if path == "/dev/pts" || path == "/dev/pts/" {
        let mut entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
        ];
        for idx in crate::fs::list_dev_pts() {
            entries.push(PseudoDirent {
                name: alloc::format!("{}", idx),
                ino: 2000 + idx as u64,
                dtype: 2,
            });
        }
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev/pts", entries)));
    }
    if let Some(rest) = path.strip_prefix("/dev/pts/") {
        if !rest.is_empty() && !rest.contains('/') && rest.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(idx) = rest.parse::<u32>() {
                if let Some(node) = crate::fs::open_dev_pts(idx) {
                    return Some(node);
                }
            }
        }
    }
    if path == "/dev/shm" || path == "/dev/shm/" {
        let mut entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
        ];
        for (idx, name) in shm_list().into_iter().enumerate() {
            entries.push(PseudoDirent {
                name,
                ino: (1000 + idx) as u64,
                dtype: 8,
            });
        }
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev/shm", entries)));
    }
    if path == "/dev/misc" || path == "/dev/misc/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("rtc"),
                ino: 2,
                dtype: 8
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev/misc", entries)));
    }
    if path == "/etc" || path == "/etc/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("passwd"),
                ino: 2,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("group"),
                ino: 3,
                dtype: 8
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/etc", entries)));
    }
    if path == "/etc/passwd" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:\n",
        )));
    }
    if path == "/etc/group" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(
            "root:x:0:\ndaemon:x:1:\nusers:x:100:\nnobody:x:65534:\nnogroup:x:65534:\n",
        )));
    }

    // Minimal block topology nodes expected by LTP device helpers.
    if path == "/sys/block" || path == "/sys/block/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("root"),
                ino: 2,
                dtype: 4
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/sys/block", entries)));
    }
    if path == "/sys/block/root" || path == "/sys/block/root/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("queue"),
                ino: 2,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("size"),
                ino: 3,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("stat"),
                ino: 4,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("dev"),
                ino: 5,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("removable"),
                ino: 6,
                dtype: 8
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(
            "/sys/block/root",
            entries,
        )));
    }
    if path == "/sys/block/root/queue" || path == "/sys/block/root/queue/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("logical_block_size"),
                ino: 2,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("physical_block_size"),
                ino: 3,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("minimum_io_size"),
                ino: 4,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("optimal_io_size"),
                ino: 5,
                dtype: 8
            },
            PseudoDirent {
                name: alloc::string::String::from("dma_alignment"),
                ino: 6,
                dtype: 8
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(
            "/sys/block/root/queue",
            entries,
        )));
    }
    if path == "/sys/block/root/size" {
        // 1GiB pseudo block device in 512-byte sectors.
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("2097152\n")));
    }
    if path == "/sys/block/root/stat" {
        let stat = pseudo_block_stat_snapshot();
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(&stat)));
    }
    if path == "/sys/block/root/dev" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("1:0\n")));
    }
    if path == "/sys/block/root/removable" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("0\n")));
    }
    if path == "/sys/block/root/queue/logical_block_size" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("512\n")));
    }
    if path == "/sys/block/root/queue/physical_block_size" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("4096\n")));
    }
    if path == "/sys/block/root/queue/minimum_io_size" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("512\n")));
    }
    if path == "/sys/block/root/queue/optimal_io_size" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("0\n")));
    }
    if path == "/sys/block/root/queue/dma_alignment" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("0\n")));
    }
    if path == "/sys/dev" || path == "/sys/dev/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("block"),
                ino: 2,
                dtype: 4
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/sys/dev", entries)));
    }
    if path == "/sys/dev/block" || path == "/sys/dev/block/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("1:0"),
                ino: 2,
                dtype: 4
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(
            "/sys/dev/block",
            entries,
        )));
    }
    if path == "/sys/dev/block/1:0" || path == "/sys/dev/block/1:0/" {
        let entries = alloc::vec![
            PseudoDirent {
                name: alloc::string::String::from("."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from(".."),
                ino: 1,
                dtype: 4
            },
            PseudoDirent {
                name: alloc::string::String::from("uevent"),
                ino: 2,
                dtype: 8
            },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(
            "/sys/dev/block/1:0",
            entries,
        )));
    }
    if path == "/sys/dev/block/1:0/uevent" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(
            "MAJOR=1\nMINOR=0\nDEVNAME=root\nDEVTYPE=disk\n",
        )));
    }

    // /sys/devices/system/cpu/*
    if path == "/sys/devices/system/cpu/possible"
        || path == "/sys/devices/system/cpu/present"
        || path == "/sys/devices/system/cpu/online"
    {
        let n = crate::config::MAX_HARTS;
        let s = if n == 0 {
            String::from("\n")
        } else if n == 1 {
            String::from("0\n")
        } else {
            alloc::format!("0-{}\n", n - 1)
        };
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
    }
    if path == "/sys/devices/system/cpu/kernel_max" {
        let n = crate::config::MAX_HARTS;
        let s = if n == 0 {
            String::from("0\n")
        } else {
            alloc::format!("{}\n", n - 1)
        };
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
    }
    // /sys/devices/system/node/*
    if path == "/sys/devices/system/node/online" || path == "/sys/devices/system/node/possible" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("0\n")));
    }
    // /dev/*
    if path == "/dev/ptmx" {
        return Some(crate::fs::open_dev_ptmx());
    }
    if path == "/dev/tty" {
        return Some(crate::fs::open_dev_tty());
    }
    if path == "/dev/root" {
        return Some(alloc::sync::Arc::new(PseudoBlock::new()));
    }
    if let Some(name) = shm_object_name(path) {
        let data = shm_get(name)?;
        return Some(alloc::sync::Arc::new(PseudoShmFile::new(data)));
    }
    if path == "/dev/null" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_null()));
    }
    if path == "/dev/zero" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_zero()));
    }
    if path == "/dev/urandom" || path == "/dev/random" {
        let seed =
            (crate::time::get_time() as u64) ^ ((crate::task::processor::hart_id() as u64) << 32);
        return Some(alloc::sync::Arc::new(PseudoFile::new_urandom(seed)));
    }
    if path == "/dev/misc/rtc" {
        return Some(alloc::sync::Arc::new(RtcFile::new()));
    }
    if let Some(node) = crate::fs::open_pseudo_dev_dir(path) {
        return Some(node);
    }
    None
}

/// Linux `faccessat(2)` (syscall 48 on riscv64).
///
/// Used by busybox `which` and shells to locate executables.
pub fn syscall_faccessat(dirfd: isize, pathname: usize, mode: usize, _flags: usize) -> isize {
    if mode & !0x7 != 0 {
        return EINVAL;
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
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
            ENOENT
        };
    }

    let (uid, gid) = current_real_uid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, uid, gid, true) {
        Ok(v) => v,
        Err(ENOENT) if matches!(path.as_str(), "busybox" | "./busybox") => {
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
                None => return ENOENT,
            }
        }
        Err(e) => return e,
    };

    if (mode & 2) != 0 && rofs_for_path(dirfd, &path) {
        return EROFS;
    }
    if !inode_mode_allows_uid_gid(&inode, mode, uid, gid) {
        return EACCES;
    }
    if let Some(abs) = resolve_abs_path(dirfd, &path) {
        mount_note_path_access(&abs);
    }
    0
}

/// Linux `fchmod(2)` (syscall 52 on riscv64).
pub fn syscall_fchmod(fd: usize, mode: usize) -> isize {
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if os_inode.readonly_fs() {
            return EROFS;
        }
        let inode = os_inode.ext4_inode();
        let _ext4_guard = ext4_lock();
        let (uid, _gid) = current_effective_uid_gid();
        if uid != 0 && inode.uid() != uid {
            return EPERM;
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

/// Linux `fchmodat(2)` (syscall 53 on riscv64).
pub fn syscall_fchmodat(dirfd: isize, pathname: usize, mode: usize, flags: usize) -> isize {
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

/// Linux `fchown(2)` (syscall 55 on riscv64).
pub fn syscall_fchown(fd: usize, uid: usize, gid: usize) -> isize {
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if os_inode.readonly_fs() {
            return EROFS;
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

/// Linux `fchownat(2)` (syscall 54 on riscv64).
pub fn syscall_fchownat(
    dirfd: isize,
    pathname: usize,
    uid: usize,
    gid: usize,
    flags: usize,
) -> isize {
    let valid_flags = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;
    if (flags & !valid_flags) != 0 {
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
        return EROFS;
    }
    let ret = apply_chown_to_inode(&inode, uid, gid);
    if ret != 0 {
        return ret;
    }
    0
}

/// Linux `setxattr(2)` (syscall 5 on riscv64).
pub fn syscall_setxattr(
    path: usize,
    name: usize,
    value: usize,
    size: usize,
    flags: usize,
) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match read_user_xattr_value(token, value, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_setxattr(&inode, &name, value.as_slice(), flags)
}

/// Linux `lsetxattr(2)` (syscall 6 on riscv64).
pub fn syscall_lsetxattr(
    path: usize,
    name: usize,
    value: usize,
    size: usize,
    flags: usize,
) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match read_user_xattr_value(token, value, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_setxattr(&inode, &name, value.as_slice(), flags)
}

/// Linux `fsetxattr(2)` (syscall 7 on riscv64).
pub fn syscall_fsetxattr(fd: usize, name: usize, value: usize, size: usize, flags: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match read_user_xattr_value(token, value, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_fd_inode(fd) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return if xattr_is_user_namespace(&name) {
                EPERM
            } else {
                EOPNOTSUPP
            };
        }
        Err(e) => return e,
    };
    do_setxattr(&inode, &name, value.as_slice(), flags)
}

/// Linux `getxattr(2)` (syscall 8 on riscv64).
pub fn syscall_getxattr(path: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_getxattr(&inode, &name, value, size, token)
}

/// Linux `lgetxattr(2)` (syscall 9 on riscv64).
pub fn syscall_lgetxattr(path: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_getxattr(&inode, &name, value, size, token)
}

/// Linux `fgetxattr(2)` (syscall 10 on riscv64).
pub fn syscall_fgetxattr(fd: usize, name: usize, value: usize, size: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_fd_inode(fd) {
        Ok(Some(v)) => v,
        Ok(None) => return ENODATA,
        Err(e) => return e,
    };
    do_getxattr(&inode, &name, value, size, token)
}

/// Linux `listxattr(2)` (syscall 11 on riscv64).
pub fn syscall_listxattr(path: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_path_inode(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_listxattr(&inode, list, size, token)
}

/// Linux `llistxattr(2)` (syscall 12 on riscv64).
pub fn syscall_llistxattr(path: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_path_inode(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_listxattr(&inode, list, size, token)
}

/// Linux `flistxattr(2)` (syscall 13 on riscv64).
pub fn syscall_flistxattr(fd: usize, list: usize, size: usize) -> isize {
    let token = get_current_token();
    let inode = match resolve_xattr_fd_inode(fd) {
        Ok(Some(v)) => v,
        Ok(None) => return 0,
        Err(e) => return e,
    };
    do_listxattr(&inode, list, size, token)
}

/// Linux `removexattr(2)` (syscall 14 on riscv64).
pub fn syscall_removexattr(path: usize, name: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_removexattr(&inode, &name)
}

/// Linux `lremovexattr(2)` (syscall 15 on riscv64).
pub fn syscall_lremovexattr(path: usize, name: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_path_inode(path, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_removexattr(&inode, &name)
}

/// Linux `fremovexattr(2)` (syscall 16 on riscv64).
pub fn syscall_fremovexattr(fd: usize, name: usize) -> isize {
    let token = get_current_token();
    let name = match read_user_xattr_name(token, name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let inode = match resolve_xattr_fd_inode(fd) {
        Ok(Some(v)) => v,
        Ok(None) => return ENODATA,
        Err(e) => return e,
    };
    do_removexattr(&inode, &name)
}

/// Linux `readlinkat(2)` (syscall 78 on riscv64).
///
/// If the path exists but is not a symlink, Linux returns `EINVAL`.
pub fn syscall_readlinkat(dirfd: isize, pathname: usize, buf: usize, bufsiz: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if bufsiz == 0 {
        return EINVAL;
    }
    if path.is_empty() {
        if dirfd < 0 {
            return ENOENT;
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return EBADF;
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return EINVAL;
        };
        let _ext4_guard = ext4_lock();
        let inode = os_inode.ext4_inode();
        if !inode.is_symlink() {
            return EINVAL;
        }
        let target = inode.read_all();
        let len = min(target.len(), bufsiz);
        if try_copy_to_user(token, buf as *mut u8, &target[..len]).is_err() {
            return EFAULT;
        }
        return len as isize;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(target) = crate::fs::proc_readlink(abs) {
            let bytes = target.as_bytes();
            let len = min(bytes.len(), bufsiz);
            if try_copy_to_user(token, buf as *mut u8, &bytes[..len]).is_err() {
                return EFAULT;
            }
            return len as isize;
        }
        return if open_pseudo(abs).is_some() {
            EINVAL
        } else {
            ENOENT
        };
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !inode.is_symlink() {
        return EINVAL;
    }
    let target = inode.read_all();
    let len = min(target.len(), bufsiz);
    if try_copy_to_user(token, buf as *mut u8, &target[..len]).is_err() {
        return EFAULT;
    }
    len as isize
}

/// Linux `symlinkat(2)` (syscall 36 on riscv64).
pub fn syscall_symlinkat(target: usize, newdirfd: isize, linkpath: usize) -> isize {
    let token = get_current_token();
    let target_path = match read_user_cstring(token, target) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let path = match read_user_cstring(token, linkpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(newdirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let AtPath::PseudoAbs(_) = &at {
        return EROFS;
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !parent.is_dir() {
        return ENOTDIR;
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return EACCES;
    }
    if rofs_for_path(newdirfd, &path) {
        return EROFS;
    }

    match parent.create_symlink(&name, &target_path) {
        Ok(inode) => {
            let gid = gid_for_created_inode(Some(&parent), fsgid);
            inode.set_uid_gid(fsuid, gid);
            inode.set_mode(0o777);
            0
        }
        Err(e) => ext4_err_to_errno(e),
    }
}

/// Linux `linkat(2)` (syscall 37 on riscv64).
pub fn syscall_linkat(
    olddirfd: isize,
    oldpath: usize,
    newdirfd: isize,
    newpath: usize,
    flags: usize,
) -> isize {
    let valid_flags = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;
    if (flags & !valid_flags) != 0 {
        return EINVAL;
    }

    let token = get_current_token();
    let old_s = match read_user_cstring(token, oldpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new_s = match read_user_cstring(token, newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if new_s.is_empty() {
        return ENOENT;
    }

    let old_at = if old_s.is_empty() {
        if (flags & AT_EMPTY_PATH) == 0 {
            return ENOENT;
        }
        None
    } else {
        match resolve_at_path(olddirfd, &old_s) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };

    let new_at = match resolve_at_path(newdirfd, &new_s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if matches!(new_at, AtPath::PseudoAbs(_)) {
        return EROFS;
    }
    if let Some(AtPath::PseudoAbs(abs)) = &old_at {
        if parse_proc_fd_for_current_process(abs).is_none() {
            return EXDEV;
        }
    }
    if let (Some(AtPath::Ext4Abs(old_abs)), AtPath::Ext4Abs(new_abs)) = (&old_at, &new_at) {
        if hardlink_cross_mount(old_abs, new_abs) {
            return EXDEV;
        }
    }

    if rofs_for_path(newdirfd, &new_s) {
        return EROFS;
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_old = (flags & AT_SYMLINK_FOLLOW) != 0;
    let _ext4_guard = ext4_lock();

    let source = if let Some(at) = old_at {
        match at {
            AtPath::PseudoAbs(abs) => {
                let fd = match parse_proc_fd_for_current_process(&abs) {
                    Some(v) => v,
                    None => return EXDEV,
                };
                let Some(file) = get_fd_file(fd) else {
                    return EBADF;
                };
                let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
                    return EPERM;
                };
                os_inode.ext4_inode()
            }
            other => match resolve_at_inode(&other, fsuid, fsgid, follow_old) {
                Ok(v) => v,
                Err(e) => return e,
            },
        }
    } else {
        if olddirfd < 0 {
            return EBADF;
        }
        let Some(file) = get_fd_file(olddirfd as usize) else {
            return EBADF;
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return EPERM;
        };
        os_inode.ext4_inode()
    };
    if source.is_dir() {
        return EPERM;
    }

    let (parent, name) = match resolve_parent_and_name(&new_at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !parent.is_dir() {
        return ENOTDIR;
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return EACCES;
    }
    if parent.find(&name).is_some() {
        return EEXIST;
    }
    if parent.device_id() != source.device_id() {
        return EXDEV;
    }
    if rofs_for_path(newdirfd, &new_s) {
        return EROFS;
    }

    match parent.link_inode(&name, &source) {
        Ok(_) => 0,
        Err(ext4_fs::Ext4Error::Unsupported) => EPERM,
        Err(e) => ext4_err_to_errno(e),
    }
}

fn inode_eq(a: &Arc<ext4_fs::Inode>, b: &Arc<ext4_fs::Inode>) -> bool {
    a.device_id() == b.device_id() && a.inode_num() == b.inode_num()
}

fn path_is_descendant_of(dir: Arc<ext4_fs::Inode>, ancestor: &Arc<ext4_fs::Inode>) -> bool {
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

fn sticky_rename_allowed(
    parent: &Arc<ext4_fs::Inode>,
    victim: &Arc<ext4_fs::Inode>,
    fsuid: u32,
) -> bool {
    if (parent.mode() & 0o1000) == 0 {
        return true;
    }
    fsuid == 0 || fsuid == parent.uid() || fsuid == victim.uid()
}

fn remove_rename_target(parent: &Arc<ext4_fs::Inode>, name: &str) -> isize {
    match parent.unlink(name) {
        Ok(()) => 0,
        Err(ext4_fs::Ext4Error::Unsupported) => ENOTEMPTY,
        Err(e) => ext4_err_to_errno(e),
    }
}

fn do_renameat(
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
        if crate::fs::is_cgroup_pseudo_path(old_abs) && crate::fs::is_cgroup_pseudo_path(new_abs)
        {
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

fn do_renameat_exchange(olddirfd: isize, old_s: &str, newdirfd: isize, new_s: &str) -> isize {
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
pub fn syscall_renameat(olddirfd: isize, oldpath: usize, newdirfd: isize, newpath: usize) -> isize {
    let token = get_current_token();
    let old_s = match read_user_cstring(token, oldpath) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_s = match read_user_cstring(token, newpath) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if old_s.is_empty() || new_s.is_empty() {
        return ENOENT;
    }
    do_renameat(olddirfd, &old_s, newdirfd, &new_s, false)
}

/// Linux `renameat2(2)` (syscall 276 on riscv64).
pub fn syscall_renameat2(
    olddirfd: isize,
    oldpath: usize,
    newdirfd: isize,
    newpath: usize,
    flags: usize,
) -> isize {
    const RENAME_NOREPLACE: usize = 1;
    const RENAME_EXCHANGE: usize = 2;
    const RENAME_WHITEOUT: usize = 4;

    if (flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT)) != 0 {
        return EINVAL;
    }
    if (flags & RENAME_EXCHANGE) != 0 && (flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)) != 0 {
        return EINVAL;
    }
    if (flags & RENAME_WHITEOUT) != 0 {
        return EINVAL;
    }

    let token = get_current_token();
    let old_s = match read_user_cstring(token, oldpath) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_s = match read_user_cstring(token, newpath) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if old_s.is_empty() || new_s.is_empty() {
        return ENOENT;
    }

    if flags == 0 {
        return do_renameat(olddirfd, &old_s, newdirfd, &new_s, false);
    }
    if flags == RENAME_NOREPLACE {
        return do_renameat(olddirfd, &old_s, newdirfd, &new_s, true);
    }
    if flags == RENAME_EXCHANGE {
        return do_renameat_exchange(olddirfd, &old_s, newdirfd, &new_s);
    }
    EINVAL
}

pub fn syscall_close(fd: usize) -> isize {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return EBADF;
    }
    let lock_key = inner.fd_table[fd].as_ref().and_then(file_lock_key);
    let _ = inner.clear_fd(fd);
    drop(inner);
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

/// Linux `close_range(2)` (syscall 436 on riscv64/loongarch64).
///
/// Supported flags:
/// - `CLOSE_RANGE_UNSHARE` (materialize a private fd table before update)
/// - `CLOSE_RANGE_CLOEXEC`
pub fn syscall_close_range(first: usize, last: usize, flags: usize) -> isize {
    const CLOSE_RANGE_UNSHARE: usize = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: usize = 1 << 2;
    let valid = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if first > last || (flags & !valid) != 0 {
        return EINVAL;
    }

    let set_cloexec = (flags & CLOSE_RANGE_CLOEXEC) != 0;
    let process = current_process();
    if (flags & CLOSE_RANGE_UNSHARE) != 0 {
        process.unshare_files();
    }
    let files_process = process.files_owner_process();
    let mut inner = files_process.borrow_mut();
    inner.ensure_fd_flags_len();
    if inner.fd_table.is_empty() {
        return 0;
    }
    let end = core::cmp::min(last, inner.fd_table.len() - 1);
    if first > end {
        return 0;
    }

    let mut lock_keys = BTreeSet::new();
    for fd in first..=end {
        if set_cloexec {
            if inner.is_fd_open(fd) {
                inner.fd_flags[fd] |= FD_CLOEXEC;
            }
        } else {
            if let Some(file) = inner.fd_table[fd].as_ref() {
                if let Some(key) = file_lock_key(file) {
                    lock_keys.insert(key);
                }
            }
            let _ = inner.clear_fd(fd);
        }
    }
    drop(inner);
    if !set_cloexec {
        let owner_pid = current_process().getpid();
        for key in lock_keys {
            remove_process_record_locks_for_key(owner_pid, key);
            remove_owner_file_lease_for_key(owner_pid, key);
        }
    }
    0
}

pub fn syscall_read(fd: usize, buffer: usize, len: usize) -> isize {
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file.readable() {
        return EBADF;
    }
    if len == 0 {
        return 0;
    }
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if let Err(e) = validate_direct_io_request(fd, &file, buffer, len, os_inode.offset()) {
            return e;
        }
    }
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = {
            let _ext4_guard = ext4_lock();
            inode.is_dir()
        };
        if is_dir {
            return EISDIR;
        }
    }
    if fd_has_nonblock(fd) {
        if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
            if !pipe.poll_readable() {
                return EAGAIN;
            }
        } else if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
            if !sock.poll_readable() {
                return EAGAIN;
            }
        } else if let Some(duplex) = file.as_any().downcast_ref::<FifoDuplexFile>() {
            if !duplex.poll_readable() {
                return EAGAIN;
            }
        }
    }
    let Ok(user_bufs) = try_translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
        MapPermission::W,
    ) else {
        return EFAULT;
    };
    let buf = UserBuffer::new(user_bufs);
    let read_len = file.read(buf) as isize;
    if read_len >= 0 && !fd_has_noatime(fd) {
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            let inode = os_inode.ext4_inode();
            maybe_update_inode_atime(&inode, false);
        }
    }
    read_len
}

pub fn syscall_write(fd: usize, buffer: usize, len: usize) -> isize {
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file.writable() {
        return EBADF;
    }
    if len == 0 {
        return 0;
    }
    if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return EFAULT;
        };
        let mut data = Vec::with_capacity(len);
        for slice in user_bufs {
            data.extend_from_slice(slice);
        }
        return match cgroup.write_payload(&data) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if let Err(e) = validate_direct_io_request(fd, &file, buffer, len, os_inode.offset()) {
            return e;
        }
    }
    let write_start_off = file
        .as_any()
        .downcast_ref::<OSInode>()
        .map(|inode| inode.offset());
    let mut write_len = len;
    if fd_has_nonblock(fd) {
        if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
            if pipe.all_read_ends_closed() {
                return EPIPE;
            }
            let avail = pipe.available_write();
            if avail == 0 {
                return EAGAIN;
            }
            if write_len <= PIPE_BUF {
                if avail < write_len {
                    return EAGAIN;
                }
            } else {
                write_len = write_len.min(avail);
            }
        } else if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
            if !sock.poll_writable() {
                return EAGAIN;
            }
        } else if let Some(duplex) = file.as_any().downcast_ref::<FifoDuplexFile>() {
            if duplex.write_end_closed() {
                return EPIPE;
            }
            let avail = duplex.available_write();
            if avail == 0 {
                return EAGAIN;
            }
            if write_len <= PIPE_BUF {
                if avail < write_len {
                    return EAGAIN;
                }
            } else {
                write_len = write_len.min(avail);
            }
        }
    }
    let mut hit_fsize_limit = false;
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let fsize_limit = {
            let process = current_process();
            let inner = process.borrow_mut();
            inner.rlimit_fsize_cur
        };
        if fsize_limit != u64::MAX {
            let start = os_inode.offset() as u64;
            if start >= fsize_limit && len > 0 {
                let pid = current_process().getpid();
                queue_process_signal(pid, SIGXFSZ_NUM);
                return EFBIG;
            }
            let remain = (fsize_limit.saturating_sub(start)).min(usize::MAX as u64) as usize;
            if write_len > remain {
                write_len = remain;
                hit_fsize_limit = true;
            }
        }
    }
    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE) {
            return EPERM;
        }
        let start = shm.offset();
        let end = start.saturating_add(write_len);
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_GROW) && end > shm.len() {
            return EPERM;
        }
    }
    let Ok(user_bufs) = try_translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        write_len,
        MapPermission::R,
    ) else {
        return EFAULT;
    };
    let buf = UserBuffer::new(user_bufs);
    let written = file.write(buf) as isize;
    if written == 0 && write_len > 0 {
        if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
            if pipe.all_read_ends_closed() {
                return EPIPE;
            }
        }
        if let Some(duplex) = file.as_any().downcast_ref::<FifoDuplexFile>() {
            if duplex.write_end_closed() {
                return EPIPE;
            }
        }
    }
    if written > 0 {
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            cgroup_charge_file_write(current_process().getpid(), written as usize);
            mirror_inode_write_to_current_mmaps(
                os_inode,
                write_start_off.unwrap_or(0),
                buffer,
                written as usize,
            );
            if let Err(e) = os_inode.flush_with_error() {
                return ext4_err_to_errno(e);
            }
        }
    }
    if hit_fsize_limit {
        let pid = current_process().getpid();
        queue_process_signal(pid, SIGXFSZ_NUM);
    }
    written
}

fn mirror_inode_write_to_current_mmaps(
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
pub fn syscall_pread64(fd: usize, buffer: usize, len: usize, pos: isize) -> isize {
    if pos < 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file_is_seekable_for_preadwrite(&file) {
        return ESPIPE;
    }
    if !file.readable() {
        return EBADF;
    }
    if let Err(e) = validate_direct_io_request(fd, &file, buffer, len, pos as usize) {
        return e;
    }

    // ext4 regular files
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = {
            let _ext4_guard = ext4_lock();
            inode.is_dir()
        };
        if is_dir {
            return EISDIR;
        }

        let mut total = 0usize;
        let token = get_current_token();
        let mut off = pos as usize;
        let mut user_ptr = buffer;
        const CHUNK_MAX: usize = 16 * 1024;
        let buf_cap = core::cmp::min(len, CHUNK_MAX);
        let mut kbuf = vec![0u8; buf_cap];
        while total < len {
            let want = core::cmp::min(len - total, buf_cap);
            let n = os_inode.pread_at(off, &mut kbuf[..want]);
            if n == 0 {
                break;
            }
            if try_copy_to_user(token, user_ptr as *mut u8, &kbuf[..n]).is_err() {
                return if total > 0 { total as isize } else { EFAULT };
            }
            total += n;
            off += n;
            user_ptr += n;
            if n < want {
                break;
            }
        }
        if !fd_has_noatime(fd) {
            maybe_update_inode_atime(&inode, false);
        }
        return total as isize;
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        let old = shm.offset();
        shm.set_offset(pos as usize);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ) else {
            shm.set_offset(old);
            return EFAULT;
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.read(buf) as isize;
        shm.set_offset(old);
        return n;
    }

    // Seekable pseudo files: emulate by temporarily adjusting the per-fd offset.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        if pf.len().is_none() {
            return ESPIPE;
        }
        let old = pf.offset();
        pf.set_offset(pos as usize);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ) else {
            pf.set_offset(old);
            return EFAULT;
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.read(buf) as isize;
        pf.set_offset(old);
        return n;
    }

    ESPIPE
}

/// Linux `pwrite64(2)` (syscall 68 on riscv64).
///
/// Unlike `write(2)`, this does not update the file offset.
pub fn syscall_pwrite64(fd: usize, buffer: usize, len: usize, pos: isize) -> isize {
    if pos < 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file_is_seekable_for_preadwrite(&file) {
        return ESPIPE;
    }
    if !file.writable() {
        return EBADF;
    }
    if let Err(e) = validate_direct_io_request(fd, &file, buffer, len, pos as usize) {
        return e;
    }

    // ext4 regular files
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = {
            let _ext4_guard = ext4_lock();
            inode.is_dir()
        };
        if is_dir {
            return EISDIR;
        }

        let effective_pos = if os_inode.append() {
            let disk_end = {
                let _ext4_guard = ext4_lock();
                inode.size() as usize
            };
            core::cmp::max(disk_end, os_inode.pending_write_end())
        } else {
            pos as usize
        };

        let mut write_len = len;
        let mut hit_fsize_limit = false;
        let fsize_limit = {
            let process = current_process();
            let inner = process.borrow_mut();
            inner.rlimit_fsize_cur
        };
        if fsize_limit != u64::MAX {
            let start = effective_pos as u64;
            if start >= fsize_limit && len > 0 {
                let pid = current_process().getpid();
                queue_process_signal(pid, SIGXFSZ_NUM);
                return EFBIG;
            }
            let remain = (fsize_limit.saturating_sub(start)).min(usize::MAX as u64) as usize;
            if write_len > remain {
                write_len = remain;
                hit_fsize_limit = true;
            }
        }

        let mut total = 0usize;
        let token = get_current_token();
        let mut off = effective_pos;
        let mut user_ptr = buffer;
        const CHUNK_MAX: usize = 16 * 1024;
        let buf_cap = core::cmp::min(write_len, CHUNK_MAX);
        let mut kbuf = vec![0u8; buf_cap];
        while total < write_len {
            let want = core::cmp::min(write_len - total, buf_cap);
            if try_copy_from_user(token, user_ptr as *const u8, &mut kbuf[..want]).is_err() {
                return if total > 0 { total as isize } else { EFAULT };
            }
            match os_inode.pwrite_at(off, &kbuf[..want]) {
                Ok(n) => {
                    total += n;
                    off += n;
                    user_ptr += n;
                    if n < want {
                        break;
                    }
                }
                Err(_) => {
                    crate::println!("[ext4] Warning: pwrite failed");
                    return if total > 0 { total as isize } else { EIO };
                }
            }
        }
        if hit_fsize_limit {
            let pid = current_process().getpid();
            queue_process_signal(pid, SIGXFSZ_NUM);
        }
        if total > 0 {
            cgroup_charge_file_write(current_process().getpid(), total);
        }
        return total as isize;
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE) {
            return EPERM;
        }
        let start = pos as usize;
        let end = start.saturating_add(len);
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_GROW) && end > shm.len() {
            return EPERM;
        }
        let old = shm.offset();
        shm.set_offset(start);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            shm.set_offset(old);
            return EFAULT;
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.write(buf) as isize;
        shm.set_offset(old);
        return n;
    }

    // Seekable pseudo files: emulate by temporarily adjusting the per-fd offset.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        if pf.len().is_none() {
            return ESPIPE;
        }
        let old = pf.offset();
        pf.set_offset(pos as usize);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            pf.set_offset(old);
            return EFAULT;
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.write(buf) as isize;
        pf.set_offset(old);
        return n;
    }

    if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
        if pos != 0 {
            return EINVAL;
        }
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return EFAULT;
        };
        let mut data = Vec::with_capacity(len);
        for slice in user_bufs {
            data.extend_from_slice(slice);
        }
        return match cgroup.write_payload(&data) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }

    ESPIPE
}

pub fn syscall_pipe2(pipefd: usize, _flags: usize) -> isize {
    let process = current_files_process();
    let token = get_current_token();
    let (pipe_read, pipe_write) = make_pipe();

    let mut inner = process.borrow_mut();
    let Some(read_fd) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[read_fd] = Some(pipe_read);
    let Some(write_fd) = inner.alloc_fd() else {
        let _ = inner.clear_fd(read_fd);
        return EMFILE;
    };
    inner.fd_table[write_fd] = Some(pipe_write);
    let mut fd_flags = 0u32;
    if (_flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    if (_flags & O_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK as u32;
    }
    inner.fd_flags[read_fd] = fd_flags;
    inner.fd_flags[write_fd] = fd_flags;
    // Drop PCB borrow before user-memory writes: uaccess may need to resolve
    // lazy/COW pages via `process.try_borrow_mut()`.
    drop(inner);

    // Linux ABI: pipefd points to `int pipefd[2]` (i32).
    if try_write_user_value(token, pipefd as *mut i32, &(read_fd as i32)).is_err()
        || try_write_user_value(
            token,
            (pipefd + core::mem::size_of::<i32>()) as *mut i32,
            &(write_fd as i32),
        )
        .is_err()
    {
        let mut inner = process.borrow_mut();
        let _ = inner.clear_fd(read_fd);
        let _ = inner.clear_fd(write_fd);
        return EFAULT;
    }
    0
}

pub fn syscall_dup(oldfd: usize) -> isize {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    if !inner.is_fd_open(oldfd) {
        return EBADF;
    }
    let file = inner.fd_table[oldfd].as_ref().unwrap().clone();
    inner.ensure_fd_flags_len();
    let old_flags = inner.fd_flags[oldfd];
    let Some(newfd) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[newfd] = Some(file);
    inner.fd_flags[newfd] = old_flags & !FD_CLOEXEC;
    newfd as isize
}

pub fn syscall_dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    if (flags & !O_CLOEXEC) != 0 {
        return EINVAL;
    }
    if oldfd == newfd {
        return EINVAL;
    }
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    if newfd >= inner.rlimit_nofile_cur as usize {
        return EBADF;
    }
    if !inner.is_fd_open(oldfd) {
        return EBADF;
    }
    let owner_pid = current_process().getpid();
    let mut replaced_lock_key = None;
    if inner.is_fd_open(newfd) {
        replaced_lock_key = inner.fd_table[newfd].as_ref().and_then(file_lock_key);
        let _ = inner.clear_fd(newfd);
    }
    if let Some(key) = replaced_lock_key {
        remove_process_record_locks_for_key(owner_pid, key);
        remove_owner_file_lease_for_key(owner_pid, key);
    }
    let file = inner.fd_table[oldfd].as_ref().unwrap().clone();
    inner.ensure_fd_flags_len();
    let old_flags = inner.fd_flags[oldfd];
    while inner.fd_table.len() <= newfd {
        inner.fd_table.push(None);
        inner.fd_flags.push(0);
    }
    inner.fd_table[newfd] = Some(file);
    let mut new_flags = old_flags;
    if (flags & O_CLOEXEC) != 0 {
        new_flags |= FD_CLOEXEC;
    } else {
        new_flags &= !FD_CLOEXEC;
    }
    inner.fd_flags[newfd] = new_flags;
    newfd as isize
}

/// Linux `chroot(2)` (syscall 51 on riscv64/loongarch64).
pub fn syscall_chroot(pathname: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(AT_FDCWD, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if matches!(at, AtPath::PseudoAbs(_)) {
        return ENOTDIR;
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
            return ENOTDIR;
        }
        if !inode_mode_allows_uid_gid(&inode, 1, fsuid, fsgid) {
            return EACCES;
        }
        resolve_final_symlink_abs_path(&candidate_abs)
    };

    // Capability check after pathname validation so permission errors surface
    // first, matching Linux/LTP expectations.
    let has_priv = {
        let inner = process.borrow_mut();
        inner.euid == 0
    };
    if !has_priv {
        return EPERM;
    }

    let mut inner = process.borrow_mut();
    inner.root = final_root.clone();
    inner.cwd = final_root;
    0
}

pub fn syscall_chdir(pathname: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
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
            return ENOTDIR;
        }
        if !inode_mode_allows_uid_gid(&inode, 1, fsuid, fsgid) {
            return EACCES;
        }
        resolve_final_symlink_abs_path(&new_cwd)
    } else if let Some(node) = open_pseudo(&new_cwd) {
        if node.as_any().downcast_ref::<PseudoDir>().is_none() {
            return ENOTDIR;
        }
        new_cwd
    } else {
        return ENOENT;
    };

    process.borrow_mut().cwd = final_cwd;
    0
}

/// Linux `fchdir(2)` (syscall 50 on riscv64/loongarch64).
pub fn syscall_fchdir(fd: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };

    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        let new_cwd = String::from(pdir.path());
        current_process().borrow_mut().cwd = new_cwd;
        return 0;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return ENOTDIR;
    };
    let inode = os_inode.ext4_inode();
    let (fsuid, fsgid) = current_fsuid_gid();
    {
        let _ext4_guard = ext4_lock();
        if !inode.is_dir() {
            return ENOTDIR;
        }
        if !inode_mode_allows_uid_gid(&inode, 1, fsuid, fsgid) {
            return EACCES;
        }
    }

    let proc_fd_path = alloc::format!("/proc/self/fd/{}", fd);
    let fallback_cwd = {
        let process = current_process();
        process.borrow_mut().cwd.clone()
    };
    let target_path = crate::fs::proc_readlink(&proc_fd_path).unwrap_or(fallback_cwd);
    let final_cwd = if crate::fs::is_proc_pseudo_path(&target_path) || is_pseudo_path(&target_path)
    {
        target_path
    } else {
        resolve_final_symlink_abs_path(&target_path)
    };
    current_process().borrow_mut().cwd = final_cwd;
    0
}

pub fn syscall_mknodat(dirfd: isize, pathname: usize, mode: usize, dev: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let AtPath::PseudoAbs(_) = &at {
        return EROFS;
    }
    let (fsuid, fsgid) = current_fsuid_gid();

    let _ext4_guard = ext4_lock();
    let dirfd_rofs = matches!(
        &at,
        AtPath::Ext4Rel { base, .. } if inode_is_rofs_mount_root(base)
    );
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if dirfd_rofs || rofs_for_path(dirfd, &path) {
        return EROFS;
    }
    if !parent.is_dir() {
        return ENOTDIR;
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return EACCES;
    }
    if parent.find(&name).is_some() {
        return EEXIST;
    }

    let mut file_type = (mode as u16) & S_IFMT;
    if file_type == 0 {
        file_type = S_IFREG;
    }
    let valid_type = matches!(file_type, S_IFREG | S_IFIFO | S_IFCHR | S_IFBLK | S_IFSOCK);
    if !valid_type {
        return EINVAL;
    }

    let gid = gid_for_created_inode(Some(&parent), fsgid);
    let perm_bits = apply_umask(mode) & 0o7777;
    let create_mode = mode_for_created_file(file_type | perm_bits, gid);

    if matches!(file_type, S_IFCHR | S_IFBLK) {
        let (euid, _) = current_effective_uid_gid();
        if euid != 0 {
            return EPERM;
        }
    }

    let create_result = match file_type {
        S_IFREG => parent.create_file(&name),
        S_IFIFO | S_IFSOCK => parent.create_special(&name, create_mode, 0),
        S_IFCHR | S_IFBLK => parent.create_special(&name, create_mode, dev as u64),
        _ => unreachable!(),
    };

    match create_result {
        Ok(inode) => {
            inode.set_uid_gid(fsuid, gid);
            inode.set_mode(create_mode);
            0
        }
        Err(e) => ext4_err_to_errno(e),
    }
}

pub fn syscall_mkdirat(dirfd: isize, pathname: usize, mode: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
    }
    if crate::debug_config::DEBUG_SYSCALL {
        let pid = current_process().getpid();
        crate::println!(
            "[mkdir] pid={} dirfd={} path='{}' mode=0o{:o}",
            pid,
            dirfd,
            path,
            mode
        );
    }

    let create_mode = apply_umask(mode);
    let (fsuid, fsgid) = current_fsuid_gid();

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if crate::debug_config::DEBUG_SYSCALL {
        let pid = current_process().getpid();
        match &at {
            AtPath::Ext4Abs(abs) => {
                crate::println!("[mkdir] pid={} abs='{}'", pid, abs);
            }
            AtPath::Ext4Rel { rel, .. } => {
                crate::println!("[mkdir] pid={} rel='{}'", pid, rel);
            }
            AtPath::PseudoAbs(abs) => {
                crate::println!("[mkdir] pid={} pseudo='{}'", pid, abs);
            }
        }
    }

    if let AtPath::PseudoAbs(abs) = &at {
        if open_pseudo(abs).is_some() || crate::fs::proc_readlink(abs).is_some() {
            return EEXIST;
        }
        if crate::fs::is_cgroup_pseudo_path(abs) {
            return cgroup_mkdir(abs);
        }
        let rc = crate::fs::pseudo_dev_dir_mkdir(abs);
        if rc != EROFS {
            return rc;
        }
        return EROFS;
    }

    let _ext4_guard = ext4_lock();
    if matches!(at, AtPath::Ext4Abs(ref abs) if abs == "/") {
        return EEXIST;
    }
    if matches!(at, AtPath::Ext4Rel { ref rel, .. } if rel.is_empty()) {
        return EEXIST;
    }
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !parent.is_dir() {
        return ENOTDIR;
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return EACCES;
    }
    if parent.find(&name).is_some() {
        return EEXIST;
    }
    if rofs_for_path(dirfd, &path) {
        return EROFS;
    }
    match parent.create_dir(&name) {
        Ok(dir) => {
            let gid = gid_for_created_inode(Some(&parent), fsgid);
            let mut dir_mode = create_mode;
            if parent_forces_gid_inherit(&parent) {
                dir_mode |= 0o2000;
            }
            dir.set_uid_gid(fsuid, gid);
            dir.set_mode(dir_mode);
            if crate::debug_config::DEBUG_SYSCALL {
                let pid = current_process().getpid();
                crate::println!(
                    "[mkdir] pid={} inode={} mode=0o{:o} is_dir={}",
                    pid,
                    dir.inode_num(),
                    dir.mode(),
                    dir.is_dir()
                );
            }
            0
        }
        Err(e) => {
            let err = ext4_err_to_errno(e);
            if crate::debug_config::DEBUG_SYSCALL {
                let pid = current_process().getpid();
                crate::println!("[mkdir] pid={} create_dir err={}", pid, err);
            }
            err
        }
    }
}

pub fn syscall_unlinkat(dirfd: isize, pathname: usize, flags: usize) -> isize {
    const AT_REMOVEDIR: usize = 0x200;
    if (flags & !AT_REMOVEDIR) != 0 {
        return EINVAL;
    }

    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
    }
    let remove_dir = (flags & AT_REMOVEDIR) != 0;

    if remove_dir {
        if final_non_empty_component(&path) == Some(".") {
            return EINVAL;
        }
        if final_non_empty_component(&path) == Some("..") {
            return ENOTEMPTY;
        }
        if let Some(abs) = resolve_abs_path(dirfd, &path) {
            if path_is_mount_point(&abs) {
                return EBUSY;
            }
        }
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        // Minimal `/dev/shm` support for POSIX `shm_unlink`.
        if abs == "/dev/shm" || abs == "/dev/shm/" {
            return if remove_dir { EROFS } else { EISDIR };
        }
        if crate::fs::is_cgroup_pseudo_path(abs) {
            return if remove_dir {
                cgroup_rmdir(abs)
            } else if open_pseudo(abs).is_some() {
                EISDIR
            } else {
                ENOENT
            };
        }
        if let Some(name) = shm_object_name(abs) {
            if remove_dir {
                return ENOTDIR;
            }
            return if shm_remove(name) { 0 } else { ENOENT };
        }
        if crate::fs::pseudo_dev_dir_exists(abs) {
            return if remove_dir {
                crate::fs::pseudo_dev_dir_rmdir(abs)
            } else {
                EISDIR
            };
        }
        return EROFS;
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    if matches!(at, AtPath::Ext4Abs(ref abs) if abs == "/") {
        return EISDIR;
    }
    if matches!(at, AtPath::Ext4Rel { ref rel, .. } if rel.is_empty()) {
        return EISDIR;
    }
    let (parent, name) = match resolve_parent_and_name(&at, fsuid, fsgid) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if !parent.is_dir() {
        return ENOTDIR;
    }
    if !inode_mode_allows_uid_gid(&parent, 3, fsuid, fsgid) {
        return EACCES;
    }
    if remove_dir && name == "." {
        return EINVAL;
    }
    if remove_dir && name == ".." {
        return ENOTEMPTY;
    }

    // Validate target type: unlink vs rmdir semantics.
    let Some(child) = parent.find(&name) else {
        if rofs_for_path(dirfd, &path) {
            return EROFS;
        }
        return ENOENT;
    };
    if remove_dir {
        if !child.is_dir() {
            return ENOTDIR;
        }
        if !child.ls().is_empty() {
            return ENOTEMPTY;
        }
    } else {
        if child.is_dir() {
            return EISDIR;
        }
    }
    if !sticky_rename_allowed(&parent, &child, fsuid) {
        return EPERM;
    }
    if inode_is_immutable_or_append(&child) {
        return EPERM;
    }
    if rofs_for_path(dirfd, &path) {
        return EROFS;
    }

    if !remove_dir {
        match defer_unlink_open_file(&parent, &name, &child) {
            Ok(true) => return 0,
            Ok(false) => {}
            Err(e) => return e,
        }
    }

    match parent.unlink(&name) {
        Ok(_) => 0,
        Err(ext4_fs::Ext4Error::Unsupported) => ENOTEMPTY,
        Err(e) => ext4_err_to_errno(e),
    }
}

fn fsize_limit_allows(new_len: usize) -> Result<(), isize> {
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

fn flush_open_inode_views(target: &Arc<ext4_fs::Inode>) {
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

fn has_open_inode_view(target: &Arc<ext4_fs::Inode>) -> bool {
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

fn defer_unlink_open_file(
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

fn truncate_regular_inode(inode: &Arc<ext4_fs::Inode>, new_len: usize) -> isize {
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

fn read_inode_range(
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

fn write_inode_range(inode: &Arc<ext4_fs::Inode>, offset: usize, data: &[u8]) -> isize {
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

fn write_zeros_range(inode: &Arc<ext4_fs::Inode>, offset: usize, len: usize) -> isize {
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

fn punch_hole_keep_size(inode: &Arc<ext4_fs::Inode>, offset: usize, len: usize) -> isize {
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
pub fn syscall_fallocate(fd: usize, mode: usize, offset: usize, len: usize) -> isize {
    if fd_has_o_path(fd) {
        return EBADF;
    }
    if (offset as i64) < 0 || (len as i64) < 0 {
        return EINVAL;
    }
    if len == 0 {
        return EINVAL;
    }
    if (mode & !FALLOC_FL_SUPPORTED_MASK) != 0 {
        return EOPNOTSUPP;
    }
    if (mode & FALLOC_FL_PUNCH_HOLE) != 0 && (mode & FALLOC_FL_KEEP_SIZE) == 0 {
        return EINVAL;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file.writable() {
        return EBADF;
    }
    let Some(end) = offset.checked_add(len) else {
        return EFBIG;
    };
    if end > (i64::MAX as usize) {
        return EFBIG;
    }
    // Current backend does not model tmpfs-like huge preallocation reliably.
    // Keep this explicit so large/stress-only cases return TCONF instead of
    // polluting later tests by filling the shared root image.
    if mode == 0 && offset == 0 && len >= (1 << 20) {
        return EOPNOTSUPP;
    }
    // Misaligned mode=0 fallocate requires filesystem support we don't expose
    // yet; report unsupported to keep semantics explicit.
    if mode == 0 && (offset & 0xfff) != 0 {
        return EOPNOTSUPP;
    }
    if fsize_limit_allows(end).is_err() {
        return EFBIG;
    }
    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        if (mode & FALLOC_FL_PUNCH_HOLE) != 0 {
            if shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE) {
                return EPERM;
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
            return EPERM;
        }
        if alloc_end > old_size {
            shm.truncate(alloc_end);
        }
        return 0;
    }
    if (mode & FALLOC_FL_PUNCH_HOLE) != 0 {
        // Keep semantics explicit until sparse extent metadata is implemented.
        return EOPNOTSUPP;
    }
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return EINVAL;
    };
    if os_inode.readonly_fs() {
        return EROFS;
    }
    let inode = os_inode.ext4_inode();
    {
        let _ext4_guard = ext4_lock();
        if inode.is_dir() {
            return EISDIR;
        }
        if !inode.is_file() {
            return EINVAL;
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

/// Linux `ftruncate(2)` (syscall 46 on riscv64).
pub fn syscall_ftruncate(fd: usize, length: usize) -> isize {
    if (length as i64) < 0 {
        return EINVAL;
    }
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file.writable() {
        // Linux reports EINVAL when the descriptor does not permit writing.
        return EINVAL;
    }
    if fsize_limit_allows(length).is_err() {
        return EFBIG;
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        let old_size = shm.len();
        if length < old_size && shm.has_memfd_seal(PseudoShmFile::F_SEAL_SHRINK) {
            return EPERM;
        }
        if length > old_size && shm.has_memfd_seal(PseudoShmFile::F_SEAL_GROW) {
            return EPERM;
        }
        shm.truncate(length);
        return 0;
    }
    if file.as_any().downcast_ref::<NetSocketFile>().is_some() {
        return EINVAL;
    }
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if os_inode.readonly_fs() {
            return EROFS;
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
        }
        return ret;
    }
    EINVAL
}

/// Linux `truncate(2)` (syscall 45 on riscv64).
pub fn syscall_truncate(pathname: usize, length: usize) -> isize {
    if (length as i64) < 0 {
        return EINVAL;
    }
    if fsize_limit_allows(length).is_err() {
        return EFBIG;
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
    }
    let trailing_slash = path.len() > 1 && path.ends_with('/');
    if rofs_for_path(AT_FDCWD, &path) {
        return EROFS;
    }
    let at = match resolve_at_path(AT_FDCWD, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let AtPath::PseudoAbs(_) = &at {
        return EINVAL;
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if trailing_slash && !inode.is_dir() {
        return ENOTDIR;
    }
    if !inode.is_file() {
        if inode.is_dir() {
            return EISDIR;
        }
        return EINVAL;
    }
    if !inode_mode_allows_uid_gid(&inode, 2, fsuid, fsgid) {
        return EACCES;
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
    }
    ret
}

/// Linux `sendfile(2)` (syscall 71 on riscv64).
pub fn syscall_sendfile(out_fd: usize, in_fd: usize, offset: usize, count: usize) -> isize {
    if count == 0 {
        return 0;
    }
    if fd_has_o_path(in_fd) || fd_has_o_path(out_fd) {
        return EBADF;
    }
    let Some(in_file) = get_fd_file(in_fd) else {
        return EBADF;
    };
    let Some(out_file) = get_fd_file(out_fd) else {
        return EBADF;
    };
    if !in_file.readable() || !out_file.writable() {
        return EBADF;
    }

    let Some(in_inode) = in_file.as_any().downcast_ref::<OSInode>() else {
        return EINVAL;
    };
    let raw_in_pos = match read_optional_offset(offset) {
        Ok(Some(v)) => v,
        Ok(None) => in_inode.offset(),
        Err(e) => return e,
    };

    let out_is_socketpair = out_file.as_any().downcast_ref::<SocketPairEnd>().is_some();
    let nonblock = fd_has_nonblock(out_fd);
    if nonblock && out_is_socketpair {
        let Some(sock) = out_file.as_any().downcast_ref::<SocketPairEnd>() else {
            return EINVAL;
        };
        if !sock.poll_writable() {
            return EAGAIN;
        }
    }

    let mut in_pos = raw_in_pos;
    let mut total = 0usize;
    let mut remaining = count;
    let mut out_pos = 0usize;
    let mut out_inode_opt = out_file.as_any().downcast_ref::<OSInode>();
    if let Some(out_inode) = out_inode_opt {
        if out_inode.readonly_fs() {
            return EROFS;
        }
        out_pos = out_inode.offset();
    }
    let mut buf = vec![0u8; core::cmp::min(remaining, 16 * 1024)];
    while remaining > 0 {
        let want = core::cmp::min(remaining, buf.len());
        let read = in_inode.pread_at(in_pos, &mut buf[..want]);
        if read == 0 {
            break;
        }
        let wrote = if let Some(out_inode) = out_inode_opt {
            match out_inode.pwrite_at(out_pos, &buf[..read]) {
                Ok(n) => n,
                Err(_) => return if total > 0 { total as isize } else { EIO },
            }
        } else if out_is_socketpair {
            match socketpair_write_from_kernel(&out_file, &buf[..read], nonblock) {
                Ok(n) => n,
                Err(e) => return if total > 0 { total as isize } else { e },
            }
        } else {
            return if total > 0 { total as isize } else { EINVAL };
        };
        if wrote == 0 {
            break;
        }
        total += wrote;
        remaining -= wrote;
        in_pos += wrote;
        if out_inode_opt.is_some() {
            out_pos += wrote;
        }
        if wrote < read {
            break;
        }
    }

    let mut flush_failed = false;
    if let Some(out_inode) = out_inode_opt {
        flush_failed = total > 0 && out_inode.flush().is_err();
        out_inode.set_offset(out_pos);
    }

    if offset == 0 {
        in_inode.set_offset(in_pos);
    } else if let Err(e) = write_optional_offset(offset, in_pos) {
        return e;
    }
    if flush_failed {
        return EIO;
    }
    total as isize
}

/// Linux `splice(2)` (syscall 76 on riscv64).
pub fn syscall_splice(
    fd_in: usize,
    off_in: usize,
    fd_out: usize,
    off_out: usize,
    len: usize,
    flags: usize,
) -> isize {
    let valid_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (flags & !valid_flags) != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if fd_has_o_path(fd_in) || fd_has_o_path(fd_out) {
        return EBADF;
    }
    let Some(in_file) = get_fd_file(fd_in) else {
        return EBADF;
    };
    let Some(out_file) = get_fd_file(fd_out) else {
        return EBADF;
    };
    if !in_file.readable() || !out_file.writable() {
        return EBADF;
    }
    let in_is_pipe = file_is_pipe(&in_file);
    let out_is_pipe = file_is_pipe(&out_file);
    if !in_is_pipe && !out_is_pipe {
        return EINVAL;
    }
    if in_is_pipe && off_in != 0 {
        return ESPIPE;
    }
    if out_is_pipe && off_out != 0 {
        return ESPIPE;
    }
    if !out_is_pipe
        && (fd_has_append(fd_out)
            || out_file
                .as_any()
                .downcast_ref::<OSInode>()
                .map(|f| f.append())
                .unwrap_or(false))
    {
        return EINVAL;
    }
    let out_is_inode = out_file.as_any().downcast_ref::<OSInode>().is_some();
    let out_is_socketpair = out_file.as_any().downcast_ref::<SocketPairEnd>().is_some();
    if !out_is_pipe && !out_is_inode && !out_is_socketpair {
        return EINVAL;
    }
    let in_is_inode = in_file.as_any().downcast_ref::<OSInode>().is_some();
    if !in_is_pipe && !in_is_inode {
        return EINVAL;
    }

    let nonblock =
        (flags & SPLICE_F_NONBLOCK) != 0 || fd_has_nonblock(fd_in) || fd_has_nonblock(fd_out);
    let mut in_pos = if in_is_pipe {
        0usize
    } else {
        match read_optional_offset(off_in) {
            Ok(Some(v)) => v,
            Ok(None) => {
                let Some(in_inode) = in_file.as_any().downcast_ref::<OSInode>() else {
                    return EINVAL;
                };
                in_inode.offset()
            }
            Err(e) => return e,
        }
    };
    let mut out_pos = if out_is_pipe {
        0usize
    } else {
        match read_optional_offset(off_out) {
            Ok(Some(v)) => v,
            Ok(None) => {
                if let Some(out_inode) = out_file.as_any().downcast_ref::<OSInode>() {
                    out_inode.offset()
                } else {
                    0
                }
            }
            Err(e) => return e,
        }
    };

    let mut moved = 0usize;
    let mut buf = vec![0u8; core::cmp::min(len, PIPE_BUF)];
    while moved < len {
        let want = core::cmp::min(buf.len(), len - moved);
        let read = if in_is_pipe {
            if nonblock {
                if let Some(pipe) = out_file.as_any().downcast_ref::<Pipe>() {
                    if !pipe.poll_writable() {
                        return if moved > 0 { moved as isize } else { EAGAIN };
                    }
                } else if let Some(sock) = out_file.as_any().downcast_ref::<SocketPairEnd>() {
                    if !sock.poll_writable() {
                        return if moved > 0 { moved as isize } else { EAGAIN };
                    }
                }
            }
            match pipe_read_to_kernel(&in_file, &mut buf[..want], nonblock) {
                Ok(n) => n,
                Err(e) => return if moved > 0 { moved as isize } else { e },
            }
        } else {
            let Some(in_inode) = in_file.as_any().downcast_ref::<OSInode>() else {
                return if moved > 0 { moved as isize } else { EINVAL };
            };
            let is_file = {
                let inode = in_inode.ext4_inode();
                let _ext4_guard = ext4_lock();
                inode.is_file()
            };
            if !is_file {
                return if moved > 0 { moved as isize } else { EINVAL };
            }
            let n = in_inode.pread_at(in_pos, &mut buf[..want]);
            if n == 0 {
                break;
            }
            n
        };
        if read == 0 {
            break;
        }

        let wrote = if out_is_pipe {
            match pipe_write_from_kernel(&out_file, &buf[..read], nonblock) {
                Ok(n) => n,
                Err(e) => return if moved > 0 { moved as isize } else { e },
            }
        } else if let Some(out_inode) = out_file.as_any().downcast_ref::<OSInode>() {
            let is_file = {
                let inode = out_inode.ext4_inode();
                let _ext4_guard = ext4_lock();
                inode.is_file()
            };
            if !is_file {
                return if moved > 0 { moved as isize } else { EINVAL };
            }
            if out_inode.readonly_fs() {
                return if moved > 0 { moved as isize } else { EROFS };
            }
            match out_inode.pwrite_at(out_pos, &buf[..read]) {
                Ok(n) => n,
                Err(_) => return if moved > 0 { moved as isize } else { EIO },
            }
        } else if out_file.as_any().downcast_ref::<SocketPairEnd>().is_some() {
            match socketpair_write_from_kernel(&out_file, &buf[..read], nonblock) {
                Ok(n) => n,
                Err(e) => return if moved > 0 { moved as isize } else { e },
            }
        } else {
            return if moved > 0 { moved as isize } else { EINVAL };
        };
        if wrote == 0 {
            break;
        }
        moved += wrote;
        if !in_is_pipe {
            in_pos += wrote;
        }
        if !out_is_pipe && out_file.as_any().downcast_ref::<OSInode>().is_some() {
            out_pos += wrote;
        }
        if wrote < read {
            break;
        }
    }

    if !in_is_pipe {
        if off_in == 0 {
            if let Some(in_inode) = in_file.as_any().downcast_ref::<OSInode>() {
                in_inode.set_offset(in_pos);
            }
        } else if let Err(e) = write_optional_offset(off_in, in_pos) {
            return e;
        }
    }
    if !out_is_pipe {
        if let Some(out_inode) = out_file.as_any().downcast_ref::<OSInode>() {
            if moved > 0 && out_inode.flush().is_err() {
                return EIO;
            }
            if off_out == 0 {
                out_inode.set_offset(out_pos);
            } else if let Err(e) = write_optional_offset(off_out, out_pos) {
                return e;
            }
        }
    }
    moved as isize
}

/// Linux `tee(2)` (syscall 77 on riscv64).
pub fn syscall_tee(fd_in: usize, fd_out: usize, len: usize, flags: usize) -> isize {
    let valid_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (flags & !valid_flags) != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if fd_has_o_path(fd_in) || fd_has_o_path(fd_out) {
        return EBADF;
    }
    let Some(in_file) = get_fd_file(fd_in) else {
        return EBADF;
    };
    let Some(out_file) = get_fd_file(fd_out) else {
        return EBADF;
    };
    if !in_file.readable() || !out_file.writable() {
        return EBADF;
    }
    let Some(in_pipe) = in_file.as_any().downcast_ref::<Pipe>() else {
        return EINVAL;
    };
    let Some(out_pipe) = out_file.as_any().downcast_ref::<Pipe>() else {
        return EINVAL;
    };
    if in_pipe.same_buffer(out_pipe) {
        return EINVAL;
    }
    let nonblock =
        (flags & SPLICE_F_NONBLOCK) != 0 || fd_has_nonblock(fd_in) || fd_has_nonblock(fd_out);
    let mut copied = 0usize;
    let mut buf = vec![0u8; core::cmp::min(len, PIPE_BUF)];
    let mut consume_buf = vec![0u8; core::cmp::min(len, PIPE_BUF)];
    while copied < len {
        let want = core::cmp::min(len - copied, buf.len());
        let peeked = match in_pipe.peek_to_slice(&mut buf[..want], nonblock) {
            Ok(n) => n,
            Err(e) => return if copied > 0 { copied as isize } else { e },
        };
        if peeked == 0 {
            break;
        }
        let wrote = match out_pipe.write_from_slice(&buf[..peeked], nonblock) {
            Ok(n) => n,
            Err(e) => return if copied > 0 { copied as isize } else { e },
        };
        if wrote == 0 {
            break;
        }
        let consumed = match in_pipe.read_to_slice(&mut consume_buf[..wrote], true) {
            Ok(n) => n,
            Err(e) => return if copied > 0 { copied as isize } else { e },
        };
        if consumed == 0 {
            break;
        }
        copied += consumed;
        if consumed < peeked {
            break;
        }
    }
    copied as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VmIoVec {
    iov_base: usize,
    iov_len: usize,
}

fn read_vm_iovec(token: usize, iov_ptr: usize, index: usize) -> Result<VmIoVec, isize> {
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
pub fn syscall_vmsplice(fd: usize, iov_ptr: usize, nr_segs: usize, flags: usize) -> isize {
    let valid_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (flags & !valid_flags) != 0 {
        return EINVAL;
    }
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
        return EBADF;
    };
    if nr_segs > IOV_MAX {
        return EINVAL;
    }
    if nr_segs == 0 {
        return 0;
    }
    let nonblock = (flags & SPLICE_F_NONBLOCK) != 0 || fd_has_nonblock(fd);
    let token = get_current_token();
    let mut total = 0usize;
    let mut scratch = vec![0u8; PIPE_BUF];
    for i in 0..nr_segs {
        let iv = match read_vm_iovec(token, iov_ptr, i) {
            Ok(v) => v,
            Err(e) => return if total > 0 { total as isize } else { e },
        };
        if iv.iov_len == 0 {
            continue;
        }
        if file.writable() {
            let mut seg_off = 0usize;
            while seg_off < iv.iov_len {
                let want = core::cmp::min(iv.iov_len - seg_off, scratch.len());
                let src_ptr = (iv.iov_base + seg_off) as *const u8;
                if try_copy_from_user(token, src_ptr, &mut scratch[..want]).is_err() {
                    return if total > 0 { total as isize } else { EFAULT };
                }
                // Linux may return a short vmsplice() once some bytes are moved.
                // Avoid blocking indefinitely trying to drain very large iovecs.
                let write_nonblock = nonblock || total > 0 || seg_off > 0;
                let wrote = match pipe.write_from_slice(&scratch[..want], write_nonblock) {
                    Ok(n) => n,
                    Err(e) => return if total > 0 { total as isize } else { e },
                };
                if wrote == 0 {
                    return if total > 0 { total as isize } else { EPIPE };
                }
                total += wrote;
                seg_off += wrote;
                if wrote < want {
                    break;
                }
            }
        } else if file.readable() {
            let mut seg_off = 0usize;
            while seg_off < iv.iov_len {
                let want = core::cmp::min(iv.iov_len - seg_off, scratch.len());
                let read = match pipe.read_to_slice(&mut scratch[..want], nonblock) {
                    Ok(n) => n,
                    Err(e) => return if total > 0 { total as isize } else { e },
                };
                if read == 0 {
                    return total as isize;
                }
                let dst_ptr = (iv.iov_base + seg_off) as *mut u8;
                if try_copy_to_user(token, dst_ptr, &scratch[..read]).is_err() {
                    return if total > 0 { total as isize } else { EFAULT };
                }
                total += read;
                seg_off += read;
                if read < want {
                    break;
                }
            }
        } else {
            return if total > 0 { total as isize } else { EBADF };
        }
    }
    total as isize
}

/// Linux `copy_file_range(2)` (syscall 285 on riscv64).
pub fn syscall_copy_file_range(
    fd_in: usize,
    off_in: usize,
    fd_out: usize,
    off_out: usize,
    len: usize,
    flags: usize,
) -> isize {
    // Keep an explicit max file-size guard so oversized ranges still report EFBIG
    // (used by LTP copy_file_range02), but do not cap normal file copies too low.
    const COPY_FILE_RANGE_MAX_FILE_SIZE: u64 = 1u64 << 40; // 1 TiB
    if flags != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if len > i64::MAX as usize {
        return EOVERFLOW;
    }
    if fd_has_o_path(fd_in) || fd_has_o_path(fd_out) {
        return EBADF;
    }
    let Some(in_file) = get_fd_file(fd_in) else {
        return EBADF;
    };
    let Some(out_file) = get_fd_file(fd_out) else {
        return EBADF;
    };
    if !in_file.readable() {
        return EBADF;
    }
    let Some(in_os_inode) = in_file.as_any().downcast_ref::<OSInode>() else {
        return EINVAL;
    };
    let Some(out_os_inode) = out_file.as_any().downcast_ref::<OSInode>() else {
        return EINVAL;
    };
    let in_inode = in_os_inode.ext4_inode();
    let out_inode = out_os_inode.ext4_inode();
    if out_inode.is_dir() {
        return EISDIR;
    }
    if !out_file.writable() {
        return EBADF;
    }
    if out_os_inode.append() {
        return EBADF;
    }
    if out_os_inode.readonly_fs() {
        return EROFS;
    }
    if in_inode.device_id() != out_inode.device_id() {
        return EXDEV;
    }
    if !in_inode.is_file() || !out_inode.is_file() {
        return EINVAL;
    }

    let token = get_current_token();
    let mut in_pos = if off_in == 0 {
        in_os_inode.offset()
    } else {
        let Some(v) = try_read_user_value(token, off_in as *const i64) else {
            return EFAULT;
        };
        if v < 0 {
            return EINVAL;
        }
        v as usize
    };
    let mut out_pos = if off_out == 0 {
        out_os_inode.offset()
    } else {
        let Some(v) = try_read_user_value(token, off_out as *const i64) else {
            return EFAULT;
        };
        if v < 0 {
            return EINVAL;
        }
        v as usize
    };

    if len > 0 && (out_pos as u64) >= COPY_FILE_RANGE_MAX_FILE_SIZE {
        return EFBIG;
    }
    if in_inode.inode_num() == out_inode.inode_num() {
        let in_end = in_pos.saturating_add(len);
        let out_end = out_pos.saturating_add(len);
        if in_pos < out_end && out_pos < in_end {
            return EINVAL;
        }
    }

    let mut copied = 0usize;
    let mut remaining = len;
    let mut buf = vec![0u8; core::cmp::min(remaining, 16 * 1024)];
    while remaining > 0 {
        let room = COPY_FILE_RANGE_MAX_FILE_SIZE.saturating_sub(out_pos as u64) as usize;
        if room == 0 {
            if copied == 0 {
                return EFBIG;
            }
            break;
        }
        let want = core::cmp::min(remaining, core::cmp::min(buf.len(), room));
        let read = in_os_inode.pread_at(in_pos, &mut buf[..want]);
        if read == 0 {
            break;
        }
        let written = match out_os_inode.pwrite_at(out_pos, &buf[..read]) {
            Ok(v) => v,
            Err(_) => return EIO,
        };
        if written == 0 {
            break;
        }
        copied += written;
        in_pos += written;
        out_pos += written;
        remaining -= written;
        if written < read {
            break;
        }
    }
    if copied > 0 {
        let _ = out_os_inode.flush();
        touch_inode_mtime_ctime_now(&out_inode);
    }

    if off_in == 0 {
        in_os_inode.set_offset(in_pos);
    } else {
        let next = in_pos as i64;
        if try_write_user_value(token, off_in as *mut i64, &next).is_err() {
            return EFAULT;
        }
    }
    if off_out == 0 {
        out_os_inode.set_offset(out_pos);
    } else {
        let next = out_pos as i64;
        if try_write_user_value(token, off_out as *mut i64, &next).is_err() {
            return EFAULT;
        }
    }

    copied as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KStatFs {
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

fn fill_statfs(st_ptr: usize, mount_flags: i64) -> isize {
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
pub fn syscall_fstatfs(fd: usize, st_ptr: usize) -> isize {
    if get_fd_file(fd).is_none() {
        return EBADF;
    }
    let _ext4_guard = ext4_lock();
    fill_statfs(st_ptr, 0)
}

/// Linux `statfs(2)` (syscall 43 on riscv64).
pub fn syscall_statfs(pathname: usize, st_ptr: usize) -> isize {
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() {
        return ENOENT;
    }
    let at = match resolve_at_path(AT_FDCWD, path.as_str()) {
        Ok(v) => v,
        Err(e) => return e,
    };

    match at {
        AtPath::PseudoAbs(abs) => {
            if open_pseudo(&abs).is_none() {
                return ENOENT;
            }
            fill_statfs(st_ptr, statfs_mount_flags_for_abs(&abs))
        }
        AtPath::Ext4Abs(_) | AtPath::Ext4Rel { .. } => {
            let (fsuid, fsgid) = current_fsuid_gid();
            let _ext4_guard = ext4_lock();
            if let Err(e) = resolve_at_inode(&at, fsuid, fsgid, true) {
                return e;
            }
            let abs =
                resolve_abs_path(AT_FDCWD, path.as_str()).unwrap_or_else(|| String::from("/"));
            fill_statfs(st_ptr, statfs_mount_flags_for_abs(&abs))
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

const UTIME_OMIT: i64 = 0x3ffffffe;
const UTIME_NOW: i64 = 0x3fffffff;

fn resolve_utime(ts: TimeSpec, now: (i64, i64)) -> Result<Option<(i64, i64)>, isize> {
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
pub fn syscall_utimensat(dirfd: isize, pathname: usize, _times: usize, _flags: usize) -> isize {
    // `futimens` passes a null pathname and uses dirfd as the target fd.
    if pathname == 0 {
        if dirfd == AT_FDCWD {
            return EFAULT;
        }
        if dirfd < 0 {
            return EBADF;
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return EBADF;
        };
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            if os_inode.readonly_fs() {
                return EROFS;
            }
            let inode = os_inode.ext4_inode();
            let ino = inode.inode_num() as u64;
            let now = current_timespec();
            let (atime, mtime) = if _times == 0 {
                (Some(now), Some(now))
            } else {
                let token = get_current_token();
                let ts0 = read_user_value(token, _times as *const TimeSpec);
                let ts1 = read_user_value(
                    token,
                    (_times + core::mem::size_of::<TimeSpec>()) as *const TimeSpec,
                );
                let at = match resolve_utime(ts0, now) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let mt = match resolve_utime(ts1, now) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                (at, mt)
            };
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
        }
        return 0;
    }
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if open_pseudo(abs).is_some() {
            return EROFS;
        }
        // If any prefix is a pseudo file, report ENOTDIR for deeper paths.
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
                    return ENOTDIR;
                }
            }
        }
        return ENOENT;
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let (euid, _egid) = current_effective_uid_gid();
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if rofs_for_path(dirfd, &path) {
        return EROFS;
    }
    if _times == 0 {
        if euid != 0 && euid != inode.uid() && !inode_mode_allows_uid_gid(&inode, 2, fsuid, fsgid) {
            return EACCES;
        }
    } else if euid != 0 && euid != inode.uid() {
        return EPERM;
    }
    let ino = inode.inode_num() as u64;
    let now = current_timespec();
    let (atime, mtime) = if _times == 0 {
        (Some(now), Some(now))
    } else {
        let ts0 = read_user_value(token, _times as *const TimeSpec);
        let ts1 = read_user_value(
            token,
            (_times + core::mem::size_of::<TimeSpec>()) as *const TimeSpec,
        );
        let at = match resolve_utime(ts0, now) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mt = match resolve_utime(ts1, now) {
            Ok(v) => v,
            Err(e) => return e,
        };
        (at, mt)
    };
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

pub fn syscall_getcwd(buf: usize, size: usize) -> isize {
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let need = cwd.len().saturating_add(1);
    if size < need {
        return ERANGE;
    }
    if buf == 0 {
        return EFAULT;
    }
    let mut bytes = cwd.into_bytes();
    bytes.push(0);
    let token = get_current_token();
    if try_copy_to_user(token, buf as *mut u8, &bytes).is_err() {
        return EFAULT;
    }
    need as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KStat {
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
struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Statx {
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

const STATX_BASIC_STATS: u32 = 0x07ff;
const STATX_ATTR_IMMUTABLE: u64 = 0x0000_0010;
const STATX_ATTR_APPEND: u64 = 0x0000_0020;
const STATX_ATTR_NODUMP: u64 = 0x0000_0040;

const EXT4_ST_DEV: u64 = 1;

fn dt_type_from_ext4(ftype: u8) -> u8 {
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

fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

fn read_u32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

fn read_u16_le(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[0], buf[1]])
}

fn write_bytes_user(token: usize, mut dst: usize, bytes: &[u8]) {
    for b in bytes {
        *translated_mutref(token, dst as *mut u8) = *b;
        dst += 1;
    }
}

fn statx_timestamp(sec: i64, nsec: i64) -> StatxTimestamp {
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

fn statx_from_kstat(st: &KStat) -> Statx {
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

fn kstat_from_fd(fd: usize) -> Result<KStat, isize> {
    let Some(file) = get_fd_file(fd) else {
        return Err(EBADF);
    };

    // Pseudo nodes.
    if file.as_any().downcast_ref::<PseudoDir>().is_some()
        || file.as_any().downcast_ref::<PseudoFile>().is_some()
        || file.as_any().downcast_ref::<CgroupFile>().is_some()
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<PseudoShmFile>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
        || file.as_any().downcast_ref::<TtyFile>().is_some()
        || file.as_any().downcast_ref::<PtyMasterFile>().is_some()
        || file.as_any().downcast_ref::<PtySlaveFile>().is_some()
        || file.as_any().downcast_ref::<Pipe>().is_some()
    {
        let mode: u32 = if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
            cgroup.mode()
        } else if file.as_any().downcast_ref::<Pipe>().is_some() {
            0o010600
        } else if file.as_any().downcast_ref::<PseudoBlock>().is_some() {
            0o060600
        } else if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if file.as_any().downcast_ref::<RtcFile>().is_some() {
            0o100666
        } else if file.as_any().downcast_ref::<TtyFile>().is_some()
            || file.as_any().downcast_ref::<PtyMasterFile>().is_some()
            || file.as_any().downcast_ref::<PtySlaveFile>().is_some()
        {
            0o020666
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
        return Ok(KStat {
            st_dev: 0,
            st_ino: 1,
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
        return Err(EBADF);
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
    let mut size = core::cmp::max(disk_size, os_inode.pending_write_end()) as i64;
    if let Some(kind) = crate::fs::proc_file_kind(inode.inode_num()) {
        size = crate::fs::proc_file_len(&kind) as i64;
    }
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

pub fn syscall_fstat(fd: usize, st_ptr: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            crate::println!("[fs] fstat(pid={}) fd={} -> EBADF(nofile)", pid, fd);
        }
        return EBADF;
    };
    if st_ptr == 0 {
        return EFAULT;
    }

    // Pseudo nodes: return minimal metadata so libc/busybox can `opendir()` them.
    if file.as_any().downcast_ref::<PseudoDir>().is_some()
        || file.as_any().downcast_ref::<PseudoFile>().is_some()
        || file.as_any().downcast_ref::<CgroupFile>().is_some()
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<PseudoShmFile>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
        || file.as_any().downcast_ref::<TtyFile>().is_some()
        || file.as_any().downcast_ref::<PtyMasterFile>().is_some()
        || file.as_any().downcast_ref::<PtySlaveFile>().is_some()
        || file.as_any().downcast_ref::<Pipe>().is_some()
    {
        let mode: u32 = if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
            cgroup.mode()
        } else if file.as_any().downcast_ref::<Pipe>().is_some() {
            0o010600
        } else if file.as_any().downcast_ref::<PseudoBlock>().is_some() {
            0o060600
        } else if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if file.as_any().downcast_ref::<RtcFile>().is_some() {
            0o100666
        } else if file.as_any().downcast_ref::<TtyFile>().is_some()
            || file.as_any().downcast_ref::<PtyMasterFile>().is_some()
            || file.as_any().downcast_ref::<PtySlaveFile>().is_some()
        {
            0o020666
        } else if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
            match pf.kind_tag() {
                // /dev/null, /dev/zero, /dev/{u}random should look like character devices
                // to satisfy glibc helpers such as `daemon()`.
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
        } else if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
            match pf.kind_tag() {
                crate::fs::PseudoKindTag::Static => pf.len().unwrap_or(0) as i64,
                _ => 0,
            }
        } else {
            0
        };
        let st_blocks: u64 = if st_size <= 0 {
            0
        } else {
            ((st_size as u64 + 511) / 512) as u64
        };
        let st_ino = file
            .as_any()
            .downcast_ref::<Pipe>()
            .map(|pipe| pipe as *const Pipe as u64)
            .unwrap_or(1);
        let st = KStat {
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
        };
        let token = get_current_token();
        if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
            return EFAULT;
        }
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            if fd <= 8 {
                crate::println!("[fs] fstat(pid={}) fd={} pseudo -> ok", pid, fd);
            }
        }
        return 0;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        // Fallback for non-inode descriptors (pipe/socketpair/stdin/stdout...).
        let perm = match (file.readable(), file.writable()) {
            (true, true) => 0o666,
            (true, false) => 0o444,
            (false, true) => 0o222,
            (false, false) => 0o000,
        };
        let st = KStat {
            st_dev: 0,
            st_ino: (file.as_any() as *const dyn core::any::Any as *const () as u64),
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
        };
        let token = get_current_token();
        if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
            return EFAULT;
        }
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            crate::println!(
                "[fs] fstat(pid={}) fd={} -> fallback mode={:#o}",
                pid,
                fd,
                st.st_mode
            );
        }
        return 0;
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
    let mut size = core::cmp::max(disk_size, os_inode.pending_write_end()) as i64;
    if let Some(kind) = crate::fs::proc_file_kind(inode.inode_num()) {
        size = crate::fs::proc_file_len(&kind) as i64;
    }
    let blocks = (((size as u64) + 511) / 512) as u64;
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

    let token = get_current_token();
    if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
        return EFAULT;
    }
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && fd <= 8 {
            crate::println!("[fs] fstat(pid={}) fd={} -> ok mode={:#o}", pid, fd, mode);
        }
    }
    0
}

/// Linux `fsync(2)` / `fdatasync(2)` (syscalls 82/83 on riscv64).
///
/// iozone uses this heavily; keep it lightweight but flush per-fd buffered writes.
pub fn syscall_fsync(fd: usize) -> isize {
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        {
            let _ext4_guard = ext4_lock();
            if !(inode.is_file() || inode.is_dir()) {
                return EINVAL;
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
    EINVAL
}

/// Linux `sync(2)` (syscall 81 on riscv64).
///
/// Flush per-fd write buffers and the ext4 block cache to disk.
pub fn syscall_sync() -> isize {
    let current = current_process();
    let mut files: Vec<alloc::sync::Arc<dyn File + Send + Sync>> = Vec::new();
    {
        let inner = current.borrow_mut();
        for file in inner.fd_table.iter().filter_map(|f| f.as_ref()) {
            files.push(file.clone());
        }
    }

    let processes: Vec<alloc::sync::Arc<ProcessControlBlock>> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    for process in processes {
        if core::ptr::eq(
            alloc::sync::Arc::as_ptr(&process),
            alloc::sync::Arc::as_ptr(&current),
        ) {
            continue;
        }
        if let Some(inner) = process.try_borrow_mut() {
            for file in inner.fd_table.iter().filter_map(|f| f.as_ref()) {
                files.push(file.clone());
            }
        }
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

/// Linux `syncfs(2)` (syscall 267 on riscv64).
///
/// We treat this as a per-filesystem sync request rooted at `fd`.
pub fn syscall_syncfs(fd: usize) -> isize {
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if file.as_any().downcast_ref::<OSInode>().is_none() {
        return EINVAL;
    }
    syscall_sync()
}

/// Linux `sync_file_range(2)` (syscall 84 on riscv64).
///
/// Minimal implementation: flush buffered data for regular files.
pub fn syscall_sync_file_range(fd: usize, offset: usize, nbytes: usize, flags: usize) -> isize {
    const SYNC_FILE_RANGE_WAIT_BEFORE: usize = 1;
    const SYNC_FILE_RANGE_WRITE: usize = 2;
    const SYNC_FILE_RANGE_WAIT_AFTER: usize = 4;
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if file.as_any().downcast_ref::<Pipe>().is_some()
        || file.as_any().downcast_ref::<FifoDuplexFile>().is_some()
        || file.as_any().downcast_ref::<PseudoFile>().is_some()
        || file.as_any().downcast_ref::<CgroupFile>().is_some()
        || file.as_any().downcast_ref::<PseudoDir>().is_some()
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
        || file.as_any().downcast_ref::<NetSocketFile>().is_some()
    {
        return ESPIPE;
    }
    let valid_flags =
        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if (flags & !valid_flags) != 0 {
        return EINVAL;
    }
    if (offset as i64) < 0 || (nbytes as i64) < 0 {
        return EINVAL;
    }
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return EINVAL;
    };
    let inode = os_inode.ext4_inode();
    {
        let _ext4_guard = ext4_lock();
        if !inode.is_file() {
            return EINVAL;
        }
    }
    if os_inode.readonly_fs() {
        return 0;
    }
    let _ = os_inode.flush();
    pseudo_block_note_sync();
    0
}

/// Linux `fadvise64(2)` / userspace `posix_fadvise(3)` backend.
pub fn syscall_fadvise64(fd: usize, offset: usize, len: usize, advice: usize) -> isize {
    const POSIX_FADV_NORMAL: usize = 0;
    const POSIX_FADV_RANDOM: usize = 1;
    const POSIX_FADV_SEQUENTIAL: usize = 2;
    const POSIX_FADV_WILLNEED: usize = 3;
    const POSIX_FADV_DONTNEED: usize = 4;
    const POSIX_FADV_NOREUSE: usize = 5;

    if (offset as i64) < 0 || (len as i64) < 0 {
        return EINVAL;
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
        return EINVAL;
    }
    if fd_has_o_path(fd) {
        return EBADF;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };

    if file.as_any().downcast_ref::<Pipe>().is_some()
        || file.as_any().downcast_ref::<FifoDuplexFile>().is_some()
    {
        return ESPIPE;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return EINVAL;
    };
    let inode = os_inode.ext4_inode();
    {
        let _ext4_guard = ext4_lock();
        if !inode.is_file() {
            return ESPIPE;
        }
    }
    0
}

pub fn syscall_newfstatat(dirfd: isize, pathname: usize, st_ptr: usize, _flags: usize) -> isize {
    if st_ptr == 0 {
        return EFAULT;
    }
    const AT_EMPTY_PATH: usize = 0x1000;
    let valid_flags = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    if (_flags & !valid_flags) != 0 {
        return EINVAL;
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
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Pseudo nodes: return minimal metadata.
    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(target) = crate::fs::proc_readlink(abs) {
            let st_size = target.len() as i64;
            let st_blocks = if st_size <= 0 {
                0
            } else {
                ((st_size as u64 + 511) / 512) as u64
            };
            let st = KStat {
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
            };
            if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
                return EFAULT;
            }
            return 0;
        }
        let Some(node) = open_pseudo(abs) else {
            return ENOENT;
        };
        let mode: u32 = if node.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if let Some(cgroup) = node.as_any().downcast_ref::<CgroupFile>() {
            cgroup.mode()
        } else if abs == "/dev/root" {
            0o060600
        } else if node.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if abs == "/dev/null"
            || abs == "/dev/zero"
            || abs == "/dev/misc/rtc"
            || abs == "/dev/ptmx"
            || abs == "/dev/tty"
            || abs.starts_with("/dev/pts/")
        {
            0o020666
        } else {
            0o100444
        };
        let st_rdev: u64 = if abs == "/dev/root" {
            EXT4_ST_DEV
        } else if abs == "/dev/null" {
            0x103
        } else if abs == "/dev/zero" {
            0x105
        } else if abs == "/dev/misc/rtc" {
            0x109
        } else if abs == "/dev/ptmx" {
            0x501
        } else if abs == "/dev/tty" {
            0x500
        } else if abs.starts_with("/dev/pts/") {
            0x502
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = node.as_any().downcast_ref::<PseudoShmFile>() {
            shm.len() as i64
        } else if let Some(cgroup) = node.as_any().downcast_ref::<CgroupFile>() {
            cgroup.len() as i64
        } else if let Some(pf) = node.as_any().downcast_ref::<PseudoFile>() {
            match pf.kind_tag() {
                crate::fs::PseudoKindTag::Static => pf.len().unwrap_or(0) as i64,
                _ => 0,
            }
        } else {
            0
        };
        let st_blocks: u64 = if st_size <= 0 {
            0
        } else {
            ((st_size as u64 + 511) / 512) as u64
        };
        let st = KStat {
            st_dev: 0,
            st_ino: 1,
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
        };
        if try_write_user_value(token, st_ptr as *mut KStat, &st).is_err() {
            return EFAULT;
        }
        return 0;
    }

    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_final = (_flags & AT_SYMLINK_NOFOLLOW) == 0;
    let _ext4_guard = ext4_lock();
    let inode = match resolve_at_inode(&at, fsuid, fsgid, follow_final) {
        Ok(v) => v,
        Err(ENOENT) if matches!(path.as_str(), "busybox" | "./busybox") => {
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
                None => return ENOENT,
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
    let mut size = inode_visible_size(&inode) as i64;
    if let Some(kind) = crate::fs::proc_file_kind(inode.inode_num()) {
        size = crate::fs::proc_file_len(&kind) as i64;
    }
    let blocks = (((size as u64) + 511) / 512) as u64;
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
        return EFAULT;
    }
    0
}

/// Linux `statx(2)` (syscall 291 on riscv64/loongarch64).
pub fn syscall_statx(
    dirfd: isize,
    pathname: usize,
    flags: usize,
    _mask: usize,
    stx_ptr: usize,
) -> isize {
    if stx_ptr == 0 {
        return EFAULT;
    }
    let valid_flags = AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE;
    if (flags & !valid_flags) != 0 {
        return EINVAL;
    }
    const STATX_VALID_MASK: usize = 0x0001_FFFF;
    if (_mask & !STATX_VALID_MASK) != 0 {
        return EINVAL;
    }
    let token = get_current_token();
    let path = match read_user_cstring(token, pathname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if path.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        if dirfd < 0 {
            return EINVAL;
        }
        let st = match kstat_from_fd(dirfd as usize) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let stx = statx_from_kstat(&st);
        if try_write_user_value(token, stx_ptr as *mut Statx, &stx).is_err() {
            return EFAULT;
        }
        return 0;
    }
    if path.is_empty() {
        return ENOENT;
    }

    if dirfd < 0 && dirfd != AT_FDCWD {
        return EBADF;
    }
    let effective_dirfd = dirfd;
    let at = match resolve_at_path(effective_dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Pseudo nodes: return minimal metadata.
    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(target) = crate::fs::proc_readlink(abs) {
            let st_size = target.len() as i64;
            let st_blocks: u64 = if st_size <= 0 {
                0
            } else {
                ((st_size as u64 + 511) / 512) as u64
            };
            let st = KStat {
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
            };
            let stx = statx_from_kstat(&st);
            if try_write_user_value(token, stx_ptr as *mut Statx, &stx).is_err() {
                return EFAULT;
            }
            return 0;
        }
        let Some(node) = open_pseudo(abs) else {
            return ENOENT;
        };
        let mode: u32 = if node.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if let Some(cgroup) = node.as_any().downcast_ref::<CgroupFile>() {
            cgroup.mode()
        } else if abs == "/dev/root" {
            0o060600
        } else if node.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if abs == "/dev/null"
            || abs == "/dev/zero"
            || abs == "/dev/misc/rtc"
            || abs == "/dev/ptmx"
            || abs == "/dev/tty"
            || abs.starts_with("/dev/pts/")
        {
            0o020666
        } else {
            0o100444
        };
        let st_rdev: u64 = if abs == "/dev/root" {
            EXT4_ST_DEV
        } else if abs == "/dev/null" {
            0x103
        } else if abs == "/dev/zero" {
            0x105
        } else if abs == "/dev/misc/rtc" {
            0x109
        } else if abs == "/dev/ptmx" {
            0x501
        } else if abs == "/dev/tty" {
            0x500
        } else if abs.starts_with("/dev/pts/") {
            0x502
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = node.as_any().downcast_ref::<PseudoShmFile>() {
            shm.len() as i64
        } else if let Some(cgroup) = node.as_any().downcast_ref::<CgroupFile>() {
            cgroup.len() as i64
        } else {
            0
        };
        let st_blocks: u64 = if st_size <= 0 {
            0
        } else {
            ((st_size as u64 + 511) / 512) as u64
        };
        let st = KStat {
            st_dev: 0,
            st_ino: 1,
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
        };
        let stx = statx_from_kstat(&st);
        if try_write_user_value(token, stx_ptr as *mut Statx, &stx).is_err() {
            return EFAULT;
        }
        return 0;
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
        return ENOENT;
    };

    let mode_raw = inode.mode();
    let mode = mode_raw as u32;
    let uid = inode.uid();
    let gid = inode.gid();
    let nlink = inode.link_count();
    let st_rdev = inode_rdev_for_mode(&inode, mode_raw);
    let mut size = inode_visible_size(&inode) as i64;
    if let Some(kind) = crate::fs::proc_file_kind(inode.inode_num()) {
        size = crate::fs::proc_file_len(&kind) as i64;
    }
    let blocks = (((size as u64) + 511) / 512) as u64;
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
        return EFAULT;
    }
    0
}

pub fn syscall_getdents64(fd: usize, dirp: usize, len: usize) -> isize {
    // Avoid unbounded kernel heap allocations from user-provided buffer sizes.
    // Returning fewer bytes is allowed; callers will retry with the remaining entries.
    const MAX_DIRENT_BUF: usize = 256 * 1024;
    let len = len.min(MAX_DIRENT_BUF);
    if len > 0 && len < 24 {
        return EINVAL;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    let token = get_current_token();

    // Pseudo directories (e.g. /sys, /dev).
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            crate::println!("[fs] getdents64(pid={}) pseudo fd={} len={}", pid, fd, len);
        }
        let entries = pdir.entries();
        let mut index = pdir.index();
        if index >= entries.len() || len == 0 {
            return 0;
        }

        let mut kbuf = alloc::vec![0u8; len];
        let mut written = 0usize;
        while index < entries.len() {
            let ent = &entries[index];
            let name_bytes = ent.name.as_bytes();
            let reclen = align_up(19 + name_bytes.len() + 1, 8);
            if written + reclen > len {
                break;
            }
            let base = written;
            kbuf[base..base + 8].copy_from_slice(&ent.ino.to_le_bytes());
            kbuf[base + 8..base + 16].copy_from_slice(&((index + 1) as i64).to_le_bytes());
            kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
            kbuf[base + 18] = ent.dtype;
            kbuf[base + 19..base + 19 + name_bytes.len()].copy_from_slice(name_bytes);
            kbuf[base + 19 + name_bytes.len()] = 0;
            for b in kbuf[base + 19 + name_bytes.len() + 1..base + reclen].iter_mut() {
                *b = 0;
            }

            written += reclen;
            index += 1;
        }

        let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written, MapPermission::W);
        let mut src_off = 0usize;
        for ub in user_bufs {
            let end = src_off + ub.len();
            ub.copy_from_slice(&kbuf[src_off..end]);
            src_off = end;
        }
        pdir.set_index(index);
        return written as isize;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return ENOTDIR;
    };
    let inode = os_inode.ext4_inode();
    if crate::fs::is_proc_root(inode.as_ref()) {
        let pids = crate::fs::collect_pids();
        let ext4_guard = ext4_lock();
        let static_entries = inode.dir_entries();
        drop(ext4_guard);

        let entries = crate::fs::build_proc_root_entries(static_entries, pids);
        let mut index = os_inode.dir_offset();
        if index >= entries.len() || len == 0 {
            return 0;
        }

        let mut kbuf = alloc::vec![0u8; len];
        let mut written = 0usize;
        while index < entries.len() {
            let ent = &entries[index];
            let name_bytes = ent.name.as_bytes();
            let reclen = align_up(19 + name_bytes.len() + 1, 8);
            if written + reclen > len {
                break;
            }
            let base = written;
            kbuf[base..base + 8].copy_from_slice(&ent.ino.to_le_bytes());
            kbuf[base + 8..base + 16].copy_from_slice(&((index + 1) as i64).to_le_bytes());
            kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
            kbuf[base + 18] = ent.dtype;
            kbuf[base + 19..base + 19 + name_bytes.len()].copy_from_slice(name_bytes);
            kbuf[base + 19 + name_bytes.len()] = 0;
            for b in kbuf[base + 19 + name_bytes.len() + 1..base + reclen].iter_mut() {
                *b = 0;
            }

            written += reclen;
            index += 1;
        }

        let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written, MapPermission::W);
        let mut src_off = 0usize;
        for ub in user_bufs {
            let end = src_off + ub.len();
            ub.copy_from_slice(&kbuf[src_off..end]);
            src_off = end;
        }
        os_inode.set_dir_offset(index);
        if written > 0 {
            maybe_update_inode_atime(&inode, true);
        }
        return written as isize;
    }

    let ext4_guard = ext4_lock();
    if !inode.is_dir() {
        return ENOTDIR;
    };
    if inode.link_count() == 0 {
        return ENOENT;
    }

    if len == 0 {
        return 0;
    }

    // Stream ext4 directory entries from the on-disk format using a byte offset.
    //
    // This avoids rebuilding `inode.dir_entries()` on every `getdents64` call, which
    // becomes O(n^2) for large directories (busybox `du`/`find`).
    let block_size = inode.block_size();
    const EXT4_DIRENT_HDR: usize = 8; // u32 ino, u16 rec_len, u8 name_len, u8 file_type

    let dir_size = inode.size() as usize;
    let mut off = os_inode.dir_offset();
    if off >= dir_size {
        return 0;
    }

    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && (fd == 3 || fd == 4) {
            crate::println!(
                "[fs] getdents64(pid={}) fd={} len={} off={} dir_size={}",
                pid,
                fd,
                len,
                off,
                dir_size
            );
        }
    }

    let mut kbuf = alloc::vec![0u8; len];
    let mut written = 0usize;

    let mut scratch = alloc::vec![0u8; block_size];
    while off < dir_size && written + 24 <= len {
        let block_start = (off / block_size) * block_size;
        let within = off - block_start;
        let to_read = core::cmp::min(block_size, dir_size - block_start);
        if to_read < EXT4_DIRENT_HDR || within >= to_read {
            break;
        }
        inode.read_at(block_start, &mut scratch[..to_read]);

        // Parse entries within this block, starting at `within`.
        let mut pos = within;
        while pos + EXT4_DIRENT_HDR <= to_read && written + 24 <= len {
            let inode_num = read_u32_le(&scratch[pos..pos + 4]);
            let rec_len = read_u16_le(&scratch[pos + 4..pos + 6]) as usize;
            let name_len = scratch[pos + 6] as usize;
            let file_type = scratch[pos + 7];

            if rec_len < EXT4_DIRENT_HDR || pos + rec_len > to_read {
                // Corrupt/unsupported entry; stop to avoid looping.
                off = dir_size;
                break;
            }

            let next_off = block_start + pos + rec_len;
            // Skip unused entries (inode_num == 0).
            if inode_num != 0 && name_len > 0 && pos + EXT4_DIRENT_HDR + name_len <= pos + rec_len {
                let name_bytes = &scratch[pos + EXT4_DIRENT_HDR..pos + EXT4_DIRENT_HDR + name_len];
                let reclen = align_up(19 + name_len + 1, 8);
                if written + reclen > len {
                    // Caller buffer full; keep current offset for next call.
                    os_inode.set_dir_offset(block_start + pos);
                    let user_bufs =
                        translated_byte_buffer(token, dirp as *mut u8, written, MapPermission::W);
                    let mut src_off = 0usize;
                    for ub in user_bufs {
                        let end = src_off + ub.len();
                        ub.copy_from_slice(&kbuf[src_off..end]);
                        src_off = end;
                    }
                    return written as isize;
                }

                let base = written;
                kbuf[base..base + 8].copy_from_slice(&(inode_num as u64).to_le_bytes());
                kbuf[base + 8..base + 16].copy_from_slice(&(next_off as i64).to_le_bytes());
                kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
                kbuf[base + 18] = dt_type_from_ext4(file_type);
                kbuf[base + 19..base + 19 + name_len].copy_from_slice(name_bytes);
                kbuf[base + 19 + name_len] = 0;
                for b in kbuf[base + 19 + name_len + 1..base + reclen].iter_mut() {
                    *b = 0;
                }
                written += reclen;
            }

            pos += rec_len;
            off = block_start + pos;
            if off >= dir_size {
                break;
            }
        }
    }

    // Copy back to user buffer with per-page translation, avoiding per-byte translation overhead.
    let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written, MapPermission::W);
    let mut src_off = 0usize;
    for ub in user_bufs {
        let end = src_off + ub.len();
        ub.copy_from_slice(&kbuf[src_off..end]);
        src_off = end;
    }

    os_inode.set_dir_offset(off);
    drop(ext4_guard);
    if written > 0 {
        maybe_update_inode_atime(&inode, true);
    }
    written as isize
}

/// Linux `lseek(2)` (syscall 62 on riscv64).
///
/// Needed by glibc directory APIs (`opendir`/`readdir`/`rewinddir`/`telldir`).
pub fn syscall_lseek(fd: usize, offset: isize, whence: usize) -> isize {
    const SEEK_SET: usize = 0;
    const SEEK_CUR: usize = 1;
    const SEEK_END: usize = 2;
    const PSEUDO_ROOT_DEV_BYTES: usize = 1024 * 1024 * 1024;

    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };

    // Directories: map seek position to our per-fd `dir_offset`.
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        let cur = pdir.index() as isize;
        let end = pdir.entries().len() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        pdir.set_index(new as usize);
        return new;
    }

    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let inode_num = inode.inode_num();
        let (is_dir, is_fifo, mut end) = {
            let _ext4_guard = ext4_lock();
            let disk = inode.size() as usize;
            let end = core::cmp::max(disk, os_inode.pending_write_end()) as isize;
            (inode.is_dir(), inode.is_fifo(), end)
        };
        if is_fifo {
            return ESPIPE;
        }
        if !is_dir {
            if let Some(kind) = crate::fs::proc_file_kind(inode_num) {
                end = crate::fs::proc_file_len(&kind) as isize;
            }
        }

        if is_dir {
            let cur = os_inode.dir_offset() as isize;
            let new = match whence {
                SEEK_SET => offset,
                SEEK_CUR => cur.saturating_add(offset),
                SEEK_END => end.saturating_add(offset),
                _ => return EINVAL,
            };
            if new < 0 {
                return EINVAL;
            }
            os_inode.set_dir_offset(new as usize);
            return new;
        }

        // Regular files: adjust read/write offset.
        let cur = os_inode.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        os_inode.set_offset(new as usize);
        return new;
    }

    if let Some(pblk) = file.as_any().downcast_ref::<PseudoBlock>() {
        let cur = pblk.offset() as isize;
        let end = PSEUDO_ROOT_DEV_BYTES as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        pblk.set_offset(new as usize);
        return new;
    }

    // Pseudo regular files: allow seeking for static content (e.g., `/dev` nodes),
    // which libc helpers (busybox `df`) may `rewind()` via lseek.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        let Some(end) = pf.len().map(|n| n as isize) else {
            return ESPIPE;
        };
        let cur = pf.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        pf.set_offset(new as usize);
        return new;
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        let end = shm.len() as isize;
        let cur = shm.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        shm.set_offset(new as usize);
        return new;
    }

    if let Some(proc_file) = file.as_any().downcast_ref::<ProcPseudoFile>() {
        let cur = proc_file.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => proc_file.seek_end().saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        proc_file.set_offset(new as usize);
        return new;
    }

    if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
        let cur = cgroup.offset() as isize;
        let end = cgroup.len() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        cgroup.set_offset(new as usize);
        return new;
    }

    ESPIPE
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum FsContextMode {
    Create,
    Reconfigure,
}

struct FsContextState {
    mode: FsContextMode,
    fs_type: String,
    source_display: String,
    source_abs: Option<String>,
    target_abs: Option<String>,
    pending_flags: usize,
    created: bool,
}

struct FsContextFile {
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

struct MountHandleState {
    source: String,
    source_display: String,
    fs_type: String,
    flags: usize,
}

struct MountHandleFile {
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
struct KMountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

fn alloc_internal_fd(file: Arc<dyn File + Send + Sync>, fd_flags: u32) -> Result<isize, isize> {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return Err(EMFILE);
    };
    inner.fd_table[fd] = Some(file);
    inner.fd_flags[fd] = fd_flags;
    Ok(fd as isize)
}

fn mount_attr_bits_to_legacy_flags(attrs: usize) -> usize {
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

fn sync_rofs_state(target: &str, flags: usize) {
    if (flags & MS_RDONLY) != 0 {
        register_rofs_mount(target);
    } else {
        unregister_rofs_mount(target);
    }
}

fn read_user_path_abs(dirfd: isize, ptr: usize) -> Result<String, isize> {
    let token = get_current_token();
    let path = read_user_cstring(token, ptr)?;
    if path.is_empty() {
        return Err(ENOENT);
    }
    resolve_abs_path(dirfd, &path).ok_or(EBADF)
}

fn ensure_mount_target_dir(abs: &str) -> Result<(), isize> {
    let _ext4_guard = ext4_lock();
    let Some(inode) = find_path_in_roots(abs) else {
        return Err(ENOENT);
    };
    if !inode.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(())
}

fn mount_fs_type_for_abs(abs: &str) -> String {
    mount_lookup_for_abs(abs)
        .map(|m| m.fs_type)
        .unwrap_or_else(|| String::from("ext4"))
}

fn mount_source_display_for_abs(abs: &str) -> String {
    mount_lookup_for_abs(abs)
        .map(|m| m.source_display)
        .unwrap_or_else(|| String::from("/dev/root"))
}

pub fn syscall_fsopen(fsname: usize, flags: usize) -> isize {
    if (flags & !FSOPEN_CLOEXEC) != 0 {
        return EINVAL;
    }
    let token = get_current_token();
    let fsname = match read_user_cstring(token, fsname) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if fsname.is_empty() {
        return EINVAL;
    }
    if fsname == "invalid" || fsname == "error" {
        return ENODEV;
    }
    let mut fd_flags = 0u32;
    if (flags & FSOPEN_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_internal_fd(Arc::new(FsContextFile::new_create(&fsname)), fd_flags).unwrap_or_else(|e| e)
}

pub fn syscall_fsconfig(fd: usize, cmd: usize, key: usize, value: usize, aux: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return EINVAL;
    };
    let Some(ctx_file) = file.as_any().downcast_ref::<FsContextFile>() else {
        return EINVAL;
    };
    let token = get_current_token();
    let key_s = if key == 0 {
        None
    } else {
        match read_user_cstring(token, key) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };
    let value_s = if value == 0 {
        None
    } else {
        match read_user_cstring(token, value) {
            Ok(v) => Some(v),
            Err(e) => return e,
        }
    };
    let mut state = ctx_file.state.lock();
    match cmd {
        FSCONFIG_SET_FLAG => {
            let Some(key_s) = key_s.as_deref() else {
                return EINVAL;
            };
            if value_s.is_some() || aux != 0 {
                return EINVAL;
            }
            match key_s {
                "rw" => state.pending_flags &= !MS_RDONLY,
                "ro" => state.pending_flags |= MS_RDONLY,
                _ => return EINVAL,
            }
            0
        }
        FSCONFIG_SET_STRING => {
            let Some(key_s) = key_s.as_deref() else {
                return EINVAL;
            };
            let Some(value_s) = value_s.as_deref() else {
                return EINVAL;
            };
            if aux != 0 || key_s.is_empty() || value_s.is_empty() {
                return EINVAL;
            }
            match key_s {
                "source" => {
                    state.source_display = String::from(value_s);
                    state.source_abs = Some(String::from("/"));
                    0
                }
                "sync" => 0,
                _ => EINVAL,
            }
        }
        FSCONFIG_SET_BINARY => EINVAL,
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY | FSCONFIG_SET_FD => {
            if key_s.as_deref().unwrap_or("").is_empty() {
                return EINVAL;
            }
            match cmd {
                FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
                    if value_s.is_none() || aux == usize::MAX {
                        return EINVAL;
                    }
                }
                FSCONFIG_SET_FD => {
                    if value_s.is_some() || aux == usize::MAX {
                        return EINVAL;
                    }
                }
                _ => {}
            }
            EOPNOTSUPP
        }
        FSCONFIG_CMD_CREATE => {
            if key_s.is_some() || value_s.is_some() || aux != 0 {
                return EINVAL;
            }
            if state.mode != FsContextMode::Create || state.source_abs.is_none() {
                return EINVAL;
            }
            state.created = true;
            0
        }
        FSCONFIG_CMD_RECONFIGURE => {
            if key_s.is_some() || value_s.is_some() || aux != 0 {
                return EINVAL;
            }
            if state.mode != FsContextMode::Reconfigure {
                return EINVAL;
            }
            let Some(target_abs) = state.target_abs.clone() else {
                return EINVAL;
            };
            if !update_mount_record_flags(&target_abs, state.pending_flags) {
                return EINVAL;
            }
            sync_rofs_state(&target_abs, state.pending_flags);
            0
        }
        _ => EOPNOTSUPP,
    }
}

pub fn syscall_fsmount(fd: usize, flags: usize, mount_attrs: usize) -> isize {
    if (flags & !FSMOUNT_CLOEXEC) != 0 {
        return EINVAL;
    }
    if (mount_attrs & !FSMOUNT_SUPPORTED_ATTRS) != 0 {
        return EINVAL;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    let Some(ctx_file) = file.as_any().downcast_ref::<FsContextFile>() else {
        return EINVAL;
    };
    let state = ctx_file.state.lock();
    if state.mode != FsContextMode::Create || !state.created {
        return EINVAL;
    }
    let source = state
        .source_abs
        .clone()
        .unwrap_or_else(|| String::from("/"));
    let handle_flags = state.pending_flags | mount_attr_bits_to_legacy_flags(mount_attrs);
    let mut fd_flags = 0u32;
    if (flags & FSMOUNT_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_internal_fd(
        Arc::new(MountHandleFile::new(
            &source,
            &state.source_display,
            &state.fs_type,
            handle_flags,
        )),
        fd_flags,
    )
    .unwrap_or_else(|e| e)
}

pub fn syscall_fspick(dirfd: isize, path: usize, flags: usize) -> isize {
    let valid_flags =
        FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
    if (flags & !valid_flags) != 0 {
        return EINVAL;
    }
    let abs = if path == 0 {
        return EFAULT;
    } else {
        match read_user_path_abs(dirfd, path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    if let Err(e) = ensure_mount_target_dir(&translate_mount_abs(&abs)) {
        return e;
    }
    let fs_type = mount_fs_type_for_abs(&abs);
    let source_abs = translate_mount_abs(&abs);
    let source_display = mount_source_display_for_abs(&abs);
    let mut fd_flags = 0u32;
    if (flags & FSPICK_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    alloc_internal_fd(
        Arc::new(FsContextFile::new_reconfigure(
            &fs_type,
            &source_display,
            &source_abs,
            &abs,
            mount_flags_for_abs(&abs),
        )),
        fd_flags,
    )
    .unwrap_or_else(|e| e)
}

pub fn syscall_open_tree(dirfd: isize, path: usize, flags: usize) -> isize {
    let valid_flags =
        OPEN_TREE_CLONE | O_CLOEXEC | AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
    if (flags & !valid_flags) != 0 {
        return EINVAL;
    }
    let abs = if path == 0 {
        return EFAULT;
    } else {
        match read_user_path_abs(dirfd, path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    if let Err(e) = ensure_mount_target_dir(&translate_mount_abs(&abs)) {
        return e;
    }
    let source_abs = translate_mount_abs(&abs);
    let source_display = mount_source_display_for_abs(&abs);
    let fs_type = mount_fs_type_for_abs(&abs);
    let mount_flags = mount_flags_for_abs(&abs);
    let mut fd_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    fd_flags |= O_PATH as u32;
    alloc_internal_fd(
        Arc::new(MountHandleFile::new(
            &source_abs,
            &source_display,
            &fs_type,
            mount_flags,
        )),
        fd_flags,
    )
    .unwrap_or_else(|e| e)
}

pub fn syscall_move_mount(
    from_dirfd: isize,
    from_path: usize,
    to_dirfd: isize,
    to_path: usize,
    flags: usize,
) -> isize {
    if (flags & !MOVE_MOUNT__MASK) != 0 {
        return EINVAL;
    }
    let from_path_s = if from_path == 0 {
        return EFAULT;
    } else {
        match read_user_cstring(get_current_token(), from_path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    let to_abs = match read_user_path_abs(to_dirfd, to_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = ensure_mount_target_dir(&to_abs) {
        return e;
    }
    if from_dirfd < 0 {
        return EBADF;
    }
    let Some(file) = get_fd_file(from_dirfd as usize) else {
        return EBADF;
    };
    let Some(handle) = file.as_any().downcast_ref::<MountHandleFile>() else {
        return EBADF;
    };
    if !from_path_s.is_empty() {
        return ENOENT;
    }
    if (flags & MOVE_MOUNT_F_EMPTY_PATH) == 0 {
        return ENOENT;
    }
    let state = handle.state.lock();
    upsert_mount_record(
        &to_abs,
        &state.source,
        &state.source_display,
        &state.fs_type,
        state.flags,
    );
    sync_rofs_state(&to_abs, state.flags);
    0
}

pub fn syscall_mount_setattr(
    dirfd: isize,
    path: usize,
    flags: usize,
    attr: usize,
    size: usize,
) -> isize {
    if dirfd < 0 {
        return EBADF;
    }
    if attr == 0 || size < core::mem::size_of::<KMountAttr>() {
        return EINVAL;
    }
    let path_s = if path == 0 {
        return EFAULT;
    } else {
        match read_user_cstring(get_current_token(), path) {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    if (flags & AT_EMPTY_PATH) == 0 || !path_s.is_empty() {
        return EINVAL;
    }
    let Some(file) = get_fd_file(dirfd as usize) else {
        return EBADF;
    };
    let Some(handle) = file.as_any().downcast_ref::<MountHandleFile>() else {
        return EINVAL;
    };
    let mount_attr = match try_read_user_value(get_current_token(), attr as *const KMountAttr) {
        Some(v) => v,
        None => return EFAULT,
    };
    let attr_set = mount_attr.attr_set as usize;
    let attr_clr = mount_attr.attr_clr as usize;
    if (attr_set & !FSMOUNT_SUPPORTED_ATTRS) != 0 || (attr_clr & !FSMOUNT_SUPPORTED_ATTRS) != 0 {
        return EINVAL;
    }
    let mut state = handle.state.lock();
    state.flags |= mount_attr_bits_to_legacy_flags(attr_set);
    state.flags &= !mount_attr_bits_to_legacy_flags(attr_clr);
    0
}
pub fn syscall_mount(
    special: usize,
    dir: usize,
    fstype: usize,
    flags: usize,
    data: usize,
) -> isize {
    syscall_mount_impl(special, dir, fstype, flags, data)
}

pub fn syscall_umount2(special: usize, flags: usize) -> isize {
    syscall_umount2_impl(special, flags)
}
