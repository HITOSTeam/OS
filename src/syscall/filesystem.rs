use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::task::manager::{PID2PCB, wakeup_task};
use crate::{
    fs::{
        File, NetSocketFile, OSInode, OpenFlags, Pipe, PseudoBlock, PseudoDir, PseudoDirent,
        PseudoFile, PseudoShmFile, RtcFile, ext4_lock, find_path_in_roots, make_pipe, open_file,
        secondary_root_inode, shm_create, shm_get, shm_list, shm_remove,
    },
    mm::{
        MapPermission, UserBuffer, copy_from_user, copy_to_user, read_user_value,
        translated_byte_buffer, translated_mutref, translated_str, try_copy_from_user,
        try_copy_to_user, try_read_user_value, try_translated_byte_buffer, try_write_user_value,
        write_user_value,
    },
    task::processor::{
        current_files_process, current_process, current_task, suspend_current_and_run_next,
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
const O_NOATIME: usize = 0x40000;
const O_PATH: usize = 0x200000;
const O_DIRECTORY: usize = 0x10000;
const O_NOFOLLOW: usize = 0x20000;
const O_CLOEXEC: usize = 0x80000;
// __O_TMPFILE (020000000) | O_DIRECTORY from asm-generic/fcntl.h
const O_TMPFILE: usize = 0x410000;

const FD_CLOEXEC: u32 = 1;
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
const EFBIG: isize = -27;
const EAGAIN: isize = -11;
const EINTR: isize = -4;
const E2BIG: isize = -7;
const ELOOP: isize = -40;
const EPERM: isize = -1;
const ENOENT: isize = -2;
const ENODATA: isize = -61;
const EINVAL: isize = -22;
const ERANGE: isize = -34;
const EMFILE: isize = -24;
const ENOTDIR: isize = -20;
const EISDIR: isize = -21;
const EACCES: isize = -13;
const EEXIST: isize = -17;
const EXDEV: isize = -18;
const EIO: isize = -5;
const ESPIPE: isize = -29;
const EPIPE: isize = -32;
const EROFS: isize = -30;
const ENOSPC: isize = -28;
const ENOSYS: isize = -38;
const ENAMETOOLONG: isize = -36;
const ENXIO: isize = -6;
const EOPNOTSUPP: isize = -95;
const ENOTEMPTY: isize = -39;
const EOVERFLOW: isize = -75;

const XATTR_CREATE: usize = 0x1;
const XATTR_REPLACE: usize = 0x2;
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: usize = 65536;
const PIPE_BUF: usize = 4096;

// fs/ioctl.h flags consumed by setxattr03.
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_APPEND_FL: u32 = 0x0000_0020;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FileLockKey {
    dev: u64,
    ino: u64,
}

#[derive(Clone, Copy)]
struct RecordLock {
    owner_pid: usize,
    lock_type: i16,
    start: i64,
    end: Option<i64>,
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
    static ref FIFO_PIPE_STATES: Mutex<BTreeMap<u64, Arc<FifoPipeState>>> =
        Mutex::new(BTreeMap::new());
    static ref ROFS_MOUNTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ref ACCT_STATE: Mutex<Option<AcctState>> = Mutex::new(None);
    static ref RECORD_LOCKS: Mutex<BTreeMap<FileLockKey, Vec<RecordLock>>> =
        Mutex::new(BTreeMap::new());
    static ref RECORD_LOCK_WAITERS: Mutex<BTreeMap<FileLockKey, VecDeque<Arc<TaskControlBlock>>>> =
        Mutex::new(BTreeMap::new());
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

fn inode_is_immutable_or_append(inode: &Arc<ext4_fs::Inode>) -> bool {
    (inode_fs_flags(inode.inode_num() as u64) & (FS_IMMUTABLE_FL | FS_APPEND_FL)) != 0
}

pub(crate) fn register_rofs_mount(abs: &str) {
    let mut mounts = ROFS_MOUNTS.lock();
    if !mounts.iter().any(|m| m == abs) {
        mounts.push(String::from(abs));
    }
}

pub(crate) fn unregister_rofs_mount(abs: &str) {
    let mut mounts = ROFS_MOUNTS.lock();
    mounts.retain(|m| m != abs);
}

fn path_is_rofs(abs: &str) -> bool {
    let mounts = ROFS_MOUNTS.lock();
    mounts.iter().any(|mnt| {
        if mnt == "/" {
            return true;
        }
        if abs == mnt {
            return true;
        }
        abs.starts_with(mnt) && abs.as_bytes().get(mnt.len()) == Some(&b'/')
    })
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

fn rofs_mount_root_for_abs(abs: &str) -> Option<String> {
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

fn open_fd_flags(flags: usize, o_path: bool) -> u32 {
    let mut fd_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    if (flags & O_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK as u32;
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
    abs == "/sys"
        || abs.starts_with("/sys/")
        || abs == "/dev"
        || abs.starts_with("/dev/")
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
        return Ok(if is_pseudo_path(&abs) {
            AtPath::PseudoAbs(abs)
        } else {
            AtPath::Ext4Abs(abs)
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
        return Ok(if is_pseudo_path(&abs) {
            AtPath::PseudoAbs(abs)
        } else {
            AtPath::Ext4Abs(abs)
        });
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
        return Ok(if is_pseudo_path(&abs) {
            AtPath::PseudoAbs(abs)
        } else {
            AtPath::Ext4Abs(abs)
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

fn resolve_xattr_fd_inode(fd: usize) -> Result<Arc<ext4_fs::Inode>, isize> {
    if fd_has_o_path(fd) {
        return Err(EBADF);
    }
    let Some(file) = get_fd_file(fd) else {
        return Err(EBADF);
    };
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return Err(EBADF);
    };
    Ok(os_inode.ext4_inode())
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
                return resolve_ext4_abs_path(
                    &new_path,
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
        // For ext4 dirfds, we can't reliably reconstruct an absolute path (no reverse lookup).
        if let Some(file) = get_fd_file(dirfd as usize) {
            if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
                normalize_path(pdir.path(), path)
            } else {
                normalize_path(&cwd, path)
            }
        } else {
            return None;
        }
    } else {
        normalize_path(&cwd, path)
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
    Some(FileLockKey {
        dev: inode.device_id() as u64,
        ino: inode.inode_num() as u64,
    })
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

fn lock_conflicts(
    req_type: i16,
    req_start: i64,
    req_end: Option<i64>,
    owner_pid: usize,
    existing: &RecordLock,
) -> bool {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;

    if existing.owner_pid == owner_pid || existing.lock_type == F_UNLCK {
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

fn has_pending_unmasked_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_unmasked_pending(inner.pending_signals, inner.signal_mask, false)
}

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
    const F_DUPFD_CLOEXEC: usize = 1030;
    const F_SETPIPE_SZ: usize = 1031;
    const F_GETPIPE_SZ: usize = 1032;
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;

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
            inner.ensure_fd_flags_len();
            let mut cur = inner.fd_flags[fd];
            if (arg & O_NONBLOCK) != 0 {
                cur |= O_NONBLOCK as u32;
            } else {
                cur &= !(O_NONBLOCK as u32);
            }
            inner.fd_flags[fd] = cur;
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
            if (cur_flags & O_PATH as u32) != 0 {
                flags |= O_PATH;
            }
            if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
                if os_inode.append() {
                    flags |= O_APPEND;
                }
            }
            flags as isize
        }
        F_GETLK | F_SETLK | F_SETLKW => {
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
            let token = get_current_token();
            let flock = match try_read_user_value::<FcntlFlock>(token, arg as *const FcntlFlock) {
                Some(v) => v,
                None => return EFAULT,
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

            if cmd == F_GETLK {
                let owner_pid = current_process().getpid();
                let mut out = flock;
                let conflict = {
                    let table = RECORD_LOCKS.lock();
                    table.get(&key).and_then(|locks| {
                        locks
                            .iter()
                            .find(|lock| lock_conflicts(flock.l_type, start, end, owner_pid, lock))
                            .copied()
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
                    out.l_pid = lock.owner_pid as i32;
                } else {
                    out.l_type = F_UNLCK;
                    out.l_pid = 0;
                }
                if try_write_user_value(token, arg as *mut FcntlFlock, &out).is_err() {
                    return EFAULT;
                }
                0
            } else {
                let blocking = cmd == F_SETLKW;
                let owner_pid = current_process().getpid();
                let waiter_task = if blocking { current_task() } else { None };
                let ret = loop {
                    let mut remove_key = false;
                    let mut conflict_exists = false;
                    let mut should_wake_waiters = false;
                    {
                        let mut table = RECORD_LOCKS.lock();
                        let locks = table.entry(key).or_insert_with(Vec::new);
                        if flock.l_type == F_UNLCK {
                            let before = locks.len();
                            locks.retain(|lock| {
                                !(lock.owner_pid == owner_pid
                                    && ranges_overlap(start, end, lock.start, lock.end))
                            });
                            should_wake_waiters = locks.len() != before;
                            remove_key = locks.is_empty();
                        } else {
                            conflict_exists = locks.iter().any(|lock| {
                                lock_conflicts(flock.l_type, start, end, owner_pid, lock)
                            });
                            if !conflict_exists {
                                let before = locks.len();
                                locks.retain(|lock| {
                                    !(lock.owner_pid == owner_pid
                                        && ranges_overlap(start, end, lock.start, lock.end))
                                });
                                should_wake_waiters = locks.len() != before;
                                locks.push(RecordLock {
                                    owner_pid,
                                    lock_type: flock.l_type,
                                    start,
                                    end,
                                });
                            }
                        }
                        if remove_key {
                            table.remove(&key);
                        }
                    }
                    if should_wake_waiters {
                        wake_record_lock_waiters(key);
                    }

                    if flock.l_type == F_UNLCK {
                        break 0;
                    }
                    if !conflict_exists {
                        break 0;
                    }
                    if !blocking {
                        break EACCES;
                    }
                    let Some(task) = waiter_task.as_ref() else {
                        break EACCES;
                    };
                    enqueue_record_lock_waiter(key, task);
                    let still_conflict = {
                        let table = RECORD_LOCKS.lock();
                        table
                            .get(&key)
                            .map(|locks| {
                                locks.iter().any(|lock| {
                                    lock_conflicts(flock.l_type, start, end, owner_pid, lock)
                                })
                            })
                            .unwrap_or(false)
                    };
                    if !still_conflict {
                        remove_record_lock_waiter(key, task);
                        continue;
                    }
                    if has_pending_unmasked_signal() {
                        remove_record_lock_waiter(key, task);
                        break EINTR;
                    }
                    suspend_current_and_run_next();
                    if has_pending_unmasked_signal() {
                        remove_record_lock_waiter(key, task);
                        break EINTR;
                    }
                };
                if let Some(task) = waiter_task.as_ref() {
                    remove_record_lock_waiter(key, task);
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
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                return EINVAL;
            };
            pipe.pipe_size() as isize
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
            let mut newfd = minfd;
            while newfd < inner.fd_table.len() && inner.fd_table[newfd].is_some() {
                newfd += 1;
            }
            if newfd >= inner.fd_table.len() {
                // Extend fd table to fit.
                if newfd > 4096 {
                    return EMFILE;
                }
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
    let write_intent = writable || (flags & (O_CREAT | O_TRUNC | O_TMPFILE)) != 0;
    let readonly_fs = rofs_for_path(dirfd, &path);
    if write_intent && readonly_fs {
        return EROFS;
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
    let tmpfile_requested = (flags & O_TMPFILE) == O_TMPFILE;
    let create_mode = apply_umask(mode);
    let mut created = false;
    let mut created_parent: Option<alloc::sync::Arc<ext4_fs::Inode>> = None;
    let mut tmpfile_cleanup_parent: Option<alloc::sync::Arc<ext4_fs::Inode>> = None;
    let mut tmpfile_cleanup_name: Option<alloc::string::String> = None;
    let (fsuid, fsgid) = current_fsuid_gid();

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
                    alloc::sync::Arc::new(PseudoShmFile::new(data))
                } else {
                    let Some(data) = shm_get(name) else {
                        return ENOENT;
                    };
                    alloc::sync::Arc::new(PseudoShmFile::new(data))
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
        tmpfile_cleanup,
    ));
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
    if let Some(node) = crate::fs::open_proc_pseudo(path) {
        return Some(node);
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
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/sys", entries)));
    }
    if path == "/dev" || path == "/dev/" {
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
                ino: 6,
                dtype: 6
            },
            PseudoDirent {
                name: alloc::string::String::from("shm"),
                ino: 8,
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
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev", entries)));
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
        Ok(v) => v,
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
        Ok(v) => v,
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
        Ok(v) => v,
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
        Ok(v) => v,
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

/// Linux `renameat(2)` (syscall 38 on riscv64).
pub fn syscall_renameat(olddirfd: isize, oldpath: usize, newdirfd: isize, newpath: usize) -> isize {
    let token = get_current_token();
    let old_s = translated_str(token, oldpath as *const u8);
    let new_s = translated_str(token, newpath as *const u8);
    if old_s.is_empty() || new_s.is_empty() {
        return ENOENT;
    }

    let old_at = match resolve_at_path(olddirfd, &old_s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_at = match resolve_at_path(newdirfd, &new_s) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if matches!(old_at, AtPath::PseudoAbs(_)) || matches!(new_at, AtPath::PseudoAbs(_)) {
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

    if !old_parent.is_dir() || !new_parent.is_dir() {
        return ENOTDIR;
    }
    if !inode_mode_allows_uid_gid(&old_parent, 3, fsuid, fsgid)
        || !inode_mode_allows_uid_gid(&new_parent, 3, fsuid, fsgid)
    {
        return EACCES;
    }
    if old_parent.find(&old_name).is_none() {
        return ENOENT;
    }
    if rofs_for_path(olddirfd, &old_s) || rofs_for_path(newdirfd, &new_s) {
        return EROFS;
    }

    // ext4 implementation only supports rename within the same directory for now.
    if old_parent.inode_num() != new_parent.inode_num() {
        return EXDEV;
    }

    match old_parent.rename(&old_name, &new_name) {
        Ok(_) => 0,
        Err(e) => ext4_err_to_errno(e),
    }
}

/// Linux `renameat2(2)` (syscall 276 on riscv64).
pub fn syscall_renameat2(
    olddirfd: isize,
    oldpath: usize,
    newdirfd: isize,
    newpath: usize,
    flags: usize,
) -> isize {
    if flags != 0 {
        return EINVAL;
    }
    syscall_renameat(olddirfd, oldpath, newdirfd, newpath)
}

pub fn syscall_close(fd: usize) -> isize {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return EBADF;
    }
    let _ = inner.clear_fd(fd);
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

    for fd in first..=end {
        if set_cloexec {
            if inner.is_fd_open(fd) {
                inner.fd_flags[fd] |= FD_CLOEXEC;
            }
        } else {
            let _ = inner.clear_fd(fd);
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
    file.read(buf) as isize
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
            if os_inode.flush().is_err() {
                return EIO;
            }
        }
    }
    if hit_fsize_limit {
        let pid = current_process().getpid();
        queue_process_signal(pid, SIGXFSZ_NUM);
    }
    written
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
    if !file.readable() {
        return EBADF;
    }

    // ext4 regular files
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = {
            let _ext4_guard = ext4_lock();
            inode.is_dir()
        };
        if is_dir {
            return ESPIPE;
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
            copy_to_user(token, user_ptr as *mut u8, &kbuf[..n]);
            total += n;
            off += n;
            user_ptr += n;
            if n < want {
                break;
            }
        }
        return total as isize;
    }

    // Seekable pseudo files: emulate by temporarily adjusting the per-fd offset.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        if pf.len().is_none() {
            return ESPIPE;
        }
        let old = pf.offset();
        pf.set_offset(pos as usize);
        let buf = UserBuffer::new(translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ));
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
    if !file.writable() {
        return EBADF;
    }

    // ext4 regular files
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = {
            let _ext4_guard = ext4_lock();
            inode.is_dir()
        };
        if is_dir {
            return ESPIPE;
        }

        let mut write_len = len;
        let mut hit_fsize_limit = false;
        let fsize_limit = {
            let process = current_process();
            let inner = process.borrow_mut();
            inner.rlimit_fsize_cur
        };
        if fsize_limit != u64::MAX {
            let start = pos as u64;
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
        let mut off = pos as usize;
        let mut user_ptr = buffer;
        const CHUNK_MAX: usize = 16 * 1024;
        let buf_cap = core::cmp::min(write_len, CHUNK_MAX);
        let mut kbuf = vec![0u8; buf_cap];
        while total < write_len {
            let want = core::cmp::min(write_len - total, buf_cap);
            copy_from_user(token, user_ptr as *const u8, &mut kbuf[..want]);
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
                    break;
                }
            }
        }
        if hit_fsize_limit {
            let pid = current_process().getpid();
            queue_process_signal(pid, SIGXFSZ_NUM);
        }
        return total as isize;
    }

    // Seekable pseudo files: emulate by temporarily adjusting the per-fd offset.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        if pf.len().is_none() {
            return ESPIPE;
        }
        let old = pf.offset();
        pf.set_offset(pos as usize);
        let buf = UserBuffer::new(translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ));
        let n = file.write(buf) as isize;
        pf.set_offset(old);
        return n;
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
    drop(inner);

    // Linux ABI: pipefd points to `int pipefd[2]` (i32).
    write_user_value(token, pipefd as *mut i32, &(read_fd as i32));
    write_user_value(
        token,
        (pipefd + core::mem::size_of::<i32>()) as *mut i32,
        &(write_fd as i32),
    );
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
    if inner.is_fd_open(newfd) {
        let _ = inner.clear_fd(newfd);
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

pub fn syscall_unlinkat(dirfd: isize, pathname: usize, _flags: usize) -> isize {
    const AT_REMOVEDIR: usize = 0x200;
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
        let remove_dir = (_flags & AT_REMOVEDIR) != 0;
        // Minimal `/dev/shm` support for POSIX `shm_unlink`.
        if abs == "/dev/shm" || abs == "/dev/shm/" {
            return if remove_dir { EROFS } else { EISDIR };
        }
        if let Some(name) = shm_object_name(abs) {
            if remove_dir {
                return ENOTDIR;
            }
            return if shm_remove(name) { 0 } else { ENOENT };
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

    let remove_dir = (_flags & AT_REMOVEDIR) != 0;

    // Validate target type: unlink vs rmdir semantics.
    let Some(child) = parent.find(&name) else {
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
    if rofs_for_path(dirfd, &path) {
        return EROFS;
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
    drop(_ext4_guard);
    flush_open_inode_views(&inode);
    let ret = truncate_regular_inode(&inode, length);
    if ret == 0 {
        touch_inode_mtime_ctime_now(&inode);
    }
    ret
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

fn fill_statfs(st_ptr: usize) -> isize {
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
        f_flags: 0,
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
    fill_statfs(st_ptr)
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
            fill_statfs(st_ptr)
        }
        AtPath::Ext4Abs(_) | AtPath::Ext4Rel { .. } => {
            let (fsuid, fsgid) = current_fsuid_gid();
            let _ext4_guard = ext4_lock();
            if let Err(e) = resolve_at_inode(&at, fsuid, fsgid, true) {
                return e;
            }
            fill_statfs(st_ptr)
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
    Statx {
        stx_mask: STATX_BASIC_STATS,
        stx_blksize: st.st_blksize,
        stx_attributes: 0,
        stx_nlink: st.st_nlink,
        stx_uid: st.st_uid,
        stx_gid: st.st_gid,
        stx_mode: st.st_mode as u16,
        __spare0: 0,
        stx_ino: st.st_ino,
        stx_size: st.st_size.max(0) as u64,
        stx_blocks: st.st_blocks,
        stx_attributes_mask: 0,
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
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<PseudoShmFile>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
        || file.as_any().downcast_ref::<Pipe>().is_some()
    {
        let mode: u32 = if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if file.as_any().downcast_ref::<Pipe>().is_some() {
            0o010600
        } else if file.as_any().downcast_ref::<PseudoBlock>().is_some() {
            0o060600
        } else if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if file.as_any().downcast_ref::<RtcFile>().is_some() {
            0o100666
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
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
            shm.len() as i64
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
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<PseudoShmFile>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
        || file.as_any().downcast_ref::<Pipe>().is_some()
    {
        let mode: u32 = if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if file.as_any().downcast_ref::<Pipe>().is_some() {
            0o010600
        } else if file.as_any().downcast_ref::<PseudoBlock>().is_some() {
            0o060600
        } else if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if file.as_any().downcast_ref::<RtcFile>().is_some() {
            0o100666
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
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
            shm.len() as i64
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
    // A full ext4 sync for every `fsync` call is prohibitively expensive for
    // micro-benchmarks like iozone (it may call `fsync` very frequently).
    // Flush the per-fd write buffer so subsequent reads from other fds see data.
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if os_inode.readonly_fs() {
            return 0;
        }
        let _ = os_inode.flush();
    }
    0
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
        } else if abs == "/dev/root" {
            0o060600
        } else if node.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if abs == "/dev/null" || abs == "/dev/zero" || abs == "/dev/misc/rtc" {
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
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = node.as_any().downcast_ref::<PseudoShmFile>() {
            shm.len() as i64
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
        } else if abs == "/dev/root" {
            0o060600
        } else if node.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if abs == "/dev/null" || abs == "/dev/zero" || abs == "/dev/misc/rtc" {
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
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = node.as_any().downcast_ref::<PseudoShmFile>() {
            shm.len() as i64
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
        return written as isize;
    }

    let ext4_guard = ext4_lock();
    if !inode.is_dir() {
        return ENOTDIR;
    };

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
    written as isize
}

/// Linux `lseek(2)` (syscall 62 on riscv64).
///
/// Needed by glibc directory APIs (`opendir`/`readdir`/`rewinddir`/`telldir`).
pub fn syscall_lseek(fd: usize, offset: isize, whence: usize) -> isize {
    const SEEK_SET: usize = 0;
    const SEEK_CUR: usize = 1;
    const SEEK_END: usize = 2;

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

    ESPIPE
}
