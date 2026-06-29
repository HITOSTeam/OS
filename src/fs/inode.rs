//! Inode abstraction for ext4 filesystem

use super::{File, POLLIN, POLLOUT};
use crate::drivers::{BLOCK_DEVICE, USER_BLOCK_DEVICE};
use crate::mm::UserBuffer;
use crate::println;
use crate::task::manager::PID2PCB;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, Ordering};
use ext4_fs::{Ext4FileSystem, Inode};
use lazy_static::*;
use spin::Mutex;

/// Yield-aware spinlock for serializing ext4 filesystem operations.
///
/// Unlike a pure spinlock, this lock cooperatively yields the current task
/// (via `suspend_current_and_run_next`) when contended and a task context
/// is available. During early boot (before the task system is initialized),
/// it falls back to a spin-loop hint. This avoids wasting CPU on busy-wait
/// while still working correctly outside of a multitasking context.
struct Ext4Lock {
    held: AtomicBool,
}

impl Ext4Lock {
    const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
        }
    }

    fn lock(&self) {
        loop {
            // Attempt to acquire: CAS is more efficient than swap on
            // weakly-ordered architectures (RISC-V, LoongArch) because it
            // avoids writing when the lock is already held.
            if self
                .held
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            // Hint the CPU we are in a spin-wait before deciding to yield.
            spin_loop();
            if crate::task::processor::current_task().is_some() {
                crate::task::processor::suspend_current_and_run_next();
            }
        }
    }

    fn unlock(&self) {
        self.held.store(false, Ordering::Release);
    }
}

pub(crate) struct Ext4Guard {
    lock: Arc<Ext4Lock>,
}

impl Drop for Ext4Guard {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

// Serialize ext4 operations across harts.
lazy_static! {
    static ref EXT4_LOCK: Arc<Ext4Lock> = Arc::new(Ext4Lock::new());
    static ref DEBUG_IOZONE_INODES: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static ref DEFERRED_UNLINK_CLEANUP: Mutex<BTreeMap<(usize, u32), TmpfileCleanup>> =
        Mutex::new(BTreeMap::new());
    static ref INODE_PATH_HINTS: Mutex<BTreeMap<(usize, u32), String>> =
        Mutex::new(BTreeMap::new());
}

pub(crate) fn ext4_lock() -> Ext4Guard {
    let lock = Arc::clone(&EXT4_LOCK);
    lock.lock();
    Ext4Guard { lock }
}

pub(crate) fn debug_track_iozone_inode(path: &str, inode_num: u32) {
    if !crate::debug_config::DEBUG_IOZONE_FS {
        return;
    }
    if !path.contains("iozone.tmp") {
        return;
    }
    let mut tracked = DEBUG_IOZONE_INODES.lock();
    if tracked.iter().any(|&n| n == inode_num) {
        return;
    }
    tracked.push(inode_num);
    println!("[iozone-debug] track inode={} path='{}'", inode_num, path);
}

pub(crate) fn note_inode_path_hint(inode: &Arc<Inode>, path: &str) {
    INODE_PATH_HINTS
        .lock()
        .insert((inode.device_id(), inode.inode_num()), String::from(path));
}

pub(crate) fn inode_path_hint(inode: &Arc<Inode>) -> Option<String> {
    INODE_PATH_HINTS
        .lock()
        .get(&(inode.device_id(), inode.inode_num()))
        .cloned()
}

fn normalize_inode_abs_path(cwd: &str, path: &str) -> String {
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

fn split_inode_parent_and_name(path: &str) -> Option<(&str, &str)> {
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

fn join_inode_path(base: &str, name: &str) -> String {
    if base == "/" {
        alloc::format!("/{name}")
    } else {
        alloc::format!("{base}/{name}")
    }
}

fn find_inode_path_in_subtree(
    dir: &Arc<Inode>,
    base: &str,
    target_dev: usize,
    target_ino: u32,
    depth: usize,
) -> Option<String> {
    if depth == 0 {
        return None;
    }
    for (name, _ino, _ftype) in dir.dir_entries() {
        if name == "." || name == ".." {
            continue;
        }
        // `/proc` is pseudo-fs state; don't leak an ext4 placeholder entry here.
        if base == "/" && name == "proc" {
            continue;
        }
        let Some(child) = dir.find(&name) else {
            continue;
        };
        let path = join_inode_path(base, &name);
        if child.device_id() == target_dev && child.inode_num() == target_ino {
            return Some(path);
        }
        if child.is_dir() {
            if let Some(found) =
                find_inode_path_in_subtree(&child, &path, target_dev, target_ino, depth - 1)
            {
                return Some(found);
            }
        }
    }
    None
}

pub(crate) fn inode_path_in_roots(target: &Arc<Inode>) -> Option<String> {
    let target_dev = target.device_id();
    let target_ino = target.inode_num();
    let _guard = ext4_lock();

    let primary = root_inode_for_path("/");
    if primary.device_id() == target_dev && primary.inode_num() == target_ino {
        return Some(String::from("/"));
    }
    if let Some(found) = find_inode_path_in_subtree(&primary, "/", target_dev, target_ino, 64) {
        return Some(found);
    }

    let secondary = secondary_root_inode()?;
    if secondary.device_id() == target_dev && secondary.inode_num() == target_ino {
        return Some(String::from("/"));
    }
    find_inode_path_in_subtree(&secondary, "/", target_dev, target_ino, 64)
}

pub(crate) fn path_resolves_to_inode(path: &str, target: &Arc<Inode>) -> bool {
    let _guard = ext4_lock();
    let Some(found) = find_path_in_roots(path) else {
        return false;
    };
    found.device_id() == target.device_id() && found.inode_num() == target.inode_num()
}

/// Caller must already hold `ext4_lock()`.
pub(crate) fn resolve_final_symlink_abs_path_locked(abs: &str) -> String {
    let mut current = String::from(abs);
    for _ in 0..40 {
        if current == "/" {
            break;
        }
        let Some((parent, name)) = split_inode_parent_and_name(&current) else {
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
            normalize_inode_abs_path("/", &target)
        } else {
            normalize_inode_abs_path(parent_abs, &target)
        };
    }
    current
}

pub(crate) fn resolve_final_symlink_abs_path(abs: &str) -> String {
    let _guard = ext4_lock();
    resolve_final_symlink_abs_path_locked(abs)
}

fn debug_iozone_tracked(inode_num: u32) -> bool {
    if !crate::debug_config::DEBUG_IOZONE_FS {
        return false;
    }
    DEBUG_IOZONE_INODES.lock().iter().any(|&n| n == inode_num)
}

/// A wrapper around a filesystem inode to implement File trait
pub struct OSInode {
    readable: bool,
    writable: bool,
    regular_file_poll_ready: bool,
    append: bool,
    readonly_fs: bool,
    replace_on_write: bool,
    tmpfile_cleanup: Option<TmpfileCleanup>,
    inner: Mutex<OSInodeInner>,
}

struct TmpfileCleanup {
    parent: Arc<Inode>,
    name: String,
}

/// The OS inode inner
pub struct OSInodeInner {
    offset: usize,
    dir_offset: usize,
    inode: Arc<Inode>,
    write_buf_off: usize,
    write_buf: Vec<u8>,
    read_buf_off: usize,
    read_buf_valid: usize,
    read_buf: Vec<u8>,
}

const READBUF_MAX: usize = 128 * 1024;
const READBUF_MIN: usize = 4 * 1024;
const WRITEBUF_MAX: usize = 128 * 1024;

impl OSInode {
    /// Construct an OS inode from an inode
    pub fn new(readable: bool, writable: bool, inode: Arc<Inode>) -> Self {
        Self::new_with_append(readable, writable, false, inode)
    }

    pub fn new_with_append(
        readable: bool,
        writable: bool,
        append: bool,
        inode: Arc<Inode>,
    ) -> Self {
        Self::new_with_append_rofs(readable, writable, append, inode, false)
    }

    pub fn new_with_append_rofs(
        readable: bool,
        writable: bool,
        append: bool,
        inode: Arc<Inode>,
        readonly_fs: bool,
    ) -> Self {
        Self::new_with_append_rofs_tmp_cleanup(
            readable,
            writable,
            append,
            inode,
            readonly_fs,
            false,
            None,
        )
    }

    #[allow(dead_code)]
    pub fn new_replace_on_write(readable: bool, writable: bool, inode: Arc<Inode>) -> Self {
        Self::new_with_append_rofs_tmp_cleanup(readable, writable, false, inode, false, true, None)
    }

    pub fn new_with_append_rofs_tmp_cleanup(
        readable: bool,
        writable: bool,
        append: bool,
        inode: Arc<Inode>,
        readonly_fs: bool,
        replace_on_write: bool,
        tmpfile_cleanup: Option<(Arc<Inode>, String)>,
    ) -> Self {
        let regular_file_poll_ready = inode.is_file();
        Self {
            readable,
            writable,
            regular_file_poll_ready,
            append,
            readonly_fs,
            replace_on_write,
            tmpfile_cleanup: tmpfile_cleanup.map(|(parent, name)| TmpfileCleanup { parent, name }),
            inner: Mutex::new(OSInodeInner {
                offset: 0,
                dir_offset: 0,
                inode,
                write_buf_off: 0,
                write_buf: Vec::new(),
                read_buf_off: 0,
                read_buf_valid: 0,
                read_buf: Vec::new(),
            }),
        }
    }

    pub fn append(&self) -> bool {
        self.append
    }

    pub fn readonly_fs(&self) -> bool {
        self.readonly_fs
    }

    /// Read all data inside an inode into vector
    pub fn read_all(&self) -> Vec<u8> {
        let mut inner = self.inner.lock();
        if self.writable {
            let _ = Self::flush_inner(&mut inner);
        }
        let file_size = inner.inode.size() as usize;

        let mut buffer = [0u8; 4096]; // Use larger buffer for ext4 (4K blocks)
        let mut v: Vec<u8> = Vec::new();
        let mut total_read = 0usize;

        loop {
            let len = {
                let _fs_guard = ext4_lock();
                inner.inode.read_at(inner.offset, &mut buffer)
            };
            if len == 0 {
                break;
            }
            inner.offset += len;
            total_read += len;
            v.extend_from_slice(&buffer[..len]);

            if total_read >= file_size {
                break;
            }
        }

        v
    }

    pub fn ext4_inode(&self) -> Arc<Inode> {
        self.inner.lock().inode.clone()
    }

    /// Return the end offset of buffered (not-yet-flushed) writes.
    ///
    /// This is used to report a correct file size to userspace (`fstat`, `lseek(SEEK_END)`)
    /// even when we are buffering writes in memory.
    pub fn pending_write_end(&self) -> usize {
        let inner = self.inner.lock();
        inner.write_buf_off.saturating_add(inner.write_buf.len())
    }

    /// Read from this inode at the given offset without updating the file offset.
    pub fn pread_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        let mut inner = self.inner.lock();
        if self.writable {
            let _ = Self::flush_inner(&mut inner);
        }
        let inode_num = inner.inode.inode_num();

        if inner.read_buf.len() < READBUF_MAX {
            inner.read_buf.resize(READBUF_MAX, 0);
            inner.read_buf_off = 0;
            inner.read_buf_valid = 0;
        }

        let mut pos = offset;
        let mut done = 0usize;
        while done < buf.len() {
            let need_refill = inner.read_buf_valid == 0
                || pos < inner.read_buf_off
                || pos >= inner.read_buf_off + inner.read_buf_valid;
            if need_refill {
                let refill_len =
                    core::cmp::max(READBUF_MIN, core::cmp::min(READBUF_MAX, buf.len() - done));
                inner.read_buf_off = pos;
                let inode = inner.inode.clone();
                let off = pos;
                let n = {
                    let _fs_guard = ext4_lock();
                    inode.read_at(off, &mut inner.read_buf[..refill_len])
                };
                inner.read_buf_valid = n;
                if debug_iozone_tracked(inode_num) {
                    let size = inode.size() as usize;
                    println!(
                        "[iozone-debug] pread inode={} off={} len={} size={}",
                        inode_num, off, n, size
                    );
                }
                if n == 0 {
                    break;
                }
            }

            let cache_off = pos - inner.read_buf_off;
            let avail = inner.read_buf_valid.saturating_sub(cache_off);
            if avail == 0 {
                break;
            }
            let n = core::cmp::min(avail, buf.len() - done);
            buf[done..done + n].copy_from_slice(&inner.read_buf[cache_off..cache_off + n]);
            done += n;
            pos += n;
        }
        done
    }

    /// Write to this inode at the given offset without updating the file offset.
    pub fn pwrite_at(&self, offset: usize, buf: &[u8]) -> Result<usize, ()> {
        let mut inner = self.inner.lock();
        if self.replace_on_write && offset == 0 && inner.write_buf.is_empty() {
            self.clear_inode_for_replace_write(&mut inner, offset)?;
        }
        // Writes via pwrite/pwritev must invalidate the buffered read cache.
        inner.read_buf_valid = 0;
        let inode_num = inner.inode.inode_num();
        let size_before = inner.inode.size() as usize;

        if buf.len() >= WRITEBUF_MAX {
            if !inner.write_buf.is_empty() {
                if Self::flush_inner(&mut inner).is_err() {
                    return Err(());
                }
                inner.read_buf_valid = 0;
            }
            let result = {
                let _fs_guard = ext4_lock();
                inner.inode.write_at(offset, buf)
            };
            if debug_iozone_tracked(inode_num) {
                let size_after = inner.inode.size() as usize;
                match result {
                    Ok(n) => {
                        println!(
                            "[iozone-debug] pwrite inode={} off={} len={} wrote={} size={}->{}",
                            inode_num,
                            offset,
                            buf.len(),
                            n,
                            size_before,
                            size_after
                        );
                    }
                    Err(_) => {
                        println!(
                            "[iozone-debug] pwrite inode={} off={} len={} err size={}->{}",
                            inode_num,
                            offset,
                            buf.len(),
                            size_before,
                            size_after
                        );
                    }
                }
            }
            return result.map_err(|_| ());
        }

        if !inner.write_buf.is_empty()
            && offset != inner.write_buf_off.saturating_add(inner.write_buf.len())
        {
            if Self::flush_inner(&mut inner).is_err() {
                return Err(());
            }
            inner.read_buf_valid = 0;
        }

        if inner.write_buf.is_empty() {
            inner.write_buf_off = offset;
        }

        inner.write_buf.extend_from_slice(buf);
        if inner.write_buf.len() >= WRITEBUF_MAX {
            if Self::flush_inner(&mut inner).is_err() {
                return Err(());
            }
            return Ok(buf.len());
        }

        Ok(buf.len())
    }

    /// Flush buffered writes to disk. Caller must already hold `self.inner`.
    fn flush_inner(inner: &mut OSInodeInner) -> Result<(), ext4_fs::Ext4Error> {
        if inner.write_buf.is_empty() {
            return Ok(());
        }
        let off = inner.write_buf_off;
        let data = core::mem::take(&mut inner.write_buf);
        let inode_num = inner.inode.inode_num();
        let size_before = inner.inode.size() as usize;
        let result = {
            let _fs_guard = ext4_lock();
            inner.inode.write_at(off, &data)
        };
        if debug_iozone_tracked(inode_num) {
            let size_after = inner.inode.size() as usize;
            match result {
                Ok(n) => {
                    crate::println!(
                        "[iozone-debug] flush inode={} off={} len={} wrote={} size={}->{}",
                        inode_num,
                        off,
                        data.len(),
                        n,
                        size_before,
                        size_after
                    );
                }
                Err(_) => {
                    crate::println!(
                        "[iozone-debug] flush inode={} off={} len={} err size={}->{}",
                        inode_num,
                        off,
                        data.len(),
                        size_before,
                        size_after
                    );
                }
            }
        }
        match result {
            Ok(n) if n == data.len() => Ok(()),
            Ok(_) => {
                inner.write_buf_off = off;
                inner.write_buf = data;
                Err(ext4_fs::Ext4Error::NoSpace)
            }
            Err(e) => {
                inner.write_buf_off = off;
                inner.write_buf = data;
                Err(e)
            }
        }
    }

    pub fn flush_with_error(&self) -> Result<(), ext4_fs::Ext4Error> {
        let mut inner = self.inner.lock();
        Self::flush_inner(&mut inner)
    }

    pub fn flush(&self) -> Result<(), ()> {
        self.flush_with_error().map_err(|_| ())
    }

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        let mut inner = self.inner.lock();
        if self.writable {
            let _ = Self::flush_inner(&mut inner);
        }
        inner.offset = offset;
        inner.read_buf_valid = 0;
    }

    fn clear_inode_for_replace_write(
        &self,
        inner: &mut OSInodeInner,
        write_offset: usize,
    ) -> Result<(), ()> {
        if !self.replace_on_write || !inner.write_buf.is_empty() || write_offset != 0 {
            return Ok(());
        }
        let result = {
            let _fs_guard = ext4_lock();
            inner.inode.clear()
        };
        match result {
            Ok(_) => {
                inner.read_buf_valid = 0;
                Ok(())
            }
            Err(_) => Err(()),
        }
    }

    pub fn dir_offset(&self) -> usize {
        self.inner.lock().dir_offset
    }

    pub fn set_dir_offset(&self, offset: usize) {
        self.inner.lock().dir_offset = offset;
    }
}

pub(crate) fn register_deferred_unlink_cleanup(
    inode: &Arc<Inode>,
    parent: Arc<Inode>,
    name: String,
) {
    let key = (inode.device_id(), inode.inode_num());
    DEFERRED_UNLINK_CLEANUP
        .lock()
        .insert(key, TmpfileCleanup { parent, name });
}

fn has_open_inode_fd_refs(device_id: usize, inode_num: u32) -> bool {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            // Cannot inspect this process (lock held) — conservatively assume
            // it may reference the inode.  The cleanup will be retried on the
            // next OSInode::drop for the same inode.
            return true;
        };
        let files = Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        if files
            .lock()
            .iter_files_snapshot()
            .into_iter()
            .any(|(_fd, file)| {
                file.as_any()
                    .downcast_ref::<OSInode>()
                    .map(|o| {
                        let inode = o.ext4_inode();
                        inode.inode_num() == inode_num && inode.device_id() == device_id
                    })
                    .unwrap_or(false)
            })
        {
            return true;
        }
    }
    false
}

/// Attempt to clean up any lingering deferred-unlink entries whose inodes
/// no longer have open file descriptors.  Called opportunistically after a
/// successful cleanup to prevent orphan accumulation.
fn sweep_deferred_unlinks() {
    let keys: Vec<(usize, u32)> = { DEFERRED_UNLINK_CLEANUP.lock().keys().cloned().collect() };
    for key in keys {
        // Only proceed if we can definitively confirm no refs remain.
        if !has_open_inode_fd_refs(key.0, key.1) {
            if let Some(cleanup) = DEFERRED_UNLINK_CLEANUP.lock().remove(&key) {
                let _fs_guard = ext4_lock();
                let _ = cleanup.parent.unlink(&cleanup.name);
            }
        }
    }
}

lazy_static! {
    static ref DISK0_FS: Arc<spin::Mutex<Ext4FileSystem>> = {
        Ext4FileSystem::open(BLOCK_DEVICE.clone())
    };

    static ref DISK1_FS: Option<Arc<spin::Mutex<Ext4FileSystem>>> = {
        USER_BLOCK_DEVICE
            .as_ref()
            .and_then(|dev| Ext4FileSystem::try_open(dev.clone()).ok())
    };

    static ref DISK0_ROOT: Arc<Inode> = {
        Arc::new(Ext4FileSystem::root_inode(&DISK0_FS))
    };

    static ref DISK1_ROOT: Option<Arc<Inode>> = {
        DISK1_FS
            .as_ref()
            .map(|fs| Arc::new(Ext4FileSystem::root_inode(fs)))
    };

    static ref ROOT_SELECTION: RootSelection = RootSelection::new(
        &DISK0_ROOT,
        &DISK1_ROOT,
        &DISK0_FS,
        &DISK1_FS,
    );

    /// ext4 filesystem handle (primary root device).
    pub static ref EXT4_FS: Arc<spin::Mutex<Ext4FileSystem>> = ROOT_SELECTION.primary_fs.clone();

    /// Root inode of the primary filesystem.
    pub static ref ROOT_INODE: Arc<Inode> = ROOT_SELECTION.primary_root.clone();

    /// Optional secondary filesystem (if present).
    pub static ref SECONDARY_EXT4_FS: Option<Arc<spin::Mutex<Ext4FileSystem>>> =
        ROOT_SELECTION.secondary_fs.clone();

    /// Root inode of the secondary filesystem (if present).
    pub static ref SECONDARY_ROOT_INODE: Option<Arc<Inode>> =
        ROOT_SELECTION.secondary_root.clone();

    /// User directory inode (for ext4, apps are in /user).
    pub static ref USER_INODE: Arc<Inode> = {
        ROOT_INODE
            .find("user")
            .expect("[ext4] /user directory not found!")
    };
}

pub(crate) fn root_inode_for_path(path: &str) -> Arc<Inode> {
    let _ = path;
    ROOT_INODE.clone()
}

pub(crate) fn secondary_root_inode() -> Option<Arc<Inode>> {
    SECONDARY_ROOT_INODE.as_ref().map(Arc::clone)
}

/// Find a path in the primary root, falling back to the secondary root when missing.
///
/// Caller should hold `ext4_lock()` if concurrent ext4 access is possible.
pub(crate) fn find_path_in_roots(path: &str) -> Option<Arc<Inode>> {
    if let Some(inode) = ROOT_INODE.find_path(path) {
        return Some(inode);
    }
    SECONDARY_ROOT_INODE.as_ref()?.find_path(path)
}
//if a disk has a /user directory while the other does not, prefer the one with /user
//todo: better solution.
struct RootSelection {
    primary_root: Arc<Inode>,
    secondary_root: Option<Arc<Inode>>,
    primary_fs: Arc<spin::Mutex<Ext4FileSystem>>,
    #[allow(dead_code)]
    secondary_fs: Option<Arc<spin::Mutex<Ext4FileSystem>>>,
}

impl RootSelection {
    fn new(
        root0: &Arc<Inode>,
        root1: &Option<Arc<Inode>>,
        fs0: &Arc<spin::Mutex<Ext4FileSystem>>,
        fs1: &Option<Arc<spin::Mutex<Ext4FileSystem>>>,
    ) -> Self {
        // Avoid taking ext4_lock() here; this may run during lazy_static initialization
        // while a caller already holds the lock.
        let has_user0 = root0.find("user").is_some();
        let has_user1 = root1
            .as_ref()
            .map(|root| root.find("user").is_some())
            .unwrap_or(false);

        if root1.is_some() && !has_user0 && has_user1 {
            RootSelection {
                primary_root: root1.as_ref().unwrap().clone(),
                secondary_root: Some(root0.clone()),
                primary_fs: fs1.as_ref().unwrap().clone(),
                secondary_fs: Some(fs0.clone()),
            }
        } else {
            RootSelection {
                primary_root: root0.clone(),
                secondary_root: root1.clone(),
                primary_fs: fs0.clone(),
                secondary_fs: fs1.clone(),
            }
        }
    }
}

/// List all files in the filesystem
#[allow(dead_code)]
pub fn list_apps() {
    let _fs_guard = ext4_lock();
    println!("/**** APPS ****");
    println!("[ext4] list_apps start");
    let mut count = 0usize;
    for app in USER_INODE.ls() {
        println!("{}", app);
        count += 1;
    }
    println!("[ext4] list_apps done count={}", count);
    println!("**************/");
}

bitflags! {
    /// Open file flags
    pub struct OpenFlags: u32 {
        /// Read only
        const RDONLY = 0;
        /// Write only
        const WRONLY = 1 << 0;
        /// Read & Write
        const RDWR = 1 << 1;
        /// Allow create
        const CREATE = 1 << 9;
        /// Clear file and return an empty one
        const TRUNC = 1 << 10;
    }
}

impl OpenFlags {
    /// Do not check validity for simplicity
    /// Return (readable, writable)
    pub fn read_write(&self) -> (bool, bool) {
        if self.is_empty() {
            (true, false)
        } else if self.contains(Self::WRONLY) {
            (false, true)
        } else {
            (true, true)
        }
    }
}

/// Open file with flags (read-only for ext4)
/// Files are located in /user directory
pub fn open_file(name: &str, flags: OpenFlags) -> Option<Arc<OSInode>> {
    let (readable, writable) = flags.read_write();
    let _fs_guard = ext4_lock();

    let raw = name.trim_matches('\0');
    if raw.is_empty() {
        return None;
    }

    // Default: resolve relative paths from /user to keep exec() behavior.
    let is_abs = raw.starts_with('/');
    let base_dir: Arc<Inode> = if is_abs {
        root_inode_for_path(raw)
    } else {
        Arc::clone(&USER_INODE)
    };

    let mut inode = if is_abs {
        find_path_in_roots(raw)
    } else {
        base_dir.find_path(raw)
    };

    // Keep compatibility: exec("foo") can omit ".bin".
    if inode.is_none() && !raw.contains('/') && !raw.ends_with(".bin") {
        let name_with_bin = alloc::format!("{}.bin", raw);
        inode = base_dir.find_path(&name_with_bin);
    }

    // CREATE: create the file if it does not exist.
    if inode.is_none() && flags.contains(OpenFlags::CREATE) {
        let (parent_path, file_name) = split_parent_and_name(raw)?;
        let parent = if parent_path.is_empty() {
            Arc::clone(&base_dir)
        } else if is_abs {
            let parent_abs = alloc::format!("/{}", parent_path);
            find_path_in_roots(&parent_abs)?
        } else {
            base_dir.find_path(parent_path)?
        };
        inode = parent.create_file(file_name).ok();
    }

    let inode = inode?;

    // TRUNC: clear file contents.
    if flags.contains(OpenFlags::TRUNC) {
        let _ = inode.clear();
    }

    Some(Arc::new(OSInode::new(readable, writable, inode)))
}

impl File for OSInode {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn poll_mask(&self) -> i16 {
        if self.regular_file_poll_ready {
            return POLLIN | POLLOUT;
        }
        let mut mask = 0;
        if self.readable {
            mask |= POLLIN;
        }
        if self.writable {
            mask |= POLLOUT;
        }
        mask
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        if self.writable {
            let _ = Self::flush_inner(&mut inner);
        }
        let mut total_read_size = 0usize;

        if inner.read_buf.len() < READBUF_MAX {
            inner.read_buf.resize(READBUF_MAX, 0);
            inner.read_buf_off = 0;
            inner.read_buf_valid = 0;
        }

        for slice in buf.buffers.iter_mut() {
            let mut out: &mut [u8] = *slice;
            while !out.is_empty() {
                let need_refill = inner.read_buf_valid == 0
                    || inner.offset < inner.read_buf_off
                    || inner.offset >= inner.read_buf_off + inner.read_buf_valid;

                if need_refill {
                    let sequential = inner.read_buf_valid > 0
                        && inner.offset == inner.read_buf_off.saturating_add(inner.read_buf_valid);
                    let refill_len = if sequential {
                        READBUF_MAX
                    } else {
                        core::cmp::min(READBUF_MAX, core::cmp::max(out.len(), READBUF_MIN))
                    };
                    inner.read_buf_off = inner.offset;
                    let inode = inner.inode.clone();
                    let off = inner.read_buf_off;
                    let n = {
                        let _fs_guard = ext4_lock();
                        inode.read_at(off, &mut inner.read_buf[..refill_len])
                    };
                    inner.read_buf_valid = n;
                    let inode_num = inode.inode_num();
                    if debug_iozone_tracked(inode_num) {
                        let size = inode.size() as usize;
                        println!(
                            "[iozone-debug] read inode={} off={} len={} size={}",
                            inode_num, off, n, size
                        );
                    }
                    if n == 0 {
                        return total_read_size;
                    }
                }

                let buf_off = inner.offset - inner.read_buf_off;
                let avail = inner.read_buf_valid.saturating_sub(buf_off);
                if avail == 0 {
                    continue;
                }

                let n = core::cmp::min(avail, out.len());
                out[..n].copy_from_slice(&inner.read_buf[buf_off..buf_off + n]);
                inner.offset += n;
                total_read_size += n;
                out = &mut out[n..];
            }
        }
        total_read_size
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        if self.append {
            if !inner.write_buf.is_empty() {
                let off = inner.write_buf_off;
                let len = inner.write_buf.len();
                let inode_num = inner.inode.inode_num();
                let size_before = inner.inode.size() as usize;
                let result = {
                    let _fs_guard = ext4_lock();
                    inner.inode.write_at(off, &inner.write_buf)
                };
                if debug_iozone_tracked(inode_num) {
                    let size_after = inner.inode.size() as usize;
                    match result {
                        Ok(n) => {
                            println!(
                                "[iozone-debug] write inode={} off={} len={} wrote={} size={}->{}",
                                inode_num, off, len, n, size_before, size_after
                            );
                        }
                        Err(_) => {
                            println!(
                                "[iozone-debug] write inode={} off={} len={} err size={}->{}",
                                inode_num, off, len, size_before, size_after
                            );
                        }
                    }
                }
                let _ = result;
                inner.write_buf.clear();
            }
            inner.offset = inner.inode.size() as usize;
        }
        let mut total_write_size = 0usize;

        let current_offset = inner.offset;
        if self
            .clear_inode_for_replace_write(&mut inner, current_offset)
            .is_err()
        {
            return 0;
        }

        for slice in _buf.buffers.iter() {
            // Flush on non-sequential writes.
            if !inner.write_buf.is_empty()
                && inner.offset != inner.write_buf_off.saturating_add(inner.write_buf.len())
            {
                let off = inner.write_buf_off;
                let len = inner.write_buf.len();
                let inode_num = inner.inode.inode_num();
                let size_before = inner.inode.size() as usize;
                let result = {
                    let _fs_guard = ext4_lock();
                    inner.inode.write_at(off, &inner.write_buf)
                };
                if debug_iozone_tracked(inode_num) {
                    let size_after = inner.inode.size() as usize;
                    match result {
                        Ok(n) => {
                            println!(
                                "[iozone-debug] write inode={} off={} len={} wrote={} size={}->{}",
                                inode_num, off, len, n, size_before, size_after
                            );
                        }
                        Err(_) => {
                            println!(
                                "[iozone-debug] write inode={} off={} len={} err size={}->{}",
                                inode_num, off, len, size_before, size_after
                            );
                        }
                    }
                }
                if result.is_err() {
                    println!("[ext4] Warning: write failed");
                    break;
                }
                inner.write_buf.clear();
            }

            if inner.write_buf.is_empty() {
                inner.write_buf_off = inner.offset;
            }

            inner.write_buf.extend_from_slice(slice);
            inner.offset += slice.len();
            total_write_size += slice.len();
            inner.read_buf_valid = 0;

            if inner.write_buf.len() >= WRITEBUF_MAX {
                let off = inner.write_buf_off;
                let len = inner.write_buf.len();
                let inode_num = inner.inode.inode_num();
                let size_before = inner.inode.size() as usize;
                let result = {
                    let _fs_guard = ext4_lock();
                    inner.inode.write_at(off, &inner.write_buf)
                };
                if debug_iozone_tracked(inode_num) {
                    let size_after = inner.inode.size() as usize;
                    match result {
                        Ok(n) => {
                            println!(
                                "[iozone-debug] write inode={} off={} len={} wrote={} size={}->{}",
                                inode_num, off, len, n, size_before, size_after
                            );
                        }
                        Err(_) => {
                            println!(
                                "[iozone-debug] write inode={} off={} len={} err size={}->{}",
                                inode_num, off, len, size_before, size_after
                            );
                        }
                    }
                }
                if result.is_err() {
                    println!("[ext4] Warning: write failed");
                    break;
                }
                inner.write_buf.clear();
                inner.read_buf_valid = 0;
            }
        }
        total_write_size
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Drop for OSInode {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        let inode_key = (inner.inode.device_id(), inner.inode.inode_num());
        if !inner.write_buf.is_empty() {
            let off = inner.write_buf_off;
            let data = core::mem::take(&mut inner.write_buf);
            let _ = {
                let _fs_guard = ext4_lock();
                inner.inode.write_at(off, &data)
            };
        }
        drop(inner);
        if let Some(cleanup) = self.tmpfile_cleanup.take() {
            let _ = {
                let _fs_guard = ext4_lock();
                cleanup.parent.unlink(&cleanup.name)
            };
        }
        let deferred_cleanup = { DEFERRED_UNLINK_CLEANUP.lock().remove(&inode_key) };
        if let Some(cleanup) = deferred_cleanup {
            if has_open_inode_fd_refs(inode_key.0, inode_key.1) {
                DEFERRED_UNLINK_CLEANUP.lock().insert(inode_key, cleanup);
            } else {
                let _ = {
                    let _fs_guard = ext4_lock();
                    cleanup.parent.unlink(&cleanup.name)
                };
                // Opportunistically clean up other lingering deferred entries.
                sweep_deferred_unlinks();
            }
        }
    }
}

fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(pos) => {
            let (parent, name) = trimmed.split_at(pos);
            let name = &name[1..];
            Some((parent, name))
        }
        None => Some(("", trimmed)),
    }
}
