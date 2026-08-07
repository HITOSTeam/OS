//! Inode abstraction for ext4 filesystem

use super::vfs::{PinnedPath, VfsPath};
use super::{File, POLLIN, POLLOUT};
use crate::drivers::BLOCK_DEVICES;
use crate::mm::UserBuffer;
use crate::println;
use crate::sync::{
    KernelMutex, KernelMutexGuard, KernelRwSemaphore, KernelRwSemaphoreReadGuard,
    KernelRwSemaphoreWriteGuard,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use bitflags::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use ext4_fs::{Ext4FileSystem, Ext4FileSystemHandle, Inode};
use lazy_static::*;
use spin::Mutex;

const EXT4_INODE_LOCK_CACHE_MAX: usize = 4096;

struct PendingWriteRegistration {
    device_id: usize,
    inode_num: u32,
    end: usize,
    inner: Weak<Mutex<OSInodeInner>>,
}

// Serialize ext4 operations across harts.
lazy_static! {
    /// Linux `s_vfs_rename_mutex` analogue.  It is only taken for operations
    /// that move names between two directories, before either parent lock.
    static ref EXT4_TOPOLOGY_LOCK: KernelMutex<()> = KernelMutex::new(());
    /// Stable Linux `i_rwsem` equivalents.  ext4-fs may construct more than
    /// one Rust `Inode` object for the same on-disk inode (in particular for
    /// hard links), so object addresses cannot identify the lock.
    static ref EXT4_INODE_LOCKS:
        Mutex<BTreeMap<(usize, u32), Weak<Ext4InodeLock>>> =
        Mutex::new(BTreeMap::new());
    static ref DEBUG_IOZONE_INODES: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static ref INODE_LIFETIMES: Mutex<BTreeMap<(usize, u32), InodeLifetimeState>> =
        Mutex::new(BTreeMap::new());
    static ref INODE_PATH_HINTS: Mutex<BTreeMap<(usize, u32), String>> =
        Mutex::new(BTreeMap::new());
    static ref INODE_TEXT_ACCESS: Mutex<BTreeMap<(usize, u32), InodeTextAccess>> =
        Mutex::new(BTreeMap::new());
    static ref PENDING_WRITE_REGISTRY: Mutex<BTreeMap<usize, PendingWriteRegistration>> =
        Mutex::new(BTreeMap::new());
}

pub(crate) fn ext4_topology_lock() -> KernelMutexGuard<'static, ()> {
    EXT4_TOPOLOGY_LOCK.lock()
}

/// Stable state associated with one ext4 inode identity.
///
/// Linux keeps both `i_rwsem` and namespace-change state on the persistent
/// inode object. ext4-fs can materialize several Rust `Inode` wrappers for one
/// disk inode, so keep the equivalent state in the keyed table above.
pub(crate) struct Ext4InodeLock {
    semaphore: KernelRwSemaphore<()>,
    namespace_generation: AtomicUsize,
}

impl Ext4InodeLock {
    fn new() -> Self {
        Self {
            semaphore: KernelRwSemaphore::new(()),
            namespace_generation: AtomicUsize::new(0),
        }
    }

    pub(crate) fn read(&self) -> KernelRwSemaphoreReadGuard<'_, ()> {
        self.semaphore.read()
    }

    pub(crate) fn write(&self) -> KernelRwSemaphoreWriteGuard<'_, ()> {
        self.semaphore.write()
    }

    /// Publish invalidation before the caller changes any child name while it
    /// owns the directory write semaphore. Readers observing the new value
    /// miss the dcache and then wait on `read()` for the mutation to finish;
    /// readers that observed the old value linearize before this publication.
    pub(crate) fn begin_namespace_mutation(&self) {
        self.namespace_generation.fetch_add(1, Ordering::Release);
    }

    pub(crate) fn namespace_generation(&self) -> usize {
        self.namespace_generation.load(Ordering::Acquire)
    }
}

pub(crate) fn ext4_inode_key(inode: &Inode) -> (usize, u32) {
    (inode.device_id(), inode.inode_num())
}

fn ext4_inode_lock_by_key(key: (usize, u32)) -> Arc<Ext4InodeLock> {
    let mut locks = EXT4_INODE_LOCKS.lock();
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    if locks.len() >= EXT4_INODE_LOCK_CACHE_MAX {
        locks.retain(|_, lock| lock.strong_count() != 0);
    }
    let lock = Arc::new(Ext4InodeLock::new());
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

/// Return the stable per-inode sleeping read/write semaphore.
///
/// Weak table entries allow closed and unlinked inodes to be reclaimed.  An
/// active caller always owns a strong reference before acquiring the lock.
pub(crate) fn ext4_inode_lock(inode: &Inode) -> Arc<Ext4InodeLock> {
    ext4_inode_lock_by_key(ext4_inode_key(inode))
}

/// Mark the beginning of a legacy ext4 directory mutation.
///
/// New object-VFS operations can publish through their retained inode state;
/// legacy syscall adapters use this helper while they are migrated. The
/// caller must already own the parent inode write semaphore and must call this
/// before the first on-disk directory change.
pub(crate) fn ext4_begin_namespace_mutation(inode: &Inode) {
    ext4_inode_lock(inode).begin_namespace_mutation();
}

pub(crate) fn with_ext4_inode_read<R>(inode: &Inode, operation: impl FnOnce() -> R) -> R {
    let lock = ext4_inode_lock(inode);
    let _guard = lock.read();
    operation()
}

pub(crate) fn with_ext4_inode_write<R>(inode: &Inode, operation: impl FnOnce() -> R) -> R {
    let lock = ext4_inode_lock(inode);
    let _guard = lock.write();
    operation()
}

/// Acquire several inode write semaphores in stable filesystem/inode order.
///
/// This is the project's address-independent equivalent of Linux ordering
/// non-directory `i_rwsem` locks by inode address.  Stable keys are required
/// because ext4-fs can materialize multiple Rust objects for one inode.
pub(crate) fn with_ext4_inode_write_set<R>(inodes: &[&Inode], operation: impl FnOnce() -> R) -> R {
    let mut locks = inodes
        .iter()
        .map(|inode| (ext4_inode_key(inode), ext4_inode_lock(inode)))
        .collect::<Vec<_>>();
    locks.sort_unstable_by_key(|(key, _)| *key);
    locks.dedup_by_key(|(key, _)| *key);
    let _guards = locks
        .iter()
        .map(|(_, lock)| lock.write())
        .collect::<Vec<_>>();
    operation()
}

// Compatibility hooks kept until all legacy syscall callers use the VFS
// dentry cache.  The old absolute-path cache is intentionally gone: returning
// an inode without revalidating its parent dentry races rename/unlink, and
// populating an unused global BTreeMap only reintroduces path-walk contention.
pub(crate) fn clear_ext4_path_cache() {}

pub(crate) fn invalidate_ext4_path_cache_inode(_inode: &Inode) {}

#[derive(Clone, Copy, Default)]
struct InodeTextAccess {
    write_open: usize,
    executing: usize,
}

fn valid_text_key(dev: usize, ino: u32) -> bool {
    dev != 0 || ino != 0
}

fn prune_text_access_entry(
    access: &mut BTreeMap<(usize, u32), InodeTextAccess>,
    key: (usize, u32),
) {
    if access
        .get(&key)
        .is_some_and(|state| state.write_open == 0 && state.executing == 0)
    {
        access.remove(&key);
    }
}

fn register_write_open_inode(dev: usize, ino: u32) -> Result<(), isize> {
    if dev == 0 && ino == 0 {
        return Ok(());
    }
    let mut access = INODE_TEXT_ACCESS.lock();
    let state = access.entry((dev, ino)).or_default();
    if state.executing > 0 {
        return Err(ETXTBSY_ERR);
    }
    state.write_open = state.write_open.saturating_add(1);
    Ok(())
}

fn unregister_write_open_inode(dev: usize, ino: u32) {
    if !valid_text_key(dev, ino) {
        return;
    }
    let key = (dev, ino);
    let mut access = INODE_TEXT_ACCESS.lock();
    if let Some(state) = access.get_mut(&key) {
        if state.write_open > 0 {
            state.write_open -= 1;
        }
    }
    prune_text_access_entry(&mut access, key);
}

pub(crate) fn is_inode_currently_executed(dev: usize, ino: u32) -> bool {
    if !valid_text_key(dev, ino) {
        return false;
    }
    INODE_TEXT_ACCESS
        .lock()
        .get(&(dev, ino))
        .copied()
        .unwrap_or_default()
        .executing
        > 0
}

pub(crate) fn register_executing_inode(dev: usize, ino: u32) {
    if !valid_text_key(dev, ino) {
        return;
    }
    let mut access = INODE_TEXT_ACCESS.lock();
    let state = access.entry((dev, ino)).or_default();
    state.executing = state.executing.saturating_add(1);
}

pub(crate) fn try_register_executing_inode(dev: usize, ino: u32) -> Result<(), isize> {
    if !valid_text_key(dev, ino) {
        return Ok(());
    }
    // Buffered writes remain part of the writable-open text exclusion until
    // they are flushed or discarded; otherwise exec could parse one image and
    // map segment bytes from a later one.
    if pending_inode_write_end(dev, ino).is_some() {
        return Err(ETXTBSY_ERR);
    }
    let key = (dev, ino);
    let mut access = INODE_TEXT_ACCESS.lock();
    if access.get(&key).is_some_and(|state| state.write_open > 0) {
        return Err(ETXTBSY_ERR);
    }
    // Close the race where a writer drops write-open state before its dirty
    // buffer reaches the backing inode.
    if pending_inode_write_end(dev, ino).is_some() {
        return Err(ETXTBSY_ERR);
    }
    let state = access.entry(key).or_default();
    state.executing = state.executing.saturating_add(1);
    Ok(())
}

pub(crate) fn unregister_executing_inode(dev: usize, ino: u32) {
    if !valid_text_key(dev, ino) {
        return;
    }
    let key = (dev, ino);
    let mut access = INODE_TEXT_ACCESS.lock();
    if let Some(state) = access.get_mut(&key) {
        if state.executing > 0 {
            state.executing -= 1;
        }
    }
    prune_text_access_entry(&mut access, key);
}

pub(crate) struct ExecInodeReservation {
    key: Option<(usize, u32)>,
}

impl ExecInodeReservation {
    pub(crate) fn new(dev: usize, ino: u32) -> Result<Self, isize> {
        try_register_executing_inode(dev, ino)?;
        Ok(Self {
            key: valid_text_key(dev, ino).then_some((dev, ino)),
        })
    }

    pub(crate) fn key(&self) -> (usize, u32) {
        self.key.unwrap_or((0, 0))
    }
}

impl Drop for ExecInodeReservation {
    fn drop(&mut self) {
        if let Some((dev, ino)) = self.key.take() {
            unregister_executing_inode(dev, ino);
        }
    }
}

#[derive(Default)]
struct WriteOpenState {
    key: Option<(usize, u32)>,
    fd_refs: usize,
}

impl WriteOpenState {
    fn register_for_inode(writable: bool, inode: &Inode) -> Result<Self, isize> {
        if writable && inode.is_file() {
            let key = (inode.device_id(), inode.inode_num());
            register_write_open_inode(key.0, key.1)?;
            Ok(Self {
                key: Some(key),
                fd_refs: 0,
            })
        } else {
            Ok(Self::default())
        }
    }
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
    let dir_lock = ext4_inode_lock(dir);
    let _dir_guard = dir_lock.read();
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

    for (index, root) in BLOCK_ROOTS.iter().enumerate() {
        let Some(root) = root.as_ref() else {
            continue;
        };
        let base = if index == 0 {
            String::from("/")
        } else {
            alloc::format!("/dev/vd{}", (b'a' + index as u8) as char)
        };
        if root.device_id() == target_dev && root.inode_num() == target_ino {
            return Some(base);
        }
        if let Some(found) = find_inode_path_in_subtree(root, &base, target_dev, target_ino, 64) {
            return Some(found);
        }
    }
    None
}

pub(crate) fn path_resolves_to_inode(path: &str, target: &Arc<Inode>) -> bool {
    let Some(found) = find_path_in_roots(path) else {
        return false;
    };
    found.device_id() == target.device_id() && found.inode_num() == target.inode_num()
}

fn debug_iozone_tracked(inode_num: u32) -> bool {
    if !crate::debug_config::DEBUG_IOZONE_FS {
        return false;
    }
    DEBUG_IOZONE_INODES.lock().iter().any(|&n| n == inode_num)
}

/// A wrapper around a filesystem inode to implement File trait
pub struct OSInode {
    flock_owner_id: usize,
    open_fd_refs: AtomicUsize,
    inode_device_id: usize,
    inode_num: u32,
    /// Stable inode identity outside the open-file-description state.
    /// Positional reads do not need to serialize on the shared file offset.
    inode: Arc<Inode>,
    inode_lock: Arc<Ext4InodeLock>,
    readable: bool,
    writable: bool,
    regular_file_poll_ready: bool,
    append: bool,
    readonly_fs: bool,
    replace_on_write: bool,
    fanotify_silent: bool,
    fanotify_path: Option<String>,
    vfs_path: Option<PinnedPath>,
    tmpfile_cleanup: Option<TmpfileCleanup>,
    write_open: Mutex<WriteOpenState>,
    inner: Arc<Mutex<OSInodeInner>>,
}

struct TmpfileCleanup {
    parent: Arc<Inode>,
    name: String,
}

#[derive(Default)]
struct InodeLifetimeState {
    /// Number of live open file descriptions for this on-disk inode.
    ///
    /// This deliberately counts `OSInode` objects rather than descriptor
    /// slots.  `dup()` and `fork()` share one description, while epoll and
    /// SCM_RIGHTS references can keep a description alive after its last fd
    /// slot disappears, matching Linux's `struct file` lifetime model.
    open_descriptions: usize,
    /// An unlink reserves the lifetime before renaming the target to its
    /// hidden compatibility name.  This closes the last-close-vs-rename race
    /// without holding this short spin lock across ext4 I/O.
    unlink_reservations: usize,
    /// Hidden names waiting for the last open description to disappear.
    /// One inode can have multiple dentries (hard links), and more than one
    /// of those names may be unlinked while the inode remains open.
    deferred_cleanups: Vec<TmpfileCleanup>,
}

fn cleanup_deferred_unlink(cleanup: TmpfileCleanup) {
    let parent_lock = ext4_inode_lock(&cleanup.parent);
    let _parent_guard = parent_lock.write();
    let child = cleanup.parent.find(&cleanup.name);
    let child_lock = child.as_ref().map(|child| ext4_inode_lock(child));
    let _child_guard = child_lock.as_ref().map(|lock| lock.write());
    parent_lock.begin_namespace_mutation();
    if cleanup.parent.unlink(&cleanup.name).is_ok() {
        clear_ext4_path_cache();
    }
}

fn register_open_inode_description(key: (usize, u32)) {
    let mut lifetimes = INODE_LIFETIMES.lock();
    let state = lifetimes.entry(key).or_default();
    state.open_descriptions = state.open_descriptions.saturating_add(1);
}

fn unregister_open_inode_description(key: (usize, u32)) -> Vec<TmpfileCleanup> {
    let mut lifetimes = INODE_LIFETIMES.lock();
    let (cleanups, remove_entry) = {
        let state = lifetimes
            .get_mut(&key)
            .expect("open inode description lifetime is not registered");
        debug_assert!(state.open_descriptions > 0);
        state.open_descriptions = state.open_descriptions.saturating_sub(1);
        let cleanups = if state.open_descriptions == 0 && state.unlink_reservations == 0 {
            core::mem::take(&mut state.deferred_cleanups)
        } else {
            Vec::new()
        };
        let remove_entry = state.open_descriptions == 0
            && state.unlink_reservations == 0
            && state.deferred_cleanups.is_empty();
        (cleanups, remove_entry)
    };
    if remove_entry {
        lifetimes.remove(&key);
    }
    cleanups
}

/// Reservation covering the gap between deciding that an open inode must be
/// preserved and publishing its hidden-name cleanup record.
///
/// Linux does not need this compatibility rename: the VFS inode and dentry
/// references naturally keep an unlinked inode alive.  Until ext4-fs exposes
/// that lifetime directly, this token supplies the same atomicity without the
/// former O(processes * fds) scan on every unlink.
pub(crate) struct DeferredUnlinkReservation {
    key: (usize, u32),
    active: bool,
}

impl DeferredUnlinkReservation {
    fn finish(&mut self, new_cleanup: Option<TmpfileCleanup>) -> Vec<TmpfileCleanup> {
        let mut lifetimes = INODE_LIFETIMES.lock();
        let (cleanups, remove_entry) = {
            let state = lifetimes
                .get_mut(&self.key)
                .expect("deferred unlink lifetime is not registered");
            debug_assert!(state.unlink_reservations > 0);
            state.unlink_reservations = state.unlink_reservations.saturating_sub(1);
            if let Some(cleanup) = new_cleanup {
                state.deferred_cleanups.push(cleanup);
            }
            let cleanups = if state.open_descriptions == 0 && state.unlink_reservations == 0 {
                core::mem::take(&mut state.deferred_cleanups)
            } else {
                Vec::new()
            };
            let remove_entry = state.open_descriptions == 0
                && state.unlink_reservations == 0
                && state.deferred_cleanups.is_empty();
            (cleanups, remove_entry)
        };
        if remove_entry {
            lifetimes.remove(&self.key);
        }
        self.active = false;
        cleanups
    }

    pub(crate) fn commit(mut self, parent: Arc<Inode>, name: String) {
        for cleanup in self.finish(Some(TmpfileCleanup { parent, name })) {
            cleanup_deferred_unlink(cleanup);
        }
    }
}

impl Drop for DeferredUnlinkReservation {
    fn drop(&mut self) {
        if self.active {
            for cleanup in self.finish(None) {
                cleanup_deferred_unlink(cleanup);
            }
        }
    }
}

pub(crate) fn reserve_deferred_unlink(inode: &Inode) -> Option<DeferredUnlinkReservation> {
    let key = (inode.device_id(), inode.inode_num());
    let mut lifetimes = INODE_LIFETIMES.lock();
    let state = lifetimes.get_mut(&key)?;
    if state.open_descriptions == 0 {
        return None;
    }
    state.unlink_reservations = state.unlink_reservations.saturating_add(1);
    Some(DeferredUnlinkReservation { key, active: true })
}

/// The OS inode inner
pub struct OSInodeInner {
    offset: usize,
    dir_offset: usize,
    inode: Arc<Inode>,
    write_buf_off: usize,
    write_buf: Vec<u8>,
    write_buf_counted: bool,
    write_buf_registry_id: usize,
    write_buf_registry_inner: Weak<Mutex<OSInodeInner>>,
    read_buf_off: usize,
    read_buf_valid: usize,
    read_buf: Vec<u8>,
}

const READBUF_MAX: usize = 128 * 1024;
const READBUF_MIN: usize = 4 * 1024;
const WRITEBUF_MAX: usize = 128 * 1024;
const ETXTBSY_ERR: isize = -26;
static PENDING_WRITE_BUFFERS: AtomicUsize = AtomicUsize::new(0);
static NEXT_WRITE_BUF_REGISTRY_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_FLOCK_OWNER_ID: AtomicUsize = AtomicUsize::new(1);

pub(crate) fn pending_inode_write_end(device_id: usize, inode_num: u32) -> Option<usize> {
    if PENDING_WRITE_BUFFERS.load(Ordering::Acquire) == 0 {
        return None;
    }

    PENDING_WRITE_REGISTRY
        .lock()
        .values()
        .filter(|entry| entry.device_id == device_id && entry.inode_num == inode_num)
        .map(|entry| entry.end)
        .max()
}

fn pending_inode_write_inners(
    device_id: usize,
    inode_num: u32,
) -> Vec<(usize, Weak<Mutex<OSInodeInner>>)> {
    if PENDING_WRITE_BUFFERS.load(Ordering::Acquire) == 0 {
        return Vec::new();
    }

    PENDING_WRITE_REGISTRY
        .lock()
        .iter()
        .filter(|(_, entry)| entry.device_id == device_id && entry.inode_num == inode_num)
        .map(|(id, entry)| (*id, Weak::clone(&entry.inner)))
        .collect()
}

fn remove_stale_pending_write_entry(id: usize) {
    if PENDING_WRITE_REGISTRY.lock().remove(&id).is_some() {
        PENDING_WRITE_BUFFERS.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn flush_inode_pending_writes_before_truncate(
    device_id: usize,
    inode_num: u32,
    new_len: usize,
) -> Result<(), ext4_fs::Ext4Error> {
    for (id, inner_weak) in pending_inode_write_inners(device_id, inode_num) {
        let Some(inner_arc) = inner_weak.upgrade() else {
            remove_stale_pending_write_entry(id);
            continue;
        };
        let inode_lock = ext4_inode_lock_by_key((device_id, inode_num));
        let _inode_guard = inode_lock.write();
        let mut inner = inner_arc.lock();
        if inner.write_buf_registry_id != id
            || inner.inode.device_id() != device_id
            || inner.inode.inode_num() != inode_num
        {
            continue;
        }
        if !inner.write_buf_counted || inner.write_buf.is_empty() {
            OSInode::mark_write_buf_clean(&mut inner);
            continue;
        }

        let start = inner.write_buf_off;
        let end = start.saturating_add(inner.write_buf.len());
        if start >= new_len {
            continue;
        }
        inner.read_buf_valid = 0;
        if end <= new_len {
            OSInode::flush_inner_locked(&mut inner)?;
            continue;
        }

        let keep_len = new_len - start;
        if keep_len == 0 {
            continue;
        }
        let data = inner.write_buf[..keep_len].to_vec();
        let result = inner.inode.write_at(start, &data);
        match result {
            Ok(n) if n == data.len() => {}
            Ok(_) => return Err(ext4_fs::Ext4Error::NoSpace),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub(crate) fn discard_inode_pending_writes_after_truncate(
    device_id: usize,
    inode_num: u32,
    new_len: usize,
) {
    for (id, inner_weak) in pending_inode_write_inners(device_id, inode_num) {
        let Some(inner_arc) = inner_weak.upgrade() else {
            remove_stale_pending_write_entry(id);
            continue;
        };
        let inode_lock = ext4_inode_lock_by_key((device_id, inode_num));
        let _inode_guard = inode_lock.write();
        let mut inner = inner_arc.lock();
        if inner.write_buf_registry_id != id
            || inner.inode.device_id() != device_id
            || inner.inode.inode_num() != inode_num
        {
            continue;
        }
        if !inner.write_buf_counted || inner.write_buf.is_empty() {
            OSInode::mark_write_buf_clean(&mut inner);
            continue;
        }
        let end = inner.write_buf_off.saturating_add(inner.write_buf.len());
        if end > new_len {
            inner.write_buf.clear();
            inner.read_buf_valid = 0;
            OSInode::mark_write_buf_clean(&mut inner);
        }
    }
}

impl OSInode {
    /// Construct an OS inode from an inode
    pub fn new(readable: bool, writable: bool, inode: Arc<Inode>) -> Result<Self, isize> {
        Self::new_with_append(readable, writable, false, inode)
    }

    pub fn new_with_append(
        readable: bool,
        writable: bool,
        append: bool,
        inode: Arc<Inode>,
    ) -> Result<Self, isize> {
        Self::new_with_append_rofs(readable, writable, append, inode, false)
    }

    pub fn new_with_append_rofs(
        readable: bool,
        writable: bool,
        append: bool,
        inode: Arc<Inode>,
        readonly_fs: bool,
    ) -> Result<Self, isize> {
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
    pub fn new_replace_on_write(
        readable: bool,
        writable: bool,
        inode: Arc<Inode>,
    ) -> Result<Self, isize> {
        Self::new_with_append_rofs_tmp_cleanup(readable, writable, false, inode, false, true, None)
    }

    pub(crate) fn new_fanotify_event(inode: Arc<Inode>) -> Self {
        let mut file = Self::new(true, false, inode)
            .expect("fanotify event inode open cannot fail for read-only files");
        file.fanotify_silent = true;
        file
    }

    pub fn new_with_append_rofs_tmp_cleanup(
        readable: bool,
        writable: bool,
        append: bool,
        inode: Arc<Inode>,
        readonly_fs: bool,
        replace_on_write: bool,
        tmpfile_cleanup: Option<(Arc<Inode>, String)>,
    ) -> Result<Self, isize> {
        let regular_file_poll_ready = inode.is_file();
        let inode_device_id = inode.device_id();
        let inode_num = inode.inode_num();
        let inode_lock = ext4_inode_lock(&inode);
        let write_open = WriteOpenState::register_for_inode(writable, &inode)?;
        let inner = Arc::new_cyclic(|inner_weak| {
            Mutex::new(OSInodeInner {
                offset: 0,
                dir_offset: 0,
                inode: Arc::clone(&inode),
                write_buf_off: 0,
                write_buf: Vec::new(),
                write_buf_counted: false,
                write_buf_registry_id: NEXT_WRITE_BUF_REGISTRY_ID.fetch_add(1, Ordering::Relaxed),
                write_buf_registry_inner: Weak::clone(inner_weak),
                read_buf_off: 0,
                read_buf_valid: 0,
                read_buf: Vec::new(),
            })
        });
        register_open_inode_description((inode_device_id, inode_num));
        Ok(Self {
            flock_owner_id: NEXT_FLOCK_OWNER_ID.fetch_add(1, Ordering::Relaxed),
            open_fd_refs: AtomicUsize::new(0),
            inode_device_id,
            inode_num,
            inode,
            inode_lock,
            readable,
            writable,
            regular_file_poll_ready,
            append,
            readonly_fs,
            replace_on_write,
            fanotify_silent: false,
            fanotify_path: None,
            vfs_path: None,
            tmpfile_cleanup: tmpfile_cleanup.map(|(parent, name)| TmpfileCleanup { parent, name }),
            write_open: Mutex::new(write_open),
            inner,
        })
    }

    pub(crate) fn with_fanotify_path(mut self, path: Option<String>) -> Self {
        self.fanotify_path = path;
        self
    }

    pub(crate) fn with_vfs_path(mut self, path: Option<VfsPath>) -> Self {
        self.vfs_path = path.map(PinnedPath::new);
        self
    }

    pub(crate) fn vfs_path(&self) -> Option<&PinnedPath> {
        self.vfs_path.as_ref()
    }

    pub fn append(&self) -> bool {
        self.append
    }

    pub(crate) fn flock_owner_id(&self) -> usize {
        self.flock_owner_id
    }

    fn close_fd_ref(&self) -> bool {
        let mut refs = self.open_fd_refs.load(Ordering::Acquire);
        loop {
            if refs == 0 {
                return false;
            }
            match self.open_fd_refs.compare_exchange_weak(
                refs,
                refs - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return refs == 1,
                Err(actual) => refs = actual,
            }
        }
    }

    pub fn readonly_fs(&self) -> bool {
        self.vfs_path
            .as_ref()
            .map(|path| path.path().mount().flags().is_read_only())
            .unwrap_or(self.readonly_fs)
    }

    pub(crate) fn fanotify_silent(&self) -> bool {
        self.fanotify_silent
    }

    pub(crate) fn fanotify_path(&self) -> Option<String> {
        self.fanotify_path.clone()
    }

    /// Read all data inside an inode into vector
    pub fn read_all(&self) -> Vec<u8> {
        if self.writable {
            let _inode_guard = self.inode_lock.write();
            return self.read_all_locked();
        }
        let _inode_guard = self.inode_lock.read();
        self.read_all_locked()
    }

    fn read_all_locked(&self) -> Vec<u8> {
        let mut inner = self.inner.lock();
        if self.writable {
            let _ = Self::flush_inner_locked(&mut inner);
        }
        let file_size = inner.inode.size() as usize;

        let mut buffer = [0u8; 4096]; // Use larger buffer for ext4 (4K blocks)
        let mut v: Vec<u8> = Vec::new();
        let mut total_read = 0usize;

        loop {
            let len = inner.inode.read_at(inner.offset, &mut buffer);
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
        Arc::clone(&self.inode)
    }

    /// Return the end offset of buffered (not-yet-flushed) writes.
    ///
    /// This is used to report a correct file size to userspace (`fstat`, `lseek(SEEK_END)`)
    /// even when we are buffering writes in memory.
    pub fn pending_write_end(&self) -> usize {
        let inner = self.inner.lock();
        inner.write_buf_off.saturating_add(inner.write_buf.len())
    }

    fn write_at_zeroing_gap(
        inode: &Arc<Inode>,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, ext4_fs::Ext4Error> {
        if data.is_empty() {
            return Ok(0);
        }

        let size = inode.size() as usize;
        if offset > size {
            let zeros = [0u8; 4096];
            let mut off = size;
            while off < offset {
                let chunk = core::cmp::min(zeros.len(), offset - off);
                match inode.write_at(off, &zeros[..chunk]) {
                    Ok(0) => return Err(ext4_fs::Ext4Error::NoSpace),
                    Ok(written) => off += written,
                    Err(e) => return Err(e),
                }
            }
        }

        inode.write_at(offset, data)
    }

    /// Read from this inode at the given offset without updating the file offset.
    pub fn pread_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        if self.writable {
            let _inode_guard = self.inode_lock.write();
            return self.pread_at_locked(offset, buf);
        }
        let _inode_guard = self.inode_lock.read();
        // Linux pread(2) supplies a private ki_pos and therefore does not take
        // file->f_pos_lock. Preserve the small per-description readahead cache
        // on the uncontended path, but do not spin behind another positional
        // reader while it is yielding in ext4/block I/O.
        let Some(mut inner) = self.inner.try_lock() else {
            return self.inode.read_at(offset, buf);
        };
        self.pread_with_inner(&mut inner, offset, buf)
    }

    fn pread_at_locked(&self, offset: usize, buf: &mut [u8]) -> usize {
        let mut inner = self.inner.lock();
        self.pread_with_inner(&mut inner, offset, buf)
    }

    fn pread_with_inner(&self, inner: &mut OSInodeInner, offset: usize, buf: &mut [u8]) -> usize {
        if self.writable {
            let _ = Self::flush_inner_locked(inner);
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
                let n = inode.read_at(off, &mut inner.read_buf[..refill_len]);
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
        let _inode_guard = self.inode_lock.write();
        let mut inner = self.inner.lock();
        let offset = if self.append {
            let disk_end = inner.inode.size() as usize;
            let pending_end =
                pending_inode_write_end(inner.inode.device_id(), inner.inode.inode_num())
                    .unwrap_or(0);
            core::cmp::max(disk_end, pending_end)
        } else {
            offset
        };
        if self.replace_on_write && offset == 0 && inner.write_buf.is_empty() {
            self.clear_inode_for_replace_write_locked(&mut inner, offset)?;
        }
        // Writes via pwrite/pwritev must invalidate the buffered read cache.
        inner.read_buf_valid = 0;
        let inode_num = inner.inode.inode_num();
        let size_before = inner.inode.size() as usize;

        if buf.len() >= WRITEBUF_MAX {
            if !inner.write_buf.is_empty() {
                if Self::flush_inner_locked(&mut inner).is_err() {
                    return Err(());
                }
                inner.read_buf_valid = 0;
            }
            let result = Self::write_at_zeroing_gap(&inner.inode, offset, buf);
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
            if Self::flush_inner_locked(&mut inner).is_err() {
                return Err(());
            }
            inner.read_buf_valid = 0;
        }

        if inner.write_buf.is_empty() {
            inner.write_buf_off = offset;
        }

        inner.write_buf.extend_from_slice(buf);
        if !buf.is_empty() {
            Self::mark_write_buf_dirty(&mut inner);
        }
        if inner.write_buf.len() >= WRITEBUF_MAX {
            if Self::flush_inner_locked(&mut inner).is_err() {
                return Err(());
            }
            return Ok(buf.len());
        }

        Ok(buf.len())
    }

    /// Flush with the inode's write semaphore already held.
    fn flush_inner_locked(inner: &mut OSInodeInner) -> Result<(), ext4_fs::Ext4Error> {
        if inner.write_buf.is_empty() {
            return Ok(());
        }
        let off = inner.write_buf_off;
        let data = core::mem::take(&mut inner.write_buf);
        let inode_num = inner.inode.inode_num();
        let size_before = inner.inode.size() as usize;
        let result = Self::write_at_zeroing_gap(&inner.inode, off, &data);
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
            Ok(n) if n == data.len() => {
                Self::mark_write_buf_clean(inner);
                Ok(())
            }
            Ok(_) => {
                inner.write_buf_off = off;
                inner.write_buf = data;
                Self::mark_write_buf_dirty(inner);
                Err(ext4_fs::Ext4Error::NoSpace)
            }
            Err(e) => {
                inner.write_buf_off = off;
                inner.write_buf = data;
                Self::mark_write_buf_dirty(inner);
                Err(e)
            }
        }
    }

    fn mark_write_buf_dirty(inner: &mut OSInodeInner) {
        if inner.write_buf.is_empty() {
            Self::mark_write_buf_clean(inner);
            return;
        }
        if !inner.write_buf_counted {
            PENDING_WRITE_BUFFERS.fetch_add(1, Ordering::AcqRel);
            inner.write_buf_counted = true;
        }
        PENDING_WRITE_REGISTRY.lock().insert(
            inner.write_buf_registry_id,
            PendingWriteRegistration {
                device_id: inner.inode.device_id(),
                inode_num: inner.inode.inode_num(),
                end: inner.write_buf_off.saturating_add(inner.write_buf.len()),
                inner: Weak::clone(&inner.write_buf_registry_inner),
            },
        );
    }

    fn mark_write_buf_clean(inner: &mut OSInodeInner) {
        if inner.write_buf_counted {
            inner.write_buf_counted = false;
            PENDING_WRITE_BUFFERS.fetch_sub(1, Ordering::AcqRel);
        }
        PENDING_WRITE_REGISTRY
            .lock()
            .remove(&inner.write_buf_registry_id);
    }

    pub fn flush_with_error(&self) -> Result<(), ext4_fs::Ext4Error> {
        let _inode_guard = self.inode_lock.write();
        let mut inner = self.inner.lock();
        Self::flush_inner_locked(&mut inner)
    }

    pub fn flush(&self) -> Result<(), ()> {
        self.flush_with_error().map_err(|_| ())
    }

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn visible_end(&self) -> usize {
        let inode = self.ext4_inode();
        let _inode_guard = self.inode_lock.read();
        let disk_end = inode.size() as usize;
        pending_inode_write_end(inode.device_id(), inode.inode_num())
            .map(|pending_end| core::cmp::max(disk_end, pending_end))
            .unwrap_or(disk_end)
    }

    pub fn set_offset(&self, offset: usize) {
        if !self.writable {
            let mut inner = self.inner.lock();
            inner.offset = offset;
            inner.read_buf_valid = 0;
            return;
        }
        let _inode_guard = self.inode_lock.write();
        let mut inner = self.inner.lock();
        let _ = Self::flush_inner_locked(&mut inner);
        inner.offset = offset;
        inner.read_buf_valid = 0;
    }

    fn clear_inode_for_replace_write_locked(
        &self,
        inner: &mut OSInodeInner,
        write_offset: usize,
    ) -> Result<(), ()> {
        if !self.replace_on_write || !inner.write_buf.is_empty() || write_offset != 0 {
            return Ok(());
        }
        let result = inner.inode.clear();
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

lazy_static! {
    /// One optional ext4 instance per registered block device.  Keeping the
    /// vector aligned with `/dev/vdX` preserves stable device identities even
    /// when a future non-ext4 disk is present.
    static ref BLOCK_FILESYSTEMS: Vec<Option<Arc<Ext4FileSystemHandle>>> = BLOCK_DEVICES
        .iter()
        .map(|device| Ext4FileSystem::try_open(device.clone()).ok())
        .collect();

    static ref BLOCK_ROOTS: Vec<Option<Arc<Inode>>> = BLOCK_FILESYSTEMS
        .iter()
        .map(|fs| {
            fs.as_ref()
                .map(|fs| Arc::new(Ext4FileSystem::root_inode(fs)))
        })
        .collect();

    /// ext4 filesystem handle (primary root device).
    pub static ref EXT4_FS: Arc<Ext4FileSystemHandle> = BLOCK_FILESYSTEMS
        .first()
        .and_then(|fs| fs.as_ref())
        .cloned()
        .expect("[ext4] /dev/vda is not a valid ext4 filesystem");

    /// Root inode of the primary filesystem.
    pub static ref ROOT_INODE: Arc<Inode> = BLOCK_ROOTS
        .first()
        .and_then(|root| root.as_ref())
        .cloned()
        .expect("[ext4] /dev/vda has no ext4 root inode");

    /// User-app filesystem root.  The split layout stores app binaries at the
    /// root of `/dev/vdb` and mounts that filesystem at `/user`.
    pub static ref USER_INODE: Arc<Inode> = BLOCK_ROOTS
        .get(1)
        .and_then(|root| root.as_ref())
        .cloned()
        .expect("[ext4] /dev/vdb has no user ext4 root inode");
}

fn root_inode_for_path(path: &str) -> Arc<Inode> {
    device_path_parts(path)
        .and_then(|(index, _)| block_root(index))
        .unwrap_or_else(|| ROOT_INODE.clone())
}

pub(crate) fn root_inode_for_device(device_id: usize) -> Option<Arc<Inode>> {
    BLOCK_ROOTS
        .iter()
        .filter_map(|root| root.as_ref())
        .find(|root| root.device_id() == device_id)
        .cloned()
}

pub(crate) fn ensure_root_mount_directory(name: &str) {
    let root_lock = ext4_inode_lock(&ROOT_INODE);
    let _root_guard = root_lock.write();
    if ROOT_INODE.find(name).is_some() {
        return;
    }
    root_lock.begin_namespace_mutation();
    if let Ok(inode) = ROOT_INODE.create_dir(name) {
        inode.set_uid_gid(0, 0);
        inode.set_mode(0o755);
        clear_ext4_path_cache();
    }
}

pub(crate) fn block_device_source_path(name: &str) -> Option<String> {
    let index = block_device_index(name)?;
    BLOCK_ROOTS.get(index)?.as_ref()?;
    Some(alloc::format!("/dev/vd{}", (b'a' + index as u8) as char))
}

/// Resolve a block-device mount source directly to that device's ext4 root.
/// Object-VFS callers use this instead of manufacturing a hidden pathname.
pub(crate) fn block_root_for_source(name: &str) -> Option<Arc<Inode>> {
    block_device_index(name).and_then(block_root)
}

fn block_device_index(name: &str) -> Option<usize> {
    let suffix = name
        .strip_prefix("/dev/vd")
        .or_else(|| name.strip_prefix("vd"))?;
    if suffix.len() != 1 {
        return None;
    }
    suffix
        .as_bytes()
        .first()
        .and_then(|letter| letter.checked_sub(b'a'))
        .map(usize::from)
}

fn device_path_parts(path: &str) -> Option<(usize, &str)> {
    let path = path.strip_prefix("/dev/")?;
    let (device, suffix) = path.split_once('/').unwrap_or((path, ""));
    Some((block_device_index(device)?, suffix))
}

pub(crate) fn block_root(index: usize) -> Option<Arc<Inode>> {
    BLOCK_ROOTS
        .get(index)
        .and_then(|root| root.as_ref())
        .cloned()
}

/// Find a path in exactly one filesystem.
///
/// Transitional callers may identify a non-root filesystem as `/dev/vdX`.
/// The device name selects exactly one ext4 root; missing files never fall
/// through to another disk, matching Linux mount semantics.  Object-VFS
/// callers hold the selected filesystem directly and do not use this path.
///
fn find_path_from_inode(start: Arc<Inode>, path: &str) -> Option<Arc<Inode>> {
    let mut current = start;
    for component in path.split('/').filter(|component| !component.is_empty()) {
        if component == "." {
            continue;
        }
        let next = {
            let current_lock = ext4_inode_lock(&current);
            let _current_guard = current_lock.read();
            current.find(component)?
        };
        current = next;
    }
    Some(current)
}

/// Each component lookup takes the directory's shared `i_rwsem` equivalent.
pub(crate) fn find_path_in_roots(path: &str) -> Option<Arc<Inode>> {
    if let Some((index, suffix)) = device_path_parts(path) {
        let root = block_root(index)?;
        if suffix.is_empty() {
            return Some(root);
        }
        return find_path_from_inode(root, suffix);
    }
    find_path_from_inode(Arc::clone(&ROOT_INODE), path)
}

/// List all files in the filesystem
#[allow(dead_code)]
pub fn list_apps() {
    let user_lock = ext4_inode_lock(&USER_INODE);
    let _user_guard = user_lock.read();
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
        find_path_from_inode(Arc::clone(&base_dir), raw)
    };

    // Keep compatibility: exec("foo") can omit ".bin".
    if inode.is_none() && !raw.contains('/') && !raw.ends_with(".bin") {
        let name_with_bin = alloc::format!("{}.bin", raw);
        inode = find_path_from_inode(Arc::clone(&base_dir), &name_with_bin);
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
            find_path_from_inode(Arc::clone(&base_dir), parent_path)?
        };
        let parent_lock = ext4_inode_lock(&parent);
        let _parent_guard = parent_lock.write();
        parent_lock.begin_namespace_mutation();
        inode = parent.create_file(file_name).ok();
        if inode.is_some() {
            clear_ext4_path_cache();
        }
    }

    let inode = inode?;

    // TRUNC: clear file contents.
    if flags.contains(OpenFlags::TRUNC) {
        let inode_lock = ext4_inode_lock(&inode);
        let _inode_guard = inode_lock.write();
        let _ = inode.clear();
    }

    Some(Arc::new(OSInode::new(readable, writable, inode).ok()?))
}

impl File for OSInode {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn on_fd_install(&self) {
        self.open_fd_refs.fetch_add(1, Ordering::AcqRel);
        let mut write_open = self.write_open.lock();
        if write_open.key.is_some() {
            write_open.fd_refs = write_open.fd_refs.saturating_add(1);
        }
    }

    fn on_fd_close(&self) {
        let last_fd = self.close_fd_ref();
        let key = {
            let mut write_open = self.write_open.lock();
            if write_open.fd_refs > 0 {
                write_open.fd_refs -= 1;
            }
            if write_open.fd_refs == 0 {
                write_open.key.take()
            } else {
                None
            }
        };
        // Linux runs the potentially sleeping part of fput from task/workqueue
        // context.  Flush our per-description write buffer while the last fd
        // is being closed, before the Arc can be reclaimed by the idle cleanup
        // path where there is no current task to sleep on an inode rwsem.
        if last_fd && self.writable {
            let _ = self.flush_with_error();
        }
        if let Some((dev, ino)) = key {
            unregister_write_open_inode(dev, ino);
        }
        if last_fd {
            crate::syscall::filesystem::release_flock_owner_for_inode(
                self.inode_device_id,
                self.inode_num,
                self.flock_owner_id,
            );
        }
    }

    fn poll_mask(&self) -> i16 {
        if let Some(mask) = self.fixed_poll_mask() {
            return mask;
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

    fn fixed_poll_mask(&self) -> Option<i16> {
        self.regular_file_poll_ready.then_some(POLLIN | POLLOUT)
    }

    fn object_path(&self) -> Option<&VfsPath> {
        self.vfs_path.as_ref().map(PinnedPath::path)
    }

    fn logical_path_hint(&self) -> Option<&str> {
        self.fanotify_path.as_deref()
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let output_len = buf.len();
        let mut read_locked = || {
            let mut inner = self.inner.lock();
            if self.writable {
                let _ = Self::flush_inner_locked(&mut inner);
            }
            let mut total_read_size = 0usize;

            if inner.read_buf.len() < READBUF_MAX {
                inner.read_buf.resize(READBUF_MAX, 0);
                inner.read_buf_off = 0;
                inner.read_buf_valid = 0;
            }

            while total_read_size < output_len {
                let need_refill = inner.read_buf_valid == 0
                    || inner.offset < inner.read_buf_off
                    || inner.offset >= inner.read_buf_off + inner.read_buf_valid;

                if need_refill {
                    let sequential = inner.read_buf_valid > 0
                        && inner.offset == inner.read_buf_off.saturating_add(inner.read_buf_valid);
                    let refill_len = if sequential {
                        READBUF_MAX
                    } else {
                        core::cmp::min(
                            READBUF_MAX,
                            core::cmp::max(output_len - total_read_size, READBUF_MIN),
                        )
                    };
                    inner.read_buf_off = inner.offset;
                    let inode = inner.inode.clone();
                    let off = inner.read_buf_off;
                    let n = inode.read_at(off, &mut inner.read_buf[..refill_len]);
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
                        break;
                    }
                }

                let buf_off = inner.offset - inner.read_buf_off;
                let avail = inner.read_buf_valid.saturating_sub(buf_off);
                if avail == 0 {
                    continue;
                }

                let n = core::cmp::min(avail, output_len - total_read_size);
                let copied =
                    buf.copy_from_slice_at(total_read_size, &inner.read_buf[buf_off..buf_off + n]);
                inner.offset += copied;
                total_read_size += copied;
                if copied != n {
                    break;
                }
            }
            total_read_size
        };

        if self.writable {
            let _inode_guard = self.inode_lock.write();
            read_locked()
        } else {
            let _inode_guard = self.inode_lock.read();
            read_locked()
        }
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        let input_len = _buf.len();
        let mut input = alloc::vec![0u8; core::cmp::min(input_len, crate::config::PAGE_SIZE)];
        let _inode_guard = self.inode_lock.write();
        let mut inner = self.inner.lock();
        if self.append {
            if !inner.write_buf.is_empty() {
                if Self::flush_inner_locked(&mut inner).is_err() {
                    println!("[ext4] Warning: write failed");
                    return 0;
                }
                inner.read_buf_valid = 0;
            }
            let disk_end = inner.inode.size() as usize;
            let pending_end =
                pending_inode_write_end(inner.inode.device_id(), inner.inode.inode_num())
                    .unwrap_or(0);
            inner.offset = core::cmp::max(disk_end, pending_end);
        }
        let mut total_write_size = 0usize;

        let current_offset = inner.offset;
        if self
            .clear_inode_for_replace_write_locked(&mut inner, current_offset)
            .is_err()
        {
            return 0;
        }

        let mut input_offset = 0usize;
        while input_offset < input_len {
            let chunk = core::cmp::min(input.len(), input_len - input_offset);
            let copied = _buf.copy_to_slice_at(input_offset, &mut input[..chunk]);
            if copied == 0 {
                break;
            }
            let slice = &input[..copied];
            // Flush on non-sequential writes.
            if !inner.write_buf.is_empty()
                && inner.offset != inner.write_buf_off.saturating_add(inner.write_buf.len())
            {
                if Self::flush_inner_locked(&mut inner).is_err() {
                    println!("[ext4] Warning: write failed");
                    break;
                }
                inner.read_buf_valid = 0;
            }

            if inner.write_buf.is_empty() {
                inner.write_buf_off = inner.offset;
            }

            inner.write_buf.extend_from_slice(slice);
            if !slice.is_empty() {
                Self::mark_write_buf_dirty(&mut inner);
            }
            inner.offset += slice.len();
            total_write_size += slice.len();
            input_offset += slice.len();
            inner.read_buf_valid = 0;

            if inner.write_buf.len() >= WRITEBUF_MAX {
                if Self::flush_inner_locked(&mut inner).is_err() {
                    println!("[ext4] Warning: write failed");
                    break;
                }
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
        let inode_key = (self.inode_device_id, self.inode_num);
        // A read-only close does not need i_rwsem.  Linux ext4_release_file()
        // only enters write-side data synchronization for a last writer; an
        // unconditional inode write lock here can deadlock idle-side fput with
        // file-backed page faults that hold a read lock while sleeping on I/O.
        let has_pending_write = self.writable && !self.inner.lock().write_buf.is_empty();
        if has_pending_write {
            let _inode_guard = self.inode_lock.write();
            let mut inner = self.inner.lock();
            if !inner.write_buf.is_empty() {
                let off = inner.write_buf_off;
                let data = core::mem::take(&mut inner.write_buf);
                let _ = Self::write_at_zeroing_gap(&inner.inode, off, &data);
                Self::mark_write_buf_clean(&mut inner);
            }
        }
        crate::syscall::filesystem::release_flock_owner_for_inode(
            inode_key.0,
            inode_key.1,
            self.flock_owner_id,
        );
        if let Some(cleanup) = self.tmpfile_cleanup.take() {
            if {
                let parent_lock = ext4_inode_lock(&cleanup.parent);
                let _parent_guard = parent_lock.write();
                let child = cleanup.parent.find(&cleanup.name);
                let child_lock = child.as_ref().map(|child| ext4_inode_lock(child));
                let _child_guard = child_lock.as_ref().map(|lock| lock.write());
                parent_lock.begin_namespace_mutation();
                cleanup.parent.unlink(&cleanup.name)
            }
            .is_ok()
            {
                clear_ext4_path_cache();
            }
        }
        for cleanup in unregister_open_inode_description(inode_key) {
            cleanup_deferred_unlink(cleanup);
        }
        let key = {
            let mut write_open = self.write_open.lock();
            write_open.fd_refs = 0;
            write_open.key.take()
        };
        if let Some((dev, ino)) = key {
            unregister_write_open_inode(dev, ino);
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
