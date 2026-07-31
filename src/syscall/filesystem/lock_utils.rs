use super::{
    Arc, BTreeMap, BTreeSet, File, Mutex, OSInode, PID2PCB, ProcessControlBlock, SIGIO_NUM,
    SyscallError, TaskControlBlock, Vec, VecDeque, current_task, err,
    has_wait_interrupting_pending, inode_visible_size, queue_process_signal, wakeup_tasks,
};
use lazy_static::lazy_static;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct FcntlFlock {
    pub(crate) l_type: i16,
    pub(crate) l_whence: i16,
    pub(crate) l_start: i64,
    pub(crate) l_len: i64,
    pub(crate) l_pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct FcntlOwnerEx {
    pub(crate) type_: i32,
    pub(crate) pid: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileLockKey {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordLock {
    pub(crate) owner: RecordLockOwner,
    pub(crate) owner_pid: usize,
    pub(crate) lock_type: i16,
    pub(crate) start: i64,
    pub(crate) end: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RecordLockOwner {
    Process(usize),
    OpenFile(usize),
}

#[derive(Clone, Copy)]
pub(crate) struct WaitingRecordLock {
    pub(crate) key: FileLockKey,
    pub(crate) req_type: i16,
    pub(crate) start: i64,
    pub(crate) end: Option<i64>,
}

#[derive(Clone, Copy)]
pub(crate) struct FlockLock {
    pub(crate) owner: usize,
    pub(crate) exclusive: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct FileLease {
    pub(crate) owner_pid: usize,
    pub(crate) lease_type: i16,
    pub(crate) pending_break_write: bool,
}

lazy_static! {
    pub(crate) static ref RECORD_LOCKS: Mutex<BTreeMap<FileLockKey, Vec<RecordLock>>> =
        Mutex::new(BTreeMap::new());
    pub(crate) static ref RECORD_LOCK_WAITERS: Mutex<BTreeMap<FileLockKey, VecDeque<Arc<TaskControlBlock>>>> =
        Mutex::new(BTreeMap::new());
    pub(crate) static ref RECORD_LOCK_BLOCKED: Mutex<BTreeMap<usize, WaitingRecordLock>> =
        Mutex::new(BTreeMap::new());
    pub(crate) static ref FLOCK_LOCKS: Mutex<BTreeMap<FileLockKey, Vec<FlockLock>>> =
        Mutex::new(BTreeMap::new());
    pub(crate) static ref FILE_LEASES: Mutex<BTreeMap<FileLockKey, FileLease>> =
        Mutex::new(BTreeMap::new());
}

/// Derives the lock-table key for a file when it is backed by an ext4 inode.
pub(crate) fn file_lock_key(file: &Arc<dyn File + Send + Sync>) -> Option<FileLockKey> {
    let os_inode = file.as_any().downcast_ref::<OSInode>()?;
    let inode = os_inode.ext4_inode();
    Some(file_lock_key_from_inode(&inode))
}

/// Builds the canonical device/inode key used by record locks and leases.
pub(crate) fn file_lock_key_from_inode(inode: &Arc<ext4_fs::Inode>) -> FileLockKey {
    FileLockKey {
        dev: inode.device_id() as u64,
        ino: inode.inode_num() as u64,
    }
}

/// Returns a stable owner id for open-file-description locks on this handle.
pub(crate) fn ofd_lock_owner_id(file: &Arc<dyn File + Send + Sync>) -> usize {
    Arc::as_ptr(file) as *const () as usize
}

/// Treats `None` as an unbounded range end for comparisons.
pub(crate) fn range_end_i128(end: Option<i64>) -> i128 {
    end.map(|v| v as i128).unwrap_or(i128::MAX)
}

/// Returns whether two byte ranges intersect.
pub(crate) fn ranges_overlap(
    a_start: i64,
    a_end: Option<i64>,
    b_start: i64,
    b_end: Option<i64>,
) -> bool {
    let a0 = a_start as i128;
    let b0 = b_start as i128;
    let a1 = range_end_i128(a_end);
    let b1 = range_end_i128(b_end);
    a0 <= b1 && b0 <= a1
}

/// Returns the larger of two optional range ends, preserving infinity.
pub(crate) fn max_range_end(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (None, _) | (_, None) => None,
        (Some(x), Some(y)) => Some(core::cmp::max(x, y)),
    }
}

/// Returns whether two sorted ranges either overlap or are immediately adjacent.
pub(crate) fn ranges_touch_or_overlap_sorted(left_end: Option<i64>, right_start: i64) -> bool {
    match left_end {
        None => true,
        Some(end) => right_start <= end.saturating_add(1),
    }
}

/// Tests whether a requested record lock conflicts with an existing one.
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

/// Returns the first conflicting lock in deterministic order, if any.
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

/// Drops unlock records, sorts by owner/range, and merges adjacent compatible locks.
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

/// Applies one lock or unlock request to the locks owned by a single owner.
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

/// Collects process owners whose locks block the requested range.
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

/// Records that `pid` is currently blocked on a record-lock request.
pub(crate) fn set_record_lock_waiting(pid: usize, waiting: WaitingRecordLock) {
    RECORD_LOCK_BLOCKED.lock().insert(pid, waiting);
}

/// Clears the remembered blocked-lock state for `pid`.
pub(crate) fn clear_record_lock_waiting(pid: usize) {
    RECORD_LOCK_BLOCKED.lock().remove(&pid);
}

/// Detects whether granting a wait would create a process-level lock dependency cycle.
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

/// Converts a userspace `struct flock` into an absolute byte range for this file.
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
            let os_inode = file
                .as_any()
                .downcast_ref::<OSInode>()
                .ok_or_else(|| err(SyscallError::EINVAL))?;
            i64::try_from(os_inode.offset()).map_err(|_| err(SyscallError::EOVERFLOW))?
        }
        SEEK_END => {
            let os_inode = file
                .as_any()
                .downcast_ref::<OSInode>()
                .ok_or_else(|| err(SyscallError::EINVAL))?;
            let inode = os_inode.ext4_inode();
            i64::try_from(inode_visible_size(&inode)).map_err(|_| err(SyscallError::EOVERFLOW))?
        }
        _ => return Err(err(SyscallError::EINVAL)),
    };

    let mut start = base
        .checked_add(flock.l_start)
        .ok_or_else(|| err(SyscallError::EOVERFLOW))?;
    if start < 0 {
        return Err(err(SyscallError::EINVAL));
    }

    if flock.l_len > 0 {
        let end = start
            .checked_add(flock.l_len - 1)
            .ok_or_else(|| err(SyscallError::EOVERFLOW))?;
        return Ok((start, Some(end)));
    }
    if flock.l_len == 0 {
        return Ok((start, None));
    }

    let neg_start = start
        .checked_add(flock.l_len)
        .ok_or_else(|| err(SyscallError::EOVERFLOW))?;
    let end = start
        .checked_sub(1)
        .ok_or_else(|| err(SyscallError::EOVERFLOW))?;
    if neg_start < 0 {
        return Err(err(SyscallError::EINVAL));
    }
    start = neg_start;
    Ok((start, Some(end)))
}

/// Enqueues a task on the wait list for a lock key unless it is already present.
pub(crate) fn enqueue_record_lock_waiter(key: FileLockKey, task: &Arc<TaskControlBlock>) {
    let mut waiters = RECORD_LOCK_WAITERS.lock();
    let queue = waiters.entry(key).or_insert_with(VecDeque::new);
    if queue.iter().any(|waiter| Arc::ptr_eq(waiter, task)) {
        return;
    }
    queue.push_back(Arc::clone(task));
}

/// Removes one task from a lock wait queue and drops the queue if it becomes empty.
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

/// Drains and returns all waiters currently parked on a lock key.
pub(crate) fn take_record_lock_waiters(key: FileLockKey) -> Vec<Arc<TaskControlBlock>> {
    RECORD_LOCK_WAITERS
        .lock()
        .remove(&key)
        .map(|queue| queue.into_iter().collect())
        .unwrap_or_default()
}

/// Wakes every task currently blocked on a record-lock key.
pub(crate) fn wake_record_lock_waiters(key: FileLockKey) {
    wakeup_tasks(take_record_lock_waiters(key));
}

/// Tries to install or convert a BSD `flock` owned by one open file description.
///
/// The owner is removed before conflict checking so a SH->EX conversion cannot
/// deadlock while retaining its old shared lock. The table update itself stays
/// atomic when the conversion can be granted immediately.
pub(crate) fn try_apply_flock(key: FileLockKey, owner: usize, exclusive: bool) -> (bool, bool) {
    let mut table = FLOCK_LOCKS.lock();
    let locks = table.entry(key).or_insert_with(Vec::new);
    let old = locks
        .iter()
        .find(|lock| lock.owner == owner)
        .map(|lock| lock.exclusive);
    locks.retain(|lock| lock.owner != owner);

    let conflict = locks.iter().any(|lock| exclusive || lock.exclusive);
    if conflict {
        if locks.is_empty() {
            table.remove(&key);
        }
        return (false, old.is_some());
    }

    locks.push(FlockLock { owner, exclusive });
    (
        true,
        old.is_some_and(|old_exclusive| old_exclusive != exclusive),
    )
}

/// Returns whether another open file description conflicts with this request.
pub(crate) fn flock_has_conflict(key: FileLockKey, owner: usize, exclusive: bool) -> bool {
    FLOCK_LOCKS.lock().get(&key).is_some_and(|locks| {
        locks
            .iter()
            .any(|lock| lock.owner != owner && (exclusive || lock.exclusive))
    })
}

/// Releases a BSD lock and wakes tasks waiting on this inode.
pub(crate) fn release_flock_owner(key: FileLockKey, owner: usize) {
    let changed = {
        let mut table = FLOCK_LOCKS.lock();
        let Some(locks) = table.get_mut(&key) else {
            return;
        };
        let before = locks.len();
        locks.retain(|lock| lock.owner != owner);
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

/// Drop hook used by `OSInode` when its open file description disappears.
pub(crate) fn release_flock_owner_for_inode(dev: usize, ino: u32, owner: usize) {
    release_flock_owner(
        FileLockKey {
            dev: dev as u64,
            ino: ino as u64,
        },
        owner,
    );
}

/// Removes all process-owned locks for `key` and wakes waiters if anything changed.
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

/// Drops the file lease for `key` when it belongs to `owner_pid`.
pub(crate) fn remove_owner_file_lease_for_key(owner_pid: usize, key: FileLockKey) {
    let mut table = FILE_LEASES.lock();
    if table
        .get(&key)
        .is_some_and(|lease| lease.owner_pid == owner_pid)
    {
        table.remove(&key);
    }
}

/// Counts open descriptors across all processes that still reference this inode key.
pub(crate) fn count_open_fds_for_key(key: FileLockKey) -> usize {
    let processes: Vec<alloc::sync::Arc<ProcessControlBlock>> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    let mut count = 0usize;
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        let table = alloc::sync::Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(alloc::sync::Arc::as_ptr(&table) as usize) {
            continue;
        }
        for (_fd, file) in table.lock().iter_files_snapshot() {
            if file_lock_key(&file).is_some_and(|k| k == key) {
                count += 1;
            }
        }
    }
    count
}

/// Installs, updates, or removes a file lease after Linux-style ownership checks.
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
        _ => return err(SyscallError::EINVAL),
    }
    if lease_type == F_UNLCK {
        let mut table = FILE_LEASES.lock();
        match table.get(&key) {
            Some(lease) if lease.owner_pid != owner_pid => err(SyscallError::EAGAIN),
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
                return err(SyscallError::EAGAIN);
            }
            if lease.pending_break_write {
                return err(SyscallError::EAGAIN);
            }
        }

        if lease_type == F_RDLCK {
            // Linux read lease requires read-only open description.
            if !file.readable() || file.writable() {
                return err(SyscallError::EAGAIN);
            }
        } else if lease_type == F_WRLCK {
            // Linux write lease requires no other open descriptors.
            if count_open_fds_for_key(key) > 1 {
                return err(SyscallError::EBUSY);
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

/// Returns the lease type held by `owner_pid` for `key`, or `F_UNLCK` when absent.
pub(crate) fn get_file_lease_type(key: FileLockKey, owner_pid: usize) -> i16 {
    FILE_LEASES
        .lock()
        .get(&key)
        .filter(|lease| lease.owner_pid == owner_pid)
        .map(|lease| lease.lease_type)
        .unwrap_or(2)
}

/// Sends a lease-break notification when an operation would conflict with an existing lease.
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

/// Returns whether the current task has an unmasked pending signal that should abort waits.
pub(crate) fn has_pending_unmasked_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
}
