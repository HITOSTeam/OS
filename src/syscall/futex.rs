use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::syscall::error::{SyscallError, err};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::{
    config::clock_freq,
    debug_config::DEBUG_FUTEX,
    mm::{PageTable, VirtAddr, read_user_value},
    syscall::time_sys::realtime_now_timespec,
    task::block_sleep::add_timer,
    task::{
        manager::wakeup_task,
        processor::{block_current_and_run_next, current_process, current_task},
        signal::has_wait_interrupting_pending,
        task_block::TaskControlBlock,
    },
    time::get_time,
    trap::get_current_token,
};

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const FUTEX_REQUEUE: usize = 3;
const FUTEX_CMP_REQUEUE: usize = 4;
const FUTEX_WAIT_BITSET: usize = 9;
const FUTEX_WAKE_BITSET: usize = 10;
const FUTEX_PRIVATE_FLAG: usize = 128;
const FUTEX_CLOCK_REALTIME: usize = 256;
const FUTEX_CMD_MASK: usize = 0x7f;
const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;
const NSEC_PER_SEC: u64 = 1_000_000_000;
const NSEC_PER_MSEC: u64 = 1_000_000;

type FutexKey = (usize, usize); // (key_pid, uaddr)

#[derive(Clone)]
struct FutexWaiter {
    task: Arc<TaskControlBlock>,
    bitset: u32,
    in_queue: Arc<AtomicBool>,
}

lazy_static! {
    static ref FUTEX_QUEUES: Mutex<BTreeMap<FutexKey, VecDeque<FutexWaiter>>> =
        Mutex::new(BTreeMap::new());
}

static FUTEX_TIMEOUT_SEQ: AtomicUsize = AtomicUsize::new(0);
static FUTEX_WAIT_DIAG_BASE_NS: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

fn timespec_to_ns(ts: TimeSpec) -> Option<u64> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= NSEC_PER_SEC as i64 {
        return None;
    }
    Some(
        (ts.sec as u64)
            .saturating_mul(NSEC_PER_SEC)
            .saturating_add(ts.nsec as u64),
    )
}

fn monotonic_now_ns() -> u64 {
    let ticks = get_time() as u64;
    let freq = clock_freq() as u128;
    ((ticks as u128).saturating_mul(NSEC_PER_SEC as u128) / freq) as u64
}

fn realtime_now_ns() -> u64 {
    let (sec, nsec) = realtime_now_timespec();
    if sec < 0 || nsec < 0 {
        return 0;
    }
    (sec as u64)
        .saturating_mul(NSEC_PER_SEC)
        .saturating_add(nsec as u64)
}

fn ns_to_ms_ceil(ns: u64) -> usize {
    ((ns.saturating_add(NSEC_PER_MSEC - 1)) / NSEC_PER_MSEC) as usize
}

fn futex_wait_now_ns(cmd: usize, clock_realtime: bool) -> u64 {
    if cmd == FUTEX_WAIT_BITSET && clock_realtime {
        realtime_now_ns()
    } else {
        monotonic_now_ns()
    }
}

fn pending_unmasked_signal() -> bool {
    let task = current_task().unwrap();
    let inner = task.borrow_mut();
    has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
}

pub(crate) fn shared_futex_addr_key(token: usize, uaddr: usize) -> usize {
    let page_table = PageTable::from_token(token);
    if DEBUG_FUTEX && page_table.translate_va(VirtAddr::from(uaddr)).is_none() {
        log::debug!(
            "[futex_key] shared translation miss token={:#x} uaddr={:#x}, fallback to va key",
            token,
            uaddr
        );
    }
    page_table
        .translate_va(VirtAddr::from(uaddr))
        .map(|pa| {
            let pa_usize: usize = pa.into();
            pa_usize
        })
        .unwrap_or(uaddr)
}

fn futex_key(pid: usize, token: usize, uaddr: usize, private: bool) -> FutexKey {
    if private {
        (pid, uaddr)
    } else {
        // Process-shared futex: key by physical address to survive exec() where
        // user virtual addresses often change (notably in glibc test helpers).
        (0, shared_futex_addr_key(token, uaddr))
    }
}

fn remove_waiter(in_queue: &Arc<AtomicBool>) -> Option<FutexKey> {
    let mut map = FUTEX_QUEUES.lock();
    let mut removed = false;
    let mut removed_key = None;
    map.retain(|key, queue| {
        queue.retain(|w| {
            let keep = !Arc::ptr_eq(&w.in_queue, in_queue);
            if !keep {
                removed = true;
            }
            keep
        });
        if removed && removed_key.is_none() {
            removed_key = Some(*key);
        }
        !queue.is_empty()
    });
    if removed {
        in_queue.store(false, Ordering::Release);
        removed_key
    } else {
        None
    }
}

pub fn remove_futex_waiters(task: &Arc<TaskControlBlock>) {
    let mut map = FUTEX_QUEUES.lock();
    map.retain(|_, queue| {
        queue.retain(|w| {
            let keep = !Arc::ptr_eq(&w.task, task);
            if !keep {
                w.in_queue.store(false, Ordering::Release);
            }
            keep
        });
        !queue.is_empty()
    });
}

pub fn debug_count_task_waiters(task: &Arc<TaskControlBlock>) -> usize {
    FUTEX_QUEUES
        .lock()
        .values()
        .map(|queue| queue.iter().filter(|w| Arc::ptr_eq(&w.task, task)).count())
        .sum()
}

fn futex_wake_with_mask(key: FutexKey, uaddr: usize, nr_wake: usize, bitset_mask: u32) -> isize {
    if uaddr == 0 {
        return err(SyscallError::EINVAL);
    }
    if bitset_mask == 0 {
        return err(SyscallError::EINVAL);
    }
    if DEBUG_FUTEX {
        log::debug!(
            "[futex_wake] key_pid={} uaddr={:#x} nr={} bitset={:#x}",
            key.0,
            uaddr,
            nr_wake,
            bitset_mask
        );
    }
    let mut wake_list = Vec::new();
    let woke = {
        let mut map = FUTEX_QUEUES.lock();
        let Some(queue) = map.get_mut(&key) else {
            return 0;
        };
        let mut woke = 0usize;
        let mut remain = VecDeque::new();
        while let Some(waiter) = queue.pop_front() {
            if woke < nr_wake && (waiter.bitset & bitset_mask) != 0 {
                waiter.in_queue.store(false, Ordering::Release);
                wake_list.push(waiter.task);
                woke += 1;
            } else {
                remain.push_back(waiter);
            }
        }
        *queue = remain;
        if queue.is_empty() {
            map.remove(&key);
        }
        woke
    };
    for task in wake_list {
        wakeup_task(task);
    }
    woke as isize
}

pub(crate) fn futex_wake(key: FutexKey, uaddr: usize, nr_wake: usize) -> isize {
    futex_wake_with_mask(key, uaddr, nr_wake, FUTEX_BITSET_MATCH_ANY)
}

/// Wake futex waiters when caller doesn't know whether the waiter used
/// `FUTEX_PRIVATE_FLAG`.
///
/// We wake both:
/// - private key: `(pid, uaddr)`
/// - shared key: `(0, pa(uaddr))`
pub(crate) fn futex_wake_private_and_shared(
    pid: usize,
    token: usize,
    uaddr: usize,
    nr_wake: usize,
) -> isize {
    let woke_private = futex_wake((pid, uaddr), uaddr, nr_wake);
    let shared_key = (0, shared_futex_addr_key(token, uaddr));
    let woke_shared = futex_wake(shared_key, uaddr, nr_wake);
    if woke_private < 0 {
        return woke_private;
    }
    if woke_shared < 0 {
        return woke_shared;
    }
    woke_private.saturating_add(woke_shared)
}

pub fn syscall_futex(
    uaddr: usize,
    op: usize,
    val: usize,
    _timeout: usize,
    _uaddr2: usize,
    _val3: usize,
) -> isize {
    let cmd = op & FUTEX_CMD_MASK;
    let _private = (op & FUTEX_PRIVATE_FLAG) != 0;
    let clock_realtime = (op & FUTEX_CLOCK_REALTIME) != 0;
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            if uaddr == 0 {
                return err(SyscallError::EINVAL);
            }
            let task = current_task().unwrap();
            let pid = current_process().getpid();
            let tid = task
                .borrow_mut()
                .res
                .as_ref()
                .map(|r| r.tid)
                .unwrap_or(usize::MAX);
            let token = get_current_token();
            let bitset = if cmd == FUTEX_WAIT_BITSET {
                let bitset = _val3 as u32;
                if bitset == 0 {
                    return err(SyscallError::EINVAL);
                }
                bitset
            } else {
                FUTEX_BITSET_MATCH_ANY
            };
            let cur = read_user_value(token, uaddr as *const i32);
            if cur != val as i32 {
                if DEBUG_FUTEX {
                    log::debug!(
                        "[futex_wait] mismatch pid={} tid={} uaddr={:#x} cur={} expected={}",
                        pid,
                        tid,
                        uaddr,
                        cur,
                        val
                    );
                }
                return if pending_unmasked_signal() {
                    err(SyscallError::EINTR)
                } else {
                    err(SyscallError::EAGAIN)
                };
            }
            // Read first, then derive key. This forces lazy mappings to be
            // instantiated before shared-key PA translation.
            let key = futex_key(pid, token, uaddr, _private);
            let in_queue = Arc::new(AtomicBool::new(true));
            let mut map = FUTEX_QUEUES.lock();
            let queue_len_before = map.get(&key).map(VecDeque::len).unwrap_or(0);
            if crate::debug_config::DEBUG_PTHREAD {
                let (tid, pending_sig, mask) = {
                    let inner = task.borrow_mut();
                    (
                        inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX),
                        inner.pending_signals,
                        inner.signal_mask,
                    )
                };
                log::debug!(
                    "[futex_wait] pid={} tid={} uaddr={:#x} val={} pending_sig={:#x} mask={:#x}",
                    pid,
                    tid,
                    uaddr,
                    val,
                    pending_sig,
                    mask
                );
            }
            if pending_unmasked_signal() {
                return err(SyscallError::EINTR);
            }
            if DEBUG_FUTEX {
                log::debug!(
                    "[futex_wait] pid={} tid={} uaddr={:#x} val={}",
                    pid,
                    tid,
                    uaddr,
                    val
                );
            }
            let wait_start_ns = futex_wait_now_ns(cmd, clock_realtime);
            let deadline_ns = if _timeout == 0 {
                None
            } else {
                let ts = read_user_value(token, _timeout as *const TimeSpec);
                let timeout_ns = match timespec_to_ns(ts) {
                    Some(ns) => ns,
                    None => return err(SyscallError::EINVAL),
                };
                let now_ns = futex_wait_now_ns(cmd, clock_realtime);
                let deadline_ns = if cmd == FUTEX_WAIT_BITSET {
                    timeout_ns
                } else {
                    now_ns.saturating_add(timeout_ns)
                };
                if deadline_ns <= now_ns {
                    return err(SyscallError::ETIMEDOUT);
                }
                Some(deadline_ns)
            };
            map.entry(key)
                .or_insert_with(VecDeque::new)
                .push_back(FutexWaiter {
                    task: Arc::clone(&task),
                    bitset,
                    in_queue: Arc::clone(&in_queue),
                });
            if DEBUG_FUTEX && queue_len_before == 0 {
                FUTEX_WAIT_DIAG_BASE_NS.store(monotonic_now_ns() as usize, Ordering::Relaxed);
            }
            if DEBUG_FUTEX {
                let queue_len_after = map.get(&key).map(VecDeque::len).unwrap_or(0);
                log::debug!(
                    "[futex_wait_enqueue] pid={} tid={} private={} uaddr={:#x} key=({:#x},{:#x}) val={} bitset={:#x} qlen={}=>{}",
                    pid,
                    tid,
                    _private,
                    uaddr,
                    key.0,
                    key.1,
                    val,
                    bitset,
                    queue_len_before,
                    queue_len_after
                );
                if queue_len_after >= 100 && queue_len_after % 100 == 0 {
                    let base_ns = FUTEX_WAIT_DIAG_BASE_NS.load(Ordering::Relaxed) as u64;
                    let now_ns = monotonic_now_ns();
                    let elapsed_ms = if base_ns == 0 {
                        0
                    } else {
                        now_ns.saturating_sub(base_ns).saturating_div(NSEC_PER_MSEC)
                    };
                    log::warn!(
                        "[futex_wait_depth] pid={} tid={} key=({:#x},{:#x}) qlen={} val={} elapsed_ms={}",
                        pid,
                        tid,
                        key.0,
                        key.1,
                        queue_len_after,
                        val,
                        elapsed_ms
                    );
                }
            }
            drop(map);
            if let Some(deadline_ns) = deadline_ns {
                let now_ns = futex_wait_now_ns(cmd, clock_realtime);
                if now_ns >= deadline_ns {
                    let _ = remove_waiter(&in_queue);
                    return err(SyscallError::ETIMEDOUT);
                }
                let wait_ms = ns_to_ms_ceil(deadline_ns.saturating_sub(now_ns)).max(1);
                add_timer(Arc::clone(&task), wait_ms);
            }
            loop {
                block_current_and_run_next();
                if crate::debug_config::DEBUG_PTHREAD {
                    let (tid, pending_sig, mask) = {
                        let inner = task.borrow_mut();
                        (
                            inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX),
                            inner.pending_signals,
                            inner.signal_mask,
                        )
                    };
                    log::debug!(
                        "[futex_wait] pid={} tid={} woke pending_sig={:#x} mask={:#x}",
                        pid,
                        tid,
                        pending_sig,
                        mask
                    );
                }
                // Fast waiter-local check: dequeue side clears this bit before waking us.
                if !in_queue.load(Ordering::Acquire) {
                    return 0;
                }
                if pending_unmasked_signal() {
                    if let Some(removed_key) = remove_waiter(&in_queue) {
                        if DEBUG_FUTEX {
                            let seq = FUTEX_TIMEOUT_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
                            if seq <= 8 || seq % 64 == 0 {
                                log::warn!(
                                    "[futex_wait_detach] seq={} reason=signal pid={} tid={} key=({:#x},{:#x})",
                                    seq,
                                    pid,
                                    tid,
                                    removed_key.0,
                                    removed_key.1
                                );
                            }
                        }
                        return err(SyscallError::EINTR);
                    }
                    if !in_queue.load(Ordering::Acquire) {
                        return 0;
                    }
                    return err(SyscallError::EINTR);
                }
                if let Some(deadline_ns) = deadline_ns {
                    let now_ns = futex_wait_now_ns(cmd, clock_realtime);
                    if now_ns >= deadline_ns {
                        if let Some(removed_key) = remove_waiter(&in_queue) {
                            if DEBUG_FUTEX {
                                let seq = FUTEX_TIMEOUT_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
                                let waited_ms = now_ns
                                    .saturating_sub(wait_start_ns)
                                    .saturating_div(NSEC_PER_MSEC);
                                if seq <= 16 || seq % 32 == 0 {
                                    log::warn!(
                                        "[futex_wait_detach] seq={} reason=timeout pid={} tid={} key=({:#x},{:#x}) waited_ms={}",
                                        seq,
                                        pid,
                                        tid,
                                        removed_key.0,
                                        removed_key.1,
                                        waited_ms
                                    );
                                }
                            }
                            return err(SyscallError::ETIMEDOUT);
                        }
                        if !in_queue.load(Ordering::Acquire) {
                            return 0;
                        }
                        return err(SyscallError::ETIMEDOUT);
                    }
                    // Our timer wheel is millisecond-granularity and may wake
                    // slightly early; re-arm until the absolute deadline.
                    let wait_ms = ns_to_ms_ceil(deadline_ns.saturating_sub(now_ns)).max(1);
                    add_timer(Arc::clone(&task), wait_ms);
                }
                // Blocked signals can still wake tasks in our scheduler, so if
                // the waiter remains queued we continue sleeping.
            }
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let nr_wake = val as isize;
            if nr_wake < 0 {
                return err(SyscallError::EINVAL);
            }
            let bitset_mask = if cmd == FUTEX_WAKE_BITSET {
                let bitset = _val3 as u32;
                if bitset == 0 {
                    return err(SyscallError::EINVAL);
                }
                bitset
            } else {
                FUTEX_BITSET_MATCH_ANY
            };
            let pid = current_process().getpid();
            let token = get_current_token();
            // Validate/fault-in mapping before PA-based shared-key lookup.
            let _ = read_user_value(token, uaddr as *const i32);
            let key = futex_key(pid, token, uaddr, _private);
            futex_wake_with_mask(key, uaddr, nr_wake as usize, bitset_mask)
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            if uaddr == 0 || _uaddr2 == 0 {
                return err(SyscallError::EINVAL);
            }
            let nr_wake = val as isize;
            let nr_requeue = _timeout as isize;
            if nr_wake < 0 || nr_requeue < 0 {
                return err(SyscallError::EINVAL);
            }
            let pid = current_process().getpid();
            let token = get_current_token();
            let key1 = futex_key(pid, token, uaddr, _private);
            let key2 = futex_key(pid, token, _uaddr2, _private);
            if DEBUG_FUTEX {
                log::warn!(
                    "[futex_requeue_enter] pid={} private={} cmd={} uaddr={:#x} uaddr2={:#x} key1=({:#x},{:#x}) key2=({:#x},{:#x}) nr_wake={} nr_requeue={} cmp_expected={}",
                    pid,
                    _private,
                    cmd,
                    uaddr,
                    _uaddr2,
                    key1.0,
                    key1.1,
                    key2.0,
                    key2.1,
                    nr_wake,
                    nr_requeue,
                    _val3
                );
            }
            if cmd == FUTEX_CMP_REQUEUE {
                let cur = read_user_value(token, uaddr as *const i32);
                if DEBUG_FUTEX {
                    log::warn!(
                        "[futex_cmp_requeue_cmp] pid={} uaddr={:#x} key1=({:#x},{:#x}) cur={} expected={}",
                        pid,
                        uaddr,
                        key1.0,
                        key1.1,
                        cur,
                        _val3
                    );
                }
                if cur != _val3 as i32 {
                    if DEBUG_FUTEX {
                        log::warn!(
                            "[futex_cmp_requeue_cmp] cmp mismatch -> err(SyscallError::EAGAIN) pid={} uaddr={:#x}",
                            pid,
                            uaddr
                        );
                    }
                    return err(SyscallError::EAGAIN);
                }
            }
            let val2 = nr_requeue as usize;
            let mut wake_list = Vec::new();
            let (woke, moved) = {
                let mut map = FUTEX_QUEUES.lock();
                let key1_len_before = map.get(&key1).map(VecDeque::len).unwrap_or(0);
                let key2_len_before = map.get(&key2).map(VecDeque::len).unwrap_or(0);
                let Some(mut queue1) = map.remove(&key1) else {
                    if DEBUG_FUTEX {
                        log::warn!(
                            "[futex_requeue_state] pid={} key1=({:#x},{:#x}) missing source queue key1_len_before={} key2_len_before={}",
                            pid,
                            key1.0,
                            key1.1,
                            key1_len_before,
                            key2_len_before
                        );
                    }
                    return 0;
                };
                let mut woke = 0usize;
                let mut moved = 0usize;
                while woke < nr_wake as usize {
                    let Some(waiter) = queue1.pop_front() else {
                        break;
                    };
                    waiter.in_queue.store(false, Ordering::Release);
                    wake_list.push(waiter.task);
                    woke += 1;
                }
                let skipped_same_key = val2 > 0 && !queue1.is_empty() && key2 == key1;
                if val2 > 0 && !queue1.is_empty() && key2 != key1 {
                    let target = map.entry(key2).or_insert_with(VecDeque::new);
                    while moved < val2 {
                        let Some(waiter) = queue1.pop_front() else {
                            break;
                        };
                        target.push_back(waiter);
                        moved += 1;
                    }
                }
                if !queue1.is_empty() {
                    map.insert(key1, queue1);
                }
                if DEBUG_FUTEX {
                    let key1_len_after = map.get(&key1).map(VecDeque::len).unwrap_or(0);
                    let key2_len_after = map.get(&key2).map(VecDeque::len).unwrap_or(0);
                    log::warn!(
                        "[futex_requeue_state] pid={} key1=({:#x},{:#x}) key2=({:#x},{:#x}) qlen1={}=>{} qlen2={}=>{} woke={} moved={} skipped_same_key={}",
                        pid,
                        key1.0,
                        key1.1,
                        key2.0,
                        key2.1,
                        key1_len_before,
                        key1_len_after,
                        key2_len_before,
                        key2_len_after,
                        woke,
                        moved,
                        skipped_same_key
                    );
                }
                (woke, moved)
            };
            for task in wake_list {
                wakeup_task(task);
            }
            woke.saturating_add(moved) as isize
        }
        _ => err(SyscallError::ENOSYS),
    }
}
