use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

use lazy_static::lazy_static;
use spin::Mutex;

use crate::{
    debug_config::DEBUG_FUTEX,
    mm::{PageTable, VirtAddr, read_user_value},
    task::block_sleep::add_timer,
    task::{
        manager::wakeup_task,
        processor::{block_current_and_run_next, current_process, current_task},
        signal::has_unmasked_pending,
        task_block::TaskControlBlock,
    },
    time::get_time_ms,
    trap::get_current_token,
};

const ENOSYS: isize = -38;
const EINVAL: isize = -22;
const EAGAIN: isize = -11;
const EINTR: isize = -4;
const ETIMEDOUT: isize = -110;

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const FUTEX_REQUEUE: usize = 3;
const FUTEX_CMP_REQUEUE: usize = 4;
const FUTEX_WAIT_BITSET: usize = 9;
const FUTEX_WAKE_BITSET: usize = 10;
const FUTEX_PRIVATE_FLAG: usize = 128;
const FUTEX_CLOCK_REALTIME: usize = 256;
const FUTEX_CMD_MASK: usize = 0x7f;

type FutexKey = (usize, usize); // (key_pid, uaddr)

lazy_static! {
    static ref FUTEX_QUEUES: Mutex<BTreeMap<FutexKey, VecDeque<Arc<TaskControlBlock>>>> =
        Mutex::new(BTreeMap::new());
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

fn timespec_to_ms(ts: TimeSpec) -> Option<usize> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= 1_000_000_000 {
        return None;
    }
    let ms = (ts.sec as u64)
        .saturating_mul(1_000)
        .saturating_add((ts.nsec as u64) / 1_000_000);
    Some(ms.min(usize::MAX as u64) as usize)
}

fn pending_unmasked_signal() -> bool {
    let task = current_task().unwrap();
    let inner = task.borrow_mut();
    has_unmasked_pending(inner.pending_signals, inner.signal_mask, false)
}

pub(crate) fn shared_futex_addr_key(token: usize, uaddr: usize) -> usize {
    let page_table = PageTable::from_token(token);
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

fn remove_waiter(key: FutexKey, task: &Arc<TaskControlBlock>) {
    let mut map = FUTEX_QUEUES.lock();
    let Some(queue) = map.get_mut(&key) else {
        return;
    };
    queue.retain(|t| !Arc::ptr_eq(t, task));
    if queue.is_empty() {
        map.remove(&key);
    }
}

pub fn remove_futex_waiters(task: &Arc<TaskControlBlock>) {
    let mut map = FUTEX_QUEUES.lock();
    map.retain(|_, queue| {
        queue.retain(|t| !Arc::ptr_eq(t, task));
        !queue.is_empty()
    });
}

pub(crate) fn futex_wake(key: FutexKey, uaddr: usize, nr_wake: usize) -> isize {
    if uaddr == 0 {
        return EINVAL;
    }
    if DEBUG_FUTEX {
        log::debug!(
            "[futex_wake] key_pid={} uaddr={:#x} nr={}",
            key.0,
            uaddr,
            nr_wake
        );
    }
    let mut map = FUTEX_QUEUES.lock();
    let Some(queue) = map.get_mut(&key) else {
        return 0;
    };
    let mut woke = 0usize;
    while woke < nr_wake {
        let Some(task) = queue.pop_front() else {
            break;
        };
        wakeup_task(task);
        woke += 1;
    }
    if queue.is_empty() {
        map.remove(&key);
    }
    woke as isize
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
                return EINVAL;
            }
            let task = current_task().unwrap();
            let pid = current_process().getpid();
            let token = get_current_token();
            let key = futex_key(pid, token, uaddr, _private);
            let mut map = FUTEX_QUEUES.lock();
            let cur = read_user_value(token, uaddr as *const i32);
            if cur != val as i32 {
                if DEBUG_FUTEX {
                    let tid = task
                        .borrow_mut()
                        .res
                        .as_ref()
                        .map(|r| r.tid)
                        .unwrap_or(usize::MAX);
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
                    EINTR
                } else {
                    EAGAIN
                };
            }
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
                return EINTR;
            }
            if DEBUG_FUTEX {
                let tid = task
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                log::debug!(
                    "[futex_wait] pid={} tid={} uaddr={:#x} val={}",
                    pid,
                    tid,
                    uaddr,
                    val
                );
            }
            let deadline_ms = if _timeout == 0 {
                None
            } else {
                let ts = read_user_value(token, _timeout as *const TimeSpec);
                let timeout_ms = match timespec_to_ms(ts) {
                    Some(ms) => ms,
                    None => return EINVAL,
                };
                let now_ms = get_time_ms();
                if clock_realtime {
                    if timeout_ms <= now_ms {
                        return ETIMEDOUT;
                    }
                    Some(timeout_ms)
                } else {
                    if timeout_ms == 0 {
                        return ETIMEDOUT;
                    }
                    Some(now_ms.saturating_add(timeout_ms))
                }
            };
            map.entry(key)
                .or_insert_with(VecDeque::new)
                .push_back(Arc::clone(&task));
            drop(map);
            if let Some(deadline_ms) = deadline_ms {
                let now_ms = get_time_ms();
                let wait_ms = deadline_ms.saturating_sub(now_ms);
                if wait_ms == 0 {
                    remove_waiter(key, &task);
                    return ETIMEDOUT;
                }
                add_timer(Arc::clone(&task), wait_ms);
            }
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
            if pending_unmasked_signal() {
                remove_waiter(key, &task);
                return EINTR;
            }
            if let Some(deadline_ms) = deadline_ms {
                let now_ms = get_time_ms();
                if now_ms >= deadline_ms {
                    let task = current_task().unwrap();
                    remove_waiter(key, &task);
                    return ETIMEDOUT;
                }
            }
            0
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let pid = current_process().getpid();
            let token = get_current_token();
            let key = futex_key(pid, token, uaddr, _private);
            futex_wake(key, uaddr, val)
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            if uaddr == 0 || _uaddr2 == 0 {
                return EINVAL;
            }
            let pid = current_process().getpid();
            let token = get_current_token();
            let key1 = futex_key(pid, token, uaddr, _private);
            let key2 = futex_key(pid, token, _uaddr2, _private);
            if cmd == FUTEX_CMP_REQUEUE {
                let cur = read_user_value(token, uaddr as *const i32);
                if cur != val as i32 {
                    return EAGAIN;
                }
            }
            let val2 = _timeout;
            let mut map = FUTEX_QUEUES.lock();
            let Some(mut queue1) = map.remove(&key1) else {
                return 0;
            };
            let mut woke = 0usize;
            while woke < val {
                let Some(task) = queue1.pop_front() else {
                    break;
                };
                wakeup_task(task);
                woke += 1;
            }
            if val2 > 0 && !queue1.is_empty() && key2 != key1 {
                let target = map.entry(key2).or_insert_with(VecDeque::new);
                let mut moved = 0usize;
                while moved < val2 {
                    let Some(task) = queue1.pop_front() else {
                        break;
                    };
                    target.push_back(task);
                    moved += 1;
                }
            }
            if !queue1.is_empty() {
                map.insert(key1, queue1);
            }
            woke as isize
        }
        _ => ENOSYS,
    }
}
