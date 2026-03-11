// this is used for sleep (blocked) threads
use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use core::{cmp::Ordering, time};

use crate::task::signal::{SIGALRM_NUM, pick_task_for_signal, queue_process_signal, signal_bit};
use crate::{
    task::{manager::wakeup_task, task_block::TaskControlBlock},
    time::get_time_ms,
};
use lazy_static::*;
use spin::Mutex;

use alloc::vec::Vec;
use alloc::{collections::BinaryHeap, sync::Arc};

use crate::debug_config::{DEBUG_TIMER, DEBUG_UNIXBENCH};
use crate::task::process_block::ProcessControlBlock;
use crate::{
    arch, mm::write_user_value, syscall::futex::futex_wake_private_and_shared,
    task::manager::pid2process,
};
pub struct TimeWrap {
    pub task: Arc<TaskControlBlock>,
    pub tid: usize,
    pub time_expired: usize,
}
impl TimeWrap {
    fn new(task: Arc<TaskControlBlock>, time_wait: usize) -> Self {
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        Self {
            task,
            tid,
            time_expired: get_time_ms() + time_wait,
        }
    }
}

impl PartialEq for TimeWrap {
    fn eq(&self, other: &Self) -> bool {
        self.time_expired == other.time_expired
    }
}
impl Eq for TimeWrap {}
impl PartialOrd for TimeWrap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = -(self.time_expired as isize);
        let b = -(other.time_expired as isize);
        Some(a.cmp(&b))
    }
}
impl Ord for TimeWrap {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

lazy_static! {
    pub static ref TIMERS: Mutex<BinaryHeap<TimeWrap>> = Mutex::new(BinaryHeap::<TimeWrap>::new());
}

#[derive(Clone, Copy)]
struct AlarmTimer {
    pid: usize,
    which: usize,
    signum: usize,
    deadline_ms: usize,
    interval_ms: usize,
}

lazy_static! {
    static ref ALARM_TIMERS: Mutex<Vec<AlarmTimer>> = Mutex::new(Vec::new());
}

#[derive(Clone, Copy)]
struct DelayedTidClear {
    pid: usize,
    ctid: usize,
    deadline_ms: usize,
}

lazy_static! {
    static ref DELAYED_TID_CLEARS: Mutex<Vec<DelayedTidClear>> = Mutex::new(Vec::new());
}

#[derive(Clone, Copy)]
struct PosixTimer {
    pid: usize,
    timer_id: usize,
    clock_id: usize,
    thread_tid: Option<usize>,
    signum: usize,
    deadline_ns: Option<u64>,
    interval_ns: u64,
    overrun: usize,
}

lazy_static! {
    static ref POSIX_TIMERS: Mutex<Vec<PosixTimer>> = Mutex::new(Vec::new());
}

static NEXT_POSIX_TIMER_ID: AtomicUsize = AtomicUsize::new(1);

pub fn create_posix_timer(
    pid: usize,
    clock_id: usize,
    signum: usize,
    thread_tid: Option<usize>,
) -> Option<usize> {
    if signum == 0 || signum > 64 {
        return None;
    }
    let timer_id = NEXT_POSIX_TIMER_ID.fetch_add(1, AtomicOrdering::Relaxed);
    POSIX_TIMERS.lock().push(PosixTimer {
        pid,
        timer_id,
        clock_id,
        thread_tid,
        signum,
        deadline_ns: None,
        interval_ns: 0,
        overrun: 0,
    });
    Some(timer_id)
}

pub fn set_posix_timer(
    pid: usize,
    timer_id: usize,
    deadline_ns: Option<u64>,
    interval_ns: u64,
    initial_overrun: usize,
) -> Result<(u64, u64), isize> {
    const EINVAL: isize = -22;
    let mut timers = POSIX_TIMERS.lock();
    let Some(timer) = timers
        .iter_mut()
        .find(|t| t.pid == pid && t.timer_id == timer_id)
    else {
        return Err(EINVAL);
    };
    let Some(now_ns) =
        crate::syscall::timer_clock_now_ns(timer.clock_id, timer.pid, timer.thread_tid)
    else {
        return Err(EINVAL);
    };
    let prev_remain = timer
        .deadline_ns
        .map(|d| d.saturating_sub(now_ns))
        .unwrap_or(0);
    let prev_interval = timer.interval_ns;
    timer.interval_ns = interval_ns;
    timer.deadline_ns = deadline_ns;
    timer.overrun = initial_overrun.min(i32::MAX as usize);
    Ok((prev_remain, prev_interval))
}

pub fn delete_posix_timer(pid: usize, timer_id: usize) -> isize {
    const EINVAL: isize = -22;
    let mut timers = POSIX_TIMERS.lock();
    if let Some(idx) = timers
        .iter()
        .position(|t| t.pid == pid && t.timer_id == timer_id)
    {
        timers.swap_remove(idx);
        return 0;
    }
    EINVAL
}

pub fn query_posix_timer(
    pid: usize,
    timer_id: usize,
) -> Result<(usize, Option<u64>, u64, Option<usize>), isize> {
    const EINVAL: isize = -22;
    let timers = POSIX_TIMERS.lock();
    let Some(timer) = timers
        .iter()
        .find(|t| t.pid == pid && t.timer_id == timer_id)
    else {
        return Err(EINVAL);
    };
    Ok((
        timer.clock_id,
        timer.deadline_ns,
        timer.interval_ns,
        timer.thread_tid,
    ))
}

pub fn take_posix_timer_overrun(pid: usize, timer_id: usize) -> Result<isize, isize> {
    const EINVAL: isize = -22;
    let mut timers = POSIX_TIMERS.lock();
    let Some(timer) = timers
        .iter_mut()
        .find(|t| t.pid == pid && t.timer_id == timer_id)
    else {
        return Err(EINVAL);
    };
    let overrun = timer.overrun.min(i32::MAX as usize) as isize;
    timer.overrun = 0;
    Ok(overrun)
}

pub fn schedule_tid_clear(pid: usize, ctid: usize, delay_ms: usize) {
    if ctid == 0 {
        return;
    }
    let deadline_ms = get_time_ms().saturating_add(delay_ms);
    DELAYED_TID_CLEARS.lock().push(DelayedTidClear {
        pid,
        ctid,
        deadline_ms,
    });
}

fn process_delayed_tid_clears(current_ms: usize) {
    let mut due = Vec::new();
    {
        let mut clears = DELAYED_TID_CLEARS.lock();
        let mut i = 0;
        while i < clears.len() {
            if clears[i].deadline_ms <= current_ms {
                due.push(clears.swap_remove(i));
            } else {
                i += 1;
            }
        }
    }

    for entry in due {
        let Some(proc) = pid2process(entry.pid) else {
            continue;
        };
        let token = proc.borrow_mut().get_user_token();
        let _ = crate::mm::try_write_user_value(token, entry.ctid as *mut i32, &0);
        let _ = futex_wake_private_and_shared(entry.pid, token, entry.ctid, 1);
    }
}

pub fn add_timer(task: Arc<TaskControlBlock>, time_wait: usize) {
    let timer = TimeWrap::new(task, time_wait);
    crate::log_if!(
        DEBUG_TIMER,
        debug,
        "[timer] add tid={} wait_ms={} expire_ms={}",
        timer.tid,
        time_wait,
        timer.time_expired
    );
    TIMERS.lock().push(timer);
}

pub fn debug_count_task_refs_in_timers(task: &Arc<TaskControlBlock>) -> usize {
    TIMERS
        .lock()
        .iter()
        .filter(|entry| Arc::ptr_eq(&entry.task, task))
        .count()
}

pub fn set_alarm_timer(pid: usize, delay_ms: Option<usize>) -> usize {
    let (remaining_ms, _) = set_itimer_timer(pid, 0, SIGALRM_NUM, delay_ms, 0);
    remaining_ms
}

pub fn set_itimer_timer(
    pid: usize,
    which: usize,
    signum: usize,
    delay_ms: Option<usize>,
    interval_ms: usize,
) -> (usize, usize) {
    let now = get_time_ms();
    let mut remaining_ms = 0usize;
    let mut old_interval_ms = 0usize;
    let mut timers = ALARM_TIMERS.lock();
    if let Some(idx) = timers.iter().position(|t| t.pid == pid && t.which == which) {
        let old = timers.swap_remove(idx);
        remaining_ms = old.deadline_ms.saturating_sub(now);
        old_interval_ms = old.interval_ms;
    }
    if let Some(delay) = delay_ms {
        if delay > 0 {
            timers.push(AlarmTimer {
                pid,
                which,
                signum,
                deadline_ms: now.saturating_add(delay),
                interval_ms,
            });
        }
    }
    (remaining_ms, old_interval_ms)
}

pub fn alarm_remaining_ms(pid: usize) -> usize {
    let (remaining_ms, _) = itimer_remaining_and_interval_ms(pid, 0);
    remaining_ms
}

pub fn itimer_remaining_and_interval_ms(pid: usize, which: usize) -> (usize, usize) {
    let now = get_time_ms();
    let timers = ALARM_TIMERS.lock();
    if let Some(entry) = timers.iter().find(|t| t.pid == pid && t.which == which) {
        return (entry.deadline_ms.saturating_sub(now), entry.interval_ms);
    }
    (0, 0)
}

fn deliver_alarm(pid: usize) {
    let Some(proc) = pid2process(pid) else {
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[alarm] drop pid={} (no process)",
            pid
        );
        return;
    };
    let Some(bit) = signal_bit(SIGALRM_NUM) else {
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[alarm] drop pid={} (invalid signal)",
            pid
        );
        return;
    };
    let task = {
        let inner = proc.borrow_mut();
        let tasks = inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<Vec<_>>();
        pick_task_for_signal(&tasks, bit)
    };
    let Some(task) = task else {
        crate::log_if!(DEBUG_UNIXBENCH, info, "[alarm] drop pid={} (no task)", pid);
        return;
    };
    let (tid, on_cpu, mask, pending) = {
        let mut inner = task.borrow_mut();
        inner.pending_signals |= bit;
        let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        (
            tid,
            task.on_cpu.load(AtomicOrdering::Acquire),
            inner.signal_mask,
            inner.pending_signals,
        )
    };
    crate::log_if!(
        DEBUG_UNIXBENCH,
        info,
        "[alarm] fire pid={} tid={} on_cpu={} mask={:#x} pending={:#x}",
        pid,
        tid,
        on_cpu,
        mask,
        pending
    );
    wakeup_task(task.clone());
    if on_cpu != TaskControlBlock::OFF_CPU {
        arch::send_ipi(on_cpu);
    }
}

fn process_alarm_timers(current_ms: usize) {
    loop {
        let expired_timer = {
            let mut timers = ALARM_TIMERS.lock();
            if let Some((idx, _)) = timers
                .iter()
                .enumerate()
                .find(|(_, t)| t.deadline_ms <= current_ms)
            {
                Some(timers.swap_remove(idx))
            } else {
                None
            }
        };
        let Some(mut timer) = expired_timer else {
            break;
        };
        if timer.signum == SIGALRM_NUM {
            deliver_alarm(timer.pid);
        } else {
            queue_process_signal(timer.pid, timer.signum);
        }
        if timer.interval_ms > 0 && pid2process(timer.pid).is_some() {
            let interval = timer.interval_ms.max(1);
            let elapsed = current_ms.saturating_sub(timer.deadline_ms);
            let expirations = elapsed / interval + 1;
            timer.deadline_ms = timer
                .deadline_ms
                .saturating_add(expirations.saturating_mul(interval));
            ALARM_TIMERS.lock().push(timer);
        }
    }
}

fn process_posix_timers() {
    loop {
        let fired = {
            let mut timers = POSIX_TIMERS.lock();
            let idx = timers.iter().position(|t| {
                let Some(deadline_ns) = t.deadline_ns else {
                    return false;
                };
                let Some(now_ns) =
                    crate::syscall::timer_clock_now_ns(t.clock_id, t.pid, t.thread_tid)
                else {
                    return false;
                };
                deadline_ns <= now_ns
            });
            if let Some(idx) = idx {
                let timer = &mut timers[idx];
                let pid = timer.pid;
                let signum = timer.signum;
                let now_ns =
                    crate::syscall::timer_clock_now_ns(timer.clock_id, timer.pid, timer.thread_tid)
                        .unwrap_or(0);
                if timer.interval_ns == 0 {
                    timer.deadline_ns = None;
                } else {
                    let base = timer.deadline_ns.unwrap_or(now_ns);
                    let elapsed = now_ns.saturating_sub(base);
                    let expirations = elapsed / timer.interval_ns + 1;
                    let extra = expirations.saturating_sub(1);
                    if extra > 0 {
                        timer.overrun = timer
                            .overrun
                            .saturating_add(extra as usize)
                            .min(i32::MAX as usize);
                    }
                    timer.deadline_ns =
                        Some(base.saturating_add(expirations.saturating_mul(timer.interval_ns)));
                }
                Some((pid, signum))
            } else {
                None
            }
        };
        let Some((pid, signum)) = fired else {
            break;
        };
        queue_process_signal(pid, signum);
    }
}

pub fn check_timer() {
    let current_ms = get_time_ms();

    loop {
        // Pop one expired timer (if any) while holding the lock, then wake it after releasing.
        let popped = {
            let mut timers = TIMERS.lock();
            if DEBUG_TIMER {
                let len = timers.len();
                if let Some(head) = timers.peek() {
                    log::debug!(
                        "[timer] check now_ms={} timers_len={} head_tid={} head_expire_ms={}",
                        current_ms,
                        len,
                        head.tid,
                        head.time_expired
                    );
                } else {
                    log::debug!("[timer] check now_ms={} timers_len=0", current_ms);
                }
            }
            if let Some(head) = timers.peek() {
                let expire = head.time_expired;
                if DEBUG_TIMER {
                    let status = if expire <= current_ms {
                        "ready"
                    } else {
                        "future"
                    };
                    log::debug!(
                        "[timer] peek tid={} expire_ms={} now_ms={} status={}",
                        head.tid,
                        expire,
                        current_ms,
                        status
                    );
                }
                if expire <= current_ms {
                    Some(timers.pop().unwrap())
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(timer) = popped {
            let pid = timer
                .task
                .process
                .upgrade()
                .map(|p: alloc::sync::Arc<ProcessControlBlock>| p.getpid())
                .unwrap_or(usize::MAX);
            crate::log_if!(
                DEBUG_TIMER,
                debug,
                "[timer] pop pid={} tid={} expire_ms={} now_ms={}",
                pid,
                timer.tid,
                timer.time_expired,
                current_ms
            );
            crate::log_if!(
                DEBUG_TIMER,
                debug,
                "[timer] wake pid={} tid={} expire_ms={} now_ms={}",
                pid,
                timer.tid,
                timer.time_expired,
                current_ms
            );
            wakeup_task(timer.task.clone());
            // Continue looping in case more timers have expired at the same tick.
            continue;
        }
        break;
    }

    process_delayed_tid_clears(current_ms);
    process_alarm_timers(current_ms);
    process_posix_timers();
    crate::fs::process_timerfd_expirations();
}

pub fn has_pending_timers() -> bool {
    !TIMERS.lock().is_empty()
        || !ALARM_TIMERS.lock().is_empty()
        || POSIX_TIMERS.lock().iter().any(|t| t.deadline_ns.is_some())
        || !DELAYED_TID_CLEARS.lock().is_empty()
}
