// this is used for sleep (blocked) threads
use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use core::{cmp::Ordering, time};

use crate::task::signal::{pick_task_for_signal, queue_process_signal, signal_bit, SIGALRM_NUM};
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
    arch,
    mm::write_user_value,
    syscall::futex::futex_wake_private_and_shared,
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
    signum: usize,
    deadline_ms: Option<usize>,
    interval_ms: usize,
    overrun: usize,
}

lazy_static! {
    static ref POSIX_TIMERS: Mutex<Vec<PosixTimer>> = Mutex::new(Vec::new());
}

static NEXT_POSIX_TIMER_ID: AtomicUsize = AtomicUsize::new(1);

pub fn create_posix_timer(pid: usize, clock_id: usize, signum: usize) -> Option<usize> {
    if signum == 0 || signum > 64 {
        return None;
    }
    let timer_id = NEXT_POSIX_TIMER_ID.fetch_add(1, AtomicOrdering::Relaxed);
    POSIX_TIMERS.lock().push(PosixTimer {
        pid,
        timer_id,
        clock_id,
        signum,
        deadline_ms: None,
        interval_ms: 0,
        overrun: 0,
    });
    Some(timer_id)
}

pub fn set_posix_timer(
    pid: usize,
    timer_id: usize,
    delay_ms: Option<usize>,
    interval_ms: usize,
    initial_overrun: usize,
) -> Result<(usize, usize), isize> {
    const EINVAL: isize = -22;
    let now = get_time_ms();
    let mut timers = POSIX_TIMERS.lock();
    let Some(timer) = timers
        .iter_mut()
        .find(|t| t.pid == pid && t.timer_id == timer_id)
    else {
        return Err(EINVAL);
    };
    let prev_remain = timer.deadline_ms.map(|d| d.saturating_sub(now)).unwrap_or(0);
    let prev_interval = timer.interval_ms;
    timer.interval_ms = interval_ms;
    timer.deadline_ms = delay_ms.map(|d| now.saturating_add(d));
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

pub fn query_posix_timer(pid: usize, timer_id: usize) -> Result<(usize, Option<usize>, usize), isize> {
    const EINVAL: isize = -22;
    let timers = POSIX_TIMERS.lock();
    let Some(timer) = timers
        .iter()
        .find(|t| t.pid == pid && t.timer_id == timer_id)
    else {
        return Err(EINVAL);
    };
    Ok((timer.clock_id, timer.deadline_ms, timer.interval_ms))
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
        return (
            entry.deadline_ms.saturating_sub(now),
            entry.interval_ms,
        );
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

fn process_posix_timers(current_ms: usize) {
    loop {
        let fired = {
            let mut timers = POSIX_TIMERS.lock();
            if let Some(timer) = timers
                .iter_mut()
                .find(|t| t.deadline_ms.map(|d| d <= current_ms).unwrap_or(false))
            {
                let pid = timer.pid;
                let signum = timer.signum;
                if timer.interval_ms == 0 {
                    timer.deadline_ms = None;
                } else {
                    let interval = timer.interval_ms.max(1);
                    let base = timer.deadline_ms.unwrap_or(current_ms);
                    let elapsed = current_ms.saturating_sub(base);
                    let expirations = elapsed / interval + 1;
                    let extra = expirations.saturating_sub(1);
                    if extra > 0 {
                        timer.overrun = timer
                            .overrun
                            .saturating_add(extra)
                            .min(i32::MAX as usize);
                    }
                    timer.deadline_ms = Some(base.saturating_add(expirations.saturating_mul(interval)));
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
    process_posix_timers(current_ms);
}

pub fn has_pending_timers() -> bool {
    !TIMERS.lock().is_empty()
        || !ALARM_TIMERS.lock().is_empty()
        || POSIX_TIMERS
            .lock()
            .iter()
            .any(|t| t.deadline_ms.is_some())
        || !DELAYED_TID_CLEARS.lock().is_empty()
}
