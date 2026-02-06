// this is used for sleep (blocked) threads
use core::{cmp::Ordering, time};
use core::sync::atomic::Ordering as AtomicOrdering;

use crate::{
    task::{manager::wakeup_task, task_block::TaskControlBlock},
    time::get_time_ms,
};
use crate::task::signal::{pick_task_for_signal, signal_bit, SIGALRM_NUM};
use lazy_static::*;
use spin::Mutex;

use alloc::{collections::BinaryHeap, sync::Arc};
use alloc::vec::Vec;

use crate::debug_config::{DEBUG_TIMER, DEBUG_UNIXBENCH};
use crate::task::process_block::ProcessControlBlock;
use crate::{
    arch,
    mm::write_user_value,
    syscall::futex::futex_wake,
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
    deadline_ms: usize,
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

pub fn schedule_tid_clear(pid: usize, ctid: usize, delay_ms: usize) {
    if ctid == 0 {
        return;
    }
    let deadline_ms = get_time_ms().saturating_add(delay_ms);
    DELAYED_TID_CLEARS
        .lock()
        .push(DelayedTidClear { pid, ctid, deadline_ms });
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
        // Wake both private/shared futex keys; tid-clears don't encode the flag.
        let _ = futex_wake((entry.pid, entry.ctid), entry.ctid, 1);
        let _ = futex_wake((0, entry.ctid), entry.ctid, 1);
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
    let now = get_time_ms();
    let mut remaining_ms = 0usize;
    let mut timers = ALARM_TIMERS.lock();
    if let Some(idx) = timers.iter().position(|t| t.pid == pid) {
        let old = timers.swap_remove(idx);
        if old.deadline_ms > now {
            remaining_ms = old.deadline_ms - now;
        }
    }
    if let Some(delay) = delay_ms {
        if delay > 0 {
            timers.push(AlarmTimer {
                pid,
                deadline_ms: now.saturating_add(delay),
            });
        }
    }
    remaining_ms
}

pub fn alarm_remaining_ms(pid: usize) -> usize {
    let now = get_time_ms();
    let timers = ALARM_TIMERS.lock();
    if let Some(entry) = timers.iter().find(|t| t.pid == pid) {
        return entry.deadline_ms.saturating_sub(now);
    }
    0
}

fn deliver_alarm(pid: usize) {
    let Some(proc) = pid2process(pid) else {
        crate::log_if!(DEBUG_UNIXBENCH, info, "[alarm] drop pid={} (no process)", pid);
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
        let expired = {
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
        let Some(timer) = expired else {
            break;
        };
        deliver_alarm(timer.pid);
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
                    let status = if expire <= current_ms { "ready" } else { "future" };
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
}

pub fn has_pending_timers() -> bool {
    !TIMERS.lock().is_empty()
        || !ALARM_TIMERS.lock().is_empty()
        || !DELAYED_TID_CLEARS.lock().is_empty()
}
