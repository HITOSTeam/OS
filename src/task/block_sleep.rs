// this is used for sleep (blocked) threads
use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use core::{cmp::Ordering, time};

use alloc::{
    collections::{BTreeMap, BinaryHeap},
    sync::Arc,
    vec::Vec,
};
use crate::task::signal::{SIGALRM_NUM, pick_task_for_signal, queue_process_signal, signal_bit};
use crate::{
    task::{manager::wakeup_task, task_block::TaskControlBlock},
    time::get_time_ms,
};
use lazy_static::*;
use spin::Mutex;

use crate::debug_config::{DEBUG_TIMER, DEBUG_UNIXBENCH};
use crate::task::process_block::ProcessControlBlock;
use crate::{
    arch, mm::write_user_value, syscall::futex::futex_wake_private_and_shared,
    task::manager::pid2process,
};

const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const CLOCK_PROCESS_CPUTIME_ID: usize = 2;
const CLOCK_THREAD_CPUTIME_ID: usize = 3;
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
    schedule_seq: u64,
}

lazy_static! {
    static ref POSIX_TIMERS: Mutex<PosixTimerState> = Mutex::new(PosixTimerState::default());
    static ref POSIX_CPU_TIMER_STATE: Mutex<PosixCpuTimerState> =
        Mutex::new(PosixCpuTimerState::default());
    static ref POSIX_TIMER_SCHEDULE: Mutex<PosixTimerScheduleState> =
        Mutex::new(PosixTimerScheduleState::default());
}

static NEXT_POSIX_TIMER_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Default)]
struct PosixTimerState {
    timers: Vec<PosixTimer>,
    timer_index: BTreeMap<(usize, usize), usize>,
}

impl PosixTimerState {
    fn insert(&mut self, timer: PosixTimer) {
        let idx = self.timers.len();
        self.timer_index.insert((timer.pid, timer.timer_id), idx);
        self.timers.push(timer);
    }

    fn get(&self, pid: usize, timer_id: usize) -> Option<&PosixTimer> {
        let idx = *self.timer_index.get(&(pid, timer_id))?;
        self.timers.get(idx)
    }

    fn get_mut(&mut self, pid: usize, timer_id: usize) -> Option<&mut PosixTimer> {
        let idx = *self.timer_index.get(&(pid, timer_id))?;
        self.timers.get_mut(idx)
    }

    fn remove(&mut self, pid: usize, timer_id: usize) -> Option<PosixTimer> {
        let idx = self.timer_index.remove(&(pid, timer_id))?;
        let timer = self.timers.swap_remove(idx);
        if let Some(moved) = self.timers.get(idx) {
            self.timer_index.insert((moved.pid, moved.timer_id), idx);
        }
        Some(timer)
    }
}

#[derive(Clone, Copy)]
enum PosixCpuTimerBucketKey {
    Process { pid: usize },
    Thread { pid: usize, tid: usize },
}

struct PosixCpuTimerBucket {
    timers: BTreeMap<(usize, usize), u64>,
    next_deadline_ns: u64,
}

impl Default for PosixCpuTimerBucket {
    fn default() -> Self {
        Self {
            timers: BTreeMap::new(),
            next_deadline_ns: u64::MAX,
        }
    }
}

impl PosixCpuTimerBucket {
    fn refresh_next_deadline(&mut self) {
        self.next_deadline_ns = self.timers.values().copied().min().unwrap_or(u64::MAX);
    }
}

#[derive(Clone)]
struct PosixCpuTimerBucketSnapshot {
    clock_id: usize,
    pid: usize,
    thread_tid: Option<usize>,
    next_deadline_ns: u64,
    timers: Vec<(usize, usize)>,
}

#[derive(Default)]
struct PosixCpuTimerState {
    process: BTreeMap<usize, PosixCpuTimerBucket>,
    thread: BTreeMap<(usize, usize), PosixCpuTimerBucket>,
}

impl PosixCpuTimerState {
    fn bucket_mut(&mut self, key: PosixCpuTimerBucketKey) -> &mut PosixCpuTimerBucket {
        match key {
            PosixCpuTimerBucketKey::Process { pid } => self.process.entry(pid).or_default(),
            PosixCpuTimerBucketKey::Thread { pid, tid } => self.thread.entry((pid, tid)).or_default(),
        }
    }

    fn insert_or_update(
        &mut self,
        key: PosixCpuTimerBucketKey,
        timer_key: (usize, usize),
        deadline_ns: u64,
    ) {
        let bucket = self.bucket_mut(key);
        bucket.timers.insert(timer_key, deadline_ns);
        bucket.refresh_next_deadline();
    }

    fn remove(&mut self, key: PosixCpuTimerBucketKey, timer_key: (usize, usize)) {
        match key {
            PosixCpuTimerBucketKey::Process { pid } => {
                let Some(bucket) = self.process.get_mut(&pid) else {
                    return;
                };
                bucket.timers.remove(&timer_key);
                if bucket.timers.is_empty() {
                    self.process.remove(&pid);
                } else {
                    bucket.refresh_next_deadline();
                }
            }
            PosixCpuTimerBucketKey::Thread { pid, tid } => {
                let Some(bucket) = self.thread.get_mut(&(pid, tid)) else {
                    return;
                };
                bucket.timers.remove(&timer_key);
                if bucket.timers.is_empty() {
                    self.thread.remove(&(pid, tid));
                } else {
                    bucket.refresh_next_deadline();
                }
            }
        }
    }

    fn snapshots(&self) -> Vec<PosixCpuTimerBucketSnapshot> {
        let mut snapshots = Vec::new();
        for (&pid, bucket) in self.process.iter() {
            snapshots.push(PosixCpuTimerBucketSnapshot {
                clock_id: CLOCK_PROCESS_CPUTIME_ID,
                pid,
                thread_tid: None,
                next_deadline_ns: bucket.next_deadline_ns,
                timers: bucket.timers.keys().copied().collect(),
            });
        }
        for (&(pid, tid), bucket) in self.thread.iter() {
            snapshots.push(PosixCpuTimerBucketSnapshot {
                clock_id: CLOCK_THREAD_CPUTIME_ID,
                pid,
                thread_tid: Some(tid),
                next_deadline_ns: bucket.next_deadline_ns,
                timers: bucket.timers.keys().copied().collect(),
            });
        }
        snapshots
    }

    fn has_armed_timers(&self) -> bool {
        !self.process.is_empty() || !self.thread.is_empty()
    }
}

#[derive(Clone, Copy)]
struct PosixTimerScheduleEntry {
    deadline_ns: u64,
    sequence: u64,
    pid: usize,
    timer_id: usize,
}

impl PartialEq for PosixTimerScheduleEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_ns == other.deadline_ns
            && self.sequence == other.sequence
            && self.pid == other.pid
            && self.timer_id == other.timer_id
    }
}

impl Eq for PosixTimerScheduleEntry {}

impl PartialOrd for PosixTimerScheduleEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PosixTimerScheduleEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deadline_ns
            .cmp(&self.deadline_ns)
            .then_with(|| other.sequence.cmp(&self.sequence))
            .then_with(|| other.pid.cmp(&self.pid))
            .then_with(|| other.timer_id.cmp(&self.timer_id))
    }
}

#[derive(Default)]
struct PosixTimerScheduleState {
    monotonic: BinaryHeap<PosixTimerScheduleEntry>,
    realtime: BinaryHeap<PosixTimerScheduleEntry>,
    monotonic_armed: usize,
    realtime_armed: usize,
}

impl PosixTimerScheduleState {
    fn adjust_armed(&mut self, clock_id: usize, was_armed: bool, is_armed: bool) {
        if was_armed == is_armed {
            return;
        }
        let armed = match clock_id {
            CLOCK_MONOTONIC => &mut self.monotonic_armed,
            CLOCK_REALTIME => &mut self.realtime_armed,
            _ => return,
        };
        if is_armed {
            *armed = armed.saturating_add(1);
        } else {
            *armed = armed.saturating_sub(1);
        }
    }

    fn has_live_timers(&self) -> bool {
        self.monotonic_armed != 0 || self.realtime_armed != 0
    }
}

fn posix_timer_now_ns(timer: &PosixTimer) -> Option<u64> {
    crate::syscall::timer_clock_now_ns(timer.clock_id, timer.pid, timer.thread_tid)
}

fn posix_schedule_heap_mut(
    state: &mut PosixTimerScheduleState,
    clock_id: usize,
) -> Option<&mut BinaryHeap<PosixTimerScheduleEntry>> {
    match clock_id {
        CLOCK_MONOTONIC => Some(&mut state.monotonic),
        CLOCK_REALTIME => Some(&mut state.realtime),
        _ => None,
    }
}

fn posix_timer_uses_deadline_heap(clock_id: usize) -> bool {
    matches!(clock_id, CLOCK_MONOTONIC | CLOCK_REALTIME)
}

fn posix_timer_uses_cpu_bucket(clock_id: usize) -> bool {
    matches!(clock_id, CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID)
}

fn posix_timer_cpu_bucket(timer: &PosixTimer) -> Option<PosixCpuTimerBucketKey> {
    match timer.clock_id {
        CLOCK_PROCESS_CPUTIME_ID => Some(PosixCpuTimerBucketKey::Process { pid: timer.pid }),
        CLOCK_THREAD_CPUTIME_ID => Some(PosixCpuTimerBucketKey::Thread {
            pid: timer.pid,
            tid: timer.thread_tid?,
        }),
        _ => None,
    }
}

fn posix_timer_heap_armed(timer: &PosixTimer) -> bool {
    timer.deadline_ns.is_some() && posix_timer_uses_deadline_heap(timer.clock_id)
}

fn posix_update_cpu_timer_state(
    timer: &PosixTimer,
    old_deadline_ns: Option<u64>,
    new_deadline_ns: Option<u64>,
) {
    if !posix_timer_uses_cpu_bucket(timer.clock_id) {
        return;
    }
    let Some(bucket_key) = posix_timer_cpu_bucket(timer) else {
        return;
    };
    let timer_key = (timer.pid, timer.timer_id);
    let mut state = POSIX_CPU_TIMER_STATE.lock();
    match (old_deadline_ns, new_deadline_ns) {
        (_, Some(deadline_ns)) => state.insert_or_update(bucket_key, timer_key, deadline_ns),
        (Some(_), None) => state.remove(bucket_key, timer_key),
        (None, None) => {}
    }
}

fn posix_reschedule_timer_locked(timer: &mut PosixTimer, was_armed: bool) {
    let is_armed = posix_timer_heap_armed(timer);
    timer.schedule_seq = timer.schedule_seq.wrapping_add(1);
    if !was_armed && !is_armed {
        return;
    }
    let Some(deadline_ns) = timer.deadline_ns else {
        let mut schedule = POSIX_TIMER_SCHEDULE.lock();
        schedule.adjust_armed(timer.clock_id, was_armed, is_armed);
        return;
    };
    let mut schedule = POSIX_TIMER_SCHEDULE.lock();
    schedule.adjust_armed(timer.clock_id, was_armed, is_armed);
    if !is_armed {
        return;
    }
    let Some(heap) = posix_schedule_heap_mut(&mut schedule, timer.clock_id) else {
        return;
    };
    heap.push(PosixTimerScheduleEntry {
        deadline_ns,
        sequence: timer.schedule_seq,
        pid: timer.pid,
        timer_id: timer.timer_id,
    });
}

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
    POSIX_TIMERS.lock().insert(PosixTimer {
        pid,
        timer_id,
        clock_id,
        thread_tid,
        signum,
        deadline_ns: None,
        interval_ns: 0,
        overrun: 0,
        schedule_seq: 0,
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
    let Some(timer) = timers.get_mut(pid, timer_id) else {
        return Err(EINVAL);
    };
    let Some(now_ns) = posix_timer_now_ns(timer) else {
        return Err(EINVAL);
    };
    let prev_remain = timer
        .deadline_ns
        .map(|d| d.saturating_sub(now_ns))
        .unwrap_or(0);
    let prev_interval = timer.interval_ns;
    let old_deadline_ns = timer.deadline_ns;
    let was_armed = posix_timer_heap_armed(timer);
    timer.interval_ns = interval_ns;
    timer.deadline_ns = deadline_ns;
    timer.overrun = initial_overrun.min(i32::MAX as usize);
    posix_update_cpu_timer_state(timer, old_deadline_ns, timer.deadline_ns);
    posix_reschedule_timer_locked(timer, was_armed);
    Ok((prev_remain, prev_interval))
}

pub fn delete_posix_timer(pid: usize, timer_id: usize) -> isize {
    const EINVAL: isize = -22;
    let mut timers = POSIX_TIMERS.lock();
    if let Some(timer) = timers.remove(pid, timer_id) {
        posix_update_cpu_timer_state(&timer, timer.deadline_ns, None);
        if posix_timer_heap_armed(&timer) {
            POSIX_TIMER_SCHEDULE
                .lock()
                .adjust_armed(timer.clock_id, true, false);
        }
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
    let Some(timer) = timers.get(pid, timer_id) else {
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
    let Some(timer) = timers.get_mut(pid, timer_id) else {
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
    for clock_id in [CLOCK_MONOTONIC, CLOCK_REALTIME] {
        loop {
            let entry = {
                let Some(now_ns) = crate::syscall::timer_clock_now_ns(clock_id, 0, None) else {
                    break;
                };
                let mut schedule = POSIX_TIMER_SCHEDULE.lock();
                let Some(heap) = posix_schedule_heap_mut(&mut schedule, clock_id) else {
                    break;
                };
                match heap.peek() {
                    Some(entry) if entry.deadline_ns <= now_ns => heap.pop(),
                    _ => None,
                }
            };
            let Some(entry) = entry else {
                break;
            };
            let fired = {
                let mut timers = POSIX_TIMERS.lock();
                let Some(timer) = timers.get_mut(entry.pid, entry.timer_id) else {
                    continue;
                };
                if timer.clock_id != clock_id
                    || timer.schedule_seq != entry.sequence
                    || timer.deadline_ns != Some(entry.deadline_ns)
                {
                    continue;
                }
                let Some(now_ns) = posix_timer_now_ns(timer) else {
                    continue;
                };
                if entry.deadline_ns > now_ns {
                    continue;
                }
                let was_armed = posix_timer_heap_armed(timer);
                let pid = timer.pid;
                let signum = timer.signum;
                if timer.interval_ns == 0 {
                    timer.deadline_ns = None;
                } else {
                    let elapsed = now_ns.saturating_sub(entry.deadline_ns);
                    let expirations = elapsed / timer.interval_ns + 1;
                    let extra = expirations.saturating_sub(1);
                    if extra > 0 {
                        timer.overrun = timer
                            .overrun
                            .saturating_add(extra as usize)
                            .min(i32::MAX as usize);
                    }
                    timer.deadline_ns = Some(
                        entry
                            .deadline_ns
                            .saturating_add(expirations.saturating_mul(timer.interval_ns)),
                    );
                }
                posix_reschedule_timer_locked(timer, was_armed);
                Some((pid, signum))
            };
            let Some((pid, signum)) = fired else {
                continue;
            };
            queue_process_signal(pid, signum);
        }
    }

    loop {
        let bucket = {
            let snapshots = POSIX_CPU_TIMER_STATE.lock().snapshots();
            snapshots.into_iter().find_map(|snapshot| {
                let now_ns =
                    crate::syscall::timer_clock_now_ns(snapshot.clock_id, snapshot.pid, snapshot.thread_tid)?;
                (snapshot.next_deadline_ns <= now_ns).then_some((snapshot, now_ns))
            })
        };
        let Some((bucket, now_ns)) = bucket else {
            break;
        };
        let fired = {
            let mut timers = POSIX_TIMERS.lock();
            let due_key = bucket.timers.into_iter().find(|(pid, timer_id)| {
                let Some(timer) = timers.get(*pid, *timer_id) else {
                    return false;
                };
                timer.clock_id == bucket.clock_id
                    && timer.thread_tid == bucket.thread_tid
                    && timer.deadline_ns.is_some_and(|deadline_ns| deadline_ns <= now_ns)
            });
            if let Some((pid, timer_id)) = due_key {
                if let Some(timer) = timers.get_mut(pid, timer_id) {
                    let old_deadline_ns = timer.deadline_ns;
                    let was_armed = posix_timer_heap_armed(timer);
                    let pid = timer.pid;
                    let signum = timer.signum;
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
                        timer.deadline_ns = Some(
                            base.saturating_add(expirations.saturating_mul(timer.interval_ns)),
                        );
                    }
                    posix_update_cpu_timer_state(timer, old_deadline_ns, timer.deadline_ns);
                    posix_reschedule_timer_locked(timer, was_armed);
                    Some((pid, signum))
                } else {
                    None
                }
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
    let posix_pending = {
        let cpu_timer_armed = POSIX_CPU_TIMER_STATE.lock().has_armed_timers();
        let schedule = POSIX_TIMER_SCHEDULE.lock();
        cpu_timer_armed || schedule.has_live_timers()
    };
    !TIMERS.lock().is_empty()
        || !ALARM_TIMERS.lock().is_empty()
        || posix_pending
        || !DELAYED_TID_CLEARS.lock().is_empty()
}
