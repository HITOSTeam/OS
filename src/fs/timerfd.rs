use alloc::{
    collections::{BTreeMap, BinaryHeap},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    any::Any,
    cmp::Ordering,
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::{
    mm::UserBuffer,
    task::{
        processor::{block_current_and_run_next, current_task},
        task_block::TaskControlBlock,
    },
};

use super::{File, POLLIN, PollWaitQueue, wake_tasks};
use crate::syscall::error::{SyscallError, err};

const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;

lazy_static! {
    static ref TIMERFD_SCHEDULE: Mutex<TimerFdScheduleState> =
        Mutex::new(TimerFdScheduleState::default());
}

static TIMERFD_ARMED_TOTAL: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct TimerFdScheduleEntry {
    deadline_ns: u64,
    sequence: u64,
    file: Weak<TimerFdFile>,
}

impl PartialEq for TimerFdScheduleEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_ns == other.deadline_ns && self.sequence == other.sequence
    }
}

impl Eq for TimerFdScheduleEntry {}

impl PartialOrd for TimerFdScheduleEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimerFdScheduleEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deadline_ns
            .cmp(&self.deadline_ns)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

#[derive(Default)]
struct TimerFdScheduleState {
    monotonic: BinaryHeap<TimerFdScheduleEntry>,
    realtime: BinaryHeap<TimerFdScheduleEntry>,
    monotonic_armed: usize,
    realtime_armed: usize,
}

impl TimerFdScheduleState {
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
            TIMERFD_ARMED_TOTAL.fetch_add(1, AtomicOrdering::AcqRel);
        } else {
            *armed = armed.saturating_sub(1);
            TIMERFD_ARMED_TOTAL
                .fetch_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |value| {
                    value.checked_sub(1)
                })
                .ok();
        }
    }

    fn live_realtime_files(&self) -> Vec<Arc<TimerFdFile>> {
        if self.realtime_armed == 0 {
            return Vec::new();
        }
        let mut live = BTreeMap::new();
        for entry in self.realtime.iter() {
            let Some(file) = entry.file.upgrade() else {
                continue;
            };
            live.entry(Arc::as_ptr(&file) as usize).or_insert(file);
        }
        live.into_values().collect()
    }
}

struct TimerFdInner {
    deadline_ns: Option<u64>,
    interval_ns: u64,
    expirations: u64,
    cancel_on_set: bool,
    canceled: bool,
    schedule_seq: u64,
    read_waiters: alloc::collections::VecDeque<Weak<TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
}

pub struct TimerFdFile {
    clock_id: usize,
    self_ref: Weak<TimerFdFile>,
    inner: Mutex<TimerFdInner>,
}

impl TimerFdFile {
    pub fn new(clock_id: usize) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            clock_id,
            self_ref: weak.clone(),
            inner: Mutex::new(TimerFdInner {
                deadline_ns: None,
                interval_ns: 0,
                expirations: 0,
                cancel_on_set: false,
                canceled: false,
                schedule_seq: 0,
                read_waiters: alloc::collections::VecDeque::new(),
                poll_waiters: PollWaitQueue::default(),
            }),
        })
    }

    pub fn clock_id(&self) -> usize {
        self.clock_id
    }

    fn now_ns(clock_id: usize) -> Option<u64> {
        match clock_id {
            CLOCK_REALTIME | CLOCK_MONOTONIC => {
                crate::syscall::timer_clock_now_ns(clock_id, 0, None)
            }
            _ => None,
        }
    }

    fn arm_clockevent_for_deadline(clock_id: usize, deadline_ns: u64) {
        let Some(clock_now_ns) = Self::now_ns(clock_id) else {
            return;
        };
        let delta_ns = deadline_ns.saturating_sub(clock_now_ns).max(1);
        crate::time::arm_timer_for_deadline_ns(crate::time::get_time_ns().saturating_add(delta_ns));
    }

    fn add_waiter_once(
        waiters: &mut alloc::collections::VecDeque<Weak<TaskControlBlock>>,
        task: &Arc<TaskControlBlock>,
    ) {
        waiters.retain(|waiter| waiter.upgrade().is_some());
        if waiters
            .iter()
            .any(|waiter| waiter.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
        {
            return;
        }
        waiters.push_back(Arc::downgrade(task));
    }

    fn wake_read_waiters(
        waiters: &mut alloc::collections::VecDeque<Weak<TaskControlBlock>>,
    ) -> Vec<Arc<TaskControlBlock>> {
        let mut ready = Vec::new();
        waiters.retain(|waiter| {
            let Some(task) = waiter.upgrade() else {
                return false;
            };
            ready.push(task);
            false
        });
        ready
    }

    fn schedule_heap_mut(
        state: &mut TimerFdScheduleState,
        clock_id: usize,
    ) -> Option<&mut BinaryHeap<TimerFdScheduleEntry>> {
        match clock_id {
            CLOCK_MONOTONIC => Some(&mut state.monotonic),
            CLOCK_REALTIME => Some(&mut state.realtime),
            _ => None,
        }
    }

    fn is_armed_locked(&self, inner: &TimerFdInner) -> bool {
        matches!(self.clock_id, CLOCK_MONOTONIC | CLOCK_REALTIME)
            && inner.deadline_ns.is_some()
            && !inner.canceled
    }

    fn update_schedule_locked(
        &self,
        inner: &mut TimerFdInner,
        was_armed: bool,
        old_deadline_ns: Option<u64>,
    ) {
        let is_armed = self.is_armed_locked(inner);
        let new_deadline_ns = inner.deadline_ns.filter(|_| is_armed);
        if was_armed == is_armed && old_deadline_ns == new_deadline_ns {
            return;
        }

        inner.schedule_seq = inner.schedule_seq.wrapping_add(1);
        let mut state = TIMERFD_SCHEDULE.lock();
        state.adjust_armed(self.clock_id, was_armed, is_armed);
        let Some(deadline_ns) = new_deadline_ns else {
            return;
        };
        let Some(heap) = Self::schedule_heap_mut(&mut state, self.clock_id) else {
            return;
        };
        heap.push(TimerFdScheduleEntry {
            deadline_ns,
            sequence: inner.schedule_seq,
            file: self.self_ref.clone(),
        });
        drop(state);
        Self::arm_clockevent_for_deadline(self.clock_id, deadline_ns);
    }

    fn update_expirations_locked(inner: &mut TimerFdInner, now_ns: u64) -> bool {
        if inner.canceled {
            return false;
        }
        let prev_ready = inner.expirations > 0;
        let Some(deadline_ns) = inner.deadline_ns else {
            return false;
        };
        if now_ns < deadline_ns {
            return false;
        }
        if inner.interval_ns == 0 {
            inner.expirations = inner.expirations.saturating_add(1);
            inner.deadline_ns = None;
        } else {
            let elapsed = now_ns.saturating_sub(deadline_ns);
            let expirations = elapsed / inner.interval_ns + 1;
            inner.expirations = inner.expirations.saturating_add(expirations);
            inner.deadline_ns =
                Some(deadline_ns.saturating_add(expirations.saturating_mul(inner.interval_ns)));
        }
        !prev_ready && inner.expirations > 0
    }

    fn advance_to_ns_locked(&self, inner: &mut TimerFdInner, now_ns: u64) -> bool {
        let was_armed = self.is_armed_locked(inner);
        let prev_deadline = inner.deadline_ns;
        let became_ready = Self::update_expirations_locked(inner, now_ns);
        if inner.deadline_ns != prev_deadline {
            self.update_schedule_locked(inner, was_armed, prev_deadline);
        }
        became_ready
    }

    fn flush_expirations(&self, inner: &mut TimerFdInner) -> bool {
        let Some(now_ns) = Self::now_ns(self.clock_id) else {
            return false;
        };
        self.advance_to_ns_locked(inner, now_ns)
    }

    fn poll_mask_locked(&self, inner: &mut TimerFdInner) -> i16 {
        let _ = self.flush_expirations(inner);
        if inner.canceled || inner.expirations > 0 {
            POLLIN
        } else {
            0
        }
    }

    pub fn poll_readable(&self) -> bool {
        let mut inner = self.inner.lock();
        self.poll_mask_locked(&mut inner) != 0
    }

    pub fn read_counter(&self, nonblock: bool) -> Result<u64, isize> {
        loop {
            let mut inner = self.inner.lock();
            let _ = self.flush_expirations(&mut inner);
            if inner.canceled {
                return Err(err(SyscallError::ECANCELED));
            }
            if inner.expirations > 0 {
                let value = inner.expirations;
                inner.expirations = 0;
                return Ok(value);
            }
            if nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            let Some(task) = current_task() else {
                return Err(err(SyscallError::EAGAIN));
            };
            Self::add_waiter_once(&mut inner.read_waiters, &task);
            drop(inner);
            block_current_and_run_next();
        }
    }

    pub fn get_time(&self) -> Result<(u64, u64), isize> {
        let mut inner = self.inner.lock();
        let _ = self.flush_expirations(&mut inner);
        let remain_ns = if inner.canceled {
            0
        } else if let Some(deadline_ns) = inner.deadline_ns {
            let Some(now_ns) = Self::now_ns(self.clock_id) else {
                return Err(err(SyscallError::EINVAL));
            };
            deadline_ns.saturating_sub(now_ns)
        } else {
            0
        };
        Ok((remain_ns, inner.interval_ns))
    }

    pub fn set_time(
        &self,
        deadline_ns: Option<u64>,
        interval_ns: u64,
        cancel_on_set: bool,
    ) -> Result<(u64, u64, bool), isize> {
        let mut inner = self.inner.lock();
        let _ = self.flush_expirations(&mut inner);
        let was_canceled = inner.canceled;
        let remain_ns = if inner.canceled {
            0
        } else if let Some(old_deadline_ns) = inner.deadline_ns {
            let Some(now_ns) = Self::now_ns(self.clock_id) else {
                return Err(err(SyscallError::EINVAL));
            };
            old_deadline_ns.saturating_sub(now_ns)
        } else {
            0
        };
        let old_interval_ns = inner.interval_ns;
        let was_armed = self.is_armed_locked(&inner);
        let old_deadline_ns = inner.deadline_ns.filter(|_| was_armed);
        inner.deadline_ns = deadline_ns;
        inner.interval_ns = interval_ns;
        inner.expirations = 0;
        inner.cancel_on_set = cancel_on_set;
        inner.canceled = false;
        self.update_schedule_locked(&mut inner, was_armed, old_deadline_ns);
        let became_ready = self.flush_expirations(&mut inner);
        if became_ready {
            let mut waiters = Self::wake_read_waiters(&mut inner.read_waiters);
            waiters.extend(inner.poll_waiters.take_wakeups());
            drop(inner);
            wake_tasks(waiters);
        }
        Ok((remain_ns, old_interval_ns, was_canceled))
    }

    fn cancel_on_realtime_set(&self) -> bool {
        let mut inner = self.inner.lock();
        if self.clock_id != CLOCK_REALTIME || !inner.cancel_on_set || inner.canceled {
            return false;
        }
        let was_armed = self.is_armed_locked(&inner);
        let old_deadline_ns = inner.deadline_ns.filter(|_| was_armed);
        inner.canceled = true;
        inner.deadline_ns = None;
        inner.expirations = 0;
        self.update_schedule_locked(&mut inner, was_armed, old_deadline_ns);
        let mut waiters = Self::wake_read_waiters(&mut inner.read_waiters);
        waiters.extend(inner.poll_waiters.take_wakeups());
        drop(inner);
        wake_tasks(waiters);
        true
    }
}

impl Drop for TimerFdFile {
    fn drop(&mut self) {
        let inner = self.inner.lock();
        if !matches!(self.clock_id, CLOCK_MONOTONIC | CLOCK_REALTIME)
            || inner.deadline_ns.is_none()
            || inner.canceled
        {
            return;
        }
        TIMERFD_SCHEDULE
            .lock()
            .adjust_armed(self.clock_id, true, false);
    }
}

impl File for TimerFdFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let Ok(value) = self.read_counter(false) else {
            return 0;
        };
        let bytes = value.to_ne_bytes();
        let mut copied = 0usize;
        for slice in buf.buffers.iter_mut() {
            let n = slice.len().min(bytes.len().saturating_sub(copied));
            slice[..n].copy_from_slice(&bytes[copied..copied + n]);
            copied += n;
            if copied >= bytes.len() {
                break;
            }
        }
        copied
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn poll_mask(&self) -> i16 {
        let mut inner = self.inner.lock();
        self.poll_mask_locked(&mut inner)
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut inner = self.inner.lock();
        if self.poll_mask_locked(&mut inner) != 0 {
            return true;
        }
        inner.poll_waiters.register_waiter(task)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) fn process_timerfd_expirations() {
    for clock_id in [CLOCK_MONOTONIC, CLOCK_REALTIME] {
        let Some(now_ns) = TimerFdFile::now_ns(clock_id) else {
            continue;
        };
        loop {
            let entry = {
                let mut state = TIMERFD_SCHEDULE.lock();
                let Some(heap) = TimerFdFile::schedule_heap_mut(&mut state, clock_id) else {
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
            let Some(file) = entry.file.upgrade() else {
                continue;
            };
            let waiters = {
                let mut inner = file.inner.lock();
                if inner.schedule_seq != entry.sequence
                    || inner.canceled
                    || inner.deadline_ns.is_none()
                {
                    continue;
                }
                if !file.advance_to_ns_locked(&mut inner, now_ns) {
                    continue;
                }
                let mut waiters = TimerFdFile::wake_read_waiters(&mut inner.read_waiters);
                waiters.extend(inner.poll_waiters.take_wakeups());
                waiters
            };
            wake_tasks(waiters);
        }
    }
}

pub(crate) fn timerfd_work_pending_for_user_return() -> bool {
    if TIMERFD_ARMED_TOTAL.load(AtomicOrdering::Acquire) == 0 {
        return false;
    }
    let monotonic_now_ns = TimerFdFile::now_ns(CLOCK_MONOTONIC);
    let realtime_now_ns = TimerFdFile::now_ns(CLOCK_REALTIME);
    let state = TIMERFD_SCHEDULE.lock();
    let monotonic_due = state.monotonic_armed != 0
        && monotonic_now_ns.is_some_and(|now_ns| {
            state
                .monotonic
                .peek()
                .is_some_and(|entry| entry.deadline_ns <= now_ns)
        });
    let realtime_due = state.realtime_armed != 0
        && realtime_now_ns.is_some_and(|now_ns| {
            state
                .realtime
                .peek()
                .is_some_and(|entry| entry.deadline_ns <= now_ns)
        });
    monotonic_due || realtime_due
}

pub(crate) fn cancel_realtime_timerfds_on_set() {
    let files = TIMERFD_SCHEDULE.lock().live_realtime_files();
    for file in files {
        let _ = file.cancel_on_realtime_set();
    }
}
