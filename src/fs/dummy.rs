use alloc::{
    collections::{BTreeMap, BinaryHeap, VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{any::Any, cmp::Ordering, mem::size_of};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::{
    config::PAGE_SIZE,
    mm::UserBuffer,
    task::{
        manager::{pid2process, wakeup_task},
        processor::{block_current_and_run_next, current_task},
        task_block::TaskControlBlock,
    },
};

use super::{File, POLLIN, POLLOUT, PollWaitQueue, wake_tasks};

const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFD_PAGEFAULT_FLAG_WRITE: u64 = 1 << 0;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
const UFFD_API_IOCTLS: u64 = (1u64 << 0) | (1u64 << 3) | (1u64 << 0x3f);
const UFFD_REGISTER_IOCTLS: u64 = 1u64 << 3;
const EINVAL: isize = -22;
const EAGAIN: isize = -11;
const ECANCELED: isize = -125;
const EVENTFD_COUNTER_MAX: u64 = u64::MAX - 1;

/// A minimal no-op file for stubbed syscalls.
pub struct DummyFile {
    readable: bool,
    writable: bool,
}

impl DummyFile {
    pub fn new(readable: bool, writable: bool) -> Self {
        Self { readable, writable }
    }
}

impl File for DummyFile {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, buf: UserBuffer) -> usize {
        buf.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct EventFdInner {
    counter: u64,
    read_waiters: VecDeque<Weak<TaskControlBlock>>,
    write_waiters: VecDeque<Weak<TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
}

pub struct EventFdFile {
    semaphore: bool,
    nonblock: bool,
    inner: Mutex<EventFdInner>,
}

impl EventFdFile {
    pub fn new(counter: u64, semaphore: bool, nonblock: bool) -> Self {
        Self {
            semaphore,
            nonblock,
            inner: Mutex::new(EventFdInner {
                counter,
                read_waiters: VecDeque::new(),
                write_waiters: VecDeque::new(),
                poll_waiters: PollWaitQueue::default(),
            }),
        }
    }

    pub fn nonblock(&self) -> bool {
        self.nonblock
    }

    pub fn poll_readable(&self) -> bool {
        self.inner.lock().counter > 0
    }

    pub fn poll_writable(&self) -> bool {
        self.inner.lock().counter < EVENTFD_COUNTER_MAX
    }

    fn add_waiter_once(
        waiters: &mut VecDeque<Weak<TaskControlBlock>>,
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

    fn wake_waiters(waiters: &mut VecDeque<Weak<TaskControlBlock>>) {
        let mut ready = Vec::new();
        waiters.retain(|waiter| {
            let Some(task) = waiter.upgrade() else {
                return false;
            };
            ready.push(task);
            false
        });
        wake_tasks(ready);
    }

    fn wake_state_waiters(inner: &mut EventFdInner) {
        Self::wake_waiters(&mut inner.read_waiters);
        Self::wake_waiters(&mut inner.write_waiters);
        wake_tasks(inner.poll_waiters.take_wakeups());
    }

    pub fn read_counter(&self, nonblock: bool) -> Result<u64, isize> {
        loop {
            let mut inner = self.inner.lock();
            if inner.counter > 0 {
                let value = if self.semaphore {
                    inner.counter -= 1;
                    1
                } else {
                    let value = inner.counter;
                    inner.counter = 0;
                    value
                };
                Self::wake_state_waiters(&mut inner);
                return Ok(value);
            }
            if nonblock || self.nonblock {
                return Err(EAGAIN);
            }
            let Some(task) = current_task() else {
                return Err(EAGAIN);
            };
            Self::add_waiter_once(&mut inner.read_waiters, &task);
            drop(inner);
            block_current_and_run_next();
        }
    }

    pub fn write_counter(&self, value: u64, nonblock: bool) -> Result<(), isize> {
        if value == u64::MAX {
            return Err(EINVAL);
        }
        loop {
            let mut inner = self.inner.lock();
            if value <= EVENTFD_COUNTER_MAX.saturating_sub(inner.counter) {
                inner.counter = inner.counter.saturating_add(value);
                Self::wake_state_waiters(&mut inner);
                return Ok(());
            }
            if nonblock || self.nonblock {
                return Err(EAGAIN);
            }
            let Some(task) = current_task() else {
                return Err(EAGAIN);
            };
            Self::add_waiter_once(&mut inner.write_waiters, &task);
            drop(inner);
            block_current_and_run_next();
        }
    }
}

impl File for EventFdFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
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

    fn write(&self, buf: UserBuffer) -> usize {
        if buf.len() < size_of::<u64>() {
            return 0;
        }
        let mut bytes = [0u8; size_of::<u64>()];
        let mut copied = 0usize;
        for slice in buf.buffers.iter() {
            let n = slice.len().min(bytes.len().saturating_sub(copied));
            bytes[copied..copied + n].copy_from_slice(&slice[..n]);
            copied += n;
            if copied >= bytes.len() {
                break;
            }
        }
        if copied < bytes.len() {
            return 0;
        }
        let Ok(()) = self.write_counter(u64::from_ne_bytes(bytes), false) else {
            return 0;
        };
        size_of::<u64>()
    }

    fn poll_mask(&self) -> i16 {
        let inner = self.inner.lock();
        let mut mask = 0;
        if inner.counter > 0 {
            mask |= POLLIN;
        }
        if inner.counter < EVENTFD_COUNTER_MAX {
            mask |= POLLOUT;
        }
        mask
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut inner = self.inner.lock();
        let _ = inner.poll_waiters.register_waiter(task);
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

lazy_static! {
    static ref TIMERFD_SCHEDULE: Mutex<TimerFdScheduleState> =
        Mutex::new(TimerFdScheduleState::default());
}

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
        } else {
            *armed = armed.saturating_sub(1);
        }
    }

    fn has_live_timers(&self) -> bool {
        self.monotonic_armed != 0 || self.realtime_armed != 0
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
    read_waiters: VecDeque<Weak<TaskControlBlock>>,
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
                read_waiters: VecDeque::new(),
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

    fn add_waiter_once(
        waiters: &mut VecDeque<Weak<TaskControlBlock>>,
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
        waiters: &mut VecDeque<Weak<TaskControlBlock>>,
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

    fn update_schedule_locked(&self, inner: &mut TimerFdInner, was_armed: bool) {
        let is_armed = self.is_armed_locked(inner);
        inner.schedule_seq = inner.schedule_seq.wrapping_add(1);
        let mut state = TIMERFD_SCHEDULE.lock();
        state.adjust_armed(self.clock_id, was_armed, is_armed);
        let Some(deadline_ns) = inner.deadline_ns.filter(|_| is_armed) else {
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
            self.update_schedule_locked(inner, was_armed);
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
                return Err(ECANCELED);
            }
            if inner.expirations > 0 {
                let value = inner.expirations;
                inner.expirations = 0;
                return Ok(value);
            }
            if nonblock {
                return Err(EAGAIN);
            }
            let Some(task) = current_task() else {
                return Err(EAGAIN);
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
                return Err(EINVAL);
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
                return Err(EINVAL);
            };
            old_deadline_ns.saturating_sub(now_ns)
        } else {
            0
        };
        let old_interval_ns = inner.interval_ns;
        let was_armed = self.is_armed_locked(&inner);
        inner.deadline_ns = deadline_ns;
        inner.interval_ns = interval_ns;
        inner.expirations = 0;
        inner.cancel_on_set = cancel_on_set;
        inner.canceled = false;
        self.update_schedule_locked(&mut inner, was_armed);
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
        inner.canceled = true;
        inner.deadline_ns = None;
        inner.expirations = 0;
        self.update_schedule_locked(&mut inner, was_armed);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceKind {
    Ipc,
}

impl NamespaceKind {
    pub fn clone_flag(self) -> usize {
        const CLONE_NEWIPC: usize = 0x0800_0000;
        match self {
            Self::Ipc => CLONE_NEWIPC,
        }
    }
}

/// Minimal namespace descriptor exposed by `/proc/<pid>/ns/*`.
pub struct NamespaceFile {
    kind: NamespaceKind,
    ns_id: usize,
}

impl NamespaceFile {
    pub fn new(kind: NamespaceKind, ns_id: usize) -> Self {
        Self { kind, ns_id }
    }

    pub fn new_ipc(ns_id: usize) -> Self {
        Self::new(NamespaceKind::Ipc, ns_id)
    }

    pub fn kind(&self) -> NamespaceKind {
        self.kind
    }

    pub fn ns_id(&self) -> usize {
        self.ns_id
    }
}

impl File for NamespaceFile {
    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// pidfd object used by `pidfd_open(2)` and `waitid(P_PIDFD, ...)`.
pub struct PidFdFile {
    target_pid: usize,
}

impl PidFdFile {
    pub fn new(target_pid: usize) -> Self {
        Self { target_pid }
    }

    pub fn target_pid(&self) -> usize {
        self.target_pid
    }

    fn poll_readable(&self) -> bool {
        match pid2process(self.target_pid()) {
            Some(proc) => proc.borrow_mut().is_zombie,
            None => true,
        }
    }
}

impl File for PidFdFile {
    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn poll_mask(&self) -> i16 {
        if self.poll_readable() { POLLIN } else { 0 }
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        if self.poll_readable() {
            return true;
        }
        if let Some(process) = pid2process(self.target_pid()) {
            let mut inner = process.borrow_mut();
            if inner.is_zombie {
                return true;
            }
            let _ = inner.pidfd_poll_waiters.register_waiter(task);
        }
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UffdMsgPagefault {
    flags: u64,
    address: u64,
    reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UffdMsg {
    event: u8,
    reserved1: u8,
    reserved2: u16,
    reserved3: u32,
    pagefault: UffdMsgPagefault,
}

impl UffdMsg {
    fn pagefault(address: usize, write: bool) -> Self {
        Self {
            event: UFFD_EVENT_PAGEFAULT,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            pagefault: UffdMsgPagefault {
                flags: if write { UFFD_PAGEFAULT_FLAG_WRITE } else { 0 },
                address: address as u64,
                reserved: 0,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct UffdRegistration {
    start: usize,
    end: usize,
    mode: u64,
}

struct UserfaultfdInner {
    api_enabled: bool,
    registrations: Vec<UffdRegistration>,
    pending: VecDeque<UffdMsg>,
    blocked_pages: BTreeMap<usize, Vec<Weak<TaskControlBlock>>>,
    read_waiters: Vec<Weak<TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
}

pub struct UserfaultfdFile {
    inner: Mutex<UserfaultfdInner>,
}

impl UserfaultfdFile {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(UserfaultfdInner {
                api_enabled: false,
                registrations: Vec::new(),
                pending: VecDeque::new(),
                blocked_pages: BTreeMap::new(),
                read_waiters: Vec::new(),
                poll_waiters: PollWaitQueue::default(),
            }),
        }
    }

    pub fn poll_readable(&self) -> bool {
        !self.inner.lock().pending.is_empty()
    }

    pub fn enable_api(&self) -> u64 {
        let mut inner = self.inner.lock();
        inner.api_enabled = true;
        UFFD_API_IOCTLS
    }

    pub fn register_missing(&self, start: usize, len: usize, mode: u64) -> Result<u64, isize> {
        if len == 0 || mode != UFFDIO_REGISTER_MODE_MISSING {
            return Err(EINVAL);
        }
        let end = start.checked_add(len).ok_or(EINVAL)?;
        let mut inner = self.inner.lock();
        if !inner.api_enabled {
            return Err(EINVAL);
        }
        inner
            .registrations
            .push(UffdRegistration { start, end, mode });
        Ok(UFFD_REGISTER_IOCTLS)
    }

    pub fn handle_page_fault(&self, fault_addr: usize, is_write: bool) -> bool {
        let page = fault_addr & !(PAGE_SIZE - 1);
        let waiters = {
            let mut inner = self.inner.lock();
            if !inner.api_enabled
                || !inner.registrations.iter().any(|reg| {
                    reg.mode == UFFDIO_REGISTER_MODE_MISSING
                        && fault_addr >= reg.start
                        && fault_addr < reg.end
                })
            {
                return false;
            }
            if let Some(task) = current_task() {
                inner
                    .blocked_pages
                    .entry(page)
                    .or_default()
                    .push(Arc::downgrade(&task));
            }
            if !inner.blocked_pages.contains_key(&page)
                || !inner.pending.iter().any(|msg| {
                    msg.event == UFFD_EVENT_PAGEFAULT
                        && (msg.pagefault.address as usize & !(PAGE_SIZE - 1)) == page
                })
            {
                inner
                    .pending
                    .push_back(UffdMsg::pagefault(fault_addr, is_write));
            }
            let mut ready = Vec::new();
            inner.read_waiters.retain(|waiter| {
                if let Some(task) = waiter.upgrade() {
                    ready.push(task);
                    false
                } else {
                    false
                }
            });
            ready.extend(inner.poll_waiters.take_wakeups());
            ready
        };
        wake_tasks(waiters);
        block_current_and_run_next();
        true
    }

    pub fn finish_copy(&self, dst: usize, len: usize, wake: bool) {
        if len == 0 {
            return;
        }
        let start = dst & !(PAGE_SIZE - 1);
        let end = (dst + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let tasks = {
            let mut inner = self.inner.lock();
            let mut tasks = Vec::new();
            if wake {
                let mut page = start;
                while page < end {
                    if let Some(waiters) = inner.blocked_pages.remove(&page) {
                        for waiter in waiters {
                            if let Some(task) = waiter.upgrade() {
                                tasks.push(task);
                            }
                        }
                    }
                    page += PAGE_SIZE;
                }
            }
            tasks
        };
        for task in tasks {
            wakeup_task(task);
        }
    }

    fn wait_for_message(&self) -> UffdMsg {
        loop {
            if let Some(msg) = self.inner.lock().pending.pop_front() {
                return msg;
            }
            if let Some(task) = current_task() {
                self.inner.lock().read_waiters.push(Arc::downgrade(&task));
            }
            block_current_and_run_next();
        }
    }
}

impl File for UserfaultfdFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, buf: UserBuffer) -> usize {
        let msg = self.wait_for_message();
        let src = unsafe {
            core::slice::from_raw_parts((&msg as *const UffdMsg) as *const u8, size_of::<UffdMsg>())
        };
        let mut copied = 0usize;
        let mut it = buf.into_iter();
        while copied < src.len() {
            let Some(dst) = it.next() else {
                break;
            };
            unsafe {
                *dst = src[copied];
            }
            copied += 1;
        }
        copied
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn poll_mask(&self) -> i16 {
        if self.poll_readable() { POLLIN } else { 0 }
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut inner = self.inner.lock();
        if !inner.pending.is_empty() {
            return true;
        }
        let _ = inner.poll_waiters.register_waiter(task);
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) fn wake_pidfd_poll_waiters(pid: usize) {
    let Some(process) = pid2process(pid) else {
        return;
    };
    let waiters = {
        let mut inner = process.borrow_mut();
        inner.pidfd_poll_waiters.take_wakeups()
    };
    wake_tasks(waiters);
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

pub(crate) fn has_pending_timerfds() -> bool {
    TIMERFD_SCHEDULE.lock().has_live_timers()
}

pub(crate) fn cancel_realtime_timerfds_on_set() {
    let files = TIMERFD_SCHEDULE.lock().live_realtime_files();
    for file in files {
        let _ = file.cancel_on_realtime_set();
    }
}
