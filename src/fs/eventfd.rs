use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{any::Any, mem::size_of};
use spin::Mutex;

use crate::{
    mm::UserBuffer,
    task::{
        processor::{block_current_and_run_next, current_task},
        task_block::TaskControlBlock,
    },
};

use super::{File, POLLIN, POLLOUT, PollWaitQueue, wake_tasks};
use crate::syscall::error::{SyscallError, err};

const EVENTFD_COUNTER_MAX: u64 = u64::MAX - 1;

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

    #[allow(dead_code)]
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

    pub fn write_counter(&self, value: u64, nonblock: bool) -> Result<(), isize> {
        if value == u64::MAX {
            return Err(err(SyscallError::EINVAL));
        }
        loop {
            let mut inner = self.inner.lock();
            if value <= EVENTFD_COUNTER_MAX.saturating_sub(inner.counter) {
                inner.counter = inner.counter.saturating_add(value);
                Self::wake_state_waiters(&mut inner);
                return Ok(());
            }
            if nonblock || self.nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            let Some(task) = current_task() else {
                return Err(err(SyscallError::EAGAIN));
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
