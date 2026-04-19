use alloc::sync::Arc;
use core::any::Any;

use crate::{
    mm::UserBuffer,
    task::{
        manager::{pid2process, wakeup_task},
        task_block::TaskControlBlock,
    },
};

use super::{File, POLLIN, PollWaitQueue, wake_tasks};

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
