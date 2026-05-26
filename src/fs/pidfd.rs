use alloc::sync::{Arc, Weak};
use core::any::Any;

use crate::{
    mm::UserBuffer,
    task::{ProcessControlBlock, task_block::TaskControlBlock},
};

use super::{File, POLLIN, wake_tasks};

/// `pidfd_open(2)` / `clone3(CLONE_PIDFD)` / `waitid(P_PIDFD, ...)` 用到的 pidfd 对象。
///
/// 持有 `Weak<ProcessControlBlock>` 而不是裸 PID。Linux pidfd 语义要求绑定的是
/// "那一次创建的进程"本身，而不是 PID 数值——目标退出并被回收后，即便分配器
/// 在某次 wrap 回环里把同一个 PID 重新分给新进程，stale pidfd 也必须返回
/// `ESRCH`，绝不能误投递到无关进程。`Weak` 升级失败这一事实正好对应
/// "原 target 的 `ProcessControlBlock` 已被 drop"，与 `PidHandle::drop` 触发
/// PID 释放的时刻一致，因此可作为 identity 判据。
pub struct PidFdFile {
    target: Weak<ProcessControlBlock>,
}

impl PidFdFile {
    pub fn new(process: &Arc<ProcessControlBlock>) -> Self {
        Self {
            target: Arc::downgrade(process),
        }
    }

    /// identity-safe 的目标进程解析。返回 `None` 表示创建时绑定的那个
    /// `ProcessControlBlock` 已被完全释放，此时调用方应返回 `ESRCH`。
    pub fn target_process(&self) -> Option<Arc<ProcessControlBlock>> {
        self.target.upgrade()
    }

    fn poll_readable(&self) -> bool {
        match self.target_process() {
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
        if let Some(process) = self.target_process() {
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
    let Some(process) = crate::task::manager::pid2process(pid) else {
        return;
    };
    let waiters = {
        let mut inner = process.borrow_mut();
        inner.pidfd_poll_waiters.take_wakeups()
    };
    wake_tasks(waiters);
}
