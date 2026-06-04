//! 条件变量的实现
use alloc::{collections::VecDeque, sync::Arc};

use crate::task::{
    manager::wakeup_task,
    mutex::Mutex,
    processor::{block_current_and_run_next, current_task},
    task_block::TaskControlBlock,
};
use spin::Mutex as SpinLock;

/// 条件变量。
/// 实现为一个受mutex 保护的队列。
pub struct Condvar {
    pub inner: SpinLock<CondvarInner>,
}

pub struct CondvarInner {
    pub wait_queue: VecDeque<Arc<TaskControlBlock>>,
}

impl Condvar {
    /// 创建一个空的条件变量
    pub fn new() -> Self {
        Self {
            inner: SpinLock::new(CondvarInner {
                wait_queue: VecDeque::new(),
            }),
        }
    }

    /// 唤醒等待队列中最早阻塞的任务（FIFO），队列为空时无操作
    pub fn signal(&self) {
        let mut inner = self.inner.lock();
        if let Some(task) = inner.wait_queue.pop_front() {
            wakeup_task(task);
        }
    }

    /// 原子地释放 `mutex`、阻塞当前任务并在被唤醒后重新获取 `mutex`
    pub fn wait(&self, mutex: Arc<dyn Mutex>) {
        // 确保操作原子
        let mut inner = self.inner.lock();
        mutex.unlock();
        inner.wait_queue.push_back(current_task().unwrap());
        // 必须在调度切换前显式释放自旋锁，否则 signal() 将在下一次调度时死等同一把锁
        drop(inner);
        block_current_and_run_next();
        mutex.lock();
    }
}
