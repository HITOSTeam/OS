use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::task::{
    manager::wakeup_task,
    processor::{block_current_and_run_next, current_task, suspend_current_and_run_next},
    task_block::TaskControlBlock,
};
use spin::Mutex as SpinLock;

// this is needed for multi thread(or error )
pub trait Mutex: Sync + Send {
    fn lock(&self);
    fn unlock(&self);
}
// todo :busy-wait mutex and block mutex
// because things in arc cant be changed we need inner part here.

pub struct BlockMutex {
    inner: SpinLock<BlockMutexInner>,
}
pub struct BlockMutexInner {
    is_blocked: bool,
    //use priorioty queue to contain the TimeWrap(block task)
    wait_queue: VecDeque<Arc<TaskControlBlock>>,
}
impl BlockMutex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: SpinLock::new(BlockMutexInner {
                is_blocked: false,
                wait_queue: VecDeque::new(),
            }),
        })
    }
}
impl Mutex for BlockMutex {
    fn lock(&self) {
        let mut inner = self.inner.lock();
        match inner.is_blocked {
            false => {
                inner.is_blocked = true;
            }
            true => {
                let task = current_task().unwrap();
                inner.wait_queue.push_back(task);
                drop(inner); // Drop the borrow before blocking
                block_current_and_run_next();
            }
        }
    }
    fn unlock(&self) {
        let mut inner = self.inner.lock();
        assert!(inner.is_blocked);
        if let Some(task) = inner.wait_queue.pop_front() {
            // everytime we just wake one
            wakeup_task(task);
        } else {
            inner.is_blocked = false;
        }
    }
}

pub struct SpinMutex {
    locked: AtomicBool,
}
impl SpinMutex {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            locked: AtomicBool::new(false),
        })
    }
}
impl Mutex for SpinMutex {
    fn lock(&self) {
        loop {
            if self.locked.swap(true, Ordering::Acquire) {
                suspend_current_and_run_next();
                continue;
            } else {
                return;
            }
        }
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}
