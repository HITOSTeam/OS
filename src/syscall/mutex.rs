use crate::task::mutex::BlockMutex;

use crate::task::mutex::Mutex;
use crate::task::mutex::SpinMutex;
use crate::task::processor::current_task;
use alloc::sync::Arc;

pub fn sys_mutex_create(is_block: bool) -> isize {
    let target_mutex: Arc<dyn Mutex>;
    if is_block {
        target_mutex = BlockMutex::new();
    } else {
        target_mutex = SpinMutex::new(); // TODO: replace with BusyWaitMutex
    }
    let current_task = current_task().expect("sys_mutex_create: no current task");
    let Some(pcb) = current_task.process.upgrade() else {
        return -1;
    };
    let mut pcb_inner = pcb.borrow_mut();
    pcb_inner.mutex_list.push(Some(target_mutex));
    0
}
pub fn sys_mutex_lock(mutex_id: usize) -> isize {
    let current_task = current_task().expect("sys_mutex_lock: no current task");
    let Some(pcb) = current_task.process.upgrade() else {
        return -1;
    };
    let pcb_inner = pcb.borrow_mut();
    let Some(mutex) = pcb_inner.mutex_list.get(mutex_id).and_then(|m| m.clone()) else {
        return -1;
    };
    drop(pcb_inner);
    drop(current_task);
    mutex.lock();
    0
}
pub fn sys_mutex_unlock(mutex_id: usize) -> isize {
    let current_task = current_task().expect("sys_mutex_unlock: no current task");
    let Some(pcb) = current_task.process.upgrade() else {
        return -1;
    };
    let pcb_inner = pcb.borrow_mut();
    let Some(mutex) = pcb_inner.mutex_list.get(mutex_id).and_then(|m| m.clone()) else {
        return -1;
    };
    drop(pcb_inner);
    drop(current_task);
    mutex.unlock();
    0
}
