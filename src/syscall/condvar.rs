//! 本文件只是condvar syscall 封装，详细代码在task内
use alloc::sync::Arc;

use crate::task::{condvar::Condvar, processor::current_process};
//！
/// 为当前进程创建一个条件变量，返回其在 condvar_list 中的下标，失败返回 -1
// 允许复用 老id
pub fn sys_condvar_create() -> isize {
    let process = current_process();
    let mut process_inner = process.borrow_mut();
    let id = if let Some(id) = process_inner
        .condvar_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        process_inner.condvar_list[id] = Some(Arc::new(Condvar::new()));
        id
    } else {
        process_inner
            .condvar_list
            .push(Some(Arc::new(Condvar::new())));
        process_inner.condvar_list.len() - 1
    };
    id as isize
}

/// 唤醒等待 `condvar_id` 的一个任务，condvar 不存在时返回 -1
pub fn sys_condvar_signal(condvar_id: usize) -> isize {
    let process = current_process();
    let process_inner = process.borrow_mut();
    let Some(condvar) = process_inner
        .condvar_list
        .get(condvar_id)
        .and_then(|c| c.as_ref())
        .cloned()
    else {
        return -1;
    };
    // condvar.signal() 内部可能触发调度器重新借用 process，必须先归还 borrow
    drop(process_inner);
    condvar.signal();
    0
}

/// 在 `condvar_id` 上等待，等待期间释放 `mutex_id` 对应的互斥锁，唤醒后重新持有；condvar 或 mutex 不存在时返回 -1
pub fn sys_condvar_wait(condvar_id: usize, mutex_id: usize) -> isize {
    let process = current_process();
    let process_inner = process.borrow_mut();
    let Some(condvar) = process_inner
        .condvar_list
        .get(condvar_id)
        .and_then(|c| c.as_ref())
        .cloned()
    else {
        return -1;
    };
    // 两次 cloned() 都在同一次 borrow 内完成，避免释放再借期间列表被其他线程修改
    let Some(mutex) = process_inner
        .mutex_list
        .get(mutex_id)
        .and_then(|m| m.as_ref())
        .cloned()
    else {
        return -1;
    };
    // condvar.wait() 会触发调度切换并重新借用 process，必须先释放 RefCell borrow 否则 panic
    drop(process_inner);
    condvar.wait(mutex);
    0
}
