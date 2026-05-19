use alloc::sync::Arc;

use crate::task::{condvar::Condvar, processor::current_process};

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
    drop(process_inner);
    condvar.signal();
    0
}

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
    let Some(mutex) = process_inner
        .mutex_list
        .get(mutex_id)
        .and_then(|m| m.as_ref())
        .cloned()
    else {
        return -1;
    };
    drop(process_inner);
    condvar.wait(mutex);
    0
}
