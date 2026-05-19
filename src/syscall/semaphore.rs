pub fn sys_semaphore_create(res_count: usize) -> isize {
    let semaphore = crate::task::semaphore::Semaphore::new(res_count);
    let current_task =
        crate::task::processor::current_task().expect("sys_semaphore_create: no current task");
    let Some(pcb) = current_task.process.upgrade() else {
        return -1;
    };
    let mut pcb_inner = pcb.borrow_mut();
    pcb_inner.semaphore_list.push(Some(semaphore));
    (pcb_inner.semaphore_list).len() as isize - 1
}
pub fn sys_semaphore_up(sem_id: usize) -> isize {
    let current_task =
        crate::task::processor::current_task().expect("sys_semaphore_up: no current task");
    let Some(pcb) = current_task.process.upgrade() else {
        return -1;
    };
    let pcb_inner = pcb.borrow_mut();
    let Some(semaphore) = pcb_inner.semaphore_list.get(sem_id).and_then(|s| s.clone()) else {
        return -1;
    };
    drop(pcb_inner);
    drop(current_task);
    semaphore.up();
    0
}
pub fn sys_semaphore_down(sem_id: usize) -> isize {
    let current_task =
        crate::task::processor::current_task().expect("sys_semaphore_down: no current task");
    let Some(pcb) = current_task.process.upgrade() else {
        return -1;
    };
    let pcb_inner = pcb.borrow_mut();
    let Some(semaphore) = pcb_inner.semaphore_list.get(sem_id).and_then(|s| s.clone()) else {
        return -1;
    };
    drop(pcb_inner);
    drop(current_task);
    semaphore.down();
    0
}
