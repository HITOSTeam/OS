use alloc::{sync::Arc, vec::Vec};

use crate::{
    task::{
        ProcessControlBlock,
        processor::current_task,
        task_block::TaskControlBlock,
    },
    time::get_time_ns,
};

/// Monotonic nanoseconds used for scheduler runtime accounting.
#[inline]
pub fn monotonic_time_ns() -> u64 {
    get_time_ns()
}

/// Charge runtime consumed by a currently running task up to `now_ns`.
#[inline]
pub fn charge_running_task_until(task: &Arc<TaskControlBlock>, now_ns: u64) -> u64 {
    task.account_runtime_until(now_ns)
}

/// Charge runtime using the current monotonic timestamp.
#[inline]
pub fn charge_running_task(task: &Arc<TaskControlBlock>) -> u64 {
    charge_running_task_until(task, monotonic_time_ns())
}

/// Mark the start of a fresh runtime slice after the task is scheduled in.
#[inline]
pub fn start_task_runtime_slice(task: &Arc<TaskControlBlock>, now_ns: u64) {
    task.begin_runtime_slice(now_ns);
}

/// Return total runtime for a task, including its in-flight running slice.
#[inline]
pub fn task_cpu_time_ns_at(task: &Arc<TaskControlBlock>, now_ns: u64) -> u64 {
    task.cpu_time_total_ns(now_ns)
}

/// Return total runtime for a task using the current monotonic timestamp.
#[inline]
pub fn task_cpu_time_ns(task: &Arc<TaskControlBlock>) -> u64 {
    task_cpu_time_ns_at(task, monotonic_time_ns())
}

/// Snapshot all live threads of a process so callers can sum without holding
/// the PCB lock while traversing per-task runtime state.
pub fn process_tasks(process: &Arc<ProcessControlBlock>) -> Vec<Arc<TaskControlBlock>> {
    let inner = process.borrow_mut();
    inner
        .tasks
        .iter()
        .filter_map(|task| task.as_ref().cloned())
        .collect()
}

/// Resolve a live thread by internal tid index.
pub fn process_task_by_index(
    process: &Arc<ProcessControlBlock>,
    tid_index: usize,
) -> Option<Arc<TaskControlBlock>> {
    let inner = process.borrow_mut();
    inner.tasks.get(tid_index)?.as_ref().cloned()
}

/// Return total CPU runtime for a process at a fixed snapshot time.
pub fn process_cpu_time_ns_at(process: &Arc<ProcessControlBlock>, now_ns: u64) -> u64 {
    process_tasks(process)
        .into_iter()
        .map(|task| task_cpu_time_ns_at(&task, now_ns))
        .fold(0u64, |acc, ns| acc.saturating_add(ns))
}

/// Return total CPU runtime for a process using the current monotonic timestamp.
pub fn process_cpu_time_ns(process: &Arc<ProcessControlBlock>) -> u64 {
    process_cpu_time_ns_at(process, monotonic_time_ns())
}

/// Return total CPU runtime for the current task, including the running slice.
pub fn current_task_cpu_time_ns() -> u64 {
    current_task().map(|task| task_cpu_time_ns(&task)).unwrap_or(0)
}
