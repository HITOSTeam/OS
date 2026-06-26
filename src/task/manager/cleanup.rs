use alloc::sync::Arc;

use crate::task::task_block::TaskControlBlock;

use super::remove_task;

/// 取消该任务拥有的通用 sleep timer。
pub fn remove_timer(task: Arc<TaskControlBlock>) {
    crate::task::block_sleep::remove_timers_for_task(&task);
}

/// 完整清理一个不再活跃的任务：从 futex 等待队列、条件变量等待队列、定时器堆和就绪队列中移除
pub fn remove_inactive_task(task: Arc<TaskControlBlock>) {
    // 这里可能会加入 todo
    crate::syscall::futex::remove_futex_waiters(&task);
    crate::task::process_block::remove_task_from_wait_queues(&task);
    remove_timer(task.clone());
    remove_task(task.clone());
}

/// 对已知离开对象等待队列的任务做轻量清理。
///
/// 正在运行并自行退出的任务不会睡在 futex/pipe/condvar 等待队列上；已经完成
/// exit 清理的 zombie 任务也已在退出路径处理过这些引用。这里仅清理调度器/timer
/// 引用，避免 fork-heavy 工作负载每次 reap 都付出 O(processes * fds) 的全局扫描成本。
pub fn remove_sched_timer_refs(task: Arc<TaskControlBlock>) {
    remove_timer(task.clone());
    remove_task(task);
}
