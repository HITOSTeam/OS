//! EEVDF 公平调度器运行时计时模块
//!
//! 本模块是调度系统与时间统计之间的薄层适配器，负责：
//!
//! - 提供调度器使用的单调纳秒时间戳（[`monotonic_time_ns`]）
//! - 在任务被抢占或主动让出 CPU 时，将本次运行片段的耗时计入 TCB 累计值（charge）
//! - 在任务被调度上 CPU 时，记录本次运行片段的起点时间戳（slice start）
//! - 以固定快照时间点为基准，查询单个任务或整个进程的累计 CPU 时间
//!
//! # 设计说明
//!
//! 调度器在计算 vruntime 时需要多次读取同一批任务的运行时间；为避免在遍历各
//! `TaskControlBlock` 时反复持有 `ProcessControlBlock` 的自旋锁，
//! [`process_tasks`] 先在锁内完成快照（克隆 `Arc` 引用），随后释放锁，
//! 再由调用方在无锁状态下逐个查询每个 TCB 的运行时信息。
//!
//! 所有涉及时间累加的地方均使用 `saturating_add` / `saturating_sub`，
//! 防止在极端情况下（如时钟回退或长时间运行）发生整数溢出。
use alloc::{sync::Arc, vec::Vec};

use crate::{
    task::{ProcessControlBlock, processor::current_task, task_block::TaskControlBlock},
    time::get_time_ns,
};

/// 返回调度器使用的单调递增纳秒时间戳。
///
/// 直接转发底层 `get_time_ns()`，统一为调度模块提供唯一的时间源，
/// 便于未来替换或在测试中 mock 时间。
///
/// # 返回值
///
/// 自系统启动以来经过的纳秒数（单调时钟，不受 NTP 调整影响）。
#[inline]
pub fn monotonic_time_ns() -> u64 {
    get_time_ns()
}

/// 将任务自上次计费点到 `now_ns` 期间消耗的 CPU 时间计入其 TCB。
///
/// 通常在任务被抢占、主动 `yield` 或进入睡眠时调用，用于结束当前运行片段
/// 并将增量时间累加到 `TaskControlBlockInner::cpu_time_ns`。
///
/// # 参数
///
/// - `task`：需要计费的任务控制块引用。
/// - `now_ns`：本次计费截止的纳秒时间戳（通常由调用方在进入调度路径前
///   一次性读取，避免多次系统调用引入误差）。
///
/// # 返回值
///
/// 本次计费的增量纳秒数（`now_ns - runtime_start_ns`）；若时间戳未前进则为 0。
#[inline]
pub fn charge_running_task_until(task: &Arc<TaskControlBlock>, now_ns: u64) -> u64 {
    task.account_runtime_until(now_ns)
}

/// 使用当前单调时间戳对任务进行计费，是 [`charge_running_task_until`] 的便捷封装。
///
/// # 参数
///
/// - `task`：需要计费的任务控制块引用。
///
/// # 返回值
///
/// 本次计费的增量纳秒数。
#[inline]
pub fn charge_running_task(task: &Arc<TaskControlBlock>) -> u64 {
    charge_running_task_until(task, monotonic_time_ns())
}

/// 记录任务本次运行片段的起点时间戳。
///
/// 在任务被调度器选中并即将上 CPU 时调用，将 `now_ns` 写入
/// `TaskControlBlockInner::runtime_start_ns`，作为下次 charge 的基准点。
///
/// # 参数
///
/// - `task`：即将运行的任务控制块引用。
/// - `now_ns`：调度发生时的纳秒时间戳。
#[inline]
pub fn start_task_runtime_slice(task: &Arc<TaskControlBlock>, now_ns: u64) {
    task.begin_runtime_slice(now_ns);
}

/// 查询任务在 `now_ns` 时刻的累计 CPU 时间，包含尚未计费的当前运行片段。
///
/// 若任务当前正在 CPU 上执行（`on_cpu != OFF_CPU`），则在已累计值的基础上
/// 再加上自 `runtime_start_ns` 至 `now_ns` 的增量，确保读数反映实时状态。
///
/// # 参数
///
/// - `task`：目标任务控制块引用。
/// - `now_ns`：查询基准时间戳；调用方应在遍历多个任务前统一读取一次，
///   保证同一批次数据使用相同的时间基准。
///
/// # 返回值
///
/// 任务从创建到 `now_ns` 的累计 CPU 时间（纳秒）。
#[inline]
pub fn task_cpu_time_ns_at(task: &Arc<TaskControlBlock>, now_ns: u64) -> u64 {
    task.cpu_time_total_ns(now_ns)
}

/// 使用当前单调时间戳查询任务的累计 CPU 时间，是 [`task_cpu_time_ns_at`] 的便捷封装。
///
/// # 参数
///
/// - `task`：目标任务控制块引用。
///
/// # 返回值
///
/// 任务到当前时刻的累计 CPU 时间（纳秒）。
#[inline]
pub fn task_cpu_time_ns(task: &Arc<TaskControlBlock>) -> u64 {
    task_cpu_time_ns_at(task, monotonic_time_ns())
}

/// 快照进程的所有存活线程，返回其 TCB 的 `Arc` 引用列表。
///
/// # 设计动机
///
/// 调度器在汇总进程 CPU 时间时需要遍历各 TCB 并分别持有其自旋锁；若在持有
/// PCB 锁的同时再获取 TCB 锁，容易形成锁序倒置死锁。因此本函数的策略是：
///
/// 1. 持有 PCB 锁，仅做浅拷贝（克隆 `Arc<TaskControlBlock>`），耗时极短；
/// 2. 立即释放 PCB 锁（`inner` 在函数末尾随 `MutexGuard` 一同 drop）；
/// 3. 调用方在无锁状态下逐个访问各 TCB。
///
/// # 参数
///
/// - `process`：目标进程控制块引用。
///
/// # 返回值
///
/// 包含所有存活线程 TCB 引用的向量；已退出（槽位为 `None`）的线程不包含在内。
pub fn process_tasks(process: &Arc<ProcessControlBlock>) -> Vec<Arc<TaskControlBlock>> {
    // borrow_mut 在此处获取 PCB 内部自旋锁（名称虽为 mut，但语义为"获取独占访问"）；
    // 返回的 MutexGuard 在 collect() 完成后即离开作用域，锁自动释放。
    let inner = process.borrow_mut();
    inner
        .tasks
        .iter()
        .filter_map(|task| task.as_ref().cloned()) // 过滤已退出（None）的线程槽位
        .collect()
}

/// 通过内部 tid 索引定位进程的某一线程。
///
/// tid 索引是线程在 `ProcessControlBlockInner::tasks` 向量中的下标，
/// 与 Linux 的 tid 不同，仅在内核内部使用。
///
/// # 参数
///
/// - `process`：目标进程控制块引用。
/// - `tid_index`：线程在 `tasks` 向量中的下标。
///
/// # 返回值
///
/// - `Some(Arc<TaskControlBlock>)`：该槽位存在且线程仍存活。
/// - `None`：下标越界，或该槽位的线程已退出。
pub fn process_task_by_index(
    process: &Arc<ProcessControlBlock>,
    tid_index: usize,
) -> Option<Arc<TaskControlBlock>> {
    // 同 process_tasks，持锁期间只做 Arc 克隆，立即释放锁
    let inner = process.borrow_mut();
    inner.tasks.get(tid_index)?.as_ref().cloned()
}

/// 在固定时间基准 `now_ns` 下，查询进程所有线程的累计 CPU 时间之和。
///
/// 先通过 [`process_tasks`] 快照线程列表（释放 PCB 锁），再逐线程查询，
/// 最后用 `saturating_add` 累加，防止多线程长时间运行导致 `u64` 溢出。
///
/// # 参数
///
/// - `process`：目标进程控制块引用。
/// - `now_ns`：统一的查询基准时间戳；调用方应在调用前读取一次并复用，
///   保证各线程的时间读数基于同一时刻，避免因分批读取引入误差。
///
/// # 返回值
///
/// 进程所有存活线程到 `now_ns` 的累计 CPU 时间总和（纳秒）。
pub fn process_cpu_time_ns_at(process: &Arc<ProcessControlBlock>, now_ns: u64) -> u64 {
    let (saved_cpu_ns, tasks) = {
        let inner = process.borrow_mut();
        let tasks = inner
            .tasks
            .iter()
            .filter_map(|task| task.as_ref().cloned())
            .collect::<Vec<_>>();
        (inner.cpu_time_ns, tasks)
    };
    tasks
        .into_iter()
        .map(|task| task_cpu_time_ns_at(&task, now_ns))
        // saturating_add：在极端情况（如进程运行数千年）下防止 u64 回绕为 0
        .fold(saved_cpu_ns, |acc, ns| acc.saturating_add(ns))
}

/// 使用当前单调时间戳查询进程的累计 CPU 时间，是 [`process_cpu_time_ns_at`] 的便捷封装。
///
/// # 参数
///
/// - `process`：目标进程控制块引用。
///
/// # 返回值
///
/// 进程所有存活线程到当前时刻的累计 CPU 时间总和（纳秒）。
pub fn process_cpu_time_ns(process: &Arc<ProcessControlBlock>) -> u64 {
    process_cpu_time_ns_at(process, monotonic_time_ns())
}

/// 查询当前正在 CPU 上执行的任务的累计 CPU 时间，包含本次尚未计费的运行片段。
///
/// 若当前处理器上没有正在运行的任务（如在空闲循环或中断上下文中调用），返回 0。
///
/// # 返回值
///
/// - 当前任务到此刻的累计 CPU 时间（纳秒）。
/// - `0`：当前处理器上无正在运行的任务。
pub fn current_task_cpu_time_ns() -> u64 {
    current_task()
        .map(|task| task_cpu_time_ns(&task))
        .unwrap_or(0) // 无当前任务（如 idle 上下文）时安全返回 0
}
