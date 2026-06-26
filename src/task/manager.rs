use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use lazy_static::*;
use spin::Mutex;

use crate::arch;
use crate::config::MAX_HARTS;
use crate::task::process_block::ProcessControlBlock;
use crate::task::task_block::{TaskControlBlock, TaskStatus};

mod cleanup;
mod diagnostics;
mod fair;
mod pid_map;
mod rt;
mod run_queue;

pub use self::cleanup::{remove_inactive_task, remove_sched_timer_refs, remove_timer};
pub use self::diagnostics::dump_system_state;
pub use self::fair::{
    fair_current_deadline_expired, fair_wakeup_preempts_current_on_hart, record_fair_sleep_lag,
};
pub use self::pid_map::{
    insert_into_pid2process, live_process_uses_net_namespace, pid2process, remove_from_pid2process,
};
pub use self::rt::{account_rt_runtime, rt_bandwidth_throttled};
pub use self::run_queue::TaskManager;

use self::fair::{EnqueueKind, ReadyQueueSlot, task_queue_slot};
use self::rt::{has_ready_rt_count_at_or_above, has_ready_rt_count_higher_than, ready_fair_count};
use self::run_queue::{hart_bit, resolve_enqueue_hart, resolve_wakeup_hart};

/// 轮询分配的下一个 hart 计数器，用于新任务在不同 hart 间实现简单负载均衡
static NEXT_HART: AtomicUsize = AtomicUsize::new(0);
/// 是否已经启用当前 hart 的 mask。
static ONLINE_HART_MASK: AtomicUsize = AtomicUsize::new(0);

pub(super) fn current_time_ns_usize() -> usize {
    crate::time::get_time_ns().min(usize::MAX as u64) as usize
}

/// 让 hart 上线
pub fn mark_hart_online(hart_id: usize) {
    if hart_id < usize::BITS as usize {
        ONLINE_HART_MASK.fetch_or(1usize << hart_id, Ordering::SeqCst);
    }
}

/// hart_mask 的全局包装
pub fn online_hart_mask() -> usize {
    let mask = ONLINE_HART_MASK.load(Ordering::Acquire);
    // 兜底：至少 hart0 存在。
    if mask == 0 { 1 } else { mask }
}

/// 从 start hart 开始轮询，返回第一个在线（已上线）的 hart ID
pub(super) fn pick_online_hart(start: usize) -> usize {
    let mask = online_hart_mask();
    for i in 0..MAX_HARTS {
        let cand = (start + i) % MAX_HARTS;
        if (mask & (1usize << cand)) != 0 {
            return cand;
        }
    }
    0
}

/// 为新任务选择一个负载最轻的在线 hart，返回其 hart_id
pub fn select_hart_for_new_task() -> usize {
    let start = NEXT_HART.fetch_add(1, Ordering::Relaxed) % MAX_HARTS;
    pick_online_hart(start)
}

lazy_static! {
    /// 全局任务管理器；内部按 hart 拆分 runqueue 锁。
    pub static ref TASK_MANAGER: TaskManager = TaskManager::new();
    /// PID 到 PCB 的全局映射表（受 spin::Mutex 保护）
    pub static ref PID2PCB: Mutex<BTreeMap<usize, Arc<ProcessControlBlock>>> =
        Mutex::new(BTreeMap::new());
}

fn enqueue_task(task: Arc<TaskControlBlock>, kind: EnqueueKind) -> Option<(usize, bool)> {
    // 保护就绪队列，避免 timer 中断重入；随后恢复先前的 SIE 状态。
    let prev_sie = arch::disable_interrupts();
    let mask = online_hart_mask();
    let cur = crate::task::processor::hart_id() % MAX_HARTS;
    let hart_id = if kind == EnqueueKind::Wakeup {
        // Linux 唤醒具有 CPU 亲和性：睡眠任务通常会重新入队到上一次运行的 CPU，
        // 除非 affinity 禁止。新建/fork 出来的公平调度工作仍可使用
        // `resolve_enqueue_hart()` 中的负载分散路径。
        resolve_wakeup_hart(&task, cur, mask)
    } else {
        resolve_enqueue_hart(&task, cur, mask)
    };
    let queued = TASK_MANAGER.add(Arc::clone(&task), hart_id, kind);
    arch::restore_interrupts(prev_sie);
    queued.map(|was_empty| (hart_id, was_empty))
}

/// 将新创建的任务加入某个在线 hart 的就绪队列。
///
/// 这对应 Linux `wake_up_new_task()`：公平调度实体以 `ENQUEUE_INITIAL` 入队，
/// 因而获得不同于普通 requeue/wakeup 流量的初始 deadline 放置。
/// 返回 `Some(hart_id)` 表示本次实际入队的目标 hart；`None` 表示任务已在就绪
/// 队列中、未重复入队（调用方据此决定是否触发唤醒抢占）。
pub fn add_task(task: Arc<TaskControlBlock>) -> Option<usize> {
    let local_hart = crate::task::processor::hart_id() % MAX_HARTS;
    let Some((hart_id, was_empty)) = enqueue_task(Arc::clone(&task), EnqueueKind::Initial) else {
        return None;
    };
    // Linux `wake_up_new_task()` 会带 WF_FORK 调用 wakeup_preempt()。公平调度类
    // 会刻意忽略 WF_FORK，而更高调度类仍可抢占。保留这个形态：刚 clone 出来的
    // 公平调度工作线程不应在父任务完成线程组构建前立即打断父任务，但刚变为可运行的
    // RT 任务仍可以抢占公平调度任务。
    if matches!(task_queue_slot(&task), ReadyQueueSlot::Rt(_))
        && crate::task::processor::wakeup_should_preempt_target_hart(&task, hart_id)
    {
        crate::task::processor::request_reschedule_for_wakeup(&task, hart_id);
    } else if local_hart != hart_id && was_empty {
        arch::send_ipi(hart_id);
    }
    Some(hart_id)
}

/// 将刚 yield 或被抢占的任务重新入队。
///
/// 与 `add_task()` 不同，这里不能使用 ENQUEUE_INITIAL 放置；否则 CPU-bound 任务
/// 每个时间片都可能重新获得新任务 deadline 信用。
pub fn requeue_task(task: Arc<TaskControlBlock>) -> Option<usize> {
    let local_hart = crate::task::processor::hart_id() % MAX_HARTS;
    let Some((hart_id, was_empty)) = enqueue_task(task, EnqueueKind::Requeue) else {
        return None;
    };
    if local_hart != hart_id && was_empty {
        arch::send_ipi(hart_id);
    }
    Some(hart_id)
}

#[derive(Default)]
struct WakeupBatch {
    kick_mask: usize,
    resched_mask: usize,
}

impl WakeupBatch {
    fn note_enqueued(&mut self, task: &Arc<TaskControlBlock>, target_hart: usize, was_empty: bool) {
        let local_hart = crate::task::processor::hart_id() % MAX_HARTS;
        if target_hart != local_hart && was_empty {
            self.kick_mask |= hart_bit(target_hart);
        }
        if crate::task::processor::wakeup_should_preempt_target_hart(task, target_hart) {
            self.resched_mask |= hart_bit(target_hart);
        }
    }

    fn flush(&mut self) {
        let resched_mask = self.resched_mask;
        let kick_only_mask = self.kick_mask & !resched_mask;
        self.kick_mask = 0;
        self.resched_mask = 0;

        crate::task::processor::request_reschedule_harts(resched_mask);

        let local_hart = crate::task::processor::hart_id() % MAX_HARTS;
        for target_hart in 0..MAX_HARTS {
            if target_hart != local_hart && (kick_only_mask & hart_bit(target_hart)) != 0 {
                arch::send_ipi(target_hart);
            }
        }
    }
}

fn wakeup_task_with_batch(task: Arc<TaskControlBlock>, batch: &mut WakeupBatch) {
    fn wake_if_blocked(task: Arc<TaskControlBlock>, batch: &mut WakeupBatch) {
        let mut task_inner = task.borrow_mut();
        if task_inner.res.is_none() {
            return;
        }
        if task_inner.task_status == TaskStatus::Blocked {
            if task_inner.cgroup_frozen {
                task_inner.wake_on_cgroup_thaw = true;
                task.wakeup_pending
                    .store(false, core::sync::atomic::Ordering::Release);
                return;
            }
            task_inner.task_status = TaskStatus::Ready;
            task_inner.parked_by_cgroup = false;
            task_inner.wake_on_cgroup_thaw = false;
            task.wakeup_pending
                .store(false, core::sync::atomic::Ordering::Release);
            drop(task_inner);
            if let Some((hart_id, was_empty)) = enqueue_task(Arc::clone(&task), EnqueueKind::Wakeup)
            {
                batch.note_enqueued(&task, hart_id, was_empty);
            }
        }
    }

    // SMP 安全性：如果任务确实仍在某个 hart 上执行，不要直接入队
    // （否则会在同一个内核栈上竞争）。改为标记待处理唤醒，让该 hart
    // 切回 idle 后再把任务入队。
    if task.on_cpu.load(core::sync::atomic::Ordering::Acquire) != TaskControlBlock::OFF_CPU {
        task.wakeup_pending
            .store(true, core::sync::atomic::Ordering::Release);
        if task.on_cpu.load(core::sync::atomic::Ordering::Acquire) == TaskControlBlock::OFF_CPU {
            wake_if_blocked(task, batch);
        }
        return;
    }

    wake_if_blocked(task, batch);
}

/// 在进程调度策略/优先级/nice 值变更后，重新将其所有可运行线程入队到正确的位置
pub fn refresh_process_runqueues(process: &Arc<ProcessControlBlock>) {
    let tasks = {
        let inner = process.borrow_mut();
        inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<alloc::vec::Vec<_>>()
    };
    if tasks.is_empty() {
        return;
    }
    let mut requeued_tasks = alloc::vec::Vec::new();
    let prev_sie = arch::disable_interrupts();
    let cur = crate::task::processor::hart_id() % MAX_HARTS;
    let mask = online_hart_mask();
    for task in tasks {
        if !task
            .in_ready_queue
            .load(core::sync::atomic::Ordering::Acquire)
        {
            continue;
        }
        if TASK_MANAGER.remove(Arc::clone(&task)) == 0 {
            continue;
        }
        let hart_id = resolve_enqueue_hart(&task, cur, mask);
        if TASK_MANAGER
            .add(Arc::clone(&task), hart_id, EnqueueKind::Requeue)
            .is_some()
        {
            requeued_tasks.push((task, hart_id));
        }
    }
    arch::restore_interrupts(prev_sie);

    for (task, hart_id) in requeued_tasks {
        crate::task::processor::request_reschedule_for_wakeup(&task, hart_id);
    }
}

/// 单个任务的调度属性或 affinity 变化后，刷新它的运行队列位置。
pub fn refresh_task_runqueue(task: &Arc<TaskControlBlock>) {
    if !task
        .in_ready_queue
        .load(core::sync::atomic::Ordering::Acquire)
    {
        return;
    }
    let mut requeued_hart = None;
    let prev_sie = arch::disable_interrupts();
    if TASK_MANAGER.remove(Arc::clone(task)) != 0 {
        let cur = crate::task::processor::hart_id() % MAX_HARTS;
        let mask = online_hart_mask();
        let hart_id = resolve_enqueue_hart(task, cur, mask);
        if TASK_MANAGER
            .add(Arc::clone(task), hart_id, EnqueueKind::Requeue)
            .is_some()
        {
            requeued_hart = Some(hart_id);
        }
    }
    arch::restore_interrupts(prev_sie);

    if let Some(hart_id) = requeued_hart {
        crate::task::processor::request_reschedule_for_wakeup(task, hart_id);
    }
}

/// 唤醒一个阻塞中的任务。SMP 安全：如果任务还在其他 hart 上执行，则标记 wakeup_pending 让其自行处理。
pub fn wakeup_task(task: Arc<TaskControlBlock>) {
    let mut batch = WakeupBatch::default();
    wakeup_task_with_batch(task, &mut batch);
    batch.flush();
}

/// `wakeup_task` 的批量版本，用于 Linux 风格的信号扇出和 wake_q 使用者。
/// 它保留每个任务的阻塞/on-cpu 竞态处理，但会把远端 idle kick 和重调度 IPI
/// 合并到最后一次 flush 中。
pub fn wakeup_tasks(tasks: alloc::vec::Vec<Arc<TaskControlBlock>>) {
    let mut batch = WakeupBatch::default();
    for task in tasks {
        wakeup_task_with_batch(task, &mut batch);
    }
    batch.flush();
}

/// 将任务从其所在 hart 的就绪队列中移除（关中断，防止与定时器中断路径竞争）
pub fn remove_task(task: Arc<TaskControlBlock>) {
    let prev_sie = arch::disable_interrupts();
    TASK_MANAGER.remove(task);
    arch::restore_interrupts(prev_sie);
}

/// 调试用：返回指定任务在所有就绪队列中的引用计数（检测重复入队）
pub fn debug_count_task_refs_in_runqueues(task: &Arc<TaskControlBlock>) -> usize {
    let prev_sie = arch::disable_interrupts();
    let count = TASK_MANAGER.debug_count_task_refs(task);
    arch::restore_interrupts(prev_sie);
    count
}

/// 从当前 hart 的就绪队列中取走下一个可运行的任务（RT 优先，其次在 EEVDF 公平组中选择 deadline 最早者）
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id();
    let t = TASK_MANAGER.fetch(hart_id);
    arch::restore_interrupts(prev_sie);
    t
}

/// 返回每个 hart 的就绪队列长度（用于调试和负载均衡）
pub fn ready_queue_lengths() -> alloc::vec::Vec<usize> {
    TASK_MANAGER.ready_queue_lengths()
}

/// 当前系统是否已有可运行任务在等待调度。
pub fn has_ready_tasks() -> bool {
    TASK_MANAGER.has_ready_tasks()
}

/// 当前 hart 上等待运行的公平调度类任务数，不包含当前正在运行的任务。
pub fn fair_ready_task_count() -> usize {
    let hart_id = crate::task::processor::hart_id() % MAX_HARTS;
    ready_fair_count(hart_id)
}

/// 检查当前 hart 上是否有比给定优先级更高的 RT 任务就绪（用于 RT 抢占判断）
pub fn has_ready_rt_higher_than(priority: i32) -> bool {
    let hart_id = crate::task::processor::hart_id();
    has_ready_rt_count_higher_than(hart_id, priority)
}

/// 检查当前 hart 上是否有不低于给定优先级的 RT 任务就绪
pub fn has_ready_rt_at_or_above(priority: i32) -> bool {
    let hart_id = crate::task::processor::hart_id();
    has_ready_rt_count_at_or_above(hart_id, priority)
}

/// 检查所有每 hart RT 队列中是否存在优先级不低于 `priority` 的可运行任务。
///
/// Linux 的 fput/close_files 路径会在昂贵 close 操作之间调用 `cond_resched()`，
/// 它会观察 CPU 的 need-resched 状态。我们的延迟 close 工作可能运行在 idle hart 上，
/// 而 cyclictest RT 线程排队在另一个 hart，因此后台清理应更保守：系统中存在任何
/// 待处理 RT 工作时都要停下。
pub fn has_ready_rt_any_at_or_above(priority: i32) -> bool {
    (0..MAX_HARTS).any(|hart_id| has_ready_rt_count_at_or_above(hart_id, priority))
}
