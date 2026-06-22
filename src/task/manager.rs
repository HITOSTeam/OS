use alloc::collections::binary_heap::BinaryHeap;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use lazy_static::*;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch;
use crate::config::MAX_HARTS;
use crate::debug_config::DEBUG_SCHED;
use crate::fs::legacy_cpu_fair_group;
use crate::task::block_sleep::{TIMERS, TimeWrap};
use crate::task::process_block::ProcessControlBlock;
use crate::task::sched::{
    RT_PRIO_LEVELS, RT_PRIO_MAX, RT_PRIO_MIN, SchedClass, rt_queue_index, sched_class,
};
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use spin::Mutex;

/// 轮询分配的下一个 hart 计数器，用于新任务在不同 hart 间实现简单负载均衡
static NEXT_HART: AtomicUsize = AtomicUsize::new(0);
/// 是否已经启用当前 Hart 的mask
static ONLINE_HART_MASK: AtomicUsize = AtomicUsize::new(0);

/// 让hart 上线
pub fn mark_hart_online(hart_id: usize) {
    if hart_id < usize::BITS as usize {
        ONLINE_HART_MASK.fetch_or(1usize << hart_id, Ordering::SeqCst);
    }
}

/// hart_mask 的全局包装
pub fn online_hart_mask() -> usize {
    let mask = ONLINE_HART_MASK.load(Ordering::Acquire);
    // Fallback: at least hart0 exists.
    if mask == 0 { 1 } else { mask }
}

/// 从 start hart 开始轮询，返回第一个在线（已上线）的 hart ID
fn pick_online_hart(start: usize) -> usize {
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

/// 看门狗（watchdog）系统状态转储：打印所有 hart 的就绪队列长度、每个进程的线程/信号量/互斥锁状态
pub fn dump_system_state() {
    log::warn!("==== [watchdog] system state dump ====");
    // Disable interrupts to prevent deadlock with timer-driven wakeup_task().
    let prev_sie = arch::disable_interrupts();
    let mgr = TASK_MANAGER.lock();
    let total_ready: usize = mgr.ready_queues.iter().map(HartRunQueue::len).sum();
    log::warn!(
        "[watchdog] ready_queues_total_len={} per_hart={:?}",
        total_ready,
        mgr.ready_queues
            .iter()
            .map(HartRunQueue::len)
            .collect::<alloc::vec::Vec<_>>()
    );
    drop(mgr);
    let map = PID2PCB.lock();
    for (pid, pcb) in map.iter() {
        let Some(process_inner) = pcb.try_borrow_mut() else {
            log::warn!("[watchdog] pid={} pcb_lock=BUSY", pid);
            continue;
        };
        log::warn!(
            "[watchdog] pid={} zombie={} tasks_len={} children_len={} sems_len={}",
            pid,
            process_inner.is_zombie,
            process_inner.tasks.len(),
            process_inner.children.len(),
            process_inner.semaphore_list.len()
        );
        // Tasks
        for (tid, t) in process_inner.tasks.iter().enumerate() {
            let Some(tcb) = t else { continue };
            let on_cpu = tcb.on_cpu.load(core::sync::atomic::Ordering::Acquire);
            let in_rq = tcb
                .in_ready_queue
                .load(core::sync::atomic::Ordering::Acquire);
            let wp = tcb
                .wakeup_pending
                .load(core::sync::atomic::Ordering::Acquire);
            let (status, exit_code) = if let Some(g) = tcb.try_borrow_mut() {
                (Some(g.task_status), g.exit_code)
            } else {
                (None, None)
            };
            log::warn!(
                "[watchdog]  tid={} status={:?} on_cpu={} in_rq={} wakeup_pending={} exit_code={:?}",
                tid,
                status,
                on_cpu,
                in_rq,
                wp,
                exit_code
            );
        }
        // Semaphores
        for (sid, sem) in process_inner.semaphore_list.iter().enumerate() {
            let Some(sem) = sem else { continue };
            let Some(guard) = sem.inner.try_lock() else {
                log::warn!("[watchdog]  sem[{}] lock=BUSY", sid);
                continue;
            };
            log::warn!(
                "[watchdog]  sem[{}] count={} waiters={}",
                sid,
                guard.count,
                guard.wait_queue.len()
            );
        }
        // Mutexes
        for (mid, m) in process_inner.mutex_list.iter().enumerate() {
            if m.is_some() {
                log::warn!("[watchdog]  mutex[{}]=Some(..)", mid);
            }
        }
        drop(process_inner);
    }
    drop(map);
    log::warn!("==== [watchdog] end ====");
    arch::restore_interrupts(prev_sie);
}

#[derive(Default)]
struct FairGroupQueue {
    shares: u64,                            // 该 group 的 CPU 时间权重
    vruntime: u128,                         // 虚拟运行时间，用于 CFS 调度决策（值越小越优先）
    tasks: VecDeque<Arc<TaskControlBlock>>, // 属于该 group 的就绪任务队列
}

/// 每个hart 拥有的 运行队列
#[derive(Default)]
struct HartRunQueue {
    rt_queues: alloc::vec::Vec<VecDeque<Arc<TaskControlBlock>>>, // 实时优先级队列（RT FIFO/RR），按优先级分桶
    fair_groups: BTreeMap<u64, FairGroupQueue>, // CFS fair group 集合，key 为 group_id
}

impl HartRunQueue {
    fn new() -> Self {
        Self {
            rt_queues: (0..RT_PRIO_LEVELS).map(|_| VecDeque::new()).collect(),
            fair_groups: BTreeMap::new(),
        }
    }

    /// 该 hart 就绪队列中 fair(CFS) 任务的总数（不含 RT 队列）。
    fn fair_len(&self) -> usize {
        self.fair_groups
            .values()
            .map(|group| group.tasks.len())
            .sum()
    }

    /// 返回该 hart 就绪队列中所有任务的总数（RT + Fair）
    fn len(&self) -> usize {
        self.rt_queues.iter().map(VecDeque::len).sum::<usize>() + self.fair_len()
    }
}

/// 任务入队时的目标槽位：RT 队列（按优先级索引）或 CFS Fair 队列
enum ReadyQueueSlot {
    Rt(usize),
    Fair,
}

/// 根据任务的调度策略和优先级，确定其应放入的就绪队列槽位（RT 或 Fair）

fn task_queue_slot(task: &Arc<TaskControlBlock>) -> ReadyQueueSlot {
    // if getting processblock fails,we set this to fair
    let Some(process) = task.process.upgrade() else {
        return ReadyQueueSlot::Fair;
    };
    let (policy, rt_priority) = {
        let inner = process.borrow_mut();
        (
            inner.scheduling.sched_policy,
            inner.scheduling.sched_priority,
        )
    };
    // according to the policy number,decide the target position
    // FIFO RR 都加入到 RT
    // 其余 FAIR
    match sched_class(policy) {
        Some(SchedClass::Fifo) | Some(SchedClass::Rr) => {
            ReadyQueueSlot::Rt(rt_queue_index(rt_priority))
        }
        Some(SchedClass::Fair) | None => ReadyQueueSlot::Fair,
    }
}

/// 获取任务所属的 fair group ID 及其权重（shares），用于 CFS 调度决策
fn fair_group_id_and_shares(task: &Arc<TaskControlBlock>) -> Option<(u64, u64)> {
    let process = task.process.upgrade()?;
    let tgid = process.getpid();
    let tid_index = task.borrow_mut().res.as_ref()?.tid;
    Some(legacy_cpu_fair_group(tgid, tid_index))
}

/// 任务重新入队时根据已消耗的 CPU 时间累加 group 的 vruntime，实现 CFS 的 CPU 时间记账
/// vrntime 更新函数
fn account_fair_task_enqueue(group: &mut FairGroupQueue, task: &Arc<TaskControlBlock>) {
    const DEFAULT_SHARES: u128 = 1024;
    let mut inner = task.borrow_mut();
    let current_ns = inner.cpu_time_ns;
    let delta_ns = current_ns.saturating_sub(inner.fair_runtime_checkpoint_ns);
    if delta_ns > 0 {
        let shares = u128::from(group.shares.max(1));
        // vruntime += delta_ns * 1024 / shares，即权重越大 vruntime 增长越慢，从而获得更多 CPU
        let scaled = ((u128::from(delta_ns) * DEFAULT_SHARES) / shares).max(1);
        group.vruntime = group.vruntime.saturating_add(scaled);
    }
    inner.fair_runtime_checkpoint_ns = current_ns;
}

/// 全局任务管理器，每个 Hart 维护一个独立就绪队列（包含 RT 和 CFS Fair 两个调度类）
pub struct TaskManager {
    ready_queues: alloc::vec::Vec<HartRunQueue>,
}

/// 决定任务应放入哪个 hart 的就绪队列：优先 affinity 指定的 hart，否则用当前 hart，最后 fallback 到任意在线 hart
fn resolve_enqueue_hart(task: &Arc<TaskControlBlock>, current_hart: usize, mask: usize) -> usize {
    let desired = task.get_cpu_id() % MAX_HARTS;
    if (mask & (1usize << desired)) != 0 {
        desired
    } else if (mask & (1usize << current_hart)) != 0 {
        task.set_cpu_id(current_hart);
        current_hart
    } else {
        let picked = pick_online_hart(0);
        task.set_cpu_id(picked);
        picked
    }
}

/// A Linux-like split runqueue: RT queues + a fair queue.
impl TaskManager {
    /// 为每个 hart 创建一个空就绪队列
    pub fn new() -> Self {
        Self {
            ready_queues: (0..MAX_HARTS).map(|_| HartRunQueue::new()).collect(),
        }
    }
    /// 关键函数
    /// 将任务加入指定 hart 的就绪队列。返回 `Some(true)` 表示入队前该队列为空；
    /// 返回 `None` 表示任务已在就绪队列中，本次没有重复入队。
    /// 使用 `in_ready_queue` 标志防止 SMP 下同一任务被重复入队。
    pub fn add(&mut self, task: Arc<TaskControlBlock>, hart_id: usize) -> Option<bool> {
        // Avoid enqueueing the same task multiple times under SMP.
        if task
            .in_ready_queue
            .swap(true, core::sync::atomic::Ordering::AcqRel)
        {
            return None;
        }
        let hart_rq = &mut self.ready_queues[hart_id];
        let was_empty = hart_rq.len() == 0;
        if DEBUG_SCHED {
            let tid = task
                .borrow_mut()
                .res
                .as_ref()
                .map(|r| r.tid)
                .unwrap_or(usize::MAX);
            log::debug!(
                "[sched] add_task tid={} hart={} ready_queue_len_before={}",
                tid,
                hart_id,
                hart_rq.len()
            );
        }
        match task_queue_slot(&task) {
            ReadyQueueSlot::Rt(idx) => hart_rq.rt_queues[idx].push_back(task),
            ReadyQueueSlot::Fair => {
                let (group_id, shares) = fair_group_id_and_shares(&task).unwrap_or((0, 1024));
                let group = hart_rq.fair_groups.entry(group_id).or_default();
                group.shares = shares.max(1);
                account_fair_task_enqueue(group, &task);
                group.tasks.push_back(task);
            }
        }
        if DEBUG_SCHED {
            log::debug!(
                "[sched] hart={} ready_queue_len_after={}",
                hart_id,
                hart_rq.len()
            );
        }
        Some(was_empty)
    }

    /// 从 RT 队列头部弹出第一个状态为 Ready 的任务，跳过并清理状态已过期的任务
    fn pop_ready_candidate(
        queue: &mut VecDeque<Arc<TaskControlBlock>>,
        hart_id: usize,
    ) -> Option<Arc<TaskControlBlock>> {
        while let Some(candidate) = queue.pop_front() {
            candidate
                .in_ready_queue
                .store(false, core::sync::atomic::Ordering::Release);
            let status = candidate.borrow_mut().task_status;
            if status == TaskStatus::Ready {
                return Some(candidate);
            }
            if DEBUG_SCHED {
                let tid = candidate
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                log::debug!(
                    "[sched] drop stale entry tid={} hart={} status={:?} remaining_len={}",
                    tid,
                    hart_id,
                    status,
                    queue.len()
                );
            }
        }
        None
    }

    /// 检查 fair group 队列头部的任务状态，跳过并清理状态已过期的条目（不弹出，仅清理脏头部）
    fn prune_fair_group_front(
        queue: &mut VecDeque<Arc<TaskControlBlock>>,
        hart_id: usize,
    ) -> Option<Arc<TaskControlBlock>> {
        while let Some(candidate) = queue.front().cloned() {
            let status = candidate.borrow_mut().task_status;
            if status == TaskStatus::Ready {
                return Some(candidate);
            }
            queue.pop_front();
            candidate
                .in_ready_queue
                .store(false, core::sync::atomic::Ordering::Release);
            if DEBUG_SCHED {
                let tid = candidate
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                log::debug!(
                    "[sched] drop stale fair entry tid={} hart={} status={:?} remaining_len={}",
                    tid,
                    hart_id,
                    status,
                    queue.len()
                );
            }
        }
        None
    }

    /// 从指定 hart 取走下一个可运行的任务：RT 优先级队列优先，CFS Fair group 选 vruntime 最小的 group
    pub fn fetch(&mut self, hart_id: usize) -> Option<Arc<TaskControlBlock>> {
        // Skip stale entries: under SMP, bugs or races can temporarily leave
        // non-ready tasks (Blocked/Running) in the ready queue. Never schedule them.
        let t = {
            let rq = &mut self.ready_queues[hart_id];
            let mut picked = None;
            for rtq in rq.rt_queues.iter_mut() {
                if let Some(task) = Self::pop_ready_candidate(rtq, hart_id) {
                    picked = Some(task);
                    break;
                }
            }
            if picked.is_none() {
                let group_ids = rq
                    .fair_groups
                    .keys()
                    .copied()
                    .collect::<alloc::vec::Vec<_>>();
                let mut best_group = None;
                let mut best_vruntime = u128::MAX;
                let mut empty_groups = alloc::vec::Vec::new();
                for group_id in group_ids {
                    let Some(group) = rq.fair_groups.get_mut(&group_id) else {
                        continue;
                    };
                    if Self::prune_fair_group_front(&mut group.tasks, hart_id).is_none() {
                        if group.tasks.is_empty() {
                            empty_groups.push(group_id);
                        }
                        continue;
                    }
                    // 选择 vruntime 最小的 group（即获得 CPU 时间最少的 group），实现 CFS 公平调度
                    if group.vruntime < best_vruntime {
                        best_vruntime = group.vruntime;
                        best_group = Some(group_id);
                    }
                }
                for group_id in empty_groups {
                    rq.fair_groups.remove(&group_id);
                }
                if let Some(group_id) = best_group {
                    if let Some(group) = rq.fair_groups.get_mut(&group_id) {
                        if let Some(task) = group.tasks.pop_front() {
                            task.in_ready_queue
                                .store(false, core::sync::atomic::Ordering::Release);
                            {
                                let mut inner = task.borrow_mut();
                                inner.fair_runtime_checkpoint_ns = inner.cpu_time_ns;
                            }
                            if group.tasks.is_empty() {
                                rq.fair_groups.remove(&group_id);
                            }
                            picked = Some(task);
                        }
                    }
                }
            }
            picked
        };
        if DEBUG_SCHED {
            if let Some(ref task) = t {
                let tid = task
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                log::debug!(
                    "[sched] hart={} fetch_task -> Some(tid={}) remaining_len={}",
                    hart_id,
                    tid,
                    self.ready_queues[hart_id].len()
                );
            }
        }
        t
    }
    /// 从所有 hart 的就绪队列中移除指定任务（同时清理 RT 和 Fair 队列中可能存在的重复条目）
    pub fn remove(&mut self, task: Arc<TaskControlBlock>) {
        let mut removed = 0usize;
        for rq in self.ready_queues.iter_mut() {
            for q in rq.rt_queues.iter_mut() {
                let before = q.len();
                q.retain(|t| !Arc::ptr_eq(t, &task));
                removed = removed.saturating_add(before.saturating_sub(q.len()));
            }
            let fair_group_ids = rq
                .fair_groups
                .keys()
                .copied()
                .collect::<alloc::vec::Vec<_>>();
            for group_id in fair_group_ids {
                let mut should_remove_group = false;
                if let Some(group) = rq.fair_groups.get_mut(&group_id) {
                    let before = group.tasks.len();
                    group.tasks.retain(|t| !Arc::ptr_eq(t, &task));
                    removed = removed.saturating_add(before.saturating_sub(group.tasks.len()));
                    should_remove_group = group.tasks.is_empty();
                }
                if should_remove_group {
                    rq.fair_groups.remove(&group_id);
                }
            }
        }
        if crate::debug_config::DEBUG_TASK_LIFECYCLE && removed > 1 {
            let tid = task
                .borrow_mut()
                .res
                .as_ref()
                .map(|r| r.tid)
                .unwrap_or(usize::MAX);
            crate::println!("[sched-remove] tid={} removed_dup_entries={}", tid, removed);
        }
        task.in_ready_queue
            .store(false, core::sync::atomic::Ordering::Release);
    }

    /// 返回每个 hart 的就绪队列长度（用于调试和负载均衡）
    pub fn ready_queue_lengths(&self) -> alloc::vec::Vec<usize> {
        self.ready_queues.iter().map(HartRunQueue::len).collect()
    }

    /// 返回指定 hart 上等待运行的 fair-class 任务数。
    fn ready_fair_task_count(&self, hart_id: usize) -> usize {
        self.ready_queues
            .get(hart_id)
            .map(HartRunQueue::fair_len)
            .unwrap_or(0)
    }

    /// 调试用：统计指定任务在所有就绪队列中出现的引用次数（用于检测重复入队等异常）
    fn debug_count_task_refs(&self, task: &Arc<TaskControlBlock>) -> usize {
        self.ready_queues
            .iter()
            .map(|rq| {
                rq.rt_queues
                    .iter()
                    .map(|q| q.iter().filter(|t| Arc::ptr_eq(t, task)).count())
                    .sum::<usize>()
                    + rq.fair_groups
                        .values()
                        .map(|group| group.tasks.iter().filter(|t| Arc::ptr_eq(t, task)).count())
                        .sum::<usize>()
            })
            .sum()
    }

    /// 检查指定 hart 上是否有比给定优先级更高的 RT 任务就绪（用于 RT 抢占判断）
    fn has_ready_rt_higher_than(&self, hart_id: usize, priority: i32) -> bool {
        let rq = &self.ready_queues[hart_id];
        let prio = priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX);
        let idx = rt_queue_index(prio);
        rq.rt_queues[..idx].iter().any(|q| !q.is_empty())
    }

    /// 检查指定 hart 上是否有不低于给定优先级的 RT 任务就绪
    fn has_ready_rt_at_or_above(&self, hart_id: usize, priority: i32) -> bool {
        let rq = &self.ready_queues[hart_id];
        let prio = priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX);
        let idx = rt_queue_index(prio);
        rq.rt_queues[..=idx].iter().any(|q| !q.is_empty())
    }
}

lazy_static! {
    /// 全局任务管理器（受 spin::Mutex 保护，中断安全的加锁）
    pub static ref TASK_MANAGER: Mutex<TaskManager> = Mutex::new(TaskManager::new());
    /// PID 到 PCB 的全局映射表（受 spin::Mutex 保护）
    pub static ref PID2PCB: Mutex<BTreeMap<usize, Arc<ProcessControlBlock>>> =
        Mutex::new(BTreeMap::new());
}

/// 将任务加入某个在线 hart 的就绪队列。目标 hart 空闲时（wfi）发送 IPI 唤醒之。
/// 类似 Linux wake_up_process：优先使用 task->cpu 指定的 hart，否则放当前 hart。
/// 返回 `Some(hart_id)` 表示本次实际入队的目标 hart；`None` 表示任务已在就绪
/// 队列中、未重复入队（调用方据此决定是否触发唤醒抢占）。
pub fn add_task(task: Arc<TaskControlBlock>) -> Option<usize> {
    // Protect the ready queue from timer interrupt re-entrancy, but restore the previous SIE state.
    let prev_sie = arch::disable_interrupts();
    let mask = online_hart_mask();
    let cur = crate::task::processor::hart_id() % MAX_HARTS;
    let hart_id = resolve_enqueue_hart(&task, cur, mask);
    let queued = TASK_MANAGER.lock().add(Arc::clone(&task), hart_id);
    // Linux-style: if we queued to a remote hart, kick it out of `wfi` via IPI.
    // For fork storms this avoids flooding remote harts with redundant IPIs when
    // their runqueue is already non-empty.
    if cur < MAX_HARTS && cur != hart_id && queued == Some(true) {
        arch::send_ipi(hart_id);
    }
    arch::restore_interrupts(prev_sie);
    queued.map(|_| hart_id)
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
    let prev_sie = arch::disable_interrupts();
    let cur = crate::task::processor::hart_id() % MAX_HARTS;
    let mask = online_hart_mask();
    let mut mgr = TASK_MANAGER.lock();
    for task in tasks {
        if !task
            .in_ready_queue
            .load(core::sync::atomic::Ordering::Acquire)
        {
            continue;
        }
        mgr.remove(Arc::clone(&task));
        let hart_id = resolve_enqueue_hart(&task, cur, mask);
        let _ = mgr.add(task, hart_id);
    }
    arch::restore_interrupts(prev_sie);
}

/// 唤醒一个阻塞中的任务。SMP 安全：如果任务还在其他 hart 上执行，则标记 wakeup_pending 让其自行处理。
pub fn wakeup_task(task: Arc<TaskControlBlock>) {
    // 尝试将阻塞任务转为 Ready 并加入就绪队列（cgroup 冻结时推迟唤醒）
    fn wake_if_blocked(task: Arc<TaskControlBlock>) {
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
            // 入队成功后，若被唤醒任务应抢占目标 hart 的当前任务，则请求一次
            // 返回用户态前的重调度（仅当 add_task 返回 Some、即确实入队时）。
            if let Some(hart_id) = add_task(Arc::clone(&task)) {
                crate::task::processor::request_reschedule_for_wakeup(&task, hart_id);
            }
        }
    }

    // SMP safety: if the task is truly still executing on some hart, do not enqueue it
    // (it would race on the same kernel stack). Instead mark a pending wakeup and let
    // that hart enqueue the task after it has switched back to idle.
    //
    // Important: handle the tiny window where a waker observes `on_cpu != OFF_CPU`,
    // sets `wakeup_pending`, but the task clears `on_cpu` and checks `wakeup_pending`
    // just before this store becomes visible. To avoid losing the wakeup, re-check
    // `on_cpu` after setting the flag and enqueue immediately if it is already off-cpu.
    //
    // 中文说明：SMP 下如果目标任务仍在其他核上执行，直接入队会导致内核栈竞争。
    // 因此设置 wakeup_pending 标志，让那个核上正在退出的任务自行入队。
    // 但存在竞态窗口：设置标志前任务刚好离开 CPU，所以设置后要再检查一次 on_cpu。
    if task.on_cpu.load(core::sync::atomic::Ordering::Acquire) != TaskControlBlock::OFF_CPU {
        task.wakeup_pending
            .store(true, core::sync::atomic::Ordering::Release);
        if task.on_cpu.load(core::sync::atomic::Ordering::Acquire) == TaskControlBlock::OFF_CPU {
            wake_if_blocked(task);
        }
        return;
    }

    wake_if_blocked(task);
}

/// 将任务从全局就绪队列中移除（关中断，防止与定时器中断路径竞争）
pub fn remove_task(task: Arc<TaskControlBlock>) {
    let prev_sie = arch::disable_interrupts();
    TASK_MANAGER.lock().remove(task);
    arch::restore_interrupts(prev_sie);
}

/// 调试用：返回指定任务在所有就绪队列中的引用计数（检测重复入队）
pub fn debug_count_task_refs_in_runqueues(task: &Arc<TaskControlBlock>) -> usize {
    let prev_sie = arch::disable_interrupts();
    let count = TASK_MANAGER.lock().debug_count_task_refs(task);
    arch::restore_interrupts(prev_sie);
    count
}

/// 从当前 hart 的就绪队列中取走下一个可运行的任务（RT 优先，其次 CFS fair group 中选 vruntime 最小的）
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id();
    let t = TASK_MANAGER.lock().fetch(hart_id);
    arch::restore_interrupts(prev_sie);
    t
}

/// 当前 hart 上等待运行的 fair-class 任务数，不包含当前正在运行的任务。
pub fn fair_ready_task_count() -> usize {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id() % MAX_HARTS;
    let count = TASK_MANAGER.lock().ready_fair_task_count(hart_id);
    arch::restore_interrupts(prev_sie);
    count
}

/// 检查当前 hart 上是否有比给定优先级更高的 RT 任务就绪（用于 RT 抢占判断）
pub fn has_ready_rt_higher_than(priority: i32) -> bool {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id();
    let ready = TASK_MANAGER
        .lock()
        .has_ready_rt_higher_than(hart_id, priority);
    arch::restore_interrupts(prev_sie);
    ready
}

/// 检查当前 hart 上是否有不低于给定优先级的 RT 任务就绪
pub fn has_ready_rt_at_or_above(priority: i32) -> bool {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id();
    let ready = TASK_MANAGER
        .lock()
        .has_ready_rt_at_or_above(hart_id, priority);
    arch::restore_interrupts(prev_sie);
    ready
}

/// 根据 PID 从全局映射表中查询对应的进程控制块
pub fn pid2process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let map = PID2PCB.lock();
    map.get(&pid).map(Arc::clone)
}

/// 将进程插入全局 PID->PCB 映射表，当 map 大小达到 2 的幂时输出调试日志
pub fn insert_into_pid2process(pid: usize, process: Arc<ProcessControlBlock>) {
    let mut map = PID2PCB.lock();
    map.insert(pid, process);
    let len = map.len();
    if crate::debug_config::DEBUG_PID_MAP && len >= 64 && (len & (len - 1)) == 0 {
        crate::println!("[pid-debug] insert pid={} map_len={}", pid, len);
    }
}

/// 从全局 PID->PCB 映射表中移除指定 PID，找不到时输出警告
pub fn remove_from_pid2process(pid: usize) {
    let mut map = PID2PCB.lock();
    if map.remove(&pid).is_none() {
        log::warn!(
            "remove_from_pid2process: pid {} not found (already reaped?)",
            pid
        );
        return;
    }
    let len = map.len();
    if crate::debug_config::DEBUG_PID_MAP && len >= 64 && (len & (len - 1)) == 0 {
        crate::println!("[pid-debug] remove pid={} map_len={}", pid, len);
    }
}

/// Return whether any non-zombie process still owns the given network namespace.
///
/// Zombie PCBs stay in `PID2PCB` until wait4() reaps them, but their fd tables
/// and address spaces have already been released.  Network namespace teardown
/// must therefore ignore zombies and only treat live processes as owners.
pub fn live_process_uses_net_namespace(ns_id: usize) -> bool {
    let map = PID2PCB.lock();
    for process in map.values() {
        let Some(inner) = process.try_borrow_mut() else {
            // A contended PCB may be in the middle of clone/exit/setns.  Keep
            // the namespace alive rather than racing teardown against it.
            return true;
        };
        if !inner.is_zombie && inner.net_ns_id == ns_id {
            return true;
        }
    }
    false
}

/// 从全局定时器堆中移除所有属于指定任务的定时器（任务退出时清理）
pub fn remove_timer(task: Arc<TaskControlBlock>) {
    let mut timers = TIMERS.lock();
    let mut temp = BinaryHeap::<TimeWrap>::new();
    for condvar in timers.drain() {
        if Arc::as_ptr(&task) != Arc::as_ptr(&condvar.task) {
            temp.push(condvar);
        }
    }
    timers.clear();
    timers.append(&mut temp);
}

/// 完整清理一个不再活跃的任务：从 futex 等待队列、条件变量等待队列、定时器堆和就绪队列中移除
pub fn remove_inactive_task(task: Arc<TaskControlBlock>) {
    // 这里可能会加入 todo
    crate::syscall::futex::remove_futex_waiters(&task);
    crate::task::process_block::remove_task_from_wait_queues(&task);
    remove_timer(task.clone());
    remove_task(task.clone());
}
