use alloc::collections::VecDeque;
use alloc::sync::Arc;

use spin::Mutex;

use crate::config::MAX_HARTS;
use crate::debug_config::DEBUG_SCHED;
use crate::task::task_block::{TaskControlBlock, TaskStatus};

use super::TASK_MANAGER;
use super::current_time_ns_usize;
use super::fair::{
    EnqueueKind, FairGroupQueue, HartRunQueue, ReadyQueueSlot, current_fair_entity_for_group,
    fair_group_id_and_shares, fair_nice_weight, fair_task_id, place_fair_task_entity,
    task_queue_slot,
};
use super::pick_online_hart;
use super::rt::{
    dec_ready_fair_count, dec_ready_rt_count, inc_ready_fair_count, inc_ready_rt_count,
    rt_bandwidth_throttled,
};

/// 全局任务管理器，每个 hart 维护一个独立就绪队列（包含 RT 和 EEVDF 公平两个调度类）
pub struct TaskManager {
    pub(super) ready_queues: alloc::vec::Vec<Mutex<HartRunQueue>>,
}

/// 决定任务应放入哪个 hart 的就绪队列：优先使用 affinity 指定的 hart，否则用当前 hart，最后回退到任意在线 hart
pub(super) fn resolve_enqueue_hart(
    task: &Arc<TaskControlBlock>,
    current_hart: usize,
    mask: usize,
    _kind: EnqueueKind,
) -> usize {
    let affinity_mask = {
        let inner = task.borrow_mut();
        if inner.scheduling.cpu_affinity_mask == 0 {
            mask
        } else {
            inner.scheduling.cpu_affinity_mask & mask
        }
    };
    let allowed_mask = if affinity_mask == 0 {
        mask
    } else {
        affinity_mask
    };
    if matches!(task_queue_slot(task), ReadyQueueSlot::Fair) {
        // Linux can correct fork placement through sched-domain balancing.
        // Until this scheduler has an equivalent periodic balancer, pinning
        // every new fair task to the forking CPU leaves parallel compiler
        // children concentrated on a few harts. Use the same least-loaded
        // placement as fair wakeups while still respecting affinity.
        let picked = pick_least_loaded_hart_from_mask(allowed_mask);
        task.set_cpu_id(picked);
        return picked;
    }
    let desired = task.get_cpu_id() % MAX_HARTS;
    if (allowed_mask & (1usize << desired)) != 0 {
        desired
    } else if (allowed_mask & (1usize << current_hart)) != 0 {
        task.set_cpu_id(current_hart);
        current_hart
    } else {
        let picked = pick_online_hart_from_mask(allowed_mask);
        task.set_cpu_id(picked);
        picked
    }
}

pub(super) fn pick_least_loaded_hart_from_mask(mask: usize) -> usize {
    let mut best_hart = None;
    let mut best_len = usize::MAX;
    for hart_id in 0..MAX_HARTS {
        if (mask & (1usize << hart_id)) == 0 {
            continue;
        }
        // A hart with an empty runqueue may still be executing a CPU-bound
        // task. Counting only queued entities repeatedly selects the first
        // such hart and defeats SMP distribution. Linux's rq load includes
        // the current entity; approximate that here without blocking on a
        // remote processor lock.
        let running = usize::from(
            crate::task::processor::current_task_on_hart(hart_id)
                .is_some_and(|task| task.get_cpu_id() == hart_id),
        );
        let len = TASK_MANAGER.ready_queues[hart_id]
            .lock()
            .len()
            .saturating_add(running);
        if len < best_len {
            best_len = len;
            best_hart = Some(hart_id);
        }
    }
    best_hart.unwrap_or_else(|| pick_online_hart(0))
}

pub(super) fn pick_online_hart_from_mask(mask: usize) -> usize {
    for hart_id in 0..MAX_HARTS {
        if (mask & (1usize << hart_id)) != 0 {
            return hart_id;
        }
    }
    pick_online_hart(0)
}

pub(super) fn hart_bit(hart_id: usize) -> usize {
    if hart_id < usize::BITS as usize {
        1usize << hart_id
    } else {
        0
    }
}

pub(super) fn allowed_hart_mask_for_task(
    task: &Arc<TaskControlBlock>,
    online_mask: usize,
) -> usize {
    let affinity_mask = {
        let inner = task.borrow_mut();
        if inner.scheduling.cpu_affinity_mask == 0 {
            online_mask
        } else {
            inner.scheduling.cpu_affinity_mask & online_mask
        }
    };
    if affinity_mask == 0 {
        online_mask
    } else {
        affinity_mask
    }
}

pub(super) fn resolve_wakeup_hart(
    task: &Arc<TaskControlBlock>,
    current_hart: usize,
    mask: usize,
) -> usize {
    let allowed_mask = allowed_hart_mask_for_task(task, mask);
    let previous = task.get_cpu_id() % MAX_HARTS;
    if matches!(task_queue_slot(task), ReadyQueueSlot::Fair) {
        // Linux 的 fair 唤醒放置可能会从 wake-affine 回退到调度域内的最空闲 CPU 搜索。
        // 在完整建模 domain/idle-sibling 逻辑之前，保留已经验证过的负载分散路径：
        // cyclictest worker 初始化不能被粘在 hackbench-heavy CPU 后面。
        let picked = pick_least_loaded_hart_from_mask(allowed_mask);
        task.set_cpu_id(picked);
        return picked;
    }
    if (allowed_mask & hart_bit(previous)) != 0 {
        return previous;
    }
    if (allowed_mask & hart_bit(current_hart)) != 0 {
        task.set_cpu_id(current_hart);
        return current_hart;
    }
    let picked = pick_online_hart_from_mask(allowed_mask);
    task.set_cpu_id(picked);
    picked
}

pub(super) fn resolve_sync_wakeup_hart(
    task: &Arc<TaskControlBlock>,
    source_hart: usize,
    mask: usize,
) -> usize {
    let allowed_mask = allowed_hart_mask_for_task(task, mask);
    if matches!(task_queue_slot(task), ReadyQueueSlot::Fair) {
        // Linux WF_SYNC biases a wakee toward the waker CPU because the waker is
        // expected to sleep or hand off control soon. Keep this limited to
        // explicit sync wakeups; ordinary fair I/O wakeups still use the
        // load-spreading path above.
        if (allowed_mask & hart_bit(source_hart)) != 0 {
            task.set_cpu_id(source_hart);
            return source_hart;
        }
        let previous = task.get_cpu_id() % MAX_HARTS;
        if (allowed_mask & hart_bit(previous)) != 0 {
            return previous;
        }
        let picked = pick_online_hart_from_mask(allowed_mask);
        task.set_cpu_id(picked);
        return picked;
    }
    resolve_wakeup_hart(task, source_hart, mask)
}

/// Linux 风格的拆分运行队列：RT 队列 + 公平队列。
impl TaskManager {
    /// 为每个 hart 创建一个空就绪队列
    pub fn new() -> Self {
        Self {
            ready_queues: (0..MAX_HARTS)
                .map(|_| Mutex::new(HartRunQueue::new()))
                .collect(),
        }
    }
    /// 关键函数
    /// 将任务加入指定 hart 的就绪队列。返回 `Some(true)` 表示入队前该队列为空；
    /// 返回 `None` 表示任务已在就绪队列中，本次没有重复入队。
    /// 使用 `ready_queue_hart` 防止 SMP 下同一任务被重复入队。
    pub(super) fn add(
        &self,
        task: Arc<TaskControlBlock>,
        hart_id: usize,
        kind: EnqueueKind,
    ) -> Option<bool> {
        // 避免 SMP 下同一个任务被重复入队。
        if task
            .ready_queue_hart
            .compare_exchange(
                TaskControlBlock::OFF_CPU,
                hart_id,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        task.set_cpu_id(hart_id);
        let mut hart_rq = self.ready_queues[hart_id].lock();
        if task
            .ready_queue_hart
            .load(core::sync::atomic::Ordering::Acquire)
            != hart_id
        {
            // The owner that changed ready_queue_hart also owns publication
            // of in_ready_queue.  Clearing it here could race with a new add
            // that has already inserted the task on another hart.
            return None;
        }
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
            ReadyQueueSlot::Rt(idx) => {
                hart_rq.rt_queues[idx].push_back(Arc::clone(&task));
                inc_ready_rt_count(hart_id, idx);
            }
            ReadyQueueSlot::Fair => {
                let (group_id, shares) = fair_group_id_and_shares(&task);
                let min_vruntime = hart_rq.min_fair_vruntime;
                hart_rq.unlink_fair_group(group_id);
                let group = hart_rq
                    .fair_groups
                    .entry(group_id)
                    .or_insert_with(|| FairGroupQueue::new(min_vruntime));
                group.shares = shares.max(1);
                let now_ns = current_time_ns_usize() as u64;
                let current_entity = current_fair_entity_for_group(hart_id, group_id, now_ns);
                let (task_vruntime, deadline) =
                    place_fair_task_entity(group, &task, kind, current_entity);
                let weight = {
                    let inner = task.borrow_mut();
                    fair_nice_weight(inner.nice)
                };
                let task_id = fair_task_id(&task);
                group.insert_task(task_id, Arc::clone(&task), task_vruntime, deadline, weight);
                hart_rq.relink_fair_group_if_runnable(group_id);
                inc_ready_fair_count(hart_id);
            }
        }
        // Publish the boolean only after the entity is physically present in
        // the locked runqueue.  Refresh/removal code can now distinguish a
        // claimed marker from a completed insertion instead of canceling the
        // add in the CAS-to-rq-lock window.
        task.in_ready_queue
            .store(true, core::sync::atomic::Ordering::Release);
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
    fn pop_ready_rt_candidate(
        queue: &mut VecDeque<Arc<TaskControlBlock>>,
        hart_id: usize,
        rt_idx: usize,
    ) -> Option<Arc<TaskControlBlock>> {
        while let Some(candidate) = queue.pop_front() {
            dec_ready_rt_count(hart_id, rt_idx);
            if candidate
                .ready_queue_hart
                .load(core::sync::atomic::Ordering::Acquire)
                != hart_id
            {
                continue;
            }
            // Publish OFF only after the physical queue entry and its boolean
            // have both been cleared while the owning rq lock is held.  A new
            // add on another hart may claim OFF immediately afterwards.
            candidate
                .in_ready_queue
                .store(false, core::sync::atomic::Ordering::Release);
            let released = candidate
                .ready_queue_hart
                .compare_exchange(
                    hart_id,
                    TaskControlBlock::OFF_CPU,
                    core::sync::atomic::Ordering::Release,
                    core::sync::atomic::Ordering::Acquire,
                )
                .is_ok();
            debug_assert!(released, "rq ownership changed while its lock was held");
            if !released {
                continue;
            }
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

    ///使用紧凑的 EEVDF 可选资格规则，从一个组中挑选公平调度任务。
    ///
    /// Linux `pick_eevdf()` 会先查找具备可选资格的实体，然后才回退到当前/最左选择。
    /// 我们的 per-group 队列简单得多，但在 fork-heavy 压力下同样需要这个规则：
    /// `vruntime` 超过组虚拟时间的实体，不应仅因 deadline 排在前面就遮住
    /// 具备可选资格的新可运行工作线程。
    /// tldr:
    /// 为hart 选择任务,同时移除所有非法的 group 内任务
    fn prune_fair_group_front(group: &mut FairGroupQueue, hart_id: usize) -> Option<u64> {
        // 只有不足平均 的 才有资格 加入,
        let eligible_vruntime = group.avg_task_vruntime().unwrap_or(group.min_task_vruntime);
        loop {
            // task order 按照 deadline ,runtime 顺序排列
            // deadline 先行
            let Some((deadline, vruntime, task_id)) = group.task_order.iter().next().copied()
            else {
                return None;
            };
            let Some(entity) = group.tasks.get(&task_id) else {
                group.task_order.remove(&(deadline, vruntime, task_id));
                continue;
            };
            // 可能的防御
            if entity.vruntime != vruntime || entity.deadline != deadline {
                group.task_order.remove(&(deadline, vruntime, task_id));
                group
                    .task_order
                    .insert((entity.deadline, entity.vruntime, task_id));
                continue;
            }

            let candidate = Arc::clone(&entity.task);
            let status = candidate.borrow_mut().task_status;
            let queued_here = candidate
                .ready_queue_hart
                .load(core::sync::atomic::Ordering::Acquire)
                == hart_id;
            if queued_here && status == TaskStatus::Ready {
                if entity.vruntime <= eligible_vruntime {
                    //deadline 已经是最小的了，task_order保证
                    return Some(task_id);
                }
                // 如果默认最优选择不行，那就逐个遍历。Linux 的
                // pick_eevdf() 会从树中寻找 eligible 且 deadline 最早的实体；
                // 这里没有 rb-tree 增强索引，不能用固定扫描窗口截断，否则
                // hackbench 这类数百实体负载会把刚唤醒/刚创建的短控制任务
                // 挡在窗口外。
                let mut fallback = Some((entity.vruntime, task_id));
                for (deadline, vruntime, task_id) in group.task_order.iter().copied().skip(1) {
                    let Some(entity) = group.tasks.get(&task_id) else {
                        continue;
                    };
                    if entity.vruntime != vruntime || entity.deadline != deadline {
                        continue;
                    }
                    let candidate = Arc::clone(&entity.task);
                    let status = candidate.borrow_mut().task_status;
                    let queued_here = candidate
                        .ready_queue_hart
                        .load(core::sync::atomic::Ordering::Acquire)
                        == hart_id;
                    if queued_here && status == TaskStatus::Ready {
                        if entity.vruntime <= eligible_vruntime {
                            return Some(task_id);
                        }
                        if fallback
                            .map(|(fallback_vruntime, _)| entity.vruntime < fallback_vruntime)
                            .unwrap_or(true)
                        {
                            fallback = Some((entity.vruntime, task_id));
                        }
                    }
                }
                return fallback.map(|(_, task_id)| task_id);
            }

            /// 这个任务不对，既没有准备好，也不在我们的hart上
            let _ = group.unlink_task(task_id);
            // 清理计数
            dec_ready_fair_count(hart_id);
            // 如果 没有就绪，释放任务
            if queued_here {
                candidate
                    .in_ready_queue
                    .store(false, core::sync::atomic::Ordering::Release);
                let released = candidate.ready_queue_hart.compare_exchange(
                    hart_id,
                    TaskControlBlock::OFF_CPU,
                    core::sync::atomic::Ordering::Release,
                    core::sync::atomic::Ordering::Acquire,
                );
                debug_assert!(
                    released.is_ok(),
                    "rq ownership changed while its lock was held"
                );
            }
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
                    group.len()
                );
            }
        }
    }

    /// 弹出就绪任务,按照EEVDF
    fn pop_ready_fair_candidate(
        rq: &mut HartRunQueue,
        hart_id: usize,
    ) -> Option<Arc<TaskControlBlock>> {
        loop {
            // 先弹出对应的组
            let Some((indexed_vruntime, group_id)) = rq.fair_order.iter().next().copied() else {
                return None;
            };
            rq.fair_order.remove(&(indexed_vruntime, group_id));

            let mut should_remove_group = false;
            let mut should_relink_group = false;
            let task = {
                let Some(group) = rq.fair_groups.get_mut(&group_id) else {
                    continue;
                };
                if group.vruntime != indexed_vruntime {
                    // 对陈旧索引项做防御性修复。正常入队/删除路径会让该索引与
                    // group.vruntime 同步更新。
                    should_relink_group = !group.is_empty();
                    None
                } else {
                    // 弹出组之后，从组中选择任务了
                    match Self::prune_fair_group_front(group, hart_id) {
                        Some(task_id) => {
                            let entity = group.unlink_task(task_id);
                            if let Some(entity) = entity {
                                dec_ready_fair_count(hart_id);
                                group.min_task_vruntime =
                                    group.min_task_vruntime.max(entity.vruntime);
                                rq.min_fair_vruntime = rq.min_fair_vruntime.max(group.vruntime);
                                should_remove_group = group.is_empty();
                                should_relink_group = !group.is_empty();
                                Some(entity.task)
                            } else {
                                should_remove_group = group.is_empty();
                                should_relink_group = !group.is_empty();
                                None
                            }
                        }
                        None => {
                            should_remove_group = group.is_empty();
                            should_relink_group = !group.is_empty();
                            None
                        }
                    }
                }
            };
            if should_remove_group {
                rq.fair_groups.remove(&group_id);
            } else if should_relink_group {
                rq.relink_fair_group_if_runnable(group_id);
            }
            let Some(task) = task else {
                continue;
            };
            if task
                .ready_queue_hart
                .load(core::sync::atomic::Ordering::Acquire)
                != hart_id
            {
                continue;
            }
            task.in_ready_queue
                .store(false, core::sync::atomic::Ordering::Release);
            let released = task
                .ready_queue_hart
                .compare_exchange(
                    hart_id,
                    TaskControlBlock::OFF_CPU,
                    core::sync::atomic::Ordering::Release,
                    core::sync::atomic::Ordering::Acquire,
                )
                .is_ok();
            debug_assert!(released, "rq ownership changed while its lock was held");
            if !released {
                continue;
            }
            {
                let mut inner = task.borrow_mut();
                inner.fair_runtime_checkpoint_ns = inner.cpu_time_ns;
            }
            return Some(task);
        }
    }

    /// 从指定 hart 取走下一个可运行的任务：RT 优先级队列优先，EEVDF 公平组选择 vruntime 最小的组
    pub fn fetch(&self, hart_id: usize) -> Option<Arc<TaskControlBlock>> {
        // 跳过陈旧条目：SMP 下，bug 或竞态可能会暂时把非 Ready 任务
        // （Blocked/Running）留在就绪队列中。绝不能调度它们。
        let t = {
            let mut rq = self.ready_queues[hart_id].lock();
            let mut picked = None;
            // RT-RUNTIME 还没用完 ，那就直接从rt中拿取
            if !rt_bandwidth_throttled(hart_id) {
                for (rt_idx, rtq) in rq.rt_queues.iter_mut().enumerate() {
                    if let Some(task) = Self::pop_ready_rt_candidate(rtq, hart_id, rt_idx) {
                        picked = Some(task);
                        break;
                    }
                }
            }
            if picked.is_none() {
                picked = Self::pop_ready_fair_candidate(&mut rq, hart_id);
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
                    self.ready_queues[hart_id].lock().len()
                );
            }
        }
        t
    }
    /// 从所有 hart 的就绪队列中移除指定任务（同时清理 RT 和 Fair 队列中可能存在的重复条目）
    pub fn remove(&self, task: Arc<TaskControlBlock>) -> usize {
        loop {
            let queued_hart = task
                .ready_queue_hart
                .load(core::sync::atomic::Ordering::Acquire);
            if queued_hart >= MAX_HARTS {
                return 0;
            }
            let mut rq = self.ready_queues[queued_hart].lock();
            // fetch/remove on the old hart may have released ownership while
            // we waited for its rq lock, and a new enqueue may already target
            // another hart.  Retry against that owner rather than deleting a
            // stale entry and clobbering the new queue's boolean.
            if task
                .ready_queue_hart
                .load(core::sync::atomic::Ordering::Acquire)
                != queued_hart
            {
                drop(rq);
                core::hint::spin_loop();
                continue;
            }
            let mut removed = 0usize;
            for (rt_idx, q) in rq.rt_queues.iter_mut().enumerate() {
                let before = q.len();
                q.retain(|t| !Arc::ptr_eq(t, &task));
                let removed_now = before.saturating_sub(q.len());
                for _ in 0..removed_now {
                    dec_ready_rt_count(queued_hart, rt_idx);
                }
                removed = removed.saturating_add(removed_now);
            }
            let task_id = fair_task_id(&task);
            let mut fair_removed = 0usize;
            let (group_id, _) = fair_group_id_and_shares(&task);
            fair_removed =
                Self::remove_fair_task_from_group(&mut rq, group_id, task_id, queued_hart);
            if fair_removed == 0 {
                let fair_group_ids = rq
                    .fair_groups
                    .keys()
                    .copied()
                    .collect::<alloc::vec::Vec<_>>();
                for group_id in fair_group_ids {
                    fair_removed = fair_removed.saturating_add(Self::remove_fair_task_from_group(
                        &mut rq,
                        group_id,
                        task_id,
                        queued_hart,
                    ));
                    if fair_removed > 0 {
                        break;
                    }
                }
            }
            removed = removed.saturating_add(fair_removed);
            if removed == 0
                && !task
                    .in_ready_queue
                    .load(core::sync::atomic::Ordering::Acquire)
            {
                // The marker can be owned by an add that won OFF -> hart but
                // has not acquired this rq lock yet.  Do not cancel that
                // enqueue generation: a concurrent refresh would otherwise
                // see remove=0 while the producer also aborts, losing a Ready
                // task from every queue.  Let the producer publish its entity
                // and retry the physical removal afterwards.
                drop(rq);
                core::hint::spin_loop();
                continue;
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
            // OFF is the release publication that the old physical entry has
            // gone away.  Keep it last and under the rq lock so a concurrent
            // add cannot be followed by our stale `in_ready_queue = false`.
            task.in_ready_queue
                .store(false, core::sync::atomic::Ordering::Release);
            let released = task
                .ready_queue_hart
                .compare_exchange(
                    queued_hart,
                    TaskControlBlock::OFF_CPU,
                    core::sync::atomic::Ordering::Release,
                    core::sync::atomic::Ordering::Acquire,
                )
                .is_ok();
            debug_assert!(released, "rq ownership changed while its lock was held");
            return removed;
        }
    }

    /// 返回每个 hart 的就绪队列长度（用于调试和负载均衡）
    pub fn ready_queue_lengths(&self) -> alloc::vec::Vec<usize> {
        self.ready_queues.iter().map(|rq| rq.lock().len()).collect()
    }

    /// Whether any hart currently has runnable work waiting in its ready queue.
    pub fn has_ready_tasks(&self) -> bool {
        self.ready_queues.iter().any(|rq| rq.lock().len() > 0)
    }

    /// 调试用：统计指定任务在所有就绪队列中出现的引用次数（用于检测重复入队等异常）
    pub(super) fn debug_count_task_refs(&self, task: &Arc<TaskControlBlock>) -> usize {
        self.ready_queues
            .iter()
            .map(|rq| {
                let rq = rq.lock();
                rq.rt_queues
                    .iter()
                    .map(|q| q.iter().filter(|t| Arc::ptr_eq(t, task)).count())
                    .sum::<usize>()
                    + rq.fair_groups
                        .values()
                        .map(|group| {
                            group
                                .tasks
                                .values()
                                .filter(|entity| Arc::ptr_eq(&entity.task, task))
                                .count()
                        })
                        .sum::<usize>()
            })
            .sum()
    }

    fn remove_fair_task_from_group(
        rq: &mut HartRunQueue,
        group_id: u64,
        task_id: u64,
        hart_id: usize,
    ) -> usize {
        rq.unlink_fair_group(group_id);
        let mut removed = 0usize;
        let mut should_remove_group = false;
        let mut should_relink_group = false;
        if let Some(group) = rq.fair_groups.get_mut(&group_id) {
            if group.unlink_task(task_id).is_some() {
                dec_ready_fair_count(hart_id);
                removed = 1;
            }
            should_remove_group = group.is_empty();
            should_relink_group = !group.is_empty();
        }
        if should_remove_group {
            rq.fair_groups.remove(&group_id);
        } else if should_relink_group {
            rq.relink_fair_group_if_runnable(group_id);
        }
        removed
    }
}
