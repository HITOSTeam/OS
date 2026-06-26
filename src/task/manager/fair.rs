use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;

use crate::config::MAX_HARTS;
use crate::task::sched::{RT_PRIO_LEVELS, SchedClass, rt_queue_index, sched_class};
use crate::task::task_block::TaskControlBlock;

use super::TASK_MANAGER;
use super::current_time_ns_usize;
use super::rt::ready_fair_count;

/// 任务在调度中的相关信息
pub(super) struct FairTaskEntity {
    /// vruntime
    pub(super) vruntime: u128,
    /// 下一次退出的时间点
    pub(super) deadline: u128,
    /// 参与计算 averrage vuntime 时候的权重
    pub(super) weight: u128,
    pub(super) task: Arc<TaskControlBlock>,
}

/// 调度以组为单位
#[derive(Default)]
pub(super) struct FairGroupQueue {
    pub(super) shares: u64,                             // 该 group 的 CPU 时间权重
    pub(super) vruntime: u128, // 虚拟运行时间，用于 EEVDF 调度决策（值越小越优先）
    pub(super) min_task_vruntime: u128, // group 内 task entity 的单调 vruntime 基线
    pub(super) vruntime_weighted_sum: u128, // Σ(vruntime * weight), for avg_vruntime
    pub(super) weight_sum: u128, // Σ(weight) of runnable task entities
    pub(super) tasks: BTreeMap<u64, FairTaskEntity>, // 属于该 group 的就绪任务实体
    pub(super) task_order: BTreeSet<(u128, u128, u64)>, // 按 EEVDF deadline/vruntime 排序的实体索引
}

impl FairGroupQueue {
    /// 创建一个新的公平组队列。
    ///
    /// `vruntime` 为该组的初始虚拟运行时间，通常取自所在 hart 运行队列的
    /// `min_fair_vruntime` 基线，使新组能以接近当前全局进度的位置加入组间竞争，
    /// 而不是从 0 起步导致独占 CPU。
    /// 默认 `shares = 1024`（等价于 nice 0 的权重），由调用方按 cgroup 配置覆盖。
    pub(super) fn new(vruntime: u128) -> Self {
        Self {
            shares: 1024,
            vruntime,
            min_task_vruntime: vruntime,
            vruntime_weighted_sum: 0,
            weight_sum: 0,
            tasks: BTreeMap::new(),
            task_order: BTreeSet::new(),
        }
    }

    /// 返回该组内当前就绪任务实体的数量。
    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    /// 返回该组是否没有任何就绪任务实体。
    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// 将指定任务实体从该组中移除并返回。
    ///
    /// 同步维护三处状态：
    /// - 从 `tasks` 映射中删除实体；
    /// - 从 `task_order` 排序索引中删除对应的 `(deadline, vruntime, task_id)` 项；
    /// - 从 `vruntime_weighted_sum` / `weight_sum` 中扣减该实体的贡献，
    ///   保持 `avg_task_vruntime` 的 O(1) 增量统计正确。
    ///
    /// 若 `task_id` 不存在则返回 `None`。
    pub(super) fn unlink_task(&mut self, task_id: u64) -> Option<FairTaskEntity> {
        let entity = self.tasks.remove(&task_id)?;
        self.task_order
            .remove(&(entity.deadline, entity.vruntime, task_id));
        self.vruntime_weighted_sum = self
            .vruntime_weighted_sum
            .saturating_sub(entity.vruntime.saturating_mul(entity.weight));
        self.weight_sum = self.weight_sum.saturating_sub(entity.weight);
        Some(entity)
    }

    /// 将一个任务实体插入该组，若 `task_id` 已存在则覆盖旧实体。
    ///
    /// 同步维护三处状态（与 `unlink_task` 对称）：
    /// - 向 `tasks` 映射插入新实体；若覆盖了旧实体，先从 `task_order` 和
    ///   `vruntime_weighted_sum` / `weight_sum` 中扣减旧实体的贡献，避免重复计数；
    /// - 向 `vruntime_weighted_sum` / `weight_sum` 累加新实体的 `vruntime * weight`
    ///   和 `weight`；
    /// - 向 `task_order` 插入 `(deadline, vruntime, task_id)`，使之参与 EEVDF
    ///   的 earliest-deadline-first 选择。
    pub(super) fn insert_task(
        &mut self,
        task_id: u64,
        task: Arc<TaskControlBlock>,
        vruntime: u128,
        deadline: u128,
        weight: u128,
    ) {
        if let Some(old) = self.tasks.insert(
            task_id,
            FairTaskEntity {
                vruntime,
                deadline,
                weight,
                task,
            },
        ) {
            self.task_order
                .remove(&(old.deadline, old.vruntime, task_id));
            self.vruntime_weighted_sum = self
                .vruntime_weighted_sum
                .saturating_sub(old.vruntime.saturating_mul(old.weight));
            self.weight_sum = self.weight_sum.saturating_sub(old.weight);
        }
        self.vruntime_weighted_sum = self
            .vruntime_weighted_sum
            .saturating_add(vruntime.saturating_mul(weight));
        self.weight_sum = self.weight_sum.saturating_add(weight);
        self.task_order.insert((deadline, vruntime, task_id));
    }

    /// 计算该组内就绪任务实体的加权平均虚拟运行时间（avg_vruntime）。
    ///
    /// avg_vruntime 是 EEVDF 的 eligible 判定基准：`vruntime <= avg` 的任务被视为
    /// "被欠 CPU"而有资格被选中。加权平均保证权重大的任务对基准的影响更大，
    /// 与 Linux `avg_vruntime()` 一致。
    ///
    /// `current` 参数允许把"当前正在运行但尚未出队的任务"临时纳入统计：该任务的
    /// vruntime 尚未通过 `insert_task` 进入 `vruntime_weighted_sum`，但在放置新
    /// 入队实体时需要它参与基准计算，否则 avg 会偏低导致新实体被放置到不合理位置。
    ///
    /// 结果不会低于 `min_task_vruntime`，保持单调性，防止 avg 倒退。
    /// 若组内没有任何实体且未提供 `current`，返回 `None`。
    pub(super) fn avg_task_vruntime_with(&self, current: Option<(u128, u128)>) -> Option<u128> {
        let mut weighted_sum = self.vruntime_weighted_sum;
        let mut weight_sum = self.weight_sum;
        if let Some((vruntime, weight)) = current {
            weighted_sum = weighted_sum.saturating_add(vruntime.saturating_mul(weight));
            weight_sum = weight_sum.saturating_add(weight);
        }
        if weight_sum == 0 {
            return None;
        }
        Some((weighted_sum / weight_sum).max(self.min_task_vruntime))
    }

    /// 计算该组内就绪任务实体的加权平均虚拟运行时间（不包含当前正在运行的任务）。
    ///
    /// 这是 `avg_task_vruntime_with(None)` 的便捷封装，用于选择路径
    ///（`prune_fair_group_front`）中判定 eligible：`vruntime <= avg` 的实体有资格
    /// 被 EEVDF 选中。若组为空则返回 `None`。
    pub(super) fn avg_task_vruntime(&self) -> Option<u128> {
        self.avg_task_vruntime_with(None)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum EnqueueKind {
    Initial,
    Wakeup,
    Requeue,
}

/// 每个hart 拥有的 运行队列
#[derive(Default)]
pub(super) struct HartRunQueue {
    pub(super) rt_queues: alloc::vec::Vec<VecDeque<Arc<TaskControlBlock>>>, // 实时优先级队列（RT FIFO/RR），按优先级分桶
    pub(super) fair_groups: BTreeMap<u64, FairGroupQueue>, // EEVDF 公平组集合，key 为 group_id
    /// 按 vruntime 排序的公平组。
    ///
    /// Linux EEVDF 将可运行调度实体保存在 rb-tree 中（按 deadline/vruntime 排序）并选择
    /// 最左侧实体。这个紧凑索引让我们的 per-cgroup 公平队列具备同样的热路径形态：
    /// fetch 不再扫描每个组。
    pub(super) fair_order: BTreeSet<(u128, u64)>,
    /// 新变为可运行的公平组使用的单调 EEVDF 基线。
    ///
    /// Linux 会把刚 fork 或刚唤醒的调度实体初始化到接近 `rq->cfs.min_vruntime` 的位置；
    /// 否则带有 vruntime=0 实体的 fork 风暴可能饿死已经积累较高 vruntime 的长时间运行
    /// shell/script。
    pub(super) min_fair_vruntime: u128,
}

impl HartRunQueue {
    pub(super) fn new() -> Self {
        Self {
            rt_queues: (0..RT_PRIO_LEVELS).map(|_| VecDeque::new()).collect(),
            fair_groups: BTreeMap::new(),
            fair_order: BTreeSet::new(),
            min_fair_vruntime: 0,
        }
    }

    /// 该 hart 就绪队列中公平调度（EEVDF）任务的总数（不含 RT 队列）。
    pub(super) fn fair_len(&self) -> usize {
        self.fair_groups.values().map(FairGroupQueue::len).sum()
    }

    /// 返回该 hart 就绪队列中所有任务的总数（RT + Fair）
    pub(super) fn len(&self) -> usize {
        self.rt_queues.iter().map(VecDeque::len).sum::<usize>() + self.fair_len()
    }

    pub(super) fn unlink_fair_group(&mut self, group_id: u64) {
        if let Some(group) = self.fair_groups.get(&group_id) {
            self.fair_order.remove(&(group.vruntime, group_id));
        }
    }

    pub(super) fn relink_fair_group_if_runnable(&mut self, group_id: u64) {
        if let Some(group) = self.fair_groups.get(&group_id) {
            if !group.is_empty() {
                self.fair_order.insert((group.vruntime, group_id));
            }
        }
    }
}

/// 任务入队时的目标槽位：RT 队列（按优先级索引）或 EEVDF 公平队列
pub(super) enum ReadyQueueSlot {
    Rt(usize),
    Fair,
}

/// 根据任务的调度策略和优先级，确定其应放入的就绪队列槽位（RT 或公平队列）

pub(super) fn task_queue_slot(task: &Arc<TaskControlBlock>) -> ReadyQueueSlot {
    let (policy, rt_priority) = {
        let inner = task.borrow_mut();
        (
            inner.scheduling.sched_policy,
            inner.scheduling.sched_priority,
        )
    };
    // 根据调度策略编号决定目标队列位置。
    // FIFO RR 都加入到 RT
    // 其余进入公平调度队列
    match sched_class(policy) {
        Some(SchedClass::Fifo) | Some(SchedClass::Rr) => {
            ReadyQueueSlot::Rt(rt_queue_index(rt_priority))
        }
        Some(SchedClass::Fair) | None => ReadyQueueSlot::Fair,
    }
}

/// 获取任务所属的公平组 ID 及其权重（shares），用于 EEVDF 调度决策
pub(super) fn fair_group_id_and_shares(task: &Arc<TaskControlBlock>) -> (u64, u64) {
    let inner = task.borrow_mut();
    (inner.fair_group_id, inner.fair_group_shares.max(1))
}

pub(super) fn fair_task_id(task: &Arc<TaskControlBlock>) -> u64 {
    Arc::as_ptr(task) as usize as u64
}

pub(super) fn fair_nice_weight(nice: i32) -> u128 {
    // Linux sched_prio_to_weight[-20..19]。
    const NICE_WEIGHTS: [u32; 40] = [
        88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100,
        4904, 3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172,
        137, 110, 87, 70, 56, 45, 36, 29, 23, 18, 15,
    ];
    let idx = (nice.clamp(-20, 19) + 20) as usize;
    u128::from(NICE_WEIGHTS[idx])
}

fn scale_fair_delta(delta_ns: u64, weight: u128) -> u128 {
    const NICE_0_LOAD: u128 = 1024;
    ((u128::from(delta_ns) * NICE_0_LOAD) / weight.max(1)).max(1)
}

fn fair_entity_vslice_ns(nice: i32, kind: EnqueueKind) -> u128 {
    // Linux EEVDF 使用 sysctl_sched_base_slice 作为实体请求大小。我们还没有
    // hrtick/update_curr 驱动的公平抢占，因此实际公平抢占点是调度器 tick。
    // 让虚拟请求与这个粒度对齐；否则刚 clone 出来的公平调度工作线程只会落后创建者
    // 约 0.7ms，而创建者在重新入队前可能被记满一个 10ms tick，这会破坏 fork-heavy
    // 负载下 WF_FORK 的父任务继续运行行为。
    const FAIR_BASE_SLICE_NS: u64 = 10_000_000;
    let mut vslice = scale_fair_delta(FAIR_BASE_SLICE_NS, fair_nice_weight(nice));
    if kind == EnqueueKind::Initial {
        // Linux PLACE_DEADLINE_INITIAL 让新任务以半个 slice 起步，
        // 使它们能及时加入已经存在的运行竞争。
        vslice = (vslice / 2).max(1);
    }
    vslice
}

fn fair_lag_limit_ns(nice: i32) -> u128 {
    // Linux 的 entity_lag() 会把虚拟 lag 限制在大约 max_slice + TICK_NSEC。
    // 我们的周期 tick 是 10ms，而 EEVDF 请求是亚毫秒级。
    fair_entity_vslice_ns(nice, EnqueueKind::Requeue).saturating_add(10_000_000)
}

pub(super) const FAIR_PICK_SCAN_LIMIT: usize = 32;

/// 任务重新入队时根据已消耗的 CPU 时间累加 vruntime，并执行一个简化版
/// Linux `place_entity()`：按 avg/min vruntime 放置实体，再用
/// `deadline = vruntime + vslice` 参与 EEVDF 风格选择。
pub(super) fn place_fair_task_entity(
    group: &mut FairGroupQueue,
    task: &Arc<TaskControlBlock>,
    kind: EnqueueKind,
    current_entity: Option<(u128, u128)>,
) -> (u128, u128) {
    let avg_vruntime = group
        .avg_task_vruntime_with(current_entity)
        .unwrap_or(group.min_task_vruntime);
    let mut inner = task.borrow_mut();
    if inner.fair_vruntime_ns < group.min_task_vruntime {
        inner.fair_vruntime_ns = group.min_task_vruntime;
    }
    let current_ns = inner.cpu_time_ns;
    let delta_ns = current_ns.saturating_sub(inner.fair_runtime_checkpoint_ns);
    if delta_ns > 0 {
        // vruntime += delta_ns * 1024 / shares，即权重越大 vruntime 增长越慢，从而获得更多 CPU
        group.vruntime = group
            .vruntime
            .saturating_add(scale_fair_delta(delta_ns, u128::from(group.shares.max(1))));
        inner.fair_vruntime_ns = inner
            .fair_vruntime_ns
            .saturating_add(scale_fair_delta(delta_ns, fair_nice_weight(inner.nice)));
    }
    let placement_vruntime = avg_vruntime.max(group.min_task_vruntime);
    let weight = fair_nice_weight(inner.nice);
    let saved_vlag = core::mem::take(&mut inner.fair_vlag_ns).min(fair_lag_limit_ns(inner.nice));
    if kind == EnqueueKind::Initial {
        // Linux 的 fork placement 会让子任务靠近运行队列虚拟时间，并依赖
        // WF_FORK 唤醒抢占规则，而不是额外背上一个本地 tick 的 vruntime 债务。
        // 如果在这里记上这笔债，短 setup 线程在提升自身策略/优先级前会被无关公平调度
        // 负载挡住。
        inner.fair_vruntime_ns = placement_vruntime;
    } else if kind == EnqueueKind::Wakeup {
        let current_weight = current_entity.map(|(_, weight)| weight).unwrap_or(0);
        let load = group.weight_sum.saturating_add(current_weight);
        if saved_vlag > 0 && load > 0 {
            // Linux PLACE_LAG 会补偿被唤醒实体对 V 的影响，
            // 使 lag 不会在实体插入时消失：
            // lag = vlag * (W + w_i) / W。
            let inflated = saved_vlag
                .saturating_mul(load.saturating_add(weight))
                .checked_div(load)
                .unwrap_or(saved_vlag);
            inner.fair_vruntime_ns = placement_vruntime.saturating_sub(inflated);
        } else if inner.fair_vruntime_ns > placement_vruntime {
            // Linux EEVDF 会在唤醒时保留有界 lag，而不是让之前睡眠的任务携带
            // 无界旧 vruntime。将其限制到运行队列虚拟时间，可以让短控制任务
            // （例如 cyclictest 后的 shell 清理）在 fork-heavy 公平调度负载下仍保持可选资格。
            inner.fair_vruntime_ns = placement_vruntime;
        }
    }
    inner.fair_runtime_checkpoint_ns = current_ns;
    let vruntime = inner.fair_vruntime_ns;
    let deadline = vruntime.saturating_add(fair_entity_vslice_ns(inner.nice, kind));
    inner.fair_deadline_ns = deadline;
    (vruntime, deadline)
}

fn fair_task_vruntime_deadline_at(task: &Arc<TaskControlBlock>, now_ns: u64) -> (u128, u128) {
    let inner = task.borrow_mut();
    let current_runtime_ns =
        if task.on_cpu.load(core::sync::atomic::Ordering::Acquire) != TaskControlBlock::OFF_CPU {
            inner
                .cpu_time_ns
                .saturating_add(now_ns.saturating_sub(inner.runtime_start_ns))
        } else {
            inner.cpu_time_ns
        };
    let delta_ns = current_runtime_ns.saturating_sub(inner.fair_runtime_checkpoint_ns);
    let vruntime = inner
        .fair_vruntime_ns
        .saturating_add(scale_fair_delta(delta_ns, fair_nice_weight(inner.nice)));
    (vruntime, inner.fair_deadline_ns)
}

pub(super) fn current_fair_entity_for_group(
    hart_id: usize,
    group_id: u64,
    now_ns: u64,
) -> Option<(u128, u128)> {
    let current = crate::task::processor::current_task_on_hart(hart_id)?;
    if current.on_cpu.load(core::sync::atomic::Ordering::Acquire) == TaskControlBlock::OFF_CPU {
        return None;
    }
    let weight = {
        let inner = current.borrow_mut();
        if inner.fair_group_id != group_id
            || !matches!(
                sched_class(inner.scheduling.sched_policy),
                Some(SchedClass::Fair)
            )
        {
            return None;
        }
        fair_nice_weight(inner.nice)
    };
    let (vruntime, _) = fair_task_vruntime_deadline_at(&current, now_ns);
    Some((vruntime, weight))
}

/// 返回当前公平调度任务是否已经耗尽自己的 EEVDF 请求。
///
/// Linux `update_deadline()` 会在 `se->vruntime` 到达 `se->deadline` 时请求重调度。
/// 我们在调度器 tick 和显式唤醒/抢占路径做同样检查；syscall 返回只消费由此产生的
/// NEED_RESCHED 位，而不是每次 syscall 都重新计算公平调度 deadline。
pub fn fair_current_deadline_expired(task: &Arc<TaskControlBlock>, now_ns: u64) -> bool {
    let hart_id = crate::task::processor::hart_id() % MAX_HARTS;
    if ready_fair_count(hart_id) == 0 {
        return false;
    }
    let (vruntime, deadline) = fair_task_vruntime_deadline_at(task, now_ns);
    deadline == 0 || vruntime >= deadline
}

/// 两个公平调度任务之间的 Linux EEVDF 唤醒抢占近似。
///
/// 公平调度类不会仅仅因为被唤醒者有更早的虚拟 deadline 就抢占。
/// `wakeup_preempt_fair()` 会在启用保护的情况下调用 `pick_next_entity()`，
/// 而 `pick_eevdf()` 会在当前实体仍处于受保护请求内时保留它。只有真正更短的
/// 被唤醒者时间片才可以提前取消该保护。
pub fn fair_wakeup_preempts_current_on_hart(
    current: &Arc<TaskControlBlock>,
    woken: &Arc<TaskControlBlock>,
    hart_id: usize,
    now_ns: u64,
) -> bool {
    let (current_vruntime, current_deadline) = fair_task_vruntime_deadline_at(current, now_ns);
    if current_deadline == 0 || current_vruntime >= current_deadline {
        return true;
    }
    let (woken_vruntime, woken_deadline) = fair_task_vruntime_deadline_at(woken, now_ns);
    let (current_group_id, current_weight, current_full_slice) = {
        let inner = current.borrow_mut();
        (
            inner.fair_group_id,
            fair_nice_weight(inner.nice),
            fair_entity_vslice_ns(inner.nice, EnqueueKind::Requeue),
        )
    };
    let woken_group_id = woken.borrow_mut().fair_group_id;
    let woken_eligible = {
        let rq = TASK_MANAGER.ready_queues[hart_id % MAX_HARTS].lock();
        if let Some(group) = rq.fair_groups.get(&woken_group_id) {
            let current_for_group = if current_group_id == woken_group_id {
                Some((current_vruntime, current_weight))
            } else {
                None
            };
            let avg_vruntime = group
                .avg_task_vruntime_with(current_for_group)
                .unwrap_or(group.min_task_vruntime);
            woken_vruntime <= avg_vruntime
        } else {
            woken_vruntime <= current_vruntime
        }
    };

    if woken_eligible && woken_deadline < current_deadline {
        return true;
    }
    let woken_slice = woken_deadline.saturating_sub(woken_vruntime);
    if woken_eligible && woken_slice < current_full_slice {
        return true;
    }
    false
}

/// 在公平调度任务阻塞前捕获有界的正 EEVDF lag。
///
/// Linux 会在出队时保存 `se->vlag`，并在唤醒时的 `place_entity()` 中使用它。
/// 没有这个机制时，反复阻塞在大量可运行工作线程后面的短生命周期控制线程会丢失
/// 睡眠者信用，恢复运行可能需要数百毫秒。
pub fn record_fair_sleep_lag(task: &Arc<TaskControlBlock>) {
    let policy = task.borrow_mut().scheduling.sched_policy;
    if !matches!(sched_class(policy), Some(SchedClass::Fair)) {
        return;
    }

    let hart_id = crate::task::processor::hart_id() % MAX_HARTS;
    let now_ns = current_time_ns_usize() as u64;
    let (task_vruntime, _) = fair_task_vruntime_deadline_at(task, now_ns);
    let (group_id, _) = fair_group_id_and_shares(task);
    let task_weight = {
        let inner = task.borrow_mut();
        fair_nice_weight(inner.nice)
    };
    let avg_vruntime = {
        let rq = TASK_MANAGER.ready_queues[hart_id].lock();
        rq.fair_groups
            .get(&group_id)
            .and_then(|group| group.avg_task_vruntime_with(Some((task_vruntime, task_weight))))
            .unwrap_or(rq.min_fair_vruntime)
    };

    let mut inner = task.borrow_mut();
    let limit = fair_lag_limit_ns(inner.nice);
    inner.fair_vlag_ns = avg_vruntime.saturating_sub(task_vruntime).min(limit);
}
