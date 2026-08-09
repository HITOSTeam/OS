use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;

use crate::config::MAX_HARTS;
use crate::task::sched::{RT_PRIO_LEVELS, SchedClass, rt_queue_index, sched_class};
use crate::task::task_block::{TaskControlBlock, TaskControlBlockInner};

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

    /// 重排序 group 因为 group 更新了，所以原先order不再 适合
    pub(super) fn relink_fair_group_if_runnable(&mut self, group_id: u64) {
        if let Some(group) = self.fair_groups.get(&group_id) {
            if !group.is_empty() {
                self.fair_order.insert((group.vruntime, group_id));
            }
        }
    }
}

/// 任务入队时的目标槽位：RT 队列（按优先级索引）或 EEVDF 公平队列
#[derive(Clone, Copy)]
pub(super) enum ReadyQueueSlot {
    Rt(usize),
    Fair,
}

/// 根据任务的调度策略和优先级，确定其应放入的就绪队列槽位（RT 或公平队列）

pub(super) fn task_queue_slot(task: &Arc<TaskControlBlock>) -> ReadyQueueSlot {
    let inner = task.borrow_mut();
    task_queue_slot_from_inner(&inner)
}

pub(super) fn task_queue_slot_from_inner(inner: &TaskControlBlockInner) -> ReadyQueueSlot {
    let policy = inner.scheduling.sched_policy;
    let rt_priority = inner.scheduling.sched_priority;
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

/// nice weight 转换，越nice 越倾向于给别人，所以运行时的 vruntime要积攒的比较快，对应weight(分母
/// 就要小)
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

/// 计算vruntime = 时间 /weight
fn scale_fair_delta(delta_ns: u64, weight: u128) -> u128 {
    const NICE_0_LOAD: u128 = 1024;
    ((u128::from(delta_ns) * NICE_0_LOAD) / weight.max(1)).max(1)
}

fn fair_entity_vslice_ns(nice: i32, kind: EnqueueKind) -> u128 {
    // Linux EEVDF 使用 sysctl_sched_base_slice 作为实体请求大小，默认量级
    // 是亚毫秒到数毫秒。当前内核还没有 hrtick，实际公平抢占仍主要受
    // 100Hz tick 约束；这里用 2ms request，而不是旧的 10ms tick 宽度，
    // 避免 400 个 fair hackbench 实体把短控制任务的等待放大到数秒。
    const FAIR_BASE_SLICE_NS: u64 = 2_000_000;
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
    fair_entity_vslice_ns(nice, EnqueueKind::Requeue)
        .saturating_add(u128::from(crate::time::tick_period_ns()))
}

fn fair_wakeup_lag_cap_ns(nice: i32) -> u128 {
    fair_lag_limit_ns(nice).saturating_mul(2)
}

fn fair_startup_credit_cap_ns() -> u128 {
    50_000_000
}

fn inflate_fair_lag_ns(vlag: u128, load: u128, weight: u128) -> u128 {
    // Linux PLACE_LAG compensates the entity's contribution to avg_vruntime:
    // lag = vlag * (W + w_i) / W.
    vlag.saturating_mul(load.saturating_add(weight))
        .checked_div(load)
        .unwrap_or(vlag)
}

/// 任务重新入队时根据已消耗的 CPU 时间累加 vruntime，并执行一个简化版
/// Linux `place_entity()`：按 avg/min vruntime 放置实体，再用
/// `deadline = vruntime + vslice` 参与 EEVDF 风格选择。
pub(super) fn place_fair_task_entity(
    group: &mut FairGroupQueue,
    inner: &mut TaskControlBlockInner,
    kind: EnqueueKind,
    current_entity: Option<(u128, u128)>,
) -> (u128, u128) {
    let avg_vruntime = group
        .avg_task_vruntime_with(current_entity)
        .unwrap_or(group.min_task_vruntime);
    // group 限制最低 vruntime,防止 新进入任务亏欠太多
    if inner.fair_vruntime_ns < group.min_task_vruntime {
        inner.fair_vruntime_ns = group.min_task_vruntime;
    }
    let current_ns = inner.cpu_time_ns;
    let delta_ns = current_ns.saturating_sub(inner.fair_runtime_checkpoint_ns);
    // 任务之前被运行过，那么vruntime需要更新，
    if delta_ns > 0 {
        // vruntime += delta_ns * 1024 / shares，即权重越大 vruntime 增长越慢，从而获得更多 CPU
        group.vruntime = group
            .vruntime
            .saturating_add(scale_fair_delta(delta_ns, u128::from(group.shares.max(1))));
        inner.fair_vruntime_ns = inner
            .fair_vruntime_ns
            .saturating_add(scale_fair_delta(delta_ns, fair_nice_weight(inner.nice)));
    }
    // 新加入任务的基准 这与上面的不是重复 (min_task_vruntime的更新 )
    let placement_vruntime = avg_vruntime.max(group.min_task_vruntime);
    let weight = fair_nice_weight(inner.nice);
    // 是否是重复进入，如果是重复进入，那么会有 lag（之前退出或显式 wakeup
    // prime 保存的）。普通 sleep lag 仍在 record_fair_sleep_lag() 中按
    // entity_lag() 封顶；这里允许 timer 到期路径写入的额外有界 credit 生效。
    let saved_vlag =
        core::mem::take(&mut inner.fair_vlag_ns).min(fair_wakeup_lag_cap_ns(inner.nice));
    let startup_credit =
        core::mem::take(&mut inner.fair_startup_credit_ns).min(fair_startup_credit_cap_ns());
    if kind == EnqueueKind::Initial {
        // Linux `place_entity()` starts new forked entities at avg_vruntime.
        // ENQUEUE_INITIAL only shortens the first deadline below; it must not
        // repeatedly place a fork storm at the parent's older vruntime.
        inner.fair_vruntime_ns = placement_vruntime;
    } else if kind == EnqueueKind::Wakeup {
        // 对于重新入队的，我们使用
        // 之前保存的vlag对新进入的vruntime进行修正，亏欠（lag)越多，placement_vruntime被减去的越多，从而
        // 能够更有机会的被调度到
        let current_weight = current_entity.map(|(_, weight)| weight).unwrap_or(0);
        // 当前任务的权重，参与新补偿（vruntime-补偿）的计算
        let load = group.weight_sum.saturating_add(current_weight);
        let effective_vlag = saved_vlag.max(startup_credit);
        if effective_vlag > 0 && load > 0 {
            let inflated = inflate_fair_lag_ns(effective_vlag, load, weight);
            inner.fair_vruntime_ns = placement_vruntime.saturating_sub(inflated);
        } else if inner.fair_vruntime_ns > placement_vruntime {
            // Linux EEVDF 会在唤醒时保留有界 lag，而不是让之前睡眠的任务携带
            // 无界旧 vruntime。将其限制到运行队列虚拟时间，可以让短控制任务
            // （例如 cyclictest 后的 shell 清理）在 fork-heavy 公平调度负载下仍保持可选资格。
            //tldr:防止一个任务长时间死亡
            inner.fair_vruntime_ns = placement_vruntime;
        }
    } else if kind == EnqueueKind::Requeue && startup_credit > 0 {
        let current_weight = current_entity.map(|(_, weight)| weight).unwrap_or(0);
        let load = group.weight_sum.saturating_add(current_weight);
        if load > 0 {
            let inflated = inflate_fair_lag_ns(startup_credit, load, weight);
            let credited_vruntime = placement_vruntime.saturating_sub(inflated);
            if inner.fair_vruntime_ns > credited_vruntime {
                inner.fair_vruntime_ns = credited_vruntime;
            }
        } else if inner.fair_vruntime_ns > placement_vruntime {
            inner.fair_vruntime_ns = placement_vruntime;
        }
    }
    inner.fair_runtime_checkpoint_ns = current_ns;
    let vruntime = inner.fair_vruntime_ns;
    /// elgible 之后看的标准
    let deadline = vruntime.saturating_add(fair_entity_vslice_ns(inner.nice, kind));
    inner.fair_deadline_ns = deadline;
    (vruntime, deadline)
}

/// 实时估算任务在此刻的 (vruntime, deadline)，包含尚未入队记账的运行时间。
///
/// vruntime 只在任务入队（`place_fair_task_entity`）时累加，但任务正在运行时
/// vruntime 已经过时——它跑了一段时间但 `fair_vruntime_ns` 还没更新。这个函数
/// 用于抢占判定路径（tick / 唤醒），需要知道"此刻的真实 vruntime"才能准确
/// 比较 deadline。
///
/// 计算方式：
/// - 若任务正在运行（`on_cpu != OFF_CPU`）：`cpu_time_ns + (now_ns - runtime_start_ns)`，
///   即已记账的 CPU 时间加上从上次 tick 到现在的未记账片段。
/// - 若任务不在运行：直接用 `cpu_time_ns`。
///
/// 然后用与 `place_fair_task_entity` 相同的 `scale_fair_delta` 公式把
/// `delta = current_runtime - checkpoint` 按权重缩放后累加到 `fair_vruntime_ns` 上，
/// 得到实时估算值。`fair_deadline_ns` 直接从 TCB 读取（deadline 只在入队时设置）。
///
/// 注意：这个函数**不修改** TCB 状态，只做只读估算。真正的 vruntime 累加
/// 发生在下一次入队时的 `place_fair_task_entity`。
fn fair_task_vruntime_deadline_from_inner(
    task: &TaskControlBlock,
    inner: &TaskControlBlockInner,
    now_ns: u64,
) -> (u128, u128) {
    // 若任务正在运行，补上从 runtime_start_ns 到 now 的未记账片段。
    let current_runtime_ns =
        if task.on_cpu.load(core::sync::atomic::Ordering::Acquire) != TaskControlBlock::OFF_CPU {
            inner
                .cpu_time_ns
                .saturating_add(now_ns.saturating_sub(inner.runtime_start_ns))
        } else {
            inner.cpu_time_ns
        };
    // delta = 本次估算的运行时间 - 上次入队时的快照。
    let delta_ns = current_runtime_ns.saturating_sub(inner.fair_runtime_checkpoint_ns);
    // 按权重缩放后累加，得到实时 vruntime。
    let vruntime = inner
        .fair_vruntime_ns
        .saturating_add(scale_fair_delta(delta_ns, fair_nice_weight(inner.nice)));
    (vruntime, inner.fair_deadline_ns)
}

fn fair_task_vruntime_deadline_at(task: &Arc<TaskControlBlock>, now_ns: u64) -> (u128, u128) {
    let inner = task.borrow_mut();
    fair_task_vruntime_deadline_from_inner(task, &inner, now_ns)
}

/// 获取指定 hart 上当前正在运行的 fair 任务实体信息（vruntime, weight），
/// 且仅当该任务属于指定的 `group_id` 时返回。
///
/// 用于 `place_fair_task_entity` 的 `current_entity` 参数：当新任务入队时，
/// 需要把"当前正在跑的同组任务"纳入 `avg_task_vruntime` 计算，否则 avg 会偏低
/// 导致新实体被放置到不合理位置。
///
/// 返回 `None` 的情况：
/// - 该 hart 没有当前任务；
/// - 当前任务不在运行（`on_cpu == OFF_CPU`）；
/// - 当前任务不属于 `group_id`（不同 cgroup 的任务不参与彼此的 avg）；
/// - 当前任务不是 fair 类（RT 任务不参与 fair avg）。
pub(super) fn current_fair_entity_for_group(
    hart_id: usize,
    group_id: u64,
    now_ns: u64,
) -> Option<(u128, u128)> {
    let current = crate::task::processor::current_task_on_hart(hart_id)?;
    if current.on_cpu.load(core::sync::atomic::Ordering::Acquire) == TaskControlBlock::OFF_CPU {
        return None;
    }
    // Enqueue may already hold the target runqueue lock. Linux reads the
    // current entity directly under rq ownership; our transitional TCB keeps
    // that state behind a separate lock. Never wait for it while an rq can be
    // held: the running task may itself be trying to acquire that rq while it
    // owns TCB.inner. Omitting a contended current entity only makes the EEVDF
    // average snapshot conservative and cannot lose runnable ownership.
    let inner = current.try_borrow_mut()?;
    if inner.fair_group_id != group_id
        || !matches!(
            sched_class(inner.scheduling.sched_policy),
            Some(SchedClass::Fair)
        )
    {
        return None;
    }
    let weight = fair_nice_weight(inner.nice);
    let (vruntime, _) = fair_task_vruntime_deadline_from_inner(&current, &inner, now_ns);
    Some((vruntime, weight))
}

fn peek_fair_group_task(group: &FairGroupQueue, hart_id: usize) -> Option<u64> {
    let eligible_vruntime = group.avg_task_vruntime().unwrap_or(group.min_task_vruntime);
    let mut fallback = None;

    for (_deadline, vruntime, task_id) in group.task_order.iter().copied() {
        let Some(entity) = group.tasks.get(&task_id) else {
            continue;
        };
        if entity.vruntime != vruntime {
            continue;
        }
        let candidate = &entity.task;
        let queued_here = candidate
            .ready_queue_hart
            .load(core::sync::atomic::Ordering::Acquire)
            == hart_id;
        // Physical rq membership plus ready_queue_hart is the authoritative
        // runnable state, as Linux's rb-tree membership is under rq_lock. Do
        // not take the broad TCB.inner lock while holding rq_lock.
        if !queued_here {
            continue;
        }
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

    fallback.map(|(_, task_id)| task_id)
}

/// Return whether `task` is already the entity the fair runqueue would pick next.
///
/// Linux's wakeup preemption path enqueues the wakee and then asks EEVDF's
/// picker whether that wakee became the next entity. Our older approximation
/// only compared the current and wakee deadlines, which misses cases where a
/// timer/control task is correctly placed at the front of a large runqueue but
/// the direct pairwise comparison still preserves the current task.
pub fn fair_task_is_next_on_hart(task: &Arc<TaskControlBlock>, hart_id: usize) -> bool {
    // These runqueue reads participate in the same IRQ lock domain as enqueue
    // and dequeue.  This mirrors Linux's rq_lock_irqsave requirement.
    let _irq_guard = crate::sync::LocalIrqSaveGuard::new();
    let hart_id = hart_id % MAX_HARTS;
    let task_id = fair_task_id(task);
    let rq = TASK_MANAGER.ready_queues[hart_id].lock();

    for (indexed_vruntime, candidate_group_id) in rq.fair_order.iter().copied() {
        let Some(group) = rq.fair_groups.get(&candidate_group_id) else {
            continue;
        };
        if group.vruntime != indexed_vruntime {
            continue;
        }
        let Some(candidate_task_id) = peek_fair_group_task(group, hart_id) else {
            continue;
        };
        // Task ids are globally unique, so the rq tree itself is sufficient;
        // no TCB metadata lock is needed to recover the wakee's group id.
        return candidate_task_id == task_id;
    }

    false
}

/// 返回当前 fair 任务是否已耗尽自己的 EEVDF 虚拟请求（tick 抢冒判据）。
///
/// 对应 Linux `update_deadline()`：在 `se->vruntime` 到达 `se->deadline` 时
/// 请求重调度。我们在调度器 tick（`should_preempt_current_on_tick`）和
/// 显式唤醒/抢占路径做同样检查；syscall 返回只消费由此产生的 `NEED_RESCHED`
/// 位，而不是每次 syscall 都重新计算 fair deadline。
///
/// 判定逻辑：
/// 1. **先检查有没有 fair 竞争者**（`ready_fair_count`）：如果本 hart 没有
///    其他就绪的 fair 任务，即使 deadline 到了也不让出——让出了也没人接，
///    不如继续跑。这是无锁快路径，避免获取调度器锁。
/// 2. **vruntime >= deadline**：用 `fair_task_vruntime_deadline_at` 实时估算
///    当前 vruntime，与 `fair_deadline_ns` 比较。`deadline == 0` 是未初始化
///    的防御性判定，也视为该让出。
pub fn fair_current_deadline_expired(task: &Arc<TaskControlBlock>, now_ns: u64) -> bool {
    let hart_id = crate::task::processor::hart_id() % MAX_HARTS;
    // 无 fair 竞争者 → 不让出（没有其他人可换）。
    if ready_fair_count(hart_id) == 0 {
        return false;
    }
    let (vruntime, deadline) = fair_task_vruntime_deadline_at(task, now_ns);
    // deadline 未初始化或 vruntime 已追上 deadline → 本轮请求耗尽。
    deadline == 0 || vruntime >= deadline
}

/// 两个 fair 任务之间的 EEVDF 唤醒抢占近似判定。
///
/// 当一个 fair 任务被唤醒时，判断它是否应该抢占当前正在运行的 fair 任务。
/// 对应 Linux `wakeup_preempt_fair()` + `pick_eevdf()` 的保护逻辑：fair 类
/// 不会仅仅因为被唤醒者有更早的虚拟 deadline 就抢占——当前实体仍处于
/// 受保护请求内时会保留它，只有真正更短的被唤醒者切片才可以取消保护。
///
/// 判定分三步：
///
/// 1. **当前任务 deadline 已到** → 直接抢（当前任务自己的请求耗尽，换谁都行）。
///
/// 2. **被唤醒者是否 eligible**：查被唤醒者所在组的 `avg_vruntime`，
///    `woken_vruntime <= avg` 则 eligible。若当前任务与被唤醒者同组，则把
///    当前任务也纳入 avg 计算（因为它还没出队）；不同组则只用被唤醒者
///    自己组的 avg。若被唤醒者的组不存在（刚创建等），退化为与当前
///    vruntime 直接比较。
///
/// 3. **两个抢占条件**（均要求 eligible）：
///    - **deadline 更早**：`woken_deadline < current_deadline`——标准 EEVDF
///      "该被唤醒者先跑"。
///    - **剩余切片更短**：`woken_deadline - woken_vruntime < current_full_slice`——
///      即使 deadline 没更早，但被唤醒者需求量更小，让它先跑完再回来更高效。
///      这对应 Linux 的"只有更短切片才能打破当前任务的保护"。
pub fn fair_wakeup_preempts_current_on_hart(
    current: &Arc<TaskControlBlock>,
    woken: &Arc<TaskControlBlock>,
    hart_id: usize,
    now_ns: u64,
) -> bool {
    let _irq_guard = crate::sync::LocalIrqSaveGuard::new();
    // `try_to_wake_up()` must not wait for either task's broad state lock.
    // Snapshot each entity once before rq_lock. On contention this precise
    // pairwise test is deferred; the caller still checks whether the wakee is
    // the actual first entity in the rq tree without touching TCB.inner.
    let Some(current_inner) = current.try_borrow_mut() else {
        return false;
    };
    let (current_vruntime, current_deadline) =
        fair_task_vruntime_deadline_from_inner(current, &current_inner, now_ns);
    let current_group_id = current_inner.fair_group_id;
    let current_weight = fair_nice_weight(current_inner.nice);
    let current_full_slice = fair_entity_vslice_ns(current_inner.nice, EnqueueKind::Requeue);
    drop(current_inner);
    // 步骤 1：当前任务自己的 deadline 已到 → 直接抢。
    if current_deadline == 0 || current_vruntime >= current_deadline {
        return true;
    }
    let Some(woken_inner) = woken.try_borrow_mut() else {
        return false;
    };
    let (woken_vruntime, woken_deadline) =
        fair_task_vruntime_deadline_from_inner(woken, &woken_inner, now_ns);
    let woken_group_id = woken_inner.fair_group_id;
    drop(woken_inner);
    // 步骤 2：判定被唤醒者是否 eligible。
    let woken_eligible = {
        let rq = TASK_MANAGER.ready_queues[hart_id % MAX_HARTS].lock();
        if let Some(group) = rq.fair_groups.get(&woken_group_id) {
            // 同组时把当前任务纳入 avg（它还没出队）；不同组则不算。
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
            // 被唤醒者的组不存在（刚创建等），退化为与当前 vruntime 比较。
            woken_vruntime <= current_vruntime
        }
    };

    // 步骤 3：两个抢占条件（均要求 eligible）。
    // 条件 A：eligible 且 deadline 更早 → 标准 EEVDF 抢占。
    if woken_eligible && woken_deadline < current_deadline {
        return true;
    }
    // 条件 B：eligible 且被唤醒者剩余切片 < 当前完整切片 → 更短需求可打破保护。
    let woken_slice = woken_deadline.saturating_sub(woken_vruntime);
    if woken_eligible && woken_slice < current_full_slice {
        return true;
    }
    false
}

/// 在 fair 任务阻塞前捕获有界的正 EEVDF lag，供唤醒时补偿使用。
///
/// 对应 Linux 在出队时保存 `se->vlag`、在唤醒时的 `place_entity()` 中使用它
///（`PLACE_LAG` 机制）。没有这个机制时，反复阻塞在大量可运行工作线程后面的
/// 短生命周期控制线程会丢失睡眠者信用，恢复运行可能需要数百毫秒。
///
/// 流程：
/// 1. 只对 fair 类任务做（RT 类不参与）。
/// 2. 用 `fair_task_vruntime_deadline_at` 估算任务当前真实 vruntime。
/// 3. 取任务所在组的 `avg_vruntime`（把任务自己也算进去，因为它还没出队）。
/// 4. `vlag = avg - task_vruntime`，取正值（被欠才存），封顶到 `fair_lag_limit_ns`
///    （约一个切片 + 一个 tick），防止睡很久的任务带巨额 lag 回来。
/// 5. 存入 `fair_vlag_ns`，唤醒时由 `place_fair_task_entity` 的 Wakeup 分支消费。
pub fn record_fair_sleep_lag(task: &Arc<TaskControlBlock>) {
    let _irq_guard = crate::sync::LocalIrqSaveGuard::new();
    let policy = task.borrow_mut().scheduling.sched_policy;
    // 只对 fair 类任务保存 lag；RT 类不参与 EEVDF。
    if !matches!(sched_class(policy), Some(SchedClass::Fair)) {
        return;
    }

    let hart_id = crate::task::processor::hart_id() % MAX_HARTS;
    let now_ns = current_time_ns_usize() as u64;
    // 估算任务此刻的真实 vruntime（含未记账的运行片段）。
    let (task_vruntime, _) = fair_task_vruntime_deadline_at(task, now_ns);
    let (group_id, _) = fair_group_id_and_shares(task);
    let task_weight = {
        let inner = task.borrow_mut();
        fair_nice_weight(inner.nice)
    };
    // 取组 avg（含本任务），因为任务此刻还在队列里，即将被移出。
    let avg_vruntime = {
        let rq = TASK_MANAGER.ready_queues[hart_id].lock();
        rq.fair_groups
            .get(&group_id)
            .and_then(|group| group.avg_task_vruntime_with(Some((task_vruntime, task_weight))))
            .unwrap_or(rq.min_fair_vruntime)
    };

    let mut inner = task.borrow_mut();
    let limit = fair_lag_limit_ns(inner.nice);
    // lag = avg - vruntime，取正值（saturating_sub 在 avg < vruntime 时得 0），
    // 封顶到 limit，存入 fair_vlag_ns 供唤醒时 PLACE_LAG 补偿使用。
    inner.fair_vlag_ns = avg_vruntime.saturating_sub(task_vruntime).min(limit);
}

/// 给到期的 timer sleeper 一个有界的 wakeup lag。
///
/// Linux 的 CFS/EEVDF 通过 `PLACE_LAG`、wakeup preempt 和细粒度 tick/hrtick
/// 让短睡眠控制线程在唤醒后很快重新参与运行。本内核目前没有完整 hrtick，
/// 在 400 个 fair 实体的 hackbench 负载下，timer sleeper 即使被按时唤醒，
/// 也可能因为没有正 lag 而被放到平均虚拟时间附近，随后排队几十秒。
///
/// 这里只在睡眠定时器真正到期时补一个与 `entity_lag()` 同量级的有界 credit；
/// 由于当前没有 hrtick，再额外给一个 tick 量级的余量以补偿粗粒度抢占，
/// 仍然由 `place_fair_task_entity(Wakeup)` 做最终放置，避免把这个策略扩散到
/// pipe/socket/futex 等普通同步或 I/O 唤醒。
pub fn prime_fair_timer_wakeup_lag(task: &Arc<TaskControlBlock>) {
    let mut inner = task.borrow_mut();
    if !matches!(
        sched_class(inner.scheduling.sched_policy),
        Some(SchedClass::Fair)
    ) {
        return;
    }
    let credit = fair_wakeup_lag_cap_ns(inner.nice);
    inner.fair_vlag_ns = inner.fair_vlag_ns.max(credit);
}

/// 给同步等待者一个保守的 wakeup lag。
///
/// futex/join/wait4 这类唤醒通常是控制线程等待某个明确事件完成；在 hackbench
/// 这类 400 个 fair pipe worker 的压力下，如果这些控制线程按普通 I/O wakeup
/// 放置，就容易在事件已经完成后仍长时间排队。调用方只应把它用于明确的同步
/// handoff waiter，例如 futex/join/wait4 或 pipe 的直接读写等待者；poll/epoll
/// 这类就绪通知等待者仍应使用普通 wakeup placement。
pub fn prime_fair_sync_wakeup_lag(task: &Arc<TaskControlBlock>) {
    let mut inner = task.borrow_mut();
    if !matches!(
        sched_class(inner.scheduling.sched_policy),
        Some(SchedClass::Fair)
    ) {
        return;
    }
    let limit = fair_lag_limit_ns(inner.nice);
    inner.fair_vlag_ns = inner.fair_vlag_ns.max(limit);
}

/// 保护正在 fork/clone 的 fair 父任务，避免 WF_FORK 场景被刚创建的 fair
/// 子任务或无关 fair 负载在下一个 tick 立即打断。
///
/// Linux 的 `wake_up_new_task(WF_FORK)` 不会让 fair 子任务直接抢占父任务；
/// 在本内核没有 hrtick/load-balance 细节时，如果父任务创建 cyclictest 线程组时
/// 太早让出，首个子线程升到 SCHED_FIFO 后会反过来饿住仍在创建后续线程的父任务。
/// 这里只补齐未初始化的 deadline，不在每次 fork 时续期父任务；否则 hackbench
/// 这类 fork storm 会让父任务持续延长 slice，压住 shell/echo/sleep 控制路径。
pub fn protect_fair_fork_parent(task: &Arc<TaskControlBlock>) {
    let now_ns = current_time_ns_usize() as u64;
    let mut inner = task.borrow_mut();
    if !matches!(
        sched_class(inner.scheduling.sched_policy),
        Some(SchedClass::Fair)
    ) {
        return;
    }
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
    if inner.fair_deadline_ns == 0 {
        inner.fair_deadline_ns =
            vruntime.saturating_add(fair_entity_vslice_ns(inner.nice, EnqueueKind::Requeue));
    }
}

fn prime_fair_startup_credit(task: &Arc<TaskControlBlock>, credit_ns: u128) {
    let now_ns = current_time_ns_usize() as u64;
    let mut inner = task.borrow_mut();
    if !matches!(
        sched_class(inner.scheduling.sched_policy),
        Some(SchedClass::Fair)
    ) {
        return;
    }
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
    inner.fair_deadline_ns = inner
        .fair_deadline_ns
        .max(vruntime.saturating_add(credit_ns));
    inner.fair_startup_credit_ns = inner
        .fair_startup_credit_ns
        .max(credit_ns.min(fair_startup_credit_cap_ns()));
}

/// Give a freshly exec'd fair task a short startup window.
///
/// Linux has `sched_exec()` and wakeup/preemption machinery that keeps an
/// interactive exec from being buried behind a large fair runqueue while it is
/// still setting up the new image.  On our single-hart QEMU cyclictest case,
/// the foreground `cyclictest` process must run a small fair-control section
/// before its RT worker exists; without a startup window, 400 hackbench fair
/// workers can repeatedly preempt it before `pthread_create()`/scheduler setup.
pub fn prime_fair_exec_start(task: &Arc<TaskControlBlock>) {
    prime_fair_startup_credit(task, fair_startup_credit_cap_ns());
}

/// Protect a small pthread-style startup fanout.
///
/// `cyclictest -t8` creates RT worker threads from a fair control thread.  Once
/// the first workers switch to SCHED_FIFO, the control thread can be preempted
/// and then requeued behind hundreds of hackbench fair tasks before it finishes
/// the remaining pthread_create() calls.  Linux's WF_FORK/sched_exec/wakeup
/// paths keep this kind of foreground startup moving; here we approximate that
/// with a bounded, one-shot fair credit and stop after a small thread group so
/// thread storms do not continuously renew their parent.
pub fn prime_fair_thread_group_start(task: &Arc<TaskControlBlock>, thread_count: usize) {
    const THREAD_GROUP_STARTUP_MAX_THREADS: usize = 16;
    if thread_count > THREAD_GROUP_STARTUP_MAX_THREADS {
        return;
    }
    prime_fair_startup_credit(task, fair_startup_credit_cap_ns());
}
