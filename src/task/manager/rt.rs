use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::config::MAX_HARTS;
use crate::task::sched::{
    RT_PRIO_LEVELS, RT_PRIO_MAX, RT_PRIO_MIN, rt_period_us, rt_queue_index, rt_runtime_us,
};

use super::current_time_ns_usize;

/// 每个 hart 的 RT 可运行任务计数，索引方式与 `HartRunQueue::rt_queues` 一致。
///
/// `READY_RT_COUNTS[hart][rt_idx]` 表示该 hart 上第 `rt_idx` 个优先级桶中
/// 当前处于就绪态的 RT 任务数。`rt_idx=0` 对应最高 RT 优先级（99），
/// `rt_idx=98` 对应最低（1），与 `rt_queue_index()` 的反序一致。
///
/// Linux 会把每 CPU 的 RT 可运行状态放在运行队列附近，因此常见的
/// “是否有 RT 任务应该抢占我？”检查不需要扫描队列。这里维护精确计数，
/// 用于 tick/返回用户态时的抢占检查（`has_ready_rt_count_higher_than` 等）；
/// 真正的队列仍然是状态来源，计数只是无锁快路径缓存。
static READY_RT_COUNTS: [[AtomicUsize; RT_PRIO_LEVELS]; MAX_HARTS] =
    [const { [const { AtomicUsize::new(0) }; RT_PRIO_LEVELS] }; MAX_HARTS];

/// 当前 RT 带宽周期的起始时间（纳秒），每个 hart 一份。
///
/// 周期长度由 `sched_rt_period_us`（默认 1s）决定。当 `now - period_start >= period`
/// 时进入新周期，`RT_RUNTIME_REMAINING_NS` 重置为完整额度。初始值 0 表示
/// 尚未初始化，首次调用 `refresh_rt_bandwidth` 时用 CAS 设为当前时间。
static RT_PERIOD_START_NS: [AtomicUsize; MAX_HARTS] = [const { AtomicUsize::new(0) }; MAX_HARTS];

/// 当前周期内 RT 调度类还能运行多少纳秒，每个 hart 一份。
///
/// 每次 `account_rt_runtime` 会从中扣减 RT 任务实际运行时间。减到 0 时
/// 置位 `RT_THROTTLED`，`fetch` 跳过 RT 队列，让 fair 类得到执行。
/// 新周期开始时重置为 `sched_rt_runtime_us`（默认 950ms）对应的纳秒值。
/// 若 `rt_runtime_us < 0`（禁用限流），则设为 `usize::MAX` 表示无限。
static RT_RUNTIME_REMAINING_NS: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_HARTS];

/// 该 hart 的 RT 调度类是否已被节流（带宽耗尽）。
///
/// 为 true 时 `fetch` 跳过 RT 队列直接选 fair；tick 抢占检查
/// （`has_ready_rt_count_*`）也直接返回 false，不再因 RT 任务而请求抢占。
/// 新周期开始或 `rt_runtime_us < 0` 时清零。
static RT_THROTTLED: [AtomicBool; MAX_HARTS] = [const { AtomicBool::new(false) }; MAX_HARTS];

/// 每个 hart 的公平调度可运行任务计数。
///
/// 这对应上面的 RT 快路径，用于 syscall/tick 抢占检查。公平组队列仍然是
/// 状态来源；该计数器只是在每次返回用户态时避免为了回答
/// “这个 hart 是否有公平调度任务？”而获取全局调度器锁。
///
/// `fair_current_deadline_expired` 会先检查它是否为 0：若没有 fair 竞争者，
/// 当前 fair 任务即使 deadline 到了也不需要让出 CPU。
static READY_FAIR_COUNTS: [AtomicUsize; MAX_HARTS] = [const { AtomicUsize::new(0) }; MAX_HARTS];

/// 微秒到纳秒的换算因子。
const USEC_TO_NSEC: usize = 1_000;

/// 将 sysctl 中的 `sched_rt_period_us` / `sched_rt_runtime_us` 换算为纳秒对。
///
/// 返回 `(period_ns, runtime_ns)`：
/// - `period_ns`：周期长度，至少 1ns，防止除零。
/// - `runtime_ns`：周期内 RT 允许运行的上限，不超过 `period_ns`。
///
/// 若 `rt_runtime_us < 0`（用户设为 -1 表示禁用 RT 限流），返回 `None`，
/// 调用方据此将 `RT_RUNTIME_REMAINING_NS` 设为 `usize::MAX` 并永不节流。
fn rt_bandwidth_ns() -> Option<(usize, usize)> {
    let runtime_us = rt_runtime_us();
    // 表示不限制 RT
    if runtime_us < 0 {
        return None;
    }
    let period_us = rt_period_us().max(1) as usize;
    let period_ns = period_us.saturating_mul(USEC_TO_NSEC).max(1);
    let runtime_ns = (runtime_us.max(0) as usize)
        .saturating_mul(USEC_TO_NSEC)
        .min(period_ns);
    Some((period_ns, runtime_ns))
}

/// 刷新指定 hart 的 RT 带宽状态，返回当前是否处于节流。
///
/// 这是 RT 带宽机制的核心，在每次 `fetch` / `account_rt_runtime` / 抢占检查
/// 时调用。它处理三种情况：
///
/// 1. **首次初始化**（`period_start == 0`）：用 CAS 将周期起点设为当前时间，
///    发放完整额度。CAS 失败说明另一个核已初始化，用观察到的值继续。
///
/// 2. **周期已过**（`elapsed >= period_ns`）：按整周期数推进 `period_start`，
///    重置 `remaining` 为完整额度，清除节流标志。这样即使多个周期没刷新
///    也能正确跳到当前周期，不会累积欠额。
///
/// 3. **周期内**：检查 `remaining` 是否异常超过 `runtime_ns`（可能是 sysctl
///    被调小），若超限则截断。最终节流状态 = `runtime_ns == 0`（额度为零）
///    或 `remaining == 0`（用完了）或已被标记节流。
///
/// 返回 `true` 表示该 hart 的 RT 类当前被节流，`fetch` 应跳过 RT 队列。
fn refresh_rt_bandwidth(hart_id: usize, now_ns: usize) -> bool {
    let hart = hart_id % MAX_HARTS;
    // 禁用限流模式（rt_runtime_us < 0）：额度无限，永不节流。
    let Some((period_ns, runtime_ns)) = rt_bandwidth_ns() else {
        // 如果不限制 rt 那就始终返回false 即可
        RT_PERIOD_START_NS[hart].store(now_ns, Ordering::Release);
        RT_RUNTIME_REMAINING_NS[hart].store(usize::MAX, Ordering::Release);
        RT_THROTTLED[hart].store(false, Ordering::Release);
        return false;
    };

    // 情况 1：首次初始化，周期起点从 0 设为当前时间。
    let mut period_start = RT_PERIOD_START_NS[hart].load(Ordering::Acquire);
    if period_start == 0 {
        // 第一次开始，设置 当前时间
        match RT_PERIOD_START_NS[hart].compare_exchange(
            0,
            now_ns,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                RT_RUNTIME_REMAINING_NS[hart].store(runtime_ns, Ordering::Release);
                let throttled = runtime_ns == 0;
                RT_THROTTLED[hart].store(throttled, Ordering::Release);
                return throttled;
            }
            Err(observed) => period_start = observed,
        }
    }

    // 情况 2：周期已过，按整周期推进起点并重置额度。
    let elapsed = now_ns.saturating_sub(period_start);
    if elapsed >= period_ns {
        // 这里是为了对齐
        let periods = elapsed / period_ns;
        let new_start = period_start.saturating_add(periods.saturating_mul(period_ns));
        RT_PERIOD_START_NS[hart].store(new_start, Ordering::Release);
        RT_RUNTIME_REMAINING_NS[hart].store(runtime_ns, Ordering::Release);
        let throttled = runtime_ns == 0;
        RT_THROTTLED[hart].store(throttled, Ordering::Release);
        return throttled;
    }

    // 情况 3：周期内。若 remaining 异常超过 runtime_ns（sysctl 被调小），
    // 截断到新上限。
    let remaining = RT_RUNTIME_REMAINING_NS[hart].load(Ordering::Acquire);
    if remaining > runtime_ns {
        RT_RUNTIME_REMAINING_NS[hart].store(runtime_ns, Ordering::Release);
        let throttled = runtime_ns == 0;
        RT_THROTTLED[hart].store(throttled, Ordering::Release);
        return throttled;
    }
    // 节流判定：额度为零 || 剩余为零 || 已标记节流。
    let throttled = runtime_ns == 0 || remaining == 0 || RT_THROTTLED[hart].load(Ordering::Acquire);
    RT_THROTTLED[hart].store(throttled, Ordering::Release);
    throttled
}

/// 查询指定 hart 的 RT 调度类是否被节流。
///
/// 这是 `fetch` / 抢占检查路径的入口：先调 `refresh_rt_bandwidth` 更新状态
/// （可能跨过周期边界解除节流），再返回当前节流标志。被节流时 `fetch`
/// 跳过 RT 队列，直接从 fair 类选任务，保证普通任务不被 RT 饿死。
pub fn rt_bandwidth_throttled(hart_id: usize) -> bool {
    refresh_rt_bandwidth(hart_id, current_time_ns_usize())
}

/// 从该 hart 的 RT 带宽额度中扣减 RT 任务实际运行的时间。
///
/// 在每次 tick 对当前 RT 任务调用（`charge_task_runtime_for_scheduler`）。
/// 流程：
/// 1. 先 `refresh_rt_bandwidth` 更新状态——如果已经节流则直接返回，
///    不再扣减（节流期间 RT 不跑，不应再扣）。
/// 2. 用 CAS 循环从 `RT_RUNTIME_REMAINING_NS` 中减去 `delta_ns`，
///    `saturating_sub` 保证不减到负数。
/// 3. 若扣减后 `remaining == 0`，置位 `RT_THROTTLED`，下一次 `fetch`
///    就会跳过 RT，让 fair 得到执行。
///
/// CAS 循环处理多核同时扣减的竞态：若中间被别的核改了，重载当前值重试。
pub fn account_rt_runtime(hart_id: usize, delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    let hart = hart_id % MAX_HARTS;
    let now_ns = current_time_ns_usize();
    // 已节流则不扣减（节流期间不应有 RT 运行；若刚跨周期解除节流，
    // refresh 会重置额度，下面的扣减从新额度开始）。
    if refresh_rt_bandwidth(hart, now_ns) {
        return;
    }
    // 禁用限流模式不扣减。
    if rt_bandwidth_ns().is_none() {
        return;
    }

    let delta = delta_ns.min(usize::MAX as u64) as usize;
    let counter = &RT_RUNTIME_REMAINING_NS[hart];
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.saturating_sub(delta);
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                // 额度耗尽，立刻节流。下一个 fetch 就会跳过 RT。
                if next == 0 {
                    RT_THROTTLED[hart].store(true, Ordering::Release);
                }
                return;
            }
            Err(observed) => current = observed,
        }
    }
}

/// 将一个 RT 任务加入某 hart 的就绪队列时，递增对应优先级桶的计数。
///
/// 由 `TaskManager::add` 在 RT 入队路径调用。之后抢占检查
/// （`has_ready_rt_count_*`）可以 O(1) 判断该 hart 是否有更高优先级
/// RT 任务就绪，无需扫描 `rt_queues`。
pub(super) fn inc_ready_rt_count(hart_id: usize, rt_idx: usize) {
    READY_RT_COUNTS[hart_id % MAX_HARTS][rt_idx].fetch_add(1, Ordering::Release);
}

/// 将一个 RT 任务移出某 hart 的就绪队列时，递减对应优先级桶的计数。
///
/// CAS 循环防止多核同时出队导致的下溢：若中间被改了就重载重试，
/// 且不会减到负数（`while current > 0` 保护）。
pub(super) fn dec_ready_rt_count(hart_id: usize, rt_idx: usize) {
    let counter = &READY_RT_COUNTS[hart_id % MAX_HARTS][rt_idx];
    let mut current = counter.load(Ordering::Acquire);
    while current > 0 {
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// 将一个 fair 任务加入某 hart 的就绪队列时，递增 fair 就绪计数。
///
/// `fair_current_deadline_expired` 用它快速判断"是否有 fair 竞争者"：
/// 若计数为 0，当前 fair 任务即使 deadline 到了也无需让出（没有别人可换）。
pub(super) fn inc_ready_fair_count(hart_id: usize) {
    READY_FAIR_COUNTS[hart_id % MAX_HARTS].fetch_add(1, Ordering::Release);
}

/// 将一个 fair 任务移出某 hart 的就绪队列时，递减 fair 就绪计数。
///
/// CAS 循环防止多核同时出队导致的下溢，逻辑同 `dec_ready_rt_count`。
pub(super) fn dec_ready_fair_count(hart_id: usize) {
    let counter = &READY_FAIR_COUNTS[hart_id % MAX_HARTS];
    let mut current = counter.load(Ordering::Acquire);
    while current > 0 {
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// 返回指定 hart 当前就绪的 fair 任务数量。
///
/// 无锁读取，用于 tick/syscall 返回时的快速抢占判定，避免获取调度器锁。
/// 真实状态以 `HartRunQueue::fair_groups` 为准，此计数只是增量维护的缓存。
pub(super) fn ready_fair_count(hart_id: usize) -> usize {
    READY_FAIR_COUNTS[hart_id % MAX_HARTS].load(Ordering::Acquire)
}

/// 查询该 hart 上是否有**严格高于** `priority` 的 RT 任务就绪。
///
/// 用于 tick 抢占判定：当前 RT 任务跑着，检查是否有更高优先级 RT
/// 醒来应该抢占。`rt_queue_index` 把 RT 优先级反序成桶索引
/// （99→0, 1→98），所以 `..idx` 是所有比 `priority` 更高优先级的桶。
///
/// 若 RT 被节流则直接返回 false——节流期间 RT 不应抢占任何人。
pub(super) fn has_ready_rt_count_higher_than(hart_id: usize, priority: i32) -> bool {
    if rt_bandwidth_throttled(hart_id) {
        return false;
    }
    let idx = rt_queue_index(priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX));
    READY_RT_COUNTS[hart_id % MAX_HARTS][..idx]
        .iter()
        .any(|counter| counter.load(Ordering::Acquire) > 0)
}

/// 查询该 hart 上是否有**高于或等于** `priority` 的 RT 任务就绪。
///
/// 用于唤醒抢占判定：被唤醒的 RT 任务优先级为 `priority`，检查当前
/// 队列里是否有同优先级或更高的就绪任务。`..=idx` 包含了 `idx` 自身
/// （同优先级），因为 RT FIFO 同优先级按入队顺序，新唤醒的排后面，
/// 不应抢占正在跑的同优先级任务——但这个函数只回答"有没有"，
/// 具体能否抢占由调用方结合其他条件决定。
///
/// 若 RT 被节流则直接返回 false。
pub(super) fn has_ready_rt_count_at_or_above(hart_id: usize, priority: i32) -> bool {
    if rt_bandwidth_throttled(hart_id) {
        return false;
    }
    let idx = rt_queue_index(priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX));
    READY_RT_COUNTS[hart_id % MAX_HARTS][..=idx]
        .iter()
        .any(|counter| counter.load(Ordering::Acquire) > 0)
}
