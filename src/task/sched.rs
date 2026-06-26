//! 调度策略、优先级和辅助函数。
//!
//! 本模块定义了与 Linux 兼容的调度常量（SCHED_OTHER/SCHED_FIFO/SCHED_RR 等）、
//! 调度类别枚举[SchedClass]、优先级范围以及策略校验/转换辅助函数。

use core::sync::atomic::{AtomicI64, AtomicIsize, Ordering};

/// 调度类别：EEVDF 公平调度、FIFO 实时、RR 实时。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedClass {
    /// 公平调度类，内部采用 EEVDF 算法（vruntime/vlag/deadline/eligible），
    /// 对应 Linux SCHED_OTHER/SCHED_BATCH/SCHED_IDLE。
    Fair,
    /// 实时 FIFO：一旦获得 CPU 就运行直到主动放弃或被更高优先级 RT 任务抢占
    Fifo,
    /// 实时 RR：与 FIFO 类似，但有时间片轮转，时间片耗尽后让出 CPU
    Rr,
}

/// SCHED_OTHER — Linux 默认调度策略，即 EEVDF 公平调度。
pub const SCHED_OTHER: i32 = 0;
/// SCHED_FIFO — 实时先进先出调度策略，优先级范围 1-99。
pub const SCHED_FIFO: i32 = 1;
/// SCHED_RR — 实时时间片轮转调度策略，优先级范围 1-99。
pub const SCHED_RR: i32 = 2;
/// SCHED_BATCH — 批处理调度策略（公平调度子类），不抢占、适合吞吐量优先的负载。
pub const SCHED_BATCH: i32 = 3;
/// SCHED_IDLE — 空闲优先级调度策略（公平调度子类），仅在系统完全空闲时运行。
pub const SCHED_IDLE: i32 = 5;
/// SCHED_DEADLINE — 实时 deadline 调度策略（目前仅做参数校验，未实际调度）。
pub const SCHED_DEADLINE: i32 = 6;
/// Linux policy flag: reset privileged scheduling state in children after fork.
pub const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;
/// `sched_setattr(2)` flag corresponding to SCHED_RESET_ON_FORK.
pub const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;

/// POSIX nice 值下限：-20（最高优先级）。
pub const NICE_MIN: i32 = -20;
/// POSIX nice 值上限：19（最低优先级）。
pub const NICE_MAX: i32 = 19;
/// RT 优先级下限：1。
pub const RT_PRIO_MIN: i32 = 1;
/// RT 优先级上限：99。
pub const RT_PRIO_MAX: i32 = 99;
/// RT 优先级档次总数：99 档（1→99）。
pub const RT_PRIO_LEVELS: usize = (RT_PRIO_MAX - RT_PRIO_MIN + 1) as usize;

/// RR 时间片长度：100ms。
pub const RR_TIMESLICE_MS: isize = 100;
/// RR 时间片长度：以 tick（10ms）为单位，即 10 个 tick。
pub const RR_TIMESLICE_TICKS: usize = (RR_TIMESLICE_MS as usize) / 10;
/// Linux 默认 RT 调度周期：1s。
pub const RT_PERIOD_US_DEFAULT: i64 = 1_000_000;
/// Linux 默认 RT 调度运行时间：950ms。
pub const RT_RUNTIME_US_DEFAULT: i64 = 950_000;
const RT_SYSCTL_MAX_US: i64 = i32::MAX as i64;

// 这三个调度参数通过 /proc/sys/kernel/{sched_rr_timeslice_ms,sched_rt_period_us,
// sched_rt_runtime_us} 暴露给用户态、可在运行时修改（proc_sched_rt01 依赖）。
// 用原子量保存当前生效值，初值取上方的 Linux 默认常量。
/// RR 时间片长度
static RR_TIMESLICE_MS_CURRENT: AtomicIsize = AtomicIsize::new(RR_TIMESLICE_MS);
//. 每个period里 ，最多跑 runtime 个 时间,二者配合
static RT_PERIOD_US_CURRENT: AtomicI64 = AtomicI64::new(RT_PERIOD_US_DEFAULT);
static RT_RUNTIME_US_CURRENT: AtomicI64 = AtomicI64::new(RT_RUNTIME_US_DEFAULT);

/// RR 时间片长度，可设置
pub fn rr_timeslice_ms() -> isize {
    RR_TIMESLICE_MS_CURRENT.load(Ordering::Relaxed)
}

/// 当前 RR 时间片换算成 tick 数（10ms/tick，向上取整，至少 1）。
pub fn rr_timeslice_ticks() -> usize {
    core::cmp::max(1, (rr_timeslice_ms().max(1) as usize).div_ceil(10))
}

/// 写 `sched_rr_timeslice_ms`：`-1` 复位为默认值 `RR_TIMESLICE_MS`，否则取
/// `[1, i32::MAX]` 内的毫秒值；越界返回 `None`（上层转成 EINVAL）。
/// tldr:
/// 动态设置rr 时间片 长度
pub fn set_rr_timeslice_ms_from_procfs(value: i64) -> Option<isize> {
    let applied = if value == -1 {
        // 默认值
        RR_TIMESLICE_MS
    } else if (1..=RT_SYSCTL_MAX_US).contains(&value) {
        // 处于合法区间
        value as isize
    } else {
        return None;
    };
    RR_TIMESLICE_MS_CURRENT.store(applied, Ordering::Relaxed);
    Some(applied)
}

/// RT 时间片长度，可设置
pub fn rt_period_us() -> i64 {
    RT_PERIOD_US_CURRENT.load(Ordering::Relaxed)
}

/// RT 时间片运行时支持的最大 长度，可设置
pub fn rt_runtime_us() -> i64 {
    RT_RUNTIME_US_CURRENT.load(Ordering::Relaxed)
}

/// 写 `sched_rt_period_us`：取 `[1, i32::MAX]` 微秒，且不允许小于当前 runtime
/// （否则 runtime > period 不自洽）。越界或违反约束返回 `None`。
pub fn set_rt_period_us_from_procfs(value: i64) -> Option<i64> {
    if !(1..=RT_SYSCTL_MAX_US).contains(&value) {
        return None;
    }
    let runtime = rt_runtime_us();
    if runtime != -1 && runtime > value {
        return None;
    }
    RT_PERIOD_US_CURRENT.store(value, Ordering::Relaxed);
    Some(value)
}

/// 写 `sched_rt_runtime_us`：`-1` 表示关闭 RT 带宽限制（不 throttle），其余取
/// `[-1, i32::MAX]` 微秒且不得大于当前 period；违反约束返回 `None`。
/// tldr:设置rt 最大运行时
pub fn set_rt_runtime_us_from_procfs(value: i64) -> Option<i64> {
    if !(-1..=RT_SYSCTL_MAX_US).contains(&value) {
        return None;
    }
    if value != -1 && value > rt_period_us() {
        return None;
    }
    RT_RUNTIME_US_CURRENT.store(value, Ordering::Relaxed);
    Some(value)
}

/// 将 nice 值钳制在 [-20, 19] 范围内。
pub fn clamp_nice(nice: i32) -> i32 {
    nice.clamp(NICE_MIN, NICE_MAX)
}

/// 检查给定 policy 值是否为内核支持的调度策略。
///
/// 白名单：SCHED_OTHER(0) / FIFO(1) / RR(2) / BATCH(3) / IDLE(5) / DEADLINE(6)。
pub fn check_policy(policy: i32) -> bool {
    matches!(
        policy,
        SCHED_OTHER | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE
    )
}

/// 将 Linux 策略常量映射为内部[SchedClass]枚举。
///
/// FIFO/RR → Rt，OTHER/BATCH/IDLE → Fair，DEADLINE 等其他值 → None。
pub fn sched_class(policy: i32) -> Option<SchedClass> {
    match policy {
        SCHED_FIFO => Some(SchedClass::Fifo),
        SCHED_RR => Some(SchedClass::Rr),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => Some(SchedClass::Fair),
        _ => None,
    }
}

/// 返回给定策略允许的最低优先级。
///
/// FIFO/RR 返回 1（RT_PRIO_MIN），其他策略返回 0。
pub fn policy_priority_min(policy: i32) -> Option<i32> {
    match policy {
        SCHED_FIFO | SCHED_RR => Some(RT_PRIO_MIN),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Some(0),
        _ => None,
    }
}

/// 返回给定策略允许的最高优先级。
///
/// FIFO/RR 返回 99（RT_PRIO_MAX），其他策略返回 0。
pub fn policy_priority_max(policy: i32) -> Option<i32> {
    match policy {
        SCHED_FIFO | SCHED_RR => Some(RT_PRIO_MAX),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Some(0),
        _ => None,
    }
}

/// 检查给定优先级是否在指定策略的合法范围内。
pub fn valid_priority_for_policy(policy: i32, priority: i32) -> bool {
    match (policy_priority_min(policy), policy_priority_max(policy)) {
        (Some(min), Some(max)) => priority >= min && priority <= max,
        _ => false,
    }
}

/// 将 RT 优先级钳制在 [1, 99] 范围内。clamp,大于最大就是 最大
pub fn normalized_rt_priority(priority: i32) -> i32 {
    priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX)
}

/// 将 RT 优先级映射为就绪队列索引。
///
/// 索引 0 对应最高优先级(99)，索引 98 对应最低优先级(1)。
/// 这意味着遍历 `rt_queues` 时从前到后自然按优先级降序。
pub fn rt_queue_index(priority: i32) -> usize {
    (RT_PRIO_MAX - normalized_rt_priority(priority)) as usize
}
