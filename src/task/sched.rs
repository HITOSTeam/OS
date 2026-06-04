//! 调度策略、优先级和辅助函数。
//!
//! 本模块定义了与 Linux 兼容的调度常量（SCHED_OTHER/SCHED_FIFO/SCHED_RR 等）、
//! 调度类别枚举[SchedClass]、优先级范围以及策略校验/转换辅助函数。

/// 调度类别：CFS 公平调度、FIFO 实时、RR 实时。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedClass {
    /// CFS 完全公平调度，对应 Linux SCHED_OTHER/SCHED_BATCH/SCHED_IDLE
    Fair,
    /// 实时 FIFO：一旦获得 CPU 就运行直到主动放弃或被更高优先级 RT 任务抢占
    Fifo,
    /// 实时 RR：与 FIFO 类似，但有时间片轮转，时间片耗尽后让出 CPU
    Rr,
}

/// SCHED_OTHER — Linux 默认调度策略，即 CFS 完全公平调度。
pub const SCHED_OTHER: i32 = 0;
/// SCHED_FIFO — 实时先进先出调度策略，优先级范围 1-99。
pub const SCHED_FIFO: i32 = 1;
/// SCHED_RR — 实时时间片轮转调度策略，优先级范围 1-99。
pub const SCHED_RR: i32 = 2;
/// SCHED_BATCH — 批处理调度策略（CFS 子类），不抢占、适合吞吐量优先的负载。
pub const SCHED_BATCH: i32 = 3;
/// SCHED_IDLE — 空闲优先级调度策略（CFS 子类），仅在系统完全空闲时运行。
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

/// 将 RT 优先级钳制在 [1, 99] 范围内。
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
