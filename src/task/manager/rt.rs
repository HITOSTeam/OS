use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::config::MAX_HARTS;
use crate::task::sched::{
    RT_PRIO_LEVELS, RT_PRIO_MAX, RT_PRIO_MIN, rt_period_us, rt_queue_index, rt_runtime_us,
};

use super::current_time_ns_usize;

/// 每个 hart 的 RT 可运行任务计数，索引方式与 `HartRunQueue::rt_queues` 一致。
///
/// Linux 会把每 CPU 的 RT 可运行状态放在运行队列附近，因此常见的
/// “是否有 RT 任务应该抢占我？”检查不需要扫描队列。这里维护精确计数，
/// 用于 tick/返回用户态时的抢占检查；真正的队列仍然是状态来源。
static READY_RT_COUNTS: [[AtomicUsize; RT_PRIO_LEVELS]; MAX_HARTS] =
    [const { [const { AtomicUsize::new(0) }; RT_PRIO_LEVELS] }; MAX_HARTS];
/// 与 Linux 兼容的 RT 带宽状态，每个运行队列一份。
///
/// Linux 默认 `sched_rt_period_us=1000000`、`sched_rt_runtime_us=950000`，
/// RT 调度类耗尽带宽后会被限流，让公平调度任务有机会运行。sysctl 值已经保存在
/// `task::sched` 中；这些原子变量是每 hart 的运行时间桶。
static RT_PERIOD_START_NS: [AtomicUsize; MAX_HARTS] = [const { AtomicUsize::new(0) }; MAX_HARTS];
static RT_RUNTIME_REMAINING_NS: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_HARTS];
static RT_THROTTLED: [AtomicBool; MAX_HARTS] = [const { AtomicBool::new(false) }; MAX_HARTS];
/// 每个 hart 的公平调度可运行任务计数。
///
/// 这对应上面的 RT 快路径，用于 syscall/tick 抢占检查。公平组队列仍然是
/// 状态来源；该计数器只是在每次返回用户态时避免为了回答
/// “这个 hart 是否有公平调度任务？”而获取全局调度器锁。
static READY_FAIR_COUNTS: [AtomicUsize; MAX_HARTS] = [const { AtomicUsize::new(0) }; MAX_HARTS];
const USEC_TO_NSEC: usize = 1_000;

fn rt_bandwidth_ns() -> Option<(usize, usize)> {
    let runtime_us = rt_runtime_us();
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

fn refresh_rt_bandwidth(hart_id: usize, now_ns: usize) -> bool {
    let hart = hart_id % MAX_HARTS;
    let Some((period_ns, runtime_ns)) = rt_bandwidth_ns() else {
        RT_PERIOD_START_NS[hart].store(now_ns, Ordering::Release);
        RT_RUNTIME_REMAINING_NS[hart].store(usize::MAX, Ordering::Release);
        RT_THROTTLED[hart].store(false, Ordering::Release);
        return false;
    };

    let mut period_start = RT_PERIOD_START_NS[hart].load(Ordering::Acquire);
    if period_start == 0 {
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

    let elapsed = now_ns.saturating_sub(period_start);
    if elapsed >= period_ns {
        let periods = elapsed / period_ns;
        let new_start = period_start.saturating_add(periods.saturating_mul(period_ns));
        RT_PERIOD_START_NS[hart].store(new_start, Ordering::Release);
        RT_RUNTIME_REMAINING_NS[hart].store(runtime_ns, Ordering::Release);
        let throttled = runtime_ns == 0;
        RT_THROTTLED[hart].store(throttled, Ordering::Release);
        return throttled;
    }

    let remaining = RT_RUNTIME_REMAINING_NS[hart].load(Ordering::Acquire);
    if remaining > runtime_ns {
        RT_RUNTIME_REMAINING_NS[hart].store(runtime_ns, Ordering::Release);
        let throttled = runtime_ns == 0;
        RT_THROTTLED[hart].store(throttled, Ordering::Release);
        return throttled;
    }
    let throttled = runtime_ns == 0 || remaining == 0 || RT_THROTTLED[hart].load(Ordering::Acquire);
    RT_THROTTLED[hart].store(throttled, Ordering::Release);
    throttled
}

pub fn rt_bandwidth_throttled(hart_id: usize) -> bool {
    refresh_rt_bandwidth(hart_id, current_time_ns_usize())
}

pub fn account_rt_runtime(hart_id: usize, delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    let hart = hart_id % MAX_HARTS;
    let now_ns = current_time_ns_usize();
    if refresh_rt_bandwidth(hart, now_ns) {
        return;
    }
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
                if next == 0 {
                    RT_THROTTLED[hart].store(true, Ordering::Release);
                }
                return;
            }
            Err(observed) => current = observed,
        }
    }
}

pub(super) fn inc_ready_rt_count(hart_id: usize, rt_idx: usize) {
    READY_RT_COUNTS[hart_id % MAX_HARTS][rt_idx].fetch_add(1, Ordering::Release);
}

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

pub(super) fn inc_ready_fair_count(hart_id: usize) {
    READY_FAIR_COUNTS[hart_id % MAX_HARTS].fetch_add(1, Ordering::Release);
}

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

pub(super) fn ready_fair_count(hart_id: usize) -> usize {
    READY_FAIR_COUNTS[hart_id % MAX_HARTS].load(Ordering::Acquire)
}

pub(super) fn has_ready_rt_count_higher_than(hart_id: usize, priority: i32) -> bool {
    if rt_bandwidth_throttled(hart_id) {
        return false;
    }
    let idx = rt_queue_index(priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX));
    READY_RT_COUNTS[hart_id % MAX_HARTS][..idx]
        .iter()
        .any(|counter| counter.load(Ordering::Acquire) > 0)
}

pub(super) fn has_ready_rt_count_at_or_above(hart_id: usize, priority: i32) -> bool {
    if rt_bandwidth_throttled(hart_id) {
        return false;
    }
    let idx = rt_queue_index(priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX));
    READY_RT_COUNTS[hart_id % MAX_HARTS][..=idx]
        .iter()
        .any(|counter| counter.load(Ordering::Acquire) > 0)
}
