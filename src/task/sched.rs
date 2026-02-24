#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedClass {
    Fair,
    Fifo,
    Rr,
}

pub const SCHED_OTHER: i32 = 0;
pub const SCHED_FIFO: i32 = 1;
pub const SCHED_RR: i32 = 2;
pub const SCHED_BATCH: i32 = 3;
pub const SCHED_IDLE: i32 = 5;
pub const SCHED_DEADLINE: i32 = 6;

pub const NICE_MIN: i32 = -20;
pub const NICE_MAX: i32 = 19;
pub const RT_PRIO_MIN: i32 = 1;
pub const RT_PRIO_MAX: i32 = 99;
pub const RT_PRIO_LEVELS: usize = (RT_PRIO_MAX - RT_PRIO_MIN + 1) as usize;

pub const RR_TIMESLICE_MS: isize = 100;
pub const RR_TIMESLICE_TICKS: usize = (RR_TIMESLICE_MS as usize) / 10;

pub fn clamp_nice(nice: i32) -> i32 {
    nice.clamp(NICE_MIN, NICE_MAX)
}

pub fn check_policy(policy: i32) -> bool {
    matches!(
        policy,
        SCHED_OTHER | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE
    )
}

pub fn sched_class(policy: i32) -> Option<SchedClass> {
    match policy {
        SCHED_FIFO => Some(SchedClass::Fifo),
        SCHED_RR => Some(SchedClass::Rr),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => Some(SchedClass::Fair),
        _ => None,
    }
}

pub fn policy_priority_min(policy: i32) -> Option<i32> {
    match policy {
        SCHED_FIFO | SCHED_RR => Some(RT_PRIO_MIN),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Some(0),
        _ => None,
    }
}

pub fn policy_priority_max(policy: i32) -> Option<i32> {
    match policy {
        SCHED_FIFO | SCHED_RR => Some(RT_PRIO_MAX),
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Some(0),
        _ => None,
    }
}

pub fn valid_priority_for_policy(policy: i32, priority: i32) -> bool {
    match (policy_priority_min(policy), policy_priority_max(policy)) {
        (Some(min), Some(max)) => priority >= min && priority <= max,
        _ => false,
    }
}

pub fn normalized_rt_priority(priority: i32) -> i32 {
    priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX)
}

pub fn rt_queue_index(priority: i32) -> usize {
    (RT_PRIO_MAX - normalized_rt_priority(priority)) as usize
}
