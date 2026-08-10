// this is used for sleep (blocked) threads
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use core::{cmp::Ordering, time};

use crate::task::signal::{SIGALRM_NUM, pick_task_for_signal, queue_process_signal, signal_bit};
use crate::{
    config::MAX_HARTS,
    task::{
        manager::{prime_fair_timer_wakeup_lag, wakeup_task},
        task_block::TaskControlBlock,
    },
    time::{arm_timer_for_deadline_ns, get_time_ms, get_time_ns},
};
use alloc::{
    collections::{BTreeMap, BinaryHeap},
    sync::{Arc, Weak},
    vec::Vec,
};
use lazy_static::*;
use spin::Mutex;

use crate::debug_config::{DEBUG_TIMER, DEBUG_UNIXBENCH};
use crate::task::process_block::ProcessControlBlock;
use crate::{
    arch, mm::write_user_value, syscall::futex::futex_wake_private_and_shared,
    task::manager::pid2process,
};

// POSIX 时钟常量，对应 Linux 的 `clockid_t` 取值：
// `CLOCK_REALTIME`/`CLOCK_MONOTONIC` 走墙钟/单调钟的截止时间堆，
// `CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID` 走 CPU 时间桶。
const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const CLOCK_PROCESS_CPUTIME_ID: usize = 2;
const CLOCK_THREAD_CPUTIME_ID: usize = 3;

/// 睡眠定时器堆中的条目，包装一个被阻塞任务及其到期时间。
///
/// `task_key` 用 `Arc` 指针值做去重标识，`timer_seq` 配合任务自身的
/// `sleep_timer_seq` 检测过期条目（任务可能在中途被对象等待提前唤醒，
/// 旧定时器需作废），避免唤醒已重新进入睡眠的任务。
pub struct TimeWrap {
    /// 被阻塞任务的弱引用，到期时尝试升级并唤醒。
    pub task: Weak<TaskControlBlock>,
    /// `Arc<TaskControlBlock>` 的指针值，用于按任务去重。
    pub task_key: usize,
    /// 该定时器创建时从任务取到的序列号，用于作废过期条目。
    pub timer_seq: u64,
    /// 任务在创建时的 tid，仅用于调试日志。
    pub tid: usize,
    /// 绝对到期时间（纳秒）。
    pub time_expired_ns: u64,
}

impl TimeWrap {
    /// 以毫秒为单位构造一个睡眠定时器条目，内部转成纳秒。
    fn new(task: Arc<TaskControlBlock>, time_wait: usize) -> Self {
        Self::new_ns(task, (time_wait as u64).saturating_mul(1_000_000).max(1))
    }

    /// 以纳秒为单位构造一个睡眠定时器条目，记录任务指针、序列号与到期时间。
    fn new_ns(task: Arc<TaskControlBlock>, time_wait_ns: u64) -> Self {
        let task_key = Arc::as_ptr(&task) as usize;
        let timer_seq = task.next_sleep_timer_seq();
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        Self {
            task: Arc::downgrade(&task),
            task_key,
            timer_seq,
            tid,
            time_expired_ns: get_time_ns().saturating_add(time_wait_ns.max(1)),
        }
    }
}

impl PartialEq for TimeWrap {
    fn eq(&self, other: &Self) -> bool {
        self.time_expired_ns == other.time_expired_ns
    }
}
impl Eq for TimeWrap {}
impl PartialOrd for TimeWrap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for TimeWrap {
    fn cmp(&self, other: &Self) -> Ordering {
        other.time_expired_ns.cmp(&self.time_expired_ns)
    }
}

lazy_static! {
    /// 睡眠定时器最小堆，按 `time_expired_ns` 升序弹出最早到期的任务。
    pub static ref TIMERS: Mutex<BinaryHeap<TimeWrap>> = Mutex::new(BinaryHeap::<TimeWrap>::new());
}

/// alarm/itimer 定时器条目，到期后向目标进程投递信号。
#[derive(Clone, Copy)]
struct AlarmTimer {
    pid: usize,
    /// itimer 的 which 索引（ITIMER_REAL=0 等），用于区分同一进程的不同 itimer。
    which: usize,
    signum: usize,
    /// 绝对到期时间（毫秒）。
    deadline_ms: usize,
    /// 周期重装间隔（毫秒），0 表示一次性定时器。
    interval_ms: usize,
}

lazy_static! {
    /// 全部 alarm/itimer 定时器的列表。
    static ref ALARM_TIMERS: Mutex<Vec<AlarmTimer>> = Mutex::new(Vec::new());
}

/// 延迟清理用户态 `ctid` 的条目。
///
/// clone(CLONE_CHILD_CLEARTID) 要求线程退出时清零用户态 tid 字段并唤醒
/// futex；但线程结构自身的回收与用户态写操作存在时序冲突，故推迟一段
/// 时间后再执行清理，避免误写已释放的内存。
#[derive(Clone, Copy)]
struct DelayedTidClear {
    pid: usize,
    /// 用户态需要被清零的 tid 地址。
    ctid: usize,
    /// 绝对到期时间（毫秒）。
    deadline_ms: usize,
}

lazy_static! {
    /// 待执行的延迟 ctid 清理条目列表。
    static ref DELAYED_TID_CLEARS: Mutex<Vec<DelayedTidClear>> = Mutex::new(Vec::new());
}

/// POSIX 定时器（`timer_create`/`timer_settime`）的内核表示。
#[derive(Clone, Copy)]
struct PosixTimer {
    pid: usize,
    /// 全局唯一的定时器 id，由 `NEXT_POSIX_TIMER_ID` 分配。
    timer_id: usize,
    clock_id: usize,
    /// 仅对 CPU 时间钟有意义，绑定的线程 tid；为 `None` 表示进程级。
    thread_tid: Option<usize>,
    signum: usize,
    /// 当前装定的绝对截止时间（纳秒），`None` 表示未装定。
    deadline_ns: Option<u64>,
    /// 周期重装间隔（纳秒），0 表示一次性。
    interval_ns: u64,
    /// 累积未投递的溢出次数，由 `timer_getoverrun` 读取。
    overrun: usize,
    /// 调度序列号，每次重装自增，用于让过期调度堆条目失效。
    schedule_seq: u64,
}

lazy_static! {
    /// POSIX 定时器表，按 `(pid, timer_id)` 索引。
    static ref POSIX_TIMERS: Mutex<PosixTimerState> = Mutex::new(PosixTimerState::default());
    /// CPU 时间钟（进程/线程 CPU 时间）的桶状态，按 pid/tid 分组管理到期时间。
    static ref POSIX_CPU_TIMER_STATE: Mutex<PosixCpuTimerState> =
        Mutex::new(PosixCpuTimerState::default());
    /// POSIX 定时器的截止时间堆，墙钟与单调钟各一个。
    static ref POSIX_TIMER_SCHEDULE: Mutex<PosixTimerScheduleState> =
        Mutex::new(PosixTimerScheduleState::default());
}

/// 下一个可分配的 POSIX 定时器 id（从 1 起，0 被视为无效）。
static NEXT_POSIX_TIMER_ID: AtomicUsize = AtomicUsize::new(1);
/// 每 hart 一个的“延迟内核定时器 tick”标志。
///
/// 内核态中断期间不能直接调 `check_timer()`（可能持锁死锁），故只置位，
/// 由 idle/返回用户态前的安全点处理，对应 Linux 的 `run_local_timers`。
static DEFERRED_KERNEL_TIMER_TICK: [AtomicBool; MAX_HARTS] =
    [const { AtomicBool::new(false) }; MAX_HARTS];
/// 当前已装入睡眠定时器堆的活跃条目数，用于快速判断是否有睡眠定时器待处理。
static SLEEP_TIMER_ACTIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
/// 睡眠定时器堆的最近截止时间（纳秒），无定时器时为 `usize::MAX`，供返回用户态前快速判断。
static SLEEP_TIMER_NEXT_DEADLINE_NS: AtomicUsize = AtomicUsize::new(usize::MAX);
/// 当前活跃的 alarm/itimer 条目数。
static ALARM_TIMER_ACTIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
/// alarm/itimer 的最近截止时间（毫秒），无条目时为 `usize::MAX`。
static ALARM_TIMER_NEXT_DEADLINE_MS: AtomicUsize = AtomicUsize::new(usize::MAX);
/// 待执行的延迟 ctid 清理条目数。
static DELAYED_TID_CLEAR_COUNT: AtomicUsize = AtomicUsize::new(0);
/// 延迟 ctid 清理的最近截止时间（毫秒），无条目时为 `usize::MAX`。
static DELAYED_TID_CLEAR_NEXT_DEADLINE_MS: AtomicUsize = AtomicUsize::new(usize::MAX);
/// 已装入截止时间堆的活跃 POSIX 定时器数（墙钟+单调钟）。
static POSIX_TIMER_ACTIVE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// POSIX 定时器存储，用 `Vec` + 索引映射实现 O(log n) 增删查。
#[derive(Default)]
struct PosixTimerState {
    timers: Vec<PosixTimer>,
    timer_index: BTreeMap<(usize, usize), usize>,
}

impl PosixTimerState {
    /// 插入一个新 POSIX 定时器，建立 `(pid, timer_id)` 到下标的索引。
    fn insert(&mut self, timer: PosixTimer) {
        let idx = self.timers.len();
        self.timer_index.insert((timer.pid, timer.timer_id), idx);
        self.timers.push(timer);
    }

    /// 按 `(pid, timer_id)` 查询定时器的不可变引用。
    fn get(&self, pid: usize, timer_id: usize) -> Option<&PosixTimer> {
        let idx = *self.timer_index.get(&(pid, timer_id))?;
        self.timers.get(idx)
    }

    /// 按 `(pid, timer_id)` 查询定时器的可变引用。
    fn get_mut(&mut self, pid: usize, timer_id: usize) -> Option<&mut PosixTimer> {
        let idx = *self.timer_index.get(&(pid, timer_id))?;
        self.timers.get_mut(idx)
    }

    /// 按 `(pid, timer_id)` 移除定时器。
    ///
    /// 使用 `swap_remove` 保持 O(1)，并修复被搬动条目的索引映射。
    fn remove(&mut self, pid: usize, timer_id: usize) -> Option<PosixTimer> {
        let idx = self.timer_index.remove(&(pid, timer_id))?;
        let timer = self.timers.swap_remove(idx);
        if let Some(moved) = self.timers.get(idx) {
            self.timer_index.insert((moved.pid, moved.timer_id), idx);
        }
        Some(timer)
    }
}

/// CPU 时间钟的桶键，区分进程级与线程级。
#[derive(Clone, Copy)]
enum PosixCpuTimerBucketKey {
    Process { pid: usize },
    Thread { pid: usize, tid: usize },
}

/// 同一进程/线程下所有 CPU 时间钟定时器的桶，记录各自到期时间并维护最早截止时间。
struct PosixCpuTimerBucket {
    timers: BTreeMap<(usize, usize), u64>,
    /// 本桶内最早的到期时间（纳秒），无定时器时为 `u64::MAX`。
    next_deadline_ns: u64,
}

impl Default for PosixCpuTimerBucket {
    fn default() -> Self {
        Self {
            timers: BTreeMap::new(),
            next_deadline_ns: u64::MAX,
        }
    }
}

impl PosixCpuTimerBucket {
    /// 重新计算本桶的最早截止时间，在增删条目后调用以保持快速判断。
    fn refresh_next_deadline(&mut self) {
        self.next_deadline_ns = self.timers.values().copied().min().unwrap_or(u64::MAX);
    }
}

/// CPU 时间钟桶的快照，用于在不长期持锁的情况下扫描到期条目。
#[derive(Clone)]
struct PosixCpuTimerBucketSnapshot {
    clock_id: usize,
    pid: usize,
    thread_tid: Option<usize>,
    next_deadline_ns: u64,
    timers: Vec<(usize, usize)>,
}

/// CPU 时间钟状态，按进程和线程两个维度组织桶。
#[derive(Default)]
struct PosixCpuTimerState {
    process: BTreeMap<usize, PosixCpuTimerBucket>,
    thread: BTreeMap<(usize, usize), PosixCpuTimerBucket>,
}

impl PosixCpuTimerState {
    /// 取得指定键对应的桶，不存在则插入空桶。
    fn bucket_mut(&mut self, key: PosixCpuTimerBucketKey) -> &mut PosixCpuTimerBucket {
        match key {
            PosixCpuTimerBucketKey::Process { pid } => self.process.entry(pid).or_default(),
            PosixCpuTimerBucketKey::Thread { pid, tid } => {
                self.thread.entry((pid, tid)).or_default()
            }
        }
    }

    /// 插入或更新一个 CPU 时间钟定时器的截止时间，并刷新桶的最早截止时间。
    fn insert_or_update(
        &mut self,
        key: PosixCpuTimerBucketKey,
        timer_key: (usize, usize),
        deadline_ns: u64,
    ) {
        let bucket = self.bucket_mut(key);
        bucket.timers.insert(timer_key, deadline_ns);
        bucket.refresh_next_deadline();
    }

    /// 移除一个 CPU 时间钟定时器；若桶空则一并删除桶，否则刷新最早截止时间。
    fn remove(&mut self, key: PosixCpuTimerBucketKey, timer_key: (usize, usize)) {
        match key {
            PosixCpuTimerBucketKey::Process { pid } => {
                let Some(bucket) = self.process.get_mut(&pid) else {
                    return;
                };
                bucket.timers.remove(&timer_key);
                if bucket.timers.is_empty() {
                    self.process.remove(&pid);
                } else {
                    bucket.refresh_next_deadline();
                }
            }
            PosixCpuTimerBucketKey::Thread { pid, tid } => {
                let Some(bucket) = self.thread.get_mut(&(pid, tid)) else {
                    return;
                };
                bucket.timers.remove(&timer_key);
                if bucket.timers.is_empty() {
                    self.thread.remove(&(pid, tid));
                } else {
                    bucket.refresh_next_deadline();
                }
            }
        }
    }

    /// 收集所有桶的快照，供后续在不持锁的情况下扫描到期条目。
    fn snapshots(&self) -> Vec<PosixCpuTimerBucketSnapshot> {
        let mut snapshots = Vec::new();
        for (&pid, bucket) in self.process.iter() {
            snapshots.push(PosixCpuTimerBucketSnapshot {
                clock_id: CLOCK_PROCESS_CPUTIME_ID,
                pid,
                thread_tid: None,
                next_deadline_ns: bucket.next_deadline_ns,
                timers: bucket.timers.keys().copied().collect(),
            });
        }
        for (&(pid, tid), bucket) in self.thread.iter() {
            snapshots.push(PosixCpuTimerBucketSnapshot {
                clock_id: CLOCK_THREAD_CPUTIME_ID,
                pid,
                thread_tid: Some(tid),
                next_deadline_ns: bucket.next_deadline_ns,
                timers: bucket.timers.keys().copied().collect(),
            });
        }
        snapshots
    }

    /// 是否存在已装定的 CPU 时间钟定时器。
    fn has_armed_timers(&self) -> bool {
        !self.process.is_empty() || !self.thread.is_empty()
    }
}

/// POSIX 定时器截止时间堆中的一个调度条目。
#[derive(Clone, Copy)]
struct PosixTimerScheduleEntry {
    deadline_ns: u64,
    /// 与 `PosixTimer.schedule_seq` 对应，用于让过期条目失效。
    sequence: u64,
    pid: usize,
    timer_id: usize,
}

impl PartialEq for PosixTimerScheduleEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_ns == other.deadline_ns
            && self.sequence == other.sequence
            && self.pid == other.pid
            && self.timer_id == other.timer_id
    }
}

impl Eq for PosixTimerScheduleEntry {}

impl PartialOrd for PosixTimerScheduleEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PosixTimerScheduleEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deadline_ns
            .cmp(&self.deadline_ns)
            .then_with(|| other.sequence.cmp(&self.sequence))
            .then_with(|| other.pid.cmp(&self.pid))
            .then_with(|| other.timer_id.cmp(&self.timer_id))
    }
}

/// POSIX 定时器调度状态，墙钟与单调钟各维护一个截止时间堆及活跃计数。
#[derive(Default)]
struct PosixTimerScheduleState {
    monotonic: BinaryHeap<PosixTimerScheduleEntry>,
    realtime: BinaryHeap<PosixTimerScheduleEntry>,
    monotonic_armed: usize,
    realtime_armed: usize,
}

impl PosixTimerScheduleState {
    /// 根据定时器装定状态变化调整对应时钟的活跃计数。
    ///
    /// 该计数用于在不peek堆的情况下快速判断某时钟是否有待处理到期。
    fn adjust_armed(&mut self, clock_id: usize, was_armed: bool, is_armed: bool) {
        if was_armed == is_armed {
            return;
        }
        let armed = match clock_id {
            CLOCK_MONOTONIC => &mut self.monotonic_armed,
            CLOCK_REALTIME => &mut self.realtime_armed,
            _ => return,
        };
        if is_armed {
            *armed = armed.saturating_add(1);
        } else {
            *armed = armed.saturating_sub(1);
        }
    }
}

/// 取得 POSIX 定时器当前时钟读数（纳秒），CPU 时间钟需要 pid/tid 上下文。
fn posix_timer_now_ns(timer: &PosixTimer) -> Option<u64> {
    crate::syscall::timer_clock_now_ns(timer.clock_id, timer.pid, timer.thread_tid)
}

/// 按时钟 id 取得对应的截止时间堆的可变引用，仅墙钟/单调钟走堆。
fn posix_schedule_heap_mut(
    state: &mut PosixTimerScheduleState,
    clock_id: usize,
) -> Option<&mut BinaryHeap<PosixTimerScheduleEntry>> {
    match clock_id {
        CLOCK_MONOTONIC => Some(&mut state.monotonic),
        CLOCK_REALTIME => Some(&mut state.realtime),
        _ => None,
    }
}

/// 该时钟是否走截止时间堆（墙钟与单调钟）。
fn posix_timer_uses_deadline_heap(clock_id: usize) -> bool {
    matches!(clock_id, CLOCK_MONOTONIC | CLOCK_REALTIME)
}

/// 该时钟是否走 CPU 时间桶（进程/线程 CPU 时间钟）。
fn posix_timer_uses_cpu_bucket(clock_id: usize) -> bool {
    matches!(clock_id, CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID)
}

/// 针对墙钟/单调钟的截止时间，换算成内核单调钟的绝对时间后装定硬件定时器。
///
/// 墙钟/单调钟读数与内核 `get_time_ns`（单调）可能不同，故需先求相对 delta
/// 再叠加到当前内核时间上。
fn arm_clockevent_for_deadline(clock_id: usize, deadline_ns: u64) {
    if !posix_timer_uses_deadline_heap(clock_id) {
        return;
    }
    let Some(clock_now_ns) = crate::syscall::timer_clock_now_ns(clock_id, 0, None) else {
        return;
    };
    let delta_ns = deadline_ns.saturating_sub(clock_now_ns).max(1);
    arm_timer_for_deadline_ns(get_time_ns().saturating_add(delta_ns));
}

/// 将毫秒截止时间转成纳秒后装定硬件定时器（用于 alarm/itimer 等单调钟场景）。
fn arm_monotonic_deadline_ms(deadline_ms: usize) {
    arm_timer_for_deadline_ns((deadline_ms as u64).saturating_mul(1_000_000));
}

/// 根据 POSIX 定时器的时钟类型构造对应的 CPU 时间桶键。
fn posix_timer_cpu_bucket(timer: &PosixTimer) -> Option<PosixCpuTimerBucketKey> {
    match timer.clock_id {
        CLOCK_PROCESS_CPUTIME_ID => Some(PosixCpuTimerBucketKey::Process { pid: timer.pid }),
        CLOCK_THREAD_CPUTIME_ID => Some(PosixCpuTimerBucketKey::Thread {
            pid: timer.pid,
            tid: timer.thread_tid?,
        }),
        _ => None,
    }
}

/// 该 POSIX 定时器是否已装入截止时间堆（有截止时间且时钟走堆）。
fn posix_timer_heap_armed(timer: &PosixTimer) -> bool {
    timer.deadline_ns.is_some() && posix_timer_uses_deadline_heap(timer.clock_id)
}

/// 根据 before/after 活跃状态调整某个活跃计数原子变量。
fn adjust_active_counter(counter: &AtomicUsize, was_active: bool, is_active: bool) {
    match (was_active, is_active) {
        (false, true) => {
            counter.fetch_add(1, AtomicOrdering::AcqRel);
        }
        (true, false) => {
            counter
                .try_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |value| {
                    value.checked_sub(1)
                })
                .ok();
        }
        _ => {}
    }
}

/// 调整 POSIX 定时器的活跃计数，依据装定前后的截止时间是否存在。
fn adjust_posix_timer_active(old_deadline_ns: Option<u64>, new_deadline_ns: Option<u64>) {
    adjust_active_counter(
        &POSIX_TIMER_ACTIVE_COUNT,
        old_deadline_ns.is_some(),
        new_deadline_ns.is_some(),
    );
}

/// 计算所有 alarm/itimer 条目中的最早截止时间（毫秒），无条目时返回 `usize::MAX`。
fn min_alarm_deadline_ms(timers: &[AlarmTimer]) -> usize {
    timers
        .iter()
        .map(|timer| timer.deadline_ms)
        .min()
        .unwrap_or(usize::MAX)
}

/// 计算所有延迟 ctid 清理条目中的最早截止时间（毫秒），无条目时返回 `usize::MAX`。
fn min_delayed_tid_clear_deadline_ms(clears: &[DelayedTidClear]) -> usize {
    clears
        .iter()
        .map(|entry| entry.deadline_ms)
        .min()
        .unwrap_or(usize::MAX)
}

/// 同步更新 CPU 时间钟桶状态：插入/更新或移除对应定时器的截止时间。
fn posix_update_cpu_timer_state(
    timer: &PosixTimer,
    old_deadline_ns: Option<u64>,
    new_deadline_ns: Option<u64>,
) {
    if !posix_timer_uses_cpu_bucket(timer.clock_id) {
        return;
    }
    let Some(bucket_key) = posix_timer_cpu_bucket(timer) else {
        return;
    };
    let timer_key = (timer.pid, timer.timer_id);
    let mut state = POSIX_CPU_TIMER_STATE.lock();
    match (old_deadline_ns, new_deadline_ns) {
        (_, Some(deadline_ns)) => state.insert_or_update(bucket_key, timer_key, deadline_ns),
        (Some(_), None) => state.remove(bucket_key, timer_key),
        (None, None) => {}
    }
}

/// 在 POSIX 定时器装定状态变化后，重排截止时间堆并装定硬件定时器。
///
/// 自增 `schedule_seq` 使旧的堆条目失效；只在装定状态真正变化时才调整
/// 活跃计数与硬件定时器，避免无谓的 IPI/重排。
fn posix_reschedule_timer_locked(timer: &mut PosixTimer, was_armed: bool) {
    let is_armed = posix_timer_heap_armed(timer);
    timer.schedule_seq = timer.schedule_seq.wrapping_add(1);
    if !was_armed && !is_armed {
        return;
    }
    let Some(deadline_ns) = timer.deadline_ns else {
        let mut schedule = POSIX_TIMER_SCHEDULE.lock();
        schedule.adjust_armed(timer.clock_id, was_armed, is_armed);
        return;
    };
    let mut schedule = POSIX_TIMER_SCHEDULE.lock();
    schedule.adjust_armed(timer.clock_id, was_armed, is_armed);
    if !is_armed {
        return;
    }
    let Some(heap) = posix_schedule_heap_mut(&mut schedule, timer.clock_id) else {
        return;
    };
    heap.push(PosixTimerScheduleEntry {
        deadline_ns,
        sequence: timer.schedule_seq,
        pid: timer.pid,
        timer_id: timer.timer_id,
    });
    drop(schedule);
    arm_clockevent_for_deadline(timer.clock_id, deadline_ns);
}

/// 创建一个 POSIX 定时器，返回新分配的 timer_id。
///
/// `signum` 必须在 1..=64 范围内，否则返回 `None`。新建定时器初始为未装定状态。
pub fn create_posix_timer(
    pid: usize,
    clock_id: usize,
    signum: usize,
    thread_tid: Option<usize>,
) -> Option<usize> {
    if signum == 0 || signum > 64 {
        return None;
    }
    let timer_id = NEXT_POSIX_TIMER_ID.fetch_add(1, AtomicOrdering::Relaxed);
    POSIX_TIMERS.lock().insert(PosixTimer {
        pid,
        timer_id,
        clock_id,
        thread_tid,
        signum,
        deadline_ns: None,
        interval_ns: 0,
        overrun: 0,
        schedule_seq: 0,
    });
    Some(timer_id)
}

/// 装定/修改一个 POSIX 定时器，返回 `(剩余纳秒, 旧间隔纳秒)`。
///
/// `deadline_ns` 为 `None` 表示 disarm。同时同步活跃计数、CPU 时间桶状态
/// 与截止时间堆，使下一次硬件定时器中断能命中新的截止时间。
pub fn set_posix_timer(
    pid: usize,
    timer_id: usize,
    deadline_ns: Option<u64>,
    interval_ns: u64,
    initial_overrun: usize,
) -> Result<(u64, u64), isize> {
    const EINVAL: isize = -22;
    let mut timers = POSIX_TIMERS.lock();
    let Some(timer) = timers.get_mut(pid, timer_id) else {
        return Err(EINVAL);
    };
    let Some(now_ns) = posix_timer_now_ns(timer) else {
        return Err(EINVAL);
    };
    let prev_remain = timer
        .deadline_ns
        .map(|d| d.saturating_sub(now_ns))
        .unwrap_or(0);
    let prev_interval = timer.interval_ns;
    let old_deadline_ns = timer.deadline_ns;
    let was_armed = posix_timer_heap_armed(timer);
    timer.interval_ns = interval_ns;
    timer.deadline_ns = deadline_ns;
    timer.overrun = initial_overrun.min(i32::MAX as usize);
    adjust_posix_timer_active(old_deadline_ns, timer.deadline_ns);
    posix_update_cpu_timer_state(timer, old_deadline_ns, timer.deadline_ns);
    posix_reschedule_timer_locked(timer, was_armed);
    Ok((prev_remain, prev_interval))
}

/// 删除一个 POSIX 定时器，成功返回 0，找不到返回 -EINVAL。
///
/// 同时清理活跃计数、CPU 时间桶与截止时间堆中的对应条目。
pub fn delete_posix_timer(pid: usize, timer_id: usize) -> isize {
    const EINVAL: isize = -22;
    let mut timers = POSIX_TIMERS.lock();
    if let Some(timer) = timers.remove(pid, timer_id) {
        adjust_posix_timer_active(timer.deadline_ns, None);
        posix_update_cpu_timer_state(&timer, timer.deadline_ns, None);
        if posix_timer_heap_armed(&timer) {
            POSIX_TIMER_SCHEDULE
                .lock()
                .adjust_armed(timer.clock_id, true, false);
        }
        return 0;
    }
    EINVAL
}

/// 查询一个 POSIX 定时器的当前装定信息。
///
/// 返回 `(clock_id, deadline_ns, interval_ns, thread_tid)`，找不到返回 -EINVAL。
pub fn query_posix_timer(
    pid: usize,
    timer_id: usize,
) -> Result<(usize, Option<u64>, u64, Option<usize>), isize> {
    const EINVAL: isize = -22;
    let timers = POSIX_TIMERS.lock();
    let Some(timer) = timers.get(pid, timer_id) else {
        return Err(EINVAL);
    };
    Ok((
        timer.clock_id,
        timer.deadline_ns,
        timer.interval_ns,
        timer.thread_tid,
    ))
}

/// 取走并返回一个 POSIX 定时器累积的 overrun 计数，随后清零。
pub fn take_posix_timer_overrun(pid: usize, timer_id: usize) -> Result<isize, isize> {
    const EINVAL: isize = -22;
    let mut timers = POSIX_TIMERS.lock();
    let Some(timer) = timers.get_mut(pid, timer_id) else {
        return Err(EINVAL);
    };
    let overrun = timer.overrun.min(i32::MAX as usize) as isize;
    timer.overrun = 0;
    Ok(overrun)
}

/// 安排一次延迟的 ctid 清理：在 `delay_ms` 毫秒后清零用户态 `ctid` 并唤醒 futex。
///
/// `ctid == 0` 时视为无清理需求，直接返回。
pub fn schedule_tid_clear(pid: usize, ctid: usize, delay_ms: usize) {
    if ctid == 0 {
        return;
    }
    let deadline_ms = get_time_ms().saturating_add(delay_ms);
    {
        let mut clears = DELAYED_TID_CLEARS.lock();
        clears.push(DelayedTidClear {
            pid,
            ctid,
            deadline_ms,
        });
        DELAYED_TID_CLEAR_NEXT_DEADLINE_MS.store(
            min_delayed_tid_clear_deadline_ms(&clears),
            AtomicOrdering::Release,
        );
    }
    DELAYED_TID_CLEAR_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
}

/// 处理所有已到期的延迟 ctid 清理条目：写零用户态 tid 字段并唤醒等待的 futex。
fn process_delayed_tid_clears(current_ms: usize) {
    let mut due = Vec::new();
    {
        let mut clears = DELAYED_TID_CLEARS.lock();
        let mut i = 0;
        while i < clears.len() {
            if clears[i].deadline_ms <= current_ms {
                due.push(clears.swap_remove(i));
                DELAYED_TID_CLEAR_COUNT
                    .try_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |value| {
                        value.checked_sub(1)
                    })
                    .ok();
            } else {
                i += 1;
            }
        }
        DELAYED_TID_CLEAR_NEXT_DEADLINE_MS.store(
            min_delayed_tid_clear_deadline_ms(&clears),
            AtomicOrdering::Release,
        );
    }

    for entry in due {
        let Some(proc) = pid2process(entry.pid) else {
            continue;
        };
        let token = proc.borrow_mut().get_user_token();
        let _ = crate::mm::try_write_user_value(token, entry.ctid as *mut i32, &0);
        let _ = futex_wake_private_and_shared(entry.pid, token, entry.ctid, 1);
    }
}

/// 以毫秒为单位添加一个睡眠定时器，将任务挂入睡眠定时器堆。
pub fn add_timer(task: Arc<TaskControlBlock>, time_wait: usize) {
    let timer = TimeWrap::new(task, time_wait);
    push_sleep_timer(timer, Some(time_wait));
}

/// 以纳秒为单位添加一个睡眠定时器，将任务挂入睡眠定时器堆。
pub fn add_timer_ns(task: Arc<TaskControlBlock>, time_wait_ns: u64) {
    let timer = TimeWrap::new_ns(task, time_wait_ns);
    push_sleep_timer(timer, None);
}

/// 将睡眠定时器条目压入堆，更新活跃计数与最近截止时间，并装定硬件定时器。
fn push_sleep_timer(timer: TimeWrap, wait_ms: Option<usize>) {
    crate::log_if!(
        DEBUG_TIMER,
        debug,
        "[timer] add tid={} wait_ms={:?} expire_ns={}",
        timer.tid,
        wait_ms,
        timer.time_expired_ns
    );
    let (next_deadline, reprogram_clockevent) = {
        let mut timers = TIMERS.lock();
        let old_head_deadline = timers.peek().map(|head| head.time_expired_ns);
        timers.push(timer);
        SLEEP_TIMER_ACTIVE_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
        let new_head_deadline = timers.peek().map(|head| head.time_expired_ns);
        // A later sleep request must not postpone an already-armed short
        // deadline. Reprogram the hardware clockevent only when the heap head
        // moves earlier, matching the usual clockevent/hrtimer contract.
        let reprogram_clockevent = match (old_head_deadline, new_head_deadline) {
            (None, Some(_)) => true,
            (Some(old), Some(new)) => new < old,
            _ => false,
        };
        (new_head_deadline, reprogram_clockevent)
    };
    SLEEP_TIMER_NEXT_DEADLINE_NS.store(
        next_deadline.unwrap_or(u64::MAX) as usize,
        AtomicOrdering::Release,
    );
    if reprogram_clockevent && let Some(deadline_ns) = next_deadline {
        arm_timer_for_deadline_ns(deadline_ns);
    }
}

/// 重新装定睡眠定时器堆的最近截止时间，在消费完一个到期条目后调用。
fn rearm_next_sleep_timer_deadline() {
    let next_deadline = TIMERS.lock().peek().map(|head| head.time_expired_ns);
    match next_deadline {
        Some(deadline_ns) => {
            SLEEP_TIMER_NEXT_DEADLINE_NS.store(deadline_ns as usize, AtomicOrdering::Release);
            arm_timer_for_deadline_ns(deadline_ns);
        }
        None => {
            SLEEP_TIMER_NEXT_DEADLINE_NS.store(usize::MAX, AtomicOrdering::Release);
        }
    }
}

/// 在对象特定的等待正常完成之后，移除该任务挂着的睡眠定时器。
///
/// 一个任务同一时刻只能阻塞在一个对象上，因此清掉它的全部通用睡眠
/// 定时器也会丢弃之前被中断等待留下的过期超时唤醒。
pub fn remove_timers_for_task(task: &Arc<TaskControlBlock>) {
    task.cancel_sleep_timers();
}

/// 调试用：返回睡眠定时器堆中属于指定任务的条目数。
pub fn debug_count_task_refs_in_timers(task: &Arc<TaskControlBlock>) -> usize {
    let task_key = Arc::as_ptr(task) as usize;
    TIMERS
        .lock()
        .iter()
        .filter(|entry| entry.task_key == task_key)
        .count()
}

/// 在当前 hart 上标记一个延迟的内核定时器 tick，等待安全点再处理。
pub fn note_kernel_timer_tick() {
    let hart = crate::task::processor::hart_id() % MAX_HARTS;
    DEFERRED_KERNEL_TIMER_TICK[hart].store(true, AtomicOrdering::Release);
}

/// 取走并清除当前 hart 的延迟内核定时器 tick 标志，返回是否曾置位。
pub fn take_deferred_kernel_timer_tick() -> bool {
    let hart = crate::task::processor::hart_id() % MAX_HARTS;
    DEFERRED_KERNEL_TIMER_TICK[hart].swap(false, AtomicOrdering::AcqRel)
}

/// 返回用户态返回前是否有到期的睡眠定时器（基于活跃计数与最近截止时间的快速判断）。
fn sleep_timer_due_for_user_return(now_ns: u64) -> bool {
    SLEEP_TIMER_ACTIVE_COUNT.load(AtomicOrdering::Acquire) != 0
        && SLEEP_TIMER_NEXT_DEADLINE_NS.load(AtomicOrdering::Acquire) <= now_ns as usize
}

/// 返回用户态返回前是否有到期的 alarm/itimer 条目。
fn alarm_timer_due_for_user_return(now_ms: usize) -> bool {
    ALARM_TIMER_ACTIVE_COUNT.load(AtomicOrdering::Acquire) != 0
        && ALARM_TIMER_NEXT_DEADLINE_MS.load(AtomicOrdering::Acquire) <= now_ms
}

/// 返回用户态返回前是否有到期的延迟 ctid 清理条目。
fn delayed_tid_clear_due_for_user_return(now_ms: usize) -> bool {
    DELAYED_TID_CLEAR_COUNT.load(AtomicOrdering::Acquire) != 0
        && DELAYED_TID_CLEAR_NEXT_DEADLINE_MS.load(AtomicOrdering::Acquire) <= now_ms
}

/// 返回用户态返回前是否有到期的 POSIX 定时器（墙钟/单调钟堆或 CPU 时间桶）。
fn posix_deadline_heap_due_for_user_return() -> bool {
    if POSIX_TIMER_ACTIVE_COUNT.load(AtomicOrdering::Acquire) == 0 {
        return false;
    }
    if POSIX_CPU_TIMER_STATE.lock().has_armed_timers() {
        return true;
    }
    let monotonic_now_ns = crate::syscall::timer_clock_now_ns(CLOCK_MONOTONIC, 0, None);
    let realtime_now_ns = crate::syscall::timer_clock_now_ns(CLOCK_REALTIME, 0, None);
    let schedule = POSIX_TIMER_SCHEDULE.lock();
    let monotonic_due = schedule.monotonic_armed != 0
        && monotonic_now_ns.is_some_and(|now_ns| {
            schedule
                .monotonic
                .peek()
                .is_some_and(|entry| entry.deadline_ns <= now_ns)
        });
    let realtime_due = schedule.realtime_armed != 0
        && realtime_now_ns.is_some_and(|now_ns| {
            schedule
                .realtime
                .peek()
                .is_some_and(|entry| entry.deadline_ns <= now_ns)
        });
    monotonic_due || realtime_due
}

/// 判断在返回用户态之前是否有任何定时器工作待处理。
///
/// 检查延迟内核 tick、睡眠定时器、alarm、延迟 ctid 清理、POSIX 定时器
/// 以及 timerfd，任一待处理即返回 `true`，供 trap 路径决定是否跑 `check_timer`。
pub fn timer_work_pending_for_user_return() -> bool {
    let hart = crate::task::processor::hart_id() % MAX_HARTS;
    if DEFERRED_KERNEL_TIMER_TICK[hart].load(AtomicOrdering::Acquire) {
        return true;
    }
    let now_ns = get_time_ns();
    let now_ms = (now_ns / 1_000_000) as usize;
    sleep_timer_due_for_user_return(now_ns)
        || alarm_timer_due_for_user_return(now_ms)
        || delayed_tid_clear_due_for_user_return(now_ms)
        || posix_deadline_heap_due_for_user_return()
        || crate::fs::timerfd_work_pending_for_user_return()
}

/// 设置进程的 alarm 定时器（`alarm(2)`），返回上一轮剩余毫秒数。
pub fn set_alarm_timer(pid: usize, delay_ms: Option<usize>) -> usize {
    let (remaining_ms, _) = set_itimer_timer(pid, 0, SIGALRM_NUM, delay_ms, 0);
    remaining_ms
}

/// 设置进程的 itimer 定时器，返回 `(剩余毫秒, 旧间隔毫秒)`。
///
/// `which` 选择 ITIMER_*，`delay_ms` 为 `None` 或 0 表示 disarm。
/// 周期定时器在到期后按 `interval_ms` 自动重装。
pub fn set_itimer_timer(
    pid: usize,
    which: usize,
    signum: usize,
    delay_ms: Option<usize>,
    interval_ms: usize,
) -> (usize, usize) {
    let now = get_time_ms();
    let mut remaining_ms = 0usize;
    let mut old_interval_ms = 0usize;
    let arm_deadline_ms = {
        let mut timers = ALARM_TIMERS.lock();
        if let Some(idx) = timers.iter().position(|t| t.pid == pid && t.which == which) {
            let old = timers.swap_remove(idx);
            ALARM_TIMER_ACTIVE_COUNT
                .try_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |value| {
                    value.checked_sub(1)
                })
                .ok();
            remaining_ms = old.deadline_ms.saturating_sub(now);
            old_interval_ms = old.interval_ms;
        }
        let deadline = if let Some(delay) = delay_ms
            && delay > 0
        {
            let deadline_ms = now.saturating_add(delay);
            timers.push(AlarmTimer {
                pid,
                which,
                signum,
                deadline_ms,
                interval_ms,
            });
            ALARM_TIMER_ACTIVE_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
            Some(deadline_ms)
        } else {
            None
        };
        ALARM_TIMER_NEXT_DEADLINE_MS.store(min_alarm_deadline_ms(&timers), AtomicOrdering::Release);
        deadline
    };
    if let Some(deadline_ms) = arm_deadline_ms {
        arm_monotonic_deadline_ms(deadline_ms);
    }
    (remaining_ms, old_interval_ms)
}

/// 返回进程 alarm 的剩余毫秒数（`which = 0`）。
pub fn alarm_remaining_ms(pid: usize) -> usize {
    let (remaining_ms, _) = itimer_remaining_and_interval_ms(pid, 0);
    remaining_ms
}

/// 返回指定 itimer 的 `(剩余毫秒, 间隔毫秒)`，未装定则返回 `(0, 0)`。
pub fn itimer_remaining_and_interval_ms(pid: usize, which: usize) -> (usize, usize) {
    let now = get_time_ms();
    let timers = ALARM_TIMERS.lock();
    if let Some(entry) = timers.iter().find(|t| t.pid == pid && t.which == which) {
        return (entry.deadline_ms.saturating_sub(now), entry.interval_ms);
    }
    (0, 0)
}

/// 向目标进程投递一次 SIGALRM：选择一个可接收该信号的任务，置位并按需发 IPI 唤醒。
fn deliver_alarm(pid: usize) {
    let Some(proc) = pid2process(pid) else {
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[alarm] drop pid={} (no process)",
            pid
        );
        return;
    };
    let Some(bit) = signal_bit(SIGALRM_NUM) else {
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[alarm] drop pid={} (invalid signal)",
            pid
        );
        return;
    };
    let task = {
        let inner = proc.borrow_mut();
        let tasks = inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<Vec<_>>();
        pick_task_for_signal(&tasks, bit)
    };
    let Some(task) = task else {
        crate::log_if!(DEBUG_UNIXBENCH, info, "[alarm] drop pid={} (no task)", pid);
        return;
    };
    let (tid, on_cpu, mask, pending) = {
        let mut inner = task.borrow_mut();
        inner.pending_signals |= bit;
        let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        (
            tid,
            task.on_cpu.load(AtomicOrdering::Acquire),
            inner.signal_mask,
            inner.pending_signals,
        )
    };
    task.mark_signal_pending();
    crate::log_if!(
        DEBUG_UNIXBENCH,
        info,
        "[alarm] fire pid={} tid={} on_cpu={} mask={:#x} pending={:#x}",
        pid,
        tid,
        on_cpu,
        mask,
        pending
    );
    wakeup_task(task.clone());
    if on_cpu != TaskControlBlock::OFF_CPU {
        arch::send_ipi(on_cpu);
    }
}

/// 处理所有已到期的 alarm/itimer 条目，投递信号并按周期重装。
fn process_alarm_timers(current_ms: usize) {
    loop {
        let expired_timer = {
            let mut timers = ALARM_TIMERS.lock();
            if let Some((idx, _)) = timers
                .iter()
                .enumerate()
                .find(|(_, t)| t.deadline_ms <= current_ms)
            {
                let timer = timers.swap_remove(idx);
                ALARM_TIMER_ACTIVE_COUNT
                    .try_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |value| {
                        value.checked_sub(1)
                    })
                    .ok();
                ALARM_TIMER_NEXT_DEADLINE_MS
                    .store(min_alarm_deadline_ms(&timers), AtomicOrdering::Release);
                Some(timer)
            } else {
                None
            }
        };
        let Some(mut timer) = expired_timer else {
            break;
        };
        if timer.signum == SIGALRM_NUM {
            deliver_alarm(timer.pid);
        } else {
            queue_process_signal(timer.pid, timer.signum);
        }
        if timer.interval_ms > 0 && pid2process(timer.pid).is_some() {
            let interval = timer.interval_ms.max(1);
            let elapsed = current_ms.saturating_sub(timer.deadline_ms);
            let expirations = elapsed / interval + 1;
            timer.deadline_ms = timer
                .deadline_ms
                .saturating_add(expirations.saturating_mul(interval));
            let deadline_ms = timer.deadline_ms;
            {
                let mut timers = ALARM_TIMERS.lock();
                timers.push(timer);
                ALARM_TIMER_NEXT_DEADLINE_MS
                    .store(min_alarm_deadline_ms(&timers), AtomicOrdering::Release);
            }
            ALARM_TIMER_ACTIVE_COUNT.fetch_add(1, AtomicOrdering::AcqRel);
            arm_monotonic_deadline_ms(deadline_ms);
        }
    }
}

/// 处理已到期的 POSIX 定时器：先处理墙钟/单调钟堆，再处理 CPU 时间桶，
/// 投递信号并按周期重装（含溢出 overrun 累计）。
fn process_posix_timers() {
    for clock_id in [CLOCK_MONOTONIC, CLOCK_REALTIME] {
        loop {
            let entry = {
                let Some(now_ns) = crate::syscall::timer_clock_now_ns(clock_id, 0, None) else {
                    break;
                };
                let mut schedule = POSIX_TIMER_SCHEDULE.lock();
                let Some(heap) = posix_schedule_heap_mut(&mut schedule, clock_id) else {
                    break;
                };
                match heap.peek() {
                    Some(entry) if entry.deadline_ns <= now_ns => heap.pop(),
                    _ => None,
                }
            };
            let Some(entry) = entry else {
                break;
            };
            let fired = {
                let mut timers = POSIX_TIMERS.lock();
                let Some(timer) = timers.get_mut(entry.pid, entry.timer_id) else {
                    continue;
                };
                if timer.clock_id != clock_id
                    || timer.schedule_seq != entry.sequence
                    || timer.deadline_ns != Some(entry.deadline_ns)
                {
                    continue;
                }
                let Some(now_ns) = posix_timer_now_ns(timer) else {
                    continue;
                };
                if entry.deadline_ns > now_ns {
                    continue;
                }
                let was_armed = posix_timer_heap_armed(timer);
                let old_deadline_ns = timer.deadline_ns;
                let pid = timer.pid;
                let signum = timer.signum;
                if timer.interval_ns == 0 {
                    timer.deadline_ns = None;
                } else {
                    let elapsed = now_ns.saturating_sub(entry.deadline_ns);
                    let expirations = elapsed / timer.interval_ns + 1;
                    let extra = expirations.saturating_sub(1);
                    if extra > 0 {
                        timer.overrun = timer
                            .overrun
                            .saturating_add(extra as usize)
                            .min(i32::MAX as usize);
                    }
                    timer.deadline_ns = Some(
                        entry
                            .deadline_ns
                            .saturating_add(expirations.saturating_mul(timer.interval_ns)),
                    );
                }
                adjust_posix_timer_active(old_deadline_ns, timer.deadline_ns);
                posix_reschedule_timer_locked(timer, was_armed);
                Some((pid, signum))
            };
            let Some((pid, signum)) = fired else {
                continue;
            };
            queue_process_signal(pid, signum);
        }
    }

    loop {
        let bucket = {
            let snapshots = POSIX_CPU_TIMER_STATE.lock().snapshots();
            snapshots.into_iter().find_map(|snapshot| {
                let now_ns = crate::syscall::timer_clock_now_ns(
                    snapshot.clock_id,
                    snapshot.pid,
                    snapshot.thread_tid,
                )?;
                (snapshot.next_deadline_ns <= now_ns).then_some((snapshot, now_ns))
            })
        };
        let Some((bucket, now_ns)) = bucket else {
            break;
        };
        let fired = {
            let mut timers = POSIX_TIMERS.lock();
            let due_key = bucket.timers.into_iter().find(|(pid, timer_id)| {
                let Some(timer) = timers.get(*pid, *timer_id) else {
                    return false;
                };
                timer.clock_id == bucket.clock_id
                    && timer.thread_tid == bucket.thread_tid
                    && timer
                        .deadline_ns
                        .is_some_and(|deadline_ns| deadline_ns <= now_ns)
            });
            if let Some((pid, timer_id)) = due_key {
                if let Some(timer) = timers.get_mut(pid, timer_id) {
                    let old_deadline_ns = timer.deadline_ns;
                    let was_armed = posix_timer_heap_armed(timer);
                    let pid = timer.pid;
                    let signum = timer.signum;
                    if timer.interval_ns == 0 {
                        timer.deadline_ns = None;
                    } else {
                        let base = timer.deadline_ns.unwrap_or(now_ns);
                        let elapsed = now_ns.saturating_sub(base);
                        let expirations = elapsed / timer.interval_ns + 1;
                        let extra = expirations.saturating_sub(1);
                        if extra > 0 {
                            timer.overrun = timer
                                .overrun
                                .saturating_add(extra as usize)
                                .min(i32::MAX as usize);
                        }
                        timer.deadline_ns = Some(
                            base.saturating_add(expirations.saturating_mul(timer.interval_ns)),
                        );
                    }
                    adjust_posix_timer_active(old_deadline_ns, timer.deadline_ns);
                    posix_update_cpu_timer_state(timer, old_deadline_ns, timer.deadline_ns);
                    posix_reschedule_timer_locked(timer, was_armed);
                    Some((pid, signum))
                } else {
                    None
                }
            } else {
                None
            }
        };
        let Some((pid, signum)) = fired else {
            break;
        };
        queue_process_signal(pid, signum);
    }
}

/// 定时器中断的主入口：弹出并唤醒所有已到期的睡眠定时器，再依次处理
/// 延迟 ctid 清理、alarm/itimer、POSIX 定时器与 timerfd。
pub fn check_timer() {
    let _ = take_deferred_kernel_timer_tick();

    loop {
        let current_ns = get_time_ns();
        // Pop one expired timer (if any) while holding the lock, then wake it after releasing.
        let popped = {
            let mut timers = TIMERS.lock();
            if DEBUG_TIMER {
                let len = timers.len();
                if let Some(head) = timers.peek() {
                    log::debug!(
                        "[timer] check now_ns={} timers_len={} head_tid={} head_expire_ns={}",
                        current_ns,
                        len,
                        head.tid,
                        head.time_expired_ns
                    );
                } else {
                    log::debug!("[timer] check now_ns={} timers_len=0", current_ns);
                }
            }
            if let Some(head) = timers.peek() {
                let expire = head.time_expired_ns;
                if DEBUG_TIMER {
                    let status = if expire <= current_ns {
                        "ready"
                    } else {
                        "future"
                    };
                    log::debug!(
                        "[timer] peek tid={} expire_ns={} now_ns={} status={}",
                        head.tid,
                        expire,
                        current_ns,
                        status
                    );
                }
                if expire <= current_ns {
                    Some(timers.pop().unwrap())
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(timer) = popped {
            SLEEP_TIMER_ACTIVE_COUNT
                .try_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |value| {
                    value.checked_sub(1)
                })
                .ok();
            let Some(task) = timer.task.upgrade() else {
                continue;
            };
            if task.sleep_timer_seq() != timer.timer_seq {
                continue;
            }
            let pid = task
                .process
                .upgrade()
                .map(|p: alloc::sync::Arc<ProcessControlBlock>| p.getpid())
                .unwrap_or(usize::MAX);
            crate::log_if!(
                DEBUG_TIMER,
                debug,
                "[timer] pop pid={} tid={} expire_ns={} now_ns={}",
                pid,
                timer.tid,
                timer.time_expired_ns,
                current_ns
            );
            crate::log_if!(
                DEBUG_TIMER,
                debug,
                "[timer] wake pid={} tid={} expire_ns={} now_ns={}",
                pid,
                timer.tid,
                timer.time_expired_ns,
                current_ns
            );
            prime_fair_timer_wakeup_lag(&task);
            wakeup_task(task);
            // Continue looping in case more timers have expired at the same tick.
            continue;
        }
        break;
    }

    // `set_next_trigger()` installs the periodic tick before calling `check_timer()`.
    // After consuming one hrtimer-style sleep deadline, program the next sleep
    // deadline explicitly so nearby nanosleep users do not wait for the next tick.
    rearm_next_sleep_timer_deadline();

    let current_ms = get_time_ms();
    process_delayed_tid_clears(current_ms);
    process_alarm_timers(current_ms);
    process_posix_timers();
    crate::fs::process_timerfd_expirations();
}

/// 返回是否存在已到期的睡眠定时器，供调度路径快速判断是否需要立即处理。
pub fn has_due_sleep_timer() -> bool {
    let now_ns = get_time_ns();
    TIMERS
        .lock()
        .peek()
        .is_some_and(|head| head.time_expired_ns <= now_ns)
}
