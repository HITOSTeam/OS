use crate::syscall::error::{SyscallError, err};
use crate::task::task_block::TaskControlBlock;
use crate::{
    config::clock_freq,
    debug_config::{DEBUG_CYCLICTEST, DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    fs::{File, NetSocketFile, POLLIN, POLLOUT, POLLPRI},
    mm::{
        try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value,
        write_user_value,
    },
    syscall::thread,
    syscall::{CyclicDiagEvent, cyclic_diag_note, misc::decode_linux_tid},
    task::block_sleep::{
        create_posix_timer, delete_posix_timer, itimer_remaining_and_interval_ms,
        query_posix_timer, set_itimer_timer, set_posix_timer, take_posix_timer_overrun,
    },
    task::signal::{
        SIGALRM_NUM, SIGKILL_NUM, SIGSTOP_NUM, has_wait_interrupting_pending, signal_bit,
    },
    task::{
        manager::pid2process,
        processor::{PreparedWait, current_files, current_process, current_task},
        runtime::{
            current_task_cpu_time_ns, process_cpu_time_ns, process_task_by_index, task_cpu_time_ns,
        },
    },
    time::{get_realtime_ns, get_time, get_time_ns, set_realtime_ns},
    trap::get_current_token,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

const CYCLICTEST_LOG_LIMIT: usize = 32;
static CLOCK_NS_LOGS: AtomicUsize = AtomicUsize::new(0);
const NSEC_PER_SEC: u64 = 1_000_000_000;
const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const CLOCK_PROCESS_CPUTIME_ID: usize = 2;
const CLOCK_THREAD_CPUTIME_ID: usize = 3;
const CLOCK_MONOTONIC_RAW: usize = 4;
const CLOCK_REALTIME_COARSE: usize = 5;
const CLOCK_MONOTONIC_COARSE: usize = 6;
const CLOCK_BOOTTIME: usize = 7;

const CLOCKFD: i32 = 3;
const CPUCLOCK_CLOCK_MASK: i32 = 0x3;
const CPUCLOCK_PERTHREAD_MASK: i32 = 0x4;

const TIMER_ABSTIME: usize = 1;
const SIGEV_SIGNAL: i32 = 0;
const ADJ_OFFSET: u32 = 0x0001;
const ADJ_FREQUENCY: u32 = 0x0002;
const ADJ_MAXERROR: u32 = 0x0004;
const ADJ_ESTERROR: u32 = 0x0008;
const ADJ_STATUS: u32 = 0x0010;
const ADJ_TIMECONST: u32 = 0x0020;
const ADJ_TAI: u32 = 0x0080;
const ADJ_MICRO: u32 = 0x1000;
const ADJ_NANO: u32 = 0x2000;
const ADJ_TICK: u32 = 0x4000;
const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001;
const ADJ_OFFSET_SS_READ: u32 = 0xa001;
const STA_NANO: i32 = 0x2000;
const CAP_SYS_TIME: usize = 25;
const TIMEX_WRITE_MODES: u32 = ADJ_OFFSET
    | ADJ_FREQUENCY
    | ADJ_MAXERROR
    | ADJ_ESTERROR
    | ADJ_STATUS
    | ADJ_TIMECONST
    | ADJ_TAI
    | ADJ_MICRO
    | ADJ_NANO
    | ADJ_TICK
    | ADJ_OFFSET_SINGLESHOT;
const TIMEX_ALLOWED_MODES: u32 = TIMEX_WRITE_MODES | ADJ_OFFSET_SS_READ;

/// 内核维护的 `adjtimex` 时钟调整状态，对应 `struct timex` 的可写子集。
/// 用于 NTP 风格的软件时钟校正（`clock_adjtime` / `adjtimex` 系统调用）。
#[derive(Clone, Copy)]
struct AdjtimexState {
    /// 时钟偏移量（纳秒或微秒，取决于 status 中的 ADJ_NANO 位）
    offset: i64,
    /// 频率误差，单位 ppm（scaled by 2^16）
    freq: i64,
    /// 最大误差估计（微秒）
    maxerror: i64,
    /// 估计误差（微秒）
    esterror: i64,
    /// 时钟状态标志位（STA_PLL、STA_UNSYNC 等）
    status: i32,
    /// PLL 时间常数（影响调整速度）
    constant: i64,
    /// 每个 tick 的微秒数，通常为 10000（对应 HZ=100）
    tick: i64,
    /// 国际原子时与 UTC 的秒差（TAI-UTC）
    tai: i32,
}

impl AdjtimexState {
    const fn new() -> Self {
        Self {
            offset: 0,
            freq: 0,
            maxerror: 0,
            esterror: 0,
            status: 0,
            constant: 0,
            tick: 10_000,
            tai: 0,
        }
    }
}

static ADJTIMEX_STATE: Mutex<AdjtimexState> = Mutex::new(AdjtimexState::new());

fn now_ns() -> u64 {
    get_time_ns()
}

fn realtime_now_ns() -> u64 {
    get_realtime_ns()
}

fn posix_timer_process_cpu_time_ns(pid: usize) -> Option<u64> {
    let process = pid2process(pid)?;
    Some(process_cpu_time_ns(&process))
}

fn posix_timer_thread_cpu_time_ns(pid: usize, tid: usize) -> Option<u64> {
    let process = pid2process(pid)?;
    let task = process_task_by_index(&process, tid)?;
    Some(task_cpu_time_ns(&task))
}

pub(crate) fn timer_clock_now_ns(
    clock_id: usize,
    pid: usize,
    thread_tid: Option<usize>,
) -> Option<u64> {
    match clock_id {
        CLOCK_REALTIME => Some(realtime_now_ns()),
        CLOCK_MONOTONIC => Some(now_ns()),
        CLOCK_PROCESS_CPUTIME_ID => posix_timer_process_cpu_time_ns(pid),
        CLOCK_THREAD_CPUTIME_ID => {
            let tid = thread_tid?;
            posix_timer_thread_cpu_time_ns(pid, tid)
        }
        _ => None,
    }
}

pub fn realtime_now_seconds() -> u64 {
    realtime_now_ns() / NSEC_PER_SEC
}

pub fn realtime_now_timespec() -> (i64, i64) {
    let ns = realtime_now_ns();
    ((ns / NSEC_PER_SEC) as i64, (ns % NSEC_PER_SEC) as i64)
}

fn timespec_to_ns(ts: TimeSpec) -> Option<u64> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= NSEC_PER_SEC as i64 {
        return None;
    }
    Some(
        (ts.sec as u64)
            .saturating_mul(NSEC_PER_SEC)
            .saturating_add(ts.nsec as u64),
    )
}

fn ns_to_timespec(ns: u64) -> TimeSpec {
    TimeSpec {
        sec: (ns / NSEC_PER_SEC) as i64,
        nsec: (ns % NSEC_PER_SEC) as i64,
    }
}

/// 解码后的动态 CPU 时钟描述符。
/// Linux 用负数 clock_id 编码进程/线程 CPU 时钟，该结构体保存解码结果。
#[derive(Clone, Copy)]
struct DynamicCpuClock {
    /// 目标进程 PID 或线程 TID
    target_id: usize,
    /// true 表示线程级 CPU 时钟，false 表示进程级
    per_thread: bool,
}

fn decode_dynamic_cpu_clock(clk_id: i32) -> Option<DynamicCpuClock> {
    if clk_id >= 0 {
        return None;
    }
    // fd-based clocks use low bits `11` and are handled differently.
    if (clk_id & CPUCLOCK_CLOCK_MASK) == CLOCKFD {
        return None;
    }
    Some(DynamicCpuClock {
        target_id: ((!clk_id) >> 3) as usize,
        per_thread: (clk_id & CPUCLOCK_PERTHREAD_MASK) != 0,
    })
}

fn resolve_thread_cpu_time_ns(target_tid_like: usize) -> Option<u64> {
    let process = current_process();
    let cur_pid = process.getpid();
    let tid = if target_tid_like == 0 || target_tid_like == cur_pid {
        Some(0usize)
    } else if let Some(t) = decode_linux_tid(cur_pid, target_tid_like) {
        Some(t)
    } else {
        // Accept raw per-process thread indices as a compatibility fallback.
        Some(target_tid_like)
    }?;
    let task = process_task_by_index(&process, tid)?;
    Some(task_cpu_time_ns(&task))
}

fn resolve_process_cpu_time_ns(target_pid: usize) -> Option<u64> {
    if target_pid == 0 {
        return Some(process_cpu_time_ns(&current_process()));
    }
    let process = pid2process(target_pid)?;
    Some(process_cpu_time_ns(&process))
}

fn dynamic_cpu_clock_time_ns(clk: DynamicCpuClock) -> Option<u64> {
    if clk.per_thread {
        resolve_thread_cpu_time_ns(clk.target_id)
    } else {
        resolve_process_cpu_time_ns(clk.target_id)
    }
}

/// 对应 C `struct timeval`，精度到微秒。
/// 用于 `gettimeofday` / `settimeofday`。
#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal {
    /// 秒
    sec: u64,
    /// 微秒（0 ~ 999_999）
    usec: u64,
}

/// 对应 C `struct timezone`，随 `gettimeofday` 一起传出。
/// 现代系统已基本废弃，内核通常忽略写入并返回全零。
#[repr(C)]
#[derive(Clone, Copy)]
struct TimeZone {
    /// UTC 偏移分钟数（西为正，如 UTC+8 为 -480）
    minuteswest: i32,
    /// 夏令时类型（已废弃，始终为 0）
    dsttime: i32,
}

/// 对应 C `struct timespec`，精度到纳秒。
/// 用于 `clock_gettime`、`nanosleep`、`pselect` 等高精度时间接口。
#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    /// 秒
    sec: i64,
    /// 纳秒（0 ~ 999_999_999）
    nsec: i64,
}

/// `pselect6` 第 6 个参数指向的结构体。
///
/// 由于 syscall 只有 6 个寄存器参数，而信号掩码需要同时传指针和大小，
/// Linux 将两者打包成此结构体，通过指针间接传入。
///
/// 对应 C：`struct { const sigset_t *ss; size_t ss_len; }`
#[repr(C)]
#[derive(Clone, Copy)]
struct PSelectSigmaskArg {
    /// 指向用户空间 `sigset_t` 的指针（64 位信号位图）
    sigmask_ptr: usize,
    /// `sigset_t` 的字节大小，现代 64 位系统固定为 8；
    /// 保留此字段是为了兼容早期 32 位 sigset_t
    sigset_size: usize,
}

/// 对应 C `struct tms`，由 `times` 系统调用填充。
/// 记录进程及其已回收子进程的 CPU 时间，单位为时钟滴答（clock tick）。
#[repr(C)]
#[derive(Clone, Copy)]
struct Tms {
    /// 当前进程用户态 CPU 时间
    tms_utime: i64,
    /// 当前进程内核态 CPU 时间
    tms_stime: i64,
    /// 已 wait 的子进程用户态 CPU 时间之和
    tms_cutime: i64,
    /// 已 wait 的子进程内核态 CPU 时间之和
    tms_cstime: i64,
}

/// 有符号版本的 `struct timeval`，用于 `adjtimex` / `Timex` 内部。
/// 与 `TimeVal` 的区别：`sec` 为 `i64`（可表示负偏移）。
#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal64 {
    /// 秒（有符号）
    sec: i64,
    /// 微秒（0 ~ 999_999）
    usec: i64,
}

/// 对应 C `struct timex`，用于 `adjtimex` / `clock_adjtime` 系统调用。
/// 是 NTP 时钟调整的用户空间接口，内核读写其中的字段来同步硬件时钟。
#[repr(C)]
#[derive(Clone, Copy)]
struct Timex {
    /// 操作模式标志（ADJ_OFFSET、ADJ_FREQ 等），决定哪些字段有效
    modes: u32,
    _pad0: u32,
    /// 时钟偏移（纳秒或微秒，由 status 中 ADJ_NANO 决定）
    offset: i64,
    /// 频率误差，单位 scaled ppm（ppm × 2^16）
    freq: i64,
    /// 最大误差估计（微秒）
    maxerror: i64,
    /// 当前估计误差（微秒）
    esterror: i64,
    /// 时钟状态标志（STA_PLL、STA_UNSYNC、STA_NANO 等）
    status: i32,
    _pad1: i32,
    /// PLL 时间常数，影响频率调整的收敛速度
    constant: i64,
    /// 时钟精度（只读，内核填充）
    precision: i64,
    /// 频率容差（只读，内核填充）
    tolerance: i64,
    /// 当前时间（只读，内核填充）
    time: TimeVal64,
    /// 每 tick 微秒数（通常 10000，对应 HZ=100）
    tick: i64,
    /// PPS 频率（只读）
    ppsfreq: i64,
    /// PPS 抖动（只读）
    jitter: i64,
    /// PPS 校准间隔的 log2 值
    shift: i32,
    _pad2: i32,
    /// PPS 稳定性（只读）
    stabil: i64,
    /// PPS 抖动超限计数（只读）
    jitcnt: i64,
    /// PPS 校准次数（只读）
    calcnt: i64,
    /// PPS 误差超限计数（只读）
    errcnt: i64,
    /// PPS 稳定性超限计数（只读）
    stbcnt: i64,
    /// TAI-UTC 秒差（只读）
    tai: i32,
    _pad3: [i32; 11],
}

/// 对应 C `struct itimerval`，用于 `getitimer` / `setitimer`。
/// 描述一个基于 `ITIMER_REAL` / `ITIMER_VIRTUAL` / `ITIMER_PROF` 的间隔定时器。
#[repr(C)]
#[derive(Clone, Copy)]
struct ITimerVal {
    /// 定时器到期后的重复间隔；为零表示单次触发
    it_interval: TimeVal64,
    /// 距下次到期的剩余时间；为零表示定时器已停止
    it_value: TimeVal64,
}

/// 对应 C `struct sigevent`，用于 POSIX 定时器（`timer_create`）。
/// 描述定时器到期时的通知方式。
#[repr(C)]
#[derive(Clone, Copy)]
struct SigEvent {
    /// 传递给信号处理函数的附加值（`siginfo_t.si_value`）
    sigev_value: usize,
    /// 到期时发送的信号编号（SIGEV_SIGNAL 模式下有效）
    sigev_signo: i32,
    /// 通知方式：SIGEV_NONE / SIGEV_SIGNAL / SIGEV_THREAD 等
    sigev_notify: i32,
}

/// 对应 C `struct itimerspec`，用于 POSIX 定时器（`timer_settime` / `timer_gettime`）。
/// 与 `ITimerVal` 类似，但时间精度为纳秒。
#[repr(C)]
#[derive(Clone, Copy)]
struct ITimerSpec {
    /// 定时器到期后的重复间隔；为零表示单次触发
    it_interval: TimeSpec,
    /// 距下次到期的剩余时间；为零表示定时器已停止
    it_value: TimeSpec,
}

#[allow(dead_code)]
fn current_euid() -> u32 {
    let process = current_process();
    let inner = process.borrow_mut();
    inner.euid
}

fn can_adjust_wallclock() -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    inner.euid == 0 && (inner.cap_effective & (1u64 << CAP_SYS_TIME)) != 0
}

fn timex_tick_limits() -> (i64, i64) {
    // Linux uses USER_HZ here; LTP reads _SC_CLK_TCK (typically 100).
    let hz = 100i64;
    (900_000 / hz, 1_100_000 / hz)
}

fn apply_adjtimex(ptr: usize) -> isize {
    if ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(mut tx) = try_read_user_value::<Timex>(token, ptr as *const Timex) else {
        return err(SyscallError::EFAULT);
    };
    let modes = tx.modes;
    if modes != ADJ_OFFSET_SINGLESHOT && modes != ADJ_OFFSET_SS_READ && (modes & 0x8000) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (modes & !TIMEX_ALLOWED_MODES) != 0 {
        return err(SyscallError::EINVAL);
    }

    let mut state = ADJTIMEX_STATE.lock();
    if modes != 0 && modes != ADJ_OFFSET_SS_READ {
        if !can_adjust_wallclock() {
            return err(SyscallError::EPERM);
        }
        if (modes & ADJ_TICK) != 0 {
            let (min_tick, max_tick) = timex_tick_limits();
            if tx.tick < min_tick || tx.tick > max_tick {
                return err(SyscallError::EINVAL);
            }
            state.tick = tx.tick;
        }
        if (modes & ADJ_OFFSET) != 0 {
            state.offset = tx.offset;
        }
        if (modes & ADJ_FREQUENCY) != 0 {
            state.freq = tx.freq;
        }
        if (modes & ADJ_MAXERROR) != 0 {
            state.maxerror = tx.maxerror;
        }
        if (modes & ADJ_ESTERROR) != 0 {
            state.esterror = tx.esterror;
        }
        if (modes & ADJ_TIMECONST) != 0 {
            state.constant = tx.constant;
        }
        if (modes & ADJ_STATUS) != 0 {
            state.status = tx.status;
        }
        if (modes & ADJ_TAI) != 0 {
            state.tai = tx.tai;
        }
        if (modes & ADJ_NANO) != 0 {
            state.status |= STA_NANO;
        }
        if (modes & ADJ_MICRO) != 0 {
            state.status &= !STA_NANO;
        }
    }

    tx.offset = state.offset;
    tx.freq = state.freq;
    tx.maxerror = state.maxerror;
    tx.esterror = state.esterror;
    tx.status = state.status;
    tx.constant = state.constant;
    tx.tick = state.tick;
    tx.tai = state.tai;
    let now = realtime_now_ns();
    tx.time.sec = (now / NSEC_PER_SEC) as i64;
    tx.time.usec = if (state.status & STA_NANO) != 0 {
        (now % NSEC_PER_SEC) as i64
    } else {
        ((now % NSEC_PER_SEC) / 1_000) as i64
    };

    if try_write_user_value(token, ptr as *mut Timex, &tx).is_err() {
        return err(SyscallError::EFAULT);
    }
    // TIME_OK
    0
}

pub fn syscall_settimeofday(tv_ptr: usize, tz_ptr: usize) -> isize {
    if tv_ptr == 0 {
        if tz_ptr != 0 {
            let token = get_current_token();
            if try_read_user_value::<TimeZone>(token, tz_ptr as *const TimeZone).is_none() {
                return err(SyscallError::EFAULT);
            }
        }
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let Some(tv) = try_read_user_value::<TimeVal64>(token, tv_ptr as *const TimeVal64) else {
        return err(SyscallError::EFAULT);
    };
    if tv.sec < 0 || tv.usec < 0 || tv.usec >= 1_000_000 {
        return err(SyscallError::EINVAL);
    }
    if !can_adjust_wallclock() {
        return err(SyscallError::EPERM);
    }
    if tz_ptr != 0 && try_read_user_value::<TimeZone>(token, tz_ptr as *const TimeZone).is_none() {
        return err(SyscallError::EFAULT);
    }
    let target_ns = (tv.sec as u64)
        .saturating_mul(NSEC_PER_SEC)
        .saturating_add((tv.usec as u64).saturating_mul(1_000));
    set_realtime_ns(target_ns);
    crate::fs::cancel_realtime_timerfds_on_set();
    0
}

pub fn syscall_adjtimex(ptr: usize) -> isize {
    apply_adjtimex(ptr)
}

pub fn syscall_clock_adjtime(clk_id: usize, ptr: usize) -> isize {
    if decode_dynamic_cpu_clock(clk_id as i32).is_some() {
        return err(SyscallError::EINVAL);
    }
    if clk_id != CLOCK_REALTIME {
        return err(SyscallError::EINVAL);
    }
    apply_adjtimex(ptr)
}

pub fn syscall_gettimeofday(tv_ptr: usize, tz_ptr: usize) -> isize {
    let token = get_current_token();
    if tv_ptr != 0 {
        let ns = realtime_now_ns();
        let tv = TimeVal {
            sec: ns / NSEC_PER_SEC,
            usec: (ns % NSEC_PER_SEC) / 1_000,
        };
        if try_write_user_value(token, tv_ptr as *mut TimeVal, &tv).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    if tz_ptr != 0 && try_read_user_value::<TimeZone>(token, tz_ptr as *const TimeZone).is_none() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_nanosleep(req_ptr: usize, _rem_ptr: usize) -> isize {
    if req_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value(token, req_ptr as *const TimeSpec) else {
        return err(SyscallError::EFAULT);
    };
    let Some(req_ns) = timespec_to_ns(ts) else {
        return err(SyscallError::EINVAL);
    };
    if req_ns == 0 {
        return 0;
    }
    let start_ns = now_ns();
    let deadline_ns = start_ns.saturating_add(req_ns);
    if DEBUG_SIGNAL {
        let pid = crate::task::processor::current_process().getpid();
        let tid = current_task()
            .and_then(|t| t.borrow_mut().res.as_ref().map(|r| r.tid))
            .unwrap_or(usize::MAX);
        let now_ms = (get_time() as u64)
            .saturating_mul(1_000)
            .saturating_div(clock_freq() as u64);
        crate::log_if!(
            DEBUG_SIGNAL,
            info,
            "[nanosleep] pid={} tid={} req_ns={} now_ms={}",
            pid,
            tid,
            req_ns,
            now_ms
        );
    }
    loop {
        let current = now_ns();
        if current >= deadline_ns {
            break;
        }
        let remaining = deadline_ns.saturating_sub(current);
        let ret = thread::sys_sleep_ns(remaining.max(1));
        if ret == err(SyscallError::EINTR) {
            if DEBUG_SIGNAL {
                let now_ms = (get_time() as u64)
                    .saturating_mul(1_000)
                    .saturating_div(clock_freq() as u64);
                crate::log_if!(
                    DEBUG_SIGNAL,
                    info,
                    "[nanosleep] ret=err(SyscallError::EINTR) now_ms={} elapsed_ns={}",
                    now_ms,
                    now_ns().saturating_sub(start_ns)
                );
            }
            if _rem_ptr != 0 {
                let now = now_ns();
                let rem = ns_to_timespec(deadline_ns.saturating_sub(now));
                let token = get_current_token();
                write_user_value(token, _rem_ptr as *mut TimeSpec, &rem);
            }
            return err(SyscallError::EINTR);
        }
    }
    if DEBUG_SIGNAL {
        let now_ms = (get_time() as u64)
            .saturating_mul(1_000)
            .saturating_div(clock_freq() as u64);
        crate::log_if!(
            DEBUG_SIGNAL,
            info,
            "[nanosleep] ret=0 now_ms={} elapsed_ns={}",
            now_ms,
            now_ns().saturating_sub(start_ns)
        );
    }
    0
}

pub fn syscall_clock_gettime(clk_id: usize, tp_ptr: usize) -> isize {
    if tp_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let dynamic_clk = decode_dynamic_cpu_clock(clk_id as i32);
    if dynamic_clk.is_none() {
        match clk_id {
            CLOCK_REALTIME
            | CLOCK_MONOTONIC
            | CLOCK_PROCESS_CPUTIME_ID
            | CLOCK_THREAD_CPUTIME_ID
            | CLOCK_MONOTONIC_RAW
            | CLOCK_REALTIME_COARSE
            | CLOCK_MONOTONIC_COARSE
            | CLOCK_BOOTTIME => {}
            _ => return err(SyscallError::EINVAL),
        }
    }
    let ns = if let Some(clk) = dynamic_clk {
        let Some(ns) = dynamic_cpu_clock_time_ns(clk) else {
            return err(SyscallError::EINVAL);
        };
        ns
    } else {
        match clk_id {
            CLOCK_REALTIME | CLOCK_REALTIME_COARSE => realtime_now_ns(),
            CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
                now_ns()
            }
            CLOCK_PROCESS_CPUTIME_ID => process_cpu_time_ns(&current_process()),
            CLOCK_THREAD_CPUTIME_ID => current_task_cpu_time_ns(),
            _ => return err(SyscallError::EINVAL),
        }
    };
    let ts = TimeSpec {
        sec: (ns / NSEC_PER_SEC) as i64,
        nsec: (ns % NSEC_PER_SEC) as i64,
    };
    let token = get_current_token();
    if try_write_user_value(token, tp_ptr as *mut TimeSpec, &ts).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_clock_settime(clk_id: usize, tp_ptr: usize) -> isize {
    if decode_dynamic_cpu_clock(clk_id as i32).is_some() {
        return err(SyscallError::EINVAL);
    }
    if clk_id != CLOCK_REALTIME {
        return err(SyscallError::EINVAL);
    }
    if tp_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value(token, tp_ptr as *const TimeSpec) else {
        return err(SyscallError::EFAULT);
    };
    let Some(target_ns) = timespec_to_ns(ts) else {
        return err(SyscallError::EINVAL);
    };
    if !can_adjust_wallclock() {
        return err(SyscallError::EPERM);
    }
    set_realtime_ns(target_ns);
    crate::fs::cancel_realtime_timerfds_on_set();
    0
}

pub fn syscall_clock_getres(clk_id: usize, tp_ptr: usize) -> isize {
    if decode_dynamic_cpu_clock(clk_id as i32).is_none() {
        match clk_id {
            CLOCK_REALTIME
            | CLOCK_MONOTONIC
            | CLOCK_PROCESS_CPUTIME_ID
            | CLOCK_THREAD_CPUTIME_ID
            | CLOCK_MONOTONIC_RAW
            | CLOCK_REALTIME_COARSE
            | CLOCK_MONOTONIC_COARSE
            | CLOCK_BOOTTIME => {}
            _ => return err(SyscallError::EINVAL),
        }
    }
    if tp_ptr == 0 {
        return 0;
    }
    let res_ns = match clk_id {
        CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => 1_000_000,
        _ => 1,
    };
    let token = get_current_token();
    let ts = ns_to_timespec(res_ns);
    if try_write_user_value(token, tp_ptr as *mut TimeSpec, &ts).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_timer_create(clock_id: usize, sevp_ptr: usize, timerid_ptr: usize) -> isize {
    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {}
        _ => return err(SyscallError::EINVAL),
    }
    if timerid_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let signum = if sevp_ptr == 0 {
        SIGALRM_NUM
    } else {
        let Some(sev) = try_read_user_value(token, sevp_ptr as *const SigEvent) else {
            return err(SyscallError::EFAULT);
        };
        if sev.sigev_notify != SIGEV_SIGNAL {
            return err(SyscallError::EINVAL);
        }
        if sev.sigev_signo <= 0 || sev.sigev_signo > 64 {
            return err(SyscallError::EINVAL);
        }
        sev.sigev_signo as usize
    };
    let pid = current_process().getpid();
    let thread_tid = if clock_id == CLOCK_THREAD_CPUTIME_ID {
        let Some(task) = current_task() else {
            return err(SyscallError::EINVAL);
        };
        let inner = task.borrow_mut();
        inner.res.as_ref().map(|res| res.tid)
    } else {
        None
    };
    let Some(timer_id) = create_posix_timer(pid, clock_id, signum, thread_tid) else {
        return err(SyscallError::EINVAL);
    };
    let timer_id_i32 = timer_id as i32;
    if try_write_user_value(token, timerid_ptr as *mut i32, &timer_id_i32).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_timer_gettime(timer_id: isize, curr_ptr: usize) -> isize {
    if timer_id < 0 {
        return err(SyscallError::EINVAL);
    }
    if curr_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let pid = current_process().getpid();
    let Ok((clock_id, deadline_ns, interval_ns, thread_tid)) =
        query_posix_timer(pid, timer_id as usize)
    else {
        return err(SyscallError::EINVAL);
    };
    let Some(now_ns) = timer_clock_now_ns(clock_id, pid, thread_tid) else {
        return err(SyscallError::EINVAL);
    };
    let value_ns = deadline_ns.map(|d| d.saturating_sub(now_ns)).unwrap_or(0);
    let spec = ITimerSpec {
        it_interval: ns_to_timespec(interval_ns),
        it_value: ns_to_timespec(value_ns),
    };
    let token = get_current_token();
    if try_write_user_value(token, curr_ptr as *mut ITimerSpec, &spec).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_timer_settime(
    timer_id: isize,
    flags: usize,
    new_ptr: usize,
    old_ptr: usize,
) -> isize {
    if timer_id < 0 {
        return err(SyscallError::EINVAL);
    }
    if new_ptr == 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & !TIMER_ABSTIME) != 0 {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let Some(new_spec) = try_read_user_value(token, new_ptr as *const ITimerSpec) else {
        return err(SyscallError::EFAULT);
    };
    let pid = current_process().getpid();
    let Ok((clock_id, _, _, thread_tid)) = query_posix_timer(pid, timer_id as usize) else {
        return err(SyscallError::EINVAL);
    };
    let Some(value_ns) = timespec_to_ns(new_spec.it_value) else {
        return err(SyscallError::EINVAL);
    };
    let Some(interval_ns) = timespec_to_ns(new_spec.it_interval) else {
        return err(SyscallError::EINVAL);
    };
    let Some(now_base) = timer_clock_now_ns(clock_id, pid, thread_tid) else {
        return err(SyscallError::EINVAL);
    };
    let mut initial_overrun = 0usize;
    let deadline_ns = if value_ns == 0 {
        None
    } else if (flags & TIMER_ABSTIME) != 0 {
        if value_ns <= now_base && interval_ns > 0 {
            let overdue_ns = now_base.saturating_sub(value_ns);
            let expirations = overdue_ns / interval_ns + 1;
            initial_overrun = expirations.saturating_sub(1).min(i32::MAX as u64) as usize;
        }
        Some(value_ns)
    } else {
        Some(now_base.saturating_add(value_ns))
    };
    let Ok((prev_remain_ns, prev_interval_ns)) = set_posix_timer(
        pid,
        timer_id as usize,
        deadline_ns,
        interval_ns,
        initial_overrun,
    ) else {
        return err(SyscallError::EINVAL);
    };
    if old_ptr != 0 {
        let old_spec = ITimerSpec {
            it_interval: ns_to_timespec(prev_interval_ns),
            it_value: ns_to_timespec(prev_remain_ns),
        };
        if try_write_user_value(token, old_ptr as *mut ITimerSpec, &old_spec).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    0
}

pub fn syscall_timer_delete(timer_id: isize) -> isize {
    if timer_id < 0 {
        return err(SyscallError::EINVAL);
    }
    let pid = current_process().getpid();
    delete_posix_timer(pid, timer_id as usize)
}

pub fn syscall_timer_getoverrun(timer_id: isize) -> isize {
    if timer_id < 0 {
        return err(SyscallError::EINVAL);
    }
    let pid = current_process().getpid();
    let Ok(overrun) = take_posix_timer_overrun(pid, timer_id as usize) else {
        return err(SyscallError::EINVAL);
    };
    overrun
}

/// Linux `clock_nanosleep` (syscall 115 on riscv64).
///
/// rt-tests (cyclictest) uses this for periodic sleeps (often with TIMER_ABSTIME).
pub fn syscall_clock_nanosleep(
    clk_id: usize,
    flags: usize,
    req_ptr: usize,
    rem_ptr: usize,
) -> isize {
    const TIMER_ABSTIME: usize = 1;
    if req_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    if clk_id != CLOCK_REALTIME && clk_id != CLOCK_MONOTONIC {
        return err(SyscallError::EOPNOTSUPP);
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value(token, req_ptr as *const TimeSpec) else {
        return err(SyscallError::EFAULT);
    };
    let Some(req_ns) = timespec_to_ns(ts) else {
        return err(SyscallError::EINVAL);
    };
    let clock_now_ns = || match clk_id {
        CLOCK_REALTIME => realtime_now_ns(),
        CLOCK_MONOTONIC => now_ns(),
        _ => now_ns(),
    };
    let start_ns = clock_now_ns();
    if DEBUG_CYCLICTEST {
        let pid = current_process().getpid();
        let tid = current_task()
            .and_then(|task| task.borrow_mut().res.as_ref().map(|r| r.tid))
            .unwrap_or(usize::MAX);
        cyclic_diag_note(CyclicDiagEvent::ClockNanosleep, pid, tid);
    }
    if DEBUG_SIGNAL {
        let pid = crate::task::processor::current_process().getpid();
        let tid = current_task()
            .and_then(|t| t.borrow_mut().res.as_ref().map(|r| r.tid))
            .unwrap_or(usize::MAX);
        let now_ms = (get_time() as u64)
            .saturating_mul(1_000)
            .saturating_div(clock_freq() as u64);
        crate::log_if!(
            DEBUG_SIGNAL,
            info,
            "[clock_nanosleep] pid={} tid={} flags={:#x} req_ns={} now_ms={}",
            pid,
            tid,
            flags,
            req_ns,
            now_ms
        );
    }
    let target_ns = if (flags & TIMER_ABSTIME) != 0 {
        req_ns
    } else {
        start_ns.saturating_add(req_ns)
    };
    loop {
        let current_ns = clock_now_ns();
        if target_ns <= current_ns {
            if DEBUG_SIGNAL {
                let now_ms = (get_time() as u64)
                    .saturating_mul(1_000)
                    .saturating_div(clock_freq() as u64);
                crate::log_if!(
                    DEBUG_SIGNAL,
                    info,
                    "[clock_nanosleep] ret=0 now_ms={} elapsed_ns={}",
                    now_ms,
                    current_ns.saturating_sub(start_ns)
                );
            }
            return 0;
        }
        let delta_ns = target_ns - current_ns;
        if DEBUG_CYCLICTEST {
            let idx = CLOCK_NS_LOGS.fetch_add(1, Ordering::Relaxed);
            if idx < CYCLICTEST_LOG_LIMIT || delta_ns > 2_000_000_000 {
                let tid = current_task()
                    .and_then(|task| task.borrow_mut().res.as_ref().map(|r| r.tid))
                    .unwrap_or(usize::MAX);
                log::warn!(
                    "[clock_nanosleep] tid={} clk_id={} flags={:#x} target_ns={} now_ns={} delta_ns={}",
                    tid,
                    clk_id,
                    flags,
                    target_ns,
                    current_ns,
                    delta_ns
                );
            }
        }
        let ret = thread::sys_sleep_ns(delta_ns);
        if ret == err(SyscallError::EINTR) {
            if DEBUG_SIGNAL {
                let now_ms = (get_time() as u64)
                    .saturating_mul(1_000)
                    .saturating_div(clock_freq() as u64);
                crate::log_if!(
                    DEBUG_SIGNAL,
                    info,
                    "[clock_nanosleep] ret=err(SyscallError::EINTR) now_ms={} elapsed_ns={}",
                    now_ms,
                    clock_now_ns().saturating_sub(start_ns)
                );
            }
            if rem_ptr != 0 {
                let remaining = target_ns.saturating_sub(clock_now_ns());
                let rem = ns_to_timespec(remaining);
                let token = get_current_token();
                if try_write_user_value(token, rem_ptr as *mut TimeSpec, &rem).is_err() {
                    return err(SyscallError::EFAULT);
                }
            }
            return err(SyscallError::EINTR);
        }
    }
}

fn ns_to_user_hz_ticks(ns: u64) -> i64 {
    const USER_HZ: u64 = 100;
    (ns.saturating_mul(USER_HZ) / NSEC_PER_SEC) as i64
}

pub fn syscall_times(tms_ptr: usize) -> isize {
    let process = current_process();
    let self_cpu_ns = process_cpu_time_ns(&process);
    let child_cpu_ns = {
        let inner = process.borrow_mut();
        inner.child_cpu_time_ns
    };
    if tms_ptr != 0 {
        let token = get_current_token();
        let tms = Tms {
            tms_utime: ns_to_user_hz_ticks(self_cpu_ns),
            tms_stime: ns_to_user_hz_ticks(self_cpu_ns),
            tms_cutime: ns_to_user_hz_ticks(child_cpu_ns),
            tms_cstime: ns_to_user_hz_ticks(child_cpu_ns),
        };
        write_user_value(token, tms_ptr as *mut Tms, &tms);
    }
    crate::time::get_time_ms() as isize
}

const ITIMER_REAL: usize = 0;
const ITIMER_VIRTUAL: usize = 1;
const ITIMER_PROF: usize = 2;
const SIGVTALRM_NUM: usize = 26;
const SIGPROF_NUM: usize = 27;

fn itimer_signum(which: usize) -> Option<usize> {
    match which {
        ITIMER_REAL => Some(SIGALRM_NUM),
        ITIMER_VIRTUAL => Some(SIGVTALRM_NUM),
        ITIMER_PROF => Some(SIGPROF_NUM),
        _ => None,
    }
}

fn timeval_to_us(tv: TimeVal64) -> Option<u64> {
    if tv.sec < 0 || tv.usec < 0 || tv.usec >= 1_000_000 {
        return None;
    }
    Some(
        (tv.sec as u64)
            .saturating_mul(1_000_000)
            .saturating_add(tv.usec as u64),
    )
}

fn us_to_ms_ceil(us: u64) -> usize {
    ((us.saturating_add(999)) / 1_000) as usize
}

fn ms_to_timeval(ms: usize) -> TimeVal64 {
    TimeVal64 {
        sec: (ms / 1_000) as i64,
        usec: ((ms % 1_000) * 1_000) as i64,
    }
}

fn build_itimerval(remaining_ms: usize, interval_ms: usize) -> ITimerVal {
    ITimerVal {
        it_interval: ms_to_timeval(interval_ms),
        it_value: ms_to_timeval(remaining_ms),
    }
}

pub fn syscall_getitimer(which: usize, curr_ptr: usize) -> isize {
    if itimer_signum(which).is_none() {
        return err(SyscallError::EINVAL);
    }
    if curr_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let pid = crate::task::processor::current_process().getpid();
    let (remaining_ms, interval_ms) = itimer_remaining_and_interval_ms(pid, which);
    let val = build_itimerval(remaining_ms, interval_ms);
    if try_write_user_value(token, curr_ptr as *mut ITimerVal, &val).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_setitimer(which: usize, new_ptr: usize, old_ptr: usize) -> isize {
    let Some(signum) = itimer_signum(which) else {
        return err(SyscallError::EINVAL);
    };
    if new_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(new_val) = try_read_user_value(token, new_ptr as *const ITimerVal) else {
        return err(SyscallError::EFAULT);
    };
    let Some(delay_us) = timeval_to_us(new_val.it_value) else {
        return err(SyscallError::EINVAL);
    };
    let Some(interval_us) = timeval_to_us(new_val.it_interval) else {
        return err(SyscallError::EINVAL);
    };
    let pid = crate::task::processor::current_process().getpid();
    let (prev_ms, prev_interval_ms) = itimer_remaining_and_interval_ms(pid, which);
    if old_ptr != 0 {
        let old_val = build_itimerval(prev_ms, prev_interval_ms);
        if try_write_user_value(token, old_ptr as *mut ITimerVal, &old_val).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    let delay_ms = if delay_us == 0 {
        None
    } else {
        Some(us_to_ms_ceil(delay_us))
    };
    let interval_ms = if interval_us == 0 {
        0
    } else {
        us_to_ms_ceil(interval_us).max(1)
    };
    set_itimer_timer(pid, which, signum, delay_ms, interval_ms);
    crate::log_if!(
        DEBUG_UNIXBENCH,
        info,
        "[itimer] set pid={} which={} delay_ms={:?} interval_ms={} prev_ms={} prev_interval_ms={}",
        pid,
        which,
        delay_ms,
        interval_ms,
        prev_ms,
        prev_interval_ms
    );
    0
}

/// Linux `pselect6`(riscv64 系统调用号 72)。
///
/// 足以支撑 iperf / netperf / netserver 这类事件循环:
/// - 提供 fdset 时,根据本进程 fd 表逐个 poll 出可读 / 可写 / 异常状态;
/// - `nfds == 0`(或三个 fdset 全为 NULL)时,退化成"带信号唤醒的睡眠原语",
///   musl 的 `usleep` / 部分 event loop 会这么用。
///
/// 返回约定(与 Linux 对齐):
/// - `>= 0`:就绪 fd 数(超时为 0);
/// - `-EINTR`:被未屏蔽且可递送的信号打断;
/// - `-EBADF` / `-EINVAL` / `-EFAULT`:参数错误。
// nfds 监听套接字。
/// 各个参数的意思：
/// nfds 从0-nfds遍历检查
/// readfds 检查可读的
/// 可写的
/// 异常的
/// 超时时间设置
/// 信号掩码，select内部采用的掩码
pub fn syscall_pselect6(
    _nfds: usize,
    _readfds: usize,
    _writefds: usize,
    _exceptfds: usize,
    timeout_ptr: usize,
    _sigmask: usize,
) -> isize {
    fn recover_mask(now_task: Arc<TaskControlBlock>, restore_mask: Option<u64>) {
        if let Some(old_mask) = restore_mask {
            let mut inner = now_task.borrow_mut();
            inner.signal_mask = old_mask;
        }
    }
    // -------- 第 ① 段:参数边界检查 --------
    const EBADF: isize = -9;
    // fdset 上限 256KB,对应 ~2M 个 fd,远超本内核 fd 表规模,主要防恶意巨值。
    const MAX_FDSET_BYTES: usize = 256 * 1024;
    if (_nfds as isize) < 0 {
        return err(SyscallError::EINVAL);
    }
    if _nfds > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    let nfds = _nfds;
    let readfds = _readfds;
    let writefds = _writefds;
    let exceptfds = _exceptfds;

    // 提前缓存当前任务的页表 token、fd 表、TCB 句柄,后续多次复用,避免反复加锁。
    let token = get_current_token();
    let files = current_files();
    let task = current_task().unwrap();

    // -------- 第 ② 段:临时替换 signal_mask(pselect 区别于 select 的关键)--------
    //
    // pselect6 相比 select 多了"原子地切换信号屏蔽字"语义:进入等待前用 user 传入的
    // mask 覆盖原 mask,返回前恢复。这避免了 select + sigprocmask 之间存在窗口、
    // 信号丢失的经典竞态。restore_mask 在函数末尾负责恢复。
    let mut restore_mask = None;
    if _sigmask != 0 {
        // user 传的是 { sigmask_ptr, sigset_size } 结构,而不是直接的位图指针。
        let Some(arg) =
            try_read_user_value::<PSelectSigmaskArg>(token, _sigmask as *const PSelectSigmaskArg)
        else {
            return err(SyscallError::EFAULT);
        };
        // sigset_size 必须至少能装下我们用的 u64 位图,否则视为 ABI 不兼容。
        if arg.sigset_size < core::mem::size_of::<u64>() {
            return err(SyscallError::EINVAL);
        }
        let mut new_mask = 0u64;
        if arg.sigmask_ptr != 0 {
            let Some(mask) = try_read_user_value::<u64>(token, arg.sigmask_ptr as *const u64)
            else {
                return err(SyscallError::EFAULT);
            };
            new_mask = mask;
        }
        // SIGKILL / SIGSTOP 按 POSIX 永远不可屏蔽,即使 user 在 mask 里置位也要强制清掉,
        // 否则会出现一个进程永远等不到 kill -9 的灾难场景。
        let sigkill_bit = signal_bit(SIGKILL_NUM).unwrap_or(0);
        let sigstop_bit = signal_bit(SIGSTOP_NUM).unwrap_or(0);
        new_mask &= !(sigkill_bit | sigstop_bit);
        // 在 TCB 临界区里完成 "读旧值 + 写新值",保证替换原子。
        let old_mask = {
            let mut inner = task.borrow_mut();
            let old = inner.signal_mask;
            inner.signal_mask = new_mask;
            old
        };
        restore_mask = Some(old_mask);
    }

    // -------- 第 ③ 段:把 user 的相对 timespec 换算成绝对截止时间(纳秒)--------
    //
    // - timeout_ptr == 0 → None,表示无限等待;
    // - 否则把 user 的 (sec, nsec) 相对值与 now_ns() 相加,得到一个统一的绝对截止时间,
    //   后续两个等待循环都用这个 deadline 直接比较,免去每次重算。
    // - 注意:任意一条错误路径返回前都要恢复 signal_mask,否则上面 ② 段改的位不会复原。
    let deadline_ns = if timeout_ptr == 0 {
        None
    } else {
        let Some(ts) = try_read_user_value::<TimeSpec>(token, timeout_ptr as *const TimeSpec)
        else {
            recover_mask(task.clone(), restore_mask);
            return err(SyscallError::EFAULT);
        };
        let Some(delta_ns) = timespec_to_ns(ts) else {
            recover_mask(task.clone(), restore_mask);
            return err(SyscallError::EINVAL);
        };
        // saturating_add 防止 user 传超大值时溢出回绕成"已经超时"。
        Some(now_ns().saturating_add(delta_ns))
    };

    // -------- 第 ④ 段:nfds == 0 的"纯睡眠"快速路径 --------
    //
    // 没有任何 fd 要监听,等价于一个可被信号唤醒的 nanosleep。musl 部分实现会用这种
    // 方式做毫秒级延时,所以我们必须支持,不能直接返回 EINVAL。
    if nfds == 0 {
        let ret = loop {
            // 每轮重新读 pending / mask,因为 mask 可能在子线程里被改(虽然罕见),
            // pending 则会被其它核 / 中断在任意时刻置位。
            let (pending, mask) = {
                let inner = task.borrow_mut();
                (inner.pending_signals, inner.signal_mask)
            };
            // SIGCHLD 只有在 disposition 为默认忽略或 SIG_IGN 时才跳过；
            // 若用户安装了 handler，pselect 仍必须被 EINTR 打断。
            if has_wait_interrupting_pending(pending, mask) {
                break err(SyscallError::EINTR);
            }
            if let Some(deadline) = deadline_ns {
                if now_ns() >= deadline {
                    break 0;
                }
                // 有 deadline → suspend(可被调度回来重新检查 deadline / 信号);
                // 没 deadline → block(等显式唤醒,减少无谓 busy 唤醒)。
                crate::task::processor::suspend_current_and_run_next();
            } else {
                // Publish Blocked with local IRQs disabled, then recheck the
                // signal condition.  This is the pselect equivalent of Linux
                // set_current_state() before schedule(); it closes the window
                // where a signal wake races with timer preemption.
                let prepared = PreparedWait::new().expect("pselect wait lost its current task");
                let (pending, mask) = {
                    let inner = task.borrow_mut();
                    (inner.pending_signals, inner.signal_mask)
                };
                if has_wait_interrupting_pending(pending, mask) {
                    break err(SyscallError::EINTR);
                }
                prepared.sleep();
            }
        };
        // 退出快速路径前同样要恢复 ② 段临时替换的 signal_mask。
        recover_mask(task.clone(), restore_mask);
        return ret;
    }

    // -------- 第 ⑤ 段:有 fdset 的真正 select 路径 --------
    //
    // 内存布局:fdset 是位图,每 8 个 fd 占 1 字节;in_* 持有 user 传入的输入位图,
    // out_* 是本轮计算出的输出位图(只有 break 时才写回 user),双缓冲避免循环里
    // 反复 copy_to_user。
    let bytes_len = (nfds + 7) / 8;
    if bytes_len > MAX_FDSET_BYTES {
        recover_mask(task.clone(), restore_mask);
        return err(SyscallError::EINVAL);
    }

    let mut in_r = alloc::vec![0u8; bytes_len];
    let mut in_w = alloc::vec![0u8; bytes_len];
    let mut in_e = alloc::vec![0u8; bytes_len];
    let mut out_r = alloc::vec![0u8; bytes_len];
    let mut out_w = alloc::vec![0u8; bytes_len];
    let mut out_e = alloc::vec![0u8; bytes_len];

    // 把三个 user fdset 各自拷进内核(空指针即跳过)。任何一个拷贝失败都按
    // EFAULT 退出,且退出前同样要恢复 signal_mask。
    // 这里也就是所谓 Select需要拷贝 性能底下的地方
    if readfds != 0 && try_copy_from_user(token, readfds as *const u8, in_r.as_mut_slice()).is_err()
    {
        recover_mask(task.clone(), restore_mask);
        return err(SyscallError::EFAULT);
    }
    if writefds != 0
        && try_copy_from_user(token, writefds as *const u8, in_w.as_mut_slice()).is_err()
    {
        recover_mask(task.clone(), restore_mask);
        return err(SyscallError::EFAULT);
    }
    if exceptfds != 0
        && try_copy_from_user(token, exceptfds as *const u8, in_e.as_mut_slice()).is_err()
    {
        recover_mask(task.clone(), restore_mask);
        return err(SyscallError::EFAULT);
    }

    // 把 out_* 回写到 user 三个 fdset。只在确认要返回(就绪 / 超时)时调用一次,
    // 不放进循环里以节约 copy_to_user 开销。
    let write_sets = |r: &[u8], w: &[u8], e: &[u8]| -> isize {
        if readfds != 0 && try_copy_to_user(token, readfds as *mut u8, r).is_err() {
            return err(SyscallError::EFAULT);
        }
        if writefds != 0 && try_copy_to_user(token, writefds as *mut u8, w).is_err() {
            return err(SyscallError::EFAULT);
        }
        if exceptfds != 0 && try_copy_to_user(token, exceptfds as *mut u8, e).is_err() {
            return err(SyscallError::EFAULT);
        }
        0
    };

    struct SelectFdInterest {
        fd: usize,
        byte: usize,
        bit_mask: u8,
        want_r: bool,
        want_w: bool,
        want_e: bool,
    }

    struct SelectPollTarget {
        file: Option<Arc<dyn File + Send + Sync>>,
        fixed_mask: Option<i16>,
    }

    let mut watched = alloc::vec::Vec::new();
    for fd in 0..nfds {
        let byte = fd / 8;
        let bit = fd % 8;
        let bit_mask = 1u8 << bit;
        let want_r = readfds != 0 && (in_r[byte] & bit_mask) != 0;
        let want_w = writefds != 0 && (in_w[byte] & bit_mask) != 0;
        let want_e = exceptfds != 0 && (in_e[byte] & bit_mask) != 0;
        if want_r || want_w || want_e {
            watched.push(SelectFdInterest {
                fd,
                byte,
                bit_mask,
                want_r,
                want_w,
                want_e,
            });
        }
    }

    // 主等待循环:每一轮 = "检查信号 → 扫一遍 fd → 命中就返回 / 超时就返回 / 都没命中就 yield"。
    // 没有事件驱动唤醒机制,采用 busy poll + suspend 让出 CPU 的简化模型。
    let ret = loop {
        // ① 信号检查:被未屏蔽且可递送的信号打断要立刻 EINTR 返回。
        let (pending, mask) = {
            let inner = task.borrow_mut();
            (inner.pending_signals, inner.signal_mask)
        };
        if has_wait_interrupting_pending(pending, mask) {
            break err(SyscallError::EINTR);
        }

        // ② 每轮把 out_* 清空重算,避免上一轮残留位影响本轮结果。
        let mut ready = 0isize;
        out_r.fill(0);
        out_w.fill(0);
        out_e.fill(0);

        // ③ 对本轮监听的 fd 拿一次 fd 表快照，再逐个统计就绪数。
        //    这样仍然不在持 fd 表锁时调用 poll_mask()，但避免 100+ fd 场景
        //    对同一张表重复加锁。
        let file_snapshot = if watched.is_empty() {
            alloc::vec::Vec::new()
        } else {
            let files_guard = files.lock();
            watched
                .iter()
                .map(|watch| {
                    files_guard
                        .get_poll_snapshot(watch.fd)
                        .map(|(file, fixed_mask, _flags)| SelectPollTarget { file, fixed_mask })
                })
                .collect::<alloc::vec::Vec<_>>()
        };
        let mut bad_fd = false;
        for (watch, target) in watched.iter().zip(file_snapshot.iter()) {
            let Some(target) = target.as_ref() else {
                // user 让我们监听一个不存在的 fd → 整次 select 返回 EBADF。
                bad_fd = true;
                break;
            };

            // 统一通过 poll_mask() 拿到当前 fd 的可读 / 可写 / 错误位,把 select 的
            // 三集合语义复用到 poll 的实现上。
            let mask_now = match target.fixed_mask {
                Some(mask) => mask,
                None => target
                    .file
                    .as_ref()
                    .map(|file| file.poll_mask())
                    .unwrap_or(0),
            };
            // POLLHUP(对端关闭)在 select 语义里也算"可读",且要优先于普通 POLLIN
            // 判断:这样 user 的 read() 才会拿到 EOF 而不是一直阻塞。
            if watch.want_r && (mask_now & crate::fs::POLLHUP) != 0 {
                out_r[watch.byte] |= watch.bit_mask;
                ready += 1;
            } else if watch.want_r && (mask_now & POLLIN) != 0 {
                out_r[watch.byte] |= watch.bit_mask;
                ready += 1;
            }
            if watch.want_w && (mask_now & POLLOUT) != 0 {
                out_w[watch.byte] |= watch.bit_mask;
                ready += 1;
            }
            // exceptfds 在 Linux 里实际承载的是带外数据(POLLPRI),不是泛义"错误"。
            if watch.want_e && (mask_now & POLLPRI) != 0 {
                out_e[watch.byte] |= watch.bit_mask;
                ready += 1;
            }
        }

        if bad_fd {
            break EBADF;
        }

        // ④ 有 fd 就绪 → 写回三个 fdset,返回就绪计数。
        if ready != 0 {
            let wr = write_sets(&out_r, &out_w, &out_e);
            if wr != 0 {
                break wr;
            }
            break ready;
        }

        // ⑤ 没就绪 + 已到截止时间 → 返回 0,但仍要把(全 0 的)fdset 回写,
        //    否则 user 端的 FD_ISSET 可能读到 stale 输入位。
        if let Some(deadline) = deadline_ns {
            if now_ns() >= deadline {
                let wr = write_sets(&out_r, &out_w, &out_e);
                if wr != 0 {
                    break wr;
                }
                break 0;
            }
        }

        if readfds != 0 {
            let mut polled = false;
            for (watch, target) in watched.iter().zip(file_snapshot.iter()) {
                if !watch.want_r {
                    continue;
                }
                let Some(target) = target.as_ref() else {
                    continue;
                };
                let Some(file) = target.file.as_ref() else {
                    continue;
                };
                let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() else {
                    continue;
                };
                polled = sock.busy_poll_for_poll_events(POLLIN) || polled;
            }
            if polled {
                continue;
            }
        }

        // ⑥ 让出 CPU,等下次被调度回来再扫一遍。
        crate::task::processor::suspend_current_and_run_next();
    };

    // 函数唯一的统一出口:还原 ② 段临时替换的 signal_mask。pselect 区别于 select 的
    // "原子还原 mask" 语义就靠这里兜底。
    recover_mask(task.clone(), restore_mask);

    ret
}
