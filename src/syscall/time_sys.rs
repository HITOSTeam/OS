use crate::{
    config::clock_freq,
    debug_config::{DEBUG_CYCLICTEST, DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    fs::{POLLIN, POLLOUT, POLLPRI},
    mm::{
        read_user_value, try_copy_from_user, try_copy_to_user, try_read_user_value,
        try_write_user_value, write_user_value,
    },
    syscall::misc::decode_linux_tid,
    syscall::thread,
    task::block_sleep::{
        create_posix_timer, delete_posix_timer, itimer_remaining_and_interval_ms,
        query_posix_timer, set_itimer_timer, set_posix_timer, take_posix_timer_overrun,
    },
    task::signal::{SIGALRM_NUM, SIGKILL_NUM, SIGSTOP_NUM, has_unmasked_pending, signal_bit},
    task::{
        ProcessControlBlock,
        manager::pid2process,
        processor::{current_files_process, current_process, current_task},
        runtime::{
            current_task_cpu_time_ns, process_cpu_time_ns, process_task_by_index, task_cpu_time_ns,
        },
    },
    time::{get_time, get_time_ns},
    trap::get_current_token,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use spin::Mutex;

const CYCLICTEST_LOG_LIMIT: usize = 32;
static CLOCK_NS_LOGS: AtomicUsize = AtomicUsize::new(0);
const DEFAULT_REALTIME_EPOCH_NS: i64 = 1_700_000_000_000_000_000;
static REALTIME_OFFSET_NS: AtomicI64 = AtomicI64::new(DEFAULT_REALTIME_EPOCH_NS);
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

const EINVAL: isize = -22;
const EFAULT: isize = -14;
const EPERM: isize = -1;
const EOPNOTSUPP: isize = -95;
const EINTR: isize = -4;
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

#[derive(Clone, Copy)]
struct AdjtimexState {
    offset: i64,
    freq: i64,
    maxerror: i64,
    esterror: i64,
    status: i32,
    constant: i64,
    tick: i64,
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
    let base = now_ns() as i128;
    let offset = REALTIME_OFFSET_NS.load(Ordering::Relaxed) as i128;
    let adjusted = base + offset;
    if adjusted <= 0 {
        0
    } else if adjusted > u64::MAX as i128 {
        u64::MAX
    } else {
        adjusted as u64
    }
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

#[derive(Clone, Copy)]
struct DynamicCpuClock {
    target_id: usize,
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

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal {
    sec: u64,
    usec: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeZone {
    minuteswest: i32,
    dsttime: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PSelectSigmaskArg {
    sigmask_ptr: usize,
    sigset_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Tms {
    tms_utime: i64,
    tms_stime: i64,
    tms_cutime: i64,
    tms_cstime: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal64 {
    sec: i64,
    usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Timex {
    modes: u32,
    _pad0: u32,
    offset: i64,
    freq: i64,
    maxerror: i64,
    esterror: i64,
    status: i32,
    _pad1: i32,
    constant: i64,
    precision: i64,
    tolerance: i64,
    time: TimeVal64,
    tick: i64,
    ppsfreq: i64,
    jitter: i64,
    shift: i32,
    _pad2: i32,
    stabil: i64,
    jitcnt: i64,
    calcnt: i64,
    errcnt: i64,
    stbcnt: i64,
    tai: i32,
    _pad3: [i32; 11],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ITimerVal {
    it_interval: TimeVal64,
    it_value: TimeVal64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SigEvent {
    sigev_value: usize,
    sigev_signo: i32,
    sigev_notify: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ITimerSpec {
    it_interval: TimeSpec,
    it_value: TimeSpec,
}

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
        return EFAULT;
    }
    let token = get_current_token();
    let Some(mut tx) = try_read_user_value::<Timex>(token, ptr as *const Timex) else {
        return EFAULT;
    };
    let modes = tx.modes;
    if modes != ADJ_OFFSET_SINGLESHOT && modes != ADJ_OFFSET_SS_READ && (modes & 0x8000) != 0 {
        return EINVAL;
    }
    if (modes & !TIMEX_ALLOWED_MODES) != 0 {
        return EINVAL;
    }

    let mut state = ADJTIMEX_STATE.lock();
    if modes != 0 && modes != ADJ_OFFSET_SS_READ {
        if !can_adjust_wallclock() {
            return EPERM;
        }
        if (modes & ADJ_TICK) != 0 {
            let (min_tick, max_tick) = timex_tick_limits();
            if tx.tick < min_tick || tx.tick > max_tick {
                return EINVAL;
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
        return EFAULT;
    }
    // TIME_OK
    0
}

pub fn syscall_settimeofday(tv_ptr: usize, tz_ptr: usize) -> isize {
    if tv_ptr == 0 {
        if tz_ptr != 0 {
            let token = get_current_token();
            if try_read_user_value::<TimeZone>(token, tz_ptr as *const TimeZone).is_none() {
                return EFAULT;
            }
        }
        return EINVAL;
    }
    let token = get_current_token();
    let Some(tv) = try_read_user_value::<TimeVal64>(token, tv_ptr as *const TimeVal64) else {
        return EFAULT;
    };
    if tv.sec < 0 || tv.usec < 0 || tv.usec >= 1_000_000 {
        return EINVAL;
    }
    if !can_adjust_wallclock() {
        return EPERM;
    }
    if tz_ptr != 0 && try_read_user_value::<TimeZone>(token, tz_ptr as *const TimeZone).is_none() {
        return EFAULT;
    }
    let target_ns = (tv.sec as u64)
        .saturating_mul(NSEC_PER_SEC)
        .saturating_add((tv.usec as u64).saturating_mul(1_000));
    let current_mono_ns = now_ns();
    let offset = (target_ns as i128)
        .saturating_sub(current_mono_ns as i128)
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    REALTIME_OFFSET_NS.store(offset, Ordering::Relaxed);
    crate::fs::cancel_realtime_timerfds_on_set();
    0
}

pub fn syscall_adjtimex(ptr: usize) -> isize {
    apply_adjtimex(ptr)
}

pub fn syscall_clock_adjtime(clk_id: usize, ptr: usize) -> isize {
    if decode_dynamic_cpu_clock(clk_id as i32).is_some() {
        return EINVAL;
    }
    if clk_id != CLOCK_REALTIME {
        return EINVAL;
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
            return EFAULT;
        }
    }
    if tz_ptr != 0 && try_read_user_value::<TimeZone>(token, tz_ptr as *const TimeZone).is_none() {
        return EFAULT;
    }
    0
}

pub fn syscall_nanosleep(req_ptr: usize, _rem_ptr: usize) -> isize {
    if req_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value(token, req_ptr as *const TimeSpec) else {
        return EFAULT;
    };
    let Some(req_ns) = timespec_to_ns(ts) else {
        return EINVAL;
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
        let ms = ((remaining + 999_999) / 1_000_000) as usize;
        let ret = thread::sys_sleep(ms.max(1));
        if ret == EINTR {
            if DEBUG_SIGNAL {
                let now_ms = (get_time() as u64)
                    .saturating_mul(1_000)
                    .saturating_div(clock_freq() as u64);
                crate::log_if!(
                    DEBUG_SIGNAL,
                    info,
                    "[nanosleep] ret=EINTR now_ms={} elapsed_ns={}",
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
            return EINTR;
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
        return EFAULT;
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
            _ => return EINVAL,
        }
    }
    let ns = if let Some(clk) = dynamic_clk {
        let Some(ns) = dynamic_cpu_clock_time_ns(clk) else {
            return EINVAL;
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
            _ => return EINVAL,
        }
    };
    let ts = TimeSpec {
        sec: (ns / NSEC_PER_SEC) as i64,
        nsec: (ns % NSEC_PER_SEC) as i64,
    };
    let token = get_current_token();
    if try_write_user_value(token, tp_ptr as *mut TimeSpec, &ts).is_err() {
        return EFAULT;
    }
    0
}

pub fn syscall_clock_settime(clk_id: usize, tp_ptr: usize) -> isize {
    if decode_dynamic_cpu_clock(clk_id as i32).is_some() {
        return EINVAL;
    }
    if clk_id != CLOCK_REALTIME {
        return EINVAL;
    }
    if tp_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value(token, tp_ptr as *const TimeSpec) else {
        return EFAULT;
    };
    let Some(target_ns) = timespec_to_ns(ts) else {
        return EINVAL;
    };
    if !can_adjust_wallclock() {
        return EPERM;
    }
    let current_mono_ns = now_ns();
    let offset = (target_ns as i128)
        .saturating_sub(current_mono_ns as i128)
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    REALTIME_OFFSET_NS.store(offset, Ordering::Relaxed);
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
            _ => return EINVAL,
        }
    }
    if tp_ptr == 0 {
        return 0;
    }
    let token = get_current_token();
    let ts = TimeSpec {
        sec: 0,
        nsec: 1_000_000,
    };
    if try_write_user_value(token, tp_ptr as *mut TimeSpec, &ts).is_err() {
        return EFAULT;
    }
    0
}

pub fn syscall_timer_create(clock_id: usize, sevp_ptr: usize, timerid_ptr: usize) -> isize {
    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {}
        _ => return EINVAL,
    }
    if timerid_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let signum = if sevp_ptr == 0 {
        SIGALRM_NUM
    } else {
        let Some(sev) = try_read_user_value(token, sevp_ptr as *const SigEvent) else {
            return EFAULT;
        };
        if sev.sigev_notify != SIGEV_SIGNAL {
            return EINVAL;
        }
        if sev.sigev_signo <= 0 || sev.sigev_signo > 64 {
            return EINVAL;
        }
        sev.sigev_signo as usize
    };
    let pid = current_process().getpid();
    let thread_tid = if clock_id == CLOCK_THREAD_CPUTIME_ID {
        let Some(task) = current_task() else {
            return EINVAL;
        };
        let inner = task.borrow_mut();
        inner.res.as_ref().map(|res| res.tid)
    } else {
        None
    };
    let Some(timer_id) = create_posix_timer(pid, clock_id, signum, thread_tid) else {
        return EINVAL;
    };
    let timer_id_i32 = timer_id as i32;
    if try_write_user_value(token, timerid_ptr as *mut i32, &timer_id_i32).is_err() {
        return EFAULT;
    }
    0
}

pub fn syscall_timer_gettime(timer_id: isize, curr_ptr: usize) -> isize {
    if timer_id < 0 {
        return EINVAL;
    }
    if curr_ptr == 0 {
        return EFAULT;
    }
    let pid = current_process().getpid();
    let Ok((clock_id, deadline_ns, interval_ns, thread_tid)) =
        query_posix_timer(pid, timer_id as usize)
    else {
        return EINVAL;
    };
    let Some(now_ns) = timer_clock_now_ns(clock_id, pid, thread_tid) else {
        return EINVAL;
    };
    let value_ns = deadline_ns.map(|d| d.saturating_sub(now_ns)).unwrap_or(0);
    let spec = ITimerSpec {
        it_interval: ns_to_timespec(interval_ns),
        it_value: ns_to_timespec(value_ns),
    };
    let token = get_current_token();
    if try_write_user_value(token, curr_ptr as *mut ITimerSpec, &spec).is_err() {
        return EFAULT;
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
        return EINVAL;
    }
    if new_ptr == 0 {
        return EINVAL;
    }
    if (flags & !TIMER_ABSTIME) != 0 {
        return EINVAL;
    }
    let token = get_current_token();
    let Some(new_spec) = try_read_user_value(token, new_ptr as *const ITimerSpec) else {
        return EFAULT;
    };
    let pid = current_process().getpid();
    let Ok((clock_id, _, _, thread_tid)) = query_posix_timer(pid, timer_id as usize) else {
        return EINVAL;
    };
    let Some(value_ns) = timespec_to_ns(new_spec.it_value) else {
        return EINVAL;
    };
    let Some(interval_ns) = timespec_to_ns(new_spec.it_interval) else {
        return EINVAL;
    };
    let Some(now_base) = timer_clock_now_ns(clock_id, pid, thread_tid) else {
        return EINVAL;
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
        return EINVAL;
    };
    if old_ptr != 0 {
        let old_spec = ITimerSpec {
            it_interval: ns_to_timespec(prev_interval_ns),
            it_value: ns_to_timespec(prev_remain_ns),
        };
        if try_write_user_value(token, old_ptr as *mut ITimerSpec, &old_spec).is_err() {
            return EFAULT;
        }
    }
    0
}

pub fn syscall_timer_delete(timer_id: isize) -> isize {
    if timer_id < 0 {
        return EINVAL;
    }
    let pid = current_process().getpid();
    delete_posix_timer(pid, timer_id as usize)
}

pub fn syscall_timer_getoverrun(timer_id: isize) -> isize {
    if timer_id < 0 {
        return EINVAL;
    }
    let pid = current_process().getpid();
    let Ok(overrun) = take_posix_timer_overrun(pid, timer_id as usize) else {
        return EINVAL;
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
        return EFAULT;
    }
    if clk_id != CLOCK_REALTIME && clk_id != CLOCK_MONOTONIC {
        return EOPNOTSUPP;
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value(token, req_ptr as *const TimeSpec) else {
        return EFAULT;
    };
    let Some(req_ns) = timespec_to_ns(ts) else {
        return EINVAL;
    };
    let clock_now_ns = || match clk_id {
        CLOCK_REALTIME => realtime_now_ns(),
        CLOCK_MONOTONIC => now_ns(),
        _ => now_ns(),
    };
    let start_ns = clock_now_ns();
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
        // Our sleep granularity is milliseconds; don't block on sub-ms targets.
        let ms = ((delta_ns + 999_999) / 1_000_000) as usize;
        if DEBUG_CYCLICTEST {
            let idx = CLOCK_NS_LOGS.fetch_add(1, Ordering::Relaxed);
            if idx < CYCLICTEST_LOG_LIMIT || ms > 2_000 {
                let tid = current_task()
                    .and_then(|task| task.borrow_mut().res.as_ref().map(|r| r.tid))
                    .unwrap_or(usize::MAX);
                log::warn!(
                    "[clock_nanosleep] tid={} clk_id={} flags={:#x} target_ns={} now_ns={} delta_ns={} sleep_ms={}",
                    tid,
                    clk_id,
                    flags,
                    target_ns,
                    current_ns,
                    delta_ns,
                    ms
                );
            }
        }
        if ms == 0 {
            return 0;
        }
        let ret = thread::sys_sleep(ms);
        if ret == EINTR {
            if DEBUG_SIGNAL {
                let now_ms = (get_time() as u64)
                    .saturating_mul(1_000)
                    .saturating_div(clock_freq() as u64);
                crate::log_if!(
                    DEBUG_SIGNAL,
                    info,
                    "[clock_nanosleep] ret=EINTR now_ms={} elapsed_ns={}",
                    now_ms,
                    clock_now_ns().saturating_sub(start_ns)
                );
            }
            if rem_ptr != 0 {
                let remaining = target_ns.saturating_sub(clock_now_ns());
                let rem = ns_to_timespec(remaining);
                let token = get_current_token();
                if try_write_user_value(token, rem_ptr as *mut TimeSpec, &rem).is_err() {
                    return EFAULT;
                }
            }
            return EINTR;
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
        return EINVAL;
    }
    if curr_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let pid = crate::task::processor::current_process().getpid();
    let (remaining_ms, interval_ms) = itimer_remaining_and_interval_ms(pid, which);
    let val = build_itimerval(remaining_ms, interval_ms);
    if try_write_user_value(token, curr_ptr as *mut ITimerVal, &val).is_err() {
        return EFAULT;
    }
    0
}

pub fn syscall_setitimer(which: usize, new_ptr: usize, old_ptr: usize) -> isize {
    let Some(signum) = itimer_signum(which) else {
        return EINVAL;
    };
    if new_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let Some(new_val) = try_read_user_value(token, new_ptr as *const ITimerVal) else {
        return EFAULT;
    };
    let Some(delay_us) = timeval_to_us(new_val.it_value) else {
        return EINVAL;
    };
    let Some(interval_us) = timeval_to_us(new_val.it_interval) else {
        return EINVAL;
    };
    let pid = crate::task::processor::current_process().getpid();
    let (prev_ms, prev_interval_ms) = itimer_remaining_and_interval_ms(pid, which);
    if old_ptr != 0 {
        let old_val = build_itimerval(prev_ms, prev_interval_ms);
        if try_write_user_value(token, old_ptr as *mut ITimerVal, &old_val).is_err() {
            return EFAULT;
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

/// Linux `pselect6` (syscall 72 on riscv64).
///
/// Enough for iperf/netperf event loops:
/// - When fdsets are provided, report readiness based on our fd table.
/// - When `nfds==0` (or all fdsets are NULL), treat it as a sleep/yield primitive.
pub fn syscall_pselect6(
    _nfds: usize,
    _readfds: usize,
    _writefds: usize,
    _exceptfds: usize,
    timeout_ptr: usize,
    _sigmask: usize,
) -> isize {
    const EBADF: isize = -9;
    const MAX_FDSET_BYTES: usize = 256 * 1024;
    if (_nfds as isize) < 0 {
        return EINVAL;
    }
    if _nfds > i32::MAX as usize {
        return EINVAL;
    }
    let nfds = _nfds;
    let readfds = _readfds;
    let writefds = _writefds;
    let exceptfds = _exceptfds;

    let token = get_current_token();
    let process = current_files_process();
    let task = current_task().unwrap();

    let mut restore_mask = None;
    if _sigmask != 0 {
        let Some(arg) =
            try_read_user_value::<PSelectSigmaskArg>(token, _sigmask as *const PSelectSigmaskArg)
        else {
            return EFAULT;
        };
        if arg.sigset_size < core::mem::size_of::<u64>() {
            return EINVAL;
        }
        let mut new_mask = 0u64;
        if arg.sigmask_ptr != 0 {
            let Some(mask) = try_read_user_value::<u64>(token, arg.sigmask_ptr as *const u64)
            else {
                return EFAULT;
            };
            new_mask = mask;
        }
        let sigkill_bit = signal_bit(SIGKILL_NUM).unwrap_or(0);
        let sigstop_bit = signal_bit(SIGSTOP_NUM).unwrap_or(0);
        new_mask &= !(sigkill_bit | sigstop_bit);
        let old_mask = {
            let mut inner = task.borrow_mut();
            let old = inner.signal_mask;
            inner.signal_mask = new_mask;
            old
        };
        restore_mask = Some(old_mask);
    }

    let deadline_ns = if timeout_ptr == 0 {
        None
    } else {
        let Some(ts) = try_read_user_value::<TimeSpec>(token, timeout_ptr as *const TimeSpec)
        else {
            if let Some(old_mask) = restore_mask {
                let mut inner = task.borrow_mut();
                inner.signal_mask = old_mask;
            }
            return EFAULT;
        };
        let Some(delta_ns) = timespec_to_ns(ts) else {
            if let Some(old_mask) = restore_mask {
                let mut inner = task.borrow_mut();
                inner.signal_mask = old_mask;
            }
            return EINVAL;
        };
        Some(now_ns().saturating_add(delta_ns))
    };

    if nfds == 0 {
        let ret = loop {
            let (pending, mask) = {
                let inner = task.borrow_mut();
                (inner.pending_signals, inner.signal_mask)
            };
            if has_unmasked_pending(pending, mask, false) {
                break EINTR;
            }
            if let Some(deadline) = deadline_ns {
                if now_ns() >= deadline {
                    break 0;
                }
                crate::task::processor::suspend_current_and_run_next();
            } else {
                crate::task::processor::block_current_and_run_next();
            }
        };
        if let Some(old_mask) = restore_mask {
            let mut inner = task.borrow_mut();
            inner.signal_mask = old_mask;
        }
        return ret;
    }

    let bytes_len = (nfds + 7) / 8;
    if bytes_len > MAX_FDSET_BYTES {
        if let Some(old_mask) = restore_mask {
            let mut inner = task.borrow_mut();
            inner.signal_mask = old_mask;
        }
        return EINVAL;
    }

    let mut in_r = alloc::vec![0u8; bytes_len];
    let mut in_w = alloc::vec![0u8; bytes_len];
    let mut in_e = alloc::vec![0u8; bytes_len];
    let mut out_r = alloc::vec![0u8; bytes_len];
    let mut out_w = alloc::vec![0u8; bytes_len];
    let mut out_e = alloc::vec![0u8; bytes_len];

    if readfds != 0 && try_copy_from_user(token, readfds as *const u8, in_r.as_mut_slice()).is_err()
    {
        if let Some(old_mask) = restore_mask {
            let mut inner = task.borrow_mut();
            inner.signal_mask = old_mask;
        }
        return EFAULT;
    }
    if writefds != 0
        && try_copy_from_user(token, writefds as *const u8, in_w.as_mut_slice()).is_err()
    {
        if let Some(old_mask) = restore_mask {
            let mut inner = task.borrow_mut();
            inner.signal_mask = old_mask;
        }
        return EFAULT;
    }
    if exceptfds != 0
        && try_copy_from_user(token, exceptfds as *const u8, in_e.as_mut_slice()).is_err()
    {
        if let Some(old_mask) = restore_mask {
            let mut inner = task.borrow_mut();
            inner.signal_mask = old_mask;
        }
        return EFAULT;
    }

    let write_sets = |r: &[u8], w: &[u8], e: &[u8]| -> isize {
        if readfds != 0 && try_copy_to_user(token, readfds as *mut u8, r).is_err() {
            return EFAULT;
        }
        if writefds != 0 && try_copy_to_user(token, writefds as *mut u8, w).is_err() {
            return EFAULT;
        }
        if exceptfds != 0 && try_copy_to_user(token, exceptfds as *mut u8, e).is_err() {
            return EFAULT;
        }
        0
    };

    let ret = loop {
        let (pending, mask) = {
            let inner = task.borrow_mut();
            (inner.pending_signals, inner.signal_mask)
        };
        if has_unmasked_pending(pending, mask, false) {
            break EINTR;
        }

        let mut ready = 0isize;
        out_r.fill(0);
        out_w.fill(0);
        out_e.fill(0);

        let mut bad_fd = false;
        for fd in 0..nfds {
            let byte = fd / 8;
            let bit = fd % 8;
            let mask = 1u8 << bit;
            let want_r = readfds != 0 && (in_r[byte] & mask) != 0;
            let want_w = writefds != 0 && (in_w[byte] & mask) != 0;
            let want_e = exceptfds != 0 && (in_e[byte] & mask) != 0;
            if !want_r && !want_w && !want_e {
                continue;
            }
            let file = {
                let inner = process.borrow_mut();
                if fd >= inner.fd_table.len() {
                    None
                } else {
                    inner.fd_table[fd].clone()
                }
            };
            let Some(file) = file else {
                bad_fd = true;
                break;
            };

            let mask_now = file.poll_mask();
            if want_r && (mask_now & crate::fs::POLLHUP) != 0 {
                out_r[byte] |= mask;
                ready += 1;
            } else if want_r && (mask_now & POLLIN) != 0 {
                out_r[byte] |= mask;
                ready += 1;
            }
            if want_w && (mask_now & POLLOUT) != 0 {
                out_w[byte] |= mask;
                ready += 1;
            }
            if want_e && (mask_now & POLLPRI) != 0 {
                out_e[byte] |= mask;
                ready += 1;
            }
        }

        if bad_fd {
            break EBADF;
        }

        if ready != 0 {
            let wr = write_sets(&out_r, &out_w, &out_e);
            if wr != 0 {
                break wr;
            }
            break ready;
        }

        if let Some(deadline) = deadline_ns {
            if now_ns() >= deadline {
                let wr = write_sets(&out_r, &out_w, &out_e);
                if wr != 0 {
                    break wr;
                }
                break 0;
            }
        }

        crate::task::processor::suspend_current_and_run_next();
    };

    if let Some(old_mask) = restore_mask {
        let mut inner = task.borrow_mut();
        inner.signal_mask = old_mask;
    }

    ret
}
