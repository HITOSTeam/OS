use crate::{
    config::clock_freq,
    debug_config::{DEBUG_CYCLICTEST, DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    mm::{
        read_user_value, try_copy_from_user, try_copy_to_user, try_read_user_value,
        try_write_user_value, write_user_value,
    },
    syscall::thread,
    task::block_sleep::{
        create_posix_timer, delete_posix_timer, itimer_remaining_and_interval_ms,
        query_posix_timer, set_itimer_timer, set_posix_timer, take_posix_timer_overrun,
    },
    task::processor::{current_files_process, current_process, current_task},
    task::signal::{has_unmasked_pending, signal_bit, SIGALRM_NUM, SIGKILL_NUM, SIGSTOP_NUM},
    time::get_time,
    trap::get_current_token,
};
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

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

const EINVAL: isize = -22;
const EFAULT: isize = -14;
const EOPNOTSUPP: isize = -95;
const EINTR: isize = -4;
const TIMER_ABSTIME: usize = 1;
const SIGEV_SIGNAL: i32 = 0;

fn ticks_to_ns(ticks: u64) -> u64 {
    let freq = clock_freq() as u128;
    ((ticks as u128).saturating_mul(NSEC_PER_SEC as u128) / freq) as u64
}

fn now_ns() -> u64 {
    ticks_to_ns(get_time() as u64)
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

fn ns_to_ms_ceil(ns: u64) -> usize {
    ((ns.saturating_add(999_999)) / 1_000_000) as usize
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
    let ns = match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => realtime_now_ns(),
        CLOCK_MONOTONIC
        | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID
        | CLOCK_MONOTONIC_RAW
        | CLOCK_MONOTONIC_COARSE
        | CLOCK_BOOTTIME => now_ns(),
        _ => return EINVAL,
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
    let current_mono_ns = now_ns();
    let offset = (target_ns as i128)
        .saturating_sub(current_mono_ns as i128)
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    REALTIME_OFFSET_NS.store(offset, Ordering::Relaxed);
    0
}

pub fn syscall_clock_getres(clk_id: usize, tp_ptr: usize) -> isize {
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
    let Some(timer_id) = create_posix_timer(pid, clock_id, signum) else {
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
    let Ok((_clock_id, deadline_ms, interval_ms)) = query_posix_timer(pid, timer_id as usize)
    else {
        return EINVAL;
    };
    let now_ms = crate::time::get_time_ms();
    let value_ms = deadline_ms.map(|d| d.saturating_sub(now_ms)).unwrap_or(0);
    let spec = ITimerSpec {
        it_interval: ns_to_timespec((interval_ms as u64).saturating_mul(1_000_000)),
        it_value: ns_to_timespec((value_ms as u64).saturating_mul(1_000_000)),
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
    let Ok((clock_id, _, _)) = query_posix_timer(pid, timer_id as usize) else {
        return EINVAL;
    };
    let Some(value_ns) = timespec_to_ns(new_spec.it_value) else {
        return EINVAL;
    };
    let Some(interval_ns) = timespec_to_ns(new_spec.it_interval) else {
        return EINVAL;
    };
    let mut initial_overrun = 0usize;
    let delay_ms = if value_ns == 0 {
        None
    } else if (flags & TIMER_ABSTIME) != 0 {
        let now_base = match clock_id {
            CLOCK_REALTIME => realtime_now_ns(),
            CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => now_ns(),
            _ => return EINVAL,
        };
        if value_ns <= now_base {
            if interval_ns > 0 {
                let overdue_ns = now_base.saturating_sub(value_ns);
                let expirations = overdue_ns / interval_ns + 1;
                initial_overrun = expirations.saturating_sub(1).min(i32::MAX as u64) as usize;
            }
            Some(0)
        } else {
            Some(ns_to_ms_ceil(value_ns - now_base).max(1))
        }
    } else {
        Some(ns_to_ms_ceil(value_ns).max(1))
    };
    let interval_ms = if interval_ns == 0 {
        0
    } else {
        ns_to_ms_ceil(interval_ns).max(1)
    };
    let Ok((prev_remain_ms, prev_interval_ms)) = set_posix_timer(
        pid,
        timer_id as usize,
        delay_ms,
        interval_ms,
        initial_overrun,
    ) else {
        return EINVAL;
    };
    if old_ptr != 0 {
        let old_spec = ITimerSpec {
            it_interval: ns_to_timespec((prev_interval_ms as u64).saturating_mul(1_000_000)),
            it_value: ns_to_timespec((prev_remain_ms as u64).saturating_mul(1_000_000)),
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

pub fn syscall_times(tms_ptr: usize) -> isize {
    if tms_ptr != 0 {
        let token = get_current_token();
        let tms = Tms {
            tms_utime: 0,
            tms_stime: 0,
            tms_cutime: 0,
            tms_cstime: 0,
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

            let (r_ok, w_ok) = crate::syscall::net::poll_file_read_write(&file);

            if want_r && r_ok {
                out_r[byte] |= mask;
                ready += 1;
            }
            if want_w && w_ok {
                out_w[byte] |= mask;
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
