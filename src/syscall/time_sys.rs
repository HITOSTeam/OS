use crate::{
    config::clock_freq,
    debug_config::{DEBUG_CYCLICTEST, DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    mm::{read_user_value, write_user_value},
    syscall::thread,
    task::block_sleep::{alarm_remaining_ms, set_alarm_timer},
    task::processor::current_task,
    time::get_time,
    trap::get_current_token,
};
use core::sync::atomic::{AtomicUsize, Ordering};

const CYCLICTEST_LOG_LIMIT: usize = 32;
static CLOCK_NS_LOGS: AtomicUsize = AtomicUsize::new(0);
const NSEC_PER_SEC: u64 = 1_000_000_000;

const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;

const EINVAL: isize = -22;
const EFAULT: isize = -14;
const EOPNOTSUPP: isize = -95;
const EINTR: isize = -4;

fn ticks_to_ns(ticks: u64) -> u64 {
    let freq = clock_freq() as u128;
    ((ticks as u128).saturating_mul(NSEC_PER_SEC as u128) / freq) as u64
}

fn now_ns() -> u64 {
    ticks_to_ns(get_time() as u64)
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

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal {
    sec: u64,
    usec: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
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

pub fn syscall_gettimeofday(tv_ptr: usize, _tz: usize) -> isize {
    if tv_ptr == 0 {
        return 0;
    }
    let ticks = get_time() as u64;
    let us = ticks.saturating_mul(1_000_000) / clock_freq() as u64;
    let tv = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let token = get_current_token();
    write_user_value(token, tv_ptr as *mut TimeVal, &tv);
    0
}

pub fn syscall_nanosleep(req_ptr: usize, _rem_ptr: usize) -> isize {
    if req_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let ts = read_user_value(token, req_ptr as *const TimeSpec);
    let Some(req_ns) = timespec_to_ns(ts) else {
        return EINVAL;
    };
    if req_ns == 0 {
        return 0;
    }
    let start_ns = now_ns();
    let ms = ((req_ns + 999_999) / 1_000_000) as usize;
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
            "[nanosleep] pid={} tid={} req_ns={} ms={} now_ms={}",
            pid,
            tid,
            req_ns,
            ms,
            now_ms
        );
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
                "[nanosleep] ret=EINTR now_ms={} elapsed_ns={}",
                now_ms,
                now_ns().saturating_sub(start_ns)
            );
        }
        if _rem_ptr != 0 {
            let elapsed = now_ns().saturating_sub(start_ns);
            let remaining = req_ns.saturating_sub(elapsed);
            let rem = ns_to_timespec(remaining);
            let token = get_current_token();
            write_user_value(token, _rem_ptr as *mut TimeSpec, &rem);
        }
        return EINTR;
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

pub fn syscall_clock_gettime(_clk_id: usize, tp_ptr: usize) -> isize {
    if tp_ptr == 0 {
        return EFAULT;
    }
    let ns = now_ns();
    let ts = TimeSpec {
        sec: (ns / NSEC_PER_SEC) as i64,
        nsec: (ns % NSEC_PER_SEC) as i64,
    };
    let token = get_current_token();
    write_user_value(token, tp_ptr as *mut TimeSpec, &ts);
    0
}

/// Linux `clock_nanosleep` (syscall 115 on riscv64).
///
/// rt-tests (cyclictest) uses this for periodic sleeps (often with TIMER_ABSTIME).
pub fn syscall_clock_nanosleep(clk_id: usize, flags: usize, req_ptr: usize, rem_ptr: usize) -> isize {
    const TIMER_ABSTIME: usize = 1;
    if req_ptr == 0 {
        return EFAULT;
    }
    if clk_id != CLOCK_REALTIME && clk_id != CLOCK_MONOTONIC {
        return EOPNOTSUPP;
    }
    let token = get_current_token();
    let ts = read_user_value(token, req_ptr as *const TimeSpec);
    let Some(req_ns) = timespec_to_ns(ts) else {
        return EINVAL;
    };
    let start_ns = now_ns();
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
        let current_ns = now_ns();
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
                    now_ns().saturating_sub(start_ns)
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
                    now_ns().saturating_sub(start_ns)
                );
            }
            if rem_ptr != 0 {
                let remaining = target_ns.saturating_sub(now_ns());
                let rem = ns_to_timespec(remaining);
                let token = get_current_token();
                write_user_value(token, rem_ptr as *mut TimeSpec, &rem);
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

fn timeval_to_ms(tv: TimeVal64) -> Option<usize> {
    if tv.sec < 0 || tv.usec < 0 || tv.usec >= 1_000_000 {
        return None;
    }
    let ms = (tv.sec as u64)
        .saturating_mul(1_000)
        .saturating_add((tv.usec as u64) / 1_000);
    Some(ms as usize)
}

fn write_itimerval(ptr: usize, remaining_ms: usize) {
    if ptr == 0 {
        return;
    }
    let token = get_current_token();
    let sec = (remaining_ms / 1000) as i64;
    let usec = ((remaining_ms % 1000) * 1000) as i64;
    let val = ITimerVal {
        it_interval: TimeVal64 { sec: 0, usec: 0 },
        it_value: TimeVal64 { sec, usec },
    };
    write_user_value(token, ptr as *mut ITimerVal, &val);
}

pub fn syscall_getitimer(which: usize, curr_ptr: usize) -> isize {
    const ITIMER_REAL: usize = 0;
    const EINVAL: isize = -22;
    const EFAULT: isize = -14;
    if which != ITIMER_REAL {
        return EINVAL;
    }
    if curr_ptr == 0 {
        return EFAULT;
    }
    let pid = crate::task::processor::current_process().getpid();
    let remaining_ms = alarm_remaining_ms(pid);
    write_itimerval(curr_ptr, remaining_ms);
    0
}

pub fn syscall_setitimer(which: usize, new_ptr: usize, old_ptr: usize) -> isize {
    const ITIMER_REAL: usize = 0;
    const EINVAL: isize = -22;
    const EFAULT: isize = -14;
    if which != ITIMER_REAL {
        return EINVAL;
    }
    if new_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let new_val = read_user_value(token, new_ptr as *const ITimerVal);
    let Some(delay_ms) = timeval_to_ms(new_val.it_value) else {
        return EINVAL;
    };
    let pid = crate::task::processor::current_process().getpid();
    let prev_ms = set_alarm_timer(pid, if delay_ms == 0 { None } else { Some(delay_ms) });
    crate::log_if!(
        DEBUG_UNIXBENCH,
        info,
        "[alarm] set pid={} delay_ms={} prev_ms={}",
        pid,
        delay_ms,
        prev_ms
    );
    if old_ptr != 0 {
        write_itimerval(old_ptr, prev_ms);
    }
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

    let nfds = _nfds;
    let readfds = _readfds;
    let writefds = _writefds;
    let exceptfds = _exceptfds;

    // Sleep primitive: `pselect6(0, NULL, NULL, NULL, &ts, NULL)`.
    if (nfds == 0 || (readfds == 0 && writefds == 0 && exceptfds == 0)) && timeout_ptr != 0 {
        let _ = syscall_nanosleep(timeout_ptr, 0);
        return 0;
    }

    if nfds == 0 {
        crate::task::processor::suspend_current_and_run_next();
        return 0;
    }

    let token = crate::trap::get_current_token();
    let process = crate::task::processor::current_process();

    // Use a byte-sized bitmap (nfds bits).
    let bytes_len_full = (nfds + 7) / 8;
    let bytes_len = bytes_len_full.min(MAX_FDSET_BYTES);
    let max_fds = bytes_len * 8;
    let mut in_r = alloc::vec![0u8; bytes_len];
    let mut in_w = alloc::vec![0u8; bytes_len];
    let mut out_r = alloc::vec![0u8; bytes_len];
    let mut out_w = alloc::vec![0u8; bytes_len];

    if readfds != 0 {
        crate::mm::copy_from_user(token, readfds as *const u8, in_r.as_mut_slice());
    }
    if writefds != 0 {
        crate::mm::copy_from_user(token, writefds as *const u8, in_w.as_mut_slice());
    }

    // If a timeout is provided, we must return early when fds become ready.
    // Avoid relying on `nanosleep()` here (which can oversleep) and instead
    // cooperatively yield until either an fd becomes ready or the deadline hits.
    let deadline_ms = if timeout_ptr == 0 {
        None
    } else {
        let ts = read_user_value(token, timeout_ptr as *const TimeSpec);
        let ms = (ts.sec.max(0) as usize)
            .saturating_mul(1000)
            .saturating_add((ts.nsec.max(0) as usize) / 1_000_000);
        Some(crate::time::get_time_ms().saturating_add(ms))
    };
    loop {
        let mut ready = 0isize;
        out_r.fill(0);
        out_w.fill(0);

        let limit = core::cmp::min(nfds, max_fds);
        for fd in 0..limit {
            let byte = fd / 8;
            let bit = fd % 8;
            let mask = 1u8 << bit;
            let want_r = readfds != 0 && (in_r[byte] & mask) != 0;
            let want_w = writefds != 0 && (in_w[byte] & mask) != 0;
            if !want_r && !want_w {
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
                return EBADF;
            };

            let mut r_ok = false;
            let mut w_ok = false;
            if let Some(pipe) = file.as_any().downcast_ref::<crate::fs::Pipe>() {
                r_ok = pipe.poll_readable();
                w_ok = pipe.poll_writable();
            } else if let Some(sp) = file.as_any().downcast_ref::<crate::fs::SocketPairEnd>() {
                r_ok = sp.poll_readable();
                w_ok = sp.poll_writable();
            } else if let Some(ns) = file.as_any().downcast_ref::<crate::fs::NetSocketFile>() {
                r_ok = ns.poll_readable();
                w_ok = ns.poll_writable();
            } else {
                r_ok = file.readable();
                w_ok = file.writable();
            }

            if want_r && r_ok {
                out_r[byte] |= mask;
                ready += 1;
            }
            if want_w && w_ok {
                out_w[byte] |= mask;
                ready += 1;
            }
        }

        // Always clear exceptfds (we don't model exceptions).
        if exceptfds != 0 {
            let zeros = alloc::vec![0u8; bytes_len];
            crate::mm::copy_to_user(token, exceptfds as *mut u8, zeros.as_slice());
        }

        if ready != 0 {
            if readfds != 0 {
                crate::mm::copy_to_user(token, readfds as *mut u8, out_r.as_slice());
            }
            if writefds != 0 {
                crate::mm::copy_to_user(token, writefds as *mut u8, out_w.as_slice());
            }
            return ready;
        }

        if let Some(deadline) = deadline_ms {
            if crate::time::get_time_ms() >= deadline {
            if readfds != 0 {
                crate::mm::copy_to_user(token, readfds as *mut u8, out_r.as_slice());
            }
            if writefds != 0 {
                crate::mm::copy_to_user(token, writefds as *mut u8, out_w.as_slice());
            }
            return 0;
            }
        }

        crate::task::processor::suspend_current_and_run_next();
    }
}
