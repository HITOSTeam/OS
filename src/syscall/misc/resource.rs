use crate::{
    mm::{try_read_user_value, try_write_user_value},
    syscall::error::{SyscallError, err},
    task::{
        manager::{PID2PCB, pid2process},
        processor::{current_process, current_task},
        runtime::{current_task_cpu_time_ns, process_cpu_time_ns},
        signal::{SIGKILL_NUM, SIGXCPU_NUM, queue_process_signal},
    },
    time::get_time_ms,
    trap::get_current_token,
};
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::session::normalized_pgid;

// ---- I/O priority -----------------------------------------------------------

const IOPRIO_CLASS_SHIFT: usize = 13;
const IOPRIO_PRIO_MASK: usize = (1 << IOPRIO_CLASS_SHIFT) - 1;
const IOPRIO_CLASS_NONE: usize = 0;
const IOPRIO_CLASS_RT: usize = 1;
const IOPRIO_CLASS_BE: usize = 2;
const IOPRIO_CLASS_IDLE: usize = 3;
const IOPRIO_PRIO_NUM: usize = 8;
const IOPRIO_WHO_PROCESS: isize = 1;
const IOPRIO_WHO_PGRP: isize = 2;
const IOPRIO_WHO_USER: isize = 3;

fn ioprio_class(ioprio: usize) -> usize {
    ioprio >> IOPRIO_CLASS_SHIFT
}

fn ioprio_level(ioprio: usize) -> usize {
    ioprio & IOPRIO_PRIO_MASK
}

fn valid_ioprio(ioprio: usize) -> bool {
    match ioprio_class(ioprio) {
        IOPRIO_CLASS_NONE => ioprio_level(ioprio) == 0,
        IOPRIO_CLASS_RT | IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE => {
            ioprio_level(ioprio) < IOPRIO_PRIO_NUM
        }
        _ => false,
    }
}

fn collect_ioprio_targets(
    which: isize,
    who: isize,
) -> Result<Vec<Arc<crate::task::ProcessControlBlock>>, isize> {
    match which {
        IOPRIO_WHO_PROCESS | IOPRIO_WHO_PGRP | IOPRIO_WHO_USER => {
            collect_priority_targets(which - 1, who)
        }
        _ => Err(err(SyscallError::EINVAL)),
    }
}

pub fn syscall_ioprio_set(which: isize, who: isize, ioprio: usize) -> isize {
    if !valid_ioprio(ioprio) {
        return err(SyscallError::EINVAL);
    }
    if ioprio_class(ioprio) == IOPRIO_CLASS_RT && current_process().borrow_mut().euid != 0 {
        return err(SyscallError::EPERM);
    }

    let targets = match collect_ioprio_targets(which, who) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let ioprio = ioprio as u16;
    for proc in targets {
        proc.borrow_mut().ioprio = ioprio;
    }
    0
}

pub fn syscall_ioprio_get(which: isize, who: isize) -> isize {
    let targets = match collect_ioprio_targets(which, who) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut best: Option<usize> = None;
    for proc in targets {
        let value = proc.borrow_mut().ioprio as usize;
        best = Some(match best {
            Some(cur) => cur.min(value),
            None => value,
        });
    }
    best.unwrap_or(0) as isize
}

// ---- Process priority (nice) ------------------------------------------------

const PRIO_PROCESS: isize = 0;
const PRIO_PGRP: isize = 1;
const PRIO_USER: isize = 2;

fn clamp_nice(prio: isize) -> i32 {
    prio.clamp(-20, 19) as i32
}

fn collect_priority_targets(
    which: isize,
    who: isize,
) -> Result<Vec<Arc<crate::task::ProcessControlBlock>>, isize> {
    let caller = current_process();
    let caller_pid = caller.getpid();
    let (caller_pgid, caller_uid) = {
        let inner = caller.borrow_mut();
        (normalized_pgid(caller_pid, inner.pgid), inner.uid)
    };

    if who < 0 {
        return Err(err(SyscallError::ESRCH));
    }

    match which {
        PRIO_PROCESS => {
            let target_pid = if who == 0 { caller_pid } else { who as usize };
            let Some(proc) = pid2process(target_pid) else {
                return Err(err(SyscallError::ESRCH));
            };
            let mut out = Vec::new();
            out.push(proc);
            Ok(out)
        }
        PRIO_PGRP => {
            let target_pgid = if who == 0 { caller_pgid } else { who as usize };
            let map = PID2PCB.lock();
            let mut out = Vec::new();
            for proc in map.values() {
                let pgid = {
                    let inner = proc.borrow_mut();
                    normalized_pgid(proc.getpid(), inner.pgid)
                };
                if pgid == target_pgid {
                    out.push(Arc::clone(proc));
                }
            }
            if out.is_empty() {
                return Err(err(SyscallError::ESRCH));
            }
            Ok(out)
        }
        PRIO_USER => {
            let target_uid = if who == 0 { caller_uid } else { who as u32 };
            let map = PID2PCB.lock();
            let mut out = Vec::new();
            for proc in map.values() {
                let uid = {
                    let inner = proc.borrow_mut();
                    inner.uid
                };
                if uid == target_uid {
                    out.push(Arc::clone(proc));
                }
            }
            if out.is_empty() {
                return Err(err(SyscallError::ESRCH));
            }
            Ok(out)
        }
        _ => Err(err(SyscallError::EINVAL)),
    }
}

/// Linux `setpriority(2)` (syscall 140 on riscv64).
pub fn syscall_setpriority(which: isize, who: isize, prio: isize) -> isize {
    if which == PRIO_PROCESS && who == 0 {
        let new_nice = clamp_nice(prio);
        let caller = current_process();
        let caller_euid = {
            let inner = caller.borrow_mut();
            inner.euid
        };
        let task = current_task().unwrap();
        let (cur_nice, from_nice_wrapper) = {
            let mut inner = task.borrow_mut();
            let cur_nice = inner.nice;
            let from_nice_wrapper = inner.nice_query_hint;
            inner.nice_query_hint = false;
            (cur_nice, from_nice_wrapper)
        };
        if caller_euid != 0 && new_nice < cur_nice {
            // libc `nice()` is often emulated by getpriority()+setpriority().
            // Linux reports err(SyscallError::EPERM) for nice(-N), while plain setpriority() keeps err(SyscallError::EACCES).
            return if from_nice_wrapper { err(SyscallError::EPERM) } else { err(SyscallError::EACCES) };
        }
        {
            let mut inner = task.borrow_mut();
            inner.nice = new_nice;
        }
        // Keep process-level default nice in sync for newly created threads.
        caller.borrow_mut().scheduling.nice = new_nice;
        crate::task::manager::refresh_process_runqueues(&caller);
        return 0;
    }

    if let Some(task) = current_task() {
        task.borrow_mut().nice_query_hint = false;
    }

    let targets = match collect_priority_targets(which, who) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_nice = clamp_nice(prio);
    let caller = current_process();
    let (caller_uid, caller_euid) = {
        let inner = caller.borrow_mut();
        (inner.uid, inner.euid)
    };

    if caller_euid != 0 {
        for proc in targets.iter() {
            let (uid, cur_nice) = {
                let inner = proc.borrow_mut();
                (inner.uid, inner.scheduling.nice)
            };
            if uid != caller_uid && uid != caller_euid {
                return err(SyscallError::EPERM);
            }
            if new_nice < cur_nice {
                return err(SyscallError::EACCES);
            }
        }
    }

    for proc in targets {
        let mut inner = proc.borrow_mut();
        inner.scheduling.nice = new_nice;
        drop(inner);
        crate::task::manager::refresh_process_runqueues(&proc);
    }
    0
}

/// Linux `getpriority(2)` (syscall 141 on riscv64).
///
/// Return kernel-internal encoded value (1..40); libc converts it back to
/// user-visible nice range (-20..19).
pub fn syscall_getpriority(which: isize, who: isize) -> isize {
    if which == PRIO_PROCESS && who == 0 {
        let task = current_task().unwrap();
        let nice = {
            let mut inner = task.borrow_mut();
            inner.nice_query_hint = true;
            inner.nice
        };
        return (20 - nice as isize) as isize;
    }

    let targets = match collect_priority_targets(which, who) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut best = 19i32;
    for proc in targets {
        let nice = {
            let inner = proc.borrow_mut();
            inner.scheduling.nice
        };
        if nice < best {
            best = nice;
        }
    }
    (20 - best as isize) as isize
}

// ---- Resource usage ---------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct RUsageTimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RUsage64 {
    ru_utime: RUsageTimeVal,
    ru_stime: RUsageTimeVal,
    ru_maxrss: i64,
    ru_ixrss: i64,
    ru_idrss: i64,
    ru_isrss: i64,
    ru_minflt: i64,
    ru_majflt: i64,
    ru_nswap: i64,
    ru_inblock: i64,
    ru_oublock: i64,
    ru_msgsnd: i64,
    ru_msgrcv: i64,
    ru_nsignals: i64,
    ru_nvcsw: i64,
    ru_nivcsw: i64,
}

fn ns_to_rusage_timeval(ns: u64) -> RUsageTimeVal {
    RUsageTimeVal {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_usec: ((ns % 1_000_000_000) / 1_000) as i64,
    }
}

/// Linux `getrusage(2)` (syscall 165 on riscv64).
///
/// Report best-effort CPU time based on the scheduler's per-thread runtime
/// accounting. We do not yet split user/system time, so all CPU time is
/// exposed via `ru_utime` and `ru_stime` stays zero.
pub fn syscall_getrusage(who: isize, usage: usize) -> isize {
    const RUSAGE_SELF: isize = 0;
    const RUSAGE_CHILDREN: isize = -1;
    const RUSAGE_THREAD: isize = 1;

    if usage == 0 {
        return err(SyscallError::EFAULT);
    }

    let cpu_ns = match who {
        RUSAGE_SELF => process_cpu_time_ns(&current_process()),
        RUSAGE_THREAD => current_task_cpu_time_ns(),
        RUSAGE_CHILDREN => current_process().borrow_mut().child_cpu_time_ns,
        _ => return err(SyscallError::EINVAL),
    };
    let (utime, stime) = (ns_to_rusage_timeval(cpu_ns), ns_to_rusage_timeval(0));

    let ru = RUsage64 {
        ru_utime: utime,
        ru_stime: stime,
        ru_maxrss: 0,
        ru_ixrss: 0,
        ru_idrss: 0,
        ru_isrss: 0,
        ru_minflt: 0,
        ru_majflt: 0,
        ru_nswap: 0,
        ru_inblock: 0,
        ru_oublock: 0,
        ru_msgsnd: 0,
        ru_msgrcv: 0,
        ru_nsignals: 0,
        ru_nvcsw: 0,
        ru_nivcsw: 0,
    };
    let token = get_current_token();
    if try_write_user_value(token, usage as *mut RUsage64, &ru).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

// ---- Resource limits --------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

const RLIM_INFINITY: u64 = u64::MAX;
const RLIMIT_CPU: usize = 0;
const RLIMIT_FSIZE: usize = 1;
const RLIMIT_DATA: usize = 2;
const RLIMIT_STACK: usize = 3;
const RLIMIT_CORE: usize = 4;
const RLIMIT_RSS: usize = 5;
const RLIMIT_NPROC: usize = 6;
const RLIMIT_NOFILE: usize = 7;
const RLIMIT_MEMLOCK: usize = 8;
const RLIMIT_AS: usize = 9;
const RLIMIT_LOCKS: usize = 10;
const RLIMIT_SIGPENDING: usize = 11;
const RLIMIT_MSGQUEUE: usize = 12;
const RLIMIT_NICE: usize = 13;
const RLIMIT_RTPRIO: usize = 14;
const RLIMIT_RTTIME: usize = 15;
const FS_NR_OPEN: u64 = 1024 * 1024;

fn rlimit_for_resource(
    process: &Arc<crate::task::ProcessControlBlock>,
    resource: usize,
) -> Option<(u64, u64)> {
    let inner = process.borrow_mut();
    match resource {
        RLIMIT_CPU => Some((inner.rlimits.rlimit_cpu_cur, inner.rlimits.rlimit_cpu_max)),
        RLIMIT_FSIZE => Some((inner.rlimits.rlimit_fsize_cur, inner.rlimits.rlimit_fsize_max)),
        RLIMIT_DATA => Some((inner.rlimits.rlimit_data_cur, inner.rlimits.rlimit_data_max)),
        RLIMIT_STACK => Some((inner.rlimits.rlimit_stack_cur, inner.rlimits.rlimit_stack_max)),
        RLIMIT_CORE => Some((inner.rlimits.rlimit_core_cur, inner.rlimits.rlimit_core_max)),
        RLIMIT_RSS => Some((inner.rlimits.rlimit_rss_cur, inner.rlimits.rlimit_rss_max)),
        RLIMIT_NPROC => Some((inner.rlimits.rlimit_nproc_cur, inner.rlimits.rlimit_nproc_max)),
        RLIMIT_NOFILE => Some((inner.rlimits.rlimit_nofile_cur, inner.rlimits.rlimit_nofile_max)),
        RLIMIT_MEMLOCK => Some((inner.rlimits.rlimit_memlock_cur, inner.rlimits.rlimit_memlock_max)),
        RLIMIT_AS => Some((inner.rlimits.rlimit_as_cur, inner.rlimits.rlimit_as_max)),
        RLIMIT_LOCKS => Some((inner.rlimits.rlimit_locks_cur, inner.rlimits.rlimit_locks_max)),
        RLIMIT_SIGPENDING => Some((inner.rlimits.rlimit_sigpending_cur, inner.rlimits.rlimit_sigpending_max)),
        RLIMIT_MSGQUEUE => Some((inner.rlimits.rlimit_msgqueue_cur, inner.rlimits.rlimit_msgqueue_max)),
        RLIMIT_NICE => Some((inner.rlimits.rlimit_nice_cur, inner.rlimits.rlimit_nice_max)),
        RLIMIT_RTPRIO => Some((inner.rlimits.rlimit_rtprio_cur, inner.rlimits.rlimit_rtprio_max)),
        RLIMIT_RTTIME => Some((inner.rlimits.rlimit_rttime_cur, inner.rlimits.rlimit_rttime_max)),
        _ => None,
    }
}

fn apply_rlimit_to_resource(
    process: &Arc<crate::task::ProcessControlBlock>,
    resource: usize,
    new: RLimit64,
) -> isize {
    let mut inner = process.borrow_mut();
    match resource {
        RLIMIT_CPU => {
            inner.rlimits.rlimit_cpu_cur = new.rlim_cur;
            inner.rlimits.rlimit_cpu_max = new.rlim_max;
            inner.rlimits.rlimit_cpu_start_ms = get_time_ms();
            inner.rlimits.rlimit_cpu_soft_sent = false;
        }
        RLIMIT_FSIZE => {
            inner.rlimits.rlimit_fsize_cur = new.rlim_cur;
            inner.rlimits.rlimit_fsize_max = new.rlim_max;
        }
        RLIMIT_DATA => {
            inner.rlimits.rlimit_data_cur = new.rlim_cur;
            inner.rlimits.rlimit_data_max = new.rlim_max;
        }
        RLIMIT_STACK => {
            inner.rlimits.rlimit_stack_cur = new.rlim_cur;
            inner.rlimits.rlimit_stack_max = new.rlim_max;
        }
        RLIMIT_CORE => {
            inner.rlimits.rlimit_core_cur = new.rlim_cur;
            inner.rlimits.rlimit_core_max = new.rlim_max;
        }
        RLIMIT_RSS => {
            inner.rlimits.rlimit_rss_cur = new.rlim_cur;
            inner.rlimits.rlimit_rss_max = new.rlim_max;
        }
        RLIMIT_NPROC => {
            inner.rlimits.rlimit_nproc_cur = new.rlim_cur;
            inner.rlimits.rlimit_nproc_max = new.rlim_max;
        }
        RLIMIT_NOFILE => {
            inner.rlimits.rlimit_nofile_cur = new.rlim_cur;
            inner.rlimits.rlimit_nofile_max = new.rlim_max;
        }
        RLIMIT_MEMLOCK => {
            inner.rlimits.rlimit_memlock_cur = new.rlim_cur;
            inner.rlimits.rlimit_memlock_max = new.rlim_max;
        }
        RLIMIT_AS => {
            inner.rlimits.rlimit_as_cur = new.rlim_cur;
            inner.rlimits.rlimit_as_max = new.rlim_max;
        }
        RLIMIT_LOCKS => {
            inner.rlimits.rlimit_locks_cur = new.rlim_cur;
            inner.rlimits.rlimit_locks_max = new.rlim_max;
        }
        RLIMIT_SIGPENDING => {
            inner.rlimits.rlimit_sigpending_cur = new.rlim_cur;
            inner.rlimits.rlimit_sigpending_max = new.rlim_max;
        }
        RLIMIT_MSGQUEUE => {
            inner.rlimits.rlimit_msgqueue_cur = new.rlim_cur;
            inner.rlimits.rlimit_msgqueue_max = new.rlim_max;
        }
        RLIMIT_NICE => {
            inner.rlimits.rlimit_nice_cur = new.rlim_cur;
            inner.rlimits.rlimit_nice_max = new.rlim_max;
        }
        RLIMIT_RTPRIO => {
            inner.rlimits.rlimit_rtprio_cur = new.rlim_cur;
            inner.rlimits.rlimit_rtprio_max = new.rlim_max;
        }
        RLIMIT_RTTIME => {
            inner.rlimits.rlimit_rttime_cur = new.rlim_cur;
            inner.rlimits.rlimit_rttime_max = new.rlim_max;
        }
        _ => return err(SyscallError::EINVAL),
    }
    0
}

fn set_rlimit_checked(
    process: &Arc<crate::task::ProcessControlBlock>,
    resource: usize,
    new: RLimit64,
    caller_euid: u32,
) -> isize {
    if new.rlim_cur > new.rlim_max {
        return err(SyscallError::EINVAL);
    }
    let Some((_, old_max)) = rlimit_for_resource(process, resource) else {
        return err(SyscallError::EINVAL);
    };
    if caller_euid != 0 && new.rlim_max > old_max {
        return err(SyscallError::EPERM);
    }
    if resource == RLIMIT_NOFILE && new.rlim_max > FS_NR_OPEN {
        return err(SyscallError::EPERM);
    }
    if resource == RLIMIT_NOFILE && new.rlim_cur > FS_NR_OPEN {
        return err(SyscallError::EINVAL);
    }
    apply_rlimit_to_resource(process, resource, new)
}

/// Linux `prlimit64(2)` (syscall 261 on riscv64).
///
/// Provide a permissive "unlimited" answer for common queries (e.g. RLIMIT_STACK).
pub fn syscall_prlimit64(pid: usize, resource: usize, new_limit: usize, old_limit: usize) -> isize {
    let caller = current_process();
    let caller_pid = caller.getpid();
    let caller_euid = {
        let inner = caller.borrow_mut();
        inner.euid
    };

    let target = if pid == 0 || pid == caller_pid {
        caller.clone()
    } else {
        if caller_euid != 0 {
            return err(SyscallError::EPERM);
        }
        let Some(p) = pid2process(pid) else {
            return err(SyscallError::ESRCH);
        };
        p
    };

    if new_limit != 0 {
        let token = get_current_token();
        let Some(new) = try_read_user_value(token, new_limit as *const RLimit64) else {
            return err(SyscallError::EFAULT);
        };
        let ret = set_rlimit_checked(&target, resource, new, caller_euid);
        if ret != 0 {
            return ret;
        }
    }
    if old_limit != 0 {
        let Some((rlim_cur, rlim_max)) = rlimit_for_resource(&target, resource) else {
            return err(SyscallError::EINVAL);
        };
        let token = get_current_token();
        let rl = RLimit64 { rlim_cur, rlim_max };
        if try_write_user_value(token, old_limit as *mut RLimit64, &rl).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    0
}

/// Linux `getrlimit(2)` (syscall 163 on riscv64).
pub fn syscall_getrlimit(resource: usize, rlim: usize) -> isize {
    if rlim == 0 {
        return err(SyscallError::EFAULT);
    }
    let process = current_process();
    let Some((rlim_cur, rlim_max)) = rlimit_for_resource(&process, resource) else {
        return err(SyscallError::EINVAL);
    };
    let token = get_current_token();
    let rl = RLimit64 { rlim_cur, rlim_max };
    if try_write_user_value(token, rlim as *mut RLimit64, &rl).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// Linux `setrlimit(2)` (syscall 164 on riscv64).
pub fn syscall_setrlimit(resource: usize, rlim: usize) -> isize {
    if rlim == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(new) = try_read_user_value(token, rlim as *const RLimit64) else {
        return err(SyscallError::EFAULT);
    };
    let process = current_process();
    let caller_euid = {
        let inner = process.borrow_mut();
        inner.euid
    };
    set_rlimit_checked(&process, resource, new, caller_euid)
}

/// Approximate RLIMIT_CPU accounting using timer ticks.
///
/// LTP setrlimit06 spins in userspace; checking on every timer interrupt is
/// sufficient to emulate Linux behavior (SIGXCPU then SIGKILL).
pub fn check_current_rlimit_cpu() {
    let process = current_process();
    let pid = process.getpid();
    let now_ms = get_time_ms();

    let mut send_soft = false;
    let mut send_hard = false;
    {
        let mut inner = process.borrow_mut();
        let soft = inner.rlimits.rlimit_cpu_cur;
        let hard = inner.rlimits.rlimit_cpu_max;
        if soft == RLIM_INFINITY && hard == RLIM_INFINITY {
            return;
        }
        let elapsed_sec = (now_ms.saturating_sub(inner.rlimits.rlimit_cpu_start_ms) / 1000) as u64;
        if soft != RLIM_INFINITY && elapsed_sec >= soft && !inner.rlimits.rlimit_cpu_soft_sent {
            inner.rlimits.rlimit_cpu_soft_sent = true;
            send_soft = true;
        } else if hard != RLIM_INFINITY && elapsed_sec >= hard {
            if soft != RLIM_INFINITY && !inner.rlimits.rlimit_cpu_soft_sent {
                // If we reached hard limit before ever observing soft limit, queue
                // SIGXCPU first and let the next tick deliver SIGKILL.
                inner.rlimits.rlimit_cpu_soft_sent = true;
                send_soft = true;
            } else {
                send_hard = true;
            }
        }
    }
    if send_soft {
        queue_process_signal(pid, SIGXCPU_NUM);
    }
    if send_hard {
        queue_process_signal(pid, SIGKILL_NUM);
    }
}
