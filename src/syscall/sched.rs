use alloc::sync::Arc;
use crate::syscall::error::{SyscallError, err};

use crate::{
    config::MAX_HARTS,
    debug_config::DEBUG_CYCLICTEST,
    mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value},
    syscall::misc::decode_linux_tid,
    task::{
        ProcessControlBlock,
        manager::{pid2process, refresh_process_runqueues},
        processor::{current_process, hart_id, suspend_current_and_run_next},
        sched::{
            RR_TIMESLICE_MS, SCHED_BATCH, SCHED_DEADLINE, SCHED_IDLE, SCHED_OTHER, SchedClass,
            check_policy, clamp_nice, policy_priority_max, policy_priority_min, sched_class,
            valid_priority_for_policy,
        },
    },
    trap::get_current_token,
};


#[repr(C)]
#[derive(Clone, Copy)]
struct SchedParam {
    sched_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    tv_sec: isize,
    tv_nsec: isize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
    sched_util_min: u32,
    sched_util_max: u32,
}

const SCHED_ATTR_SIZE_V0: usize = 48;

fn invalid_pid(pid: usize) -> bool {
    (pid as isize) < 0
}

fn allowed_unpriv_policy(policy: i32) -> bool {
    matches!(policy, SCHED_OTHER | SCHED_BATCH | SCHED_IDLE)
}

fn can_control_target(target: &Arc<ProcessControlBlock>) -> bool {
    let caller = current_process();
    let caller_euid = {
        let inner = caller.borrow_mut();
        inner.euid
    };
    if caller_euid == 0 {
        return true;
    }
    if Arc::ptr_eq(target, &caller) {
        return true;
    }
    let (target_uid, target_euid) = {
        let inner = target.borrow_mut();
        (inner.uid, inner.euid)
    };
    caller_euid == target_uid || caller_euid == target_euid
}

fn full_affinity_mask() -> usize {
    if MAX_HARTS >= usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << MAX_HARTS) - 1
    }
}

fn resolve_process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let cur = current_process();
    if pid == 0 {
        Some(cur)
    } else {
        // glibc often passes a thread ID (TID) to sched_* syscalls.
        // Accept both:
        // - plain TGIDs (process PIDs), and
        // - encoded TIDs produced by our `gettid()` compatibility layer.
        let cur_pid = cur.getpid();
        if pid == cur_pid {
            Some(cur)
        } else {
            if decode_linux_tid(cur_pid, pid).is_some() {
                return Some(cur);
            }
            // Accept raw TIDs from the current process (pthread APIs may pass plain tid indexes).
            let has_task = {
                let inner = cur.borrow_mut();
                pid < inner.tasks.len() && inner.tasks[pid].is_some()
            };
            if has_task {
                return Some(cur);
            }
            if let Some(proc) = pid2process(pid) {
                return Some(proc);
            }
            None
        }
    }
}

pub fn syscall_sched_getscheduler(pid: usize) -> isize {
    if DEBUG_CYCLICTEST {
        log::warn!("[sched_getscheduler] pid={}", pid);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = resolve_process(pid) else {
        return err(SyscallError::ESRCH);
    };
    let policy = process.borrow_mut().scheduling.sched_policy;
    if check_policy(policy) {
        policy as isize
    } else {
        0
    }
}

pub fn syscall_sched_getparam(pid: usize, param_ptr: usize) -> isize {
    if DEBUG_CYCLICTEST {
        log::warn!("[sched_getparam] pid={} param_ptr={:#x}", pid, param_ptr);
    }
    if param_ptr == 0 {
        if DEBUG_CYCLICTEST {
            log::warn!("[sched_getparam] err(SyscallError::EINVAL) pid={} param_ptr=0", pid);
        }
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = resolve_process(pid) else {
        if DEBUG_CYCLICTEST {
            log::warn!(
                "[sched_getparam] err(SyscallError::ESRCH) pid={} param_ptr={:#x}",
                pid,
                param_ptr
            );
        }
        return err(SyscallError::ESRCH);
    };
    let prio = {
        let inner = process.borrow_mut();
        inner.scheduling.sched_priority
    };
    let token = get_current_token();
    let sp = SchedParam {
        sched_priority: prio,
    };
    if try_copy_to_user(token, param_ptr as *mut u8, unsafe {
        core::slice::from_raw_parts(
            &sp as *const SchedParam as *const u8,
            core::mem::size_of::<SchedParam>(),
        )
    })
    .is_err()
    {
        if DEBUG_CYCLICTEST {
            log::warn!(
                "[sched_getparam] err(SyscallError::EFAULT) pid={} param_ptr={:#x}",
                pid,
                param_ptr
            );
        }
        return err(SyscallError::EFAULT);
    }
    if DEBUG_CYCLICTEST {
        log::warn!("[sched_getparam] ok pid={} prio={}", pid, prio);
    }
    0
}

pub fn syscall_sched_setparam(pid: usize, param_ptr: usize) -> isize {
    if param_ptr == 0 {
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = resolve_process(pid) else {
        return err(SyscallError::ESRCH);
    };
    let token = get_current_token();
    let Some(param) = try_read_user_value(token, param_ptr as *const SchedParam) else {
        return err(SyscallError::EFAULT);
    };
    if !can_control_target(&process) {
        return err(SyscallError::EPERM);
    }
    let prio = param.sched_priority;
    let policy = process.borrow_mut().scheduling.sched_policy;
    if !check_policy(policy) || !valid_priority_for_policy(policy, prio) {
        return err(SyscallError::EINVAL);
    }
    process.borrow_mut().scheduling.sched_priority = prio;
    refresh_process_runqueues(&process);
    0
}

pub fn syscall_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> isize {
    if param_ptr == 0 {
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = resolve_process(pid) else {
        return err(SyscallError::ESRCH);
    };
    let policy = policy as i32;
    if !check_policy(policy) {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let Some(param) = try_read_user_value(token, param_ptr as *const SchedParam) else {
        return err(SyscallError::EFAULT);
    };
    if !can_control_target(&process) {
        return err(SyscallError::EPERM);
    }
    if !allowed_unpriv_policy(policy) && current_process().borrow_mut().euid != 0 {
        return err(SyscallError::EPERM);
    }
    let prio = param.sched_priority;
    if !valid_priority_for_policy(policy, prio) {
        return err(SyscallError::EINVAL);
    }
    let mut inner = process.borrow_mut();
    inner.scheduling.sched_policy = policy;
    inner.scheduling.sched_priority = prio;
    if policy != SCHED_DEADLINE {
        inner.scheduling.sched_runtime = 0;
        inner.scheduling.sched_deadline = 0;
        inner.scheduling.sched_period = 0;
    }
    drop(inner);
    refresh_process_runqueues(&process);
    0
}

pub fn syscall_sched_getaffinity(pid: usize, cpusetsize: usize, mask_ptr: usize) -> isize {
    if mask_ptr == 0 || cpusetsize == 0 {
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    // Avoid large kernel allocations from bogus cpusetsize values.
    const MAX_CPUSET_BYTES: usize = 128;
    let cpusetsize = core::cmp::min(cpusetsize, MAX_CPUSET_BYTES);
    let Some(process) = resolve_process(pid) else {
        return err(SyscallError::ESRCH);
    };
    let affinity_mask = {
        let inner = process.borrow_mut();
        let mask = inner.scheduling.cpu_affinity_mask;
        if mask == 0 {
            full_affinity_mask()
        } else {
            mask
        }
    };
    let mut tmp = alloc::vec![0u8; cpusetsize];
    let max_bits = cpusetsize * 8;
    for cpu in 0..MAX_HARTS {
        if cpu >= max_bits {
            break;
        }
        if (affinity_mask & (1usize << cpu)) != 0 {
            tmp[cpu / 8] |= 1u8 << (cpu % 8);
        }
    }
    let token = get_current_token();
    if try_copy_to_user(token, mask_ptr as *mut u8, tmp.as_slice()).is_err() {
        return err(SyscallError::EFAULT);
    }
    // Linux `sched_getaffinity` syscall returns the number of bytes written.
    // musl uses this return value (not the wrapper) when implementing `sysconf(_SC_NPROCESSORS_*)`.
    cpusetsize as isize
}

pub fn syscall_sched_setaffinity(pid: usize, cpusetsize: usize, mask_ptr: usize) -> isize {
    if mask_ptr == 0 || cpusetsize == 0 {
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    // Avoid large allocations from bogus cpusetsize values.
    const MAX_CPUSET_BYTES: usize = 128;
    let cpusetsize = core::cmp::min(cpusetsize, MAX_CPUSET_BYTES);
    let Some(process) = resolve_process(pid) else {
        if DEBUG_CYCLICTEST {
            log::warn!(
                "[sched_setaffinity] err(SyscallError::ESRCH) pid={} cpusetsize={} mask_ptr={:#x}",
                pid,
                cpusetsize,
                mask_ptr
            );
        }
        return err(SyscallError::ESRCH);
    };
    if !can_control_target(&process) {
        return err(SyscallError::EPERM);
    }
    let token = get_current_token();
    let mut mask = alloc::vec![0u8; cpusetsize];
    if try_copy_from_user(token, mask_ptr as *const u8, mask.as_mut_slice()).is_err() {
        return err(SyscallError::EFAULT);
    }
    let max_bits = cpusetsize * 8;
    let mut requested_mask = 0usize;
    for cpu in 0..MAX_HARTS {
        if cpu >= max_bits {
            break;
        }
        if (mask[cpu / 8] & (1u8 << (cpu % 8))) != 0 {
            requested_mask |= 1usize << cpu;
        }
    }
    if requested_mask == 0 {
        return err(SyscallError::EINVAL);
    }

    let current_hart = hart_id() % MAX_HARTS;
    let preferred_cpu = if (requested_mask & (1usize << current_hart)) != 0 {
        current_hart
    } else {
        requested_mask.trailing_zeros() as usize
    };

    let tasks = {
        let mut inner = process.borrow_mut();
        inner.scheduling.cpu_affinity_mask = requested_mask;
        inner
            .tasks
            .iter()
            .filter_map(|task| task.as_ref().cloned())
            .collect::<alloc::vec::Vec<_>>()
    };
    for task in tasks {
        task.set_cpu_id(preferred_cpu);
    }
    refresh_process_runqueues(&process);

    if Arc::ptr_eq(&current_process(), &process) && (requested_mask & (1usize << current_hart)) == 0
    {
        suspend_current_and_run_next();
    }
    0
}

pub fn syscall_sched_get_priority_max(policy: usize) -> isize {
    policy_priority_max(policy as i32).map_or(err(SyscallError::EINVAL), |v| v as isize)
}

pub fn syscall_sched_get_priority_min(policy: usize) -> isize {
    policy_priority_min(policy as i32).map_or(err(SyscallError::EINVAL), |v| v as isize)
}

pub fn syscall_sched_rr_get_interval(pid: usize, interval_ptr: usize) -> isize {
    if interval_ptr == 0 {
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = resolve_process(pid) else {
        return err(SyscallError::ESRCH);
    };
    let policy = process.borrow_mut().scheduling.sched_policy;
    let interval_ms = match sched_class(policy) {
        Some(SchedClass::Rr) => RR_TIMESLICE_MS,
        _ => 0,
    };
    let token = get_current_token();
    let ts = TimeSpec {
        tv_sec: interval_ms / 1000,
        tv_nsec: (interval_ms % 1000) * 1_000_000,
    };
    if try_write_user_value(token, interval_ptr as *mut TimeSpec, &ts).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_sched_getattr(pid: usize, attr_ptr: usize, size: usize, flags: usize) -> isize {
    if attr_ptr == 0 || size < SCHED_ATTR_SIZE_V0 || flags != 0 {
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = resolve_process(pid) else {
        return err(SyscallError::ESRCH);
    };
    let (policy, prio, nice, runtime, deadline, period) = {
        let inner = process.borrow_mut();
        (
            inner.scheduling.sched_policy as u32,
            inner.scheduling.sched_priority as u32,
            inner.scheduling.nice,
            inner.scheduling.sched_runtime,
            inner.scheduling.sched_deadline,
            inner.scheduling.sched_period,
        )
    };
    let mut attr = SchedAttr::default();
    let struct_size = core::mem::size_of::<SchedAttr>();
    let copy_len = core::cmp::min(size, struct_size);
    attr.size = copy_len as u32;
    attr.sched_policy = policy;
    attr.sched_priority = prio;
    attr.sched_nice = nice;
    attr.sched_runtime = runtime;
    attr.sched_deadline = deadline;
    attr.sched_period = period;
    let bytes =
        unsafe { core::slice::from_raw_parts(&attr as *const SchedAttr as *const u8, copy_len) };
    let token = get_current_token();
    if try_copy_to_user(token, attr_ptr as *mut u8, bytes).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub fn syscall_sched_setattr(pid: usize, attr_ptr: usize, flags: usize, _unused: usize) -> isize {
    if attr_ptr == 0 {
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    if flags != 0 {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = resolve_process(pid) else {
        return err(SyscallError::ESRCH);
    };
    if !can_control_target(&process) {
        return err(SyscallError::EPERM);
    }
    let token = get_current_token();
    let mut attr = SchedAttr::default();
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut attr as *mut SchedAttr as *mut u8,
            core::mem::size_of::<SchedAttr>(),
        )
    };
    if try_copy_from_user(token, attr_ptr as *const u8, dst_bytes).is_err() {
        return err(SyscallError::EFAULT);
    }
    if attr.size < SCHED_ATTR_SIZE_V0 as u32 {
        return err(SyscallError::EINVAL);
    }
    let policy = attr.sched_policy as i32;
    if !check_policy(policy) {
        return err(SyscallError::EINVAL);
    }
    if !allowed_unpriv_policy(policy) && current_process().borrow_mut().euid != 0 {
        return err(SyscallError::EPERM);
    }
    let prio = attr.sched_priority as i32;
    if !valid_priority_for_policy(policy, prio) {
        return err(SyscallError::EINVAL);
    }
    let nice = clamp_nice(attr.sched_nice);
    if policy == SCHED_DEADLINE
        && (attr.sched_runtime == 0
            || attr.sched_deadline == 0
            || attr.sched_period == 0
            || attr.sched_runtime > attr.sched_deadline
            || attr.sched_deadline > attr.sched_period)
    {
        return err(SyscallError::EINVAL);
    }
    let mut inner = process.borrow_mut();
    inner.scheduling.sched_policy = policy;
    inner.scheduling.sched_priority = prio;
    inner.scheduling.nice = nice;
    if policy == SCHED_DEADLINE {
        inner.scheduling.sched_runtime = attr.sched_runtime;
        inner.scheduling.sched_deadline = attr.sched_deadline;
        inner.scheduling.sched_period = attr.sched_period;
    } else {
        inner.scheduling.sched_runtime = 0;
        inner.scheduling.sched_deadline = 0;
        inner.scheduling.sched_period = 0;
    }
    drop(inner);
    refresh_process_runqueues(&process);
    0
}
