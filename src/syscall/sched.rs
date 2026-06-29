use crate::syscall::error::{SyscallError, err};
use alloc::sync::Arc;

use crate::{
    debug_config::DEBUG_CYCLICTEST,
    mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value},
    syscall::misc::decode_linux_tid,
    syscall::{CyclicDiagEvent, cyclic_diag_note},
    task::{
        ProcessControlBlock,
        manager::{online_hart_mask, pid2process, refresh_task_runqueue},
        processor::{
            current_process, current_task, hart_id, request_reschedule_current_hart,
            request_reschedule_harts, suspend_current_and_run_next,
        },
        sched::{
            SCHED_BATCH, SCHED_DEADLINE, SCHED_FLAG_RESET_ON_FORK, SCHED_IDLE, SCHED_OTHER,
            SCHED_RESET_ON_FORK, SchedClass, check_policy, clamp_nice, policy_priority_max,
            policy_priority_min, rr_timeslice_ms, sched_class, valid_priority_for_policy,
        },
        task_block::TaskControlBlock,
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
    online_hart_mask()
}

fn task_is_current(task: &Arc<TaskControlBlock>) -> bool {
    current_task()
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, task))
}

fn request_reschedule_for_running_task(task: &Arc<TaskControlBlock>) {
    let running_hart = task.on_cpu.load(core::sync::atomic::Ordering::Acquire);
    if running_hart == TaskControlBlock::OFF_CPU {
        return;
    }
    if task_is_current(task) {
        request_reschedule_current_hart();
    } else if running_hart < usize::BITS as usize {
        request_reschedule_harts(1usize << running_hart);
    }
}

/// RT 任务切回 Fair 时，切断 RT 运行时间对 Fair vruntime 的追算。
///
/// `cpu_time_ns` 是跨调度类累计的总 CPU 时间，而
/// `fair_runtime_checkpoint_ns` 只应用来记录 Fair 类已经结算到的位置。
/// 如果线程在 SCHED_FIFO/RR 中运行后切回 Fair，不能把 RT 期间消耗的时间
/// 继续折算成 EEVDF vruntime。
fn reset_fair_runtime_after_rt(task: &Arc<TaskControlBlock>, old_policy: i32, new_policy: i32) {
    let old_class = sched_class(old_policy);
    let new_class = sched_class(new_policy);
    if !matches!(old_class, Some(SchedClass::Fifo) | Some(SchedClass::Rr))
        || !matches!(new_class, Some(SchedClass::Fair))
    {
        return;
    }

    let mut inner = task.borrow_mut();
    inner.fair_runtime_checkpoint_ns = inner.cpu_time_ns;
    inner.fair_vlag_ns = 0;
}

fn task_from_process(
    process: &Arc<ProcessControlBlock>,
    tid: usize,
) -> Option<Arc<TaskControlBlock>> {
    let inner = process.borrow_mut();
    inner.tasks.get(tid).and_then(|task| task.as_ref()).cloned()
}

fn resolve_task(pid: usize) -> Option<(Arc<ProcessControlBlock>, Arc<TaskControlBlock>)> {
    let cur = current_process();
    if pid == 0 {
        return current_task().map(|task| (cur, task));
    }
    let cur_pid = cur.getpid();
    if let Some(tid) = decode_linux_tid(cur_pid, pid) {
        return task_from_process(&cur, tid).map(|task| (cur, task));
    }
    {
        let inner = cur.borrow_mut();
        if pid < inner.tasks.len() {
            if let Some(task) = inner.tasks[pid].as_ref().cloned() {
                drop(inner);
                return Some((cur, task));
            }
        }
    }
    let process = pid2process(pid)?;
    let task = task_from_process(&process, 0)?;
    Some((process, task))
}

pub fn syscall_sched_getscheduler(pid: usize) -> isize {
    if DEBUG_CYCLICTEST {
        log::warn!("[sched_getscheduler] pid={}", pid);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some((_process, task)) = resolve_task(pid) else {
        return err(SyscallError::ESRCH);
    };
    let (policy, reset_on_fork) = {
        let inner = task.borrow_mut();
        (
            inner.scheduling.sched_policy,
            inner.scheduling.reset_on_fork,
        )
    };
    if check_policy(policy) {
        let reset_flag = if reset_on_fork {
            SCHED_RESET_ON_FORK
        } else {
            0
        };
        (policy | reset_flag) as isize
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
            log::warn!(
                "[sched_getparam] err(SyscallError::EINVAL) pid={} param_ptr=0",
                pid
            );
        }
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some((_process, task)) = resolve_task(pid) else {
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
        let inner = task.borrow_mut();
        inner.scheduling.sched_priority
    };
    let token = get_current_token();
    let sp = SchedParam {
        sched_priority: prio,
    };
    // SAFETY: sp is a stack-local struct with known layout; length equals size_of::<SchedParam>().
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
    let Some((process, task)) = resolve_task(pid) else {
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
    let policy = task.borrow_mut().scheduling.sched_policy;
    if !check_policy(policy) || !valid_priority_for_policy(policy, prio) {
        return err(SyscallError::EINVAL);
    }
    task.borrow_mut().scheduling.sched_priority = prio;
    refresh_task_runqueue(&task);
    request_reschedule_for_running_task(&task);
    0
}

pub fn syscall_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> isize {
    if param_ptr == 0 {
        return err(SyscallError::EINVAL);
    }
    if invalid_pid(pid) {
        return err(SyscallError::EINVAL);
    }
    let Some((process, task)) = resolve_task(pid) else {
        return err(SyscallError::ESRCH);
    };
    let reset_on_fork = (policy & SCHED_RESET_ON_FORK as usize) != 0;
    let policy_bits = policy & !(SCHED_RESET_ON_FORK as usize);
    if policy_bits > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    let policy = policy_bits as i32;
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
    if DEBUG_CYCLICTEST {
        let caller_tid = current_task()
            .and_then(|task| task.borrow_mut().res.as_ref().map(|r| r.tid))
            .unwrap_or(usize::MAX);
        let target_tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        log::warn!(
            "[sched_setscheduler] pid_arg={} caller_tid={} target_tid={} policy={} prio={}",
            pid,
            caller_tid,
            target_tid,
            policy,
            prio
        );
        cyclic_diag_note(CyclicDiagEvent::SetScheduler, process.getpid(), target_tid);
    }
    let old_policy = {
        let mut inner = task.borrow_mut();
        let old_policy = inner.scheduling.sched_policy;
        inner.scheduling.sched_policy = policy;
        inner.scheduling.sched_priority = prio;
        inner.scheduling.reset_on_fork = reset_on_fork;
        if policy != SCHED_DEADLINE {
            inner.scheduling.sched_runtime = 0;
            inner.scheduling.sched_deadline = 0;
            inner.scheduling.sched_period = 0;
        }
        old_policy
    };
    reset_fair_runtime_after_rt(&task, old_policy, policy);
    refresh_task_runqueue(&task);
    request_reschedule_for_running_task(&task);
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
    let Some((_process, task)) = resolve_task(pid) else {
        return err(SyscallError::ESRCH);
    };
    let affinity_mask = {
        let inner = task.borrow_mut();
        let mask = inner.scheduling.cpu_affinity_mask;
        if mask == 0 {
            full_affinity_mask()
        } else {
            mask
        }
    };
    let mut tmp = alloc::vec![0u8; cpusetsize];
    let max_bits = cpusetsize * 8;
    let online_mask = full_affinity_mask();
    let effective_mask = affinity_mask & online_mask;
    for cpu in 0..usize::BITS as usize {
        if cpu >= max_bits {
            break;
        }
        if (effective_mask & (1usize << cpu)) != 0 {
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
    let Some((process, task)) = resolve_task(pid) else {
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
    for cpu in 0..usize::BITS as usize {
        if cpu >= max_bits {
            break;
        }
        if (mask[cpu / 8] & (1u8 << (cpu % 8))) != 0 {
            requested_mask |= 1usize << cpu;
        }
    }
    requested_mask &= full_affinity_mask();
    if requested_mask == 0 {
        return err(SyscallError::EINVAL);
    }

    let current_hart = hart_id() % usize::BITS as usize;
    let preferred_cpu = if (requested_mask & (1usize << current_hart)) != 0 {
        current_hart
    } else {
        requested_mask.trailing_zeros() as usize
    };

    {
        let mut inner = task.borrow_mut();
        inner.scheduling.cpu_affinity_mask = requested_mask;
    }
    task.set_cpu_id(preferred_cpu);
    refresh_task_runqueue(&task);
    if DEBUG_CYCLICTEST {
        let target_tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        cyclic_diag_note(CyclicDiagEvent::SetAffinity, process.getpid(), target_tid);
    }

    if current_task()
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, &task))
        && (requested_mask & (1usize << current_hart)) == 0
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
    let Some((_process, task)) = resolve_task(pid) else {
        return err(SyscallError::ESRCH);
    };
    let policy = task.borrow_mut().scheduling.sched_policy;
    let interval_ms = match sched_class(policy) {
        Some(SchedClass::Rr) => rr_timeslice_ms(),
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
    let Some((_process, task)) = resolve_task(pid) else {
        return err(SyscallError::ESRCH);
    };
    let (policy, prio, flags, nice, runtime, deadline, period) = {
        let inner = task.borrow_mut();
        (
            inner.scheduling.sched_policy as u32,
            inner.scheduling.sched_priority as u32,
            if inner.scheduling.reset_on_fork {
                SCHED_FLAG_RESET_ON_FORK
            } else {
                0
            },
            inner.nice,
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
    attr.sched_flags = flags;
    attr.sched_priority = prio;
    attr.sched_nice = nice;
    attr.sched_runtime = runtime;
    attr.sched_deadline = deadline;
    attr.sched_period = period;
    // SAFETY: attr is a stack-local struct with known layout; copy_len bounded by size_of::<SchedAttr>().
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
    let Some((process, task)) = resolve_task(pid) else {
        return err(SyscallError::ESRCH);
    };
    if !can_control_target(&process) {
        return err(SyscallError::EPERM);
    }
    let token = get_current_token();
    let Some(user_size) = try_read_user_value(token, attr_ptr as *const u32) else {
        return err(SyscallError::EFAULT);
    };
    if user_size < SCHED_ATTR_SIZE_V0 as u32 {
        return err(SyscallError::EINVAL);
    }

    let mut attr = SchedAttr::default();
    let struct_size = core::mem::size_of::<SchedAttr>();
    let copy_len = core::cmp::min(user_size as usize, struct_size);
    // SAFETY: attr is a stack-local struct with known layout; copy_len is bounded by size_of::<SchedAttr>().
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(&mut attr as *mut SchedAttr as *mut u8, copy_len)
    };
    if try_copy_from_user(token, attr_ptr as *const u8, dst_bytes).is_err() {
        return err(SyscallError::EFAULT);
    }
    if attr.size < SCHED_ATTR_SIZE_V0 as u32 {
        return err(SyscallError::EINVAL);
    }
    if (attr.sched_flags & !SCHED_FLAG_RESET_ON_FORK) != 0 {
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
    let old_policy = {
        let mut inner = task.borrow_mut();
        let old_policy = inner.scheduling.sched_policy;
        inner.scheduling.sched_policy = policy;
        inner.scheduling.sched_priority = prio;
        inner.scheduling.nice = nice;
        inner.nice = nice;
        inner.scheduling.reset_on_fork = (attr.sched_flags & SCHED_FLAG_RESET_ON_FORK) != 0;
        if policy == SCHED_DEADLINE {
            inner.scheduling.sched_runtime = attr.sched_runtime;
            inner.scheduling.sched_deadline = attr.sched_deadline;
            inner.scheduling.sched_period = attr.sched_period;
        } else {
            inner.scheduling.sched_runtime = 0;
            inner.scheduling.sched_deadline = 0;
            inner.scheduling.sched_period = 0;
        }
        old_policy
    };
    reset_fair_runtime_after_rt(&task, old_policy, policy);
    refresh_task_runqueue(&task);
    request_reschedule_for_running_task(&task);
    0
}
