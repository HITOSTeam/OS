use alloc::sync::Arc;

use crate::{
    config::MAX_HARTS,
    debug_config::DEBUG_CYCLICTEST,
    mm::{
        read_user_value, translated_byte_buffer, try_copy_from_user, try_copy_to_user,
        write_user_value, MapPermission,
    },
    syscall::misc::decode_linux_tid,
    task::{manager::pid2process, processor::current_process, ProcessControlBlock},
    trap::get_current_token,
};

const ESRCH: isize = -3;
const EINVAL: isize = -22;
const EFAULT: isize = -14;

const SCHED_OTHER: i32 = 0;
const SCHED_FIFO: i32 = 1;
const SCHED_RR: i32 = 2;

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
// Keep in sync with misc.rs Linux-like TID encoding (tgid << 15 | tid).
const LINUX_TID_PID_SHIFT: usize = 15;

fn decode_any_linux_tid(pid: usize) -> Option<(usize, usize)> {
    // Strip futex owner/waiter bits that user space may OR into the TID word.
    let tid = pid & 0x3fff_ffff;
    let tgid = tid >> LINUX_TID_PID_SHIFT;
    if tgid == 0 {
        return None;
    }
    Some((tgid, tid & 0x7fff))
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
            // Accept encoded TIDs from other processes: decode and use tgid.
            if let Some((tgid, _)) = decode_any_linux_tid(pid) {
                return pid2process(tgid);
            }
            None
        }
    }
}

fn check_policy(policy: i32) -> bool {
    matches!(policy, SCHED_OTHER | SCHED_FIFO | SCHED_RR)
}

pub fn syscall_sched_getscheduler(pid: usize) -> isize {
    if DEBUG_CYCLICTEST {
        log::warn!("[sched_getscheduler] pid={}", pid);
    }
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let inner = process.borrow_mut();
    inner.sched_policy as isize
}

pub fn syscall_sched_getparam(pid: usize, param_ptr: usize) -> isize {
    if DEBUG_CYCLICTEST {
        log::warn!(
            "[sched_getparam] pid={} param_ptr={:#x}",
            pid,
            param_ptr
        );
    }
    if param_ptr == 0 {
        if DEBUG_CYCLICTEST {
            log::warn!("[sched_getparam] EINVAL pid={} param_ptr=0", pid);
        }
        return EINVAL;
    }
    let Some(process) = resolve_process(pid) else {
        if DEBUG_CYCLICTEST {
            log::warn!("[sched_getparam] ESRCH pid={} param_ptr={:#x}", pid, param_ptr);
        }
        return ESRCH;
    };
    let prio = {
        let inner = process.borrow_mut();
        inner.sched_priority
    };
    let token = get_current_token();
    let sp = SchedParam { sched_priority: prio };
    if try_copy_to_user(
        token,
        param_ptr as *mut u8,
        unsafe {
            core::slice::from_raw_parts(
                &sp as *const SchedParam as *const u8,
                core::mem::size_of::<SchedParam>(),
            )
        },
    )
    .is_err()
    {
        if DEBUG_CYCLICTEST {
            log::warn!(
                "[sched_getparam] EFAULT pid={} param_ptr={:#x}",
                pid,
                param_ptr
            );
        }
        return EFAULT;
    }
    if DEBUG_CYCLICTEST {
        log::warn!("[sched_getparam] ok pid={} prio={}", pid, prio);
    }
    0
}

pub fn syscall_sched_setparam(pid: usize, param_ptr: usize) -> isize {
    if param_ptr == 0 {
        return EINVAL;
    }
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let token = get_current_token();
    let prio = read_user_value(token, param_ptr as *const SchedParam).sched_priority;
    let mut inner = process.borrow_mut();
    inner.sched_priority = prio;
    0
}

pub fn syscall_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> isize {
    if param_ptr == 0 {
        return EINVAL;
    }
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let policy = policy as i32;
    if !check_policy(policy) {
        return EINVAL;
    }
    let token = get_current_token();
    let prio = read_user_value(token, param_ptr as *const SchedParam).sched_priority;
    let mut inner = process.borrow_mut();
    inner.sched_policy = policy;
    inner.sched_priority = prio;
    0
}

pub fn syscall_sched_getaffinity(pid: usize, cpusetsize: usize, mask_ptr: usize) -> isize {
    if mask_ptr == 0 || cpusetsize == 0 {
        return EINVAL;
    }
    // Avoid large kernel allocations from bogus cpusetsize values.
    const MAX_CPUSET_BYTES: usize = 128;
    let cpusetsize = core::cmp::min(cpusetsize, MAX_CPUSET_BYTES);
    let Some(_process) = resolve_process(pid) else {
        return ESRCH;
    };
    let mut tmp = alloc::vec![0u8; cpusetsize];
    let max_bits = cpusetsize * 8;
    for cpu in 0..MAX_HARTS {
        if cpu >= max_bits {
            break;
        }
        tmp[cpu / 8] |= 1u8 << (cpu % 8);
    }
    let token = get_current_token();
    let bufs = translated_byte_buffer(
        token,
        mask_ptr as *mut u8,
        cpusetsize,
        MapPermission::W,
    );
    let mut off = 0usize;
    for b in bufs {
        let n = core::cmp::min(b.len(), cpusetsize - off);
        b[..n].copy_from_slice(&tmp[off..off + n]);
        off += n;
        if off == cpusetsize {
            break;
        }
    }
    // Linux `sched_getaffinity` syscall returns the number of bytes written.
    // musl uses this return value (not the wrapper) when implementing `sysconf(_SC_NPROCESSORS_*)`.
    cpusetsize as isize
}

pub fn syscall_sched_setaffinity(pid: usize, cpusetsize: usize, mask_ptr: usize) -> isize {
    if mask_ptr == 0 || cpusetsize == 0 {
        return EINVAL;
    }
    let Some(_process) = resolve_process(pid) else {
        if DEBUG_CYCLICTEST {
            log::warn!(
                "[sched_setaffinity] ESRCH pid={} cpusetsize={} mask_ptr={:#x}",
                pid,
                cpusetsize,
                mask_ptr
            );
        }
        return ESRCH;
    };
    // Best-effort: accept and ignore. The scheduler is FIFO and does not yet enforce affinity.
    0
}

pub fn syscall_sched_get_priority_max(policy: usize) -> isize {
    match policy as i32 {
        SCHED_FIFO | SCHED_RR => 99,
        SCHED_OTHER => 0,
        _ => EINVAL,
    }
}

pub fn syscall_sched_get_priority_min(policy: usize) -> isize {
    match policy as i32 {
        SCHED_FIFO | SCHED_RR => 1,
        SCHED_OTHER => 0,
        _ => EINVAL,
    }
}

pub fn syscall_sched_rr_get_interval(pid: usize, interval_ptr: usize) -> isize {
    if interval_ptr == 0 {
        return EINVAL;
    }
    let Some(_process) = resolve_process(pid) else {
        return ESRCH;
    };
    let token = get_current_token();
    let ts = TimeSpec { tv_sec: 0, tv_nsec: 0 };
    write_user_value(token, interval_ptr as *mut TimeSpec, &ts);
    0
}

pub fn syscall_sched_getattr(pid: usize, attr_ptr: usize, size: usize, flags: usize) -> isize {
    if attr_ptr == 0 || size < SCHED_ATTR_SIZE_V0 || flags != 0 {
        return EINVAL;
    }
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let (policy, prio) = {
        let inner = process.borrow_mut();
        (inner.sched_policy as u32, inner.sched_priority as u32)
    };
    let mut attr = SchedAttr::default();
    let struct_size = core::mem::size_of::<SchedAttr>();
    let copy_len = core::cmp::min(size, struct_size);
    attr.size = copy_len as u32;
    attr.sched_policy = policy;
    attr.sched_priority = prio;
    let bytes = unsafe {
        core::slice::from_raw_parts(&attr as *const SchedAttr as *const u8, copy_len)
    };
    let token = get_current_token();
    if try_copy_to_user(token, attr_ptr as *mut u8, bytes).is_err() {
        return EFAULT;
    }
    0
}

pub fn syscall_sched_setattr(pid: usize, attr_ptr: usize, size: usize, flags: usize) -> isize {
    if attr_ptr == 0 {
        return EINVAL;
    }
    let mut size = size;
    let mut flags = flags;
    // Linux sched_setattr has 3 arguments (pid, attr, flags). Accept both 3-arg and 4-arg variants.
    if flags == 0 && size < SCHED_ATTR_SIZE_V0 {
        // Treat "size" as flags for the 3-arg call.
        flags = size;
        size = 0;
    }
    if flags != 0 {
        return EINVAL;
    }
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let struct_size = core::mem::size_of::<SchedAttr>();
    let copy_len = if size == 0 {
        struct_size
    } else {
        core::cmp::min(size, struct_size)
    };
    if copy_len < SCHED_ATTR_SIZE_V0 {
        return EINVAL;
    }
    let token = get_current_token();
    let mut attr = SchedAttr::default();
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(&mut attr as *mut SchedAttr as *mut u8, copy_len)
    };
    if try_copy_from_user(token, attr_ptr as *const u8, dst_bytes).is_err() {
        return EFAULT;
    }
    let policy = attr.sched_policy as i32;
    if !check_policy(policy) {
        return EINVAL;
    }
    let mut inner = process.borrow_mut();
    inner.sched_policy = policy;
    inner.sched_priority = attr.sched_priority as i32;
    0
}
