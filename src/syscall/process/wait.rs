use super::*;
use alloc::sync::Arc;

static REAP_LINGER_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);
static REAP_CHILD_ARC_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);

const PTRACE_TRACEME: usize = 0;
const PTRACE_CONT: usize = 7;
const PTRACE_KILL: usize = 8;
const PTRACE_ATTACH: usize = 16;
const PTRACE_DETACH: usize = 17;

#[repr(C)]
#[derive(Clone, Copy)]
struct SigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad0: i32,
    si_pid: i32,
    si_uid: u32,
    si_status: i32,
    _pad1: i32,
    si_utime: i64,
    si_stime: i64,
    _pad2: [u8; 80],
}

impl Default for SigInfo {
    fn default() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_pid: 0,
            si_uid: 0,
            si_status: 0,
            _pad1: 0,
            si_utime: 0,
            si_stime: 0,
            _pad2: [0u8; 80],
        }
    }
}

pub(super) fn remove_wait_queue_entry(
    queue: &mut alloc::collections::VecDeque<Arc<TaskControlBlock>>,
    task: &Arc<TaskControlBlock>,
) {
    queue.retain(|t| !Arc::ptr_eq(t, task));
}

pub(super) fn enqueue_waiter_once(
    queue: &mut alloc::collections::VecDeque<Arc<TaskControlBlock>>,
    task: &Arc<TaskControlBlock>,
) -> bool {
    if queue.iter().any(|t| Arc::ptr_eq(t, task)) {
        return false;
    }
    queue.push_back(task.clone());
    true
}

fn reap_zombie_child(child: &Arc<ProcessControlBlock>) -> u64 {
    // Main-thread resources are already detached in exit path; this aggressively
    // drops lingering task Arcs so kernel stacks are reclaimed on reap.
    let cpu_ns = crate::task::runtime::process_cpu_time_ns_at(
        child,
        crate::task::runtime::monotonic_time_ns(),
    );
    let tasks = {
        let mut inner = child.borrow_mut();
        core::mem::take(&mut inner.tasks)
    };
    let child_pid = child.getpid();
    for task in tasks.into_iter().flatten() {
        remove_inactive_task(task.clone());
        let strong = Arc::strong_count(&task);
        if strong > 1 {
            // Retry once so duplicate stale queue entries are aggressively dropped.
            remove_inactive_task(task.clone());
            let count = REAP_LINGER_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if count <= 16 || (count & (count - 1)) == 0 {
                let tid = task
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                let (
                    runqueue_refs,
                    processor_refs,
                    timer_refs,
                    futex_refs,
                    record_lock_refs,
                    task_slot_refs,
                    wait_queue_refs,
                    join_waiter_refs,
                    sync_waiter_refs,
                    pipe_waiter_refs,
                ) = debug_task_ref_breakdown(&task);
                let known_refs = runqueue_refs
                    .saturating_add(processor_refs)
                    .saturating_add(timer_refs)
                    .saturating_add(futex_refs)
                    .saturating_add(record_lock_refs)
                    .saturating_add(task_slot_refs)
                    .saturating_add(wait_queue_refs)
                    .saturating_add(join_waiter_refs)
                    .saturating_add(sync_waiter_refs)
                    .saturating_add(pipe_waiter_refs);
                let unknown_refs = strong.saturating_sub(1 + known_refs);
                crate::println!(
                    "[reap-debug] child_pid={} tid={} lingering_refs={} seq={} rq={} proc={} timer={} futex={} rec_lock={} task_slot={} waitq={} join={} sync={} pipe={} unknown={}",
                    child_pid,
                    tid,
                    strong,
                    count,
                    runqueue_refs,
                    processor_refs,
                    timer_refs,
                    futex_refs,
                    record_lock_refs,
                    task_slot_refs,
                    wait_queue_refs,
                    join_waiter_refs,
                    sync_waiter_refs,
                    pipe_waiter_refs,
                    unknown_refs
                );
            }
        }
        drop(task);
    }
    cpu_ns
}

fn wait4_pending_action(task: &Arc<TaskControlBlock>) -> Option<isize> {
    const EINTR: isize = -4;
    let (pending, mask) = {
        let inner = task.borrow_mut();
        (inner.pending_signals, inner.signal_mask)
    };
    let mut bits = pending_unmasked_bits(pending, mask, true);
    if bits == 0 {
        return None;
    }
    let mut clear_bits = 0u64;
    let mut saw_restart = false;
    let mut saw_interrupt = false;
    let mut first_sig = None;
    let process = current_process();
    let inner = process.borrow_mut();
    while bits != 0 {
        let signum = bits.trailing_zeros() as usize + 1;
        let bit = 1u64 << (signum - 1);
        bits &= bits - 1;
        if first_sig.is_none() {
            first_sig = Some(signum);
        }
        let action = inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default();
        if action.handler == SIG_IGN {
            clear_bits |= bit;
            continue;
        }
        if action.handler == SIG_DFL {
            if signum <= MAX_SIG {
                if let Some(flag) = SignalFlags::from_bits(1u32 << signum) {
                    if flag.check_error().is_none() {
                        clear_bits |= bit;
                        continue;
                    }
                }
            }
            saw_interrupt = true;
            break;
        }
        if (action.flags & SA_RESTART) != 0 {
            saw_restart = true;
        } else {
            saw_interrupt = true;
            break;
        }
    }
    drop(inner);
    if clear_bits != 0 {
        let mut inner = task.borrow_mut();
        inner.pending_signals &= !clear_bits;
    }
    if saw_interrupt || saw_restart {
        let pid = current_process().getpid();
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        crate::log_if!(
            DEBUG_SIGNAL,
            info,
            "[wait4] pid={} tid={} pending={:#x} mask={:#x} sig={:?} action={}",
            pid,
            tid,
            pending,
            mask,
            first_sig,
            if saw_interrupt { "eintr" } else { "restart" }
        );
    }
    if saw_interrupt {
        Some(EINTR)
    } else if saw_restart {
        Some(ERESTARTSYS)
    } else {
        None
    }
}

fn wake_waiters_on(process: &Arc<ProcessControlBlock>) {
    queue_process_signal(process.getpid(), SIGCHLD_NUM);
    let waiters = {
        let mut inner = process.borrow_mut();
        inner.wait_queue.drain(..).collect::<Vec<_>>()
    };
    for waiter in waiters {
        wakeup_task(waiter);
    }
}

pub(super) fn wake_parent_waiters_for(process: &Arc<ProcessControlBlock>) {
    let (parent, tracer_pid) = {
        let inner = process.borrow_mut();
        (
            inner.parent.as_ref().and_then(|w| w.upgrade()),
            inner.ptrace_tracer_pid,
        )
    };

    let mut parent_pid = None;
    if let Some(parent) = parent {
        parent_pid = Some(parent.getpid());
        wake_waiters_on(&parent);
    }
    if let Some(tracer_pid) = tracer_pid {
        if parent_pid != Some(tracer_pid) {
            if let Some(tracer) = pid2process(tracer_pid) {
                wake_waiters_on(&tracer);
            }
        }
    }
}

pub(super) fn enter_ptrace_stop(process: &Arc<ProcessControlBlock>, signum: i32) {
    let tasks = {
        let mut inner = process.borrow_mut();
        if inner.ptrace_tracer_pid.is_none() {
            return;
        }
        inner.stopped = true;
        inner.stop_signal = signum;
        inner.stop_pending = true;
        inner.continued = false;
        inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<Vec<_>>()
    };
    for task in tasks {
        let mut task_inner = task.borrow_mut();
        if task_inner.task_status != TaskStatus::Blocked {
            task_inner.task_status = TaskStatus::Blocked;
            task_inner.stopped_by_signal = true;
        }
    }
    wake_parent_waiters_for(process);
    block_current_and_run_next();
}

pub fn syscall_wait4(pid: isize, wstatus_ptr: usize, options: usize, _rusage: usize) -> isize {
    const WNOHANG: usize = 0x00000001;
    const WUNTRACED: usize = 0x00000002;
    const WCONTINUED: usize = 0x00000008;
    const ECHILD: isize = -10;
    let allowed = WNOHANG | WUNTRACED | WCONTINUED;
    if (options & !allowed) != 0 {
        return err(SyscallError::EINVAL);
    }
    if pid == isize::MIN || pid == (i32::MIN as isize) {
        return err(SyscallError::ESRCH);
    }
    let token = get_current_token();
    let mut temp_exit_code: i32 = 0;
    let mut temp_signal: Option<i32> = None;
    let mut temp_coredump = false;
    loop {
        let cur_process = current_process();
        let task = current_task().unwrap();
        if let Some(action) = wait4_pending_action(&task) {
            let mut process_inner = cur_process.borrow_mut();
            remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
            drop(process_inner);
            return action;
        }
        let mut process_inner = cur_process.borrow_mut();
        remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
        let parent_pgid = process_inner.pgid;
        let parent_pid = cur_process.getpid();
        let mut stop_event: Option<(Arc<ProcessControlBlock>, i32)> = None;
        let mut cont_event: Option<Arc<ProcessControlBlock>> = None;
        let (has_matching_child, zombie_child) = if process_inner.children.is_empty() {
            (false, None)
        } else {
            let mut found: Option<usize> = None;
            let mut has_match = false;
            for (index, child) in process_inner.children.iter().enumerate() {
                let child_inner = child.borrow_mut();
                let matches = match pid {
                    -1 => true, // any child
                    0 => child_inner.pgid == parent_pgid,
                    p if p > 0 => child.pid.0 == p as usize,
                    p => child_inner.pgid == (-p) as usize,
                };
                if matches {
                    has_match = true;
                }
                if matches && child_inner.is_zombie {
                    temp_exit_code = child_inner.exit_code;
                    temp_signal = if temp_exit_code < 0 {
                        Some(-temp_exit_code)
                    } else {
                        None
                    };
                    temp_coredump = child_inner.dumped_core;
                    found = Some(index);
                    break;
                }
                let ptrace_stop_visible = child_inner.ptrace_tracer_pid == Some(parent_pid);
                if matches
                    && child_inner.stopped
                    && child_inner.stop_pending
                    && ((options & WUNTRACED) != 0 || ptrace_stop_visible)
                {
                    let sig = if child_inner.stop_signal != 0 {
                        child_inner.stop_signal
                    } else {
                        crate::task::signal::SIGSTOP_NUM as i32
                    };
                    stop_event = Some((child.clone(), sig));
                    break;
                }
                if matches && (options & WCONTINUED) != 0 && child_inner.continued {
                    cont_event = Some(child.clone());
                    break;
                }
            }
            if let Some(index) = found {
                let child = process_inner.children.remove(index);
                (true, Some(child))
            } else {
                (has_match, None)
            }
        };

        let mut has_matching_ptrace = false;
        if stop_event.is_none() && zombie_child.is_none() {
            let traced_processes = {
                let map = PID2PCB.lock();
                map.values().cloned().collect::<Vec<_>>()
            };
            for traced in traced_processes {
                if Arc::ptr_eq(&traced, &cur_process) {
                    continue;
                }
                let traced_pid = traced.getpid();
                let traced_inner = traced.borrow_mut();
                if traced_inner.ptrace_tracer_pid != Some(parent_pid) {
                    continue;
                }
                let matches = match pid {
                    -1 => true,
                    p if p > 0 => traced_pid == p as usize,
                    _ => false,
                };
                if !matches {
                    continue;
                }
                has_matching_ptrace = true;
                if traced_inner.stopped && traced_inner.stop_pending {
                    let sig = if traced_inner.stop_signal != 0 {
                        traced_inner.stop_signal
                    } else {
                        SIGSTOP_NUM as i32
                    };
                    stop_event = Some((traced.clone(), sig));
                    break;
                }
                if (options & WCONTINUED) != 0 && traced_inner.continued {
                    cont_event = Some(traced.clone());
                    break;
                }
            }
        }

        if let Some((target, sig)) = stop_event {
            let pid = target.getpid();
            let mut target_inner = target.borrow_mut();
            target_inner.stop_pending = false;
            target_inner.stop_signal = sig;
            drop(target_inner);
            drop(process_inner);
            if wstatus_ptr != 0 {
                let status = ((sig & 0xff) << 8) | 0x7f;
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }
        if let Some(target) = cont_event {
            let pid = target.getpid();
            let mut target_inner = target.borrow_mut();
            target_inner.continued = false;
            drop(target_inner);
            drop(process_inner);
            if wstatus_ptr != 0 {
                let status = 0xffff;
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }

        if let Some(child) = zombie_child {
            let pid = child.getpid();
            drop(process_inner);
            // Keep exited processes visible (e.g., for `kill $!`) until they are reaped.
            let child_cpu_ns = reap_zombie_child(&child);
            // Reaping is complete now; remove it from the global PID table.
            crate::task::manager::remove_from_pid2process(pid);
            let child_refs = Arc::strong_count(&child);
            if child_refs > 1 {
                let seq = REAP_CHILD_ARC_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if seq <= 16 || (seq & (seq - 1)) == 0 {
                    crate::println!(
                        "[reap-child-debug] child_pid={} refs_after_reap={} seq={}",
                        pid,
                        child_refs,
                        seq
                    );
                }
            }
            {
                let mut parent_inner = cur_process.borrow_mut();
                parent_inner.child_cpu_time_ns =
                    parent_inner.child_cpu_time_ns.saturating_add(child_cpu_ns);
            }
            drop(child);
            if wstatus_ptr != 0 {
                // Linux wait status encoding:
                // - normal exit: (code & 0xff) << 8
                // - signaled: signal number in low 7 bits
                let status = if let Some(sig) = temp_signal {
                    let mut status = sig & 0x7f;
                    if temp_coredump {
                        status |= 0x80;
                    }
                    status
                } else {
                    (((temp_exit_code as u32) & 0xff) << 8) as i32
                };
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }

        if !has_matching_child && !has_matching_ptrace {
            if DEBUG_PTHREAD {
                let child_pids = process_inner
                    .children
                    .iter()
                    .map(|c| c.getpid())
                    .collect::<Vec<_>>();
                let traced_pids = {
                    let map = PID2PCB.lock();
                    map.values()
                        .filter_map(|p| {
                            if Arc::ptr_eq(p, &cur_process) {
                                return None;
                            }
                            let inner = p.borrow_mut();
                            if inner.ptrace_tracer_pid == Some(parent_pid) {
                                Some(p.getpid())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                };
                log::debug!(
                    "[wait4] pid={} wait_pid={} no matching child children={:?} traced={:?}",
                    cur_process.getpid(),
                    pid,
                    child_pids,
                    traced_pids
                );
            }
            drop(process_inner);
            return ECHILD;
        }

        // Non-blocking wait: return immediately if no child has exited yet.
        if (options & WNOHANG) != 0 {
            drop(process_inner);
            return 0;
        }

        // Block until a child exits or changes state.
        let inserted = enqueue_waiter_once(&mut process_inner.wait_queue, &task);
        if inserted {
            let qlen = process_inner.wait_queue.len();
            if qlen >= 64 && (qlen & (qlen - 1)) == 0 {
                crate::println!(
                    "[wait4-debug] pid={} wait_queue_len={} children={} wait_pid={} options=0x{:x}",
                    cur_process.getpid(),
                    qlen,
                    process_inner.children.len(),
                    pid,
                    options
                );
            }
        }
        drop(process_inner);
        block_current_and_run_next();
    }
}

pub fn syscall_waitid(idtype: usize, id: usize, infop: usize, options: usize) -> isize {
    const P_ALL: usize = 0;
    const P_PID: usize = 1;
    const P_PGID: usize = 2;
    const P_PIDFD: usize = 3;
    const WNOHANG: usize = 0x00000001;
    const WSTOPPED: usize = 0x00000002;
    const WEXITED: usize = 0x00000004;
    const WCONTINUED: usize = 0x00000008;
    const WNOWAIT: usize = 0x01000000;
    const SIGCHLD: i32 = 17;
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    const CLD_STOPPED: i32 = 5;
    const CLD_CONTINUED: i32 = 6;
    const ECHILD: isize = -10;
    const EBADF: isize = -9;
    const EAGAIN: isize = -11;
    const O_NONBLOCK: u32 = 0x800;

    let allowed = WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT;
    if (options & !allowed) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (options & (WEXITED | WSTOPPED | WCONTINUED)) == 0 {
        return err(SyscallError::EINVAL);
    }
    if infop == 0 {
        return err(SyscallError::EFAULT);
    }
    if matches!(idtype, P_PID) && id == 0 {
        return err(SyscallError::EINVAL);
    }
    let mut pidfd_target_pid = 0usize;
    let mut pidfd_nonblock = false;
    if idtype == P_PIDFD {
        let (file, descriptor_flags) = {
            let files = current_files();
            let files = files.lock();
            let Some((file, descriptor_flags)) = files.get_file_and_flags(id) else {
                return EBADF;
            };
            (file, descriptor_flags)
        };
        let Some(pidfd) = file.as_any().downcast_ref::<PidFdFile>() else {
            return EBADF;
        };
        pidfd_target_pid = pidfd.target_pid();
        pidfd_nonblock = (descriptor_flags & O_NONBLOCK) != 0;
    }

    let token = get_current_token();
    loop {
        let cur_process = current_process();
        let task = current_task().unwrap();
        if let Some(action) = wait4_pending_action(&task) {
            let mut process_inner = cur_process.borrow_mut();
            remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
            drop(process_inner);
            return action;
        }

        let mut process_inner = cur_process.borrow_mut();
        remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
        let parent_pgid = process_inner.pgid;
        let mut has_match = false;
        let mut found_zombie: Option<(usize, i32, Option<i32>, bool, u32)> = None;
        let mut found_stop: Option<(usize, i32, u32)> = None;
        let mut found_cont: Option<(usize, u32)> = None;

        for (index, child) in process_inner.children.iter().enumerate() {
            let child_inner = child.borrow_mut();
            let matches = match idtype {
                P_ALL => true,
                P_PID => child.pid.0 == id,
                P_PGID => {
                    let target = if id == 0 { parent_pgid } else { id };
                    child_inner.pgid == target
                }
                P_PIDFD => child.pid.0 == pidfd_target_pid,
                _ => return err(SyscallError::EINVAL),
            };
            if !matches {
                continue;
            }
            has_match = true;
            if (options & WEXITED) != 0 && child_inner.is_zombie {
                let exit_code = child_inner.exit_code;
                let signal = if exit_code < 0 {
                    Some(-exit_code)
                } else {
                    None
                };
                let coredump = child_inner.dumped_core;
                found_zombie = Some((index, exit_code, signal, coredump, child_inner.uid));
                break;
            }
            if (options & WSTOPPED) != 0 && child_inner.stopped && child_inner.stop_pending {
                let sig = if child_inner.stop_signal != 0 {
                    child_inner.stop_signal
                } else {
                    crate::task::signal::SIGSTOP_NUM as i32
                };
                found_stop = Some((child.pid.0, sig, child_inner.uid));
                break;
            }
            if (options & WCONTINUED) != 0 && child_inner.continued {
                found_cont = Some((child.pid.0, child_inner.uid));
                break;
            }
        }

        if let Some((index, exit_code, signal, coredump, uid)) = found_zombie {
            let child_pid = process_inner.children[index].pid.0;
            let child = if (options & WNOWAIT) == 0 {
                Some(process_inner.children.remove(index))
            } else {
                None
            };
            drop(process_inner);
            if (options & WNOWAIT) == 0 {
                if let Some(child) = child.as_ref() {
                    let child_cpu_ns = reap_zombie_child(child);
                    crate::task::manager::remove_from_pid2process(child_pid);
                    let mut parent_inner = cur_process.borrow_mut();
                    parent_inner.child_cpu_time_ns =
                        parent_inner.child_cpu_time_ns.saturating_add(child_cpu_ns);
                }
            }
            let (si_status, si_code) = if let Some(sig) = signal {
                (sig, if coredump { CLD_DUMPED } else { CLD_KILLED })
            } else {
                (exit_code & 0xff, CLD_EXITED)
            };
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = si_code;
            info.si_pid = child_pid as i32;
            info.si_uid = uid;
            info.si_status = si_status;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if let Some((pid, sig, uid)) = found_stop {
            if (options & WNOWAIT) == 0 {
                if let Some(child) = process_inner.children.iter().find(|c| c.getpid() == pid) {
                    let mut child_inner = child.borrow_mut();
                    child_inner.stop_pending = false;
                }
            }
            drop(process_inner);
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = CLD_STOPPED;
            info.si_pid = pid as i32;
            info.si_uid = uid;
            info.si_status = sig;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if let Some((pid, uid)) = found_cont {
            if (options & WNOWAIT) == 0 {
                if let Some(child) = process_inner.children.iter().find(|c| c.getpid() == pid) {
                    let mut child_inner = child.borrow_mut();
                    child_inner.continued = false;
                }
            }
            drop(process_inner);
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = CLD_CONTINUED;
            info.si_pid = pid as i32;
            info.si_uid = uid;
            info.si_status = crate::task::signal::SIGCONT_NUM as i32;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if !has_match {
            drop(process_inner);
            return ECHILD;
        }

        if (options & WNOHANG) != 0 {
            drop(process_inner);
            let info = SigInfo::default();
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if idtype == P_PIDFD && pidfd_nonblock {
            drop(process_inner);
            return EAGAIN;
        }

        let inserted = enqueue_waiter_once(&mut process_inner.wait_queue, &task);
        if inserted {
            let qlen = process_inner.wait_queue.len();
            if qlen >= 64 && (qlen & (qlen - 1)) == 0 {
                crate::println!(
                    "[waitid-debug] pid={} wait_queue_len={} children={} idtype={} id={} options=0x{:x}",
                    cur_process.getpid(),
                    qlen,
                    process_inner.children.len(),
                    idtype,
                    id,
                    options
                );
            }
        }
        drop(process_inner);
        block_current_and_run_next();
    }
}

pub fn syscall_getpid() -> isize {
    current_task()
        .unwrap()
        .process
        .upgrade()
        .unwrap()
        .visible_pid() as isize
}

fn ptrace_target_for_current(pid: usize) -> Result<Arc<ProcessControlBlock>, isize> {
    if pid == 0 {
        return Err(err(SyscallError::ESRCH));
    }
    let Some(target) = pid2process(pid) else {
        return Err(err(SyscallError::ESRCH));
    };
    let tracer_pid = current_process().getpid();
    let traced_by_current = {
        let inner = target.borrow_mut();
        if inner.is_zombie {
            return Err(err(SyscallError::ESRCH));
        }
        inner.ptrace_tracer_pid == Some(tracer_pid)
    };
    if !traced_by_current {
        return Err(err(SyscallError::EPERM));
    }
    Ok(target)
}

pub fn syscall_ptrace(request: usize, pid: usize, _addr: usize, data: usize) -> isize {
    match request {
        PTRACE_TRACEME => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if inner.ptrace_tracer_pid.is_some() {
                return err(SyscallError::EPERM);
            }
            let Some(parent_pid) = inner
                .parent
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|p| p.getpid())
            else {
                return err(SyscallError::EPERM);
            };
            inner.ptrace_tracer_pid = Some(parent_pid);
            0
        }
        PTRACE_ATTACH => {
            let tracer_pid = current_process().getpid();
            if pid == tracer_pid {
                return err(SyscallError::EPERM);
            }
            let Some(target) = pid2process(pid) else {
                return err(SyscallError::ESRCH);
            };
            if !crate::task::signal::can_signal_process(&target, SIGSTOP_NUM as i32) {
                return err(SyscallError::EPERM);
            }
            let tasks = {
                let mut inner = target.borrow_mut();
                if inner.is_zombie {
                    return err(SyscallError::ESRCH);
                }
                if inner.ptrace_tracer_pid.is_some() {
                    return err(SyscallError::EPERM);
                }
                inner.ptrace_tracer_pid = Some(tracer_pid);
                inner.stopped = true;
                inner.stop_pending = true;
                inner.stop_signal = SIGSTOP_NUM as i32;
                inner.continued = false;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if task_inner.task_status != TaskStatus::Blocked {
                    task_inner.task_status = TaskStatus::Blocked;
                    task_inner.stopped_by_signal = true;
                }
            }
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_DETACH => {
            let sig = data as isize;
            if sig < 0 || sig as usize > RT_SIG_MAX {
                return err(SyscallError::EINVAL);
            }
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let tasks = {
                let mut inner = target.borrow_mut();
                inner.ptrace_tracer_pid = None;
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = true;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            if sig != 0 {
                queue_process_signal(pid, sig as usize);
            }
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_CONT => {
            let sig = data as isize;
            if sig < 0 || sig as usize > RT_SIG_MAX {
                return err(SyscallError::EINVAL);
            }
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let tasks = {
                let mut inner = target.borrow_mut();
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = true;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            if sig != 0 {
                queue_process_signal(pid, sig as usize);
            }
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_KILL => {
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let tasks = {
                let mut inner = target.borrow_mut();
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = false;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            queue_process_signal(pid, SIGKILL_NUM);
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            0
        }
        _ => {
            // Keep invalid memory/register ptrace operations Linux-like for LTP:
            // return err(SyscallError::EIO) (tests also accept err(SyscallError::EFAULT)).
            if let Err(e) = ptrace_target_for_current(pid) {
                return e;
            }
            err(SyscallError::EIO)
        }
    }
}
