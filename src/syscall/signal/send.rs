use super::*;

pub fn syscall_kill(pid: usize, signum: i32) -> isize {
    let pid = pid as isize;
    if pid > 0 {
        return kill(pid as usize, signum);
    }

    let current = current_process();
    let self_pid = current.getpid();
    let current_ns_id = current.pid_namespace_id();
    let current_pgid = current.borrow_mut().pgid;
    let procs: Vec<_> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };

    let targets: Vec<usize> = match pid {
        0 => procs
            .into_iter()
            .filter_map(|p| {
                let inner = p.borrow_mut();
                if p.getpid() == self_pid {
                    return None;
                }
                if current_ns_id != 0
                    && !crate::task::process_visible_in_pid_namespace(&p, current_ns_id)
                {
                    return None;
                }
                if inner.pgid == current_pgid {
                    Some(p.getpid())
                } else {
                    None
                }
            })
            .collect(),
        -1 => procs
            .into_iter()
            .filter_map(|p| {
                if p.getpid() == 0 || p.getpid() == self_pid {
                    return None;
                }
                if current_ns_id != 0
                    && !crate::task::process_visible_in_pid_namespace(&p, current_ns_id)
                {
                    return None;
                }
                Some(p.getpid())
            })
            .collect(),
        p if p < -1 => {
            let target_pgid = (-p) as usize;
            procs
                .into_iter()
                .filter_map(|p| {
                    let inner = p.borrow_mut();
                    if p.getpid() == self_pid {
                        return None;
                    }
                    if current_ns_id != 0
                        && !crate::task::process_visible_in_pid_namespace(&p, current_ns_id)
                    {
                        return None;
                    }
                    if inner.pgid == target_pgid {
                        Some(p.getpid())
                    } else {
                        None
                    }
                })
                .collect()
        }
        _ => Vec::new(),
    };

    let mut delivered = false;
    let mut denied = false;
    for target in targets {
        match kill(target, signum) {
            0 => delivered = true,
            e if e == err(SyscallError::EPERM) => denied = true,
            _ => {}
        }
    }
    if delivered {
        0
    } else if denied {
        err(SyscallError::EPERM)
    } else {
        err(SyscallError::ESRCH)
    }
}

/// Linux `tgkill` (syscall 131).
///
/// Delivers a signal to a specific thread (Linux-style tid encoding).
pub fn syscall_tgkill(tgid: usize, tid: usize, sig: i32) -> isize {
    if sig < 0 || sig as usize > RT_SIG_MAX {
        return err(SyscallError::EINVAL);
    }
    if (tgid as isize) <= 0 || (tid as isize) <= 0 {
        return err(SyscallError::EINVAL);
    }
    if DEBUG_PTHREAD {
        crate::println!("[tgkill] tgid={} tid={} sig={}", tgid, tid, sig);
    }
    let Some(proc) = pid2process(tgid) else {
        return err(SyscallError::ESRCH);
    };
    let Some(tid_index) = decode_linux_tid_strict(tgid, tid) else {
        return err(SyscallError::ESRCH);
    };
    if !can_signal_process(&proc, sig) {
        return err(SyscallError::EPERM);
    }
    let task = {
        let inner = proc.borrow_mut();
        inner.tasks.get(tid_index).and_then(|t| t.as_ref()).cloned()
    };
    let Some(task) = task else {
        return err(SyscallError::ESRCH);
    };
    if sig == 0 {
        return 0;
    }
    if rt_sigpending_limit_reached(&proc, sig as usize) {
        return err(SyscallError::EAGAIN);
    }
    let sender = current_process();
    let sender_pid = sender.getpid() as i32;
    let sender_uid = {
        let inner = sender.borrow_mut();
        inner.uid
    };
    queue_signal_to_task(task.clone(), sig as usize, sender_pid, sender_uid, -6, 0);
    if DEBUG_PTHREAD && sig == 33 {
        let (tid_idx, status, on_cpu) = {
            let inner = task.borrow_mut();
            (
                inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX),
                inner.task_status,
                task.on_cpu.load(Ordering::Acquire),
            )
        };
        log::debug!(
            "[tgkill] sigcancel pid={} tid_index={} status={:?} on_cpu={}",
            tgid,
            tid_idx,
            status,
            on_cpu
        );
    }
    0
}

/// Linux `tkill` (syscall 130).
///
/// Delivers a signal to a specific thread in the current process.
pub fn syscall_tkill(tid: usize, sig: i32) -> isize {
    if sig < 0 || sig as usize > RT_SIG_MAX {
        return err(SyscallError::EINVAL);
    }
    if (tid as isize) <= 0 {
        return err(SyscallError::EINVAL);
    }
    let Some((proc, task)) = find_task_by_linux_tid(tid) else {
        return err(SyscallError::ESRCH);
    };
    if !can_signal_process(&proc, sig) {
        return err(SyscallError::EPERM);
    }
    if sig == 0 {
        return 0;
    }
    if rt_sigpending_limit_reached(&proc, sig as usize) {
        return err(SyscallError::EAGAIN);
    }
    let sender = current_process();
    let sender_pid = sender.getpid() as i32;
    let sender_uid = {
        let inner = sender.borrow_mut();
        inner.uid
    };
    queue_signal_to_task(task, sig as usize, sender_pid, sender_uid, -6, 0);
    0
}
