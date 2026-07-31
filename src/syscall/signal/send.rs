use super::*;

use crate::fs::{PidFdFile, PseudoDir};

/// Deliver a signal to a process and all its live tasks.
fn deliver_signal_to_process(
    target: &Arc<ProcessControlBlock>,
    signum: i32,
    legacy_flag: Option<SignalFlags>,
    sender_pid: i32,
    sender_uid: u32,
) {
    if target.borrow_mut().is_zombie {
        return;
    }
    {
        let mut process_ref = target.signal();
        if let Some(flag) = legacy_flag {
            process_ref.signals.insert(flag);
        }
    }
    let tasks = target.tasks_snapshot();
    for task in tasks {
        queue_signal_to_task(task, signum as usize, sender_pid, sender_uid, 0, 0);
    }
}

pub fn syscall_kill(pid: usize, signum: i32) -> isize {
    let pid = pid as isize;
    if pid > 0 {
        return kill(pid as usize, signum);
    }

    if signum < 0 || signum as usize > RT_SIG_MAX {
        return err(SyscallError::EINVAL);
    }

    let current = current_process();
    let self_pid = current.getpid();
    let current_ns_id = current.pid_namespace_id();
    let current_pgid = current.borrow_mut().pgid;
    let procs: Vec<_> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };

    // Collect target process references directly instead of global PIDs.
    // Previously this collected getpid() (global PID) then passed it to kill(),
    // which re-resolves via visible_pid() in the caller's namespace — causing
    // signals to be silently dropped when the caller is in a PID namespace.
    let targets: Vec<Arc<ProcessControlBlock>> = match pid {
        0 => procs
            .into_iter()
            .filter(|p| {
                if current_ns_id != 0
                    && !crate::task::process_visible_in_pid_namespace(p, current_ns_id)
                {
                    return false;
                }
                let inner = p.borrow_mut();
                inner.pgid == current_pgid
            })
            .collect(),
        -1 => procs
            .into_iter()
            .filter(|p| {
                if p.getpid() <= 1 || p.getpid() == self_pid {
                    return false;
                }
                if current_ns_id != 0
                    && !crate::task::process_visible_in_pid_namespace(p, current_ns_id)
                {
                    return false;
                }
                true
            })
            .collect(),
        p if p < -1 => {
            let target_pgid = (-p) as usize;
            procs
                .into_iter()
                .filter(|p| {
                    if current_ns_id != 0
                        && !crate::task::process_visible_in_pid_namespace(p, current_ns_id)
                    {
                        return false;
                    }
                    let inner = p.borrow_mut();
                    inner.pgid == target_pgid
                })
                .collect()
        }
        _ => Vec::new(),
    };

    // Signal collected processes directly, bypassing PID namespace re-resolution.
    let legacy_flag = if (signum as usize) <= crate::task::signal::MAX_SIG {
        SignalFlags::from_bits(1u32 << signum)
    } else {
        None
    };
    let sender_pid = self_pid as i32;
    let sender_uid = {
        let inner = current.borrow_mut();
        inner.uid
    };

    let mut delivered = false;
    let mut denied = false;
    for target in &targets {
        if !can_signal_process(target, signum) {
            denied = true;
            continue;
        }

        // Linux: a PID namespace init process cannot send SIGKILL/SIGSTOP
        // to itself — the signal is silently accepted but not delivered.
        // This prevents the namespace init from accidentally tearing down
        // its own namespace via kill(0, SIGKILL) or similar.
        if current_ns_id != 0
            && current.is_pid_namespace_init()
            && Arc::ptr_eq(&current, target)
            && matches!(signum as usize, SIGKILL_NUM | SIGSTOP_NUM)
        {
            delivered = true;
            continue;
        }

        delivered = true;
        if signum == 0 {
            continue;
        }
        // Deliver signal directly to the target process and all its tasks.
        deliver_signal_to_process(target, signum, legacy_flag, sender_pid, sender_uid);

        // Linux: when SIGKILL is delivered to a PID namespace init in a
        // non-root namespace, cascade the signal to every member of that
        // namespace so the entire namespace is torn down.
        if signum as usize == SIGKILL_NUM
            && target.is_pid_namespace_init()
            && target.pid_namespace_id() != 0
        {
            let ns_id = target.pid_namespace_id();
            for member_pid in crate::task::pid_namespace_member_pids(ns_id) {
                if let Some(member) = pid2process(member_pid) {
                    if !targets.iter().any(|t| Arc::ptr_eq(t, &member)) {
                        if can_signal_process(&member, signum) {
                            deliver_signal_to_process(
                                &member,
                                signum,
                                legacy_flag,
                                sender_pid,
                                sender_uid,
                            );
                        }
                    }
                }
            }
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

/// 从任意文件对象中提取 `pidfd_send_signal` 的目标进程。
///
/// 支持两种 fd 类型：
/// - [`PidFdFile`]：`pidfd_open` / `clone3(CLONE_PIDFD)` 产生的 pidfd，
///   通过内部 `Weak<ProcessControlBlock>` 升级——若原进程已退出且 PCB 被释放，
///   升级失败返回 `ESRCH`，确保 PID 复用后不误投递。
/// - [`PseudoDir`]：`/proc/<pid>` 目录 fd，通过 `pidfd_target_process()` 解析，
///   同样以 `Weak` 绑定进程身份。
///
/// 其他文件类型一律返回 `EBADF`。
fn pidfd_send_signal_target(
    file: &(dyn crate::fs::File + Send + Sync),
) -> Result<Arc<ProcessControlBlock>, SyscallError> {
    if let Some(pidfd_file) = file.as_any().downcast_ref::<PidFdFile>() {
        return pidfd_file.target_process().ok_or(SyscallError::ESRCH);
    }
    if let Some(proc_dir) = file.as_any().downcast_ref::<PseudoDir>() {
        if proc_dir.is_pidfd_target_dir() {
            return proc_dir.pidfd_target_process().ok_or(SyscallError::ESRCH);
        }
    }
    Err(SyscallError::EBADF)
}

/// Linux `pidfd_send_signal(2)` for pidfds created by `pidfd_open` /
/// `clone3(CLONE_PIDFD)` and for `/proc/<pid>` directory fds.
pub fn syscall_pidfd_send_signal(pidfd: usize, sig: i32, info_ptr: usize, flags: usize) -> isize {
    if flags != 0 {
        return err(SyscallError::EINVAL);
    }
    if sig < 0 || sig as usize > RT_SIG_MAX {
        return err(SyscallError::EINVAL);
    }

    let file = {
        let files = current_files();
        files.lock().get_file(pidfd)
    };
    let Some(file) = file else {
        return err(SyscallError::EBADF);
    };
    let process = match pidfd_send_signal_target(file.as_ref()) {
        Ok(process) => process,
        Err(e) => return err(e),
    };
    // Resolve through the fd-held Weak<ProcessControlBlock>, so a stale proc
    // pidfd cannot accidentally signal an unrelated process after PID reuse.

    if !can_signal_process(&process, sig) {
        return err(SyscallError::EPERM);
    }
    // sig=0 is a Linux convention: probe whether the process exists and is
    // reachable without actually delivering any signal or touching siginfo.
    if sig == 0 {
        return 0;
    }

    let sender = current_process();
    let sender_pid = sender.getpid() as i32;
    let sender_uid = {
        let inner = sender.borrow_mut();
        inner.uid
    };
    let (si_code, sig_value) = if info_ptr != 0 {
        let Some(info) = try_read_user_value::<LinuxSigInfo>(
            get_current_token(),
            info_ptr as *const LinuxSigInfo,
        ) else {
            return err(SyscallError::EFAULT);
        };
        if info.si_signo != sig {
            return err(SyscallError::EINVAL);
        }
        // field[2]/field[3] map to si_value.sival_ptr in the kernel ABI layout.
        // Reconstruct the 64-bit value from two consecutive 32-bit words.
        let lo = info.field[2] as u32 as usize;
        let hi = info.field[3] as u32 as usize;
        (info.si_code, lo | (hi << 32))
    } else {
        (0, 0)
    };

    let signum = sig as usize;
    if rt_sigpending_limit_reached(&process, signum) {
        return err(SyscallError::EAGAIN);
    }

    let Some(bit) = signal_bit(signum) else {
        return err(SyscallError::EINVAL);
    };
    let tasks = process.tasks_snapshot();
    let Some(task) = crate::task::signal::pick_task_for_signal(&tasks, bit) else {
        return err(SyscallError::ESRCH);
    };
    queue_signal_to_task(task, signum, sender_pid, sender_uid, si_code, sig_value);
    0
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
    let task = proc.task_at(tid_index);
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
                task.running_hart().unwrap_or(TaskControlBlock::OFF_CPU),
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
