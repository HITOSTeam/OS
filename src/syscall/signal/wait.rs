use super::*;

/// Linux `rt_sigsuspend` (syscall 133).
pub fn syscall_rt_sigsuspend(mask_ptr: usize, sigsetsize: usize) -> isize {
    if !valid_sigset_size(sigsetsize) {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let new_mask = if mask_ptr != 0 {
        let Some(v) = try_read_user_value(token, mask_ptr as *const u64) else {
            return err(SyscallError::EFAULT);
        };
        v
    } else {
        0
    };
    let task = current_task().unwrap();
    let old_mask = {
        let inner = task.borrow_mut();
        inner.signal_mask
    };

    loop {
        let (pending, mask) = {
            let mut inner = task.borrow_mut();
            if inner.sigsuspend_old_mask.is_none() {
                inner.sigsuspend_old_mask = Some(old_mask);
            }
            inner.signal_mask = new_mask;
            (inner.pending_signals, inner.signal_mask)
        };
        if has_wait_interrupting_pending(pending, mask) {
            return err(SyscallError::EINTR);
        }
        block_current_and_run_next();
    }
}

/// Linux `rt_sigreturn` (syscall 139).
pub fn syscall_rt_sigreturn() -> isize {
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    if DEBUG_PTHREAD {
        crate::println!(
            "[rt_sigreturn] tid={}",
            inner.res.as_ref().map(|r| r.tid).unwrap_or(0)
        );
    }
    let Some(saved) = inner.sig_saved_ctx.pop() else {
        drop(inner);
        exit_current_and_run_next(-1)
    };
    if saved.uses_ucontext && saved.ucontext_ptr != 0 {
        let token = get_current_token();
        let sp = inner.get_trap_cx().x[REG_SP];
        let a2 = inner.get_trap_cx().x[REG_A2];
        let uc = try_read_user_value(token, saved.ucontext_ptr as *const UContext)
            .or_else(|| try_read_user_value(token, sp as *const UContext));
        if let Some(uc) = uc {
            if DEBUG_PTHREAD && saved.signum == 33 {
                let tp = saved.trap_cx.x[REG_TP];
                let cancel = try_read_user_value(token, tp.wrapping_sub(156) as *const i32);
                let canceldisable = try_read_user_value(token, tp.wrapping_sub(152) as *const u8);
                let cancelasync = try_read_user_value(token, tp.wrapping_sub(151) as *const u8);
                let sig_ctx = uc.uc_mcontext;
                log::debug!(
                    "[sigcancel] ucontext ptr={:#x} sp={:#x} a2={:#x} sepc {:#x}->{:#x} a0 {:#x}->{:#x} mask {:#x}->{:#x} tp {:#x}->{:#x} flags={:?}/{:?}/{:?}",
                    saved.ucontext_ptr,
                    sp,
                    a2,
                    saved.trap_cx.sepc,
                    sig_ctx.regs.pc,
                    saved.trap_cx.x[REG_A0],
                    sig_ctx.regs.a0,
                    saved.mask,
                    uc.uc_sigmask,
                    saved.trap_cx.x[REG_TP],
                    sig_ctx.regs.tp,
                    cancel,
                    canceldisable,
                    cancelasync
                );
            }
            let mut restored = saved.trap_cx;
            let sig_ctx = uc.uc_mcontext;
            sig_ctx.regs.write_to_trap(&mut restored);
            *inner.get_trap_cx() = restored;
            inner.signal_mask = uc.uc_sigmask;
            inner.on_sigaltstack = saved.was_on_sigaltstack;
            return restored.x[REG_A0] as isize;
        }
    }
    *inner.get_trap_cx() = saved.trap_cx;
    inner.signal_mask = saved.mask;
    inner.on_sigaltstack = saved.was_on_sigaltstack;
    saved.trap_cx.x[REG_A0] as isize
}

fn write_siginfo(
    info_ptr: usize,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
    si_code: i32,
    sig_value: usize,
) -> Result<(), ()> {
    if info_ptr == 0 {
        return Ok(());
    }
    let token = get_current_token();
    let mut si = LinuxSigInfo::default();
    si.si_signo = signum as i32;
    si.si_errno = 0;
    si.si_code = si_code;
    // siginfo_t kill/pid payload.
    si.field[0] = translate_sender_pid_for_receiver(sender_pid);
    si.field[1] = sender_uid as i32;
    si.field[2] = sig_value as i32;
    si.field[3] = (sig_value >> 32) as i32;
    try_write_user_value(token, info_ptr as *mut LinuxSigInfo, &si)
}

fn timespec_to_ms(ts: TimeSpec) -> Option<usize> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= 1_000_000_000 {
        return None;
    }
    let ms = (ts.sec as u64)
        .saturating_mul(1_000)
        .saturating_add((ts.nsec as u64) / 1_000_000);
    Some(ms.min(usize::MAX as u64) as usize)
}

fn has_zombie_child() -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    inner
        .children
        .iter()
        .any(|child| child.borrow_mut().is_zombie)
}

fn remove_waiter(task: &Arc<TaskControlBlock>) {
    let process = current_process();
    let mut inner = process.borrow_mut();
    inner.wait_queue.retain(|t| !Arc::ptr_eq(t, task));
}

fn take_pending_in_set(
    task: &Arc<TaskControlBlock>,
    wait_mask: u64,
) -> Option<(usize, i32, u32, i32, usize)> {
    let mut inner = task.borrow_mut();
    let pending = inner.pending_signals & wait_mask;
    if pending == 0 {
        return None;
    }
    let sig = pending.trailing_zeros() as usize + 1;
    if let Some(bit) = sig_bit(sig) {
        inner.pending_signals &= !bit;
        task.refresh_signal_pending(inner.pending_signals);
    }
    let mut sender_pid = 0;
    let mut sender_uid = 0;
    let mut si_code = 0;
    let mut sig_value = 0usize;
    if sig <= RT_SIG_MAX {
        sender_pid = inner.pending_signal_pid[sig];
        sender_uid = inner.pending_signal_uid[sig];
        si_code = inner.pending_signal_code[sig];
        sig_value = inner.pending_signal_value[sig];
        inner.pending_signal_pid[sig] = 0;
        inner.pending_signal_uid[sig] = 0;
        inner.pending_signal_code[sig] = 0;
        inner.pending_signal_value[sig] = 0;
    }
    Some((sig, sender_pid, sender_uid, si_code, sig_value))
}

fn has_nonwait_interrupt(task: &Arc<TaskControlBlock>, wait_mask: u64) -> bool {
    let (pending, mask) = {
        let inner = task.borrow_mut();
        (inner.pending_signals & !wait_mask, inner.signal_mask)
    };
    has_wait_interrupting_pending(pending, mask)
}

/// Linux `rt_sigtimedwait` (syscall 137).
pub fn syscall_rt_sigtimedwait(
    set: usize,
    info: usize,
    timeout: usize,
    sigsetsize: usize,
) -> isize {
    if set == 0 {
        return err(SyscallError::EFAULT);
    }
    if !valid_sigset_size(sigsetsize) {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let Some(mask) = try_read_user_value(token, set as *const u64) else {
        return err(SyscallError::EFAULT);
    };

    let sigchld_bit = sig_bit(SIGCHLD).unwrap();
    let task = current_task().unwrap();
    {
        let mut inner = task.borrow_mut();
        inner.sigwait_mask = Some(mask);
    }
    let clear_sigwait_mask = |task: &Arc<TaskControlBlock>| {
        task.borrow_mut().sigwait_mask = None;
    };

    let deadline_ms = if timeout != 0 {
        let Some(ts) = try_read_user_value(token, timeout as *const TimeSpec) else {
            clear_sigwait_mask(&task);
            return err(SyscallError::EFAULT);
        };
        let timeout_ms = match timespec_to_ms(ts) {
            Some(ms) => ms,
            None => {
                clear_sigwait_mask(&task);
                return err(SyscallError::EINVAL);
            }
        };
        Some(get_time_ms().saturating_add(timeout_ms))
    } else {
        None
    };

    let mut timer_set = false;
    loop {
        if let Some((sig, sender_pid, sender_uid, si_code, sig_value)) =
            take_pending_in_set(&task, mask)
        {
            if write_siginfo(info, sig, sender_pid, sender_uid, si_code, sig_value).is_err() {
                clear_sigwait_mask(&task);
                return err(SyscallError::EFAULT);
            }
            clear_sigwait_mask(&task);
            return sig as isize;
        }

        // SIGCHLD may be observed via waitable zombie state even before queueing.
        if (mask & sigchld_bit) != 0 && has_zombie_child() {
            if write_siginfo(info, SIGCHLD, 0, 0, 0, 0).is_err() {
                clear_sigwait_mask(&task);
                return err(SyscallError::EFAULT);
            }
            clear_sigwait_mask(&task);
            return SIGCHLD as isize;
        }

        // Non-target signals interrupt the wait.
        if has_nonwait_interrupt(&task, mask) {
            clear_sigwait_mask(&task);
            return err(SyscallError::EINTR);
        }

        if let Some(deadline_ms) = deadline_ms {
            if get_time_ms() >= deadline_ms {
                clear_sigwait_mask(&task);
                return err(SyscallError::EAGAIN);
            }
        }

        {
            let process = current_process();
            let mut inner = process.borrow_mut();
            inner.wait_queue.push_back(Arc::clone(&task));
        }
        if let Some(deadline_ms) = deadline_ms {
            if !timer_set {
                let now_ms = get_time_ms();
                let wait_ms = deadline_ms.saturating_sub(now_ms);
                if wait_ms == 0 {
                    remove_waiter(&task);
                    clear_sigwait_mask(&task);
                    return err(SyscallError::EAGAIN);
                }
                add_timer(Arc::clone(&task), wait_ms);
                timer_set = true;
            }
        }

        block_current_and_run_next();
        remove_waiter(&task);
    }
}
