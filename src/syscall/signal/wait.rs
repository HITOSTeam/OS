use super::*;

#[cfg(target_arch = "loongarch64")]
fn loongarch_bad_sigreturn(task: &Arc<TaskControlBlock>) -> isize {
    const SIGSEGV: usize = 11;
    const SI_KERNEL: i32 = 0x80;

    // A malformed user frame is not allowed to strand us at the sigreturn
    // trampoline or on its bad stack. Recover the kernel-side snapshot solely
    // as a safe delivery base, then force SIGSEGV just as Linux's badframe path
    // does. The user frame remains authoritative on every successful return.
    let (restored_fp, force_default) = {
        let mut inner = task.borrow_mut();
        match inner.sig_saved_ctx.pop() {
            Some(saved) => {
                let segv_bit = signal_bit(SIGSEGV).unwrap_or(0);
                let segv_was_blocked = (inner.signal_mask & segv_bit) != 0;
                let segv_already_active = saved.signum == SIGSEGV
                    || inner
                        .sig_saved_ctx
                        .iter()
                        .any(|context| context.signum == SIGSEGV);
                *inner.get_trap_cx() = saved.trap_cx;
                inner.signal_mask = saved.mask;
                inner.on_sigaltstack = saved.was_on_sigaltstack;
                inner.loongarch_fp = saved.loongarch_fp;
                // If a SIGSEGV handler is already active, another user-handler
                // delivery would recurse forever. Linux also resets a forced
                // signal to SIG_DFL when user space had it blocked.
                (true, segv_already_active || segv_was_blocked)
            }
            None => (false, true),
        }
    };

    if restored_fp {
        crate::arch::restore_user_fp_state(task);
    }
    if force_default {
        let process = current_process();
        let mut process_inner = process.borrow_mut();
        if let Some(action) = process_inner.rt_sig_handlers.get_mut(SIGSEGV) {
            *action = RtSigAction::default();
        }
        process_inner.signals_actions.table[SIGSEGV] = SignalAction::default();
    }

    // Linux's force_sig(SIGSEGV) uses kernel-origin siginfo rather than
    // pretending the malformed frame was a new hardware page fault.
    crate::task::signal::force_current_fault_signal(SIGSEGV, SI_KERNEL, 0);
    0
}

#[cfg(target_arch = "loongarch64")]
fn read_loongarch_signal_fp_state(
    token: usize,
    mut info_ptr: usize,
    flags: u32,
) -> Option<crate::task::task_block::LoongArchFpState> {
    use crate::task::task_block::LoongArchFpState;

    let mut state: Option<LoongArchFpState> = None;
    for _ in 0..8 {
        let info = try_read_user_value(token, info_ptr as *const LoongArchSctxInfo)?;
        if info.magic == 0 {
            if info.size != 0 {
                return None;
            }
            return match ((flags & LOONGARCH_SC_USED_FP) != 0, state) {
                (false, None) => Some(LoongArchFpState::new()),
                (true, Some(state)) => Some(state),
                _ => None,
            };
        }

        let size = info.size as usize;
        if size < core::mem::size_of::<LoongArchSctxInfo>() || size & 0x0f != 0 {
            return None;
        }
        let payload_ptr = info_ptr.checked_add(core::mem::size_of::<LoongArchSctxInfo>())?;
        let restored = match info.magic {
            LOONGARCH_FPU_CTX_MAGIC => {
                if size
                    < core::mem::size_of::<LoongArchSctxInfo>()
                        + core::mem::size_of::<LoongArchFpuContext>()
                {
                    return None;
                }
                try_read_user_value(token, payload_ptr as *const LoongArchFpuContext)?.into_state()
            }
            LOONGARCH_LSX_CTX_MAGIC => {
                if size
                    < core::mem::size_of::<LoongArchSctxInfo>()
                        + core::mem::size_of::<LoongArchLsxContext>()
                {
                    return None;
                }
                try_read_user_value(token, payload_ptr as *const LoongArchLsxContext)?.into_state()
            }
            _ => return None,
        };
        if state.replace(restored).is_some() {
            return None;
        }
        info_ptr = info_ptr.checked_add(size)?;
    }
    None
}

/// Linux LoongArch `rt_sigreturn`: the user rt_sigframe is authoritative.
/// This is required for fork-from-handler and for handlers that intentionally
/// edit GPR/FP/LSX state in their ucontext.
#[cfg(target_arch = "loongarch64")]
pub fn syscall_rt_sigreturn() -> isize {
    let task = current_task().unwrap();
    let token = get_current_token();
    let frame_ptr = task.borrow_mut().get_trap_cx().x[REG_SP];
    if frame_ptr & 0x0f != 0 {
        return loongarch_bad_sigreturn(&task);
    }
    let Some(frame) = try_read_user_value(token, frame_ptr as *const LoongArchRtSigFrame) else {
        return loongarch_bad_sigreturn(&task);
    };
    let Some(extcontext_ptr) = frame_ptr.checked_add(core::mem::size_of::<LoongArchRtSigFrame>())
    else {
        return loongarch_bad_sigreturn(&task);
    };
    let Some(mut fp_state) =
        read_loongarch_signal_fp_state(token, extcontext_ptr, frame.rs_uctx.uc_mcontext.sc_flags)
    else {
        return loongarch_bad_sigreturn(&task);
    };
    fp_state.hardware_live = false;
    let pending_fpe = crate::arch::sanitize_user_fcsr(&mut fp_state.fcsr);
    let restored_pc = frame.rs_uctx.uc_mcontext.sc_pc as usize;

    let result = {
        let mut inner = task.borrow_mut();
        let mut restored = *inner.get_trap_cx();
        frame.rs_uctx.uc_mcontext.write_to_trap(&mut restored);
        *inner.get_trap_cx() = restored;
        inner.signal_mask = frame.rs_uctx.uc_sigmask;
        inner.loongarch_fp = fp_state;

        let stack = frame.rs_uctx.uc_stack;
        if stack.ss_flags & SS_DISABLE != 0 {
            inner.sigaltstack_sp = 0;
            inner.sigaltstack_size = 0;
            inner.sigaltstack_enabled = false;
            inner.on_sigaltstack = false;
        } else {
            inner.sigaltstack_sp = stack.ss_sp;
            inner.sigaltstack_size = stack.ss_size;
            inner.sigaltstack_enabled = true;
            inner.on_sigaltstack = stack.ss_flags & SS_ONSTACK != 0;
        }
        // Keep the private stack only as a fallback for legacy fault-return;
        // normal LoongArch sigreturn never depends on it.
        let _ = inner.sig_saved_ctx.pop();
        restored.x[REG_A0] as isize
    };
    crate::arch::restore_user_fp_state(&task);
    if let Some(si_code) = pending_fpe {
        crate::task::signal::force_current_fault_signal(8, si_code, restored_pc);
    }
    result
}

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
#[cfg(target_arch = "riscv64")]
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
            #[cfg(target_arch = "loongarch64")]
            {
                inner.loongarch_fp = saved.loongarch_fp;
            }
            return restored.x[REG_A0] as isize;
        }
    }
    *inner.get_trap_cx() = saved.trap_cx;
    inner.signal_mask = saved.mask;
    inner.on_sigaltstack = saved.was_on_sigaltstack;
    #[cfg(target_arch = "loongarch64")]
    {
        inner.loongarch_fp = saved.loongarch_fp;
    }
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
