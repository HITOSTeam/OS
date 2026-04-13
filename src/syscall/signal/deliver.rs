use super::*;

pub fn maybe_deliver_signal() {
    let Some(task) = current_task() else {
        return;
    };
    const MAX_SIGNAL_DEPTH: usize = 8;
    static SIGALRM_LOG_LEFT: AtomicUsize = AtomicUsize::new(16);
    let sigalrm_bit = signal_bit(SIGALRM_NUM).unwrap_or(0);
    let (signum, sender_pid, sender_uid, si_code, sig_value) = {
        let mut inner = task.borrow_mut();
        if inner.sig_saved_ctx.len() >= MAX_SIGNAL_DEPTH {
            // User handlers may escape via longjmp() instead of rt_sigreturn().
            // In that case kernel-saved signal frames become stale and can
            // accumulate until delivery is permanently blocked. Recover by
            // dropping stale frames and continuing normal delivery.
            inner.sig_saved_ctx.clear();
            inner.sigsuspend_old_mask = None;
        }
        if inner.sigwait_mask.is_some() {
            let pending = inner.pending_signals;
            let sigkill_bit = signal_bit(SIGKILL_NUM).unwrap_or(0);
            let sigstop_bit = signal_bit(SIGSTOP_NUM).unwrap_or(0);
            let sigcont_bit = signal_bit(SIGCONT_NUM).unwrap_or(0);
            if (pending & (sigkill_bit | sigstop_bit | sigcont_bit)) == 0 {
                return;
            }
        }
        let mask = inner.signal_mask;
        let pending = inner.pending_signals;
        let Some(sig) = take_first_unmasked(&mut inner.pending_signals, mask) else {
            if DEBUG_UNIXBENCH
                && sigalrm_bit != 0
                && (pending & sigalrm_bit) != 0
                && SIGALRM_LOG_LEFT.fetch_sub(1, Ordering::Relaxed) > 0
            {
                let pid = current_process().getpid();
                let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
                crate::log_if!(
                    DEBUG_UNIXBENCH,
                    debug,
                    "[signal] masked sig=14 pid={} tid={} pending={:#x} mask={:#x}",
                    pid,
                    tid,
                    pending,
                    mask
                );
            }
            return;
        };
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
        (sig, sender_pid, sender_uid, si_code, sig_value)
    };
    if DEBUG_UNIXBENCH && signum == 14 {
        let pid = current_process().getpid();
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        crate::log_if!(
            DEBUG_UNIXBENCH,
            debug,
            "[signal] deliver pid={} tid={} sig={}",
            pid,
            tid,
            signum
        );
    }
    if DEBUG_SIGNAL {
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
            "[signal] deliver pid={} tid={} sig={} now_ms={}",
            pid,
            tid,
            signum,
            get_time_ms()
        );
    }
    if DEBUG_PTHREAD {
        let mask = task.borrow_mut().signal_mask;
        crate::println!("[signal] deliver sig={} mask={:#x}", signum, mask);
    }
    if DEBUG_PTHREAD && signum == 33 {
        let token = get_current_token();
        let tp = task.borrow_mut().get_trap_cx().x[REG_TP];
        let cancel = try_read_user_value(token, tp.wrapping_sub(156) as *const i32);
        let canceldisable = try_read_user_value(token, tp.wrapping_sub(152) as *const u8);
        let cancelasync = try_read_user_value(token, tp.wrapping_sub(151) as *const u8);
        log::debug!(
            "[sigcancel] tp={:#x} cancel={:?} disable={:?} async={:?}",
            tp,
            cancel,
            canceldisable,
            cancelasync
        );
    }

    let action = {
        let process = current_process();
        let inner = process.borrow_mut();
        inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default()
    };
    let restore_sigsuspend_mask = |task: &Arc<TaskControlBlock>| {
        let mut inner = task.borrow_mut();
        if let Some(saved) = inner.sigsuspend_old_mask.take() {
            inner.signal_mask = saved;
        }
    };
    if DEBUG_PTHREAD {
        crate::println!(
            "[signal] action signo={} handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
            signum,
            action.handler,
            action.flags,
            action.restorer,
            action.mask
        );
    }
    if signum != SIGKILL_NUM {
        let trace_stop_tasks = {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if inner.ptrace_tracer_pid.is_some() {
                inner.stopped = true;
                inner.stop_signal = signum as i32;
                inner.stop_pending = true;
                inner.continued = false;
                Some(
                    inner
                        .tasks
                        .iter()
                        .filter_map(|t| t.as_ref().cloned())
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            }
        };
        if let Some(tasks) = trace_stop_tasks {
            for t in tasks {
                let mut t_inner = t.borrow_mut();
                if t_inner.task_status != TaskStatus::Blocked {
                    t_inner.task_status = TaskStatus::Blocked;
                    t_inner.stopped_by_signal = true;
                }
            }
            wake_parent_waiters();
            restore_sigsuspend_mask(&task);
            block_current_and_run_next();
            return;
        }
    }
    if signum == SIGCONT_NUM {
        let was_stopped = {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if inner.stopped {
                inner.stopped = false;
                inner.continued = true;
                inner.stop_pending = false;
                true
            } else {
                false
            }
        };
        if was_stopped {
            let tasks = {
                let process = current_process();
                let inner = process.borrow_mut();
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for t in tasks {
                let mut t_inner = t.borrow_mut();
                if !t_inner.stopped_by_signal {
                    continue;
                }
                t_inner.stopped_by_signal = false;
                drop(t_inner);
                wakeup_task(t);
            }
            wake_parent_waiters();
        }
        if action.handler == SIG_IGN || action.handler == SIG_DFL {
            restore_sigsuspend_mask(&task);
            return;
        }
    }
    if is_stop_signal(signum) {
        if signum != SIGSTOP_NUM && action.handler == SIG_IGN {
            restore_sigsuspend_mask(&task);
            return;
        }
        if action.handler == SIG_DFL || signum == SIGSTOP_NUM {
            let tasks = {
                let process = current_process();
                let mut inner = process.borrow_mut();
                if !inner.stopped {
                    inner.stopped = true;
                    inner.stop_signal = signum as i32;
                    inner.stop_pending = true;
                    inner.continued = false;
                }
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for t in tasks {
                let mut t_inner = t.borrow_mut();
                if t_inner.task_status != TaskStatus::Blocked {
                    t_inner.task_status = TaskStatus::Blocked;
                    t_inner.stopped_by_signal = true;
                }
            }
            wake_parent_waiters();
            restore_sigsuspend_mask(&task);
            block_current_and_run_next();
            return;
        }
    }
    if action.handler == SIG_IGN {
        restore_sigsuspend_mask(&task);
        return;
    }
    if action.handler == SIG_DFL {
        if signum <= crate::task::signal::MAX_SIG {
            if let Some(flag) = SignalFlags::from_bits(1u32 << signum) {
                if let Some((errno, msg)) = flag.check_error() {
                    let _ = kill_current(signum as i32);
                    crate::println!("[kernel] {}", msg);
                    exit_group_and_run_next(errno);
                }
            }
        }
        restore_sigsuspend_mask(&task);
        return;
    }

    let mut inner = task.borrow_mut();
    let cx = inner.get_trap_cx();
    let cur_mask = inner.signal_mask;
    let saved_mask = inner.sigsuspend_old_mask.take().unwrap_or(cur_mask);
    let was_on_sigaltstack = inner.on_sigaltstack;
    let mut saved_trap = *cx;
    let restart_syscall = saved_trap.x[REG_A0] == ERESTARTSYS as usize;
    if restart_syscall && inner.last_syscall_valid {
        saved_trap.sepc = saved_trap.sepc.wrapping_sub(4);
        saved_trap.x[REG_A0] = inner.last_syscall_args[0];
        saved_trap.x[REG_A1] = inner.last_syscall_args[1];
        saved_trap.x[REG_A2] = inner.last_syscall_args[2];
        saved_trap.x[REG_A3] = inner.last_syscall_args[3];
        saved_trap.x[REG_A4] = inner.last_syscall_args[4];
        saved_trap.x[REG_A5] = inner.last_syscall_args[5];
        saved_trap.x[REG_A7] = inner.last_syscall_id;
    }
    // Fault signals are often handled with non-local control flow (e.g. longjmp),
    // which bypasses rt_sigreturn(). Keep only one saved context slot here to
    // avoid unbounded stale-frame accumulation.
    if signum == 11 || signum == 7 {
        inner.sig_saved_ctx.clear();
    }
    inner.sig_saved_ctx.push(SigSavedContext {
        trap_cx: saved_trap,
        mask: saved_mask,
        ucontext_ptr: 0,
        uses_ucontext: false,
        signum,
        was_on_sigaltstack,
    });

    let mut new_mask = cur_mask | action.mask;
    if (action.flags & SA_NODEFER) == 0 {
        if let Some(bit) = sig_bit(signum) {
            new_mask |= bit;
        }
    }
    inner.signal_mask = new_mask;

    let mut user_sp = cx.x[REG_SP];
    if (action.flags & SA_ONSTACK) != 0
        && inner.sigaltstack_enabled
        && !inner.on_sigaltstack
        && inner.sigaltstack_size > 0
    {
        user_sp = inner.sigaltstack_sp.saturating_add(inner.sigaltstack_size);
        inner.on_sigaltstack = true;
    }
    let mut siginfo_ptr = 0usize;
    let mut ucontext_ptr = 0usize;
    if (action.flags & SA_SIGINFO) != 0 {
        user_sp = (user_sp.saturating_sub(15)) & !0x0f;
        user_sp = user_sp.saturating_sub(core::mem::size_of::<LinuxSigInfo>());
        siginfo_ptr = user_sp;

        user_sp = (user_sp.saturating_sub(15)) & !0x0f;
        user_sp = user_sp.saturating_sub(core::mem::size_of::<UContext>());
        ucontext_ptr = user_sp;

        let mut siginfo = LinuxSigInfo::default();
        siginfo.si_signo = signum as i32;
        siginfo.si_code = si_code;
        siginfo.field[0] = translate_sender_pid_for_receiver(sender_pid);
        siginfo.field[1] = sender_uid as i32;
        siginfo.field[2] = sig_value as i32;
        siginfo.field[3] = (sig_value >> 32) as i32;

        let sig_context = SigContext {
            regs: UserRegsStruct::from_trap(&saved_trap),
            ..Default::default()
        };
        let uc_stack = SigStack {
            ss_sp: inner.sigaltstack_sp,
            ss_flags: if !inner.sigaltstack_enabled {
                SS_DISABLE
            } else if was_on_sigaltstack {
                SS_ONSTACK
            } else {
                0
            },
            _pad: 0,
            ss_size: inner.sigaltstack_size,
        };
        let ucontext = UContext {
            uc_flags: 0,
            uc_link: 0,
            uc_stack,
            uc_sigmask: saved_mask,
            uc_mcontext: sig_context,
            ..Default::default()
        };

        let token = get_current_token();
        write_user_value(token, siginfo_ptr as *mut LinuxSigInfo, &siginfo);
        write_user_value(token, ucontext_ptr as *mut UContext, &ucontext);
        if let Some(saved) = inner.sig_saved_ctx.last_mut() {
            saved.ucontext_ptr = ucontext_ptr;
            saved.uses_ucontext = true;
        }

        cx.x[REG_A1] = siginfo_ptr;
        cx.x[REG_A2] = ucontext_ptr;
        if DEBUG_PTHREAD && signum == 33 {
            log::debug!(
                "[sigcancel] frame sp={:#x} siginfo={:#x} ucontext={:#x}",
                user_sp,
                siginfo_ptr,
                ucontext_ptr
            );
        }
    } else {
        cx.x[REG_A1] = 0;
        cx.x[REG_A2] = 0;
    }

    cx.x[REG_SP] = user_sp;
    cx.sepc = action.handler;
    cx.x[REG_A0] = signum;
    // Always use the kernel-provided rt_sigreturn trampoline to avoid invalid
    // user restorer pointers causing instruction page faults.
    cx.x[REG_RA] = sigreturn_trampoline_va();
}

pub fn try_sigreturn_from_fault() -> bool {
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    let Some(saved) = inner.sig_saved_ctx.pop() else {
        return false;
    };
    *inner.get_trap_cx() = saved.trap_cx;
    inner.signal_mask = saved.mask;
    inner.on_sigaltstack = saved.was_on_sigaltstack;
    true
}
