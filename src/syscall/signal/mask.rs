use super::*;

fn rt_sigmask_to_legacy_flags(mask: u64) -> SignalFlags {
    // rt sigset uses bit (signum - 1); the legacy SignalFlags table uses
    // bit signum with bit 0 reserved for SIGDEF.
    let legacy_bits = ((mask & ((1u64 << crate::task::signal::MAX_SIG) - 1)) << 1) as u32;
    SignalFlags::from_bits_truncate(legacy_bits)
}

#[allow(dead_code)]
pub fn syscall_sigaction(
    signum: i32,
    action: *const SignalAction,
    old_action: *mut SignalAction,
) -> isize {
    if DEBUG_UNIXBENCH && signum == SIGALRM_NUM as i32 {
        let token = get_current_token();
        let act = if action == core::ptr::null() {
            SignalAction::default()
        } else {
            read_user_value(token, action)
        };
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[signal] sigaction(legacy) sig=14 handler={:#x} mask={:#x}",
            act.handler,
            act.mask.bits()
        );
    }
    set_signal(signum, action, old_action)
}
#[allow(dead_code)]
pub fn syscall_sigprocmask(how: u32) -> isize {
    set_signal_mask(how)
}

/// Linux `rt_sigaction` (syscall 134).
pub fn syscall_rt_sigaction(signum: usize, act: usize, oldact: usize, sigsetsize: usize) -> isize {
    if signum == 0 || signum > RT_SIG_MAX {
        return err(SyscallError::EINVAL);
    }
    if !valid_sigset_size(sigsetsize) {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let new_action = if act != 0 {
        if signum == crate::task::signal::SIGKILL_NUM || signum == crate::task::signal::SIGSTOP_NUM
        {
            return err(SyscallError::EINVAL);
        }
        let Some(new_action) = try_read_user_value(token, act as *const RtSigAction) else {
            return err(SyscallError::EFAULT);
        };
        if DEBUG_UNIXBENCH && signum == 14 {
            crate::log_if!(
                DEBUG_UNIXBENCH,
                info,
                "[signal] sigaction sig={} handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
                signum,
                new_action.handler,
                new_action.flags,
                new_action.restorer,
                new_action.mask
            );
        }
        if DEBUG_PTHREAD {
            crate::println!(
                "[rt_sigaction] signo={} handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
                signum,
                new_action.handler,
                new_action.flags,
                new_action.restorer,
                new_action.mask
            );
        }
        Some(new_action)
    } else {
        None
    };

    let old_action = {
        let process = current_process();
        let mut inner = process.borrow_mut();
        let old_action = if oldact != 0 {
            Some(
                inner
                    .rt_sig_handlers
                    .get(signum)
                    .copied()
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        if let Some(new_action) = new_action {
            if signum < inner.rt_sig_handlers.len() {
                inner.rt_sig_handlers[signum] = new_action;
            }
            if signum <= crate::task::signal::MAX_SIG {
                inner.signals_actions.table[signum] = SignalAction {
                    handler: new_action.handler,
                    mask: rt_sigmask_to_legacy_flags(new_action.mask),
                };
            }
        }
        old_action
    };
    if let Some(old_action) = old_action {
        if try_write_user_value(token, oldact as *mut RtSigAction, &old_action).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    0
}

/// Linux `rt_sigprocmask` (syscall 135).
pub fn syscall_rt_sigprocmask(how: usize, set: usize, oldset: usize, sigsetsize: usize) -> isize {
    if !valid_sigset_size(sigsetsize) {
        return err(SyscallError::EINVAL);
    }
    let token = get_current_token();
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    let old_mask = inner.signal_mask;
    let new_mask = if set != 0 {
        // Read new mask before writing oldset to support aliasing set/oldset.
        let Some(v) = try_read_user_value(token, set as *const u64) else {
            return err(SyscallError::EFAULT);
        };
        v
    } else {
        old_mask
    };
    if set != 0 {
        if DEBUG_PTHREAD {
            crate::println!(
                "[rt_sigprocmask] how={} new_mask={:#x} old_mask={:#x}",
                how,
                new_mask,
                inner.signal_mask
            );
        }
        let sigalrm_bit = signal_bit(SIGALRM_NUM).unwrap_or(0);
        let sigkill_bit = signal_bit(crate::task::signal::SIGKILL_NUM).unwrap_or(0);
        let sigstop_bit = signal_bit(crate::task::signal::SIGSTOP_NUM).unwrap_or(0);
        let mut updated = match how {
            0 => old_mask | new_mask,  // SIG_BLOCK
            1 => old_mask & !new_mask, // SIG_UNBLOCK
            2 => new_mask,             // SIG_SETMASK
            _ => return err(SyscallError::EINVAL),
        };
        updated &= !(sigkill_bit | sigstop_bit);
        inner.signal_mask = updated;
        if DEBUG_UNIXBENCH && sigalrm_bit != 0 && ((old_mask ^ updated) & sigalrm_bit) != 0 {
            let pid = current_process().getpid();
            let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
            crate::log_if!(
                DEBUG_UNIXBENCH,
                info,
                "[signal] sigmask pid={} tid={} how={} setsize={} old={:#x} new={:#x}",
                pid,
                tid,
                how,
                sigsetsize,
                old_mask,
                updated
            );
        }
    }
    if oldset != 0 {
        if try_write_user_value(token, oldset as *mut u64, &old_mask).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    0
}

/// Linux `sigaltstack` (syscall 132).
pub fn syscall_sigaltstack(ss: usize, old_ss: usize) -> isize {
    let token = get_current_token();
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();

    if old_ss != 0 {
        let flags = if !inner.sigaltstack_enabled {
            SS_DISABLE
        } else if inner.on_sigaltstack {
            SS_ONSTACK
        } else {
            0
        };
        let old = SigStack {
            ss_sp: inner.sigaltstack_sp,
            ss_flags: flags,
            _pad: 0,
            ss_size: inner.sigaltstack_size,
        };
        if try_write_user_value(token, old_ss as *mut SigStack, &old).is_err() {
            return err(SyscallError::EFAULT);
        }
    }

    if ss == 0 {
        return 0;
    }
    if inner.on_sigaltstack {
        return err(SyscallError::EPERM);
    }
    let Some(new_ss) = try_read_user_value(token, ss as *const SigStack) else {
        return err(SyscallError::EFAULT);
    };
    if (new_ss.ss_flags & !(SS_DISABLE)) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (new_ss.ss_flags & SS_DISABLE) != 0 {
        inner.sigaltstack_enabled = false;
        inner.sigaltstack_sp = 0;
        inner.sigaltstack_size = 0;
        return 0;
    }
    if new_ss.ss_sp == 0 {
        return err(SyscallError::EINVAL);
    }
    if new_ss.ss_size < MINSIGSTKSZ {
        return err(SyscallError::ENOMEM);
    }
    inner.sigaltstack_enabled = true;
    inner.sigaltstack_sp = new_ss.ss_sp;
    inner.sigaltstack_size = new_ss.ss_size;
    0
}

/// Linux `rt_sigpending` (syscall 136).
pub fn syscall_rt_sigpending(set: usize, sigsetsize: usize) -> isize {
    if set == 0 {
        return err(SyscallError::EFAULT);
    }
    if !valid_sigset_size(sigsetsize) {
        return err(SyscallError::EINVAL);
    }
    let pending = {
        let task = current_task().unwrap();
        let inner = task.borrow_mut();
        inner.pending_signals
    };
    let token = get_current_token();
    if try_write_user_value(token, set as *mut u64, &pending).is_err() {
        return err(SyscallError::EFAULT);
    }
    // User sigset_t may be larger than 8 bytes; zero trailing bytes.
    if sigsetsize > core::mem::size_of::<u64>() {
        let zero: u8 = 0;
        for off in core::mem::size_of::<u64>()..sigsetsize {
            if try_write_user_value(token, (set + off) as *mut u8, &zero).is_err() {
                return err(SyscallError::EFAULT);
            }
        }
    }
    0
}
