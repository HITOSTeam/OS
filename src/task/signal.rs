pub const MAX_SIG: usize = 31;
pub const RT_SIG_MAX: usize = 64;
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
pub const SIGPIPE_NUM: usize = 13;
pub const SIGALRM_NUM: usize = 14;
pub const SIGCHLD_NUM: usize = 17;
pub const SIGCONT_NUM: usize = 18;
pub const SIGKILL_NUM: usize = 9;
pub const SIGSTOP_NUM: usize = 19;
pub const SIGXCPU_NUM: usize = 24;
pub const SIGXFSZ_NUM: usize = 25;
pub const SIGTSTP_NUM: usize = 20;
pub const SIGTTIN_NUM: usize = 21;
pub const SIGTTOU_NUM: usize = 22;
use bitflags::bitflags;

use alloc::sync::Arc;
use alloc::vec;

use crate::{
    arch,
    debug_config::{DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    mm::{read_user_value, translated_single_address, write_user_value},
    println,
    task::processor::current_process,
    task::{
        manager::{pid2process, wakeup_task},
        pid_namespace_member_pids, process_visible_in_pid_namespace, resolve_process_in_pid_namespace,
        process_block::ProcessControlBlock,
        processor::{current_task, suspend_current_and_run_next},
        task_block::{TaskControlBlock, TaskControlBlockInner},
    },
    time::get_time_ms,
    trap::{context::TrapContext, get_current_token},
};

pub fn signal_bit(signum: usize) -> Option<u64> {
    if signum == 0 || signum > RT_SIG_MAX {
        return None;
    }
    Some(1u64 << (signum - 1))
}

fn current_sender_ids() -> (i32, u32, u32, usize) {
    let proc = current_process();
    let pid = proc.getpid() as i32;
    let (uid, euid, sid) = {
        let inner = proc.borrow_mut();
        (inner.uid, inner.euid, inner.sid)
    };
    (pid, uid, euid, sid)
}

fn can_send_signal(
    sender_uid: u32,
    sender_euid: u32,
    sender_sid: usize,
    target_uid: u32,
    target_euid: u32,
    target_suid: u32,
    target_sid: usize,
    signum: i32,
) -> bool {
    if sender_euid == 0 {
        return true;
    }
    if sender_uid == target_uid
        || sender_uid == target_euid
        || sender_uid == target_suid
        || sender_euid == target_uid
        || sender_euid == target_euid
        || sender_euid == target_suid
    {
        return true;
    }
    signum as usize == SIGCONT_NUM && sender_sid != 0 && sender_sid == target_sid
}

pub fn can_signal_process(process: &Arc<ProcessControlBlock>, signum: i32) -> bool {
    let (_, sender_uid, sender_euid, sender_sid) = current_sender_ids();
    let (target_uid, target_euid, target_suid, target_sid) = {
        let inner = process.borrow_mut();
        (inner.uid, inner.euid, inner.suid, inner.sid)
    };
    can_send_signal(
        sender_uid,
        sender_euid,
        sender_sid,
        target_uid,
        target_euid,
        target_suid,
        target_sid,
        signum,
    )
}

fn mark_pending_signal(
    inner: &mut TaskControlBlockInner,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
    si_code: i32,
    sig_value: usize,
) {
    let Some(bit) = signal_bit(signum) else {
        return;
    };
    inner.pending_signals |= bit;
    if signum <= RT_SIG_MAX {
        inner.pending_signal_pid[signum] = sender_pid;
        inner.pending_signal_uid[signum] = sender_uid;
        inner.pending_signal_code[signum] = si_code;
        inner.pending_signal_value[signum] = sig_value;
    }
}

pub fn pending_unmasked_bits(pending: u64, mask: u64, ignore_sigchld: bool) -> u64 {
    let mut ready = pending & !mask;
    let sigkill_bit = 1u64 << (SIGKILL_NUM - 1);
    let sigstop_bit = 1u64 << (SIGSTOP_NUM - 1);
    ready |= pending & (sigkill_bit | sigstop_bit);
    if ignore_sigchld {
        if let Some(bit) = signal_bit(SIGCHLD_NUM) {
            ready &= !bit;
        }
    }
    ready
}

pub fn pick_task_for_signal(
    tasks: &[Arc<TaskControlBlock>],
    bit: u64,
) -> Option<Arc<TaskControlBlock>> {
    if bit == 0 {
        return None;
    }
    let mut unmasked: Option<Arc<TaskControlBlock>> = None;
    let mut fallback: Option<Arc<TaskControlBlock>> = None;
    for task in tasks.iter() {
        let inner = task.borrow_mut();
        if inner.res.is_none() {
            continue;
        }
        let pending = (inner.pending_signals & bit) != 0;
        let blocked = (inner.signal_mask & bit) != 0;
        let handling = !inner.sig_saved_ctx.is_empty();
        drop(inner);
        if !blocked && !pending && !handling {
            return Some(task.clone());
        }
        if !blocked && unmasked.is_none() {
            unmasked = Some(task.clone());
        }
        if fallback.is_none() {
            fallback = Some(task.clone());
        }
    }
    unmasked.or(fallback)
}

pub fn has_unmasked_pending(pending: u64, mask: u64, ignore_sigchld: bool) -> bool {
    pending_unmasked_bits(pending, mask, ignore_sigchld) != 0
}

pub fn take_first_unmasked(pending: &mut u64, mask: u64) -> Option<usize> {
    let ready = pending_unmasked_bits(*pending, mask, false);
    if ready == 0 {
        return None;
    }
    let signum = ready.trailing_zeros() as usize + 1;
    if let Some(bit) = signal_bit(signum) {
        *pending &= !bit;
    }
    Some(signum)
}

bitflags! {
    pub struct SignalFlags: u32 {
        const SIGDEF = 1; // Default signal handling
        const SIGHUP = 1 << 1;
        const SIGINT = 1 << 2;
        const SIGQUIT = 1 << 3;
        const SIGILL = 1 << 4;
        const SIGTRAP = 1 << 5;
        const SIGABRT = 1 << 6;
        const SIGBUS = 1 << 7;
        const SIGFPE = 1 << 8;
        const SIGKILL = 1 << 9;
        const SIGUSR1 = 1 << 10;
        const SIGSEGV = 1 << 11;
        const SIGUSR2 = 1 << 12;
        const SIGPIPE = 1 << 13;
        const SIGALRM = 1 << 14;
        const SIGTERM = 1 << 15;
        const SIGSTKFLT = 1 << 16;
        const SIGCHLD = 1 << 17;
        const SIGCONT = 1 << 18;
        const SIGSTOP = 1 << 19;
        const SIGTSTP = 1 << 20;
        const SIGTTIN = 1 << 21;
        const SIGTTOU = 1 << 22;
        const SIGURG = 1 << 23;
        const SIGXCPU = 1 << 24;
        const SIGXFSZ = 1 << 25;
        const SIGVTALRM = 1 << 26;
        const SIGPROF = 1 << 27;
        const SIGWINCH = 1 << 28;
        const SIGIO = 1 << 29;
        const SIGPWR = 1 << 30;
        const SIGSYS = 1 << 31;
    }
}
impl SignalFlags {
    pub fn check_error(&self) -> Option<(i32, &'static str)> {
        // Linux default actions: terminate (with/without core) for these signals.
        if self.contains(Self::SIGHUP) {
            Some((-1, "Hangup, SIGHUP=1"))
        } else if self.contains(Self::SIGINT) {
            Some((-2, "Killed, SIGINT=2"))
        } else if self.contains(Self::SIGQUIT) {
            Some((-3, "Quit, SIGQUIT=3"))
        } else if self.contains(Self::SIGILL) {
            Some((-4, "Illegal Instruction, SIGILL=4"))
        } else if self.contains(Self::SIGTRAP) {
            Some((-5, "Trace/breakpoint trap, SIGTRAP=5"))
        } else if self.contains(Self::SIGABRT) {
            Some((-6, "Aborted, SIGABRT=6"))
        } else if self.contains(Self::SIGBUS) {
            Some((-7, "Bus error, SIGBUS=7"))
        } else if self.contains(Self::SIGFPE) {
            Some((-8, "Erroneous Arithmetic Operation, SIGFPE=8"))
        } else if self.contains(Self::SIGKILL) {
            Some((-9, "Killed, SIGKILL=9"))
        } else if self.contains(Self::SIGUSR1) {
            Some((-10, "User-defined signal 1, SIGUSR1=10"))
        } else if self.contains(Self::SIGSEGV) {
            Some((-11, "Segmentation Fault, SIGSEGV=11"))
        } else if self.contains(Self::SIGUSR2) {
            Some((-12, "User-defined signal 2, SIGUSR2=12"))
        } else if self.contains(Self::SIGPIPE) {
            Some((-13, "Broken pipe, SIGPIPE=13"))
        } else if self.contains(Self::SIGALRM) {
            Some((-14, "Alarm clock, SIGALRM=14"))
        } else if self.contains(Self::SIGTERM) {
            Some((-15, "Terminated, SIGTERM=15"))
        } else if self.contains(Self::SIGSTKFLT) {
            Some((-16, "Stack fault, SIGSTKFLT=16"))
        } else if self.contains(Self::SIGXCPU) {
            Some((-24, "CPU time limit exceeded, SIGXCPU=24"))
        } else if self.contains(Self::SIGXFSZ) {
            Some((-25, "File size limit exceeded, SIGXFSZ=25"))
        } else if self.contains(Self::SIGVTALRM) {
            Some((-26, "Virtual alarm clock, SIGVTALRM=26"))
        } else if self.contains(Self::SIGPROF) {
            Some((-27, "Profiling timer expired, SIGPROF=27"))
        } else if self.contains(Self::SIGIO) {
            Some((-29, "I/O possible, SIGIO/SIGPOLL=29"))
        } else if self.contains(Self::SIGPWR) {
            Some((-30, "Power failure, SIGPWR=30"))
        } else if self.contains(Self::SIGSYS) {
            Some((-31, "Bad system call, SIGSYS=31"))
        } else {
            //println!("[K] signalflags check_error  {:?}", self);
            None
        }
    }
}
pub fn check_if_current_signals_error() -> Option<(i32, &'static str)> {
    let Some(task) = current_task() else {
        return None;
    };
    let (pending, mask) = {
        let inner = task.borrow_mut();
        (inner.pending_signals, inner.signal_mask)
    };
    let mut ready = pending_unmasked_bits(pending, mask, false);
    if ready == 0 {
        return None;
    }
    while ready != 0 {
        let signum = ready.trailing_zeros() as usize + 1;
        ready &= ready - 1;
        let Some(bit) = signal_bit(signum) else {
            continue;
        };
        let (handler, traced) = {
            let process = current_process();
            let inner = process.borrow_mut();
            let handler = if signum <= MAX_SIG {
                let legacy = inner.signals_actions.table[signum].handler;
                if legacy != 0 {
                    legacy
                } else {
                    inner
                        .rt_sig_handlers
                        .get(signum)
                        .map(|a| a.handler)
                        .unwrap_or(SIG_DFL)
                }
            } else {
                inner
                    .rt_sig_handlers
                    .get(signum)
                    .map(|a| a.handler)
                    .unwrap_or(SIG_DFL)
            };
            (handler, inner.ptrace_tracer_pid.is_some())
        };
        // Traced tasks should be intercepted in ptrace-stop first (except SIGKILL),
        // so don't short-circuit to default fatal handling here.
        if traced && signum != SIGKILL_NUM {
            continue;
        }
        if handler == SIG_IGN {
            // Ignored signals are discarded.
            let mut inner = task.borrow_mut();
            inner.pending_signals &= !bit;
            continue;
        }
        if handler != SIG_DFL {
            // User handler present: let normal delivery handle it.
            continue;
        }
        if signum <= MAX_SIG {
            if let Some(flag) = SignalFlags::from_bits(1u32 << signum) {
                if let Some((errno, msg)) = flag.check_error() {
                    return Some((errno, msg));
                }
            }
        }
    }
    None
}
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct SignalAction {
    pub handler: usize,
    pub mask: SignalFlags,
}
impl Default for SignalAction {
    fn default() -> Self {
        SignalAction {
            handler: 0,
            mask: SignalFlags { bits: 0 },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtSigAction {
    pub handler: usize,
    pub flags: usize,
    pub restorer: usize,
    pub mask: u64,
}

pub struct SignalActions {
    pub table: [SignalAction; MAX_SIG + 1],
    // pub table: i32,
}
impl Default for SignalActions {
    fn default() -> Self {
        // SignalActions { table: 0 }
        SignalActions {
            table: [SignalAction {
                handler: 0,
                mask: SignalFlags { bits: 0 },
            }; MAX_SIG + 1],
        }
    }
}

// set the signal mask, return the old mask
pub fn set_signal_mask(mask: u32) -> isize {
    let cur_process = current_process();
    let mut inner = cur_process.borrow_mut();
    let old_mask = inner.signals;
    if let Some(flag) = SignalFlags::from_bits(mask) {
        inner.signals = flag;
        old_mask.bits() as isize
    } else {
        -1
    }
}

// check if the signal num is valid (and action)
fn check_sigaction_error(signal: SignalFlags, action: usize, old_action: usize) -> bool {
    if action == 0
        || old_action == 0
        || signal == SignalFlags::SIGKILL
        || signal == SignalFlags::SIGSTOP
    {
        true
    } else {
        false
    }
}

pub fn set_signal(
    signum: i32,
    action: *const SignalAction,
    old_action: *mut SignalAction,
) -> isize {
    let token = get_current_token();
    let process = current_process();
    let mut inner = process.borrow_mut();
    if signum <= 0 || signum as usize > RT_SIG_MAX {
        return -1;
    }
    let signum = signum as usize;
    if action.is_null() || old_action.is_null() || signum == SIGKILL_NUM || signum == SIGSTOP_NUM {
        -1
    } else {
        let prev_rt = inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default();
        let prev_action = if signum <= MAX_SIG {
            inner.signals_actions.table[signum]
        } else {
            SignalAction {
                handler: prev_rt.handler,
                mask: SignalFlags::from_bits_truncate(prev_rt.mask as u32),
            }
        };
        write_user_value(token, old_action, &prev_action);

        let new_action = read_user_value(token, action as *const SignalAction);
        if signum <= MAX_SIG {
            if let Some(flag) = SignalFlags::from_bits(1u32 << signum) {
                if check_sigaction_error(flag, action as usize, old_action as usize) {
                    return -1;
                }
            }
            inner.signals_actions.table[signum] = new_action;
        }
        // Keep rt_sigaction table in sync so delivery uses the latest handler.
        if signum < inner.rt_sig_handlers.len() {
            inner.rt_sig_handlers[signum] = RtSigAction {
                handler: new_action.handler,
                flags: 0,
                restorer: 0,
                mask: new_action.mask.bits() as u64,
            };
        }
        0
    }
}

// insert the bit flag.. if already set  return -1
pub fn kill(pid: usize, signum: i32) -> isize {
    let current = current_process();
    if signum < 0 || signum as usize > RT_SIG_MAX {
        return -22; // EINVAL
    }
    let current_ns_id = current.pid_namespace_id();
    let process = if current_ns_id == 0 {
        pid2process(pid)
    } else {
        resolve_process_in_pid_namespace(current_ns_id, pid)
    };
    let Some(process) = process else {
        return -3; // ESRCH
    };
    if process.borrow_mut().is_zombie {
        return -3; // ESRCH
    }
    if current_ns_id != 0
        && current.is_pid_namespace_init()
        && Arc::ptr_eq(&current, &process)
        && matches!(signum as usize, SIGKILL_NUM | SIGSTOP_NUM)
    {
        return 0;
    }
    if !can_signal_process(&process, signum) {
        return -1; // EPERM
    }
    if signum == 0 {
        return 0;
    }
    let sig_bit = signal_bit(signum as usize).unwrap_or(0);
    let legacy_flag = if signum as usize <= MAX_SIG {
        SignalFlags::from_bits(1u32 << signum)
    } else {
        None
    };
    let (sender_pid, sender_uid, _, _) = current_sender_ids();
    let target_ns_id = process.pid_namespace_id();
    let target_is_ns_init = process.is_pid_namespace_init();
    let mut target_pids = vec![process.getpid()];
    if signum as usize == SIGKILL_NUM && target_is_ns_init && target_ns_id != 0 {
        for member_pid in pid_namespace_member_pids(target_ns_id) {
            if !target_pids.contains(&member_pid) {
                target_pids.push(member_pid);
            }
        }
    }
    let tasks = target_pids
        .into_iter()
        .filter_map(pid2process)
        .filter_map(|target: Arc<ProcessControlBlock>| {
            if target.borrow_mut().is_zombie {
                return None;
            }
            if !can_signal_process(&target, signum) {
                return None;
            }
            if current_ns_id != 0 && !process_visible_in_pid_namespace(&target, current_ns_id) {
                return None;
            }
            let mut process_ref = target.borrow_mut();
            if let Some(flag) = legacy_flag {
                process_ref.signals.insert(flag);
            }
            Some(
                process_ref
                    .tasks
                    .iter()
                    .filter_map(|task_slot: &Option<Arc<TaskControlBlock>>| task_slot.as_ref().cloned())
                    .collect::<alloc::vec::Vec<Arc<TaskControlBlock>>>(),
            )
        })
        .flatten()
        .collect::<alloc::vec::Vec<Arc<TaskControlBlock>>>();
    crate::log_if!(
        DEBUG_SIGNAL,
        info,
        "[signal] kill pid={} sig={} tasks={} now_ms={}",
        pid,
        signum,
        tasks.len(),
        get_time_ms()
    );
    if sig_bit != 0 {
        for t in tasks.iter() {
            let (tid, pending, mask) = {
                let mut inner: spin::MutexGuard<'_, TaskControlBlockInner> = t.borrow_mut();
                mark_pending_signal(&mut inner, signum as usize, sender_pid, sender_uid, 0, 0);
                let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
                (tid, inner.pending_signals, inner.signal_mask)
            };
            crate::log_if!(
                DEBUG_SIGNAL,
                debug,
                "[signal] kill pid={} tid={} set_pending sig={} pending={:#x} mask={:#x}",
                pid,
                tid,
                signum,
                pending,
                mask
            );
        }
    }
    for t in tasks {
        wakeup_task(t);
    }
    0
}

pub fn kill_current(signum: i32) -> isize {
    let process = current_process();
    if signum == 0 {
        return 0;
    }
    if signum < 0 || signum as usize > RT_SIG_MAX {
        return -22; // EINVAL
    }
    let legacy_flag = if signum as usize <= MAX_SIG {
        SignalFlags::from_bits(1u32 << signum)
    } else {
        None
    };
    let (sender_pid, sender_uid, _, _) = current_sender_ids();
    let tasks = {
        let mut process_ref = process.borrow_mut();
        if let Some(flag) = legacy_flag {
            process_ref.signals.insert(flag);
        }
        process_ref
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<alloc::vec::Vec<_>>()
    };
    for t in tasks {
        {
            let mut inner = t.borrow_mut();
            mark_pending_signal(&mut inner, signum as usize, sender_pid, sender_uid, 0, 0);
        }
        wakeup_task(t);
    }
    0
}

/// Queue a non-fatal signal to one thread in the target process.
///
/// This mirrors the "one thread" delivery behavior used for alarms and keeps
/// SIGCHLD visible to user-space job control (e.g., busybox/ash).
pub fn queue_process_signal_info(
    pid: usize,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
    si_code: i32,
    sig_value: usize,
) {
    if signum == 0 || signum > RT_SIG_MAX {
        return;
    }
    let Some(bit) = signal_bit(signum) else {
        return;
    };
    let Some(process) = pid2process(pid) else {
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[signal] drop sig={} pid={} (no process)",
            signum,
            pid
        );
        return;
    };
    let tasks = {
        let inner = process.borrow_mut();
        inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<alloc::vec::Vec<_>>()
    };
    let Some(task) = pick_task_for_signal(&tasks, bit) else {
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[signal] drop sig={} pid={} (no task)",
            signum,
            pid
        );
        return;
    };
    let (tid, on_cpu, queued) = {
        let mut inner = task.borrow_mut();
        let already = (inner.pending_signals & bit) != 0;
        mark_pending_signal(&mut inner, signum, sender_pid, sender_uid, si_code, sig_value);
        let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        (
            tid,
            task.on_cpu.load(core::sync::atomic::Ordering::Acquire),
            !already,
        )
    };
    crate::log_if!(
        DEBUG_UNIXBENCH,
        info,
        "[signal] queue pid={} tid={} sig={} queued={} on_cpu={}",
        pid,
        tid,
        signum,
        queued,
        on_cpu
    );
    if queued {
        wakeup_task(task.clone());
        if on_cpu != TaskControlBlock::OFF_CPU {
            arch::send_ipi(on_cpu);
        }
    }
}

pub fn queue_process_signal(pid: usize, signum: usize) {
    queue_process_signal_info(pid, signum, 0, 0, 0, 0);
}

// fn check_pending_signals() {
//     for sig in 0..(MAX_SIG + 1) {
//         let process = current_process();
//         let process_inner = process.borrow_mut();
//         let signal = SignalFlags::from_bits(1 << sig).unwrap();
//         // 如果当前📶 进入 等候区间,并且 没有被mask
//         if process_inner.signals.contains(signal) && (!process_inner.signals_masks.contains(signal))
//         {
//             let mut masked = true;
//             let handling_sig = process_inner.handling_signal;
//             // 已经在处理了,那么 不进行信号处理
//             if handling_sig == -1 {
//                 masked = false;
//             } else {
//                 // 没有在处理,但是 没有handler
//                 let handling_sig = handling_sig as usize;
//                 if !process_inner.signals_actions.table[handling_sig]
//                     .mask
//                     .contains(signal)
//                 {
//                     masked = false;
//                 }
//             }
//             if !masked {
//                 drop(process_inner);
//                 drop(process);
//                 if signal == SignalFlags::SIGKILL
//                     || signal == SignalFlags::SIGSTOP
//                     || signal == SignalFlags::SIGCONT
//                     || signal == SignalFlags::SIGDEF
//                 {
//                     // signal is a kernel signal
//                     call_kernel_signal_handler(signal);
//                 } else {
//                     // signal is a user signal
//                     call_user_signal_handler(sig, signal);
//                     return;
//                 }
//             }
//         }
//     }
// }
// check if there is siganl to solve .
// if so it will change the ret addr to the signal handler
// if have pending signal ,it will suspend
// pub fn handle_signals() {
//     loop {
//         // in the below function , it will change the sepc address to the signal
//         // (if possible )
//         check_pending_signals();
//         let (frozen, killed) = {
//             let process = current_process().unwrap();
//             let process_inner = process.borrow_mut();
//             (process_inner.frozen, process_inner.killed)
//         };
//         // if not frozen or killed , then break
//         if !frozen || killed {
//             break;
//         }
//         suspend_current_and_run_next();
//     }
// }

// os/src/process/mod.rs

// fn call_kernel_signal_handler(signal: SignalFlags) {
//     let process = current_process().unwrap();
//     let mut process_inner = process.borrow_mut();
//     match signal {
//         SignalFlags::SIGSTOP => {
//             process_inner.frozen = true;
//             process_inner.signals ^= SignalFlags::SIGSTOP;
//         }
//         SignalFlags::SIGCONT => {
//             if process_inner.signals.contains(SignalFlags::SIGCONT) {
//                 process_inner.signals ^= SignalFlags::SIGCONT;
//                 process_inner.frozen = false;
//             }
//         }
//         _ => {
//             // println!(
//             //     "[K] call_kernel_signal_handler:: current process sigflag {:?}",
//             //     process_inner.signals
//             // );
//             process_inner.killed = true;
//         }
//     }
// }

// fn call_user_signal_handler(sig: usize, signal: SignalFlags) {
//     let process = current_process();
//     let mut process_inner = process.borrow_mut();

//     let handler = process_inner.signal_actions.table[sig].handler;
//     if handler != 0 {
//         // user handler

//         // handle flag
//         process_inner.handling_signal = sig as isize;
//         // remove the siganl ..
//         process_inner.signals ^= signal;

//         // backup trapframe
//         let mut trap_ctx = process.borrow_mut().trap_context_loc.get_mut() as &mut TrapContext;
//         process_inner.trap_ctx_backup = Some(*trap_ctx);

//         // modify trapframe
//         trap_ctx.sepc = handler;

//         // put args (a0)
//         trap_ctx.x[10] = sig;
//     } else {
//         // default action
//         println!("[K] process/call_user_signal_handler: default action: ignore it or kill process");
//     }
// }

// pub fn sigreturn() -> isize {
//     let process =current_process();
//     let mut inner = process.borrow_mut();
//     inner.handling_signal = -1;
//     // restore the trap context
//     let trap_ctx = inner.trap_context_loc.get_mut() as &mut TrapContext;
//     *trap_ctx = inner.trap_ctx_backup.unwrap();
//     trap_ctx.x[10] as isize
// }
