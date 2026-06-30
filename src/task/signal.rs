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
pub const SIGURG_NUM: usize = 23;
pub const SIGWINCH_NUM: usize = 28;
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
        manager::{
            pid2process, prime_fair_sync_wakeup_lag, wakeup_signal_tasks, wakeup_task, wakeup_tasks,
        },
        pid_namespace_member_pids,
        process_block::{ProcessControlBlock, ProcessControlBlockInner},
        process_visible_in_pid_namespace,
        processor::{current_task, hart_id, suspend_current_and_run_next},
        resolve_process_in_pid_namespace,
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

fn hart_mask_bit(hart: usize) -> usize {
    if hart < usize::BITS as usize {
        1usize << hart
    } else {
        0
    }
}

fn send_signal_ipis(mask: usize) {
    let local_hart = hart_id();
    for target_hart in 0..crate::config::MAX_HARTS {
        if target_hart != local_hart && (mask & hart_mask_bit(target_hart)) != 0 {
            arch::send_ipi(target_hart);
        }
    }
}

pub(crate) fn request_reschedule_for_signal_target(task: &Arc<TaskControlBlock>) {
    let local_hart = hart_id() % crate::config::MAX_HARTS;
    let running_hart = task.on_cpu.load(core::sync::atomic::Ordering::Acquire);
    if running_hart != TaskControlBlock::OFF_CPU {
        if running_hart == local_hart {
            crate::task::processor::request_reschedule_current_hart();
        } else if running_hart < crate::config::MAX_HARTS {
            crate::task::processor::request_reschedule_harts(1usize << running_hart);
        }
        return;
    }

    if !task
        .in_ready_queue
        .load(core::sync::atomic::Ordering::Acquire)
    {
        return;
    }
    let ready_hart = task
        .ready_queue_hart
        .load(core::sync::atomic::Ordering::Acquire);
    if ready_hart >= crate::config::MAX_HARTS {
        return;
    }
    if ready_hart == local_hart {
        crate::task::processor::request_reschedule_current_hart();
    } else {
        crate::task::processor::request_reschedule_harts(1usize << ready_hart);
    }
}

pub fn signal_has_core_dump(signum: usize) -> bool {
    matches!(
        signum,
        3  // SIGQUIT
            | 4  // SIGILL
            | 5  // SIGTRAP
            | 6  // SIGABRT / SIGIOT
            | 7  // SIGBUS
            | 8  // SIGFPE
            | 11 // SIGSEGV
            | 24 // SIGXCPU
            | 25 // SIGXFSZ
            | 31 // SIGSYS
    )
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

fn process_signal_handler(inner: &ProcessControlBlockInner, signum: usize) -> usize {
    if signum <= MAX_SIG {
        let legacy = inner.signals_actions.table[signum].handler;
        if legacy != SIG_DFL {
            return legacy;
        }
    }
    inner
        .rt_sig_handlers
        .get(signum)
        .map(|action| action.handler)
        .unwrap_or(SIG_DFL)
}

fn queue_current_single_thread_signal(
    process: &Arc<ProcessControlBlock>,
    signum: usize,
    legacy_flag: Option<SignalFlags>,
    sender_pid: i32,
    sender_uid: u32,
) -> bool {
    let Some(current) = current_task() else {
        return false;
    };
    let task = {
        let mut process_ref = process.borrow_mut();
        if process_ref.is_zombie {
            return true;
        }

        let mut live_tasks = process_ref
            .tasks
            .iter()
            .filter_map(|task| task.as_ref().cloned());
        let Some(task) = live_tasks.next() else {
            return true;
        };
        if live_tasks.next().is_some() {
            return false;
        }
        if !Arc::ptr_eq(&task, &current) {
            return false;
        }
        if let Some(flag) = legacy_flag {
            process_ref.signals.insert(flag);
        }
        task
    };

    let (tid, pending, mask) = {
        let mut inner = task.borrow_mut();
        mark_pending_signal(&mut inner, signum, sender_pid, sender_uid, 0, 0);
        let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        (tid, inner.pending_signals, inner.signal_mask)
    };
    task.mark_signal_pending();
    crate::log_if!(
        DEBUG_SIGNAL,
        debug,
        "[signal] self pid={} tid={} set_pending sig={} pending={:#x} mask={:#x}",
        process.getpid(),
        tid,
        signum,
        pending,
        mask
    );
    true
}

/// 检查当前是否有 pending 且 未被 mask的信号,其中 SIG KILL 与 SIGSTOP 无法被mask
pub fn pending_unmasked_bits(pending: u64, mask: u64) -> u64 {
    let mut ready = pending & !mask;
    let sigkill_bit = 1u64 << (SIGKILL_NUM - 1);
    let sigstop_bit = 1u64 << (SIGSTOP_NUM - 1);
    ready |= pending & (sigkill_bit | sigstop_bit);
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

/// process stop 当前进程是否被Stop. SIGCOUNT 可以恢复
pub fn sig_default_interrupts_wait(signum: usize, process_stopped: bool) -> bool {
    match signum {
        SIGCHLD_NUM | SIGURG_NUM | SIGWINCH_NUM => false,
        SIGCONT_NUM => process_stopped,
        _ => true,
    }
}

/// 检查当前爱你是否有 需要打断的信号
pub fn has_wait_interrupting_pending(pending: u64, mask: u64) -> bool {
    let mut ready = pending_unmasked_bits(pending, mask);
    if ready == 0 {
        return false;
    }
    let process = current_process();
    let inner = process.borrow_mut();
    while ready != 0 {
        let signum = ready.trailing_zeros() as usize + 1;
        ready &= ready - 1;
        if signum == SIGKILL_NUM || signum == SIGSTOP_NUM {
            return true;
        }
        let handler = inner
            .rt_sig_handlers
            .get(signum)
            .map(|action| action.handler)
            .unwrap_or(SIG_DFL);
        //SIG IGN 忽略
        if handler == SIG_IGN {
            continue;
        }
        // SIG DFL 默认。 Linux 对于一些信号有默认处理,检查默认处理 是否是打断
        if handler == SIG_DFL && !sig_default_interrupts_wait(signum, inner.stopped) {
            continue;
        }
        return true;
    }
    false
}

pub fn take_first_unmasked(pending: &mut u64, mask: u64) -> Option<usize> {
    let ready = pending_unmasked_bits(*pending, mask);
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

fn signal_default_terminates(signum: usize) -> bool {
    // Keep the wakeup decision aligned with the existing default-action table:
    // only signals that would make `check_error()` terminate the task get the
    // stronger fatal-signal wakeup path.
    signum <= MAX_SIG
        && SignalFlags::from_bits(1u32 << signum)
            .and_then(|flag| flag.check_error())
            .is_some()
}

pub fn check_task_signals_error(task: &Arc<TaskControlBlock>) -> Option<(i32, &'static str)> {
    if !task.has_signal_pending() {
        return None;
    }
    let (pending, mask) = {
        let inner = task.borrow_mut();
        (inner.pending_signals, inner.signal_mask)
    };
    let mut ready = pending_unmasked_bits(pending, mask);
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
            task.refresh_signal_pending(inner.pending_signals);
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

pub fn check_if_current_signals_error() -> Option<(i32, &'static str)> {
    let task = current_task()?;
    check_task_signals_error(&task)
}

pub fn log_signal_exit(msg: &'static str) {
    crate::log_if!(DEBUG_SIGNAL, info, "[signal-exit] {}", msg);
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
    let _ = action;
    let _ = old_action;
    signal == SignalFlags::SIGKILL || signal == SignalFlags::SIGSTOP
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
    if signum == SIGKILL_NUM || signum == SIGSTOP_NUM {
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
        if !old_action.is_null() {
            write_user_value(token, old_action, &prev_action);
        }

        if !action.is_null() {
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
    if Arc::ptr_eq(&current, &process)
        && queue_current_single_thread_signal(
            &process,
            signum as usize,
            legacy_flag,
            sender_pid,
            sender_uid,
        )
    {
        return 0;
    }
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
    let signum_usize = signum as usize;
    let mut prompt_user_handler_wakeup = false;
    let mut fatal_default_wakeup = false;
    let tasks = target_pids
        .into_iter()
        .filter_map(pid2process)
        .filter_map(|target: Arc<ProcessControlBlock>| {
            if !can_signal_process(&target, signum) {
                return None;
            }
            if current_ns_id != 0 && !process_visible_in_pid_namespace(&target, current_ns_id) {
                return None;
            }
            let mut process_ref = target.borrow_mut();
            if process_ref.is_zombie {
                // Linux keeps unreaped zombies visible by PID and killable in
                // the sense that kill(2) succeeds, but no signal is delivered.
                return None;
            }
            if let Some(flag) = legacy_flag {
                process_ref.signals.insert(flag);
            }
            let handler = process_signal_handler(&process_ref, signum_usize);
            if handler != SIG_DFL && handler != SIG_IGN {
                prompt_user_handler_wakeup = true;
            } else if handler == SIG_DFL && signal_default_terminates(signum_usize) {
                fatal_default_wakeup = true;
            }
            Some(
                process_ref
                    .tasks
                    .iter()
                    .filter_map(|task_slot: &Option<Arc<TaskControlBlock>>| {
                        task_slot.as_ref().cloned()
                    })
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
    let mut running_signal_ipi_mask = 0usize;
    if sig_bit != 0 {
        for t in tasks.iter() {
            let (tid, pending, mask) = {
                let mut inner: spin::MutexGuard<'_, TaskControlBlockInner> = t.borrow_mut();
                mark_pending_signal(&mut inner, signum as usize, sender_pid, sender_uid, 0, 0);
                let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
                (tid, inner.pending_signals, inner.signal_mask)
            };
            t.mark_signal_pending();
            if prompt_user_handler_wakeup || fatal_default_wakeup {
                request_reschedule_for_signal_target(t);
            }
            let on_cpu = t.on_cpu.load(core::sync::atomic::Ordering::Acquire);
            if on_cpu != TaskControlBlock::OFF_CPU {
                running_signal_ipi_mask |= hart_mask_bit(on_cpu);
            }
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
    // A user handler needs the target to reach user mode promptly so the
    // handler can run. A fatal default signal needs the blocked task to observe
    // pending termination promptly. Other ignored/nonfatal signals keep the
    // cheaper normal signal wakeup behavior.
    if prompt_user_handler_wakeup {
        for task in tasks.iter() {
            prime_fair_sync_wakeup_lag(task);
        }
        wakeup_tasks(tasks.clone());
        crate::task::processor::request_reschedule_current_hart();
        for task in tasks.iter() {
            request_reschedule_for_signal_target(task);
        }
    } else if fatal_default_wakeup {
        for task in tasks.iter() {
            prime_fair_sync_wakeup_lag(task);
        }
        wakeup_signal_tasks(tasks.clone());
        for task in tasks.iter() {
            request_reschedule_for_signal_target(task);
        }
    } else {
        wakeup_signal_tasks(tasks);
    }
    if running_signal_ipi_mask != 0 {
        send_signal_ipis(running_signal_ipi_mask);
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
    let mut running_signal_ipi_mask = 0usize;
    for t in tasks.iter() {
        {
            let mut inner = t.borrow_mut();
            mark_pending_signal(&mut inner, signum as usize, sender_pid, sender_uid, 0, 0);
        }
        t.mark_signal_pending();
        request_reschedule_for_signal_target(t);
        let on_cpu = t.on_cpu.load(core::sync::atomic::Ordering::Acquire);
        if on_cpu != TaskControlBlock::OFF_CPU {
            running_signal_ipi_mask |= hart_mask_bit(on_cpu);
        }
    }
    wakeup_tasks(tasks.clone());
    for task in tasks.iter() {
        request_reschedule_for_signal_target(task);
    }
    if running_signal_ipi_mask != 0 {
        send_signal_ipis(running_signal_ipi_mask);
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
        mark_pending_signal(
            &mut inner, signum, sender_pid, sender_uid, si_code, sig_value,
        );
        let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        (
            tid,
            task.on_cpu.load(core::sync::atomic::Ordering::Acquire),
            !already,
        )
    };
    task.mark_signal_pending();
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
        request_reschedule_for_signal_target(&task);
        wakeup_task(task.clone());
        request_reschedule_for_signal_target(&task);
        if on_cpu != TaskControlBlock::OFF_CPU {
            arch::send_ipi(on_cpu);
        }
    }
}

pub fn queue_process_signal(pid: usize, signum: usize) {
    queue_process_signal_info(pid, signum, 0, 0, 0, 0);
}
