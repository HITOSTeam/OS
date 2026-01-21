pub const MAX_SIG: usize = 31;
pub const RT_SIG_MAX: usize = 64;
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
pub const SIGPIPE_NUM: usize = 13;
pub const SIGALRM_NUM: usize = 14;
pub const SIGCHLD_NUM: usize = 17;
pub const SIGKILL_NUM: usize = 9;
pub const SIGSTOP_NUM: usize = 19;
use bitflags::bitflags;

use alloc::sync::Arc;

use crate::{
    arch,
    debug_config::DEBUG_UNIXBENCH,
    mm::{read_user_value, translated_single_address, write_user_value},
    println,
    task::processor::current_process,
    task::{
        manager::{pid2process, wakeup_task},
        processor::suspend_current_and_run_next,
        task_block::TaskControlBlock,
    },
    trap::{context::TrapContext, get_current_token},
};

pub fn signal_bit(signum: usize) -> Option<u64> {
    if signum == 0 || signum > RT_SIG_MAX {
        return None;
    }
    Some(1u64 << (signum - 1))
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
        if self.contains(Self::SIGINT) {
            Some((-2, "Killed, SIGINT=2"))
        } else if self.contains(Self::SIGILL) {
            Some((-4, "Illegal Instruction, SIGILL=4"))
        } else if self.contains(Self::SIGABRT) {
            Some((-6, "Aborted, SIGABRT=6"))
        } else if self.contains(Self::SIGFPE) {
            Some((-8, "Erroneous Arithmetic Operation, SIGFPE=8"))
        } else if self.contains(Self::SIGKILL) {
            Some((-9, "Killed, SIGKILL=9"))
        } else if self.contains(Self::SIGSEGV) {
            Some((-11, "Segmentation Fault, SIGSEGV=11"))
        } else if self.contains(Self::SIGPIPE) {
            Some((-13, "Broken pipe, SIGPIPE=13"))
        } else {
            //println!("[K] signalflags check_error  {:?}", self);
            None
        }
    }
}
pub fn check_if_current_signals_error() -> Option<(i32, &'static str)> {
    let process = current_process();
    let process_inner = process.borrow_mut();
    process_inner.signals.check_error()
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
    if signum as usize > MAX_SIG {
        return -1;
    }
    if let Some(flag) = SignalFlags::from_bits(1 << signum) {
        if check_sigaction_error(flag, action as usize, old_action as usize) {
            return -1;
        }
        let prev_action = inner.signals_actions.table[signum as usize];
        write_user_value(token, old_action, &prev_action);
        inner.signals_actions.table[signum as usize] =
            read_user_value(token, action as *const SignalAction);
        0
    } else {
        -1
    }
}

// insert the bit flag.. if already set  return -1
pub fn kill(pid: usize, signum: i32) -> isize {
    let Some(process) = pid2process(pid) else {
        return -3; // ESRCH
    };
    if signum == 0 {
        return 0;
    }
    if signum < 0 || signum as usize > MAX_SIG {
        return -22; // EINVAL
    }
    let Some(flag) = SignalFlags::from_bits(1u32 << signum) else {
        return -22; // EINVAL
    };
    let (tasks, child_pids) = {
        let mut process_ref = process.borrow_mut();
        process_ref.signals.insert(flag);
        let tasks = process_ref
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<alloc::vec::Vec<_>>();
        let child_pids = if signum == 2 || signum == 9 {
            process_ref
                .children
                .iter()
                .map(|c| c.getpid())
                .collect::<alloc::vec::Vec<_>>()
        } else {
            alloc::vec::Vec::new()
        };
        (tasks, child_pids)
    };
    for t in tasks {
        wakeup_task(t);
    }
    for child_pid in child_pids {
        let _ = kill(child_pid, signum);
    }
    0
}

pub fn kill_current(signum: i32) -> isize {
    let process = current_process();
    if signum == 0 {
        return 0;
    }
    if signum < 0 || signum as usize > MAX_SIG {
        return -22; // EINVAL
    }
    let Some(flag) = SignalFlags::from_bits(1u32 << signum) else {
        return -22; // EINVAL
    };
    let tasks = {
        let mut process_ref = process.borrow_mut();
        process_ref.signals.insert(flag);
        process_ref
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<alloc::vec::Vec<_>>()
    };
    for t in tasks {
        wakeup_task(t);
    }
    0
}

/// Queue a non-fatal signal to one thread in the target process.
///
/// This mirrors the "one thread" delivery behavior used for alarms and keeps
/// SIGCHLD visible to user-space job control (e.g., busybox/ash).
pub fn queue_process_signal(pid: usize, signum: usize) {
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
        inner.pending_signals |= bit;
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
