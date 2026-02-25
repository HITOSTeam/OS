use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::{
    REG_A0, REG_A1, REG_A2, REG_A3, REG_A4, REG_A5, REG_A6, REG_A7, REG_GP, REG_RA, REG_S0, REG_S1,
    REG_SP, REG_T0, REG_T1, REG_T2, REG_TP,
};
use crate::config::SIGRETURN_TRAMPOLINE;
use crate::{
    arch,
    debug_config::{DEBUG_PTHREAD, DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    mm::{read_user_value, try_read_user_value, try_write_user_value, write_user_value},
    syscall::misc::{decode_linux_tid, encode_linux_tid},
    task::{
        block_sleep::add_timer,
        manager::{pid2process, wakeup_task, PID2PCB},
        processor::{
            block_current_and_run_next, current_process, current_task, exit_current_and_run_next,
        },
        signal::{
            can_signal_process, has_unmasked_pending, kill, kill_current, pending_unmasked_bits,
            set_signal, set_signal_mask, signal_bit, take_first_unmasked, RtSigAction,
            SignalAction, SignalFlags, RT_SIG_MAX, SIGALRM_NUM, SIGCONT_NUM, SIGSTOP_NUM,
            SIGTSTP_NUM, SIGTTIN_NUM, SIGTTOU_NUM, SIG_DFL, SIG_IGN,
        },
        task_block::{SigSavedContext, TaskControlBlock, TaskStatus},
        ProcessControlBlock,
    },
    time::get_time_ms,
    trap::get_current_token,
};

fn sigreturn_trampoline_va() -> usize {
    unsafe extern "C" {
        fn alltraps();
        fn sigreturn_trampoline();
    }
    sigreturn_trampoline as usize - alltraps as usize + SIGRETURN_TRAMPOLINE
}

const EINVAL: isize = -22;
const EAGAIN: isize = -11;
const ENOMEM: isize = -12;
const ESRCH: isize = -3;
const EFAULT: isize = -14;
const EINTR: isize = -4;
const EPERM: isize = -1;
const SIGCHLD: usize = 17;
const SA_SIGINFO: usize = 0x4;
const SA_ONSTACK: usize = 0x08000000;
const SA_NODEFER: usize = 0x40000000;
pub const SA_RESTART: usize = 0x10000000;
pub const ERESTARTSYS: isize = -512;
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
const MINSIGSTKSZ: usize = 2048;
const COMPAT_SIGSET_SIZE: usize = 128;

fn valid_sigset_size(sigsetsize: usize) -> bool {
    sigsetsize == core::mem::size_of::<u64>() || sigsetsize == COMPAT_SIGSET_SIZE
}

fn is_stop_signal(signum: usize) -> bool {
    matches!(
        signum,
        SIGSTOP_NUM | SIGTSTP_NUM | SIGTTIN_NUM | SIGTTOU_NUM
    )
}

fn wake_parent_waiters() {
    let child = current_process();
    let parent = {
        let inner = child.borrow_mut();
        inner.parent.as_ref().and_then(|p| p.upgrade())
    };
    let Some(parent) = parent else {
        return;
    };
    crate::task::signal::queue_process_signal(parent.getpid(), SIGCHLD);
    let waiters = {
        let mut parent_inner = parent.borrow_mut();
        parent_inner.wait_queue.drain(..).collect::<Vec<_>>()
    };
    for waiter in waiters {
        wakeup_task(waiter);
    }
}

fn find_task_by_linux_tid(tid: usize) -> Option<(Arc<ProcessControlBlock>, Arc<TaskControlBlock>)> {
    let tid = tid & 0x3fff_ffff;

    if let Some(proc) = pid2process(tid) {
        let main_task = {
            let inner = proc.borrow_mut();
            inner.tasks.first().and_then(|t| t.as_ref()).cloned()
        };
        if let Some(task) = main_task {
            return Some((proc, task));
        }
    }

    let procs: Vec<_> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    for proc in procs {
        let pid = proc.getpid();
        let tasks = {
            let inner = proc.borrow_mut();
            inner
                .tasks
                .iter()
                .enumerate()
                .filter_map(|(idx, t)| t.as_ref().cloned().map(|task| (idx, task)))
                .collect::<Vec<_>>()
        };
        for (idx, task) in tasks {
            if encode_linux_tid(pid, idx) == tid {
                return Some((proc.clone(), task));
            }
        }
    }
    None
}

fn rt_sigpending_limit_reached(proc: &Arc<ProcessControlBlock>, signum: usize) -> bool {
    if signum <= crate::task::signal::MAX_SIG {
        return false;
    }
    let (limit, tasks) = {
        let inner = proc.borrow_mut();
        let tasks = inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<Vec<_>>();
        (inner.rlimit_sigpending_cur, tasks)
    };
    if limit == u64::MAX {
        return false;
    }
    let pending = tasks
        .iter()
        .map(|task| {
            let inner = task.borrow_mut();
            (inner.pending_signals >> crate::task::signal::MAX_SIG).count_ones() as u64
        })
        .sum::<u64>();
    pending >= limit
}

// pub fn syscall_sigreturn() -> isize {
//     sigreturn()
// }

pub fn syscall_kill(pid: usize, signum: i32) -> isize {
    let pid = pid as isize;
    if pid > 0 {
        return kill(pid as usize, signum);
    }

    let targets: Vec<usize> = match pid {
        0 => {
            let pgid = current_process().borrow_mut().pgid;
            let procs: Vec<_> = {
                let map = PID2PCB.lock();
                map.values().cloned().collect()
            };
            procs
                .into_iter()
                .filter_map(|p| {
                    let inner = p.borrow_mut();
                    if inner.pgid == pgid {
                        Some(p.getpid())
                    } else {
                        None
                    }
                })
                .collect()
        }
        -1 => {
            let self_pid = current_process().getpid();
            let map = PID2PCB.lock();
            map.keys()
                .copied()
                .filter(|pid| *pid != 0 && *pid != self_pid)
                .collect()
        }
        p if p < -1 => {
            let target_pgid = (-p) as usize;
            let procs: Vec<_> = {
                let map = PID2PCB.lock();
                map.values().cloned().collect()
            };
            procs
                .into_iter()
                .filter_map(|p| {
                    let inner = p.borrow_mut();
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
            EPERM => denied = true,
            _ => {}
        }
    }
    if delivered {
        0
    } else if denied {
        EPERM
    } else {
        ESRCH
    }
}

/// Linux `tgkill` (syscall 131).
///
/// Delivers a signal to a specific thread (Linux-style tid encoding).
pub fn syscall_tgkill(tgid: usize, tid: usize, sig: i32) -> isize {
    if sig < 0 || sig as usize > RT_SIG_MAX {
        return EINVAL;
    }
    if (tgid as isize) <= 0 || (tid as isize) <= 0 {
        return EINVAL;
    }
    if DEBUG_PTHREAD {
        crate::println!("[tgkill] tgid={} tid={} sig={}", tgid, tid, sig);
    }
    let norm_tid = tid & 0x3fff_ffff;
    let Some(proc) = pid2process(tgid) else {
        return ESRCH;
    };
    let Some(tid_index) = decode_linux_tid(tgid, norm_tid) else {
        return ESRCH;
    };
    if !can_signal_process(&proc, sig) {
        return EPERM;
    }
    let task = {
        let inner = proc.borrow_mut();
        inner.tasks.get(tid_index).and_then(|t| t.as_ref()).cloned()
    };
    let Some(task) = task else {
        return ESRCH;
    };
    if sig == 0 {
        return 0;
    }
    if rt_sigpending_limit_reached(&proc, sig as usize) {
        return EAGAIN;
    }
    let sender = current_process();
    let sender_pid = sender.getpid() as i32;
    let sender_uid = {
        let inner = sender.borrow_mut();
        inner.uid
    };
    {
        let mut inner = task.borrow_mut();
        if let Some(bit) = signal_bit(sig as usize) {
            inner.pending_signals |= bit;
            let signum = sig as usize;
            if signum <= RT_SIG_MAX {
                inner.pending_signal_pid[signum] = sender_pid;
                inner.pending_signal_uid[signum] = sender_uid;
                inner.pending_signal_code[signum] = -6; // SI_TKILL
            }
        }
    }
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
    let on_cpu = task.on_cpu.load(Ordering::Acquire);
    wakeup_task(task);
    if on_cpu != TaskControlBlock::OFF_CPU {
        arch::send_ipi(on_cpu);
    }
    0
}

/// Linux `tkill` (syscall 130).
///
/// Delivers a signal to a specific thread in the current process.
pub fn syscall_tkill(tid: usize, sig: i32) -> isize {
    if sig < 0 || sig as usize > RT_SIG_MAX {
        return EINVAL;
    }
    if (tid as isize) <= 0 {
        return EINVAL;
    }
    let Some((proc, task)) = find_task_by_linux_tid(tid) else {
        return ESRCH;
    };
    if !can_signal_process(&proc, sig) {
        return EPERM;
    }
    if sig == 0 {
        return 0;
    }
    if rt_sigpending_limit_reached(&proc, sig as usize) {
        return EAGAIN;
    }
    let sender = current_process();
    let sender_pid = sender.getpid() as i32;
    let sender_uid = {
        let inner = sender.borrow_mut();
        inner.uid
    };
    {
        let mut inner = task.borrow_mut();
        if let Some(bit) = signal_bit(sig as usize) {
            inner.pending_signals |= bit;
            let signum = sig as usize;
            if signum <= RT_SIG_MAX {
                inner.pending_signal_pid[signum] = sender_pid;
                inner.pending_signal_uid[signum] = sender_uid;
                inner.pending_signal_code[signum] = -6; // SI_TKILL
            }
        }
    }
    let on_cpu = task.on_cpu.load(Ordering::Acquire);
    wakeup_task(task);
    if on_cpu != TaskControlBlock::OFF_CPU {
        arch::send_ipi(on_cpu);
    }
    0
}
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
pub fn syscall_sigprocmask(how: u32) -> isize {
    set_signal_mask(how)
}

/// Linux `rt_sigaction` (syscall 134).
pub fn syscall_rt_sigaction(signum: usize, act: usize, oldact: usize, sigsetsize: usize) -> isize {
    if signum == 0 || signum > RT_SIG_MAX {
        return EINVAL;
    }
    if signum == crate::task::signal::SIGKILL_NUM || signum == crate::task::signal::SIGSTOP_NUM {
        return EINVAL;
    }
    if !valid_sigset_size(sigsetsize) {
        return EINVAL;
    }
    let token = get_current_token();
    let process = current_process();
    let mut inner = process.borrow_mut();
    if oldact != 0 {
        let cur = inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default();
        if try_write_user_value(token, oldact as *mut RtSigAction, &cur).is_err() {
            return EFAULT;
        }
    }
    if act != 0 {
        let Some(new) = try_read_user_value(token, act as *const RtSigAction) else {
            return EFAULT;
        };
        if DEBUG_UNIXBENCH && signum == 14 {
            crate::log_if!(
                DEBUG_UNIXBENCH,
                info,
                "[signal] sigaction sig={} handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
                signum,
                new.handler,
                new.flags,
                new.restorer,
                new.mask
            );
        }
        if DEBUG_PTHREAD {
            crate::println!(
                "[rt_sigaction] signo={} handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
                signum,
                new.handler,
                new.flags,
                new.restorer,
                new.mask
            );
        }
        if signum < inner.rt_sig_handlers.len() {
            inner.rt_sig_handlers[signum] = new;
        }
    }
    0
}

/// Linux `rt_sigprocmask` (syscall 135).
pub fn syscall_rt_sigprocmask(how: usize, set: usize, oldset: usize, sigsetsize: usize) -> isize {
    if !valid_sigset_size(sigsetsize) {
        return EINVAL;
    }
    let token = get_current_token();
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    let old_mask = inner.signal_mask;
    let new_mask = if set != 0 {
        // Read new mask before writing oldset to support aliasing set/oldset.
        let Some(v) = try_read_user_value(token, set as *const u64) else {
            return EFAULT;
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
            _ => return EINVAL,
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
            return EFAULT;
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
            return EFAULT;
        }
    }

    if ss == 0 {
        return 0;
    }
    if inner.on_sigaltstack {
        return EPERM;
    }
    let Some(new_ss) = try_read_user_value(token, ss as *const SigStack) else {
        return EFAULT;
    };
    if (new_ss.ss_flags & !(SS_DISABLE)) != 0 {
        return EINVAL;
    }
    if (new_ss.ss_flags & SS_DISABLE) != 0 {
        inner.sigaltstack_enabled = false;
        inner.sigaltstack_sp = 0;
        inner.sigaltstack_size = 0;
        return 0;
    }
    if new_ss.ss_sp == 0 {
        return EINVAL;
    }
    if new_ss.ss_size < MINSIGSTKSZ {
        return ENOMEM;
    }
    inner.sigaltstack_enabled = true;
    inner.sigaltstack_sp = new_ss.ss_sp;
    inner.sigaltstack_size = new_ss.ss_size;
    0
}

/// Linux `rt_sigpending` (syscall 136).
pub fn syscall_rt_sigpending(set: usize, sigsetsize: usize) -> isize {
    if set == 0 {
        return EFAULT;
    }
    if !valid_sigset_size(sigsetsize) {
        return EINVAL;
    }
    let pending = {
        let task = current_task().unwrap();
        let inner = task.borrow_mut();
        inner.pending_signals
    };
    let token = get_current_token();
    if try_write_user_value(token, set as *mut u64, &pending).is_err() {
        return EFAULT;
    }
    // User sigset_t may be larger than 8 bytes; zero trailing bytes.
    if sigsetsize > core::mem::size_of::<u64>() {
        let zero: u8 = 0;
        for off in core::mem::size_of::<u64>()..sigsetsize {
            if try_write_user_value(token, (set + off) as *mut u8, &zero).is_err() {
                return EFAULT;
            }
        }
    }
    0
}

fn has_deliverable_pending(pending: u64, mask: u64) -> bool {
    let mut bits = pending_unmasked_bits(pending, mask, false);
    if bits == 0 {
        return false;
    }
    let process = current_process();
    let inner = process.borrow_mut();
    while bits != 0 {
        let signum = bits.trailing_zeros() as usize + 1;
        bits &= bits - 1;
        let action = inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default();
        if action.handler == SIG_IGN {
            continue;
        }
        if action.handler == SIG_DFL {
            if signum <= crate::task::signal::MAX_SIG {
                if let Some(flag) = SignalFlags::from_bits(1u32 << signum) {
                    if flag.check_error().is_some() {
                        return true;
                    }
                }
            } else {
                return true;
            }
            continue;
        }
        return true;
    }
    false
}

/// Linux `rt_sigsuspend` (syscall 133).
pub fn syscall_rt_sigsuspend(mask_ptr: usize, sigsetsize: usize) -> isize {
    if !valid_sigset_size(sigsetsize) {
        return EINVAL;
    }
    let token = get_current_token();
    let new_mask = if mask_ptr != 0 {
        let Some(v) = try_read_user_value(token, mask_ptr as *const u64) else {
            return EFAULT;
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
        if has_deliverable_pending(pending, mask) {
            return EINTR;
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
        exit_current_and_run_next(-1);
        unreachable!("exit_current_and_run_next should not return");
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

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct LinuxSigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    si_pad0: i32,
    field: [i32; 28],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SigStack {
    ss_sp: usize,
    ss_flags: i32,
    _pad: i32,
    ss_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserRegsStruct {
    pc: usize,
    ra: usize,
    sp: usize,
    gp: usize,
    tp: usize,
    t0: usize,
    t1: usize,
    t2: usize,
    s0: usize,
    s1: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    t3: usize,
    t4: usize,
    t5: usize,
    t6: usize,
}

impl UserRegsStruct {
    fn from_trap(cx: &crate::trap::context::TrapContext) -> Self {
        Self {
            pc: cx.sepc,
            ra: cx.x[REG_RA],
            sp: cx.x[REG_SP],
            gp: cx.x[REG_GP],
            tp: cx.x[REG_TP],
            t0: cx.x[REG_T0],
            t1: cx.x[REG_T1],
            t2: cx.x[REG_T2],
            s0: cx.x[REG_S0],
            s1: cx.x[REG_S1],
            a0: cx.x[REG_A0],
            a1: cx.x[REG_A1],
            a2: cx.x[REG_A2],
            a3: cx.x[REG_A3],
            a4: cx.x[REG_A4],
            a5: cx.x[REG_A5],
            a6: cx.x[REG_A6],
            a7: cx.x[REG_A7],
            s2: cx.x[18],
            s3: cx.x[19],
            s4: cx.x[20],
            s5: cx.x[21],
            s6: cx.x[22],
            s7: cx.x[23],
            s8: cx.x[24],
            s9: cx.x[25],
            s10: cx.x[26],
            s11: cx.x[27],
            t3: cx.x[28],
            t4: cx.x[29],
            t5: cx.x[30],
            t6: cx.x[31],
        }
    }

    fn write_to_trap(&self, cx: &mut crate::trap::context::TrapContext) {
        cx.sepc = self.pc;
        cx.x[0] = 0;
        cx.x[REG_RA] = self.ra;
        cx.x[REG_SP] = self.sp;
        cx.x[REG_GP] = self.gp;
        cx.x[REG_TP] = self.tp;
        cx.x[REG_T0] = self.t0;
        cx.x[REG_T1] = self.t1;
        cx.x[REG_T2] = self.t2;
        cx.x[REG_S0] = self.s0;
        cx.x[REG_S1] = self.s1;
        cx.x[REG_A0] = self.a0;
        cx.x[REG_A1] = self.a1;
        cx.x[REG_A2] = self.a2;
        cx.x[REG_A3] = self.a3;
        cx.x[REG_A4] = self.a4;
        cx.x[REG_A5] = self.a5;
        cx.x[REG_A6] = self.a6;
        cx.x[REG_A7] = self.a7;
        cx.x[18] = self.s2;
        cx.x[19] = self.s3;
        cx.x[20] = self.s4;
        cx.x[21] = self.s5;
        cx.x[22] = self.s6;
        cx.x[23] = self.s7;
        cx.x[24] = self.s8;
        cx.x[25] = self.s9;
        cx.x[26] = self.s10;
        cx.x[27] = self.s11;
        cx.x[28] = self.t3;
        cx.x[29] = self.t4;
        cx.x[30] = self.t5;
        cx.x[31] = self.t6;
    }
}

const RISCV_FP_STATE_SIZE: usize = 528;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct SigContext {
    regs: UserRegsStruct,
    fp_state: [u8; RISCV_FP_STATE_SIZE],
}

impl Default for SigContext {
    fn default() -> Self {
        Self {
            regs: UserRegsStruct::default(),
            fp_state: [0u8; RISCV_FP_STATE_SIZE],
        }
    }
}

const UCONTEXT_SIGSET_PAD: usize = 128 - core::mem::size_of::<u64>();

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct UContext {
    uc_flags: usize,
    uc_link: usize,
    uc_stack: SigStack,
    uc_sigmask: u64,
    __unused: [u8; UCONTEXT_SIGSET_PAD],
    uc_mcontext: SigContext,
}

impl Default for UContext {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SigStack::default(),
            uc_sigmask: 0,
            __unused: [0u8; UCONTEXT_SIGSET_PAD],
            uc_mcontext: SigContext::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

fn write_siginfo(
    info_ptr: usize,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
    si_code: i32,
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
    si.field[0] = sender_pid;
    si.field[1] = sender_uid as i32;
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

fn sig_bit(sig: usize) -> Option<u64> {
    if sig == 0 || sig > 64 {
        return None;
    }
    Some(1u64 << (sig - 1))
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
) -> Option<(usize, i32, u32, i32)> {
    let mut inner = task.borrow_mut();
    let pending = inner.pending_signals & wait_mask;
    if pending == 0 {
        return None;
    }
    let sig = pending.trailing_zeros() as usize + 1;
    if let Some(bit) = sig_bit(sig) {
        inner.pending_signals &= !bit;
    }
    let mut sender_pid = 0;
    let mut sender_uid = 0;
    let mut si_code = 0;
    if sig <= RT_SIG_MAX {
        sender_pid = inner.pending_signal_pid[sig];
        sender_uid = inner.pending_signal_uid[sig];
        si_code = inner.pending_signal_code[sig];
        inner.pending_signal_pid[sig] = 0;
        inner.pending_signal_uid[sig] = 0;
        inner.pending_signal_code[sig] = 0;
    }
    Some((sig, sender_pid, sender_uid, si_code))
}

fn has_nonwait_interrupt(task: &Arc<TaskControlBlock>, wait_mask: u64) -> bool {
    let inner = task.borrow_mut();
    let ready = pending_unmasked_bits(inner.pending_signals, inner.signal_mask, false);
    (ready & !wait_mask) != 0
}

/// Linux `rt_sigtimedwait` (syscall 137).
pub fn syscall_rt_sigtimedwait(
    set: usize,
    info: usize,
    timeout: usize,
    sigsetsize: usize,
) -> isize {
    if set == 0 {
        return EFAULT;
    }
    if !valid_sigset_size(sigsetsize) {
        return EINVAL;
    }
    let token = get_current_token();
    let Some(mask) = try_read_user_value(token, set as *const u64) else {
        return EFAULT;
    };

    let sigchld_bit = sig_bit(SIGCHLD).unwrap();
    let task = current_task().unwrap();

    let deadline_ms = if timeout != 0 {
        let Some(ts) = try_read_user_value(token, timeout as *const TimeSpec) else {
            return EFAULT;
        };
        let timeout_ms = match timespec_to_ms(ts) {
            Some(ms) => ms,
            None => return EINVAL,
        };
        Some(get_time_ms().saturating_add(timeout_ms))
    } else {
        None
    };

    let mut timer_set = false;
    loop {
        if let Some((sig, sender_pid, sender_uid, si_code)) = take_pending_in_set(&task, mask) {
            if write_siginfo(info, sig, sender_pid, sender_uid, si_code).is_err() {
                return EFAULT;
            }
            return sig as isize;
        }

        // SIGCHLD may be observed via waitable zombie state even before queueing.
        if (mask & sigchld_bit) != 0 && has_zombie_child() {
            if write_siginfo(info, SIGCHLD, 0, 0, 0).is_err() {
                return EFAULT;
            }
            return SIGCHLD as isize;
        }

        // Non-target signals interrupt the wait.
        if has_nonwait_interrupt(&task, mask) {
            return EINTR;
        }

        if let Some(deadline_ms) = deadline_ms {
            if get_time_ms() >= deadline_ms {
                return EAGAIN;
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
                    return EAGAIN;
                }
                add_timer(Arc::clone(&task), wait_ms);
                timer_set = true;
            }
        }

        block_current_and_run_next();
        remove_waiter(&task);
    }
}

pub fn maybe_deliver_signal() {
    let Some(task) = current_task() else {
        return;
    };
    const MAX_SIGNAL_DEPTH: usize = 8;
    static SIGALRM_LOG_LEFT: AtomicUsize = AtomicUsize::new(16);
    let sigalrm_bit = signal_bit(SIGALRM_NUM).unwrap_or(0);
    let (signum, sender_pid, sender_uid, si_code) = {
        let mut inner = task.borrow_mut();
        if inner.sig_saved_ctx.len() >= MAX_SIGNAL_DEPTH {
            if DEBUG_UNIXBENCH
                && sigalrm_bit != 0
                && (inner.pending_signals & sigalrm_bit) != 0
                && SIGALRM_LOG_LEFT.fetch_sub(1, Ordering::Relaxed) > 0
            {
                let pid = current_process().getpid();
                let tid = inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
                crate::log_if!(
                    DEBUG_UNIXBENCH,
                    debug,
                    "[signal] drop sig=14 (nesting) pid={} tid={} depth={}",
                    pid,
                    tid,
                    inner.sig_saved_ctx.len()
                );
            }
            return;
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
        if sig <= RT_SIG_MAX {
            sender_pid = inner.pending_signal_pid[sig];
            sender_uid = inner.pending_signal_uid[sig];
            si_code = inner.pending_signal_code[sig];
            inner.pending_signal_pid[sig] = 0;
            inner.pending_signal_uid[sig] = 0;
            inner.pending_signal_code[sig] = 0;
        }
        (sig, sender_pid, sender_uid, si_code)
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
                    exit_current_and_run_next(errno);
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
        siginfo.field[0] = sender_pid;
        siginfo.field[1] = sender_uid as i32;

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
