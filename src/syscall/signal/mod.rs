mod deliver;
mod mask;
mod send;
mod wait;

pub use deliver::*;
pub use mask::*;
pub use send::*;
pub use wait::*;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::{
    REG_A0, REG_A1, REG_A2, REG_A3, REG_A4, REG_A5, REG_A6, REG_A7, REG_GP, REG_RA, REG_S0, REG_S1,
    REG_SP, REG_T0, REG_T1, REG_T2, REG_TP,
};
use crate::config::SIGRETURN_TRAMPOLINE;
use crate::syscall::error::{SyscallError, err};
use crate::{
    arch,
    debug_config::{DEBUG_PTHREAD, DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    mm::{read_user_value, try_read_user_value, try_write_user_value, write_user_value},
    syscall::misc::{decode_linux_tid_strict, encode_linux_tid},
    task::{
        ProcessControlBlock,
        block_sleep::add_timer,
        manager::{PID2PCB, pid2process, wakeup_task},
        process_visible_in_pid_namespace,
        processor::{
            block_current_and_run_next, current_files, current_process, current_task,
            exit_current_and_run_next, exit_group_and_run_next,
        },
        signal::{
            RT_SIG_MAX, RtSigAction, SIG_DFL, SIG_IGN, SIGALRM_NUM, SIGCONT_NUM, SIGKILL_NUM,
            SIGSTOP_NUM, SIGTSTP_NUM, SIGTTIN_NUM, SIGTTOU_NUM, SignalAction, SignalFlags,
            can_signal_process, has_wait_interrupting_pending, kill, kill_current,
            request_reschedule_for_signal_target, set_signal, set_signal_mask, signal_bit,
            take_first_unmasked,
        },
        task_block::{SigSavedContext, TaskControlBlock, TaskStatus},
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

fn translate_sender_pid_for_receiver(sender_pid: i32) -> i32 {
    if sender_pid <= 0 {
        return 0;
    }
    let receiver = current_process();
    let receiver_ns_id = receiver.pid_namespace_id();
    let Some(sender) = pid2process(sender_pid as usize) else {
        return 0;
    };
    if receiver_ns_id == 0 {
        return sender.getpid() as i32;
    }
    if !process_visible_in_pid_namespace(&sender, receiver_ns_id) {
        return 0;
    }
    if sender.pid_namespace_id() == receiver_ns_id {
        sender.visible_pid() as i32
    } else {
        sender.getpid() as i32
    }
}

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
    let (parent, tracer_pid) = {
        let inner = child.borrow_mut();
        (
            inner.parent.as_ref().and_then(|p| p.upgrade()),
            inner.ptrace_tracer_pid,
        )
    };

    let mut parent_pid = None;
    if let Some(parent) = parent {
        parent_pid = Some(parent.getpid());
        crate::task::signal::queue_process_signal(parent.getpid(), SIGCHLD);
        let waiters = {
            let mut parent_inner = parent.borrow_mut();
            parent_inner.wait_queue.drain(..).collect::<Vec<_>>()
        };
        for waiter in waiters {
            wakeup_task(waiter);
        }
    }

    if let Some(tracer_pid) = tracer_pid {
        if parent_pid != Some(tracer_pid) {
            if let Some(tracer) = pid2process(tracer_pid) {
                crate::task::signal::queue_process_signal(tracer.getpid(), SIGCHLD);
                let waiters = {
                    let mut tracer_inner = tracer.borrow_mut();
                    tracer_inner.wait_queue.drain(..).collect::<Vec<_>>()
                };
                for waiter in waiters {
                    wakeup_task(waiter);
                }
            }
        }
    }
}

fn find_task_by_linux_tid(tid: usize) -> Option<(Arc<ProcessControlBlock>, Arc<TaskControlBlock>)> {
    if let Some(proc) = pid2process(tid) {
        let main_task = proc.task_at(0);
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
        let tasks = proc.indexed_tasks_snapshot();
        for (idx, task) in tasks {
            if encode_linux_tid(pid, idx) == tid {
                return Some((proc.clone(), task));
            }
        }
    }
    None
}

fn queue_signal_to_task(
    task: Arc<TaskControlBlock>,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
    si_code: i32,
    sig_value: usize,
) {
    let Some(bit) = signal_bit(signum) else {
        return;
    };
    {
        let mut inner = task.borrow_mut();
        inner.pending_signals |= bit;
        if signum <= RT_SIG_MAX {
            inner.pending_signal_pid[signum] = sender_pid;
            inner.pending_signal_uid[signum] = sender_uid;
            inner.pending_signal_code[signum] = si_code;
            inner.pending_signal_value[signum] = sig_value;
        }
    }
    task.mark_signal_pending();
    let on_cpu = task.on_cpu.load(Ordering::Acquire);
    request_reschedule_for_signal_target(&task);
    wakeup_task(task.clone());
    request_reschedule_for_signal_target(&task);
    if on_cpu != TaskControlBlock::OFF_CPU {
        arch::send_ipi(on_cpu);
    }
}

pub(crate) fn queue_signal_with_info(
    target_pid: usize,
    target_tid: Option<usize>,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
    si_code: i32,
    sig_value: usize,
) -> isize {
    if signum == 0 || signum > RT_SIG_MAX {
        return err(SyscallError::EINVAL);
    }
    let Some(process) = pid2process(target_pid) else {
        return err(SyscallError::ESRCH);
    };

    if let Some(tid) = target_tid {
        let Some((tid_proc, task)) = find_task_by_linux_tid(tid) else {
            return err(SyscallError::ESRCH);
        };
        if tid_proc.getpid() != target_pid {
            return err(SyscallError::ESRCH);
        }
        queue_signal_to_task(task, signum, sender_pid, sender_uid, si_code, sig_value);
        return 0;
    }

    let bit = signal_bit(signum).unwrap();
    let tasks = process.tasks_snapshot();
    let Some(task) = crate::task::signal::pick_task_for_signal(&tasks, bit) else {
        return err(SyscallError::ESRCH);
    };
    queue_signal_to_task(task, signum, sender_pid, sender_uid, si_code, sig_value);
    0
}

fn rt_sigpending_limit_reached(proc: &Arc<ProcessControlBlock>, signum: usize) -> bool {
    if signum <= crate::task::signal::MAX_SIG {
        return false;
    }
    let limit = {
        let inner = proc.borrow_mut();
        inner.rlimits.rlimit_sigpending_cur
    };
    let tasks = proc.tasks_snapshot();
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

fn sig_bit(sig: usize) -> Option<u64> {
    if sig == 0 || sig > 64 {
        return None;
    }
    Some(1u64 << (sig - 1))
}

// pub fn syscall_sigreturn() -> isize {
//     sigreturn()
// }

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
