// os/src/syscall/thread.rs

use alloc::sync::Arc;

use crate::syscall::error::{SyscallError, err};

use crate::debug_config::{DEBUG_CYCLICTEST, DEBUG_SIGNAL, DEBUG_TIMER};
use crate::{
    arch,
    arch::REG_A0,
    mm::kernel_token,
    task::{
        block_sleep::add_timer_ns,
        manager::{add_task, select_hart_for_new_task},
        processor::{block_current_and_run_next, current_task},
        signal::has_wait_interrupting_pending,
        task_block::TaskControlBlock,
    },
    time::get_time_ms,
    trap::{context::TrapContext, trap_handler},
};

pub fn sys_thread_create(entry: usize, arg: usize) -> isize {
    let task = current_task().expect("sys_thread_create: no current task");
    let Some(process) = task.process.upgrade() else {
        return -1;
    };
    let Some(ustack_base) = task.borrow_mut().res.as_ref().map(|r| r.ustack_base) else {
        return -1;
    };
    let parent_scheduling = task.scheduling_snapshot();
    // create a new thread
    let new_task = match TaskControlBlock::try_new(Arc::clone(&process), ustack_base, true) {
        Ok(t) => Arc::new(t),
        Err(e) => return err(SyscallError::from(e)),
    };
    new_task.set_scheduling_snapshot(parent_scheduling);
    // Spread newly created threads across harts (Linux-like: task has a target cpu).
    new_task.set_cpu_id(select_hart_for_new_task());

    // Fully initialize the new thread (PCB slot + TrapContext) *before* enqueueing it.
    // Otherwise, another hart might schedule it and jump to user with an uninitialized TrapContext.
    let new_task_tid = {
        let new_task_inner = new_task.borrow_mut();
        let Some(new_task_res) = new_task_inner.res.as_ref() else {
            return -1;
        };
        let new_task_tid = new_task_res.tid;

        // add new thread to current process
        {
            let mut process_inner = process.borrow_mut();
            let tasks = &mut process_inner.tasks;
            while tasks.len() < new_task_tid + 1 {
                tasks.push(None);
            }
            tasks[new_task_tid] = Some(Arc::clone(&new_task));
        }

        let new_task_trap_cx = new_task_inner.get_trap_cx();
        *new_task_trap_cx = TrapContext::app_init_context(
            entry,
            new_task_res.ustack_top(),
            kernel_token(),
            new_task.kstack_top(),
            trap_handler as usize,
        );
        (*new_task_trap_cx).x[REG_A0] = arg;
        new_task_tid
    };

    // add new task to scheduler
    add_task(Arc::clone(&new_task));
    new_task_tid as isize
}

pub fn sys_gettid() -> isize {
    let task = current_task().expect("sys_gettid: no current task");
    let inner = task.borrow_mut();
    let Some(res) = inner.res.as_ref() else {
        return -1;
    };
    res.tid as isize
}

/// thread does not exist, return -1
/// thread has not exited yet, return -2
/// otherwise, return thread's exit code
pub fn sys_waittid(tid: usize) -> i32 {
    let task = current_task().expect("sys_waittid: no current task");
    let Some(process) = task.process.upgrade() else {
        return -1;
    };

    // Get current tid without holding locks across other borrows.
    let self_tid = {
        let task_inner = task.borrow_mut();
        let Some(res) = task_inner.res.as_ref() else {
            return -1;
        };
        res.tid
    };
    // a thread cannot wait for itself
    if self_tid == tid {
        return err(SyscallError::EPERM) as i32;
    }

    // Clone the waited task Arc while holding the PCB lock, then drop the PCB lock
    // before borrowing the waited task's TCB. This avoids a deadlock where:
    // - waiter holds PCB lock and wants waited TCB lock
    // - waited thread holds its TCB lock and drops TaskUserRes (needs PCB lock)
    let waited_task = {
        let process_inner = process.borrow_mut();
        process_inner
            .tasks
            .get(tid)
            .and_then(|t| t.as_ref())
            .cloned()
    };
    let waited_task = match waited_task {
        Some(t) => t,
        None => return -1, // waited thread does not exist
    };

    loop {
        // Check exit code (and enqueue ourselves as a join waiter) by locking only the waited TCB.
        {
            let mut waited_inner = waited_task.borrow_mut();
            if let Some(exit_code) = waited_inner.exit_code {
                // Dealloc the exited thread entry in PCB.
                let mut process_inner = process.borrow_mut();
                if let Some(slot) = process_inner.tasks.get_mut(tid) {
                    // Only clear if it still points to the same TCB.
                    if let Some(existing) = slot.as_ref() {
                        if Arc::ptr_eq(existing, &waited_task) {
                            *slot = None;
                        }
                    }
                }
                return exit_code;
            }
            waited_inner.join_waiters.push_back(task.clone());
        } // drop waited_inner

        // Block until the waited thread exits and wakes us.
        block_current_and_run_next();
        // After waking, loop and re-check exit_code.
    }
}

pub fn sys_sleep(time_ms: usize) -> isize {
    sys_sleep_duration_ns((time_ms as u64).saturating_mul(1_000_000), Some(time_ms))
}

pub fn sys_sleep_ns(time_ns: u64) -> isize {
    sys_sleep_duration_ns(time_ns, None)
}

fn sys_sleep_duration_ns(time_ns: u64, request_ms: Option<usize>) -> isize {
    // Edge case: zero-duration sleep should return immediately.
    // Blocking here can hang if no timer tick arrives and wakes us up
    // (or if the wakeup happens before we actually block).
    if time_ns == 0 {
        return 0;
    }
    let task = current_task().expect("sys_sleep: no current task");
    let tid = if DEBUG_TIMER || DEBUG_CYCLICTEST {
        task.borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX)
    } else {
        usize::MAX
    };
    let start_ms = if DEBUG_SIGNAL {
        Some(get_time_ms())
    } else {
        None
    };
    if DEBUG_TIMER {
        crate::println!(
            "[sleep] tid={} request_ns={} request_ms={:?} now_ms={}",
            tid,
            time_ns,
            request_ms,
            get_time_ms()
        );
    }
    if DEBUG_CYCLICTEST && time_ns > 2_000_000_000 {
        log::warn!("[sleep] tid={} long sleep request_ns={}", tid, time_ns);
    }
    // Prevent "lost wakeup": make the enqueue+block sequence atomic w.r.t. timer interrupts.
    // Keep interrupts disabled in kernel code paths; restore the previous SIE state after we
    // resume from sleep. (The trap return path controls interrupt enabling for user mode.)
    let prev_sie = arch::disable_interrupts();
    {
        let mut inner = task.borrow_mut();
        inner.task_status = crate::task::task_block::TaskStatus::Blocked;
    }
    add_timer_ns(Arc::clone(&task), time_ns);
    // This will take the task out of PROCESSOR and switch to idle, letting the scheduler run.
    block_current_and_run_next();
    arch::restore_interrupts(prev_sie);
    const EINTR: isize = -4;
    let interrupted = {
        let inner = task.borrow_mut();
        has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
    };
    if interrupted {
        let (tid, pending, mask) = {
            let inner = task.borrow_mut();
            (
                inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX),
                inner.pending_signals,
                inner.signal_mask,
            )
        };
        crate::log_if!(
            DEBUG_SIGNAL,
            info,
            "[sleep] tid={} interrupted now_ms={} pending={:#x} mask={:#x}",
            tid,
            get_time_ms(),
            pending,
            mask
        );
        return EINTR;
    }
    if let Some(start_ms) = start_ms {
        crate::log_if!(
            DEBUG_SIGNAL,
            info,
            "[sleep] tid={} woke now_ms={} elapsed_ms={} req_ms={}",
            task.borrow_mut()
                .res
                .as_ref()
                .map(|r| r.tid)
                .unwrap_or(usize::MAX),
            get_time_ms(),
            get_time_ms().saturating_sub(start_ms),
            request_ms.unwrap_or_else(|| ((time_ns + 999_999) / 1_000_000) as usize)
        );
    }
    if DEBUG_TIMER {
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        crate::println!(
            "[sleep] tid={} woke now_ms={} slept_for~={}ns",
            tid,
            get_time_ms(),
            time_ns
        );
    }
    0
}
