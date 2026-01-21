// os/src/syscall/thread.rs

use alloc::sync::Arc;

use crate::{
    arch,
    mm::kernel_token,
    time::get_time_ms,
    task::{
        block_sleep::add_timer,
        manager::{add_task, select_hart_for_new_task},
        processor::{block_current_and_run_next, current_task},
        signal::has_unmasked_pending,
        task_block::TaskControlBlock,
    },
    trap::{context::TrapContext, trap_handler},
};
use crate::debug_config::{DEBUG_CYCLICTEST, DEBUG_TIMER};

pub fn sys_thread_create(entry: usize, arg: usize) -> isize {
    const ENOMEM: isize = -12;
    let task = current_task().unwrap();
    let process = task.process.upgrade().unwrap();
    let ustack_base = task.borrow_mut().res.as_ref().unwrap().ustack_base;
    // create a new thread
    let Some(new_task) =
        TaskControlBlock::try_new(Arc::clone(&process), ustack_base, true).map(Arc::new)
    else {
        return ENOMEM;
    };
    // Spread newly created threads across harts (Linux-like: task has a target cpu).
    new_task.set_cpu_id(select_hart_for_new_task());

    // Fully initialize the new thread (PCB slot + TrapContext) *before* enqueueing it.
    // Otherwise, another hart might schedule it and jump to user with an uninitialized TrapContext.
    let new_task_tid = {
        let mut new_task_inner = new_task.borrow_mut();
        let new_task_res = new_task_inner.res.as_ref().unwrap();
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
            new_task.kstack.get_top(),
            trap_handler as usize,
        );
        (*new_task_trap_cx).x[10] = arg;
        new_task_tid
    };

    // add new task to scheduler
    add_task(Arc::clone(&new_task));
    new_task_tid as isize
}

pub fn sys_gettid() -> isize {
    current_task()
        .unwrap()
        .borrow_mut()
        .res
        .as_ref()
        .unwrap()
        .tid as isize
}

/// thread does not exist, return -1
/// thread has not exited yet, return -2
/// otherwise, return thread's exit code
pub fn sys_waittid(tid: usize) -> i32 {
    let task = current_task().unwrap();
    let process = task.process.upgrade().unwrap();

    // Get current tid without holding locks across other borrows.
    let self_tid = {
        let task_inner = task.borrow_mut();
        task_inner.res.as_ref().unwrap().tid
    };
    // a thread cannot wait for itself
    if self_tid == tid {
        return -1;
    }

    // Clone the waited task Arc while holding the PCB lock, then drop the PCB lock
    // before borrowing the waited task's TCB. This avoids a deadlock where:
    // - waiter holds PCB lock and wants waited TCB lock
    // - waited thread holds its TCB lock and drops TaskUserRes (needs PCB lock)
    let waited_task = {
        let process_inner = process.borrow_mut();
        process_inner.tasks.get(tid).and_then(|t| t.as_ref()).cloned()
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
    // Edge case: sleeping for 0ms should return immediately.
    // Blocking here can hang if no timer tick arrives and wakes us up
    // (or if the wakeup happens before we actually block).
    if time_ms == 0 {
        return 0;
    }
    let task = current_task().unwrap();
    let tid = if DEBUG_TIMER || DEBUG_CYCLICTEST {
        task.borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX)
    } else {
        usize::MAX
    };
    if DEBUG_TIMER {
        crate::println!(
            "[sleep] tid={} request_ms={} now_ms={}",
            tid,
            time_ms,
            get_time_ms()
        );
    }
    if DEBUG_CYCLICTEST && time_ms > 2_000 {
        log::warn!("[sleep] tid={} long sleep request_ms={}", tid, time_ms);
    }
    // Prevent "lost wakeup": make the enqueue+block sequence atomic w.r.t. timer interrupts.
    // Keep interrupts disabled in kernel code paths; restore the previous SIE state after we
    // resume from sleep. (The trap return path controls interrupt enabling for user mode.)
    let prev_sie = arch::disable_interrupts();
    {
        let mut inner = task.borrow_mut();
        inner.task_status = crate::task::task_block::TaskStatus::Blocked;
    }
    add_timer(Arc::clone(&task), time_ms);
    // This will take the task out of PROCESSOR and switch to idle, letting the scheduler run.
    block_current_and_run_next();
    arch::restore_interrupts(prev_sie);
    const EINTR: isize = -4;
    let interrupted = {
        let inner = task.borrow_mut();
        has_unmasked_pending(inner.pending_signals, inner.signal_mask, false)
    };
    if interrupted {
        return EINTR;
    }
    if DEBUG_TIMER {
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        crate::println!(
            "[sleep] tid={} woke now_ms={} slept_for~={}ms",
            tid,
            get_time_ms(),
            time_ms
        );
    }
    0
}
