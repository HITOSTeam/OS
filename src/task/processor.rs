use crate::{
    arch,
    config::MAX_HARTS,
    fs::{cgroup_exit_process, cgroup_exit_thread},
    mm::{try_write_user_value, MemorySet},
    println,
    syscall::futex::futex_wake_private_and_shared,
    task::{
        id::{KernelStack, TaskUserRes},
        manager::{
            add_task, fetch_task, has_ready_rt_at_or_above, has_ready_rt_higher_than,
            remove_inactive_task, wakeup_task, PID2PCB, TASK_MANAGER,
        },
        process_block::ProcessControlBlock,
        sched::{sched_class, SchedClass, RR_TIMESLICE_TICKS, RT_PRIO_MIN},
        switch,
        task_block::{TaskControlBlock, TaskStatus},
        task_context::{self, TaskContext},
        INITPROC,
    },
    trap::init_trap,
};
use alloc::{collections::VecDeque, sync::Arc, task, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use lazy_static::lazy_static;
use log;
use spin::Mutex;

use crate::debug_config::{DEBUG_PTHREAD, DEBUG_SCHED};

static TASK_DROP_QUEUED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static TASK_DROP_DONE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static TASK_DROP_REF_DIAG_SEQ: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static TASK_FETCH_REF_DIAG_SEQ: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

fn should_log_pow2(v: usize) -> bool {
    v >= 64 && (v & (v - 1)) == 0
}

fn maybe_log_task_drop(event: &str) {
    if !crate::debug_config::DEBUG_TASK_LIFECYCLE {
        return;
    }
    let queued = TASK_DROP_QUEUED.load(core::sync::atomic::Ordering::Relaxed);
    let done = TASK_DROP_DONE.load(core::sync::atomic::Ordering::Relaxed);
    let inflight = queued.saturating_sub(done);
    if should_log_pow2(inflight) || should_log_pow2(queued) || should_log_pow2(done) {
        crate::println!(
            "[task-drop] event={} inflight={} queued={} done={}",
            event,
            inflight,
            queued,
            done
        );
    }
}

fn kill_pid_namespace_members_on_init_exit(process: &Arc<ProcessControlBlock>) {
    let (pid, ns_id, is_ns_init) = {
        let inner = process.borrow_mut();
        (process.getpid(), inner.pid_ns_id, inner.pid_ns_init)
    };
    if !is_ns_init || ns_id == 0 {
        return;
    }
    for member_pid in crate::task::pid_namespace_member_pids(ns_id) {
        if member_pid == pid {
            continue;
        }
        let Some(member) = crate::task::manager::pid2process(member_pid) else {
            continue;
        };
        if member.borrow_mut().is_zombie {
            continue;
        }
        crate::task::signal::queue_process_signal(member_pid, crate::task::signal::SIGKILL_NUM);
    }
}

fn queue_exiting_task_drop(task: Arc<TaskControlBlock>) {
    if crate::debug_config::DEBUG_TASK_LIFECYCLE {
        let seq = TASK_DROP_REF_DIAG_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
        if seq <= 16 || (seq & (seq - 1)) == 0 {
            let strong = Arc::strong_count(&task);
            let processes = {
                let map = PID2PCB.lock();
                map.values().cloned().collect::<Vec<_>>()
            };
            let runqueue_refs = crate::task::manager::debug_count_task_refs_in_runqueues(&task);
            let processor_refs = debug_count_task_refs_in_processors(&task);
            let timer_refs = crate::task::block_sleep::debug_count_task_refs_in_timers(&task);
            let futex_refs = crate::syscall::futex::debug_count_task_waiters(&task);
            let record_lock_refs =
                crate::syscall::filesystem::debug_count_record_lock_waiters_for_task(&task);
            let (self_join_len, self_join_self_refs, tid) = {
                let inner = task.borrow_mut();
                (
                    inner.join_waiters.len(),
                    inner
                        .join_waiters
                        .iter()
                        .filter(|w| Arc::ptr_eq(w, &task))
                        .count(),
                    inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX),
                )
            };
            let mut task_slots = 0usize;
            let mut wait_queues = 0usize;
            let mut join_waiters = 0usize;
            let mut sem_waiters = 0usize;
            let mut condvar_waiters = 0usize;
            let mut mutex_waiters = 0usize;
            for process in processes {
                if let Some(inner) = process.try_borrow_mut() {
                    task_slots = task_slots.saturating_add(
                        inner
                            .tasks
                            .iter()
                            .filter(|slot| {
                                slot.as_ref()
                                    .map(|holder| Arc::ptr_eq(holder, &task))
                                    .unwrap_or(false)
                            })
                            .count(),
                    );
                    wait_queues = wait_queues.saturating_add(
                        inner
                            .wait_queue
                            .iter()
                            .filter(|holder| Arc::ptr_eq(holder, &task))
                            .count(),
                    );
                    for holder in inner.tasks.iter().filter_map(|slot| slot.as_ref()) {
                        if Arc::ptr_eq(holder, &task) {
                            continue;
                        }
                        if let Some(holder_inner) = holder.try_borrow_mut() {
                            join_waiters = join_waiters.saturating_add(
                                holder_inner
                                    .join_waiters
                                    .iter()
                                    .filter(|w| Arc::ptr_eq(w, &task))
                                    .count(),
                            );
                        }
                    }
                    for sem in inner.semaphore_list.iter().filter_map(|s| s.as_ref()) {
                        sem_waiters = sem_waiters.saturating_add(
                            sem.inner
                                .lock()
                                .wait_queue
                                .iter()
                                .filter(|w| Arc::ptr_eq(w, &task))
                                .count(),
                        );
                    }
                    for condvar in inner.condvar_list.iter().filter_map(|c| c.as_ref()) {
                        condvar_waiters = condvar_waiters.saturating_add(
                            condvar
                                .inner
                                .lock()
                                .wait_queue
                                .iter()
                                .filter(|w| Arc::ptr_eq(w, &task))
                                .count(),
                        );
                    }
                    for mutex in inner.mutex_list.iter().filter_map(|m| m.as_ref()) {
                        mutex_waiters =
                            mutex_waiters.saturating_add(mutex.debug_count_waiters_for_task(&task));
                    }
                }
            }
            let pipe_waiters = crate::fs::debug_count_pipe_waiters_for_task(&task);
            crate::println!(
                "[task-drop-ref] phase=queue seq={} tid={} strong={} rq={} proc={} timer={} futex={} rec_lock={} task_slots={} waitq={} join={} sem={} cond={} mutex={} pipe={} self_join_len={} self_join_self={}",
                seq,
                tid,
                strong,
                runqueue_refs,
                processor_refs,
                timer_refs,
                futex_refs,
                record_lock_refs,
                task_slots,
                wait_queues,
                join_waiters,
                sem_waiters,
                condvar_waiters,
                mutex_waiters,
                pipe_waiters,
                self_join_len,
                self_join_self_refs
            );
        }
    }
    // Detach the kernel stack now, but free it only after switching to idle.
    // This keeps stack reclamation independent from lingering task Arc refs.
    let kstack = task.take_kstack();
    let mut processor = local_processor().lock();
    if let Some(kstack) = kstack {
        processor.set_pending_kstack_drop(kstack);
    }
    processor.set_pending_drop(task);
    drop(processor);
    TASK_DROP_QUEUED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    maybe_log_task_drop("queue");
}

fn clear_child_tid_now(pid: usize, token: usize, ctid: usize) {
    if ctid == 0 {
        return;
    }
    let _ = try_write_user_value(token, ctid as *mut i32, &0);
    let _ = futex_wake_private_and_shared(pid, token, ctid, 1);
}

fn fair_timeslice_ticks(nice: i32) -> usize {
    // A very short fair slice causes excessive context-switch churn under
    // fork-heavy workloads (e.g. LTP msgstress) where many sleepers wake up
    // briefly and can starve the task that is still constructing the workload.
    // Keep a coarser minimum granularity while preserving longer quanta for
    // higher-priority (negative nice) threads.
    const FAIR_BASE_SLICE_TICKS: usize = 12;
    if nice < 0 {
        (FAIR_BASE_SLICE_TICKS + (-nice as usize)).min(20)
    } else {
        FAIR_BASE_SLICE_TICKS
    }
}

/// Best-effort per-thread CPU accounting used by *_CPUTIME clocks.
pub fn account_current_task_tick() {
    const TICK_NS: u64 = 10_000_000; // 100Hz
    let Some(task) = current_task() else {
        return;
    };
    let mut inner = task.borrow_mut();
    inner.cpu_time_ns = inner.cpu_time_ns.saturating_add(TICK_NS);
}
pub struct Processor {
    now_task_block: Option<Arc<TaskControlBlock>>,
    idle_task_context: TaskContext,
    /// A task that should be enqueued after we have switched back to idle.
    ///
    /// This avoids a race where we would put the current task back into the global
    /// ready queue *before* context switching away, letting another hart run the
    /// same task concurrently on the same kernel stack.
    pending_ready: Option<Arc<TaskControlBlock>>,
    /// A task that is transitioning into Blocked state; finalized after switching to idle.
    pending_blocked: Option<Arc<TaskControlBlock>>,
    /// A task to drop after switching to idle (safe to free its kernel stack).
    pending_drop: VecDeque<Arc<TaskControlBlock>>,
    /// Kernel stacks to drop after switching to idle.
    pending_kstack_drop: VecDeque<KernelStack>,
}
impl Processor {
    pub fn new() -> Self {
        Self {
            now_task_block: None,
            idle_task_context: TaskContext::new(),
            pending_ready: None,
            pending_blocked: None,
            pending_drop: VecDeque::new(),
            pending_kstack_drop: VecDeque::new(),
        }
    }
    pub fn get_idle_task_ptr(&mut self) -> *mut TaskContext {
        &mut self.idle_task_context as *mut _
    }

    pub fn take_current_task(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.now_task_block.take()
    }
    pub fn current(&self) -> Option<Arc<TaskControlBlock>> {
        self.now_task_block.as_ref().cloned()
    }

    pub fn take_pending_ready(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.pending_ready.take()
    }

    pub fn set_pending_ready(&mut self, task: Arc<TaskControlBlock>) {
        self.pending_ready = Some(task);
    }

    pub fn take_pending_blocked(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.pending_blocked.take()
    }

    pub fn set_pending_blocked(&mut self, task: Arc<TaskControlBlock>) {
        self.pending_blocked = Some(task);
    }

    pub fn take_pending_drop(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.pending_drop.pop_front()
    }

    pub fn set_pending_drop(&mut self, task: Arc<TaskControlBlock>) {
        self.pending_drop.push_back(task);
    }

    pub fn take_pending_kstack_drop(&mut self) -> Option<KernelStack> {
        self.pending_kstack_drop.pop_front()
    }

    pub fn set_pending_kstack_drop(&mut self, kstack: KernelStack) {
        self.pending_kstack_drop.push_back(kstack);
    }
}
pub fn current_task() -> Option<Arc<TaskControlBlock>> {
    let processor = local_processor().lock();
    let task = processor.current();
    drop(processor);
    task
}
pub fn current_process() -> Arc<ProcessControlBlock> {
    current_task()
        .and_then(|task| task.process.upgrade())
        .unwrap_or_else(|| {
            if DEBUG_SCHED {
                log::warn!("[sched] no current task, fall back to init process");
            }
            INITPROC.clone()
        })
}

/// Resolve the process that owns the current task's file table.
pub fn current_files_process() -> Arc<ProcessControlBlock> {
    let process = current_process();
    process.files_owner_process()
}

// todo
pub fn current_process_has_child(pid_or_negative: isize, exit_code: &mut i32) -> Option<usize> {
    // 获取当前任务（当前正在运行的进程）
    let pid = pid_or_negative;

    let cur_process = current_process();
    // Clone children_vec in a separate scope to release the borrow immediately
    let children_vec = {
        let process_inner = cur_process.borrow_mut();
        process_inner.children.clone()
    }; // process_inner is dropped here, releasing the borrow

    // 遍历当前任务的所有子任务
    let mut possible_index: Option<usize> = None;
    let mut found_pid: Option<usize> = None;

    for (index, child) in children_vec.iter().enumerate() {
        // 匹配 pid 且子进程已退出
        let child_inner = child.borrow_mut();
        if (pid == -1 || child.pid.0 == pid as usize) && child_inner.is_zombie {
            // 将退出码写入 exit_code
            *exit_code = child_inner.exit_code;
            possible_index = Some(index);
            found_pid = Some(child.pid.0);
            drop(child_inner);
            break;
        }
        drop(child_inner);
    }

    if let Some(pid_index) = possible_index {
        // Remove the child from parent's children list
        let mut process_inner = cur_process.borrow_mut();
        let child = process_inner.children.remove(pid_index);
        drop(process_inner);
        // The child process will be deallocated when Arc count reaches 0
        return found_pid;
    }
    None
}

pub fn debug_count_task_refs_in_processors(task: &Arc<TaskControlBlock>) -> usize {
    PROCESSORS
        .iter()
        .map(|p| {
            let p = p.lock();
            let mut count = 0usize;
            if p.now_task_block
                .as_ref()
                .map(|t| Arc::ptr_eq(t, task))
                .unwrap_or(false)
            {
                count = count.saturating_add(1);
            }
            if p.pending_ready
                .as_ref()
                .map(|t| Arc::ptr_eq(t, task))
                .unwrap_or(false)
            {
                count = count.saturating_add(1);
            }
            if p.pending_blocked
                .as_ref()
                .map(|t| Arc::ptr_eq(t, task))
                .unwrap_or(false)
            {
                count = count.saturating_add(1);
            }
            count = count.saturating_add(
                p.pending_drop
                    .iter()
                    .filter(|t| Arc::ptr_eq(t, task))
                    .count(),
            );
            count
        })
        .sum()
}

pub fn take_current_task() -> Option<Arc<TaskControlBlock>> {
    let mut processor = local_processor().lock();
    let task = processor.take_current_task();
    drop(processor);
    task
}
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    let mut processor = local_processor().lock();
    let idle_task_cx_ptr = processor.get_idle_task_ptr();
    drop(processor);
    // println!(
    //     "schedule: switch from {:x} to {:x}",
    //     switched_task_cx_ptr as usize, idle_task_cx_ptr as usize
    // );
    unsafe {
        switch::switch(
            switched_task_cx_ptr as *const usize,
            idle_task_cx_ptr as *const usize,
        );
    }
}

/// Linux-like tick preemption policy:
/// - FAIR class: preempt on every tick.
/// - FIFO class: only preempt when a higher-priority RT task is waiting.
/// - RR class: round-robin at fixed quantum, but still preempt immediately for higher RT prio.
pub fn should_preempt_current_on_tick() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let Some(process) = task.process.upgrade() else {
        return true;
    };
    let (policy, rt_prio) = {
        let inner = process.borrow_mut();
        (inner.sched_policy, inner.sched_priority)
    };
    match sched_class(policy) {
        Some(SchedClass::Fair) | None => {
            if has_ready_rt_at_or_above(RT_PRIO_MIN) {
                return true;
            }
            let mut task_inner = task.borrow_mut();
            task_inner.rr_ticks = task_inner.rr_ticks.saturating_add(1);
            let slice = fair_timeslice_ticks(task_inner.nice);
            if task_inner.rr_ticks < slice {
                return false;
            }
            task_inner.rr_ticks = 0;
            true
        }
        Some(SchedClass::Fifo) => has_ready_rt_higher_than(rt_prio),
        Some(SchedClass::Rr) => {
            if has_ready_rt_higher_than(rt_prio) {
                return true;
            }
            let mut task_inner = task.borrow_mut();
            task_inner.rr_ticks = task_inner.rr_ticks.saturating_add(1);
            if task_inner.rr_ticks < RR_TIMESLICE_TICKS.max(1) {
                return false;
            }
            task_inner.rr_ticks = 0;
            has_ready_rt_at_or_above(rt_prio)
        }
    }
}
pub fn idle_task() {
    #[allow(dead_code)]
    static EMPTY_SPINS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    static IDLE_FIRST_LOG: AtomicBool = AtomicBool::new(true);
    static IDLE_FIRST_SWITCH_LOG: AtomicBool = AtomicBool::new(true);
    loop {
        // Ensure kernel-mode traps use the kernel handler (stvec points to alltraps_k)
        init_trap();
        if IDLE_FIRST_LOG.swap(false, Ordering::SeqCst) {
            let hart = hart_id();
            let mgr = crate::task::manager::TASK_MANAGER.lock();
            let lens = mgr.ready_queue_lengths();
            drop(mgr);
            println!("[idle] enter hart={} ready_queues={:?}", hart, lens);
        }
        // Disable interrupts while accessing TASK_MANAGER to prevent
        // timer interrupt from calling check_timer -> wakeup_task -> add_task
        // while we hold the TASK_MANAGER lock in fetch_task
        let _ = arch::disable_interrupts();

        // Finalize a task that just switched away and wanted to become Blocked.
        if let Some(task) = local_processor().lock().take_pending_blocked() {
            // The task is now off CPU on this hart.
            task.clear_on_cpu();
            if task
                .wakeup_pending
                .swap(false, core::sync::atomic::Ordering::AcqRel)
            {
                let mut inner = task.borrow_mut();
                inner.task_status = TaskStatus::Ready;
                drop(inner);
                add_task(task);
            }
        }

        // Enqueue a task that was marked runnable by this hart *before* it switched
        // to idle. This makes the task visible to other harts only after we are
        // no longer running on its kernel stack.
        if let Some(task) = local_processor().lock().take_pending_ready() {
            task.clear_on_cpu();
            task.wakeup_pending
                .store(false, core::sync::atomic::Ordering::Release);
            add_task(task);
        }

        while let Some(task) = local_processor().lock().take_pending_drop() {
            if crate::debug_config::DEBUG_TASK_LIFECYCLE {
                let seq = TASK_DROP_DONE.load(core::sync::atomic::Ordering::Relaxed) + 1;
                if seq <= 16 || (seq & (seq - 1)) == 0 {
                    let strong = Arc::strong_count(&task);
                    crate::println!(
                        "[task-drop-ref] phase=idle seq={} strong_refs={}",
                        seq,
                        strong
                    );
                }
            }
            task.clear_on_cpu();
            // Best-effort cleanup in process task tables.
            //
            // For zombie processes we prefer Linux-like eager release (clear slot now),
            // but if there are unexpected extra refs we keep the slot so wait4() can
            // still reap and drop the task deterministically.
            if let Some(process) = task.process.upgrade() {
                if let Some(mut inner) = process.try_borrow_mut() {
                    let keep_for_reap = inner.is_zombie && Arc::strong_count(&task) > 2;
                    if !keep_for_reap {
                        for slot in inner.tasks.iter_mut() {
                            if slot
                                .as_ref()
                                .map(|t| Arc::ptr_eq(t, &task))
                                .unwrap_or(false)
                            {
                                *slot = None;
                                break;
                            }
                        }
                    }
                }
            }
            drop(task);
            TASK_DROP_DONE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            maybe_log_task_drop("done");
        }

        while let Some(kstack) = local_processor().lock().take_pending_kstack_drop() {
            drop(kstack);
        }

        if let Some(task) = fetch_task() {
            arch::restore_user_fp_state(&task);
            if crate::debug_config::DEBUG_TASK_LIFECYCLE {
                let seq =
                    TASK_FETCH_REF_DIAG_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
                if seq <= 32 || (seq & (seq - 1)) == 0 {
                    let strong = Arc::strong_count(&task);
                    let pid = task
                        .process
                        .upgrade()
                        .map(|p| p.getpid())
                        .unwrap_or(usize::MAX);
                    let tid = task
                        .borrow_mut()
                        .res
                        .as_ref()
                        .map(|r| r.tid)
                        .unwrap_or(usize::MAX);
                    crate::println!(
                        "[task-fetch-ref] seq={} pid={} tid={} strong_refs={}",
                        seq,
                        pid,
                        tid,
                        strong
                    );
                }
            }
            if crate::debug_config::DEBUG_WATCHDOG {
                EMPTY_SPINS.store(0, core::sync::atomic::Ordering::Relaxed);
            }
            let mut processor = local_processor().lock();
            let idle_task_cx_ptr = processor.get_idle_task_ptr();
            // access coming task TCB exclusively
            let mut task_inner = task.borrow_mut();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
            if IDLE_FIRST_SWITCH_LOG.swap(false, Ordering::SeqCst) {
                let tid = task_inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
                let trap_cx = task_inner
                    .res
                    .as_ref()
                    .map(|r| r.trap_cx_user_va())
                    .unwrap_or(0);
                println!(
                    "[idle] switch hart={} tid={} ra={:#x} sp={:#x} trap_cx_va={:#x} trap_return={:#x}",
                    hart_id(),
                    tid,
                    task_inner.task_cx.ra,
                    task_inner.task_cx.sp,
                    trap_cx,
                    crate::trap::trap_return as usize
                );
            }
            if DEBUG_SCHED {
                let tid = task_inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
                log::debug!(
                    "[idle] hart={} switch to tid={} ra={:#x} sp={:#x}",
                    hart_id(),
                    tid,
                    task_inner.task_cx.ra,
                    task_inner.task_cx.sp
                );
            }
            // Keep kernel tp (hart id) in the trap context in sync for migrations.
            task_inner.get_trap_cx().kernel_tp = hart_id();
            task.mark_on_cpu(hart_id());
            task_inner.task_status = TaskStatus::Running;

            drop(task_inner);
            // release coming task TCB manually
            processor.now_task_block = Some(task);
            // release processor manually
            drop(processor);

            // Keep interrupts disabled while resuming kernel context; sret will enable them for user.
            unsafe {
                switch::switch(
                    idle_task_cx_ptr as *const usize,
                    next_task_cx_ptr as *const usize,
                );
            }
            if DEBUG_SCHED {
                log::debug!("[idle] hart={} switch returned to idle", hart_id());
            }
        } else {
            if crate::debug_config::DEBUG_WATCHDOG {
                let c = EMPTY_SPINS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if c == 1_000 {
                    crate::task::manager::dump_system_state();
                }
            }
            if crate::task::block_sleep::has_pending_timers() {
                // Poll timers while idle to avoid missing wakeups if interrupts are masked.
                crate::task::block_sleep::check_timer();
                core::hint::spin_loop();
                continue;
            }
            // crate::println!("[idle] No tasks, entering wfi...");
            // No ready tasks - enable interrupts and wait
            // Use wfi to save power while waiting for timer interrupt
            // Timer interrupt will call check_timer() to wake up sleeping tasks
            //
            // IMPORTANT: We must loop back to check fetch_task() after wfi returns
            // because the interrupt handler may have woken up a task
            arch::enable_interrupts();
            arch::wait_for_interrupt();
            // crate::println!("[idle] Woke up from wfi");
            // Loop back immediately to check for newly ready tasks
        }
    }
}

// ...existing code...
#[inline(always)]
pub fn set_tp(hart_id: usize) {
    arch::set_tp(hart_id);
}

pub fn hart_id() -> usize {
    arch::hart_id()
}

fn local_processor() -> &'static Mutex<Processor> {
    let id = hart_id();
    if id >= MAX_HARTS {
        panic!("hart id {} exceeds MAX_HARTS={}", id, MAX_HARTS);
    }
    &PROCESSORS[id]
}

lazy_static! {
    pub static ref PROCESSORS: Vec<Mutex<Processor>> = (0..MAX_HARTS)
        .map(|_| Mutex::new(Processor::new()))
        .collect();
}

pub fn go_to_first_task() -> ! {
    idle_task();
    panic!("Unreachable in go_to_first_task!");
}
pub fn suspend_current_and_run_next() {
    // If the current process has a fatal pending signal, terminate it even if we are
    // inside a long-running/blocking syscall loop (where we may never return to the
    // trap handler's "check signal then return to user" path).
    //
    // Use `try_borrow_mut` to avoid deadlocking if the caller already holds the PCB lock.
    if let Some((errno, msg)) = crate::task::signal::check_if_current_signals_error() {
        crate::println!("[kernel] {}", msg);
        exit_group_and_run_next(errno);
    }
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.borrow_mut();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    task_inner.task_status = TaskStatus::Ready;
    task_inner.rr_ticks = 0;
    drop(task_inner);
    // ---- release current PCB

    // Do NOT push back to the global ready queue here: another hart could pick
    // it up and run it while we are still executing on this task's kernel stack
    // inside the trap handler/syscall path.
    //
    // Instead, stash it on this hart and let `idle_task()` enqueue it after the
    // context switch completes.
    arch::save_user_fp_state(&task);
    local_processor().lock().set_pending_ready(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}
pub fn block_current_and_run_next() {
    // Same rationale as in `suspend_current_and_run_next()`: a task can be stuck
    // yielding within a syscall (interrupts disabled), so handle fatal signals here.
    if let Some((errno, msg)) = crate::task::signal::check_if_current_signals_error() {
        crate::println!("[kernel] {}", msg);
        exit_group_and_run_next(errno);
    }
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.borrow_mut();
    if crate::debug_config::DEBUG_TIMER {
        let tid = task_inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        log::debug!(
            "[block] tid={} status_before={:?}",
            tid,
            task_inner.task_status
        );
    }
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    let should_block = match task_inner.task_status {
        TaskStatus::Ready => false,
        TaskStatus::Running | TaskStatus::Blocked => true,
    };
    if should_block {
        task_inner.task_status = TaskStatus::Blocked;
    }
    task_inner.rr_ticks = 0;
    drop(task_inner);
    // ---- release current PCB

    if should_block {
        arch::save_user_fp_state(&task);
        local_processor().lock().set_pending_blocked(task);
    } else {
        // Behave like a yield: enqueue after we have switched back to idle
        // to avoid "run on two harts".
        arch::save_user_fp_state(&task);
        local_processor().lock().set_pending_ready(task);
    }
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}

/// pid of usertests app in make run TEST=1
pub const IDLE_PID: usize = 0;

// 线程(task)  单位的推出
pub fn exit_current_and_run_next(exit_code: i32) {
    // 标记线程状态,
    let task = take_current_task().unwrap();
    // This task will never be scheduled again; ensure it is considered off CPU.
    task.clear_on_cpu();
    let Some(process) = task.process.upgrade() else {
        if DEBUG_SCHED {
            log::warn!("[exit] task lost process; dropping task and scheduling idle");
        }
        queue_exiting_task_drop(task);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        return;
    };

    // Extract tid in a separate scope to release the borrow early.
    // Also drop TaskUserRes *after* releasing the TCB lock to avoid deadlocks with sys_waittid.
    let (tid, res_to_drop, join_waiters, clear_child_tid, robust_list_head, is_linux_thread) = {
        let mut task_inner = task.borrow_mut();
        task_inner.exit_code = Some(exit_code);
        let tid = task_inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        let is_linux_thread = task_inner
            .res
            .as_ref()
            .map(|r| r.is_linux_thread())
            .unwrap_or(false);
        let res_to_drop = task_inner.res.take();
        let clear_child_tid = task_inner.clear_child_tid.take();
        let robust_list_head = task_inner.robust_list_head;
        let join_waiters = task_inner.join_waiters.drain(..).collect::<Vec<_>>();
        (
            tid,
            res_to_drop,
            join_waiters,
            clear_child_tid,
            robust_list_head,
            is_linux_thread,
        )
    }; // task_inner dropped here

    let clear_child_tid_addr = clear_child_tid;
    let is_linux_thread = is_linux_thread || clear_child_tid_addr.is_some();

    let token = {
        let inner = process.borrow_mut();
        inner.memory_set.token()
    };

    if robust_list_head != 0 {
        let linux_tid = crate::syscall::misc::encode_linux_tid(process.getpid(), tid) as u32;
        crate::syscall::robust_list::exit_robust_list(
            process.getpid(),
            token,
            robust_list_head,
            linux_tid,
        );
    }

    // Linux pthreads expect CLONE_CHILD_CLEARTID/set_tid_address semantics:
    // clear *ctid to 0 and wake any futex waiters.
    if let Some(ctid) = clear_child_tid_addr {
        clear_child_tid_now(process.getpid(), token, ctid);
    }
    drop(res_to_drop);
    for waiter in join_waiters {
        wakeup_task(waiter);
    }

    if tid != 0 && tid != usize::MAX {
        if DEBUG_PTHREAD {
            log::debug!(
                "[thread_exit] pid={} tid={} ctid={:#x} linux_thread={}",
                process.getpid(),
                tid,
                clear_child_tid_addr.unwrap_or(0),
                is_linux_thread
            );
        }
        if is_linux_thread {
            cgroup_exit_thread(process.getpid(), tid);
            // For Linux threads, remove from the process task table immediately.
            // Joiners use futexes instead of waittid, so we don't need the slot.
            let mut process_inner = process.borrow_mut();
            if let Some(slot) = process_inner.tasks.get_mut(tid) {
                if slot
                    .as_ref()
                    .map(|t| Arc::ptr_eq(t, &task))
                    .unwrap_or(false)
                {
                    *slot = None;
                }
            }
        }
    }

    log::debug!(
        "[exit] pid={} tid={} exit_code={}",
        process.getpid(),
        tid,
        exit_code
    );

    let dumped_core = {
        let inner = process.borrow_mut();
        if exit_code >= 0 {
            false
        } else {
            let signum = (-exit_code) as usize;
            inner.rlimit_core_cur != 0 && crate::task::signal::signal_has_core_dump(signum)
        }
    };

    // 已经从current_task拿走了 所以 对于一般的 线程,可以了.
    //  对于主线程,我们需要处理一些 清理工作
    // 对于系统进程,直接推出
    // 一般进程
    // 1.将 进程标记为推出(主线程推出,进程推出)
    // 2.将 子进程 交给 initproc 进程
    // 3.回收资源
    //      回收资源的思路是: 将所有子线程的资源拿走,放到一个临时的 vec 中,通过 drop 进行回收
    //      然后回收 进程的内存空间,文件描述符
    // 对于主线程,需要进行更多的清理工作
    if tid == 0 {
        let pid = process.getpid();
        if pid == IDLE_PID {
            println!(
                "[kernel] Idle process exit with exit_code {} ...",
                exit_code
            );
            if exit_code != 0 {
                //crate::sbi::shutdown(255); //255 == -1 for err hint
                arch::shutdown();
            } else {
                //crate::sbi::shutdown(0); //0 for success hint
                arch::shutdown();
            }
        }
        // Mark zombie and capture parent pointer first...
        let parent = {
            let mut process_inner = process.borrow_mut();
            crate::syscall::process::unregister_executing_inode(
                process_inner.exec_inode_dev,
                process_inner.exec_inode_num,
            );
            process_inner.is_zombie = true;
            process_inner.dumped_core = dumped_core;
            process_inner.exit_code = exit_code;
            process_inner.parent.as_ref().and_then(|p| p.upgrade())
        }; // drop child PCB lock before touching parent to avoid lock inversion
        kill_pid_namespace_members_on_init_exit(&process);
        cgroup_exit_process(pid);
        crate::syscall::filesystem::acct_process_exit(&process, exit_code);

        // ...then wake parent waiters (waitpid) without holding the child PCB lock.
        if let Some(parent) = parent {
            crate::task::signal::queue_process_signal(
                parent.getpid(),
                crate::task::signal::SIGCHLD_NUM,
            );
            let waiters = {
                let mut parent_inner = parent.borrow_mut();
                parent_inner.wait_queue.drain(..).collect::<Vec<_>>()
            }; // drop parent lock
            for waiter in waiters {
                wakeup_task(waiter);
            }
        }

        let mut process_inner = process.borrow_mut();

        // 非 系统进程,执行之前的 将 子进程 交给 initproc 进程  过程
        {
            // move all child processes under init process
            let mut initproc_inner = INITPROC.borrow_mut();
            for child in process_inner.children.iter() {
                child.borrow_mut().parent = Some(Arc::downgrade(&INITPROC));
                initproc_inner.children.push(child.clone());
            }
        }

        // deallocate user res (including tid/trap_cx/ustack) of all threads
        // it has to be done before we dealloc the whole memory_set
        // otherwise they will be deallocated twice
        // 接下来,处理 线程资源回收
        // 首先先将 所有子线程的资源 载入
        let mut recycle_res = Vec::<TaskUserRes>::new();
        for task in process_inner.tasks.iter().filter(|t| t.is_some()) {
            let task = task.as_ref().unwrap();
            // if other tasks are Ready in TaskManager or waiting for a timer to be
            // expired, we should remove them.
            //
            // Mention that we do not need to consider Mutex/Semaphore since they
            // are limited in a single process. Therefore, the blocked tasks are
            // removed when the PCB is deallocated.
            remove_inactive_task(Arc::clone(&task));
            let mut task_inner = task.borrow_mut();
            if let Some(res) = task_inner.res.take() {
                recycle_res.push(res);
            }
        }
        // dealloc_tid and dealloc_user_res require access to PCB inner, so we
        // need to collect those user res first, then release process_inner
        // for now to avoid deadlock/double borrow problem.
        drop(process_inner);
        recycle_res.clear();
        process.handoff_files_owner_on_exit();

        let mut process_inner = process.borrow_mut();
        process_inner.children.clear();
        let old_shm = core::mem::take(&mut process_inner.sysv_shm_attaches);
        crate::syscall::sysv_shm::exit_cleanup(process_inner.ipc_ns_id, &old_shm);
        // Linux releases `mm_struct` at exit and keeps only zombie metadata.
        // Drop the full user address space here so unreaped zombies do not pin
        // page-table pages (and COW refs) during fork-heavy workloads.
        process_inner.memory_set = MemorySet::new_bare();
        crate::syscall::filesystem::release_all_record_locks_for_owner(pid);
        crate::syscall::filesystem::release_all_file_leases_for_owner(pid);
        // drop file descriptors
        process_inner.fd_table.clear();
        process_inner.fd_flags.clear();
        // Keep zombie `tasks[]` until wait4() reaps the process so reaping has
        // a deterministic place to drop any lingering task Arcs.
    }

    if tid != 0 {
        // This path never returns after schedule(); move `task` out now so it can be dropped on idle.
        queue_exiting_task_drop(task);
        drop(process);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        return;
    }
    // Drop the current task after switching to idle to avoid leaking the final
    // strong Arc from this never-returning exit path.
    queue_exiting_task_drop(task);
    drop(process);
    // we do not have to save task context
    // println!(
    //     "[DEBUG] exit_current_and_run_next: about to schedule, tid={}",
    //     tid
    // );
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
}

/// Terminate the entire process, even when called from a non-main thread.
pub fn exit_group_and_run_next(exit_code: i32) {
    let task = take_current_task().unwrap();
    task.clear_on_cpu();
    let Some(process) = task.process.upgrade() else {
        if DEBUG_SCHED {
            log::warn!("[exit_group] task lost process; dropping task and scheduling idle");
        }
        queue_exiting_task_drop(task);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        return;
    };

    let (tid, res_to_drop, join_waiters, clear_child_tid, robust_list_head) = {
        let mut task_inner = task.borrow_mut();
        task_inner.exit_code = Some(exit_code);
        let tid = task_inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        let res_to_drop = task_inner.res.take();
        let clear_child_tid = task_inner.clear_child_tid.take();
        let robust_list_head = task_inner.robust_list_head;
        let join_waiters = task_inner.join_waiters.drain(..).collect::<Vec<_>>();
        (
            tid,
            res_to_drop,
            join_waiters,
            clear_child_tid,
            robust_list_head,
        )
    };

    let clear_child_tid_addr = clear_child_tid;

    let token = {
        let inner = process.borrow_mut();
        inner.memory_set.token()
    };

    if robust_list_head != 0 {
        let linux_tid = crate::syscall::misc::encode_linux_tid(process.getpid(), tid) as u32;
        crate::syscall::robust_list::exit_robust_list(
            process.getpid(),
            token,
            robust_list_head,
            linux_tid,
        );
    }

    if let Some(ctid) = clear_child_tid_addr {
        clear_child_tid_now(process.getpid(), token, ctid);
    }
    drop(res_to_drop);
    for waiter in join_waiters {
        wakeup_task(waiter);
    }

    log::debug!(
        "[exit_group] pid={} tid={} exit_code={}",
        process.getpid(),
        tid,
        exit_code
    );

    let dumped_core = {
        let inner = process.borrow_mut();
        if exit_code >= 0 {
            false
        } else {
            let signum = (-exit_code) as usize;
            inner.rlimit_core_cur != 0 && crate::task::signal::signal_has_core_dump(signum)
        }
    };

    let pid = process.getpid();
    if pid == IDLE_PID {
        println!(
            "[kernel] Idle process exit with exit_code {} ...",
            exit_code
        );
        if exit_code != 0 {
            arch::shutdown();
        } else {
            arch::shutdown();
        }
    }

    let parent = {
        let mut process_inner = process.borrow_mut();
        crate::syscall::process::unregister_executing_inode(
            process_inner.exec_inode_dev,
            process_inner.exec_inode_num,
        );
        process_inner.is_zombie = true;
        process_inner.dumped_core = dumped_core;
        process_inner.exit_code = exit_code;
        process_inner.parent.as_ref().and_then(|p| p.upgrade())
    };
    cgroup_exit_process(pid);
    crate::syscall::filesystem::acct_process_exit(&process, exit_code);

    if let Some(parent) = parent {
        crate::task::signal::queue_process_signal(
            parent.getpid(),
            crate::task::signal::SIGCHLD_NUM,
        );
        let waiters = {
            let mut parent_inner = parent.borrow_mut();
            parent_inner.wait_queue.drain(..).collect::<Vec<_>>()
        };
        for waiter in waiters {
            wakeup_task(waiter);
        }
    }

    let mut process_inner = process.borrow_mut();
    {
        let mut initproc_inner = INITPROC.borrow_mut();
        for child in process_inner.children.iter() {
            child.borrow_mut().parent = Some(Arc::downgrade(&INITPROC));
            initproc_inner.children.push(child.clone());
        }
    }

    let mut recycle_res = Vec::<TaskUserRes>::new();
    for task in process_inner.tasks.iter().filter(|t| t.is_some()) {
        let task = task.as_ref().unwrap();
        remove_inactive_task(Arc::clone(&task));
        let mut task_inner = task.borrow_mut();
        if let Some(res) = task_inner.res.take() {
            recycle_res.push(res);
        }
    }
    drop(process_inner);
    recycle_res.clear();
    process.handoff_files_owner_on_exit();

    let mut process_inner = process.borrow_mut();
    process_inner.children.clear();
    let old_shm = core::mem::take(&mut process_inner.sysv_shm_attaches);
    crate::syscall::sysv_shm::exit_cleanup(process_inner.ipc_ns_id, &old_shm);
    // Same as exit_current_and_run_next(): release the whole user address
    // space eagerly and keep only zombie bookkeeping in the PCB.
    process_inner.memory_set = MemorySet::new_bare();
    crate::syscall::filesystem::release_all_record_locks_for_owner(pid);
    crate::syscall::filesystem::release_all_file_leases_for_owner(pid);
    process_inner.fd_table.clear();
    process_inner.fd_flags.clear();

    // Same as `exit_current_and_run_next()`: keep zombie `tasks[]` until wait4().

    drop(process_inner);
    // Same as exit_current_and_run_next(): defer drop until we are on idle stack.
    queue_exiting_task_drop(task);
    drop(process);
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
}
