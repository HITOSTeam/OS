use crate::{
    arch,
    config::MAX_HARTS,
    mm::try_write_user_value,
    println,
    syscall::futex::futex_wake,
    task::{
        INITPROC,
        id::TaskUserRes,
        manager::{
            TASK_MANAGER, add_task, fetch_task, remove_inactive_task,
            wakeup_task,
        },
        process_block::ProcessControlBlock,
        switch,
        task_block::{TaskControlBlock, TaskStatus},
        task_context::{self, TaskContext},
    },
    trap::init_trap,
};
use alloc::{sync::Arc, task, vec::Vec};
use lazy_static::lazy_static;
use log;
use spin::Mutex;

use crate::debug_config::{DEBUG_PTHREAD, DEBUG_SCHED};

fn clear_child_tid_now(pid: usize, token: usize, ctid: usize) {
    if ctid == 0 {
        return;
    }
    let _ = try_write_user_value(token, ctid as *mut i32, &0);
    let _ = futex_wake(pid, ctid, 1);
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
    pending_drop: Option<Arc<TaskControlBlock>>,
}
impl Processor {
    pub fn new() -> Self {
        Self {
            now_task_block: None,
            idle_task_context: TaskContext::new(),
            pending_ready: None,
            pending_blocked: None,
            pending_drop: None,
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
        self.pending_drop.take()
    }

    pub fn set_pending_drop(&mut self, task: Arc<TaskControlBlock>) {
        self.pending_drop = Some(task);
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
pub fn idle_task() {
    #[allow(dead_code)]
    static EMPTY_SPINS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    loop {
        // Ensure kernel-mode traps use the kernel handler (stvec points to alltraps_k)
        init_trap();
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

        if let Some(task) = local_processor().lock().take_pending_drop() {
            task.clear_on_cpu();
            drop(task);
        }

        if let Some(task) = fetch_task() {
            if crate::debug_config::DEBUG_WATCHDOG {
                EMPTY_SPINS.store(0, core::sync::atomic::Ordering::Relaxed);
            }
            let mut processor = local_processor().lock();
            let idle_task_cx_ptr = processor.get_idle_task_ptr();
            // access coming task TCB exclusively
            let mut task_inner = task.borrow_mut();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
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
    {
        let process = current_process();
        let fatal = process
            .try_borrow_mut()
            .and_then(|inner| inner.signals.check_error());
        if let Some((errno, msg)) = fatal {
            crate::println!("[kernel] {}", msg);
            exit_current_and_run_next(errno);
        }
    }
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.borrow_mut();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    // ---- release current PCB

    // Do NOT push back to the global ready queue here: another hart could pick
    // it up and run it while we are still executing on this task's kernel stack
    // inside the trap handler/syscall path.
    //
    // Instead, stash it on this hart and let `idle_task()` enqueue it after the
    // context switch completes.
    local_processor().lock().set_pending_ready(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}
pub fn block_current_and_run_next() {
    // Same rationale as in `suspend_current_and_run_next()`: a task can be stuck
    // yielding within a syscall (interrupts disabled), so handle fatal signals here.
    {
        let process = current_process();
        let fatal = process
            .try_borrow_mut()
            .and_then(|inner| inner.signals.check_error());
        if let Some((errno, msg)) = fatal {
            crate::println!("[kernel] {}", msg);
            exit_current_and_run_next(errno);
        }
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
    drop(task_inner);
    // ---- release current PCB

    if should_block {
        local_processor().lock().set_pending_blocked(task);
    } else {
        // Behave like a yield: enqueue after we have switched back to idle
        // to avoid "run on two harts".
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
        // Defer dropping the task until after switching to idle to avoid freeing
        // its kernel stack while still running on it.
        local_processor().lock().set_pending_drop(task);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        return;
    };

    // Extract tid in a separate scope to release the borrow early.
    // Also drop TaskUserRes *after* releasing the TCB lock to avoid deadlocks with sys_waittid.
    let (tid, res_to_drop, join_waiters, clear_child_tid, robust_list_head) = {
        let mut task_inner = task.borrow_mut();
        task_inner.exit_code = Some(exit_code);
        let tid = task_inner.res.as_ref().map(|r| r.tid).unwrap_or(usize::MAX);
        let res_to_drop = task_inner.res.take();
        let clear_child_tid = task_inner.clear_child_tid.take();
        let robust_list_head = task_inner.robust_list_head;
        let join_waiters = task_inner.join_waiters.drain(..).collect::<Vec<_>>();
        (tid, res_to_drop, join_waiters, clear_child_tid, robust_list_head)
    }; // task_inner dropped here

    let clear_child_tid_addr = clear_child_tid;
    let is_linux_thread = clear_child_tid_addr.is_some();

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
        // Defer dropping the exiting task until after we switch to idle so its
        // kernel stack is no longer in use.
        local_processor().lock().set_pending_drop(task);
    }

    log::debug!(
        "[exit] pid={} tid={} exit_code={}",
        process.getpid(),
        tid,
        exit_code
    );

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
            process_inner.is_zombie = true;
            process_inner.exit_code = exit_code;
            process_inner.parent.as_ref().and_then(|p| p.upgrade())
        }; // drop child PCB lock before touching parent to avoid lock inversion

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

        let mut process_inner = process.borrow_mut();
        process_inner.children.clear();
        let old_shm = core::mem::take(&mut process_inner.sysv_shm_attaches);
        crate::syscall::sysv_shm::exit_cleanup(&old_shm);
        // deallocate other data in user space i.e. program code/data section
        process_inner.memory_set.recycle_data_pages();
        // drop file descriptors
        process_inner.fd_table.clear();
        process_inner.fd_flags.clear();
        // Remove all tasks except for the main thread itself.
        // This is because we are still using the kstack under the TCB
        // of the main thread. This TCB, including its kstack, will be
        // deallocated when the process is reaped via waitpid.
        //
        while process_inner.tasks.len() > 1 {
            process_inner.tasks.pop();
        }
    }

    if tid != 0 {
        drop(process);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        return;
    }
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
        local_processor().lock().set_pending_drop(task);
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
        (tid, res_to_drop, join_waiters, clear_child_tid, robust_list_head)
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
        process_inner.is_zombie = true;
        process_inner.exit_code = exit_code;
        process_inner.parent.as_ref().and_then(|p| p.upgrade())
    };

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

    let mut process_inner = process.borrow_mut();
    process_inner.children.clear();
    let old_shm = core::mem::take(&mut process_inner.sysv_shm_attaches);
    crate::syscall::sysv_shm::exit_cleanup(&old_shm);
    process_inner.memory_set.recycle_data_pages();
    process_inner.fd_table.clear();
    process_inner.fd_flags.clear();

    if tid != usize::MAX {
        for (idx, slot) in process_inner.tasks.iter_mut().enumerate() {
            if idx == tid {
                continue;
            }
            *slot = None;
        }
    } else {
        process_inner.tasks.clear();
    }

    drop(process_inner);
    drop(process);
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
}
