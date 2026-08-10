use crate::{
    arch,
    config::MAX_HARTS,
    fs::{File, cgroup_exit_process, cgroup_exit_thread},
    mm::{MemorySet, MmRef, try_write_user_value},
    println,
    syscall::futex::futex_wake_shared,
    task::{
        FilesLock, FilesStruct, INITPROC,
        id::{KernelStack, LiveThreadRetirement, TaskUserRes},
        manager::{
            PID2PCB, account_rt_runtime, fair_current_deadline_expired, fair_task_is_next_on_hart,
            fair_wakeup_preempts_current_on_hart, fetch_task, has_ready_rt_at_or_above,
            has_ready_rt_higher_than, has_ready_tasks_on_hart, prime_fair_sync_wakeup_lag,
            ready_queue_lengths, record_fair_sleep_lag, release_process_mm_owner,
            remove_inactive_task, remove_sched_timer_refs, requeue_task, rt_bandwidth_throttled,
            wakeup_sync_task_on_hart, wakeup_task, wakeup_tasks,
        },
        process_block::ProcessControlBlock,
        runtime::{monotonic_time_ns, start_task_runtime_slice},
        sched::{RT_PRIO_MIN, SchedClass, rr_timeslice_ticks, sched_class},
        switch,
        task_block::{TaskControlBlock, TaskStatus},
        task_context::{self, TaskContext},
    },
    trap::init_trap,
};
use alloc::{collections::VecDeque, sync::Arc, task, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use lazy_static::lazy_static;

/// A Linux-style prepared sleep for condition wait queues.
///
/// The caller arms this token while still holding the lock that protects the
/// wait condition, then drops that lock and calls [`PreparedWait::sleep`].
/// Local interrupts remain disabled across that hand-off, so a timer
/// preemption cannot turn the task back into `Running` between the final
/// condition check and the scheduler commit.  A remote wakeup is retained in
/// `wakeup_pending` and makes `sleep()` return without blocking.
#[must_use = "a prepared wait must be slept or cancelled"]
pub(crate) struct PreparedWait {
    task: Arc<TaskControlBlock>,
    irq_guard: Option<crate::sync::LocalIrqSaveGuard>,
    armed: bool,
}

impl PreparedWait {
    pub(crate) fn new() -> Option<Self> {
        Self::with_irq_guard(crate::sync::LocalIrqSaveGuard::new())
    }

    pub(crate) fn with_irq_guard(irq_guard: crate::sync::LocalIrqSaveGuard) -> Option<Self> {
        let task = current_task()?;
        {
            let _wakeup_guard = task.lock_wakeup_transition();
            let mut inner = task.borrow_mut();
            debug_assert_eq!(inner.task_status, TaskStatus::Running);
            inner.task_status = TaskStatus::Blocked;
        }
        Some(Self {
            task,
            irq_guard: Some(irq_guard),
            armed: true,
        })
    }

    /// Leave a prepared interruptible sleep for exec or fatal signal teardown.
    ///
    /// Linux's wait queues call `signal_pending_state()` before committing a
    /// TASK_INTERRUPTIBLE/TASK_KILLABLE sleep.  Consequently SIGKILL from
    /// `do_group_exit()` and the fatal signal used by `de_thread()` cannot be
    /// consumed as an ordinary wake followed by another sleep.  Exec uses a
    /// task-local token here, while ordinary group exit uses the pending signal
    /// bitmap, so this boundary must check both forms of fatal teardown.
    fn exit_for_fatal_teardown_if_requested(&mut self) {
        // Taking TaskUserRes is the point of no return for thread exit. Exit
        // cleanup itself may sleep while unmapping the old mm; waking that
        // continuation must resume its original stack, not recursively enter
        // exit_current_and_run_next() without the LiveThreadRetirement ticket.
        // This is the same guard used by the ordinary block/suspend paths.
        if self.task.borrow_mut().res.is_none() {
            return;
        }
        if self.task.exec_exit_requested() {
            self.armed = false;
            drop(self.irq_guard.take());
            exit_current_and_run_next(0);
        }
        if let Some((errno, msg)) = crate::task::signal::check_if_current_signals_error() {
            self.armed = false;
            drop(self.irq_guard.take());
            crate::task::signal::log_signal_exit(msg);
            exit_group_and_run_next(errno);
        }
    }

    pub(crate) fn sleep(mut self) {
        let wake_already_pending = {
            let _wakeup_guard = self.task.lock_wakeup_transition();
            let pending = self
                .task
                .wakeup_pending
                .swap(false, core::sync::atomic::Ordering::AcqRel);
            if pending {
                self.task.wakeup_sync_hart.store(
                    TaskControlBlock::OFF_CPU,
                    core::sync::atomic::Ordering::Release,
                );
                let mut inner = self.task.borrow_mut();
                inner.task_status = TaskStatus::Running;
            }
            pending
        };
        if wake_already_pending {
            self.armed = false;
            self.exit_for_fatal_teardown_if_requested();
            return;
        }

        // Close the interval between prepare_to_wait() and schedule(). If a
        // fatal teardown won before the task committed the sleep, it must not
        // enter the wait queue again.
        self.exit_for_fatal_teardown_if_requested();
        self.armed = false;
        block_prepared_current_and_run_next();
        // Fatal teardown can arrive after the pre-schedule check. Its wake
        // makes block_prepared_current_and_run_next() return; consume it before
        // the syscall's readiness loop can prepare another sleep.
        self.exit_for_fatal_teardown_if_requested();
    }
}

impl Drop for PreparedWait {
    fn drop(&mut self) {
        if self.armed {
            let _wakeup_guard = self.task.lock_wakeup_transition();
            let mut inner = self.task.borrow_mut();
            if inner.task_status == TaskStatus::Blocked {
                inner.task_status = TaskStatus::Running;
            }
            // Cancellation means the caller rechecked its condition and will
            // keep running or return.  A wake latched while the token was
            // armed is therefore already observed and must not leak into a
            // later unrelated sleep.
            self.task
                .wakeup_pending
                .store(false, core::sync::atomic::Ordering::Release);
            self.task.wakeup_sync_hart.store(
                TaskControlBlock::OFF_CPU,
                core::sync::atomic::Ordering::Release,
            );
        }
        drop(self.irq_guard.take());
    }
}
use log;
use spin::Mutex;

use crate::debug_config::{DEBUG_PTHREAD, DEBUG_SCHED};

static TASK_DROP_QUEUED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static TASK_DROP_DONE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static TASK_DROP_REF_DIAG_SEQ: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static TASK_FETCH_REF_DIAG_SEQ: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
const IDLE_CLEANUP_BUDGET: usize = 4;
const IDLE_FILES_STRUCT_DROP_BUDGET: usize = 2;
const IDLE_FILES_STRUCT_CLOSE_BATCH: usize = 2;
const IDLE_FILE_DROP_BUDGET: usize = 16;
const IDLE_MM_DROP_BUDGET: usize = 4;

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

/// 向当前任务的 CPU 时间记账，并按调度类做额外处理。
///
/// 调 `charge_running_task` 把本次运行片段计入 `cpu_time_ns`，返回这段
/// 真实时间 `delta_ns`。若当前任务是 RT 类（FIFO/RR），还要调
/// `account_rt_runtime` 从 RT 带宽额度中扣减，可能触发节流。
/// fair 类的 vruntime 累加在入队时由 `place_fair_task_entity` 完成，
/// 此处不重复。
fn charge_task_runtime_for_scheduler(task: &Arc<TaskControlBlock>) {
    let policy = task.borrow_mut().scheduling.sched_policy;
    let delta_ns = crate::task::runtime::charge_running_task(task);
    if matches!(
        sched_class(policy),
        Some(SchedClass::Fifo) | Some(SchedClass::Rr)
    ) {
        account_rt_runtime(hart_id(), delta_ns);
    }
}

/// 排空延迟的内核态定时器工作。
///
/// 内核态定时器中断（syscall 执行期间触发的 tick）不能立即调用
/// `check_timer()`，因为被中断的 syscall 可能正持有自旋锁（如堆锁、
/// 管道锁），而 `check_timer` 会唤醒任务、分配内存、操作定时器堆——
/// 这些都可能尝试获取同一把锁，导致死锁。
///
/// 因此内核态定时器中断只置一个延迟位（`note_kernel_timer_tick`），
/// 真正的处理推迟到 idle 循环这个安全点：此时没有任何任务锁或 syscall
/// 锁被持有，处理定时器不会与任何持锁上下文冲突。这对应 Linux 在
/// "选下一个任务之前先跑定时器"的 `run_local_timers()` 排序。
///
/// 检查两个条件，任一为真则调 `check_timer()`：
/// - `take_deferred_kernel_timer_tick()`：内核态 tick 置位了延迟标记。
/// - `has_due_sleep_timer()`：有 sleep 定时器已到期（可能在 idle 空转时
///   被硬件定时器触发，但 tick 还没到）。
fn drain_deferred_kernel_timer_work() {
    if crate::task::block_sleep::take_deferred_kernel_timer_tick()
        || crate::task::block_sleep::has_due_sleep_timer()
    {
        // 内核态定时器中断只置延迟位，因为被中断的 syscall 可能持有
        // 定时器唤醒路径会用到的自旋锁。idle 调度循环是安全点：没有
        // 任务锁或 syscall 锁被持有，在此处理定时器对应 Linux 的
        // "选下一个任务之前先跑定时器"排序。
        crate::task::block_sleep::check_timer();
    }
}

/// 判断 idle 后台清理是否应该停下来给就绪任务让路。
///
/// 在 idle 循环的后台清理阶段（释放 TCB/栈/mm/fd），每处理一批就调此函数
/// 检查"是不是有活干了"。返回 true 表示有就绪任务（RT 或 fair），清理应
/// 尽快结束，让 idle 去做 `fetch_task` 切到就绪任务。
///
/// 先调 `drain_deferred_kernel_timer_work`：定时器可能刚唤醒了一批任务
/// 使其变为就绪，不先排空定时器的话下面的就绪检查会漏掉这些新就绪任务。
///
/// 然后只检查当前 hart 的 O(1) runnable 计数。Linux 的 idle 清理和
/// `schedule()` 都以本地 `rq->nr_running` 为快速判定；其他 hart 的 runnable
/// 工作由其本地调度器处理，当前 hart 若真正空闲则在 pick 阶段执行一次
/// `sched_balance_newidle()` 风格的 fair task pull。
fn idle_cleanup_should_stop_for_runnable_work() -> bool {
    drain_deferred_kernel_timer_work();
    has_ready_tasks_on_hart(hart_id())
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

fn try_reparent_child_to(
    child: &Arc<ProcessControlBlock>,
    reaper: &Arc<ProcessControlBlock>,
) -> bool {
    let mut reaper_inner = reaper.borrow_mut();
    if reaper_inner.is_zombie || reaper_inner.exit_teardown || reaper.live_thread_count() == 0 {
        return false;
    }
    let reaper_pid = reaper.getpid();
    let reaper_pid_ns_id = reaper_inner.pid_ns_id;
    let reaper_visible_pid = reaper_inner.pid_ns_vpid;
    let (queue_for_reaper, exit_signal) = {
        let mut child_inner = child.borrow_mut();
        if child_inner.wait_reaped {
            return false;
        }
        child_inner.parent = Some(Arc::downgrade(reaper));
        child.update_parent_visible_pid_from_locked_child(
            child_inner.pid_ns_id,
            reaper_pid_ns_id,
            reaper_visible_pid,
        );
        if child_inner.is_zombie
            && !child_inner.wait_reaped
            && child_inner.exited_parent_queue_pid != Some(reaper_pid)
        {
            child_inner.exited_parent_queue_pid = Some(reaper_pid);
            (true, child_inner.exit_signal)
        } else {
            (false, child_inner.exit_signal)
        }
    };
    reaper_inner.add_child(child.clone());
    let mut waiters = Vec::new();
    if queue_for_reaper {
        reaper_inner.exited_children.push_back(child.clone());
        waiters.extend(reaper_inner.wait_queue.drain(..));
        waiters.extend(reaper_inner.vfork_wait_queue.drain(..));
        for waiter in &waiters {
            prime_fair_sync_wakeup_lag(waiter);
        }
    }
    drop(reaper_inner);
    if queue_for_reaper && exit_signal > 0 {
        crate::task::signal::queue_process_signal(reaper_pid, exit_signal as usize);
    }
    wakeup_tasks(waiters);
    true
}

fn try_reparent_child_to_namespace_reaper(
    child: &Arc<ProcessControlBlock>,
    exiting_process: &Arc<ProcessControlBlock>,
    namespace_id: usize,
) -> bool {
    let mut current_namespace = Some(namespace_id);
    while let Some(ns_id) = current_namespace {
        if let Some(reaper) = crate::task::pid_namespace_reaper(ns_id)
            && !Arc::ptr_eq(&reaper, exiting_process)
            && !Arc::ptr_eq(&reaper, child)
            && try_reparent_child_to(child, &reaper)
        {
            return true;
        }
        current_namespace = crate::task::pid_namespace_parent(ns_id);
    }
    false
}

fn reparent_orphaned_children(process: &Arc<ProcessControlBlock>) {
    let (children, namespace_id) = {
        let process_inner = process.borrow_mut();
        (process_inner.children.clone(), process_inner.pid_ns_id)
    };
    for child in children {
        if try_reparent_child_to_namespace_reaper(&child, process, namespace_id) {
            continue;
        }
        let initproc = INITPROC.clone();
        if !Arc::ptr_eq(&initproc, process) && !Arc::ptr_eq(&initproc, &child) {
            let _ = try_reparent_child_to(&child, &initproc);
        }
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
                    wait_queues = wait_queues.saturating_add(
                        inner
                            .vfork_wait_queue
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

/// 将一个文件描述符表延迟到 idle 循环释放。
///
/// 若引用计数不为 1（还有其他持有者），直接 drop 当前引用即可——
/// 表本身不会在此刻释放，无需排队。只有唯一引用时才放入
/// `pending_files_struct_drop`，由 idle 渐进关闭所有 fd 并释放表，
/// 避免 exit 路径里同步 close 大量文件造成延迟。
fn queue_files_struct_drop(files: Arc<FilesLock>) {
    if Arc::strong_count(&files) != 1 {
        drop(files);
        return;
    }

    close_files_struct_fd_refs_if_unshared(&files);
    local_processor()
        .lock()
        .set_pending_files_struct_drop(files);
}

fn close_files_struct_fd_refs_if_unshared(files: &Arc<FilesLock>) {
    let detached = files.lock().release_process_owner();
    crate::task::complete_fd_closes(detached);
}

/// 将一个地址空间（mm）延迟到 idle 循环释放。
///
/// drop 页表可能很重（遍历 VMA、释放页），放入 `pending_mm_drop`
/// 由 idle 带预算渐进释放，避免在 exit 的不可抢占路径里阻塞调度。
fn queue_mm_drop(mm: MmRef) {
    local_processor().lock().set_pending_mm_drop(mm);
}

fn clear_child_tid_now(pid: usize, token: usize, ctid: usize) {
    if ctid == 0 {
        return;
    }
    let _ = try_write_user_value(token, ctid as *mut i32, &0);
    let _ = futex_wake_shared(pid, token, ctid, 1);
}

struct ThreadExitCleanup {
    tid: usize,
    is_linux_thread: bool,
    res_to_drop: Option<TaskUserRes>,
    join_waiters: Vec<Arc<TaskControlBlock>>,
    clear_child_tid_addr: Option<usize>,
    robust_list_head: usize,
}

fn take_thread_exit_cleanup(task: &Arc<TaskControlBlock>, exit_code: i32) -> ThreadExitCleanup {
    let mut task_inner = task.borrow_mut();
    task_inner.exit_code = Some(exit_code);
    let robust_list_head = core::mem::take(&mut task_inner.robust_list_head);
    task_inner.robust_list_len = 0;
    ThreadExitCleanup {
        tid: task_inner
            .res
            .as_ref()
            .map(|res| res.tid)
            .unwrap_or(usize::MAX),
        is_linux_thread: task_inner
            .res
            .as_ref()
            .map(|res| res.is_linux_thread())
            .unwrap_or(false),
        res_to_drop: task_inner.res.take(),
        join_waiters: task_inner.join_waiters.drain(..).collect::<Vec<_>>(),
        clear_child_tid_addr: task_inner.clear_child_tid.take(),
        robust_list_head,
    }
}

fn finish_thread_exit_cleanup(
    process: &Arc<ProcessControlBlock>,
    cleanup: ThreadExitCleanup,
    drop_user_res: bool,
) -> (usize, bool, Option<usize>, Option<LiveThreadRetirement>) {
    let pid = process.getpid();
    let token = cleanup
        .res_to_drop
        .as_ref()
        .map(|res| res.memory_set().token())
        .unwrap_or_else(|| process.memory_set().token());

    if cleanup.robust_list_head != 0 {
        let linux_tid = crate::syscall::misc::encode_linux_tid(pid, cleanup.tid) as u32;
        crate::syscall::robust_list::exit_robust_list(
            pid,
            token,
            cleanup.robust_list_head,
            linux_tid,
        );
    }
    if let Some(ctid) = cleanup.clear_child_tid_addr {
        clear_child_tid_now(pid, token, ctid);
    }
    let live_thread_retirement = cleanup
        .res_to_drop
        .map(|res| res.finish_thread_exit(drop_user_res));
    for waiter in &cleanup.join_waiters {
        prime_fair_sync_wakeup_lag(waiter);
    }
    wakeup_tasks(cleanup.join_waiters);

    (
        cleanup.tid,
        cleanup.is_linux_thread || cleanup.clear_child_tid_addr.is_some(),
        cleanup.clear_child_tid_addr,
        live_thread_retirement,
    )
}

fn transfer_exiting_thread_bookkeeping(
    process: &Arc<ProcessControlBlock>,
    task: &Arc<TaskControlBlock>,
    tid: usize,
) {
    if tid != 0 && tid != usize::MAX {
        cgroup_exit_thread(process.getpid(), tid);
    }
    let thread_cpu_ns = crate::task::runtime::task_cpu_time_ns(task);
    let mut process_inner = process.borrow_mut();
    if task.try_mark_cpu_time_transferred() {
        process_inner.cpu_time_ns = process_inner.cpu_time_ns.saturating_add(thread_cpu_ns);
    }
}

fn remove_exiting_task_slot(
    process: &Arc<ProcessControlBlock>,
    task: &Arc<TaskControlBlock>,
    tid: usize,
) {
    let mut process_inner = process.borrow_mut();
    let remove_slot = process_inner
        .tasks
        .get(tid)
        .and_then(|slot| slot.as_ref())
        .map(|candidate| Arc::ptr_eq(candidate, task))
        .unwrap_or(false);
    if remove_slot {
        process_inner.tasks[tid] = None;
    }
}

/// Publish the common, fully cleaned exit point and consume an exec token when
/// one was installed concurrently.
///
/// The live-thread ticket is released only after the task is off CPU and all
/// queue/user cleanup is complete.  The final NONE/COUNTED -> RETIRED CAS then
/// closes both sides of exec's snapshot race without spinning in IRQ context.
fn retire_exiting_task(
    process: &Arc<ProcessControlBlock>,
    task: &Arc<TaskControlBlock>,
    tid: usize,
    detach_regular_thread: bool,
    live_thread_retirement: Option<LiveThreadRetirement>,
) -> (bool, bool) {
    // A signal wake may leave references in futex/timer/ready queues. Remove
    // them before either last-thread teardown or an exec owner may release the
    // old address space.
    remove_inactive_task(Arc::clone(task));
    // Every task performs its cgroup/CPU handoff before releasing the live
    // ticket. This remains true for group-exit members whose zombie slot is
    // intentionally retained until the process is reaped.
    transfer_exiting_thread_bookkeeping(process, task, tid);
    if detach_regular_thread {
        remove_exiting_task_slot(process, task, tid);
    }

    let last_live_thread = live_thread_retirement
        .map(LiveThreadRetirement::retire)
        .unwrap_or(false);
    let exec_peer = task.retire_exec_lifecycle();
    if exec_peer {
        if !detach_regular_thread {
            remove_exiting_task_slot(process, task, tid);
        }
        // This is the final publication for a counted peer.  Everything above
        // must remain ordered before the counter can wake the exec owner.
        process.finish_exec_peer_exit();
    }
    (exec_peer, last_live_thread)
}

fn process_dumped_core(process: &Arc<ProcessControlBlock>, exit_code: i32) -> bool {
    let Some(signum) = exit_code.checked_neg().filter(|sig| *sig > 0) else {
        return false;
    };
    if !crate::task::signal::signal_has_core_dump(signum as usize) {
        return false;
    }
    process.borrow_mut().rlimits.rlimit_core_cur != 0
}

struct ExitPublication {
    parent: Option<Arc<ProcessControlBlock>>,
    exit_signal: i32,
    parent_waiters: Vec<Arc<TaskControlBlock>>,
    pidfd_waiters: Vec<Arc<TaskControlBlock>>,
}

/// Publish the final waitable state after teardown has completed.
///
/// The parent PCB is locked before the child PCB, matching wait4/waitid.  Thus
/// a waiter either observes a non-zombie child and sleeps in `wait_queue`, or
/// observes the fully initialized zombie and claims it; it cannot reap between
/// `is_zombie` becoming visible and `exited_children` publication.  Pidfd
/// waiters are detached in the same child critical section so PID-table removal
/// cannot lose their wakeup.
fn publish_process_exit(
    process: &Arc<ProcessControlBlock>,
    dumped_core: bool,
    exit_code: i32,
    cpu_time_ns: u64,
) -> ExitPublication {
    loop {
        let parent = {
            let process_inner = process.borrow_mut();
            process_inner.parent.as_ref().and_then(|p| p.upgrade())
        };

        let Some(parent) = parent else {
            let mut process_inner = process.borrow_mut();
            // Reparenting may have completed between the first snapshot and
            // this lock acquisition. Retry under the canonical parent->child
            // order rather than publishing against the stale parent state.
            if process_inner
                .parent
                .as_ref()
                .and_then(|p| p.upgrade())
                .is_some()
            {
                continue;
            }
            debug_assert!(!process_inner.is_zombie);
            debug_assert!(process_inner.exit_teardown);
            debug_assert!(!process_inner.wait_reaped);
            process_inner.dumped_core = dumped_core;
            process_inner.exit_code = exit_code;
            process_inner.cpu_time_ns = cpu_time_ns;
            process_inner.is_zombie = true;
            let exit_signal = process_inner.exit_signal;
            let pidfd_waiters = process_inner.pidfd_poll_waiters.take_wakeups();
            return ExitPublication {
                parent: None,
                exit_signal,
                parent_waiters: Vec::new(),
                pidfd_waiters,
            };
        };

        let parent_pid = parent.getpid();
        let mut parent_inner = parent.borrow_mut();
        let mut process_inner = process.borrow_mut();
        let still_parent = process_inner
            .parent
            .as_ref()
            .and_then(|p| p.upgrade())
            .is_some_and(|current| Arc::ptr_eq(&current, &parent));
        if !still_parent {
            drop(process_inner);
            drop(parent_inner);
            continue;
        }
        let owned_by_parent = process_inner.child_parent_index.is_some_and(|index| {
            parent_inner
                .children
                .get(index)
                .is_some_and(|owned| Arc::ptr_eq(owned, process))
        });
        debug_assert!(
            owned_by_parent,
            "exiting process missing from parent children"
        );
        debug_assert!(!process_inner.is_zombie);
        debug_assert!(process_inner.exit_teardown);
        debug_assert!(!process_inner.wait_reaped);
        process_inner.dumped_core = dumped_core;
        process_inner.exit_code = exit_code;
        process_inner.cpu_time_ns = cpu_time_ns;
        process_inner.is_zombie = true;
        let exit_signal = process_inner.exit_signal;
        let pidfd_waiters = process_inner.pidfd_poll_waiters.take_wakeups();
        let should_queue =
            owned_by_parent && process_inner.exited_parent_queue_pid != Some(parent_pid);
        if should_queue {
            process_inner.exited_parent_queue_pid = Some(parent_pid);
        }
        drop(process_inner);

        if should_queue {
            parent_inner.exited_children.push_back(Arc::clone(process));
        }
        let mut parent_waiters = parent_inner.wait_queue.drain(..).collect::<Vec<_>>();
        parent_waiters.extend(parent_inner.vfork_wait_queue.drain(..));
        for waiter in &parent_waiters {
            prime_fair_sync_wakeup_lag(waiter);
        }
        drop(parent_inner);
        return ExitPublication {
            parent: Some(parent),
            exit_signal,
            parent_waiters,
            pidfd_waiters,
        };
    }
}

/// 每线程 CPU 时间尽力统计，供 `*_CPUTIME` 时钟使用。
pub fn account_current_task_tick() {
    let Some(task) = current_task() else {
        return;
    };
    charge_task_runtime_for_scheduler(&task);
}
pub struct Processor {
    now_task_block: Option<Arc<TaskControlBlock>>,
    idle_task_context: TaskContext,
    /// 切回 idle 后才入队的任务（Ready）。
    ///
    /// 避免在上下文切换之前就把当前任务放回全局就绪队列——否则另一个
    /// hart 可能在本任务还在用自己内核栈时就调度它，导致同栈并发。
    pending_ready: Option<Arc<TaskControlBlock>>,
    /// 正在进入 Blocked 的任务，切到 idle 后再处理（清 on_cpu、补唤醒）。
    pending_blocked: Option<Arc<TaskControlBlock>>,
    /// 切到 idle 后才释放的已退出任务 TCB（此时释放内核栈才安全）。
    pending_drop: VecDeque<Arc<TaskControlBlock>>,
    /// 切到 idle 后才释放的内核栈。
    pending_kstack_drop: VecDeque<KernelStack>,
    /// 进程退出时摘下的文件引用。最终的 fput 式释放可能唤醒
    /// pipe/socket 等待者，故由 idle 渐进排空，且 RT 就绪时跳过。
    pending_file_drop: VecDeque<Arc<dyn File + Send + Sync>>,
    /// 进程退出时摘下的完整文件描述符表。退出时应尽快发布空表，
    /// idle 再把旧表转成逐文件的 fput 工作，对应 Linux
    /// `exit_files()`/task-work 形态。
    pending_files_struct_drop: VecDeque<Arc<FilesLock>>,
    /// 摘下待最终释放的地址空间。drop mm 要遍历页表和帧元数据，
    /// 放到 idle 里做，避免阻塞不可抢占的 exit 路径。
    pending_mm_drop: VecDeque<MmRef>,
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
            pending_file_drop: VecDeque::new(),
            pending_files_struct_drop: VecDeque::new(),
            pending_mm_drop: VecDeque::new(),
        }
    }
    /// 返回 idle 上下文的可变指针，`schedule`/`idle_task` 用它做 switch 的
    /// 源/目标。
    pub fn get_idle_task_ptr(&mut self) -> *mut TaskContext {
        &mut self.idle_task_context as *mut _
    }

    /// 取走当前任务的所有权（用于退出路径清空 now_task_block）。
    pub fn take_current_task(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.now_task_block.take()
    }
    /// 获取当前任务的克隆引用（不取走所有权）。
    pub fn current(&self) -> Option<Arc<TaskControlBlock>> {
        self.now_task_block.as_ref().cloned()
    }

    /// 取出暂存的待重新入队任务（Ready），切到 idle 后由 idle 代为入队。
    pub fn take_pending_ready(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.pending_ready.take()
    }

    /// 暂存一个待重新入队的任务，避免在它自己的内核栈上直接入队。
    pub fn set_pending_ready(&mut self, task: Arc<TaskControlBlock>) {
        self.pending_ready = Some(task);
    }

    /// 取出暂存的待阻塞任务（Blocked），切到 idle 后由 idle 清 on_cpu
    /// 并视情况补唤醒。
    pub fn take_pending_blocked(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.pending_blocked.take()
    }

    /// 暂存一个要进入 Blocked 的任务，等切到 idle 后再处理。
    pub fn set_pending_blocked(&mut self, task: Arc<TaskControlBlock>) {
        self.pending_blocked = Some(task);
    }

    /// 取出一个待释放的 TCB，由 idle 循环渐进 drop。
    pub fn take_pending_drop(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.pending_drop.pop_front()
    }

    /// 将一个已退出任务的 TCB 排入待释放队列，由 idle 渐进释放。
    pub fn set_pending_drop(&mut self, task: Arc<TaskControlBlock>) {
        self.pending_drop.push_back(task);
    }

    /// 取出一个待释放的内核栈，由 idle 循环渐进 drop。
    pub fn take_pending_kstack_drop(&mut self) -> Option<KernelStack> {
        self.pending_kstack_drop.pop_front()
    }

    /// 将一个内核栈排入待释放队列，等 idle 在安全上下文释放。
    pub fn set_pending_kstack_drop(&mut self, kstack: KernelStack) {
        self.pending_kstack_drop.push_back(kstack);
    }

    /// 取出一个待释放的文件对象，由 idle 循环渐进 drop。
    pub fn take_pending_file_drop(&mut self) -> Option<Arc<dyn File + Send + Sync>> {
        self.pending_file_drop.pop_front()
    }

    /// 批量追加待释放的文件对象（如关闭文件描述符表时取出的一批 fd）。
    pub fn extend_pending_file_drop(&mut self, files: Vec<Arc<dyn File + Send + Sync>>) {
        self.pending_file_drop.extend(files);
    }

    /// 取出一个待释放的文件描述符表，由 idle 渐进关闭其内所有 fd。
    pub fn take_pending_files_struct_drop(&mut self) -> Option<Arc<FilesLock>> {
        self.pending_files_struct_drop.pop_front()
    }

    /// 将一个文件描述符表排入待释放队列。仅当引用计数为 1（唯一持有）
    /// 时才需要排队，否则直接 drop 当前引用即可。
    pub fn set_pending_files_struct_drop(&mut self, files: Arc<FilesLock>) {
        self.pending_files_struct_drop.push_back(files);
    }

    /// 取出一个待释放的地址空间（mm），由 idle 渐进 drop 页表。
    pub fn take_pending_mm_drop(&mut self) -> Option<MmRef> {
        self.pending_mm_drop.pop_front()
    }

    /// 将一个地址空间排入待释放队列，避免在 exit 路径同步释放页表。
    pub fn set_pending_mm_drop(&mut self, mm: MmRef) {
        self.pending_mm_drop.push_back(mm);
    }

    /// 是否还有任意类型的待清理项（TCB/栈/文件/fd表/mm）。
    /// idle 循环用此判断是否要 spin 一轮而不是直接进 wfi。
    pub fn has_pending_cleanup(&self) -> bool {
        !self.pending_drop.is_empty()
            || !self.pending_kstack_drop.is_empty()
            || !self.pending_file_drop.is_empty()
            || !self.pending_files_struct_drop.is_empty()
            || !self.pending_mm_drop.is_empty()
    }
}
/// 获取本 hart 当前正在运行的任务（阻塞式获取 processor 锁）。
pub fn current_task() -> Option<Arc<TaskControlBlock>> {
    let processor = local_processor().lock();
    let task = processor.current();
    drop(processor);
    task
}

/// 唤醒路径专用：用 `try_lock` 获取当前任务，拿不到锁就放弃抢占判断，
/// 避免在持有就绪队列锁时再去抢 processor 锁而死锁。
fn current_task_for_wakeup_preempt() -> Option<Arc<TaskControlBlock>> {
    let processor = local_processor().try_lock()?;
    processor.current()
}

/// 获取指定 hart 上当前正在运行的任务，用于唤醒抢占判定。
/// 用 `try_lock` 避免在持有就绪队列锁时再抢 processor 锁而死锁。
pub fn current_task_on_hart(hart: usize) -> Option<Arc<TaskControlBlock>> {
    let processor = PROCESSORS.get(hart)?.try_lock()?;
    processor.current()
}

/// 获取本 hart 当前任务所属的进程。若没有当前任务（idle 上下文等）
/// 则回退到 init 进程，保证调用方总能拿到一个有效 PCB。
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

/// 尝试读取任务的调度类与实时优先级，供唤醒抢占比较使用。
///
/// Linux 的唤醒抢占判断读取的是由调度器锁保护的 `sched_entity` 字段，不会
/// 为了观察另一个任务而等待它的宽 task lock。当前调度字段仍暂存在 TCB.inner
/// 中，因此这里只允许非阻塞快照；拿不到时由调用方根据 RT 类或实际 rq 队首
/// 做有界退化，不阻塞整个唤醒链。
fn task_sched_class_and_priority(task: &Arc<TaskControlBlock>) -> Option<(SchedClass, i32)> {
    let inner = task.try_borrow_mut()?;
    let class = sched_class(inner.scheduling.sched_policy).unwrap_or(SchedClass::Fair);
    Some((class, inner.scheduling.sched_priority))
}

/// 两个 fair(EEVDF) 任务之间的唤醒抢占判定。
fn fair_wakeup_should_preempt_current(
    current: &Arc<TaskControlBlock>,
    woken: &Arc<TaskControlBlock>,
    target_hart: usize,
) -> bool {
    fair_wakeup_preempts_current_on_hart(current, woken, target_hart, monotonic_time_ns())
}

/// 判断刚被唤醒的任务是否应抢占本 hart 当前运行的任务，按调度类分派：
/// 唤醒的 RT 抢占当前 fair；RT 之间比较优先级；fair 之间走 EEVDF 规则；
/// 当前为 RT 而唤醒的是 fair 时不抢占。
fn wakeup_should_preempt_task(
    current: &Arc<TaskControlBlock>,
    woken: &Arc<TaskControlBlock>,
    target_hart: usize,
) -> bool {
    if Arc::ptr_eq(&current, woken) {
        return false;
    }
    let Some((woken_class, woken_priority)) = task_sched_class_and_priority(woken) else {
        // The task is already runnable. Deferring one imprecise preemption is
        // preferable to blocking every waker or forcing an unrelated switch.
        return false;
    };
    let Some((current_class, current_priority)) = task_sched_class_and_priority(current) else {
        // Do not queue behind the running task's broad TCB lock. RT wakees
        // retain strict priority; fair wakees use their actual rq position as
        // the lock-free fallback instead of unconditionally forcing a switch.
        return matches!(woken_class, SchedClass::Fifo | SchedClass::Rr)
            || fair_task_is_next_on_hart(woken, target_hart);
    };
    match (woken_class, current_class) {
        (SchedClass::Fifo | SchedClass::Rr, SchedClass::Fair) => true,
        (SchedClass::Fifo | SchedClass::Rr, SchedClass::Fifo | SchedClass::Rr) => {
            woken_priority > current_priority
        }
        (SchedClass::Fair, SchedClass::Fair) => {
            fair_wakeup_should_preempt_current(&current, woken, target_hart)
                || fair_task_is_next_on_hart(woken, target_hart)
        }
        (SchedClass::Fair, SchedClass::Fifo | SchedClass::Rr) => false,
    }
}

/// 判断被唤醒的任务是否应抢占本 hart（调用方所在 hart）当前运行的任务。
/// 取不到当前任务则视为应抢占（idle 状态，谁来都行）。
fn wakeup_should_preempt_current(woken: &Arc<TaskControlBlock>) -> bool {
    let Some(current) = current_task_for_wakeup_preempt() else {
        return true;
    };
    wakeup_should_preempt_task(&current, woken, hart_id() % MAX_HARTS)
}

/// 判断被唤醒的任务是否应抢占指定 target_hart 上当前运行的任务。
/// 用于跨核唤醒：唤醒方在本地 hart，目标在远端 hart。
fn wakeup_should_preempt_hart(woken: &Arc<TaskControlBlock>, target_hart: usize) -> bool {
    let Some(current) = current_task_on_hart(target_hart) else {
        return true;
    };
    wakeup_should_preempt_task(&current, woken, target_hart)
}

/// 判断新就绪的任务是否应抢占 target_hart 上当前运行的任务。
///
/// 批量唤醒路径先用此函数做一次抢占判定，再合并实际的
/// `NEED_RESCHED`/IPI 工作（`request_reschedule_harts`），
/// 对应 Linux wake_q 风格：遍历等待者时决定哪些 CPU 需要重调度，
/// 每个目标 hart 最多发一个 IPI。
///
/// 特殊情况：被唤醒者是 RT 但目标 hart 的 RT 带宽已节流 → 不抢占
///（节流期间 RT 不该抢任何人）。
pub fn wakeup_should_preempt_target_hart(
    woken: &Arc<TaskControlBlock>,
    target_hart: usize,
) -> bool {
    let local_hart = hart_id() % MAX_HARTS;
    if target_hart >= MAX_HARTS {
        return false;
    }
    if let Some((class, _)) = task_sched_class_and_priority(woken)
        && matches!(class, SchedClass::Fifo | SchedClass::Rr)
        && rt_bandwidth_throttled(target_hart)
    {
        return false;
    }
    if target_hart == local_hart {
        wakeup_should_preempt_current(woken)
    } else {
        wakeup_should_preempt_hart(woken, target_hart)
    }
}

/// 唤醒任务入队后调用：若它应抢占目标 hart 的当前任务，则置位目标 hart 的
/// `NEED_RESCHED`，远端 hart 通过 IPI 尽快走到返回用户态前的调度点。
pub fn request_reschedule_for_wakeup(woken: &Arc<TaskControlBlock>, target_hart: usize) {
    let local_hart = hart_id() % MAX_HARTS;
    if target_hart >= MAX_HARTS {
        return;
    }
    if !wakeup_should_preempt_target_hart(woken, target_hart) {
        return;
    }
    NEED_RESCHED[target_hart].store(true, Ordering::Release);
    if target_hart != local_hart {
        arch::send_ipi(target_hart);
    }
}

/// `request_reschedule_for_wakeup` 的合并版，对应 Linux wake_q 风格。
///
/// 批量唤醒时遍历等待者，收集哪些 hart 需要重调度，然后统一置位
/// `NEED_RESCHED` 并对每个远端 hart 最多发一个 IPI，避免逐个唤醒
/// 逐个发 IPI 的开销。
pub fn request_reschedule_harts(target_mask: usize) {
    let local_hart = hart_id() % MAX_HARTS;
    for target_hart in 0..MAX_HARTS {
        if (target_mask & (1usize << target_hart)) != 0 {
            NEED_RESCHED[target_hart].store(true, Ordering::Release);
        }
    }
    for target_hart in 0..MAX_HARTS {
        if target_hart != local_hart && (target_mask & (1usize << target_hart)) != 0 {
            arch::send_ipi(target_hart);
        }
    }
}

/// 当前 hart 需要在返回用户态前重新调度。
///
/// 用于已经有 runnable 任务等待、但当前路径不是严格的 blocked->ready 唤醒
/// 的场景。例如信号投递给已在就绪队列中的任务时，Linux 可以在 syscall 返回前
/// 发生抢占；本内核需要显式补一个合作式抢占点。
pub fn request_reschedule_current_hart() {
    let local_hart = hart_id() % MAX_HARTS;
    NEED_RESCHED[local_hart].store(true, Ordering::Release);
}

/// trap 返回用户态前的抢占点：本 hart 若被标记 `NEED_RESCHED` 就让出当前任务，
/// 使刚唤醒的高优先级任务尽快得到运行，缓解 starvation。仿 Linux 的
/// `TIF_NEED_RESCHED` 检查点。
pub fn reschedule_before_user_return_if_needed() {
    let local_hart = hart_id() % MAX_HARTS;
    if !NEED_RESCHED[local_hart].swap(false, Ordering::AcqRel) {
        return;
    }
    if current_task().is_some() {
        suspend_current_and_run_next();
    }
}

pub(crate) fn current_files() -> Arc<FilesLock> {
    let process = current_process();
    process.files()
}

pub(crate) fn current_files_and_nofile_limit() -> (Arc<FilesLock>, usize) {
    let process = current_process();
    let inner = process.borrow_mut();
    (
        Arc::clone(&inner.files),
        inner.rlimits.rlimit_nofile_cur as usize,
    )
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
/// 调度核心函数,直接完成任务的切换，传入参数为我们需要切换的任务的上下文
/// 完毕之后，该hart 进入idle_task,idle-Task会进入调度循环idle_task()
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    // Keep current-task removal, FP owner teardown and the actual context
    // switch atomic with respect to local timer/IPI handling. Exit paths call
    // schedule directly, so gate stale user extension state here as well.
    let _ = arch::disable_interrupts();
    arch::discard_user_fp_state();
    #[cfg(target_arch = "riscv64")]
    // The RISC-V trap path runs part of the kernel on the current user SATP
    // with shared kernel roots. Switch to the full kernel SATP before the idle
    // scheduler can drop or recycle the outgoing task's address space.
    crate::mm::activate_kernel_space();
    let mut processor = local_processor().lock();
    let idle_task_cx_ptr = processor.get_idle_task_ptr();
    drop(processor);
    // SAFETY: both task contexts are valid kernel stack pointers owned by their respective tasks;
    // switched_task_cx_ptr is the current task's context, idle_task_cx_ptr is the idle context.
    unsafe {
        switch::switch(
            switched_task_cx_ptr as *const usize,
            idle_task_cx_ptr as *const usize,
        );
    }
}

/// 时钟 tick 驱动的抢占判定：根据当前任务的调度类决定是否需要让出 CPU。
///
/// 对应 Linux 时钟中断里的 `scheduler_tick()` → `requeue_task()` / `check_preempt_tick()`
/// 路径。本函数只回答"该不该抢"，不执行切换；由调用方（trap handler 的 timer 分支）
/// 在返回 true 时调用 `suspend_current_and_run_next()`。
///
/// 三种调度类的判定规则：
///
/// - **Fair（SCHED_OTHER/BATCH/IDLE）**：RT 绝对优先，只要本 hart 有任意就绪 RT 任务
///   就立即让出；否则检查 EEVDF 虚拟截止时间是否到期（`fair_current_deadline_expired`），
///   到期则让同组其他 fair 任务轮转一次。若没有 fair 竞争者（`ready_fair_count == 0`），
///   即使 deadline 到了也不让出。
///
/// - **FIFO（SCHED_FIFO）**：无时间片概念，只在两种情况让出——RT 带宽被节流
///   （用满 `sched_rt_runtime_us`，强制给 fair 留窗口）或有**严格更高优先级**的
///   RT 任务就绪。同优先级 FIFO 不轮转，先到先跑到阻塞/退出为止。
///
/// - **RR（SCHED_RR）**：在 FIFO 基础上增加同优先级轮转。每个 tick 递增 `rr_ticks`，
///   到达 `sched_rr_timeslice_ms`（默认 100ms = 10 tick）后，若有**同优先级或更高**
///   的 RT 任务就绪则让出轮转；没有则继续跑下一轮。更高优先级 RT 和带宽节流
///   仍然立即抢占，不等时间片。
pub fn should_preempt_current_on_tick() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let (policy, rt_prio) = {
        let inner = task.borrow_mut();
        (
            inner.scheduling.sched_policy,
            inner.scheduling.sched_priority,
        )
    };
    match sched_class(policy) {
        // Fair 类：RT 绝对优先，其次看 EEVDF deadline 是否到期。
        Some(SchedClass::Fair) | None => {
            // 任意优先级的 RT 任务就绪 → 立即让出（RT 永远优先于 fair）。
            if has_ready_rt_at_or_above(RT_PRIO_MIN) {
                return true;
            }
            // EEVDF 虚拟截止时间到期 → 让同组 fair 任务轮转。
            // 内部会先检查 ready_fair_count > 0，没有竞争者则不让。
            if fair_current_deadline_expired(&task, monotonic_time_ns()) {
                // rr_ticks 复用为 fair 的 tick 计数，抢占后清零。
                task.borrow_mut().rr_ticks = 0;
                return true;
            }
            false
        }
        // FIFO 类：无时间片，只在带宽节流或更高优先级 RT 时让出。
        Some(SchedClass::Fifo) => {
            //  分别是是否节流，以及 是否有更高优先级
            rt_bandwidth_throttled(hart_id()) || has_ready_rt_higher_than(rt_prio)
        }
        // RR 类：在 FIFO 基础上增加同优先级时间片轮转。
        Some(SchedClass::Rr) => {
            // 带宽节流 → 强制让出，给 fair 留窗口。
            if rt_bandwidth_throttled(hart_id()) {
                return true;
            }
            // 更高优先级 RT 就绪 → 立即让出（严格优先级）。
            if has_ready_rt_higher_than(rt_prio) {
                return true;
            }
            let mut task_inner = task.borrow_mut();
            // 累加本轮已消耗的 tick。
            task_inner.rr_ticks = task_inner.rr_ticks.saturating_add(1);
            // 还没到时间片（默认 10 tick = 100ms）→ 继续跑。
            // RR 还未轮转完
            if task_inner.rr_ticks < rr_timeslice_ticks() {
                return false;
            }
            // RR 轮转逻辑，如果轮转完毕 就切换
            // 时间片到 → 清零计数，检查是否有同优先级或更高的 RT 任务可轮转。
            // has_ready_rt_at_or_above 含同优先级（..=idx），所以同优先级会轮转；
            // 没有同优先级就绪则继续跑下一轮。
            task_inner.rr_ticks = 0;
            // 再判断一次
            has_ready_rt_at_or_above(rt_prio)
        }
    }
}

/// syscall 返回用户态前的额外抢占检查。
///
/// Linux 在 syscall/interrupt 返回路径主要消费 `TIF_NEED_RESCHED`；fair
/// slice 到期由 tick/update_curr 或 wakeup path 置位，而不是每次 syscall
/// return 都重新计算一次 EEVDF deadline。这里仅保留 RT runnable 的防御性
/// 快路径，普通 fair 抢占交给下面的 `reschedule_before_user_return_if_needed()`。
pub fn should_preempt_current_on_syscall_return() -> bool {
    if let Some(task) = current_task() {
        let policy = task.borrow_mut().scheduling.sched_policy;
        if matches!(
            sched_class(policy),
            Some(SchedClass::Fifo) | Some(SchedClass::Rr)
        ) && rt_bandwidth_throttled(hart_id())
        {
            return true;
        }
    }
    has_ready_rt_at_or_above(RT_PRIO_MIN) && should_preempt_current_on_tick()
}

/// Busy-poll 等内核短自旋循环使用的轻量 `need_resched` 判断。
/// Linux `napi_busy_loop()` 只在真正需要调度时退出忙轮询；不能因为普通
/// fair runnable 任务存在就每轮让出，否则 50us 的 busy-poll 预算会被
/// 上下文切换成本放大。
pub fn should_resched_for_busy_poll() -> bool {
    let local_hart = hart_id() % MAX_HARTS;
    NEED_RESCHED[local_hart].swap(false, Ordering::AcqRel) || has_ready_rt_at_or_above(RT_PRIO_MIN)
}

/// 调度器核心循环（idle 循环），每个 hart 独立运行一个实例。
///
/// 这是整个调度器的心脏：所有任务让出 CPU 后都会切回这个循环，由它负责
/// 选出下一个要运行的任务并切换过去。函数永不返回，一直循环到系统关闭。
///
/// 每轮循环分四个阶段：
///
/// 1. **延迟入队/唤醒**（关中断）：处理上一个切走任务的 `pending_blocked` /
///    `pending_ready`。任务不能在自己的 `suspend` / `block` 路径里直接入队
///    （它还在用自己的内核栈），而是暂存到 Processor 上，切到 idle 后才由
///    idle 代为入队。这是 SMP 下避免"任务还在用自己栈就被别人调度"的关键。
///
/// 2. **后台清理**（开中断）：idle 兼当垃圾回收 worker，渐进释放退出任务的
///    TCB、内核栈、地址空间、文件描述符表等重资源。有就绪任务时清理预算=1
///    （快速让出），无就绪任务时用大预算（利用空闲）。清理在开中断下进行，
///    不会屏蔽定时器 tick。
///
/// 3. **选任务并切换**（关中断）：调 `fetch_task()` → `TaskManager::fetch`
///    （RT 优先 → fair 兜底 → fair 内部两级 EEVDF），选中后恢复浮点状态、
///    记录运行起点、标记 on_cpu、切到目标任务。switch 返回时说明目标任务
///    又让出了 CPU，回到循环顶部继续下一轮。
///
/// 4. **无任务可跑 → 空闲等待**：检查待清理项、延迟内核定时器、过期 sleep
///    定时器；若真没活则开中断 + `wfi` 省电等待，被定时器/IPI 唤醒后回到
///    循环顶部重新检查 `fetch_task`。
pub fn idle_task() {
    #[allow(dead_code)]
    static EMPTY_SPINS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    /// 以下都是调试用 TODO: 使用规范的日志模块
    static IDLE_FIRST_LOG: AtomicBool = AtomicBool::new(true);
    static IDLE_FIRST_SWITCH_LOG: AtomicBool = AtomicBool::new(true);
    loop {
        // 确保内核态 trap 使用内核态 handler（stvec 指向 alltraps_k）。
        init_trap();
        ///  日志处理
        if IDLE_FIRST_LOG.swap(false, Ordering::SeqCst) {
            let hart = hart_id();
            let lens = ready_queue_lengths();
            println!("[idle] enter hart={} ready_queues={:?}", hart, lens);
        }
        // 阶段 1 入口：关中断，防止定时器驱动的唤醒在入队时与本 hart
        // 的运行队列锁递归竞争。
        let _ = arch::disable_interrupts();

        // 处理上一个切走的任务：它想变成 Blocked。
        // 此时任务已不在 CPU 上（已切到 idle 上下文），可以安全清理 on_cpu。
        // NOTE: 如果在这之前就将task 入队，那么另一个hart 可能进入 从而导致问题
        if let Some(task) = local_processor().lock().take_pending_blocked() {
            let should_wake = {
                // Pairs with the irq-safe task transition lock in
                // try_to_wake_up(): publish on_cpu=OFF and consume a pending
                // wake atomically with respect to the waker's decision.
                let _wakeup_guard = task.lock_wakeup_transition();
                task.clear_on_cpu();
                task.wakeup_pending
                    .swap(false, core::sync::atomic::Ordering::AcqRel)
            };
            // 切走期间有人尝试唤醒它（wakeup_pending）→ 补唤醒。
            // 对应 Linux try_to_wake_up() 等 prev 离开 CPU 后再走正常唤醒路径，
            // 使 wakeup_preempt() 能正确设 NEED_RESCHED。
            if should_wake {
                let sync_hart = task.wakeup_sync_hart.swap(
                    TaskControlBlock::OFF_CPU,
                    core::sync::atomic::Ordering::AcqRel,
                );
                if sync_hart < MAX_HARTS {
                    wakeup_sync_task_on_hart(task, sync_hart);
                } else {
                    wakeup_task(task);
                }
            }
        }

        // 处理上一个切走的任务：它要重新 Ready（时间片到/被抢占）。
        // 延迟到 idle 上下文才入队，保证任务不再使用自己的内核栈时才
        // 对其他 hart 可见，避免 SMP 下同一任务被两个 hart 同时调度。
        if let Some(task) = local_processor().lock().take_pending_ready() {
            {
                let _wakeup_guard = task.lock_wakeup_transition();
                task.clear_on_cpu();
                task.wakeup_pending
                    .store(false, core::sync::atomic::Ordering::Release);
                task.wakeup_sync_hart.store(
                    TaskControlBlock::OFF_CPU,
                    core::sync::atomic::Ordering::Release,
                );
            }
            requeue_task(task);
        }

        // 处理内核态定时器中断延迟的工作（只置位、不立即处理的那部分）。
        drain_deferred_kernel_timer_work();
        // 阶段 1 结束：开中断，保证后面的后台清理不会屏蔽定时器 tick。
        // 清理可能释放管道、socket、地址空间、fd 表等，耗时较长，不应
        // 在关中断下进行。
        arch::enable_interrupts();

        // 阶段 2：后台清理（idle 兼垃圾回收 worker）。
        // 有就绪任务时用小预算（赶紧让出）；无就绪任务时用大预算（利用空闲）。
        let runnable_work_waiting = idle_cleanup_should_stop_for_runnable_work();
        let mm_drop_budget = if runnable_work_waiting {
            1
        } else {
            IDLE_MM_DROP_BUDGET
        };
        let cleanup_budget = if runnable_work_waiting {
            1
        } else {
            IDLE_CLEANUP_BUDGET
        };

        // 2a：文件描述符表清理——批量取出待关闭的 fd，分批 drop。
        // 有就绪任务时跳过（不优先做文件清理）。
        if !runnable_work_waiting {
            for _ in 0..IDLE_FILES_STRUCT_DROP_BUDGET {
                let Some(files) = local_processor().lock().take_pending_files_struct_drop() else {
                    break;
                };
                let (detached, files_done) = {
                    let mut files_guard = files.lock();
                    let detached = files_guard.take_file_close_batch(IDLE_FILES_STRUCT_CLOSE_BATCH);
                    (detached, files_guard.is_empty())
                };
                let files_to_drop = detached
                    .into_iter()
                    .map(|detached| detached.complete_close())
                    .collect::<Vec<_>>();
                if !files_done {
                    // 还有剩余，放回 pending 队列下轮继续。
                    local_processor()
                        .lock()
                        .set_pending_files_struct_drop(files);
                }
                if !files_to_drop.is_empty() {
                    local_processor()
                        .lock()
                        .extend_pending_file_drop(files_to_drop);
                }
                if idle_cleanup_should_stop_for_runnable_work() {
                    break;
                }
            }

            // 2b：逐个 drop 文件对象。
            for _ in 0..IDLE_FILE_DROP_BUDGET {
                let Some(file) = local_processor().lock().take_pending_file_drop() else {
                    break;
                };
                drop(file);
                if idle_cleanup_should_stop_for_runnable_work() {
                    break;
                }
            }
        }

        // Socket destructors only enqueue their final network-namespace
        // release: they may run while a weak-socket registry is locked. Retry
        // teardown here, outside file/registry locks, one namespace per loop.
        crate::syscall::net::drain_pending_net_namespace_cleanup();

        // 2c：释放地址空间（mm）。drop 页表可能很重，故限制每轮预算。
        for _ in 0..mm_drop_budget {
            let Some(mm) = local_processor().lock().take_pending_mm_drop() else {
                break;
            };
            drop(mm);
            if !runnable_work_waiting && idle_cleanup_should_stop_for_runnable_work() {
                break;
            }
        }

        // 2d：释放已退出任务的 TCB（Arc drop）。
        // 僵尸进程优先 eager release（清 slot），但有额外引用时保留给 wait4 reap。
        for _ in 0..cleanup_budget {
            let Some(task) = local_processor().lock().take_pending_drop() else {
                break;
            };
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
            // 尝试从进程的线程列表中清掉这个 task 的 slot。
            // 僵尸进程且有额外引用时保留 slot，让 wait4 能 reap。
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
            if !runnable_work_waiting && idle_cleanup_should_stop_for_runnable_work() {
                break;
            }
        }

        // 2e：释放内核栈。
        for _ in 0..cleanup_budget {
            let Some(kstack) = local_processor().lock().take_pending_kstack_drop() else {
                break;
            };
            drop(kstack);
            if !runnable_work_waiting && idle_cleanup_should_stop_for_runnable_work() {
                break;
            }
        }

        // 阶段 3：选任务并切换。
        // 关中断：fetch + 设置 on_cpu + switch 必须原子于定时器中断。
        let _ = arch::disable_interrupts();
        drain_deferred_kernel_timer_work();
        if let Some(task) = fetch_task() {
            // A task may be scheduled after taking TaskUserRes solely to
            // finish kernel-side exit cleanup.  It resumes its saved kernel
            // context and must not touch the already-unmapped user/FP state.
            let has_user_res = task.borrow_mut().res.is_some();
            if has_user_res {
                arch::restore_user_fp_state(&task);
            } else {
                arch::discard_user_fp_state();
            }
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
            let now_ns = monotonic_time_ns();
            // 记录任务开始运行的时间戳，用于 vruntime 运行时间统计。
            start_task_runtime_slice(&task, now_ns);
            let mut task_inner = task.borrow_mut();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
            // 首次调度日志。
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
                    crate::trap::trap_return as *const () as usize
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
            // 同步 trap context 中的 kernel_tp（hart id），适配跨核迁移。
            // Exit-cleanup continuations no longer own a trap context.
            if task_inner.res.is_some() {
                task_inner.get_trap_cx().kernel_tp = hart_id();
            }
            task.mark_on_cpu(hart_id());
            task_inner.task_status = TaskStatus::Running;

            drop(task_inner);
            // 把目标任务设为当前任务。
            processor.now_task_block = Some(task);
            drop(processor);

            // 切换：idle 上下文 → 目标任务上下文。
            // switch 返回时说明目标任务又让出了 CPU，回到 idle 循环继续。
            // 关中断保持到 sret：返回用户态时 sret 会自动开中断。
            // SAFETY: 两个上下文指针都是各自内核栈上的有效 TaskContext，
            // idle_task_cx_ptr 是 idle 上下文，next_task_cx_ptr 是目标任务的保存上下文。
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
            // 阶段 4：没有就绪任务 → 空闲等待。
            // 4a：还有待清理项 → spin 一轮，不进 wfi（清理可能很快产生就绪任务）。
            if local_processor().lock().has_pending_cleanup() {
                core::hint::spin_loop();
                continue;
            }
            // 4b：watchdog 诊断——空转太久则 dump 系统状态。
            if crate::debug_config::DEBUG_WATCHDOG {
                let c = EMPTY_SPINS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if c == 1_000 {
                    crate::task::manager::dump_system_state();
                }
            }
            // 4c：处理内核态定时器中断延迟的 tick。
            // 内核态定时器中断只置位，不立即处理（避免在持锁 syscall 上下文里
            // 做唤醒/分配）。这里在无就绪任务时安全处理。
            if crate::task::block_sleep::take_deferred_kernel_timer_tick() {
                crate::task::block_sleep::check_timer();
                core::hint::spin_loop();
                continue;
            }
            // 4d：检查已过期的 sleep 定时器。
            // 在进 wfi 之前 poll 已到期的 sleep timer，未来的留给硬件定时器。
            if crate::task::block_sleep::has_due_sleep_timer() {
                crate::task::block_sleep::check_timer();
                core::hint::spin_loop();
                continue;
            }
            // 4e：真的没活了 → 开中断 + wfi 省电等待。
            // wfi 会被定时器中断或 IPI 唤醒；唤醒后 loop 回去重新检查 fetch_task，
            // 因为定时器/IPI 可能已经唤醒了任务使其变为就绪。
            arch::enable_interrupts();
            arch::wait_for_interrupt();
            // 唤醒后立即回到循环顶部检查就绪任务。
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

/// 每 hart 的“需要重新调度”标志，仿 Linux 的 `TIF_NEED_RESCHED`：
/// 唤醒路径里由 `request_reschedule_for_wakeup` 置位，返回用户态前由
/// `reschedule_before_user_return_if_needed` 消费。
static NEED_RESCHED: [AtomicBool; MAX_HARTS] = [const { AtomicBool::new(false) }; MAX_HARTS];

pub fn go_to_first_task() -> ! {
    idle_task();
    panic!("Unreachable in go_to_first_task!");
}
fn suspend_current_and_run_next_impl(interruptible: bool) {
    // Once TaskUserRes has been taken, this stack is already executing the
    // one-shot exit cleanup.  A cold robust-list/clear_child_tid access may
    // still yield through block-device I/O; that yield must not recursively
    // enter exit again or inspect user signal state after the trap context was
    // removed.
    let (kernel_exit_cleanup, exec_exit_requested) = current_task()
        .map(|task| {
            let kernel_exit_cleanup = task.borrow_mut().res.is_none();
            (kernel_exit_cleanup, task.exec_exit_requested())
        })
        .unwrap_or((false, false));
    // Exec de-threading is task-local and does not enqueue a normal SIGKILL
    // bit (which would risk being rebroadcast to the exec owner).  Interruptible
    // kernel wait loops must therefore consume the token directly instead of
    // waiting to reach the user-return signal path.
    if interruptible && !kernel_exit_cleanup && exec_exit_requested {
        exit_current_and_run_next(0);
    }
    // If the current process has a fatal pending signal, terminate it even if we are
    // inside a long-running/blocking syscall loop (where we may never return to the
    // trap handler's "check signal then return to user" path).
    //
    // Use `try_borrow_mut` to avoid deadlocking if the caller already holds the PCB lock.
    if interruptible
        && !kernel_exit_cleanup
        && let Some((errno, msg)) = crate::task::signal::check_if_current_signals_error()
    {
        crate::task::signal::log_signal_exit(msg);
        exit_group_and_run_next(errno);
    }
    let interrupts_were_enabled = arch::disable_interrupts();
    let Some(task) = take_current_task() else {
        arch::restore_interrupts(interrupts_were_enabled);
        return;
    };
    charge_task_runtime_for_scheduler(&task);

    // ---- access current TCB exclusively
    let mut task_inner = task.borrow_mut();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    let has_user_res = task_inner.res.is_some();
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
    if has_user_res {
        arch::save_user_fp_state(&task);
    } else {
        arch::discard_user_fp_state();
    }
    local_processor().lock().set_pending_ready(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
    arch::restore_interrupts(interrupts_were_enabled);
}

pub fn suspend_current_and_run_next() {
    suspend_current_and_run_next_impl(true);
}

/// Cooperatively yield while retaining ownership of an in-flight kernel
/// resource. Pending fatal signals are handled after the resource completes.
pub fn suspend_current_and_run_next_uninterruptible() {
    suspend_current_and_run_next_impl(false);
}

/// Commit a task that was marked `Blocked` by [`PreparedWait`].
///
/// `PreparedWait` owns the irq-save guard across this call.  Do not perform
/// signal checks or re-enable interrupts here: condition-wait callers check
/// interruption before arming, and a signal arriving after arming sets
/// `wakeup_pending`, which cancels or immediately reverses this sleep.
fn block_prepared_current_and_run_next() {
    let Some(task) = take_current_task() else {
        return;
    };
    charge_task_runtime_for_scheduler(&task);

    let mut task_inner = task.borrow_mut();
    debug_assert_eq!(task_inner.task_status, TaskStatus::Blocked);
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    let has_user_res = task_inner.res.is_some();
    task_inner.rr_ticks = 0;
    drop(task_inner);

    if has_user_res {
        arch::save_user_fp_state(&task);
    } else {
        arch::discard_user_fp_state();
    }
    record_fair_sleep_lag(&task);
    local_processor().lock().set_pending_blocked(task);
    schedule(task_cx_ptr);
}

fn block_current_and_run_next_impl(interruptible: bool) {
    let (kernel_exit_cleanup, exec_exit_requested) = current_task()
        .map(|task| {
            let kernel_exit_cleanup = task.borrow_mut().res.is_none();
            (kernel_exit_cleanup, task.exec_exit_requested())
        })
        .unwrap_or((false, false));
    if interruptible && !kernel_exit_cleanup && exec_exit_requested {
        exit_current_and_run_next(0);
    }
    // Ordinary syscall waits remain killable.  Kernel-owned resources such as
    // an in-flight DMA request use the uninterruptible entry point below so a
    // fatal signal cannot abandon device-owned memory or a lock hand-off.
    if interruptible
        && !kernel_exit_cleanup
        && let Some((errno, msg)) = crate::task::signal::check_if_current_signals_error()
    {
        crate::task::signal::log_signal_exit(msg);
        exit_group_and_run_next(errno);
    }
    let interrupts_were_enabled = arch::disable_interrupts();
    let Some(task) = take_current_task() else {
        arch::restore_interrupts(interrupts_were_enabled);
        return;
    };
    charge_task_runtime_for_scheduler(&task);

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
    let has_user_res = task_inner.res.is_some();
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

    if has_user_res {
        arch::save_user_fp_state(&task);
    } else {
        // The task is already committed to exit and will never return to user
        // mode; only its saved kernel context remains live.
        arch::discard_user_fp_state();
    }
    if should_block {
        record_fair_sleep_lag(&task);
        local_processor().lock().set_pending_blocked(task);
    } else {
        // Behave like a yield: enqueue after we have switched back to idle
        // to avoid "run on two harts".
        local_processor().lock().set_pending_ready(task);
    }
    // jump to scheduling cycle
    schedule(task_cx_ptr);
    arch::restore_interrupts(interrupts_were_enabled);
}

pub fn block_current_and_run_next() {
    block_current_and_run_next_impl(true);
}

/// Block without consuming fatal signals until the wait condition is complete.
///
/// This is reserved for kernel-internal waits whose owner cannot disappear
/// safely, notably sleeping locks and submitted DMA requests.  The normal trap
/// return path observes any pending signal immediately after the resource has
/// been released.
pub fn block_current_and_run_next_uninterruptible() {
    block_current_and_run_next_impl(false);
}

/// pid of usertests app in make run TEST=1
pub const IDLE_PID: usize = 0;

// 线程(task)  单位的推出
pub fn exit_current_and_run_next(exit_code: i32) -> ! {
    // Keep the task installed as this hart's current task until robust-futex
    // and clear_child_tid uaccess has completed. Linux performs both while
    // `current` still owns its mm; removing it earlier prevents lazy/COW fault
    // resolution in the uaccess helpers.
    let task = current_task().expect("exit without a current task");
    let Some(process) = task.process.upgrade() else {
        let installed_task = take_current_task().unwrap();
        debug_assert!(Arc::ptr_eq(&task, &installed_task));
        drop(installed_task);
        charge_task_runtime_for_scheduler(&task);
        task.clear_on_cpu();
        if DEBUG_SCHED {
            log::warn!("[exit] task lost process; dropping task and scheduling idle");
        }
        queue_exiting_task_drop(task);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        unreachable!("schedule should not return after task exit");
    };
    // A concurrent exit_group owns the process exit status and teardown.  Join
    // that rendezvous even if this thread reached the plain exit syscall just
    // before observing its SIGKILL.
    if process.group_exit_in_progress() && !task.exec_exit_requested() {
        exit_group_and_run_next(process.group_exit_code());
    }
    // Extract exit bookkeeping first, then perform Linux-thread cleanup without
    // holding the TCB lock so the same logic can be reused by exit_group().
    let cleanup = take_thread_exit_cleanup(&task, exit_code);
    let drop_user_res = cleanup.tid != 0;
    let drop_user_res = drop_user_res || cleanup.is_linux_thread;
    let (tid, is_linux_thread, clear_child_tid_addr, live_thread_retirement) =
        finish_thread_exit_cleanup(&process, cleanup, drop_user_res);

    let installed_task = take_current_task().expect("current task disappeared during exit cleanup");
    debug_assert!(Arc::ptr_eq(&task, &installed_task));
    // `current_task()` above cloned the TCB so robust-list and clear_child_tid
    // cleanup could run while the task remained installed on this hart. Drop
    // the processor-owned clone explicitly: this function switches away via
    // `schedule()` and never unwinds, so shadowing it would leak the TCB and
    // therefore the complete user mm on every process exit.
    drop(installed_task);
    charge_task_runtime_for_scheduler(&task);
    // This task will never be scheduled again; ensure it is considered off CPU.
    task.clear_on_cpu();

    let (exec_peer, last_live_thread) = retire_exiting_task(
        &process,
        &task,
        tid,
        is_linux_thread && tid != 0 && tid != usize::MAX,
        live_thread_retirement,
    );
    if exec_peer && !last_live_thread {
        queue_exiting_task_drop(task);
        drop(process);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        unreachable!("schedule should not return for an exec peer");
    }
    if last_live_thread {
        let mut process_inner = process.borrow_mut();
        debug_assert!(!process_inner.exit_teardown);
        process_inner.exit_teardown = true;
    }

    if !exec_peer && tid != 0 && tid != usize::MAX {
        if DEBUG_PTHREAD {
            log::debug!(
                "[thread_exit] pid={} tid={} ctid={:#x} linux_thread={}",
                process.getpid(),
                tid,
                clear_child_tid_addr.unwrap_or(0),
                is_linux_thread
            );
        }
    }

    // A plain exit may have crossed its initial group-exit check just before a
    // peer published exit_group(), or it may be the final exec peer after the
    // exec owner was killed.  Linux preserves the winning group status.
    let effective_exit_code = if process.group_exit_in_progress() {
        process.group_exit_code()
    } else {
        exit_code
    };
    if effective_exit_code != exit_code {
        task.borrow_mut().exit_code = Some(effective_exit_code);
    }

    log::debug!(
        "[exit] pid={} tid={} exit_code={}",
        process.getpid(),
        tid,
        effective_exit_code
    );

    let dumped_core = process_dumped_core(&process, effective_exit_code);
    let process_cpu_ns =
        crate::task::runtime::process_cpu_time_ns_at(&process, monotonic_time_ns());

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
    if last_live_thread {
        let pid = process.getpid();
        if pid == IDLE_PID {
            println!(
                "[kernel] Idle process exit with exit_code {} ...",
                effective_exit_code
            );
            if effective_exit_code != 0 {
                //crate::sbi::shutdown(255); //255 == -1 for err hint
                arch::shutdown();
            } else {
                //crate::sbi::shutdown(0); //0 for success hint
                arch::shutdown();
            }
        }
        // Detach files and fs_struct before publishing zombie state, matching
        // Linux's exit_files()/exit_fs() ordering ahead of exit_notify().
        // Heavy anonymous file destruction remains deferred below; dropping
        // our fs_struct Arc immediately releases cwd/root pins unless another
        // live CLONE_FS owner still shares the same context.
        let (old_files, old_fs) = {
            let mut process_inner = process.borrow_mut();
            crate::syscall::process::unregister_executing_inode(
                process_inner.exec_inode_dev,
                process_inner.exec_inode_num,
            );
            let old_files = core::mem::replace(
                &mut process_inner.files,
                Arc::new(FilesLock::new(FilesStruct::new())),
            );
            let old_fs = process_inner.fs.take();
            (old_files, old_fs)
        };
        close_files_struct_fd_refs_if_unshared(&old_files);
        drop(old_fs);
        // Drop the child PCB lock before filesystem teardown and parent
        // notification to avoid lock inversion.
        crate::syscall::process::release_ptrace_tracer(&process);
        kill_pid_namespace_members_on_init_exit(&process);
        cgroup_exit_process(pid);
        crate::syscall::sysv_ipc::exit_cleanup(pid);
        crate::syscall::filesystem::acct_process_exit(&process, effective_exit_code);

        reparent_orphaned_children(&process);

        let empty_mm = MmRef::new(MemorySet::new_bare());
        let (old_mm_token, old_net_ns_id, mut old_mm, zombie_tasks) = {
            let mut process_inner = process.borrow_mut();
            process_inner.clear_children();
            process_inner.exited_children.clear();
            let old_mm_token = process_inner.memory_set.token();
            let old_net_ns_id = process_inner.net_ns_id;
            let zombie_tasks = process_inner
                .tasks
                .iter()
                .filter_map(|task| task.as_ref().map(Arc::clone))
                .collect::<Vec<_>>();
            // Linux releases `mm_struct` at exit and keeps only zombie metadata.
            // Drop the full user address space here so unreaped zombies do not pin
            // page-table pages (and COW refs) during fork-heavy workloads.
            let old_mm = core::mem::replace(&mut process_inner.memory_set, empty_mm.clone());
            (old_mm_token, old_net_ns_id, old_mm, zombie_tasks)
        };
        for zombie_task in zombie_tasks {
            drop(zombie_task.replace_memory_set(empty_mm.clone()));
        }
        let old_shm_cleanup = old_mm.take_sysv_shm_attaches_for_cleanup();
        crate::syscall::filesystem::release_all_record_locks_for_owner(pid);
        crate::syscall::filesystem::release_all_file_leases_for_owner(pid);
        if !release_process_mm_owner(old_mm_token) {
            crate::syscall::net::clear_packet_ring_mmaps_for_token(old_mm_token);
        }
        if let Some(old_shm) = old_shm_cleanup {
            crate::syscall::sysv_shm::exit_cleanup(&old_shm);
        }
        if let Some(released_net_ns_id) = process.release_net_namespace_owner() {
            debug_assert_eq!(released_net_ns_id, old_net_ns_id);
            crate::syscall::net::cleanup_net_namespace_if_unused(released_net_ns_id);
        }
        queue_files_struct_drop(old_files);
        queue_mm_drop(old_mm);
        let publication =
            publish_process_exit(&process, dumped_core, effective_exit_code, process_cpu_ns);
        if let Some(parent) = publication.parent.as_ref()
            && publication.exit_signal > 0
        {
            crate::task::signal::queue_process_signal(
                parent.getpid(),
                publication.exit_signal as usize,
            );
        }
        wakeup_tasks(publication.parent_waiters);
        crate::fs::wake_tasks(publication.pidfd_waiters);
        // Keep zombie `tasks[]` until wait4() reaps the process so reaping has
        // a deterministic place to drop any lingering task Arcs.
    }

    if tid != 0 {
        // This path never returns after schedule(); move `task` out now so it can be dropped on idle.
        queue_exiting_task_drop(task);
        drop(process);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        unreachable!("schedule should not return after task exit");
    }
    // Drop the current task after switching to idle to avoid leaking the final
    // strong Arc from this never-returning exit path.
    queue_exiting_task_drop(task);
    drop(process);
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
    unreachable!("schedule should not return after task exit");
}

/// Terminate the entire process, even when called from a non-main thread.
pub fn exit_group_and_run_next(exit_code: i32) -> ! {
    let task = current_task().expect("exit_group without a current task");
    let Some(process) = task.process.upgrade() else {
        let installed_task = take_current_task().unwrap();
        debug_assert!(Arc::ptr_eq(&task, &installed_task));
        drop(installed_task);
        task.clear_on_cpu();
        queue_exiting_task_drop(task);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        unreachable!("schedule should not return after group exit");
    };
    // SIGKILL sent by de-threading is task-local: it must retire this peer,
    // not start a process-wide group exit that would also kill the exec caller.
    if task.exec_exit_requested() {
        exit_current_and_run_next(0);
    }
    let tid = task
        .borrow_mut()
        .res
        .as_ref()
        .map(|res| res.tid)
        .unwrap_or(usize::MAX - 1);
    // The initiating thread broadcasts SIGKILL to the complete thread group.
    // Every member then exits independently. This mirrors Linux's group-exit
    // rendezvous and, crucially, never spins waiting for a remote hart that may
    // currently be inside a long-running syscall.
    if process.begin_group_exit(&task, tid, exit_code) {
        let _ = crate::task::signal::kill_current(crate::task::signal::SIGKILL_NUM as i32);
    }
    // begin_group_exit() serializes with exec snapshot publication.  If exec
    // won while this task was entering group exit, its task-local request is
    // now fully visible and must not be turned into a process-wide exit.
    if task.exec_exit_requested() {
        exit_current_and_run_next(0);
    }
    let exit_code = process.group_exit_code();

    let cleanup = take_thread_exit_cleanup(&task, exit_code);
    let drop_user_res = cleanup.tid != 0 || cleanup.is_linux_thread;
    let (tid, _is_linux_thread, _clear_child_tid_addr, live_thread_retirement) =
        finish_thread_exit_cleanup(&process, cleanup, drop_user_res);

    let installed_task =
        take_current_task().expect("current task disappeared during group-exit cleanup");
    debug_assert!(Arc::ptr_eq(&task, &installed_task));
    // See exit_current_and_run_next(): the initial `current_task()` clone must
    // be the one moved into deferred drop, while the processor-owned reference
    // is released before this never-returning context switch.
    drop(installed_task);
    charge_task_runtime_for_scheduler(&task);
    task.clear_on_cpu();

    let (exec_peer, last_live_thread) =
        retire_exiting_task(&process, &task, tid, false, live_thread_retirement);
    if exec_peer && !last_live_thread {
        queue_exiting_task_drop(task);
        drop(process);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        unreachable!("schedule should not return for an exec peer");
    }
    if last_live_thread {
        let mut process_inner = process.borrow_mut();
        debug_assert!(!process_inner.exit_teardown);
        process_inner.exit_teardown = true;
    }

    log::debug!(
        "[exit_group] pid={} tid={} exit_code={}",
        process.getpid(),
        tid,
        exit_code
    );

    if !last_live_thread {
        // This member is fully detached from user resources. Keep its TCB alive
        // through the context switch; the final member will perform shared PCB
        // cleanup after every peer has reached this point.
        queue_exiting_task_drop(task);
        drop(process);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        unreachable!("schedule should not return for a group-exit member");
    }

    let dumped_core = process_dumped_core(&process, exit_code);
    let process_cpu_ns =
        crate::task::runtime::process_cpu_time_ns_at(&process, monotonic_time_ns());

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

    // Release cwd/root and descriptor ownership before the zombie can be
    // observed, just like Linux do_exit() calls exit_files()/exit_fs() before
    // exit_notify().  Shared CLONE_FS/CLONE_FILES objects remain alive through
    // their other process owners.
    let (old_files, old_fs) = {
        let mut process_inner = process.borrow_mut();
        crate::syscall::process::unregister_executing_inode(
            process_inner.exec_inode_dev,
            process_inner.exec_inode_num,
        );
        let old_files = core::mem::replace(
            &mut process_inner.files,
            Arc::new(FilesLock::new(FilesStruct::new())),
        );
        let old_fs = process_inner.fs.take();
        (old_files, old_fs)
    };
    close_files_struct_fd_refs_if_unshared(&old_files);
    drop(old_fs);
    crate::syscall::process::release_ptrace_tracer(&process);
    kill_pid_namespace_members_on_init_exit(&process);
    cgroup_exit_process(pid);
    crate::syscall::sysv_ipc::exit_cleanup(pid);
    crate::syscall::filesystem::acct_process_exit(&process, exit_code);

    reparent_orphaned_children(&process);

    let empty_mm = MmRef::new(MemorySet::new_bare());
    let (old_mm_token, old_net_ns_id, mut old_mm, zombie_tasks) = {
        let mut process_inner = process.borrow_mut();
        process_inner.clear_children();
        process_inner.exited_children.clear();
        let old_mm_token = process_inner.memory_set.token();
        let old_net_ns_id = process_inner.net_ns_id;
        let zombie_tasks = process_inner
            .tasks
            .iter()
            .filter_map(|task| task.as_ref().map(Arc::clone))
            .collect::<Vec<_>>();
        // Same as exit_current_and_run_next(): release the whole user address
        // space eagerly and keep only zombie bookkeeping in the PCB.
        let old_mm = core::mem::replace(&mut process_inner.memory_set, empty_mm.clone());
        (old_mm_token, old_net_ns_id, old_mm, zombie_tasks)
    };
    for zombie_task in zombie_tasks {
        drop(zombie_task.replace_memory_set(empty_mm.clone()));
    }
    let old_shm_cleanup = old_mm.take_sysv_shm_attaches_for_cleanup();
    crate::syscall::filesystem::release_all_record_locks_for_owner(pid);
    crate::syscall::filesystem::release_all_file_leases_for_owner(pid);
    if !release_process_mm_owner(old_mm_token) {
        crate::syscall::net::clear_packet_ring_mmaps_for_token(old_mm_token);
    }
    if let Some(old_shm) = old_shm_cleanup {
        crate::syscall::sysv_shm::exit_cleanup(&old_shm);
    }
    if let Some(released_net_ns_id) = process.release_net_namespace_owner() {
        debug_assert_eq!(released_net_ns_id, old_net_ns_id);
        crate::syscall::net::cleanup_net_namespace_if_unused(released_net_ns_id);
    }
    queue_files_struct_drop(old_files);
    queue_mm_drop(old_mm);

    let publication = publish_process_exit(&process, dumped_core, exit_code, process_cpu_ns);
    if let Some(parent) = publication.parent.as_ref()
        && publication.exit_signal > 0
    {
        crate::task::signal::queue_process_signal(
            parent.getpid(),
            publication.exit_signal as usize,
        );
    }
    wakeup_tasks(publication.parent_waiters);
    crate::fs::wake_tasks(publication.pidfd_waiters);

    // Same as `exit_current_and_run_next()`: keep zombie `tasks[]` until wait4().

    // Same as exit_current_and_run_next(): defer drop until we are on idle stack.
    queue_exiting_task_drop(task);
    drop(process);
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
    unreachable!("schedule should not return after group exit");
}
