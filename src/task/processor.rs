use crate::{
    arch,
    config::MAX_HARTS,
    fs::{File, cgroup_exit_process, cgroup_exit_thread},
    mm::{MemorySet, MmRef, try_write_user_value},
    println,
    syscall::futex::futex_wake_private_and_shared,
    task::{
        FilesStruct, INITPROC,
        id::{KernelStack, TaskUserRes},
        manager::{
            PID2PCB, account_rt_runtime, fair_current_deadline_expired,
            fair_wakeup_preempts_current_on_hart, fetch_task, has_ready_rt_any_at_or_above,
            has_ready_rt_at_or_above, has_ready_rt_higher_than, has_ready_tasks,
            prime_fair_sync_wakeup_lag, ready_queue_lengths, record_fair_sleep_lag,
            remove_inactive_task, remove_sched_timer_refs, requeue_task, rt_bandwidth_throttled,
            wakeup_task, wakeup_tasks,
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
/// 然后检查两个条件（任一为 true 即应停止清理）：
/// - `has_ready_rt_any_at_or_above(RT_PRIO_MIN)`：任意优先级的 RT 任务就绪。
///   RT 应立即响应，不等清理。
/// - `has_ready_tasks()`：任意 hart 的就绪队列有任务。fair 任务也应尽快调度，
///   不能因为清理而无限延迟。
fn idle_cleanup_should_stop_for_runnable_work() -> bool {
    drain_deferred_kernel_timer_work();
    has_ready_rt_any_at_or_above(RT_PRIO_MIN) || has_ready_tasks()
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

/// 将一个文件描述符表延迟到 idle 循环释放。
///
/// 若引用计数不为 1（还有其他持有者），直接 drop 当前引用即可——
/// 表本身不会在此刻释放，无需排队。只有唯一引用时才放入
/// `pending_files_struct_drop`，由 idle 渐进关闭所有 fd 并释放表，
/// 避免 exit 路径里同步 close 大量文件造成延迟。
fn queue_files_struct_drop(files: Arc<spin::Mutex<FilesStruct>>) {
    if Arc::strong_count(&files) != 1 {
        drop(files);
        return;
    }

    local_processor()
        .lock()
        .set_pending_files_struct_drop(files);
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
    let _ = futex_wake_private_and_shared(pid, token, ctid, 1);
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
        robust_list_head: task_inner.robust_list_head,
    }
}

fn finish_thread_exit_cleanup(
    process: &Arc<ProcessControlBlock>,
    cleanup: ThreadExitCleanup,
    drop_user_res: bool,
) -> (usize, bool, Option<usize>) {
    let pid = process.getpid();
    let token = {
        let inner = process.borrow_mut();
        inner.memory_set.token()
    };

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
    if let Some(res) = cleanup.res_to_drop {
        if drop_user_res {
            drop(res);
        } else {
            res.detach_for_process_exit();
        }
    }
    for waiter in &cleanup.join_waiters {
        prime_fair_sync_wakeup_lag(waiter);
    }
    wakeup_tasks(cleanup.join_waiters);

    (
        cleanup.tid,
        cleanup.is_linux_thread || cleanup.clear_child_tid_addr.is_some(),
        cleanup.clear_child_tid_addr,
    )
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

/// 把已退出的子进程加入父进程的 exited_children 队列，并取出全部
/// 等待 wait4 的阻塞线程用于唤醒。
///
/// 用 `exited_parent_queue_pid` 去重，防止同一子进程被重复入队
///（exit 与 group_exit 可能并发）。返回 drain 出的 wait_queue，
/// 调用方负责唤醒它们。
fn queue_exited_child_and_drain_waiters(
    parent: &Arc<ProcessControlBlock>,
    child: &Arc<ProcessControlBlock>,
) -> Vec<Arc<TaskControlBlock>> {
    let parent_pid = parent.getpid();
    let mut parent_inner = parent.borrow_mut();
    let should_queue = {
        let mut child_inner = child.borrow_mut();
        if child_inner.exited_parent_queue_pid == Some(parent_pid) {
            false
        } else {
            child_inner.exited_parent_queue_pid = Some(parent_pid);
            true
        }
    };
    if should_queue {
        parent_inner.exited_children.push_back(Arc::clone(child));
    }
    let waiters = parent_inner.wait_queue.drain(..).collect::<Vec<_>>();
    for waiter in &waiters {
        prime_fair_sync_wakeup_lag(waiter);
    }
    waiters
}

/// 进程组退出时清理同组所有其他线程，回收它们的用户态资源。
///
/// 遍历进程的 `tasks` 列表：当前线程只清调度定时器引用（自己由
/// 调用方处理）；其他线程调 `remove_inactive_task` 移出就绪队列、
/// 走 `finish_thread_exit_cleanup` 完成退出记账。最后收集所有线程
/// 的 `TaskUserRes` 返回，供调用方统一回收用户态资源（tid、
/// clear_child_tid 等）。
fn cleanup_process_threads_for_group_exit(
    process: &Arc<ProcessControlBlock>,
    current_task: &Arc<TaskControlBlock>,
    exit_code: i32,
) -> Vec<TaskUserRes> {
    let members = {
        let process_inner = process.borrow_mut();
        process_inner
            .tasks
            .iter()
            .filter_map(|task| task.as_ref().cloned())
            .collect::<Vec<_>>()
    };

    let mut recycle_res = Vec::<TaskUserRes>::new();
    for member in &members {
        if Arc::ptr_eq(member, current_task) {
            remove_sched_timer_refs(Arc::clone(member));
            continue;
        }
        remove_inactive_task(Arc::clone(member));
        let cleanup = take_thread_exit_cleanup(member, exit_code);
        let _ = finish_thread_exit_cleanup(process, cleanup, false);
    }
    for member in members {
        let mut member_inner = member.borrow_mut();
        if let Some(res) = member_inner.res.take() {
            recycle_res.push(res);
        }
    }
    recycle_res
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
    pending_files_struct_drop: VecDeque<Arc<spin::Mutex<FilesStruct>>>,
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
    pub fn take_pending_files_struct_drop(&mut self) -> Option<Arc<spin::Mutex<FilesStruct>>> {
        self.pending_files_struct_drop.pop_front()
    }

    /// 将一个文件描述符表排入待释放队列。仅当引用计数为 1（唯一持有）
    /// 时才需要排队，否则直接 drop 当前引用即可。
    pub fn set_pending_files_struct_drop(&mut self, files: Arc<spin::Mutex<FilesStruct>>) {
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

/// 读取任务所属进程的调度类与实时优先级，供唤醒抢占比较使用。
fn task_sched_class_and_priority(task: &Arc<TaskControlBlock>) -> Option<(SchedClass, i32)> {
    let inner = task.borrow_mut();
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
    let Some((current_class, current_priority)) = task_sched_class_and_priority(current) else {
        return false;
    };
    let Some((woken_class, woken_priority)) = task_sched_class_and_priority(woken) else {
        return false;
    };
    match (woken_class, current_class) {
        (SchedClass::Fifo | SchedClass::Rr, SchedClass::Fair) => true,
        (SchedClass::Fifo | SchedClass::Rr, SchedClass::Fifo | SchedClass::Rr) => {
            woken_priority > current_priority
        }
        (SchedClass::Fair, SchedClass::Fair) => {
            fair_wakeup_should_preempt_current(&current, woken, target_hart)
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

pub(crate) fn current_files() -> Arc<spin::Mutex<FilesStruct>> {
    let process = current_process();
    process.files()
}

pub(crate) fn current_files_and_nofile_limit() -> (Arc<spin::Mutex<FilesStruct>>, usize) {
    let process = current_process();
    let inner = process.borrow_mut();
    (
        Arc::clone(&inner.files),
        inner.rlimits.rlimit_nofile_cur as usize,
    )
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
        let child = process_inner.remove_child_at(pid_index);
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
/// 调度核心函数,直接完成任务的切换，传入参数为我们需要切换的任务的上下文
/// 完毕之后，该hart 进入idle_task,idle-Task会进入调度循环idle_task()
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
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
            task.clear_on_cpu();
            // 切走期间有人尝试唤醒它（wakeup_pending）→ 补唤醒。
            // 对应 Linux try_to_wake_up() 等 prev 离开 CPU 后再走正常唤醒路径，
            // 使 wakeup_preempt() 能正确设 NEED_RESCHED。
            if task
                .wakeup_pending
                .swap(false, core::sync::atomic::Ordering::AcqRel)
            {
                wakeup_task(task);
            }
        }

        // 处理上一个切走的任务：它要重新 Ready（时间片到/被抢占）。
        // 延迟到 idle 上下文才入队，保证任务不再使用自己的内核栈时才
        // 对其他 hart 可见，避免 SMP 下同一任务被两个 hart 同时调度。
        if let Some(task) = local_processor().lock().take_pending_ready() {
            task.clear_on_cpu();
            task.wakeup_pending
                .store(false, core::sync::atomic::Ordering::Release);
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
                let (files_to_drop, files_done) = {
                    let mut files_guard = files.lock();
                    let files_to_drop =
                        files_guard.take_file_close_batch(IDLE_FILES_STRUCT_CLOSE_BATCH);
                    (files_to_drop, files_guard.is_empty())
                };
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
            // 恢复目标任务的浮点寄存器状态。
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
            // 同步 trap context 中的 kernel_tp（hart id），适配跨核迁移。
            task_inner.get_trap_cx().kernel_tp = hart_id();
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
pub fn suspend_current_and_run_next() {
    // If the current process has a fatal pending signal, terminate it even if we are
    // inside a long-running/blocking syscall loop (where we may never return to the
    // trap handler's "check signal then return to user" path).
    //
    // Use `try_borrow_mut` to avoid deadlocking if the caller already holds the PCB lock.
    if let Some((errno, msg)) = crate::task::signal::check_if_current_signals_error() {
        crate::task::signal::log_signal_exit(msg);
        exit_group_and_run_next(errno);
    }
    let Some(task) = take_current_task() else {
        return;
    };
    charge_task_runtime_for_scheduler(&task);

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
        crate::task::signal::log_signal_exit(msg);
        exit_group_and_run_next(errno);
    }
    let Some(task) = take_current_task() else {
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
        record_fair_sleep_lag(&task);
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
pub fn exit_current_and_run_next(exit_code: i32) -> ! {
    // 标记线程状态,
    let task = take_current_task().unwrap();
    charge_task_runtime_for_scheduler(&task);
    // This task will never be scheduled again; ensure it is considered off CPU.
    task.clear_on_cpu();
    let Some(process) = task.process.upgrade() else {
        if DEBUG_SCHED {
            log::warn!("[exit] task lost process; dropping task and scheduling idle");
        }
        queue_exiting_task_drop(task);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        unreachable!("schedule should not return after task exit");
    };

    // Extract exit bookkeeping first, then perform Linux-thread cleanup without
    // holding the TCB lock so the same logic can be reused by exit_group().
    let cleanup = take_thread_exit_cleanup(&task, exit_code);
    let drop_user_res = cleanup.tid != 0;
    let (tid, is_linux_thread, clear_child_tid_addr) =
        finish_thread_exit_cleanup(&process, cleanup, drop_user_res);

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
            let thread_cpu_ns = crate::task::runtime::task_cpu_time_ns(&task);
            let mut process_inner = process.borrow_mut();
            let remove_slot = process_inner
                .tasks
                .get(tid)
                .and_then(|slot| slot.as_ref())
                .map(|t| Arc::ptr_eq(t, &task))
                .unwrap_or(false);
            if remove_slot {
                process_inner.cpu_time_ns = process_inner.cpu_time_ns.saturating_add(thread_cpu_ns);
                process_inner.tasks[tid] = None;
            }
        }
    }

    log::debug!(
        "[exit] pid={} tid={} exit_code={}",
        process.getpid(),
        tid,
        exit_code
    );

    let dumped_core = process_dumped_core(&process, exit_code);
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
        let (parent, exit_signal) = {
            let mut process_inner = process.borrow_mut();
            crate::syscall::process::unregister_executing_inode(
                process_inner.exec_inode_dev,
                process_inner.exec_inode_num,
            );
            process_inner.is_zombie = true;
            process_inner.dumped_core = dumped_core;
            process_inner.exit_code = exit_code;
            process_inner.cpu_time_ns = process_cpu_ns;
            (
                process_inner.parent.as_ref().and_then(|p| p.upgrade()),
                process_inner.exit_signal,
            )
        }; // drop child PCB lock before touching parent to avoid lock inversion
        crate::syscall::process::release_ptrace_tracer(&process);
        crate::fs::wake_pidfd_poll_waiters(pid);
        kill_pid_namespace_members_on_init_exit(&process);
        cgroup_exit_process(pid);
        crate::syscall::sysv_ipc::exit_cleanup(pid);
        crate::syscall::filesystem::acct_process_exit(&process, exit_code);

        // ...then wake parent waiters (waitpid) without holding the child PCB lock.
        if let Some(parent) = parent {
            // clone(2) allows exit_signal=0 to suppress parent notification entirely.
            // Only send the signal when the caller explicitly requested one.
            if exit_signal > 0 {
                crate::task::signal::queue_process_signal(parent.getpid(), exit_signal as usize);
            }
            let waiters = queue_exited_child_and_drain_waiters(&parent, &process);
            wakeup_tasks(waiters);
        }

        {
            let process_inner = process.borrow_mut();
            let mut initproc_inner = INITPROC.borrow_mut();
            let init_pid = INITPROC.getpid();
            for child in process_inner.children.iter() {
                let queue_for_init = {
                    let mut child_inner = child.borrow_mut();
                    child_inner.parent = Some(Arc::downgrade(&INITPROC));
                    if child_inner.is_zombie
                        && child_inner.exited_parent_queue_pid != Some(init_pid)
                    {
                        child_inner.exited_parent_queue_pid = Some(init_pid);
                        true
                    } else {
                        false
                    }
                };
                initproc_inner.add_child(child.clone());
                if queue_for_init {
                    initproc_inner.exited_children.push_back(child.clone());
                }
            }
        }

        // Deallocate user-thread resources only after each member has run the
        // same exit-side futex/join cleanup as the current thread.
        let mut recycle_res = cleanup_process_threads_for_group_exit(&process, &task, exit_code);
        recycle_res.clear();
        let (old_shm_cleanup, old_mm_token, old_net_ns_id, old_mm, old_files) = {
            let mut process_inner = process.borrow_mut();
            process_inner.clear_children();
            process_inner.exited_children.clear();
            let old_mm_token = process_inner.memory_set.token();
            let old_net_ns_id = process_inner.net_ns_id;
            let old_shm_cleanup = process_inner
                .memory_set
                .take_sysv_shm_attaches_for_cleanup();
            // Linux releases `mm_struct` at exit and keeps only zombie metadata.
            // Drop the full user address space here so unreaped zombies do not pin
            // page-table pages (and COW refs) during fork-heavy workloads.
            let old_mm = core::mem::replace(
                &mut process_inner.memory_set,
                MmRef::new(MemorySet::new_bare()),
            );
            crate::syscall::filesystem::release_all_record_locks_for_owner(pid);
            crate::syscall::filesystem::release_all_file_leases_for_owner(pid);
            // Detach the file table under the PCB lock, then drop/close it
            // outside the lock. Linux exit_files() follows the same shape:
            // publish an empty files_struct first, then perform expensive fd
            // close and pipe wakeups without holding process metadata locks.
            let old_files = core::mem::replace(
                &mut process_inner.files,
                Arc::new(spin::Mutex::new(FilesStruct::new())),
            );
            (
                old_shm_cleanup,
                old_mm_token,
                old_net_ns_id,
                old_mm,
                old_files,
            )
        };
        crate::syscall::net::clear_packet_ring_mmaps_for_token(old_mm_token);
        if let Some(old_shm) = old_shm_cleanup {
            crate::syscall::sysv_shm::exit_cleanup(&old_shm);
        }
        crate::syscall::net::cleanup_net_namespace_if_unused(old_net_ns_id);
        queue_files_struct_drop(old_files);
        queue_mm_drop(old_mm);
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
    let task = take_current_task().unwrap();
    charge_task_runtime_for_scheduler(&task);
    task.clear_on_cpu();
    let Some(process) = task.process.upgrade() else {
        if DEBUG_SCHED {
            log::warn!("[exit_group] task lost process; dropping task and scheduling idle");
        }
        queue_exiting_task_drop(task);
        let mut _unused = TaskContext::new();
        schedule(&mut _unused as *mut _);
        unreachable!("schedule should not return after group exit");
    };

    let (tid, _is_linux_thread, _clear_child_tid_addr) =
        finish_thread_exit_cleanup(&process, take_thread_exit_cleanup(&task, exit_code), false);

    log::debug!(
        "[exit_group] pid={} tid={} exit_code={}",
        process.getpid(),
        tid,
        exit_code
    );

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

    let (parent, exit_signal) = {
        let mut process_inner = process.borrow_mut();
        crate::syscall::process::unregister_executing_inode(
            process_inner.exec_inode_dev,
            process_inner.exec_inode_num,
        );
        process_inner.is_zombie = true;
        process_inner.dumped_core = dumped_core;
        process_inner.exit_code = exit_code;
        process_inner.cpu_time_ns = process_cpu_ns;
        (
            process_inner.parent.as_ref().and_then(|p| p.upgrade()),
            process_inner.exit_signal,
        )
    };
    crate::syscall::process::release_ptrace_tracer(&process);
    crate::fs::wake_pidfd_poll_waiters(pid);
    cgroup_exit_process(pid);
    crate::syscall::sysv_ipc::exit_cleanup(pid);
    crate::syscall::filesystem::acct_process_exit(&process, exit_code);

    if let Some(parent) = parent {
        // clone(2) allows exit_signal=0 to suppress parent notification entirely.
        // Only send the signal when the caller explicitly requested one.
        if exit_signal > 0 {
            crate::task::signal::queue_process_signal(parent.getpid(), exit_signal as usize);
        }
        let waiters = queue_exited_child_and_drain_waiters(&parent, &process);
        wakeup_tasks(waiters);
    }

    {
        let process_inner = process.borrow_mut();
        let mut initproc_inner = INITPROC.borrow_mut();
        let init_pid = INITPROC.getpid();
        for child in process_inner.children.iter() {
            let queue_for_init = {
                let mut child_inner = child.borrow_mut();
                child_inner.parent = Some(Arc::downgrade(&INITPROC));
                if child_inner.is_zombie && child_inner.exited_parent_queue_pid != Some(init_pid) {
                    child_inner.exited_parent_queue_pid = Some(init_pid);
                    true
                } else {
                    false
                }
            };
            initproc_inner.add_child(child.clone());
            if queue_for_init {
                initproc_inner.exited_children.push_back(child.clone());
            }
        }
    }

    let mut recycle_res = cleanup_process_threads_for_group_exit(&process, &task, exit_code);
    recycle_res.clear();
    let (old_shm_cleanup, old_mm_token, old_net_ns_id, old_mm, old_files) = {
        let mut process_inner = process.borrow_mut();
        process_inner.clear_children();
        process_inner.exited_children.clear();
        let old_mm_token = process_inner.memory_set.token();
        let old_net_ns_id = process_inner.net_ns_id;
        let old_shm_cleanup = process_inner
            .memory_set
            .take_sysv_shm_attaches_for_cleanup();
        // Same as exit_current_and_run_next(): release the whole user address
        // space eagerly and keep only zombie bookkeeping in the PCB.
        let old_mm = core::mem::replace(
            &mut process_inner.memory_set,
            MmRef::new(MemorySet::new_bare()),
        );
        crate::syscall::filesystem::release_all_record_locks_for_owner(pid);
        crate::syscall::filesystem::release_all_file_leases_for_owner(pid);
        // See exit_current_and_run_next(): detach under PCB lock, close/drop outside.
        let old_files = core::mem::replace(
            &mut process_inner.files,
            Arc::new(spin::Mutex::new(FilesStruct::new())),
        );
        (
            old_shm_cleanup,
            old_mm_token,
            old_net_ns_id,
            old_mm,
            old_files,
        )
    };
    crate::syscall::net::clear_packet_ring_mmaps_for_token(old_mm_token);
    if let Some(old_shm) = old_shm_cleanup {
        crate::syscall::sysv_shm::exit_cleanup(&old_shm);
    }
    crate::syscall::net::cleanup_net_namespace_if_unused(old_net_ns_id);
    queue_files_struct_drop(old_files);
    queue_mm_drop(old_mm);

    // Same as `exit_current_and_run_next()`: keep zombie `tasks[]` until wait4().

    // Same as exit_current_and_run_next(): defer drop until we are on idle stack.
    queue_exiting_task_drop(task);
    drop(process);
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
    unreachable!("schedule should not return after group exit");
}
