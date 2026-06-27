//! 子进程状态等待系统调用实现。
//!
//! 本模块实现以下系统调用：
//! - `wait4`：等待子进程退出或状态变更，支持 `__WCLONE`/`__WALL` 语义
//! - `waitid`：POSIX 扩展等待，支持 pidfd、`WNOWAIT` 非破坏性查询
//! - `ptrace`：进程追踪控制（`PTRACE_TRACEME`/`ATTACH`/`DETACH`/`CONT`/`KILL`）
//!
//! 以及以下辅助函数：
//! - `reap_zombie_child`：回收僵尸进程资源，含 Arc 残留引用诊断
//! - `wake_parent_waiters_for`：同时唤醒亲父进程和 tracer 的 wait 队列
//! - `enter_ptrace_stop`：将进程置入 ptrace-stop 状态并挂起所有线程
//!
//! # 设计说明
//!
//! **锁顺序**：持有 `process_inner` 锁期间不可再调用 `wait4_pending_action`
//! （后者需要重新读取当前进程信号动作），否则会反向获取同一 PCB 锁。
//! wait4 因此先持锁扫描已就绪的子状态；若准备阻塞，再释放锁检查待处理信号，
//! 然后重新持锁扫描并入队。第二次扫描与入队处于同一个父 PCB 临界区，
//! 避免子进程退出事件落在扫描和入队之间。
//!
//! **睡眠路径**：`enqueue_waiter_once` + `block_current_and_run_next` 组成等待对，
//! 前者保证同一 task 不重复入队，后者让出 CPU；唤醒由 `wake_parent_waiters_for`
//! 在子进程状态变更时触发。

use super::*;
use alloc::sync::Arc;

// 诊断计数器：分别统计 task Arc 残留和 child Arc 残留的累计触发次数，
// 用于控制诊断日志打印频率（见 reap_zombie_child）。
static REAP_LINGER_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);
static REAP_CHILD_ARC_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);

// ptrace request 编号，与 Linux uapi/linux/ptrace.h 保持一致。
const PTRACE_TRACEME: usize = 0;
const PTRACE_CONT: usize = 7;
const PTRACE_KILL: usize = 8;
const PTRACE_ATTACH: usize = 16;
const PTRACE_DETACH: usize = 17;

/// 向用户态 `waitid` 返回的子进程状态信息结构，对应 Linux `siginfo_t` 的 wait 子集。
///
/// 只使用了 wait 相关字段（`si_signo`=`SIGCHLD`、`si_code`、`si_pid`、`si_uid`、`si_status`）；
/// 其余字节清零，以满足 `waitid` 调用约定——内核保证整个结构体归零后再填写有效字段。
#[repr(C)]
#[derive(Clone, Copy)]
struct SigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad0: i32,
    si_pid: i32,
    si_uid: u32,
    /// 对 `CLD_EXITED` 为退出码，对 `CLD_KILLED`/`CLD_DUMPED` 为终止信号号。
    si_status: i32,
    _pad1: i32,
    si_utime: i64,
    si_stime: i64,
    _pad2: [u8; 80],
}

impl Default for SigInfo {
    fn default() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_pid: 0,
            si_uid: 0,
            si_status: 0,
            _pad1: 0,
            si_utime: 0,
            si_stime: 0,
            _pad2: [0u8; 80],
        }
    }
}

/// 从等待队列中删除指定 task 的条目。
///
/// 每次 wait 循环重新入睡前都需要先调用本函数清理上一轮留下的条目，
/// 防止同一 task 在队列中堆积多份（否则单次唤醒会消耗多个槽位而漏掉真正的等待者）。
pub(super) fn remove_wait_queue_entry(
    queue: &mut alloc::collections::VecDeque<Arc<TaskControlBlock>>,
    task: &Arc<TaskControlBlock>,
) {
    queue.retain(|t| !Arc::ptr_eq(t, task));
}

/// 幂等地将 task 加入等待队列，若已存在则不重复插入。
///
/// 返回 `true` 表示本次确实插入了新条目，可用于触发队列长度诊断日志。
/// 防重复是为了避免单次信号唤醒后 task 被调度多次的错误。
pub(super) fn enqueue_waiter_once(
    queue: &mut alloc::collections::VecDeque<Arc<TaskControlBlock>>,
    task: &Arc<TaskControlBlock>,
) -> bool {
    if queue.iter().any(|t| Arc::ptr_eq(t, task)) {
        return false;
    }
    queue.push_back(task.clone());
    true
}

fn wait4_signal_matches(exit_signal: i32, options: usize, wall: usize, wclone: usize) -> bool {
    let is_clone_child = exit_signal != SIGCHLD_NUM as i32;
    (options & wall) != 0 || ((options & wclone) != 0) == is_clone_child
}

fn note_ptrace_attach_to(tracer_pid: usize) {
    if let Some(tracer) = pid2process(tracer_pid) {
        let mut inner = tracer.borrow_mut();
        inner.ptrace_tracee_count = inner.ptrace_tracee_count.saturating_add(1);
    }
}

fn note_ptrace_detach_from(tracer_pid: usize) {
    if let Some(tracer) = pid2process(tracer_pid) {
        let mut inner = tracer.borrow_mut();
        inner.ptrace_tracee_count = inner.ptrace_tracee_count.saturating_sub(1);
    }
}

pub(crate) fn release_ptrace_tracer(process: &Arc<ProcessControlBlock>) {
    let tracer_pid = {
        let mut inner = process.borrow_mut();
        inner.ptrace_tracer_pid.take()
    };
    if let Some(tracer_pid) = tracer_pid {
        note_ptrace_detach_from(tracer_pid);
    }
}

fn remove_exited_child_ref(
    queue: &mut alloc::collections::VecDeque<Arc<ProcessControlBlock>>,
    child: &Arc<ProcessControlBlock>,
) {
    queue.retain(|queued| !Arc::ptr_eq(queued, child));
}

/// 回收僵尸子进程占用的内核资源，并返回其累计 CPU 时间（纳秒）。
///
/// exit 路径已将主线程资源解绑，但 task Arc 可能仍被调度器运行队列、
/// futex 等待列表、管道等处持有。本函数对每个 task 执行两次 `remove_inactive_task`
/// 以尽量清除残余引用；若 `DEBUG_SIGNAL` 开启且 Arc 引用计数仍 >1，
/// 则触发诊断日志（见下方说明）。
///
/// `DEBUG_SIGNAL` 诊断日志策略（`REAP_LINGER_DIAG_COUNT`）：
/// - 前 16 次每次打印，之后仅在计数为 2 的幂时打印，避免日志在大量 fork/exit 场景下爆炸。
/// - `debug_task_ref_breakdown` 分解各子系统的引用计数，帮助定位哪个子系统未正常释放引用。
/// - `unknown_refs` = 总引用数 − 1（本函数自持） − 已知子系统之和，非零说明存在未被追踪的持有者。
fn reap_zombie_child(child: &Arc<ProcessControlBlock>) -> u64 {
    // Main-thread resources are already detached in exit path; this aggressively
    // drops lingering task Arcs so kernel stacks are reclaimed on reap.
    let (own_cpu_ns, child_cpu_ns) = {
        let inner = child.borrow_mut();
        (inner.cpu_time_ns, inner.child_cpu_time_ns)
    };
    // Linux accumulates the child's thread-group CPU time plus the child's
    // already waited descendants into the parent at reap time.
    let cpu_ns = own_cpu_ns.saturating_add(child_cpu_ns);
    let tasks = {
        let mut inner = child.borrow_mut();
        core::mem::take(&mut inner.tasks)
    };
    let child_pid = child.getpid();
    for task in tasks.into_iter().flatten() {
        let exit_cleaned = task.borrow_mut().res.is_none();
        if exit_cleaned {
            remove_sched_timer_refs(task.clone());
        } else {
            remove_inactive_task(task.clone());
        }
        let strong = Arc::strong_count(&task);
        if strong > 1 && DEBUG_SIGNAL {
            // Retry once so duplicate stale queue entries are aggressively dropped.
            remove_inactive_task(task.clone());
            let count = REAP_LINGER_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            // 前 16 次全打印，之后仅在 2 的幂次时打印，节流日志量。
            if count <= 16 || (count & (count - 1)) == 0 {
                let tid = task
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                let (
                    runqueue_refs,
                    processor_refs,
                    timer_refs,
                    futex_refs,
                    record_lock_refs,
                    task_slot_refs,
                    wait_queue_refs,
                    join_waiter_refs,
                    sync_waiter_refs,
                    pipe_waiter_refs,
                ) = debug_task_ref_breakdown(&task);
                let known_refs = runqueue_refs
                    .saturating_add(processor_refs)
                    .saturating_add(timer_refs)
                    .saturating_add(futex_refs)
                    .saturating_add(record_lock_refs)
                    .saturating_add(task_slot_refs)
                    .saturating_add(wait_queue_refs)
                    .saturating_add(join_waiter_refs)
                    .saturating_add(sync_waiter_refs)
                    .saturating_add(pipe_waiter_refs);
                // 扣除本函数自持的 1 个引用后，剩余无法归因的引用即为 unknown。
                let unknown_refs = strong.saturating_sub(1 + known_refs);
                crate::println!(
                    "[reap-debug] child_pid={} tid={} lingering_refs={} seq={} rq={} proc={} timer={} futex={} rec_lock={} task_slot={} waitq={} join={} sync={} pipe={} unknown={}",
                    child_pid,
                    tid,
                    strong,
                    count,
                    runqueue_refs,
                    processor_refs,
                    timer_refs,
                    futex_refs,
                    record_lock_refs,
                    task_slot_refs,
                    wait_queue_refs,
                    join_waiter_refs,
                    sync_waiter_refs,
                    pipe_waiter_refs,
                    unknown_refs
                );
            }
        }
        drop(task);
    }
    cpu_ns
}

/// 检查当前 task 是否有未屏蔽的待处理信号，并决定 wait 系列调用应如何响应。
///
/// Linux 对 wait 系列可中断行为的语义：
/// - `SIG_IGN`：被显式忽略的信号，wait 可以清除该 pending 位并继续睡眠，
///   因为用户态不会看到此信号，无需中断 wait。
/// - `SIG_DFL`：默认动作为"忽略或与当前 stopped 状态无关"的信号同上；
///   若默认动作会实际中断进程（如 `SIGTERM`），则 wait 需返回 `EINTR`。
/// - 用户安装的处理函数设置了 `SA_RESTART`：内核在信号处理返回后重新执行 wait，
///   返回 `ERESTARTSYS` 通知调度层重启该系统调用。
/// - 用户安装的处理函数未设置 `SA_RESTART`：返回 `EINTR`，让用户态感知中断。
///
/// 返回 `None` 表示没有需要响应的信号，wait 可继续阻塞。
fn wait4_pending_action(task: &Arc<TaskControlBlock>) -> Option<isize> {
    const EINTR: isize = -4;
    let (pending, mask) = {
        let inner = task.borrow_mut();
        (inner.pending_signals, inner.signal_mask)
    };
    let mut bits = pending_unmasked_bits(pending, mask);
    if bits == 0 {
        return None;
    }
    let mut clear_bits = 0u64;
    let mut saw_restart = false;
    let mut saw_interrupt = false;
    let mut first_sig = None;
    let process = current_process();
    let inner = process.borrow_mut();
    while bits != 0 {
        let signum = bits.trailing_zeros() as usize + 1;
        let bit = 1u64 << (signum - 1);
        bits &= bits - 1;
        if first_sig.is_none() {
            first_sig = Some(signum);
        }
        let action = inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default();
        if action.handler == SIG_IGN {
            // 被忽略的信号：清除 pending 位，wait 继续睡眠，不返回错误。
            clear_bits |= bit;
            continue;
        }
        if action.handler == SIG_DFL {
            // 默认动作不中断 wait（如 SIGCHLD 默认忽略）时，同样清除并继续。
            // 若默认动作确实需要打断（如 SIGTERM），则设置 interrupt 标志后立即退出遍历。
            if !sig_default_interrupts_wait(signum, inner.stopped) {
                clear_bits |= bit;
                continue;
            }
            saw_interrupt = true;
            break;
        }
        // 用户安装的处理函数：SA_RESTART 决定是重启系统调用还是返回 EINTR。
        if (action.flags & SA_RESTART) != 0 {
            saw_restart = true;
        } else {
            saw_interrupt = true;
            break;
        }
    }
    drop(inner);
    if clear_bits != 0 {
        let mut inner = task.borrow_mut();
        inner.pending_signals &= !clear_bits;
        task.refresh_signal_pending(inner.pending_signals);
    }
    if saw_interrupt || saw_restart {
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
            "[wait4] pid={} tid={} pending={:#x} mask={:#x} sig={:?} action={}",
            pid,
            tid,
            pending,
            mask,
            first_sig,
            if saw_interrupt { "eintr" } else { "restart" }
        );
    }
    if saw_interrupt {
        Some(EINTR)
    } else if saw_restart {
        Some(ERESTARTSYS)
    } else {
        None
    }
}

/// 向目标进程的 wait 队列投递 `SIGCHLD` 并唤醒所有等待者。
///
/// 仅供 `wake_parent_waiters_for` 调用，封装了"发信号 + 排队唤醒"两步操作。
fn wake_waiters_on(process: &Arc<ProcessControlBlock>) {
    queue_process_signal(process.getpid(), SIGCHLD_NUM);
    let waiters = {
        let mut inner = process.borrow_mut();
        // 一次性 drain 清空队列：避免唤醒风暴，每次状态变更只唤醒一轮等待者。
        inner.wait_queue.drain(..).collect::<Vec<_>>()
    };
    for waiter in waiters {
        wakeup_task(waiter);
    }
}

/// 唤醒子进程状态变更应通知的所有相关方：亲父进程和 tracer（若不同）。
///
/// ptrace 语义下，tracer 也是子进程状态事件的接收者，它的 wait 调用同样需要被唤醒。
/// 如果 tracer 和亲父进程是同一进程（常见于 `PTRACE_TRACEME` 后父进程调试子进程的场景），
/// 则只唤醒一次，避免重复发送 `SIGCHLD`。
pub(super) fn wake_parent_waiters_for(process: &Arc<ProcessControlBlock>) {
    let (parent, tracer_pid) = {
        let inner = process.borrow_mut();
        (
            inner.parent.as_ref().and_then(|w| w.upgrade()),
            inner.ptrace_tracer_pid,
        )
    };

    let mut parent_pid = None;
    if let Some(parent) = parent {
        parent_pid = Some(parent.getpid());
        wake_waiters_on(&parent);
    }
    // 仅当 tracer 与亲父进程不同时才额外唤醒，防止对同一进程重复投递 SIGCHLD。
    if let Some(tracer_pid) = tracer_pid {
        if parent_pid != Some(tracer_pid) {
            if let Some(tracer) = pid2process(tracer_pid) {
                wake_waiters_on(&tracer);
            }
        }
    }
}

/// 将进程置入 ptrace-stop 状态，挂起其所有线程，并通知 tracer。
///
/// 仅当进程已有 tracer 时才执行；否则直接返回，避免无意义地挂起进程。
/// 所有线程均被设为 `Blocked + stopped_by_signal = true`，
/// 以便 `PTRACE_CONT`/`PTRACE_DETACH` 通过 `stopped_by_signal` 标志精确地反向唤醒它们。
/// 最后调用 `block_current_and_run_next` 挂起当前线程，等待 tracer 的下一次 continue。
pub(super) fn enter_ptrace_stop(process: &Arc<ProcessControlBlock>, signum: i32) {
    let tasks = {
        let mut inner = process.borrow_mut();
        if inner.ptrace_tracer_pid.is_none() {
            return;
        }
        inner.stopped = true;
        inner.stop_signal = signum;
        inner.stop_pending = true;
        inner.continued = false;
        inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<Vec<_>>()
    };
    for task in tasks {
        let mut task_inner = task.borrow_mut();
        if task_inner.task_status != TaskStatus::Blocked {
            task_inner.task_status = TaskStatus::Blocked;
            task_inner.stopped_by_signal = true;
        }
    }
    // 通知 tracer（和亲父进程）后再挂起自身；顺序不能颠倒，否则唤醒会丢失。
    wake_parent_waiters_for(process);
    block_current_and_run_next();
}

/// 实现 `wait4` 系统调用：等待匹配的子进程退出或状态变更。
///
/// 本实现的整体结构是一个重试循环（loop）：每次迭代先扫描子进程列表，
/// 若找到可消费的事件则立即返回；否则将自身加入 wait 队列后让出 CPU，
/// 等被 `wake_parent_waiters_for` 唤醒后再次扫描。
///
/// 扫描顺序和优先级：zombie > stop_event > cont_event，与 Linux 保持一致。
/// ptrace 被追踪进程的 stop/cont 事件在子进程列表扫描之后补充扫描。
pub fn syscall_wait4(pid: isize, wstatus_ptr: usize, options: usize, _rusage: usize) -> isize {
    const WNOHANG: usize = 0x00000001;
    const WUNTRACED: usize = 0x00000002;
    const WCONTINUED: usize = 0x00000008;
    // Linux-internal flags required by clone3 callers that set a non-SIGCHLD exit_signal:
    // __WCLONE  — wait for children that do NOT deliver SIGCHLD on exit (clone children)
    // __WALL    — wait for any child regardless of exit signal
    // __WNOTHREAD — Linux 用它限制只等待调用线程自己的子进程；本实现当前
    // children 仍按进程保存，没有记录 creator thread，因此先拒绝而非假装支持。
    // Unless __WALL is set, wait4 separates normal SIGCHLD children from clone
    // children whose exit_signal is 0 or a non-SIGCHLD signal.
    const __WCLONE: usize = 0x80000000;
    const __WALL: usize = 0x40000000;
    const __WNOTHREAD: usize = 0x20000000;
    const ECHILD: isize = -10;
    if (options & __WNOTHREAD) != 0 {
        return err(SyscallError::EINVAL);
    }
    let allowed = WNOHANG | WUNTRACED | WCONTINUED | __WCLONE | __WALL;
    if (options & !allowed) != 0 {
        return err(SyscallError::EINVAL);
    }
    if pid == isize::MIN || pid == (i32::MIN as isize) {
        return err(SyscallError::ESRCH);
    }
    let token = get_current_token();
    let mut temp_exit_code: i32 = 0;
    let mut temp_signal: Option<i32> = None;
    let mut temp_coredump = false;
    let mut checked_pending_signal = false;
    loop {
        let cur_process = current_process();
        let task = current_task().unwrap();
        let mut process_inner = cur_process.borrow_mut();
        // 每轮开始时先清理自身的 wait 队列条目，防止重复入队导致引用计数膨胀。
        remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
        let parent_pgid = process_inner.pgid;
        let parent_pid = cur_process.getpid();
        let has_ptrace_tracees = process_inner.ptrace_tracee_count != 0;
        let mut stop_event: Option<(Arc<ProcessControlBlock>, i32)> = None;
        let mut cont_event: Option<Arc<ProcessControlBlock>> = None;
        let mut queued_zombie_child: Option<Arc<ProcessControlBlock>> = None;
        if pid == -1 && (options & (WUNTRACED | WCONTINUED)) == 0 {
            let mut index = 0;
            while index < process_inner.exited_children.len() {
                let child = Arc::clone(&process_inner.exited_children[index]);
                let mut child_inner = child.borrow_mut();
                let still_child = child_inner
                    .parent
                    .as_ref()
                    .and_then(|parent| parent.upgrade())
                    .map_or(false, |parent| Arc::ptr_eq(&parent, &cur_process));
                if !still_child || !child_inner.is_zombie {
                    if child_inner.exited_parent_queue_pid == Some(parent_pid) {
                        child_inner.exited_parent_queue_pid = None;
                    }
                    drop(child_inner);
                    process_inner.exited_children.remove(index);
                    continue;
                }
                if !wait4_signal_matches(child_inner.exit_signal, options, __WALL, __WCLONE) {
                    drop(child_inner);
                    index += 1;
                    continue;
                }
                temp_exit_code = child_inner.exit_code;
                temp_signal = if temp_exit_code < 0 {
                    Some(-temp_exit_code)
                } else {
                    None
                };
                temp_coredump = child_inner.dumped_core;
                drop(child_inner);
                let child = process_inner
                    .exited_children
                    .remove(index)
                    .expect("queued child index disappeared");
                let _ = process_inner.remove_child(&child);
                queued_zombie_child = Some(child);
                break;
            }
        }
        // --- 阶段一：扫描亲子进程列表，按 zombie > stop > cont 优先级查找事件 ---
        let (has_matching_child, zombie_child) = if let Some(child) = queued_zombie_child {
            (true, Some(child))
        } else if process_inner.children.is_empty() {
            (false, None)
        } else {
            let mut found: Option<usize> = None;
            let mut has_match = false;
            for (index, child) in process_inner.children.iter().enumerate() {
                let child_inner = child.borrow_mut();
                let pid_matches = match pid {
                    -1 => true, // any child
                    0 => child_inner.pgid == parent_pgid,
                    p if p > 0 => child.pid.0 == p as usize,
                    p => child_inner.pgid == (-p) as usize,
                };
                let is_clone_child = child_inner.exit_signal != SIGCHLD_NUM as i32;
                // Linux wait4 默认只匹配退出时向父进程发送 SIGCHLD 的子进程；
                // clone 子进程需要 __WCLONE，__WALL 则跳过这层 exit_signal 过滤。
                let signal_matches =
                    (options & __WALL) != 0 || ((options & __WCLONE) != 0) == is_clone_child;
                let matches = pid_matches && signal_matches;
                if matches {
                    has_match = true;
                }
                if matches && child_inner.is_zombie {
                    temp_exit_code = child_inner.exit_code;
                    temp_signal = if temp_exit_code < 0 {
                        Some(-temp_exit_code)
                    } else {
                        None
                    };
                    temp_coredump = child_inner.dumped_core;
                    found = Some(index);
                    break;
                }
                // stop 事件：WUNTRACED 允许普通父进程看到 stopped 子进程；
                // ptrace tracer 则无条件可见自己所追踪子进程的 stop_pending。
                let ptrace_stop_visible = child_inner.ptrace_tracer_pid == Some(parent_pid);
                if matches
                    && child_inner.stopped
                    && child_inner.stop_pending
                    && ((options & WUNTRACED) != 0 || ptrace_stop_visible)
                {
                    let sig = if child_inner.stop_signal != 0 {
                        child_inner.stop_signal
                    } else {
                        crate::task::signal::SIGSTOP_NUM as i32
                    };
                    stop_event = Some((child.clone(), sig));
                    break;
                }
                if matches && (options & WCONTINUED) != 0 && child_inner.continued {
                    cont_event = Some(child.clone());
                    break;
                }
            }
            if let Some(index) = found {
                let child = process_inner.remove_child_at(index);
                remove_exited_child_ref(&mut process_inner.exited_children, &child);
                (true, Some(child))
            } else {
                (has_match, None)
            }
        };

        // --- 阶段二：若阶段一未找到 stop/zombie 事件，补充扫描 ptrace 被追踪进程 ---
        // 被追踪进程不一定是当前进程的亲子，因此需要扫描全局 PID 表。
        let mut has_matching_ptrace = false;
        if has_ptrace_tracees && stop_event.is_none() && zombie_child.is_none() {
            let traced_processes = {
                let map = PID2PCB.lock();
                map.values().cloned().collect::<Vec<_>>()
            };
            for traced in traced_processes {
                if Arc::ptr_eq(&traced, &cur_process) {
                    continue;
                }
                let traced_pid = traced.getpid();
                let traced_inner = traced.borrow_mut();
                if traced_inner.ptrace_tracer_pid != Some(parent_pid) {
                    continue;
                }
                let matches = match pid {
                    -1 => true,
                    p if p > 0 => traced_pid == p as usize,
                    // 按进程组过滤对 ptrace 被追踪进程没有明确 Linux 语义，暂不支持。
                    _ => false,
                };
                if !matches {
                    continue;
                }
                has_matching_ptrace = true;
                if traced_inner.stopped && traced_inner.stop_pending {
                    let sig = if traced_inner.stop_signal != 0 {
                        traced_inner.stop_signal
                    } else {
                        SIGSTOP_NUM as i32
                    };
                    stop_event = Some((traced.clone(), sig));
                    break;
                }
                if (options & WCONTINUED) != 0 && traced_inner.continued {
                    cont_event = Some(traced.clone());
                    break;
                }
            }
        }

        // --- 阶段三：消费并返回 stop 事件 ---
        // 清除 stop_pending 以防同一 stop 被重复消费（Linux 语义：每次 ptrace-stop 只报告一次）。
        if let Some((target, sig)) = stop_event {
            let pid = target.getpid();
            let mut target_inner = target.borrow_mut();
            target_inner.stop_pending = false;
            target_inner.stop_signal = sig;
            drop(target_inner);
            drop(process_inner);
            if wstatus_ptr != 0 {
                // Linux wait status encoding for stopped: ((sig & 0xff) << 8) | 0x7f
                let status = ((sig & 0xff) << 8) | 0x7f;
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }
        // --- 阶段三（续）：消费并返回 cont 事件 ---
        if let Some(target) = cont_event {
            let pid = target.getpid();
            let mut target_inner = target.borrow_mut();
            target_inner.continued = false;
            drop(target_inner);
            drop(process_inner);
            if wstatus_ptr != 0 {
                // Linux wait status encoding for continued: 0xffff
                let status = 0xffff;
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }

        // --- 阶段四：消费并回收 zombie 子进程 ---
        if let Some(child) = zombie_child {
            let pid = child.getpid();
            drop(process_inner);
            // Keep exited processes visible (e.g., for `kill $!`) until they are reaped.
            let child_cpu_ns = reap_zombie_child(&child);
            // Reaping is complete now; remove it from the global PID table.
            crate::task::manager::remove_from_pid2process(pid);
            if crate::debug_config::DEBUG_TASK_LIFECYCLE {
                let child_refs = Arc::strong_count(&child);
                // 若 PID 表删除后 child Arc 仍有多个持有者，说明存在子系统未释放引用。
                if child_refs > 1 {
                    let seq = REAP_CHILD_ARC_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                    if seq <= 16 || (seq & (seq - 1)) == 0 {
                        crate::println!(
                            "[reap-child-debug] child_pid={} refs_after_reap={} seq={}",
                            pid,
                            child_refs,
                            seq
                        );
                    }
                }
            }
            {
                let mut parent_inner = cur_process.borrow_mut();
                // 将子进程的 CPU 时间累计到父进程，以正确响应 getrusage(RUSAGE_CHILDREN)。
                parent_inner.child_cpu_time_ns =
                    parent_inner.child_cpu_time_ns.saturating_add(child_cpu_ns);
            }
            drop(child);
            if wstatus_ptr != 0 {
                // Linux wait status encoding:
                // - normal exit: (code & 0xff) << 8
                // - signaled: signal number in low 7 bits
                let status = if let Some(sig) = temp_signal {
                    let mut status = sig & 0x7f;
                    if temp_coredump {
                        status |= 0x80;
                    }
                    status
                } else {
                    (((temp_exit_code as u32) & 0xff) << 8) as i32
                };
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }

        // --- 阶段五：无任何匹配子进程，或所有匹配子进程均处于无事件状态 ---
        if !has_matching_child && !has_matching_ptrace {
            // 没有任何符合 pid 参数的子进程存在，按 Linux 约定返回 ECHILD。
            if DEBUG_PTHREAD {
                let child_pids = process_inner
                    .children
                    .iter()
                    .map(|c| c.getpid())
                    .collect::<Vec<_>>();
                let traced_pids = {
                    let map = PID2PCB.lock();
                    map.values()
                        .filter_map(|p| {
                            if Arc::ptr_eq(p, &cur_process) {
                                return None;
                            }
                            let inner = p.borrow_mut();
                            if inner.ptrace_tracer_pid == Some(parent_pid) {
                                Some(p.getpid())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                };
                log::debug!(
                    "[wait4] pid={} wait_pid={} no matching child children={:?} traced={:?}",
                    cur_process.getpid(),
                    pid,
                    child_pids,
                    traced_pids
                );
            }
            drop(process_inner);
            return ECHILD;
        }

        // Non-blocking wait: return immediately if no child has exited yet.
        if (options & WNOHANG) != 0 {
            drop(process_inner);
            return 0;
        }

        if !checked_pending_signal {
            drop(process_inner);
            // 不能在持有 process_inner 时检查信号动作；但检查信号期间子进程
            // 可能刚好退出，所以检查后必须重新进入循环复扫，而不是直接入队。
            if let Some(action) = wait4_pending_action(&task) {
                let mut process_inner = cur_process.borrow_mut();
                remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
                drop(process_inner);
                return action;
            }
            checked_pending_signal = true;
            continue;
        }

        // --- 阶段六：将自身入队并让出 CPU，等待子进程状态变更唤醒 ---
        // 这里沿用复扫时持有的 process_inner 锁，不在 scan 和 enqueue 之间释放。
        // 否则 exit_signal=0 的 clone child 可能在空队列上完成唤醒，父线程随后
        // 才入队并永久睡眠。
        let inserted = enqueue_waiter_once(&mut process_inner.wait_queue, &task);
        if inserted {
            let qlen = process_inner.wait_queue.len();
            // 队列长度达到 64 的 2 的幂时打印诊断，定位可能的父进程多线程 wait 竞争问题。
            if qlen >= 64 && (qlen & (qlen - 1)) == 0 {
                crate::println!(
                    "[wait4-debug] pid={} wait_queue_len={} children={} wait_pid={} options=0x{:x}",
                    cur_process.getpid(),
                    qlen,
                    process_inner.children.len(),
                    pid,
                    options
                );
            }
        }
        drop(process_inner);
        checked_pending_signal = false;
        block_current_and_run_next();
    }
}

/// 实现 `waitid` 系统调用：以结构化 `siginfo_t` 方式等待子进程状态变更。
///
/// 与 `wait4` 的主要区别：
/// - 结果通过 `SigInfo` 结构体写回，包含 `si_code`（区分正常退出/信号终止/stop/cont）
/// - `WNOWAIT` 允许"窥看"事件而不消费（子进程不被从 children 列表移除、stop_pending 不清除），
///   从而支持多次查询同一事件
/// - 支持 `P_PIDFD`：通过文件描述符而非 PID 定位子进程，`O_NONBLOCK` 的 pidfd 对应 `EAGAIN`
pub fn syscall_waitid(idtype: usize, id: usize, infop: usize, options: usize) -> isize {
    const P_ALL: usize = 0;
    const P_PID: usize = 1;
    const P_PGID: usize = 2;
    // P_PIDFD 通过文件描述符引用目标进程，解耦了进程生命周期与 PID 复用问题。
    const P_PIDFD: usize = 3;
    const WNOHANG: usize = 0x00000001;
    const WSTOPPED: usize = 0x00000002;
    const WEXITED: usize = 0x00000004;
    const WCONTINUED: usize = 0x00000008;
    // WNOWAIT：报告事件但不回收，后续 wait 仍可重新匹配同一子进程。
    const WNOWAIT: usize = 0x01000000;
    const SIGCHLD: i32 = 17;
    // CLD_* 常量对应 si_code 字段，区分子进程退出原因，供用户态区分处理。
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    const CLD_STOPPED: i32 = 5;
    const CLD_CONTINUED: i32 = 6;
    const ECHILD: isize = -10;
    const EBADF: isize = -9;
    // pidfd 以 O_NONBLOCK 打开时，若无可消费事件则返回 EAGAIN 而非阻塞。
    const EAGAIN: isize = -11;
    const O_NONBLOCK: u32 = 0x800;

    let allowed = WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT;
    if (options & !allowed) != 0 {
        return err(SyscallError::EINVAL);
    }
    // 至少需要指定一个感兴趣的事件类型，否则 wait 永远不会返回有效数据。
    if (options & (WEXITED | WSTOPPED | WCONTINUED)) == 0 {
        return err(SyscallError::EINVAL);
    }
    if infop == 0 {
        return err(SyscallError::EFAULT);
    }
    if matches!(idtype, P_PID) && id == 0 {
        return err(SyscallError::EINVAL);
    }
    // P_PIDFD 用 Arc identity 而非 PID 数值匹配子进程：
    // 防止原 target 退出 + PID 被复用后误命中无关进程。target_process 升级
    // 失败说明原 target 已彻底释放（已被 reap 并 drop），按 Linux 语义返回 ECHILD。
    let mut pidfd_target: Option<Arc<ProcessControlBlock>> = None;
    let mut pidfd_nonblock = false;
    if idtype == P_PIDFD {
        // descriptor_flags 来自 open() 时的 fd flags，与 file status flags 不同。
        let (file, descriptor_flags) = {
            let files = current_files();
            let files = files.lock();
            let Some((file, descriptor_flags)) = files.get_file_and_flags(id) else {
                return EBADF;
            };
            (file, descriptor_flags)
        };
        let Some(pidfd) = file.as_any().downcast_ref::<PidFdFile>() else {
            return EBADF;
        };
        let Some(target) = pidfd.target_process() else {
            return ECHILD;
        };
        pidfd_target = Some(target);
        pidfd_nonblock = (descriptor_flags & O_NONBLOCK) != 0;
    }

    let token = get_current_token();
    loop {
        let cur_process = current_process();
        let task = current_task().unwrap();
        // waitid 在循环开头就检查信号，与 wait4 不同；这样可以尽早响应 SIGCHLD
        // 被忽略（父进程设置 SIG_IGN）时的异常路径，与 Linux glibc 行为对齐。
        if let Some(action) = wait4_pending_action(&task) {
            let mut process_inner = cur_process.borrow_mut();
            remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
            drop(process_inner);
            return action;
        }

        let mut process_inner = cur_process.borrow_mut();
        remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
        let parent_pgid = process_inner.pgid;
        let mut has_match = false;
        // 使用 Option 而非直接返回，是为了在同一持锁区间内完成匹配和（可选的）消费，
        // 避免先释放锁再重新加锁带来的 TOCTOU 问题。
        let mut found_zombie: Option<(usize, i32, Option<i32>, bool, u32)> = None;
        let mut found_stop: Option<(usize, i32, u32)> = None;
        let mut found_cont: Option<(usize, u32)> = None;

        for (index, child) in process_inner.children.iter().enumerate() {
            let child_inner = child.borrow_mut();
            let matches = match idtype {
                P_ALL => true,
                P_PID => child.pid.0 == id,
                P_PGID => {
                    // id == 0 表示等待与调用者同进程组的子进程，与 wait4(0) 语义一致。
                    let target = if id == 0 { parent_pgid } else { id };
                    child_inner.pgid == target
                }
                P_PIDFD => pidfd_target
                    .as_ref()
                    .is_some_and(|target| Arc::ptr_eq(child, target)),
                _ => return err(SyscallError::EINVAL),
            };
            if !matches {
                continue;
            }
            has_match = true;
            if (options & WEXITED) != 0 && child_inner.is_zombie {
                let exit_code = child_inner.exit_code;
                let signal = if exit_code < 0 {
                    Some(-exit_code)
                } else {
                    None
                };
                let coredump = child_inner.dumped_core;
                found_zombie = Some((index, exit_code, signal, coredump, child_inner.uid));
                break;
            }
            if (options & WSTOPPED) != 0 && child_inner.stopped && child_inner.stop_pending {
                let sig = if child_inner.stop_signal != 0 {
                    child_inner.stop_signal
                } else {
                    crate::task::signal::SIGSTOP_NUM as i32
                };
                found_stop = Some((child.pid.0, sig, child_inner.uid));
                break;
            }
            if (options & WCONTINUED) != 0 && child_inner.continued {
                found_cont = Some((child.pid.0, child_inner.uid));
                break;
            }
        }

        if let Some((index, exit_code, signal, coredump, uid)) = found_zombie {
            let child_pid = process_inner.children[index].pid.0;
            // WNOWAIT：不从 children 列表移除，保留僵尸以供后续 wait 重复查询。
            let child = if (options & WNOWAIT) == 0 {
                let child = process_inner.remove_child_at(index);
                remove_exited_child_ref(&mut process_inner.exited_children, &child);
                Some(child)
            } else {
                None
            };
            drop(process_inner);
            if (options & WNOWAIT) == 0 {
                if let Some(child) = child.as_ref() {
                    let child_cpu_ns = reap_zombie_child(child);
                    crate::task::manager::remove_from_pid2process(child_pid);
                    let mut parent_inner = cur_process.borrow_mut();
                    parent_inner.child_cpu_time_ns =
                        parent_inner.child_cpu_time_ns.saturating_add(child_cpu_ns);
                }
            }
            let (si_status, si_code) = if let Some(sig) = signal {
                (sig, if coredump { CLD_DUMPED } else { CLD_KILLED })
            } else {
                // 正常退出时 si_status 存放退出码低 8 位，与 wait4 的 wstatus 编码不同。
                (exit_code & 0xff, CLD_EXITED)
            };
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = si_code;
            info.si_pid = child_pid as i32;
            info.si_uid = uid;
            info.si_status = si_status;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if let Some((pid, sig, uid)) = found_stop {
            // WNOWAIT：不清除 stop_pending，允许同一 stop 事件被再次 wait 消费。
            if (options & WNOWAIT) == 0 {
                if let Some(child) = process_inner.children.iter().find(|c| c.getpid() == pid) {
                    let mut child_inner = child.borrow_mut();
                    child_inner.stop_pending = false;
                }
            }
            drop(process_inner);
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = CLD_STOPPED;
            info.si_pid = pid as i32;
            info.si_uid = uid;
            info.si_status = sig;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if let Some((pid, uid)) = found_cont {
            // WNOWAIT：不清除 continued 标志，与 stop_pending 的处理逻辑对称。
            if (options & WNOWAIT) == 0 {
                if let Some(child) = process_inner.children.iter().find(|c| c.getpid() == pid) {
                    let mut child_inner = child.borrow_mut();
                    child_inner.continued = false;
                }
            }
            drop(process_inner);
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = CLD_CONTINUED;
            info.si_pid = pid as i32;
            info.si_uid = uid;
            info.si_status = crate::task::signal::SIGCONT_NUM as i32;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if !has_match {
            drop(process_inner);
            return ECHILD;
        }

        // WNOHANG：有匹配子进程但当前无事件，写入全零 SigInfo 并立即返回 0（非 ECHILD）。
        if (options & WNOHANG) != 0 {
            drop(process_inner);
            let info = SigInfo::default();
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        // pidfd 以 O_NONBLOCK 打开时，有匹配进程但无就绪事件应返回 EAGAIN 而非阻塞。
        if idtype == P_PIDFD && pidfd_nonblock {
            drop(process_inner);
            return EAGAIN;
        }

        // 有匹配子进程但尚无事件，入队睡眠等待唤醒，逻辑与 wait4 相同。
        let inserted = enqueue_waiter_once(&mut process_inner.wait_queue, &task);
        if inserted {
            let qlen = process_inner.wait_queue.len();
            if qlen >= 64 && (qlen & (qlen - 1)) == 0 {
                crate::println!(
                    "[waitid-debug] pid={} wait_queue_len={} children={} idtype={} id={} options=0x{:x}",
                    cur_process.getpid(),
                    qlen,
                    process_inner.children.len(),
                    idtype,
                    id,
                    options
                );
            }
        }
        drop(process_inner);
        block_current_and_run_next();
    }
}

pub fn syscall_getpid() -> isize {
    current_task()
        .unwrap()
        .process
        .upgrade()
        .unwrap()
        .visible_pid() as isize
}

/// 查找并验证当前进程是否正在追踪指定 PID 的进程。
///
/// ptrace 操作（DETACH/CONT/KILL 等）都需要确认调用者确实是目标进程的 tracer，
/// 否则一个进程可以任意干扰它不应控制的进程。
fn ptrace_target_for_current(pid: usize) -> Result<Arc<ProcessControlBlock>, isize> {
    if pid == 0 {
        return Err(err(SyscallError::ESRCH));
    }
    let Some(target) = pid2process(pid) else {
        return Err(err(SyscallError::ESRCH));
    };
    let tracer_pid = current_process().getpid();
    let traced_by_current = {
        let inner = target.borrow_mut();
        if inner.is_zombie {
            return Err(err(SyscallError::ESRCH));
        }
        inner.ptrace_tracer_pid == Some(tracer_pid)
    };
    if !traced_by_current {
        return Err(err(SyscallError::EPERM));
    }
    Ok(target)
}

/// 实现 `ptrace` 系统调用，支持基础的追踪控制操作。
///
/// 当前实现覆盖：
/// - `PTRACE_TRACEME`：被追踪方主动声明愿意接受父进程的追踪
/// - `PTRACE_ATTACH`：追踪方强制附加到目标进程并发送 `SIGSTOP`
/// - `PTRACE_DETACH`：解除追踪关系并恢复目标进程运行
/// - `PTRACE_CONT`：继续被停止的被追踪进程，可同时投递信号
/// - `PTRACE_KILL`：强制终止被追踪进程（先唤醒后发 `SIGKILL`）
/// - 其余 request：验证 tracer 身份后返回 `EIO`，兼容 LTP 对内存/寄存器访问的预期错误码
pub fn syscall_ptrace(request: usize, pid: usize, _addr: usize, data: usize) -> isize {
    match request {
        PTRACE_TRACEME => {
            // 语义：当前进程自愿成为父进程的 ptrace 被追踪者。
            // 前置条件：当前进程尚未被任何 tracer 附加（否则重复 TRACEME 返回 EPERM）。
            // 父进程不存在（如 init 进程）时同样失败，因为没有合法的 tracer 承接事件。
            let process = current_process();
            let mut inner = process.borrow_mut();
            if inner.ptrace_tracer_pid.is_some() {
                return err(SyscallError::EPERM);
            }
            let Some(parent_pid) = inner
                .parent
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|p| p.getpid())
            else {
                return err(SyscallError::EPERM);
            };
            inner.ptrace_tracer_pid = Some(parent_pid);
            drop(inner);
            note_ptrace_attach_to(parent_pid);
            0
        }
        PTRACE_ATTACH => {
            // 语义：追踪方强制附加到目标进程，等效于目标进程执行了 PTRACE_TRACEME 并收到 SIGSTOP。
            // 前置条件：目标进程未被其他 tracer 持有；调用者对目标有信号投递权限（与 kill 权限相同）。
            // 附加后立即将所有线程置为 Blocked，并唤醒 tracer 的 wait 队列，
            // 这样 tracer 的下一次 wait 调用就能立刻收到 stop 事件。
            let tracer_pid = current_process().getpid();
            if pid == tracer_pid {
                return err(SyscallError::EPERM);
            }
            let Some(target) = pid2process(pid) else {
                return err(SyscallError::ESRCH);
            };
            if !crate::task::signal::can_signal_process(&target, SIGSTOP_NUM as i32) {
                return err(SyscallError::EPERM);
            }
            let tasks = {
                let mut inner = target.borrow_mut();
                if inner.is_zombie {
                    return err(SyscallError::ESRCH);
                }
                if inner.ptrace_tracer_pid.is_some() {
                    return err(SyscallError::EPERM);
                }
                inner.ptrace_tracer_pid = Some(tracer_pid);
                inner.stopped = true;
                inner.stop_pending = true;
                inner.stop_signal = SIGSTOP_NUM as i32;
                inner.continued = false;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            note_ptrace_attach_to(tracer_pid);
            // 将目标进程的所有线程标记为因信号停止，以便 DETACH/CONT 能精确恢复它们。
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if task_inner.task_status != TaskStatus::Blocked {
                    task_inner.task_status = TaskStatus::Blocked;
                    task_inner.stopped_by_signal = true;
                }
            }
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_DETACH => {
            // 语义：解除追踪关系，目标进程恢复运行，可附带投递一个信号（data 为信号号，0 表示不投递）。
            // 清除 ptrace_tracer_pid 后目标进程不再受 tracer 控制；
            // 设置 continued=true 以便父进程的 WCONTINUED wait 能感知此次恢复。
            let sig = data as isize;
            if sig < 0 || sig as usize > RT_SIG_MAX {
                return err(SyscallError::EINVAL);
            }
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let (old_tracer, tasks) = {
                let mut inner = target.borrow_mut();
                let old_tracer = inner.ptrace_tracer_pid.take();
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = true;
                let tasks = inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>();
                (old_tracer, tasks)
            };
            if let Some(tracer_pid) = old_tracer {
                note_ptrace_detach_from(tracer_pid);
            }
            // 只恢复因 ptrace stop 而 Blocked 的线程，避免错误唤醒因其他原因（如 futex）阻塞的线程。
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            if sig != 0 {
                queue_process_signal(pid, sig as usize);
            }
            // 唤醒父进程 wait 队列，使其能通过 WCONTINUED 感知目标进程已被恢复。
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_CONT => {
            // 语义：继续被 ptrace stop 的进程，tracer 关系保持不变（与 DETACH 的区别）。
            // 可同时投递信号（data != 0），允许 tracer 在 continue 时注入信号。
            let sig = data as isize;
            if sig < 0 || sig as usize > RT_SIG_MAX {
                return err(SyscallError::EINVAL);
            }
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let tasks = {
                let mut inner = target.borrow_mut();
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = true;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            if sig != 0 {
                queue_process_signal(pid, sig as usize);
            }
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_KILL => {
            // 语义：强制终止被追踪进程。
            // 必须先唤醒所有因 ptrace stop 而 Blocked 的线程，再投递 SIGKILL——
            // 若线程仍处于 Blocked 状态，SIGKILL 的递送可能永远等不到调度机会。
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let tasks = {
                let mut inner = target.borrow_mut();
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = false;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            // 先投递 SIGKILL，再唤醒线程，确保线程恢复运行后第一时间处理致命信号。
            queue_process_signal(pid, SIGKILL_NUM);
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            0
        }
        _ => {
            // Keep invalid memory/register ptrace operations Linux-like for LTP:
            // return err(SyscallError::EIO) (tests also accept err(SyscallError::EFAULT)).
            if let Err(e) = ptrace_target_for_current(pid) {
                return e;
            }
            err(SyscallError::EIO)
        }
    }
}
