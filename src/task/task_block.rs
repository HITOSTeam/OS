use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};

use crate::{
    mm::PhysPageNum,
    task::{
        id::{KernelStack, TaskUserRes, kstack_alloc},
        process_block::ProcessControlBlock,
        signal::RT_SIG_MAX,
        task_context::TaskContext,
    },
    trap::{context::TrapContext, trap_handler, trap_return},
};

pub struct TaskControlBlock {
    // immutable
    // 对于所有的线程,共享一个父进程
    pub process: Weak<ProcessControlBlock>,
    // Keep kernel-stack ownership separate so exited tasks can release stack
    // pages even if some metadata Arc references linger for a while.
    pub kstack: Mutex<Option<KernelStack>>,
    /// Preferred CPU (hart) to run this task on.
    ///
    /// This is used by the scheduler to decide which per-hart run queue the task should be
    /// enqueued into when it becomes runnable.
    pub cpu_id: AtomicUsize,
    /// The hart id currently running this task, or OFF_CPU if none.
    pub on_cpu: AtomicUsize,
    /// Set by a waker if it tried to wake while the task was still on_cpu.
    pub wakeup_pending: AtomicBool,
    /// Whether this task is currently enqueued in the global ready queue.
    pub in_ready_queue: AtomicBool,
    // mutable
    inner: Mutex<TaskControlBlockInner>,
}

static TASK_TCB_ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static TASK_TCB_DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

fn maybe_log_tcb_inflight(event: &str) {
    if !crate::debug_config::DEBUG_TASK_LIFECYCLE {
        return;
    }
    let allocs = TASK_TCB_ALLOC_COUNT.load(Ordering::Relaxed);
    let drops = TASK_TCB_DROP_COUNT.load(Ordering::Relaxed);
    let inflight = allocs.saturating_sub(drops);
    if inflight >= 64 && (inflight & (inflight - 1)) == 0 {
        crate::println!(
            "[tcb-debug] event={} inflight={} allocs={} drops={}",
            event,
            inflight,
            allocs,
            drops
        );
    }
}

impl TaskControlBlock {
    pub const OFF_CPU: usize = usize::MAX;

    pub fn set_cpu_id(&self, cpu_id: usize) {
        self.cpu_id.store(cpu_id, Ordering::Release);
    }

    pub fn get_cpu_id(&self) -> usize {
        self.cpu_id.load(Ordering::Acquire)
    }

    pub fn mark_on_cpu(&self, hart_id: usize) {
        self.cpu_id.store(hart_id, Ordering::Release);
        self.on_cpu.store(hart_id, Ordering::Release);
        // Once running, no wakeup should be pending.
        self.wakeup_pending.store(false, Ordering::Release);
    }

    pub fn clear_on_cpu(&self) {
        self.on_cpu.store(Self::OFF_CPU, Ordering::Release);
    }

    pub fn borrow_mut(&self) -> MutexGuard<'_, TaskControlBlockInner> {
        self.inner.lock()
    }

    pub fn kstack_top(&self) -> usize {
        self.kstack
            .lock()
            .as_ref()
            .expect("kernel stack already released")
            .get_top()
    }

    pub fn take_kstack(&self) -> Option<KernelStack> {
        self.kstack.lock().take()
    }

    pub fn try_borrow_mut(&self) -> Option<MutexGuard<'_, TaskControlBlockInner>> {
        self.inner.try_lock()
    }

    pub fn get_user_token(&self) -> usize {
        let process = self.process.upgrade().unwrap();
        let inner = process.borrow_mut();
        inner.memory_set.token()
    }
}

pub struct TaskControlBlockInner {
    // 对于所有的线程,共享一个父进程
    pub res: Option<TaskUserRes>,
    pub trap_cx_ppn: PhysPageNum,
    pub task_cx: TaskContext,
    pub task_status: TaskStatus,
    pub exit_code: Option<i32>,
    pub join_waiters: VecDeque<Arc<TaskControlBlock>>,
    /// Linux `CLONE_CHILD_CLEARTID`/`set_tid_address` target address (user VA).
    pub clear_child_tid: Option<usize>,
    /// Linux robust futex list head (user VA) and length.
    pub robust_list_head: usize,
    pub robust_list_len: usize,
    /// Pending POSIX signals for this thread (bitmask).
    pub pending_signals: u64,
    /// Best-effort sender metadata for pending signals (indexed by signum).
    pub pending_signal_pid: [i32; RT_SIG_MAX + 1],
    pub pending_signal_uid: [u32; RT_SIG_MAX + 1],
    pub pending_signal_code: [i32; RT_SIG_MAX + 1],
    pub pending_signal_value: [usize; RT_SIG_MAX + 1],
    /// Signal mask for this thread (bitmask of blocked signals).
    pub signal_mask: u64,
    /// Active `sigwaitinfo()/sigtimedwait()/sigwait()` interest set.
    /// While present, normal signal delivery defers matching and interrupting
    /// signals back to the waiting syscall so it can return Linux-like
    /// results instead of consuming them via handlers first.
    pub sigwait_mask: Option<u64>,
    /// Saved mask to restore after a `sigsuspend`-delivered signal.
    pub sigsuspend_old_mask: Option<u64>,
    /// Saved user contexts when running nested signal handlers (stack).
    pub sig_saved_ctx: alloc::vec::Vec<SigSavedContext>,
    /// Alternate signal stack state (`sigaltstack`).
    pub sigaltstack_sp: usize,
    pub sigaltstack_size: usize,
    pub sigaltstack_enabled: bool,
    pub on_sigaltstack: bool,
    /// Last syscall info for restartable syscalls (SA_RESTART).
    pub last_syscall_id: usize,
    pub last_syscall_args: [usize; 6],
    pub last_syscall_valid: bool,
    /// Task was blocked due to a job-control stop signal.
    pub stopped_by_signal: bool,
    /// Task is logically frozen by the cgroup freezer.
    pub cgroup_frozen: bool,
    /// Task was runnable but parked by the cgroup freezer.
    pub parked_by_cgroup: bool,
    /// A wakeup event happened while the task was cgroup-frozen.
    pub wake_on_cgroup_thaw: bool,
    /// Number of timer ticks consumed in current SCHED_RR round.
    pub rr_ticks: usize,
    /// Best-effort per-thread CPU runtime used for *_CPUTIME clocks.
    /// 每次时钟中断时候更新,
    pub cpu_time_ns: u64,
    /// Monotonic timestamp captured when the task most recently started running.
    pub runtime_start_ns: u64,
    /// CPU runtime snapshot used to charge fair-group virtual runtime when the
    /// task returns to a runqueue.
    pub fair_runtime_checkpoint_ns: u64,
    /// Per-thread nice value (Linux/NPTL semantics).
    pub nice: i32,
    /// Hint that libc just queried self priority and may issue `nice()`.
    pub nice_query_hint: bool,
    /// Saved user floating-point registers (`f0..f31`) for context switches.
    pub fp_regs: [u64; 32],
    /// Saved floating-point control/status register.
    pub fp_fcsr: u32,
    /// Saved floating-point condition code registers (LoongArch FCC0-FCC7).
    pub fp_fcc: u8,
    /// Whether `fp_regs/fp_fcsr` contain a valid snapshot.
    pub fp_valid: bool,
}

#[derive(Clone, Copy)]
pub struct SigSavedContext {
    pub trap_cx: TrapContext,
    pub mask: u64,
    pub ucontext_ptr: usize,
    pub uses_ucontext: bool,
    pub signum: usize,
    pub was_on_sigaltstack: bool,
}

impl TaskControlBlockInner {
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }

    #[allow(unused)]
    fn get_status(&self) -> TaskStatus {
        self.task_status
    }
}

/// Reason why `TaskControlBlock` allocation failed.
#[derive(Debug, Clone, Copy)]
pub enum TaskAllocError {
    /// Mapping the per-thread trap-context (or user-stack) page failed (OOM).
    TrapCxAllocFailed,
    /// Kernel-stack frame allocation failed (OOM).
    KernelStackOom,
}

impl TaskControlBlock {
    pub fn try_new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Result<Self, TaskAllocError> {
        let res = TaskUserRes::try_new(Arc::clone(&process), ustack_base, alloc_user_res)
            .ok_or(TaskAllocError::TrapCxAllocFailed)?;
        let trap_cx_ppn = res.trap_cx_ppn();
        let kstack = kstack_alloc().ok_or(TaskAllocError::KernelStackOom)?;
        let kstack_top = kstack.get_top();
        let process_nice = {
            let inner = process.borrow_mut();
            inner.scheduling.nice
        };
        let tcb = Self {
            process: Arc::downgrade(&process),
            kstack: Mutex::new(Some(kstack)),
            cpu_id: AtomicUsize::new(0),
            on_cpu: AtomicUsize::new(Self::OFF_CPU),
            wakeup_pending: AtomicBool::new(false),
            in_ready_queue: AtomicBool::new(false),
            inner: Mutex::new(TaskControlBlockInner {
                res: Some(res),
                trap_cx_ppn,
                //创建应用的时候把他设置为trap_return,这样第一次switch的时候就会从trap_return进入
                task_cx: TaskContext::set_for_app(trap_return as usize, kstack_top),
                task_status: TaskStatus::Ready,
                exit_code: None,
                join_waiters: VecDeque::new(),
                clear_child_tid: None,
                robust_list_head: 0,
                robust_list_len: 0,
                pending_signals: 0,
                pending_signal_pid: [0; RT_SIG_MAX + 1],
                pending_signal_uid: [0; RT_SIG_MAX + 1],
                pending_signal_code: [0; RT_SIG_MAX + 1],
                pending_signal_value: [0; RT_SIG_MAX + 1],
                signal_mask: 0,
                sigwait_mask: None,
                sigsuspend_old_mask: None,
                sig_saved_ctx: alloc::vec::Vec::new(),
                sigaltstack_sp: 0,
                sigaltstack_size: 0,
                sigaltstack_enabled: false,
                on_sigaltstack: false,
                last_syscall_id: 0,
                last_syscall_args: [0; 6],
                last_syscall_valid: false,
                stopped_by_signal: false,
                cgroup_frozen: false,
                parked_by_cgroup: false,
                wake_on_cgroup_thaw: false,
                rr_ticks: 0,
                cpu_time_ns: 0,
                runtime_start_ns: 0,
                fair_runtime_checkpoint_ns: 0,
                nice: process_nice,
                nice_query_hint: false,
                fp_regs: [0; 32],
                fp_fcsr: 0,
                fp_fcc: 0,
                fp_valid: false,
            }),
        };
        TASK_TCB_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        maybe_log_tcb_inflight("alloc");
        Ok(tcb)
    }

    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        Self::try_new(process, ustack_base, alloc_user_res).expect("OOM: TaskControlBlock::new")
    }

    /// 为 Linux 线程语义（CLONE_THREAD | CLONE_VM）的 clone 创建一个新的 TCB。
    ///
    /// 与 `try_new` 的区别：
    /// - 不再为线程分配独立的用户栈：父子共享地址空间，用户栈由调用方
    ///   （glibc/musl 的 pthread_create）从堆里自行划分并通过 clone 的 stack 参数传入。
    /// - 仍然需要独占的 trap_cx 帧和内核栈：每个线程在内核态都要有自己的现场。
    /// - 不参与 user resource 的 ustack/entry 分配流程，因此用 `try_new_trap_cx_only`。
    ///
    /// 失败原因：trap_cx 物理页分配失败、内核栈 OOM 等，全部以 `TaskAllocError` 透出。
    pub fn try_new_linux_thread(process: Arc<ProcessControlBlock>) -> Result<Self, TaskAllocError> {
        // 仅为新线程分配 trap_cx 页（不分配用户栈/不绑定 entry），失败回 TrapCxAllocFailed
        let res = TaskUserRes::try_new_trap_cx_only(Arc::clone(&process))
            .ok_or(TaskAllocError::TrapCxAllocFailed)?;
        // 取出 trap_cx 所在物理页号，后续切换时内核据此找回该线程的陷入现场
        let trap_cx_ppn = res.trap_cx_ppn();
        // 为新线程分配独立的内核栈；OOM 时上抛 KernelStackOom
        let kstack = kstack_alloc().ok_or(TaskAllocError::KernelStackOom)?;
        let kstack_top = kstack.get_top();
        // 继承进程当前的 nice 值，避免新线程上调度器后 nice 不一致
        let process_nice = {
            let inner = process.borrow_mut();
            inner.scheduling.nice
        };
        let tcb = Self {
            // 用 Weak 反指回所属进程，避免线程 TCB 与进程 PCB 之间形成 Arc 循环引用
            process: Arc::downgrade(&process),
            // 内核栈所有权交给 TCB，drop 时一并回收
            kstack: Mutex::new(Some(kstack)),
            // 初始未绑定 hart，调用方随后通过 set_cpu_id 指定运行核
            cpu_id: AtomicUsize::new(0),
            // 当前未上 CPU；运行时由调度器把它切到 ON_CPU 状态
            on_cpu: AtomicUsize::new(Self::OFF_CPU),
            // 唤醒标记/就绪队列标记的初值均为 false：刚创建还未排队
            wakeup_pending: AtomicBool::new(false),
            in_ready_queue: AtomicBool::new(false),
            inner: Mutex::new(TaskControlBlockInner {
                res: Some(res),
                trap_cx_ppn,
                // 任务切换上下文：首次被调度时从 trap_return 入口返回用户态，sp 指向新内核栈顶
                task_cx: TaskContext::set_for_app(trap_return as usize, kstack_top),
                // 进入就绪状态，等待调度器拣选
                task_status: TaskStatus::Ready,
                exit_code: None,
                join_waiters: VecDeque::new(),
                // CLONE_CHILD_CLEARTID 的目标地址由调用方在 clone 路径里填入，这里先置空
                clear_child_tid: None,
                // robust futex list：尚未通过 set_robust_list 注册，初值为 0
                robust_list_head: 0,
                robust_list_len: 0,
                // 信号子系统的待处理位图与元数据，全部清零；信号屏蔽字也由调用方按父线程复制
                pending_signals: 0,
                pending_signal_pid: [0; RT_SIG_MAX + 1],
                pending_signal_uid: [0; RT_SIG_MAX + 1],
                pending_signal_code: [0; RT_SIG_MAX + 1],
                pending_signal_value: [0; RT_SIG_MAX + 1],
                signal_mask: 0,
                sigwait_mask: None,
                sigsuspend_old_mask: None,
                sig_saved_ctx: alloc::vec::Vec::new(),
                // sigaltstack 默认未启用：线程未调用 sigaltstack(2) 之前走主栈处理信号
                sigaltstack_sp: 0,
                sigaltstack_size: 0,
                sigaltstack_enabled: false,
                on_sigaltstack: false,
                // 最近一次 syscall 的快照清零；ptrace/strace 类调试会按需写入
                last_syscall_id: 0,
                last_syscall_args: [0; 6],
                last_syscall_valid: false,
                stopped_by_signal: false,
                // cgroup 冻结/解冻状态：新线程默认未冻结，也未挂起等待解冻
                cgroup_frozen: false,
                parked_by_cgroup: false,
                wake_on_cgroup_thaw: false,
                // 调度统计：RR 时间片、CPU 累计时间、公平调度基线全部归零
                rr_ticks: 0,
                cpu_time_ns: 0,
                runtime_start_ns: 0,
                fair_runtime_checkpoint_ns: 0,
                // 继承父进程的 nice，新线程从同一起跑线开始竞争 CPU
                nice: process_nice,
                nice_query_hint: false,
                // 浮点寄存器初值置零；首次切换时按需做 lazy 保存/恢复
                fp_regs: [0; 32],
                fp_fcsr: 0,
                fp_fcc: 0,
                fp_valid: false,
            }),
        };
        // 全局 TCB 计数 +1，配合 drop 端的减法可监控泄漏
        TASK_TCB_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        // 视调试开关打印当前在飞 TCB 数量
        maybe_log_tcb_inflight("alloc");
        Ok(tcb)
    }

    pub fn new_linux_thread(process: Arc<ProcessControlBlock>) -> Self {
        Self::try_new_linux_thread(process).expect("OOM: TaskControlBlock::new_linux_thread")
    }
}

impl Drop for TaskControlBlock {
    fn drop(&mut self) {
        TASK_TCB_DROP_COUNT.fetch_add(1, Ordering::Relaxed);
        maybe_log_tcb_inflight("drop");
    }
}

impl TaskControlBlock {
    /// Account runtime consumed since the last charge point while the task is running.
    ///  退出 时 调用。 任务的运行时间
    pub(crate) fn account_runtime_until(&self, now_ns: u64) -> u64 {
        let mut inner = self.borrow_mut();
        let delta_ns = now_ns.saturating_sub(inner.runtime_start_ns);
        if delta_ns > 0 {
            inner.cpu_time_ns = inner.cpu_time_ns.saturating_add(delta_ns);
            inner.runtime_start_ns = now_ns;
        }
        delta_ns
    }

    /// Mark the task as newly running from `now_ns`.
    /// 开始时 调用 更新任务开始时间。
    pub(crate) fn begin_runtime_slice(&self, now_ns: u64) {
        self.borrow_mut().runtime_start_ns = now_ns;
    }

    /// Return total charged CPU time, including the currently running slice.
    pub(crate) fn cpu_time_total_ns(&self, now_ns: u64) -> u64 {
        let inner = self.borrow_mut();
        // 当前CPU 仍在调度
        // 当前 时间 + 累计时间
        if self.on_cpu.load(Ordering::Acquire) != Self::OFF_CPU {
            inner
                .cpu_time_ns
                .saturating_add(now_ns.saturating_sub(inner.runtime_start_ns))
        } else {
            inner.cpu_time_ns
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum TaskStatus {
    Ready,
    Running,
    Blocked,
}
