use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};

use crate::{
    mm::{MmRef, PhysPageNum},
    task::{
        id::{KernelStack, TaskUserRes, kstack_alloc},
        process_block::{ProcessControlBlock, ProcessScheduling},
        signal::RT_SIG_MAX,
        task_context::TaskContext,
    },
    trap::{context::TrapContext, trap_handler, trap_return},
};

pub struct TaskControlBlock {
    // 不可变字段
    // 对于所有的线程,共享一个父进程
    pub process: Weak<ProcessControlBlock>,
    /// Cached current address space. The PCB remains the authoritative owner;
    /// this avoids taking the large process lock on every return to user mode.
    memory_set: Mutex<MmRef>,
    // 将内核栈所有权单独保存，这样即使部分元数据 Arc 引用暂时残留，
    // 已退出任务也能释放内核栈页。
    pub kstack: Mutex<Option<KernelStack>>,
    /// 当前任务偏好的运行 CPU（hart）。
    ///
    /// 调度器在任务变为可运行时，用它决定应放入哪个每 hart 运行队列。
    pub cpu_id: AtomicUsize,
    /// 当前正在运行该任务的 hart id；如果没有运行在任何 hart 上，则为 OFF_CPU。
    pub on_cpu: AtomicUsize,
    /// 当唤醒方尝试唤醒仍处于 `on_cpu` 状态的任务时置位。
    pub wakeup_pending: AtomicBool,
    /// `wakeup_pending` 对应的同步唤醒来源 hart。
    ///
    /// Linux `WF_SYNC` 风格 handoff 可能发生在目标任务还位于自己的内核栈上时。
    /// 此时只能延迟到目标切回 idle 后入队；这里保留原始 waker hart，避免
    /// 补唤醒退化成“贴近 wakee 原 CPU”。
    pub wakeup_sync_hart: AtomicUsize,
    /// 线程存在待处理信号的快速标志。
    ///
    /// 对应 Linux 的 `TIF_SIGPENDING` 思路：返回用户态前先看这个原子标志，
    /// 无信号的热路径不需要进入 TCB 内层锁。
    signal_pending: AtomicBool,
    /// 当前任务是否已经进入某个每 hart 就绪队列。
    pub in_ready_queue: AtomicBool,
    /// 当前持有该任务的 hart 运行队列；未入队时为 `OFF_CPU`。
    pub ready_queue_hart: AtomicUsize,
    /// futex wait 入队后的反向句柄。
    ///
    /// 退出清理可凭它直接进入对应 futex bucket 删除 waiter，避免扫描所有
    /// futex 队列；正常 wake/timeout/signal 路径会清掉这个句柄。
    futex_wait: Mutex<Option<FutexWaitHandle>>,
    // 可变字段
    inner: Mutex<TaskControlBlockInner>,
}

pub struct FutexWaitHandle {
    pub key: (usize, usize),
    pub in_queue: Arc<AtomicBool>,
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

    /// 在任务离开运行队列时原子声明 CPU 所有权。
    ///
    /// 必须在任务仍受运行队列锁保护时完成；否则另一核可能在“已经出队、
    /// 尚未标记运行”的窗口中再次入队同一任务，最终并发使用同一内核栈。
    pub fn try_mark_on_cpu(&self, hart_id: usize) -> bool {
        self.cpu_id.store(hart_id, Ordering::Release);
        self.on_cpu
            .compare_exchange(Self::OFF_CPU, hart_id, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn clear_on_cpu(&self) {
        self.on_cpu.store(Self::OFF_CPU, Ordering::Release);
    }

    pub fn mark_signal_pending(&self) {
        self.signal_pending.store(true, Ordering::Release);
    }

    pub fn refresh_signal_pending(&self, pending: u64) {
        self.signal_pending.store(pending != 0, Ordering::Release);
    }

    pub fn has_signal_pending(&self) -> bool {
        self.signal_pending.load(Ordering::Acquire)
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
        self.memory_set.lock().token()
    }

    /// Clone the cached mm handle without borrowing the owning process.
    pub fn memory_set(&self) -> MmRef {
        self.memory_set.lock().clone()
    }

    /// Replace the task's cached mm after exec installs a new address space.
    pub fn set_memory_set(&self, memory_set: MmRef) {
        *self.memory_set.lock() = memory_set;
    }

    #[cfg(target_arch = "loongarch64")]
    pub fn prepare_user_asid(&self) -> (usize, bool) {
        self.memory_set.lock().prepare_user_asid()
    }

    #[cfg(target_arch = "riscv64")]
    pub fn prepare_user_satp(&self) -> (usize, bool, bool) {
        self.memory_set.lock().prepare_user_satp()
    }

    /// 将保存的用户态浮点状态重置为 Linux exec/线程初始状态：
    /// 所有 FP 寄存器和控制位均为 0。
    /// 初始化 fp 相关寄存器。
    pub fn reset_fp_state(&self) {
        let mut inner = self.borrow_mut();
        inner.fp_regs = [0; 32];
        inner.fp_fcsr = 0;
        inner.fp_fcc = 0;
        inner.fp_valid = true;
        inner.fp_used = false;
    }

    /// 将父任务保存的用户态浮点状态复制到刚 fork/clone 出来的子任务。
    /// 调用方必须先把当前硬件 FPU 状态保存到 `parent` 中，这与 Linux 的
    /// arch_dup_task_struct()/copy_thread() 语义一致。子任务继承保存的
    /// 快照，但不继承“当前 CPU 已加载 FPU”的 owner 状态。
    /// 继承父任务的寄存器。
    pub fn inherit_fp_state_from(&self, parent: &TaskControlBlock) {
        let (fp_regs, fp_fcsr, fp_fcc, fp_valid) = {
            let parent_inner = parent.borrow_mut();
            (
                parent_inner.fp_regs,
                parent_inner.fp_fcsr,
                parent_inner.fp_fcc,
                parent_inner.fp_valid,
            )
        };
        let mut inner = self.borrow_mut();
        inner.fp_regs = fp_regs;
        inner.fp_fcsr = fp_fcsr;
        inner.fp_fcc = fp_fcc;
        inner.fp_valid = fp_valid;
        inner.fp_used = false;
    }

    pub fn scheduling_snapshot(&self) -> ProcessScheduling {
        self.borrow_mut().scheduling.clone()
    }

    pub fn set_scheduling_snapshot(&self, scheduling: ProcessScheduling) {
        let mut inner = self.borrow_mut();
        inner.nice = scheduling.nice;
        inner.scheduling = scheduling;
    }

    pub fn next_sleep_timer_seq(&self) -> u64 {
        let mut inner = self.borrow_mut();
        inner.sleep_timer_seq = inner.sleep_timer_seq.wrapping_add(1);
        inner.sleep_timer_seq
    }

    pub fn sleep_timer_seq(&self) -> u64 {
        self.borrow_mut().sleep_timer_seq
    }

    pub fn cancel_sleep_timers(&self) {
        let mut inner = self.borrow_mut();
        inner.sleep_timer_seq = inner.sleep_timer_seq.wrapping_add(1);
    }

    pub fn set_futex_wait(&self, key: (usize, usize), in_queue: Arc<AtomicBool>) {
        *self.futex_wait.lock() = Some(FutexWaitHandle { key, in_queue });
    }

    pub fn update_futex_wait_key(&self, in_queue: &Arc<AtomicBool>, key: (usize, usize)) {
        let mut handle = self.futex_wait.lock();
        if let Some(handle) = handle.as_mut()
            && Arc::ptr_eq(&handle.in_queue, in_queue)
        {
            handle.key = key;
        }
    }

    pub fn clear_futex_wait(&self, in_queue: &Arc<AtomicBool>) {
        let mut handle = self.futex_wait.lock();
        if handle
            .as_ref()
            .map(|handle| Arc::ptr_eq(&handle.in_queue, in_queue))
            .unwrap_or(false)
        {
            *handle = None;
        }
    }

    pub fn take_futex_wait(&self) -> Option<FutexWaitHandle> {
        self.futex_wait.lock().take()
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
    /// Linux `CLONE_CHILD_CLEARTID`/`set_tid_address` 的目标地址（用户虚拟地址）。
    pub clear_child_tid: Option<usize>,
    /// Linux robust futex 链表头（用户虚拟地址）及长度。
    pub robust_list_head: usize,
    pub robust_list_len: usize,
    /// 当前线程的待处理 POSIX 信号（位图）。
    pub pending_signals: u64,
    /// 待处理信号的发送方元数据（按信号编号索引，尽力保存）。
    pub pending_signal_pid: [i32; RT_SIG_MAX + 1],
    pub pending_signal_uid: [u32; RT_SIG_MAX + 1],
    pub pending_signal_code: [i32; RT_SIG_MAX + 1],
    pub pending_signal_value: [usize; RT_SIG_MAX + 1],
    /// 当前线程的信号屏蔽字（被阻塞信号的位图）。
    pub signal_mask: u64,
    /// 当前活跃的 `sigwaitinfo()/sigtimedwait()/sigwait()` 关注信号集合。
    /// 存在该集合时，普通信号投递会把匹配且可中断的信号交还给正在等待的系统调用，
    /// 让它返回 Linux 风格结果，而不是先被信号处理函数消费。
    pub sigwait_mask: Option<u64>,
    /// `sigsuspend` 投递信号后需要恢复的旧信号屏蔽字。
    pub sigsuspend_old_mask: Option<u64>,
    /// 运行嵌套信号处理函数时保存的用户上下文栈。
    pub sig_saved_ctx: alloc::vec::Vec<SigSavedContext>,
    /// 备用信号栈状态（`sigaltstack`）。
    pub sigaltstack_sp: usize,
    pub sigaltstack_size: usize,
    pub sigaltstack_enabled: bool,
    pub on_sigaltstack: bool,
    /// 可重启系统调用（SA_RESTART）使用的最近一次 syscall 信息。
    pub last_syscall_id: usize,
    pub last_syscall_args: [usize; 6],
    pub last_syscall_valid: bool,
    /// 任务因作业控制停止信号而阻塞。
    pub stopped_by_signal: bool,
    /// 任务在逻辑上被 cgroup freezer 冻结。
    pub cgroup_frozen: bool,
    /// 任务原本可运行，但被 cgroup freezer 暂停放置。
    pub parked_by_cgroup: bool,
    /// 任务处于 cgroup 冻结状态期间发生过唤醒事件。
    pub wake_on_cgroup_thaw: bool,
    /// 当前 SCHED_RR 轮次中已经消耗的 timer tick 数。
    pub rr_ticks: usize,
    /// `*_CPUTIME` 时钟使用的线程级 CPU 运行时间（尽力统计）。
    /// 每次时钟中断时更新。
    pub cpu_time_ns: u64,
    /// 任务最近一次开始运行时记录的单调时间戳。
    pub runtime_start_ns: u64,
    /// 任务返回运行队列时，用于向公平组虚拟运行时间记账的 CPU 运行时间快照。
    pub fair_runtime_checkpoint_ns: u64,
    /// 当前任务的 EEVDF 调度实体虚拟运行时间。
    ///
    /// Linux 将 vruntime 保存在 `task_struct::se` 中；这里按任务保存，
    /// 避免把公平组中的所有任务当作 FIFO 队列项处理。
    pub fair_vruntime_ns: u128,
    /// 当前公平调度请求的 EEVDF 虚拟截止时间。
    ///
    /// Linux 将它保存在 `task_struct::se.deadline` 中；时钟 tick 和 syscall 返回路径
    /// 会用当前 vruntime 与它比较，而不是等待粗粒度的整 tick 轮转时间片。
    pub fair_deadline_ns: u128,
    /// 公平调度任务阻塞时捕获的正 EEVDF 滞后值。
    ///
    /// Linux 会在 sleep/wakeup 之间保留有界的 `se->vlag`（`PLACE_LAG`），
    /// 使短控制线程在 fork-heavy 负载下不会丢失全部公平调度信用。
    pub fair_vlag_ns: u128,
    /// exec/小线程组启动阶段的一次性 fair credit。
    ///
    /// 这不是长期优先级；只在下一次重新入队时消费，用于补偿当前没有完整
    /// wakeup-preempt/hrtick 机制时 foreground 控制线程被大 fair 队列埋住的问题。
    pub fair_startup_credit_ns: u128,
    /// 公平调度使用的 legacy CPU cgroup 身份缓存。
    ///
    /// Linux 会让 cgroup/task-group 调度状态可从任务的调度实体访问；
    /// 入队路径不应再查询 cgroup 文件系统注册表。
    pub fair_group_id: u64,
    pub fair_group_shares: u64,
    /// 通用睡眠定时器的代数。递增它即可取消旧定时器堆项，
    /// 无需扫描堆，对应 Linux hrtimer_cancel() 的形态。
    pub sleep_timer_seq: u64,
    /// 线程级 nice 值（Linux/NPTL 语义）。
    pub nice: i32,
    /// libc 刚查询过自身优先级、可能接着调用 `nice()` 的提示位。
    pub nice_query_hint: bool,
    /// 任务级调度属性。Linux 将调度策略、RT 优先级和 CPU 亲和性保存在
    /// `task_struct` 中；PCB 中的字段只作为创建新任务时使用的默认值。
    pub scheduling: ProcessScheduling,
    /// 上下文切换时保存的用户态浮点寄存器（`f0..f31`）。
    pub fp_regs: [u64; 32],
    /// 保存的浮点控制/状态寄存器。
    pub fp_fcsr: u32,
    /// 保存的浮点条件码寄存器（LoongArch FCC0-FCC7）。
    pub fp_fcc: u8,
    /// `fp_regs/fp_fcsr` 是否包含有效快照。
    pub fp_valid: bool,
    /// 当前任务是否已经实际使用过 FP，且硬件 FPU 中可能持有它的 live 状态。
    pub fp_used: bool,
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

/// `TaskControlBlock` 分配失败的原因。
#[derive(Debug, Clone, Copy)]
pub enum TaskAllocError {
    /// 映射线程级 trap-context（或用户栈）页面失败（OOM）。
    TrapCxAllocFailed,
    /// 内核栈帧分配失败（OOM）。
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
        let process_scheduling = {
            let inner = process.borrow_mut();
            inner.scheduling.clone()
        };
        let memory_set = process.memory_set();
        let tcb = Self {
            process: Arc::downgrade(&process),
            memory_set: Mutex::new(memory_set),
            kstack: Mutex::new(Some(kstack)),
            cpu_id: AtomicUsize::new(0),
            on_cpu: AtomicUsize::new(Self::OFF_CPU),
            wakeup_pending: AtomicBool::new(false),
            wakeup_sync_hart: AtomicUsize::new(Self::OFF_CPU),
            signal_pending: AtomicBool::new(false),
            in_ready_queue: AtomicBool::new(false),
            ready_queue_hart: AtomicUsize::new(Self::OFF_CPU),
            futex_wait: Mutex::new(None),
            inner: Mutex::new(TaskControlBlockInner {
                res: Some(res),
                trap_cx_ppn,
                //创建应用的时候把它设置为 trap_return，这样第一次切换时会从 trap_return 进入
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
                fair_vruntime_ns: 0,
                fair_deadline_ns: 0,
                fair_vlag_ns: 0,
                fair_startup_credit_ns: 0,
                fair_group_id: 0,
                fair_group_shares: 1024,
                sleep_timer_seq: 0,
                nice: process_scheduling.nice,
                nice_query_hint: false,
                scheduling: process_scheduling,
                fp_regs: [0; 32],
                fp_fcsr: 0,
                fp_fcc: 0,
                fp_valid: true,
                fp_used: false,
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
    /// - 不参与用户资源中的 ustack/entry 分配流程，因此用 `try_new_trap_cx_only`。
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
        let process_scheduling = {
            let inner = process.borrow_mut();
            inner.scheduling.clone()
        };
        let memory_set = process.memory_set();
        let tcb = Self {
            // 用 Weak 反指回所属进程，避免线程 TCB 与进程 PCB 之间形成 Arc 循环引用
            process: Arc::downgrade(&process),
            memory_set: Mutex::new(memory_set),
            // 内核栈所有权交给 TCB，drop 时一并回收
            kstack: Mutex::new(Some(kstack)),
            // 初始未绑定 hart，调用方随后通过 set_cpu_id 指定运行核
            cpu_id: AtomicUsize::new(0),
            // 当前未上 CPU；运行时由调度器把它切到 ON_CPU 状态
            on_cpu: AtomicUsize::new(Self::OFF_CPU),
            // 唤醒标记/就绪队列标记的初值均为 false：刚创建还未排队
            wakeup_pending: AtomicBool::new(false),
            wakeup_sync_hart: AtomicUsize::new(Self::OFF_CPU),
            signal_pending: AtomicBool::new(false),
            in_ready_queue: AtomicBool::new(false),
            ready_queue_hart: AtomicUsize::new(Self::OFF_CPU),
            futex_wait: Mutex::new(None),
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
                fair_vruntime_ns: 0,
                fair_deadline_ns: 0,
                fair_vlag_ns: 0,
                fair_startup_credit_ns: 0,
                fair_group_id: 0,
                fair_group_shares: 1024,
                sleep_timer_seq: 0,
                // 继承父进程的 nice，新线程从同一起跑线开始竞争 CPU
                nice: process_scheduling.nice,
                nice_query_hint: false,
                scheduling: process_scheduling,
                // 浮点寄存器初值是有效的全零快照，避免首次调度继承 hart 残留状态
                fp_regs: [0; 32],
                fp_fcsr: 0,
                fp_fcc: 0,
                fp_valid: true,
                fp_used: false,
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
    /// 统计任务运行期间自上一次记账点以来消耗的运行时间。
    /// 退出时调用，用于记录任务的运行时间。
    pub(crate) fn account_runtime_until(&self, now_ns: u64) -> u64 {
        let mut inner = self.borrow_mut();
        let delta_ns = now_ns.saturating_sub(inner.runtime_start_ns);
        if delta_ns > 0 {
            inner.cpu_time_ns = inner.cpu_time_ns.saturating_add(delta_ns);
            inner.runtime_start_ns = now_ns;
        }
        delta_ns
    }

    /// 标记任务从 `now_ns` 开始新一段运行。
    /// 开始运行时调用，用于更新任务开始时间。
    pub(crate) fn begin_runtime_slice(&self, now_ns: u64) {
        self.borrow_mut().runtime_start_ns = now_ns;
    }

    /// 返回已记账的 CPU 总时间，包括当前正在运行的时间片。
    pub(crate) fn cpu_time_total_ns(&self, now_ns: u64) -> u64 {
        let inner = self.borrow_mut();
        // 当前 CPU 仍在调度。
        // 当前时间 + 累计时间。
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
