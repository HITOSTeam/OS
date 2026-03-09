// use super::restore;
// use super::task_context::TaskContext;
// use crate::config::{TRAMPOLINE, TRAP_CONTEXT, kernel_stack_position};
// use crate::fs::{File, Stdin, Stdout};
// use crate::mm::{
//     KERNEL_SPACE, MapPermission, MemorySet, PhysPageNum, VirtAddr, VirtPageNum,
//     translated_single_address,
// };
// use crate::task::manager::TaskManager;
// use crate::task::pid::{Pid, alloc_pid};
// use crate::task::signal::{self, SignalActions, SignalFlags};
// use crate::task::stack::KernelStack;
// use crate::trap::context::{TrapContext, push_trap_context_at};
// use crate::trap::{trap_handler, trap_return};
// use crate::utils::{RefCellSafe, get_app_data_by_name};
// use crate::{println, trap};
// use alloc::string::String;
// use alloc::sync::{Arc, Weak};
// use alloc::vec;
// use alloc::vec::Vec;
// use core::cell::{Ref, RefMut};
// use core::fmt::Display;
// use riscv::interrupt::Trap;
// #[derive(Copy, Clone, PartialEq, Eq, Debug)]

// pub enum TaskState {
//     //if it is ready,it means the program has not been run
//     Ready = 1,
//     Running = 2,
//     Suspended = 3,
//     Exited = 4,
// }
// impl Display for TaskState {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         let state_str = match self {
//             TaskState::Ready => "Ready",
//             TaskState::Running => "Running",
//             TaskState::Suspended => "Suspended",
//             TaskState::Exited => "Exited",
//         };
//         write!(f, "{}", state_str)
//     }
// }

// pub struct TaskBlock {
//     pub pid: Pid,
//     pub task_name: [u8; 32],

//     // we hold this.. just because for RAII
//     pub kernel_stack: KernelStack,
//     // becuase we will use arc in the future, so if we want to change we need to use the Refcell
//     task_block_inner: RefCellSafe<TaskBlockInner>,
// }
// pub struct TaskBlockInner {
//     pub state: TaskState,

//     // we just need task context for a task... trap context is held in the user space..
//     pub task_context: TaskContext,
//     pub code_memory_set: MemorySet,
//     // becuase now the trap context is stored in the user memoryspace so we need to
//     // store an adress here to make sure we can pass it to the restore
//     // when we exit the trap handler...
//     pub trap_context_loc: PhysPageNum,
//     pub children_task: Vec<Arc<TaskBlock>>,
//     pub father_task: Option<Weak<TaskBlock>>,
//     pub exit_code: i32,
//     pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
//     //siganl
//     pub signals: SignalFlags,
//     pub signal_mask: SignalFlags,
//     pub signal_actions: SignalActions,
//     // this is used to work with the the signal handling
//     pub killed: bool,
//     pub frozen: bool,
//     pub handling_signal: isize,
//     pub trap_ctx_backup: Option<TrapContext>,
// }
// impl TaskBlockInner {
//     pub fn alloc_fd(&mut self) -> usize {
//         if let Some(fd) = (0..self.fd_table.len()).find(|&fd| self.fd_table[fd].is_none()) {
//             fd
//         } else {
//             self.fd_table.push(None);
//             self.fd_table.len() - 1
//         }
//     }
// }
// impl TaskBlock {
//     pub fn new_raw() -> Self {
//         Self {
//             kernel_stack: KernelStack::new(99),
//             pid: Pid(99),
//             task_name: [0; 32],
//             task_block_inner: RefCellSafe::new(TaskBlockInner {
//                 task_context: TaskContext::new(),
//                 state: TaskState::Exited,
//                 code_memory_set: MemorySet::new_bare(),
//                 trap_context_loc: PhysPageNum(0),
//                 children_task: Vec::new(),
//                 father_task: None,
//                 exit_code: 0,
//                 fd_table: Vec::new(),
//                 frozen: false,
//                 killed: false,
//                 signals: SignalFlags::empty(),
//                 signal_mask: SignalFlags::empty(),
//                 signal_actions: SignalActions::default(),
//                 handling_signal: -1,
//                 trap_ctx_backup: None,
//             }),
//         }
//     }
//     pub fn get_inner(&self) -> RefMut<'_, TaskBlockInner> {
//         self.task_block_inner.borrow_mut()
//     }
//     // todo:the code below create the signal_task on the stack and move ,which will cause problem
//     //maybe.  maybe we need to  solve this..
//     pub fn new(elf_data: &[u8], app_name: usize) -> Self {
//         // unsafe {
//         //     let task_name_array =
//         //     let app_code = core::slice::from_raw_parts(app_start as *const u8, app_end - app_start);

//         // }
//         // let trap_context_ptr = KERNEL_STACK[no].push_trap_context(
//         //     crate::trap::context::TrapContext::app_init_context(
//         //         the_code_start(no),
//         //         USER_STACK[no].top(),
//         //     ),
//         // );
//         //get pid
//         let pid = alloc_pid();
//         let (mem_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
//         // already insert the trampolitan area in memset so we only need to insert data;
//         let kernel_stack = KernelStack::new(pid.0);
//         let kernel_stack_top = kernel_stack.kernel_stack_top;
//         let trap_page = mem_set
//             .translate(VirtAddr::from(TRAP_CONTEXT).into())
//             .unwrap()
//             .ppn();
//         // todo : make sure the top is what we want;
//         // todo: draw a picture here.
//         let token = KERNEL_SPACE.borrow().token();
//         let trap_context = crate::trap::context::TrapContext::app_init_context(
//             entry_point,
//             user_sp,
//             token,
//             kernel_stack.kernel_stack_top,
//             trap_handler as usize,
//         );

//         let trap_context_ref: &mut TrapContext = trap_page.get_mut();
//         *trap_context_ref = trap_context;

//         unsafe {
//             let _app_name: [u8; 32] = *(app_name as *const [u8; 32]);

//             let mut result = Self {
//                 pid,
//                 task_name: _app_name,

//                 kernel_stack,
//                 // fill this later
//                 task_block_inner: RefCellSafe::new(TaskBlockInner {
//                     task_context: TaskContext::set_for_app(trap_return as usize, kernel_stack_top),
//                     state: TaskState::Ready,
//                     code_memory_set: mem_set,
//                     trap_context_loc: trap_page,
//                     father_task: None,
//                     children_task: Vec::new(),
//                     exit_code: 0,
//                     fd_table: vec![
//                         Some(Arc::new(Stdin)),
//                         // 1 -> stdout
//                         Some(Arc::new(Stdout)),
//                         // 2 -> stderr
//                         Some(Arc::new(Stdout)),
//                     ],
//                     frozen: false,
//                     killed: false,
//                     signals: SignalFlags::empty(),
//                     signal_mask: SignalFlags::empty(),
//                     signal_actions: SignalActions::default(),
//                     handling_signal: -1,
//                     trap_ctx_backup: None,
//                 }),
//             }; // set user stack pointer
//             result
//         }
//     }
//     // ...existing code...
//     pub fn exec(&self, name: usize, args: Vec<String>) -> Result<(), &'static str> {
//         unsafe extern "C" {
//             fn num_user_apps();
//         }
//         let number_of_apps = unsafe { *(num_user_apps as *const i64) } as usize;
//         let start_loc = (num_user_apps as usize) + core::mem::size_of::<usize>();
//         let elf_data = get_app_data_by_name(name, number_of_apps, start_loc);
//         let (mem_set, mut user_sp, entry_point) = MemorySet::from_elf(&elf_data);
//         let kernel_stack_top = self.kernel_stack.kernel_stack_top;
//         let trap_page = mem_set
//             .translate(VirtAddr::from(TRAP_CONTEXT).into())
//             .ok_or("ERROR while get trap context")?
//             .ppn();

//         // push arguments on user stack
//         user_sp -= (args.len() + 1) * core::mem::size_of::<usize>();
//         let argv_base = user_sp;
//         let mut argv: Vec<*mut usize> = (0..=args.len())
//             .map(|arg| {
//                 translated_single_address(
//                     mem_set.token(),
//                     (argv_base + arg * core::mem::size_of::<usize>()) as *const u8,
//                 ) as *mut u8 as *mut usize
//             })
//             .collect();
//         unsafe {
//             *argv[args.len()] = 0;
//         }
//         for i in 0..args.len() {
//             user_sp -= args[i].len() + 1;
//             unsafe {
//                 *argv[i] = user_sp;
//             }
//             let mut p = user_sp;
//             for c in args[i].as_bytes() {
//                 *translated_single_address(mem_set.token(), p as *mut u8) = *c;
//                 p += 1;
//             }
//             *translated_single_address(mem_set.token(), p as *mut u8) = 0;
//         }
//         // make the user_sp aligned to 8B for k210 platform
//         user_sp -= user_sp % core::mem::size_of::<usize>();

//         self.get_inner().code_memory_set = mem_set;
//         let token = KERNEL_SPACE.borrow().token();
//         let mut trap_context = crate::trap::context::TrapContext::app_init_context(
//             entry_point,
//             user_sp,
//             token,
//             kernel_stack_top,
//             trap_handler as usize,
//         );

//         trap_context.x[10] = args.len(); // a0 = argc
//         trap_context.x[11] = argv_base; // a1 = argv

//         let trap_context_ref: &mut TrapContext = trap_page.get_mut();
//         *trap_context_ref = trap_context;
//         self.get_inner().trap_context_loc = trap_page;
//         self.get_inner().task_context =
//             TaskContext::set_for_app(trap_return as usize, kernel_stack_top);
//         // self.get_inner().state = TaskState::Ready; // 确保任务准备运行
//         Ok(())
//     }
//     // ...existing code...
//     pub fn fork(now_task_block: Arc<TaskBlock>) -> Arc<TaskBlock> {
//         let child_pid = alloc_pid();
//         let kernel_stack = KernelStack::new(child_pid.0);
//         let kernel_stack_top = kernel_stack.kernel_stack_top;
//         let mem_set = now_task_block.get_inner().code_memory_set.clone(); // todo: clone the memory set
//         // attention: we dont need to manually initialize the trap context it should be done
//         // in the prior clone. since the trap context is stored in the user space
//         // correct:we still need to change the trap_context's kernel_sp to the new one
//         // and return value register
//         let trap_page = mem_set
//             .translate(VirtAddr::from(TRAP_CONTEXT).into())
//             .unwrap()
//             .ppn();

//         let mut now_task_block_inner = now_task_block.get_inner();

//         let mut result = Self {
//             pid: child_pid,
//             task_name: now_task_block.task_name,

//             kernel_stack,
//             // fill this later
//             //todo there are some error!!
//             task_block_inner: RefCellSafe::new(TaskBlockInner {
//                 task_context: TaskContext::set_for_app(trap_return as usize, kernel_stack_top),
//                 state: TaskState::Ready,
//                 code_memory_set: mem_set,
//                 trap_context_loc: trap_page,
//                 father_task: Some(Arc::downgrade(&now_task_block)),
//                 children_task: Vec::new(),
//                 exit_code: 0,
//                 fd_table: now_task_block_inner
//                     .fd_table
//                     .iter()
//                     .map(|fd_option| fd_option.as_ref().map(|fd| Arc::clone(fd)))
//                     .collect(),
//                 frozen: false,
//                 killed: false,
//                 signals: now_task_block_inner.signals,
//                 signal_mask: now_task_block_inner.signal_mask,
//                 signal_actions: SignalActions::default(),
//                 handling_signal: -1,
//                 trap_ctx_backup: None,
//             }),
//         }; // set user stack pointer

//         // we need to change the kernel stack here...
//         let trap_context_ref: &mut TrapContext = trap_page.get_mut();
//         trap_context_ref.kernel_sp = kernel_stack_top;
//         trap_context_ref.x[10] = 0; // Child process return value

//         let target_arc = Arc::new(result);

//         now_task_block_inner.children_task.push(target_arc.clone());
//         drop(now_task_block_inner);
//         target_arc
//     }
//     pub fn alloc_fd(&self) -> usize {
//         let mut inner_block = self.get_inner();
//         if let Some(fd) =
//             (0..inner_block.fd_table.len()).find(|&fd| inner_block.fd_table[fd].is_none())
//         {
//             fd
//         } else {
//             inner_block.fd_table.push(None);
//             inner_block.fd_table.len() - 1
//         }
//     }
// }
// // impl Display for TaskBlock {
// //     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
// //         let name_end = self
// //             .task_name
// //             .iter()
// //             .position(|&c| c == 0)
// //             .unwrap_or(self.task_name.len());
// //         // .asciz makes sure there is a null terminator
// //         let name_str = core::str::from_utf8(&self.task_name[..name_end]).unwrap_or("Invalid UTF-8");
// //         write!(
// //             f,
// //             "TaskBlock {{ name: {}, state: {:?}}}",
// //             name_str, self.state,
// //         )
// //     }
// // }

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
    pub cpu_time_ns: u64,
    /// Per-thread nice value (Linux/NPTL semantics).
    pub nice: i32,
    /// Hint that libc just queried self priority and may issue `nice()`.
    pub nice_query_hint: bool,
    /// Saved user floating-point registers (`f0..f31`) for context switches.
    pub fp_regs: [u64; 32],
    /// Saved floating-point control/status register.
    pub fp_fcsr: u32,
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

impl TaskControlBlock {
    pub fn try_new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Option<Self> {
        let res = TaskUserRes::try_new(Arc::clone(&process), ustack_base, alloc_user_res)?;
        let trap_cx_ppn = res.trap_cx_ppn();
        let kstack = kstack_alloc()?;
        let kstack_top = kstack.get_top();
        let process_nice = {
            let inner = process.borrow_mut();
            inner.nice
        };
        Some(Self {
            process: Arc::downgrade(&process),
            kstack: Mutex::new(Some(kstack)),
            cpu_id: AtomicUsize::new(0),
            on_cpu: AtomicUsize::new(Self::OFF_CPU),
            wakeup_pending: AtomicBool::new(false),
            in_ready_queue: AtomicBool::new(false),
            inner: Mutex::new(TaskControlBlockInner {
                res: Some(res),
                trap_cx_ppn,
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
                nice: process_nice,
                nice_query_hint: false,
                fp_regs: [0; 32],
                fp_fcsr: 0,
                fp_valid: false,
            }),
        })
        .map(|tcb| {
            TASK_TCB_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            maybe_log_tcb_inflight("alloc");
            tcb
        })
    }

    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        Self::try_new(process, ustack_base, alloc_user_res).expect("OOM: TaskControlBlock::new")
    }

    // Debug output
    // use crate::println;
    // println!(
    //     "[DEBUG] TaskControlBlock::new - trap_return={:#x}, kstack_top={:#x}, trap_cx_ppn={:#x}",
    //     trap_return as usize, kstack_top, trap_cx_ppn.0
    // );

    pub fn try_new_linux_thread(process: Arc<ProcessControlBlock>) -> Option<Self> {
        let res = TaskUserRes::try_new_trap_cx_only(Arc::clone(&process))?;
        let trap_cx_ppn = res.trap_cx_ppn();
        let kstack = kstack_alloc()?;
        let kstack_top = kstack.get_top();
        let process_nice = {
            let inner = process.borrow_mut();
            inner.nice
        };
        Some(Self {
            process: Arc::downgrade(&process),
            kstack: Mutex::new(Some(kstack)),
            cpu_id: AtomicUsize::new(0),
            on_cpu: AtomicUsize::new(Self::OFF_CPU),
            wakeup_pending: AtomicBool::new(false),
            in_ready_queue: AtomicBool::new(false),
            inner: Mutex::new(TaskControlBlockInner {
                res: Some(res),
                trap_cx_ppn,
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
                nice: process_nice,
                nice_query_hint: false,
                fp_regs: [0; 32],
                fp_fcsr: 0,
                fp_valid: false,
            }),
        })
        .map(|tcb| {
            TASK_TCB_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            maybe_log_tcb_inflight("alloc");
            tcb
        })
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

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum TaskStatus {
    Ready,
    Running,
    Blocked,
}
