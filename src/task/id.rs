use alloc::{collections::BTreeSet, sync::Arc, sync::Weak};

use crate::{
    config::{KERNEL_STACK_SIZE, PAGE_SIZE, TRAMPOLINE, TRAP_CONTEXT_BASE, USER_STACK_SIZE},
    mm::{KERNEL_SPACE, MapPermission, PhysPageNum, VirtAddr},
    task::{lazy_static, process_block::ProcessControlBlock},
    utils::RecycleAllocator,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

const PID_MAX_DEFAULT: usize = 32768;
const PID_MAX_HARD_LIMIT: usize = 4 * 1024 * 1024;

static PID_MAX_VALUE: AtomicUsize = AtomicUsize::new(PID_MAX_DEFAULT);
static KSTACK_ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static KSTACK_DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

fn maybe_log_kstack_inflight(event: &str) {
    if !crate::debug_config::DEBUG_TASK_LIFECYCLE {
        return;
    }
    let allocs = KSTACK_ALLOC_COUNT.load(Ordering::Relaxed);
    let drops = KSTACK_DROP_COUNT.load(Ordering::Relaxed);
    let inflight = allocs.saturating_sub(drops);
    if inflight >= 64 && (inflight & (inflight - 1)) == 0 {
        crate::println!(
            "[kstack-debug] event={} inflight={} allocs={} drops={}",
            event,
            inflight,
            allocs,
            drops
        );
    }
}

fn clamp_pid_max(pid_max: usize) -> usize {
    pid_max.clamp(2, PID_MAX_HARD_LIMIT)
}

struct PidAllocator {
    next: usize,
    active: BTreeSet<usize>,
}

impl PidAllocator {
    fn new() -> Self {
        Self {
            // Keep pid=0 for the bootstrap task, then rotate in [1, pid_max).
            next: 0,
            active: BTreeSet::new(),
        }
    }

    fn alloc(&mut self) -> usize {
        let pid_max = pid_max();
        if self.next >= pid_max {
            self.next = 1;
        }

        for _ in 0..pid_max {
            let pid = self.next;
            self.next = if pid + 1 >= pid_max { 1 } else { pid + 1 };
            if self.active.insert(pid) {
                return pid;
            }
        }

        panic!("pid allocator exhausted (pid_max={pid_max})");
    }

    fn dealloc(&mut self, pid: usize) {
        assert!(self.active.remove(&pid), "pid {pid} has been deallocated!");
    }
}

lazy_static! {
    static ref PID_ALLOCATOR: Mutex<PidAllocator> = Mutex::new(PidAllocator::new());
}

pub struct PidHandle(pub usize);

pub fn pid_max() -> usize {
    clamp_pid_max(PID_MAX_VALUE.load(Ordering::Relaxed))
}

pub fn set_pid_max(pid_max: usize) -> usize {
    let clamped = clamp_pid_max(pid_max);
    PID_MAX_VALUE.store(clamped, Ordering::Relaxed);
    clamped
}

pub fn pid_alloc() -> PidHandle {
    PidHandle(PID_ALLOCATOR.lock().alloc())
}

impl Drop for PidHandle {
    fn drop(&mut self) {
        PID_ALLOCATOR.lock().dealloc(self.0);
    }
}
lazy_static! {
    static ref KSTACK_ALLOCATOR: Mutex<RecycleAllocator> = Mutex::new(RecycleAllocator::new());
}
pub struct KernelStack(pub usize);

impl KernelStack {
    pub fn get_top(&self) -> usize {
        let (_, kernel_stack_top) = kernel_stack_position(self.0);
        kernel_stack_top
    }
}
/// Return (bottom, top) of a kernel stack in kernel space.
pub fn kernel_stack_position(kstack_id: usize) -> (usize, usize) {
    #[cfg(target_arch = "loongarch64")]
    let top = crate::config::KERNEL_STACK_TOP - kstack_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    #[cfg(not(target_arch = "loongarch64"))]
    let top = TRAMPOLINE - kstack_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    (bottom, top)
}

pub fn kstack_alloc() -> Option<KernelStack> {
    let kstack_id = KSTACK_ALLOCATOR.lock().alloc();
    let (kstack_bottom, kstack_top) = kernel_stack_position(kstack_id);
    let ok = KERNEL_SPACE.lock().try_insert_framed_area(
        kstack_bottom.into(),
        kstack_top.into(),
        MapPermission::R | MapPermission::W,
    );
    if !ok {
        KSTACK_ALLOCATOR.lock().dealloc(kstack_id);
        return None;
    }
    KSTACK_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    maybe_log_kstack_inflight("alloc");
    Some(KernelStack(kstack_id))
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        let (kernel_stack_bottom, kernel_stack_top) = kernel_stack_position(self.0);
        let kernel_stack_bottom_va: VirtAddr = kernel_stack_bottom.into();
        let kernel_stack_top_va: VirtAddr = kernel_stack_top.into();
        KERNEL_SPACE
            .lock()
            .remove_area(kernel_stack_bottom_va.into(), kernel_stack_top_va.into());
        KSTACK_ALLOCATOR.lock().dealloc(self.0);
        KSTACK_DROP_COUNT.fetch_add(1, Ordering::Relaxed);
        maybe_log_kstack_inflight("drop");
    }
}

//THREAD USER RESOURCES
pub struct TaskUserRes {
    pub tid: usize,
    pub ustack_base: usize,
    pub process: Weak<ProcessControlBlock>,
    owns_ustack: bool,
}

// 现在 顶部映射的 有多个 trap_cx , 每个线程一个
fn trap_cx_bottom_from_tid(tid: usize) -> usize {
    TRAP_CONTEXT_BASE - tid * PAGE_SIZE
}

// 用户占 也有多份
fn ustack_bottom_from_tid(ustack_base: usize, tid: usize) -> usize {
    ustack_base + tid * (PAGE_SIZE + USER_STACK_SIZE)
}
impl TaskUserRes {
    /// 在创建线程时调用, 分配 tid, 并根据 alloc_user_res 决定是否分配用户资源
    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        Self::try_new(process, ustack_base, alloc_user_res).expect("OOM: TaskUserRes::new")
    }

    /// Allocate only a per-thread TrapContext page (no kernel-managed user stack).
    ///
    /// This is used to host Linux/glibc `clone(CLONE_VM|...)` threads whose stacks are
    /// allocated by userspace via `mmap`.
    pub fn new_trap_cx_only(process: Arc<ProcessControlBlock>) -> Self {
        Self::try_new_trap_cx_only(process).expect("OOM: TaskUserRes::new_trap_cx_only")
    }

    pub fn try_new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Option<Self> {
        let tid = process.borrow_mut().alloc_tid();
        let task_user_res = Self {
            tid,
            ustack_base,
            process: Arc::downgrade(&process),
            owns_ustack: true,
        };
        if alloc_user_res && !task_user_res.try_alloc_user_res() {
            return None;
        }
        Some(task_user_res)
    }

    pub fn try_new_trap_cx_only(process: Arc<ProcessControlBlock>) -> Option<Self> {
        let tid = process.borrow_mut().alloc_tid();
        let task_user_res = Self {
            tid,
            ustack_base: 0,
            process: Arc::downgrade(&process),
            owns_ustack: false,
        };
        if !task_user_res.try_alloc_trap_cx_only() {
            return None;
        }
        Some(task_user_res)
    }

    fn try_alloc_trap_cx_only(&self) -> bool {
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.borrow_mut();
        let trap_cx_bottom = trap_cx_bottom_from_tid(self.tid);
        let trap_cx_top = trap_cx_bottom + PAGE_SIZE;
        process_inner.memory_set.try_insert_framed_area(
            trap_cx_bottom.into(),
            trap_cx_top.into(),
            MapPermission::R | MapPermission::W,
        )
    }

    // 具体的 插入 用户资源 ,如 用户栈 和 trap_cx
    pub fn alloc_user_res(&self) {
        assert!(
            self.try_alloc_user_res(),
            "OOM: TaskUserRes::alloc_user_res"
        );
    }

    fn try_alloc_user_res(&self) -> bool {
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.borrow_mut();
        if self.owns_ustack {
            // alloc user stack
            let ustack_bottom = ustack_bottom_from_tid(self.ustack_base, self.tid);
            let ustack_top = ustack_bottom + USER_STACK_SIZE;
            // insert the user resource into the program memory space
            if !process_inner.memory_set.try_insert_framed_area(
                ustack_bottom.into(),
                ustack_top.into(),
                MapPermission::R | MapPermission::W | MapPermission::U,
            ) {
                return false;
            }
        }
        // alloc trap_cx
        let trap_cx_bottom = trap_cx_bottom_from_tid(self.tid);
        let trap_cx_top = trap_cx_bottom + PAGE_SIZE;
        if !process_inner.memory_set.try_insert_framed_area(
            trap_cx_bottom.into(),
            trap_cx_top.into(),
            MapPermission::R | MapPermission::W,
        ) {
            if self.owns_ustack {
                let ustack_bottom_va: VirtAddr =
                    ustack_bottom_from_tid(self.ustack_base, self.tid).into();
                process_inner
                    .memory_set
                    .remove_area_with_start_vpn(ustack_bottom_va.into());
            }
            return false;
        }
        true
    }

    fn dealloc_user_res(&self) {
        // dealloc tid
        let Some(process) = self.process.upgrade() else {
            return;
        };
        let mut process_inner = process.borrow_mut();
        if self.owns_ustack {
            // dealloc ustack manually
            let ustack_bottom_va: VirtAddr =
                ustack_bottom_from_tid(self.ustack_base, self.tid).into();
            process_inner
                .memory_set
                .remove_area_with_start_vpn(ustack_bottom_va.into());
        }
        // dealloc trap_cx manually
        let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid).into();
        process_inner
            .memory_set
            .remove_area_with_start_vpn(trap_cx_bottom_va.into());
    }

    #[allow(unused)]
    pub fn alloc_tid(&mut self) {
        if let Some(process) = self.process.upgrade() {
            self.tid = process.borrow_mut().alloc_tid();
        }
    }

    pub fn dealloc_tid(&self) {
        let Some(process) = self.process.upgrade() else {
            return;
        };
        let mut process_inner = process.borrow_mut();
        process_inner.dealloc_tid(self.tid);
    }

    pub fn trap_cx_user_va(&self) -> usize {
        trap_cx_bottom_from_tid(self.tid)
    }

    pub fn trap_cx_ppn(&self) -> PhysPageNum {
        let process = self.process.upgrade().expect("process already dropped");
        let process_inner = process.borrow_mut();
        let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid).into();
        process_inner
            .memory_set
            .translate(trap_cx_bottom_va.into())
            .unwrap()
            .ppn()
    }

    pub fn ustack_base(&self) -> usize {
        self.ustack_base
    }
    pub fn ustack_top(&self) -> usize {
        ustack_bottom_from_tid(self.ustack_base, self.tid) + USER_STACK_SIZE
    }

    /// Whether this thread uses a user-managed stack (Linux CLONE_VM threads do).
    pub fn is_linux_thread(&self) -> bool {
        !self.owns_ustack
    }
}

impl Drop for TaskUserRes {
    fn drop(&mut self) {
        // IMPORTANT: unmap user resources before releasing tid back to the allocator.
        // Otherwise, another thread may reuse the same tid and try to map the same
        // ustack/trap_cx region while it is still mapped, causing a "vpn is mapped"
        // panic (or worse, use-after-unmap).
        self.dealloc_user_res();
        self.dealloc_tid();
    }
}
