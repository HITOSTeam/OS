use alloc::{collections::BTreeSet, sync::Arc, sync::Weak, vec::Vec};

use crate::{
    config::{
        KERNEL_STACK_SIZE, KERNEL_STACK_TOP, MAX_HARTS, PAGE_SIZE, TRAP_CONTEXT_BASE,
        USER_STACK_SIZE,
    },
    mm::{KERNEL_SPACE, MapPermission, MmRef, PhysPageNum, VirtAddr},
    task::{lazy_static, process_block::ProcessControlBlock},
    utils::RecycleAllocator,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

const PID_MAX_DEFAULT: usize = 32768;
const PID_MAX_MIN: usize = 2;
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
    pid_max.clamp(PID_MAX_MIN, PID_MAX_HARD_LIMIT)
}

fn maybe_log_pid_active(event: &str, len: usize) {
    if !crate::debug_config::DEBUG_PID_MAP {
        return;
    }
    if len >= 64 && (len & (len - 1)) == 0 {
        crate::println!("[pid-active] event={} active={}", event, len);
    }
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

    fn alloc(&mut self) -> Option<usize> {
        let pid_max = pid_max();
        if self.next >= pid_max {
            self.next = 1;
        }

        for _ in 0..pid_max {
            let pid = self.next;
            self.next = if pid + 1 >= pid_max { 1 } else { pid + 1 };
            if self.active.insert(pid) {
                maybe_log_pid_active("alloc", self.active.len());
                return Some(pid);
            }
        }

        None
    }

    fn dealloc(&mut self, pid: usize) {
        if !self.active.remove(&pid) {
            log::warn!("pid {} double-dealloc (already freed)", pid);
            return;
        }
        maybe_log_pid_active("dealloc", self.active.len());
    }
}

lazy_static! {
    static ref PID_ALLOCATOR: Mutex<PidAllocator> = Mutex::new(PidAllocator::new());
}

pub struct PidHandle(pub usize);

/// Reason why PID allocation failed.
#[derive(Debug, Clone, Copy)]
pub enum PidAllocError {
    /// All PIDs in [0, pid_max) are currently in use.
    Exhausted,
}

pub fn pid_max() -> usize {
    clamp_pid_max(PID_MAX_VALUE.load(Ordering::Relaxed))
}

pub fn pid_max_bounds() -> (usize, usize) {
    (PID_MAX_MIN, PID_MAX_HARD_LIMIT)
}

pub fn set_pid_max(pid_max: usize) -> usize {
    let clamped = clamp_pid_max(pid_max);
    PID_MAX_VALUE.store(clamped, Ordering::Relaxed);
    clamped
}

pub fn pid_alloc() -> Result<PidHandle, PidAllocError> {
    PID_ALLOCATOR
        .lock()
        .alloc()
        .map(PidHandle)
        .ok_or(PidAllocError::Exhausted)
}

impl Drop for PidHandle {
    fn drop(&mut self) {
        PID_ALLOCATOR.lock().dealloc(self.0);
    }
}
/// Aggregate equivalent of Linux's two cached VMAP stacks per CPU.
///
/// The cache is shared because CongCore has no NUMA placement to preserve. Its
/// fixed budget retains at most 512 KiB on an 8-hart RISC-V release build and
/// 768 KiB on a 12-hart LoongArch release build.
const KSTACK_CACHE_MAX: usize = MAX_HARTS * 2;

lazy_static! {
    static ref KSTACK_ALLOCATOR: Mutex<RecycleAllocator> = Mutex::new(RecycleAllocator::new());
    /// Free kernel stacks whose high-half mappings remain installed.
    ///
    /// Linux caches VMAP stacks in `kernel/fork.c` so normal thread churn does
    /// not repeatedly modify kernel page tables. Retaining a bounded set here
    /// gives the same steady-state property: only growth beyond the cache's
    /// mapped high-water mark needs a shared-kernel TLB shootdown.
    static ref KSTACK_CACHE: Mutex<Vec<usize>> = Mutex::new(Vec::new());
}
pub struct KernelStack(pub usize);

impl KernelStack {
    pub fn get_top(&self) -> usize {
        let (_, kernel_stack_top) = kernel_stack_position(self.0);
        kernel_stack_top
    }

    pub fn bounds(&self) -> (usize, usize) {
        kernel_stack_position(self.0)
    }
}
/// Return (bottom, top) of a kernel stack in kernel space.
pub fn kernel_stack_position(kstack_id: usize) -> (usize, usize) {
    let top = KERNEL_STACK_TOP - kstack_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    (bottom, top)
}

pub fn kstack_alloc() -> Option<KernelStack> {
    // End the cache-lock scope before clearing the retained stack. Clearing is
    // bounded but still touches every stack page and must not serialize other
    // harts trying to return or acquire a cached ID.
    let cached_kstack_id = KSTACK_CACHE.lock().pop();
    if let Some(kstack_id) = cached_kstack_id {
        let (kstack_bottom, _) = kernel_stack_position(kstack_id);
        // Linux clears a cached VMAP stack before assigning it to a new task.
        // SAFETY: a cached ID is no longer owned by a task, its complete stack
        // range remains mapped writable, and the cache lock transfers unique
        // ownership of this ID to the caller before the bytes are cleared.
        unsafe {
            core::ptr::write_bytes(kstack_bottom as *mut u8, 0, KERNEL_STACK_SIZE);
        }
        crate::perf::record_kstack_reuse();
        KSTACK_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        maybe_log_kstack_inflight("alloc");
        return Some(KernelStack(kstack_id));
    }
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
    // Kernel stacks live in the shared high-half page table. A user-ASID
    // invalidation batch cannot publish this new mapping to harts currently
    // running with the LoongArch kernel PGDH/ASID 0 (and the same distinction
    // applies to RISC-V global kernel mappings). Match the removal path and
    // complete a shared-kernel shootdown before the stack can be scheduled.
    // Only reached when the live-thread high-water mark grows, not per thread.
    crate::perf::record_kstack_map();
    crate::mm::flush_kernel_shared_tlb();
    KSTACK_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    maybe_log_kstack_inflight("alloc");
    Some(KernelStack(kstack_id))
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        KSTACK_DROP_COUNT.fetch_add(1, Ordering::Relaxed);
        maybe_log_kstack_inflight("drop");
        // Keep the mapping installed while the bounded cache has room. A
        // failed metadata allocation simply falls back to the ordinary unmap.
        {
            let mut cache = KSTACK_CACHE.lock();
            if cache.len() < KSTACK_CACHE_MAX && cache.try_reserve(1).is_ok() {
                cache.push(self.0);
                return;
            }
        }
        let (kernel_stack_bottom, kernel_stack_top) = self.bounds();
        let kernel_stack_bottom_va: VirtAddr = kernel_stack_bottom.into();
        let kernel_stack_top_va: VirtAddr = kernel_stack_top.into();
        crate::perf::record_kstack_unmap();
        KERNEL_SPACE
            .lock()
            .remove_area(kernel_stack_bottom_va.into(), kernel_stack_top_va.into());
        // MemorySet::remove_area completes the architecture-specific shared
        // kernel shootdown before releasing the stack frames.
        KSTACK_ALLOCATOR.lock().dealloc(self.0);
    }
}

///THREAD USER RESOURCES
pub struct TaskUserRes {
    pub tid: usize,
    trap_cx_slot: usize,
    pub ustack_base: usize,
    pub process: Weak<ProcessControlBlock>,
    memory_set: MmRef,
    owns_ustack: bool,
    ustack_mapped: bool,
    trap_cx_mapped: bool,
    trap_cx_slot_reserved: bool,
    live_thread_registered: bool,
}

/// Delays the live-thread release until the exiting task is no longer current
/// and has been detached from scheduler/user-visible per-thread state.
///
/// Linux elects the final process teardown only after the task has crossed its
/// common exit point.  Keeping this ticket separate from `TaskUserRes` lets us
/// unmap trap/user resources first without making another hart believe the
/// complete thread has already retired.
#[must_use]
pub struct LiveThreadRetirement {
    process: Weak<ProcessControlBlock>,
    registered: bool,
}

impl LiveThreadRetirement {
    pub fn retire(mut self) -> bool {
        if !core::mem::take(&mut self.registered) {
            return false;
        }
        self.process
            .upgrade()
            .map(|process| process.unregister_live_thread())
            .unwrap_or(true)
    }
}

impl Drop for LiveThreadRetirement {
    fn drop(&mut self) {
        if self.registered {
            if let Some(process) = self.process.upgrade() {
                let _ = process.unregister_live_thread();
            }
            self.registered = false;
        }
    }
}

// Trap contexts live in per-mm slots near the top of user VA. The slot is
// intentionally separate from per-PCB tid so future non-thread CLONE_VM tasks
// can share one mm without colliding at tid 0.
fn trap_cx_bottom_from_slot(slot: usize) -> usize {
    TRAP_CONTEXT_BASE - slot * PAGE_SIZE
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
        let (tid, memory_set) = {
            let mut process_inner = process.borrow_mut();
            (process_inner.alloc_tid(), process_inner.memory_set.clone())
        };
        let trap_cx_slot = if alloc_user_res {
            memory_set.alloc_trap_context_slot()
        } else {
            memory_set.reserve_trap_context_slot(tid);
            tid
        };
        let mut task_user_res = Self {
            tid,
            trap_cx_slot,
            ustack_base,
            process: Arc::downgrade(&process),
            memory_set,
            owns_ustack: true,
            // `from_elf` and fork already contain the main task's mappings
            // when `alloc_user_res` is false.
            ustack_mapped: !alloc_user_res,
            trap_cx_mapped: !alloc_user_res,
            trap_cx_slot_reserved: true,
            live_thread_registered: false,
        };
        if alloc_user_res && !task_user_res.try_alloc_user_res() {
            return None;
        }
        process.register_live_thread();
        task_user_res.live_thread_registered = true;
        Some(task_user_res)
    }

    pub fn try_new_trap_cx_only(process: Arc<ProcessControlBlock>) -> Option<Self> {
        let (tid, memory_set) = {
            let mut process_inner = process.borrow_mut();
            (process_inner.alloc_tid(), process_inner.memory_set.clone())
        };
        let trap_cx_slot = memory_set.alloc_trap_context_slot();
        let mut task_user_res = Self {
            tid,
            trap_cx_slot,
            ustack_base: 0,
            process: Arc::downgrade(&process),
            memory_set,
            owns_ustack: false,
            ustack_mapped: false,
            trap_cx_mapped: false,
            trap_cx_slot_reserved: true,
            live_thread_registered: false,
        };
        if !task_user_res.try_alloc_trap_cx_only() {
            return None;
        }
        process.register_live_thread();
        task_user_res.live_thread_registered = true;
        Some(task_user_res)
    }

    fn try_alloc_trap_cx_only(&mut self) -> bool {
        let trap_cx_bottom = trap_cx_bottom_from_slot(self.trap_cx_slot);
        let trap_cx_top = trap_cx_bottom + PAGE_SIZE;
        self.trap_cx_mapped = self.memory_set.try_insert_framed_area(
            trap_cx_bottom.into(),
            trap_cx_top.into(),
            MapPermission::R | MapPermission::W,
        );
        self.trap_cx_mapped
    }

    // 具体的 插入 用户资源 ,如 用户栈 和 trap_cx
    pub fn alloc_user_res(&mut self) {
        assert!(
            self.try_alloc_user_res(),
            "OOM: TaskUserRes::alloc_user_res"
        );
    }

    fn try_alloc_user_res(&mut self) -> bool {
        if self.owns_ustack {
            // alloc user stack
            let ustack_bottom = ustack_bottom_from_tid(self.ustack_base, self.tid);
            let ustack_top = ustack_bottom + USER_STACK_SIZE;
            // insert the user resource into the program memory space
            if !self.memory_set.try_insert_stack_framed_range(
                ustack_bottom,
                ustack_top,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ) {
                return false;
            }
            self.ustack_mapped = true;
        }
        // alloc trap_cx
        // if trap alloc failed,we will remove the user_stack too
        let trap_cx_bottom = trap_cx_bottom_from_slot(self.trap_cx_slot);
        let trap_cx_top = trap_cx_bottom + PAGE_SIZE;
        if !self.memory_set.try_insert_framed_area(
            trap_cx_bottom.into(),
            trap_cx_top.into(),
            MapPermission::R | MapPermission::W,
        ) {
            if self.owns_ustack {
                let ustack_bottom = ustack_bottom_from_tid(self.ustack_base, self.tid);
                let ustack_top = ustack_bottom + USER_STACK_SIZE;
                self.memory_set
                    .unmap_user_vma_range(ustack_bottom.into(), ustack_top.into());
                self.ustack_mapped = false;
            }
            return false;
        }
        self.trap_cx_mapped = true;
        true
    }

    fn dealloc_user_res(&mut self) {
        if self.ustack_mapped {
            // dealloc ustack manually
            let ustack_bottom = ustack_bottom_from_tid(self.ustack_base, self.tid);
            let ustack_top = ustack_bottom + USER_STACK_SIZE;
            self.memory_set
                .unmap_user_vma_range(ustack_bottom.into(), ustack_top.into());
            self.ustack_mapped = false;
        }
        // dealloc trap_cx manually
        if self.trap_cx_mapped {
            let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_slot(self.trap_cx_slot).into();
            self.memory_set
                .remove_area_with_start_vpn(trap_cx_bottom_va.into());
            self.trap_cx_mapped = false;
        }
        if self.trap_cx_slot_reserved {
            self.memory_set.dealloc_trap_context_slot(self.trap_cx_slot);
            self.trap_cx_slot_reserved = false;
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
        trap_cx_bottom_from_slot(self.trap_cx_slot)
    }

    pub fn trap_cx_ppn(&self) -> PhysPageNum {
        let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_slot(self.trap_cx_slot).into();
        self.memory_set
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

    pub fn trap_cx_slot(&self) -> usize {
        self.trap_cx_slot
    }

    pub fn memory_set(&self) -> MmRef {
        self.memory_set.clone()
    }

    pub fn reset_for_exec(&mut self, ustack_base: usize, memory_set: MmRef) -> MmRef {
        // After de-threading, the exec caller becomes the sole thread-group
        // leader. The old address space (including its old TID-indexed
        // resources) is about to be discarded.
        self.tid = 0;
        self.trap_cx_slot = 0;
        self.ustack_base = ustack_base;
        let old_memory_set = core::mem::replace(&mut self.memory_set, memory_set);
        self.owns_ustack = true;
        self.ustack_mapped = true;
        self.trap_cx_mapped = true;
        self.trap_cx_slot_reserved = true;
        old_memory_set
    }

    /// Whether this thread uses a user-managed stack (Linux CLONE_VM threads do).
    pub fn is_linux_thread(&self) -> bool {
        !self.owns_ustack
    }

    /// Finish one task's user-resource teardown and elect the thread that may
    /// perform process-wide cleanup.
    ///
    /// `drop_user_stack == false` is used for a process leader whose stack VMA
    /// may still be visible through another PCB sharing this mm.  Trap state is
    /// always task-private and must be removed before the live-thread release.
    pub fn finish_thread_exit(mut self, drop_user_stack: bool) -> LiveThreadRetirement {
        if !drop_user_stack {
            self.ustack_mapped = false;
        }
        self.dealloc_user_res();
        let retirement = LiveThreadRetirement {
            process: self.process.clone(),
            registered: core::mem::take(&mut self.live_thread_registered),
        };
        // Run TaskUserRes::drop (including TID release) before publishing the
        // live-thread retirement. The flag was moved into `retirement`, so the
        // fallback Drop path cannot decrement the counter twice.
        drop(self);
        retirement
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
        if self.live_thread_registered {
            if let Some(process) = self.process.upgrade() {
                let _ = process.unregister_live_thread();
            }
            self.live_thread_registered = false;
        }
    }
}
