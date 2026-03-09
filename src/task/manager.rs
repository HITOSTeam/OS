use alloc::collections::binary_heap::BinaryHeap;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use lazy_static::*;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch;
use crate::config::MAX_HARTS;
use crate::debug_config::DEBUG_SCHED;
use crate::task::block_sleep::{TIMERS, TimeWrap};
use crate::task::process_block::ProcessControlBlock;
use crate::task::sched::{
    RT_PRIO_LEVELS, RT_PRIO_MAX, RT_PRIO_MIN, SchedClass, rt_queue_index, sched_class,
};
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use spin::Mutex;

static NEXT_HART: AtomicUsize = AtomicUsize::new(0);
static ONLINE_HART_MASK: AtomicUsize = AtomicUsize::new(0);

pub fn mark_hart_online(hart_id: usize) {
    if hart_id < usize::BITS as usize {
        ONLINE_HART_MASK.fetch_or(1usize << hart_id, Ordering::SeqCst);
    }
}

fn online_hart_mask() -> usize {
    let mask = ONLINE_HART_MASK.load(Ordering::Acquire);
    // Fallback: at least hart0 exists.
    if mask == 0 { 1 } else { mask }
}

fn pick_online_hart(start: usize) -> usize {
    let mask = online_hart_mask();
    for i in 0..MAX_HARTS {
        let cand = (start + i) % MAX_HARTS;
        if (mask & (1usize << cand)) != 0 {
            return cand;
        }
    }
    0
}

pub fn select_hart_for_new_task() -> usize {
    let start = NEXT_HART.fetch_add(1, Ordering::Relaxed) % MAX_HARTS;
    pick_online_hart(start)
}

pub fn dump_system_state() {
    log::warn!("==== [watchdog] system state dump ====");
    let mgr = TASK_MANAGER.lock();
    let total_ready: usize = mgr.ready_queues.iter().map(HartRunQueue::len).sum();
    log::warn!(
        "[watchdog] ready_queues_total_len={} per_hart={:?}",
        total_ready,
        mgr.ready_queues
            .iter()
            .map(HartRunQueue::len)
            .collect::<alloc::vec::Vec<_>>()
    );
    drop(mgr);
    let map = PID2PCB.lock();
    for (pid, pcb) in map.iter() {
        let Some(process_inner) = pcb.try_borrow_mut() else {
            log::warn!("[watchdog] pid={} pcb_lock=BUSY", pid);
            continue;
        };
        log::warn!(
            "[watchdog] pid={} zombie={} tasks_len={} children_len={} sems_len={}",
            pid,
            process_inner.is_zombie,
            process_inner.tasks.len(),
            process_inner.children.len(),
            process_inner.semaphore_list.len()
        );
        // Tasks
        for (tid, t) in process_inner.tasks.iter().enumerate() {
            let Some(tcb) = t else { continue };
            let on_cpu = tcb.on_cpu.load(core::sync::atomic::Ordering::Acquire);
            let in_rq = tcb
                .in_ready_queue
                .load(core::sync::atomic::Ordering::Acquire);
            let wp = tcb
                .wakeup_pending
                .load(core::sync::atomic::Ordering::Acquire);
            let (status, exit_code) = if let Some(g) = tcb.try_borrow_mut() {
                (Some(g.task_status), g.exit_code)
            } else {
                (None, None)
            };
            log::warn!(
                "[watchdog]  tid={} status={:?} on_cpu={} in_rq={} wakeup_pending={} exit_code={:?}",
                tid,
                status,
                on_cpu,
                in_rq,
                wp,
                exit_code
            );
        }
        // Semaphores
        for (sid, sem) in process_inner.semaphore_list.iter().enumerate() {
            let Some(sem) = sem else { continue };
            let Some(guard) = sem.inner.try_lock() else {
                log::warn!("[watchdog]  sem[{}] lock=BUSY", sid);
                continue;
            };
            log::warn!(
                "[watchdog]  sem[{}] count={} waiters={}",
                sid,
                guard.count,
                guard.wait_queue.len()
            );
        }
        // Mutexes
        for (mid, m) in process_inner.mutex_list.iter().enumerate() {
            if m.is_some() {
                log::warn!("[watchdog]  mutex[{}]=Some(..)", mid);
            }
        }
        drop(process_inner);
    }
    drop(map);
    log::warn!("==== [watchdog] end ====");
}

#[derive(Default)]
struct HartRunQueue {
    rt_queues: alloc::vec::Vec<VecDeque<Arc<TaskControlBlock>>>,
    fair_queue: VecDeque<Arc<TaskControlBlock>>,
}

impl HartRunQueue {
    fn new() -> Self {
        Self {
            rt_queues: (0..RT_PRIO_LEVELS).map(|_| VecDeque::new()).collect(),
            fair_queue: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.fair_queue.len() + self.rt_queues.iter().map(VecDeque::len).sum::<usize>()
    }
}

enum ReadyQueueSlot {
    Rt(usize),
    Fair,
}

fn task_queue_slot(task: &Arc<TaskControlBlock>) -> ReadyQueueSlot {
    let Some(process) = task.process.upgrade() else {
        return ReadyQueueSlot::Fair;
    };
    let (policy, rt_priority) = {
        let inner = process.borrow_mut();
        (inner.sched_policy, inner.sched_priority)
    };
    match sched_class(policy) {
        Some(SchedClass::Fifo) | Some(SchedClass::Rr) => {
            ReadyQueueSlot::Rt(rt_queue_index(rt_priority))
        }
        Some(SchedClass::Fair) | None => ReadyQueueSlot::Fair,
    }
}

pub struct TaskManager {
    ready_queues: alloc::vec::Vec<HartRunQueue>,
}

fn resolve_enqueue_hart(task: &Arc<TaskControlBlock>, current_hart: usize, mask: usize) -> usize {
    let desired = task.get_cpu_id() % MAX_HARTS;
    if (mask & (1usize << desired)) != 0 {
        desired
    } else if (mask & (1usize << current_hart)) != 0 {
        task.set_cpu_id(current_hart);
        current_hart
    } else {
        let picked = pick_online_hart(0);
        task.set_cpu_id(picked);
        picked
    }
}

/// A Linux-like split runqueue: RT queues + a fair queue.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queues: (0..MAX_HARTS).map(|_| HartRunQueue::new()).collect(),
        }
    }
    pub fn add(&mut self, task: Arc<TaskControlBlock>, hart_id: usize) -> bool {
        // Avoid enqueueing the same task multiple times under SMP.
        if task
            .in_ready_queue
            .swap(true, core::sync::atomic::Ordering::AcqRel)
        {
            return false;
        }
        let hart_rq = &mut self.ready_queues[hart_id];
        let was_empty = hart_rq.len() == 0;
        if DEBUG_SCHED {
            let tid = task
                .borrow_mut()
                .res
                .as_ref()
                .map(|r| r.tid)
                .unwrap_or(usize::MAX);
            log::debug!(
                "[sched] add_task tid={} hart={} ready_queue_len_before={}",
                tid,
                hart_id,
                hart_rq.len()
            );
        }
        match task_queue_slot(&task) {
            ReadyQueueSlot::Rt(idx) => hart_rq.rt_queues[idx].push_back(task),
            ReadyQueueSlot::Fair => hart_rq.fair_queue.push_back(task),
        }
        if DEBUG_SCHED {
            log::debug!(
                "[sched] hart={} ready_queue_len_after={}",
                hart_id,
                hart_rq.len()
            );
        }
        was_empty
    }

    fn pop_ready_candidate(
        queue: &mut VecDeque<Arc<TaskControlBlock>>,
        hart_id: usize,
    ) -> Option<Arc<TaskControlBlock>> {
        while let Some(candidate) = queue.pop_front() {
            candidate
                .in_ready_queue
                .store(false, core::sync::atomic::Ordering::Release);
            let status = candidate.borrow_mut().task_status;
            if status == TaskStatus::Ready {
                return Some(candidate);
            }
            if DEBUG_SCHED {
                let tid = candidate
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                log::debug!(
                    "[sched] drop stale entry tid={} hart={} status={:?} remaining_len={}",
                    tid,
                    hart_id,
                    status,
                    queue.len()
                );
            }
        }
        None
    }

    pub fn fetch(&mut self, hart_id: usize) -> Option<Arc<TaskControlBlock>> {
        // Skip stale entries: under SMP, bugs or races can temporarily leave
        // non-ready tasks (Blocked/Running) in the ready queue. Never schedule them.
        let t = {
            let rq = &mut self.ready_queues[hart_id];
            let mut picked = None;
            for rtq in rq.rt_queues.iter_mut() {
                if let Some(task) = Self::pop_ready_candidate(rtq, hart_id) {
                    picked = Some(task);
                    break;
                }
            }
            if picked.is_none() {
                picked = Self::pop_ready_candidate(&mut rq.fair_queue, hart_id);
            }
            picked
        };
        if DEBUG_SCHED {
            if let Some(ref task) = t {
                let tid = task
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                log::debug!(
                    "[sched] hart={} fetch_task -> Some(tid={}) remaining_len={}",
                    hart_id,
                    tid,
                    self.ready_queues[hart_id].len()
                );
            }
        }
        t
    }
    pub fn remove(&mut self, task: Arc<TaskControlBlock>) {
        let mut removed = 0usize;
        for rq in self.ready_queues.iter_mut() {
            for q in rq
                .rt_queues
                .iter_mut()
                .chain(core::iter::once(&mut rq.fair_queue))
            {
                let before = q.len();
                q.retain(|t| !Arc::ptr_eq(t, &task));
                removed = removed.saturating_add(before.saturating_sub(q.len()));
            }
        }
        if crate::debug_config::DEBUG_TASK_LIFECYCLE && removed > 1 {
            let tid = task
                .borrow_mut()
                .res
                .as_ref()
                .map(|r| r.tid)
                .unwrap_or(usize::MAX);
            crate::println!("[sched-remove] tid={} removed_dup_entries={}", tid, removed);
        }
        task.in_ready_queue
            .store(false, core::sync::atomic::Ordering::Release);
    }

    pub fn ready_queue_lengths(&self) -> alloc::vec::Vec<usize> {
        self.ready_queues.iter().map(HartRunQueue::len).collect()
    }

    fn debug_count_task_refs(&self, task: &Arc<TaskControlBlock>) -> usize {
        self.ready_queues
            .iter()
            .map(|rq| {
                rq.fair_queue
                    .iter()
                    .filter(|t| Arc::ptr_eq(t, task))
                    .count()
                    + rq.rt_queues
                        .iter()
                        .map(|q| q.iter().filter(|t| Arc::ptr_eq(t, task)).count())
                        .sum::<usize>()
            })
            .sum()
    }

    fn has_ready_rt_higher_than(&self, hart_id: usize, priority: i32) -> bool {
        let rq = &self.ready_queues[hart_id];
        let prio = priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX);
        let idx = rt_queue_index(prio);
        rq.rt_queues[..idx].iter().any(|q| !q.is_empty())
    }

    fn has_ready_rt_at_or_above(&self, hart_id: usize, priority: i32) -> bool {
        let rq = &self.ready_queues[hart_id];
        let prio = priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX);
        let idx = rt_queue_index(prio);
        rq.rt_queues[..=idx].iter().any(|q| !q.is_empty())
    }
}

lazy_static! {
    pub static ref TASK_MANAGER: Mutex<TaskManager> = Mutex::new(TaskManager::new());
    pub static ref PID2PCB: Mutex<BTreeMap<usize, Arc<ProcessControlBlock>>> =
        Mutex::new(BTreeMap::new());
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    // Protect the ready queue from timer interrupt re-entrancy, but restore the previous SIE state.
    let prev_sie = arch::disable_interrupts();
    let mask = online_hart_mask();
    let cur = crate::task::processor::hart_id() % MAX_HARTS;
    let hart_id = resolve_enqueue_hart(&task, cur, mask);
    let was_empty = TASK_MANAGER.lock().add(task, hart_id);
    // Linux-style: if we queued to a remote hart, kick it out of `wfi` via IPI.
    // For fork storms this avoids flooding remote harts with redundant IPIs when
    // their runqueue is already non-empty.
    if cur < MAX_HARTS && cur != hart_id && was_empty {
        arch::send_ipi(hart_id);
    }
    arch::restore_interrupts(prev_sie);
}

/// Requeue runnable threads after policy/priority/nice changes.
pub fn refresh_process_runqueues(process: &Arc<ProcessControlBlock>) {
    let tasks = {
        let inner = process.borrow_mut();
        inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<alloc::vec::Vec<_>>()
    };
    if tasks.is_empty() {
        return;
    }
    let prev_sie = arch::disable_interrupts();
    let cur = crate::task::processor::hart_id() % MAX_HARTS;
    let mask = online_hart_mask();
    let mut mgr = TASK_MANAGER.lock();
    for task in tasks {
        if !task
            .in_ready_queue
            .load(core::sync::atomic::Ordering::Acquire)
        {
            continue;
        }
        mgr.remove(Arc::clone(&task));
        let hart_id = resolve_enqueue_hart(&task, cur, mask);
        let _ = mgr.add(task, hart_id);
    }
    arch::restore_interrupts(prev_sie);
}

pub fn wakeup_task(task: Arc<TaskControlBlock>) {
    fn wake_if_blocked(task: Arc<TaskControlBlock>) {
        let mut task_inner = task.borrow_mut();
        if task_inner.res.is_none() {
            return;
        }
        if task_inner.task_status == TaskStatus::Blocked {
            if task_inner.cgroup_frozen {
                task_inner.wake_on_cgroup_thaw = true;
                task.wakeup_pending
                    .store(false, core::sync::atomic::Ordering::Release);
                return;
            }
            task_inner.task_status = TaskStatus::Ready;
            task_inner.parked_by_cgroup = false;
            task_inner.wake_on_cgroup_thaw = false;
            task.wakeup_pending
                .store(false, core::sync::atomic::Ordering::Release);
            drop(task_inner);
            add_task(task);
        }
    }

    // SMP safety: if the task is truly still executing on some hart, do not enqueue it
    // (it would race on the same kernel stack). Instead mark a pending wakeup and let
    // that hart enqueue the task after it has switched back to idle.
    //
    // Important: handle the tiny window where a waker observes `on_cpu != OFF_CPU`,
    // sets `wakeup_pending`, but the task clears `on_cpu` and checks `wakeup_pending`
    // just before this store becomes visible. To avoid losing the wakeup, re-check
    // `on_cpu` after setting the flag and enqueue immediately if it is already off-cpu.
    if task.on_cpu.load(core::sync::atomic::Ordering::Acquire) != TaskControlBlock::OFF_CPU {
        task.wakeup_pending
            .store(true, core::sync::atomic::Ordering::Release);
        if task.on_cpu.load(core::sync::atomic::Ordering::Acquire) == TaskControlBlock::OFF_CPU {
            wake_if_blocked(task);
        }
        return;
    }

    wake_if_blocked(task);
}

pub fn remove_task(task: Arc<TaskControlBlock>) {
    let prev_sie = arch::disable_interrupts();
    TASK_MANAGER.lock().remove(task);
    arch::restore_interrupts(prev_sie);
}

pub fn debug_count_task_refs_in_runqueues(task: &Arc<TaskControlBlock>) -> usize {
    let prev_sie = arch::disable_interrupts();
    let count = TASK_MANAGER.lock().debug_count_task_refs(task);
    arch::restore_interrupts(prev_sie);
    count
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id();
    let t = TASK_MANAGER.lock().fetch(hart_id);
    arch::restore_interrupts(prev_sie);
    t
}

pub fn has_ready_rt_higher_than(priority: i32) -> bool {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id();
    let ready = TASK_MANAGER
        .lock()
        .has_ready_rt_higher_than(hart_id, priority);
    arch::restore_interrupts(prev_sie);
    ready
}

pub fn has_ready_rt_at_or_above(priority: i32) -> bool {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id();
    let ready = TASK_MANAGER
        .lock()
        .has_ready_rt_at_or_above(hart_id, priority);
    arch::restore_interrupts(prev_sie);
    ready
}

pub fn pid2process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let map = PID2PCB.lock();
    map.get(&pid).map(Arc::clone)
}

pub fn insert_into_pid2process(pid: usize, process: Arc<ProcessControlBlock>) {
    let mut map = PID2PCB.lock();
    map.insert(pid, process);
    let len = map.len();
    if crate::debug_config::DEBUG_PID_MAP && len >= 64 && (len & (len - 1)) == 0 {
        crate::println!("[pid-debug] insert pid={} map_len={}", pid, len);
    }
}

pub fn remove_from_pid2process(pid: usize) {
    let mut map = PID2PCB.lock();
    if map.remove(&pid).is_none() {
        panic!("cannot find pid {} in pid2task!", pid);
    }
    let len = map.len();
    if crate::debug_config::DEBUG_PID_MAP && len >= 64 && (len & (len - 1)) == 0 {
        crate::println!("[pid-debug] remove pid={} map_len={}", pid, len);
    }
}

pub fn remove_timer(task: Arc<TaskControlBlock>) {
    let mut timers = TIMERS.lock();
    let mut temp = BinaryHeap::<TimeWrap>::new();
    for condvar in timers.drain() {
        if Arc::as_ptr(&task) != Arc::as_ptr(&condvar.task) {
            temp.push(condvar);
        }
    }
    timers.clear();
    timers.append(&mut temp);
}

pub fn remove_inactive_task(task: Arc<TaskControlBlock>) {
    // 这里可能会加入 todo
    crate::syscall::futex::remove_futex_waiters(&task);
    crate::task::process_block::remove_task_from_wait_queues(&task);
    remove_timer(task.clone());
    remove_task(task.clone());
}
