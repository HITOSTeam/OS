use alloc::collections::binary_heap::BinaryHeap;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use lazy_static::*;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch;
use crate::debug_config::DEBUG_SCHED;
use crate::config::MAX_HARTS;
use crate::task::block_sleep::{TIMERS, TimeWrap};
use crate::task::process_block::ProcessControlBlock;
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
    let total_ready: usize = mgr.ready_queues.iter().map(|q| q.len()).sum();
    log::warn!(
        "[watchdog] ready_queues_total_len={} per_hart={:?}",
        total_ready,
        mgr.ready_queues.iter().map(|q| q.len()).collect::<alloc::vec::Vec<_>>()
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

pub struct TaskManager {
    ready_queues: alloc::vec::Vec<VecDeque<Arc<TaskControlBlock>>>,
}

/// A simple FIFO scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queues: (0..MAX_HARTS).map(|_| VecDeque::new()).collect(),
        }
    }
    pub fn add(&mut self, task: Arc<TaskControlBlock>, hart_id: usize) {
        // Avoid enqueueing the same task multiple times under SMP.
        if task
            .in_ready_queue
            .swap(true, core::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
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
                self.ready_queues[hart_id].len()
            );
        }
        self.ready_queues[hart_id].push_back(task);
        if DEBUG_SCHED {
            log::debug!(
                "[sched] hart={} ready_queue_len_after={}",
                hart_id,
                self.ready_queues[hart_id].len()
            );
        }
    }
    pub fn fetch(&mut self, hart_id: usize) -> Option<Arc<TaskControlBlock>> {
        // Skip stale entries: under SMP, bugs or races can temporarily leave
        // non-ready tasks (Blocked/Running) in the ready queue. Never schedule them.
        let mut t = None;
        while let Some(candidate) = self.ready_queues[hart_id].pop_front() {
            candidate
                .in_ready_queue
                .store(false, core::sync::atomic::Ordering::Release);
            let status = candidate.borrow_mut().task_status;
            if status == TaskStatus::Ready {
                t = Some(candidate);
                break;
            } else if DEBUG_SCHED {
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
                    self.ready_queues[hart_id].len()
                );
            }
        }
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
        for q in self.ready_queues.iter_mut() {
            if let Some((id, _)) = q
                .iter()
                .enumerate()
                .find(|(_, t)| Arc::as_ptr(t) == Arc::as_ptr(&task))
            {
                q.remove(id);
                break;
            }
        }
        task.in_ready_queue
            .store(false, core::sync::atomic::Ordering::Release);
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
    let desired = task.get_cpu_id() % MAX_HARTS;
    let mask = online_hart_mask();
    let cur = crate::task::processor::hart_id() % MAX_HARTS;
    let hart_id = if (mask & (1usize << desired)) != 0 {
        desired
    } else if (mask & (1usize << cur)) != 0 {
        // If the preferred hart is offline, run it where we are.
        task.set_cpu_id(cur);
        cur
    } else {
        // Last resort: pick any online hart.
        let picked = pick_online_hart(0);
        task.set_cpu_id(picked);
        picked
    };
    TASK_MANAGER.lock().add(task, hart_id);
    // Linux-style: if we queued to a remote hart, kick it out of `wfi` via IPI.
    if cur < MAX_HARTS && cur != hart_id {
        arch::send_ipi(hart_id);
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
            task_inner.task_status = TaskStatus::Ready;
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

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    let prev_sie = arch::disable_interrupts();
    let hart_id = crate::task::processor::hart_id();
    let t = TASK_MANAGER.lock().fetch(hart_id);
    arch::restore_interrupts(prev_sie);
    t
}

pub fn pid2process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let map = PID2PCB.lock();
    map.get(&pid).map(Arc::clone)
}

pub fn insert_into_pid2process(pid: usize, process: Arc<ProcessControlBlock>) {
    PID2PCB.lock().insert(pid, process);
}

pub fn remove_from_pid2process(pid: usize) {
    let mut map = PID2PCB.lock();
    if map.remove(&pid).is_none() {
        panic!("cannot find pid {} in pid2task!", pid);
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
    remove_timer(task.clone());
    remove_task(task.clone());
}
