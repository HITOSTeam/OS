use crate::arch;

use super::{PID2PCB, ready_queue_lengths};

/// 看门狗（watchdog）系统状态转储：打印所有 hart 的就绪队列长度、每个进程的线程/信号量/互斥锁状态
pub fn dump_system_state() {
    log::warn!("==== [watchdog] system state dump ====");
    // 关闭中断，防止与 timer 驱动的 wakeup_task() 死锁。
    let prev_sie = arch::disable_interrupts();
    let lens = ready_queue_lengths();
    let total_ready: usize = lens.iter().sum();
    log::warn!(
        "[watchdog] ready_queues_total_len={} per_hart={:?}",
        total_ready,
        lens
    );
    let map = PID2PCB.lock();
    for (pid, pcb) in map.iter() {
        let Some(process_inner) = pcb.try_borrow_mut() else {
            log::warn!("[watchdog] pid={} pcb_lock=BUSY", pid);
            continue;
        };
        log::warn!(
            "[watchdog] pid={} zombie={} tasks_len={} children_len={} exited_children_len={} waiters={} vfork_waiters={} sems_len={}",
            pid,
            process_inner.is_zombie,
            process_inner.tasks.len(),
            process_inner.children.len(),
            process_inner.exited_children.len(),
            process_inner.wait_queue.len(),
            process_inner.vfork_wait_queue.len(),
            process_inner.semaphore_list.len()
        );
        // 任务
        for (tid, t) in process_inner.tasks.iter().enumerate() {
            let Some(tcb) = t else { continue };
            let on_cpu = tcb.on_cpu.load(core::sync::atomic::Ordering::Acquire);
            let in_rq = tcb
                .in_ready_queue
                .load(core::sync::atomic::Ordering::Acquire);
            let ready_hart = tcb
                .ready_queue_hart
                .load(core::sync::atomic::Ordering::Acquire);
            let wp = tcb
                .wakeup_pending
                .load(core::sync::atomic::Ordering::Acquire);
            let (status, exit_code, has_res, pending, mask, last_syscall) =
                if let Some(g) = tcb.try_borrow_mut() {
                    (
                        Some(g.task_status),
                        g.exit_code,
                        Some(g.res.is_some()),
                        Some(g.pending_signals),
                        Some(g.signal_mask),
                        g.last_syscall_valid
                            .then_some((g.last_syscall_id, g.last_syscall_args)),
                    )
                } else {
                    (None, None, None, None, None, None)
                };
            log::warn!(
                "[watchdog]  tid={} status={:?} res={:?} on_cpu={} ready_hart={} in_rq={} wakeup_pending={} exec={} retired={} exit_code={:?} pending={:?} mask={:?} last_syscall={:?}",
                tid,
                status,
                has_res,
                on_cpu,
                ready_hart,
                in_rq,
                wp,
                tcb.exec_exit_requested(),
                tcb.exit_lifecycle_retired(),
                exit_code,
                pending,
                mask,
                last_syscall
            );
        }
        // 信号量
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
        // 互斥锁
        for (mid, m) in process_inner.mutex_list.iter().enumerate() {
            if m.is_some() {
                log::warn!("[watchdog]  mutex[{}]=Some(..)", mid);
            }
        }
        drop(process_inner);
    }
    drop(map);
    log::warn!("==== [watchdog] end ====");
    arch::restore_interrupts(prev_sie);
}
