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
        let tasks = pcb.indexed_tasks_snapshot();
        let Some(process_inner) = pcb.try_borrow_mut() else {
            log::warn!("[watchdog] pid={} pcb_lock=BUSY", pid);
            continue;
        };
        log::warn!(
            "[watchdog] pid={} zombie={} tasks_len={} children_len={} sems_len={}",
            pid,
            process_inner.is_zombie,
            tasks.len(),
            process_inner.children.len(),
            process_inner.semaphore_list.len()
        );
        let semaphores = process_inner
            .semaphore_list
            .iter()
            .enumerate()
            .filter_map(|(sid, sem)| sem.as_ref().cloned().map(|sem| (sid, sem)))
            .collect::<alloc::vec::Vec<_>>();
        let mutex_ids = process_inner
            .mutex_list
            .iter()
            .enumerate()
            .filter_map(|(mid, mutex)| mutex.is_some().then_some(mid))
            .collect::<alloc::vec::Vec<_>>();
        drop(process_inner);
        // 任务
        for (tid, tcb) in tasks {
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
        // 信号量
        for (sid, sem) in semaphores {
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
        for mid in mutex_ids {
            log::warn!("[watchdog]  mutex[{}]=Some(..)", mid);
        }
    }
    drop(map);
    log::warn!("==== [watchdog] end ====");
    arch::restore_interrupts(prev_sie);
}
