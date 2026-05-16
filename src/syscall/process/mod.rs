mod exec;
mod fork;
mod wait;

pub use exec::*;
pub use fork::*;
pub use wait::*;

use crate::syscall::error::{SyscallError, err};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{
    mem::size_of,
    sync::atomic::{AtomicUsize, Ordering},
};
use lazy_static::lazy_static;
use spin::{Mutex, MutexGuard};

use crate::{
    arch::{REG_A0, REG_SP, REG_TP},
    debug_config::{DEBUG_EXEC, DEBUG_FUTEX, DEBUG_PTHREAD, DEBUG_SIGNAL},
    fs::{
        PidFdFile, cgroup_attach_thread, cgroup_current_path, cgroup_fork_precheck, ext4_lock,
        root_inode_for_path, secondary_root_inode,
    },
    mm::{
        MapPermission, MemorySet, kernel_token, try_read_user_value, try_write_user_value,
        write_user_value,
    },
    println,
    syscall::{
        filesystem::{
            normalize_path, resolve_exec_inode, resolve_exec_inode_at, resolve_read_inode,
        },
        misc::encode_linux_tid,
        signal::{ERESTARTSYS, SA_RESTART},
    },
    task::{
        ProcessControlBlock,
        manager::{
            PID2PCB, add_task, pid2process, remove_inactive_task, select_hart_for_new_task,
            wakeup_task,
        },
        processor::{
            block_current_and_run_next, current_files, current_process, current_task, hart_id,
            suspend_current_and_run_next,
        },
        sched::{SchedClass, sched_class},
        signal::{
            RT_SIG_MAX, SIG_DFL, SIG_IGN, SIGCHLD_NUM, SIGKILL_NUM, SIGSTOP_NUM,
            pending_unmasked_bits, queue_process_signal, sig_default_interrupts_wait,
        },
        task_block::{TaskControlBlock, TaskStatus},
    },
    trap::{get_current_token, trap_handler},
};

lazy_static! {
    static ref EXECUTING_INODES: Mutex<BTreeMap<(usize, u32), usize>> = Mutex::new(BTreeMap::new());
}

pub(crate) type ExecutingInodesGuard = MutexGuard<'static, BTreeMap<(usize, u32), usize>>;

#[allow(clippy::type_complexity)]
pub(super) fn debug_task_ref_breakdown(
    task: &alloc::sync::Arc<TaskControlBlock>,
) -> (
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) {
    let runqueue_refs = crate::task::manager::debug_count_task_refs_in_runqueues(task);
    let processor_refs = crate::task::processor::debug_count_task_refs_in_processors(task);
    let timer_refs = crate::task::block_sleep::debug_count_task_refs_in_timers(task);
    let futex_refs = crate::syscall::futex::debug_count_task_waiters(task);
    let record_lock_refs =
        crate::syscall::filesystem::debug_count_record_lock_waiters_for_task(task);

    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut task_slot_refs = 0usize;
    let mut wait_queue_refs = 0usize;
    let mut join_waiter_refs = 0usize;
    let mut sem_waiter_refs = 0usize;
    let mut condvar_waiter_refs = 0usize;
    let mut mutex_waiter_refs = 0usize;
    for process in processes {
        let inner = process.borrow_mut();
        task_slot_refs = task_slot_refs.saturating_add(
            inner
                .tasks
                .iter()
                .filter(|slot| {
                    slot.as_ref()
                        .map(|holder| alloc::sync::Arc::ptr_eq(holder, task))
                        .unwrap_or(false)
                })
                .count(),
        );
        wait_queue_refs = wait_queue_refs.saturating_add(
            inner
                .wait_queue
                .iter()
                .filter(|holder| alloc::sync::Arc::ptr_eq(holder, task))
                .count(),
        );
        for holder in inner.tasks.iter().filter_map(|slot| slot.as_ref()) {
            if let Some(holder_inner) = holder.try_borrow_mut() {
                join_waiter_refs = join_waiter_refs.saturating_add(
                    holder_inner
                        .join_waiters
                        .iter()
                        .filter(|w| alloc::sync::Arc::ptr_eq(w, task))
                        .count(),
                );
            }
        }
        for sem in inner.semaphore_list.iter().filter_map(|s| s.as_ref()) {
            sem_waiter_refs = sem_waiter_refs.saturating_add(
                sem.inner
                    .lock()
                    .wait_queue
                    .iter()
                    .filter(|w| alloc::sync::Arc::ptr_eq(w, task))
                    .count(),
            );
        }
        for condvar in inner.condvar_list.iter().filter_map(|c| c.as_ref()) {
            condvar_waiter_refs = condvar_waiter_refs.saturating_add(
                condvar
                    .inner
                    .lock()
                    .wait_queue
                    .iter()
                    .filter(|w| alloc::sync::Arc::ptr_eq(w, task))
                    .count(),
            );
        }
        for mutex in inner.mutex_list.iter().filter_map(|m| m.as_ref()) {
            mutex_waiter_refs =
                mutex_waiter_refs.saturating_add(mutex.debug_count_waiters_for_task(task));
        }
    }
    let pipe_waiter_refs = crate::fs::debug_count_pipe_waiters_for_task(task);

    (
        runqueue_refs,
        processor_refs,
        timer_refs,
        futex_refs,
        record_lock_refs,
        task_slot_refs,
        wait_queue_refs,
        join_waiter_refs,
        sem_waiter_refs
            .saturating_add(condvar_waiter_refs)
            .saturating_add(mutex_waiter_refs),
        pipe_waiter_refs,
    )
}

#[allow(dead_code)]
pub(crate) fn is_inode_currently_executed(device_id: usize, inode_num: u32) -> bool {
    if device_id == 0 && inode_num == 0 {
        return false;
    }
    let guard = lock_executing_inodes();
    is_inode_currently_executed_locked(&guard, device_id, inode_num)
}

pub(crate) fn lock_executing_inodes() -> ExecutingInodesGuard {
    EXECUTING_INODES.lock()
}

pub(crate) fn is_inode_currently_executed_locked(
    guard: &ExecutingInodesGuard,
    device_id: usize,
    inode_num: u32,
) -> bool {
    guard.get(&(device_id, inode_num)).copied().unwrap_or(0) > 0
}

pub(crate) fn register_executing_inode(dev: usize, ino: u32) {
    let mut guard = lock_executing_inodes();
    register_executing_inode_locked(&mut guard, dev, ino);
}

pub(crate) fn unregister_executing_inode(dev: usize, ino: u32) {
    let mut guard = lock_executing_inodes();
    unregister_executing_inode_locked(&mut guard, dev, ino);
}

pub(crate) fn register_executing_inode_locked(
    guard: &mut ExecutingInodesGuard,
    dev: usize,
    ino: u32,
) {
    if dev != 0 || ino != 0 {
        let count = guard.entry((dev, ino)).or_insert(0);
        *count = count.saturating_add(1);
    }
}

pub(crate) fn unregister_executing_inode_locked(
    guard: &mut ExecutingInodesGuard,
    dev: usize,
    ino: u32,
) {
    if dev != 0 || ino != 0 {
        if let Some(count) = guard.get_mut(&(dev, ino)) {
            if *count > 1 {
                *count -= 1;
            } else {
                guard.remove(&(dev, ino));
            }
        }
    }
}

pub(super) fn try_read_usize_user(token: usize, ptr: usize) -> Result<usize, isize> {
    try_read_user_value(token, ptr as *const usize).ok_or(err(SyscallError::EFAULT))
}

pub(super) fn try_read_user_cstr(token: usize, ptr: usize) -> Result<String, isize> {
    const MAX_USER_CSTR: usize = 256 * 1024;
    let mut s = String::new();
    for i in 0..MAX_USER_CSTR {
        let ch =
            try_read_user_value(token, (ptr + i) as *const u8).ok_or(err(SyscallError::EFAULT))?;
        if ch == 0 {
            return Ok(s);
        }
        s.push(ch as char);
    }
    Err(err(SyscallError::ENAMETOOLONG))
}

pub(super) fn read_user_str_array(token: usize, vec_ptr: usize) -> Result<Vec<String>, isize> {
    let mut out = Vec::new();
    if vec_ptr == 0 {
        return Ok(out);
    }
    for i in 0..4096usize {
        let p = try_read_usize_user(token, vec_ptr + i * size_of::<usize>())?;
        if p == 0 {
            return Ok(out);
        }
        out.push(try_read_user_cstr(token, p)?);
    }
    Err(err(SyscallError::E2BIG))
}
