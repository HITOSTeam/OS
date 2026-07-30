mod exec;
mod fork;
mod wait;

pub use exec::*;
pub use fork::*;
pub use wait::*;

use crate::syscall::error::{SyscallError, err};
use alloc::{string::String, vec::Vec};
use core::{
    mem::size_of,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    arch::{REG_A0, REG_SP, REG_TP},
    debug_config::{DEBUG_EXEC, DEBUG_FUTEX, DEBUG_PTHREAD, DEBUG_SIGNAL},
    fs::{
        CgroupAttachTarget, PidFdFile, cgroup_attach_process_to_target, cgroup_attach_thread,
        cgroup_clone_into_target_from_file, cgroup_current_path, cgroup_fork_precheck, ext4_lock,
        fanotify_notify_open_exec, fanotify_permission_open,
        refresh_thread_legacy_cpu_fair_group_cache, root_inode_for_path, secondary_root_inode,
    },
    mm::{
        MapPermission, MemorySet, kernel_token, try_copy_from_user, try_read_user_value,
        try_write_user_value, write_user_value,
    },
    println,
    syscall::{
        filesystem::{
            AT_FDCWD, normalize_path, resolve_abs_path, resolve_exec_inode, resolve_exec_inode_at,
            resolve_read_inode,
        },
        misc::encode_linux_tid,
        signal::{ERESTARTSYS, SA_RESTART},
    },
    task::{
        ProcessControlBlock,
        manager::{
            PID2PCB, add_task, pid2process, register_shared_mm_process_owner, remove_inactive_task,
            remove_sched_timer_refs, select_hart_for_new_task, wakeup_task,
        },
        processor::{
            block_current_and_run_next, current_files, current_files_and_nofile_limit,
            current_process, current_task,
        },
        signal::{
            RT_SIG_MAX, SIG_DFL, SIG_IGN, SIGCHLD_NUM, SIGKILL_NUM, SIGSTOP_NUM,
            pending_unmasked_bits, queue_process_signal, sig_default_interrupts_wait,
        },
        task_block::{TaskControlBlock, TaskStatus},
    },
    trap::{get_current_token, trap_handler},
};

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
        let tasks = process.tasks_snapshot();
        task_slot_refs = task_slot_refs.saturating_add(
            tasks
                .iter()
                .filter(|holder| alloc::sync::Arc::ptr_eq(holder, task))
                .count(),
        );
        for holder in &tasks {
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
        let inner = process.borrow_mut();
        wait_queue_refs = wait_queue_refs.saturating_add(
            inner
                .wait_queue
                .iter()
                .filter(|holder| alloc::sync::Arc::ptr_eq(holder, task))
                .count(),
        );
        // vfork waiters hold task Arcs just like wait4 waiters, so include
        // them in leak/refcount diagnostics before blaming scheduler queues.
        wait_queue_refs = wait_queue_refs.saturating_add(
            inner
                .vfork_wait_queue
                .iter()
                .filter(|holder| alloc::sync::Arc::ptr_eq(holder, task))
                .count(),
        );
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
    crate::fs::is_inode_currently_executed(device_id, inode_num)
}

pub(crate) fn register_executing_inode(dev: usize, ino: u32) {
    crate::fs::register_executing_inode(dev, ino);
}

pub(crate) fn unregister_executing_inode(dev: usize, ino: u32) {
    crate::fs::unregister_executing_inode(dev, ino);
}

/// 从用户地址空间读取一个 `usize` 指针/整数。
///
/// `token` 指定要读取的用户页表；地址无效或不可读时返回 `EFAULT`。
pub(super) fn try_read_usize_user(token: usize, ptr: usize) -> Result<usize, isize> {
    try_read_user_value(token, ptr as *const usize).ok_or(err(SyscallError::EFAULT))
}

// exec 参数/环境指针数组的最大项数。上限按用户栈能容纳的指针数量估算。
pub(super) const EXEC_ARG_PTR_LIMIT: usize =
    crate::config::USER_STACK_SIZE / core::mem::size_of::<usize>();
// 单个 argv/env 字符串最大长度，参考 Linux 的 MAX_ARG_STRLEN（32 pages）。
pub(super) const EXEC_MAX_ARG_STRLEN: usize = crate::config::PAGE_SIZE * 32;

/// 从用户地址读取以 NUL 结尾的 C 字符串，并限制最大扫描长度。
///
/// 这个函数同时服务普通路径字符串和 exec argv/env 字符串：
/// - 读到 NUL 时返回当前字符串；
/// - 用户地址不可读时返回 `EFAULT`；
/// - 超过 `max_len` 仍未遇到 NUL 时返回调用方指定的错误。
fn try_read_user_cstr_limited(
    token: usize,
    ptr: usize,
    max_len: usize,
    too_long: SyscallError,
) -> Result<String, isize> {
    let mut s = String::new();
    for i in 0..max_len {
        let ch =
            try_read_user_value(token, (ptr + i) as *const u8).ok_or(err(SyscallError::EFAULT))?;
        if ch == 0 {
            return Ok(s);
        }
        s.push(ch as char);
    }
    Err(err(too_long))
}

/// 读取普通 syscall 路径/字符串参数。
///
/// 长度超过当前兼容上限时按路径类错误返回 `ENAMETOOLONG`。
pub(super) fn try_read_user_cstr(token: usize, ptr: usize) -> Result<String, isize> {
    try_read_user_cstr_limited(token, ptr, 256 * 1024, SyscallError::ENAMETOOLONG)
}

/// 读取 exec 专用的 argv/env 字符串。
///
/// Linux 对单个 argv/env 字符串使用 `MAX_ARG_STRLEN` 限制，超限应返回
/// `E2BIG`，区别于普通路径字符串的 `ENAMETOOLONG`。
pub(super) fn try_read_user_exec_cstr(token: usize, ptr: usize) -> Result<String, isize> {
    try_read_user_cstr_limited(token, ptr, EXEC_MAX_ARG_STRLEN, SyscallError::E2BIG)
}

/// 读取用户传入的指针数组，直到遇到 NULL 结束项。
///
/// 用于 `argv`/`envp` 这类 `char **` 参数。空指针表示空数组；数组项过多
/// 时返回 `E2BIG`，避免内核无限扫描用户内存。
pub(super) fn read_user_ptr_array(token: usize, vec_ptr: usize) -> Result<Vec<usize>, isize> {
    let mut out = Vec::new();
    if vec_ptr == 0 {
        return Ok(out);
    }
    for i in 0..EXEC_ARG_PTR_LIMIT {
        let p = try_read_usize_user(token, vec_ptr + i * size_of::<usize>())?;
        if p == 0 {
            return Ok(out);
        }
        out.push(p);
    }
    Err(err(SyscallError::E2BIG))
}
