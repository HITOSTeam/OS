use super::*;
use alloc::sync::Arc;

static FORK_DIAG_PARENT_PID: AtomicUsize = AtomicUsize::new(usize::MAX);
static FORK_DIAG_START_MS: AtomicUsize = AtomicUsize::new(0);
static FORK_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);

fn should_report_fork_diag(count: usize) -> bool {
    count <= 16 || count % 128 == 0
}

fn record_fork_diag(parent_pid: usize, child_pid: usize, flags: usize, fork_elapsed_us: usize) {
    if !DEBUG_FUTEX {
        return;
    }
    let now_ms = crate::time::get_time_ms();
    let prev_parent = FORK_DIAG_PARENT_PID.load(Ordering::Relaxed);
    if prev_parent != parent_pid {
        FORK_DIAG_PARENT_PID.store(parent_pid, Ordering::Relaxed);
        FORK_DIAG_START_MS.store(now_ms, Ordering::Relaxed);
        FORK_DIAG_COUNT.store(0, Ordering::Relaxed);
    }
    let count = FORK_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let start_ms = FORK_DIAG_START_MS.load(Ordering::Relaxed);
    let elapsed_ms = now_ms.saturating_sub(start_ms);
    if should_report_fork_diag(count) {
        log::warn!(
            "[fork_diag] parent_pid={} child_pid={} count={} elapsed_ms={} fork_elapsed_us={} flags={:#x}",
            parent_pid,
            child_pid,
            count,
            elapsed_ms,
            fork_elapsed_us,
            flags
        );
    }
}

pub fn syscall_clone(flags: usize, stack: usize, _ptid: usize, _tls: usize, _ctid: usize) -> isize {
    const CLONE_VM: usize = 0x0000_0100;
    const CLONE_FS: usize = 0x0000_0200;
    const CLONE_FILES: usize = 0x0000_0400;
    const CLONE_VFORK: usize = 0x0000_4000;
    const CLONE_PARENT: usize = 0x0000_8000;
    const CLONE_SIGHAND: usize = 0x0000_0800;
    const CLONE_THREAD: usize = 0x0001_0000;
    const CLONE_NEWNS: usize = 0x0002_0000;
    const CLONE_SETTLS: usize = 0x0008_0000;
    const CLONE_PARENT_SETTID: usize = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
    const CLONE_NEWCGROUP: usize = 0x0200_0000;
    const CLONE_NEWIPC: usize = 0x0800_0000;
    const CLONE_NEWUTS: usize = 0x0400_0000;
    const CLONE_CHILD_SETTID: usize = 0x0100_0000;
    const CLONE_NEWPID: usize = 0x2000_0000;
    const CLONE_NEWNET: usize = 0x4000_0000;

    // LoongArch syscall ABI uses a different argument order:
    // clone(flags, stack, ptid, ctid, tls). Swap tls/ctid here.
    #[cfg(target_arch = "loongarch64")]
    let (_tls, _ctid) = (_ctid, _tls);

    // Network namespace is not implemented yet.
    if (flags & CLONE_NEWNET) != 0 {
        return err(SyscallError::EINVAL);
    }

    // Linux flag constraints:
    // - CLONE_SIGHAND requires CLONE_VM.
    // - CLONE_THREAD requires CLONE_SIGHAND (and therefore CLONE_VM).
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_VM) == 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & CLONE_THREAD) != 0 && (flags & CLONE_SIGHAND) == 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & CLONE_NEWIPC) != 0 && (flags & CLONE_THREAD) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & CLONE_NEWNS) != 0 && (flags & CLONE_FS) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWCGROUP)) != 0
        && current_process().borrow_mut().euid != 0
    {
        return err(SyscallError::EPERM);
    }
    if stack == 0 {
        // Linux permits fork-like clone(SIGCHLD, NULL, ...) but rejects NULL
        // stack for plain clone(0, ...) and thread-like clone variants.
        let exit_signal = flags & 0xff;
        let requires_child_stack =
            (flags & (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_SETTLS)) != 0;
        if exit_signal == 0 || requires_child_stack {
            return err(SyscallError::EINVAL);
        }
    }

    // Thread-like clone is strictly CLONE_THREAD-based. CLONE_SIGHAND without
    // CLONE_THREAD still creates a child process that wait()/getppid() must see.
    let is_thread_like = (flags & CLONE_THREAD) != 0 && (flags & CLONE_VM) != 0;
    if is_thread_like {
        let task = current_task().unwrap();
        let parent_mask = {
            let inner = task.borrow_mut();
            inner.signal_mask
        };
        let parent_tid_index = {
            let inner = task.borrow_mut();
            inner.res.as_ref().map(|res| res.tid).unwrap_or(0)
        };
        let parent_cx = {
            let inner = task.borrow_mut();
            *inner.get_trap_cx()
        };
        let process = current_process();
        if let Err(e) = cgroup_fork_precheck(process.getpid()) {
            return e;
        }
        let new_task = match TaskControlBlock::try_new_linux_thread(Arc::clone(&process)) {
            Ok(t) => Arc::new(t),
            Err(e) => return err(SyscallError::from(e)),
        };
        new_task.set_cpu_id(select_hart_for_new_task());

        let (_tid_index, linux_tid) = {
            let mut new_inner = new_task.borrow_mut();
            let res = new_inner.res.as_ref().unwrap();
            let tid_index = res.tid;
            let linux_tid = encode_linux_tid(process.getpid(), tid_index);

            // Attach to process thread table.
            {
                let mut process_inner = process.borrow_mut();
                let tasks = &mut process_inner.tasks;
                while tasks.len() < tid_index + 1 {
                    tasks.push(None);
                }
                tasks[tid_index] = Some(Arc::clone(&new_task));
            }

            new_inner.signal_mask = parent_mask;
            let trap_cx = new_inner.get_trap_cx();
            *trap_cx = parent_cx;
            trap_cx.x[REG_A0] = 0; // child returns 0 from syscall
            if stack != 0 {
                trap_cx.x[REG_SP] = stack;
            }
            if (flags & CLONE_SETTLS) != 0 {
                trap_cx.x[REG_TP] = _tls; // tp (TLS)
            }
            trap_cx.kernel_satp = kernel_token();
            trap_cx.kernel_sp = new_task.kstack_top();
            trap_cx.trap_handler = trap_handler as usize;
            if (flags & CLONE_CHILD_CLEARTID) != 0 && _ctid != 0 {
                new_inner.clear_child_tid = Some(_ctid);
            }
            cgroup_attach_thread(process.getpid(), parent_tid_index, tid_index);
            (tid_index, linux_tid)
        };

        if DEBUG_PTHREAD {
            log::debug!(
                "[clone] vm flags={:#x} stack={:#x} ptid={:#x} tls={:#x} ctid={:#x} tid={} linux_tid={}",
                flags,
                stack,
                _ptid,
                _tls,
                _ctid,
                _tid_index,
                linux_tid
            );
        }

        // Parent/child tid pointers live in the shared address space.
        let token = get_current_token();
        if (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
            if try_write_user_value(token, _ptid as *mut i32, &(linux_tid as i32)).is_err() {
                return err(SyscallError::EFAULT);
            }
        }
        if (flags & CLONE_CHILD_SETTID) != 0 && _ctid != 0 {
            if try_write_user_value(token, _ctid as *mut i32, &(linux_tid as i32)).is_err() {
                return err(SyscallError::EFAULT);
            }
        }

        add_task(new_task);
        return linux_tid as isize;
    }

    // Fork-like clone (process).
    let task = current_task().unwrap();
    let parent_cx = {
        let inner = task.borrow_mut();
        *inner.get_trap_cx()
    };
    let process = current_process();
    let share_files = (flags & CLONE_FILES) != 0;
    let share_vm = (flags & CLONE_VM) != 0;

    // For CLONE_VM + CLONE_PARENT_SETTID, ensure the parent-tid page is
    // materialized before cloning so the child shares the same backing frame.
    if share_vm && (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
        let token = get_current_token();
        let _ = try_write_user_value(token, _ptid as *mut i32, &0);
    }

    let fork_start_cycles = if DEBUG_FUTEX {
        crate::arch::read_time()
    } else {
        0
    };
    if let Err(e) = cgroup_fork_precheck(process.getpid()) {
        return e;
    }
    let (child, task) = match process.fork_with_task(share_files, share_vm) {
        Ok(pair) => pair,
        Err(e) => return err(SyscallError::from(e)),
    };
    if (flags & CLONE_NEWIPC) != 0 {
        let (parent_ipc_ns_id, inherited_attaches) = {
            let child_inner = child.borrow_mut();
            (child_inner.ipc_ns_id, child_inner.sysv_shm_attaches.clone())
        };
        if !inherited_attaches.is_empty() {
            crate::syscall::sysv_shm::rollback_fork_inherit(parent_ipc_ns_id, &inherited_attaches);
        }
        let mut child_inner = child.borrow_mut();
        child_inner.sysv_shm_attaches.clear();
        child_inner.ipc_ns_id = crate::task::alloc_ipc_namespace_id();
    }
    if (flags & CLONE_NEWUTS) != 0 {
        child.unshare_uts_namespace();
    }
    if (flags & CLONE_NEWNS) != 0 {
        child.unshare_mount_namespace();
    }
    if (flags & CLONE_NEWCGROUP) != 0 {
        child.set_cgroup_namespace_root(cgroup_current_path(child.getpid()));
    }
    if (flags & CLONE_NEWPID) != 0 {
        let parent_ns_id = process.pid_namespace_id();
        let child_ns_id = crate::task::alloc_pid_namespace_id();
        crate::task::register_pid_namespace(parent_ns_id, child_ns_id);
        let mut child_inner = child.borrow_mut();
        child_inner.pid_ns_id = child_ns_id;
        child_inner.pid_ns_vpid = 1;
        child_inner.pid_ns_init = true;
    }
    let fork_elapsed_us = if DEBUG_FUTEX {
        let delta = crate::arch::read_time().wrapping_sub(fork_start_cycles) as u128;
        let freq = crate::config::clock_freq() as u128;
        if freq == 0 {
            0
        } else {
            (delta.saturating_mul(1_000_000) / freq) as usize
        }
    } else {
        0
    };
    let child_pid = child.getpid();

    {
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        *trap_cx = parent_cx;
        trap_cx.x[REG_A0] = 0; // child returns 0 from syscall
        if stack != 0 {
            trap_cx.x[REG_SP] = stack;
        }
        trap_cx.kernel_satp = kernel_token();
        trap_cx.kernel_sp = task.kstack_top();
        trap_cx.trap_handler = trap_handler as usize;
        if (flags & CLONE_CHILD_CLEARTID) != 0 && _ctid != 0 {
            task_inner.clear_child_tid = Some(_ctid);
        }
    }

    if (flags & CLONE_PARENT) != 0 {
        let real_parent = {
            let inner = process.borrow_mut();
            inner.parent.as_ref().and_then(|p| p.upgrade())
        };
        if let Some(real_parent) = real_parent {
            {
                let mut caller_inner = process.borrow_mut();
                caller_inner.children.retain(|c| !Arc::ptr_eq(c, &child));
            }
            {
                let mut child_inner = child.borrow_mut();
                child_inner.parent = Some(Arc::downgrade(&real_parent));
            }
            {
                let mut real_parent_inner = real_parent.borrow_mut();
                real_parent_inner.children.push(Arc::clone(&child));
            }
        }
    }

    if (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
        let token = get_current_token();
        let _ = try_write_user_value(token, _ptid as *mut i32, &(child_pid as i32));
    }

    if (flags & CLONE_CHILD_SETTID) != 0 && _ctid != 0 {
        let child_token = {
            let mut inner = child.borrow_mut();
            let _ = inner.memory_set.resolve_cow_fault(_ctid);
            let _ = inner.memory_set.resolve_lazy_fault(_ctid, MapPermission::W);
            inner.memory_set.token()
        };
        if try_write_user_value(child_token, _ctid as *mut i32, &(child_pid as i32)).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    if crate::debug_config::DEBUG_TASK_LIFECYCLE
        && (child_pid <= 16 || (child_pid & (child_pid - 1)) == 0)
    {
        crate::println!(
            "[fork-task-ref] phase=pre_add child_pid={} strong_refs={}",
            child_pid,
            Arc::strong_count(&task)
        );
    }
    let child_same_hart = task.get_cpu_id() == hart_id();
    add_task(task);
    record_fork_diag(process.getpid(), child_pid, flags, fork_elapsed_us);

    if !is_thread_like && (flags & CLONE_VFORK) == 0 {
        let parent_fair =
            sched_class(process.borrow_mut().scheduling.sched_policy) == Some(SchedClass::Fair);
        let child_fair =
            sched_class(child.borrow_mut().scheduling.sched_policy) == Some(SchedClass::Fair);
        if parent_fair && child_fair && child_same_hart {
            // Let a freshly forked fair child run promptly so it can finish
            // exec/signal setup before the parent races ahead in user space.
            suspend_current_and_run_next();
        }
    }

    if (flags & CLONE_VFORK) != 0 {
        let parent_task = current_task().unwrap();
        loop {
            let done = {
                let inner = child.borrow_mut();
                inner.is_zombie || inner.did_exec
            };
            if done {
                break;
            }
            {
                let mut inner = process.borrow_mut();
                super::wait::enqueue_waiter_once(&mut inner.wait_queue, &parent_task);
            }
            block_current_and_run_next();
        }
        {
            let mut inner = process.borrow_mut();
            super::wait::remove_wait_queue_entry(&mut inner.wait_queue, &parent_task);
        }
    }

    crate::log_if!(
        DEBUG_SIGNAL,
        info,
        "[fork] parent_pid={} child_pid={} flags={:#x} stack={:#x}",
        process.getpid(),
        child_pid,
        flags,
        stack
    );
    child_pid as isize
}

/// Linux `vfork(2)` compatibility.
///
/// For now, treat it as a normal `fork(2)` (copy address space). This is
/// sufficient for busybox/ash and many OSComp scripts, and avoids the strict
/// parent-blocking/VM-sharing semantics of true vfork.
pub fn syscall_vfork() -> isize {
    let process = current_process();
    if let Err(e) = cgroup_fork_precheck(process.getpid()) {
        return e;
    }
    match process.fork() {
        Ok(child) => {
            crate::log_if!(
                DEBUG_SIGNAL,
                info,
                "[vfork] parent_pid={} child_pid={}",
                process.getpid(),
                child.getpid()
            );
            if sched_class(process.borrow_mut().scheduling.sched_policy) == Some(SchedClass::Fair)
                && sched_class(child.borrow_mut().scheduling.sched_policy) == Some(SchedClass::Fair)
            {
                suspend_current_and_run_next();
            }
            child.getpid() as isize
        }
        Err(e) => err(SyscallError::from(e)),
    }
}
