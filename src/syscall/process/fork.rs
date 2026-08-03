use super::*;
use alloc::sync::Arc;

static FORK_DIAG_PARENT_PID: AtomicUsize = AtomicUsize::new(usize::MAX);
static FORK_DIAG_START_MS: AtomicUsize = AtomicUsize::new(0);
static FORK_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);

fn log_clone_tid_write_failure(
    process: &Arc<ProcessControlBlock>,
    task: &Arc<TaskControlBlock>,
    target: &str,
    token: usize,
    ptr: usize,
    flags: usize,
) {
    let pte = crate::mm::PageTable::from_token(token)
        .translate(crate::mm::VirtAddr::from(ptr).floor())
        .map(|pte| pte.bits);
    log::error!(
        "[clone] {} write failed pid={} ptr={:#x} flags={:#x} pte={:#x?} \
         free_pages={} token={:#x} task_token={:#x}",
        target,
        process.getpid(),
        ptr,
        flags,
        pte,
        crate::mm::frame_available_pages(),
        token,
        task.get_user_token(),
    );
}

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
    // LoongArch syscall ABI uses a different argument order:
    // clone(flags, stack, ptid, ctid, tls). Swap tls/ctid here.
    #[cfg(target_arch = "loongarch64")]
    let (_tls, _ctid) = (_ctid, _tls);

    clone_from_parts(flags, stack, _ptid, _tls, _ctid, None, None, false)
}

// 封装 clone3(2) 系统调用，支持将子进程原子性地加入 cgroup。
//
// 选用 clone3 而非 clone 的原因：clone3 的 clone_args 结构允许在 fork 时
// 直接指定目标 cgroup，消除了"fork 后、加入 cgroup 前"的竞争窗口。
//
// 参数：
//   flags             — CLONE_* 标志位，控制命名空间、信号等共享行为
//   stack             — 子进程栈顶地址；传 0 时内核自动分配（仅线程场景有意义）
//   _ptid / _tls / _ctid — 对应 clone_args 中的同名字段，保留接口与结构体的
//                          对应关系，当前测试场景不使用，后续扩展可直接启用
//   clone_into_cgroup — Some(target) 时原子性将子进程加入目标 cgroup；
//                       None 时退回不指定 cgroup 的普通 clone3 行为
//   allow_detached_null_stack — clone3 允许 exit_signal=0 的 fork-like 进程
//                               使用 NULL stack；clone(2) 仍按旧规则拒绝
//
// 返回值：
//   > 0  子进程 PID（父进程视角）
//   0    子进程自身的执行起点
//   < 0  -errno，系统调用失败
fn clone_from_parts(
    flags: usize,
    stack: usize,
    _ptid: usize,
    _tls: usize,
    _ctid: usize,
    clone_into_cgroup: Option<CgroupAttachTarget>,
    pidfd_user_ptr: Option<usize>,
    allow_detached_null_stack: bool,
) -> isize {
    // 本地重新声明标准 Linux 常量，避免引入 libc 依赖——此函数直接走裸 syscall
    const CLONE_VM: usize = 0x0000_0100; // 与父进程共享地址空间
    const CLONE_FS: usize = 0x0000_0200; // 共享文件系统信息（cwd/root/umask）
    const CLONE_FILES: usize = 0x0000_0400; // 共享文件描述符表
    const CLONE_VFORK: usize = 0x0000_4000; // 父进程阻塞，直到子进程 exec/exit
    const CLONE_PARENT: usize = 0x0000_8000; // 子进程的父亲设为调用者的父亲（兄弟关系）
    const CLONE_SIGHAND: usize = 0x0000_0800; // 共享信号处理表
    const CLONE_THREAD: usize = 0x0001_0000; // 加入调用者所在的线程组（同 TGID）
    const CLONE_NEWNS: usize = 0x0002_0000; // 新建 mount namespace
    const CLONE_SETTLS: usize = 0x0008_0000; // 设置子进程 TLS 寄存器
    const CLONE_PARENT_SETTID: usize = 0x0010_0000; // 将子 TID 写回父进程指针 _ptid
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000; // 子线程退出时清零 _ctid 并 futex 唤醒
    const CLONE_NEWCGROUP: usize = 0x0200_0000; // 新建 cgroup namespace
    const CLONE_NEWIPC: usize = 0x0800_0000; // 新建 System V IPC namespace
    const CLONE_NEWUTS: usize = 0x0400_0000; // 新建 UTS（hostname/domain）namespace
    const CLONE_CHILD_SETTID: usize = 0x0100_0000; // 将子 TID 写到子地址空间 _ctid
    const CLONE_NEWPID: usize = 0x2000_0000; // 新建 PID namespace
    const CLONE_NEWNET: usize = 0x4000_0000; // 新建 network namespace

    // Linux flag constraints:
    // - CLONE_SIGHAND requires CLONE_VM.
    // - CLONE_THREAD requires CLONE_SIGHAND (and therefore CLONE_VM).
    // Linux 标志位约束：
    // - 共享信号处理表必须同时共享地址空间，否则信号上下文无法对齐
    // - 线程组成员必须共享信号处理表（从而也共享地址空间）
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_VM) == 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & CLONE_THREAD) != 0 && (flags & CLONE_SIGHAND) == 0 {
        return err(SyscallError::EINVAL);
    }
    // PID namespace boundaries are process-scoped. Linux rejects requests that
    // would make a thread the init task of a fresh PID namespace, and CLONE_PARENT
    // would move that namespace-init child under the caller's parent.
    // PID 命名空间以进程为边界：线程不能成为新 PID namespace 的 init；
    // CLONE_PARENT 也不能和 CLONE_NEWPID 组合，否则新 init 会被重挂到调用者父进程下。
    if (flags & CLONE_NEWPID) != 0 && (flags & (CLONE_THREAD | CLONE_PARENT)) != 0 {
        return err(SyscallError::EINVAL);
    }
    // Namespace init must stay the root reaper of its namespace. Linux returns
    // EINVAL for CLONE_PARENT from any PID namespace init, even if it has an
    // outside parent in the ancestor namespace.
    // PID namespace 的 init 必须保持该 namespace 的根回收者；即使它在上层 namespace
    // 里有父进程，也不能用 CLONE_PARENT 把新子进程交给外层父进程回收。
    if (flags & CLONE_PARENT) != 0 && current_process().is_pid_namespace_init() {
        return err(SyscallError::EINVAL);
    }
    // 线程不能拥有独立的 IPC 命名空间：同进程线程必须共享 IPC 资源视图
    if (flags & CLONE_NEWIPC) != 0 && (flags & CLONE_THREAD) != 0 {
        return err(SyscallError::EINVAL);
    }
    // SysV shm attachments are mm-local in this kernel.  Sharing the mm while
    // moving only the child into a new IPC namespace would leave shared VMAs
    // owned by the old namespace with no unambiguous cleanup owner.
    if (flags & CLONE_NEWIPC) != 0 && (flags & CLONE_VM) != 0 {
        return err(SyscallError::EINVAL);
    }
    // 新建 mount 命名空间时不能再共享 fs（cwd/root/umask），否则两个 ns 会互相污染挂载点
    if (flags & CLONE_NEWNS) != 0 && (flags & CLONE_FS) != 0 {
        return err(SyscallError::EINVAL);
    }
    // 创建新命名空间需要 root 权限（euid == 0）
    if (flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWCGROUP)) != 0
        && current_process().borrow_mut().euid != 0
    {
        return err(SyscallError::EPERM);
    }
    if stack == 0 {
        // Linux clone(2) permits fork-like clone(SIGCHLD, NULL, ...) but rejects
        // clone(0, NULL, ...). clone3 split exit_signal out of flags and allows
        // exit_signal=0 with NULL stack for fork-like, non-CLONE_VM processes.
        // vfork(2) is the special CLONE_VM | CLONE_VFORK case: the child starts
        // on the caller's stack and the parent remains blocked until exec/exit.
        // Linux clone(2) 允许 fork 形式的 clone(SIGCHLD, NULL, ...)，但拒绝
        // clone(0, NULL, ...)。clone3 将 exit_signal 独立成字段后，允许
        // exit_signal=0 的非 CLONE_VM 进程 clone 使用 NULL stack 来禁止父进程通知。
        let exit_signal = flags & 0xff;
        // 这些强制要求栈
        let requires_child_stack = (flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_SETTLS)) != 0
            || ((flags & CLONE_VM) != 0 && (flags & CLONE_VFORK) == 0);
        let detached_fork_like_clone3 = allow_detached_null_stack && exit_signal == 0;
        if requires_child_stack || (exit_signal == 0 && !detached_fork_like_clone3) {
            return err(SyscallError::EINVAL);
        }
    }

    // Thread-like clone is strictly CLONE_THREAD-based. CLONE_SIGHAND without
    // CLONE_THREAD still creates a child process that wait()/getppid() must see.
    // 线程语义严格以 CLONE_THREAD 为准：仅有 CLONE_SIGHAND 而无 CLONE_THREAD
    // 仍会创建独立子进程，wait()/getppid() 必须能看到它
    let is_thread_like = (flags & CLONE_THREAD) != 0 && (flags & CLONE_VM) != 0;
    if is_thread_like {
        // pidfd 语义绑定进程对象，本实现暂不为线程型 clone3 返回 pidfd。
        // CLONE_INTO_CGROUP 可用于线程：目标 hierarchy 进入指定 cgroup，其余 hierarchy 继承父线程。
        if pidfd_user_ptr.is_some() {
            return err(SyscallError::EINVAL);
        }
        let task = current_task().unwrap();
        // Linux fork/clone first saves the caller's current FPU registers, then
        // copies that snapshot into the child so user FP registers survive clone.
        crate::arch::save_user_fp_state(&task);
        // 复制父线程的信号屏蔽字，子线程沿用直到自己 sigprocmask
        let parent_mask = {
            let inner = task.borrow_mut();
            inner.signal_mask
        };
        let parent_scheduling = task.scheduling_snapshot();
        // 记录父线程在进程线程表中的 tid 索引，用于 cgroup 线程附挂时定位归属
        let parent_tid_index = {
            let inner = task.borrow_mut();
            inner.res.as_ref().map(|res| res.tid).unwrap_or(0)
        };
        // 快照父线程的陷入上下文，子线程会基于它构造自己的初始寄存器现场
        let parent_cx = {
            let inner = task.borrow_mut();
            *inner.get_trap_cx()
        };
        let process = current_process();
        if process.exec_in_progress() || process.group_exit_in_progress() {
            return err(SyscallError::EAGAIN);
        }
        // 在当前进程下新建一个 Linux 风格线程的 TCB（共享地址空间/文件等）
        let new_task = match TaskControlBlock::try_new_linux_thread(Arc::clone(&process)) {
            Ok(t) => Arc::new(t),
            Err(e) => return err(SyscallError::from(e)),
        };
        new_task.inherit_fp_state_from(&task);
        new_task.set_scheduling_snapshot(parent_scheduling);
        // 为新线程挑选一个负载较轻的 hart 作为初始运行核
        new_task.set_cpu_id(select_hart_for_new_task());

        let (_tid_index, linux_tid) = {
            let mut new_inner = new_task.borrow_mut();
            let res = new_inner.res.as_ref().unwrap();
            let tid_index = res.tid;
            // 编码为 Linux 视角的 TID（高位含 PID，低位为线程槽位）
            let linux_tid = encode_linux_tid(process.getpid(), tid_index);

            // 继承父线程的信号屏蔽字
            new_inner.signal_mask = parent_mask;
            // 基于父上下文搭建子线程的 trap 帧，使其从同一指令处恢复执行
            let trap_cx = new_inner.get_trap_cx();
            *trap_cx = parent_cx;
            trap_cx.x[REG_A0] = 0; // child returns 0 from syscall  子线程从 syscall 返回 0
            // 用户态指定了子栈地址则切换 sp，否则沿用父栈（VM 共享时通常必传）
            if stack != 0 {
                trap_cx.x[REG_SP] = stack;
            }
            // CLONE_SETTLS：把用户传入的 TLS 基址写入 tp 寄存器
            if (flags & CLONE_SETTLS) != 0 {
                trap_cx.x[REG_TP] = _tls; // tp (TLS)
            }
            // 内核陷入相关字段：内核页表、内核栈顶、陷入入口
            trap_cx.kernel_satp = kernel_token();
            trap_cx.kernel_sp = new_task.kstack_top();
            trap_cx.trap_handler = trap_handler as usize;
            // CLONE_CHILD_CLEARTID：记录退出时要清零并 futex 唤醒的用户地址
            if (flags & CLONE_CHILD_CLEARTID) != 0 && _ctid != 0 {
                new_inner.clear_child_tid = Some(_ctid);
            }
            (tid_index, linux_tid)
        };

        // Complete every fallible initialization step before publishing the
        // TCB in process.tasks.  Exec snapshots only published tasks; exposing
        // an unstarted task here and later rolling it back could strand the
        // exec coordinator's one-shot peer token forever.
        if let Err(e) = cgroup_attach_thread(
            process.getpid(),
            parent_tid_index,
            _tid_index,
            clone_into_cgroup.as_ref(),
        ) {
            return e;
        }

        // 线程克隆路径的调试日志：仅在打开 DEBUG_PTHREAD 时输出
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
        // 父/子 TID 指针位于共享地址空间内，可直接用当前 token 写入
        let token = get_current_token();
        // CLONE_PARENT_SETTID：把新 TID 回写到父线程指定的用户地址
        if (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
            if try_write_user_value(token, _ptid as *mut i32, &(linux_tid as i32)).is_err() {
                log_clone_tid_write_failure(&process, &new_task, "parent_tid", token, _ptid, flags);
                crate::fs::cgroup_exit_thread(process.getpid(), _tid_index);
                return err(SyscallError::EFAULT);
            }
        }
        // CLONE_CHILD_SETTID：把新 TID 写到子线程视角的用户地址（此处地址空间共享，等价）
        if (flags & CLONE_CHILD_SETTID) != 0 && _ctid != 0 {
            if try_write_user_value(token, _ctid as *mut i32, &(linux_tid as i32)).is_err() {
                log_clone_tid_write_failure(&process, &new_task, "child_tid", token, _ctid, flags);
                crate::fs::cgroup_exit_thread(process.getpid(), _tid_index);
                return err(SyscallError::EFAULT);
            }
        }

        // Publish exactly once, after no failing operation remains. Holding
        // the PCB lock serializes this insertion with exec's task snapshot. If
        // a group-wide action won while initialization was in flight, discard
        // the still-private TCB and its old-mm reference.
        {
            let mut process_inner = process.borrow_mut();
            if process.exec_in_progress() || process.group_exit_in_progress() {
                drop(process_inner);
                crate::fs::cgroup_exit_thread(process.getpid(), _tid_index);
                return err(SyscallError::EAGAIN);
            }
            let tasks = &mut process_inner.tasks;
            while tasks.len() < _tid_index + 1 {
                tasks.push(None);
            }
            debug_assert!(tasks[_tid_index].is_none());
            tasks[_tid_index] = Some(Arc::clone(&new_task));
        }
        refresh_thread_legacy_cpu_fair_group_cache(process.getpid(), _tid_index);
        crate::syscall::cyclic_diag_note(
            crate::syscall::CyclicDiagEvent::Clone,
            process.getpid(),
            _tid_index,
        );

        // The creating thread is still fair until the new pthreads finish their
        // scheduler setup. Give that control path one bounded startup credit so
        // it is not buried behind a large hackbench-style fair runqueue.
        crate::task::manager::prime_fair_thread_group_start(&task, _tid_index);

        // 将新线程加入调度队列；线程路径不走下方进程 fork 流程，直接返回
        add_task(new_task);
        return linux_tid as isize;
    }

    // Fork-like clone (process).
    // 以下为进程语义的 clone（即 fork 系列）：会得到独立的 task_struct/PID
    let task = current_task().unwrap();
    // 快照父任务的陷入上下文，子进程将基于它恢复用户态执行
    let parent_cx = {
        let inner = task.borrow_mut();
        *inner.get_trap_cx()
    };
    let process = current_process();
    // 是否与父进程共享文件描述符表 / 地址空间
    let share_files = (flags & CLONE_FILES) != 0;
    let share_vm = (flags & CLONE_VM) != 0;
    let share_fs = (flags & CLONE_FS) != 0;

    // For CLONE_VM + CLONE_PARENT_SETTID, ensure the parent-tid page is
    // materialized before cloning so the child shares the same backing frame.
    // CLONE_VM + CLONE_PARENT_SETTID 组合下，预先 touch 父 TID 所在页，
    // 让该页在 fork 前完成物理分配，子进程才能与父共享同一物理帧
    if share_vm && (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
        let token = get_current_token();
        let _ = try_write_user_value(token, _ptid as *mut i32, &0);
    }

    // 记录 fork 起始时间戳，用于 futex/fork 性能诊断（仅 DEBUG_FUTEX 时启用）
    let fork_start_cycles = if DEBUG_FUTEX {
        crate::arch::read_time()
    } else {
        0
    };
    // cgroup 预校验：拒绝在冻结/超配的 cgroup 中分裂出子进程
    if let Err(e) = cgroup_fork_precheck(process.getpid()) {
        return e;
    }
    // 实际复制进程资源：返回 (子进程控制块, 子进程主任务)
    let (child, task) = match process.fork_with_task(share_files, share_vm, share_fs) {
        Ok(pair) => pair,
        Err(e) => return err(SyscallError::from(e)),
    };
    // CLONE_NEWIPC：为子进程切换到新的 IPC 命名空间
    // 父进程继承下来的 System V 共享内存挂载需要回滚（新 ns 内不应可见），
    // 然后再分配一个独立的 ipc_ns_id
    if (flags & CLONE_NEWIPC) != 0 {
        let child_memory_set = child.memory_set();
        let inherited_attaches = child_memory_set.sysv_shm_attaches_snapshot();
        if !share_vm && !inherited_attaches.is_empty() {
            crate::syscall::sysv_shm::rollback_fork_inherit(&inherited_attaches);
        }
        child_memory_set.replace_sysv_shm_attaches(Vec::new());
        let mut child_inner = child.borrow_mut();
        child_inner.ipc_ns_id = crate::task::alloc_ipc_namespace_id();
    }
    // CLONE_NEWUTS：拆出独立的 UTS（hostname/domain）命名空间
    if (flags & CLONE_NEWUTS) != 0 {
        child.unshare_uts_namespace();
    }
    // CLONE_NEWNS：拆出独立的 mount 命名空间，后续 mount/umount 不影响父
    if (flags & CLONE_NEWNS) != 0 {
        child.unshare_mount_namespace();
    }
    // CLONE_NEWNET：当前只分配 namespace 句柄，网络设备表仍全局共享。
    if (flags & CLONE_NEWNET) != 0 {
        child.unshare_net_namespace();
    }
    // CLONE_NEWCGROUP：以当前 cgroup 路径作为子的 cgroup ns 根
    if (flags & CLONE_NEWCGROUP) != 0 {
        child.unshare_cgroup_namespace(cgroup_current_path(child.getpid()));
    }
    // CLONE_NEWPID：子进程进入新的 PID 命名空间，自身在新 ns 内成为 init(vpid=1)
    if (flags & CLONE_NEWPID) != 0 {
        let parent_ns_id = process.pid_namespace_id();
        let child_ns_id = crate::task::alloc_pid_namespace_id();
        crate::task::register_pid_namespace(parent_ns_id, child_ns_id);
        {
            let mut child_inner = child.borrow_mut();
            child_inner.pid_ns_id = child_ns_id;
            child_inner.pid_ns_vpid = 1;
            child_inner.pid_ns_init = true;
            child.update_parent_visible_pid_from_locked_child(child_ns_id, parent_ns_id, 0);
        }
        crate::task::register_pid_namespace_reaper(child_ns_id, child.getpid());
    }
    // 计算本次 fork 实际耗时（微秒），用于诊断慢 fork（仅 DEBUG_FUTEX 时启用）
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
    // 低 8 位 flags 是子进程退出时投递给父的信号（典型为 SIGCHLD）
    {
        let mut child_inner = child.borrow_mut();
        child_inner.exit_signal = (flags & 0xff) as i32;
    }
    // clone3 的 CLONE_INTO_CGROUP：把新进程原子性附挂到目标 cgroup
    if let Some(target) = clone_into_cgroup.as_ref() {
        if let Err(e) = cgroup_attach_process_to_target(child_pid, target) {
            rollback_unstarted_child(&child, share_vm);
            return e;
        }
    }

    // 构造子进程主线程的初始 trap 上下文：基于父快照，并改写 sp/a0 等
    {
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        *trap_cx = parent_cx;
        trap_cx.x[REG_A0] = 0; // child returns 0 from syscall  子进程的 syscall 返回值为 0
        // 显式传入栈顶则改用之；为 0 表示沿用父 sp（仅适用于不共享 VM 的 fork 语义）
        if stack != 0 {
            trap_cx.x[REG_SP] = stack;
        }
        // 内核态相关字段：内核页表、内核栈、陷入入口
        trap_cx.kernel_satp = kernel_token();
        trap_cx.kernel_sp = task.kstack_top();
        trap_cx.trap_handler = trap_handler as usize;
        // CLONE_CHILD_CLEARTID：子退出时清零 _ctid 并 futex 唤醒等待者
        if (flags & CLONE_CHILD_CLEARTID) != 0 && _ctid != 0 {
            task_inner.clear_child_tid = Some(_ctid);
        }
    }

    // CLONE_PARENT：把子的父亲改成调用者的父亲（产生"兄弟"关系），
    // 这是 pthread 创建组等场景需要的语义
    if (flags & CLONE_PARENT) != 0 {
        let attached = loop {
            let real_parent = {
                let inner = process.borrow_mut();
                inner.parent.as_ref().and_then(|p| p.upgrade())
            };
            let Some(real_parent) = real_parent else {
                break false;
            };
            // Hold the prospective parent's PCB lock across the liveness
            // recheck and child-list insertion. If its last thread starts
            // exit concurrently, either live_threads is already zero and this
            // clone fails safely, or exit waits for this lock and includes the
            // newly attached child in its orphan snapshot.
            let mut real_parent_inner = real_parent.borrow_mut();
            let mut caller_inner = process.borrow_mut();
            let still_real_parent = caller_inner
                .parent
                .as_ref()
                .and_then(|parent| parent.upgrade())
                .is_some_and(|parent| Arc::ptr_eq(&parent, &real_parent));
            if !still_real_parent {
                // The caller was reparented between the optimistic lookup and
                // the ordered parent -> caller lock acquisition. Retry using
                // the new parent rather than attaching to a stale ancestor.
                drop(caller_inner);
                drop(real_parent_inner);
                continue;
            }
            let can_adopt = !real_parent_inner.is_zombie
                && !real_parent_inner.exit_teardown
                && real_parent.live_thread_count() != 0;
            if !can_adopt {
                break false;
            }
            let real_parent_pid_ns_id = real_parent_inner.pid_ns_id;
            let real_parent_visible_pid = if real_parent_pid_ns_id == 0 {
                real_parent.getpid()
            } else {
                real_parent_inner.pid_ns_vpid
            };
            // The real parent is the caller's ancestor, so parent -> caller ->
            // child is the same lock order used by wait and exit publication.
            if caller_inner.remove_child(&child).is_none() {
                break false;
            }
            let mut child_inner = child.borrow_mut();
            child_inner.parent = Some(Arc::downgrade(&real_parent));
            child.update_parent_visible_pid_from_locked_child(
                child_inner.pid_ns_id,
                real_parent_pid_ns_id,
                real_parent_visible_pid,
            );
            drop(child_inner);
            real_parent_inner.add_child(Arc::clone(&child));
            break true;
        };
        if !attached {
            // Linux serializes CLONE_PARENT attachment with task reparenting.
            // If the prospective parent is already irreversibly exiting, fail
            // before the child is runnable instead of silently changing its
            // parent semantics or leaving a phantom child behind.
            rollback_unstarted_child(&child, share_vm);
            return err(SyscallError::EAGAIN);
        }
    }

    // CLONE_PARENT_SETTID：把子 PID 写回父地址空间的 _ptid 指针
    if (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
        let token = get_current_token();
        let _ = try_write_user_value(token, _ptid as *mut i32, &(child_pid as i32));
    }

    // CLONE_CHILD_SETTID：把子 PID 写入子地址空间的 _ctid 指针
    // 子的页表与父不同（除非 CLONE_VM），写入前需先处理 COW/lazy 缺页
    if (flags & CLONE_CHILD_SETTID) != 0 && _ctid != 0 {
        let child_memory_set = {
            let inner = child.borrow_mut();
            inner.memory_set.clone()
        };
        // Fault preparation can allocate/copy pages. Keep the child PCB lock
        // out of that path, just as Linux drops task-level locking before
        // faulting in CLONE_CHILD_SETTID storage. Charge a newly materialized
        // anonymous page to the child: current_process() is still the parent,
        // while Linux memcg accounting follows the target fault context.
        let _ = child_memory_set.resolve_cow_fault(_ctid);
        let _ = child_memory_set.resolve_lazy_fault_for(_ctid, MapPermission::W, child_pid);
        let child_token = child_memory_set.token();
        if try_write_user_value(child_token, _ctid as *mut i32, &(child_pid as i32)).is_err() {
            rollback_unstarted_child(&child, share_vm);
            return err(SyscallError::EFAULT);
        }
    }
    if let Some(pidfd_user_ptr) = pidfd_user_ptr {
        let token = get_current_token();
        if let Err(e) = install_child_pidfd(&child, token, pidfd_user_ptr) {
            rollback_unstarted_child(&child, share_vm);
            return err(e);
        }
    }
    // 任务生命周期调试：仅对小 PID 或 2 的幂打印，控制日志量
    if crate::debug_config::DEBUG_TASK_LIFECYCLE
        && (child_pid <= 16 || (child_pid & (child_pid - 1)) == 0)
    {
        crate::println!(
            "[fork-task-ref] phase=pre_add child_pid={} strong_refs={}",
            child_pid,
            Arc::strong_count(&task)
        );
    }
    if share_vm {
        let shared_mm_token = child.borrow_mut().memory_set.token();
        register_shared_mm_process_owner(shared_mm_token);
    }
    // 将子任务推入调度队列；至此子才真正可被调度执行
    add_task(task);
    // 落入 fork 诊断统计（按 parent_pid 聚合，节流输出）
    record_fork_diag(process.getpid(), child_pid, flags, fork_elapsed_us);

    // 普通 fork 不强制 child-first。Linux/CFS 只把 child 放入就绪队列，
    // 是否抢占由调度器决定；这里主动让父进程让出会把 fork-heavy 程序
    // 串行化，例如 mmapstress09 需要父进程先完成一批 fork 再设置 alarm。

    // CLONE_VFORK：父需阻塞直到子调用 execve 或退出。
    if (flags & CLONE_VFORK) != 0 {
        let parent_task = current_task().unwrap();
        loop {
            let should_block = {
                let mut parent_inner = process.borrow_mut();
                let inner = child.borrow_mut();
                let done = inner.is_zombie || inner.did_exec;
                drop(inner);
                if done {
                    super::wait::remove_wait_queue_entry(
                        &mut parent_inner.vfork_wait_queue,
                        &parent_task,
                    );
                    false
                } else {
                    super::wait::enqueue_waiter_once(
                        &mut parent_inner.vfork_wait_queue,
                        &parent_task,
                    );
                    true
                }
            };
            if !should_block {
                parent_task
                    .wakeup_pending
                    .store(false, core::sync::atomic::Ordering::Release);
                break;
            }
            block_current_and_run_next();
        }
        // 唤醒后清理等待队列残留，避免悬挂引用。
        {
            let mut inner = process.borrow_mut();
            super::wait::remove_wait_queue_entry(&mut inner.vfork_wait_queue, &parent_task);
        }
    }

    // 信号子系统侧的 fork 落地日志（仅 DEBUG_SIGNAL 启用）
    crate::log_if!(
        DEBUG_SIGNAL,
        info,
        "[fork] parent_pid={} child_pid={} flags={:#x} stack={:#x}",
        process.getpid(),
        child_pid,
        flags,
        stack
    );
    // 父进程视角返回子 PID（>0）；子进程是通过 trap 上下文里写好的 a0=0 路径返回的
    child_pid as isize
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Clone3Args {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// 从user space 读取 clone3空间
fn read_clone3_args(args_ptr: usize, size: usize) -> Result<Clone3Args, SyscallError> {
    const CLONE_ARGS_MIN_SIZE: usize = 64;
    const CLONE_ARGS_MAX_COPY: usize = 4096;

    if size == 0 || size < CLONE_ARGS_MIN_SIZE {
        return Err(SyscallError::EINVAL);
    }
    if size > CLONE_ARGS_MAX_COPY {
        return Err(SyscallError::E2BIG);
    }
    if args_ptr == 0 {
        return Err(SyscallError::EFAULT);
    }

    let token = get_current_token();
    let mut raw = Vec::new();
    raw.resize(size, 0);
    if try_copy_from_user(token, args_ptr as *const u8, raw.as_mut_slice()).is_err() {
        return Err(SyscallError::EFAULT);
    }

    let mut args = Clone3Args::default();
    let copy_len = core::cmp::min(size, size_of::<Clone3Args>());
    unsafe {
        core::ptr::copy_nonoverlapping(
            raw.as_ptr(),
            &mut args as *mut Clone3Args as *mut u8,
            copy_len,
        );
    }
    if size > size_of::<Clone3Args>()
        && raw[size_of::<Clone3Args>()..].iter().any(|byte| *byte != 0)
    {
        return Err(SyscallError::E2BIG);
    }
    Ok(args)
}

/// `clone3(CLONE_PIDFD)` 的收尾步骤：为刚创建的子进程构造 pidfd 并安装到父进程的 fd 表，
/// 再将 fd 编号回写到用户态指针 `user_ptr`。
///
/// 关键设计：直接传入 `&Arc<ProcessControlBlock>` 而非裸 PID，
/// 使 [`PidFdFile`] 内部持有 `Weak<ProcessControlBlock>`。
/// 这样即便 PID 数值在子进程退出后被重新分配，
/// 外部通过此 pidfd 做 `waitid(P_PIDFD)` / `pidfd_send_signal` 时
/// `target_process()` 升级会返回 `None`（`ECHILD`/`ESRCH`），不会错误地作用于无关进程。
///
/// 若 fd 安装成功但用户态回写失败（`EFAULT`），则立即撤销已分配的 fd，
/// 保证不泄露 fd 资源；随后 `clone_from_parts` 调用 `rollback_unstarted_child`
/// 回滚整个 clone 操作。
fn install_child_pidfd(
    child: &Arc<ProcessControlBlock>,
    token: usize,
    user_ptr: usize,
) -> Result<i32, SyscallError> {
    const FD_CLOEXEC: u32 = 1;

    let (files, limit) = current_files_and_nofile_limit();
    // 通过 Arc 构造 pidfd，使其内部持有 Weak<ProcessControlBlock>：
    // 即便 PID 数值未来被复用，本 pidfd 也只解析到这一次 fork 的子进程，
    // 不会误投递到无关进程。
    let pidfd: Arc<dyn crate::fs::File + Send + Sync> = Arc::new(PidFdFile::new(child));
    let installed = files
        .lock()
        .install_fd(Arc::clone(&pidfd), FD_CLOEXEC, limit);
    let fd = match installed {
        Ok(fd) => fd as i32,
        Err(rejected) => {
            rejected.discard();
            return Err(SyscallError::EMFILE);
        }
    };
    if try_write_user_value(token, user_ptr as *mut i32, &fd).is_err() {
        let detached = {
            let mut files = files.lock();
            if files
                .get_file(fd as usize)
                .is_some_and(|current| Arc::ptr_eq(&current, &pidfd))
            {
                files.clear_fd(fd as usize)
            } else {
                None
            }
        };
        if let Some(detached) = detached {
            drop(detached.complete_close());
        }
        return Err(SyscallError::EFAULT);
    }
    Ok(fd)
}

fn rollback_unstarted_child(child: &Arc<ProcessControlBlock>, share_vm: bool) {
    // First make the unpublished child impossible to reparent. The parent may
    // itself be exiting, so validate child.parent while holding parent -> child
    // locks and retry if ownership changed before the locks were acquired.
    loop {
        let parent = {
            let child_inner = child.borrow_mut();
            child_inner
                .parent
                .as_ref()
                .and_then(|parent| parent.upgrade())
        };
        let Some(parent) = parent else {
            let mut child_inner = child.borrow_mut();
            child_inner.wait_reaped = true;
            child_inner.exit_teardown = true;
            child_inner.child_parent_index = None;
            break;
        };
        let mut parent_inner = parent.borrow_mut();
        let mut child_inner = child.borrow_mut();
        let still_child_of_parent = child_inner
            .parent
            .as_ref()
            .and_then(|candidate| candidate.upgrade())
            .is_some_and(|candidate| Arc::ptr_eq(&candidate, &parent));
        if !still_child_of_parent {
            drop(child_inner);
            drop(parent_inner);
            continue;
        }

        // `try_reparent_child_to()` checks wait_reaped under the child lock.
        // Publishing it here makes any concurrent reparent attempt abort once
        // this lock is released.
        child_inner.wait_reaped = true;
        child_inner.exit_teardown = true;
        child_inner.parent = None;
        child_inner.exited_parent_queue_pid = None;

        let index = child_inner
            .child_parent_index
            .filter(|index| {
                *index < parent_inner.children.len()
                    && Arc::ptr_eq(&parent_inner.children[*index], child)
            })
            .or_else(|| {
                parent_inner
                    .children
                    .iter()
                    .position(|candidate| Arc::ptr_eq(candidate, child))
            });
        if let Some(index) = index {
            let removed = parent_inner.children.swap_remove(index);
            debug_assert!(Arc::ptr_eq(&removed, child));
            if index < parent_inner.children.len() {
                parent_inner.children[index].borrow_mut().child_parent_index = Some(index);
            }
        }
        child_inner.child_parent_index = None;
        break;
    }

    let child_pid = child.getpid();
    crate::fs::cgroup_exit_process(child_pid);
    let detached = child.files().lock().release_process_owner();
    crate::task::complete_fd_closes(detached);
    let child_memory_set = child.memory_set();
    let child_mm_token = child_memory_set.token();
    let shm_attaches = if share_vm {
        Vec::new()
    } else {
        let attaches = child_memory_set.sysv_shm_attaches_snapshot();
        child_memory_set.replace_sysv_shm_attaches(Vec::new());
        crate::syscall::net::clear_packet_ring_mmaps_for_token(child_mm_token);
        attaches
    };
    let (exec_dev, exec_ino, net_ns_id) = {
        let child_inner = child.borrow_mut();
        (
            child_inner.exec_inode_dev,
            child_inner.exec_inode_num,
            child_inner.net_ns_id,
        )
    };
    if !shm_attaches.is_empty() {
        crate::syscall::sysv_shm::rollback_fork_inherit(&shm_attaches);
    }
    unregister_executing_inode(exec_dev, exec_ino);
    if let Some(released_net_ns_id) = child.release_net_namespace_owner() {
        debug_assert_eq!(released_net_ns_id, net_ns_id);
        crate::syscall::net::cleanup_net_namespace_if_unused(released_net_ns_id);
    }
    crate::task::manager::remove_from_pid2process(child_pid);
}

/// Linux `clone3(2)` compatibility.
///
/// This reuses the existing clone implementation after translating the
/// extensible `struct clone_args` ABI into canonical clone arguments.
///
/// Linux clone3(2) 兼容实现。
///
/// 思路：先把可扩展的 `struct clone_args` 翻译成 clone 系列的标准参数，
/// 再复用 `clone_from_parts` 完成真正的复制工作。clone3 相比 clone(2) 的
/// 新增能力体现在：
///   - `exit_signal` 从 flags 低 8 位独立成字段（支持 RT 信号编号 > 0xff）
///   - `pidfd`：fork 完成时同步把 pidfd 写回用户空间
///   - `set_tid`：允许显式指定子进程 PID（本实现尚未支持）
///   - `cgroup` + CLONE_INTO_CGROUP：fork 时原子性将子进程加入目标 cgroup
///
/// 参数：
///   args_ptr — 用户态 `struct clone_args` 的地址
///   size     — 用户告知的结构体长度（用于 ABI 前向兼容）
/// 返回：
///   >0 子进程 PID；<0 -errno。
pub fn syscall_clone3(args_ptr: usize, size: usize) -> isize {
    const CLONE_VM: usize = 0x0000_0100; // 与父进程共享地址空间
    const CLONE_FS: usize = 0x0000_0200; // 共享文件系统信息
    const CLONE_FILES: usize = 0x0000_0400; // 共享文件描述符表
    const CLONE_SIGHAND: usize = 0x0000_0800; // 共享信号处理表
    const CLONE_PIDFD: usize = 0x0000_1000; // 创建后回写一个 pidfd 给父
    const CLONE_VFORK: usize = 0x0000_4000; // 父进程阻塞直到子进程 exec/exit
    const CLONE_PARENT: usize = 0x0000_8000; // 子进程父亲指向调用者的父亲（兄弟关系）
    const CLONE_THREAD: usize = 0x0001_0000; // 创建同线程组线程
    const CLONE_NEWNS: usize = 0x0002_0000; // 新建 mount namespace
    const CLONE_SYSVSEM: usize = 0x0004_0000; // 共享 System V semaphore undo state
    const CLONE_SETTLS: usize = 0x0008_0000; // 设置子进程 TLS
    const CLONE_PARENT_SETTID: usize = 0x0010_0000; // 将子 TID 写回父进程指针
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000; // 子线程退出时清零并 futex 唤醒
    const CLONE_DETACHED: usize = 0x0040_0000; // clone3 禁止的历史遗留标志
    const CLONE_CHILD_SETTID: usize = 0x0100_0000; // 将子 TID 写到子地址空间
    const CLONE_NEWCGROUP: usize = 0x0200_0000; // 新建 cgroup namespace
    const CLONE_NEWUTS: usize = 0x0400_0000; // 新建 UTS namespace
    const CLONE_NEWIPC: usize = 0x0800_0000; // 新建 IPC namespace
    const CLONE_NEWPID: usize = 0x2000_0000; // 新建 PID namespace
    const CLONE_NEWNET: usize = 0x4000_0000; // 新建 network namespace
    const CLONE_INTO_CGROUP: usize = 0x0000_0002_0000_0000; // 原子性加入目标 cgroup
    const CLONE_ARGS_CGROUP_SIZE: usize = size_of::<Clone3Args>();
    const SUPPORTED_CLONE3_FLAGS: usize = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_PIDFD
        | CLONE_VFORK
        | CLONE_PARENT
        | CLONE_THREAD
        | CLONE_NEWNS
        | CLONE_SYSVSEM
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID
        | CLONE_NEWCGROUP
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWPID
        | CLONE_NEWNET
        | CLONE_INTO_CGROUP;

    // 从用户空间安全读取 clone_args；按 size 兼容更短/更长版本，
    // 末尾若有非零字节会返回 E2BIG（说明内核还不识别这些扩展字段）
    let args = match read_clone3_args(args_ptr, size) {
        Ok(args) => args,
        Err(e) => return err(e),
    };

    let flags = args.flags as usize;
    let exit_signal = args.exit_signal as usize;
    // clone3 的 flags 低 8 位必须为 0（exit_signal 已独立成字段）；
    // 同时退出信号编号不能超过实时信号上限
    if (flags & 0xff) != 0 || exit_signal > RT_SIG_MAX {
        return err(SyscallError::EINVAL);
    }
    // clone3_args_valid 语义：未知 flags 和 CLONE_DETACHED 这类禁用历史位必须
    // 在 fork 前拒绝，不能把不支持的语义静默忽略后仍创建子进程。
    if (flags & CLONE_DETACHED) != 0 || (flags & !SUPPORTED_CLONE3_FLAGS) != 0 {
        return err(SyscallError::EINVAL);
    }
    // Linux clone3_args_valid 要求：CLONE_THREAD/CLONE_PARENT 与非零 exit_signal 互斥。
    // CLONE_THREAD 共享线程组，由 thread leader 退出时统一通知父进程，禁止设置独立的 exit_signal；
    // CLONE_PARENT 使新子的父亲指向调用者的父亲，与"由本调用者接收 exit_signal"的语义冲突。
    if (flags & (CLONE_THREAD | CLONE_PARENT)) != 0 && exit_signal != 0 {
        return err(SyscallError::EINVAL);
    }
    // stack 与 stack_size 必须成对出现：要么都为 0，要么都非 0
    if (args.stack == 0) != (args.stack_size == 0) {
        return err(SyscallError::EINVAL);
    }
    // set_tid（指定子 PID 列表）暂未实现，传入即拒绝
    if args.set_tid != 0 || args.set_tid_size != 0 {
        return err(SyscallError::EINVAL);
    }
    // pidfd 和 parent_tid 都是父进程地址空间的输出槽，Linux 禁止两者别名，
    // 否则同一个地址会先后写入 pid 和 fd，成功返回却丢失其中一个结果。
    if (flags & (CLONE_PIDFD | CLONE_PARENT_SETTID)) == (CLONE_PIDFD | CLONE_PARENT_SETTID)
        && args.pidfd == args.parent_tid
    {
        return err(SyscallError::EINVAL);
    }
    let pidfd_user_ptr = if (flags & CLONE_PIDFD) != 0 {
        if args.pidfd == 0 {
            return err(SyscallError::EFAULT);
        }
        if (flags & CLONE_THREAD) != 0 {
            return err(SyscallError::EINVAL);
        }
        Some(args.pidfd as usize)
    } else {
        None
    };

    // CLONE_INTO_CGROUP：根据 cgroup fd 解析出附挂目标，传给底层 clone 路径
    // 让 fork 与 cgroup 附挂保持原子，消除"先 fork 再 attach"的竞态窗口
    let clone_into_cgroup = if (flags & CLONE_INTO_CGROUP) != 0 {
        // cgroup 字段是 clone_args 的 5.7 扩展；旧 size 未覆盖该字段时，
        // 不能使用默认初始化出来的 fd 0，必须按无效 ABI 布局返回 EINVAL。
        if size < CLONE_ARGS_CGROUP_SIZE {
            return err(SyscallError::EINVAL);
        }
        // 从当前进程的 fd 表里取出对应的 cgroup 目录文件
        let file = {
            let files = current_files();
            files.lock().get_file(args.cgroup as usize)
        };
        let Some(file) = file else {
            return err(SyscallError::EBADF);
        };
        // 校验该 fd 确实指向一个合法 cgroup 节点，并把它转换成附挂目标
        match cgroup_clone_into_target_from_file(&file) {
            Ok(target) => Some(target),
            Err(e) => return e,
        }
    } else {
        None
    };

    // 计算子进程的初始 sp：clone3 传的是栈底+栈大小，需相加得到栈顶；
    // 溢出则视为非法参数；stack==0 表示沿用父栈（仅 fork 语义）
    let child_stack = if args.stack == 0 {
        0
    } else {
        match (args.stack as usize).checked_add(args.stack_size as usize) {
            Some(sp) => sp,
            None => return err(SyscallError::EINVAL),
        }
    };
    // 把 exit_signal 合并回 flags 的低 8 位，使下层 clone_from_parts 沿用 clone(2) 的约定
    let clone_flags = flags | exit_signal;
    // 真正执行 clone：复制进程/线程、构造 trap 上下文、做命名空间分裂等
    let child_pid = clone_from_parts(
        clone_flags,
        child_stack,
        args.parent_tid as usize,
        args.tls as usize,
        args.child_tid as usize,
        clone_into_cgroup,
        pidfd_user_ptr,
        true,
    );
    // clone_from_parts 返回负数即 -errno，原样回传
    if child_pid < 0 {
        return child_pid;
    }

    // 父进程视角返回子 PID
    child_pid
}

/// Linux `vfork(2)` compatibility.
pub fn syscall_vfork() -> isize {
    const CLONE_VM: usize = 0x0000_0100;
    const CLONE_VFORK: usize = 0x0000_4000;

    clone_from_parts(
        CLONE_VM | CLONE_VFORK | SIGCHLD_NUM,
        0,
        0,
        0,
        0,
        None,
        None,
        false,
    )
}
