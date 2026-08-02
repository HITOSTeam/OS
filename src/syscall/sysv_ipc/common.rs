use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::task::processor::{current_process, current_task};
use crate::task::signal::has_wait_interrupting_pending;
use crate::task::task_block::{TaskControlBlock, TaskStatus};

use super::abi::IpcPermUser;

/// 内核态保存的 IPC 对象权限信息（比用户态 IpcPermUser 精简，不含填充/保留字段）。
#[derive(Clone, Copy)]
pub(super) struct IpcPermKernel {
    /// 关联的 key。
    pub(super) key: u32,
    /// 属主用户 id。
    pub(super) uid: u32,
    /// 属主组 id。
    pub(super) gid: u32,
    /// 创建者用户 id。
    pub(super) cuid: u32,
    /// 创建者组 id。
    pub(super) cgid: u32,
    /// 权限模式（低 9 位 rwx）。
    pub(super) mode: u16,
}

impl IpcPermKernel {
    /// 将内核态权限结构转换为用户态 ABI 的 ipc_perm 布局（填充字段保持默认 0）。
    pub(super) fn to_user(self) -> IpcPermUser {
        IpcPermUser {
            __key: self.key,
            uid: self.uid,
            gid: self.gid,
            cuid: self.cuid,
            cgid: self.cgid,
            mode: self.mode,
            ..IpcPermUser::default()
        }
    }
}

/// 当前进程凭据的快照，用于 IPC 权限检查与记录操作者 pid。
pub(super) struct Cred {
    /// 有效用户 id（euid==0 为 root，拥有全部权限）。
    pub(super) euid: u32,
    /// 有效组 id。
    pub(super) egid: u32,
    /// 附加组列表，权限检查时一并考虑。
    pub(super) groups: Vec<u32>,
    /// 进程 pid，记录到 IPC 对象的 lspid/lrpid/last_pid 等字段。
    pub(super) pid: u32,
}

/// 返回当前实时时钟的秒数，用于填充 IPC 对象的时间戳字段。
pub(super) fn now_secs() -> i64 {
    crate::syscall::time_sys::realtime_now_seconds() as i64
}

/// 获取当前进程所属的 IPC 命名空间 id（所有 SysV IPC 对象按命名空间隔离）。
pub(super) fn current_ipc_namespace_id() -> usize {
    let process = current_process();
    process.borrow_mut().ipc_ns_id
}

/// 快照当前进程的凭据（euid/egid/附加组/pid），用于权限检查与记录操作者。
pub(super) fn current_cred() -> Cred {
    let process = current_process();
    let inner = process.borrow_mut();
    Cred {
        euid: inner.euid,
        egid: inner.egid,
        groups: inner.supplementary_gids.clone(),
        pid: process.getpid() as u32,
    }
}

/// 判断是否为 root 或对象的属主/创建者（IPC_SET、IPC_RMID 等特权操作的前提）。
pub(super) fn is_owner_or_root(perm: &IpcPermKernel, cred: &Cred) -> bool {
    cred.euid == 0 || cred.euid == perm.uid || cred.euid == perm.cuid
}

/// 按 Linux 的 owner/group/other 三级权限模型检查访问权限。
/// `req` 为请求的权限位（如 MSG_R/SEM_A），root 与 req==0 直接放行；
/// 否则根据 euid/egid/附加组确定权限类别，再比对 mode 中对应的权限位。
pub(super) fn check_ipc_access(perm: &IpcPermKernel, req: u16, cred: &Cred) -> bool {
    if req == 0 || cred.euid == 0 {
        return true;
    }
    let class_shift = if cred.euid == perm.uid || cred.euid == perm.cuid {
        6
    } else if cred.egid == perm.gid
        || cred.egid == perm.cgid
        || cred
            .groups
            .iter()
            .any(|g| *g == perm.gid || *g == perm.cgid)
    {
        3
    } else {
        0
    };
    let need = ((req as usize) >> 6) & 0x7;
    let allow = ((perm.mode as usize) >> class_shift) & 0x7;
    (allow & need) == need
}

/// 清理计数用等待队列中的死引用，并返回当前处于 Blocked 状态的等待者数量。
///
/// 不能按状态删除存活任务：SMP 下等待者会先登记到对象等待队列，随后才在
/// `block_current_and_run_next()` 中切为 Blocked。计数命令若在这个 Running 窗口
/// 把它移除，就会制造和唤醒路径相同的丢唤醒问题。
pub(super) fn count_blocked_waiters(queue: &mut VecDeque<Weak<TaskControlBlock>>) -> usize {
    let mut blocked = 0;
    queue.retain(|task| {
        // 没有被持有了，可以放心扔掉
        let Some(task) = task.upgrade() else {
            return false;
        };

        let inner = task.borrow_mut();
        if inner.task_status == TaskStatus::Blocked {
            blocked += 1;
        }
        true
    });
    blocked
}

/// 取出所有仍存活的等待者用于唤醒。
///
/// 不按 `TaskStatus::Blocked` 过滤：SMP 下等待者会先登记到对象等待队列，
/// 随后才在 `block_current_and_run_next()` 中切为 Blocked。若唤醒方在这个窗口
/// 按状态过滤，会绕过 `wakeup_task()` 的原子延迟唤醒机制并丢失唤醒。
/// 这里会唤醒所有存活等待者，依赖阻塞 syscall 被唤醒后循环重查对象条件。
pub(super) fn drain_live_waiters(
    queue: &mut VecDeque<Weak<TaskControlBlock>>,
) -> Vec<Arc<TaskControlBlock>> {
    let mut wake = Vec::new();
    for waiter in queue.drain(..) {
        if let Some(task) = waiter.upgrade() {
            wake.push(task);
        }
    }
    wake
}

/// 将任务加入等待队列，若该任务已在队列中则不重复加入（去重）。
pub(super) fn add_waiter_once(
    queue: &mut VecDeque<Weak<TaskControlBlock>>,
    task: &Arc<TaskControlBlock>,
) {
    if queue
        .iter()
        .any(|w| w.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
    {
        return;
    }
    queue.push_back(Arc::downgrade(task));
}

/// 判断当前任务是否有未被屏蔽、可中断阻塞的挂起信号（用于阻塞型 IPC 调用返回 EINTR）。
pub(super) fn has_pending_unmasked_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
}
