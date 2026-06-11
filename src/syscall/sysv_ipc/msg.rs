use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::manager::wakeup_task;
use crate::task::processor::{block_current_and_run_next, current_task};
use crate::task::task_block::TaskControlBlock;
use crate::trap::get_current_token;

use super::abi::{
    IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_NOWAIT, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, MSG_COPY,
    MSG_EXCEPT, MSG_INFO, MSG_NOERROR, MSG_R, MSG_STAT, MSG_STAT_ANY, MSG_W, MSGMAP, MSGPOOL,
    MSGSEG, MSGSSZ, MSGTQL, MsgInfoUser, MsqidDsUser,
};
use super::common::{
    IpcPermKernel, add_waiter_once, check_ipc_access, current_cred, current_ipc_namespace_id,
    drain_live_waiters, has_pending_unmasked_signal, is_owner_or_root, now_secs,
};
use super::sysctl::{runtime_msgmax_limit, runtime_msgmnb_limit, runtime_msgmni_limit};

/// 消息队列中的一条消息。
#[derive(Clone)]
struct Msg {
    /// 消息类型，必须为正数；msgrcv 可按此值挑选要接收的消息。
    mtype: i64,
    /// 消息体的原始字节内容。
    mtext: Vec<u8>,
}

/// 一个 System V 消息队列对象（对应用户态的一个 msqid）。
struct MsgQueue {
    /// 队列 id（msgget 返回、msgsnd/msgrcv/msgctl 使用的标识）。
    id: usize,
    /// 关联的 key；IPC_PRIVATE 创建的队列无 key，为 None。
    key: Option<u32>,
    /// 属主与权限信息（uid/gid/创建者/mode），用于权限检查。
    perm: IpcPermKernel,
    /// 队列中按顺序存放的消息，队首最先被接收。
    msgs: VecDeque<Msg>,
    /// 因队列为空而阻塞在 msgrcv 上的接收者，队列有新消息时被唤醒。
    recv_waiters: VecDeque<Weak<TaskControlBlock>>,
    /// 因队列已满而阻塞在 msgsnd 上的发送者，队列腾出空间时被唤醒。
    send_waiters: VecDeque<Weak<TaskControlBlock>>,
    /// 当前队列中所有消息体的总字节数（current bytes）。
    cbytes: usize,
    /// 队列容量上限，单位字节（msgmnb，可经 IPC_SET 修改）。
    qbytes: usize,
    /// 最近一次执行 msgsnd 的进程 pid（last send pid）。
    lspid: u32,
    /// 最近一次执行 msgrcv 的进程 pid（last receive pid）。
    lrpid: u32,
    /// 最近一次 msgsnd 的时间戳，单位秒（send time）。
    stime: i64,
    /// 最近一次 msgrcv 的时间戳，单位秒（receive time）。
    rtime: i64,
    /// 最近一次创建或经 IPC_SET 修改的时间戳，单位秒（change time）。
    ctime: i64,
}

/// 消息队列管理器 namespace 隔离
#[derive(Default)]
struct MsgManager {
    /// 下一个待分配的 id（递增并跳过已占用值）。
    next_id: usize,
    /// id -> 消息队列 的映射。
    queues: BTreeMap<usize, MsgQueue>,
    /// key -> id 的映射，供按 key 复用已有队列。
    key2id: BTreeMap<u32, usize>,
}

impl MsgManager {
    /// 分配一个未被占用的消息队列 id（从 1 开始递增，跳过已存在的 id）。
    ///
    /// 当前 id 同时作为 MSG_STAT/MSG_STAT_ANY 的内部索引使用；若未来引入
    /// sequence bits，需要同步调整 STAT 查询与 IPC_INFO 返回值。
    fn alloc_id(&mut self) -> usize {
        if self.next_id < 1 {
            self.next_id = 1;
        }
        while self.queues.contains_key(&self.next_id) {
            self.next_id += 1;
        }
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// 删除指定消息队列并返回需要唤醒的等待任务列表（收/发等待者，
    /// 让它们从阻塞中返回并感知队列已被移除 EIDRM）。同时清理 key->id 映射。
    fn remove_queue(&mut self, id: usize) -> Vec<Arc<TaskControlBlock>> {
        let mut wake = Vec::new();
        if let Some(mut queue) = self.queues.remove(&id) {
            wake.extend(drain_live_waiters(&mut queue.recv_waiters));
            wake.extend(drain_live_waiters(&mut queue.send_waiters));
            if let Some(key) = queue.key {
                if self.key2id.get(&key).copied() == Some(id) {
                    self.key2id.remove(&key);
                }
            }
        }
        wake
    }
}

lazy_static! {
    /// 全局消息队列管理表：IPC 命名空间 id -> 该命名空间的 MsgManager。
    static ref MSG_MANAGERS: Mutex<BTreeMap<usize, MsgManager>> = Mutex::new(BTreeMap::new());
}

/// 生成 /proc/sysvipc/msg 的内容：表头加上当前 IPC 命名空间内每个消息队列一行的统计信息。
pub fn proc_sysvipc_msg() -> String {
    let mut out = String::from(
        "       key      msqid perms      cbytes       qnum       qbytes lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n",
    );
    let ipc_ns_id = current_ipc_namespace_id();
    let managers = MSG_MANAGERS.lock();
    let Some(mgr) = managers.get(&ipc_ns_id) else {
        return out;
    };
    for queue in mgr.queues.values() {
        let key = queue.key.unwrap_or(0);
        let line = alloc::format!(
            "{:10} {:10} {:5o} {:11} {:10} {:12} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10}\n",
            key,
            queue.id,
            queue.perm.mode & 0o777,
            queue.cbytes,
            queue.msgs.len(),
            queue.qbytes,
            queue.lspid,
            queue.lrpid,
            queue.perm.uid,
            queue.perm.gid,
            queue.perm.cuid,
            queue.perm.cgid,
            queue.stime,
            queue.rtime,
            queue.ctime
        );
        out.push_str(&line);
    }
    out
}

/// 唤醒消息队列上所有等待者（收或发），用于队列状态变化时让它们重新检查条件。
fn wake_msg_waiters(queue: &mut VecDeque<Weak<TaskControlBlock>>) {
    for task in drain_live_waiters(queue) {
        wakeup_task(task);
    }
}

/// 将内核消息队列状态转换为用户态 msqid_ds 结构（供 IPC_STAT/MSG_STAT 返回）。
fn msq_to_user(queue: &MsgQueue) -> MsqidDsUser {
    MsqidDsUser {
        msg_perm: queue.perm.to_user(),
        msg_stime: queue.stime,
        msg_rtime: queue.rtime,
        msg_ctime: queue.ctime,
        msg_cbytes: queue.cbytes as u64,
        msg_qnum: queue.msgs.len() as u64,
        msg_qbytes: queue.qbytes as u64,
        msg_lspid: queue.lspid,
        msg_lrpid: queue.lrpid,
        ..MsqidDsUser::default()
    }
}

/// msgget(2)：按 key 查找或创建消息队列。
/// 处理 IPC_PRIVATE（总是新建）、IPC_CREAT/IPC_EXCL 语义、权限检查与 msgmni 上限，
/// 返回消息队列 id 或错误。
pub fn syscall_msgget(key: usize, msgflg: usize) -> isize {
    // 取当前进程凭据（euid/egid/pid 等），用于设置新队列的属主和做权限检查。
    let cred = current_cred();
    // 用户传入的 key 是 usize，IPC 对象内部用 u32 存储，这里做一次转换。
    let key_u32 = key as u32;
    // SysV IPC 对象按 IPC 命名空间隔离，先确定当前进程属于哪个命名空间。
    let ipc_ns_id = current_ipc_namespace_id();
    // 锁住全局消息队列表，并取出（不存在则新建）本命名空间的管理器。
    let mut managers = MSG_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();

    // IPC_PRIVATE 表示「不关联任何 key，每次都新建一个私有队列」，所以这段按 key 查找的
    // 逻辑只在非 IPC_PRIVATE 时才执行。
    if key != IPC_PRIVATE {
        // 该 key 之前已经创建过队列：尝试复用已有的那个。
        if let Some(id) = mgr.key2id.get(&key_u32).copied() {
            // IPC_CREAT|IPC_EXCL 语义是「独占创建」：要求对象必须不存在。
            // 现在它已存在，于是返回 EEXIST（类似 open 的 O_CREAT|O_EXCL）。
            if (msgflg & IPC_CREAT) != 0 && (msgflg & IPC_EXCL) != 0 {
                return err(SyscallError::EEXIST);
            }
            // key2id 里有映射，但实际队列对象缺失，属于不一致状态，返回 ENOENT。
            let Some(queue) = mgr.queues.get(&id) else {
                return err(SyscallError::ENOENT);
            };
            // msgflg 低 9 位是权限位，取其中 owner 三位（0o700）作为本次请求的访问权限，
            // 校验调用者是否有权访问这个已存在的队列。
            let req = (msgflg & 0o700) as u16;
            if !check_ipc_access(&queue.perm, req, &cred) {
                return err(SyscallError::EACCES);
            }
            // 复用成功，直接返回已有队列的 id。
            return id as isize;
        }
        // key 不存在，且调用者没有要求创建（未设 IPC_CREAT），按规范返回 ENOENT。
        if (msgflg & IPC_CREAT) == 0 {
            return err(SyscallError::ENOENT);
        }
    }
    // 走到这里说明需要新建队列。先检查是否超过系统允许的消息队列数量上限（msgmni）。
    if mgr.queues.len() >= runtime_msgmni_limit() {
        return err(SyscallError::ENOSPC);
    }

    // 分配一个未被占用的队列 id。
    let id = mgr.alloc_id();
    // 取 msgflg 低 9 位作为权限模式（rwx for owner/group/other）。
    let mode = (msgflg & 0o777) as u16;
    // 构造权限结构：创建者即属主，uid/gid 与 cuid/cgid（creator）都设为当前进程的有效 id。
    let perm = IpcPermKernel {
        key: key_u32,
        uid: cred.euid,
        gid: cred.egid,
        cuid: cred.euid,
        cgid: cred.egid,
        mode,
    };
    // 初始化队列本体：空消息列表、空等待队列，容量上限取运行时 msgmnb，创建时间戳填当前时间。
    let queue = MsgQueue {
        id,
        // IPC_PRIVATE 创建的队列不关联 key（None），普通队列记录其 key 以便后续按 key 复用。
        key: if key == IPC_PRIVATE {
            None
        } else {
            Some(key_u32)
        },
        perm,
        msgs: VecDeque::new(),
        recv_waiters: VecDeque::new(),
        send_waiters: VecDeque::new(),
        cbytes: 0,
        qbytes: runtime_msgmnb_limit(),
        lspid: 0,
        lrpid: 0,
        stime: 0,
        rtime: 0,
        ctime: now_secs(),
    };
    // 若队列带 key，登记 key->id 映射，使得后续相同 key 的 msgget 能复用它。
    if let Some(k) = queue.key {
        mgr.key2id.insert(k, id);
    }
    // 把新队列放入管理器，并返回其 id 给用户态。
    mgr.queues.insert(id, queue);
    id as isize
}

/// msgctl(2)：消息队列控制。
/// 支持 IPC_INFO/MSG_INFO（系统/运行时统计）、MSG_STAT/MSG_STAT_ANY（按 id 取状态）、
/// IPC_STAT（取状态）、IPC_SET（改属性）、IPC_RMID（删除并唤醒等待者）。
pub fn syscall_msgctl(msqid: usize, cmd: usize, buf: usize) -> isize {
    // 调用者凭据用于权限检查；token 是用户态页表令牌，读写用户内存时需要。
    let cred = current_cred();
    let token = get_current_token();
    // 取出当前 IPC 命名空间的消息队列管理器。
    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = MSG_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();

    // IPC_INFO / MSG_INFO：返回整个消息子系统的限制与统计信息，不针对具体某个队列。
    if cmd == IPC_INFO || cmd == MSG_INFO {
        // 返回值为「当前最大的队列 id」，作为遍历 MSG_STAT 时的上界提示。
        let highest_index = mgr.queues.keys().next_back().copied().unwrap_or(0);
        // MSG_INFO 返回运行时实际占用（队列数、消息总数、总字节）；
        // IPC_INFO 返回静态的池容量常量。两者用同一结构但字段含义不同。
        let (msgpool, msgmap, msgtql) = if cmd == MSG_INFO {
            let total_messages = mgr
                .queues
                .values()
                .fold(0usize, |acc, queue| acc.saturating_add(queue.msgs.len()));
            let total_bytes = mgr
                .queues
                .values()
                .fold(0usize, |acc, queue| acc.saturating_add(queue.cbytes));
            (
                mgr.queues.len().min(i32::MAX as usize) as i32,
                total_messages.min(i32::MAX as usize) as i32,
                total_bytes.min(i32::MAX as usize) as i32,
            )
        } else {
            (MSGPOOL, MSGMAP, MSGTQL)
        };
        // 组装并写回用户态的 msginfo 结构；限制项取当前运行时值。
        let info = MsgInfoUser {
            msgpool,
            msgmap,
            msgmax: runtime_msgmax_limit() as i32,
            msgmnb: runtime_msgmnb_limit() as i32,
            msgmni: runtime_msgmni_limit() as i32,
            msgssz: MSGSSZ,
            msgtql,
            msgseg: MSGSEG,
            ..MsgInfoUser::default()
        };
        if try_write_user_value(token, buf as *mut MsgInfoUser, &info).is_err() {
            return err(SyscallError::EFAULT);
        }
        return highest_index as isize;
    }

    // MSG_STAT / MSG_STAT_ANY：按当前内部 id 取某个队列的状态，返回值为该队列 id。
    if cmd == MSG_STAT || cmd == MSG_STAT_ANY {
        let Some(queue) = mgr.queues.get(&msqid) else {
            return err(SyscallError::EINVAL);
        };
        // MSG_STAT_ANY 跳过读权限检查；MSG_STAT 需要调用者具备读权限。
        if cmd == MSG_STAT_ANY || check_ipc_access(&queue.perm, MSG_R, &cred) {
            let ds = msq_to_user(queue);
            if try_write_user_value(token, buf as *mut MsqidDsUser, &ds).is_err() {
                return err(SyscallError::EFAULT);
            }
            return msqid as isize;
        }
        return err(SyscallError::EACCES);
    }

    // 其余命令都针对一个具体存在的队列，先按 id 取出，不存在则 EINVAL。
    let Some(queue) = mgr.queues.get_mut(&msqid) else {
        return err(SyscallError::EINVAL);
    };
    match cmd {
        // IPC_RMID：删除队列。需属主或 root；删除后唤醒所有等待者，让它们返回 EIDRM。
        IPC_RMID => {
            if !is_owner_or_root(&queue.perm, &cred) {
                return err(SyscallError::EPERM);
            }
            let wake = mgr.remove_queue(msqid);
            // 先释放管理器锁，再唤醒任务，避免持锁唤醒带来的潜在死锁。
            drop(managers);
            for task in wake {
                wakeup_task(task);
            }
            0
        }
        // IPC_STAT：把队列状态写回用户态，需读权限。
        IPC_STAT => {
            if !check_ipc_access(&queue.perm, MSG_R, &cred) {
                return err(SyscallError::EACCES);
            }
            let ds = msq_to_user(queue);
            if try_write_user_value(token, buf as *mut MsqidDsUser, &ds).is_err() {
                return err(SyscallError::EFAULT);
            }
            0
        }
        // IPC_SET：修改属主/权限/容量上限，需属主或 root。
        IPC_SET => {
            if !is_owner_or_root(&queue.perm, &cred) {
                return err(SyscallError::EPERM);
            }
            // 从用户态读入新的 msqid_ds，只采纳允许修改的字段。
            let Some(ds) = try_read_user_value(token, buf as *const MsqidDsUser) else {
                return err(SyscallError::EFAULT);
            };
            queue.perm.uid = ds.msg_perm.uid;
            queue.perm.gid = ds.msg_perm.gid;
            queue.perm.mode = ds.msg_perm.mode & 0o777;
            queue.qbytes = ds.msg_qbytes as usize;
            queue.ctime = now_secs();
            // 容量可能被调大，唤醒因队列满而阻塞的发送者重新尝试。
            wake_msg_waiters(&mut queue.send_waiters);
            0
        }
        _ => err(SyscallError::EINVAL),
    }
}

/// msgsnd(2)：向消息队列发送一条消息。
/// 校验大小与 mtype，从用户态拷入消息体；队列满时按 IPC_NOWAIT 返回 EAGAIN 或阻塞等待，
/// 入队后更新统计并唤醒接收等待者。
pub fn syscall_msgsnd(msqid: usize, msgp: usize, msgsz: usize, msgflg: usize) -> isize {
    // msgsz 是消息体长度。负数（最高位为 1）非法。
    if (msgsz as isize) < 0 {
        return err(SyscallError::EINVAL);
    }
    // 单条消息体不能超过 msgmax 上限。
    if msgsz > runtime_msgmax_limit() {
        return err(SyscallError::EINVAL);
    }
    let cred = current_cred();
    let token = get_current_token();
    // 用户缓冲区布局是 `struct msgbuf { long mtype; char mtext[]; }`，先读出开头的 mtype。
    let Some(mtype) = try_read_user_value(token, msgp as *const i64) else {
        return err(SyscallError::EFAULT);
    };
    // 消息类型必须为正数。
    if mtype <= 0 {
        return err(SyscallError::EINVAL);
    }
    // 紧跟在 mtype 之后的是 msgsz 字节的消息体，先整体拷入内核缓冲。
    let mut mtext = vec![0u8; msgsz];
    if try_copy_from_user(
        token,
        (msgp + core::mem::size_of::<i64>()) as *const u8,
        &mut mtext,
    )
    .is_err()
    {
        return err(SyscallError::EFAULT);
    }

    // waited 标记本次调用是否曾经阻塞过：用于区分「队列一开始就不存在(EINVAL)」
    // 和「阻塞期间队列被删除(EIDRM)」两种错误。
    let mut waited = false;
    let ipc_ns_id = current_ipc_namespace_id();
    // 循环重试：队列满 -> 阻塞 -> 被唤醒后回到循环开头重新检查条件。
    loop {
        let mut managers = MSG_MANAGERS.lock();
        let mgr = managers.entry(ipc_ns_id).or_default();
        let Some(queue) = mgr.queues.get_mut(&msqid) else {
            return if waited {
                err(SyscallError::EIDRM)
            } else {
                err(SyscallError::EINVAL)
            };
        };
        // 发送需要写权限。
        if !check_ipc_access(&queue.perm, MSG_W, &cred) {
            return err(SyscallError::EACCES);
        }
        // 队列容量足够（当前字节数 + 本条消息 <= 上限）时入队。
        if queue.cbytes.saturating_add(msgsz) <= queue.qbytes {
            queue.msgs.push_back(Msg {
                mtype,
                mtext: mtext.clone(),
            });
            queue.cbytes += msgsz;
            // 记录最近发送者 pid 和发送时间。
            queue.lspid = cred.pid;
            queue.stime = now_secs();
            // 队列有了新消息，唤醒可能在等待接收的任务。
            wake_msg_waiters(&mut queue.recv_waiters);
            return 0;
        }
        // 队列已满：非阻塞模式直接返回 EAGAIN。
        if (msgflg & IPC_NOWAIT) != 0 {
            return err(SyscallError::EAGAIN);
        }
        // 阻塞前先检查是否有挂起信号，有则返回 EINTR（被信号中断）。
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        let Some(task) = current_task() else {
            return err(SyscallError::EINVAL);
        };
        // 把自己登记到「发送等待者」队列，然后释放锁并让出 CPU 进入阻塞。
        add_waiter_once(&mut queue.send_waiters, &task);
        drop(managers);
        block_current_and_run_next();
        waited = true;
        // 被唤醒后：若是因信号而醒，返回 EINTR；否则回到循环顶部重新尝试入队。
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
    }
}

/// msgrcv(2)：从消息队列接收一条消息。
/// 按 msgtyp 选择消息（0 取队首，>0 取匹配类型，<0 取不超过 |msgtyp| 的最小类型），
/// 支持 MSG_NOERROR（截断）、MSG_EXCEPT（取不等于）、MSG_COPY（仅复制不移除）标志；
/// 无匹配时按 IPC_NOWAIT 返回 ENOMSG 或阻塞等待。
pub fn syscall_msgrcv(
    msqid: usize,
    msgp: usize,
    msgsz: usize,
    msgtyp: isize,
    msgflg: usize,
) -> isize {
    // msgsz 为接收缓冲区可容纳的消息体上限。负数非法。
    if (msgsz as isize) < 0 {
        return err(SyscallError::EINVAL);
    }
    let cred = current_cred();
    let token = get_current_token();
    // MSG_COPY：按下标“复制”一条消息但不出队（常配合 /proc 调试）；MSG_EXCEPT：取类型“不等于”msgtyp 的消息。
    let msg_copy = (msgflg & MSG_COPY) != 0;
    let msg_except = (msgflg & MSG_EXCEPT) != 0;
    // 标志组合合法性校验：
    // - MSG_COPY 必须搭配 IPC_NOWAIT，且不能与 MSG_EXCEPT 同用，msgtyp（此时是下标）不能为负。
    // - 非 COPY 模式下，MSG_EXCEPT 要求 msgtyp 非 0（否则“排除 0”没有意义）。
    if msg_copy {
        if (msgflg & IPC_NOWAIT) == 0 || msg_except || msgtyp < 0 {
            return err(SyscallError::EINVAL);
        }
    } else if msg_except && msgtyp == 0 {
        return err(SyscallError::EINVAL);
    }

    // waited 同 msgsnd：区分队列从未存在(EINVAL) vs 阻塞中被删除(EIDRM)。
    let mut waited = false;
    let ipc_ns_id = current_ipc_namespace_id();
    // 循环重试：无匹配消息 -> 阻塞 -> 被唤醒后重新挑选。
    loop {
        let mut managers = MSG_MANAGERS.lock();
        let mgr = managers.entry(ipc_ns_id).or_default();
        let Some(queue) = mgr.queues.get_mut(&msqid) else {
            return if waited {
                err(SyscallError::EIDRM)
            } else {
                err(SyscallError::EINVAL)
            };
        };
        // 接收需要读权限。
        if !check_ipc_access(&queue.perm, MSG_R, &cred) {
            return err(SyscallError::EACCES);
        }

        // 根据 msgtyp 与标志，挑选要接收的消息在队列中的下标：
        let pick_idx = if queue.msgs.is_empty() {
            // 队列为空，没得挑。
            None
        } else if msg_copy {
            // COPY 模式：msgtyp 当作下标，越界则视为无匹配。
            let idx = msgtyp as usize;
            if idx < queue.msgs.len() {
                Some(idx)
            } else {
                None
            }
        } else if msgtyp == 0 {
            // msgtyp==0：取队首（最早的）消息。
            Some(0)
        } else if msgtyp > 0 {
            // msgtyp>0：取第一条类型等于（或 MSG_EXCEPT 时不等于）msgtyp 的消息。
            if msg_except {
                queue.msgs.iter().position(|m| m.mtype != msgtyp as i64)
            } else {
                queue.msgs.iter().position(|m| m.mtype == msgtyp as i64)
            }
        } else {
            // msgtyp<0：取类型 <= |msgtyp| 的消息中类型最小的那条。
            let limit = (-msgtyp) as i64;
            queue
                .msgs
                .iter()
                .enumerate()
                .filter(|(_, m)| m.mtype <= limit)
                .min_by_key(|(_, m)| m.mtype)
                .map(|(idx, _)| idx)
        };

        if let Some(idx) = pick_idx {
            let src = queue.msgs.get(idx).unwrap();
            // 消息体比用户缓冲区大，且未设 MSG_NOERROR（截断）则报错 E2BIG。
            if src.mtext.len() > msgsz && (msgflg & MSG_NOERROR) == 0 {
                return err(SyscallError::E2BIG);
            }
            // 实际拷贝长度取「消息体长度」与「缓冲区大小」的较小值（NOERROR 时即截断）。
            let copy_len = src.mtext.len().min(msgsz);
            let msg_type = src.mtype;
            let mut payload = vec![0u8; copy_len];
            payload.copy_from_slice(&src.mtext[..copy_len]);
            // 非 COPY 模式才真正出队：移除消息、更新字节统计、记录接收者与时间，并唤醒等待发送者。
            if !msg_copy {
                let removed = queue.msgs.remove(idx).unwrap();
                queue.cbytes = queue.cbytes.saturating_sub(removed.mtext.len());
                queue.lrpid = cred.pid;
                queue.rtime = now_secs();
                wake_msg_waiters(&mut queue.send_waiters);
            }
            // 拷贝到用户态前先释放管理器锁。
            drop(managers);

            // 把消息类型写回用户缓冲区开头的 mtype 字段。
            if try_write_user_value(token, msgp as *mut i64, &msg_type).is_err() {
                return err(SyscallError::EFAULT);
            }
            // 把消息体写到 mtype 之后的位置。
            if try_copy_to_user(
                token,
                (msgp + core::mem::size_of::<i64>()) as *mut u8,
                &payload,
            )
            .is_err()
            {
                return err(SyscallError::EFAULT);
            }
            // 返回实际接收的消息体字节数。
            return copy_len as isize;
        }

        // 没有匹配消息：非阻塞模式返回 ENOMSG。
        if (msgflg & IPC_NOWAIT) != 0 {
            return err(SyscallError::ENOMSG);
        }
        // 阻塞前检查挂起信号。
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        let Some(task) = current_task() else {
            return err(SyscallError::EINVAL);
        };
        // 登记到「接收等待者」队列，释放锁后阻塞，等待发送方唤醒。
        add_waiter_once(&mut queue.recv_waiters, &task);
        drop(managers);
        block_current_and_run_next();
        waited = true;
        // 被唤醒后：信号中断返回 EINTR，否则回到循环顶部重新挑选消息。
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
    }
}
