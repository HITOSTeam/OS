//! POSIX 消息队列——核心数据结构与队列生命周期管理
//!
//! 本文件定义并实现消息队列子系统的所有核心对象：
//!
//! - **`MqMessage`**：单条消息，携带优先级和字节载荷。
//! - **`MqQueueState`**（由 `Mutex` 保护）：队列的动态运行时状态，包含消息链表、
//!   阻塞等待者列表（收/发两路）、epoll 等待者，以及 `mq_notify` 注册记录。
//! - **`MqQueue`**：队列对象本体，`name`（命名）与 `state`（消息收发状态）使用
//!   独立的 `Mutex` 保护，使 `mq_unlink` 不会干扰正在进行的消息收发。
//! - **`MqManager`**（per-IPC-namespace）：维护 `name→id` 和 `id→Arc<MqQueue>`
//!   两张索引，支持按名称查找与按 ID 回收。
//! - **`MQ_MANAGERS`**：全局静态表，以 IPC 命名空间 ID 为键，队列在命名空间间完全隔离。
//! - **`Cred` / `MqPerm` / `check_access`**：Unix DAC 权限模型的轻量实现。
//! - **等待者工具**：`add_waiter_once`、`wake_all_waiters`、`wake_poll_waiters`、
//!   `retain_blocked_waiters`，供收发路径在阻塞/唤醒时使用。
//! - **GC**：`gc_unlinked_queue`——当队列已被 unlink 且无任何 fd 引用时，
//!   从 `by_id` 中删除对象，完成最终回收。
//! - **sysctl**：`write_mqueue_sysctl` / `queues_max_limit_for_procfs`，
//!   处理对 `/proc/sys/fs/mqueue/queues_max` 的读写。

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use lazy_static::lazy_static;
use spin::Mutex;

use super::abi::{MQ_DEFAULT_QUEUES_MAX, MQ_HARD_QUEUES_MAX, PROCFS_QUEUES_MAX};
use super::notify::NotifyRegistration;
use crate::fs::{PollWaitQueue, parse_proc_sys_usize, wake_tasks};
use crate::syscall::error::{SyscallError, err};
use crate::task::manager::wakeup_task;
use crate::task::processor::current_process;
use crate::task::task_block::{TaskControlBlock, TaskStatus};

// 运行时可通过 /proc/sys/fs/mqueue/queues_max 调整，默认值见 MQ_DEFAULT_QUEUES_MAX
static MQ_QUEUES_MAX_LIMIT: AtomicUsize = AtomicUsize::new(MQ_DEFAULT_QUEUES_MAX);

/// 当前进程的凭证快照，用于权限判断
/// 使用固定大小数组避免在权限检查路径上堆分配
#[derive(Clone, Copy)]
pub(super) struct Cred {
    pub(super) uid: u32,
    pub(super) euid: u32, // 有效用户 ID，权限判断以此为准
    pub(super) egid: u32, // 有效组 ID
    groups: [u32; 8],     // 补充组列表（最多取前 8 个）
    groups_len: usize,
    pub(super) pid: usize,
}

/// 从当前进程捕获凭证快照
pub(super) fn current_cred() -> Cred {
    let proc = current_process();
    let inner = proc.borrow_mut();
    let mut groups = [0u32; 8];
    let mut groups_len = 0usize;
    for gid in inner.supplementary_gids.iter().copied().take(groups.len()) {
        groups[groups_len] = gid;
        groups_len += 1;
    }
    Cred {
        uid: inner.uid,
        euid: inner.euid,
        egid: inner.egid,
        groups,
        groups_len,
        pid: proc.getpid(),
    }
}

/// 消息队列的所有权与权限位，类似 inode 权限
#[derive(Clone, Copy)]
pub(super) struct MqPerm {
    pub(super) uid: u32,  // 创建者的 euid
    pub(super) gid: u32,  // 创建者的 egid
    pub(super) mode: u16, // 权限位，低 9 位（rwxrwxrwx），由 mq_open 的 mode 参数决定
}

/// 判断当前凭证是否为队列所有者或 root，用于 mq_unlink 权限检查
///
/// # 参数
/// - `perm`：队列的权限元数据（仅用到 `uid`）
/// - `cred`：调用方凭证快照
pub(super) fn is_owner_or_root(perm: &MqPerm, cred: &Cred) -> bool {
    cred.euid == 0 || cred.euid == perm.uid
}

/// 按照 Unix DAC 模型检查读/写访问权限
/// class_shift: owner=6, group=3, other=0，对应 mode 中三组权限位的偏移
///
/// # 参数
/// - `perm`：队列的所有者/组/mode 元数据
/// - `cred`：调用方凭证（含补充组列表）
/// - `need_read`：本次访问是否需要读权限
/// - `need_write`：本次访问是否需要写权限
pub(super) fn check_access(perm: &MqPerm, cred: &Cred, need_read: bool, need_write: bool) -> bool {
    if cred.euid == 0 {
        return true;
    }
    let class_shift = if cred.euid == perm.uid {
        6 // 属主
    } else if cred.egid == perm.gid
        || cred.groups[..cred.groups_len]
            .iter()
            .copied()
            .any(|g| g == perm.gid)
    {
        3 // 属组
    } else {
        0 // 其他
    };
    let mut need = 0usize;
    if need_read {
        need |= 0b100;
    }
    if need_write {
        need |= 0b010;
    }
    let allow = ((perm.mode as usize) >> class_shift) & 0x7;
    (allow & need) == need
}

/// 队列中的单条消息
#[derive(Clone)]
pub(super) struct MqMessage {
    pub(super) prio: u32,     // 消息优先级，队列按降序排列（高优先级先出）
    pub(super) data: Vec<u8>, // 消息内容
}

/// 队列的动态状态，所有并发访问通过外层 Mutex 保护
pub(super) struct MqQueueState {
    pub(super) perm: MqPerm,
    pub(super) maxmsg: usize,  // 队列容量上限（创建时确定，不可更改）
    pub(super) msgsize: usize, // 单条消息最大字节数（创建时确定，不可更改）
    // 消息按优先级降序存放：高优先级在队列头，同优先级 FIFO
    pub(super) messages: VecDeque<MqMessage>,
    // 等待接收的阻塞任务列表（队列为空时阻塞）
    pub(super) recv_waiters: VecDeque<Weak<TaskControlBlock>>,
    // 等待发送的阻塞任务列表（队列已满时阻塞）
    pub(super) send_waiters: VecDeque<Weak<TaskControlBlock>>,
    // epoll/select 等待者，消息可读/可写状态变化时唤醒
    pub(super) poll_waiters: PollWaitQueue,
    // 异步通知注册，消息从空变非空时触发一次后自动清除
    pub(super) notify: Option<NotifyRegistration>,
}

/// 单个 POSIX 消息队列对象
/// name 与 state 分别用独立 Mutex 保护：unlink 只需锁 name，不干扰消息收发
pub(super) struct MqQueue {
    pub(super) id: usize,                   // 全局唯一 ID，用于 by_id 索引
    pub(super) ipc_ns_id: usize,            // 所属 IPC 命名空间 ID，队列不跨命名空间可见
    pub(super) name: Mutex<Option<String>>, // unlink 后置为 None，GC 据此判断是否可回收
    pub(super) state: Mutex<MqQueueState>,
}

/// 每个 IPC 命名空间的队列管理器，维护 name→id 和 id→queue 两张索引
#[derive(Default)]
pub(super) struct MqManager {
    pub(super) next_id: usize,
    pub(super) by_id: BTreeMap<usize, Arc<MqQueue>>,
    pub(super) by_name: BTreeMap<String, usize>,
}

impl MqManager {
    /// 分配一个未使用的队列 ID（从 1 开始，跳过已占用的）
    pub(super) fn alloc_id(&mut self) -> usize {
        if self.next_id == 0 {
            self.next_id = 1;
        }
        while self.by_id.contains_key(&self.next_id) {
            self.next_id += 1;
        }
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

lazy_static! {
    // 以 IPC 命名空间 ID 为键，每个命名空间维护独立的 MqManager
    // POSIX MQ 对象在命名空间间完全隔离
    pub(super) static ref MQ_MANAGERS: Mutex<BTreeMap<usize, MqManager>> = Mutex::new(BTreeMap::new());
}

/// 对已 unlink（name 为 None）且无其他 fd 引用的队列执行垃圾回收
/// strong_count <= 2：一个来自 by_id，一个来自当前调用方的临时 Arc
///
/// # 参数
/// - `queue`：调用方持有的队列 `Arc`，决定 `strong_count` 的判断阈值
pub(super) fn gc_unlinked_queue(queue: &Arc<MqQueue>) {
    let mut managers = MQ_MANAGERS.lock();
    let Some(mgr) = managers.get_mut(&queue.ipc_ns_id) else {
        return;
    };
    let queue_id = queue.id;
    let should_remove = {
        let Some(queue) = mgr.by_id.get(&queue_id) else {
            return;
        };
        let no_name = queue.name.lock().is_none();
        no_name && Arc::strong_count(queue) <= 2
    };
    if should_remove {
        mgr.by_id.remove(&queue_id);
    }
}

/// 清理等待列表中已不处于 Blocked 状态的任务（例如被信号唤醒后自行退出等待）
///
/// # 参数
/// - `waiters`：发送 / 接收 / poll 等待者列表，将就地剔除已死亡或非 Blocked 项
fn retain_blocked_waiters(waiters: &mut VecDeque<Weak<TaskControlBlock>>) {
    waiters.retain(|w| {
        let Some(task) = w.upgrade() else {
            return false;
        };
        let inner = task.borrow_mut();
        inner.task_status == TaskStatus::Blocked
    });
}

/// 将任务加入等待列表，若已在列表中则不重复添加
///
/// # 参数
/// - `waiters`：目标等待列表（队列的 `recv_waiters` 或 `send_waiters`）
/// - `task`：当前阻塞的任务，弱引用形式持有
pub(super) fn add_waiter_once(
    waiters: &mut VecDeque<Weak<TaskControlBlock>>,
    task: &Arc<TaskControlBlock>,
) {
    if waiters
        .iter()
        .any(|w| w.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
    {
        return;
    }
    waiters.push_back(Arc::downgrade(task));
}

/// 唤醒等待列表中所有仍处于 Blocked 状态的任务
///
/// # 参数
/// - `waiters`：被消费（drain）的等待列表
pub(super) fn wake_all_waiters(waiters: &mut VecDeque<Weak<TaskControlBlock>>) {
    retain_blocked_waiters(waiters);
    let mut wake = Vec::new();
    for waiter in waiters.drain(..) {
        if let Some(task) = waiter.upgrade() {
            wake.push(task);
        }
    }
    for task in wake {
        wakeup_task(task);
    }
}

/// 唤醒所有通过 epoll/select 等待该队列的任务
///
/// # 参数
/// - `state`：调用方已持锁的队列状态，从中取走 poll 唤醒列表
pub(super) fn wake_poll_waiters(state: &mut MqQueueState) {
    let waiters = state.poll_waiters.take_wakeups();
    wake_tasks(waiters);
}

/// 读取当前生效的队列数量上限
///
/// 单纯封装对 `MQ_QUEUES_MAX_LIMIT` 的 atomic load，便于在 hot path 上调用。
/// 该值可被 `/proc/sys/fs/mqueue/queues_max` 修改，初始为 `MQ_DEFAULT_QUEUES_MAX`。
fn mq_queues_max_limit() -> usize {
    MQ_QUEUES_MAX_LIMIT.load(Ordering::Relaxed)
}

/// procfs 视图下当前生效的队列数量上限
///
/// 由 `/proc/sys/fs/mqueue/queues_max` 的 read 路径调用，对外暴露为 `pub`，
/// 内部直接复用 `mq_queues_max_limit`。
pub fn queues_max_limit_for_procfs() -> usize {
    mq_queues_max_limit()
}

/// 处理对 /proc/sys/fs/mqueue/queues_max 的写操作
/// 值必须在 [1, MQ_HARD_QUEUES_MAX] 范围内，否则返回 EINVAL
///
/// # 参数
/// - `path`：sysctl 文件路径，必须是 `PROCFS_QUEUES_MAX`，否则拒绝
/// - `data`：用户写入的字节流，按十进制 usize 解析
pub fn write_mqueue_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    if path != PROCFS_QUEUES_MAX {
        return Err(err(SyscallError::EINVAL));
    }
    let value = parse_proc_sys_usize(data)?;
    if !(1..=MQ_HARD_QUEUES_MAX).contains(&value) {
        return Err(err(SyscallError::EINVAL));
    }
    MQ_QUEUES_MAX_LIMIT.store(value, Ordering::Relaxed);
    Ok(alloc::format!("{}\n", value).into_bytes())
}

/// 返回编译期定义的队列数量默认上限
///
/// 与 `mq_queues_max_limit()` 不同：此值不受 sysctl 影响，常用于
/// 测试或重置 sysctl 时回退到出厂默认。
#[allow(dead_code)]
pub fn mq_queues_default_limit() -> usize {
    MQ_DEFAULT_QUEUES_MAX
}
