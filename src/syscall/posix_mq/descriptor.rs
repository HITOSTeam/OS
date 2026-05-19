//! POSIX 消息队列——文件描述符（`MqDescriptor`）
//!
//! `MqDescriptor` 是消息队列的内核侧文件描述符对象，实现了 `File` trait，
//! 使消息队列可以像普通文件描述符一样参与 epoll/select/poll 事件监听。
//!
//! 每次 `mq_open` 产生一个独立的 `MqDescriptor`，多个描述符可共享同一个 `MqQueue`。
//! 该对象记录了此次打开的访问模式（readable/writable）和 O_NONBLOCK 标志，
//! 并在 `drop` 时自动清理该进程在队列上的 `mq_notify` 注册及可能的 GC。

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};

use super::abi::O_NONBLOCK;
use super::notify::maybe_clear_notify_for_owner;
use super::object::{MqQueue, MqQueueState, gc_unlinked_queue};
use crate::fs::{File, POLLIN, POLLOUT};
use crate::mm::UserBuffer;
use crate::task::task_block::TaskControlBlock;

/// 消息队列文件描述符，实现 File trait，可参与 epoll/select
/// 每个 mq_open 调用产生一个独立的 MqDescriptor，共享同一个 MqQueue
pub struct MqDescriptor {
    pub(super) queue: Arc<MqQueue>,
    pub(super) readable: bool,
    pub(super) writable: bool,
    flags: AtomicU32, // 运行时可修改的标志（目前只有 O_NONBLOCK）
    owner_pid: usize, // 记录打开该 fd 的进程，用于 drop 时清除 notify 注册
}

impl MqDescriptor {
    /// 构造一个新的消息队列描述符
    ///
    /// 只在 `mq_open` 成功获得共享 `MqQueue` 之后调用：
    /// `readable`/`writable` 由打开模式（O_RDONLY/WRONLY/RDWR）决定，
    /// `nonblock` 来自 O_NONBLOCK，`owner_pid` 用于 `Drop` 时清除该进程的 notify 注册。
    ///
    /// # 参数
    /// - `queue`：本次打开所引用的共享队列对象
    /// - `readable`：是否允许 `mq_timedreceive`
    /// - `writable`：是否允许 `mq_timedsend`
    /// - `nonblock`：是否设置 O_NONBLOCK（运行时仍可由 `mq_getsetattr` 修改）
    /// - `owner_pid`：打开该 fd 的进程 pid，用于 Drop 时定向清理 mq_notify 注册
    pub(super) fn new(
        queue: Arc<MqQueue>,
        readable: bool,
        writable: bool,
        nonblock: bool,
        owner_pid: usize,
    ) -> Self {
        let mut flags = 0u32;
        if nonblock {
            flags |= O_NONBLOCK as u32;
        }
        Self {
            queue,
            readable,
            writable,
            flags: AtomicU32::new(flags),
            owner_pid,
        }
    }

    /// 当前 fd 是否处于 O_NONBLOCK 模式
    ///
    /// 该标志可被 `mq_getsetattr` 在运行时切换，因此使用原子读取避免加锁。
    pub(super) fn nonblock(&self) -> bool {
        (self.flags.load(Ordering::Relaxed) & (O_NONBLOCK as u32)) != 0
    }

    /// 设置 / 清除 O_NONBLOCK 标志（由 `mq_getsetattr` 调用）
    pub(super) fn set_nonblock(&self, enabled: bool) {
        if enabled {
            self.flags.fetch_or(O_NONBLOCK as u32, Ordering::Relaxed);
        } else {
            self.flags
                .fetch_and(!(O_NONBLOCK as u32), Ordering::Relaxed);
        }
    }

    /// 根据队列当前状态计算 poll 事件掩码
    /// 需要在调用方持有 state 锁的情况下调用，避免二次加锁
    ///
    /// # 参数
    /// - `state`：调用方已持有的 `MqQueueState` 借用
    fn poll_mask_from_state(&self, state: &MqQueueState) -> i16 {
        let mut mask = 0;
        if self.readable && !state.messages.is_empty() {
            mask |= POLLIN;
        }
        if self.writable && state.messages.len() < state.maxmsg {
            mask |= POLLOUT;
        }
        mask
    }
}

impl Drop for MqDescriptor {
    fn drop(&mut self) {
        // 关闭 fd 时，清除属于当前进程的 notify 注册（POSIX 要求）
        maybe_clear_notify_for_owner(&self.queue, self.owner_pid);
        // 若队列已被 unlink 且无其他 fd 引用，释放队列对象
        gc_unlinked_queue(&self.queue);
    }
}

impl File for MqDescriptor {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    // mq 不支持通过 read/write 系统调用收发消息，必须使用专用的 mq_* 接口
    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn poll_mask(&self) -> i16 {
        let state = self.queue.state.lock();
        self.poll_mask_from_state(&state)
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut state = self.queue.state.lock();
        // 在锁内同时检查状态并注册等待者，避免先检查后注册之间发生状态变化
        if self.poll_mask_from_state(&state) != 0 {
            return true;
        }
        state.poll_waiters.register_waiter(task)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
