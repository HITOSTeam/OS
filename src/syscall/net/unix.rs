//! AF_UNIX（本地套接字）实现模块。
//!
//! 本模块负责：
//! - 维护路径绑定（`UNIX_BOUND_PATHS`）和抽象命名空间绑定（`UNIX_BOUND_ABSTRACT`）两张全局注册表；
//! - 实现面向流的 socket（SOCK_STREAM / SOCK_SEQPACKET）和数据报 socket（SOCK_DGRAM）；
//! - 处理 `bind` / `connect` / `send` / `recv` / `accept` 的内核侧逻辑；
//! - 提供 `SockAddrUn` ABI 结构体及其与内核表示之间的转换辅助函数。

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::mem::size_of;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::{
    File, POLLIN, POLLOUT, PollWaitQueue, SocketPairEnd, ext4_lock, find_path_in_roots,
    make_socketpair, wake_tasks,
};
use crate::mm::{
    UserBuffer, try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value,
};
use crate::syscall::error::{SyscallError, err};
use crate::syscall::filesystem::normalize_path;
use crate::task::processor::{current_process, suspend_current_and_run_next};
use crate::task::task_block::TaskControlBlock;
use crate::trap::get_current_token;

use super::*;

/// 指向 `File` trait 对象的弱引用别名，用于注册表中持有 socket 而不阻止其释放。
type FileWeak = Weak<dyn File + Send + Sync>;

/// AF_UNIX socket 的绑定地址，对应 POSIX 定义的两种命名空间。
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum UnixBoundAddr {
    /// 文件系统路径绑定：内核在 bind 时会在文件系统中创建占位文件，socket 释放时不自动删除该文件。
    Path(String),
    /// 抽象命名空间绑定：`sun_path` 首字节为 `\0`，名称仅存在于内核注册表中，不产生任何文件系统条目，
    /// socket 关闭后名称随之消失，无需手动清理文件。
    Abstract(Vec<u8>),
}

lazy_static! {
    /// 路径绑定注册表：将文件系统路径映射到对应 socket 的弱引用。
    /// 使用 `Weak` 而非 `Arc` 是为了让 socket 在最后一个强引用消失时能自动 drop，
    /// 无需调用方显式注销——`Drop for UnixSocketFile` 会主动清除条目，
    /// 但即便忘记清除，`Weak::upgrade()` 失败后查找函数也会惰性删除过期条目。
    static ref UNIX_BOUND_PATHS: Mutex<BTreeMap<String, FileWeak>> = Mutex::new(BTreeMap::new());
    /// 抽象命名空间注册表：将抽象名称（不含首部 `\0`）映射到 socket 的弱引用。
    /// 设计原因与 `UNIX_BOUND_PATHS` 相同，参见上方注释。
    static ref UNIX_BOUND_ABSTRACT: Mutex<BTreeMap<Vec<u8>, FileWeak>> =
        Mutex::new(BTreeMap::new());
}

/// 一条 UNIX 数据报消息，保存在接收队列中直至被 `recv_dgram` 取走。
pub(super) struct UnixDatagram {
    /// 发送方的绑定地址；未绑定的发送方为 `None`，接收方据此决定是否能回复。
    pub(super) from: Option<UnixBoundAddr>,
    /// 报文有效载荷，完整保留（数据报不做流式拆分）。
    pub(super) payload: Vec<u8>,
}

/// `UnixSocketFile` 的可变状态，由 `Mutex` 保护，集中管理所有运行时字段。
pub(super) struct UnixSocketState {
    /// socket 当前绑定的地址，`None` 表示尚未 bind。
    bound: Option<UnixBoundAddr>,
    /// 是否已进入监听状态（stream 类型调用 `listen` 后置 true）。
    listening: bool,
    /// 监听队列上限，对应 `listen(backlog)`，内部钳位到 [1, 32]。
    backlog: usize,
    /// 等待 `accept` 的已连接 socket 队列；由 `connect_unix` 的发起方填入，`accept_stream` 取走。
    pending_accept: VecDeque<Arc<UnixSocketFile>>,
    /// stream 模式下持有的 `SocketPairEnd`，数据读写通过它转发给对端。
    stream_end: Option<Arc<SocketPairEnd>>,
    /// 对端地址（stream 连接后由 `connect_unix` 填入，或 dgram `connect` 后记录默认目标）。
    peer_addr: Option<UnixBoundAddr>,
    /// 对端进程凭证，连接时由内核填入，供 `SO_PEERCRED` 查询使用。
    peer_cred: Option<UCred>,
    /// dgram 模式下 `connect` 设定的默认发送目标，省去每次 `sendto` 都指定地址。
    dgram_peer: Option<UnixBoundAddr>,
    /// dgram 接收队列，按到达顺序存放，由 `send_dgram` 写入、`recv_dgram` 消费。
    pub(super) dgram_queue: VecDeque<UnixDatagram>,
    /// 注册了 poll 等待的任务列表，用于在状态变化时批量唤醒。
    poll_waiters: PollWaitQueue,
}

impl UnixSocketState {
    fn new() -> Self {
        Self {
            bound: None,
            listening: false,
            backlog: 1,
            pending_accept: VecDeque::new(),
            stream_end: None,
            peer_addr: None,
            peer_cred: None,
            dgram_peer: None,
            dgram_queue: VecDeque::new(),
            poll_waiters: PollWaitQueue::default(),
        }
    }
}

pub(crate) struct UnixSocketFile {
    sock_type: usize,
    pub(super) state: Mutex<UnixSocketState>,
}

impl UnixSocketFile {
    /// 创建一个未绑定、未连接的空白 Unix socket。
    pub(super) fn new(sock_type: usize) -> Self {
        Self {
            sock_type,
            state: Mutex::new(UnixSocketState::new()),
        }
    }

    /// 创建一条已完成握手的 stream socket，供 `connect_unix` 在服务端 `pending_accept` 中插入。
    ///
    /// 此函数不走 bind/listen 流程，直接持有 `server_end`，因此创建后即可读写。
    fn new_connected_stream(
        sock_type: usize,
        stream_end: Arc<SocketPairEnd>,
        peer_addr: Option<UnixBoundAddr>,
        peer_cred: Option<UCred>,
    ) -> Self {
        let mut state = UnixSocketState::new();
        state.stream_end = Some(stream_end);
        state.peer_addr = peer_addr;
        state.peer_cred = peer_cred;
        Self {
            sock_type,
            state: Mutex::new(state),
        }
    }

    /// 判断是否为面向流的类型（SOCK_STREAM 或 SOCK_SEQPACKET）。
    pub(super) fn is_stream_like(&self) -> bool {
        matches!(self.sock_type, SOCK_STREAM | SOCK_SEQPACKET)
    }

    /// 判断是否为数据报类型（SOCK_DGRAM）。
    pub(super) fn is_dgram(&self) -> bool {
        self.sock_type == SOCK_DGRAM
    }

    /// 返回当前绑定地址的克隆，用于在 connect 时告知对端自己的标识。
    pub(super) fn bound_addr(&self) -> Option<UnixBoundAddr> {
        self.state.lock().bound.clone()
    }

    fn set_bound_addr(&self, addr: UnixBoundAddr) {
        self.state.lock().bound = Some(addr);
    }

    /// 返回对端地址：stream 连接优先，dgram 默认目标次之。
    pub(super) fn peer_addr(&self) -> Option<UnixBoundAddr> {
        let st = self.state.lock();
        st.peer_addr.clone().or_else(|| st.dgram_peer.clone())
    }

    /// 返回对端进程凭证，供 `SO_PEERCRED` 使用。
    pub(super) fn peer_cred(&self) -> Option<UCred> {
        self.state.lock().peer_cred
    }

    /// 批量唤醒所有等待此 socket 事件的任务（如 accept 就绪、连接完成）。
    fn notify_poll_waiters(&self) {
        let waiters = self.state.lock().poll_waiters.take_wakeups();
        wake_tasks(waiters);
    }

    /// 将 socket 置为监听状态，`backlog` 会被钳位到 [1, 32] 以防过大的队列占用资源。
    ///
    /// 必须先 bind 才能 listen；通知已在等待的 poll 调用方（如 select/epoll）。
    pub(super) fn set_listening(&self, backlog: usize) -> isize {
        if !self.is_stream_like() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let mut st = self.state.lock();
        if st.bound.is_none() {
            return err(SyscallError::EINVAL);
        }
        st.listening = true;
        st.backlog = backlog.max(1).min(32);
        drop(st);
        self.notify_poll_waiters();
        0
    }

    /// 从 `pending_accept` 队列中取出一条已完成连接的 socket 并返回给调用方。
    ///
    /// 队列为空时调用 `suspend_current_and_run_next` 让出 CPU，等待 `connect_unix` 插入新连接后
    /// 被 `wake_tasks` 唤醒再重试，实现阻塞语义。
    pub(super) fn accept_stream(&self) -> Result<Arc<UnixSocketFile>, isize> {
        if !self.is_stream_like() {
            return Err(err(SyscallError::EOPNOTSUPP));
        }
        loop {
            let mut st = self.state.lock();
            if !st.listening {
                return Err(err(SyscallError::EINVAL));
            }
            if let Some(conn) = st.pending_accept.pop_front() {
                return Ok(conn);
            }
            // 队列为空，主动挂起当前任务，等待 connect 端插入连接后唤醒
            drop(st);
            suspend_current_and_run_next();
        }
    }

    /// 发起连接请求，根据 socket 类型走不同分支：
    ///
    /// **stream 路径**：
    /// 1. 调用 `make_socketpair` 创建 `(client_end, server_end)` 双向管道；
    /// 2. 把 `server_end` 包装成新的 `UnixSocketFile`，推入服务端的 `pending_accept` 队列，
    ///    并唤醒在服务端 poll 的任务（让 `accept_stream` 返回）；
    /// 3. 本端持有 `client_end`，连接完成后可直接读写。
    ///
    /// **dgram 路径**：仅记录默认发送目标，不建立任何双向通道。
    pub(super) fn connect_unix(&self, addr: UnixBoundAddr) -> isize {
        if self.is_stream_like() {
            {
                let st = self.state.lock();
                if st.stream_end.is_some() {
                    return err(SyscallError::EISCONN);
                }
            }
            let peer_file = match lookup_unix_bound_socket(&addr) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
                return err(SyscallError::ECONNREFUSED);
            };
            if !peer.is_stream_like() {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            let (client_end, server_end) = make_socketpair();
            let client_bound = self.bound_addr();
            let client_cred = current_unix_ucred();
            {
                let mut peer_st = peer.state.lock();
                if !peer_st.listening {
                    return err(SyscallError::ECONNREFUSED);
                }
                // 检查 backlog 上限，超出则拒绝，避免服务端队列无限增长
                if peer_st.pending_accept.len() >= peer_st.backlog {
                    return err(SyscallError::ECONNREFUSED);
                }
                // 将 server_end 包装为一个已连接的 socket，放入服务端 accept 队列
                let accepted = Arc::new(UnixSocketFile::new_connected_stream(
                    self.sock_type,
                    server_end,
                    client_bound,
                    Some(client_cred),
                ));
                peer_st.pending_accept.push_back(accepted);
                // 唤醒可能正在 accept_stream 中挂起的服务端任务
                let wake = peer_st.poll_waiters.take_wakeups();
                drop(peer_st);
                wake_tasks(wake);
            }
            let mut st = self.state.lock();
            // 释放锁后重新检查，防止并发 connect 导致重复连接
            if st.stream_end.is_some() {
                return err(SyscallError::EISCONN);
            }
            st.stream_end = Some(client_end);
            st.peer_addr = Some(addr);
            drop(st);
            self.notify_poll_waiters();
            return 0;
        }
        if !self.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let peer_file = match lookup_unix_bound_socket(&addr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
            return err(SyscallError::ECONNREFUSED);
        };
        if !peer.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        // dgram connect 仅记录默认目标，不建立真正的连接状态
        let mut st = self.state.lock();
        st.dgram_peer = Some(addr.clone());
        st.peer_addr = Some(addr);
        0
    }

    /// 发送一条数据报到 `target`（若 `target` 为 `None` 则使用 `connect` 设置的默认目标）。
    ///
    /// 发送成功后立即唤醒接收方的 poll 等待任务，使其能及时从 `dgram_queue` 取走数据。
    /// 返回实际发送的字节数，出错返回负的 errno。
    pub(super) fn send_dgram(&self, payload: Vec<u8>, target: Option<UnixBoundAddr>) -> isize {
        if !self.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let (to, from) = {
            let st = self.state.lock();
            // 优先使用调用方传入的显式目标，其次回退到 connect 记录的默认目标
            let Some(to) = target.or_else(|| st.dgram_peer.clone()) else {
                return err(SyscallError::EINVAL);
            };
            (to, st.bound.clone())
        };
        let peer_file = match lookup_unix_bound_socket(&to) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
            return err(SyscallError::ECONNREFUSED);
        };
        if !peer.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let n = payload.len();
        let wake = {
            let mut peer_st = peer.state.lock();
            peer_st
                .dgram_queue
                .push_back(UnixDatagram { from, payload });
            peer_st.poll_waiters.take_wakeups()
        };
        wake_tasks(wake);
        n as isize
    }

    /// 从 `dgram_queue` 中取出最早到达的一条数据报。
    ///
    /// 队列为空时挂起当前任务，等待 `send_dgram` 写入后唤醒。
    pub(super) fn recv_dgram(&self) -> UnixDatagram {
        loop {
            let mut st = self.state.lock();
            if let Some(msg) = st.dgram_queue.pop_front() {
                return msg;
            }
            // 队列为空，让出 CPU 等待发送方填入数据
            drop(st);
            suspend_current_and_run_next();
        }
    }

    /// 返回 stream socket 持有的管道端点，供上层读写操作使用。
    pub(super) fn stream_end(&self) -> Option<Arc<SocketPairEnd>> {
        self.state.lock().stream_end.clone()
    }

    /// 判断 socket 当前是否可读（有数据或有等待 accept 的连接）。
    ///
    /// stream 监听中：`pending_accept` 非空即可读；已连接：委托给 `SocketPairEnd`。
    /// dgram：`dgram_queue` 非空即可读。
    pub(crate) fn poll_readable(&self) -> bool {
        if self.is_stream_like() {
            let (listening, pending_accept, stream_end) = {
                let st = self.state.lock();
                (
                    st.listening,
                    !st.pending_accept.is_empty(),
                    st.stream_end.clone(),
                )
            };
            if listening {
                return pending_accept;
            }
            if let Some(end) = stream_end {
                return end.poll_readable();
            }
            return false;
        }
        if self.is_dgram() {
            return !self.state.lock().dgram_queue.is_empty();
        }
        false
    }

    /// 判断 socket 当前是否可写。
    ///
    /// stream 监听状态不可写；已连接时委托给 `SocketPairEnd`。
    /// dgram 始终可写（目标地址合法性在 `send_dgram` 中校验）。
    #[allow(dead_code)]
    pub(crate) fn poll_writable(&self) -> bool {
        if self.is_stream_like() {
            let (listening, stream_end) = {
                let st = self.state.lock();
                (st.listening, st.stream_end.clone())
            };
            if listening {
                return false;
            }
            if let Some(end) = stream_end {
                return end.poll_writable();
            }
            return false;
        }
        if self.is_dgram() {
            return true;
        }
        false
    }
}

impl Drop for UnixSocketFile {
    /// socket 关闭时从全局注册表中移除绑定条目。
    ///
    /// 必须在 drop 时主动清理，否则绑定的路径或抽象名称在注册表中永久残留，
    /// 导致后续同名 bind 报 EADDRINUSE（即使原 socket 已不存在）。
    /// 路径绑定仅清理注册表条目，文件系统中的占位文件不在此处删除。
    fn drop(&mut self) {
        if let Some(bound) = self.state.lock().bound.take() {
            match bound {
                UnixBoundAddr::Path(path) => {
                    UNIX_BOUND_PATHS.lock().remove(&path);
                }
                UnixBoundAddr::Abstract(name) => {
                    UNIX_BOUND_ABSTRACT.lock().remove(&name);
                }
            }
        }
    }
}

impl File for UnixSocketFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        if self.is_stream_like() {
            if let Some(end) = self.stream_end() {
                return end.read(buf);
            }
            return 0;
        }
        if !self.is_dgram() {
            return 0;
        }
        let msg = self.recv_dgram();
        copy_slice_to_user_buffer(buf, &msg.payload)
    }

    fn write(&self, buf: UserBuffer) -> usize {
        if self.is_stream_like() {
            if let Some(end) = self.stream_end() {
                return end.write(buf);
            }
            return 0;
        }
        if !self.is_dgram() {
            return 0;
        }
        let payload = copy_user_buffer_to_vec(buf);
        if payload.is_empty() {
            return 0;
        }
        let n = payload.len();
        if self.send_dgram(payload, None) < 0 {
            return 0;
        }
        n
    }

    fn poll_mask(&self) -> i16 {
        if self.is_stream_like() {
            let (listening, pending_accept, stream_end) = {
                let st = self.state.lock();
                (
                    st.listening,
                    !st.pending_accept.is_empty(),
                    st.stream_end.clone(),
                )
            };
            if listening {
                return if pending_accept { POLLIN } else { 0 };
            }
            if let Some(end) = stream_end {
                return end.poll_mask();
            }
            return 0;
        }
        if self.is_dgram() {
            let mut mask = POLLOUT;
            if !self.state.lock().dgram_queue.is_empty() {
                mask |= POLLIN;
            }
            return mask;
        }
        0
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        if self.is_stream_like() {
            let mut st = self.state.lock();
            let _ = st.poll_waiters.register_waiter(task);
            if st.listening {
                return true;
            }
            let end = st.stream_end.clone();
            drop(st);
            if let Some(end) = end.as_ref() {
                let _ = end.register_poll_waiter(task);
            }
            return true;
        }
        if self.is_dgram() {
            let mut st = self.state.lock();
            let _ = st.poll_waiters.register_waiter(task);
            return true;
        }
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// POSIX `struct sockaddr_un` 的内核侧 ABI 表示，布局必须与用户空间完全一致。
///
/// `sun_path` 固定 108 字节，源自历史 BSD 约定；超出此长度的路径会被截断。
/// 路径有两种解读方式：
/// - `sun_path[0] != 0`：以 NUL 结尾的文件系统路径；
/// - `sun_path[0] == 0`：抽象命名空间，实际名称为 `sun_path[1..]`（去除尾部多余 `\0`）。
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SockAddrUn {
    sun_family: u16,
    /// 固定 108 字节（POSIX ABI），路径或抽象名称存放于此。
    sun_path: [u8; 108],
}

/// 将绝对路径拆分为父目录和文件名，用于在父目录下创建 socket 占位文件。
///
/// 去除尾部多余 `/` 后再分割，以处理形如 `/tmp/sock/` 的输入。
/// 根路径 `/` 本身无法再拆分，返回 `None`。
fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }
    let (parent, name) = trimmed.rsplit_once('/')?;
    // rsplit_once 在路径为 "/foo" 时会产生空的 parent，需要还原为 "/"
    let parent = if parent.is_empty() { "/" } else { parent };
    if name.is_empty() {
        return None;
    }
    Some((parent, name))
}

/// 读取当前进程的有效 UID/GID 并打包为 `UCred`，供 `SO_PEERCRED` 使用。
fn current_unix_ucred() -> UCred {
    let proc = current_process();
    let inner = proc.borrow_mut();
    UCred {
        pid: proc.pid.0 as u32,
        uid: inner.euid as u32,
        gid: inner.egid as u32,
    }
}

/// 从用户空间读取 `sockaddr_un` 并解析为 `(is_abstract, 名称字节)` 二元组。
///
/// 地址类型由 `sun_path[0]` 决定：
/// - `sun_path[0] == 0`：抽象命名空间，名称为 `sun_path[1..]`，尾部多余的 `\0` 需要修剪，
///   因为用户空间通常用 `sizeof` 而非实际字符串长度传入 `addrlen`，会带来多余的零字节；
/// - `sun_path[0] != 0`：文件系统路径，取到第一个 `\0` 为止。
///
/// 只读取 `min(len, sizeof(SockAddrUn))` 字节，超出 ABI 大小的部分直接忽略。
fn parse_sockaddr_un(user_ptr: usize, len: usize) -> Result<(bool, Vec<u8>), isize> {
    if user_ptr == 0 || len < size_of::<u16>() {
        return Err(err(SyscallError::EINVAL));
    }
    if len > i32::MAX as usize {
        return Err(err(SyscallError::EINVAL));
    }
    // 最多读取一个完整的 SockAddrUn，用户传入更长的 len 也安全截断
    let to_copy = len.min(size_of::<SockAddrUn>());
    let token = get_current_token();
    let mut raw = vec![0u8; to_copy];
    if try_copy_from_user(token, user_ptr as *const u8, raw.as_mut_slice()).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    if family != AF_UNIX {
        return Err(err(SyscallError::EAFNOSUPPORT));
    }
    let path = &raw[size_of::<u16>()..];
    if path.is_empty() {
        return Err(err(SyscallError::EINVAL));
    }
    if path[0] == 0 {
        // 首字节为 \0 表示抽象命名空间；修剪尾部多余的 \0，避免把填充字节纳入名称
        let mut name = path[1..].to_vec();
        while matches!(name.last(), Some(0)) {
            name.pop();
        }
        if name.is_empty() {
            return Err(err(SyscallError::EINVAL));
        }
        return Ok((true, name));
    }
    // 文件系统路径：取到第一个 NUL 终止符，若不存在则取全部（内核侧容错）
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    if end == 0 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok((false, path[..end].to_vec()))
}

/// 将用户空间的 `sockaddr_un` 转换为内核的 `UnixBoundAddr`。
///
/// 路径类型会相对当前进程工作目录规范化为绝对路径，确保后续注册表查找结果一致。
pub(super) fn parse_unix_bound_addr(addr: usize, addrlen: usize) -> Result<UnixBoundAddr, isize> {
    let (is_abstract, raw_name) = parse_sockaddr_un(addr, addrlen)?;
    if is_abstract {
        return Ok(UnixBoundAddr::Abstract(raw_name));
    }
    let Ok(path_part) = core::str::from_utf8(&raw_name) else {
        return Err(err(SyscallError::EINVAL));
    };
    let cwd = { current_process().borrow_mut().cwd.clone() };
    // 相对路径需要结合 cwd 规范化，保证不同进程使用同一路径时能命中同一注册表条目
    let abs = normalize_path(&cwd, path_part);
    Ok(UnixBoundAddr::Path(abs))
}

/// 在全局注册表中查找指定地址对应的 socket 强引用。
///
/// 若找到条目但 `Weak::upgrade()` 失败，说明 socket 已 drop 但条目未被 `Drop` 清除
/// （理论上不应发生，但作为防御性措施），此时惰性删除过期条目。
fn lookup_unix_bound_socket(addr: &UnixBoundAddr) -> Result<FileArc, isize> {
    match addr {
        UnixBoundAddr::Path(path) => {
            let mut reg = UNIX_BOUND_PATHS.lock();
            let Some(weak) = reg.get(path) else {
                return Err(err(SyscallError::ENOENT));
            };
            if let Some(file) = weak.upgrade() {
                return Ok(file);
            }
            // Weak 已失效，惰性清除过期条目
            reg.remove(path);
            Err(err(SyscallError::ENOENT))
        }
        UnixBoundAddr::Abstract(name) => {
            let mut reg = UNIX_BOUND_ABSTRACT.lock();
            let Some(weak) = reg.get(name) else {
                return Err(err(SyscallError::ENOENT));
            };
            if let Some(file) = weak.upgrade() {
                return Ok(file);
            }
            // Weak 已失效，惰性清除过期条目
            reg.remove(name);
            Err(err(SyscallError::ENOENT))
        }
    }
}

/// 将 socket 以弱引用形式注册到全局注册表。
///
/// 若地址已被存活的 socket 占用则返回 EADDRINUSE；
/// 若旧条目的 Weak 已失效（对应 socket 已 drop），则替换旧条目以允许复用。
fn register_unix_bound_socket(addr: &UnixBoundAddr, file: &FileArc) -> isize {
    match addr {
        UnixBoundAddr::Path(path) => {
            let mut reg = UNIX_BOUND_PATHS.lock();
            if let Some(existing) = reg.get(path) {
                if existing.upgrade().is_some() {
                    return err(SyscallError::EADDRINUSE);
                }
                // 旧 socket 已释放，清除残留条目后允许重新注册
                reg.remove(path);
            }
            reg.insert(path.clone(), Arc::downgrade(file));
        }
        UnixBoundAddr::Abstract(name) => {
            let mut reg = UNIX_BOUND_ABSTRACT.lock();
            if let Some(existing) = reg.get(name) {
                if existing.upgrade().is_some() {
                    return err(SyscallError::EADDRINUSE);
                }
                // 旧 socket 已释放，清除残留条目后允许重新注册
                reg.remove(name);
            }
            reg.insert(name.clone(), Arc::downgrade(file));
        }
    }
    0
}

/// 将 socket 绑定到指定地址，区分文件系统路径和抽象命名空间两种情况。
///
/// **路径绑定流程**：
/// 1. 在文件系统中创建占位文件（使其在 `ls` 中可见，符合 POSIX 行为）；
/// 2. 向注册表注册；注册失败时回滚删除刚创建的文件，避免留下无主占位文件。
///
/// **抽象命名空间**：无文件系统操作，直接注册即可。
pub(super) fn bind_unix_socket(
    file: &FileArc,
    sock: &UnixSocketFile,
    addr: usize,
    addrlen: usize,
) -> isize {
    if sock.bound_addr().is_some() {
        return err(SyscallError::EINVAL);
    }
    let bound = match parse_unix_bound_addr(addr, addrlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let UnixBoundAddr::Path(abs) = &bound {
        let Some((parent_path, name)) = split_parent_and_name(abs) else {
            return err(SyscallError::EINVAL);
        };
        let _fs_guard = ext4_lock();
        let Some(parent) = find_path_in_roots(parent_path) else {
            return err(SyscallError::ENOENT);
        };
        if !parent.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        // 提前检查文件是否已存在，避免 create_file 返回模糊错误
        if parent.find(name).is_some() {
            return err(SyscallError::EADDRINUSE);
        }
        if parent.create_file(name).is_err() {
            // create_file 失败后再次检查：可能是并发 bind 抢先创建了同名文件
            if parent.find(name).is_some() {
                return err(SyscallError::EADDRINUSE);
            }
            return err(SyscallError::EINVAL);
        }
        let reg_result = register_unix_bound_socket(&bound, file);
        if reg_result != 0 {
            // 注册失败（如另一个 socket 已占用此路径），回滚删除刚创建的占位文件
            let _ = parent.unlink(name);
            return reg_result;
        }
    } else {
        let reg_result = register_unix_bound_socket(&bound, file);
        if reg_result != 0 {
            return reg_result;
        }
    }
    sock.set_bound_addr(bound);
    0
}

/// 将内核的 `UnixBoundAddr` 序列化为 `sockaddr_un` 并写回用户空间缓冲区。
///
/// 遵循 `getsockname` / `getpeername` / `recvfrom` 的写回约定：
/// - 只写入 `min(用户提供的 len, sizeof(SockAddrUn))` 字节（防止越界）；
/// - 始终将 `*addrlen` 更新为 `sizeof(SockAddrUn)`（即实际所需长度），
///   便于调用方判断缓冲区是否足够。
pub(super) fn write_sockaddr_un(
    user_ptr: usize,
    user_len_ptr: usize,
    addr: Option<&UnixBoundAddr>,
) -> isize {
    if user_ptr == 0 || user_len_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(len_u32) = try_read_user_value::<u32>(token, user_len_ptr as *const u32) else {
        return err(SyscallError::EFAULT);
    };
    let len = len_u32 as usize;
    if len > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    let mut sa = SockAddrUn {
        sun_family: AF_UNIX,
        sun_path: [0; 108],
    };
    if let Some(bound) = addr {
        match bound {
            UnixBoundAddr::Path(path) => {
                let raw = path.as_bytes();
                // 保留最后一字节为 NUL 终止符，路径过长时截断（POSIX 允许）
                let copy = raw.len().min(sa.sun_path.len().saturating_sub(1));
                sa.sun_path[..copy].copy_from_slice(&raw[..copy]);
            }
            UnixBoundAddr::Abstract(name) => {
                // 抽象地址：首字节固定为 \0，名称从下标 1 开始，过长时截断
                sa.sun_path[0] = 0;
                let copy = name.len().min(sa.sun_path.len().saturating_sub(1));
                sa.sun_path[1..1 + copy].copy_from_slice(&name[..copy]);
            }
        }
    }
    let required = size_of::<SockAddrUn>();
    let copy_len = core::cmp::min(len, required);
    if copy_len > 0 {
        // SAFETY: sa is a stack-local struct with known layout; copy_len <= size_of::<SockAddrUn>().
        let bytes = unsafe {
            core::slice::from_raw_parts((&sa as *const SockAddrUn) as *const u8, copy_len)
        };
        if try_copy_to_user(token, user_ptr as *mut u8, bytes).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    if try_write_user_value(token, user_len_ptr as *mut u32, &(required as u32)).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// 将发送方地址序列化为 `sockaddr_un` 并写入 `msghdr.msg_name`，供 `recvmsg` 返回给用户空间。
///
/// 与 `write_sockaddr_un` 的区别在于目标缓冲区来自 `MsgHdr`，
/// 写入逻辑委托给 `write_msg_name_bytes`，后者负责长度校验和实际复制。
pub(super) fn write_msg_name_un(msg: &mut MsgHdr, addr: Option<&UnixBoundAddr>) -> isize {
    let mut sa = SockAddrUn {
        sun_family: AF_UNIX,
        sun_path: [0; 108],
    };
    if let Some(bound) = addr {
        match bound {
            UnixBoundAddr::Path(path) => {
                let raw = path.as_bytes();
                let copy = raw.len().min(sa.sun_path.len().saturating_sub(1));
                sa.sun_path[..copy].copy_from_slice(&raw[..copy]);
            }
            UnixBoundAddr::Abstract(name) => {
                sa.sun_path[0] = 0;
                let copy = name.len().min(sa.sun_path.len().saturating_sub(1));
                sa.sun_path[1..1 + copy].copy_from_slice(&name[..copy]);
            }
        }
    }
    // SAFETY: sa is a stack-local struct with known layout; length equals size_of::<SockAddrUn>().
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&sa as *const SockAddrUn) as *const u8,
            size_of::<SockAddrUn>(),
        )
    };
    write_msg_name_bytes(msg, bytes)
}
