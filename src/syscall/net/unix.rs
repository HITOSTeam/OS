//! AF_UNIX（本地套接字）实现模块。
//!
//! 本模块负责：
//! - 维护路径绑定（`UNIX_BOUND_PATHS`）和抽象命名空间绑定（`UNIX_BOUND_ABSTRACT`）两张注册表；
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

use crate::bpf::BpfProgFile;
use crate::fs::{
    File, POLLERR, POLLHUP, POLLIN, POLLOUT, PollWaitQueue, SocketPairEnd, clear_ext4_path_cache,
    ext4_inode_lock, find_path_in_roots, make_socketpair, wake_tasks,
};
use crate::mm::{
    UserBuffer, try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value,
};
use crate::syscall::error::{SyscallError, err};
use crate::syscall::filesystem::normalize_path;
use crate::task::processor::{current_process, current_task, suspend_current_and_run_next};
use crate::task::signal::has_wait_interrupting_pending;
use crate::task::task_block::TaskControlBlock;
use crate::trap::get_current_token;

use super::cbpf::ClassicBpfProgram;
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
    /// 抽象命名空间注册表：将 `(netns, 抽象名称)` 映射到 socket 的弱引用。
    /// Linux 的 abstract UNIX socket namespace 跟随 network namespace，而不是全局共享。
    /// 设计原因与 `UNIX_BOUND_PATHS` 相同，参见上方注释。
    static ref UNIX_BOUND_ABSTRACT: Mutex<BTreeMap<(usize, Vec<u8>), FileWeak>> =
        Mutex::new(BTreeMap::new());
}

pub(super) fn cleanup_net_namespace(ns_id: usize) {
    UNIX_BOUND_ABSTRACT
        .lock()
        .retain(|(entry_ns, _), _| *entry_ns != ns_id);
}

/// 一条 UNIX 数据报消息，保存在接收队列中直至被 `recv_dgram` 取走。
#[derive(Clone)]
pub(super) struct UnixDatagram {
    /// 发送方的绑定地址；未绑定的发送方为 `None`，接收方据此决定是否能回复。
    pub(super) from: Option<UnixBoundAddr>,
    /// 报文有效载荷，完整保留（数据报不做流式拆分）。
    pub(super) payload: Vec<u8>,
    /// Unix ancillary data；普通 `read/recvfrom` 会丢弃，`recvmsg` 按 socket 选项返回。
    pub(super) control: ScmControl,
}

#[derive(Clone)]
struct UnixSocketFilterSnapshot {
    filter_locked: bool,
    classic_filter: Option<ClassicBpfProgram>,
    ebpf_filter: Option<Arc<BpfProgFile>>,
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
    /// 本端可暴露给对端的凭证快照，stream listen 时会刷新到 Linux 的连接建立语义。
    local_cred: UCred,
    /// 对端进程凭证，连接时由内核填入，供 `SO_PEERCRED` 查询使用。
    peer_cred: Option<UCred>,
    /// dgram 模式下 `connect` 设定的默认发送目标，省去每次 `sendto` 都指定地址。
    dgram_peer: Option<UnixBoundAddr>,
    /// dgram 接收队列，按到达顺序存放，由 `send_dgram` 写入、`recv_dgram` 消费。
    pub(super) dgram_queue: VecDeque<UnixDatagram>,
    reuseaddr: bool,
    dontroute: bool,
    broadcast: bool,
    keepalive: bool,
    oobinline: bool,
    linger_on: bool,
    linger_sec: i32,
    rcvlowat: i32,
    passcred: bool,
    filter_locked: bool,
    classic_filter: Option<ClassicBpfProgram>,
    ebpf_filter: Option<Arc<BpfProgFile>>,
    last_timestamp: Option<SocketTimestamp>,
    pending_error: i32,
    rd_shutdown: bool,
    wr_shutdown: bool,
    rcvtimeo_ms: Option<usize>,
    sndtimeo_ms: Option<usize>,
    /// 注册了 poll 等待的任务列表，用于在状态变化时批量唤醒。
    poll_waiters: PollWaitQueue,
}

impl UnixSocketState {
    fn new() -> Self {
        Self::new_with_cred(current_unix_ucred())
    }

    fn new_with_cred(local_cred: UCred) -> Self {
        Self {
            bound: None,
            listening: false,
            backlog: 1,
            pending_accept: VecDeque::new(),
            stream_end: None,
            peer_addr: None,
            local_cred,
            peer_cred: None,
            dgram_peer: None,
            dgram_queue: VecDeque::new(),
            reuseaddr: false,
            dontroute: false,
            broadcast: false,
            keepalive: false,
            oobinline: false,
            linger_on: false,
            linger_sec: 0,
            rcvlowat: 1,
            passcred: false,
            filter_locked: false,
            classic_filter: None,
            ebpf_filter: None,
            last_timestamp: None,
            pending_error: 0,
            rd_shutdown: false,
            wr_shutdown: false,
            rcvtimeo_ms: None,
            sndtimeo_ms: None,
            poll_waiters: PollWaitQueue::default(),
        }
    }

    fn filter_snapshot(&self) -> UnixSocketFilterSnapshot {
        UnixSocketFilterSnapshot {
            filter_locked: self.filter_locked,
            classic_filter: self.classic_filter.clone(),
            ebpf_filter: self.ebpf_filter.clone(),
        }
    }
}

pub(crate) struct UnixSocketFile {
    sock_type: usize,
    /// `/proc/net/unix` 使用的稳定 inode。Linux 为 socket 分配 sock inode，
    /// 这里复用网络层的递增 inode，避免 proc 输出依赖枚举顺序。
    proc_inode: u64,
    /// socket 创建时所在的 network namespace。抽象 UNIX socket 名称空间按此字段隔离；
    /// 路径 socket 仍通过 VFS 路径可见。
    net_ns_id: usize,
    pub(super) state: Mutex<UnixSocketState>,
}

impl UnixSocketFile {
    /// 创建一个未绑定、未连接的空白 Unix socket。
    pub(super) fn new(sock_type: usize) -> Self {
        Self {
            sock_type,
            proc_inode: alloc_socket_inode(),
            net_ns_id: current_process().net_namespace_id(),
            state: Mutex::new(UnixSocketState::new()),
        }
    }

    /// 创建一条已完成握手的 stream socket，供 `connect_unix` 在服务端 `pending_accept` 中插入。
    ///
    /// 此函数不走 bind/listen 流程，直接持有 `server_end`，因此创建后即可读写。
    fn new_connected_stream(
        sock_type: usize,
        net_ns_id: usize,
        stream_end: Arc<SocketPairEnd>,
        peer_addr: Option<UnixBoundAddr>,
        local_cred: UCred,
        peer_cred: Option<UCred>,
        passcred: bool,
    ) -> Self {
        let mut state = UnixSocketState::new_with_cred(local_cred);
        state.rcvtimeo_ms = stream_end.rcvtimeo_ms();
        state.sndtimeo_ms = stream_end.sndtimeo_ms();
        state.stream_end = Some(stream_end);
        state.peer_addr = peer_addr;
        state.peer_cred = peer_cred;
        state.passcred = passcred;
        Self {
            sock_type,
            proc_inode: alloc_socket_inode(),
            net_ns_id,
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

    pub(super) fn socket_type(&self) -> usize {
        self.sock_type
    }

    pub(crate) fn net_ns_id(&self) -> usize {
        self.net_ns_id
    }

    pub(super) fn is_listening(&self) -> bool {
        self.state.lock().listening
    }

    pub(super) fn set_reuseaddr(&self, enabled: bool) {
        self.state.lock().reuseaddr = enabled;
    }

    pub(super) fn reuseaddr(&self) -> bool {
        self.state.lock().reuseaddr
    }

    pub(super) fn set_dontroute(&self, enabled: bool) {
        self.state.lock().dontroute = enabled;
    }

    pub(super) fn dontroute(&self) -> bool {
        self.state.lock().dontroute
    }

    pub(super) fn set_broadcast(&self, enabled: bool) {
        self.state.lock().broadcast = enabled;
    }

    pub(super) fn broadcast(&self) -> bool {
        self.state.lock().broadcast
    }

    pub(super) fn set_keepalive(&self, enabled: bool) {
        self.state.lock().keepalive = enabled;
    }

    pub(super) fn keepalive(&self) -> bool {
        self.state.lock().keepalive
    }

    pub(super) fn set_oobinline(&self, enabled: bool) {
        self.state.lock().oobinline = enabled;
    }

    pub(super) fn oobinline(&self) -> bool {
        self.state.lock().oobinline
    }

    pub(super) fn set_linger(&self, on: bool, sec: i32) {
        let mut state = self.state.lock();
        state.linger_on = on;
        state.linger_sec = sec;
    }

    pub(super) fn linger(&self) -> (bool, i32) {
        let state = self.state.lock();
        (state.linger_on, state.linger_sec)
    }

    pub(super) fn set_rcvlowat(&self, value: i32) {
        self.state.lock().rcvlowat = value;
    }

    pub(super) fn rcvlowat(&self) -> i32 {
        self.state.lock().rcvlowat
    }

    fn rcvlowat_bytes(&self) -> usize {
        self.state.lock().rcvlowat.max(1) as usize
    }

    pub(super) fn set_rcvtimeo_ms(&self, timeout_ms: Option<usize>) {
        let stream_end = {
            let mut st = self.state.lock();
            st.rcvtimeo_ms = timeout_ms;
            st.stream_end.clone()
        };
        if let Some(end) = stream_end {
            end.set_rcvtimeo_ms(timeout_ms);
        }
    }

    pub(super) fn rcvtimeo_ms(&self) -> Option<usize> {
        self.state.lock().rcvtimeo_ms
    }

    fn rcvtimeo_deadline_ms(&self) -> Option<usize> {
        self.rcvtimeo_ms()
            .map(|ms| crate::time::get_time_ms().saturating_add(ms))
    }

    pub(super) fn set_sndtimeo_ms(&self, timeout_ms: Option<usize>) {
        let stream_end = {
            let mut st = self.state.lock();
            st.sndtimeo_ms = timeout_ms;
            st.stream_end.clone()
        };
        if let Some(end) = stream_end {
            end.set_sndtimeo_ms(timeout_ms);
        }
    }

    pub(super) fn sndtimeo_ms(&self) -> Option<usize> {
        self.state.lock().sndtimeo_ms
    }

    fn arm_timeout_timer(deadline_ms: Option<usize>) -> Result<(), isize> {
        let Some(deadline_ms) = deadline_ms else {
            suspend_current_and_run_next();
            return Ok(());
        };
        let now = crate::time::get_time_ms();
        if now >= deadline_ms {
            return Err(err(SyscallError::EAGAIN));
        }
        if let Some(task) = current_task() {
            crate::task::block_sleep::add_timer(task, deadline_ms.saturating_sub(now).max(1));
        }
        suspend_current_and_run_next();
        Ok(())
    }

    pub(super) fn set_passcred(&self, enabled: bool) {
        let stream_end = {
            let mut state = self.state.lock();
            state.passcred = enabled;
            state.stream_end.clone()
        };
        if let Some(end) = stream_end {
            end.set_passcred(enabled);
        }
    }

    pub(super) fn passcred(&self) -> bool {
        self.state.lock().passcred
    }

    fn apply_filter_snapshot_to_stream_end(
        end: &Arc<SocketPairEnd>,
        snapshot: UnixSocketFilterSnapshot,
    ) {
        if let Some(filter) = snapshot.classic_filter {
            let _ = end.attach_filter(filter);
        } else if let Some(filter) = snapshot.ebpf_filter {
            let _ = end.attach_bpf(filter);
        }
        if snapshot.filter_locked {
            let _ = end.set_filter_locked(true);
        }
    }

    fn install_filter_snapshot(&self, snapshot: UnixSocketFilterSnapshot) {
        let stream_end = {
            let mut state = self.state.lock();
            state.filter_locked = snapshot.filter_locked;
            state.classic_filter = snapshot.classic_filter.clone();
            state.ebpf_filter = snapshot.ebpf_filter.clone();
            state.stream_end.clone()
        };
        if let Some(end) = stream_end {
            Self::apply_filter_snapshot_to_stream_end(&end, snapshot);
        }
    }

    pub(super) fn attach_filter(&self, filter: ClassicBpfProgram) -> isize {
        let stream_end = {
            let mut state = self.state.lock();
            if state.filter_locked {
                return err(SyscallError::EPERM);
            }
            state.classic_filter = Some(filter.clone());
            state.ebpf_filter = None;
            state.stream_end.clone()
        };
        if let Some(end) = stream_end {
            return end.attach_filter(filter);
        }
        0
    }

    pub(super) fn attach_bpf(&self, filter: Arc<BpfProgFile>) -> isize {
        let stream_end = {
            let mut state = self.state.lock();
            if state.filter_locked {
                return err(SyscallError::EPERM);
            }
            state.classic_filter = None;
            state.ebpf_filter = Some(filter.clone());
            state.stream_end.clone()
        };
        if let Some(end) = stream_end {
            return end.attach_bpf(filter);
        }
        0
    }

    pub(super) fn detach_filter(&self) -> isize {
        let (stream_end, had_filter) = {
            let mut state = self.state.lock();
            if state.filter_locked {
                return err(SyscallError::EPERM);
            }
            let had_filter =
                state.classic_filter.take().is_some() | state.ebpf_filter.take().is_some();
            (state.stream_end.clone(), had_filter)
        };
        if let Some(end) = stream_end {
            let ret = end.detach_filter();
            if ret == 0 || had_filter {
                return 0;
            }
            return ret;
        }
        if had_filter {
            0
        } else {
            err(SyscallError::ENOENT)
        }
    }

    pub(super) fn set_filter_locked(&self, locked: bool) -> isize {
        let stream_end = {
            let mut state = self.state.lock();
            if state.filter_locked && !locked {
                return err(SyscallError::EPERM);
            }
            state.filter_locked = locked;
            state.stream_end.clone()
        };
        if let Some(end) = stream_end {
            return end.set_filter_locked(locked);
        }
        0
    }

    pub(super) fn filter_locked(&self) -> bool {
        let (locked, stream_end) = {
            let state = self.state.lock();
            (state.filter_locked, state.stream_end.clone())
        };
        stream_end
            .as_ref()
            .map(|end| end.filter_locked())
            .unwrap_or(locked)
    }

    pub(super) fn classic_filter_snapshot(&self) -> (Option<ClassicBpfProgram>, bool) {
        let state = self.state.lock();
        (state.classic_filter.clone(), state.ebpf_filter.is_some())
    }

    /// 返回当前绑定地址的克隆，用于在 connect 时告知对端自己的标识。
    pub(super) fn bound_addr(&self) -> Option<UnixBoundAddr> {
        self.state.lock().bound.clone()
    }

    pub(crate) fn proc_net_snapshot(&self) -> (u64, usize, u8, String) {
        let state = self.state.lock();
        let socket_state = if state.stream_end.is_some() || state.peer_addr.is_some() {
            0x03
        } else if state.listening {
            0x0a
        } else {
            0x01
        };
        let path = match &state.bound {
            Some(UnixBoundAddr::Path(path)) => path.clone(),
            Some(UnixBoundAddr::Abstract(name)) => {
                let mut out = String::from("@");
                match core::str::from_utf8(name) {
                    Ok(name) => out.push_str(name),
                    Err(_) => {
                        for byte in name {
                            let _ =
                                core::fmt::Write::write_fmt(&mut out, format_args!("{:02x}", byte));
                        }
                    }
                }
                out
            }
            None => String::new(),
        };
        (self.proc_inode, self.sock_type, socket_state, path)
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

    fn local_cred(&self) -> UCred {
        self.state.lock().local_cred
    }

    fn set_socket_error(&self, errno: isize) {
        if errno >= 0 {
            return;
        }
        self.state.lock().pending_error = (-errno) as i32;
        self.notify_poll_waiters();
    }

    fn record_peer_error(&self, errno: isize) {
        if errno == isize::from(SyscallError::EPIPE)
            || errno == isize::from(SyscallError::ECONNREFUSED)
            || errno == isize::from(SyscallError::ENOENT)
        {
            self.set_socket_error(errno);
        }
    }

    pub(super) fn take_socket_error(&self) -> u32 {
        let stream_end = {
            let mut st = self.state.lock();
            let errno = st.pending_error.max(0) as u32;
            if errno != 0 {
                st.pending_error = 0;
                return errno;
            }
            st.stream_end.clone()
        };
        stream_end
            .as_ref()
            .map(|end| end.take_socket_error())
            .unwrap_or(0)
    }

    pub(super) fn shutdown(&self, how: usize) -> isize {
        let rd = how == 0 || how == 2;
        let wr = how == 1 || how == 2;
        let stream_end = {
            let mut st = self.state.lock();
            // Linux unix_shutdown() 先记录本端半关闭；没有 peer 时也返回成功。
            if rd {
                st.rd_shutdown = true;
            }
            if wr {
                st.wr_shutdown = true;
            }
            st.stream_end.clone()
        };
        if let Some(end) = stream_end {
            let _ = end.shutdown(how);
        }
        self.notify_poll_waiters();
        0
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
        st.local_cred = current_unix_ucred();
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
    pub(super) fn accept_stream(&self, nonblock: bool) -> Result<Arc<UnixSocketFile>, isize> {
        if !self.is_stream_like() {
            return Err(err(SyscallError::EOPNOTSUPP));
        }
        let deadline_ms = (!nonblock).then(|| self.rcvtimeo_deadline_ms()).flatten();
        loop {
            let mut st = self.state.lock();
            if !st.listening {
                return Err(err(SyscallError::EINVAL));
            }
            if let Some(conn) = st.pending_accept.pop_front() {
                return Ok(conn);
            }
            if nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            // 队列为空，主动挂起当前任务，等待 connect 端插入连接后唤醒
            drop(st);
            Self::arm_timeout_timer(deadline_ms)?;
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
            let peer_file = match lookup_unix_bound_socket(self.net_ns_id, &addr) {
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
            let peer_cred = peer.local_cred();
            {
                let mut peer_st = peer.state.lock();
                if !peer_st.listening {
                    return err(SyscallError::ECONNREFUSED);
                }
                // 检查 backlog 上限，超出则拒绝，避免服务端队列无限增长
                if peer_st.pending_accept.len() >= peer_st.backlog {
                    return err(SyscallError::ECONNREFUSED);
                }
                let listener_filter = peer_st.filter_snapshot();
                let listener_rcvtimeo_ms = peer_st.rcvtimeo_ms;
                let listener_sndtimeo_ms = peer_st.sndtimeo_ms;
                let listener_passcred = peer_st.passcred;
                server_end.set_rcvtimeo_ms(listener_rcvtimeo_ms);
                server_end.set_sndtimeo_ms(listener_sndtimeo_ms);
                server_end.set_passcred(listener_passcred);
                // 将 server_end 包装为一个已连接的 socket，放入服务端 accept 队列
                let accepted = Arc::new(UnixSocketFile::new_connected_stream(
                    self.sock_type,
                    peer.net_ns_id,
                    server_end,
                    client_bound,
                    peer_cred,
                    Some(client_cred),
                    listener_passcred,
                ));
                accepted.install_filter_snapshot(listener_filter);
                peer_st.pending_accept.push_back(accepted);
                // 唤醒可能正在 accept_stream 中挂起的服务端任务
                let wake = peer_st.poll_waiters.take_wakeups();
                drop(peer_st);
                wake_tasks(wake);
            }
            let (client_filter, rcvtimeo_ms, sndtimeo_ms, client_passcred) = {
                let mut st = self.state.lock();
                // 释放锁后重新检查，防止并发 connect 导致重复连接
                if st.stream_end.is_some() {
                    return err(SyscallError::EISCONN);
                }
                st.stream_end = Some(client_end.clone());
                st.peer_addr = Some(addr);
                st.peer_cred = Some(peer_cred);
                (
                    st.filter_snapshot(),
                    st.rcvtimeo_ms,
                    st.sndtimeo_ms,
                    st.passcred,
                )
            };
            client_end.set_rcvtimeo_ms(rcvtimeo_ms);
            client_end.set_sndtimeo_ms(sndtimeo_ms);
            client_end.set_passcred(client_passcred);
            Self::apply_filter_snapshot_to_stream_end(&client_end, client_filter);
            self.notify_poll_waiters();
            return 0;
        }
        if !self.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let peer_file = match lookup_unix_bound_socket(self.net_ns_id, &addr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
            return err(SyscallError::ECONNREFUSED);
        };
        if !peer.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let peer_cred = peer.local_cred();
        // dgram connect 仅记录默认目标，不建立真正的连接状态
        let mut st = self.state.lock();
        st.dgram_peer = Some(addr.clone());
        st.peer_addr = Some(addr);
        st.peer_cred = Some(peer_cred);
        0
    }

    pub(super) fn disconnect_unix(&self) -> isize {
        if !self.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let mut st = self.state.lock();
        st.dgram_peer = None;
        st.peer_addr = None;
        st.peer_cred = None;
        drop(st);
        self.notify_poll_waiters();
        0
    }

    /// 发送一条数据报到 `target`（若 `target` 为 `None` 则使用 `connect` 设置的默认目标）。
    ///
    /// 发送成功后立即唤醒接收方的 poll 等待任务，使其能及时从 `dgram_queue` 取走数据。
    /// 返回实际发送的字节数，出错返回负的 errno。
    pub(super) fn send_dgram(&self, payload: Vec<u8>, target: Option<UnixBoundAddr>) -> isize {
        let control = ScmControl::default();
        self.send_dgram_with_control(payload, target, control)
    }

    pub(super) fn send_dgram_with_control(
        &self,
        payload: Vec<u8>,
        target: Option<UnixBoundAddr>,
        mut control: ScmControl,
    ) -> isize {
        if !self.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let (to, from, sender_passcred) = {
            let st = self.state.lock();
            if st.wr_shutdown {
                let e = err(SyscallError::EPIPE);
                drop(st);
                self.set_socket_error(e);
                return e;
            }
            // 优先使用调用方传入的显式目标，其次回退到 connect 记录的默认目标
            let Some(to) = target.or_else(|| st.dgram_peer.clone()) else {
                return err(SyscallError::ENOTCONN);
            };
            (to, st.bound.clone(), st.passcred)
        };
        let peer_file = match lookup_unix_bound_socket(self.net_ns_id, &to) {
            Ok(f) => f,
            Err(e) => {
                self.record_peer_error(e);
                return e;
            }
        };
        let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
            let e = err(SyscallError::ECONNREFUSED);
            self.set_socket_error(e);
            return e;
        };
        if !peer.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let n = payload.len();
        let wake = {
            let mut peer_st = peer.state.lock();
            control
                .ensure_credentials_if(sender_passcred || peer_st.passcred || control.has_rights());
            let mut payload = payload;
            if let Some(filter) = peer_st.classic_filter.as_ref() {
                let Some(snaplen) = filter.filter_len(&payload) else {
                    return n as isize;
                };
                payload.truncate(snaplen);
            }
            if let Some(filter) = peer_st.ebpf_filter.as_ref() {
                let Some(snaplen) = filter.filter_len(&payload) else {
                    return n as isize;
                };
                payload.truncate(snaplen);
            }
            peer_st.dgram_queue.push_back(UnixDatagram {
                from,
                payload,
                control,
            });
            peer_st.poll_waiters.take_wakeups()
        };
        wake_tasks(wake);
        n as isize
    }

    /// 从 `dgram_queue` 中取出最早到达的一条数据报。
    ///
    /// 队列为空时挂起当前任务，等待 `send_dgram` 写入后唤醒。
    pub(super) fn recv_dgram(&self, nonblock: bool, peek: bool) -> Result<UnixDatagram, isize> {
        let deadline_ms = (!nonblock).then(|| self.rcvtimeo_deadline_ms()).flatten();
        loop {
            let mut st = self.state.lock();
            if st.rd_shutdown {
                return Ok(UnixDatagram {
                    from: None,
                    payload: Vec::new(),
                    control: ScmControl::default(),
                });
            }
            let msg = if peek {
                st.dgram_queue.front().cloned()
            } else {
                st.dgram_queue.pop_front()
            };
            if let Some(msg) = msg {
                if !peek {
                    st.last_timestamp = Some(SocketTimestamp::now());
                }
                return Ok(msg);
            }
            if nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            if let Some(task) = current_task() {
                crate::task::block_sleep::check_timer();
                let inner = task.borrow_mut();
                if has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask) {
                    return Err(err(SyscallError::EINTR));
                }
            }
            // 队列为空，让出 CPU 等待发送方填入数据
            drop(st);
            Self::arm_timeout_timer(deadline_ms)?;
        }
    }

    /// 返回 stream socket 持有的管道端点，供上层读写操作使用。
    pub(super) fn stream_end(&self) -> Option<Arc<SocketPairEnd>> {
        self.state.lock().stream_end.clone()
    }

    pub(crate) fn socket_timestamp(&self) -> Option<SocketTimestamp> {
        let st = self.state.lock();
        if self.sock_type == SOCK_DGRAM {
            st.last_timestamp
        } else {
            st.stream_end
                .as_ref()
                .and_then(|end| end.socket_timestamp())
        }
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
                return end.poll_readable_with_lowat(self.rcvlowat_bytes());
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
    /// dgram 在写端未 shutdown 时可写（目标地址合法性在 `send_dgram` 中校验）。
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
            return !self.state.lock().wr_shutdown;
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
        crate::syscall::net::clear_msg_more_pending_for_addr(self as *const Self as usize);
        if let Some(bound) = self.state.lock().bound.take() {
            match bound {
                UnixBoundAddr::Path(path) => {
                    UNIX_BOUND_PATHS.lock().remove(&path);
                }
                UnixBoundAddr::Abstract(name) => {
                    UNIX_BOUND_ABSTRACT.lock().remove(&(self.net_ns_id, name));
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
        self.poll_writable()
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
        match self.recv_dgram(false, false) {
            Ok(msg) => copy_slice_to_user_buffer(buf, &msg.payload),
            Err(_) => 0,
        }
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
        let err_mask = if self.state.lock().pending_error != 0 {
            POLLERR
        } else {
            0
        };
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
                return err_mask | if pending_accept { POLLIN } else { 0 };
            }
            if let Some(end) = stream_end {
                let end_mask = end.poll_mask();
                let read_mask = if end.poll_readable_with_lowat(self.rcvlowat_bytes()) {
                    POLLIN
                } else {
                    0
                };
                return err_mask | (end_mask & !POLLIN) | read_mask;
            }
            return err_mask;
        }
        if self.is_dgram() {
            let (rd_shutdown, wr_shutdown, readable) = {
                let st = self.state.lock();
                (st.rd_shutdown, st.wr_shutdown, !st.dgram_queue.is_empty())
            };
            let mut mask = err_mask;
            if rd_shutdown || readable {
                mask |= POLLIN;
            }
            if !wr_shutdown {
                mask |= POLLOUT;
            }
            if rd_shutdown && wr_shutdown {
                mask |= POLLHUP;
            }
            return mask;
        }
        err_mask
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
    UCred::current()
}

/// 从用户空间读取 `sockaddr_un` 并解析为 `(is_abstract, 名称字节)` 二元组。
///
/// 地址类型由 `sun_path[0]` 决定：
/// - `sun_path[0] == 0`：抽象命名空间，名称为 `sun_path[1..]`，尾部多余的 `\0` 需要修剪，
///   因为用户空间通常用 `sizeof` 而非实际字符串长度传入 `addrlen`，会带来多余的零字节；
/// - `sun_path[0] != 0`：文件系统路径，取到第一个 `\0` 为止。
///
fn parse_sockaddr_un(user_ptr: usize, len: usize) -> Result<(bool, Vec<u8>), isize> {
    if len > SOCKADDR_STORAGE_SIZE {
        return Err(err(SyscallError::EINVAL));
    }
    if len != 0 && user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut raw = vec![0u8; len];
    if len > 0 && try_copy_from_user(token, user_ptr as *const u8, raw.as_mut_slice()).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    if len <= size_of::<u16>() || len > size_of::<SockAddrUn>() {
        return Err(err(SyscallError::EINVAL));
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    if family != AF_UNIX {
        return Err(err(SyscallError::EINVAL));
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

pub(super) fn read_sockaddr_un_family(addr: usize, addrlen: usize) -> Result<u16, isize> {
    if addr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    if addrlen < size_of::<u16>() {
        return Err(err(SyscallError::EINVAL));
    }
    let token = get_current_token();
    let Some(family) = try_read_user_value::<u16>(token, addr as *const u16) else {
        return Err(err(SyscallError::EFAULT));
    };
    Ok(family)
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
    let cwd = current_process().fs_struct().cwd_display();
    // 相对路径需要结合 cwd 规范化，保证不同进程使用同一路径时能命中同一注册表条目
    let abs = normalize_path(&cwd, path_part);
    Ok(UnixBoundAddr::Path(abs))
}

/// 在全局注册表中查找指定地址对应的 socket 强引用。
///
/// 若找到条目但 `Weak::upgrade()` 失败，说明 socket 已 drop 但条目未被 `Drop` 清除
/// （理论上不应发生，但作为防御性措施），此时惰性删除过期条目。
fn lookup_unix_bound_socket(ns_id: usize, addr: &UnixBoundAddr) -> Result<FileArc, isize> {
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
            let key = (ns_id, name.clone());
            let Some(weak) = reg.get(&key) else {
                return Err(err(SyscallError::ENOENT));
            };
            if let Some(file) = weak.upgrade() {
                return Ok(file);
            }
            // Weak 已失效，惰性清除过期条目
            reg.remove(&key);
            Err(err(SyscallError::ENOENT))
        }
    }
}

/// 将 socket 以弱引用形式注册到全局注册表。
///
/// 若地址已被存活的 socket 占用则返回 EADDRINUSE；
/// 若旧条目的 Weak 已失效（对应 socket 已 drop），则替换旧条目以允许复用。
fn register_unix_bound_socket(ns_id: usize, addr: &UnixBoundAddr, file: &FileArc) -> isize {
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
            let key = (ns_id, name.clone());
            if let Some(existing) = reg.get(&key) {
                if existing.upgrade().is_some() {
                    return err(SyscallError::EADDRINUSE);
                }
                // 旧 socket 已释放，清除残留条目后允许重新注册
                reg.remove(&key);
            }
            reg.insert(key, Arc::downgrade(file));
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
        let Some(parent) = find_path_in_roots(parent_path) else {
            return err(SyscallError::ENOENT);
        };
        let parent_lock = ext4_inode_lock(&parent);
        let _parent_guard = parent_lock.write();
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
        clear_ext4_path_cache();
        let reg_result = register_unix_bound_socket(sock.net_ns_id, &bound, file);
        if reg_result != 0 {
            // 注册失败（如另一个 socket 已占用此路径），回滚删除刚创建的占位文件
            if parent.unlink(name).is_ok() {
                clear_ext4_path_cache();
            }
            return reg_result;
        }
    } else {
        let reg_result = register_unix_bound_socket(sock.net_ns_id, &bound, file);
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
