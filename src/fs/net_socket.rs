use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::cmp::min;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::{wake_tasks, File, PollWaitQueue, POLLIN, POLLOUT, POLLRDHUP};
use crate::mm::UserBuffer;
use crate::task::processor::current_task;
use crate::task::signal::has_wait_interrupting_pending;
use crate::task::task_block::TaskControlBlock;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address};

// 全局  网络相关 参数设置
// TCP 默认收发缓冲区刻意配得较大，主要是为了让 iperf 一类大吞吐测试
// 不会过早被 smoltcp 的用户态缓冲区限制住。
//
const TCP_RX_BUF_LEN_IPERF: usize = 128 * 1024;
const TCP_TX_BUF_LEN_IPERF: usize = 128 * 1024;
// UDP 也保留较大的整包缓冲区，避免较大的 datagram 在回环/压测场景下频繁因空间不足失败。
const UDP_RX_BUF_LEN: usize = 64 * 1024;
const UDP_TX_BUF_LEN: usize = 64 * 1024;
//
// 网络阻塞等待被未屏蔽信号打断时，统一向上层返回 Linux 风格的 EINTR。
const EINTR: isize = -4;

/// 检查当前任务是否有未被 signal mask 屏蔽的待处理信号。如果有未处理信号，一般会打断 睡眠(suspend)
// 这会在各类阻塞式网络等待循环中被轮询，用来模拟 Linux 中“睡眠中的 IO 可被信号打断”的语义。
fn pending_unmasked_signal() -> bool {
    // 先顺带推进一次定时器，避免任务因为超时事件尚未结算而错过应投递的信号。
    crate::task::block_sleep::check_timer();
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
}

// 判断 listener backlog 槽位上的 TCP socket 是否已经可以被 accept。
// 这里不只接受 Established，还接受若干已进入关闭流程但连接曾经建立过的状态，
// 因为 accept 关心的是“三次握手已完成且内核可交付这个连接”，而不是连接此刻是否还处于稳态收发期。
fn tcp_accept_ready(state: tcp::State) -> bool {
    matches!(
        state,
        tcp::State::Established
            | tcp::State::FinWait1
            | tcp::State::FinWait2
            | tcp::State::CloseWait
            | tcp::State::Closing
            | tcp::State::LastAck
            | tcp::State::TimeWait
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// 该文件支持的三类网络 socket。
///
/// - `TcpStream`：面向连接的已建立 TCP 端点
/// - `TcpListener`：监听端口并维护 backlog 槽位的 TCP 监听端
/// - `Udp`：无连接但可记录默认对端的 UDP 端点
pub enum NetSocketKind {
    /// 已建立或正在建立中的 TCP 流式连接。
    TcpStream,
    /// 通过多个底层监听 socket 模拟 backlog 的 TCP 监听端。
    TcpListener,
    /// 面向报文的 UDP socket，可选记录一个 connect 后的默认对端。
    Udp,
}

/// `NetSocketFile` 内部真正持有的底层网络对象。
///
/// 这里把不同类型 socket 的差异收敛到一个枚举里，外层文件接口只需要围绕它做分派。
enum Inner {
    /// 单个 TCP 连接，对应 smoltcp 里的一个 tcp socket handle。
    TcpStream {
        /// 指向全局 `SocketSet` 中实际 TCP socket 的句柄。由Smoltcp包装
        handle: SocketHandle,
    },
    /// TCP 监听端。
    TcpListener {
        /// 监听端口号，accept 后补充 backlog 槽位时要继续沿用它。
        port: u16,
        /// 用户可见的 backlog 上限；本实现通过预建多个监听 socket 近似模拟。
        backlog: usize,
        /// backlog 槽位对应的一组监听 handle；每个 handle 都可能独立进入“可 accept”状态。
        listen: Vec<SocketHandle>,
    },
    /// UDP 端点。
    Udp {
        /// 指向全局 `SocketSet` 中实际 UDP socket 的句柄。
        handle: SocketHandle,
        /// `connect()` 之后记住的默认对端；UDP 本身并不会真正建立连接。
        connected: Option<IpEndpoint>,
    },
}

/// 网络 socket 对应的文件对象。
///
/// - `inner`：描述当前文件绑定的是哪一种底层 socket 及其 handle
/// - `opts`：保存不直接存放在 smoltcp socket 中的 Linux 语义选项
/// - `poll_waiters`：该文件对象自己维护的一份 poll 等待队列
pub struct NetSocketFile {
    /// socket 类型与底层 handle。
    inner: Mutex<Inner>,
    /// 额外 socket 选项与半关闭状态。
    opts: Mutex<SocketOptions>,
    /// 绑定在当前文件对象上的 poll 等待者。
    poll_waiters: Mutex<PollWaitQueue>,
}

#[derive(Debug, Clone, Copy)]
/// 与文件对象绑定的 socket 选项快照。
pub struct SocketOptions {
    /// 用户视角的发送缓冲区大小配置。
    sndbuf: u32,
    /// 用户视角的接收缓冲区大小配置。
    rcvbuf: u32,
    /// 是否加入过组播；当前主要用于保存 setsockopt 状态。
    mcast_joined: bool,
    /// 本端是否执行过读半关闭；这会影响 poll 的 RDHUP 语义。
    rd_shutdown: bool,
}

#[derive(Clone, Copy)]
/// poll 全局注册表中 handle 对应的 socket 类别。
enum PollRegistrationKind {
    TcpStream,
    TcpListener,
    Udp,
}

/// 某个底层 socket handle 在全局 poll 体系中的注册信息。
struct PollRegistration {
    /// 该 handle 应按哪种 socket 规则计算事件掩码。
    kind: PollRegistrationKind,
    /// 上一次观察到的事件掩码，用来抑制无意义的重复唤醒。
    last_mask: i16,
    /// 等待这个 handle 事件变化的任务集合。
    waiters: PollWaitQueue,
}

lazy_static! {
    /// 全局网络 poll 注册表。
    ///
    /// key 选 `SocketHandle`，因为真正产生可读/可写状态变化的是底层 socket；
    /// handle 是标识 Socket 在interface 中的 Key
    /// value 用 `BTreeMap` 存放，既能稳定按 handle 遍历，也避免额外哈希依赖，足够满足当前内核规模。
    static ref NET_POLL_WAITERS: Mutex<BTreeMap<SocketHandle, PollRegistration>> =
        Mutex::new(BTreeMap::new());
}

// 按底层 handle 当前状态计算 poll 事件掩码。
fn poll_mask_for_registered_handle(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    kind: PollRegistrationKind,
) -> i16 {
    match kind {
        PollRegistrationKind::TcpStream => {
            // 获得对应的socket
            let s = sockets.get::<tcp::Socket>(handle);
            let mut mask = 0;
            // 即使收不到新字节，只要对端已经不会再发送，read() 也应立刻返回 0；
            // 因此 EOF 同样要表现为“可读”，这样 poll/select 才不会把它当成还需继续阻塞。
            if s.can_recv() || !s.may_recv() {
                mask |= POLLIN;
            }
            if s.can_send() || !s.may_send() {
                mask |= POLLOUT;
            }
            if !s.may_recv() {
                mask |= POLLRDHUP;
            }
            mask
        }
        PollRegistrationKind::TcpListener => {
            let s = sockets.get::<tcp::Socket>(handle);
            let mut mask = POLLOUT;
            if tcp_accept_ready(s.state()) {
                mask |= POLLIN;
            }
            mask
        }
        PollRegistrationKind::Udp => {
            let s = sockets.get::<udp::Socket>(handle);
            let mut mask = 0;
            if s.can_recv() {
                mask |= POLLIN;
            }
            if s.can_send() {
                mask |= POLLOUT;
            }
            mask
        }
    }
}

/// 把某个任务注册到指定底层 handle 的全局 poll 等待队列中。
/// 返回值沿用 `register_waiter()` 语义：若这是一次有效注册，则上层可据此决定是否需要重新检查事件。
fn register_poll_waiter_for_handle(
    handle: SocketHandle,
    kind: PollRegistrationKind,
    task: &Arc<TaskControlBlock>,
) -> bool {
    let mut registrations = NET_POLL_WAITERS.lock();
    let entry = registrations
        .entry(handle)
        .or_insert_with(|| PollRegistration {
            kind,
            last_mask: 0,
            waiters: PollWaitQueue::default(),
        });
    entry.kind = kind;
    entry.waiters.register_waiter(task)
}

// 在 socket 生命周期结束时移除全局 poll 注册，避免 Drop 后仍有任务挂在无效 handle 上。
fn unregister_poll_waiters(handles: &[SocketHandle]) {
    let mut registrations = NET_POLL_WAITERS.lock();
    for handle in handles {
        registrations.remove(handle);
    }
}

// 由网络轮询路径统一调用，检查所有已注册 handle 的事件变化并按需唤醒任务。
// 简单介绍下运行过程， 首先收集所有的，仍然有waiter 的poll queue
// 收集新的mask. 与旧mask比较，如何不同，收集，然后wake
//
pub(crate) fn notify_net_poll_events() {
    let mut wake = Vec::new();
    let mut registrations = NET_POLL_WAITERS.lock();
    registrations.retain(|_, entry| entry.waiters.has_waiters());
    if registrations.is_empty() {
        return;
    }
    let masks = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
        registrations
            .iter()
            .map(|(handle, entry)| {
                (
                    *handle,
                    poll_mask_for_registered_handle(sockets, *handle, entry.kind),
                )
            })
            .collect::<Vec<_>>()
    });
    for (handle, mask) in masks {
        let Some(entry) = registrations.get_mut(&handle) else {
            continue;
        };
        // 只有事件掩码发生变化时才真正唤醒等待者，避免每次 net::poll()
        // 都制造一次无意义的 spurious wakeup。
        if mask != entry.last_mask {
            entry.last_mask = mask;
            wake.extend(entry.waiters.take_wakeups());
        }
    }
    drop(registrations);
    wake_tasks(wake);
}

/// 网络 socket 文件对象的核心操作实现。
impl NetSocketFile {
    pub fn new_tcp() -> Arc<Self> {
        crate::net::init();
        let handle = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            // TCP 默认就按大吞吐场景分配较大的环形缓冲区，避免 iperf 等测试被小 buffer 人为限速。
            let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
            let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
            sockets.add(tcp::Socket::new(rx, tx))
        });
        Arc::new(Self {
            inner: Mutex::new(Inner::TcpStream { handle }),
            opts: Mutex::new(SocketOptions {
                sndbuf: TCP_TX_BUF_LEN_IPERF as u32,
                rcvbuf: TCP_RX_BUF_LEN_IPERF as u32,
                mcast_joined: false,
                rd_shutdown: false,
            }),
            poll_waiters: Mutex::new(PollWaitQueue::default()),
        })
    }

    pub fn new_udp() -> Arc<Self> {
        crate::net::init();
        let handle = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            // UDP 按“整包”管理数据，因此直接给收发 packet buffer 预留较大的连续空间。
            let rx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; 256],
                vec![0u8; UDP_RX_BUF_LEN],
            );
            let tx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; 256],
                vec![0u8; UDP_TX_BUF_LEN],
            );
            sockets.add(udp::Socket::new(rx, tx))
        });
        Arc::new(Self {
            inner: Mutex::new(Inner::Udp {
                handle,
                connected: None,
            }),
            opts: Mutex::new(SocketOptions {
                sndbuf: UDP_TX_BUF_LEN as u32,
                rcvbuf: UDP_RX_BUF_LEN as u32,
                mcast_joined: false,
                rd_shutdown: false,
            }),
            poll_waiters: Mutex::new(PollWaitQueue::default()),
        })
    }

    fn notify_poll_waiters(&self) {
        let waiters = self.poll_waiters.lock().take_wakeups();
        wake_tasks(waiters);
    }

    pub fn set_sockbuf(&self, sndbuf: Option<u32>, rcvbuf: Option<u32>) {
        let mut opts = self.opts.lock();
        if let Some(v) = sndbuf {
            opts.sndbuf = v;
        }
        if let Some(v) = rcvbuf {
            opts.rcvbuf = v;
        }
    }

    pub fn getsockopt_sndbuf(&self) -> u32 {
        self.opts.lock().sndbuf
    }

    pub fn getsockopt_rcvbuf(&self) -> u32 {
        self.opts.lock().rcvbuf
    }

    pub fn set_multicast_joined(&self, joined: bool) {
        self.opts.lock().mcast_joined = joined;
    }

    pub fn multicast_joined(&self) -> bool {
        self.opts.lock().mcast_joined
    }

    pub fn kind(&self) -> NetSocketKind {
        match &*self.inner.lock() {
            Inner::TcpStream { .. } => NetSocketKind::TcpStream,
            Inner::TcpListener { .. } => NetSocketKind::TcpListener,
            Inner::Udp { .. } => NetSocketKind::Udp,
        }
    }

    /// 先抓取一份只包含必要状态的快照，再到全局 `SocketSet` 里查询实际 socket 状态。
    ///  这样可以避免在持有 `inner` 锁时再进入 NET 全局锁，减少锁嵌套和反向依赖。
    fn snapshot(&self) -> Snapshot {
        let inner = self.inner.lock();
        match &*inner {
            Inner::TcpStream { handle } => Snapshot::TcpStream {
                handle: *handle,
                rd_shutdown: self.opts.lock().rd_shutdown,
            },
            Inner::TcpListener { listen, .. } => Snapshot::TcpListener(listen.clone()),
            Inner::Udp { handle, .. } => Snapshot::Udp(*handle),
        }
    }

    fn poll_mask_for_snapshot(snapshot: &Snapshot, sockets: &mut SocketSet<'_>) -> i16 {
        match snapshot {
            Snapshot::TcpStream {
                handle,
                rd_shutdown,
            } => {
                let s = sockets.get::<tcp::Socket>(*handle);
                let mut mask = 0;
                if s.can_recv() || !s.may_recv() {
                    mask |= POLLIN;
                }
                if s.can_send() || !s.may_send() {
                    mask |= POLLOUT;
                }
                // 本端执行 shutdown(SHUT_RD) 后，即便对端未关闭，也要把读半关闭态通过 POLLRDHUP 暴露给 poll。
                if *rd_shutdown || !s.may_recv() {
                    mask |= POLLRDHUP;
                }
                mask
            }
            Snapshot::TcpListener(listen) => {
                let mut mask = POLLOUT;
                if listen.iter().any(|handle| {
                    let s = sockets.get::<tcp::Socket>(*handle);
                    tcp_accept_ready(s.state())
                }) {
                    mask |= POLLIN;
                }
                mask
            }
            Snapshot::Udp(handle) => {
                let s = sockets.get::<udp::Socket>(*handle);
                let mut mask = 0;
                if s.can_recv() {
                    mask |= POLLIN;
                }
                if s.can_send() {
                    mask |= POLLOUT;
                }
                mask
            }
        }
    }

    /// 统一从快照计算当前 poll 掩码，避免调用者自己决定该看哪一种底层 socket 状态。
    fn current_poll_mask(&self) -> i16 {
        let snapshot = self.snapshot();
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            Self::poll_mask_for_snapshot(&snapshot, sockets)
        })
    }

    // 返回需要参与全局 poll 注册的底层 handle 集合。
    // 对 listener 而言，真正可能变成“可 accept”的是每一个 backlog 槽位，因此必须全部注册。
    fn poll_registration_handles(&self) -> Vec<(SocketHandle, PollRegistrationKind)> {
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => vec![(*handle, PollRegistrationKind::TcpStream)],
            Inner::TcpListener { listen, .. } => listen
                .iter()
                .copied()
                .map(|handle| (handle, PollRegistrationKind::TcpListener))
                .collect(),
            Inner::Udp { handle, .. } => vec![(*handle, PollRegistrationKind::Udp)],
        }
    }

    pub fn poll_readable(&self) -> bool {
        // 先驱动一次网络栈，把延迟中的状态变化折算到当前 poll 掩码里。
        crate::net::poll();
        (self.current_poll_mask() & POLLIN) != 0
    }

    #[allow(dead_code)]
    pub fn poll_writable(&self) -> bool {
        // “可写”同样依赖先推进协议状态机，例如窗口更新或连接完成后才会真正出现 POLLOUT。
        crate::net::poll();
        (self.current_poll_mask() & POLLOUT) != 0
    }

    #[allow(dead_code)]
    pub fn poll_rdhup(&self) -> bool {
        // RDHUP 既可能来自对端 EOF，也可能来自本端记录的读半关闭状态。
        crate::net::poll();
        (self.current_poll_mask() & POLLRDHUP) != 0
    }

    /// 关闭读，同时通知所有的 等待
    pub fn shutdown_read(&self) {
        // smoltcp 不直接维护 Linux 风格的“读半关闭”文件语义，因此单独记一个标志位并主动唤醒 poll 等待者。
        self.opts.lock().rd_shutdown = true;
        self.notify_poll_waiters();
    }

    pub fn bind_v4(&self, ip: Ipv4Address, port: u16) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EOPNOTSUPP: isize = -95;
        let ephemeral = port == 0;
        let mut port = port;
        // `bind(..., port = 0)` 需要表现为 Linux 的 ephemeral port 语义，
        // 这样上层 libc/测试用例才能把“端口自动分配”当成正常路径使用。
        if ephemeral {
            port = crate::net::alloc_ephemeral_port();
        }
        crate::net::poll();
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::TcpStream { handle } => {
                crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get_mut::<tcp::Socket>(*handle);
                    s.set_bound_endpoint(IpListenEndpoint {
                        addr: Some(IpAddress::Ipv4(ip)),
                        port,
                    });
                });
                Ok(())
            }
            Inner::Udp { handle, .. } => {
                let mut last_err = EINVAL;
                // UDP 绑定 ephemeral port 时要容忍竞争；这里多试几次，避免分配出的临时端口刚好撞上已用端口。
                for _ in 0..32 {
                    let try_port = if ephemeral {
                        crate::net::alloc_ephemeral_port()
                    } else {
                        port
                    };
                    let r = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                        let s = sockets.get_mut::<udp::Socket>(*handle);
                        if ip == Ipv4Address::UNSPECIFIED {
                            // 当前网络实现主要是 loopback，`0.0.0.0` 在这里落到 `127.0.0.1` 更符合实际可通信行为。
                            // TODO: REAL LOGIC
                            s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), try_port))
                        } else {
                            s.bind((IpAddress::Ipv4(ip), try_port))
                        }
                    });
                    match r {
                        Ok(()) => return Ok(()),
                        Err(_) => {
                            last_err = EINVAL;
                            if !ephemeral {
                                break;
                            }
                        }
                    }
                }
                Err(last_err)
            }
            Inner::TcpListener { .. } => Err(EOPNOTSUPP),
        }
    }

    pub fn listen(&self, backlog: usize) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EOPNOTSUPP: isize = -95;
        // 限制 back log
        let backlog = backlog.max(1).min(32);
        crate::net::poll();
        let mut inner = self.inner.lock();
        //
        // only tcp可以被listen

        let handle = match &*inner {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        // 获取绑定的 pOrt
        let port = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<tcp::Socket>(handle);
            let bound = s.get_bound_endpoint();
            bound.port
        });

        if port == 0 {
            return Err(EINVAL);
        }

        let mut listen_handles = Vec::new();
        // smoltcp 没有现成的 backlog 队列，这里用“多个同时 listen 的 socket”近似模拟 backlog 槽位。
        // 现有 handle 直接复用成第一个槽位，避免无意义地销毁再重建。
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            let _ = s.listen((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
        });
        listen_handles.push(handle);
        //
        // 创建若干个 listen socket 来 满足backlog
        //
        for _ in 1..backlog {
            let h = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
                let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
                let mut s = tcp::Socket::new(rx, tx);

                let _ = s.listen((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
                sockets.add(s)
            });
            listen_handles.push(h);
        }
        *inner = Inner::TcpListener {
            port,
            backlog,
            listen: listen_handles,
        };
        drop(inner);
        self.notify_poll_waiters();
        Ok(())
    }

    pub fn accept(&self) -> Result<Arc<NetSocketFile>, isize> {
        const EOPNOTSUPP: isize = -95;
        const EAGAIN: isize = -11;
        loop {
            crate::net::poll();
            let mut inner = self.inner.lock();
            let Inner::TcpListener {
                port,
                backlog,
                listen,
            } = &mut *inner
            else {
                return Err(EOPNOTSUPP);
            };
            // backlog 本质上是一组监听槽位，accept 时要找到其中任意一个已完成握手的连接。
            let mut idx = None;
            for (i, h) in listen.iter().enumerate() {
                let established = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get::<tcp::Socket>(*h);
                    tcp_accept_ready(s.state())
                });
                if established {
                    idx = Some(i);
                    break;
                }
            }
            if let Some(i) = idx {
                let h = listen.remove(i);
                // 取走一个已连接槽位后，立刻补一个新的监听 socket 回去，维持用户看到的 backlog 容量。
                // TODO: 硬编码地址修改
                while listen.len() < *backlog {
                    let new_h = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
                        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
                        let mut s = tcp::Socket::new(rx, tx);
                        let _ = s.listen((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), *port));
                        sockets.add(s)
                    });
                    listen.push(new_h);
                }
                drop(inner);
                self.notify_poll_waiters();
                return Ok(Arc::new(NetSocketFile {
                    inner: Mutex::new(Inner::TcpStream { handle: h }),
                    opts: Mutex::new(SocketOptions {
                        sndbuf: TCP_TX_BUF_LEN_IPERF as u32,
                        rcvbuf: TCP_RX_BUF_LEN_IPERF as u32,
                        mcast_joined: false,
                        rd_shutdown: false,
                    }),
                    poll_waiters: Mutex::new(PollWaitQueue::default()),
                }));
            }
            drop(inner);
            if pending_unmasked_signal() {
                return Err(EINTR);
            }
            // 当前实现没有单独的阻塞等待原语，accept 采用“让出 CPU + 重试”的方式等待新连接到达。
            // TODO: Linux behavior
            crate::task::processor::suspend_current_and_run_next();
            // 这里保留 EAGAIN 只是提醒未来若接入 O_NONBLOCK，可在此分出非阻塞路径。
            let _ = EAGAIN;
        }
    }

    pub fn connect_v4(
        &self,
        ip: Ipv4Address,
        port: u16,
        local_port: Option<u16>,
    ) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EOPNOTSUPP: isize = -95;
        const EISCONN: isize = -106;
        const ECONNREFUSED: isize = -111;
        if port == 0 {
            return Err(EINVAL);
        }
        crate::net::poll();
        // 先摘出需要的 handle，避免拿着文件锁去执行可能较慢的网络状态机操作。
        let (tcp_handle, udp_handle) = match &*self.inner.lock() {
            Inner::TcpStream { handle } => (Some(*handle), None),
            Inner::Udp { handle, .. } => (None, Some(*handle)),
            _ => return Err(EOPNOTSUPP),
        };

        if let Some(handle) = tcp_handle {
            let r = crate::net::with_sockets_mut(|iface, _dev, sockets| {
                let cx = iface.context();
                let bound = sockets.get::<tcp::Socket>(handle).get_bound_endpoint();
                let local = local_port
                    .or_else(|| {
                        if bound.port != 0 {
                            Some(bound.port)
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(crate::net::alloc_ephemeral_port);
                let local_ep = IpListenEndpoint {
                    addr: bound.addr,
                    port: local,
                };
                sockets.get_mut::<tcp::Socket>(handle).connect(
                    cx,
                    (IpAddress::Ipv4(ip), port),
                    local_ep,
                )
            });
            match r {
                Ok(()) => {}
                Err(tcp::ConnectError::InvalidState) => return Err(EISCONN),
                Err(tcp::ConnectError::Unaddressable) => return Err(EINVAL),
            }
            // 目前文件层还没完整实现 O_NONBLOCK，所以 TCP connect 采用阻塞式等待：
            // 最多等待 5 秒，期间不断 poll 网络栈并让出 CPU，直到建立、失败或超时。
            const ETIMEDOUT: isize = -110;
            let start = crate::time::get_time_ms();
            let deadline = start.saturating_add(5_000);
            loop {
                crate::net::poll();
                let st = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    sockets.get::<tcp::Socket>(handle).state()
                });
                if matches!(st, tcp::State::Established) {
                    self.notify_poll_waiters();
                    break;
                }
                if matches!(st, tcp::State::Closed) {
                    self.notify_poll_waiters();
                    return Err(ECONNREFUSED);
                }
                if crate::time::get_time_ms() >= deadline {
                    self.notify_poll_waiters();
                    return Err(ETIMEDOUT);
                }
                crate::task::processor::suspend_current_and_run_next();
            }
            return Ok(());
        }

        let Some(handle) = udp_handle else {
            return Err(EOPNOTSUPP);
        };

        // UDP 的 connect 只是在内核侧记住默认对端，并确保后续发送时已经有本地端口；不会真的发起握手。
        let remote = IpEndpoint::new(IpAddress::Ipv4(ip), port);
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<udp::Socket>(handle);
            if s.endpoint().port == 0 {
                let local = local_port.unwrap_or_else(crate::net::alloc_ephemeral_port);
                let _ = s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), local));
            }
        });
        let mut inner = self.inner.lock();
        if let Inner::Udp { connected, .. } = &mut *inner {
            *connected = Some(remote);
            drop(inner);
            self.notify_poll_waiters();
            Ok(())
        } else {
            Err(EOPNOTSUPP)
        }
    }

    pub fn tcp_send(&self, data: &[u8]) -> Result<usize, isize> {
        const EOPNOTSUPP: isize = -95;
        const EPIPE: isize = -32;
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let mut off = 0usize;
        while off < data.len() {
            crate::net::poll();
            let sent = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<tcp::Socket>(handle);
                if !s.may_send() {
                    return Err(EPIPE);
                }
                if !s.can_send() {
                    return Ok(0usize);
                }
                // 一次最多只能塞进 smoltcp 当前 send buffer 剩余容量，余下部分在外层循环继续发送。
                Ok(s.send_slice(&data[off..]).unwrap_or(0))
            })?;
            if sent == 0 {
                if pending_unmasked_signal() {
                    return Err(EINTR);
                }
                crate::task::processor::suspend_current_and_run_next();
                continue;
            }
            off += sent;
            crate::net::poll();
        }
        Ok(off)
    }

    pub fn tcp_recv(&self, buf: &mut [u8]) -> Result<usize, isize> {
        const EOPNOTSUPP: isize = -95;
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        loop {
            crate::net::poll();
            let res: Result<Option<usize>, isize> =
                crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get_mut::<tcp::Socket>(handle);
                    if s.can_recv() {
                        return Ok(Some(s.recv_slice(buf).unwrap_or(0)));
                    }
                    // 对端已经关闭发送方向时应立即以 0 告知 EOF，而不是继续把调用者阻塞住。
                    if !s.may_recv() {
                        return Ok(Some(0usize));
                    }
                    Ok(None)
                });
            let res = res?;
            if let Some(n) = res {
                if n > 0 {
                    crate::net::poll();
                }
                return Ok(n);
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    pub fn tcp_close(&self) -> Result<(), isize> {
        const EOPNOTSUPP: isize = -95;
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            if !matches!(s.state(), tcp::State::Closed) {
                s.close();
            }
        });
        // 关闭后额外多 poll 几轮，让 loopback 上的 FIN 真正被发出并被对端观察到，
        // 否则紧接着 remove handle 可能让连接像“瞬间消失”而不是正常四次挥手的一部分。
        for _ in 0..8 {
            crate::net::poll();
        }
        Ok(())
    }

    pub fn udp_send_connected(&self, data: &[u8]) -> Result<usize, isize> {
        const EOPNOTSUPP: isize = -95;
        const EDESTADDRREQ: isize = -89;
        crate::net::poll();
        let (handle, remote) = match &*self.inner.lock() {
            Inner::Udp { handle, connected } => (*handle, *connected),
            _ => return Err(EOPNOTSUPP),
        };
        let Some(remote) = remote else {
            return Err(EDESTADDRREQ);
        };
        // smoltcp 发送前要求本地端点已绑定；若用户尚未 bind，则在首次发送前自动补一个临时端口。
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<udp::Socket>(handle);
            if s.endpoint().port == 0 {
                let port = crate::net::alloc_ephemeral_port();
                let _ = s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
            }
        });
        loop {
            crate::net::poll();
            let ok = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<udp::Socket>(handle);
                if !s.can_send() {
                    return false;
                }
                s.send_slice(data, remote).is_ok()
            });
            if ok {
                crate::net::poll();
                return Ok(data.len());
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    pub fn udp_send_to_v4(&self, ip: Ipv4Address, port: u16, data: &[u8]) -> Result<usize, isize> {
        const EINVAL: isize = -22;
        const EOPNOTSUPP: isize = -95;
        if port == 0 {
            return Err(EINVAL);
        }
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let remote = IpEndpoint::new(IpAddress::Ipv4(ip), port);
        // 与 `udp_send_connected()` 一样，发包前必须确保本地端口已经就绪。
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<udp::Socket>(handle);
            if s.endpoint().port == 0 {
                let port = crate::net::alloc_ephemeral_port();
                let _ = s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
            }
        });
        loop {
            crate::net::poll();
            let ok = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<udp::Socket>(handle);
                if !s.can_send() {
                    return false;
                }
                s.send_slice(data, remote).is_ok()
            });
            if ok {
                crate::net::poll();
                return Ok(data.len());
            }
            if pending_unmasked_signal() {
                return Err(EINTR);
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    pub fn udp_recv_from(&self, buf: &mut [u8]) -> Result<(usize, Ipv4Address, u16), isize> {
        const EOPNOTSUPP: isize = -95;
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        loop {
            crate::net::poll();
            let res = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<udp::Socket>(handle);
                if !s.can_recv() {
                    return None;
                }
                s.recv().ok().map(|(payload, meta)| {
                    let n = min(buf.len(), payload.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    (n, meta)
                })
            });
            if let Some((n, meta)) = res {
                let IpAddress::Ipv4(ip) = meta.endpoint.addr;
                if crate::debug_config::DEBUG_NET && n == 4 {
                    let v = u32::from_ne_bytes(buf[..4].try_into().unwrap_or([0; 4]));
                    crate::println!(
                        "[net] udp recv {} bytes from {}:{} val=0x{:08x}",
                        n,
                        ip,
                        meta.endpoint.port,
                        v
                    );
                }
                // UDP 接收天然要把源地址一并返回给上层，因此这里返回 `(len, src_ip, src_port)`。
                return Ok((n, ip, meta.endpoint.port));
            }
            if pending_unmasked_signal() {
                return Err(EINTR);
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    /// 返回两端地址
    pub fn tcp_endpoints_v4(&self) -> Option<(Ipv4Address, u16, Ipv4Address, u16)> {
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return None,
        };
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<tcp::Socket>(handle);
            let local = s.local_endpoint()?;
            let remote = s.remote_endpoint()?;
            let IpAddress::Ipv4(lip) = local.addr;
            let IpAddress::Ipv4(rip) = remote.addr;
            Some((lip, local.port, rip, remote.port))
        })
    }

    /// tcp 的绑定地址，两种情况，普通tcp listen tcp
    pub fn tcp_local_endpoint_v4(&self) -> Option<(Ipv4Address, u16)> {
        crate::net::poll();
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get::<tcp::Socket>(*handle);
                if let Some(local) = s.local_endpoint() {
                    let IpAddress::Ipv4(ip) = local.addr;
                    return Some((ip, local.port));
                }
                let bound = s.get_bound_endpoint();
                let ip = match bound.addr {
                    Some(IpAddress::Ipv4(ip)) => ip,
                    _ => Ipv4Address::UNSPECIFIED,
                };
                Some((ip, bound.port))
            }),
            Inner::TcpListener { port, .. } => Some((Ipv4Address::new(127, 0, 0, 1), *port)),
            _ => None,
        }
    }

    pub fn udp_endpoint_v4(&self) -> Option<(Ipv4Address, u16)> {
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return None,
        };
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<udp::Socket>(handle);
            let ep = s.endpoint();
            let ip = match ep.addr {
                Some(IpAddress::Ipv4(ip)) => ip,
                _ => Ipv4Address::UNSPECIFIED,
            };
            Some((ip, ep.port))
        })
    }

    pub fn udp_peer_v4(&self) -> Option<(Ipv4Address, u16)> {
        crate::net::poll();
        match &*self.inner.lock() {
            Inner::Udp {
                connected: Some(peer),
                ..
            } => match peer.addr {
                IpAddress::Ipv4(ip) => Some((ip, peer.port)),
            },
            _ => None,
        }
    }
}

/// 负责在文件对象销毁时回收底层 socket 资源。
impl Drop for NetSocketFile {
    fn drop(&mut self) {
        let kind = match &*self.inner.lock() {
            Inner::TcpStream { .. } => NetSocketKind::TcpStream,
            Inner::TcpListener { .. } => NetSocketKind::TcpListener,
            Inner::Udp { .. } => NetSocketKind::Udp,
        };

        if kind == NetSocketKind::TcpStream {
            // TCP 要先尝试发出 FIN，再把 handle 从 `SocketSet` 里摘掉；
            // 否则对端看到的会更像“连接被突然回收”，而不是正常关闭流程。
            let _ = self.tcp_close();
        }

        let handles: Vec<SocketHandle> = match &*self.inner.lock() {
            Inner::TcpStream { handle } => vec![*handle],
            Inner::Udp { handle, .. } => vec![*handle],
            Inner::TcpListener { listen, .. } => listen.clone(),
        };
        unregister_poll_waiters(handles.as_slice());
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            for h in handles {
                sockets.remove(h);
            }
        })
    }
}

#[derive(Clone)]
/// 计算 poll 掩码时使用的轻量级快照。
///
/// 这里只保留查询事件所需的最小信息，避免把 `inner` 锁一路带进全局网络锁。
enum Snapshot {
    TcpStream {
        handle: SocketHandle,
        rd_shutdown: bool,
    },
    TcpListener(Vec<SocketHandle>),
    Udp(SocketHandle),
}

/// 把网络 socket 挂接到通用 `File` 接口上的适配层。
impl File for NetSocketFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        crate::net::poll();
        let inner = self.inner.lock();
        let kind = match &*inner {
            Inner::TcpStream { handle } => Some((*handle, NetSocketKind::TcpStream)),
            Inner::Udp { handle, .. } => Some((*handle, NetSocketKind::Udp)),
            Inner::TcpListener { .. } => None,
        };
        drop(inner);
        let Some((handle, kind)) = kind else {
            return 0;
        };
        match kind {
            NetSocketKind::TcpStream => {
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    loop {
                        crate::net::poll();
                        enum ReadStep {
                            Data(usize),
                            Eof,
                            Blocked,
                        }
                        let res = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                            let s = sockets.get_mut::<tcp::Socket>(handle);
                            if s.can_recv() {
                                match s.recv_slice(*slice) {
                                    Ok(n) => ReadStep::Data(n),
                                    Err(_) => ReadStep::Blocked,
                                }
                            } else if !s.may_recv() {
                                ReadStep::Eof
                            } else {
                                ReadStep::Blocked
                            }
                        });
                        match res {
                            ReadStep::Data(n) => {
                                total += n;
                                if n > 0 {
                                    crate::net::poll();
                                }
                                break;
                            }
                            // TCP 是流语义：一旦读到 EOF，就应立即把已经拿到的数据返回给上层，
                            // 不再继续填后续 UserBuffer 分片。
                            ReadStep::Eof => return total,
                            ReadStep::Blocked => {}
                        }
                        crate::task::processor::suspend_current_and_run_next();
                    }
                    // UserBuffer 可能包含空分片；到这里说明本次分片已处理完成，可直接结束外层遍历。
                    if slice.is_empty() {
                        break;
                    }
                }
                total
            }
            NetSocketKind::Udp => {
                // UDP 没有“把一个报文拆成多次 read” 的流式语义，必须先整包收进临时缓冲区，
                // 再按 UserBuffer 的分片布局复制出去；否则会把一次 datagram 错误地暴露成多次读取。
                let total_len = buf.buffers.iter().map(|b| b.len()).sum::<usize>();
                if total_len == 0 {
                    return 0;
                }
                let mut tmp = alloc::vec![0u8; total_len];
                let n = match self.udp_recv_from(&mut tmp) {
                    Ok((n, _, _)) => n,
                    Err(_) => return 0,
                };
                let mut copied = 0usize;
                for slice in buf.buffers.iter_mut() {
                    let to_copy = min(slice.len(), n - copied);
                    slice[..to_copy].copy_from_slice(&tmp[copied..copied + to_copy]);
                    copied += to_copy;
                    if copied >= n {
                        break;
                    }
                }
                copied
            }
            NetSocketKind::TcpListener => 0,
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        crate::net::poll();
        enum WriteSnapshot {
            Tcp(SocketHandle),
            Udp(SocketHandle, Option<IpEndpoint>),
            None,
        }
        let snapshot = match &*self.inner.lock() {
            Inner::TcpStream { handle } => WriteSnapshot::Tcp(*handle),
            Inner::Udp { handle, connected } => WriteSnapshot::Udp(*handle, *connected),
            Inner::TcpListener { .. } => WriteSnapshot::None,
        };
        match snapshot {
            WriteSnapshot::None => 0,
            WriteSnapshot::Tcp(handle) => {
                let mut total = 0usize;
                for slice in buf.buffers.iter() {
                    let mut off = 0usize;
                    while off < slice.len() {
                        crate::net::poll();
                        let sent = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                            let s = sockets.get_mut::<tcp::Socket>(handle);
                            if !s.can_send() {
                                return 0usize;
                            }
                            // TCP 写是流式的，允许把一个用户缓冲区分多轮塞进底层发送队列。
                            s.send_slice(&slice[off..]).unwrap_or(0)
                        });
                        if sent == 0 {
                            // send buffer 暂时满时主动让出 CPU，等待后续 poll 推进 ACK / 窗口更新。
                            crate::task::processor::suspend_current_and_run_next();
                            continue;
                        }
                        off += sent;
                        total += sent;
                        crate::net::poll();
                    }
                }
                total
            }
            WriteSnapshot::Udp(handle, remote) => {
                let Some(remote) = remote else { return 0 };
                let total_len = buf.buffers.iter().map(|b| b.len()).sum::<usize>();
                if total_len == 0 {
                    return 0;
                }
                // UDP 一次 write 对应一个完整 datagram，因此先把所有分片拼成连续缓冲区再一次性发送。
                let mut data = alloc::vec![0u8; total_len];
                let mut off = 0usize;
                for slice in buf.buffers.iter() {
                    data[off..off + slice.len()].copy_from_slice(slice);
                    off += slice.len();
                }
                crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get_mut::<udp::Socket>(handle);
                    if s.endpoint().port == 0 {
                        let port = crate::net::alloc_ephemeral_port();
                        let r = s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
                        if crate::debug_config::DEBUG_NET {
                            crate::println!("[net] udp autobind port={} -> {:?}", port, r);
                        }
                    }
                });
                loop {
                    crate::net::poll();
                    let ok = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                        let s = sockets.get_mut::<udp::Socket>(handle);
                        if !s.can_send() {
                            return false;
                        }
                        let r = s.send_slice(&data, remote);
                        if crate::debug_config::DEBUG_NET && data.len() <= 8 {
                            crate::println!(
                                "[net] udp send {} bytes to {} -> {:?}",
                                data.len(),
                                remote,
                                r
                            );
                        }
                        r.is_ok()
                    });
                    if ok {
                        crate::net::poll();
                        return data.len();
                    }
                    crate::task::processor::suspend_current_and_run_next();
                }
            }
        }
    }

    fn poll_mask(&self) -> i16 {
        // 先推进网络栈，再返回当前统一计算出的事件掩码。
        crate::net::poll();
        self.current_poll_mask()
    }

    fn supports_poll(&self) -> bool {
        true
    }

    /// 添加本地任务到 poll waiters 并且 添加 我们的 Socket 到全局的poll结构
    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        // 文件对象本地 wait queue 负责 `NetSocketFile::notify_poll_waiters()` 这一路唤醒，
        // 全局 `NET_POLL_WAITERS` 则负责底层 socket 状态变化驱动的唤醒；两边都要注册。
        let _ = self.poll_waiters.lock().register_waiter(task);
        let mut armed = false;
        for (handle, kind) in self.poll_registration_handles() {
            armed = register_poll_waiter_for_handle(handle, kind, task) || armed;
        }
        armed
            || self.current_poll_mask() != 0
            || matches!(&*self.inner.lock(), Inner::TcpListener { .. })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
