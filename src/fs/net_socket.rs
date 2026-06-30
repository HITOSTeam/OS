use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::bpf::BpfProgFile;
use crate::fs::{File, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, PollWaitQueue, wake_tasks};
use crate::mm::UserBuffer;
use crate::syscall::net::netdev;
use crate::syscall::net::{
    AF_INET, AF_INET6, IP_PMTUDISC_DO, IP_PMTUDISC_PROBE, IP_PMTUDISC_WANT, IPPROTO_TCP,
    IPPROTO_UDP, IPPROTO_UDPLITE, IPV4_UDP_MAX_PAYLOAD, Ipv4ErrorQueueEntry, SO_EE_ORIGIN_ICMP,
    SocketTimestamp, SocketTimestampMode, UDPLITE_RECV_CSCOV, UDPLITE_SEND_CSCOV,
    alloc_socket_inode, cbpf::ClassicBpfProgram,
};
use crate::task::processor::{current_process, current_task};
use crate::task::signal::has_wait_interrupting_pending;
use crate::task::task_block::TaskControlBlock;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::phy::PacketMeta;
use smoltcp::socket::Socket as SmolSocket;
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::Duration;
use smoltcp::wire::{
    IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Address, Ipv6Address,
};

// 全局  网络相关 参数设置
// TCP 默认收发缓冲区刻意配得较大，主要是为了让 iperf 一类大吞吐测试
// 不会过早被 smoltcp 的用户态缓冲区限制住。
//
const TCP_RX_BUF_LEN_IPERF: usize = 1024 * 1024;
const TCP_TX_BUF_LEN_IPERF: usize = 1024 * 1024;
// Linux 的 UDP rmem/wmem 是按需消耗的；smoltcp 需要建 socket 时就给定容量。
// 这里保持较小的初始缓冲，避免 LTP multicast 一次创建数千个 UDP socket 时
// 因每个 socket 预分配大块内核堆而 OOM。
const UDP_PACKET_METADATA_LEN: usize = 16;
const UDP_RX_BUF_LEN: usize = 8 * 1024;
const UDP_TX_BUF_LEN: usize = 8 * 1024;
const IPV4_ERROR_QUEUE_LIMIT: usize = 16;
const IPV4_DEFAULT_TTL: i32 = 64;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const TCP_KEEPALIVE_DEFAULT_SECS: u64 = 7_200;
const TCP_KEEPINTVL_DEFAULT_SECS: u32 = 75;
const TCP_KEEPCNT_DEFAULT: u32 = 9;
const TCP_BUFFER_BYTES_PER_HANDLE: usize = TCP_RX_BUF_LEN_IPERF + TCP_TX_BUF_LEN_IPERF;
const TCP_LISTEN_BACKLOG_PREALLOC_LIMIT: usize = 8;
//
// 网络阻塞等待被未屏蔽信号打断时，统一向上层返回 Linux 风格的 EINTR。
const EINTR: isize = -4;

static LIVE_NET_SOCKET_FILES: AtomicUsize = AtomicUsize::new(0);
static CREATED_NET_SOCKET_FILES: AtomicUsize = AtomicUsize::new(0);
static DROPPED_NET_SOCKET_FILES: AtomicUsize = AtomicUsize::new(0);
static LIVE_TCP_HANDLES: AtomicUsize = AtomicUsize::new(0);
static CREATED_TCP_HANDLES: AtomicUsize = AtomicUsize::new(0);
static FREED_TCP_HANDLES: AtomicUsize = AtomicUsize::new(0);
static LIVE_TCP_BUFFER_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_UDP_HANDLES: AtomicUsize = AtomicUsize::new(0);
static CREATED_UDP_HANDLES: AtomicUsize = AtomicUsize::new(0);
static FREED_UDP_HANDLES: AtomicUsize = AtomicUsize::new(0);
static LIVE_UDP_BUFFER_BYTES: AtomicUsize = AtomicUsize::new(0);

fn note_net_socket_file_created() {
    CREATED_NET_SOCKET_FILES.fetch_add(1, Ordering::Relaxed);
    LIVE_NET_SOCKET_FILES.fetch_add(1, Ordering::Relaxed);
}

fn note_net_socket_file_dropped() {
    DROPPED_NET_SOCKET_FILES.fetch_add(1, Ordering::Relaxed);
    LIVE_NET_SOCKET_FILES.fetch_sub(1, Ordering::Relaxed);
}

fn note_tcp_handle_created() {
    CREATED_TCP_HANDLES.fetch_add(1, Ordering::Relaxed);
    LIVE_TCP_HANDLES.fetch_add(1, Ordering::Relaxed);
    LIVE_TCP_BUFFER_BYTES.fetch_add(TCP_BUFFER_BYTES_PER_HANDLE, Ordering::Relaxed);
}

fn note_tcp_handles_freed(count: usize) {
    if count == 0 {
        return;
    }
    FREED_TCP_HANDLES.fetch_add(count, Ordering::Relaxed);
    LIVE_TCP_HANDLES.fetch_sub(count, Ordering::Relaxed);
    LIVE_TCP_BUFFER_BYTES.fetch_sub(
        count.saturating_mul(TCP_BUFFER_BYTES_PER_HANDLE),
        Ordering::Relaxed,
    );
}

fn note_udp_handle_created(rx_bytes: usize, tx_bytes: usize) {
    CREATED_UDP_HANDLES.fetch_add(1, Ordering::Relaxed);
    LIVE_UDP_HANDLES.fetch_add(1, Ordering::Relaxed);
    LIVE_UDP_BUFFER_BYTES.fetch_add(rx_bytes + tx_bytes, Ordering::Relaxed);
}

fn note_udp_handle_resized(old_rx: usize, old_tx: usize, new_rx: usize, new_tx: usize) {
    let old_total = old_rx + old_tx;
    let new_total = new_rx + new_tx;
    if new_total >= old_total {
        LIVE_UDP_BUFFER_BYTES.fetch_add(new_total - old_total, Ordering::Relaxed);
    } else {
        LIVE_UDP_BUFFER_BYTES.fetch_sub(old_total - new_total, Ordering::Relaxed);
    }
}

fn note_udp_handle_freed(rx_bytes: usize, tx_bytes: usize) {
    FREED_UDP_HANDLES.fetch_add(1, Ordering::Relaxed);
    LIVE_UDP_HANDLES.fetch_sub(1, Ordering::Relaxed);
    LIVE_UDP_BUFFER_BYTES.fetch_sub(rx_bytes + tx_bytes, Ordering::Relaxed);
}

pub(crate) fn debug_net_socket_atomic_heap_state() {
    crate::println!(
        "[oom][net-atomic] files live={} created={} dropped={} tcp_handles live={} created={} freed={} tcp_buf={} udp_handles live={} created={} freed={} udp_buf={}",
        LIVE_NET_SOCKET_FILES.load(Ordering::Relaxed),
        CREATED_NET_SOCKET_FILES.load(Ordering::Relaxed),
        DROPPED_NET_SOCKET_FILES.load(Ordering::Relaxed),
        LIVE_TCP_HANDLES.load(Ordering::Relaxed),
        CREATED_TCP_HANDLES.load(Ordering::Relaxed),
        FREED_TCP_HANDLES.load(Ordering::Relaxed),
        LIVE_TCP_BUFFER_BYTES.load(Ordering::Relaxed),
        LIVE_UDP_HANDLES.load(Ordering::Relaxed),
        CREATED_UDP_HANDLES.load(Ordering::Relaxed),
        FREED_UDP_HANDLES.load(Ordering::Relaxed),
        LIVE_UDP_BUFFER_BYTES.load(Ordering::Relaxed),
    );
}

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

fn wait_for_socket_event(
    socket: &NetSocketFile,
    required_mask: i16,
    deadline_ms: Option<usize>,
) -> Result<(), isize> {
    const EAGAIN: isize = -11;
    if pending_unmasked_signal() {
        return Err(EINTR);
    }
    let Some(task) = current_task() else {
        socket.poll_net();
        return Err(EAGAIN);
    };
    if let Some(deadline) = deadline_ms {
        let now = crate::time::get_time_ms();
        if now >= deadline {
            return Err(EAGAIN);
        }
        let wait_ms = deadline.saturating_sub(now).max(1);
        crate::task::block_sleep::add_timer(Arc::clone(&task), wait_ms);
    } else {
        // The current net backend is poll-driven rather than interrupt-driven.
        // Register for real socket wakeups, but keep a short timer fallback so
        // blocking recv paths still periodically drive the stack if no peer
        // task happens to poll it.
        crate::task::block_sleep::add_timer(Arc::clone(&task), 1);
    }
    let _ = <NetSocketFile as File>::register_poll_waiter(socket, &task);
    socket.poll_net();
    if (socket.current_poll_mask() & required_mask) != 0 {
        return Ok(());
    }
    crate::task::processor::block_current_and_run_next();
    Ok(())
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

fn tcp_state_for_proc(state: tcp::State) -> u8 {
    match state {
        tcp::State::Established => 0x01,
        tcp::State::SynSent => 0x02,
        tcp::State::SynReceived => 0x03,
        tcp::State::FinWait1 => 0x04,
        tcp::State::FinWait2 => 0x05,
        tcp::State::TimeWait => 0x06,
        tcp::State::Closed => 0x07,
        tcp::State::CloseWait => 0x08,
        tcp::State::LastAck => 0x09,
        tcp::State::Listen => 0x0a,
        tcp::State::Closing => 0x0b,
    }
}

fn ipv4_bytes(ip: Ipv4Address) -> [u8; 4] {
    let b = ip.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

fn ipv4_ttl_hop_limit(value: i32) -> Option<u8> {
    if value < 0 {
        None
    } else {
        Some(value.clamp(1, 255) as u8)
    }
}

fn ipv4_tos_meta(value: u8) -> Option<u8> {
    (value != 0).then_some(value)
}

fn ipv4_pmtu_reports_oversize(pmtudisc: i32) -> bool {
    matches!(pmtudisc, IP_PMTUDISC_DO | IP_PMTUDISC_PROBE)
}

fn tcp_keepalive_timers(
    enabled: bool,
    keepidle_secs: u32,
    keepintvl_secs: u32,
    keepcnt: u32,
) -> (Option<Duration>, Option<Duration>) {
    if !enabled {
        return (None, None);
    }
    let interval_secs = keepintvl_secs.max(1) as u64;
    let timeout_secs = (keepidle_secs as u64)
        .saturating_add(interval_secs.saturating_mul(keepcnt.max(1) as u64))
        .max(1);
    (
        Some(Duration::from_secs(interval_secs)),
        Some(Duration::from_secs(timeout_secs)),
    )
}

fn udp_send_metadata(
    remote: IpEndpoint,
    local_addr: Option<IpAddress>,
    ipv4_tos: Option<u8>,
) -> udp::UdpMetadata {
    let mut meta = PacketMeta::default();
    meta.set_ipv4_tos(ipv4_tos);
    udp::UdpMetadata {
        endpoint: remote,
        local_address: local_addr,
        meta,
    }
}

fn udp_packet_buffer(payload_len: usize) -> udp::PacketBuffer<'static> {
    udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_METADATA_LEN],
        vec![0u8; payload_len],
    )
}

fn endpoint_v4(endpoint: Option<IpEndpoint>) -> ([u8; 4], u16) {
    let Some(endpoint) = endpoint else {
        return ([0; 4], 0);
    };
    let ip = match endpoint.addr {
        IpAddress::Ipv4(ip) => ip,
        IpAddress::Ipv6(_) => Ipv4Address::UNSPECIFIED,
    };
    (ipv4_bytes(ip), endpoint.port)
}

fn listen_endpoint_v4(endpoint: IpListenEndpoint) -> ([u8; 4], u16) {
    let ip = match endpoint.addr {
        Some(IpAddress::Ipv4(ip)) => ip,
        _ => Ipv4Address::UNSPECIFIED,
    };
    (ipv4_bytes(ip), endpoint.port)
}

fn endpoint_addr_v4(endpoint: IpEndpoint) -> Ipv4Address {
    match endpoint.addr {
        IpAddress::Ipv4(ip) => ip,
        IpAddress::Ipv6(_) => Ipv4Address::UNSPECIFIED,
    }
}

fn ip_is_unspecified(ip: IpAddress) -> bool {
    match ip {
        IpAddress::Ipv4(ip) => ip == Ipv4Address::UNSPECIFIED,
        IpAddress::Ipv6(ip) => ip == Ipv6Address::UNSPECIFIED,
    }
}

fn ipv6_bytes(ip: Ipv6Address) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(ip.as_bytes());
    out
}

fn inet_bind_addr_conflicts(left: Option<IpAddress>, right: Option<IpAddress>) -> bool {
    left.is_none() || right.is_none() || left == right
}

fn inet_bind_domains_conflict(
    left_addr: Option<IpAddress>,
    left_domain: u16,
    left_v6only: bool,
    right_addr: Option<IpAddress>,
    right_domain: u16,
    right_v6only: bool,
) -> bool {
    if left_domain == right_domain {
        return inet_bind_addr_conflicts(left_addr, right_addr);
    }
    let (v6_addr, v6only, v4_addr) = if left_domain == AF_INET6 {
        (left_addr, left_v6only, right_addr)
    } else {
        (right_addr, right_v6only, left_addr)
    };
    if v6only {
        return false;
    }
    match v6_addr {
        None => true,
        Some(IpAddress::Ipv4(v6_v4)) => match v4_addr {
            None => true,
            Some(IpAddress::Ipv4(v4)) => v6_v4 == v4,
            Some(IpAddress::Ipv6(_)) => false,
        },
        Some(IpAddress::Ipv6(_)) => false,
    }
}

#[derive(Clone, Copy)]
struct TcpSocketMeta {
    reuseaddr: bool,
    domain: u16,
    ipv6_v6only: bool,
}

#[derive(Clone, Copy)]
struct UdpSocketMeta {
    reuseaddr: bool,
    domain: u16,
    ipv6_v6only: bool,
}

fn tcp_port_in_use(
    net_ns_id: usize,
    sockets: &SocketSet<'_>,
    skip: SocketHandle,
    requested_addr: Option<IpAddress>,
    requested_port: u16,
    requested_reuseaddr: bool,
    requested_domain: u16,
    requested_v6only: bool,
) -> bool {
    let tcp_meta = TCP_SOCKET_META.lock();
    sockets.iter().any(|(handle, socket)| {
        if handle == skip {
            return false;
        }
        let SmolSocket::Tcp(sock) = socket else {
            return false;
        };
        let peer = tcp_meta
            .get(&(net_ns_id, handle))
            .copied()
            .unwrap_or(TcpSocketMeta {
                reuseaddr: false,
                domain: AF_INET,
                ipv6_v6only: false,
            });
        let bound = sock.get_bound_endpoint();
        let bound_conflicts = bound.port == requested_port
            && requested_port != 0
            && inet_bind_domains_conflict(
                bound.addr,
                peer.domain,
                peer.ipv6_v6only,
                requested_addr,
                requested_domain,
                requested_v6only,
            );
        let local_conflicts = sock.local_endpoint().is_some_and(|endpoint| {
            endpoint.port == requested_port
                && requested_port != 0
                && inet_bind_domains_conflict(
                    Some(endpoint.addr),
                    peer.domain,
                    peer.ipv6_v6only,
                    requested_addr,
                    requested_domain,
                    requested_v6only,
                )
        });
        if !bound_conflicts && !local_conflicts {
            return false;
        }

        let peer_reuseaddr = peer.reuseaddr;
        !(requested_reuseaddr && peer_reuseaddr && sock.state() != tcp::State::Listen)
    })
}

fn udp_port_in_use(
    net_ns_id: usize,
    sockets: &SocketSet<'_>,
    skip: SocketHandle,
    requested_addr: Option<IpAddress>,
    requested_port: u16,
    requested_reuseaddr: bool,
    requested_protocol: IpProtocol,
    requested_domain: u16,
    requested_v6only: bool,
) -> bool {
    let udp_meta = UDP_SOCKET_META.lock();
    sockets.iter().any(|(handle, socket)| {
        if handle == skip {
            return false;
        }
        let SmolSocket::Udp(sock) = socket else {
            return false;
        };
        if sock.transport_protocol() != requested_protocol {
            return false;
        }
        let peer = udp_meta
            .get(&(net_ns_id, handle))
            .copied()
            .unwrap_or(UdpSocketMeta {
                reuseaddr: false,
                domain: AF_INET,
                ipv6_v6only: false,
            });
        let endpoint = sock.endpoint();
        if endpoint.port != requested_port
            || requested_port == 0
            || !inet_bind_domains_conflict(
                endpoint.addr,
                peer.domain,
                peer.ipv6_v6only,
                requested_addr,
                requested_domain,
                requested_v6only,
            )
        {
            return false;
        }

        let peer_reuseaddr = peer.reuseaddr;
        !(requested_reuseaddr && peer_reuseaddr)
    })
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
        /// Linux listen 端点；`addr = None` 表示 `0.0.0.0` wildcard bind。
        endpoint: IpListenEndpoint,
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
    /// socket 创建时所在的 network namespace。Linux socket 绑定创建时的 netns，
    /// 后续进程 `setns()` 不应改变这个 socket 可见的网络设备集合。
    net_ns_id: usize,
    /// 创建 socket 时的地址族；AF_INET6 目前只提供 IPv4-mapped dual-stack 兼容。
    domain: u16,
    /// 创建 socket 时的协议号，用于 `SO_PROTOCOL` 与 UDP-Lite 这类同类型不同协议的区分。
    protocol: usize,
    /// `/proc/net/{tcp,udp}` 中暴露的稳定 socket inode，类似 Linux `sock_i_ino()`。
    proc_inode: u64,
    /// 创建 socket 时的有效 uid，用于 `/proc/net/{tcp,udp}` owner 字段。
    proc_uid: u32,
    /// socket 类型与底层 handle。
    inner: Mutex<Inner>,
    /// 额外 socket 选项与半关闭状态。
    opts: Mutex<SocketOptions>,
    /// IPv4 multicast membership 列表，类似 Linux `inet_sock::mc_list`。
    mcast_memberships: Mutex<Vec<Ipv4MulticastMembership>>,
    /// 绑定在当前文件对象上的 poll 等待者。
    poll_waiters: Mutex<PollWaitQueue>,
}

#[derive(Clone)]
/// 与文件对象绑定的 socket 选项快照。
pub struct SocketOptions {
    /// `SO_REUSEADDR`，TCP/UDP bind 冲突判定会按 Linux 复用规则消费。
    reuseaddr: bool,
    /// `IPV6_V6ONLY`，AF_INET6 默认关闭，保持 Linux dual-stack 默认值。
    ipv6_v6only: bool,
    /// `SO_DONTROUTE`，UDP 发送路径会按本链路直连语义约束选路。
    dontroute: bool,
    /// `SO_BROADCAST`，UDP 发往 IPv4 broadcast 时必须开启，否则返回 `EACCES`。
    broadcast: bool,
    /// `SO_KEEPALIVE`，TCP socket 会同步到底层 keepalive 定时器；其他协议保存用户可见状态。
    keepalive: bool,
    /// `TCP_NODELAY`，关闭 Nagle 算法以降低小包延迟。
    tcp_nodelay: bool,
    /// `TCP_CORK`，发送路径会延后下发小块数据，关闭时再 flush。
    tcp_cork: bool,
    /// `TCP_KEEPIDLE`，开启 keepalive 后首次探测前的空闲秒数。
    tcp_keepidle_secs: u32,
    /// `TCP_KEEPINTVL`，同步到 smoltcp keepalive 探测周期。
    tcp_keepintvl_secs: u32,
    /// `TCP_KEEPCNT`，用于推导 keepalive 失败 timeout。
    tcp_keepcnt: u32,
    /// 用户视角的发送缓冲区大小配置。
    sndbuf: u32,
    /// 用户视角的接收缓冲区大小配置。
    rcvbuf: u32,
    /// `SO_OOBINLINE`，TCP 带外数据尚未实现，这里先保存用户可见状态。
    oobinline: bool,
    /// `SO_NO_CHECK`，主要面向 UDP 校验和控制；开启后 UDP 发包使用 0 checksum。
    no_check: bool,
    /// UDP-Lite 发送端 checksum coverage；0 表示全包覆盖。
    udplite_send_cscov: u32,
    /// UDP-Lite 接收端最小 checksum coverage；0 表示使用 Linux 默认策略。
    udplite_recv_cscov: u32,
    /// `SO_PRIORITY`，当前没有 qdisc，但 Linux 允许设置并回读优先级。
    priority: u32,
    /// `SO_MARK`，当前轻量路由不使用该 mark，但需按 Linux ABI 保存并可回读。
    mark: u32,
    /// `SO_RCVMARK`：接收时把 skb mark 作为 `SO_MARK` 控制消息返回。
    rcvmark: bool,
    /// `SO_RCVPRIORITY`：接收时把 skb priority 作为 `SO_PRIORITY` 控制消息返回。
    rcvpriority: bool,
    /// `SO_LINGER` 状态，单位按 Linux 用户 ABI 使用秒。
    linger_on: bool,
    linger_sec: i32,
    /// `SO_RCVLOWAT` 默认 1。
    rcvlowat: i32,
    /// `SO_BUSY_POLL` 保存用户请求的低延迟忙轮询时间，单位微秒。
    busy_poll: u32,
    /// `SO_RCVTIMEO`，None 表示 Linux 默认的无限阻塞等待。
    rcvtimeo_ms: Option<usize>,
    /// `SO_SNDTIMEO`，None 表示 Linux 默认的无限阻塞等待。
    sndtimeo_ms: Option<usize>,
    /// `IP_MULTICAST_IF` 选择的出接口，0 表示由路由/默认接口决定。
    mcast_ifindex: i32,
    /// `IP_MULTICAST_IF` 保存的本地地址；Linux getsockopt 返回这个字段。
    mcast_ifaddr: [u8; 4],
    /// `IP_MULTICAST_TTL`，Linux 默认值为 1。
    mcast_ttl: u8,
    /// `IP_MULTICAST_LOOP`，Linux 默认开启。
    mcast_loop: bool,
    /// IPv4 路径 MTU discovery 策略，取值对齐 Linux IP_PMTUDISC_*。
    ip_pmtudisc: i32,
    /// 是否把异步 IPv4 错误放入 socket error queue。
    ip_recverr: bool,
    /// 是否通过控制消息返回 IPv4 TTL。
    ip_recvttl: bool,
    /// 是否通过控制消息返回 IPv4 TOS/DSCP/ECN 字节。
    ip_recvtos: bool,
    /// `IP_TOS` 保存的 IPv4 TOS/DSCP/ECN 字节。
    ip_tos: u8,
    /// 是否通过控制消息返回 IPv4 packet info。
    ip_pktinfo: bool,
    /// 用户指定的 IPv4 TTL；-1 表示使用系统默认 TTL。
    ip_ttl: i32,
    /// `SO_BINDTODEVICE` 绑定的接口；0 表示未绑定。
    bound_ifindex: i32,
    /// 本端是否执行过读半关闭；这会影响 poll 的 RDHUP 语义。
    rd_shutdown: bool,
    /// 本端是否执行过写半关闭；TCP/UDP 发送据此返回 EPIPE。
    wr_shutdown: bool,
    /// 非阻塞 TCP connect 已发起但尚未完成。
    connect_in_progress: bool,
    /// 待用户通过 `getsockopt(SO_ERROR)` 读取的一次性错误码，按 Linux ABI 返回正 errno。
    pending_error: i32,
    /// `IP_RECVERR` 打开时积累的 IPv4 异步错误队列。
    error_queue: VecDeque<Ipv4ErrorQueueEntry>,
    /// `SO_TIMESTAMP*` 控制消息模式；关闭时只保留 `SIOCGSTAMP*` 查询状态。
    timestamp_mode: SocketTimestampMode,
    /// 最近一次真正接收数据的时间，供 `SIOCGSTAMP*` 查询。
    last_timestamp: Option<SocketTimestamp>,
    /// `SO_LOCK_FILTER`：锁定后禁止替换或卸载 socket filter。
    filter_locked: bool,
    /// `SO_ATTACH_FILTER` 附加的 classic BPF socket receive filter。
    classic_filter: Option<ClassicBpfProgram>,
    /// `SO_ATTACH_BPF` 附加的 socket receive filter。
    bpf_filter: Option<Arc<BpfProgFile>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4SourceFilterMode {
    Exclude,
    Include,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Ipv4MulticastMembership {
    group: [u8; 4],
    ifindex: i32,
    ifaddr: [u8; 4],
    filter_mode: Ipv4SourceFilterMode,
    sources: Vec<[u8; 4]>,
}

#[derive(Clone, Copy)]
pub struct ProcNetSocketSnapshot {
    pub kind: NetSocketKind,
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub state: u8,
    pub tx_queue: usize,
    pub rx_queue: usize,
    pub uid: u32,
    pub inode: u64,
}

#[derive(Clone, Copy)]
/// poll 全局注册表中 handle 对应的 socket 类别。
enum PollRegistrationKind {
    TcpStream { rcvlowat: usize },
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
    /// key 包含 network namespace 和 `SocketHandle`。不同 namespace 拥有独立
    /// `SocketSet`，同一个 handle 数值在不同 namespace 内可以同时存在。
    /// value 用 `BTreeMap` 存放，既能稳定按 handle 遍历，也避免额外哈希依赖，足够满足当前内核规模。
    static ref NET_POLL_WAITERS: Mutex<BTreeMap<(usize, SocketHandle), PollRegistration>> =
        Mutex::new(BTreeMap::new());
    /// TCP handle 对应的 Linux socket 选项元数据。
    ///
    /// smoltcp 的 `SocketSet` 只保存协议状态，不保存 `SOL_SOCKET` 选项；bind 冲突判断
    /// 需要知道“已有 socket 是否也设置了 SO_REUSEADDR”，所以在 fd 层维护这份轻量镜像。
    static ref TCP_SOCKET_META: Mutex<BTreeMap<(usize, SocketHandle), TcpSocketMeta>> =
        Mutex::new(BTreeMap::new());
    /// UDP 端口允许 `SO_REUSEADDR` 多绑定，默认仍应拒绝同地址/同端口重复 bind。
    static ref UDP_SOCKET_META: Mutex<BTreeMap<(usize, SocketHandle), UdpSocketMeta>> =
        Mutex::new(BTreeMap::new());
}

fn set_tcp_socket_meta(
    ns_id: usize,
    handles: &[SocketHandle],
    reuseaddr: bool,
    domain: u16,
    ipv6_v6only: bool,
) {
    let mut meta = TCP_SOCKET_META.lock();
    for handle in handles {
        meta.insert((ns_id, *handle), TcpSocketMeta {
            reuseaddr,
            domain,
            ipv6_v6only,
        });
    }
}

fn unregister_tcp_socket_meta(ns_id: usize, handles: &[SocketHandle]) {
    let mut meta = TCP_SOCKET_META.lock();
    for handle in handles {
        meta.remove(&(ns_id, *handle));
    }
}

fn set_udp_socket_meta(
    ns_id: usize,
    handles: &[SocketHandle],
    reuseaddr: bool,
    domain: u16,
    ipv6_v6only: bool,
) {
    let mut meta = UDP_SOCKET_META.lock();
    for handle in handles {
        meta.insert((ns_id, *handle), UdpSocketMeta {
            reuseaddr,
            domain,
            ipv6_v6only,
        });
    }
}

fn unregister_udp_socket_meta(ns_id: usize, handles: &[SocketHandle]) {
    let mut meta = UDP_SOCKET_META.lock();
    for handle in handles {
        meta.remove(&(ns_id, *handle));
    }
}

/// Remove fd-layer socket metadata that belongs to a destroyed network namespace.
pub(crate) fn cleanup_net_namespace(ns_id: usize) {
    NET_POLL_WAITERS
        .lock()
        .retain(|(entry_ns, _), _| *entry_ns != ns_id);
    TCP_SOCKET_META
        .lock()
        .retain(|(entry_ns, _), _| *entry_ns != ns_id);
    UDP_SOCKET_META
        .lock()
        .retain(|(entry_ns, _), _| *entry_ns != ns_id);
}

// 按底层 handle 当前状态计算 poll 事件掩码。
fn poll_mask_for_registered_handle(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    kind: PollRegistrationKind,
) -> i16 {
    match kind {
        PollRegistrationKind::TcpStream { rcvlowat } => {
            // 获得对应的socket
            let s = sockets.get::<tcp::Socket>(handle);
            let mut mask = 0;
            // 即使收不到新字节，只要对端已经不会再发送，read() 也应立刻返回 0；
            // 因此 EOF 同样要表现为“可读”，这样 poll/select 才不会把它当成还需继续阻塞。
            if s.recv_queue() >= rcvlowat.max(1) || !s.may_recv() {
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
    ns_id: usize,
    handle: SocketHandle,
    kind: PollRegistrationKind,
    current_mask: i16,
    task: &Arc<TaskControlBlock>,
) -> bool {
    let mut registrations = NET_POLL_WAITERS.lock();
    let entry = registrations
        .entry((ns_id, handle))
        .or_insert_with(|| PollRegistration {
            kind,
            last_mask: 0,
            waiters: PollWaitQueue::default(),
        });
    if !entry.waiters.has_waiters() {
        entry.last_mask = current_mask;
    }
    entry.kind = kind;
    entry.waiters.register_waiter(task)
}

// 在 socket 生命周期结束时移除全局 poll 注册，避免 Drop 后仍有任务挂在无效 handle 上。
fn unregister_poll_waiters(ns_id: usize, handles: &[SocketHandle]) {
    let mut registrations = NET_POLL_WAITERS.lock();
    for handle in handles {
        registrations.remove(&(ns_id, *handle));
    }
}

// 由网络轮询路径统一调用，检查所有已注册 handle 的事件变化并按需唤醒任务。
// 简单介绍下运行过程， 首先收集所有的，仍然有waiter 的poll queue
// 收集新的mask. 与旧mask比较，如何不同，收集，然后wake
//
pub(crate) fn notify_net_poll_events_in(ns_id: usize) {
    let mut wake = Vec::new();
    let mut registrations = NET_POLL_WAITERS.lock();
    registrations.retain(|_, entry| entry.waiters.has_waiters());
    if registrations
        .keys()
        .all(|(registered_ns_id, _)| *registered_ns_id != ns_id)
    {
        return;
    }
    let masks = crate::net::with_sockets_mut_in(ns_id, |_iface, _dev, sockets| {
        registrations
            .iter()
            .filter(|((registered_ns_id, _), _)| *registered_ns_id == ns_id)
            .map(|((_, handle), entry)| {
                (
                    *handle,
                    poll_mask_for_registered_handle(sockets, *handle, entry.kind),
                )
            })
            .collect::<Vec<_>>()
    });
    for (handle, mask) in masks {
        let Some(entry) = registrations.get_mut(&(ns_id, handle)) else {
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
        Self::new_tcp_with_domain(AF_INET)
    }

    pub fn new_tcp_with_domain(domain: u16) -> Arc<Self> {
        debug_assert!(domain == AF_INET || domain == AF_INET6);
        let process = current_process();
        let net_ns_id = process.net_namespace_id();
        let proc_uid = process.borrow_mut().euid;
        let handle = crate::net::with_sockets_mut_in(net_ns_id, |_iface, _dev, sockets| {
            // TCP 默认就按大吞吐场景分配较大的环形缓冲区，避免 iperf 等测试被小 buffer 人为限速。
            let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
            let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
            sockets.add(tcp::Socket::new(rx, tx))
        });
        note_tcp_handle_created();
        set_tcp_socket_meta(net_ns_id, &[handle], false, domain, false);
        let file = Arc::new(Self {
            net_ns_id,
            domain,
            protocol: IPPROTO_TCP,
            proc_inode: alloc_socket_inode(),
            proc_uid,
            inner: Mutex::new(Inner::TcpStream { handle }),
            opts: Mutex::new(SocketOptions {
                reuseaddr: false,
                ipv6_v6only: false,
                dontroute: false,
                broadcast: false,
                keepalive: false,
                tcp_nodelay: false,
                tcp_cork: false,
                tcp_keepidle_secs: TCP_KEEPALIVE_DEFAULT_SECS as u32,
                tcp_keepintvl_secs: TCP_KEEPINTVL_DEFAULT_SECS,
                tcp_keepcnt: TCP_KEEPCNT_DEFAULT,
                sndbuf: TCP_TX_BUF_LEN_IPERF as u32,
                rcvbuf: TCP_RX_BUF_LEN_IPERF as u32,
                oobinline: false,
                no_check: false,
                udplite_send_cscov: 0,
                udplite_recv_cscov: 0,
                priority: 0,
                mark: 0,
                rcvmark: false,
                rcvpriority: false,
                linger_on: false,
                linger_sec: 0,
                rcvlowat: 1,
                busy_poll: crate::fs::procfs::net_core_busy_read_usecs(),
                rcvtimeo_ms: None,
                sndtimeo_ms: None,
                mcast_ifindex: 0,
                mcast_ifaddr: [0; 4],
                mcast_ttl: 1,
                mcast_loop: true,
                ip_pmtudisc: IP_PMTUDISC_WANT,
                ip_recverr: false,
                ip_recvttl: false,
                ip_recvtos: false,
                ip_tos: 0,
                ip_pktinfo: false,
                ip_ttl: -1,
                bound_ifindex: 0,
                rd_shutdown: false,
                wr_shutdown: false,
                connect_in_progress: false,
                pending_error: 0,
                error_queue: VecDeque::new(),
                timestamp_mode: SocketTimestampMode::Off,
                last_timestamp: None,
                filter_locked: false,
                classic_filter: None,
                bpf_filter: None,
            }),
            mcast_memberships: Mutex::new(Vec::new()),
            poll_waiters: Mutex::new(PollWaitQueue::default()),
        });
        note_net_socket_file_created();
        file
    }

    pub fn new_udp() -> Arc<Self> {
        Self::new_udp_with_domain(AF_INET)
    }

    pub fn new_udp_with_domain(domain: u16) -> Arc<Self> {
        Self::new_udp_with_protocol(domain, IPPROTO_UDP)
    }

    pub fn new_udp_lite_with_domain(domain: u16) -> Arc<Self> {
        Self::new_udp_with_protocol(domain, IPPROTO_UDPLITE)
    }

    fn new_udp_with_protocol(domain: u16, protocol: usize) -> Arc<Self> {
        debug_assert!(domain == AF_INET || domain == AF_INET6);
        debug_assert!(matches!(protocol, IPPROTO_UDP | IPPROTO_UDPLITE));
        let process = current_process();
        let net_ns_id = process.net_namespace_id();
        let proc_uid = process.borrow_mut().euid;
        let handle = crate::net::with_sockets_mut_in(net_ns_id, |_iface, _dev, sockets| {
            // UDP 按“整包”管理数据，因此直接给收发 packet buffer 预留较大的连续空间。
            let rx = udp_packet_buffer(UDP_RX_BUF_LEN);
            let tx = udp_packet_buffer(UDP_TX_BUF_LEN);
            let mut socket = udp::Socket::new(rx, tx);
            if protocol == IPPROTO_UDPLITE {
                socket.set_transport_protocol(IpProtocol::UdpLite);
            }
            sockets.add(socket)
        });
        note_udp_handle_created(UDP_RX_BUF_LEN, UDP_TX_BUF_LEN);
        set_udp_socket_meta(net_ns_id, &[handle], false, domain, false);
        let file = Arc::new(Self {
            net_ns_id,
            domain,
            protocol,
            proc_inode: alloc_socket_inode(),
            proc_uid,
            inner: Mutex::new(Inner::Udp {
                handle,
                connected: None,
            }),
            opts: Mutex::new(SocketOptions {
                reuseaddr: false,
                ipv6_v6only: false,
                dontroute: false,
                broadcast: false,
                keepalive: false,
                tcp_nodelay: false,
                tcp_cork: false,
                tcp_keepidle_secs: TCP_KEEPALIVE_DEFAULT_SECS as u32,
                tcp_keepintvl_secs: TCP_KEEPINTVL_DEFAULT_SECS,
                tcp_keepcnt: TCP_KEEPCNT_DEFAULT,
                sndbuf: UDP_TX_BUF_LEN as u32,
                rcvbuf: UDP_RX_BUF_LEN as u32,
                oobinline: false,
                no_check: false,
                udplite_send_cscov: 0,
                udplite_recv_cscov: 0,
                priority: 0,
                mark: 0,
                rcvmark: false,
                rcvpriority: false,
                linger_on: false,
                linger_sec: 0,
                rcvlowat: 1,
                busy_poll: crate::fs::procfs::net_core_busy_read_usecs(),
                rcvtimeo_ms: None,
                sndtimeo_ms: None,
                mcast_ifindex: 0,
                mcast_ifaddr: [0; 4],
                mcast_ttl: 1,
                mcast_loop: true,
                ip_pmtudisc: IP_PMTUDISC_WANT,
                ip_recverr: false,
                ip_recvttl: false,
                ip_recvtos: false,
                ip_tos: 0,
                ip_pktinfo: false,
                ip_ttl: -1,
                bound_ifindex: 0,
                rd_shutdown: false,
                wr_shutdown: false,
                connect_in_progress: false,
                pending_error: 0,
                error_queue: VecDeque::new(),
                timestamp_mode: SocketTimestampMode::Off,
                last_timestamp: None,
                filter_locked: false,
                classic_filter: None,
                bpf_filter: None,
            }),
            mcast_memberships: Mutex::new(Vec::new()),
            poll_waiters: Mutex::new(PollWaitQueue::default()),
        });
        note_net_socket_file_created();
        file
    }

    fn notify_poll_waiters(&self) {
        let waiters = self.poll_waiters.lock().take_wakeups();
        wake_tasks(waiters);
    }

    fn poll_net(&self) {
        crate::net::poll_in(self.net_ns_id);
    }

    fn busy_recv_window_usecs(&self) -> u32 {
        self.opts.lock().busy_poll
    }

    fn busy_poll_window_usecs(&self) -> u32 {
        crate::fs::procfs::net_core_busy_poll_usecs()
    }

    fn busy_poll_until_mask(&self, usecs: u32, ready_mask: i16, cooperative_yield: bool) -> i16 {
        if usecs == 0 {
            return 0;
        }
        let start_ns = crate::time::get_time_ns();
        let deadline_ns = start_ns.saturating_add((usecs as u64).saturating_mul(1_000));
        // Linux exits primarily on the microsecond window, with cond_resched()
        // points so busy-polling does not starve the producer. In this
        // cooperative QEMU setup the peer task often has to run to produce the
        // packet we are polling for, so keep scheduler yield points inside the
        // requested busy-poll window and a hard iteration cap for coarse timer
        // sources.
        let iteration_cap = if cooperative_yield {
            ((usecs as usize) / 4).clamp(8, 64)
        } else {
            (usecs as usize).saturating_mul(2).clamp(8, 512)
        };
        for i in 0..iteration_cap {
            let mask = self.poll_net_busy_current_mask();
            if (mask & ready_mask) != 0 {
                return mask;
            }
            let should_yield = (cooperative_yield && i == 0)
                || (i % 8 == 7 && crate::task::processor::should_resched_for_busy_poll());
            if should_yield {
                crate::task::processor::suspend_current_and_run_next();
            }
            if i % 4 == 3 && crate::time::get_time_ns() >= deadline_ns {
                break;
            }
            core::hint::spin_loop();
        }
        0
    }

    fn busy_recv_readable(&self) -> bool {
        self.busy_poll_until_mask(
            self.busy_recv_window_usecs(),
            POLLIN | POLLERR | POLLHUP,
            false,
        ) != 0
    }

    pub(crate) fn busy_poll_for_poll_events(&self, events: i16) -> bool {
        self.busy_poll_revents_for_poll_events(events) != 0
    }

    pub(crate) fn busy_poll_revents_for_poll_events(&self, events: i16) -> i16 {
        if (events & POLLIN) == 0 {
            return 0;
        }
        let mask = self.busy_poll_until_mask(
            self.busy_poll_window_usecs(),
            POLLIN | POLLERR | POLLHUP | POLLRDHUP,
            true,
        );
        if mask == 0 {
            return 0;
        }
        mask & (events | POLLERR | POLLHUP)
    }

    fn with_sockets_mut<R>(
        &self,
        f: impl FnOnce(
            &mut smoltcp::iface::Interface,
            &mut crate::net::PacketTapLoopback,
            &mut SocketSet<'static>,
        ) -> R,
    ) -> R {
        crate::net::with_sockets_mut_in(self.net_ns_id, f)
    }

    pub(crate) fn net_ns_id(&self) -> usize {
        self.net_ns_id
    }

    pub fn domain(&self) -> u16 {
        self.domain
    }

    pub fn protocol(&self) -> usize {
        self.protocol
    }

    pub fn ipv6_v6only(&self) -> bool {
        self.opts.lock().ipv6_v6only
    }

    pub fn set_ipv6_v6only(&self, enabled: bool) -> Result<(), isize> {
        const EINVAL: isize = -22;
        if self.domain != AF_INET6 || self.is_bound_or_connected() {
            return Err(EINVAL);
        }
        self.opts.lock().ipv6_v6only = enabled;
        let (kind, handles) = match &*self.inner.lock() {
            Inner::TcpStream { handle } => (NetSocketKind::TcpStream, vec![*handle]),
            Inner::TcpListener { listen, .. } => (NetSocketKind::TcpListener, listen.clone()),
            Inner::Udp { handle, .. } => (NetSocketKind::Udp, vec![*handle]),
        };
        let reuseaddr = self.reuseaddr();
        if kind == NetSocketKind::Udp {
            set_udp_socket_meta(self.net_ns_id, &handles, reuseaddr, self.domain, enabled);
        } else {
            set_tcp_socket_meta(self.net_ns_id, &handles, reuseaddr, self.domain, enabled);
        }
        Ok(())
    }

    fn is_bound_or_connected(&self) -> bool {
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => self.with_sockets_mut(|_iface, _dev, sockets| {
                let socket = sockets.get::<tcp::Socket>(*handle);
                socket.get_bound_endpoint().port != 0 || socket.local_endpoint().is_some()
            }),
            Inner::TcpListener { .. } => true,
            Inner::Udp { handle, connected } => {
                connected.is_some()
                    || self.with_sockets_mut(|_iface, _dev, sockets| {
                        sockets.get::<udp::Socket>(*handle).endpoint().port != 0
                    })
            }
        }
    }

    fn ensure_udp_buffer_capacity(&self, min_rx_payload: usize, min_tx_payload: usize) {
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return,
        };
        let min_rx_payload = min_rx_payload.min(IPV4_UDP_MAX_PAYLOAD);
        let min_tx_payload = min_tx_payload.min(IPV4_UDP_MAX_PAYLOAD);
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<udp::Socket>(handle);
            let rx_cap = s.payload_recv_capacity();
            let tx_cap = s.payload_send_capacity();
            let mut target_rx = rx_cap.max(min_rx_payload);
            let target_tx = tx_cap.max(min_tx_payload);
            if target_rx == rx_cap && target_tx == tx_cap {
                return;
            }
            // Rebuilding a smoltcp UDP socket drops buffered datagrams. Linux keeps
            // queued skb data across SO_RCVBUF changes; until smoltcp exposes a
            // resize API, preserve already queued RX packets by deferring RX growth.
            if s.can_recv() {
                target_rx = rx_cap;
            }
            if target_rx == rx_cap && target_tx == tx_cap {
                return;
            }
            let endpoint = s.endpoint();
            let hop_limit = s.hop_limit();
            let no_checksum = s.no_checksum();
            let transport_protocol = s.transport_protocol();
            let send_checksum_coverage = s.udplite_send_checksum_coverage();
            let recv_checksum_coverage = s.udplite_recv_checksum_coverage();
            let mut new_socket =
                udp::Socket::new(udp_packet_buffer(target_rx), udp_packet_buffer(target_tx));
            if endpoint.port != 0 {
                let _ = new_socket.bind(endpoint);
            }
            new_socket.set_hop_limit(hop_limit);
            new_socket.set_no_checksum(no_checksum);
            new_socket.set_transport_protocol(transport_protocol);
            new_socket.set_udplite_send_checksum_coverage(send_checksum_coverage);
            new_socket.set_udplite_recv_checksum_coverage(recv_checksum_coverage);
            note_udp_handle_resized(rx_cap, tx_cap, target_rx, target_tx);
            *s = new_socket;
        });
    }

    pub fn set_sockbuf(&self, sndbuf: Option<u32>, rcvbuf: Option<u32>) {
        let (target_sndbuf, target_rcvbuf) = {
            let mut opts = self.opts.lock();
            if let Some(v) = sndbuf {
                opts.sndbuf = v;
            }
            if let Some(v) = rcvbuf {
                opts.rcvbuf = v;
            }
            (opts.sndbuf as usize, opts.rcvbuf as usize)
        };
        self.ensure_udp_buffer_capacity(target_rcvbuf, target_sndbuf);
    }

    pub fn getsockopt_sndbuf(&self) -> u32 {
        self.opts.lock().sndbuf
    }

    pub fn getsockopt_rcvbuf(&self) -> u32 {
        self.opts.lock().rcvbuf
    }

    pub fn set_reuseaddr(&self, enabled: bool) {
        self.opts.lock().reuseaddr = enabled;
        let (kind, handles) = match &*self.inner.lock() {
            Inner::TcpStream { handle } => (NetSocketKind::TcpStream, vec![*handle]),
            Inner::TcpListener { listen, .. } => (NetSocketKind::TcpListener, listen.clone()),
            Inner::Udp { handle, .. } => (NetSocketKind::Udp, vec![*handle]),
        };
        let v6only = self.ipv6_v6only();
        if kind == NetSocketKind::Udp {
            set_udp_socket_meta(self.net_ns_id, &handles, enabled, self.domain, v6only);
        } else {
            set_tcp_socket_meta(self.net_ns_id, &handles, enabled, self.domain, v6only);
        }
    }

    pub fn reuseaddr(&self) -> bool {
        self.opts.lock().reuseaddr
    }

    pub fn set_dontroute(&self, enabled: bool) {
        self.opts.lock().dontroute = enabled;
    }

    pub fn dontroute(&self) -> bool {
        self.opts.lock().dontroute
    }

    pub fn set_broadcast(&self, enabled: bool) {
        self.opts.lock().broadcast = enabled;
    }

    pub fn broadcast(&self) -> bool {
        self.opts.lock().broadcast
    }

    fn check_broadcast_send(&self, dst: Ipv4Address) -> Result<(), isize> {
        const EACCES: isize = -13;
        let (broadcast_enabled, bound_ifindex) = {
            let opts = self.opts.lock();
            (opts.broadcast, opts.bound_ifindex)
        };
        if !broadcast_enabled && netdev::ipv4_is_broadcast_addr(ipv4_bytes(dst), bound_ifindex) {
            Err(EACCES)
        } else {
            Ok(())
        }
    }

    pub fn set_keepalive(&self, enabled: bool) {
        self.opts.lock().keepalive = enabled;
        self.apply_tcp_keepalive();
    }

    pub fn keepalive(&self) -> bool {
        self.opts.lock().keepalive
    }

    fn tcp_handles(&self) -> Option<Vec<SocketHandle>> {
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => Some(vec![*handle]),
            Inner::TcpListener { listen, .. } => Some(listen.clone()),
            Inner::Udp { .. } => None,
        }
    }

    fn apply_tcp_keepalive(&self) {
        let handles = match &*self.inner.lock() {
            Inner::TcpStream { handle } => vec![*handle],
            Inner::TcpListener { listen, .. } => listen.clone(),
            Inner::Udp { .. } => return,
        };
        let (interval, timeout) = {
            let opts = self.opts.lock();
            tcp_keepalive_timers(
                opts.keepalive,
                opts.tcp_keepidle_secs,
                opts.tcp_keepintvl_secs,
                opts.tcp_keepcnt,
            )
        };
        self.with_sockets_mut(|_iface, _dev, sockets| {
            for handle in handles {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                socket.set_keep_alive(interval);
                socket.set_timeout(timeout);
            }
        });
    }

    pub fn set_tcp_nodelay(&self, enabled: bool) -> Result<(), isize> {
        const ENOPROTOOPT: isize = -92;
        let Some(handles) = self.tcp_handles() else {
            return Err(ENOPROTOOPT);
        };
        self.opts.lock().tcp_nodelay = enabled;
        self.with_sockets_mut(|_iface, _dev, sockets| {
            for handle in handles {
                sockets
                    .get_mut::<tcp::Socket>(handle)
                    .set_nagle_enabled(!enabled);
            }
        });
        if enabled {
            crate::syscall::net::flush_tcp_msg_more_pending_for_addr(
                self as *const Self as usize,
                self,
            );
        }
        Ok(())
    }

    pub fn tcp_nodelay(&self) -> Result<bool, isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        Ok(self.opts.lock().tcp_nodelay)
    }

    pub fn set_tcp_cork(&self, enabled: bool) -> Result<(), isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        self.opts.lock().tcp_cork = enabled;
        if !enabled {
            crate::syscall::net::flush_tcp_msg_more_pending_for_addr(
                self as *const Self as usize,
                self,
            );
        }
        Ok(())
    }

    pub fn tcp_cork(&self) -> Result<bool, isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        Ok(self.opts.lock().tcp_cork)
    }

    pub fn set_tcp_keepidle_secs(&self, secs: u32) -> Result<(), isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        self.opts.lock().tcp_keepidle_secs = secs;
        self.apply_tcp_keepalive();
        Ok(())
    }

    pub fn tcp_keepidle_secs(&self) -> Result<u32, isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        Ok(self.opts.lock().tcp_keepidle_secs)
    }

    pub fn set_tcp_keepintvl_secs(&self, secs: u32) -> Result<(), isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        self.opts.lock().tcp_keepintvl_secs = secs;
        self.apply_tcp_keepalive();
        Ok(())
    }

    pub fn tcp_keepintvl_secs(&self) -> Result<u32, isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        Ok(self.opts.lock().tcp_keepintvl_secs)
    }

    pub fn set_tcp_keepcnt(&self, count: u32) -> Result<(), isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        self.opts.lock().tcp_keepcnt = count;
        self.apply_tcp_keepalive();
        Ok(())
    }

    pub fn tcp_keepcnt(&self) -> Result<u32, isize> {
        const ENOPROTOOPT: isize = -92;
        if self.tcp_handles().is_none() {
            return Err(ENOPROTOOPT);
        }
        Ok(self.opts.lock().tcp_keepcnt)
    }

    pub fn set_oobinline(&self, enabled: bool) {
        self.opts.lock().oobinline = enabled;
    }

    pub fn oobinline(&self) -> bool {
        self.opts.lock().oobinline
    }

    pub fn set_no_check(&self, enabled: bool) {
        self.opts.lock().no_check = enabled;
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => Some(*handle),
            _ => None,
        };
        if let Some(handle) = handle {
            self.with_sockets_mut(|_iface, _dev, sockets| {
                sockets
                    .get_mut::<udp::Socket>(handle)
                    .set_no_checksum(enabled);
            });
        }
    }

    pub fn no_check(&self) -> bool {
        self.opts.lock().no_check
    }

    pub fn set_udplite_checksum_coverage(&self, optname: usize, value: i32) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const ENOPROTOOPT: isize = -92;
        if self.protocol != IPPROTO_UDPLITE {
            return Err(ENOPROTOOPT);
        }
        if value < 0 || (value != 0 && value < UDP_HEADER_LEN as i32) {
            return Err(EINVAL);
        }
        let value = value as u32;
        {
            let mut opts = self.opts.lock();
            match optname {
                UDPLITE_SEND_CSCOV => opts.udplite_send_cscov = value,
                UDPLITE_RECV_CSCOV => opts.udplite_recv_cscov = value,
                _ => return Err(ENOPROTOOPT),
            }
        }
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => Some(*handle),
            _ => None,
        };
        if let Some(handle) = handle {
            self.with_sockets_mut(|_iface, _dev, sockets| {
                let socket = sockets.get_mut::<udp::Socket>(handle);
                match optname {
                    UDPLITE_SEND_CSCOV => socket.set_udplite_send_checksum_coverage(value as usize),
                    UDPLITE_RECV_CSCOV => socket.set_udplite_recv_checksum_coverage(value as usize),
                    _ => {}
                }
            });
        }
        Ok(())
    }

    pub fn udplite_send_cscov(&self) -> Result<u32, isize> {
        const ENOPROTOOPT: isize = -92;
        if self.protocol != IPPROTO_UDPLITE {
            return Err(ENOPROTOOPT);
        }
        Ok(self.opts.lock().udplite_send_cscov)
    }

    pub fn udplite_recv_cscov(&self) -> Result<u32, isize> {
        const ENOPROTOOPT: isize = -92;
        if self.protocol != IPPROTO_UDPLITE {
            return Err(ENOPROTOOPT);
        }
        Ok(self.opts.lock().udplite_recv_cscov)
    }

    pub fn set_priority(&self, priority: u32) {
        self.opts.lock().priority = priority;
    }

    pub fn priority(&self) -> u32 {
        self.opts.lock().priority
    }

    pub fn set_mark(&self, mark: u32) {
        self.opts.lock().mark = mark;
    }

    pub fn mark(&self) -> u32 {
        self.opts.lock().mark
    }

    pub fn set_rcvmark(&self, enabled: bool) {
        self.opts.lock().rcvmark = enabled;
    }

    pub fn rcvmark(&self) -> bool {
        self.opts.lock().rcvmark
    }

    pub fn set_rcvpriority(&self, enabled: bool) {
        self.opts.lock().rcvpriority = enabled;
    }

    pub fn rcvpriority(&self) -> bool {
        self.opts.lock().rcvpriority
    }

    pub fn set_linger(&self, on: bool, sec: i32) {
        let mut opts = self.opts.lock();
        opts.linger_on = on;
        opts.linger_sec = sec;
    }

    pub fn linger(&self) -> (bool, i32) {
        let opts = self.opts.lock();
        (opts.linger_on, opts.linger_sec)
    }

    pub fn set_rcvlowat(&self, value: i32) {
        self.opts.lock().rcvlowat = value;
    }

    pub fn rcvlowat(&self) -> i32 {
        self.opts.lock().rcvlowat
    }

    pub fn set_busy_poll(&self, usecs: u32) {
        self.opts.lock().busy_poll = usecs;
    }

    pub fn busy_poll(&self) -> u32 {
        self.opts.lock().busy_poll
    }

    pub fn set_rcvtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.opts.lock().rcvtimeo_ms = timeout_ms;
    }

    pub fn rcvtimeo_ms(&self) -> Option<usize> {
        self.opts.lock().rcvtimeo_ms
    }

    fn rcvtimeo_deadline_ms(&self) -> Option<usize> {
        self.rcvtimeo_ms()
            .map(|ms| crate::time::get_time_ms().saturating_add(ms.max(1)))
    }

    pub fn set_sndtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.opts.lock().sndtimeo_ms = timeout_ms;
    }

    pub fn sndtimeo_ms(&self) -> Option<usize> {
        self.opts.lock().sndtimeo_ms
    }

    fn sndtimeo_deadline_ms(&self) -> Option<usize> {
        self.sndtimeo_ms()
            .map(|ms| crate::time::get_time_ms().saturating_add(ms.max(1)))
    }

    fn set_socket_error(&self, errno: isize) {
        self.set_socket_local_error(errno, 0, None);
    }

    fn set_socket_local_error(&self, errno: isize, info: u32, offender: Option<([u8; 4], u16)>) {
        if errno >= 0 {
            return;
        }
        let mut opts = self.opts.lock();
        let errno = (-errno) as i32;
        opts.pending_error = errno;
        if opts.ip_recverr {
            if opts.error_queue.len() >= IPV4_ERROR_QUEUE_LIMIT {
                opts.error_queue.pop_front();
            }
            opts.error_queue
                .push_back(Ipv4ErrorQueueEntry::local_with_info(
                    errno,
                    info,
                    offender,
                    Vec::new(),
                ));
        }
        drop(opts);
        self.notify_poll_waiters();
    }

    fn push_ipv4_error_queue_entry(&self, entry: Ipv4ErrorQueueEntry) {
        let mut opts = self.opts.lock();
        if !opts.ip_recverr {
            return;
        }
        if opts.error_queue.len() >= IPV4_ERROR_QUEUE_LIMIT {
            opts.error_queue.pop_front();
        }
        opts.error_queue.push_back(entry);
        drop(opts);
        self.notify_poll_waiters();
    }

    fn maybe_queue_udp_port_unreachable(
        &self,
        remote: IpEndpoint,
        local_addr: Option<IpAddress>,
        ifindex_override: Option<i32>,
        payload: &[u8],
    ) {
        const ECONNREFUSED: u32 = 111;
        const ICMP_DEST_UNREACH: u8 = 3;
        const ICMP_PORT_UNREACH: u8 = 3;

        let IpAddress::Ipv4(remote_ip) = remote.addr else {
            return;
        };
        let local = match local_addr {
            Some(IpAddress::Ipv4(ip)) => Some(ipv4_bytes(ip)),
            _ => None,
        };
        let bound_ifindex = ifindex_override.unwrap_or_else(|| self.bound_device_ifindex());
        let Some((peer_ns_id, _peer)) = netdev::direct_veth_peer_for_ipv4_destination(
            self.net_ns_id,
            bound_ifindex,
            local,
            ipv4_bytes(remote_ip),
        ) else {
            return;
        };
        if crate::net::udp_port_bound_in(peer_ns_id, remote_ip, remote.port) {
            return;
        }
        self.push_ipv4_error_queue_entry(Ipv4ErrorQueueEntry {
            errno: ECONNREFUSED,
            origin: SO_EE_ORIGIN_ICMP,
            ty: ICMP_DEST_UNREACH,
            code: ICMP_PORT_UNREACH,
            info: 0,
            data: 0,
            offender: Some((ipv4_bytes(remote_ip), remote.port)),
            payload: payload.to_vec(),
        });
    }

    fn refresh_connect_error(&self) {
        const ECONNREFUSED: i32 = 111;
        if !self.opts.lock().connect_in_progress {
            return;
        }
        self.poll_net();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return,
        };
        let state = self
            .with_sockets_mut(|_iface, _dev, sockets| sockets.get::<tcp::Socket>(handle).state());
        if matches!(state, tcp::State::Established) {
            self.opts.lock().connect_in_progress = false;
            self.notify_poll_waiters();
        } else if matches!(state, tcp::State::Closed) {
            let mut opts = self.opts.lock();
            opts.connect_in_progress = false;
            opts.pending_error = ECONNREFUSED;
            if opts.ip_recverr {
                if opts.error_queue.len() >= IPV4_ERROR_QUEUE_LIMIT {
                    opts.error_queue.pop_front();
                }
                opts.error_queue
                    .push_back(Ipv4ErrorQueueEntry::local(ECONNREFUSED));
            }
            drop(opts);
            self.notify_poll_waiters();
        }
    }

    pub fn take_socket_error(&self) -> u32 {
        self.refresh_connect_error();
        let mut opts = self.opts.lock();
        let errno = opts.pending_error.max(0) as u32;
        opts.pending_error = 0;
        errno
    }

    fn record_recv_timestamp(&self) {
        self.opts.lock().last_timestamp = Some(SocketTimestamp::now());
    }

    pub(crate) fn socket_timestamp(&self) -> Option<SocketTimestamp> {
        self.opts.lock().last_timestamp
    }

    pub fn set_timestamp_mode(&self, mode: SocketTimestampMode) {
        self.opts.lock().timestamp_mode = mode;
    }

    pub fn timestamp_mode(&self) -> SocketTimestampMode {
        self.opts.lock().timestamp_mode
    }

    fn resolve_ipv4_multicast_if(
        &self,
        requested_ifindex: i32,
        requested_addr: [u8; 4],
    ) -> Result<(i32, [u8; 4]), isize> {
        const EADDRNOTAVAIL: isize = -99;
        const EINVAL: isize = -22;
        if requested_ifindex < 0 {
            return Err(EINVAL);
        }
        if requested_ifindex > 0 {
            if netdev::device_snapshot_by_index_in_namespace(self.net_ns_id, requested_ifindex)
                .is_none()
            {
                return Err(EADDRNOTAVAIL);
            }
            return Ok((requested_ifindex, requested_addr));
        }
        if requested_addr != [0; 4] {
            let Some(ifindex) =
                netdev::ifindex_by_ipv4_addr_in_namespace(self.net_ns_id, requested_addr)
            else {
                return Err(EADDRNOTAVAIL);
            };
            return Ok((ifindex, requested_addr));
        }
        let opts = self.opts.lock();
        if opts.mcast_ifindex > 0 {
            return Ok((opts.mcast_ifindex, opts.mcast_ifaddr));
        }
        drop(opts);
        let Some(ifindex) = netdev::default_ipv4_ifindex_in_namespace(self.net_ns_id) else {
            return Err(EADDRNOTAVAIL);
        };
        let addr = netdev::primary_ipv4_addr_by_ifindex_in_namespace(self.net_ns_id, ifindex)
            .unwrap_or([0; 4]);
        Ok((ifindex, addr))
    }

    pub fn set_ipv4_multicast_if(&self, ifindex: i32, addr: [u8; 4]) -> isize {
        const EINVAL: isize = -22;
        if self.kind() == NetSocketKind::TcpStream {
            return EINVAL;
        }
        if ifindex == 0 && addr == [0; 4] {
            let mut opts = self.opts.lock();
            opts.mcast_ifindex = 0;
            opts.mcast_ifaddr = [0; 4];
            return 0;
        }
        let (ifindex, addr) = match self.resolve_ipv4_multicast_if(ifindex, addr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let bound = self.bound_device_ifindex();
        if bound > 0 && bound != ifindex {
            return EINVAL;
        }
        let mut opts = self.opts.lock();
        opts.mcast_ifindex = ifindex;
        opts.mcast_ifaddr = addr;
        0
    }

    pub fn ipv4_multicast_if_addr(&self) -> [u8; 4] {
        self.opts.lock().mcast_ifaddr
    }

    pub fn set_ipv4_multicast_ttl(&self, ttl: u8) {
        self.opts.lock().mcast_ttl = ttl;
    }

    pub fn ipv4_multicast_ttl(&self) -> u8 {
        self.opts.lock().mcast_ttl
    }

    fn udp_hop_limit_for_remote(&self, remote: IpEndpoint) -> Option<u8> {
        let opts = self.opts.lock();
        match remote.addr {
            IpAddress::Ipv4(ip) if netdev::ipv4_is_multicast_addr(ipv4_bytes(ip)) => {
                // Linux 允许 multicast TTL=0 表示只在本机投递；smoltcp 不接受
                // hop limit 0。当前网络栈只有 loopback 路径，夹到 1 不会外发转发。
                Some(opts.mcast_ttl.max(1))
            }
            _ => ipv4_ttl_hop_limit(opts.ip_ttl),
        }
    }

    pub fn set_ipv4_multicast_loop(&self, enabled: bool) {
        self.opts.lock().mcast_loop = enabled;
    }

    pub fn ipv4_multicast_loop(&self) -> bool {
        self.opts.lock().mcast_loop
    }

    fn join_ipv4_multicast_inner(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        allow_tcp: bool,
    ) -> isize {
        const EINVAL: isize = -22;
        const EADDRINUSE: isize = -98;
        if (!allow_tcp && self.kind() == NetSocketKind::TcpStream)
            || !netdev::ipv4_is_multicast_addr(group)
        {
            return EINVAL;
        }
        let (ifindex, ifaddr) = match self.resolve_ipv4_multicast_if(ifindex, ifaddr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        {
            let memberships = self.mcast_memberships.lock();
            if memberships
                .iter()
                .any(|entry| entry.group == group && entry.ifindex == ifindex)
            {
                return EADDRINUSE;
            }
        }
        let mac = netdev::ipv4_multicast_mac(group);
        if let Err(e) = netdev::add_maddr(ifindex, mac) {
            return e;
        }
        self.mcast_memberships.lock().push(Ipv4MulticastMembership {
            group,
            ifindex,
            ifaddr,
            filter_mode: Ipv4SourceFilterMode::Exclude,
            sources: Vec::new(),
        });
        0
    }

    pub fn join_ipv4_multicast(&self, group: [u8; 4], ifindex: i32, ifaddr: [u8; 4]) -> isize {
        self.join_ipv4_multicast_inner(group, ifindex, ifaddr, false)
    }

    pub fn join_ipv4_multicast_group(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
    ) -> isize {
        self.join_ipv4_multicast_inner(group, ifindex, ifaddr, true)
    }

    pub fn join_ipv4_multicast_source(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        source: [u8; 4],
    ) -> isize {
        const EINVAL: isize = -22;
        const EADDRNOTAVAIL: isize = -99;
        if self.kind() == NetSocketKind::TcpStream || !netdev::ipv4_is_multicast_addr(group) {
            return EINVAL;
        }
        let (ifindex, ifaddr) = match self.resolve_ipv4_multicast_if(ifindex, ifaddr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut memberships = self.mcast_memberships.lock();
        if let Some(entry) = memberships
            .iter_mut()
            .find(|entry| entry.group == group && entry.ifindex == ifindex)
        {
            if entry.filter_mode != Ipv4SourceFilterMode::Include && !entry.sources.is_empty() {
                return EINVAL;
            }
            if entry.sources.contains(&source) {
                return EADDRNOTAVAIL;
            }
            entry.filter_mode = Ipv4SourceFilterMode::Include;
            entry.sources.push(source);
            return 0;
        }
        drop(memberships);

        if let Err(e) = netdev::add_maddr(ifindex, netdev::ipv4_multicast_mac(group)) {
            return e;
        }
        self.mcast_memberships.lock().push(Ipv4MulticastMembership {
            group,
            ifindex,
            ifaddr,
            filter_mode: Ipv4SourceFilterMode::Include,
            sources: vec![source],
        });
        0
    }

    pub fn leave_ipv4_multicast_source(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        source: [u8; 4],
    ) -> isize {
        const EINVAL: isize = -22;
        const EADDRNOTAVAIL: isize = -99;
        let resolved = self.resolve_ipv4_multicast_if(ifindex, ifaddr).ok();
        let mut memberships = self.mcast_memberships.lock();
        let Some(pos) = memberships.iter().position(|entry| {
            if entry.group != group {
                return false;
            }
            if let Some((resolved_ifindex, resolved_addr)) = resolved {
                if ifindex > 0 {
                    return entry.ifindex == resolved_ifindex;
                }
                if ifaddr != [0; 4] {
                    return entry.ifaddr == resolved_addr;
                }
            }
            true
        }) else {
            return EADDRNOTAVAIL;
        };
        if memberships[pos].filter_mode != Ipv4SourceFilterMode::Include {
            return EINVAL;
        }
        let Some(src_pos) = memberships[pos]
            .sources
            .iter()
            .position(|addr| *addr == source)
        else {
            return EADDRNOTAVAIL;
        };
        if memberships[pos].sources.len() == 1 {
            let entry = memberships.remove(pos);
            drop(memberships);
            let _ = netdev::del_maddr(entry.ifindex, netdev::ipv4_multicast_mac(entry.group));
        } else {
            memberships[pos].sources.remove(src_pos);
        }
        0
    }

    pub fn block_ipv4_multicast_source(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        source: [u8; 4],
    ) -> isize {
        const EINVAL: isize = -22;
        const EADDRNOTAVAIL: isize = -99;
        if !netdev::ipv4_is_multicast_addr(group) {
            return EINVAL;
        }
        let resolved = self.resolve_ipv4_multicast_if(ifindex, ifaddr).ok();
        let mut memberships = self.mcast_memberships.lock();
        let Some(entry) = memberships.iter_mut().find(|entry| {
            if entry.group != group {
                return false;
            }
            if let Some((resolved_ifindex, resolved_addr)) = resolved {
                if ifindex > 0 {
                    return entry.ifindex == resolved_ifindex;
                }
                if ifaddr != [0; 4] {
                    return entry.ifaddr == resolved_addr;
                }
            }
            true
        }) else {
            return EINVAL;
        };
        if entry.filter_mode != Ipv4SourceFilterMode::Exclude && !entry.sources.is_empty() {
            return EINVAL;
        }
        if entry.sources.contains(&source) {
            return EADDRNOTAVAIL;
        }
        entry.filter_mode = Ipv4SourceFilterMode::Exclude;
        entry.sources.push(source);
        0
    }

    pub fn unblock_ipv4_multicast_source(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        source: [u8; 4],
    ) -> isize {
        const EINVAL: isize = -22;
        const EADDRNOTAVAIL: isize = -99;
        let resolved = self.resolve_ipv4_multicast_if(ifindex, ifaddr).ok();
        let mut memberships = self.mcast_memberships.lock();
        let Some(entry) = memberships.iter_mut().find(|entry| {
            if entry.group != group {
                return false;
            }
            if let Some((resolved_ifindex, resolved_addr)) = resolved {
                if ifindex > 0 {
                    return entry.ifindex == resolved_ifindex;
                }
                if ifaddr != [0; 4] {
                    return entry.ifaddr == resolved_addr;
                }
            }
            true
        }) else {
            return EADDRNOTAVAIL;
        };
        if entry.filter_mode != Ipv4SourceFilterMode::Exclude && !entry.sources.is_empty() {
            return EINVAL;
        }
        let Some(src_pos) = entry.sources.iter().position(|addr| *addr == source) else {
            return EADDRNOTAVAIL;
        };
        entry.filter_mode = Ipv4SourceFilterMode::Exclude;
        entry.sources.remove(src_pos);
        0
    }

    pub fn set_ipv4_multicast_source_filter(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        mode: Ipv4SourceFilterMode,
        sources: Vec<[u8; 4]>,
    ) -> isize {
        const EINVAL: isize = -22;
        const EADDRNOTAVAIL: isize = -99;
        if self.kind() == NetSocketKind::TcpStream || !netdev::ipv4_is_multicast_addr(group) {
            return EINVAL;
        }
        if mode == Ipv4SourceFilterMode::Include && sources.is_empty() {
            return self.leave_ipv4_multicast(group, ifindex, ifaddr);
        }
        let (resolved_ifindex, resolved_addr) =
            match self.resolve_ipv4_multicast_if(ifindex, ifaddr) {
                Ok(v) => v,
                Err(e) => return e,
            };
        let mut memberships = self.mcast_memberships.lock();
        let Some(entry) = memberships
            .iter_mut()
            .find(|entry| entry.group == group && entry.ifindex == resolved_ifindex)
        else {
            return EINVAL;
        };
        if ifaddr != [0; 4] && entry.ifaddr != resolved_addr {
            return EADDRNOTAVAIL;
        }
        entry.filter_mode = mode;
        entry.sources = sources;
        0
    }

    pub fn ipv4_multicast_source_filter(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
    ) -> Result<(Ipv4SourceFilterMode, Vec<[u8; 4]>), isize> {
        const EINVAL: isize = -22;
        const EADDRNOTAVAIL: isize = -99;
        if !netdev::ipv4_is_multicast_addr(group) {
            return Err(EINVAL);
        }
        let (resolved_ifindex, resolved_addr) = self.resolve_ipv4_multicast_if(ifindex, ifaddr)?;
        let memberships = self.mcast_memberships.lock();
        let Some(entry) = memberships
            .iter()
            .find(|entry| entry.group == group && entry.ifindex == resolved_ifindex)
        else {
            return Err(EADDRNOTAVAIL);
        };
        if ifaddr != [0; 4] && entry.ifaddr != resolved_addr {
            return Err(EADDRNOTAVAIL);
        }
        Ok((entry.filter_mode, entry.sources.clone()))
    }

    fn multicast_source_allowed(&self, ifindex: i32, group: [u8; 4], source: [u8; 4]) -> bool {
        let memberships = self.mcast_memberships.lock();
        let Some(entry) = memberships
            .iter()
            .find(|entry| entry.group == group && entry.ifindex == ifindex)
        else {
            return true;
        };
        match entry.filter_mode {
            Ipv4SourceFilterMode::Exclude => !entry.sources.contains(&source),
            Ipv4SourceFilterMode::Include => entry.sources.contains(&source),
        }
    }

    fn leave_ipv4_multicast_inner(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        allow_tcp: bool,
    ) -> isize {
        const EINVAL: isize = -22;
        const EADDRNOTAVAIL: isize = -99;
        if !allow_tcp && self.kind() == NetSocketKind::TcpStream {
            return EINVAL;
        }
        let resolved = self.resolve_ipv4_multicast_if(ifindex, ifaddr).ok();
        let mut memberships = self.mcast_memberships.lock();
        let pos = memberships.iter().position(|entry| {
            if entry.group != group {
                return false;
            }
            if let Some((resolved_ifindex, resolved_addr)) = resolved {
                if ifindex > 0 {
                    return entry.ifindex == resolved_ifindex;
                }
                if ifaddr != [0; 4] {
                    return entry.ifaddr == resolved_addr;
                }
            }
            true
        });
        let Some(pos) = pos else {
            return EADDRNOTAVAIL;
        };
        let entry = memberships.remove(pos);
        drop(memberships);
        let _ = netdev::del_maddr(entry.ifindex, netdev::ipv4_multicast_mac(entry.group));
        0
    }

    pub fn leave_ipv4_multicast(&self, group: [u8; 4], ifindex: i32, ifaddr: [u8; 4]) -> isize {
        self.leave_ipv4_multicast_inner(group, ifindex, ifaddr, false)
    }

    pub fn leave_ipv4_multicast_group(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
    ) -> isize {
        self.leave_ipv4_multicast_inner(group, ifindex, ifaddr, true)
    }

    fn release_ipv4_multicast_memberships(&self) {
        let memberships = {
            let mut memberships = self.mcast_memberships.lock();
            core::mem::take(&mut *memberships)
        };
        for entry in memberships {
            let _ = netdev::del_maddr(entry.ifindex, netdev::ipv4_multicast_mac(entry.group));
        }
    }

    pub fn set_ipv4_mtu_discover(&self, value: i32) {
        self.opts.lock().ip_pmtudisc = value;
    }

    pub fn ipv4_mtu_discover(&self) -> i32 {
        self.opts.lock().ip_pmtudisc
    }

    pub fn set_ipv4_recverr(&self, enabled: bool) {
        let mut opts = self.opts.lock();
        opts.ip_recverr = enabled;
        if !enabled {
            opts.error_queue.clear();
        }
    }

    pub fn ipv4_recverr(&self) -> bool {
        self.opts.lock().ip_recverr
    }

    pub fn pop_ipv4_error_queue(&self) -> Option<Ipv4ErrorQueueEntry> {
        self.opts.lock().error_queue.pop_front()
    }

    pub fn set_ipv4_recvttl(&self, enabled: bool) {
        self.opts.lock().ip_recvttl = enabled;
    }

    pub fn ipv4_recvttl(&self) -> bool {
        self.opts.lock().ip_recvttl
    }

    pub fn set_ipv4_recvtos(&self, enabled: bool) {
        self.opts.lock().ip_recvtos = enabled;
    }

    pub fn ipv4_recvtos(&self) -> bool {
        self.opts.lock().ip_recvtos
    }

    pub fn set_ipv4_tos(&self, value: i32) {
        let tos = value as u8;
        self.opts.lock().ip_tos = tos;
        let tcp_handles = match &*self.inner.lock() {
            Inner::TcpStream { handle } => alloc::vec![*handle],
            Inner::TcpListener { listen, .. } => listen.clone(),
            Inner::Udp { .. } => Vec::new(),
        };
        if !tcp_handles.is_empty() {
            let tos = ipv4_tos_meta(tos);
            self.with_sockets_mut(|_iface, _dev, sockets| {
                for handle in tcp_handles {
                    sockets.get_mut::<tcp::Socket>(handle).set_ipv4_tos(tos);
                }
            });
        }
    }

    pub fn ipv4_tos(&self) -> u32 {
        self.opts.lock().ip_tos as u32
    }

    pub fn set_ipv4_pktinfo(&self, enabled: bool) {
        self.opts.lock().ip_pktinfo = enabled;
    }

    pub fn ipv4_pktinfo(&self) -> bool {
        self.opts.lock().ip_pktinfo
    }

    pub fn set_ipv4_ttl(&self, value: i32) {
        self.opts.lock().ip_ttl = value;
        let hop_limit = ipv4_ttl_hop_limit(value);
        enum Target {
            Tcp(Vec<SocketHandle>),
            Udp(SocketHandle),
        }
        let target = match &*self.inner.lock() {
            Inner::TcpStream { handle } => Target::Tcp(alloc::vec![*handle]),
            Inner::TcpListener { listen, .. } => Target::Tcp(listen.clone()),
            Inner::Udp { handle, .. } => Target::Udp(*handle),
        };
        self.with_sockets_mut(|_iface, _dev, sockets| match target {
            Target::Tcp(handles) => {
                for handle in handles {
                    sockets
                        .get_mut::<tcp::Socket>(handle)
                        .set_hop_limit(hop_limit);
                }
            }
            Target::Udp(handle) => sockets
                .get_mut::<udp::Socket>(handle)
                .set_hop_limit(hop_limit),
        });
    }

    pub fn ipv4_ttl(&self) -> i32 {
        let ttl = self.opts.lock().ip_ttl;
        if ttl < 0 { IPV4_DEFAULT_TTL } else { ttl }
    }

    pub fn set_bound_device_ifindex(&self, ifindex: i32) {
        self.opts.lock().bound_ifindex = ifindex.max(0);
    }

    pub fn bound_device_ifindex(&self) -> i32 {
        self.opts.lock().bound_ifindex
    }

    pub fn ipv4_path_mtu(&self) -> Option<u32> {
        let bound_ifindex = self.bound_device_ifindex();
        let (local, remote) = match &*self.inner.lock() {
            Inner::TcpStream { handle } => self.with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get::<tcp::Socket>(*handle);
                let local = s.local_endpoint().and_then(|endpoint| match endpoint.addr {
                    IpAddress::Ipv4(ip) => Some(ipv4_bytes(ip)),
                    IpAddress::Ipv6(_) => None,
                });
                let local = local.or_else(|| match s.get_bound_endpoint().addr {
                    Some(IpAddress::Ipv4(ip)) => Some(ipv4_bytes(ip)),
                    _ => None,
                });
                let remote = s
                    .remote_endpoint()
                    .and_then(|endpoint| match endpoint.addr {
                        IpAddress::Ipv4(ip) => Some(ipv4_bytes(ip)),
                        IpAddress::Ipv6(_) => None,
                    });
                (local, remote)
            }),
            Inner::TcpListener { endpoint, .. } => {
                let local = match endpoint.addr {
                    Some(IpAddress::Ipv4(ip)) => Some(ipv4_bytes(ip)),
                    _ => None,
                };
                (local, None)
            }
            Inner::Udp { handle, connected } => {
                let remote = connected.map(endpoint_addr_v4).map(ipv4_bytes);
                self.with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get::<udp::Socket>(*handle);
                    let local = match s.endpoint().addr {
                        Some(IpAddress::Ipv4(ip)) => Some(ipv4_bytes(ip)),
                        _ => None,
                    };
                    (local, remote)
                })
            }
        };
        netdev::ipv4_path_mtu_in_namespace(self.net_ns_id, bound_ifindex, local, remote)
    }

    fn check_udp_path_mtu(
        &self,
        remote: Ipv4Address,
        remote_port: u16,
        local: Option<IpAddress>,
        ifindex_override: Option<i32>,
        payload_len: usize,
    ) -> Result<(), isize> {
        const EMSGSIZE: isize = -90;
        let pmtudisc = self.opts.lock().ip_pmtudisc;
        if !ipv4_pmtu_reports_oversize(pmtudisc) {
            return Ok(());
        }
        let total_len = IPV4_HEADER_LEN
            .saturating_add(UDP_HEADER_LEN)
            .saturating_add(payload_len);
        let local = match local {
            Some(IpAddress::Ipv4(ip)) => Some(ipv4_bytes(ip)),
            _ => None,
        };
        let bound_ifindex = ifindex_override.unwrap_or_else(|| self.bound_device_ifindex());
        let Some(mtu) = netdev::ipv4_path_mtu_in_namespace(
            self.net_ns_id,
            bound_ifindex,
            local,
            Some(ipv4_bytes(remote)),
        ) else {
            return Ok(());
        };
        if total_len > mtu as usize {
            self.set_socket_local_error(EMSGSIZE, mtu, Some((ipv4_bytes(remote), remote_port)));
            return Err(EMSGSIZE);
        }
        Ok(())
    }

    fn check_udp_dontroute(
        &self,
        remote: Ipv4Address,
        local: Option<IpAddress>,
        ifindex_override: Option<i32>,
        msg_dontroute: bool,
    ) -> Result<(), isize> {
        const ENETUNREACH: isize = -101;
        if !self.opts.lock().dontroute && !msg_dontroute {
            return Ok(());
        }
        let local = match local {
            Some(IpAddress::Ipv4(ip)) => Some(ipv4_bytes(ip)),
            _ => None,
        };
        let bound_ifindex = ifindex_override.unwrap_or_else(|| self.bound_device_ifindex());
        if netdev::ipv4_link_scope_reachable_in_namespace(
            self.net_ns_id,
            bound_ifindex,
            local,
            ipv4_bytes(remote),
        ) {
            Ok(())
        } else {
            Err(ENETUNREACH)
        }
    }

    fn confirm_udp_neighbor(
        &self,
        remote: Ipv4Address,
        local: Option<IpAddress>,
        ifindex_override: Option<i32>,
        msg_dontroute: bool,
        msg_confirm: bool,
    ) {
        if !msg_confirm {
            return;
        }
        let local = match local {
            Some(IpAddress::Ipv4(ip)) => Some(ipv4_bytes(ip)),
            _ => None,
        };
        let bound_ifindex = ifindex_override.unwrap_or_else(|| self.bound_device_ifindex());
        let allow_routed = !self.opts.lock().dontroute && !msg_dontroute;
        let _ = netdev::confirm_ipv4_neighbor_on_device_in_namespace_with_routing(
            self.net_ns_id,
            bound_ifindex,
            local,
            ipv4_bytes(remote),
            allow_routed,
        );
    }

    #[allow(dead_code)]
    fn bound_device_source_addr_for(&self, remote: Ipv4Address) -> Option<IpAddress> {
        self.bound_device_source_addr_for_ip(IpAddress::Ipv4(remote))
    }

    fn bound_device_source_addr_for_ip(&self, remote: IpAddress) -> Option<IpAddress> {
        let ifindex = self.bound_device_ifindex();
        if ifindex == 0 {
            return None;
        }
        match remote {
            IpAddress::Ipv4(remote) => netdev::select_ipv4_source_addr_on_device_in_namespace(
                self.net_ns_id,
                ifindex,
                ipv4_bytes(remote),
            )
            .map(|addr| IpAddress::Ipv4(Ipv4Address::from_bytes(&addr))),
            IpAddress::Ipv6(remote) => netdev::select_ipv6_source_addr_on_device_in_namespace(
                self.net_ns_id,
                ifindex,
                ipv6_bytes(remote),
            )
            .map(|addr| IpAddress::Ipv6(Ipv6Address::from_bytes(&addr))),
        }
    }

    #[allow(dead_code)]
    fn tcp_connect_source_addr_for(&self, remote: Ipv4Address) -> Option<IpAddress> {
        self.tcp_connect_source_addr_for_ip(IpAddress::Ipv4(remote))
    }

    fn tcp_connect_source_addr_for_ip(&self, remote: IpAddress) -> Option<IpAddress> {
        self.bound_device_source_addr_for_ip(remote)
            .or_else(|| match remote {
                IpAddress::Ipv4(remote) => {
                    netdev::select_ipv4_source_addr_in_namespace(self.net_ns_id, ipv4_bytes(remote))
                        .map(|addr| IpAddress::Ipv4(Ipv4Address::from_bytes(&addr)))
                }
                IpAddress::Ipv6(remote) => {
                    netdev::select_ipv6_source_addr_in_namespace(self.net_ns_id, ipv6_bytes(remote))
                        .map(|addr| IpAddress::Ipv6(Ipv6Address::from_bytes(&addr)))
                }
            })
    }

    fn udp_pktinfo_source_addr_for(
        &self,
        remote: Ipv4Address,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
    ) -> Result<Option<IpAddress>, isize> {
        const EINVAL: isize = -22;
        const ENODEV: isize = -19;
        const EADDRNOTAVAIL: isize = -99;

        let bound_ifindex = self.bound_device_ifindex();
        let effective_ifindex = ifindex_override.or((bound_ifindex > 0).then_some(bound_ifindex));
        if bound_ifindex > 0
            && let Some(ifindex) = ifindex_override
            && ifindex != bound_ifindex
        {
            return Err(EINVAL);
        }

        let lo =
            netdev::device_snapshot_by_name_in_namespace(self.net_ns_id, "lo").ok_or(ENODEV)?;
        let output_ifindex = if let Some(ifindex) = effective_ifindex {
            let _dev = netdev::device_snapshot_by_index_in_namespace(self.net_ns_id, ifindex)
                .ok_or(ENODEV)?;
            ifindex
        } else {
            lo.ifindex
        };

        if let Some(local) = local_override {
            let local = ipv4_bytes(local);
            if !netdev::is_local_ipv4_addr_on_device_in_namespace(
                self.net_ns_id,
                output_ifindex,
                local,
            ) {
                return Err(EADDRNOTAVAIL);
            }
            return Ok(Some(IpAddress::Ipv4(Ipv4Address::from_bytes(&local))));
        }

        if effective_ifindex.is_some() {
            let Some(local) = netdev::select_ipv4_source_addr_on_device_in_namespace(
                self.net_ns_id,
                output_ifindex,
                ipv4_bytes(remote),
            ) else {
                return Err(EADDRNOTAVAIL);
            };
            return Ok(Some(IpAddress::Ipv4(Ipv4Address::from_bytes(&local))));
        }

        Ok(None)
    }

    fn udp_pktinfo_source_addr_for_ip(
        &self,
        remote: IpAddress,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
    ) -> Result<Option<IpAddress>, isize> {
        const EINVAL: isize = -22;
        const ENODEV: isize = -19;
        const EADDRNOTAVAIL: isize = -99;

        let IpAddress::Ipv6(remote6) = remote else {
            let IpAddress::Ipv4(remote4) = remote else {
                unreachable!();
            };
            return self.udp_pktinfo_source_addr_for(remote4, ifindex_override, local_override);
        };
        if local_override.is_some() {
            return Err(EINVAL);
        }

        let bound_ifindex = self.bound_device_ifindex();
        let effective_ifindex = ifindex_override.or((bound_ifindex > 0).then_some(bound_ifindex));
        if bound_ifindex > 0
            && let Some(ifindex) = ifindex_override
            && ifindex != bound_ifindex
        {
            return Err(EINVAL);
        }

        if let Some(ifindex) = effective_ifindex {
            let _dev = netdev::device_snapshot_by_index_in_namespace(self.net_ns_id, ifindex)
                .ok_or(ENODEV)?;
            let Some(local) = netdev::select_ipv6_source_addr_on_device_in_namespace(
                self.net_ns_id,
                ifindex,
                ipv6_bytes(remote6),
            ) else {
                return Err(EADDRNOTAVAIL);
            };
            return Ok(Some(IpAddress::Ipv6(Ipv6Address::from_bytes(&local))));
        }

        Ok(None)
    }

    #[allow(dead_code)]
    fn bound_device_accepts_addr(&self, ip: Ipv4Address) -> bool {
        self.bound_device_accepts_ip(IpAddress::Ipv4(ip))
    }

    fn bound_device_accepts_ip(&self, ip: IpAddress) -> bool {
        let ifindex = self.bound_device_ifindex();
        if ifindex == 0 || ip_is_unspecified(ip) {
            return true;
        }
        match ip {
            IpAddress::Ipv4(ip) => netdev::is_local_ipv4_addr_on_device_in_namespace(
                self.net_ns_id,
                ifindex,
                ipv4_bytes(ip),
            ),
            IpAddress::Ipv6(ip) => netdev::is_local_ipv6_addr_on_device_in_namespace(
                self.net_ns_id,
                ifindex,
                ipv6_bytes(ip),
            ),
        }
    }

    pub fn kind(&self) -> NetSocketKind {
        match &*self.inner.lock() {
            Inner::TcpStream { .. } => NetSocketKind::TcpStream,
            Inner::TcpListener { .. } => NetSocketKind::TcpListener,
            Inner::Udp { .. } => NetSocketKind::Udp,
        }
    }

    pub fn attach_filter(&self, filter: ClassicBpfProgram) -> isize {
        const EPERM: isize = -1;
        let mut opts = self.opts.lock();
        if opts.filter_locked {
            return EPERM;
        }
        opts.classic_filter = Some(filter);
        opts.bpf_filter = None;
        0
    }

    pub fn attach_bpf(&self, filter: Arc<BpfProgFile>) -> isize {
        const EPERM: isize = -1;
        let mut opts = self.opts.lock();
        if opts.filter_locked {
            return EPERM;
        }
        opts.classic_filter = None;
        opts.bpf_filter = Some(filter);
        0
    }

    pub fn detach_filter(&self) -> isize {
        const ENOENT: isize = -2;
        const EPERM: isize = -1;
        let mut opts = self.opts.lock();
        if opts.filter_locked {
            return EPERM;
        }
        let had_filter = opts.classic_filter.take().is_some() | opts.bpf_filter.take().is_some();
        if had_filter { 0 } else { ENOENT }
    }

    pub fn set_filter_locked(&self, locked: bool) -> isize {
        const EPERM: isize = -1;
        let mut opts = self.opts.lock();
        if opts.filter_locked && !locked {
            return EPERM;
        }
        opts.filter_locked = locked;
        0
    }

    pub fn filter_locked(&self) -> bool {
        self.opts.lock().filter_locked
    }

    pub fn classic_filter_snapshot(&self) -> (Option<ClassicBpfProgram>, bool) {
        let opts = self.opts.lock();
        (opts.classic_filter.clone(), opts.bpf_filter.is_some())
    }

    pub fn proc_net_snapshot(&self) -> Option<ProcNetSocketSnapshot> {
        self.poll_net();
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => {
                let handle = *handle;
                self.with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get::<tcp::Socket>(handle);
                    let (local_addr, local_port) = s
                        .local_endpoint()
                        .map(|ep| endpoint_v4(Some(ep)))
                        .unwrap_or_else(|| listen_endpoint_v4(s.get_bound_endpoint()));
                    let (remote_addr, remote_port) = endpoint_v4(s.remote_endpoint());
                    Some(ProcNetSocketSnapshot {
                        kind: NetSocketKind::TcpStream,
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        state: tcp_state_for_proc(s.state()),
                        tx_queue: s.send_queue(),
                        rx_queue: s.recv_queue(),
                        uid: self.proc_uid,
                        inode: self.proc_inode,
                    })
                })
            }
            Inner::TcpListener { endpoint, .. } => {
                let (local_addr, local_port) = listen_endpoint_v4(*endpoint);
                Some(ProcNetSocketSnapshot {
                    kind: NetSocketKind::TcpListener,
                    local_addr,
                    local_port,
                    remote_addr: [0; 4],
                    remote_port: 0,
                    state: 0x0a,
                    tx_queue: 0,
                    rx_queue: 0,
                    uid: self.proc_uid,
                    inode: self.proc_inode,
                })
            }
            Inner::Udp { handle, connected } => {
                let handle = *handle;
                let connected = *connected;
                self.with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get_mut::<udp::Socket>(handle);
                    let ep = s.endpoint();
                    let local_addr = match ep.addr {
                        Some(IpAddress::Ipv4(ip)) => ipv4_bytes(ip),
                        _ => [0; 4],
                    };
                    let (remote_addr, remote_port) = endpoint_v4(connected);
                    let rx_queue = s.peek().map(|(payload, _meta)| payload.len()).unwrap_or(0);
                    Some(ProcNetSocketSnapshot {
                        kind: NetSocketKind::Udp,
                        local_addr,
                        local_port: ep.port,
                        remote_addr,
                        remote_port,
                        state: 0x07,
                        tx_queue: 0,
                        rx_queue,
                        uid: self.proc_uid,
                        inode: self.proc_inode,
                    })
                })
            }
        }
    }

    pub fn proc_inode(&self) -> u64 {
        self.proc_inode
    }

    /// 先抓取一份只包含必要状态的快照，再到全局 `SocketSet` 里查询实际 socket 状态。
    ///  这样可以避免在持有 `inner` 锁时再进入 NET 全局锁，减少锁嵌套和反向依赖。
    fn snapshot(&self) -> Snapshot {
        let inner = self.inner.lock();
        match &*inner {
            Inner::TcpStream { handle } => {
                let opts = self.opts.lock();
                Snapshot::TcpStream {
                    handle: *handle,
                    rd_shutdown: opts.rd_shutdown,
                    wr_shutdown: opts.wr_shutdown,
                    rcvlowat: opts.rcvlowat.max(1) as usize,
                }
            }
            Inner::TcpListener { listen, .. } => Snapshot::TcpListener(listen.clone()),
            Inner::Udp { handle, .. } => {
                let opts = self.opts.lock();
                Snapshot::Udp {
                    handle: *handle,
                    rd_shutdown: opts.rd_shutdown,
                    wr_shutdown: opts.wr_shutdown,
                }
            }
        }
    }

    fn poll_mask_for_snapshot(snapshot: &Snapshot, sockets: &mut SocketSet<'_>) -> i16 {
        match snapshot {
            Snapshot::TcpStream {
                handle,
                rd_shutdown,
                wr_shutdown,
                rcvlowat,
            } => {
                let s = sockets.get::<tcp::Socket>(*handle);
                let state = s.state();
                let mut mask = 0;
                if *rd_shutdown || s.recv_queue() >= *rcvlowat || !s.may_recv() {
                    mask |= POLLIN;
                }
                if !*wr_shutdown && (s.can_send() || !s.may_send()) {
                    mask |= POLLOUT;
                }
                // 本端执行 shutdown(SHUT_RD) 后，即便对端未关闭，也要把读半关闭态通过 POLLRDHUP 暴露给 poll。
                if *rd_shutdown || !s.may_recv() {
                    mask |= POLLRDHUP;
                }
                if (*rd_shutdown && *wr_shutdown) || matches!(state, tcp::State::Closed) {
                    mask |= POLLHUP;
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
            Snapshot::Udp {
                handle,
                rd_shutdown,
                wr_shutdown,
            } => {
                let s = sockets.get::<udp::Socket>(*handle);
                let mut mask = 0;
                if *rd_shutdown || s.can_recv() {
                    mask |= POLLIN;
                }
                if !*wr_shutdown && s.can_send() {
                    mask |= POLLOUT;
                }
                if *rd_shutdown && *wr_shutdown {
                    mask |= POLLHUP;
                }
                mask
            }
        }
    }

    /// 统一从快照计算当前 poll 掩码，避免调用者自己决定该看哪一种底层 socket 状态。
    fn current_poll_mask(&self) -> i16 {
        self.refresh_connect_error();
        let err_mask = if self.opts.lock().pending_error != 0 {
            POLLERR
        } else {
            0
        };
        let snapshot = self.snapshot();
        err_mask
            | self.with_sockets_mut(|_iface, _dev, sockets| {
                Self::poll_mask_for_snapshot(&snapshot, sockets)
            })
    }

    fn poll_net_busy_current_mask(&self) -> i16 {
        self.refresh_connect_error();
        let err_mask = if self.opts.lock().pending_error != 0 {
            POLLERR
        } else {
            0
        };
        let snapshot = self.snapshot();
        err_mask
            | crate::net::poll_busy_with_sockets_mut_in(self.net_ns_id, |_iface, _dev, sockets| {
                Self::poll_mask_for_snapshot(&snapshot, sockets)
            })
    }

    // 返回需要参与全局 poll 注册的底层 handle 集合。
    // 对 listener 而言，真正可能变成“可 accept”的是每一个 backlog 槽位，因此必须全部注册。
    fn poll_registration_handles(&self) -> Vec<(SocketHandle, PollRegistrationKind)> {
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => vec![(
                *handle,
                PollRegistrationKind::TcpStream {
                    rcvlowat: self.opts.lock().rcvlowat.max(1) as usize,
                },
            )],
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
        self.poll_net();
        (self.current_poll_mask() & POLLIN) != 0
    }

    #[allow(dead_code)]
    pub fn poll_writable(&self) -> bool {
        // “可写”同样依赖先推进协议状态机，例如窗口更新或连接完成后才会真正出现 POLLOUT。
        self.poll_net();
        (self.current_poll_mask() & POLLOUT) != 0
    }

    #[allow(dead_code)]
    pub fn poll_rdhup(&self) -> bool {
        // RDHUP 既可能来自对端 EOF，也可能来自本端记录的读半关闭状态。
        self.poll_net();
        (self.current_poll_mask() & POLLRDHUP) != 0
    }

    pub fn shutdown_v4(&self, how: usize) -> Result<(), isize> {
        const ENOTCONN: isize = -107;
        self.poll_net();
        let (kind, tcp_handle, udp_connected) = match &*self.inner.lock() {
            Inner::TcpStream { handle } => (NetSocketKind::TcpStream, Some(*handle), None),
            Inner::TcpListener { .. } => (NetSocketKind::TcpListener, None, None),
            Inner::Udp { connected, .. } => (NetSocketKind::Udp, None, Some(connected.is_some())),
        };

        if let Some(handle) = tcp_handle {
            let state = self.with_sockets_mut(|_iface, _dev, sockets| {
                sockets.get::<tcp::Socket>(handle).state()
            });
            if matches!(state, tcp::State::Closed) {
                return Err(ENOTCONN);
            }
        } else if kind == NetSocketKind::TcpListener {
            return Err(ENOTCONN);
        } else if kind == NetSocketKind::Udp && udp_connected != Some(true) {
            return Err(ENOTCONN);
        }

        let rd = how == 0 || how == 2;
        let wr = how == 1 || how == 2;
        {
            let mut opts = self.opts.lock();
            if rd {
                opts.rd_shutdown = true;
            }
            if wr {
                opts.wr_shutdown = true;
            }
        }
        if wr && kind == NetSocketKind::TcpStream {
            let _ = self.tcp_close();
        }
        self.notify_poll_waiters();
        Ok(())
    }

    #[allow(dead_code)]
    pub fn bind_v4(&self, ip: Ipv4Address, port: u16) -> Result<(), isize> {
        self.bind_ip(IpAddress::Ipv4(ip), port)
    }

    pub fn bind_ip(&self, ip: IpAddress, port: u16) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EADDRINUSE: isize = -98;
        const EADDRNOTAVAIL: isize = -99;
        const EOPNOTSUPP: isize = -95;
        let local_addr = match ip {
            IpAddress::Ipv4(ip) if ip == Ipv4Address::UNSPECIFIED => true,
            IpAddress::Ipv4(ip) => {
                netdev::is_local_ipv4_addr_in_namespace(self.net_ns_id, ipv4_bytes(ip))
            }
            IpAddress::Ipv6(ip) if ip == Ipv6Address::UNSPECIFIED => true,
            IpAddress::Ipv6(ip) => {
                netdev::is_local_ipv6_addr_in_namespace(self.net_ns_id, ipv6_bytes(ip))
            }
        };
        if !local_addr {
            return Err(EADDRNOTAVAIL);
        }
        if !self.bound_device_accepts_ip(ip) {
            return Err(EADDRNOTAVAIL);
        }
        let ephemeral = port == 0;
        self.poll_net();
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::TcpStream { handle } => self.with_sockets_mut(|_iface, _dev, sockets| {
                let port = if ephemeral {
                    crate::net::alloc_ephemeral_port_in(sockets).ok_or(EADDRINUSE)?
                } else {
                    port
                };
                let v6only = self.ipv6_v6only();
                let requested_addr = if ip_is_unspecified(ip) {
                    (self.domain == AF_INET6 && v6only).then_some(ip)
                } else {
                    Some(ip)
                };
                let requested_reuseaddr = self.reuseaddr();
                if tcp_port_in_use(
                    self.net_ns_id,
                    sockets,
                    *handle,
                    requested_addr,
                    port,
                    requested_reuseaddr,
                    self.domain,
                    v6only,
                ) {
                    return Err(EADDRINUSE);
                }
                let s = sockets.get_mut::<tcp::Socket>(*handle);
                s.set_bound_endpoint(IpListenEndpoint {
                    addr: requested_addr,
                    port,
                });
                Ok(())
            }),
            Inner::Udp { handle, .. } => {
                let mut last_err = EINVAL;
                // UDP 绑定 ephemeral port 时要容忍竞争；这里多试几次，避免分配出的临时端口刚好撞上已用端口。
                for _ in 0..32 {
                    let r = self.with_sockets_mut(|_iface, _dev, sockets| {
                        let try_port = if ephemeral {
                            crate::net::alloc_ephemeral_port_in(sockets).ok_or(EADDRINUSE)?
                        } else {
                            port
                        };
                        let v6only = self.ipv6_v6only();
                        let requested_addr = if ip_is_unspecified(ip) {
                            (self.domain == AF_INET6 && v6only).then_some(ip)
                        } else {
                            Some(ip)
                        };
                        let requested_reuseaddr = self.reuseaddr();
                        if udp_port_in_use(
                            self.net_ns_id,
                            sockets,
                            *handle,
                            requested_addr,
                            try_port,
                            requested_reuseaddr,
                            if self.protocol == IPPROTO_UDPLITE {
                                IpProtocol::UdpLite
                            } else {
                                IpProtocol::Udp
                            },
                            self.domain,
                            v6only,
                        ) {
                            return Err(EADDRINUSE);
                        }
                        let s = sockets.get_mut::<udp::Socket>(*handle);
                        s.bind(IpListenEndpoint {
                            addr: requested_addr,
                            port: try_port,
                        })
                        .map_err(|_| EINVAL)
                    });
                    match r {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            last_err = e;
                            if !ephemeral || e == EADDRINUSE {
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
        // smoltcp 没有 Linux 那样的半连接/全连接队列。本实现用多个
        // listening socket 近似 backlog，但每个槽都会预分配 TCP 数据缓冲；
        // 因此只预建一个小的内部窗口，避免长时间 LTP 批次把内核堆耗尽。
        let backlog = backlog.max(1).min(TCP_LISTEN_BACKLOG_PREALLOC_LIMIT);
        self.poll_net();
        let mut inner = self.inner.lock();
        //
        // only tcp可以被listen

        let handle = match &*inner {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        // 获取绑定端点；未显式 bind 时 Linux 语义要求 listen() 返回 EINVAL。
        let endpoint = self.with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<tcp::Socket>(handle);
            s.get_bound_endpoint()
        });

        if endpoint.port == 0 {
            return Err(EINVAL);
        }

        let (
            hop_limit,
            ipv4_tos,
            keepalive,
            keepidle_secs,
            keepintvl_secs,
            keepcnt,
            tcp_nodelay,
            reuseaddr,
        ) = {
            let opts = self.opts.lock();
            (
                ipv4_ttl_hop_limit(opts.ip_ttl),
                ipv4_tos_meta(opts.ip_tos),
                opts.keepalive,
                opts.tcp_keepidle_secs,
                opts.tcp_keepintvl_secs,
                opts.tcp_keepcnt,
                opts.tcp_nodelay,
                opts.reuseaddr,
            )
        };
        let (keepalive_interval, keepalive_timeout) =
            tcp_keepalive_timers(keepalive, keepidle_secs, keepintvl_secs, keepcnt);
        let mut listen_handles = Vec::new();
        // smoltcp 没有现成的 backlog 队列，这里用“多个同时 listen 的 socket”近似模拟 backlog 槽位。
        // 现有 handle 直接复用成第一个槽位，避免无意义地销毁再重建。
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            s.set_hop_limit(hop_limit);
            s.set_ipv4_tos(ipv4_tos);
            s.set_keep_alive(keepalive_interval);
            s.set_timeout(keepalive_timeout);
            s.set_nagle_enabled(!tcp_nodelay);
            let _ = s.listen(endpoint);
        });
        listen_handles.push(handle);
        //
        // 创建若干个 listen socket 来 满足backlog
        //
        for _ in 1..backlog {
            let h = self.with_sockets_mut(|_iface, _dev, sockets| {
                let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
                let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
                let mut s = tcp::Socket::new(rx, tx);
                s.set_hop_limit(hop_limit);
                s.set_ipv4_tos(ipv4_tos);
                s.set_keep_alive(keepalive_interval);
                s.set_timeout(keepalive_timeout);
                s.set_nagle_enabled(!tcp_nodelay);

                let _ = s.listen(endpoint);
                sockets.add(s)
            });
            note_tcp_handle_created();
            listen_handles.push(h);
        }
        set_tcp_socket_meta(
            self.net_ns_id,
            &listen_handles,
            reuseaddr,
            self.domain,
            self.ipv6_v6only(),
        );
        *inner = Inner::TcpListener {
            endpoint,
            backlog,
            listen: listen_handles,
        };
        drop(inner);
        self.notify_poll_waiters();
        Ok(())
    }

    pub fn accept(&self, nonblock: bool) -> Result<Arc<NetSocketFile>, isize> {
        const EOPNOTSUPP: isize = -95;
        const EAGAIN: isize = -11;
        loop {
            self.poll_net();
            let mut inner = self.inner.lock();
            let Inner::TcpListener {
                endpoint,
                backlog,
                listen,
            } = &mut *inner
            else {
                return Err(EOPNOTSUPP);
            };
            // backlog 本质上是一组监听槽位，accept 时要找到其中任意一个已完成握手的连接。
            let mut idx = None;
            for (i, h) in listen.iter().enumerate() {
                let established = self.with_sockets_mut(|_iface, _dev, sockets| {
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
                let mut accepted_opts = self.opts.lock().clone();
                accepted_opts.rd_shutdown = false;
                accepted_opts.wr_shutdown = false;
                accepted_opts.connect_in_progress = false;
                // 取走一个已连接槽位后，立刻补一个新的监听 socket 回去，维持用户看到的 backlog 容量。
                while listen.len() < *backlog {
                    let hop_limit = ipv4_ttl_hop_limit(accepted_opts.ip_ttl);
                    let ipv4_tos = ipv4_tos_meta(accepted_opts.ip_tos);
                    let (keepalive_interval, keepalive_timeout) = tcp_keepalive_timers(
                        accepted_opts.keepalive,
                        accepted_opts.tcp_keepidle_secs,
                        accepted_opts.tcp_keepintvl_secs,
                        accepted_opts.tcp_keepcnt,
                    );
                    let tcp_nodelay = accepted_opts.tcp_nodelay;
                    let new_h = self.with_sockets_mut(|_iface, _dev, sockets| {
                        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
                        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
                        let mut s = tcp::Socket::new(rx, tx);
                        s.set_hop_limit(hop_limit);
                        s.set_ipv4_tos(ipv4_tos);
                        s.set_keep_alive(keepalive_interval);
                        s.set_timeout(keepalive_timeout);
                        s.set_nagle_enabled(!tcp_nodelay);
                        let _ = s.listen(*endpoint);
                        sockets.add(s)
                    });
                    note_tcp_handle_created();
                    set_tcp_socket_meta(
                        self.net_ns_id,
                        &[new_h],
                        accepted_opts.reuseaddr,
                        self.domain,
                        accepted_opts.ipv6_v6only,
                    );
                    listen.push(new_h);
                }
                set_tcp_socket_meta(
                    self.net_ns_id,
                    &[h],
                    accepted_opts.reuseaddr,
                    self.domain,
                    accepted_opts.ipv6_v6only,
                );
                drop(inner);
                self.notify_poll_waiters();
                let accepted = Arc::new(NetSocketFile {
                    net_ns_id: self.net_ns_id,
                    domain: self.domain,
                    protocol: self.protocol,
                    proc_inode: alloc_socket_inode(),
                    proc_uid: self.proc_uid,
                    inner: Mutex::new(Inner::TcpStream { handle: h }),
                    opts: Mutex::new(accepted_opts),
                    mcast_memberships: Mutex::new(Vec::new()),
                    poll_waiters: Mutex::new(PollWaitQueue::default()),
                });
                note_net_socket_file_created();
                return Ok(accepted);
            }
            drop(inner);
            if nonblock {
                return Err(EAGAIN);
            }
            if pending_unmasked_signal() {
                return Err(EINTR);
            }
            // 阻塞 accept 必须挂到监听 socket 的等待队列上。只让出 CPU
            // 会错过 connect 完成时的网络唤醒，使已完成握手的连接停在 backlog
            // 槽位里但 accept 任务不再及时运行。
            wait_for_socket_event(self, POLLIN, None)?;
        }
    }

    #[allow(dead_code)]
    pub fn connect_v4(
        &self,
        ip: Ipv4Address,
        port: u16,
        local_port: Option<u16>,
        nonblock: bool,
    ) -> Result<(), isize> {
        self.connect_ip(IpAddress::Ipv4(ip), port, local_port, nonblock)
    }

    pub fn connect_ip(
        &self,
        ip: IpAddress,
        port: u16,
        local_port: Option<u16>,
        nonblock: bool,
    ) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EADDRINUSE: isize = -98;
        const EOPNOTSUPP: isize = -95;
        const EISCONN: isize = -106;
        const ECONNREFUSED: isize = -111;
        const EALREADY: isize = -114;
        const EINPROGRESS: isize = -115;
        if port == 0 {
            return Err(EINVAL);
        }
        self.poll_net();
        // 先摘出需要的 handle，避免拿着文件锁去执行可能较慢的网络状态机操作。
        let (tcp_handle, udp_handle) = match &*self.inner.lock() {
            Inner::TcpStream { handle } => (Some(*handle), None),
            Inner::Udp { handle, .. } => (None, Some(*handle)),
            _ => return Err(EOPNOTSUPP),
        };

        if let Some(handle) = tcp_handle {
            self.refresh_connect_error();
            let state = self.with_sockets_mut(|_iface, _dev, sockets| {
                sockets.get::<tcp::Socket>(handle).state()
            });
            if matches!(state, tcp::State::Established) {
                self.opts.lock().connect_in_progress = false;
                return Err(EISCONN);
            }
            let pending = {
                let mut opts = self.opts.lock();
                if opts.pending_error != 0 {
                    let errno = opts.pending_error;
                    opts.pending_error = 0;
                    Some(-(errno as isize))
                } else {
                    None
                }
            };
            if let Some(errno) = pending {
                return Err(errno);
            }
            if !matches!(state, tcp::State::Closed) {
                if nonblock {
                    return Err(EALREADY);
                }
            }
            let local_addr = self.tcp_connect_source_addr_for_ip(ip);
            let r = self.with_sockets_mut(|iface, _dev, sockets| {
                let cx = iface.context();
                let bound = sockets.get::<tcp::Socket>(handle).get_bound_endpoint();
                let local = if let Some(local) = local_port.or_else(|| {
                    if bound.port != 0 {
                        Some(bound.port)
                    } else {
                        None
                    }
                }) {
                    local
                } else {
                    let Some(local) = crate::net::alloc_ephemeral_port_in(sockets) else {
                        return Err(EADDRINUSE);
                    };
                    local
                };
                let local_ep = IpListenEndpoint {
                    addr: bound.addr.or(local_addr),
                    port: local,
                };
                Ok(sockets
                    .get_mut::<tcp::Socket>(handle)
                    .connect(cx, (ip, port), local_ep))
            });
            let r = match r {
                Ok(r) => r,
                Err(e) => return Err(e),
            };
            match r {
                Ok(()) => {}
                Err(tcp::ConnectError::InvalidState) => {
                    let state = self.with_sockets_mut(|_iface, _dev, sockets| {
                        sockets.get::<tcp::Socket>(handle).state()
                    });
                    if nonblock && !matches!(state, tcp::State::Established | tcp::State::Closed) {
                        return Err(EALREADY);
                    }
                    return Err(EISCONN);
                }
                Err(tcp::ConnectError::Unaddressable) => return Err(EINVAL),
            }
            if nonblock {
                self.poll_net();
                let state = self.with_sockets_mut(|_iface, _dev, sockets| {
                    sockets.get::<tcp::Socket>(handle).state()
                });
                if matches!(state, tcp::State::Established) {
                    self.opts.lock().connect_in_progress = false;
                    self.notify_poll_waiters();
                    return Ok(());
                }
                if matches!(state, tcp::State::Closed) {
                    self.set_socket_error(ECONNREFUSED);
                    return Err(ECONNREFUSED);
                }
                self.opts.lock().connect_in_progress = true;
                self.notify_poll_waiters();
                return Err(EINPROGRESS);
            }

            // 阻塞式 TCP connect：最多等待 5 秒，期间不断 poll 网络栈并让出 CPU。
            const ETIMEDOUT: isize = -110;
            let start = crate::time::get_time_ms();
            let deadline = start.saturating_add(5_000);
            loop {
                self.poll_net();
                let st = self.with_sockets_mut(|_iface, _dev, sockets| {
                    sockets.get::<tcp::Socket>(handle).state()
                });
                if matches!(st, tcp::State::Established) {
                    self.opts.lock().connect_in_progress = false;
                    self.notify_poll_waiters();
                    break;
                }
                if matches!(st, tcp::State::Closed) {
                    self.opts.lock().connect_in_progress = false;
                    self.notify_poll_waiters();
                    self.set_socket_error(ECONNREFUSED);
                    return Err(ECONNREFUSED);
                }
                if crate::time::get_time_ms() >= deadline {
                    self.opts.lock().connect_in_progress = false;
                    self.notify_poll_waiters();
                    self.set_socket_error(ETIMEDOUT);
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
        if let IpAddress::Ipv4(ip) = ip {
            self.check_broadcast_send(ip)?;
        }
        let remote = IpEndpoint::new(ip, port);
        let bound_device_addr = self.bound_device_source_addr_for_ip(ip);
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let needs_bind = sockets.get::<udp::Socket>(handle).endpoint().port == 0;
            if needs_bind {
                let local = if let Some(local) = local_port {
                    local
                } else {
                    let Some(local) = crate::net::alloc_ephemeral_port_in(sockets) else {
                        return Err(EADDRINUSE);
                    };
                    local
                };
                sockets
                    .get_mut::<udp::Socket>(handle)
                    .bind(IpListenEndpoint {
                        addr: bound_device_addr,
                        port: local,
                    })
                    .map_err(|_| EADDRINUSE)?;
            }
            Ok(())
        })?;
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

    pub fn disconnect_v4(&self) -> Result<(), isize> {
        const EOPNOTSUPP: isize = -95;
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::TcpStream { handle } => {
                let handle = *handle;
                drop(inner);
                self.opts.lock().connect_in_progress = false;
                self.with_sockets_mut(|_iface, _dev, sockets| {
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                });
                self.notify_poll_waiters();
                Ok(())
            }
            Inner::Udp { connected, .. } => {
                *connected = None;
                drop(inner);
                self.notify_poll_waiters();
                Ok(())
            }
            Inner::TcpListener { .. } => Err(EOPNOTSUPP),
        }
    }

    pub fn tcp_send(&self, data: &[u8], nonblock: bool) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        const EOPNOTSUPP: isize = -95;
        const EPIPE: isize = -32;
        self.poll_net();
        if self.opts.lock().wr_shutdown {
            return Err(EPIPE);
        }
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let deadline_ms = (!nonblock).then(|| self.sndtimeo_deadline_ms()).flatten();
        let mut off = 0usize;
        while off < data.len() {
            self.poll_net();
            let sent = self.with_sockets_mut(|_iface, _dev, sockets| {
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
                if nonblock {
                    return if off > 0 { Ok(off) } else { Err(EAGAIN) };
                }
                if let Err(e) = wait_for_socket_event(self, POLLOUT, deadline_ms) {
                    return if off > 0 { Ok(off) } else { Err(e) };
                }
                continue;
            }
            off += sent;
            self.poll_net();
        }
        Ok(off)
    }

    pub fn tcp_prepare_cork_send(&self, nonblock: bool) -> Result<(), isize> {
        const EAGAIN: isize = -11;
        const EOPNOTSUPP: isize = -95;
        const EPIPE: isize = -32;
        self.poll_net();
        if self.opts.lock().wr_shutdown {
            return Err(EPIPE);
        }
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let deadline_ms = (!nonblock).then(|| self.sndtimeo_deadline_ms()).flatten();
        loop {
            self.poll_net();
            let ready = self.with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get::<tcp::Socket>(handle);
                if !s.may_send() {
                    return Err(EPIPE);
                }
                Ok(s.can_send())
            })?;
            if ready {
                return Ok(());
            }
            if nonblock {
                return Err(EAGAIN);
            }
            wait_for_socket_event(self, POLLOUT, deadline_ms)?;
        }
    }

    pub(crate) fn tcp_try_flush_send_buffer(&self, data: &[u8]) -> usize {
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return 0,
        };
        if self.opts.lock().wr_shutdown {
            return 0;
        }
        let mut off = 0usize;
        while off < data.len() {
            self.poll_net();
            let sent = self.with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<tcp::Socket>(handle);
                if !s.may_send() || !s.can_send() {
                    return 0usize;
                }
                s.send_slice(&data[off..]).unwrap_or(0)
            });
            if sent == 0 {
                break;
            }
            off += sent;
        }
        if off > 0 {
            self.poll_net();
        }
        off
    }

    fn udp_wait_send_ready(&self, handle: SocketHandle, nonblock: bool) -> Result<(), isize> {
        const EAGAIN: isize = -11;
        let deadline_ms = (!nonblock).then(|| self.sndtimeo_deadline_ms()).flatten();
        loop {
            self.poll_net();
            if self.with_sockets_mut(|_iface, _dev, sockets| {
                sockets.get::<udp::Socket>(handle).can_send()
            }) {
                return Ok(());
            }
            if nonblock {
                return Err(EAGAIN);
            }
            wait_for_socket_event(self, POLLOUT, deadline_ms)?;
        }
    }

    pub fn tcp_recv(&self, buf: &mut [u8], peek: bool) -> Result<usize, isize> {
        self.tcp_recv_inner(buf, peek, false)
    }

    pub fn tcp_recv_nonblock(&self, buf: &mut [u8], peek: bool) -> Result<usize, isize> {
        self.tcp_recv_inner(buf, peek, true)
    }

    fn tcp_recv_inner(&self, buf: &mut [u8], peek: bool, nonblock: bool) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        const EOPNOTSUPP: isize = -95;
        enum TcpRecvResult {
            Data(usize),
            Dropped,
        }
        self.poll_net();
        if self.opts.lock().rd_shutdown {
            return Ok(0);
        }
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let deadline_ms = (!nonblock).then(|| self.rcvtimeo_deadline_ms()).flatten();
        let lowat_target = if buf.is_empty() {
            0
        } else {
            core::cmp::min(self.rcvlowat().max(1) as usize, buf.len())
        };
        loop {
            self.poll_net();
            let (classic_filter, bpf_filter) = {
                let opts = self.opts.lock();
                (opts.classic_filter.clone(), opts.bpf_filter.clone())
            };
            let res: Result<Option<TcpRecvResult>, isize> =
                self.with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get_mut::<tcp::Socket>(handle);
                    let queued = s.recv_queue();
                    if queued > 0 && queued < lowat_target && !nonblock && s.may_recv() {
                        return Ok(None);
                    }
                    if s.can_recv() {
                        if classic_filter.is_none() && bpf_filter.is_none() {
                            let n = if peek {
                                s.peek_slice(buf).unwrap_or(0)
                            } else {
                                s.recv_slice(buf).unwrap_or(0)
                            };
                            return Ok(Some(TcpRecvResult::Data(n)));
                        }
                        if queued == 0 {
                            return Ok(Some(TcpRecvResult::Data(0)));
                        }
                        let mut packet = s.peek(queued).unwrap_or(&[]).to_vec();
                        let packet_len = packet.len();
                        if packet_len == 0 {
                            return Ok(Some(TcpRecvResult::Data(0)));
                        }
                        let mut visible_len = packet_len;
                        if let Some(filter) = &classic_filter {
                            let Some(snaplen) = filter.filter_len(&packet[..visible_len]) else {
                                let _ = s.recv_slice(&mut packet);
                                return Ok(Some(TcpRecvResult::Dropped));
                            };
                            visible_len = snaplen;
                        }
                        if let Some(filter) = &bpf_filter {
                            let Some(snaplen) = filter.filter_len(&packet[..visible_len]) else {
                                let _ = s.recv_slice(&mut packet);
                                return Ok(Some(TcpRecvResult::Dropped));
                            };
                            visible_len = snaplen;
                        }
                        let n = buf.len().min(visible_len);
                        buf[..n].copy_from_slice(&packet[..n]);
                        if !peek {
                            let consume_len = if visible_len < packet_len {
                                packet_len
                            } else {
                                n
                            };
                            let _ = s.recv_slice(&mut packet[..consume_len]);
                        }
                        return Ok(Some(TcpRecvResult::Data(n)));
                    }
                    // 对端已经关闭发送方向时应立即以 0 告知 EOF，而不是继续把调用者阻塞住。
                    if !s.may_recv() {
                        return Ok(Some(TcpRecvResult::Data(0)));
                    }
                    Ok(None)
                });
            let res = res?;
            if let Some(TcpRecvResult::Dropped) = res {
                self.poll_net();
                continue;
            }
            if let Some(TcpRecvResult::Data(n)) = res {
                if n > 0 {
                    if !peek {
                        self.record_recv_timestamp();
                    }
                    self.poll_net();
                }
                return Ok(n);
            }
            // Linux receive paths may run sk_busy_loop() after checking the
            // receive queue and before sleeping/reporting EAGAIN. Keep TCP on
            // that low-latency path when SO_BUSY_POLL or the net.core
            // busy-poll sysctls are enabled.
            if self.busy_recv_readable() {
                continue;
            }
            if nonblock {
                return Err(EAGAIN);
            }
            wait_for_socket_event(self, POLLIN, deadline_ms)?;
        }
    }

    pub fn tcp_close(&self) -> Result<(), isize> {
        const EOPNOTSUPP: isize = -95;
        self.poll_net();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            if !matches!(s.state(), tcp::State::Closed) {
                s.close();
            }
        });
        // Linux close 后 TCP 控制块会作为 orphan 继续把已排队数据和 FIN 送完。
        // 当前内核还没有 orphan socket 表，因此在移除 smoltcp handle 前主动推进到
        // FIN 至少已被对端 ACK 的状态；否则大文件 sendfile 后立刻 close 可能让客户端
        // 永远等不到 EOF。
        for _ in 0..65536 {
            self.poll_net();
            let flushed = self.with_sockets_mut(|_iface, _dev, sockets| {
                let state = sockets.get::<tcp::Socket>(handle).state();
                matches!(
                    state,
                    tcp::State::FinWait2 | tcp::State::TimeWait | tcp::State::Closed
                )
            });
            if flushed {
                break;
            }
            // 仅在当前任务里紧密 poll 会让 peer 进程没有机会读取 socket、
            // 推进窗口并 ACK 已排队数据。让出 CPU 后再继续检查，近似 Linux
            // orphan TCP 控制块在 close 返回后仍会异步排空发送队列的语义。
            if current_task().is_some() {
                crate::task::processor::suspend_current_and_run_next();
            } else {
                break;
            }
        }
        Ok(())
    }

    fn tcp_abortive_close(&self) -> Result<(), isize> {
        const EOPNOTSUPP: isize = -95;
        self.poll_net();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        self.with_sockets_mut(|_iface, _dev, sockets| {
            sockets.get_mut::<tcp::Socket>(handle).abort();
        });
        for _ in 0..4 {
            self.poll_net();
        }
        Ok(())
    }

    pub fn udp_send_connected(
        &self,
        data: &[u8],
        nonblock: bool,
        msg_dontroute: bool,
        msg_confirm: bool,
        ttl_override: Option<u8>,
        tos_override: Option<u8>,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
    ) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        const EOPNOTSUPP: isize = -95;
        const EDESTADDRREQ: isize = -89;
        const EADDRINUSE: isize = -98;
        const EMSGSIZE: isize = -90;
        const EPIPE: isize = -32;
        if data.len() > IPV4_UDP_MAX_PAYLOAD {
            return Err(EMSGSIZE);
        }
        self.poll_net();
        if self.opts.lock().wr_shutdown {
            return Err(EPIPE);
        }
        let (handle, remote) = match &*self.inner.lock() {
            Inner::Udp { handle, connected } => (*handle, *connected),
            _ => return Err(EOPNOTSUPP),
        };
        let Some(remote) = remote else {
            return Err(EDESTADDRREQ);
        };
        if let IpAddress::Ipv4(remote4) = remote.addr {
            self.check_broadcast_send(remote4)?;
        }
        let pktinfo_addr =
            self.udp_pktinfo_source_addr_for_ip(remote.addr, ifindex_override, local_override)?;
        let bound_device_addr = pktinfo_addr;
        if let IpAddress::Ipv4(remote4) = remote.addr {
            self.check_udp_dontroute(remote4, bound_device_addr, ifindex_override, msg_dontroute)?;
            self.check_udp_path_mtu(
                remote4,
                remote.port,
                bound_device_addr,
                ifindex_override,
                data.len(),
            )?;
            self.confirm_udp_neighbor(
                remote4,
                bound_device_addr,
                ifindex_override,
                msg_dontroute,
                msg_confirm,
            );
        }
        let hop_limit = ttl_override.or_else(|| self.udp_hop_limit_for_remote(remote));
        let ipv4_tos = tos_override.or_else(|| {
            let tos = self.opts.lock().ip_tos;
            (tos != 0).then_some(tos)
        });
        let suppress_multicast_loopback = match remote.addr {
            IpAddress::Ipv4(remote4) => {
                netdev::ipv4_is_multicast_addr(ipv4_bytes(remote4)) && !self.opts.lock().mcast_loop
            }
            IpAddress::Ipv6(_) => false,
        };
        let local_addr = bound_device_addr;
        let meta = udp_send_metadata(remote, local_addr, ipv4_tos);
        // smoltcp 发送前要求本地端点已绑定；若用户尚未 bind，则在首次发送前自动补一个临时端口。
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let needs_bind = sockets.get::<udp::Socket>(handle).endpoint().port == 0;
            if needs_bind {
                let Some(port) = crate::net::alloc_ephemeral_port_in(sockets) else {
                    return Err(EADDRINUSE);
                };
                sockets
                    .get_mut::<udp::Socket>(handle)
                    .bind(IpListenEndpoint {
                        addr: bound_device_addr,
                        port,
                    })
                    .map_err(|_| EADDRINUSE)?;
            }
            Ok(())
        })?;
        self.ensure_udp_buffer_capacity(UDP_RX_BUF_LEN, data.len());
        let deadline_ms = (!nonblock).then(|| self.sndtimeo_deadline_ms()).flatten();
        loop {
            self.poll_net();
            let ok = self.with_sockets_mut(|_iface, dev, sockets| {
                let sent = {
                    let s = sockets.get_mut::<udp::Socket>(handle);
                    s.set_hop_limit(hop_limit);
                    if !s.can_send() {
                        return Ok::<bool, isize>(false);
                    }
                    s.send_slice(data, meta)
                }
                .map(|_| true)
                .map_err(|err| match err {
                    udp::SendError::BufferFull => EMSGSIZE,
                    udp::SendError::Unaddressable => EDESTADDRREQ,
                })?;
                if sent && suppress_multicast_loopback {
                    dev.suppress_next_multicast_loopback();
                }
                Ok(sent)
            })?;
            if ok {
                self.poll_net();
                self.maybe_queue_udp_port_unreachable(remote, local_addr, ifindex_override, data);
                return Ok(data.len());
            }
            if nonblock {
                return Err(EAGAIN);
            }
            wait_for_socket_event(self, POLLOUT, deadline_ms)?;
        }
    }

    pub fn udp_prepare_connected_send(
        &self,
        data_len: usize,
        nonblock: bool,
        msg_dontroute: bool,
        msg_confirm: bool,
        ttl_override: Option<u8>,
        tos_override: Option<u8>,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
    ) -> Result<(), isize> {
        const EADDRINUSE: isize = -98;
        const EOPNOTSUPP: isize = -95;
        const EDESTADDRREQ: isize = -89;
        const EMSGSIZE: isize = -90;
        const EPIPE: isize = -32;
        if data_len > IPV4_UDP_MAX_PAYLOAD {
            return Err(EMSGSIZE);
        }
        self.poll_net();
        if self.opts.lock().wr_shutdown {
            return Err(EPIPE);
        }
        let (handle, remote) = match &*self.inner.lock() {
            Inner::Udp { handle, connected } => (*handle, *connected),
            _ => return Err(EOPNOTSUPP),
        };
        let Some(remote) = remote else {
            return Err(EDESTADDRREQ);
        };
        let _ = (ttl_override, tos_override);
        if let IpAddress::Ipv4(remote4) = remote.addr {
            self.check_broadcast_send(remote4)?;
        }
        let pktinfo_addr =
            self.udp_pktinfo_source_addr_for_ip(remote.addr, ifindex_override, local_override)?;
        let bound_device_addr = pktinfo_addr;
        if let IpAddress::Ipv4(remote4) = remote.addr {
            self.check_udp_dontroute(remote4, bound_device_addr, ifindex_override, msg_dontroute)?;
            self.check_udp_path_mtu(
                remote4,
                remote.port,
                bound_device_addr,
                ifindex_override,
                data_len,
            )?;
            self.confirm_udp_neighbor(
                remote4,
                bound_device_addr,
                ifindex_override,
                msg_dontroute,
                msg_confirm,
            );
        }
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let needs_bind = sockets.get::<udp::Socket>(handle).endpoint().port == 0;
            if needs_bind {
                let Some(port) = crate::net::alloc_ephemeral_port_in(sockets) else {
                    return Err(EADDRINUSE);
                };
                sockets
                    .get_mut::<udp::Socket>(handle)
                    .bind(IpListenEndpoint {
                        addr: bound_device_addr,
                        port,
                    })
                    .map_err(|_| EADDRINUSE)?;
            }
            Ok(())
        })?;
        self.udp_wait_send_ready(handle, nonblock)
    }

    #[allow(dead_code)]
    pub fn udp_send_to_v4(
        &self,
        ip: Ipv4Address,
        port: u16,
        data: &[u8],
        nonblock: bool,
        msg_dontroute: bool,
        msg_confirm: bool,
        ttl_override: Option<u8>,
        tos_override: Option<u8>,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
    ) -> Result<usize, isize> {
        self.udp_send_to_ip(
            IpAddress::Ipv4(ip),
            port,
            data,
            nonblock,
            msg_dontroute,
            msg_confirm,
            ttl_override,
            tos_override,
            ifindex_override,
            local_override,
        )
    }

    pub fn udp_send_to_ip(
        &self,
        ip: IpAddress,
        port: u16,
        data: &[u8],
        nonblock: bool,
        msg_dontroute: bool,
        msg_confirm: bool,
        ttl_override: Option<u8>,
        tos_override: Option<u8>,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
    ) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        const EINVAL: isize = -22;
        const EADDRINUSE: isize = -98;
        const EOPNOTSUPP: isize = -95;
        const EDESTADDRREQ: isize = -89;
        const EMSGSIZE: isize = -90;
        const EPIPE: isize = -32;
        if port == 0 {
            return Err(EINVAL);
        }
        if data.len() > IPV4_UDP_MAX_PAYLOAD {
            return Err(EMSGSIZE);
        }
        self.poll_net();
        if self.opts.lock().wr_shutdown {
            return Err(EPIPE);
        }
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        if let IpAddress::Ipv4(ip4) = ip {
            self.check_broadcast_send(ip4)?;
        }
        let remote = IpEndpoint::new(ip, port);
        let pktinfo_addr =
            self.udp_pktinfo_source_addr_for_ip(ip, ifindex_override, local_override)?;
        let bound_device_addr = pktinfo_addr;
        if let IpAddress::Ipv4(ip4) = ip {
            self.check_udp_dontroute(ip4, bound_device_addr, ifindex_override, msg_dontroute)?;
            self.check_udp_path_mtu(ip4, port, bound_device_addr, ifindex_override, data.len())?;
            self.confirm_udp_neighbor(
                ip4,
                bound_device_addr,
                ifindex_override,
                msg_dontroute,
                msg_confirm,
            );
        }
        let hop_limit = ttl_override.or_else(|| self.udp_hop_limit_for_remote(remote));
        let ipv4_tos = tos_override.or_else(|| {
            let tos = self.opts.lock().ip_tos;
            (tos != 0).then_some(tos)
        });
        let suppress_multicast_loopback = match ip {
            IpAddress::Ipv4(ip4) => {
                netdev::ipv4_is_multicast_addr(ipv4_bytes(ip4)) && !self.opts.lock().mcast_loop
            }
            IpAddress::Ipv6(_) => false,
        };
        let local_addr = bound_device_addr;
        let meta = udp_send_metadata(remote, local_addr, ipv4_tos);
        // 与 `udp_send_connected()` 一样，发包前必须确保本地端口已经就绪。
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let needs_bind = sockets.get::<udp::Socket>(handle).endpoint().port == 0;
            if needs_bind {
                let Some(local_port) = crate::net::alloc_ephemeral_port_in(sockets) else {
                    return Err(EADDRINUSE);
                };
                sockets
                    .get_mut::<udp::Socket>(handle)
                    .bind(IpListenEndpoint {
                        addr: bound_device_addr,
                        port: local_port,
                    })
                    .map_err(|_| EADDRINUSE)?;
            }
            Ok(())
        })?;
        self.ensure_udp_buffer_capacity(UDP_RX_BUF_LEN, data.len());
        let deadline_ms = (!nonblock).then(|| self.sndtimeo_deadline_ms()).flatten();
        loop {
            self.poll_net();
            let ok = self.with_sockets_mut(|_iface, dev, sockets| {
                let sent = {
                    let s = sockets.get_mut::<udp::Socket>(handle);
                    s.set_hop_limit(hop_limit);
                    if !s.can_send() {
                        return Ok::<bool, isize>(false);
                    }
                    s.send_slice(data, meta)
                }
                .map(|_| true)
                .map_err(|err| match err {
                    udp::SendError::BufferFull => EMSGSIZE,
                    udp::SendError::Unaddressable => EDESTADDRREQ,
                })?;
                if sent && suppress_multicast_loopback {
                    dev.suppress_next_multicast_loopback();
                }
                Ok(sent)
            })?;
            if ok {
                self.poll_net();
                self.maybe_queue_udp_port_unreachable(remote, local_addr, ifindex_override, data);
                return Ok(data.len());
            }
            if nonblock {
                return Err(EAGAIN);
            }
            wait_for_socket_event(self, POLLOUT, deadline_ms)?;
        }
    }

    #[allow(dead_code)]
    pub fn udp_prepare_send_to_v4(
        &self,
        ip: Ipv4Address,
        port: u16,
        data_len: usize,
        nonblock: bool,
        msg_dontroute: bool,
        msg_confirm: bool,
        ttl_override: Option<u8>,
        tos_override: Option<u8>,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
    ) -> Result<(), isize> {
        self.udp_prepare_send_to_ip(
            IpAddress::Ipv4(ip),
            port,
            data_len,
            nonblock,
            msg_dontroute,
            msg_confirm,
            ttl_override,
            tos_override,
            ifindex_override,
            local_override,
        )
    }

    pub fn udp_prepare_send_to_ip(
        &self,
        ip: IpAddress,
        port: u16,
        data_len: usize,
        nonblock: bool,
        msg_dontroute: bool,
        msg_confirm: bool,
        ttl_override: Option<u8>,
        tos_override: Option<u8>,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
    ) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EADDRINUSE: isize = -98;
        const EOPNOTSUPP: isize = -95;
        const EMSGSIZE: isize = -90;
        const EPIPE: isize = -32;
        if port == 0 {
            return Err(EINVAL);
        }
        if data_len > IPV4_UDP_MAX_PAYLOAD {
            return Err(EMSGSIZE);
        }
        self.poll_net();
        if self.opts.lock().wr_shutdown {
            return Err(EPIPE);
        }
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let _ = (ttl_override, tos_override);
        if let IpAddress::Ipv4(ip4) = ip {
            self.check_broadcast_send(ip4)?;
        }
        let pktinfo_addr =
            self.udp_pktinfo_source_addr_for_ip(ip, ifindex_override, local_override)?;
        let bound_device_addr = pktinfo_addr;
        if let IpAddress::Ipv4(ip4) = ip {
            self.check_udp_dontroute(ip4, bound_device_addr, ifindex_override, msg_dontroute)?;
            self.check_udp_path_mtu(ip4, port, bound_device_addr, ifindex_override, data_len)?;
            self.confirm_udp_neighbor(
                ip4,
                bound_device_addr,
                ifindex_override,
                msg_dontroute,
                msg_confirm,
            );
        }
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let needs_bind = sockets.get::<udp::Socket>(handle).endpoint().port == 0;
            if needs_bind {
                let Some(local_port) = crate::net::alloc_ephemeral_port_in(sockets) else {
                    return Err(EADDRINUSE);
                };
                sockets
                    .get_mut::<udp::Socket>(handle)
                    .bind(IpListenEndpoint {
                        addr: bound_device_addr,
                        port: local_port,
                    })
                    .map_err(|_| EADDRINUSE)?;
            }
            Ok(())
        })?;
        self.udp_wait_send_ready(handle, nonblock)
    }

    pub fn udp_recv_from(
        &self,
        buf: &mut [u8],
        peek: bool,
        nonblock: bool,
    ) -> Result<
        (
            usize,
            usize,
            IpAddress,
            u16,
            Option<crate::syscall::net::UdpIpv4RxInfo>,
        ),
        isize,
    > {
        const EOPNOTSUPP: isize = -95;
        const EAGAIN: isize = -11;
        if self.opts.lock().rd_shutdown {
            return Ok((0, 0, IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0, None));
        }
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let deadline_ms = self.rcvtimeo_deadline_ms();
        let mut first_probe = true;
        loop {
            let already_readable = first_probe
                && self.with_sockets_mut(|_iface, _dev, sockets| {
                    sockets.get::<udp::Socket>(handle).can_recv()
                });
            first_probe = false;
            if !already_readable {
                self.poll_net();
            }
            let (classic_filter, bpf_filter) = {
                let opts = self.opts.lock();
                (opts.classic_filter.clone(), opts.bpf_filter.clone())
            };
            let res = self.with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<udp::Socket>(handle);
                if !s.can_recv() {
                    return None;
                }
                let local_endpoint = s.endpoint();
                let local_addr = local_endpoint.addr;
                let local_port = local_endpoint.port;
                let local_group = match s.endpoint().addr {
                    Some(IpAddress::Ipv4(ip)) => {
                        let group = ipv4_bytes(ip);
                        netdev::ipv4_is_multicast_addr(group).then_some(group)
                    }
                    _ => None,
                };
                let packet = if peek {
                    s.peek()
                        .ok()
                        .map(|(payload, meta)| (payload.to_vec(), *meta, true))
                } else {
                    s.recv()
                        .ok()
                        .map(|(payload, meta)| (payload.to_vec(), meta, false))
                };
                packet.map(|(payload, meta, from_peek)| {
                    let rx_info = match (local_addr, meta.endpoint.addr) {
                        (Some(IpAddress::Ipv4(local)), IpAddress::Ipv4(remote)) => {
                            crate::syscall::net::udp_ipv4_rx_info(
                                local,
                                local_port,
                                remote,
                                meta.endpoint.port,
                                payload.len(),
                                peek,
                            )
                        }
                        _ => None,
                    };
                    if let Some(group) = local_group
                        && let Some(rx_info) = rx_info
                        && let IpAddress::Ipv4(ip) = meta.endpoint.addr
                        && !self.multicast_source_allowed(rx_info.ifindex, group, ipv4_bytes(ip))
                    {
                        if from_peek {
                            let _ = s.recv();
                            if let (Some(IpAddress::Ipv4(local)), IpAddress::Ipv4(remote)) =
                                (local_addr, meta.endpoint.addr)
                            {
                                let _ = crate::syscall::net::udp_ipv4_rx_info(
                                    local,
                                    local_port,
                                    remote,
                                    meta.endpoint.port,
                                    payload.len(),
                                    false,
                                );
                            }
                        }
                        return None;
                    }
                    let mut payload_len = payload.len();
                    if let Some(filter) = &classic_filter {
                        let Some(snaplen) = filter.filter_len(&payload[..payload_len]) else {
                            if from_peek {
                                let _ = s.recv();
                                if let (Some(IpAddress::Ipv4(local)), IpAddress::Ipv4(remote)) =
                                    (local_addr, meta.endpoint.addr)
                                {
                                    let _ = crate::syscall::net::udp_ipv4_rx_info(
                                        local,
                                        local_port,
                                        remote,
                                        meta.endpoint.port,
                                        payload.len(),
                                        false,
                                    );
                                }
                            }
                            return None;
                        };
                        payload_len = snaplen;
                    }
                    if let Some(filter) = &bpf_filter {
                        let Some(snaplen) = filter.filter_len(&payload[..payload_len]) else {
                            if from_peek {
                                let _ = s.recv();
                                if let (Some(IpAddress::Ipv4(local)), IpAddress::Ipv4(remote)) =
                                    (local_addr, meta.endpoint.addr)
                                {
                                    let _ = crate::syscall::net::udp_ipv4_rx_info(
                                        local,
                                        local_port,
                                        remote,
                                        meta.endpoint.port,
                                        payload.len(),
                                        false,
                                    );
                                }
                            }
                            return None;
                        };
                        payload_len = snaplen;
                    }
                    let n = min(buf.len(), payload_len);
                    buf[..n].copy_from_slice(&payload[..n]);
                    Some((n, payload_len, meta, rx_info))
                })
            });
            if let Some(None) = res {
                first_probe = true;
                continue;
            }
            if let Some(Some((n, payload_len, meta, rx_info))) = res {
                if !peek {
                    self.record_recv_timestamp();
                }
                if crate::debug_config::DEBUG_NET && n == 4 {
                    let v = u32::from_ne_bytes(buf[..4].try_into().unwrap_or([0; 4]));
                    crate::println!(
                        "[net] udp recv {} bytes from {}:{} val=0x{:08x}",
                        n,
                        meta.endpoint.addr,
                        meta.endpoint.port,
                        v
                    );
                }
                // UDP 数据报一次性出队；返回原始报文长度供 recvmsg(MSG_TRUNC) 按 Linux 语义报告。
                return Ok((
                    n,
                    payload_len,
                    meta.endpoint.addr,
                    meta.endpoint.port,
                    rx_info,
                ));
            }
            // Linux UDP receive checks the queue, then calls sk_busy_loop()
            // before sleeping. Without this, SO_BUSY_POLL on UDP sockets is
            // only stored but never affects the receive path.
            if self.busy_recv_readable() {
                first_probe = true;
                continue;
            }
            if nonblock {
                return Err(EAGAIN);
            }
            wait_for_socket_event(self, POLLIN, deadline_ms)?;
        }
    }

    /// 返回两端地址
    pub fn tcp_endpoints(&self) -> Option<(IpAddress, u16, IpAddress, u16)> {
        self.poll_net();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return None,
        };
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<tcp::Socket>(handle);
            let local = s.local_endpoint()?;
            let remote = s.remote_endpoint()?;
            Some((local.addr, local.port, remote.addr, remote.port))
        })
    }

    #[allow(dead_code)]
    pub fn tcp_endpoints_v4(&self) -> Option<(Ipv4Address, u16, Ipv4Address, u16)> {
        let (lip, lport, rip, rport) = self.tcp_endpoints()?;
        let (IpAddress::Ipv4(lip), IpAddress::Ipv4(rip)) = (lip, rip) else {
            return None;
        };
        Some((lip, lport, rip, rport))
    }

    /// TCP `getpeername(2)` 使用的对端地址。
    ///
    /// smoltcp 在 SYN-SENT 阶段已经保存了 remote endpoint；Linux
    /// `inet_getname(peer=1)` 在连接尚未完成时仍返回 ENOTCONN，所以这里
    /// 过滤掉 Closed/SynSent，只在连接曾经建立后暴露对端地址。
    #[allow(dead_code)]
    pub fn tcp_peer_endpoint_v4(&self) -> Option<(Ipv4Address, u16)> {
        let (ip, port) = self.tcp_peer_endpoint()?;
        let IpAddress::Ipv4(ip) = ip else {
            return None;
        };
        Some((ip, port))
    }

    pub fn tcp_peer_endpoint(&self) -> Option<(IpAddress, u16)> {
        self.poll_net();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return None,
        };
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<tcp::Socket>(handle);
            if matches!(s.state(), tcp::State::Closed | tcp::State::SynSent) {
                return None;
            }
            let remote = s.remote_endpoint()?;
            Some((remote.addr, remote.port))
        })
    }

    /// tcp 的绑定地址，两种情况，普通tcp listen tcp
    #[allow(dead_code)]
    pub fn tcp_local_endpoint_v4(&self) -> Option<(Ipv4Address, u16)> {
        let (ip, port) = self.tcp_local_endpoint()?;
        let IpAddress::Ipv4(ip) = ip else {
            return None;
        };
        Some((ip, port))
    }

    pub fn tcp_local_endpoint(&self) -> Option<(IpAddress, u16)> {
        self.poll_net();
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => self.with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get::<tcp::Socket>(*handle);
                if let Some(local) = s.local_endpoint() {
                    return Some((local.addr, local.port));
                }
                let bound = s.get_bound_endpoint();
                let ip = bound
                    .addr
                    .unwrap_or_else(|| IpAddress::Ipv4(Ipv4Address::UNSPECIFIED));
                Some((ip, bound.port))
            }),
            Inner::TcpListener { endpoint, .. } => {
                let ip = endpoint
                    .addr
                    .unwrap_or_else(|| IpAddress::Ipv4(Ipv4Address::UNSPECIFIED));
                Some((ip, endpoint.port))
            }
            _ => None,
        }
    }

    pub fn udp_endpoint(&self) -> Option<(IpAddress, u16)> {
        self.poll_net();
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return None,
        };
        self.with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<udp::Socket>(handle);
            let ep = s.endpoint();
            let ip = ep
                .addr
                .unwrap_or_else(|| IpAddress::Ipv4(Ipv4Address::UNSPECIFIED));
            Some((ip, ep.port))
        })
    }

    #[allow(dead_code)]
    pub fn udp_endpoint_v4(&self) -> Option<(Ipv4Address, u16)> {
        let (ip, port) = self.udp_endpoint()?;
        let IpAddress::Ipv4(ip) = ip else {
            return None;
        };
        Some((ip, port))
    }

    pub fn udp_peer(&self) -> Option<(IpAddress, u16)> {
        self.poll_net();
        match &*self.inner.lock() {
            Inner::Udp {
                connected: Some(peer),
                ..
            } => Some((peer.addr, peer.port)),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn udp_peer_v4(&self) -> Option<(Ipv4Address, u16)> {
        let (ip, port) = self.udp_peer()?;
        let IpAddress::Ipv4(ip) = ip else {
            return None;
        };
        Some((ip, port))
    }
}

/// 负责在文件对象销毁时回收底层 socket 资源。
impl Drop for NetSocketFile {
    fn drop(&mut self) {
        note_net_socket_file_dropped();
        self.release_ipv4_multicast_memberships();

        let kind = match &*self.inner.lock() {
            Inner::TcpStream { .. } => NetSocketKind::TcpStream,
            Inner::TcpListener { .. } => NetSocketKind::TcpListener,
            Inner::Udp { .. } => NetSocketKind::Udp,
        };

        if kind == NetSocketKind::TcpStream {
            let abortive = {
                let opts = self.opts.lock();
                opts.linger_on && opts.linger_sec == 0
            };
            if abortive {
                crate::syscall::net::clear_msg_more_pending_for_addr(self as *const Self as usize);
                let _ = self.tcp_abortive_close();
            } else {
                crate::syscall::net::drop_tcp_msg_more_pending_for_addr(
                    self as *const Self as usize,
                    self,
                );
                // TCP 要先尝试发出 FIN，再把 handle 从 `SocketSet` 里摘掉；
                // 否则对端看到的会更像“连接被突然回收”，而不是正常关闭流程。
                let _ = self.tcp_close();
            }
        } else {
            crate::syscall::net::clear_msg_more_pending_for_addr(self as *const Self as usize);
        }

        let handles: Vec<SocketHandle> = match &*self.inner.lock() {
            Inner::TcpStream { handle } => vec![*handle],
            Inner::Udp { handle, .. } => vec![*handle],
            Inner::TcpListener { listen, .. } => listen.clone(),
        };
        unregister_poll_waiters(self.net_ns_id, handles.as_slice());
        if kind == NetSocketKind::TcpStream || kind == NetSocketKind::TcpListener {
            unregister_tcp_socket_meta(self.net_ns_id, handles.as_slice());
        } else if kind == NetSocketKind::Udp {
            unregister_udp_socket_meta(self.net_ns_id, handles.as_slice());
        }
        let handle_count = handles.len();
        crate::net::with_sockets_mut_in(self.net_ns_id, |_iface, _dev, sockets| match kind {
            NetSocketKind::TcpStream | NetSocketKind::TcpListener => {
                for h in handles {
                    sockets.remove(h);
                }
                note_tcp_handles_freed(handle_count);
            }
            NetSocketKind::Udp => {
                for h in handles {
                    let (rx_bytes, tx_bytes) = {
                        let s = sockets.get::<udp::Socket>(h);
                        (s.payload_recv_capacity(), s.payload_send_capacity())
                    };
                    sockets.remove(h);
                    note_udp_handle_freed(rx_bytes, tx_bytes);
                }
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
        wr_shutdown: bool,
        rcvlowat: usize,
    },
    TcpListener(Vec<SocketHandle>),
    Udp {
        handle: SocketHandle,
        rd_shutdown: bool,
        wr_shutdown: bool,
    },
}

/// 把网络 socket 挂接到通用 `File` 接口上的适配层。
impl File for NetSocketFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        !self.opts.lock().wr_shutdown
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        self.poll_net();
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
                if self.opts.lock().rd_shutdown {
                    return 0;
                }
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    if slice.is_empty() {
                        break;
                    }
                    if total > 0 && !self.poll_readable() {
                        break;
                    }
                    loop {
                        self.poll_net();
                        enum ReadStep {
                            Data(usize),
                            Eof,
                            Blocked,
                        }
                        let res = self.with_sockets_mut(|_iface, _dev, sockets| {
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
                                    self.poll_net();
                                }
                                if n < slice.len() {
                                    return total;
                                }
                                break;
                            }
                            // TCP 是流语义：一旦读到 EOF，就应立即把已经拿到的数据返回给上层，
                            // 不再继续填后续 UserBuffer 分片。
                            ReadStep::Eof => return total,
                            ReadStep::Blocked => {
                                if total > 0 {
                                    return total;
                                }
                            }
                        }
                        if !self.busy_recv_readable() {
                            crate::task::processor::suspend_current_and_run_next();
                        }
                    }
                }
                total
            }
            NetSocketKind::Udp => {
                if self.opts.lock().rd_shutdown {
                    return 0;
                }
                // UDP 没有“把一个报文拆成多次 read” 的流式语义，必须先整包收进临时缓冲区，
                // 再按 UserBuffer 的分片布局复制出去；否则会把一次 datagram 错误地暴露成多次读取。
                let total_len = buf.buffers.iter().map(|b| b.len()).sum::<usize>();
                if total_len == 0 {
                    return 0;
                }
                let mut tmp = alloc::vec![0u8; total_len];
                let n = match self.udp_recv_from(&mut tmp, false, false) {
                    Ok((n, _, _, _, _)) => n,
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
        self.poll_net();
        enum WriteSnapshot {
            Tcp(SocketHandle),
            Udp,
            None,
        }
        let snapshot = match &*self.inner.lock() {
            Inner::TcpStream { handle } => WriteSnapshot::Tcp(*handle),
            Inner::Udp { .. } => WriteSnapshot::Udp,
            Inner::TcpListener { .. } => WriteSnapshot::None,
        };
        match snapshot {
            WriteSnapshot::None => 0,
            WriteSnapshot::Tcp(handle) => {
                if self.opts.lock().wr_shutdown {
                    return 0;
                }
                if self.opts.lock().tcp_cork {
                    let total_len = buf.buffers.iter().map(|b| b.len()).sum::<usize>();
                    if total_len == 0 {
                        return 0;
                    }
                    let mut data = alloc::vec![0u8; total_len];
                    let mut off = 0usize;
                    for slice in buf.buffers.iter() {
                        data[off..off + slice.len()].copy_from_slice(slice);
                        off += slice.len();
                    }
                    crate::syscall::net::queue_tcp_msg_more_pending_for_addr(
                        self as *const Self as usize,
                        &data,
                    );
                    return total_len;
                }
                let mut total = 0usize;
                for slice in buf.buffers.iter() {
                    let mut off = 0usize;
                    while off < slice.len() {
                        self.poll_net();
                        enum TcpWriteStep {
                            Sent(usize),
                            WouldBlock,
                            Closed,
                        }
                        let step = self.with_sockets_mut(|_iface, _dev, sockets| {
                            let s = sockets.get_mut::<tcp::Socket>(handle);
                            if !s.may_send() {
                                return TcpWriteStep::Closed;
                            }
                            if !s.can_send() {
                                return TcpWriteStep::WouldBlock;
                            }
                            // TCP 写是流式的，允许把一个用户缓冲区分多轮塞进底层发送队列。
                            match s.send_slice(&slice[off..]) {
                                Ok(n) if n > 0 => TcpWriteStep::Sent(n),
                                Ok(_) => TcpWriteStep::WouldBlock,
                                Err(_) => TcpWriteStep::Closed,
                            }
                        });
                        let sent = match step {
                            TcpWriteStep::Sent(n) => n,
                            TcpWriteStep::WouldBlock => {
                                // send buffer 暂时满时主动让出 CPU，等待后续 poll 推进 ACK / 窗口更新。
                                crate::task::processor::suspend_current_and_run_next();
                                continue;
                            }
                            TcpWriteStep::Closed => return total,
                        };
                        if sent == 0 {
                            return total;
                        }
                        off += sent;
                        total += sent;
                        self.poll_net();
                    }
                }
                total
            }
            WriteSnapshot::Udp => {
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
                self.udp_send_connected(&data, false, false, false, None, None, None, None)
                    .unwrap_or(0)
            }
        }
    }

    fn poll_mask(&self) -> i16 {
        // 先推进网络栈，再返回当前统一计算出的事件掩码。
        self.poll_net();
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
        let handles = self.poll_registration_handles();
        let masks = self.with_sockets_mut(|_iface, _dev, sockets| {
            handles
                .iter()
                .map(|(handle, kind)| poll_mask_for_registered_handle(sockets, *handle, *kind))
                .collect::<Vec<_>>()
        });
        for ((handle, kind), current_mask) in handles.into_iter().zip(masks.into_iter()) {
            armed =
                register_poll_waiter_for_handle(self.net_ns_id, handle, kind, current_mask, task)
                    || armed;
        }
        armed
            || self.current_poll_mask() != 0
            || matches!(&*self.inner.lock(), Inner::TcpListener { .. })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
