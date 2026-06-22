//! 内核网络栈封装层。
//!
//! 本模块基于 [`smoltcp`] 为每个 network namespace 维护一份协议栈实例，所有 socket
//! 系统调用（`bind` / `connect` / `send` / `recv` 等）最终都通过这里访问创建 socket
//! 时所在 netns 的 [`Interface`] 与 [`SocketSet`]。
//!
//! 当前能力：
//! - 每个 netns 都有独立虚拟回环网卡（`127.0.0.1/8`），不接外部物理网络；
//! - 所有 netns 栈仍共用一把 [`spin::Mutex`]，SMP 下是已知的串行化点；
//! - TCP/UDP 临时端口在持有目标 netns 的 socket 集合锁时会避开已占用端口。
//!
//! 使用方式：
//! 1. 通过 [`init_in`] 幂等初始化目标 netns（也可由 [`with_sockets_mut_in`] 惰性触发）。
//! 2. 周期性调用 [`poll_in`] 推进目标 netns 协议栈定时事件、唤醒等待网络的任务。
//! 3. 业务代码通过 [`with_sockets_mut_in`] 在持锁状态下操作 smoltcp 对象。
//!
//! TODO 参考linux 实现物理设备+ 虚拟网卡 的支持

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use lazy_static::lazy_static;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::Medium,
    socket::Socket,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address},
};
use spin::Mutex;

mod loopback;

pub(crate) use loopback::PacketTapLoopback;

/// 临时端口区间下界（含）。
///
/// 取值遵循 RFC 6335 推荐的 49152–65535 范围；`connect()` 没有显式 `bind()`
/// 时由 [`alloc_ephemeral_port_in`] 在该区间内挑选源端口。
const EPHEMERAL_START: u16 = 49152;
/// 临时端口区间上界（含）。计数器越过此值后回绕至 [`EPHEMERAL_START`]。
const EPHEMERAL_END: u16 = 65535;
/// 跨命名空间虚拟网卡投递积压队列的上限。
///
/// Linux veth 流量最终会受到 qdisc/设备队列限制；这里的内核队列是该路径的
/// 简化替代，因此也必须有界。否则压测发送端可能持续克隆数据包到内核堆，
/// 速度超过对端命名空间轮询处理的速度。
const PENDING_VETH_QUEUE_LIMIT: usize = 8192;
/// 单次 poll 触发时最多从 veth 积压队列中取出的包数。
const PENDING_VETH_DELIVERY_BUDGET: usize = 4096;

// 全局网络栈表：按 network namespace id 索引，每个 netns 一份独立的 [`NetStack`]。
// 用 `BTreeMap` 而非 `Vec` 是为了用任意 ns_id 直接定位，且不要求 id 连续。
// 所有 netns 仍共用这一把 [`Mutex`]，是 SMP 下已知的串行化点（见模块级文档）。
// PENDING_VETH_IP 是跨 netns veth 直连投递队列：发送侧只入队，后续 poll 再把包注入
// 对端 netns，避免递归持锁推进两个协议栈。
// 注意：这里用普通注释而非 `///`，因为文档注释不能挂在宏调用（lazy_static!）上。
lazy_static! {
    static ref NET: Mutex<BTreeMap<usize, NetStack>> = Mutex::new(BTreeMap::new());
    static ref PENDING_VETH_IP: Mutex<VecDeque<PendingIpDelivery>> = Mutex::new(VecDeque::new());
}

/// 一条等待投递到目标 netns 回环栈的 IP 报文。
struct PendingIpDelivery {
    /// 目标网络命名空间 id。
    target_ns_id: usize,
    /// 已克隆的完整 IP 包字节序列。
    packet: Vec<u8>,
}

/// 临时端口分配计数器：以原子方式自增，越过 [`EPHEMERAL_END`] 后绕回
/// [`EPHEMERAL_START`]。占用检测由 [`alloc_ephemeral_port_in`] 在持有
/// [`SocketSet`] 时完成。
static NEXT_EPHEMERAL: AtomicU16 = AtomicU16::new(EPHEMERAL_START);
/// 防止 veth 待投递队列在 `poll_in()` 嵌套触发时重入 drain。
static DRAINING_PENDING_VETH: AtomicBool = AtomicBool::new(false);

/// 内核网络栈的三件套，必须同时持有才能驱动协议处理：
/// - `iface`：smoltcp 协议引擎，负责 IP 地址管理和 TCP/UDP 状态机；
/// - `dev`：虚拟回环网卡，充当数据包的收发队列；
/// - `sockets`：所有活跃 smoltcp socket 的集中存储池。
pub struct NetStack {
    /// smoltcp 协议引擎：管理本机 IP 地址、ARP/邻居表、TCP/UDP 状态机，
    /// 由 [`poll_in`] 在每次轮询时驱动一次。
    iface: Interface,
    /// 虚拟回环设备，扮演 `lo` 的角色。`Interface::poll` 会从此设备
    /// 取出 RX 报文、推入 TX 报文。
    dev: PacketTapLoopback,
    /// 所有活跃 smoltcp socket 的存储池。socket 句柄（`SocketHandle`）
    /// 由文件描述符层（参见 `fs::socket`）持有，访问时通过此集合解引用。
    sockets: SocketSet<'static>,
}

/// 将内核时钟（毫秒）转换为 smoltcp 所需的 Instant 时间戳。
/// smoltcp 用它计算 TCP 超时、重传等定时事件。
fn now() -> Instant {
    Instant::from_millis(crate::time::get_time_ms() as i64)
}

/// 为指定 network namespace `ns_id` 新建一份网络栈。
///
/// 完成回环网卡创建、IP 地址绑定与 smoltcp 接口初始化，返回可直接放入 [`NET`] 的
/// [`NetStack`]。仅在该 netns 首次被访问时由 [`init_in`] 调用一次。
fn new_stack(ns_id: usize) -> NetStack {
    // Medium::Ip：回环无需以太网帧头，直接收发 IP 数据包。
    let mut dev = PacketTapLoopback::new(ns_id, Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    // 为每个 netns 派生独立随机种子，避免跨命名空间 TCP ISN 序列完全相同。
    config.random_seed =
        0xA2CE_05A2_CE05_A2CEu64 ^ (ns_id as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut iface = Interface::new(config, &mut dev, now());
    iface.update_ip_addrs(|addrs| {
        // 绑定回环地址 127.0.0.1/8。
        let cidr = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), 8);
        let _ = addrs.push(cidr);
        // 同步 Linux 回环设备的 ::1/128，供 AF_INET6 loopback 和 netns 内 IPv6 流量使用。
        let cidr6 = IpCidr::new(IpAddress::Ipv6(Ipv6Address::LOOPBACK), 128);
        let _ = addrs.push(cidr6);
    });
    // set_any_ip(true)：允许接收目标地址不在 iface 地址列表中的数据包，
    // 使绑定 0.0.0.0 的 socket 也能收到发往 127.x.x.x 的回环流量。
    iface.set_any_ip(true);
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::UNSPECIFIED);
    let sockets = SocketSet::new(vec![]);
    NetStack {
        iface,
        dev,
        sockets,
    }
}

/// 幂等初始化目标 netns 的网络栈：若 `ns_id` 尚未建栈则创建，否则原样保留。
/// 所有对外接口（poll / with_sockets / inject）都会先经过它，调用方无需关心启动顺序。
pub fn init_in(ns_id: usize) {
    let mut net = NET.lock();
    net.entry(ns_id).or_insert_with(|| new_stack(ns_id));
}

/// 清理已销毁网络命名空间的所有协议栈状态。
///
/// 这是 Linux netns 释放流程中网络栈侧的处理。最后一个存活进程离开非初始
/// netns 后，对应的 smoltcp socket 池和排队中的 veth 投递也必须释放；
/// 否则反复创建命名空间的压测会让旧 TCP 缓冲区一直被保留，直到未回收的
/// 进程控制块消失。
pub(crate) fn cleanup_namespace(ns_id: usize) {
    if ns_id == 0 {
        return;
    }
    NET.lock().remove(&ns_id);
    PENDING_VETH_IP
        .lock()
        .retain(|delivery| delivery.target_ns_id != ns_id);
}

/// 驱动网络栈前进一步：处理 dev 中积压的数据包，推进所有 socket 的状态机，
/// 并将待发送的应答包（ACK、SYN-ACK 等）写回 dev。
/// 完成后通知等待网络事件的 task 重新检查（类似软中断下半部）。
pub fn poll_in(ns_id: usize) {
    init_in(ns_id);
    let mut net = NET.lock();
    let Some(stack) = net.get_mut(&ns_id) else {
        return;
    };
    sync_iface_ip_addrs(ns_id, &mut stack.iface);
    let _ = stack.iface.poll(now(), &mut stack.dev, &mut stack.sockets);
    drop(net);
    crate::fs::notify_net_poll_events_in(ns_id);
    drain_pending_veth_ip_deliveries();
}

/// 执行一次 busy-poll，并在仍持有 netns 栈锁时检查目标 socket 集合。
///
/// 这比「先单独 poll、再二次查找 socket」更接近 Linux 接收侧结构，也能避免
/// 短小 UDP poll/recv 循环把 50us 预算都耗在锁竞争上。
pub fn poll_busy_with_sockets_mut_in<R>(
    ns_id: usize,
    f: impl FnOnce(&mut Interface, &mut PacketTapLoopback, &mut SocketSet<'static>) -> R,
) -> R {
    init_in(ns_id);
    let (changed, ret) = {
        let mut net = NET.lock();
        let stack = net.get_mut(&ns_id).unwrap();
        let changed = stack.iface.poll(now(), &mut stack.dev, &mut stack.sockets);
        let ret = f(&mut stack.iface, &mut stack.dev, &mut stack.sockets);
        (changed, ret)
    };
    if changed {
        drain_pending_veth_ip_deliveries();
    }
    ret
}

/// 将 smoltcp iface 的地址列表同步为当前 netns 中处于 UP 状态的设备地址。
///
/// smoltcp 只根据 iface 地址判断本机可接收目标，因此每次 poll 前都要把 netdev
/// 控制面维护的 IPv4/IPv6 地址同步进去；回环地址始终保留。
fn sync_iface_ip_addrs(ns_id: usize, iface: &mut Interface) {
    let devices = crate::syscall::net::netdev::devices_snapshot_in_namespace(ns_id);
    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        let loopback = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), 8);
        let _ = addrs.push(loopback);
        let loopback6 = IpCidr::new(IpAddress::Ipv6(Ipv6Address::LOOPBACK), 128);
        let _ = addrs.push(loopback6);
        for dev in devices {
            if (dev.flags & crate::syscall::net::netdev::IFF_UP) == 0 {
                continue;
            }
            for entry in dev.addrs {
                let ip = IpAddress::Ipv4(Ipv4Address::from_bytes(&entry.addr));
                if addrs.iter().any(|probe| probe.address() == ip) {
                    continue;
                }
                let _ = addrs.push(IpCidr::new(ip, entry.prefix_len));
            }
            for entry in dev.addrs6 {
                let ip = IpAddress::Ipv6(Ipv6Address::from_bytes(&entry.addr));
                if addrs.iter().any(|probe| probe.address() == ip) {
                    continue;
                }
                let _ = addrs.push(IpCidr::new(ip, entry.prefix_len));
            }
        }
    });
}

/// 取下一个临时端口候选值（只发号、不判重）。
///
/// 以原子自增轮询 [`EPHEMERAL_START`, `EPHEMERAL_END`] 区间，越界即回绕到下界。
/// 是否真的可用由调用方 [`alloc_ephemeral_port_in`] 结合 [`SocketSet`] 判定。
fn next_ephemeral_candidate() -> u16 {
    loop {
        let p = NEXT_EPHEMERAL.fetch_add(1, Ordering::Relaxed);
        if p < EPHEMERAL_START || p > EPHEMERAL_END {
            NEXT_EPHEMERAL.store(EPHEMERAL_START, Ordering::Relaxed);
            continue;
        }
        return p;
    }
}

/// 判断 `socket` 是否已占用本地端口 `port`，用于临时端口分配时排除冲突。
///
/// TCP 的本地端口分散在两个字段，需要都查：
/// - `get_bound_endpoint()`：`bind()`/`listen()` 设定的监听端口，连接建立前就存在；
/// - `local_endpoint()`：连接四元组里的本地端，仅在连接建立后才有值。
/// UDP 只有单一绑定端点 `endpoint()`，查一处即可。
fn socket_uses_local_port(socket: &Socket<'_>, port: u16) -> bool {
    match socket {
        Socket::Tcp(sock) => {
            sock.get_bound_endpoint().port == port
                || sock
                    .local_endpoint()
                    .is_some_and(|endpoint| endpoint.port == port)
        }
        Socket::Udp(sock) => sock.endpoint().port == port,
        // 其余 socket 类型（Raw/Icmp/Dhcpv4/Dns，按 smoltcp feature 开启时才存在）
        // 不在 TCP/UDP 临时端口空间内占用端口，故对临时端口分配而言一律视为「未占用」。
        // 当前仅启用 socket-tcp/socket-udp，此分支暂不可达；保留它以便将来启用
        // socket-icmp / socket-raw 等特性后匹配仍然完整。
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// 在已持有全局 socket 集合时，按 Linux ephemeral bind/connect 思路挑一个未占用端口。
pub fn alloc_ephemeral_port_in(sockets: &SocketSet<'_>) -> Option<u16> {
    let span = usize::from(EPHEMERAL_END - EPHEMERAL_START) + 1;
    for _ in 0..span {
        let port = next_ephemeral_candidate();
        if sockets
            .iter()
            .all(|(_handle, socket)| !socket_uses_local_port(socket, port))
        {
            return Some(port);
        }
    }
    None
}

/// 判断指定 netns 内是否已有 UDP socket 绑定到 `addr:port`。
///
/// 用于内核内部在构造控制面行为时避开已占用端口；绑定到通配地址的 socket
/// 视为占用所有本地 IPv4 地址。
pub fn udp_port_bound_in(ns_id: usize, addr: Ipv4Address, port: u16) -> bool {
    if port == 0 {
        return false;
    }
    init_in(ns_id);
    let mut net = NET.lock();
    let Some(stack) = net.get_mut(&ns_id) else {
        return false;
    };
    stack.sockets.iter().any(|(_, socket)| {
        let Socket::Udp(sock) = socket else {
            return false;
        };
        let endpoint = sock.endpoint();
        endpoint.port == port
            && match endpoint.addr {
                None => true,
                Some(IpAddress::Ipv4(bound)) => bound == Ipv4Address::UNSPECIFIED || bound == addr,
                Some(IpAddress::Ipv6(_)) => false,
            }
    })
}

/// 在持有全局 [`NET`] 锁的前提下，将目标 netns 的 `iface` / `dev` / `sockets` 一并
/// 借给闭包 `f` 使用。
///
/// 所有需要读写 smoltcp socket 的代码（`bind` / `connect` / `send` / `recv` 等）
/// 都应通过本函数进入临界区；不同 netns 的协议栈彼此独立，但当前仍共用同一把锁。
///
/// 函数内部会先调用 [`init_in`] 做幂等初始化，调用方无需自己保证启动顺序。
pub fn with_sockets_mut_in<R>(
    ns_id: usize,
    f: impl FnOnce(&mut Interface, &mut PacketTapLoopback, &mut SocketSet<'static>) -> R,
) -> R {
    init_in(ns_id);
    let mut net = NET.lock();
    let stack = net.get_mut(&ns_id).unwrap();
    f(&mut stack.iface, &mut stack.dev, &mut stack.sockets)
}

/// 直接向目标 netns 的回环网卡注入一个 IP 报文，并立即推进一次协议栈。
///
/// 用于「从协议栈外部把包送进回环」的场景：先 [`init_in`] 确保栈存在，把报文压入
/// 回环设备的接收队列，再 [`poll_in`] 让 smoltcp 处理该包（必要时唤醒等待的 task）。
/// `observe_rx` 控制这次注入是否计入抓包/统计观察路径。
fn inject_loopback_ip_packet_in_with_observe(ns_id: usize, packet: &[u8], observe_rx: bool) {
    init_in(ns_id);
    {
        let mut net = NET.lock();
        if let Some(stack) = net.get_mut(&ns_id) {
            stack.dev.inject_ip_packet(packet, observe_rx);
        }
    }
    poll_in(ns_id);
}

/// 从 veth 待投递队列中取出一批包并注入对应目标 netns。
///
/// 这里用全局重入标志保证同一时刻只有一个 drain 过程；注入会触发 `poll_in()`，
/// 因此必须避免递归 drain 无界增长。
fn drain_pending_veth_ip_deliveries() {
    if DRAINING_PENDING_VETH
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    for _ in 0..PENDING_VETH_DELIVERY_BUDGET {
        let Some(delivery) = PENDING_VETH_IP.lock().pop_front() else {
            break;
        };
        inject_loopback_ip_packet_in_with_observe(delivery.target_ns_id, &delivery.packet, true);
    }
    DRAINING_PENDING_VETH.store(false, Ordering::Release);
}

/// 将一个 IP 包克隆后挂到目标 netns 的 veth 待投递队列。
///
/// 队列满时直接丢包，模拟设备队列压力下的丢弃行为，同时避免压测把内核堆打爆。
fn enqueue_pending_veth_ip(ns_id: usize, packet: &[u8]) {
    let mut pending = PENDING_VETH_IP.lock();
    if pending.len() >= PENDING_VETH_QUEUE_LIMIT {
        return;
    }
    pending.push_back(PendingIpDelivery {
        target_ns_id: ns_id,
        packet: packet.to_vec(),
    });
}

/// 如果 IPv4 包命中当前 netns 的直连 veth peer，则排队投递到对端 netns。
///
/// 返回 `true` 表示该包已被 veth 路径接管；返回 `false` 表示调用方应继续走
/// 原有回环/协议栈处理。成功接管时同步更新发送端和接收端设备流量统计。
pub(crate) fn queue_veth_ipv4_delivery(ns_id: usize, packet: &[u8]) -> bool {
    let Some((src, dst)) = parse_ipv4_src_dst(packet) else {
        return false;
    };
    let peer = crate::syscall::net::netdev::direct_veth_peer_for_ipv4_destination(
        ns_id,
        0,
        Some(src),
        dst,
    );
    let Some((peer_ns_id, peer)) = peer else {
        return false;
    };

    if let Some(ifindex) =
        crate::syscall::net::netdev::ifindex_by_ipv4_addr_in_namespace(ns_id, src)
    {
        crate::syscall::net::netdev::record_device_traffic_in_namespace(
            ns_id,
            ifindex,
            packet.len(),
            true,
        );
        crate::syscall::net::netdev::record_protocol_packet_in_namespace(ns_id, packet, true);
    }
    crate::syscall::net::netdev::record_device_traffic_in_namespace(
        peer_ns_id,
        peer.ifindex,
        packet.len(),
        false,
    );
    crate::syscall::net::netdev::record_protocol_packet_in_namespace(peer_ns_id, packet, false);
    enqueue_pending_veth_ip(peer_ns_id, packet);
    true
}

/// IPv6 版本的 veth 直连投递逻辑。
///
/// 当前 IPv6 数据面只覆盖本批测试需要的 netns/veth 直连路径；命中 peer 后入队，
/// 未命中则返回 `false` 交还给调用方。
pub(crate) fn queue_veth_ipv6_delivery(ns_id: usize, packet: &[u8]) -> bool {
    let Some((src, dst)) = parse_ipv6_src_dst(packet) else {
        return false;
    };
    let peer = crate::syscall::net::netdev::direct_veth_peer_for_ipv6_destination(
        ns_id,
        0,
        Some(src),
        dst,
    );
    let Some((peer_ns_id, peer)) = peer else {
        return false;
    };

    if let Some(ifindex) =
        crate::syscall::net::netdev::ifindex_by_ipv6_addr_in_namespace(ns_id, src)
    {
        crate::syscall::net::netdev::record_device_traffic_in_namespace(
            ns_id,
            ifindex,
            packet.len(),
            true,
        );
    }
    crate::syscall::net::netdev::record_device_traffic_in_namespace(
        peer_ns_id,
        peer.ifindex,
        packet.len(),
        false,
    );
    enqueue_pending_veth_ip(peer_ns_id, packet);
    true
}

/// 从 IPv4 包头提取源/目的地址，同时做最小包长、版本、IHL 和 total length 校验。
fn parse_ipv4_src_dst(packet: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl > packet.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || total_len > packet.len() {
        return None;
    }
    Some((
        packet[12..16].try_into().ok()?,
        packet[16..20].try_into().ok()?,
    ))
}

/// 从 IPv6 固定头提取源/目的地址，同时校验 payload length 不超过实际包长。
fn parse_ipv6_src_dst(packet: &[u8]) -> Option<([u8; 16], [u8; 16])> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = 40usize.checked_add(payload_len)?;
    if total_len > packet.len() {
        return None;
    }
    Some((
        packet[8..24].try_into().ok()?,
        packet[24..40].try_into().ok()?,
    ))
}

/// 向目标 netns 注入 IP 包，并让观察路径记录这次接收。
pub fn inject_loopback_ip_packet_in(ns_id: usize, packet: &[u8]) {
    inject_loopback_ip_packet_in_with_observe(ns_id, packet, true);
}

/// 向目标 netns 注入 IP 包，但不计入抓包/统计观察路径。
///
/// WireGuard 解封装后的内层包使用该入口，避免同一逻辑包被外层 UDP 和内层 IP
/// 重复计入观察路径。
pub fn inject_loopback_ip_packet_in_silent(ns_id: usize, packet: &[u8]) {
    inject_loopback_ip_packet_in_with_observe(ns_id, packet, false);
}

/// 由 IPv4 地址和端口构造 smoltcp 的 [`IpEndpoint`] 便捷函数。
///
/// 目前 syscall 层暂未直接调用，保留供后续 socket 相关代码复用，
/// 故标注 `#[allow(dead_code)]` 以避免编译告警。
#[allow(dead_code)]
pub fn ip_endpoint_from_v4(ip: Ipv4Address, port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(ip), port)
}
