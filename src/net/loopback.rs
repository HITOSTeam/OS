//! 带「数据包观测」能力的虚拟回环网卡。
//!
//! 与 smoltcp 自带的 [`smoltcp::phy::Loopback`] 相比，本设备在收发路径上插入了
//! 观测钩子 [`crate::syscall::net::observe_loopback_ip_packet_in`]，使流经 `lo`
//! 的每个 IP 报文都能被 AF_PACKET 抓包、网卡/协议流量统计等机制看到，并按
//! network namespace 归属。

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use smoltcp::{
    phy::{
        ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken as SmolRxToken,
        TxToken as SmolTxToken,
    },
    time::Instant,
};

const LOOPBACK_QUEUE_LIMIT: usize = 8192;

// 设备专用包
struct QueuedLoopbackPacket {
    data: Vec<u8>,
    // 是否触发 钩子
    observe_rx: bool,
}

/// 虚拟回环网卡，向 smoltcp 实现 [`Device`] trait，扮演 `lo` 的角色。
///
/// 它不连接任何物理网络，只用一个 FIFO 队列把「发出去」的报文原样当作
/// 「收进来」的报文，从而让本机回环流量（`127.0.0.1`）在 smoltcp 内部闭环。
/// 每个 network namespace 拥有独立的一份实例。
pub(crate) struct PacketTapLoopback {
    /// 所属 network namespace 的 id，仅用于把抓包/观测事件归属到正确的 netns。
    ns_id: usize,
    /// 报文双端 队列：TX 侧写入的帧会排在队尾，RX 侧再从队首取出。
    /// 因为是回环，发送即等于接收，故收发共用同一条队列。
    queue: VecDeque<QueuedLoopbackPacket>,
    /// 链路层介质类型。这里固定为 [`Medium::Ip`]（纯 IP，无以太网头）。
    medium: Medium,
    /// 需要跳过本地回环的 multicast TX 包数量。
    suppress_multicast_loopback: usize,
}

impl PacketTapLoopback {
    /// 创建一块属于 `ns_id` 的空回环网卡，队列初始为空。
    pub(super) fn new(ns_id: usize, medium: Medium) -> Self {
        Self {
            ns_id,
            queue: VecDeque::new(),
            medium,
            suppress_multicast_loopback: 0,
        }
    }

    pub(crate) fn suppress_next_multicast_loopback(&mut self) {
        self.suppress_multicast_loopback = self.suppress_multicast_loopback.saturating_add(1);
    }

    /// 从外部（非 smoltcp 发送路径）直接向回环队列注入一个 IP 报文，
    /// 下次 `receive` 时即可被协议栈取走。供 `inject_loopback_ip_packet_in` 使用。
    pub(super) fn inject_ip_packet(&mut self, packet: &[u8], observe_rx: bool) {
        push_back_bounded(&mut self.queue, QueuedLoopbackPacket {
            data: packet.to_vec(),
            observe_rx,
        });
    }
}

fn push_back_bounded(queue: &mut VecDeque<QueuedLoopbackPacket>, packet: QueuedLoopbackPacket) {
    if queue.len() >= LOOPBACK_QUEUE_LIMIT {
        return;
    }
    queue.push_back(packet);
}

fn push_front_bounded(queue: &mut VecDeque<QueuedLoopbackPacket>, packet: QueuedLoopbackPacket) {
    if queue.len() >= LOOPBACK_QUEUE_LIMIT {
        return;
    }
    queue.push_front(packet);
}

/// 接收令牌：代表「队列里已有一个待消费的报文」。
///
/// smoltcp 的 `Device` 抽象用「令牌」表示一次收/发的许可，真正的数据访问
/// 推迟到 [`SmolRxToken::consume`] 时才发生。
pub(crate) struct PacketTapRxToken {
    /// 所属 netns，用于报文观测归属。
    ns_id: usize,
    /// 本次要交给协议栈处理的报文内容（已从队列取出）。
    buffer: Vec<u8>,
    /// 是否在 RX 消费时上报给 AF_PACKET/raw 和统计层。
    observe_rx: bool,
}

impl SmolRxToken for PacketTapRxToken {
    /// 消费这个接收令牌：先把报文上报给抓包/观测钩子（`is_tx = false`），
    /// 再把可变缓冲交给 smoltcp 解析。
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if self.observe_rx {
            crate::syscall::net::observe_loopback_ip_packet_in(self.ns_id, &self.buffer, false);
        }
        f(&mut self.buffer)
    }
}

/// 发送令牌：代表「可以向回环队列写入一个报文」。
///
/// 持有底层队列的可变借用，`consume` 时由 smoltcp 填充帧内容，随后入队。
pub(crate) struct PacketTapTxToken<'a> {
    /// 所属 netns，用于报文观测归属。
    ns_id: usize,
    /// 回环队列的可变借用；填好的帧会被推入队尾，等待 RX 侧取出。
    queue: &'a mut VecDeque<QueuedLoopbackPacket>,
    /// 发送端通过 `IP_MULTICAST_LOOP=0` 请求跳过本地 multicast 回环。
    suppress_multicast_loopback: &'a mut usize,
}

impl<'a> SmolTxToken for PacketTapTxToken<'a> {
    /// 消费这个发送令牌：分配 `len` 字节缓冲交给 smoltcp 写入帧内容，
    /// 再根据目标路径决定交给 WireGuard、veth，或作为 loopback 包回灌给本 namespace。
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        // smoltcp 在回调里把 TCP/UDP/IP 头和 payload 写进这块缓冲；
        // 回调返回值是 smoltcp 调用者要拿到的结果，后续分发不能改变它。
        let result = f(&mut buffer);

        // WireGuard 是隧道设备：如果这个内层 IP 包匹配到 peer/allowed-ips，
        // 这里会把它封装成外层 UDP 包并投递出去，原始内层包不再进入 lo 队列。
        if crate::syscall::net::wireguard::encapsulate_outbound_ipv4(self.ns_id, &buffer) {
            return result;
        }
        if crate::syscall::net::wireguard::encapsulate_outbound_ipv6(self.ns_id, &buffer) {
            return result;
        }

        // veth 表示包要穿到 peer namespace；投递成功后也不能再本地 loopback 一份。
        if super::queue_veth_ipv4_delivery(self.ns_id, &buffer) {
            return result;
        }
        if super::queue_veth_ipv6_delivery(self.ns_id, &buffer) {
            return result;
        }

        // 没有被隧道或虚拟网卡接管时，这才是普通 lo 发送：
        // 先记录 TX 方向的可观察副作用，再决定是否回灌到 RX 队列。
        crate::syscall::net::observe_loopback_ip_packet_in(self.ns_id, &buffer, true);
        if is_ipv4_multicast_packet(&buffer) && *self.suppress_multicast_loopback > 0 {
            // IP_MULTICAST_LOOP=0 只抑制“自己收回自己发出的 multicast”，
            // TX 统计和抓包观测已经在上面发生。
            *self.suppress_multicast_loopback -= 1;
        } else {
            // loopback 的发送结果就是稍后被同一个 namespace 的 RX 路径取走。
            push_back_bounded(self.queue, QueuedLoopbackPacket {
                data: buffer,
                observe_rx: true,
            });
        }
        result
    }
}

fn is_ipv4_multicast_packet(packet: &[u8]) -> bool {
    packet.len() >= 20 && (packet[0] >> 4) == 4 && (224..=239).contains(&packet[16])
}

impl Device for PacketTapLoopback {
    type RxToken<'a> = PacketTapRxToken;
    type TxToken<'a> = PacketTapTxToken<'a>;

    /// 尝试取出一个待接收报文。队列非空时返回一对令牌：
    /// `RxToken` 携带刚取出的报文，`TxToken` 用于在处理过程中可能产生的回应帧
    /// （如 TCP ACK），smoltcp 要求收发令牌成对出现。队列为空则返回 `None`。
    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        while let Some(packet) = self.queue.pop_front() {
            if let Some(inner_packets) =
                crate::syscall::net::wireguard::handle_inbound_ipv4_packet(self.ns_id, &packet.data)
            {
                for inner in inner_packets.into_iter().rev() {
                    push_front_bounded(&mut self.queue, QueuedLoopbackPacket {
                        data: inner,
                        observe_rx: true,
                    });
                }
                continue;
            }
            let rx = PacketTapRxToken {
                ns_id: self.ns_id,
                buffer: packet.data,
                observe_rx: packet.observe_rx,
            };
            let tx = PacketTapTxToken {
                ns_id: self.ns_id,
                queue: &mut self.queue,
                suppress_multicast_loopback: &mut self.suppress_multicast_loopback,
            };
            return Some((rx, tx));
        }
        None
    }

    /// 申请一个发送令牌。回环设备永远可发送，故总是返回 `Some`。
    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PacketTapTxToken {
            ns_id: self.ns_id,
            queue: &mut self.queue,
            suppress_multicast_loopback: &mut self.suppress_multicast_loopback,
        })
    }

    /// 上报设备能力：MTU 取 IP 包最大值 65535，介质沿用创建时的设置。
    /// Linux loopback 会把本机包当作无需校验和处理；这里也声明 checksum ignored，
    /// 避免 iperf 大 TCP 包在同一个内核里反复计算和验证校验和。
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 65535;
        caps.medium = self.medium;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }
}
