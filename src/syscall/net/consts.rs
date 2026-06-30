//! 网络相关系统调用使用的、与 Linux ABI 兼容的常量集合。
//!
//! 这些常量原先内联在 `net/mod.rs` 中，为减小该文件体积、便于查阅与维护，
//! 统一抽取到本模块；由 `net/mod.rs` 通过 `pub(crate) use consts::*;` 重导出，
//! 因此各子模块（socket / sendrecv / sockopt 等）以及 `crate::syscall::net::*`
//! 路径的引用方式保持不变。
//!
//! 取值严格对应 Linux 头文件（`<bits/socket.h>`、`<asm-generic/socket.h>`、
//! `<linux/if_packet.h>`、`<linux/netlink.h>` 等），修改前请先核对内核定义。

// ── 地址族（AF_*,Address family）常量，对应 Linux <bits/socket.h> ──────────────────────────
/// unspecified
pub(crate) const AF_UNSPEC: u16 = 0;
/// IPC 套接字
pub(crate) const AF_UNIX: u16 = 1;
/// ipv4 地址族
pub(crate) const AF_INET: u16 = 2;
/// ipv6 地址族；当前数据面未实现，仅用于拒绝错误的 netlink IPv6 变更请求。
pub(crate) const AF_INET6: u16 = 10;
// 特殊套接字 ,可以读取网络配置
pub(crate) const AF_NETLINK: u16 = 16;
/// 二层 packet socket，当前用于 ifreq ioctl 兼容。
pub(crate) const AF_PACKET: u16 = 17;
/// vSockets 地址族，对应 Linux AF_VSOCK / PF_VSOCK。
pub(crate) const AF_VSOCK: u16 = 40;

/// Linux `struct sockaddr_storage` 上限；socket syscall 入口先按这个上限校验 addrlen。
pub(crate) const SOCKADDR_STORAGE_SIZE: usize = 128;

// ── 套接字类型（SOCK_*）及创建标志 ───────────────────────────────────────────
pub(crate) const SOCK_STREAM: usize = 1;
pub(crate) const SOCK_DGRAM: usize = 2;
/// 直接处理IP 包 标志
pub(crate) const SOCK_RAW: usize = 3;
/// SCTP 特殊
pub(crate) const SOCK_SEQPACKET: usize = 5;
/// Linux `SOCK_TYPE_MASK`：低 4 位保存真实 socket 类型，高位只允许创建 flag。
pub(crate) const SOCK_TYPE_MASK: usize = 0xf;
/// 以下不是 纯粹的socket 而是 结合使用的标志位(SOCK是创建标志，O 是fcntl设置标志)
/// 创建时即设置 O_NONBLOCK，避免额外的 fcntl 调用
pub(crate) const SOCK_NONBLOCK: usize = 0x800;
/// 创建时即设置 FD_CLOEXEC，防止 fd 泄漏到子进程
pub(crate) const SOCK_CLOEXEC: usize = 0x80000;
pub(crate) const O_NONBLOCK: u32 = 0x800;
/// O_PATH fd 只能用于路径操作，不能进行 I/O，因此对套接字无效
pub(crate) const O_PATH: u32 = 0x200000;
pub(crate) const FD_CLOEXEC: u32 = 1;

// ── setsockopt/getsockopt 的协议层（level）标识 ──────────────────────────────
pub(crate) const SOL_IP: usize = 0;
/// SOL_SOCKET = 1，作用于通用套接字层而非具体协议
pub(crate) const SOL_SOCKET: usize = 1;
/// SOL_PACKET = 263，作用于 AF_PACKET 二层套接字。
pub(crate) const SOL_PACKET: usize = 263;
pub(crate) const SOL_TCP: usize = 6;
pub(crate) const SOL_UDP: usize = 17;
/// Linux `IPPROTO_IPV6`/`SOL_IPV6`.
pub(crate) const IPPROTO_IPV6: usize = 41;
pub(crate) const SOL_IPV6: usize = IPPROTO_IPV6;
/// SOL_UDPLITE = 136，对应 Linux UDP-Lite 协议层选项。
pub(crate) const SOL_UDPLITE: usize = 136;
/// SOL_NETLINK = 270，作用于 AF_NETLINK 控制面套接字。
pub(crate) const SOL_NETLINK: usize = 270;
/// SOL_VSOCK = 287，Linux 也接受 AF_VSOCK 作为 vSockets sockopt level。
pub(crate) const SOL_VSOCK: usize = 287;
pub(crate) const IPPROTO_ICMP: usize = 1;
pub(crate) const IPPROTO_IGMP: usize = 2;
pub(crate) const IPPROTO_TCP: usize = 6;
pub(crate) const IPPROTO_UDP: usize = 17;
pub(crate) const IPPROTO_UDPLITE: usize = 136;
pub(crate) const IPPROTO_RAW: usize = 255;
pub(crate) const IPV4_UDP_MAX_PAYLOAD: usize = 65_507;

pub(crate) const IPV6_V6ONLY: usize = 26;

pub(crate) const SO_VM_SOCKETS_BUFFER_SIZE: usize = 0;
pub(crate) const SO_VM_SOCKETS_BUFFER_MIN_SIZE: usize = 1;
pub(crate) const SO_VM_SOCKETS_BUFFER_MAX_SIZE: usize = 2;
pub(crate) const SO_VM_SOCKETS_CONNECT_TIMEOUT_OLD: usize = 6;
pub(crate) const SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW: usize = 8;
pub(crate) const VMADDR_CID_ANY: u32 = u32::MAX;
pub(crate) const VMADDR_PORT_ANY: u32 = u32::MAX;
pub(crate) const VMADDR_CID_LOCAL: u32 = 1;

pub(crate) const TCP_NODELAY: usize = 1;
pub(crate) const TCP_MAXSEG: usize = 2;
pub(crate) const TCP_CORK: usize = 3;
pub(crate) const TCP_KEEPIDLE: usize = 4;
pub(crate) const TCP_KEEPINTVL: usize = 5;
pub(crate) const TCP_KEEPCNT: usize = 6;
pub(crate) const TCP_INFO: usize = 11;
pub(crate) const UDPLITE_SEND_CSCOV: usize = 10;
pub(crate) const UDPLITE_RECV_CSCOV: usize = 11;

pub(crate) const IP_TOS: usize = 1;
pub(crate) const IP_TTL: usize = 2;
pub(crate) const IP_HDRINCL: usize = 3;
pub(crate) const IP_PKTINFO: usize = 8;
pub(crate) const IP_MTU_DISCOVER: usize = 10;
pub(crate) const IP_RECVERR: usize = 11;
pub(crate) const IP_RECVTTL: usize = 12;
pub(crate) const IP_RECVTOS: usize = 13;
pub(crate) const IP_MTU: usize = 14;
pub(crate) const SO_EE_ORIGIN_LOCAL: u8 = 1;
pub(crate) const SO_EE_ORIGIN_ICMP: u8 = 2;
pub(crate) const IP_PMTUDISC_DONT: i32 = 0;
pub(crate) const IP_PMTUDISC_WANT: i32 = 1;
pub(crate) const IP_PMTUDISC_DO: i32 = 2;
pub(crate) const IP_PMTUDISC_PROBE: i32 = 3;
pub(crate) const IP_PMTUDISC_OMIT: i32 = 5;

// ── SOL_SOCKET 层选项名 ───────────────────────────────────────────────────────
/// 允许复用TIME_WAIT
pub(crate) const SO_REUSEADDR: usize = 2;
pub(crate) const SO_TYPE: usize = 3;
pub(crate) const SO_ERROR: usize = 4;
pub(crate) const SO_DONTROUTE: usize = 5;
pub(crate) const SO_BROADCAST: usize = 6;
/// 设置大小
pub(crate) const SO_SNDBUF: usize = 7;
pub(crate) const SO_RCVBUF: usize = 8;
pub(crate) const SO_KEEPALIVE: usize = 9;
/// 带外数据内联到普通数据流，而非通过独立通道接收
pub(crate) const SO_OOBINLINE: usize = 10;
/// Disable UDP checksum generation. The lightweight stack currently does not
/// model checksum offload state, but Linux accepts the option on UDP sockets.
pub(crate) const SO_NO_CHECK: usize = 11;
/// Socket packet priority. The current stack records no qdisc state, but Linux
/// accepts the control option on raw/IP sockets.
pub(crate) const SO_PRIORITY: usize = 12;
pub(crate) const SO_LINGER: usize = 13;
pub(crate) const SO_BSDCOMPAT: usize = 14;
pub(crate) const SO_REUSEPORT: usize = 15;
/// 接收端请求通过 `SCM_CREDENTIALS` 返回发送方凭证
pub(crate) const SO_PASSCRED: usize = 16;
/// 获取对端进程凭证（pid/uid/gid），仅 Unix 域套接字支持
pub(crate) const SO_PEERCRED: usize = 17;
pub(crate) const SO_RCVLOWAT: usize = 18;
pub(crate) const SO_SNDLOWAT: usize = 19;
/// Receive timeout. 64-bit Linux maps SO_RCVTIMEO to the old number, while
/// time64 ABIs may use the NEW number; both carry `__kernel_sock_timeval`.
pub(crate) const SO_RCVTIMEO_OLD: usize = 20;
pub(crate) const SO_SNDTIMEO_OLD: usize = 21;
/// 将 socket 绑定到指定接口名。
pub(crate) const SO_BINDTODEVICE: usize = 25;
/// 经典 BPF socket filter，tcpdump/libpcap 仍会优先使用这条路径。
pub(crate) const SO_ATTACH_FILTER: usize = 26;
pub(crate) const SO_DETACH_FILTER: usize = 27;
pub(crate) const SO_TIMESTAMP_OLD: usize = 29;
/// 查询 socket 是否处于监听状态。
pub(crate) const SO_ACCEPTCONN: usize = 30;
/// 与 SO_SNDBUF/SO_RCVBUF 的区别：FORCE 变体绕过系统上限，需要 CAP_NET_ADMIN
pub(crate) const SO_SNDBUFFORCE: usize = 32;
pub(crate) const SO_RCVBUFFORCE: usize = 33;
pub(crate) const SO_TIMESTAMPNS_OLD: usize = 35;
pub(crate) const SO_MARK: usize = 36;
/// 查询创建 socket 时确定的协议号与地址族。
pub(crate) const SO_PROTOCOL: usize = 38;
pub(crate) const SO_DOMAIN: usize = 39;
pub(crate) const SO_LOCK_FILTER: usize = 44;
/// Low-latency busy-poll timeout in microseconds, stored per socket.
pub(crate) const SO_BUSY_POLL: usize = 46;
pub(crate) const SO_BPF_EXTENSIONS: usize = 48;
/// 将 eBPF 程序附加到套接字，用于流量过滤
pub(crate) const SO_ATTACH_BPF: usize = 50;
pub(crate) const SO_TIMESTAMP_NEW: usize = 63;
pub(crate) const SO_TIMESTAMPNS_NEW: usize = 64;
pub(crate) const SO_RCVTIMEO_NEW: usize = 66;
pub(crate) const SO_SNDTIMEO_NEW: usize = 67;
pub(crate) const SO_RCVMARK: usize = 75;
pub(crate) const SO_RCVPRIORITY: usize = 82;
pub(crate) const IP_OPTIONS: usize = 4;
pub(crate) const IP_MULTICAST_IF: usize = 32;
pub(crate) const IP_MULTICAST_TTL: usize = 33;
pub(crate) const IP_MULTICAST_LOOP: usize = 34;
pub(crate) const IP_ADD_MEMBERSHIP: usize = 35;
pub(crate) const IP_DROP_MEMBERSHIP: usize = 36;
pub(crate) const IP_UNBLOCK_SOURCE: usize = 37;
pub(crate) const IP_BLOCK_SOURCE: usize = 38;
pub(crate) const IP_ADD_SOURCE_MEMBERSHIP: usize = 39;
pub(crate) const IP_DROP_SOURCE_MEMBERSHIP: usize = 40;
pub(crate) const IP_MSFILTER: usize = 41;
/// IP 组播组加入/离开选项，用于 setsockopt(SOL_IP, MCAST_JOIN_GROUP, ...)
pub(crate) const MCAST_JOIN_GROUP: usize = 42;
pub(crate) const MCAST_BLOCK_SOURCE: usize = 43;
pub(crate) const MCAST_UNBLOCK_SOURCE: usize = 44;
pub(crate) const MCAST_LEAVE_GROUP: usize = 45;
pub(crate) const MCAST_JOIN_SOURCE_GROUP: usize = 46;
pub(crate) const MCAST_LEAVE_SOURCE_GROUP: usize = 47;
pub(crate) const MCAST_MSFILTER: usize = 48;
pub(crate) const MCAST_EXCLUDE: u32 = 0;
pub(crate) const MCAST_INCLUDE: u32 = 1;

// ── SOL_PACKET 层选项 ───────────────────────────────────────────────────────
pub(crate) const PACKET_ADD_MEMBERSHIP: usize = 1;
pub(crate) const PACKET_DROP_MEMBERSHIP: usize = 2;
pub(crate) const PACKET_RX_RING: usize = 5;
pub(crate) const PACKET_STATISTICS: usize = 6;
pub(crate) const PACKET_COPY_THRESH: usize = 7;
pub(crate) const PACKET_AUXDATA: usize = 8;
pub(crate) const PACKET_ORIGDEV: usize = 9;
pub(crate) const PACKET_VERSION: usize = 10;
pub(crate) const PACKET_HDRLEN: usize = 11;
pub(crate) const PACKET_RESERVE: usize = 12;
pub(crate) const PACKET_TX_RING: usize = 13;
pub(crate) const PACKET_VNET_HDR: usize = 15;
pub(crate) const PACKET_FANOUT: usize = 18;
pub(crate) const PACKET_QDISC_BYPASS: usize = 20;
pub(crate) const PACKET_IGNORE_OUTGOING: usize = 23;
pub(crate) const PACKET_VNET_HDR_SZ: usize = 24;
pub(crate) const PACKET_FANOUT_HASH: u32 = 0;
pub(crate) const PACKET_FANOUT_LB: u32 = 1;
pub(crate) const PACKET_FANOUT_CPU: u32 = 2;
pub(crate) const PACKET_FANOUT_ROLLOVER: u32 = 3;
pub(crate) const PACKET_FANOUT_RND: u32 = 4;
pub(crate) const PACKET_FANOUT_QM: u32 = 5;
pub(crate) const PACKET_FANOUT_CBPF: u32 = 6;
pub(crate) const PACKET_FANOUT_EBPF: u32 = 7;
pub(crate) const PACKET_FANOUT_FLAG_ROLLOVER: u32 = 0x1000;
pub(crate) const PACKET_FANOUT_FLAG_UNIQUEID: u32 = 0x2000;
pub(crate) const PACKET_FANOUT_FLAG_IGNORE_OUTGOING: u32 = 0x4000;
pub(crate) const PACKET_FANOUT_FLAG_DEFRAG: u32 = 0x8000;
pub(crate) const PACKET_FANOUT_FLAG_MASK: u32 = PACKET_FANOUT_FLAG_ROLLOVER
    | PACKET_FANOUT_FLAG_UNIQUEID
    | PACKET_FANOUT_FLAG_IGNORE_OUTGOING
    | PACKET_FANOUT_FLAG_DEFRAG;
pub(crate) const PACKET_MR_MULTICAST: u16 = 0;
pub(crate) const PACKET_MR_PROMISC: u16 = 1;
pub(crate) const PACKET_MR_ALLMULTI: u16 = 2;
pub(crate) const PACKET_MR_UNICAST: u16 = 3;
pub(crate) const TPACKET_V1: i32 = 0;
pub(crate) const TPACKET_V2: i32 = 1;
pub(crate) const TPACKET_V3: i32 = 2;

// ── SOL_NETLINK 层选项 ───────────────────────────────────────────────────────
pub(crate) const NETLINK_ADD_MEMBERSHIP: usize = 1;
pub(crate) const NETLINK_DROP_MEMBERSHIP: usize = 2;
pub(crate) const NETLINK_PKTINFO: usize = 3;
pub(crate) const NETLINK_BROADCAST_ERROR: usize = 4;
pub(crate) const NETLINK_NO_ENOBUFS: usize = 5;
pub(crate) const NETLINK_LISTEN_ALL_NSID: usize = 8;
pub(crate) const NETLINK_CAP_ACK: usize = 10;
pub(crate) const NETLINK_EXT_ACK: usize = 11;
pub(crate) const NETLINK_GET_STRICT_CHK: usize = 12;

// ── sendmsg/recvmsg flags ────────────────────────────────────────────────────
/// 带外（紧急）数据标志
pub(crate) const MSG_OOB: usize = 0x1;
/// 窥视缓冲区内容而不消耗数据
pub(crate) const MSG_PEEK: usize = 0x2;
/// 发送时绕过普通路由表；RAW IPv4 路径会按链路直连语义消费该标志。
pub(crate) const MSG_DONTROUTE: usize = 0x4;
/// control message 缓冲区不足时由 recvmsg 返回。
pub(crate) const MSG_CTRUNC: usize = 0x8;
/// 面向记录协议的记录结束标志；TCP/UDP 路径可忽略。
pub(crate) const MSG_EOR: usize = 0x80;
pub(crate) const MSG_WAITALL: usize = 0x100;
/// recvmsg 返回实际数据长度而非截断后的长度
pub(crate) const MSG_TRUNC: usize = 0x20;
pub(crate) const MSG_DONTWAIT: usize = 0x40;
/// 确认邻居/路由路径有效；IPv4 UDP/RAW 发送路径会刷新邻居表。
pub(crate) const MSG_CONFIRM: usize = 0x800;
/// 读取错误队列中的异步错误（如 ICMP 不可达），而非正常数据
pub(crate) const MSG_ERRQUEUE: usize = 0x2000;
/// 发送端请求不因对端未处理 SIGPIPE 而终止进程
pub(crate) const MSG_NOSIGNAL: usize = 0x4000;
/// 提示内核后续还有更多数据，可与当前数据合并（类似 TCP_CORK）
pub(crate) const MSG_MORE: usize = 0x8000;
/// recvmmsg 专用：收到第一条消息后立即返回，不再等待后续消息
pub(crate) const MSG_WAITFORONE: usize = 0x10000;
/// recvmsg flag: received file descriptors are installed with FD_CLOEXEC.
pub(crate) const MSG_CMSG_CLOEXEC: usize = 0x4000_0000;

/// scatter/gather I/O 的最大 iovec 数量上限，与 Linux 保持一致
pub(crate) const UIO_MAXIOV: usize = 1024;
/// mq_notify SIGEV_THREAD 模式下，通知 cookie 的固定字节长度
pub(crate) const MQ_THREAD_NOTIFY_COOKIE_LEN: usize = 32;

/// Linux `struct sockaddr_ll` 中硬件地址字段（`sll_addr`）的偏移量，
/// 即结构体到 `sll_addr` 之前所有定长字段的累计大小。
pub(crate) const SOCKADDR_LL_ADDR_OFFSET: usize = 12;
