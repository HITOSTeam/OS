//! AF_NETLINK socket 实现，模拟 Linux rtnetlink 子集供 glibc/getaddrinfo 使用。
//!
//! 本模块不依赖真实网卡，仅向 user 空间暴露足以让 `getaddrinfo(AI_ADDRCONFIG)` 通过
//! 的最小接口：响应 `RTM_GETLINK`（链路信息）与 `RTM_GETADDR`（地址信息）两类请求，
//! 其余请求一律回 `NLMSG_DONE` 以防 user 端死等。

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::mem::size_of;

use spin::Mutex;

use crate::fs::{File, POLLIN, POLLOUT, PollWaitQueue, wake_tasks};
use crate::mm::{UserBuffer, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::processor::{block_current_and_run_next, current_process, current_task};
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use crate::trap::get_current_token;

use super::*;

// --- netlink 报文头部与对齐 ---
const NLMSG_HDR_LEN: usize = 16; // struct nlmsghdr 固定大小
const NLMSG_ALIGNTO: usize = 4; // 报文整体按 4 字节对齐
const RTA_ALIGNTO: usize = 4; // rtattr TLV 按 4 字节对齐
const RTATTR_HDR_LEN: usize = 4; // struct rtattr 头部：u16 len + u16 type

// --- netlink 消息标志与类型 ---
const NLM_F_MULTI: u16 = 0x02; // 多部分消息标志，最后一条改用 NLMSG_DONE 结尾

const NLMSG_DONE: u16 = 3; // 多部分回复的终止帧
const RTM_NEWLINK: u16 = 16; // 通知：网络接口信息
const RTM_GETLINK: u16 = 18; // 请求：获取网络接口列表
const RTM_NEWADDR: u16 = 20; // 通知：接口地址信息
const RTM_GETADDR: u16 = 22; // 请求：获取接口地址列表

// --- 硬件类型与接口标志（来自 linux/if_arp.h 和 linux/if.h）---
const ARPHRD_ETHER: u16 = 1; // 以太网接口
const ARPHRD_LOOPBACK: u16 = 772; // loopback 接口
const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_MULTICAST: u32 = 0x1000;

// --- rtnetlink TLV 属性类型（来自 linux/if_link.h 和 linux/if_addr.h）---
const IFLA_ADDRESS_ATTR: u16 = 1; // 接口硬件（MAC）地址
const IFLA_IFNAME: u16 = 3; // 接口名称字符串
const IFLA_MTU: u16 = 4; // 最大传输单元
const IFLA_OPERSTATE: u16 = 16; // 运行状态（RFC 2863）
const IFA_ADDRESS: u16 = 1; // 接口地址
const IFA_LOCAL: u16 = 2; // 本地地址（点对点链路有别于目的地址）
const IFA_LABEL: u16 = 3; // 地址所属接口名称
const IFA_F_PERMANENT: u8 = 0x80; // 地址为永久配置（非临时/动态）
const RT_SCOPE_UNIVERSE: u8 = 0; // 全局路由可达范围
const RT_SCOPE_HOST: u8 = 254; // 仅本机可达（loopback 地址使用）

/// `struct sockaddr_nl` 的 Rust 镜像（`#[repr(C)]` 保证内存布局一致）。
///
/// - `nl_family`：地址族，固定为 `AF_NETLINK`
/// - `nl_pad`：填充字节，必须为 0
/// - `nl_pid`：port id，标识 socket 端点；内核端固定为 0，用户端通常为进程 PID
/// - `nl_groups`：组播组位掩码，不使用时置 0
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

// 将 value 向上对齐到 align 的整数倍（align 必须是 2 的幂）。
fn align_to(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

// 从 buf[offset..offset+2] 读取一个主机序 u16，越界时返回 None。
fn read_u16_ne(buf: &[u8], offset: usize) -> Option<u16> {
    (offset + 2 <= buf.len()).then(|| u16::from_ne_bytes([buf[offset], buf[offset + 1]]))
}

// 从 buf[offset..offset+4] 读取一个主机序 u32，越界时返回 None。
fn read_u32_ne(buf: &[u8], offset: usize) -> Option<u32> {
    (offset + 4 <= buf.len()).then(|| {
        u32::from_ne_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    })
}

// 追加一条 rtnetlink TLV(rtattr):`{u16 len, u16 type, payload, 4字节对齐填充}`。
// rtnetlink 报文里 IFLA_*/IFA_* 这些字段都靠这种 TLV 串联;少一个对齐填充字节,
// glibc 解析时会以为后面还有更多 attr 然后越界读 → 死循环或 EAI_FAIL。
fn append_rtattr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = RTATTR_HDR_LEN + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % RTA_ALIGNTO != 0 {
        buf.push(0);
    }
}

// 拼出一条完整的 nlmsghdr + payload 的 netlink 消息,字节序按主机序(netlink 不用网络序)。
// 头部 16 字节:{u32 len, u16 type, u16 flags, u32 seq, u32 pid}。
// `port_id` 写在 pid 位置,user 端用它做 reply 匹配,所以必须等于 user bind 时拿到的 nl_pid。
fn build_nlmsg(msg_type: u16, flags: u16, seq: u32, port_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDR_LEN + payload.len();
    let mut buf = Vec::with_capacity(align_to(len, NLMSG_ALIGNTO));
    buf.extend_from_slice(&(len as u32).to_ne_bytes());
    buf.extend_from_slice(&msg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&port_id.to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % NLMSG_ALIGNTO != 0 {
        buf.push(0);
    }
    buf
}

// 构造一条 lo 的 RTM_NEWLINK 应答(ifinfomsg + IFLA_* 属性)。
// payload 前 16 字节是 ifinfomsg:{u8 family, u8 pad, u16 type=ARPHRD_LOOPBACK,
//   i32 ifindex=1, u32 flags=UP|LOOPBACK|RUNNING, u32 change=~0}。
// 之后挂三个 attr:接口名 "lo"、MTU=64KiB、operstate=UNKNOWN(0)。
fn build_loopback_link(seq: u32, flags: u16, port_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_UNSPEC as u8);
    payload.push(0);
    payload.extend_from_slice(&ARPHRD_LOOPBACK.to_ne_bytes());
    payload.extend_from_slice(&1i32.to_ne_bytes());
    payload.extend_from_slice(&(IFF_UP | IFF_LOOPBACK | IFF_RUNNING).to_ne_bytes());
    payload.extend_from_slice(&u32::MAX.to_ne_bytes());
    append_rtattr(&mut payload, IFLA_IFNAME, b"lo\0");
    append_rtattr(&mut payload, IFLA_MTU, &65536u32.to_ne_bytes());
    append_rtattr(&mut payload, IFLA_OPERSTATE, &[0]);
    build_nlmsg(RTM_NEWLINK, flags, seq, port_id, &payload)
}

// 伪造一个 eth0 link。
// Why: glibc 的 `getaddrinfo(..., AI_ADDRCONFIG)` 在只看到 lo 时判定本机"没有 IPv4
// 网络环境",直接返回 EAI_NONAME。我们没有真实网卡,但 socket 路径其实是 loopback
// 在工作,这里就向 user 撒一个最小的非 loopback 以太网 link(MAC 02:00:00:00:00:01,
// ifindex=2, MTU=1500, operstate=UP),让 AI_ADDRCONFIG 通过。
fn build_ipv4_link(seq: u32, flags: u16, port_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_UNSPEC as u8);
    payload.push(0);
    payload.extend_from_slice(&ARPHRD_ETHER.to_ne_bytes());
    payload.extend_from_slice(&2i32.to_ne_bytes());
    payload
        .extend_from_slice(&(IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST).to_ne_bytes());
    payload.extend_from_slice(&u32::MAX.to_ne_bytes());
    append_rtattr(&mut payload, IFLA_ADDRESS_ATTR, &[0x02, 0, 0, 0, 0, 1]);
    append_rtattr(&mut payload, IFLA_IFNAME, b"eth0\0");
    append_rtattr(&mut payload, IFLA_MTU, &1500u32.to_ne_bytes());
    append_rtattr(&mut payload, IFLA_OPERSTATE, &[6]);
    build_nlmsg(RTM_NEWLINK, flags, seq, port_id, &payload)
}

// 构造 lo 上 127.0.0.1/8 的 RTM_NEWADDR(ifaddrmsg + IFA_* 属性)。
// ifaddrmsg:{u8 family=AF_INET, u8 prefixlen=8, u8 flags, u8 scope=HOST, u32 ifindex=1}。
fn build_loopback_addr(seq: u32, flags: u16, port_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_INET as u8);
    payload.push(8);
    payload.push(IFA_F_PERMANENT);
    payload.push(RT_SCOPE_HOST);
    payload.extend_from_slice(&1u32.to_ne_bytes());
    append_rtattr(&mut payload, IFA_ADDRESS, &[127, 0, 0, 1]);
    append_rtattr(&mut payload, IFA_LOCAL, &[127, 0, 0, 1]);
    append_rtattr(&mut payload, IFA_LABEL, b"lo\0");
    build_nlmsg(RTM_NEWADDR, flags, seq, port_id, &payload)
}

// 与 build_ipv4_link 成对出现:在伪 eth0 上挂一个 10.0.2.15/24 的 universe-scope 地址,
// 让 AI_ADDRCONFIG 能识别成"已经有 IPv4 地址"。地址本身不会真正参与发包,只是被探测。
fn build_ipv4_addr(seq: u32, flags: u16, port_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_INET as u8);
    payload.push(24);
    payload.push(IFA_F_PERMANENT);
    payload.push(RT_SCOPE_UNIVERSE);
    payload.extend_from_slice(&2u32.to_ne_bytes());
    append_rtattr(&mut payload, IFA_ADDRESS, &[10, 0, 2, 15]);
    append_rtattr(&mut payload, IFA_LOCAL, &[10, 0, 2, 15]);
    append_rtattr(&mut payload, IFA_LABEL, b"eth0\0");
    build_nlmsg(RTM_NEWADDR, flags, seq, port_id, &payload)
}

// 一条 multipart netlink 应答必须以 NLMSG_DONE 收尾,user 端的 mnl/libnl/glibc
// 都靠看到 DONE 才会停止 recv 循环。少这一条,getaddrinfo 会永远等下一个包。
fn build_done(seq: u32, port_id: u32) -> Vec<u8> {
    build_nlmsg(NLMSG_DONE, NLM_F_MULTI, seq, port_id, &[])
}

// rtnetlink 应答总调度。
//
// 把 user 一次 sendmsg 写进来的字节流(可能是多条 nlmsghdr 拼起来的批量请求)逐条解析,
// 按 msg_type 给出对应的 multipart 回复;回复全部排队进 socket 的 messages 队列,
// 后续 recvmsg/recvfrom 拿走。当前只识别 glibc resolver / busybox `ip` 真正会发的两类:
//
// - RTM_GETLINK → 回 lo + 伪 eth0 两个 RTM_NEWLINK,再补 NLMSG_DONE
// - RTM_GETADDR → 回 127.0.0.1 + 10.0.2.15 两个 RTM_NEWADDR,再补 NLMSG_DONE
// - 其它类型   → 只回一个 NLMSG_DONE,避免 user 死等
//
// 用 seq / port_id 回填请求头,让 user 端能把 reply 与自己的请求对上号。
// 字节移动按 NLMSG_ALIGNTO 对齐,这样兼容 user 端打包时的 padding。
fn build_route_netlink_replies(request: &[u8], port_id: u32) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    let mut offset = 0usize;
    while offset + NLMSG_HDR_LEN <= request.len() {
        let Some(nlmsg_len) = read_u32_ne(request, offset).map(|v| v as usize) else {
            break;
        };
        if nlmsg_len < NLMSG_HDR_LEN || offset + nlmsg_len > request.len() {
            break;
        }
        let msg_type = read_u16_ne(request, offset + 4).unwrap_or(0);
        let seq = read_u32_ne(request, offset + 8).unwrap_or(0);
        match msg_type {
            RTM_GETLINK => {
                replies.push(build_loopback_link(seq, NLM_F_MULTI, port_id));
                replies.push(build_ipv4_link(seq, NLM_F_MULTI, port_id));
                replies.push(build_done(seq, port_id));
            }
            RTM_GETADDR => {
                replies.push(build_loopback_addr(seq, NLM_F_MULTI, port_id));
                replies.push(build_ipv4_addr(seq, NLM_F_MULTI, port_id));
                replies.push(build_done(seq, port_id));
            }
            _ => replies.push(build_done(seq, port_id)),
        }
        offset += align_to(nlmsg_len, NLMSG_ALIGNTO);
    }
    replies
}

// netlink socket 的核心可变状态。
// `messages` 之前是定长 `[u8; 32]` 数组,只够装一条最短的 NLMSG_DONE。rtnetlink 的
// RTM_NEWLINK / RTM_NEWADDR 通常 64~128 字节,且一次回复有多条,所以改成 `Vec<u8>`
// 的队列:每个元素就是一条完整的 nlmsghdr+payload。
struct NetlinkSocketState {
    /// 本端 netlink 地址（nl_pid 即 port id）。
    /// 由 `bind()` 显式设置，或在第一次 `sendmsg` 时由 `ensure_port_id` 懒分配。
    bound: Option<SockAddrNl>,
    /// 内核已构造好、等待 user 端 `recvmsg` 取走的 netlink 报文队列。
    /// 每个元素是一条完整的 `nlmsghdr + payload`，遵循数据报语义，不可拆分。
    messages: VecDeque<Vec<u8>>,
    /// 阻塞在 `recvmsg` 上的任务列表。
    /// 内核把回复入队后会逐个唤醒，使用 `Weak` 避免循环引用。
    recv_waiters: VecDeque<Weak<TaskControlBlock>>,
    /// `poll`/`select`/`epoll` 等待队列，有消息可读时触发。
    poll_waiters: PollWaitQueue,
}

/// AF_NETLINK 套接字文件对象，模拟 Linux rtnetlink 子集。
///
/// 支持的请求类型：
/// - `RTM_GETLINK`：返回 lo + 伪 eth0 的接口信息
/// - `RTM_GETADDR`：返回 127.0.0.1 + 10.0.2.15 的地址信息
///
/// glibc 的 `getaddrinfo` 内部会通过此接口查询本机地址配置。
pub(crate) struct NetlinkSocketFile {
    /// 受 Mutex 保护的可变状态，包含绑定地址、消息队列和等待者列表。
    state: Mutex<NetlinkSocketState>,
}

impl NetlinkSocketFile {
    /// 创建一个未绑定的 netlink socket，消息队列和等待者列表均为空。
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(NetlinkSocketState {
                bound: None,
                messages: VecDeque::new(),
                recv_waiters: VecDeque::new(),
                poll_waiters: PollWaitQueue::default(),
            }),
        }
    }

    /// 清理等待者列表中已不处于 Blocked 状态的僵尸条目。
    /// 在每次唤醒前调用，防止列表无限增长。
    fn retain_blocked_waiters(waiters: &mut VecDeque<Weak<TaskControlBlock>>) {
        waiters.retain(|w| {
            let Some(task) = w.upgrade() else {
                return false;
            };
            task.borrow_mut().task_status == TaskStatus::Blocked
        });
    }

    /// 将任务加入等待者列表，若已存在则跳过（去重）。
    fn add_waiter_once(
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

    /// 绑定本端 netlink 地址。
    /// `nl_pid == 0` 时自动使用当前进程 PID 作为 port id（Linux 约定）。
    /// 已绑定的 socket 再次 bind 返回 EINVAL。
    pub(super) fn bind_local(&self, addr: SockAddrNl) -> isize {
        if addr.nl_family != AF_NETLINK {
            return err(SyscallError::EAFNOSUPPORT);
        }
        let mut st = self.state.lock();
        if st.bound.is_some() {
            return err(SyscallError::EINVAL);
        }
        st.bound = Some(SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: if addr.nl_pid == 0 {
                current_process().pid.0 as u32
            } else {
                addr.nl_pid
            },
            nl_groups: addr.nl_groups,
        });
        0
    }

    /// 返回本端地址；未绑定时返回全零地址（nl_pid = 0）。
    pub(super) fn local_addr(&self) -> SockAddrNl {
        self.state.lock().bound.unwrap_or(SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        })
    }

    // 内核 netlink 端的地址固定 nl_pid = 0(POSIX/Linux 约定)。
    // recvmsg/recvfrom 在 user 提供 msg_name 时要把"包的来源"回填给 user,user 端的
    // libmnl/glibc 用它来区分这是 kernel 主动发的 reply,还是另一个进程发的 unicast。
    // 不正确地填会让 getaddrinfo 把回复当成无关消息丢弃。
    /// 返回内核侧 netlink 地址（nl_pid 固定为 0）。
    /// `recvmsg` 回填 `msg_name` 时使用，glibc 用此值验证回复来自内核而非其他进程。
    pub(super) fn kernel_addr(&self) -> SockAddrNl {
        SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        }
    }

    /// 取出所有阻塞在 recv 或 poll 上的等待任务，准备唤醒。
    fn wake_readers(st: &mut NetlinkSocketState) -> Vec<Arc<TaskControlBlock>> {
        let mut wake = Vec::new();
        Self::retain_blocked_waiters(&mut st.recv_waiters);
        for waiter in st.recv_waiters.drain(..) {
            if let Some(task) = waiter.upgrade() {
                wake.push(task);
            }
        }
        wake.extend(st.poll_waiters.take_wakeups());
        wake
    }

    /// 将一批报文入队，并唤醒所有等待读取的任务。
    fn enqueue_packets(&self, packets: Vec<Vec<u8>>) {
        if packets.is_empty() {
            return;
        }
        let wake = {
            let mut st = self.state.lock();
            for packet in packets {
                st.messages.push_back(packet);
            }
            Self::wake_readers(&mut st)
        };
        wake_tasks(wake);
    }

    // 给一个未 bind 的 netlink socket 即时分配 port id(用 pid 当默认值)。
    //
    // Why: 很多 user 端(包括 glibc resolver)发请求前从来不调用 bind(),只是
    // socket()+sendmsg。但回复里的 nlmsghdr.pid 必须等于"该 socket 在 kernel 侧
    // 看到的 port id",否则 user 端做的 seq/port 过滤会把我们的 reply 全丢掉,
    // 看起来就是"发请求没回应"。这里在第一次 sendmsg 路径上 lazy 分配,保证回复
    // 一定带着 user 能识别的 port id。
    /// 懒分配 port id：若已绑定则直接返回 nl_pid，否则用当前 PID 自动绑定。
    ///
    /// 保证回复报文中的 `nlmsghdr.pid` 与 user 端过滤条件一致，
    /// 避免 glibc 因 port id 不匹配而丢弃内核回复。
    fn ensure_port_id(&self) -> u32 {
        let mut st = self.state.lock();
        match st.bound {
            Some(addr) => addr.nl_pid,
            None => {
                let port_id = current_process().pid.0 as u32;
                st.bound = Some(SockAddrNl {
                    nl_family: AF_NETLINK,
                    nl_pad: 0,
                    nl_pid: port_id,
                    nl_groups: 0,
                });
                port_id
            }
        }
    }

    // user 通过 sendmsg/write 写入的 netlink 请求最终落到这里。
    //
    // 原 netlink 实现直接丢弃 user 字节,导致 user 端 recvmsg 永远阻塞。这里改成:
    //   1) 解析 user 字节流里所有 nlmsghdr
    //   2) 对每条请求构造对应的 multipart 应答
    //   3) 把所有应答一次性 enqueue 到 messages,并唤醒等在 recvmsg 上的任务
    /// 处理 user 端通过 `sendmsg`/`write` 发来的 netlink 请求。
    ///
    /// 解析字节流中的所有 `nlmsghdr`，为每条请求构造 multipart 应答，
    /// 一次性入队并唤醒阻塞在 `recvmsg` 上的任务。
    pub(super) fn handle_outbound(&self, buf: &[u8]) {
        let port_id = self.ensure_port_id();
        self.enqueue_packets(build_route_netlink_replies(buf, port_id));
    }

    /// 将 POSIX 消息队列通知投递到此 netlink socket。
    ///
    /// `mq_notify` 使用 `SIGEV_THREAD` 时，内核通过此接口把 cookie 写入
    /// user 注册的 netlink socket，user 端线程池读取后触发回调。
    pub(crate) fn enqueue_mq_notify(
        &self,
        mut cookie: [u8; MQ_THREAD_NOTIFY_COOKIE_LEN],
        notify_kind: u8,
    ) {
        cookie[MQ_THREAD_NOTIFY_COOKIE_LEN - 1] = notify_kind;
        let wake = {
            let mut st = self.state.lock();
            st.messages.push_back(cookie.to_vec());
            Self::wake_readers(&mut st)
        };
        wake_tasks(wake);
    }

    // 从 messages 队列里取走(或 peek)一条完整的 netlink 报文。
    //
    // 关键点:netlink 是"数据报"语义,每条 message 必须整条出/整条进,不能像 TCP
    // 那样切片;所以队列元素是 `Vec<u8>`,这里直接 pop 整条。`_len` 由调用者负责
    // 截断,这层不做任何 partial-read。
    //
    // 队列空时:MSG_DONTWAIT → EAGAIN;否则把自己挂进 recv_waiters 然后 block,
    // 等下一次 handle_outbound 入队回复时把自己唤醒。
    /// 从消息队列取出（或 peek）一条完整的 netlink 报文。
    ///
    /// - `MSG_PEEK`：不消费，仅返回队首副本
    /// - `MSG_DONTWAIT`：队列空时立即返回 `EAGAIN`
    /// - 否则：阻塞直到有消息可读
    ///
    /// 截断由调用者（`recvmsg`）负责，此层不做 partial-read。
    pub(super) fn recv_packet(&self, _len: usize, flags: usize) -> Result<Vec<u8>, isize> {
        let peek = (flags & MSG_PEEK) != 0;
        let nonblock = (flags & MSG_DONTWAIT) != 0;
        loop {
            let mut st = self.state.lock();
            let msg = if peek {
                st.messages.front().cloned()
            } else {
                st.messages.pop_front()
            };
            if let Some(msg) = msg {
                drop(st);
                return Ok(msg);
            }
            if nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            let Some(task) = current_task() else {
                return Err(err(SyscallError::EAGAIN));
            };
            Self::add_waiter_once(&mut st.recv_waiters, &task);
            drop(st);
            block_current_and_run_next();
        }
    }

    /// 消息队列非空时返回 `true`，供 `poll`/`epoll` 使用。
    #[allow(dead_code)]
    pub(crate) fn poll_readable(&self) -> bool {
        !self.state.lock().messages.is_empty()
    }

    /// netlink socket 始终可写（内核侧无发送缓冲区限制）。
    #[allow(dead_code)]
    pub(crate) fn poll_writable(&self) -> bool {
        true
    }
}

impl File for NetlinkSocketFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        let len = buf.len();
        if len == 0 {
            return 0;
        }
        match self.recv_packet(len, 0) {
            Ok(msg) => copy_slice_to_user_buffer(buf, &msg[..len.min(msg.len())]),
            Err(_) => 0,
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        let data = copy_user_buffer_to_vec(buf);
        let len = data.len();
        self.handle_outbound(&data);
        len
    }

    fn poll_mask(&self) -> i16 {
        let mut mask = POLLOUT;
        if !self.state.lock().messages.is_empty() {
            mask |= POLLIN;
        }
        mask
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut st = self.state.lock();
        st.poll_waiters.register_waiter(task)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// 从用户空间读取并校验一个 `SockAddrNl`。
///
/// # 参数
/// - `user_ptr`：用户空间 `sockaddr_nl` 指针
/// - `len`：用户传入的地址长度，必须 `>= size_of::<SockAddrNl>()`
///
/// # 错误
/// - `EINVAL`：指针为空或长度不足
/// - `EFAULT`：读取用户内存失败
/// - `EAFNOSUPPORT`：`nl_family` 非零且不等于 `AF_NETLINK`
pub(super) fn parse_sockaddr_nl(user_ptr: usize, len: usize) -> Result<SockAddrNl, isize> {
    if user_ptr == 0 || len < size_of::<SockAddrNl>() {
        return Err(err(SyscallError::EINVAL));
    }
    if len > i32::MAX as usize {
        return Err(err(SyscallError::EINVAL));
    }
    let token = get_current_token();
    let Some(sa) = try_read_user_value(token, user_ptr as *const SockAddrNl) else {
        return Err(err(SyscallError::EFAULT));
    };
    if sa.nl_family != AF_NETLINK {
        if sa.nl_family != 0 {
            return Err(err(SyscallError::EAFNOSUPPORT));
        }
    }
    Ok(sa)
}

/// 将 `SockAddrNl` 写回用户空间，并更新用户提供的长度字段。
///
/// 遵循 `getsockname`/`recvmsg` 的 POSIX 截断语义：若用户缓冲区小于结构体大小，
/// 只复制用户缓冲区能容纳的字节，但长度字段仍回写实际所需的完整大小。
///
/// # 参数
/// - `user_ptr`：目标 `sockaddr_nl` 指针
/// - `user_len_ptr`：指向长度字段（`socklen_t *`）的指针，读入后回写实际长度
/// - `sa`：待写入的地址结构引用
///
/// # 错误
/// - `EFAULT`：任一指针为空或用户内存访问失败
/// - `EINVAL`：用户传入的长度值超出合法范围
pub(super) fn write_sockaddr_nl(user_ptr: usize, user_len_ptr: usize, sa: &SockAddrNl) -> isize {
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
    let required = size_of::<SockAddrNl>();
    let copy_len = core::cmp::min(len, required);
    if copy_len > 0 {
        // SAFETY: sa is a reference to a valid SockAddrNl; copy_len <= size_of::<SockAddrNl>().
        let bytes = unsafe {
            core::slice::from_raw_parts((&*sa as *const SockAddrNl) as *const u8, copy_len)
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
