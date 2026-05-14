mod sendrecv;
mod socket;
mod sockopt;

pub use sendrecv::*;
pub use socket::*;
pub use sockopt::*;

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
use crate::task::manager::pid2process;
use crate::task::processor::{
    block_current_and_run_next, current_files, current_process, current_task,
    suspend_current_and_run_next,
};
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use crate::trap::get_current_token;

pub(super) const AF_UNSPEC: u16 = 0;
pub(super) const AF_UNIX: u16 = 1;
pub(super) const AF_INET: u16 = 2;
pub(super) const AF_NETLINK: u16 = 16;
pub(super) const SOL_IP: usize = 0;

pub(super) const SOCK_STREAM: usize = 1;
pub(super) const SOCK_DGRAM: usize = 2;
pub(super) const SOCK_RAW: usize = 3;
pub(super) const SOCK_SEQPACKET: usize = 5;
pub(super) const SOCK_NONBLOCK: usize = 0x800;
pub(super) const SOCK_CLOEXEC: usize = 0x80000;
pub(super) const O_NONBLOCK: u32 = 0x800;
pub(super) const O_PATH: u32 = 0x200000;
pub(super) const FD_CLOEXEC: u32 = 1;

pub(super) const SOL_SOCKET: usize = 1;
pub(super) const SOL_TCP: usize = 6;
pub(super) const SOL_UDP: usize = 17;
pub(super) const SO_REUSEADDR: usize = 2;
pub(super) const SO_SNDBUF: usize = 7;
pub(super) const SO_RCVBUF: usize = 8;
pub(super) const SO_OOBINLINE: usize = 10;
pub(super) const SO_PEERCRED: usize = 17;
pub(super) const SO_SNDBUFFORCE: usize = 32;
pub(super) const SO_RCVBUFFORCE: usize = 33;
pub(super) const SO_ATTACH_BPF: usize = 50;
pub(super) const MCAST_JOIN_GROUP: usize = 42;
pub(super) const MCAST_LEAVE_GROUP: usize = 45;

pub(super) const MSG_OOB: usize = 0x1;
pub(super) const MSG_PEEK: usize = 0x2;
pub(super) const MSG_WAITALL: usize = 0x100;
pub(super) const MSG_TRUNC: usize = 0x20;
pub(super) const MSG_DONTWAIT: usize = 0x40;
pub(super) const MSG_ERRQUEUE: usize = 0x2000;
pub(super) const MSG_NOSIGNAL: usize = 0x4000;
pub(super) const MSG_MORE: usize = 0x8000;
pub(super) const MSG_WAITFORONE: usize = 0x10000;

pub(super) const UIO_MAXIOV: usize = 1024;
pub(super) const MQ_THREAD_NOTIFY_COOKIE_LEN: usize = 32;

const NLMSG_HDR_LEN: usize = 16;
const NLMSG_ALIGNTO: usize = 4;
const RTA_ALIGNTO: usize = 4;
const RTATTR_HDR_LEN: usize = 4;

const NLM_F_MULTI: u16 = 0x02;

const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_MULTICAST: u32 = 0x1000;

const IFLA_ADDRESS_ATTR: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_OPERSTATE: u16 = 16;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_F_PERMANENT: u8 = 0x80;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;

pub(super) type FileArc = Arc<dyn File + Send + Sync>;
pub(super) type FileWeak = Weak<dyn File + Send + Sync>;
pub(super) type UdpTarget = (smoltcp::wire::Ipv4Address, u16);

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum UnixBoundAddr {
    Path(String),
    Abstract(Vec<u8>),
}

lazy_static! {
    static ref UNIX_BOUND_PATHS: Mutex<BTreeMap<String, FileWeak>> = Mutex::new(BTreeMap::new());
    static ref UNIX_BOUND_ABSTRACT: Mutex<BTreeMap<Vec<u8>, FileWeak>> =
        Mutex::new(BTreeMap::new());
    static ref MSG_MORE_PENDING: Mutex<BTreeMap<usize, PendingMoreState>> =
        Mutex::new(BTreeMap::new());
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct IoVec {
    pub(super) base: usize,
    pub(super) len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MsgHdr {
    pub(super) msg_name: usize,
    pub(super) msg_namelen: u32,
    pub(super) _pad0: u32,
    pub(super) msg_iov: usize,
    pub(super) msg_iovlen: usize,
    pub(super) msg_control: usize,
    pub(super) msg_controllen: usize,
    pub(super) msg_flags: i32,
    pub(super) _pad1: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MMsgHdr {
    pub(super) msg_hdr: MsgHdr,
    pub(super) msg_len: u32,
    pub(super) _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct UserTimespec {
    pub(super) tv_sec: i64,
    pub(super) tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct UCred {
    pub(super) pid: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

struct PendingMoreState {
    data: Vec<u8>,
    udp_target: Option<UdpTarget>,
}

pub(super) struct UnixDatagram {
    pub(super) from: Option<UnixBoundAddr>,
    pub(super) payload: Vec<u8>,
}

pub(super) struct UnixSocketState {
    bound: Option<UnixBoundAddr>,
    listening: bool,
    backlog: usize,
    pending_accept: VecDeque<Arc<UnixSocketFile>>,
    stream_end: Option<Arc<SocketPairEnd>>,
    peer_addr: Option<UnixBoundAddr>,
    peer_cred: Option<UCred>,
    dgram_peer: Option<UnixBoundAddr>,
    pub(super) dgram_queue: VecDeque<UnixDatagram>,
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
    pub(super) fn new(sock_type: usize) -> Self {
        Self {
            sock_type,
            state: Mutex::new(UnixSocketState::new()),
        }
    }

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

    pub(super) fn is_stream_like(&self) -> bool {
        matches!(self.sock_type, SOCK_STREAM | SOCK_SEQPACKET)
    }

    pub(super) fn is_dgram(&self) -> bool {
        self.sock_type == SOCK_DGRAM
    }

    pub(super) fn bound_addr(&self) -> Option<UnixBoundAddr> {
        self.state.lock().bound.clone()
    }

    fn set_bound_addr(&self, addr: UnixBoundAddr) {
        self.state.lock().bound = Some(addr);
    }

    pub(super) fn peer_addr(&self) -> Option<UnixBoundAddr> {
        let st = self.state.lock();
        st.peer_addr.clone().or_else(|| st.dgram_peer.clone())
    }

    pub(super) fn peer_cred(&self) -> Option<UCred> {
        self.state.lock().peer_cred
    }

    fn notify_poll_waiters(&self) {
        let waiters = self.state.lock().poll_waiters.take_wakeups();
        wake_tasks(waiters);
    }

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
            drop(st);
            suspend_current_and_run_next();
        }
    }

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
                if peer_st.pending_accept.len() >= peer_st.backlog {
                    return err(SyscallError::ECONNREFUSED);
                }
                let accepted = Arc::new(UnixSocketFile::new_connected_stream(
                    self.sock_type,
                    server_end,
                    client_bound,
                    Some(client_cred),
                ));
                peer_st.pending_accept.push_back(accepted);
                let wake = peer_st.poll_waiters.take_wakeups();
                drop(peer_st);
                wake_tasks(wake);
            }
            let mut st = self.state.lock();
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
        let mut st = self.state.lock();
        st.dgram_peer = Some(addr.clone());
        st.peer_addr = Some(addr);
        0
    }

    pub(super) fn send_dgram(&self, payload: Vec<u8>, target: Option<UnixBoundAddr>) -> isize {
        if !self.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let (to, from) = {
            let st = self.state.lock();
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

    pub(super) fn recv_dgram(&self) -> UnixDatagram {
        loop {
            let mut st = self.state.lock();
            if let Some(msg) = st.dgram_queue.pop_front() {
                return msg;
            }
            drop(st);
            suspend_current_and_run_next();
        }
    }

    pub(super) fn stream_end(&self) -> Option<Arc<SocketPairEnd>> {
        self.state.lock().stream_end.clone()
    }

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

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

fn align_to(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn read_u16_ne(buf: &[u8], offset: usize) -> Option<u16> {
    (offset + 2 <= buf.len()).then(|| u16::from_ne_bytes([buf[offset], buf[offset + 1]]))
}

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

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SockAddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32, // network byte order
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SockAddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }
    let (parent, name) = trimmed.rsplit_once('/')?;
    let parent = if parent.is_empty() { "/" } else { parent };
    if name.is_empty() {
        return None;
    }
    Some((parent, name))
}

pub(super) fn get_file(fd: usize) -> Result<FileArc, isize> {
    let files = current_files();
    let files = files.lock();
    let Some((file, descriptor_flags)) = files.get_file_and_flags(fd) else {
        return Err(err(SyscallError::EBADF));
    };
    if (descriptor_flags & O_PATH) != 0 {
        return Err(err(SyscallError::EBADF));
    }
    Ok(file)
}

fn get_file_from_process(pid: usize, fd: usize) -> Result<FileArc, isize> {
    let Some(process) = pid2process(pid) else {
        return Err(err(SyscallError::EBADF));
    };
    process
        .files()
        .lock()
        .get_file(fd)
        .ok_or(err(SyscallError::EBADF))
}

pub(crate) fn mq_notify_validate_thread_sockfd(pid: usize, sockfd: usize) -> isize {
    let file = match get_file_from_process(pid, sockfd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_none() {
        return err(SyscallError::EBADF);
    }
    0
}

pub(crate) fn mq_notify_send_thread_event(
    pid: usize,
    sockfd: usize,
    cookie: [u8; MQ_THREAD_NOTIFY_COOKIE_LEN],
    notify_kind: u8,
) -> isize {
    let file = match get_file_from_process(pid, sockfd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let Some(sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() else {
        return err(SyscallError::EBADF);
    };
    sock.enqueue_mq_notify(cookie, notify_kind);
    0
}

fn current_unix_ucred() -> UCred {
    let proc = current_process();
    let inner = proc.borrow_mut();
    UCred {
        pid: proc.pid.0 as u32,
        uid: inner.euid as u32,
        gid: inner.egid as u32,
    }
}

pub(super) fn file_key(file: &FileArc) -> usize {
    Arc::as_ptr(file) as *const () as usize
}

fn take_pending_more(key: usize) -> Option<PendingMoreState> {
    MSG_MORE_PENDING.lock().remove(&key)
}

fn put_pending_more(key: usize, state: PendingMoreState) {
    MSG_MORE_PENDING.lock().insert(key, state);
}

pub(super) fn queue_pending_more_chunk(key: usize, chunk: &[u8], udp_target: Option<UdpTarget>) {
    let mut pending = take_pending_more(key).unwrap_or(PendingMoreState {
        data: Vec::new(),
        udp_target,
    });
    if pending.udp_target.is_none() {
        pending.udp_target = udp_target;
    }
    pending.data.extend_from_slice(chunk);
    put_pending_more(key, pending);
}

pub(super) fn consume_pending_more(
    key: usize,
    payload: Vec<u8>,
) -> (Vec<u8>, bool, Option<UdpTarget>) {
    if let Some(mut pending) = take_pending_more(key) {
        let pending_target = pending.udp_target;
        pending.data.extend_from_slice(&payload);
        (pending.data, true, pending_target)
    } else {
        (payload, false, None)
    }
}

pub(super) fn visible_send_len(sent: usize, user_len: usize, had_pending: bool) -> isize {
    if had_pending {
        user_len as isize
    } else {
        sent as isize
    }
}

pub(super) fn visible_send_result(ret: isize, user_len: usize, had_pending: bool) -> isize {
    if ret < 0 {
        ret
    } else {
        visible_send_len(ret as usize, user_len, had_pending)
    }
}

pub(crate) fn file_supports_poll(file: &Arc<dyn File + Send + Sync>) -> bool {
    file.supports_poll()
}

fn copy_slice_to_user_buffer(buf: UserBuffer, src: &[u8]) -> usize {
    let mut it = buf.into_iter();
    let mut copied = 0usize;
    while copied < src.len() {
        let Some(dst) = it.next() else {
            break;
        };
        // SAFETY: dst is a valid mutable pointer from UserBuffer iterator; src[copied] is in bounds.
        unsafe { *dst = src[copied] };
        copied += 1;
    }
    copied
}

fn copy_user_buffer_to_vec(buf: UserBuffer) -> Vec<u8> {
    let mut data = Vec::with_capacity(buf.len());
    for p in buf.into_iter() {
        // SAFETY: p is a valid pointer from UserBuffer iterator which guarantees page is mapped.
        data.push(unsafe { *p });
    }
    data
}

pub(super) fn parse_sockaddr_in(
    user_ptr: usize,
    len: usize,
) -> Result<(smoltcp::wire::Ipv4Address, u16), isize> {
    if user_ptr == 0 || len < size_of::<SockAddrIn>() {
        return Err(err(SyscallError::EINVAL));
    }
    if len > i32::MAX as usize {
        return Err(err(SyscallError::EINVAL));
    }
    let token = get_current_token();
    let Some(sa) = try_read_user_value(token, user_ptr as *const SockAddrIn) else {
        return Err(err(SyscallError::EFAULT));
    };
    if sa.sin_family != AF_INET {
        if sa.sin_family != 0 {
            return Err(err(SyscallError::EAFNOSUPPORT));
        }
    }
    let port = u16::from_be(sa.sin_port);
    let ip_raw = u32::from_be(sa.sin_addr);
    let ip = smoltcp::wire::Ipv4Address::from_bytes(&ip_raw.to_be_bytes());
    Ok((ip, port))
}

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

fn parse_sockaddr_un(user_ptr: usize, len: usize) -> Result<(bool, Vec<u8>), isize> {
    if user_ptr == 0 || len < size_of::<u16>() {
        return Err(err(SyscallError::EINVAL));
    }
    if len > i32::MAX as usize {
        return Err(err(SyscallError::EINVAL));
    }
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
        let mut name = path[1..].to_vec();
        while matches!(name.last(), Some(0)) {
            name.pop();
        }
        if name.is_empty() {
            return Err(err(SyscallError::EINVAL));
        }
        return Ok((true, name));
    }
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    if end == 0 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok((false, path[..end].to_vec()))
}

pub(super) fn parse_unix_bound_addr(addr: usize, addrlen: usize) -> Result<UnixBoundAddr, isize> {
    let (is_abstract, raw_name) = parse_sockaddr_un(addr, addrlen)?;
    if is_abstract {
        return Ok(UnixBoundAddr::Abstract(raw_name));
    }
    let Ok(path_part) = core::str::from_utf8(&raw_name) else {
        return Err(err(SyscallError::EINVAL));
    };
    let cwd = { current_process().borrow_mut().cwd.clone() };
    let abs = normalize_path(&cwd, path_part);
    Ok(UnixBoundAddr::Path(abs))
}

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
            reg.remove(name);
            Err(err(SyscallError::ENOENT))
        }
    }
}

fn register_unix_bound_socket(addr: &UnixBoundAddr, file: &FileArc) -> isize {
    match addr {
        UnixBoundAddr::Path(path) => {
            let mut reg = UNIX_BOUND_PATHS.lock();
            if let Some(existing) = reg.get(path) {
                if existing.upgrade().is_some() {
                    return err(SyscallError::EADDRINUSE);
                }
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
                reg.remove(name);
            }
            reg.insert(name.clone(), Arc::downgrade(file));
        }
    }
    0
}

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
        if parent.find(name).is_some() {
            return err(SyscallError::EADDRINUSE);
        }
        if parent.create_file(name).is_err() {
            if parent.find(name).is_some() {
                return err(SyscallError::EADDRINUSE);
            }
            return err(SyscallError::EINVAL);
        }
        let reg_result = register_unix_bound_socket(&bound, file);
        if reg_result != 0 {
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

pub(super) fn write_sockaddr_in(
    user_ptr: usize,
    user_len_ptr: usize,
    ip: smoltcp::wire::Ipv4Address,
    port: u16,
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
    let sa = SockAddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: {
            let b = ip.as_bytes();
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_be()
        },
        sin_zero: [0; 8],
    };
    let required = size_of::<SockAddrIn>();
    let copy_len = core::cmp::min(len, required);
    if copy_len > 0 {
        // SAFETY: sa is a stack-local struct with known layout; copy_len <= size_of::<SockAddrIn>().
        let bytes = unsafe {
            core::slice::from_raw_parts((&sa as *const SockAddrIn) as *const u8, copy_len)
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

pub(super) fn read_iovecs(iov_ptr: usize, iovcnt: usize) -> Result<Vec<IoVec>, isize> {
    if iovcnt == 0 {
        return Ok(Vec::new());
    }
    if iovcnt > UIO_MAXIOV {
        return Err(err(SyscallError::EMSGSIZE));
    }
    if iov_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut iovs = Vec::with_capacity(iovcnt);
    for i in 0..iovcnt {
        let ptr = (iov_ptr + i * size_of::<IoVec>()) as *const IoVec;
        let Some(iv) = try_read_user_value::<IoVec>(token, ptr) else {
            return Err(err(SyscallError::EFAULT));
        };
        iovs.push(iv);
    }
    Ok(iovs)
}

pub(super) fn gather_iovecs_data(iovs: &[IoVec]) -> Result<Vec<u8>, isize> {
    let total = iovecs_total_len(iovs)?;
    let token = get_current_token();
    let mut out = vec![0u8; total];
    let mut off = 0usize;
    for iv in iovs {
        if iv.len == 0 {
            continue;
        }
        let end = off + iv.len;
        if try_copy_from_user(token, iv.base as *const u8, &mut out[off..end]).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        off = end;
    }
    Ok(out)
}

pub(super) fn iovecs_total_len(iovs: &[IoVec]) -> Result<usize, isize> {
    iovs.iter()
        .try_fold(0usize, |acc, iv| acc.checked_add(iv.len))
        .ok_or(err(SyscallError::EINVAL))
}

pub(super) fn scatter_iovecs_data(iovs: &[IoVec], data: &[u8]) -> Result<usize, isize> {
    let token = get_current_token();
    let mut off = 0usize;
    for iv in iovs {
        if off >= data.len() {
            break;
        }
        if iv.len == 0 {
            continue;
        }
        let n = core::cmp::min(iv.len, data.len() - off);
        if try_copy_to_user(token, iv.base as *mut u8, &data[off..off + n]).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        off += n;
    }
    Ok(off)
}

pub(super) fn write_msg_name_bytes(msg: &mut MsgHdr, value: &[u8]) -> isize {
    if msg.msg_name == 0 {
        msg.msg_namelen = 0;
        return 0;
    }
    let user_len = msg.msg_namelen as usize;
    if user_len > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    let copy_len = core::cmp::min(user_len, value.len());
    if copy_len > 0 {
        let token = get_current_token();
        if try_copy_to_user(token, msg.msg_name as *mut u8, &value[..copy_len]).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    msg.msg_namelen = value.len() as u32;
    0
}

pub(super) fn write_msg_name_in(
    msg: &mut MsgHdr,
    ip: smoltcp::wire::Ipv4Address,
    port: u16,
) -> isize {
    let sa = SockAddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: {
            let b = ip.as_bytes();
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_be()
        },
        sin_zero: [0; 8],
    };
    // SAFETY: sa is a stack-local struct with known layout; length equals size_of::<SockAddrIn>().
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&sa as *const SockAddrIn) as *const u8,
            size_of::<SockAddrIn>(),
        )
    };
    write_msg_name_bytes(msg, bytes)
}

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

pub(super) fn validate_send_flags(flags: usize) -> isize {
    let known = MSG_OOB | MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE;
    if (flags & !known) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    if (flags & MSG_OOB) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    0
}

pub(super) fn validate_recv_flags(flags: usize) -> isize {
    if (flags & MSG_OOB) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & MSG_ERRQUEUE) != 0 {
        return err(SyscallError::EAGAIN);
    }
    let known = MSG_DONTWAIT
        | MSG_PEEK
        | MSG_ERRQUEUE
        | MSG_OOB
        | MSG_WAITFORONE
        | MSG_WAITALL
        | MSG_NOSIGNAL;
    if (flags & !known) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    0
}

pub(super) fn read_msghdr(user_ptr: usize) -> Result<MsgHdr, isize> {
    if user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    try_read_user_value::<MsgHdr>(token, user_ptr as *const MsgHdr).ok_or(err(SyscallError::EFAULT))
}

pub(super) fn write_mmsghdr_msg_len(user_ptr: usize, idx: usize, msg_len: u32) -> isize {
    let token = get_current_token();
    let base = user_ptr + idx * size_of::<MMsgHdr>();
    let ptr = (base + size_of::<MsgHdr>()) as *mut u32;
    if try_write_user_value(token, ptr, &msg_len).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub(super) fn write_mmsghdr(user_ptr: usize, idx: usize, mmsg: &MMsgHdr) -> isize {
    let token = get_current_token();
    let ptr = (user_ptr + idx * size_of::<MMsgHdr>()) as *mut MMsgHdr;
    if try_write_user_value(token, ptr, mmsg).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}
