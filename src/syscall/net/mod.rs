/// 网络相关系统调用的公共基础层。
///
/// 本模块负责：
/// - 汇聚并重导出各子模块的系统调用实现（socket / sendrecv / sockopt）
/// - 定义与 Linux ABI 兼容的常量（地址族、套接字类型、选项名、消息标志）
/// - 提供在内核态与用户态之间安全传递套接字地址、iovec、msghdr 的辅助函数
/// - 为消息队列异步通知（mq_notify SIGEV_THREAD）提供跨进程套接字操作接口
pub(crate) mod cbpf;
mod consts;
pub(crate) mod netdev;
mod netlink;
mod sendrecv;
mod socket;
mod sockopt;
mod unix;
pub(crate) mod wireguard;
mod wireguard_crypto;

pub(crate) use consts::*;

use self::netlink::{
    NetlinkSender, NetlinkSocketFile, SockAddrNl, parse_sockaddr_nl_connect,
    parse_sockaddr_nl_kernel_peer, write_sockaddr_nl,
};
use self::unix::{
    UnixSocketFile, bind_unix_socket, parse_unix_bound_addr, read_sockaddr_un_family,
    write_msg_name_un, write_sockaddr_un,
};

pub use sendrecv::*;
pub use socket::*;
pub use sockopt::*;

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::File;
use crate::mm::{
    UserBuffer, try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value,
};
use crate::syscall::error::{SyscallError, err};
use crate::task::manager::pid2process;
use crate::task::processor::current_files;
use crate::trap::get_current_token;

static NEXT_SOCKET_INODE: AtomicU64 = AtomicU64::new(100_000);

lazy_static! {
    static ref PENDING_NET_NAMESPACE_CLEANUP: Mutex<BTreeSet<usize>> = Mutex::new(BTreeSet::new());
}

pub(crate) fn alloc_socket_inode() -> u64 {
    NEXT_SOCKET_INODE.fetch_add(1, Ordering::Relaxed)
}

/// Queue a teardown retry outside socket Drop/registry lock contexts.
pub(crate) fn queue_net_namespace_cleanup(ns_id: usize) {
    if ns_id != 0 {
        PENDING_NET_NAMESPACE_CLEANUP.lock().insert(ns_id);
    }
}

/// Drain one deferred namespace teardown from the idle cleanup worker.
pub(crate) fn drain_pending_net_namespace_cleanup() {
    let ns_id = {
        let mut pending = PENDING_NET_NAMESPACE_CLEANUP.lock();
        let ns_id = pending.iter().next().copied();
        if let Some(ns_id) = ns_id {
            pending.remove(&ns_id);
        }
        ns_id
    };
    if let Some(ns_id) = ns_id {
        cleanup_net_namespace_if_unused(ns_id);
    }
}

pub(crate) fn cleanup_net_namespace_if_unused(ns_id: usize) {
    if !crate::fs::try_begin_net_namespace_cleanup(ns_id) {
        return;
    }
    crate::fs::cleanup_net_socket_namespace(ns_id);
    socket::cleanup_net_namespace(ns_id);
    unix::cleanup_net_namespace(ns_id);
    NetlinkSocketFile::cleanup_net_namespace(ns_id);
    netdev::cleanup_net_namespace(ns_id);
    crate::net::cleanup_namespace(ns_id);
    crate::fs::finish_net_namespace_cleanup(ns_id);
}

/// 套接字层记录的一个时间戳（秒 + 纳秒），用于 `SO_TIMESTAMP*` 选项返回收包时刻。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketTimestamp {
    pub(crate) sec: i64,
    pub(crate) nsec: i64,
}

/// IPv4 套接字错误队列（`MSG_ERRQUEUE`）中的一条条目，对应 Linux `sock_extended_err`。
///
/// 当启用 `IP_RECVERR` 后，本机产生的或 ICMP 反馈的错误会以此结构入队，
/// 供 `recvmsg(MSG_ERRQUEUE)` 读取。`offender` 为触发错误的对端地址/端口（可选），
/// `payload` 为随错误一同返回的原始数据片段。
#[derive(Clone, Debug)]
pub(crate) struct Ipv4ErrorQueueEntry {
    pub(crate) errno: u32,
    pub(crate) origin: u8,
    pub(crate) ty: u8,
    pub(crate) code: u8,
    pub(crate) info: u32,
    pub(crate) data: u32,
    pub(crate) offender: Option<([u8; 4], u16)>,
    pub(crate) payload: Vec<u8>,
}

impl Ipv4ErrorQueueEntry {
    /// 构造一条「本地来源」（`SO_EE_ORIGIN_LOCAL`）的错误条目，仅带 errno。
    pub(crate) fn local(errno: i32) -> Self {
        Self::local_with_info(errno, 0, None, Vec::new())
    }

    /// 构造一条本地来源错误条目，可附带 `info`（如 MTU 值）、触发方地址与负载。
    ///
    /// `errno` 会被规整为非负值后存为 `u32`，与 Linux 错误队列字段语义一致。
    pub(crate) fn local_with_info(
        errno: i32,
        info: u32,
        offender: Option<([u8; 4], u16)>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            errno: errno.max(0) as u32,
            origin: SO_EE_ORIGIN_LOCAL,
            ty: 0,
            code: 0,
            info,
            data: 0,
            offender,
            payload,
        }
    }
}

/// 套接字时间戳模式，对应 `SO_TIMESTAMP(NS)` 新旧两套 ABI 的取值组合。
///
/// `*Old`/`*New` 区分 32 位 time_t 与 time64 ABI；`Timeval` 用秒+微秒、
/// `Timespec` 用秒+纳秒。`Off` 表示未开启时间戳。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SocketTimestampMode {
    #[default]
    Off,
    TimevalOld,
    TimespecOld,
    TimevalNew,
    TimespecNew,
}

impl SocketTimestamp {
    /// 取当前 CLOCK_REALTIME 时刻作为时间戳。
    pub(crate) fn now() -> Self {
        let (sec, nsec) = crate::syscall::time_sys::realtime_now_timespec();
        Self { sec, nsec }
    }
}

/// 判断给定文件对象是否为任意一种套接字（INET/UnixPair/Unix/Netlink/Packet/Raw）。
///
/// 套接字专用的系统调用（如 `getsockopt`、`bind`）入口先用它过滤掉普通文件 fd。
pub(crate) fn is_socket_file(file: &(dyn File + Send + Sync)) -> bool {
    file.as_any()
        .downcast_ref::<crate::fs::NetSocketFile>()
        .is_some()
        || file
            .as_any()
            .downcast_ref::<crate::fs::SocketPairEnd>()
            .is_some()
        || file.as_any().downcast_ref::<UnixSocketFile>().is_some()
        || file.as_any().downcast_ref::<NetlinkSocketFile>().is_some()
        || file.as_any().downcast_ref::<PacketSocketFile>().is_some()
        || file.as_any().downcast_ref::<RawSocketFile>().is_some()
        || file.as_any().downcast_ref::<VsockSocketFile>().is_some()
}

/// 返回该套接字最近一次记录的收包时间戳（若未开启时间戳或类型不支持则为 `None`）。
///
/// 按套接字具体类型向下转型后转发到各自实现；Netlink 不携带数据时间戳，故不在列。
pub(crate) fn socket_last_timestamp(file: &(dyn File + Send + Sync)) -> Option<SocketTimestamp> {
    if let Some(sock) = file.as_any().downcast_ref::<crate::fs::NetSocketFile>() {
        return sock.socket_timestamp();
    }
    if let Some(sock) = file.as_any().downcast_ref::<crate::fs::SocketPairEnd>() {
        return sock.socket_timestamp();
    }
    if let Some(sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        return sock.socket_timestamp();
    }
    if let Some(sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        return sock.socket_timestamp();
    }
    if let Some(sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        return sock.socket_timestamp();
    }
    None
}

/// 查询套接字当前的时间戳模式；不支持时间戳的类型一律返回 [`SocketTimestampMode::Off`]。
pub(crate) fn socket_timestamp_mode(file: &(dyn File + Send + Sync)) -> SocketTimestampMode {
    if let Some(sock) = file.as_any().downcast_ref::<crate::fs::NetSocketFile>() {
        return sock.timestamp_mode();
    }
    if let Some(sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        return sock.timestamp_mode();
    }
    if let Some(sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        return sock.timestamp_mode();
    }
    SocketTimestampMode::Off
}

/// 套接字上的 `write(2)` 走与 `sendto(2)` 相同的发送路径。
///
/// 这样数据报套接字才能按协议返回错误，并且能发送零长度数据包。
pub(crate) fn socket_write_uses_sendto(file: &(dyn File + Send + Sync)) -> bool {
    file.as_any()
        .downcast_ref::<crate::fs::NetSocketFile>()
        .is_some()
        || file
            .as_any()
            .downcast_ref::<crate::fs::SocketPairEnd>()
            .is_some()
        || file.as_any().downcast_ref::<UnixSocketFile>().is_some()
        || file.as_any().downcast_ref::<NetlinkSocketFile>().is_some()
        || file.as_any().downcast_ref::<PacketSocketFile>().is_some()
        || file.as_any().downcast_ref::<RawSocketFile>().is_some()
        || file.as_any().downcast_ref::<VsockSocketFile>().is_some()
}

/// 套接字上的 `read(2)` 对齐 Linux `sock_read_iter()`，复用接收路径。
///
/// 这样 fd 标志、待处理错误和数据包截断规则都能与 `recvfrom(2)` 保持一致。
pub(crate) fn socket_read_uses_recvfrom(file: &(dyn File + Send + Sync)) -> bool {
    file.as_any()
        .downcast_ref::<crate::fs::NetSocketFile>()
        .is_some()
        || file
            .as_any()
            .downcast_ref::<crate::fs::SocketPairEnd>()
            .is_some()
        || file.as_any().downcast_ref::<UnixSocketFile>().is_some()
        || file.as_any().downcast_ref::<NetlinkSocketFile>().is_some()
        || file.as_any().downcast_ref::<PacketSocketFile>().is_some()
        || file.as_any().downcast_ref::<RawSocketFile>().is_some()
        || file.as_any().downcast_ref::<VsockSocketFile>().is_some()
}

/// 判断 `socket(AF_INET, SOCK_RAW, protocol)` 请求的协议号是否受支持。
///
/// 显式实现的协议（ICMP/IGMP/TCP/UDP/RAW）直接放行；其余小于 `IPPROTO_RAW`(255)
/// 的协议号按 Linux 行为也接受（内核创建 raw socket 时不预先拒绝未知协议）。
pub(super) fn raw_protocol_supported(protocol: usize) -> bool {
    protocol != 0
        && (matches!(
            protocol,
            IPPROTO_ICMP | IPPROTO_IGMP | IPPROTO_TCP | IPPROTO_UDP | IPPROTO_RAW
        ) || protocol < IPPROTO_RAW)
}

/// 内核内部传递文件对象的类型别名，要求可跨线程共享（Send + Sync）
pub(super) type FileArc = Arc<dyn File + Send + Sync>;

/// Unix 套接字控制消息中的 `SCM_RIGHTS` 载荷。
///
/// Linux 传递的是打开文件描述对象；这里用 `Arc<File>` 克隆同一个内核文件对象，
/// 接收端再安装成新的 fd，从而保持偏移、socket 状态等共享语义。
#[derive(Clone)]
pub(crate) struct ScmRights {
    files: Vec<Arc<dyn File + Send + Sync>>,
}

impl ScmRights {
    /// 用一组待传递的文件对象构造 `SCM_RIGHTS` 载荷。
    pub(crate) fn new(files: Vec<Arc<dyn File + Send + Sync>>) -> Self {
        Self { files }
    }

    /// 待传递的文件个数。
    pub(crate) fn len(&self) -> usize {
        self.files.len()
    }

    /// 是否不携带任何文件。
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// 遍历待传递的文件对象。
    pub(crate) fn iter(&self) -> core::slice::Iter<'_, Arc<dyn File + Send + Sync>> {
        self.files.iter()
    }
}

/// 与 Linux `struct iovec` ABI 兼容的分散/聚合缓冲区描述符。
///
/// `base` 为用户空间虚拟地址，`len` 为字节数。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct IoVec {
    pub(super) base: usize,
    pub(super) len: usize,
}

/// 与 Linux `struct msghdr` ABI 兼容的消息头，用于 sendmsg/recvmsg。
///
/// 字段布局严格按照 64 位 Linux ABI，两处显式填充字段（`_pad0`、`_pad1`）
/// 是为了匹配 C 编译器的对齐行为，不携带语义。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MsgHdr {
    /// 目标/来源套接字地址的用户空间指针（发送时为目标地址，接收时由内核填充来源地址）
    pub(super) msg_name: usize,
    /// `msg_name` 所指缓冲区的字节长度；recvmsg 返回时内核将其更新为实际地址长度
    pub(super) msg_namelen: u32,
    pub(super) _pad0: u32,
    /// 指向用户空间 `iovec` 数组的指针
    pub(super) msg_iov: usize,
    pub(super) msg_iovlen: usize,
    /// 辅助数据（控制消息）缓冲区的用户空间指针
    pub(super) msg_control: usize,
    pub(super) msg_controllen: usize,
    /// 接收时由内核填充的标志位（如 MSG_TRUNC、MSG_CTRUNC）
    pub(super) msg_flags: i32,
    pub(super) _pad1: i32,
}

/// 与 Linux `struct mmsghdr` ABI 兼容的批量消息头，用于 sendmmsg/recvmmsg。
///
/// `msg_len` 在 recvmmsg 返回时由内核填写，表示本条消息实际接收到的字节数。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MMsgHdr {
    pub(super) msg_hdr: MsgHdr,
    /// 本条消息实际传输的字节数（由内核在调用返回时写入）
    pub(super) msg_len: u32,
    pub(super) _pad: u32,
}

/// 与 Linux `struct timespec` ABI 兼容的用户空间时间戳，用于超时参数传递。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct UserTimespec {
    pub(super) tv_sec: i64,
    pub(super) tv_nsec: i64,
}

/// 套接字对端进程凭证，对应 `SO_PEERCRED` 选项返回的 `struct ucred`。
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct UCred {
    pub(super) pid: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

impl UCred {
    /// 取当前进程的有效凭证（pid/euid/egid），用于 `SO_PEERCRED`。
    pub(crate) fn current() -> Self {
        let proc = crate::task::processor::current_process();
        let inner = proc.borrow_mut();
        Self {
            pid: proc.pid.0 as u32,
            uid: inner.euid as u32,
            gid: inner.egid as u32,
        }
    }

    /// 取当前进程的发送凭证（pid/uid/gid），用于自动生成 `SCM_CREDENTIALS`。
    pub(crate) fn current_scm() -> Self {
        let proc = crate::task::processor::current_process();
        let inner = proc.borrow_mut();
        Self {
            pid: proc.pid.0 as u32,
            uid: inner.uid as u32,
            gid: inner.gid as u32,
        }
    }
}

/// 一次逻辑发送所携带的 Unix 套接字辅助数据（控制消息）。
///
/// 可同时携带传递的文件描述符（`SCM_RIGHTS`）与发送方凭证（`SCM_CREDENTIALS`）。
#[derive(Clone, Default)]
pub(crate) struct ScmControl {
    pub(crate) rights: Option<ScmRights>,
    pub(crate) credentials: Option<UCred>,
}

impl ScmControl {
    /// 是否携带至少一个待传递的文件描述符。
    pub(crate) fn has_rights(&self) -> bool {
        self.rights
            .as_ref()
            .is_some_and(|rights| !rights.is_empty())
    }

    /// 是否既无可传递的 fd 也无凭证（即无需附带任何控制消息）。
    pub(crate) fn is_empty(&self) -> bool {
        !self.has_rights() && self.credentials.is_none()
    }

    /// 若发送侧规则要求携带凭证且尚未填充，则补上当前进程凭证。
    pub(crate) fn ensure_credentials_if(&mut self, needed: bool) {
        if needed && self.credentials.is_none() {
            self.credentials = Some(UCred::current_scm());
        }
    }

    /// 取走（move）非空的 `SCM_RIGHTS`，用于接收端安装这些 fd。
    pub(crate) fn take_rights(&mut self) -> Option<ScmRights> {
        self.rights.take().filter(|rights| !rights.is_empty())
    }

    /// 合并另一份控制数据：fd 列表追加合并，凭证缺省时采用对方的。
    pub(crate) fn merge_from(&mut self, mut other: Self) {
        if let Some(rights) = other.rights.take().filter(|rights| !rights.is_empty()) {
            if let Some(existing) = self.rights.as_mut() {
                existing.files.extend(rights.files);
            } else {
                self.rights = Some(rights);
            }
        }
        if self.credentials.is_none() {
            self.credentials = other.credentials;
        }
    }

    /// 返回去掉凭证后的副本（仅保留 fd 传递部分）。
    pub(crate) fn without_credentials(mut self) -> Self {
        self.credentials = None;
        self
    }

    /// 控制消息是否会被当前接收端实际暴露给用户。
    pub(crate) fn visible_for_passcred(&self, passcred: bool) -> bool {
        self.has_rights() || (passcred && self.credentials.is_some())
    }
}

/// Packet/RAW 套接字上随单个包传播的发送元数据。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PacketMetadata {
    pub(crate) mark: u32,
    pub(crate) priority: u32,
    pub(crate) orig_ifindex: i32,
}

/// 与 Linux `struct sockaddr_in` ABI 兼容的 IPv4 套接字地址。
///
/// 注意：`sin_port` 和 `sin_addr` 均以**网络字节序**存储，读写时需做字节序转换。
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SockAddrIn {
    sin_family: u16,
    sin_port: u16, // 网络字节序
    sin_addr: u32, // 网络字节序
    sin_zero: [u8; 8],
}

/// 与 Linux `struct sockaddr_in6` ABI 兼容的 IPv6 套接字地址。
///
/// 当前内核没有完整 IPv6 数据面，只消费/返回 IPv4-mapped IPv6 地址，
/// 以兼容 Linux 双栈套接字的常见控制流。
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SockAddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

/// 与 Linux `struct sockaddr_ll` ABI 兼容的 packet 套接字地址。
///
/// `sll_protocol` 与 Linux 一样保持网络字节序；AF_PACKET 的 `protocol`
/// 参数也按原始 `__be16` 值保存。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct SockAddrLl {
    pub(super) sll_family: u16,
    pub(super) sll_protocol: u16,
    pub(super) sll_ifindex: i32,
    pub(super) sll_hatype: u16,
    pub(super) sll_pkttype: u8,
    pub(super) sll_halen: u8,
    pub(super) sll_addr: [u8; 8],
}

/// `read_sockaddr_in` 的解析结果：已转为主机字节序的 IPv4 地址与端口，
/// 外加原始的地址族 `family` 和用户传入长度 `len`（供上层做进一步的 ABI 校验）。
#[derive(Clone, Copy)]
pub(super) struct ParsedSockAddrIn {
    pub(super) family: u16,
    pub(super) ip: smoltcp::wire::IpAddress,
    pub(super) port: u16,
    pub(super) len: usize,
}

/// 从当前进程的文件描述符表中获取指定 fd 对应的文件对象。
///
/// O_PATH fd 在 Linux 语义下不能执行实际 I/O，因此视为无效套接字 fd 返回 EBADF。
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

/// 从指定 PID 进程的文件描述符表中获取文件对象。
///
/// 用于跨进程操作场景（如 mq_notify），调用者须确保目标进程在调用期间不会退出。
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

/// 验证指定进程的 fd 是否为有效的 Netlink 套接字，用于 mq_notify SIGEV_THREAD 模式的前置检查。
///
/// mq_notify 的 SIGEV_THREAD 实现需要将通知投递到用户指定的线程，该线程通过
/// 一个 Netlink 套接字与内核通信，因此必须确认 fd 指向 NetlinkSocketFile。
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

/// 向指定进程的 Netlink 套接字投递消息队列通知事件。
///
/// 在 mq_notify SIGEV_THREAD 路径上，由消息队列子系统在消息到达时调用此函数，
/// 将 `cookie`（标识本次通知的上下文令牌）和 `notify_kind` 写入目标套接字的接收队列，
/// 由用户态线程从套接字读取并触发相应的回调。
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

/// 将内核侧切片 `src` 写入用户空间 `UserBuffer`，返回实际写入字节数。
///
/// `UserBuffer` 的 copy API 负责跨越不连续的物理页，并把每次物理页访问限制在
/// 页级访问锁保护的短作用域内。
fn copy_slice_to_user_buffer(mut buf: UserBuffer, src: &[u8]) -> usize {
    buf.copy_from_slice(src)
}

/// 将用户空间 `UserBuffer` 的内容读取到内核堆分配的 `Vec<u8>` 中。
///
/// 同 `copy_slice_to_user_buffer`，通过受控 copy API 处理跨页缓冲区。
fn copy_user_buffer_to_vec(buf: UserBuffer) -> Vec<u8> {
    buf.to_vec()
}

/// 从用户空间读取 `sockaddr_in` 并解析为内核使用的 IPv4 地址和端口。
///
/// 按 Linux `move_addr_to_kernel()` + IPv4 层校验顺序处理：
/// 先根据用户提供的长度触碰地址内存，坏地址返回 EFAULT；之后长度不足才返回 EINVAL。
/// `sin_family` 为 0 时按 AF_INET 静默处理，与 raw 套接字的兼容路径一致。
/// 端口和地址均以网络字节序存储，此处转换为主机字节序后再返回。
pub(super) fn read_sockaddr_in(user_ptr: usize, len: usize) -> Result<ParsedSockAddrIn, isize> {
    if len > SOCKADDR_STORAGE_SIZE {
        return Err(err(SyscallError::EINVAL));
    }
    if len != 0 && user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let mut storage = [0u8; SOCKADDR_STORAGE_SIZE];
    let token = get_current_token();
    if len > 0 {
        if try_copy_from_user(token, user_ptr as *const u8, &mut storage[..len]).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
    }
    if len < size_of::<u16>() {
        return Err(err(SyscallError::EINVAL));
    }
    let family = unsafe { core::ptr::read_unaligned(storage.as_ptr() as *const u16) };
    if len < size_of::<SockAddrIn>() {
        return Ok(ParsedSockAddrIn {
            family,
            ip: smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::UNSPECIFIED),
            port: 0,
            len,
        });
    }
    // SAFETY: `storage` 至少包含完整 sockaddr_in，但字节数组只有 u8 对齐。
    // 使用 read_unaligned 符合 C ABI 的按字节复制语义。
    let sa = unsafe { core::ptr::read_unaligned(storage.as_ptr() as *const SockAddrIn) };
    let port = u16::from_be(sa.sin_port);
    let ip_raw = u32::from_be(sa.sin_addr);
    let ip = smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_bytes(
        &ip_raw.to_be_bytes(),
    ));
    Ok(ParsedSockAddrIn {
        family: sa.sin_family,
        ip,
        port,
        len,
    })
}

/// 读取并校验 `sockaddr_in`，返回 IPv4 地址与端口（主机字节序）。
///
/// 在 [`read_sockaddr_in`] 基础上追加 IPv4 专用校验：长度必须足够容纳完整
/// `sockaddr_in`（否则 EINVAL），地址族只接受 `AF_INET`/`AF_UNSPEC`（否则 EAFNOSUPPORT）。
pub(super) fn parse_sockaddr_in(
    user_ptr: usize,
    len: usize,
) -> Result<(smoltcp::wire::Ipv4Address, u16), isize> {
    let sa = read_sockaddr_in(user_ptr, len)?;
    if sa.len < size_of::<SockAddrIn>() {
        return Err(err(SyscallError::EINVAL));
    }
    if sa.family != AF_INET && sa.family != AF_UNSPEC {
        return Err(err(SyscallError::EAFNOSUPPORT));
    }
    let smoltcp::wire::IpAddress::Ipv4(ip) = sa.ip else {
        return Err(err(SyscallError::EAFNOSUPPORT));
    };
    Ok((ip, sa.port))
}

fn ipv4_from_in6_addr(addr: [u8; 16]) -> Option<smoltcp::wire::Ipv4Address> {
    if addr == [0; 16] {
        return Some(smoltcp::wire::Ipv4Address::UNSPECIFIED);
    }
    if addr[..10].iter().all(|byte| *byte == 0) && addr[10] == 0xff && addr[11] == 0xff {
        return Some(smoltcp::wire::Ipv4Address::from_bytes(&addr[12..16]));
    }
    if addr[..15].iter().all(|byte| *byte == 0) && addr[15] == 1 {
        return Some(smoltcp::wire::Ipv4Address::new(127, 0, 0, 1));
    }
    None
}

fn in6_addr_from_ipv4(ip: smoltcp::wire::Ipv4Address) -> [u8; 16] {
    if ip == smoltcp::wire::Ipv4Address::UNSPECIFIED {
        return [0; 16];
    }
    let b = ip.as_bytes();
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, b[0], b[1], b[2], b[3],
    ]
}

fn in6_addr_from_ip(ip: smoltcp::wire::IpAddress) -> [u8; 16] {
    match ip {
        smoltcp::wire::IpAddress::Ipv4(ip) => in6_addr_from_ipv4(ip),
        smoltcp::wire::IpAddress::Ipv6(ip) => {
            let mut out = [0u8; 16];
            out.copy_from_slice(ip.as_bytes());
            out
        }
    }
}

pub(super) fn read_sockaddr_in_for_domain(
    user_ptr: usize,
    len: usize,
    socket_domain: u16,
) -> Result<ParsedSockAddrIn, isize> {
    if socket_domain == AF_INET {
        return read_sockaddr_in(user_ptr, len);
    }
    if socket_domain != AF_INET6 {
        return Err(err(SyscallError::EAFNOSUPPORT));
    }
    if len > SOCKADDR_STORAGE_SIZE {
        return Err(err(SyscallError::EINVAL));
    }
    if len != 0 && user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    if len < size_of::<u16>() {
        return Err(err(SyscallError::EINVAL));
    }
    let token = get_current_token();
    let Some(family) = try_read_user_value::<u16>(token, user_ptr as *const u16) else {
        return Err(err(SyscallError::EFAULT));
    };
    if family == AF_UNSPEC {
        return Ok(ParsedSockAddrIn {
            family,
            ip: smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::UNSPECIFIED),
            port: 0,
            len,
        });
    }
    if family != AF_INET6 {
        return Err(err(SyscallError::EAFNOSUPPORT));
    }
    if len < size_of::<SockAddrIn6>() {
        return Err(err(SyscallError::EINVAL));
    }
    let Some(sa) = try_read_user_value::<SockAddrIn6>(token, user_ptr as *const SockAddrIn6) else {
        return Err(err(SyscallError::EFAULT));
    };
    let ip = if let Some(ip) = ipv4_from_in6_addr(sa.sin6_addr) {
        smoltcp::wire::IpAddress::Ipv4(ip)
    } else {
        smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_bytes(&sa.sin6_addr))
    };
    Ok(ParsedSockAddrIn {
        family,
        ip,
        port: u16::from_be(sa.sin6_port),
        len,
    })
}

pub(super) fn parse_sockaddr_in_for_domain(
    user_ptr: usize,
    len: usize,
    socket_domain: u16,
) -> Result<(smoltcp::wire::IpAddress, u16), isize> {
    let sa = read_sockaddr_in_for_domain(user_ptr, len, socket_domain)?;
    let required = if sa.family == AF_INET6 {
        size_of::<SockAddrIn6>()
    } else {
        size_of::<SockAddrIn>()
    };
    if sa.len < required {
        return Err(err(SyscallError::EINVAL));
    }
    if sa.family != socket_domain && sa.family != AF_UNSPEC {
        return Err(err(SyscallError::EAFNOSUPPORT));
    }
    Ok((sa.ip, sa.port))
}

/// 从用户空间读取 Linux `sockaddr_ll`，用于 AF_PACKET bind/sendto。
///
/// 参考 Linux `packet_bind()`：长度不足或 family 非 AF_PACKET 均返回 EINVAL；
/// 用户指针不可读返回 EFAULT。
pub(super) fn parse_sockaddr_ll(user_ptr: usize, len: usize) -> Result<SockAddrLl, isize> {
    if len > SOCKADDR_STORAGE_SIZE {
        return Err(err(SyscallError::EINVAL));
    }
    if len < size_of::<SockAddrLl>() {
        return Err(err(SyscallError::EINVAL));
    }
    if user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut storage = [0u8; SOCKADDR_STORAGE_SIZE];
    if try_copy_from_user(token, user_ptr as *const u8, &mut storage[..len]).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let sa = unsafe { core::ptr::read_unaligned(storage.as_ptr() as *const SockAddrLl) };
    if sa.sll_family != AF_PACKET {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(sa)
}

/// 校验 `sendto`/`sendmsg` 给出的 `sockaddr_ll`：硬件地址长度 `sll_halen`
/// 不得超过 `sll_addr` 数组容量，否则返回 EINVAL。
pub(super) fn validate_sockaddr_ll_send(sa: &SockAddrLl) -> Result<(), isize> {
    if usize::from(sa.sll_halen) > sa.sll_addr.len() {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(())
}

/// 将内核侧的 IPv4 地址和端口序列化为 `sockaddr_in` 写回用户空间。
///
/// 遵循 POSIX getpeername/getsockname 语义：
/// - 先读取用户提供的缓冲区长度，按实际可用空间截断写入；
/// - 无论截断与否，都将 `*user_len_ptr` 更新为结构体的完整长度，
///   让调用者知晓需要多大的缓冲区。
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
    // 用户缓冲区可能小于结构体大小，只写入可容纳的部分
    let copy_len = core::cmp::min(len, required);
    if copy_len > 0 {
        // SAFETY: sa 是栈上结构体且布局已知；copy_len <= size_of::<SockAddrIn>()。
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

pub(super) fn write_sockaddr_in6(
    user_ptr: usize,
    user_len_ptr: usize,
    ip: smoltcp::wire::IpAddress,
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
    let sa = SockAddrIn6 {
        sin6_family: AF_INET6,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: in6_addr_from_ip(ip),
        sin6_scope_id: 0,
    };
    let required = size_of::<SockAddrIn6>();
    let copy_len = core::cmp::min(len, required);
    if copy_len > 0 {
        // SAFETY: sa 是栈上结构体且布局已知；copy_len <= size_of::<SockAddrIn6>()。
        let bytes = unsafe {
            core::slice::from_raw_parts((&sa as *const SockAddrIn6) as *const u8, copy_len)
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

pub(super) fn write_sockaddr_in_for_domain(
    user_ptr: usize,
    user_len_ptr: usize,
    domain: u16,
    ip: smoltcp::wire::IpAddress,
    port: u16,
) -> isize {
    if domain == AF_INET6 {
        write_sockaddr_in6(user_ptr, user_len_ptr, ip, port)
    } else {
        let smoltcp::wire::IpAddress::Ipv4(ip) = ip else {
            return err(SyscallError::EINVAL);
        };
        write_sockaddr_in(user_ptr, user_len_ptr, ip, port)
    }
}

/// 将 `sockaddr_ll` 写回用户空间的公共实现，`required` 为应回填的「完整地址长度」。
///
/// 遵循 getsockname/recvfrom 语义：按用户缓冲区可用空间截断写入，但始终把
/// `*user_len_ptr` 更新为 `required`，让调用者得知实际/所需长度。由
/// [`write_sockaddr_ll`] 与 [`write_recv_sockaddr_ll`] 以不同 `required` 复用。
fn write_sockaddr_ll_with_len(
    user_ptr: usize,
    user_len_ptr: usize,
    sa: &SockAddrLl,
    required: usize,
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
    let copy_len = core::cmp::min(len, required);
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (sa as *const SockAddrLl) as *const u8,
            size_of::<SockAddrLl>(),
        )
    };
    if copy_len > 0 && try_copy_to_user(token, user_ptr as *mut u8, &bytes[..copy_len]).is_err() {
        return err(SyscallError::EFAULT);
    }
    let required_u32 = required as u32;
    if try_write_user_value(token, user_len_ptr as *mut u32, &required_u32).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub(super) fn write_sockaddr_ll(user_ptr: usize, user_len_ptr: usize, sa: &SockAddrLl) -> isize {
    let required = SOCKADDR_LL_ADDR_OFFSET + usize::from(sa.sll_halen).min(sa.sll_addr.len());
    write_sockaddr_ll_with_len(user_ptr, user_len_ptr, sa, required)
}

pub(super) fn write_recv_sockaddr_ll(
    user_ptr: usize,
    user_len_ptr: usize,
    sa: &SockAddrLl,
) -> isize {
    write_sockaddr_ll_with_len(user_ptr, user_len_ptr, sa, size_of::<SockAddrLl>())
}

/// 从用户空间读取 `iovcnt` 个 `iovec` 结构体，返回内核侧副本。
///
/// 超出 `UIO_MAXIOV` 的请求返回 EMSGSIZE，与 Linux 行为一致。
/// 全部读入后再处理，避免在散步复制过程中遭遇并发修改（TOCTOU）。
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
        let Some(ptr) = i
            .checked_mul(size_of::<IoVec>())
            .and_then(|off| iov_ptr.checked_add(off))
        else {
            return Err(err(SyscallError::EFAULT));
        };
        let ptr = ptr as *const IoVec;
        let Some(iv) = try_read_user_value::<IoVec>(token, ptr) else {
            return Err(err(SyscallError::EFAULT));
        };
        iovs.push(iv);
    }
    Ok(iovs)
}

/// 按 gather 语义将多个用户空间 iovec 缓冲区的内容合并到单个连续字节向量中。
///
/// 对应 sendmsg 发送路径：将分散的用户缓冲区聚合为一段连续数据后再交给协议栈。
/// 先计算总长度以一次性分配内存，避免多次重新分配。
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

/// 计算 iovec 数组的总字节数，使用 checked_add 防止整数溢出。
pub(super) fn iovecs_total_len(iovs: &[IoVec]) -> Result<usize, isize> {
    iovs.iter()
        .try_fold(0usize, |acc, iv| acc.checked_add(iv.len))
        .ok_or(err(SyscallError::EINVAL))
}

/// 按 scatter 语义将连续数据 `data` 分发写入多个用户空间 iovec 缓冲区，返回实际写入字节数。
///
/// 对应 recvmsg 接收路径：协议栈返回连续数据后，再按 iovec 描述分散到用户缓冲区。
/// 数据耗尽时提前退出，不会越界访问 `data`。
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

/// 将原始字节序列写入 `msghdr.msg_name` 所指向的用户空间地址缓冲区。
///
/// `msg_name` 为 NULL 时静默忽略（recvfrom 调用者不关心来源地址的合法情形）。
/// 函数始终将 `msg_namelen` 更新为 `value` 的完整长度，即便因缓冲区过小发生截断，
/// 调用者可据此判断地址是否被截断（POSIX 要求）。
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
    // 即使发生截断，也写回完整长度，让调用者感知到地址被截断
    msg.msg_namelen = value.len() as u32;
    0
}

/// 将 IPv4 地址和端口序列化为 `sockaddr_in` 后写入 `msghdr.msg_name`。
///
/// 封装 `write_msg_name_bytes`，避免调用方重复构造 `SockAddrIn` 的字节序转换逻辑。
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
    // SAFETY: sa 是栈上结构体且布局已知；长度等于 size_of::<SockAddrIn>()。
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&sa as *const SockAddrIn) as *const u8,
            size_of::<SockAddrIn>(),
        )
    };
    write_msg_name_bytes(msg, bytes)
}

pub(super) fn write_msg_name_in6(
    msg: &mut MsgHdr,
    ip: smoltcp::wire::IpAddress,
    port: u16,
) -> isize {
    let sa = SockAddrIn6 {
        sin6_family: AF_INET6,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: in6_addr_from_ip(ip),
        sin6_scope_id: 0,
    };
    // SAFETY: sa 是栈上结构体且布局已知；长度等于 size_of::<SockAddrIn6>()。
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&sa as *const SockAddrIn6) as *const u8,
            size_of::<SockAddrIn6>(),
        )
    };
    write_msg_name_bytes(msg, bytes)
}

pub(super) fn write_msg_name_in_for_domain(
    msg: &mut MsgHdr,
    domain: u16,
    ip: smoltcp::wire::IpAddress,
    port: u16,
) -> isize {
    if domain == AF_INET6 {
        write_msg_name_in6(msg, ip, port)
    } else {
        let smoltcp::wire::IpAddress::Ipv4(ip) = ip else {
            return err(SyscallError::EINVAL);
        };
        write_msg_name_in(msg, ip, port)
    }
}

/// 校验 sendmsg/sendto 的 flags 参数，拒绝内核尚未实现的标志位。
///
/// MSG_NOSIGNAL 在内核侧无需特殊处理；MSG_DONTROUTE 由支持本地选路的
/// 发送路径消费；MSG_CONFIRM 会传到 IPv4 UDP/RAW 路径刷新邻居项；MSG_EOR
/// 作为 Linux 兼容标志暂按空操作处理。
pub(super) fn validate_send_flags(flags: usize) -> isize {
    let supported = MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE | MSG_DONTROUTE | MSG_EOR | MSG_CONFIRM;
    if (flags & !supported) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    0
}

/// 校验 recvmsg/recvfrom 的 flags 参数，拒绝内核尚未实现的标志位。
///
/// MSG_OOB：当前协议栈不实现带外数据。TCP 在无紧急数据时 Linux 返回 EINVAL
/// （见 net/ipv4/tcp.c `tcp_recv_urg`）；我们恒无紧急数据，故对所有套接字统一返回 EINVAL。
/// MSG_ERRQUEUE 需要在拿到具体 socket 后读取错误队列，这里只把标志认作已知。
pub(super) fn validate_recv_flags(flags: usize) -> isize {
    if (flags & MSG_OOB) != 0 {
        return err(SyscallError::EINVAL);
    }
    let known = MSG_DONTWAIT
        | MSG_PEEK
        | MSG_ERRQUEUE
        | MSG_OOB
        | MSG_TRUNC
        | MSG_WAITFORONE
        | MSG_WAITALL
        | MSG_CMSG_CLOEXEC
        | MSG_NOSIGNAL;
    if (flags & !known) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    0
}

/// 从用户空间读取 `msghdr` 结构体，返回内核侧副本。
pub(super) fn read_msghdr(user_ptr: usize) -> Result<MsgHdr, isize> {
    if user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    try_read_user_value::<MsgHdr>(token, user_ptr as *const MsgHdr).ok_or(err(SyscallError::EFAULT))
}

/// 仅更新 `mmsghdr` 数组第 `idx` 项的 `msg_len` 字段，用于 recvmmsg 逐条填写接收长度。
///
/// 跳过整个 `MMsgHdr` 的写回，减少不必要的用户空间写操作。
pub(super) fn write_mmsghdr_msg_len(user_ptr: usize, idx: usize, msg_len: u32) -> isize {
    let token = get_current_token();
    let Some(base) = idx
        .checked_mul(size_of::<MMsgHdr>())
        .and_then(|off| user_ptr.checked_add(off))
    else {
        return err(SyscallError::EFAULT);
    };
    // msg_len 字段紧跟在 MsgHdr 之后，偏移量等于 size_of::<MsgHdr>()
    let Some(ptr) = base.checked_add(size_of::<MsgHdr>()) else {
        return err(SyscallError::EFAULT);
    };
    let ptr = ptr as *mut u32;
    if try_write_user_value(token, ptr, &msg_len).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// 将完整的 `MMsgHdr` 写回用户空间 `mmsghdr` 数组的第 `idx` 项。
pub(super) fn write_mmsghdr(user_ptr: usize, idx: usize, mmsg: &MMsgHdr) -> isize {
    let token = get_current_token();
    let Some(ptr) = idx
        .checked_mul(size_of::<MMsgHdr>())
        .and_then(|off| user_ptr.checked_add(off))
    else {
        return err(SyscallError::EFAULT);
    };
    let ptr = ptr as *mut MMsgHdr;
    if try_write_user_value(token, ptr, mmsg).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}
