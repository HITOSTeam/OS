/// 网络相关系统调用的公共基础层。
///
/// 本模块负责：
/// - 汇聚并重导出各子模块的系统调用实现（socket / sendrecv / sockopt）
/// - 定义与 Linux ABI 兼容的常量（地址族、套接字类型、选项名、消息标志）
/// - 提供在内核态与用户态之间安全传递套接字地址、iovec、msghdr 的辅助函数
/// - 为消息队列异步通知（mq_notify SIGEV_THREAD）提供跨进程套接字操作接口
mod netlink;
mod sendrecv;
mod socket;
mod sockopt;
mod unix;

use self::netlink::{NetlinkSocketFile, SockAddrNl, parse_sockaddr_nl, write_sockaddr_nl};
use self::unix::{
    SockAddrUn, UnixSocketFile, bind_unix_socket, parse_unix_bound_addr, write_msg_name_un,
    write_sockaddr_un,
};

pub use sendrecv::*;
pub use socket::*;
pub use sockopt::*;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use crate::fs::File;
use crate::mm::{
    UserBuffer, try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value,
};
use crate::syscall::error::{SyscallError, err};
use crate::task::manager::pid2process;
use crate::task::processor::current_files;
use crate::trap::get_current_token;

// ── 地址族（AF_*,Address family）常量，对应 Linux <bits/socket.h> ──────────────────────────
/// unspecified
pub(super) const AF_UNSPEC: u16 = 0;
/// IPC 套接字
pub(super) const AF_UNIX: u16 = 1;
/// ipv4 地址族
pub(super) const AF_INET: u16 = 2;
// 特殊套接字 ,可以读取网络配置
pub(super) const AF_NETLINK: u16 = 16;

// ── 套接字类型（SOCK_*）及创建标志 ───────────────────────────────────────────
pub(super) const SOCK_STREAM: usize = 1;
pub(super) const SOCK_DGRAM: usize = 2;
/// 直接处理IP 包 标志
pub(super) const SOCK_RAW: usize = 3;
/// SCTP 特殊
pub(super) const SOCK_SEQPACKET: usize = 5;
/// 以下不是 纯粹的socket 而是 结合使用的标志位(SOCK是创建标志，O 是fcntl设置标志)
/// 创建时即设置 O_NONBLOCK，避免额外的 fcntl 调用

pub(super) const SOCK_NONBLOCK: usize = 0x800;
/// 创建时即设置 FD_CLOEXEC，防止 fd 泄漏到子进程
pub(super) const SOCK_CLOEXEC: usize = 0x80000;
pub(super) const O_NONBLOCK: u32 = 0x800;
/// O_PATH fd 只能用于路径操作，不能进行 I/O，因此对套接字无效
pub(super) const O_PATH: u32 = 0x200000;
pub(super) const FD_CLOEXEC: u32 = 1;

// ── setsockopt/getsockopt 的协议层（level）标识 ──────────────────────────────
pub(super) const SOL_IP: usize = 0;
/// SOL_SOCKET = 1，作用于通用套接字层而非具体协议
pub(super) const SOL_SOCKET: usize = 1;
pub(super) const SOL_TCP: usize = 6;
pub(super) const SOL_UDP: usize = 17;

// ── SOL_SOCKET 层选项名 ───────────────────────────────────────────────────────
/// 允许复用TIME_WAIT

pub(super) const SO_REUSEADDR: usize = 2;
/// 设置大小
pub(super) const SO_SNDBUF: usize = 7;
pub(super) const SO_RCVBUF: usize = 8;
/// 带外数据内联到普通数据流，而非通过独立通道接收
pub(super) const SO_OOBINLINE: usize = 10;
/// 获取对端进程凭证（pid/uid/gid），仅 Unix 域套接字支持
pub(super) const SO_PEERCRED: usize = 17;
/// 与 SO_SNDBUF/SO_RCVBUF 的区别：FORCE 变体绕过系统上限，需要 CAP_NET_ADMIN
pub(super) const SO_SNDBUFFORCE: usize = 32;
pub(super) const SO_RCVBUFFORCE: usize = 33;
/// 将 eBPF 程序附加到套接字，用于流量过滤
pub(super) const SO_ATTACH_BPF: usize = 50;
/// IP 组播组加入/离开选项，用于 setsockopt(SOL_IP, MCAST_JOIN_GROUP, ...)
pub(super) const MCAST_JOIN_GROUP: usize = 42;
pub(super) const MCAST_LEAVE_GROUP: usize = 45;

// ── sendmsg/recvmsg flags ────────────────────────────────────────────────────
/// 带外（紧急）数据标志
pub(super) const MSG_OOB: usize = 0x1;
/// 窥视缓冲区内容而不消耗数据
pub(super) const MSG_PEEK: usize = 0x2;
pub(super) const MSG_WAITALL: usize = 0x100;
/// recvmsg 返回实际数据长度而非截断后的长度
pub(super) const MSG_TRUNC: usize = 0x20;
pub(super) const MSG_DONTWAIT: usize = 0x40;
/// 读取错误队列中的异步错误（如 ICMP 不可达），而非正常数据
pub(super) const MSG_ERRQUEUE: usize = 0x2000;
/// 发送端请求不因对端未处理 SIGPIPE 而终止进程
pub(super) const MSG_NOSIGNAL: usize = 0x4000;
/// 提示内核后续还有更多数据，可与当前数据合并（类似 TCP_CORK）
pub(super) const MSG_MORE: usize = 0x8000;
/// recvmmsg 专用：收到第一条消息后立即返回，不再等待后续消息
pub(super) const MSG_WAITFORONE: usize = 0x10000;

/// scatter/gather I/O 的最大 iovec 数量上限，与 Linux 保持一致
pub(super) const UIO_MAXIOV: usize = 1024;
/// mq_notify SIGEV_THREAD 模式下，通知 cookie 的固定字节长度
pub(super) const MQ_THREAD_NOTIFY_COOKIE_LEN: usize = 32;

/// 内核内部传递文件对象的类型别名，要求可跨线程共享（Send + Sync）
pub(super) type FileArc = Arc<dyn File + Send + Sync>;

/// 与 Linux `struct iovec` ABI 兼容的 scatter/gather 缓冲区描述符。
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
    /// 辅助数据（control message）缓冲区的用户空间指针
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
#[derive(Clone, Copy)]
pub(super) struct UCred {
    pub(super) pid: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

/// 与 Linux `struct sockaddr_in` ABI 兼容的 IPv4 套接字地址。
///
/// 注意：`sin_port` 和 `sin_addr` 均以**网络字节序**存储，读写时需做字节序转换。
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SockAddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32, // network byte order
    sin_zero: [u8; 8],
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

/// 将内核侧切片 `src` 逐字节写入用户空间 `UserBuffer`，返回实际写入字节数。
///
/// 使用迭代器逐指针写入，而非 memcpy，是因为 UserBuffer 可能跨越不连续的物理页，
/// 其迭代器负责处理页边界的跳转。
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

/// 将用户空间 `UserBuffer` 的内容读取到内核堆分配的 `Vec<u8>` 中。
///
/// 同 `copy_slice_to_user_buffer`，以迭代器方式处理跨页缓冲区。
fn copy_user_buffer_to_vec(buf: UserBuffer) -> Vec<u8> {
    let mut data = Vec::with_capacity(buf.len());
    for p in buf.into_iter() {
        // SAFETY: p is a valid pointer from UserBuffer iterator which guarantees page is mapped.
        data.push(unsafe { *p });
    }
    data
}

/// 从用户空间读取 `sockaddr_in` 并解析为内核使用的 IPv4 地址和端口。
///
/// `sin_family` 为 0 时按 AF_INET 静默处理，与 Linux 行为保持一致（部分旧程序不填写 family）。
/// 端口和地址均以网络字节序存储，此处转换为主机字节序后再返回。
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
        let ptr = (iov_ptr + i * size_of::<IoVec>()) as *const IoVec;
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
/// 先计算总长度以一次性分配内存，避免多次 realloc。
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
    // SAFETY: sa is a stack-local struct with known layout; length equals size_of::<SockAddrIn>().
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&sa as *const SockAddrIn) as *const u8,
            size_of::<SockAddrIn>(),
        )
    };
    write_msg_name_bytes(msg, bytes)
}

/// 校验 sendmsg/sendto 的 flags 参数，拒绝内核尚未实现的标志位。
///
/// MSG_NOSIGNAL 在内核侧无需特殊处理（内核不会向自身发信号），此处仅做合法性检查。
pub(super) fn validate_send_flags(flags: usize) -> isize {
    let supported = MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE;
    if (flags & !supported) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    0
}

/// 校验 recvmsg/recvfrom 的 flags 参数，拒绝内核尚未实现的标志位。
///
/// MSG_OOB 返回 EINVAL 而非 EOPNOTSUPP，是因为该标志在语义上明确无效（内核不支持带外数据）。
/// MSG_ERRQUEUE 返回 EAGAIN，向调用者表明错误队列为空（当前实现未维护错误队列）。
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
    let base = user_ptr + idx * size_of::<MMsgHdr>();
    // msg_len 字段紧跟在 MsgHdr 之后，偏移量等于 size_of::<MsgHdr>()
    let ptr = (base + size_of::<MsgHdr>()) as *mut u32;
    if try_write_user_value(token, ptr, &msg_len).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// 将完整的 `MMsgHdr` 写回用户空间 `mmsghdr` 数组的第 `idx` 项。
pub(super) fn write_mmsghdr(user_ptr: usize, idx: usize, mmsg: &MMsgHdr) -> isize {
    let token = get_current_token();
    let ptr = (user_ptr + idx * size_of::<MMsgHdr>()) as *mut MMsgHdr;
    if try_write_user_value(token, ptr, mmsg).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}
