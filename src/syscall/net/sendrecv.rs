//! 网络收发系统调用实现。
//!
//! 本模块负责将用户态的 `sendmsg` / `recvmsg` / `sendmmsg` / `recvmmsg` /
//! `sendto` / `recvfrom` 系统调用分发到三类内核 socket：
//! - **UnixSocketFile**：域内流式（SEQPACKET/STREAM）与数据报（DGRAM）
//! - **NetlinkSocketFile**：内核 netlink 控制通道
//! - **NetSocketFile**：TCP 流 / UDP 数据报（基于 smoltcp）
//!
//! 此外，模块维护一张全局的 `MSG_MORE` 积累表（[`MSG_MORE_PENDING`]），在
//! 用户连续使用 `MSG_MORE` 标志时将分片数据暂存，待最后一次不带该标志的调用
//! 时统一发送，从而减少协议栈调用次数并保证数据报的原子性。

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::NetSocketFile;
use crate::mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::trap::get_current_token;

use super::*;

/// UDP 发送目标：IPv4 地址 + 目的端口号。
type UdpTarget = (smoltcp::wire::Ipv4Address, u16);

// MSG_MORE 积累缓冲：user 带 MSG_MORE 发送时字节先攒在这里，最后一次不带 MSG_MORE
// 的调用才触发真正发送。用 socket Arc 指针作 key，无需侵入 socket 内部状态。
/// MSG_MORE 模式下单个 socket 的待发缓冲状态。
///
/// 当用户连续调用带 `MSG_MORE` 标志的发送接口时，每次的载荷先追加到 `data`，
/// 直到不带 `MSG_MORE` 的最后一次调用才将 `data` 一并交给底层协议栈发送。
struct PendingMoreState {
    /// 已积累但尚未下发的字节序列。
    data: Vec<u8>,
    /// UDP 目标地址（仅对 UDP socket 有意义）；对 TCP / Unix 流式 socket 始终为 `None`。
    udp_target: Option<UdpTarget>,
}

lazy_static! {
    /// 全局 MSG_MORE 积累表，键为 socket 文件的 Arc 指针地址。
    ///
    /// 选用全局 BTreeMap 而非在 socket 结构体中增加字段，是为了**避免侵入**
    /// UnixSocketFile / NetSocketFile 等各自的内部状态，保持 socket 实现的纯净性。
    /// 键使用 [`file_key`] 取 Arc 分配地址（在 Arc 存活期间全局唯一），无需在
    /// socket 类型上引入额外 ID 字段。
    static ref MSG_MORE_PENDING: Mutex<BTreeMap<usize, PendingMoreState>> =
        Mutex::new(BTreeMap::new());
}

/// 将 socket 文件的 `Arc` 指针地址转换为 `MSG_MORE_PENDING` 的键。
///
/// Arc 分配在堆上，同一个 Arc 存活期间地址不变且全局唯一，因此可作为
/// socket 的轻量标识——无需在 socket 类型上引入额外 ID 字段。
fn file_key(file: &FileArc) -> usize {
    Arc::as_ptr(file) as *const () as usize
}

/// 从积累表取出并移除指定 socket 的待发状态（若不存在则返回 `None`）。
fn take_pending_more(key: usize) -> Option<PendingMoreState> {
    MSG_MORE_PENDING.lock().remove(&key)
}

/// 将待发状态写回积累表。
fn put_pending_more(key: usize, state: PendingMoreState) {
    MSG_MORE_PENDING.lock().insert(key, state);
}

/// 将 `chunk` 追加到指定 socket 的 MSG_MORE 积累缓冲中。
///
/// 若该 socket 尚无积累状态则新建；UDP 目标地址以**首次指定**的为准，
/// 后续同一批 MSG_MORE 调用传入的地址会被忽略（详见函数体内注释）。
fn queue_pending_more_chunk(key: usize, chunk: &[u8], udp_target: Option<UdpTarget>) {
    let mut pending = take_pending_more(key).unwrap_or(PendingMoreState {
        data: Vec::new(),
        udp_target,
    });
    // UDP 目标地址以第一次指定的为准，后续同一批 MSG_MORE 调用的地址忽略。
    if pending.udp_target.is_none() {
        pending.udp_target = udp_target;
    }
    pending.data.extend_from_slice(chunk);
    put_pending_more(key, pending);
}

/// 将积累缓冲与本次 `payload` 合并，返回 `(合并后载荷, 是否有待发数据, UDP目标地址)`。
///
/// 若存在积累数据，则将 `payload` 追加到其末尾，并返回 `had_pending = true`，
/// 供 [`visible_send_len`] 据此决定向用户报告的字节数。
fn consume_pending_more(key: usize, payload: Vec<u8>) -> (Vec<u8>, bool, Option<UdpTarget>) {
    if let Some(mut pending) = take_pending_more(key) {
        let pending_target = pending.udp_target;
        pending.data.extend_from_slice(&payload);
        (pending.data, true, pending_target)
    } else {
        (payload, false, None)
    }
}

// MSG_MORE 场景下返回 user_len 而非底层实际发送字节数：user 期望看到本次调用传入的
// 字节数，而不是被底层合并后的总量，否则上层计算进度会出错。
/// 计算向用户报告的发送字节数。
///
/// 若本次发送合并了之前 MSG_MORE 积累的数据（`had_pending == true`），底层
/// `sent` 会大于用户本次实际传入的字节数 `user_len`。此时必须返回 `user_len`，
/// 因为用户依赖返回值来追踪"本次调用消费了多少字节"，返回底层总量会破坏其进度计算。
fn visible_send_len(sent: usize, user_len: usize, had_pending: bool) -> isize {
    if had_pending {
        user_len as isize
    } else {
        sent as isize
    }
}

/// [`visible_send_len`] 的错误透传包装：`ret < 0` 时直接返回错误码，否则调用
/// `visible_send_len` 修正字节数。
fn visible_send_result(ret: isize, user_len: usize, had_pending: bool) -> isize {
    if ret < 0 {
        ret
    } else {
        visible_send_len(ret as usize, user_len, had_pending)
    }
}

/// `sendmsg` / `sendmmsg` 的核心实现，支持三类 socket。
///
/// 按以下顺序尝试 downcast：
/// 1. **UnixSocketFile**：流式 socket 逐 iovec 调用 `syscall_sendto`（利用 MSG_MORE
///    合并分片）；数据报 socket 将所有 iovec 聚合后一次性发送。
/// 2. **NetlinkSocketFile**：iovec 聚合后交给 `handle_outbound` 同步处理，
///    返回值始终等于发送字节数。
/// 3. **NetSocketFile**：TCP 和 UDP 均支持 MSG_MORE 积累语义。
///
/// `flags` 中支持的标志见 [`validate_send_flags`]。
fn sendmsg_inner(fd: usize, msg: &MsgHdr, flags: usize) -> isize {
    if msg.msg_iovlen > UIO_MAXIOV {
        return err(SyscallError::EMSGSIZE);
    }
    let iovs = match read_iovecs(msg.msg_iov, msg.msg_iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if msg.msg_controllen > 0 {
        if msg.msg_control == 0 {
            return err(SyscallError::EFAULT);
        }
        let token = get_current_token();
        let mut probe = [0u8; 1];
        if try_copy_from_user(token, msg.msg_control as *const u8, &mut probe).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        if unix_sock.is_stream_like() {
            if iovs.is_empty() {
                return 0;
            }
            let mut total = 0isize;
            // 除最后一个 iovec 外都注入 MSG_MORE，让底层把所有分片合并成一次发送。
            for (idx, iv) in iovs.iter().enumerate() {
                let mut f = flags;
                if idx + 1 < iovs.len() {
                    f |= MSG_MORE;
                }
                let n = syscall_sendto(
                    fd,
                    iv.base,
                    iv.len,
                    f,
                    msg.msg_name,
                    msg.msg_namelen as usize,
                );
                if n < 0 {
                    return if total > 0 { total } else { n };
                }
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
            }
            return total;
        }
        if !unix_sock.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let kbuf = match gather_iovecs_data(&iovs) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if kbuf.is_empty() {
            return 0;
        }
        let user_len = kbuf.len();
        let target = if msg.msg_name == 0 || msg.msg_namelen == 0 {
            None
        } else {
            match parse_unix_bound_addr(msg.msg_name, msg.msg_namelen as usize) {
                Ok(v) => Some(v),
                Err(e) => return e,
            }
        };
        let key = file_key(&file);
        if (flags & MSG_MORE) != 0 {
            queue_pending_more_chunk(key, &kbuf, None);
            return kbuf.len() as isize;
        }
        let (kbuf, had_pending, _) = consume_pending_more(key, kbuf);
        return visible_send_result(unix_sock.send_dgram(kbuf, target), user_len, had_pending);
    }
    // sendmsg 的 netlink 分支:把 iovec 拼起来交给 handle_outbound,由它解析 nlmsghdr
    // 并立刻构造好回复入队。msg_name 是 user 指定的"发给谁",但这里 kernel 是唯一
    // 对端,只 parse 一遍校验合法性再丢弃。返回值按"全部成功发送"上报,因为我们已经
    // 在 handle_outbound 里把整批字节处理完了。
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        let kbuf = match gather_iovecs_data(&iovs) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if kbuf.is_empty() {
            return 0;
        }
        if msg.msg_name != 0 && msg.msg_namelen != 0 {
            let _ = match parse_sockaddr_nl(msg.msg_name, msg.msg_namelen as usize) {
                Ok(v) => v,
                Err(e) => return e,
            };
        }
        netlink_sock.handle_outbound(&kbuf);
        return kbuf.len() as isize;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let send_flag_check = validate_send_flags(flags);
    if send_flag_check != 0 {
        return send_flag_check;
    }
    let kbuf = match gather_iovecs_data(&iovs) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if kbuf.is_empty() {
        return 0;
    }
    let user_len = kbuf.len();
    let key = file_key(&file);
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            if (flags & MSG_MORE) != 0 {
                queue_pending_more_chunk(key, &kbuf, None);
                return kbuf.len() as isize;
            }
            let (kbuf, had_pending, _) = consume_pending_more(key, kbuf);
            match sock.tcp_send(&kbuf) {
                Ok(n) => visible_send_len(n, user_len, had_pending),
                Err(e) => e,
            }
        }
        crate::fs::NetSocketKind::Udp => {
            if kbuf.len() > 65507 {
                return err(SyscallError::EMSGSIZE);
            }
            let target = if msg.msg_name == 0 || msg.msg_namelen == 0 {
                None
            } else {
                match parse_sockaddr_in(msg.msg_name, msg.msg_namelen as usize) {
                    Ok(v) => Some(v),
                    Err(e) => return e,
                }
            };
            if (flags & MSG_MORE) != 0 {
                queue_pending_more_chunk(key, &kbuf, target);
                return kbuf.len() as isize;
            }
            let (kbuf, had_pending, pending_target) = consume_pending_more(key, kbuf);
            let target = target.or(pending_target);
            if let Some((ip, port)) = target {
                match sock.udp_send_to_v4(ip, port, &kbuf) {
                    Ok(n) => visible_send_len(n, user_len, had_pending),
                    Err(e) => e,
                }
            } else {
                match sock.udp_send_connected(&kbuf) {
                    Ok(n) => visible_send_len(n, user_len, had_pending),
                    Err(e) => e,
                }
            }
        }
        crate::fs::NetSocketKind::TcpListener => err(SyscallError::EOPNOTSUPP),
    }
}

/// `recvmsg` / `recvmmsg` 的核心实现，支持三类 socket。
///
/// 按以下顺序尝试 downcast：
/// 1. **UnixSocketFile**：流式 socket 逐 iovec 阻塞读首片、非阻塞探测后续；
///    数据报 socket 阻塞等待一整个 dgram，超出 iovec 总长的字节设 `MSG_TRUNC`。
/// 2. **NetlinkSocketFile**：从接收队列取一整条 reply 并 scatter 到 iovec；
///    在 `msg_name` 非空时回填 kernel 地址（`nl_pid = 0`）。
/// 3. **NetSocketFile**：TCP 逐 iovec 读取；UDP 一次性读取并回填对端地址。
///
/// 成功时返回实际复制的字节数，失败时返回负的 errno。
fn recvmsg_inner(fd: usize, msg: &mut MsgHdr, flags: usize) -> isize {
    let recv_flag_check = validate_recv_flags(flags);
    if recv_flag_check != 0 {
        return recv_flag_check;
    }
    if msg.msg_iovlen > UIO_MAXIOV {
        return err(SyscallError::EMSGSIZE);
    }
    let iovs = match read_iovecs(msg.msg_iov, msg.msg_iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if msg.msg_controllen > 0 && msg.msg_control == 0 {
        return err(SyscallError::EFAULT);
    }
    let total_len = match iovecs_total_len(&iovs) {
        Ok(v) => v,
        Err(e) => return e,
    };
    msg.msg_flags = 0;
    msg.msg_controllen = 0;
    if total_len == 0 {
        msg.msg_namelen = 0;
        return 0;
    }
    if iovs.is_empty() {
        msg.msg_namelen = 0;
        return 0;
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if unix_sock.is_stream_like() {
            if (flags & MSG_DONTWAIT) != 0 && !unix_sock.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
            let mut total = 0usize;
            // 第一个 iovec 阻塞读；之后每次先探测是否还有数据，避免在数据不足时永久挂起。
            for iv in iovs.iter() {
                if iv.len == 0 {
                    continue;
                }
                if total > 0 && !unix_sock.poll_readable() {
                    break;
                }
                let n = crate::syscall::filesystem::syscall_read(fd, iv.base, iv.len);
                if n < 0 {
                    return if total > 0 { total as isize } else { n };
                }
                let n = n as usize;
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
                if n < iv.len {
                    break;
                }
            }
            let peer = unix_sock.peer_addr();
            let r = write_msg_name_un(msg, peer.as_ref());
            if r != 0 {
                return r;
            }
            return total as isize;
        }
        if !unix_sock.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        if (flags & MSG_DONTWAIT) != 0 && unix_sock.state.lock().dgram_queue.is_empty() {
            return err(SyscallError::EAGAIN);
        }
        let dgram = unix_sock.recv_dgram();
        let copied = match scatter_iovecs_data(&iovs, &dgram.payload) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if copied < dgram.payload.len() {
            msg.msg_flags |= MSG_TRUNC as i32;
        }
        let r = write_msg_name_un(msg, dgram.from.as_ref());
        if r != 0 {
            return r;
        }
        return copied as isize;
    }
    // recvmsg 的 netlink 分支:从队列拿一整条 reply,scatter 到 user 的 iovec 里;
    // 若 user 提供了 msg_name,把 kernel netlink 地址(nl_pid = 0)填回去,这样 glibc
    // 才会把这条 reply 认作"来自 kernel"。user 没要 msg_name 就把长度清零,避免脏值。
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let packet = match netlink_sock.recv_packet(total_len, flags) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let copied = match scatter_iovecs_data(&iovs, &packet[..total_len.min(packet.len())]) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if copied < packet.len() {
            msg.msg_flags |= MSG_TRUNC as i32;
        }
        if msg.msg_name != 0 && msg.msg_namelen != 0 {
            let sa = netlink_sock.kernel_addr();
            // SAFETY: `sa` is a fully initialized stack local `SockAddrNl`, and we expose
            // exactly its in-memory bytes for the duration of this call. A wrong pointer or
            // length here would read invalid memory and copy garbage into userspace.
            let r = write_msg_name_bytes(msg, unsafe {
                core::slice::from_raw_parts(
                    (&sa as *const SockAddrNl) as *const u8,
                    size_of::<SockAddrNl>(),
                )
            });
            if r != 0 {
                return r;
            }
        } else {
            msg.msg_namelen = 0;
        }
        return copied as isize;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
            let mut total = 0usize;
            // 第一个 iovec 阻塞读；之后非阻塞探测，TCP 窗口不足时提前返回已收数据。
            for iv in iovs.iter() {
                if iv.len == 0 {
                    continue;
                }
                if total > 0 && !sock.poll_readable() {
                    break;
                }
                let mut kbuf = vec![0u8; iv.len];
                let n = match sock.tcp_recv(&mut kbuf) {
                    Ok(v) => v,
                    Err(e) => return if total > 0 { total as isize } else { e },
                };
                if n > 0 {
                    let token = get_current_token();
                    if try_copy_to_user(token, iv.base as *mut u8, &kbuf[..n]).is_err() {
                        return err(SyscallError::EFAULT);
                    }
                }
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
                if n < iv.len {
                    break;
                }
            }
            if let Some((_lip, _lport, rip, rport)) = sock.tcp_endpoints_v4() {
                let r = write_msg_name_in(msg, rip, rport);
                if r != 0 {
                    return r;
                }
            } else {
                msg.msg_namelen = 0;
            }
            total as isize
        }
        crate::fs::NetSocketKind::Udp => {
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
            let mut kbuf = vec![0u8; total_len];
            let (n, ip, port) = match sock.udp_recv_from(&mut kbuf) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let copied = match scatter_iovecs_data(&iovs, &kbuf[..n]) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let r = write_msg_name_in(msg, ip, port);
            if r != 0 {
                return r;
            }
            copied as isize
        }
        crate::fs::NetSocketKind::TcpListener => err(SyscallError::EOPNOTSUPP),
    }
}

/// `sendmsg(2)` 系统调用入口。
///
/// 从用户态读取 [`MsgHdr`] 后委托给 [`sendmsg_inner`] 处理。
///
/// # 参数
/// - `fd`：已打开的 socket 文件描述符
/// - `msg`：用户态 `struct msghdr *` 指针
/// - `flags`：发送标志（`MSG_MORE`、`MSG_DONTWAIT` 等）
///
/// # 返回值
/// 成功时返回发送字节数，失败时返回负的 errno。
pub fn syscall_sendmsg(fd: usize, msg: usize, flags: usize) -> isize {
    let msghdr = match read_msghdr(msg) {
        Ok(v) => v,
        Err(e) => return e,
    };
    sendmsg_inner(fd, &msghdr, flags)
}

/// `recvmsg(2)` 系统调用入口。
///
/// 从用户态读取 [`MsgHdr`]，调用 [`recvmsg_inner`] 后将修改后的
/// `MsgHdr`（含 `msg_namelen`、`msg_flags`、`msg_controllen`）写回用户态。
///
/// # 参数
/// - `fd`：已打开的 socket 文件描述符
/// - `msg`：用户态 `struct msghdr *` 指针（调用后内核会更新其字段）
/// - `flags`：接收标志（`MSG_DONTWAIT`、`MSG_PEEK` 等）
///
/// # 返回值
/// 成功时返回接收字节数，失败时返回负的 errno。
pub fn syscall_recvmsg(fd: usize, msg: usize, flags: usize) -> isize {
    let mut msghdr = match read_msghdr(msg) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let ret = recvmsg_inner(fd, &mut msghdr, flags);
    if ret < 0 {
        return ret;
    }
    let token = get_current_token();
    if try_write_user_value(token, msg as *mut MsgHdr, &msghdr).is_err() {
        return err(SyscallError::EFAULT);
    }
    ret
}

/// `sendmmsg(2)` 系统调用入口：批量发送多条消息。
///
/// 依次处理 `msgvec[0..vlen]` 中的每条 [`MMsgHdr`]，每条成功后将实际发送字节数
/// 写回对应的 `msg_len` 字段。
///
/// **POSIX 错误语义**：若在第 `i` 条（`i > 0`）消息处出错，返回已成功发送的消息
/// 计数而非错误码，确保调用方能感知部分成功。仅在第一条就失败时才返回错误码。
///
/// # 返回值
/// 成功时返回发送的消息条数（`≥ 0`），失败时返回负的 errno。
pub fn syscall_sendmmsg(fd: usize, msgvec: usize, vlen: usize, flags: usize) -> isize {
    if vlen == 0 {
        return 0;
    }
    if msgvec == 0 {
        return err(SyscallError::EFAULT);
    }
    let mut sent = 0usize;
    for i in 0..vlen {
        let token = get_current_token();
        let ptr = (msgvec + i * size_of::<MMsgHdr>()) as *const MMsgHdr;
        let Some(mmsg) = try_read_user_value::<MMsgHdr>(token, ptr) else {
            return if sent > 0 {
                sent as isize
            } else {
                err(SyscallError::EFAULT)
            };
        };
        let ret = sendmsg_inner(fd, &mmsg.msg_hdr, flags);
        if ret < 0 {
            return if sent > 0 { sent as isize } else { ret };
        }
        let wr = write_mmsghdr_msg_len(msgvec, i, ret as u32);
        if wr < 0 {
            return if sent > 0 { sent as isize } else { wr };
        }
        sent += 1;
    }
    sent as isize
}

/// `recvmmsg(2)` 系统调用入口：批量接收多条消息。
///
/// 依次接收最多 `vlen` 条消息，每条成功后将实际接收字节数写回 `msg_len`，
/// 并将更新后的 [`MMsgHdr`] 写回用户态。
///
/// **POSIX 错误语义**：与 [`syscall_sendmmsg`] 相同——已收到至少一条消息时，
/// 后续错误不传播，直接返回已接收的消息计数。
///
/// **`MSG_WAITFORONE`**：收到第一条消息后，后续接收均改为非阻塞（追加
/// `MSG_DONTWAIT`），实现"至少一条、尽量多收"的高效语义。
///
/// `timeout` 当前仅做合法性校验（格式检查），不实际限制等待时长。
///
/// # 返回值
/// 成功时返回接收的消息条数（`≥ 0`），失败时返回负的 errno。
pub fn syscall_recvmmsg(
    fd: usize,
    msgvec: usize,
    vlen: usize,
    flags: usize,
    timeout: usize,
) -> isize {
    if vlen == 0 {
        return 0;
    }
    if msgvec == 0 {
        return err(SyscallError::EFAULT);
    }
    if timeout != 0 {
        let token = get_current_token();
        let Some(ts) = try_read_user_value::<UserTimespec>(token, timeout as *const UserTimespec)
        else {
            return err(SyscallError::EFAULT);
        };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
            return err(SyscallError::EINVAL);
        }
    }
    let mut recvd = 0usize;
    for i in 0..vlen {
        let token = get_current_token();
        let ptr = (msgvec + i * size_of::<MMsgHdr>()) as *const MMsgHdr;
        let Some(mut mmsg) = try_read_user_value::<MMsgHdr>(token, ptr) else {
            return if recvd > 0 {
                recvd as isize
            } else {
                err(SyscallError::EFAULT)
            };
        };
        let mut recv_flags = flags;
        // MSG_WAITFORONE：第一条收到后，剩余都改非阻塞，实现"至少一条、尽量多收"语义。
        if recvd > 0 && (flags & MSG_WAITFORONE) != 0 {
            recv_flags |= MSG_DONTWAIT;
        }
        let ret = recvmsg_inner(fd, &mut mmsg.msg_hdr, recv_flags);
        if ret < 0 {
            return if recvd > 0 { recvd as isize } else { ret };
        }
        mmsg.msg_len = ret as u32;
        let wr = write_mmsghdr(msgvec, i, &mmsg);
        if wr < 0 {
            return if recvd > 0 { recvd as isize } else { wr };
        }
        recvd += 1;
        if ret == 0 {
            break;
        }
    }
    recvd as isize
}

/// `sendto(2)` 系统调用入口。
///
/// 支持 Unix socket（流式 / 数据报）、netlink socket 和 TCP/UDP socket。
/// 对流式 Unix socket 直接复用 `syscall_write`；其余 socket 类型均支持
/// MSG_MORE 积累语义。
///
/// # 参数
/// - `fd`：已打开的 socket 文件描述符
/// - `buf_ptr`：用户态发送缓冲区指针
/// - `len`：发送字节数
/// - `flags`：发送标志（`MSG_MORE`、`MSG_DONTWAIT` 等）
/// - `addr`：目标地址结构体指针（`struct sockaddr *`），连接态 socket 可传 `0`
/// - `addrlen`：`addr` 指向结构体的字节长度
///
/// # 返回值
/// 成功时返回本次调用消费的用户字节数，失败时返回负的 errno。
pub fn syscall_sendto(
    fd: usize,
    buf_ptr: usize,
    len: usize,
    flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        if len == 0 {
            return 0;
        }
        if unix_sock.is_stream_like() {
            return crate::syscall::filesystem::syscall_write(fd, buf_ptr, len);
        }
        if !unix_sock.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        if try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err() {
            return err(SyscallError::EFAULT);
        }
        let target = if addr == 0 || addrlen == 0 {
            None
        } else {
            let t = match parse_unix_bound_addr(addr, addrlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
            Some(t)
        };
        let key = file_key(&file);
        let user_len = kbuf.len();
        if (flags & MSG_MORE) != 0 {
            queue_pending_more_chunk(key, &kbuf, None);
            return len as isize;
        }
        let (kbuf, had_pending, _) = consume_pending_more(key, kbuf);
        return visible_send_result(unix_sock.send_dgram(kbuf, target), user_len, had_pending);
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        if len == 0 {
            return 0;
        }
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        if try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 && addrlen != 0 {
            let _ = match parse_sockaddr_nl(addr, addrlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
        }
        netlink_sock.handle_outbound(&kbuf);
        return len as isize;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let send_flag_check = validate_send_flags(flags);
    if send_flag_check != 0 {
        return send_flag_check;
    }
    if len == 0 {
        return 0;
    }
    let token = get_current_token();
    let mut kbuf = alloc::vec![0u8; len];
    if try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err() {
        return err(SyscallError::EFAULT);
    }
    let key = file_key(&file);
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            let user_len = kbuf.len();
            if (flags & MSG_MORE) != 0 {
                queue_pending_more_chunk(key, &kbuf, None);
                return len as isize;
            }
            let (kbuf, had_pending, _) = consume_pending_more(key, kbuf);
            match sock.tcp_send(&kbuf) {
                Ok(n) => visible_send_len(n, user_len, had_pending),
                Err(e) => e,
            }
        }
        crate::fs::NetSocketKind::Udp => {
            let user_len = kbuf.len();
            if kbuf.len() > 65507 {
                return err(SyscallError::EMSGSIZE);
            }
            let target = if addr == 0 || addrlen == 0 {
                None
            } else {
                let (ip, port) = match parse_sockaddr_in(addr, addrlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                Some((ip, port))
            };
            if (flags & MSG_MORE) != 0 {
                queue_pending_more_chunk(key, &kbuf, target);
                return len as isize;
            }
            let (kbuf, had_pending, pending_target) = consume_pending_more(key, kbuf);
            let target = target.or(pending_target);
            if let Some((ip, port)) = target {
                match sock.udp_send_to_v4(ip, port, &kbuf) {
                    Ok(n) => visible_send_len(n, user_len, had_pending),
                    Err(e) => e,
                }
            } else {
                match sock.udp_send_connected(&kbuf) {
                    Ok(n) => visible_send_len(n, user_len, had_pending),
                    Err(e) => e,
                }
            }
        }
        crate::fs::NetSocketKind::TcpListener => err(SyscallError::EOPNOTSUPP),
    }
}

/// `recvfrom(2)` 系统调用入口。
///
/// 支持 Unix socket（流式 / 数据报）、netlink socket 和 TCP/UDP socket。
/// 若 `addr` 非空，调用成功后将对端地址写回用户态。
///
/// # 参数
/// - `fd`：已打开的 socket 文件描述符
/// - `buf_ptr`：用户态接收缓冲区指针
/// - `len`：缓冲区字节长度
/// - `flags`：接收标志（`MSG_DONTWAIT`、`MSG_PEEK` 等）
/// - `addr`：用于写回对端地址的 `struct sockaddr *`，不需要时传 `0`
/// - `addrlen`：`addr` 缓冲区长度的用户态指针（`socklen_t *`），不需要时传 `0`
///
/// # 返回值
/// 成功时返回接收字节数，失败时返回负的 errno。
pub fn syscall_recvfrom(
    fd: usize,
    buf_ptr: usize,
    len: usize,
    flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    let recv_flag_check = validate_recv_flags(flags);
    if recv_flag_check != 0 {
        return recv_flag_check;
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if len == 0 {
            return 0;
        }
        if unix_sock.is_stream_like() {
            let n = crate::syscall::filesystem::syscall_read(fd, buf_ptr, len);
            if n >= 0 && addr != 0 && addrlen != 0 {
                let peer = unix_sock.peer_addr();
                let r = write_sockaddr_un(addr, addrlen, peer.as_ref());
                if r != 0 {
                    return r;
                }
            }
            return n;
        }
        if !unix_sock.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        if (flags & MSG_DONTWAIT) != 0 && unix_sock.state.lock().dgram_queue.is_empty() {
            return err(SyscallError::EAGAIN);
        }
        let msg = unix_sock.recv_dgram();
        let n = len.min(msg.payload.len());
        let token = get_current_token();
        if try_copy_to_user(token, buf_ptr as *mut u8, &msg.payload[..n]).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 && addrlen != 0 {
            let r = write_sockaddr_un(addr, addrlen, msg.from.as_ref());
            if r != 0 {
                return r;
            }
        }
        return n as isize;
    }
    // recvfrom 的 netlink 分支(与上面 recvmsg 分支语义一致,只是参数风格不同):
    // user 给单个 buf 而不是 iovec,长度过短时直接截断(netlink 由 user 端按
    // nlmsghdr.len 自己处理 MSG_TRUNC,我们这里不补 MSG_TRUNC 标记)。
    // 同样在 addr 非空时回填 kernel netlink 地址(nl_pid = 0)。
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        if len == 0 {
            return 0;
        }
        let packet = match netlink_sock.recv_packet(len, flags) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let copied = core::cmp::min(len, packet.len());
        let token = get_current_token();
        if try_copy_to_user(token, buf_ptr as *mut u8, &packet[..copied]).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 && addrlen != 0 {
            let sa = netlink_sock.kernel_addr();
            let r = write_sockaddr_nl(addr, addrlen, &sa);
            if r != 0 {
                return r;
            }
        }
        return copied as isize;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    if len == 0 {
        return 0;
    }
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            if addr != 0 || addrlen != 0 {
                if addr == 0 || addrlen == 0 {
                    return err(SyscallError::EFAULT);
                }
                let token = get_current_token();
                let Some(name_len) = try_read_user_value::<u32>(token, addrlen as *const u32)
                else {
                    return err(SyscallError::EFAULT);
                };
                if (name_len as usize) > i32::MAX as usize {
                    return err(SyscallError::EINVAL);
                }
            }
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
            let mut kbuf = alloc::vec![0u8; len];
            let n = match sock.tcp_recv(&mut kbuf) {
                Ok(n) => n,
                Err(e) => return e,
            };
            let token = get_current_token();
            if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]).is_err() {
                return err(SyscallError::EFAULT);
            }
            n as isize
        }
        crate::fs::NetSocketKind::Udp => {
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
            let mut kbuf = alloc::vec![0u8; len];
            let (n, ip, port) = match sock.udp_recv_from(&mut kbuf) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let token = get_current_token();
            if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]).is_err() {
                return err(SyscallError::EFAULT);
            }
            if addr != 0 && addrlen != 0 {
                let r = write_sockaddr_in(addr, addrlen, ip, port);
                if r != 0 {
                    return r;
                }
            }
            n as isize
        }
        crate::fs::NetSocketKind::TcpListener => err(SyscallError::EOPNOTSUPP),
    }
}
