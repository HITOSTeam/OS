//! 套接字选项与地址查询系统调用。
//!
//! 本模块实现以下五个系统调用：
//! - [`syscall_getsockname`]：获取套接字本端绑定地址
//! - [`syscall_getpeername`]：获取套接字对端地址
//! - [`syscall_setsockopt`]：设置套接字选项
//! - [`syscall_getsockopt`]：读取套接字选项
//! - [`syscall_shutdown`]：关闭套接字的读写通道
//!
//! 内部辅助函数 [`write_sockopt_bytes`] 负责将选项值安全写回用户空间，
//! 并按 POSIX `getsockopt` 语义将实际选项长度写回 `optlen` 指针。

use core::mem::size_of;

use crate::bpf::get_prog_clone;
use crate::fs::{NetSocketFile, SocketPairEnd};
use crate::mm::{try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::processor::current_process;
use crate::trap::get_current_token;

use super::*;

/// 获取套接字本端绑定的地址（`getsockname(2)`）。
///
/// 按以下顺序分派到各套接字类型：
/// 1. Unix 域套接字 —— 返回已绑定的路径（若未绑定则返回空地址）
/// 2. SocketPair 端点 —— 匿名对，无绑定路径，始终写入空地址
/// 3. Netlink 套接字 —— 返回内核侧本地 `sockaddr_nl`
/// 4. TCP/UDP 套接字 —— 依次尝试 TCP 已连接端点、TCP 仅监听端点、UDP 端点
///
/// # 参数
/// - `fd`：套接字文件描述符
/// - `addr`：用户空间 `sockaddr` 缓冲区指针（不可为 null）
/// - `addrlen`：指向缓冲区长度的用户空间指针（不可为 null）
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_getsockname(fd: usize, addr: usize, addrlen: usize) -> isize {
    if addr == 0 || addrlen == 0 {
        return err(SyscallError::EFAULT);
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let bound = unix_sock.bound_addr();
        return write_sockaddr_un(addr, addrlen, bound.as_ref());
    }
    // SocketPair 是匿名对，没有绑定路径，传 None 写入零长地址
    if file.as_any().downcast_ref::<SocketPairEnd>().is_some() {
        return write_sockaddr_un(addr, addrlen, None);
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let sa = netlink_sock.local_addr();
        return write_sockaddr_nl(addr, addrlen, &sa);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    // 已建立连接的 TCP：从四元组中取本端 IP 和端口
    if let Some((lip, lport, _rip, _rport)) = sock.tcp_endpoints_v4() {
        return write_sockaddr_in(addr, addrlen, lip, lport);
    }
    // 仅监听（未连接）的 TCP：使用本地端点
    if let Some((lip, lport)) = sock.tcp_local_endpoint_v4() {
        return write_sockaddr_in(addr, addrlen, lip, lport);
    }
    if let Some((ip, port)) = sock.udp_endpoint_v4() {
        return write_sockaddr_in(addr, addrlen, ip, port);
    }
    err(SyscallError::ENOTCONN)
}

/// 获取套接字对端（远端）地址（`getpeername(2)`）。
///
/// 按以下顺序分派到各套接字类型：
/// 1. Unix 域套接字 —— 返回对端绑定路径；若未连接则返回 `ENOTCONN`
/// 2. SocketPair 端点 —— 匿名对，写入空地址（对端同样无路径）
/// 3. Netlink 套接字 —— 没有 TCP 意义上的对端，始终返回 `ENOTCONN`
/// 4. TCP/UDP 套接字 —— 从四元组或 UDP peer 中取远端地址
///
/// # 参数
/// - `fd`：套接字文件描述符
/// - `addr`：用户空间 `sockaddr` 缓冲区指针（不可为 null）
/// - `addrlen`：指向缓冲区长度的用户空间指针（不可为 null）
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_getpeername(fd: usize, addr: usize, addrlen: usize) -> isize {
    if addr == 0 || addrlen == 0 {
        return err(SyscallError::EFAULT);
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let peer = unix_sock.peer_addr();
        let Some(peer) = peer else {
            return err(SyscallError::ENOTCONN);
        };
        return write_sockaddr_un(addr, addrlen, Some(&peer));
    }
    // SocketPair 匿名对：对端同样无路径，写入空地址
    if file.as_any().downcast_ref::<SocketPairEnd>().is_some() {
        return write_sockaddr_un(addr, addrlen, None);
    }
    // Netlink 是内核消息总线，没有 TCP 意义上的远端，符合 Linux 行为
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        return err(SyscallError::ENOTCONN);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    // 已连接的 TCP：从四元组中取远端 IP 和端口
    if let Some((_lip, _lport, rip, rport)) = sock.tcp_endpoints_v4() {
        return write_sockaddr_in(addr, addrlen, rip, rport);
    }
    if let Some((rip, rport)) = sock.udp_peer_v4() {
        return write_sockaddr_in(addr, addrlen, rip, rport);
    }
    err(SyscallError::ENOTCONN)
}

/// 设置套接字选项（`setsockopt(2)`）。
///
/// 支持以下选项层级与名称：
/// - `SOL_SOCKET / SO_ATTACH_BPF`：将 eBPF 程序附加到套接字
/// - `SOL_SOCKET / SO_REUSEADDR`：接受，当前作为空操作（no-op）
/// - `SOL_SOCKET / SO_SNDBUF | SO_SNDBUFFORCE`：设置发送缓冲区大小
/// - `SOL_SOCKET / SO_RCVBUF | SO_RCVBUFFORCE`：设置接收缓冲区大小
/// - `SOL_SOCKET / SO_OOBINLINE`：接受，当前作为空操作（no-op）
/// - `SOL_IP / MCAST_JOIN_GROUP`：加入组播组
/// - `SOL_IP / MCAST_LEAVE_GROUP`：离开组播组
///
/// # 参数
/// - `fd`：套接字文件描述符
/// - `level`：选项层级（`SOL_SOCKET`、`SOL_IP` 等）
/// - `optname`：选项名称
/// - `optval`：指向选项值的用户空间指针
/// - `optlen`：选项值的字节长度
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_setsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if level == SOL_SOCKET && optname == SO_ATTACH_BPF {
        // SO_ATTACH_BPF 的语义与普通 sockopt 不同：
        // optval 指向的是一个 **eBPF 程序的文件描述符**（i32），而非程序本身的指针。
        // 需要先从用户空间读出该 fd 整数，再通过 get_prog_clone 解析为内核 BPF 程序句柄。
        if optlen < size_of::<i32>() {
            return err(SyscallError::EINVAL);
        }
        if optval == 0 {
            return err(SyscallError::EFAULT);
        }
        let token = get_current_token();
        // 读取用户空间传入的 BPF 程序 fd 整数
        let Some(prog_fd) = try_read_user_value::<i32>(token, optval as *const i32) else {
            return err(SyscallError::EFAULT);
        };
        if prog_fd < 0 {
            return err(SyscallError::EBADF);
        }
        // 通过 fd 取出对应的 eBPF 程序克隆句柄
        let Some(prog) = get_prog_clone(prog_fd as usize) else {
            return err(SyscallError::EBADF);
        };
        if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
            sock.attach_bpf(prog);
            return 0;
        }
        if let Some(sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
            if let Some(end) = sock.stream_end() {
                end.attach_bpf(prog);
                return 0;
            }
            return err(SyscallError::ENOTSOCK);
        }
    }
    // Netlink 套接字：内核侧不维护 sockopt 状态，所有设置请求静默成功
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        return 0;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    if level == SOL_SOCKET {
        if optlen < size_of::<i32>() {
            return err(SyscallError::EINVAL);
        }
        if optval == 0 {
            return err(SyscallError::EFAULT);
        }
        let token = get_current_token();
        let Some(v_i32) = try_read_user_value::<i32>(token, optval as *const i32) else {
            return err(SyscallError::EFAULT);
        };
        // 负值或零均视为 0，避免将非法值传入底层缓冲区配置
        let v = if v_i32 <= 0 { 0 } else { v_i32 as u32 };
        if crate::debug_config::DEBUG_NET && (optname == SO_SNDBUF || optname == SO_RCVBUF) {
            crate::println!(
                "[net] pid={} setsockopt(fd={}, opt={}) = {}",
                current_process().pid.0,
                fd,
                optname,
                v
            );
        }
        match optname {
            // SO_REUSEADDR：当前实现中端口复用由协议栈隐式处理，此处作为空操作接受
            SO_REUSEADDR => {}
            SO_SNDBUF | SO_SNDBUFFORCE => sock.set_sockbuf(Some(v), None),
            SO_RCVBUF | SO_RCVBUFFORCE => sock.set_sockbuf(None, Some(v)),
            // SO_OOBINLINE：带外数据内联当前未实现，作为空操作接受以保持应用兼容性
            SO_OOBINLINE => {}
            _ => return err(SyscallError::ENOPROTOOPT),
        }
        return 0;
    }
    if level == SOL_IP {
        match optname {
            MCAST_JOIN_GROUP => {
                sock.set_multicast_joined(true);
                return 0;
            }
            MCAST_LEAVE_GROUP => {
                // 遵循 Linux 语义：对未加入的组调用 MCAST_LEAVE_GROUP 返回 EADDRNOTAVAIL
                if sock.multicast_joined() {
                    sock.set_multicast_joined(false);
                    return 0;
                }
                return err(SyscallError::EADDRNOTAVAIL);
            }
            _ => return err(SyscallError::ENOPROTOOPT),
        }
    }
    if level == SOL_TCP || level == SOL_UDP {
        return err(SyscallError::ENOPROTOOPT);
    }
    err(SyscallError::ENOPROTOOPT)
}

/// 将套接字选项值安全写回用户空间（内部辅助）。
///
/// 按 POSIX `getsockopt(2)` 语义处理缓冲区长度：
/// - 实际拷贝长度为 `min(user_len, value.len())`，超出部分截断，不报错。
/// - 无论是否发生截断，均将**选项的完整长度**（`value.len()`）写回 `optlen` 指针，
///   使调用方可以感知缓冲区不足并按需重新分配。
///
/// # 参数
/// - `optval`：用户空间目标缓冲区指针
/// - `optlen`：用户空间 `socklen_t *` 指针，调用后被更新为实际选项长度
/// - `user_len`：用户提供的缓冲区大小（字节）
/// - `value`：要写入的选项值字节切片
///
/// # 返回值
/// 成功返回 `0`；写入失败返回 `EFAULT`。
fn write_sockopt_bytes(optval: usize, optlen: usize, user_len: usize, value: &[u8]) -> isize {
    let token = get_current_token();
    // 以用户缓冲区大小为上限截断，防止越界写入
    let copy_len = core::cmp::min(user_len, value.len());
    if copy_len > 0 && try_copy_to_user(token, optval as *mut u8, &value[..copy_len]).is_err() {
        return err(SyscallError::EFAULT);
    }
    // 回写完整的选项长度（非截断后的长度），符合 POSIX getsockopt 语义
    if try_write_user_value(token, optlen as *mut u32, &(value.len() as u32)).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// 读取套接字选项（`getsockopt(2)`）。
///
/// 支持的选项层级与名称：
/// - Netlink 套接字：对所有查询返回 `0`（内核不维护 sockopt 状态）
/// - Unix 域套接字：`SOL_SOCKET / SO_PEERCRED`（对端凭证）、`SO_OOBINLINE`
/// - TCP/UDP 套接字：`SOL_SOCKET / SO_SNDBUF`、`SO_RCVBUF`、`SO_OOBINLINE`
///
/// # 参数
/// - `fd`：套接字文件描述符
/// - `level`：选项层级（`SOL_SOCKET`、`SOL_IP` 等）
/// - `optname`：选项名称
/// - `optval`：用户空间接收缓冲区指针（不可为 null）
/// - `optlen`：指向缓冲区长度的用户空间指针（不可为 null）；调用后被更新为实际选项长度
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_getsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    if optval == 0 || optlen == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(user_len_u32) = try_read_user_value::<u32>(token, optlen as *const u32) else {
        return err(SyscallError::EFAULT);
    };
    let user_len = user_len_u32 as usize;
    // 防止后续长度运算溢出：optlen 不应超过 i32::MAX
    if user_len > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    if user_len == 0 {
        return err(SyscallError::EINVAL);
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    // Netlink 套接字：内核侧不维护 sockopt 状态，返回固定的零值而非报错
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        let val: u32 = 0;
        return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
    }
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if level == SOL_SOCKET && optname == SO_PEERCRED {
            let Some(cred) = unix_sock.peer_cred() else {
                return err(SyscallError::ENOTCONN);
            };
            // SAFETY: `cred` is a fully initialized local `UCred`, and we reborrow exactly
            // `size_of::<UCred>()` bytes from it while `cred` stays alive. If the layout or
            // length were wrong, userspace would observe uninitialized or out-of-bounds bytes.
            let cred_bytes = unsafe {
                core::slice::from_raw_parts(
                    (&cred as *const UCred) as *const u8,
                    size_of::<UCred>(),
                )
            };
            return write_sockopt_bytes(optval, optlen, user_len, cred_bytes);
        }
        if level == SOL_SOCKET {
            let val: u32 = match optname {
                SO_OOBINLINE => 0,
                _ => return err(SyscallError::EOPNOTSUPP),
            };
            return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
        }
        if level == SOL_UDP {
            return err(SyscallError::EOPNOTSUPP);
        }
        if level == SOL_IP || level == SOL_TCP {
            return err(SyscallError::ENOPROTOOPT);
        }
        return err(SyscallError::EOPNOTSUPP);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let val: u32 = match level {
        SOL_SOCKET => match optname {
            SO_SNDBUF => sock.getsockopt_sndbuf(),
            SO_RCVBUF => sock.getsockopt_rcvbuf(),
            SO_OOBINLINE => 0,
            _ => return err(SyscallError::EOPNOTSUPP),
        },
        SOL_UDP => return err(SyscallError::EOPNOTSUPP),
        SOL_IP | SOL_TCP => return err(SyscallError::ENOPROTOOPT),
        _ => return err(SyscallError::EOPNOTSUPP),
    };
    if crate::debug_config::DEBUG_NET && (optname == SO_SNDBUF || optname == SO_RCVBUF) {
        crate::println!(
            "[net] pid={} getsockopt(fd={}, opt={}) -> {}",
            current_process().pid.0,
            fd,
            optname,
            val
        );
    }
    write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes())
}

/// 关闭套接字的读写通道（`shutdown(2)`）。
///
/// `how` 参数含义：
/// - `SHUT_RD (0)`：关闭读端，调用 `shutdown_read`
/// - `SHUT_WR (1)`：关闭写端，调用 `tcp_close`
/// - `SHUT_RDWR (2)`：同时关闭读写两端，**依次**调用 `shutdown_read` 和 `tcp_close`
///
/// Unix 域套接字和 Netlink 套接字不区分半关闭状态，直接返回 `0`。
/// 半关闭（half-close）是 TCP 协议特有的概念，对这两类套接字无实际意义。
///
/// # 参数
/// - `_fd`：套接字文件描述符
/// - `_how`：关闭方向（`SHUT_RD`、`SHUT_WR` 或 `SHUT_RDWR`）
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_shutdown(_fd: usize, _how: usize) -> isize {
    const SHUT_RD: usize = 0; // 关闭读端
    const SHUT_WR: usize = 1; // 关闭写端
    const SHUT_RDWR: usize = 2; // 同时关闭读写两端
    if _how > SHUT_RDWR {
        return err(SyscallError::EINVAL);
    }
    let file = match get_file(_fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    // Unix 域套接字：半关闭无意义，静默成功
    if file.as_any().downcast_ref::<UnixSocketFile>().is_some() {
        return 0;
    }
    // Netlink 套接字：半关闭无意义，静默成功
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        return 0;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    if sock.kind() == crate::fs::NetSocketKind::TcpStream {
        // SHUT_RDWR 会同时触发两个分支，读写两端独立关闭，符合 Linux 行为
        if _how == SHUT_RD || _how == SHUT_RDWR {
            sock.shutdown_read();
        }
        if _how == SHUT_WR || _how == SHUT_RDWR {
            let _ = sock.tcp_close();
        }
    }
    0
}
