//! 核心套接字系统调用实现。
//!
//! 本模块提供 `socket`、`bind`、`listen`、`accept`/`accept4`、`connect`
//! 六个系统调用的内核侧实现，支持 AF_INET（TCP/UDP）、AF_UNIX 及
//! AF_NETLINK（仅 stub）三种协议族。

use alloc::sync::Arc;
use core::mem::size_of;

use crate::fs::NetSocketFile;
use crate::mm::{try_copy_to_user, try_read_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::processor::{current_files, current_files_and_nofile_limit, current_process};
use crate::trap::get_current_token;

use super::*;

/// `socket(domain, type, protocol)` — 创建一个新 socket，返回文件描述符。
///
/// `socket_type` 低 8 位为实际类型（SOCK_STREAM / SOCK_DGRAM / …），
/// 高位 flag 可叠加：`SOCK_CLOEXEC`（exec 时自动关闭）、`SOCK_NONBLOCK`（非阻塞模式）。
pub fn syscall_socket(domain: usize, socket_type: usize, protocol: usize) -> isize {
    // 低 8 位是 socket 类型，高位是 SOCK_CLOEXEC / SOCK_NONBLOCK 等 flag。
    let st = socket_type & 0xff;
    let cloexec = (socket_type & SOCK_CLOEXEC) != 0;
    let nonblock = (socket_type & SOCK_NONBLOCK) != 0;

    // 仅支持这四种类型，其他直接 EINVAL。
    if !matches!(st, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET) {
        return err(SyscallError::EINVAL);
    }

    let file: FileArc = match domain as u16 {
        AF_INET => match st {
            SOCK_STREAM => {
                // protocol=0 或 6（IPPROTO_TCP）均合法，其他拒绝。
                if protocol != 0 && protocol != 6 {
                    return err(SyscallError::EPROTONOSUPPORT);
                }
                NetSocketFile::new_tcp()
            }
            SOCK_DGRAM => {
                // protocol=0 或 17（IPPROTO_UDP）均合法，其他拒绝。
                if protocol != 0 && protocol != 17 {
                    return err(SyscallError::EPROTONOSUPPORT);
                }
                NetSocketFile::new_udp()
            }
            // AF_INET 的 RAW / SEQPACKET 暂不支持。
            SOCK_RAW | SOCK_SEQPACKET => return err(SyscallError::EPROTONOSUPPORT),
            _ => return err(SyscallError::EINVAL),
        },
        AF_UNIX => {
            if protocol != 0 {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            if !matches!(st, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
                return err(SyscallError::EINVAL);
            }
            // AF_UNIX 由 UnixSocketFile 实现（内部队列，不经过 smoltcp）。
            Arc::new(UnixSocketFile::new(st))
        }
        // NETLINK 是一种特殊协议。告诉外部网络接口状态。ip addr等工具用的就是这个
        AF_NETLINK => {
            // NETLINK 仅支持 RAW / DGRAM，且 protocol 必须为 0（NETLINK_ROUTE stub）。
            if !matches!(st, SOCK_RAW | SOCK_DGRAM) {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            if protocol != 0 {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            Arc::new(NetlinkSocketFile::new())
        }
        // 其他协议族一律 EAFNOSUPPORT。
        _ => {
            return err(SyscallError::EAFNOSUPPORT);
        }
    };

    // 将 SOCK_CLOEXEC / SOCK_NONBLOCK 转换为 fd 描述符 flag。
    let mut descriptor_flags = 0u32;
    if cloexec {
        descriptor_flags |= FD_CLOEXEC;
    }
    if nonblock {
        descriptor_flags |= O_NONBLOCK;
    }

    // 安装到进程 fd 表，超出 nofile 限制时返回 EMFILE。
    let (files, limit) = current_files_and_nofile_limit();
    let Some(fd) = files.lock().install_fd(file, descriptor_flags, limit) else {
        return err(SyscallError::EMFILE);
    };
    if crate::debug_config::DEBUG_NET {
        let pid = current_process().getpid();
        crate::println!("[net] pid={} socket() -> fd={} type={}", pid, fd, st);
    }
    fd as isize
}

/// `bind(fd, addr, addrlen)` — 将 socket 绑定到指定本地地址和端口。
///
/// - `fd`：待绑定的 socket 文件描述符。
/// - `addr`：用户空间 `sockaddr` 指针（支持 `sockaddr_in` / `sockaddr_un` / `sockaddr_nl`）。
/// - `addrlen`：地址结构体长度（字节）。
///
/// 对 AF_INET socket，内核仅有 loopback 网卡，因此只允许绑定
/// `0.0.0.0`（通配）或 `127.0.0.1`，其他 IP 返回 `EADDRNOTAVAIL`。
/// 端口 < 1024 属于 Linux 特权端口，须 `euid == 0` 方可绑定，否则返回 `EACCES`。
pub fn syscall_bind(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        return bind_unix_socket(&file, unix_sock, addr, addrlen);
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let sa = match parse_sockaddr_nl(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return netlink_sock.bind_local(sa);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let (ip, port) = match parse_sockaddr_in(addr, addrlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // 内核没有真实 NIC，只有 loopback。拒绝绑定到任何非本机 IP，
    // 避免用户误以为可以监听外部网络。
    if ip != smoltcp::wire::Ipv4Address::UNSPECIFIED
        && ip != smoltcp::wire::Ipv4Address::new(127, 0, 0, 1)
    {
        return err(SyscallError::EADDRNOTAVAIL);
    }
    // 遵循 Linux 特权端口约定：0–1023 号端口仅 root 可绑定。
    if port < 1024 {
        let euid = current_process().borrow_mut().euid;
        if euid != 0 {
            return err(SyscallError::EACCES);
        }
    }
    // 0.0.0.0 means "any"; in loopback-only setup treat as 127.0.0.1.
    let ip = if ip == smoltcp::wire::Ipv4Address::UNSPECIFIED {
        smoltcp::wire::Ipv4Address::new(127, 0, 0, 1)
    } else {
        ip
    };
    let r = match sock.bind_v4(ip, port) {
        Ok(()) => 0,
        Err(e) => e,
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} bind(fd={}) -> {}:{} = {}",
            current_process().pid.0,
            fd,
            ip,
            port,
            r
        );
    }
    r
}

/// `listen(fd, backlog)` — 将 socket 转为监听状态，设置全连接队列上限。
///
/// - `fd`：已绑定地址的 TCP socket 或 AF_UNIX stream socket。
/// - `backlog`：已完成三次握手但尚未被 `accept` 取走的连接数上限。
///   实际队列容量由底层实现（smoltcp / UnixSocketFile）决定。
pub fn syscall_listen(fd: usize, backlog: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        return unix_sock.set_listening(backlog);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} listen(fd={}, backlog={}) kind={:?}",
            current_process().pid.0,
            fd,
            backlog,
            sock.kind()
        );
    }
    let r = match sock.listen(backlog) {
        Ok(()) => 0,
        Err(e) => e,
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} listen(fd={}) -> {}",
            current_process().pid.0,
            fd,
            r
        );
    }
    r
}

/// `accept(fd, addr, addrlen)` — 从监听 socket 取出一条已完成三次握手的连接。
///
/// - `fd`：处于监听状态的 socket（TCP 或 AF_UNIX stream）。
/// - `addr`：用于接收对端地址的用户空间缓冲区指针；传 `NULL`（0）表示不关心对端地址。
/// - `addrlen`：指向缓冲区长度的用户空间指针（入参为缓冲区大小，出参为实际写入长度）。
///
/// 在阻塞等待新连接之前，会先验证用户提供的地址缓冲区是否可写，
/// 以防止 TOCTOU（检查-使用时间差）竞争：若缓冲区非法，应在阻塞前尽早报错，
/// 而不是等到连接建立后才发现地址无法写回。
///
/// 返回新连接的文件描述符；出错时返回负的 errno。
pub fn syscall_accept(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if addr != 0 {
            // 提前探测地址缓冲区可访问性，避免 accept 阻塞后再遇到无效指针。
            if addrlen == 0 {
                return err(SyscallError::EINVAL);
            }
            let token = get_current_token();
            let Some(len) = try_read_user_value::<u32>(token, addrlen as *const u32) else {
                return err(SyscallError::EINVAL);
            };
            if (len as usize) < size_of::<SockAddrUn>() {
                return err(SyscallError::EINVAL);
            }
            if try_copy_to_user(token, addr as *mut u8, &[0u8]).is_err() {
                return err(SyscallError::EINVAL);
            }
        }
        let new_sock = match unix_sock.accept_stream() {
            Ok(s) => s,
            Err(e) => return e,
        };
        let peer_addr = new_sock.peer_addr();
        let (files, limit) = current_files_and_nofile_limit();
        let mut files = files.lock();
        // 继承监听 fd 的 flags（如 O_NONBLOCK），但清除 FD_CLOEXEC：
        // Linux 语义规定 accept 返回的 fd 在 exec 后默认可见，
        // 子进程不应自动关闭父进程已 accept 的连接。
        let mut inherited_flags = files.get_flags(fd);
        inherited_flags &= !FD_CLOEXEC;
        let new_file: FileArc = new_sock;
        let Some(newfd) = files.install_fd(new_file, inherited_flags, limit) else {
            return err(SyscallError::EMFILE);
        };
        drop(files);
        if addr != 0 && addrlen != 0 {
            let r = write_sockaddr_un(addr, addrlen, peer_addr.as_ref());
            if r != 0 {
                return r;
            }
        }
        return newfd as isize;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    // Validate user-provided address buffer (when present) before blocking in accept().
    if addr != 0 {
        if addrlen == 0 {
            return err(SyscallError::EINVAL);
        }
        let token = get_current_token();
        let Some(len) = try_read_user_value::<u32>(token, addrlen as *const u32) else {
            return err(SyscallError::EINVAL);
        };
        if (len as usize) < size_of::<SockAddrIn>() {
            return err(SyscallError::EINVAL);
        }
        if try_copy_to_user(token, addr as *mut u8, &[0u8]).is_err() {
            return err(SyscallError::EINVAL);
        }
    }
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => return err(SyscallError::EINVAL),
        crate::fs::NetSocketKind::Udp => return err(SyscallError::EOPNOTSUPP),
        crate::fs::NetSocketKind::TcpListener => {}
    }
    let new_sock = match sock.accept() {
        Ok(s) => s,
        Err(e) => {
            if crate::debug_config::DEBUG_NET {
                crate::println!(
                    "[net] pid={} accept(fd={}) kind={:?} -> {}",
                    current_process().pid.0,
                    fd,
                    sock.kind(),
                    e
                );
            }
            return e;
        }
    };
    let peer = new_sock.tcp_endpoints_v4();
    let (files, limit) = current_files_and_nofile_limit();
    let mut files = files.lock();
    // 继承监听 fd 的 flags，但清除 FD_CLOEXEC（同 AF_UNIX 路径，原因相同）。
    let mut inherited_flags = files.get_flags(fd);
    inherited_flags &= !FD_CLOEXEC;
    let Some(newfd) = files.install_fd(new_sock, inherited_flags, limit) else {
        return err(SyscallError::EMFILE);
    };
    drop(files);
    if addr != 0 && addrlen != 0 {
        if let Some((_lip, _lport, rip, rport)) = peer {
            let r = write_sockaddr_in(addr, addrlen, rip, rport);
            if r != 0 {
                return r;
            }
        }
    }
    newfd as isize
}

/// `accept4(fd, addr, addrlen, flags)` — `accept` 的扩展版本，可原子设置新 fd 的 flags。
///
/// - `flags`：仅允许 `SOCK_CLOEXEC`（exec 时关闭）和 `SOCK_NONBLOCK`（非阻塞）的组合，
///   其他位置位则返回 `EINVAL`。
///
/// 实现方式：先调用 `syscall_accept` 获得新 fd，再根据 `flags` 调整 fd flags。
/// `syscall_accept` 默认清除了 `FD_CLOEXEC`（遵循 Linux 语义）；
/// 若调用者显式传入 `SOCK_CLOEXEC`，此处再重新置位，实现原子 close-on-exec 语义，
/// 避免多线程 fork 竞争窗口。
pub fn syscall_accept4(fd: usize, addr: usize, addrlen: usize, flags: usize) -> isize {
    if (flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK)) != 0 {
        return err(SyscallError::EINVAL);
    }
    let newfd = syscall_accept(fd, addr, addrlen);
    if newfd < 0 {
        return newfd;
    }
    let files = current_files();
    let mut files = files.lock();
    let fd = newfd as usize;
    let mut cur = files.get_flags(fd);
    if (flags & SOCK_CLOEXEC) != 0 {
        cur |= FD_CLOEXEC;
    } else {
        cur &= !FD_CLOEXEC;
    }
    if (flags & SOCK_NONBLOCK) != 0 {
        cur |= O_NONBLOCK;
    } else {
        cur &= !O_NONBLOCK;
    }
    let _ = files.set_flags(fd, cur);
    newfd
}

/// `connect(fd, addr, addrlen)` — 向指定远端地址发起连接（或为无连接 socket 设置默认对端）。
///
/// - `fd`：待连接的 socket。
/// - `addr`：目标地址（`sockaddr_in` / `sockaddr_un` / `sockaddr_nl`）。
/// - `addrlen`：地址结构体长度（字节）。
///
/// 对 AF_NETLINK socket，`connect` 仅校验地址合法性后直接返回成功，
/// 不建立任何实际连接——内核的 netlink 实现是 stub，无需维护连接状态。
///
/// 对 AF_INET socket，目标 IP `0.0.0.0` 被映射到 `127.0.0.1`（同 `bind` 的处理逻辑）。
pub fn syscall_connect(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let bound = match parse_unix_bound_addr(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return unix_sock.connect_unix(bound);
    }
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        // netlink 是内核内部协议，connect 只需确认地址格式合法即可，
        // 不需要真正建立连接通道。
        let _ = match parse_sockaddr_nl(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return 0;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let (ip, port) = match parse_sockaddr_in(addr, addrlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // 目标 0.0.0.0 无实际意义，统一映射到 loopback，与 bind 保持一致。
    let ip = if ip == smoltcp::wire::Ipv4Address::UNSPECIFIED {
        smoltcp::wire::Ipv4Address::new(127, 0, 0, 1)
    } else {
        ip
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} connect(fd={}) -> {}:{}",
            current_process().pid.0,
            fd,
            ip,
            port
        );
    }
    match sock.connect_v4(ip, port, None) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
