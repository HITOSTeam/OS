use alloc::sync::Arc;
use core::any::Any;
use core::mem::size_of;

use crate::fs::NetSocketFile;
use crate::mm::{try_copy_to_user, try_read_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::processor::{current_files_process, current_process};
use crate::trap::get_current_token;

use super::*;

pub fn syscall_socket(domain: usize, socket_type: usize, protocol: usize) -> isize {
    let st = socket_type & 0xff;
    let cloexec = (socket_type & SOCK_CLOEXEC) != 0;
    let nonblock = (socket_type & SOCK_NONBLOCK) != 0;
    if !matches!(st, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET) {
        return err(SyscallError::EINVAL);
    }
    let file: FileArc = match domain as u16 {
        AF_INET => match st {
            SOCK_STREAM => {
                if protocol != 0 && protocol != 6 {
                    return err(SyscallError::EPROTONOSUPPORT);
                }
                NetSocketFile::new_tcp()
            }
            SOCK_DGRAM => {
                if protocol != 0 && protocol != 17 {
                    return err(SyscallError::EPROTONOSUPPORT);
                }
                NetSocketFile::new_udp()
            }
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
            Arc::new(UnixSocketFile::new(st))
        }
        AF_NETLINK => {
            if !matches!(st, SOCK_RAW | SOCK_DGRAM) {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            if protocol != 0 {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            Arc::new(NetlinkSocketFile::new())
        }
        _ => {
            return err(SyscallError::EAFNOSUPPORT);
        }
    };
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return err(SyscallError::EMFILE);
    };
    inner.fd_table[fd] = Some(file);
    let mut fd_flags = 0u32;
    if cloexec {
        fd_flags |= FD_CLOEXEC;
    }
    if nonblock {
        fd_flags |= O_NONBLOCK;
    }
    inner.fd_flags[fd] = fd_flags;
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} socket() -> fd={} type={}",
            process.pid.0,
            fd,
            st
        );
    }
    fd as isize
}

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
    if ip != smoltcp::wire::Ipv4Address::UNSPECIFIED
        && ip != smoltcp::wire::Ipv4Address::new(127, 0, 0, 1)
    {
        return err(SyscallError::EADDRNOTAVAIL);
    }
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

pub fn syscall_accept(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if addr != 0 {
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
        let process = current_files_process();
        let mut inner = process.borrow_mut();
        if fd >= inner.fd_flags.len() {
            let len = inner.fd_table.len();
            inner.fd_flags.resize(len, 0);
        }
        let mut inherited_flags = inner.fd_flags.get(fd).copied().unwrap_or(0);
        inherited_flags &= !FD_CLOEXEC;
        let Some(newfd) = inner.alloc_fd() else {
            return err(SyscallError::EMFILE);
        };
        let new_file: FileArc = new_sock;
        inner.fd_table[newfd] = Some(new_file);
        inner.fd_flags[newfd] = inherited_flags;
        drop(inner);
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
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        let len = inner.fd_table.len();
        inner.fd_flags.resize(len, 0);
    }
    let mut inherited_flags = inner.fd_flags.get(fd).copied().unwrap_or(0);
    inherited_flags &= !FD_CLOEXEC;
    let Some(newfd) = inner.alloc_fd() else {
        return err(SyscallError::EMFILE);
    };
    inner.fd_table[newfd] = Some(new_sock);
    inner.fd_flags[newfd] = inherited_flags;
    drop(inner);
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

pub fn syscall_accept4(fd: usize, addr: usize, addrlen: usize, flags: usize) -> isize {
    if (flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK)) != 0 {
        return err(SyscallError::EINVAL);
    }
    let newfd = syscall_accept(fd, addr, addrlen);
    if newfd < 0 {
        return newfd;
    }
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let fd = newfd as usize;
    if fd >= inner.fd_flags.len() {
        let len = inner.fd_table.len();
        inner.fd_flags.resize(len, 0);
    }
    let mut cur = inner.fd_flags[fd];
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
    inner.fd_flags[fd] = cur;
    newfd
}

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
