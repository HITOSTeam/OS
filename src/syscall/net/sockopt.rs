use core::mem::size_of;

use crate::bpf::get_prog_clone;
use crate::fs::{NetSocketFile, SocketPairEnd};
use crate::mm::{try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::processor::current_process;
use crate::trap::get_current_token;

use super::*;

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
    if let Some((lip, lport, _rip, _rport)) = sock.tcp_endpoints_v4() {
        return write_sockaddr_in(addr, addrlen, lip, lport);
    }
    if let Some((lip, lport)) = sock.tcp_local_endpoint_v4() {
        return write_sockaddr_in(addr, addrlen, lip, lport);
    }
    if let Some((ip, port)) = sock.udp_endpoint_v4() {
        return write_sockaddr_in(addr, addrlen, ip, port);
    }
    err(SyscallError::ENOTCONN)
}

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
    if file.as_any().downcast_ref::<SocketPairEnd>().is_some() {
        return write_sockaddr_un(addr, addrlen, None);
    }
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        return err(SyscallError::ENOTCONN);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    if let Some((_lip, _lport, rip, rport)) = sock.tcp_endpoints_v4() {
        return write_sockaddr_in(addr, addrlen, rip, rport);
    }
    if let Some((rip, rport)) = sock.udp_peer_v4() {
        return write_sockaddr_in(addr, addrlen, rip, rport);
    }
    err(SyscallError::ENOTCONN)
}

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
        if optlen < size_of::<i32>() {
            return err(SyscallError::EINVAL);
        }
        if optval == 0 {
            return err(SyscallError::EFAULT);
        }
        let token = get_current_token();
        let Some(prog_fd) = try_read_user_value::<i32>(token, optval as *const i32) else {
            return err(SyscallError::EFAULT);
        };
        if prog_fd < 0 {
            return err(SyscallError::EBADF);
        }
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
            SO_REUSEADDR => {}
            SO_SNDBUF | SO_SNDBUFFORCE => sock.set_sockbuf(Some(v), None),
            SO_RCVBUF | SO_RCVBUFFORCE => sock.set_sockbuf(None, Some(v)),
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

fn write_sockopt_bytes(optval: usize, optlen: usize, user_len: usize, value: &[u8]) -> isize {
    let token = get_current_token();
    let copy_len = core::cmp::min(user_len, value.len());
    if copy_len > 0 && try_copy_to_user(token, optval as *mut u8, &value[..copy_len]).is_err() {
        return err(SyscallError::EFAULT);
    }
    if try_write_user_value(token, optlen as *mut u32, &(value.len() as u32)).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

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

pub fn syscall_shutdown(_fd: usize, _how: usize) -> isize {
    const SHUT_RD: usize = 0;
    const SHUT_WR: usize = 1;
    const SHUT_RDWR: usize = 2;
    if _how > SHUT_RDWR {
        return err(SyscallError::EINVAL);
    }
    let file = match get_file(_fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if file.as_any().downcast_ref::<UnixSocketFile>().is_some() {
        return 0;
    }
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        return 0;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    if sock.kind() == crate::fs::NetSocketKind::TcpStream {
        if _how == SHUT_RD || _how == SHUT_RDWR {
            sock.shutdown_read();
        }
        if _how == SHUT_WR || _how == SHUT_RDWR {
            let _ = sock.tcp_close();
        }
    }
    0
}
