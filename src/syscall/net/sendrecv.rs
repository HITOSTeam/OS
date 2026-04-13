use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::mem::size_of;

use crate::fs::NetSocketFile;
use crate::mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::trap::get_current_token;

use super::*;

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
        let mut kbuf = match gather_iovecs_data(&iovs) {
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
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
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
        // Outbound netlink is ignored in current kernel model.
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
    let mut kbuf = match gather_iovecs_data(&iovs) {
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
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let packet = match netlink_sock.recv_packet(total_len, flags) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let copied = match scatter_iovecs_data(&iovs, &packet[..total_len.min(packet.len())]) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if msg.msg_name != 0 && msg.msg_namelen != 0 {
            let sa = netlink_sock.local_addr();
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

pub fn syscall_sendmsg(fd: usize, msg: usize, flags: usize) -> isize {
    let msghdr = match read_msghdr(msg) {
        Ok(v) => v,
        Err(e) => return e,
    };
    sendmsg_inner(fd, &msghdr, flags)
}

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
            return if sent > 0 { sent as isize } else { err(SyscallError::EFAULT) };
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
            return if recvd > 0 { recvd as isize } else { err(SyscallError::EFAULT) };
        };
        let mut recv_flags = flags;
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
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        if len == 0 {
            return 0;
        }
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        // Minimal support for mq_notify helper sockets: outbound netlink is ignored.
        let token = get_current_token();
        let mut probe = [0u8; 1];
        if try_copy_from_user(token, buf_ptr as *const u8, &mut probe).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 && addrlen != 0 {
            let _ = match parse_sockaddr_nl(addr, addrlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
        }
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
            let sa = netlink_sock.local_addr();
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
