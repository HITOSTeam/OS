use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::mem::size_of;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::{ext4_lock, find_path_in_roots, make_socketpair, File, NetSocketFile, SocketPairEnd};
use crate::mm::{
    read_user_value, try_copy_from_user, try_copy_to_user, try_read_user_value, write_user_value,
    UserBuffer,
};
use crate::syscall::filesystem::normalize_path;
use crate::task::processor::{current_files_process, current_process, suspend_current_and_run_next};
use crate::trap::get_current_token;

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const SOL_IP: usize = 0;

const SOCK_STREAM: usize = 1;
const SOCK_DGRAM: usize = 2;
const SOCK_RAW: usize = 3;
const SOCK_SEQPACKET: usize = 5;
const SOCK_NONBLOCK: usize = 0x800;
const SOCK_CLOEXEC: usize = 0x80000;
const O_NONBLOCK: u32 = 0x800;
const O_PATH: u32 = 0x200000;
const FD_CLOEXEC: u32 = 1;

const SOL_SOCKET: usize = 1;
const SO_SNDBUF: usize = 7;
const SO_RCVBUF: usize = 8;
const MCAST_JOIN_GROUP: usize = 42;
const MCAST_LEAVE_GROUP: usize = 45;

const EINVAL: isize = -22;
const EBADF: isize = -9;
const EFAULT: isize = -14;
const EACCES: isize = -13;
const ENOTDIR: isize = -20;
const EAFNOSUPPORT: isize = -97;
const EPROTONOSUPPORT: isize = -93;
const ENOTSOCK: isize = -88;
const EOPNOTSUPP: isize = -95;
const EISCONN: isize = -106;
const ENOTCONN: isize = -107;
const EMFILE: isize = -24;
const EADDRINUSE: isize = -98;
const EADDRNOTAVAIL: isize = -99;
const ECONNREFUSED: isize = -111;
const ENOENT: isize = -2;

type FileArc = Arc<dyn File + Send + Sync>;
type FileWeak = Weak<dyn File + Send + Sync>;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum UnixBoundAddr {
    Path(String),
    Abstract(Vec<u8>),
}

lazy_static! {
    static ref UNIX_BOUND_PATHS: Mutex<BTreeMap<String, FileWeak>> = Mutex::new(BTreeMap::new());
    static ref UNIX_BOUND_ABSTRACT: Mutex<BTreeMap<Vec<u8>, FileWeak>> = Mutex::new(BTreeMap::new());
}

struct UnixDatagram {
    from: Option<UnixBoundAddr>,
    payload: Vec<u8>,
}

struct UnixSocketState {
    bound: Option<UnixBoundAddr>,
    listening: bool,
    backlog: usize,
    pending_accept: VecDeque<Arc<UnixSocketFile>>,
    stream_end: Option<Arc<SocketPairEnd>>,
    peer_addr: Option<UnixBoundAddr>,
    dgram_peer: Option<UnixBoundAddr>,
    dgram_queue: VecDeque<UnixDatagram>,
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
            dgram_peer: None,
            dgram_queue: VecDeque::new(),
        }
    }
}

struct UnixSocketFile {
    sock_type: usize,
    state: Mutex<UnixSocketState>,
}

impl UnixSocketFile {
    fn new(sock_type: usize) -> Self {
        Self {
            sock_type,
            state: Mutex::new(UnixSocketState::new()),
        }
    }

    fn new_connected_stream(
        sock_type: usize,
        stream_end: Arc<SocketPairEnd>,
        peer_addr: Option<UnixBoundAddr>,
    ) -> Self {
        let mut state = UnixSocketState::new();
        state.stream_end = Some(stream_end);
        state.peer_addr = peer_addr;
        Self {
            sock_type,
            state: Mutex::new(state),
        }
    }

    fn is_stream_like(&self) -> bool {
        matches!(self.sock_type, SOCK_STREAM | SOCK_SEQPACKET)
    }

    fn is_dgram(&self) -> bool {
        self.sock_type == SOCK_DGRAM
    }

    fn bound_addr(&self) -> Option<UnixBoundAddr> {
        self.state.lock().bound.clone()
    }

    fn set_bound_addr(&self, addr: UnixBoundAddr) {
        self.state.lock().bound = Some(addr);
    }

    fn peer_addr(&self) -> Option<UnixBoundAddr> {
        let st = self.state.lock();
        st.peer_addr.clone().or_else(|| st.dgram_peer.clone())
    }

    fn set_listening(&self, backlog: usize) -> isize {
        if !self.is_stream_like() {
            return EOPNOTSUPP;
        }
        let mut st = self.state.lock();
        if st.bound.is_none() {
            return EINVAL;
        }
        st.listening = true;
        st.backlog = backlog.max(1).min(32);
        0
    }

    fn accept_stream(&self) -> Result<Arc<UnixSocketFile>, isize> {
        if !self.is_stream_like() {
            return Err(EOPNOTSUPP);
        }
        loop {
            let mut st = self.state.lock();
            if !st.listening {
                return Err(EINVAL);
            }
            if let Some(conn) = st.pending_accept.pop_front() {
                return Ok(conn);
            }
            drop(st);
            suspend_current_and_run_next();
        }
    }

    fn connect_unix(&self, addr: UnixBoundAddr) -> isize {
        if self.is_stream_like() {
            {
                let st = self.state.lock();
                if st.stream_end.is_some() {
                    return EISCONN;
                }
            }
            let peer_file = match lookup_unix_bound_socket(&addr) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
                return ECONNREFUSED;
            };
            if !peer.is_stream_like() {
                return EPROTONOSUPPORT;
            }
            let (client_end, server_end) = make_socketpair();
            let client_bound = self.bound_addr();
            {
                let mut peer_st = peer.state.lock();
                if !peer_st.listening {
                    return ECONNREFUSED;
                }
                if peer_st.pending_accept.len() >= peer_st.backlog {
                    return ECONNREFUSED;
                }
                let accepted = Arc::new(UnixSocketFile::new_connected_stream(
                    self.sock_type,
                    server_end,
                    client_bound,
                ));
                peer_st.pending_accept.push_back(accepted);
            }
            let mut st = self.state.lock();
            if st.stream_end.is_some() {
                return EISCONN;
            }
            st.stream_end = Some(client_end);
            st.peer_addr = Some(addr);
            return 0;
        }
        if !self.is_dgram() {
            return EPROTONOSUPPORT;
        }
        let peer_file = match lookup_unix_bound_socket(&addr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
            return ECONNREFUSED;
        };
        if !peer.is_dgram() {
            return EPROTONOSUPPORT;
        }
        let mut st = self.state.lock();
        st.dgram_peer = Some(addr.clone());
        st.peer_addr = Some(addr);
        0
    }

    fn send_dgram(&self, payload: Vec<u8>, target: Option<UnixBoundAddr>) -> isize {
        if !self.is_dgram() {
            return EOPNOTSUPP;
        }
        let (to, from) = {
            let st = self.state.lock();
            let Some(to) = target.or_else(|| st.dgram_peer.clone()) else {
                return EINVAL;
            };
            (to, st.bound.clone())
        };
        let peer_file = match lookup_unix_bound_socket(&to) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
            return ECONNREFUSED;
        };
        if !peer.is_dgram() {
            return EPROTONOSUPPORT;
        }
        let n = payload.len();
        peer.state.lock().dgram_queue.push_back(UnixDatagram { from, payload });
        n as isize
    }

    fn recv_dgram(&self) -> UnixDatagram {
        loop {
            let mut st = self.state.lock();
            if let Some(msg) = st.dgram_queue.pop_front() {
                return msg;
            }
            drop(st);
            suspend_current_and_run_next();
        }
    }

    fn stream_end(&self) -> Option<Arc<SocketPairEnd>> {
        self.state.lock().stream_end.clone()
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32, // network byte order
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrUn {
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

fn get_file(fd: usize) -> Result<FileArc, isize> {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return Err(EBADF);
    }
    if fd < inner.fd_flags.len() && (inner.fd_flags[fd] & O_PATH) != 0 {
        return Err(EBADF);
    }
    inner.fd_table[fd].clone().ok_or(EBADF)
}

fn copy_slice_to_user_buffer(buf: UserBuffer, src: &[u8]) -> usize {
    let mut it = buf.into_iter();
    let mut copied = 0usize;
    while copied < src.len() {
        let Some(dst) = it.next() else {
            break;
        };
        unsafe { *dst = src[copied] };
        copied += 1;
    }
    copied
}

fn copy_user_buffer_to_vec(buf: UserBuffer) -> Vec<u8> {
    let mut data = Vec::with_capacity(buf.len());
    for p in buf.into_iter() {
        data.push(unsafe { *p });
    }
    data
}

fn parse_sockaddr_in(
    user_ptr: usize,
    len: usize,
) -> Result<(smoltcp::wire::Ipv4Address, u16), isize> {
    if user_ptr == 0 || len < size_of::<SockAddrIn>() {
        return Err(EINVAL);
    }
    let token = get_current_token();
    let Some(sa) = try_read_user_value(token, user_ptr as *const SockAddrIn) else {
        return Err(EFAULT);
    };
    if sa.sin_family != AF_INET {
        if sa.sin_family != 0 {
            return Err(EAFNOSUPPORT);
        }
    }
    let port = u16::from_be(sa.sin_port);
    let ip_raw = u32::from_be(sa.sin_addr);
    let ip = smoltcp::wire::Ipv4Address::from_bytes(&ip_raw.to_be_bytes());
    Ok((ip, port))
}

fn parse_sockaddr_un(user_ptr: usize, len: usize) -> Result<(bool, Vec<u8>), isize> {
    if user_ptr == 0 || len < size_of::<u16>() {
        return Err(EINVAL);
    }
    let to_copy = len.min(size_of::<SockAddrUn>());
    let token = get_current_token();
    let mut raw = vec![0u8; to_copy];
    if try_copy_from_user(token, user_ptr as *const u8, raw.as_mut_slice()).is_err() {
        return Err(EFAULT);
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    if family != AF_UNIX {
        return Err(EAFNOSUPPORT);
    }
    let path = &raw[size_of::<u16>()..];
    if path.is_empty() {
        return Err(EINVAL);
    }
    if path[0] == 0 {
        let mut name = path[1..].to_vec();
        while matches!(name.last(), Some(0)) {
            name.pop();
        }
        if name.is_empty() {
            return Err(EINVAL);
        }
        return Ok((true, name));
    }
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    if end == 0 {
        return Err(EINVAL);
    }
    Ok((false, path[..end].to_vec()))
}

fn parse_unix_bound_addr(addr: usize, addrlen: usize) -> Result<UnixBoundAddr, isize> {
    let (is_abstract, raw_name) = parse_sockaddr_un(addr, addrlen)?;
    if is_abstract {
        return Ok(UnixBoundAddr::Abstract(raw_name));
    }
    let Ok(path_part) = core::str::from_utf8(&raw_name) else {
        return Err(EINVAL);
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
                return Err(ENOENT);
            };
            if let Some(file) = weak.upgrade() {
                return Ok(file);
            }
            reg.remove(path);
            Err(ENOENT)
        }
        UnixBoundAddr::Abstract(name) => {
            let mut reg = UNIX_BOUND_ABSTRACT.lock();
            let Some(weak) = reg.get(name) else {
                return Err(ENOENT);
            };
            if let Some(file) = weak.upgrade() {
                return Ok(file);
            }
            reg.remove(name);
            Err(ENOENT)
        }
    }
}

fn register_unix_bound_socket(addr: &UnixBoundAddr, file: &FileArc) -> isize {
    match addr {
        UnixBoundAddr::Path(path) => {
            let mut reg = UNIX_BOUND_PATHS.lock();
            if let Some(existing) = reg.get(path) {
                if existing.upgrade().is_some() {
                    return EADDRINUSE;
                }
                reg.remove(path);
            }
            reg.insert(path.clone(), Arc::downgrade(file));
        }
        UnixBoundAddr::Abstract(name) => {
            let mut reg = UNIX_BOUND_ABSTRACT.lock();
            if let Some(existing) = reg.get(name) {
                if existing.upgrade().is_some() {
                    return EADDRINUSE;
                }
                reg.remove(name);
            }
            reg.insert(name.clone(), Arc::downgrade(file));
        }
    }
    0
}

fn bind_unix_socket(file: &FileArc, sock: &UnixSocketFile, addr: usize, addrlen: usize) -> isize {
    if sock.bound_addr().is_some() {
        return EINVAL;
    }
    let bound = match parse_unix_bound_addr(addr, addrlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let UnixBoundAddr::Path(abs) = &bound {
        let Some((parent_path, name)) = split_parent_and_name(abs) else {
            return EINVAL;
        };
        let _fs_guard = ext4_lock();
        let Some(parent) = find_path_in_roots(parent_path) else {
            return ENOENT;
        };
        if !parent.is_dir() {
            return ENOTDIR;
        }
        if parent.find(name).is_some() {
            return EADDRINUSE;
        }
        if parent.create_file(name).is_err() {
            if parent.find(name).is_some() {
                return EADDRINUSE;
            }
            return EINVAL;
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

fn write_sockaddr_in(
    user_ptr: usize,
    user_len_ptr: usize,
    ip: smoltcp::wire::Ipv4Address,
    port: u16,
) {
    if user_ptr == 0 || user_len_ptr == 0 {
        return;
    }
    let token = get_current_token();
    let mut len = read_user_value(token, user_len_ptr as *const u32) as usize;
    if len < size_of::<SockAddrIn>() {
        // Write back required size anyway.
        len = size_of::<SockAddrIn>();
        write_user_value(token, user_len_ptr as *mut u32, &(len as u32));
        return;
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
    write_user_value(token, user_ptr as *mut SockAddrIn, &sa);
    write_user_value(
        token,
        user_len_ptr as *mut u32,
        &(size_of::<SockAddrIn>() as u32),
    );
}

fn write_sockaddr_un(user_ptr: usize, user_len_ptr: usize, addr: Option<&UnixBoundAddr>) {
    if user_ptr == 0 || user_len_ptr == 0 {
        return;
    }
    let token = get_current_token();
    let mut len = read_user_value(token, user_len_ptr as *const u32) as usize;
    if len < size_of::<SockAddrUn>() {
        len = size_of::<SockAddrUn>();
        write_user_value(token, user_len_ptr as *mut u32, &(len as u32));
        return;
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
    write_user_value(token, user_ptr as *mut SockAddrUn, &sa);
    write_user_value(
        token,
        user_len_ptr as *mut u32,
        &(size_of::<SockAddrUn>() as u32),
    );
}

pub fn syscall_socket(domain: usize, socket_type: usize, protocol: usize) -> isize {
    let st = socket_type & 0xff;
    let cloexec = (socket_type & SOCK_CLOEXEC) != 0;
    let nonblock = (socket_type & SOCK_NONBLOCK) != 0;
    if !matches!(st, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET) {
        return EINVAL;
    }
    let file: FileArc = match domain as u16 {
        AF_INET => match st {
            SOCK_STREAM => {
                if protocol != 0 && protocol != 6 {
                    return EPROTONOSUPPORT;
                }
                NetSocketFile::new_tcp()
            }
            SOCK_DGRAM => {
                if protocol != 0 && protocol != 17 {
                    return EPROTONOSUPPORT;
                }
                NetSocketFile::new_udp()
            }
            SOCK_RAW | SOCK_SEQPACKET => return EPROTONOSUPPORT,
            _ => return EINVAL,
        },
        AF_UNIX => {
            if protocol != 0 {
                return EPROTONOSUPPORT;
            }
            if !matches!(st, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
                return EINVAL;
            }
            Arc::new(UnixSocketFile::new(st))
        }
        _ => return EAFNOSUPPORT,
    };
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return EMFILE;
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
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    let (ip, port) = match parse_sockaddr_in(addr, addrlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if ip != smoltcp::wire::Ipv4Address::UNSPECIFIED
        && ip != smoltcp::wire::Ipv4Address::new(127, 0, 0, 1)
    {
        return EADDRNOTAVAIL;
    }
    if port < 1024 {
        let euid = current_process().borrow_mut().euid;
        if euid != 0 {
            return EACCES;
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
        None => return ENOTSOCK,
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
                return EINVAL;
            }
            let token = get_current_token();
            let Some(len) = try_read_user_value::<u32>(token, addrlen as *const u32) else {
                return EINVAL;
            };
            if (len as usize) < size_of::<SockAddrUn>() {
                return EINVAL;
            }
            if try_copy_to_user(token, addr as *mut u8, &[0u8]).is_err() {
                return EINVAL;
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
            return EMFILE;
        };
        let new_file: FileArc = new_sock;
        inner.fd_table[newfd] = Some(new_file);
        inner.fd_flags[newfd] = inherited_flags;
        drop(inner);
        if addr != 0 && addrlen != 0 {
            write_sockaddr_un(addr, addrlen, peer_addr.as_ref());
        }
        return newfd as isize;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    // Validate user-provided address buffer (when present) before blocking in accept().
    if addr != 0 {
        if addrlen == 0 {
            return EINVAL;
        }
        let token = get_current_token();
        let Some(len) = try_read_user_value::<u32>(token, addrlen as *const u32) else {
            return EINVAL;
        };
        if (len as usize) < size_of::<SockAddrIn>() {
            return EINVAL;
        }
        if try_copy_to_user(token, addr as *mut u8, &[0u8]).is_err() {
            return EINVAL;
        }
    }
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => return EINVAL,
        crate::fs::NetSocketKind::Udp => return EOPNOTSUPP,
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
        return EMFILE;
    };
    inner.fd_table[newfd] = Some(new_sock);
    inner.fd_flags[newfd] = inherited_flags;
    drop(inner);
    if let Some((_lip, _lport, rip, rport)) = peer {
        write_sockaddr_in(addr, addrlen, rip, rport);
    }
    newfd as isize
}

pub fn syscall_accept4(fd: usize, addr: usize, addrlen: usize, flags: usize) -> isize {
    if (flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK)) != 0 {
        return EINVAL;
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
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
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

pub fn syscall_sendto(
    fd: usize,
    buf_ptr: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if len == 0 {
            return 0;
        }
        if unix_sock.is_stream_like() {
            if addr != 0 && addrlen != 0 {
                return EISCONN;
            }
            return crate::syscall::filesystem::syscall_write(fd, buf_ptr, len);
        }
        if !unix_sock.is_dgram() {
            return EOPNOTSUPP;
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
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        crate::mm::copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice());
        return unix_sock.send_dgram(kbuf, target);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if len == 0 {
        return 0;
    }
    let token = get_current_token();
    let mut kbuf = alloc::vec![0u8; len];
    crate::mm::copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice());
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            // Linux: send()/sendto() on a connected TCP socket ignores the dest address.
            if addr != 0 && addrlen != 0 {
                return EISCONN;
            }
            match sock.tcp_send(&kbuf) {
                Ok(n) => n as isize,
                Err(e) => e,
            }
        }
        crate::fs::NetSocketKind::Udp => {
            if addr == 0 || addrlen == 0 {
                match sock.udp_send_connected(&kbuf) {
                    Ok(n) => n as isize,
                    Err(e) => e,
                }
            } else {
                let (ip, port) = match parse_sockaddr_in(addr, addrlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match sock.udp_send_to_v4(ip, port, &kbuf) {
                    Ok(n) => n as isize,
                    Err(e) => e,
                }
            }
        }
        crate::fs::NetSocketKind::TcpListener => EOPNOTSUPP,
    }
}

pub fn syscall_recvfrom(
    fd: usize,
    buf_ptr: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
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
                write_sockaddr_un(addr, addrlen, peer.as_ref());
            }
            return n;
        }
        if !unix_sock.is_dgram() {
            return EOPNOTSUPP;
        }
        let msg = unix_sock.recv_dgram();
        let n = len.min(msg.payload.len());
        let token = get_current_token();
        crate::mm::copy_to_user(token, buf_ptr as *mut u8, &msg.payload[..n]);
        if addr != 0 && addrlen != 0 {
            write_sockaddr_un(addr, addrlen, msg.from.as_ref());
        }
        return n as isize;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if len == 0 {
        return 0;
    }
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            let mut kbuf = alloc::vec![0u8; len];
            let n = match sock.tcp_recv(&mut kbuf) {
                Ok(n) => n,
                Err(e) => return e,
            };
            let token = get_current_token();
            crate::mm::copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]);
            if addr != 0 && addrlen != 0 {
                if let Some((_lip, _lport, rip, rport)) = sock.tcp_endpoints_v4() {
                    write_sockaddr_in(addr, addrlen, rip, rport);
                }
            }
            n as isize
        }
        crate::fs::NetSocketKind::Udp => {
            let mut kbuf = alloc::vec![0u8; len];
            let (n, ip, port) = match sock.udp_recv_from(&mut kbuf) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let token = get_current_token();
            crate::mm::copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]);
            if addr != 0 && addrlen != 0 {
                write_sockaddr_in(addr, addrlen, ip, port);
            }
            n as isize
        }
        crate::fs::NetSocketKind::TcpListener => EOPNOTSUPP,
    }
}

pub fn syscall_getsockname(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let bound = unix_sock.bound_addr();
        write_sockaddr_un(addr, addrlen, bound.as_ref());
        return 0;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if let Some((lip, lport, _rip, _rport)) = sock.tcp_endpoints_v4() {
        write_sockaddr_in(addr, addrlen, lip, lport);
        return 0;
    }
    if let Some((lip, lport)) = sock.tcp_local_endpoint_v4() {
        write_sockaddr_in(addr, addrlen, lip, lport);
        return 0;
    }
    if let Some((ip, port)) = sock.udp_endpoint_v4() {
        write_sockaddr_in(addr, addrlen, ip, port);
        return 0;
    }
    EOPNOTSUPP
}

pub fn syscall_getpeername(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let peer = unix_sock.peer_addr();
        let Some(peer) = peer else {
            return ENOTCONN;
        };
        write_sockaddr_un(addr, addrlen, Some(&peer));
        return 0;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if let Some((_lip, _lport, rip, rport)) = sock.tcp_endpoints_v4() {
        write_sockaddr_in(addr, addrlen, rip, rport);
        return 0;
    }
    if let Some((rip, rport)) = sock.udp_peer_v4() {
        write_sockaddr_in(addr, addrlen, rip, rport);
        return 0;
    }
    EOPNOTSUPP
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
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if level == SOL_SOCKET {
        if optval == 0 || optlen < size_of::<i32>() {
            return EINVAL;
        }
        let token = get_current_token();
        let v = read_user_value(token, optval as *const i32);
        if v <= 0 {
            return 0;
        }
        let v = v as u32;
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
            SO_SNDBUF => sock.set_sockbuf(Some(v), None),
            SO_RCVBUF => sock.set_sockbuf(None, Some(v)),
            _ => {}
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
                return EADDRNOTAVAIL;
            }
            _ => return 0,
        }
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
    // `optlen` is a user pointer to socklen_t.
    let token = get_current_token();
    if optlen == 0 {
        return EINVAL;
    }
    let user_len = read_user_value(token, optlen as *const u32) as usize;
    if user_len < size_of::<u32>() {
        write_user_value(token, optlen as *mut u32, &(size_of::<u32>() as u32));
        return EINVAL;
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    let val = if level == SOL_SOCKET {
        match optname {
            SO_SNDBUF => sock.getsockopt_sndbuf(),
            SO_RCVBUF => sock.getsockopt_rcvbuf(),
            _ => 0,
        }
    } else {
        0
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
    if optval != 0 {
        let v: u32 = val;
        write_user_value(token, optval as *mut u32, &v);
    }
    write_user_value(token, optlen as *mut u32, &(size_of::<u32>() as u32));
    0
}

pub fn syscall_shutdown(_fd: usize, _how: usize) -> isize {
    let file = match get_file(_fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if file.as_any().downcast_ref::<UnixSocketFile>().is_some() {
        return 0;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if sock.kind() == crate::fs::NetSocketKind::TcpStream {
        let _ = sock.tcp_close();
    }
    0
}
