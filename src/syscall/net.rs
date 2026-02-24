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
    File, NetSocketFile, SocketPairEnd, ext4_lock, find_path_in_roots, make_socketpair,
};
use crate::mm::{
    UserBuffer, read_user_value, try_copy_from_user, try_copy_to_user, try_read_user_value,
    try_write_user_value,
};
use crate::syscall::filesystem::normalize_path;
use crate::task::processor::{
    current_files_process, current_process, suspend_current_and_run_next,
};
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
const SOL_TCP: usize = 6;
const SOL_UDP: usize = 17;
const SO_REUSEADDR: usize = 2;
const SO_SNDBUF: usize = 7;
const SO_RCVBUF: usize = 8;
const SO_OOBINLINE: usize = 10;
const SO_PEERCRED: usize = 17;
const SO_SNDBUFFORCE: usize = 32;
const SO_RCVBUFFORCE: usize = 33;
const MCAST_JOIN_GROUP: usize = 42;
const MCAST_LEAVE_GROUP: usize = 45;

const EINVAL: isize = -22;
const EBADF: isize = -9;
const EAGAIN: isize = -11;
const EFAULT: isize = -14;
const EACCES: isize = -13;
const ENOTDIR: isize = -20;
const EAFNOSUPPORT: isize = -97;
const EMSGSIZE: isize = -90;
const ENOPROTOOPT: isize = -92;
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

const MSG_OOB: usize = 0x1;
const MSG_PEEK: usize = 0x2;
const MSG_TRUNC: usize = 0x20;
const MSG_DONTWAIT: usize = 0x40;
const MSG_ERRQUEUE: usize = 0x2000;
const MSG_NOSIGNAL: usize = 0x4000;
const MSG_MORE: usize = 0x8000;
const MSG_WAITFORONE: usize = 0x10000;

const UIO_MAXIOV: usize = 1024;

type FileArc = Arc<dyn File + Send + Sync>;
type FileWeak = Weak<dyn File + Send + Sync>;
type UdpTarget = (smoltcp::wire::Ipv4Address, u16);

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum UnixBoundAddr {
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
struct IoVec {
    base: usize,
    len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MsgHdr {
    msg_name: usize,
    msg_namelen: u32,
    _pad0: u32,
    msg_iov: usize,
    msg_iovlen: usize,
    msg_control: usize,
    msg_controllen: usize,
    msg_flags: i32,
    _pad1: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MMsgHdr {
    msg_hdr: MsgHdr,
    msg_len: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UCred {
    pid: u32,
    uid: u32,
    gid: u32,
}

struct PendingMoreState {
    data: Vec<u8>,
    udp_target: Option<UdpTarget>,
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
    peer_cred: Option<UCred>,
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
            peer_cred: None,
            dgram_peer: None,
            dgram_queue: VecDeque::new(),
        }
    }
}

pub(crate) struct UnixSocketFile {
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

    fn peer_cred(&self) -> Option<UCred> {
        self.state.lock().peer_cred
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
            let client_cred = current_unix_ucred();
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
                    Some(client_cred),
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
        peer.state
            .lock()
            .dgram_queue
            .push_back(UnixDatagram { from, payload });
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

fn current_unix_ucred() -> UCred {
    let proc = current_process();
    let inner = proc.borrow_mut();
    UCred {
        pid: proc.pid.0 as u32,
        uid: inner.euid as u32,
        gid: inner.egid as u32,
    }
}

fn file_key(file: &FileArc) -> usize {
    Arc::as_ptr(file) as *const () as usize
}

fn take_pending_more(key: usize) -> Option<PendingMoreState> {
    MSG_MORE_PENDING.lock().remove(&key)
}

fn put_pending_more(key: usize, state: PendingMoreState) {
    MSG_MORE_PENDING.lock().insert(key, state);
}

fn queue_pending_more_chunk(key: usize, chunk: &[u8], udp_target: Option<UdpTarget>) {
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

fn consume_pending_more(key: usize, payload: Vec<u8>) -> (Vec<u8>, bool, Option<UdpTarget>) {
    if let Some(mut pending) = take_pending_more(key) {
        let pending_target = pending.udp_target;
        pending.data.extend_from_slice(&payload);
        (pending.data, true, pending_target)
    } else {
        (payload, false, None)
    }
}

fn visible_send_len(sent: usize, user_len: usize, had_pending: bool) -> isize {
    if had_pending {
        user_len as isize
    } else {
        sent as isize
    }
}

fn visible_send_result(ret: isize, user_len: usize, had_pending: bool) -> isize {
    if ret < 0 {
        ret
    } else {
        visible_send_len(ret as usize, user_len, had_pending)
    }
}

pub(crate) fn poll_file_read_write(file: &Arc<dyn File + Send + Sync>) -> (bool, bool) {
    if let Some(pipe) = file.as_any().downcast_ref::<crate::fs::Pipe>() {
        return (pipe.poll_readable(), pipe.poll_writable());
    }
    if let Some(sp) = file.as_any().downcast_ref::<SocketPairEnd>() {
        return (sp.poll_readable(), sp.poll_writable());
    }
    if let Some(ns) = file.as_any().downcast_ref::<NetSocketFile>() {
        return (ns.poll_readable(), ns.poll_writable());
    }
    if let Some(us) = file.as_any().downcast_ref::<UnixSocketFile>() {
        return (us.poll_readable(), us.poll_writable());
    }
    (file.readable(), file.writable())
}

pub(crate) fn file_supports_poll(file: &Arc<dyn File + Send + Sync>) -> bool {
    file.as_any().downcast_ref::<crate::fs::Pipe>().is_some()
        || file.as_any().downcast_ref::<SocketPairEnd>().is_some()
        || file.as_any().downcast_ref::<NetSocketFile>().is_some()
        || file.as_any().downcast_ref::<UnixSocketFile>().is_some()
}

pub(crate) fn poll_file_epoll(file: &Arc<dyn File + Send + Sync>) -> (bool, bool, bool) {
    let (readable, writable) = poll_file_read_write(file);
    let mut rdhup = false;
    if let Some(ns) = file.as_any().downcast_ref::<NetSocketFile>() {
        rdhup = ns.poll_rdhup();
    }
    (readable, writable, rdhup)
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
    if len > i32::MAX as usize {
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
    if len > i32::MAX as usize {
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
) -> isize {
    if user_ptr == 0 || user_len_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let Some(len_u32) = try_read_user_value::<u32>(token, user_len_ptr as *const u32) else {
        return EFAULT;
    };
    let len = len_u32 as usize;
    if len > i32::MAX as usize {
        return EINVAL;
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
        let bytes = unsafe {
            core::slice::from_raw_parts((&sa as *const SockAddrIn) as *const u8, copy_len)
        };
        if try_copy_to_user(token, user_ptr as *mut u8, bytes).is_err() {
            return EFAULT;
        }
    }
    if try_write_user_value(token, user_len_ptr as *mut u32, &(required as u32)).is_err() {
        return EFAULT;
    }
    0
}

fn write_sockaddr_un(user_ptr: usize, user_len_ptr: usize, addr: Option<&UnixBoundAddr>) -> isize {
    if user_ptr == 0 || user_len_ptr == 0 {
        return EFAULT;
    }
    let token = get_current_token();
    let Some(len_u32) = try_read_user_value::<u32>(token, user_len_ptr as *const u32) else {
        return EFAULT;
    };
    let len = len_u32 as usize;
    if len > i32::MAX as usize {
        return EINVAL;
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
        let bytes = unsafe {
            core::slice::from_raw_parts((&sa as *const SockAddrUn) as *const u8, copy_len)
        };
        if try_copy_to_user(token, user_ptr as *mut u8, bytes).is_err() {
            return EFAULT;
        }
    }
    if try_write_user_value(token, user_len_ptr as *mut u32, &(required as u32)).is_err() {
        return EFAULT;
    }
    0
}

fn read_iovecs(iov_ptr: usize, iovcnt: usize) -> Result<Vec<IoVec>, isize> {
    if iovcnt == 0 {
        return Ok(Vec::new());
    }
    if iovcnt > UIO_MAXIOV {
        return Err(EMSGSIZE);
    }
    if iov_ptr == 0 {
        return Err(EFAULT);
    }
    let token = get_current_token();
    let mut iovs = Vec::with_capacity(iovcnt);
    for i in 0..iovcnt {
        let ptr = (iov_ptr + i * size_of::<IoVec>()) as *const IoVec;
        let Some(iv) = try_read_user_value::<IoVec>(token, ptr) else {
            return Err(EFAULT);
        };
        iovs.push(iv);
    }
    Ok(iovs)
}

fn gather_iovecs_data(iovs: &[IoVec]) -> Result<Vec<u8>, isize> {
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
            return Err(EFAULT);
        }
        off = end;
    }
    Ok(out)
}

fn iovecs_total_len(iovs: &[IoVec]) -> Result<usize, isize> {
    iovs.iter()
        .try_fold(0usize, |acc, iv| acc.checked_add(iv.len))
        .ok_or(EINVAL)
}

fn scatter_iovecs_data(iovs: &[IoVec], data: &[u8]) -> Result<usize, isize> {
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
            return Err(EFAULT);
        }
        off += n;
    }
    Ok(off)
}

fn write_msg_name_bytes(msg: &mut MsgHdr, value: &[u8]) -> isize {
    if msg.msg_name == 0 {
        msg.msg_namelen = 0;
        return 0;
    }
    let user_len = msg.msg_namelen as usize;
    if user_len > i32::MAX as usize {
        return EINVAL;
    }
    let copy_len = core::cmp::min(user_len, value.len());
    if copy_len > 0 {
        let token = get_current_token();
        if try_copy_to_user(token, msg.msg_name as *mut u8, &value[..copy_len]).is_err() {
            return EFAULT;
        }
    }
    msg.msg_namelen = value.len() as u32;
    0
}

fn write_msg_name_in(msg: &mut MsgHdr, ip: smoltcp::wire::Ipv4Address, port: u16) -> isize {
    let sa = SockAddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: {
            let b = ip.as_bytes();
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_be()
        },
        sin_zero: [0; 8],
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&sa as *const SockAddrIn) as *const u8,
            size_of::<SockAddrIn>(),
        )
    };
    write_msg_name_bytes(msg, bytes)
}

fn write_msg_name_un(msg: &mut MsgHdr, addr: Option<&UnixBoundAddr>) -> isize {
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
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&sa as *const SockAddrUn) as *const u8,
            size_of::<SockAddrUn>(),
        )
    };
    write_msg_name_bytes(msg, bytes)
}

fn validate_send_flags(flags: usize) -> isize {
    let known = MSG_OOB | MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE;
    if (flags & !known) != 0 {
        return EOPNOTSUPP;
    }
    if (flags & MSG_OOB) != 0 {
        return EOPNOTSUPP;
    }
    0
}

fn validate_recv_flags(flags: usize) -> isize {
    if (flags & MSG_OOB) != 0 {
        return EINVAL;
    }
    if (flags & MSG_ERRQUEUE) != 0 {
        return EAGAIN;
    }
    let known = MSG_DONTWAIT | MSG_PEEK | MSG_ERRQUEUE | MSG_OOB | MSG_WAITFORONE;
    if (flags & !known) != 0 {
        return EOPNOTSUPP;
    }
    0
}

fn read_msghdr(user_ptr: usize) -> Result<MsgHdr, isize> {
    if user_ptr == 0 {
        return Err(EFAULT);
    }
    let token = get_current_token();
    try_read_user_value::<MsgHdr>(token, user_ptr as *const MsgHdr).ok_or(EFAULT)
}

fn write_mmsghdr_msg_len(user_ptr: usize, idx: usize, msg_len: u32) -> isize {
    let token = get_current_token();
    let base = user_ptr + idx * size_of::<MMsgHdr>();
    let ptr = (base + size_of::<MsgHdr>()) as *mut u32;
    if try_write_user_value(token, ptr, &msg_len).is_err() {
        return EFAULT;
    }
    0
}

fn write_mmsghdr(user_ptr: usize, idx: usize, mmsg: &MMsgHdr) -> isize {
    let token = get_current_token();
    let ptr = (user_ptr + idx * size_of::<MMsgHdr>()) as *mut MMsgHdr;
    if try_write_user_value(token, ptr, mmsg).is_err() {
        return EFAULT;
    }
    0
}

fn sendmsg_inner(fd: usize, msg: &MsgHdr, flags: usize) -> isize {
    if msg.msg_iovlen > UIO_MAXIOV {
        return EMSGSIZE;
    }
    let iovs = match read_iovecs(msg.msg_iov, msg.msg_iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if msg.msg_controllen > 0 {
        if msg.msg_control == 0 {
            return EFAULT;
        }
        let token = get_current_token();
        let mut probe = [0u8; 1];
        if try_copy_from_user(token, msg.msg_control as *const u8, &mut probe).is_err() {
            return EFAULT;
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
                    None => return EINVAL,
                };
            }
            return total;
        }
        if !unix_sock.is_dgram() {
            return EOPNOTSUPP;
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
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
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
                return EMSGSIZE;
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
        crate::fs::NetSocketKind::TcpListener => EOPNOTSUPP,
    }
}

fn recvmsg_inner(fd: usize, msg: &mut MsgHdr, flags: usize) -> isize {
    let recv_flag_check = validate_recv_flags(flags);
    if recv_flag_check != 0 {
        return recv_flag_check;
    }
    if msg.msg_iovlen > UIO_MAXIOV {
        return EMSGSIZE;
    }
    let iovs = match read_iovecs(msg.msg_iov, msg.msg_iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if msg.msg_controllen > 0 && msg.msg_control == 0 {
        return EFAULT;
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
                return EAGAIN;
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
                    None => return EINVAL,
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
            return EOPNOTSUPP;
        }
        if (flags & MSG_DONTWAIT) != 0 && unix_sock.state.lock().dgram_queue.is_empty() {
            return EAGAIN;
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
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return EAGAIN;
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
                        return EFAULT;
                    }
                }
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return EINVAL,
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
                return EAGAIN;
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
        crate::fs::NetSocketKind::TcpListener => EOPNOTSUPP,
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
        return EFAULT;
    }
    ret
}

pub fn syscall_sendmmsg(fd: usize, msgvec: usize, vlen: usize, flags: usize) -> isize {
    if vlen == 0 {
        return 0;
    }
    if msgvec == 0 {
        return EFAULT;
    }
    let mut sent = 0usize;
    for i in 0..vlen {
        let token = get_current_token();
        let ptr = (msgvec + i * size_of::<MMsgHdr>()) as *const MMsgHdr;
        let Some(mmsg) = try_read_user_value::<MMsgHdr>(token, ptr) else {
            return if sent > 0 { sent as isize } else { EFAULT };
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
        return EFAULT;
    }
    if timeout != 0 {
        let token = get_current_token();
        let Some(ts) = try_read_user_value::<UserTimespec>(token, timeout as *const UserTimespec)
        else {
            return EFAULT;
        };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
            return EINVAL;
        }
    }
    let mut recvd = 0usize;
    for i in 0..vlen {
        let token = get_current_token();
        let ptr = (msgvec + i * size_of::<MMsgHdr>()) as *const MMsgHdr;
        let Some(mut mmsg) = try_read_user_value::<MMsgHdr>(token, ptr) else {
            return if recvd > 0 { recvd as isize } else { EFAULT };
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
            let r = write_sockaddr_un(addr, addrlen, peer_addr.as_ref());
            if r != 0 {
                return r;
            }
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
            return EOPNOTSUPP;
        }
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        if try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err() {
            return EFAULT;
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
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
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
        return EFAULT;
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
                return EMSGSIZE;
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
        crate::fs::NetSocketKind::TcpListener => EOPNOTSUPP,
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
            return EOPNOTSUPP;
        }
        if (flags & MSG_DONTWAIT) != 0 && unix_sock.state.lock().dgram_queue.is_empty() {
            return EAGAIN;
        }
        let msg = unix_sock.recv_dgram();
        let n = len.min(msg.payload.len());
        let token = get_current_token();
        if try_copy_to_user(token, buf_ptr as *mut u8, &msg.payload[..n]).is_err() {
            return EFAULT;
        }
        if addr != 0 && addrlen != 0 {
            let r = write_sockaddr_un(addr, addrlen, msg.from.as_ref());
            if r != 0 {
                return r;
            }
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
            if addr != 0 || addrlen != 0 {
                if addr == 0 || addrlen == 0 {
                    return EFAULT;
                }
                let token = get_current_token();
                let Some(name_len) = try_read_user_value::<u32>(token, addrlen as *const u32)
                else {
                    return EFAULT;
                };
                if (name_len as usize) > i32::MAX as usize {
                    return EINVAL;
                }
            }
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return EAGAIN;
            }
            let mut kbuf = alloc::vec![0u8; len];
            let n = match sock.tcp_recv(&mut kbuf) {
                Ok(n) => n,
                Err(e) => return e,
            };
            let token = get_current_token();
            if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]).is_err() {
                return EFAULT;
            }
            n as isize
        }
        crate::fs::NetSocketKind::Udp => {
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return EAGAIN;
            }
            let mut kbuf = alloc::vec![0u8; len];
            let (n, ip, port) = match sock.udp_recv_from(&mut kbuf) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let token = get_current_token();
            if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]).is_err() {
                return EFAULT;
            }
            if addr != 0 && addrlen != 0 {
                let r = write_sockaddr_in(addr, addrlen, ip, port);
                if r != 0 {
                    return r;
                }
            }
            n as isize
        }
        crate::fs::NetSocketKind::TcpListener => EOPNOTSUPP,
    }
}

pub fn syscall_getsockname(fd: usize, addr: usize, addrlen: usize) -> isize {
    if addr == 0 || addrlen == 0 {
        return EFAULT;
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
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
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
    ENOTCONN
}

pub fn syscall_getpeername(fd: usize, addr: usize, addrlen: usize) -> isize {
    if addr == 0 || addrlen == 0 {
        return EFAULT;
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let peer = unix_sock.peer_addr();
        let Some(peer) = peer else {
            return ENOTCONN;
        };
        return write_sockaddr_un(addr, addrlen, Some(&peer));
    }
    if file.as_any().downcast_ref::<SocketPairEnd>().is_some() {
        return write_sockaddr_un(addr, addrlen, None);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    if let Some((_lip, _lport, rip, rport)) = sock.tcp_endpoints_v4() {
        return write_sockaddr_in(addr, addrlen, rip, rport);
    }
    if let Some((rip, rport)) = sock.udp_peer_v4() {
        return write_sockaddr_in(addr, addrlen, rip, rport);
    }
    ENOTCONN
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
        if optlen < size_of::<i32>() {
            return EINVAL;
        }
        if optval == 0 {
            return EFAULT;
        }
        let token = get_current_token();
        let Some(v_i32) = try_read_user_value::<i32>(token, optval as *const i32) else {
            return EFAULT;
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
            _ => return ENOPROTOOPT,
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
            _ => return ENOPROTOOPT,
        }
    }
    if level == SOL_TCP || level == SOL_UDP {
        return ENOPROTOOPT;
    }
    ENOPROTOOPT
}

fn write_sockopt_bytes(optval: usize, optlen: usize, user_len: usize, value: &[u8]) -> isize {
    let token = get_current_token();
    let copy_len = core::cmp::min(user_len, value.len());
    if copy_len > 0 && try_copy_to_user(token, optval as *mut u8, &value[..copy_len]).is_err() {
        return EFAULT;
    }
    if try_write_user_value(token, optlen as *mut u32, &(value.len() as u32)).is_err() {
        return EFAULT;
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
        return EFAULT;
    }
    let token = get_current_token();
    let Some(user_len_u32) = try_read_user_value::<u32>(token, optlen as *const u32) else {
        return EFAULT;
    };
    let user_len = user_len_u32 as usize;
    if user_len > i32::MAX as usize {
        return EINVAL;
    }
    if user_len == 0 {
        return EINVAL;
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if level == SOL_SOCKET && optname == SO_PEERCRED {
            let Some(cred) = unix_sock.peer_cred() else {
                return ENOTCONN;
            };
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
                _ => return EOPNOTSUPP,
            };
            return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
        }
        if level == SOL_UDP {
            return EOPNOTSUPP;
        }
        if level == SOL_IP || level == SOL_TCP {
            return ENOPROTOOPT;
        }
        return EOPNOTSUPP;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return ENOTSOCK,
    };
    let val: u32 = match level {
        SOL_SOCKET => match optname {
            SO_SNDBUF => sock.getsockopt_sndbuf(),
            SO_RCVBUF => sock.getsockopt_rcvbuf(),
            SO_OOBINLINE => 0,
            _ => return EOPNOTSUPP,
        },
        SOL_UDP => return EOPNOTSUPP,
        SOL_IP | SOL_TCP => return ENOPROTOOPT,
        _ => return EOPNOTSUPP,
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
        return EINVAL;
    }
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
        if _how == SHUT_RD || _how == SHUT_RDWR {
            sock.shutdown_read();
        }
        if _how == SHUT_WR || _how == SHUT_RDWR {
            let _ = sock.tcp_close();
        }
    }
    0
}
