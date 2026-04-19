mod sendrecv;
mod socket;
mod sockopt;

pub use sendrecv::*;
pub use socket::*;
pub use sockopt::*;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::mem::size_of;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::mm::{
    UserBuffer, try_copy_from_user, try_copy_to_user, try_read_user_value,
    try_write_user_value,
};
use crate::syscall::filesystem::normalize_path;
use crate::task::manager::pid2process;
use crate::task::processor::{
    block_current_and_run_next, current_files_process, current_process, current_task,
    suspend_current_and_run_next,
};
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use crate::trap::get_current_token;
use crate::syscall::error::{SyscallError, err};
use crate::fs::{
    File, POLLIN, POLLOUT, PollWaitQueue, SocketPairEnd, ext4_lock, find_path_in_roots,
    make_socketpair, wake_tasks,
};

pub(super) const AF_UNIX: u16 = 1;
pub(super) const AF_INET: u16 = 2;
pub(super) const AF_NETLINK: u16 = 16;
pub(super) const SOL_IP: usize = 0;

pub(super) const SOCK_STREAM: usize = 1;
pub(super) const SOCK_DGRAM: usize = 2;
pub(super) const SOCK_RAW: usize = 3;
pub(super) const SOCK_SEQPACKET: usize = 5;
pub(super) const SOCK_NONBLOCK: usize = 0x800;
pub(super) const SOCK_CLOEXEC: usize = 0x80000;
pub(super) const O_NONBLOCK: u32 = 0x800;
pub(super) const O_PATH: u32 = 0x200000;
pub(super) const FD_CLOEXEC: u32 = 1;

pub(super) const SOL_SOCKET: usize = 1;
pub(super) const SOL_TCP: usize = 6;
pub(super) const SOL_UDP: usize = 17;
pub(super) const SO_REUSEADDR: usize = 2;
pub(super) const SO_SNDBUF: usize = 7;
pub(super) const SO_RCVBUF: usize = 8;
pub(super) const SO_OOBINLINE: usize = 10;
pub(super) const SO_PEERCRED: usize = 17;
pub(super) const SO_SNDBUFFORCE: usize = 32;
pub(super) const SO_RCVBUFFORCE: usize = 33;
pub(super) const SO_ATTACH_BPF: usize = 50;
pub(super) const MCAST_JOIN_GROUP: usize = 42;
pub(super) const MCAST_LEAVE_GROUP: usize = 45;


pub(super) const MSG_OOB: usize = 0x1;
pub(super) const MSG_PEEK: usize = 0x2;
pub(super) const MSG_WAITALL: usize = 0x100;
pub(super) const MSG_TRUNC: usize = 0x20;
pub(super) const MSG_DONTWAIT: usize = 0x40;
pub(super) const MSG_ERRQUEUE: usize = 0x2000;
pub(super) const MSG_NOSIGNAL: usize = 0x4000;
pub(super) const MSG_MORE: usize = 0x8000;
pub(super) const MSG_WAITFORONE: usize = 0x10000;

pub(super) const UIO_MAXIOV: usize = 1024;
pub(super) const MQ_THREAD_NOTIFY_COOKIE_LEN: usize = 32;

pub(super) type FileArc = Arc<dyn File + Send + Sync>;
pub(super) type FileWeak = Weak<dyn File + Send + Sync>;
pub(super) type UdpTarget = (smoltcp::wire::Ipv4Address, u16);

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum UnixBoundAddr {
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
pub(super) struct IoVec {
    pub(super) base: usize,
    pub(super) len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MsgHdr {
    pub(super) msg_name: usize,
    pub(super) msg_namelen: u32,
    pub(super) _pad0: u32,
    pub(super) msg_iov: usize,
    pub(super) msg_iovlen: usize,
    pub(super) msg_control: usize,
    pub(super) msg_controllen: usize,
    pub(super) msg_flags: i32,
    pub(super) _pad1: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MMsgHdr {
    pub(super) msg_hdr: MsgHdr,
    pub(super) msg_len: u32,
    pub(super) _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct UserTimespec {
    pub(super) tv_sec: i64,
    pub(super) tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct UCred {
    pub(super) pid: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

struct PendingMoreState {
    data: Vec<u8>,
    udp_target: Option<UdpTarget>,
}

pub(super) struct UnixDatagram {
    pub(super) from: Option<UnixBoundAddr>,
    pub(super) payload: Vec<u8>,
}

pub(super) struct UnixSocketState {
    bound: Option<UnixBoundAddr>,
    listening: bool,
    backlog: usize,
    pending_accept: VecDeque<Arc<UnixSocketFile>>,
    stream_end: Option<Arc<SocketPairEnd>>,
    peer_addr: Option<UnixBoundAddr>,
    peer_cred: Option<UCred>,
    dgram_peer: Option<UnixBoundAddr>,
    pub(super) dgram_queue: VecDeque<UnixDatagram>,
    poll_waiters: PollWaitQueue,
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
            poll_waiters: PollWaitQueue::default(),
        }
    }
}

pub(crate) struct UnixSocketFile {
    sock_type: usize,
    pub(super) state: Mutex<UnixSocketState>,
}

impl UnixSocketFile {
    pub(super) fn new(sock_type: usize) -> Self {
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

    pub(super) fn is_stream_like(&self) -> bool {
        matches!(self.sock_type, SOCK_STREAM | SOCK_SEQPACKET)
    }

    pub(super) fn is_dgram(&self) -> bool {
        self.sock_type == SOCK_DGRAM
    }

    pub(super) fn bound_addr(&self) -> Option<UnixBoundAddr> {
        self.state.lock().bound.clone()
    }

    fn set_bound_addr(&self, addr: UnixBoundAddr) {
        self.state.lock().bound = Some(addr);
    }

    pub(super) fn peer_addr(&self) -> Option<UnixBoundAddr> {
        let st = self.state.lock();
        st.peer_addr.clone().or_else(|| st.dgram_peer.clone())
    }

    pub(super) fn peer_cred(&self) -> Option<UCred> {
        self.state.lock().peer_cred
    }

    fn notify_poll_waiters(&self) {
        let waiters = self.state.lock().poll_waiters.take_wakeups();
        wake_tasks(waiters);
    }

    pub(super) fn set_listening(&self, backlog: usize) -> isize {
        if !self.is_stream_like() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let mut st = self.state.lock();
        if st.bound.is_none() {
            return err(SyscallError::EINVAL);
        }
        st.listening = true;
        st.backlog = backlog.max(1).min(32);
        drop(st);
        self.notify_poll_waiters();
        0
    }

    pub(super) fn accept_stream(&self) -> Result<Arc<UnixSocketFile>, isize> {
        if !self.is_stream_like() {
            return Err(err(SyscallError::EOPNOTSUPP));
        }
        loop {
            let mut st = self.state.lock();
            if !st.listening {
                return Err(err(SyscallError::EINVAL));
            }
            if let Some(conn) = st.pending_accept.pop_front() {
                return Ok(conn);
            }
            drop(st);
            suspend_current_and_run_next();
        }
    }

    pub(super) fn connect_unix(&self, addr: UnixBoundAddr) -> isize {
        if self.is_stream_like() {
            {
                let st = self.state.lock();
                if st.stream_end.is_some() {
                    return err(SyscallError::EISCONN);
                }
            }
            let peer_file = match lookup_unix_bound_socket(&addr) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
                return err(SyscallError::ECONNREFUSED);
            };
            if !peer.is_stream_like() {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            let (client_end, server_end) = make_socketpair();
            let client_bound = self.bound_addr();
            let client_cred = current_unix_ucred();
            {
                let mut peer_st = peer.state.lock();
                if !peer_st.listening {
                    return err(SyscallError::ECONNREFUSED);
                }
                if peer_st.pending_accept.len() >= peer_st.backlog {
                    return err(SyscallError::ECONNREFUSED);
                }
                let accepted = Arc::new(UnixSocketFile::new_connected_stream(
                    self.sock_type,
                    server_end,
                    client_bound,
                    Some(client_cred),
                ));
                peer_st.pending_accept.push_back(accepted);
                let wake = peer_st.poll_waiters.take_wakeups();
                drop(peer_st);
                wake_tasks(wake);
            }
            let mut st = self.state.lock();
            if st.stream_end.is_some() {
                return err(SyscallError::EISCONN);
            }
            st.stream_end = Some(client_end);
            st.peer_addr = Some(addr);
            drop(st);
            self.notify_poll_waiters();
            return 0;
        }
        if !self.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let peer_file = match lookup_unix_bound_socket(&addr) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
            return err(SyscallError::ECONNREFUSED);
        };
        if !peer.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let mut st = self.state.lock();
        st.dgram_peer = Some(addr.clone());
        st.peer_addr = Some(addr);
        0
    }

    pub(super) fn send_dgram(&self, payload: Vec<u8>, target: Option<UnixBoundAddr>) -> isize {
        if !self.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let (to, from) = {
            let st = self.state.lock();
            let Some(to) = target.or_else(|| st.dgram_peer.clone()) else {
                return err(SyscallError::EINVAL);
            };
            (to, st.bound.clone())
        };
        let peer_file = match lookup_unix_bound_socket(&to) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let Some(peer) = peer_file.as_any().downcast_ref::<UnixSocketFile>() else {
            return err(SyscallError::ECONNREFUSED);
        };
        if !peer.is_dgram() {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let n = payload.len();
        let wake = {
            let mut peer_st = peer.state.lock();
            peer_st
                .dgram_queue
                .push_back(UnixDatagram { from, payload });
            peer_st.poll_waiters.take_wakeups()
        };
        wake_tasks(wake);
        n as isize
    }

    pub(super) fn recv_dgram(&self) -> UnixDatagram {
        loop {
            let mut st = self.state.lock();
            if let Some(msg) = st.dgram_queue.pop_front() {
                return msg;
            }
            drop(st);
            suspend_current_and_run_next();
        }
    }

    pub(super) fn stream_end(&self) -> Option<Arc<SocketPairEnd>> {
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

    #[allow(dead_code)]
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

    fn poll_mask(&self) -> i16 {
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
                return if pending_accept { POLLIN } else { 0 };
            }
            if let Some(end) = stream_end {
                return end.poll_mask();
            }
            return 0;
        }
        if self.is_dgram() {
            let mut mask = POLLOUT;
            if !self.state.lock().dgram_queue.is_empty() {
                mask |= POLLIN;
            }
            return mask;
        }
        0
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        if self.is_stream_like() {
            let mut st = self.state.lock();
            let _ = st.poll_waiters.register_waiter(task);
            if st.listening {
                return true;
            }
            let end = st.stream_end.clone();
            drop(st);
            if let Some(end) = end.as_ref() {
                let _ = end.register_poll_waiter(task);
            }
            return true;
        }
        if self.is_dgram() {
            let mut st = self.state.lock();
            let _ = st.poll_waiters.register_waiter(task);
            return true;
        }
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

struct NetlinkSocketState {
    bound: Option<SockAddrNl>,
    messages: VecDeque<[u8; MQ_THREAD_NOTIFY_COOKIE_LEN]>,
    recv_waiters: VecDeque<Weak<TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
}

pub(crate) struct NetlinkSocketFile {
    state: Mutex<NetlinkSocketState>,
}

impl NetlinkSocketFile {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(NetlinkSocketState {
                bound: None,
                messages: VecDeque::new(),
                recv_waiters: VecDeque::new(),
                poll_waiters: PollWaitQueue::default(),
            }),
        }
    }

    fn retain_blocked_waiters(waiters: &mut VecDeque<Weak<TaskControlBlock>>) {
        waiters.retain(|w| {
            let Some(task) = w.upgrade() else {
                return false;
            };
            task.borrow_mut().task_status == TaskStatus::Blocked
        });
    }

    fn add_waiter_once(
        waiters: &mut VecDeque<Weak<TaskControlBlock>>,
        task: &Arc<TaskControlBlock>,
    ) {
        if waiters
            .iter()
            .any(|w| w.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
        {
            return;
        }
        waiters.push_back(Arc::downgrade(task));
    }

    pub(super) fn bind_local(&self, addr: SockAddrNl) -> isize {
        if addr.nl_family != AF_NETLINK {
            return err(SyscallError::EAFNOSUPPORT);
        }
        let mut st = self.state.lock();
        if st.bound.is_some() {
            return err(SyscallError::EINVAL);
        }
        st.bound = Some(SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: if addr.nl_pid == 0 {
                current_process().pid.0 as u32
            } else {
                addr.nl_pid
            },
            nl_groups: addr.nl_groups,
        });
        0
    }

    pub(super) fn local_addr(&self) -> SockAddrNl {
        self.state.lock().bound.unwrap_or(SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        })
    }

    pub(crate) fn enqueue_mq_notify(
        &self,
        mut cookie: [u8; MQ_THREAD_NOTIFY_COOKIE_LEN],
        notify_kind: u8,
    ) {
        cookie[MQ_THREAD_NOTIFY_COOKIE_LEN - 1] = notify_kind;
        let mut wake = Vec::new();
        {
            let mut st = self.state.lock();
            st.messages.push_back(cookie);
            Self::retain_blocked_waiters(&mut st.recv_waiters);
            for waiter in st.recv_waiters.drain(..) {
                if let Some(task) = waiter.upgrade() {
                    wake.push(task);
                }
            }
            wake.extend(st.poll_waiters.take_wakeups());
        }
        wake_tasks(wake);
    }

    pub(super) fn recv_packet(
        &self,
        _len: usize,
        flags: usize,
    ) -> Result<[u8; MQ_THREAD_NOTIFY_COOKIE_LEN], isize> {
        let peek = (flags & MSG_PEEK) != 0;
        let nonblock = (flags & MSG_DONTWAIT) != 0;
        loop {
            let mut st = self.state.lock();
            let msg = if peek {
                st.messages.front().copied()
            } else {
                st.messages.pop_front()
            };
            if let Some(msg) = msg {
                drop(st);
                return Ok(msg);
            }
            if nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            let Some(task) = current_task() else {
                return Err(err(SyscallError::EAGAIN));
            };
            Self::add_waiter_once(&mut st.recv_waiters, &task);
            drop(st);
            block_current_and_run_next();
        }
    }

    #[allow(dead_code)]
    pub(crate) fn poll_readable(&self) -> bool {
        !self.state.lock().messages.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn poll_writable(&self) -> bool {
        true
    }
}

impl File for NetlinkSocketFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        let len = buf.len();
        if len == 0 {
            return 0;
        }
        match self.recv_packet(len, 0) {
            Ok(msg) => copy_slice_to_user_buffer(buf, &msg[..len.min(msg.len())]),
            Err(_) => 0,
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        copy_user_buffer_to_vec(buf).len()
    }

    fn poll_mask(&self) -> i16 {
        let mut mask = POLLOUT;
        if !self.state.lock().messages.is_empty() {
            mask |= POLLIN;
        }
        mask
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut st = self.state.lock();
        st.poll_waiters.register_waiter(task)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SockAddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32, // network byte order
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SockAddrUn {
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

pub(super) fn get_file(fd: usize) -> Result<FileArc, isize> {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return Err(err(SyscallError::EBADF));
    }
    if fd < inner.fd_flags.len() && (inner.fd_flags[fd] & O_PATH) != 0 {
        return Err(err(SyscallError::EBADF));
    }
    inner.fd_table[fd].clone().ok_or(err(SyscallError::EBADF))
}

fn get_file_from_process(pid: usize, fd: usize) -> Result<FileArc, isize> {
    let Some(process) = pid2process(pid) else {
        return Err(err(SyscallError::EBADF));
    };
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return Err(err(SyscallError::EBADF));
    }
    inner.fd_table[fd].clone().ok_or(err(SyscallError::EBADF))
}

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

fn current_unix_ucred() -> UCred {
    let proc = current_process();
    let inner = proc.borrow_mut();
    UCred {
        pid: proc.pid.0 as u32,
        uid: inner.euid as u32,
        gid: inner.egid as u32,
    }
}

pub(super) fn file_key(file: &FileArc) -> usize {
    Arc::as_ptr(file) as *const () as usize
}

fn take_pending_more(key: usize) -> Option<PendingMoreState> {
    MSG_MORE_PENDING.lock().remove(&key)
}

fn put_pending_more(key: usize, state: PendingMoreState) {
    MSG_MORE_PENDING.lock().insert(key, state);
}

pub(super) fn queue_pending_more_chunk(key: usize, chunk: &[u8], udp_target: Option<UdpTarget>) {
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

pub(super) fn consume_pending_more(key: usize, payload: Vec<u8>) -> (Vec<u8>, bool, Option<UdpTarget>) {
    if let Some(mut pending) = take_pending_more(key) {
        let pending_target = pending.udp_target;
        pending.data.extend_from_slice(&payload);
        (pending.data, true, pending_target)
    } else {
        (payload, false, None)
    }
}

pub(super) fn visible_send_len(sent: usize, user_len: usize, had_pending: bool) -> isize {
    if had_pending {
        user_len as isize
    } else {
        sent as isize
    }
}

pub(super) fn visible_send_result(ret: isize, user_len: usize, had_pending: bool) -> isize {
    if ret < 0 {
        ret
    } else {
        visible_send_len(ret as usize, user_len, had_pending)
    }
}

pub(crate) fn file_supports_poll(file: &Arc<dyn File + Send + Sync>) -> bool {
    file.supports_poll()
}

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

fn copy_user_buffer_to_vec(buf: UserBuffer) -> Vec<u8> {
    let mut data = Vec::with_capacity(buf.len());
    for p in buf.into_iter() {
        // SAFETY: p is a valid pointer from UserBuffer iterator which guarantees page is mapped.
        data.push(unsafe { *p });
    }
    data
}

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

pub(super) fn parse_sockaddr_nl(user_ptr: usize, len: usize) -> Result<SockAddrNl, isize> {
    if user_ptr == 0 || len < size_of::<SockAddrNl>() {
        return Err(err(SyscallError::EINVAL));
    }
    if len > i32::MAX as usize {
        return Err(err(SyscallError::EINVAL));
    }
    let token = get_current_token();
    let Some(sa) = try_read_user_value(token, user_ptr as *const SockAddrNl) else {
        return Err(err(SyscallError::EFAULT));
    };
    if sa.nl_family != AF_NETLINK {
        if sa.nl_family != 0 {
            return Err(err(SyscallError::EAFNOSUPPORT));
        }
    }
    Ok(sa)
}

fn parse_sockaddr_un(user_ptr: usize, len: usize) -> Result<(bool, Vec<u8>), isize> {
    if user_ptr == 0 || len < size_of::<u16>() {
        return Err(err(SyscallError::EINVAL));
    }
    if len > i32::MAX as usize {
        return Err(err(SyscallError::EINVAL));
    }
    let to_copy = len.min(size_of::<SockAddrUn>());
    let token = get_current_token();
    let mut raw = vec![0u8; to_copy];
    if try_copy_from_user(token, user_ptr as *const u8, raw.as_mut_slice()).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    if family != AF_UNIX {
        return Err(err(SyscallError::EAFNOSUPPORT));
    }
    let path = &raw[size_of::<u16>()..];
    if path.is_empty() {
        return Err(err(SyscallError::EINVAL));
    }
    if path[0] == 0 {
        let mut name = path[1..].to_vec();
        while matches!(name.last(), Some(0)) {
            name.pop();
        }
        if name.is_empty() {
            return Err(err(SyscallError::EINVAL));
        }
        return Ok((true, name));
    }
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    if end == 0 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok((false, path[..end].to_vec()))
}

pub(super) fn parse_unix_bound_addr(addr: usize, addrlen: usize) -> Result<UnixBoundAddr, isize> {
    let (is_abstract, raw_name) = parse_sockaddr_un(addr, addrlen)?;
    if is_abstract {
        return Ok(UnixBoundAddr::Abstract(raw_name));
    }
    let Ok(path_part) = core::str::from_utf8(&raw_name) else {
        return Err(err(SyscallError::EINVAL));
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
                return Err(err(SyscallError::ENOENT));
            };
            if let Some(file) = weak.upgrade() {
                return Ok(file);
            }
            reg.remove(path);
            Err(err(SyscallError::ENOENT))
        }
        UnixBoundAddr::Abstract(name) => {
            let mut reg = UNIX_BOUND_ABSTRACT.lock();
            let Some(weak) = reg.get(name) else {
                return Err(err(SyscallError::ENOENT));
            };
            if let Some(file) = weak.upgrade() {
                return Ok(file);
            }
            reg.remove(name);
            Err(err(SyscallError::ENOENT))
        }
    }
}

fn register_unix_bound_socket(addr: &UnixBoundAddr, file: &FileArc) -> isize {
    match addr {
        UnixBoundAddr::Path(path) => {
            let mut reg = UNIX_BOUND_PATHS.lock();
            if let Some(existing) = reg.get(path) {
                if existing.upgrade().is_some() {
                    return err(SyscallError::EADDRINUSE);
                }
                reg.remove(path);
            }
            reg.insert(path.clone(), Arc::downgrade(file));
        }
        UnixBoundAddr::Abstract(name) => {
            let mut reg = UNIX_BOUND_ABSTRACT.lock();
            if let Some(existing) = reg.get(name) {
                if existing.upgrade().is_some() {
                    return err(SyscallError::EADDRINUSE);
                }
                reg.remove(name);
            }
            reg.insert(name.clone(), Arc::downgrade(file));
        }
    }
    0
}

pub(super) fn bind_unix_socket(file: &FileArc, sock: &UnixSocketFile, addr: usize, addrlen: usize) -> isize {
    if sock.bound_addr().is_some() {
        return err(SyscallError::EINVAL);
    }
    let bound = match parse_unix_bound_addr(addr, addrlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let UnixBoundAddr::Path(abs) = &bound {
        let Some((parent_path, name)) = split_parent_and_name(abs) else {
            return err(SyscallError::EINVAL);
        };
        let _fs_guard = ext4_lock();
        let Some(parent) = find_path_in_roots(parent_path) else {
            return err(SyscallError::ENOENT);
        };
        if !parent.is_dir() {
            return err(SyscallError::ENOTDIR);
        }
        if parent.find(name).is_some() {
            return err(SyscallError::EADDRINUSE);
        }
        if parent.create_file(name).is_err() {
            if parent.find(name).is_some() {
                return err(SyscallError::EADDRINUSE);
            }
            return err(SyscallError::EINVAL);
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

pub(super) fn write_sockaddr_nl(user_ptr: usize, user_len_ptr: usize, sa: &SockAddrNl) -> isize {
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
    let required = size_of::<SockAddrNl>();
    let copy_len = core::cmp::min(len, required);
    if copy_len > 0 {
        // SAFETY: sa is a reference to a valid SockAddrNl; copy_len <= size_of::<SockAddrNl>().
        let bytes = unsafe {
            core::slice::from_raw_parts((&*sa as *const SockAddrNl) as *const u8, copy_len)
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

pub(super) fn write_sockaddr_un(user_ptr: usize, user_len_ptr: usize, addr: Option<&UnixBoundAddr>) -> isize {
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
        // SAFETY: sa is a stack-local struct with known layout; copy_len <= size_of::<SockAddrUn>().
        let bytes = unsafe {
            core::slice::from_raw_parts((&sa as *const SockAddrUn) as *const u8, copy_len)
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

pub(super) fn iovecs_total_len(iovs: &[IoVec]) -> Result<usize, isize> {
    iovs.iter()
        .try_fold(0usize, |acc, iv| acc.checked_add(iv.len))
        .ok_or(err(SyscallError::EINVAL))
}

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
    msg.msg_namelen = value.len() as u32;
    0
}

pub(super) fn write_msg_name_in(msg: &mut MsgHdr, ip: smoltcp::wire::Ipv4Address, port: u16) -> isize {
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

pub(super) fn write_msg_name_un(msg: &mut MsgHdr, addr: Option<&UnixBoundAddr>) -> isize {
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
    // SAFETY: sa is a stack-local struct with known layout; length equals size_of::<SockAddrUn>().
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&sa as *const SockAddrUn) as *const u8,
            size_of::<SockAddrUn>(),
        )
    };
    write_msg_name_bytes(msg, bytes)
}

pub(super) fn validate_send_flags(flags: usize) -> isize {
    let known = MSG_OOB | MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE;
    if (flags & !known) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    if (flags & MSG_OOB) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    0
}

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

pub(super) fn read_msghdr(user_ptr: usize) -> Result<MsgHdr, isize> {
    if user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    try_read_user_value::<MsgHdr>(token, user_ptr as *const MsgHdr).ok_or(err(SyscallError::EFAULT))
}

pub(super) fn write_mmsghdr_msg_len(user_ptr: usize, idx: usize, msg_len: u32) -> isize {
    let token = get_current_token();
    let base = user_ptr + idx * size_of::<MMsgHdr>();
    let ptr = (base + size_of::<MsgHdr>()) as *mut u32;
    if try_write_user_value(token, ptr, &msg_len).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

pub(super) fn write_mmsghdr(user_ptr: usize, idx: usize, mmsg: &MMsgHdr) -> isize {
    let token = get_current_token();
    let ptr = (user_ptr + idx * size_of::<MMsgHdr>()) as *mut MMsgHdr;
    if try_write_user_value(token, ptr, mmsg).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

