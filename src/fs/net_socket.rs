use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::cmp::min;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::{File, POLLIN, POLLOUT, POLLRDHUP, PollWaitQueue, wake_tasks};
use crate::mm::UserBuffer;
use crate::task::processor::current_task;
use crate::task::signal::has_unmasked_pending;
use crate::task::task_block::TaskControlBlock;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address};

const TCP_RX_BUF_LEN_IPERF: usize = 128 * 1024;
const TCP_TX_BUF_LEN_IPERF: usize = 128 * 1024;
const UDP_RX_BUF_LEN: usize = 64 * 1024;
const UDP_TX_BUF_LEN: usize = 64 * 1024;
const EINTR: isize = -4;

fn pending_unmasked_signal() -> bool {
    crate::task::block_sleep::check_timer();
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_unmasked_pending(inner.pending_signals, inner.signal_mask, false)
}

fn tcp_accept_ready(state: tcp::State) -> bool {
    matches!(
        state,
        tcp::State::Established
            | tcp::State::FinWait1
            | tcp::State::FinWait2
            | tcp::State::CloseWait
            | tcp::State::Closing
            | tcp::State::LastAck
            | tcp::State::TimeWait
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetSocketKind {
    TcpStream,
    TcpListener,
    Udp,
}

enum Inner {
    TcpStream {
        handle: SocketHandle,
    },
    TcpListener {
        port: u16,
        backlog: usize,
        listen: Vec<SocketHandle>,
    },
    Udp {
        handle: SocketHandle,
        connected: Option<IpEndpoint>,
    },
}

pub struct NetSocketFile {
    inner: Mutex<Inner>,
    opts: Mutex<SocketOptions>,
    poll_waiters: Mutex<PollWaitQueue>,
}

#[derive(Debug, Clone, Copy)]
pub struct SocketOptions {
    sndbuf: u32,
    rcvbuf: u32,
    mcast_joined: bool,
    rd_shutdown: bool,
}

#[derive(Clone, Copy)]
enum PollRegistrationKind {
    TcpStream,
    TcpListener,
    Udp,
}

struct PollRegistration {
    kind: PollRegistrationKind,
    last_mask: i16,
    waiters: PollWaitQueue,
}

lazy_static! {
    static ref NET_POLL_WAITERS: Mutex<BTreeMap<SocketHandle, PollRegistration>> =
        Mutex::new(BTreeMap::new());
}

fn poll_mask_for_registered_handle(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    kind: PollRegistrationKind,
) -> i16 {
    match kind {
        PollRegistrationKind::TcpStream => {
            let s = sockets.get::<tcp::Socket>(handle);
            let mut mask = 0;
            if s.can_recv() || !s.may_recv() {
                mask |= POLLIN;
            }
            if s.can_send() || !s.may_send() {
                mask |= POLLOUT;
            }
            if !s.may_recv() {
                mask |= POLLRDHUP;
            }
            mask
        }
        PollRegistrationKind::TcpListener => {
            let s = sockets.get::<tcp::Socket>(handle);
            let mut mask = POLLOUT;
            if tcp_accept_ready(s.state()) {
                mask |= POLLIN;
            }
            mask
        }
        PollRegistrationKind::Udp => {
            let s = sockets.get::<udp::Socket>(handle);
            let mut mask = 0;
            if s.can_recv() {
                mask |= POLLIN;
            }
            if s.can_send() {
                mask |= POLLOUT;
            }
            mask
        }
    }
}

fn register_poll_waiter_for_handle(
    handle: SocketHandle,
    kind: PollRegistrationKind,
    task: &Arc<TaskControlBlock>,
) -> bool {
    let mut registrations = NET_POLL_WAITERS.lock();
    let entry = registrations
        .entry(handle)
        .or_insert_with(|| PollRegistration {
            kind,
            last_mask: 0,
            waiters: PollWaitQueue::default(),
        });
    entry.kind = kind;
    entry.waiters.register_waiter(task)
}

fn unregister_poll_waiters(handles: &[SocketHandle]) {
    let mut registrations = NET_POLL_WAITERS.lock();
    for handle in handles {
        registrations.remove(handle);
    }
}

pub(crate) fn notify_net_poll_events() {
    let mut wake = Vec::new();
    let mut registrations = NET_POLL_WAITERS.lock();
    registrations.retain(|_, entry| entry.waiters.has_waiters());
    if registrations.is_empty() {
        return;
    }
    let masks = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
        registrations
            .iter()
            .map(|(handle, entry)| {
                (
                    *handle,
                    poll_mask_for_registered_handle(sockets, *handle, entry.kind),
                )
            })
            .collect::<Vec<_>>()
    });
    for (handle, mask) in masks {
        let Some(entry) = registrations.get_mut(&handle) else {
            continue;
        };
        if mask != entry.last_mask {
            entry.last_mask = mask;
            wake.extend(entry.waiters.take_wakeups());
        }
    }
    drop(registrations);
    wake_tasks(wake);
}

impl NetSocketFile {
    pub fn new_tcp() -> Arc<Self> {
        crate::net::init();
        let handle = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
            let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
            sockets.add(tcp::Socket::new(rx, tx))
        });
        Arc::new(Self {
            inner: Mutex::new(Inner::TcpStream { handle }),
            opts: Mutex::new(SocketOptions {
                sndbuf: TCP_TX_BUF_LEN_IPERF as u32,
                rcvbuf: TCP_RX_BUF_LEN_IPERF as u32,
                mcast_joined: false,
                rd_shutdown: false,
            }),
            poll_waiters: Mutex::new(PollWaitQueue::default()),
        })
    }

    pub fn new_udp() -> Arc<Self> {
        crate::net::init();
        let handle = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let rx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; 256],
                vec![0u8; UDP_RX_BUF_LEN],
            );
            let tx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; 256],
                vec![0u8; UDP_TX_BUF_LEN],
            );
            sockets.add(udp::Socket::new(rx, tx))
        });
        Arc::new(Self {
            inner: Mutex::new(Inner::Udp {
                handle,
                connected: None,
            }),
            opts: Mutex::new(SocketOptions {
                sndbuf: UDP_TX_BUF_LEN as u32,
                rcvbuf: UDP_RX_BUF_LEN as u32,
                mcast_joined: false,
                rd_shutdown: false,
            }),
            poll_waiters: Mutex::new(PollWaitQueue::default()),
        })
    }

    fn notify_poll_waiters(&self) {
        let waiters = self.poll_waiters.lock().take_wakeups();
        wake_tasks(waiters);
    }

    pub fn set_sockbuf(&self, sndbuf: Option<u32>, rcvbuf: Option<u32>) {
        let mut opts = self.opts.lock();
        if let Some(v) = sndbuf {
            opts.sndbuf = v;
        }
        if let Some(v) = rcvbuf {
            opts.rcvbuf = v;
        }
    }

    pub fn getsockopt_sndbuf(&self) -> u32 {
        self.opts.lock().sndbuf
    }

    pub fn getsockopt_rcvbuf(&self) -> u32 {
        self.opts.lock().rcvbuf
    }

    pub fn set_multicast_joined(&self, joined: bool) {
        self.opts.lock().mcast_joined = joined;
    }

    pub fn multicast_joined(&self) -> bool {
        self.opts.lock().mcast_joined
    }

    pub fn kind(&self) -> NetSocketKind {
        match &*self.inner.lock() {
            Inner::TcpStream { .. } => NetSocketKind::TcpStream,
            Inner::TcpListener { .. } => NetSocketKind::TcpListener,
            Inner::Udp { .. } => NetSocketKind::Udp,
        }
    }

    fn snapshot(&self) -> Snapshot {
        let inner = self.inner.lock();
        match &*inner {
            Inner::TcpStream { handle } => Snapshot::TcpStream {
                handle: *handle,
                rd_shutdown: self.opts.lock().rd_shutdown,
            },
            Inner::TcpListener { listen, .. } => Snapshot::TcpListener(listen.clone()),
            Inner::Udp { handle, .. } => Snapshot::Udp(*handle),
        }
    }

    fn poll_mask_for_snapshot(snapshot: &Snapshot, sockets: &mut SocketSet<'_>) -> i16 {
        match snapshot {
            Snapshot::TcpStream {
                handle,
                rd_shutdown,
            } => {
                let s = sockets.get::<tcp::Socket>(*handle);
                let mut mask = 0;
                if s.can_recv() || !s.may_recv() {
                    mask |= POLLIN;
                }
                if s.can_send() || !s.may_send() {
                    mask |= POLLOUT;
                }
                if *rd_shutdown || !s.may_recv() {
                    mask |= POLLRDHUP;
                }
                mask
            }
            Snapshot::TcpListener(listen) => {
                let mut mask = POLLOUT;
                if listen.iter().any(|handle| {
                    let s = sockets.get::<tcp::Socket>(*handle);
                    tcp_accept_ready(s.state())
                }) {
                    mask |= POLLIN;
                }
                mask
            }
            Snapshot::Udp(handle) => {
                let s = sockets.get::<udp::Socket>(*handle);
                let mut mask = 0;
                if s.can_recv() {
                    mask |= POLLIN;
                }
                if s.can_send() {
                    mask |= POLLOUT;
                }
                mask
            }
        }
    }

    fn current_poll_mask(&self) -> i16 {
        let snapshot = self.snapshot();
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            Self::poll_mask_for_snapshot(&snapshot, sockets)
        })
    }

    fn poll_registration_handles(&self) -> Vec<(SocketHandle, PollRegistrationKind)> {
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => vec![(*handle, PollRegistrationKind::TcpStream)],
            Inner::TcpListener { listen, .. } => listen
                .iter()
                .copied()
                .map(|handle| (handle, PollRegistrationKind::TcpListener))
                .collect(),
            Inner::Udp { handle, .. } => vec![(*handle, PollRegistrationKind::Udp)],
        }
    }

    pub fn poll_readable(&self) -> bool {
        crate::net::poll();
        (self.current_poll_mask() & POLLIN) != 0
    }

    #[allow(dead_code)]
    pub fn poll_writable(&self) -> bool {
        crate::net::poll();
        (self.current_poll_mask() & POLLOUT) != 0
    }

    #[allow(dead_code)]
    pub fn poll_rdhup(&self) -> bool {
        crate::net::poll();
        (self.current_poll_mask() & POLLRDHUP) != 0
    }

    pub fn shutdown_read(&self) {
        self.opts.lock().rd_shutdown = true;
        self.notify_poll_waiters();
    }

    pub fn bind_v4(&self, ip: Ipv4Address, port: u16) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EOPNOTSUPP: isize = -95;
        let ephemeral = port == 0;
        let mut port = port;
        // Linux allows port 0 and picks an ephemeral port. Mirror that behavior
        // so libc tests that bind with port 0 succeed.
        if ephemeral {
            port = crate::net::alloc_ephemeral_port();
        }
        crate::net::poll();
        let mut inner = self.inner.lock();
        match &mut *inner {
            Inner::TcpStream { handle } => {
                crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get_mut::<tcp::Socket>(*handle);
                    s.set_bound_endpoint(IpListenEndpoint {
                        addr: Some(IpAddress::Ipv4(ip)),
                        port,
                    });
                });
                Ok(())
            }
            Inner::Udp { handle, .. } => {
                let mut last_err = EINVAL;
                // If port was zero, try a few ephemeral ports to avoid collisions.
                for _ in 0..32 {
                    let try_port = if ephemeral {
                        crate::net::alloc_ephemeral_port()
                    } else {
                        port
                    };
                    let r = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                        let s = sockets.get_mut::<udp::Socket>(*handle);
                        if ip == Ipv4Address::UNSPECIFIED {
                            // Loopback-only: bind to 127.0.0.1 explicitly.
                            s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), try_port))
                        } else {
                            s.bind((IpAddress::Ipv4(ip), try_port))
                        }
                    });
                    match r {
                        Ok(()) => return Ok(()),
                        Err(_) => {
                            last_err = EINVAL;
                            if !ephemeral {
                                break;
                            }
                        }
                    }
                }
                Err(last_err)
            }
            Inner::TcpListener { .. } => Err(EOPNOTSUPP),
        }
    }

    pub fn listen(&self, backlog: usize) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EOPNOTSUPP: isize = -95;
        let backlog = backlog.max(1).min(32);
        crate::net::poll();
        let mut inner = self.inner.lock();
        let handle = match &*inner {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let port = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<tcp::Socket>(handle);
            let bound = s.get_bound_endpoint();
            bound.port
        });
        if port == 0 {
            return Err(EINVAL);
        }
        let mut listen_handles = Vec::new();
        // Reuse the existing socket as the first listener.
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            let _ = s.listen((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
        });
        listen_handles.push(handle);
        for _ in 1..backlog {
            let h = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
                let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
                let mut s = tcp::Socket::new(rx, tx);
                let _ = s.listen((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
                sockets.add(s)
            });
            listen_handles.push(h);
        }
        *inner = Inner::TcpListener {
            port,
            backlog,
            listen: listen_handles,
        };
        drop(inner);
        self.notify_poll_waiters();
        Ok(())
    }

    pub fn accept(&self) -> Result<Arc<NetSocketFile>, isize> {
        const EOPNOTSUPP: isize = -95;
        const EAGAIN: isize = -11;
        loop {
            crate::net::poll();
            let mut inner = self.inner.lock();
            let Inner::TcpListener {
                port,
                backlog,
                listen,
            } = &mut *inner
            else {
                return Err(EOPNOTSUPP);
            };
            // Find an established connection.
            let mut idx = None;
            for (i, h) in listen.iter().enumerate() {
                let established = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get::<tcp::Socket>(*h);
                    tcp_accept_ready(s.state())
                });
                if established {
                    idx = Some(i);
                    break;
                }
            }
            if let Some(i) = idx {
                let h = listen.remove(i);
                // Maintain backlog: add a fresh listening socket.
                while listen.len() < *backlog {
                    let new_h = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_LEN_IPERF]);
                        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_LEN_IPERF]);
                        let mut s = tcp::Socket::new(rx, tx);
                        let _ = s.listen((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), *port));
                        sockets.add(s)
                    });
                    listen.push(new_h);
                }
                drop(inner);
                self.notify_poll_waiters();
                return Ok(Arc::new(NetSocketFile {
                    inner: Mutex::new(Inner::TcpStream { handle: h }),
                    opts: Mutex::new(SocketOptions {
                        sndbuf: TCP_TX_BUF_LEN_IPERF as u32,
                        rcvbuf: TCP_RX_BUF_LEN_IPERF as u32,
                        mcast_joined: false,
                        rd_shutdown: false,
                    }),
                    poll_waiters: Mutex::new(PollWaitQueue::default()),
                }));
            }
            drop(inner);
            if pending_unmasked_signal() {
                return Err(EINTR);
            }
            // Best-effort: yield and try again.
            crate::task::processor::suspend_current_and_run_next();
            // If we are used in non-blocking mode, callers will likely retry.
            let _ = EAGAIN;
        }
    }

    pub fn connect_v4(
        &self,
        ip: Ipv4Address,
        port: u16,
        local_port: Option<u16>,
    ) -> Result<(), isize> {
        const EINVAL: isize = -22;
        const EOPNOTSUPP: isize = -95;
        const EISCONN: isize = -106;
        const ECONNREFUSED: isize = -111;
        if port == 0 {
            return Err(EINVAL);
        }
        crate::net::poll();
        // Take a snapshot of what we need without holding the file mutex while touching NET.
        let (tcp_handle, udp_handle) = match &*self.inner.lock() {
            Inner::TcpStream { handle } => (Some(*handle), None),
            Inner::Udp { handle, .. } => (None, Some(*handle)),
            _ => return Err(EOPNOTSUPP),
        };

        if let Some(handle) = tcp_handle {
            let r = crate::net::with_sockets_mut(|iface, _dev, sockets| {
                let cx = iface.context();
                let bound = sockets.get::<tcp::Socket>(handle).get_bound_endpoint();
                let local = local_port
                    .or_else(|| {
                        if bound.port != 0 {
                            Some(bound.port)
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(crate::net::alloc_ephemeral_port);
                let local_ep = IpListenEndpoint {
                    addr: bound.addr,
                    port: local,
                };
                sockets.get_mut::<tcp::Socket>(handle).connect(
                    cx,
                    (IpAddress::Ipv4(ip), port),
                    local_ep,
                )
            });
            match r {
                Ok(()) => {}
                Err(tcp::ConnectError::InvalidState) => return Err(EISCONN),
                Err(tcp::ConnectError::Unaddressable) => return Err(EINVAL),
            }
            // Our userspace (musl/glibc) often assumes a blocking connect unless O_NONBLOCK is set.
            // Since we do not model per-fd nonblocking flags yet, wait until the connection is established.
            const ETIMEDOUT: isize = -110;
            let start = crate::time::get_time_ms();
            let deadline = start.saturating_add(5_000); // 5s best-effort
            loop {
                crate::net::poll();
                let st = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    sockets.get::<tcp::Socket>(handle).state()
                });
                if matches!(st, tcp::State::Established) {
                    self.notify_poll_waiters();
                    break;
                }
                if matches!(st, tcp::State::Closed) {
                    self.notify_poll_waiters();
                    return Err(ECONNREFUSED);
                }
                if crate::time::get_time_ms() >= deadline {
                    self.notify_poll_waiters();
                    return Err(ETIMEDOUT);
                }
                crate::task::processor::suspend_current_and_run_next();
            }
            return Ok(());
        }

        let Some(handle) = udp_handle else {
            return Err(EOPNOTSUPP);
        };

        // UDP "connect": remember default peer and ensure the socket has a local port.
        let remote = IpEndpoint::new(IpAddress::Ipv4(ip), port);
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<udp::Socket>(handle);
            if s.endpoint().port == 0 {
                let local = local_port.unwrap_or_else(crate::net::alloc_ephemeral_port);
                // Bind to loopback explicitly so smoltcp doesn't have to guess a source address.
                let _ = s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), local));
            }
        });
        let mut inner = self.inner.lock();
        if let Inner::Udp { connected, .. } = &mut *inner {
            *connected = Some(remote);
            drop(inner);
            self.notify_poll_waiters();
            Ok(())
        } else {
            Err(EOPNOTSUPP)
        }
    }

    pub fn tcp_send(&self, data: &[u8]) -> Result<usize, isize> {
        const EOPNOTSUPP: isize = -95;
        const EPIPE: isize = -32;
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let mut off = 0usize;
        while off < data.len() {
            crate::net::poll();
            let sent = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<tcp::Socket>(handle);
                if !s.may_send() {
                    return Err(EPIPE);
                }
                if !s.can_send() {
                    return Ok(0usize);
                }
                Ok(s.send_slice(&data[off..]).unwrap_or(0))
            })?;
            if sent == 0 {
                if pending_unmasked_signal() {
                    return Err(EINTR);
                }
                crate::task::processor::suspend_current_and_run_next();
                continue;
            }
            off += sent;
            crate::net::poll();
        }
        Ok(off)
    }

    pub fn tcp_recv(&self, buf: &mut [u8]) -> Result<usize, isize> {
        const EOPNOTSUPP: isize = -95;
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        loop {
            crate::net::poll();
            let res: Result<Option<usize>, isize> =
                crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get_mut::<tcp::Socket>(handle);
                    if s.can_recv() {
                        return Ok(Some(s.recv_slice(buf).unwrap_or(0)));
                    }
                    if !s.may_recv() {
                        return Ok(Some(0usize));
                    }
                    Ok(None)
                });
            let res = res?;
            if let Some(n) = res {
                if n > 0 {
                    crate::net::poll();
                }
                return Ok(n);
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    pub fn tcp_close(&self) -> Result<(), isize> {
        const EOPNOTSUPP: isize = -95;
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            if !matches!(s.state(), tcp::State::Closed) {
                s.close();
            }
        });
        // Drive loopback TX/RX so the peer observes FIN before we drop the handle.
        for _ in 0..8 {
            crate::net::poll();
        }
        Ok(())
    }

    pub fn udp_send_connected(&self, data: &[u8]) -> Result<usize, isize> {
        const EOPNOTSUPP: isize = -95;
        const EDESTADDRREQ: isize = -89;
        crate::net::poll();
        let (handle, remote) = match &*self.inner.lock() {
            Inner::Udp { handle, connected } => (*handle, *connected),
            _ => return Err(EOPNOTSUPP),
        };
        let Some(remote) = remote else {
            return Err(EDESTADDRREQ);
        };
        // Ensure local bind.
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<udp::Socket>(handle);
            if s.endpoint().port == 0 {
                let port = crate::net::alloc_ephemeral_port();
                let _ = s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
            }
        });
        loop {
            crate::net::poll();
            let ok = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<udp::Socket>(handle);
                if !s.can_send() {
                    return false;
                }
                s.send_slice(data, remote).is_ok()
            });
            if ok {
                crate::net::poll();
                return Ok(data.len());
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    pub fn udp_send_to_v4(&self, ip: Ipv4Address, port: u16, data: &[u8]) -> Result<usize, isize> {
        const EINVAL: isize = -22;
        const EOPNOTSUPP: isize = -95;
        if port == 0 {
            return Err(EINVAL);
        }
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        let remote = IpEndpoint::new(IpAddress::Ipv4(ip), port);
        // Ensure the socket has a local port. Unlike Linux, smoltcp requires explicit bind.
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get_mut::<udp::Socket>(handle);
            if s.endpoint().port == 0 {
                let port = crate::net::alloc_ephemeral_port();
                // Bind to loopback explicitly so smoltcp doesn't have to guess a source address.
                let _ = s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
            }
        });
        loop {
            crate::net::poll();
            let ok = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<udp::Socket>(handle);
                if !s.can_send() {
                    return false;
                }
                s.send_slice(data, remote).is_ok()
            });
            if ok {
                // Drive the loopback device to flush TX->RX.
                crate::net::poll();
                return Ok(data.len());
            }
            if pending_unmasked_signal() {
                return Err(EINTR);
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    pub fn udp_recv_from(&self, buf: &mut [u8]) -> Result<(usize, Ipv4Address, u16), isize> {
        const EOPNOTSUPP: isize = -95;
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return Err(EOPNOTSUPP),
        };
        loop {
            crate::net::poll();
            let res = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get_mut::<udp::Socket>(handle);
                if !s.can_recv() {
                    return None;
                }
                s.recv().ok().map(|(payload, meta)| {
                    let n = min(buf.len(), payload.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    (n, meta)
                })
            });
            if let Some((n, meta)) = res {
                let IpAddress::Ipv4(ip) = meta.endpoint.addr;
                if crate::debug_config::DEBUG_NET && n == 4 {
                    let v = u32::from_ne_bytes(buf[..4].try_into().unwrap_or([0; 4]));
                    crate::println!(
                        "[net] udp recv {} bytes from {}:{} val=0x{:08x}",
                        n,
                        ip,
                        meta.endpoint.port,
                        v
                    );
                }
                return Ok((n, ip, meta.endpoint.port));
            }
            if pending_unmasked_signal() {
                return Err(EINTR);
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    pub fn tcp_endpoints_v4(&self) -> Option<(Ipv4Address, u16, Ipv4Address, u16)> {
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::TcpStream { handle } => *handle,
            _ => return None,
        };
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<tcp::Socket>(handle);
            let local = s.local_endpoint()?;
            let remote = s.remote_endpoint()?;
            let IpAddress::Ipv4(lip) = local.addr;
            let IpAddress::Ipv4(rip) = remote.addr;
            Some((lip, local.port, rip, remote.port))
        })
    }

    pub fn tcp_local_endpoint_v4(&self) -> Option<(Ipv4Address, u16)> {
        crate::net::poll();
        match &*self.inner.lock() {
            Inner::TcpStream { handle } => crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                let s = sockets.get::<tcp::Socket>(*handle);
                if let Some(local) = s.local_endpoint() {
                    let IpAddress::Ipv4(ip) = local.addr;
                    return Some((ip, local.port));
                }
                let bound = s.get_bound_endpoint();
                let ip = match bound.addr {
                    Some(IpAddress::Ipv4(ip)) => ip,
                    _ => Ipv4Address::UNSPECIFIED,
                };
                Some((ip, bound.port))
            }),
            Inner::TcpListener { port, .. } => Some((Ipv4Address::new(127, 0, 0, 1), *port)),
            _ => None,
        }
    }

    pub fn udp_endpoint_v4(&self) -> Option<(Ipv4Address, u16)> {
        crate::net::poll();
        let handle = match &*self.inner.lock() {
            Inner::Udp { handle, .. } => *handle,
            _ => return None,
        };
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            let s = sockets.get::<udp::Socket>(handle);
            let ep = s.endpoint();
            let ip = match ep.addr {
                Some(IpAddress::Ipv4(ip)) => ip,
                _ => Ipv4Address::UNSPECIFIED,
            };
            Some((ip, ep.port))
        })
    }

    pub fn udp_peer_v4(&self) -> Option<(Ipv4Address, u16)> {
        crate::net::poll();
        match &*self.inner.lock() {
            Inner::Udp {
                connected: Some(peer),
                ..
            } => match peer.addr {
                IpAddress::Ipv4(ip) => Some((ip, peer.port)),
            },
            _ => None,
        }
    }
}

impl Drop for NetSocketFile {
    fn drop(&mut self) {
        let kind = match &*self.inner.lock() {
            Inner::TcpStream { .. } => NetSocketKind::TcpStream,
            Inner::TcpListener { .. } => NetSocketKind::TcpListener,
            Inner::Udp { .. } => NetSocketKind::Udp,
        };

        if kind == NetSocketKind::TcpStream {
            let _ = self.tcp_close();
        }

        let handles: Vec<SocketHandle> = match &*self.inner.lock() {
            Inner::TcpStream { handle } => vec![*handle],
            Inner::Udp { handle, .. } => vec![*handle],
            Inner::TcpListener { listen, .. } => listen.clone(),
        };
        unregister_poll_waiters(handles.as_slice());
        crate::net::with_sockets_mut(|_iface, _dev, sockets| {
            for h in handles {
                sockets.remove(h);
            }
        })
    }
}

#[derive(Clone)]
enum Snapshot {
    TcpStream {
        handle: SocketHandle,
        rd_shutdown: bool,
    },
    TcpListener(Vec<SocketHandle>),
    Udp(SocketHandle),
}

impl File for NetSocketFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        crate::net::poll();
        let inner = self.inner.lock();
        let kind = match &*inner {
            Inner::TcpStream { handle } => Some((*handle, NetSocketKind::TcpStream)),
            Inner::Udp { handle, .. } => Some((*handle, NetSocketKind::Udp)),
            Inner::TcpListener { .. } => None,
        };
        drop(inner);
        let Some((handle, kind)) = kind else {
            return 0;
        };
        match kind {
            NetSocketKind::TcpStream => {
                let mut total = 0usize;
                for slice in buf.buffers.iter_mut() {
                    loop {
                        crate::net::poll();
                        enum ReadStep {
                            Data(usize),
                            Eof,
                            Blocked,
                        }
                        let res = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                            let s = sockets.get_mut::<tcp::Socket>(handle);
                            if s.can_recv() {
                                match s.recv_slice(*slice) {
                                    Ok(n) => ReadStep::Data(n),
                                    Err(_) => ReadStep::Blocked,
                                }
                            } else if !s.may_recv() {
                                ReadStep::Eof
                            } else {
                                ReadStep::Blocked
                            }
                        });
                        match res {
                            ReadStep::Data(n) => {
                                total += n;
                                if n > 0 {
                                    crate::net::poll();
                                }
                                break;
                            }
                            ReadStep::Eof => return total,
                            ReadStep::Blocked => {}
                        }
                        crate::task::processor::suspend_current_and_run_next();
                    }
                    if slice.is_empty() {
                        break;
                    }
                }
                total
            }
            NetSocketKind::Udp => {
                // Treat read() on UDP as recv() / recvfrom() dropping peer info.
                let total_len = buf.buffers.iter().map(|b| b.len()).sum::<usize>();
                if total_len == 0 {
                    return 0;
                }
                let mut tmp = alloc::vec![0u8; total_len];
                let n = match self.udp_recv_from(&mut tmp) {
                    Ok((n, _, _)) => n,
                    Err(_) => return 0,
                };
                let mut copied = 0usize;
                for slice in buf.buffers.iter_mut() {
                    let to_copy = min(slice.len(), n - copied);
                    slice[..to_copy].copy_from_slice(&tmp[copied..copied + to_copy]);
                    copied += to_copy;
                    if copied >= n {
                        break;
                    }
                }
                copied
            }
            NetSocketKind::TcpListener => 0,
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        crate::net::poll();
        enum WriteSnapshot {
            Tcp(SocketHandle),
            Udp(SocketHandle, Option<IpEndpoint>),
            None,
        }
        let snapshot = match &*self.inner.lock() {
            Inner::TcpStream { handle } => WriteSnapshot::Tcp(*handle),
            Inner::Udp { handle, connected } => WriteSnapshot::Udp(*handle, *connected),
            Inner::TcpListener { .. } => WriteSnapshot::None,
        };
        match snapshot {
            WriteSnapshot::None => 0,
            WriteSnapshot::Tcp(handle) => {
                let mut total = 0usize;
                for slice in buf.buffers.iter() {
                    let mut off = 0usize;
                    while off < slice.len() {
                        crate::net::poll();
                        let sent = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                            let s = sockets.get_mut::<tcp::Socket>(handle);
                            if !s.can_send() {
                                return 0usize;
                            }
                            s.send_slice(&slice[off..]).unwrap_or(0)
                        });
                        if sent == 0 {
                            crate::task::processor::suspend_current_and_run_next();
                            continue;
                        }
                        off += sent;
                        total += sent;
                        crate::net::poll();
                    }
                }
                total
            }
            WriteSnapshot::Udp(handle, remote) => {
                let Some(remote) = remote else { return 0 };
                let total_len = buf.buffers.iter().map(|b| b.len()).sum::<usize>();
                if total_len == 0 {
                    return 0;
                }
                let mut data = alloc::vec![0u8; total_len];
                let mut off = 0usize;
                for slice in buf.buffers.iter() {
                    data[off..off + slice.len()].copy_from_slice(slice);
                    off += slice.len();
                }
                // Ensure local bind.
                crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                    let s = sockets.get_mut::<udp::Socket>(handle);
                    if s.endpoint().port == 0 {
                        let port = crate::net::alloc_ephemeral_port();
                        // Bind to loopback explicitly so smoltcp doesn't have to guess a source address.
                        let r = s.bind((IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), port));
                        if crate::debug_config::DEBUG_NET {
                            crate::println!("[net] udp autobind port={} -> {:?}", port, r);
                        }
                    }
                });
                loop {
                    crate::net::poll();
                    let ok = crate::net::with_sockets_mut(|_iface, _dev, sockets| {
                        let s = sockets.get_mut::<udp::Socket>(handle);
                        if !s.can_send() {
                            return false;
                        }
                        let r = s.send_slice(&data, remote);
                        if crate::debug_config::DEBUG_NET && data.len() <= 8 {
                            crate::println!(
                                "[net] udp send {} bytes to {} -> {:?}",
                                data.len(),
                                remote,
                                r
                            );
                        }
                        r.is_ok()
                    });
                    if ok {
                        // Drive the loopback device to flush TX->RX.
                        crate::net::poll();
                        return data.len();
                    }
                    crate::task::processor::suspend_current_and_run_next();
                }
            }
        }
    }

    fn poll_mask(&self) -> i16 {
        crate::net::poll();
        self.current_poll_mask()
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let _ = self.poll_waiters.lock().register_waiter(task);
        let mut armed = false;
        for (handle, kind) in self.poll_registration_handles() {
            armed = register_poll_waiter_for_handle(handle, kind, task) || armed;
        }
        armed
            || self.current_poll_mask() != 0
            || matches!(&*self.inner.lock(), Inner::TcpListener { .. })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
