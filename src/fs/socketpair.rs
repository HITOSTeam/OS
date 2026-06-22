use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::any::Any;
use spin::Mutex;

use crate::{
    bpf::BpfProgFile,
    mm::UserBuffer,
    syscall::error::{SyscallError, err},
    syscall::net::{ScmControl, SocketTimestamp, UCred, cbpf::ClassicBpfProgram},
    task::{
        manager::wakeup_task,
        processor::{block_current_and_run_next, current_task},
        signal::has_wait_interrupting_pending,
        task_block::TaskControlBlock,
    },
};

use super::{
    File, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, PollWaitQueue,
    pipe::{Pipe, make_pipe},
    wake_tasks,
};

const SOCK_DGRAM: usize = 2;

fn wait_until_deadline(deadline_ms: Option<usize>) -> Result<(), isize> {
    let Some(deadline_ms) = deadline_ms else {
        block_current_and_run_next();
        return Ok(());
    };
    let now = crate::time::get_time_ms();
    if now >= deadline_ms {
        return Err(err(SyscallError::EAGAIN));
    }
    if let Some(task) = current_task() {
        crate::task::block_sleep::add_timer(task, deadline_ms.saturating_sub(now).max(1));
    }
    block_current_and_run_next();
    Ok(())
}

/// A minimal full-duplex endpoint used to implement Unix socket pairs.
pub struct SocketPairEnd {
    backend: SocketPairBackend,
    socket_type: usize,
    opts: Mutex<SocketPairOptions>,
    peer_cred: UCred,
}

enum SocketPairBackend {
    Stream {
        read_end: Arc<Pipe>,
        write_end: Arc<Pipe>,
        recv_control: Arc<StreamControlQueue>,
        send_control: Arc<StreamControlQueue>,
    },
    Datagram {
        inbox: Arc<DatagramQueue>,
        peer: Weak<DatagramQueue>,
    },
}

struct StreamControlQueue {
    inner: Mutex<StreamControlQueueInner>,
}

struct StreamControlQueueInner {
    items: VecDeque<StreamControlItem>,
    passcred: bool,
}

struct StreamControlItem {
    /// Number of unread stream bytes before this control message becomes visible.
    bytes_before: usize,
    /// Number of bytes written by the send operation that carried this control message.
    byte_len: usize,
    control: ScmControl,
}

struct DatagramQueue {
    inner: Mutex<DatagramQueueInner>,
}

#[derive(Default)]
struct SocketPairOptions {
    reuseaddr: bool,
    dontroute: bool,
    broadcast: bool,
    keepalive: bool,
    oobinline: bool,
    linger_on: bool,
    linger_sec: i32,
    rcvlowat: i32,
    passcred: bool,
    rd_shutdown: bool,
    wr_shutdown: bool,
    rcvtimeo_ms: Option<usize>,
    sndtimeo_ms: Option<usize>,
    pending_error: i32,
    last_timestamp: Option<SocketTimestamp>,
}

#[derive(Default)]
struct DatagramQueueInner {
    packets: VecDeque<DatagramPacket>,
    read_waiters: VecDeque<Arc<TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
    passcred: bool,
    filter_locked: bool,
    classic_filter: Option<ClassicBpfProgram>,
    attached_bpf: Option<Arc<BpfProgFile>>,
    last_timestamp: Option<SocketTimestamp>,
}

struct DatagramPacket {
    payload: Vec<u8>,
    control: ScmControl,
}

impl StreamControlQueue {
    fn new() -> Self {
        Self {
            inner: Mutex::new(StreamControlQueueInner {
                items: VecDeque::new(),
                passcred: false,
            }),
        }
    }

    fn enqueue(&self, bytes_before: usize, byte_len: usize, control: ScmControl) {
        if control.is_empty() {
            return;
        }
        self.inner.lock().items.push_back(StreamControlItem {
            bytes_before,
            byte_len,
            control,
        });
    }

    fn read_len_until_control(&self, max_len: usize, passcred: bool) -> usize {
        if max_len == 0 {
            return 0;
        }
        self.inner
            .lock()
            .items
            .iter()
            .find(|item| item.control.visible_for_passcred(passcred))
            .map(|item| max_len.min(item.bytes_before.saturating_add(item.byte_len)))
            .unwrap_or(max_len)
    }

    fn recv(&self, copied: usize, peek: bool) -> ScmControl {
        if copied == 0 {
            return ScmControl::default();
        }
        let mut inner = self.inner.lock();
        if peek {
            let mut control = ScmControl::default();
            for item in inner.items.iter() {
                if copied <= item.bytes_before {
                    break;
                }
                control.merge_from(item.control.clone());
            }
            return control;
        }

        let mut control = ScmControl::default();
        loop {
            let Some(front) = inner.items.front_mut() else {
                break;
            };
            if copied <= front.bytes_before {
                front.bytes_before -= copied;
                break;
            }
            let item = inner.items.pop_front().unwrap();
            control.merge_from(item.control);
        }
        control
    }

    fn set_passcred(&self, enabled: bool) {
        self.inner.lock().passcred = enabled;
    }

    fn passcred(&self) -> bool {
        self.inner.lock().passcred
    }
}

impl DatagramQueue {
    fn new() -> Self {
        Self {
            inner: Mutex::new(DatagramQueueInner::default()),
        }
    }

    fn poll_readable(&self) -> bool {
        !self.inner.lock().packets.is_empty()
    }

    fn push_reader_once(
        waiters: &mut VecDeque<Arc<TaskControlBlock>>,
        task: Arc<TaskControlBlock>,
    ) {
        if waiters.iter().any(|t| Arc::ptr_eq(t, &task)) {
            return;
        }
        waiters.push_back(task);
    }

    fn remove_reader(waiters: &mut VecDeque<Arc<TaskControlBlock>>, task: &Arc<TaskControlBlock>) {
        waiters.retain(|t| !Arc::ptr_eq(t, task));
    }

    fn recv_to_slice(
        &self,
        out: &mut [u8],
        nonblock: bool,
        peek: bool,
        deadline_ms: Option<usize>,
        peer_alive: impl Fn() -> bool,
    ) -> Result<(usize, usize, ScmControl), isize> {
        const EAGAIN: isize = -11;
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
        };
        loop {
            let mut inner = self.inner.lock();
            if let Some(packet) = inner.packets.front() {
                let packet_len = packet.payload.len();
                let copied = core::cmp::min(out.len(), packet_len);
                out[..copied].copy_from_slice(&packet.payload[..copied]);
                let control = if peek {
                    packet.control.clone()
                } else {
                    inner
                        .packets
                        .pop_front()
                        .map(|packet| packet.control)
                        .unwrap_or_default()
                };
                if !peek {
                    inner.last_timestamp = Some(SocketTimestamp::now());
                }
                Self::remove_reader(&mut inner.read_waiters, &task);
                return Ok((copied, packet_len, control));
            }
            if !peer_alive() {
                Self::remove_reader(&mut inner.read_waiters, &task);
                return Ok((0, 0, ScmControl::default()));
            }
            if nonblock {
                Self::remove_reader(&mut inner.read_waiters, &task);
                return Err(EAGAIN);
            }
            if has_pending_signal() {
                Self::remove_reader(&mut inner.read_waiters, &task);
                return Err(err(SyscallError::EINTR));
            }
            Self::push_reader_once(&mut inner.read_waiters, task.clone());
            drop(inner);
            if let Err(e) = wait_until_deadline(deadline_ms) {
                let mut inner = self.inner.lock();
                Self::remove_reader(&mut inner.read_waiters, &task);
                return Err(e);
            }
        }
    }

    fn enqueue(&self, packet: Vec<u8>, control: ScmControl) -> Result<usize, isize> {
        let len = packet.len();
        let (reader, pollers) = {
            let mut inner = self.inner.lock();
            let mut packet = packet;
            if let Some(filter) = inner.classic_filter.as_ref() {
                let Some(snaplen) = filter.filter_len(&packet) else {
                    return Ok(len);
                };
                packet.truncate(snaplen);
            }
            if let Some(filter) = inner.attached_bpf.as_ref() {
                let Some(snaplen) = filter.filter_len(&packet) else {
                    return Ok(len);
                };
                packet.truncate(snaplen);
            }
            inner.packets.push_back(DatagramPacket {
                payload: packet,
                control,
            });
            (
                inner.read_waiters.pop_front(),
                inner.poll_waiters.take_wakeups(),
            )
        };
        if let Some(reader) = reader {
            wakeup_task(reader);
        }
        wake_tasks(pollers);
        Ok(len)
    }

    fn set_passcred(&self, enabled: bool) {
        self.inner.lock().passcred = enabled;
    }

    fn passcred(&self) -> bool {
        self.inner.lock().passcred
    }

    fn attach_filter(&self, filter: ClassicBpfProgram) -> isize {
        let mut inner = self.inner.lock();
        if inner.filter_locked {
            return err(SyscallError::EPERM);
        }
        inner.classic_filter = Some(filter);
        inner.attached_bpf = None;
        0
    }

    fn attach_bpf(&self, prog: Arc<BpfProgFile>) -> isize {
        let mut inner = self.inner.lock();
        if inner.filter_locked {
            return err(SyscallError::EPERM);
        }
        inner.classic_filter = None;
        inner.attached_bpf = Some(prog);
        0
    }

    fn detach_filter(&self) -> isize {
        let mut inner = self.inner.lock();
        if inner.filter_locked {
            return err(SyscallError::EPERM);
        }
        let had_filter =
            inner.classic_filter.take().is_some() | inner.attached_bpf.take().is_some();
        if had_filter {
            0
        } else {
            err(SyscallError::ENOENT)
        }
    }

    fn set_filter_locked(&self, locked: bool) -> isize {
        let mut inner = self.inner.lock();
        if inner.filter_locked && !locked {
            return err(SyscallError::EPERM);
        }
        inner.filter_locked = locked;
        0
    }

    fn filter_locked(&self) -> bool {
        self.inner.lock().filter_locked
    }

    fn classic_filter_snapshot(&self) -> (Option<ClassicBpfProgram>, bool) {
        let inner = self.inner.lock();
        (inner.classic_filter.clone(), inner.attached_bpf.is_some())
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        self.inner.lock().poll_waiters.register_waiter(task)
    }

    fn wake_all(&self) {
        let (readers, pollers) = {
            let mut inner = self.inner.lock();
            (
                inner.read_waiters.drain(..).collect::<Vec<_>>(),
                inner.poll_waiters.take_wakeups(),
            )
        };
        wake_tasks(readers);
        wake_tasks(pollers);
    }
}

impl SocketPairEnd {
    fn new_stream(
        read_end: Arc<Pipe>,
        write_end: Arc<Pipe>,
        recv_control: Arc<StreamControlQueue>,
        send_control: Arc<StreamControlQueue>,
        socket_type: usize,
    ) -> Self {
        Self {
            backend: SocketPairBackend::Stream {
                read_end,
                write_end,
                recv_control,
                send_control,
            },
            socket_type,
            peer_cred: UCred::current(),
            opts: Mutex::new(SocketPairOptions {
                rcvlowat: 1,
                ..SocketPairOptions::default()
            }),
        }
    }

    fn new_datagram(
        inbox: Arc<DatagramQueue>,
        peer: Weak<DatagramQueue>,
        socket_type: usize,
    ) -> Self {
        Self {
            backend: SocketPairBackend::Datagram { inbox, peer },
            socket_type,
            peer_cred: UCred::current(),
            opts: Mutex::new(SocketPairOptions {
                rcvlowat: 1,
                ..SocketPairOptions::default()
            }),
        }
    }

    pub fn socket_type(&self) -> usize {
        self.socket_type
    }

    pub fn peer_cred(&self) -> UCred {
        self.peer_cred
    }

    pub fn is_dgram(&self) -> bool {
        self.socket_type == SOCK_DGRAM
    }

    pub fn set_reuseaddr(&self, enabled: bool) {
        self.opts.lock().reuseaddr = enabled;
    }

    pub fn reuseaddr(&self) -> bool {
        self.opts.lock().reuseaddr
    }

    pub fn set_dontroute(&self, enabled: bool) {
        self.opts.lock().dontroute = enabled;
    }

    pub fn dontroute(&self) -> bool {
        self.opts.lock().dontroute
    }

    pub fn set_broadcast(&self, enabled: bool) {
        self.opts.lock().broadcast = enabled;
    }

    pub fn broadcast(&self) -> bool {
        self.opts.lock().broadcast
    }

    pub fn set_keepalive(&self, enabled: bool) {
        self.opts.lock().keepalive = enabled;
    }

    pub fn keepalive(&self) -> bool {
        self.opts.lock().keepalive
    }

    pub fn set_oobinline(&self, enabled: bool) {
        self.opts.lock().oobinline = enabled;
    }

    pub fn oobinline(&self) -> bool {
        self.opts.lock().oobinline
    }

    pub fn set_linger(&self, on: bool, sec: i32) {
        let mut opts = self.opts.lock();
        opts.linger_on = on;
        opts.linger_sec = sec;
    }

    pub fn linger(&self) -> (bool, i32) {
        let opts = self.opts.lock();
        (opts.linger_on, opts.linger_sec)
    }

    pub fn set_rcvlowat(&self, value: i32) {
        self.opts.lock().rcvlowat = value;
    }

    pub fn rcvlowat(&self) -> i32 {
        self.opts.lock().rcvlowat
    }

    fn rcvlowat_bytes(&self) -> usize {
        self.opts.lock().rcvlowat.max(1) as usize
    }

    pub fn set_rcvtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.opts.lock().rcvtimeo_ms = timeout_ms;
    }

    pub fn rcvtimeo_ms(&self) -> Option<usize> {
        self.opts.lock().rcvtimeo_ms
    }

    pub fn rcvtimeo_deadline_ms(&self) -> Option<usize> {
        self.rcvtimeo_ms()
            .map(|ms| crate::time::get_time_ms().saturating_add(ms))
    }

    pub fn set_sndtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.opts.lock().sndtimeo_ms = timeout_ms;
    }

    pub fn sndtimeo_ms(&self) -> Option<usize> {
        self.opts.lock().sndtimeo_ms
    }

    fn sndtimeo_deadline_ms(&self) -> Option<usize> {
        self.sndtimeo_ms()
            .map(|ms| crate::time::get_time_ms().saturating_add(ms))
    }

    pub fn set_passcred(&self, enabled: bool) {
        self.opts.lock().passcred = enabled;
        match &self.backend {
            SocketPairBackend::Stream { recv_control, .. } => recv_control.set_passcred(enabled),
            SocketPairBackend::Datagram { inbox, .. } => inbox.set_passcred(enabled),
        }
    }

    pub fn passcred(&self) -> bool {
        self.opts.lock().passcred
    }

    fn peer_passcred(&self) -> bool {
        match &self.backend {
            SocketPairBackend::Stream { send_control, .. } => send_control.passcred(),
            SocketPairBackend::Datagram { peer, .. } => {
                peer.upgrade().is_some_and(|peer| peer.passcred())
            }
        }
    }

    fn prepare_send_control(&self, control: &mut ScmControl) {
        control
            .ensure_credentials_if(self.passcred() || self.peer_passcred() || control.has_rights());
    }

    fn set_socket_error(&self, errno: isize) {
        if errno >= 0 {
            return;
        }
        self.opts.lock().pending_error = (-errno) as i32;
    }

    pub fn take_socket_error(&self) -> u32 {
        let mut opts = self.opts.lock();
        let errno = opts.pending_error.max(0) as u32;
        opts.pending_error = 0;
        errno
    }

    pub fn poll_readable(&self) -> bool {
        if self.opts.lock().rd_shutdown {
            return true;
        }
        self.poll_readable_with_lowat(self.rcvlowat_bytes())
    }

    pub(crate) fn poll_readable_with_lowat(&self, lowat: usize) -> bool {
        match &self.backend {
            SocketPairBackend::Stream { read_end, .. } => {
                let queued = read_end.queued_bytes();
                queued >= lowat.max(1) || read_end.all_write_ends_closed()
            }
            SocketPairBackend::Datagram { inbox, peer } => {
                inbox.poll_readable() || peer.upgrade().is_none()
            }
        }
    }

    pub fn poll_writable(&self) -> bool {
        if self.opts.lock().wr_shutdown {
            return false;
        }
        match &self.backend {
            SocketPairBackend::Stream { write_end, .. } => write_end.poll_writable(),
            SocketPairBackend::Datagram { peer, .. } => peer.upgrade().is_some(),
        }
    }

    #[allow(dead_code)]
    pub fn read_to_slice(&self, out: &mut [u8], nonblock: bool) -> Result<usize, isize> {
        let (copied, _, _) = self.recv_to_slice(out, nonblock, false)?;
        Ok(copied)
    }

    pub fn recv_to_slice(
        &self,
        out: &mut [u8],
        nonblock: bool,
        peek: bool,
    ) -> Result<(usize, usize, ScmControl), isize> {
        if self.opts.lock().rd_shutdown {
            return Ok((0, 0, ScmControl::default()));
        }
        let deadline_ms = (!nonblock).then(|| self.rcvtimeo_deadline_ms()).flatten();
        match &self.backend {
            SocketPairBackend::Stream {
                read_end,
                recv_control,
                ..
            } => {
                let read_len = recv_control.read_len_until_control(out.len(), self.passcred());
                let out = &mut out[..read_len];
                if !out.is_empty() {
                    let lowat = if nonblock {
                        1
                    } else {
                        core::cmp::min(self.rcvlowat_bytes(), out.len())
                    };
                    read_end.wait_readable_lowat(lowat, nonblock, deadline_ms, true)?;
                }
                let copied = if peek {
                    read_end.peek_to_slice_with_deadline(out, nonblock, deadline_ms)?
                } else {
                    read_end.read_to_slice_with_deadline(out, nonblock, deadline_ms)?
                };
                let control = if copied > 0 {
                    recv_control.recv(copied, peek)
                } else {
                    ScmControl::default()
                };
                if copied > 0 && !peek {
                    self.opts.lock().last_timestamp = Some(SocketTimestamp::now());
                }
                Ok((copied, copied, control))
            }
            SocketPairBackend::Datagram { inbox, peer } => {
                inbox.recv_to_slice(out, nonblock, peek, deadline_ms, || {
                    peer.upgrade().is_some()
                })
            }
        }
    }

    pub fn socket_timestamp(&self) -> Option<SocketTimestamp> {
        match &self.backend {
            SocketPairBackend::Stream { .. } => self.opts.lock().last_timestamp,
            SocketPairBackend::Datagram { inbox, .. } => inbox.inner.lock().last_timestamp,
        }
    }

    pub fn write_from_slice(&self, data: &[u8], nonblock: bool) -> Result<usize, isize> {
        self.write_from_slice_with_control(data, nonblock, ScmControl::default())
    }

    pub fn write_from_slice_with_control(
        &self,
        data: &[u8],
        nonblock: bool,
        mut control: ScmControl,
    ) -> Result<usize, isize> {
        if self.opts.lock().wr_shutdown {
            let e = err(SyscallError::EPIPE);
            self.set_socket_error(e);
            return Err(e);
        }
        self.prepare_send_control(&mut control);
        match &self.backend {
            SocketPairBackend::Stream {
                write_end,
                send_control,
                ..
            } => {
                if !control.is_empty() && data.is_empty() {
                    return Err(err(SyscallError::EINVAL));
                }
                let deadline_ms = (!nonblock).then(|| self.sndtimeo_deadline_ms()).flatten();
                let bytes_before = write_end.queued_bytes();
                let written =
                    match write_end.write_from_slice_with_deadline(data, nonblock, deadline_ms) {
                        Ok(v) => v,
                        Err(e) => {
                            self.set_socket_error(e);
                            return Err(e);
                        }
                    };
                if written == 0 && !data.is_empty() && write_end.all_read_ends_closed() {
                    let e = err(SyscallError::EPIPE);
                    self.set_socket_error(e);
                    return Err(e);
                }
                if written > 0 {
                    send_control.enqueue(bytes_before, written, control);
                }
                Ok(written)
            }
            SocketPairBackend::Datagram { peer, .. } => {
                let Some(peer) = peer.upgrade() else {
                    let e = err(SyscallError::EPIPE);
                    self.set_socket_error(e);
                    return Err(e);
                };
                let _ = nonblock;
                match peer.enqueue(data.to_vec(), control) {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        self.set_socket_error(e);
                        Err(e)
                    }
                }
            }
        }
    }

    pub fn shutdown(&self, how: usize) -> Result<(), isize> {
        let rd = how == 0 || how == 2;
        let wr = how == 1 || how == 2;
        {
            let mut opts = self.opts.lock();
            if rd {
                opts.rd_shutdown = true;
            }
            if wr {
                opts.wr_shutdown = true;
            }
        }
        match &self.backend {
            SocketPairBackend::Stream {
                read_end,
                write_end,
                ..
            } => {
                if rd {
                    read_end.shutdown_read_end();
                }
                if wr {
                    write_end.shutdown_write_end();
                }
            }
            SocketPairBackend::Datagram { inbox, .. } => {
                if rd {
                    inbox.wake_all();
                }
            }
        }
        Ok(())
    }

    pub fn attach_filter(&self, filter: ClassicBpfProgram) -> isize {
        match &self.backend {
            SocketPairBackend::Stream { read_end, .. } => read_end.attach_filter(filter),
            SocketPairBackend::Datagram { inbox, .. } => inbox.attach_filter(filter),
        }
    }

    pub fn attach_bpf(&self, prog: Arc<BpfProgFile>) -> isize {
        match &self.backend {
            SocketPairBackend::Stream { read_end, .. } => read_end.attach_bpf(prog),
            SocketPairBackend::Datagram { inbox, .. } => inbox.attach_bpf(prog),
        }
    }

    pub fn detach_filter(&self) -> isize {
        match &self.backend {
            SocketPairBackend::Stream { read_end, .. } => read_end.detach_filter(),
            SocketPairBackend::Datagram { inbox, .. } => inbox.detach_filter(),
        }
    }

    pub fn set_filter_locked(&self, locked: bool) -> isize {
        match &self.backend {
            SocketPairBackend::Stream { read_end, .. } => read_end.set_filter_locked(locked),
            SocketPairBackend::Datagram { inbox, .. } => inbox.set_filter_locked(locked),
        }
    }

    pub fn filter_locked(&self) -> bool {
        match &self.backend {
            SocketPairBackend::Stream { read_end, .. } => read_end.filter_locked(),
            SocketPairBackend::Datagram { inbox, .. } => inbox.filter_locked(),
        }
    }

    pub fn classic_filter_snapshot(&self) -> (Option<ClassicBpfProgram>, bool) {
        match &self.backend {
            SocketPairBackend::Stream { read_end, .. } => read_end.classic_filter_snapshot(),
            SocketPairBackend::Datagram { inbox, .. } => inbox.classic_filter_snapshot(),
        }
    }
}

impl Drop for SocketPairEnd {
    fn drop(&mut self) {
        crate::syscall::net::clear_msg_more_pending_for_addr(self as *const Self as usize);
        if let SocketPairBackend::Datagram { peer, .. } = &self.backend {
            if let Some(peer) = peer.upgrade() {
                peer.wake_all();
            }
        }
    }
}

/// Create a bidirectional pair of endpoints.
pub fn make_socketpair() -> (Arc<SocketPairEnd>, Arc<SocketPairEnd>) {
    make_socketpair_with_type(1)
}

/// Create a bidirectional pair of endpoints with the userspace-visible socket type.
pub fn make_socketpair_with_type(socket_type: usize) -> (Arc<SocketPairEnd>, Arc<SocketPairEnd>) {
    if socket_type == SOCK_DGRAM {
        let queue0 = Arc::new(DatagramQueue::new());
        let queue1 = Arc::new(DatagramQueue::new());
        let end0 = Arc::new(SocketPairEnd::new_datagram(
            queue0.clone(),
            Arc::downgrade(&queue1),
            socket_type,
        ));
        let end1 = Arc::new(SocketPairEnd::new_datagram(
            queue1,
            Arc::downgrade(&queue0),
            socket_type,
        ));
        return (end0, end1);
    }

    // Two one-way pipes to form a full-duplex channel.
    let (a_to_b_r, a_to_b_w) = make_pipe();
    let (b_to_a_r, b_to_a_w) = make_pipe();
    let a_to_b_ctl = Arc::new(StreamControlQueue::new());
    let b_to_a_ctl = Arc::new(StreamControlQueue::new());

    let end0 = Arc::new(SocketPairEnd::new_stream(
        b_to_a_r,
        a_to_b_w,
        b_to_a_ctl.clone(),
        a_to_b_ctl.clone(),
        socket_type,
    ));
    let end1 = Arc::new(SocketPairEnd::new_stream(
        a_to_b_r,
        b_to_a_w,
        a_to_b_ctl,
        b_to_a_ctl,
        socket_type,
    ));
    (end0, end1)
}

impl File for SocketPairEnd {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        self.poll_writable()
    }

    fn read(&self, buf: UserBuffer) -> usize {
        match &self.backend {
            SocketPairBackend::Stream { .. } => {
                let len = buf.len();
                if len == 0 {
                    return 0;
                }
                let mut data = Vec::with_capacity(len);
                data.resize(len, 0);
                let Ok((copied, _, _)) = self.recv_to_slice(&mut data, false, false) else {
                    return 0;
                };
                for (dst, src) in buf.into_iter().zip(data.iter().take(copied)) {
                    unsafe {
                        *dst = *src;
                    }
                }
                copied
            }
            SocketPairBackend::Datagram { .. } => {
                let len = buf.len();
                if len == 0 {
                    return 0;
                }
                let mut data = Vec::with_capacity(len);
                data.resize(len, 0);
                let Ok((copied, _, _)) = self.recv_to_slice(&mut data, false, false) else {
                    return 0;
                };
                for (dst, src) in buf.into_iter().zip(data.iter().take(copied)) {
                    unsafe {
                        *dst = *src;
                    }
                }
                copied
            }
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        match &self.backend {
            SocketPairBackend::Stream { .. } | SocketPairBackend::Datagram { .. } => {
                let len = buf.len();
                if len == 0 {
                    return 0;
                }
                let mut data = Vec::with_capacity(len);
                for byte_ref in buf.into_iter() {
                    unsafe {
                        data.push(*byte_ref);
                    }
                }
                self.write_from_slice(&data, false).unwrap_or(0)
            }
        }
    }

    fn poll_mask(&self) -> i16 {
        let (rd_shutdown, wr_shutdown, pending_error) = {
            let opts = self.opts.lock();
            (opts.rd_shutdown, opts.wr_shutdown, opts.pending_error != 0)
        };
        let err_mask = if pending_error { POLLERR } else { 0 };
        match &self.backend {
            SocketPairBackend::Stream {
                read_end,
                write_end,
                ..
            } => {
                let read_mask = if rd_shutdown {
                    let mut mask = POLLIN | POLLRDHUP;
                    if wr_shutdown {
                        mask |= POLLHUP;
                    }
                    mask
                } else if self.poll_readable_with_lowat(self.rcvlowat_bytes()) {
                    let mut mask = POLLIN;
                    if read_end.all_write_ends_closed() {
                        mask |= POLLRDHUP;
                        if wr_shutdown {
                            mask |= POLLHUP;
                        }
                    }
                    mask
                } else {
                    let mut mask = read_end.poll_mask() & !POLLIN;
                    if (mask & POLLHUP) != 0 {
                        mask &= !POLLHUP;
                        mask |= POLLRDHUP;
                        if wr_shutdown {
                            mask |= POLLHUP;
                        }
                    }
                    mask
                };
                let write_mask = if wr_shutdown {
                    POLLERR
                } else {
                    write_end.poll_mask()
                };
                (read_mask & (POLLIN | POLLRDHUP | POLLHUP))
                    | (write_mask & (POLLOUT | POLLERR))
                    | err_mask
            }
            SocketPairBackend::Datagram { inbox, peer } => {
                let mut mask = err_mask;
                if rd_shutdown || inbox.poll_readable() {
                    mask |= POLLIN;
                }
                if !wr_shutdown && peer.upgrade().is_some() {
                    mask |= POLLOUT;
                } else {
                    mask |= POLLHUP | POLLERR;
                }
                mask
            }
        }
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(
        &self,
        task: &alloc::sync::Arc<crate::task::task_block::TaskControlBlock>,
    ) -> bool {
        match &self.backend {
            SocketPairBackend::Stream {
                read_end,
                write_end,
                ..
            } => {
                let _ = read_end.register_poll_waiter(task);
                let _ = write_end.register_poll_waiter(task);
                true
            }
            SocketPairBackend::Datagram { inbox, .. } => inbox.register_poll_waiter(task),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
