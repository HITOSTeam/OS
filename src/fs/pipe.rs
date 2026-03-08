use alloc::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use spin::Mutex;

use crate::{
    bpf::BpfProgFile,
    debug_config::DEBUG_UNIXBENCH,
    fs::{File, find_path_in_roots},
    mm::UserBuffer,
    task::{
        manager::{PID2PCB, wakeup_task},
        processor::{block_current_and_run_next, current_process, current_task},
        signal::{SIGPIPE_NUM, has_unmasked_pending, queue_process_signal_info, signal_bit},
        task_block::TaskControlBlock,
    },
};

// A small pipe buffer makes typical shell pipelines (busybox/ash, rt-tests) extremely
// slow and can even deadlock if producers/consumers don't run concurrently.
const PIPE_BUF: usize = 4096;
const DEFAULT_PIPE_CAPACITY: usize = 16 * PIPE_BUF;
const MAX_PIPE_CAPACITY: usize = DEFAULT_PIPE_CAPACITY;
const SIGIO_NUM: i32 = 29;
const CAP_SYS_RESOURCE: usize = 24;
const F_OWNER_TID: i32 = 0;
const F_OWNER_PID: i32 = 1;
const F_OWNER_PGRP: i32 = 2;

fn has_cap_sys_resource() -> bool {
    let proc = current_process();
    let inner = proc.borrow_mut();
    inner.euid == 0 && (inner.cap_effective & (1u64 << CAP_SYS_RESOURCE)) != 0
}

fn pipe_max_size_limit() -> usize {
    let Some(inode) = find_path_in_roots("/proc/sys/fs/pipe-max-size") else {
        return DEFAULT_PIPE_CAPACITY;
    };
    let mut buf = [0u8; 32];
    let len = inode.read_at(0, &mut buf);
    if len == 0 {
        return DEFAULT_PIPE_CAPACITY;
    }
    let Ok(raw) = core::str::from_utf8(&buf[..len]) else {
        return DEFAULT_PIPE_CAPACITY;
    };
    let Ok(value) = raw.trim().parse::<usize>() else {
        return DEFAULT_PIPE_CAPACITY;
    };
    value.clamp(PIPE_BUF, MAX_PIPE_CAPACITY)
}

fn default_pipe_capacity_for_current() -> usize {
    if has_cap_sys_resource() {
        DEFAULT_PIPE_CAPACITY
    } else {
        DEFAULT_PIPE_CAPACITY.min(pipe_max_size_limit())
    }
}
//  Pipe 是一个包装器,包装 具体的 队列
pub struct Pipe {
    readable: bool,
    writable: bool,
    buffer: Arc<Mutex<PipeRingBuffer>>,
}

impl Pipe {
    pub fn read_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: true,
            writable: false,
            buffer,
        }
    }
    pub fn write_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: false,
            writable: true,
            buffer,
        }
    }

    pub fn poll_readable(&self) -> bool {
        if !self.readable {
            return false;
        }
        let ring = self.buffer.lock();
        ring.available_read() > 0 || ring.all_write_ends_closed()
    }

    pub fn poll_writable(&self) -> bool {
        if !self.writable {
            return false;
        }
        let ring = self.buffer.lock();
        ring.available_write() >= ring.poll_writable_threshold() || ring.all_read_ends_closed()
    }

    pub fn available_read(&self) -> usize {
        if !self.readable {
            return 0;
        }
        self.buffer.lock().available_read()
    }

    /// Number of unread bytes currently buffered in the pipe, regardless of
    /// whether this handle is a read end or a write end.
    pub fn queued_bytes(&self) -> usize {
        self.buffer.lock().available_read()
    }

    pub fn available_write(&self) -> usize {
        if !self.writable {
            return 0;
        }
        self.buffer.lock().available_write()
    }

    pub fn pipe_size(&self) -> usize {
        self.buffer.lock().pipe_size()
    }

    pub fn set_pipe_size(&self, size: usize) -> Result<usize, isize> {
        self.buffer.lock().set_pipe_size(size)
    }

    pub fn set_end_ref_bias(&self, read_bias: usize, write_bias: usize) {
        self.buffer.lock().set_end_ref_bias(read_bias, write_bias);
    }

    pub fn attach_bpf(&self, prog: Arc<BpfProgFile>) {
        self.buffer.lock().attached_bpf = Some(prog);
    }

    pub fn attached_bpf(&self) -> Option<Arc<BpfProgFile>> {
        self.buffer.lock().attached_bpf.clone()
    }

    pub fn set_async_enabled(&self, enabled: bool) {
        if !self.readable {
            return;
        }
        self.buffer.lock().async_enabled = enabled;
    }

    pub fn get_async_owner(&self) -> (i32, i32) {
        let ring = self.buffer.lock();
        (ring.async_owner_type, ring.async_owner_pid)
    }

    pub fn set_async_owner(&self, owner_type: i32, owner_pid: i32) -> Result<(), isize> {
        const EINVAL: isize = -22;
        if !self.readable {
            return Err(EINVAL);
        }
        if !matches!(owner_type, F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP) {
            return Err(EINVAL);
        }
        if owner_pid < 0 {
            return Err(EINVAL);
        }
        let mut ring = self.buffer.lock();
        ring.async_owner_type = owner_type;
        ring.async_owner_pid = owner_pid;
        Ok(())
    }

    pub fn set_async_fd(&self, fd: i32) -> Result<(), isize> {
        const EINVAL: isize = -22;
        if !self.readable || fd < 0 {
            return Err(EINVAL);
        }
        self.buffer.lock().async_fd = fd;
        Ok(())
    }

    pub fn get_async_signal(&self) -> i32 {
        self.buffer.lock().async_signal
    }

    pub fn set_async_signal(&self, sig: i32) -> Result<(), isize> {
        const EINVAL: isize = -22;
        if sig < 0 || sig > 64 {
            return Err(EINVAL);
        }
        if !self.readable {
            return Err(EINVAL);
        }
        self.buffer.lock().async_signal = sig;
        Ok(())
    }

    pub fn open_read_end_count(&self) -> usize {
        self.buffer.lock().read_end_count()
    }

    pub fn open_write_end_count(&self) -> usize {
        self.buffer.lock().write_end_count()
    }

    pub fn all_read_ends_closed(&self) -> bool {
        self.buffer.lock().all_read_ends_closed()
    }

    pub fn same_buffer(&self, other: &Pipe) -> bool {
        Arc::ptr_eq(&self.buffer, &other.buffer)
    }

    pub fn read_to_slice(&self, out: &mut [u8], nonblock: bool) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        assert!(self.readable());
        if out.is_empty() {
            return Ok(0);
        }
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_unmasked_pending(inner.pending_signals, inner.signal_mask, true)
        };
        loop {
            let mut ring_buffer = self.buffer.lock();
            let avail = ring_buffer.available_read();
            if avail == 0 {
                if ring_buffer.all_write_ends_closed() {
                    ring_buffer.remove_reader(&task);
                    return Ok(0);
                }
                if nonblock {
                    ring_buffer.remove_reader(&task);
                    return Err(EAGAIN);
                }
                if has_pending_signal() {
                    ring_buffer.remove_reader(&task);
                    return Ok(0);
                }
                ring_buffer.push_reader(task.clone());
                drop(ring_buffer);
                block_current_and_run_next();
                continue;
            }
            let to_read = core::cmp::min(avail, out.len());
            for byte in out.iter_mut().take(to_read) {
                *byte = ring_buffer.read_byte();
            }
            let writer = ring_buffer.pop_writer();
            drop(ring_buffer);
            if let Some(writer) = writer {
                wakeup_task(writer);
            }
            return Ok(to_read);
        }
    }

    pub fn write_from_slice(&self, data: &[u8], nonblock: bool) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        assert!(self.writable());
        if data.is_empty() {
            return Ok(0);
        }
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_unmasked_pending(inner.pending_signals, inner.signal_mask, true)
        };
        let mut written = 0usize;
        loop {
            let mut ring_buffer = self.buffer.lock();
            if ring_buffer.all_read_ends_closed() {
                if let Some(bit) = signal_bit(SIGPIPE_NUM) {
                    task.borrow_mut().pending_signals |= bit;
                }
                ring_buffer.remove_writer(&task);
                return Ok(written);
            }
            let avail = ring_buffer.available_write();
            let remaining = data.len() - written;
            if avail == 0 || (remaining <= PIPE_BUF && avail < remaining && written == 0) {
                if nonblock {
                    ring_buffer.remove_writer(&task);
                    return if written > 0 {
                        Ok(written)
                    } else {
                        Err(EAGAIN)
                    };
                }
                if has_pending_signal() {
                    ring_buffer.remove_writer(&task);
                    return Ok(written);
                }
                ring_buffer.push_writer(task.clone());
                drop(ring_buffer);
                block_current_and_run_next();
                continue;
            }
            let mut to_write = remaining;
            if nonblock && to_write > PIPE_BUF {
                to_write = to_write.min(avail);
            }
            for byte in data[written..written + to_write].iter().copied() {
                ring_buffer.write_byte(byte);
            }
            written += to_write;
            let reader_to_wake = if to_write > 0 {
                ring_buffer.pop_reader()
            } else {
                None
            };
            let async_notify = if to_write > 0 {
                ring_buffer.async_target()
            } else {
                None
            };
            let attached_bpf = if to_write > 0 {
                ring_buffer.attached_bpf.clone()
            } else {
                None
            };
            let bpf_packet = if to_write > 0 && attached_bpf.is_some() {
                Some(data[written - to_write..written].to_vec())
            } else {
                None
            };
            drop(ring_buffer);
            if let (Some(prog), Some(packet)) = (attached_bpf, bpf_packet) {
                prog.run_packet(packet.as_slice());
            }
            if let Some((owner_type, owner_pid, sig, fd)) = async_notify {
                notify_async_io(owner_type, owner_pid, sig, fd);
            }
            if let Some(reader) = reader_to_wake {
                wakeup_task(reader);
            }
            if written == data.len() || nonblock {
                return Ok(written);
            }
        }
    }

    pub fn peek_to_slice(&self, out: &mut [u8], nonblock: bool) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        assert!(self.readable());
        if out.is_empty() {
            return Ok(0);
        }
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_unmasked_pending(inner.pending_signals, inner.signal_mask, true)
        };
        loop {
            let mut ring_buffer = self.buffer.lock();
            let avail = ring_buffer.available_read();
            if avail == 0 {
                if ring_buffer.all_write_ends_closed() {
                    ring_buffer.remove_reader(&task);
                    return Ok(0);
                }
                if nonblock {
                    ring_buffer.remove_reader(&task);
                    return Err(EAGAIN);
                }
                if has_pending_signal() {
                    ring_buffer.remove_reader(&task);
                    return Ok(0);
                }
                ring_buffer.push_reader(task.clone());
                drop(ring_buffer);
                block_current_and_run_next();
                continue;
            }
            return Ok(ring_buffer.peek_into(out));
        }
    }
}
#[derive(Copy, Clone, PartialEq)]
enum RingBufferStatus {
    FULL,
    EMPTY,
    NORMAL,
}

pub struct PipeRingBuffer {
    arr: Vec<u8>,
    attached_bpf: Option<Arc<BpfProgFile>>,
    capacity: usize,
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    read_end: Option<Weak<Pipe>>,
    write_end: Option<Weak<Pipe>>,
    read_end_ref_bias: usize,
    write_end_ref_bias: usize,
    read_waiters: VecDeque<Arc<crate::task::task_block::TaskControlBlock>>,
    write_waiters: VecDeque<Arc<crate::task::task_block::TaskControlBlock>>,
    async_enabled: bool,
    async_owner_type: i32,
    async_owner_pid: i32,
    async_signal: i32,
    async_fd: i32,
}

impl PipeRingBuffer {
    pub fn new() -> Self {
        let capacity = default_pipe_capacity_for_current();
        Self {
            arr: vec![0; MAX_PIPE_CAPACITY],
            attached_bpf: None,
            capacity,
            head: 0,
            tail: 0,
            status: RingBufferStatus::EMPTY,
            read_end: None,
            write_end: None,
            read_end_ref_bias: 0,
            write_end_ref_bias: 0,
            read_waiters: VecDeque::new(),
            write_waiters: VecDeque::new(),
            async_enabled: false,
            async_owner_type: F_OWNER_PID,
            async_owner_pid: 0,
            async_signal: 0,
            async_fd: -1,
        }
    }

    /// 设置内部参数
    pub fn set_read_end(&mut self, read_end: &Arc<Pipe>) {
        self.read_end = Some(Arc::downgrade(read_end));
    }
    pub fn set_write_end(&mut self, write_end: &Arc<Pipe>) {
        self.write_end = Some(Arc::downgrade(write_end));
    }

    pub fn set_end_ref_bias(&mut self, read_bias: usize, write_bias: usize) {
        self.read_end_ref_bias = read_bias;
        self.write_end_ref_bias = write_bias;
    }
    /// 环状队列 读取字节
    pub fn read_byte(&mut self) -> u8 {
        self.status = RingBufferStatus::NORMAL;
        let c = self.arr[self.head];
        self.head = (self.head + 1) % self.capacity;
        if self.head == self.tail {
            self.status = RingBufferStatus::EMPTY;
        }
        c
    }
    pub fn write_byte(&mut self, byte: u8) {
        self.status = RingBufferStatus::NORMAL;
        self.arr[self.tail] = byte;
        self.tail = (self.tail + 1) % self.capacity;
        if self.tail == self.head {
            self.status = RingBufferStatus::FULL;
        }
    }
    //. 队列是否有可读字节
    pub fn available_read(&self) -> usize {
        if self.status == RingBufferStatus::EMPTY {
            0
        } else {
            if self.status == RingBufferStatus::FULL {
                self.capacity
            } else if self.tail > self.head {
                self.tail - self.head
            } else {
                self.tail + self.capacity - self.head
            }
        }
    }
    pub fn available_write(&self) -> usize {
        if self.status == RingBufferStatus::FULL {
            0
        } else {
            self.capacity - self.available_read()
        }
    }

    fn pipe_size(&self) -> usize {
        self.capacity
    }

    fn poll_writable_threshold(&self) -> usize {
        self.capacity.min(PIPE_BUF)
    }

    fn set_pipe_size(&mut self, size: usize) -> Result<usize, isize> {
        const EBUSY: isize = -16;
        const EPERM: isize = -1;
        const EINVAL: isize = -22;
        if size > (1usize << 31) {
            return Err(EINVAL);
        }
        let base = if size == 0 {
            PIPE_BUF
        } else {
            size.max(PIPE_BUF)
        };
        let Some(new_capacity) = base
            .checked_add(PIPE_BUF - 1)
            .map(|v| (v / PIPE_BUF) * PIPE_BUF)
        else {
            return Err(EINVAL);
        };
        let cap_sys_resource = has_cap_sys_resource();
        let unpriv_limit = pipe_max_size_limit();
        if !cap_sys_resource && new_capacity > unpriv_limit {
            return Err(EPERM);
        }
        if new_capacity > MAX_PIPE_CAPACITY {
            return Err(EINVAL);
        }
        if new_capacity == self.capacity {
            return Ok(self.capacity);
        }

        let used = self.available_read();
        if used > new_capacity {
            return Err(EBUSY);
        }

        let old_capacity = self.capacity;
        let mut data = vec![0u8; used];
        if used > 0 {
            let first = core::cmp::min(used, old_capacity - self.head);
            data[..first].copy_from_slice(&self.arr[self.head..self.head + first]);
            if used > first {
                data[first..].copy_from_slice(&self.arr[..used - first]);
            }
        }

        self.capacity = new_capacity;
        self.head = 0;
        self.tail = if used == new_capacity { 0 } else { used };
        if used == 0 {
            self.status = RingBufferStatus::EMPTY;
        } else if used == new_capacity {
            self.status = RingBufferStatus::FULL;
        } else {
            self.status = RingBufferStatus::NORMAL;
        }
        self.arr[..used].copy_from_slice(data.as_slice());
        Ok(self.capacity)
    }

    fn peek_into(&self, dst: &mut [u8]) -> usize {
        let n = core::cmp::min(dst.len(), self.available_read());
        if n == 0 {
            return 0;
        }
        let first = core::cmp::min(n, self.capacity - self.head);
        dst[..first].copy_from_slice(&self.arr[self.head..self.head + first]);
        if n > first {
            dst[first..n].copy_from_slice(&self.arr[..n - first]);
        }
        n
    }
    /// 通过weak Ptr 判断是否所有写端都关闭
    pub fn all_write_ends_closed(&self) -> bool {
        match self.write_end.as_ref() {
            Some(end) => end.strong_count() <= self.write_end_ref_bias,
            None => true,
        }
    }

    /// 通过weak Ptr 判断是否所有读端都关闭
    pub fn all_read_ends_closed(&self) -> bool {
        match self.read_end.as_ref() {
            Some(end) => end.strong_count() <= self.read_end_ref_bias,
            None => true,
        }
    }

    fn read_end_count(&self) -> usize {
        self.read_end
            .as_ref()
            .map(|w| w.strong_count().saturating_sub(self.read_end_ref_bias))
            .unwrap_or(0)
    }

    fn write_end_count(&self) -> usize {
        self.write_end
            .as_ref()
            .map(|w| w.strong_count().saturating_sub(self.write_end_ref_bias))
            .unwrap_or(0)
    }

    fn push_reader(&mut self, task: Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        if self.read_waiters.iter().any(|t| Arc::ptr_eq(t, &task)) {
            return false;
        }
        self.read_waiters.push_back(task);
        true
    }

    fn push_writer(&mut self, task: Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        if self.write_waiters.iter().any(|t| Arc::ptr_eq(t, &task)) {
            return false;
        }
        self.write_waiters.push_back(task);
        true
    }

    fn pop_reader(&mut self) -> Option<Arc<crate::task::task_block::TaskControlBlock>> {
        self.read_waiters.pop_front()
    }

    fn pop_writer(&mut self) -> Option<Arc<crate::task::task_block::TaskControlBlock>> {
        self.write_waiters.pop_front()
    }

    fn remove_reader(&mut self, task: &Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        let before = self.read_waiters.len();
        self.read_waiters.retain(|t| !Arc::ptr_eq(t, task));
        before != self.read_waiters.len()
    }

    fn remove_writer(&mut self, task: &Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        let before = self.write_waiters.len();
        self.write_waiters.retain(|t| !Arc::ptr_eq(t, task));
        before != self.write_waiters.len()
    }

    fn drain_readers(&mut self) -> Vec<Arc<crate::task::task_block::TaskControlBlock>> {
        self.read_waiters.drain(..).collect()
    }

    fn drain_writers(&mut self) -> Vec<Arc<crate::task::task_block::TaskControlBlock>> {
        self.write_waiters.drain(..).collect()
    }

    fn async_target(&self) -> Option<(i32, i32, i32, i32)> {
        if !self.async_enabled || self.async_owner_pid <= 0 {
            return None;
        }
        Some((
            self.async_owner_type,
            self.async_owner_pid,
            self.async_signal,
            self.async_fd,
        ))
    }
}

fn notify_async_io(owner_type: i32, owner_pid: i32, sig: i32, fd: i32) {
    const POLL_IN: i32 = 1;
    let signum = if sig == 0 { SIGIO_NUM } else { sig };
    if signum <= 0 || signum > 64 {
        return;
    }
    match owner_type {
        // For now map TID to process leader PID in this single-thread use case.
        F_OWNER_TID | F_OWNER_PID => {
            queue_process_signal_info(
                owner_pid as usize,
                signum as usize,
                0,
                0,
                POLL_IN,
                fd as usize,
            );
        }
        F_OWNER_PGRP => {
            let targets = {
                let map = PID2PCB.lock();
                map.values()
                    .filter_map(|pcb| {
                        let inner = pcb.try_borrow_mut()?;
                        if inner.pgid == owner_pid as usize {
                            Some(pcb.getpid())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            };
            for pid in targets {
                queue_process_signal_info(pid, signum as usize, 0, 0, POLL_IN, fd as usize);
            }
        }
        _ => {}
    }
}

pub fn debug_count_task_waiters(task: &Arc<TaskControlBlock>) -> usize {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen = BTreeSet::new();
    let mut refs = 0usize;
    for process in processes {
        let files = {
            let Some(inner) = process.try_borrow_mut() else {
                continue;
            };
            inner
                .fd_table
                .iter()
                .filter_map(|f| f.as_ref().cloned())
                .collect::<Vec<_>>()
        };
        for file in files {
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                continue;
            };
            let ring_ptr = Arc::as_ptr(&pipe.buffer) as usize;
            if !seen.insert(ring_ptr) {
                continue;
            }
            let ring = pipe.buffer.lock();
            refs = refs.saturating_add(
                ring.read_waiters
                    .iter()
                    .filter(|w| Arc::ptr_eq(w, task))
                    .count(),
            );
            refs = refs.saturating_add(
                ring.write_waiters
                    .iter()
                    .filter(|w| Arc::ptr_eq(w, task))
                    .count(),
            );
        }
    }
    refs
}

pub fn remove_task_waiters(task: &Arc<TaskControlBlock>) -> usize {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen = BTreeSet::new();
    let mut removed = 0usize;
    for process in processes {
        let files = {
            let Some(inner) = process.try_borrow_mut() else {
                continue;
            };
            inner
                .fd_table
                .iter()
                .filter_map(|f| f.as_ref().cloned())
                .collect::<Vec<_>>()
        };
        for file in files {
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                continue;
            };
            let ring_ptr = Arc::as_ptr(&pipe.buffer) as usize;
            if !seen.insert(ring_ptr) {
                continue;
            }
            let mut ring = pipe.buffer.lock();
            if ring.remove_reader(task) {
                removed = removed.saturating_add(1);
            }
            if ring.remove_writer(task) {
                removed = removed.saturating_add(1);
            }
        }
    }
    removed
}

fn log_pipe_end_owners(end: &Arc<Pipe>, label: &str) {
    if !DEBUG_UNIXBENCH {
        return;
    }
    let end_ptr = Arc::as_ptr(end);
    let map = PID2PCB.lock();
    let mut owners = Vec::new();
    let mut total = 0usize;
    for (pid, pcb) in map.iter() {
        let Some(inner) = pcb.try_borrow_mut() else {
            continue;
        };
        for (fd, file) in inner.fd_table.iter().enumerate() {
            let Some(file) = file else {
                continue;
            };
            let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
                continue;
            };
            if (pipe as *const Pipe) == end_ptr {
                total += 1;
                if owners.len() < 8 {
                    owners.push((*pid, fd));
                }
            }
        }
    }
    drop(map);
    if total > 0 {
        crate::log_if!(
            DEBUG_UNIXBENCH,
            info,
            "[pipe] {} owners={:?} total={}",
            label,
            owners,
            total
        );
    }
}

/// Return (read_end, write_end)
pub fn make_pipe() -> (Arc<Pipe>, Arc<Pipe>) {
    let buffer = Arc::new(Mutex::new(PipeRingBuffer::new()));
    let read_end = Arc::new(Pipe::read_end_with_buffer(buffer.clone()));
    let write_end = Arc::new(Pipe::write_end_with_buffer(buffer.clone()));
    {
        let mut inner = buffer.lock();
        inner.set_read_end(&read_end);
        inner.set_write_end(&write_end);
    }
    (read_end, write_end)
}

impl File for Pipe {
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn read(&self, buf: UserBuffer) -> usize {
        assert!(self.readable());
        let want_to_read = buf.len();
        if want_to_read == 0 {
            return 0;
        }
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_unmasked_pending(inner.pending_signals, inner.signal_mask, true)
        };
        loop {
            let mut ring_buffer = self.buffer.lock();
            let avail = ring_buffer.available_read();
            if avail == 0 {
                if has_pending_signal() {
                    ring_buffer.remove_reader(&task);
                    crate::log_if!(DEBUG_UNIXBENCH, info, "[pipe] read abort (pending signal)");
                    return 0;
                }
                if ring_buffer.all_write_ends_closed() {
                    ring_buffer.remove_reader(&task);
                    crate::log_if!(DEBUG_UNIXBENCH, info, "[pipe] read EOF");
                    return 0;
                }
                let task_for_log = task.clone();
                let inserted = ring_buffer.push_reader(task.clone());
                let mut waiters = 0usize;
                let mut writers = 0usize;
                let mut write_end: Option<Arc<Pipe>> = None;
                if DEBUG_UNIXBENCH && inserted {
                    waiters = ring_buffer.read_waiters.len();
                    writers = ring_buffer.write_end_count();
                    if writers > 0 {
                        write_end = ring_buffer.write_end.as_ref().and_then(|w| w.upgrade());
                    }
                }
                drop(ring_buffer);
                if DEBUG_UNIXBENCH && inserted {
                    let pid = task_for_log
                        .process
                        .upgrade()
                        .map(|p| p.getpid())
                        .unwrap_or(usize::MAX);
                    let tid = task_for_log
                        .borrow_mut()
                        .res
                        .as_ref()
                        .map(|r| r.tid)
                        .unwrap_or(usize::MAX);
                    crate::log_if!(
                        DEBUG_UNIXBENCH,
                        info,
                        "[pipe] wait read pid={} tid={} waiters={} writers={}",
                        pid,
                        tid,
                        waiters,
                        writers
                    );
                    if writers > 0 {
                        if let Some(end) = write_end {
                            log_pipe_end_owners(&end, "write");
                        }
                    }
                }
                block_current_and_run_next();
                continue;
            }
            // Read at most what's currently available; for pipes, returning a
            // short read is normal once some data is obtained.
            let mut buf_iter = buf.into_iter();
            let mut read_now = 0usize;
            let to_read = core::cmp::min(avail, want_to_read);
            for _ in 0..to_read {
                let Some(byte_ref) = buf_iter.next() else {
                    break;
                };
                unsafe {
                    *byte_ref = ring_buffer.read_byte();
                }
                read_now += 1;
            }
            let writer = if read_now > 0 {
                ring_buffer.pop_writer()
            } else {
                None
            };
            drop(ring_buffer);
            if let Some(writer) = writer {
                wakeup_task(writer);
            }
            return read_now;
        }
    }
    fn write(&self, buf: UserBuffer) -> usize {
        assert!(self.writable());
        let want_to_write = buf.len();
        if want_to_write == 0 {
            return 0;
        }
        let mut data = Vec::with_capacity(want_to_write);
        for byte_ref in buf.into_iter() {
            unsafe {
                data.push(*byte_ref);
            }
        }
        self.write_from_slice(data.as_slice(), false).unwrap_or(0)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
