use alloc::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::{
    bpf::BpfProgFile,
    fs::{
        File, POLLERR, POLLHUP, POLLIN, POLLOUT, PollWaitQueue, parse_proc_sys_usize, wake_tasks,
    },
    mm::UserBuffer,
    syscall::{
        error::{SyscallError, err},
        net::cbpf::ClassicBpfProgram,
    },
    task::{
        block_sleep::add_timer,
        manager::{PID2PCB, prime_fair_sync_wakeup_lag, wakeup_sync_task},
        processor::{block_current_and_run_next, current_process, current_task},
        signal::{
            SIGPIPE_NUM, has_wait_interrupting_pending, queue_process_signal_info, signal_bit,
        },
        task_block::TaskControlBlock,
    },
};

//  Pipe 相关的基本设置
// A small pipe buffer makes typical shell pipelines (busybox/ash, rt-tests) extremely
// slow and can even deadlock if producers/consumers don't run concurrently.
const PIPE_BUF: usize = 4096;
const DEFAULT_PIPE_CAPACITY: usize = 16 * PIPE_BUF;
const MAX_PIPE_CAPACITY: usize = DEFAULT_PIPE_CAPACITY;
static PIPE_MAX_SIZE_LIMIT: AtomicUsize = AtomicUsize::new(DEFAULT_PIPE_CAPACITY);
const SIGIO_NUM: i32 = 29;
const CAP_SYS_RESOURCE: usize = 24;
const F_OWNER_TID: i32 = 0;
const F_OWNER_PID: i32 = 1;
const F_OWNER_PGRP: i32 = 2;
const EINVAL: isize = -22;

/// cap sys resouces:
/// linux 一种cap 权限位的特殊机制
/// 能够使得进程分配更多的系统资源
/// 检查两个 1 root 2.能力位
fn has_cap_sys_resource() -> bool {
    let proc = current_process();
    let inner = proc.borrow_mut();
    inner.euid == 0 && (inner.cap_effective & (1u64 << CAP_SYS_RESOURCE)) != 0
}

/// 读取pipe size的简单包装
fn pipe_max_size_limit() -> usize {
    PIPE_MAX_SIZE_LIMIT.load(Ordering::Relaxed)
}

pub fn pipe_max_size_limit_for_procfs() -> usize {
    pipe_max_size_limit()
}

/// 写入全局pipe_max_size_limit 受最大hard code 影响
pub fn write_pipe_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    if path != "/proc/sys/fs/pipe-max-size" {
        return Err(EINVAL);
    }
    let value = parse_proc_sys_usize(data)?;
    if !(PIPE_BUF..=MAX_PIPE_CAPACITY).contains(&value) {
        return Err(EINVAL);
    }
    PIPE_MAX_SIZE_LIMIT.store(value, Ordering::Relaxed);
    Ok(alloc::format!("{}\n", value).into_bytes())
}

/// 一般的user 就是普通的default size并且被 pipe_max_size_limit，一个全局的变量限制
/// 如果有 cap则不受限
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
    /// 返回一个pipe的写端,对于给定缓冲区
    /// 具体而言，就是 通过readble 和 writebale两个bool 控制
    /// 注意设置是双向的，你需要在pipe内部保留对于Buffer的指针
    /// 也需要在buffer内部保留 pipe的weak ptr
    pub fn read_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: true,
            writable: false,
            buffer,
        }
    }
    /// 返回一个pipe的读端，对于给定的一个缓冲区
    /// 具体而言，就是 通过readble 和 writebale两个bool 控制
    pub fn write_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: false,
            writable: true,
            buffer,
        }
    }

    // determin whether pipe will block read ?
    pub fn poll_readable(&self) -> bool {
        if !self.readable {
            return false;
        }
        let ring = self.buffer.lock();
        ring.available_read() > 0 || ring.all_write_ends_closed()
    }

    // the same as the last one
    // but we dont return ok if the buffer is too small.
    // 不会在过小的缓冲区返回
    pub fn poll_writable(&self) -> bool {
        if !self.writable {
            return false;
        }
        let ring = self.buffer.lock();
        if ring.write_end_shutdown {
            return false;
        }
        ring.available_write() >= ring.poll_writable_threshold() || ring.all_read_ends_closed()
    }

    #[allow(dead_code)]
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

    pub fn wait_readable_lowat(
        &self,
        lowat: usize,
        nonblock: bool,
        deadline_ms: Option<usize>,
        signal_as_eintr: bool,
    ) -> Result<(), isize> {
        const EAGAIN: isize = -11;
        assert!(self.readable());
        let target = lowat.max(1);
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
        };
        loop {
            let mut ring_buffer = self.buffer.lock();
            let avail = ring_buffer.available_read();
            if avail >= target || ring_buffer.all_write_ends_closed() || (nonblock && avail > 0) {
                ring_buffer.remove_reader(&task);
                return Ok(());
            }
            if nonblock {
                ring_buffer.remove_reader(&task);
                return Err(EAGAIN);
            }
            if has_pending_signal() {
                ring_buffer.remove_reader(&task);
                return if signal_as_eintr {
                    Err(err(SyscallError::EINTR))
                } else {
                    Ok(())
                };
            }
            if let Some(deadline_ms) = deadline_ms {
                let now = crate::time::get_time_ms();
                if now >= deadline_ms {
                    ring_buffer.remove_reader(&task);
                    return Err(EAGAIN);
                }
                add_timer(task.clone(), deadline_ms.saturating_sub(now).max(1));
            }
            ring_buffer.push_reader(task.clone());
            drop(ring_buffer);
            block_current_and_run_next();
        }
    }

    pub fn available_write(&self) -> usize {
        if !self.writable {
            return 0;
        }
        let ring = self.buffer.lock();
        if ring.write_end_shutdown {
            return 0;
        }
        ring.available_write()
    }

    pub fn pipe_size(&self) -> usize {
        self.buffer.lock().pipe_size()
    }

    /// 调整本管道底层环形缓冲区的容量，对应 `fcntl(F_SETPIPE_SZ)` 的语义。
    ///
    /// 行为：
    /// - 在持有 `buffer` 锁的情况下调用底层 `RingBuffer::set_pipe_size` 完成实际的
    ///   容量校验、对齐（按 `PIPE_BUF` 向上取整）、权限检查（CAP_SYS_RESOURCE /
    ///   `/proc/sys/fs/pipe-max-size`）以及数据搬迁。
    /// - 仅当调整成功时，才取出当前所有挂在该管道上的 poll 等待者
    ///   （`drain_poll_waiters`），随后在锁外调用 `wake_tasks` 唤醒它们；
    ///   失败路径不唤醒，避免无意义的 spurious wakeup。
    /// - 把“取等待者列表”和“唤醒”分两步完成，是为了**不在持有 buffer 锁的情况下
    ///   去拿任务调度相关的锁**，防止与其它路径形成锁序反转。
    ///
    /// 返回：
    /// - `Ok(new_capacity)`：调整后的实际容量（已按 `PIPE_BUF` 对齐）。
    /// - `Err(errno)`：透传底层错误，常见为 `EINVAL` / `EPERM` / `EBUSY`。
    pub fn set_pipe_size(&self, size: usize) -> Result<usize, isize> {
        let (ret, pollers) = {
            let mut ring = self.buffer.lock();
            let ret = ring.set_pipe_size(size);
            let pollers = if ret.is_ok() {
                ring.drain_poll_waiters()
            } else {
                Vec::new()
            };
            (ret, pollers)
        };
        wake_tasks(pollers);
        ret
    }

    pub fn set_end_ref_bias(&self, read_bias: usize, write_bias: usize) {
        self.buffer.lock().set_end_ref_bias(read_bias, write_bias);
    }

    pub fn attach_filter(&self, filter: ClassicBpfProgram) -> isize {
        let mut ring = self.buffer.lock();
        if ring.filter_locked {
            return err(SyscallError::EPERM);
        }
        ring.classic_filter = Some(filter);
        ring.attached_bpf = None;
        0
    }

    pub fn attach_bpf(&self, prog: Arc<BpfProgFile>) -> isize {
        let mut ring = self.buffer.lock();
        if ring.filter_locked {
            return err(SyscallError::EPERM);
        }
        ring.classic_filter = None;
        ring.attached_bpf = Some(prog);
        0
    }

    pub fn detach_filter(&self) -> isize {
        let mut ring = self.buffer.lock();
        if ring.filter_locked {
            return err(SyscallError::EPERM);
        }
        let had_filter = ring.classic_filter.take().is_some() | ring.attached_bpf.take().is_some();
        if had_filter {
            0
        } else {
            err(SyscallError::ENOENT)
        }
    }

    pub fn set_filter_locked(&self, locked: bool) -> isize {
        let mut ring = self.buffer.lock();
        if ring.filter_locked && !locked {
            return err(SyscallError::EPERM);
        }
        ring.filter_locked = locked;
        0
    }

    pub fn filter_locked(&self) -> bool {
        self.buffer.lock().filter_locked
    }

    pub fn classic_filter_snapshot(&self) -> (Option<ClassicBpfProgram>, bool) {
        let ring = self.buffer.lock();
        (ring.classic_filter.clone(), ring.attached_bpf.is_some())
    }

    #[allow(dead_code)]
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

    pub fn closed_read_end_write_error(&self) -> Option<isize> {
        let mut ring = self.buffer.lock();
        if !ring.all_read_ends_closed() {
            return None;
        }
        let task = current_task().unwrap();
        queue_sigpipe(&task);
        ring.remove_writer(&task);
        Some(err(SyscallError::EPIPE))
    }

    pub fn all_write_ends_closed(&self) -> bool {
        self.buffer.lock().all_write_ends_closed()
    }

    pub fn shutdown_read_end(&self) {
        if !self.readable {
            return;
        }
        let wakeups = {
            let mut ring = self.buffer.lock();
            ring.read_end_shutdown = true;
            let mut wakeups = ring.drain_writers();
            wakeups.extend(ring.drain_poll_waiters());
            wakeups
        };
        wake_tasks(wakeups);
    }

    pub fn shutdown_write_end(&self) {
        if !self.writable {
            return;
        }
        let wakeups = {
            let mut ring = self.buffer.lock();
            ring.write_end_shutdown = true;
            let mut wakeups = ring.drain_readers();
            wakeups.extend(ring.drain_poll_waiters());
            wakeups
        };
        wake_tasks(wakeups);
    }

    pub fn same_buffer(&self, other: &Pipe) -> bool {
        Arc::ptr_eq(&self.buffer, &other.buffer)
    }

    /// 从管道读取数据到 `out`，返回实际读取字节数。
    ///
    /// 阻塞策略（`nonblock = false`）：
    /// - 若缓冲区为空且写端未全关闭，将当前 task 加入 `read_waiters` 后挂起，
    ///   等写端写入数据时被唤醒后重试。
    /// - 若缓冲区为空但写端已全关闭，返回 `Ok(0)`（EOF）。
    /// - 若有未屏蔽挂起信号，中断等待并返回 `Ok(0)`（让上层处理信号）。
    ///
    /// 非阻塞模式（`nonblock = true`）：
    /// - 缓冲区为空时立即返回 `Err(EAGAIN)`。
    ///
    /// 读取成功后，唤醒一个阻塞写者（`pop_writer`）和所有 poll 等待者，
    /// 保证写端不会永久挂起。唤醒操作在锁外执行，避免锁序反转。
    pub fn read_to_slice(&self, out: &mut [u8], nonblock: bool) -> Result<usize, isize> {
        self.read_to_slice_inner(out, nonblock, None, false)
    }

    pub fn read_to_slice_with_deadline(
        &self,
        out: &mut [u8],
        nonblock: bool,
        deadline_ms: Option<usize>,
    ) -> Result<usize, isize> {
        self.read_to_slice_inner(out, nonblock, deadline_ms, true)
    }

    fn read_to_slice_inner(
        &self,
        out: &mut [u8],
        nonblock: bool,
        deadline_ms: Option<usize>,
        signal_as_eintr: bool,
    ) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        assert!(self.readable());
        if out.is_empty() {
            return Ok(0);
        }
        let task = current_task().unwrap();
        // 验证当前task 是否有未处理信号
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
        };
        loop {
            let mut ring_buffer = self.buffer.lock();
            let avail = ring_buffer.available_read();
            if avail == 0 {
                // write 端已关闭，直接推出
                if ring_buffer.all_write_ends_closed() {
                    ring_buffer.remove_reader(&task);
                    return Ok(0);
                }
                // 非阻塞read，那么empty，立即返回
                if nonblock {
                    ring_buffer.remove_reader(&task);
                    return Err(EAGAIN);
                }
                // 信号优先处理
                if has_pending_signal() {
                    ring_buffer.remove_reader(&task);
                    return if signal_as_eintr {
                        Err(err(SyscallError::EINTR))
                    } else {
                        Ok(0)
                    };
                }
                if let Some(deadline_ms) = deadline_ms {
                    let now = crate::time::get_time_ms();
                    if now >= deadline_ms {
                        ring_buffer.remove_reader(&task);
                        return Err(EAGAIN);
                    }
                    add_timer(task.clone(), deadline_ms.saturating_sub(now).max(1));
                }
                // 阻塞写read，加入阻塞队列
                ring_buffer.push_reader(task.clone());
                drop(ring_buffer);
                block_current_and_run_next();
                continue;
            }
            // 到这里说明可以读，我们即将写入
            let to_read = core::cmp::min(avail, out.len());
            let read_now = ring_buffer.read_into_slice(&mut out[..to_read]);

            // 通知 写者，和 epoll
            let writer = ring_buffer.pop_writer();
            let wakeups = ring_buffer.drain_poll_waiters();
            drop(ring_buffer);
            wake_pipe_waiters(wakeups, writer);
            return Ok(read_now);
        }
    }

    /// 将 `data` 写入管道，返回实际写入字节数。
    ///
    /// **原子性保证（POSIX）**：写入量 ≤ `PIPE_BUF` 时，要么一次写完，要么全部阻塞等待；
    /// 永远不会出现部分写的情况（`written == 0` 时强制等待直到空间足够）。
    /// 写入量 > `PIPE_BUF` 时可分多次循环写入。
    ///
    /// **读端已全关闭**：向当前 task 投递 `SIGPIPE`，返回已写字节数（可能为 0）。
    /// 上层（如 `write` 系统调用）会在信号处理后重新检查。
    ///
    /// **阻塞策略（`nonblock = false`）**：
    /// - 缓冲区满，或剩余数据 ≤ `PIPE_BUF` 但空间不足时，将 task 加入 `write_waiters` 挂起，
    ///   等读端消费数据后被唤醒重试。
    /// - 有未屏蔽挂起信号时中断，返回已写字节数。
    ///
    /// **非阻塞模式（`nonblock = true`）**：
    /// - 若尚未写出任何字节，返回 `Err(EAGAIN)`；否则返回已写字节数。
    /// - 单次写入量超过 `PIPE_BUF` 时，截断为当前可用空间（允许短写）。
    ///
    /// 每次成功写入后（锁外执行，避免死锁）：
    /// 1. 若有 BPF 程序挂载，用本次写入的数据包运行 BPF 过滤器。
    /// 2. 若开启了异步 IO（`F_SETFL O_ASYNC`），向属主发送 `SIGIO`/自定义信号。
    /// 3. 唤醒一个阻塞读者（`pop_reader`）和所有 poll 等待者。
    pub fn write_from_slice(&self, data: &[u8], nonblock: bool) -> Result<usize, isize> {
        self.write_from_slice_inner(data, nonblock, None, false)
    }

    pub fn write_from_slice_with_deadline(
        &self,
        data: &[u8],
        nonblock: bool,
        deadline_ms: Option<usize>,
    ) -> Result<usize, isize> {
        self.write_from_slice_inner(data, nonblock, deadline_ms, true)
    }

    fn write_from_slice_inner(
        &self,
        data: &[u8],
        nonblock: bool,
        deadline_ms: Option<usize>,
        signal_as_eintr: bool,
    ) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        assert!(self.writable());
        if data.is_empty() {
            return Ok(0);
        }
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
        };
        let mut written = 0usize;
        loop {
            let mut ring_buffer = self.buffer.lock();
            if ring_buffer.all_read_ends_closed() {
                queue_sigpipe(&task);
                ring_buffer.remove_writer(&task);
                return if written == 0 {
                    Err(err(SyscallError::EPIPE))
                } else {
                    Ok(written)
                };
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
                    return if signal_as_eintr && written == 0 {
                        Err(err(SyscallError::EINTR))
                    } else {
                        Ok(written)
                    };
                }
                if let Some(deadline_ms) = deadline_ms {
                    let now = crate::time::get_time_ms();
                    if now >= deadline_ms {
                        ring_buffer.remove_writer(&task);
                        return if written > 0 {
                            Ok(written)
                        } else {
                            Err(EAGAIN)
                        };
                    }
                    add_timer(task.clone(), deadline_ms.saturating_sub(now).max(1));
                }
                ring_buffer.push_writer(task.clone());
                drop(ring_buffer);
                block_current_and_run_next();
                continue;
            }
            let mut to_write = remaining.min(avail);
            if nonblock && to_write > PIPE_BUF {
                to_write = to_write.min(avail);
            }
            let classic_filter = ring_buffer.classic_filter.clone();
            let attached_bpf = ring_buffer.attached_bpf.clone();
            let write_slice = &data[written..written + to_write];
            let mut filter_truncated = false;
            if let Some(filter) = classic_filter.as_ref() {
                let Some(filter_len) = filter.filter_len(write_slice) else {
                    ring_buffer.remove_writer(&task);
                    return Ok(data.len());
                };
                filter_truncated |= filter_len < write_slice.len();
                to_write = to_write.min(filter_len);
            }
            if let Some(filter) = attached_bpf.as_ref() {
                let Some(filter_len) = filter.filter_len(&write_slice[..to_write]) else {
                    ring_buffer.remove_writer(&task);
                    return Ok(data.len());
                };
                filter_truncated |= filter_len < to_write;
                to_write = to_write.min(filter_len);
            }
            let to_write = ring_buffer.write_from_slice_bytes(&write_slice[..to_write]);
            written += to_write;
            let reader_to_wake = if to_write > 0 {
                ring_buffer.pop_reader()
            } else {
                None
            };
            let wakeups = if to_write > 0 {
                ring_buffer.drain_poll_waiters()
            } else {
                Vec::new()
            };
            let async_notify = if to_write > 0 {
                ring_buffer.async_target()
            } else {
                None
            };
            drop(ring_buffer);
            if let Some((owner_type, owner_pid, sig, fd)) = async_notify {
                notify_async_io(owner_type, owner_pid, sig, fd);
            }
            wake_pipe_waiters(wakeups, reader_to_wake);
            if filter_truncated {
                return Ok(data.len());
            }
            if written == data.len() || nonblock {
                return Ok(written);
            }
        }
    }

    /// Read directly into a user buffer while preserving Linux syscall errors.
    ///
    /// The legacy `File::read` trait returns only `usize`, which forces waitable
    /// objects to squash signal interruption into a zero-length read.  Syscall
    /// paths use this typed helper so a signal that wakes an interruptible pipe
    /// wait returns `-EINTR`, matching Linux pipe semantics.
    pub fn read_user_result(&self, mut buf: UserBuffer, nonblock: bool) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        assert!(self.readable());
        let want_to_read = buf.len();
        if want_to_read == 0 {
            return Ok(0);
        }
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
        };
        let mut data = alloc::vec![0u8; core::cmp::min(want_to_read, MAX_PIPE_CAPACITY)];
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
                    return Err(err(SyscallError::EINTR));
                }
                ring_buffer.push_reader(task.clone());
                drop(ring_buffer);
                block_current_and_run_next();
                continue;
            }

            let to_read = core::cmp::min(avail, want_to_read);
            let read_now = ring_buffer.read_into_slice(&mut data[..to_read]);
            let writer = if read_now > 0 {
                ring_buffer.pop_writer()
            } else {
                None
            };
            let wakeups = if read_now > 0 {
                ring_buffer.drain_poll_waiters()
            } else {
                Vec::new()
            };
            drop(ring_buffer);
            wake_pipe_waiters(wakeups, writer);
            return Ok(buf.copy_from_slice(&data[..read_now]));
        }
    }

    /// Write from a user buffer while preserving Linux syscall errors.
    pub fn write_user_result(&self, buf: UserBuffer, nonblock: bool) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        assert!(self.writable());
        let want_to_write = buf.len();
        if want_to_write == 0 {
            return Ok(0);
        }

        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
        };
        let mut written = 0usize;
        let mut scratch = alloc::vec![0u8; core::cmp::min(want_to_write, PIPE_BUF)];
        loop {
            let mut ring_buffer = self.buffer.lock();
            if ring_buffer.has_filter() {
                ring_buffer.remove_writer(&task);
                drop(ring_buffer);
                let mut data = alloc::vec![0u8; want_to_write - written];
                let copied = buf.copy_to_slice_at(written, &mut data);
                data.truncate(copied);
                return match self.write_from_slice_with_deadline(&data, nonblock, None) {
                    Ok(n) => Ok(written + n),
                    Err(_e) if written > 0 => Ok(written),
                    Err(e) => Err(e),
                };
            }
            if ring_buffer.all_read_ends_closed() {
                queue_sigpipe(&task);
                ring_buffer.remove_writer(&task);
                return if written == 0 {
                    Err(err(SyscallError::EPIPE))
                } else {
                    Ok(written)
                };
            }

            let avail = ring_buffer.available_write();
            let remaining = want_to_write - written;
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
                    return if written > 0 {
                        Ok(written)
                    } else {
                        Err(err(SyscallError::EINTR))
                    };
                }
                ring_buffer.push_writer(task.clone());
                drop(ring_buffer);
                block_current_and_run_next();
                continue;
            }

            let to_write = remaining.min(avail);
            let mut write_now = 0usize;
            while write_now < to_write {
                let chunk = core::cmp::min(scratch.len(), to_write - write_now);
                let copied = buf.copy_to_slice_at(written + write_now, &mut scratch[..chunk]);
                if copied == 0 {
                    break;
                }
                let pushed = ring_buffer.write_from_slice_bytes(&scratch[..copied]);
                write_now += pushed;
                if pushed != copied {
                    break;
                }
            }
            written += write_now;

            let reader_to_wake = if write_now > 0 {
                ring_buffer.pop_reader()
            } else {
                None
            };
            let wakeups = if write_now > 0 {
                ring_buffer.drain_poll_waiters()
            } else {
                Vec::new()
            };
            let async_notify = if write_now > 0 {
                ring_buffer.async_target()
            } else {
                None
            };
            drop(ring_buffer);
            if let Some((owner_type, owner_pid, sig, fd)) = async_notify {
                notify_async_io(owner_type, owner_pid, sig, fd);
            }
            wake_pipe_waiters(wakeups, reader_to_wake);

            if written == want_to_write || nonblock {
                return Ok(written);
            }
        }
    }

    /// 窥看（peek）管道数据到 `out`，**不消费**缓冲区内容（head/tail 不移动）。
    /// 对应 `recv(MSG_PEEK)` 语义，用于 socketpair/unix-socket 的 peek 路径。
    ///
    /// 阻塞/非阻塞、信号处理策略与 `read_to_slice` 相同；
    /// 区别在于读取成功后不唤醒写者（数据未被消费，空间未释放）。
    pub fn peek_to_slice(&self, out: &mut [u8], nonblock: bool) -> Result<usize, isize> {
        self.peek_to_slice_inner(out, nonblock, None, false)
    }

    pub fn peek_to_slice_with_deadline(
        &self,
        out: &mut [u8],
        nonblock: bool,
        deadline_ms: Option<usize>,
    ) -> Result<usize, isize> {
        self.peek_to_slice_inner(out, nonblock, deadline_ms, true)
    }

    fn peek_to_slice_inner(
        &self,
        out: &mut [u8],
        nonblock: bool,
        deadline_ms: Option<usize>,
        signal_as_eintr: bool,
    ) -> Result<usize, isize> {
        const EAGAIN: isize = -11;
        assert!(self.readable());
        if out.is_empty() {
            return Ok(0);
        }
        let task = current_task().unwrap();
        let has_pending_signal = || {
            let inner = task.borrow_mut();
            has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
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
                    return if signal_as_eintr {
                        Err(err(SyscallError::EINTR))
                    } else {
                        Ok(0)
                    };
                }
                if let Some(deadline_ms) = deadline_ms {
                    let now = crate::time::get_time_ms();
                    if now >= deadline_ms {
                        ring_buffer.remove_reader(&task);
                        return Err(EAGAIN);
                    }
                    add_timer(task.clone(), deadline_ms.saturating_sub(now).max(1));
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

/// 管道缓冲区
pub struct PipeRingBuffer {
    arr: Option<Vec<u8>>,
    filter_locked: bool,
    classic_filter: Option<ClassicBpfProgram>,
    attached_bpf: Option<Arc<BpfProgFile>>,
    capacity: usize,
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    read_end: Option<Weak<Pipe>>,
    write_end: Option<Weak<Pipe>>,
    read_end_shutdown: bool,
    write_end_shutdown: bool,
    /// 读端引用计数基线：从 `read_end.strong_count()` 中减去此值才得到"真实打开的读端数"。
    /// 用于 FIFO 场景：`FifoPipeState` 自身持有一份 `Arc<Pipe>` 作为注册引用，
    /// 将 bias 设为 1 可让 `all_read_ends_closed()` 和 `read_end_count()` 忽略该注册引用，
    /// 保证 EOF / EPIPE 语义仅跟踪真实 fd。
    read_end_ref_bias: usize,
    /// 写端引用计数基线，语义同 `read_end_ref_bias`。
    write_end_ref_bias: usize,
    /// Descriptor references are tracked separately from `Arc` references.
    ///
    /// Exiting processes detach their descriptor table before the kernel
    /// eventually drops the backing `Arc`s.  Pipe EOF/EPIPE must follow the
    /// descriptor lifetime immediately, not that deferred object destruction.
    read_fd_refs: usize,
    write_fd_refs: usize,
    read_fd_tracking: bool,
    write_fd_tracking: bool,
    read_waiters: VecDeque<Weak<crate::task::task_block::TaskControlBlock>>,
    write_waiters: VecDeque<Weak<crate::task::task_block::TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
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
            arr: None,
            filter_locked: false,
            classic_filter: None,
            attached_bpf: None,
            capacity,
            head: 0,
            tail: 0,
            status: RingBufferStatus::EMPTY,
            read_end: None,
            write_end: None,
            read_end_shutdown: false,
            write_end_shutdown: false,
            read_end_ref_bias: 0,
            write_end_ref_bias: 0,
            read_fd_refs: 0,
            write_fd_refs: 0,
            read_fd_tracking: false,
            write_fd_tracking: false,
            read_waiters: VecDeque::new(),
            write_waiters: VecDeque::new(),
            poll_waiters: PollWaitQueue::default(),
            async_enabled: false,
            async_owner_type: F_OWNER_PID,
            async_owner_pid: 0,
            async_signal: 0,
            async_fd: -1,
        }
    }

    /// 设置写端, 注意 同样需要在另一端保留 对应的指针，详细参考make_pipe
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

    fn install_fd_ref(&mut self, readable: bool, writable: bool) {
        if readable {
            self.read_fd_tracking = true;
            self.read_fd_refs = self.read_fd_refs.saturating_add(1);
        }
        if writable {
            self.write_fd_tracking = true;
            self.write_fd_refs = self.write_fd_refs.saturating_add(1);
        }
    }

    fn close_fd_ref(&mut self, readable: bool, writable: bool) -> (bool, bool) {
        let mut last_reader = false;
        let mut last_writer = false;
        if readable && self.read_fd_tracking && self.read_fd_refs > 0 {
            self.read_fd_refs -= 1;
            last_reader = self.read_fd_refs == 0;
        }
        if writable && self.write_fd_tracking && self.write_fd_refs > 0 {
            self.write_fd_refs -= 1;
            last_writer = self.write_fd_refs == 0;
        }
        (last_reader, last_writer)
    }

    /// 访问之前必须确保数据已经被分配
    fn data(&self) -> &[u8] {
        self.arr
            .as_ref()
            .expect("pipe buffer backing missing while data is queued")
    }

    fn data_mut(&mut self) -> &mut [u8] {
        self.arr
            .as_mut()
            .expect("pipe buffer backing missing while data is queued")
    }

    /// 懒分配机制，确保数据真实存在
    fn ensure_backing(&mut self) {
        if self.arr.is_none() {
            self.arr = Some(vec![0; MAX_PIPE_CAPACITY]);
        }
    }

    /// Copy queued pipe bytes into `dst` in up to two contiguous chunks.
    ///
    /// Linux stores pipe data in page-backed pipe buffers and moves whole
    /// spans rather than updating ring state per byte.  This ring still uses a
    /// byte array, but keeping the hot path chunked avoids one status/head
    /// update per byte for lmbench's pipe bandwidth workload.
    fn read_into_slice(&mut self, dst: &mut [u8]) -> usize {
        let n = core::cmp::min(dst.len(), self.available_read());
        if n == 0 {
            return 0;
        }
        let first = core::cmp::min(n, self.capacity - self.head);
        let head = self.head;
        let arr = self.data();
        dst[..first].copy_from_slice(&arr[head..head + first]);
        if n > first {
            dst[first..n].copy_from_slice(&arr[..n - first]);
        }
        self.head = (self.head + n) % self.capacity;
        self.status = if self.head == self.tail {
            RingBufferStatus::EMPTY
        } else {
            RingBufferStatus::NORMAL
        };
        n
    }

    /// Copy `src` into free pipe space in up to two contiguous chunks.
    fn write_from_slice_bytes(&mut self, src: &[u8]) -> usize {
        let n = core::cmp::min(src.len(), self.available_write());
        if n == 0 {
            return 0;
        }
        self.ensure_backing();
        let first = core::cmp::min(n, self.capacity - self.tail);
        let tail = self.tail;
        {
            let arr = self.data_mut();
            arr[tail..tail + first].copy_from_slice(&src[..first]);
            if n > first {
                arr[..n - first].copy_from_slice(&src[first..n]);
            }
        }
        self.tail = (self.tail + n) % self.capacity;
        self.status = if self.tail == self.head {
            RingBufferStatus::FULL
        } else {
            RingBufferStatus::NORMAL
        };
        n
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

    /// 一次可以写的至少预留大小，为了避免小字节的频繁写入
    fn poll_writable_threshold(&self) -> usize {
        self.capacity.min(PIPE_BUF)
    }

    /// 调整环形缓冲区的容量（`fcntl(F_SETPIPE_SZ)` 的核心实现）。
    ///
    /// 处理流程：
    /// 1. 参数合法性检查：拒绝大于 `1<<31` 的请求（与 Linux 行为一致，避免溢出）。
    /// 2. 规范化目标容量：
    ///    - `size == 0` 视为请求最小值 `PIPE_BUF`；
    ///    - 否则向上取到不小于 `PIPE_BUF`，再按 `PIPE_BUF` 对齐（向上取整）。
    /// 3. 权限/上限检查：
    ///    - 若进程没有 `CAP_SYS_RESOURCE`，则不得超过
    ///      `/proc/sys/fs/pipe-max-size` 给出的非特权上限，否则返回 `EPERM`；
    ///    - 任何情况下不得超过内核硬上限 `MAX_PIPE_CAPACITY`，否则返回 `EINVAL`。
    /// 4. 若新容量与当前相同，立即返回，避免无谓的数据搬迁。
    /// 5. 若当前已用字节数 `used` 大于新容量，返回 `EBUSY`
    ///    （Linux 在缩小管道时不丢弃数据）。
    /// 6. 把当前环形缓冲区内的有效数据拷贝到一段连续的临时 buffer，
    ///    重置 `head/tail/status`，再写回新容量缓冲区的起始位置，
    ///    保证“逻辑顺序”不变并消除环绕。`ensure_backing` 用于按需分配新底层存储。
    ///
    /// 返回值是规范化并实际生效的新容量。
    fn set_pipe_size(&mut self, size: usize) -> Result<usize, isize> {
        const EBUSY: isize = -16;
        const EPERM: isize = -1;
        const EINVAL: isize = -22;
        // 对应1
        if size > (1usize << 31) {
            return Err(EINVAL);
        }
        // 对应2
        let base = if size == 0 {
            PIPE_BUF
        } else {
            size.max(PIPE_BUF)
        };
        // 对应 3 向上取整操作
        let Some(new_capacity) = base
            .checked_add(PIPE_BUF - 1)
            .map(|v| (v / PIPE_BUF) * PIPE_BUF)
        else {
            return Err(EINVAL);
        };
        //检查 capacity +  pipe 最大限制
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
        // 对应 5 防止丢失 老数据
        if used > new_capacity {
            return Err(EBUSY);
        }

        let old_capacity = self.capacity;
        let mut data = vec![0u8; used];
        // 这里的大体逻辑 简而言之 就是 把老的数据复制到前面
        if used > 0 {
            let arr = self.data();
            let first = core::cmp::min(used, old_capacity - self.head);
            data[..first].copy_from_slice(&arr[self.head..self.head + first]);
            if used > first {
                data[first..].copy_from_slice(&arr[..used - first]);
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
        if used > 0 {
            self.ensure_backing();
            self.data_mut()[..used].copy_from_slice(data.as_slice());
        }
        Ok(self.capacity)
    }

    /// 读取数据到dst
    fn peek_into(&self, dst: &mut [u8]) -> usize {
        let n = core::cmp::min(dst.len(), self.available_read());
        if n == 0 {
            return 0;
        }
        let first = core::cmp::min(n, self.capacity - self.head);
        let arr = self.data();
        dst[..first].copy_from_slice(&arr[self.head..self.head + first]);
        if n > first {
            dst[first..n].copy_from_slice(&arr[..n - first]);
        }
        n
    }
    /// 通过weak Ptr 判断是否所有写端都关闭
    pub fn all_write_ends_closed(&self) -> bool {
        if self.write_end_shutdown {
            return true;
        }
        if self.write_fd_tracking {
            return self.write_fd_refs == 0;
        }
        match self.write_end.as_ref() {
            Some(end) => end.strong_count() <= self.write_end_ref_bias,
            None => true,
        }
    }

    /// 通过weak Ptr 判断是否所有读端都关闭
    pub fn all_read_ends_closed(&self) -> bool {
        if self.read_end_shutdown {
            return true;
        }
        if self.read_fd_tracking {
            return self.read_fd_refs == 0;
        }
        match self.read_end.as_ref() {
            Some(end) => end.strong_count() <= self.read_end_ref_bias,
            None => true,
        }
    }

    fn read_end_count(&self) -> usize {
        if self.read_fd_tracking {
            return self.read_fd_refs;
        }
        self.read_end
            .as_ref()
            .map(|w| w.strong_count().saturating_sub(self.read_end_ref_bias))
            .unwrap_or(0)
    }

    fn write_end_count(&self) -> usize {
        if self.write_fd_tracking {
            return self.write_fd_refs;
        }
        self.write_end
            .as_ref()
            .map(|w| w.strong_count().saturating_sub(self.write_end_ref_bias))
            .unwrap_or(0)
    }

    fn waiter_matches(
        waiter: &Weak<crate::task::task_block::TaskControlBlock>,
        task: &Arc<crate::task::task_block::TaskControlBlock>,
    ) -> bool {
        waiter.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task))
    }

    fn push_reader(&mut self, task: Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        self.read_waiters.retain(|w| w.strong_count() > 0);
        if self
            .read_waiters
            .iter()
            .any(|waiter| Self::waiter_matches(waiter, &task))
        {
            return false;
        }
        self.read_waiters.push_back(Arc::downgrade(&task));
        true
    }

    fn push_writer(&mut self, task: Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        self.write_waiters.retain(|w| w.strong_count() > 0);
        if self
            .write_waiters
            .iter()
            .any(|waiter| Self::waiter_matches(waiter, &task))
        {
            return false;
        }
        self.write_waiters.push_back(Arc::downgrade(&task));
        true
    }

    fn pop_reader(&mut self) -> Option<Arc<crate::task::task_block::TaskControlBlock>> {
        while let Some(waiter) = self.read_waiters.pop_front() {
            if let Some(task) = waiter.upgrade() {
                return Some(task);
            }
        }
        None
    }

    fn pop_writer(&mut self) -> Option<Arc<crate::task::task_block::TaskControlBlock>> {
        while let Some(waiter) = self.write_waiters.pop_front() {
            if let Some(task) = waiter.upgrade() {
                return Some(task);
            }
        }
        None
    }

    fn remove_reader(&mut self, task: &Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        let before = self.read_waiters.len();
        self.read_waiters.retain(|waiter| {
            waiter
                .upgrade()
                .is_some_and(|waiter_task| !Arc::ptr_eq(&waiter_task, task))
        });
        before != self.read_waiters.len()
    }

    fn remove_writer(&mut self, task: &Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        let before = self.write_waiters.len();
        self.write_waiters.retain(|waiter| {
            waiter
                .upgrade()
                .is_some_and(|waiter_task| !Arc::ptr_eq(&waiter_task, task))
        });
        before != self.write_waiters.len()
    }

    /// 取出所有的 reader
    fn drain_readers(&mut self) -> Vec<Arc<crate::task::task_block::TaskControlBlock>> {
        self.read_waiters
            .drain(..)
            .filter_map(|w| w.upgrade())
            .collect()
    }

    /// 取出所有的 write
    fn drain_writers(&mut self) -> Vec<Arc<crate::task::task_block::TaskControlBlock>> {
        self.write_waiters
            .drain(..)
            .filter_map(|w| w.upgrade())
            .collect()
    }

    fn add_poll_waiter_once(
        &mut self,
        task: &Arc<crate::task::task_block::TaskControlBlock>,
    ) -> bool {
        self.poll_waiters.add_waiter_once(task)
    }

    fn register_poll_waiter(
        &mut self,
        task: &Arc<crate::task::task_block::TaskControlBlock>,
    ) -> bool {
        let _ = self.add_poll_waiter_once(task);
        true
    }

    /// 取出所有的数据
    fn drain_poll_waiters(&mut self) -> Vec<Arc<crate::task::task_block::TaskControlBlock>> {
        self.poll_waiters.take_wakeups()
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

    fn has_filter(&self) -> bool {
        self.classic_filter.is_some() || self.attached_bpf.is_some()
    }
}

fn queue_sigpipe(task: &Arc<crate::task::task_block::TaskControlBlock>) {
    if let Some(bit) = signal_bit(SIGPIPE_NUM) {
        task.borrow_mut().pending_signals |= bit;
        task.mark_signal_pending();
    }
}

/// Wake poll waiters normally and direct pipe read/write waiters as a sync wakeup.
///
/// Linux pipe read/write wakeups use the synchronous wakeup variant for the
/// opposite endpoint: the waker is usually about to block or hand control back
/// to its peer, so the scheduler should preserve a small amount of wakeup lag
/// for that peer. Readiness waiters (`poll`/`epoll`/`select`) are notification
/// waiters rather than the direct pipe endpoint, so keep their ordinary wakeup
/// placement.
fn wake_pipe_waiters(
    poll_waiters: Vec<Arc<TaskControlBlock>>,
    direct_waiter: Option<Arc<TaskControlBlock>>,
) {
    if poll_waiters.is_empty() && direct_waiter.is_none() {
        return;
    }
    if let Some(waiter) = direct_waiter {
        prime_fair_sync_wakeup_lag(&waiter);
        wakeup_sync_task(waiter);
    }
    if !poll_waiters.is_empty() {
        wake_tasks(poll_waiters);
    }
}

/// 向管道异步 IO 属主（`F_SETOWN`）投递就绪信号（默认 `SIGIO`，可由 `F_SETSIG` 自定义）。
///
/// - `F_OWNER_TID` / `F_OWNER_PID`：向指定进程发送信号（当前实现将 TID 映射到进程 leader）。
/// - `F_OWNER_PGRP`：向整个进程组广播信号，先快照 pgid 匹配的进程列表再逐一发送，
///   避免在持有 `PID2PCB` 锁期间重入。
/// - `sig <= 0` 或超出 `[1,64]` 范围时静默忽略（内核 `kill` 的标准行为）。
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

/// 统计 `task` 在全局所有管道等待队列中出现的次数（调试用）。
///
/// 遍历所有进程的文件表，对每个管道的 `PipeRingBuffer` 做一次检查。
/// 使用 `seen` / `seen_tables` 两个去重集合，避免因 fd 复制（`dup`）或
/// 进程间共享文件表（`CLONE_FILES`）导致同一 buffer 被重复计数。
pub fn debug_count_task_waiters(task: &Arc<TaskControlBlock>) -> usize {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen = BTreeSet::new();
    let mut seen_tables = BTreeSet::new();
    let mut refs = 0usize;
    for process in processes {
        let files = {
            let Some(inner) = process.try_borrow_mut() else {
                continue;
            };
            Arc::clone(&inner.files)
        };
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        for (_fd, file) in files.lock().iter_files_snapshot() {
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
                    .filter(|w| PipeRingBuffer::waiter_matches(w, task))
                    .count(),
            );
            refs = refs.saturating_add(
                ring.write_waiters
                    .iter()
                    .filter(|w| PipeRingBuffer::waiter_matches(w, task))
                    .count(),
            );
        }
    }
    refs
}

/// Pipe read/write waiters are weak references, so exiting tasks do not need a
/// global fd-table scan to drop pipe waiter references. Stale weak entries are
/// pruned on local pipe enqueue/pop/drain paths.
pub fn remove_task_waiters(_task: &Arc<TaskControlBlock>) -> usize {
    0
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

impl Drop for Pipe {
    fn drop(&mut self) {
        let wakeups = {
            let mut ring = self.buffer.lock();
            let mut wakeups = if self.writable {
                // Last write end vanished: blocked readers must observe EOF.
                ring.drain_readers()
            } else {
                Vec::new()
            };
            if self.readable {
                // Last read end vanished: blocked writers must observe EPIPE/SIGPIPE.
                wakeups.extend(ring.drain_writers());
            }
            wakeups.extend(ring.drain_poll_waiters());
            wakeups
        };
        wake_tasks(wakeups);
    }
}

impl File for Pipe {
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn on_fd_install(&self) {
        self.buffer
            .lock()
            .install_fd_ref(self.readable, self.writable);
    }
    fn on_fd_close(&self) {
        let wakeups = {
            let mut ring = self.buffer.lock();
            let (last_reader, last_writer) = ring.close_fd_ref(self.readable, self.writable);
            let mut wakeups = Vec::new();
            if last_writer {
                wakeups.extend(ring.drain_readers());
            }
            if last_reader {
                wakeups.extend(ring.drain_writers());
            }
            if last_reader || last_writer {
                wakeups.extend(ring.drain_poll_waiters());
            }
            wakeups
        };
        wake_tasks(wakeups);
    }
    /// `File::read` 的管道实现：从用户态 `UserBuffer` 接收目标地址，阻塞读取。
    ///
    /// 与 `read_to_slice` 逻辑相同，但目标是散布的用户页帧（`UserBuffer`），
    /// 读取时按每段用户页帧批量拷贝，避免在 pipe 热路径逐字节更新环形队列。
    /// 读到数据后返回短读（short read）而非等满 `want_to_read`，符合 POSIX 管道语义。
    fn read(&self, buf: UserBuffer) -> usize {
        self.read_user_result(buf, false).unwrap_or(0)
    }
    /// `File::write` 的管道实现：从用户态 `UserBuffer` 分段拷贝到管道环形缓冲区。
    /// 普通 pipe 写入不再为整个请求预先分配内核暂存区；带 classic/BPF filter 的
    /// pipe 仍回退到切片写入路径，以保留过滤器按写包处理的语义。
    fn write(&self, buf: UserBuffer) -> usize {
        self.write_user_result(buf, false).unwrap_or(0)
    }

    fn poll_mask(&self) -> i16 {
        let ring = self.buffer.lock();
        let mut mask = 0;
        if self.readable {
            if ring.available_read() > 0 {
                mask |= POLLIN;
            }
            if ring.all_write_ends_closed() {
                mask |= POLLHUP;
            }
        }
        if self.writable {
            if ring.all_read_ends_closed() {
                mask |= POLLERR;
            } else if ring.available_write() >= ring.poll_writable_threshold() {
                mask |= POLLOUT;
            }
        }
        mask
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<crate::task::task_block::TaskControlBlock>) -> bool {
        self.buffer.lock().register_poll_waiter(task)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
