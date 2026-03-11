use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};

use lazy_static::lazy_static;
use spin::Mutex;

use crate::config::clock_freq;
use crate::fs::{File, POLLIN, POLLOUT, PollWaitQueue, find_path_in_roots, wake_tasks};
use crate::mm::{
    UserBuffer, try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value,
};
use crate::task::block_sleep::add_timer;
use crate::task::manager::wakeup_task;
use crate::task::processor::{
    block_current_and_run_next, current_files_process, current_process, current_task,
};
use crate::task::signal::{RT_SIG_MAX, has_unmasked_pending, signal_bit};
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use crate::time::get_time;
use crate::trap::get_current_token;

const O_ACCMODE: usize = 0x3;
const O_RDONLY: usize = 0x0;
const O_WRONLY: usize = 0x1;
const O_RDWR: usize = 0x2;
const O_CREAT: usize = 0x40;
const O_EXCL: usize = 0x80;
const O_NONBLOCK: usize = 0x800;
const O_CLOEXEC: usize = 0x80000;
const FD_CLOEXEC: u32 = 1;

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;
const SI_MESGQ: i32 = -3;

const EACCES: isize = -13;
const EAGAIN: isize = -11;
const EBADF: isize = -9;
const EBUSY: isize = -16;
const EEXIST: isize = -17;
const EFAULT: isize = -14;
const EINVAL: isize = -22;
const EINTR: isize = -4;
const EMFILE: isize = -24;
const EMSGSIZE: isize = -90;
const ENAMETOOLONG: isize = -36;
const ENOENT: isize = -2;
const ENOSPC: isize = -28;
const ETIMEDOUT: isize = -110;

const MQ_NAME_MAX: usize = 255;
const MQ_NAME_MAX_WITH_SLASH: usize = MQ_NAME_MAX + 1;
const MQ_PRIO_MAX: usize = 32768;
const MQ_DEFAULT_MAXMSG: usize = 10;
const MQ_DEFAULT_MSGSIZE: usize = 8192;
const MQ_DEFAULT_QUEUES_MAX: usize = 256;
const MQ_HARD_QUEUES_MAX: usize = 65536;
const MQ_NOTIFY_COOKIE_LEN: usize = 32;
const MQ_NOTIFY_WOKENUP: u8 = 1;
const MQ_NOTIFY_REMOVED: u8 = 2;
const PROCFS_QUEUES_MAX: &str = "/proc/sys/fs/mqueue/queues_max";
const NSEC_PER_SEC: u64 = 1_000_000_000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MqAttrUser {
    mq_flags: i64,
    mq_maxmsg: i64,
    mq_msgsize: i64,
    mq_curmsgs: i64,
    __reserved: [i64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TimeSpecUser {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SigeventUser {
    sigev_value: usize,
    sigev_signo: i32,
    sigev_notify: i32,
    sigev_data: [usize; 2],
}

#[derive(Clone, Copy)]
struct Cred {
    uid: u32,
    euid: u32,
    egid: u32,
    groups: [u32; 8],
    groups_len: usize,
    pid: usize,
}

fn current_cred() -> Cred {
    let proc = current_process();
    let inner = proc.borrow_mut();
    let mut groups = [0u32; 8];
    let mut groups_len = 0usize;
    for gid in inner.supplementary_gids.iter().copied().take(groups.len()) {
        groups[groups_len] = gid;
        groups_len += 1;
    }
    Cred {
        uid: inner.uid,
        euid: inner.euid,
        egid: inner.egid,
        groups,
        groups_len,
        pid: proc.getpid(),
    }
}

#[derive(Clone, Copy)]
struct MqPerm {
    uid: u32,
    gid: u32,
    mode: u16,
}

fn is_owner_or_root(perm: &MqPerm, cred: &Cred) -> bool {
    cred.euid == 0 || cred.euid == perm.uid
}

fn check_access(perm: &MqPerm, cred: &Cred, need_read: bool, need_write: bool) -> bool {
    if cred.euid == 0 {
        return true;
    }
    let class_shift = if cred.euid == perm.uid {
        6
    } else if cred.egid == perm.gid
        || cred.groups[..cred.groups_len]
            .iter()
            .copied()
            .any(|g| g == perm.gid)
    {
        3
    } else {
        0
    };
    let mut need = 0usize;
    if need_read {
        need |= 0b100;
    }
    if need_write {
        need |= 0b010;
    }
    let allow = ((perm.mode as usize) >> class_shift) & 0x7;
    (allow & need) == need
}

#[derive(Clone)]
struct MqMessage {
    prio: u32,
    data: Vec<u8>,
}

#[derive(Clone, Copy)]
struct NotifyRegistration {
    owner_pid: usize,
    notify: i32,
    signo: i32,
    sig_value: usize,
    tid: Option<usize>,
    thread_sockfd: usize,
    thread_cookie: [u8; MQ_NOTIFY_COOKIE_LEN],
}

struct MqQueueState {
    perm: MqPerm,
    maxmsg: usize,
    msgsize: usize,
    messages: VecDeque<MqMessage>,
    recv_waiters: VecDeque<Weak<TaskControlBlock>>,
    send_waiters: VecDeque<Weak<TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
    notify: Option<NotifyRegistration>,
}

struct MqQueue {
    id: usize,
    ipc_ns_id: usize,
    name: Mutex<Option<String>>,
    state: Mutex<MqQueueState>,
}

#[derive(Default)]
struct MqManager {
    next_id: usize,
    by_id: BTreeMap<usize, Arc<MqQueue>>,
    by_name: BTreeMap<String, usize>,
}

impl MqManager {
    fn alloc_id(&mut self) -> usize {
        if self.next_id == 0 {
            self.next_id = 1;
        }
        while self.by_id.contains_key(&self.next_id) {
            self.next_id += 1;
        }
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

lazy_static! {
    // POSIX MQ objects are isolated per IPC namespace.
    static ref MQ_MANAGERS: Mutex<BTreeMap<usize, MqManager>> = Mutex::new(BTreeMap::new());
}

pub struct MqDescriptor {
    queue: Arc<MqQueue>,
    readable: bool,
    writable: bool,
    flags: AtomicU32,
    owner_pid: usize,
}

impl MqDescriptor {
    fn new(
        queue: Arc<MqQueue>,
        readable: bool,
        writable: bool,
        nonblock: bool,
        owner_pid: usize,
    ) -> Self {
        let mut flags = 0u32;
        if nonblock {
            flags |= O_NONBLOCK as u32;
        }
        Self {
            queue,
            readable,
            writable,
            flags: AtomicU32::new(flags),
            owner_pid,
        }
    }

    fn nonblock(&self) -> bool {
        (self.flags.load(Ordering::Relaxed) & (O_NONBLOCK as u32)) != 0
    }

    fn set_nonblock(&self, enabled: bool) {
        if enabled {
            self.flags.fetch_or(O_NONBLOCK as u32, Ordering::Relaxed);
        } else {
            self.flags
                .fetch_and(!(O_NONBLOCK as u32), Ordering::Relaxed);
        }
    }

    fn poll_mask_from_state(&self, state: &MqQueueState) -> i16 {
        let mut mask = 0;
        if self.readable && !state.messages.is_empty() {
            mask |= POLLIN;
        }
        if self.writable && state.messages.len() < state.maxmsg {
            mask |= POLLOUT;
        }
        mask
    }
}

impl Drop for MqDescriptor {
    fn drop(&mut self) {
        maybe_clear_notify_for_owner(&self.queue, self.owner_pid);
        gc_unlinked_queue(&self.queue);
    }
}

impl File for MqDescriptor {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn poll_mask(&self) -> i16 {
        let state = self.queue.state.lock();
        self.poll_mask_from_state(&state)
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut state = self.queue.state.lock();
        if self.poll_mask_from_state(&state) != 0 {
            return true;
        }
        state.poll_waiters.register_waiter(task)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn maybe_clear_notify_for_owner(queue: &Arc<MqQueue>, owner_pid: usize) {
    let notify = {
        let mut state = queue.state.lock();
        if state
            .notify
            .is_some_and(|notify| notify.owner_pid == owner_pid)
        {
            state.notify.take()
        } else {
            None
        }
    };
    if let Some(reg) = notify {
        if reg.notify == SIGEV_THREAD {
            let _ = crate::syscall::net::mq_notify_send_thread_event(
                reg.owner_pid,
                reg.thread_sockfd,
                reg.thread_cookie,
                MQ_NOTIFY_REMOVED,
            );
        }
    }
}

fn gc_unlinked_queue(queue: &Arc<MqQueue>) {
    let mut managers = MQ_MANAGERS.lock();
    let Some(mgr) = managers.get_mut(&queue.ipc_ns_id) else {
        return;
    };
    let queue_id = queue.id;
    let should_remove = {
        let Some(queue) = mgr.by_id.get(&queue_id) else {
            return;
        };
        let no_name = queue.name.lock().is_none();
        no_name && Arc::strong_count(queue) <= 2
    };
    if should_remove {
        mgr.by_id.remove(&queue_id);
    }
}

fn retain_blocked_waiters(waiters: &mut VecDeque<Weak<TaskControlBlock>>) {
    waiters.retain(|w| {
        let Some(task) = w.upgrade() else {
            return false;
        };
        let inner = task.borrow_mut();
        inner.task_status == TaskStatus::Blocked
    });
}

fn add_waiter_once(waiters: &mut VecDeque<Weak<TaskControlBlock>>, task: &Arc<TaskControlBlock>) {
    if waiters
        .iter()
        .any(|w| w.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
    {
        return;
    }
    waiters.push_back(Arc::downgrade(task));
}

fn wake_all_waiters(waiters: &mut VecDeque<Weak<TaskControlBlock>>) {
    retain_blocked_waiters(waiters);
    let mut wake = Vec::new();
    for waiter in waiters.drain(..) {
        if let Some(task) = waiter.upgrade() {
            wake.push(task);
        }
    }
    for task in wake {
        wakeup_task(task);
    }
}

fn wake_poll_waiters(state: &mut MqQueueState) {
    let waiters = state.poll_waiters.take_wakeups();
    wake_tasks(waiters);
}

fn mq_queues_max_limit() -> usize {
    let Some(inode) = find_path_in_roots(PROCFS_QUEUES_MAX) else {
        return MQ_DEFAULT_QUEUES_MAX;
    };
    let mut buf = [0u8; 64];
    let len = inode.read_at(0, &mut buf);
    if len == 0 {
        return MQ_DEFAULT_QUEUES_MAX;
    }
    let Ok(raw) = core::str::from_utf8(&buf[..len]) else {
        return MQ_DEFAULT_QUEUES_MAX;
    };
    let Ok(value) = raw.trim().parse::<usize>() else {
        return MQ_DEFAULT_QUEUES_MAX;
    };
    value.clamp(1, MQ_HARD_QUEUES_MAX)
}

fn monotonic_now_ns() -> u64 {
    let ticks = get_time() as u128;
    let freq = clock_freq() as u128;
    if freq == 0 {
        return 0;
    }
    (ticks.saturating_mul(NSEC_PER_SEC as u128) / freq) as u64
}

fn realtime_now_ns() -> u64 {
    let sec = crate::syscall::time_sys::realtime_now_seconds();
    sec.saturating_mul(NSEC_PER_SEC)
        .saturating_add(monotonic_now_ns() % NSEC_PER_SEC)
}

fn parse_abs_timeout(timeout_ptr: usize) -> Result<Option<u64>, isize> {
    if timeout_ptr == 0 {
        return Ok(None);
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value(token, timeout_ptr as *const TimeSpecUser) else {
        return Err(EFAULT);
    };
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NSEC_PER_SEC as i64 {
        return Err(EINVAL);
    }
    let sec = ts.tv_sec as u64;
    let nsec = ts.tv_nsec as u64;
    Ok(Some(sec.saturating_mul(NSEC_PER_SEC).saturating_add(nsec)))
}

fn timed_out(deadline_ns: Option<u64>) -> bool {
    deadline_ns.is_some_and(|deadline| realtime_now_ns() >= deadline)
}

fn arm_timeout_timer(task: &Arc<TaskControlBlock>, deadline_ns: u64) {
    let now = realtime_now_ns();
    let remain_ns = deadline_ns.saturating_sub(now);
    let mut wait_ms = remain_ns / 1_000_000;
    if remain_ns % 1_000_000 != 0 {
        wait_ms = wait_ms.saturating_add(1);
    }
    let wait_ms = (wait_ms as usize).max(1);
    add_timer(Arc::clone(task), wait_ms);
}

fn has_pending_unmasked_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_unmasked_pending(inner.pending_signals, inner.signal_mask, true)
}

fn current_ipc_namespace_id() -> usize {
    let process = current_process();
    process.borrow_mut().ipc_ns_id
}

fn read_queue_name(ptr: usize) -> Result<String, isize> {
    if ptr == 0 {
        return Err(EFAULT);
    }
    let token = get_current_token();
    let mut bytes = Vec::new();
    let mut cur = ptr;
    loop {
        let Some(ch) = try_read_user_value(token, cur as *const u8) else {
            return Err(EFAULT);
        };
        if ch == 0 {
            break;
        }
        bytes.push(ch);
        if bytes.len() > MQ_NAME_MAX_WITH_SLASH {
            return Err(ENAMETOOLONG);
        }
        cur = cur.saturating_add(1);
    }
    if bytes.is_empty() {
        return Err(EINVAL);
    }
    let name = if bytes[0] == b'/' {
        if bytes.len() == 1 {
            return Err(EINVAL);
        }
        &bytes[1..]
    } else {
        &bytes[..]
    };
    if name.is_empty() {
        return Err(EINVAL);
    }
    if name.len() > MQ_NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    if name.iter().any(|ch| *ch == b'/') {
        return Err(EINVAL);
    }
    String::from_utf8(name.to_vec()).map_err(|_| EINVAL)
}

fn resolve_fd_file(fd: usize) -> Result<Arc<dyn File + Send + Sync>, isize> {
    let process = current_files_process();
    {
        let inner = process.borrow_mut();
        if fd >= inner.fd_table.len() {
            return Err(EBADF);
        }
        inner.fd_table[fd].clone().ok_or(EBADF)
    }
}

fn install_descriptor(desc: Arc<MqDescriptor>, oflag: usize) -> Result<usize, isize> {
    let file: Arc<dyn File + Send + Sync> = desc;
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return Err(EMFILE);
    };
    inner.fd_table[fd] = Some(file);
    inner.ensure_fd_flags_len();
    let mut fd_flags = 0u32;
    if (oflag & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    if (oflag & O_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK as u32;
    }
    inner.fd_flags[fd] = fd_flags;
    Ok(fd)
}

fn deliver_notification(reg: NotifyRegistration, sender_pid: i32, sender_uid: u32) {
    if reg.notify == SIGEV_THREAD {
        let _ = crate::syscall::net::mq_notify_send_thread_event(
            reg.owner_pid,
            reg.thread_sockfd,
            reg.thread_cookie,
            MQ_NOTIFY_WOKENUP,
        );
        return;
    }
    let signo = reg.signo as usize;
    if signo == 0 || signo > RT_SIG_MAX || signal_bit(signo).is_none() {
        return;
    }
    let _ = crate::syscall::signal::queue_signal_with_info(
        reg.owner_pid,
        reg.tid,
        signo,
        sender_pid,
        sender_uid,
        SI_MESGQ,
        reg.sig_value,
    );
}

pub fn syscall_mq_open(name: usize, oflag: usize, mode: usize, attr: usize) -> isize {
    let qname = match read_queue_name(name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let accmode = oflag & O_ACCMODE;
    let (readable, writable) = match accmode {
        O_RDONLY => (true, false),
        O_WRONLY => (false, true),
        O_RDWR => (true, true),
        _ => return EINVAL,
    };
    let cred = current_cred();
    let ipc_ns_id = current_ipc_namespace_id();
    let mut created_new_queue = false;

    let queue = {
        let mut managers = MQ_MANAGERS.lock();
        let mgr = managers.entry(ipc_ns_id).or_default();
        if let Some(id) = mgr.by_name.get(&qname).copied() {
            if (oflag & O_CREAT) != 0 && (oflag & O_EXCL) != 0 {
                return EEXIST;
            }
            let Some(queue) = mgr.by_id.get(&id).cloned() else {
                return ENOENT;
            };
            let state = queue.state.lock();
            if !check_access(&state.perm, &cred, readable, writable) {
                return EACCES;
            }
            drop(state);
            queue
        } else {
            if (oflag & O_CREAT) == 0 {
                return ENOENT;
            }
            let mut mq_maxmsg = MQ_DEFAULT_MAXMSG;
            let mut mq_msgsize = MQ_DEFAULT_MSGSIZE;
            if attr != 0 {
                let token = get_current_token();
                let Some(user_attr) = try_read_user_value(token, attr as *const MqAttrUser) else {
                    return EFAULT;
                };
                if user_attr.mq_maxmsg <= 0 || user_attr.mq_msgsize <= 0 {
                    return EINVAL;
                }
                mq_maxmsg = user_attr.mq_maxmsg as usize;
                mq_msgsize = user_attr.mq_msgsize as usize;
            }
            if mgr.by_id.len() >= mq_queues_max_limit() {
                return ENOSPC;
            }
            let id = mgr.alloc_id();
            let queue = Arc::new(MqQueue {
                id,
                ipc_ns_id,
                name: Mutex::new(Some(qname.clone())),
                state: Mutex::new(MqQueueState {
                    perm: MqPerm {
                        uid: cred.euid,
                        gid: cred.egid,
                        mode: (mode as u16) & 0o777,
                    },
                    maxmsg: mq_maxmsg,
                    msgsize: mq_msgsize,
                    messages: VecDeque::new(),
                    recv_waiters: VecDeque::new(),
                    send_waiters: VecDeque::new(),
                    poll_waiters: PollWaitQueue::default(),
                    notify: None,
                }),
            });
            mgr.by_name.insert(qname.clone(), id);
            mgr.by_id.insert(id, queue.clone());
            created_new_queue = true;
            queue
        }
    };
    let queue_id = queue.id;

    let desc = Arc::new(MqDescriptor::new(
        queue,
        readable,
        writable,
        (oflag & O_NONBLOCK) != 0,
        cred.pid,
    ));
    match install_descriptor(desc, oflag) {
        Ok(fd) => fd as isize,
        Err(e) => {
            // Keep mq_open atomic: if queue creation succeeded but fd install failed
            // (e.g. EMFILE), drop the freshly created queue from the global namespace.
            if created_new_queue {
                let mut managers = MQ_MANAGERS.lock();
                let Some(mgr) = managers.get_mut(&ipc_ns_id) else {
                    return e;
                };
                if mgr.by_name.get(&qname).is_some_and(|id| *id == queue_id) {
                    mgr.by_name.remove(&qname);
                }
                mgr.by_id.remove(&queue_id);
            }
            e
        }
    }
}

pub fn syscall_mq_unlink(name: usize) -> isize {
    let qname = match read_queue_name(name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let cred = current_cred();
    let ipc_ns_id = current_ipc_namespace_id();
    let queue = {
        let mut managers = MQ_MANAGERS.lock();
        let Some(mgr) = managers.get_mut(&ipc_ns_id) else {
            return ENOENT;
        };
        let Some(id) = mgr.by_name.get(&qname).copied() else {
            return ENOENT;
        };
        let Some(queue) = mgr.by_id.get(&id).cloned() else {
            return ENOENT;
        };
        let allowed = {
            let state = queue.state.lock();
            is_owner_or_root(&state.perm, &cred)
        };
        if !allowed {
            return EACCES;
        }
        mgr.by_name.remove(&qname);
        queue
    };
    *queue.name.lock() = None;
    gc_unlinked_queue(&queue);
    0
}

pub fn syscall_mq_getsetattr(mqdes: usize, newattr: usize, oldattr: usize) -> isize {
    let file = match resolve_fd_file(mqdes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(desc) = file.as_any().downcast_ref::<MqDescriptor>() else {
        return EBADF;
    };
    let state = desc.queue.state.lock();
    let old = MqAttrUser {
        mq_flags: if desc.nonblock() {
            O_NONBLOCK as i64
        } else {
            0
        },
        mq_maxmsg: state.maxmsg as i64,
        mq_msgsize: state.msgsize as i64,
        mq_curmsgs: state.messages.len() as i64,
        __reserved: [0; 4],
    };
    drop(state);

    let token = get_current_token();
    if oldattr != 0 && try_write_user_value(token, oldattr as *mut MqAttrUser, &old).is_err() {
        return EFAULT;
    }
    if newattr != 0 {
        let Some(new_attr) = try_read_user_value(token, newattr as *const MqAttrUser) else {
            return EFAULT;
        };
        desc.set_nonblock((new_attr.mq_flags as usize & O_NONBLOCK) != 0);
    }
    0
}

pub fn syscall_mq_notify(mqdes: usize, notification: usize) -> isize {
    let cred = current_cred();
    let mut parsed = None;
    if notification != 0 {
        let token = get_current_token();
        let Some(ev) = try_read_user_value(token, notification as *const SigeventUser) else {
            return EFAULT;
        };
        let parsed_ev = match ev.sigev_notify {
            SIGEV_NONE => NotifyRegistration {
                owner_pid: cred.pid,
                notify: SIGEV_NONE,
                signo: 0,
                sig_value: ev.sigev_value,
                tid: None,
                thread_sockfd: 0,
                thread_cookie: [0; MQ_NOTIFY_COOKIE_LEN],
            },
            SIGEV_SIGNAL => {
                if ev.sigev_signo <= 0 || ev.sigev_signo as usize > RT_SIG_MAX {
                    return EINVAL;
                }
                NotifyRegistration {
                    owner_pid: cred.pid,
                    notify: SIGEV_SIGNAL,
                    signo: ev.sigev_signo,
                    sig_value: ev.sigev_value,
                    tid: None,
                    thread_sockfd: 0,
                    thread_cookie: [0; MQ_NOTIFY_COOKIE_LEN],
                }
            }
            SIGEV_THREAD => {
                if ev.sigev_signo < 0 {
                    return EBADF;
                }
                let sockfd = ev.sigev_signo as usize;
                let sock_ok =
                    crate::syscall::net::mq_notify_validate_thread_sockfd(cred.pid, sockfd);
                if sock_ok != 0 {
                    return sock_ok;
                }
                let mut cookie = [0u8; MQ_NOTIFY_COOKIE_LEN];
                if try_copy_from_user(token, ev.sigev_value as *const u8, &mut cookie).is_err() {
                    return EFAULT;
                }
                NotifyRegistration {
                    owner_pid: cred.pid,
                    notify: SIGEV_THREAD,
                    signo: ev.sigev_signo,
                    sig_value: ev.sigev_value,
                    tid: None,
                    thread_sockfd: sockfd,
                    thread_cookie: cookie,
                }
            }
            SIGEV_THREAD_ID => {
                if ev.sigev_signo <= 0 || ev.sigev_signo as usize > RT_SIG_MAX {
                    return EINVAL;
                }
                let tid = ev.sigev_data[0] & 0x3fff_ffff;
                if tid == 0 {
                    return EINVAL;
                }
                NotifyRegistration {
                    owner_pid: cred.pid,
                    notify: SIGEV_THREAD_ID,
                    signo: ev.sigev_signo,
                    sig_value: ev.sigev_value,
                    tid: Some(tid),
                    thread_sockfd: 0,
                    thread_cookie: [0; MQ_NOTIFY_COOKIE_LEN],
                }
            }
            _ => return EINVAL,
        };
        parsed = Some(parsed_ev);
    }

    let file = match resolve_fd_file(mqdes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(desc) = file.as_any().downcast_ref::<MqDescriptor>() else {
        return EBADF;
    };
    let mut state = desc.queue.state.lock();
    if let Some(reg) = parsed {
        if state.notify.is_some() {
            return EBUSY;
        }
        state.notify = Some(reg);
        return 0;
    }
    let removed = if state
        .notify
        .is_some_and(|notify| notify.owner_pid == cred.pid)
    {
        state.notify.take()
    } else {
        None
    };
    drop(state);
    if let Some(reg) = removed {
        if reg.notify == SIGEV_THREAD {
            let _ = crate::syscall::net::mq_notify_send_thread_event(
                reg.owner_pid,
                reg.thread_sockfd,
                reg.thread_cookie,
                MQ_NOTIFY_REMOVED,
            );
        }
    }
    0
}

pub fn syscall_mq_timedsend(
    mqdes: usize,
    msg_ptr: usize,
    msg_len: usize,
    msg_prio: usize,
    timeout_ptr: usize,
) -> isize {
    if msg_prio >= MQ_PRIO_MAX {
        return EINVAL;
    }
    let deadline_ns = match parse_abs_timeout(timeout_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let file = match resolve_fd_file(mqdes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(desc) = file.as_any().downcast_ref::<MqDescriptor>() else {
        return EBADF;
    };
    if !desc.writable {
        return EBADF;
    }

    let msgsize = {
        let state = desc.queue.state.lock();
        state.msgsize
    };
    if msg_len > msgsize {
        return EMSGSIZE;
    }
    let mut payload = vec![0u8; msg_len];
    if msg_len > 0 {
        let token = get_current_token();
        if try_copy_from_user(token, msg_ptr as *const u8, &mut payload).is_err() {
            return EFAULT;
        }
    }
    let cred = current_cred();

    loop {
        let mut state = desc.queue.state.lock();
        if state.messages.len() < state.maxmsg {
            let was_empty = state.messages.is_empty();
            let insert_at = state
                .messages
                .iter()
                .position(|m| m.prio < msg_prio as u32)
                .unwrap_or(state.messages.len());
            state.messages.insert(
                insert_at,
                MqMessage {
                    prio: msg_prio as u32,
                    data: payload.clone(),
                },
            );
            wake_all_waiters(&mut state.recv_waiters);
            wake_poll_waiters(&mut state);
            let notify = if was_empty { state.notify.take() } else { None };
            drop(state);
            if let Some(reg) = notify {
                deliver_notification(reg, cred.pid as i32, cred.uid);
            }
            return 0;
        }

        if desc.nonblock() {
            return EAGAIN;
        }
        if timed_out(deadline_ns) {
            return ETIMEDOUT;
        }
        if has_pending_unmasked_signal() {
            return EINTR;
        }
        let Some(task) = current_task() else {
            return EINVAL;
        };
        add_waiter_once(&mut state.send_waiters, &task);
        if let Some(deadline) = deadline_ns {
            arm_timeout_timer(&task, deadline);
        }
        drop(state);
        block_current_and_run_next();
        if has_pending_unmasked_signal() {
            return EINTR;
        }
        if timed_out(deadline_ns) {
            return ETIMEDOUT;
        }
    }
}

pub fn syscall_mq_timedreceive(
    mqdes: usize,
    msg_ptr: usize,
    msg_len: usize,
    msg_prio: usize,
    timeout_ptr: usize,
) -> isize {
    let deadline_ns = match parse_abs_timeout(timeout_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let file = match resolve_fd_file(mqdes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(desc) = file.as_any().downcast_ref::<MqDescriptor>() else {
        return EBADF;
    };
    if !desc.readable {
        return EBADF;
    }
    let token = get_current_token();

    loop {
        let mut state = desc.queue.state.lock();
        if let Some(front) = state.messages.front() {
            if msg_len < front.data.len() {
                return EMSGSIZE;
            }
            let msg = state.messages.pop_front().unwrap();
            wake_all_waiters(&mut state.send_waiters);
            wake_poll_waiters(&mut state);
            drop(state);
            if !msg.data.is_empty()
                && try_copy_to_user(token, msg_ptr as *mut u8, msg.data.as_slice()).is_err()
            {
                return EFAULT;
            }
            if msg_prio != 0
                && try_write_user_value(token, msg_prio as *mut u32, &(msg.prio as u32)).is_err()
            {
                return EFAULT;
            }
            return msg.data.len() as isize;
        }

        if desc.nonblock() {
            return EAGAIN;
        }
        if timed_out(deadline_ns) {
            return ETIMEDOUT;
        }
        if has_pending_unmasked_signal() {
            return EINTR;
        }
        let Some(task) = current_task() else {
            return EINVAL;
        };
        add_waiter_once(&mut state.recv_waiters, &task);
        if let Some(deadline) = deadline_ns {
            arm_timeout_timer(&task, deadline);
        }
        drop(state);
        block_current_and_run_next();
        if has_pending_unmasked_signal() {
            return EINTR;
        }
        if timed_out(deadline_ns) {
            return ETIMEDOUT;
        }
    }
}

#[allow(dead_code)]
pub fn mq_queues_default_limit() -> usize {
    MQ_DEFAULT_QUEUES_MAX
}
