use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::parse_proc_sys_usize;
use crate::mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::block_sleep::add_timer;
use crate::task::manager::wakeup_task;
use crate::task::processor::{block_current_and_run_next, current_process, current_task};
use crate::task::signal::has_wait_interrupting_pending;
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use crate::time::get_time_ms;
use crate::trap::get_current_token;

const IPC_PRIVATE: usize = 0;
const IPC_CREAT: usize = 0x200;
const IPC_EXCL: usize = 0x400;
const IPC_NOWAIT: usize = 0x800;

const IPC_RMID: usize = 0;
const IPC_SET: usize = 1;
const IPC_STAT: usize = 2;
const IPC_INFO: usize = 3;
const MSG_STAT: usize = 11;
const MSG_INFO: usize = 12;
const MSG_STAT_ANY: usize = 13;
const SEM_STAT: usize = 18;
const SEM_INFO: usize = 19;
const SEM_STAT_ANY: usize = 20;

const MSG_NOERROR: usize = 0x1000;
const MSG_EXCEPT: usize = 0x2000;
const MSG_COPY: usize = 0x4000;

const GETPID: usize = 11;
const GETVAL: usize = 12;
const GETALL: usize = 13;
const GETNCNT: usize = 14;
const GETZCNT: usize = 15;
const SETVAL: usize = 16;
const SETALL: usize = 17;

const MSG_R: u16 = 0o400;
const MSG_W: u16 = 0o200;
const SEM_R: u16 = 0o400;
const SEM_A: u16 = 0o200;

const SEMVMX: i32 = 32767;
const SEMMSL: usize = 32000;
const SEMMNS: usize = 1_024_000_000;
const SEMMNI: usize = 32000;
const SEMOPM: usize = 500;
const MSGMNB: usize = 16384;
const MSGMNI: usize = 4096;
const MSGMAX: usize = 8192;
const MSGSSZ: i32 = 16;
const MSGPOOL: i32 = (MSGMNI * MSGMNB / 1024) as i32;
const MSGTQL: i32 = MSGMNB as i32;
const MSGMAP: i32 = MSGMNB as i32;
const MSGSEG: i32 = {
    let seg = MSGPOOL * 1024 / MSGSSZ;
    if seg <= 0xffff { seg } else { 0xffff }
};
const PROCFS_MSGMAX: &str = "/proc/sys/kernel/msgmax";
const PROCFS_MSGMNB: &str = "/proc/sys/kernel/msgmnb";
const PROCFS_MSGMNI: &str = "/proc/sys/kernel/msgmni";
const PROCFS_SEM: &str = "/proc/sys/kernel/sem";
static RUNTIME_MSGMAX_LIMIT: AtomicUsize = AtomicUsize::new(MSGMAX);
static RUNTIME_MSGMNB_LIMIT: AtomicUsize = AtomicUsize::new(MSGMNB);
static RUNTIME_MSGMNI_LIMIT: AtomicUsize = AtomicUsize::new(MSGMNI);
static RUNTIME_SEMMSL_LIMIT: AtomicUsize = AtomicUsize::new(SEMMSL);
static RUNTIME_SEMMNS_LIMIT: AtomicUsize = AtomicUsize::new(SEMMNS);
static RUNTIME_SEMMNI_LIMIT: AtomicUsize = AtomicUsize::new(SEMMNI);
static RUNTIME_SEMOPM_LIMIT: AtomicUsize = AtomicUsize::new(SEMOPM);

#[allow(dead_code)]
pub fn msgmax_limit() -> usize {
    MSGMAX
}

#[allow(dead_code)]
pub fn msgmnb_limit() -> usize {
    MSGMNB
}

#[allow(dead_code)]
pub fn msgmni_limit() -> usize {
    MSGMNI
}

#[allow(dead_code)]
pub fn semmsl_limit() -> usize {
    SEMMSL
}

#[allow(dead_code)]
pub fn semmns_limit() -> usize {
    SEMMNS
}

#[allow(dead_code)]
pub fn semopm_limit() -> usize {
    SEMOPM
}

#[allow(dead_code)]
pub fn semmni_limit() -> usize {
    SEMMNI
}

fn runtime_msgmax_limit() -> usize {
    RUNTIME_MSGMAX_LIMIT.load(Ordering::Relaxed)
}

fn runtime_msgmnb_limit() -> usize {
    RUNTIME_MSGMNB_LIMIT.load(Ordering::Relaxed)
}

fn runtime_msgmni_limit() -> usize {
    RUNTIME_MSGMNI_LIMIT.load(Ordering::Relaxed)
}

fn runtime_sem_limits() -> (usize, usize, usize, usize) {
    (
        RUNTIME_SEMMSL_LIMIT.load(Ordering::Relaxed),
        RUNTIME_SEMMNS_LIMIT.load(Ordering::Relaxed),
        RUNTIME_SEMOPM_LIMIT.load(Ordering::Relaxed),
        RUNTIME_SEMMNI_LIMIT.load(Ordering::Relaxed),
    )
}

pub fn runtime_msgmax_for_procfs() -> usize {
    runtime_msgmax_limit()
}

pub fn runtime_msgmnb_for_procfs() -> usize {
    runtime_msgmnb_limit()
}

pub fn runtime_msgmni_for_procfs() -> usize {
    runtime_msgmni_limit()
}

pub fn runtime_sem_limits_for_procfs() -> (usize, usize, usize, usize) {
    runtime_sem_limits()
}

pub fn write_msg_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    let slot = match path {
        PROCFS_MSGMAX => &RUNTIME_MSGMAX_LIMIT,
        PROCFS_MSGMNB => &RUNTIME_MSGMNB_LIMIT,
        PROCFS_MSGMNI => &RUNTIME_MSGMNI_LIMIT,
        _ => return Err(err(SyscallError::EINVAL)),
    };
    let value = parse_proc_sys_usize(data)?;
    if value == 0 || value > i32::MAX as usize {
        return Err(err(SyscallError::EINVAL));
    }
    slot.store(value, Ordering::Relaxed);
    Ok(alloc::format!("{}\n", value).into_bytes())
}

pub fn write_sem_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    if path != PROCFS_SEM {
        return Err(err(SyscallError::EINVAL));
    }
    let Ok(raw) = core::str::from_utf8(data) else {
        return Err(err(SyscallError::EINVAL));
    };
    let mut parts = raw.split_whitespace();
    let Some(semmsl) = parts.next().and_then(|v| v.parse::<usize>().ok()) else {
        return Err(err(SyscallError::EINVAL));
    };
    let Some(semmns) = parts.next().and_then(|v| v.parse::<usize>().ok()) else {
        return Err(err(SyscallError::EINVAL));
    };
    let Some(semopm) = parts.next().and_then(|v| v.parse::<usize>().ok()) else {
        return Err(err(SyscallError::EINVAL));
    };
    let Some(semmni) = parts.next().and_then(|v| v.parse::<usize>().ok()) else {
        return Err(err(SyscallError::EINVAL));
    };
    if parts.next().is_some() {
        return Err(err(SyscallError::EINVAL));
    }
    let values = [semmsl, semmns, semopm, semmni];
    if values
        .iter()
        .any(|value| *value == 0 || *value > i32::MAX as usize)
    {
        return Err(err(SyscallError::EINVAL));
    }
    if semmns < semmsl {
        return Err(err(SyscallError::EINVAL));
    }
    RUNTIME_SEMMSL_LIMIT.store(semmsl, Ordering::Relaxed);
    RUNTIME_SEMMNS_LIMIT.store(semmns, Ordering::Relaxed);
    RUNTIME_SEMOPM_LIMIT.store(semopm, Ordering::Relaxed);
    RUNTIME_SEMMNI_LIMIT.store(semmni, Ordering::Relaxed);
    Ok(alloc::format!("{}\t{}\t{}\t{}\n", semmsl, semmns, semopm, semmni).into_bytes())
}

pub fn proc_sysvipc_msg() -> String {
    let mut out = String::from(
        "       key      msqid perms      cbytes       qnum       qbytes lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n",
    );
    let ipc_ns_id = current_ipc_namespace_id();
    let managers = MSG_MANAGERS.lock();
    let Some(mgr) = managers.get(&ipc_ns_id) else {
        return out;
    };
    for queue in mgr.queues.values() {
        let key = queue.key.unwrap_or(0);
        let line = alloc::format!(
            "{:10} {:10} {:5o} {:11} {:10} {:12} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10}\n",
            key,
            queue.id,
            queue.perm.mode & 0o777,
            queue.cbytes,
            queue.msgs.len(),
            queue.qbytes,
            queue.lspid,
            queue.lrpid,
            queue.perm.uid,
            queue.perm.gid,
            queue.perm.cuid,
            queue.perm.cgid,
            queue.stime,
            queue.rtime,
            queue.ctime
        );
        out.push_str(&line);
    }
    out
}

pub fn proc_sysvipc_sem() -> String {
    let mut out = String::from(
        "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n",
    );
    let ipc_ns_id = current_ipc_namespace_id();
    let managers = SEM_MANAGERS.lock();
    let Some(mgr) = managers.get(&ipc_ns_id) else {
        return out;
    };
    for set in mgr.sets.values() {
        let key = set.key.unwrap_or(0);
        let line = alloc::format!(
            "{:10} {:10} {:5o} {:10} {:5} {:5} {:5} {:5} {:10} {:10}\n",
            key,
            set.id,
            set.perm.mode & 0o777,
            set.sems.len(),
            set.perm.uid,
            set.perm.gid,
            set.perm.cuid,
            set.perm.cgid,
            set.otime,
            set.ctime
        );
        out.push_str(&line);
    }
    out
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IpcPermUser {
    __key: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    __pad1: u16,
    __seq: u16,
    __pad2: u16,
    __unused1: u64,
    __unused2: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MsqidDsUser {
    msg_perm: IpcPermUser,
    msg_stime: i64,
    msg_rtime: i64,
    msg_ctime: i64,
    msg_cbytes: u64,
    msg_qnum: u64,
    msg_qbytes: u64,
    msg_lspid: u32,
    msg_lrpid: u32,
    __unused4: u64,
    __unused5: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MsgInfoUser {
    msgpool: i32,
    msgmap: i32,
    msgmax: i32,
    msgmnb: i32,
    msgmni: i32,
    msgssz: i32,
    msgtql: i32,
    msgseg: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SemidDsUser {
    sem_perm: IpcPermUser,
    sem_otime: i64,
    sem_ctime: i64,
    sem_nsems: u64,
    __unused3: u64,
    __unused4: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SemInfoUser {
    semmap: i32,
    semmni: i32,
    semmns: i32,
    semmnu: i32,
    semmsl: i32,
    semopm: i32,
    semume: i32,
    semusz: i32,
    semvmx: i32,
    semaem: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SemBuf {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SemTimeSpecUser {
    tv_sec: i64,
    tv_nsec: i64,
}

#[derive(Clone, Copy)]
struct IpcPermKernel {
    key: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
}

impl IpcPermKernel {
    fn to_user(self) -> IpcPermUser {
        IpcPermUser {
            __key: self.key,
            uid: self.uid,
            gid: self.gid,
            cuid: self.cuid,
            cgid: self.cgid,
            mode: self.mode,
            ..IpcPermUser::default()
        }
    }
}

#[derive(Clone)]
struct Msg {
    mtype: i64,
    mtext: Vec<u8>,
}

struct MsgQueue {
    id: usize,
    key: Option<u32>,
    perm: IpcPermKernel,
    msgs: VecDeque<Msg>,
    recv_waiters: VecDeque<Weak<TaskControlBlock>>,
    send_waiters: VecDeque<Weak<TaskControlBlock>>,
    cbytes: usize,
    qbytes: usize,
    lspid: u32,
    lrpid: u32,
    stime: i64,
    rtime: i64,
    ctime: i64,
}

#[derive(Default)]
struct MsgManager {
    next_id: usize,
    queues: BTreeMap<usize, MsgQueue>,
    key2id: BTreeMap<u32, usize>,
}

impl MsgManager {
    fn alloc_id(&mut self) -> usize {
        if self.next_id < 1 {
            self.next_id = 1;
        }
        while self.queues.contains_key(&self.next_id) {
            self.next_id += 1;
        }
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn remove_queue(&mut self, id: usize) -> Vec<Arc<TaskControlBlock>> {
        let mut wake = Vec::new();
        if let Some(mut queue) = self.queues.remove(&id) {
            retain_blocked_waiters(&mut queue.recv_waiters);
            retain_blocked_waiters(&mut queue.send_waiters);
            for waiter in queue.recv_waiters.drain(..) {
                if let Some(task) = waiter.upgrade() {
                    wake.push(task);
                }
            }
            for waiter in queue.send_waiters.drain(..) {
                if let Some(task) = waiter.upgrade() {
                    wake.push(task);
                }
            }
            if let Some(key) = queue.key {
                if self.key2id.get(&key).copied() == Some(id) {
                    self.key2id.remove(&key);
                }
            }
        }
        wake
    }
}

struct SemEntry {
    val: i32,
    last_pid: u32,
    ncnt_waiters: VecDeque<Weak<TaskControlBlock>>,
    zcnt_waiters: VecDeque<Weak<TaskControlBlock>>,
}

impl SemEntry {
    fn new() -> Self {
        Self {
            val: 0,
            last_pid: 0,
            ncnt_waiters: VecDeque::new(),
            zcnt_waiters: VecDeque::new(),
        }
    }
}

struct SemSet {
    id: usize,
    key: Option<u32>,
    perm: IpcPermKernel,
    sems: Vec<SemEntry>,
    otime: i64,
    ctime: i64,
}

#[derive(Default)]
struct SemManager {
    next_id: usize,
    sets: BTreeMap<usize, SemSet>,
    key2id: BTreeMap<u32, usize>,
}

impl SemManager {
    fn alloc_id(&mut self) -> usize {
        if self.next_id < 1 {
            self.next_id = 1;
        }
        while self.sets.contains_key(&self.next_id) {
            self.next_id += 1;
        }
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn remove_set(&mut self, id: usize) -> Vec<Arc<TaskControlBlock>> {
        let mut wake = Vec::new();
        if let Some(mut set) = self.sets.remove(&id) {
            for sem in set.sems.iter_mut() {
                for waiter in sem.ncnt_waiters.drain(..) {
                    if let Some(task) = waiter.upgrade() {
                        wake.push(task);
                    }
                }
                for waiter in sem.zcnt_waiters.drain(..) {
                    if let Some(task) = waiter.upgrade() {
                        wake.push(task);
                    }
                }
            }
            if let Some(key) = set.key {
                if self.key2id.get(&key).copied() == Some(id) {
                    self.key2id.remove(&key);
                }
            }
        }
        wake
    }
}

lazy_static! {
    // SysV IPC objects are scoped per IPC namespace.
    static ref MSG_MANAGERS: Mutex<BTreeMap<usize, MsgManager>> = Mutex::new(BTreeMap::new());
    static ref SEM_MANAGERS: Mutex<BTreeMap<usize, SemManager>> = Mutex::new(BTreeMap::new());
}

struct Cred {
    euid: u32,
    egid: u32,
    groups: Vec<u32>,
    pid: u32,
}

fn now_secs() -> i64 {
    crate::syscall::time_sys::realtime_now_seconds() as i64
}

fn current_ipc_namespace_id() -> usize {
    let process = current_process();
    process.borrow_mut().ipc_ns_id
}

fn current_cred() -> Cred {
    let process = current_process();
    let inner = process.borrow_mut();
    Cred {
        euid: inner.euid,
        egid: inner.egid,
        groups: inner.supplementary_gids.clone(),
        pid: process.getpid() as u32,
    }
}

fn is_owner_or_root(perm: &IpcPermKernel, cred: &Cred) -> bool {
    cred.euid == 0 || cred.euid == perm.uid || cred.euid == perm.cuid
}

fn check_ipc_access(perm: &IpcPermKernel, req: u16, cred: &Cred) -> bool {
    if req == 0 || cred.euid == 0 {
        return true;
    }
    let class_shift = if cred.euid == perm.uid || cred.euid == perm.cuid {
        6
    } else if cred.egid == perm.gid
        || cred.egid == perm.cgid
        || cred
            .groups
            .iter()
            .any(|g| *g == perm.gid || *g == perm.cgid)
    {
        3
    } else {
        0
    };
    let need = ((req as usize) >> 6) & 0x7;
    let allow = ((perm.mode as usize) >> class_shift) & 0x7;
    (allow & need) == need
}

fn retain_blocked_waiters(queue: &mut VecDeque<Weak<TaskControlBlock>>) {
    queue.retain(|task| {
        let Some(task) = task.upgrade() else {
            return false;
        };
        let inner = task.borrow_mut();
        inner.task_status == TaskStatus::Blocked
    });
}

fn wake_sem_waiters(sem: &mut SemEntry) {
    retain_blocked_waiters(&mut sem.ncnt_waiters);
    retain_blocked_waiters(&mut sem.zcnt_waiters);
    let mut wake = Vec::new();
    if sem.val == 0 {
        for waiter in sem.zcnt_waiters.drain(..) {
            if let Some(task) = waiter.upgrade() {
                wake.push(task);
            }
        }
    }
    if sem.val > 0 {
        for waiter in sem.ncnt_waiters.drain(..) {
            if let Some(task) = waiter.upgrade() {
                wake.push(task);
            }
        }
    }
    for task in wake {
        wakeup_task(task);
    }
}

fn add_waiter_once(queue: &mut VecDeque<Weak<TaskControlBlock>>, task: &Arc<TaskControlBlock>) {
    if queue
        .iter()
        .any(|w| w.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
    {
        return;
    }
    queue.push_back(Arc::downgrade(task));
}

fn wake_msg_waiters(queue: &mut VecDeque<Weak<TaskControlBlock>>) {
    retain_blocked_waiters(queue);
    let mut wake = Vec::new();
    for waiter in queue.drain(..) {
        if let Some(task) = waiter.upgrade() {
            wake.push(task);
        }
    }
    for task in wake {
        wakeup_task(task);
    }
}

fn has_pending_unmasked_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
}

fn msq_to_user(queue: &MsgQueue) -> MsqidDsUser {
    MsqidDsUser {
        msg_perm: queue.perm.to_user(),
        msg_stime: queue.stime,
        msg_rtime: queue.rtime,
        msg_ctime: queue.ctime,
        msg_cbytes: queue.cbytes as u64,
        msg_qnum: queue.msgs.len() as u64,
        msg_qbytes: queue.qbytes as u64,
        msg_lspid: queue.lspid,
        msg_lrpid: queue.lrpid,
        ..MsqidDsUser::default()
    }
}

fn sem_to_user(set: &SemSet) -> SemidDsUser {
    SemidDsUser {
        sem_perm: set.perm.to_user(),
        sem_otime: set.otime,
        sem_ctime: set.ctime,
        sem_nsems: set.sems.len() as u64,
        ..SemidDsUser::default()
    }
}

pub fn syscall_msgget(key: usize, msgflg: usize) -> isize {
    let cred = current_cred();
    let key_u32 = key as u32;
    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = MSG_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();

    if key != IPC_PRIVATE {
        if let Some(id) = mgr.key2id.get(&key_u32).copied() {
            if (msgflg & IPC_CREAT) != 0 && (msgflg & IPC_EXCL) != 0 {
                return err(SyscallError::EEXIST);
            }
            let Some(queue) = mgr.queues.get(&id) else {
                return err(SyscallError::ENOENT);
            };
            let req = (msgflg & 0o700) as u16;
            if !check_ipc_access(&queue.perm, req, &cred) {
                return err(SyscallError::EACCES);
            }
            return id as isize;
        }
        if (msgflg & IPC_CREAT) == 0 {
            return err(SyscallError::ENOENT);
        }
    }
    if mgr.queues.len() >= runtime_msgmni_limit() {
        return err(SyscallError::ENOSPC);
    }

    let id = mgr.alloc_id();
    let mode = (msgflg & 0o777) as u16;
    let perm = IpcPermKernel {
        key: key_u32,
        uid: cred.euid,
        gid: cred.egid,
        cuid: cred.euid,
        cgid: cred.egid,
        mode,
    };
    let queue = MsgQueue {
        id,
        key: if key == IPC_PRIVATE {
            None
        } else {
            Some(key_u32)
        },
        perm,
        msgs: VecDeque::new(),
        recv_waiters: VecDeque::new(),
        send_waiters: VecDeque::new(),
        cbytes: 0,
        qbytes: runtime_msgmnb_limit(),
        lspid: 0,
        lrpid: 0,
        stime: 0,
        rtime: 0,
        ctime: now_secs(),
    };
    if let Some(k) = queue.key {
        mgr.key2id.insert(k, id);
    }
    mgr.queues.insert(id, queue);
    id as isize
}

pub fn syscall_msgctl(msqid: usize, cmd: usize, buf: usize) -> isize {
    let cred = current_cred();
    let token = get_current_token();
    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = MSG_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();

    if cmd == IPC_INFO || cmd == MSG_INFO {
        let highest_index = mgr.queues.keys().next_back().copied().unwrap_or(0);
        let (msgpool, msgmap, msgtql) = if cmd == MSG_INFO {
            let total_messages = mgr
                .queues
                .values()
                .fold(0usize, |acc, queue| acc.saturating_add(queue.msgs.len()));
            let total_bytes = mgr
                .queues
                .values()
                .fold(0usize, |acc, queue| acc.saturating_add(queue.cbytes));
            (
                mgr.queues.len().min(i32::MAX as usize) as i32,
                total_messages.min(i32::MAX as usize) as i32,
                total_bytes.min(i32::MAX as usize) as i32,
            )
        } else {
            (MSGPOOL, MSGMAP, MSGTQL)
        };
        let info = MsgInfoUser {
            msgpool,
            msgmap,
            msgmax: runtime_msgmax_limit() as i32,
            msgmnb: runtime_msgmnb_limit() as i32,
            msgmni: runtime_msgmni_limit() as i32,
            msgssz: MSGSSZ,
            msgtql,
            msgseg: MSGSEG,
            ..MsgInfoUser::default()
        };
        if try_write_user_value(token, buf as *mut MsgInfoUser, &info).is_err() {
            return err(SyscallError::EFAULT);
        }
        return highest_index as isize;
    }

    if cmd == MSG_STAT || cmd == MSG_STAT_ANY {
        let Some(queue) = mgr.queues.get(&msqid) else {
            return err(SyscallError::EINVAL);
        };
        if cmd == MSG_STAT_ANY || check_ipc_access(&queue.perm, MSG_R, &cred) {
            let ds = msq_to_user(queue);
            if try_write_user_value(token, buf as *mut MsqidDsUser, &ds).is_err() {
                return err(SyscallError::EFAULT);
            }
            return msqid as isize;
        }
        return err(SyscallError::EACCES);
    }

    let Some(queue) = mgr.queues.get_mut(&msqid) else {
        return err(SyscallError::EINVAL);
    };
    match cmd {
        IPC_RMID => {
            if !is_owner_or_root(&queue.perm, &cred) {
                return err(SyscallError::EPERM);
            }
            let wake = mgr.remove_queue(msqid);
            drop(managers);
            for task in wake {
                wakeup_task(task);
            }
            0
        }
        IPC_STAT => {
            if !check_ipc_access(&queue.perm, MSG_R, &cred) {
                return err(SyscallError::EACCES);
            }
            let ds = msq_to_user(queue);
            if try_write_user_value(token, buf as *mut MsqidDsUser, &ds).is_err() {
                return err(SyscallError::EFAULT);
            }
            0
        }
        IPC_SET => {
            if !is_owner_or_root(&queue.perm, &cred) {
                return err(SyscallError::EPERM);
            }
            let Some(ds) = try_read_user_value(token, buf as *const MsqidDsUser) else {
                return err(SyscallError::EFAULT);
            };
            queue.perm.uid = ds.msg_perm.uid;
            queue.perm.gid = ds.msg_perm.gid;
            queue.perm.mode = ds.msg_perm.mode & 0o777;
            queue.qbytes = ds.msg_qbytes as usize;
            queue.ctime = now_secs();
            wake_msg_waiters(&mut queue.send_waiters);
            0
        }
        _ => err(SyscallError::EINVAL),
    }
}

pub fn syscall_msgsnd(msqid: usize, msgp: usize, msgsz: usize, msgflg: usize) -> isize {
    if (msgsz as isize) < 0 {
        return err(SyscallError::EINVAL);
    }
    if msgsz > runtime_msgmax_limit() {
        return err(SyscallError::EINVAL);
    }
    let cred = current_cred();
    let token = get_current_token();
    let Some(mtype) = try_read_user_value(token, msgp as *const i64) else {
        return err(SyscallError::EFAULT);
    };
    if mtype <= 0 {
        return err(SyscallError::EINVAL);
    }
    let mut mtext = vec![0u8; msgsz];
    if try_copy_from_user(
        token,
        (msgp + core::mem::size_of::<i64>()) as *const u8,
        &mut mtext,
    )
    .is_err()
    {
        return err(SyscallError::EFAULT);
    }

    let mut waited = false;
    let ipc_ns_id = current_ipc_namespace_id();
    loop {
        let mut managers = MSG_MANAGERS.lock();
        let mgr = managers.entry(ipc_ns_id).or_default();
        let Some(queue) = mgr.queues.get_mut(&msqid) else {
            return if waited {
                err(SyscallError::EIDRM)
            } else {
                err(SyscallError::EINVAL)
            };
        };
        if !check_ipc_access(&queue.perm, MSG_W, &cred) {
            return err(SyscallError::EACCES);
        }
        if queue.cbytes.saturating_add(msgsz) <= queue.qbytes {
            queue.msgs.push_back(Msg {
                mtype,
                mtext: mtext.clone(),
            });
            queue.cbytes += msgsz;
            queue.lspid = cred.pid;
            queue.stime = now_secs();
            wake_msg_waiters(&mut queue.recv_waiters);
            return 0;
        }
        if (msgflg & IPC_NOWAIT) != 0 {
            return err(SyscallError::EAGAIN);
        }
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        let Some(task) = current_task() else {
            return err(SyscallError::EINVAL);
        };
        add_waiter_once(&mut queue.send_waiters, &task);
        drop(managers);
        block_current_and_run_next();
        waited = true;
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
    }
}

pub fn syscall_msgrcv(
    msqid: usize,
    msgp: usize,
    msgsz: usize,
    msgtyp: isize,
    msgflg: usize,
) -> isize {
    if (msgsz as isize) < 0 {
        return err(SyscallError::EINVAL);
    }
    let cred = current_cred();
    let token = get_current_token();
    let msg_copy = (msgflg & MSG_COPY) != 0;
    let msg_except = (msgflg & MSG_EXCEPT) != 0;
    if msg_copy {
        if (msgflg & IPC_NOWAIT) == 0 || msg_except || msgtyp < 0 {
            return err(SyscallError::EINVAL);
        }
    } else if msg_except && msgtyp == 0 {
        return err(SyscallError::EINVAL);
    }

    let mut waited = false;
    let ipc_ns_id = current_ipc_namespace_id();
    loop {
        let mut managers = MSG_MANAGERS.lock();
        let mgr = managers.entry(ipc_ns_id).or_default();
        let Some(queue) = mgr.queues.get_mut(&msqid) else {
            return if waited {
                err(SyscallError::EIDRM)
            } else {
                err(SyscallError::EINVAL)
            };
        };
        if !check_ipc_access(&queue.perm, MSG_R, &cred) {
            return err(SyscallError::EACCES);
        }

        let pick_idx = if queue.msgs.is_empty() {
            None
        } else if msg_copy {
            let idx = msgtyp as usize;
            if idx < queue.msgs.len() {
                Some(idx)
            } else {
                None
            }
        } else if msgtyp == 0 {
            Some(0)
        } else if msgtyp > 0 {
            if msg_except {
                queue.msgs.iter().position(|m| m.mtype != msgtyp as i64)
            } else {
                queue.msgs.iter().position(|m| m.mtype == msgtyp as i64)
            }
        } else {
            let limit = (-msgtyp) as i64;
            queue
                .msgs
                .iter()
                .enumerate()
                .filter(|(_, m)| m.mtype <= limit)
                .min_by_key(|(_, m)| m.mtype)
                .map(|(idx, _)| idx)
        };

        if let Some(idx) = pick_idx {
            let src = queue.msgs.get(idx).unwrap();
            if src.mtext.len() > msgsz && (msgflg & MSG_NOERROR) == 0 {
                return err(SyscallError::E2BIG);
            }
            let copy_len = src.mtext.len().min(msgsz);
            let msg_type = src.mtype;
            let mut payload = vec![0u8; copy_len];
            payload.copy_from_slice(&src.mtext[..copy_len]);
            if !msg_copy {
                let removed = queue.msgs.remove(idx).unwrap();
                queue.cbytes = queue.cbytes.saturating_sub(removed.mtext.len());
                queue.lrpid = cred.pid;
                queue.rtime = now_secs();
                wake_msg_waiters(&mut queue.send_waiters);
            }
            drop(managers);

            if try_write_user_value(token, msgp as *mut i64, &msg_type).is_err() {
                return err(SyscallError::EFAULT);
            }
            if try_copy_to_user(
                token,
                (msgp + core::mem::size_of::<i64>()) as *mut u8,
                &payload,
            )
            .is_err()
            {
                return err(SyscallError::EFAULT);
            }
            return copy_len as isize;
        }

        if (msgflg & IPC_NOWAIT) != 0 {
            return err(SyscallError::ENOMSG);
        }
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        let Some(task) = current_task() else {
            return err(SyscallError::EINVAL);
        };
        add_waiter_once(&mut queue.recv_waiters, &task);
        drop(managers);
        block_current_and_run_next();
        waited = true;
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
    }
}

pub fn syscall_semget(key: usize, nsems: usize, semflg: usize) -> isize {
    let cred = current_cred();
    let key_u32 = key as u32;
    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = SEM_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();

    if key != IPC_PRIVATE {
        if let Some(id) = mgr.key2id.get(&key_u32).copied() {
            if (semflg & IPC_CREAT) != 0 && (semflg & IPC_EXCL) != 0 {
                return err(SyscallError::EEXIST);
            }
            let Some(set) = mgr.sets.get(&id) else {
                return err(SyscallError::ENOENT);
            };
            if nsems != 0 && nsems > set.sems.len() {
                return err(SyscallError::EINVAL);
            }
            let req = (semflg & 0o700) as u16;
            if !check_ipc_access(&set.perm, req, &cred) {
                return err(SyscallError::EACCES);
            }
            return id as isize;
        }
        if (semflg & IPC_CREAT) == 0 {
            return err(SyscallError::ENOENT);
        }
    }

    let (semmsl, semmns, _semopm, semmni) = runtime_sem_limits();
    if nsems == 0 || nsems > semmsl {
        return err(SyscallError::EINVAL);
    }
    if mgr.sets.len() >= semmni {
        return err(SyscallError::ENOSPC);
    }
    let total_sems = mgr
        .sets
        .values()
        .fold(0usize, |acc, set| acc.saturating_add(set.sems.len()));
    if total_sems.saturating_add(nsems) > semmns {
        return err(SyscallError::ENOSPC);
    }
    let id = mgr.alloc_id();
    let mode = (semflg & 0o777) as u16;
    let mut sems = Vec::with_capacity(nsems);
    for _ in 0..nsems {
        sems.push(SemEntry::new());
    }
    let set = SemSet {
        id,
        key: if key == IPC_PRIVATE {
            None
        } else {
            Some(key_u32)
        },
        perm: IpcPermKernel {
            key: key_u32,
            uid: cred.euid,
            gid: cred.egid,
            cuid: cred.euid,
            cgid: cred.egid,
            mode,
        },
        sems,
        otime: 0,
        ctime: now_secs(),
    };
    if let Some(k) = set.key {
        mgr.key2id.insert(k, id);
    }
    mgr.sets.insert(id, set);
    id as isize
}

pub fn syscall_semctl(semid: usize, semnum: usize, cmd: usize, arg: usize) -> isize {
    let cred = current_cred();
    let token = get_current_token();
    let ipc_ns_id = current_ipc_namespace_id();

    match cmd {
        IPC_INFO | SEM_INFO => {
            let mut managers = SEM_MANAGERS.lock();
            let mgr = managers.entry(ipc_ns_id).or_default();
            let highest_index = mgr.sets.keys().next_back().copied().unwrap_or(0);
            let (semmsl, semmns, semopm, semmni) = runtime_sem_limits();
            let total_sems = mgr
                .sets
                .values()
                .fold(0usize, |acc, set| acc.saturating_add(set.sems.len()));
            let info = SemInfoUser {
                semmni: semmni as i32,
                semmns: semmns as i32,
                semmsl: semmsl as i32,
                semopm: semopm as i32,
                semusz: mgr.sets.len() as i32,
                semaem: if cmd == SEM_INFO {
                    total_sems as i32
                } else {
                    SEMVMX
                },
                semvmx: SEMVMX,
                ..SemInfoUser::default()
            };
            if try_write_user_value(token, arg as *mut SemInfoUser, &info).is_err() {
                return err(SyscallError::EFAULT);
            }
            return highest_index as isize;
        }
        _ => {}
    }

    let mut managers = SEM_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();
    if cmd == SEM_STAT || cmd == SEM_STAT_ANY {
        let Some(set) = mgr.sets.get(&semid) else {
            return err(SyscallError::EINVAL);
        };
        if cmd == SEM_STAT && !check_ipc_access(&set.perm, SEM_R, &cred) {
            return err(SyscallError::EACCES);
        }
        let ds = sem_to_user(set);
        if try_write_user_value(token, arg as *mut SemidDsUser, &ds).is_err() {
            return err(SyscallError::EFAULT);
        }
        return semid as isize;
    }

    let Some(set) = mgr.sets.get_mut(&semid) else {
        return err(SyscallError::EINVAL);
    };

    match cmd {
        IPC_RMID => {
            if !is_owner_or_root(&set.perm, &cred) {
                return err(SyscallError::EPERM);
            }
            let wake = mgr.remove_set(semid);
            drop(managers);
            for task in wake {
                wakeup_task(task);
            }
            0
        }
        IPC_STAT => {
            if !check_ipc_access(&set.perm, SEM_R, &cred) {
                return err(SyscallError::EACCES);
            }
            let ds = sem_to_user(set);
            if try_write_user_value(token, arg as *mut SemidDsUser, &ds).is_err() {
                return err(SyscallError::EFAULT);
            }
            0
        }
        IPC_SET => {
            if !is_owner_or_root(&set.perm, &cred) {
                return err(SyscallError::EPERM);
            }
            let Some(ds) = try_read_user_value(token, arg as *const SemidDsUser) else {
                return err(SyscallError::EFAULT);
            };
            set.perm.uid = ds.sem_perm.uid;
            set.perm.gid = ds.sem_perm.gid;
            set.perm.mode = ds.sem_perm.mode & 0o777;
            set.ctime = now_secs();
            0
        }
        GETALL => {
            if semnum > set.sems.len() {
                return err(SyscallError::EINVAL);
            }
            let mut vals = Vec::with_capacity(set.sems.len());
            for sem in set.sems.iter() {
                vals.push(sem.val as u16);
            }
            // SAFETY: vals is an owned Vec<u16>; byte length equals vals.len() * size_of::<u16>().
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    vals.as_ptr() as *const u8,
                    vals.len() * core::mem::size_of::<u16>(),
                )
            };
            if try_copy_to_user(token, arg as *mut u8, bytes).is_err() {
                return err(SyscallError::EFAULT);
            }
            0
        }
        SETALL => {
            if !is_owner_or_root(&set.perm, &cred) {
                return err(SyscallError::EACCES);
            }
            let mut vals = vec![0u16; set.sems.len()];
            // SAFETY: vals is an owned Vec<u16>; byte length equals vals.len() * size_of::<u16>().
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    vals.as_mut_ptr() as *mut u8,
                    vals.len() * core::mem::size_of::<u16>(),
                )
            };
            if try_copy_from_user(token, arg as *const u8, bytes).is_err() {
                return err(SyscallError::EFAULT);
            }
            if vals.iter().any(|&val| (val as i32) > SEMVMX) {
                return err(SyscallError::ERANGE);
            }
            for (sem, val) in set.sems.iter_mut().zip(vals.into_iter()) {
                sem.val = val as i32;
                sem.last_pid = cred.pid;
                wake_sem_waiters(sem);
            }
            set.otime = now_secs();
            0
        }
        GETVAL => {
            let Some(sem) = set.sems.get(semnum) else {
                return err(SyscallError::EINVAL);
            };
            sem.val as isize
        }
        SETVAL => {
            if !is_owner_or_root(&set.perm, &cred) {
                return err(SyscallError::EACCES);
            }
            let Some(sem) = set.sems.get_mut(semnum) else {
                return err(SyscallError::EINVAL);
            };
            let val = arg as i32;
            if val < 0 || val > SEMVMX {
                return err(SyscallError::ERANGE);
            }
            sem.val = val;
            sem.last_pid = cred.pid;
            wake_sem_waiters(sem);
            set.otime = now_secs();
            0
        }
        GETPID => {
            let Some(sem) = set.sems.get(semnum) else {
                return err(SyscallError::EINVAL);
            };
            sem.last_pid as isize
        }
        GETNCNT => {
            let Some(sem) = set.sems.get_mut(semnum) else {
                return err(SyscallError::EINVAL);
            };
            retain_blocked_waiters(&mut sem.ncnt_waiters);
            sem.ncnt_waiters.len() as isize
        }
        GETZCNT => {
            let Some(sem) = set.sems.get_mut(semnum) else {
                return err(SyscallError::EINVAL);
            };
            retain_blocked_waiters(&mut sem.zcnt_waiters);
            sem.zcnt_waiters.len() as isize
        }
        _ => err(SyscallError::EINVAL),
    }
}

#[derive(Clone, Copy)]
enum SemBlockKind {
    WaitForZero,
    WaitForIncrease,
}

#[derive(Clone, Copy)]
enum SemTimeout {
    None,
    Expired,
    DeadlineMs(usize),
}

impl SemTimeout {
    fn from_user(token: usize, timeout_ptr: usize) -> Result<Self, isize> {
        if timeout_ptr == 0 {
            return Ok(Self::None);
        }
        let Some(ts) = try_read_user_value(token, timeout_ptr as *const SemTimeSpecUser) else {
            return Err(err(SyscallError::EFAULT));
        };
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
            return Err(err(SyscallError::EINVAL));
        }
        if ts.tv_sec == 0 && ts.tv_nsec == 0 {
            return Ok(Self::Expired);
        }
        let sec_ms = (ts.tv_sec as usize).saturating_mul(1000);
        let nsec_ms = ((ts.tv_nsec as usize).saturating_add(999_999)) / 1_000_000;
        let wait_ms = sec_ms.saturating_add(nsec_ms).max(1);
        Ok(Self::DeadlineMs(get_time_ms().saturating_add(wait_ms)))
    }

    fn expired(self) -> bool {
        match self {
            Self::Expired => true,
            Self::DeadlineMs(deadline_ms) => get_time_ms() >= deadline_ms,
            Self::None => false,
        }
    }

    fn remaining_ms(self) -> Option<usize> {
        match self {
            Self::DeadlineMs(deadline_ms) => Some(deadline_ms.saturating_sub(get_time_ms()).max(1)),
            Self::None | Self::Expired => None,
        }
    }
}

fn read_sem_ops(token: usize, sops: usize, nsops: usize) -> Result<Vec<SemBuf>, isize> {
    let mut ops = vec![
        SemBuf {
            sem_num: 0,
            sem_op: 0,
            sem_flg: 0,
        };
        nsops
    ];
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            ops.as_mut_ptr() as *mut u8,
            ops.len() * core::mem::size_of::<SemBuf>(),
        )
    };
    if try_copy_from_user(token, sops as *const u8, bytes).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok(ops)
}

fn do_semop(semid: usize, sops: usize, nsops: usize, timeout: SemTimeout) -> isize {
    if nsops == 0 {
        return err(SyscallError::EINVAL);
    }
    let (_semmsl, _semmns, semopm, _semmni) = runtime_sem_limits();
    if nsops > semopm {
        return err(SyscallError::E2BIG);
    }
    let token = get_current_token();
    let ops = match read_sem_ops(token, sops, nsops) {
        Ok(ops) => ops,
        Err(e) => return e,
    };
    do_semop_locked(semid, ops, timeout)
}

fn do_semop_locked(semid: usize, ops: Vec<SemBuf>, timeout: SemTimeout) -> isize {
    let cred = current_cred();
    let ipc_ns_id = current_ipc_namespace_id();
    let mut waited = false;
    let alter = ops.iter().any(|op| op.sem_op != 0);

    loop {
        let mut managers = SEM_MANAGERS.lock();
        let mgr = managers.entry(ipc_ns_id).or_default();
        let Some(set) = mgr.sets.get_mut(&semid) else {
            return if waited {
                err(SyscallError::EIDRM)
            } else {
                err(SyscallError::EINVAL)
            };
        };
        for op in ops.iter().copied() {
            if op.sem_num as usize >= set.sems.len() {
                return err(SyscallError::EFBIG);
            }
        }
        let req = if alter { SEM_A } else { SEM_R };
        if !check_ipc_access(&set.perm, req, &cred) {
            return err(SyscallError::EACCES);
        }
        let mut values = set.sems.iter().map(|sem| sem.val).collect::<Vec<_>>();
        let mut operated = vec![false; set.sems.len()];
        let mut touched = vec![false; set.sems.len()];
        let mut would_block: Option<(usize, SemBlockKind, i16)> = None;

        for op in ops.iter().copied() {
            let idx = op.sem_num as usize;
            operated[idx] = true;

            if op.sem_op > 0 {
                let next = values[idx].saturating_add(op.sem_op as i32);
                if next > SEMVMX {
                    return err(SyscallError::ERANGE);
                }
                values[idx] = next;
                touched[idx] = true;
                continue;
            }

            if op.sem_op == 0 {
                if values[idx] == 0 {
                    continue;
                }
                would_block = Some((idx, SemBlockKind::WaitForZero, op.sem_flg));
                break;
            }

            let need = (-(op.sem_op as i32)) as i32;
            if values[idx] >= need {
                values[idx] -= need;
                touched[idx] = true;
                continue;
            }
            would_block = Some((idx, SemBlockKind::WaitForIncrease, op.sem_flg));
            break;
        }

        if would_block.is_none() {
            for (idx, sem) in set.sems.iter_mut().enumerate() {
                if operated[idx] {
                    sem.val = values[idx];
                    sem.last_pid = cred.pid;
                }
                if touched[idx] {
                    wake_sem_waiters(sem);
                }
            }
            set.otime = now_secs();
            return 0;
        }

        let (idx, kind, sem_flg) = would_block.unwrap();
        if (sem_flg as usize & IPC_NOWAIT) != 0 || timeout.expired() {
            return err(SyscallError::EAGAIN);
        }
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        let Some(task) = current_task() else {
            return err(SyscallError::EINVAL);
        };
        let Some(sem) = set.sems.get_mut(idx) else {
            return err(SyscallError::EFBIG);
        };
        match kind {
            SemBlockKind::WaitForZero => add_waiter_once(&mut sem.zcnt_waiters, &task),
            SemBlockKind::WaitForIncrease => add_waiter_once(&mut sem.ncnt_waiters, &task),
        }
        if let Some(wait_ms) = timeout.remaining_ms() {
            add_timer(Arc::clone(&task), wait_ms);
        }
        drop(managers);
        block_current_and_run_next();
        waited = true;
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        if timeout.expired() {
            return err(SyscallError::EAGAIN);
        }
    }
}

pub fn syscall_semop(semid: usize, sops: usize, nsops: usize) -> isize {
    do_semop(semid, sops, nsops, SemTimeout::None)
}

pub fn syscall_semtimedop(semid: usize, sops: usize, nsops: usize, timeout: usize) -> isize {
    let sem_timeout = match SemTimeout::from_user(get_current_token(), timeout) {
        Ok(timeout) => timeout,
        Err(e) => return e,
    };
    do_semop(semid, sops, nsops, sem_timeout)
}
