use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::block_sleep::{add_timer, remove_timers_for_task};
use crate::task::manager::wakeup_task;
use crate::task::processor::{block_current_and_run_next, current_task};
use crate::task::task_block::TaskControlBlock;
use crate::time::get_time_ms;
use crate::trap::get_current_token;

use super::abi::{
    GETALL, GETNCNT, GETPID, GETVAL, GETZCNT, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_NOWAIT,
    IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, SEM_A, SEM_INFO, SEM_R, SEM_STAT, SEM_STAT_ANY,
    SEM_UNDO, SEMVMX, SETALL, SETVAL, SemBuf, SemInfoUser, SemTimeSpecUser, SemidDsUser,
};
use super::common::{
    IpcPermKernel, add_waiter_once, check_ipc_access, current_cred, current_ipc_namespace_id,
    drain_live_waiters, has_pending_unmasked_signal, is_owner_or_root, now_secs,
    retain_blocked_waiters,
};
use super::sysctl::runtime_sem_limits;

/// 单个信号量：一个计数值加上两类等待者队列。
struct SemEntry {
    /// 信号量当前值（非负，上限为 SEMVMX）。
    val: i32,
    /// 最近一次对该信号量执行操作的进程 pid（GETPID 返回）。
    last_pid: u32,
    /// 等待该信号量值“增大到足够”的任务（执行减操作受阻者）。
    ncnt_waiters: VecDeque<Weak<TaskControlBlock>>,
    /// 等待该信号量值“变为 0”的任务（执行等零操作受阻者）。
    zcnt_waiters: VecDeque<Weak<TaskControlBlock>>,
}

impl SemEntry {
    /// 创建一个初值为 0、无等待者的信号量条目。
    fn new() -> Self {
        Self {
            val: 0,
            last_pid: 0,
            ncnt_waiters: VecDeque::new(),
            zcnt_waiters: VecDeque::new(),
        }
    }
}

/// 一个信号量集（对应用户态的一个 semid，semget 创建时指定包含几个信号量）。
struct SemSet {
    /// 信号量集 id。
    id: usize,
    /// 关联的 key；IPC_PRIVATE 创建的集合无 key，为 None。
    key: Option<u32>,
    /// 属主与权限信息。
    perm: IpcPermKernel,
    /// 集合中的各个信号量，下标即 semop/semctl 中的 sem_num。
    sems: Vec<SemEntry>,
    /// 最近一次 semop 操作的时间戳（秒）。
    otime: i64,
    /// 最近一次创建或经 IPC_SET 修改的时间戳（秒）。
    ctime: i64,
}

/// 信号量集管理器，按 IPC 命名空间隔离。
#[derive(Default)]
struct SemManager {
    /// 下一个待分配的 id（递增并跳过已占用值）。
    next_id: usize,
    /// id -> 信号量集 的映射。
    sets: BTreeMap<usize, SemSet>,
    /// key -> id 的映射，供按 key 复用已有集合。
    key2id: BTreeMap<u32, usize>,
}

impl SemManager {
    /// 分配一个未被占用的信号量集 id（从 1 开始递增，跳过已存在的 id）。
    ///
    /// 当前 id 同时作为 SEM_STAT/SEM_STAT_ANY 的内部索引使用；若未来引入
    /// sequence bits，需要同步调整 STAT 查询与 IPC_INFO 返回值。
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

    /// 删除指定信号量集并返回需要唤醒的等待任务列表（所有信号量上等待
    /// 增大或等待归零的任务），同时清理 key->id 映射。
    fn remove_set(&mut self, id: usize) -> Vec<Arc<TaskControlBlock>> {
        let mut wake = Vec::new();
        if let Some(mut set) = self.sets.remove(&id) {
            for sem in set.sems.iter_mut() {
                wake.extend(drain_live_waiters(&mut sem.ncnt_waiters));
                wake.extend(drain_live_waiters(&mut sem.zcnt_waiters));
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
    /// 全局信号量管理表：IPC 命名空间 id -> 该命名空间的 SemManager。
    static ref SEM_MANAGERS: Mutex<BTreeMap<usize, SemManager>> = Mutex::new(BTreeMap::new());
    /// 进程级 SEM_UNDO 调整表：pid -> semadj 条目。
    static ref SEM_UNDOS: Mutex<BTreeMap<usize, Vec<SemUndoEntry>>> = Mutex::new(BTreeMap::new());
}

#[derive(Clone, Copy)]
struct SemUndoEntry {
    ipc_ns_id: usize,
    semid: usize,
    semnum: usize,
    adj: i32,
}

/// 生成 /proc/sysvipc/sem 的内容：表头加上当前 IPC 命名空间内每个信号量集一行的统计信息。
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

/// 根据信号量当前值唤醒相应的等待者：值为 0 时唤醒“等待归零”者，
/// 值大于 0 时唤醒“等待增大”者；唤醒前先清理失效等待者。
fn wake_sem_waiters(sem: &mut SemEntry) {
    let mut wake = Vec::new();
    if sem.val == 0 {
        wake.extend(drain_live_waiters(&mut sem.zcnt_waiters));
    }
    if sem.val > 0 {
        wake.extend(drain_live_waiters(&mut sem.ncnt_waiters));
    }
    for task in wake {
        wakeup_task(task);
    }
}

fn clear_undo_for_sem(ipc_ns_id: usize, semid: usize, semnum: usize) {
    let mut undo = SEM_UNDOS.lock();
    undo.retain(|_, entries| {
        entries.retain(|entry| {
            !(entry.ipc_ns_id == ipc_ns_id && entry.semid == semid && entry.semnum == semnum)
        });
        !entries.is_empty()
    });
}

fn clear_undo_for_set(ipc_ns_id: usize, semid: usize) {
    let mut undo = SEM_UNDOS.lock();
    undo.retain(|_, entries| {
        entries.retain(|entry| !(entry.ipc_ns_id == ipc_ns_id && entry.semid == semid));
        !entries.is_empty()
    });
}

fn record_sem_undo(pid: usize, ipc_ns_id: usize, semid: usize, deltas: &[i32]) {
    if deltas.iter().all(|delta| *delta == 0) {
        return;
    }
    let mut undo = SEM_UNDOS.lock();
    let entries = undo.entry(pid).or_default();
    for (semnum, delta) in deltas.iter().copied().enumerate() {
        if delta == 0 {
            continue;
        }
        if let Some(entry) = entries.iter_mut().find(|entry| {
            entry.ipc_ns_id == ipc_ns_id && entry.semid == semid && entry.semnum == semnum
        }) {
            entry.adj = entry.adj.saturating_add(delta);
        } else {
            entries.push(SemUndoEntry {
                ipc_ns_id,
                semid,
                semnum,
                adj: delta,
            });
        }
    }
    entries.retain(|entry| entry.adj != 0);
    if entries.is_empty() {
        undo.remove(&pid);
    }
}

/// Apply and forget all SEM_UNDO adjustments owned by a process.
///
/// Linux keeps semadj state per thread group for pthread-style CLONE_SYSVSEM
/// users. This kernel's Linux threads share one PCB/pid, so pid-scoped undo
/// gives the same "only when the last thread exits" behavior for LTP.
pub fn exit_cleanup(pid: usize) {
    let mut managers = SEM_MANAGERS.lock();
    let entries = {
        let mut undo = SEM_UNDOS.lock();
        undo.remove(&pid).unwrap_or_default()
    };
    if entries.is_empty() {
        return;
    }
    for entry in entries {
        let Some(mgr) = managers.get_mut(&entry.ipc_ns_id) else {
            continue;
        };
        let Some(set) = mgr.sets.get_mut(&entry.semid) else {
            continue;
        };
        let Some(sem) = set.sems.get_mut(entry.semnum) else {
            continue;
        };
        let next = sem.val.saturating_add(entry.adj).clamp(0, SEMVMX);
        if next == sem.val {
            continue;
        }
        sem.val = next;
        sem.last_pid = pid as u32;
        wake_sem_waiters(sem);
        set.otime = now_secs();
    }
}

/// 将内核信号量集状态转换为用户态 semid_ds 结构（供 IPC_STAT/SEM_STAT 返回）。
fn sem_to_user(set: &SemSet) -> SemidDsUser {
    SemidDsUser {
        sem_perm: set.perm.to_user(),
        sem_otime: set.otime,
        sem_ctime: set.ctime,
        sem_nsems: set.sems.len() as u64,
        ..SemidDsUser::default()
    }
}

/// semget(2)：按 key 查找或创建信号量集。
/// 处理 IPC_PRIVATE、IPC_CREAT/IPC_EXCL 语义与权限检查，新建时校验 nsems 以及
/// semmsl/semmni/semmns 各项上限，返回信号量集 id 或错误。
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

/// semctl(2)：信号量集控制。
/// 支持 IPC_INFO/SEM_INFO（统计）、SEM_STAT/SEM_STAT_ANY（按 id 取状态）、
/// IPC_STAT/IPC_SET/IPC_RMID，以及对单个/全部信号量值的操作
/// GETVAL/SETVAL/GETALL/SETALL/GETPID/GETNCNT/GETZCNT。
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
            clear_undo_for_set(ipc_ns_id, semid);
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
            clear_undo_for_set(ipc_ns_id, semid);
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
            clear_undo_for_sem(ipc_ns_id, semid, semnum);
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

/// 信号量操作受阻时的阻塞原因，决定把任务挂到哪个等待队列上。
#[derive(Clone, Copy)]
enum SemBlockKind {
    /// 等待信号量值变为 0（等零操作）。
    WaitForZero,
    /// 等待信号量值增大到足够（减操作）。
    WaitForIncrease,
}

/// semop/semtimedop 的超时状态。
#[derive(Clone, Copy)]
enum SemTimeout {
    /// 无超时，无限等待。
    None,
    /// 立即超时（传入的 timespec 为 {0,0}），不阻塞。
    Expired,
    /// 绝对截止时间，单位毫秒。
    DeadlineMs(usize),
}

impl SemTimeout {
    /// 从用户态 timespec 指针解析超时：空指针表示无限等待（None）；
    /// {0,0} 表示立即超时（Expired）；否则换算为绝对毫秒截止时间（DeadlineMs）。
    /// 非法的 tv_sec/tv_nsec 返回 EINVAL，指针不可读返回 EFAULT。
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

    /// 判断超时是否已到期：Expired 恒为真，DeadlineMs 比较当前时间，None 永不超时。
    fn expired(self) -> bool {
        match self {
            Self::Expired => true,
            Self::DeadlineMs(deadline_ms) => get_time_ms() >= deadline_ms,
            Self::None => false,
        }
    }

    /// 返回距截止时间的剩余毫秒数（至少 1ms），用于设置定时器；
    /// None/Expired 无需定时器，返回 None。
    fn remaining_ms(self) -> Option<usize> {
        match self {
            Self::DeadlineMs(deadline_ms) => Some(deadline_ms.saturating_sub(get_time_ms()).max(1)),
            Self::None | Self::Expired => None,
        }
    }
}

/// 从用户态一次性读取 nsops 个 sembuf 操作数组（按 SemBuf 的 C 布局拷贝）。
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

fn check_semop_count(nsops: usize) -> Result<(), isize> {
    if nsops == 0 {
        return Err(err(SyscallError::EINVAL));
    }
    let (_semmsl, _semmns, semopm, _semmni) = runtime_sem_limits();
    if nsops > semopm {
        return Err(err(SyscallError::E2BIG));
    }
    Ok(())
}

/// semop/semtimedop 的公共入口：校验 nsops（非 0 且不超过 semopm），
/// 读取操作数组后交由 `do_semop_ops` 执行。
fn do_semop(semid: usize, sops: usize, nsops: usize, timeout: SemTimeout) -> isize {
    if let Err(e) = check_semop_count(nsops) {
        return e;
    }
    do_semop_after_count_check(semid, sops, nsops, timeout)
}

fn do_semop_after_count_check(
    semid: usize,
    sops: usize,
    nsops: usize,
    timeout: SemTimeout,
) -> isize {
    let token = get_current_token();
    let ops = match read_sem_ops(token, sops, nsops) {
        Ok(ops) => ops,
        Err(e) => return e,
    };
    do_semop_ops(semid, ops, timeout)
}

/// 原子地执行一组信号量操作（全有或全无语义）。
/// 先在数值副本上模拟所有操作：增操作可能触发 ERANGE，等零/减操作若条件不满足则记录首个
/// 会阻塞的位置。若全部可完成则一次性提交并唤醒相关等待者；否则按 IPC_NOWAIT/超时返回 EAGAIN，
/// 或挂起当前任务（必要时设置定时器）后重试。挂起期间收到信号返回 EINTR，对象被删除返回 EIDRM。
fn do_semop_ops(semid: usize, ops: Vec<SemBuf>, timeout: SemTimeout) -> isize {
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
        let mut undo_deltas = vec![0i32; set.sems.len()];
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
                if (op.sem_flg & SEM_UNDO) != 0 {
                    undo_deltas[idx] = undo_deltas[idx].saturating_sub(op.sem_op as i32);
                }
                continue;
            }

            if op.sem_op == 0 {
                if values[idx] == 0 {
                    continue;
                }
                would_block = Some((idx, SemBlockKind::WaitForZero, op.sem_flg));
                break;
            }

            let need = -(op.sem_op as i32);
            if values[idx] >= need {
                values[idx] -= need;
                touched[idx] = true;
                if (op.sem_flg & SEM_UNDO) != 0 {
                    undo_deltas[idx] = undo_deltas[idx].saturating_add(need);
                }
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
            record_sem_undo(cred.pid as usize, ipc_ns_id, semid, &undo_deltas);
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
        remove_timers_for_task(&task);
        waited = true;
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
    }
}

/// semop(2)：无超时地执行一组信号量操作。
pub fn syscall_semop(semid: usize, sops: usize, nsops: usize) -> isize {
    do_semop(semid, sops, nsops, SemTimeout::None)
}

/// semtimedop(2)：带超时地执行一组信号量操作。
pub fn syscall_semtimedop(semid: usize, sops: usize, nsops: usize, timeout: usize) -> isize {
    if let Err(e) = check_semop_count(nsops) {
        return e;
    }
    let sem_timeout = match SemTimeout::from_user(get_current_token(), timeout) {
        Ok(timeout) => timeout,
        Err(e) => return e,
    };
    do_semop_after_count_check(semid, sops, nsops, sem_timeout)
}
