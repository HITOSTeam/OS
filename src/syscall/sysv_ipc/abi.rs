// ---- IPC key 与 *get 调用的标志位（用于 msgget/semget/shmget 的 flag 参数）----
/// 私有 key，每次调用都会创建一个全新的、与任何 key 无关的 IPC 对象。
pub(super) const IPC_PRIVATE: usize = 0;
/// 若 key 对应的对象不存在则创建它。
pub(super) const IPC_CREAT: usize = 0x200;
/// 与 IPC_CREAT 配合使用：若对象已存在则返回 EEXIST（保证“独占创建”）。
pub(super) const IPC_EXCL: usize = 0x400;
/// 操作无法立即完成时不阻塞，直接返回 EAGAIN（非阻塞标志）。
pub(super) const IPC_NOWAIT: usize = 0x800;

// ---- *ctl 控制命令（msgctl/semctl/shmctl 的 cmd 参数）----
/// 删除该 IPC 对象。
pub(super) const IPC_RMID: usize = 0;
/// 设置该 IPC 对象的部分属性（权限、属主等）。
pub(super) const IPC_SET: usize = 1;
/// 获取该 IPC 对象的状态信息（ipc_perm 等）。
pub(super) const IPC_STAT: usize = 2;
/// 获取系统级 IPC 资源上限信息（静态限制）。
pub(super) const IPC_INFO: usize = 3;
/// 按内部数组索引获取消息队列状态，返回值为对应的 msqid（Linux 特有）。
pub(super) const MSG_STAT: usize = 11;
/// 获取消息队列子系统的运行时统计信息。
pub(super) const MSG_INFO: usize = 12;
/// 与 MSG_STAT 类似，但忽略读权限检查（Linux 特有）。
pub(super) const MSG_STAT_ANY: usize = 13;
/// 按内部数组索引获取信号量集状态，返回值为对应的 semid（Linux 特有）。
pub(super) const SEM_STAT: usize = 18;
/// 获取信号量子系统的运行时统计信息。
pub(super) const SEM_INFO: usize = 19;
/// 与 SEM_STAT 类似，但忽略读权限检查（Linux 特有）。
pub(super) const SEM_STAT_ANY: usize = 20;

// ---- msgrcv 的标志位 ----
/// 消息超过缓冲区大小时截断而非报错（默认会返回 E2BIG）。
pub(super) const MSG_NOERROR: usize = 0x1000;
/// 取出第一条 mtype 不等于指定值的消息。
pub(super) const MSG_EXCEPT: usize = 0x2000;
/// 复制消息而不将其从队列中移除（需配合 MSG_STAT/索引使用）。
pub(super) const MSG_COPY: usize = 0x4000;

// ---- semctl 的命令（针对单个/整组信号量值的操作）----
/// 返回对该信号量最近执行操作的进程 PID（sempid）。
pub(super) const GETPID: usize = 11;
/// 返回指定信号量的当前值。
pub(super) const GETVAL: usize = 12;
/// 返回信号量集中所有信号量的当前值。
pub(super) const GETALL: usize = 13;
/// 返回等待该信号量值增大的进程数（semncnt）。
pub(super) const GETNCNT: usize = 14;
/// 返回等待该信号量值变为 0 的进程数（semzcnt）。
pub(super) const GETZCNT: usize = 15;
/// 设置指定信号量的值。
pub(super) const SETVAL: usize = 16;
/// 设置信号量集中所有信号量的值。
pub(super) const SETALL: usize = 17;

// ---- 权限位（用于 check_ipc_access 中的权限校验）----
/// 消息队列读权限位。
pub(super) const MSG_R: u16 = 0o400;
/// 消息队列写权限位。
pub(super) const MSG_W: u16 = 0o200;
/// 信号量集读权限位。
pub(super) const SEM_R: u16 = 0o400;
/// 信号量集修改（alter）权限位。
pub(super) const SEM_A: u16 = 0o200;
/// semop 操作退出时自动回滚的标志位。
pub(super) const SEM_UNDO: i16 = 0x1000;

// ---- 系统级资源上限（默认值，运行时可经 procfs 覆盖）----
/// 信号量可取的最大值（semop 增大后超过此值返回 ERANGE）。
pub(super) const SEMVMX: i32 = 32767;
/// SEM_UNDO 调整值的最大绝对值。
pub(super) const SEMAEM: i32 = SEMVMX;
/// 单个信号量集中信号量的最大个数。
pub(super) const SEMMSL: usize = 32000;
/// 系统范围内信号量总数的上限。
pub(super) const SEMMNS: usize = 1_024_000_000;
/// 系统范围内信号量集的最大个数。
pub(super) const SEMMNI: usize = 32000;
/// 单次 semop 调用中允许的最大操作数。
pub(super) const SEMOPM: usize = 500;
/// 单个消息队列的最大字节容量（队列中所有消息体之和的上限）。
pub(super) const MSGMNB: usize = 16384;
/// 系统范围内消息队列的最大个数。
pub(super) const MSGMNI: usize = 4096;
/// 单条消息体的最大字节数。
pub(super) const MSGMAX: usize = 8192;
/// 消息段（message segment）大小，单位字节（IPC_INFO/MSG_INFO 上报用）。
pub(super) const MSGSSZ: i32 = 16;
/// 消息池总大小，单位为 1KB 块：msgmni * msgmnb / 1024（MSG_INFO 上报用）。
pub(super) const MSGPOOL: i32 = (MSGMNI * MSGMNB / 1024) as i32;
/// 系统范围内可同时存在的消息头（消息条数）上限。
pub(super) const MSGTQL: i32 = MSGMNB as i32;
/// 消息映射表条目数（历史遗留字段，MSG_INFO 上报用）。
pub(super) const MSGMAP: i32 = MSGMNB as i32;
/// 系统范围内消息段总数：msgpool 折算为段数，并钳制到 0xffff（MSG_INFO 上报用）。
pub(super) const MSGSEG: i32 = {
    let seg = MSGPOOL * 1024 / MSGSSZ;
    if seg <= 0xffff { seg } else { 0xffff }
};

/// procfs 路径：单条消息体大小上限（msgmax）。
pub(super) const PROCFS_MSGMAX: &str = "/proc/sys/kernel/msgmax";
/// procfs 路径：单个消息队列字节容量上限（msgmnb）。
pub(super) const PROCFS_MSGMNB: &str = "/proc/sys/kernel/msgmnb";
/// procfs 路径：消息队列数量上限（msgmni）。
pub(super) const PROCFS_MSGMNI: &str = "/proc/sys/kernel/msgmni";
/// procfs 路径：信号量限制四元组（semmsl semmns semopm semmni）。
pub(super) const PROCFS_SEM: &str = "/proc/sys/kernel/sem";

/// 用户态 `struct ipc_perm` 的内存布局，所有 IPC 对象状态结构共用的权限头。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct IpcPermUser {
    /// 关联的 key（用户态字段名为 __key，下划线表示一般不直接使用）。
    pub(super) __key: u32,
    /// 属主用户 id。
    pub(super) uid: u32,
    /// 属主组 id。
    pub(super) gid: u32,
    /// 创建者用户 id。
    pub(super) cuid: u32,
    /// 创建者组 id。
    pub(super) cgid: u32,
    /// 权限模式（低 9 位为 rwx 权限）。
    pub(super) mode: u16,
    /// 对齐填充。
    pub(super) __pad1: u16,
    /// 序列号（用于复用同一槽位时区分对象，本实现未使用）。
    pub(super) __seq: u16,
    /// 对齐填充。
    pub(super) __pad2: u16,
    /// 保留字段，与 Linux ABI 对齐用。
    pub(super) __unused1: u64,
    /// 保留字段，与 Linux ABI 对齐用。
    pub(super) __unused2: u64,
}

/// 用户态 `struct msqid_ds` 的内存布局（IPC_STAT/MSG_STAT 返回给用户的消息队列状态）。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MsqidDsUser {
    /// 权限与属主信息。
    pub(super) msg_perm: IpcPermUser,
    /// 最近一次 msgsnd 的时间戳（秒）。
    pub(super) msg_stime: i64,
    /// 最近一次 msgrcv 的时间戳（秒）。
    pub(super) msg_rtime: i64,
    /// 最近一次状态变更的时间戳（秒）。
    pub(super) msg_ctime: i64,
    /// 队列当前占用的字节数。
    pub(super) msg_cbytes: u64,
    /// 队列中的消息条数。
    pub(super) msg_qnum: u64,
    /// 队列字节容量上限。
    pub(super) msg_qbytes: u64,
    /// 最近一次发送消息的进程 pid。
    pub(super) msg_lspid: u32,
    /// 最近一次接收消息的进程 pid。
    pub(super) msg_lrpid: u32,
    /// 保留字段。
    pub(super) __unused4: u64,
    /// 保留字段。
    pub(super) __unused5: u64,
}

/// 用户态 `struct msginfo` 的内存布局（IPC_INFO/MSG_INFO 返回的消息子系统统计/限制信息）。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MsgInfoUser {
    /// 消息池大小（IPC_INFO 为静态值，MSG_INFO 为队列数）。
    pub(super) msgpool: i32,
    /// 消息映射表条目数（IPC_INFO 为静态值，MSG_INFO 为消息总数）。
    pub(super) msgmap: i32,
    /// 单条消息体大小上限。
    pub(super) msgmax: i32,
    /// 单个队列字节容量上限。
    pub(super) msgmnb: i32,
    /// 队列数量上限。
    pub(super) msgmni: i32,
    /// 消息段大小（字节）。
    pub(super) msgssz: i32,
    /// 消息头数量上限（IPC_INFO）或当前总字节数（MSG_INFO）。
    pub(super) msgtql: i32,
    /// 消息段总数。
    pub(super) msgseg: i32,
}

/// 用户态 `struct semid_ds` 的内存布局（IPC_STAT/SEM_STAT 返回的信号量集状态）。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct SemidDsUser {
    /// 权限与属主信息。
    pub(super) sem_perm: IpcPermUser,
    /// 最近一次 semop 操作的时间戳（秒）。
    pub(super) sem_otime: i64,
    /// 最近一次状态变更的时间戳（秒）。
    pub(super) sem_ctime: i64,
    /// 集合中信号量的个数。
    pub(super) sem_nsems: u64,
    /// 保留字段。
    pub(super) __unused3: u64,
    /// 保留字段。
    pub(super) __unused4: u64,
}

/// 用户态 `struct seminfo` 的内存布局（IPC_INFO/SEM_INFO 返回的信号量子系统统计/限制信息）。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct SemInfoUser {
    /// 信号量映射表条目数（历史遗留字段）。
    pub(super) semmap: i32,
    /// 信号量集数量上限。
    pub(super) semmni: i32,
    /// 系统信号量总数上限。
    pub(super) semmns: i32,
    /// 每进程可用的 undo 结构数（本实现未使用）。
    pub(super) semmnu: i32,
    /// 单集信号量个数上限。
    pub(super) semmsl: i32,
    /// 单次 semop 操作数上限。
    pub(super) semopm: i32,
    /// 每个 undo 结构的最大条目数（本实现未使用）。
    pub(super) semume: i32,
    /// 当前已使用的信号量集数量。
    pub(super) semusz: i32,
    /// 信号量可取的最大值。
    pub(super) semvmx: i32,
    /// 调整值上限（SEM_INFO 时为当前信号量总数）。
    pub(super) semaem: i32,
}

/// 用户态 `struct sembuf` 的内存布局（semop 的单个操作描述符）。
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SemBuf {
    /// 目标信号量在集合中的下标。
    pub(super) sem_num: u16,
    /// 操作量：>0 为增、<0 为减、==0 为等待归零。
    pub(super) sem_op: i16,
    /// 操作标志（如 IPC_NOWAIT/SEM_UNDO）。
    pub(super) sem_flg: i16,
}

/// 用户态 `struct timespec` 的内存布局（semtimedop 的超时参数）。
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SemTimeSpecUser {
    /// 秒。
    pub(super) tv_sec: i64,
    /// 纳秒（合法范围 0..1_000_000_000）。
    pub(super) tv_nsec: i64,
}
