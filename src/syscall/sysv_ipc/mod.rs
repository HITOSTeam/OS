//! SysV IPC syscall support.
//!
//! 子模块职责：
//! - `abi`：Linux ABI 常量和用户态结构布局。
//! - `sysctl`：`/proc/sys/kernel/{msgmax,msgmnb,msgmni,sem}` 运行时限制。
//! - `common`：凭据快照、IPC 权限检查、等待队列通用工具。
//! - `msg`：SysV 消息队列 syscall 与 `/proc/sysvipc/msg`。
//! - `sem`：SysV 信号量 syscall 与 `/proc/sysvipc/sem`。

mod abi;
mod common;
mod msg;
mod sem;
mod sysctl;

pub use msg::{proc_sysvipc_msg, syscall_msgctl, syscall_msgget, syscall_msgrcv, syscall_msgsnd};
pub use sem::{
    exit_cleanup, proc_sysvipc_sem, syscall_semctl, syscall_semget, syscall_semop,
    syscall_semtimedop,
};
#[allow(unused_imports)]
pub use sysctl::{
    msgmax_limit, msgmnb_limit, msgmni_limit, semmni_limit, semmns_limit, semmsl_limit,
    semopm_limit,
};
pub use sysctl::{
    runtime_msgmax_for_procfs, runtime_msgmnb_for_procfs, runtime_msgmni_for_procfs,
    runtime_sem_limits_for_procfs, write_msg_sysctl, write_sem_sysctl,
};
