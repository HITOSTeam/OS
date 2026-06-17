use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::fs::parse_proc_sys_usize;
use crate::syscall::error::{SyscallError, err};

use super::abi::{
    MSGMAX, MSGMNB, MSGMNI, PROCFS_MSGMAX, PROCFS_MSGMNB, PROCFS_MSGMNI, PROCFS_SEM, SEMMNI,
    SEMMNS, SEMMSL, SEMOPM,
};

// 运行时生效的资源限制：初值取自 abi 中的编译期默认值，可经 procfs 写入覆盖。
/// msgmax 的运行时值（单条消息体大小上限）。
static RUNTIME_MSGMAX_LIMIT: AtomicUsize = AtomicUsize::new(MSGMAX);
/// msgmnb 的运行时值（单个队列字节容量上限）。
static RUNTIME_MSGMNB_LIMIT: AtomicUsize = AtomicUsize::new(MSGMNB);
/// msgmni 的运行时值（队列数量上限）。
static RUNTIME_MSGMNI_LIMIT: AtomicUsize = AtomicUsize::new(MSGMNI);
/// semmsl 的运行时值（单集信号量个数上限）。
static RUNTIME_SEMMSL_LIMIT: AtomicUsize = AtomicUsize::new(SEMMSL);
/// semmns 的运行时值（系统信号量总数上限）。
static RUNTIME_SEMMNS_LIMIT: AtomicUsize = AtomicUsize::new(SEMMNS);
/// semmni 的运行时值（信号量集数量上限）。
static RUNTIME_SEMMNI_LIMIT: AtomicUsize = AtomicUsize::new(SEMMNI);
/// semopm 的运行时值（单次 semop 操作数上限）。
static RUNTIME_SEMOPM_LIMIT: AtomicUsize = AtomicUsize::new(SEMOPM);

/// 返回编译期默认的 msgmax（单条消息体大小上限）。
#[allow(dead_code)]
pub fn msgmax_limit() -> usize {
    MSGMAX
}

/// 返回编译期默认的 msgmnb（单个消息队列字节容量上限）。
#[allow(dead_code)]
pub fn msgmnb_limit() -> usize {
    MSGMNB
}

/// 返回编译期默认的 msgmni（消息队列数量上限）。
#[allow(dead_code)]
pub fn msgmni_limit() -> usize {
    MSGMNI
}

/// 返回编译期默认的 semmsl（单集信号量个数上限）。
#[allow(dead_code)]
pub fn semmsl_limit() -> usize {
    SEMMSL
}

/// 返回编译期默认的 semmns（系统信号量总数上限）。
#[allow(dead_code)]
pub fn semmns_limit() -> usize {
    SEMMNS
}

/// 返回编译期默认的 semopm（单次 semop 操作数上限）。
#[allow(dead_code)]
pub fn semopm_limit() -> usize {
    SEMOPM
}

/// 返回编译期默认的 semmni（信号量集数量上限）。
#[allow(dead_code)]
pub fn semmni_limit() -> usize {
    SEMMNI
}

/// 读取当前生效（可被 procfs 覆盖）的 msgmax 运行时限制。
pub(super) fn runtime_msgmax_limit() -> usize {
    RUNTIME_MSGMAX_LIMIT.load(Ordering::Relaxed)
}

/// 读取当前生效（可被 procfs 覆盖）的 msgmnb 运行时限制。
pub(super) fn runtime_msgmnb_limit() -> usize {
    RUNTIME_MSGMNB_LIMIT.load(Ordering::Relaxed)
}

/// 读取当前生效（可被 procfs 覆盖）的 msgmni 运行时限制。
pub(super) fn runtime_msgmni_limit() -> usize {
    RUNTIME_MSGMNI_LIMIT.load(Ordering::Relaxed)
}

/// 一次性读取信号量四元组运行时限制，返回 (semmsl, semmns, semopm, semmni)。
pub(super) fn runtime_sem_limits() -> (usize, usize, usize, usize) {
    (
        RUNTIME_SEMMSL_LIMIT.load(Ordering::Relaxed),
        RUNTIME_SEMMNS_LIMIT.load(Ordering::Relaxed),
        RUNTIME_SEMOPM_LIMIT.load(Ordering::Relaxed),
        RUNTIME_SEMMNI_LIMIT.load(Ordering::Relaxed),
    )
}

/// 供 procfs（/proc/sys/kernel/msgmax）读取当前 msgmax 值。
pub fn runtime_msgmax_for_procfs() -> usize {
    runtime_msgmax_limit()
}

/// 供 procfs（/proc/sys/kernel/msgmnb）读取当前 msgmnb 值。
pub fn runtime_msgmnb_for_procfs() -> usize {
    runtime_msgmnb_limit()
}

/// 供 procfs（/proc/sys/kernel/msgmni）读取当前 msgmni 值。
pub fn runtime_msgmni_for_procfs() -> usize {
    runtime_msgmni_limit()
}

/// 供 procfs（/proc/sys/kernel/sem）读取当前信号量四元组限制。
pub fn runtime_sem_limits_for_procfs() -> (usize, usize, usize, usize) {
    runtime_sem_limits()
}

/// 处理对 msg 相关 procfs 节点（msgmax/msgmnb/msgmni）的写入，
/// 校验数值（>0 且不超过 i32::MAX）后更新对应运行时限制，并回显写回的值。
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

/// 处理对 /proc/sys/kernel/sem 的写入：解析四个数值
/// (semmsl semmns semopm semmni)，校验范围与 semmns >= semmsl 约束后整体更新限制。
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
