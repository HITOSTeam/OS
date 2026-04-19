use crate::{
    syscall::error::{SyscallError, err},
    task::{
        manager::{PID2PCB, pid2process},
        processor::current_process,
    },
};
use alloc::sync::Arc;

pub fn normalized_pgid(pid: usize, pgid: usize) -> usize {
    if pgid == 0 && pid != 0 { pid } else { pgid }
}

pub(super) fn normalized_sid(pid: usize, sid: usize, pgid: usize) -> usize {
    if sid != 0 {
        sid
    } else {
        normalized_pgid(pid, pgid)
    }
}

pub fn syscall_getppid() -> isize {
    let process = current_process();
    let (pid_ns_id, parent) = {
        let inner = process.borrow_mut();
        (
            inner.pid_ns_id,
            inner.parent.as_ref().and_then(|p| p.upgrade()),
        )
    };
    match parent {
        Some(parent) if pid_ns_id == 0 || parent.pid_namespace_id() == pid_ns_id => {
            parent.visible_pid() as isize
        }
        Some(_) | None => 0,
    }
}

/// Linux `setpgid(2)` (syscall 154 on riscv64).
///
/// Minimal process-group support for waitpid job-control tests.
pub fn syscall_setpgid(pid: usize, pgid: usize) -> isize {
    if (pid as isize) < 0 || (pgid as isize) < 0 {
        return err(SyscallError::EINVAL);
    }

    let cur = current_process();
    let cur_pid = cur.getpid();
    let target_pid = if pid == 0 { cur_pid } else { pid };
    let new_pgid = if pgid == 0 { target_pid } else { pgid };

    let target = if target_pid == cur_pid {
        Some(Arc::clone(&cur))
    } else {
        let child = {
            let inner = cur.borrow_mut();
            inner
                .children
                .iter()
                .find(|c| c.getpid() == target_pid)
                .cloned()
        };
        child
    };

    let Some(target) = target else {
        return err(SyscallError::ESRCH);
    };

    let cur_sid = {
        let inner = cur.borrow_mut();
        normalized_sid(cur_pid, inner.sid, inner.pgid)
    };

    let (target_sid, target_is_session_leader, target_did_exec) = {
        let inner = target.borrow_mut();
        (
            normalized_sid(target_pid, inner.sid, inner.pgid),
            inner.sid != 0 && inner.sid == target_pid,
            inner.did_exec,
        )
    };

    if target_pid != cur_pid && target_did_exec {
        return err(SyscallError::EACCES);
    }
    if target_sid != cur_sid || target_is_session_leader {
        return err(SyscallError::EPERM);
    }

    if new_pgid != target_pid {
        let Some(group_leader) = pid2process(new_pgid) else {
            return err(SyscallError::EPERM);
        };
        let group_sid = {
            let inner = group_leader.borrow_mut();
            normalized_sid(new_pgid, inner.sid, inner.pgid)
        };
        if group_sid != target_sid {
            return err(SyscallError::EPERM);
        }
    }

    let mut inner = target.borrow_mut();
    inner.pgid = new_pgid;
    0
}

/// Linux `getpgid(2)` (syscall 155 on riscv64).
pub fn syscall_getpgid(pid: usize) -> isize {
    let cur = current_process();
    let cur_pid = cur.getpid();
    let target_pid = if pid == 0 { cur_pid } else { pid };
    if target_pid == cur_pid {
        let inner = cur.borrow_mut();
        return normalized_pgid(cur_pid, inner.pgid) as isize;
    }
    let Some(target) = pid2process(target_pid) else {
        return err(SyscallError::ESRCH);
    };
    let inner = target.borrow_mut();
    if inner.is_zombie {
        return err(SyscallError::ESRCH);
    }
    normalized_pgid(target_pid, inner.pgid) as isize
}

/// Linux `getsid(2)` (syscall 156 on riscv64).
pub fn syscall_getsid(pid: usize) -> isize {
    let cur = current_process();
    let cur_pid = cur.getpid();
    let target_pid = if pid == 0 { cur_pid } else { pid };
    if target_pid == cur_pid {
        let inner = cur.borrow_mut();
        return normalized_sid(cur_pid, inner.sid, inner.pgid) as isize;
    }
    let Some(target) = pid2process(target_pid) else {
        return err(SyscallError::ESRCH);
    };
    let inner = target.borrow_mut();
    normalized_sid(target_pid, inner.sid, inner.pgid) as isize
}

/// Linux `setsid(2)` (syscall 157 on riscv64).
///
/// Create a new session unless a process group with ID equal to caller PID
/// already exists.
pub fn syscall_setsid() -> isize {
    let process = current_process();
    let pid = process.getpid();
    {
        let map = PID2PCB.lock();
        for proc in map.values() {
            let inner = proc.borrow_mut();
            if normalized_pgid(proc.getpid(), inner.pgid) == pid {
                return err(SyscallError::EPERM);
            }
        }
    }
    let mut inner = process.borrow_mut();
    inner.sid = pid;
    inner.pgid = pid;
    pid as isize
}
