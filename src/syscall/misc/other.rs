use crate::{
    config::clock_freq,
    debug_config::DEBUG_PTHREAD,
    fs::{NetSocketFile, POLLERR, POLLHUP, POLLIN, POLLNVAL},
    mm::{MapPermission, translated_byte_buffer, try_read_user_value, try_write_user_value},
    syscall::{
        error::{SyscallError, err},
        filesystem::O_PATH,
        robust_list::ROBUST_LIST_HEAD_LEN,
    },
    task::{
        manager::pid2process,
        processor::{PreparedWait, current_files, current_process, current_task},
        signal::{SIGKILL_NUM, SIGSTOP_NUM, has_wait_interrupting_pending, signal_bit},
    },
    time::get_time,
    trap::get_current_token,
};
use alloc::{sync::Arc, vec::Vec};
use core::mem::size_of;

use super::{current_linux_tid, encode_linux_tid};
use crate::fs::File;

/// Linux `set_tid_address(2)` (syscall 96 on riscv64).
///
/// We currently run a single-threaded process model for glibc apps; we accept the
/// pointer and return a Linux-like TID (use PID as TID).
pub fn syscall_set_tid_address(_tidptr: usize) -> isize {
    let task = current_task().unwrap();
    let tid_index = {
        let mut inner = task.borrow_mut();
        if _tidptr != 0 {
            inner.clear_child_tid = Some(_tidptr);
        }
        inner.res.as_ref().unwrap().tid
    };
    if DEBUG_PTHREAD {
        log::debug!(
            "[set_tid_address] tidptr={:#x} tid_index={}",
            _tidptr,
            tid_index
        );
    }
    encode_linux_tid(current_process().getpid(), tid_index) as isize
}

/// Linux `gettid(2)` (syscall 178 on riscv64).
pub fn syscall_gettid_linux() -> isize {
    current_linux_tid() as isize
}

#[allow(dead_code)]
pub fn syscall_mount(
    _special: usize,
    _dir: usize,
    _fstype: usize,
    _flags: usize,
    _data: usize,
) -> isize {
    crate::syscall::filesystem::syscall_mount_impl(_special, _dir, _fstype, _flags, _data)
}

#[allow(dead_code)]
pub fn syscall_umount2(_special: usize, _flags: usize) -> isize {
    crate::syscall::filesystem::syscall_umount2_impl(_special, _flags)
}

/// Linux `set_robust_list(2)` (syscall 99 on riscv64).
///
/// glibc uses this for mutex robustness; we store the head pointer for
/// best-effort cleanup on thread exit.
pub fn syscall_set_robust_list(_head: usize, _len: usize) -> isize {
    if _len != ROBUST_LIST_HEAD_LEN {
        return err(SyscallError::EINVAL);
    }
    let task = current_task().unwrap();
    let mut inner = task.borrow_mut();
    inner.robust_list_head = _head;
    inner.robust_list_len = _len;
    0
}

/// Linux `get_robust_list(2)` (syscall 100 on riscv64).
///
/// We only support querying the current thread (pid=0).
pub fn syscall_get_robust_list(pid: usize, head_ptr: usize, len_ptr: usize) -> isize {
    if head_ptr == 0 || len_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let caller = current_process();
    let caller_pid = caller.getpid();
    let caller_euid = {
        let inner = caller.borrow_mut();
        inner.euid
    };

    let task = if pid == 0 {
        current_task().unwrap()
    } else {
        // Linux permits querying self, but querying another task without
        // privilege should fail with err(SyscallError::EPERM).
        if caller_euid != 0 && pid != caller_pid {
            return err(SyscallError::EPERM);
        }
        let Some(target_proc) = pid2process(pid) else {
            return err(SyscallError::ESRCH);
        };
        let inner = target_proc.borrow_mut();
        let Some(task) = inner.tasks.first().and_then(|t| t.as_ref()).cloned() else {
            return err(SyscallError::ESRCH);
        };
        task
    };

    let (robust_head, robust_len) = {
        let inner = task.borrow_mut();
        (inner.robust_list_head, inner.robust_list_len)
    };
    let token = get_current_token();
    if try_write_user_value(token, head_ptr as *mut usize, &robust_head).is_err() {
        return err(SyscallError::EFAULT);
    }
    if try_write_user_value(token, len_ptr as *mut usize, &robust_len).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

/// Linux `getrandom(2)` (syscall 278 on riscv64).
///
/// Fill the buffer with a simple xorshift PRNG seeded from time and pid/tid.
pub fn syscall_getrandom(buf: usize, len: usize, _flags: u32) -> isize {
    const GRND_NONBLOCK: u32 = 0x0001;
    const GRND_RANDOM: u32 = 0x0002;

    if (_flags & !(GRND_NONBLOCK | GRND_RANDOM)) != 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    if buf == 0 {
        return err(SyscallError::EFAULT);
    }

    let token = get_current_token();
    let mut seed = (get_time() as u64)
        ^ ((current_process().getpid() as u64) << 32)
        ^ (current_linux_tid() as u64);
    for i in 0..len {
        // xorshift64*
        let mut x = seed;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x = x.wrapping_mul(0x2545F4914F6CDD1D);
        seed = x;
        let byte = (x & 0xff) as u8;
        if try_write_user_value(token, (buf + i) as *mut u8, &byte).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    len as isize
}

// ---- ppoll ------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

struct PollTarget {
    file: Option<Arc<dyn File + Send + Sync>>,
    fixed_mask: Option<i16>,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PollTimeSpec {
    sec: i64,
    nsec: i64,
}

const NSEC_PER_SEC: u64 = 1_000_000_000;

fn ppoll_now_ns() -> u64 {
    (get_time() as u64)
        .saturating_mul(NSEC_PER_SEC)
        .saturating_div(clock_freq() as u64)
}

fn ppoll_timespec_to_ns(ts: PollTimeSpec) -> Option<u64> {
    if ts.sec < 0 || ts.nsec < 0 || ts.nsec >= NSEC_PER_SEC as i64 {
        return None;
    }
    Some(
        (ts.sec as u64)
            .saturating_mul(NSEC_PER_SEC)
            .saturating_add(ts.nsec as u64),
    )
}

fn ppoll_write_back(token: usize, fds_ptr: usize, pfds: &[PollFd]) -> Result<(), isize> {
    for (i, pfd) in pfds.iter().enumerate() {
        let pfd_ptr = (fds_ptr + i * size_of::<PollFd>()) as *mut PollFd;
        if try_write_user_value(token, pfd_ptr, pfd).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
    }
    Ok(())
}

/// Linux `ppoll(2)` (syscall 73 on riscv64).
///
/// Minimal readiness reporting for shells (busybox/ash) and glibc helpers.
/// Readiness comes from each file's Linux-style `poll_mask()`.
pub fn syscall_ppoll(
    fds_ptr: usize,
    nfds: usize,
    _tmo_p: usize,
    _sigmask: usize,
    _sigsetsize: usize,
) -> isize {
    const EINTR: isize = -4;
    if (nfds as isize) < 0 {
        return err(SyscallError::EINVAL);
    }
    if nfds > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    if nfds > 0 && fds_ptr == 0 {
        return err(SyscallError::EFAULT);
    }

    let token = get_current_token();
    let files = current_files();
    let deadline_ns = if _tmo_p == 0 {
        None
    } else {
        let Some(ts) = try_read_user_value::<PollTimeSpec>(token, _tmo_p as *const PollTimeSpec)
        else {
            return err(SyscallError::EFAULT);
        };
        let Some(delta_ns) = ppoll_timespec_to_ns(ts) else {
            return err(SyscallError::EINVAL);
        };
        Some(ppoll_now_ns().saturating_add(delta_ns))
    };

    let task = current_task().unwrap();
    let mut restore_mask = None;
    if _sigmask != 0 {
        if _sigsetsize < size_of::<u64>() {
            return err(SyscallError::EINVAL);
        }
        let Some(mut new_mask) = try_read_user_value::<u64>(token, _sigmask as *const u64) else {
            return err(SyscallError::EFAULT);
        };
        let sigkill_bit = signal_bit(SIGKILL_NUM).unwrap_or(0);
        let sigstop_bit = signal_bit(SIGSTOP_NUM).unwrap_or(0);
        new_mask &= !(sigkill_bit | sigstop_bit);
        let old_mask = {
            let mut inner = task.borrow_mut();
            let old = inner.signal_mask;
            inner.signal_mask = new_mask;
            old
        };
        restore_mask = Some(old_mask);
    }

    let mut pfds = Vec::with_capacity(nfds);
    for i in 0..nfds {
        let pfd_ptr = (fds_ptr + i * size_of::<PollFd>()) as *const PollFd;
        let Some(mut pfd) = try_read_user_value::<PollFd>(token, pfd_ptr) else {
            if let Some(old_mask) = restore_mask {
                let mut inner = task.borrow_mut();
                inner.signal_mask = old_mask;
            }
            return err(SyscallError::EFAULT);
        };
        pfd.revents = 0;
        pfds.push(pfd);
    }

    let snapshot_poll_files = |pfds: &[PollFd]| -> Vec<PollTarget> {
        if pfds.is_empty() {
            return Vec::new();
        }
        let files_guard = files.lock();
        pfds.iter()
            .map(|pfd| {
                if pfd.fd < 0 {
                    PollTarget {
                        file: None,
                        fixed_mask: None,
                        flags: 0,
                    }
                } else {
                    match files_guard.get_poll_snapshot(pfd.fd as usize) {
                        Some((file, fixed_mask, flags)) => PollTarget {
                            file,
                            fixed_mask,
                            flags,
                        },
                        None => PollTarget {
                            file: None,
                            fixed_mask: None,
                            flags: 0,
                        },
                    }
                }
            })
            .collect()
    };

    let scan_ready = |pfds: &mut [PollFd], poll_files: &[PollTarget]| -> isize {
        let mut ready = 0isize;
        for (pfd, target) in pfds.iter_mut().zip(poll_files.iter()) {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            if target.file.is_none() && target.fixed_mask.is_none() {
                pfd.revents = POLLNVAL;
                ready += 1;
                continue;
            }
            if (target.flags & O_PATH as u32) != 0 {
                pfd.revents = POLLNVAL;
                ready += 1;
                continue;
            }

            let mask = match target.fixed_mask {
                Some(mask) => mask,
                None => target
                    .file
                    .as_ref()
                    .map(|file| file.poll_mask())
                    .unwrap_or(0),
            };
            pfd.revents = mask & (pfd.events | POLLERR | POLLHUP);
            if pfd.revents != 0 {
                ready += 1;
            }
        }
        ready
    };
    let busy_poll_net_read = |pfds: &mut [PollFd], poll_files: &[PollTarget]| -> isize {
        let mut ready = 0isize;
        for (pfd, target) in pfds.iter_mut().zip(poll_files.iter()) {
            if pfd.fd < 0 || (pfd.events & POLLIN) == 0 {
                continue;
            }
            let Some(file) = target.file.as_ref() else {
                continue;
            };
            let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() else {
                continue;
            };
            let revents = sock.busy_poll_revents_for_poll_events(pfd.events);
            if revents != 0 {
                pfd.revents = revents;
                ready += 1;
            }
        }
        ready
    };

    let ret = loop {
        let (pending, mask) = {
            let inner = task.borrow_mut();
            (inner.pending_signals, inner.signal_mask)
        };
        // Keep poll-like waits aligned with epoll/pipe behavior: don't let
        // default SIGCHLD bookkeeping spuriously interrupt readiness waits.
        if has_wait_interrupting_pending(pending, mask) {
            break EINTR;
        }

        let poll_files = snapshot_poll_files(&pfds);
        let ready = scan_ready(&mut pfds, &poll_files);

        if ready != 0 {
            break ready;
        }
        if let Some(deadline) = deadline_ns {
            let now = ppoll_now_ns();
            if now >= deadline {
                break 0;
            }
        }
        let ready = busy_poll_net_read(&mut pfds, &poll_files);
        if ready != 0 {
            break ready;
        }
        let mut waiter_armed = false;
        let mut net_timer_needed = false;
        for (pfd, target) in pfds.iter().zip(poll_files.iter()) {
            if pfd.fd < 0 {
                continue;
            }
            let Some(file) = target.file.as_ref() else {
                continue;
            };
            if file.as_any().downcast_ref::<NetSocketFile>().is_some() {
                net_timer_needed = true;
            }
            waiter_armed = file.register_poll_waiter(&task) || waiter_armed;
        }
        // Match Linux do_poll(): publish the sleeping task state before the
        // final table scan.  Otherwise a timer preemption can make a waker see
        // Ready just before this task resumes and blocks forever.
        let prepared = (waiter_armed || (nfds == 0 && deadline_ns.is_none()))
            .then(|| PreparedWait::new().expect("ppoll wait lost its current task"));
        let ready = scan_ready(&mut pfds, &poll_files);
        if ready != 0 {
            break ready;
        }
        if let Some(deadline) = deadline_ns {
            let now = ppoll_now_ns();
            if now >= deadline {
                break 0;
            }
        }
        if let Some(deadline) = deadline_ns {
            let now = ppoll_now_ns();
            let remain_ns = deadline.saturating_sub(now);
            let mut sleep_ms = ((remain_ns.saturating_add(999_999)) / 1_000_000) as usize;
            if sleep_ms == 0 {
                sleep_ms = 1;
            }
            if net_timer_needed {
                // 当前网络栈由 poll 推进；长时间阻塞在 poll 中时也要周期性运行 TCP 定时器。
                sleep_ms = sleep_ms.min(1);
            }
            if waiter_armed {
                crate::task::block_sleep::add_timer(Arc::clone(&task), sleep_ms);
                prepared
                    .expect("armed ppoll waiter has no prepared sleep")
                    .sleep();
            } else {
                let r = crate::syscall::thread::sys_sleep(sleep_ms);
                if r == EINTR {
                    let (pending, mask) = {
                        let inner = task.borrow_mut();
                        (inner.pending_signals, inner.signal_mask)
                    };
                    if has_wait_interrupting_pending(pending, mask) {
                        break EINTR;
                    }
                }
            }
        } else if nfds == 0 {
            prepared
                .expect("fd-less ppoll wait has no prepared sleep")
                .sleep();
        } else if waiter_armed {
            if net_timer_needed {
                crate::task::block_sleep::add_timer(Arc::clone(&task), 1);
            }
            prepared
                .expect("armed ppoll waiter has no prepared sleep")
                .sleep();
        } else {
            crate::task::processor::suspend_current_and_run_next();
        }
    };

    if ret >= 0 || ret == EINTR {
        if ppoll_write_back(token, fds_ptr, &pfds).is_err() {
            if let Some(old_mask) = restore_mask {
                let mut inner = task.borrow_mut();
                inner.signal_mask = old_mask;
            }
            return err(SyscallError::EFAULT);
        }
    }

    if let Some(old_mask) = restore_mask {
        let mut inner = task.borrow_mut();
        inner.signal_mask = old_mask;
    }

    ret
}

// ---- syslog -----------------------------------------------------------------

/// Linux `syslog(2)` / `klogctl(2)` (syscall 116 on riscv64).
///
/// Busybox `dmesg` calls this. We don't maintain a kernel log buffer for userspace;
/// return success and (for read requests) an empty buffer.
pub fn syscall_syslog(_type: usize, bufp: usize, len: usize) -> isize {
    // `klogctl` actions (Linux uapi).
    const SYSLOG_ACTION_READ: usize = 2;
    const SYSLOG_ACTION_READ_ALL: usize = 3;
    const SYSLOG_ACTION_READ_CLEAR: usize = 4;
    const SYSLOG_ACTION_CLEAR: usize = 5;
    const SYSLOG_ACTION_SIZE_BUFFER: usize = 10;
    const SYSLOG_ACTION_SIZE_UNREAD: usize = 11;

    match _type {
        SYSLOG_ACTION_SIZE_BUFFER => return crate::klog::capacity() as isize,
        SYSLOG_ACTION_SIZE_UNREAD => return crate::klog::len() as isize,
        SYSLOG_ACTION_CLEAR => {
            crate::klog::clear();
            return 0;
        }
        _ => {}
    }

    if bufp == 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }

    let data = match _type {
        SYSLOG_ACTION_READ | SYSLOG_ACTION_READ_ALL => crate::klog::snapshot(len),
        SYSLOG_ACTION_READ_CLEAR => crate::klog::snapshot_and_clear(len),
        _ => return err(SyscallError::EINVAL),
    };

    let token = get_current_token();
    let bufs = translated_byte_buffer(token, bufp as *mut u8, len, MapPermission::W);
    let mut off = 0usize;
    for b in bufs {
        if off >= data.len() {
            break;
        }
        let n = core::cmp::min(b.len(), data.len() - off);
        b[..n].copy_from_slice(&data[off..off + n]);
        off += n;
        if n < b.len() {
            break;
        }
    }
    data.len() as isize
}
