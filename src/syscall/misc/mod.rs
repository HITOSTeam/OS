mod capability;
mod identity;
mod ioctl;
mod module;
mod namespace;
mod other;
mod prctl;
mod resource;
mod session;
mod sysinfo;

pub use self::sysinfo::*;
pub use capability::*;
pub use identity::*;
pub use ioctl::*;
pub use module::*;
pub use namespace::*;
pub use other::*;
pub use prctl::*;
pub use resource::*;
pub use session::*;

// ---- Linux-like TID encoding ------------------------------------------------
//
// Internally, CongCore uses a small per-process `tid` index for locating per-thread resources
// (trap context pages, optional kernel-managed stacks). glibc expects a Linux-style `gettid()`
// that is:
// - equal to `getpid()` for the main thread, and
// - unique across all threads in the system.
//
// To avoid refactoring the internal resource indexing, we encode non-main thread IDs into
// a 32-bit range derived from (tgid << 15) | tid_index, keeping bit 30 clear so
// futex owner bits (OWNER_DIED/WAITERS) remain usable.
// (tgid << 15) occupies bits [15..29] for typical OSComp PID ranges (< 32768).
const LINUX_TID_PID_SHIFT: usize = 15;

use crate::task::processor::{current_process, current_task};

pub(crate) fn encode_linux_tid(tgid: usize, tid_index: usize) -> usize {
    if tid_index == 0 {
        tgid
    } else {
        (tgid << LINUX_TID_PID_SHIFT) | (tid_index & 0x7fff)
    }
}

pub(crate) fn decode_linux_tid(tgid: usize, tid: usize) -> Option<usize> {
    // Strip futex owner/waiter bits that user space may OR into the TID word.
    let tid = tid & 0x3fff_ffff;
    if tid == tgid {
        return Some(0);
    }
    let pid_part = tid >> LINUX_TID_PID_SHIFT;
    if pid_part != tgid {
        return None;
    }
    Some(tid & 0x7fff)
}

pub(crate) fn decode_linux_tid_strict(tgid: usize, tid: usize) -> Option<usize> {
    if tid == tgid {
        return Some(0);
    }
    let pid_part = tid >> LINUX_TID_PID_SHIFT;
    if pid_part != tgid {
        return None;
    }
    Some(tid & 0x7fff)
}

pub(super) fn current_tid_index() -> usize {
    let Some(task) = current_task() else {
        return 0;
    };
    // exit_group 可能在另一个核心撤销本线程的用户资源；当前系统调用仍需
    // 走到 trap_return，后者发现 res 为空后会完成线程退出。此窗口内把它
    // 视为线程组主线程，不能因线程号已解绑而 panic。
    task.borrow_mut()
        .res
        .as_ref()
        .map(|res| res.tid)
        .unwrap_or(0)
}

pub(super) fn current_linux_tid() -> usize {
    encode_linux_tid(current_process().getpid(), current_tid_index())
}
