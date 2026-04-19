mod identity;
mod session;
mod capability;
mod namespace;
mod sysinfo;
mod resource;
mod prctl;
mod ioctl;
mod other;

pub use identity::*;
pub use session::*;
pub use capability::*;
pub use namespace::*;
pub use self::sysinfo::*;
pub use resource::*;
pub use prctl::*;
pub use ioctl::*;
pub use other::*;

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
    current_task()
        .unwrap()
        .borrow_mut()
        .res
        .as_ref()
        .unwrap()
        .tid
}

pub(super) fn current_linux_tid() -> usize {
    encode_linux_tid(current_process().getpid(), current_tid_index())
}
