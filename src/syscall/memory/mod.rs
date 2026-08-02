mod mlock;
mod mmap;
mod unmap;

pub use mlock::*;
pub use mmap::*;
pub use unmap::*;

pub(super) use crate::syscall::error::{SyscallError, err};
pub(super) use crate::{
    config::PAGE_SIZE,
    fs::{
        File, OSInode, PseudoShmFile, vm_commit_limit_bytes, vm_committed_as_bytes,
        vm_overcommit_memory,
    },
    mm::{
        BrkUpdate, MapPermission, MapType, MemorySet, MprotectError, PTEFlags, VmRegion,
        VmRegionKind, VmaInsertArea, frame_available_pages, reclaim_file_page_cache,
        try_copy_to_user,
    },
    task::{
        manager::PID2PCB,
        processor::{current_files, current_process},
    },
    trap::get_current_token,
};
pub(super) use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
pub(super) use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};

pub(super) const PROT_READ: usize = 1;
pub(super) const PROT_WRITE: usize = 2;
pub(super) const PROT_EXEC: usize = 4;

// Linux `mmap(2)` flags (subset).
pub(super) const MAP_SHARED: usize = 0x01;
pub(super) const MAP_PRIVATE: usize = 0x02;
pub(super) const MAP_SHARED_VALIDATE: usize = 0x03;
pub(super) const MAP_FIXED: usize = 0x10;
pub(super) const MAP_ANONYMOUS: usize = 0x20;
pub(super) const MAP_GROWSDOWN: usize = 0x0100;
pub(super) const MAP_LOCKED: usize = 0x2000;
pub(super) const MAP_STACK: usize = 0x20000;
pub(super) const MAP_FIXED_NOREPLACE: usize = 0x100000;
pub(super) const MAP_TYPE_MASK: usize = 0x0f;

pub(super) const LARGE_ANON_MMAP: usize = 1 * 1024 * 1024;

pub(super) const MCL_CURRENT: usize = 0x01;
pub(super) const MCL_FUTURE: usize = 0x02;
pub(super) const MCL_ONFAULT: usize = 0x04;

pub(super) const MREMAP_MAYMOVE: usize = 0x1;
pub(super) const MREMAP_FIXED: usize = 0x2;

#[cfg(target_arch = "loongarch64")]
pub(super) const USER_VA_TOP: usize = crate::config::TRAP_CONTEXT;
// Sv39 user-space low canonical range is [0, 2^38).
// Reject higher addresses so mmap() can't wrap/alias via VirtAddr masking.
#[cfg(not(target_arch = "loongarch64"))]
pub(super) const USER_VA_TOP: usize = 1usize << 38;

pub(super) fn align_down(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

pub(super) fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}
/// 用户地址区间检查，不要覆盖trap 跳板代码就行
pub(super) fn user_range_valid(start: usize, end: usize) -> bool {
    start < end && end <= USER_VA_TOP
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OvercommitRejectReason {
    GuessRequestExceedsMemory,
    StrictCommitLimit,
}

impl OvercommitRejectReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::GuessRequestExceedsMemory => "request-exceeds-memory",
            Self::StrictCommitLimit => "commit-limit",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OvercommitRejection {
    mode: usize,
    reason: OvercommitRejectReason,
    requested_bytes: usize,
    committed_bytes: usize,
    limit_bytes: usize,
}

static OVERCOMMIT_REJECT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Apply Linux's three overcommit policies to one new accountable mapping.
///
/// `OVERCOMMIT_GUESS` (mode 0) deliberately does not compare the system-wide
/// committed counter against `CommitLimit`: Linux only rejects a single request
/// larger than RAM plus swap in this mode.  This kernel has no swap, so managed
/// RAM is the corresponding bound.  The global committed counter is a hard gate
/// only for `OVERCOMMIT_NEVER` (mode 2).
fn evaluate_overcommit(
    mode: usize,
    additional_bytes: usize,
    committed_bytes: usize,
    managed_bytes: usize,
    strict_limit_bytes: usize,
) -> Option<OvercommitRejection> {
    if additional_bytes == 0 {
        return None;
    }

    let (reason, limit_bytes, rejected) = match mode {
        0 => (
            OvercommitRejectReason::GuessRequestExceedsMemory,
            managed_bytes,
            additional_bytes > managed_bytes,
        ),
        1 => return None,
        2 => (
            OvercommitRejectReason::StrictCommitLimit,
            strict_limit_bytes,
            committed_bytes.saturating_add(additional_bytes) > strict_limit_bytes,
        ),
        // /proc/sys/vm/overcommit_memory accepts only 0..=2.  Keep an invalid
        // internal value permissive instead of unexpectedly breaking mmap.
        _ => return None,
    };

    rejected.then_some(OvercommitRejection {
        mode,
        reason,
        requested_bytes: additional_bytes,
        committed_bytes,
        limit_bytes,
    })
}

fn overcommit_rejection(additional_bytes: usize) -> Option<OvercommitRejection> {
    evaluate_overcommit(
        vm_overcommit_memory(),
        additional_bytes,
        vm_committed_as_bytes(),
        crate::mm::frame_managed_pages().saturating_mul(PAGE_SIZE),
        vm_commit_limit_bytes(),
    )
}

/// Return true when the current overcommit policy rejects an allocation and
/// emit a sampled diagnostic.  Rejections are rare and actionable; sampling
/// keeps a malformed workload from flooding the serial console.
pub(super) fn overcommit_rejects(
    operation: &'static str,
    pid: usize,
    additional_bytes: usize,
) -> bool {
    let Some(rejection) = overcommit_rejection(additional_bytes) else {
        return false;
    };

    let sequence = OVERCOMMIT_REJECT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if sequence <= 8 || sequence.is_power_of_two() {
        log::warn!(
            "[mm-overcommit] seq={} op={} pid={} mode={} reason={} request={} committed={} limit={} free={}",
            sequence,
            operation,
            pid,
            rejection.mode,
            rejection.reason.as_str(),
            rejection.requested_bytes,
            rejection.committed_bytes,
            rejection.limit_bytes,
            frame_available_pages().saturating_mul(PAGE_SIZE),
        );
    }
    true
}

#[cfg(test)]
mod overcommit_tests {
    use super::*;

    const RAM: usize = 8 * 1024 * 1024;
    const STRICT_LIMIT: usize = RAM / 2;

    #[test]
    fn guess_mode_ignores_aggregate_commit_for_small_requests() {
        let rejection = evaluate_overcommit(0, 64 * 1024, RAM * 8, RAM, STRICT_LIMIT);
        assert_eq!(rejection, None);
    }

    #[test]
    fn guess_mode_rejects_only_a_single_request_larger_than_memory() {
        assert_eq!(evaluate_overcommit(0, RAM, 0, RAM, STRICT_LIMIT), None);
        assert_eq!(
            evaluate_overcommit(0, RAM + PAGE_SIZE, 0, RAM, STRICT_LIMIT)
                .map(|rejection| rejection.reason),
            Some(OvercommitRejectReason::GuessRequestExceedsMemory)
        );
    }

    #[test]
    fn always_mode_never_rejects_from_commit_accounting() {
        assert_eq!(
            evaluate_overcommit(1, usize::MAX, usize::MAX, RAM, STRICT_LIMIT),
            None
        );
    }

    #[test]
    fn strict_mode_checks_aggregate_commit_limit() {
        assert_eq!(
            evaluate_overcommit(2, PAGE_SIZE, STRICT_LIMIT - PAGE_SIZE, RAM, STRICT_LIMIT),
            None
        );
        assert_eq!(
            evaluate_overcommit(
                2,
                PAGE_SIZE * 2,
                STRICT_LIMIT - PAGE_SIZE,
                RAM,
                STRICT_LIMIT
            )
            .map(|rejection| rejection.reason),
            Some(OvercommitRejectReason::StrictCommitLimit)
        );
    }
}

pub(super) fn find_inode_file_in_snapshot(
    files: &[(usize, Arc<dyn File + Send + Sync>)],
    device_id: usize,
    inode_num: u32,
) -> Option<Arc<dyn File + Send + Sync>> {
    for (_fd, file) in files {
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            continue;
        };
        let inode = os_inode.ext4_inode();
        if inode.device_id() == device_id && inode.inode_num() == inode_num {
            return Some(Arc::clone(file));
        }
    }
    None
}

pub(super) fn find_open_inode_file(
    device_id: usize,
    inode_num: u32,
) -> Option<Arc<dyn File + Send + Sync>> {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        let files = Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        let snapshot = files.lock().iter_files_snapshot();
        if let Some(file) = find_inode_file_in_snapshot(&snapshot, device_id, inode_num) {
            return Some(file);
        }
    }
    None
}

pub(super) fn find_shm_file_in_snapshot(
    files: &[(usize, Arc<dyn File + Send + Sync>)],
    memfd_id: u64,
) -> Option<Arc<dyn File + Send + Sync>> {
    if memfd_id == 0 {
        return None;
    }
    for (_fd, file) in files {
        let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() else {
            continue;
        };
        if shm.memfd_id() == memfd_id {
            return Some(Arc::clone(file));
        }
    }
    None
}

pub(super) fn find_open_shm_file(memfd_id: u64) -> Option<Arc<dyn File + Send + Sync>> {
    if memfd_id == 0 {
        return None;
    }
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut seen_tables = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        let files = Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        let snapshot = files.lock().iter_files_snapshot();
        if let Some(file) = find_shm_file_in_snapshot(&snapshot, memfd_id) {
            return Some(file);
        }
    }
    None
}

pub(super) fn page_overlaps_sysv_shm_regions(
    page_start: usize,
    attaches: &[crate::syscall::sysv_shm::ShmAttach],
) -> bool {
    let page_end = page_start.saturating_add(PAGE_SIZE);
    attaches.iter().any(|a| {
        let a_end = a.addr.saturating_add(a.len);
        page_end > a.addr && page_start < a_end
    })
}
