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
        File, OSInode, PseudoShmFile, ext4_lock, vm_commit_limit_bytes, vm_committed_as_bytes,
        vm_overcommit_memory,
    },
    mm::{
        BrkUpdate, MapPermission, MapType, MemorySet, MprotectError, PTEFlags, VmRegion,
        VmRegionKind, VmaInsertArea, frame_available_pages, reclaim_shared_file_page_cache,
        try_copy_to_user, try_copy_to_user_unchecked,
    },
    task::{
        manager::PID2PCB,
        processor::{current_files, current_process},
    },
    trap::get_current_token,
};
pub(super) use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
pub(super) use core::cmp::min;

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

#[derive(Clone, Copy)]
pub(super) struct OvercommitSnapshot {
    limit: Option<usize>,
    committed: usize,
    cumulative: bool,
}

impl OvercommitSnapshot {
    /// 在获取当前进程 mm 锁之前拍摄 overcommit 状态。Linux 模式 0 是
    /// 启发式检查，只拒绝单次明显超过可用内存的请求；模式 2 才使用全局
    /// committed 快照。这样常见的 brk/mmap 不再扫描并锁住所有 PCB。
    pub fn capture() -> Self {
        match vm_overcommit_memory() {
            0 => {
                let total = crate::mm::frame_managed_pages().saturating_mul(PAGE_SIZE);
                Self {
                    limit: Some(total.saturating_add(total / 2)),
                    committed: 0,
                    cumulative: false,
                }
            }
            1 => Self {
                limit: None,
                committed: 0,
                cumulative: false,
            },
            2 => Self {
                limit: Some(vm_commit_limit_bytes()),
                committed: vm_committed_as_bytes(),
                cumulative: true,
            },
            _ => Self {
                limit: None,
                committed: 0,
                cumulative: false,
            },
        }
    }

    pub fn rejects(self, additional_bytes: usize) -> bool {
        let Some(limit) = self.limit else {
            return false;
        };
        let requested = if self.cumulative {
            self.committed.saturating_add(additional_bytes)
        } else {
            additional_bytes
        };
        requested > limit
    }
}

pub(super) fn exceeds_overcommit_limit(additional_bytes: usize) -> bool {
    if additional_bytes == 0 {
        return false;
    }
    OvercommitSnapshot::capture().rejects(additional_bytes)
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
        let files = process.files();
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
        let files = process.files();
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
