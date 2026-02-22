use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::config::PAGE_SIZE;
use crate::mm::{FrameTracker, MapPermission, PTEFlags, VirtAddr, frame_alloc};
use crate::task::processor::current_process;

const IPC_PRIVATE: usize = 0;
const IPC_CREAT: usize = 0x200;
const IPC_EXCL: usize = 0x400;

// `shmat(2)` flags (subset).
const SHM_RDONLY: usize = 0x1000;
const SHM_RND: usize = 0x2000;
const SHM_REMAP: usize = 0x4000;

// `shmctl(2)` operations (subset).
const IPC_RMID: usize = 0;

const EINVAL: isize = -22;
const ENOMEM: isize = -12;
const ENOENT: isize = -2;
const EEXIST: isize = -17;

fn align_down(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

#[derive(Clone, Copy, Debug)]
pub struct ShmAttach {
    pub addr: usize,
    pub shmid: usize,
    pub len: usize,
}

#[derive(Debug)]
struct ShmSegment {
    id: usize,
    key: Option<usize>,
    size: usize,
    frames: Vec<FrameTracker>,
    nattch: usize,
    marked_for_deletion: bool,
}

#[derive(Debug, Default)]
struct ShmManager {
    next_id: usize,
    segments: BTreeMap<usize, ShmSegment>,
    key2id: BTreeMap<usize, usize>,
}

impl ShmManager {
    fn alloc_id(&mut self) -> usize {
        if self.next_id < 1 {
            self.next_id = 1;
        }
        let mut id = self.next_id;
        while self.segments.contains_key(&id) {
            id += 1;
        }
        self.next_id = id + 1;
        id
    }

    fn remove_segment(&mut self, id: usize) {
        if let Some(seg) = self.segments.remove(&id) {
            if let Some(key) = seg.key {
                if self.key2id.get(&key).copied() == Some(id) {
                    self.key2id.remove(&key);
                }
            }
        }
    }
}

lazy_static! {
    static ref SHM_MANAGER: Mutex<ShmManager> = Mutex::new(ShmManager::default());
}

pub fn fork_inherit(attaches: &[ShmAttach]) {
    let mut mgr = SHM_MANAGER.lock();
    for a in attaches {
        if let Some(seg) = mgr.segments.get_mut(&a.shmid) {
            seg.nattch += 1;
        }
    }
}

pub fn exit_cleanup(attaches: &[ShmAttach]) {
    let mut mgr = SHM_MANAGER.lock();
    for a in attaches {
        if let Some(seg) = mgr.segments.get_mut(&a.shmid) {
            if seg.nattch > 0 {
                seg.nattch -= 1;
            }
        }
    }
    let to_remove: Vec<usize> = mgr
        .segments
        .iter()
        .filter_map(|(id, seg)| {
            if seg.marked_for_deletion && seg.nattch == 0 {
                Some(*id)
            } else {
                None
            }
        })
        .collect();
    for id in to_remove {
        mgr.remove_segment(id);
    }
}

pub fn syscall_shmget(key: usize, size: usize, shmflg: usize) -> isize {
    if size == 0 {
        return EINVAL;
    }
    let size_aligned = align_up(size, PAGE_SIZE);

    let mut mgr = SHM_MANAGER.lock();
    if key != IPC_PRIVATE {
        if let Some(id) = mgr.key2id.get(&key).copied() {
            if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
                return EEXIST;
            }
            return id as isize;
        }
        if (shmflg & IPC_CREAT) == 0 {
            return ENOENT;
        }
    }

    let id = mgr.alloc_id();
    let pages = size_aligned / PAGE_SIZE;
    let mut frames = Vec::with_capacity(pages);
    for _ in 0..pages {
        let Some(frame) = frame_alloc() else {
            return ENOMEM;
        };
        frames.push(frame);
    }

    let seg = ShmSegment {
        id,
        key: if key == IPC_PRIVATE { None } else { Some(key) },
        size,
        frames,
        nattch: 0,
        marked_for_deletion: false,
    };
    if let Some(k) = seg.key {
        mgr.key2id.insert(k, id);
    }
    mgr.segments.insert(id, seg);
    id as isize
}

pub fn syscall_shmat(shmid: usize, shmaddr: usize, shmflg: usize) -> isize {
    if shmaddr % PAGE_SIZE != 0 && (shmflg & SHM_RND) == 0 {
        return EINVAL;
    }
    let mut mgr = SHM_MANAGER.lock();
    let Some(seg) = mgr.segments.get_mut(&shmid) else {
        return EINVAL;
    };

    let map_len = align_up(seg.size, PAGE_SIZE);
    let process = current_process();
    let mut inner = process.borrow_mut();

    let start = if shmaddr == 0 {
        align_up(inner.mmap_next, PAGE_SIZE)
    } else {
        align_down(shmaddr, PAGE_SIZE)
    };
    let Some(end) = start.checked_add(map_len) else {
        return ENOMEM;
    };

    // If the caller asks for a fixed address, follow SHM_REMAP by replacing
    // existing user mappings. Otherwise, reject overlaps.
    if shmaddr != 0 {
        let mut cur = start;
        while cur < end {
            let vpn = VirtAddr::from(cur).floor();
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                    return ENOMEM;
                }
                if pte.is_valid() && (shmflg & SHM_REMAP) == 0 {
                    return EINVAL;
                }
            }
            cur += PAGE_SIZE;
        }
        if (shmflg & SHM_REMAP) != 0 {
            inner.memory_set.unmap_user_range(start.into(), end.into());
        }
    }

    let mut perm = MapPermission::U | MapPermission::R;
    if (shmflg & SHM_RDONLY) == 0 {
        perm |= MapPermission::W;
    }

    let frames: Vec<FrameTracker> = seg.frames.iter().cloned().collect();
    inner
        .memory_set
        .insert_shared_frames_area(start.into(), end.into(), perm, frames);

    seg.nattch += 1;
    if end > inner.mmap_next {
        inner.mmap_next = end;
    }
    inner.sysv_shm_attaches.push(ShmAttach {
        addr: start,
        shmid,
        len: map_len,
    });
    start as isize
}

pub fn syscall_shmdt(shmaddr: usize) -> isize {
    if shmaddr % PAGE_SIZE != 0 {
        return EINVAL;
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    let Some((idx, a)) = inner
        .sysv_shm_attaches
        .iter()
        .enumerate()
        .find(|(_i, a)| a.addr == shmaddr)
        .map(|(i, a)| (i, *a))
    else {
        return EINVAL;
    };

    let end = a.addr + a.len;
    inner.memory_set.unmap_user_range(a.addr.into(), end.into());
    inner.sysv_shm_attaches.remove(idx);
    drop(inner);

    let mut mgr = SHM_MANAGER.lock();
    if let Some(seg) = mgr.segments.get_mut(&a.shmid) {
        if seg.nattch > 0 {
            seg.nattch -= 1;
        }
        if seg.marked_for_deletion && seg.nattch == 0 {
            mgr.remove_segment(a.shmid);
        }
    }
    0
}

pub fn syscall_shmctl(shmid: usize, cmd: usize, _buf: usize) -> isize {
    if cmd != IPC_RMID {
        return EINVAL;
    }
    let mut mgr = SHM_MANAGER.lock();
    let Some(seg) = mgr.segments.get_mut(&shmid) else {
        return EINVAL;
    };
    seg.marked_for_deletion = true;
    if seg.nattch == 0 {
        mgr.remove_segment(shmid);
    }
    0
}
