use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::config::PAGE_SIZE;
use crate::fs::find_path_in_roots;
use crate::mm::{
    frame_alloc, try_read_user_value, try_write_user_value, FrameTracker, MapPermission, PTEFlags,
    VirtAddr,
};
use crate::task::processor::current_process;

const IPC_PRIVATE: usize = 0;
const IPC_CREAT: usize = 0x200;
const IPC_EXCL: usize = 0x400;
const IPC_SET: usize = 1;
const IPC_INFO: usize = 3;

// `shmat(2)` flags (subset).
const SHM_RDONLY: usize = 0x1000;
const SHM_RND: usize = 0x2000;
const SHM_REMAP: usize = 0x4000;
const SHM_HUGETLB: usize = 0x0800;

// `shmctl(2)` operations (subset).
const IPC_RMID: usize = 0;
const IPC_STAT: usize = 2;
const SHM_LOCK: usize = 11;
const SHM_UNLOCK: usize = 12;
const SHM_STAT: usize = 13;
const SHM_INFO: usize = 14;
const SHM_STAT_ANY: usize = 15;

const SHM_LOCKED: u16 = 0o2000;
const SHMMIN: usize = 1;
const SHMMNI: usize = 4096;
const SHMMAX: usize = usize::MAX - (1usize << 24);
const SHMALL: usize = usize::MAX / PAGE_SIZE;
const SHM_MMAP_MIN_ADDR: usize = 0x10000;
const PROCFS_SHMMAX: &str = "/proc/sys/kernel/shmmax";
const PROCFS_SHMMNI: &str = "/proc/sys/kernel/shmmni";
const PROCFS_SHMALL: &str = "/proc/sys/kernel/shmall";

const EACCES: isize = -13;
const EFAULT: isize = -14;
const EINVAL: isize = -22;
const ENOMEM: isize = -12;
const ENOENT: isize = -2;
const EEXIST: isize = -17;
const EPERM: isize = -1;
const ENOSPC: isize = -28;

pub fn shmmax_limit() -> usize {
    SHMMAX
}

pub fn shmmni_limit() -> usize {
    SHMMNI
}

pub fn shmall_limit() -> usize {
    SHMALL
}

fn read_proc_sys_limit(path: &str, default: usize, min: usize, max: usize) -> usize {
    let Some(inode) = find_path_in_roots(path) else {
        return default;
    };
    let mut buf = [0u8; 64];
    let len = inode.read_at(0, &mut buf);
    if len == 0 {
        return default;
    }
    let Ok(raw) = core::str::from_utf8(&buf[..len]) else {
        return default;
    };
    let Ok(value) = raw.trim().parse::<usize>() else {
        return default;
    };
    value.clamp(min, max)
}

fn runtime_shmmax_limit() -> usize {
    read_proc_sys_limit(PROCFS_SHMMAX, SHMMAX, SHMMIN, SHMMAX)
}

fn runtime_shmmni_limit() -> usize {
    read_proc_sys_limit(PROCFS_SHMMNI, SHMMNI, 1, SHMMNI)
}

fn runtime_shmall_limit() -> usize {
    read_proc_sys_limit(PROCFS_SHMALL, SHMALL, 1, SHMALL)
}

pub fn proc_sysvipc_shm() -> String {
    let mut out = String::from(
        "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime rss swap\n",
    );
    let ipc_ns_id = current_ipc_namespace_id();
    let managers = SHM_MANAGERS.lock();
    let Some(mgr) = managers.get(&ipc_ns_id) else {
        return out;
    };
    for seg in mgr.segments.values() {
        let key = seg.key.unwrap_or(0);
        let line = format!(
            "{:10} {:10} {:5o} {:21} {:5} {:5} {:6} {:5} {:5} {:5} {:5} {:10} {:10} {:10} {:3} {:4}\n",
            key,
            seg.id,
            seg.mode & 0o777,
            seg.size,
            seg.cpid,
            seg.lpid,
            seg.nattch,
            seg.uid,
            seg.gid,
            seg.cuid,
            seg.cgid,
            seg.atime,
            seg.dtime,
            seg.ctime,
            align_up(seg.size, PAGE_SIZE) / PAGE_SIZE,
            0
        );
        out.push_str(&line);
    }
    out
}

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
    mode: u16,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    ctime: i64,
    atime: i64,
    dtime: i64,
    cpid: u32,
    lpid: u32,
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
    // SysV SHM objects are scoped per IPC namespace.
    static ref SHM_MANAGERS: Mutex<BTreeMap<usize, ShmManager>> = Mutex::new(BTreeMap::new());
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IpcPermUser {
    __key: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    __pad1: u16,
    __seq: u16,
    __pad2: u16,
    __unused1: u64,
    __unused2: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ShmidDsUser {
    shm_perm: IpcPermUser,
    shm_segsz: u64,
    shm_atime: i64,
    shm_dtime: i64,
    shm_ctime: i64,
    shm_cpid: u32,
    shm_lpid: u32,
    shm_nattch: u64,
    __unused4: u64,
    __unused5: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ShmInfoUser {
    used_ids: i32,
    __pad: i32,
    shm_tot: u64,
    shm_rss: u64,
    shm_swp: u64,
    swap_attempts: u64,
    swap_successes: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ShminfoUser {
    shmmax: u64,
    shmmin: u64,
    shmmni: u64,
    shmseg: u64,
    shmall: u64,
    __unused1: u64,
    __unused2: u64,
    __unused3: u64,
    __unused4: u64,
}

fn now_secs() -> i64 {
    crate::syscall::time_sys::realtime_now_seconds() as i64
}

fn current_ipc_namespace_id() -> usize {
    let process = current_process();
    process.borrow_mut().ipc_ns_id
}

fn current_ids() -> (u32, u32, u32, Vec<u32>) {
    let process = current_process();
    let inner = process.borrow_mut();
    (
        inner.euid,
        inner.egid,
        process.getpid() as u32,
        inner.supplementary_gids.clone(),
    )
}

fn check_perm(
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    req: u16,
    caller_uid: u32,
    caller_gid: u32,
    groups: &[u32],
) -> bool {
    if req == 0 || caller_uid == 0 {
        return true;
    }
    let class_shift = if caller_uid == uid || caller_uid == cuid {
        6
    } else if caller_gid == gid
        || caller_gid == cgid
        || groups.iter().any(|g| *g == gid || *g == cgid)
    {
        3
    } else {
        0
    };
    let need = ((req as usize) >> 6) & 0x7;
    let allow = ((mode as usize) >> class_shift) & 0x7;
    (allow & need) == need
}

pub fn fork_inherit(ipc_ns_id: usize, attaches: &[ShmAttach]) {
    let mut managers = SHM_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();
    for a in attaches {
        if let Some(seg) = mgr.segments.get_mut(&a.shmid) {
            seg.nattch += 1;
        }
    }
}

pub fn rollback_fork_inherit(ipc_ns_id: usize, attaches: &[ShmAttach]) {
    let mut managers = SHM_MANAGERS.lock();
    let Some(mgr) = managers.get_mut(&ipc_ns_id) else {
        return;
    };
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

pub fn exit_cleanup(ipc_ns_id: usize, attaches: &[ShmAttach]) {
    rollback_fork_inherit(ipc_ns_id, attaches);
}

pub fn syscall_shmget(key: usize, size: usize, shmflg: usize) -> isize {
    if (shmflg & SHM_HUGETLB) != 0 {
        // HugeTLB shared memory is not supported yet.
        return EINVAL;
    }
    let shmmax_limit = runtime_shmmax_limit();
    let shmmni_limit = runtime_shmmni_limit();
    let shmall_limit = runtime_shmall_limit();

    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = SHM_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();
    if key != IPC_PRIVATE {
        if let Some(id) = mgr.key2id.get(&key).copied() {
            if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
                return EEXIST;
            }
            let Some(seg) = mgr.segments.get(&id) else {
                return EINVAL;
            };
            if size > seg.size {
                return EINVAL;
            }
            let (uid, gid, _, groups) = current_ids();
            let req = (shmflg & 0o600) as u16;
            if !check_perm(
                seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, req, uid, gid, &groups,
            ) {
                return EACCES;
            }
            return id as isize;
        }
        if (shmflg & IPC_CREAT) == 0 {
            return ENOENT;
        }
    }
    if size < SHMMIN || size > shmmax_limit {
        return EINVAL;
    }
    let size_aligned = align_up(size, PAGE_SIZE);
    let pages = size_aligned / PAGE_SIZE;
    if mgr.segments.len() >= shmmni_limit {
        return ENOSPC;
    }
    let used_pages = mgr.segments.values().fold(0usize, |acc, seg| {
        acc.saturating_add(align_up(seg.size, PAGE_SIZE) / PAGE_SIZE)
    });
    if pages > shmall_limit.saturating_sub(used_pages) {
        return ENOSPC;
    }

    let id = mgr.alloc_id();
    let (uid, gid, pid, _) = current_ids();
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
        mode: (shmflg & 0o777) as u16,
        uid,
        gid,
        cuid: uid,
        cgid: gid,
        ctime: now_secs(),
        atime: 0,
        dtime: 0,
        cpid: pid,
        lpid: 0,
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
    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = SHM_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();
    let Some(seg) = mgr.segments.get_mut(&shmid) else {
        return EINVAL;
    };
    let (uid, gid, pid, groups) = current_ids();
    if !check_perm(
        seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, 0o400, uid, gid, &groups,
    ) {
        return EACCES;
    }
    if (shmflg & SHM_RDONLY) == 0
        && !check_perm(
            seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, 0o200, uid, gid, &groups,
        )
    {
        return EACCES;
    }

    let map_len = align_up(seg.size, PAGE_SIZE);
    let process = current_process();
    let mut inner = process.borrow_mut();

    let start = if shmaddr == 0 {
        align_up(inner.mmap_next, PAGE_SIZE)
    } else {
        align_down(shmaddr, PAGE_SIZE)
    };
    if (shmflg & SHM_REMAP) != 0 && start < SHM_MMAP_MIN_ADDR {
        // Keep low-page protection when SHM_RND rounds down close-to-null hints.
        return EINVAL;
    }
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
    seg.atime = now_secs();
    seg.lpid = pid;
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

    let (_, _, pid, _) = current_ids();
    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = SHM_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();
    if let Some(seg) = mgr.segments.get_mut(&a.shmid) {
        if seg.nattch > 0 {
            seg.nattch -= 1;
        }
        seg.dtime = now_secs();
        seg.lpid = pid;
        if seg.marked_for_deletion && seg.nattch == 0 {
            mgr.remove_segment(a.shmid);
        }
    }
    0
}

fn shm_to_user(seg: &ShmSegment) -> ShmidDsUser {
    ShmidDsUser {
        shm_perm: IpcPermUser {
            __key: seg.key.unwrap_or(0) as u32,
            uid: seg.uid,
            gid: seg.gid,
            cuid: seg.cuid,
            cgid: seg.cgid,
            mode: seg.mode,
            ..IpcPermUser::default()
        },
        shm_segsz: seg.size as u64,
        shm_atime: seg.atime,
        shm_dtime: seg.dtime,
        shm_ctime: seg.ctime,
        shm_cpid: seg.cpid,
        shm_lpid: seg.lpid,
        shm_nattch: seg.nattch as u64,
        ..ShmidDsUser::default()
    }
}

pub fn syscall_shmctl(shmid: usize, cmd: usize, _buf: usize) -> isize {
    let token = crate::trap::get_current_token();
    let (uid, gid, _pid, groups) = current_ids();
    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = SHM_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();

    if cmd == IPC_INFO {
        let highest_index = mgr.segments.keys().next_back().copied().unwrap_or(0);
        let info = ShminfoUser {
            shmmax: runtime_shmmax_limit() as u64,
            shmmin: SHMMIN as u64,
            shmmni: runtime_shmmni_limit() as u64,
            shmseg: runtime_shmmni_limit() as u64,
            shmall: runtime_shmall_limit() as u64,
            ..ShminfoUser::default()
        };
        if try_write_user_value(token, _buf as *mut ShminfoUser, &info).is_err() {
            return EFAULT;
        }
        return highest_index as isize;
    }

    if cmd == SHM_INFO {
        let highest_index = mgr.segments.keys().next_back().copied().unwrap_or(0);
        let total_pages = mgr
            .segments
            .values()
            .map(|s| align_up(s.size, PAGE_SIZE) / PAGE_SIZE)
            .sum::<usize>();
        let info = ShmInfoUser {
            used_ids: mgr.segments.len() as i32,
            shm_tot: total_pages as u64,
            shm_rss: total_pages as u64,
            ..ShmInfoUser::default()
        };
        if try_write_user_value(token, _buf as *mut ShmInfoUser, &info).is_err() {
            return EFAULT;
        }
        return highest_index as isize;
    }

    if cmd == SHM_STAT || cmd == SHM_STAT_ANY {
        let Some((&seg_id, seg)) = mgr.segments.iter().nth(shmid) else {
            return EINVAL;
        };
        if cmd == SHM_STAT
            && !check_perm(
                seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, 0o400, uid, gid, &groups,
            )
        {
            return EACCES;
        }
        let ds = shm_to_user(seg);
        if try_write_user_value(token, _buf as *mut ShmidDsUser, &ds).is_err() {
            return EFAULT;
        }
        return seg_id as isize;
    }

    let Some(seg) = mgr.segments.get_mut(&shmid) else {
        return EINVAL;
    };
    match cmd {
        IPC_RMID => {
            if uid != 0 && uid != seg.uid && uid != seg.cuid {
                return EPERM;
            }
            seg.marked_for_deletion = true;
            if seg.nattch == 0 {
                mgr.remove_segment(shmid);
            }
            0
        }
        IPC_STAT => {
            if !check_perm(
                seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, 0o400, uid, gid, &groups,
            ) {
                return EACCES;
            }
            let ds = shm_to_user(seg);
            if try_write_user_value(token, _buf as *mut ShmidDsUser, &ds).is_err() {
                return EFAULT;
            }
            0
        }
        IPC_SET => {
            if uid != 0 && uid != seg.uid && uid != seg.cuid {
                return EPERM;
            }
            let Some(ds) = try_read_user_value(token, _buf as *const ShmidDsUser) else {
                return EFAULT;
            };
            seg.uid = ds.shm_perm.uid;
            seg.gid = ds.shm_perm.gid;
            seg.mode = (seg.mode & SHM_LOCKED) | (ds.shm_perm.mode & 0o777);
            seg.ctime = now_secs();
            0
        }
        SHM_LOCK => {
            if uid != 0 && uid != seg.uid && uid != seg.cuid {
                return EPERM;
            }
            seg.mode |= SHM_LOCKED;
            0
        }
        SHM_UNLOCK => {
            if uid != 0 && uid != seg.uid && uid != seg.cuid {
                return EPERM;
            }
            seg.mode &= !SHM_LOCKED;
            0
        }
        _ => EINVAL,
    }
}
