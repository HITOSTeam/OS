use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::config::PAGE_SIZE;
use crate::fs::parse_proc_sys_usize;
use crate::mm::{
    FrameTracker, MapPermission, MapType, PTEFlags, VirtAddr, VmRegion, VmRegionKind,
    VmaInsertArea, frame_alloc, try_read_user_value, try_write_user_value,
};
use crate::syscall::error::{SyscallError, err};
use crate::syscall::memory::USER_VA_TOP;
use crate::task::processor::current_process;

pub use crate::mm::{ShmAttach, ShmAttachRef};

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
static RUNTIME_SHMMAX_LIMIT: AtomicUsize = AtomicUsize::new(SHMMAX);
static RUNTIME_SHMMNI_LIMIT: AtomicUsize = AtomicUsize::new(SHMMNI);
static RUNTIME_SHMALL_LIMIT: AtomicUsize = AtomicUsize::new(SHMALL);
static NEXT_SHM_ATTACH_ID: AtomicUsize = AtomicUsize::new(1);

#[allow(dead_code)]
pub fn shmmax_limit() -> usize {
    SHMMAX
}

#[allow(dead_code)]
pub fn shmmni_limit() -> usize {
    SHMMNI
}

#[allow(dead_code)]
pub fn shmall_limit() -> usize {
    SHMALL
}

pub fn write_shm_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    let (slot, min, max) = match path {
        PROCFS_SHMMAX => (&RUNTIME_SHMMAX_LIMIT, SHMMIN, SHMMAX),
        PROCFS_SHMMNI => (&RUNTIME_SHMMNI_LIMIT, 1, SHMMNI),
        PROCFS_SHMALL => (&RUNTIME_SHMALL_LIMIT, 1, SHMALL),
        _ => return Err(err(SyscallError::EINVAL)),
    };
    let value = parse_proc_sys_usize(data)?;
    if value < min || value > max {
        return Err(err(SyscallError::EINVAL));
    }
    slot.store(value, Ordering::Relaxed);
    Ok(format!("{}\n", value).into_bytes())
}

fn runtime_shmmax_limit() -> usize {
    RUNTIME_SHMMAX_LIMIT.load(Ordering::Relaxed)
}

fn runtime_shmmni_limit() -> usize {
    RUNTIME_SHMMNI_LIMIT.load(Ordering::Relaxed)
}

fn runtime_shmall_limit() -> usize {
    RUNTIME_SHMALL_LIMIT.load(Ordering::Relaxed)
}

pub fn runtime_shmmax_for_procfs() -> usize {
    runtime_shmmax_limit()
}

pub fn runtime_shmmni_for_procfs() -> usize {
    runtime_shmmni_limit()
}

pub fn runtime_shmall_for_procfs() -> usize {
    runtime_shmall_limit()
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

fn alloc_attach_id() -> usize {
    NEXT_SHM_ATTACH_ID.fetch_add(1, Ordering::Relaxed).max(1)
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

pub fn fork_inherit(attaches: &[ShmAttach]) {
    let mut managers = SHM_MANAGERS.lock();
    for a in attaches {
        if !a.accounted {
            continue;
        }
        let mgr = managers.entry(a.ipc_ns_id).or_default();
        if let Some(seg) = mgr.segments.get_mut(&a.shmid) {
            seg.nattch += 1;
        }
    }
}

pub fn rollback_fork_inherit(attaches: &[ShmAttach]) {
    let mut managers = SHM_MANAGERS.lock();
    let mut to_remove = Vec::new();
    for a in attaches {
        if !a.accounted {
            continue;
        }
        let Some(mgr) = managers.get_mut(&a.ipc_ns_id) else {
            continue;
        };
        if let Some(seg) = mgr.segments.get_mut(&a.shmid) {
            if seg.nattch > 0 {
                seg.nattch -= 1;
            }
            if seg.marked_for_deletion && seg.nattch == 0 {
                to_remove.push(ShmAttachRef {
                    ipc_ns_id: a.ipc_ns_id,
                    shmid: a.shmid,
                });
            }
        }
    }
    for attach_ref in to_remove {
        if let Some(mgr) = managers.get_mut(&attach_ref.ipc_ns_id) {
            mgr.remove_segment(attach_ref.shmid);
        }
    }
}

pub fn exit_cleanup(attaches: &[ShmAttach]) {
    rollback_fork_inherit(attaches);
}

pub fn segment_size(ipc_ns_id: usize, shmid: usize) -> Option<usize> {
    let managers = SHM_MANAGERS.lock();
    managers
        .get(&ipc_ns_id)
        .and_then(|mgr| mgr.segments.get(&shmid))
        .map(|seg| seg.size)
}

pub fn segment_shared_frames_existing(
    ipc_ns_id: usize,
    shmid: usize,
    offset: usize,
    len: usize,
) -> Option<Vec<FrameTracker>> {
    let end = offset.checked_add(len)?;
    let managers = SHM_MANAGERS.lock();
    let seg = managers.get(&ipc_ns_id)?.segments.get(&shmid)?;
    let mapped_len = align_up(seg.size, PAGE_SIZE);
    if end > mapped_len {
        return None;
    }
    let start_page = offset / PAGE_SIZE;
    let end_page = end.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE;
    if end_page < start_page || end_page > seg.frames.len() {
        return None;
    }
    Some(seg.frames[start_page..end_page].iter().cloned().collect())
}

pub fn find_attach_containing(
    attaches: &[ShmAttach],
    shmid: usize,
    start: usize,
    len: usize,
) -> Option<usize> {
    attaches
        .iter()
        .position(|attach| attach.shmid == shmid && attach.contains_range(start, len))
}

pub fn split_mremap_attach(
    attaches: &mut Vec<ShmAttach>,
    idx: usize,
    old_addr: usize,
    old_len: usize,
    new_addr: usize,
    new_len: usize,
) -> bool {
    if idx >= attaches.len() || new_len == 0 {
        return false;
    }
    let Some(old_end) = old_addr.checked_add(old_len) else {
        return false;
    };
    let Some(new_end) = new_addr.checked_add(new_len) else {
        return false;
    };
    if old_end <= old_addr || new_end <= new_addr {
        return false;
    }

    let attach = attaches.remove(idx);
    let attach_end = attach.end();
    if old_addr < attach.addr || old_end > attach_end {
        attaches.push(attach);
        return false;
    }

    let mut fragments = Vec::new();
    if old_addr > attach.addr {
        fragments.push(ShmAttach {
            ipc_ns_id: attach.ipc_ns_id,
            addr: attach.addr,
            shmid: attach.shmid,
            len: old_addr - attach.addr,
            attach_id: attach.attach_id,
            accounted: false,
        });
    }
    fragments.push(ShmAttach {
        ipc_ns_id: attach.ipc_ns_id,
        addr: new_addr,
        shmid: attach.shmid,
        len: new_len,
        attach_id: attach.attach_id,
        accounted: attach.accounted,
    });
    if old_end < attach_end {
        fragments.push(ShmAttach {
            ipc_ns_id: attach.ipc_ns_id,
            addr: old_end,
            shmid: attach.shmid,
            len: attach_end - old_end,
            attach_id: attach.attach_id,
            accounted: false,
        });
    }
    attaches.extend(fragments);
    attaches.sort_unstable_by(|left, right| {
        left.addr
            .cmp(&right.addr)
            .then(left.attach_id.cmp(&right.attach_id))
            .then(left.shmid.cmp(&right.shmid))
    });
    true
}

pub fn detach_attaches_overlapping(
    attaches: &mut Vec<ShmAttach>,
    start: usize,
    len: usize,
) -> Option<Vec<ShmAttachRef>> {
    let end = start.checked_add(len)?;
    if end <= start {
        return Some(Vec::new());
    }

    let mut next = Vec::with_capacity(attaches.len());
    let mut removed_accounted = Vec::new();
    for attach in attaches.drain(..) {
        let attach_end = attach.end();
        if end <= attach.addr || start >= attach_end {
            next.push(attach);
            continue;
        }
        if attach.accounted {
            removed_accounted.push((
                attach.attach_id,
                ShmAttachRef {
                    ipc_ns_id: attach.ipc_ns_id,
                    shmid: attach.shmid,
                },
            ));
        }
        if start > attach.addr {
            next.push(ShmAttach {
                ipc_ns_id: attach.ipc_ns_id,
                addr: attach.addr,
                shmid: attach.shmid,
                len: start - attach.addr,
                attach_id: attach.attach_id,
                accounted: false,
            });
        }
        if end < attach_end {
            next.push(ShmAttach {
                ipc_ns_id: attach.ipc_ns_id,
                addr: end,
                shmid: attach.shmid,
                len: attach_end - end,
                attach_id: attach.attach_id,
                accounted: false,
            });
        }
    }
    *attaches = next;
    attaches.sort_unstable_by(|left, right| {
        left.addr
            .cmp(&right.addr)
            .then(left.attach_id.cmp(&right.attach_id))
            .then(left.shmid.cmp(&right.shmid))
    });

    let mut release_shmids = Vec::new();
    for (attach_id, attach_ref) in removed_accounted {
        if let Some(survivor) = attaches
            .iter_mut()
            .find(|attach| attach.attach_id == attach_id)
        {
            survivor.accounted = true;
        } else {
            release_shmids.push(attach_ref);
        }
    }
    Some(release_shmids)
}

fn release_detached_attach_ref_in_manager(mgr: &mut ShmManager, pid: u32, shmid: usize) -> bool {
    let Some(seg) = mgr.segments.get_mut(&shmid) else {
        return false;
    };
    if seg.nattch > 0 {
        seg.nattch -= 1;
    }
    seg.dtime = now_secs();
    seg.lpid = pid;
    seg.marked_for_deletion && seg.nattch == 0
}

pub fn release_detached_attach_refs(pid: u32, refs: &[ShmAttachRef]) {
    if refs.is_empty() {
        return;
    }
    let mut managers = SHM_MANAGERS.lock();
    let mut to_remove = Vec::new();
    for attach_ref in refs {
        let Some(mgr) = managers.get_mut(&attach_ref.ipc_ns_id) else {
            continue;
        };
        if release_detached_attach_ref_in_manager(mgr, pid, attach_ref.shmid) {
            to_remove.push(*attach_ref);
        }
    }
    for attach_ref in to_remove {
        if let Some(mgr) = managers.get_mut(&attach_ref.ipc_ns_id) {
            mgr.remove_segment(attach_ref.shmid);
        }
    }
}

pub fn syscall_shmget(key: usize, size: usize, shmflg: usize) -> isize {
    if (shmflg & SHM_HUGETLB) != 0 {
        // HugeTLB shared memory is not supported yet.
        return err(SyscallError::EINVAL);
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
                return err(SyscallError::EEXIST);
            }
            let Some(seg) = mgr.segments.get(&id) else {
                return err(SyscallError::EINVAL);
            };
            if size > seg.size {
                return err(SyscallError::EINVAL);
            }
            let (uid, gid, _, groups) = current_ids();
            let req = (shmflg & 0o600) as u16;
            if !check_perm(
                seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, req, uid, gid, &groups,
            ) {
                return err(SyscallError::EACCES);
            }
            return id as isize;
        }
        if (shmflg & IPC_CREAT) == 0 {
            return err(SyscallError::ENOENT);
        }
    }
    if size < SHMMIN || size > shmmax_limit {
        return err(SyscallError::EINVAL);
    }
    let size_aligned = align_up(size, PAGE_SIZE);
    let pages = size_aligned / PAGE_SIZE;
    if mgr.segments.len() >= shmmni_limit {
        return err(SyscallError::ENOSPC);
    }
    let used_pages = mgr.segments.values().fold(0usize, |acc, seg| {
        acc.saturating_add(align_up(seg.size, PAGE_SIZE) / PAGE_SIZE)
    });
    if pages > shmall_limit.saturating_sub(used_pages) {
        return err(SyscallError::ENOSPC);
    }

    let id = mgr.alloc_id();
    let (uid, gid, pid, _) = current_ids();
    let mut frames = Vec::with_capacity(pages);
    for _ in 0..pages {
        let Some(frame) = frame_alloc() else {
            return err(SyscallError::ENOMEM);
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
        return err(SyscallError::EINVAL);
    }
    let ipc_ns_id = current_ipc_namespace_id();
    let mut managers = SHM_MANAGERS.lock();
    let mgr = managers.entry(ipc_ns_id).or_default();
    let Some(seg) = mgr.segments.get_mut(&shmid) else {
        return err(SyscallError::EINVAL);
    };
    let (uid, gid, pid, groups) = current_ids();
    if !check_perm(
        seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, 0o400, uid, gid, &groups,
    ) {
        return err(SyscallError::EACCES);
    }
    if (shmflg & SHM_RDONLY) == 0
        && !check_perm(
            seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, 0o200, uid, gid, &groups,
        )
    {
        return err(SyscallError::EACCES);
    }

    let map_len = align_up(seg.size, PAGE_SIZE);
    let process = current_process();
    let inner = process.borrow_mut();

    let start = if shmaddr == 0 {
        let mut memory_set = inner.memory_set.lock();
        let Some(start) = memory_set.find_free_mmap_range(None, map_len, USER_VA_TOP) else {
            return err(SyscallError::ENOMEM);
        };
        start
    } else {
        align_down(shmaddr, PAGE_SIZE)
    };
    if (shmflg & SHM_REMAP) != 0 && start < SHM_MMAP_MIN_ADDR {
        // Keep low-page protection when SHM_RND rounds down close-to-null hints.
        return err(SyscallError::EINVAL);
    }
    let Some(end) = start.checked_add(map_len) else {
        return err(SyscallError::ENOMEM);
    };

    // If the caller asks for a fixed address, follow SHM_REMAP by replacing
    // existing user mappings. Otherwise, reject overlaps.
    if shmaddr != 0 {
        let memory_set = inner.memory_set.lock();
        let mut cur = start;
        while cur < end {
            let vpn = VirtAddr::from(cur).floor();
            if let Some(pte) = memory_set.translate(vpn) {
                if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                    return err(SyscallError::ENOMEM);
                }
                if pte.is_valid() && (shmflg & SHM_REMAP) == 0 {
                    return err(SyscallError::EINVAL);
                }
            }
            cur += PAGE_SIZE;
        }
        if memory_set.concrete_range_overlaps(start.into(), end.into()) && (shmflg & SHM_REMAP) == 0
        {
            return err(SyscallError::EINVAL);
        }
    }

    let mut perm = MapPermission::U | MapPermission::R;
    if (shmflg & SHM_RDONLY) == 0 {
        perm |= MapPermission::W;
    }

    let frames: Vec<FrameTracker> = seg.frames.iter().cloned().collect();
    let region = VmRegion {
        kind: VmRegionKind::Mmap,
        start,
        len: map_len,
        prot: VmRegion::prot_from_permission(perm),
        map_type: MapType::Framed,
        map_perm: perm,
        file_valid_len: seg.size.min(map_len),
        sigbus_start: end,
        shared: true,
        may_write_upgrade: (shmflg & SHM_RDONLY) == 0,
        file_backed: false,
        file_dev: 0,
        file_ino: 0,
        file_offset: 0,
        backing_id: 0,
        shmem_id: 0,
        anon_shared_id: 0,
        sysv_shmid: shmid,
        growsdown: false,
        fork_inherited_anon: false,
    };
    let areas = Vec::from([VmaInsertArea::SharedFrames { start, end, frames }]);
    let detached_shmids = {
        let mut memory_set = inner.memory_set.lock();
        let remap_attach_update = if (shmflg & SHM_REMAP) != 0 {
            let mut updated_attaches = memory_set.sysv_shm_attaches_snapshot();
            let Some(release_shmids) =
                detach_attaches_overlapping(&mut updated_attaches, start, map_len)
            else {
                return err(SyscallError::ENOMEM);
            };
            Some((updated_attaches, release_shmids))
        } else {
            None
        };
        let inserted = if (shmflg & SHM_REMAP) != 0 {
            memory_set.try_replace_user_vma(region, areas, false, None)
        } else {
            memory_set.try_insert_user_vma(region, areas, false, None)
        };
        if !inserted {
            return err(SyscallError::ENOMEM);
        }

        if let Some((updated_attaches, release_shmids)) = remap_attach_update {
            memory_set.replace_sysv_shm_attaches(updated_attaches);
            release_shmids
        } else {
            Vec::new()
        }
    };
    seg.nattch += 1;
    seg.atime = now_secs();
    seg.lpid = pid;
    {
        let mut memory_set = inner.memory_set.lock();
        memory_set.note_mmap_end(end);
        memory_set.push_sysv_shm_attach(ShmAttach {
            ipc_ns_id,
            addr: start,
            shmid,
            len: map_len,
            attach_id: alloc_attach_id(),
            accounted: true,
        });
    }
    drop(inner);
    drop(managers);
    release_detached_attach_refs(pid, detached_shmids.as_slice());
    start as isize
}

pub fn syscall_shmdt(shmaddr: usize) -> isize {
    if shmaddr % PAGE_SIZE != 0 {
        return err(SyscallError::EINVAL);
    }
    let process = current_process();
    let inner = process.borrow_mut();
    let Some((a, transferred_account)) = ({
        let mut memory_set = inner.memory_set.lock();
        let result = memory_set.remove_sysv_shm_attach(shmaddr);
        if let Some((a, _)) = result {
            let end = a.addr + a.len;
            memory_set.unmap_user_vma_range(a.addr.into(), end.into());
        }
        result
    }) else {
        return err(SyscallError::EINVAL);
    };
    drop(inner);

    let (_, _, pid, _) = current_ids();
    let mut managers = SHM_MANAGERS.lock();
    let mgr = managers.entry(a.ipc_ns_id).or_default();
    if let Some(seg) = mgr.segments.get_mut(&a.shmid) {
        if a.accounted && !transferred_account && seg.nattch > 0 {
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
            return err(SyscallError::EFAULT);
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
            return err(SyscallError::EFAULT);
        }
        return highest_index as isize;
    }

    if cmd == SHM_STAT || cmd == SHM_STAT_ANY {
        let Some((&seg_id, seg)) = mgr.segments.iter().nth(shmid) else {
            return err(SyscallError::EINVAL);
        };
        if cmd == SHM_STAT
            && !check_perm(
                seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, 0o400, uid, gid, &groups,
            )
        {
            return err(SyscallError::EACCES);
        }
        let ds = shm_to_user(seg);
        if try_write_user_value(token, _buf as *mut ShmidDsUser, &ds).is_err() {
            return err(SyscallError::EFAULT);
        }
        return seg_id as isize;
    }

    let Some(seg) = mgr.segments.get_mut(&shmid) else {
        return err(SyscallError::EINVAL);
    };
    match cmd {
        IPC_RMID => {
            if uid != 0 && uid != seg.uid && uid != seg.cuid {
                return err(SyscallError::EPERM);
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
                return err(SyscallError::EACCES);
            }
            let ds = shm_to_user(seg);
            if try_write_user_value(token, _buf as *mut ShmidDsUser, &ds).is_err() {
                return err(SyscallError::EFAULT);
            }
            0
        }
        IPC_SET => {
            if uid != 0 && uid != seg.uid && uid != seg.cuid {
                return err(SyscallError::EPERM);
            }
            let Some(ds) = try_read_user_value(token, _buf as *const ShmidDsUser) else {
                return err(SyscallError::EFAULT);
            };
            seg.uid = ds.shm_perm.uid;
            seg.gid = ds.shm_perm.gid;
            seg.mode = (seg.mode & SHM_LOCKED) | (ds.shm_perm.mode & 0o777);
            seg.ctime = now_secs();
            0
        }
        SHM_LOCK => {
            if uid != 0 && uid != seg.uid && uid != seg.cuid {
                return err(SyscallError::EPERM);
            }
            seg.mode |= SHM_LOCKED;
            0
        }
        SHM_UNLOCK => {
            if uid != 0 && uid != seg.uid && uid != seg.cuid {
                return err(SyscallError::EPERM);
            }
            seg.mode &= !SHM_LOCKED;
            0
        }
        _ => err(SyscallError::EINVAL),
    }
}
