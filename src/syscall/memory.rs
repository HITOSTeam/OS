use crate::{
    config::{PAGE_SIZE, TRAP_CONTEXT},
    fs::{ext4_lock, File, OSInode, PseudoShmFile},
    mm::{frame_alloc, try_copy_to_user, try_copy_to_user_unchecked, MapPermission, PTEFlags},
    task::processor::{current_files_process, current_process},
    task::MmapRegion,
    trap::get_current_token,
};
use alloc::sync::Arc;
use core::cmp::min;

const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const PROT_EXEC: usize = 4;

// Linux `mmap(2)` flags (subset).
const MAP_SHARED: usize = 0x01;
const MAP_PRIVATE: usize = 0x02;
const MAP_SHARED_VALIDATE: usize = 0x03;
const MAP_FIXED: usize = 0x10;
const MAP_ANONYMOUS: usize = 0x20;
const MAP_LOCKED: usize = 0x2000;
const MAP_STACK: usize = 0x20000;
const MAP_FIXED_NOREPLACE: usize = 0x100000;
const MAP_TYPE_MASK: usize = 0x0f;

const LARGE_ANON_MMAP: usize = 1 * 1024 * 1024;

const EACCES: isize = -13;
const EBADF: isize = -9;
const EFAULT: isize = -14;
const EINVAL: isize = -22;
const ENOMEM: isize = -12;
const EEXIST: isize = -17;
const EPERM: isize = -1;

const MCL_CURRENT: usize = 0x01;
const MCL_FUTURE: usize = 0x02;
const MCL_ONFAULT: usize = 0x04;

#[cfg(target_arch = "loongarch64")]
const USER_VA_TOP: usize = TRAP_CONTEXT;
// Sv39 user-space low canonical range is [0, 2^38).
// Reject higher addresses so mmap() can't wrap/alias via VirtAddr masking.
#[cfg(not(target_arch = "loongarch64"))]
const USER_VA_TOP: usize = 1usize << 38;

fn align_down(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

fn user_range_valid(start: usize, end: usize) -> bool {
    start < end && end <= USER_VA_TOP
}

fn get_fd_file(fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return None;
    }
    inner.fd_table[fd].clone()
}

fn get_fd_inode(fd: usize) -> Option<Arc<ext4_fs::Inode>> {
    let file = get_fd_file(fd)?;
    file.as_any().downcast_ref::<OSInode>().map(|o| {
        // Ensure data written via buffered `write(2)` is visible to file-backed `mmap(2)`.
        // This keeps simple tests (write -> fstat -> mmap -> read) working.
        let _ = o.flush();
        o.ext4_inode()
    })
}

fn push_mmap_region_merged(regions: &mut alloc::vec::Vec<MmapRegion>, region: MmapRegion) {
    if region.len == 0 {
        return;
    }
    if let Some(last) = regions.last_mut() {
        if last.end() == region.start
            && last.prot == region.prot
            && last.shared == region.shared
            && last.may_write_upgrade == region.may_write_upgrade
        {
            last.len += region.len;
            return;
        }
    }
    regions.push(region);
}

fn trim_mmap_regions(regions: &mut alloc::vec::Vec<MmapRegion>, start: usize, end: usize) {
    let mut next = alloc::vec::Vec::new();
    for region in regions.drain(..) {
        let r_end = region.end();
        if end <= region.start || start >= r_end {
            push_mmap_region_merged(&mut next, region);
            continue;
        }
        if start > region.start {
            push_mmap_region_merged(
                &mut next,
                MmapRegion {
                    start: region.start,
                    len: start - region.start,
                    ..region
                },
            );
        }
        if end < r_end {
            push_mmap_region_merged(
                &mut next,
                MmapRegion {
                    start: end,
                    len: r_end - end,
                    ..region
                },
            );
        }
    }
    *regions = next;
}

fn apply_mprotect_to_mmap_regions(
    regions: &mut alloc::vec::Vec<MmapRegion>,
    start: usize,
    end: usize,
    new_prot: usize,
) -> Result<(), ()> {
    let mut next = alloc::vec::Vec::new();
    for region in regions.iter().copied() {
        let r_end = region.end();
        if end <= region.start || start >= r_end {
            push_mmap_region_merged(&mut next, region);
            continue;
        }
        if start > region.start {
            push_mmap_region_merged(
                &mut next,
                MmapRegion {
                    start: region.start,
                    len: start - region.start,
                    ..region
                },
            );
        }
        let ov_start = core::cmp::max(start, region.start);
        let ov_end = core::cmp::min(end, r_end);
        let mut mid = MmapRegion {
            start: ov_start,
            len: ov_end - ov_start,
            ..region
        };
        if (new_prot & PROT_WRITE) != 0 && (mid.prot & PROT_WRITE) == 0 && !mid.may_write_upgrade {
            return Err(());
        }
        mid.prot = new_prot;
        push_mmap_region_merged(&mut next, mid);
        if end < r_end {
            push_mmap_region_merged(
                &mut next,
                MmapRegion {
                    start: end,
                    len: r_end - end,
                    ..region
                },
            );
        }
    }
    *regions = next;
    Ok(())
}

fn push_range_merged(ranges: &mut alloc::vec::Vec<(usize, usize)>, start: usize, end: usize) {
    if end <= start {
        return;
    }
    if let Some(last) = ranges.last_mut() {
        if start <= last.1 {
            last.1 = last.1.max(end);
            return;
        }
    }
    ranges.push((start, end));
}

fn normalize_ranges(ranges: &mut alloc::vec::Vec<(usize, usize)>) {
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = alloc::vec::Vec::new();
    for (start, end) in ranges.drain(..) {
        push_range_merged(&mut merged, start, end);
    }
    *ranges = merged;
}

fn trim_ranges(ranges: &mut alloc::vec::Vec<(usize, usize)>, start: usize, end: usize) {
    if end <= start {
        return;
    }
    let mut next = alloc::vec::Vec::new();
    for (r_start, r_end) in ranges.drain(..) {
        if end <= r_start || start >= r_end {
            push_range_merged(&mut next, r_start, r_end);
            continue;
        }
        if start > r_start {
            push_range_merged(&mut next, r_start, start);
        }
        if end < r_end {
            push_range_merged(&mut next, end, r_end);
        }
    }
    *ranges = next;
}

fn ranges_total_len(ranges: &[(usize, usize)]) -> usize {
    ranges
        .iter()
        .map(|(start, end)| end.saturating_sub(*start))
        .sum()
}

fn ranges_overlap(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    ranges
        .iter()
        .any(|(r_start, r_end)| end > *r_start && start < *r_end)
}

pub fn syscall_brk(addr: usize) -> isize {
    const BRK_RELATIVE_COMPAT_MAX: usize = 64 * 1024;
    let process = current_process();
    let pid = process.getpid();
    let mut inner = process.borrow_mut();
    if addr == 0 {
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!(
                "[brk] pid={} query brk={:#x} heap_start={:#x}",
                pid,
                inner.brk,
                inner.heap_start
            );
        }
        return inner.brk as isize;
    }
    let mut new_brk = addr;
    if new_brk < inner.heap_start
        && inner.brk == inner.heap_start
        && new_brk <= BRK_RELATIVE_COMPAT_MAX
    {
        // Some musl environments may issue `brk()` with a small positive
        // increment before their internal break base gets initialized.
        // Treat this as a relative grow-from-base request.
        if let Some(candidate) = inner.brk.checked_add(new_brk) {
            if candidate > inner.brk {
                new_brk = candidate;
            }
        }
    }
    if new_brk < inner.heap_start {
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!(
                "[brk] pid={} reject addr={:#x} heap_start={:#x} brk={:#x}",
                pid,
                new_brk,
                inner.heap_start,
                inner.brk
            );
        }
        return inner.brk as isize;
    }
    if new_brk > USER_VA_TOP || align_up(new_brk, PAGE_SIZE) > USER_VA_TOP {
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!(
                "[brk] pid={} reject addr={:#x} above user top={:#x}",
                pid,
                new_brk,
                USER_VA_TOP
            );
        }
        return inner.brk as isize;
    }

    let old_brk = inner.brk;
    let heap_start = inner.heap_start;
    let old_end = align_up(old_brk, PAGE_SIZE);
    let new_end = align_up(new_brk, PAGE_SIZE);
    if crate::debug_config::DEBUG_SYSCALL {
        crate::println!(
            "[brk] pid={} heap_start={:#x} old_brk={:#x} new_brk={:#x} old_end={:#x} new_end={:#x}",
            pid,
            heap_start,
            old_brk,
            new_brk,
            old_end,
            new_end
        );
    }
    let ok = if new_end > old_end {
        if inner
            .memory_set
            .range_overlaps(old_end.into(), new_end.into())
        {
            if crate::debug_config::DEBUG_SYSCALL {
                crate::println!(
                    "[brk] pid={} grow range [{:#x}, {:#x}) overlaps existing mapping",
                    pid,
                    old_end,
                    new_end
                );
            }
            return old_brk as isize;
        }
        let mut ok = inner
            .memory_set
            .append_to(heap_start.into(), new_end.into());
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!("[brk] pid={} append_to ok={}", pid, ok);
        }
        if !ok {
            // fix posssible error that happends in the cloud env
            let perm = MapPermission::R | MapPermission::W | MapPermission::U;
            ok = inner
                .memory_set
                .try_insert_lazy_area(heap_start.into(), new_end.into(), perm);
            if crate::debug_config::DEBUG_SYSCALL {
                crate::println!("[brk] pid={} insert_lazy ok={}", pid, ok);
            }
        }
        ok
    } else if new_end < old_end {
        let ok = inner
            .memory_set
            .shrink_to(heap_start.into(), new_end.into());
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!("[brk] pid={} shrink_to ok={}", pid, ok);
        }
        ok
    } else {
        true
    };
    if !ok {
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!("[brk] pid={} failed, brk stays {:#x}", pid, old_brk);
        }
        return old_brk as isize;
    }
    inner.brk = new_brk;
    if crate::debug_config::DEBUG_SYSCALL {
        crate::println!("[brk] pid={} updated brk={:#x}", pid, inner.brk);
    }
    inner.brk as isize
}

pub fn syscall_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: isize,
    off: usize,
) -> isize {
    let map_type = flags & MAP_TYPE_MASK;
    if map_type != MAP_SHARED && map_type != MAP_PRIVATE && map_type != MAP_SHARED_VALIDATE {
        return EINVAL;
    }
    let is_shared = map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE;
    let is_anon = (flags & MAP_ANONYMOUS) != 0;
    if !is_anon && fd < 0 {
        return EBADF;
    }
    if len == 0 {
        return EINVAL;
    }
    if fd >= 0 && (off % PAGE_SIZE) != 0 {
        return EINVAL;
    }

    let file = if !is_anon {
        let Some(file) = get_fd_file(fd as usize) else {
            return EBADF;
        };
        if !file.readable() {
            return EACCES;
        }
        if is_shared && (prot & PROT_WRITE) != 0 && !file.writable() {
            return EACCES;
        }
        Some(file)
    } else {
        None
    };
    let map_len = align_up(len, PAGE_SIZE);

    let process = current_process();
    let mut inner = process.borrow_mut();

    // A very small `mmap` implementation:
    // - only honor `addr` when `MAP_FIXED` is set;
    // - otherwise treat `addr` as a hint and allocate from `mmap_next`;
    // - never move `mmap_next` backwards (important for glibc/ld.so).
    let is_fixed = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;
    let start = if is_fixed {
        if addr == 0 {
            return EINVAL;
        }
        align_down(addr, PAGE_SIZE)
    } else {
        align_up(inner.mmap_next, PAGE_SIZE)
    };
    let Some(end) = start.checked_add(map_len) else {
        return ENOMEM;
    };
    if !user_range_valid(start, end) {
        return if is_fixed { EINVAL } else { ENOMEM };
    }
    let map_start = start;
    let map_end = end;
    if is_anon && len >= LARGE_ANON_MMAP {
        let pid = process.getpid();
        log::info!(
            "[mmap] pid={} anon len={} map_len={} addr_hint={:#x} start={:#x} prot={:#x} flags={:#x} stack={} fd={} off={:#x}",
            pid,
            len,
            map_len,
            addr,
            map_start,
            prot,
            flags,
            (flags & MAP_STACK) != 0,
            fd,
            off
        );
    }

    let mut perm = MapPermission::U;
    if (prot & PROT_READ) != 0 {
        perm |= MapPermission::R;
    }
    if (prot & PROT_WRITE) != 0 {
        perm |= MapPermission::W;
    }
    if (prot & PROT_EXEC) != 0 {
        perm |= MapPermission::X;
    }

    if (flags & MAP_FIXED_NOREPLACE) != 0 {
        if inner
            .memory_set
            .range_overlaps(map_start.into(), map_end.into())
        {
            return EEXIST;
        }
    }

    if (flags & MAP_FIXED) != 0 {
        // Refuse to map over kernel-only pages (e.g. TrapContext/trampoline).
        let mut cur = start;
        while cur < end {
            let vpn = crate::mm::VirtAddr::from(cur).floor();
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                    return ENOMEM;
                }
            }
            cur += PAGE_SIZE;
        }

        // Linux MAP_FIXED replaces any existing mappings in the range.
        inner.memory_set.unmap_user_range(start.into(), end.into());

        // Keep `mmap_areas` bookkeeping consistent (split/trim overlaps).
        trim_mmap_regions(&mut inner.mmap_areas, start, end);
        trim_ranges(&mut inner.mlocked_ranges, start, end);
    }

    if is_shared {
        let frames = if let Some(file) = &file {
            if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
                let Some(frames) = shm.shared_frames(off, map_len) else {
                    return ENOMEM;
                };
                frames
            } else {
                let pages = map_len / PAGE_SIZE;
                let mut frames = alloc::vec::Vec::with_capacity(pages);
                for _ in 0..pages {
                    let Some(frame) = frame_alloc() else {
                        return ENOMEM;
                    };
                    frames.push(frame);
                }
                frames
            }
        } else {
            let pages = map_len / PAGE_SIZE;
            let mut frames = alloc::vec::Vec::with_capacity(pages);
            for _ in 0..pages {
                let Some(frame) = frame_alloc() else {
                    return ENOMEM;
                };
                frames.push(frame);
            }
            frames
        };
        inner
            .memory_set
            .insert_shared_frames_area(map_start.into(), map_end.into(), perm, frames);
    } else {
        let map_ok = if is_anon {
            inner
                .memory_set
                .try_insert_lazy_area(map_start.into(), map_end.into(), perm)
        } else {
            inner
                .memory_set
                .try_insert_framed_area(map_start.into(), map_end.into(), perm)
        };
        if !map_ok {
            return ENOMEM;
        }
    }
    if !is_fixed && end > inner.mmap_next {
        inner.mmap_next = end;
    }
    let may_write_upgrade = if is_anon {
        true
    } else if is_shared {
        file.as_ref().map(|f| f.writable()).unwrap_or(false)
    } else {
        true
    };
    push_mmap_region_merged(
        &mut inner.mmap_areas,
        MmapRegion {
            start,
            len: map_len,
            prot: prot & (PROT_READ | PROT_WRITE | PROT_EXEC),
            shared: is_shared,
            may_write_upgrade,
        },
    );
    if inner.mlockall_future || (flags & MAP_LOCKED) != 0 {
        inner.mlocked_ranges.push((start, end));
        normalize_ranges(&mut inner.mlocked_ranges);
    }
    drop(inner);

    // Best-effort: file-backed initial population.
    if !is_anon && fd >= 0 {
        if let Some(inode) = get_fd_inode(fd as usize) {
            let _ext4_guard = ext4_lock();
            let token = get_current_token();
            let mut pos = 0usize;
            let mut tmp = [0u8; 512];
            while pos < len {
                let to_read = min(tmp.len(), len - pos);
                let read = inode.read_at(off + pos, &mut tmp[..to_read]);
                if read == 0 {
                    break;
                }
                if try_copy_to_user_unchecked(token, (start + pos) as *mut u8, &tmp[..read])
                    .is_err()
                {
                    return ENOMEM;
                }
                pos += read;
            }
        }
    }

    start as isize
}

pub fn syscall_munmap(addr: usize, len: usize) -> isize {
    if len == 0 {
        return EINVAL;
    }
    if addr % PAGE_SIZE != 0 {
        return EINVAL;
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    let start = addr;
    let Some(end) = start.checked_add(len) else {
        return EINVAL;
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(start, end) {
        return EINVAL;
    }

    inner.memory_set.unmap_user_range(start.into(), end.into());

    // Update `mmap_areas` bookkeeping: remove/split any overlapping entries.
    trim_mmap_regions(&mut inner.mmap_areas, start, end);
    trim_ranges(&mut inner.mlocked_ranges, start, end);
    0
}

/// Linux `msync(2)` (syscall 227).
pub fn syscall_msync(addr: usize, len: usize, flags: usize) -> isize {
    const MS_ASYNC: usize = 1;
    const MS_INVALIDATE: usize = 2;
    const MS_SYNC: usize = 4;

    if (flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC)) != 0 {
        return EINVAL;
    }
    if (flags & MS_ASYNC) != 0 && (flags & MS_SYNC) != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if addr % PAGE_SIZE != 0 {
        return EINVAL;
    }
    let Some(end) = addr.checked_add(len) else {
        return EINVAL;
    };
    if !user_range_valid(addr, align_up(end, PAGE_SIZE)) {
        return ENOMEM;
    }
    0
}

/// Linux `mprotect` (syscall 226).
///
/// Many glibc programs call this during startup to set guard pages / adjust
/// permissions.
pub fn syscall_mprotect(addr: usize, len: usize, prot: usize) -> isize {
    if len == 0 {
        return 0;
    }
    if addr % PAGE_SIZE != 0 {
        return EINVAL;
    }
    let Some(end) = addr.checked_add(len) else {
        return EINVAL;
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(addr, end) {
        return EINVAL;
    }

    let mut perm = MapPermission::U;
    if (prot & PROT_READ) != 0 {
        perm |= MapPermission::R;
    }
    if (prot & PROT_WRITE) != 0 {
        perm |= MapPermission::W;
    }
    if (prot & PROT_EXEC) != 0 {
        perm |= MapPermission::X;
    }

    let process = current_process();
    let mut inner = process.borrow_mut();
    let mut next_regions = inner.mmap_areas.clone();
    if apply_mprotect_to_mmap_regions(&mut next_regions, addr, end, prot).is_err() {
        return EACCES;
    }
    if !inner
        .memory_set
        .mprotect_user_range(addr.into(), end.into(), perm)
    {
        return ENOMEM;
    }
    inner.mmap_areas = next_regions;
    // Ensure permission changes take effect immediately.
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("sfence.vma");
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        core::arch::asm!("invtlb 0x1, $r0, $r0");
    }
    0
}

/// Linux `madvise(2)` (syscall 233 on riscv64).
///
/// This keeps a Linux-like errno matrix for LTP coverage.
pub fn syscall_madvise(addr: usize, len: usize, advice: usize) -> isize {
    if addr % PAGE_SIZE != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let Some(end) = addr.checked_add(len) else {
        return ENOMEM;
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(addr, end) {
        return ENOMEM;
    }

    const MADV_NORMAL: usize = 0;
    const MADV_RANDOM: usize = 1;
    const MADV_SEQUENTIAL: usize = 2;
    const MADV_WILLNEED: usize = 3;
    const MADV_DONTNEED: usize = 4;
    const MADV_FREE: usize = 8;
    const MADV_DONTDUMP: usize = 16;
    const MADV_DODUMP: usize = 17;
    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_DONTNEED | MADV_FREE
        | MADV_DONTDUMP | MADV_DODUMP => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if !inner
                .memory_set
                .user_range_fully_mapped(addr.into(), end.into())
            {
                return ENOMEM;
            }
            if advice == MADV_WILLNEED || advice == MADV_NORMAL {
                return 0;
            }
            if advice == MADV_DONTDUMP || advice == MADV_DODUMP {
                // Core-dump filtering is currently coarse-grained. Accept these
                // hints as no-ops so Linux userspace can proceed.
                return 0;
            }
            if advice == MADV_DONTNEED {
                let shared_overlap = inner
                    .mmap_areas
                    .iter()
                    .any(|region| end > region.start && addr < region.end() && region.shared);
                if shared_overlap || ranges_overlap(&inner.mlocked_ranges, addr, end) {
                    return EINVAL;
                }
            }
            if advice == MADV_FREE {
                let shared_overlap = inner
                    .mmap_areas
                    .iter()
                    .any(|region| end > region.start && addr < region.end() && region.shared);
                if shared_overlap {
                    return EINVAL;
                }
            }
            inner
                .memory_set
                .discard_lazy_user_range(addr.into(), end.into());
            0
        }
        _ => EINVAL,
    }
}

/// Linux `mlock` (syscall 228).
pub fn syscall_mlock(addr: usize, len: usize) -> isize {
    if len == 0 {
        return 0;
    }
    let start = align_down(addr, PAGE_SIZE);
    let Some(end) = addr.checked_add(len) else {
        return ENOMEM;
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(start, end) {
        return ENOMEM;
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    if !inner
        .memory_set
        .user_range_fully_mapped(start.into(), end.into())
    {
        return ENOMEM;
    }
    let mut next = inner.mlocked_ranges.clone();
    next.push((start, end));
    normalize_ranges(&mut next);
    if inner.euid != 0 {
        let limit = inner.rlimit_memlock_cur as usize;
        if limit == 0 {
            return EPERM;
        }
        if ranges_total_len(&next) > limit {
            return ENOMEM;
        }
    }
    inner.mlocked_ranges = next;
    0
}

/// Linux `munlock` (syscall 229).
pub fn syscall_munlock(addr: usize, len: usize) -> isize {
    if len == 0 {
        return 0;
    }
    let start = align_down(addr, PAGE_SIZE);
    let Some(end) = addr.checked_add(len) else {
        return ENOMEM;
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(start, end) {
        return ENOMEM;
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    if !inner
        .memory_set
        .user_range_fully_mapped(start.into(), end.into())
    {
        return ENOMEM;
    }
    trim_ranges(&mut inner.mlocked_ranges, start, end);
    0
}

/// Linux `mlockall` (syscall 230).
pub fn syscall_mlockall(flags: usize) -> isize {
    if (flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) != 0 {
        return EINVAL;
    }
    if (flags & (MCL_CURRENT | MCL_FUTURE)) == 0 {
        return EINVAL;
    }
    if (flags & MCL_ONFAULT) != 0 && (flags & (MCL_CURRENT | MCL_FUTURE)) == 0 {
        return EINVAL;
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    let mut next = inner.mlocked_ranges.clone();
    if (flags & MCL_CURRENT) != 0 {
        for (start, end) in inner.memory_set.user_mapped_ranges() {
            next.push((start, end));
        }
        if next.is_empty() {
            next.push((inner.heap_start, inner.heap_start + PAGE_SIZE));
        }
    }
    normalize_ranges(&mut next);
    if inner.euid != 0 {
        let limit = inner.rlimit_memlock_cur as usize;
        if limit == 0 {
            return EPERM;
        }
        if ranges_total_len(&next) > limit {
            return ENOMEM;
        }
    }
    inner.mlocked_ranges = next;
    inner.mlockall_future = (flags & MCL_FUTURE) != 0;
    0
}

/// Linux `munlockall` (syscall 231).
pub fn syscall_munlockall() -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    inner.mlocked_ranges.clear();
    inner.mlockall_future = false;
    0
}

/// Linux `mincore(2)` (syscall 232).
pub fn syscall_mincore(addr: usize, len: usize, vec: usize) -> isize {
    if addr % PAGE_SIZE != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let Some(end_raw) = addr.checked_add(len) else {
        return ENOMEM;
    };
    let end = align_up(end_raw, PAGE_SIZE);
    if !user_range_valid(addr, end) {
        return ENOMEM;
    }

    let process = current_process();
    let inner = process.borrow_mut();
    if !inner
        .memory_set
        .user_range_fully_mapped(addr.into(), end.into())
    {
        return ENOMEM;
    }
    drop(inner);

    let pages = (end - addr) / PAGE_SIZE;
    let residency = alloc::vec![1u8; pages];
    if try_copy_to_user(get_current_token(), vec as *mut u8, &residency).is_err() {
        return EFAULT;
    }
    0
}
