use crate::{
    config::PAGE_SIZE,
    fs::{File, OSInode, PseudoShmFile, ext4_lock},
    mm::{MapPermission, PTEFlags, frame_alloc, try_copy_to_user_unchecked},
    task::processor::current_process,
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
const MAP_FIXED: usize = 0x10;
const MAP_ANONYMOUS: usize = 0x20;
const MAP_STACK: usize = 0x20000;

const LARGE_ANON_MMAP: usize = 1 * 1024 * 1024;

const EINVAL: isize = -22;
const ENOMEM: isize = -12;

fn align_down(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

fn get_fd_file(fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
    let process = current_process();
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

pub fn syscall_brk(addr: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    if addr == 0 {
        return inner.brk as isize;
    }
    if addr < inner.heap_start {
        return inner.brk as isize;
    }

    let old_brk = inner.brk;
    let new_brk = addr;
    let heap_start = inner.heap_start;
    let old_end = align_up(old_brk, PAGE_SIZE);
    let new_end = align_up(new_brk, PAGE_SIZE);
    let ok = if new_end > old_end {
        let mut ok = inner
            .memory_set
            .append_to(heap_start.into(), new_end.into());
        if !ok {
            // fix posssible error that happends in the cloud env
            let perm = MapPermission::R | MapPermission::W | MapPermission::U;
            ok = inner
                .memory_set
                .try_insert_lazy_area(heap_start.into(), new_end.into(), perm);
        }
        ok
    } else if new_end < old_end {
        inner
            .memory_set
            .shrink_to(heap_start.into(), new_end.into())
    } else {
        true
    };
    if !ok {
        return old_brk as isize;
    }
    inner.brk = new_brk;
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
    if len == 0 {
        return EINVAL;
    }
    if (flags & MAP_SHARED) != 0 && (flags & MAP_PRIVATE) != 0 {
        return EINVAL;
    }
    if fd < 0 && (flags & MAP_ANONYMOUS) == 0 {
        return EINVAL;
    }
    if fd >= 0 && (off % PAGE_SIZE) != 0 {
        return EINVAL;
    }

    let is_shared = (flags & MAP_SHARED) != 0;
    let is_anon = fd < 0 || (flags & MAP_ANONYMOUS) != 0;
    let file = if !is_anon && fd >= 0 {
        get_fd_file(fd as usize)
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
    let start = if (flags & MAP_FIXED) != 0 {
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
        let mut new_areas = alloc::vec::Vec::new();
        for (s, l) in inner.mmap_areas.drain(..) {
            let e = s + l;
            if end <= s || start >= e {
                new_areas.push((s, l));
                continue;
            }
            if start > s {
                new_areas.push((s, start - s));
            }
            if end < e {
                new_areas.push((end, e - end));
            }
        }
        inner.mmap_areas = new_areas;
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
    if end > inner.mmap_next {
        inner.mmap_next = end;
    }
    inner.mmap_areas.push((start, map_len));
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

    inner.memory_set.unmap_user_range(start.into(), end.into());

    // Update `mmap_areas` bookkeeping: remove/split any overlapping entries.
    let mut new_areas = alloc::vec::Vec::new();
    for (s, l) in inner.mmap_areas.drain(..) {
        let e = s + l;
        if end <= s || start >= e {
            new_areas.push((s, l));
            continue;
        }
        if start > s {
            new_areas.push((s, start - s));
        }
        if end < e {
            new_areas.push((end, e - end));
        }
    }
    inner.mmap_areas = new_areas;
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
    if !inner
        .memory_set
        .mprotect_user_range(addr.into(), end.into(), perm)
    {
        return ENOMEM;
    }
    // Ensure permission changes take effect immediately.
    unsafe {
        core::arch::asm!("sfence.vma");
    }
    0
}

/// Linux `mlock` (syscall 228).
///
/// We do not implement page pinning; accept the call so rt-tests can proceed.
pub fn syscall_mlock(_addr: usize, _len: usize) -> isize {
    0
}

/// Linux `munlock` (syscall 229).
pub fn syscall_munlock(_addr: usize, _len: usize) -> isize {
    0
}

/// Linux `mlockall` (syscall 230).
pub fn syscall_mlockall(_flags: usize) -> isize {
    0
}

/// Linux `munlockall` (syscall 231).
pub fn syscall_munlockall() -> isize {
    0
}
