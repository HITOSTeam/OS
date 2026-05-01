use super::*;

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
    if new_brk < inner.heap_start && new_brk <= BRK_RELATIVE_COMPAT_MAX {
        // Some libc builds issue `brk()` with a small positive increment
        // (relative form) instead of an absolute break address.
        // Treat such low values as relative grows from current break.
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
    if new_end > old_end && exceeds_overcommit_limit(new_end.saturating_sub(old_end)) {
        return old_brk as isize;
    }
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
        // Keep legacy Linux behavior used by mmapstress03:
        // brk may grow across mmap holes, but must fail on SysV SHM attachments.
        let perm = MapPermission::R | MapPermission::W | MapPermission::U;
        let mut cur = old_end;
        let mut ok = true;
        while cur < new_end {
            if page_overlaps_sysv_shm_regions(cur, &inner.sysv_shm_attaches) {
                if crate::debug_config::DEBUG_SYSCALL {
                    crate::println!("[brk] pid={} grow blocked by sysv_shm page={:#x}", pid, cur);
                }
                ok = false;
                break;
            }
            if page_overlaps_mmap_regions(cur, &inner.mmap_areas)
                || inner
                    .memory_set
                    .user_range_fully_mapped(cur.into(), (cur + PAGE_SIZE).into())
            {
                cur += PAGE_SIZE;
                continue;
            }
            let run_start = cur;
            cur += PAGE_SIZE;
            while cur < new_end
                && !page_overlaps_sysv_shm_regions(cur, &inner.sysv_shm_attaches)
                && !page_overlaps_mmap_regions(cur, &inner.mmap_areas)
                && !inner
                    .memory_set
                    .user_range_fully_mapped(cur.into(), (cur + PAGE_SIZE).into())
            {
                cur += PAGE_SIZE;
            }
            if !inner
                .memory_set
                .try_insert_lazy_area(run_start.into(), cur.into(), perm)
            {
                ok = false;
                break;
            }
        }
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!("[brk] pid={} grow_with_holes ok={}", pid, ok);
        }
        ok
    } else if new_end < old_end {
        let mut cur = new_end;
        while cur < old_end {
            if !page_overlaps_mmap_regions(cur, &inner.mmap_areas) {
                inner
                    .memory_set
                    .unmap_user_range(cur.into(), (cur + PAGE_SIZE).into());
            }
            cur += PAGE_SIZE;
        }
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!("[brk] pid={} shrink_with_holes done", pid);
        }
        true
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
    const MAP_KNOWN_MASK: usize = MAP_TYPE_MASK
        | MAP_FIXED
        | MAP_ANONYMOUS
        | MAP_GROWSDOWN
        | MAP_LOCKED
        | MAP_STACK
        | MAP_FIXED_NOREPLACE;
    let map_type = flags & MAP_TYPE_MASK;
    if map_type != MAP_SHARED && map_type != MAP_PRIVATE && map_type != MAP_SHARED_VALIDATE {
        return err(SyscallError::EINVAL);
    }
    if map_type == MAP_SHARED_VALIDATE && (flags & !MAP_KNOWN_MASK) != 0 {
        return err(SyscallError::EOPNOTSUPP);
    }
    let is_shared = map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE;
    let is_anon = (flags & MAP_ANONYMOUS) != 0;
    if !is_anon && fd < 0 {
        return err(SyscallError::EBADF);
    }
    if len == 0 {
        return err(SyscallError::EINVAL);
    }
    if fd >= 0 && (off % PAGE_SIZE) != 0 {
        return err(SyscallError::EINVAL);
    }

    let file = if !is_anon {
        let Some(file) = get_fd_file(fd as usize) else {
            return err(SyscallError::EBADF);
        };
        if !file.readable() {
            return err(SyscallError::EACCES);
        }
        if is_shared && (prot & PROT_WRITE) != 0 {
            if !file.writable() {
                return err(SyscallError::EACCES);
            }
            if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
                if shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE) {
                    return err(SyscallError::EPERM);
                }
            }
        }
        Some(file)
    } else {
        None
    };
    let (file_backed, file_dev, file_ino, file_offset) = if let Some(file) = &file {
        if let Some(inode_file) = file.as_any().downcast_ref::<OSInode>() {
            let inode = inode_file.ext4_inode();
            let (dev, ino) = {
                let _ext4_guard = ext4_lock();
                (inode.device_id(), inode.inode_num())
            };
            (true, dev, ino, off)
        } else {
            (false, 0, 0, 0)
        }
    } else {
        (false, 0, 0, 0)
    };
    let map_len = align_up(len, PAGE_SIZE);
    let commit_charge = anon_private_commit_charge(map_len, prot, is_anon, is_shared);
    if exceeds_overcommit_limit(commit_charge) {
        return err(SyscallError::ENOMEM);
    }

    let process = current_process();
    let mut inner = process.borrow_mut();

    // A very small `mmap` implementation:
    // - only honor `addr` when `MAP_FIXED` is set;
    // - otherwise treat `addr` as a hint and allocate from `mmap_next`;
    // - never move `mmap_next` backwards (important for glibc/ld.so).
    let is_fixed = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;
    let start = if is_fixed {
        if addr == 0 {
            return err(SyscallError::EINVAL);
        }
        align_down(addr, PAGE_SIZE)
    } else {
        let preferred = align_up(inner.mmap_next, PAGE_SIZE);
        let fallback = align_up(inner.brk.saturating_add(USER_HEAP_GAP), PAGE_SIZE);
        let mapped = inner.memory_set.user_mapped_ranges();
        if addr != 0 {
            let hinted = align_down(addr, PAGE_SIZE);
            let hinted_end = hinted.checked_add(map_len);
            if let Some(hinted_end) = hinted_end {
                if user_range_valid(hinted, hinted_end)
                    && !inner
                        .memory_set
                        .range_overlaps(hinted.into(), hinted_end.into())
                {
                    hinted
                } else {
                    find_free_user_range(mapped.as_slice(), preferred, map_len)
                        .or_else(|| {
                            (fallback < preferred)
                                .then(|| find_free_user_range(mapped.as_slice(), fallback, map_len))
                                .flatten()
                        })
                        .unwrap_or(USER_VA_TOP)
                }
            } else {
                find_free_user_range(mapped.as_slice(), preferred, map_len)
                    .or_else(|| {
                        (fallback < preferred)
                            .then(|| find_free_user_range(mapped.as_slice(), fallback, map_len))
                            .flatten()
                    })
                    .unwrap_or(USER_VA_TOP)
            }
        } else {
            find_free_user_range(mapped.as_slice(), preferred, map_len)
                .or_else(|| {
                    (fallback < preferred)
                        .then(|| find_free_user_range(mapped.as_slice(), fallback, map_len))
                        .flatten()
                })
                .unwrap_or(USER_VA_TOP)
        }
    };
    let Some(end) = start.checked_add(map_len) else {
        return err(SyscallError::ENOMEM);
    };
    if !user_range_valid(start, end) {
        return if is_fixed {
            err(SyscallError::EINVAL)
        } else {
            err(SyscallError::ENOMEM)
        };
    }
    let map_start = start;
    let map_end = end;
    if is_anon && len >= LARGE_ANON_MMAP {
        let pid = process.getpid();
        crate::println!(
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
            return err(SyscallError::EEXIST);
        }
    }

    // Linux delivers SIGBUS for file-backed accesses that go beyond EOF,
    // starting from the first full page after the file-backed byte range.
    let sigbus_enabled = !is_anon && is_shared;
    let sigbus_start = if sigbus_enabled {
        if let Some(file) = &file {
            if let Some(inode_file) = file.as_any().downcast_ref::<OSInode>() {
                let pending_end = inode_file.pending_write_end();
                let inode = inode_file.ext4_inode();
                let file_size = {
                    let _ext4_guard = ext4_lock();
                    inode.size() as usize
                }
                .max(pending_end);
                let file_bytes = file_size.saturating_sub(off).min(map_len);
                map_start + align_up(file_bytes, PAGE_SIZE).min(map_len)
            } else {
                map_end
            }
        } else {
            map_end
        }
    } else {
        map_end
    };

    if (flags & MAP_FIXED) != 0 {
        // Refuse to map over kernel-only pages (e.g. TrapContext/trampoline).
        let mut cur = start;
        while cur < end {
            let vpn = crate::mm::VirtAddr::from(cur).floor();
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                    return err(SyscallError::ENOMEM);
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
                    return err(SyscallError::ENOMEM);
                };
                frames
            } else {
                let file_mapped_len = sigbus_start.saturating_sub(map_start);
                let pages = file_mapped_len / PAGE_SIZE;
                let mut frames = alloc::vec::Vec::with_capacity(pages);
                for _ in 0..pages {
                    let Some(frame) = frame_alloc() else {
                        return err(SyscallError::ENOMEM);
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
                    return err(SyscallError::ENOMEM);
                };
                frames.push(frame);
            }
            frames
        };
        if map_start < sigbus_start {
            inner.memory_set.insert_shared_frames_area(
                map_start.into(),
                sigbus_start.into(),
                perm,
                frames,
            );
        }
        if sigbus_start < map_end
            && !inner.memory_set.try_insert_lazy_area(
                sigbus_start.into(),
                map_end.into(),
                MapPermission::U,
            )
        {
            inner
                .memory_set
                .unmap_user_range(map_start.into(), map_end.into());
            return err(SyscallError::ENOMEM);
        }
    } else {
        let map_ok = if is_anon {
            inner
                .memory_set
                .try_insert_lazy_area(map_start.into(), map_end.into(), perm)
        } else {
            let mut ok = true;
            if map_start < sigbus_start {
                ok &= inner.memory_set.try_insert_framed_area(
                    map_start.into(),
                    sigbus_start.into(),
                    perm,
                );
            }
            if ok && sigbus_start < map_end {
                ok &= inner.memory_set.try_insert_lazy_area(
                    sigbus_start.into(),
                    map_end.into(),
                    MapPermission::U,
                );
            }
            ok
        };
        if !map_ok {
            inner
                .memory_set
                .unmap_user_range(map_start.into(), map_end.into());
            return err(SyscallError::ENOMEM);
        }
    }
    if !is_fixed && end > inner.mmap_next {
        inner.mmap_next = end;
    }
    let backing_id = if file_backed {
        let id = inner.next_mmap_backing_id;
        inner.next_mmap_backing_id = inner.next_mmap_backing_id.saturating_add(1);
        if let Some(file) = &file {
            inner.mmap_backings.insert(id, Arc::clone(file));
            id
        } else {
            0
        }
    } else {
        0
    };
    let (memfd_id, sealed_write) = if let Some(file) = &file {
        if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
            (
                shm.memfd_id(),
                shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE),
            )
        } else {
            (0, false)
        }
    } else {
        (0, false)
    };
    let may_write_upgrade = if is_anon {
        true
    } else if is_shared {
        file.as_ref()
            .map(|f| f.writable() && !sealed_write)
            .unwrap_or(false)
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
            file_backed,
            file_dev,
            file_ino,
            file_offset,
            backing_id,
            memfd_id,
            growsdown: (flags & MAP_GROWSDOWN) != 0,
            sigbus_start,
        },
    );
    if inner.mlockall_future || (flags & MAP_LOCKED) != 0 {
        inner.mlocked_ranges.push((start, end));
        normalize_ranges(&mut inner.mlocked_ranges);
    }
    drop(inner);

    // Best-effort: file-backed initial population.
    if !is_anon && fd >= 0 {
        if let Some(file) = &file {
            if let Some(inode_file) = file.as_any().downcast_ref::<OSInode>() {
                // Ensure buffered writes are reflected in file-backed mappings.
                let _ = inode_file.flush();
                let token = get_current_token();
                let mut pos = 0usize;
                let mut tmp = [0u8; 512];
                while pos < len {
                    let to_read = min(tmp.len(), len - pos);
                    let read = inode_file.pread_at(off + pos, &mut tmp[..to_read]);
                    if read == 0 {
                        break;
                    }
                    if try_copy_to_user_unchecked(token, (start + pos) as *mut u8, &tmp[..read])
                        .is_err()
                    {
                        return err(SyscallError::ENOMEM);
                    }
                    pos += read;
                }
            }
        }
    }

    start as isize
}

pub fn syscall_mremap(
    old_addr: usize,
    old_size: usize,
    new_size: usize,
    flags: usize,
    new_addr: usize,
) -> isize {
    let supported_flags = MREMAP_MAYMOVE | MREMAP_FIXED;
    if (flags & !supported_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & MREMAP_FIXED) != 0 && (flags & MREMAP_MAYMOVE) == 0 {
        return err(SyscallError::EINVAL);
    }
    if old_size == 0 || new_size == 0 || old_addr % PAGE_SIZE != 0 {
        return err(SyscallError::EINVAL);
    }

    let old_len = align_up(old_size, PAGE_SIZE);
    let new_len = align_up(new_size, PAGE_SIZE);
    let Some(old_end) = old_addr.checked_add(old_len) else {
        return err(SyscallError::EFAULT);
    };
    if !user_range_valid(old_addr, old_end) {
        return err(SyscallError::EFAULT);
    }

    let files_snapshot = current_files().lock().iter_files_snapshot();
    let process = current_process();
    let mut inner = process.borrow_mut();
    if !inner
        .memory_set
        .user_range_fully_mapped(old_addr.into(), old_end.into())
    {
        return err(SyscallError::EFAULT);
    }

    let Some(src_idx) = inner
        .mmap_areas
        .iter()
        .position(|region| old_addr >= region.start && old_end <= region.end())
    else {
        return if (flags & MREMAP_MAYMOVE) == 0 && new_len > old_len {
            err(SyscallError::ENOMEM)
        } else {
            err(SyscallError::EFAULT)
        };
    };
    let src_region = inner.mmap_areas[src_idx];

    if (flags & MREMAP_FIXED) != 0 {
        if new_addr % PAGE_SIZE != 0 {
            return err(SyscallError::EINVAL);
        }
        let Some(new_end) = new_addr.checked_add(new_len) else {
            return err(SyscallError::EINVAL);
        };
        if !user_range_valid(new_addr, new_end) {
            return err(SyscallError::EINVAL);
        }
        if new_len != old_len {
            return err(SyscallError::EINVAL);
        }
        if !(new_end <= old_addr || new_addr >= old_end) {
            return err(SyscallError::EINVAL);
        }
        let mut cur = new_addr;
        while cur < new_end {
            let vpn = crate::mm::VirtAddr::from(cur).floor();
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                    return err(SyscallError::ENOMEM);
                }
            }
            cur += PAGE_SIZE;
        }
        inner
            .memory_set
            .unmap_user_range(new_addr.into(), new_end.into());
        trim_mmap_regions(&mut inner.mmap_areas, new_addr, new_end);
        trim_ranges(&mut inner.mlocked_ranges, new_addr, new_end);
        if !inner
            .memory_set
            .move_user_range(old_addr.into(), old_end.into(), new_addr.into())
        {
            return err(SyscallError::ENOMEM);
        }
        let mut next = Vec::new();
        for region in inner.mmap_areas.drain(..) {
            let r_end = region.end();
            if old_end <= region.start || old_addr >= r_end {
                push_mmap_region_merged(&mut next, region);
                continue;
            }
            if old_addr > region.start {
                push_mmap_region_merged(
                    &mut next,
                    slice_mmap_region(region, region.start, old_addr - region.start),
                );
            }
            let moved = move_mmap_region(slice_mmap_region(region, old_addr, old_len), new_addr);
            push_mmap_region_merged(&mut next, moved);
            if old_end < r_end {
                push_mmap_region_merged(
                    &mut next,
                    slice_mmap_region(region, old_end, r_end - old_end),
                );
            }
        }
        inner.mmap_areas = next;
        return new_addr as isize;
    }

    if new_len <= old_len {
        let shrink_start = old_addr + new_len;
        if shrink_start < old_end {
            inner
                .memory_set
                .unmap_user_range(shrink_start.into(), old_end.into());
            trim_mmap_regions(&mut inner.mmap_areas, shrink_start, old_end);
            trim_ranges(&mut inner.mlocked_ranges, shrink_start, old_end);
        }
        return old_addr as isize;
    }

    let mut target_start = old_addr;
    let mut target_old_end = old_end;
    let mut target_new_end = match old_addr.checked_add(new_len) {
        Some(v) => v,
        None => return err(SyscallError::ENOMEM),
    };
    if !user_range_valid(target_start, target_new_end) {
        return err(SyscallError::ENOMEM);
    }
    if inner
        .memory_set
        .range_overlaps((old_addr + old_len).into(), target_new_end.into())
    {
        if (flags & MREMAP_MAYMOVE) == 0 {
            return err(SyscallError::ENOMEM);
        }
        let preferred = align_up(inner.mmap_next, PAGE_SIZE);
        let fallback = align_up(inner.brk.saturating_add(USER_HEAP_GAP), PAGE_SIZE);
        let mut mapped = inner.memory_set.user_mapped_ranges();
        trim_ranges(&mut mapped, old_addr, old_end);
        let Some(free_start) = find_free_user_range(mapped.as_slice(), preferred, new_len)
            .or_else(|| find_free_user_range(mapped.as_slice(), fallback, new_len))
        else {
            return err(SyscallError::ENOMEM);
        };
        let Some(free_old_end) = free_start.checked_add(old_len) else {
            return err(SyscallError::ENOMEM);
        };
        let Some(free_new_end) = free_start.checked_add(new_len) else {
            return err(SyscallError::ENOMEM);
        };
        if !inner
            .memory_set
            .move_user_range(old_addr.into(), old_end.into(), free_start.into())
        {
            return err(SyscallError::ENOMEM);
        }
        let mut next = Vec::new();
        for region in inner.mmap_areas.drain(..) {
            let r_end = region.end();
            if old_end <= region.start || old_addr >= r_end {
                push_mmap_region_merged(&mut next, region);
                continue;
            }
            if old_addr > region.start {
                push_mmap_region_merged(
                    &mut next,
                    slice_mmap_region(region, region.start, old_addr - region.start),
                );
            }
            let moved = move_mmap_region(slice_mmap_region(region, old_addr, old_len), free_start);
            push_mmap_region_merged(&mut next, moved);
            if old_end < r_end {
                push_mmap_region_merged(
                    &mut next,
                    slice_mmap_region(region, old_end, r_end - old_end),
                );
            }
        }
        inner.mmap_areas = next;
        target_start = free_start;
        target_old_end = free_old_end;
        target_new_end = free_new_end;
    }

    let grow_start = target_old_end;
    let grow_len = new_len - old_len;
    let mut perm = MapPermission::U;
    if (src_region.prot & PROT_READ) != 0 {
        perm |= MapPermission::R;
    }
    if (src_region.prot & PROT_WRITE) != 0 {
        perm |= MapPermission::W;
    }
    if (src_region.prot & PROT_EXEC) != 0 {
        perm |= MapPermission::X;
    }

    let grow_ok = if !src_region.file_backed {
        inner
            .memory_set
            .try_insert_lazy_area(grow_start.into(), target_new_end.into(), perm)
    } else if src_region.shared {
        let Some(file) = inner
            .mmap_backings
            .get(&src_region.backing_id)
            .cloned()
            .or_else(|| {
                find_inode_file_in_snapshot(
                    &files_snapshot,
                    src_region.file_dev,
                    src_region.file_ino,
                )
                .or_else(|| find_open_inode_file(src_region.file_dev, src_region.file_ino))
            })
        else {
            return err(SyscallError::ENOMEM);
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return err(SyscallError::ENOMEM);
        };
        if !inner
            .memory_set
            .try_insert_framed_area(grow_start.into(), target_new_end.into(), perm)
        {
            return err(SyscallError::ENOMEM);
        }
        let token = inner.memory_set.token();
        let mut pos = 0usize;
        let mut tmp = [0u8; 512];
        while pos < grow_len {
            let to_read = min(tmp.len(), grow_len - pos);
            let read =
                os_inode.pread_at(src_region.file_offset + old_len + pos, &mut tmp[..to_read]);
            if read == 0 {
                break;
            }
            if try_copy_to_user_unchecked(token, (grow_start + pos) as *mut u8, &tmp[..read])
                .is_err()
            {
                return err(SyscallError::ENOMEM);
            }
            pos += read;
        }
        true
    } else {
        inner
            .memory_set
            .try_insert_framed_area(grow_start.into(), target_new_end.into(), perm)
    };
    if !grow_ok {
        return err(SyscallError::ENOMEM);
    }

    if let Some(region) = inner
        .mmap_areas
        .iter_mut()
        .find(|region| region.start == target_start)
    {
        region.len = new_len;
    }
    if target_new_end > inner.mmap_next {
        inner.mmap_next = target_new_end;
    }
    target_start as isize
}
