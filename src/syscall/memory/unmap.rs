use super::*;

pub fn syscall_munmap(addr: usize, len: usize) -> isize {
    if len == 0 {
        return err(SyscallError::EINVAL);
    }
    if addr % PAGE_SIZE != 0 {
        return err(SyscallError::EINVAL);
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    let start = addr;
    let Some(end) = start.checked_add(len) else {
        return err(SyscallError::EINVAL);
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(start, end) {
        return err(SyscallError::EINVAL);
    }

    let overlaps = inner
        .mmap_areas
        .iter()
        .copied()
        .filter(|region| {
            region.shared && region.file_backed && end > region.start && start < region.end()
        })
        .collect::<Vec<_>>();
    for region in overlaps {
        let Some(file) = inner
            .mmap_backings
            .get(&region.backing_id)
            .cloned()
            .or_else(|| {
                find_inode_file_in_fd_table(&inner.fd_table, region.file_dev, region.file_ino)
                    .or_else(|| find_open_inode_file(region.file_dev, region.file_ino))
            })
        else {
            continue;
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            continue;
        };
        let seg_start = core::cmp::max(start, region.start);
        let seg_end = core::cmp::min(end, region.end());
        let mut cur = align_down(seg_start, PAGE_SIZE);
        while cur < seg_end {
            let vpn = crate::mm::VirtAddr::from(cur).floor();
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if pte.is_valid() {
                    let page = pte.ppn().get_bytes_array();
                    let page_start = cur;
                    let copy_start = core::cmp::max(seg_start, page_start);
                    let copy_end = core::cmp::min(seg_end, page_start + PAGE_SIZE);
                    if copy_end > copy_start {
                        let off_in_page = copy_start - page_start;
                        let file_off = region.file_offset + (copy_start - region.start);
                        if os_inode
                            .pwrite_at(
                                file_off,
                                &page[off_in_page..off_in_page + (copy_end - copy_start)],
                            )
                            .is_err()
                        {
                            return err(SyscallError::EIO);
                        }
                    }
                }
            }
            cur = cur.saturating_add(PAGE_SIZE);
        }
        if os_inode.flush().is_err() {
            return err(SyscallError::EIO);
        }
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
        return err(SyscallError::EINVAL);
    }
    if (flags & MS_ASYNC) != 0 && (flags & MS_SYNC) != 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    if addr % PAGE_SIZE != 0 {
        return err(SyscallError::EINVAL);
    }
    let Some(end_raw) = addr.checked_add(len) else {
        return err(SyscallError::EINVAL);
    };
    let end = align_up(end_raw, PAGE_SIZE);
    if !user_range_valid(addr, end) {
        return err(SyscallError::EINVAL);
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    if !inner
        .memory_set
        .user_range_fully_mapped(addr.into(), end.into())
    {
        return err(SyscallError::ENOMEM);
    }
    if (flags & MS_INVALIDATE) != 0 && ranges_overlap(&inner.mlocked_ranges, addr, end) {
        return err(SyscallError::EBUSY);
    }
    let overlaps = inner
        .mmap_areas
        .iter()
        .copied()
        .filter(|region| {
            region.shared && region.file_backed && end > region.start && addr < region.end()
        })
        .collect::<Vec<_>>();
    let mut cleared_dirty = false;
    for region in overlaps {
        let Some(file) = inner
            .mmap_backings
            .get(&region.backing_id)
            .cloned()
            .or_else(|| {
                find_inode_file_in_fd_table(&inner.fd_table, region.file_dev, region.file_ino)
                    .or_else(|| find_open_inode_file(region.file_dev, region.file_ino))
            })
        else {
            continue;
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            continue;
        };
        let seg_start = core::cmp::max(addr, region.start);
        let seg_end = core::cmp::min(end, region.end());
        let mut cur = align_down(seg_start, PAGE_SIZE);
        while cur < seg_end {
            let vpn = crate::mm::VirtAddr::from(cur).floor();
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if pte.is_valid() {
                    let page = pte.ppn().get_bytes_array();
                    let page_start = cur;
                    let copy_start = core::cmp::max(seg_start, page_start);
                    let copy_end = core::cmp::min(seg_end, page_start + PAGE_SIZE);
                    if copy_end > copy_start {
                        let off_in_page = copy_start - page_start;
                        let file_off = region.file_offset + (copy_start - region.start);
                        if os_inode
                            .pwrite_at(
                                file_off,
                                &page[off_in_page..off_in_page + (copy_end - copy_start)],
                            )
                            .is_err()
                        {
                            return err(SyscallError::EIO);
                        }
                    }
                }
            }
            cur = cur.saturating_add(PAGE_SIZE);
        }
        if os_inode.flush().is_err() {
            return err(SyscallError::EIO);
        }
        let mut cur = align_down(seg_start, PAGE_SIZE);
        while cur < seg_end {
            let vpn = crate::mm::VirtAddr::from(cur).floor();
            if let Some(pte) = inner.memory_set.translate(vpn) {
                if pte.is_valid() && pte.flags().contains(PTEFlags::D) {
                    let mut flags = pte.flags();
                    flags.remove(PTEFlags::D);
                    if inner.memory_set.set_pte_flags(vpn, flags) {
                        cleared_dirty = true;
                    }
                }
            }
            cur = cur.saturating_add(PAGE_SIZE);
        }
    }
    if cleared_dirty {
        #[cfg(target_arch = "riscv64")]
        // SAFETY: sfence.vma is a privileged instruction valid in S-mode; flushes TLB.
        unsafe {
            core::arch::asm!("sfence.vma");
        }
        #[cfg(target_arch = "loongarch64")]
        // SAFETY: invtlb is a privileged instruction valid in S-mode; flushes TLB.
        unsafe {
            core::arch::asm!("invtlb 0x1, $r0, $r0");
        }
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
        return err(SyscallError::EINVAL);
    }
    let Some(end) = addr.checked_add(len) else {
        return err(SyscallError::EINVAL);
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(addr, end) {
        return err(SyscallError::EINVAL);
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
        return err(SyscallError::EACCES);
    }
    if !inner
        .memory_set
        .mprotect_user_range(addr.into(), end.into(), perm)
    {
        return err(SyscallError::ENOMEM);
    }
    inner.mmap_areas = next_regions;
    // Ensure permission changes take effect immediately.
    #[cfg(target_arch = "riscv64")]
    // SAFETY: sfence.vma is a privileged instruction valid in S-mode; flushes TLB.
    unsafe {
        core::arch::asm!("sfence.vma");
    }
    #[cfg(target_arch = "loongarch64")]
    // SAFETY: invtlb is a privileged instruction valid in S-mode; flushes TLB.
    unsafe {
        core::arch::asm!("invtlb 0x1, $r0, $r0");
    }
    0
}
