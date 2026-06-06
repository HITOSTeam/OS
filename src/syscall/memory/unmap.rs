use super::*;

pub fn syscall_munmap(addr: usize, len: usize) -> isize {
    if len == 0 {
        return err(SyscallError::EINVAL);
    }
    if addr % PAGE_SIZE != 0 {
        return err(SyscallError::EINVAL);
    }
    let files_snapshot = current_files().lock().iter_files_snapshot();
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
        .memory_set
        .shared_file_vm_regions_overlapping(start, end);
    for region in overlaps {
        let Some(file) = inner
            .memory_set
            .mmap_backing_file(region.backing_id)
            .or_else(|| {
                find_inode_file_in_snapshot(&files_snapshot, region.file_dev, region.file_ino)
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

    // Update `vm_regions` bookkeeping: remove/split any overlapping entries.
    inner.memory_set.trim_vm_regions(start, end);
    inner.memory_set.trim_locked_ranges(start, end);
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
    let files_snapshot = current_files().lock().iter_files_snapshot();
    let process = current_process();
    let mut inner = process.borrow_mut();
    if !inner
        .memory_set
        .user_range_fully_mapped(addr.into(), end.into())
    {
        return err(SyscallError::ENOMEM);
    }
    if (flags & MS_INVALIDATE) != 0 && inner.memory_set.locked_ranges_overlap(addr, end) {
        return err(SyscallError::EBUSY);
    }
    let overlaps = inner
        .memory_set
        .shared_file_vm_regions_overlapping(addr, end);
    let mut cleared_dirty = false;
    for region in overlaps {
        let Some(file) = inner
            .memory_set
            .mmap_backing_file(region.backing_id)
            .or_else(|| {
                find_inode_file_in_snapshot(&files_snapshot, region.file_dev, region.file_ino)
                    .or_else(|| find_open_inode_file(region.file_dev, region.file_ino))
            })
        else {
            continue;
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            continue;
        };
        let seg_start = core::cmp::max(addr, region.start);
        let valid_end = region
            .start
            .saturating_add(region.file_valid_len.min(region.len));
        let seg_end = core::cmp::min(core::cmp::min(end, region.end()), valid_end);
        if seg_end <= seg_start {
            continue;
        }
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

    let perm = VmRegion::permission_from_prot(prot);

    let process = current_process();
    let mut inner = process.borrow_mut();
    if !inner.memory_set.can_mprotect_vm_regions(addr, end, prot) {
        return err(SyscallError::EACCES);
    }
    if !inner
        .memory_set
        .mprotect_user_range(addr.into(), end.into(), perm)
    {
        return err(SyscallError::ENOMEM);
    }
    let _ = inner
        .memory_set
        .apply_mprotect_to_vm_regions(addr, end, prot);
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
