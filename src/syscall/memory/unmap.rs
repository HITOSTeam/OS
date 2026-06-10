use super::*;

pub fn syscall_munmap(addr: usize, len: usize) -> isize {
    if len == 0 {
        return err(SyscallError::EINVAL);
    }
    if addr % PAGE_SIZE != 0 {
        return err(SyscallError::EINVAL);
    }
    let process = current_process();
    let inner = process.borrow_mut();
    let start = addr;
    let Some(end) = start.checked_add(len) else {
        return err(SyscallError::EINVAL);
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(start, end) {
        return err(SyscallError::EINVAL);
    }

    let mut memory_set = inner.memory_set.lock();
    if memory_set
        .writeback_shared_file_mmap_range(start, end, false)
        .is_err()
    {
        return err(SyscallError::EIO);
    }
    memory_set.unmap_user_vma_range(start.into(), end.into());
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
    let inner = process.borrow_mut();
    let cleared_dirty = {
        let mut memory_set = inner.memory_set.lock();
        if !memory_set.user_range_fully_mapped(addr.into(), end.into()) {
            return err(SyscallError::ENOMEM);
        }
        if (flags & MS_INVALIDATE) != 0 && memory_set.locked_ranges_overlap(addr, end) {
            return err(SyscallError::EBUSY);
        }
        match memory_set.writeback_shared_file_mmap_range(addr, end, true) {
            Ok(cleared_dirty) => cleared_dirty,
            Err(()) => return err(SyscallError::EIO),
        }
    };
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

    let process = current_process();
    let inner = process.borrow_mut();
    {
        let mut memory_set = inner.memory_set.lock();
        match memory_set.mprotect_user_vma_range(addr.into(), end.into(), prot) {
            Ok(()) => {}
            Err(MprotectError::AccessDenied) => return err(SyscallError::EACCES),
            Err(MprotectError::Unmapped) => return err(SyscallError::ENOMEM),
        }
    }
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
