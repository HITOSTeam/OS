use super::*;

/// Linux `madvise(2)` (syscall 233 on riscv64).
///
/// This keeps a Linux-like errno matrix for LTP coverage.
pub fn syscall_madvise(addr: usize, len: usize, advice: usize) -> isize {
    if addr % PAGE_SIZE != 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    let Some(end) = addr.checked_add(len) else {
        return err(SyscallError::ENOMEM);
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(addr, end) {
        return err(SyscallError::ENOMEM);
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
            let inner = process.borrow_mut();
            let mut memory_set = inner.memory_set.lock();
            if !memory_set.user_range_fully_mapped(addr.into(), end.into()) {
                return err(SyscallError::ENOMEM);
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
                let shared_overlap = memory_set.shared_vm_region_overlaps(addr, end);
                if shared_overlap || memory_set.locked_ranges_overlap(addr, end) {
                    return err(SyscallError::EINVAL);
                }
            }
            if advice == MADV_FREE {
                if !memory_set.vm_range_is_private_anonymous(addr, end) {
                    return err(SyscallError::EINVAL);
                }
                // Linux MADV_FREE is lazy: pages must remain readable until
                // memory pressure reclaims them. We do not have lazy-free
                // reclaim yet, so accepting it as a no-op is closer than
                // immediately discarding pages like MADV_DONTNEED.
                return 0;
            }
            memory_set.discard_madvise_dontneed_range(addr.into(), end.into());
            0
        }
        _ => err(SyscallError::EINVAL),
    }
}

/// Linux `mlock` (syscall 228).
pub fn syscall_mlock(addr: usize, len: usize) -> isize {
    if len == 0 {
        return 0;
    }
    let start = align_down(addr, PAGE_SIZE);
    let Some(end) = addr.checked_add(len) else {
        return err(SyscallError::ENOMEM);
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(start, end) {
        return err(SyscallError::ENOMEM);
    }
    let process = current_process();
    let inner = process.borrow_mut();
    let euid = inner.euid;
    let memlock_limit = inner.rlimits.rlimit_memlock_cur as usize;
    let mut memory_set = inner.memory_set.lock();
    if !memory_set.user_range_fully_mapped(start.into(), end.into()) {
        return err(SyscallError::ENOMEM);
    }
    let mut cur = start;
    while cur < end {
        let vpn = crate::mm::VirtAddr::from(cur).floor();
        let present = memory_set
            .translate(vpn)
            .map(|pte| pte.is_valid())
            .unwrap_or(false);
        if !present {
            match memory_set.resolve_lazy_fault(cur, MapPermission::R) {
                crate::mm::LazyFaultResult::Resolved => {}
                crate::mm::LazyFaultResult::Oom => return err(SyscallError::ENOMEM),
                crate::mm::LazyFaultResult::Invalid => return err(SyscallError::ENOMEM),
            }
        }
        cur += PAGE_SIZE;
    }
    let next_locked_bytes = memory_set.locked_bytes_after_add(start, end);
    if euid != 0 {
        if memlock_limit == 0 {
            return err(SyscallError::EPERM);
        }
        if next_locked_bytes > memlock_limit {
            return err(SyscallError::ENOMEM);
        }
    }
    memory_set.add_locked_range(start, end);
    0
}

/// Linux `munlock` (syscall 229).
pub fn syscall_munlock(addr: usize, len: usize) -> isize {
    if len == 0 {
        return 0;
    }
    let start = align_down(addr, PAGE_SIZE);
    let Some(end) = addr.checked_add(len) else {
        return err(SyscallError::ENOMEM);
    };
    let end = align_up(end, PAGE_SIZE);
    if !user_range_valid(start, end) {
        return err(SyscallError::ENOMEM);
    }
    let process = current_process();
    let inner = process.borrow_mut();
    let mut memory_set = inner.memory_set.lock();
    if !memory_set.user_range_fully_mapped(start.into(), end.into()) {
        return err(SyscallError::ENOMEM);
    }
    memory_set.trim_locked_ranges(start, end);
    0
}

/// Linux `mlockall` (syscall 230).
pub fn syscall_mlockall(flags: usize) -> isize {
    if (flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) != 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & (MCL_CURRENT | MCL_FUTURE)) == 0 {
        return err(SyscallError::EINVAL);
    }
    if (flags & MCL_ONFAULT) != 0 && (flags & (MCL_CURRENT | MCL_FUTURE)) == 0 {
        return err(SyscallError::EINVAL);
    }
    let process = current_process();
    let inner = process.borrow_mut();
    let euid = inner.euid;
    let memlock_limit = inner.rlimits.rlimit_memlock_cur as usize;
    let mut memory_set = inner.memory_set.lock();
    let next_locked_bytes = if (flags & MCL_CURRENT) != 0 {
        memory_set.locked_bytes_after_mlockall_current()
    } else {
        memory_set.locked_bytes()
    };
    if euid != 0 {
        if memlock_limit == 0 {
            return err(SyscallError::EPERM);
        }
        if next_locked_bytes > memlock_limit {
            return err(SyscallError::ENOMEM);
        }
    }
    if (flags & MCL_CURRENT) != 0 {
        memory_set.lock_current_mappings();
    }
    memory_set.set_mlockall_future((flags & MCL_FUTURE) != 0);
    0
}

/// Linux `munlockall` (syscall 231).
pub fn syscall_munlockall() -> isize {
    let process = current_process();
    let inner = process.borrow_mut();
    let mut memory_set = inner.memory_set.lock();
    memory_set.clear_mlock_state();
    0
}

/// Linux `mincore(2)` (syscall 232).
pub fn syscall_mincore(addr: usize, len: usize, vec: usize) -> isize {
    if addr % PAGE_SIZE != 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    let Some(end_raw) = addr.checked_add(len) else {
        return err(SyscallError::ENOMEM);
    };
    let end = align_up(end_raw, PAGE_SIZE);
    if !user_range_valid(addr, end) {
        return err(SyscallError::ENOMEM);
    }

    let process = current_process();
    let inner = process.borrow_mut();
    let memory_set = inner.memory_set.lock();
    if !memory_set.user_range_fully_mapped(addr.into(), end.into()) {
        return err(SyscallError::ENOMEM);
    }

    let pages = (end - addr) / PAGE_SIZE;
    let mut residency = alloc::vec![0u8; pages];
    for (idx, byte) in residency.iter_mut().enumerate() {
        let vpn = crate::mm::VirtAddr::from(addr + idx * PAGE_SIZE).floor();
        if memory_set
            .translate(vpn)
            .map(|pte| pte.is_valid())
            .unwrap_or(false)
        {
            *byte = 1;
        }
    }
    drop(memory_set);
    drop(inner);

    if try_copy_to_user(get_current_token(), vec as *mut u8, &residency).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}
