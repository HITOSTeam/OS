use super::*;
use crate::fs::{PseudoFile, PseudoKindTag};
use crate::syscall::sysv_shm::{
    detach_attaches_overlapping, find_attach_containing, release_detached_attach_refs,
    segment_shared_frames_existing, segment_size, split_mremap_attach,
};
use alloc::vec;

pub fn syscall_brk(addr: usize) -> isize {
    const BRK_RELATIVE_COMPAT_MAX: usize = 64 * 1024;
    let process = current_process();
    let pid = process.getpid();
    let inner = process.borrow_mut();
    if addr == 0 {
        let memory_set = inner.memory_set.lock();
        let brk = memory_set.brk();
        let heap_start = memory_set.heap_start();
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!(
                "[brk] pid={} query brk={:#x} heap_start={:#x}",
                pid,
                brk,
                heap_start
            );
        }
        return brk as isize;
    }
    let mut memory_set = inner.memory_set.lock();
    let shm_attaches = memory_set.sysv_shm_attaches_snapshot();
    let update: BrkUpdate = memory_set.try_update_brk_with_holes(
        addr,
        USER_VA_TOP,
        BRK_RELATIVE_COMPAT_MAX,
        |page| page_overlaps_sysv_shm_regions(page, &shm_attaches),
        exceeds_overcommit_limit,
    );
    if crate::debug_config::DEBUG_SYSCALL {
        crate::println!(
            "[brk] pid={} heap_start={:#x} old_brk={:#x} new_brk={:#x} old_end={:#x} new_end={:#x}",
            pid,
            update.heap_start,
            update.old_brk,
            update.new_brk,
            update.old_end,
            update.new_end
        );
    }
    if !update.success {
        if crate::debug_config::DEBUG_SYSCALL {
            crate::println!("[brk] pid={} failed, brk stays {:#x}", pid, update.old_brk);
        }
        return update.old_brk as isize;
    }
    if crate::debug_config::DEBUG_SYSCALL {
        crate::println!("[brk] pid={} updated brk={:#x}", pid, update.new_brk);
    }
    update.result_brk() as isize
}

/// 使用 文件 填充 mmap 地方的内容
fn populate_file_mapping(
    memory_set: &mut MemorySet,
    file: &Arc<dyn File + Send + Sync>,
    start: usize,
    len: usize,
    off: usize,
) -> bool {
    let Some(inode_file) = file.as_any().downcast_ref::<OSInode>() else {
        return true;
    };
    // Ensure buffered writes are reflected in file-backed mappings.
    let _ = inode_file.flush();
    let token = memory_set.token();
    let mut pos = 0usize;
    let mut tmp = [0u8; 512];
    while pos < len {
        let to_read = min(tmp.len(), len - pos);
        let read = inode_file.pread_at(off + pos, &mut tmp[..to_read]);
        if read == 0 {
            break;
        }
        if try_copy_to_user_unchecked(token, (start + pos) as *mut u8, &tmp[..read]).is_err() {
            return false;
        }
        pos += read;
    }
    true
}

#[derive(Clone, Copy)]
enum MmapSource<'a> {
    Anonymous,
    RegularFile {
        inode_file: &'a OSInode,
        dev: usize,
        ino: u32,
    },
    Shm {
        shm: &'a PseudoShmFile,
        memfd_id: u64,
        sealed_write: bool,
    },
    DevZero,
}

impl MmapSource<'_> {
    // 对于不同文件类型，进行长度的转换
    fn file_valid_len(self, off: usize, map_len: usize) -> usize {
        match self {
            Self::Anonymous | Self::DevZero => map_len,
            Self::RegularFile { inode_file, .. } => {
                let pending_end = inode_file.pending_write_end();
                let inode = inode_file.ext4_inode();
                let file_size = {
                    let _ext4_guard = ext4_lock();
                    inode.size() as usize
                }
                .max(pending_end);
                file_size.saturating_sub(off).min(map_len)
            }
            Self::Shm { shm, .. } => shm.len().saturating_sub(off).min(map_len),
        }
    }

    // 文件长度 是否有超出 的可能性
    fn has_sigbus_tail(self) -> bool {
        matches!(self, Self::RegularFile { .. } | Self::Shm { .. })
    }
}

// 根据 mmap source 和共享属性构造需要插入的 VMA 。
// 返回vec的原因是私有文件映射 超出部分 也需要
fn build_vma_areas(
    source: MmapSource<'_>,
    is_shared: bool,
    map_start: usize,
    map_end: usize,
    sigbus_start: usize,
    off: usize,
) -> Result<Vec<VmaInsertArea>, isize> {
    let mut areas = Vec::new();
    match (is_shared, source) {
        (true, MmapSource::RegularFile { .. }) => {
            // 普通文件 MAP_SHARED 走 lazy fault + shared file cache。
            if map_start < sigbus_start {
                areas.push(VmaInsertArea::Lazy {
                    start: map_start,
                    end: sigbus_start,
                });
            }
        }
        (true, MmapSource::Shm { shm, .. }) => {
            let file_mapped_len = sigbus_start.saturating_sub(map_start);
            let Some(frames) = shm.shared_frames_existing(off, file_mapped_len) else {
                return Err(err(SyscallError::ENOMEM));
            };
            if map_start < sigbus_start {
                areas.push(VmaInsertArea::SharedFrames {
                    start: map_start,
                    end: sigbus_start,
                    frames,
                });
            } else if !frames.is_empty() {
                return Err(err(SyscallError::ENOMEM));
            }
        }
        (true, MmapSource::Anonymous | MmapSource::DevZero) => {
            // Linux 的共享匿名 mmap 只建立 VMA；页在 fault 时分配并按 VMA 身份共享。
            areas.push(VmaInsertArea::Lazy {
                start: map_start,
                end: map_end,
            });
        }
        (false, MmapSource::Anonymous | MmapSource::DevZero) => {
            areas.push(VmaInsertArea::Lazy {
                start: map_start,
                end: map_end,
            });
        }
        (false, MmapSource::RegularFile { .. } | MmapSource::Shm { .. }) => {
            if map_start < sigbus_start {
                areas.push(VmaInsertArea::Framed {
                    start: map_start,
                    end: sigbus_start,
                });
            }
            if sigbus_start < map_end {
                areas.push(VmaInsertArea::Lazy {
                    start: sigbus_start,
                    end: map_end,
                });
            }
        }
    }
    if is_shared && sigbus_start < map_end {
        areas.push(VmaInsertArea::Lazy {
            start: sigbus_start,
            end: map_end,
        });
    }
    Ok(areas)
}

// 执行 VMA 记录 的插入 或者 替换
fn commit_mmap_vma(
    memory_set: &mut MemorySet,
    replace: bool,
    region: VmRegion,
    areas: Vec<VmaInsertArea>,
    lock_range: bool,
    backing_file: Option<&Arc<dyn File + Send + Sync>>,
    populate_file: Option<&Arc<dyn File + Send + Sync>>,
    start: usize,
    len: usize,
    off: usize,
) -> bool {
    match (replace, populate_file) {
        (true, Some(file)) => memory_set.try_replace_user_vma_with(
            region,
            areas,
            lock_range,
            backing_file,
            |memory_set| populate_file_mapping(memory_set, file, start, len, off),
        ),
        (true, None) => memory_set.try_replace_user_vma(region, areas, lock_range, backing_file),
        (false, Some(file)) => memory_set.try_insert_user_vma_with(
            region,
            areas,
            lock_range,
            backing_file,
            |memory_set| populate_file_mapping(memory_set, file, start, len, off),
        ),
        (false, None) => memory_set.try_insert_user_vma(region, areas, lock_range, backing_file),
    }
}

fn mmap_packet_socket_ring(
    packet_sock: &crate::syscall::net::PacketSocketFile,
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    off: usize,
) -> isize {
    if off != 0 || (prot & PROT_WRITE) == 0 {
        return err(SyscallError::EINVAL);
    }
    let map_type = flags & MAP_TYPE_MASK;
    if map_type != MAP_SHARED && map_type != MAP_SHARED_VALIDATE {
        return err(SyscallError::EINVAL);
    }
    let Some(ring_len) = packet_sock.rx_ring_mmap_len() else {
        return err(SyscallError::EINVAL);
    };
    let map_len = align_up(len, PAGE_SIZE);
    // Linux packet_mmap() requires the VMA size to match the total configured
    // packet ring size exactly; accepting a larger mapping would expose pages
    // that are not owned by the ring ABI.
    if map_len != ring_len {
        return err(SyscallError::EINVAL);
    }

    let process = current_process();
    let inner = process.borrow_mut();
    let is_fixed = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;
    let start = if is_fixed {
        if addr == 0 || addr % PAGE_SIZE != 0 {
            return err(SyscallError::EINVAL);
        }
        addr
    } else {
        let mut memory_set = inner.memory_set.lock();
        let Some(start) =
            memory_set.find_free_mmap_range((addr != 0).then_some(addr), map_len, USER_VA_TOP)
        else {
            return err(SyscallError::ENOMEM);
        };
        start
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

    let lock_range = {
        let memory_set = inner.memory_set.lock();
        if !is_fixed && !memory_set.user_range_is_free(start, end, USER_VA_TOP) {
            return err(SyscallError::ENOMEM);
        }
        if (flags & MAP_FIXED_NOREPLACE) != 0
            && !memory_set.user_range_is_free(start, end, USER_VA_TOP)
        {
            return err(SyscallError::EEXIST);
        }
        if (flags & MAP_FIXED) != 0 {
            let mut cur = start;
            while cur < end {
                let vpn = crate::mm::VirtAddr::from(cur).floor();
                if let Some(pte) = memory_set.translate(vpn) {
                    if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                        return err(SyscallError::ENOMEM);
                    }
                }
                cur += PAGE_SIZE;
            }
        }
        memory_set.mlockall_future() || (flags & MAP_LOCKED) != 0
    };

    let region = VmRegion {
        kind: VmRegionKind::Mmap,
        start,
        len: map_len,
        prot: prot & (PROT_READ | PROT_WRITE | PROT_EXEC),
        map_type: MapType::Framed,
        map_perm: VmRegion::permission_from_prot(prot),
        file_valid_len: map_len,
        sigbus_start: end,
        shared: true,
        may_write_upgrade: true,
        file_backed: false,
        file_dev: 0,
        file_ino: 0,
        file_offset: 0,
        backing_id: 0,
        memfd_id: 0,
        anon_shared_id: crate::mm::allocate_shared_anon_id(),
        sysv_shmid: 0,
        growsdown: false,
        fork_inherited_anon: false,
    };
    let areas = vec![VmaInsertArea::Framed { start, end }];
    let replace_existing = (flags & MAP_FIXED) != 0;
    let mut memory_set = inner.memory_set.lock();
    let inserted = commit_mmap_vma(
        &mut memory_set,
        replace_existing,
        region,
        areas,
        lock_range,
        None,
        None,
        start,
        len,
        off,
    );
    if !inserted {
        return err(SyscallError::ENOMEM);
    }
    if !replace_existing {
        memory_set.note_mmap_end(end);
    }
    let token = memory_set.token();
    drop(memory_set);
    drop(inner);

    if replace_existing {
        crate::syscall::net::clear_packet_ring_mmaps_for_range(token, start, end);
    }
    let ret = packet_sock.set_rx_ring_mmap(start, map_len, token);
    if ret < 0 {
        let process = current_process();
        let inner = process.borrow_mut();
        inner
            .memory_set
            .lock()
            .unmap_user_vma_range(start.into(), end.into());
        return ret;
    }
    start as isize
}

pub fn syscall_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: isize,
    off: usize,
) -> isize {
    // mmap 入口只解析用户参数并构造 VmRegion/VmaInsertArea。
    // 真正的插入、替换、回滚交给 MemorySet 统一处理。
    //
    // 1.flags检查,flags必须是以下可知类型
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
    // 是否为共享 mmap
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

    // 非匿名映射，那么读取对应的文件
    let file = if !is_anon {
        let Some(file) = current_files().lock().get_file(fd as usize) else {
            return err(SyscallError::EBADF);
        };
        if !file.readable() {
            return err(SyscallError::EACCES);
        }
        if is_shared && (prot & PROT_WRITE) != 0 {
            // 文件可写性检查
            // 普通文件 与 shmfile
            if !file.writable() {
                return err(SyscallError::EACCES);
            }
        }
        Some(file)
    } else {
        None
    };
    if let Some(file) = file.as_ref()
        && let Some(packet_sock) = file
            .as_any()
            .downcast_ref::<crate::syscall::net::PacketSocketFile>()
    {
        return mmap_packet_socket_ring(packet_sock, addr, len, prot, flags, off);
    }
    // 像 Linux can_mmap_file() 一样先显式确认 fd 类型；未知文件不能 fallback 成零页。
    let source = if is_anon {
        MmapSource::Anonymous
    } else {
        let file = file.as_ref().expect("non-anonymous mmap has file");
        if let Some(inode_file) = file.as_any().downcast_ref::<OSInode>() {
            let inode = inode_file.ext4_inode();
            let (dev, ino) = {
                let _ext4_guard = ext4_lock();
                (inode.device_id(), inode.inode_num())
            };
            MmapSource::RegularFile {
                inode_file,
                dev,
                ino,
            }
        } else if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
            MmapSource::Shm {
                shm,
                memfd_id: shm.memfd_id(),
                sealed_write: shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE),
            }
        } else if file
            .as_any()
            .downcast_ref::<PseudoFile>()
            .is_some_and(|pseudo| pseudo.kind_tag() == PseudoKindTag::Zero)
        {
            MmapSource::DevZero
        } else {
            return err(SyscallError::ENODEV);
        }
    };
    let (file_backed, file_dev, file_ino) = match source {
        MmapSource::RegularFile { dev, ino, .. } => (true, dev, ino),
        _ => (false, 0, 0),
    };
    let file_offset = match source {
        MmapSource::Anonymous => 0,
        _ => off,
    };
    if is_shared && (prot & PROT_WRITE) != 0 {
        if let MmapSource::Shm { sealed_write, .. } = source {
            if sealed_write {
                return err(SyscallError::EPERM);
            }
        }
    }
    let shared_inode_backed = is_shared && matches!(source, MmapSource::RegularFile { .. });
    let shared_anon_backed =
        is_shared && matches!(source, MmapSource::Anonymous | MmapSource::DevZero);
    // 对齐len
    let map_len = align_up(len, PAGE_SIZE);
    // 私有匿名和 /dev/zero 私有映射都可能在写 fault 时分配私有页。
    let private_zero_source = is_anon || matches!(source, MmapSource::DevZero);
    let commit_charge = if private_zero_source && !is_shared && (prot & PROT_WRITE) != 0 {
        map_len
    } else {
        0
    };
    // 检查是否超出限制
    if exceeds_overcommit_limit(commit_charge) {
        return err(SyscallError::ENOMEM);
    }

    let process = current_process();
    let inner = process.borrow_mut();

    // 非 MAP_FIXED 时 addr 仅作为地址建议；MemorySet 会从高地址向下找空闲区间，
    // 找不到时回退到 brk 附近的低地址（与 Linux 行为一致）。
    let is_fixed = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;
    let start = if is_fixed {
        if addr == 0 || addr % PAGE_SIZE != 0 {
            return err(SyscallError::EINVAL);
        }
        addr
    } else {
        let mut memory_set = inner.memory_set.lock();
        let Some(start) =
            memory_set.find_free_mmap_range((addr != 0).then_some(addr), map_len, USER_VA_TOP)
        else {
            return err(SyscallError::ENOMEM);
        };
        start
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
    let perm = VmRegion::permission_from_prot(prot);
    // 是否锁定 对应区间,目前还没有swap 实现(TODO)
    let lock_range = {
        let memory_set = inner.memory_set.lock();
        // 非 MAP_FIXED 时目标区间必须在两套数据结构中均空闲，vma 以及 真实数据映射
        if !is_fixed && !memory_set.user_range_is_free(map_start, map_end, USER_VA_TOP) {
            return err(SyscallError::ENOMEM);
        }
        if (flags & MAP_FIXED_NOREPLACE) != 0 {
            // MAP_FIXED_NOREPLACE：目标区间与任何已有映射冲突时必须返回 EEXIST，而不是重新选址。
            if !memory_set.user_range_is_free(map_start, map_end, USER_VA_TOP) {
                return err(SyscallError::EEXIST);
            }
        }
        // FIXED允许覆盖,但
        // 禁止覆盖内核专用页（如 TrapContext/trampoline），这些页的 PTE 不含 U 位。
        if (flags & MAP_FIXED) != 0 {
            let mut cur = start;
            while cur < end {
                let vpn = crate::mm::VirtAddr::from(cur).floor();
                if let Some(pte) = memory_set.translate(vpn) {
                    if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                        return err(SyscallError::ENOMEM);
                    }
                }
                cur += PAGE_SIZE;
            }
        }
        memory_set.mlockall_future() || (flags & MAP_LOCKED) != 0
    };
    if crate::debug_config::DEBUG_SYSCALL && is_anon && len >= LARGE_ANON_MMAP {
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

    // 文件长度由显式 source 决定；/dev/zero 按无限零源处理，不产生 SIGBUS 尾区。
    let file_valid_len = source.file_valid_len(off, map_len);
    // 文件映射中超出文件末尾的访问会触发 SIGBUS，从文件有效范围之后的第一个完整页开始。
    let sigbus_start = if source.has_sigbus_tail() {
        map_start + align_up(file_valid_len, PAGE_SIZE).min(map_len)
    } else {
        map_end
    };

    let vma_areas = match build_vma_areas(source, is_shared, map_start, map_end, sigbus_start, off)
    {
        Ok(areas) => areas,
        Err(e) => return e,
    };
    let (memfd_id, sealed_write) = match source {
        MmapSource::Shm {
            memfd_id,
            sealed_write,
            ..
        } => (memfd_id, sealed_write),
        _ => (0, false),
    };
    let anon_shared_id = if shared_anon_backed {
        crate::mm::allocate_shared_anon_id()
    } else {
        0
    };
    let may_write_upgrade = if is_anon {
        true
    } else if matches!(source, MmapSource::DevZero) {
        !is_shared || file.as_ref().is_some_and(|f| f.writable())
    } else if is_shared {
        file.as_ref()
            .map(|f| f.writable() && !sealed_write)
            .unwrap_or(false)
    } else {
        true
    };
    // VmRegion 是 syscall 可见语义的权威记录，fault/mprotect/msync 都应回到这里取策略。
    let region = VmRegion {
        kind: VmRegionKind::Mmap,
        start,
        len: map_len,
        prot: prot & (PROT_READ | PROT_WRITE | PROT_EXEC),
        map_type: match (is_shared, source) {
            (true, MmapSource::RegularFile { .. })
            | (true, MmapSource::Anonymous | MmapSource::DevZero)
            | (false, MmapSource::Anonymous | MmapSource::DevZero) => MapType::Lazy,
            (true, MmapSource::Shm { .. })
            | (false, MmapSource::RegularFile { .. })
            | (false, MmapSource::Shm { .. }) => MapType::Framed,
        },
        map_perm: perm,
        file_valid_len,
        sigbus_start,
        shared: is_shared,
        may_write_upgrade,
        file_backed,
        file_dev,
        file_ino,
        file_offset,
        backing_id: 0,
        memfd_id,
        anon_shared_id,
        sysv_shmid: 0,
        growsdown: (flags & MAP_GROWSDOWN) != 0,
        fork_inherited_anon: false,
    };
    // shared OSInode 页由 fault 从文件/cache 装入；private/file framed 映射仍可预填充。
    let should_populate_file =
        matches!(source, MmapSource::RegularFile { .. }) && !shared_inode_backed;
    let backing_file = match source {
        MmapSource::RegularFile { .. } | MmapSource::Shm { .. } => file.as_ref(),
        _ => None,
    };
    let populate_file = should_populate_file.then_some(backing_file).flatten();
    let replace_existing = (flags & MAP_FIXED) != 0;
    let (detached_shmids, fixed_packet_ring_token) = {
        let mut memory_set = inner.memory_set.lock();
        let fixed_attach_update = if replace_existing {
            let mut updated_attaches = memory_set.sysv_shm_attaches_snapshot();
            let Some(release_shmids) =
                detach_attaches_overlapping(&mut updated_attaches, map_start, map_len)
            else {
                return err(SyscallError::ENOMEM);
            };
            Some((updated_attaches, release_shmids))
        } else {
            None
        };
        let inserted = commit_mmap_vma(
            &mut memory_set,
            replace_existing,
            region,
            vma_areas,
            lock_range,
            backing_file,
            populate_file,
            start,
            len,
            off,
        );
        if !inserted {
            return err(SyscallError::ENOMEM);
        }

        let detached_shmids = if let Some((updated_attaches, release_shmids)) = fixed_attach_update
        {
            memory_set.replace_sysv_shm_attaches(updated_attaches);
            release_shmids
        } else {
            Vec::new()
        };
        if !replace_existing {
            memory_set.note_mmap_end(end);
        }
        let clear_token = replace_existing.then_some(memory_set.token());
        (detached_shmids, clear_token)
    };
    let pid = process.getpid() as u32;
    drop(inner);
    if let Some(token) = fixed_packet_ring_token {
        crate::syscall::net::clear_packet_ring_mmaps_for_range(token, map_start, map_end);
    }
    release_detached_attach_refs(pid, detached_shmids.as_slice());

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
    let inner = process.borrow_mut();
    let (src_region, sysv_attach, mm_token) = {
        let memory_set = inner.memory_set.lock();
        let Some(src_region) = memory_set.vm_region_containing(old_addr, old_end) else {
            return err(SyscallError::EFAULT);
        };
        if !memory_set.user_range_fully_mapped(old_addr.into(), old_end.into()) {
            return err(SyscallError::EFAULT);
        }
        let sysv_attach = if src_region.sysv_shmid != 0 {
            let attaches = memory_set.sysv_shm_attaches_snapshot();
            let Some(idx) =
                find_attach_containing(&attaches, src_region.sysv_shmid, old_addr, old_len)
            else {
                return err(SyscallError::EINVAL);
            };
            Some(attaches[idx])
        } else {
            None
        };
        (src_region, sysv_attach, memory_set.token())
    };
    if crate::syscall::net::packet_ring_mmap_overlaps_range(mm_token, old_addr, old_end) {
        // Our packet rings store the userspace base address in the socket state.
        // Without Linux-style VMA ops, moving or resizing that mapping would
        // leave the socket writing to stale addresses.
        return err(SyscallError::EINVAL);
    }

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
        let detached_shmids = {
            let mut memory_set = inner.memory_set.lock();
            let mut cur = new_addr;
            while cur < new_end {
                let vpn = crate::mm::VirtAddr::from(cur).floor();
                if let Some(pte) = memory_set.translate(vpn) {
                    if pte.is_valid() && !pte.flags().contains(PTEFlags::U) {
                        return err(SyscallError::ENOMEM);
                    }
                }
                cur += PAGE_SIZE;
            }

            let mut updated_attaches = memory_set.sysv_shm_attaches_snapshot();
            let Some(detached_shmids) =
                detach_attaches_overlapping(&mut updated_attaches, new_addr, new_len)
            else {
                return err(SyscallError::ENOMEM);
            };
            if src_region.sysv_shmid != 0 {
                let Some(src_attach_idx) = find_attach_containing(
                    &updated_attaches,
                    src_region.sysv_shmid,
                    old_addr,
                    old_len,
                ) else {
                    return err(SyscallError::EINVAL);
                };
                if !split_mremap_attach(
                    &mut updated_attaches,
                    src_attach_idx,
                    old_addr,
                    old_len,
                    new_addr,
                    new_len,
                ) {
                    return err(SyscallError::ENOMEM);
                }
            }
            if !memory_set.move_user_vma_range_replacing(old_addr, old_len, new_addr) {
                return err(SyscallError::ENOMEM);
            }
            memory_set.replace_sysv_shm_attaches(updated_attaches);
            detached_shmids
        };
        let pid = process.getpid() as u32;
        drop(inner);
        crate::syscall::net::clear_packet_ring_mmaps_for_range(mm_token, new_addr, new_end);
        release_detached_attach_refs(pid, detached_shmids.as_slice());
        return new_addr as isize;
    }

    if new_len <= old_len {
        {
            let mut memory_set = inner.memory_set.lock();
            let updated_attaches = if sysv_attach.is_some() {
                let mut updated_attaches = memory_set.sysv_shm_attaches_snapshot();
                let Some(idx) = find_attach_containing(
                    &updated_attaches,
                    src_region.sysv_shmid,
                    old_addr,
                    old_len,
                ) else {
                    return err(SyscallError::EINVAL);
                };
                if !split_mremap_attach(
                    &mut updated_attaches,
                    idx,
                    old_addr,
                    old_len,
                    old_addr,
                    new_len,
                ) {
                    return err(SyscallError::ENOMEM);
                }
                Some(updated_attaches)
            } else {
                None
            };
            let shrink_start = old_addr + new_len;
            if shrink_start < old_end {
                memory_set.unmap_user_vma_range(shrink_start.into(), old_end.into());
            }
            if let Some(updated_attaches) = updated_attaches {
                memory_set.replace_sysv_shm_attaches(updated_attaches);
            }
        }
        return old_addr as isize;
    }

    let mut target_start = old_addr;
    let mut target_old_end = old_end;
    let mut target_new_end = old_addr.checked_add(new_len).unwrap_or(0);
    // In-place grow only works if the bytes just past the old end are free in
    // both structures and the expanded range stays inside user VA. If the
    // original mapping sits at the top of a top-down mmap layout, MAYMOVE must
    // still get a chance to relocate instead of failing on the invalid in-place
    // end address.
    let in_place_grow_ok = {
        let memory_set = inner.memory_set.lock();
        target_new_end != 0
            && user_range_valid(target_start, target_new_end)
            && memory_set.user_range_is_free(old_end, target_new_end, USER_VA_TOP)
    };
    if !in_place_grow_ok {
        if (flags & MREMAP_MAYMOVE) == 0 {
            return err(SyscallError::ENOMEM);
        }
        let mut memory_set = inner.memory_set.lock();
        let Some(free_start) = memory_set.find_free_mmap_range(None, new_len, USER_VA_TOP) else {
            return err(SyscallError::ENOMEM);
        };
        let Some(free_old_end) = free_start.checked_add(old_len) else {
            return err(SyscallError::ENOMEM);
        };
        let Some(free_new_end) = free_start.checked_add(new_len) else {
            return err(SyscallError::ENOMEM);
        };
        target_start = free_start;
        target_old_end = free_old_end;
        target_new_end = free_new_end;
    }

    let grow_start = target_old_end;
    let src_file_offset = match src_region
        .file_offset
        .checked_add(old_addr.saturating_sub(src_region.start))
    {
        Some(offset) => offset,
        None => return err(SyscallError::ENOMEM),
    };

    let updated_attaches = if sysv_attach.is_some() {
        let memory_set = inner.memory_set.lock();
        let mut updated_attaches = memory_set.sysv_shm_attaches_snapshot();
        let Some(idx) =
            find_attach_containing(&updated_attaches, src_region.sysv_shmid, old_addr, old_len)
        else {
            return err(SyscallError::EINVAL);
        };
        if !split_mremap_attach(
            &mut updated_attaches,
            idx,
            old_addr,
            old_len,
            target_start,
            new_len,
        ) {
            return err(SyscallError::ENOMEM);
        }
        Some(updated_attaches)
    } else {
        None
    };

    let grow_ok = if src_region.sysv_shmid != 0 {
        let sysv_ipc_ns_id = sysv_attach
            .map(|attach| attach.ipc_ns_id)
            .unwrap_or(inner.ipc_ns_id);
        let Some(seg_size) = segment_size(sysv_ipc_ns_id, src_region.sysv_shmid) else {
            return err(SyscallError::ENOMEM);
        };
        let old_slice_file_valid_len = src_region
            .file_valid_end()
            .saturating_sub(old_addr)
            .min(old_len);
        let current_file_valid_len = seg_size.saturating_sub(src_file_offset).min(new_len);
        let final_file_valid_len = old_slice_file_valid_len
            .max(current_file_valid_len)
            .min(new_len);
        let final_sigbus_start =
            target_start.saturating_add(align_up(final_file_valid_len, PAGE_SIZE).min(new_len));

        let mut grow_areas = Vec::new();
        let Some(grow_file_offset) = src_file_offset.checked_add(old_len) else {
            return err(SyscallError::ENOMEM);
        };
        if grow_start < final_sigbus_start {
            let shared_end = min(final_sigbus_start, target_new_end);
            let shared_len = shared_end.saturating_sub(grow_start);
            let Some(frames) = segment_shared_frames_existing(
                sysv_ipc_ns_id,
                src_region.sysv_shmid,
                grow_file_offset,
                shared_len,
            ) else {
                return err(SyscallError::ENOMEM);
            };
            grow_areas.push(VmaInsertArea::SharedFrames {
                start: grow_start,
                end: shared_end,
                frames,
            });
        }
        if final_sigbus_start < target_new_end {
            grow_areas.push(VmaInsertArea::Lazy {
                start: final_sigbus_start.max(grow_start),
                end: target_new_end,
            });
        }
        {
            let mut memory_set = inner.memory_set.lock();
            memory_set.try_grow_user_vma_range_with_file_len(
                old_addr,
                old_len,
                target_start,
                new_len,
                grow_areas,
                final_file_valid_len,
                |_| true,
            )
        }
    } else if src_region.shared && src_region.memfd_id != 0 {
        let backing_file = {
            let memory_set = inner.memory_set.lock();
            memory_set.mmap_backing_file(src_region.backing_id)
        };
        let Some(file) = backing_file
            .or_else(|| find_shm_file_in_snapshot(&files_snapshot, src_region.memfd_id))
            .or_else(|| find_open_shm_file(src_region.memfd_id))
        else {
            return err(SyscallError::ENOMEM);
        };
        let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() else {
            return err(SyscallError::ENOMEM);
        };
        let file_size = shm.len();
        let old_slice_file_valid_len = src_region
            .file_valid_end()
            .saturating_sub(old_addr)
            .min(old_len);
        let current_file_valid_len = file_size.saturating_sub(src_file_offset).min(new_len);
        let final_file_valid_len = old_slice_file_valid_len
            .max(current_file_valid_len)
            .min(new_len);
        let final_sigbus_start =
            target_start.saturating_add(align_up(final_file_valid_len, PAGE_SIZE).min(new_len));

        let mut grow_areas = Vec::new();
        let Some(grow_file_offset) = src_file_offset.checked_add(old_len) else {
            return err(SyscallError::ENOMEM);
        };
        if grow_start < final_sigbus_start {
            let shared_end = min(final_sigbus_start, target_new_end);
            let shared_len = shared_end.saturating_sub(grow_start);
            let Some(frames) = shm.shared_frames_existing(grow_file_offset, shared_len) else {
                return err(SyscallError::ENOMEM);
            };
            grow_areas.push(VmaInsertArea::SharedFrames {
                start: grow_start,
                end: shared_end,
                frames,
            });
        }
        if final_sigbus_start < target_new_end {
            grow_areas.push(VmaInsertArea::Lazy {
                start: final_sigbus_start.max(grow_start),
                end: target_new_end,
            });
        }
        {
            let mut memory_set = inner.memory_set.lock();
            memory_set.try_grow_user_vma_range_with_file_len(
                old_addr,
                old_len,
                target_start,
                new_len,
                grow_areas,
                final_file_valid_len,
                |_| true,
            )
        }
    } else if src_region.file_backed {
        let backing_file = {
            let memory_set = inner.memory_set.lock();
            memory_set.mmap_backing_file(src_region.backing_id)
        };
        let Some(file) = backing_file.or_else(|| {
            find_inode_file_in_snapshot(&files_snapshot, src_region.file_dev, src_region.file_ino)
                .or_else(|| find_open_inode_file(src_region.file_dev, src_region.file_ino))
        }) else {
            return err(SyscallError::ENOMEM);
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return err(SyscallError::ENOMEM);
        };
        let pending_end = os_inode.pending_write_end();
        let inode = os_inode.ext4_inode();
        let file_size = {
            let _ext4_guard = ext4_lock();
            inode.size() as usize
        }
        .max(pending_end);
        let old_slice_file_valid_len = src_region
            .file_valid_end()
            .saturating_sub(old_addr)
            .min(old_len);
        let current_file_valid_len = file_size.saturating_sub(src_file_offset).min(new_len);
        let final_file_valid_len = old_slice_file_valid_len
            .max(current_file_valid_len)
            .min(new_len);
        let final_sigbus_start =
            target_start.saturating_add(align_up(final_file_valid_len, PAGE_SIZE).min(new_len));

        let mut grow_areas = Vec::new();
        if grow_start < final_sigbus_start {
            let grow_valid_end = min(final_sigbus_start, target_new_end);
            if src_region.shared {
                // shared grow 的新有效页保持 lazy，避免和全局 shared cache 分裂。
                grow_areas.push(VmaInsertArea::Lazy {
                    start: grow_start,
                    end: grow_valid_end,
                });
            } else {
                grow_areas.push(VmaInsertArea::Framed {
                    start: grow_start,
                    end: grow_valid_end,
                });
            }
        }
        if final_sigbus_start < target_new_end {
            grow_areas.push(VmaInsertArea::Lazy {
                start: final_sigbus_start.max(grow_start),
                end: target_new_end,
            });
        }
        let Some(grow_file_offset) = src_file_offset.checked_add(old_len) else {
            return err(SyscallError::ENOMEM);
        };
        let file_mapped_grow_len = min(
            target_new_end.saturating_sub(grow_start),
            final_sigbus_start.saturating_sub(grow_start),
        );
        if grow_file_offset.checked_add(file_mapped_grow_len).is_none() {
            return err(SyscallError::ENOMEM);
        }

        {
            let mut memory_set = inner.memory_set.lock();
            memory_set.try_grow_user_vma_range_with_file_len(
                old_addr,
                old_len,
                target_start,
                new_len,
                grow_areas,
                final_file_valid_len,
                |memory_set| {
                    if src_region.shared {
                        // shared file 新页不在 mremap 时拷贝，后续 fault 统一走 cache/file。
                        return true;
                    }
                    let token = memory_set.token();
                    let mut pos = 0usize;
                    let mut tmp = [0u8; 512];
                    while pos < file_mapped_grow_len {
                        let to_read = min(tmp.len(), file_mapped_grow_len - pos);
                        let read = os_inode.pread_at(grow_file_offset + pos, &mut tmp[..to_read]);
                        if read == 0 {
                            break;
                        }
                        if try_copy_to_user_unchecked(
                            token,
                            (grow_start + pos) as *mut u8,
                            &tmp[..read],
                        )
                        .is_err()
                        {
                            return false;
                        }
                        pos += read;
                    }
                    true
                },
            )
        }
    } else {
        let grow_area = VmaInsertArea::Lazy {
            start: grow_start,
            end: target_new_end,
        };
        {
            let mut memory_set = inner.memory_set.lock();
            memory_set.try_grow_user_vma_range(
                old_addr,
                old_len,
                target_start,
                new_len,
                grow_area,
                |_| true,
            )
        }
    };
    if !grow_ok {
        return err(SyscallError::ENOMEM);
    }

    {
        let mut memory_set = inner.memory_set.lock();
        if let Some(updated_attaches) = updated_attaches {
            memory_set.replace_sysv_shm_attaches(updated_attaches);
        }
        memory_set.note_mmap_end(target_new_end);
    }
    drop(inner);
    let clear_start = if target_start == old_addr {
        old_end
    } else {
        target_start
    };
    crate::syscall::net::clear_packet_ring_mmaps_for_range(mm_token, clear_start, target_new_end);
    target_start as isize
}
