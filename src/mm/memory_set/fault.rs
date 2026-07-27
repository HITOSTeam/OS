use super::backing::{
    shared_anon_page_cache_get, shared_anon_page_cache_insert_or_get, shared_file_page_cache_get,
    shared_file_page_cache_insert_or_get,
};
use super::{
    LazyFaultResult, MapPermission, MapType, MemorySet, vm_region_map_area_type_compatible,
};
use crate::config::{PAGE_SIZE, USER_STACK_GUARD_GAP};
use crate::fs::{OSInode, cgroup_charge_anon_current};
use crate::mm::{PTEFlags, VirtAddr, VirtPageNum, frame_alloc};
use crate::task::processor::current_process;

impl MemorySet {
    /// 检查 addr 是否落在文件映射的 SIGBUS tail 区（EOF 之后的不可访问段）。
    #[allow(dead_code)]
    pub fn fault_hits_mmap_sigbus_tail(&self, addr: usize) -> bool {
        self.vm_region_containing_addr(addr)
            .is_some_and(|region| addr >= region.sigbus_start())
    }

    /// 处理 MAP_GROWSDOWN 栈向下扩展的 guard page fault：
    /// 检查扩展合法性（guard gap、无重叠），扩展 VMA 和 MapArea，再物化页面。
    #[allow(dead_code)]
    pub fn try_expand_growsdown(
        &mut self,
        fault_va: usize,
        access: MapPermission,
    ) -> LazyFaultResult {
        // 栈向下增长：先扩 VMA/MapArea，再按普通 lazy fault 物化页面。
        let fault_page = fault_va & !(PAGE_SIZE - 1);

        if let Some(region) = self.vm_regions.growsdown_candidate_before(fault_page) {
            let perm = region.map_permission();
            if !perm.contains(access) {
                return LazyFaultResult::Invalid;
            }
            if self.concrete_range_overlaps(fault_page.into(), region.start.into()) {
                return LazyFaultResult::Invalid;
            }
            // 保留 Linux 风格的 guard gap，防止栈无限扩展覆盖其他映射。
            let Some(next_guard_start) = fault_page.checked_sub(USER_STACK_GUARD_GAP) else {
                return LazyFaultResult::Invalid;
            };
            if self.map_area_range_overlaps_except(next_guard_start, fault_page, None)
                || self.vm_region_range_overlaps_except(next_guard_start, fault_page, None)
            {
                return LazyFaultResult::Invalid;
            }
            if !self.try_insert_lazy_area_raw(fault_page.into(), region.start.into(), perm) {
                return LazyFaultResult::Invalid;
            }

            if !self
                .vm_regions
                .expand_growsdown_at(region.start, fault_page)
            {
                return LazyFaultResult::Invalid;
            }
            self.debug_assert_user_vm_invariants();
            return self.resolve_lazy_fault(fault_va, access);
        }
        LazyFaultResult::Invalid
    }

    /// 返回 fork/COW 内存压力诊断统计：
    /// (area数, 驻留帧数, identical_vpns, lazy_areas, framed_areas, identical_areas)
    pub fn cow_diag_stats(&self) -> (usize, usize, usize, usize, usize, usize) {
        let mut total_data_frames = 0usize;
        let mut identical_vpns = 0usize;
        let mut lazy_areas = 0usize;
        let mut framed_areas = 0usize;
        let mut identical_areas = 0usize;
        for area in self.areas.iter() {
            total_data_frames = total_data_frames.saturating_add(area.tracked_frame_count());
            match area.map_type() {
                MapType::Lazy => lazy_areas = lazy_areas.saturating_add(1),
                MapType::Framed => framed_areas = framed_areas.saturating_add(1),
                MapType::Identical => {
                    identical_areas = identical_areas.saturating_add(1);
                    identical_vpns = identical_vpns.saturating_add(area.page_count());
                }
            }
        }
        (
            self.areas.len(),
            total_data_frames,
            identical_vpns,
            lazy_areas,
            framed_areas,
            identical_areas,
        )
    }

    /// 处理 COW fault：PTE 标有 COW 位时，分配新帧、复制旧页内容、
    /// 重映射为可写，更新 MapArea frame tracker，刷新 TLB。
    pub fn resolve_cow_fault(&mut self, fault_va: usize) -> bool {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        let Some(region) = self.vm_region_containing_addr(fault_va) else {
            return false;
        };
        if !region.allows_cow_fault(fault_va) {
            return false;
        }
        let Some(pte) = self.translate(vpn) else {
            return false;
        };
        let flags = pte.flags();
        if !flags.contains(PTEFlags::COW) {
            return false;
        }
        if flags.contains(PTEFlags::SHARED) {
            return false;
        }
        let old_ppn = pte.ppn();
        let Some(frame) = frame_alloc() else {
            return false;
        };
        // 复制旧页内容到新帧（COW 写时复制语义）。
        frame
            .ppn
            .get_bytes_array()
            .copy_from_slice(old_ppn.get_bytes_array());

        let mut new_flags = flags;
        new_flags.remove(PTEFlags::COW);
        new_flags.insert(PTEFlags::W);
        new_flags.insert(PTEFlags::D);
        #[cfg(target_arch = "loongarch64")]
        {
            // Keep the COW remap and the visible TLB invalidation separate:
            // the ASID helper below can invalidate exactly this user address
            // without falling back to a full context-switch flush.
            if !self.page_table.remap_deferred(vpn, frame.ppn, new_flags) {
                return false;
            }
        }
        #[cfg(not(target_arch = "loongarch64"))]
        {
            if !self.page_table.remap(vpn, frame.ppn, new_flags) {
                return false;
            }
        }

        // 更新 MapArea 的 frame tracker，旧共享帧引用计数随之减少。
        for area in self.areas.iter_mut() {
            if area.is_identical() {
                continue;
            }
            if !area.contains_vpn(vpn) {
                continue;
            }
            area.insert_tracked_frame(vpn, frame);
            break;
        }

        // 刷新 TLB，使新 PTE 立即生效。
        //
        // 这里不能只刷新当前 hart：fork 之后，父进程的多个线程可能在不同
        // hart 上共享同一份页表。某个线程处理 COW fault 时，其他 hart 若仍
        // 缓存旧的只读+COW PTE，会在随后写入时再次陷入，甚至观察到已经被
        // 回收的旧映射。fork 时对父页表降权已经做了远程 shootdown；COW remap
        // 同样必须保持这个 TLB 一致性不变量。
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        self.flush_user_page(fault_va);
        #[cfg(target_arch = "riscv64")]
        {
            let remote_hart_mask = crate::task::manager::online_hart_mask()
                & !(1usize << crate::arch::hart_id());
            if remote_hart_mask != 0 {
                crate::sbi::remote_sfence_vma_all(remote_hart_mask);
            }
        }
        true
    }

    /// 处理 lazy fault：从 VmRegion 取策略，按需分配/复用 frame 并安装 PTE。
    ///
    /// 处理流程：
    /// 1. 查 VmRegion 确认地址合法且有 lazy 策略；
    /// 2. 对共享映射优先从全局缓存复用 frame；
    /// 3. 新帧对文件映射从文件读入内容（EOF 尾保持零填充）；
    /// 4. 共享映射通过 insert_or_get 保证同文件页全局唯一帧；
    /// 5. 私有匿名映射向 cgroup 记账；
    /// 6. 安装 PTE、更新 MapArea frame tracker、记录 backing resident 页、刷 TLB。
    pub fn resolve_lazy_fault(
        &mut self,
        fault_va: usize,
        access: MapPermission,
    ) -> LazyFaultResult {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        // 查找对应vma 记录
        let Some(region) = self.vm_region_containing_addr(fault_va) else {
            return LazyFaultResult::Invalid;
        };
        // 获取对应 新页 的PTE 记录 以及 映射 类型
        let Some((perm, pte_flags)) = region.lazy_fault_policy(fault_va, access) else {
            return LazyFaultResult::Invalid;
        };
        let page_start = vpn.0.saturating_mul(PAGE_SIZE);
        let file_page = (region.backing_id != 0).then(|| {
            region
                .file_offset
                .saturating_add(page_start.saturating_sub(region.start))
                / PAGE_SIZE
        });
        let shared_inode_backed = region.shared && region.file_backed && region.memfd_id == 0;
        let shared_anon_backed = region.shared && region.anon_shared_id != 0;
        let anon_page = shared_anon_backed.then(|| {
            region
                .file_offset
                .saturating_add(page_start.saturating_sub(region.start))
                / PAGE_SIZE
        });
        // MAP_SHARED fault 优先复用全局共享页缓存。
        let mut cached_shared_frame = if shared_inode_backed {
            file_page.and_then(|file_page| {
                shared_file_page_cache_get(region.file_dev, region.file_ino, file_page)
                    .or_else(|| self.mmap_backing_resident_frame(region.backing_id, file_page))
            })
        } else if shared_anon_backed {
            anon_page
                .and_then(|anon_page| shared_anon_page_cache_get(region.anon_shared_id, anon_page))
        } else {
            None
        };
        for area in self.areas.iter_mut() {
            if !area.is_lazy() {
                continue;
            }
            if !area.contains_vpn(vpn) {
                continue;
            }
            debug_assert_eq!(
                area.map_perm(),
                perm,
                "lazy MapArea permission drift at fault address {:#x}",
                fault_va
            );
            debug_assert!(
                vm_region_map_area_type_compatible(&region, area),
                "lazy MapArea type drift at fault address {:#x}: area={:?}, region={:?}",
                fault_va,
                area.map_type(),
                region.map_type
            );
            if let Some(pte) = self.page_table.translate(vpn) {
                if pte.is_valid() {
                    return LazyFaultResult::Invalid;
                }
            }
            let total_pages = area.page_count();
            let accounted_pages = area.charged_or_tracked_pages();
            let new_charge_pages = total_pages.saturating_sub(accounted_pages);
            let (frame, reused_cached_frame) = if let Some(frame) = cached_shared_frame.take() {
                // 命中共享缓存，直接复用不读文件。
                (frame, true)
            } else {
                let Some(frame) = frame_alloc() else {
                    crate::println!("[mm] OOM: lazy fault alloc failed for vpn={:?}", vpn);
                    return LazyFaultResult::Oom;
                };
                (frame, false)
            };
            if !reused_cached_frame {
                if region.file_backed {
                    if let Some(file) = self
                        .mmap_backings
                        .get(&region.backing_id)
                        .map(|backing| backing.file())
                    {
                        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
                            // 新分配的 file-backed 页从文件读入，EOF 页尾保持零填充。
                            let region_delta = page_start.saturating_sub(region.start);
                            let file_off = region.file_offset.saturating_add(region_delta);
                            let valid_len = region.file_valid_len();
                            let read_len = valid_len.saturating_sub(region_delta).min(PAGE_SIZE);
                            if read_len > 0 {
                                let page = frame.ppn.get_bytes_array();
                                let _ = os_inode.pread_at(file_off, &mut page[..read_len]);
                            }
                        }
                    }
                }
            }
            let frame = match (shared_inode_backed, file_page) {
                (true, Some(file_page)) => {
                    // insert_or_get 处理并发/重入语义：若已有共享页，统一使用已有 frame。
                    shared_file_page_cache_insert_or_get(
                        region.file_dev,
                        region.file_ino,
                        file_page,
                        frame,
                    )
                }
                _ => match (shared_anon_backed, anon_page) {
                    (true, Some(anon_page)) => shared_anon_page_cache_insert_or_get(
                        region.anon_shared_id,
                        anon_page,
                        frame,
                    ),
                    _ => frame,
                },
            };
            // 先分配帧再 cgroup 记账，避免 OOM 导致记账泄漏。
            if new_charge_pages > 0
                && region.is_private_anonymous()
                && perm.contains(MapPermission::U)
                && perm.contains(MapPermission::W)
            {
                let charge_bytes = new_charge_pages.saturating_mul(PAGE_SIZE);
                if !cgroup_charge_anon_current(current_process().getpid(), charge_bytes) {
                    return LazyFaultResult::Oom;
                }
                area.set_charged_pages(accounted_pages.saturating_add(new_charge_pages));
            }
            self.page_table.map(vpn, frame.ppn, pte_flags);
            #[cfg(target_arch = "riscv64")]
            if pte_flags.contains(PTEFlags::X) {
                // Newly faulted executable pages may contain instructions from
                // a file mapping. Defer the fence.i to the next return to this
                // mm instead of issuing it for every lazy fault.
                crate::arch::riscv64::mm::mark_icache_stale(self.asid.as_ref());
            }
            let shared_file_backing_frame = shared_inode_backed.then(|| frame.clone());
            area.insert_tracked_frame(vpn, frame);
            if region.backing_id != 0 {
                if let Some(file_page) = file_page {
                    // 记录 resident 页，供 msync/munmap/writeback 和 debug invariant 使用。
                    if let Some(backing) = self.mmap_backings.get_mut(&region.backing_id) {
                        backing.add_resident_page_ref(
                            file_page,
                            shared_file_backing_frame.as_ref(),
                            pte_flags.contains(PTEFlags::D),
                        );
                    }
                }
            }
            #[cfg(target_arch = "loongarch64")]
            self.flush_user_page(fault_va);
            #[cfg(target_arch = "riscv64")]
            self.flush_user_page(fault_va);
            return LazyFaultResult::Resolved;
        }
        LazyFaultResult::Invalid
    }
}
