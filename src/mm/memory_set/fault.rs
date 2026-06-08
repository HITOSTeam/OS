use super::backing::{shared_file_page_cache_get, shared_file_page_cache_insert_or_get};
use super::{
    LazyFaultResult, MapPermission, MapType, MemorySet, vm_region_map_area_type_compatible,
};
use crate::config::{PAGE_SIZE, USER_STACK_GUARD_GAP};
use crate::fs::{OSInode, cgroup_charge_anon_current};
use crate::mm::{PTEFlags, VirtAddr, VirtPageNum, frame_alloc};
use crate::task::processor::current_process;

impl MemorySet {
    #[allow(dead_code)]
    pub fn fault_hits_mmap_sigbus_tail(&self, addr: usize) -> bool {
        self.vm_region_containing_addr(addr)
            .is_some_and(|region| addr >= region.sigbus_start())
    }

    #[allow(dead_code)]
    pub fn try_expand_growsdown(
        &mut self,
        fault_va: usize,
        access: MapPermission,
    ) -> LazyFaultResult {
        let fault_page = fault_va & !(PAGE_SIZE - 1);

        if let Some(region) = self.vm_regions.growsdown_candidate_before(fault_page) {
            let perm = region.map_permission();
            if !perm.contains(access) {
                return LazyFaultResult::Invalid;
            }
            if self.concrete_range_overlaps(fault_page.into(), region.start.into()) {
                return LazyFaultResult::Invalid;
            }
            // Keep a Linux-style guard gap below the expanded stack segment.
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

    /// Lightweight summary used to diagnose fork/COW memory pressure.
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

    /// Resolve a copy-on-write fault at `fault_va` if the page is tagged COW.
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
        frame
            .ppn
            .get_bytes_array()
            .copy_from_slice(old_ppn.get_bytes_array());

        let mut new_flags = flags;
        new_flags.remove(PTEFlags::COW);
        new_flags.insert(PTEFlags::W);
        new_flags.insert(PTEFlags::D);
        if !self.page_table.remap(vpn, frame.ppn, new_flags) {
            return false;
        }

        // Update the owning MapArea's frame tracker so the old shared frame gets its refcount decremented.
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

        // Flush TLB for this address.
        #[cfg(target_arch = "riscv64")]
        // SAFETY: sfence.vma is valid in S-mode; fault_va is the address to flush from TLB.
        unsafe {
            core::arch::asm!("sfence.vma {0}, zero", in(reg) fault_va);
        }
        #[cfg(target_arch = "loongarch64")]
        // SAFETY: invtlb is valid in S-mode; fault_va is the address to flush from TLB.
        unsafe {
            core::arch::asm!("invtlb 0x4, $r0, {}", in(reg) fault_va);
        }
        true
    }

    /// Resolve a lazy user mapping fault by allocating a page on demand.
    pub fn resolve_lazy_fault(
        &mut self,
        fault_va: usize,
        access: MapPermission,
    ) -> LazyFaultResult {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        let Some(region) = self.vm_region_containing_addr(fault_va) else {
            return LazyFaultResult::Invalid;
        };
        let Some((perm, pte_flags)) = region.lazy_fault_policy(fault_va, access) else {
            return LazyFaultResult::Invalid;
        };
        let file_backing = region
            .file_backed
            .then(|| self.mmap_backing_file(region.backing_id))
            .flatten();
        let page_start = vpn.0.saturating_mul(PAGE_SIZE);
        let file_page = (region.backing_id != 0).then(|| {
            region
                .file_offset
                .saturating_add(page_start.saturating_sub(region.start))
                / PAGE_SIZE
        });
        let shared_inode_backed = region.shared && region.file_backed && region.memfd_id == 0;
        let mut cached_shared_frame = if shared_inode_backed {
            file_page.and_then(|file_page| {
                shared_file_page_cache_get(region.file_dev, region.file_ino, file_page)
                    .or_else(|| self.mmap_backing_resident_frame(region.backing_id, file_page))
            })
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
                (frame, true)
            } else {
                let Some(frame) = frame_alloc() else {
                    crate::println!("[mm] OOM: lazy fault alloc failed for vpn={:?}", vpn);
                    return LazyFaultResult::Oom;
                };
                (frame, false)
            };
            if !reused_cached_frame && let Some(file) = file_backing.as_ref() {
                if region.file_backed {
                    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
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
            let frame = if shared_inode_backed && let Some(file_page) = file_page {
                shared_file_page_cache_insert_or_get(
                    region.file_dev,
                    region.file_ino,
                    file_page,
                    frame,
                )
            } else {
                frame
            };
            // Allocate before charging so OOM in frame_alloc() cannot leak cgroup accounting;
            // if charging fails, the uninstalled frame is dropped immediately.
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
            area.insert_tracked_frame(vpn, frame);
            if region.backing_id != 0
                && let Some(file_page) = file_page
            {
                let backing_frame = area
                    .tracked_frame(vpn)
                    .expect("lazy fault inserted frame")
                    .clone();
                if let Some(backing) = self.mmap_backings.get_mut(&region.backing_id) {
                    let cache_frame =
                        (region.shared && region.file_backed).then_some(&backing_frame);
                    backing.add_resident_page_ref(
                        file_page,
                        cache_frame,
                        pte_flags.contains(PTEFlags::D),
                    );
                }
            }
            #[cfg(target_arch = "riscv64")]
            // SAFETY: sfence.vma is valid in S-mode; fault_va is the address to flush from TLB.
            unsafe {
                core::arch::asm!("sfence.vma {0}, zero", in(reg) fault_va);
            }
            #[cfg(target_arch = "loongarch64")]
            // SAFETY: invtlb is valid in S-mode; fault_va is the address to flush from TLB.
            unsafe {
                core::arch::asm!("invtlb 0x4, $r0, {}", in(reg) fault_va);
            }
            return LazyFaultResult::Resolved;
        }
        LazyFaultResult::Invalid
    }
}
