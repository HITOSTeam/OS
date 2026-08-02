use super::backing::{
    FilePageCacheLoadError, file_page_cache_get_or_load, shared_anon_page_cache_get,
    shared_anon_page_cache_insert_or_get,
};
use super::{
    LazyFaultResult, MapPermission, MapType, MemorySet, MmRef, PageTableUpdateBatch, VmRegion,
    vm_region_map_area_type_compatible,
};
use crate::config::{PAGE_SIZE, USER_STACK_GUARD_GAP};
use crate::fs::{OSInode, cgroup_charge_anon_current};
use crate::mm::{FrameTracker, PTEFlags, PageTableEntry, VirtAddr, VirtPageNum, frame_alloc};
use crate::task::processor::current_process;

const FAULT_FAST_RETRIES: usize = 3;

struct CowFaultPlan {
    vpn: VirtPageNum,
    region: VmRegion,
    old_frame: FrameTracker,
}

enum CowFaultPrepare {
    Ready(CowFaultPlan),
    Resolved,
    Invalid,
}

enum CowFaultCommit {
    Installed,
    Resolved,
    Retry,
}

struct LazyFaultPlan {
    vpn: VirtPageNum,
    region: VmRegion,
    perm: MapPermission,
    pte_flags: PTEFlags,
    file_page: Option<usize>,
    anon_page: Option<usize>,
    inode_backed: bool,
    private_file_cow: bool,
    shared_anon_backed: bool,
    file: Option<alloc::sync::Arc<dyn crate::fs::File + Send + Sync>>,
    file_off: usize,
}

enum LazyFaultPrepare {
    Ready(LazyFaultPlan),
    Resolved,
    Cow,
    Invalid,
}

enum LazyFaultCommit {
    Installed,
    Resolved,
    Retry,
    Oom,
}

fn pte_allows_access(pte: PageTableEntry, access: MapPermission) -> bool {
    pte.is_valid()
        && (!access.contains(MapPermission::R) || pte.readable())
        && (!access.contains(MapPermission::W) || pte.writable())
        && (!access.contains(MapPermission::X) || pte.executable())
}

/// Apply Linux's clean private-file mapping policy to a VMA-derived PTE.
/// Keep this transformation shared by prepare and commit so their recheck
/// compares identical policy snapshots.
fn private_file_cache_pte_flags(region: &VmRegion, mut flags: PTEFlags) -> (PTEFlags, bool) {
    let private_file_cow = region.file_backed && region.memfd_id == 0 && !region.shared;
    if private_file_cow {
        flags.remove(PTEFlags::W | PTEFlags::D | PTEFlags::SHARED);
        flags.insert(PTEFlags::COW);
    }
    (flags, private_file_cow)
}

impl MemorySet {
    /// 检查 addr 是否落在文件映射的 SIGBUS tail 区（EOF 之后的不可访问段）。
    #[allow(dead_code)]
    pub fn fault_hits_mmap_sigbus_tail(&self, addr: usize) -> bool {
        self.vm_region_containing_addr(addr)
            .is_some_and(|region| addr >= region.sigbus_start())
    }

    /// Validate and extend MAP_GROWSDOWN metadata for one guard-page fault.
    ///
    /// Page allocation is deliberately left to `MmRef::resolve_lazy_fault`
    /// after the mm lock is released. Linux similarly changes the VMA under
    /// mmap locking, then resolves/installs the page through the fault path.
    fn expand_growsdown_metadata(&mut self, fault_va: usize, access: MapPermission) -> bool {
        let fault_page = fault_va & !(PAGE_SIZE - 1);

        if let Some(region) = self.vm_regions.growsdown_candidate_before(fault_page) {
            let perm = region.map_permission();
            if !perm.contains(access) {
                return false;
            }
            if self.concrete_range_overlaps(fault_page.into(), region.start.into()) {
                return false;
            }
            // 保留 Linux 风格的 guard gap，防止栈无限扩展覆盖其他映射。
            let Some(next_guard_start) = fault_page.checked_sub(USER_STACK_GUARD_GAP) else {
                return false;
            };
            if self.map_area_range_overlaps_except(next_guard_start, fault_page, None)
                || self.vm_region_range_overlaps_except(next_guard_start, fault_page, None)
            {
                return false;
            }
            if !self.try_insert_lazy_area_raw(fault_page.into(), region.start.into(), perm) {
                return false;
            }

            if !self
                .vm_regions
                .expand_growsdown_at(region.start, fault_page)
            {
                return false;
            }
            self.debug_assert_user_vm_invariants();
            return true;
        }
        false
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

    fn prepare_cow_fault(&self, fault_va: usize) -> CowFaultPrepare {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        let Some(region) = self.vm_region_containing_addr(fault_va) else {
            return CowFaultPrepare::Invalid;
        };
        if !region.allows_cow_fault(fault_va) {
            return CowFaultPrepare::Invalid;
        }
        let Some(pte) = self.translate(vpn) else {
            return CowFaultPrepare::Invalid;
        };
        let flags = pte.flags();
        if !flags.contains(PTEFlags::COW) {
            return if pte.writable() {
                CowFaultPrepare::Resolved
            } else {
                CowFaultPrepare::Invalid
            };
        }
        if flags.contains(PTEFlags::SHARED) {
            return CowFaultPrepare::Invalid;
        }
        let Some(old_frame) = self
            .areas
            .iter()
            .filter(|area| !area.is_identical() && area.contains_vpn(vpn))
            .find_map(|area| area.tracked_frame(vpn))
            .filter(|frame| frame.ppn == pte.ppn())
            .cloned()
        else {
            return CowFaultPrepare::Invalid;
        };

        CowFaultPrepare::Ready(CowFaultPlan {
            vpn,
            region,
            old_frame,
        })
    }

    fn commit_cow_fault(&mut self, plan: &CowFaultPlan, frame: &FrameTracker) -> CowFaultCommit {
        let fault_va = plan.vpn.0.saturating_mul(PAGE_SIZE);
        let Some(region) = self.vm_region_containing_addr(fault_va) else {
            return CowFaultCommit::Retry;
        };
        if region != plan.region || !region.allows_cow_fault(fault_va) {
            return CowFaultCommit::Retry;
        }
        let Some(pte) = self.translate(plan.vpn) else {
            return CowFaultCommit::Retry;
        };
        let flags = pte.flags();
        if !flags.contains(PTEFlags::COW) {
            return if pte.writable() {
                CowFaultCommit::Resolved
            } else {
                CowFaultCommit::Retry
            };
        }
        if flags.contains(PTEFlags::SHARED) || pte.ppn() != plan.old_frame.ppn {
            return CowFaultCommit::Retry;
        }
        let Some(area_idx) = self.areas.iter().position(|area| {
            !area.is_identical()
                && area.contains_vpn(plan.vpn)
                && area
                    .tracked_frame(plan.vpn)
                    .is_some_and(|tracked| tracked.ppn == plan.old_frame.ppn)
        }) else {
            return CowFaultCommit::Retry;
        };

        let mut new_flags = flags;
        new_flags.remove(PTEFlags::COW);
        new_flags.insert(PTEFlags::W | PTEFlags::D);
        let mut batch: PageTableUpdateBatch = self.begin_page_table_update();
        let Some(changed) = self
            .page_table
            .remap_deferred_changed(plan.vpn, frame.ppn, new_flags)
        else {
            return CowFaultCommit::Retry;
        };
        if changed {
            batch.record_page(fault_va);
        }
        #[cfg(target_arch = "riscv64")]
        if new_flags.contains(PTEFlags::X) {
            batch.mark_icache_stale();
        }
        // Keep the old frame pinned until every target hart has acknowledged
        // the invalidation for the newly installed PTE.
        self.areas[area_idx].replace_tracked_frame_batched(plan.vpn, frame.clone(), &mut batch);
        batch.commit();
        CowFaultCommit::Installed
    }

    fn prepare_lazy_fault(&self, fault_va: usize, access: MapPermission) -> LazyFaultPrepare {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        let Some(region) = self.vm_region_containing_addr(fault_va) else {
            return LazyFaultPrepare::Invalid;
        };
        let Some((perm, pte_flags)) = region.lazy_fault_policy(fault_va, access) else {
            return LazyFaultPrepare::Invalid;
        };
        let Some(area) = self
            .areas
            .iter()
            .find(|area| area.is_lazy() && area.contains_vpn(vpn))
        else {
            return LazyFaultPrepare::Invalid;
        };
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
        if let Some(pte) = self.page_table.translate(vpn)
            && pte.is_valid()
        {
            return if pte_allows_access(pte, access) {
                LazyFaultPrepare::Resolved
            } else if access.contains(MapPermission::W) && pte.flags().contains(PTEFlags::COW) {
                LazyFaultPrepare::Cow
            } else {
                LazyFaultPrepare::Invalid
            };
        }

        let page_start = vpn.0.saturating_mul(PAGE_SIZE);
        let file_page = (region.backing_id != 0).then(|| {
            region
                .file_offset
                .saturating_add(page_start.saturating_sub(region.start))
                / PAGE_SIZE
        });
        let inode_backed = region.file_backed && region.memfd_id == 0;
        // Linux maps a clean MAP_PRIVATE file folio read-only into every mm.
        // The first private write goes through do_cow_fault() and must never
        // modify the inode page-cache frame, even if the VMA is currently
        // read-only and is upgraded later with mprotect(PROT_WRITE).
        let (pte_flags, private_file_cow) = private_file_cache_pte_flags(&region, pte_flags);
        let shared_anon_backed = region.shared && region.anon_shared_id != 0;
        let anon_page = shared_anon_backed.then(|| {
            region
                .file_offset
                .saturating_add(page_start.saturating_sub(region.start))
                / PAGE_SIZE
        });
        let file = self
            .mmap_backings
            .get(&region.backing_id)
            .map(|backing| backing.file());
        let region_delta = page_start.saturating_sub(region.start);
        let file_off = region.file_offset.saturating_add(region_delta);
        LazyFaultPrepare::Ready(LazyFaultPlan {
            vpn,
            region,
            perm,
            pte_flags,
            file_page,
            anon_page,
            inode_backed,
            private_file_cow,
            shared_anon_backed,
            file,
            file_off,
        })
    }

    fn commit_lazy_fault(
        &mut self,
        fault_va: usize,
        access: MapPermission,
        plan: &LazyFaultPlan,
        candidate: &FrameTracker,
        pid: usize,
    ) -> LazyFaultCommit {
        let Some(region) = self.vm_region_containing_addr(fault_va) else {
            return LazyFaultCommit::Retry;
        };
        if region != plan.region {
            return LazyFaultCommit::Retry;
        }
        let Some((perm, pte_flags)) = region.lazy_fault_policy(fault_va, access) else {
            return LazyFaultCommit::Retry;
        };
        let (pte_flags, private_file_cow) = private_file_cache_pte_flags(&region, pte_flags);
        if perm != plan.perm
            || pte_flags != plan.pte_flags
            || private_file_cow != plan.private_file_cow
        {
            return LazyFaultCommit::Retry;
        }
        if let Some(pte) = self.page_table.translate(plan.vpn)
            && pte.is_valid()
        {
            return if pte_allows_access(pte, access) {
                LazyFaultCommit::Resolved
            } else {
                LazyFaultCommit::Retry
            };
        }

        let Some(area_idx) = self
            .areas
            .iter()
            .position(|area| area.is_lazy() && area.contains_vpn(plan.vpn))
        else {
            return LazyFaultCommit::Retry;
        };
        debug_assert_eq!(self.areas[area_idx].map_perm(), plan.perm);
        debug_assert!(vm_region_map_area_type_compatible(
            &region,
            &self.areas[area_idx]
        ));

        let total_pages = self.areas[area_idx].page_count();
        let accounted_pages = self.areas[area_idx].charged_or_tracked_pages();
        let new_charge_pages = total_pages.saturating_sub(accounted_pages);
        if new_charge_pages > 0
            && region.is_private_anonymous()
            && plan.perm.contains(MapPermission::U)
            && plan.perm.contains(MapPermission::W)
        {
            let charge_bytes = new_charge_pages.saturating_mul(PAGE_SIZE);
            if !cgroup_charge_anon_current(pid, charge_bytes) {
                return LazyFaultCommit::Oom;
            }
            self.areas[area_idx]
                .set_charged_pages(accounted_pages.saturating_add(new_charge_pages));
        }

        // Shared-anonymous cache arbitration is intentionally delayed until
        // after the PTE/VMA recheck.  Regular-file cache I/O and publication
        // already happened without holding the mm lock.
        let frame = match (plan.shared_anon_backed, plan.anon_page) {
            (true, Some(anon_page)) => shared_anon_page_cache_insert_or_get(
                region.anon_shared_id,
                anon_page,
                candidate.clone(),
            ),
            _ => candidate.clone(),
        };

        let mut batch = self.begin_page_table_update();
        self.page_table.map(plan.vpn, frame.ppn, plan.pte_flags);
        let shared_file_backing_frame = (plan.inode_backed && region.shared).then(|| frame.clone());
        self.areas[area_idx].insert_tracked_frame(plan.vpn, frame);
        if let (Some(backing), Some(file_page)) = (
            self.mmap_backings.get_mut(&region.backing_id),
            plan.file_page,
        ) {
            backing.add_resident_page_ref(
                file_page,
                shared_file_backing_frame.as_ref(),
                plan.pte_flags.contains(PTEFlags::D),
            );
        }
        batch.record_page(fault_va);
        #[cfg(target_arch = "riscv64")]
        if plan.pte_flags.contains(PTEFlags::X) {
            batch.mark_icache_stale();
        }
        batch.commit();
        LazyFaultCommit::Installed
    }
}

impl MmRef {
    /// Resolve a COW fault in three phases, following Linux's
    /// `do_cow_fault()`/PTE-lock pattern: snapshot and pin the source page,
    /// allocate/copy without the mm lock, then recheck the authoritative PTE
    /// before committing the new mapping.
    pub fn resolve_cow_fault(&self, fault_va: usize) -> bool {
        let mut retries = 0usize;
        let mut slow_guard = None;
        loop {
            let plan = match self.lock().prepare_cow_fault(fault_va) {
                CowFaultPrepare::Ready(plan) => plan,
                CowFaultPrepare::Resolved => {
                    self.flush_user_page(fault_va);
                    return true;
                }
                CowFaultPrepare::Invalid => return false,
            };

            let Some(frame) = frame_alloc() else {
                return false;
            };
            frame
                .ppn
                .get_bytes_array()
                .copy_from_slice(plan.old_frame.ppn.get_bytes_array());

            let commit = self.lock().commit_cow_fault(&plan, &frame);
            match commit {
                CowFaultCommit::Installed => return true,
                CowFaultCommit::Resolved => {
                    self.flush_user_page(fault_va);
                    return true;
                }
                CowFaultCommit::Retry => {
                    retries = retries.saturating_add(1);
                    if retries >= FAULT_FAST_RETRIES && slow_guard.is_none() {
                        // Linux may retry a fault after dropping mmap/PTE locks.
                        // Do not turn repeated revalidation races into SIGSEGV:
                        // serialize only contended retrying faults, then keep
                        // using the same prepare/work/recheck protocol.
                        slow_guard = Some(self.fault_retry_lock.lock());
                    }
                }
            }
        }
    }

    /// Resolve a lazy page fault without keeping the process or mm lock across
    /// page allocation, zeroing, or file I/O. The final VMA/PTE recheck is the
    /// local analogue of Linux's `finish_fault()` validation.
    pub fn resolve_lazy_fault(&self, fault_va: usize, access: MapPermission) -> LazyFaultResult {
        self.resolve_lazy_fault_for(fault_va, access, current_process().getpid())
    }

    /// Resolve a lazy fault and charge anonymous memory to `charge_pid`.
    ///
    /// Normal hardware faults use the current process through
    /// `resolve_lazy_fault()`. Kernel-assisted faults into another mm (for
    /// example CLONE_CHILD_SETTID) must name that mm's process explicitly.
    /// Linux carries this ownership in the fault/memcg context; inferring it
    /// from the currently executing task would charge a child fault to its
    /// parent and could bypass the child's memory limit.
    pub fn resolve_lazy_fault_for(
        &self,
        fault_va: usize,
        access: MapPermission,
        charge_pid: usize,
    ) -> LazyFaultResult {
        let mut retries = 0usize;
        let mut slow_guard = None;
        loop {
            let plan =
                match self.lock().prepare_lazy_fault(fault_va, access) {
                    LazyFaultPrepare::Ready(plan) => plan,
                    LazyFaultPrepare::Resolved => {
                        self.flush_user_page(fault_va);
                        return LazyFaultResult::Resolved;
                    }
                    LazyFaultPrepare::Cow => {
                        if self.resolve_cow_fault(fault_va) {
                            return LazyFaultResult::Resolved;
                        }
                        let vpn = VirtAddr::from(fault_va).floor();
                        if self.lock().translate(vpn).is_some_and(|pte| {
                            pte.is_valid() && pte.flags().contains(PTEFlags::COW)
                        }) {
                            return LazyFaultResult::Oom;
                        }
                        retries = retries.saturating_add(1);
                        continue;
                    }
                    LazyFaultPrepare::Invalid => return LazyFaultResult::Invalid,
                };

            // Consult shared caches without nesting them under the mm lock.
            // Regular-file pages use a locked/loading cache slot so only one
            // concurrent fault performs filesystem I/O.
            let file_cache_frame = if plan.inode_backed {
                let Some(file_page) = plan.file_page else {
                    return LazyFaultResult::Invalid;
                };
                let Some(file) = plan.file.as_ref() else {
                    return LazyFaultResult::Invalid;
                };
                let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
                    return LazyFaultResult::Invalid;
                };
                match file_page_cache_get_or_load(
                    plan.region.file_dev,
                    plan.region.file_ino,
                    file_page,
                    |page| {
                        // Linux fills the complete cache folio independently
                        // of the VMA that triggered the miss.  pread_at()
                        // naturally stops at EOF and the freshly allocated
                        // frame keeps the remainder zero-filled.
                        let _ = os_inode.pread_at(plan.file_off, page);
                    },
                ) {
                    Ok(frame) => Some(frame),
                    Err(FilePageCacheLoadError::Oom) => return LazyFaultResult::Oom,
                    Err(FilePageCacheLoadError::Invalidated) => {
                        retries = retries.saturating_add(1);
                        if retries >= FAULT_FAST_RETRIES && slow_guard.is_none() {
                            slow_guard = Some(self.fault_retry_lock.lock());
                        }
                        continue;
                    }
                }
            } else {
                None
            };
            let cached_frame = if plan.shared_anon_backed {
                plan.anon_page
                    .and_then(|page| shared_anon_page_cache_get(plan.region.anon_shared_id, page))
            } else {
                file_cache_frame
            };

            let (frame, needs_file_fill) = if let Some(frame) = cached_frame {
                (frame, false)
            } else {
                let Some(frame) = frame_alloc() else {
                    crate::println!("[mm] OOM: lazy fault alloc failed for vpn={:?}", plan.vpn);
                    return LazyFaultResult::Oom;
                };
                (frame, true)
            };

            debug_assert!(!needs_file_fill || !plan.region.file_backed);

            let commit = self
                .lock()
                .commit_lazy_fault(fault_va, access, &plan, &frame, charge_pid);
            match commit {
                LazyFaultCommit::Installed => {
                    // A write fault on a clean MAP_PRIVATE file page follows
                    // Linux do_cow_fault(): copy the page-cache frame into an
                    // anonymous private frame before reporting the write as
                    // resolved.  Read/exec faults keep sharing the clean page.
                    if access.contains(MapPermission::W) && plan.private_file_cow {
                        if self.resolve_cow_fault(fault_va) {
                            return LazyFaultResult::Resolved;
                        }
                        if self.lock().translate(plan.vpn).is_some_and(|pte| {
                            pte.is_valid() && pte.flags().contains(PTEFlags::COW)
                        }) {
                            return LazyFaultResult::Oom;
                        }
                        retries = retries.saturating_add(1);
                        continue;
                    }
                    return LazyFaultResult::Resolved;
                }
                LazyFaultCommit::Resolved => {
                    self.flush_user_page(fault_va);
                    return LazyFaultResult::Resolved;
                }
                LazyFaultCommit::Oom => return LazyFaultResult::Oom,
                LazyFaultCommit::Retry => {
                    retries = retries.saturating_add(1);
                    if retries >= FAULT_FAST_RETRIES && slow_guard.is_none() {
                        slow_guard = Some(self.fault_retry_lock.lock());
                    }
                }
            }
        }
    }

    pub fn try_expand_growsdown(&self, fault_va: usize, access: MapPermission) -> LazyFaultResult {
        {
            let mut memory_set = self.lock();
            let _ = memory_set.expand_growsdown_metadata(fault_va, access);
        }
        // A racing thread may already have expanded the VMA, so always re-run
        // the normal resolver after releasing the metadata lock.
        self.resolve_lazy_fault(fault_va, access)
    }
}
