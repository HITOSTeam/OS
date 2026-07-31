//! 用户地址空间管理。
//!
//! `VmRegion` 记录 mmap/brk/ELF 的语义，
//! `MapArea` 记录已经物化的页，`PageTable` 是硬件最终看到的映射。

use super::elf_loader::{
    ENOMEM, ET_DYN, ElfHeader64, ElfLoadInfo, ElfPhdr64, PF_R, PF_W, PF_X, PT_LOAD, PT_PHDR,
    elf_arch_abi_from_bytes, parse_elf_headers, read_exact_with, validate_elf_arch_abi,
    validate_elf_interp_abi,
};
use super::{FrameTracker, frame_alloc, try_copy_to_user_unchecked};
use super::{PTEFlags, PageTable, PageTableEntry, PageWalkCache};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
#[cfg(target_arch = "loongarch64")]
use crate::arch::loongarch64::mm::AsidContext;
#[cfg(target_arch = "riscv64")]
use crate::arch::riscv64::mm::AsidContext;
#[cfg(target_arch = "riscv64")]
use crate::config::{KERNEL_STACK_TOP, phys_mem_end, phys_mem_start};
use crate::config::{
    MMIO, PAGE_SIZE, SIGRETURN_TRAMPOLINE, TRAMPOLINE, TRAP_CONTEXT, USER_HEAP_GAP,
    USER_STACK_SIZE, for_each_dtb_mmio_range, for_each_phys_mem_range,
};
use crate::fs::File;
use crate::println;
use crate::utils::RecycleAllocator;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
#[cfg(target_arch = "riscv64")]
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::*;
#[cfg(target_arch = "riscv64")]
use riscv::register::satp::{self, Satp};
use spin::Mutex;
unsafe extern "C" {
    safe fn stext();
    safe fn etext();
    safe fn srodata();
    safe fn erodata();
    safe fn sdata();
    safe fn edata();
    safe fn sbss_with_stack();
    safe fn ebss();
    safe fn strampoline();
}

mod backing;
mod fault;
mod file_mmap;
mod layout;
mod map_area;
mod mm_ref;
mod range;
mod rollback;
mod vma;

use backing::MmapBacking;
pub use layout::BrkUpdate;
pub use map_area::{LazyFaultResult, MapPermission, MapType};
use map_area::{MapArea, pte_flags_for_mprotect, shift_vpn_by_delta};
pub use mm_ref::MmRef;
use range::*;
use rollback::{UserRangeRollback, UserRangeSnapshot};
use vma::VmRegionSet;
pub use vma::{VmRegion, VmRegionKind, VmaInsertArea};

static COW_CLONE_DIAG_SEQ: AtomicUsize = AtomicUsize::new(0);
static MMAP_ASLR_SEQ: AtomicUsize = AtomicUsize::new(0);
const DEFAULT_MMAP_BASE: usize = 0x34_0000_0000;
const MMAP_ASLR_RANGE: usize = 256 * 1024 * 1024;

lazy_static! {
    /// a memory set instance through lazy_static! managing kernel space
    pub static ref KERNEL_SPACE: Mutex<MemorySet> = Mutex::new(MemorySet::new_kernel());
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn riscv_satp_asid(token: usize) -> usize {
    (token >> 44) & 0xffff
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn riscv_write_satp_and_flush_asid(token: usize) {
    let asid = riscv_satp_asid(token);
    // SAFETY: `token` is a kernel-created SATP value. Using a non-x0 rs2 keeps
    // RISC-V global mappings valid while flushing non-global entries for this ASID.
    unsafe {
        satp::write(Satp::from_bits(token));
        asm!("sfence.vma x0, {asid}", asid = in(reg) asid, options(nostack));
    }
}

pub(crate) fn update_shared_file_page_cache(dev: usize, ino: u32, write_off: usize, data: &[u8]) {
    backing::shared_file_page_cache_write(dev, ino, write_off, data);
}

pub(crate) fn resize_shared_file_page_cache(dev: usize, ino: u32, file_size: usize) {
    backing::shared_file_page_cache_resize(dev, ino, file_size);
}

pub(crate) fn reclaim_shared_file_page_cache() -> usize {
    backing::shared_file_page_cache_reclaim_unreferenced()
}

pub(crate) fn allocate_shared_anon_id() -> u64 {
    backing::allocate_shared_anon_id()
}

/// memory set structure, controls virtual-memory space
pub struct MemorySet {
    /// 页表是真正给硬件使用的映射结果。
    page_table: PageTable,
    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    asid: Arc<AsidContext>,
    /// 已物化页的跟踪表，包括 frame、COW 和 PROT_NONE 保存的 PTE 标志。
    areas: Vec<MapArea>,
    /// 用户态 VMA 的权威元数据，类似 Linux mm_struct 里的 VMA 集合。
    vm_regions: VmRegionSet,
    /// System V shared memory attachments owned by this address space.
    sysv_shm_attaches: Vec<ShmAttach>,
    mmap_backings: BTreeMap<usize, MmapBacking>,
    next_mmap_backing_id: usize,
    heap_start: usize,
    brk: usize,
    mmap_next: usize,
    mmap_topdown_cursor: usize,
    mmap_aslr_offset: usize,
    /// Virtual ranges currently locked by mlock/mlockall.
    mlocked_ranges: Vec<(usize, usize)>,
    /// Whether MCL_FUTURE is enabled for this address space.
    mlockall_future: bool,
    /// Mm-local trap-context VA slot allocator. Linux-style CLONE_VM needs this
    /// to be tied to the address space rather than to per-PCB thread indexes.
    trap_context_slots: RecycleAllocator,
    /// RISC-V user page tables share kernel-only root entries with KERNEL_SPACE.
    /// These mappings are intentionally not represented in `areas`, otherwise
    /// fork/COW would walk the whole physical direct map for every child.
    #[cfg(target_arch = "riscv64")]
    has_user_kernel_mappings: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MprotectError {
    AccessDenied,
    Unmapped,
}

fn sort_map_areas(areas: &mut [MapArea]) {
    areas.sort_unstable_by_key(|area| area.start_vpn().0);
}

fn vm_region_map_area_type_compatible(region: &VmRegion, area: &MapArea) -> bool {
    area.map_type() == region.map_type
        || (region.can_have_lazy_concrete() && area.map_type() == MapType::Lazy)
}

#[cfg(debug_assertions)]
fn pte_flags_executable(flags: PTEFlags) -> bool {
    #[cfg(target_arch = "riscv64")]
    {
        flags.contains(PTEFlags::X)
    }
    #[cfg(target_arch = "loongarch64")]
    {
        !flags.contains(PTEFlags::NX)
    }
}

#[cfg(debug_assertions)]
fn debug_assert_resident_pte_matches_region(region: &VmRegion, va: usize, flags: PTEFlags) {
    debug_assert!(
        va < region.sigbus_start(),
        "resident PTE exists in VmRegion SIGBUS tail: va={:#x}, region={:#x}..{:#x}, sigbus={:#x}",
        va,
        region.start,
        region.end(),
        region.sigbus_start()
    );
    debug_assert!(
        flags.contains(PTEFlags::U),
        "resident user frame has non-user PTE at {:#x}",
        va
    );
    if !region.map_permission().contains(MapPermission::W) {
        debug_assert!(
            !flags.contains(PTEFlags::W),
            "non-writable VmRegion has writable resident PTE at {:#x}",
            va
        );
    }
    if !region.map_permission().contains(MapPermission::X) {
        debug_assert!(
            !pte_flags_executable(flags),
            "non-executable VmRegion has executable resident PTE at {:#x}",
            va
        );
    }
    if flags.contains(PTEFlags::COW) {
        debug_assert!(
            !flags.contains(PTEFlags::W),
            "COW PTE is still writable at {:#x}",
            va
        );
        debug_assert!(
            !flags.contains(PTEFlags::SHARED),
            "PTE is both COW and SHARED at {:#x}",
            va
        );
    }
    if flags.contains(PTEFlags::SHARED) {
        debug_assert!(
            region.shared,
            "SHARED PTE is not covered by a shared VmRegion at {:#x}",
            va
        );
    }
}

#[cfg(debug_assertions)]
fn debug_assert_saved_pte_flags_match_region(region: &VmRegion, va: usize, flags: PTEFlags) {
    if flags.contains(PTEFlags::COW) {
        debug_assert!(
            !flags.contains(PTEFlags::SHARED),
            "saved PTE flags are both COW and SHARED at {:#x}",
            va
        );
    }
    if flags.contains(PTEFlags::SHARED) {
        debug_assert!(
            region.shared,
            "saved SHARED PTE flags are not covered by a shared VmRegion at {:#x}",
            va
        );
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ElfAux {
    pub phdr: usize,
    pub phent: usize,
    pub phnum: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct ShmAttach {
    pub ipc_ns_id: usize,
    pub addr: usize,
    pub shmid: usize,
    pub len: usize,
    pub attach_id: usize,
    pub accounted: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ShmAttachRef {
    pub ipc_ns_id: usize,
    pub shmid: usize,
}

impl ShmAttach {
    pub fn end(&self) -> usize {
        self.addr.saturating_add(self.len)
    }

    pub fn contains_range(&self, start: usize, len: usize) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        start >= self.addr && end <= self.end()
    }
}

impl MemorySet {
    #[cfg(target_arch = "riscv64")]
    const RISCV_ROOT_ENTRY_SIZE: usize = 1 << 30;
    #[cfg(target_arch = "riscv64")]
    const RISCV_SHARED_KSTACK_ROOT_COUNT: usize = 1;

    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            asid: Arc::new(AsidContext::new()),
            areas: Vec::new(),
            vm_regions: VmRegionSet::new(),
            sysv_shm_attaches: Vec::new(),
            mmap_backings: BTreeMap::new(),
            next_mmap_backing_id: 1,
            heap_start: 0,
            brk: 0,
            mmap_next: DEFAULT_MMAP_BASE,
            mmap_topdown_cursor: 0,
            mmap_aslr_offset: next_mmap_aslr_offset(),
            mlocked_ranges: Vec::new(),
            mlockall_future: false,
            trap_context_slots: RecycleAllocator::new(),
            #[cfg(target_arch = "riscv64")]
            has_user_kernel_mappings: false,
        }
    }
    pub fn token(&self) -> usize {
        self.page_table.token()
    }

    #[cfg(target_arch = "loongarch64")]
    pub fn flush_user_tlb(&self) {
        crate::arch::loongarch64::mm::drop_user_asid(self.asid.as_ref());
    }

    #[cfg(target_arch = "riscv64")]
    pub fn flush_user_tlb(&self) {
        crate::arch::riscv64::mm::flush_user_all(self.asid.as_ref());
        crate::arch::riscv64::mm::mark_icache_stale(self.asid.as_ref());
    }

    #[cfg(target_arch = "loongarch64")]
    pub fn flush_user_page(&self, va: usize) {
        crate::arch::loongarch64::mm::flush_user_page(self.asid.as_ref(), va);
    }

    #[cfg(target_arch = "riscv64")]
    pub fn flush_user_page(&self, va: usize) {
        crate::arch::riscv64::mm::flush_user_page(self.asid.as_ref(), va);
    }

    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    pub fn flush_local_user_page(&self, va: usize) {
        #[cfg(target_arch = "loongarch64")]
        crate::arch::loongarch64::mm::flush_local_user_page(self.asid.as_ref(), va);
        #[cfg(target_arch = "riscv64")]
        crate::arch::riscv64::mm::flush_local_user_page(self.asid.as_ref(), va);
    }

    #[cfg(target_arch = "riscv64")]
    pub fn flush_user_tlb_all(&self) {
        crate::arch::riscv64::mm::flush_user_all(self.asid.as_ref());
    }

    fn inherit_user_vm_metadata_from(&mut self, parent: &MemorySet) {
        self.vm_regions = parent.vm_regions.clone();
        self.vm_regions.mark_fork_inherited_anonymous_mmap();
        self.sysv_shm_attaches = parent.sysv_shm_attaches.clone();
        self.mmap_backings = parent.mmap_backings.clone();
        self.next_mmap_backing_id = parent.next_mmap_backing_id;
        self.heap_start = parent.heap_start;
        self.brk = parent.brk;
        self.mmap_next = parent.mmap_next;
        self.mmap_topdown_cursor = parent.mmap_topdown_cursor;
        self.mmap_aslr_offset = parent.mmap_aslr_offset;
        self.trap_context_slots = parent.trap_context_slots.clone();
        // Do not inherit mlock/mlockall state across fork-style address-space
        // cloning; Linux clears memory locks in the child.
        self.debug_assert_user_vm_invariants();
    }

    pub fn sysv_shm_attaches_snapshot(&self) -> Vec<ShmAttach> {
        self.sysv_shm_attaches.clone()
    }

    pub fn replace_sysv_shm_attaches(&mut self, attaches: Vec<ShmAttach>) {
        self.sysv_shm_attaches = attaches;
    }

    pub fn push_sysv_shm_attach(&mut self, attach: ShmAttach) {
        self.sysv_shm_attaches.push(attach);
    }

    pub fn take_sysv_shm_attaches(&mut self) -> Vec<ShmAttach> {
        core::mem::take(&mut self.sysv_shm_attaches)
    }

    pub fn remove_sysv_shm_attach(&mut self, shmaddr: usize) -> Option<(ShmAttach, bool)> {
        let (idx, attach) = self
            .sysv_shm_attaches
            .iter()
            .enumerate()
            .find(|(_i, attach)| attach.addr == shmaddr)
            .map(|(i, attach)| (i, *attach))?;

        self.sysv_shm_attaches.remove(idx);
        let transferred_account = if attach.accounted {
            if let Some(next) = self
                .sysv_shm_attaches
                .iter_mut()
                .find(|next| next.attach_id == attach.attach_id)
            {
                next.accounted = true;
                true
            } else {
                false
            }
        } else {
            false
        };
        Some((attach, transferred_account))
    }

    pub fn alloc_trap_context_slot(&mut self) -> usize {
        self.trap_context_slots.alloc()
    }

    pub fn reserve_trap_context_slot(&mut self, slot: usize) {
        self.trap_context_slots.reserve(slot);
    }

    pub fn dealloc_trap_context_slot(&mut self, slot: usize) {
        self.trap_context_slots.dealloc(slot);
    }

    fn try_insert_initial_trap_context(&mut self) -> bool {
        let slot = self.alloc_trap_context_slot();
        debug_assert_eq!(slot, 0, "initial TrapContext must use mm slot 0");
        let ok = self.try_push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                SIGRETURN_TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        if !ok {
            self.dealloc_trap_context_slot(slot);
        }
        ok
    }

    fn sort_user_areas(&mut self) {
        sort_map_areas(&mut self.areas);
    }

    /// 简单的测试函数
    #[cfg(debug_assertions)]
    fn debug_assert_user_vm_invariants(&self) {
        let mut prev_area_end = VirtPageNum(0);
        for area in self.areas.iter() {
            let start = area.start_vpn();
            let end = area.end_vpn();
            debug_assert!(
                start >= prev_area_end,
                "MapArea list is not sorted or overlaps: prev_end={:#x}, start={:#x}, end={:#x}",
                prev_area_end.0.saturating_mul(PAGE_SIZE),
                start.0.saturating_mul(PAGE_SIZE),
                end.0.saturating_mul(PAGE_SIZE)
            );
            debug_assert!(start <= end, "MapArea has inverted VPN range");
            if area.is_identical() {
                debug_assert!(
                    area.tracked_frame_count() == 0,
                    "Identical MapArea must not own frame trackers"
                );
            }
            for vpn in area.tracked_vpns() {
                debug_assert!(
                    vpn >= start && vpn < end,
                    "MapArea frame tracker outside owning range"
                );
            }
            for vpn in area.saved_flag_vpns() {
                debug_assert!(
                    vpn >= start && vpn < end,
                    "MapArea saved PTE flags outside owning range"
                );
            }
            prev_area_end = end;
        }

        let allowed_perm_bits = MapPermission::all().bits();
        let mut prev_region_end = 0usize;
        for region in self.vm_regions.iter() {
            let end = region.end();
            debug_assert!(region.len > 0, "VmRegion must not be empty");
            debug_assert!(end > region.start, "VmRegion end wrapped");
            debug_assert!(
                region.start >= prev_region_end,
                "VmRegion list is not sorted or overlaps: prev_end={:#x}, start={:#x}, end={:#x}",
                prev_region_end,
                region.start,
                end
            );
            debug_assert!(
                region.map_perm.bits() & !allowed_perm_bits == 0,
                "VmRegion has unknown MapPermission bits"
            );
            debug_assert!(
                region.map_permission().contains(MapPermission::U),
                "VmRegion must describe a user mapping"
            );
            debug_assert!(
                region.file_valid_len <= region.len,
                "VmRegion file_valid_len exceeds mapping length"
            );
            debug_assert!(
                region.sigbus_start >= region.start && region.sigbus_start <= end,
                "VmRegion SIGBUS tail marker outside mapping"
            );
            let has_external_backing =
                region.file_backed || region.memfd_id != 0 || region.sysv_shmid != 0;
            if region.file_backed || region.memfd_id != 0 {
                debug_assert!(
                    region.backing_id != 0,
                    "file-backed or shared-object VmRegion must keep a backing id"
                );
                let backing = self.mmap_backings.get(&region.backing_id);
                debug_assert!(
                    backing.is_some(),
                    "VmRegion references missing mmap backing id {}",
                    region.backing_id
                );
                if let Some(backing) = backing {
                    debug_assert!(
                        backing.kind.matches_region(region),
                        "VmRegion backing id {} points at mismatched backing identity",
                        region.backing_id
                    );
                }
            } else if !has_external_backing {
                if region.shared {
                    debug_assert_ne!(
                        region.anon_shared_id, 0,
                        "shared anonymous VmRegion must keep an anon_shared_id"
                    );
                } else {
                    debug_assert_eq!(
                        region.anon_shared_id, 0,
                        "private anonymous VmRegion must not keep an anon_shared_id"
                    );
                }
                debug_assert_eq!(
                    region.sigbus_start, end,
                    "anonymous VmRegion should not carry a SIGBUS tail"
                );
                debug_assert!(
                    region.file_valid_len == 0 || region.file_valid_len == region.len,
                    "anonymous VmRegion should not carry a partial file_valid_len"
                );
            }
            prev_region_end = end;
        }
        for backing_id in self.mmap_backings.keys().copied() {
            debug_assert!(
                self.vm_regions.iter().any(|region| {
                    (region.file_backed || region.memfd_id != 0) && region.backing_id == backing_id
                }),
                "mmap backing id {} is not referenced by any VmRegion",
                backing_id
            );
        }
        let backing_identities = self
            .mmap_backings
            .iter()
            .map(|(&backing_id, backing)| (backing_id, backing.kind))
            .collect::<Vec<_>>();
        for (idx, (left_id, left_kind)) in backing_identities.iter().enumerate() {
            for (right_id, right_kind) in backing_identities.iter().skip(idx + 1) {
                debug_assert_ne!(
                    left_kind, right_kind,
                    "duplicate mmap backing identity: ids {} and {} both {:?}",
                    left_id, right_id, left_kind
                );
            }
        }
        for (backing_id, backing) in self.mmap_backings.iter() {
            let expected_vm_state = self.collect_mmap_backing_vm_state(*backing_id);
            debug_assert_eq!(
                backing.vm_state, expected_vm_state,
                "mmap backing id {} has stale VmRegion lifecycle state",
                backing_id
            );
            for (&file_page, state) in backing.resident_pages.iter() {
                debug_assert!(
                    state.ref_count > 0,
                    "mmap backing id {} has zero resident refcount for file page {}",
                    backing_id,
                    file_page
                );
                let file_page_start = file_page.saturating_mul(PAGE_SIZE);
                let file_page_end = file_page_start.saturating_add(PAGE_SIZE);
                debug_assert!(
                    self.vm_regions.iter().any(|region| {
                        if region.backing_id != *backing_id {
                            return false;
                        }
                        let valid_start = region.file_offset;
                        let valid_end = region.file_offset.saturating_add(region.file_valid_len());
                        file_page_start < valid_end && file_page_end > valid_start
                    }),
                    "mmap backing id {} has resident file page {} without VMA coverage",
                    backing_id,
                    file_page
                );
            }
        }

        for region in self.vm_regions.iter() {
            let checked_start = region.start;
            let checked_end = core::cmp::min(region.end(), region.sigbus_start());
            if checked_start >= checked_end {
                continue;
            }

            let mut cursor = checked_start;
            for area in self.areas.iter() {
                if !area.contains_perm(MapPermission::U) {
                    continue;
                }
                let area_start = area.start_vpn().0.saturating_mul(PAGE_SIZE);
                let area_end = area.end_vpn().0.saturating_mul(PAGE_SIZE);
                if area_end <= cursor {
                    continue;
                }
                if area_start >= checked_end {
                    break;
                }
                debug_assert!(
                    area_start <= cursor,
                    "VmRegion has a gap in MapArea coverage: region={:#x}..{:#x}, cursor={:#x}, area={:#x}..{:#x}",
                    checked_start,
                    checked_end,
                    cursor,
                    area_start,
                    area_end
                );
                if cursor < region.sigbus_start() {
                    debug_assert_eq!(
                        area.map_perm(),
                        region.map_permission(),
                        "VmRegion/MapArea permission drift at {:#x}",
                        cursor
                    );
                    debug_assert!(
                        vm_region_map_area_type_compatible(region, area),
                        "VmRegion/MapArea mapping type drift at {:#x}: area={:?}, region={:?}",
                        cursor,
                        area.map_type(),
                        region.map_type
                    );
                }
                cursor = core::cmp::min(area_end, checked_end);
                if cursor >= checked_end {
                    break;
                }
            }
            debug_assert!(
                cursor >= checked_end,
                "VmRegion tail is missing MapArea coverage: region={:#x}..{:#x}, cursor={:#x}",
                checked_start,
                checked_end,
                cursor
            );
        }

        for area in self.areas.iter() {
            if !area.contains_perm(MapPermission::U) {
                continue;
            }
            let checked_start = area.start_vpn().0.saturating_mul(PAGE_SIZE);
            let checked_end = area.end_vpn().0.saturating_mul(PAGE_SIZE);
            if checked_start >= checked_end {
                continue;
            }

            let mut cursor = checked_start;
            for region in self.vm_regions.iter() {
                let region_end = region.end();
                if region_end <= cursor {
                    continue;
                }
                if region.start >= checked_end {
                    break;
                }
                debug_assert!(
                    region.start <= cursor,
                    "User MapArea has a gap in VmRegion coverage: area={:#x}..{:#x}, cursor={:#x}, region={:#x}..{:#x}",
                    checked_start,
                    checked_end,
                    cursor,
                    region.start,
                    region_end
                );
                if cursor < region.sigbus_start() {
                    debug_assert_eq!(
                        area.map_perm(),
                        region.map_permission(),
                        "MapArea/VmRegion permission drift at {:#x}",
                        cursor
                    );
                    debug_assert!(
                        vm_region_map_area_type_compatible(region, area),
                        "MapArea/VmRegion mapping type drift at {:#x}: area={:?}, region={:?}",
                        cursor,
                        area.map_type(),
                        region.map_type
                    );
                }
                cursor = core::cmp::min(region_end, checked_end);
                if cursor >= checked_end {
                    break;
                }
            }
            debug_assert!(
                cursor >= checked_end,
                "User MapArea is missing VmRegion coverage: area={:#x}..{:#x}, cursor={:#x}",
                checked_start,
                checked_end,
                cursor
            );
        }

        for area in self.areas.iter() {
            if !area.contains_perm(MapPermission::U) {
                continue;
            }
            for (vpn, _) in area.tracked_frames() {
                let va = vpn.0.saturating_mul(PAGE_SIZE);
                let Some(region) = self.vm_region_containing_addr(va) else {
                    debug_assert!(false, "tracked user frame is missing VmRegion coverage");
                    continue;
                };
                if let Some(pte) = self.page_table.translate(vpn) {
                    if pte.is_valid() {
                        debug_assert_resident_pte_matches_region(&region, va, pte.flags());
                        continue;
                    }
                }
                debug_assert!(
                    area.has_saved_pte_flags(vpn),
                    "tracked user frame has neither a resident PTE nor saved PROT_NONE flags at {:#x}",
                    va
                );
            }
            for (vpn, flags) in area.saved_flag_entries() {
                let va = vpn.0.saturating_mul(PAGE_SIZE);
                if let Some(pte) = self.page_table.translate(vpn) {
                    debug_assert!(
                        !pte.is_valid(),
                        "saved PROT_NONE flags coexist with a valid PTE at {:#x}",
                        va
                    );
                }
                let Some(region) = self.vm_region_containing_addr(va) else {
                    debug_assert!(false, "saved PROT_NONE flags are missing VmRegion coverage");
                    continue;
                };
                debug_assert_saved_pte_flags_match_region(&region, va, flags);
            }
        }
    }

    #[cfg(not(debug_assertions))]
    fn debug_assert_user_vm_invariants(&self) {}

    pub fn mlockall_future(&self) -> bool {
        self.mlockall_future
    }

    pub fn set_mlockall_future(&mut self, enabled: bool) {
        self.mlockall_future = enabled;
    }

    pub fn locked_bytes(&self) -> usize {
        ranges_total_len(&self.mlocked_ranges)
    }

    pub fn locked_overlap_bytes(&self, start: usize, end: usize) -> usize {
        self.mlocked_ranges
            .iter()
            .map(|(lock_start, lock_end)| range_overlap_len(start, end, *lock_start, *lock_end))
            .sum()
    }

    pub fn locked_ranges_overlap(&self, start: usize, end: usize) -> bool {
        ranges_overlap(&self.mlocked_ranges, start, end)
    }

    pub fn locked_bytes_after_add(&self, start: usize, end: usize) -> usize {
        let mut next = self.mlocked_ranges.clone();
        next.push((start, end));
        normalize_ranges(&mut next);
        ranges_total_len(&next)
    }

    pub fn add_locked_range(&mut self, start: usize, end: usize) {
        self.mlocked_ranges.push((start, end));
        normalize_ranges(&mut self.mlocked_ranges);
    }

    pub fn trim_locked_ranges(&mut self, start: usize, end: usize) {
        trim_ranges(&mut self.mlocked_ranges, start, end);
    }

    pub fn move_locked_ranges(&mut self, old_addr: usize, old_len: usize, new_start: usize) {
        let old_end = old_addr.saturating_add(old_len);
        if old_end <= old_addr {
            return;
        }
        let mut next = Vec::new();
        for (lock_start, lock_end) in self.mlocked_ranges.drain(..) {
            if old_end <= lock_start || old_addr >= lock_end {
                next.push((lock_start, lock_end));
                continue;
            }
            if old_addr > lock_start {
                next.push((lock_start, old_addr));
            }
            let overlap_start = core::cmp::max(lock_start, old_addr);
            let overlap_end = core::cmp::min(lock_end, old_end);
            let moved_start = new_start.saturating_add(overlap_start.saturating_sub(old_addr));
            let moved_end = new_start.saturating_add(overlap_end.saturating_sub(old_addr));
            next.push((moved_start, moved_end));
            if old_end < lock_end {
                next.push((old_end, lock_end));
            }
        }
        normalize_ranges(&mut next);
        self.mlocked_ranges = next;
    }

    fn locked_ranges_with_current_mappings(&self) -> Vec<(usize, usize)> {
        let mut next = self.mlocked_ranges.clone();
        for (start, end) in self.user_mapped_ranges() {
            next.push((start, end));
        }
        if next.is_empty() {
            next.push((self.heap_start, self.heap_start.saturating_add(PAGE_SIZE)));
        }
        normalize_ranges(&mut next);
        next
    }

    pub fn locked_bytes_after_mlockall_current(&self) -> usize {
        let next = self.locked_ranges_with_current_mappings();
        ranges_total_len(&next)
    }

    pub fn lock_current_mappings(&mut self) {
        self.mlocked_ranges = self.locked_ranges_with_current_mappings();
    }

    pub fn clear_mlock_state(&mut self) {
        self.mlocked_ranges.clear();
        self.mlockall_future = false;
    }

    pub fn vm_regions_snapshot(&self) -> Vec<VmRegion> {
        self.vm_regions.to_vec()
    }

    pub fn vm_regions_total_len(&self) -> usize {
        self.vm_regions
            .iter()
            .filter(|region| region.is_mmap())
            .map(|region| region.len)
            .sum()
    }

    pub fn anon_private_writable_vm_bytes(&self) -> usize {
        self.vm_regions.iter().fold(0usize, |sum, region| {
            if region.is_mmap()
                && Self::vm_region_is_private_anonymous(*region)
                && region.map_permission().contains(MapPermission::W)
            {
                sum.saturating_add(region.len)
            } else {
                sum
            }
        })
    }

    pub fn vm_regions_overlap(&self, start: usize, end: usize) -> bool {
        self.vm_regions.overlaps_range(start, end)
    }

    fn vm_region_containing_addr(&self, addr: usize) -> Option<VmRegion> {
        self.vm_regions.containing_addr(addr)
    }

    pub fn shared_vm_region_overlaps(&self, start: usize, end: usize) -> bool {
        self.vm_regions
            .any_overlap_where(start, end, |region| region.shared)
    }

    fn vm_region_is_private_anonymous(region: VmRegion) -> bool {
        region.is_private_anonymous()
    }

    pub fn vm_range_is_private_anonymous(&self, start: usize, end: usize) -> bool {
        if !self.vm_regions.covers_range(start, end) {
            return false;
        }
        self.vm_regions
            .snapshot_range(start, end)
            .into_iter()
            .all(Self::vm_region_is_private_anonymous)
    }

    fn push_vm_region_raw(&mut self, region: VmRegion) {
        self.vm_regions.push_merged(region);
    }

    pub fn push_vm_region(&mut self, region: VmRegion) {
        // VMA 新增后统一合并，并刷新 file backing 的派生状态。
        let backing_id = region.backing_id;
        self.push_vm_region_raw(region);
        if backing_id != 0 {
            self.refresh_mmap_backing_state(backing_id);
        }
        self.debug_assert_user_vm_invariants();
    }

    #[cfg(debug_assertions)]
    fn debug_assert_range_has_no_resident_pages(&self, start: usize, end: usize) {
        let start_vpn = VirtAddr::from(start).floor();
        let end_vpn = VirtAddr::from(end).ceil();
        for area in self
            .areas
            .iter()
            .filter(|area| area.overlaps_vpn_range(start_vpn, end_vpn))
        {
            let ov_start = core::cmp::max(start_vpn, area.start_vpn());
            let ov_end = core::cmp::min(end_vpn, area.end_vpn());
            for vpn in VPNRange::new(ov_start, ov_end) {
                debug_assert!(
                    area.tracked_frame(vpn).is_none(),
                    "new lazy VMA range unexpectedly owns a resident frame"
                );
                debug_assert!(
                    !area.has_saved_pte_flags(vpn),
                    "new lazy VMA range unexpectedly owns saved PTE flags"
                );
                if let Some(pte) = self.page_table.translate(vpn) {
                    debug_assert!(
                        !pte.is_valid(),
                        "new lazy VMA range unexpectedly has a valid PTE"
                    );
                }
            }
        }
    }

    #[cfg(not(debug_assertions))]
    fn debug_assert_range_has_no_resident_pages(&self, _start: usize, _end: usize) {}

    fn static_user_region(
        kind: VmRegionKind,
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
    ) -> Option<VmRegion> {
        if !map_perm.contains(MapPermission::U) {
            return None;
        }
        let start = start_va.floor().0.saturating_mul(PAGE_SIZE);
        let end = end_va.ceil().0.saturating_mul(PAGE_SIZE);
        if end <= start {
            return None;
        }
        let len = end - start;
        Some(VmRegion {
            kind,
            start,
            len,
            prot: VmRegion::prot_from_permission(map_perm),
            map_type,
            map_perm,
            file_valid_len: len,
            sigbus_start: end,
            shared: false,
            may_write_upgrade: true,
            file_backed: false,
            file_dev: 0,
            file_ino: 0,
            file_offset: 0,
            backing_id: 0,
            memfd_id: 0,
            anon_shared_id: 0,
            sysv_shmid: 0,
            growsdown: false,
            fork_inherited_anon: false,
        })
    }

    fn try_insert_static_user_framed_range(
        &mut self,
        kind: VmRegionKind,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
        data: Option<&[u8]>,
    ) -> Option<VirtPageNum> {
        let region = Self::static_user_region(kind, start_va, end_va, MapType::Framed, permission);
        let map_area = MapArea::new(start_va, end_va, MapType::Framed, permission);
        let end_vpn = map_area.end_vpn();
        if map_area.start_vpn() >= map_area.end_vpn() {
            return Some(end_vpn);
        }
        if !self.try_push_raw(map_area, data) {
            return None;
        }
        if let Some(region) = region {
            self.push_vm_region(region);
        } else {
            self.debug_assert_user_vm_invariants();
        }
        Some(end_vpn)
    }

    /// 在空闲范围内插入一个新 VMA（VmRegion + MapArea）。
    /// 若目标范围与任何已有映射重叠则返回 false，不做任何修改。
    pub fn try_insert_user_vma(
        &mut self,
        region: VmRegion,
        areas: Vec<VmaInsertArea>,
        lock_range: bool,
        backing_file: Option<&Arc<dyn File + Send + Sync>>,
    ) -> bool {
        self.try_insert_user_vma_with(region, areas, lock_range, backing_file, |_| true)
    }

    /// 同 try_insert_user_vma，但插入成功后额外执行 post_insert 回调（如预填充文件内容）。
    /// 回调返回 false 时回滚整个插入。
    pub fn try_insert_user_vma_with<F>(
        &mut self,
        region: VmRegion,
        areas: Vec<VmaInsertArea>,
        lock_range: bool,
        backing_file: Option<&Arc<dyn File + Send + Sync>>,
        post_insert: F,
    ) -> bool
    where
        F: FnOnce(&mut Self) -> bool,
    {
        // syscall 层只描述 VMA；这里负责同时建立 VMA 元数据和具体 MapArea。
        let start = region.start;
        let end = region.end();
        // 重叠 （包括 已有 area + vma ) 以及 合法性检查
        let invalid = end <= start;
        let concrete_overlap = if cfg!(debug_assertions) {
            self.concrete_range_overlaps(start.into(), end.into())
        } else {
            false
        };
        let vma_overlap = self.vm_regions_overlap(start, end);
        let count_after = self.vm_regions.count_after_insert_merged(region);
        let max_map_count = crate::fs::vm_max_map_count();
        let compatible = areas
            .iter()
            .all(|area| area.compatible_with_region(&region));
        let max_count_failure_point = max_map_count.saturating_add(1);
        if invalid
            || concrete_overlap
            || vma_overlap
            || count_after > max_count_failure_point
            || !compatible
        {
            return false;
        }
        let needs_backing = region.file_backed || region.memfd_id != 0;
        if needs_backing && backing_file.is_none() {
            return false;
        }

        // 回滚机制，用来 在
        // 1. 插入vma 失败 恢复
        // 2. post 函数处理 失败恢复
        let rollback = UserRangeRollback::capture(self, &[(start, end)]);
        if !self.try_insert_user_vma_raw(region, areas, lock_range, backing_file) {
            rollback.restore(self);
            return false;
        }
        if post_insert(self) {
            return true;
        }
        rollback.restore(self);
        false
    }

    fn try_insert_user_vma_raw(
        &mut self,
        mut region: VmRegion,
        areas: Vec<VmaInsertArea>,
        lock_range: bool,
        backing_file: Option<&Arc<dyn File + Send + Sync>>,
    ) -> bool {
        let start = region.start;
        let end = region.end();
        for area in areas {
            let Some(area_permission) = area.concrete_permission_from_region(&region) else {
                return false;
            };
            let inserted = match area {
                VmaInsertArea::Lazy {
                    start: area_start,
                    end: area_end,
                } => {
                    if area_end <= area_start {
                        true
                    } else if area_start < start || area_end > end {
                        false
                    } else {
                        self.try_insert_lazy_area_raw(
                            area_start.into(),
                            area_end.into(),
                            area_permission,
                        )
                    }
                }
                VmaInsertArea::Framed {
                    start: area_start,
                    end: area_end,
                } => {
                    if area_end <= area_start {
                        true
                    } else if area_start < start || area_end > end {
                        false
                    } else {
                        self.try_insert_framed_area_raw(
                            area_start.into(),
                            area_end.into(),
                            area_permission,
                        )
                    }
                }
                VmaInsertArea::SharedFrames {
                    start: area_start,
                    end: area_end,
                    frames,
                } => {
                    if area_end <= area_start {
                        frames.is_empty()
                    } else if area_start < start || area_end > end {
                        false
                    } else {
                        self.try_insert_shared_frames_area_raw(
                            area_start.into(),
                            area_end.into(),
                            area_permission,
                            frames,
                        )
                    }
                }
            };
            if !inserted {
                return false;
            }
        }

        if region.file_backed || region.memfd_id != 0 {
            region.backing_id = self.allocate_mmap_backing(&region, backing_file);
            if region.backing_id == 0 {
                return false;
            }
        }
        let backing_id = region.backing_id;
        let lazy_backing_insert = backing_id != 0 && region.map_type == MapType::Lazy;
        self.push_vm_region_raw(region);
        if backing_id != 0 {
            if lazy_backing_insert {
                self.debug_assert_range_has_no_resident_pages(start, end);
                self.refresh_mmap_backing_vm_state(backing_id);
            } else {
                self.refresh_mmap_backing_state(backing_id);
            }
        }
        if lock_range {
            self.add_locked_range(start, end);
        }
        self.debug_assert_user_vm_invariants();
        true
    }

    /// 对 [start, end) 范围内的用户映射拍快照，供回滚使用。
    /// 快照内容包括：
    /// - 与该范围重叠的 MapArea（裁剪到范围边界）及其 PTE；
    /// - 与该范围重叠的 VmRegion；
    /// - 这些 VmRegion 对应的 mmap backing 条目；
    /// - 与该范围重叠的 mlock 区段。
    fn snapshot_user_range(&self, start: usize, end: usize) -> UserRangeSnapshot {
        let start_vpn = VirtAddr::from(start).floor();
        let end_vpn = VirtAddr::from(end).ceil();
        let mut areas = Vec::new();
        let mut ptes = Vec::new();

        // 提取重合的 MapArea
        for area in self.areas.iter() {
            if !area.contains_perm(MapPermission::U) {
                continue;
            }
            if !area.overlaps_vpn_range(start_vpn, end_vpn) {
                continue;
            }
            let ov_start = core::cmp::max(start_vpn, area.start_vpn());
            let ov_end = core::cmp::min(end_vpn, area.end_vpn());
            if ov_start >= ov_end {
                continue;
            }
            for vpn in VPNRange::new(ov_start, ov_end) {
                if let Some(pte) = self.page_table.translate(vpn) {
                    if pte.is_valid() {
                        ptes.push((vpn, pte.ppn(), pte.flags()));
                    }
                }
            }
            let (_left, mid, _right) = area.clone().split_around(ov_start, ov_end);
            areas.push(mid);
        }

        let vm_regions = self.vm_regions.snapshot_range(start, end);
        let mut backing_entries = Vec::new();
        for region in vm_regions.iter() {
            if !(region.file_backed || region.memfd_id != 0) || region.backing_id == 0 {
                continue;
            }
            if backing_entries
                .iter()
                .any(|(backing_id, _file)| *backing_id == region.backing_id)
            {
                continue;
            }
            if let Some(backing) = self.mmap_backings.get(&region.backing_id) {
                backing_entries.push((region.backing_id, backing.clone()));
            }
        }

        let locked_ranges = self
            .mlocked_ranges
            .iter()
            .copied()
            .filter_map(|(lock_start, lock_end)| {
                let ov_start = core::cmp::max(start, lock_start);
                let ov_end = core::cmp::min(end, lock_end);
                (ov_start < ov_end).then_some((ov_start, ov_end))
            })
            .collect();

        UserRangeSnapshot {
            start,
            end,
            areas,
            vm_regions,
            locked_ranges,
            ptes,
            backing_entries,
            next_mmap_backing_id: self.next_mmap_backing_id,
        }
    }

    fn restore_user_range(&mut self, snapshot: UserRangeSnapshot) {
        self.unmap_user_vma_range(snapshot.start.into(), snapshot.end.into());

        self.areas.extend(snapshot.areas);
        self.sort_user_areas();
        for (vpn, ppn, flags) in snapshot.ptes {
            self.page_table.map(vpn, ppn, flags);
        }

        for region in snapshot.vm_regions {
            self.vm_regions.push_merged(region);
        }

        for (backing_id, backing) in snapshot.backing_entries {
            self.mmap_backings.insert(backing_id, backing);
        }
        self.mlocked_ranges.extend(snapshot.locked_ranges);
        normalize_ranges(&mut self.mlocked_ranges);
        let next_live_backing_id = self
            .mmap_backings
            .keys()
            .copied()
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        self.next_mmap_backing_id = snapshot.next_mmap_backing_id.max(next_live_backing_id);
        self.debug_assert_user_vm_invariants();
    }

    /// MAP_FIXED 路径：先拆除目标范围内的所有已有映射，再插入新 VMA。
    /// 插入失败时恢复原有映射（回滚）。
    pub fn try_replace_user_vma(
        &mut self,
        region: VmRegion,
        areas: Vec<VmaInsertArea>,
        lock_range: bool,
        backing_file: Option<&Arc<dyn File + Send + Sync>>,
    ) -> bool {
        self.try_replace_user_vma_with(region, areas, lock_range, backing_file, |_| true)
    }

    /// 同 try_replace_user_vma，但插入成功后额外执行 post_insert 回调。
    /// 回调返回 false 时恢复被拆除的原有映射。
    pub fn try_replace_user_vma_with<F>(
        &mut self,
        region: VmRegion,
        areas: Vec<VmaInsertArea>,
        lock_range: bool,
        backing_file: Option<&Arc<dyn File + Send + Sync>>,
        post_insert: F,
    ) -> bool
    where
        F: FnOnce(&mut Self) -> bool,
    {
        let start = region.start;
        let end = region.end();
        let snapshot = self.snapshot_user_range(start, end);
        self.unmap_user_vma_range(start.into(), end.into());
        if !self.try_insert_user_vma(region, areas, lock_range, backing_file) {
            self.restore_user_range(snapshot);
            return false;
        }
        if post_insert(self) {
            return true;
        }
        self.restore_user_range(snapshot);
        false
    }

    pub fn try_insert_heap_lazy_range(
        &mut self,
        start: usize,
        end: usize,
        permission: MapPermission,
    ) -> bool {
        if end <= start {
            return true;
        }
        let region = VmRegion {
            kind: VmRegionKind::Heap,
            start,
            len: end - start,
            prot: VmRegion::PROT_READ | VmRegion::PROT_WRITE,
            map_type: MapType::Lazy,
            map_perm: permission,
            file_valid_len: end - start,
            sigbus_start: end,
            shared: false,
            may_write_upgrade: true,
            file_backed: false,
            file_dev: 0,
            file_ino: 0,
            file_offset: start.saturating_sub(self.heap_start),
            backing_id: 0,
            memfd_id: 0,
            anon_shared_id: 0,
            sysv_shmid: 0,
            growsdown: false,
            fork_inherited_anon: false,
        };
        self.try_insert_user_vma(
            region,
            Vec::from([VmaInsertArea::Lazy { start, end }]),
            self.mlockall_future(),
            None,
        )
    }

    pub fn try_insert_stack_framed_range(
        &mut self,
        start: usize,
        end: usize,
        permission: MapPermission,
    ) -> bool {
        if end <= start || !permission.contains(MapPermission::U) {
            return false;
        }
        let len = end - start;
        let region = VmRegion {
            kind: VmRegionKind::Stack,
            start,
            len,
            prot: VmRegion::prot_from_permission(permission),
            map_type: MapType::Framed,
            map_perm: permission,
            file_valid_len: len,
            sigbus_start: end,
            shared: false,
            may_write_upgrade: true,
            file_backed: false,
            file_dev: 0,
            file_ino: 0,
            file_offset: 0,
            backing_id: 0,
            memfd_id: 0,
            anon_shared_id: 0,
            sysv_shmid: 0,
            growsdown: false,
            fork_inherited_anon: false,
        };
        self.try_insert_user_vma(
            region,
            Vec::from([VmaInsertArea::Framed { start, end }]),
            self.mlockall_future(),
            None,
        )
    }

    pub fn trim_vm_regions(&mut self, start: usize, end: usize) {
        self.vm_regions.trim_range(start, end);
        self.prune_unused_mmap_backings();
        self.debug_assert_user_vm_invariants();
    }

    pub fn trim_heap_regions(&mut self, start: usize, end: usize) {
        self.vm_regions.trim_heap_range(start, end);
        self.debug_assert_user_vm_invariants();
    }

    pub fn unmap_heap_vma_range(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        let start = start_va.0;
        let end = end_va.0;
        self.unmap_user_range(start_va, end_va);
        self.trim_heap_regions(start, end);
        self.trim_locked_ranges(start, end);
    }

    pub fn unmap_user_vma_range(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        let start = start_va.0;
        let end = end_va.0;
        self.unmap_user_range(start_va, end_va);
        self.trim_vm_regions(start, end);
        self.trim_locked_ranges(start, end);
    }

    pub fn can_mprotect_vm_regions(&self, start: usize, end: usize, new_prot: usize) -> bool {
        self.vm_regions.can_mprotect_range(start, end, new_prot)
    }

    pub fn mprotect_user_vma_range(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        new_prot: usize,
    ) -> Result<(), MprotectError> {
        let start = start_va.0;
        let end = end_va.0;
        if !self.can_mprotect_vm_regions(start, end, new_prot) {
            return Err(MprotectError::AccessDenied);
        }

        if !self.user_range_fully_mapped(start_va, end_va) {
            return Err(MprotectError::Unmapped);
        }

        self.vm_regions
            .apply_mprotect_range(start, end, new_prot)
            .map_err(|_| MprotectError::AccessDenied)?;
        for region in self.vm_regions.snapshot_range(start, end) {
            let valid_start = region.start;
            let valid_end = core::cmp::min(region.end(), region.sigbus_start());
            if valid_start < valid_end
                && !self.mprotect_user_range(
                    valid_start.into(),
                    valid_end.into(),
                    region.map_permission(),
                )
            {
                return Err(MprotectError::Unmapped);
            }
            let tail_start = valid_end;
            if tail_start < region.end()
                && !self.mprotect_user_range(
                    tail_start.into(),
                    region.end().into(),
                    MapPermission::U,
                )
            {
                return Err(MprotectError::Unmapped);
            }
        }
        #[cfg(target_arch = "riscv64")]
        {
            // mprotect 修改的是共享页表；同一进程的其他线程可能正在其他 hart
            // 使用相同 ASID，必须在返回用户态前完成跨 hart TLB shootdown。
            self.flush_user_tlb_all();
            if (new_prot & VmRegion::PROT_EXEC) != 0 {
                crate::arch::riscv64::mm::mark_icache_stale(self.asid.as_ref());
            }
        }
        let backing_ids = self.backing_ids_for_vma_range(start, end);
        self.refresh_mmap_backing_states(backing_ids);
        self.debug_assert_user_vm_invariants();
        Ok(())
    }

    fn move_vm_region_metadata_raw(&mut self, old_addr: usize, old_len: usize, new_start: usize) {
        self.vm_regions
            .move_range_metadata_raw(old_addr, old_len, new_start);
    }

    fn isolate_vm_region_range_raw(&mut self, start: usize, len: usize) -> bool {
        self.vm_regions.isolate_range_raw(start, len)
    }

    pub fn move_user_vma_range(
        &mut self,
        old_addr: usize,
        old_len: usize,
        new_start: usize,
    ) -> bool {
        let Some(old_end) = old_addr.checked_add(old_len) else {
            return false;
        };
        if !self.move_user_range_raw(old_addr.into(), old_end.into(), new_start.into()) {
            return false;
        }
        let mut backing_ids = self.backing_ids_for_vma_range(old_addr, old_end);
        self.move_vm_region_metadata_raw(old_addr, old_len, new_start);
        self.move_locked_ranges(old_addr, old_len, new_start);
        if let Some(new_end) = new_start.checked_add(old_len) {
            for backing_id in self.backing_ids_for_vma_range(new_start, new_end) {
                Self::push_unique_backing_id(&mut backing_ids, backing_id);
            }
        }
        self.refresh_mmap_backing_states(backing_ids);
        self.debug_assert_user_vm_invariants();
        true
    }

    pub fn move_user_vma_range_replacing(
        &mut self,
        old_addr: usize,
        old_len: usize,
        new_start: usize,
    ) -> bool {
        let Some(old_end) = old_addr.checked_add(old_len) else {
            return false;
        };
        let Some(new_end) = new_start.checked_add(old_len) else {
            return false;
        };
        let rollback =
            UserRangeRollback::capture(self, &[(old_addr, old_end), (new_start, new_end)]);
        self.unmap_user_vma_range(new_start.into(), new_end.into());
        if self.move_user_vma_range(old_addr, old_len, new_start) {
            return true;
        }
        rollback.restore(self);
        false
    }

    pub fn try_grow_user_vma_range<F>(
        &mut self,
        old_addr: usize,
        old_len: usize,
        target_start: usize,
        new_len: usize,
        grow_area: VmaInsertArea,
        populate_grow: F,
    ) -> bool
    where
        F: FnOnce(&mut MemorySet) -> bool,
    {
        let mut grow_areas = Vec::new();
        grow_areas.push(grow_area);
        self.try_grow_user_vma_range_with_layout(
            old_addr,
            old_len,
            target_start,
            new_len,
            grow_areas,
            None,
            populate_grow,
        )
    }

    pub fn try_grow_user_vma_range_with_file_len<F>(
        &mut self,
        old_addr: usize,
        old_len: usize,
        target_start: usize,
        new_len: usize,
        grow_areas: Vec<VmaInsertArea>,
        final_file_valid_len: usize,
        populate_grow: F,
    ) -> bool
    where
        F: FnOnce(&mut MemorySet) -> bool,
    {
        self.try_grow_user_vma_range_with_layout(
            old_addr,
            old_len,
            target_start,
            new_len,
            grow_areas,
            Some(final_file_valid_len),
            populate_grow,
        )
    }

    fn try_grow_user_vma_range_with_layout<F>(
        &mut self,
        old_addr: usize,
        old_len: usize,
        target_start: usize,
        new_len: usize,
        grow_areas: Vec<VmaInsertArea>,
        final_file_valid_len: Option<usize>,
        populate_grow: F,
    ) -> bool
    where
        F: FnOnce(&mut MemorySet) -> bool,
    {
        if new_len <= old_len {
            return false;
        }
        let Some(old_end) = old_addr.checked_add(old_len) else {
            return false;
        };
        let Some(target_old_end) = target_start.checked_add(old_len) else {
            return false;
        };
        let Some(target_new_end) = target_start.checked_add(new_len) else {
            return false;
        };
        let mut cursor = target_old_end;
        for area in grow_areas.iter() {
            let (area_start, area_end) = area.bounds();
            if area_end <= area_start {
                continue;
            }
            if area_start != cursor || area_end > target_new_end {
                return false;
            }
            cursor = area_end;
        }
        if cursor != target_new_end {
            return false;
        }

        let rollback = UserRangeRollback::capture(self, &[
            (old_addr, old_end),
            (target_start, target_new_end),
        ]);
        let relocated = target_start != old_addr;
        if relocated && !self.move_user_vma_range(old_addr, old_len, target_start) {
            rollback.restore(self);
            return false;
        }

        if !relocated {
            if !self.isolate_vm_region_range_raw(old_addr, old_len) {
                rollback.restore(self);
                return false;
            }
        }

        let Some(mut grown_region) = self.vm_region_containing_addr(target_start) else {
            rollback.restore(self);
            return false;
        };
        if grown_region.start != target_start || grown_region.end() != target_old_end {
            rollback.restore(self);
            return false;
        }
        if let Some(file_valid_len) = final_file_valid_len {
            grown_region.set_len_and_file_valid(new_len, file_valid_len);
        } else {
            grown_region.set_len(new_len);
        }

        for area in grow_areas {
            if !self.try_insert_vma_area_raw_in_region(
                area,
                &grown_region,
                target_old_end,
                target_new_end,
            ) {
                rollback.restore(self);
                return false;
            }
        }

        if !populate_grow(self) {
            rollback.restore(self);
            return false;
        }

        let metadata_updated = if let Some(file_valid_len) = final_file_valid_len {
            self.set_vm_region_len_and_file_valid_by_start(target_start, new_len, file_valid_len)
        } else {
            self.set_vm_region_len_by_start(target_start, new_len)
        };
        if !metadata_updated {
            rollback.restore(self);
            return false;
        }
        if let Some(region) = self.vm_region_containing_addr(target_start) {
            if region.backing_id != 0 {
                self.refresh_mmap_backing_state(region.backing_id);
            }
        }
        self.debug_assert_user_vm_invariants();
        true
    }

    fn try_insert_vma_area_raw_in_region(
        &mut self,
        area: VmaInsertArea,
        region: &VmRegion,
        start: usize,
        end: usize,
    ) -> bool {
        let Some(area_permission) = area.concrete_permission_from_region(region) else {
            return false;
        };
        match area {
            VmaInsertArea::Lazy {
                start: area_start,
                end: area_end,
            } => {
                if area_end <= area_start {
                    true
                } else if area_start < start || area_end > end {
                    false
                } else {
                    self.try_insert_lazy_area_raw(
                        area_start.into(),
                        area_end.into(),
                        area_permission,
                    )
                }
            }
            VmaInsertArea::Framed {
                start: area_start,
                end: area_end,
            } => {
                if area_end <= area_start {
                    true
                } else if area_start < start || area_end > end {
                    false
                } else {
                    self.try_insert_framed_area_raw(
                        area_start.into(),
                        area_end.into(),
                        area_permission,
                    )
                }
            }
            VmaInsertArea::SharedFrames {
                start: area_start,
                end: area_end,
                frames,
            } => {
                if area_end <= area_start {
                    frames.is_empty()
                } else if area_start < start || area_end > end {
                    false
                } else {
                    self.try_insert_shared_frames_area_raw(
                        area_start.into(),
                        area_end.into(),
                        area_permission,
                        frames,
                    )
                }
            }
        }
    }

    pub fn set_vm_region_len_by_start(&mut self, start: usize, len: usize) -> bool {
        if self.vm_regions.set_len_by_start(start, len) {
            if let Some(region) = self.vm_region_containing_addr(start) {
                if region.backing_id != 0 {
                    self.refresh_mmap_backing_state(region.backing_id);
                }
            }
            self.debug_assert_user_vm_invariants();
            true
        } else {
            false
        }
    }

    pub fn set_vm_region_len_and_file_valid_by_start(
        &mut self,
        start: usize,
        len: usize,
        file_valid_len: usize,
    ) -> bool {
        if self
            .vm_regions
            .set_len_and_file_valid_by_start(start, len, file_valid_len)
        {
            if let Some(region) = self.vm_region_containing_addr(start) {
                if region.backing_id != 0 {
                    self.refresh_mmap_backing_state(region.backing_id);
                }
            }
            self.debug_assert_user_vm_invariants();
            true
        } else {
            false
        }
    }

    pub fn vm_region_containing(&self, start: usize, end: usize) -> Option<VmRegion> {
        let region = self.vm_region_containing_addr(start)?;
        (region.is_mmap() && end <= region.end()).then_some(region)
    }

    pub fn page_overlaps_mmap_region(&self, page_start: usize) -> bool {
        let page_end = page_start.saturating_add(PAGE_SIZE);
        self.vm_regions
            .any_overlap_where(page_start, page_end, |region| region.is_mmap())
    }

    pub fn page_overlaps_mmap_region_started_before(
        &self,
        page_start: usize,
        limit: usize,
    ) -> bool {
        let page_end = page_start.saturating_add(PAGE_SIZE);
        self.vm_regions
            .any_overlap_where(page_start, page_end, |region| {
                region.is_mmap() && region.start < limit
            })
    }

    /// Assume that no conflicts.
    #[allow(dead_code)]
    pub fn insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) {
        assert!(
            self.try_insert_framed_area(start_va, end_va, permission),
            "OOM: insert_framed_area({:?}..{:?})",
            start_va,
            end_va
        );
    }

    /// Try to insert a framed (allocated) area; returns `false` on OOM.
    pub fn try_insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        let inserted = self.try_insert_framed_area_raw(start_va, end_va, permission);
        if inserted {
            self.debug_assert_user_vm_invariants();
        }
        inserted
    }

    fn try_insert_framed_area_raw(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        self.try_push_raw(
            MapArea::new(start_va, end_va, MapType::Framed, permission),
            None,
        )
    }

    /// Try to insert a lazily-allocated (on-demand) anonymous area.
    #[allow(dead_code)]
    pub fn try_insert_lazy_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        let inserted = self.try_insert_lazy_area_raw(start_va, end_va, permission);
        if inserted {
            self.debug_assert_user_vm_invariants();
        }
        inserted
    }

    fn try_insert_lazy_area_raw(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return true;
        }
        // Refuse to insert over an existing VMA. brk()/mmap() already pre-scan
        // for free space, but this is the last-resort guard that stops a racing
        // or mis-computed range from silently overlapping a live mapping.
        if self.concrete_range_overlaps(start_va, end_va) {
            return false;
        }

        // Linux merges adjacent anonymous VMAs with identical attributes.
        // Keep this independent of Vec ordering so brk-style growth can still
        // coalesce after the area list is normalized by address.
        if let Some(idx) = self.areas.iter().position(|area| {
            area.is_lazy() && area.map_perm() == permission && area.end_vpn() == start_vpn
        }) {
            let appended = self.areas[idx].append_to(&mut self.page_table, end_vpn);
            if appended {
                self.sort_user_areas();
            }
            return appended;
        }

        if let Some(idx) = self.areas.iter().position(|area| {
            area.is_lazy() && area.map_perm() == permission && area.start_vpn() == end_vpn
        }) {
            let prepended = self.areas[idx].prepend_to(&mut self.page_table, start_vpn);
            if prepended {
                self.sort_user_areas();
            }
            return prepended;
        }

        self.try_push_raw(
            MapArea::new(start_va, end_va, MapType::Lazy, permission),
            None,
        )
    }

    /// Map an identical (VA=PA) range into the address space.
    #[allow(dead_code)]
    pub fn map_identical_range(
        &mut self,
        start: usize,
        end: usize,
        permission: MapPermission,
    ) -> bool {
        if end <= start {
            return true;
        }
        self.try_push(
            MapArea::new(start.into(), end.into(), MapType::Identical, permission),
            None,
        )
    }

    /// Map an identical (VA=PA) range, skipping pages already mapped.
    #[allow(dead_code)]
    pub fn map_identical_range_skip_mapped(
        &mut self,
        start: usize,
        end: usize,
        permission: MapPermission,
    ) {
        if end <= start {
            return;
        }
        let mut vpn = VirtAddr::from(start).floor();
        let end_vpn = VirtAddr::from(end).ceil();
        while vpn < end_vpn {
            let mapped = self
                .page_table
                .translate(vpn)
                .map(|pte| pte.is_valid())
                .unwrap_or(false);
            if !mapped {
                let ppn = PhysPageNum(vpn.0);
                self.page_table.map(vpn, ppn, PTEFlags::from(permission));
            }
            vpn.step();
        }
    }

    fn push(&mut self, map_area: MapArea, data: Option<&[u8]>) {
        assert!(self.try_push(map_area, data), "OOM: mapping area failed");
    }

    fn try_push(&mut self, map_area: MapArea, data: Option<&[u8]>) -> bool {
        let pushed = self.try_push_raw(map_area, data);
        if pushed {
            self.debug_assert_user_vm_invariants();
        }
        pushed
    }

    fn try_push_raw(&mut self, mut map_area: MapArea, data: Option<&[u8]>) -> bool {
        // Common choke point for every area insertion: bail out instead of
        // mapping a range that overlaps an existing VMA, which would corrupt the
        // page table and the `areas` bookkeeping.
        let start_va = VirtAddr::from(map_area.start_vpn());
        let end_va = VirtAddr::from(map_area.end_vpn());
        if self.concrete_range_overlaps(start_va, end_va) {
            return false;
        }
        if !map_area.map(&mut self.page_table) {
            return false;
        }
        if let Some(data) = data {
            map_area.copy_data(&self.page_table, data);
        }
        self.areas.push(map_area);
        self.sort_user_areas();
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        self.flush_user_tlb();
        true
    }

    fn push_mapped_raw(&mut self, map_area: MapArea) {
        self.areas.push(map_area);
        self.sort_user_areas();
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        self.flush_user_tlb();
    }

    #[cfg(target_arch = "riscv64")]
    fn riscv_kernel_stack_root_range() -> (usize, usize) {
        // Keep all kernel stacks under a small high-root window that can be
        // shared into user page tables without sharing the trampoline root.
        let end = PageTable::root_index_of_va(KERNEL_STACK_TOP - 1) + 1;
        let start = end.saturating_sub(Self::RISCV_SHARED_KSTACK_ROOT_COUNT);
        debug_assert_ne!(
            PageTable::root_index_of_va(KERNEL_STACK_TOP - 1),
            PageTable::root_index_of_va(TRAMPOLINE),
            "RISC-V kernel stacks must not share the trampoline root entry"
        );
        (start, end)
    }

    #[cfg(target_arch = "riscv64")]
    fn riscv_kernel_direct_root_range() -> (usize, usize) {
        // Share only the physical direct-map roots actually covering RAM.
        // Device/MMIO mappings stay kernel-only unless explicitly mapped.
        let start = PageTable::root_index_of_va(phys_mem_start());
        let end = PageTable::root_index_of_va(phys_mem_end().saturating_sub(1)) + 1;
        (start, end)
    }

    #[cfg(target_arch = "riscv64")]
    fn riscv_root_range_overlaps(index: usize, start: usize, end: usize) -> bool {
        let root_start = PageTable::root_entry_start(index);
        let root_end = PageTable::root_entry_end(index);
        end > root_start && start < root_end
    }

    #[cfg(target_arch = "riscv64")]
    fn riscv_high_stack_window_overlaps(start: usize, end: usize) -> bool {
        let (root_start, root_end) = Self::riscv_kernel_stack_root_range();
        let window_pages = root_end.saturating_sub(root_start);
        let window_size = window_pages.saturating_mul(Self::RISCV_ROOT_ENTRY_SIZE);
        let window_start = KERNEL_STACK_TOP.saturating_sub(window_size);
        end > window_start && start < KERNEL_STACK_TOP
    }

    #[cfg(target_arch = "riscv64")]
    fn riscv_shared_kernel_range_overlaps(&self, start: usize, end: usize) -> bool {
        if !self.has_user_kernel_mappings || end <= start {
            return false;
        }

        let (direct_start, direct_end) = Self::riscv_kernel_direct_root_range();
        for index in direct_start..direct_end {
            if Self::riscv_root_range_overlaps(index, start, end) {
                return true;
            }
        }
        if Self::riscv_high_stack_window_overlaps(start, end) {
            return true;
        }
        false
    }

    #[cfg(target_arch = "riscv64")]
    fn riscv_shared_kernel_overlap_end(&self, start: usize, end: usize) -> Option<usize> {
        if !self.has_user_kernel_mappings || end <= start {
            return None;
        }

        let mut overlap_end = None;
        let mut record = |candidate_end: usize| {
            overlap_end = Some(
                overlap_end
                    .map(|old: usize| old.min(candidate_end))
                    .unwrap_or(candidate_end),
            );
        };

        let (direct_start, direct_end) = Self::riscv_kernel_direct_root_range();
        for index in direct_start..direct_end {
            if Self::riscv_root_range_overlaps(index, start, end) {
                record(PageTable::root_entry_end(index));
            }
        }

        let (stack_root_start, stack_root_end) = Self::riscv_kernel_stack_root_range();
        let stack_window_pages = stack_root_end.saturating_sub(stack_root_start);
        let stack_window_size = stack_window_pages.saturating_mul(Self::RISCV_ROOT_ENTRY_SIZE);
        let stack_window_start = KERNEL_STACK_TOP.saturating_sub(stack_window_size);
        if end > stack_window_start && start < KERNEL_STACK_TOP {
            record(KERNEL_STACK_TOP);
        }

        overlap_end
    }

    #[cfg(target_arch = "riscv64")]
    fn page_align_up(value: usize) -> usize {
        value.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }

    fn place_initial_user_stack_bottom(&self, requested_bottom: usize) -> usize {
        #[cfg(target_arch = "riscv64")]
        {
            let mut bottom = requested_bottom;
            if self.has_user_kernel_mappings {
                // ELF 栈通常位于最后一个 PT_LOAD 段之后。共享内核根页表时，
                // 跳过高地址共享窗口，避免用户 VMA 覆盖内核页表子树。
                loop {
                    let end = bottom.saturating_add(USER_STACK_SIZE);
                    let Some(conflict_end) = self.riscv_shared_kernel_overlap_end(bottom, end)
                    else {
                        break;
                    };
                    bottom = Self::page_align_up(conflict_end.saturating_add(PAGE_SIZE));
                }
            }
            bottom
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            requested_bottom
        }
    }

    #[cfg(target_arch = "riscv64")]
    fn prepare_riscv_kernel_shared_roots(&mut self) -> bool {
        let (direct_start, direct_end) = Self::riscv_kernel_direct_root_range();
        for index in direct_start..direct_end {
            if !self.page_table.mark_root_entry_global(index) {
                return false;
            }
        }
        let (stack_start, stack_end) = Self::riscv_kernel_stack_root_range();
        for index in stack_start..stack_end {
            if !self.page_table.ensure_root_entry(index) {
                return false;
            }
            if !self.page_table.mark_root_entry_global(index) {
                return false;
            }
        }
        true
    }

    #[cfg(target_arch = "riscv64")]
    fn map_riscv_user_kernel_mappings(&mut self) -> bool {
        if self.has_user_kernel_mappings {
            return true;
        }

        // Trap entry now stays on the current SATP until scheduling, so user
        // page tables need the direct map and kernel-stack roots required to
        // run kernel code safely before switching to the full kernel SATP.
        {
            let kernel_space = KERNEL_SPACE.lock();
            let (direct_start, direct_end) = Self::riscv_kernel_direct_root_range();
            for index in direct_start..direct_end {
                if !self
                    .page_table
                    .share_root_entry_from(index, &kernel_space.page_table)
                {
                    return false;
                }
            }
            let (stack_start, stack_end) = Self::riscv_kernel_stack_root_range();
            for index in stack_start..stack_end {
                if !self
                    .page_table
                    .share_root_entry_from(index, &kernel_space.page_table)
                {
                    return false;
                }
            }
        }

        self.has_user_kernel_mappings = true;
        true
    }

    fn map_user_trampoline_pages(&mut self) -> bool {
        self.map_trampoline();
        self.map_sigreturn_trampoline_user();
        #[cfg(target_arch = "riscv64")]
        {
            self.map_riscv_user_kernel_mappings()
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            true
        }
    }

    /// Mention that trampoline is not collected by areas.
    fn map_trampoline(&mut self) {
        let flags = PTEFlags::from(MapPermission::R | MapPermission::X);
        #[cfg(target_arch = "riscv64")]
        let flags = flags | PTEFlags::G;
        self.page_table.map(
            VirtAddr::from(TRAMPOLINE).into(),
            PhysAddr::from(strampoline as usize).into(),
            flags,
        );
    }

    fn map_sigreturn_trampoline_user(&mut self) {
        self.page_table.map(
            VirtAddr::from(SIGRETURN_TRAMPOLINE).into(),
            PhysAddr::from(strampoline as usize).into(),
            PTEFlags::from(MapPermission::R | MapPermission::X | MapPermission::U),
        );
    }
    /// Without kernel stacks.
    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();
        // map trampoline (kernel-only)
        memory_set.map_trampoline();
        // map kernel sections
        println!(".text [{:#x}, {:#x})", stext as usize, etext as usize);
        println!(".rodata [{:#x}, {:#x})", srodata as usize, erodata as usize);
        println!(".data [{:#x}, {:#x})", sdata as usize, edata as usize);
        println!(
            ".bss [{:#x}, {:#x})",
            sbss_with_stack as usize, ebss as usize
        );
        println!("mapping .text section");
        memory_set.push(
            MapArea::new(
                (stext as usize).into(),
                (etext as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::X,
            ),
            None,
        );
        println!("mapping .rodata section");
        memory_set.push(
            MapArea::new(
                (srodata as usize).into(),
                (erodata as usize).into(),
                MapType::Identical,
                MapPermission::R,
            ),
            None,
        );
        println!("mapping .data section");
        memory_set.push(
            MapArea::new(
                (sdata as usize).into(),
                (edata as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        println!("mapping .bss section");
        memory_set.push(
            MapArea::new(
                (sbss_with_stack as usize).into(),
                (ebss as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        println!("mapping physical memory");
        for_each_phys_mem_range(|start, end| {
            memory_set.map_identical_range_skip_mapped(
                start,
                end,
                MapPermission::R | MapPermission::W,
            );
        });
        println!("mapping memory-mapped registers");
        for pair in MMIO {
            memory_set.push(
                MapArea::new(
                    (*pair).0.into(),
                    ((*pair).0 + (*pair).1).into(),
                    MapType::Identical,
                    MapPermission::R | MapPermission::W | MapPermission::IO,
                ),
                None,
            );
        }
        for_each_dtb_mmio_range(|start, end| {
            memory_set.map_identical_range_skip_mapped(
                start,
                end,
                MapPermission::R | MapPermission::W | MapPermission::IO,
            );
        });
        #[cfg(target_arch = "loongarch64")]
        {
            let dtb_start = crate::config::DEVICE_TREE_ADDR;
            let dtb_end = dtb_start + crate::config::DEVICE_TREE_MAX_SIZE;
            memory_set.map_identical_range_skip_mapped(dtb_start, dtb_end, MapPermission::R);
        }
        #[cfg(target_arch = "riscv64")]
        assert!(
            memory_set.prepare_riscv_kernel_shared_roots(),
            "OOM while preparing RISC-V shared kernel root entries"
        );
        memory_set
    }
    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp and entry poremove_areeint.
    /// 用户占 被设计为 程序地址 (虚拟地址) 的最高端.
    pub fn from_elf(elf_data: &[u8]) -> Result<(Self, usize, usize, ElfAux), isize> {
        let mut memory_set = Self::new_bare();
        // map trap trampoline (kernel-only) and sigreturn trampoline (user accessible)
        if !memory_set.map_user_trampoline_pages() {
            return Err(ENOMEM);
        }
        // map program headers of elf, with U flag
        validate_elf_arch_abi(elf_arch_abi_from_bytes(elf_data)?)?;
        let elf = xmas_elf::ElfFile::new(elf_data).map_err(|_| -8isize)?;
        let load_bias: usize = match elf.header.pt2.type_().as_type() {
            // Map ET_DYN (shared objects / PIE) at a non-zero base so that:
            // - the null page stays unmapped by default, and
            // - the dynamic loader (musl) can map an ET_EXEC main program at low VAs.
            xmas_elf::header::Type::SharedObject => 0x2000_0000,
            _ => 0,
        };
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        if magic != [0x7f, 0x45, 0x4c, 0x46] {
            return Err(-8);
        }
        let ph_count = elf_header.pt2.ph_count();
        let ph_entry_size = elf_header.pt2.ph_entry_size() as usize;
        let ph_offset = elf_header.pt2.ph_offset() as usize;
        let ph_table_size = ph_entry_size.saturating_mul(ph_count as usize);
        let mut phdr_vaddr: usize = 0;
        let mut max_end_vpn = VirtPageNum(0);
        for i in 0..ph_count {
            let ph = elf.program_header(i).map_err(|_| -8isize)?;
            // Prefer explicit PHDR segment when present.
            let ph_type = match ph.get_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if phdr_vaddr == 0 && ph_type == xmas_elf::program::Type::Phdr {
                phdr_vaddr = load_bias + ph.virtual_addr() as usize;
            }
            if ph_type == xmas_elf::program::Type::Load {
                let start_va: VirtAddr = (load_bias + ph.virtual_addr() as usize).into();
                let end_va: VirtAddr =
                    (load_bias + (ph.virtual_addr() + ph.mem_size()) as usize).into();
                let mut map_perm = MapPermission::U;
                let ph_flags = ph.flags();
                if ph_flags.is_read() {
                    map_perm |= MapPermission::R;
                }
                if ph_flags.is_write() {
                    map_perm |= MapPermission::W;
                }
                if ph_flags.is_execute() {
                    map_perm |= MapPermission::X;
                }
                let Some(seg_end) = memory_set.try_insert_static_user_framed_range(
                    VmRegionKind::Elf,
                    start_va,
                    end_va,
                    map_perm,
                    Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                ) else {
                    return Err(ENOMEM);
                };
                if seg_end > max_end_vpn {
                    max_end_vpn = seg_end;
                }

                // Best-effort: compute AT_PHDR virtual address if PHDR table bytes are in this LOAD.
                let seg_off = ph.offset() as usize;
                let seg_filesz = ph.file_size() as usize;
                if phdr_vaddr == 0
                    && ph_offset >= seg_off
                    && ph_offset.saturating_add(ph_table_size) <= seg_off.saturating_add(seg_filesz)
                {
                    phdr_vaddr = load_bias + ph.virtual_addr() as usize + (ph_offset - seg_off);
                }
            }
        }
        // map user stack with U flags
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        // guard page
        user_stack_bottom += PAGE_SIZE;
        user_stack_bottom = memory_set.place_initial_user_stack_bottom(user_stack_bottom);
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        // use crate::println;
        // println!(
        //     "[DEBUG] from_elf mapping user stack: bottom={:#x}, top={:#x}",
        //     user_stack_bottom, user_stack_top
        // );

        if memory_set
            .try_insert_static_user_framed_range(
                VmRegionKind::Stack,
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapPermission::R | MapPermission::W | MapPermission::U,
                None,
            )
            .is_none()
        {
            return Err(ENOMEM);
        }
        let heap_base = user_stack_top + USER_HEAP_GAP;
        // used in sbrk (lazy heap to avoid eager page allocation)
        memory_set.push(
            MapArea::new(
                heap_base.into(),
                heap_base.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        memory_set.reset_user_layout(user_stack_bottom);
        // map TrapContext
        assert!(memory_set.try_insert_initial_trap_context());
        // Return user_stack_bottom as ustack_base for thread allocation
        // Each thread will calculate its stack as: ustack_base + tid * (PAGE_SIZE + USER_STACK_SIZE)
        Ok((
            memory_set,
            user_stack_bottom,
            load_bias + elf.header.pt2.entry_point() as usize,
            ElfAux {
                phdr: phdr_vaddr,
                phent: ph_entry_size,
                phnum: ph_count as usize,
            },
        ))
    }

    /// Build a user address space from an ELF reader to avoid loading the full file into memory.
    #[allow(dead_code)]
    pub fn from_elf_reader<F>(mut read_at: F) -> Result<(Self, usize, usize, ElfAux), isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        let (hdr, phdrs) = parse_elf_headers(&mut read_at)?;
        validate_elf_arch_abi(hdr.arch_abi())?;
        Self::from_parsed_elf_reader(&mut read_at, &hdr, &phdrs)
    }

    /// Build a user address space from ELF metadata parsed earlier in the same exec.
    pub(crate) fn from_elf_info_reader<F>(
        mut read_at: F,
        info: &ElfLoadInfo,
    ) -> Result<(Self, usize, usize, ElfAux), isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        validate_elf_arch_abi(info.arch_abi)?;
        Self::from_parsed_elf_reader(&mut read_at, &info.header, &info.phdrs)
    }

    fn from_parsed_elf_reader<F>(
        read_at: &mut F,
        hdr: &ElfHeader64,
        phdrs: &[ElfPhdr64],
    ) -> Result<(Self, usize, usize, ElfAux), isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        let mut memory_set = Self::new_bare();
        if !memory_set.map_user_trampoline_pages() {
            return Err(ENOMEM);
        }

        let load_bias = if hdr.e_type == ET_DYN { 0x2000_0000 } else { 0 };
        let mut max_end_vpn = VirtPageNum(0);
        let elf_aux = Self::map_elf_segments_from_reader(
            &mut memory_set,
            read_at,
            hdr,
            phdrs,
            load_bias,
            &mut max_end_vpn,
        )?;

        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        user_stack_bottom += PAGE_SIZE;
        user_stack_bottom = memory_set.place_initial_user_stack_bottom(user_stack_bottom);
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        if memory_set
            .try_insert_static_user_framed_range(
                VmRegionKind::Stack,
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapPermission::R | MapPermission::W | MapPermission::U,
                None,
            )
            .is_none()
        {
            return Err(ENOMEM);
        }
        let heap_base = user_stack_top + USER_HEAP_GAP;
        if !memory_set.try_push(
            MapArea::new(
                heap_base.into(),
                heap_base.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        ) {
            return Err(ENOMEM);
        }
        memory_set.reset_user_layout(user_stack_bottom);
        if !memory_set.try_insert_initial_trap_context() {
            return Err(ENOMEM);
        }

        Ok((
            memory_set,
            user_stack_bottom,
            load_bias + hdr.e_entry as usize,
            elf_aux,
        ))
    }

    fn map_elf_segments_into(
        memory_set: &mut MemorySet,
        elf_data: &[u8],
        load_bias: usize,
        max_end_vpn: &mut VirtPageNum,
    ) -> Result<(usize, ElfAux), isize> {
        validate_elf_arch_abi(elf_arch_abi_from_bytes(elf_data)?)?;
        let elf = xmas_elf::ElfFile::new(elf_data).map_err(|_| -8isize)?;
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        if magic != [0x7f, 0x45, 0x4c, 0x46] {
            return Err(-8);
        }
        let ph_count = elf_header.pt2.ph_count();
        let ph_entry_size = elf_header.pt2.ph_entry_size() as usize;
        let ph_offset = elf_header.pt2.ph_offset() as usize;
        let ph_table_size = ph_entry_size.saturating_mul(ph_count as usize);

        let mut phdr_vaddr: usize = 0;
        for i in 0..ph_count {
            let ph = elf.program_header(i).map_err(|_| -8isize)?;
            let ph_type = match ph.get_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if phdr_vaddr == 0 && ph_type == xmas_elf::program::Type::Phdr {
                phdr_vaddr = load_bias + ph.virtual_addr() as usize;
            }
            if ph_type != xmas_elf::program::Type::Load {
                continue;
            }
            let start_va: VirtAddr = (load_bias + ph.virtual_addr() as usize).into();
            let end_va: VirtAddr =
                (load_bias + (ph.virtual_addr() + ph.mem_size()) as usize).into();
            let mut map_perm = MapPermission::U;
            let ph_flags = ph.flags();
            if ph_flags.is_read() {
                map_perm |= MapPermission::R;
            }
            if ph_flags.is_write() {
                map_perm |= MapPermission::W;
            }
            if ph_flags.is_execute() {
                map_perm |= MapPermission::X;
            }
            let Some(seg_end) = memory_set.try_insert_static_user_framed_range(
                VmRegionKind::Elf,
                start_va,
                end_va,
                map_perm,
                Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
            ) else {
                return Err(ENOMEM);
            };
            if seg_end > *max_end_vpn {
                *max_end_vpn = seg_end;
            }

            // Best-effort: compute AT_PHDR virtual address if PHDR table bytes are in this LOAD.
            let seg_off = ph.offset() as usize;
            let seg_filesz = ph.file_size() as usize;
            if phdr_vaddr == 0
                && ph_offset >= seg_off
                && ph_offset.saturating_add(ph_table_size) <= seg_off.saturating_add(seg_filesz)
            {
                phdr_vaddr = load_bias + ph.virtual_addr() as usize + (ph_offset - seg_off);
            }
        }

        Ok((load_bias + elf.header.pt2.entry_point() as usize, ElfAux {
            phdr: phdr_vaddr,
            phent: ph_entry_size,
            phnum: ph_count as usize,
        }))
    }

    fn map_elf_segments_from_reader<F>(
        memory_set: &mut MemorySet,
        read_at: &mut F,
        hdr: &ElfHeader64,
        phdrs: &[ElfPhdr64],
        load_bias: usize,
        max_end_vpn: &mut VirtPageNum,
    ) -> Result<ElfAux, isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        let ph_entry_size = hdr.e_phentsize as usize;
        let ph_count = hdr.e_phnum as usize;
        let ph_offset = hdr.e_phoff as usize;
        let ph_table_size = ph_entry_size.saturating_mul(ph_count);

        let mut phdr_vaddr: usize = 0;
        for ph in phdrs {
            if ph.p_type == PT_PHDR && phdr_vaddr == 0 {
                phdr_vaddr = load_bias + ph.p_vaddr as usize;
            }
            if ph.p_type != PT_LOAD {
                continue;
            }
            let start_va: VirtAddr = (load_bias + ph.p_vaddr as usize).into();
            let end_va: VirtAddr = (load_bias + (ph.p_vaddr + ph.p_memsz) as usize).into();
            let mut map_perm = MapPermission::U;
            if (ph.p_flags & PF_R) != 0 {
                map_perm |= MapPermission::R;
            }
            if (ph.p_flags & PF_W) != 0 {
                map_perm |= MapPermission::W;
            }
            if (ph.p_flags & PF_X) != 0 {
                map_perm |= MapPermission::X;
            }
            let Some(seg_end) = memory_set.try_insert_static_user_framed_range(
                VmRegionKind::Elf,
                start_va,
                end_va,
                map_perm,
                None,
            ) else {
                return Err(ENOMEM);
            };
            if seg_end > *max_end_vpn {
                *max_end_vpn = seg_end;
            }

            // Populate segment data from the file.
            let file_size = ph.p_filesz as usize;
            if file_size > 0 {
                let token = memory_set.token();
                let mut offset = 0usize;
                let mut tmp = [0u8; PAGE_SIZE];
                while offset < file_size {
                    let to_read = core::cmp::min(PAGE_SIZE, file_size - offset);
                    read_exact_with(read_at, ph.p_offset as usize + offset, &mut tmp[..to_read])?;
                    if try_copy_to_user_unchecked(
                        token,
                        (load_bias + ph.p_vaddr as usize + offset) as *mut u8,
                        &tmp[..to_read],
                    )
                    .is_err()
                    {
                        return Err(ENOMEM);
                    }
                    offset += to_read;
                }
            }

            // Best-effort: compute AT_PHDR when PHDR table bytes live in this segment.
            if phdr_vaddr == 0 {
                let seg_off = ph.p_offset as usize;
                let seg_filesz = ph.p_filesz as usize;
                if ph_offset >= seg_off
                    && ph_offset.saturating_add(ph_table_size) <= seg_off.saturating_add(seg_filesz)
                {
                    phdr_vaddr = load_bias + ph.p_vaddr as usize + (ph_offset - seg_off);
                }
            }
        }

        Ok(ElfAux {
            phdr: phdr_vaddr,
            phent: ph_entry_size,
            phnum: ph_count,
        })
    }

    /// Map a dynamically-linked main ELF together with its interpreter (PT_INTERP) in
    /// a single address space, and return both entry points.
    pub fn from_elf_with_interp(
        main_elf: &[u8],
        interp_elf: &[u8],
    ) -> Result<(Self, usize, usize, usize, ElfAux, usize), isize> {
        let mut memory_set = Self::new_bare();
        if !memory_set.map_user_trampoline_pages() {
            return Err(ENOMEM);
        }

        validate_elf_interp_abi(
            elf_arch_abi_from_bytes(main_elf)?,
            elf_arch_abi_from_bytes(interp_elf)?,
        )?;
        let main = xmas_elf::ElfFile::new(main_elf).map_err(|_| -8isize)?;
        let _interp = xmas_elf::ElfFile::new(interp_elf).map_err(|_| -8isize)?;

        // Place PIE/shared objects away from zero so the null page stays unmapped.
        let main_bias = match main.header.pt2.type_().as_type() {
            xmas_elf::header::Type::SharedObject => 0x2000_0000,
            _ => 0,
        };
        // Keep the interpreter at a different base to avoid overlap with the main program.
        // For LoongArch, keep it under 2GiB so brk stays in 32-bit range for oscomp musl tests.
        #[cfg(target_arch = "loongarch64")]
        let interp_bias = 0x4000_0000;
        // Match exampleOS layout: put the interpreter high (but still within Sv39 user range)
        // to reduce collisions with the main program/heap/mmap allocations.
        #[cfg(not(target_arch = "loongarch64"))]
        let interp_bias = 0x30_0000_0000;

        let mut max_end_vpn = VirtPageNum(0);
        let (main_entry, main_aux) =
            Self::map_elf_segments_into(&mut memory_set, main_elf, main_bias, &mut max_end_vpn)?;
        let (interp_entry, _interp_aux) = Self::map_elf_segments_into(
            &mut memory_set,
            interp_elf,
            interp_bias,
            &mut max_end_vpn,
        )?;

        // Map user stack with U flags, placed above all mapped ELF segments.
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        // guard page
        user_stack_bottom += PAGE_SIZE;
        user_stack_bottom = memory_set.place_initial_user_stack_bottom(user_stack_bottom);
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        if memory_set
            .try_insert_static_user_framed_range(
                VmRegionKind::Stack,
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapPermission::R | MapPermission::W | MapPermission::U,
                None,
            )
            .is_none()
        {
            return Err(ENOMEM);
        }
        let heap_base = user_stack_top + USER_HEAP_GAP;
        // used in sbrk (lazy heap to avoid eager page allocation)
        memory_set.push(
            MapArea::new(
                heap_base.into(),
                heap_base.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        memory_set.reset_user_layout(user_stack_bottom);
        // map TrapContext
        assert!(memory_set.try_insert_initial_trap_context());

        Ok((
            memory_set,
            user_stack_bottom,
            interp_entry,
            main_entry,
            main_aux,
            interp_bias,
        ))
    }

    /// Build a user address space from a main ELF reader and an in-memory interpreter.
    #[allow(dead_code)]
    pub fn from_elf_with_interp_reader<F>(
        mut read_at: F,
        interp_elf: &[u8],
    ) -> Result<(Self, usize, usize, usize, ElfAux, usize), isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        let (hdr, phdrs) = parse_elf_headers(&mut read_at)?;
        validate_elf_interp_abi(hdr.arch_abi(), elf_arch_abi_from_bytes(interp_elf)?)?;
        Self::from_parsed_elf_with_interp_reader(&mut read_at, &hdr, &phdrs, interp_elf)
    }

    /// Build a dynamically-linked address space from ELF metadata parsed earlier in the same exec.
    pub(crate) fn from_elf_with_interp_info_reader<F>(
        mut read_at: F,
        info: &ElfLoadInfo,
        interp_elf: &[u8],
    ) -> Result<(Self, usize, usize, usize, ElfAux, usize), isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        validate_elf_interp_abi(info.arch_abi, elf_arch_abi_from_bytes(interp_elf)?)?;
        Self::from_parsed_elf_with_interp_reader(
            &mut read_at,
            &info.header,
            &info.phdrs,
            interp_elf,
        )
    }

    fn from_parsed_elf_with_interp_reader<F>(
        read_at: &mut F,
        hdr: &ElfHeader64,
        phdrs: &[ElfPhdr64],
        interp_elf: &[u8],
    ) -> Result<(Self, usize, usize, usize, ElfAux, usize), isize>
    where
        F: FnMut(usize, &mut [u8]) -> usize,
    {
        let mut memory_set = Self::new_bare();
        if !memory_set.map_user_trampoline_pages() {
            return Err(ENOMEM);
        }

        let main_bias = if hdr.e_type == ET_DYN { 0x2000_0000 } else { 0 };
        #[cfg(target_arch = "loongarch64")]
        let interp_bias = 0x4000_0000;
        #[cfg(not(target_arch = "loongarch64"))]
        let interp_bias = 0x30_0000_0000;

        let mut max_end_vpn = VirtPageNum(0);
        let main_aux = Self::map_elf_segments_from_reader(
            &mut memory_set,
            read_at,
            hdr,
            phdrs,
            main_bias,
            &mut max_end_vpn,
        )?;
        let (interp_entry, _interp_aux) = Self::map_elf_segments_into(
            &mut memory_set,
            interp_elf,
            interp_bias,
            &mut max_end_vpn,
        )?;

        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        user_stack_bottom += PAGE_SIZE;
        user_stack_bottom = memory_set.place_initial_user_stack_bottom(user_stack_bottom);
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        if memory_set
            .try_insert_static_user_framed_range(
                VmRegionKind::Stack,
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapPermission::R | MapPermission::W | MapPermission::U,
                None,
            )
            .is_none()
        {
            return Err(ENOMEM);
        }
        let heap_base = user_stack_top + USER_HEAP_GAP;
        if !memory_set.try_push(
            MapArea::new(
                heap_base.into(),
                heap_base.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        ) {
            return Err(ENOMEM);
        }
        memory_set.reset_user_layout(user_stack_bottom);
        if !memory_set.try_insert_initial_trap_context() {
            return Err(ENOMEM);
        }

        Ok((
            memory_set,
            user_stack_bottom,
            interp_entry,
            main_bias + hdr.e_entry as usize,
            main_aux,
            interp_bias,
        ))
    }
    /// Fork a user address space using copy-on-write for user pages.
    ///
    /// - User pages (PTE.U) that were writable are remapped read-only and tagged with `PTEFlags::COW`
    ///   in both parent and child.
    /// - Kernel-only pages (e.g., TrapContext, no PTE.U) are copied eagerly.
    pub fn from_existed_user_cow(user_space: &mut MemorySet) -> MemorySet {
        let diag_enabled = crate::debug_config::DEBUG_FUTEX;
        let start_cycles = if diag_enabled {
            crate::arch::read_time()
        } else {
            0
        };
        let mut memory_set = Self::new_bare();
        assert!(memory_set.map_user_trampoline_pages());

        let mut parent_update_count = 0usize;
        let mut src_walk_cache = PageWalkCache::new();
        let mut dst_walk_cache = PageWalkCache::new();
        let mut area_count = 0usize;
        let mut identical_pages = 0usize;
        let mut shared_pages = 0usize;
        let mut kernel_private_pages = 0usize;

        for area in user_space.areas.iter() {
            area_count = area_count.saturating_add(1);
            src_walk_cache.reset();
            dst_walk_cache.reset();
            let mut new_area = MapArea::from_another(area);

            match area.map_type() {
                MapType::Identical => {
                    for vpn in area.vpn_range() {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        identical_pages = identical_pages.saturating_add(1);
                        let src_ppn = src_pte.ppn();
                        let src_flags = src_pte.flags();
                        memory_set.page_table.map_cached(
                            vpn,
                            src_ppn,
                            src_flags,
                            &mut dst_walk_cache,
                        );
                    }
                }
                // For Framed/Lazy areas we only walk materialized pages.
                // This avoids O(vma_len) scans for huge untouched lazy mappings.
                MapType::Framed | MapType::Lazy => {
                    for (vpn, frame_tracker) in area.tracked_frames() {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let mut src_flags = src_pte.flags();

                        // Kernel-only pages must not be shared (e.g., TrapContext is per-thread).
                        if !src_flags.contains(PTEFlags::U) {
                            let Some(frame) = frame_alloc() else {
                                continue;
                            };
                            frame
                                .ppn
                                .get_bytes_array()
                                .copy_from_slice(src_ppn.get_bytes_array());
                            memory_set.page_table.map_cached(
                                vpn,
                                frame.ppn,
                                src_flags,
                                &mut dst_walk_cache,
                            );
                            new_area.insert_tracked_frame(vpn, frame);
                            kernel_private_pages = kernel_private_pages.saturating_add(1);
                            continue;
                        }

                        // Share the physical page.
                        shared_pages = shared_pages.saturating_add(1);
                        let writable =
                            src_flags.contains(PTEFlags::W) || src_flags.contains(PTEFlags::D);
                        if writable && !src_flags.contains(PTEFlags::SHARED) {
                            src_flags.remove(PTEFlags::W);
                            src_flags.remove(PTEFlags::D);
                            src_flags.insert(PTEFlags::COW);
                            // Apply parent PTE demotion immediately to minimize the window where
                            // another thread could write through a still-writable PTE on another hart.
                            let changed = user_space.page_table.set_flags_cached(
                                vpn,
                                src_flags,
                                &mut src_walk_cache,
                            );
                            if changed {
                                parent_update_count = parent_update_count.saturating_add(1);
                            }
                        }
                        memory_set.page_table.map_cached(
                            vpn,
                            src_ppn,
                            src_flags,
                            &mut dst_walk_cache,
                        );
                        new_area.insert_tracked_frame(vpn, frame_tracker.clone());
                    }
                }
            }

            memory_set.push_mapped_raw(new_area);
        }

        let before_parent_update_cycles = if diag_enabled {
            crate::arch::read_time()
        } else {
            0
        };
        if parent_update_count != 0 {
            // After fork demotes parent PTEs from writable to read-only+COW,
            // the parent must not resume with stale writable translations.
            //
            // RISC-V updates the parent's active page table in-place, so the
            // current hart must flush stale writable translations immediately.
            // Other harts that may already be executing the same mm need a
            // remote shootdown as well.
            #[cfg(target_arch = "riscv64")]
            {
                let remote_hart_mask =
                    crate::task::manager::online_hart_mask() & !(1usize << crate::arch::hart_id());
                unsafe {
                    asm!("sfence.vma");
                }
                if remote_hart_mask != 0 {
                    crate::sbi::remote_sfence_vma_all(remote_hart_mask);
                }
            }
            // SAFETY: LoongArch64 currently runs single-core only (no SMP boot),
            // so dropping this address space's ASID is sufficient. When SMP is
            // added, a remote TLB shootdown (IPI + invtlb on each hart) will be
            // needed for a task that is concurrently running on another hart.
            #[cfg(target_arch = "loongarch64")]
            {
                user_space.flush_user_tlb();
            }
        }
        if diag_enabled {
            let end_cycles = crate::arch::read_time();
            let to_us = |delta_cycles: usize| -> usize {
                let freq = crate::config::clock_freq() as u128;
                if freq == 0 {
                    0
                } else {
                    ((delta_cycles as u128).saturating_mul(1_000_000) / freq) as usize
                }
            };
            let total_us = to_us(end_cycles.wrapping_sub(start_cycles));
            let seq = COW_CLONE_DIAG_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
            if seq <= 16 || seq % 128 == 0 || total_us >= 30_000 {
                let walk_us = to_us(before_parent_update_cycles.wrapping_sub(start_cycles));
                let update_us = to_us(end_cycles.wrapping_sub(before_parent_update_cycles));
                log::warn!(
                    "[cow_clone_diag] seq={} total_us={} walk_us={} parent_update_us={} areas={} ident_pages={} shared_pages={} kernel_copy_pages={} cow_marked={} parent_updates={}",
                    seq,
                    total_us,
                    walk_us,
                    update_us,
                    area_count,
                    identical_pages,
                    shared_pages,
                    kernel_private_pages,
                    parent_update_count,
                    parent_update_count
                );
            }
        }

        memory_set.inherit_user_vm_metadata_from(user_space);
        memory_set
    }

    /// Fork a user address space by copying all mapped pages (no COW).
    ///
    /// This is slower than COW but avoids COW corner cases on some platforms.
    #[allow(dead_code)]
    pub fn from_existed_user(user_space: &MemorySet) -> MemorySet {
        let mut memory_set = Self::new_bare();
        assert!(memory_set.map_user_trampoline_pages());
        let mut src_walk_cache = PageWalkCache::new();
        let mut dst_walk_cache = PageWalkCache::new();

        for area in user_space.areas.iter() {
            src_walk_cache.reset();
            dst_walk_cache.reset();
            let mut new_area = MapArea::from_another(area);

            match area.map_type() {
                MapType::Identical => {
                    for vpn in area.vpn_range() {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let src_flags = src_pte.flags();
                        memory_set.page_table.map_cached(
                            vpn,
                            src_ppn,
                            src_flags,
                            &mut dst_walk_cache,
                        );
                    }
                }
                // Lazy areas can span terabytes with no materialized pages.
                // Copy only present pages tracked in data_frames.
                MapType::Framed | MapType::Lazy => {
                    for vpn in area.tracked_vpns() {
                        let Some(src_pte) = user_space
                            .page_table
                            .translate_cached(vpn, &mut src_walk_cache)
                        else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let Some(frame) = frame_alloc() else {
                            continue;
                        };
                        frame
                            .ppn
                            .get_bytes_array()
                            .copy_from_slice(src_ppn.get_bytes_array());
                        let pte_flags = area.pte_flags();
                        memory_set.page_table.map_cached(
                            vpn,
                            frame.ppn,
                            pte_flags,
                            &mut dst_walk_cache,
                        );
                        new_area.insert_tracked_frame(vpn, frame);
                    }
                }
            }

            memory_set.push_mapped_raw(new_area);
        }

        memory_set.inherit_user_vm_metadata_from(user_space);
        memory_set
    }

    /// Insert a user-mapped framed area backed by the provided physical frames.
    ///
    /// Used by System V shared memory (`shmat`) to map the same physical pages
    /// into multiple processes.
    pub fn try_insert_shared_frames_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
        frames: Vec<FrameTracker>,
    ) -> bool {
        let inserted = self.try_insert_shared_frames_area_raw(start_va, end_va, permission, frames);
        if inserted {
            self.debug_assert_user_vm_invariants();
        }
        inserted
    }

    fn try_insert_shared_frames_area_raw(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
        frames: Vec<FrameTracker>,
    ) -> bool {
        let mut area = MapArea::new(start_va, end_va, MapType::Framed, permission);
        let expected_pages = area.page_count();
        if expected_pages == 0 {
            return frames.is_empty();
        }
        if frames.len() != expected_pages || self.concrete_range_overlaps(start_va, end_va) {
            return false;
        }
        for vpn in area.vpn_range() {
            if let Some(pte) = self.page_table.translate(vpn) {
                if pte.is_valid() {
                    return false;
                }
            }
        }

        let pte_flags = area.pte_flags() | PTEFlags::SHARED;
        for (vpn, frame) in area.vpn_range().into_iter().zip(frames.into_iter()) {
            self.page_table.map(vpn, frame.ppn, pte_flags);
            area.insert_tracked_frame(vpn, frame);
        }
        self.push_mapped_raw(area);
        true
    }

    #[allow(dead_code)]
    pub fn insert_shared_frames_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
        frames: Vec<FrameTracker>,
    ) {
        assert!(
            self.try_insert_shared_frames_area(start_va, end_va, permission, frames),
            "OOM or overlap while inserting shared frames"
        );
    }

    pub fn activate(&self) {
        #[cfg(target_arch = "riscv64")]
        {
            let satp = self.page_table.token();
            riscv_write_satp_and_flush_asid(satp);
        }
        #[cfg(target_arch = "loongarch64")]
        {
            self.page_table.activate();
        }
    }
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.page_table.translate(vpn)
    }

    pub fn set_pte_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) -> bool {
        #[cfg(target_arch = "loongarch64")]
        {
            let changed = self.page_table.set_flags_deferred(vpn, flags);
            if changed {
                self.flush_user_tlb();
            }
            changed
        }
        #[cfg(target_arch = "riscv64")]
        {
            let changed = self.page_table.set_flags(vpn, flags);
            if changed {
                self.flush_user_tlb();
            }
            changed
        }
        #[cfg(not(any(target_arch = "loongarch64", target_arch = "riscv64")))]
        {
            let changed = self.page_table.set_flags(vpn, flags);
            changed
        }
    }
    #[allow(unused)]
    pub fn shrink_to(&mut self, start: VirtAddr, new_end: VirtAddr) -> bool {
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.start_vpn() == start.floor())
        {
            area.shrink_to(&mut self.page_table, new_end.ceil());
            self.sort_user_areas();
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            self.flush_user_tlb();
            self.debug_assert_user_vm_invariants();
            true
        } else {
            false
        }
    }
    #[allow(unused)]
    pub fn append_to(&mut self, start: VirtAddr, new_end: VirtAddr) -> bool {
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.start_vpn() == start.floor())
        {
            let appended = area.append_to(&mut self.page_table, new_end.ceil());
            if appended {
                self.sort_user_areas();
                #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
                self.flush_user_tlb();
                self.debug_assert_user_vm_invariants();
            }
            appended
        } else {
            false
        }
    }

    pub fn remove_area(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        if let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .find(|(_idx, area)| area.has_exact_vpn_range(start_va.floor(), end_va.ceil()))
        {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            self.flush_user_tlb();
            self.debug_assert_user_vm_invariants();
        };
    }

    fn move_user_range_raw(
        &mut self,
        old_start_va: VirtAddr,
        old_end_va: VirtAddr,
        new_start_va: VirtAddr,
    ) -> bool {
        let old_start_vpn = old_start_va.floor();
        let old_end_vpn = old_end_va.ceil();
        let new_start_vpn = new_start_va.floor();
        if old_start_vpn >= old_end_vpn {
            return true;
        }
        let delta = new_start_vpn.0 as isize - old_start_vpn.0 as isize;
        if shift_vpn_by_delta(old_start_vpn, delta).is_none()
            || shift_vpn_by_delta(old_end_vpn, delta).is_none()
        {
            return false;
        }

        let mut moved_ptes: Vec<(VirtPageNum, PhysPageNum, PTEFlags)> = Vec::new();
        let mut moved_areas: Vec<MapArea> = Vec::new();
        let mut new_areas: Vec<MapArea> = Vec::new();
        let mut found = false;

        let mut areas = core::mem::take(&mut self.areas);
        for area in areas.drain(..) {
            if !area.contains_perm(MapPermission::U) {
                new_areas.push(area);
                continue;
            }

            let area_start = area.start_vpn();
            let area_end = area.end_vpn();
            if !area.overlaps_vpn_range(old_start_vpn, old_end_vpn) {
                new_areas.push(area);
                continue;
            }

            found = true;
            let ov_start = core::cmp::max(old_start_vpn, area_start);
            let ov_end = core::cmp::min(old_end_vpn, area_end);

            for vpn in VPNRange::new(ov_start, ov_end) {
                if let Some(pte) = self.page_table.translate(vpn) {
                    if pte.is_valid() {
                        let Some(new_vpn) = shift_vpn_by_delta(vpn, delta) else {
                            return false;
                        };
                        moved_ptes.push((new_vpn, pte.ppn(), pte.flags()));
                        #[cfg(target_arch = "loongarch64")]
                        self.page_table.unmap_if_mapped_deferred(vpn);
                        #[cfg(not(target_arch = "loongarch64"))]
                        self.page_table.unmap_if_mapped(vpn);
                    }
                }
            }

            let (left, mid, right) = area.split_around(ov_start, ov_end);
            if let Some(left) = left {
                new_areas.push(left);
            }

            let Some(mid) = mid.move_by_delta(delta) else {
                return false;
            };
            moved_areas.push(mid);

            if let Some(right) = right {
                new_areas.push(right);
            }
        }

        if !found {
            self.areas = new_areas;
            self.sort_user_areas();
            self.debug_assert_user_vm_invariants();
            return false;
        }

        self.areas = new_areas;
        for (vpn, ppn, flags) in moved_ptes {
            self.page_table.map(vpn, ppn, flags);
        }
        self.areas.extend(moved_areas);
        self.sort_user_areas();
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        self.flush_user_tlb();
        true
    }

    /// Unmap (best-effort) any user-mapped pages in `[start_va, end_va)`.
    ///
    /// This is primarily used to implement Linux `mmap(MAP_FIXED)` semantics, which
    /// replace existing mappings in the target range.
    pub fn unmap_user_range(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return;
        }

        // Fast path: exact-area munmap (common in tight mmap/munmap loops).
        // Avoid rebuilding the whole area list when we can remove one area directly.
        if let Some(idx) = self.areas.iter().position(|area| {
            area.contains_perm(MapPermission::U) && area.has_exact_vpn_range(start_vpn, end_vpn)
        }) {
            let mut area = self.areas.remove(idx);
            area.unmap(&mut self.page_table);
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            self.flush_user_tlb();
            return;
        }

        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        let mut changed = false;
        let mut new_areas: Vec<MapArea> = Vec::new();
        let mut areas = core::mem::take(&mut self.areas);
        for mut area in areas.drain(..) {
            if !area.contains_perm(MapPermission::U) {
                new_areas.push(area);
                continue;
            }

            let area_start = area.start_vpn();
            let area_end = area.end_vpn();
            if !area.overlaps_vpn_range(start_vpn, end_vpn) {
                new_areas.push(area);
                continue;
            }

            let ov_start = core::cmp::max(start_vpn, area_start);
            let ov_end = core::cmp::min(end_vpn, area_end);

            area.unmap_range_maybe(&mut self.page_table, ov_start, ov_end);
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            {
                changed = true;
            }

            let (left, _mid, right) = area.split_around(ov_start, ov_end);
            if let Some(left) = left {
                new_areas.push(left);
            }
            if let Some(right) = right {
                new_areas.push(right);
            }
        }
        self.areas = new_areas;
        self.sort_user_areas();
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        if changed {
            self.flush_user_tlb();
        }
    }

    /// Update concrete user mapping permissions in `[start_va, end_va)`.
    ///
    /// Syscall-visible coverage is checked against `VmRegionSet` before this
    /// helper runs. Missing `MapArea` coverage is therefore a bookkeeping bug,
    /// not an `mprotect(2)` policy decision.
    pub fn mprotect_user_range(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        new_perm: MapPermission,
    ) -> bool {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        let mut touched_area = false;

        let mut new_areas: Vec<MapArea> = Vec::new();
        let mut areas = core::mem::take(&mut self.areas);
        for area in areas.drain(..) {
            if !area.contains_perm(MapPermission::U) {
                new_areas.push(area);
                continue;
            }

            let area_start = area.start_vpn();
            let area_end = area.end_vpn();
            if !area.overlaps_vpn_range(start_vpn, end_vpn) {
                new_areas.push(area);
                continue;
            }
            touched_area = true;

            let ov_start = core::cmp::max(start_vpn, area_start);
            let ov_end = core::cmp::min(end_vpn, area_end);

            let (left, mut mid, right) = area.split_around(ov_start, ov_end);

            for vpn in VPNRange::new(ov_start, ov_end) {
                if let Some(pte) = self.page_table.translate(vpn) {
                    if pte.is_valid() {
                        if new_perm == MapPermission::U {
                            // PROT_NONE: unmap but keep the frame tracker.
                            mid.save_pte_flags(vpn, pte.flags());
                            #[cfg(target_arch = "loongarch64")]
                            self.page_table.unmap_deferred(vpn);
                            #[cfg(not(target_arch = "loongarch64"))]
                            self.page_table.unmap(vpn);
                            continue;
                        }
                        let old_flags = pte.flags();
                        let pte_flags = pte_flags_for_mprotect(new_perm, Some(old_flags));
                        let _ = mid.take_saved_pte_flags(vpn);
                        #[cfg(target_arch = "loongarch64")]
                        let _ = self.page_table.set_flags_deferred(vpn, pte_flags);
                        #[cfg(not(target_arch = "loongarch64"))]
                        let _ = self.page_table.set_flags(vpn, pte_flags);
                        continue;
                    }
                }
                if new_perm != MapPermission::U {
                    if let Some(ppn) = mid.tracked_frame(vpn).map(|frame| frame.ppn) {
                        let old_flags = mid.take_saved_pte_flags(vpn);
                        let pte_flags = pte_flags_for_mprotect(new_perm, old_flags);
                        self.page_table.map(vpn, ppn, pte_flags);
                    }
                }
            }

            if let Some(left) = left {
                new_areas.push(left);
            }

            mid.set_map_perm(new_perm);
            new_areas.push(mid);

            if let Some(right) = right {
                new_areas.push(right);
            }
        }
        self.areas = new_areas;
        self.sort_user_areas();
        #[cfg(target_arch = "loongarch64")]
        if touched_area {
            self.flush_user_tlb();
        }
        debug_assert!(
            touched_area || start_vpn >= end_vpn,
            "mprotect concrete update had no MapArea coverage for {:?}..{:?}",
            start_vpn,
            end_vpn
        );
        true
    }

    fn discard_lazy_concrete_range(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return;
        }
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        let mut changed = false;
        for area in self.areas.iter_mut() {
            if !area.is_lazy() {
                continue;
            }
            if !area.contains_perm(MapPermission::U) {
                continue;
            }
            let area_start = area.start_vpn();
            let area_end = area.end_vpn();
            if !area.overlaps_vpn_range(start_vpn, end_vpn) {
                continue;
            }
            let ov_start = core::cmp::max(start_vpn, area_start);
            let ov_end = core::cmp::min(end_vpn, area_end);
            area.unmap_range_maybe(&mut self.page_table, ov_start, ov_end);
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            {
                changed = true;
            }
        }
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        if changed {
            self.flush_user_tlb();
        }
    }

    fn discard_framed_concrete_to_lazy_range(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return;
        }

        let mut new_areas: Vec<MapArea> = Vec::new();
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        let mut changed = false;
        let mut areas = core::mem::take(&mut self.areas);
        for area in areas.drain(..) {
            if !area.contains_perm(MapPermission::U)
                || area.map_type() != MapType::Framed
                || area.map_perm() != permission
                || !area.overlaps_vpn_range(start_vpn, end_vpn)
            {
                new_areas.push(area);
                continue;
            }

            let ov_start = core::cmp::max(start_vpn, area.start_vpn());
            let ov_end = core::cmp::min(end_vpn, area.end_vpn());
            let (left, mut mid, right) = area.split_around(ov_start, ov_end);
            mid.unmap(&mut self.page_table);
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            {
                changed = true;
            }

            if let Some(left) = left {
                new_areas.push(left);
            }
            new_areas.push(MapArea::new(
                VirtAddr::from(ov_start),
                VirtAddr::from(ov_end),
                MapType::Lazy,
                permission,
            ));
            if let Some(right) = right {
                new_areas.push(right);
            }
        }
        self.areas = new_areas;
        self.sort_user_areas();
        #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
        if changed {
            self.flush_user_tlb();
        }
    }

    /// Discard pages for `madvise(MADV_DONTNEED)`.
    ///
    /// VMA metadata decides which ranges are eligible; `MapArea` is only the
    /// resident/lazy page cache being dropped. Private anonymous framed stack
    /// pages can be turned into lazy zero-fill holes, and private OSInode-backed
    /// framed pages can be turned back into lazy file refault holes. ELF
    /// text/data still keeps its framed pages until it has a file-backed refault
    /// source.
    pub fn discard_madvise_dontneed_range(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        let start = start_va.0;
        let end = end_va.0;
        if start >= end {
            return;
        }
        let regions = self.vm_regions.snapshot_range(start, end);
        for region in regions {
            if region.shared {
                continue;
            }
            let discard_start = core::cmp::max(start, region.start);
            let discard_end = core::cmp::min(end, region.end());
            if region.map_type == MapType::Lazy || region.is_file_like() {
                self.discard_lazy_concrete_range(discard_start.into(), discard_end.into());
            }
            if region.can_file_framed_refault() || region.can_zero_fill_framed_refault() {
                self.discard_lazy_concrete_range(discard_start.into(), discard_end.into());
                self.discard_framed_concrete_to_lazy_range(
                    discard_start.into(),
                    discard_end.into(),
                    region.map_permission(),
                );
            }
        }
        self.debug_assert_user_vm_invariants();
    }

    /// Returns true if any concrete `MapArea` overlaps the range.
    ///
    /// This is a page-table/bookkeeping guard, not a syscall-visible VMA
    /// coverage test. Use `VmRegionSet`-backed helpers for policy decisions.
    /// 逐一 检查 已有 area  是否 与 给定的 重叠
    pub fn concrete_range_overlaps(&self, start_va: VirtAddr, end_va: VirtAddr) -> bool {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if self
            .areas
            .iter()
            .any(|area| area.overlaps_vpn_range(start_vpn, end_vpn))
        {
            return true;
        }
        #[cfg(target_arch = "riscv64")]
        {
            if self.riscv_shared_kernel_range_overlaps(start_va.0, end_va.0) {
                return true;
            }
        }
        false
    }

    /// Return merged user virtual-memory ranges from current VMAs.
    pub fn user_mapped_ranges(&self) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        for region in self.vm_regions.iter() {
            if let Some((start, end)) = Self::vm_region_user_range(*region) {
                push_range_merged(&mut ranges, start, end);
            }
        }
        ranges
    }

    /// Highest end address among current user VMAs.
    pub fn max_user_mapped_end(&self) -> usize {
        self.vm_regions
            .iter()
            .filter_map(|region| Self::vm_region_user_range(*region).map(|(_start, end)| end))
            .max()
            .unwrap_or(0)
    }

    /// Whether every page in `[start_va, end_va)` belongs to some user VMA.
    pub fn user_range_fully_mapped(&self, start_va: VirtAddr, end_va: VirtAddr) -> bool {
        let start = start_va.0;
        let end = end_va.0;
        self.vm_regions.covers_range(start, end)
    }

    pub fn remove_area_with_start_vpn(&mut self, start_va: VirtAddr) {
        if let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .find(|(_idx, area)| area.start_vpn() == start_va.floor())
        {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
            #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
            self.flush_user_tlb();
            self.debug_assert_user_vm_invariants();
        };
    }

    #[allow(dead_code)]
    pub fn clone(&self) -> Self {
        let mut new_memory_set = Self::new_bare();
        let has_user = self
            .areas
            .iter()
            .any(|area| area.contains_perm(MapPermission::U));
        if has_user {
            assert!(new_memory_set.map_user_trampoline_pages());
        } else {
            new_memory_set.map_trampoline();
        }
        for area in &self.areas {
            let mut new_area = MapArea::new(
                VirtAddr::from(area.start_vpn()),
                VirtAddr::from(area.end_vpn()),
                area.map_type(),
                area.map_perm(),
            );
            if area.is_lazy() {
                let pte_flags = new_area.pte_flags();
                for vpn in area.vpn_range() {
                    let Some(src_pte) = self.page_table.translate(vpn) else {
                        continue;
                    };
                    if !src_pte.is_valid() {
                        continue;
                    }
                    let src_ppn = src_pte.ppn();
                    let Some(frame) = frame_alloc() else {
                        continue;
                    };
                    frame
                        .ppn
                        .get_bytes_array()
                        .copy_from_slice(src_ppn.get_bytes_array());
                    new_memory_set.page_table.map(vpn, frame.ppn, pte_flags);
                    new_area.insert_tracked_frame(vpn, frame);
                }
                new_memory_set.push_mapped_raw(new_area);
                continue;
            }

            assert!(new_memory_set.try_push_raw(new_area, None));
            //then copy data

            for vpn in area.vpn_range() {
                let src_ppn = self.page_table.translate(vpn).unwrap().ppn();
                let dst_ppn = new_memory_set.page_table.translate(vpn).unwrap().ppn();
                let src_bytes = src_ppn.get_bytes_array();
                let dst_bytes = dst_ppn.get_bytes_array();
                dst_bytes.copy_from_slice(&src_bytes);
            }
        }

        new_memory_set.inherit_user_vm_metadata_from(self);
        new_memory_set
    }
    #[allow(dead_code)]
    pub fn recycle_data_pages(&mut self) {
        //*self = Self::new_bare();
        self.areas.clear();
        self.debug_assert_user_vm_invariants();
    }
}
pub fn kernel_token() -> usize {
    KERNEL_SPACE.lock().token()
}

#[allow(dead_code)]
pub fn activate_token(token: usize) {
    #[cfg(target_arch = "riscv64")]
    riscv_write_satp_and_flush_asid(token);
    #[cfg(target_arch = "loongarch64")]
    {
        let page_table = PageTable::from_token(token);
        page_table.activate();
    }
}
#[allow(unused)]
pub fn remap_test() {
    let mut kernel_space = KERNEL_SPACE.lock();
    let mid_text: VirtAddr = ((stext as usize + etext as usize) / 2).into();
    let mid_rodata: VirtAddr = ((srodata as usize + erodata as usize) / 2).into();
    let mid_data: VirtAddr = ((sdata as usize + edata as usize) / 2).into();
    assert!(
        !kernel_space
            .page_table
            .translate(mid_text.floor())
            .unwrap()
            .writable(),
    );
    assert!(
        !kernel_space
            .page_table
            .translate(mid_rodata.floor())
            .unwrap()
            .writable(),
    );
    assert!(
        !kernel_space
            .page_table
            .translate(mid_data.floor())
            .unwrap()
            .executable(),
    );
    println!("remap_test passed!");
}
