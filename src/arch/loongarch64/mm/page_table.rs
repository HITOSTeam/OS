//! Implementation of [`PageTableEntry`] and [`PageTable`].

use crate::config::PAGE_SIZE;
use crate::mm::{
    FrameTracker, LazyFaultResult, MapPermission, PhysAddr, PhysPageNum, StepByOne, VirtAddr,
    VirtPageNum, frame_alloc,
};
use crate::task::processor::current_task;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::*;
use core::{
    arch::asm,
    cmp::min,
    mem::MaybeUninit,
    sync::atomic::{AtomicU32, Ordering},
};

bitflags! {
    /// page table entry flags
    pub struct PTEFlags: usize {
        const V = 1 << 0;
        const D = 1 << 1;
        const PLV0 = 0 << 2;
        const PLV1 = 1 << 2;
        const PLV2 = 2 << 2;
        const PLV3 = 3 << 2;
        const U = 3 << 2;
        const MAT_SUC = 0 << 4;
        const MAT_CC = 1 << 4;
        const MAT_WUC = 2 << 4;
        const G = 1 << 6;
        const P = 1 << 7;
        const W = 1 << 8;
        /// Software-managed copy-on-write marker.
        const COW = 1 << 9;
        /// Software-managed shared mapping marker.
        const SHARED = 1 << 10;
        /// Not readable.
        const NR = 1 << (usize::BITS - 3);
        /// Not executable.
        const NX = 1 << (usize::BITS - 2);
        /// Restricted privilege level enable.
        const RPLV = 1 << (usize::BITS - 1);
    }
}

const PALEN: usize = 48;

#[inline(always)]
fn flush_tlb_vaddr(vaddr: usize) {
    // SAFETY: `invtlb` is a privileged instruction and this kernel-only helper uses it to evict
    // the translation for `vaddr` on the current hart. Issuing it outside kernel mode would trap.
    unsafe {
        asm!("invtlb 0x4, $r0, {}", in(reg) vaddr);
    }
}

#[inline(always)]
fn flush_tlb_all() {
    // SAFETY: This is the kernel's full-TLB invalidation path; executing `invtlb` in kernel mode
    // is required after page-table changes. Running it in the wrong context would fault.
    unsafe {
        asm!("invtlb 0x1, $r0, $r0");
    }
}

#[inline(always)]
fn write_pgdl(base: usize) {
    // SAFETY: `base` is a kernel-constructed page-table root physical address, and writing PGDL
    // is only valid in kernel mode. A bogus base would redirect low-half translations incorrectly.
    unsafe {
        asm!("csrwr {}, 0x19", inout(reg) base => _);
    }
}

#[inline(always)]
fn write_pgdh(base: usize) {
    // SAFETY: `base` is the current root page-table base and this privileged CSR write updates
    // the high-half walker state. An invalid base would break kernel address translation.
    unsafe {
        asm!("csrwr {}, 0x1a", inout(reg) base => _);
    }
}

impl From<MapPermission> for PTEFlags {
    fn from(perm: MapPermission) -> Self {
        let mut flags = PTEFlags::V | PTEFlags::P;
        if !perm.contains(MapPermission::IO) {
            flags |= PTEFlags::MAT_CC;
        }
        if !perm.contains(MapPermission::R) && !perm.contains(MapPermission::X) {
            flags |= PTEFlags::NR;
        }
        if !perm.contains(MapPermission::X) {
            flags |= PTEFlags::NX;
        }
        if perm.contains(MapPermission::W) {
            flags |= PTEFlags::W | PTEFlags::D;
        }
        if perm.contains(MapPermission::U) {
            flags |= PTEFlags::U;
        }
        flags
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
/// page table entry structure
pub struct PageTableEntry {
    pub bits: usize,
}

impl PageTableEntry {
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        let mut flags = flags;
        flags.insert(PTEFlags::P);
        PageTableEntry {
            bits: (ppn.0 << 12) | flags.bits,
        }
    }
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }
    pub fn ppn(&self) -> PhysPageNum {
        let ppn_mask = ((1usize << PALEN) - 1) << 12;
        PhysPageNum((self.bits & ppn_mask) >> 12)
    }
    pub fn flags(&self) -> PTEFlags {
        let ppn_mask = ((1usize << PALEN) - 1) << 12;
        PTEFlags::from_bits(self.bits & !ppn_mask).unwrap()
    }
    pub fn is_valid(&self) -> bool {
        (self.flags() & PTEFlags::V) != PTEFlags::empty()
    }
    pub fn readable(&self) -> bool {
        !self.flags().contains(PTEFlags::NR)
    }
    pub fn writable(&self) -> bool {
        self.flags().contains(PTEFlags::D)
    }
    pub fn executable(&self) -> bool {
        !self.flags().contains(PTEFlags::NX)
    }
    pub fn is_user(&self) -> bool {
        self.flags().contains(PTEFlags::PLV3)
    }
    pub fn is_cow(&self) -> bool {
        self.flags().contains(PTEFlags::COW)
    }
    pub fn is_shared(&self) -> bool {
        self.flags().contains(PTEFlags::SHARED)
    }
}

/// page table structure
pub struct PageTable {
    root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}

/// Cached upper-level walk state for repeated nearby VPN lookups/maps.
#[derive(Clone, Copy)]
pub struct PageWalkCache {
    l0_idx: usize,
    l0_ppn: PhysPageNum,
    l1_idx: usize,
    l1_ppn: PhysPageNum,
    l0_valid: bool,
    l1_valid: bool,
}

impl PageWalkCache {
    pub const fn new() -> Self {
        Self {
            l0_idx: 0,
            l0_ppn: PhysPageNum(0),
            l1_idx: 0,
            l1_ppn: PhysPageNum(0),
            l0_valid: false,
            l1_valid: false,
        }
    }

    pub fn reset(&mut self) {
        self.l0_valid = false;
        self.l1_valid = false;
    }
}

/// Assume that it won't oom when creating/mapping.
impl PageTable {
    pub fn new() -> Self {
        let frame = frame_alloc().unwrap();
        PageTable {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }
    /// Temporarily used to get arguments from user space.
    pub fn from_token(token: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(token),
            frames: Vec::new(),
        }
    }
    fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                let frame = frame_alloc().unwrap();
                *pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            ppn = pte.ppn();
        }
        result
    }
    fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                return None;
            }
            ppn = pte.ppn();
        }
        result
    }
    /// v is added inside.
    #[allow(unused)]
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        // New mappings do not need a local flush unless a stale invalid entry
        // could already be cached. User mapping changes that may leave stale
        // translations invalidate the owning ASID at the MemorySet layer.
        let pte = self.find_pte_create(vpn).unwrap();
        debug_assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
    }

    /// Fast-path map for sorted/nearby VPN streams.
    pub fn map_cached(
        &mut self,
        vpn: VirtPageNum,
        ppn: PhysPageNum,
        flags: PTEFlags,
        cache: &mut PageWalkCache,
    ) {
        let idxs = vpn.indexes();
        if !cache.l0_valid || cache.l0_idx != idxs[0] {
            let pte_l0 = &mut self.root_ppn.get_pte_array()[idxs[0]];
            if !pte_l0.is_valid() {
                let frame = frame_alloc().unwrap();
                *pte_l0 = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            cache.l0_idx = idxs[0];
            cache.l0_ppn = pte_l0.ppn();
            cache.l0_valid = true;
            cache.l1_valid = false;
        }
        if !cache.l1_valid || cache.l1_idx != idxs[1] {
            let pte_l1 = &mut cache.l0_ppn.get_pte_array()[idxs[1]];
            if !pte_l1.is_valid() {
                let frame = frame_alloc().unwrap();
                *pte_l1 = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            cache.l1_idx = idxs[1];
            cache.l1_ppn = pte_l1.ppn();
            cache.l1_valid = true;
        }
        let pte_leaf = &mut cache.l1_ppn.get_pte_array()[idxs[2]];
        debug_assert!(
            !pte_leaf.is_valid(),
            "vpn {:?} is mapped before mapping",
            vpn
        );
        *pte_leaf = PageTableEntry::new(ppn, flags | PTEFlags::V);
    }
    #[allow(unused)]
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        self.unmap_deferred(vpn);
        flush_tlb_vaddr(vpn.0 << 12);
    }

    #[allow(unused)]
    pub fn unmap_deferred(&mut self, vpn: VirtPageNum) {
        // Callers using the deferred variant must either flush this VA
        // themselves or drop the owning user ASID before returning to user mode.
        let pte = self.find_pte(vpn).unwrap();
        assert!(pte.is_valid(), "vpn {:?} is invalid before unmapping", vpn);
        *pte = PageTableEntry::empty();
    }

    /// Unmap an existing leaf PTE if it is present and valid.
    ///
    /// Returns `true` if an entry was unmapped.
    pub fn unmap_if_mapped(&mut self, vpn: VirtPageNum) -> bool {
        if !self.unmap_if_mapped_deferred(vpn) {
            return false;
        }
        flush_tlb_vaddr(vpn.0 << 12);
        true
    }

    pub fn unmap_if_mapped_deferred(&mut self, vpn: VirtPageNum) -> bool {
        // See `unmap_deferred`: this only edits the page table.
        let Some(pte) = self.find_pte(vpn) else {
            return false;
        };
        if !pte.is_valid() {
            return false;
        }
        *pte = PageTableEntry::empty();
        true
    }
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.find_pte(vpn).map(|pte| *pte)
    }

    /// Fast-path translate for sorted/nearby VPN streams.
    pub fn translate_cached(
        &self,
        vpn: VirtPageNum,
        cache: &mut PageWalkCache,
    ) -> Option<PageTableEntry> {
        let idxs = vpn.indexes();
        if !cache.l0_valid || cache.l0_idx != idxs[0] {
            let pte_l0 = &mut self.root_ppn.get_pte_array()[idxs[0]];
            if !pte_l0.is_valid() {
                cache.reset();
                return None;
            }
            cache.l0_idx = idxs[0];
            cache.l0_ppn = pte_l0.ppn();
            cache.l0_valid = true;
            cache.l1_valid = false;
        }
        if !cache.l1_valid || cache.l1_idx != idxs[1] {
            let pte_l1 = &mut cache.l0_ppn.get_pte_array()[idxs[1]];
            if !pte_l1.is_valid() {
                cache.l1_valid = false;
                return None;
            }
            cache.l1_idx = idxs[1];
            cache.l1_ppn = pte_l1.ppn();
            cache.l1_valid = true;
        }
        let pte_leaf = &mut cache.l1_ppn.get_pte_array()[idxs[2]];
        if !pte_leaf.is_valid() {
            return None;
        }
        Some(*pte_leaf)
    }

    /// Update an existing leaf PTE's flags, preserving its mapped PPN.
    ///
    /// Returns `false` if the vpn is not mapped.
    pub fn set_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) -> bool {
        if !self.set_flags_deferred(vpn, flags) {
            return false;
        }
        flush_tlb_vaddr(vpn.0 << 12);
        true
    }

    pub fn set_flags_deferred(&mut self, vpn: VirtPageNum, flags: PTEFlags) -> bool {
        // Used by fork/mprotect paths that batch PTE edits and invalidate the
        // mm ASID once, avoiding one invtlb per page.
        let Some(pte) = self.find_pte(vpn) else {
            return false;
        };
        if !pte.is_valid() {
            return false;
        }
        let ppn = pte.ppn();
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        true
    }

    /// Batched flag update for sorted/nearby VPN streams.
    ///
    /// This is the cached equivalent of `set_flags_deferred()`: it only edits
    /// the page table. The owning `MemorySet` must invalidate its ASID or flush
    /// affected translations before returning to user mode.
    pub fn set_flags_cached(
        &mut self,
        vpn: VirtPageNum,
        flags: PTEFlags,
        cache: &mut PageWalkCache,
    ) -> bool {
        let idxs = vpn.indexes();
        if !cache.l0_valid || cache.l0_idx != idxs[0] {
            let pte_l0 = &mut self.root_ppn.get_pte_array()[idxs[0]];
            if !pte_l0.is_valid() {
                cache.reset();
                return false;
            }
            cache.l0_idx = idxs[0];
            cache.l0_ppn = pte_l0.ppn();
            cache.l0_valid = true;
            cache.l1_valid = false;
        }
        if !cache.l1_valid || cache.l1_idx != idxs[1] {
            let pte_l1 = &mut cache.l0_ppn.get_pte_array()[idxs[1]];
            if !pte_l1.is_valid() {
                cache.l1_valid = false;
                return false;
            }
            cache.l1_idx = idxs[1];
            cache.l1_ppn = pte_l1.ppn();
            cache.l1_valid = true;
        }
        let pte_leaf = &mut cache.l1_ppn.get_pte_array()[idxs[2]];
        if !pte_leaf.is_valid() {
            return false;
        }
        let ppn = pte_leaf.ppn();
        *pte_leaf = PageTableEntry::new(ppn, flags | PTEFlags::V);
        true
    }

    /// Update an existing leaf PTE's mapped PPN and flags.
    ///
    /// Returns `false` if the vpn is not mapped.
    pub fn remap(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) -> bool {
        if !self.remap_deferred(vpn, ppn, flags) {
            return false;
        }
        flush_tlb_vaddr(vpn.0 << 12);
        true
    }

    pub fn remap_deferred(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) -> bool {
        // Used by COW fault handling to edit the PTE first and flush/drop ASID
        // only after the frame metadata is also consistent.
        let Some(pte) = self.find_pte(vpn) else {
            return false;
        };
        if !pte.is_valid() {
            return false;
        }
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        true
    }
    /// Translate `VirtAddr` to `PhysAddr`
    pub fn translate_va(&self, va: VirtAddr) -> Option<PhysAddr> {
        self.find_pte(va.clone().floor()).map(|pte| {
            let aligned_pa: PhysAddr = pte.ppn().into();
            let offset = va.page_offset();
            let aligned_pa_usize: usize = aligned_pa.into();
            (aligned_pa_usize + offset).into()
        })
    }
    pub fn token(&self) -> usize {
        self.root_ppn.0
    }
    pub fn activate(&self) {
        let base = self.root_ppn.0 << 12;
        let kernel_token = crate::mm::cached_kernel_token();
        if kernel_token == 0 || self.root_ppn.0 == kernel_token {
            write_pgdh(base);
        }
        write_pgdl(base);
        super::asid::write_kernel_asid();
        flush_tlb_all();
    }
    pub fn clone(&self) -> Self {
        //todo:alloc new frames...
        return Self {
            root_ppn: self.root_ppn,
            frames: Vec::new(),
        };
    }
}

fn try_resolve_lazy_page(token: usize, va: usize, access: MapPermission) -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let memory_set = task.memory_set();
    if token != memory_set.token() {
        return false;
    }
    match memory_set.resolve_lazy_fault(va, access) {
        LazyFaultResult::Resolved => true,
        LazyFaultResult::Oom => crate::task::processor::exit_group_and_run_next(-9),
        LazyFaultResult::Invalid => false,
    }
}

fn try_resolve_user_page(token: usize, va: usize, access: MapPermission) -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let memory_set = task.memory_set();
    if token != memory_set.token() {
        return false;
    }
    if access.contains(MapPermission::W) && memory_set.resolve_cow_fault(va) {
        return true;
    }
    match memory_set.resolve_lazy_fault(va, access) {
        LazyFaultResult::Resolved => true,
        LazyFaultResult::Oom => crate::task::processor::exit_group_and_run_next(-9),
        LazyFaultResult::Invalid => false,
    }
}

fn user_access_fail(va: usize, access: MapPermission) -> ! {
    const EFAULT: i32 = -14;
    log::error!(
        "[uaccess] invalid user access addr={:#x} access={:?}",
        va,
        access
    );
    crate::task::processor::exit_current_and_run_next(EFAULT)
}

fn resolve_user_pte(token: usize, va: usize, access: MapPermission) -> Result<PageTableEntry, ()> {
    let page_table = PageTable::from_token(token);
    let vpn = VirtAddr::from(va).floor();
    let mut pte = match page_table.translate(vpn) {
        Some(pte) if pte.is_valid() => pte,
        _ => {
            if try_resolve_user_page(token, va, access) {
                match page_table.translate(vpn) {
                    Some(pte) if pte.is_valid() => pte,
                    _ => return Err(()),
                }
            } else {
                return Err(());
            }
        }
    };
    let mut flags = pte.flags();
    if access.contains(MapPermission::W) && !pte.writable() {
        if flags.contains(PTEFlags::COW) && try_resolve_user_page(token, va, access) {
            pte = page_table.translate(vpn).ok_or(())?;
            flags = pte.flags();
        }
    }
    if !pte.is_user() {
        return Err(());
    }
    if access.contains(MapPermission::R) && !pte.readable() {
        return Err(());
    }
    if access.contains(MapPermission::W) && !pte.writable() {
        return Err(());
    }
    if access.contains(MapPermission::X) && !pte.executable() {
        return Err(());
    }
    Ok(pte)
}

fn translated_address_with(token: usize, ptr: *const u8, access: MapPermission) -> &'static mut u8 {
    let va = ptr as usize;
    let pte = resolve_user_pte(token, va, access).unwrap_or_else(|_| user_access_fail(va, access));
    let ppn = pte.ppn();
    let page_off = VirtAddr::from(va).page_offset();
    &mut ppn.get_bytes_array()[page_off]
}

/// Load a string from other address spaces into kernel space without an end `\0`.
pub fn translated_str(token: usize, ptr: *const u8) -> String {
    let mut string = String::new();
    let mut va = ptr as usize;
    loop {
        let ch: u8 = *translated_address_with(token, va as *const u8, MapPermission::R);
        if ch == 0 {
            break;
        }
        string.push(ch as char);
        va += 1;
    }
    string
}
pub fn translated_mutref<T>(token: usize, ptr: *mut T) -> &'static mut T {
    let real_addr = translated_address_with(token, ptr as *const u8, MapPermission::W);
    // SAFETY: `translated_address_with` resolved `ptr` to writable mapped memory for this token,
    // and the caller expects that location to contain a properly aligned `T`. If not, this cast
    // would fabricate an invalid mutable reference into user memory.
    unsafe { &mut *(real_addr as *mut u8 as *mut T) }
}

/// Copy bytes from user space into a kernel buffer.
///
/// Terminates the current task if any user page in the range is invalid.
pub fn copy_from_user(token: usize, src: *const u8, dst: &mut [u8]) {
    if try_copy_from_user(token, src, dst).is_err() {
        user_access_fail(src as usize, MapPermission::R);
    }
}

/// Copy bytes from user space into a kernel buffer.
///
/// Returns `Err(())` if any user page in the range is unmapped.
pub fn try_copy_from_user(token: usize, src: *const u8, dst: &mut [u8]) -> Result<(), ()> {
    if dst.is_empty() {
        return Ok(());
    }
    let mut start = src as usize;
    let end = start.checked_add(dst.len()).ok_or(())?;
    let mut written = 0usize;
    while start < end {
        let start_va = VirtAddr::from(start);
        let pte = resolve_user_pte(token, start, MapPermission::R)?;
        let ppn = pte.ppn();
        let pa: PhysAddr = ppn.into();
        let page_off = start_va.page_offset();
        let n = min(PAGE_SIZE - page_off, end - start);
        // SAFETY: `resolve_user_pte` established that this page is readable and `written + n`
        // remains inside `dst`; the source span is limited to the current mapped page. If any
        // of those assumptions failed, this raw copy would read from an invalid physical address.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (pa.0 + page_off) as *const u8,
                dst.as_mut_ptr().add(written),
                n,
            );
        }
        start += n;
        written += n;
    }
    Ok(())
}

/// Copy bytes from a kernel buffer into user space.
///
/// Terminates the current task if any user page in the range is invalid.
pub fn copy_to_user(token: usize, dst: *mut u8, src: &[u8]) {
    if try_copy_to_user(token, dst, src).is_err() {
        user_access_fail(dst as usize, MapPermission::W);
    }
}

/// Copy bytes from a kernel buffer into user space.
///
/// Returns `Err(())` if any user page in the range is unmapped.
pub fn try_copy_to_user(token: usize, dst: *mut u8, src: &[u8]) -> Result<(), ()> {
    if src.is_empty() {
        return Ok(());
    }
    let mut start = dst as usize;
    let end = start.checked_add(src.len()).ok_or(())?;
    let mut read = 0usize;
    while start < end {
        let start_va = VirtAddr::from(start);
        let pte = resolve_user_pte(token, start, MapPermission::W)?;
        let ppn = pte.ppn();
        let pa: PhysAddr = ppn.into();
        let page_off = start_va.page_offset();
        let n = min(PAGE_SIZE - page_off, end - start);
        // SAFETY: The destination user page was resolved writable for this token and `read + n`
        // is bounded by `src.len()`. A stale translation or incorrect bounds would corrupt memory.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr().add(read), (pa.0 + page_off) as *mut u8, n);
        }
        start += n;
        read += n;
    }
    Ok(())
}

/// Copy bytes into user space, ignoring user R/W/X permissions.
///
/// This is intended for kernel-internal population of freshly-mapped pages
/// (e.g., file-backed `mmap`) where user permissions may be read-only.
pub fn try_copy_to_user_unchecked(token: usize, dst: *mut u8, src: &[u8]) -> Result<(), ()> {
    if src.is_empty() {
        return Ok(());
    }
    let mut start = dst as usize;
    let end = start.checked_add(src.len()).ok_or(())?;
    let mut read = 0usize;
    while start < end {
        let start_va = VirtAddr::from(start);
        let pte = resolve_user_pte(token, start, MapPermission::U)?;
        let ppn = pte.ppn();
        let pa: PhysAddr = ppn.into();
        let page_off = start_va.page_offset();
        let n = min(PAGE_SIZE - page_off, end - start);
        // SAFETY: This follows the same bounded copy discipline as `try_copy_to_user`, but it is
        // used for kernel-internal writes where permission checks are intentionally bypassed.
        // A wrong physical destination or length would still corrupt memory.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr().add(read), (pa.0 + page_off) as *mut u8, n);
        }
        start += n;
        read += n;
    }
    Ok(())
}

pub fn read_user_value<T: Copy>(token: usize, src: *const T) -> T {
    let mut value = MaybeUninit::<T>::uninit();
    // SAFETY: `value` owns enough writable storage for exactly one `T`, and we expose its raw
    // bytes so `copy_from_user` can initialize them. A mismatched length would clobber the stack.
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    copy_from_user(token, src as *const u8, dst_bytes);
    // SAFETY: The preceding copy initialized all bytes of `value`.
    unsafe { value.assume_init() }
}

pub fn try_read_user_value<T: Copy>(token: usize, src: *const T) -> Option<T> {
    let mut value = MaybeUninit::<T>::uninit();
    // SAFETY: The slice covers exactly the storage reserved for `value`, no more and no less.
    // Otherwise the user copy could either overflow or leave `value` partially uninitialized.
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    if try_copy_from_user(token, src as *const u8, dst_bytes).is_err() {
        return None;
    }
    // SAFETY: A successful `try_copy_from_user` populated the entire object representation.
    Some(unsafe { value.assume_init() })
}

pub fn write_user_value<T: Copy>(token: usize, dst: *mut T, value: &T) {
    // SAFETY: `value` is a live reference and we expose exactly its object bytes for copying.
    // Extending the slice beyond `size_of::<T>()` would read unrelated kernel memory.
    let src_bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    copy_to_user(token, dst as *mut u8, src_bytes);
}

pub fn try_write_user_value<T: Copy>(token: usize, dst: *mut T, value: &T) -> Result<(), ()> {
    // SAFETY: The raw byte slice borrows `value` for this call only and matches its exact size.
    // A bad pointer/length pair here would copy invalid kernel bytes into userspace.
    let src_bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    try_copy_to_user(token, dst as *mut u8, src_bytes)
}

/// Atomically replace one user-space futex word after resolving COW/lazy
/// mappings for write.
pub fn try_compare_exchange_user_u32(
    token: usize,
    dst: *mut u32,
    current: u32,
    new: u32,
) -> Result<Result<u32, u32>, ()> {
    let va = dst as usize;
    if !va.is_multiple_of(core::mem::align_of::<u32>()) {
        return Err(());
    }
    let pte = resolve_user_pte(token, va, MapPermission::W)?;
    let pa: PhysAddr = pte.ppn().into();
    let ptr = (pa.0 + VirtAddr::from(va).page_offset()) as *const AtomicU32;
    // SAFETY: the page-table lookup verified write access, `ptr` is naturally
    // aligned, and the four-byte object is wholly contained in this page.
    Ok(unsafe { &*ptr }.compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst))
}
/// translate a single pointer
pub fn translated_single_address(token: usize, ptr: *const u8) -> &'static mut u8 {
    translated_address_with(token, ptr, MapPermission::R)
}
/// translate a pointer to a mutable u8 Vec through page table
pub fn translated_byte_buffer(
    token: usize,
    ptr: *const u8,
    len: usize,
    access: MapPermission,
) -> Vec<&'static mut [u8]> {
    if len == 0 {
        return Vec::new();
    }
    let mut start = ptr as usize;
    let end = match start.checked_add(len) {
        Some(v) => v,
        None => user_access_fail(start, access),
    };
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start);
        let mut vpn = start_va.floor();
        let pte = resolve_user_pte(token, start, access).unwrap_or_else(|_| {
            user_access_fail(start, access);
        });
        let ppn = pte.ppn();
        vpn.step();
        let mut end_va: VirtAddr = vpn.into();
        end_va = end_va.min(VirtAddr::from(end));
        if end_va.page_offset() == 0 {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..]);
        } else {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
        }
        start = end_va.into();
    }
    v
}

/// Fallible variant of `translated_byte_buffer`.
///
/// Returns `Err(())` when the range is invalid instead of terminating
/// the current task.
pub fn try_translated_byte_buffer(
    token: usize,
    ptr: *const u8,
    len: usize,
    access: MapPermission,
) -> Result<Vec<&'static mut [u8]>, ()> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut start = ptr as usize;
    let end = start.checked_add(len).ok_or(())?;
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start);
        let mut vpn = start_va.floor();
        let pte = resolve_user_pte(token, start, access)?;
        let ppn = pte.ppn();
        vpn.step();
        let mut end_va: VirtAddr = vpn.into();
        end_va = end_va.min(VirtAddr::from(end));
        if end_va.page_offset() == 0 {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..]);
        } else {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
        }
        start = end_va.into();
    }
    Ok(v)
}
