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
use core::{cmp::min, mem::MaybeUninit};

bitflags! {
    /// page table entry flags
    pub struct PTEFlags: u16 {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
        /// Software-managed copy-on-write marker (Sv39 PTE RSW bit 0).
        const COW = 1 << 8;
        /// Software-managed shared mapping marker (Sv39 PTE RSW bit 1).
        ///
        /// Used to preserve System V shared memory mappings across `fork()`.
        const SHARED = 1 << 9;
    }
}

impl From<MapPermission> for PTEFlags {
    fn from(perm: MapPermission) -> Self {
        let mut flags = PTEFlags::empty();
        if perm.contains(MapPermission::R) {
            flags |= PTEFlags::R;
        }
        if perm.contains(MapPermission::W) {
            // RISC-V leaf PTEs with W=1 and R=0 are reserved.
            // Keep PROT_WRITE mappings hardware-valid by forcing R when W is set.
            flags |= PTEFlags::R | PTEFlags::W;
        }
        if perm.contains(MapPermission::X) {
            flags |= PTEFlags::X;
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
        PageTableEntry {
            bits: ppn.0 << 10 | flags.bits as usize,
        }
    }
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }
    pub fn ppn(&self) -> PhysPageNum {
        (self.bits >> 10 & ((1usize << 44) - 1)).into()
    }
    pub fn flags(&self) -> PTEFlags {
        // Low 10 bits are flags (including the 2 software RSW bits).
        PTEFlags::from_bits((self.bits & 0x3ff) as u16).unwrap()
    }
    pub fn is_valid(&self) -> bool {
        (self.flags() & PTEFlags::V) != PTEFlags::empty()
    }
    pub fn readable(&self) -> bool {
        (self.flags() & PTEFlags::R) != PTEFlags::empty()
    }
    pub fn writable(&self) -> bool {
        (self.flags() & PTEFlags::W) != PTEFlags::empty()
    }
    pub fn executable(&self) -> bool {
        (self.flags() & PTEFlags::X) != PTEFlags::empty()
    }
}

/// page table structure
pub struct PageTable {
    root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}

/// Cached upper-level walk state for repeated nearby VPN lookups/maps.
///
/// `MemorySet::from_existed_user_cow()` iterates sorted VPNs and can reuse
/// this cache to avoid full 3-level walks on every page.
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
    pub fn from_token(satp: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(satp & ((1usize << 44) - 1)),
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
        let pte = self.find_pte_create(vpn).unwrap();
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
    }

    /// Fast-path map for sorted/nearby VPN streams.
    ///
    /// Semantics are identical to `map()`, but the two upper page-table levels
    /// are cached in `cache` to avoid repeated full walks.
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
        assert!(
            !pte_leaf.is_valid(),
            "vpn {:?} is mapped before mapping",
            vpn
        );
        *pte_leaf = PageTableEntry::new(ppn, flags | PTEFlags::V);
    }
    #[allow(unused)]
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte(vpn).unwrap();
        assert!(pte.is_valid(), "vpn {:?} is invalid before unmapping", vpn);
        *pte = PageTableEntry::empty();
    }

    /// Unmap an existing leaf PTE if it is present and valid.
    ///
    /// Returns `true` if an entry was unmapped.
    pub fn unmap_if_mapped(&mut self, vpn: VirtPageNum) -> bool {
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

    /// Update an existing leaf PTE's mapped PPN and flags.
    ///
    /// Returns `false` if the vpn is not mapped.
    pub fn remap(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) -> bool {
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
        8usize << 60 | self.root_ppn.0
    }
    #[allow(dead_code)]
    pub fn clone(&self) -> Self {
        //todo:alloc new frames...
        return Self {
            root_ppn: self.root_ppn,
            frames: Vec::new(),
        };
    }
}

#[allow(dead_code)]
fn try_resolve_lazy_page(token: usize, va: usize, access: MapPermission) -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let Some(process) = task.process.upgrade() else {
        return false;
    };
    let Some(inner) = process.try_borrow_mut() else {
        return false;
    };
    if token != inner.memory_set.token() {
        return false;
    }
    match inner.memory_set.resolve_lazy_fault(va, access) {
        LazyFaultResult::Resolved => true,
        LazyFaultResult::Oom => {
            drop(inner);
            crate::task::processor::exit_group_and_run_next(-9)
        }
        LazyFaultResult::Invalid => false,
    }
}

fn try_resolve_user_page(token: usize, va: usize, access: MapPermission) -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let Some(process) = task.process.upgrade() else {
        return false;
    };
    let Some(inner) = process.try_borrow_mut() else {
        return false;
    };
    if token != inner.memory_set.token() {
        return false;
    }
    if access.contains(MapPermission::W) && inner.memory_set.resolve_cow_fault(va) {
        return true;
    }
    match inner.memory_set.resolve_lazy_fault(va, access) {
        LazyFaultResult::Resolved => true,
        LazyFaultResult::Oom => {
            drop(inner);
            crate::task::processor::exit_group_and_run_next(-9)
        }
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
    if access.contains(MapPermission::W) && !flags.contains(PTEFlags::W) {
        if flags.contains(PTEFlags::COW) && try_resolve_user_page(token, va, access) {
            pte = page_table.translate(vpn).ok_or(())?;
            flags = pte.flags();
        }
    }
    if !flags.contains(PTEFlags::U) {
        return Err(());
    }
    if access.contains(MapPermission::R) && !flags.contains(PTEFlags::R) {
        return Err(());
    }
    if access.contains(MapPermission::W) && !flags.contains(PTEFlags::W) {
        return Err(());
    }
    if access.contains(MapPermission::X) && !flags.contains(PTEFlags::X) {
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
#[allow(dead_code)]
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
    // SAFETY: `translated_address_with` resolved `ptr` to a writable mapped byte in the current
    // user address space, and the caller treats that location as a properly aligned `T`. If the
    // user pointer does not actually refer to a valid `T`, this cast would create an invalid reference.
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
        // SAFETY: `resolve_user_pte` verified this user page is readable, `written + n` stays
        // within `dst`, and the source physical range is page-local. Any overlap or bad mapping
        // here would turn the copy into memory corruption instead of a user-access failure.
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
        // SAFETY: `resolve_user_pte` verified this user page is writable, `read + n` stays within
        // `src`, and the destination range is limited to this mapped page. If those invariants were
        // wrong, the kernel would write through an invalid or overlapping pointer.
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
        // SAFETY: This uses the same bounds reasoning as `try_copy_to_user`, except permission
        // checks are intentionally relaxed after the page has already been resolved for this token.
        // A wrong page translation or length would still corrupt kernel-visible memory.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr().add(read), (pa.0 + page_off) as *mut u8, n);
        }
        start += n;
        read += n;
    }
    Ok(())
}

// Why we use MaybeUninit Here? On the one hand,it is because we want to use this function for
// multi-types, we don't know if this type have Default trait and for some types,it can be heavy to initialize an empty value.This is a very
// frequently used function.So we use this to optimiz
pub fn read_user_value<T: Copy>(token: usize, src: *const T) -> T {
    let mut value = MaybeUninit::<T>::uninit();
    // SAFETY: `value` is stack-allocated and we expose exactly `size_of::<T>()` bytes of its
    // storage so `copy_from_user` can initialize it. Using the wrong size would leave bytes
    // uninitialized or write past `value`.
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    copy_from_user(token, src as *const u8, dst_bytes);
    // SAFETY: `copy_from_user` filled every byte in `dst_bytes`, so `value` is fully initialized.
    // Calling `assume_init` earlier would read uninitialized data.
    unsafe { value.assume_init() }
}

pub fn try_read_user_value<T: Copy>(token: usize, src: *const T) -> Option<T> {
    let mut value = MaybeUninit::<T>::uninit();
    // SAFETY: `value` provides `size_of::<T>()` writable bytes for the incoming user copy. Any
    // mismatch between the slice length and `T` would corrupt stack memory or leave bytes unset.
    let dst_bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    if try_copy_from_user(token, src as *const u8, dst_bytes).is_err() {
        return None;
    }
    // SAFETY: The successful copy initialized the whole object representation of `value`.
    Some(unsafe { value.assume_init() })
}

pub fn write_user_value<T: Copy>(token: usize, dst: *mut T, value: &T) {
    // SAFETY: `value` is a valid reference to `T`, so reborrowing exactly its object bytes is
    // sound for copying into userspace. A wrong length would read beyond `value`.
    let src_bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    copy_to_user(token, dst as *mut u8, src_bytes);
}

pub fn try_write_user_value<T: Copy>(token: usize, dst: *mut T, value: &T) -> Result<(), ()> {
    // SAFETY: `value` stays alive for this call and `size_of::<T>()` matches the byte slice we
    // expose. Misstating the range here would read invalid kernel memory before copying it out.
    let src_bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    try_copy_to_user(token, dst as *mut u8, src_bytes)
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
