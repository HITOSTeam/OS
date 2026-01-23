//! Implementation of [`MapArea`] and [`MemorySet`].

use super::{FrameTracker, frame_alloc};
use super::{PTEFlags, PageTable, PageTableEntry};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
use crate::config::{
    MMIO, PAGE_SIZE, SIGRETURN_TRAMPOLINE, TRAMPOLINE, TRAP_CONTEXT, USER_STACK_SIZE, phys_mem_end,
};
use crate::println;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use bitflags::*;
use core::arch::asm;
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
    safe fn ekernel();
    safe fn strampoline();
}

lazy_static! {
    /// a memory set instance through lazy_static! managing kernel space
    pub static ref KERNEL_SPACE: Mutex<MemorySet> = Mutex::new(MemorySet::new_kernel());
}

/// memory set structure, controls virtual-memory space
pub struct MemorySet {
    page_table: PageTable,
    areas: Vec<MapArea>,
}

#[derive(Clone, Copy, Debug)]
pub struct ElfAux {
    pub phdr: usize,
    pub phent: usize,
    pub phnum: usize,
}

impl MemorySet {
    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: Vec::new(),
        }
    }
    pub fn token(&self) -> usize {
        self.page_table.token()
    }
    /// Assume that no conflicts.
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
        self.try_push(
            MapArea::new(start_va, end_va, MapType::Framed, permission),
            None,
        )
    }

    /// Try to insert a lazily-allocated (on-demand) anonymous area.
    pub fn try_insert_lazy_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) -> bool {
        self.try_push(
            MapArea::new(start_va, end_va, MapType::Lazy, permission),
            None,
        )
    }

    /// Map an identical (VA=PA) range into the address space.
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

    fn try_push(&mut self, mut map_area: MapArea, data: Option<&[u8]>) -> bool {
        if !map_area.map(&mut self.page_table) {
            return false;
        }
        if let Some(data) = data {
            map_area.copy_data(&self.page_table, data);
        }
        self.areas.push(map_area);
        true
    }

    /// Push an already-mapped `MapArea` into this address space (used by COW fork).
    fn push_mapped(&mut self, map_area: MapArea) {
        self.areas.push(map_area);
    }
    /// Mention that trampoline is not collected by areas.
    fn map_trampoline(&mut self) {
        self.page_table.map(
            VirtAddr::from(TRAMPOLINE).into(),
            PhysAddr::from(strampoline as usize).into(),
            PTEFlags::from(MapPermission::R | MapPermission::X),
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
        memory_set.push(
            MapArea::new(
                (ekernel as usize).into(),
                phys_mem_end().into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
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
        #[cfg(target_arch = "loongarch64")]
        {
            let dtb_start = crate::config::DEVICE_TREE_ADDR;
            let dtb_end = dtb_start + crate::config::DEVICE_TREE_MAX_SIZE;
            memory_set.map_identical_range_skip_mapped(
                dtb_start,
                dtb_end,
                MapPermission::R,
            );
        }
        memory_set
    }
    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp and entry poremove_areeint.
    /// 用户占 被设计为 程序地址 (虚拟地址) 的最高端.
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize, ElfAux) {
        let mut memory_set = Self::new_bare();
        // map trap trampoline (kernel-only) and sigreturn trampoline (user accessible)
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();
        // map program headers of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let load_bias: usize = match elf.header.pt2.type_().as_type() {
            // Map ET_DYN (shared objects / PIE) at a non-zero base so that:
            // - the null page stays unmapped by default, and
            // - the dynamic loader (musl) can map an ET_EXEC main program at low VAs.
            xmas_elf::header::Type::SharedObject => 0x2000_0000,
            _ => 0,
        };
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
        let ph_count = elf_header.pt2.ph_count();
        let ph_entry_size = elf_header.pt2.ph_entry_size() as usize;
        let ph_offset = elf_header.pt2.ph_offset() as usize;
        let ph_table_size = ph_entry_size.saturating_mul(ph_count as usize);
        let mut phdr_vaddr: usize = 0;
        let mut max_end_vpn = VirtPageNum(0);
        for i in 0..ph_count {
            let ph = elf.program_header(i).unwrap();
            // Prefer explicit PHDR segment when present.
            if phdr_vaddr == 0 && ph.get_type().unwrap() == xmas_elf::program::Type::Phdr {
                phdr_vaddr = load_bias + ph.virtual_addr() as usize;
            }
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
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
                let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
                let seg_end = map_area.vpn_range.get_end();
                if seg_end > max_end_vpn {
                    max_end_vpn = seg_end;
                }
                memory_set.push(
                    map_area,
                    Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                );

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
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        // use crate::println;
        // println!(
        //     "[DEBUG] from_elf mapping user stack: bottom={:#x}, top={:#x}",
        //     user_stack_bottom, user_stack_top
        // );

        memory_set.push(
            MapArea::new(
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        // used in sbrk (lazy heap to avoid eager page allocation)
        memory_set.push(
            MapArea::new(
                user_stack_top.into(),
                user_stack_top.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        // map TrapContext
        memory_set.push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                SIGRETURN_TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        // Return user_stack_bottom as ustack_base for thread allocation
        // Each thread will calculate its stack as: ustack_base + tid * (PAGE_SIZE + USER_STACK_SIZE)
        (
            memory_set,
            user_stack_bottom,
            load_bias + elf.header.pt2.entry_point() as usize,
            ElfAux {
                phdr: phdr_vaddr,
                phent: ph_entry_size,
                phnum: ph_count as usize,
            },
        )
    }

    fn map_elf_segments_into(
        memory_set: &mut MemorySet,
        elf_data: &[u8],
        load_bias: usize,
        max_end_vpn: &mut VirtPageNum,
    ) -> (usize, ElfAux) {
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
        let ph_count = elf_header.pt2.ph_count();
        let ph_entry_size = elf_header.pt2.ph_entry_size() as usize;
        let ph_offset = elf_header.pt2.ph_offset() as usize;
        let ph_table_size = ph_entry_size.saturating_mul(ph_count as usize);

        let mut phdr_vaddr: usize = 0;
        for i in 0..ph_count {
            let ph = elf.program_header(i).unwrap();
            if phdr_vaddr == 0 && ph.get_type().unwrap() == xmas_elf::program::Type::Phdr {
                phdr_vaddr = load_bias + ph.virtual_addr() as usize;
            }
            if ph.get_type().unwrap() != xmas_elf::program::Type::Load {
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
            let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
            let seg_end = map_area.vpn_range.get_end();
            if seg_end > *max_end_vpn {
                *max_end_vpn = seg_end;
            }
            memory_set.push(
                map_area,
                Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
            );

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

        (
            load_bias + elf.header.pt2.entry_point() as usize,
            ElfAux {
                phdr: phdr_vaddr,
                phent: ph_entry_size,
                phnum: ph_count as usize,
            },
        )
    }

    /// Map a dynamically-linked main ELF together with its interpreter (PT_INTERP) in
    /// a single address space, and return both entry points.
    pub fn from_elf_with_interp(
        main_elf: &[u8],
        interp_elf: &[u8],
    ) -> (Self, usize, usize, usize, ElfAux, usize) {
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();

        let main = xmas_elf::ElfFile::new(main_elf).unwrap();
        let interp = xmas_elf::ElfFile::new(interp_elf).unwrap();

        // Place PIE/shared objects away from zero so the null page stays unmapped.
        let main_bias = match main.header.pt2.type_().as_type() {
            xmas_elf::header::Type::SharedObject => 0x2000_0000,
            _ => 0,
        };
        // Keep the interpreter at a different base to avoid overlap with the main program.
        // Match exampleOS layout: put the interpreter high (but still within Sv39 user range)
        // to reduce collisions with the main program/heap/mmap allocations.
        let interp_bias = match interp.header.pt2.type_().as_type() {
            xmas_elf::header::Type::SharedObject => 0x30_0000_0000,
            _ => 0x30_0000_0000,
        };

        let mut max_end_vpn = VirtPageNum(0);
        let (main_entry, main_aux) =
            Self::map_elf_segments_into(&mut memory_set, main_elf, main_bias, &mut max_end_vpn);
        let (interp_entry, _interp_aux) =
            Self::map_elf_segments_into(&mut memory_set, interp_elf, interp_bias, &mut max_end_vpn);

        // Map user stack with U flags, placed above all mapped ELF segments.
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        // guard page
        user_stack_bottom += PAGE_SIZE;
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;

        memory_set.push(
            MapArea::new(
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        // used in sbrk (lazy heap to avoid eager page allocation)
        memory_set.push(
            MapArea::new(
                user_stack_top.into(),
                user_stack_top.into(),
                MapType::Lazy,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        // map TrapContext
        memory_set.push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                SIGRETURN_TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );

        (
            memory_set,
            user_stack_bottom,
            interp_entry,
            main_entry,
            main_aux,
            interp_bias,
        )
    }
    /// Fork a user address space using copy-on-write for user pages.
    ///
    /// - User pages (PTE.U) that were writable are remapped read-only and tagged with `PTEFlags::COW`
    ///   in both parent and child.
    /// - Kernel-only pages (e.g., TrapContext, no PTE.U) are copied eagerly.
    pub fn from_existed_user_cow(user_space: &mut MemorySet) -> MemorySet {
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();

        let mut parent_updates: Vec<(VirtPageNum, PTEFlags)> = Vec::new();

        for area in user_space.areas.iter() {
            let mut new_area = MapArea::from_another(area);

            for vpn in area.vpn_range {
                match area.map_type {
                    MapType::Identical => {
                        let Some(src_pte) = user_space.translate(vpn) else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let src_flags = src_pte.flags();
                        memory_set.page_table.map(vpn, src_ppn, src_flags);
                    }
                    MapType::Framed | MapType::Lazy => {
                        let Some(src_pte) = user_space.translate(vpn) else {
                            // this is for clarifing that we dont map lazy area here

                            if area.map_type == MapType::Lazy {
                                continue;
                            }
                            continue;
                        };
                        if !src_pte.is_valid() {
                            if area.map_type == MapType::Lazy {
                                continue;
                            }
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
                            memory_set.page_table.map(vpn, frame.ppn, src_flags);
                            new_area.data_frames.insert(vpn, frame);
                            continue;
                        }

                        // Share the physical page.
                        if src_flags.contains(PTEFlags::W) && !src_flags.contains(PTEFlags::SHARED)
                        {
                            src_flags.remove(PTEFlags::W);
                            src_flags.insert(PTEFlags::COW);
                            parent_updates.push((vpn, src_flags));
                        }
                        memory_set.page_table.map(vpn, src_ppn, src_flags);
                        if let Some(ft) = area.data_frames.get(&vpn) {
                            new_area.data_frames.insert(vpn, ft.clone());
                        }
                    }
                }
            }

            memory_set.push_mapped(new_area);
        }

        // Apply parent COW flag updates after we finish iterating its areas.
        for (vpn, flags) in parent_updates {
            user_space.set_pte_flags(vpn, flags);
        }

        memory_set
    }

    /// Fork a user address space by copying all mapped pages (no COW).
    ///
    /// This is slower than COW but avoids COW corner cases on some platforms.
    pub fn from_existed_user(user_space: &MemorySet) -> MemorySet {
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();
        memory_set.map_sigreturn_trampoline_user();

        for area in user_space.areas.iter() {
            let mut new_area = MapArea::from_another(area);

            for vpn in area.vpn_range {
                match area.map_type {
                    MapType::Identical => {
                        let Some(src_pte) = user_space.translate(vpn) else {
                            continue;
                        };
                        if !src_pte.is_valid() {
                            continue;
                        }
                        let src_ppn = src_pte.ppn();
                        let src_flags = src_pte.flags();
                        memory_set.page_table.map(vpn, src_ppn, src_flags);
                    }
                    MapType::Framed | MapType::Lazy => {
                        let Some(src_pte) = user_space.translate(vpn) else {
                            if area.map_type == MapType::Lazy {
                                continue;
                            }
                            continue;
                        };
                        if !src_pte.is_valid() {
                            if area.map_type == MapType::Lazy {
                                continue;
                            }
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
                        let pte_flags = PTEFlags::from(area.map_perm);
                        memory_set.page_table.map(vpn, frame.ppn, pte_flags);
                        new_area.data_frames.insert(vpn, frame);
                    }
                }
            }

            memory_set.push_mapped(new_area);
        }

        memory_set
    }

    /// Insert a user-mapped framed area backed by the provided physical frames.
    ///
    /// Used by System V shared memory (`shmat`) to map the same physical pages
    /// into multiple processes.
    pub fn insert_shared_frames_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
        frames: Vec<FrameTracker>,
    ) {
        let mut area = MapArea::new(start_va, end_va, MapType::Framed, permission);
        let pte_flags = PTEFlags::from(area.map_perm) | PTEFlags::SHARED;
        for (vpn, frame) in area.vpn_range.into_iter().zip(frames.into_iter()) {
            self.page_table.map(vpn, frame.ppn, pte_flags);
            area.data_frames.insert(vpn, frame);
        }
        self.push_mapped(area);
    }

    /// Resolve a copy-on-write fault at `fault_va` if the page is tagged COW.
    pub fn resolve_cow_fault(&mut self, fault_va: usize) -> bool {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        let Some(pte) = self.translate(vpn) else {
            return false;
        };
        let flags = pte.flags();
        if !flags.contains(PTEFlags::COW) {
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
        if !self.page_table.remap(vpn, frame.ppn, new_flags) {
            return false;
        }

        // Update the owning MapArea's frame tracker so the old shared frame gets its refcount decremented.
        for area in self.areas.iter_mut() {
            if area.map_type == MapType::Identical {
                continue;
            }
            if vpn < area.vpn_range.get_start() || vpn >= area.vpn_range.get_end() {
                continue;
            }
            area.data_frames.insert(vpn, frame);
            break;
        }

        // Flush TLB for this address.
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("sfence.vma {0}, zero", in(reg) fault_va);
        }
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            core::arch::asm!("invtlb 0x4, $r0, {}", in(reg) fault_va);
        }
        true
    }

    /// Resolve a lazy anonymous mapping fault by allocating a page on demand.
    pub fn resolve_lazy_fault(&mut self, fault_va: usize, access: MapPermission) -> bool {
        let vpn: VirtPageNum = VirtAddr::from(fault_va).floor();
        for area in self.areas.iter_mut() {
            if area.map_type != MapType::Lazy {
                continue;
            }
            if vpn < area.vpn_range.get_start() || vpn >= area.vpn_range.get_end() {
                continue;
            }
            if !area.map_perm.contains(access) {
                return false;
            }
            if let Some(pte) = self.page_table.translate(vpn) {
                if pte.is_valid() {
                    return false;
                }
            }
            let Some(frame) = frame_alloc() else {
                crate::println!("[mm] OOM: lazy fault alloc failed for vpn={:?}", vpn);
                return false;
            };
            let pte_flags = PTEFlags::from(area.map_perm);
            self.page_table.map(vpn, frame.ppn, pte_flags);
            area.data_frames.insert(vpn, frame);
            #[cfg(target_arch = "riscv64")]
            unsafe {
                core::arch::asm!("sfence.vma {0}, zero", in(reg) fault_va);
            }
            #[cfg(target_arch = "loongarch64")]
            unsafe {
                core::arch::asm!("invtlb 0x4, $r0, {}", in(reg) fault_va);
            }
            return true;
        }
        false
    }
    pub fn activate(&self) {
        #[cfg(target_arch = "riscv64")]
        {
            let satp = self.page_table.token();
            unsafe {
                satp::write(Satp::from_bits(satp));
                asm!("sfence.vma");
            }
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
        self.page_table.set_flags(vpn, flags)
    }
    #[allow(unused)]
    pub fn shrink_to(&mut self, start: VirtAddr, new_end: VirtAddr) -> bool {
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.vpn_range.get_start() == start.floor())
        {
            area.shrink_to(&mut self.page_table, new_end.ceil());
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
            .find(|area| area.vpn_range.get_start() == start.floor())
        {
            area.append_to(&mut self.page_table, new_end.ceil())
        } else {
            false
        }
    }

    pub fn remove_area(&mut self, start_va: VirtAddr, end_va: VirtAddr) {
        if let Some((idx, area)) = self.areas.iter_mut().enumerate().find(|(_idx, area)| {
            area.vpn_range.get_start() == start_va.floor()
                && area.vpn_range.get_end() == end_va.ceil()
        }) {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
        };
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

        let mut new_areas: Vec<MapArea> = Vec::new();
        let mut areas = core::mem::take(&mut self.areas);
        for mut area in areas.drain(..) {
            if !area.map_perm.contains(MapPermission::U) {
                new_areas.push(area);
                continue;
            }

            let area_start = area.vpn_range.get_start();
            let area_end = area.vpn_range.get_end();
            if end_vpn <= area_start || start_vpn >= area_end {
                new_areas.push(area);
                continue;
            }

            let ov_start = core::cmp::max(start_vpn, area_start);
            let ov_end = core::cmp::min(end_vpn, area_end);

            for vpn in VPNRange::new(ov_start, ov_end) {
                area.unmap_one_maybe(&mut self.page_table, vpn);
            }

            let mut left_frames = BTreeMap::new();
            let mut right_frames = BTreeMap::new();
            if area.map_type != MapType::Identical {
                let mut remaining = core::mem::take(&mut area.data_frames);
                right_frames = remaining.split_off(&ov_end);
                let overlap = remaining.split_off(&ov_start);
                drop(overlap);
                left_frames = remaining;
            }

            if area_start < ov_start {
                let mut left = MapArea::from_another(&area);
                left.vpn_range = VPNRange::new(area_start, ov_start);
                left.data_frames = left_frames;
                new_areas.push(left);
            }
            if ov_end < area_end {
                let mut right = MapArea::from_another(&area);
                right.vpn_range = VPNRange::new(ov_end, area_end);
                right.start_offset = 0;
                right.data_frames = right_frames;
                new_areas.push(right);
            }
        }
        self.areas = new_areas;
    }

    /// Update user mapping permissions in `[start_va, end_va)`.
    ///
    /// Returns `false` if any portion of the range is not mapped as a user area.
    pub fn mprotect_user_range(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        new_perm: MapPermission,
    ) -> bool {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        if start_vpn >= end_vpn {
            return true;
        }

        // Ensure the range is fully covered by user areas.
        let mut cursor = start_vpn;
        while cursor < end_vpn {
            let mut covered = false;
            let mut next = end_vpn;
            for area in self.areas.iter() {
                if !area.map_perm.contains(MapPermission::U) {
                    continue;
                }
                let area_start = area.vpn_range.get_start();
                let area_end = area.vpn_range.get_end();
                if cursor >= area_start && cursor < area_end {
                    covered = true;
                    next = core::cmp::min(area_end, end_vpn);
                    break;
                }
            }
            if !covered {
                return false;
            }
            cursor = next;
        }

        let mut new_areas: Vec<MapArea> = Vec::new();
        let mut areas = core::mem::take(&mut self.areas);
        for mut area in areas.drain(..) {
            if !area.map_perm.contains(MapPermission::U) {
                new_areas.push(area);
                continue;
            }

            let area_start = area.vpn_range.get_start();
            let area_end = area.vpn_range.get_end();
            if end_vpn <= area_start || start_vpn >= area_end {
                new_areas.push(area);
                continue;
            }

            let ov_start = core::cmp::max(start_vpn, area_start);
            let ov_end = core::cmp::min(end_vpn, area_end);

            let mut left_frames = BTreeMap::new();
            let mut mid_frames = BTreeMap::new();
            let mut right_frames = BTreeMap::new();
            if area.map_type != MapType::Identical {
                let mut remaining = core::mem::take(&mut area.data_frames);
                right_frames = remaining.split_off(&ov_end);
                let overlap = remaining.split_off(&ov_start);
                mid_frames = overlap;
                left_frames = remaining;
            }

            for vpn in VPNRange::new(ov_start, ov_end) {
                if let Some(pte) = self.page_table.translate(vpn) {
                    if pte.is_valid() {
                        if new_perm == MapPermission::U {
                            // PROT_NONE: unmap but keep the frame tracker.
                            self.page_table.unmap(vpn);
                            continue;
                        }
                        let mut pte_flags = PTEFlags::from(new_perm);
                        let old_flags = pte.flags();
                        if old_flags.contains(PTEFlags::COW) {
                            pte_flags.insert(PTEFlags::COW);
                            pte_flags.remove(PTEFlags::W);
                        }
                        if old_flags.contains(PTEFlags::SHARED) {
                            pte_flags.insert(PTEFlags::SHARED);
                        }
                        let _ = self.page_table.set_flags(vpn, pte_flags);
                        continue;
                    }
                }
                if new_perm != MapPermission::U {
                    if let Some(frame) = mid_frames.get(&vpn) {
                        let pte_flags = PTEFlags::from(new_perm);
                        self.page_table.map(vpn, frame.ppn, pte_flags);
                    }
                }
            }

            if area_start < ov_start {
                let mut left = MapArea::from_another(&area);
                left.vpn_range = VPNRange::new(area_start, ov_start);
                left.data_frames = left_frames;
                new_areas.push(left);
            }

            let mut mid = MapArea::from_another(&area);
            mid.vpn_range = VPNRange::new(ov_start, ov_end);
            if ov_start != area_start {
                mid.start_offset = 0;
            }
            mid.map_perm = new_perm;
            mid.data_frames = mid_frames;
            new_areas.push(mid);

            if ov_end < area_end {
                let mut right = MapArea::from_another(&area);
                right.vpn_range = VPNRange::new(ov_end, area_end);
                right.start_offset = 0;
                right.data_frames = right_frames;
                new_areas.push(right);
            }
        }
        self.areas = new_areas;
        true
    }

    /// Returns true if any existing mapping overlaps the range.
    pub fn range_overlaps(&self, start_va: VirtAddr, end_va: VirtAddr) -> bool {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        self.areas.iter().any(|area| {
            let area_start = area.vpn_range.get_start();
            let area_end = area.vpn_range.get_end();
            end_vpn > area_start && start_vpn < area_end
        })
    }
    pub fn remove_area_with_start_vpn(&mut self, start_va: VirtAddr) {
        if let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .find(|(_idx, area)| area.vpn_range.get_start() == start_va.floor())
        {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
        };
    }

    pub fn clone(&self) -> Self {
        let mut new_memory_set = Self::new_bare();
        let has_user = self
            .areas
            .iter()
            .any(|area| area.map_perm.contains(MapPermission::U));
        new_memory_set.map_trampoline();
        if has_user {
            new_memory_set.map_sigreturn_trampoline_user();
        }
        for area in &self.areas {
            let mut new_area = MapArea::new(
                VirtAddr::from(area.vpn_range.get_start()),
                VirtAddr::from(area.vpn_range.get_end()),
                area.map_type,
                area.map_perm,
            );
            if area.map_type == MapType::Lazy {
                let pte_flags = PTEFlags::from(new_area.map_perm);
                for vpn in area.vpn_range {
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
                    new_area.data_frames.insert(vpn, frame);
                }
                new_memory_set.push_mapped(new_area);
                continue;
            }

            new_memory_set.push(new_area, None);
            //then copy data

            for vpn in area.vpn_range {
                let src_ppn = self.page_table.translate(vpn).unwrap().ppn();
                let dst_ppn = new_memory_set.page_table.translate(vpn).unwrap().ppn();
                let src_bytes = src_ppn.get_bytes_array();
                let dst_bytes = dst_ppn.get_bytes_array();
                dst_bytes.copy_from_slice(&src_bytes);
            }
        }

        new_memory_set
    }
    pub fn recycle_data_pages(&mut self) {
        //*self = Self::new_bare();
        self.areas.clear();
    }
}

/// map area structure, controls a contiguous piece of virtual memory
pub struct MapArea {
    vpn_range: VPNRange,
    data_frames: BTreeMap<VirtPageNum, FrameTracker>,
    map_type: MapType,
    map_perm: MapPermission,
    start_offset: usize,
}

impl MapArea {
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
    ) -> Self {
        let start_vpn: VirtPageNum = start_va.floor();
        let end_vpn: VirtPageNum = end_va.ceil();
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            map_type,
            map_perm,
            start_offset: start_va.page_offset(),
        }
    }
    pub fn from_another(another: &MapArea) -> Self {
        Self {
            vpn_range: VPNRange::new(another.vpn_range.get_start(), another.vpn_range.get_end()),
            data_frames: BTreeMap::new(),
            map_type: another.map_type,
            map_perm: another.map_perm,
            start_offset: another.start_offset,
        }
    }
    /// map _one 两种映射类型.其中恒等映射 本人是不持有 frame 的.
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) -> bool {
        if self.map_type == MapType::Lazy {
            return true;
        }
        let ppn: PhysPageNum = match self.map_type {
            MapType::Identical => PhysPageNum(vpn.0),
            MapType::Framed => {
                let Some(frame) = frame_alloc() else {
                    crate::println!("[mm] OOM: frame_alloc failed for vpn={:?}", vpn);
                    return false;
                };
                let ppn = frame.ppn;
                self.data_frames.insert(vpn, frame);
                ppn
            }
            MapType::Lazy => unreachable!(),
        };
        let pte_flags = PTEFlags::from(self.map_perm);
        page_table.map(vpn, ppn, pte_flags);
        true
    }
    #[allow(unused)]
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if self.map_type != MapType::Identical {
            self.data_frames.remove(&vpn);
        }
        if self.map_type == MapType::Lazy {
            page_table.unmap_if_mapped(vpn);
        } else {
            page_table.unmap(vpn);
        }
    }

    pub fn unmap_one_maybe(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if self.map_type != MapType::Identical {
            self.data_frames.remove(&vpn);
        }
        page_table.unmap_if_mapped(vpn);
    }

    /// 清理内存,并且将内存进行映射,内部使用map_one 逐个映射.
    pub fn map(&mut self, page_table: &mut PageTable) -> bool {
        if self.map_type == MapType::Lazy {
            return true;
        }
        let mut mapped: Vec<VirtPageNum> = Vec::new();
        for vpn in self.vpn_range {
            if !self.map_one(page_table, vpn) {
                // Roll back any partial mappings to avoid leaving an invalid address space.
                for vpn in mapped {
                    self.unmap_one_maybe(page_table, vpn);
                }
                return false;
            }
            mapped.push(vpn);
        }
        true
    }
    #[allow(unused)]
    pub fn unmap(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range {
            self.unmap_one(page_table, vpn);
        }
    }
    #[allow(unused)]
    pub fn shrink_to(&mut self, page_table: &mut PageTable, new_end: VirtPageNum) {
        for vpn in VPNRange::new(new_end, self.vpn_range.get_end()) {
            self.unmap_one(page_table, vpn)
        }
        self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
    }
    #[allow(unused)]
    pub fn append_to(&mut self, page_table: &mut PageTable, new_end: VirtPageNum) -> bool {
        if self.map_type == MapType::Lazy {
            self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
            return true;
        }
        let old_end = self.vpn_range.get_end();
        let mut mapped: Vec<VirtPageNum> = Vec::new();
        for vpn in VPNRange::new(old_end, new_end) {
            if !self.map_one(page_table, vpn) {
                // Roll back the newly mapped suffix.
                for vpn in mapped {
                    self.unmap_one_maybe(page_table, vpn);
                }
                return false;
            }
            mapped.push(vpn);
        }
        self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
        true
    }
    /// data: start-aligned but maybe with shorter length
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &PageTable, data: &[u8]) {
        assert_eq!(self.map_type, MapType::Framed);
        let mut current_vpn = self.vpn_range.get_start();
        let mut src_off = 0usize;

        // First page may start at an offset within the page.
        let mut page_off = self.start_offset;
        while src_off < data.len() {
            let dst_page = page_table
                .translate(current_vpn)
                .unwrap()
                .ppn()
                .get_bytes_array();
            let cap = PAGE_SIZE - page_off;
            let to_copy = core::cmp::min(cap, data.len() - src_off);
            dst_page[page_off..page_off + to_copy]
                .copy_from_slice(&data[src_off..src_off + to_copy]);
            src_off += to_copy;
            current_vpn.step();
            page_off = 0;
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
/// map type for memory set: identical, framed, or lazy (on-demand)
pub enum MapType {
    Identical,
    Framed,
    Lazy,
}

bitflags! {
    /// map permission corresponding to that in pte: `R W X U`
    pub struct MapPermission: u8 {
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        /// Device/IO memory mapping (non-cacheable on loongarch64).
        const IO = 1 << 5;
    }
}
pub fn kernel_token() -> usize {
    KERNEL_SPACE.lock().token()
}

pub fn activate_token(token: usize) {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        satp::write(Satp::from_bits(token));
        asm!("sfence.vma");
    }
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
