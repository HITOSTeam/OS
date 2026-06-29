use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

use riscv::register::satp::{self, Satp};

use crate::config::MAX_HARTS;

/// Linux-style per-mm ASID and deferred I-cache state.
///
/// RISC-V SATP carries both the page-table PPN and ASID, so each `MemorySet`
/// caches an ASID generation here and only asks the trampoline for `sfence.vma`
/// when the ASID is new or hardware ASID is unavailable. Executable mapping
/// changes mark the mm's I-cache stale; on SMP we keep the conservative
/// `fence.i` behaviour until active-mm tracking can safely target remote harts.
const SATP_ASID_SHIFT: usize = 44;
const SATP_ASID_MASK: usize = 0xffff;
const KERNEL_ASID: usize = 0;
const FIRST_USER_ASID: usize = 1;
const HW_ASID_MASK_UNPROBED: usize = usize::MAX;

static NEXT_USER_ASID: AtomicUsize = AtomicUsize::new(FIRST_USER_ASID);
static ASID_GENERATION: AtomicUsize = AtomicUsize::new(1);
static HW_ASID_MASK: AtomicUsize = AtomicUsize::new(HW_ASID_MASK_UNPROBED);

pub struct AsidContext {
    asid: AtomicUsize,
    generation: AtomicUsize,
    icache_stale_mask: AtomicUsize,
}

impl AsidContext {
    pub const fn new() -> Self {
        Self {
            asid: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
            icache_stale_mask: AtomicUsize::new(configured_hart_mask()),
        }
    }

    fn current(&self) -> (usize, usize) {
        (
            self.asid.load(Ordering::Acquire),
            self.generation.load(Ordering::Acquire),
        )
    }

    fn valid_for(&self, generation: usize) -> bool {
        let (asid, ctx_generation) = self.current();
        asid != KERNEL_ASID && ctx_generation == generation
    }

    fn store(&self, asid: usize, generation: usize) {
        self.generation.store(generation, Ordering::Release);
        self.asid.store(asid, Ordering::Release);
    }

    pub fn invalidate(&self) {
        self.asid.store(0, Ordering::Release);
        self.generation.store(0, Ordering::Release);
    }

    pub fn mark_icache_stale(&self) {
        self.icache_stale_mask
            .fetch_or(online_hart_mask(), Ordering::Release);
    }

    fn take_local_icache_stale(&self, single_hart: bool) -> bool {
        // Until we track active mm contexts and can issue remote fence.i like
        // Linux, keep the old conservative behaviour on SMP. The SMP=1 path is
        // the hot cyclictest/hackbench case and can safely defer I-cache flushes
        // per mm/hart.
        if !single_hart {
            return true;
        }
        let bit = local_hart_bit();
        if bit == 0 {
            return self.icache_stale_mask.swap(0, Ordering::AcqRel) != 0;
        }
        self.icache_stale_mask.fetch_and(!bit, Ordering::AcqRel) & bit != 0
    }
}

fn single_hart_online() -> bool {
    crate::task::manager::online_hart_mask().count_ones() <= 1
}

const fn configured_hart_mask() -> usize {
    if MAX_HARTS >= usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << MAX_HARTS) - 1
    }
}

fn online_hart_mask() -> usize {
    let mask = crate::task::manager::online_hart_mask() & configured_hart_mask();
    if mask == 0 { 1 } else { mask }
}

fn local_hart_bit() -> usize {
    let hart = crate::arch::hart_id();
    if hart < usize::BITS as usize {
        1usize << hart
    } else {
        0
    }
}

fn probe_hw_asid_mask() -> usize {
    let old = satp::read().bits();
    let trial = old | (SATP_ASID_MASK << SATP_ASID_SHIFT);
    // SAFETY: probing SATP ASID bits follows the Linux approach: write ones to
    // the ASID field, read back implemented bits, then restore the old SATP.
    unsafe {
        satp::write(Satp::from_bits(trial));
    }
    let supported = (satp::read().bits() >> SATP_ASID_SHIFT) & SATP_ASID_MASK;
    // SAFETY: restore the exact SATP value and discard any translations that
    // may have been populated while the temporary ASID was active.
    unsafe {
        satp::write(Satp::from_bits(old));
        asm!("sfence.vma", options(nostack));
    }
    supported
}

fn hw_asid_mask() -> usize {
    let cached = HW_ASID_MASK.load(Ordering::Acquire);
    if cached != HW_ASID_MASK_UNPROBED {
        return cached;
    }

    let probed = probe_hw_asid_mask();
    let _ = HW_ASID_MASK.compare_exchange(
        HW_ASID_MASK_UNPROBED,
        probed,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    HW_ASID_MASK.load(Ordering::Acquire)
}

fn asid_fast_path_enabled() -> bool {
    single_hart_online() && hw_asid_mask() != 0
}

fn allocate_user_asid(max_asid: usize) -> (usize, usize, bool) {
    let asid = NEXT_USER_ASID.fetch_add(1, Ordering::AcqRel);
    if asid <= max_asid {
        return (asid, ASID_GENERATION.load(Ordering::Acquire), false);
    }

    let current = ASID_GENERATION.load(Ordering::Acquire);
    let mut next_generation = current.wrapping_add(1);
    if next_generation == 0 {
        next_generation = 1;
    }
    ASID_GENERATION.store(next_generation, Ordering::Release);
    NEXT_USER_ASID.store(FIRST_USER_ASID + 1, Ordering::Release);
    (FIRST_USER_ASID, next_generation, true)
}

fn token_with_asid(token: usize, asid: usize) -> usize {
    (token & !(SATP_ASID_MASK << SATP_ASID_SHIFT)) | ((asid & SATP_ASID_MASK) << SATP_ASID_SHIFT)
}

pub fn prepare_user_satp(ctx: &AsidContext, token: usize) -> (usize, bool, bool) {
    let single_hart = single_hart_online();
    let need_icache_flush = ctx.take_local_icache_stale(single_hart);
    let max_asid = hw_asid_mask();
    if !(single_hart && max_asid != 0) {
        return (token_with_asid(token, KERNEL_ASID), true, need_icache_flush);
    }

    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if ctx.valid_for(generation) {
        return (
            token_with_asid(token, ctx.asid.load(Ordering::Acquire)),
            false,
            need_icache_flush,
        );
    }

    let (asid, generation, need_flush) = allocate_user_asid(max_asid);
    ctx.store(asid, generation);
    (token_with_asid(token, asid), need_flush, need_icache_flush)
}

pub fn drop_user_asid(ctx: &AsidContext) {
    ctx.invalidate();
}

pub fn mark_icache_stale(ctx: &AsidContext) {
    ctx.mark_icache_stale();
}

pub fn flush_user_page(ctx: &AsidContext, vaddr: usize) {
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if asid_fast_path_enabled() && ctx.valid_for(generation) {
        let asid = ctx.asid.load(Ordering::Acquire);
        // SAFETY: the address and ASID are kernel-managed; this invalidates one
        // non-global user translation while preserving unrelated ASIDs.
        unsafe {
            asm!(
                "sfence.vma {addr}, {asid}",
                addr = in(reg) vaddr,
                asid = in(reg) asid,
                options(nostack)
            );
        }
    } else {
        // SAFETY: when no valid ASID is assigned, flush the address for all ASIDs.
        unsafe {
            asm!("sfence.vma {addr}, zero", addr = in(reg) vaddr, options(nostack));
        }
    }
}
