use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::sync::Arc;
use riscv::register::satp::{self, Satp};
use spin::Mutex;

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
/// Address space whose translations each hart may currently consume.
///
/// Linux keeps the equivalent per-CPU `active_mm` pointer and updates
/// `mm_cpumask()` during `switch_mm()`. Holding an `Arc` here gives the same
/// lifetime guarantee: a writer can snapshot the target mask without racing an
/// `AsidContext` free, and the bit is cleared only after the hart has installed
/// the kernel SATP.
static ACTIVE_USER_CONTEXTS: [Mutex<Option<Arc<AsidContext>>>; MAX_HARTS] =
    [const { Mutex::new(None) }; MAX_HARTS];

pub struct AsidContext {
    asid: AtomicUsize,
    generation: AtomicUsize,
    icache_stale_mask: AtomicUsize,
    /// Harts that may consume translations from this address space.
    ///
    /// This is the local equivalent of Linux's `mm_cpumask(mm)`: COW PTE
    /// replacement only needs a remote TLB invalidation on CPUs that can still
    /// consume this mm's old translation. The bit remains set in a syscall
    /// because the RISC-V trap path deliberately keeps the user SATP active.
    active_hart_mask: AtomicUsize,
}

impl AsidContext {
    pub const fn new() -> Self {
        Self {
            asid: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
            icache_stale_mask: AtomicUsize::new(configured_hart_mask()),
            active_hart_mask: AtomicUsize::new(0),
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

    fn mark_local_active(&self) {
        let bit = local_hart_bit();
        if bit != 0 {
            // Acquiring the writer's zero-bit RMW below ensures page-table
            // stores become visible before the final local sfence/user return
            // when the writer raced just before this activation.
            self.active_hart_mask.fetch_or(bit, Ordering::AcqRel);
        }
    }

    fn mark_local_inactive(&self) {
        let bit = local_hart_bit();
        if bit != 0 {
            self.active_hart_mask.fetch_and(!bit, Ordering::AcqRel);
        }
    }

    fn active_harts_after_pte_update(&self) -> usize {
        // A zero-bit RMW publishes all preceding PTE writes. If a returning
        // hart activates after this snapshot, its AcqRel RMW observes this
        // release sequence before it performs the mandatory local sfence. If
        // it activates first, this operation observes its bit and the caller
        // sends a remote shootdown.
        self.active_hart_mask.fetch_or(0, Ordering::AcqRel)
    }
}

fn switch_local_active_context(ctx: &Arc<AsidContext>) {
    let hart = crate::arch::hart_id() % MAX_HARTS;
    let mut active = ACTIVE_USER_CONTEXTS[hart].lock();
    if active
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, ctx))
    {
        ctx.mark_local_active();
        return;
    }
    if let Some(previous) = active.replace(Arc::clone(ctx)) {
        previous.mark_local_inactive();
    }
    ctx.mark_local_active();
}

/// Pin the user address space currently associated with this hart.
///
/// A temporary kernel-page-table guard can outlive a scheduler switch while
/// waiting for block I/O.  Keeping this `Arc` lets the guard publish the same
/// active-mm again before it restores the saved user SATP, even when the task
/// resumes on a different hart.
pub fn pin_local_user_mm() -> Option<Arc<AsidContext>> {
    let hart = crate::arch::hart_id() % MAX_HARTS;
    ACTIVE_USER_CONTEXTS[hart].lock().as_ref().map(Arc::clone)
}

/// Publish a pinned user address space on the current hart.
///
/// This must run before restoring a user SATP. It provides the same ordering
/// as `prepare_user_satp()`: a concurrent PTE writer either observes the hart
/// bit and sends a shootdown, or its update precedes the local SATP flush.
pub fn restore_pinned_user_mm(ctx: &Arc<AsidContext>) {
    switch_local_active_context(ctx);
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

pub fn prepare_user_satp(ctx: &Arc<AsidContext>, token: usize) -> (usize, bool, bool) {
    let single_hart = single_hart_online();
    let need_icache_flush = ctx.take_local_icache_stale(single_hart);
    let max_asid = hw_asid_mask();
    // Publish mm activity before the trampoline can install user SATP. On SMP
    // the no-ASID path below always performs a local sfence.vma, so a racing PTE
    // update either observes this bit and shoots us down, or precedes that
    // final local flush. This is the same ordering role as Linux's active-mm
    // CPU mask around context switch and TLB gather.
    switch_local_active_context(ctx);
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

/// Drop this hart's active-mm reference after the kernel SATP is installed.
///
/// Do not call this at trap entry: `alltraps` intentionally continues on the
/// user page table and kernel uaccess may still consume its translations.
pub fn leave_user_mm() {
    let hart = crate::arch::hart_id() % MAX_HARTS;
    if let Some(active) = ACTIVE_USER_CONTEXTS[hart].lock().take() {
        active.mark_local_inactive();
    }
}

pub fn active_user_hart_mask(ctx: &AsidContext) -> usize {
    ctx.active_harts_after_pte_update()
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
