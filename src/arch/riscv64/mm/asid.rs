use alloc::sync::Arc;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};

use riscv::register::satp::{self, Satp};
use spin::Mutex;

use crate::config::{MAX_HARTS, PAGE_SIZE};

const SATP_ASID_SHIFT: usize = 44;
const SATP_ASID_MASK: usize = 0xffff;
const CONTEXT_ASID_BITS: usize = SATP_ASID_MASK.count_ones() as usize;
const KERNEL_ASID: usize = 0;
const FIRST_USER_ASID: usize = 1;
const TLB_SMALL_RANGE_PAGES: usize = 64;

struct AsidAllocator {
    next: usize,
    generation: usize,
}

impl AsidAllocator {
    const fn new() -> Self {
        Self {
            next: FIRST_USER_ASID,
            generation: 1,
        }
    }
}

static ASID_ALLOCATOR: Mutex<AsidAllocator> = Mutex::new(AsidAllocator::new());
static ASID_GENERATION: AtomicUsize = AtomicUsize::new(1);
static HW_ASID_MASK: AtomicUsize = AtomicUsize::new(0);
static ASID_ENABLED: AtomicBool = AtomicBool::new(false);
static POSSIBLE_HART_MASK: AtomicUsize = AtomicUsize::new(1);
static PENDING_LOCAL_FLUSH: AtomicUsize = AtomicUsize::new(0);

/// Per-address-space RISC-V MMU state.
///
/// `context` is the generation-tagged ASID allocated for new users of this
/// address space. `hart_contexts` records what each hart actually loaded, so a
/// generation rollover can coexist briefly with an old user context without
/// losing shootdown coverage. The even/odd sequence closes the race between a
/// page-table edit and the final transition back to userspace.
pub struct AsidContext {
    context: AtomicUsize,
    hart_contexts: [AtomicUsize; MAX_HARTS],
    resident_harts: AtomicUsize,
    active_harts: AtomicUsize,
    invalidation_sequence: AtomicUsize,
    icache_stale_mask: AtomicUsize,
}

impl AsidContext {
    pub const fn new() -> Self {
        Self {
            context: AtomicUsize::new(0),
            hart_contexts: [const { AtomicUsize::new(0) }; MAX_HARTS],
            resident_harts: AtomicUsize::new(0),
            active_harts: AtomicUsize::new(0),
            invalidation_sequence: AtomicUsize::new(0),
            icache_stale_mask: AtomicUsize::new(configured_hart_mask()),
        }
    }

    fn begin_invalidation(&self) -> usize {
        loop {
            let sequence = self.invalidation_sequence.load(Ordering::Acquire);
            if sequence & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let odd = sequence.wrapping_add(1) | 1;
            if self
                .invalidation_sequence
                .compare_exchange(sequence, odd, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return odd;
            }
        }
    }

    fn finish_invalidation(&self, odd_sequence: usize) {
        let mut even = odd_sequence.wrapping_add(1) & !1;
        if even == 0 {
            even = 2;
        }
        self.invalidation_sequence.store(even, Ordering::Release);
    }

    fn mark_icache_stale(&self) {
        // Publish instruction bytes before any local or remote instruction
        // cache synchronization observes this stale generation.
        fence(Ordering::Release);
        // SAFETY: pair ordinary stores with fence.i/RFENCE on every target.
        unsafe {
            asm!("fence rw, rw", options(nostack));
        }
        self.icache_stale_mask
            .fetch_or(possible_hart_mask(), Ordering::Release);

        let local_bit = local_hart_bit();
        if local_bit != 0 {
            // A fence now is sufficient even when this hart is not currently
            // executing the mm: future instruction fetches are ordered after
            // the code stores that preceded this call.
            // SAFETY: fence.i is required by the RISC-V ISA after publishing
            // instruction bytes and has no memory operands.
            unsafe {
                asm!("fence.i", options(nostack));
            }
            crate::perf::record_icache_local_fence(false);
            self.icache_stale_mask
                .fetch_and(!local_bit, Ordering::AcqRel);
        }

        let remote = self.active_harts.load(Ordering::Acquire)
            & crate::task::manager::online_hart_mask()
            & configured_hart_mask()
            & !local_bit;
        if remote != 0 {
            let ret = crate::sbi::remote_fence_i(remote);
            assert_eq!(ret.error, 0, "remote RISC-V fence.i failed");
            crate::perf::record_icache_remote_fence(remote.count_ones() as usize);
            self.icache_stale_mask.fetch_and(!remote, Ordering::AcqRel);
        }
    }

    fn take_local_icache_stale(&self) -> bool {
        let bit = local_hart_bit();
        self.icache_stale_mask.fetch_and(!bit, Ordering::AcqRel) & bit != 0
    }
}

const fn configured_hart_mask() -> usize {
    if MAX_HARTS >= usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << MAX_HARTS) - 1
    }
}

fn possible_hart_mask() -> usize {
    POSSIBLE_HART_MASK.load(Ordering::Acquire) & configured_hart_mask()
}

fn local_hart_bit() -> usize {
    let hart = super::super::hart_id();
    if hart < MAX_HARTS && hart < usize::BITS as usize {
        1usize << hart
    } else {
        0
    }
}

fn probe_hw_asid_mask() -> usize {
    let old = satp::read().bits();
    let trial = old | (SATP_ASID_MASK << SATP_ASID_SHIFT);
    // SAFETY: write-ones/read-back is the architectural WARL ASID-width probe.
    unsafe {
        satp::write(Satp::from_bits(trial));
    }
    let supported = (satp::read().bits() >> SATP_ASID_SHIFT) & SATP_ASID_MASK;
    // SAFETY: restore the exact original address space and discard anything
    // filled while the temporary ASID value was installed.
    unsafe {
        satp::write(Satp::from_bits(old));
        asm!("sfence.vma", options(nostack));
    }
    supported
}

/// Probe ASID width after kernel paging is active and decide whether the
/// namespace is large enough for Linux-style SMP allocation.
pub fn init_asid_allocator(present_harts: usize) {
    let possible = present_harts & configured_hart_mask();
    POSSIBLE_HART_MASK.store(if possible == 0 { 1 } else { possible }, Ordering::Release);
    let mask = probe_hw_asid_mask();
    HW_ASID_MASK.store(mask, Ordering::Release);
    let asid_count = mask.saturating_add(1);
    let enabled = mask != 0 && asid_count > 2 * possible.count_ones() as usize;
    ASID_ENABLED.store(enabled, Ordering::Release);
    crate::println!(
        "[mm] riscv ASID bits={} count={} enabled={} possible_harts={:#x}",
        mask.count_ones(),
        asid_count,
        enabled,
        possible
    );
}

#[inline]
fn encode_context(asid: usize, generation: usize) -> usize {
    (generation << CONTEXT_ASID_BITS) | (asid & SATP_ASID_MASK)
}

#[inline]
fn context_asid(context: usize) -> usize {
    context & SATP_ASID_MASK
}

#[inline]
fn context_generation(context: usize) -> usize {
    context >> CONTEXT_ASID_BITS
}

fn allocate_context_locked(allocator: &mut AsidAllocator) -> usize {
    let max_asid = HW_ASID_MASK.load(Ordering::Acquire);
    if allocator.next > max_asid {
        let mut generation = allocator.generation.wrapping_add(1);
        if generation == 0 {
            generation = 1;
        }
        allocator.generation = generation;
        allocator.next = FIRST_USER_ASID;
        ASID_GENERATION.store(generation, Ordering::Release);
        PENDING_LOCAL_FLUSH.fetch_or(possible_hart_mask(), Ordering::AcqRel);
        crate::perf::record_tlb_asid_wrap();
    }
    let asid = allocator.next;
    allocator.next = allocator.next.saturating_add(1);
    encode_context(asid, allocator.generation)
}

fn current_or_allocate_context(ctx: &AsidContext) -> usize {
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    let current = ctx.context.load(Ordering::Acquire);
    if context_asid(current) != KERNEL_ASID && context_generation(current) == generation {
        return current;
    }

    let mut allocator = ASID_ALLOCATOR.lock();
    let generation = allocator.generation;
    let current = ctx.context.load(Ordering::Acquire);
    if context_asid(current) != KERNEL_ASID && context_generation(current) == generation {
        return current;
    }
    let context = allocate_context_locked(&mut allocator);
    ctx.context.store(context, Ordering::Release);
    context
}

#[inline]
fn token_with_asid(token: usize, asid: usize) -> usize {
    (token & !(SATP_ASID_MASK << SATP_ASID_SHIFT)) | ((asid & SATP_ASID_MASK) << SATP_ASID_SHIFT)
}

/// Prepare the final SATP value and mark this hart active in the mm.
pub fn prepare_user_satp(ctx: &AsidContext, token: usize) -> (usize, bool, bool) {
    let hart_id = super::super::hart_id();
    assert!(hart_id < MAX_HARTS, "hart {} exceeds MAX_HARTS", hart_id);
    let hart_bit = 1usize << hart_id;
    let mut need_flush = false;

    loop {
        let sequence = ctx.invalidation_sequence.load(Ordering::Acquire);
        if sequence & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }

        let context = if ASID_ENABLED.load(Ordering::Acquire) {
            let context = current_or_allocate_context(ctx);
            if PENDING_LOCAL_FLUSH.fetch_and(!hart_bit, Ordering::AcqRel) & hart_bit != 0 {
                need_flush = true;
            }
            context
        } else {
            need_flush = true;
            0
        };

        ctx.hart_contexts[hart_id].store(context, Ordering::Release);
        ctx.resident_harts.fetch_or(hart_bit, Ordering::AcqRel);
        ctx.active_harts.fetch_or(hart_bit, Ordering::AcqRel);
        if ctx.invalidation_sequence.load(Ordering::Acquire) == sequence {
            // Take the I-cache marker only after publishing active_harts. A
            // concurrent code update then either leaves this bit set for us,
            // or observes us as active and completes an SBI remote fence.i.
            let need_icache_flush = ctx.take_local_icache_stale();
            return (
                token_with_asid(token, context_asid(context)),
                need_flush,
                need_icache_flush,
            );
        }

        ctx.active_harts.fetch_and(!hart_bit, Ordering::AcqRel);
    }
}

/// Must installing `asid` on this hart be followed by a TLB invalidation?
///
/// Linux's `set_mm_asid()` reaches `switch_mm_fast` and writes SATP with no
/// invalidation at all; it flushes only when this CPU still owes one after an
/// ASID-version rollover (`context_tlb_flush_pending`).  This kernel used to
/// invalidate unconditionally on every SATP write, which meant an ASID-wide
/// `sfence.vma` on every context switch, discarding the entire point of
/// hardware ASIDs.
///
/// Entering the kernel address space needs nothing: kernel roots are installed
/// as global entries, so an ASID-scoped fence would not touch them anyway, the
/// kernel ASID is never recycled, and kernel mapping changes are published
/// separately by `flush_kernel_shared_tlb()`.  Any other ASID keeps the
/// conservative invalidation, as does a machine with no usable hardware ASIDs,
/// where every root collapses onto ASID 0 and stale non-global entries really
/// can alias.
pub fn satp_switch_needs_flush(asid: usize) -> bool {
    if !ASID_ENABLED.load(Ordering::Acquire) {
        return true;
    }
    asid != KERNEL_ASID
}

/// The trampoline has trapped out of userspace. The user SATP may remain
/// installed while the kernel runs, so the hart stays in `resident_harts` and
/// is still included in page-table shootdowns.
pub fn leave_user_satp(ctx: &AsidContext) {
    let bit = local_hart_bit();
    if bit != 0 {
        ctx.active_harts.fetch_and(!bit, Ordering::AcqRel);
    }
}

#[inline(always)]
fn page_table_write_barrier() {
    fence(Ordering::SeqCst);
    // SAFETY: order PTE stores before the local fence and SBI RFENCE request.
    unsafe {
        asm!("fence rw, rw", options(nostack));
    }
}

/// if we can use a uniform (equal) ASID to do a efficiently flush
fn uniform_target_asid(ctx: &AsidContext, hart_mask: usize) -> Option<usize> {
    let mut selected = None;
    for hart_id in 0..MAX_HARTS {
        if hart_mask & (1usize << hart_id) == 0 {
            continue;
        }
        let asid = context_asid(ctx.hart_contexts[hart_id].load(Ordering::Acquire));
        if asid == KERNEL_ASID {
            return None;
        }
        if let Some(existing) = selected {
            if existing != asid {
                return None;
            }
        } else {
            selected = Some(asid);
        }
    }
    selected
}

fn local_flush_range(asid: Option<usize>, start: usize, end: usize) {
    let mut address = start & !(PAGE_SIZE - 1);
    let aligned_end = end.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    crate::perf::record_tlb_exact_pairs(aligned_end.saturating_sub(address) / PAGE_SIZE);
    while address < aligned_end {
        // SAFETY: invalidate exactly one page, optionally scoped to the mm ASID.
        unsafe {
            if let Some(asid) = asid {
                asm!(
                    "sfence.vma {address}, {asid}",
                    address = in(reg) address,
                    asid = in(reg) asid,
                    options(nostack)
                );
            } else {
                asm!("sfence.vma {address}, zero", address = in(reg) address, options(nostack));
            }
        }
        address = address.saturating_add(PAGE_SIZE);
    }
}

fn shootdown_range(ctx: &AsidContext, start: usize, end: usize) {
    if start >= end {
        return;
    }
    let targets = ctx.resident_harts.load(Ordering::Acquire)
        & crate::task::manager::online_hart_mask()
        & configured_hart_mask();
    if targets == 0 {
        return;
    }
    page_table_write_barrier();
    let local_bit = local_hart_bit();
    if targets & local_bit != 0 {
        let local_asid = uniform_target_asid(ctx, local_bit);
        local_flush_range(local_asid, start, end);
    }

    let remote = targets & !local_bit;
    if remote == 0 {
        return;
    }
    let size = end.saturating_sub(start);
    let wait_start = if crate::perf::enabled() {
        super::super::read_time()
    } else {
        0
    };
    let ret = if let Some(asid) = uniform_target_asid(ctx, remote) {
        crate::sbi::remote_sfence_vma_asid(remote, start, size, asid)
    } else {
        crate::sbi::remote_sfence_vma(remote, start, size)
    };
    assert_eq!(ret.error, 0, "remote RISC-V TLB range fence failed");
    let wait_cycles = if crate::perf::enabled() {
        super::super::read_time().wrapping_sub(wait_start)
    } else {
        0
    };
    crate::perf::record_tlb_shootdown(remote.count_ones() as usize, wait_cycles);
}

fn shootdown_and_retire_context(ctx: &AsidContext) {
    let targets = ctx.resident_harts.load(Ordering::Acquire)
        & crate::task::manager::online_hart_mask()
        & configured_hart_mask();
    // Retire the context used by future trap returns, but retain the per-hart
    // residency footprint and the ASID each hart actually loaded. A remote
    // hart may continue executing this mm after the synchronous RFENCE and
    // refill from the now-current PTEs; retaining it in the footprint ensures
    // a following page-table edit still targets it before its next trap.
    ctx.context.store(0, Ordering::Release);
    let target_asid = uniform_target_asid(ctx, targets);
    if targets == 0 {
        return;
    }

    page_table_write_barrier();
    let local_bit = local_hart_bit();
    if targets & local_bit != 0 {
        // SAFETY: a full-ASID fence retires the old address-space context;
        // ASID 0 fallback must invalidate every non-global translation.
        unsafe {
            if let Some(asid) = target_asid {
                asm!("sfence.vma zero, {asid}", asid = in(reg) asid, options(nostack));
            } else {
                asm!("sfence.vma", options(nostack));
            }
        }
    }

    let remote = targets & !local_bit;
    if remote == 0 {
        return;
    }
    let wait_start = if crate::perf::enabled() {
        super::super::read_time()
    } else {
        0
    };
    let ret = if let Some(asid) = target_asid {
        crate::sbi::remote_sfence_vma_asid(remote, 0, usize::MAX, asid)
    } else {
        crate::sbi::remote_sfence_vma(remote, 0, usize::MAX)
    };
    assert_eq!(ret.error, 0, "remote RISC-V ASID fence failed");
    let wait_cycles = if crate::perf::enabled() {
        super::super::read_time().wrapping_sub(wait_start)
    } else {
        0
    };
    crate::perf::record_tlb_shootdown(remote.count_ones() as usize, wait_cycles);
}

/// One mm-local transaction. All edits are reduced to one page-aligned
/// envelope while it remains at most 64 pages; larger/overflowing batches
/// retire the mm ASID instead.
pub struct UserTlbInvalidationBatch {
    ctx: Arc<AsidContext>,
    odd_sequence: usize,
    start: usize,
    end: usize,
    edit_count: usize,
    full_mm: bool,
    committed: bool,
}

impl UserTlbInvalidationBatch {
    fn new(ctx: &Arc<AsidContext>) -> Self {
        Self {
            ctx: Arc::clone(ctx),
            odd_sequence: ctx.begin_invalidation(),
            start: usize::MAX,
            end: 0,
            edit_count: 0,
            full_mm: false,
            committed: false,
        }
    }

    pub fn record_page(&mut self, vaddr: usize) {
        let start = vaddr & !(PAGE_SIZE - 1);
        self.record_range(start, start.saturating_add(PAGE_SIZE));
    }

    pub fn record_range(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        self.edit_count = self.edit_count.saturating_add(1);
        if self.full_mm {
            return;
        }
        let aligned_start = start & !(PAGE_SIZE - 1);
        let Some(aligned_end) = end
            .checked_add(PAGE_SIZE - 1)
            .map(|value| value & !(PAGE_SIZE - 1))
        else {
            self.full_mm = true;
            return;
        };
        self.start = self.start.min(aligned_start);
        self.end = self.end.max(aligned_end);
        let pages = self.end.saturating_sub(self.start) / PAGE_SIZE;
        if pages > TLB_SMALL_RANGE_PAGES {
            self.full_mm = true;
        }
    }

    pub fn force_full_mm(&mut self) {
        self.full_mm = true;
    }

    pub fn mark_icache_stale(&self) {
        self.ctx.mark_icache_stale();
    }

    fn commit_inner(&mut self) {
        if self.committed {
            return;
        }
        if self.full_mm {
            crate::perf::record_tlb_asid_drop(self.edit_count);
            shootdown_and_retire_context(&self.ctx);
        } else if self.start < self.end {
            let pages = (self.end - self.start) / PAGE_SIZE;
            crate::perf::record_tlb_exact_batch(self.edit_count, 1, pages);
            shootdown_range(&self.ctx, self.start, self.end);
        }
        self.ctx.finish_invalidation(self.odd_sequence);
        self.committed = true;
    }

    pub fn commit(mut self) {
        self.commit_inner();
    }
}

impl Drop for UserTlbInvalidationBatch {
    fn drop(&mut self) {
        self.commit_inner();
    }
}

pub fn begin_user_tlb_batch(ctx: &Arc<AsidContext>) -> UserTlbInvalidationBatch {
    UserTlbInvalidationBatch::new(ctx)
}

pub fn drop_user_asid(ctx: &AsidContext) {
    let odd = ctx.begin_invalidation();
    crate::perf::record_tlb_asid_drop(0);
    shootdown_and_retire_context(ctx);
    ctx.finish_invalidation(odd);
}

pub fn flush_user_page(ctx: &Arc<AsidContext>, vaddr: usize) {
    let mut batch = begin_user_tlb_batch(ctx);
    batch.record_page(vaddr);
    batch.commit();
}

pub fn flush_user_range(ctx: &Arc<AsidContext>, start: usize, end: usize) {
    let mut batch = begin_user_tlb_batch(ctx);
    batch.record_range(start, end);
    batch.commit();
}

/// Publish a leaf PTE that was non-present before the current page fault.
///
/// Linux's RISC-V `update_mmu_cache_range()` performs only a local
/// `SFENCE.VMA` for this transition when the system lacks Svvptc. Svvptc makes
/// a newly valid PTE visible within a bounded time, so Linux skips the fence on
/// systems where every available hart supports the extension. Existing-PTE
/// replacement, permission changes, and unmap continue to use the synchronous
/// mm-wide invalidation paths. Executable publication still performs its
/// separate instruction-cache synchronization before publishing the PTE.
pub(crate) fn update_mmu_cache_for_new_pte(ctx: &AsidContext, vaddr: usize) {
    let hart_id = super::super::hart_id();
    if hart_id >= MAX_HARTS {
        return;
    }

    let context = ctx.hart_contexts[hart_id].load(Ordering::Acquire);
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if context_asid(context) == KERNEL_ASID || context_generation(context) != generation {
        // This hart has no reusable translation for the current generation.
        // prepare_user_satp() will install a clean context (or perform the
        // ASID-disabled full local flush) before returning to userspace.
        return;
    }

    if super::super::has_svvptc() {
        crate::perf::record_tlb_new_pte_refresh(true);
        return;
    }

    // Order the new PTE store before the address/ASID-scoped fence.  This is
    // local by design: a remote hart that raced the missing PTE resolves its
    // own possible invalid-entry cache after observing the published leaf.
    page_table_write_barrier();
    crate::perf::record_tlb_new_pte_refresh(false);
    local_flush_range(
        Some(context_asid(context)),
        vaddr,
        vaddr.saturating_add(PAGE_SIZE),
    );
}

pub fn mark_icache_stale(ctx: &AsidContext) {
    ctx.mark_icache_stale();
}
