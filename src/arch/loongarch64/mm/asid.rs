use alloc::sync::Arc;
use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::loongarch64::csr_defs::{
    CSR_ASID, CSR_ASID_BITS_MASK, CSR_ASID_BITS_SHIFT, CSR_PRCFG3, INVTLB_ADDR_GFALSE_AND_ASID,
    INVTLB_CURRENT_ALL, INVTLB_CURRENT_GFALSE, INVTLB_GFALSE_AND_ASID, PRCFG3_MTLB_SIZE_MASK,
    PRCFG3_MTLB_SIZE_SHIFT, PRCFG3_STLB_INDEX_MASK, PRCFG3_STLB_INDEX_SHIFT, PRCFG3_STLB_WAYS_MASK,
    PRCFG3_STLB_WAYS_SHIFT, PRCFG3_TLB_TYPE_MASK,
};
use crate::config::{MAX_HARTS, PAGE_SIZE};

use super::super::MAX_TLB_BATCH_RANGES;

/// Architectural maximum supported by this page-table format. Each hart probes
/// its implemented ASID width and may use a smaller local mask.
pub const ASID_MASK: usize = 0x3ff;
pub const KERNEL_ASID: usize = 0;

const FIRST_USER_ASID: usize = 1;

/// ASID allocation is per hart, matching Linux's per-CPU ASID cache. A given
/// address space can therefore own a different hardware ASID on every hart.
static NEXT_USER_ASID: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(FIRST_USER_ASID) }; MAX_HARTS];
static ASID_GENERATION: [AtomicUsize; MAX_HARTS] = [const { AtomicUsize::new(1) }; MAX_HARTS];
static LOCAL_ASID_MASK: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(ASID_MASK) }; MAX_HARTS];
static TLB_SMALL_RANGE_LIMIT: [AtomicUsize; MAX_HARTS] = [const { AtomicUsize::new(0) }; MAX_HARTS];

const TLB_PAIR_SIZE: usize = PAGE_SIZE * 2;

#[inline(always)]
fn full_memory_barrier() {
    // LoongArch is weakly ordered. The active-mask/seqlock protocol needs a
    // StoreLoad barrier, not only Rust acquire/release compiler semantics.
    unsafe {
        asm!("dbar 0", options(nostack));
    }
}

/// Per-address-space LoongArch MMU state.
///
/// `hart_contexts` stores `(generation << 10) | asid` for each hart.
/// `active_harts` contains CPUs that are in user mode, or in the final
/// transition to user mode, with this address space. The even/odd
/// `invalidation_sequence` is a small seqlock that closes races between that
/// transition and a concurrent page-table invalidation.
pub struct AsidContext {
    hart_contexts: [AtomicUsize; MAX_HARTS],
    active_harts: AtomicUsize,
    invalidation_sequence: AtomicUsize,
}

impl AsidContext {
    pub const fn new() -> Self {
        Self {
            hart_contexts: [const { AtomicUsize::new(0) }; MAX_HARTS],
            active_harts: AtomicUsize::new(0),
            invalidation_sequence: AtomicUsize::new(0),
        }
    }

    fn begin_invalidation(&self) -> usize {
        loop {
            let sequence = self.invalidation_sequence.load(Ordering::Acquire);
            if sequence & 1 != 0 {
                super::super::service_pending_tlb_shootdowns();
                core::hint::spin_loop();
                continue;
            }
            let odd = sequence.wrapping_add(1) | 1;
            if self
                .invalidation_sequence
                .compare_exchange(sequence, odd, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                full_memory_barrier();
                return odd;
            }
        }
    }

    fn finish_invalidation(&self, odd_sequence: usize) {
        let mut even = odd_sequence.wrapping_add(1) & !1;
        if even == 0 {
            // Keep zero as the pristine value; wrapping to two preserves the
            // even/odd protocol without making an in-progress writer vanish.
            even = 2;
        }
        full_memory_barrier();
        self.invalidation_sequence.store(even, Ordering::Release);
    }

    fn leave_user(&self, hart_id: usize) {
        if hart_id < usize::BITS as usize {
            full_memory_barrier();
            self.active_harts
                .fetch_and(!(1usize << hart_id), Ordering::AcqRel);
        }
    }
}

/// Probe the local TLB organization and cache Linux's range-flush cutoff.
///
/// PRCFG3 type 1 is an MTLB-only implementation, for which Linux uses half the
/// TLB capacity. Type 2 also has an STLB and uses one eighth of total capacity.
/// Unknown configurations conservatively keep exact invalidation to one pair.
pub(crate) fn init_local_tlb_capabilities() {
    let hart_id = super::super::hart_id();
    if hart_id >= MAX_HARTS {
        return;
    }
    let config: usize;
    let asid_config: usize;
    // SAFETY: PRCFG3 and ASIDBits are privileged CPU configuration fields.
    unsafe {
        asm!("csrrd {}, {csr}", out(reg) config, csr = const CSR_PRCFG3);
        asm!("csrrd {}, {csr}", out(reg) asid_config, csr = const CSR_ASID);
    }
    let asid_bits = ((asid_config >> CSR_ASID_BITS_SHIFT) & CSR_ASID_BITS_MASK)
        .min(ASID_MASK.count_ones() as usize);
    let asid_mask = if asid_bits == 0 {
        ASID_MASK
    } else {
        (1usize << asid_bits) - 1
    };
    LOCAL_ASID_MASK[hart_id].store(asid_mask, Ordering::Release);
    let tlb_type = config & PRCFG3_TLB_TYPE_MASK;
    let mtlb_size = ((config >> PRCFG3_MTLB_SIZE_SHIFT) & PRCFG3_MTLB_SIZE_MASK) + 1;
    let limit = match tlb_type {
        1 => mtlb_size / 2,
        2 => {
            let index_bits = (config >> PRCFG3_STLB_INDEX_SHIFT) & PRCFG3_STLB_INDEX_MASK;
            let sets = if index_bits < usize::BITS as usize {
                1usize << index_bits
            } else {
                0
            };
            let ways = ((config >> PRCFG3_STLB_WAYS_SHIFT) & PRCFG3_STLB_WAYS_MASK) + 1;
            mtlb_size.saturating_add(sets.saturating_mul(ways)) / 8
        }
        _ => 1,
    }
    .max(1);
    TLB_SMALL_RANGE_LIMIT[hart_id].store(limit, Ordering::Release);
}

fn small_range_limit() -> usize {
    TLB_SMALL_RANGE_LIMIT
        .iter()
        .filter_map(|limit| {
            let value = limit.load(Ordering::Acquire);
            (value != 0).then_some(value)
        })
        .min()
        .unwrap_or(1)
}

/// One mm-local invalidation transaction.
///
/// The odd invalidation sequence blocks new user returns from committing an
/// ASID while PTEs are being edited. Adjacent ranges are merged and the batch
/// automatically falls back to dropping the mm context when exact invalidation
/// would exceed the probed TLB-size cutoff.
pub struct UserTlbInvalidationBatch {
    ctx: Arc<AsidContext>,
    odd_sequence: usize,
    ranges: [(usize, usize); MAX_TLB_BATCH_RANGES],
    range_count: usize,
    pair_count: usize,
    edit_count: usize,
    full_mm: bool,
    committed: bool,
}

impl UserTlbInvalidationBatch {
    fn new(ctx: &Arc<AsidContext>) -> Self {
        Self {
            ctx: Arc::clone(ctx),
            odd_sequence: ctx.begin_invalidation(),
            ranges: [(0, 0); MAX_TLB_BATCH_RANGES],
            range_count: 0,
            pair_count: 0,
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
        let mut merged_start = start & !(TLB_PAIR_SIZE - 1);
        let mut merged_end = end.saturating_add(TLB_PAIR_SIZE - 1) & !(TLB_PAIR_SIZE - 1);
        if merged_end <= merged_start {
            self.full_mm = true;
            return;
        }

        let mut idx = 0;
        while idx < self.range_count {
            let (range_start, range_end) = self.ranges[idx];
            if range_end < merged_start || merged_end < range_start {
                idx += 1;
                continue;
            }
            merged_start = merged_start.min(range_start);
            merged_end = merged_end.max(range_end);
            for move_idx in idx..self.range_count - 1 {
                self.ranges[move_idx] = self.ranges[move_idx + 1];
            }
            self.range_count -= 1;
        }

        if self.range_count == MAX_TLB_BATCH_RANGES {
            self.full_mm = true;
            return;
        }
        let insert_at = (0..self.range_count)
            .find(|range_idx| self.ranges[*range_idx].0 > merged_start)
            .unwrap_or(self.range_count);
        for move_idx in (insert_at..self.range_count).rev() {
            self.ranges[move_idx + 1] = self.ranges[move_idx];
        }
        self.ranges[insert_at] = (merged_start, merged_end);
        self.range_count += 1;
        self.pair_count = self.ranges[..self.range_count]
            .iter()
            .map(|(range_start, range_end)| (range_end - range_start) / TLB_PAIR_SIZE)
            .fold(0usize, usize::saturating_add);
        if self.pair_count > small_range_limit() {
            self.full_mm = true;
        }
    }

    fn commit_full_mm(&self) {
        let active_harts = self.ctx.active_harts.swap(0, Ordering::AcqRel);
        let mut target_asids = [0usize; MAX_HARTS];
        let mut all_active_contexts_valid = true;
        for hart_id in 0..MAX_HARTS {
            let context = self.ctx.hart_contexts[hart_id].swap(0, Ordering::AcqRel);
            target_asids[hart_id] = context_asid(context);
            if active_harts & (1usize << hart_id) != 0 && target_asids[hart_id] == KERNEL_ASID {
                all_active_contexts_valid = false;
            }
        }
        if active_harts == 0 {
            return;
        }
        if all_active_contexts_valid {
            super::super::shootdown_user_tlb_asids(active_harts, &target_asids);
        } else {
            super::super::shootdown_user_tlb(active_harts);
        }
    }

    fn commit_ranges(&self) {
        let active_harts = self.ctx.active_harts.load(Ordering::Acquire);
        let local_hart = super::super::hart_id();
        let mut targets = 0usize;
        let mut target_asids = [0usize; MAX_HARTS];

        for hart_id in 0..MAX_HARTS {
            let context = self.ctx.hart_contexts[hart_id].load(Ordering::Acquire);
            let current_generation = ASID_GENERATION[hart_id].load(Ordering::Acquire);
            let context_valid = context_asid(context) != KERNEL_ASID
                && context_generation(context) == current_generation;
            let active = active_harts & (1usize << hart_id) != 0;

            if !context_valid {
                self.ctx.hart_contexts[hart_id].store(0, Ordering::Release);
                if active {
                    self.commit_full_mm();
                    return;
                }
                continue;
            }
            if hart_id == local_hart || active {
                targets |= 1usize << hart_id;
                target_asids[hart_id] = context_asid(context);
            } else {
                // This hart is already on kernel ASID 0. Retire its user
                // context instead of interrupting it; the stale hardware ASID
                // will never be selected again.
                self.ctx.hart_contexts[hart_id].store(0, Ordering::Release);
            }
        }

        if targets != 0 {
            super::super::shootdown_user_tlb_ranges(
                targets,
                &target_asids,
                &self.ranges[..self.range_count],
            );
        }
    }

    fn commit_inner(&mut self) {
        if self.committed {
            return;
        }
        // Order the odd writer state and every PTE store before observing the
        // active mask. Paired with the reader barrier after fetch_or, this
        // closes the Store-Buffering outcome where both sides see old state.
        full_memory_barrier();
        if self.full_mm {
            crate::perf::record_tlb_asid_drop(self.edit_count);
            self.commit_full_mm();
        } else if self.range_count != 0 {
            crate::perf::record_tlb_exact_batch(self.edit_count, self.range_count, self.pair_count);
            self.commit_ranges();
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

#[inline]
fn encode_context(asid: usize, generation: usize) -> usize {
    (generation << ASID_MASK.count_ones()) | (asid & ASID_MASK)
}

#[inline]
fn context_asid(context: usize) -> usize {
    context & ASID_MASK
}

#[inline]
fn context_generation(context: usize) -> usize {
    context >> ASID_MASK.count_ones()
}

fn next_generation(hart_id: usize) -> usize {
    let current = ASID_GENERATION[hart_id].load(Ordering::Acquire);
    let mut next = current.wrapping_add(1);
    if next == 0 {
        next = 1;
    }
    ASID_GENERATION[hart_id].store(next, Ordering::Release);
    next
}

fn allocate_user_asid(hart_id: usize) -> (usize, usize, bool) {
    let asid = NEXT_USER_ASID[hart_id].fetch_add(1, Ordering::AcqRel);
    if asid <= LOCAL_ASID_MASK[hart_id].load(Ordering::Acquire) {
        return (
            asid,
            ASID_GENERATION[hart_id].load(Ordering::Acquire),
            false,
        );
    }

    let generation = next_generation(hart_id);
    NEXT_USER_ASID[hart_id].store(FIRST_USER_ASID + 1, Ordering::Release);
    crate::perf::record_tlb_asid_wrap();
    (FIRST_USER_ASID, generation, true)
}

/// Prepare this mm for the current hart's final return to userspace.
///
/// The returned boolean asks the trampoline to flush all non-global entries
/// when the local ASID namespace wrapped. Page-table invalidations otherwise
/// allocate a fresh per-hart context and synchronously stop CPUs that are
/// already running this mm.
pub fn prepare_user_asid(ctx: &AsidContext) -> (usize, bool) {
    let hart_id = super::super::hart_id();
    assert!(hart_id < MAX_HARTS, "hart {} exceeds MAX_HARTS", hart_id);
    let hart_bit = 1usize << hart_id;
    let mut need_flush = false;

    loop {
        let sequence = ctx.invalidation_sequence.load(Ordering::Acquire);
        if sequence & 1 != 0 {
            // We can reach here with interrupts disabled in the narrow
            // trap-return transition. Polling pending requests lets the
            // invalidator finish instead of waiting for an IPI trap.
            super::super::service_pending_tlb_shootdowns();
            core::hint::spin_loop();
            continue;
        }

        let generation = ASID_GENERATION[hart_id].load(Ordering::Acquire);
        let cached = ctx.hart_contexts[hart_id].load(Ordering::Acquire);
        let context =
            if context_asid(cached) != KERNEL_ASID && context_generation(cached) == generation {
                cached
            } else {
                let (asid, generation, wrapped) = allocate_user_asid(hart_id);
                need_flush |= wrapped;
                let context = encode_context(asid, generation);
                ctx.hart_contexts[hart_id].store(context, Ordering::Release);
                context
            };

        ctx.active_harts.fetch_or(hart_bit, Ordering::AcqRel);
        full_memory_barrier();
        if ctx.invalidation_sequence.load(Ordering::Acquire) == sequence {
            return (context_asid(context), need_flush);
        }

        // An invalidator raced with the user transition. Withdraw the active
        // bit, discard the possibly stale context, service any request that
        // included us, and retry after the writer completes.
        ctx.active_harts.fetch_and(!hart_bit, Ordering::AcqRel);
        ctx.hart_contexts[hart_id].store(0, Ordering::Release);
        super::super::service_pending_tlb_shootdowns();
    }
}

/// Mark the current mm as no longer executing in userspace on this hart.
///
/// The trampoline has already switched to kernel page tables and ASID 0 before
/// Rust reaches this call, so an invalidator may safely omit this hart after
/// the bit is cleared.
pub fn leave_user_asid(ctx: &AsidContext) {
    ctx.leave_user(super::super::hart_id());
}

/// Invalidate every per-hart context and synchronously flush CPUs currently
/// executing this mm.
pub fn drop_user_asid(ctx: &AsidContext) {
    crate::perf::record_tlb_asid_drop(0);
    let odd_sequence = ctx.begin_invalidation();
    let active_harts = ctx.active_harts.swap(0, Ordering::AcqRel);
    let mut target_asids = [0usize; MAX_HARTS];
    let mut all_active_contexts_valid = true;
    for hart_id in 0..MAX_HARTS {
        let context = ctx.hart_contexts[hart_id].swap(0, Ordering::AcqRel);
        target_asids[hart_id] = context_asid(context);
        if active_harts & (1usize << hart_id) != 0 && target_asids[hart_id] == KERNEL_ASID {
            all_active_contexts_valid = false;
        }
    }
    if active_harts != 0 {
        if all_active_contexts_valid {
            super::super::shootdown_user_tlb_asids(active_harts, &target_asids);
        } else {
            super::super::shootdown_user_tlb(active_harts);
        }
    }
    ctx.finish_invalidation(odd_sequence);
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
/// Linux does not issue a remote `flush_tlb_page()` for this transition.  Its
/// LoongArch fault path calls `update_mmu_cache()`, which is local to the
/// faulting CPU (and is a no-op when the hardware page-table walker is in
/// use).  A second CPU racing the same missing PTE may take a spurious fault;
/// after observing the now-present PTE it refreshes its own TLB locally.
///
/// CongCore still needs an explicit local invalidation because a LoongArch
/// paired TLB entry can retain an invalid half while the adjacent 4-KiB page
/// is valid.  Scope that invalidation to this mm's current-hart ASID and pair.
/// Existing-PTE replacement, permission demotion, unmap, and supervisor-only
/// trap-context publication continue to use the synchronous mm-wide batch.
pub(crate) fn update_mmu_cache_for_new_pte_range(ctx: &AsidContext, start: usize, end: usize) {
    if start >= end {
        return;
    }
    let hart_id = super::super::hart_id();
    if hart_id >= MAX_HARTS {
        return;
    }

    let context = ctx.hart_contexts[hart_id].load(Ordering::Acquire);
    let generation = ASID_GENERATION[hart_id].load(Ordering::Acquire);
    if context_asid(context) == KERNEL_ASID || context_generation(context) != generation {
        // No reusable translation for this mm exists on the current hart.
        // prepare_user_asid() will allocate a clean context before user return.
        return;
    }

    // Publish every PTE before invalidating possibly cached invalid halves,
    // then keep the batched invalidation ordered before user return. One
    // LoongArch TLB entry covers an even/odd 8-KiB pair; the range helper
    // aligns once and visits each affected pair exactly once.
    full_memory_barrier();
    let aligned_start = start & !(TLB_PAIR_SIZE - 1);
    let aligned_end = end.saturating_add(TLB_PAIR_SIZE - 1) & !(TLB_PAIR_SIZE - 1);
    crate::perf::record_tlb_new_pte_pairs(
        aligned_end.saturating_sub(aligned_start) / TLB_PAIR_SIZE,
    );
    local_flush_tlb_range(context_asid(context), start, end);
    full_memory_barrier();
}

pub(crate) fn update_mmu_cache_for_new_pte(ctx: &AsidContext, vaddr: usize) {
    update_mmu_cache_for_new_pte_range(ctx, vaddr, vaddr.saturating_add(PAGE_SIZE));
}

#[inline(always)]
pub fn write_kernel_asid() {
    write_asid(KERNEL_ASID);
}

#[inline(always)]
fn write_asid(asid: usize) {
    let value = asid & ASID_MASK;
    // SAFETY: CSR.ASID is privileged. The kernel writes ASID 0 for kernel
    // execution or a hardware-masked user ASID immediately before `ertn`.
    unsafe {
        asm!("csrwr {}, 0x18", inout(reg) value => _);
    }
}

#[inline(always)]
pub(crate) fn local_flush_tlb_user() {
    // SAFETY: INVTLB_CURRENT_GFALSE drops all non-global translations in the
    // current hart's TLB, covering every user ASID.
    unsafe {
        asm!(
            "invtlb {op}, $r0, $r0",
            op = const INVTLB_CURRENT_GFALSE
        );
    }
}

#[inline(always)]
pub(crate) fn local_flush_tlb_asid(asid: usize) {
    let asid = asid & ASID_MASK;
    // SAFETY: The operation invalidates non-global entries carrying exactly
    // this hardware ASID on the current hart.
    unsafe {
        asm!(
            "invtlb {op}, {asid}, $r0",
            op = const INVTLB_GFALSE_AND_ASID,
            asid = in(reg) asid,
        );
    }
}

pub(crate) fn local_flush_tlb_range(asid: usize, start: usize, end: usize) {
    if start >= end {
        return;
    }
    let asid = asid & ASID_MASK;
    let mut address = start & !(TLB_PAIR_SIZE - 1);
    let aligned_end = end.saturating_add(TLB_PAIR_SIZE - 1) & !(TLB_PAIR_SIZE - 1);
    crate::perf::record_tlb_exact_pairs(aligned_end.saturating_sub(address) / TLB_PAIR_SIZE);
    while address < aligned_end {
        // SAFETY: LoongArch TLB entries contain an even/odd page pair. Opcode
        // 0x5 matches both the supplied ASID and pair-aligned virtual address.
        unsafe {
            asm!(
                "invtlb {op}, {asid}, {address}",
                op = const INVTLB_ADDR_GFALSE_AND_ASID,
                asid = in(reg) asid,
                address = in(reg) address,
            );
        }
        address = address.saturating_add(TLB_PAIR_SIZE);
    }
}

#[inline(always)]
pub(crate) fn local_flush_tlb_all() {
    // SAFETY: INVTLB_CURRENT_ALL invalidates every translation in this hart's
    // local TLB. It is used after shared kernel mapping changes.
    unsafe {
        asm!("invtlb {op}, $r0, $r0", op = const INVTLB_CURRENT_ALL);
    }
}
