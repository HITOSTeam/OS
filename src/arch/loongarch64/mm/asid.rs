use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Minimal per-mm ASID allocator for LoongArch.
///
/// Each `MemorySet` owns an `AsidContext`. PTE changes invalidate that context
/// instead of flushing the whole TLB immediately; the next return to user mode
/// either reuses a still-valid ASID or allocates a fresh one. When the small
/// hardware ASID space wraps, callers get `need_flush = true` and the trampoline
/// performs a current-ASID flush before `ertn`.
pub const ASID_MASK: usize = 0x3ff;
pub const KERNEL_ASID: usize = 0;

const FIRST_USER_ASID: usize = 1;

static NEXT_USER_ASID: AtomicUsize = AtomicUsize::new(FIRST_USER_ASID);
static ASID_GENERATION: AtomicUsize = AtomicUsize::new(1);

pub struct AsidContext {
    asid: AtomicUsize,
    generation: AtomicUsize,
}

impl AsidContext {
    pub const fn new() -> Self {
        Self {
            asid: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
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
}

fn allocate_user_asid() -> (usize, usize, bool) {
    let asid = NEXT_USER_ASID.fetch_add(1, Ordering::AcqRel);
    if asid <= ASID_MASK {
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

pub fn prepare_user_asid(ctx: &AsidContext) -> (usize, bool) {
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if ctx.valid_for(generation) {
        return (ctx.asid.load(Ordering::Acquire), false);
    }

    let (asid, generation, need_flush) = allocate_user_asid();
    let asid = asid & ASID_MASK;
    ctx.store(asid, generation);
    (asid, need_flush)
}

pub fn drop_user_asid(ctx: &AsidContext) {
    ctx.invalidate();
}

pub fn flush_user_page(ctx: &AsidContext, vaddr: usize) {
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if ctx.valid_for(generation) {
        flush_user_page_asid(ctx.asid.load(Ordering::Acquire), vaddr);
    }
}

#[inline(always)]
pub fn write_kernel_asid() {
    write_asid(KERNEL_ASID);
}

#[inline(always)]
fn write_asid(asid: usize) {
    let value = asid & ASID_MASK;
    // SAFETY: CSR.ASID is a privileged register. The kernel writes either ASID 0
    // for kernel execution or a valid user ASID immediately before `ertn`.
    unsafe {
        asm!("csrwr {}, 0x18", inout(reg) value => _);
    }
}

#[inline(always)]
fn flush_user_page_asid(asid: usize, vaddr: usize) {
    let asid = asid & ASID_MASK;
    let vaddr = align_tlb_pair(vaddr);
    // SAFETY: The ASID and address are kernel-managed. This invalidates the
    // matching non-global user translation without discarding unrelated ASIDs.
    unsafe {
        asm!("invtlb 0x5, {}, {}", in(reg) asid, in(reg) vaddr);
    }
}

#[inline(always)]
fn align_tlb_pair(vaddr: usize) -> usize {
    vaddr & !((crate::config::PAGE_SIZE << 1) - 1)
}
