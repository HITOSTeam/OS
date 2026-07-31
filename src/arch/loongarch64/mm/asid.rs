use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use spin::Mutex;

use crate::config::MAX_HARTS;

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
const FALLBACK_USER_ASID: usize = FIRST_USER_ASID;

static NEXT_USER_ASID: AtomicUsize = AtomicUsize::new(FIRST_USER_ASID);
static ASID_GENERATION: AtomicUsize = AtomicUsize::new(1);
static ASID_ALLOC_LOCK: Mutex<()> = Mutex::new(());
/// 在没有实现全 hart ASID rollover 前，耗尽后共用一个非零用户 ASID并本地全刷。
/// 内核固定使用 ASID 0，二者绝不能共用，否则低地址用户映射会污染内核 MMIO。
static ASID_EXHAUSTED: AtomicBool = AtomicBool::new(false);
static TLB_FLUSH_REQUEST: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_HARTS];
static TLB_FLUSH_ACK: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_HARTS];

pub struct AsidContext {
    asid: AtomicUsize,
    generation: AtomicUsize,
    active_hart_mask: AtomicUsize,
}

impl AsidContext {
    pub const fn new() -> Self {
        Self {
            asid: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
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

    fn mark_local_active(&self) {
        let bit = local_hart_bit();
        if bit != 0 {
            self.active_hart_mask.fetch_or(bit, Ordering::AcqRel);
        }
    }

    fn remote_active_harts(&self) -> usize {
        self.active_hart_mask.load(Ordering::Acquire)
            & online_hart_mask()
            & !local_hart_bit()
    }
}

fn allocate_user_asid() -> Option<(usize, usize)> {
    let asid = NEXT_USER_ASID.fetch_add(1, Ordering::AcqRel);
    if asid <= ASID_MASK {
        return Some((asid, ASID_GENERATION.load(Ordering::Acquire)));
    }

    ASID_EXHAUSTED.store(true, Ordering::Release);
    None
}

pub fn prepare_user_asid(ctx: &AsidContext) -> (usize, bool) {
    ctx.mark_local_active();
    if ASID_EXHAUSTED.load(Ordering::Acquire) {
        return (FALLBACK_USER_ASID, true);
    }
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if ctx.valid_for(generation) {
        return (ctx.asid.load(Ordering::Acquire), false);
    }

    // 同一 mm 可能同时在多个 hart 首次运行，锁内复查保证只分配一个 ASID。
    let _guard = ASID_ALLOC_LOCK.lock();
    if ASID_EXHAUSTED.load(Ordering::Acquire) {
        return (FALLBACK_USER_ASID, true);
    }
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if ctx.valid_for(generation) {
        return (ctx.asid.load(Ordering::Acquire), false);
    }
    let Some((asid, generation)) = allocate_user_asid() else {
        return (FALLBACK_USER_ASID, true);
    };
    ctx.store(asid, generation);
    (asid, false)
}

pub fn drop_user_asid(ctx: &AsidContext) {
    {
        let _guard = ASID_ALLOC_LOCK.lock();
        ctx.invalidate();
    }
    request_remote_user_tlb_flush(ctx);
}

pub fn flush_user_page(ctx: &AsidContext, vaddr: usize) {
    flush_local_user_page(ctx, vaddr);
    request_remote_user_tlb_flush(ctx);
}

pub fn flush_local_user_page(ctx: &AsidContext, vaddr: usize) {
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if !ASID_EXHAUSTED.load(Ordering::Acquire) && ctx.valid_for(generation) {
        flush_user_page_asid(ctx.asid.load(Ordering::Acquire), vaddr);
    } else {
        flush_local_user_tlb();
    }
}

pub fn wait_remote_user_tlb_flush(ctx: &AsidContext) {
    // 缺页异常期间本 hart 可能仍然关中断。多个 hart 同时处理 COW 时，若都只
    // 等待远端 ACK，就会互相等着对方进入 IPI handler。等待者必须同时充当
    // 本 hart 的轮询式 IPI handler，保证同步 shootdown 不依赖中断重入。
    service_pending_user_tlb_flush();
    let mask = ctx.remote_active_harts();
    for hart_id in 0..MAX_HARTS {
        if mask & (1usize << hart_id) == 0 {
            continue;
        }
        let requested = TLB_FLUSH_REQUEST[hart_id].load(Ordering::Acquire);
        let mut spins = 0usize;
        while TLB_FLUSH_ACK[hart_id].load(Ordering::Acquire) < requested {
            service_pending_user_tlb_flush();
            spins = spins.wrapping_add(1);
            if spins % 100_000 == 0 {
                crate::arch::send_tlb_flush_ipi(hart_id);
                // QEMU 可能合并相同 action 位；普通 reschedule 位用于补一次唤醒边沿。
                crate::arch::send_ipi(hart_id);
            }
            core::hint::spin_loop();
        }
    }
}

pub fn handle_ipi_actions(_actions: u32) {
    service_pending_user_tlb_flush();
}

pub fn service_pending_user_tlb_flush() {
    let hart_id = crate::arch::hart_id();
    if hart_id >= MAX_HARTS {
        return;
    }
    loop {
        let requested = TLB_FLUSH_REQUEST[hart_id].load(Ordering::Acquire);
        if TLB_FLUSH_ACK[hart_id].load(Ordering::Acquire) >= requested {
            break;
        }
        flush_local_user_tlb();
        TLB_FLUSH_ACK[hart_id].store(requested, Ordering::Release);
    }
}

fn request_remote_user_tlb_flush(ctx: &AsidContext) {
    let mask = ctx.remote_active_harts();
    for hart_id in 0..MAX_HARTS {
        if mask & (1usize << hart_id) == 0 {
            continue;
        }
        TLB_FLUSH_REQUEST[hart_id].fetch_add(1, Ordering::AcqRel);
        crate::arch::send_tlb_flush_ipi(hart_id);
    }
}

fn online_hart_mask() -> usize {
    crate::task::manager::online_hart_mask() & configured_hart_mask()
}

fn local_hart_bit() -> usize {
    let hart_id = crate::arch::hart_id();
    if hart_id < usize::BITS as usize {
        1usize << hart_id
    } else {
        0
    }
}

const fn configured_hart_mask() -> usize {
    if MAX_HARTS >= usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << MAX_HARTS) - 1
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
pub fn flush_local_user_tlb() {
    // 只清除本 hart 的非全局项，内核全局映射仍保持热状态。
    unsafe {
        asm!("invtlb 0x3, $r0, $r0");
    }
}

#[inline(always)]
fn align_tlb_pair(vaddr: usize) -> usize {
    vaddr & !((crate::config::PAGE_SIZE << 1) - 1)
}
