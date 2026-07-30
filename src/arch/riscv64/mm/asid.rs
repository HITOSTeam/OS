use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
/// ASID 快路径仍需完成跨 hart TLB shootdown 验证；在此之前保留按 hart
/// I-cache 优化，但使用 ASID 0 的保守切换路径保证正式 CAgent 回归稳定。
const ENABLE_USER_ASID: bool = false;

static NEXT_USER_ASID: AtomicUsize = AtomicUsize::new(FIRST_USER_ASID);
static ASID_GENERATION: AtomicUsize = AtomicUsize::new(1);
static HW_ASID_MASK: AtomicUsize = AtomicUsize::new(HW_ASID_MASK_UNPROBED);
/// 串行化首次 ASID 分配，避免同一个 mm 被多个 hart 同时分配不同 ASID。
static ASID_ALLOC_LOCK: Mutex<()> = Mutex::new(());
/// ASID 空间耗尽后永久退回 ASID 0 + 本地全量刷新。
///
/// 在没有实现 Linux 式全 hart rollover 同步前，禁止复用旧 ASID，避免远端
/// hart 的旧 TLB 项与新 mm 冲突。16 位 ASID 足以覆盖当前评测生命周期。
static ASID_EXHAUSTED: AtomicBool = AtomicBool::new(false);

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

    fn take_local_icache_stale(&self) -> bool {
        // 每个 mm 为每个 hart 保存一个 stale 位。任务迁移到某个 hart 时只消费
        // 该 hart 的位；可执行映射再次变化后，mark_icache_stale 会重新置位。
        let bit = local_hart_bit();
        if bit == 0 {
            return self.icache_stale_mask.swap(0, Ordering::AcqRel) != 0;
        }
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
    ENABLE_USER_ASID && !ASID_EXHAUSTED.load(Ordering::Acquire) && hw_asid_mask() != 0
}

fn allocate_user_asid(max_asid: usize) -> Option<(usize, usize)> {
    let asid = NEXT_USER_ASID.fetch_add(1, Ordering::AcqRel);
    if asid <= max_asid {
        return Some((asid, ASID_GENERATION.load(Ordering::Acquire)));
    }

    ASID_EXHAUSTED.store(true, Ordering::Release);
    None
}

fn token_with_asid(token: usize, asid: usize) -> usize {
    (token & !(SATP_ASID_MASK << SATP_ASID_SHIFT)) | ((asid & SATP_ASID_MASK) << SATP_ASID_SHIFT)
}

pub fn prepare_user_satp(ctx: &AsidContext, token: usize) -> (usize, bool, bool) {
    let need_icache_flush = ctx.take_local_icache_stale();
    if !ENABLE_USER_ASID {
        return (token_with_asid(token, KERNEL_ASID), true, need_icache_flush);
    }
    let max_asid = hw_asid_mask();
    if max_asid == 0 || ASID_EXHAUSTED.load(Ordering::Acquire) {
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

    // 同一个新 mm 可能被多个 hart 同时调度。锁内复查可保证它们共享同一个
    // ASID，而不是分别分配后互相覆盖 ctx。
    let _alloc_guard = ASID_ALLOC_LOCK.lock();
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if ctx.valid_for(generation) {
        return (
            token_with_asid(token, ctx.asid.load(Ordering::Acquire)),
            false,
            need_icache_flush,
        );
    }
    let Some((asid, generation)) = allocate_user_asid(max_asid) else {
        return (token_with_asid(token, KERNEL_ASID), true, need_icache_flush);
    };
    ctx.store(asid, generation);
    // ASID 在整个评测生命周期内不复用，因此首次安装也不需要清除旧 TLB。
    (token_with_asid(token, asid), false, need_icache_flush)
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
