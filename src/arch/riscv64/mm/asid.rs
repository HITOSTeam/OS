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
/// 用户地址空间使用不复用的硬件 ASID；页表修改路径负责向其他在线 hart
/// 发起 TLB shootdown，普通 trap 返回无需再做全量刷新。
const ENABLE_USER_ASID: bool = true;

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
    active_hart_mask: AtomicUsize,
    icache_stale_mask: AtomicUsize,
}

impl AsidContext {
    pub const fn new() -> Self {
        Self {
            asid: AtomicUsize::new(0),
            generation: AtomicUsize::new(0),
            active_hart_mask: AtomicUsize::new(0),
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

    fn mark_local_active(&self) {
        let bit = local_hart_bit();
        if bit != 0 {
            self.active_hart_mask.fetch_or(bit, Ordering::AcqRel);
        }
    }

    fn remote_active_harts(&self) -> usize {
        self.active_hart_mask.load(Ordering::Acquire) & online_hart_mask() & !local_hart_bit()
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
    // 记录这个 mm 曾在哪些 hart 上安装过。页表改变时只需要 shootdown 这些
    // 可能缓存旧翻译的 hart，而不是打断全部 12 个核心。
    ctx.mark_local_active();
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

pub fn mark_icache_stale(ctx: &AsidContext) {
    ctx.mark_icache_stale();
}

pub fn flush_user_all(ctx: &AsidContext) {
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if asid_fast_path_enabled() && ctx.valid_for(generation) {
        let asid = ctx.asid.load(Ordering::Acquire);
        let remote_mask = ctx.remote_active_harts();
        crate::sbi::remote_sfence_vma_asid(remote_mask, asid);
        // SAFETY: ASID 由内核分配；仅清除当前 hart 上属于该地址空间的翻译。
        unsafe {
            asm!(
                "sfence.vma zero, {asid}",
                asid = in(reg) asid,
                options(nostack)
            );
        }
    } else {
        // 未分配 ASID 时所有用户页表共用 ASID 0，远端也必须失效，不能只刷新
        // 当前 hart；active_hart_mask 只包含曾装入过当前页表的 CPU。
        crate::sbi::remote_sfence_vma_all(ctx.remote_active_harts());
        // SAFETY: 本地全量刷新可清除 ASID 0 的旧翻译。
        unsafe {
            asm!("sfence.vma", options(nostack));
        }
    }
}

pub fn flush_local_user_page(ctx: &AsidContext, vaddr: usize) {
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if asid_fast_path_enabled() && ctx.valid_for(generation) {
        let asid = ctx.asid.load(Ordering::Acquire);
        // SAFETY: 首次 lazy 映射只需清除当前 fault hart 的负缓存翻译。
        unsafe {
            asm!(
                "sfence.vma {addr}, {asid}",
                addr = in(reg) vaddr,
                asid = in(reg) asid,
                options(nostack)
            );
        }
    } else {
        // SAFETY: 无有效 ASID 时按地址清除本地所有 ASID 的翻译。
        unsafe {
            asm!("sfence.vma {addr}, zero", addr = in(reg) vaddr, options(nostack));
        }
    }
}

pub fn flush_user_page(ctx: &AsidContext, vaddr: usize) {
    let generation = ASID_GENERATION.load(Ordering::Acquire);
    if asid_fast_path_enabled() && ctx.valid_for(generation) {
        let asid = ctx.asid.load(Ordering::Acquire);
        // 同一个 mm 的线程可能在其他 hart 上运行，或在迁移前留下 TLB 项。
        // 仅失效该 mm 的 ASID，保留其他进程和内核的热翻译。
        let remote_mask = ctx.remote_active_harts();
        crate::sbi::remote_sfence_vma_asid(remote_mask, asid);
        // SAFETY: 地址和 ASID 均由内核管理；这只会失效对应的非全局用户翻译。
        unsafe {
            asm!(
                "sfence.vma {addr}, {asid}",
                addr = in(reg) vaddr,
                asid = in(reg) asid,
                options(nostack)
            );
        }
    } else {
        // 无有效 ASID 时不能按 ASID 定向失效；先清除曾运行过该页表的远端 hart，
        // 再按地址清除本地所有 ASID 的翻译。
        crate::sbi::remote_sfence_vma_all(ctx.remote_active_harts());
        // SAFETY: 此时按地址刷新所有 ASID 的翻译。
        unsafe {
            asm!("sfence.vma {addr}, zero", addr = in(reg) vaddr, options(nostack));
        }
    }
}
