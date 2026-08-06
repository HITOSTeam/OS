//! Lightweight performance counters for diagnosing bottlenecks.

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch;
use crate::debug_config::DEBUG_PERF;

static UART_BYTES: AtomicU64 = AtomicU64::new(0);
static UART_FLUSHES: AtomicU64 = AtomicU64::new(0);
static UART_FLUSH_CYCLES: AtomicU64 = AtomicU64::new(0);

static BLK_READ_OPS: AtomicU64 = AtomicU64::new(0);
static BLK_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static BLK_READ_CYCLES: AtomicU64 = AtomicU64::new(0);

static BLK_WRITE_OPS: AtomicU64 = AtomicU64::new(0);
static BLK_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
static BLK_WRITE_CYCLES: AtomicU64 = AtomicU64::new(0);

static TLB_PAGE_BATCHES: AtomicU64 = AtomicU64::new(0);
static TLB_RANGE_BATCHES: AtomicU64 = AtomicU64::new(0);
static TLB_ASID_DROPS: AtomicU64 = AtomicU64::new(0);
static TLB_BATCHED_EDITS: AtomicU64 = AtomicU64::new(0);
static TLB_MERGED_RANGES: AtomicU64 = AtomicU64::new(0);
static TLB_EXACT_PAIRS: AtomicU64 = AtomicU64::new(0);
static TLB_REMOTE_IPIS: AtomicU64 = AtomicU64::new(0);
static TLB_SHOOTDOWN_WAIT_CYCLES: AtomicU64 = AtomicU64::new(0);
static TLB_ASID_WRAPS: AtomicU64 = AtomicU64::new(0);
static ICACHE_LOCAL_FENCES: AtomicU64 = AtomicU64::new(0);
static ICACHE_DEFERRED_FENCES: AtomicU64 = AtomicU64::new(0);
static ICACHE_REMOTE_FENCES: AtomicU64 = AtomicU64::new(0);
static ICACHE_REMOTE_TARGETS: AtomicU64 = AtomicU64::new(0);

static DCACHE_LOOKUPS: AtomicU64 = AtomicU64::new(0);
static DCACHE_HITS: AtomicU64 = AtomicU64::new(0);
static DCACHE_REVALIDATED_HITS: AtomicU64 = AtomicU64::new(0);
static DCACHE_BACKEND_LOOKUPS: AtomicU64 = AtomicU64::new(0);
static DCACHE_INSERTIONS: AtomicU64 = AtomicU64::new(0);
static DCACHE_REPLACEMENTS: AtomicU64 = AtomicU64::new(0);
static DCACHE_INVALIDATIONS: AtomicU64 = AtomicU64::new(0);
static DCACHE_EVICTIONS: AtomicU64 = AtomicU64::new(0);
static DCACHE_CLOCK_SCANS: AtomicU64 = AtomicU64::new(0);
static DCACHE_ENTRIES: AtomicU64 = AtomicU64::new(0);
static DCACHE_PEAK_ENTRIES: AtomicU64 = AtomicU64::new(0);

#[inline]
#[allow(dead_code)]
pub fn enabled() -> bool {
    DEBUG_PERF
}

#[inline]
#[allow(dead_code)]
pub fn record_uart_bytes(bytes: usize) {
    if !DEBUG_PERF || bytes == 0 {
        return;
    }
    UART_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

#[inline]
#[allow(dead_code)]
pub fn uart_flush_begin() -> usize {
    if DEBUG_PERF { arch::read_time() } else { 0 }
}

#[inline]
#[allow(dead_code)]
pub fn uart_flush_end(start: usize) {
    if !DEBUG_PERF {
        return;
    }
    let end = arch::read_time();
    let delta = end.wrapping_sub(start) as u64;
    UART_FLUSHES.fetch_add(1, Ordering::Relaxed);
    UART_FLUSH_CYCLES.fetch_add(delta, Ordering::Relaxed);
}

#[inline]
pub fn block_read_begin() -> usize {
    if DEBUG_PERF { arch::read_time() } else { 0 }
}

#[inline]
pub fn block_read_end(start: usize, bytes: usize) {
    if !DEBUG_PERF {
        return;
    }
    let end = arch::read_time();
    let delta = end.wrapping_sub(start) as u64;
    BLK_READ_OPS.fetch_add(1, Ordering::Relaxed);
    BLK_READ_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    BLK_READ_CYCLES.fetch_add(delta, Ordering::Relaxed);
}

#[inline]
pub fn block_write_begin() -> usize {
    if DEBUG_PERF { arch::read_time() } else { 0 }
}

#[inline]
pub fn block_write_end(start: usize, bytes: usize) {
    if !DEBUG_PERF {
        return;
    }
    let end = arch::read_time();
    let delta = end.wrapping_sub(start) as u64;
    BLK_WRITE_OPS.fetch_add(1, Ordering::Relaxed);
    BLK_WRITE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    BLK_WRITE_CYCLES.fetch_add(delta, Ordering::Relaxed);
}

#[inline]
pub fn record_tlb_exact_batch(edits: usize, ranges: usize, pairs: usize) {
    if !DEBUG_PERF {
        return;
    }
    if ranges == 1 && pairs == 1 {
        TLB_PAGE_BATCHES.fetch_add(1, Ordering::Relaxed);
    } else {
        TLB_RANGE_BATCHES.fetch_add(1, Ordering::Relaxed);
    }
    TLB_BATCHED_EDITS.fetch_add(edits as u64, Ordering::Relaxed);
    TLB_MERGED_RANGES.fetch_add(ranges as u64, Ordering::Relaxed);
}

#[inline]
pub fn record_tlb_asid_drop(edits: usize) {
    if !DEBUG_PERF {
        return;
    }
    TLB_ASID_DROPS.fetch_add(1, Ordering::Relaxed);
    TLB_BATCHED_EDITS.fetch_add(edits as u64, Ordering::Relaxed);
}

#[inline]
pub fn record_tlb_exact_pairs(pairs: usize) {
    if DEBUG_PERF && pairs != 0 {
        TLB_EXACT_PAIRS.fetch_add(pairs as u64, Ordering::Relaxed);
    }
}

#[inline]
pub fn record_tlb_shootdown(remote_ipis: usize, wait_cycles: usize) {
    if !DEBUG_PERF {
        return;
    }
    TLB_REMOTE_IPIS.fetch_add(remote_ipis as u64, Ordering::Relaxed);
    TLB_SHOOTDOWN_WAIT_CYCLES.fetch_add(wait_cycles as u64, Ordering::Relaxed);
}

#[inline]
pub fn record_tlb_asid_wrap() {
    if DEBUG_PERF {
        TLB_ASID_WRAPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn record_icache_local_fence(deferred: bool) {
    if !DEBUG_PERF {
        return;
    }
    ICACHE_LOCAL_FENCES.fetch_add(1, Ordering::Relaxed);
    if deferred {
        ICACHE_DEFERRED_FENCES.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn record_icache_remote_fence(targets: usize) {
    if !DEBUG_PERF {
        return;
    }
    ICACHE_REMOTE_FENCES.fetch_add(1, Ordering::Relaxed);
    ICACHE_REMOTE_TARGETS.fetch_add(targets as u64, Ordering::Relaxed);
}

#[inline]
pub fn record_dcache_lookup() {
    if DEBUG_PERF {
        DCACHE_LOOKUPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn record_dcache_backend_lookup() {
    if DEBUG_PERF {
        DCACHE_BACKEND_LOOKUPS.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn record_dcache_hit(revalidated: bool) {
    if !DEBUG_PERF {
        return;
    }
    DCACHE_HITS.fetch_add(1, Ordering::Relaxed);
    if revalidated {
        DCACHE_REVALIDATED_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn record_dcache_insert(replacing: bool) {
    if !DEBUG_PERF {
        return;
    }
    DCACHE_INSERTIONS.fetch_add(1, Ordering::Relaxed);
    if replacing {
        DCACHE_REPLACEMENTS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let entries = DCACHE_ENTRIES.fetch_add(1, Ordering::Relaxed) + 1;
    DCACHE_PEAK_ENTRIES.fetch_max(entries, Ordering::Relaxed);
}

#[inline]
pub fn record_dcache_invalidations(count: usize) {
    if !DEBUG_PERF || count == 0 {
        return;
    }
    DCACHE_INVALIDATIONS.fetch_add(count as u64, Ordering::Relaxed);
    DCACHE_ENTRIES.fetch_sub(count as u64, Ordering::Relaxed);
}

#[inline]
pub fn record_dcache_drop(count: usize) {
    if DEBUG_PERF && count != 0 {
        DCACHE_ENTRIES.fetch_sub(count as u64, Ordering::Relaxed);
    }
}

#[inline]
pub fn record_dcache_eviction() {
    if !DEBUG_PERF {
        return;
    }
    DCACHE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
    DCACHE_ENTRIES.fetch_sub(1, Ordering::Relaxed);
}

#[inline]
pub fn record_dcache_clock_scan() {
    if DEBUG_PERF {
        DCACHE_CLOCK_SCANS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn dump() -> String {
    if !DEBUG_PERF {
        return String::from("perf disabled (set DEBUG_PERF=true)\n");
    }
    let uart_bytes = UART_BYTES.load(Ordering::Relaxed);
    let uart_flushes = UART_FLUSHES.load(Ordering::Relaxed);
    let uart_flush_cycles = UART_FLUSH_CYCLES.load(Ordering::Relaxed);
    let blk_read_ops = BLK_READ_OPS.load(Ordering::Relaxed);
    let blk_read_bytes = BLK_READ_BYTES.load(Ordering::Relaxed);
    let blk_read_cycles = BLK_READ_CYCLES.load(Ordering::Relaxed);
    let blk_write_ops = BLK_WRITE_OPS.load(Ordering::Relaxed);
    let blk_write_bytes = BLK_WRITE_BYTES.load(Ordering::Relaxed);
    let blk_write_cycles = BLK_WRITE_CYCLES.load(Ordering::Relaxed);
    let tlb_page_batches = TLB_PAGE_BATCHES.load(Ordering::Relaxed);
    let tlb_range_batches = TLB_RANGE_BATCHES.load(Ordering::Relaxed);
    let tlb_asid_drops = TLB_ASID_DROPS.load(Ordering::Relaxed);
    let tlb_batched_edits = TLB_BATCHED_EDITS.load(Ordering::Relaxed);
    let tlb_merged_ranges = TLB_MERGED_RANGES.load(Ordering::Relaxed);
    let tlb_exact_pairs = TLB_EXACT_PAIRS.load(Ordering::Relaxed);
    let tlb_remote_ipis = TLB_REMOTE_IPIS.load(Ordering::Relaxed);
    let tlb_shootdown_wait_cycles = TLB_SHOOTDOWN_WAIT_CYCLES.load(Ordering::Relaxed);
    let tlb_asid_wraps = TLB_ASID_WRAPS.load(Ordering::Relaxed);
    let icache_local_fences = ICACHE_LOCAL_FENCES.load(Ordering::Relaxed);
    let icache_deferred_fences = ICACHE_DEFERRED_FENCES.load(Ordering::Relaxed);
    let icache_remote_fences = ICACHE_REMOTE_FENCES.load(Ordering::Relaxed);
    let icache_remote_targets = ICACHE_REMOTE_TARGETS.load(Ordering::Relaxed);
    let dcache_lookups = DCACHE_LOOKUPS.load(Ordering::Relaxed);
    let dcache_hits = DCACHE_HITS.load(Ordering::Relaxed);
    let dcache_revalidated_hits = DCACHE_REVALIDATED_HITS.load(Ordering::Relaxed);
    let dcache_backend_lookups = DCACHE_BACKEND_LOOKUPS.load(Ordering::Relaxed);
    let dcache_insertions = DCACHE_INSERTIONS.load(Ordering::Relaxed);
    let dcache_replacements = DCACHE_REPLACEMENTS.load(Ordering::Relaxed);
    let dcache_invalidations = DCACHE_INVALIDATIONS.load(Ordering::Relaxed);
    let dcache_evictions = DCACHE_EVICTIONS.load(Ordering::Relaxed);
    let dcache_clock_scans = DCACHE_CLOCK_SCANS.load(Ordering::Relaxed);
    let dcache_entries = DCACHE_ENTRIES.load(Ordering::Relaxed);
    let dcache_peak_entries = DCACHE_PEAK_ENTRIES.load(Ordering::Relaxed);
    let (cache_hits, cache_misses) = ext4_fs::cache_stats();
    let cache_total = cache_hits.saturating_add(cache_misses);
    let cache_hit_pct = if cache_total == 0 {
        0
    } else {
        (cache_hits.saturating_mul(100)) / cache_total
    };

    alloc::format!(
        "uart_bytes: {uart_bytes}\n\
uart_flushes: {uart_flushes}\n\
uart_flush_cycles: {uart_flush_cycles}\n\
block_read_ops: {blk_read_ops}\n\
block_read_bytes: {blk_read_bytes}\n\
block_read_cycles: {blk_read_cycles}\n\
block_write_ops: {blk_write_ops}\n\
block_write_bytes: {blk_write_bytes}\n\
block_write_cycles: {blk_write_cycles}\n\
tlb_page_batches: {tlb_page_batches}\n\
tlb_range_batches: {tlb_range_batches}\n\
tlb_asid_drops: {tlb_asid_drops}\n\
tlb_batched_edits: {tlb_batched_edits}\n\
tlb_merged_ranges: {tlb_merged_ranges}\n\
tlb_exact_pairs: {tlb_exact_pairs}\n\
tlb_remote_ipis: {tlb_remote_ipis}\n\
tlb_shootdown_wait_cycles: {tlb_shootdown_wait_cycles}\n\
tlb_asid_wraps: {tlb_asid_wraps}\n\
icache_local_fences: {icache_local_fences}\n\
icache_deferred_fences: {icache_deferred_fences}\n\
icache_remote_fences: {icache_remote_fences}\n\
icache_remote_targets: {icache_remote_targets}\n\
dcache_lookups: {dcache_lookups}\n\
dcache_hits: {dcache_hits}\n\
dcache_revalidated_hits: {dcache_revalidated_hits}\n\
dcache_backend_lookups: {dcache_backend_lookups}\n\
dcache_insertions: {dcache_insertions}\n\
dcache_replacements: {dcache_replacements}\n\
dcache_invalidations: {dcache_invalidations}\n\
dcache_evictions: {dcache_evictions}\n\
dcache_clock_scans: {dcache_clock_scans}\n\
dcache_entries: {dcache_entries}\n\
dcache_peak_entries: {dcache_peak_entries}\n\
ext4_cache_hits: {cache_hits}\n\
ext4_cache_misses: {cache_misses}\n\
ext4_cache_hit_pct: {cache_hit_pct}\n"
    )
}
