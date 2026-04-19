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
ext4_cache_hits: {cache_hits}\n\
ext4_cache_misses: {cache_misses}\n\
ext4_cache_hit_pct: {cache_hit_pct}\n"
    )
}
