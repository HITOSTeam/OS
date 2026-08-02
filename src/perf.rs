//! Lightweight performance counters for diagnosing bottlenecks.
// 主要是来debug各种syscall的时间

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

// ---- CAgent 云端慢速诊断：per-syscall 计时 ----
//
// 命中率/IO 慢、fork/exec 慢、锁开销大头一般都落在几个 syscall 上。
// 每次 syscall 进出来记录 cycles 并按 id 累计：count/total/max。
// 不按次数触发，改为按时间周期触发：内存里累加，不影响正常运行速度。
#[cfg(debug_assertions)]
const SYSCALL_SLOT_COUNT: usize = 1024;
#[cfg(debug_assertions)]
const SYSCALL_DUMP_TOPN: usize = 15;
#[cfg(debug_assertions)]
const SYSCALL_DUMP_SECS: u64 = 2;

#[cfg(debug_assertions)]
static SYSCALL_COUNTS: [AtomicU64; SYSCALL_SLOT_COUNT] =
    [const { AtomicU64::new(0) }; SYSCALL_SLOT_COUNT];
#[cfg(debug_assertions)]
static SYSCALL_TOTALS: [AtomicU64; SYSCALL_SLOT_COUNT] =
    [const { AtomicU64::new(0) }; SYSCALL_SLOT_COUNT];
#[cfg(debug_assertions)]
static SYSCALL_MAXES: [AtomicU64; SYSCALL_SLOT_COUNT] =
    [const { AtomicU64::new(0) }; SYSCALL_SLOT_COUNT];
#[cfg(debug_assertions)]
static SYSCALL_GLOBAL_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(debug_assertions)]
static LAST_DUMP_TICK: AtomicU64 = AtomicU64::new(0);

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

// ---- 在debug cagent的时候添加的慢速诊断：计算每一个系统调用消耗的时间 ----

#[inline]
#[cfg(debug_assertions)]
pub fn syscall_begin(_id: usize) -> usize {
    if DEBUG_PERF { arch::read_time() } else { 0 }
}

#[inline]
#[cfg(debug_assertions)]
pub fn syscall_end(id: usize, start: usize) {
    if !DEBUG_PERF || start == 0 {
        return;
    }
    let end = arch::read_time();
    let delta_cycles = end.wrapping_sub(start) as u64;

    if id < SYSCALL_SLOT_COUNT {
        SYSCALL_COUNTS[id].fetch_add(1, Ordering::Relaxed);
        SYSCALL_TOTALS[id].fetch_add(delta_cycles, Ordering::Relaxed);
        let mut cur_max = SYSCALL_MAXES[id].load(Ordering::Relaxed);
        while delta_cycles > cur_max {
            match SYSCALL_MAXES[id].compare_exchange_weak(
                cur_max,
                delta_cycles,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => cur_max = actual,
            }
        }
    }

    let global = SYSCALL_GLOBAL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let _ = global;

    let freq = crate::config::clock_freq() as u64;
    let interval_ticks = freq.saturating_mul(SYSCALL_DUMP_SECS);
    if interval_ticks == 0 {
        return;
    }
    let end_tick = end as u64;
    let last = LAST_DUMP_TICK.load(Ordering::Relaxed);
    if end_tick.wrapping_sub(last) >= interval_ticks {
        if LAST_DUMP_TICK
            .compare_exchange(last, end_tick, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            dump_to_console();
        }
    }
}

#[inline]
#[cfg(debug_assertions)]
fn cycles_to_us(cycles: u64) -> u64 {
    let freq = crate::config::clock_freq() as u64;
    if freq == 0 {
        return cycles;
    }
    (cycles.saturating_mul(1_000_000)) / freq
}

#[cold]
#[inline(never)]
#[cfg(debug_assertions)]
pub fn dump_to_console() {
    if !DEBUG_PERF {
        return;
    }
    let freq = crate::config::clock_freq() as u64;
    let mut entries: alloc::vec::Vec<(usize, u64, u64, u64)> = alloc::vec::Vec::new();
    for id in 0..SYSCALL_SLOT_COUNT {
        let count = SYSCALL_COUNTS[id].load(Ordering::Relaxed);
        if count == 0 {
            continue;
        }
        let total_cycles = SYSCALL_TOTALS[id].load(Ordering::Relaxed);
        let max_cycles = SYSCALL_MAXES[id].load(Ordering::Relaxed);
        entries.push((
            id,
            count,
            cycles_to_us(total_cycles),
            cycles_to_us(max_cycles),
        ));
    }
    entries.sort_by(|a, b| b.2.cmp(&a.2));

    let (cache_hits, cache_misses) = ext4_fs::cache_stats();
    let cache_total = cache_hits.saturating_add(cache_misses);
    let cache_hit_pct = if cache_total == 0 {
        0
    } else {
        (cache_hits.saturating_mul(100)) / cache_total
    };
    let blk_read_ops = BLK_READ_OPS.load(Ordering::Relaxed);
    let blk_write_ops = BLK_WRITE_OPS.load(Ordering::Relaxed);

    let mut buf = String::with_capacity(512);
    buf.push_str(&alloc::format!(
        "[perf] syscalls={} freq={} cache_hit={}% blk_r={} blk_w={}",
        SYSCALL_GLOBAL_COUNT.load(Ordering::Relaxed),
        freq,
        cache_hit_pct,
        blk_read_ops,
        blk_write_ops,
    ));
    let n = entries.len().min(SYSCALL_DUMP_TOPN);
    for i in 0..n {
        let (id, count, total_us, max_us) = entries[i];
        let avg_us = if count > 0 { total_us / count } else { 0 };
        buf.push_str(&alloc::format!(
            "\n  top[{}] id={:3} cnt={} tot={}us avg={}us max={}us",
            i,
            id,
            count,
            total_us,
            avg_us,
            max_us
        ));
    }
    crate::println!("{}", buf);
}
