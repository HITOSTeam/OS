//! Timer-related functionality

use crate::{
    arch::{read_time, set_timer},
    config::clock_freq,
};

const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;

#[cfg(target_arch = "loongarch64")]
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(target_arch = "loongarch64")]
static LOONGARCH_TIMER_DELTA: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "loongarch64")]
static LOONGARCH_TIMER_LAST_TIME: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "loongarch64")]
static LOONGARCH_TIMER_CALIBRATED: AtomicBool = AtomicBool::new(false);

/// read the `mtime` register
pub fn get_time() -> usize {
    read_time()
}

/// get current time in nanoseconds from the monotonic clock source
pub fn get_time_ns() -> u64 {
    let freq = clock_freq() as u128;
    ((read_time() as u128).saturating_mul(1_000_000_000u128) / freq) as u64
}

/// get current time in milliseconds
pub fn get_time_ms() -> usize {
    read_time() / (clock_freq() / MSEC_PER_SEC)
}

/// set the next timer interrupt
pub fn set_next_trigger() {
    #[cfg(target_arch = "loongarch64")]
    {
        // LoongArch TCFG uses a relative countdown; use clock_freq directly to avoid
        // mismatches between rdtime and timer countdown sources.
        let mut delta = LOONGARCH_TIMER_DELTA.load(Ordering::Relaxed);
        if delta == 0 {
            delta = clock_freq() / TICKS_PER_SEC;
            if delta == 0 {
                delta = 4;
            }
            LOONGARCH_TIMER_DELTA.store(delta, Ordering::Relaxed);
        }
        crate::log_if!(
            crate::debug_config::DEBUG_TIMER,
            trace,
            "[time] hart={} set_next_trigger delta={:#x}",
            {
                let hart: usize;
                unsafe { core::arch::asm!("mv {}, tp", out(reg) hart) };
                hart
            },
            delta
        );
        set_timer(delta);
        return;
    }
    #[cfg(not(target_arch = "loongarch64"))]
    {
        let next = get_time() + clock_freq() / TICKS_PER_SEC;
        crate::log_if!(
            crate::debug_config::DEBUG_TIMER,
            trace,
            "[time] hart={} set_next_trigger -> {:#x} (now={:#x})",
            {
                let hart: usize;
                unsafe { core::arch::asm!("mv {}, tp", out(reg) hart) };
                hart
            },
            next,
            get_time()
        );
        set_timer(next);
    }
}

#[cfg(target_arch = "loongarch64")]
pub fn loongarch_record_timer_tick() {
    let now = read_time();
    let last = LOONGARCH_TIMER_LAST_TIME.swap(now, Ordering::Relaxed);
    if last == 0 {
        return;
    }
    if LOONGARCH_TIMER_CALIBRATED.load(Ordering::Relaxed) {
        return;
    }
    let dt = now.saturating_sub(last);
    if dt == 0 {
        return;
    }
    let target = clock_freq() / TICKS_PER_SEC;
    if target == 0 {
        return;
    }
    let current = LOONGARCH_TIMER_DELTA.load(Ordering::Relaxed);
    if current == 0 {
        return;
    }
    let mut new_delta = current.saturating_mul(target) / dt;
    if new_delta < 4 {
        new_delta = 4;
    }
    LOONGARCH_TIMER_DELTA.store(new_delta, Ordering::Relaxed);
    LOONGARCH_TIMER_CALIBRATED.store(true, Ordering::Relaxed);
}
