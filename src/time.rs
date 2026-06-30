//! Timer-related functionality

use crate::{
    arch::{hart_id, read_time, set_timer},
    config::{MAX_HARTS, clock_freq},
};
use core::sync::atomic::{AtomicUsize, Ordering};

/// 默认一秒钟执行 100 个时钟中断。
const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;
const NSEC_PER_SEC: u128 = 1_000_000_000;

#[cfg(target_arch = "loongarch64")]
use core::sync::atomic::AtomicBool;

#[cfg(target_arch = "loongarch64")]
const LOONGARCH_TIMER_CALIBRATION_SAMPLES: usize = 4;
#[cfg(target_arch = "loongarch64")]
static LOONGARCH_CLOCKEVENT_TICK_DELTA: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_HARTS];
#[cfg(target_arch = "loongarch64")]
static LOONGARCH_TIMER_LAST_TIME: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_HARTS];
#[cfg(target_arch = "loongarch64")]
static LOONGARCH_TIMER_MIN_DT: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(usize::MAX) }; MAX_HARTS];
#[cfg(target_arch = "loongarch64")]
static LOONGARCH_TIMER_SAMPLE_COUNT: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_HARTS];
#[cfg(target_arch = "loongarch64")]
static LOONGARCH_TIMER_CALIBRATED: [AtomicBool; MAX_HARTS] =
    [const { AtomicBool::new(false) }; MAX_HARTS];

#[cfg(target_arch = "loongarch64")]
static LOONGARCH_CLOCKEVENT_NEXT_DEADLINE_NS: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(usize::MAX) }; MAX_HARTS];
#[cfg(target_arch = "riscv64")]
static RISCV_CLOCKEVENT_NEXT_TICKS: [AtomicUsize; MAX_HARTS] =
    [const { AtomicUsize::new(usize::MAX) }; MAX_HARTS];

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
    #[cfg(target_arch = "riscv64")]
    {
        riscv_program_clockevent_delta_ticks(riscv_tick_delta(), true);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let next_deadline_ns = get_time_ns().saturating_add(tick_period_ns());
        loongarch_program_clockevent_deadline_ns(next_deadline_ns, true);
    }
}

pub fn tick_period_ns() -> u64 {
    (1_000_000_000u64 / TICKS_PER_SEC as u64).max(1)
}

fn clockevent_hart_idx() -> usize {
    hart_id().min(MAX_HARTS.saturating_sub(1))
}

/// Stop the current one-shot clockevent. Linux's RISC-V timer interrupt first
/// stops the event device, then lets the generic clockevent/hrtimer layer pick
/// the next event.
#[cfg(target_arch = "riscv64")]
pub fn stop_current_clockevent() {
    let hart = clockevent_hart_idx();
    RISCV_CLOCKEVENT_NEXT_TICKS[hart].store(usize::MAX, Ordering::Release);
}

#[cfg(target_arch = "loongarch64")]
fn loongarch_rdtime_tick_delta() -> usize {
    (clock_freq() / TICKS_PER_SEC).max(1)
}

#[cfg(target_arch = "loongarch64")]
fn loongarch_hart_idx() -> usize {
    crate::arch::hart_id().min(MAX_HARTS.saturating_sub(1))
}

#[cfg(target_arch = "loongarch64")]
fn loongarch_timer_tick_delta() -> usize {
    let hart = loongarch_hart_idx();
    let mut delta = LOONGARCH_CLOCKEVENT_TICK_DELTA[hart].load(Ordering::Relaxed);
    if delta == 0 {
        delta = loongarch_rdtime_tick_delta().max(4);
        LOONGARCH_CLOCKEVENT_TICK_DELTA[hart].store(delta, Ordering::Relaxed);
    }
    delta.max(1)
}

#[cfg(target_arch = "riscv64")]
fn riscv_tick_delta() -> usize {
    (clock_freq() / TICKS_PER_SEC).max(1)
}

#[cfg(target_arch = "loongarch64")]
fn ns_delta_to_ticks_ceil(delta_ns: u64) -> usize {
    let rdtime_ticks = (delta_ns as u128)
        .saturating_mul(clock_freq() as u128)
        .saturating_add(NSEC_PER_SEC - 1)
        / NSEC_PER_SEC;
    let rdtime_period = loongarch_rdtime_tick_delta() as u128;
    let timer_period = loongarch_timer_tick_delta() as u128;
    let ticks = rdtime_ticks
        .saturating_mul(timer_period)
        .saturating_add(rdtime_period.saturating_sub(1))
        / rdtime_period.max(1);
    ticks.clamp(1, usize::MAX as u128) as usize
}

#[cfg(target_arch = "riscv64")]
fn riscv_ns_delta_to_ticks_ceil(delta_ns: u64) -> usize {
    let ticks = (delta_ns as u128)
        .saturating_mul(clock_freq() as u128)
        .saturating_add(NSEC_PER_SEC - 1)
        / NSEC_PER_SEC;
    ticks.clamp(1, usize::MAX as u128) as usize
}

/// Program the timer for a sub-tick sleep deadline when it is earlier than the
/// normal scheduler tick. This is a small hrtimer-style fast path used by
/// nanosleep/clock_nanosleep while preserving the periodic tick fallback.
pub fn arm_timer_for_deadline_ns(deadline_ns: u64) {
    #[cfg(target_arch = "riscv64")]
    {
        let now_ns = get_time_ns();
        let delta_ns = deadline_ns.saturating_sub(now_ns).max(1);
        let delta_ticks = riscv_ns_delta_to_ticks_ceil(delta_ns).min(riscv_tick_delta());
        riscv_program_clockevent_delta_ticks(delta_ticks, false);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let now_ns = get_time_ns();
        let periodic_deadline_ns = now_ns.saturating_add(tick_period_ns());
        loongarch_program_clockevent_deadline_ns(deadline_ns.min(periodic_deadline_ns), false);
    }
}

#[cfg(target_arch = "riscv64")]
fn riscv_program_clockevent_delta_ticks(delta_ticks: usize, force: bool) {
    let hart = clockevent_hart_idx();
    let now_ticks = get_time();
    let delta_ticks = delta_ticks.max(1);
    let deadline_ticks = now_ticks.saturating_add(delta_ticks);

    if !force {
        let programmed_ticks = RISCV_CLOCKEVENT_NEXT_TICKS[hart].load(Ordering::Acquire);
        if programmed_ticks > now_ticks && deadline_ticks >= programmed_ticks {
            // A later hrtimer request must not push out the earlier event that
            // is already programmed for this hart.
            return;
        }
    }
    RISCV_CLOCKEVENT_NEXT_TICKS[hart].store(deadline_ticks, Ordering::Release);
    crate::log_if!(
        crate::debug_config::DEBUG_TIMER,
        trace,
        "[time] hart={} riscv clockevent now={:#x} delta={:#x} deadline={:#x} force={}",
        hart,
        now_ticks,
        delta_ticks,
        deadline_ticks,
        force
    );
    set_timer(deadline_ticks);
}

#[cfg(target_arch = "loongarch64")]
fn loongarch_program_clockevent_deadline_ns(deadline_ns: u64, force: bool) {
    let hart = clockevent_hart_idx();
    let now_ns = get_time_ns();
    let deadline_ns = deadline_ns.max(now_ns.saturating_add(1));

    if !force {
        let programmed_ns =
            LOONGARCH_CLOCKEVENT_NEXT_DEADLINE_NS[hart].load(Ordering::Acquire) as u64;
        if programmed_ns > now_ns && deadline_ns >= programmed_ns {
            return;
        }
    }
    LOONGARCH_CLOCKEVENT_NEXT_DEADLINE_NS[hart].store(deadline_ns as usize, Ordering::Release);
    let desired_delta = ns_delta_to_ticks_ceil(deadline_ns.saturating_sub(now_ns).max(1));
    crate::log_if!(
        crate::debug_config::DEBUG_TIMER,
        trace,
        "[time] hart={} loongarch clockevent deadline_ns={} delta={:#x} force={}",
        hart,
        deadline_ns,
        desired_delta,
        force
    );
    set_timer(desired_delta);
}

#[cfg(target_arch = "loongarch64")]
fn loongarch_record_min_timer_dt(hart: usize, dt: usize) {
    let mut old = LOONGARCH_TIMER_MIN_DT[hart].load(Ordering::Relaxed);
    while dt < old {
        match LOONGARCH_TIMER_MIN_DT[hart].compare_exchange_weak(
            old,
            dt,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(next) => old = next,
        }
    }
}

/// Calibrate LoongArch clockevent deltas against the rdtime clocksource.
///
/// Linux treats the LoongArch constant counter and timer as one constant-rate
/// source. Under our QEMU target, writing `clock_freq / HZ` directly to TCFG is
/// measurably too slow, so keep an explicit clockevent delta and scale hrtimer
/// deadlines through it. Linux's clockevent device is per-CPU, so keep the
/// calibration per hart too. Delayed interrupt delivery can only increase an
/// observed interval, so use the minimum of a few early periodic samples.
#[cfg(target_arch = "loongarch64")]
pub fn loongarch_record_timer_tick() {
    let now: usize = read_time();
    let hart = loongarch_hart_idx();
    // swap 的返回值是该 hart 上一次 timer tick 观察到的 rdtime。
    let last: usize = LOONGARCH_TIMER_LAST_TIME[hart].swap(now, Ordering::Relaxed);
    if last == 0 {
        return;
    }
    if LOONGARCH_TIMER_CALIBRATED[hart].load(Ordering::Relaxed) {
        return;
    }
    let dt = now.saturating_sub(last);
    if dt == 0 {
        return;
    }
    loongarch_record_min_timer_dt(hart, dt);
    let samples = LOONGARCH_TIMER_SAMPLE_COUNT[hart].fetch_add(1, Ordering::Relaxed) + 1;
    if samples < LOONGARCH_TIMER_CALIBRATION_SAMPLES {
        return;
    }
    let target = loongarch_rdtime_tick_delta();
    if target == 0 {
        return;
    }
    let current = LOONGARCH_CLOCKEVENT_TICK_DELTA[hart].load(Ordering::Relaxed);
    if current == 0 {
        return;
    }
    let best_dt = LOONGARCH_TIMER_MIN_DT[hart].load(Ordering::Relaxed);
    if best_dt == 0 || best_dt == usize::MAX {
        return;
    }
    let mut new_delta = current.saturating_mul(target) / best_dt;
    if new_delta < 4 {
        new_delta = 4;
    }
    LOONGARCH_CLOCKEVENT_TICK_DELTA[hart].store(new_delta, Ordering::Relaxed);
    LOONGARCH_TIMER_CALIBRATED[hart].store(true, Ordering::Relaxed);
}
