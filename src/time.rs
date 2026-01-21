//! RISC-V timer-related functionality

pub const CLOCK_FREQ: usize = 12500000;
use crate::arch::{read_time, set_timer};

const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;

/// read the `mtime` register
pub fn get_time() -> usize {
    read_time()
}

/// get current time in milliseconds
pub fn get_time_ms() -> usize {
    read_time() / (CLOCK_FREQ / MSEC_PER_SEC)
}

/// set the next timer interrupt
pub fn set_next_trigger() {
    let next = get_time() + CLOCK_FREQ / TICKS_PER_SEC;
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
