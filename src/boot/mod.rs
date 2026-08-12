//! Architecture-neutral early-boot coordination.
//!
//! Architecture entry points own their CPU- and platform-specific ordering.
//! This module only owns state that must be shared before normal kernel
//! synchronization and allocation are available.

use core::sync::atomic::{AtomicUsize, Ordering};

mod apps;

/// Monotonic milestones published by the bootstrap hart.
///
/// This value must remain in initialized data: secondary harts can execute
/// while the bootstrap hart is clearing BSS, so storing it in BSS would reset
/// an already claimed boot-hart election.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub(crate) enum BootPhase {
    Cold = 0,
    BootHartClaimed = 1,
    BssCleared = 2,
    GlobalReady = 3,
}

#[unsafe(link_section = ".data.boot")]
static BOOT_PHASE: AtomicUsize = AtomicUsize::new(BootPhase::Cold as usize);

// The bootstrap hart writes this after clearing BSS and before publishing
// GlobalReady. Secondary harts read it only after crossing that phase barrier.
static PRESENT_HART_MASK: AtomicUsize = AtomicUsize::new(0);

/// Elect exactly one bootstrap hart without touching BSS-backed state.
pub(crate) fn claim_boot_hart() -> bool {
    BOOT_PHASE
        .compare_exchange(
            BootPhase::Cold as usize,
            BootPhase::BootHartClaimed as usize,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok()
}

/// Clear BSS and publish the first point at which BSS-backed globals are safe.
pub(crate) fn clear_bss_and_publish() {
    unsafe extern "C" {
        safe fn sbss();
        safe fn ebss();
    }

    unsafe {
        let bss_start = sbss as *const () as usize;
        let bss_end = ebss as *const () as usize;
        let bss_size = bss_end - bss_start;
        core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size);
    }
    publish_phase(BootPhase::BssCleared);
}

/// Publish the physical hart set discovered by the bootstrap hart.
pub(crate) fn publish_present_harts(mask: usize) {
    PRESENT_HART_MASK.store(mask, Ordering::Release);
}

pub(crate) fn present_harts() -> usize {
    PRESENT_HART_MASK.load(Ordering::Acquire)
}

/// Release secondary harts after global kernel initialization is complete.
pub(crate) fn publish_global_ready() {
    publish_phase(BootPhase::GlobalReady);
}

pub(crate) fn wait_for(phase: BootPhase) {
    while BOOT_PHASE.load(Ordering::SeqCst) < phase as usize {
        core::hint::spin_loop();
    }
}

fn publish_phase(phase: BootPhase) {
    BOOT_PHASE.store(phase as usize, Ordering::SeqCst);
}
