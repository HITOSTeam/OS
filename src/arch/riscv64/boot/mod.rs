//! RISC-V entry and SMP startup.

use core::arch::global_asm;

use crate::boot::{self, BootPhase};
use crate::fs::list_apps;
use crate::println;
use crate::{arch, config, debug_config, log, mm, task, time, trap};

global_asm!(
    include_str!("entry.S"),
    max_harts = const config::MAX_HARTS,
);

fn start_other_harts(boot_hart_id: usize, dtb_pa: usize, present_mask: usize) {
    // Mark the boot hart online immediately. Secondary harts become online only
    // after they finish their own trap/timer setup and are about to enter idle.
    task::manager::mark_hart_online(boot_hart_id);
    let mut started_mask = 1usize << boot_hart_id;
    let mut failed_mask = 0usize;
    for hart_id in 0..config::MAX_HARTS {
        let hart_bit = 1usize << hart_id;
        if hart_id == boot_hart_id || present_mask & hart_bit == 0 {
            continue;
        }
        let error = arch::hart_start(hart_id, config::KERNEL_ENTRY_PA, dtb_pa);
        if error != 0 {
            println!(
                "[kernel] failed to start hart {} via SBI HSM: error={}",
                hart_id, error as isize
            );
            failed_mask |= hart_bit;
            continue;
        }
        started_mask |= hart_bit;
    }

    let started_at = arch::read_time();
    let timeout_ticks = config::clock_freq().saturating_mul(5);
    loop {
        let online = task::manager::online_hart_mask();
        if online & started_mask == started_mask {
            println!(
                "[kernel] riscv64 SMP online mask {:#x} ({} harts), failed={:#x}",
                online & present_mask,
                (online & present_mask).count_ones(),
                failed_mask
            );
            return;
        }
        if arch::read_time().wrapping_sub(started_at) >= timeout_ticks {
            println!(
                "[kernel] riscv64 SMP startup timeout: present={:#x} started={:#x} online={:#x} missing={:#x} failed={:#x}",
                present_mask,
                started_mask,
                online,
                started_mask & !online,
                failed_mask
            );
            return;
        }
        core::hint::spin_loop();
    }
}

fn secondary_main(hart_id: usize, dtb_pa: usize) -> ! {
    // The phase word lives in initialized data, so it is safe to read before
    // BSS has been cleared. Cross both milestones before using shared globals.
    boot::wait_for(BootPhase::BssCleared);
    boot::wait_for(BootPhase::GlobalReady);

    let present_mask = boot::present_harts();
    if hart_id >= config::MAX_HARTS || present_mask & (1usize << hart_id) == 0 {
        loop {
            arch::wait_for_interrupt();
        }
    }

    // Activate the page table built by the boot hart so we can safely run in S-mode.
    mm::activate_kernel_space();
    arch::init_secondary_mmu_state();
    trap::init_trap();
    arch::init_external_interrupts();
    trap::trap::enable_timer_interrupt();
    time::set_next_trigger();
    println!(
        "[kernel] secondary hart {} online (dtb_pa={:#x}), entering scheduler...",
        hart_id, dtb_pa
    );
    task::manager::mark_hart_online(hart_id);
    task::task_start_secondary();
}

#[unsafe(no_mangle)]
fn rust_main(hart_id: usize, dtb_pa: usize) -> ! {
    // Avoid timer interrupts preempting early-boot code that may hold spin
    // locks. Scheduler and user-return paths enable interrupts later.
    let _ = arch::disable_interrupts();

    unsafe extern "C" {
        fn num_user_apps();
    }

    if boot::claim_boot_hart() {
        boot::clear_bss_and_publish();
        let num_of_apps = unsafe { *(num_user_apps as *const i64) };
        println!(
            "Number of user apps: {}, from address {:#x}",
            num_of_apps, num_user_apps as *const () as usize
        );
        println!(
            "[kernel] bootstrap hart {} starting with dtb @ {:#x}",
            hart_id, dtb_pa
        );
        arch::bootstrap_init(dtb_pa);
        let topology = mm::hart_topology_from_dtb(dtb_pa, hart_id);
        boot::publish_present_harts(topology.present_mask);
        println!(
            "[kernel] riscv64 boot hart {}, FDT harts={} mask={:#x} ignored={}",
            hart_id, topology.discovered, topology.present_mask, topology.ignored
        );
        mm::init_phys_mem_from_dtb(dtb_pa);
        mm::init();
        arch::mm::init_asid_allocator(topology.present_mask);
        mm::remap_test();
        log::init();
        arch::init_external_interrupts();
        if debug_config::DEBUG_LOG_TEST {
            log::test();
        }
        println!("[kernel] memory management initialized.");
        boot::publish_global_ready();
        start_other_harts(hart_id, dtb_pa, topology.present_mask);
        trap::init_trap();
        trap::trap::enable_timer_interrupt();
        time::set_next_trigger();
        list_apps();
        task::task_start();
    } else {
        secondary_main(hart_id, dtb_pa);
    }
    panic!("shouldn't be here");
}
