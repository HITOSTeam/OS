//! Full LoongArch kernel bring-up shared by QEMU and LS2K1000LA.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::boot::{self, BootPhase};
use crate::fs::list_apps;
use crate::println;
use crate::{arch, config, log, mm, task, time, trap};

/// CPUs publish local MMU/trap/timer readiness before the bootstrap hart
/// freezes the SMP membership and ELF capability intersection.
static READY_HART_MASK: AtomicUsize = AtomicUsize::new(0);
static ADMITTED_HART_MASK: AtomicUsize = AtomicUsize::new(0);
static SMP_FINALIZED: AtomicBool = AtomicBool::new(false);

fn start_secondaries(boot_hart_id: usize, present_mask: usize) {
    unsafe extern "C" {
        fn _start();
    }

    let start_addr = _start as *const () as usize;
    let boot_bit = 1usize << boot_hart_id;
    let mut started_mask = boot_bit;
    let mut failed_mask = 0usize;
    READY_HART_MASK.store(boot_bit, Ordering::Release);
    for hart_id in 0..config::MAX_HARTS {
        let hart_bit = 1usize << hart_id;
        if hart_id == boot_hart_id || present_mask & hart_bit == 0 {
            continue;
        }
        let error = arch::hart_start(hart_id, start_addr, 0);
        if error != 0 {
            println!(
                "[kernel] failed to start LoongArch hart {}: error={}",
                hart_id, error
            );
            failed_mask |= hart_bit;
            continue;
        }
        started_mask |= hart_bit;
    }

    let started_at = arch::read_time();
    let timeout_ticks = config::clock_freq().saturating_mul(5);
    let ready_mask = loop {
        let ready = READY_HART_MASK.load(Ordering::Acquire);
        if ready & started_mask == started_mask {
            break ready & started_mask;
        }
        if arch::read_time().wrapping_sub(started_at) >= timeout_ticks {
            println!(
                "[kernel] loongarch64 SMP readiness timeout: present={:#x} started={:#x} ready={:#x} missing={:#x} failed={:#x}",
                present_mask,
                started_mask,
                ready,
                started_mask & !ready,
                failed_mask
            );
            break ready & started_mask;
        }
        core::hint::spin_loop();
    };

    // Freeze both the admitted CPU set and AT_HWCAP before creating the first
    // user process. A CPU that becomes ready after this point remains parked.
    ADMITTED_HART_MASK.store(ready_mask | boot_bit, Ordering::Release);
    arch::freeze_elf_hwcap();
    SMP_FINALIZED.store(true, Ordering::Release);

    let online_started_at = arch::read_time();
    loop {
        let online = task::manager::online_hart_mask();
        if online & ready_mask == ready_mask {
            println!(
                "[kernel] loongarch64 SMP online mask {:#x} ({} harts), failed={:#x}",
                online & present_mask,
                (online & present_mask).count_ones(),
                failed_mask
            );
            return;
        }
        if arch::read_time().wrapping_sub(online_started_at) >= timeout_ticks {
            println!(
                "[kernel] loongarch64 SMP online timeout: admitted={:#x} online={:#x} missing={:#x}",
                ready_mask,
                online,
                ready_mask & !online
            );
            return;
        }
        core::hint::spin_loop();
    }
}

fn secondary_main(hart_id: usize) -> ! {
    // The phase word is initialized data. Crossing both milestones pairs with
    // the bootstrap hart before this CPU touches BSS-backed kernel state.
    boot::wait_for(BootPhase::BssCleared);
    boot::wait_for(BootPhase::GlobalReady);

    let present_mask = boot::present_harts();
    if hart_id >= config::MAX_HARTS || present_mask & (1usize << hart_id) == 0 {
        loop {
            arch::wait_for_interrupt();
        }
    }

    // These registers are hart-local on LoongArch. Establish local MMU state
    // and interrupt sources before publishing readiness.
    arch::bootstrap_init();
    mm::activate_kernel_space();
    arch::disable_direct_map_windows();
    trap::init_trap();
    arch::init_external_interrupts();
    trap::trap::enable_timer_interrupt();
    time::set_next_trigger();
    println!(
        "[kernel] loongarch64 secondary hart {} ready, entering scheduler...",
        hart_id
    );
    let hart_bit = 1usize << hart_id;
    READY_HART_MASK.fetch_or(hart_bit, Ordering::AcqRel);
    while !SMP_FINALIZED.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    if ADMITTED_HART_MASK.load(Ordering::Acquire) & hart_bit == 0 {
        println!(
            "[kernel] loongarch64 secondary hart {} missed SMP admission; parking",
            hart_id
        );
        loop {
            arch::wait_for_interrupt();
        }
    }

    // A hart becomes a shootdown target only after it can take IPIs. Publish
    // online first and then flush locally so later writers include this CPU.
    arch::enable_interrupts();
    task::manager::mark_hart_online(hart_id);
    crate::arch::loongarch64::mm::local_flush_tlb_all();
    crate::arch::loongarch64::memory_barrier();
    task::task_start_secondary();
}

pub(super) fn start(hart_id: usize, firmware_args: Option<[usize; 4]>) -> ! {
    arch::set_tp(hart_id);
    let _ = arch::disable_interrupts();
    if boot::claim_boot_hart() {
        boot::clear_bss_and_publish();
        if let Some([a0, a1, a2, a3]) = firmware_args {
            println!(
                "[kernel] LS2K1000LA U-Boot args: a0={:#x} a1={:#x} a2={:#x} a3={:#x}",
                a0, a1, a2, a3
            );
        }
        let dtb_pa = config::DEVICE_TREE_ADDR;
        let topology = mm::hart_topology_from_dtb(dtb_pa, hart_id);
        boot::publish_present_harts(topology.present_mask);
        println!(
            "[kernel] loongarch64 boot hart {}, FDT harts={} mask={:#x} ignored={}",
            hart_id, topology.discovered, topology.present_mask, topology.ignored
        );
        arch::bootstrap_init();
        mm::init_phys_mem_from_dtb(dtb_pa);
        mm::init();
        arch::disable_direct_map_windows();
        log::init();
        trap::init_trap();
        arch::init_external_interrupts();
        trap::trap::enable_timer_interrupt();
        time::set_next_trigger();
        boot::publish_global_ready();
        arch::enable_interrupts();
        task::manager::mark_hart_online(hart_id);
        crate::arch::loongarch64::mm::local_flush_tlb_all();
        crate::arch::loongarch64::memory_barrier();
        start_secondaries(hart_id, topology.present_mask);
        list_apps();
        task::task_start();
    } else {
        secondary_main(hart_id);
    }
    panic!("shouldn't be here");
}
