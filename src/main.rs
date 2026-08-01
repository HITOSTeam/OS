#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(str_from_raw_parts)]
#![allow(unreachable_code)]
use core::{arch::global_asm, panic};
extern crate alloc;
use crate::fs::list_apps;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
mod arch;
mod bpf;
mod config;
mod console;
mod debug_config;
mod drivers;
mod fs;
mod klog;
mod lang_items;
mod log;
mod mm;
mod net;
mod perf;
#[cfg(target_arch = "riscv64")]
mod sbi;
mod syscall;
mod sync;
mod task;
mod time;
mod trap;
mod utils;

#[cfg(target_arch = "riscv64")]
global_asm!(
    include_str!("entry.asm"),
    max_harts = const config::MAX_HARTS,
);
#[cfg(target_arch = "loongarch64")]
global_asm!(include_str!("entry_loongarch.S"));
global_asm!(include_str!("link_app.asm"));

// Keep this flag in .data so clearing .bss doesn't reset it after the
// bootstrap hart marks initialization as done.
#[unsafe(link_section = ".data")]
static BOOT_HART_INITED: AtomicBool = AtomicBool::new(false);
// Secondary harts must not touch .bss-backed globals before the boot hart clears .bss.
#[unsafe(link_section = ".data")]
static BOOT_BSS_CLEARED: AtomicBool = AtomicBool::new(false);
// Secondary harts must not enter the scheduler before the boot hart finishes global init.
#[unsafe(link_section = ".data")]
static BOOT_GLOBAL_INIT_DONE: AtomicBool = AtomicBool::new(false);
// QEMU's FDT-derived physical-hart mask.  It is published before the global
// init barrier releases secondary harts.
static BOOT_PRESENT_HART_MASK: AtomicUsize = AtomicUsize::new(0);

fn clear_bss() {
    unsafe extern "C" {
        safe fn sbss();
        safe fn ebss();
    }
    unsafe {
        let bss_start = sbss as usize;
        let bss_end = ebss as usize;
        let bss_size = bss_end - bss_start;
        core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size);
    }
}

// boot hart will run this
#[cfg(target_arch = "riscv64")]
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

#[cfg(target_arch = "riscv64")]
fn secondary_main(hart_id: usize, dtb_pa: usize) -> ! {
    // Wait until the boot hart clears .bss and completes global initialization.
    while !BOOT_BSS_CLEARED.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }
    while !BOOT_GLOBAL_INIT_DONE.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }
    let present_mask = BOOT_PRESENT_HART_MASK.load(Ordering::Acquire);
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

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
fn rust_main(hart_id: usize, dtb_pa: usize) -> ! {
    // Avoid timer interrupts preempting early-boot code that may hold spin::Mutex locks
    // (e.g., heap allocator, ext4, ready queue). We'll re-enable interrupts in the
    // scheduler/idle loop and on sret back to user.
    let _ = arch::disable_interrupts();

    unsafe extern "C" {
        fn num_user_apps();
    }
    if BOOT_HART_INITED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        clear_bss();
        BOOT_BSS_CLEARED.store(true, Ordering::SeqCst);
        let num_of_apps = unsafe { *(num_user_apps as *const i64) };
        println!(
            "Number of user apps: {}, from adress {}",
            num_of_apps, num_user_apps as usize
        );
        println!(
            "[kernel] bootstrap hart {} starting with dtb @ {:#x}",
            hart_id, dtb_pa
        );
        arch::bootstrap_init(dtb_pa);
        let topology = mm::hart_topology_from_dtb(dtb_pa, hart_id);
        BOOT_PRESENT_HART_MASK.store(topology.present_mask, Ordering::Release);
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
        BOOT_GLOBAL_INIT_DONE.store(true, Ordering::SeqCst);
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

#[cfg(target_arch = "loongarch64")]
#[unsafe(no_mangle)]
fn rust_main(hart_id: usize) -> ! {
    arch::set_tp(hart_id);
    let _ = arch::disable_interrupts();
    if BOOT_HART_INITED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        clear_bss();
        BOOT_BSS_CLEARED.store(true, Ordering::SeqCst);
        // Ensure the boot hart is marked online so tasks stay on the running hart.
        task::manager::mark_hart_online(hart_id);
        println!("[kernel] loongarch64 boot hart {}", hart_id);
        arch::bootstrap_init();
        mm::init_phys_mem_from_dtb(crate::config::DEVICE_TREE_ADDR);
        mm::init();
        arch::disable_direct_map_windows();
        log::init();
        trap::init_trap();
        arch::init_external_interrupts();
        trap::trap::enable_timer_interrupt();
        time::set_next_trigger();
        list_apps();
        task::task_start();
    }
    loop {
        core::hint::spin_loop();
    }
}
