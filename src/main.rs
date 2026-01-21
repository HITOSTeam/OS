#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(str_from_raw_parts)]
#![allow(unreachable_code)]
use core::{arch::global_asm, panic};
extern crate alloc;
use crate::fs::list_apps;
use core::sync::atomic::{AtomicBool, Ordering};
mod config;
mod arch;
mod console;
mod debug_config;
mod drivers;
mod fs;
mod klog;
mod lang_items;
mod log;
mod mm;
mod net;
mod sbi;
mod syscall;
mod task;
mod time;
mod trap;
mod utils;

#[cfg(target_arch = "riscv64")]
global_asm!(include_str!("entry.asm"));
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

#[cfg(target_arch = "riscv64")]
fn start_other_harts(boot_hart_id: usize, dtb_pa: usize) {
    // Mark boot hart online; secondary harts will be marked online after successful HSM start.
    task::manager::mark_hart_online(boot_hart_id);
    for hart_id in 0..config::MAX_HARTS {
        if hart_id == boot_hart_id {
            continue;
        }
        // Only consider harts that OpenSBI successfully started as online.
        if arch::hart_start(hart_id, config::KERNEL_ENTRY_PA, dtb_pa) == 0 {
            task::manager::mark_hart_online(hart_id);
        }
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
    // Activate the page table built by the boot hart so we can safely run in S-mode.
    mm::activate_kernel_space();
    trap::init_trap();
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
        mm::init_phys_mem_from_dtb(dtb_pa);
        mm::init();
        mm::remap_test();
        log::init();
        if debug_config::DEBUG_LOG_TEST {
            log::test();
        }
        println!("[kernel] memory management initialized.");
        BOOT_GLOBAL_INIT_DONE.store(true, Ordering::SeqCst);
        start_other_harts(hart_id, dtb_pa);
        trap::init_trap();
        trap::trap::enable_timer_interrupt();
        time::set_next_trigger();
        list_apps();
        fs::init_procfs();
        task::task_start();
    } else {
        secondary_main(hart_id, dtb_pa);
    }
    panic!("shouldn't be here");
}

#[cfg(target_arch = "loongarch64")]
#[unsafe(no_mangle)]
fn rust_main(hart_id: usize) -> ! {
    if BOOT_HART_INITED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        clear_bss();
        BOOT_BSS_CLEARED.store(true, Ordering::SeqCst);
        println!("[kernel] loongarch64 boot hart {}", hart_id);
    }
    loop {
        core::hint::spin_loop();
    }
}
