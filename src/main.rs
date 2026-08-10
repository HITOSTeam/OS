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
mod sync;
mod syscall;
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
global_asm!(
    include_str!("entry_loongarch.S"),
    max_harts = const config::MAX_HARTS,
);
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

/// LoongArch CPUs publish local MMU/trap/timer readiness here before the boot
/// hart freezes the SMP membership and ELF capability intersection.
#[cfg(target_arch = "loongarch64")]
static BOOT_LOONGARCH_READY_HART_MASK: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "loongarch64")]
static BOOT_LOONGARCH_ADMITTED_HART_MASK: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "loongarch64")]
static BOOT_LOONGARCH_SMP_FINALIZED: AtomicBool = AtomicBool::new(false);

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

#[cfg(target_arch = "loongarch64")]
fn start_loongarch_secondaries(boot_hart_id: usize, present_mask: usize) {
    unsafe extern "C" {
        fn _start();
    }

    let start_addr = _start as *const () as usize;
    let boot_bit = 1usize << boot_hart_id;
    let mut started_mask = boot_bit;
    let mut failed_mask = 0usize;
    BOOT_LOONGARCH_READY_HART_MASK.store(boot_bit, Ordering::Release);
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
        let ready = BOOT_LOONGARCH_READY_HART_MASK.load(Ordering::Acquire);
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
    BOOT_LOONGARCH_ADMITTED_HART_MASK.store(ready_mask | boot_bit, Ordering::Release);
    arch::freeze_elf_hwcap();
    BOOT_LOONGARCH_SMP_FINALIZED.store(true, Ordering::Release);

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

#[cfg(target_arch = "loongarch64")]
fn loongarch_secondary_main(hart_id: usize) -> ! {
    // The boot hart publishes both barriers with Release ordering after BSS
    // clearing and global initialization. Mailbox-released CPUs pair with
    // Acquire loads before touching shared kernel state.
    while !BOOT_BSS_CLEARED.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    while !BOOT_GLOBAL_INIT_DONE.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let present_mask = BOOT_PRESENT_HART_MASK.load(Ordering::Acquire);
    if hart_id >= config::MAX_HARTS || present_mask & (1usize << hart_id) == 0 {
        loop {
            arch::wait_for_interrupt();
        }
    }

    // These registers are hart-local on LoongArch. Match Linux's CPU bring-up
    // ordering: establish local MMU state first, then interrupt sources, and
    // publish the CPU as online only after it can safely enter the scheduler.
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
    BOOT_LOONGARCH_READY_HART_MASK.fetch_or(hart_bit, Ordering::AcqRel);
    while !BOOT_LOONGARCH_SMP_FINALIZED.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    if BOOT_LOONGARCH_ADMITTED_HART_MASK.load(Ordering::Acquire) & hart_bit == 0 {
        println!(
            "[kernel] loongarch64 secondary hart {} missed SMP admission; parking",
            hart_id
        );
        loop {
            arch::wait_for_interrupt();
        }
    }
    // A hart becomes a shootdown target only after it can take IPIs. Publish
    // online first and then flush locally: a writer that sampled the old mask
    // is ordered before this final flush, while a later writer includes us.
    arch::enable_interrupts();
    task::manager::mark_hart_online(hart_id);
    crate::arch::loongarch64::mm::local_flush_tlb_all();
    crate::arch::loongarch64::memory_barrier();
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
        BOOT_BSS_CLEARED.store(true, Ordering::Release);
        // 先发布 LoongArch 的 DTB 缓存，之后的串口、关机和 PCI 路径均不再
        // 依赖固定 QEMU 地址或重新解析设备树。
        arch::loongarch64::dtb::init(crate::config::DEVICE_TREE_ADDR);
        let topology = mm::hart_topology_from_dtb(crate::config::DEVICE_TREE_ADDR, hart_id);
        BOOT_PRESENT_HART_MASK.store(topology.present_mask, Ordering::Release);
        println!(
            "[kernel] loongarch64 boot hart {}, FDT harts={} mask={:#x} ignored={}",
            hart_id, topology.discovered, topology.present_mask, topology.ignored
        );
        arch::bootstrap_init();
        mm::init_phys_mem_from_dtb(crate::config::DEVICE_TREE_ADDR);
        mm::init();
        arch::disable_direct_map_windows();
        log::init();
        trap::init_trap();
        arch::init_external_interrupts();
        trap::trap::enable_timer_interrupt();
        time::set_next_trigger();
        BOOT_GLOBAL_INIT_DONE.store(true, Ordering::Release);
        arch::enable_interrupts();
        task::manager::mark_hart_online(hart_id);
        crate::arch::loongarch64::mm::local_flush_tlb_all();
        crate::arch::loongarch64::memory_barrier();
        start_loongarch_secondaries(hart_id, topology.present_mask);
        list_apps();
        task::task_start();
    } else {
        loongarch_secondary_main(hart_id);
    }
    panic!("shouldn't be here");
}
