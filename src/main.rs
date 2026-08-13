#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
// 决赛镜像的 nightly-2025-01-18 仍要求显式启用 let-chain，
// 内核中的条件匹配依赖该语法以保持原有的短路求值语义。
#![feature(let_chains)]
// 该 nightly 已提供整数对齐判断接口，但尚未稳定，需显式开启。
#![feature(unsigned_is_multiple_of)]
// LoongArch 的 LSX 上下文保存函数使用 target_feature，旧 nightly 需显式开启。
#![feature(loongarch_target_feature)]
#![allow(unreachable_code)]
use core::{arch::global_asm, panic};
extern crate alloc;
use crate::fs::list_apps;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
// 这些模块同时承载不同架构、文件系统选项与诊断功能；final 配置不会调用其中
// 所有公开接口，保留接口以支持其它评测组合，因此只在这些可选子系统内忽略死代码。
#[allow(dead_code)]
mod arch;
mod bpf;
#[allow(dead_code)]
mod config;
mod console;
mod debug_config;
#[allow(dead_code)]
mod drivers;
#[allow(dead_code)]
mod fs;
mod klog;
mod lang_items;
mod log;
#[allow(dead_code)]
mod mm;
mod net;
#[allow(dead_code)]
mod perf;
#[cfg(target_arch = "riscv64")]
mod sbi;
#[allow(dead_code)]
mod sync;
#[allow(dead_code)]
mod syscall;
mod task;
mod time;
#[allow(dead_code)]
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
        let bss_start = sbss as *const () as usize;
        let bss_end = ebss as *const () as usize;
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
        // VisionFive 2 固件把 hart1 作为启动核；当前 OpenSBI 版本无法使 hart0
        // 从 S-mode 入口稳定返回，跳过它以保证其余从核和用户态测试正常运行。
        #[cfg(feature = "visionfive2")]
        if hart_id == 0 {
            failed_mask |= hart_bit;
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
    // VisionFive 2 尚未接入 JH7110 PLIC，不能让从核访问 QEMU 的 PLIC 寄存器布局。
    #[cfg(not(feature = "visionfive2"))]
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
            num_of_apps, num_user_apps as *const () as usize
        );
        println!(
            "[kernel] bootstrap hart {} starting with dtb @ {:#x}",
            hart_id, dtb_pa
        );
        // 一次性复制 DTB 中的 CPU、内存、保留区和设备信息；后续启动路径只
        // 查询这份固定缓存，绝不重新遍历固件提供的设备树。
        arch::riscv64::dtb::init(dtb_pa, hart_id);
        arch::bootstrap_init();
        let topology = mm::hart_topology_from_dtb();
        BOOT_PRESENT_HART_MASK.store(topology.present_mask, Ordering::Release);
        println!(
            "[kernel] riscv64 boot hart {}, FDT harts={} mask={:#x} ignored={}",
            hart_id, topology.discovered, topology.present_mask, topology.ignored
        );
        mm::init();
        arch::mm::init_asid_allocator(topology.present_mask);
        mm::remap_test();
        log::init();
        // 星光 VisionFive 2 的 SDIO 启动路径仅使用轮询。通用 RISC-V 外部中断
        // 代码目前使用 QEMU PLIC 寄存器布局；在实现 JH7110 PLIC 驱动前不访问它。
        #[cfg(not(feature = "visionfive2"))]
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
fn rust_main(hart_id: usize, efi_system_table_pa: usize) -> ! {
    arch::set_tp(hart_id);
    let _ = arch::disable_interrupts();
    if BOOT_HART_INITED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        clear_bss();
        BOOT_BSS_CLEARED.store(true, Ordering::Release);
        let dtb_pa = arch::loongarch64::efi::dtb_address(efi_system_table_pa)
            .expect("LoongArch EFI configuration table has no device-tree pointer");
        // 先发布从 EFI 配置表定位的 DTB 缓存，之后的串口、关机、PCI 和内存
        // 路径均不再依赖固定 QEMU 地址或重新解析设备树。
        arch::loongarch64::dtb::init(dtb_pa, hart_id);
        let topology = mm::hart_topology_from_dtb();
        BOOT_PRESENT_HART_MASK.store(topology.present_mask, Ordering::Release);
        println!(
            "[kernel] loongarch64 boot hart {}, FDT harts={} mask={:#x} ignored={}",
            hart_id, topology.discovered, topology.present_mask, topology.ignored
        );
        arch::bootstrap_init();
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
