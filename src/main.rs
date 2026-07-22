#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(let_chains)]
#![feature(str_from_raw_parts)]
#![allow(unreachable_code)]
use core::{arch::global_asm, panic};
extern crate alloc;
use crate::fs::list_apps;
use core::sync::atomic::{AtomicBool, Ordering};
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
    // Mark the boot hart online immediately. Secondary harts become online only
    // after they finish their own trap/timer setup and are about to enter idle.
    task::manager::mark_hart_online(boot_hart_id);
    for hart_id in 0..config::MAX_HARTS {
        if hart_id == boot_hart_id {
            continue;
        }
        //opaque是下一个核心启动的时候给他的a1寄存器放的值
        let _ = arch::hart_start(hart_id, config::KERNEL_ENTRY_PA, dtb_pa);
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
        //顺便标记第一个cpu核心已经进入到初始化阶段了
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
        task::task_start();
    } else {
        secondary_main(hart_id, dtb_pa);
    }
    panic!("shouldn't be here");
}

#[cfg(target_arch = "loongarch64")]
const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
#[cfg(target_arch = "loongarch64")]
const EFI_DEVICE_TREE_GUID: [u8; 16] = [
    0xd5, 0x21, 0xb6, 0xb1, 0x9c, 0xf1, 0xa5, 0x41, 0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0,
];

#[cfg(target_arch = "loongarch64")]
#[repr(C)]
struct EfiTableHeader {
    /// EFI system table 的固定签名，用于确认传入地址确实指向 EFI 表。
    signature: u64,
    /// EFI 规范版本。
    revision: u32,
    /// 当前表头的字节大小。
    header_size: u32,
    /// 表头的 CRC32 校验值。
    crc32: u32,
    /// EFI 规范保留字段，必须保持在结构体中以匹配 ABI 布局。
    reserved: u32,
}

#[cfg(target_arch = "loongarch64")]
#[repr(C)]
struct EfiConfigurationTable {
    /// 标识该配置表内容类型的 EFI GUID。
    vendor_guid: [u8; 16],
    /// 指向该 GUID 对应数据的启动阶段物理地址。
    vendor_table: usize,
}

#[cfg(target_arch = "loongarch64")]
#[repr(C)]
struct EfiSystemTable {
    /// EFI system table 的公共表头。
    header: EfiTableHeader,
    /// 指向固件厂商名称字符串的物理地址。
    firmware_vendor: usize,
    /// 固件实现版本。
    firmware_revision: u32,
    /// 保持后续 64 位字段对齐所需的填充。
    _firmware_revision_padding: u32,
    /// 标准输入设备句柄。
    console_in_handle: usize,
    /// 指向标准输入协议对象的地址。
    console_in: usize,
    /// 标准输出设备句柄。
    console_out_handle: usize,
    /// 指向标准输出协议对象的地址。
    console_out: usize,
    /// 标准错误输出设备句柄。
    stderr_handle: usize,
    /// 指向标准错误输出协议对象的地址。
    stderr: usize,
    /// 指向 EFI Runtime Services 表的地址。
    runtime_services: usize,
    /// 指向 EFI Boot Services 表的地址。
    boot_services: usize,
    /// configuration table 数组中的表项数量。
    number_of_table_entries: usize,
    /// 指向 EFI configuration table 数组的物理地址。
    configuration_table: *const EfiConfigurationTable,
}

#[cfg(target_arch = "loongarch64")]
/// 从 LoongArch 启动协议传入的 EFI system table 中查找 DTB 物理地址。
fn loongarch_dtb_from_efi(efi_system_table_pa: usize) -> Option<usize> {
    if efi_system_table_pa == 0 {
        return None;
    }

    // 启动协议保证 a2 指向可访问的物理 EFI system table；此时 DMW0
    // 仍提供物理地址恒等映射，因此可以在分页初始化前直接读取该表。
    let system_table = unsafe { &*(efi_system_table_pa as *const EfiSystemTable) };
    if system_table.header.signature != EFI_SYSTEM_TABLE_SIGNATURE
        || system_table.configuration_table.is_null()
    {
        return None;
    }

    for index in 0..system_table.number_of_table_entries {
        // configuration_table 指针和其中的 vendor_table 都是启动阶段物理地址。
        let entry = unsafe { &*system_table.configuration_table.add(index) };
        if entry.vendor_guid == EFI_DEVICE_TREE_GUID && entry.vendor_table != 0 {
            return Some(entry.vendor_table);
        }
    }
    None
}

#[cfg(target_arch = "loongarch64")]
#[unsafe(no_mangle)]
// 入口汇编将 hart ID 放在 a0，将 EFI system table 物理地址放在 a1。
fn rust_main(hart_id: usize, efi_system_table_pa: usize) -> ! {
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
        // DTB 是 EFI configuration table 中的一项，先按标准 GUID 查找它。
        let dtb_pa = loongarch_dtb_from_efi(efi_system_table_pa).unwrap_or(0);
        mm::init_phys_mem_from_dtb(dtb_pa);
        mm::init();
        arch::disable_direct_map_windows();
        log::init();
        trap::init_trap();
        trap::trap::enable_timer_interrupt();
        time::set_next_trigger();
        list_apps();
        task::task_start();
    }
    loop {
        core::hint::spin_loop();
    }
}
