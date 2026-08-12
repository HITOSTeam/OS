#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(str_from_raw_parts)]
#![allow(unreachable_code)]

extern crate alloc;

mod arch;
mod boot;
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
