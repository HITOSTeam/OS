#![no_std]
#![feature(alloc_error_handler)]
#![feature(str_from_raw_parts)]
pub mod utils;
extern crate alloc;
mod config;
mod arch;
mod console;
pub mod debug_config;
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
