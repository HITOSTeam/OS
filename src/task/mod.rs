#![allow(unused)]

use core::{arch::asm, cell::RefCell, fmt::Display, task};

use crate::{
    console::print,
    fs::{OpenFlags, open_file},
    println,
    task::{
        manager::{TASK_MANAGER, add_task},
        processor::{current_task, go_to_first_task},
        task_context::TaskContext,
    },
    trap::{context::TrapContext, trap::restore},
};
use alloc::sync::Arc;
use lazy_static::lazy_static;
pub mod block_sleep;
pub mod condvar;
mod id;
pub(crate) use id::{pid_max, set_pid_max};
pub mod manager;
pub mod mutex;
mod process_block;
pub(crate) use process_block::{
    MmapRegion, ProcessControlBlock, UtsNamespaceState, alloc_ipc_namespace_id,
    alloc_pid_namespace_id, pid_namespace_member_pids, process_visible_in_pid_namespace,
    register_pid_namespace, resolve_process_in_pid_namespace,
};
pub mod processor;
pub mod runtime;
pub mod sched;
pub mod semaphore;
pub mod signal;
mod switch;
pub mod task_block;
pub mod task_context;
lazy_static! {
    pub static ref INITPROC: Arc<ProcessControlBlock> = {
        let inode = open_file("/user/init_proc.bin", OpenFlags::RDONLY).unwrap();
        let data = inode.read_all();
        ProcessControlBlock::new(&data)
    };
}
pub fn task_init() {
    // Force INITPROC initialization in release builds.
    lazy_static::initialize(&INITPROC);
    crate::println!("[kernel] INITPROC initialized and enqueued");
}
pub fn task_start() {
    task_init();
    go_to_first_task();
}
/// Start scheduler on secondary harts without re-initializing initproc.
pub fn task_start_secondary() -> ! {
    go_to_first_task();
}
