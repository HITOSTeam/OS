//! Minimal eBPF support.
//!
//! This module follows Linux's broad split: UAPI-compatible layouts live in
//! `uapi`, kernel-visible handles are re-exported here, and syscall/runtime
//! details stay in private implementation modules.

mod map;
mod prog;
mod runtime;
mod syscall;
mod uapi;
mod verifier;

use crate::syscall::error::SyscallError;

type BpfResult<T> = Result<T, SyscallError>;

pub use prog::BpfProgFile;
pub use syscall::{get_prog_clone, syscall_bpf};
