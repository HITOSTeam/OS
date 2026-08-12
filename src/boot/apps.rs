//! Build-generated userspace application manifest linked into the kernel.

use core::arch::global_asm;

global_asm!(include_str!("../link_app.asm"));
