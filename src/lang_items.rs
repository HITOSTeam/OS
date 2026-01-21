use core::panic::PanicInfo;

use crate::{arch, println};

#[panic_handler]
#[allow(unused)]
fn panic<'b>(info: &PanicInfo<'b>) -> ! {
    println!("PANIC: {}\n", info);
    arch::shutdown();
}
