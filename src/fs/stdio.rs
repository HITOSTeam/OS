//!Stdin & Stdout
use super::File;
use crate::mm::UserBuffer;
use crate::arch::{console_flush, console_getchar, console_putchar};
use crate::task::processor::suspend_current_and_run_next;
///Standard input
pub struct Stdin;
///Standard output
pub struct Stdout;

impl File for Stdin {
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        false
    }
    fn read(&self, mut user_buf: UserBuffer) -> usize {
        if user_buf.len() == 0 {
            return 0;
        }
        let mut written = 0usize;
        for slice in user_buf.buffers.iter_mut() {
            for b in slice.iter_mut() {
                let c = loop {
                    let c = console_getchar();
                    // OpenSBI returns `usize::MAX` when no input is available.
                    // Some environments may return 0; treat both as "no data".
                    if c == 0 || c == usize::MAX {
                        if written == 0 {
                            suspend_current_and_run_next();
                            continue;
                        } else {
                            return written;
                        }
                    }
                    break c;
                };
                *b = c as u8;
                written += 1;
            }
        }
        written
    }
    fn write(&self, _user_buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl File for Stdout {
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        true
    }
    fn read(&self, _user_buf: UserBuffer) -> usize {
        0
    }
    fn write(&self, user_buf: UserBuffer) -> usize {
        #[cfg(target_arch = "loongarch64")]
        {
            let flush_threshold = crate::arch::UART_FIFO_DEPTH.saturating_sub(2).max(4);
            let mut pending = 0usize;
            let mut total = 0usize;
            for buffer in user_buf.buffers.iter() {
                for &b in buffer.iter() {
                    console_putchar(b as usize);
                    pending += 1;
                    total += 1;
                    if pending >= flush_threshold {
                        let start = crate::perf::uart_flush_begin();
                        console_flush();
                        crate::perf::uart_flush_end(start);
                        pending = 0;
                    }
                }
            }
            if pending != 0 {
                let start = crate::perf::uart_flush_begin();
                console_flush();
                crate::perf::uart_flush_end(start);
            }
            crate::perf::record_uart_bytes(total);
        }
        #[cfg(not(target_arch = "loongarch64"))]
        {
            for buffer in user_buf.buffers.iter() {
                for &b in buffer.iter() {
                    console_putchar(b as usize);
                }
            }
        }
        user_buf.len()
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
