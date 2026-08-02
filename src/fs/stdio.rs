//!Stdin & Stdout
use super::File;
#[cfg(target_arch = "loongarch64")]
use crate::arch::console_flush;
use crate::arch::{console_getchar, console_putchar};
use crate::mm::UserBuffer;
use crate::sync::{KernelMutex, KernelMutexGuard};
use crate::task::processor::suspend_current_and_run_next;
///Standard input
pub struct Stdin;
///Standard output
pub struct Stdout;

// Linux takes tty_write_lock() before importing the userspace iterator. Keep
// the same lifetime boundary: syscall_write acquires this sleepable lock before
// translating user pages, then holds it through the complete terminal write.
static STDOUT_WRITE_LOCK: KernelMutex<()> = KernelMutex::new(());

impl Stdout {
    pub fn lock_write(nonblock: bool) -> Option<KernelMutexGuard<'static, ()>> {
        if nonblock {
            STDOUT_WRITE_LOCK.try_lock()
        } else {
            Some(STDOUT_WRITE_LOCK.lock())
        }
    }
}

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
        while written < user_buf.len() {
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
            let byte = [c as u8];
            if user_buf.copy_from_slice_at(written, &byte) != 1 {
                break;
            }
            written += 1;
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
        let bytes = user_buf.to_vec();
        #[cfg(target_arch = "loongarch64")]
        {
            let flush_threshold = crate::arch::UART_FIFO_DEPTH.saturating_sub(2).max(4);
            let mut pending = 0usize;
            let mut total = 0usize;
            for &b in &bytes {
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
            if pending != 0 {
                let start = crate::perf::uart_flush_begin();
                console_flush();
                crate::perf::uart_flush_end(start);
            }
            crate::perf::record_uart_bytes(total);
        }
        #[cfg(not(target_arch = "loongarch64"))]
        {
            for &b in &bytes {
                console_putchar(b as usize);
            }
        }
        bytes.len()
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
