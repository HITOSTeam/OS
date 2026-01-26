use crate::arch::{console_flush, console_putchar, disable_interrupts, restore_interrupts};
use core::fmt::{self, Write};
use spin::Mutex;

struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Record raw bytes into the kernel log buffer for `dmesg`.
        // Keep `\n` as-is (UART will translate to CRLF separately).
        crate::klog::append_str(s);
        #[cfg(target_arch = "loongarch64")]
        {
            let mut pending = 0usize;
            for c in s.chars() {
                // QEMU's UART expects CRLF for proper newlines.
                if c == '\n' {
                    console_putchar('\r' as usize);
                    pending += 1;
                }
                console_putchar(c as usize);
                pending += 1;
                if pending >= 4 {
                    console_flush();
                    pending = 0;
                }
            }
            if pending != 0 {
                console_flush();
            }
            return Ok(());
        }
        #[cfg(not(target_arch = "loongarch64"))]
        {
            for c in s.chars() {
                // QEMU's UART expects CRLF for proper newlines.
                if c == '\n' {
                    console_putchar('\r' as usize);
                }
                console_putchar(c as usize);
            }
            Ok(())
        }
    }
}

static CONSOLE_LOCK: Mutex<()> = Mutex::new(());

pub fn print(args: fmt::Arguments) {
    // Make console output readable under SMP:
    // - Serialize writers across harts.
    // - Disable interrupts to avoid deadlocking on re-entrant printing (e.g. timer IRQ).
    let prev_sie = disable_interrupts();
    {
        let _guard = CONSOLE_LOCK.lock();
        Stdout.write_fmt(args).unwrap();
    }
    restore_interrupts(prev_sie);
}

#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
