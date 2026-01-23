//! Centralized debug switches.
//!
//! Keep these `false` for normal runs. Flip to `false` temporarily when diagnosing
//! hangs or scheduler/timer issues.

/// Default kernel log level when `LOG` is not set at build time.
///
/// You can override it by building with `LOG=error|warn|info|debug|trace`.
pub const DEFAULT_LOG_LEVEL: log::LevelFilter = if DEBUG_UNIXBENCH {
    log::LevelFilter::Info
} else {
    log::LevelFilter::Warn
};

/// Verbose timer debug logs (sleep timers, expiration, wakeups).
pub const DEBUG_TIMER: bool = false;

/// Verbose scheduler debug logs (ready queue push/pop, idle switches).
pub const DEBUG_SCHED: bool = true;

/// Verbose trap logs (timer/software interrupts, user exceptions).
pub const DEBUG_TRAP: bool = true;

/// Verbose syscall trace (very noisy).
pub const DEBUG_SYSCALL: bool = false;

/// Targeted execve/path resolution logs (useful for busybox/OSComp scripts).
pub const DEBUG_EXEC: bool = true;

/// Verbose pthread/clone lifecycle logs.
pub const DEBUG_PTHREAD: bool = false;

/// Verbose futex wait/wake logs.
pub const DEBUG_FUTEX: bool = false;

/// Verbose filesystem debug logs (open/getdents/lseek).
pub const DEBUG_FS: bool = false;

/// Track iozone file I/O (inode, offsets, flushes).
pub const DEBUG_IOZONE_FS: bool = false;

/// Verbose network debug logs (socket send/recv).
pub const DEBUG_NET: bool = false;

/// Targeted logs for UnixBench hangs (alarm/pipe/signal).
pub const DEBUG_UNIXBENCH: bool = false;

/// Targeted logs for cyclictest hangs (clock_nanosleep/affinity/sleep).
pub const DEBUG_CYCLICTEST: bool = false;

/// Print a periodic diagnostic dump when the system has no runnable tasks.
pub const DEBUG_WATCHDOG: bool = true;

/// Run `log::test()` at boot (very noisy).
pub const DEBUG_LOG_TEST: bool = false;
