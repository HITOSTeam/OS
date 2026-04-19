//! Global logger

use log::{self, Level, LevelFilter, Log, Metadata, Record};

use crate::debug_config::{DEBUG_LOG_TEST, DEFAULT_LOG_LEVEL};
use crate::println;
/// a simple logger
#[allow(dead_code)]
struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let color = match record.level() {
            Level::Error => 31, // Red
            Level::Warn => 93,  // BrightYellow
            Level::Info => 34,  // Blue
            Level::Debug => 32, // Green
            Level::Trace => 90, // BrightBlack
        };

        println!(
            "\u{1B}[{}m[{:>5}] {}\u{1B}[0m",
            color,
            record.level(),
            record.args(),
        );
    }
    fn flush(&self) {}
}

/// initiate logger
#[allow(dead_code)]
pub fn init() {
    static LOGGER: SimpleLogger = SimpleLogger;
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(match option_env!("LOG") {
        Some("error") => LevelFilter::Error,
        Some("warn") => LevelFilter::Warn,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        Some("off") => LevelFilter::Off,
        _ => DEFAULT_LOG_LEVEL,
    });
    if DEBUG_LOG_TEST {
        println!(
            "[kernel] logger initialized with LOG={:?} (default={:?})",
            option_env!("LOG"),
            DEFAULT_LOG_LEVEL
        );
    }
}
#[macro_export]
macro_rules! log_if {
    ($cond:expr, $level:ident, $($arg:tt)+) => {
        if $cond {
            log::$level!($($arg)+);
        }
    };
}

#[allow(dead_code)]
pub fn test() {
    println!("[test] logging test starts");
    // from highest to lowest
    log::error!("log::error!");
    log::warn!("log::warn!");
    log::info!("log::info!");
    log::debug!("log::debug!");
    log::trace!("log::trace!");
    log_if!(true, info, "log_if! true");
    log_if!(false, info, "log_if! false");
}
