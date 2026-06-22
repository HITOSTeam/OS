use core::any::Any;

use crate::mm::UserBuffer;

use super::File;

/// A minimal no-op file for stubbed syscalls.
pub struct DummyFile {
    readable: bool,
    writable: bool,
}

impl DummyFile {
    pub fn new(readable: bool, writable: bool) -> Self {
        Self { readable, writable }
    }
}

impl File for DummyFile {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, buf: UserBuffer) -> usize {
        buf.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Minimal signalfd placeholder.
///
/// It deliberately does not report readable readiness until the real signal
/// queue is wired in; Linux signalfd only becomes readable for pending signals.
pub struct SignalfdFile;

impl SignalfdFile {
    pub fn new() -> Self {
        Self
    }
}

impl File for SignalfdFile {
    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn poll_mask(&self) -> i16 {
        0
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
