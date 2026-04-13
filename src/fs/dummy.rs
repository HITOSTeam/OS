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
