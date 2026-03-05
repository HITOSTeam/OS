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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceKind {
    Ipc,
}

impl NamespaceKind {
    pub fn clone_flag(self) -> usize {
        const CLONE_NEWIPC: usize = 0x0800_0000;
        match self {
            Self::Ipc => CLONE_NEWIPC,
        }
    }
}

/// Minimal namespace descriptor exposed by `/proc/<pid>/ns/*`.
pub struct NamespaceFile {
    kind: NamespaceKind,
    ns_id: usize,
}

impl NamespaceFile {
    pub fn new(kind: NamespaceKind, ns_id: usize) -> Self {
        Self { kind, ns_id }
    }

    pub fn new_ipc(ns_id: usize) -> Self {
        Self::new(NamespaceKind::Ipc, ns_id)
    }

    pub fn kind(&self) -> NamespaceKind {
        self.kind
    }

    pub fn ns_id(&self) -> usize {
        self.ns_id
    }
}

impl File for NamespaceFile {
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// pidfd object used by `pidfd_open(2)` and `waitid(P_PIDFD, ...)`.
pub struct PidFdFile {
    target_pid: usize,
}

impl PidFdFile {
    pub fn new(target_pid: usize) -> Self {
        Self { target_pid }
    }

    pub fn target_pid(&self) -> usize {
        self.target_pid
    }
}

impl File for PidFdFile {
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}
