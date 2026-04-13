use alloc::string::String;
use core::any::Any;

use crate::mm::UserBuffer;

use super::{File, MountNamespace, mount_namespace_id};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceKind {
    Ipc,
    Mount,
}

impl NamespaceKind {
    pub fn clone_flag(self) -> usize {
        const CLONE_NEWNS: usize = 0x0002_0000;
        const CLONE_NEWIPC: usize = 0x0800_0000;
        match self {
            Self::Ipc => CLONE_NEWIPC,
            Self::Mount => CLONE_NEWNS,
        }
    }

    pub fn proc_name(self) -> &'static str {
        match self {
            Self::Ipc => "ipc",
            Self::Mount => "mnt",
        }
    }

    pub fn target_string(self, ns_id: usize) -> String {
        alloc::format!("{}:[{}]", self.proc_name(), ns_id)
    }

    pub fn inode_number(self, ns_id: usize) -> u64 {
        let kind_tag = match self {
            Self::Ipc => 1u64,
            Self::Mount => 2u64,
        };
        (kind_tag << 56) | (ns_id as u64)
    }
}

/// Minimal namespace descriptor exposed by `/proc/<pid>/ns/*`.
pub struct NamespaceFile {
    kind: NamespaceKind,
    ns_id: usize,
    mount_ns: Option<MountNamespace>,
}

impl NamespaceFile {
    pub fn new(kind: NamespaceKind, ns_id: usize) -> Self {
        Self {
            kind,
            ns_id,
            mount_ns: None,
        }
    }

    pub fn new_ipc(ns_id: usize) -> Self {
        Self::new(NamespaceKind::Ipc, ns_id)
    }

    pub fn new_mount(namespace: MountNamespace) -> Self {
        Self {
            kind: NamespaceKind::Mount,
            ns_id: mount_namespace_id(&namespace),
            mount_ns: Some(namespace),
        }
    }

    pub fn kind(&self) -> NamespaceKind {
        self.kind
    }

    pub fn ns_id(&self) -> usize {
        self.ns_id
    }

    pub fn target_string(&self) -> String {
        self.kind.target_string(self.ns_id)
    }

    pub fn inode_number(&self) -> u64 {
        self.kind.inode_number(self.ns_id)
    }

    pub fn mount_namespace(&self) -> Option<MountNamespace> {
        self.mount_ns.as_ref().map(alloc::sync::Arc::clone)
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
