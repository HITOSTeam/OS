use alloc::collections::BTreeMap;
use alloc::string::String;
use core::any::Any;

use crate::mm::UserBuffer;

use super::{File, MountNamespace, mount_namespace_id};
use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {
    static ref NET_NAMESPACE_FILE_REFS: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceKind {
    Ipc,
    Mount,
    Net,
}

impl NamespaceKind {
    pub fn clone_flag(self) -> usize {
        const CLONE_NEWNS: usize = 0x0002_0000;
        const CLONE_NEWIPC: usize = 0x0800_0000;
        const CLONE_NEWNET: usize = 0x4000_0000;
        match self {
            Self::Ipc => CLONE_NEWIPC,
            Self::Mount => CLONE_NEWNS,
            Self::Net => CLONE_NEWNET,
        }
    }

    pub fn proc_name(self) -> &'static str {
        match self {
            Self::Ipc => "ipc",
            Self::Mount => "mnt",
            Self::Net => "net",
        }
    }

    pub fn target_string(self, ns_id: usize) -> String {
        alloc::format!("{}:[{}]", self.proc_name(), ns_id)
    }

    pub fn inode_number(self, ns_id: usize) -> u64 {
        let kind_tag = match self {
            Self::Ipc => 1u64,
            Self::Mount => 2u64,
            Self::Net => 3u64,
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

fn inc_net_namespace_file_ref(ns_id: usize) {
    let mut refs = NET_NAMESPACE_FILE_REFS.lock();
    *refs.entry(ns_id).or_insert(0) += 1;
}

fn dec_net_namespace_file_ref(ns_id: usize) -> bool {
    let mut refs = NET_NAMESPACE_FILE_REFS.lock();
    let Some(count) = refs.get_mut(&ns_id) else {
        return true;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        refs.remove(&ns_id);
        return true;
    }
    false
}

pub(crate) fn net_namespace_file_refs(ns_id: usize) -> usize {
    NET_NAMESPACE_FILE_REFS
        .lock()
        .get(&ns_id)
        .copied()
        .unwrap_or(0)
}

impl NamespaceFile {
    pub fn new(kind: NamespaceKind, ns_id: usize) -> Self {
        if kind == NamespaceKind::Net {
            inc_net_namespace_file_ref(ns_id);
        }
        Self {
            kind,
            ns_id,
            mount_ns: None,
        }
    }

    pub fn new_ipc(ns_id: usize) -> Self {
        Self::new(NamespaceKind::Ipc, ns_id)
    }

    pub fn new_net(ns_id: usize) -> Self {
        Self::new(NamespaceKind::Net, ns_id)
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

impl Drop for NamespaceFile {
    fn drop(&mut self) {
        if self.kind == NamespaceKind::Net && dec_net_namespace_file_ref(self.ns_id) {
            crate::syscall::net::cleanup_net_namespace_if_unused(self.ns_id);
        }
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
