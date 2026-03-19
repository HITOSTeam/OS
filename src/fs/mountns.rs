use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountPropagation {
    Private,
    Shared,
    Slave,
    Unbindable,
}

#[derive(Clone, Debug)]
pub(crate) struct MountRecord {
    pub(crate) target: String,
    pub(crate) source: String,
    pub(crate) source_display: String,
    pub(crate) fs_type: String,
    pub(crate) flags: usize,
    pub(crate) stack_seq: usize,
    pub(crate) event_id: usize,
    pub(crate) propagation: MountPropagation,
    pub(crate) peer_group_id: Option<usize>,
    pub(crate) master_group_id: Option<usize>,
    pub(crate) access_seq: usize,
    pub(crate) expire_mark_seq: Option<usize>,
}

pub(crate) type MountNamespace = Arc<Mutex<MountNamespaceState>>;

#[derive(Debug)]
pub(crate) struct MountNamespaceState {
    id: usize,
    mounts: Vec<MountRecord>,
    rofs_mounts: Vec<String>,
}

impl MountNamespaceState {
    fn new(id: usize) -> Self {
        Self {
            id,
            mounts: Vec::new(),
            rofs_mounts: Vec::new(),
        }
    }

    pub(crate) fn id(&self) -> usize {
        self.id
    }

    pub(crate) fn mounts(&self) -> &[MountRecord] {
        &self.mounts
    }

    pub(crate) fn mounts_mut(&mut self) -> &mut Vec<MountRecord> {
        &mut self.mounts
    }

    pub(crate) fn rofs_mounts(&self) -> &[String] {
        &self.rofs_mounts
    }

    pub(crate) fn rofs_mounts_mut(&mut self) -> &mut Vec<String> {
        &mut self.rofs_mounts
    }

    fn clone_detached(&self) -> Self {
        Self {
            id: alloc_mount_namespace_id(),
            mounts: self.mounts.clone(),
            rofs_mounts: self.rofs_mounts.clone(),
        }
    }
}

static NEXT_MOUNT_NS_ID: AtomicUsize = AtomicUsize::new(1);

fn alloc_mount_namespace_id() -> usize {
    NEXT_MOUNT_NS_ID.fetch_add(1, Ordering::Relaxed)
}

lazy_static! {
    static ref INITIAL_MOUNT_NAMESPACE: MountNamespace =
        Arc::new(Mutex::new(MountNamespaceState::new(0)));
}

pub(crate) fn initial_mount_namespace() -> MountNamespace {
    Arc::clone(&INITIAL_MOUNT_NAMESPACE)
}

pub(crate) fn clone_mount_namespace(ns: &MountNamespace) -> MountNamespace {
    let snapshot = ns.lock().clone_detached();
    Arc::new(Mutex::new(snapshot))
}

pub(crate) fn mount_namespace_id(ns: &MountNamespace) -> usize {
    ns.lock().id()
}
