use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use core::any::Any;

use crate::mm::UserBuffer;

use super::{File, MountNamespace, mount_namespace_id};
use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {
    /// All lifetime classes share one lock so ownership hand-offs (notably a
    /// namespace file consumed by setns()) cannot be observed as a torn series
    /// of zero counts by the teardown worker.
    static ref NET_NAMESPACE_LIFETIMES: Mutex<NetNamespaceLifetimeState> =
        Mutex::new(NetNamespaceLifetimeState::default());
}

#[derive(Default)]
struct NetNamespaceLifetimeState {
    process_refs: BTreeMap<usize, usize>,
    file_refs: BTreeMap<usize, usize>,
    socket_refs: BTreeMap<usize, usize>,
    transient_refs: BTreeMap<usize, usize>,
    teardown_in_progress: BTreeSet<usize>,
    dead: BTreeSet<usize>,
}

impl NetNamespaceLifetimeState {
    fn refs(map: &BTreeMap<usize, usize>, ns_id: usize) -> usize {
        map.get(&ns_id).copied().unwrap_or(0)
    }

    fn is_unused(&self, ns_id: usize) -> bool {
        ns_id != 0
            && Self::refs(&self.process_refs, ns_id) == 0
            && Self::refs(&self.file_refs, ns_id) == 0
            && Self::refs(&self.socket_refs, ns_id) == 0
            && Self::refs(&self.transient_refs, ns_id) == 0
    }

    fn can_acquire(&self, ns_id: usize) -> bool {
        ns_id == 0 || (!self.teardown_in_progress.contains(&ns_id) && !self.dead.contains(&ns_id))
    }
}

fn inc_ref(map: &mut BTreeMap<usize, usize>, ns_id: usize) {
    if ns_id != 0 {
        *map.entry(ns_id).or_insert(0) += 1;
    }
}

fn dec_ref(map: &mut BTreeMap<usize, usize>, ns_id: usize, kind: &str) {
    if ns_id == 0 {
        return;
    }
    let count = map
        .get_mut(&ns_id)
        .unwrap_or_else(|| panic!("unbalanced network namespace {kind} reference"));
    assert!(*count != 0, "zero network namespace {kind} reference");
    *count -= 1;
    if *count == 0 {
        map.remove(&ns_id);
    }
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
    net_ref_held: bool,
}

pub(crate) fn register_net_namespace_file_ref(ns_id: usize) -> bool {
    let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
    if !lifetimes.can_acquire(ns_id) {
        return false;
    }
    inc_ref(&mut lifetimes.file_refs, ns_id);
    true
}

fn dec_net_namespace_file_ref(ns_id: usize) -> bool {
    let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
    dec_ref(&mut lifetimes.file_refs, ns_id, "file");
    lifetimes.is_unused(ns_id)
}

pub(crate) fn register_net_namespace_socket_ref(ns_id: usize) -> bool {
    let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
    if !lifetimes.can_acquire(ns_id) {
        return false;
    }
    inc_ref(&mut lifetimes.socket_refs, ns_id);
    true
}

/// Move one process owner between namespaces under the same lifetime lock used
/// by file/socket/pin references. Returns false only if a stale target id is
/// already being torn down.
pub(crate) fn switch_net_namespace_process_ref(old_ns_id: usize, new_ns_id: usize) -> bool {
    if old_ns_id == new_ns_id {
        return true;
    }
    let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
    if !lifetimes.can_acquire(new_ns_id) {
        return false;
    }
    assert!(
        old_ns_id == 0 || NetNamespaceLifetimeState::refs(&lifetimes.process_refs, old_ns_id) != 0,
        "unbalanced network namespace process hand-off"
    );
    inc_ref(&mut lifetimes.process_refs, new_ns_id);
    dec_ref(&mut lifetimes.process_refs, old_ns_id, "process");
    true
}

pub(crate) fn release_net_namespace_process_ref(ns_id: usize) {
    let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
    dec_ref(&mut lifetimes.process_refs, ns_id, "process");
}

/// Atomically claim teardown only after every lifetime class reaches zero.
pub(crate) fn try_begin_net_namespace_cleanup(ns_id: usize) -> bool {
    let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
    if !lifetimes.can_acquire(ns_id) || !lifetimes.is_unused(ns_id) {
        return false;
    }
    lifetimes.teardown_in_progress.insert(ns_id);
    true
}

pub(crate) fn finish_net_namespace_cleanup(ns_id: usize) {
    let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
    assert!(
        lifetimes.teardown_in_progress.remove(&ns_id),
        "finishing network namespace cleanup without a teardown claim"
    );
    // Namespace ids are monotonic and never reused. Keep a tombstone so stale
    // internal ids cannot resurrect protocol state after teardown completed.
    lifetimes.dead.insert(ns_id);
}

/// RAII pin covering the interval between a fork namespace snapshot and child
/// publication in the PID map.
pub(crate) struct NetNamespacePin {
    ns_id: usize,
    active: bool,
}

pub(crate) fn pin_net_namespace(ns_id: usize) -> NetNamespacePin {
    let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
    assert!(
        lifetimes.can_acquire(ns_id),
        "live process namespace cannot already be in teardown"
    );
    inc_ref(&mut lifetimes.transient_refs, ns_id);
    NetNamespacePin {
        ns_id,
        active: true,
    }
}

impl NetNamespacePin {
    /// Convert the fork publication pin into a process owner without exposing
    /// an intermediate zero-reference state.
    pub(crate) fn publish_process_owner(mut self) {
        let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
        dec_ref(&mut lifetimes.transient_refs, self.ns_id, "transient");
        inc_ref(&mut lifetimes.process_refs, self.ns_id);
        self.active = false;
    }
}

impl Drop for NetNamespacePin {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let became_unused = {
            let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
            dec_ref(&mut lifetimes.transient_refs, self.ns_id, "transient");
            lifetimes.is_unused(self.ns_id)
        };
        if became_unused {
            crate::syscall::net::queue_net_namespace_cleanup(self.ns_id);
        }
    }
}

/// Release a socket-held namespace reference after the socket has detached all
/// protocol state. The last release queues namespace teardown because a socket
/// destructor may itself be running while a weak-socket registry is locked.
/// Running teardown recursively there would deadlock on that registry.
pub(crate) fn release_net_namespace_socket_ref(ns_id: usize) {
    let became_unused = {
        let mut lifetimes = NET_NAMESPACE_LIFETIMES.lock();
        dec_ref(&mut lifetimes.socket_refs, ns_id, "socket");
        lifetimes.is_unused(ns_id)
    };
    if became_unused {
        crate::syscall::net::queue_net_namespace_cleanup(ns_id);
    }
}

impl NamespaceFile {
    pub fn new_ipc(ns_id: usize) -> Self {
        Self {
            kind: NamespaceKind::Ipc,
            ns_id,
            mount_ns: None,
            net_ref_held: false,
        }
    }

    /// Construct after the target PCB already acquired the file reference.
    pub(crate) fn new_net_with_acquired_ref(ns_id: usize) -> Self {
        Self {
            kind: NamespaceKind::Net,
            ns_id,
            mount_ns: None,
            net_ref_held: true,
        }
    }

    pub fn new_mount(namespace: MountNamespace) -> Self {
        Self {
            kind: NamespaceKind::Mount,
            ns_id: mount_namespace_id(&namespace),
            mount_ns: Some(namespace),
            net_ref_held: false,
        }
    }

    pub fn kind(&self) -> NamespaceKind {
        self.kind
    }

    pub fn ns_id(&self) -> usize {
        self.ns_id
    }

    pub fn holds_live_net_ref(&self) -> bool {
        self.kind != NamespaceKind::Net || self.net_ref_held
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
        if self.net_ref_held && dec_net_namespace_file_ref(self.ns_id) {
            crate::syscall::net::queue_net_namespace_cleanup(self.ns_id);
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
