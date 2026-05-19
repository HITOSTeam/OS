extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::{File, PseudoDir, PseudoDirent};
use crate::mm::UserBuffer;
use crate::syscall::misc::{decode_linux_tid_strict, encode_linux_tid};
use crate::task::{
    manager::{PID2PCB, pid2process},
    manager::{refresh_process_runqueues, wakeup_task},
    process_visible_in_pid_namespace,
    processor::{block_current_and_run_next, current_process, current_task},
    resolve_process_in_pid_namespace,
    sched::{SchedClass, sched_class},
    signal::{SIGKILL_NUM, queue_process_signal},
    task_block::TaskStatus,
};

const EEXIST: isize = -17;
const EACCES: isize = -13;
const EINVAL: isize = -22;
const ENOENT: isize = -2;
const ENODEV: isize = -19;
const ENOTEMPTY: isize = -39;
const EBUSY: isize = -16;
const EAGAIN: isize = -11;
const ESRCH: isize = -3;
const EROFS: isize = -30;
const EOPNOTSUPP: isize = -95;
const LINUX_TID_PID_SHIFT: usize = 15;

pub(crate) static NEXT_CGROUP_INO: AtomicU64 = AtomicU64::new(0x63_0000);

lazy_static! {
    pub(crate) static ref CGROUP_REGISTRY: Mutex<CgroupRegistry> =
        Mutex::new(CgroupRegistry::new());
}

const CTRL_PIDS: u32 = 1 << 0;
const CTRL_MEMORY: u32 = 1 << 1;
const ROOT_CONTROLLERS: u32 = CTRL_PIDS | CTRL_MEMORY;
const LEGACY_CPU_SHARES_DEFAULT: u64 = 1024;
const LEGACY_CPU_SHARES_MIN: u64 = 2;
const LEGACY_CPU_SHARES_MAX: u64 = 262_144;
const LEGACY_CPU_RT_PERIOD_DEFAULT_US: u64 = 1_000_000;
const LEGACY_CPU_RT_RUNTIME_DEFAULT_US: i64 = 0;
const LEGACY_CPU_RT_RUNTIME_ROOT_DEFAULT_US: i64 = 950_000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CgroupMountKind {
    Unified,
    LegacyDebug,
    LegacyCpuset,
    LegacyCpu,
    LegacyCpuAcct,
    LegacyMemory,
    LegacyFreezer,
    LegacyDevices,
    LegacyBlkio,
    LegacyNetCls,
    LegacyPerfEvent,
    LegacyNetPrio,
    LegacyHugetlb,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CgroupHierarchyKey {
    Unified,
    Legacy {
        source_label: String,
        kind: CgroupMountKind,
    },
}

mod file;
mod helpers;
mod mount_state;
mod node;
mod registry;

pub use file::{CgroupFile, cgroup_maybe_block_current};
pub(crate) use file::{CgroupFileKind, build_dir_entries};
pub(crate) use helpers::*;
pub(crate) use mount_state::CgroupMountState;
pub(crate) use node::{CgroupNode, CgroupThreadId, LegacyFreezerState};
pub(crate) use registry::CgroupRegistry;

#[derive(Clone)]
pub struct CgroupMountSpec {
    kind: CgroupMountKind,
    source_label: String,
    hierarchy_key: CgroupHierarchyKey,
}

impl CgroupMountSpec {
    pub fn unified() -> Self {
        Self {
            kind: CgroupMountKind::Unified,
            source_label: String::from("cgroup2"),
            hierarchy_key: CgroupHierarchyKey::Unified,
        }
    }

    pub fn parse_legacy_options(options: &str) -> Result<Self, isize> {
        let mut source_label = String::from("none");
        let mut kind = CgroupMountKind::LegacyDebug;
        let mut found_controller = false;
        for token in options
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            let parsed = match token {
                "none" => None,
                "debug" => Some((token, CgroupMountKind::LegacyDebug)),
                "cpuset" => Some((token, CgroupMountKind::LegacyCpuset)),
                "cpu" => Some((token, CgroupMountKind::LegacyCpu)),
                "cpuacct" => Some((token, CgroupMountKind::LegacyCpuAcct)),
                "memory" => Some((token, CgroupMountKind::LegacyMemory)),
                "freezer" => Some((token, CgroupMountKind::LegacyFreezer)),
                "devices" => Some((token, CgroupMountKind::LegacyDevices)),
                "blkio" => Some((token, CgroupMountKind::LegacyBlkio)),
                "net_cls" => Some((token, CgroupMountKind::LegacyNetCls)),
                "perf_event" => Some((token, CgroupMountKind::LegacyPerfEvent)),
                "net_prio" => Some((token, CgroupMountKind::LegacyNetPrio)),
                "hugetlb" => Some((token, CgroupMountKind::LegacyHugetlb)),
                _ if token.starts_with("name=") => {
                    source_label = String::from(token);
                    None
                }
                _ => return Err(ENODEV),
            };
            if let Some((controller, mount_kind)) = parsed {
                source_label = String::from(controller);
                kind = mount_kind;
                found_controller = true;
            }
        }
        if !found_controller && options.is_empty() {
            source_label = String::from("none");
        }
        Ok(Self {
            kind,
            hierarchy_key: CgroupHierarchyKey::Legacy {
                source_label: source_label.clone(),
                kind,
            },
            source_label,
        })
    }

    pub(crate) fn kind(&self) -> CgroupMountKind {
        self.kind
    }

    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    pub(crate) fn hierarchy_key(&self) -> &CgroupHierarchyKey {
        &self.hierarchy_key
    }
}

pub fn cgroup_mount(target: &str, spec: &CgroupMountSpec) -> isize {
    CGROUP_REGISTRY.lock().mount(target, spec)
}

pub fn cgroup_umount(target: &str) -> isize {
    CGROUP_REGISTRY.lock().umount(target)
}

pub fn is_cgroup_pseudo_path(abs: &str) -> bool {
    split_mount_path(abs).is_some()
}

pub fn open_cgroup_pseudo(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let (_mount_target, mount_rel_path, hierarchy_key) = split_mount_path(path)?;
    let process = current_process();
    let (open_euid, open_cgroup_ns_root) = {
        let inner = process.borrow_mut();
        (inner.euid, inner.cgroup_ns_root.clone())
    };
    let rel_path = namespace_resolve_rel_path(&open_cgroup_ns_root, &mount_rel_path)?;
    let registry = CGROUP_REGISTRY.lock();
    let state = registry.hierarchies.get(&hierarchy_key)?;
    if state.nodes.contains_key(&rel_path) {
        let entries = build_dir_entries(&rel_path, &open_cgroup_ns_root, state);
        return Some(Arc::new(PseudoDir::new(path, entries)));
    }
    let (parent, name) = split_rel_parent(&rel_path)?;
    state.nodes.get(&parent)?;
    let kind = CgroupFileKind::from_name(&name, state.kind)?;
    Some(CgroupFile::new(
        path,
        hierarchy_key,
        &parent,
        kind,
        open_euid,
        &open_cgroup_ns_root,
    ))
}

pub fn cgroup_mkdir(abs: &str) -> isize {
    let ns_root = current_cgroup_namespace_root();
    let (.., rel_path, hierarchy_key) = match resolve_mount_path_in_namespace(&ns_root, abs) {
        Ok(resolved) => resolved,
        Err(err) => return err,
    };
    if rel_path == ns_root {
        return EEXIST;
    }
    let Some((parent, _name)) = split_rel_parent(&rel_path) else {
        return EINVAL;
    };
    let mut registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get_mut(&hierarchy_key) else {
        return ENOENT;
    };
    if !state.nodes.contains_key(&parent) {
        return ENOENT;
    }
    if state.nodes.contains_key(&rel_path) {
        return EEXIST;
    }
    let mut node = CgroupNode::new();
    if let Some(parent_node) = state.nodes.get(&parent) {
        node.clone_children = parent_node.clone_children;
        node.notify_on_release = parent_node.notify_on_release;
    }
    state.nodes.insert(rel_path, node);
    0
}

pub fn cgroup_rmdir(abs: &str) -> isize {
    let ns_root = current_cgroup_namespace_root();
    let (.., rel_path, hierarchy_key) = match resolve_mount_path_in_namespace(&ns_root, abs) {
        Ok(resolved) => resolved,
        Err(err) => return err,
    };
    if rel_path == ns_root {
        return EBUSY;
    }
    let mut registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get_mut(&hierarchy_key) else {
        return ENOENT;
    };
    if !state.nodes.contains_key(&rel_path) {
        return ENOENT;
    }
    if !state.direct_children(&rel_path).is_empty() {
        return ENOTEMPTY;
    }
    if state
        .process_assignments
        .values()
        .any(|path| path == &rel_path)
        || state
            .thread_assignments
            .values()
            .any(|path| path == &rel_path)
    {
        return EBUSY;
    }
    state.nodes.remove(&rel_path);
    0
}

fn rename_subtree_path(path: &str, old_prefix: &str, new_prefix: &str) -> String {
    if path == old_prefix {
        return String::from(new_prefix);
    }
    let suffix = path.strip_prefix(old_prefix).unwrap_or("");
    alloc::format!("{new_prefix}{suffix}")
}

fn rename_cgroup_namespace_roots(old_prefix: &str, new_prefix: &str) {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes {
        let current_root = process.cgroup_namespace_root();
        if CgroupMountState::is_descendant_or_self(&current_root, old_prefix) {
            process.set_cgroup_namespace_root(rename_subtree_path(
                &current_root,
                old_prefix,
                new_prefix,
            ));
        }
    }
}

pub fn cgroup_rename(old_abs: &str, new_abs: &str, no_replace: bool) -> isize {
    let ns_root = current_cgroup_namespace_root();
    let (old_mount, old_rel, hierarchy_key) =
        match resolve_mount_path_in_namespace(&ns_root, old_abs) {
            Ok(resolved) => resolved,
            Err(err) => return err,
        };
    let (new_mount, new_rel, new_hierarchy_key) =
        match resolve_mount_path_in_namespace(&ns_root, new_abs) {
            Ok(resolved) => resolved,
            Err(err) => return err,
        };
    if old_mount != new_mount || hierarchy_key != new_hierarchy_key {
        return EROFS;
    }
    if old_rel == ns_root || new_rel == ns_root {
        return EBUSY;
    }
    if old_rel == new_rel {
        return 0;
    }
    let Some((old_parent, _)) = split_rel_parent(&old_rel) else {
        return EINVAL;
    };
    if CgroupMountState::is_descendant_or_self(&new_rel, &old_rel) {
        return EINVAL;
    }
    let Some((new_parent, _)) = split_rel_parent(&new_rel) else {
        return EINVAL;
    };
    if old_parent != new_parent {
        return EROFS;
    }

    let mut registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get_mut(&hierarchy_key) else {
        return ENOENT;
    };
    if !state.nodes.contains_key(&old_rel) {
        return ENOENT;
    }
    if !state.nodes.contains_key(&new_parent) {
        return ENOENT;
    }
    if state.nodes.contains_key(&new_rel) {
        let _ = no_replace;
        return EEXIST;
    }

    let renamed_keys = state
        .nodes
        .keys()
        .filter(|path| CgroupMountState::is_descendant_or_self(path, &old_rel))
        .cloned()
        .collect::<Vec<_>>();
    let renamed_nodes = renamed_keys
        .iter()
        .filter_map(|path| state.nodes.remove(path).map(|node| (path.clone(), node)))
        .collect::<Vec<_>>();
    for (old_path, node) in renamed_nodes {
        let new_path = rename_subtree_path(&old_path, &old_rel, &new_rel);
        state.nodes.insert(new_path, node);
    }
    for path in state.process_assignments.values_mut() {
        if CgroupMountState::is_descendant_or_self(path, &old_rel) {
            *path = rename_subtree_path(path, &old_rel, &new_rel);
        }
    }
    for path in state.thread_assignments.values_mut() {
        if CgroupMountState::is_descendant_or_self(path, &old_rel) {
            *path = rename_subtree_path(path, &old_rel, &new_rel);
        }
    }
    drop(registry);
    rename_cgroup_namespace_roots(&old_rel, &new_rel);
    0
}

pub fn cgroup_proc_cgroups_content() -> String {
    String::from(
        "#subsys_name\thierarchy\tnum_cgroups\tenabled\n\
debug\t0\t1\t1\n\
cpuset\t0\t1\t1\n\
cpu\t0\t1\t1\n\
cpuacct\t0\t1\t1\n\
memory\t0\t1\t1\n\
freezer\t0\t1\t1\n\
devices\t0\t1\t1\n\
blkio\t0\t1\t1\n\
net_cls\t0\t1\t1\n\
perf_event\t0\t1\t1\n\
net_prio\t0\t1\t1\n\
hugetlb\t0\t1\t1\n\
pids\t0\t1\t1\n",
    )
}

pub fn cgroup_proc_pid_content(pid: usize) -> String {
    let ns_root = pid2process(pid)
        .map(|process| process.cgroup_namespace_root())
        .unwrap_or_else(|| String::from("/"));
    let registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.preferred_proc_hierarchy() else {
        return String::from("0::/\n");
    };
    let path = namespace_visible_path(&state.path_for_pid(pid), &ns_root);
    alloc::format!("0::{path}\n")
}

pub fn cgroup_current_path(pid: usize) -> String {
    let registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.preferred_proc_hierarchy() else {
        return String::from("/");
    };
    state.path_for_pid(pid)
}

pub fn cgroup_fork_precheck(parent_pid: usize) -> Result<(), isize> {
    let registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values() {
        let path = state.path_for_pid(parent_pid);
        for ancestor in CgroupMountState::ancestor_paths(&path) {
            let Some(node) = state.nodes.get(&ancestor) else {
                continue;
            };
            let Some(limit) = node.pids_max else {
                continue;
            };
            if state.subtree_pid_count(&ancestor) >= limit {
                return Err(EAGAIN);
            }
        }
    }
    Ok(())
}

pub fn cgroup_attach_fork_child(parent_pid: usize, child_pid: usize) {
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_pid(parent_pid);
        state.attach_process(child_pid, &path);
    }
}

pub fn cgroup_attach_thread(process_pid: usize, parent_tid_index: usize, child_tid_index: usize) {
    let mut registry = CGROUP_REGISTRY.lock();
    let parent_thread_id = CgroupThreadId::new(process_pid, parent_tid_index);
    let child_thread_id = CgroupThreadId::new(process_pid, child_tid_index);
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_thread(parent_thread_id);
        state.attach_thread(child_thread_id, &path);
    }
}

pub fn cgroup_exit_thread(process_pid: usize, tid_index: usize) {
    let mut registry = CGROUP_REGISTRY.lock();
    let thread_id = CgroupThreadId::new(process_pid, tid_index);
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_thread(thread_id);
        state.flush_thread_cpu_usage(thread_id, &path);
        state.remove_thread(thread_id);
    }
}

pub fn legacy_cpu_fair_group(tgid: usize, tid_index: usize) -> (u64, u64) {
    let thread_id = CgroupThreadId::new(tgid, tid_index);
    let registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values() {
        if state.kind != CgroupMountKind::LegacyCpu {
            continue;
        }
        let path = state.path_for_thread(thread_id);
        if let Some(node) = state.nodes.get(&path) {
            return (node.ino, node.cpu_shares);
        }
        if let Some(root) = state.nodes.get("/") {
            return (root.ino, root.cpu_shares);
        }
    }
    (0, LEGACY_CPU_SHARES_DEFAULT)
}

pub fn cgroup_exit_process(pid: usize) {
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        let thread_ids = state
            .thread_assignments
            .keys()
            .copied()
            .filter(|thread_id| thread_id.tgid == pid)
            .collect::<Vec<_>>();
        for thread_id in thread_ids {
            let path = state.path_for_thread(thread_id);
            state.flush_thread_cpu_usage(thread_id, &path);
            state.remove_thread(thread_id);
        }
        state.process_assignments.remove(&pid);
        state.process_anon_bytes.remove(&pid);
    }
}

pub fn cgroup_charge_anon_current(pid: usize, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_pid(pid);
        let previous = state
            .process_anon_bytes
            .get(&pid)
            .and_then(|charges| charges.get(&path).copied())
            .unwrap_or(0);
        state
            .process_anon_bytes
            .entry(pid)
            .or_default()
            .insert(path.clone(), previous.saturating_add(bytes));
        if !state.enforce_memory_limits(&path) {
            if let Some(charges) = state.process_anon_bytes.get_mut(&pid) {
                if previous == 0 {
                    charges.remove(&path);
                } else {
                    charges.insert(path.clone(), previous);
                }
                if charges.is_empty() {
                    state.process_anon_bytes.remove(&pid);
                }
            }
            return false;
        }
    }
    true
}

pub fn cgroup_charge_file_write(pid: usize, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_pid(pid);
        if let Some(node) = state.nodes.get_mut(&path) {
            node.local_file_bytes = node.local_file_bytes.saturating_add(bytes);
            let _ = state.enforce_memory_limits(&path);
        }
    }
}

pub fn cgroup_logical_path_for_file(file: &Arc<dyn File + Send + Sync>) -> Option<String> {
    file.as_any()
        .downcast_ref::<CgroupFile>()
        .map(|file| file.path().to_string())
}
