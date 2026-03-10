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
    manager::wakeup_task,
    manager::{PID2PCB, pid2process},
    processor::{block_current_and_run_next, current_process, current_task},
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

static NEXT_CGROUP_INO: AtomicU64 = AtomicU64::new(0x63_0000);

lazy_static! {
    static ref CGROUP_REGISTRY: Mutex<CgroupRegistry> = Mutex::new(CgroupRegistry::new());
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
enum CgroupHierarchyKey {
    Unified,
    Legacy {
        source_label: String,
        kind: CgroupMountKind,
    },
}

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

    fn kind(&self) -> CgroupMountKind {
        self.kind
    }

    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    fn hierarchy_key(&self) -> &CgroupHierarchyKey {
        &self.hierarchy_key
    }
}

struct CgroupRegistry {
    mounts: BTreeMap<String, CgroupHierarchyKey>,
    hierarchies: BTreeMap<CgroupHierarchyKey, CgroupMountState>,
}

impl CgroupRegistry {
    fn new() -> Self {
        Self {
            mounts: BTreeMap::new(),
            hierarchies: BTreeMap::new(),
        }
    }

    fn mount(&mut self, target: &str, spec: &CgroupMountSpec) -> isize {
        if self.mounts.contains_key(target) {
            return EBUSY;
        }
        self.hierarchies
            .entry(spec.hierarchy_key().clone())
            .or_insert_with(|| {
                let mut state = CgroupMountState::new(spec.kind());
                state.seed_root_membership();
                state
            });
        self.mounts
            .insert(String::from(target), spec.hierarchy_key().clone());
        0
    }

    fn umount(&mut self, target: &str) -> isize {
        let Some(key) = self.mounts.remove(target) else {
            return 0;
        };
        let hierarchy_still_mounted = self.mounts.values().any(|mounted_key| mounted_key == &key);
        if !hierarchy_still_mounted {
            self.hierarchies.remove(&key);
        }
        0
    }

    fn preferred_proc_hierarchy(&self) -> Option<&CgroupMountState> {
        self.hierarchies
            .values()
            .find(|state| state.is_unified())
            .or_else(|| self.hierarchies.values().next())
    }
}

#[derive(Clone)]
struct CgroupNode {
    ino: u64,
    subtree_control: u32,
    clone_children: bool,
    notify_on_release: bool,
    freezer_state: LegacyFreezerState,
    cpu_shares: u64,
    cpu_rt_runtime_us: i64,
    cpu_rt_period_us: u64,
    cpuset_cpus: String,
    cpuset_mems: String,
    pids_max: Option<usize>,
    memory_max: Option<usize>,
    memory_swap_max: Option<usize>,
    memory_min: usize,
    memory_low: usize,
    memory_events_low: usize,
    memory_events_oom: usize,
    local_file_bytes: usize,
    local_cpu_usage_ns: u64,
    subtree_thread_count: usize,
}

impl CgroupNode {
    fn new() -> Self {
        Self {
            ino: NEXT_CGROUP_INO.fetch_add(1, Ordering::Relaxed),
            subtree_control: 0,
            clone_children: false,
            notify_on_release: false,
            freezer_state: LegacyFreezerState::Thawed,
            cpu_shares: LEGACY_CPU_SHARES_DEFAULT,
            cpu_rt_runtime_us: LEGACY_CPU_RT_RUNTIME_DEFAULT_US,
            cpu_rt_period_us: LEGACY_CPU_RT_PERIOD_DEFAULT_US,
            cpuset_cpus: String::from("0"),
            cpuset_mems: String::from("0"),
            pids_max: None,
            memory_max: None,
            memory_swap_max: None,
            memory_min: 0,
            memory_low: 0,
            memory_events_low: 0,
            memory_events_oom: 0,
            local_file_bytes: 0,
            local_cpu_usage_ns: 0,
            subtree_thread_count: 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacyFreezerState {
    Thawed,
    Frozen,
}

impl LegacyFreezerState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Thawed => "THAWED",
            Self::Frozen => "FROZEN",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CgroupThreadId {
    tgid: usize,
    tid_index: usize,
}

impl CgroupThreadId {
    fn new(tgid: usize, tid_index: usize) -> Self {
        Self { tgid, tid_index }
    }

    fn visible_tid(self) -> usize {
        encode_linux_tid(self.tgid, self.tid_index)
    }
}

#[derive(Clone)]
struct CgroupMountState {
    kind: CgroupMountKind,
    nodes: BTreeMap<String, CgroupNode>,
    process_assignments: BTreeMap<usize, String>,
    thread_assignments: BTreeMap<CgroupThreadId, String>,
    process_anon_bytes: BTreeMap<usize, BTreeMap<String, usize>>,
    thread_cpu_account_ns: BTreeMap<CgroupThreadId, u64>,
}

impl CgroupMountState {
    fn new(kind: CgroupMountKind) -> Self {
        let mut nodes = BTreeMap::new();
        let mut root = CgroupNode::new();
        if kind == CgroupMountKind::LegacyCpu {
            root.cpu_rt_runtime_us = LEGACY_CPU_RT_RUNTIME_ROOT_DEFAULT_US;
        }
        nodes.insert(String::from("/"), root);
        Self {
            kind,
            nodes,
            process_assignments: BTreeMap::new(),
            thread_assignments: BTreeMap::new(),
            process_anon_bytes: BTreeMap::new(),
            thread_cpu_account_ns: BTreeMap::new(),
        }
    }

    fn is_unified(&self) -> bool {
        matches!(self.kind, CgroupMountKind::Unified)
    }

    fn direct_children(&self, path: &str) -> Vec<String> {
        let mut names = BTreeSet::new();
        for node_path in self.nodes.keys() {
            if node_path == path {
                continue;
            }
            let Some(rest) = node_path.strip_prefix(path) else {
                continue;
            };
            let rest = if path == "/" {
                node_path.trim_start_matches('/')
            } else {
                rest.trim_start_matches('/')
            };
            if rest.is_empty() {
                continue;
            }
            let name = rest.split('/').next().unwrap_or("");
            if !name.is_empty() {
                names.insert(String::from(name));
            }
        }
        names.into_iter().collect()
    }

    fn is_descendant_or_self(path: &str, ancestor: &str) -> bool {
        if ancestor == "/" {
            return path.starts_with('/');
        }
        path == ancestor
            || (path.starts_with(ancestor)
                && path
                    .as_bytes()
                    .get(ancestor.len())
                    .copied()
                    .unwrap_or_default()
                    == b'/')
    }

    fn direct_member_processes(&self, path: &str) -> Vec<usize> {
        let mut pids = self
            .process_assignments
            .iter()
            .filter_map(|(pid, pid_path)| (*pid_path == path).then_some(*pid))
            .collect::<Vec<_>>();
        pids.sort_unstable();
        pids
    }

    fn direct_member_threads(&self, path: &str) -> Vec<usize> {
        let mut tids = self
            .thread_assignments
            .iter()
            .filter_map(|(thread_id, thread_path)| {
                (*thread_path == path).then_some(thread_id.visible_tid())
            })
            .collect::<Vec<_>>();
        tids.sort_unstable();
        tids
    }

    fn direct_member_legacy_procs(&self, path: &str) -> Vec<usize> {
        self.thread_assignments
            .iter()
            .filter_map(|(thread_id, thread_path)| (*thread_path == path).then_some(thread_id.tgid))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn subtree_member_threads(&self, path: &str) -> Vec<CgroupThreadId> {
        let mut tids = self
            .thread_assignments
            .iter()
            .filter_map(|(thread_id, thread_path)| {
                Self::is_descendant_or_self(thread_path, path).then_some(*thread_id)
            })
            .collect::<Vec<_>>();
        tids.sort_unstable();
        tids
    }

    fn subtree_pid_count(&self, path: &str) -> usize {
        self.nodes
            .get(path)
            .map(|node| node.subtree_thread_count)
            .unwrap_or(0)
    }

    fn ancestor_paths(path: &str) -> Vec<String> {
        if path == "/" {
            return vec![String::from("/")];
        }
        let mut out = vec![String::from("/")];
        let mut cur = String::new();
        for part in path.trim_start_matches('/').split('/') {
            cur.push('/');
            cur.push_str(part);
            out.push(cur.clone());
        }
        out
    }

    fn available_controllers(&self, path: &str) -> u32 {
        if path == "/" {
            return ROOT_CONTROLLERS;
        }
        split_rel_parent(path)
            .and_then(|(parent, _)| self.nodes.get(&parent).map(|node| node.subtree_control))
            .unwrap_or(0)
    }

    fn path_for_pid(&self, pid: usize) -> String {
        self.process_assignments
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| String::from("/"))
    }

    fn path_for_thread(&self, thread_id: CgroupThreadId) -> String {
        self.thread_assignments
            .get(&thread_id)
            .cloned()
            .unwrap_or_else(|| self.path_for_pid(thread_id.tgid))
    }

    fn adjust_subtree_thread_count(&mut self, path: &str, add: bool) {
        for ancestor in Self::ancestor_paths(path) {
            let Some(node) = self.nodes.get_mut(&ancestor) else {
                continue;
            };
            if add {
                node.subtree_thread_count = node.subtree_thread_count.saturating_add(1);
            } else {
                node.subtree_thread_count = node.subtree_thread_count.saturating_sub(1);
            }
        }
    }

    fn set_thread_assignment(&mut self, thread_id: CgroupThreadId, path: &str) {
        let new_path = String::from(path);
        let old_path = self.thread_assignments.insert(thread_id, new_path.clone());
        if old_path.as_deref() != Some(new_path.as_str()) {
            if let Some(old_path) = old_path {
                self.adjust_subtree_thread_count(&old_path, false);
            }
            self.adjust_subtree_thread_count(&new_path, true);
        }
    }

    fn attach_process(&mut self, pid: usize, path: &str) {
        self.process_assignments.insert(pid, String::from(path));
        for thread_id in live_thread_ids_for_process(pid) {
            self.set_thread_assignment(thread_id, path);
            self.thread_cpu_account_ns
                .insert(thread_id, thread_cpu_time_ns(thread_id));
        }
    }

    fn attach_thread(&mut self, thread_id: CgroupThreadId, path: &str) {
        self.set_thread_assignment(thread_id, path);
        self.thread_cpu_account_ns
            .insert(thread_id, thread_cpu_time_ns(thread_id));
    }

    fn remove_thread(&mut self, thread_id: CgroupThreadId) {
        if let Some(old_path) = self.thread_assignments.remove(&thread_id) {
            self.adjust_subtree_thread_count(&old_path, false);
        }
        self.thread_cpu_account_ns.remove(&thread_id);
    }

    fn seed_root_membership(&mut self) {
        for pid in live_process_ids() {
            self.attach_process(pid, "/");
        }
    }

    fn subtree_anon_bytes(&self, path: &str) -> usize {
        self.process_anon_bytes
            .iter()
            .map(|(_pid, charges)| {
                charges
                    .iter()
                    .filter_map(|(charge_path, bytes)| {
                        Self::is_descendant_or_self(charge_path, path).then_some(*bytes)
                    })
                    .sum::<usize>()
            })
            .sum()
    }

    fn subtree_file_bytes(&self, path: &str) -> usize {
        self.nodes
            .iter()
            .filter_map(|(node_path, node)| {
                Self::is_descendant_or_self(node_path, path).then_some(node.local_file_bytes)
            })
            .sum()
    }

    fn subtree_memory_usage(&self, path: &str) -> usize {
        self.subtree_anon_bytes(path)
            .saturating_add(self.subtree_file_bytes(path))
    }

    fn subtree_cpu_usage_ns(&self, path: &str) -> u64 {
        let historical = self
            .nodes
            .iter()
            .filter_map(|(node_path, node)| {
                Self::is_descendant_or_self(node_path, path).then_some(node.local_cpu_usage_ns)
            })
            .fold(0u64, |acc, ns| acc.saturating_add(ns));
        let live = self
            .thread_assignments
            .iter()
            .filter_map(|(thread_id, thread_path)| {
                if !Self::is_descendant_or_self(thread_path, path) {
                    return None;
                }
                let current = thread_cpu_time_ns(*thread_id);
                let snap = self
                    .thread_cpu_account_ns
                    .get(thread_id)
                    .copied()
                    .unwrap_or(current);
                Some(current.saturating_sub(snap))
            })
            .fold(0u64, |acc, ns| acc.saturating_add(ns));
        historical.saturating_add(live)
    }

    fn flush_thread_cpu_usage(&mut self, thread_id: CgroupThreadId, path: &str) {
        let current = thread_cpu_time_ns(thread_id);
        let previous = self
            .thread_cpu_account_ns
            .get(&thread_id)
            .copied()
            .unwrap_or(current);
        let delta = current.saturating_sub(previous);
        if delta > 0 {
            if let Some(node) = self.nodes.get_mut(path) {
                node.local_cpu_usage_ns = node.local_cpu_usage_ns.saturating_add(delta);
            }
        }
        self.thread_cpu_account_ns.insert(thread_id, current);
    }

    fn subtree_file_usage(&self, path: &str) -> usize {
        self.subtree_file_bytes(path)
    }

    fn subtree_effective_protection(&self, path: &str, respect_low: bool) -> usize {
        let usage = self.subtree_memory_usage(path);
        let protection = self.nodes.get(path).map_or(0, |node| {
            if respect_low {
                node.memory_min.max(node.memory_low)
            } else {
                node.memory_min
            }
        });
        usage.min(protection)
    }

    fn child_paths(&self, path: &str) -> Vec<String> {
        self.direct_children(path)
            .into_iter()
            .map(|name| {
                if path == "/" {
                    alloc::format!("/{name}")
                } else {
                    alloc::format!("{path}/{name}")
                }
            })
            .collect()
    }

    fn distribute_weighted_budget(
        entries: &[(String, usize)],
        budget: usize,
    ) -> BTreeMap<String, usize> {
        let mut budgets = BTreeMap::new();
        if entries.is_empty() || budget == 0 {
            return budgets;
        }
        let total_weight: usize = entries.iter().map(|(_, weight)| *weight).sum();
        if total_weight == 0 {
            return budgets;
        }
        let usable_budget = budget.min(total_weight);
        let mut used = 0usize;
        let mut remainders = Vec::new();
        for (path, weight) in entries {
            let base = usable_budget.saturating_mul(*weight) / total_weight;
            budgets.insert(path.clone(), base);
            used = used.saturating_add(base);
            let rem = usable_budget.saturating_mul(*weight) % total_weight;
            remainders.push((rem, path.clone(), *weight));
        }
        remainders.sort_unstable_by(|a, b| b.cmp(a));
        let mut leftover = usable_budget.saturating_sub(used);
        for (_, path, weight) in remainders {
            if leftover == 0 {
                break;
            }
            let current = budgets.get(&path).copied().unwrap_or(0);
            if current >= weight {
                continue;
            }
            budgets.insert(path, current + 1);
            leftover -= 1;
        }
        budgets
    }

    fn reclaim_file_bytes(
        &mut self,
        path: &str,
        target: usize,
        protected_budget: usize,
        respect_low: bool,
    ) -> usize {
        if target == 0 {
            return 0;
        }
        let current_usage = self.subtree_memory_usage(path);
        let max_reclaim = current_usage.saturating_sub(protected_budget);
        let mut need = target.min(max_reclaim);
        if need == 0 {
            return 0;
        }

        let mut reclaimed = 0usize;
        let mut children = self
            .child_paths(path)
            .into_iter()
            .map(|child| {
                let usage = self.subtree_memory_usage(&child);
                let eff = self.subtree_effective_protection(&child, respect_low);
                (child, usage, eff)
            })
            .collect::<Vec<_>>();
        let protection_inputs = children
            .iter()
            .map(|(child, _usage, eff)| (child.clone(), *eff))
            .collect::<Vec<_>>();
        let budgets =
            Self::distribute_weighted_budget(protection_inputs.as_slice(), protected_budget);
        let child_budget_total = budgets.values().copied().sum::<usize>();
        let local_file_bytes = self
            .nodes
            .get(path)
            .map(|node| node.local_file_bytes)
            .unwrap_or(0);
        let local_reclaimable =
            local_file_bytes.min(current_usage.saturating_sub(protected_budget));
        let mut reclaimable_inputs = children
            .iter()
            .filter_map(|(child, usage, _eff)| {
                let child_budget = budgets.get(child).copied().unwrap_or(0);
                let reclaimable = self
                    .subtree_file_usage(child)
                    .min(usage.saturating_sub(child_budget));
                (reclaimable > 0).then_some((child.clone(), reclaimable))
            })
            .collect::<Vec<_>>();
        if local_reclaimable > 0 {
            reclaimable_inputs.push((String::from("."), local_reclaimable));
        }
        let remaining_reclaimable = reclaimable_inputs
            .iter()
            .map(|(_, weight)| *weight)
            .sum::<usize>()
            .saturating_sub(need);
        let extra_targets =
            Self::distribute_weighted_budget(reclaimable_inputs.as_slice(), remaining_reclaimable);
        for (child, usage, _eff) in children {
            let child_budget = budgets.get(&child).copied().unwrap_or(0);
            let child_target = child_budget
                .saturating_add(extra_targets.get(&child).copied().unwrap_or(0))
                .min(usage);
            let child_need = usage.saturating_sub(child_target);
            if child_need == 0 {
                continue;
            }
            let took = self.reclaim_file_bytes(&child, child_need, child_budget, respect_low);
            reclaimed = reclaimed.saturating_add(took);
        }
        if local_reclaimable > 0 {
            let local_protected = protected_budget.saturating_sub(child_budget_total);
            let local_target = local_protected
                .saturating_add(extra_targets.get(".").copied().unwrap_or(0))
                .min(local_file_bytes);
            let local_need = local_file_bytes.saturating_sub(local_target);
            if local_need > 0 {
                let took = {
                    let Some(node) = self.nodes.get_mut(path) else {
                        return reclaimed;
                    };
                    let took = local_need.min(node.local_file_bytes);
                    node.local_file_bytes = node.local_file_bytes.saturating_sub(took);
                    if took > 0 && node.memory_low > 0 {
                        node.memory_events_low = node.memory_events_low.saturating_add(1);
                    }
                    took
                };
                reclaimed = reclaimed.saturating_add(took);
            }
        }
        reclaimed
    }

    fn enforce_memory_limits(&mut self, path: &str) -> bool {
        for ancestor in Self::ancestor_paths(path) {
            let (node_max, preferred_budget, hard_budget) = self
                .nodes
                .get(&ancestor)
                .map(|node| {
                    let usage = self.subtree_memory_usage(&ancestor);
                    (
                        node.memory_max,
                        usage.min(node.memory_min.max(node.memory_low)),
                        usage.min(node.memory_min),
                    )
                })
                .unwrap_or((None, 0, 0));
            let Some(limit) = node_max else {
                continue;
            };
            let usage = self.subtree_memory_usage(&ancestor);
            if usage <= limit {
                continue;
            }
            let excess = usage.saturating_sub(limit);
            let _ = self.reclaim_file_bytes(&ancestor, excess, preferred_budget, true);
            let usage = self.subtree_memory_usage(&ancestor);
            if usage > limit {
                let excess = usage.saturating_sub(limit);
                let _ = self.reclaim_file_bytes(&ancestor, excess, hard_budget, false);
            }
            if self.subtree_memory_usage(&ancestor) > limit {
                if let Some(node) = self.nodes.get_mut(&ancestor) {
                    node.memory_events_oom = node.memory_events_oom.saturating_add(1);
                }
                return false;
            }
        }
        true
    }
}

fn live_thread_ids_for_process(tgid: usize) -> Vec<CgroupThreadId> {
    let Some(process) = pid2process(tgid) else {
        return Vec::new();
    };
    let inner = process.borrow_mut();
    inner
        .tasks
        .iter()
        .enumerate()
        .filter_map(|(tid_index, task)| {
            task.as_ref().and_then(|task| {
                task.try_borrow_mut()
                    .and_then(|inner| {
                        (inner.res.is_some() && inner.exit_code.is_none()).then_some(())
                    })
                    .map(|_| CgroupThreadId::new(tgid, tid_index))
            })
        })
        .collect()
}

fn live_process_ids() -> Vec<usize> {
    let mut pids = PID2PCB.lock().keys().copied().collect::<Vec<_>>();
    pids.sort_unstable();
    pids
}

fn visible_tid_to_thread_id(tid: usize) -> Option<CgroupThreadId> {
    if pid2process(tid).is_some() {
        return Some(CgroupThreadId::new(tid, 0));
    }
    let tgid = tid >> LINUX_TID_PID_SHIFT;
    let tid_index = decode_linux_tid_strict(tgid, tid)?;
    let process = pid2process(tgid)?;
    let inner = process.borrow_mut();
    inner
        .tasks
        .get(tid_index)
        .and_then(|task| task.as_ref())
        .and_then(|task| {
            task.try_borrow_mut().and_then(|task_inner| {
                (task_inner.res.is_some() && task_inner.exit_code.is_none()).then_some(())
            })
        })?;
    Some(CgroupThreadId::new(tgid, tid_index))
}

fn current_cgroup_thread_id() -> Option<CgroupThreadId> {
    let tgid = current_process().getpid();
    let tid_index =
        current_task().and_then(|task| task.borrow_mut().res.as_ref().map(|res| res.tid))?;
    Some(CgroupThreadId::new(tgid, tid_index))
}

fn process_sched_class(tgid: usize) -> Option<SchedClass> {
    let process = pid2process(tgid)?;
    let policy = process.borrow_mut().sched_policy;
    sched_class(policy)
}

fn parse_decimal_u64_strict(text: &str) -> Result<u64, isize> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EINVAL);
    }
    text.parse::<u64>().map_err(|_| EINVAL)
}

fn normalize_legacy_cpu_shares(value: u64) -> u64 {
    value.clamp(LEGACY_CPU_SHARES_MIN, LEGACY_CPU_SHARES_MAX)
}

fn parse_legacy_cpu_shares(text: &str) -> Result<u64, isize> {
    Ok(normalize_legacy_cpu_shares(parse_decimal_u64_strict(text)?))
}

fn parse_legacy_cpu_rt_runtime_us(text: &str, period_us: u64) -> Result<i64, isize> {
    if text == "-1" {
        return Ok(-1);
    }
    let runtime = parse_decimal_u64_strict(text)?;
    if runtime > period_us {
        return Err(EINVAL);
    }
    i64::try_from(runtime).map_err(|_| EINVAL)
}

fn parse_legacy_cpu_rt_period_us(text: &str, runtime_us: i64) -> Result<u64, isize> {
    let period = parse_decimal_u64_strict(text)?;
    if period == 0 {
        return Err(EINVAL);
    }
    if runtime_us >= 0 && u64::try_from(runtime_us).map_err(|_| EINVAL)? > period {
        return Err(EINVAL);
    }
    Ok(period)
}

fn thread_cpu_time_ns(thread_id: CgroupThreadId) -> u64 {
    let Some(process) = pid2process(thread_id.tgid) else {
        return 0;
    };
    let inner = process.borrow_mut();
    inner
        .tasks
        .get(thread_id.tid_index)
        .and_then(|task| task.as_ref())
        .map(|task| task.borrow_mut().cpu_time_ns)
        .unwrap_or(0)
}

fn path_under_mount(abs: &str, mount: &str) -> bool {
    abs == mount
        || (abs.starts_with(mount)
            && abs.as_bytes().get(mount.len()).copied().unwrap_or_default() == b'/')
}

fn normalize_rel_path(rel: &str) -> String {
    let trimmed = rel.trim_matches('/');
    if trimmed.is_empty() {
        String::from("/")
    } else {
        let mut out = String::from("/");
        out.push_str(trimmed);
        out
    }
}

fn split_rel_parent(path: &str) -> Option<(String, String)> {
    if path == "/" {
        return None;
    }
    let trimmed = path.trim_end_matches('/');
    let idx = trimmed.rfind('/')?;
    let parent = if idx == 0 {
        String::from("/")
    } else {
        String::from(&trimmed[..idx])
    };
    let name = String::from(&trimmed[idx + 1..]);
    Some((parent, name))
}

fn namespace_resolve_rel_path(ns_root: &str, mount_rel: &str) -> Option<String> {
    if ns_root == "/" {
        return Some(String::from(mount_rel));
    }
    let actual = if mount_rel == "/" {
        String::from(ns_root)
    } else {
        alloc::format!(
            "{}/{}",
            ns_root.trim_end_matches('/'),
            mount_rel.trim_start_matches('/')
        )
    };
    CgroupMountState::is_descendant_or_self(&actual, ns_root).then_some(actual)
}

fn namespace_visible_path(actual_path: &str, ns_root: &str) -> String {
    if ns_root == "/" {
        return String::from(actual_path);
    }
    if actual_path == ns_root {
        return String::from("/");
    }
    if let Some(suffix) = actual_path.strip_prefix(ns_root) {
        if suffix.starts_with('/') {
            return normalize_rel_path(suffix);
        }
    }
    String::from("/")
}

fn current_cgroup_namespace_root() -> String {
    current_process().cgroup_namespace_root()
}

fn resolve_mount_path_in_namespace(
    ns_root: &str,
    abs: &str,
) -> Result<(String, String, CgroupHierarchyKey), isize> {
    let Some((mount_target, mount_rel_path, hierarchy_key)) = split_mount_path(abs) else {
        return Err(EROFS);
    };
    let Some(rel_path) = namespace_resolve_rel_path(ns_root, &mount_rel_path) else {
        return Err(ENOENT);
    };
    Ok((mount_target, rel_path, hierarchy_key))
}

fn split_mount_path(abs: &str) -> Option<(String, String, CgroupHierarchyKey)> {
    let registry = CGROUP_REGISTRY.lock();
    let mut best: Option<(&str, &CgroupHierarchyKey)> = None;
    for (target, hierarchy_key) in registry.mounts.iter() {
        if !path_under_mount(abs, target) {
            continue;
        }
        match best {
            Some((cur, _)) if cur.len() >= target.len() => {}
            _ => best = Some((target.as_str(), hierarchy_key)),
        }
    }
    let (target, hierarchy_key) = best?;
    let rel = if abs == target {
        String::from("/")
    } else {
        normalize_rel_path(&abs[target.len()..])
    };
    Some((String::from(target), rel, hierarchy_key.clone()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CgroupFileKind {
    Controllers,
    SubtreeControl,
    Procs,
    Tasks,
    CloneChildren,
    NotifyOnRelease,
    FreezerState,
    CpuShares,
    CpuRtRuntimeUs,
    CpuRtPeriodUs,
    CpusetCpus,
    CpusetMems,
    Kill,
    PidsMax,
    PidsCurrent,
    CpuAcctUsage,
    MemoryLimitInBytes,
    MemoryUsageInBytes,
    MemoryCurrent,
    MemoryMax,
    MemorySwapMax,
    MemoryMin,
    MemoryLow,
    MemoryEvents,
    MemoryStat,
}

impl CgroupFileKind {
    fn from_name(name: &str, kind: CgroupMountKind) -> Option<Self> {
        match kind {
            CgroupMountKind::Unified => match name {
                "cgroup.controllers" => Some(Self::Controllers),
                "cgroup.subtree_control" => Some(Self::SubtreeControl),
                "cgroup.procs" => Some(Self::Procs),
                "cgroup.kill" => Some(Self::Kill),
                "pids.max" => Some(Self::PidsMax),
                "pids.current" => Some(Self::PidsCurrent),
                "memory.current" => Some(Self::MemoryCurrent),
                "memory.max" => Some(Self::MemoryMax),
                "memory.swap.max" => Some(Self::MemorySwapMax),
                "memory.min" => Some(Self::MemoryMin),
                "memory.low" => Some(Self::MemoryLow),
                "memory.events" => Some(Self::MemoryEvents),
                "memory.stat" => Some(Self::MemoryStat),
                _ => None,
            },
            kind => {
                let base = match name {
                    "tasks" => Some(Self::Tasks),
                    "cgroup.procs" => Some(Self::Procs),
                    "cgroup.clone_children" => Some(Self::CloneChildren),
                    "notify_on_release" => Some(Self::NotifyOnRelease),
                    "cpu.shares" if kind == CgroupMountKind::LegacyCpu => Some(Self::CpuShares),
                    "cpu.rt_runtime_us" if kind == CgroupMountKind::LegacyCpu => {
                        Some(Self::CpuRtRuntimeUs)
                    }
                    "cpu.rt_period_us" if kind == CgroupMountKind::LegacyCpu => {
                        Some(Self::CpuRtPeriodUs)
                    }
                    "freezer.state" if kind == CgroupMountKind::LegacyFreezer => {
                        Some(Self::FreezerState)
                    }
                    _ => None,
                };
                if base.is_some() {
                    return base;
                }
                match kind {
                    CgroupMountKind::LegacyCpuAcct if name == "cpuacct.usage" => {
                        Some(Self::CpuAcctUsage)
                    }
                    CgroupMountKind::LegacyMemory if name == "memory.limit_in_bytes" => {
                        Some(Self::MemoryLimitInBytes)
                    }
                    CgroupMountKind::LegacyMemory if name == "memory.usage_in_bytes" => {
                        Some(Self::MemoryUsageInBytes)
                    }
                    CgroupMountKind::LegacyCpuset if name == "cpuset.cpus" => {
                        Some(Self::CpusetCpus)
                    }
                    CgroupMountKind::LegacyCpuset if name == "cpuset.mems" => {
                        Some(Self::CpusetMems)
                    }
                    _ => None,
                }
            }
        }
    }

    fn mode(self) -> u32 {
        match self {
            Self::Controllers
            | Self::PidsCurrent
            | Self::CpuAcctUsage
            | Self::MemoryUsageInBytes
            | Self::MemoryCurrent
            | Self::MemoryEvents
            | Self::MemoryStat => 0o100444,
            Self::SubtreeControl
            | Self::Procs
            | Self::Tasks
            | Self::CloneChildren
            | Self::NotifyOnRelease
            | Self::FreezerState
            | Self::CpuShares
            | Self::CpuRtRuntimeUs
            | Self::CpuRtPeriodUs
            | Self::CpusetCpus
            | Self::CpusetMems
            | Self::Kill
            | Self::PidsMax
            | Self::MemoryLimitInBytes
            | Self::MemoryMax
            | Self::MemorySwapMax
            | Self::MemoryMin
            | Self::MemoryLow => 0o100644,
        }
    }
}

fn controller_mask_to_string(mask: u32) -> String {
    let mut names = Vec::new();
    if (mask & CTRL_MEMORY) != 0 {
        names.push("memory");
    }
    if (mask & CTRL_PIDS) != 0 {
        names.push("pids");
    }
    names.join(" ")
}

fn parse_controller_token(token: &str) -> Option<(bool, u32)> {
    let (enable, name) = match token.as_bytes().first().copied() {
        Some(b'+') => (true, &token[1..]),
        Some(b'-') => (false, &token[1..]),
        _ => return None,
    };
    let ctrl = match name {
        "pids" => CTRL_PIDS,
        "memory" => CTRL_MEMORY,
        _ => return None,
    };
    Some((enable, ctrl))
}

fn parse_memory_value(text: &str) -> Result<Option<usize>, isize> {
    if text == "max" {
        return Ok(None);
    }
    if text.is_empty() || text.starts_with('-') {
        return Err(EINVAL);
    }
    let (digits, multiplier) = match text.as_bytes().last().copied() {
        Some(b'K' | b'k') => (&text[..text.len() - 1], 1024usize),
        Some(b'M' | b'm') => (&text[..text.len() - 1], 1024usize * 1024),
        Some(b'G' | b'g') => (&text[..text.len() - 1], 1024usize * 1024 * 1024),
        _ => (text, 1usize),
    };
    let value = digits.parse::<usize>().map_err(|_| EINVAL)?;
    value.checked_mul(multiplier).map(Some).ok_or(EINVAL)
}

fn legacy_freezer_path_frozen(state: &CgroupMountState, path: &str) -> bool {
    if state.kind != CgroupMountKind::LegacyFreezer {
        return false;
    }
    CgroupMountState::ancestor_paths(path)
        .into_iter()
        .any(|ancestor| {
            state
                .nodes
                .get(&ancestor)
                .map(|node| node.freezer_state == LegacyFreezerState::Frozen)
                .unwrap_or(false)
        })
}

fn set_thread_freezer_state(thread_id: CgroupThreadId, frozen: bool) -> bool {
    let Some(process) = pid2process(thread_id.tgid) else {
        return false;
    };
    let task = {
        let inner = process.borrow_mut();
        inner
            .tasks
            .get(thread_id.tid_index)
            .and_then(|task| task.as_ref().cloned())
    };
    let Some(task) = task else {
        return false;
    };
    let current_thread = current_cgroup_thread_id();
    let is_current = current_thread == Some(thread_id);
    let mut inner = task.borrow_mut();
    if frozen {
        inner.cgroup_frozen = true;
        inner.wake_on_cgroup_thaw = false;
        if inner.task_status != TaskStatus::Blocked {
            inner.task_status = TaskStatus::Blocked;
            inner.parked_by_cgroup = true;
            return is_current;
        }
    }
    let should_wake = inner.parked_by_cgroup || inner.wake_on_cgroup_thaw;
    inner.cgroup_frozen = false;
    inner.parked_by_cgroup = false;
    inner.wake_on_cgroup_thaw = false;
    drop(inner);
    if should_wake {
        wakeup_task(task);
    }
    false
}

fn apply_legacy_freezer_state(
    hierarchy_key: &CgroupHierarchyKey,
    path: &str,
    frozen: bool,
) -> Result<bool, isize> {
    let mut registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get_mut(hierarchy_key) else {
        return Err(ENOENT);
    };
    if state.kind != CgroupMountKind::LegacyFreezer {
        return Err(EOPNOTSUPP);
    }
    let node = state.nodes.get_mut(path).ok_or(ENOENT)?;
    node.freezer_state = if frozen {
        LegacyFreezerState::Frozen
    } else {
        LegacyFreezerState::Thawed
    };
    let threads = state.subtree_member_threads(path);
    drop(registry);
    let mut should_block_current = false;
    for thread_id in threads {
        should_block_current |= set_thread_freezer_state(thread_id, frozen);
    }
    Ok(should_block_current)
}

pub fn cgroup_maybe_block_current() {
    let Some(task) = current_task() else {
        return;
    };
    let should_block = task
        .try_borrow_mut()
        .map(|inner| inner.cgroup_frozen && inner.parked_by_cgroup)
        .unwrap_or(false);
    if should_block {
        block_current_and_run_next();
    }
}

struct CgroupFileInner {
    offset: usize,
}

pub struct CgroupFile {
    path: String,
    hierarchy_key: CgroupHierarchyKey,
    rel_path: String,
    kind: CgroupFileKind,
    open_euid: u32,
    open_cgroup_ns_root: String,
    inner: Mutex<CgroupFileInner>,
}

impl CgroupFile {
    fn new(
        path: &str,
        hierarchy_key: CgroupHierarchyKey,
        rel_path: &str,
        kind: CgroupFileKind,
        open_euid: u32,
        open_cgroup_ns_root: &str,
    ) -> Arc<Self> {
        Arc::new(Self {
            path: String::from(path),
            hierarchy_key,
            rel_path: String::from(rel_path),
            kind,
            open_euid,
            open_cgroup_ns_root: String::from(open_cgroup_ns_root),
            inner: Mutex::new(CgroupFileInner { offset: 0 }),
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn mode(&self) -> u32 {
        self.kind.mode()
    }

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        self.inner.lock().offset = offset;
    }

    pub fn len(&self) -> usize {
        self.read_string().len()
    }

    fn read_string(&self) -> String {
        let registry = CGROUP_REGISTRY.lock();
        let Some(state) = registry.hierarchies.get(&self.hierarchy_key) else {
            return String::new();
        };
        let Some(node) = state.nodes.get(&self.rel_path) else {
            return String::new();
        };
        match self.kind {
            CgroupFileKind::Controllers => {
                controller_mask_to_string(state.available_controllers(&self.rel_path))
            }
            CgroupFileKind::SubtreeControl => controller_mask_to_string(node.subtree_control),
            CgroupFileKind::Procs => {
                let mut out = String::new();
                let members = if state.is_unified() {
                    state.direct_member_processes(&self.rel_path)
                } else {
                    state.direct_member_legacy_procs(&self.rel_path)
                };
                for pid in members {
                    out.push_str(&alloc::format!("{pid}\n"));
                }
                out
            }
            CgroupFileKind::Tasks => {
                let mut out = String::new();
                for tid in state.direct_member_threads(&self.rel_path) {
                    out.push_str(&alloc::format!("{tid}\n"));
                }
                out
            }
            CgroupFileKind::CloneChildren => {
                alloc::format!("{}\n", if node.clone_children { 1 } else { 0 })
            }
            CgroupFileKind::NotifyOnRelease => {
                alloc::format!("{}\n", if node.notify_on_release { 1 } else { 0 })
            }
            CgroupFileKind::FreezerState => alloc::format!("{}\n", node.freezer_state.as_str()),
            CgroupFileKind::CpuShares => alloc::format!("{}\n", node.cpu_shares),
            CgroupFileKind::CpuRtRuntimeUs => alloc::format!("{}\n", node.cpu_rt_runtime_us),
            CgroupFileKind::CpuRtPeriodUs => alloc::format!("{}\n", node.cpu_rt_period_us),
            CgroupFileKind::CpusetCpus => alloc::format!("{}\n", node.cpuset_cpus),
            CgroupFileKind::CpusetMems => alloc::format!("{}\n", node.cpuset_mems),
            CgroupFileKind::Kill => String::new(),
            CgroupFileKind::PidsMax => match node.pids_max {
                Some(limit) => alloc::format!("{limit}\n"),
                None => String::from("max\n"),
            },
            CgroupFileKind::PidsCurrent => {
                alloc::format!("{}\n", state.subtree_pid_count(&self.rel_path))
            }
            CgroupFileKind::CpuAcctUsage => {
                alloc::format!("{}\n", state.subtree_cpu_usage_ns(&self.rel_path))
            }
            CgroupFileKind::MemoryLimitInBytes => match node.memory_max {
                Some(limit) => alloc::format!("{limit}\n"),
                None => String::from("-1\n"),
            },
            CgroupFileKind::MemoryUsageInBytes => {
                alloc::format!("{}\n", state.subtree_memory_usage(&self.rel_path))
            }
            CgroupFileKind::MemoryCurrent => {
                alloc::format!("{}\n", state.subtree_memory_usage(&self.rel_path))
            }
            CgroupFileKind::MemoryMax => match node.memory_max {
                Some(limit) => alloc::format!("{limit}\n"),
                None => String::from("max\n"),
            },
            CgroupFileKind::MemorySwapMax => match node.memory_swap_max {
                Some(limit) => alloc::format!("{limit}\n"),
                None => String::from("max\n"),
            },
            CgroupFileKind::MemoryMin => alloc::format!("{}\n", node.memory_min),
            CgroupFileKind::MemoryLow => alloc::format!("{}\n", node.memory_low),
            CgroupFileKind::MemoryEvents => alloc::format!(
                "low {}\noom {}\n",
                node.memory_events_low,
                node.memory_events_oom
            ),
            CgroupFileKind::MemoryStat => alloc::format!(
                "anon {}\nfile {}\n",
                state.subtree_anon_bytes(&self.rel_path),
                state.subtree_file_usage(&self.rel_path)
            ),
        }
    }

    pub fn write_payload(&self, data: &[u8]) -> Result<usize, isize> {
        let raw = core::str::from_utf8(data).map_err(|_| EINVAL)?;
        let text = raw.trim_matches(|c| c == '\n' || c == '\r' || c == ' ' || c == '\t');
        if self.kind == CgroupFileKind::FreezerState {
            let should_block_current = match text {
                "THAWED" => apply_legacy_freezer_state(&self.hierarchy_key, &self.rel_path, false)?,
                "FROZEN" => apply_legacy_freezer_state(&self.hierarchy_key, &self.rel_path, true)?,
                "FREEZING" => return Err(-5),
                _ => return Err(EINVAL),
            };
            if should_block_current {
                block_current_and_run_next();
            }
            return Ok(data.len());
        }
        let mut registry = CGROUP_REGISTRY.lock();
        let Some(state) = registry.hierarchies.get_mut(&self.hierarchy_key) else {
            return Err(ENOENT);
        };
        let available = state.available_controllers(&self.rel_path);
        if !state.nodes.contains_key(&self.rel_path) {
            return Err(ENOENT);
        }
        match self.kind {
            CgroupFileKind::Controllers
            | CgroupFileKind::PidsCurrent
            | CgroupFileKind::CpuAcctUsage
            | CgroupFileKind::MemoryUsageInBytes
            | CgroupFileKind::MemoryCurrent
            | CgroupFileKind::MemoryEvents
            | CgroupFileKind::MemoryStat => Err(EROFS),
            CgroupFileKind::CloneChildren => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.clone_children = match text {
                    "0" => false,
                    "1" => true,
                    _ => return Err(EINVAL),
                };
                Ok(data.len())
            }
            CgroupFileKind::NotifyOnRelease => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.notify_on_release = match text {
                    "0" => false,
                    "1" => true,
                    _ => return Err(EINVAL),
                };
                Ok(data.len())
            }
            CgroupFileKind::FreezerState => Err(EINVAL),
            CgroupFileKind::CpuShares => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                if self.rel_path == "/" {
                    return Err(EINVAL);
                }
                node.cpu_shares = parse_legacy_cpu_shares(text)?;
                Ok(data.len())
            }
            CgroupFileKind::CpuRtRuntimeUs => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.cpu_rt_runtime_us =
                    parse_legacy_cpu_rt_runtime_us(text, node.cpu_rt_period_us)?;
                Ok(data.len())
            }
            CgroupFileKind::CpuRtPeriodUs => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.cpu_rt_period_us =
                    parse_legacy_cpu_rt_period_us(text, node.cpu_rt_runtime_us)?;
                Ok(data.len())
            }
            CgroupFileKind::CpusetCpus => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                if text.is_empty() {
                    return Err(EINVAL);
                }
                node.cpuset_cpus = text.to_string();
                Ok(data.len())
            }
            CgroupFileKind::CpusetMems => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                if text.is_empty() {
                    return Err(EINVAL);
                }
                node.cpuset_mems = text.to_string();
                Ok(data.len())
            }
            CgroupFileKind::SubtreeControl => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                if text.is_empty() {
                    return Ok(data.len());
                }
                for token in text.split_whitespace() {
                    let Some((enable, ctrl)) = parse_controller_token(token) else {
                        return Err(EOPNOTSUPP);
                    };
                    if (available & ctrl) == 0 {
                        return Err(EOPNOTSUPP);
                    }
                    if enable {
                        node.subtree_control |= ctrl;
                    } else {
                        node.subtree_control &= !ctrl;
                    }
                }
                Ok(data.len())
            }
            CgroupFileKind::PidsMax => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                if text == "max" {
                    node.pids_max = None;
                    return Ok(data.len());
                }
                if text.starts_with('-') || text.is_empty() {
                    return Err(EINVAL);
                }
                let limit = text.parse::<usize>().map_err(|_| EINVAL)?;
                node.pids_max = Some(limit);
                Ok(data.len())
            }
            CgroupFileKind::Procs => {
                let pid = if text.is_empty() {
                    current_process().getpid()
                } else {
                    match text.parse::<usize>().map_err(|_| EINVAL)? {
                        0 => current_process().getpid(),
                        pid => pid,
                    }
                };
                if pid2process(pid).is_none() {
                    return Err(ESRCH);
                }
                if state.kind == CgroupMountKind::LegacyCpu {
                    let has_rt_threads = live_thread_ids_for_process(pid)
                        .into_iter()
                        .any(|thread_id| process_sched_class(thread_id.tgid) != Some(SchedClass::Fair));
                    if has_rt_threads {
                        return Err(EINVAL);
                    }
                }
                if !CgroupMountState::is_descendant_or_self(
                    &self.rel_path,
                    &self.open_cgroup_ns_root,
                ) {
                    return Err(ENOENT);
                }
                let old_path = state.path_for_pid(pid);
                if self.open_euid != 0 && old_path != self.rel_path {
                    return Err(EACCES);
                }
                if legacy_freezer_path_frozen(state, &old_path)
                    || legacy_freezer_path_frozen(state, &self.rel_path)
                {
                    return Err(EBUSY);
                }
                for thread_id in live_thread_ids_for_process(pid) {
                    let thread_old_path = state.path_for_thread(thread_id);
                    state.flush_thread_cpu_usage(thread_id, &thread_old_path);
                }
                state.attach_process(pid, &self.rel_path);
                Ok(data.len())
            }
            CgroupFileKind::Tasks => {
                let thread_id = if text.is_empty() {
                    current_cgroup_thread_id().ok_or(ESRCH)?
                } else {
                    let raw_tid = match text.parse::<usize>().map_err(|_| EINVAL)? {
                        0 => current_cgroup_thread_id().ok_or(ESRCH)?.visible_tid(),
                        tid => tid,
                    };
                    visible_tid_to_thread_id(raw_tid).ok_or(ESRCH)?
                };
                if state.kind == CgroupMountKind::LegacyCpu
                    && process_sched_class(thread_id.tgid) != Some(SchedClass::Fair)
                {
                    return Err(EINVAL);
                }
                if !CgroupMountState::is_descendant_or_self(
                    &self.rel_path,
                    &self.open_cgroup_ns_root,
                ) {
                    return Err(ENOENT);
                }
                let old_path = state.path_for_thread(thread_id);
                if self.open_euid != 0 && old_path != self.rel_path {
                    return Err(EACCES);
                }
                if legacy_freezer_path_frozen(state, &old_path)
                    || legacy_freezer_path_frozen(state, &self.rel_path)
                {
                    return Err(EBUSY);
                }
                state.flush_thread_cpu_usage(thread_id, &old_path);
                state.attach_thread(thread_id, &self.rel_path);
                Ok(data.len())
            }
            CgroupFileKind::Kill => {
                if text != "1" {
                    return Err(EINVAL);
                }
                let victims = state
                    .process_assignments
                    .iter()
                    .filter_map(|(pid, pid_path)| {
                        CgroupMountState::is_descendant_or_self(pid_path, &self.rel_path)
                            .then_some(*pid)
                    })
                    .collect::<Vec<_>>();
                drop(registry);
                for pid in victims {
                    queue_process_signal(pid, SIGKILL_NUM);
                }
                Ok(data.len())
            }
            CgroupFileKind::MemoryMax => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.memory_max = parse_memory_value(text)?;
                Ok(data.len())
            }
            CgroupFileKind::MemoryLimitInBytes => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.memory_max = if text == "-1" {
                    None
                } else {
                    parse_memory_value(text)?
                };
                Ok(data.len())
            }
            CgroupFileKind::MemorySwapMax => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.memory_swap_max = parse_memory_value(text)?;
                Ok(data.len())
            }
            CgroupFileKind::MemoryMin => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.memory_min = parse_memory_value(text)?.unwrap_or(usize::MAX);
                Ok(data.len())
            }
            CgroupFileKind::MemoryLow => {
                let node = state.nodes.get_mut(&self.rel_path).ok_or(ENOENT)?;
                node.memory_low = parse_memory_value(text)?.unwrap_or(usize::MAX);
                Ok(data.len())
            }
        }
    }
}

impl File for CgroupFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        !matches!(
            self.kind,
            CgroupFileKind::Controllers
                | CgroupFileKind::PidsCurrent
                | CgroupFileKind::CpuAcctUsage
                | CgroupFileKind::MemoryUsageInBytes
                | CgroupFileKind::MemoryCurrent
                | CgroupFileKind::MemoryEvents
                | CgroupFileKind::MemoryStat
        )
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let data = self.read_string();
        let bytes = data.as_bytes();
        let mut inner = self.inner.lock();
        if inner.offset >= bytes.len() {
            return 0;
        }
        let mut total = 0usize;
        for slice in buf.buffers.iter_mut() {
            if inner.offset >= bytes.len() {
                break;
            }
            let n = core::cmp::min(slice.len(), bytes.len() - inner.offset);
            slice[..n].copy_from_slice(&bytes[inner.offset..inner.offset + n]);
            inner.offset += n;
            total += n;
            if n < slice.len() {
                break;
            }
        }
        total
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn build_dir_entries(rel_path: &str, ns_root: &str, state: &CgroupMountState) -> Vec<PseudoDirent> {
    let ino = state.nodes.get(rel_path).map(|node| node.ino).unwrap_or(1);
    let parent_ino = if rel_path == "/" || rel_path == ns_root {
        ino
    } else {
        split_rel_parent(rel_path)
            .and_then(|(parent, _)| state.nodes.get(&parent).map(|node| node.ino))
            .unwrap_or(ino)
    };
    let mut entries = Vec::new();
    entries.push(PseudoDirent {
        name: String::from("."),
        ino,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from(".."),
        ino: parent_ino,
        dtype: 4,
    });
    for child in state.direct_children(rel_path) {
        let child_path = if rel_path == "/" {
            alloc::format!("/{child}")
        } else {
            alloc::format!("{rel_path}/{child}")
        };
        let child_ino = state
            .nodes
            .get(&child_path)
            .map(|node| node.ino)
            .unwrap_or(1);
        entries.push(PseudoDirent {
            name: child,
            ino: child_ino,
            dtype: 4,
        });
    }
    let file_names: &[&str] = match state.kind {
        CgroupMountKind::Unified => &[
            "cgroup.controllers",
            "cgroup.subtree_control",
            "cgroup.procs",
            "cgroup.kill",
            "pids.max",
            "pids.current",
            "memory.current",
            "memory.max",
            "memory.swap.max",
            "memory.min",
            "memory.low",
            "memory.events",
            "memory.stat",
        ],
        CgroupMountKind::LegacyCpuAcct => &[
            "tasks",
            "cgroup.procs",
            "cgroup.clone_children",
            "notify_on_release",
            "cpuacct.usage",
        ],
        CgroupMountKind::LegacyCpu => &[
            "tasks",
            "cgroup.procs",
            "cgroup.clone_children",
            "notify_on_release",
            "cpu.shares",
            "cpu.rt_runtime_us",
            "cpu.rt_period_us",
        ],
        CgroupMountKind::LegacyFreezer => &[
            "tasks",
            "cgroup.procs",
            "cgroup.clone_children",
            "notify_on_release",
            "freezer.state",
        ],
        CgroupMountKind::LegacyMemory => &[
            "tasks",
            "cgroup.procs",
            "cgroup.clone_children",
            "notify_on_release",
            "memory.limit_in_bytes",
            "memory.usage_in_bytes",
        ],
        CgroupMountKind::LegacyCpuset => &[
            "tasks",
            "cgroup.procs",
            "cgroup.clone_children",
            "notify_on_release",
            "cpuset.cpus",
            "cpuset.mems",
        ],
        _ => &[
            "tasks",
            "cgroup.procs",
            "cgroup.clone_children",
            "notify_on_release",
        ],
    };
    for name in file_names {
        entries.push(PseudoDirent {
            name: String::from(*name),
            ino: NEXT_CGROUP_INO.fetch_add(1, Ordering::Relaxed),
            dtype: 8,
        });
    }
    entries
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
