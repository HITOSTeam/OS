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
use crate::task::manager::pid2process;

const EEXIST: isize = -17;
const EINVAL: isize = -22;
const ENOENT: isize = -2;
const ENOTDIR: isize = -20;
const ENOTEMPTY: isize = -39;
const EBUSY: isize = -16;
const EAGAIN: isize = -11;
const ESRCH: isize = -3;
const EROFS: isize = -30;
const EOPNOTSUPP: isize = -95;

static NEXT_CGROUP_INO: AtomicU64 = AtomicU64::new(0x63_0000);

lazy_static! {
    static ref CGROUP_MOUNTS: Mutex<BTreeMap<String, CgroupMountState>> = Mutex::new(BTreeMap::new());
}

const CTRL_PIDS: u32 = 1 << 0;
const CTRL_MEMORY: u32 = 1 << 1;
const ROOT_CONTROLLERS: u32 = CTRL_PIDS | CTRL_MEMORY;

#[derive(Clone)]
struct CgroupNode {
    ino: u64,
    subtree_control: u32,
    pids_max: Option<usize>,
    memory_max: Option<usize>,
    memory_swap_max: Option<usize>,
    memory_min: usize,
    memory_low: usize,
    memory_events_low: usize,
    memory_events_oom: usize,
    local_file_bytes: usize,
}

impl CgroupNode {
    fn new() -> Self {
        Self {
            ino: NEXT_CGROUP_INO.fetch_add(1, Ordering::Relaxed),
            subtree_control: 0,
            pids_max: None,
            memory_max: None,
            memory_swap_max: None,
            memory_min: 0,
            memory_low: 0,
            memory_events_low: 0,
            memory_events_oom: 0,
            local_file_bytes: 0,
        }
    }
}

#[derive(Clone)]
struct CgroupMountState {
    nodes: BTreeMap<String, CgroupNode>,
    assignments: BTreeMap<usize, String>,
    process_anon_bytes: BTreeMap<usize, usize>,
}

impl CgroupMountState {
    fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(String::from("/"), CgroupNode::new());
        Self {
            nodes,
            assignments: BTreeMap::new(),
            process_anon_bytes: BTreeMap::new(),
        }
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

    fn direct_member_pids(&self, path: &str) -> Vec<usize> {
        let mut pids = self
            .assignments
            .iter()
            .filter_map(|(pid, pid_path)| (*pid_path == path).then_some(*pid))
            .collect::<Vec<_>>();
        pids.sort_unstable();
        pids
    }

    fn subtree_pid_count(&self, path: &str) -> usize {
        self.assignments
            .values()
            .filter(|pid_path| Self::is_descendant_or_self(pid_path, path))
            .count()
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
        self.assignments
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| String::from("/"))
    }

    fn subtree_anon_bytes(&self, path: &str) -> usize {
        self.process_anon_bytes
            .iter()
            .filter_map(|(pid, bytes)| {
                let pid_path = self.assignments.get(pid).map(|s| s.as_str()).unwrap_or("/");
                Self::is_descendant_or_self(pid_path, path).then_some(*bytes)
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
        let budgets = Self::distribute_weighted_budget(protection_inputs.as_slice(), protected_budget);
        let child_budget_total = budgets.values().copied().sum::<usize>();
        let local_file_bytes = self
            .nodes
            .get(path)
            .map(|node| node.local_file_bytes)
            .unwrap_or(0);
        let local_reclaimable = local_file_bytes.min(current_usage.saturating_sub(protected_budget));
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
        let remaining_reclaimable =
            reclaimable_inputs.iter().map(|(_, weight)| *weight).sum::<usize>().saturating_sub(need);
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

fn path_under_mount(abs: &str, mount: &str) -> bool {
    abs == mount
        || (abs.starts_with(mount)
            && abs
                .as_bytes()
                .get(mount.len())
                .copied()
                .unwrap_or_default()
                == b'/')
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

fn split_mount_path(abs: &str) -> Option<(String, String)> {
    let mounts = CGROUP_MOUNTS.lock();
    let mut best: Option<&str> = None;
    for target in mounts.keys() {
        if !path_under_mount(abs, target) {
            continue;
        }
        match best {
            Some(cur) if cur.len() >= target.len() => {}
            _ => best = Some(target.as_str()),
        }
    }
    let target = best?;
    let rel = if abs == target {
        String::from("/")
    } else {
        normalize_rel_path(&abs[target.len()..])
    };
    Some((String::from(target), rel))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CgroupFileKind {
    Controllers,
    SubtreeControl,
    Procs,
    PidsMax,
    PidsCurrent,
    MemoryCurrent,
    MemoryMax,
    MemorySwapMax,
    MemoryMin,
    MemoryLow,
    MemoryEvents,
    MemoryStat,
}

impl CgroupFileKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "cgroup.controllers" => Some(Self::Controllers),
            "cgroup.subtree_control" => Some(Self::SubtreeControl),
            "cgroup.procs" => Some(Self::Procs),
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
        }
    }

    fn mode(self) -> u32 {
        match self {
            Self::Controllers
            | Self::PidsCurrent
            | Self::MemoryCurrent
            | Self::MemoryEvents
            | Self::MemoryStat => 0o100444,
            Self::SubtreeControl
            | Self::Procs
            | Self::PidsMax
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

struct CgroupFileInner {
    offset: usize,
}

pub struct CgroupFile {
    path: String,
    mount_target: String,
    rel_path: String,
    kind: CgroupFileKind,
    inner: Mutex<CgroupFileInner>,
}

impl CgroupFile {
    fn new(path: &str, mount_target: &str, rel_path: &str, kind: CgroupFileKind) -> Arc<Self> {
        Arc::new(Self {
            path: String::from(path),
            mount_target: String::from(mount_target),
            rel_path: String::from(rel_path),
            kind,
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
        let mounts = CGROUP_MOUNTS.lock();
        let Some(state) = mounts.get(&self.mount_target) else {
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
                for pid in state.direct_member_pids(&self.rel_path) {
                    out.push_str(&alloc::format!("{pid}\n"));
                }
                out
            }
            CgroupFileKind::PidsMax => match node.pids_max {
                Some(limit) => alloc::format!("{limit}\n"),
                None => String::from("max\n"),
            },
            CgroupFileKind::PidsCurrent => {
                alloc::format!("{}\n", state.subtree_pid_count(&self.rel_path))
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
        let mut mounts = CGROUP_MOUNTS.lock();
        let Some(state) = mounts.get_mut(&self.mount_target) else {
            return Err(ENOENT);
        };
        let available = state.available_controllers(&self.rel_path);
        let Some(node) = state.nodes.get_mut(&self.rel_path) else {
            return Err(ENOENT);
        };
        match self.kind {
            CgroupFileKind::Controllers
            | CgroupFileKind::PidsCurrent
            | CgroupFileKind::MemoryCurrent
            | CgroupFileKind::MemoryEvents
            | CgroupFileKind::MemoryStat => Err(EROFS),
            CgroupFileKind::SubtreeControl => {
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
                if text.is_empty() {
                    return Err(EINVAL);
                }
                let pid = text.parse::<usize>().map_err(|_| EINVAL)?;
                if pid2process(pid).is_none() {
                    return Err(ESRCH);
                }
                state.assignments.insert(pid, self.rel_path.clone());
                Ok(data.len())
            }
            CgroupFileKind::MemoryMax => {
                node.memory_max = parse_memory_value(text)?;
                Ok(data.len())
            }
            CgroupFileKind::MemorySwapMax => {
                node.memory_swap_max = parse_memory_value(text)?;
                Ok(data.len())
            }
            CgroupFileKind::MemoryMin => {
                node.memory_min = parse_memory_value(text)?.unwrap_or(usize::MAX);
                Ok(data.len())
            }
            CgroupFileKind::MemoryLow => {
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

fn build_dir_entries(abs: &str, target: &str, rel_path: &str, state: &CgroupMountState) -> Vec<PseudoDirent> {
    let ino = state.nodes.get(rel_path).map(|node| node.ino).unwrap_or(1);
    let parent_ino = if rel_path == "/" {
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
        let child_ino = state.nodes.get(&child_path).map(|node| node.ino).unwrap_or(1);
        entries.push(PseudoDirent {
            name: child,
            ino: child_ino,
            dtype: 4,
        });
    }
    for name in [
        "cgroup.controllers",
        "cgroup.subtree_control",
        "cgroup.procs",
        "pids.max",
        "pids.current",
        "memory.current",
        "memory.max",
        "memory.swap.max",
        "memory.min",
        "memory.low",
        "memory.events",
        "memory.stat",
    ] {
        entries.push(PseudoDirent {
            name: String::from(name),
            ino: NEXT_CGROUP_INO.fetch_add(1, Ordering::Relaxed),
            dtype: 8,
        });
    }
    let _ = (abs, target);
    entries
}

pub fn cgroup_mount(target: &str) -> isize {
    let mut mounts = CGROUP_MOUNTS.lock();
    if mounts.contains_key(target) {
        return EBUSY;
    }
    mounts.insert(String::from(target), CgroupMountState::new());
    0
}

pub fn cgroup_umount(target: &str) -> isize {
    let mut mounts = CGROUP_MOUNTS.lock();
    mounts.remove(target);
    0
}

pub fn is_cgroup_pseudo_path(abs: &str) -> bool {
    split_mount_path(abs).is_some()
}

pub fn open_cgroup_pseudo(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let (mount_target, rel_path) = split_mount_path(path)?;
    let mounts = CGROUP_MOUNTS.lock();
    let state = mounts.get(&mount_target)?;
    if state.nodes.contains_key(&rel_path) {
        let entries = build_dir_entries(path, &mount_target, &rel_path, state);
        return Some(Arc::new(PseudoDir::new(path, entries)));
    }
    let (parent, name) = split_rel_parent(&rel_path)?;
    state.nodes.get(&parent)?;
    let kind = CgroupFileKind::from_name(&name)?;
    Some(CgroupFile::new(path, &mount_target, &parent, kind))
}

pub fn cgroup_mkdir(abs: &str) -> isize {
    let Some((mount_target, rel_path)) = split_mount_path(abs) else {
        return EROFS;
    };
    if rel_path == "/" {
        return EEXIST;
    }
    let Some((parent, _name)) = split_rel_parent(&rel_path) else {
        return EINVAL;
    };
    let mut mounts = CGROUP_MOUNTS.lock();
    let Some(state) = mounts.get_mut(&mount_target) else {
        return ENOENT;
    };
    if !state.nodes.contains_key(&parent) {
        return ENOENT;
    }
    if state.nodes.contains_key(&rel_path) {
        return EEXIST;
    }
    state.nodes.insert(rel_path, CgroupNode::new());
    0
}

pub fn cgroup_rmdir(abs: &str) -> isize {
    let Some((mount_target, rel_path)) = split_mount_path(abs) else {
        return EROFS;
    };
    if rel_path == "/" {
        return EBUSY;
    }
    let mut mounts = CGROUP_MOUNTS.lock();
    let Some(state) = mounts.get_mut(&mount_target) else {
        return ENOENT;
    };
    if !state.nodes.contains_key(&rel_path) {
        return ENOENT;
    }
    if !state.direct_children(&rel_path).is_empty() {
        return ENOTEMPTY;
    }
    if state.assignments.values().any(|path| path == &rel_path) {
        return EBUSY;
    }
    state.nodes.remove(&rel_path);
    0
}

pub fn cgroup_proc_cgroups_content() -> String {
    String::from("#subsys_name\thierarchy\tnum_cgroups\tenabled\nmemory\t0\t1\t1\npids\t0\t1\t1\n")
}

pub fn cgroup_proc_pid_content(pid: usize) -> String {
    let mounts = CGROUP_MOUNTS.lock();
    let Some((_target, state)) = mounts.iter().next() else {
        return String::from("0::/\n");
    };
    let path = state
        .assignments
        .get(&pid)
        .cloned()
        .unwrap_or_else(|| String::from("/"));
    alloc::format!("0::{path}\n")
}

pub fn cgroup_fork_precheck(parent_pid: usize) -> Result<(), isize> {
    let mounts = CGROUP_MOUNTS.lock();
    for state in mounts.values() {
        let Some(path) = state.assignments.get(&parent_pid) else {
            continue;
        };
        for ancestor in CgroupMountState::ancestor_paths(path) {
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
    let mut mounts = CGROUP_MOUNTS.lock();
    for state in mounts.values_mut() {
        if let Some(path) = state.assignments.get(&parent_pid).cloned() {
            state.assignments.insert(child_pid, path);
        }
    }
}

pub fn cgroup_exit_process(pid: usize) {
    let mut mounts = CGROUP_MOUNTS.lock();
    for state in mounts.values_mut() {
        state.assignments.remove(&pid);
        state.process_anon_bytes.remove(&pid);
    }
}

pub fn cgroup_charge_anon_current(pid: usize, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }
    let mut mounts = CGROUP_MOUNTS.lock();
    for state in mounts.values_mut() {
        let path = state.path_for_pid(pid);
        let previous = state.process_anon_bytes.get(&pid).copied().unwrap_or(0);
        state
            .process_anon_bytes
            .insert(pid, previous.saturating_add(bytes));
        if !state.enforce_memory_limits(&path) {
            if previous == 0 {
                state.process_anon_bytes.remove(&pid);
            } else {
                state.process_anon_bytes.insert(pid, previous);
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
    let mut mounts = CGROUP_MOUNTS.lock();
    for state in mounts.values_mut() {
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
