use super::*;

#[derive(Clone)]
pub(crate) struct CgroupMountState {
    pub(crate) kind: CgroupMountKind,
    pub(crate) nodes: BTreeMap<String, CgroupNode>,
    pub(crate) process_assignments: BTreeMap<usize, String>,
    pub(crate) thread_assignments: BTreeMap<CgroupThreadId, String>,
    pub(crate) process_anon_bytes: BTreeMap<usize, BTreeMap<String, usize>>,
    pub(crate) thread_cpu_account_ns: BTreeMap<CgroupThreadId, u64>,
}

impl CgroupMountState {
    pub(crate) fn new(kind: CgroupMountKind) -> Self {
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

    pub(crate) fn is_unified(&self) -> bool {
        matches!(self.kind, CgroupMountKind::Unified)
    }

    pub(crate) fn direct_children(&self, path: &str) -> Vec<String> {
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

    pub(crate) fn is_descendant_or_self(path: &str, ancestor: &str) -> bool {
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

    pub(crate) fn direct_member_processes(&self, path: &str) -> Vec<usize> {
        let mut pids = self
            .process_assignments
            .iter()
            .filter_map(|(pid, pid_path)| (*pid_path == path).then_some(*pid))
            .collect::<Vec<_>>();
        pids.sort_unstable();
        pids
    }

    pub(crate) fn direct_member_threads(&self, path: &str, pid_ns_id: usize) -> Vec<usize> {
        let mut tids = self
            .thread_assignments
            .iter()
            .filter_map(|(thread_id, thread_path)| {
                if *thread_path != path {
                    return None;
                }
                thread_id.visible_tid(pid_ns_id)
            })
            .collect::<Vec<_>>();
        tids.sort_unstable();
        tids
    }

    pub(crate) fn direct_member_legacy_procs(&self, path: &str, pid_ns_id: usize) -> Vec<usize> {
        self.thread_assignments
            .iter()
            .filter_map(|(thread_id, thread_path)| {
                if *thread_path != path {
                    return None;
                }
                visible_pid_in_namespace(thread_id.tgid, pid_ns_id)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(crate) fn subtree_member_threads(&self, path: &str) -> Vec<CgroupThreadId> {
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

    pub(crate) fn subtree_pid_count(&self, path: &str) -> usize {
        self.nodes
            .get(path)
            .map(|node| node.subtree_thread_count)
            .unwrap_or(0)
    }

    pub(crate) fn ancestor_paths(path: &str) -> Vec<String> {
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

    pub(crate) fn available_controllers(&self, path: &str) -> u32 {
        if path == "/" {
            return ROOT_CONTROLLERS;
        }
        split_rel_parent(path)
            .and_then(|(parent, _)| self.nodes.get(&parent).map(|node| node.subtree_control))
            .unwrap_or(0)
    }

    pub(crate) fn path_for_pid(&self, pid: usize) -> String {
        self.process_assignments
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| String::from("/"))
    }

    pub(crate) fn path_for_thread(&self, thread_id: CgroupThreadId) -> String {
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

    pub(crate) fn set_thread_assignment(&mut self, thread_id: CgroupThreadId, path: &str) {
        let new_path = String::from(path);
        let old_path = self.thread_assignments.insert(thread_id, new_path.clone());
        if old_path.as_deref() != Some(new_path.as_str()) {
            if let Some(old_path) = old_path {
                self.adjust_subtree_thread_count(&old_path, false);
            }
            self.adjust_subtree_thread_count(&new_path, true);
        }
    }

    pub(crate) fn attach_process(&mut self, pid: usize, path: &str) {
        self.process_assignments.insert(pid, String::from(path));
        for thread_id in live_thread_ids_for_process(pid) {
            self.set_thread_assignment(thread_id, path);
            self.thread_cpu_account_ns
                .insert(thread_id, thread_cpu_time_ns(thread_id));
        }
    }

    pub(crate) fn attach_thread(&mut self, thread_id: CgroupThreadId, path: &str) {
        self.set_thread_assignment(thread_id, path);
        self.thread_cpu_account_ns
            .insert(thread_id, thread_cpu_time_ns(thread_id));
    }

    pub(crate) fn remove_thread(&mut self, thread_id: CgroupThreadId) {
        if let Some(old_path) = self.thread_assignments.remove(&thread_id) {
            self.adjust_subtree_thread_count(&old_path, false);
        }
        self.thread_cpu_account_ns.remove(&thread_id);
    }

    pub(crate) fn seed_root_membership(&mut self) {
        for pid in live_process_ids() {
            self.attach_process(pid, "/");
        }
    }

    pub(crate) fn subtree_anon_bytes(&self, path: &str) -> usize {
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

    pub(crate) fn subtree_file_bytes(&self, path: &str) -> usize {
        self.nodes
            .iter()
            .filter_map(|(node_path, node)| {
                Self::is_descendant_or_self(node_path, path).then_some(node.local_file_bytes)
            })
            .sum()
    }

    pub(crate) fn subtree_memory_usage(&self, path: &str) -> usize {
        self.subtree_anon_bytes(path)
            .saturating_add(self.subtree_file_bytes(path))
    }

    pub(crate) fn subtree_cpu_usage_ns(&self, path: &str) -> u64 {
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

    pub(crate) fn flush_thread_cpu_usage(&mut self, thread_id: CgroupThreadId, path: &str) {
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

    pub(crate) fn subtree_file_usage(&self, path: &str) -> usize {
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

    pub(crate) fn enforce_memory_limits(&mut self, path: &str) -> bool {
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
