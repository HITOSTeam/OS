use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CgroupFileKind {
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
    pub(crate) fn from_name(name: &str, kind: CgroupMountKind) -> Option<Self> {
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

    pub(crate) fn mode(self) -> u32 {
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

pub(crate) struct CgroupFileInner {
    pub(crate) offset: usize,
}

pub struct CgroupFile {
    path: String,
    pub(crate) hierarchy_key: CgroupHierarchyKey,
    pub(crate) rel_path: String,
    pub(crate) kind: CgroupFileKind,
    open_euid: u32,
    open_cgroup_ns_root: String,
    inner: Mutex<CgroupFileInner>,
}

impl CgroupFile {
    pub(crate) fn new(
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
                let pid_ns_id = current_process().pid_namespace_id();
                let mut out = String::new();
                let members = if state.is_unified() {
                    state
                        .direct_member_processes(&self.rel_path)
                        .into_iter()
                        .filter_map(|pid| visible_pid_in_namespace(pid, pid_ns_id))
                        .collect::<Vec<_>>()
                } else {
                    state.direct_member_legacy_procs(&self.rel_path, pid_ns_id)
                };
                for pid in members {
                    out.push_str(&alloc::format!("{pid}\n"));
                }
                out
            }
            CgroupFileKind::Tasks => {
                let pid_ns_id = current_process().pid_namespace_id();
                let mut out = String::new();
                for tid in state.direct_member_threads(&self.rel_path, pid_ns_id) {
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
                let affected = descendant_processes(state, &self.rel_path);
                drop(registry);
                for pid in affected {
                    if let Some(process) = pid2process(pid) {
                        refresh_process_legacy_cpu_fair_group_cache(&process);
                        refresh_process_runqueues(&process);
                    }
                }
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
                let pid_ns_id = current_process().pid_namespace_id();
                let pid = if text.is_empty() {
                    current_process().getpid()
                } else {
                    match text.parse::<usize>().map_err(|_| EINVAL)? {
                        0 => current_process().getpid(),
                        visible_pid => {
                            let process = resolve_process_in_pid_namespace(pid_ns_id, visible_pid)
                                .ok_or(ESRCH)?;
                            process.getpid()
                        }
                    }
                };
                if pid2process(pid).is_none() {
                    return Err(ESRCH);
                }
                if state.kind == CgroupMountKind::LegacyCpu {
                    let has_rt_threads =
                        live_thread_ids_for_process(pid)
                            .into_iter()
                            .any(|thread_id| {
                                process_sched_class(thread_id.tgid) != Some(SchedClass::Fair)
                            });
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
                let should_refresh = state.kind == CgroupMountKind::LegacyCpu;
                drop(registry);
                if should_refresh {
                    if let Some(process) = pid2process(pid) {
                        refresh_process_legacy_cpu_fair_group_cache(&process);
                        refresh_process_runqueues(&process);
                    }
                }
                Ok(data.len())
            }
            CgroupFileKind::Tasks => {
                let pid_ns_id = current_process().pid_namespace_id();
                let thread_id = if text.is_empty() {
                    current_cgroup_thread_id().ok_or(ESRCH)?
                } else {
                    let raw_tid = match text.parse::<usize>().map_err(|_| EINVAL)? {
                        0 => current_cgroup_thread_id()
                            .and_then(|thread_id| thread_id.visible_tid(pid_ns_id))
                            .ok_or(ESRCH)?,
                        tid => tid,
                    };
                    visible_tid_to_thread_id(pid_ns_id, raw_tid).ok_or(ESRCH)?
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
                let should_refresh = state.kind == CgroupMountKind::LegacyCpu;
                drop(registry);
                if should_refresh {
                    if let Some(process) = pid2process(thread_id.tgid) {
                        refresh_process_legacy_cpu_fair_group_cache(&process);
                        refresh_process_runqueues(&process);
                    }
                }
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
        buf.for_each_chunk_mut(|slice| {
            if inner.offset >= bytes.len() {
                return false;
            }
            let n = core::cmp::min(slice.len(), bytes.len() - inner.offset);
            slice[..n].copy_from_slice(&bytes[inner.offset..inner.offset + n]);
            inner.offset += n;
            total += n;
            n == slice.len()
        });
        total
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) fn build_dir_entries(
    rel_path: &str,
    ns_root: &str,
    state: &CgroupMountState,
) -> Vec<PseudoDirent> {
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
