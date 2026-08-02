use super::*;

#[derive(Clone)]
pub(crate) struct CgroupNode {
    pub(crate) ino: u64,
    pub(crate) mode: u16,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// Stable kernfs-like identities and inode attributes for control files.
    pub(crate) control_nodes: BTreeMap<String, CgroupControlNode>,
    pub(crate) subtree_control: u32,
    pub(crate) clone_children: bool,
    pub(crate) notify_on_release: bool,
    pub(crate) freezer_state: LegacyFreezerState,
    pub(crate) cpu_shares: u64,
    pub(crate) cpu_rt_runtime_us: i64,
    pub(crate) cpu_rt_period_us: u64,
    pub(crate) cpuset_cpus: String,
    pub(crate) cpuset_mems: String,
    pub(crate) pids_max: Option<usize>,
    pub(crate) memory_max: Option<usize>,
    pub(crate) memory_swap_max: Option<usize>,
    pub(crate) memory_min: usize,
    pub(crate) memory_low: usize,
    pub(crate) memory_events_low: usize,
    pub(crate) memory_events_oom: usize,
    pub(crate) local_file_bytes: usize,
    pub(crate) local_cpu_usage_ns: u64,
    pub(crate) subtree_thread_count: usize,
}

impl CgroupNode {
    pub(crate) fn new() -> Self {
        Self::new_with_mode(0o755)
    }

    pub(crate) fn new_with_mode(mode: u16) -> Self {
        Self {
            ino: NEXT_CGROUP_INO.fetch_add(1, Ordering::Relaxed),
            mode: mode & 0o7777,
            uid: 0,
            gid: 0,
            control_nodes: BTreeMap::new(),
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

#[derive(Clone)]
pub(crate) struct CgroupControlNode {
    pub(crate) ino: u64,
    pub(crate) mode: u16,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

impl CgroupControlNode {
    pub(crate) fn new(mode: u16) -> Self {
        Self {
            ino: NEXT_CGROUP_INO.fetch_add(1, Ordering::Relaxed),
            mode: mode & 0o7777,
            uid: 0,
            gid: 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyFreezerState {
    Thawed,
    Frozen,
}

impl LegacyFreezerState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Thawed => "THAWED",
            Self::Frozen => "FROZEN",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CgroupThreadId {
    pub(crate) tgid: usize,
    pub(crate) tid_index: usize,
}

impl CgroupThreadId {
    pub(crate) fn new(tgid: usize, tid_index: usize) -> Self {
        Self { tgid, tid_index }
    }

    pub(crate) fn visible_tid(self, pid_ns_id: usize) -> Option<usize> {
        visible_tid_in_pid_namespace(self, pid_ns_id)
    }
}
