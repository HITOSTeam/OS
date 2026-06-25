use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use super::File;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountPropagation {
    Private,
    Shared,
    Slave,
    Unbindable,
}

/// One mount entry visible inside a mount namespace.
#[derive(Clone, Debug)]
pub(crate) struct MountRecord {
    /// Logical mount point seen by processes, e.g. `/proc` or `/mnt`.
    pub(crate) target: String,
    /// Internal source path used for path translation in this kernel.
    pub(crate) source: String,
    /// Source name shown to userspace in `/proc/*/mountinfo`.
    pub(crate) source_display: String,
    /// Filesystem type name, e.g. `ext4`, `proc`, `tmpfs`, or `cgroup2`.
    pub(crate) fs_type: String,
    /// Linux mount flags such as `MS_RDONLY`, `MS_NOSUID`, or propagation flags.
    pub(crate) flags: usize,
    /// Monotonic order for mounts stacked on the same target; larger wins lookups.
    pub(crate) stack_seq: usize,
    /// Shared event id for mount records created by the same propagated mount operation.
    pub(crate) event_id: usize,
    /// Mount propagation mode controlling whether mount events spread to peers/slaves.
    pub(crate) propagation: MountPropagation,
    /// Shared peer group id for `MS_SHARED` mounts.
    pub(crate) peer_group_id: Option<usize>,
    /// Upstream peer group id followed by `MS_SLAVE` mounts.
    pub(crate) master_group_id: Option<usize>,
    /// Access counter used by lazy unmount expiry bookkeeping.
    pub(crate) access_seq: usize,
    /// Last access counter value observed when this mount was marked for expiry.
    pub(crate) expire_mark_seq: Option<usize>,
}

pub(crate) type MountNamespace = Arc<Mutex<MountNamespaceState>>;

#[derive(Clone, Debug, PartialEq, Eq)]
/// whether a path is psudo file or real file
pub(crate) enum ClassifiedAbsPath {
    Ext4(String),
    Pseudo(String),
}

pub(crate) struct MountNamespaceState {
    id: usize,
    mounts: Vec<MountRecord>,
    rofs_mounts: Vec<String>,
    file_binds: BTreeMap<String, Arc<dyn File + Send + Sync>>,
}

impl MountNamespaceState {
    fn new(id: usize) -> Self {
        Self {
            id,
            mounts: Vec::new(),
            rofs_mounts: Vec::new(),
            file_binds: BTreeMap::new(),
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

    pub(crate) fn bound_file_for_path(&self, abs: &str) -> Option<Arc<dyn File + Send + Sync>> {
        self.file_binds.get(abs).cloned()
    }

    pub(crate) fn bind_file(&mut self, target: &str, file: Arc<dyn File + Send + Sync>) {
        self.file_binds.insert(String::from(target), file);
    }

    pub(crate) fn remove_bound_file(&mut self, target: &str) {
        self.file_binds.remove(target);
    }

    pub(crate) fn top_mount_index_for_target(&self, target: &str) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for (idx, mount) in self.mounts.iter().enumerate() {
            if mount.target != target {
                continue;
            }
            match best {
                Some((_, cur_seq)) if mount.stack_seq <= cur_seq => {}
                _ => best = Some((idx, mount.stack_seq)),
            }
        }
        best.map(|(idx, _)| idx)
    }

    pub(crate) fn mount_record_for_target(&self, target: &str) -> Option<MountRecord> {
        let idx = self.top_mount_index_for_target(target)?;
        Some(self.mounts[idx].clone())
    }

    pub(crate) fn mount_record_for_path(&self, abs: &str) -> Option<MountRecord> {
        let mut best: Option<MountRecord> = None;
        for mount in &self.mounts {
            if !path_under_mount(abs, &mount.target) {
                continue;
            }
            match best.as_ref() {
                Some(cur) if !mount_target_match_better(mount, cur) => {}
                _ => best = Some(mount.clone()),
            }
        }
        best
    }

    pub(crate) fn mount_record_for_source_path(&self, abs: &str) -> Option<MountRecord> {
        let mut best: Option<MountRecord> = None;
        for mount in &self.mounts {
            if !path_under_mount(abs, &mount.source) {
                continue;
            }
            match best.as_ref() {
                Some(cur) if !mount_source_match_better(mount, cur) => {}
                _ => best = Some(mount.clone()),
            }
        }
        best
    }

    pub(crate) fn mount_flags_for_path(&self, abs: &str) -> usize {
        self.mount_record_for_path(abs)
            .map(|mount| mount.flags)
            .unwrap_or(0)
    }

    pub(crate) fn classify_logical_abs_path(&self, abs: &str) -> ClassifiedAbsPath {
        if self.bound_file_for_path(abs).is_some() {
            return ClassifiedAbsPath::Pseudo(String::from(abs));
        }
        if super::procfs::is_proc_pseudo_path(abs)
            || super::cgroupfs::is_cgroup_pseudo_path(abs)
            || super::is_builtin_pseudo_path(abs)
        {
            return ClassifiedAbsPath::Pseudo(String::from(abs));
        }
        if self
            .mount_record_for_path(abs)
            .is_some_and(|mount| mount.fs_type == "cgroup" || mount.fs_type == "cgroup2")
        {
            return ClassifiedAbsPath::Pseudo(String::from(abs));
        }
        ClassifiedAbsPath::Ext4(self.translate_mount_abs(abs))
    }

    pub(crate) fn translate_mount_abs(&self, abs: &str) -> String {
        let Some(mount) = self.mount_record_for_path(abs) else {
            return String::from(abs);
        };
        let suffix = if abs == mount.target {
            ""
        } else {
            &abs[mount.target.len()..]
        };
        mount_path_join(&mount.source, suffix)
    }

    pub(crate) fn display_mount_abs(&self, abs: &str) -> String {
        let Some(mount) = self.mount_record_for_source_path(abs) else {
            return String::from(abs);
        };
        let suffix = if abs == mount.source {
            ""
        } else {
            &abs[mount.source.len()..]
        };
        mount_path_join(&mount.target, suffix)
    }

    pub(crate) fn note_mount_access(&mut self, abs: &str) {
        let mut best: Option<(usize, usize, usize)> = None;
        for (idx, mount) in self.mounts.iter().enumerate() {
            if !path_under_mount(abs, &mount.target) {
                continue;
            }
            match best {
                Some((_, cur_len, cur_seq))
                    if mount.target.len() < cur_len
                        || (mount.target.len() == cur_len && mount.stack_seq <= cur_seq) => {}
                _ => best = Some((idx, mount.target.len(), mount.stack_seq)),
            }
        }
        if let Some((idx, _, _)) = best {
            self.mounts[idx].access_seq = self.mounts[idx].access_seq.saturating_add(1);
        }
    }

    pub(crate) fn top_mounts(&self) -> Vec<MountRecord> {
        let mut tops: BTreeMap<String, MountRecord> = BTreeMap::new();
        for mount in &self.mounts {
            match tops.get(mount.target.as_str()) {
                Some(cur) if !mount_target_match_better(mount, cur) => {}
                _ => {
                    tops.insert(mount.target.clone(), mount.clone());
                }
            }
        }
        tops.into_values().collect()
    }

    pub(crate) fn push_record(&mut self, record: MountRecord) {
        self.mounts.push(record);
    }

    pub(crate) fn update_top_mount_flags(&mut self, target: &str, flags: usize) -> bool {
        let Some(idx) = self.top_mount_index_for_target(target) else {
            return false;
        };
        self.mounts[idx].flags = flags;
        true
    }

    pub(crate) fn move_top_mount_target(&mut self, old_target: &str, new_target: &str) -> bool {
        let Some(idx) = self.top_mount_index_for_target(old_target) else {
            return false;
        };
        self.mounts[idx].target = String::from(new_target);
        if let Some(file) = self.file_binds.remove(old_target) {
            self.file_binds.insert(String::from(new_target), file);
        }
        true
    }

    pub(crate) fn sync_rofs_mount_flag(&mut self, target: &str, flags: usize) {
        self.rofs_mounts.retain(|mount| mount != target);
        if flags != 0 {
            self.rofs_mounts.push(String::from(target));
        }
    }

    pub(crate) fn rofs_mount_contains(&self, target: &str) -> bool {
        self.rofs_mounts.iter().any(|mount| mount == target)
    }

    pub(crate) fn rofs_mount_covers(&self, abs: &str) -> bool {
        self.rofs_mounts
            .iter()
            .any(|mount| path_under_mount(abs, mount))
    }

    pub(crate) fn rofs_mount_root_for_path(&self, abs: &str) -> Option<String> {
        let mut best: Option<&str> = None;
        for mount in &self.rofs_mounts {
            if !path_under_mount(abs, mount) {
                continue;
            }
            match best {
                Some(cur) if mount.len() <= cur.len() => {}
                _ => best = Some(mount.as_str()),
            }
        }
        best.map(String::from)
    }

    fn clone_detached(&self) -> Self {
        Self {
            id: alloc_mount_namespace_id(),
            mounts: self.mounts.clone(),
            rofs_mounts: self.rofs_mounts.clone(),
            file_binds: self.file_binds.clone(),
        }
    }
}

static NEXT_MOUNT_NS_ID: AtomicUsize = AtomicUsize::new(1);

fn alloc_mount_namespace_id() -> usize {
    NEXT_MOUNT_NS_ID.fetch_add(1, Ordering::Relaxed)
}

fn mount_path_join(root: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        return String::from(root);
    }
    if root == "/" {
        return alloc::format!("/{}", suffix.trim_start_matches('/'));
    }
    alloc::format!(
        "{}/{}",
        root.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
}

fn mount_target_match_better(candidate: &MountRecord, current: &MountRecord) -> bool {
    candidate.target.len() > current.target.len()
        || (candidate.target.len() == current.target.len()
            && candidate.stack_seq > current.stack_seq)
}

fn mount_source_match_better(candidate: &MountRecord, current: &MountRecord) -> bool {
    candidate.source.len() > current.source.len()
        || (candidate.source.len() == current.source.len()
            && candidate.stack_seq > current.stack_seq)
}

fn path_under_mount(abs: &str, mount: &str) -> bool {
    if mount == "/" || abs == mount {
        return true;
    }
    abs.starts_with(mount) && abs.as_bytes().get(mount.len()) == Some(&b'/')
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
