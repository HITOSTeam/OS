use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use super::File;

const INITIAL_ROOT_PEER_GROUP_ID: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountPropagation {
    Private,
    Shared,
    Slave,
    Unbindable,
}

/// Filesystem instance attached by a mount record.
///
/// Virtual filesystems are selected from this value, never from the spelling
/// of the userspace path.  In particular, an empty `/proc` directory in an
/// ext4 image remains an ext4 directory until a `Proc` backend is mounted on
/// it, and the same backend can be mounted at an arbitrary directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MountBackend {
    Storage,
    // procfs system in certain pid namespace
    Proc { pid_namespace_id: usize },
    SysFs,
    DevTmpFs,
    Cgroup,
}

impl MountBackend {
    pub(crate) fn is_pseudo(&self) -> bool {
        !matches!(self, Self::Storage)
    }

    pub(crate) fn canonical_root(&self) -> Option<&'static str> {
        match self {
            Self::Storage => None,
            Self::Proc { .. } => Some("/proc"),
            Self::SysFs => Some("/sys"),
            Self::DevTmpFs => Some("/dev"),
            Self::Cgroup => None,
        }
    }

    pub(crate) fn statfs_magic(&self) -> i64 {
        match self {
            Self::Storage => 0xef53,
            Self::Proc { .. } => 0x9fa0,
            Self::SysFs => 0x6265_6572,
            Self::DevTmpFs => 0x0102_1994,
            Self::Cgroup => 0x6367_7270,
        }
    }
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
    /// Mounted filesystem instance used for path dispatch.
    pub(crate) backend: MountBackend,
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

#[derive(Clone, Debug)]
pub(crate) struct FdMountRef {
    pub(crate) target: String,
    pub(crate) event_id: usize,
    pub(crate) stack_seq: usize,
    pub(crate) flags: usize,
    pub(crate) backend: MountBackend,
}

impl From<&MountRecord> for FdMountRef {
    fn from(record: &MountRecord) -> Self {
        Self {
            target: record.target.clone(),
            event_id: record.event_id,
            stack_seq: record.stack_seq,
            flags: record.flags,
            backend: record.backend.clone(),
        }
    }
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
        let mut mounts = Vec::new();
        mounts.push(MountRecord {
            target: String::from("/"),
            source: String::from("/"),
            source_display: String::from("/dev/root"),
            fs_type: String::from("ext4"),
            backend: MountBackend::Storage,
            flags: 0,
            stack_seq: 1,
            event_id: 1,
            propagation: MountPropagation::Shared,
            peer_group_id: Some(INITIAL_ROOT_PEER_GROUP_ID),
            master_group_id: None,
            access_seq: 0,
            expire_mark_seq: None,
        });
        if let Some(source) = super::block_device_source_path("/dev/vdb") {
            super::ensure_root_mount_directory("user");
            mounts.push(MountRecord {
                target: String::from("/user"),
                source,
                source_display: String::from("/dev/vdb"),
                fs_type: String::from("ext4"),
                backend: MountBackend::Storage,
                flags: 0,
                stack_seq: 2,
                event_id: 2,
                propagation: MountPropagation::Private,
                peer_group_id: None,
                master_group_id: None,
                access_seq: 0,
                expire_mark_seq: None,
            });
        }
        if let Some(source) = super::block_device_source_path("/dev/vdc") {
            mounts.push(MountRecord {
                target: String::from("/mnt/oscomp"),
                source: source.clone(),
                source_display: String::from("/dev/vdc"),
                fs_type: String::from("ext4"),
                backend: MountBackend::Storage,
                flags: 0,
                stack_seq: 3,
                event_id: 3,
                propagation: MountPropagation::Private,
                peer_group_id: None,
                master_group_id: None,
                access_seq: 0,
                expire_mark_seq: None,
            });
            for (stack_seq, event_id, target, child) in
                [(4, 4, "/glibc", "glibc"), (5, 5, "/musl", "musl")]
            {
                mounts.push(MountRecord {
                    target: String::from(target),
                    source: alloc::format!("{}/{}", source, child),
                    source_display: alloc::format!("/mnt/oscomp/{}", child),
                    fs_type: String::from("none"),
                    backend: MountBackend::Storage,
                    flags: 0,
                    stack_seq,
                    event_id,
                    propagation: MountPropagation::Private,
                    peer_group_id: None,
                    master_group_id: None,
                    access_seq: 0,
                    expire_mark_seq: None,
                });
            }
        }
        Self {
            id,
            mounts,
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
        if self
            .mount_record_for_path(abs)
            .is_some_and(|mount| mount.backend.is_pseudo())
        {
            return ClassifiedAbsPath::Pseudo(String::from(abs));
        }
        ClassifiedAbsPath::Ext4(self.translate_mount_abs(abs))
    }

    /// Translate a logical path inside a virtual mount to the canonical path
    /// understood by the existing proc/sys/dev providers.
    pub(crate) fn canonical_pseudo_abs(&self, abs: &str) -> Option<(MountRecord, String)> {
        let mount = self.mount_record_for_path(abs)?;
        let canonical_root = mount.backend.canonical_root()?;
        let root = if path_under_mount(&mount.source, canonical_root) {
            mount.source.clone()
        } else {
            String::from(canonical_root)
        };
        let suffix = if abs == mount.target {
            ""
        } else {
            &abs[mount.target.len()..]
        };
        Some((mount, mount_path_join(&root, suffix)))
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
