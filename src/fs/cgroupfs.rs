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

#[derive(Clone)]
struct CgroupNode {
    ino: u64,
    subtree_pids: bool,
    pids_max: Option<usize>,
}

impl CgroupNode {
    fn new() -> Self {
        Self {
            ino: NEXT_CGROUP_INO.fetch_add(1, Ordering::Relaxed),
            subtree_pids: false,
            pids_max: None,
        }
    }
}

#[derive(Clone)]
struct CgroupMountState {
    nodes: BTreeMap<String, CgroupNode>,
    assignments: BTreeMap<usize, String>,
}

impl CgroupMountState {
    fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(String::from("/"), CgroupNode::new());
        Self {
            nodes,
            assignments: BTreeMap::new(),
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
}

impl CgroupFileKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "cgroup.controllers" => Some(Self::Controllers),
            "cgroup.subtree_control" => Some(Self::SubtreeControl),
            "cgroup.procs" => Some(Self::Procs),
            "pids.max" => Some(Self::PidsMax),
            "pids.current" => Some(Self::PidsCurrent),
            _ => None,
        }
    }

    fn mode(self) -> u32 {
        match self {
            Self::Controllers | Self::PidsCurrent => 0o100444,
            Self::SubtreeControl | Self::Procs | Self::PidsMax => 0o100644,
        }
    }
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
            CgroupFileKind::Controllers => String::from("pids\n"),
            CgroupFileKind::SubtreeControl => {
                if node.subtree_pids {
                    String::from("pids\n")
                } else {
                    String::from("\n")
                }
            }
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
        }
    }

    pub fn write_payload(&self, data: &[u8]) -> Result<usize, isize> {
        let raw = core::str::from_utf8(data).map_err(|_| EINVAL)?;
        let text = raw.trim_matches(|c| c == '\n' || c == '\r' || c == ' ' || c == '\t');
        let mut mounts = CGROUP_MOUNTS.lock();
        let Some(state) = mounts.get_mut(&self.mount_target) else {
            return Err(ENOENT);
        };
        let Some(node) = state.nodes.get_mut(&self.rel_path) else {
            return Err(ENOENT);
        };
        match self.kind {
            CgroupFileKind::Controllers | CgroupFileKind::PidsCurrent => Err(EROFS),
            CgroupFileKind::SubtreeControl => {
                if text.is_empty() {
                    return Ok(data.len());
                }
                for token in text.split_whitespace() {
                    match token {
                        "+pids" => node.subtree_pids = true,
                        "-pids" => node.subtree_pids = false,
                        _ => return Err(EOPNOTSUPP),
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
            CgroupFileKind::Controllers | CgroupFileKind::PidsCurrent
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
    String::from("#subsys_name\thierarchy\tnum_cgroups\tenabled\npids\t0\t1\t1\n")
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
    }
}

pub fn cgroup_logical_path_for_file(file: &Arc<dyn File + Send + Sync>) -> Option<String> {
    file.as_any()
        .downcast_ref::<CgroupFile>()
        .map(|file| file.path().to_string())
}
