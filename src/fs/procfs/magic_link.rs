extern crate alloc;

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::{
    File, NamespaceFile, NamespaceKind, OSInode, Pipe, PseudoDir, PseudoFile, PseudoKindTag,
    PseudoShmFile, RtcFile, inode_logical_path, inode_path_hint, inode_path_in_roots,
    path_resolves_to_inode,
};
use crate::task::manager::pid2process;
use crate::task::processor::{current_process, current_task};

use super::{ProcMagicLinkFile, is_proc_pseudo_path};
use super::entries::{encode_proc_linux_tid, proc_pid_exists, proc_pid_task_alive};
use crate::syscall::error::{SyscallError, err};

const MAX_PROC_MAGIC_SYMLINKS: usize = 40;

fn current_thread_self_target() -> Option<String> {
    let pid = current_process().getpid() as u32;
    let task = current_task()?;
    let tid_index = {
        let inner = task.borrow_mut();
        inner.res.as_ref()?.tid
    };
    let tid = encode_proc_linux_tid(pid, tid_index);
    Some(alloc::format!("{pid}/task/{tid}"))
}

fn current_thread_self_abs_target() -> Option<String> {
    current_thread_self_target().map(|target| alloc::format!("/proc/{target}"))
}

fn trim_proc_path(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

fn normalize_abs_path(cwd: &str, path: &str) -> String {
    let mut parts = Vec::new();
    let absolute = path.starts_with('/');
    if !absolute {
        for seg in cwd.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                parts.pop();
                continue;
            }
            parts.push(seg);
        }
    }
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(pos) => {
            let (parent, name) = trimmed.split_at(pos);
            Some((parent, &name[1..]))
        }
        None => Some(("", trimmed)),
    }
}

fn proc_magic_link_parent_path(link_path: &str) -> &str {
    split_parent_and_name(link_path)
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/")
}

fn proc_magic_link_target_path(link_path: &str, target: &str, remainder: &str) -> String {
    let base = if target.starts_with('/') {
        String::from(target)
    } else {
        normalize_abs_path(proc_magic_link_parent_path(link_path), target)
    };
    if remainder.is_empty() {
        base
    } else {
        normalize_abs_path(&base, remainder)
    }
}

fn proc_magic_link_dir_target_path(
    link_path: &str,
    file: &Arc<dyn File + Send + Sync>,
) -> Result<String, isize> {
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Ok(String::from(pdir.path()));
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return Err(err(SyscallError::ENOTDIR));
    };
    let inode = os_inode.ext4_inode();
    // is_dir() reads immutable inode type metadata — no ext4_lock() needed,
    // consistent with the unguarded call in proc_fd_target().
    let is_dir = inode.is_dir();
    if !is_dir {
        return Err(err(SyscallError::ENOTDIR));
    }
    if let Some(path) = proc_readlink(link_path).filter(|path| path.starts_with('/')) {
        return Ok(path);
    }
    inode_logical_path(&inode).ok_or(err(SyscallError::ENOENT))
}

fn follow_proc_magic_link_target(
    link_path: &str,
    target: ProcMagicLinkFollowTarget,
    remainder: &str,
) -> Result<String, isize> {
    match target {
        ProcMagicLinkFollowTarget::Path(target) => {
            Ok(proc_magic_link_target_path(link_path, &target, remainder))
        }
        ProcMagicLinkFollowTarget::File(file) => {
            let base = proc_magic_link_dir_target_path(link_path, &file)?;
            Ok(if remainder.is_empty() {
                base
            } else {
                normalize_abs_path(&base, remainder)
            })
        }
    }
}

fn resolve_next_proc_magic_intermediate_component(abs: &str) -> Result<Option<String>, isize> {
    if !is_proc_pseudo_path(abs) {
        return Ok(None);
    }

    let components: Vec<&str> = abs
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    if components.len() < 2 || components[0] != "proc" {
        return Ok(None);
    }

    let mut prefix = String::new();
    for idx in 0..components.len() - 1 {
        prefix.push('/');
        prefix.push_str(components[idx]);
        if let Some(target) = proc_magic_link_follow_target(&prefix) {
            let remainder = components[idx + 1..].join("/");
            return follow_proc_magic_link_target(&prefix, target, &remainder).map(Some);
        }
    }
    Ok(None)
}

pub(crate) fn resolve_proc_magic_intermediate_abs_path(abs: &str) -> Result<String, isize> {
    let mut current = String::from(abs);
    for _ in 0..MAX_PROC_MAGIC_SYMLINKS {
        let Some(next) = resolve_next_proc_magic_intermediate_component(&current)? else {
            return Ok(current);
        };
        current = next;
    }
    Err(err(SyscallError::ELOOP))
}

fn proc_magic_alias_target_path(trimmed: &str) -> Option<String> {
    if trimmed == "/proc/self" || trimmed.starts_with("/proc/self/") {
        let pid = current_process().getpid();
        let suffix = &trimmed["/proc/self".len()..];
        let mut mapped = alloc::format!("/proc/{pid}");
        mapped.push_str(suffix);
        return Some(mapped);
    }

    if trimmed == "/proc/thread-self" || trimmed.starts_with("/proc/thread-self/") {
        let mut mapped = current_thread_self_abs_target()?;
        let suffix = &trimmed["/proc/thread-self".len()..];
        mapped.push_str(suffix);
        return Some(mapped);
    }

    None
}

pub fn normalize_proc_magic_path(path: &str) -> Cow<'_, str> {
    let trimmed = trim_proc_path(path);
    match proc_magic_alias_target_path(trimmed) {
        Some(mapped) => Cow::Owned(mapped),
        None => Cow::Borrowed(trimmed),
    }
}

fn proc_fd_target(pid: u32, fd: usize) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let files_proc = proc.files_owner_process();
    let (file, cwd) = {
        let inner = files_proc.try_borrow_mut()?;
        if fd >= inner.fd_table.len() {
            return None;
        }
        (inner.fd_table[fd].as_ref()?.clone(), inner.cwd.clone())
    };

    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Some(String::from(pdir.path()));
    }
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        return match pf.kind_tag() {
            PseudoKindTag::Null => Some(String::from("/dev/null")),
            PseudoKindTag::Zero => Some(String::from("/dev/zero")),
            PseudoKindTag::Urandom => Some(String::from("/dev/urandom")),
            PseudoKindTag::Static => None,
        };
    }
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        return Some(alloc::format!("pipe:[{}]", pipe as *const Pipe as usize));
    }
    if let Some(ns) = file.as_any().downcast_ref::<NamespaceFile>() {
        return Some(ns.target_string());
    }
    if let Some(link) = file.as_any().downcast_ref::<ProcMagicLinkFile>() {
        return Some(String::from(link.link_path()));
    }
    if file.as_any().downcast_ref::<RtcFile>().is_some() {
        return Some(String::from("/dev/misc/rtc"));
    }
    if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
        return Some(String::from("/dev/shm"));
    }
    if let Some(oinode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = oinode.ext4_inode();
        if inode.is_dir() && path_resolves_to_inode(&cwd, &inode) {
            return Some(cwd);
        }
        return inode_path_hint(&inode).or_else(|| inode_path_in_roots(&inode));
    }
    None
}

fn proc_pid_cwd(pid: u32) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let inner = proc.try_borrow_mut()?;
    Some(inner.cwd.clone())
}

fn proc_pid_fd_file(pid: u32, fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
    let proc = pid2process(pid as usize)?;
    let files_proc = proc.files_owner_process();
    let inner = files_proc.try_borrow_mut()?;
    inner.fd_table.get(fd)?.as_ref().cloned()
}

fn proc_pid_namespace_target(pid: u32, kind: NamespaceKind) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let ns_id = match kind {
        NamespaceKind::Ipc => proc.try_borrow_mut()?.ipc_ns_id,
        NamespaceKind::Mount => proc.mount_namespace_id(),
    };
    Some(kind.target_string(ns_id))
}

pub(crate) fn proc_pid_namespace_file(
    pid: u32,
    kind: NamespaceKind,
) -> Option<Arc<dyn File + Send + Sync>> {
    let proc = pid2process(pid as usize)?;
    let file: Arc<dyn File + Send + Sync> = match kind {
        NamespaceKind::Ipc => {
            let inner = proc.try_borrow_mut()?;
            Arc::new(NamespaceFile::new_ipc(inner.ipc_ns_id))
        }
        NamespaceKind::Mount => Arc::new(NamespaceFile::new_mount(proc.mount_namespace())),
    };
    Some(file)
}

fn parse_proc_fd_component(fd_name: &str) -> Option<usize> {
    if fd_name.is_empty() || fd_name.contains('/') || !fd_name.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    fd_name.parse::<usize>().ok()
}

pub(crate) fn proc_pid_task_rest(rest: &str) -> Option<(u32, &str)> {
    let task_rest = rest.strip_prefix("task/")?;
    let mut parts = task_rest.splitn(2, '/');
    let tid_name = parts.next().unwrap_or("");
    if tid_name.is_empty() || !tid_name.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let tid = tid_name.parse::<u32>().ok()?;
    let tail = parts.next().unwrap_or("");
    Some((tid, tail))
}

enum ProcMagicLinkFollowTarget {
    Path(String),
    File(Arc<dyn File + Send + Sync>),
}

fn proc_magic_link_follow_target(path: &str) -> Option<ProcMagicLinkFollowTarget> {
    let trimmed = trim_proc_path(path);

    if trimmed == "/proc/self" {
        let pid = current_process().getpid();
        return Some(ProcMagicLinkFollowTarget::Path(alloc::format!("{pid}")));
    }
    if trimmed == "/proc/thread-self" {
        return current_thread_self_target().map(ProcMagicLinkFollowTarget::Path);
    }

    let normalized = normalize_proc_magic_path(trimmed);
    let trimmed = normalized.as_ref();

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    if !proc_pid_exists(pid) {
        return None;
    }
    if rest == "cwd" {
        return proc_pid_cwd(pid).map(ProcMagicLinkFollowTarget::Path);
    }
    if rest == "ns/ipc" {
        return proc_pid_namespace_file(pid, NamespaceKind::Ipc)
            .map(ProcMagicLinkFollowTarget::File);
    }
    if rest == "ns/mnt" {
        return proc_pid_namespace_file(pid, NamespaceKind::Mount)
            .map(ProcMagicLinkFollowTarget::File);
    }
    if let Some(fd_name) = rest.strip_prefix("fd/") {
        let fd = parse_proc_fd_component(fd_name)?;
        return proc_pid_fd_file(pid, fd).map(ProcMagicLinkFollowTarget::File);
    }

    let (tid, tail) = proc_pid_task_rest(rest)?;
    if !proc_pid_task_alive(pid, tid) {
        return None;
    }
    if tail == "cwd" {
        return proc_pid_cwd(pid).map(ProcMagicLinkFollowTarget::Path);
    }
    if tail == "ns/ipc" {
        return proc_pid_namespace_file(pid, NamespaceKind::Ipc)
            .map(ProcMagicLinkFollowTarget::File);
    }
    if tail == "ns/mnt" {
        return proc_pid_namespace_file(pid, NamespaceKind::Mount)
            .map(ProcMagicLinkFollowTarget::File);
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_pid_fd_file(pid, fd).map(ProcMagicLinkFollowTarget::File)
}

pub fn proc_magic_link_exists(path: &str) -> bool {
    let trimmed = trim_proc_path(path);

    if trimmed == "/proc/self" {
        return true;
    }
    if trimmed == "/proc/thread-self" {
        return current_thread_self_target().is_some();
    }

    let normalized = normalize_proc_magic_path(trimmed);
    let trimmed = normalized.as_ref();

    let Some((pid, rest)) = proc_pid_from_path_with_rest(trimmed) else {
        return false;
    };
    if !proc_pid_exists(pid) {
        return false;
    }
    if rest == "cwd" || rest == "ns/ipc" || rest == "ns/mnt" {
        return true;
    }
    if let Some(fd_name) = rest.strip_prefix("fd/") {
        return parse_proc_fd_component(fd_name)
            .and_then(|fd| proc_pid_fd_file(pid, fd))
            .is_some();
    }

    let Some((tid, tail)) = proc_pid_task_rest(rest) else {
        return false;
    };
    if !proc_pid_task_alive(pid, tid) {
        return false;
    }
    if tail == "cwd" || tail == "ns/ipc" || tail == "ns/mnt" {
        return true;
    }
    tail.strip_prefix("fd/")
        .and_then(parse_proc_fd_component)
        .and_then(|fd| proc_pid_fd_file(pid, fd))
        .is_some()
}

pub fn proc_fd_link_file(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let normalized = normalize_proc_magic_path(path);
    let trimmed = normalized.as_ref();

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    if !proc_pid_exists(pid) {
        return None;
    }
    if let Some(fd_name) = rest.strip_prefix("fd/") {
        let fd = parse_proc_fd_component(fd_name)?;
        return proc_pid_fd_file(pid, fd);
    }

    let (tid, tail) = proc_pid_task_rest(rest)?;
    if !proc_pid_task_alive(pid, tid) {
        return None;
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_pid_fd_file(pid, fd)
}

pub fn proc_readlink(path: &str) -> Option<String> {
    let trimmed = trim_proc_path(path);

    if trimmed == "/proc/self" || trimmed.starts_with("/proc/self/") {
        let pid = current_process().getpid();
        if trimmed == "/proc/self" {
            return Some(alloc::format!("{pid}"));
        }
    }

    if trimmed == "/proc/thread-self" || trimmed.starts_with("/proc/thread-self/") {
        let target = current_thread_self_target()?;
        if trimmed == "/proc/thread-self" {
            return Some(target);
        }
    }

    let normalized = normalize_proc_magic_path(trimmed);
    let trimmed = normalized.as_ref();

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    if rest == "cwd" {
        return proc_pid_cwd(pid);
    }
    if rest == "ns/ipc" {
        return proc_pid_namespace_target(pid, NamespaceKind::Ipc);
    }
    if rest == "ns/mnt" {
        return proc_pid_namespace_target(pid, NamespaceKind::Mount);
    }

    if let Some(fd_name) = rest.strip_prefix("fd/") {
        let fd = parse_proc_fd_component(fd_name)?;
        return proc_fd_target(pid, fd);
    }

    let (tid, tail) = proc_pid_task_rest(rest)?;
    if !proc_pid_task_alive(pid, tid) {
        return None;
    }
    if tail == "cwd" {
        return proc_pid_cwd(pid);
    }
    if tail == "ns/ipc" {
        return proc_pid_namespace_target(pid, NamespaceKind::Ipc);
    }
    if tail == "ns/mnt" {
        return proc_pid_namespace_target(pid, NamespaceKind::Mount);
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_fd_target(pid, fd)
}

pub(crate) fn proc_pid_from_path_with_rest(path: &str) -> Option<(u32, &str)> {
    let rest = path.strip_prefix("/proc/")?;
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return None;
    }
    let mut parts = rest.splitn(2, '/');
    let first = parts.next().unwrap_or("");
    if first.is_empty() {
        return None;
    }
    if !first.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let pid = first.parse::<u32>().ok()?;
    let tail = parts.next().unwrap_or("");
    Some((pid, tail))
}
