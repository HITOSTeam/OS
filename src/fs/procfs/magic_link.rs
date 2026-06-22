extern crate alloc;

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::{
    File, NamespaceFile, NamespaceKind, NetSocketFile, OSInode, Pipe, PseudoDir, PseudoFile,
    PseudoKindTag, PseudoShmFile, RtcFile, inode_logical_path, inode_path_hint,
    inode_path_in_roots, path_resolves_to_inode,
};
use crate::task::manager::pid2process;
use crate::task::processor::{current_process, current_task};

use super::entries::{encode_proc_linux_tid, proc_pid_exists, proc_pid_task_alive};
use super::{ProcMagicLinkFile, is_proc_pseudo_path};
use crate::syscall::error::{SyscallError, err};

const MAX_PROC_MAGIC_SYMLINKS: usize = 40;

/// 返回当前线程对应的 `/proc/thread-self` 目标，形如 `<pid>/task/<tid>`（相对 `/proc`）。
/// 用 `encode_proc_linux_tid` 把内核内部 tid 索引编码成用户态可见的 Linux TID。
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

/// `current_thread_self_target` 的绝对路径版本，结果形如 `/proc/<pid>/task/<tid>`。
fn current_thread_self_abs_target() -> Option<String> {
    current_thread_self_target().map(|target| alloc::format!("/proc/{target}"))
}

/// 去掉路径尾部的 `/`，但保留根路径 `/` 本身不变。
fn trim_proc_path(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

/// 将 `path`（可为相对或绝对）按 `cwd` 基准规范化为绝对路径。
///
/// 逐段处理 `.`（忽略）和 `..`（弹出上一段），不访问文件系统、纯字符串运算。
/// 仅当 `path` 为相对路径时才先展开 `cwd`。
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

/// 把路径拆成（父目录, 末段名）。父目录为顶层时返回空串。
/// 末尾 `/` 会被忽略；纯 `/` 或空路径返回 `None`。
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

/// 返回某个 magic link 路径所在的父目录，顶层时回退为 `/`。
/// 用作解析相对符号链接目标时的基准目录。
fn proc_magic_link_parent_path(link_path: &str) -> &str {
    split_parent_and_name(link_path)
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/")
}

/// 计算 magic link 的最终目标绝对路径。
///
/// - `target` 为绝对路径时直接采用，否则以 link 的父目录为基准展开。
/// - `remainder` 是 link 之后还需追加的剩余路径段（如 `fd/3/foo` 中的 `foo`）。
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

/// 当 magic link 指向一个「目录类」对象（如 `fd/<n>` 指向某打开的目录 fd）时，
/// 解析出该目录的绝对路径。
///
/// - 伪目录 [`PseudoDir`] 直接返回其 `path()`。
/// - 真实 ext4 目录先尝试 `proc_readlink` 的绝对结果，再回退到 inode 的逻辑路径。
/// - 非目录对象返回 `ENOTDIR`。
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

/// 根据 magic link 的解析结果（路径或文件对象）和剩余路径段，得到追加后的绝对路径。
/// `Path` 目标走字符串拼接，`File` 目标先解析目录路径再追加 `remainder`。
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

/// 在路径中查找第一个作为「中间组件」出现的 magic link 并展开一层。
///
/// 例如 `/proc/<pid>/cwd/sub` 里 `cwd` 是中间符号链接，本函数会把它解析为
/// 进程的工作目录并拼上 `sub`。逐前缀扫描，命中第一个 magic link 即返回新路径；
/// 路径非 procfs 或没有可展开组件时返回 `Ok(None)`。
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

/// 反复展开路径中的中间 magic link，直到不含可展开组件为止，返回最终绝对路径。
/// 设置 `MAX_PROC_MAGIC_SYMLINKS` 上限防止符号链接环，超限返回 `ELOOP`。
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

/// 把 `/proc/self`、`/proc/thread-self` 这两个别名前缀替换成具体的
/// `/proc/<pid>`、`/proc/<pid>/task/<tid>`，并保留其后缀。其他路径返回 `None`。
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

/// procfs 路径规范化入口：去尾 `/` 并把 `self`/`thread-self` 别名替换为实际 pid/tid。
/// 命中别名时返回 `Owned`，否则借用原串返回 `Borrowed`，避免不必要的分配。
pub fn normalize_proc_magic_path(path: &str) -> Cow<'_, str> {
    let trimmed = trim_proc_path(path);
    match proc_magic_alias_target_path(trimmed) {
        Some(mapped) => Cow::Owned(mapped),
        None => Cow::Borrowed(trimmed),
    }
}

/// 解析 `/proc/<pid>/fd/<fd>` 符号链接的目标字符串（即该 fd 实际指向的对象）。
///
/// 按文件具体类型分派：伪目录/伪文件映射到 `/dev/*` 路径，pipe 映射为 `pipe:[id]`，
/// namespace/magic-link 返回各自的目标串，真实 ext4 inode 通过路径提示反查。
/// 无法识别的类型返回 `None`。
fn proc_fd_target(pid: u32, fd: usize) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let (files, cwd) = {
        let inner = proc.try_borrow_mut()?;
        (Arc::clone(&inner.files), inner.cwd.clone())
    };
    let file = files.lock().get_file(fd)?;

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
    if let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() {
        return Some(alloc::format!("socket:[{}]", sock.proc_inode()));
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

/// 读取目标进程的当前工作目录。进程不存在或锁竞争时返回 `None`（用 `try_borrow_mut` 避免死锁）。
fn proc_pid_cwd(pid: u32) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let inner = proc.try_borrow_mut()?;
    Some(inner.cwd.clone())
}

/// 取目标进程 fd 表中指定 fd 的文件对象（克隆 `Arc`）。进程不存在或 fd 无效时返回 `None`。
fn proc_pid_fd_file(pid: u32, fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
    let proc = pid2process(pid as usize)?;
    let files = {
        let inner = proc.try_borrow_mut()?;
        Arc::clone(&inner.files)
    };
    files.lock().get_file(fd)
}

/// 返回 `/proc/<pid>/ns/<kind>` 的目标字符串（形如 `ipc:[id]`），用于 readlink。
fn proc_pid_namespace_target(pid: u32, kind: NamespaceKind) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let ns_id = match kind {
        NamespaceKind::Ipc => proc.try_borrow_mut()?.ipc_ns_id,
        NamespaceKind::Mount => proc.mount_namespace_id(),
        NamespaceKind::Net => proc.net_namespace_id(),
    };
    Some(kind.target_string(ns_id))
}

/// 为 `/proc/<pid>/ns/<kind>` 构造一个可打开的 [`NamespaceFile`]（setns/比较用）。
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
        NamespaceKind::Net => Arc::new(NamespaceFile::new_net(proc.net_namespace_id())),
    };
    Some(file)
}

/// 校验并解析 `fd/<n>` 中的数字 fd 段。非纯数字或含 `/` 一律返回 `None`。
fn parse_proc_fd_component(fd_name: &str) -> Option<usize> {
    if fd_name.is_empty() || fd_name.contains('/') || !fd_name.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    fd_name.parse::<usize>().ok()
}

/// 从 `/proc/<pid>` 之后的 `rest` 里剥出 `task/<tid>/<tail>` 结构，返回 `(tid, tail)`。
/// 不以 `task/` 开头或 tid 非数字时返回 `None`；`tail` 可为空（即恰好是 `task/<tid>`）。
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

/// magic link 的解析目标：要么是一个字符串路径，要么是一个具体的文件对象。
enum ProcMagicLinkFollowTarget {
    Path(String),
    File(Arc<dyn File + Send + Sync>),
}

/// 判断某个 procfs 路径是否本身是一个 magic link，并解析出它的跟随目标。
///
/// 覆盖 `self`/`thread-self` 别名，以及 `/proc/<pid>` 下的 `cwd`、`ns/ipc`、
/// `ns/mnt`、`fd/<n>` 和对应的 `task/<tid>/…` 变体。非 magic link 返回 `None`。
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
    if rest == "ns/net" {
        return proc_pid_namespace_file(pid, NamespaceKind::Net)
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
    if tail == "ns/net" {
        return proc_pid_namespace_file(pid, NamespaceKind::Net)
            .map(ProcMagicLinkFollowTarget::File);
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_pid_fd_file(pid, fd).map(ProcMagicLinkFollowTarget::File)
}

/// 判断给定 procfs 路径是否是一个存在的 magic link（供 `stat`/`access` 等使用）。
/// 只检查存在性，不解析目标，对 `fd/<n>` 会确认该 fd 当前确实打开。
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
    if rest == "cwd" || rest == "ns/ipc" || rest == "ns/mnt" || rest == "ns/net" {
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
    if tail == "cwd" || tail == "ns/ipc" || tail == "ns/mnt" || tail == "ns/net" {
        return true;
    }
    tail.strip_prefix("fd/")
        .and_then(parse_proc_fd_component)
        .and_then(|fd| proc_pid_fd_file(pid, fd))
        .is_some()
}

/// 把 `/proc/<pid>/fd/<n>`（含 `task/<tid>/fd/<n>`）直接解析到底层文件对象，
/// 使经由该路径的 open 复用同一个打开文件（而非重新走路径解析）。非 fd 链接返回 `None`。
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

/// 实现对 procfs magic link 的 `readlink`：返回链接指向的目标字符串。
///
/// 处理 `self`/`thread-self` 别名，以及 `/proc/<pid>` 下 `cwd`、`ns/ipc`、`ns/mnt`、
/// `fd/<n>`（及 `task/<tid>/…` 变体）。非链接路径返回 `None`。
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
    if rest == "ns/net" {
        return proc_pid_namespace_target(pid, NamespaceKind::Net);
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
    if tail == "ns/net" {
        return proc_pid_namespace_target(pid, NamespaceKind::Net);
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_fd_target(pid, fd)
}

/// 从绝对路径中拆出 `/proc/<pid>/<rest>` 的 `(pid, rest)`。
/// 首段必须是纯数字 PID，否则（如 `/proc/sys`）返回 `None`；`rest` 可为空串。
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
