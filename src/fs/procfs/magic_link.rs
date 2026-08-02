extern crate alloc;

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::sync::Arc;

use crate::fs::vfs::{LookupFlags, PathWalker, VfsCredentials, VfsLink, VfsNodeKind, VfsPath};
use crate::fs::{
    EventFdFile, FanotifyFile, File, KernelFileSystemKind, MemfdFile, NamespaceFile, NamespaceKind,
    NetSocketFile, OSInode, Pipe, PseudoDir, PseudoFile, PseudoKindTag, RtcFile, SignalfdFile,
    TimerFdFile, UserfaultfdFile, VfsOpenedFile, inode_path_hint, inode_path_in_roots,
    kernel_file_path, path_resolves_to_inode,
};
use crate::task::manager::pid2process;
use crate::task::processor::{current_process, current_task};

use super::ProcMagicLinkFile;
use super::entries::{encode_proc_linux_tid, proc_pid_exists, proc_pid_task_alive};

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
    let (files, fs) = {
        let inner = proc.try_borrow_mut()?;
        if inner.is_zombie {
            return None;
        }
        (Arc::clone(&inner.files), Arc::clone(inner.fs.as_ref()?))
    };
    let cwd = fs.cwd_display();
    let file = files.lock().get_file(fd)?;

    if let Some(path) = file.logical_path_hint() {
        return Some(String::from(path));
    }

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
        return Some(alloc::format!("pipe:[{}]", pipe.proc_inode()));
    }
    if let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() {
        return Some(alloc::format!("socket:[{}]", sock.proc_inode()));
    }
    if let Some(name) = anonymous_file_name(&file) {
        return Some(alloc::format!("anon_inode:{name}"));
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
    if let Some(memfd) = file.as_any().downcast_ref::<MemfdFile>() {
        return Some(memfd.proc_link_target());
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

/// Linux names these objects through anon_inodefs' dynamic dentry callback.
/// Keep the bracketed inode names identical to the names passed to
/// `anon_inode_getfile()` by the corresponding Linux subsystems.
fn anonymous_file_name(file: &Arc<dyn File + Send + Sync>) -> Option<&'static str> {
    let object = file.as_any();
    if object.downcast_ref::<EventFdFile>().is_some() {
        Some("[eventfd]")
    } else if object.downcast_ref::<TimerFdFile>().is_some() {
        Some("[timerfd]")
    } else if object.downcast_ref::<SignalfdFile>().is_some() {
        Some("[signalfd]")
    } else if object.downcast_ref::<UserfaultfdFile>().is_some() {
        Some("[userfaultfd]")
    } else if object.downcast_ref::<FanotifyFile>().is_some() {
        Some("[fanotify]")
    } else {
        None
    }
}

/// 读取目标进程的当前工作目录。进程不存在或锁竞争时返回 `None`（用 `try_borrow_mut` 避免死锁）。
fn proc_pid_cwd(pid: u32) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let inner = proc.try_borrow_mut()?;
    if inner.is_zombie {
        return None;
    }
    Some(inner.fs.as_ref()?.cwd_display())
}

/// 读取目标进程当前可执行文件的逻辑绝对路径。
///
/// Zombie 已经不再拥有可运行的地址空间，和 Linux 一样不再暴露 `exe` 目标。
fn proc_pid_exe(pid: u32) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let inner = proc.try_borrow_mut()?;
    if inner.is_zombie || inner.exe_path.is_empty() {
        None
    } else {
        Some(inner.exe_path.clone())
    }
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

/// Return the already resolved object pinned by a descriptor. Pathname-backed
/// descriptions keep their existing path; pipes and sockets jump into the
/// corresponding kernel-only pseudo mount, mirroring Linux `file->f_path`.
fn proc_pid_fd_vfs_link(pid: u32, fd: usize) -> Option<VfsLink> {
    let file = proc_pid_fd_file(pid, fd)?;
    if let Some(path) = file.object_path() {
        return Some(VfsLink::Magic(path.clone()));
    }
    if let Some(opened) = file.as_any().downcast_ref::<VfsOpenedFile>() {
        return Some(VfsLink::Magic(opened.path().clone()));
    }
    if let Some(path) = file
        .as_any()
        .downcast_ref::<OSInode>()
        .and_then(OSInode::vfs_path)
        .map(|path| path.path().clone())
    {
        return Some(VfsLink::Magic(path));
    }
    if let Some(node_id) = file.as_any().downcast_ref::<Pipe>().map(Pipe::proc_inode) {
        let display = alloc::format!("pipe:[{node_id}]");
        let target =
            kernel_file_path(file, KernelFileSystemKind::Pipe, node_id, VfsNodeKind::Fifo).ok()?;
        return Some(VfsLink::MagicDisplay { target, display });
    }
    if let Some(node_id) = file
        .as_any()
        .downcast_ref::<NetSocketFile>()
        .map(NetSocketFile::proc_inode)
    {
        let display = alloc::format!("socket:[{node_id}]");
        let target = kernel_file_path(
            file,
            KernelFileSystemKind::Socket,
            node_id,
            VfsNodeKind::Socket,
        )
        .ok()?;
        return Some(VfsLink::MagicDisplay { target, display });
    }
    if let Some(name) = anonymous_file_name(&file) {
        let node_id = Arc::as_ptr(&file) as *const () as usize as u64;
        let display = alloc::format!("anon_inode:{name}");
        let target = kernel_file_path(
            file,
            KernelFileSystemKind::Anonymous,
            node_id,
            VfsNodeKind::Regular,
        )
        .ok()?;
        return Some(VfsLink::MagicDisplay { target, display });
    }
    if let Some(memfd) = file.as_any().downcast_ref::<MemfdFile>() {
        let node_id = memfd.memfd_id();
        let display = memfd.proc_link_target();
        let target = kernel_file_path(
            file,
            KernelFileSystemKind::Shmem,
            node_id,
            VfsNodeKind::Regular,
        )
        .ok()?;
        return Some(VfsLink::MagicDisplay { target, display });
    }
    None
}

/// Resolve the executable name in the target task's own root and mount graph.
/// This turns `/proc/<pid>/exe` into an object jump even when that task lives
/// in a different mount namespace.
fn proc_pid_exe_vfs_path(pid: u32) -> Option<VfsPath> {
    let process = pid2process(pid as usize)?;
    let (exe_path, fs, uid, gid, zombie) = {
        let inner = process.try_borrow_mut()?;
        (
            inner.exe_path.clone(),
            inner.fs.as_ref().map(Arc::clone),
            inner.fsuid,
            inner.fsgid,
            inner.is_zombie,
        )
    };
    if zombie || exe_path.is_empty() {
        return None;
    }
    let fs = fs?;
    let root = fs.root();
    let cwd = fs.cwd();
    let namespace = process.mount_namespace().lock().vfs_namespace();
    PathWalker::new(namespace)
        .walk(
            root.path(),
            cwd.path(),
            &exe_path,
            LookupFlags(LookupFlags::FOLLOW_FINAL),
            VfsCredentials { uid, gid },
        )
        .ok()
}

/// Resolve proc magic links that already have an object-VFS target.
///
/// Linux implements these through `nd_jump_link()` rather than by formatting
/// an absolute path and feeding it back through namei. Namespace links jump
/// into the internal nsfs mount; anonymous-fd links intentionally remain
/// absent until their pipefs or sockfs nodes exist.
pub(crate) fn proc_magic_vfs_link(path: &str) -> Option<VfsLink> {
    let trimmed = trim_proc_path(path);
    if trimmed == "/proc/self" {
        let pid = current_process().getpid();
        return Some(VfsLink::Text(alloc::format!("{pid}")));
    }
    if trimmed == "/proc/thread-self" {
        return current_thread_self_target().map(VfsLink::Text);
    }

    let normalized = normalize_proc_magic_path(trimmed);
    let (pid, rest) = proc_pid_from_path_with_rest(normalized.as_ref())?;
    if !proc_pid_exists(pid) {
        return None;
    }
    if rest == "cwd" {
        return pid2process(pid as usize)
            .and_then(|process| process.try_fs_struct())
            .map(|fs| fs.cwd().path().clone())
            .map(VfsLink::Magic);
    }
    if rest == "exe" {
        return proc_pid_exe_vfs_path(pid).map(VfsLink::Magic);
    }
    if let Some(kind) = proc_namespace_kind(rest) {
        let namespace = proc_pid_namespace_descriptor(pid, kind)?;
        let display = namespace.target_string();
        let target = crate::fs::namespace_path(namespace).ok()?;
        return Some(VfsLink::MagicDisplay { target, display });
    }
    if let Some(fd_name) = rest.strip_prefix("fd/") {
        let fd = parse_proc_fd_component(fd_name)?;
        return proc_pid_fd_vfs_link(pid, fd);
    }

    let (tid, tail) = proc_pid_task_rest(rest)?;
    if !proc_pid_task_alive(pid, tid) {
        return None;
    }
    if tail == "cwd" {
        return pid2process(pid as usize)
            .and_then(|process| process.try_fs_struct())
            .map(|fs| fs.cwd().path().clone())
            .map(VfsLink::Magic);
    }
    if tail == "exe" {
        return proc_pid_exe_vfs_path(pid).map(VfsLink::Magic);
    }
    if let Some(kind) = proc_namespace_kind(tail) {
        let namespace = proc_pid_namespace_descriptor(pid, kind)?;
        let display = namespace.target_string();
        let target = crate::fs::namespace_path(namespace).ok()?;
        return Some(VfsLink::MagicDisplay { target, display });
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_pid_fd_vfs_link(pid, fd)
}

fn proc_namespace_kind(rest: &str) -> Option<NamespaceKind> {
    match rest {
        "ns/cgroup" => Some(NamespaceKind::Cgroup),
        "ns/ipc" => Some(NamespaceKind::Ipc),
        "ns/mnt" => Some(NamespaceKind::Mount),
        "ns/net" => Some(NamespaceKind::Net),
        _ => None,
    }
}

/// 返回 `/proc/<pid>/ns/<kind>` 的目标字符串（形如 `ipc:[id]`），用于 readlink。
fn proc_pid_namespace_target(pid: u32, kind: NamespaceKind) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let ns_id = match kind {
        NamespaceKind::Cgroup => proc.try_borrow_mut()?.cgroup_ns_id,
        NamespaceKind::Ipc => proc.try_borrow_mut()?.ipc_ns_id,
        NamespaceKind::Mount => proc.mount_namespace_id(),
        NamespaceKind::Net => proc.net_namespace_id(),
    };
    Some(kind.target_string(ns_id))
}

fn proc_pid_namespace_descriptor(pid: u32, kind: NamespaceKind) -> Option<Arc<NamespaceFile>> {
    let proc = pid2process(pid as usize)?;
    match kind {
        NamespaceKind::Cgroup => {
            let inner = proc.try_borrow_mut()?;
            Some(Arc::new(NamespaceFile::new_cgroup(
                inner.cgroup_ns_id,
                inner.cgroup_ns_root.clone(),
            )))
        }
        NamespaceKind::Ipc => {
            let inner = proc.try_borrow_mut()?;
            Some(Arc::new(NamespaceFile::new_ipc(inner.ipc_ns_id)))
        }
        NamespaceKind::Mount => Some(Arc::new(NamespaceFile::new_mount(proc.mount_namespace()))),
        NamespaceKind::Net => Some(Arc::new(NamespaceFile::new_net(proc.net_namespace_id()))),
    }
}

/// 为 `/proc/<pid>/ns/<kind>` 构造一个可打开的 [`NamespaceFile`]（setns/比较用）。
pub(crate) fn proc_pid_namespace_file(
    pid: u32,
    kind: NamespaceKind,
) -> Option<Arc<dyn File + Send + Sync>> {
    proc_pid_namespace_descriptor(pid, kind).map(|file| file as Arc<dyn File + Send + Sync>)
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
    if rest == "cwd" {
        return true;
    }
    if rest == "exe" {
        return proc_pid_exe(pid).is_some();
    }
    if rest == "ns/cgroup" || rest == "ns/ipc" || rest == "ns/mnt" || rest == "ns/net" {
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
    if tail == "cwd" {
        return true;
    }
    if tail == "exe" {
        return proc_pid_exe(pid).is_some();
    }
    if tail == "ns/cgroup" || tail == "ns/ipc" || tail == "ns/mnt" || tail == "ns/net" {
        return true;
    }
    tail.strip_prefix("fd/")
        .and_then(parse_proc_fd_component)
        .and_then(|fd| proc_pid_fd_file(pid, fd))
        .is_some()
}

/// 实现对 procfs magic link 的 `readlink`：返回链接指向的目标字符串。
///
/// 处理 `self`/`thread-self` 别名，以及 `/proc/<pid>` 下 `cwd`、`exe`、
/// `ns/ipc`、`ns/mnt`、`fd/<n>`（及 `task/<tid>/…` 变体）。
/// 非链接路径返回 `None`。
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
    if rest == "exe" {
        return proc_pid_exe(pid);
    }
    if rest == "ns/cgroup" {
        return proc_pid_namespace_target(pid, NamespaceKind::Cgroup);
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
    if tail == "exe" {
        return proc_pid_exe(pid);
    }
    if tail == "ns/cgroup" {
        return proc_pid_namespace_target(pid, NamespaceKind::Cgroup);
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
