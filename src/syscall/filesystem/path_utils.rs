use super::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Arc, ClassifiedAbsPath, File, INODE_XATTRS,
    MAX_SYMLINKS, NAME_MAX, O_TRUNC, OSInode, PATH_MAX, PseudoDir, PseudoShmFile, String,
    SyscallError, Vec, XATTR_CREATE, XATTR_NAME_MAX, XATTR_REPLACE, XATTR_SIZE_MAX,
    clear_ext4_path_cache, current_cwd_path, current_files, current_fsuid_gid,
    current_mount_namespace, current_process, err, ext4_inode_lock, fd_has_o_path,
    find_path_in_roots, get_current_token, get_fd_file, inode_is_immutable_or_append,
    inode_mode_allows_uid_gid, install_open_file_fd, invalidate_ext4_path_cache,
    invalidate_ext4_path_cache_subtree, logical_path_for_inode, logical_path_for_open_fd,
    mount_lookup_for_abs, note_ext4_path_cache, open_pseudo, path_is_noexec, path_is_rofs,
    pseudo_abs_for_ext4_dirfd, shm_get, shm_object_name, syscall_ftruncate,
    touch_inode_mtime_ctime_now, translate_mount_abs, try_copy_from_user, try_copy_to_user,
    try_read_user_value,
};
use alloc::vec;

/// 返回当前实时时钟的 `(秒, 纳秒)` 对，对应 `CLOCK_REALTIME`。
pub(crate) fn current_timespec() -> (i64, i64) {
    crate::syscall::time_sys::realtime_now_timespec()
}

/// Normalize a path by connect cwd + path. Remove dot
/// for example cwd == '/a/b/c' path ="."
/// we get '/a/b/c'
/// cwd and path can contain relative path like './' ' ../'
/// final path must be abs path
pub(crate) fn normalize_path(cwd: &str, path: &str) -> String {
    let mut parts = Vec::new();
    let absolute = path.starts_with('/');
    // normalize the cwd first
    // get parts finally
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
    // then normalize the input path
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
    // connect the two parts
    out.push_str(&parts.join("/"));
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Expand procfs magic components in the canonical provider namespace, then
/// map results that remain inside that procfs instance back to its logical
/// mountpoint.  Targets such as `/proc/self/cwd` that escape procfs re-enter
/// normal absolute-path resolution.
fn resolve_mounted_proc_magic_intermediate_abs_path(abs: &str) -> Result<String, isize> {
    let Some((mount, canonical)) = crate::fs::current_pseudo_canonical_abs(abs) else {
        return Ok(String::from(abs));
    };
    if !matches!(&mount.backend, crate::fs::MountBackend::Proc { .. }) {
        return Ok(String::from(abs));
    }
    if canonical == "/proc/self" || canonical == "/proc/thread-self" {
        return Ok(String::from(abs));
    }
    let pid_namespace_id = match &mount.backend {
        crate::fs::MountBackend::Proc { pid_namespace_id } => *pid_namespace_id,
        _ => unreachable!(),
    };
    let provider = crate::fs::proc_provider_path_for_namespace(&canonical, pid_namespace_id)
        .unwrap_or(canonical);
    let resolved = crate::fs::resolve_proc_magic_intermediate_abs_path(&provider)?;
    if resolved == "/proc" || resolved.starts_with("/proc/") {
        let mut visible = resolved;
        if let Some(rest) = visible.strip_prefix("/proc/") {
            let (pid_part, suffix) = rest.split_once('/').unwrap_or((rest, ""));
            if let Ok(global_pid) = pid_part.parse::<usize>()
                && let Some(process) = crate::task::manager::pid2process(global_pid)
                && let Some(visible_pid) =
                    crate::task::process_pid_in_pid_namespace(&process, pid_namespace_id)
            {
                visible = if suffix.is_empty() {
                    alloc::format!("/proc/{visible_pid}")
                } else {
                    alloc::format!("/proc/{visible_pid}/{suffix}")
                };
            }
        }
        let suffix = visible.strip_prefix("/proc").unwrap_or("");
        return Ok(normalize_path(
            &mount.target,
            suffix.trim_start_matches('/'),
        ));
    }
    Ok(resolved)
}

/// 返回当前进程的根目录（`chroot` 设置的路径，默认 `"/"`）。
pub(crate) fn current_process_root() -> String {
    let process = current_process();
    let inner = process.borrow_mut();
    inner.root.clone()
}

/// 将进程根目录前缀附加到绝对路径 `abs` 上，实现 `chroot` jail 效果。
/// 若进程根为 `"/"` 则直接返回原路径不做处理。
/// examples:
/// now process root is /abc if we want to go  a path /d then the exact path will be /abc/d
pub(crate) fn apply_process_root(abs: &str) -> String {
    let root = current_process_root();
    if root == "/" {
        return String::from(abs);
    }
    if abs == "/" {
        return root;
    }
    let mut out = root;
    if !out.ends_with('/') {
        out.push('/');
    }
    out.push_str(abs.trim_start_matches('/'));
    // now out can contain relative path(just in case) so we need to normalize it
    normalize_path("/", &out)
}

/// 规范化一个相对路径：去掉 `.`、解析 `..`、合并多余斜杠，返回不含前导 `/` 的字符串。
/// remove aubndant .. for example ../../.. we get .. finally
/// and . will be removed directly
pub(crate) fn normalize_relative_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if parts.last().is_some_and(|last| *last != "..") {
                parts.pop();
            } else {
                parts.push(seg);
            }
            continue;
        }
        parts.push(seg);
    }
    parts.join("/")
}

/// 检查路径中每个分量的长度是否超过 `NAME_MAX`，超过则返回 `ENAMETOOLONG`。
pub(crate) fn validate_path_components(path: &str) -> Result<(), isize> {
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg.len() > NAME_MAX {
            return Err(err(SyscallError::ENAMETOOLONG));
        }
    }
    Ok(())
}

/// 返回路径的最后一个分量（basename），无斜杠时返回原字符串。
pub(crate) fn path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// 检查文件系统中是否存在任一 busybox 可执行文件。
/// todo: remove this  we will add busybox direcly to the image
pub(crate) fn busybox_exists() -> bool {
    let candidates = [
        "/musl/busybox",
        "/glibc/busybox",
        "/riscv/musl/busybox",
        "/riscv/glibc/busybox",
        "/extra/riscv/musl/busybox",
        "/extra/riscv/glibc/busybox",
        "/bin/busybox",
        "/busybox",
    ];
    for cand in candidates {
        if find_path_in_roots(cand).is_some() {
            return true;
        }
    }
    false
}

/// 判断 `path` 是否值得尝试作为 busybox applet 执行。
///
/// 满足以下所有条件才返回 `true`：basename 非空且不是 `busybox` 本身、
/// 不是 `.sh` 脚本、在 busybox applet 白名单内，且路径在允许的目录下
/// （`/bin/`、`/usr/bin/` 等）或是无斜杠的裸名（需 `allow_relative = true`）。
/// todo: remove this
pub(crate) fn should_try_busybox_applet_path(path: &str, allow_relative: bool) -> bool {
    let base = path_basename(path);
    if base.is_empty() || base == "busybox" {
        return false;
    }
    if base.ends_with(".sh") {
        return false;
    }
    if !crate::syscall::busybox_applet_allowed(base) {
        return false;
    }
    if !path.contains('/') {
        return allow_relative;
    }
    path.starts_with("/bin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/sbin/")
}

/// 将路径拆分为 `(父目录, 末尾名称)`。
/// 路径为空或仅由斜杠组成时返回 `None`。
pub(crate) fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
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

pub(crate) enum RelativeAtPathBase {
    // real path,but not real file(psudo),so no inode
    LogicalAbs(String),
    // path based on an inode
    Ext4Dir {
        base: alloc::sync::Arc<ext4_fs::Inode>,
        logical_base: Option<String>,
    },
}

//
pub(crate) enum AtPath {
    /// An ext4 lookup rooted at `/`.
    Ext4Abs(String),
    /// An ext4 lookup rooted at an open directory fd.
    Ext4Rel {
        base: alloc::sync::Arc<ext4_fs::Inode>,
        rel: String,
        /// Translated absolute path used only for path-cache invalidation.
        cache_abs: Option<String>,
    },
    /// A pseudo filesystem lookup expressed as an absolute path.
    PseudoAbs(String),
}

pub(crate) fn invalidate_ext4_path_cache_for_at(at: &AtPath, subtree: bool) {
    let Some(path) = (match at {
        AtPath::Ext4Abs(abs) => Some(abs.as_str()),
        AtPath::Ext4Rel {
            cache_abs: Some(abs),
            ..
        } => Some(abs.as_str()),
        AtPath::Ext4Rel { .. } => None,
        AtPath::PseudoAbs(_) => return,
    }) else {
        clear_ext4_path_cache();
        return;
    };
    if subtree {
        invalidate_ext4_path_cache_subtree(path);
    } else {
        invalidate_ext4_path_cache(path);
    }
}

/// 根据当前进程的挂载命名空间，判断绝对路径属于 ext4 还是伪文件系统。
pub(crate) fn classify_current_abs_path(abs: &str) -> ClassifiedAbsPath {
    let state = current_mount_namespace();
    let state = state.lock();
    state.classify_logical_abs_path(abs)
}

/// 将绝对路径字符串转换为 `AtPath` 枚举，区分 ext4 路径与伪文件系统路径。
pub(crate) fn classify_abs_at_path(abs: String) -> AtPath {
    match classify_current_abs_path(&abs) {
        ClassifiedAbsPath::Ext4(translated) => AtPath::Ext4Abs(translated),
        ClassifiedAbsPath::Pseudo(path) => AtPath::PseudoAbs(path),
    }
}

/// 根据 `dirfd` 确定相对路径的基准：
/// - `AT_FDCWD`：返回当前工作目录的逻辑绝对路径；
/// - 伪目录 fd：返回其逻辑绝对路径；
/// - ext4 目录 fd：返回对应的 inode 及其逻辑路径（如可知）。
/// tldr:
/// 简单来说 就是判断dirfd是什么类型的地址，如果是 psudo file 那么会返回 logical addr  反之，返回
/// 真实node 节点 + 对因地址
pub(crate) fn resolve_relative_at_path_base(dirfd: isize) -> Result<RelativeAtPathBase, isize> {
    if dirfd == AT_FDCWD {
        return Ok(RelativeAtPathBase::LogicalAbs(current_cwd_path()));
    }
    if dirfd < 0 {
        return Err(err(SyscallError::EBADF));
    }
    let Some(file) = get_fd_file(dirfd as usize) else {
        return Err(err(SyscallError::EBADF));
    };
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Ok(RelativeAtPathBase::LogicalAbs(String::from(pdir.path())));
    }
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return Err(err(SyscallError::ENOTDIR));
    };
    let base = os_inode.ext4_inode();
    if !base.is_dir() {
        return Err(err(SyscallError::ENOTDIR));
    }
    Ok(RelativeAtPathBase::Ext4Dir {
        logical_base: logical_path_for_inode(&base),
        base,
    })
}

/// 从逻辑绝对路径基准解析相对路径，处理 `/proc` 魔法路径、挂载点重定向等情况，
/// 返回最终的 `AtPath`（ext4 绝对、ext4 相对 inode 或伪文件系统）。
/// tldr:
/// 对于非真实文件 或者 包含magic link的 at 我们返回 abs
/// 对于真实文件 返回 inode + relative path 的 相对地址类型
pub(crate) fn resolve_relative_at_path_from_logical_base(
    base_path: &str,
    path: &str,
) -> Result<AtPath, isize> {
    let logical_abs = normalize_path(base_path, path);
    // abs main contain some magic part like self
    let abs = resolve_mounted_proc_magic_intermediate_abs_path(&logical_abs)?;
    let classified_abs = classify_current_abs_path(&abs);
    if matches!(classified_abs, ClassifiedAbsPath::Pseudo(_)) {
        return Ok(AtPath::PseudoAbs(abs));
    }
    if abs != logical_abs {
        let ClassifiedAbsPath::Ext4(translated) = classified_abs else {
            unreachable!();
        };
        return Ok(AtPath::Ext4Abs(translated));
    }
    if let Some(base_mount) = mount_lookup_for_abs(base_path) {
        let same_mount = mount_lookup_for_abs(&abs).is_some_and(|mount| {
            mount.target == base_mount.target && mount.stack_seq == base_mount.stack_seq
        });
        if !same_mount {
            let ClassifiedAbsPath::Ext4(translated) = classified_abs else {
                unreachable!();
            };
            return Ok(AtPath::Ext4Abs(translated));
        }
    }
    let rel = if let Some(mount) = mount_lookup_for_abs(&abs).filter(|mount| mount.target != "/") {
        let suffix = if abs == mount.target {
            String::new()
        } else {
            String::from(abs[mount.target.len()..].trim_start_matches('/'))
        };
        let Some(base) = find_path_in_roots(&mount.source) else {
            return Err(err(SyscallError::ENOENT));
        };
        return Ok(AtPath::Ext4Rel {
            base,
            rel: suffix,
            cache_abs: Some(translate_mount_abs(&abs)),
        });
    } else {
        normalize_relative_path(path)
    };
    let (fsuid, fsgid) = current_fsuid_gid();
    let mut depth = 0usize;
    let mut seen_symlinks = Vec::new();
    let base = resolve_ext4_abs_path(
        &translate_mount_abs(base_path),
        fsuid,
        fsgid,
        true,
        &mut depth,
        &mut seen_symlinks,
    )?;
    Ok(AtPath::Ext4Rel {
        base,
        rel,
        cache_abs: Some(translate_mount_abs(&abs)),
    })
}

/// 从已知 ext4 目录 inode 出发解析相对路径。
/// 若有逻辑路径上下文，优先通过逻辑路径检测伪文件系统或挂载点；
/// 否则直接返回相对于该 inode 的 `Ext4Rel`。
pub(crate) fn resolve_relative_at_path_from_ext4_base(
    base: alloc::sync::Arc<ext4_fs::Inode>,
    logical_base: Option<String>,
    path: &str,
) -> Result<AtPath, isize> {
    if let Some(logical_base) = logical_base {
        let logical_abs = normalize_path(&logical_base, path);
        let abs = resolve_mounted_proc_magic_intermediate_abs_path(&logical_abs)?;
        if abs != logical_abs {
            return Ok(classify_abs_at_path(abs));
        }
    }
    if let Some(abs) = pseudo_abs_for_ext4_dirfd(&base, path) {
        return Ok(AtPath::PseudoAbs(abs));
    }
    let rel = normalize_relative_path(path);
    Ok(AtPath::Ext4Rel {
        base,
        rel,
        cache_abs: None,
    })
}

/// 核心函数
/// 将 `(dirfd, path)` 解析为 `AtPath`，统一处理绝对路径、相对路径、
/// `AT_FDCWD`、进程 chroot jail、路径长度/分量校验。
/// 这是所有文件系统系统调用路径解析的统一入口。 是外部传入的路径 变成 内部数据结构AtPath的器idian
pub(crate) fn resolve_at_path(dirfd: isize, path: &str) -> Result<AtPath, isize> {
    // pre check
    if path.is_empty() {
        return Err(err(SyscallError::ENOENT));
    }
    if path.len() > PATH_MAX {
        return Err(err(SyscallError::ENAMETOOLONG));
    }
    validate_path_components(path)?;

    // Absolute path: ignore dirfd.
    // if starts with / then it must be real path or psudo
    // This is decided in the classify function
    if path.starts_with('/') {
        let jail_abs = normalize_path("/", path);
        let abs = resolve_mounted_proc_magic_intermediate_abs_path(&apply_process_root(&jail_abs))?;
        return Ok(classify_abs_at_path(abs));
    }

    // handle relative address:
    match resolve_relative_at_path_base(dirfd)? {
        RelativeAtPathBase::LogicalAbs(base_path) => {
            resolve_relative_at_path_from_logical_base(&base_path, path)
        }
        RelativeAtPathBase::Ext4Dir { base, logical_base } => {
            resolve_relative_at_path_from_ext4_base(base, logical_base, path)
        }
    }
}

/// 从挂载翻译后的 ext4 绝对路径解析 inode。
///
/// `root_inode_for_path` selects exactly one backing filesystem.  An ENOENT
/// therefore stays on that filesystem and never falls through to another disk.
/// 每个路径分量在查找时获取父目录的共享 inode 锁。
pub(crate) fn resolve_ext4_abs_path(
    path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
    depth: &mut usize,
    seen_symlinks: &mut Vec<u32>,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let abs = crate::fs::normalize_proc_magic_path(path).into_owned();

    let primary = crate::fs::root_inode_for_path(&abs);
    let lookup_path = crate::fs::path_within_filesystem(&abs);
    if let Some(result) = resolve_ext4_abs_path_fast_cached(
        primary.clone(),
        &abs,
        lookup_path,
        uid,
        gid,
        follow_final,
    ) {
        return result;
    }
    let result = resolve_ext4_path(
        primary,
        lookup_path,
        uid,
        gid,
        follow_final,
        depth,
        seen_symlinks,
    );
    if let Ok(inode) = &result {
        note_ext4_path_cache(&abs, uid, gid, follow_final, inode);
    }
    result
}

fn resolve_ext4_abs_path_fast_cached(
    start: alloc::sync::Arc<ext4_fs::Inode>,
    cache_key: &str,
    lookup_path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Option<Result<alloc::sync::Arc<ext4_fs::Inode>, isize>> {
    let result = resolve_ext4_path_fast_no_symlink(start, lookup_path, uid, gid, follow_final)?;
    if let Ok(inode) = &result {
        note_ext4_path_cache(cache_key, uid, gid, follow_final, inode);
    }
    Some(result)
}

/// 若 `path` 是当前进程的 `/proc/self/fd/<n>` 或 `/proc/<pid>/fd/<n>`，
/// 返回文件描述符编号，否则返回 `None`。
pub(crate) fn parse_proc_fd_for_current_process(path: &str) -> Option<usize> {
    let trimmed = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };
    let parse_fd = |s: &str| -> Option<usize> {
        if s.is_empty() || s.contains('/') || !s.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse::<usize>().ok()
    };

    if let Some(rest) = trimmed.strip_prefix("/proc/self/fd/") {
        return parse_fd(rest);
    }

    let pid = current_process().getpid();
    let prefix = alloc::format!("/proc/{}/fd/", pid);
    let rest = trimmed.strip_prefix(prefix.as_str())?;
    parse_fd(rest)
}

/// 处理 `*at` 系统调用 `path=""` 的情况：
/// 若设置了 `AT_EMPTY_PATH`，返回 `dirfd` 本身；
/// 否则 O_PATH fd 返回 `EBADF`，普通 fd 返回 `ENOENT`。
pub(crate) fn empty_path_fd_for_at_op(dirfd: isize, flags: usize) -> Result<usize, isize> {
    if dirfd < 0 {
        return Err(err(SyscallError::ENOENT));
    }
    let fd = dirfd as usize;
    if (flags & AT_EMPTY_PATH) != 0 {
        return Ok(fd);
    }
    // Some libc fallbacks retry fd-based metadata ops via empty-path *at calls.
    // Preserve O_PATH err(SyscallError::EBADF) semantics instead of leaking err(SyscallError::ENOENT).
    if fd_has_o_path(fd) {
        return Err(err(SyscallError::EBADF));
    }
    Err(err(SyscallError::ENOENT))
}

/// 若 `abs` 指向当前进程的 `/proc/<pid>/fd/<n>`，则直接以 fd 调用 `op` 并返回结果；
/// 设置了 `AT_SYMLINK_NOFOLLOW` 时跳过（不解引用符号链接）。
pub(crate) fn maybe_dispatch_proc_fd_at(
    abs: &str,
    flags: usize,
    op: impl FnOnce(usize) -> isize,
) -> Option<isize> {
    if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
        return None;
    }
    let fd = parse_proc_fd_for_current_process(abs)?;
    Some(op(fd))
}

/// 若原始绝对路径或 `AtPath` 指向 `/proc` 伪文件系统，返回对应路径字符串引用，
/// 供调用方走 proc 特殊处理分支。
pub(crate) fn proc_path_for_at(raw_abs: Option<&str>, at: &AtPath) -> Option<String> {
    let logical = raw_abs.or_else(|| match at {
        AtPath::PseudoAbs(abs) => Some(abs.as_str()),
        _ => None,
    })?;
    let (mount, _) = crate::fs::current_pseudo_canonical_abs(logical)?;
    matches!(mount.backend, crate::fs::MountBackend::Proc { .. }).then(|| String::from(logical))
}

/// 以指定模式重新打开一个已有文件（通常来自 `/proc/self/fd` 符号链接解析），
/// 安装为新 fd 并返回。若设置了 `O_TRUNC` 且非 O_PATH，则截断文件；
/// 截断失败时关闭新 fd 并向上传播错误。
pub(crate) fn reopen_proc_link_file(
    src_file: alloc::sync::Arc<dyn File + Send + Sync>,
    flags: usize,
    readable: bool,
    writable: bool,
    o_path: bool,
) -> Result<usize, isize> {
    let file: alloc::sync::Arc<dyn File + Send + Sync> =
        if let Some(shm) = src_file.as_any().downcast_ref::<PseudoShmFile>() {
            alloc::sync::Arc::new(shm.reopen_with_mode(readable, writable))
        } else {
            src_file
        };
    let fd = install_open_file_fd(file, flags, o_path)?;
    if !o_path && (flags & O_TRUNC) != 0 {
        let tr = syscall_ftruncate(fd, 0);
        if tr != 0 {
            let files = current_files();
            let detached = files.lock().clear_fd(fd);
            if let Some(detached) = detached {
                drop(detached.complete_close());
            }
            return Err(tr);
        }
    }
    Ok(fd)
}

/// 检查伪文件系统路径是否存在，返回 `0` 或 `ENOENT`。
/// 对 `/dev/shm/` 路径检查共享内存对象是否存在，其余路径通过 `open_pseudo` 探测。
pub(crate) fn pseudo_path_exists_result(abs: &str) -> isize {
    if let Some(name) = shm_object_name(abs) {
        return if shm_get(name).is_some() {
            0
        } else {
            err(SyscallError::ENOENT)
        };
    }
    if open_pseudo(abs).is_some() {
        0
    } else {
        err(SyscallError::ENOENT)
    }
}

/// read a C string by ptr from the space specified by token,
pub(crate) fn read_user_cstring(token: usize, ptr: usize) -> Result<String, isize> {
    if ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let mut out = String::new();
    for i in 0..=PATH_MAX {
        let ch = match try_read_user_value(token, (ptr + i) as *const u8) {
            Some(v) => v,
            None => return Err(err(SyscallError::EFAULT)),
        };
        if ch == 0 {
            return Ok(out);
        }
        out.push(ch as char);
        if out.len() > PATH_MAX {
            return Err(err(SyscallError::ENAMETOOLONG));
        }
    }
    Err(err(SyscallError::ENAMETOOLONG))
}

/// 校验扩展属性名称：非空、不超过 `XATTR_NAME_MAX`，且必须含 `namespace.key` 格式的点分隔符。
pub(crate) fn validate_xattr_name(name: &str) -> Result<(), isize> {
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(err(SyscallError::ERANGE));
    }
    let Some((ns, key)) = name.split_once('.') else {
        return Err(err(SyscallError::EINVAL));
    };
    if ns.is_empty() || key.is_empty() {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(())
}

/// 从用户空间读取扩展属性名称字符串并校验格式。
pub(crate) fn read_user_xattr_name(token: usize, ptr: usize) -> Result<String, isize> {
    let name = read_user_cstring(token, ptr)?;
    validate_xattr_name(&name)?;
    Ok(name)
}

/// 从用户空间读取扩展属性值（最多 `XATTR_SIZE_MAX` 字节），`size=0` 时返回空 `Vec`。
pub(crate) fn read_user_xattr_value(
    token: usize,
    value: usize,
    size: usize,
) -> Result<Vec<u8>, isize> {
    if size > XATTR_SIZE_MAX {
        return Err(err(SyscallError::E2BIG));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    if value == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let mut out = vec![0u8; size];
    if try_copy_from_user(token, value as *const u8, out.as_mut_slice()).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok(out)
}

/// 判断扩展属性名称是否属于 `user.` 命名空间（用户可写的 xattr 命名空间）。
pub(crate) fn xattr_is_user_namespace(name: &str) -> bool {
    name.starts_with("user.")
}

/// 判断 inode 是否支持 `user.*` 扩展属性（仅普通文件和目录支持）。
pub(crate) fn inode_supports_user_xattr(inode: &Arc<ext4_fs::Inode>) -> bool {
    inode.is_file() || inode.is_dir()
}

/// 从路径指针解析出用于 xattr 操作的 ext4 inode，拒绝伪文件系统路径。
pub(crate) fn resolve_xattr_path_inode(
    path_ptr: usize,
    follow_final: bool,
) -> Result<Arc<ext4_fs::Inode>, isize> {
    let token = get_current_token();
    let path = read_user_cstring(token, path_ptr)?;
    let at = resolve_at_path(AT_FDCWD, &path)?;
    if matches!(at, AtPath::PseudoAbs(_)) {
        return Err(err(SyscallError::ENOENT));
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    resolve_at_inode(&at, fsuid, fsgid, follow_final)
}

/// 从文件描述符解析出用于 xattr 操作的 ext4 inode。
/// O_PATH fd 返回 `EBADF`；非 inode 后端的 fd（如 socket）返回 `Ok(None)`。
pub(crate) fn resolve_xattr_fd_inode(fd: usize) -> Result<Option<Arc<ext4_fs::Inode>>, isize> {
    if fd_has_o_path(fd) {
        return Err(err(SyscallError::EBADF));
    }
    let Some(file) = get_fd_file(fd) else {
        return Err(err(SyscallError::EBADF));
    };
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        // Valid fd but no inode-backed xattr storage (e.g. socket/fifo wrappers).
        return Ok(None);
    };
    Ok(Some(os_inode.ext4_inode()))
}

/// 设置 inode 的扩展属性，遵循 `XATTR_CREATE`/`XATTR_REPLACE` 标志语义，
/// 拒绝 immutable/append-only inode 的修改，成功后更新 mtime/ctime。
pub(crate) fn do_setxattr(
    inode: &Arc<ext4_fs::Inode>,
    name: &str,
    value: &[u8],
    flags: usize,
) -> isize {
    let valid_flags = XATTR_CREATE | XATTR_REPLACE;
    if (flags & !valid_flags) != 0 || (flags & valid_flags) == valid_flags {
        return err(SyscallError::EINVAL);
    }
    if xattr_is_user_namespace(name) && !inode_supports_user_xattr(inode) {
        return err(SyscallError::EPERM);
    }
    if inode_is_immutable_or_append(inode) {
        return err(SyscallError::EPERM);
    }

    let ino = inode.inode_num() as u64;
    let mut all = INODE_XATTRS.lock();
    let attrs = all.entry(ino).or_default();
    let exists = attrs.contains_key(name);
    if (flags & XATTR_CREATE) != 0 && exists {
        return err(SyscallError::EEXIST);
    }
    if (flags & XATTR_REPLACE) != 0 && !exists {
        return err(SyscallError::ENODATA);
    }
    attrs.insert(String::from(name), value.to_vec());
    drop(all);
    touch_inode_mtime_ctime_now(inode);
    0
}

/// 读取 inode 的扩展属性值并写入用户缓冲区。
/// `size=0` 时仅返回值的字节长度（不写入数据），缓冲区不足时返回 `ERANGE`。
pub(crate) fn do_getxattr(
    inode: &Arc<ext4_fs::Inode>,
    name: &str,
    value_ptr: usize,
    size: usize,
    token: usize,
) -> isize {
    if xattr_is_user_namespace(name) && !inode_supports_user_xattr(inode) {
        return err(SyscallError::ENODATA);
    }
    let value = {
        let all = INODE_XATTRS.lock();
        let Some(attrs) = all.get(&(inode.inode_num() as u64)) else {
            return err(SyscallError::ENODATA);
        };
        let Some(val) = attrs.get(name) else {
            return err(SyscallError::ENODATA);
        };
        val.clone()
    };

    if size == 0 {
        return value.len() as isize;
    }
    if size < value.len() {
        return err(SyscallError::ERANGE);
    }
    if value_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    if try_copy_to_user(token, value_ptr as *mut u8, value.as_slice()).is_err() {
        return err(SyscallError::EFAULT);
    }
    value.len() as isize
}

/// 列出 inode 的所有扩展属性名称（`\0` 分隔）并写入用户缓冲区。
/// `size=0` 时仅返回所需字节数，缓冲区不足时返回 `ERANGE`。
pub(crate) fn do_listxattr(
    inode: &Arc<ext4_fs::Inode>,
    list_ptr: usize,
    size: usize,
    token: usize,
) -> isize {
    let data = {
        let mut out = Vec::new();
        let all = INODE_XATTRS.lock();
        if let Some(attrs) = all.get(&(inode.inode_num() as u64)) {
            for name in attrs.keys() {
                out.extend_from_slice(name.as_bytes());
                out.push(0);
            }
        }
        out
    };

    if size == 0 {
        return data.len() as isize;
    }
    if size < data.len() {
        return err(SyscallError::ERANGE);
    }
    if !data.is_empty() && list_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    if !data.is_empty() && try_copy_to_user(token, list_ptr as *mut u8, data.as_slice()).is_err() {
        return err(SyscallError::EFAULT);
    }
    data.len() as isize
}

/// 删除 inode 的指定扩展属性，不存在时返回 `ENODATA`，
/// immutable/append-only inode 返回 `EPERM`，成功后更新 mtime/ctime。
pub(crate) fn do_removexattr(inode: &Arc<ext4_fs::Inode>, name: &str) -> isize {
    if xattr_is_user_namespace(name) && !inode_supports_user_xattr(inode) {
        return err(SyscallError::ENODATA);
    }
    if inode_is_immutable_or_append(inode) {
        return err(SyscallError::EPERM);
    }

    let ino = inode.inode_num() as u64;
    let mut all = INODE_XATTRS.lock();
    let Some(attrs) = all.get_mut(&ino) else {
        return err(SyscallError::ENODATA);
    };
    if attrs.remove(name).is_none() {
        return err(SyscallError::ENODATA);
    }
    let became_empty = attrs.is_empty();
    if became_empty {
        all.remove(&ino);
    }
    drop(all);
    touch_inode_mtime_ctime_now(inode);
    0
}

/// 从 ext4 起始 inode 出发，按路径分量逐级查找目标 inode，完整处理：
/// - `.` / `..` 导航（含跨越起始点的 `..`）；
/// - 目录执行权限检查（`x` 位）；
/// - 符号链接解引用（`follow_final` 控制是否解引用最后一个分量），
///   检测循环（深度 + 已见 inode 集合），绝对符号链接回到根解析。
/// 每个路径分量在查找时获取父目录的共享 inode 锁。
pub(crate) fn resolve_ext4_path(
    start: alloc::sync::Arc<ext4_fs::Inode>,
    path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
    depth: &mut usize,
    seen_symlinks: &mut Vec<u32>,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    if let Some(result) = resolve_ext4_path_fast_no_symlink(
        alloc::sync::Arc::clone(&start),
        path,
        uid,
        gid,
        follow_final,
    ) {
        return result;
    }

    let mut stack: Vec<alloc::sync::Arc<ext4_fs::Inode>> = alloc::vec![start];
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut idx = 0usize;
    while idx < components.len() {
        let seg = components[idx];
        if seg == "." {
            idx += 1;
            continue;
        }
        if seg == ".." {
            let cur = stack.last().unwrap().clone();
            let cur_lock = ext4_inode_lock(&cur);
            let _cur_guard = cur_lock.read();
            if !cur.is_dir() {
                return Err(err(SyscallError::ENOTDIR));
            }
            if !inode_mode_allows_uid_gid(&cur, 1, uid, gid) {
                return Err(err(SyscallError::EACCES));
            }
            if stack.len() > 1 {
                stack.pop();
            } else if let Some(parent) = cur.find("..") {
                // When walking from a non-root start inode (e.g. resolving a
                // relative symlink target), ".." must be able to climb above
                // that start directory.
                if parent.inode_num() != cur.inode_num() {
                    stack[0] = parent;
                }
            }
            idx += 1;
            continue;
        }
        let cur = stack.last().unwrap().clone();
        let next = {
            let cur_lock = ext4_inode_lock(&cur);
            let _cur_guard = cur_lock.read();
            if !cur.is_dir() {
                return Err(err(SyscallError::ENOTDIR));
            }
            if !inode_mode_allows_uid_gid(&cur, 1, uid, gid) {
                return Err(err(SyscallError::EACCES));
            }
            let Some(next) = cur.find(seg) else {
                return Err(err(SyscallError::ENOENT));
            };
            next
        };
        let is_last = idx + 1 == components.len();
        let next_lock = ext4_inode_lock(&next);
        let next_guard = next_lock.read();
        if next.is_symlink() && (follow_final || !is_last) {
            if *depth >= MAX_SYMLINKS {
                return Err(err(SyscallError::ELOOP));
            }
            let inode_num = next.inode_num();
            if seen_symlinks.iter().any(|&n| n == inode_num) {
                return Err(err(SyscallError::ELOOP));
            }
            seen_symlinks.push(inode_num);
            *depth += 1;
            let target_bytes = next.read_all();
            drop(next_guard);
            let target = String::from_utf8_lossy(&target_bytes).into_owned();
            if target.is_empty() {
                return Err(err(SyscallError::ENOENT));
            }
            let remaining = if is_last {
                String::new()
            } else {
                components[idx + 1..].join("/")
            };
            let mut new_path = target;
            if !remaining.is_empty() {
                if !new_path.ends_with('/') {
                    new_path.push('/');
                }
                new_path.push_str(&remaining);
            }
            if new_path.starts_with('/') {
                let translated = translate_mount_abs(&new_path);
                return resolve_ext4_abs_path(
                    &translated,
                    uid,
                    gid,
                    follow_final,
                    depth,
                    seen_symlinks,
                );
            }
            return resolve_ext4_path(cur, &new_path, uid, gid, follow_final, depth, seen_symlinks);
        }
        drop(next_guard);
        stack.push(next);
        idx += 1;
    }
    Ok(stack.last().unwrap().clone())
}

fn resolve_ext4_path_fast_no_symlink(
    start: alloc::sync::Arc<ext4_fs::Inode>,
    path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Option<Result<alloc::sync::Arc<ext4_fs::Inode>, isize>> {
    let mut cur = start;
    let mut components = path.split('/').filter(|s| !s.is_empty()).peekable();
    while let Some(seg) = components.next() {
        if seg == "." || seg == ".." {
            return None;
        }
        let next = {
            let cur_lock = ext4_inode_lock(&cur);
            let _cur_guard = cur_lock.read();
            if !cur.is_dir() {
                return Some(Err(err(SyscallError::ENOTDIR)));
            }
            if !inode_mode_allows_uid_gid(&cur, 1, uid, gid) {
                return Some(Err(err(SyscallError::EACCES)));
            }
            let Some(next) = cur.find(seg) else {
                return Some(Err(err(SyscallError::ENOENT)));
            };
            next
        };
        let is_last = components.peek().is_none();
        let next_is_symlink = {
            let next_lock = ext4_inode_lock(&next);
            let _next_guard = next_lock.read();
            next.is_symlink()
        };
        if next_is_symlink && (follow_final || !is_last) {
            return None;
        }
        cur = next;
    }
    Some(Ok(cur))
}

/// 将 `AtPath` 解析为 ext4 inode，统一分发到绝对路径或相对 inode 两条路径。
/// `PseudoAbs` 路径无法解析为 inode，返回 `ENOENT`。
pub(crate) fn resolve_at_inode(
    at: &AtPath,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let mut depth = 0usize;
    let mut seen_symlinks = Vec::new();
    match at {
        AtPath::Ext4Abs(abs) => {
            resolve_ext4_abs_path(abs, uid, gid, follow_final, &mut depth, &mut seen_symlinks)
        }
        AtPath::Ext4Rel {
            base,
            rel,
            cache_abs: _,
        } => {
            if rel.is_empty() {
                Ok(alloc::sync::Arc::clone(base))
            } else {
                resolve_ext4_path(
                    alloc::sync::Arc::clone(base),
                    rel,
                    uid,
                    gid,
                    follow_final,
                    &mut depth,
                    &mut seen_symlinks,
                )
            }
        }
        AtPath::PseudoAbs(_) => Err(err(SyscallError::ENOENT)),
    }
}

/// 解析可执行文件路径为 inode，校验：不在 noexec 挂载点、是普通文件、有执行权限。
/// `.sh` 文件检查读权限（`r` 位）而非执行权限（`x` 位）。
pub(crate) fn resolve_exec_inode(path: &str) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    if let Some(abs) = resolve_abs_path(AT_FDCWD, path)? {
        if path_is_noexec(&abs) {
            return Err(err(SyscallError::EACCES));
        }
    }
    let at = resolve_at_path(AT_FDCWD, path)?;
    if let AtPath::PseudoAbs(_) = &at {
        return Err(err(SyscallError::ENOENT));
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let inode = resolve_at_inode(&at, fsuid, fsgid, true)?;
    let inode_lock = ext4_inode_lock(&inode);
    let _inode_guard = inode_lock.read();
    if !inode.is_file() {
        return Err(err(SyscallError::EACCES));
    }
    let exec_mask = if path.ends_with(".sh") { 4 } else { 1 };
    if !inode_mode_allows_uid_gid(&inode, exec_mask, fsuid, fsgid) {
        return Err(err(SyscallError::EACCES));
    }
    Ok(inode)
}

/// `execveat` 版本的可执行 inode 解析，支持 `AT_EMPTY_PATH`（对 fd 本身执行）
/// 和 `AT_SYMLINK_NOFOLLOW`（不解引用最终符号链接，此时若目标是符号链接则报 `ELOOP`）。
pub(crate) fn resolve_exec_inode_at(
    dirfd: isize,
    path: &str,
    flags: usize,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let valid_flags = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;
    if (flags & !valid_flags) != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    if !path.is_empty() {
        if let Some(abs) = resolve_abs_path(dirfd, path)? {
            if path_is_noexec(&abs) {
                return Err(err(SyscallError::EACCES));
            }
        }
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let inode = if path.is_empty() {
        if (flags & AT_EMPTY_PATH) == 0 {
            return Err(err(SyscallError::ENOENT));
        }
        if dirfd < 0 {
            return Err(err(SyscallError::EBADF));
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return Err(err(SyscallError::EBADF));
        };
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return Err(err(SyscallError::ENOTDIR));
        };
        os_inode.ext4_inode()
    } else {
        let at = resolve_at_path(dirfd, path)?;
        if let AtPath::PseudoAbs(_) = &at {
            return Err(err(SyscallError::ENOENT));
        }
        let inode = resolve_at_inode(&at, fsuid, fsgid, follow_final)?;
        let is_symlink = {
            let inode_lock = ext4_inode_lock(&inode);
            let _inode_guard = inode_lock.read();
            inode.is_symlink()
        };
        if !follow_final && is_symlink {
            return Err(err(SyscallError::ELOOP));
        }
        inode
    };
    let inode_lock = ext4_inode_lock(&inode);
    let _inode_guard = inode_lock.read();
    if !inode.is_file() {
        return Err(err(SyscallError::EACCES));
    }
    let exec_mask = if path.ends_with(".sh") { 4 } else { 1 };
    if !inode_mode_allows_uid_gid(&inode, exec_mask, fsuid, fsgid) {
        return Err(err(SyscallError::EACCES));
    }
    Ok(inode)
}

/// 解析路径为可读文件的 inode，校验是普通文件且当前用户有读权限（`r` 位）。
pub(crate) fn resolve_read_inode(path: &str) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let at = resolve_at_path(AT_FDCWD, path)?;
    if let AtPath::PseudoAbs(_) = &at {
        return Err(err(SyscallError::ENOENT));
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let inode = resolve_at_inode(&at, fsuid, fsgid, true)?;
    let inode_lock = ext4_inode_lock(&inode);
    let _inode_guard = inode_lock.read();
    if !inode.is_file() {
        return Err(err(SyscallError::EACCES));
    }
    if !inode_mode_allows_uid_gid(&inode, 4, fsuid, fsgid) {
        return Err(err(SyscallError::EACCES));
    }
    Ok(inode)
}

/// Linux `acct(2)` (syscall 89 on riscv64).
///
/// We only validate the path and permissions for LTP. Accounting is not enabled.

/// 将 `AtPath` 拆分为父目录 inode 和末尾名称，用于 `create`/`link`/`rename` 等需要
/// 操作父目录的系统调用。`PseudoAbs` 路径返回 `EROFS`。
pub(crate) fn resolve_parent_and_name(
    at: &AtPath,
    uid: u32,
    gid: u32,
) -> Result<(alloc::sync::Arc<ext4_fs::Inode>, alloc::string::String), isize> {
    let mut depth = 0usize;
    let mut seen_symlinks = Vec::new();
    match at {
        AtPath::Ext4Abs(abs) => {
            if abs == "/" {
                return Err(err(SyscallError::EINVAL));
            }
            let Some((parent_path, name)) = split_parent_and_name(abs) else {
                return Err(err(SyscallError::EINVAL));
            };
            if name.is_empty() {
                return Err(err(SyscallError::EINVAL));
            }
            let parent_abs = if parent_path.is_empty() {
                alloc::string::String::from("/")
            } else {
                let mut p = alloc::string::String::from("/");
                p.push_str(parent_path);
                p
            };
            let parent =
                resolve_ext4_abs_path(&parent_abs, uid, gid, true, &mut depth, &mut seen_symlinks)?;
            Ok((parent, alloc::string::String::from(name)))
        }
        AtPath::Ext4Rel { base, rel, .. } => {
            if rel.is_empty() {
                return Err(err(SyscallError::EINVAL));
            }
            let Some((parent_path, name)) = split_parent_and_name(rel) else {
                return Err(err(SyscallError::EINVAL));
            };
            if name.is_empty() {
                return Err(err(SyscallError::EINVAL));
            }
            let parent = if parent_path.is_empty() {
                alloc::sync::Arc::clone(base)
            } else {
                resolve_ext4_path(
                    alloc::sync::Arc::clone(base),
                    parent_path,
                    uid,
                    gid,
                    true,
                    &mut depth,
                    &mut seen_symlinks,
                )?
            };
            Ok((parent, alloc::string::String::from(name)))
        }
        AtPath::PseudoAbs(_) => Err(err(SyscallError::EROFS)),
    }
}

/// 将 `(dirfd, path)` 解析为规范化的逻辑绝对路径字符串（不进入 ext4 查找）。
/// 路径为空时返回 `Ok(None)`；主要用于挂载点/noexec 检查等不需要 inode 的场景。
/// attetion: path can have relative parts.'abs' means the final result is abs path
pub(crate) fn resolve_abs_path(dirfd: isize, path: &str) -> Result<Option<String>, isize> {
    if path.is_empty() {
        return Ok(None);
    }
    let abs = if path.starts_with('/') {
        normalize_path("/", path)
    } else {
        let cwd = current_cwd_path();
        if dirfd == AT_FDCWD {
            normalize_path(&cwd, path)
        } else if dirfd >= 0 {
            // If dirfd refers to a pseudo directory, resolve relative to it.
            // For ext4 dirfds, prefer procfs fd symlink target to preserve mount context.
            let Some(file) = get_fd_file(dirfd as usize) else {
                return Ok(None);
            };
            let base = logical_path_for_open_fd(dirfd as usize, &file, &cwd);
            normalize_path(&base, path)
        } else {
            return Ok(None);
        }
    };
    // handle magic part like self or /proc/self/fd/4 . changes these to real path
    resolve_mounted_proc_magic_intermediate_abs_path(&abs).map(Some)
}

/// is path on Read only file sytem?
pub(crate) fn rofs_for_path(dirfd: isize, path: &str) -> bool {
    resolve_abs_path(dirfd, path)
        .ok()
        .flatten()
        .map(|abs| path_is_rofs(&abs))
        .unwrap_or(false)
}
