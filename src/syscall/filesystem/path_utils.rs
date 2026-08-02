use super::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Arc, INODE_XATTRS, MAX_SYMLINKS, NAME_MAX,
    OSInode, PATH_MAX, PseudoDir, String, SyscallError, Vec, VfsOpenedFile, XATTR_CREATE,
    XATTR_NAME_MAX, XATTR_REPLACE, XATTR_SIZE_MAX, clear_ext4_path_cache, current_cwd_path,
    current_fsuid_gid, current_process, err, ext4_inode_lock, fd_has_o_path, find_path_in_roots,
    get_fd_file, inode_is_immutable_or_append, inode_mode_allows_uid_gid,
    invalidate_ext4_path_cache, invalidate_ext4_path_cache_subtree, logical_path_for_inode,
    logical_path_for_open_fd, note_ext4_path_cache, touch_inode_mtime_ctime_now,
    try_copy_from_user, try_copy_to_user, try_read_user_value,
};
use crate::fs::ext4::Ext4VfsNode;
use crate::fs::vfs::{
    LookupFlags, PathWalker, VfsCredentials, VfsError, VfsMountNamespace, VfsPath,
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

/// 返回当前进程的根目录（`chroot` 设置的路径，默认 `"/"`）。
pub(crate) fn current_process_root() -> String {
    current_process().fs_struct().root_display()
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
        vfs_base: Option<VfsPath>,
    },
    /// Directory descriptor backed directly by an object-VFS path.
    VfsDir {
        base: VfsPath,
    },
}

#[derive(Clone)]
pub(crate) struct VfsAtPath {
    namespace: Arc<VfsMountNamespace>,
    root: VfsPath,
    start: VfsPath,
    path: String,
}

pub(crate) enum AtPath {
    /// Object VFS lookup.  The path remains unresolved until the caller chooses
    /// whether to follow the final symlink, matching Linux namei lookup flags.
    Vfs(VfsAtPath),
    /// An ext4 lookup rooted at `/`.
    Ext4Abs(String),
    /// An ext4 lookup rooted at an open directory fd.
    Ext4Rel {
        base: alloc::sync::Arc<ext4_fs::Inode>,
        rel: String,
        /// Translated absolute path used only for path-cache invalidation.
        cache_abs: Option<String>,
    },
}

pub(crate) fn invalidate_ext4_path_cache_for_at(at: &AtPath, subtree: bool) {
    let Some(path) = (match at {
        AtPath::Vfs(_) => return,
        AtPath::Ext4Abs(abs) => Some(abs.as_str()),
        AtPath::Ext4Rel {
            cache_abs: Some(abs),
            ..
        } => Some(abs.as_str()),
        AtPath::Ext4Rel { .. } => None,
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

/// 将绝对路径字符串转换为 `AtPath` 枚举，区分 ext4 路径与伪文件系统路径。
pub(crate) fn classify_abs_at_path(abs: String) -> AtPath {
    // Linux starts absolute lookup from the process's pinned root path.  The
    // mount graph, not a presentation record or translated provider string,
    // selects the filesystem for every component.
    if let Some(at) = vfs_at_from_logical_abs(&abs) {
        return at;
    }
    // Only legacy internal callers can supply a spelling outside the current
    // chroot.  Do not reinterpret it through a mount-record source string.
    AtPath::Ext4Abs(abs)
}

fn logical_path_below_process_root(abs: &str, root: &str) -> Option<String> {
    if root == "/" {
        return Some(String::from(abs));
    }
    if abs == root {
        return Some(String::from("/"));
    }
    let suffix = abs.strip_prefix(root)?;
    if !suffix.starts_with('/') {
        return None;
    }
    Some(String::from(suffix))
}

fn vfs_at_from_logical_abs(abs: &str) -> Option<AtPath> {
    let process = current_process();
    let fs = process.fs_struct();
    let path = logical_path_below_process_root(abs, &fs.root_display())?;
    let root = fs.root().path().clone();
    let namespace = process.mount_namespace().lock().vfs_namespace();
    Some(AtPath::Vfs(VfsAtPath {
        namespace,
        root: root.clone(),
        start: root,
        path,
    }))
}

fn vfs_at_from_start(start: VfsPath, path: &str) -> AtPath {
    let process = current_process();
    let fs = process.fs_struct();
    AtPath::Vfs(VfsAtPath {
        namespace: process.mount_namespace().lock().vfs_namespace(),
        root: fs.root().path().clone(),
        start,
        path: String::from(path),
    })
}

pub(crate) fn map_vfs_error(error: VfsError) -> isize {
    err(match error {
        VfsError::Access => SyscallError::EACCES,
        VfsError::Permission => SyscallError::EPERM,
        VfsError::Busy => SyscallError::EBUSY,
        VfsError::CrossDevice => SyscallError::EXDEV,
        VfsError::Exists => SyscallError::EEXIST,
        VfsError::Invalid => SyscallError::EINVAL,
        VfsError::Io => SyscallError::EIO,
        VfsError::IsDirectory => SyscallError::EISDIR,
        VfsError::Loop => SyscallError::ELOOP,
        VfsError::NameTooLong => SyscallError::ENAMETOOLONG,
        VfsError::NoEntry => SyscallError::ENOENT,
        VfsError::NoProcess => SyscallError::ESRCH,
        VfsError::NoDevice => SyscallError::ENODEV,
        VfsError::NoSpace => SyscallError::ENOSPC,
        VfsError::NotDirectory => SyscallError::ENOTDIR,
        VfsError::NotEmpty => SyscallError::ENOTEMPTY,
        VfsError::NotSupported => SyscallError::EOPNOTSUPP,
        VfsError::ReadOnly => SyscallError::EROFS,
    })
}

pub(crate) fn resolve_at_vfs_path(
    at: &AtPath,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Result<Option<VfsPath>, isize> {
    resolve_at_vfs_path_with_flags(
        at,
        uid,
        gid,
        LookupFlags(if follow_final {
            LookupFlags::FOLLOW_FINAL
        } else {
            0
        }),
    )
}

/// Resolve an object pathname with the caller's complete namei policy.
/// `openat2(2)` needs to carry scoped lookup flags all the way to the walker;
/// reconstructing a normalized absolute path here would erase escape attempts.
pub(crate) fn resolve_at_vfs_path_with_flags(
    at: &AtPath,
    uid: u32,
    gid: u32,
    flags: LookupFlags,
) -> Result<Option<VfsPath>, isize> {
    let AtPath::Vfs(vfs) = at else {
        return Ok(None);
    };
    PathWalker::new(Arc::clone(&vfs.namespace))
        .walk(
            &vfs.root,
            &vfs.start,
            &vfs.path,
            flags,
            VfsCredentials { uid, gid },
        )
        .map(Some)
        .map_err(map_vfs_error)
}

/// Return whether an object-VFS pathname resolves to the process root without
/// following its final symlink.  Linux namei treats that root as a real pinned
/// `struct path`; callers must not infer it from a spelling such as `"/"`.
pub(crate) fn vfs_at_path_is_process_root(at: &AtPath, uid: u32, gid: u32) -> Result<bool, isize> {
    let AtPath::Vfs(vfs) = at else {
        return Ok(false);
    };
    let path = resolve_at_vfs_path(at, uid, gid, false)?
        .expect("Vfs AtPath must resolve to an object path");
    Ok(path.same_object(&vfs.root))
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
    if let Some(base) = file.object_path() {
        let metadata = base.node().metadata().map_err(map_vfs_error)?;
        if metadata.kind != crate::fs::vfs::VfsNodeKind::Directory {
            return Err(err(SyscallError::ENOTDIR));
        }
        return Ok(RelativeAtPathBase::VfsDir { base: base.clone() });
    }
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Ok(RelativeAtPathBase::LogicalAbs(String::from(pdir.path())));
    }
    if let Some(vfs_file) = file.as_any().downcast_ref::<VfsOpenedFile>() {
        if vfs_file.kind() != crate::fs::vfs::VfsNodeKind::Directory {
            return Err(err(SyscallError::ENOTDIR));
        }
        return Ok(RelativeAtPathBase::VfsDir {
            base: vfs_file.path().clone(),
        });
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
        vfs_base: os_inode.vfs_path().map(|path| path.path().clone()),
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
    let fs = current_process().fs_struct();
    if base_path == fs.cwd_display() {
        return Ok(vfs_at_from_start(fs.cwd().path().clone(), path));
    }
    // A legacy directory object without `File::object_path()` can still carry
    // a logical spelling. Re-enter the authoritative graph from the process
    // root. The ext4 fallback remains only for such pre-VFS descriptors whose
    // spelling lies outside the current chroot.
    if let Some(at) = vfs_at_from_logical_abs(&logical_abs) {
        return Ok(at);
    }
    Ok(AtPath::Ext4Abs(logical_abs))
}

/// 从已知 ext4 目录 inode 出发解析相对路径。
/// 若有逻辑路径上下文，优先通过逻辑路径检测伪文件系统或挂载点；
/// 否则直接返回相对于该 inode 的 `Ext4Rel`。
pub(crate) fn resolve_relative_at_path_from_ext4_base(
    base: alloc::sync::Arc<ext4_fs::Inode>,
    _logical_base: Option<String>,
    vfs_base: Option<VfsPath>,
    path: &str,
) -> Result<AtPath, isize> {
    if let Some(vfs_base) = vfs_base {
        return Ok(vfs_at_from_start(vfs_base, path));
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
        let abs = apply_process_root(&jail_abs);
        return Ok(classify_abs_at_path(abs));
    }

    // handle relative address:
    match resolve_relative_at_path_base(dirfd)? {
        RelativeAtPathBase::LogicalAbs(base_path) => {
            resolve_relative_at_path_from_logical_base(&base_path, path)
        }
        RelativeAtPathBase::Ext4Dir {
            base,
            logical_base,
            vfs_base,
        } => resolve_relative_at_path_from_ext4_base(base, logical_base, vfs_base, path),
        RelativeAtPathBase::VfsDir { base, .. } => Ok(vfs_at_from_start(base, path)),
    }
}

fn openat2_object_start(dirfd: isize, require_directory: bool) -> Result<VfsPath, isize> {
    if dirfd == AT_FDCWD {
        return Ok(current_process().fs_struct().cwd().path().clone());
    }
    if dirfd < 0 {
        return Err(err(SyscallError::EBADF));
    }
    let file = get_fd_file(dirfd as usize).ok_or_else(|| err(SyscallError::EBADF))?;
    let path = file
        .object_path()
        .cloned()
        .ok_or_else(|| err(SyscallError::EOPNOTSUPP))?;
    if require_directory
        && path.node().metadata().map_err(map_vfs_error)?.kind
            != crate::fs::vfs::VfsNodeKind::Directory
    {
        return Err(err(SyscallError::ENOTDIR));
    }
    Ok(path)
}

/// Preserve the unresolved spelling required by `openat2(2)` scoped lookup.
/// In particular, `RESOLVE_IN_ROOT` makes even an absolute pathname start at
/// `dirfd`, while `O_EMPTYPATH` resolves the descriptor object itself.
pub(crate) fn resolve_openat2_path(
    dirfd: isize,
    path: &str,
    lookup_flags: LookupFlags,
) -> Result<AtPath, isize> {
    if path.len() > PATH_MAX {
        return Err(err(SyscallError::ENAMETOOLONG));
    }
    validate_path_components(path)?;

    if path.is_empty() {
        if !lookup_flags.contains(LookupFlags::ALLOW_EMPTY) {
            return Err(err(SyscallError::ENOENT));
        }
        return Ok(vfs_at_from_start(openat2_object_start(dirfd, false)?, path));
    }

    if lookup_flags.contains(LookupFlags::IN_ROOT) {
        return Ok(vfs_at_from_start(openat2_object_start(dirfd, true)?, path));
    }

    // Ordinary and LOOKUP_BENEATH lookups retain openat(2)'s dirfd rules.
    // The walker, not lexical normalization, decides whether `..`, symlinks,
    // or a mount transition escapes the scoped start object.
    resolve_at_path(dirfd, path)
}

/// Resolve the parent object path and final name for an object-VFS pathname.
/// Non-object transitional paths return `Ok(None)`.
pub(crate) fn resolve_parent_vfs_path(
    at: &AtPath,
    uid: u32,
    gid: u32,
) -> Result<Option<crate::fs::vfs::VfsParentPath>, isize> {
    resolve_parent_vfs_path_with_flags(at, uid, gid, LookupFlags::default())
}

pub(crate) fn resolve_parent_vfs_path_with_flags(
    at: &AtPath,
    uid: u32,
    gid: u32,
    flags: LookupFlags,
) -> Result<Option<crate::fs::vfs::VfsParentPath>, isize> {
    let AtPath::Vfs(vfs) = at else {
        return Ok(None);
    };
    PathWalker::new(Arc::clone(&vfs.namespace))
        .walk_parent(
            &vfs.root,
            &vfs.start,
            &vfs.path,
            flags,
            VfsCredentials { uid, gid },
        )
        .map(Some)
        .map_err(map_vfs_error)
}

/// Remove one positive dentry after a successful namespace mutation. Mutable
/// backends still revalidate lookups, but explicit invalidation avoids keeping
/// a replaced name attached to an open-unlinked object longer than necessary.
pub(crate) fn invalidate_vfs_parent_entry(parent: &crate::fs::vfs::VfsParentPath) {
    parent
        .parent
        .mount()
        .filesystem()
        .dentry_cache()
        .invalidate(parent.parent.dentry(), &parent.name);
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
                // Linux restarts an absolute symlink at current->fs->root and
                // then performs ordinary mount-aware namei.  Re-enter the
                // object walker instead of translating the target to a mount
                // source pathname.
                let at = resolve_at_path(AT_FDCWD, &new_path)?;
                return resolve_at_inode(&at, uid, gid, follow_final);
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
/// Object paths are downcast only when the caller specifically requires an
/// ext4 inode; non-ext4 nodes return `EOPNOTSUPP`.
pub(crate) fn resolve_at_inode(
    at: &AtPath,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let mut depth = 0usize;
    let mut seen_symlinks = Vec::new();
    match at {
        AtPath::Vfs(_) => {
            let path = resolve_at_vfs_path(at, uid, gid, follow_final)?
                .expect("Vfs AtPath must resolve to an object path");
            path.node()
                .as_any()
                .downcast_ref::<Ext4VfsNode>()
                .map(|node| Arc::clone(node.inode()))
                .ok_or_else(|| err(SyscallError::EOPNOTSUPP))
        }
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
    }
}

pub(crate) fn resolve_at_inode_with_vfs_path(
    at: &AtPath,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Result<(Arc<ext4_fs::Inode>, Option<VfsPath>), isize> {
    resolve_at_inode_with_vfs_path_flags(
        at,
        uid,
        gid,
        LookupFlags(if follow_final {
            LookupFlags::FOLLOW_FINAL
        } else {
            0
        }),
    )
}

pub(crate) fn resolve_at_inode_with_vfs_path_flags(
    at: &AtPath,
    uid: u32,
    gid: u32,
    flags: LookupFlags,
) -> Result<(Arc<ext4_fs::Inode>, Option<VfsPath>), isize> {
    if let Some(path) = resolve_at_vfs_path_with_flags(at, uid, gid, flags)? {
        let inode = path
            .node()
            .as_any()
            .downcast_ref::<Ext4VfsNode>()
            .map(|node| Arc::clone(node.inode()))
            .ok_or_else(|| err(SyscallError::EOPNOTSUPP))?;
        return Ok((inode, Some(path)));
    }
    resolve_at_inode(at, uid, gid, flags.contains(LookupFlags::FOLLOW_FINAL))
        .map(|inode| (inode, None))
}

/// 解析可执行文件路径为 inode，校验：不在 noexec 挂载点、是普通文件、有执行权限。
/// `.sh` 文件检查读权限（`r` 位）而非执行权限（`x` 位）。
pub(crate) fn resolve_exec_inode(path: &str) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let at = resolve_at_path(AT_FDCWD, path)?;
    let (fsuid, fsgid) = current_fsuid_gid();
    let (inode, vfs_path) = resolve_at_inode_with_vfs_path(&at, fsuid, fsgid, true)?;
    if vfs_path
        .as_ref()
        .is_some_and(|path| path.mount().flags().is_noexec())
    {
        return Err(err(SyscallError::EACCES));
    }
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
    let (fsuid, fsgid) = current_fsuid_gid();
    let follow_final = (flags & AT_SYMLINK_NOFOLLOW) == 0;
    let (inode, vfs_path) = if path.is_empty() {
        if (flags & AT_EMPTY_PATH) == 0 {
            return Err(err(SyscallError::ENOENT));
        }
        if dirfd < 0 {
            return Err(err(SyscallError::EBADF));
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return Err(err(SyscallError::EBADF));
        };
        let vfs_path = file.object_path().cloned();
        let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
            return Err(err(SyscallError::ENOTDIR));
        };
        (os_inode.ext4_inode(), vfs_path)
    } else {
        let at = resolve_at_path(dirfd, path)?;
        let (inode, vfs_path) = resolve_at_inode_with_vfs_path(&at, fsuid, fsgid, follow_final)?;
        let is_symlink = {
            let inode_lock = ext4_inode_lock(&inode);
            let _inode_guard = inode_lock.read();
            inode.is_symlink()
        };
        if !follow_final && is_symlink {
            return Err(err(SyscallError::ELOOP));
        }
        (inode, vfs_path)
    };
    if vfs_path
        .as_ref()
        .is_some_and(|path| path.mount().flags().is_noexec())
    {
        return Err(err(SyscallError::EACCES));
    }
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
/// 操作父目录的系统调用。Object backends are handled by
/// `resolve_parent_vfs_path`; this helper is the ext4 adapter boundary.
pub(crate) fn resolve_parent_and_name(
    at: &AtPath,
    uid: u32,
    gid: u32,
) -> Result<(alloc::sync::Arc<ext4_fs::Inode>, alloc::string::String), isize> {
    resolve_parent_and_name_with_flags(at, uid, gid, LookupFlags::default())
}

pub(crate) fn resolve_parent_and_name_with_flags(
    at: &AtPath,
    uid: u32,
    gid: u32,
    flags: LookupFlags,
) -> Result<(alloc::sync::Arc<ext4_fs::Inode>, alloc::string::String), isize> {
    let mut depth = 0usize;
    let mut seen_symlinks = Vec::new();
    match at {
        AtPath::Vfs(vfs) => {
            let parent = PathWalker::new(Arc::clone(&vfs.namespace))
                .walk_parent(
                    &vfs.root,
                    &vfs.start,
                    &vfs.path,
                    flags,
                    VfsCredentials { uid, gid },
                )
                .map_err(map_vfs_error)?;
            let inode = parent
                .parent
                .node()
                .as_any()
                .downcast_ref::<Ext4VfsNode>()
                .map(|node| Arc::clone(node.inode()))
                .ok_or_else(|| err(SyscallError::EOPNOTSUPP))?;
            Ok((inode, parent.name))
        }
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
    // This helper returns a display spelling only. Proc magic links stay as
    // components here; callers that need the target object use PathWalker and
    // receive the pinned VfsPath directly.
    Ok(Some(abs))
}
