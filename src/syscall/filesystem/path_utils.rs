use super::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Arc, INODE_XATTRS, NAME_MAX, OSInode, PATH_MAX,
    String, SyscallError, Vec, XATTR_CREATE, XATTR_NAME_MAX, XATTR_REPLACE, XATTR_SIZE_MAX,
    current_cwd_path, current_fsuid_gid, current_process, err, ext4_inode_lock, fd_has_o_path,
    find_path_in_roots, get_fd_file, inode_is_immutable_or_append, inode_mode_allows_uid_gid,
    logical_path_for_open_fd, touch_inode_mtime_ctime_now, try_copy_from_user, try_copy_to_user,
    try_read_user_value,
};
use crate::fs::ext4_inode_from_vfs_path;
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

#[derive(Clone)]
pub(crate) struct AtPath {
    namespace: Arc<VfsMountNamespace>,
    root: VfsPath,
    start: VfsPath,
    path: String,
}

fn vfs_at_from_start(start: VfsPath, path: &str) -> AtPath {
    let process = current_process();
    let fs = process.fs_struct();
    AtPath {
        namespace: process.mount_namespace().lock().vfs_namespace(),
        root: fs.root().path().clone(),
        start,
        path: String::from(path),
    }
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
) -> Result<VfsPath, isize> {
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
) -> Result<VfsPath, isize> {
    PathWalker::new(Arc::clone(&at.namespace))
        .walk(
            &at.root,
            &at.start,
            &at.path,
            flags,
            VfsCredentials { uid, gid },
        )
        .map_err(map_vfs_error)
}

/// Return whether an object-VFS pathname resolves to the process root without
/// following its final symlink.  Linux namei treats that root as a real pinned
/// `struct path`; callers must not infer it from a spelling such as `"/"`.
pub(crate) fn vfs_at_path_is_process_root(at: &AtPath, uid: u32, gid: u32) -> Result<bool, isize> {
    let path = resolve_at_vfs_path(at, uid, gid, false)?;
    Ok(path.same_object(&at.root))
}

/// Return the pinned directory object used as the start of a relative lookup.
/// Linux takes this from `fs->pwd` or `fd_file(dirfd)->f_path`; a pathname
/// string is never reconstructed from the descriptor's display name.
fn relative_at_path_start(dirfd: isize) -> Result<VfsPath, isize> {
    if dirfd == AT_FDCWD {
        return Ok(current_process().fs_struct().cwd().path().clone());
    }
    if dirfd < 0 {
        return Err(err(SyscallError::EBADF));
    }
    let Some(file) = get_fd_file(dirfd as usize) else {
        return Err(err(SyscallError::EBADF));
    };
    let Some(base) = file.object_path() else {
        // Anonymous files and pre-VFS internal descriptors cannot be dirfds.
        // Named directory opens always carry an object path.
        return Err(err(SyscallError::ENOTDIR));
    };
    if base.node().metadata().map_err(map_vfs_error)?.kind != crate::fs::vfs::VfsNodeKind::Directory
    {
        return Err(err(SyscallError::ENOTDIR));
    }
    Ok(base.clone())
}

/// 将用户的 `(dirfd, path)` 转成一次对象化 lookup 的起点和策略上下文。
/// 绝对路径从进程固定的 root 开始，相对路径从 cwd 或 dirfd 的 `f_path`
/// 开始；这里不做词法 canonicalization，实际语义由 `PathWalker` 决定。
pub(crate) fn resolve_at_path(dirfd: isize, path: &str) -> Result<AtPath, isize> {
    // pre check
    if path.is_empty() {
        return Err(err(SyscallError::ENOENT));
    }
    if path.len() > PATH_MAX {
        return Err(err(SyscallError::ENAMETOOLONG));
    }
    validate_path_components(path)?;

    // Absolute lookup ignores dirfd and starts from the task's pinned root.
    // Keep the spelling intact so the walker, not lexical normalization,
    // enforces search permission, symlink and `..` semantics.
    if path.starts_with('/') {
        let root = current_process().fs_struct().root().path().clone();
        return Ok(vfs_at_from_start(root, path));
    }

    Ok(vfs_at_from_start(relative_at_path_start(dirfd)?, path))
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

/// Resolve the parent object path and final name for a VFS pathname.
pub(crate) fn resolve_parent_vfs_path(
    at: &AtPath,
    uid: u32,
    gid: u32,
) -> Result<crate::fs::vfs::VfsParentPath, isize> {
    resolve_parent_vfs_path_with_flags(at, uid, gid, LookupFlags::default())
}

pub(crate) fn resolve_parent_vfs_path_with_flags(
    at: &AtPath,
    uid: u32,
    gid: u32,
    flags: LookupFlags,
) -> Result<crate::fs::vfs::VfsParentPath, isize> {
    PathWalker::new(Arc::clone(&at.namespace))
        .walk_parent(
            &at.root,
            &at.start,
            &at.path,
            flags,
            VfsCredentials { uid, gid },
        )
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

/// Resolve one object path and expose its ext4 adapter inode when required by
/// a legacy inode operation. Non-ext4 nodes return `EOPNOTSUPP`.
pub(crate) fn resolve_at_inode(
    at: &AtPath,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let path = resolve_at_vfs_path(at, uid, gid, follow_final)?;
    ext4_inode_from_vfs_path(&path).ok_or_else(|| err(SyscallError::EOPNOTSUPP))
}

pub(crate) fn resolve_at_inode_with_vfs_path(
    at: &AtPath,
    uid: u32,
    gid: u32,
    follow_final: bool,
) -> Result<(Arc<ext4_fs::Inode>, VfsPath), isize> {
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
) -> Result<(Arc<ext4_fs::Inode>, VfsPath), isize> {
    let path = resolve_at_vfs_path_with_flags(at, uid, gid, flags)?;
    let inode = ext4_inode_from_vfs_path(&path).ok_or_else(|| err(SyscallError::EOPNOTSUPP))?;
    Ok((inode, path))
}

/// 解析可执行文件路径为 inode，校验：不在 noexec 挂载点、是普通文件、有执行权限。
/// `.sh` 文件检查读权限（`r` 位）而非执行权限（`x` 位）。
pub(crate) fn resolve_exec_inode(path: &str) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let at = resolve_at_path(AT_FDCWD, path)?;
    let (fsuid, fsgid) = current_fsuid_gid();
    let (inode, vfs_path) = resolve_at_inode_with_vfs_path(&at, fsuid, fsgid, true)?;
    if vfs_path.mount().flags().is_noexec() {
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
        (inode, Some(vfs_path))
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
    let parent = PathWalker::new(Arc::clone(&at.namespace))
        .walk_parent(
            &at.root,
            &at.start,
            &at.path,
            flags,
            VfsCredentials { uid, gid },
        )
        .map_err(map_vfs_error)?;
    let inode =
        ext4_inode_from_vfs_path(&parent.parent).ok_or_else(|| err(SyscallError::EOPNOTSUPP))?;
    Ok((inode, parent.name))
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
