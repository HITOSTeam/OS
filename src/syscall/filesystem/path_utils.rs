use super::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Arc, BTreeMap, ClassifiedAbsPath, File,
    INODE_XATTRS, MAX_SYMLINKS, NAME_MAX, O_TRUNC, OSInode, PATH_MAX, PseudoDir, PseudoDirent,
    PseudoShmFile, String, SyscallError, Vec, XATTR_CREATE, XATTR_NAME_MAX, XATTR_REPLACE,
    XATTR_SIZE_MAX, current_cwd_path, current_files, current_fsuid_gid, current_mount_namespace,
    current_process, dt_type_from_ext4, err, ext4_lock, fd_has_o_path, find_path_in_roots,
    get_current_token, get_fd_file, inode_is_immutable_or_append, inode_mode_allows_uid_gid,
    install_open_file_fd, logical_path_for_inode, logical_path_for_open_fd, mount_lookup_for_abs,
    open_pseudo, path_is_noexec, path_is_rofs, pseudo_abs_for_ext4_dirfd,
    resolve_proc_magic_intermediate_abs_path, secondary_root_inode, shm_get, shm_object_name,
    syscall_ftruncate, touch_inode_mtime_ctime_now, translate_mount_abs, try_copy_from_user,
    try_copy_to_user, try_read_user_value,
};
use alloc::vec;

pub(crate) fn current_timespec() -> (i64, i64) {
    crate::syscall::time_sys::realtime_now_timespec()
}

/// Normalize a path by connect cwd + path. Remove dot
pub(crate) fn normalize_path(cwd: &str, path: &str) -> String {
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

pub(crate) fn current_process_root() -> String {
    let process = current_process();
    let inner = process.borrow_mut();
    inner.root.clone()
}

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
    normalize_path("/", &out)
}

pub(crate) fn normalize_relative_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
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
    parts.join("/")
}

pub(crate) fn validate_path_components(path: &str) -> Result<(), isize> {
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg.len() > NAME_MAX {
            return Err(err(SyscallError::ENAMETOOLONG));
        }
    }
    Ok(())
}

pub(crate) fn path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

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
    LogicalAbs(String),
    Ext4Dir {
        base: alloc::sync::Arc<ext4_fs::Inode>,
        logical_base: Option<String>,
    },
}

pub(crate) enum AtPath {
    /// An ext4 lookup rooted at `/`.
    Ext4Abs(String),
    /// An ext4 lookup rooted at an open directory fd.
    Ext4Rel {
        base: alloc::sync::Arc<ext4_fs::Inode>,
        rel: String,
    },
    /// A pseudo filesystem lookup expressed as an absolute path.
    PseudoAbs(String),
}

pub(crate) fn classify_current_abs_path(abs: &str) -> ClassifiedAbsPath {
    let state = current_mount_namespace();
    let state = state.lock();
    state.classify_logical_abs_path(abs)
}

pub(crate) fn classify_abs_at_path(abs: String) -> AtPath {
    match classify_current_abs_path(&abs) {
        ClassifiedAbsPath::Ext4(translated) => AtPath::Ext4Abs(translated),
        ClassifiedAbsPath::Pseudo(path) => AtPath::PseudoAbs(path),
    }
}

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

pub(crate) fn resolve_relative_at_path_from_logical_base(
    base_path: &str,
    path: &str,
) -> Result<AtPath, isize> {
    let logical_abs = normalize_path(base_path, path);
    let abs = resolve_proc_magic_intermediate_abs_path(&logical_abs)?;
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
    let rel = if let Some(mount) = mount_lookup_for_abs(&abs) {
        let suffix = if abs == mount.target {
            String::new()
        } else {
            String::from(abs[mount.target.len()..].trim_start_matches('/'))
        };
        let _ext4_guard = ext4_lock();
        let Some(base) = find_path_in_roots(&mount.source) else {
            return Err(err(SyscallError::ENOENT));
        };
        return Ok(AtPath::Ext4Rel { base, rel: suffix });
    } else {
        normalize_relative_path(path)
    };
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
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
    Ok(AtPath::Ext4Rel { base, rel })
}

pub(crate) fn resolve_relative_at_path_from_ext4_base(
    base: alloc::sync::Arc<ext4_fs::Inode>,
    logical_base: Option<String>,
    path: &str,
) -> Result<AtPath, isize> {
    if let Some(logical_base) = logical_base {
        let logical_abs = normalize_path(&logical_base, path);
        let abs = resolve_proc_magic_intermediate_abs_path(&logical_abs)?;
        if abs != logical_abs {
            return Ok(classify_abs_at_path(abs));
        }
    }
    if let Some(abs) = pseudo_abs_for_ext4_dirfd(&base, path) {
        return Ok(AtPath::PseudoAbs(abs));
    }
    let rel = normalize_relative_path(path);
    Ok(AtPath::Ext4Rel { base, rel })
}

pub(crate) fn resolve_at_path(dirfd: isize, path: &str) -> Result<AtPath, isize> {
    if path.is_empty() {
        return Err(err(SyscallError::ENOENT));
    }
    if path.len() > PATH_MAX {
        return Err(err(SyscallError::ENAMETOOLONG));
    }
    validate_path_components(path)?;

    // Absolute path: ignore dirfd.
    if path.starts_with('/') {
        let jail_abs = normalize_path("/", path);
        let abs = resolve_proc_magic_intermediate_abs_path(&apply_process_root(&jail_abs))?;
        return Ok(classify_abs_at_path(abs));
    }

    match resolve_relative_at_path_base(dirfd)? {
        RelativeAtPathBase::LogicalAbs(base_path) => {
            resolve_relative_at_path_from_logical_base(&base_path, path)
        }
        RelativeAtPathBase::Ext4Dir { base, logical_base } => {
            resolve_relative_at_path_from_ext4_base(base, logical_base, path)
        }
    }
}

pub(crate) fn resolve_ext4_abs_path(
    path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
    depth: &mut usize,
    seen_symlinks: &mut Vec<u32>,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let abs = crate::fs::normalize_proc_magic_path(path).into_owned();

    // Prefer the secondary disk for OSComp test roots when available.
    if abs == "/musl" || abs.starts_with("/musl/") || abs == "/glibc" || abs.starts_with("/glibc/")
    {
        if let Some(secondary) = secondary_root_inode() {
            let mut sec_depth = 0usize;
            let mut sec_seen = Vec::new();
            match resolve_ext4_path(
                secondary,
                &abs,
                uid,
                gid,
                follow_final,
                &mut sec_depth,
                &mut sec_seen,
            ) {
                Ok(v) => return Ok(v),
                Err(e) if e == err(SyscallError::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
    }

    let primary = crate::fs::root_inode_for_path(&abs);
    match resolve_ext4_path(primary, &abs, uid, gid, follow_final, depth, seen_symlinks) {
        Ok(v) => Ok(v),
        Err(e) if e == err(SyscallError::ENOENT) => {
            let Some(secondary) = secondary_root_inode() else {
                return Err(err(SyscallError::ENOENT));
            };
            let mut sec_depth = 0usize;
            let mut sec_seen = Vec::new();
            resolve_ext4_path(
                secondary,
                &abs,
                uid,
                gid,
                follow_final,
                &mut sec_depth,
                &mut sec_seen,
            )
        }
        Err(e) => Err(e),
    }
}

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

pub(crate) fn proc_path_for_at<'a>(raw_abs: Option<&'a str>, at: &'a AtPath) -> Option<&'a str> {
    if let Some(abs) = raw_abs {
        if crate::fs::is_proc_pseudo_path(abs) {
            return Some(abs);
        }
    }
    match at {
        AtPath::PseudoAbs(abs) if crate::fs::is_proc_pseudo_path(abs) => Some(abs.as_str()),
        _ => None,
    }
}

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
            let _ = files.lock().clear_fd(fd);
            return Err(tr);
        }
    }
    Ok(fd)
}

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

pub(crate) fn add_root_dir_entries(
    root: &alloc::sync::Arc<ext4_fs::Inode>,
    entries: &mut BTreeMap<String, (u64, u8)>,
) {
    for (name, ino, ftype) in root.dir_entries() {
        if name == "." || name == ".." {
            continue;
        }
        entries
            .entry(name)
            .or_insert((ino as u64, dt_type_from_ext4(ftype)));
    }
}

/// Build a merged root directory listing from the primary and secondary disks.
///
/// Caller should hold `ext4_lock`.
pub(crate) fn union_root_dir_entries() -> Vec<PseudoDirent> {
    let mut merged: BTreeMap<String, (u64, u8)> = BTreeMap::new();
    let primary = crate::fs::root_inode_for_path("/");
    add_root_dir_entries(&primary, &mut merged);
    if let Some(secondary) = secondary_root_inode() {
        add_root_dir_entries(&secondary, &mut merged);
    }

    let mut entries = Vec::with_capacity(merged.len() + 2);
    entries.push(PseudoDirent {
        name: alloc::string::String::from("."),
        ino: 1,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: alloc::string::String::from(".."),
        ino: 1,
        dtype: 4,
    });
    for (name, (ino, dtype)) in merged {
        entries.push(PseudoDirent { name, ino, dtype });
    }
    entries
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

pub(crate) fn read_user_xattr_name(token: usize, ptr: usize) -> Result<String, isize> {
    let name = read_user_cstring(token, ptr)?;
    validate_xattr_name(&name)?;
    Ok(name)
}

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

pub(crate) fn xattr_is_user_namespace(name: &str) -> bool {
    name.starts_with("user.")
}

pub(crate) fn inode_supports_user_xattr(inode: &Arc<ext4_fs::Inode>) -> bool {
    inode.is_file() || inode.is_dir()
}

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
    let _ext4_guard = ext4_lock();
    resolve_at_inode(&at, fsuid, fsgid, follow_final)
}

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

pub(crate) fn resolve_ext4_path(
    start: alloc::sync::Arc<ext4_fs::Inode>,
    path: &str,
    uid: u32,
    gid: u32,
    follow_final: bool,
    depth: &mut usize,
    seen_symlinks: &mut Vec<u32>,
) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
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
        if !cur.is_dir() {
            return Err(err(SyscallError::ENOTDIR));
        }
        if !inode_mode_allows_uid_gid(&cur, 1, uid, gid) {
            return Err(err(SyscallError::EACCES));
        }
        let Some(next) = cur.find(seg) else {
            return Err(err(SyscallError::ENOENT));
        };
        let is_last = idx + 1 == components.len();
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
        stack.push(next);
        idx += 1;
    }
    Ok(stack.last().unwrap().clone())
}

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
        AtPath::Ext4Rel { base, rel } => {
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
    let _ext4_guard = ext4_lock();
    let inode = resolve_at_inode(&at, fsuid, fsgid, true)?;
    if !inode.is_file() {
        return Err(err(SyscallError::EACCES));
    }
    let exec_mask = if path.ends_with(".sh") { 4 } else { 1 };
    if !inode_mode_allows_uid_gid(&inode, exec_mask, fsuid, fsgid) {
        return Err(err(SyscallError::EACCES));
    }
    Ok(inode)
}

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
        // Resolve the lookup path before taking `ext4_lock()`: the AT_FDCWD
        // relative-path branch may need to reopen the base inode under the
        // same lock, and holding it here would self-deadlock.
        let _ext4_guard = ext4_lock();
        let inode = resolve_at_inode(&at, fsuid, fsgid, follow_final)?;
        if !follow_final && inode.is_symlink() {
            return Err(err(SyscallError::ELOOP));
        }
        inode
    };
    let _ext4_guard = ext4_lock();
    if !inode.is_file() {
        return Err(err(SyscallError::EACCES));
    }
    let exec_mask = if path.ends_with(".sh") { 4 } else { 1 };
    if !inode_mode_allows_uid_gid(&inode, exec_mask, fsuid, fsgid) {
        return Err(err(SyscallError::EACCES));
    }
    Ok(inode)
}

pub(crate) fn resolve_read_inode(path: &str) -> Result<alloc::sync::Arc<ext4_fs::Inode>, isize> {
    let at = resolve_at_path(AT_FDCWD, path)?;
    if let AtPath::PseudoAbs(_) = &at {
        return Err(err(SyscallError::ENOENT));
    }
    let (fsuid, fsgid) = current_fsuid_gid();
    let _ext4_guard = ext4_lock();
    let inode = resolve_at_inode(&at, fsuid, fsgid, true)?;
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
        AtPath::Ext4Rel { base, rel } => {
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
    resolve_proc_magic_intermediate_abs_path(&abs).map(Some)
}

/// is path on Read only file sytem?
pub(crate) fn rofs_for_path(dirfd: isize, path: &str) -> bool {
    resolve_abs_path(dirfd, path)
        .ok()
        .flatten()
        .map(|abs| path_is_rofs(&abs))
        .unwrap_or(false)
}
