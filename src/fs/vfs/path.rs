use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use super::{VfsError, VfsLink, VfsMetadata, VfsMountNamespace, VfsNodeKind, VfsPath, VfsResult};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LookupFlags(pub u32);

impl LookupFlags {
    /// 跟随路径最后一个分量的符号链接；中间分量的符号链接始终需要跟随。
    pub const FOLLOW_FINAL: u32 = 1 << 0;
    /// 允许空路径；当 `path == ""` 时直接返回 `start`。
    pub const ALLOW_EMPTY: u32 = 1 << 1;
    /// 将解析限制在 `start` 以下；拒绝绝对路径以及通过 `..` 或绝对
    /// 符号链接逃出起点，语义对应 Linux `RESOLVE_BENEATH`。
    pub const BENEATH: u32 = 1 << 2;
    /// 临时把 `start` 当作本次查找的根目录；绝对路径、绝对符号链接及
    /// `..` 都以它为边界，语义对应 Linux `RESOLVE_IN_ROOT`。
    pub const IN_ROOT: u32 = 1 << 3;
    /// 禁止跨越挂载点，包括进入子挂载、从挂载根退出和跨挂载 magic link。
    pub const NO_XDEV: u32 = 1 << 4;
    /// 禁止跟随直接返回 `VfsPath` 的 magic link，例如 procfs 的 fd 链接。
    pub const NO_MAGIC_LINKS: u32 = 1 << 5;
    /// 禁止跟随任何符号链接。最终分量配合 `O_PATH|O_NOFOLLOW` 时仍可
    /// 返回链接自身，语义对应 Linux `RESOLVE_NO_SYMLINKS`。
    pub const NO_SYMLINKS: u32 = 1 << 6;

    /// 判断指定的 lookup flag 是否已设置。
    pub fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

/// permision identitiy
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsCredentials {
    pub uid: u32,
    pub gid: u32,
}

/// Result of resolving every component except the final name.  Create,
/// unlink, link and rename operate on this parent/name pair so no syscall has
/// to reconstruct an absolute string.
pub struct VfsParentPath {
    pub parent: VfsPath,
    pub name: String,
    pub trailing_slash: bool,
}

/// 路径解析
pub struct PathWalker {
    namespace: Arc<VfsMountNamespace>,
}

impl PathWalker {
    pub fn new(namespace: Arc<VfsMountNamespace>) -> Self {
        Self { namespace }
    }

    /// Select the graph that owns a resolved path.  Relative lookup from an
    /// old dirfd after `unshare(CLONE_NEWNS)` must continue in the old mount
    /// tree, not silently switch to the caller's new namespace.
    fn namespace_for(&self, path: &VfsPath) -> Arc<VfsMountNamespace> {
        path.mount()
            .owner_namespace()
            .unwrap_or_else(|| Arc::clone(&self.namespace))
    }

    /// 逐分量解析路径并返回对应的挂载与目录项。
    ///
    /// # 参数
    ///
    /// - `process_root`：当前进程可见的根目录。绝对路径从这里开始，
    ///   `..` 也不能越过该边界。chroot 会修改
    /// - `start`：相对路径的解析起点，通常是进程的 cwd，也可以是
    ///   `openat` 等系统调用传入的 dirfd。
    /// - `path`：待解析的路径字符串，可以是绝对路径或相对路径。
    /// - `flags`：控制是否跟随最终符号链接、是否允许空路径、是否允许
    ///   跨挂载点等 lookup 行为。
    /// - `credentials`：执行本次查找的 uid/gid，用于检查每一级目录的
    ///   search（execute）权限。
    pub fn walk(
        &self,
        process_root: &VfsPath,
        start: &VfsPath,
        path: &str,
        flags: LookupFlags,
        credentials: VfsCredentials,
    ) -> VfsResult<VfsPath> {
        if path.is_empty() {
            return flags
                .contains(LookupFlags::ALLOW_EMPTY)
                .then(|| start.clone())
                .ok_or(VfsError::NoEntry);
        }
        if path.len() > 4096 {
            return Err(VfsError::NameTooLong);
        }
        if path.starts_with('/') && flags.contains(LookupFlags::BENEATH) {
            return Err(VfsError::CrossDevice);
        }

        // Clone the root path so nodes remain alive throughout the walk.  A
        // mount may cover the root dentry itself (for example after mounting
        // a new root in a private namespace).  Linux starts absolute lookup
        // from the currently visible `struct path`, so follow that mount stack
        // before establishing the `..` boundary.  Relative lookup still starts
        // from the exact cwd/dirfd path and therefore preserves an old covered
        // directory, just like a pinned Linux file description.
        let raw_lookup_root = if flags.contains(LookupFlags::IN_ROOT) {
            start.clone()
        } else {
            process_root.clone()
        };
        let lookup_root = self
            .namespace_for(&raw_lookup_root)
            .follow_mounts(raw_lookup_root);
        // Select the starting point for relative or absolute lookup.
        let mut current = if path.starts_with('/') {
            lookup_root.clone()
        } else {
            start.clone()
        };
        let beneath_root = start.clone();
        let trailing_slash = path.len() > 1 && path.ends_with('/');
        let mut components = split_components(path);
        let mut symlinks = 0usize;

        // Handle `.` and `..` components.
        while let Some(component) = components.pop_front() {
            match component.as_str() {
                "" => continue,
                "." => {
                    check_search_permission(current.node().metadata()?, credentials)?;
                    continue;
                }
                ".." => {
                    // Linux checks MAY_EXEC on the directory being traversed
                    // before handling the dotdot boundary.
                    check_search_permission(current.node().metadata()?, credentials)?;
                    // LOOKUP_BENEATH rejects an attempted escape even when
                    // the scoped root also happens to be the process root.
                    // LOOKUP_IN_ROOT, in contrast, clamps dotdot at its root.
                    if flags.contains(LookupFlags::BENEATH) && current.same_object(&beneath_root) {
                        return Err(VfsError::CrossDevice);
                    }
                    // 禁止跳出 root。
                    if current.same_object(&lookup_root) {
                        continue;
                    }
                    // 禁止跨设备。
                    let parent = self.namespace_for(&current).ascend(&current);
                    if flags.contains(LookupFlags::NO_XDEV)
                        && parent.mount().id() != current.mount().id()
                    {
                        return Err(VfsError::CrossDevice);
                    }
                    current = parent;
                    continue;
                }
                _ => {}
            }

            if component.len() > 255 {
                return Err(VfsError::NameTooLong);
            }

            // 处于目录访问，检查权限。
            check_search_permission(current.node().metadata()?, credentials)?;
            let parent = current.clone();
            // component 是我们下一个要去的地方。
            let dentry = parent
                .mount()
                .filesystem()
                .dentry_cache()
                .lookup(parent.dentry(), &component)?;
            let unmounted = VfsPath::new(Arc::clone(parent.mount()), dentry);
            let mounted = self
                .namespace_for(&unmounted)
                .follow_mounts(unmounted.clone());
            if flags.contains(LookupFlags::NO_XDEV)
                && mounted.mount().id() != unmounted.mount().id()
            {
                return Err(VfsError::CrossDevice);
            }
            current = mounted;

            let is_final = components.is_empty();
            let follow = !is_final
                || flags.contains(LookupFlags::FOLLOW_FINAL)
                || (is_final && trailing_slash);
            if current.node().metadata()?.kind != VfsNodeKind::Symlink || !follow {
                continue;
            }
            if flags.contains(LookupFlags::NO_SYMLINKS) {
                return Err(VfsError::Loop);
            }
            // Linux namei checks MNT_NOSYMFOLLOW on the mount containing the
            // link immediately before following it.  This applies equally to
            // textual links and proc-style magic links; operations that do
            // not follow the final component remain unaffected.
            if current.mount().flags().is_nosymfollow() {
                return Err(VfsError::Loop);
            }
            symlinks += 1;
            if symlinks > 40 {
                return Err(VfsError::Loop);
            }
            match current.node().readlink()? {
                VfsLink::Magic(target) | VfsLink::MagicDisplay { target, .. } => {
                    if flags.contains(LookupFlags::NO_MAGIC_LINKS) {
                        return Err(VfsError::Loop);
                    }
                    // Linux nd_jump_link() rejects direct path jumps for all
                    // scoped lookups because they cannot safely preserve the
                    // LOOKUP_BENEATH/LOOKUP_IN_ROOT guarantee.
                    if flags.contains(LookupFlags::BENEATH) || flags.contains(LookupFlags::IN_ROOT)
                    {
                        return Err(VfsError::CrossDevice);
                    }
                    if flags.contains(LookupFlags::NO_XDEV)
                        && target.mount().id() != current.mount().id()
                    {
                        return Err(VfsError::CrossDevice);
                    }
                    current = target;
                }
                VfsLink::Text(target) => {
                    if target.starts_with('/') {
                        if flags.contains(LookupFlags::BENEATH) {
                            return Err(VfsError::CrossDevice);
                        }
                        current = lookup_root.clone();
                    } else {
                        current = parent;
                    }
                    prepend_components(&mut components, &target);
                }
            }
        }

        if trailing_slash && current.node().metadata()?.kind != VfsNodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        Ok(current)
    }

    /// Resolve the parent of a pathname while leaving the final component as
    /// a name.  Intermediate symlinks and mount crossings use the same walker
    /// as ordinary lookup.
    pub fn walk_parent(
        &self,
        process_root: &VfsPath,
        start: &VfsPath,
        path: &str,
        flags: LookupFlags,
        credentials: VfsCredentials,
    ) -> VfsResult<VfsParentPath> {
        if path.is_empty() || path.len() > 4096 {
            return Err(if path.len() > 4096 {
                VfsError::NameTooLong
            } else {
                VfsError::NoEntry
            });
        }
        let trailing_slash = path.len() > 1 && path.ends_with('/');
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(VfsError::Invalid);
        }
        let name = trimmed.rsplit('/').next().ok_or(VfsError::Invalid)?;
        if name.is_empty() || matches!(name, "." | "..") {
            return Err(VfsError::Invalid);
        }
        if name.len() > 255 {
            return Err(VfsError::NameTooLong);
        }
        let parent_len = trimmed.len().saturating_sub(name.len());
        let parent_text = trimmed[..parent_len].trim_end_matches('/');
        let parent = if parent_text.is_empty() {
            if path.starts_with('/') {
                self.walk(process_root, start, "/", flags, credentials)?
            } else {
                start.clone()
            }
        } else {
            self.walk(
                process_root,
                start,
                parent_text,
                LookupFlags(flags.0 | LookupFlags::FOLLOW_FINAL),
                credentials,
            )?
        };
        check_search_permission(parent.node().metadata()?, credentials)?;
        Ok(VfsParentPath {
            parent,
            name: name.to_string(),
            trailing_slash,
        })
    }
}

/// input:asd/asd/sasd// asd
/// output:[asd,asd,sasd,asd]
fn split_components(path: &str) -> VecDeque<String> {
    path.split('/')
        .filter(|component| !component.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// join two paths,path + queue
fn prepend_components(queue: &mut VecDeque<String>, path: &str) {
    let mut prefix = split_components(path);
    while let Some(component) = prefix.pop_back() {
        queue.push_front(component);
    }
}

/// check if we can go into a dir
fn check_search_permission(metadata: VfsMetadata, credentials: VfsCredentials) -> VfsResult<()> {
    if metadata.kind != VfsNodeKind::Directory {
        return Err(VfsError::NotDirectory);
    }
    if credentials.uid == 0 {
        return Ok(());
    }
    // Check owner permissions first.
    let shift = if credentials.uid == metadata.uid {
        6
    // Otherwise check the owning group.
    } else if credentials.gid == metadata.gid {
        3
    } else {
        0
    };
    ((metadata.mode >> shift) & 1 != 0)
        .then_some(())
        .ok_or(VfsError::Access)
}
