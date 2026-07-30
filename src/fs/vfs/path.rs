use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use super::{
    PositiveDentryCache, VfsError, VfsLink, VfsMetadata, VfsMountNamespace, VfsNodeKind, VfsPath,
    VfsResult,
};

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

/// 路径解析
pub struct PathWalker {
    namespace: Arc<VfsMountNamespace>,
    dcache: PositiveDentryCache,
}

impl PathWalker {
    pub fn new(namespace: Arc<VfsMountNamespace>) -> Self {
        Self {
            namespace,
            dcache: PositiveDentryCache::default(),
        }
    }

    pub fn dcache(&self) -> &PositiveDentryCache {
        &self.dcache
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

        /// clone : 持有，放置访问中途节点的消失 就死了
        let lookup_root = if flags.contains(LookupFlags::IN_ROOT) {
            start.clone()
        } else {
            process_root.clone()
        };
        /// relative or absolute：where we start
        let mut current = if path.starts_with('/') {
            lookup_root.clone()
        } else {
            start.clone()
        };
        let beneath_root = start.clone();
        let trailing_slash = path.len() > 1 && path.ends_with('/');
        let mut components = split_components(path);
        let mut symlinks = 0usize;

        /// 以下逻辑是处理路径中的 . 于 ..
        while let Some(component) = components.pop_front() {
            match component.as_str() {
                "" | "." => continue,
                ".." => {
                    /// 禁止跳出root
                    if current.same_object(&lookup_root) {
                        continue;
                    }
                    /// 禁止跨设备
                    let parent = self.namespace.ascend(&current);
                    if flags.contains(LookupFlags::NO_XDEV)
                        && parent.mount().id() != current.mount().id()
                    {
                        return Err(VfsError::CrossDevice);
                    }
                    /// BENEATH 标志禁止跨越
                    if flags.contains(LookupFlags::BENEATH) && current.same_object(&beneath_root) {
                        return Err(VfsError::CrossDevice);
                    }
                    current = parent;
                    continue;
                }
                _ => {}
            }

            /// 处于目录访问，检查权限
            check_search_permission(current.node().metadata()?, credentials)?;
            let parent = current.clone();
            /// component 是我们下一个要去的地方
            let dentry = self.dcache.lookup(parent.dentry(), &component)?;
            let unmounted = VfsPath::new(Arc::clone(parent.mount()), dentry);
            let mounted = self.namespace.follow_mounts(unmounted.clone());
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
            symlinks += 1;
            if symlinks > 40 {
                return Err(VfsError::Loop);
            }
            match current.node().readlink()? {
                VfsLink::Magic(target) => {
                    if flags.contains(LookupFlags::NO_MAGIC_LINKS) {
                        return Err(VfsError::Loop);
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
    /// check owner
    let shift = if credentials.uid == metadata.uid {
        6
    /// check group id
    } else if credentials.gid == metadata.gid {
        3
    } else {
        0
    };
    ((metadata.mode >> shift) & 1 != 0)
        .then_some(())
        .ok_or(VfsError::Access)
}
