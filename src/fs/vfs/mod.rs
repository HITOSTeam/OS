//! Object based virtual filesystem primitives.
//!
//! This module intentionally contains no pathname-to-provider translation.
//! A resolved path is the pair of a mount and a dentry, and mount crossings
//! are keyed by object identity.  The implementation is a small REF-walk: all
//! persistent objects are protected by `Arc`, while mutable namespace state is
//! protected by `RwLock`.
//!
//! Concrete filesystems live in sibling modules (`ext4`, `tmpfs`, `procfs`,
//! `sysfs`, `devtmpfs`, and `cgroupfs`).  The dependency direction is from
//! those backends to this module; the VFS core must not depend on a concrete
//! filesystem.
//!
//
// 目录项对象及正向 dentry cache。
mod dentry;
// 打开文件描述、共享文件位置以及进程 root/cwd 上下文。
mod file;
// mount 对象、mount namespace、bind/overmount/umount 关系。
mod mount;
// 具体文件系统必须实现的 node 操作接口。
mod node;
// 分量级路径遍历、符号链接和跨挂载点处理。
mod path;
// 文件系统类型注册表，以及创建文件系统实例的工厂接口。
mod registry;

// 对外统一导出 VFS 基础类型；具体后端只需要依赖 `fs::vfs`。
#[allow(unused_imports)]
pub use self::{dentry::*, file::*, mount::*, node::*, path::*, registry::*};

use alloc::string::String;

pub type VfsResult<T> = core::result::Result<T, VfsError>;

/// VFS 操作可能返回的、与具体文件系统实现无关的错误。
///
/// 枚举刻意不携带路径字符串或后端私有状态，使 ext4、tmpfs、procfs 等实现
/// 可以共享同一套接口。括号中是通常对应的 Linux errno，最终映射仍由 syscall
/// 层根据具体操作决定。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsError {
    /// 当前凭证没有执行操作所需的权限（通常为 `EACCES` 或 `EPERM`）。
    Access,
    /// 操作被文件系统策略禁止，而不是普通 DAC 检查失败（`EPERM`）。
    Permission,
    /// 对象仍被引用、目录是 cwd/root 或 mount 仍被 pin（`EBUSY`）。
    Busy,
    /// 操作不允许跨越 mount/filesystem 边界（`EXDEV`）。
    CrossDevice,
    /// 要创建的名字或注册项已经存在（`EEXIST`）。
    Exists,
    /// 参数、对象类型或状态组合无效（`EINVAL`）。
    Invalid,
    /// 后端对象存在，但当前操作发生 I/O/内部状态错误（`EIO`）。
    Io,
    /// 期望普通文件，但目标是目录（`EISDIR`）。
    IsDirectory,
    /// 符号链接解析次数过多或形成循环（`ELOOP`）。
    Loop,
    /// 路径或单个名字超过 VFS 支持的上限（`ENAMETOOLONG`）。
    NameTooLong,
    /// 路径分量或目标对象不存在（`ENOENT`）。
    NoEntry,
    /// 进程或线程 ID 在调用者可见命名空间中不存在（`ESRCH`）。
    NoProcess,
    /// 请求的块设备或其他挂载源不存在（`ENODEV`）。
    NoDevice,
    /// 文件系统没有剩余块、inode 或其他可分配资源（`ENOSPC`）。
    NoSpace,
    /// 期望目录，但路径分量不是目录（`ENOTDIR`）。
    NotDirectory,
    /// 要删除的目录仍包含目录项（`ENOTEMPTY`）。
    NotEmpty,
    /// 当前 node 或文件系统没有实现该操作（通常为 `EOPNOTSUPP`）。
    NotSupported,
    /// 挂载或文件系统处于只读状态（`EROFS`）。
    ReadOnly,
}

/// VFS 节点类型，对应 Linux inode 的文件类型部分。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsNodeKind {
    /// 可按字节读写、具有文件长度的普通文件。
    Regular,
    /// 包含命名子项、支持 `lookup`/`readdir` 的目录。
    Directory,
    /// 保存文本目标或 magic-link 目标的符号链接。
    Symlink,
    /// 命名管道。
    Fifo,
    /// 以字符流方式访问驱动的设备节点。
    CharacterDevice,
    /// 以块为单位访问驱动的设备节点。
    BlockDevice,
    /// 文件系统命名空间中的 socket 节点。
    Socket,
}

/// VFS 节点的三个标准时间戳，统一使用纳秒表示。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsTimes {
    /// 最近一次访问时间（atime）。
    pub access_ns: u64,
    /// 最近一次文件内容修改时间（mtime）。
    pub modify_ns: u64,
    /// 最近一次 inode 元数据变化时间（ctime，不是文件创建时间）。
    pub change_ns: u64,
}

/// 与具体后端无关的 inode 元数据快照。
///
/// 该结构用于 `stat` 一类查询以及路径遍历中的类型/权限判断。它是一次读取结果，
/// 后端发生修改后，调用者需要重新执行 `metadata()` 获取新值。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsMetadata {
    /// 普通文件、目录、符号链接或设备节点等类型。
    pub kind: VfsNodeKind,
    /// Unix 权限和后端支持的 mode 位；文件类型由 `kind` 单独表示。
    pub mode: u16,
    /// 所有者用户 ID。
    pub uid: u32,
    /// 所有者组 ID。
    pub gid: u32,
    /// 指向同一 node/inode 的硬链接数量。
    pub nlink: u32,
    /// 普通文件的字节长度；其他类型由后端定义其可见值。
    pub size: u64,
    /// 字符/块设备节点编码后的设备号，非设备节点通常为 0。
    pub rdev: u64,
    /// atime、mtime、ctime。
    pub times: VfsTimes,
}

/// 文件系统级容量和类型信息，对应 Linux `struct statfs` 的公共子集。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsStatFs {
    /// 标识文件系统类型的 magic，例如 ext4 的 `0xef53`。
    pub magic: u64,
    /// 文件系统报告的首选 I/O 块大小。
    pub block_size: u64,
    /// 文件系统总块数。
    pub blocks: u64,
    /// 当前可用块数。
    pub blocks_free: u64,
    /// 非特权调用者实际可分配的块数；ext4 会扣除保留块。
    pub blocks_available: u64,
    /// 可分配的文件/inode 总数。
    pub files: u64,
    /// 当前可用文件/inode 数量。
    pub files_free: u64,
    /// 单个目录项名字允许的最大字节数。
    pub name_len: u32,
}

/// node 在创建打开文件对象时需要的访问状态。
///
/// 这里只保存会影响后端打开方式的最小集合；`CLOEXEC` 属于 fd 标志，
/// 文件偏移属于 [`FileDescription`]，均不应放在这里。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsOpenOptions {
    /// 调用者需要读取文件。
    pub readable: bool,
    /// 调用者需要写入文件。
    pub writable: bool,
    /// 每次写入应定位到当时的文件末尾。
    pub append: bool,
}

/// `readdir` 返回的、与具体目录实现无关的一条目录项。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsDirEntry {
    /// 当前目录下的单个名字，不包含父路径。
    pub name: String,
    /// 后端文件系统内稳定的 node/inode 标识。
    pub node_id: u64,
    /// 目录项指向的节点类型，用于填充 `dirent.d_type` 等信息。
    pub kind: VfsNodeKind,
}

#[cfg(test)]
mod tests {
    //! 使用纯内存测试后端验证 VFS 对象关系。
    //!
    //! `TestFs`/`TestNode` 只提供构造目录树所需的最小操作，测试关注的是 VFS
    //! 路径遍历、dentry 身份和 mount graph，而不是某个真实后端的存储细节。

    use super::*;
    use alloc::{
        collections::BTreeMap,
        format,
        string::{String, ToString},
        sync::{Arc, Weak},
        vec::Vec,
    };
    use core::any::Any;
    use spin::RwLock;

    /// 每个测试文件系统实例有独立 ID 和根 node。
    ///
    /// node 通过 `Weak<TestFs>` 回指所属文件系统，既能查询 filesystem ID，
    /// 又不会形成 `TestFs -> root -> TestFs` 的强引用环。
    struct TestFs {
        id: u64,
        root: Arc<TestNode>,
        vfs_state: VfsFileSystemState,
    }

    impl TestFs {
        /// 创建只有根目录的测试文件系统。
        fn new(id: u64) -> Arc<Self> {
            Arc::new_cyclic(|weak_fs: &Weak<TestFs>| {
                let root = Arc::new(TestNode {
                    fs: weak_fs.clone(),
                    id: 1,
                    metadata: RwLock::new(test_metadata(VfsNodeKind::Directory, 0o755)),
                    children: RwLock::new(BTreeMap::new()),
                    link: RwLock::new(None),
                });
                let vfs_state = VfsFileSystemState::new(Arc::clone(&root) as Arc<dyn VfsNode>);
                Self {
                    id,
                    root,
                    vfs_state,
                }
            })
        }

        /// 在 `parent` 下插入普通测试 node，并返回可供后续构树使用的强引用。
        fn add(
            self: &Arc<Self>,
            parent: &Arc<TestNode>,
            name: &str,
            id: u64,
            kind: VfsNodeKind,
        ) -> Arc<TestNode> {
            let node = Arc::new(TestNode {
                fs: Arc::downgrade(self),
                id,
                metadata: RwLock::new(test_metadata(
                    kind,
                    if kind == VfsNodeKind::Directory {
                        0o755
                    } else {
                        0o644
                    },
                )),
                children: RwLock::new(BTreeMap::new()),
                link: RwLock::new(None),
            });
            parent
                .children
                .write()
                .insert(name.to_string(), Arc::clone(&node));
            node
        }

        /// 创建文本符号链接；magic link 在需要对象目标的测试中直接写入。
        fn add_link(
            self: &Arc<Self>,
            parent: &Arc<TestNode>,
            name: &str,
            id: u64,
            target: &str,
        ) -> Arc<TestNode> {
            let node = self.add(parent, name, id, VfsNodeKind::Symlink);
            *node.link.write() = Some(TestLink::Text(target.to_string()));
            node
        }
    }

    /// 为测试后端提供文件系统级操作。
    ///
    /// 路径遍历只依赖 filesystem identity 和 root node，因此容量与同步操作可用
    /// 空实现；具体 lookup/readlink 行为由 `TestNode` 提供。
    impl VfsFileSystem for TestFs {
        fn filesystem_id(&self) -> u64 {
            self.id
        }

        fn filesystem_type(&self) -> &'static str {
            "testfs"
        }

        fn vfs_state(&self) -> &VfsFileSystemState {
            &self.vfs_state
        }

        fn statfs(&self) -> VfsResult<VfsStatFs> {
            Ok(VfsStatFs::default())
        }

        fn sync(&self) -> VfsResult<()> {
            Ok(())
        }
    }

    /// 测试符号链接的两种目标形式。
    enum TestLink {
        /// 需要重新按分量解析的普通文本目标。
        Text(String),
        /// 已经解析完成、直接引用 mount+dentry 的 proc 风格 magic link。
        Magic(VfsPath),
    }

    /// 最小的内存 node：元数据、子项和链接目标分别用 `RwLock` 保护。
    struct TestNode {
        fs: Weak<TestFs>,
        id: u64,
        metadata: RwLock<VfsMetadata>,
        children: RwLock<BTreeMap<String, Arc<TestNode>>>,
        link: RwLock<Option<TestLink>>,
    }

    /// 实现路径遍历所需的最小 node 接口。
    impl VfsNode for TestNode {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn node_id(&self) -> u64 {
            self.id
        }

        fn filesystem_id(&self) -> u64 {
            self.fs.upgrade().expect("test fs dropped").id
        }

        fn metadata(&self) -> VfsResult<VfsMetadata> {
            Ok(*self.metadata.read())
        }

        fn lookup(&self, name: &str) -> VfsResult<Arc<dyn VfsNode>> {
            if self.metadata.read().kind != VfsNodeKind::Directory {
                return Err(VfsError::NotDirectory);
            }
            self.children
                .read()
                .get(name)
                .cloned()
                .map(|node| node as Arc<dyn VfsNode>)
                .ok_or(VfsError::NoEntry)
        }

        fn readlink(&self) -> VfsResult<VfsLink> {
            match self.link.read().as_ref() {
                Some(TestLink::Text(target)) => Ok(VfsLink::Text(target.clone())),
                Some(TestLink::Magic(target)) => Ok(VfsLink::Magic(target.clone())),
                None => Err(VfsError::Invalid),
            }
        }
    }

    /// 构造测试所需的默认元数据，避免每个用例重复填写无关字段。
    fn test_metadata(kind: VfsNodeKind, mode: u16) -> VfsMetadata {
        VfsMetadata {
            kind,
            mode,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: 0,
            rdev: 0,
            times: VfsTimes::default(),
        }
    }

    /// 创建一套彼此关联的 filesystem、mount namespace、walker 和根路径。
    fn root_fixture() -> (Arc<TestFs>, Arc<VfsMountNamespace>, PathWalker, VfsPath) {
        let fs = TestFs::new(10);
        let namespace = VfsMountNamespace::new(Arc::clone(&fs) as Arc<dyn VfsFileSystem>);
        let root = namespace.root_path();
        let walker = PathWalker::new(Arc::clone(&namespace));
        (fs, namespace, walker, root)
    }

    /// 对 `PathWalker::walk` 的简短包装，让测试只突出路径和 lookup flags。
    fn lookup(
        walker: &PathWalker,
        root: &VfsPath,
        start: &VfsPath,
        path: &str,
        flags: u32,
    ) -> VfsResult<VfsPath> {
        walker.walk(
            root,
            start,
            path,
            LookupFlags(flags),
            VfsCredentials::default(),
        )
    }

    /// A positive cache entry owns the reusable dentry, while second-chance
    /// reclaim bounds that ownership and releases invalidated objects without
    /// leaving a `Weak` Arc allocation behind.
    #[test]
    fn positive_dentry_cache_retains_hot_entries_and_reclaims_cold_ones() {
        let fs = TestFs::new(10);
        fs.add(&fs.root, "a", 2, VfsNodeKind::Regular);
        fs.add(&fs.root, "b", 3, VfsNodeKind::Regular);
        fs.add(&fs.root, "c", 4, VfsNodeKind::Regular);
        let root = fs.root_dentry();
        let cache = PositiveDentryCache::with_capacity(2);

        let a = cache.lookup(&root, "a").unwrap();
        let weak_a = Arc::downgrade(&a);
        let a_id = a.id();
        drop(a);
        assert_eq!(cache.lookup(&root, "a").unwrap().id(), a_id);

        let b = cache.lookup(&root, "b").unwrap();
        let weak_b = Arc::downgrade(&b);
        drop(b);
        // Mark `a` referenced after `b` entered the clock.  Inserting `c`
        // gives `a` its second chance and reclaims the cold `b` entry.
        drop(cache.lookup(&root, "a").unwrap());
        drop(cache.lookup(&root, "c").unwrap());
        assert!(weak_a.upgrade().is_some());
        assert!(weak_b.upgrade().is_none());
        assert_eq!(cache.len(), 2);

        cache.invalidate(&root, "a");
        assert!(weak_a.upgrade().is_none());
        assert_eq!(cache.len(), 1);
    }

    /// Stable inode identity deduplicates keys across reconstructed parent
    /// dentries, but a cached child must never carry an obsolete parent chain
    /// across rename/invalidation-style reconstruction.
    #[test]
    fn positive_dentry_cache_replaces_children_of_a_reconstructed_parent() {
        let fs = TestFs::new(10);
        let directory = fs.add(&fs.root, "dir", 2, VfsNodeKind::Directory);
        fs.add(&directory, "child", 3, VfsNodeKind::Regular);
        let root = fs.root_dentry();
        let cache = PositiveDentryCache::with_capacity(8);

        let old_parent = cache.lookup(&root, "dir").unwrap();
        let old_child = cache.lookup(&old_parent, "child").unwrap();
        cache.invalidate(&root, "dir");

        let new_parent = cache.lookup(&root, "dir").unwrap();
        assert_ne!(old_parent.id(), new_parent.id());
        let new_child = cache.lookup(&new_parent, "child").unwrap();
        assert_ne!(old_child.id(), new_child.id());
        assert_eq!(
            new_child.parent().expect("child has parent").id(),
            new_parent.id()
        );
        // `dir` and `child` each occupy one stable key; the obsolete child
        // was replaced rather than accumulated under a fresh dentry ID.
        assert_eq!(cache.len(), 2);
    }

    /// A full hot cache must not turn one foreground miss into an O(capacity)
    /// write-lock hold. The reclaim budget is deliberately much smaller than
    /// this test cache so the forced fallback path is exercised.
    #[test]
    fn positive_dentry_cache_bounds_all_hot_reclaim_scan() {
        const CAPACITY: usize = 128;
        let fs = TestFs::new(10);
        let names = (0..CAPACITY)
            .map(|index| format!("entry-{index}"))
            .collect::<Vec<_>>();
        for (index, name) in names.iter().enumerate() {
            fs.add(&fs.root, name, index as u64 + 2, VfsNodeKind::Regular);
        }
        let root = fs.root_dentry();
        let cache = PositiveDentryCache::with_capacity(CAPACITY);
        for name in &names {
            drop(cache.lookup(&root, name).unwrap());
        }
        for name in &names {
            drop(cache.lookup(&root, name).unwrap());
        }

        let scans = cache.reclaim_one_for_test();
        assert_eq!(scans, 64);
        assert_eq!(cache.len(), CAPACITY - 1);
    }

    /// Cached children own their parent dentry. Reclaim a cache-only leaf
    /// before that parent so the eviction both frees memory and preserves the
    /// reusable parent identity.
    #[test]
    fn positive_dentry_cache_reclaims_child_before_child_owned_parent() {
        let fs = TestFs::new(10);
        let directory = fs.add(&fs.root, "dir", 2, VfsNodeKind::Directory);
        fs.add(&directory, "child", 3, VfsNodeKind::Regular);
        fs.add(&fs.root, "other", 4, VfsNodeKind::Regular);
        let root = fs.root_dentry();
        let cache = PositiveDentryCache::with_capacity(2);

        let parent = cache.lookup(&root, "dir").unwrap();
        let parent_id = parent.id();
        let child = cache.lookup(&parent, "child").unwrap();
        let weak_child = Arc::downgrade(&child);
        drop(child);
        drop(parent);

        drop(cache.lookup(&root, "other").unwrap());
        assert!(weak_child.upgrade().is_none());
        assert_eq!(cache.lookup(&root, "dir").unwrap().id(), parent_id);
    }

    /// The bounded scanner also supports the smallest legal cache. Holding
    /// its only candidate as the deterministic fallback temporarily empties
    /// the clock and must not attempt another pop.
    #[test]
    fn positive_dentry_cache_reclaims_one_entry_hot_cache() {
        let fs = TestFs::new(10);
        fs.add(&fs.root, "a", 2, VfsNodeKind::Regular);
        let root = fs.root_dentry();
        let cache = PositiveDentryCache::with_capacity(1);
        drop(cache.lookup(&root, "a").unwrap());
        drop(cache.lookup(&root, "a").unwrap());

        assert_eq!(cache.reclaim_one_for_test(), 1);
        assert_eq!(cache.len(), 0);
    }

    /// Invalidation leaves metadata-only clock records behind. A later insert
    /// drops that stale record without evicting an unrelated live dentry.
    #[test]
    fn positive_dentry_cache_discards_stale_clock_record_first() {
        let fs = TestFs::new(10);
        for (name, id) in [("a", 2), ("b", 3), ("c", 4), ("d", 5)] {
            fs.add(&fs.root, name, id, VfsNodeKind::Regular);
        }
        let root = fs.root_dentry();
        let cache = PositiveDentryCache::with_capacity(3);
        let a = cache.lookup(&root, "a").unwrap();
        let b = cache.lookup(&root, "b").unwrap();
        let c = cache.lookup(&root, "c").unwrap();
        let weak_a = Arc::downgrade(&a);
        let weak_b = Arc::downgrade(&b);
        let weak_c = Arc::downgrade(&c);
        drop((a, b, c));

        cache.invalidate(&root, "a");
        assert!(weak_a.upgrade().is_none());
        drop(cache.lookup(&root, "d").unwrap());
        assert!(weak_b.upgrade().is_some());
        assert!(weak_c.upgrade().is_some());
        assert_eq!(cache.len(), 3);
    }

    /// 验证绝对/相对路径、`.`、`..` 和文本符号链接的基础 REF-walk。
    #[test]
    fn walks_absolute_relative_dotdot_and_symlinks() {
        let (fs, _, walker, root) = root_fixture();
        let a = fs.add(&fs.root, "a", 2, VfsNodeKind::Directory);
        let b = fs.add(&a, "b", 3, VfsNodeKind::Directory);
        let file = fs.add(&b, "file", 4, VfsNodeKind::Regular);
        fs.add_link(&a, "relative", 5, "b/file");
        fs.add_link(&b, "absolute", 6, "/a/b/file");

        let got = lookup(&walker, &root, &root, "/a/./b/../b/file", 0).unwrap();
        assert_eq!(got.node().node_id(), file.id);

        let a_path = lookup(&walker, &root, &root, "/a", 0).unwrap();
        let got = lookup(
            &walker,
            &root,
            &a_path,
            "relative",
            LookupFlags::FOLLOW_FINAL,
        )
        .unwrap();
        assert_eq!(got.node().node_id(), file.id);

        let got = lookup(
            &walker,
            &root,
            &root,
            "/a/b/absolute",
            LookupFlags::FOLLOW_FINAL,
        )
        .unwrap();
        assert_eq!(got.node().node_id(), file.id);
    }

    /// 验证最多跟随 40 层符号链接，并要求尾随 `/` 的最终对象必须是目录。
    #[test]
    fn caps_symlink_loops_and_honors_trailing_slash() {
        let (fs, _, walker, root) = root_fixture();
        fs.add(&fs.root, "file", 2, VfsNodeKind::Regular);
        fs.add_link(&fs.root, "one", 3, "two");
        fs.add_link(&fs.root, "two", 4, "one");

        assert_eq!(
            lookup(&walker, &root, &root, "/one", LookupFlags::FOLLOW_FINAL).err(),
            Some(VfsError::Loop)
        );
        assert_eq!(
            lookup(&walker, &root, &root, "/file/", 0).err(),
            Some(VfsError::NotDirectory)
        );
    }

    /// 验证 magic link 直接返回已解析对象，并受 `NO_MAGIC_LINKS` 限制。
    #[test]
    fn follows_magic_link_paths_without_string_reparsing() {
        let (fs, _, walker, root) = root_fixture();
        let target = fs.add(&fs.root, "target", 2, VfsNodeKind::Regular);
        let target_path = lookup(&walker, &root, &root, "/target", 0).unwrap();
        let link = fs.add(&fs.root, "magic", 3, VfsNodeKind::Symlink);
        *link.link.write() = Some(TestLink::Magic(target_path));

        let followed = lookup(&walker, &root, &root, "/magic", LookupFlags::FOLLOW_FINAL).unwrap();
        assert_eq!(followed.node().node_id(), target.id);
        assert_eq!(
            lookup(
                &walker,
                &root,
                &root,
                "/magic",
                LookupFlags::FOLLOW_FINAL | LookupFlags::NO_MAGIC_LINKS,
            )
            .err(),
            Some(VfsError::Loop)
        );
        assert_eq!(
            lookup(
                &walker,
                &root,
                &root,
                "/magic",
                LookupFlags::FOLLOW_FINAL | LookupFlags::NO_SYMLINKS,
            )
            .err(),
            Some(VfsError::Loop)
        );
        assert_eq!(
            lookup(&walker, &root, &root, "/magic", LookupFlags::NO_SYMLINKS,)
                .unwrap()
                .node()
                .node_id(),
            link.id
        );
    }

    /// `MNT_NOSYMFOLLOW` belongs to the mount containing the link.  It blocks
    /// every attempted traversal, including intermediate and magic links,
    /// while lookup/readlink-style operations may still address the link
    /// object itself.
    #[test]
    fn nosymfollow_is_enforced_by_the_link_mount() {
        let (root_fs, namespace, walker, root) = root_fixture();
        let target = root_fs.add(&root_fs.root, "target", 2, VfsNodeKind::Regular);
        root_fs.add(&root_fs.root, "mnt", 3, VfsNodeKind::Directory);
        let mountpoint = lookup(&walker, &root, &root, "/mnt", 0).unwrap();

        let mounted_fs = TestFs::new(20);
        let directory = mounted_fs.add(&mounted_fs.root, "dir", 2, VfsNodeKind::Directory);
        mounted_fs.add(&directory, "file", 3, VfsNodeKind::Regular);
        mounted_fs.add_link(&mounted_fs.root, "text", 4, "dir");
        let magic = mounted_fs.add(&mounted_fs.root, "magic", 5, VfsNodeKind::Symlink);
        let target_path = lookup(&walker, &root, &root, "/target", 0).unwrap();
        *magic.link.write() = Some(TestLink::Magic(target_path));

        let mounted = namespace
            .mount(
                &mountpoint,
                Arc::clone(&mounted_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags(VfsMountFlags::NOSYMFOLLOW),
            )
            .unwrap();
        assert!(mounted.flags().is_nosymfollow());
        assert!(!mounted.flags().is_read_only());

        let link = lookup(&walker, &root, &root, "/mnt/text", 0).unwrap();
        assert_eq!(link.node().node_id(), 4);
        assert_eq!(
            lookup(
                &walker,
                &root,
                &root,
                "/mnt/text",
                LookupFlags::FOLLOW_FINAL,
            )
            .err(),
            Some(VfsError::Loop)
        );
        assert_eq!(
            lookup(&walker, &root, &root, "/mnt/text/file", 0).err(),
            Some(VfsError::Loop)
        );
        assert_eq!(
            lookup(&walker, &root, &root, "/mnt/text/", 0).err(),
            Some(VfsError::Loop)
        );
        assert_eq!(
            lookup(
                &walker,
                &root,
                &root,
                "/mnt/magic",
                LookupFlags::FOLLOW_FINAL,
            )
            .err(),
            Some(VfsError::Loop)
        );

        mounted.set_flags(VfsMountFlags::default());
        assert_eq!(
            lookup(
                &walker,
                &root,
                &root,
                "/mnt/magic",
                LookupFlags::FOLLOW_FINAL,
            )
            .unwrap()
            .node()
            .node_id(),
            target.id
        );
    }

    /// 验证硬链接拥有不同 dentry identity，但指向同一个 node/inode identity。
    #[test]
    fn hard_links_have_distinct_dentries_and_one_node() {
        let (fs, _, walker, root) = root_fixture();
        let target = fs.add(&fs.root, "first", 2, VfsNodeKind::Regular);
        fs.root
            .children
            .write()
            .insert("second".to_string(), Arc::clone(&target));

        let first = lookup(&walker, &root, &root, "/first", 0).unwrap();
        let second = lookup(&walker, &root, &root, "/second", 0).unwrap();
        assert_ne!(first.dentry().id(), second.dentry().id());
        assert_eq!(first.node().node_id(), second.node().node_id());
    }

    /// 验证同一挂载点的栈顶 mount 可见、`..` 能退出 mount、`NO_XDEV` 禁止跨越。
    #[test]
    fn crosses_mounts_uses_top_stack_and_exits_with_dotdot() {
        let (root_fs, namespace, walker, root) = root_fixture();
        root_fs.add(&root_fs.root, "mnt", 2, VfsNodeKind::Directory);
        let mountpoint = lookup(&walker, &root, &root, "/mnt", 0).unwrap();

        let lower = TestFs::new(20);
        lower.add(&lower.root, "lower", 2, VfsNodeKind::Regular);
        namespace
            .mount(
                &mountpoint,
                Arc::clone(&lower) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        let upper = TestFs::new(30);
        upper.add(&upper.root, "upper", 2, VfsNodeKind::Regular);
        namespace
            .mount(
                &mountpoint,
                Arc::clone(&upper) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        assert_eq!(
            lookup(&walker, &root, &root, "/mnt/upper", 0)
                .unwrap()
                .node()
                .filesystem_id(),
            upper.id
        );
        assert_eq!(
            lookup(&walker, &root, &root, "/mnt/..", 0)
                .unwrap()
                .dentry()
                .id(),
            root.dentry().id()
        );
        assert_eq!(
            lookup(&walker, &root, &root, "/mnt/upper", LookupFlags::NO_XDEV).err(),
            Some(VfsError::CrossDevice)
        );
    }

    /// A syscall resolves an existing mountpoint to its visible root.  A
    /// second mount through that object must still extend the original mount
    /// stack, and popping the top must reveal the lower filesystem.
    #[test]
    fn overmount_through_visible_root_extends_existing_stack() {
        let (root_fs, namespace, walker, root) = root_fixture();
        root_fs.add(&root_fs.root, "mnt", 2, VfsNodeKind::Directory);
        let mountpoint = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        let lower = TestFs::new(20);
        lower.add(&lower.root, "lower", 2, VfsNodeKind::Regular);
        let lower_mount = namespace
            .mount(
                &mountpoint,
                Arc::clone(&lower) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        let visible_lower = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        let upper = TestFs::new(30);
        upper.add(&upper.root, "upper", 2, VfsNodeKind::Regular);
        let upper_mount = namespace
            .mount(
                &visible_lower,
                Arc::clone(&upper) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        assert_eq!(
            namespace.top_mount_at(&mountpoint).unwrap().id(),
            upper_mount.id()
        );
        assert!(lookup(&walker, &root, &root, "/mnt/upper", 0).is_ok());
        let visible_upper = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        assert_eq!(
            namespace.umount(&visible_upper, false).unwrap().id(),
            upper_mount.id()
        );
        assert_eq!(
            namespace.top_mount_at(&mountpoint).unwrap().id(),
            lower_mount.id()
        );
        assert!(lookup(&walker, &root, &root, "/mnt/lower", 0).is_ok());
    }

    /// Absolute lookup starts from the visible mount covering the process
    /// root.  A relative lookup through an already pinned lower root remains
    /// on that old object, and removing the top mount reveals it again.
    #[test]
    fn root_overmount_is_visible_only_to_absolute_lookup() {
        let (_root_fs, namespace, walker, root) = root_fixture();
        let upper = TestFs::new(20);
        upper.add(&upper.root, "upper", 2, VfsNodeKind::Regular);
        let upper_mount = namespace
            .mount(
                &root,
                Arc::clone(&upper) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        let visible_root = lookup(&walker, &root, &root, "/", 0).unwrap();
        assert_eq!(visible_root.mount().id(), upper_mount.id());
        assert!(lookup(&walker, &root, &root, "/upper", 0).is_ok());

        let pinned_lower = lookup(&walker, &root, &root, ".", 0).unwrap();
        assert_eq!(pinned_lower.mount().id(), root.mount().id());
        assert_eq!(
            lookup(&walker, &root, &root, "/..", 0)
                .unwrap()
                .mount()
                .id(),
            upper_mount.id()
        );

        namespace.umount(&visible_root, false).unwrap();
        assert_eq!(
            lookup(&walker, &root, &root, "/", 0).unwrap().mount().id(),
            root.mount().id()
        );
    }

    /// 验证 bind mount 子树和路径 pin：普通卸载报告 busy，lazy detach 只移除
    /// namespace 可达性，已经 pin 的对象仍保持有效。
    #[test]
    fn bind_subtree_and_lazy_detach_preserve_pinned_paths() {
        let (fs, namespace, walker, root) = root_fixture();
        let source = fs.add(&fs.root, "source", 2, VfsNodeKind::Directory);
        let nested = fs.add(&source, "nested", 3, VfsNodeKind::Regular);
        fs.add(&fs.root, "target", 4, VfsNodeKind::Directory);
        let source_path = lookup(&walker, &root, &root, "/source", 0).unwrap();
        let target_path = lookup(&walker, &root, &root, "/target", 0).unwrap();
        let mount = namespace
            .bind(&target_path, &source_path, VfsMountFlags::default())
            .unwrap();

        let opened = lookup(&walker, &root, &root, "/target/nested", 0).unwrap();
        assert_eq!(opened.node().node_id(), nested.id);
        let pin = PinnedPath::new(opened.clone());
        assert_eq!(
            namespace.umount(&target_path, false).err(),
            Some(VfsError::Busy)
        );
        let detached = namespace.umount(&target_path, true).unwrap();
        assert_eq!(detached.id(), mount.id());
        assert_eq!(pin.path().node().node_id(), nested.id);
        assert_eq!(
            lookup(&walker, &root, &root, "/target/nested", 0).err(),
            Some(VfsError::NoEntry)
        );
    }

    /// Recursive bind clones every nested mount identity while sharing each
    /// filesystem and dentry tree. Detaching the source subtree must not
    /// detach its clone, and a normal unmount of the clone root remains busy
    /// until cloned child mounts are removed.
    #[test]
    fn recursive_bind_clones_nested_mount_tree() {
        let (fs, namespace, walker, root) = root_fixture();
        let source = fs.add(&fs.root, "source", 2, VfsNodeKind::Directory);
        fs.add(&source, "child", 3, VfsNodeKind::Directory);
        fs.add(&fs.root, "target", 4, VfsNodeKind::Directory);

        let child_fs = TestFs::new(20);
        child_fs.add(&child_fs.root, "file", 2, VfsNodeKind::Regular);
        child_fs.add(&child_fs.root, "nested", 3, VfsNodeKind::Directory);
        let source_child = lookup(&walker, &root, &root, "/source/child", 0).unwrap();
        let original_child = namespace
            .mount(
                &source_child,
                Arc::clone(&child_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        let nested_fs = TestFs::new(30);
        nested_fs.add(&nested_fs.root, "deep", 2, VfsNodeKind::Regular);
        let source_nested = lookup(&walker, &root, &root, "/source/child/nested", 0).unwrap();
        let original_nested = namespace
            .mount(
                &source_nested,
                Arc::clone(&nested_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        let source_path = lookup(&walker, &root, &root, "/source", 0).unwrap();
        let target_path = lookup(&walker, &root, &root, "/target", 0).unwrap();
        namespace
            .bind_recursive(&target_path, &source_path, VfsMountFlags::default())
            .unwrap();

        let cloned_child = lookup(&walker, &root, &root, "/target/child", 0).unwrap();
        let cloned_nested = lookup(&walker, &root, &root, "/target/child/nested", 0).unwrap();
        assert_ne!(cloned_child.mount().id(), original_child.id());
        assert_ne!(cloned_nested.mount().id(), original_nested.id());
        assert!(Arc::ptr_eq(
            cloned_child.mount().filesystem(),
            original_child.filesystem()
        ));
        assert!(Arc::ptr_eq(
            cloned_nested.mount().filesystem(),
            original_nested.filesystem()
        ));
        assert_eq!(
            lookup(&walker, &root, &root, "/target/child/nested/deep", 0)
                .unwrap()
                .node()
                .filesystem_id(),
            nested_fs.id
        );

        namespace.umount(&source_nested, false).unwrap();
        let source_child_visible = lookup(&walker, &root, &root, "/source/child", 0).unwrap();
        namespace.umount(&source_child_visible, false).unwrap();
        assert!(lookup(&walker, &root, &root, "/source/child/file", 0).is_err());
        assert!(lookup(&walker, &root, &root, "/target/child/file", 0).is_ok());
        assert_eq!(
            namespace.umount(&target_path, false).err(),
            Some(VfsError::Busy)
        );

        let target_nested = lookup(&walker, &root, &root, "/target/child/nested", 0).unwrap();
        namespace.umount(&target_nested, false).unwrap();
        let target_child = lookup(&walker, &root, &root, "/target/child", 0).unwrap();
        namespace.umount(&target_child, false).unwrap();
        namespace.umount(&target_path, false).unwrap();
    }

    /// Unmount propagation is selected by the parent mount and covered
    /// mountpoint.  Merely sharing the child mount's peer group must not make
    /// two children below unrelated private parents disappear together.
    #[test]
    fn unmount_propagation_uses_parent_peer_group() {
        let (fs, namespace, walker, root) = root_fixture();
        let source = fs.add(&fs.root, "source", 2, VfsNodeKind::Directory);
        fs.add(&source, "child", 3, VfsNodeKind::Directory);
        fs.add(&fs.root, "target", 4, VfsNodeKind::Directory);

        let child_fs = TestFs::new(20);
        child_fs.add(&child_fs.root, "file", 2, VfsNodeKind::Regular);
        let source_child = lookup(&walker, &root, &root, "/source/child", 0).unwrap();
        let original_child = namespace
            .mount(
                &source_child,
                Arc::clone(&child_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();
        let source_child_visible = lookup(&walker, &root, &root, "/source/child", 0).unwrap();
        namespace
            .set_propagation(
                &source_child_visible,
                VfsMountPropagation::Shared { peer_group: 900 },
            )
            .unwrap();

        let source_path = lookup(&walker, &root, &root, "/source", 0).unwrap();
        let target_path = lookup(&walker, &root, &root, "/target", 0).unwrap();
        namespace
            .bind_recursive(&target_path, &source_path, VfsMountFlags::default())
            .unwrap();
        let cloned_child = lookup(&walker, &root, &root, "/target/child", 0).unwrap();
        assert_ne!(cloned_child.mount().id(), original_child.id());
        assert_eq!(
            cloned_child.mount().propagation(),
            VfsMountPropagation::Shared { peer_group: 900 }
        );

        namespace.umount(&source_child_visible, false).unwrap();
        assert!(lookup(&walker, &root, &root, "/source/child/file", 0).is_err());
        assert!(lookup(&walker, &root, &root, "/target/child/file", 0).is_ok());

        let target_child = lookup(&walker, &root, &root, "/target/child", 0).unwrap();
        namespace.umount(&target_child, false).unwrap();
        namespace.umount(&target_path, false).unwrap();
    }

    /// 验证 clone 后的 mount namespace 拥有独立 mount graph，父空间卸载不会修改副本。
    #[test]
    fn namespace_clone_has_independent_mount_stacks() {
        let (fs, namespace, walker, root) = root_fixture();
        fs.add(&fs.root, "mnt", 2, VfsNodeKind::Directory);
        let mountpoint = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        let mounted = TestFs::new(20);
        namespace
            .mount(
                &mountpoint,
                Arc::clone(&mounted) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();
        let cloned = namespace.clone_namespace_with_map();
        let clone_mountpoint = cloned.remap_path(&mountpoint).unwrap();
        let clone = Arc::clone(cloned.namespace());
        let original_mount = namespace.top_mount_at(&mountpoint).unwrap();
        let cloned_mount = clone.top_mount_at(&clone_mountpoint).unwrap();
        assert_ne!(original_mount.id(), cloned_mount.id());
        assert!(Arc::ptr_eq(
            original_mount.filesystem(),
            cloned_mount.filesystem()
        ));
        namespace.umount(&mountpoint, false).unwrap();

        assert!(namespace.top_mount_at(&mountpoint).is_none());
        assert!(clone.top_mount_at(&clone_mountpoint).is_some());
    }

    /// 验证 move/remount 操作以及 `NO_XDEV` 对跨 mount 的 `..` 同样生效。
    #[test]
    fn moves_remounts_and_blocks_cross_mount_dotdot() {
        let (fs, namespace, walker, root) = root_fixture();
        fs.add(&fs.root, "from", 2, VfsNodeKind::Directory);
        fs.add(&fs.root, "to", 3, VfsNodeKind::Directory);
        let from = lookup(&walker, &root, &root, "/from", 0).unwrap();
        let to = lookup(&walker, &root, &root, "/to", 0).unwrap();
        let mounted = TestFs::new(20);
        mounted.add(&mounted.root, "file", 2, VfsNodeKind::Regular);
        namespace
            .mount(
                &from,
                Arc::clone(&mounted) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        assert_eq!(
            lookup(&walker, &root, &root, "/from/..", LookupFlags::NO_XDEV).err(),
            Some(VfsError::CrossDevice)
        );
        namespace.move_mount(&from, &to).unwrap();
        assert_eq!(
            lookup(&walker, &root, &root, "/from/file", 0).err(),
            Some(VfsError::NoEntry)
        );
        assert_eq!(
            lookup(&walker, &root, &root, "/to/file", 0)
                .unwrap()
                .node()
                .filesystem_id(),
            mounted.id
        );
        namespace.remount(&to, VfsMountFlags(0x55)).unwrap();
        assert_eq!(namespace.top_mount_at(&to).unwrap().flags().0, 0x55);

        namespace.remount(&root, VfsMountFlags(0xaa)).unwrap();
        assert_eq!(root.mount().flags().0, 0xaa);
    }

    /// Two bind mounts may expose the same dentry and superblock while keeping
    /// independent mount flags.  Remounting one clone must not alter either
    /// the source path or its sibling clone.
    #[test]
    fn bind_mounts_keep_independent_flags() {
        let (fs, namespace, walker, root) = root_fixture();
        let source_node = fs.add(&fs.root, "source", 2, VfsNodeKind::Directory);
        fs.add(&source_node, "file", 3, VfsNodeKind::Regular);
        fs.add(&fs.root, "first", 4, VfsNodeKind::Directory);
        fs.add(&fs.root, "second", 5, VfsNodeKind::Directory);
        let source = lookup(&walker, &root, &root, "/source", 0).unwrap();
        let first = lookup(&walker, &root, &root, "/first", 0).unwrap();
        let second = lookup(&walker, &root, &root, "/second", 0).unwrap();

        let first_mount = namespace
            .bind(&first, &source, VfsMountFlags(VfsMountFlags::READ_ONLY))
            .unwrap();
        let second_mount = namespace
            .bind(&second, &source, VfsMountFlags(VfsMountFlags::NODEV))
            .unwrap();
        let first_visible = lookup(&walker, &root, &root, "/first/file", 0).unwrap();
        let second_visible = lookup(&walker, &root, &root, "/second/file", 0).unwrap();
        assert_eq!(
            first_visible.node().node_id(),
            second_visible.node().node_id()
        );
        assert!(first_mount.flags().is_read_only());
        assert!(!first_mount.flags().is_nodev());
        assert!(second_mount.flags().is_nodev());
        assert!(!second_mount.flags().is_read_only());
        assert!(!source.mount().flags().is_read_only());

        let first_root = lookup(&walker, &root, &root, "/first", 0).unwrap();
        namespace
            .remount(
                &first_root,
                VfsMountFlags(VfsMountFlags::NOEXEC | VfsMountFlags::NOSYMFOLLOW),
            )
            .unwrap();
        assert!(first_mount.flags().is_noexec());
        assert!(first_mount.flags().is_nosymfollow());
        assert!(!first_mount.flags().is_read_only());
        assert!(second_mount.flags().is_nodev());
        assert!(!second_mount.flags().is_noexec());
        assert_eq!(source.mount().flags(), VfsMountFlags::default());
    }

    /// A filesystem owns one positive dcache, so separate syscall walkers must
    /// recover the same dentry object.  Mount lookup depends on this identity.
    #[test]
    fn shares_dentry_identity_across_walkers_and_mounts() {
        let (fs, namespace, first_walker, root) = root_fixture();
        fs.add(&fs.root, "plain", 2, VfsNodeKind::Regular);
        fs.add(&fs.root, "mnt", 3, VfsNodeKind::Directory);
        let second_walker = PathWalker::new(Arc::clone(&namespace));

        let first = lookup(&first_walker, &root, &root, "/plain", 0).unwrap();
        let second = lookup(&second_walker, &root, &root, "/plain", 0).unwrap();
        assert_eq!(first.dentry().id(), second.dentry().id());
        assert!(Arc::ptr_eq(first.dentry(), second.dentry()));

        let mountpoint = lookup(&first_walker, &root, &root, "/mnt", 0).unwrap();
        let mounted_fs = TestFs::new(20);
        mounted_fs.add(&mounted_fs.root, "inside", 2, VfsNodeKind::Regular);
        let mounted = namespace
            .mount(
                &mountpoint,
                Arc::clone(&mounted_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();
        assert_eq!(
            lookup(&second_walker, &root, &root, "/mnt/inside", 0)
                .unwrap()
                .mount()
                .id(),
            mounted.id()
        );
    }

    /// Namespace copies share superblocks and dentries, not mount identities or
    /// mutable mount state.
    #[test]
    fn namespace_clone_isolates_remount_move_and_pins() {
        let (fs, namespace, walker, root) = root_fixture();
        fs.add(&fs.root, "from", 2, VfsNodeKind::Directory);
        fs.add(&fs.root, "to", 3, VfsNodeKind::Directory);
        let from = lookup(&walker, &root, &root, "/from", 0).unwrap();
        let to = lookup(&walker, &root, &root, "/to", 0).unwrap();
        let mounted_fs = TestFs::new(20);
        mounted_fs.add(&mounted_fs.root, "file", 2, VfsNodeKind::Regular);
        let original_mount = namespace
            .mount(
                &from,
                Arc::clone(&mounted_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();
        let original_visible = lookup(&walker, &root, &root, "/from", 0).unwrap();
        let original_pin = PinnedPath::new(original_visible);

        let cloned = namespace.clone_namespace_with_map();
        let clone = Arc::clone(cloned.namespace());
        let clone_from = cloned.remap_path(&from).unwrap();
        let clone_to = cloned.remap_path(&to).unwrap();
        let clone_mount = clone.top_mount_at(&clone_from).unwrap();
        assert_ne!(original_mount.id(), clone_mount.id());
        assert_eq!(original_mount.pin_count(), 1);
        assert_eq!(clone_mount.pin_count(), 0);

        let clone_walker = PathWalker::new(Arc::clone(&clone));
        let clone_root = clone.root_path();
        let clone_visible = lookup(&clone_walker, &clone_root, &clone_root, "/from", 0).unwrap();
        clone.remount(&clone_visible, VfsMountFlags(0x77)).unwrap();
        assert_eq!(clone_mount.flags().0, 0x77);
        assert_eq!(original_mount.flags().0, 0);

        clone.move_mount(&clone_visible, &clone_to).unwrap();
        assert!(lookup(&clone_walker, &clone_root, &clone_root, "/from/file", 0).is_err());
        assert!(lookup(&clone_walker, &clone_root, &clone_root, "/to/file", 0).is_ok());
        assert!(lookup(&walker, &root, &root, "/from/file", 0).is_ok());
        assert!(lookup(&walker, &root, &root, "/to/file", 0).is_err());

        let clone_moved = lookup(&clone_walker, &clone_root, &clone_root, "/to", 0).unwrap();
        clone.umount(&clone_moved, false).unwrap();
        assert_eq!(original_pin.path().mount().id(), original_mount.id());
    }

    /// Normal pathname resolution returns the mounted root, so mount operations
    /// must accept that visible object rather than requiring a hidden covered
    /// dentry retained by the caller.
    #[test]
    fn unmounts_through_visible_root_and_detached_dotdot_cannot_escape() {
        let (fs, namespace, walker, root) = root_fixture();
        fs.add(&fs.root, "mnt", 2, VfsNodeKind::Directory);
        let mountpoint = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        let mounted_fs = TestFs::new(20);
        let nested = mounted_fs.add(&mounted_fs.root, "nested", 2, VfsNodeKind::Directory);
        mounted_fs.add(&nested, "file", 3, VfsNodeKind::Regular);
        let mount = namespace
            .mount(
                &mountpoint,
                Arc::clone(&mounted_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        let visible = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        let nested_path = lookup(&walker, &root, &root, "/mnt/nested", 0).unwrap();
        let pinned = PinnedPath::new(nested_path);
        assert_eq!(
            namespace.umount(&visible, false).err(),
            Some(VfsError::Busy)
        );
        assert_eq!(namespace.umount(&visible, true).unwrap().id(), mount.id());

        let detached_parent = lookup(&walker, &root, pinned.path(), "../..", 0).unwrap();
        assert_eq!(detached_parent.mount().id(), mount.id());
        assert!(Arc::ptr_eq(detached_parent.dentry(), mount.root()));
        assert!(lookup(&walker, &root, &root, "/mnt/nested", 0).is_err());
    }

    /// A pinned dirfd keeps its original namespace graph alive.  Replacing the
    /// corresponding mount in a cloned namespace must not redirect relative
    /// lookup through that old descriptor.
    #[test]
    fn old_dirfd_keeps_original_mount_tree_after_namespace_clone() {
        let (fs, namespace, walker, root) = root_fixture();
        fs.add(&fs.root, "mnt", 2, VfsNodeKind::Directory);
        let mountpoint = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        let old_fs = TestFs::new(20);
        let old_dir = old_fs.add(&old_fs.root, "dir", 2, VfsNodeKind::Directory);
        old_fs.add(&old_dir, "old", 3, VfsNodeKind::Regular);
        namespace
            .mount(
                &mountpoint,
                Arc::clone(&old_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();
        let old_dirfd = PinnedPath::new(lookup(&walker, &root, &root, "/mnt/dir", 0).unwrap());

        let cloned = namespace.clone_namespace_with_map();
        let clone = Arc::clone(cloned.namespace());
        let clone_mountpoint = cloned.remap_path(&mountpoint).unwrap();
        let clone_walker = PathWalker::new(Arc::clone(&clone));
        let clone_root = clone.root_path();
        let clone_visible = lookup(&clone_walker, &clone_root, &clone_root, "/mnt", 0).unwrap();
        clone.umount(&clone_visible, false).unwrap();

        let replacement = TestFs::new(30);
        replacement.add(&replacement.root, "new", 2, VfsNodeKind::Regular);
        clone
            .mount(
                &clone_mountpoint,
                Arc::clone(&replacement) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();

        assert!(lookup(&clone_walker, &clone_root, old_dirfd.path(), "old", 0,).is_ok());
        assert!(lookup(&clone_walker, &clone_root, &clone_root, "/mnt/new", 0).is_ok());
        assert!(lookup(&clone_walker, &clone_root, &clone_root, "/mnt/dir/old", 0).is_err());
    }

    /// Scoped openat2 lookup rejects proc-style magic jumps exactly as Linux
    /// nd_jump_link(), and dotdot requires search permission on the directory
    /// being left.
    #[test]
    fn scoped_lookup_blocks_magic_links_and_checks_dotdot_search_permission() {
        let (fs, _, walker, root) = root_fixture();
        let jail = fs.add(&fs.root, "jail", 2, VfsNodeKind::Directory);
        fs.add(&jail, "inside", 3, VfsNodeKind::Regular);
        let outside = fs.add(&fs.root, "outside", 4, VfsNodeKind::Regular);
        let outside_path = lookup(&walker, &root, &root, "/outside", 0).unwrap();
        assert_eq!(outside_path.node().node_id(), outside.id);
        let magic = fs.add(&jail, "magic", 5, VfsNodeKind::Symlink);
        *magic.link.write() = Some(TestLink::Magic(outside_path));
        let jail_path = lookup(&walker, &root, &root, "/jail", 0).unwrap();

        assert_eq!(
            lookup(&walker, &root, &jail_path, "..", LookupFlags::BENEATH).err(),
            Some(VfsError::CrossDevice)
        );
        assert!(
            lookup(
                &walker,
                &root,
                &jail_path,
                "../inside",
                LookupFlags::IN_ROOT
            )
            .is_ok()
        );

        for scoped in [LookupFlags::BENEATH, LookupFlags::IN_ROOT] {
            assert_eq!(
                lookup(
                    &walker,
                    &root,
                    &jail_path,
                    "magic",
                    LookupFlags::FOLLOW_FINAL | scoped,
                )
                .err(),
                Some(VfsError::CrossDevice)
            );
        }

        *jail.metadata.write() = test_metadata(VfsNodeKind::Directory, 0o600);
        assert_eq!(
            walker
                .walk(
                    &root,
                    &jail_path,
                    "..",
                    LookupFlags::default(),
                    VfsCredentials {
                        uid: 1000,
                        gid: 1000
                    },
                )
                .err(),
            Some(VfsError::Access)
        );
    }

    #[test]
    fn resolves_mutation_parent_without_absolute_path_reconstruction() {
        let (fs, _, walker, root) = root_fixture();
        let dir = fs.add(&fs.root, "dir", 2, VfsNodeKind::Directory);
        fs.add(&dir, "nested", 3, VfsNodeKind::Directory);
        fs.add_link(&fs.root, "alias", 4, "dir/nested");

        let parent = walker
            .walk_parent(
                &root,
                &root,
                "/alias/new/",
                LookupFlags::default(),
                VfsCredentials::default(),
            )
            .unwrap();
        assert_eq!(parent.parent.node().node_id(), 3);
        assert_eq!(parent.name, "new");
        assert!(parent.trailing_slash);
        assert_eq!(
            walker
                .walk_parent(
                    &root,
                    &root,
                    &alloc::format!("/{}", "x".repeat(256)),
                    LookupFlags::default(),
                    VfsCredentials::default(),
                )
                .err(),
            Some(VfsError::NameTooLong)
        );
    }

    #[test]
    fn fs_struct_remaps_root_and_cwd_but_private_clone_keeps_mounts() {
        let (fs, namespace, walker, root) = root_fixture();
        fs.add(&fs.root, "mnt", 2, VfsNodeKind::Directory);
        let mountpoint = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        let mounted_fs = TestFs::new(20);
        mounted_fs.add(&mounted_fs.root, "cwd", 2, VfsNodeKind::Directory);
        namespace
            .mount(
                &mountpoint,
                Arc::clone(&mounted_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();
        let cwd = lookup(&walker, &root, &root, "/mnt/cwd", 0).unwrap();
        let fs_struct = FsStruct::new(root.clone());
        fs_struct.set_cwd(cwd.clone());

        let private = fs_struct.clone_private();
        assert_eq!(private.root().path().mount().id(), root.mount().id());
        assert_eq!(private.cwd().path().mount().id(), cwd.mount().id());

        let cloned = namespace.clone_namespace_with_map();
        let remapped = fs_struct.clone_for_namespace(&cloned).unwrap();
        assert_ne!(remapped.root().path().mount().id(), root.mount().id());
        assert_ne!(remapped.cwd().path().mount().id(), cwd.mount().id());
        assert_eq!(remapped.cwd().path().node().node_id(), cwd.node().node_id());
        assert_eq!(remapped.root().namespace().id(), cloned.namespace().id());

        let jailed =
            FsStruct::new_with_paths(root.clone(), cwd.clone(), "/jail", "/jail/subdir", 0);
        assert_eq!(jailed.cwd_visible(), "/subdir");
        jailed.set_cwd_display("/jail");
        assert_eq!(jailed.cwd_visible(), "/");
        jailed.set_cwd_display("/outside");
        assert_eq!(jailed.cwd_visible(), "(unreachable)/outside");
    }

    #[test]
    fn shared_mount_events_reach_peers_and_slaves_atomically() {
        let (fs, namespace, walker, root) = root_fixture();
        fs.add(&fs.root, "mnt", 2, VfsNodeKind::Directory);
        let mountpoint = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        namespace
            .set_propagation(&root, VfsMountPropagation::Shared { peer_group: 700 })
            .unwrap();

        let peer_clone = namespace.clone_namespace_with_map();
        let peer = Arc::clone(peer_clone.namespace());
        let peer_mountpoint = peer_clone.remap_path(&mountpoint).unwrap();
        let peer_root = peer.root_path();

        let slave_clone = namespace.clone_namespace_with_map();
        let slave = Arc::clone(slave_clone.namespace());
        let slave_mountpoint = slave_clone.remap_path(&mountpoint).unwrap();
        let slave_root = slave.root_path();
        slave
            .set_propagation(
                &slave_root,
                VfsMountPropagation::Slave { master_group: 700 },
            )
            .unwrap();

        let mounted_fs = TestFs::new(20);
        mounted_fs.add(&mounted_fs.root, "file", 2, VfsNodeKind::Regular);
        let local_mount = namespace
            .mount(
                &mountpoint,
                Arc::clone(&mounted_fs) as Arc<dyn VfsFileSystem>,
                VfsMountFlags::default(),
            )
            .unwrap();
        let peer_mount = peer.top_mount_at(&peer_mountpoint).unwrap();
        let slave_mount = slave.top_mount_at(&slave_mountpoint).unwrap();
        let child_group = match local_mount.propagation() {
            VfsMountPropagation::Shared { peer_group } => peer_group,
            _ => panic!("local child did not become shared"),
        };
        assert_eq!(
            peer_mount.propagation(),
            VfsMountPropagation::Shared {
                peer_group: child_group
            }
        );
        assert_eq!(
            slave_mount.propagation(),
            VfsMountPropagation::Slave {
                master_group: child_group
            }
        );

        let peer_walker = PathWalker::new(Arc::clone(&peer));
        let slave_walker = PathWalker::new(Arc::clone(&slave));
        assert!(lookup(&peer_walker, &peer_root, &peer_root, "/mnt/file", 0).is_ok());
        assert!(lookup(&slave_walker, &slave_root, &slave_root, "/mnt/file", 0).is_ok());

        let peer_visible = lookup(&peer_walker, &peer_root, &peer_root, "/mnt", 0).unwrap();
        let peer_pin = PinnedPath::new(peer_visible);
        let local_visible = lookup(&walker, &root, &root, "/mnt", 0).unwrap();
        assert_eq!(
            namespace.umount(&local_visible, false).err(),
            Some(VfsError::Busy)
        );
        assert!(namespace.top_mount_at(&mountpoint).is_some());
        assert!(peer.top_mount_at(&peer_mountpoint).is_some());
        assert!(slave.top_mount_at(&slave_mountpoint).is_some());

        drop(peer_pin);
        namespace.umount(&local_visible, false).unwrap();
        assert!(namespace.top_mount_at(&mountpoint).is_none());
        assert!(peer.top_mount_at(&peer_mountpoint).is_none());
        assert!(slave.top_mount_at(&slave_mountpoint).is_none());
    }
}
