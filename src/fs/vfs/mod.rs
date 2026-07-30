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
    /// 对象仍被引用、目录是 cwd/root 或 mount 仍被 pin（`EBUSY`）。
    Busy,
    /// 操作不允许跨越 mount/filesystem 边界（`EXDEV`）。
    CrossDevice,
    /// 要创建的名字或注册项已经存在（`EEXIST`）。
    Exists,
    /// 参数、对象类型或状态组合无效（`EINVAL`）。
    Invalid,
    /// 期望普通文件，但目标是目录（`EISDIR`）。
    IsDirectory,
    /// 符号链接解析次数过多或形成循环（`ELOOP`）。
    Loop,
    /// 路径或单个名字超过 VFS 支持的上限（`ENAMETOOLONG`）。
    NameTooLong,
    /// 路径分量或目标对象不存在（`ENOENT`）。
    NoEntry,
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
        string::{String, ToString},
        sync::{Arc, Weak},
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
                Self { id, root }
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

        fn root_node(&self) -> Arc<dyn VfsNode> {
            Arc::clone(&self.root) as Arc<dyn VfsNode>
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
        let clone = namespace.clone_namespace();
        namespace.umount(&mountpoint, false).unwrap();

        assert!(namespace.top_mount_at(&mountpoint).is_none());
        assert!(clone.top_mount_at(&mountpoint).is_some());
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
    }
}
