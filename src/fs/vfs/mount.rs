use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use super::{Dentry, VfsError, VfsFileSystem, VfsNode, VfsResult};

static NEXT_MOUNT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsMountFlags(pub usize);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VfsMountPropagation {
    #[default]
    Private,
    Shared {
        peer_group: u64,
    },
    Slave {
        master_group: u64,
    },
    Unbindable,
}

struct MountRelation {
    parent: Weak<VfsMount>,
    covered: Arc<Dentry>,
}

/// 一个已经挂载的文件系统实例或 bind 子树。
///
/// `VfsMount` 表示文件系统在某个 mount namespace 中的一次挂载身份，
/// 它不是文件系统本身；同一个 `VfsFileSystem` 可以对应多个挂载对象。
pub struct VfsMount {
    /// 单调分配的稳定挂载 ID，用于 mount graph 的对象身份判断。
    id: u64,
    /// 此挂载使用的后端文件系统实例；bind mount 与源挂载共享该实例。
    filesystem: Arc<dyn VfsFileSystem>,
    /// 此挂载对外暴露的根 dentry。
    ///
    /// 普通挂载指向文件系统根节点；bind mount 可以指向源文件系统中的任意
    /// 目录或文件 dentry。
    root: Arc<Dentry>,
    /// 此挂载与父挂载的连接关系。
    ///
    /// 其中记录父 mount 和被本挂载覆盖的 dentry；命名空间根、尚未 attach
    /// 或已经脱离命名空间的挂载可以没有该关系。`move_mount` 会更新它。
    relation: RwLock<Option<MountRelation>>,
    /// 当前挂载 flags；使用原子值以支持不替换挂载对象的 remount 更新。
    flags: AtomicUsize,
    /// cwd、进程 root 和打开 FD 等持久路径对该挂载的 pin 数量。
    ///
    /// 非 lazy umount 必须在该计数为零时才能成功。
    pins: AtomicUsize,
    /// bind mount 的原始源路径；普通挂载为 `None`。
    ///
    /// 保存对象化的 `VfsPath`，避免以后通过源路径字符串重新解析。
    bind_source: Option<VfsPath>,
    /// 此挂载当前的传播类型，例如 private、shared、slave 或 unbindable。
    propagation: RwLock<VfsMountPropagation>,
}

impl VfsMount {
    pub fn new(filesystem: Arc<dyn VfsFileSystem>, flags: VfsMountFlags) -> Arc<Self> {
        let root = Dentry::root(filesystem.root_node());
        Arc::new(Self {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed) as u64,
            filesystem,
            root,
            relation: RwLock::new(None),
            flags: AtomicUsize::new(flags.0),
            pins: AtomicUsize::new(0),
            bind_source: None,
            propagation: RwLock::new(VfsMountPropagation::Private),
        })
    }

    pub fn new_bind(source: &VfsPath, flags: VfsMountFlags) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed) as u64,
            filesystem: Arc::clone(source.mount().filesystem()),
            root: Arc::clone(source.dentry()),
            relation: RwLock::new(None),
            flags: AtomicUsize::new(flags.0),
            pins: AtomicUsize::new(0),
            bind_source: Some(source.clone()),
            propagation: RwLock::new(VfsMountPropagation::Private),
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn filesystem(&self) -> &Arc<dyn VfsFileSystem> {
        &self.filesystem
    }

    pub fn root(&self) -> &Arc<Dentry> {
        &self.root
    }

    pub fn flags(&self) -> VfsMountFlags {
        VfsMountFlags(self.flags.load(Ordering::Acquire))
    }

    pub fn set_flags(&self, flags: VfsMountFlags) {
        self.flags.store(flags.0, Ordering::Release);
    }

    pub fn pin_count(&self) -> usize {
        self.pins.load(Ordering::Acquire)
    }

    pub fn bind_source(&self) -> Option<&VfsPath> {
        self.bind_source.as_ref()
    }

    pub fn propagation(&self) -> VfsMountPropagation {
        *self.propagation.read()
    }

    pub fn set_propagation(&self, propagation: VfsMountPropagation) {
        *self.propagation.write() = propagation;
    }
}

/// One certain file/directory can be different in different mounts
/// a/b c/d canbe the same dentry
/// So we need this Mount to make sure where we come from
#[derive(Clone)]
pub struct VfsPath {
    mount: Arc<VfsMount>,
    dentry: Arc<Dentry>,
}

impl VfsPath {
    pub fn new(mount: Arc<VfsMount>, dentry: Arc<Dentry>) -> Self {
        Self { mount, dentry }
    }

    pub fn mount(&self) -> &Arc<VfsMount> {
        &self.mount
    }

    pub fn dentry(&self) -> &Arc<Dentry> {
        &self.dentry
    }

    pub fn node(&self) -> &Arc<dyn VfsNode> {
        self.dentry.node()
    }

    pub fn same_object(&self, other: &Self) -> bool {
        self.mount.id() == other.mount.id() && self.dentry.id() == other.dentry.id()
    }
}

/// A persistent path reference keeps a detached mount alive and makes normal
/// unmount return `Busy`.  Lazy detach removes only namespace reachability.
pub struct PinnedPath(VfsPath);

impl PinnedPath {
    pub fn new(path: VfsPath) -> Self {
        path.mount.pins.fetch_add(1, Ordering::AcqRel);
        Self(path)
    }

    pub fn path(&self) -> &VfsPath {
        &self.0
    }
}

impl Clone for PinnedPath {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl Drop for PinnedPath {
    fn drop(&mut self) {
        self.0.mount.pins.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MountPoint {
    parent_mount_id: u64,
    dentry_id: u64,
}

struct MountGraph {
    edges: BTreeMap<MountPoint, Vec<Arc<VfsMount>>>,
}

/// Mount namespace whose sole mount state is the object graph.
pub struct VfsMountNamespace {
    root: Arc<VfsMount>,
    graph: RwLock<MountGraph>,
}

impl VfsMountNamespace {
    /// 以 `root_fs` 创建新的挂载命名空间。
    ///
    /// `root_fs` 会成为命名空间的根挂载，初始 mount graph 不包含任何子挂载。
    pub fn new(root_fs: Arc<dyn VfsFileSystem>) -> Arc<Self> {
        Arc::new(Self {
            root: VfsMount::new(root_fs, VfsMountFlags::default()),
            graph: RwLock::new(MountGraph {
                edges: BTreeMap::new(),
            }),
        })
    }

    /// 返回命名空间根挂载的根路径。
    pub fn root_path(&self) -> VfsPath {
        VfsPath::new(Arc::clone(&self.root), Arc::clone(self.root.root()))
    }

    /// 在 `at` 指向的目录项上挂载一个新的文件系统实例。
    ///
    /// 新挂载会压入该挂载点的 stack，并成为用户可见的最上层挂载。
    pub fn mount(
        &self,
        at: &VfsPath,
        filesystem: Arc<dyn VfsFileSystem>,
        flags: VfsMountFlags,
    ) -> VfsResult<Arc<VfsMount>> {
        let mount = VfsMount::new(filesystem, flags);
        self.attach(at, &mount);
        Ok(mount)
    }

    /// 在 `at` 上创建以 `source` 为根的 bind mount。
    ///
    /// bind mount 保存源对象的 `VfsPath`，不会保存或重新解析源路径字符串。
    /// `Unbindable` 类型的源挂载不能作为 bind mount 来源。
    pub fn bind(
        &self,
        at: &VfsPath,
        source: &VfsPath,
        flags: VfsMountFlags,
    ) -> VfsResult<Arc<VfsMount>> {
        if source.mount().propagation() == VfsMountPropagation::Unbindable {
            return Err(VfsError::Invalid);
        }
        let mount = VfsMount::new_bind(source, flags);
        self.attach(at, &mount);
        Ok(mount)
    }

    /// 把 `mount` 接入 `at` 对应的挂载点。
    ///
    /// 同时记录父挂载和被覆盖的 dentry，并将新挂载压入该挂载点的有序 stack。
    /// 确保一个点退出之后，旧点能够回来
    fn attach(&self, at: &VfsPath, mount: &Arc<VfsMount>) {
        *mount.relation.write() = Some(MountRelation {
            parent: Arc::downgrade(at.mount()),
            covered: Arc::clone(at.dentry()),
        });
        self.graph
            .write()
            .edges
            .entry(MountPoint {
                parent_mount_id: at.mount().id(),
                dentry_id: at.dentry().id(),
            })
            .or_default()
            .push(Arc::clone(mount));
    }

    /// 返回准确覆盖 `at` 的最上层挂载；当前位置不是挂载点时返回 `None`。
    pub fn top_mount_at(&self, at: &VfsPath) -> Option<Arc<VfsMount>> {
        self.graph
            .read()
            .edges
            .get(&MountPoint {
                parent_mount_id: at.mount().id(),
                dentry_id: at.dentry().id(),
            })
            .and_then(|stack| stack.last())
            .cloned()
    }

    /// 从当前路径进入所有连续覆盖它的挂载，并返回最终可见的挂载根。
    ///
    /// 使用循环是为了处理 overmount stack，以及新挂载根本身再次被挂载的情况。
    pub fn follow_mounts(&self, mut path: VfsPath) -> VfsPath {
        while let Some(next) = self.top_mount_at(&path) {
            path = VfsPath::new(Arc::clone(&next), Arc::clone(next.root()));
        }
        path
    }

    /// 卸载 `at` 上 mount stack 的最上层挂载并返回被移除的挂载对象。
    ///
    /// 普通卸载会拒绝仍被 cwd/root/FD pin 或仍有子挂载的对象。`lazy` 为
    /// `true` 时只把挂载从命名空间图中分离，已有的 `Arc`/pin 仍可继续访问它。
    pub fn umount(&self, at: &VfsPath, lazy: bool) -> VfsResult<Arc<VfsMount>> {
        let point = MountPoint {
            parent_mount_id: at.mount().id(),
            dentry_id: at.dentry().id(),
        };
        let mut graph = self.graph.write();
        let mount = graph
            .edges
            .get(&point)
            .and_then(|stack| stack.last())
            .cloned()
            .ok_or(VfsError::Invalid)?;
        if !lazy {
            // 仍然在被使用
            if mount.pin_count() != 0 {
                return Err(VfsError::Busy);
            }
            // 仍然有子对象
            if graph
                .edges
                .keys()
                .any(|child| child.parent_mount_id == mount.id())
            {
                return Err(VfsError::Busy);
            }
        }
        let stack = graph.edges.get_mut(&point).expect("mount stack vanished");
        let detached = stack.pop().expect("checked non-empty mount stack");
        if stack.is_empty() {
            graph.edges.remove(&point);
        }
        Ok(detached)
    }

    /// 更新 `at` 上最上层挂载的 flags，不创建新的挂载对象。
    pub fn remount(&self, at: &VfsPath, flags: VfsMountFlags) -> VfsResult<()> {
        let mount = self.top_mount_at(at).ok_or(VfsError::Invalid)?;
        mount.set_flags(flags);
        Ok(())
    }

    /// 将 `from` 上最顶层的挂载移动到 `to`。
    ///
    /// 操作同时更新 mount graph 和父子关系；禁止把挂载移动到自己的后代中，
    /// 以避免在挂载图中形成环。
    pub fn move_mount(&self, from: &VfsPath, to: &VfsPath) -> VfsResult<()> {
        let from_point = MountPoint {
            parent_mount_id: from.mount().id(),
            dentry_id: from.dentry().id(),
        };
        let to_point = MountPoint {
            parent_mount_id: to.mount().id(),
            dentry_id: to.dentry().id(),
        };
        let mut graph = self.graph.write();
        let moving = graph
            .edges
            .get(&from_point)
            .and_then(|stack| stack.last())
            .cloned()
            .ok_or(VfsError::Invalid)?;
        if mount_descends_from(to.mount(), &moving) {
            return Err(VfsError::Invalid);
        }
        let source_stack = graph
            .edges
            .get_mut(&from_point)
            .expect("mount stack vanished");
        source_stack.pop();
        if source_stack.is_empty() {
            graph.edges.remove(&from_point);
        }
        *moving.relation.write() = Some(MountRelation {
            parent: Arc::downgrade(to.mount()),
            covered: Arc::clone(to.dentry()),
        });
        graph.edges.entry(to_point).or_default().push(moving);
        Ok(())
    }

    /// 克隆当前挂载命名空间的图结构。
    ///
    /// 新旧命名空间拥有独立的 edge/stack 集合，但共享 `Arc<VfsMount>` 对象，
    /// 因而已经解析并持有的 `VfsPath` 在两个命名空间中都保持有效。
    pub fn clone_namespace(&self) -> Arc<Self> {
        // Mount objects are immutable identities except for pins/flags.  A
        // namespace clone copies the graph stacks, while resolved paths remain
        // valid in either namespace just as REF-walk references do.
        let edges = self
            .graph
            .read()
            .edges
            .iter()
            .map(|(point, stack)| (point.clone(), stack.clone()))
            .collect();
        Arc::new(Self {
            root: Arc::clone(&self.root),
            graph: RwLock::new(MountGraph { edges }),
        })
    }

    /// 为路径遍历实现 `..`：返回 `path` 的可见父路径。
    ///
    /// 位于挂载根时先退出到父挂载中被覆盖 dentry 的父目录；否则返回当前
    /// mount 内的父 dentry。命名空间根没有父路径时保持原位。
    pub(super) fn ascend(&self, path: &VfsPath) -> VfsPath {
        if Arc::ptr_eq(path.dentry(), path.mount().root())
            && let Some(relation) = path.mount().relation.read().as_ref()
            && let Some(parent_mount) = relation.parent.upgrade()
        {
            let covered_parent = relation
                .covered
                .parent()
                .unwrap_or_else(|| Arc::clone(&relation.covered));
            return VfsPath::new(parent_mount, covered_parent);
        }
        match path.dentry().parent() {
            Some(parent) => VfsPath::new(Arc::clone(path.mount()), parent),
            None => path.clone(),
        }
    }
}

fn mount_descends_from(candidate: &Arc<VfsMount>, ancestor: &Arc<VfsMount>) -> bool {
    let mut current = Arc::clone(candidate);
    loop {
        if current.id() == ancestor.id() {
            return true;
        }
        let Some(parent) = current
            .relation
            .read()
            .as_ref()
            .and_then(|relation| relation.parent.upgrade())
        else {
            return false;
        };
        current = parent;
    }
}
