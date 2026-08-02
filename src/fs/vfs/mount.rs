use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use super::{Dentry, VfsError, VfsFileSystem, VfsNode, VfsResult};

static NEXT_MOUNT_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_MOUNT_NAMESPACE_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_MOUNT_PEER_GROUP_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsMountFlags(pub usize);

impl VfsMountFlags {
    /// Mount-local flags with user-visible pathname semantics.  Keep the bit
    /// values aligned with Linux UAPI `MS_*`; syscall constants re-export
    /// these values instead of maintaining a second copy.
    pub const READ_ONLY: usize = 0x1;
    pub const NODEV: usize = 0x4;
    pub const NOEXEC: usize = 0x8;
    pub const NOSYMFOLLOW: usize = 0x100;

    pub const fn contains(self, flag: usize) -> bool {
        self.0 & flag != 0
    }

    pub const fn is_read_only(self) -> bool {
        self.contains(Self::READ_ONLY)
    }

    pub const fn is_nodev(self) -> bool {
        self.contains(Self::NODEV)
    }

    pub const fn is_noexec(self) -> bool {
        self.contains(Self::NOEXEC)
    }

    pub const fn is_nosymfollow(self) -> bool {
        self.contains(Self::NOSYMFOLLOW)
    }
}

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

/// One mount identity in one mount namespace.
///
/// The filesystem and dentries may be shared by bind mounts and namespace
/// copies, while flags, pins and the parent relation belong to this mount
/// object alone.  This mirrors Linux's split between `super_block`/`dentry`
/// and `struct mount`.
pub struct VfsMount {
    id: u64,
    namespace_id: u64,
    namespace: Weak<VfsMountNamespace>,
    filesystem: Arc<dyn VfsFileSystem>,
    root: Arc<Dentry>,
    relation: RwLock<Option<MountRelation>>,
    flags: AtomicUsize,
    pins: AtomicUsize,
    bind_source: RwLock<Option<VfsPath>>,
    propagation: RwLock<VfsMountPropagation>,
    source_display: String,
}

impl VfsMount {
    fn new(
        namespace_id: u64,
        namespace: Weak<VfsMountNamespace>,
        filesystem: Arc<dyn VfsFileSystem>,
        flags: VfsMountFlags,
        source_display: String,
    ) -> Arc<Self> {
        let root = filesystem.root_dentry();
        Arc::new(Self {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed) as u64,
            namespace_id,
            namespace,
            filesystem,
            root,
            relation: RwLock::new(None),
            flags: AtomicUsize::new(flags.0),
            pins: AtomicUsize::new(0),
            bind_source: RwLock::new(None),
            propagation: RwLock::new(VfsMountPropagation::Private),
            source_display,
        })
    }

    fn new_bind(
        namespace_id: u64,
        namespace: Weak<VfsMountNamespace>,
        source: &VfsPath,
        flags: VfsMountFlags,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed) as u64,
            namespace_id,
            namespace,
            filesystem: Arc::clone(source.mount().filesystem()),
            root: Arc::clone(source.dentry()),
            relation: RwLock::new(None),
            flags: AtomicUsize::new(flags.0),
            pins: AtomicUsize::new(0),
            bind_source: RwLock::new(Some(source.clone())),
            propagation: RwLock::new(VfsMountPropagation::Private),
            source_display: source.mount().source_display().to_string(),
        })
    }

    fn clone_for_namespace(
        &self,
        namespace_id: u64,
        namespace: Weak<VfsMountNamespace>,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed) as u64,
            namespace_id,
            namespace,
            filesystem: Arc::clone(&self.filesystem),
            root: Arc::clone(&self.root),
            relation: RwLock::new(None),
            flags: AtomicUsize::new(self.flags().0),
            pins: AtomicUsize::new(0),
            bind_source: RwLock::new(None),
            propagation: RwLock::new(self.propagation()),
            source_display: self.source_display.clone(),
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

    pub fn bind_source(&self) -> Option<VfsPath> {
        self.bind_source.read().clone()
    }

    pub fn propagation(&self) -> VfsMountPropagation {
        *self.propagation.read()
    }

    pub fn set_propagation(&self, propagation: VfsMountPropagation) {
        *self.propagation.write() = propagation;
    }

    pub fn source_display(&self) -> &str {
        &self.source_display
    }

    pub fn filesystem_type(&self) -> &'static str {
        self.filesystem.filesystem_type()
    }

    pub(crate) fn owner_namespace(&self) -> Option<Arc<VfsMountNamespace>> {
        self.namespace.upgrade()
    }
}

/// A resolved pathname is an object pair, never a translated absolute string.
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

    /// Retain the exact object returned by a successful create operation.
    ///
    /// The new dentry is intentionally not inserted into the lookup cache:
    /// namespace mutation code invalidates that cache separately, while the
    /// returned path must keep naming the created object even if another task
    /// immediately renames or unlinks it.
    pub fn created_child(parent: &VfsPath, name: &str, node: Arc<dyn super::VfsNode>) -> Self {
        Self::new(
            Arc::clone(parent.mount()),
            Dentry::child(parent.dentry(), name, node),
        )
    }
}

/// Persistent paths hold both the mount and its graph owner alive.
///
/// The graph reference matters after `unshare(CLONE_NEWNS)`: an old dirfd must
/// continue walking the mount tree in which it was opened, even when no task
/// retains that namespace as its current namespace.
pub struct PinnedPath {
    path: VfsPath,
    namespace: Arc<VfsMountNamespace>,
}

impl PinnedPath {
    pub fn new(path: VfsPath) -> Self {
        let namespace = path
            .mount
            .owner_namespace()
            .expect("a persistent path must belong to a live mount graph");
        path.mount.pins.fetch_add(1, Ordering::AcqRel);
        Self { path, namespace }
    }

    pub fn path(&self) -> &VfsPath {
        &self.path
    }

    pub fn namespace(&self) -> &Arc<VfsMountNamespace> {
        &self.namespace
    }
}

impl Clone for PinnedPath {
    fn clone(&self) -> Self {
        self.path.mount.pins.fetch_add(1, Ordering::AcqRel);
        Self {
            path: self.path.clone(),
            namespace: Arc::clone(&self.namespace),
        }
    }
}

impl Drop for PinnedPath {
    fn drop(&mut self) {
        self.path.mount.pins.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MountPoint {
    parent_mount_id: u64,
    dentry_id: u64,
}

#[derive(Default)]
struct MountGraph {
    edges: BTreeMap<MountPoint, Vec<Arc<VfsMount>>>,
}

#[derive(Default)]
struct PropagationDomain {
    namespaces: RwLock<Vec<Weak<VfsMountNamespace>>>,
}

impl PropagationDomain {
    fn register(&self, namespace: &Arc<VfsMountNamespace>) {
        let mut namespaces = self.namespaces.write();
        namespaces.retain(|entry| entry.strong_count() != 0);
        namespaces.push(Arc::downgrade(namespace));
    }

    fn snapshot(&self) -> Vec<Arc<VfsMountNamespace>> {
        self.namespaces
            .read()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
}

struct PropagationDestination {
    namespace: Arc<VfsMountNamespace>,
    at: VfsPath,
    child_propagation: VfsMountPropagation,
}

/// Mount namespace whose authoritative state is an object graph.
pub struct VfsMountNamespace {
    id: u64,
    root: Arc<VfsMount>,
    graph: RwLock<MountGraph>,
    propagation_domain: Arc<PropagationDomain>,
}

/// Result of cloning a mount namespace, including Linux-style path remapping
/// for `fs_struct` root and cwd.  Open file paths deliberately remain on the
/// old mount objects.
pub struct VfsMountNamespaceClone {
    namespace: Arc<VfsMountNamespace>,
    mounts: BTreeMap<u64, Arc<VfsMount>>,
}

impl VfsMountNamespaceClone {
    pub fn namespace(&self) -> &Arc<VfsMountNamespace> {
        &self.namespace
    }

    pub fn into_namespace(self) -> Arc<VfsMountNamespace> {
        self.namespace
    }

    pub fn remap_path(&self, source: &VfsPath) -> VfsResult<VfsPath> {
        let mount = self
            .mounts
            .get(&source.mount().id())
            .cloned()
            .ok_or(VfsError::CrossDevice)?;
        Ok(VfsPath::new(mount, Arc::clone(source.dentry())))
    }
}

impl VfsMountNamespace {
    pub fn new(root_fs: Arc<dyn VfsFileSystem>) -> Arc<Self> {
        let id = NEXT_MOUNT_NAMESPACE_ID.fetch_add(1, Ordering::Relaxed) as u64;
        let propagation_domain = Arc::new(PropagationDomain::default());
        let domain = Arc::clone(&propagation_domain);
        let namespace = Arc::new_cyclic(|namespace| Self {
            id,
            root: VfsMount::new(
                id,
                namespace.clone(),
                root_fs,
                VfsMountFlags::default(),
                "/dev/root".to_string(),
            ),
            graph: RwLock::new(MountGraph::default()),
            propagation_domain: Arc::clone(&domain),
        });
        propagation_domain.register(&namespace);
        namespace
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn root_path(&self) -> VfsPath {
        VfsPath::new(Arc::clone(&self.root), Arc::clone(self.root.root()))
    }

    pub fn mount(
        self: &Arc<Self>,
        at: &VfsPath,
        filesystem: Arc<dyn VfsFileSystem>,
        flags: VfsMountFlags,
    ) -> VfsResult<Arc<VfsMount>> {
        let source = filesystem.filesystem_type().to_string();
        self.mount_with_source(at, filesystem, flags, source)
    }

    pub fn mount_with_source(
        self: &Arc<Self>,
        at: &VfsPath,
        filesystem: Arc<dyn VfsFileSystem>,
        flags: VfsMountFlags,
        source_display: String,
    ) -> VfsResult<Arc<VfsMount>> {
        let at = self.stacking_target(at)?;
        let destinations = self.propagation_destinations(&at)?;
        let mut local = None;
        for destination in destinations {
            let mount = VfsMount::new(
                destination.namespace.id,
                Arc::downgrade(&destination.namespace),
                Arc::clone(&filesystem),
                flags,
                source_display.clone(),
            );
            mount.set_propagation(destination.child_propagation);
            destination.namespace.attach(&destination.at, &mount)?;
            if destination.namespace.id == self.id
                && destination.at.mount().id() == at.mount().id()
                && destination.at.dentry().id() == at.dentry().id()
            {
                local = Some(Arc::clone(&mount));
            }
        }
        local.ok_or(VfsError::Invalid)
    }

    pub fn bind(
        self: &Arc<Self>,
        at: &VfsPath,
        source: &VfsPath,
        flags: VfsMountFlags,
    ) -> VfsResult<Arc<VfsMount>> {
        let at = self.stacking_target(at)?;
        if source.mount().propagation() == VfsMountPropagation::Unbindable {
            return Err(VfsError::Invalid);
        }
        let destinations = self.propagation_destinations(&at)?;
        let mut local = None;
        for destination in destinations {
            let mount = VfsMount::new_bind(
                destination.namespace.id,
                Arc::downgrade(&destination.namespace),
                source,
                flags,
            );
            mount.set_propagation(destination.child_propagation);
            destination.namespace.attach(&destination.at, &mount)?;
            if destination.namespace.id == self.id
                && destination.at.mount().id() == at.mount().id()
                && destination.at.dentry().id() == at.dentry().id()
            {
                local = Some(Arc::clone(&mount));
            }
        }
        local.ok_or(VfsError::Invalid)
    }

    /// Recursively clone the visible mount subtree rooted at `source`.
    ///
    /// Linux builds an unattached mount tree with `copy_tree()`/`clone_mnt()`
    /// and grafts it under the namespace lock.  Keep the same important
    /// boundary here: filesystem and dentry objects are shared, every mount
    /// gets a new identity, unbindable child subtrees are pruned, and no
    /// partially built tree is visible while backend objects are prepared.
    pub fn bind_recursive(
        self: &Arc<Self>,
        at: &VfsPath,
        source: &VfsPath,
        flags: VfsMountFlags,
    ) -> VfsResult<Arc<VfsMount>> {
        let at = self.stacking_target(at)?;
        if source.mount().propagation() == VfsMountPropagation::Unbindable {
            return Err(VfsError::Invalid);
        }
        let source_namespace = source.mount().owner_namespace().ok_or(VfsError::Invalid)?;
        let source_edges = source_namespace.graph.read().edges.clone();
        let destinations = self.propagation_destinations(&at)?;
        let mut local = None;
        for destination in destinations {
            let mount = destination.namespace.graft_recursive_bind_tree(
                &destination.at,
                source,
                flags,
                destination.child_propagation,
                &source_edges,
            )?;
            if destination.namespace.id == self.id
                && destination.at.mount().id() == at.mount().id()
                && destination.at.dentry().id() == at.dentry().id()
            {
                local = Some(mount);
            }
        }
        local.ok_or(VfsError::Invalid)
    }

    /// Convert a visibly mounted root back to the covered mountpoint when it
    /// is still the top of that stack.
    ///
    /// Ordinary pathname lookup follows mounts and therefore returns the
    /// current mounted root.  A subsequent mount on the same userspace path
    /// must append to the existing `(parent mount, covered dentry)` stack,
    /// rather than create an artificial child edge at the lower mount's root.
    /// An old dirfd into a covered or detached mount is intentionally left
    /// unchanged: it names that old tree, not today's visible mountpoint.
    fn stacking_target(&self, at: &VfsPath) -> VfsResult<VfsPath> {
        self.ensure_owned_path(at)?;
        if at.mount().id() == self.root.id() || !Arc::ptr_eq(at.dentry(), at.mount().root()) {
            return Ok(at.clone());
        }
        let (parent, covered) = {
            let relation_guard = at.mount().relation.read();
            let Some(relation) = relation_guard.as_ref() else {
                return Ok(at.clone());
            };
            let Some(parent) = relation.parent.upgrade() else {
                return Ok(at.clone());
            };
            (parent, Arc::clone(&relation.covered))
        };
        let point = MountPoint {
            parent_mount_id: parent.id(),
            dentry_id: covered.id(),
        };
        let is_top = self
            .graph
            .read()
            .edges
            .get(&point)
            .and_then(|stack| stack.last())
            .is_some_and(|top| top.id() == at.mount().id());
        Ok(if is_top {
            VfsPath::new(parent, covered)
        } else {
            at.clone()
        })
    }

    /// Build every relation first, then publish the complete cloned tree with
    /// one graph write lock.  The source snapshot may belong to another live
    /// namespace retained by a pinned dirfd.
    fn graft_recursive_bind_tree(
        self: &Arc<Self>,
        at: &VfsPath,
        source: &VfsPath,
        flags: VfsMountFlags,
        root_propagation: VfsMountPropagation,
        source_edges: &BTreeMap<MountPoint, Vec<Arc<VfsMount>>>,
    ) -> VfsResult<Arc<VfsMount>> {
        self.ensure_owned_path(at)?;
        let root = VfsMount::new_bind(self.id, Arc::downgrade(self), source, flags);
        root.set_propagation(root_propagation);
        *root.relation.write() = Some(MountRelation {
            parent: Arc::downgrade(at.mount()),
            covered: Arc::clone(at.dentry()),
        });

        let mut new_edges: BTreeMap<MountPoint, Vec<Arc<VfsMount>>> = BTreeMap::new();
        new_edges
            .entry(MountPoint {
                parent_mount_id: at.mount().id(),
                dentry_id: at.dentry().id(),
            })
            .or_default()
            .push(Arc::clone(&root));

        let mut pending = alloc::vec![(
            Arc::clone(source.mount()),
            Arc::clone(&root),
            Some(Arc::clone(source.dentry())),
        )];
        while let Some((old_parent, new_parent, first_level_root)) = pending.pop() {
            for (point, stack) in source_edges {
                if point.parent_mount_id != old_parent.id() {
                    continue;
                }
                for old_child in stack {
                    let relation = old_child.relation.read();
                    let covered = relation
                        .as_ref()
                        .filter(|relation| {
                            relation
                                .parent
                                .upgrade()
                                .is_some_and(|parent| parent.id() == old_parent.id())
                        })
                        .map(|relation| Arc::clone(&relation.covered))
                        .ok_or(VfsError::Invalid)?;
                    drop(relation);
                    if first_level_root.as_ref().is_some_and(|root_dentry| {
                        dentry_relative_names(root_dentry, &covered).is_none()
                    }) {
                        continue;
                    }
                    // MS_BIND cannot clone an unbindable root.  For MS_REC,
                    // Linux prunes unbindable child subtrees instead of
                    // manufacturing a path through them.
                    if old_child.propagation() == VfsMountPropagation::Unbindable {
                        continue;
                    }
                    let child = old_child.clone_for_namespace(self.id, Arc::downgrade(self));
                    *child.relation.write() = Some(MountRelation {
                        parent: Arc::downgrade(&new_parent),
                        covered: Arc::clone(&covered),
                    });
                    new_edges
                        .entry(MountPoint {
                            parent_mount_id: new_parent.id(),
                            dentry_id: covered.id(),
                        })
                        .or_default()
                        .push(Arc::clone(&child));
                    pending.push((old_child.clone(), child, None));
                }
            }
        }

        let mut graph = self.graph.write();
        for (point, stack) in new_edges {
            graph.edges.entry(point).or_default().extend(stack);
        }
        Ok(root)
    }

    fn ensure_owned_path(&self, path: &VfsPath) -> VfsResult<()> {
        (path.mount().namespace_id == self.id)
            .then_some(())
            .ok_or(VfsError::CrossDevice)
    }

    fn attach(&self, at: &VfsPath, mount: &Arc<VfsMount>) -> VfsResult<()> {
        self.ensure_owned_path(at)?;
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
        Ok(())
    }

    /// Compute every peer/slave destination before mutating any graph.  Dentry
    /// lookup can call a backend, so it is intentionally outside graph locks.
    fn propagation_destinations(
        self: &Arc<Self>,
        at: &VfsPath,
    ) -> VfsResult<Vec<PropagationDestination>> {
        let VfsMountPropagation::Shared { peer_group } = at.mount().propagation() else {
            return Ok(alloc::vec![PropagationDestination {
                namespace: Arc::clone(self),
                at: at.clone(),
                child_propagation: VfsMountPropagation::Private,
            }]);
        };
        let relative =
            dentry_relative_names(at.mount().root(), at.dentry()).ok_or(VfsError::Invalid)?;
        let child_peer_group = NEXT_MOUNT_PEER_GROUP_ID.fetch_add(1, Ordering::Relaxed) as u64;
        let mut destinations = BTreeMap::new();
        for namespace in self.propagation_domain.snapshot() {
            for parent in namespace.reachable_mounts() {
                let child_propagation = match parent.propagation() {
                    VfsMountPropagation::Shared {
                        peer_group: candidate,
                    } if candidate == peer_group => VfsMountPropagation::Shared {
                        peer_group: child_peer_group,
                    },
                    VfsMountPropagation::Slave { master_group } if master_group == peer_group => {
                        VfsMountPropagation::Slave {
                            master_group: child_peer_group,
                        }
                    }
                    _ => continue,
                };
                let covered = resolve_relative_dentry(&parent, &relative)?;
                let destination = VfsPath::new(Arc::clone(&parent), covered);
                destinations.insert(
                    (namespace.id, parent.id(), destination.dentry().id()),
                    PropagationDestination {
                        namespace: Arc::clone(&namespace),
                        at: destination,
                        child_propagation,
                    },
                );
            }
        }
        // The domain registry is weak and may be pruned concurrently.  Never
        // lose the caller's local event.
        destinations
            .entry((self.id, at.mount().id(), at.dentry().id()))
            .or_insert_with(|| PropagationDestination {
                namespace: Arc::clone(self),
                at: at.clone(),
                child_propagation: VfsMountPropagation::Shared {
                    peer_group: child_peer_group,
                },
            });
        Ok(destinations.into_values().collect())
    }

    fn reachable_mounts(&self) -> Vec<Arc<VfsMount>> {
        let edges = self.graph.read().edges.clone();
        let mut mounts = BTreeMap::new();
        mounts.insert(self.root.id(), Arc::clone(&self.root));
        loop {
            let before = mounts.len();
            for (point, stack) in &edges {
                if mounts.contains_key(&point.parent_mount_id) {
                    for mount in stack {
                        mounts
                            .entry(mount.id())
                            .or_insert_with(|| Arc::clone(mount));
                    }
                }
            }
            if mounts.len() == before {
                break;
            }
        }
        mounts.into_values().collect()
    }

    /// Snapshot every mount currently reachable from this namespace root.
    /// Callers use object identity and mount flags from this result; pathname
    /// lookup must continue through `PathWalker` rather than scanning it.
    pub fn mounts_snapshot(&self) -> Vec<Arc<VfsMount>> {
        self.reachable_mounts()
    }

    pub fn top_mount_at(&self, at: &VfsPath) -> Option<Arc<VfsMount>> {
        if self.ensure_owned_path(at).is_err() {
            return None;
        }
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

    pub fn follow_mounts(&self, mut path: VfsPath) -> VfsPath {
        while let Some(next) = self.top_mount_at(&path) {
            path = VfsPath::new(Arc::clone(&next), Arc::clone(next.root()));
        }
        path
    }

    /// Resolve either a covered mountpoint or the visible mounted root to the
    /// top mount object operated on by umount/remount/move.
    pub fn mounted_at(&self, at: &VfsPath) -> Option<Arc<VfsMount>> {
        if self.ensure_owned_path(at).is_err() {
            return None;
        }
        if Arc::ptr_eq(at.dentry(), at.mount().root())
            && at.mount().id() != self.root.id()
            && at.mount().relation.read().is_some()
        {
            return Some(Arc::clone(at.mount()));
        }
        self.top_mount_at(at)
    }

    pub fn umount(&self, at: &VfsPath, lazy: bool) -> VfsResult<Arc<VfsMount>> {
        self.umount_with_targets(at, lazy)
            .map(|(mount, _targets)| mount)
    }

    /// Unmount and report every namespace-visible target detached by mount
    /// propagation.  The strings are for mountinfo compatibility only; the
    /// graph mutation itself is entirely object based.
    pub fn umount_with_targets(
        &self,
        at: &VfsPath,
        lazy: bool,
    ) -> VfsResult<(Arc<VfsMount>, Vec<(u64, String)>)> {
        let mount = self.mounted_at(at).ok_or(VfsError::Invalid)?;
        let targets = self.umount_propagation_targets(&mount)?;
        // Check every peer first so normal unmount cannot partially detach a
        // propagation event before discovering a busy peer.
        for target in &targets {
            target
                .owner_namespace()
                .ok_or(VfsError::Invalid)?
                .check_umount_one(target, lazy)?;
        }
        let mut detached_targets = Vec::new();
        for target in &targets {
            let namespace = target.owner_namespace().ok_or(VfsError::Invalid)?;
            let path = VfsPath::new(Arc::clone(target), Arc::clone(target.root()));
            detached_targets.push((namespace.id, namespace.path_string(&path)?));
        }
        for target in &targets {
            target
                .owner_namespace()
                .ok_or(VfsError::Invalid)?
                .detach_one(target)?;
        }
        Ok((mount, detached_targets))
    }

    /// Find mounts that receive an unmount event from the *parent* of
    /// `mount` at the same relative mountpoint.
    ///
    /// A mount being shared does not by itself make detaching that mount
    /// detach all of its bind peers.  Linux's `propagate_umount()` walks
    /// `Propagation(parent(mount))` and looks up a child at the same
    /// mountpoint.  This distinction matters for recursive bind: cloned child
    /// mounts may be peers while their parents live in unrelated private
    /// trees.
    fn umount_propagation_targets(&self, mount: &Arc<VfsMount>) -> VfsResult<Vec<Arc<VfsMount>>> {
        let relation = mount.relation.read();
        let parent = relation
            .as_ref()
            .and_then(|relation| relation.parent.upgrade())
            .ok_or(VfsError::Invalid)?;
        let covered = Arc::clone(&relation.as_ref().expect("checked relation").covered);
        drop(relation);

        let VfsMountPropagation::Shared { peer_group } = parent.propagation() else {
            return Ok(alloc::vec![Arc::clone(mount)]);
        };
        let relative = dentry_relative_names(parent.root(), &covered).ok_or(VfsError::Invalid)?;
        let mut targets = BTreeMap::new();
        for namespace in self.propagation_domain.snapshot() {
            for candidate_parent in namespace.reachable_mounts() {
                let receives_event = matches!(
                    candidate_parent.propagation(),
                    VfsMountPropagation::Shared {
                        peer_group: candidate_group
                    } if candidate_group == peer_group
                ) || matches!(
                    candidate_parent.propagation(),
                    VfsMountPropagation::Slave { master_group }
                        if master_group == peer_group
                );
                if !receives_event {
                    continue;
                }
                let candidate_covered = resolve_relative_dentry(&candidate_parent, &relative)?;
                let candidate_at = VfsPath::new(Arc::clone(&candidate_parent), candidate_covered);
                if let Some(candidate) = namespace.top_mount_at(&candidate_at) {
                    targets.insert((namespace.id, candidate.id()), candidate);
                }
            }
        }
        // The weak propagation-domain registry may be pruned concurrently.
        // The explicitly requested mount must never disappear from the event.
        targets
            .entry((self.id, mount.id()))
            .or_insert_with(|| Arc::clone(mount));
        Ok(targets.into_values().collect())
    }

    fn check_umount_one(&self, mount: &Arc<VfsMount>, lazy: bool) -> VfsResult<()> {
        let relation = mount.relation.read();
        let parent = relation
            .as_ref()
            .and_then(|relation| relation.parent.upgrade())
            .ok_or(VfsError::Invalid)?;
        let covered = Arc::clone(&relation.as_ref().expect("checked relation").covered);
        drop(relation);
        let point = MountPoint {
            parent_mount_id: parent.id(),
            dentry_id: covered.id(),
        };

        let graph = self.graph.read();
        let stack = graph.edges.get(&point).ok_or(VfsError::Invalid)?;
        if stack.last().is_none_or(|top| top.id() != mount.id()) {
            return Err(VfsError::Invalid);
        }
        if !lazy {
            if mount.pin_count() != 0 {
                return Err(VfsError::Busy);
            }
            if graph
                .edges
                .keys()
                .any(|child| child.parent_mount_id == mount.id())
            {
                return Err(VfsError::Busy);
            }
        }
        Ok(())
    }

    fn detach_one(&self, mount: &Arc<VfsMount>) -> VfsResult<()> {
        let relation = mount.relation.read();
        let parent = relation
            .as_ref()
            .and_then(|relation| relation.parent.upgrade())
            .ok_or(VfsError::Invalid)?;
        let covered = Arc::clone(&relation.as_ref().expect("checked relation").covered);
        drop(relation);
        let point = MountPoint {
            parent_mount_id: parent.id(),
            dentry_id: covered.id(),
        };
        let mut graph = self.graph.write();
        let stack = graph.edges.get_mut(&point).ok_or(VfsError::Invalid)?;
        if stack.last().is_none_or(|top| top.id() != mount.id()) {
            return Err(VfsError::Invalid);
        }
        let detached = stack.pop().expect("checked non-empty mount stack");
        if stack.is_empty() {
            graph.edges.remove(&point);
        }
        // The detached tree keeps its internal child relations, but its root
        // no longer has a namespace parent.  Therefore `..` cannot escape.
        *detached.relation.write() = None;
        Ok(())
    }

    pub fn remount(&self, at: &VfsPath, flags: VfsMountFlags) -> VfsResult<()> {
        let mount =
            if at.mount().id() == self.root.id() && Arc::ptr_eq(at.dentry(), self.root.root()) {
                Arc::clone(&self.root)
            } else {
                self.mounted_at(at).ok_or(VfsError::Invalid)?
            };
        mount.set_flags(flags);
        Ok(())
    }

    pub fn move_mount(&self, from: &VfsPath, to: &VfsPath) -> VfsResult<()> {
        let to = self.stacking_target(to)?;
        self.ensure_owned_path(&to)?;
        let moving = self.mounted_at(from).ok_or(VfsError::Invalid)?;
        if mount_descends_from(to.mount(), &moving) {
            return Err(VfsError::Invalid);
        }
        let old_relation = moving.relation.read();
        let old_parent = old_relation
            .as_ref()
            .and_then(|relation| relation.parent.upgrade())
            .ok_or(VfsError::Invalid)?;
        let old_covered = Arc::clone(&old_relation.as_ref().expect("checked relation").covered);
        drop(old_relation);
        let from_point = MountPoint {
            parent_mount_id: old_parent.id(),
            dentry_id: old_covered.id(),
        };
        let to_point = MountPoint {
            parent_mount_id: to.mount().id(),
            dentry_id: to.dentry().id(),
        };

        let mut graph = self.graph.write();
        let source_stack = graph.edges.get_mut(&from_point).ok_or(VfsError::Invalid)?;
        if source_stack
            .last()
            .is_none_or(|top| top.id() != moving.id())
        {
            return Err(VfsError::Invalid);
        }
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

    pub fn set_propagation(&self, at: &VfsPath, propagation: VfsMountPropagation) -> VfsResult<()> {
        let mount =
            if at.mount().id() == self.root.id() && Arc::ptr_eq(at.dentry(), self.root.root()) {
                Arc::clone(&self.root)
            } else {
                self.mounted_at(at).ok_or(VfsError::Invalid)?
            };
        mount.set_propagation(propagation);
        Ok(())
    }

    /// Clone every reachable mount object while sharing filesystem/dentry
    /// objects.  Detached trees are not copied into a new namespace.
    pub fn clone_namespace_with_map(&self) -> VfsMountNamespaceClone {
        let source_edges = self.graph.read().edges.clone();
        let mut originals = BTreeMap::new();
        originals.insert(self.root.id(), Arc::clone(&self.root));
        loop {
            let before = originals.len();
            for (point, stack) in &source_edges {
                if originals.contains_key(&point.parent_mount_id) {
                    for mount in stack {
                        originals
                            .entry(mount.id())
                            .or_insert_with(|| Arc::clone(mount));
                    }
                }
            }
            if originals.len() == before {
                break;
            }
        }

        let namespace_id = NEXT_MOUNT_NAMESPACE_ID.fetch_add(1, Ordering::Relaxed) as u64;
        let exported_map = Mutex::new(None);
        let namespace = Arc::new_cyclic(|new_namespace| {
            let mut mounts = BTreeMap::new();
            for (old_id, old_mount) in &originals {
                mounts.insert(
                    *old_id,
                    old_mount.clone_for_namespace(namespace_id, new_namespace.clone()),
                );
            }

            for (old_id, old_mount) in &originals {
                let Some(old_source) = old_mount.bind_source() else {
                    continue;
                };
                let source_mount = mounts
                    .get(&old_source.mount().id())
                    .cloned()
                    .unwrap_or_else(|| Arc::clone(old_source.mount()));
                *mounts
                    .get(old_id)
                    .expect("cloned mount missing")
                    .bind_source
                    .write() = Some(VfsPath::new(source_mount, Arc::clone(old_source.dentry())));
            }

            let mut cloned_edges = BTreeMap::new();
            for (point, stack) in &source_edges {
                let Some(parent) = mounts.get(&point.parent_mount_id) else {
                    continue;
                };
                let mut cloned_stack = Vec::new();
                for old_child in stack {
                    let Some(child) = mounts.get(&old_child.id()).cloned() else {
                        continue;
                    };
                    let covered = old_child
                        .relation
                        .read()
                        .as_ref()
                        .map(|relation| Arc::clone(&relation.covered))
                        .expect("reachable child mount lacks a parent relation");
                    *child.relation.write() = Some(MountRelation {
                        parent: Arc::downgrade(parent),
                        covered,
                    });
                    cloned_stack.push(child);
                }
                if !cloned_stack.is_empty() {
                    cloned_edges.insert(
                        MountPoint {
                            parent_mount_id: parent.id(),
                            dentry_id: point.dentry_id,
                        },
                        cloned_stack,
                    );
                }
            }

            *exported_map.lock() = Some(mounts.clone());
            Self {
                id: namespace_id,
                root: mounts
                    .get(&self.root.id())
                    .cloned()
                    .expect("cloned root mount missing"),
                graph: RwLock::new(MountGraph {
                    edges: cloned_edges,
                }),
                propagation_domain: Arc::clone(&self.propagation_domain),
            }
        });
        self.propagation_domain.register(&namespace);
        let mounts = exported_map
            .into_inner()
            .expect("namespace clone did not export its mount map");
        VfsMountNamespaceClone { namespace, mounts }
    }

    pub fn clone_namespace(&self) -> Arc<Self> {
        self.clone_namespace_with_map().into_namespace()
    }

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

    /// Reconstruct the namespace-visible absolute name of a connected path.
    /// This is for getcwd/proc display only; lookup never reparses this string.
    pub fn path_string(&self, path: &VfsPath) -> VfsResult<String> {
        self.ensure_owned_path(path)?;
        let mut mount = Arc::clone(path.mount());
        let mut dentry = Arc::clone(path.dentry());
        let mut names = Vec::new();
        loop {
            while !Arc::ptr_eq(&dentry, mount.root()) {
                if dentry.name().is_empty() {
                    return Err(VfsError::Invalid);
                }
                names.push(dentry.name().to_string());
                dentry = dentry.parent().ok_or(VfsError::NoEntry)?;
            }
            if mount.id() == self.root.id() {
                break;
            }
            let relation = mount.relation.read();
            let parent = relation
                .as_ref()
                .and_then(|relation| relation.parent.upgrade())
                .ok_or(VfsError::NoEntry)?;
            dentry = Arc::clone(&relation.as_ref().expect("checked relation").covered);
            drop(relation);
            mount = parent;
        }
        names.reverse();
        if names.is_empty() {
            Ok(String::from("/"))
        } else {
            Ok(alloc::format!("/{}", names.join("/")))
        }
    }
}

fn dentry_relative_names(root: &Arc<Dentry>, target: &Arc<Dentry>) -> Option<Vec<String>> {
    let mut names = Vec::new();
    let mut current = Arc::clone(target);
    loop {
        if Arc::ptr_eq(&current, root) {
            names.reverse();
            return Some(names);
        }
        names.push(current.name().to_string());
        current = current.parent()?;
    }
}

fn resolve_relative_dentry(mount: &Arc<VfsMount>, relative: &[String]) -> VfsResult<Arc<Dentry>> {
    let mut current = Arc::clone(mount.root());
    for name in relative {
        current = mount.filesystem().dentry_cache().lookup(&current, name)?;
    }
    Ok(current)
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
