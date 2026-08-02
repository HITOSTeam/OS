//! Internal namespace filesystem.
//!
//! Linux exposes `/proc/<pid>/ns/*` as magic links into a kernel-mounted
//! `nsfs`, not as reparsed strings such as `mnt:[id]`.  This compact backend
//! keeps the same object/lifetime boundary: namespace nodes are stashed by
//! identity, procfs returns their `VfsPath`, and opening one retains the
//! underlying namespace descriptor.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;
use spin::RwLock;

use super::vfs::{
    VfsDirEntry, VfsError, VfsFileOperations, VfsFileSystem, VfsFileSystemState, VfsMetadata,
    VfsMountNamespace, VfsNode, VfsNodeKind, VfsOpenOptions, VfsPath, VfsResult, VfsStatFs,
    VfsTimes,
};
use super::{File, NamespaceFile, VfsOpenedFile};

const NSFS_MAGIC: u64 = 0x6e73_6673;
static NEXT_NSFS_ID: AtomicUsize = AtomicUsize::new(0x30_000);

struct NsFsMount {
    filesystem: Arc<NsFs>,
    namespace: Arc<VfsMountNamespace>,
}

impl NsFsMount {
    fn new() -> Self {
        let filesystem = NsFs::new();
        let namespace = VfsMountNamespace::new(Arc::clone(&filesystem) as Arc<dyn VfsFileSystem>);
        Self {
            filesystem,
            namespace,
        }
    }

    fn path_for(&self, file: Arc<NamespaceFile>) -> VfsResult<VfsPath> {
        let name = alloc::format!("{}-{}", file.kind().proc_name(), file.ns_id());
        let node = self.filesystem.stash(&name, file);
        let root = self.filesystem.root_dentry();
        // Keep the freshly installed node alive until lookup has converted it
        // into a positive dentry.
        let dentry = self.filesystem.dentry_cache().lookup(&root, &name)?;
        drop(node);
        let root_path = self.namespace.root_path();
        Ok(VfsPath::new(Arc::clone(root_path.mount()), dentry))
    }
}

lazy_static! {
    static ref NSFS_MOUNT: NsFsMount = NsFsMount::new();
}

/// Return the stashed nsfs object corresponding to one namespace descriptor.
pub(crate) fn namespace_path(file: Arc<NamespaceFile>) -> VfsResult<VfsPath> {
    NSFS_MOUNT.path_for(file)
}

/// Extract a namespace descriptor from either the transitional direct file or
/// an object-VFS file opened through nsfs.
pub(crate) fn namespace_file_from_open_file(
    file: &Arc<dyn File + Send + Sync>,
) -> Option<&NamespaceFile> {
    if let Some(namespace) = file.as_any().downcast_ref::<NamespaceFile>() {
        return Some(namespace);
    }
    let opened = file.as_any().downcast_ref::<VfsOpenedFile>()?;
    opened
        .description()
        .operations()
        .as_any()
        .downcast_ref::<NsFileOperations>()
        .map(|operations| operations.namespace.as_ref())
}

struct NsFs {
    id: u64,
    vfs_state: VfsFileSystemState,
    nodes: RwLock<BTreeMap<String, Weak<NsNode>>>,
}

impl NsFs {
    fn new() -> Arc<Self> {
        let id = NEXT_NSFS_ID.fetch_add(1, Ordering::Relaxed) as u64;
        Arc::new_cyclic(|weak_fs| {
            let root = Arc::new(NsRootNode {
                fs: weak_fs.clone(),
            });
            Self {
                id,
                vfs_state: VfsFileSystemState::new(root as Arc<dyn VfsNode>),
                nodes: RwLock::new(BTreeMap::new()),
            }
        })
    }

    fn stash(self: &Arc<Self>, name: &str, file: Arc<NamespaceFile>) -> Arc<NsNode> {
        if let Some(node) = self.nodes.read().get(name).and_then(Weak::upgrade) {
            return node;
        }
        let node = Arc::new(NsNode {
            fs: Arc::downgrade(self),
            namespace: file,
            created_ns: crate::time::get_realtime_ns(),
        });
        let mut nodes = self.nodes.write();
        if let Some(existing) = nodes.get(name).and_then(Weak::upgrade) {
            return existing;
        }
        nodes.insert(String::from(name), Arc::downgrade(&node));
        node
    }
}

impl VfsFileSystem for NsFs {
    fn filesystem_id(&self) -> u64 {
        self.id
    }

    fn filesystem_type(&self) -> &'static str {
        "nsfs"
    }

    fn vfs_state(&self) -> &VfsFileSystemState {
        &self.vfs_state
    }

    fn statfs(&self) -> VfsResult<VfsStatFs> {
        Ok(VfsStatFs {
            magic: NSFS_MAGIC,
            block_size: 1024,
            blocks: 0,
            blocks_free: 0,
            blocks_available: 0,
            files: 0,
            files_free: 0,
            name_len: 255,
        })
    }

    fn sync(&self) -> VfsResult<()> {
        Ok(())
    }
}

struct NsRootNode {
    fs: Weak<NsFs>,
}

impl VfsNode for NsRootNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn node_id(&self) -> u64 {
        1
    }

    fn filesystem_id(&self) -> u64 {
        self.fs.upgrade().map_or(0, |fs| fs.id)
    }

    fn metadata(&self) -> VfsResult<VfsMetadata> {
        Ok(namespace_metadata(VfsNodeKind::Directory, 0o555, 2, 0))
    }

    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn VfsNode>> {
        if name.is_empty() || name.contains('/') {
            return Err(VfsError::Invalid);
        }
        self.fs
            .upgrade()
            .ok_or(VfsError::Invalid)?
            .nodes
            .read()
            .get(name)
            .and_then(Weak::upgrade)
            .map(|node| node as Arc<dyn VfsNode>)
            .ok_or(VfsError::NoEntry)
    }

    fn readdir(&self) -> VfsResult<Vec<VfsDirEntry>> {
        // nsfs is kernel-mounted and its root is not user-enumerable.
        Ok(Vec::new())
    }
}

struct NsNode {
    fs: Weak<NsFs>,
    namespace: Arc<NamespaceFile>,
    created_ns: u64,
}

impl VfsNode for NsNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn node_id(&self) -> u64 {
        self.namespace.inode_number()
    }

    fn filesystem_id(&self) -> u64 {
        self.fs.upgrade().map_or(0, |fs| fs.id)
    }

    fn metadata(&self) -> VfsResult<VfsMetadata> {
        Ok(namespace_metadata(
            VfsNodeKind::Regular,
            0o444,
            1,
            self.created_ns,
        ))
    }

    fn open(self: Arc<Self>, options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        if options.writable {
            return Err(VfsError::Access);
        }
        Ok(Arc::new(NsFileOperations {
            namespace: Arc::clone(&self.namespace),
        }))
    }
}

struct NsFileOperations {
    namespace: Arc<NamespaceFile>,
}

impl VfsFileOperations for NsFileOperations {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }
}

fn namespace_metadata(kind: VfsNodeKind, mode: u16, nlink: u32, timestamp: u64) -> VfsMetadata {
    VfsMetadata {
        kind,
        mode,
        uid: 0,
        gid: 0,
        nlink,
        size: 0,
        rdev: 0,
        times: VfsTimes {
            access_ns: timestamp,
            modify_ns: timestamp,
            change_ns: timestamp,
        },
    }
}
