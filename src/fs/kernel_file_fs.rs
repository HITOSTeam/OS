//! Kernel-only filesystems for anonymous file objects.
//!
//! Linux gives pipes, sockets, anonymous-inode files, and memfd objects real
//! `struct path` objects on internal `pipefs`, `sockfs`, `anon_inodefs`, and
//! shmem mounts.  Procfs
//! can therefore return `file->f_path` from its magic-link callback without
//! reparsing display strings such as `pipe:[42]`.  This module provides the
//! same small object boundary for the VFS migration: the mounts are never
//! user-mountable, dentries are held weakly, and a returned `VfsPath` pins the
//! underlying legacy file object for exactly as long as the path is live.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
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
use super::{File, MemfdFile};

const PIPEFS_MAGIC: u64 = 0x5049_5045;
const SOCKFS_MAGIC: u64 = 0x534f_434b;
const ANON_INODE_FS_MAGIC: u64 = 0x0904_1934;
const TMPFS_MAGIC: u64 = 0x0102_1994;
static NEXT_KERNEL_FILE_FS_ID: AtomicUsize = AtomicUsize::new(0x40_000);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelFileSystemKind {
    Pipe,
    Socket,
    Anonymous,
    Shmem,
}

impl KernelFileSystemKind {
    fn filesystem_type(self) -> &'static str {
        match self {
            Self::Pipe => "pipefs",
            Self::Socket => "sockfs",
            Self::Anonymous => "anon_inodefs",
            Self::Shmem => "tmpfs",
        }
    }

    fn magic(self) -> u64 {
        match self {
            Self::Pipe => PIPEFS_MAGIC,
            Self::Socket => SOCKFS_MAGIC,
            Self::Anonymous => ANON_INODE_FS_MAGIC,
            Self::Shmem => TMPFS_MAGIC,
        }
    }

    fn mount(self) -> &'static KernelFileMount {
        match self {
            Self::Pipe => &PIPEFS_MOUNT,
            Self::Socket => &SOCKFS_MOUNT,
            Self::Anonymous => &ANONFS_MOUNT,
            Self::Shmem => &SHMEMFS_MOUNT,
        }
    }
}

struct KernelFileMount {
    filesystem: Arc<KernelFileFs>,
    namespace: Arc<VfsMountNamespace>,
}

impl KernelFileMount {
    fn new(kind: KernelFileSystemKind) -> Self {
        let filesystem = KernelFileFs::new(kind);
        let namespace = VfsMountNamespace::new(Arc::clone(&filesystem) as Arc<dyn VfsFileSystem>);
        Self {
            filesystem,
            namespace,
        }
    }

    fn path_for(
        &self,
        file: Arc<dyn File + Send + Sync>,
        node_id: u64,
        node_kind: VfsNodeKind,
    ) -> VfsResult<VfsPath> {
        let pointer = Arc::as_ptr(&file) as *const () as usize;
        let name = alloc::format!("{node_id:x}-{pointer:x}");
        let node = self
            .filesystem
            .stash(&name, file, node_id.max(2), node_kind);
        let root = self.filesystem.root_dentry();
        let dentry = self.filesystem.dentry_cache().lookup(&root, &name)?;
        drop(node);
        let root_path = self.namespace.root_path();
        Ok(VfsPath::new(Arc::clone(root_path.mount()), dentry))
    }
}

lazy_static! {
    static ref PIPEFS_MOUNT: KernelFileMount = KernelFileMount::new(KernelFileSystemKind::Pipe);
    static ref SOCKFS_MOUNT: KernelFileMount = KernelFileMount::new(KernelFileSystemKind::Socket);
    static ref ANONFS_MOUNT: KernelFileMount =
        KernelFileMount::new(KernelFileSystemKind::Anonymous);
    static ref SHMEMFS_MOUNT: KernelFileMount = KernelFileMount::new(KernelFileSystemKind::Shmem);
}

/// Create a path on a kernel-only pseudo mount for an anonymous file.
pub(crate) fn kernel_file_path(
    file: Arc<dyn File + Send + Sync>,
    filesystem_kind: KernelFileSystemKind,
    node_id: u64,
    node_kind: VfsNodeKind,
) -> VfsResult<VfsPath> {
    filesystem_kind.mount().path_for(file, node_id, node_kind)
}

/// Recover the legacy file while descriptor migration is still in progress.
///
/// The pathname is nevertheless a real VFS object.  This narrow adapter only
/// preserves the existing anonymous-file I/O ABI until pipes and sockets use
/// `FileDescription` operations directly.
pub(crate) fn kernel_file_from_path(
    path: &VfsPath,
) -> Option<(KernelFileSystemKind, Arc<dyn File + Send + Sync>)> {
    let node = path.node().as_any().downcast_ref::<KernelFileNode>()?;
    let filesystem_kind = node.fs.upgrade()?.kind;
    Some((filesystem_kind, Arc::clone(&node.file)))
}

struct KernelFileFs {
    id: u64,
    kind: KernelFileSystemKind,
    vfs_state: VfsFileSystemState,
    nodes: RwLock<BTreeMap<String, Weak<KernelFileNode>>>,
}

impl KernelFileFs {
    fn new(kind: KernelFileSystemKind) -> Arc<Self> {
        let id = NEXT_KERNEL_FILE_FS_ID.fetch_add(1, Ordering::Relaxed) as u64;
        Arc::new_cyclic(|weak_fs| {
            let root = Arc::new(KernelFileRootNode {
                fs: weak_fs.clone(),
            });
            Self {
                id,
                kind,
                vfs_state: VfsFileSystemState::new(root as Arc<dyn VfsNode>),
                nodes: RwLock::new(BTreeMap::new()),
            }
        })
    }

    fn stash(
        self: &Arc<Self>,
        name: &str,
        file: Arc<dyn File + Send + Sync>,
        node_id: u64,
        kind: VfsNodeKind,
    ) -> Arc<KernelFileNode> {
        if let Some(node) = self.nodes.read().get(name).and_then(Weak::upgrade) {
            return node;
        }
        let node = Arc::new(KernelFileNode {
            fs: Arc::downgrade(self),
            file,
            node_id,
            kind,
            created_ns: crate::time::get_realtime_ns(),
        });
        let mut nodes = self.nodes.write();
        if let Some(existing) = nodes.get(name).and_then(Weak::upgrade) {
            return existing;
        }
        nodes.insert(name.to_string(), Arc::downgrade(&node));
        node
    }
}

impl VfsFileSystem for KernelFileFs {
    fn filesystem_id(&self) -> u64 {
        self.id
    }

    fn filesystem_type(&self) -> &'static str {
        self.kind.filesystem_type()
    }

    fn vfs_state(&self) -> &VfsFileSystemState {
        &self.vfs_state
    }

    fn statfs(&self) -> VfsResult<VfsStatFs> {
        Ok(VfsStatFs {
            magic: self.kind.magic(),
            block_size: if self.kind == KernelFileSystemKind::Shmem {
                crate::config::PAGE_SIZE as u64
            } else {
                1024
            },
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

struct KernelFileRootNode {
    fs: Weak<KernelFileFs>,
}

impl VfsNode for KernelFileRootNode {
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
        Ok(kernel_file_metadata(VfsNodeKind::Directory, 0o555, 2, 0))
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
        Ok(Vec::new())
    }
}

struct KernelFileNode {
    fs: Weak<KernelFileFs>,
    file: Arc<dyn File + Send + Sync>,
    node_id: u64,
    kind: VfsNodeKind,
    created_ns: u64,
}

impl VfsNode for KernelFileNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn node_id(&self) -> u64 {
        self.node_id
    }

    fn filesystem_id(&self) -> u64 {
        self.fs.upgrade().map_or(0, |fs| fs.id)
    }

    fn metadata(&self) -> VfsResult<VfsMetadata> {
        if self
            .fs
            .upgrade()
            .is_some_and(|fs| fs.kind == KernelFileSystemKind::Shmem)
        {
            let memfd = self
                .file
                .as_any()
                .downcast_ref::<MemfdFile>()
                .ok_or(VfsError::Invalid)?;
            let mut metadata =
                kernel_file_metadata(VfsNodeKind::Regular, 0o777, 0, self.created_ns);
            metadata.size = memfd.len() as u64;
            return Ok(metadata);
        }
        let mode = match self.kind {
            VfsNodeKind::Socket => 0o777,
            _ => 0o600,
        };
        Ok(kernel_file_metadata(self.kind, mode, 1, self.created_ns))
    }

    fn open(self: Arc<Self>, _options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        // Normal opens are handled at the legacy File adapter boundary above
        // this node. O_PATH never calls VfsNode::open.
        Err(VfsError::NotSupported)
    }
}

fn kernel_file_metadata(kind: VfsNodeKind, mode: u16, nlink: u32, timestamp: u64) -> VfsMetadata {
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
