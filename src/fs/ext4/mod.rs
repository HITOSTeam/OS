//! ext4 adapter for the object-based VFS.

use crate::fs::inode::{Ext4InodeLock, ext4_inode_lock};
use crate::fs::vfs::{
    DentryCachePolicy, VfsDirEntry, VfsError, VfsFileOperations, VfsFileSystem, VfsFileSystemState,
    VfsLink, VfsMetadata, VfsNode, VfsNodeKind, VfsOpenOptions, VfsResult, VfsStatFs, VfsTimes,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use ext4_fs::{Ext4Error, Inode};
use lazy_static::lazy_static;
use spin::Mutex;

const EXT4_SUPER_MAGIC: u64 = 0xef53;

lazy_static! {
    /// One VFS superblock object per ext4 block device.  Repeated mounts and
    /// mount-namespace clones share its stable root dentry and dcache, like
    /// Linux reusing a `super_block` for the same mounted block device.
    static ref EXT4_VFS_INSTANCES: Mutex<BTreeMap<usize, Weak<Ext4Vfs>>> =
        Mutex::new(BTreeMap::new());
}

pub struct Ext4Vfs {
    filesystem_id: u64,
    root: Arc<Inode>,
    vfs_state: VfsFileSystemState,
}

impl Ext4Vfs {
    pub fn new(root: Arc<Inode>) -> Arc<Self> {
        let device_id = root.device_id();
        let mut instances = EXT4_VFS_INSTANCES.lock();
        if let Some(filesystem) = instances.get(&device_id).and_then(Weak::upgrade) {
            return filesystem;
        }
        let filesystem_id = root.device_id() as u64 + 1;
        let root_node = Arc::new(Ext4VfsNode::new(filesystem_id, Arc::clone(&root)));
        let filesystem = Arc::new(Self {
            filesystem_id,
            root,
            vfs_state: VfsFileSystemState::new(root_node as Arc<dyn VfsNode>),
        });
        instances.retain(|_, filesystem| filesystem.strong_count() != 0);
        instances.insert(device_id, Arc::downgrade(&filesystem));
        filesystem
    }
}

impl VfsFileSystem for Ext4Vfs {
    fn filesystem_id(&self) -> u64 {
        self.filesystem_id
    }

    fn filesystem_type(&self) -> &'static str {
        "ext4"
    }

    fn vfs_state(&self) -> &VfsFileSystemState {
        &self.vfs_state
    }

    fn statfs(&self) -> VfsResult<VfsStatFs> {
        let stat = self.root.filesystem_stat_snapshot();
        Ok(VfsStatFs {
            magic: EXT4_SUPER_MAGIC,
            block_size: stat.block_size,
            blocks: stat.blocks,
            blocks_free: stat.blocks_free,
            blocks_available: stat.blocks_available,
            files: stat.files,
            files_free: stat.files_free,
            name_len: 255,
        })
    }

    fn sync(&self) -> VfsResult<()> {
        ext4_fs::sync_all();
        Ok(())
    }
}

pub struct Ext4VfsNode {
    filesystem_id: u64,
    inode: Arc<Inode>,
    inode_lock: Arc<Ext4InodeLock>,
}

impl Ext4VfsNode {
    fn new(filesystem_id: u64, inode: Arc<Inode>) -> Self {
        let inode_lock = ext4_inode_lock(&inode);
        Self {
            filesystem_id,
            inode,
            inode_lock,
        }
    }

    pub fn inode(&self) -> &Arc<Inode> {
        &self.inode
    }

    fn wrap(&self, inode: Arc<Inode>) -> Arc<dyn VfsNode> {
        Arc::new(Self::new(self.filesystem_id, inode))
    }
}

impl VfsNode for Ext4VfsNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn node_id(&self) -> u64 {
        self.inode.inode_num() as u64
    }

    fn filesystem_id(&self) -> u64 {
        self.filesystem_id
    }

    fn metadata(&self) -> VfsResult<VfsMetadata> {
        let snapshot = {
            let _inode_guard = self.inode_lock.read();
            self.inode.stat_snapshot()
        };
        Ok(VfsMetadata {
            kind: inode_kind(&self.inode),
            mode: snapshot.mode & 0o7777,
            uid: snapshot.uid,
            gid: snapshot.gid,
            nlink: snapshot.nlink,
            size: snapshot.size,
            rdev: snapshot.rdev_for_mode(),
            // ext4-fs does not expose timestamp fields yet.  Keeping this
            // explicit prevents the adapter from inventing wall-clock values.
            times: VfsTimes::default(),
        })
    }

    fn dentry_cache_policy(&self) -> DentryCachePolicy {
        // ext4 mutations can also arrive through the legacy syscall adapter
        // during migration, so cached positives must be revalidated.
        DentryCachePolicy::Revalidate
    }

    fn lookup(&self, name: &str) -> VfsResult<Arc<dyn VfsNode>> {
        if name.is_empty() || name.contains('/') {
            return Err(VfsError::Invalid);
        }
        let inode = {
            let _inode_guard = self.inode_lock.read();
            if !self.inode.is_dir() {
                return Err(VfsError::NotDirectory);
            }
            self.inode.find(name).ok_or(VfsError::NoEntry)?
        };
        Ok(self.wrap(inode))
    }

    fn readdir(&self) -> VfsResult<Vec<VfsDirEntry>> {
        let entries = {
            let _inode_guard = self.inode_lock.read();
            if !self.inode.is_dir() {
                return Err(VfsError::NotDirectory);
            }
            self.inode.dir_entries()
        };
        let mut output = Vec::with_capacity(entries.len());
        for (name, inode_num, _) in entries {
            let kind = {
                let _inode_guard = self.inode_lock.read();
                self.inode
                    .find(&name)
                    .map(|inode| inode_kind(&inode))
                    .unwrap_or(VfsNodeKind::Regular)
            };
            output.push(VfsDirEntry {
                name,
                node_id: inode_num as u64,
                kind,
            });
        }
        Ok(output)
    }

    fn readlink(&self) -> VfsResult<VfsLink> {
        let size = {
            let _inode_guard = self.inode_lock.read();
            if !self.inode.is_symlink() {
                return Err(VfsError::Invalid);
            }
            self.inode.size() as usize
        };
        let mut bytes = vec![0; size];
        let read = {
            let _inode_guard = self.inode_lock.read();
            self.inode.read_at(0, &mut bytes)
        };
        bytes.truncate(read);
        let target = core::str::from_utf8(&bytes).map_err(|_| VfsError::Invalid)?;
        Ok(VfsLink::Text(String::from(target)))
    }

    fn open(self: Arc<Self>, options: VfsOpenOptions) -> VfsResult<Arc<dyn VfsFileOperations>> {
        Ok(Arc::new(Ext4VfsFile {
            inode: Arc::clone(&self.inode),
            inode_lock: Arc::clone(&self.inode_lock),
            readable: options.readable,
            writable: options.writable,
        }))
    }

    fn create(&self, name: &str, mode: u16) -> VfsResult<Arc<dyn VfsNode>> {
        let inode = {
            let _inode_guard = self.inode_lock.write();
            let inode = self.inode.create_file(name).map_err(map_ext4_error)?;
            inode.set_mode(mode);
            inode
        };
        Ok(self.wrap(inode))
    }

    fn mkdir(&self, name: &str, mode: u16) -> VfsResult<Arc<dyn VfsNode>> {
        let inode = {
            let _inode_guard = self.inode_lock.write();
            let inode = self.inode.create_dir(name).map_err(map_ext4_error)?;
            inode.set_mode(mode);
            inode
        };
        Ok(self.wrap(inode))
    }

    fn symlink(&self, name: &str, target: &str) -> VfsResult<Arc<dyn VfsNode>> {
        let inode = {
            let _inode_guard = self.inode_lock.write();
            self.inode
                .create_symlink(name, target)
                .map_err(map_ext4_error)?
        };
        Ok(self.wrap(inode))
    }

    fn link(&self, name: &str, target: &Arc<dyn VfsNode>) -> VfsResult<()> {
        let target = target
            .as_any()
            .downcast_ref::<Ext4VfsNode>()
            .ok_or(VfsError::CrossDevice)?;
        if target.filesystem_id != self.filesystem_id {
            return Err(VfsError::CrossDevice);
        }
        // Linux forbids hard-linking directories before taking the target
        // inode's exclusive lock.  Besides matching EPERM semantics, this
        // avoids recursively taking the same i_rwsem when `target` is this
        // parent directory.
        if target.inode.is_dir() {
            return Err(VfsError::Access);
        }
        let _parent_guard = self.inode_lock.write();
        let _target_guard = target.inode_lock.write();
        self.inode
            .link_inode(name, &target.inode)
            .map_err(map_ext4_error)
    }

    fn unlink(&self, name: &str, remove_dir: bool) -> VfsResult<()> {
        if matches!(name, "." | "..") {
            return Err(VfsError::Invalid);
        }
        let _parent_guard = self.inode_lock.write();
        let child = self.inode.find(name).ok_or(VfsError::NoEntry)?;
        let child_lock = ext4_inode_lock(&child);
        let _child_guard = child_lock.write();
        if child.is_dir() != remove_dir {
            return Err(if child.is_dir() {
                VfsError::IsDirectory
            } else {
                VfsError::NotDirectory
            });
        }
        self.inode.unlink(name).map_err(map_ext4_error)
    }

    fn rename(
        &self,
        old_name: &str,
        new_parent: &Arc<dyn VfsNode>,
        new_name: &str,
    ) -> VfsResult<()> {
        let new_parent = new_parent
            .as_any()
            .downcast_ref::<Ext4VfsNode>()
            .ok_or(VfsError::CrossDevice)?;
        if new_parent.filesystem_id != self.filesystem_id {
            return Err(VfsError::CrossDevice);
        }
        if matches!(old_name, "." | "..") || matches!(new_name, "." | "..") {
            return Err(VfsError::Invalid);
        }
        if new_parent.node_id() != self.node_id() {
            // ext4-fs currently exposes atomic same-directory rename only.
            return Err(VfsError::NotSupported);
        }
        let _parent_guard = self.inode_lock.write();
        let source = self.inode.find(old_name).ok_or(VfsError::NoEntry)?;
        let source_lock = ext4_inode_lock(&source);
        let _source_guard = source_lock.write();
        self.inode
            .rename(old_name, new_name)
            .map_err(map_ext4_error)
    }

    fn truncate(&self, size: u64) -> VfsResult<()> {
        if size != 0 {
            return Err(VfsError::NotSupported);
        }
        let _inode_guard = self.inode_lock.write();
        self.inode.clear().map_err(map_ext4_error)
    }

    fn mknod(
        &self,
        name: &str,
        kind: VfsNodeKind,
        mode: u16,
        rdev: u64,
    ) -> VfsResult<Arc<dyn VfsNode>> {
        let type_mode = match kind {
            VfsNodeKind::Fifo => 0o010000,
            VfsNodeKind::CharacterDevice => 0o020000,
            VfsNodeKind::BlockDevice => 0o060000,
            VfsNodeKind::Socket => 0o140000,
            _ => return Err(VfsError::Invalid),
        };
        let inode = {
            let _inode_guard = self.inode_lock.write();
            self.inode
                .create_special(name, type_mode | (mode & 0o7777), rdev)
                .map_err(map_ext4_error)?
        };
        Ok(self.wrap(inode))
    }

    fn set_mode(&self, mode: u16) -> VfsResult<()> {
        let _inode_guard = self.inode_lock.write();
        self.inode.set_mode(mode);
        Ok(())
    }

    fn set_owner(&self, uid: u32, gid: u32) -> VfsResult<()> {
        let _inode_guard = self.inode_lock.write();
        self.inode.set_uid_gid(uid, gid);
        Ok(())
    }

    fn set_mode_owner(&self, mode: u16, uid: u32, gid: u32) -> VfsResult<()> {
        let _inode_guard = self.inode_lock.write();
        self.inode.set_uid_gid(uid, gid);
        self.inode.set_mode(mode & 0o7777);
        Ok(())
    }
}

/// Stateless opened ext4 operations.  The legacy `OSInode` keeps its cursor
/// for online syscalls during migration; the object VFS does not wrap it and
/// therefore cannot acquire a second authoritative position.
struct Ext4VfsFile {
    inode: Arc<Inode>,
    inode_lock: Arc<Ext4InodeLock>,
    readable: bool,
    writable: bool,
}

impl VfsFileOperations for Ext4VfsFile {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> VfsResult<usize> {
        if !self.readable {
            return Err(VfsError::Access);
        }
        let offset = usize::try_from(offset).map_err(|_| VfsError::Invalid)?;
        let _guard = self.inode_lock.read();
        Ok(self.inode.read_at(offset, output))
    }

    fn write_at(&self, offset: u64, input: &[u8]) -> VfsResult<usize> {
        if !self.writable {
            return Err(VfsError::Access);
        }
        let offset = usize::try_from(offset).map_err(|_| VfsError::Invalid)?;
        let _guard = self.inode_lock.write();
        self.inode.write_at(offset, input).map_err(map_ext4_error)
    }

    fn size(&self) -> VfsResult<u64> {
        let _guard = self.inode_lock.read();
        Ok(self.inode.size() as u64)
    }

    fn append(&self, input: &[u8]) -> VfsResult<(u64, usize)> {
        if !self.writable {
            return Err(VfsError::Access);
        }
        let _guard = self.inode_lock.write();
        let offset = self.inode.size() as u64;
        let written = self
            .inode
            .write_at(offset as usize, input)
            .map_err(map_ext4_error)?;
        Ok((offset, written))
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        ext4_fs::sync_all();
        Ok(())
    }

    fn sync_range(&self, _offset: u64, _length: u64, _flags: u32) -> VfsResult<()> {
        ext4_fs::sync_all();
        Ok(())
    }

    fn advise(&self, _offset: u64, _length: u64, _advice: u32) -> VfsResult<()> {
        if self.inode.is_file() {
            Ok(())
        } else {
            Err(VfsError::Invalid)
        }
    }
}

fn inode_kind(inode: &Inode) -> VfsNodeKind {
    if inode.is_dir() {
        VfsNodeKind::Directory
    } else if inode.is_symlink() {
        VfsNodeKind::Symlink
    } else if inode.is_fifo() {
        VfsNodeKind::Fifo
    } else if inode.is_chrdev() {
        VfsNodeKind::CharacterDevice
    } else if inode.is_blkdev() {
        VfsNodeKind::BlockDevice
    } else if inode.is_socket() {
        VfsNodeKind::Socket
    } else {
        VfsNodeKind::Regular
    }
}

fn map_ext4_error(error: Ext4Error) -> VfsError {
    match error {
        Ext4Error::NotADirectory => VfsError::NotDirectory,
        Ext4Error::NotAFile => VfsError::IsDirectory,
        Ext4Error::AlreadyExists => VfsError::Exists,
        Ext4Error::NotFound => VfsError::NoEntry,
        Ext4Error::NoSpace => VfsError::NoSpace,
        Ext4Error::NameTooLong => VfsError::NameTooLong,
        Ext4Error::Unsupported => VfsError::NotSupported,
        Ext4Error::InvalidInput => VfsError::Invalid,
    }
}
