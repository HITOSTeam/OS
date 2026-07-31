//! ext4 adapter for the object-based VFS.

use crate::fs::inode::{Ext4InodeLock, OSInode, ext4_inode_lock};
use crate::fs::vfs::{
    DentryCachePolicy, VfsDirEntry, VfsError, VfsFileSystem, VfsLink, VfsMetadata, VfsNode,
    VfsNodeKind, VfsOpenOptions, VfsResult, VfsStatFs, VfsTimes,
};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use ext4_fs::{Ext4Error, Inode};

const EXT4_SUPER_MAGIC: u64 = 0xef53;

pub struct Ext4Vfs {
    filesystem_id: u64,
    root: Arc<Inode>,
}

impl Ext4Vfs {
    pub fn new(root: Arc<Inode>) -> Arc<Self> {
        Arc::new(Self {
            filesystem_id: root.device_id() as u64 + 1,
            root,
        })
    }
}

impl VfsFileSystem for Ext4Vfs {
    fn filesystem_id(&self) -> u64 {
        self.filesystem_id
    }

    fn filesystem_type(&self) -> &'static str {
        "ext4"
    }

    fn root_node(&self) -> Arc<dyn VfsNode> {
        Arc::new(Ext4VfsNode::new(self.filesystem_id, Arc::clone(&self.root)))
    }

    fn statfs(&self) -> VfsResult<VfsStatFs> {
        Ok(VfsStatFs {
            magic: EXT4_SUPER_MAGIC,
            block_size: self.root.block_size() as u64,
            name_len: 255,
            ..VfsStatFs::default()
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

    fn open(
        self: Arc<Self>,
        options: VfsOpenOptions,
    ) -> VfsResult<Arc<dyn crate::fs::File + Send + Sync>> {
        OSInode::new_with_append(
            options.readable,
            options.writable,
            options.append,
            Arc::clone(&self.inode),
        )
        .map(|file| Arc::new(file) as Arc<dyn crate::fs::File + Send + Sync>)
        .map_err(|_| VfsError::Invalid)
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
