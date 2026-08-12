//! Adapter from an object-VFS open file description to the kernel `File` ABI.
//!
//! The object model deliberately stays independent from user-memory handling.
//! This adapter is the narrow boundary that copies `UserBuffer` segments and
//! preserves Linux's shared `struct file` position across dup/fork/SCM_RIGHTS.

use crate::fs::vfs::{
    FileDescription, PinnedPath, VFS_STATUS_APPEND, VfsError, VfsFileOperations, VfsMetadata,
    VfsNodeKind, VfsOpenOptions, VfsPath, VfsResult,
};
use crate::fs::{File, POLLIN, POLLOUT, PathFileDescription};
use crate::mm::UserBuffer;
use crate::task::task_block::TaskControlBlock;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

/// Operations used by `O_PATH`, which pins a path without opening the node for
/// data I/O.  Linux gives these descriptors path-only file operations too.
struct PathOnlyOperations;

impl VfsFileOperations for PathOnlyOperations {
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

/// Kernel-facing file object backed by one shared VFS file description.
pub(crate) struct VfsOpenedFile {
    description: Arc<FileDescription>,
    kind: VfsNodeKind,
    logical_path: String,
}

/// Give a legacy kernel `File` the resolved path owned by this open.
///
/// Linux stores `f_path` in `struct file`, including for named FIFOs and
/// device nodes whose I/O methods are implemented by another object.  During
/// the VFS migration those backends still implement the older `File` trait,
/// so this narrow adapter keeps the mount+dentry pin next to the shared open
/// file description instead of in a parallel fd-table column.  `as_any()` is
/// deliberately forwarded so existing ioctl, pipe and inode downcasts retain
/// their behaviour.
struct PathPinnedFile {
    path: PinnedPath,
    logical_path: String,
    backing: Arc<dyn File + Send + Sync>,
}

/// Attach a resolved object path to one pathname-backed legacy open.
pub(crate) fn pin_legacy_file_path(
    backing: Arc<dyn File + Send + Sync>,
    path: VfsPath,
    logical_path: &str,
) -> Arc<dyn File + Send + Sync> {
    if backing.object_path().is_some() {
        return backing;
    }
    Arc::new(PathPinnedFile {
        path: PinnedPath::new(path),
        logical_path: String::from(logical_path),
        backing,
    })
}

impl File for PathPinnedFile {
    fn readable(&self) -> bool {
        self.backing.readable()
    }

    fn writable(&self) -> bool {
        self.backing.writable()
    }

    fn read(&self, buffer: UserBuffer) -> usize {
        self.backing.read(buffer)
    }

    fn write(&self, buffer: UserBuffer) -> usize {
        self.backing.write(buffer)
    }

    fn poll_mask(&self) -> i16 {
        self.backing.poll_mask()
    }

    fn fixed_poll_mask(&self) -> Option<i16> {
        self.backing.fixed_poll_mask()
    }

    fn supports_poll(&self) -> bool {
        self.backing.supports_poll()
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        self.backing.register_poll_waiter(task)
    }

    fn on_fd_install(&self) {
        self.backing.on_fd_install();
    }

    fn on_fd_close(&self) {
        self.backing.on_fd_close();
    }

    fn object_path(&self) -> Option<&VfsPath> {
        Some(self.path.path())
    }

    fn logical_path_hint(&self) -> Option<&str> {
        Some(&self.logical_path)
    }

    fn path_file(&self) -> Option<&dyn PathFileDescription> {
        self.backing.path_file()
    }

    fn as_any(&self) -> &dyn Any {
        self.backing.as_any()
    }
}

impl VfsOpenedFile {
    /// Open `path` and create exactly one shared file-description object.
    pub(crate) fn open(
        path: VfsPath,
        logical_path: String,
        options: VfsOpenOptions,
        path_only: bool,
    ) -> VfsResult<Arc<Self>> {
        let kind = path.node().metadata()?.kind;
        let operations: Arc<dyn VfsFileOperations> = if path_only {
            Arc::new(PathOnlyOperations)
        } else {
            Arc::clone(path.node()).open(options)?
        };
        let status_flags = if options.append { VFS_STATUS_APPEND } else { 0 };
        Ok(Arc::new(Self {
            description: FileDescription::new(
                Some(PinnedPath::new(path)),
                operations,
                status_flags,
            ),
            kind,
            logical_path,
        }))
    }

    pub(crate) fn description(&self) -> &Arc<FileDescription> {
        &self.description
    }

    pub(crate) fn path(&self) -> &VfsPath {
        self.description
            .path()
            .expect("pathname-backed VFS file lost its path pin")
            .path()
    }

    pub(crate) fn logical_path(&self) -> &str {
        &self.logical_path
    }

    pub(crate) fn kind(&self) -> VfsNodeKind {
        self.kind
    }

    pub(crate) fn metadata(&self) -> VfsResult<VfsMetadata> {
        self.path().node().metadata()
    }

    pub(crate) fn size(&self) -> VfsResult<u64> {
        self.description.operations().size()
    }

    pub(crate) fn offset(&self) -> u64 {
        self.description.position().offset
    }

    pub(crate) fn set_offset(&self, offset: u64) {
        self.description.set_offset(offset);
    }

    pub(crate) fn directory_cookie(&self) -> u64 {
        self.description.position().directory_cookie
    }

    pub(crate) fn set_directory_cookie(&self, cookie: u64) {
        self.description.set_directory_cookie(cookie);
    }

    pub(crate) fn is_append(&self) -> bool {
        self.description.status_flags() & VFS_STATUS_APPEND != 0
    }

    pub(crate) fn read_user_result(&self, mut buffer: UserBuffer) -> VfsResult<usize> {
        if self.kind == VfsNodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        let mut total = 0usize;
        let mut failure = None;
        buffer.for_each_chunk_mut(|output| match self.description.read(output) {
            Ok(read) => {
                total += read;
                read == output.len()
            }
            Err(_) if total != 0 => false,
            Err(error) => {
                failure = Some(error);
                false
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(total)
    }

    pub(crate) fn write_user_result(&self, buffer: UserBuffer) -> VfsResult<usize> {
        if self.kind == VfsNodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        let mut total = 0usize;
        let mut failure = None;
        buffer.for_each_chunk(|input| match self.description.write(input) {
            Ok(written) => {
                total += written;
                written == input.len()
            }
            Err(_) if total != 0 => false,
            Err(error) => {
                failure = Some(error);
                false
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(total)
    }

    pub(crate) fn pread_user_result(
        &self,
        mut offset: u64,
        mut buffer: UserBuffer,
    ) -> VfsResult<usize> {
        if self.kind == VfsNodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        let mut total = 0usize;
        let mut failure = None;
        buffer.for_each_chunk_mut(|output| match self.description.read_at(offset, output) {
            Ok(read) => {
                total += read;
                offset = offset.saturating_add(read as u64);
                read == output.len()
            }
            Err(_) if total != 0 => false,
            Err(error) => {
                failure = Some(error);
                false
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(total)
    }

    pub(crate) fn pwrite_user_result(
        &self,
        mut offset: u64,
        buffer: UserBuffer,
    ) -> VfsResult<usize> {
        if self.kind == VfsNodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        let mut total = 0usize;
        let mut failure = None;
        buffer.for_each_chunk(|input| match self.description.write_at(offset, input) {
            Ok(written) => {
                total += written;
                offset = offset.saturating_add(written as u64);
                written == input.len()
            }
            Err(_) if total != 0 => false,
            Err(error) => {
                failure = Some(error);
                false
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(total)
    }
}

impl PathFileDescription for VfsOpenedFile {
    fn kind(&self) -> VfsNodeKind {
        VfsOpenedFile::kind(self)
    }

    fn offset(&self) -> u64 {
        VfsOpenedFile::offset(self)
    }

    fn set_offset(&self, offset: u64) -> VfsResult<()> {
        VfsOpenedFile::set_offset(self, offset);
        Ok(())
    }

    fn directory_cookie(&self) -> u64 {
        VfsOpenedFile::directory_cookie(self)
    }

    fn set_directory_cookie(&self, cookie: u64) -> VfsResult<()> {
        VfsOpenedFile::set_directory_cookie(self, cookie);
        Ok(())
    }

    fn size(&self) -> VfsResult<u64> {
        VfsOpenedFile::size(self)
    }

    fn seek_end(&self) -> VfsResult<u64> {
        if self.kind == VfsNodeKind::Directory {
            return self
                .path()
                .node()
                .readdir()
                .map(|entries| entries.len().saturating_add(2) as u64);
        }
        VfsOpenedFile::size(self)
    }

    fn is_append(&self) -> bool {
        VfsOpenedFile::is_append(self)
    }

    fn set_append(&self, enabled: bool) {
        self.description.set_append(enabled);
    }

    fn sync(&self, data_only: bool) -> VfsResult<()> {
        self.description.sync(data_only)
    }

    fn sync_range(&self, offset: u64, length: u64, flags: u32) -> VfsResult<()> {
        self.description.sync_range(offset, length, flags)
    }

    fn advise(&self, offset: u64, length: u64, advice: u32) -> VfsResult<()> {
        self.description.advise(offset, length, advice)
    }
}

impl File for VfsOpenedFile {
    fn readable(&self) -> bool {
        self.description.operations().readable()
    }

    fn writable(&self) -> bool {
        self.description.operations().writable()
    }

    fn read(&self, buffer: UserBuffer) -> usize {
        self.read_user_result(buffer).unwrap_or(0)
    }

    fn write(&self, buffer: UserBuffer) -> usize {
        self.write_user_result(buffer).unwrap_or(0)
    }

    fn fixed_poll_mask(&self) -> Option<i16> {
        matches!(self.kind, VfsNodeKind::Regular | VfsNodeKind::Directory)
            .then_some(POLLIN | POLLOUT)
    }

    fn object_path(&self) -> Option<&VfsPath> {
        Some(self.path())
    }

    fn logical_path_hint(&self) -> Option<&str> {
        Some(self.logical_path())
    }

    fn path_file(&self) -> Option<&dyn PathFileDescription> {
        Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
