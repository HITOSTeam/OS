use super::{
    Arc, BTreeMap, DIRECT_IO_ALIGN, FD_CLOEXEC, File, MemfdFile, Mutex, O_APPEND, O_ASYNC,
    O_CLOEXEC, O_DIRECT, O_NOATIME, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_WRONLY, OSInode, Pipe,
    ProcPseudoFile, PseudoFile, SocketPairEnd, SyscallError, TaskControlBlock, UserBuffer,
    current_files, current_files_and_nofile_limit, err, get_current_token, make_pipe,
    try_read_user_value, try_write_user_value, with_ext4_inode_read,
};
use lazy_static::lazy_static;

pub(crate) struct FifoDuplexFile {
    pub(crate) read_end: Arc<Pipe>,
    pub(crate) write_end: Arc<Pipe>,
}

impl FifoDuplexFile {
    /// Builds a duplex FIFO handle that exposes both read and write directions.
    pub(crate) fn new(read_end: Arc<Pipe>, write_end: Arc<Pipe>) -> Self {
        Self {
            read_end,
            write_end,
        }
    }

    /// Returns whether the FIFO write side has lost all user-visible readers.
    pub(crate) fn write_end_closed(&self) -> bool {
        self.write_end.all_read_ends_closed()
    }

    /// Checks readiness for reading from the duplex FIFO.
    pub(crate) fn poll_readable(&self) -> bool {
        self.read_end.poll_readable()
    }

    /// Checks readiness for writing into the duplex FIFO.
    #[allow(dead_code)]
    pub(crate) fn poll_writable(&self) -> bool {
        self.write_end.poll_writable()
    }

    /// Returns how many bytes can currently be written without blocking.
    pub(crate) fn available_write(&self) -> usize {
        self.write_end.available_write()
    }
}

impl File for FifoDuplexFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        self.read_end.read(buf)
    }

    fn write(&self, buf: UserBuffer) -> usize {
        self.write_end.write(buf)
    }

    fn poll_mask(&self) -> i16 {
        let read_mask = self.read_end.poll_mask();
        let write_mask = self.write_end.poll_mask();
        (read_mask & (crate::fs::POLLIN | crate::fs::POLLHUP))
            | (write_mask & (crate::fs::POLLOUT | crate::fs::POLLERR))
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let _ = self.read_end.register_poll_waiter(task);
        let _ = self.write_end.register_poll_waiter(task);
        true
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

pub(crate) struct FifoPipeState {
    pub(crate) read_end: Arc<Pipe>,
    pub(crate) write_end: Arc<Pipe>,
}

impl FifoPipeState {
    /// Creates or resets the backing pipe pair used to model one FIFO inode.
    pub(crate) fn new() -> Self {
        let (read_end, write_end) = make_pipe();
        // Keep one registry reference to each end, but exclude it from
        // "open-end" accounting so EOF/err(SyscallError::EPIPE) semantics still track real FDs.
        read_end.set_end_ref_bias(1, 1);
        Self {
            read_end,
            write_end,
        }
    }

    /// Returns whether any opened descriptor still references the read side.
    pub(crate) fn has_open_readers(&self) -> bool {
        self.read_end.open_read_end_count() > 0
    }

    /// Returns whether any opened descriptor still references the write side.
    pub(crate) fn has_open_writers(&self) -> bool {
        self.write_end.open_write_end_count() > 0
    }

    /// Materializes the file view requested by the FIFO access mode.
    pub(crate) fn open_file(&self, accmode: usize) -> Option<Arc<dyn File + Send + Sync>> {
        match accmode {
            O_RDONLY => Some(self.read_end.clone()),
            O_WRONLY => Some(self.write_end.clone()),
            O_RDWR => Some(Arc::new(FifoDuplexFile::new(
                self.read_end.clone(),
                self.write_end.clone(),
            ))),
            _ => None,
        }
    }
}

lazy_static! {
    pub(crate) static ref FIFO_PIPE_STATES: Mutex<BTreeMap<(u64, u64), Arc<FifoPipeState>>> =
        Mutex::new(BTreeMap::new());
}

/// Returns the file currently installed at `fd`, if any.
pub(crate) fn get_fd_file(fd: usize) -> Option<alloc::sync::Arc<dyn File + Send + Sync>> {
    current_files().lock().get_file(fd)
}

/// Returns the file and descriptor flags currently installed at `fd`, if any.
pub(crate) fn get_fd_file_and_flags(
    fd: usize,
) -> Option<(alloc::sync::Arc<dyn File + Send + Sync>, u32)> {
    current_files().lock().get_file_and_flags(fd)
}

/// Get the file for `fd`, returning `-EBADF` if the descriptor is not open.
macro_rules! require_fd_file {
    ($fd:expr) => {
        match $crate::syscall::filesystem::get_fd_file($fd as usize) {
            Some(f) => f,
            None => return $crate::syscall::error::err($crate::syscall::error::SyscallError::EBADF),
        }
    };
}
pub(crate) use require_fd_file;

/// Writes bytes into a writable `/proc` pseudo file and optionally advances its offset.
pub(crate) fn try_write_proc_pseudo_file(
    file: &Arc<dyn File + Send + Sync>,
    data: &[u8],
    offset: usize,
    advance_offset: bool,
) -> Option<isize> {
    let proc_file = file.as_any().downcast_ref::<ProcPseudoFile>()?;
    if data.is_empty() {
        return Some(0);
    }
    let written = match proc_file.pwrite_bytes(offset, data) {
        Ok(written) => written,
        Err(err) => return Some(err),
    };
    if advance_offset {
        proc_file.set_offset(offset.saturating_add(written));
    }
    Some(written as isize)
}

/// Returns whether `fd` names a writable proc pseudo file.
pub(crate) fn fd_is_writable_proc_pseudo(fd: usize) -> bool {
    let Some(file) = get_fd_file(fd) else {
        return false;
    };
    file.as_any()
        .downcast_ref::<ProcPseudoFile>()
        .map(|proc_file| proc_file.writable())
        .unwrap_or(false)
}

/// Writes data to a proc pseudo fd using either an explicit or the tracked file offset.
pub(crate) fn write_proc_pseudo_fd(fd: usize, data: &[u8], offset: Option<usize>) -> Option<isize> {
    let file = get_fd_file(fd)?;
    let effective_offset = if let Some(offset) = offset {
        offset
    } else {
        file.as_any().downcast_ref::<ProcPseudoFile>()?.offset()
    };
    try_write_proc_pseudo_file(&file, data, effective_offset, offset.is_none())
}

/// Reports whether a file supports positional I/O for `pread`/`pwrite` style calls.
pub(crate) fn file_is_seekable_for_preadwrite(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
) -> bool {
    if let Some(path_file) = file.path_file() {
        return matches!(
            path_file.kind(),
            crate::fs::vfs::VfsNodeKind::Regular | crate::fs::vfs::VfsNodeKind::Directory
        );
    }
    if file.as_any().downcast_ref::<MemfdFile>().is_some() {
        return true;
    }
    if file.as_any().downcast_ref::<ProcPseudoFile>().is_some() {
        return true;
    }
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        return pf.len().is_some();
    }
    false
}

/// Returns whether the descriptor was opened with `O_PATH`.
pub(crate) fn fd_has_o_path(fd: usize) -> bool {
    (current_files().lock().get_flags(fd) & O_PATH as u32) != 0
}

/// Returns whether the descriptor was opened with `O_NONBLOCK`.
pub(crate) fn fd_has_nonblock(fd: usize) -> bool {
    (current_files().lock().get_flags(fd) & O_NONBLOCK as u32) != 0
}

/// Returns whether the descriptor tracks append-on-write semantics.
pub(crate) fn fd_has_append(fd: usize) -> bool {
    (current_files().lock().get_flags(fd) & O_APPEND as u32) != 0
}

/// Returns whether the descriptor requested `O_DIRECT`.
pub(crate) fn fd_has_odirect(fd: usize) -> bool {
    (current_files().lock().get_flags(fd) & O_DIRECT as u32) != 0
}

/// Returns whether access-time updates are suppressed for this descriptor.
pub(crate) fn fd_has_noatime(fd: usize) -> bool {
    (current_files().lock().get_flags(fd) & O_NOATIME as u32) != 0
}

/// Validates Linux-style alignment constraints for direct I/O requests.
pub(crate) fn validate_direct_io_request(
    fd: usize,
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    user_ptr: usize,
    len: usize,
    offset: usize,
) -> Result<(), isize> {
    if !fd_has_odirect(fd) || len == 0 {
        return Ok(());
    }
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return Ok(());
    };
    let inode = os_inode.ext4_inode();
    let is_regular = with_ext4_inode_read(&inode, || inode.is_file());
    if !is_regular {
        return Ok(());
    }
    let mask = DIRECT_IO_ALIGN - 1;
    if (user_ptr & mask) != 0 || (len & mask) != 0 || (offset & mask) != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(())
}

/// Reads an optional userspace `loff_t *` and converts it into a kernel offset.
pub(crate) fn read_optional_offset(ptr: usize) -> Result<Option<usize>, isize> {
    if ptr == 0 {
        return Ok(None);
    }
    let Some(raw) = try_read_user_value(get_current_token(), ptr as *const i64) else {
        return Err(err(SyscallError::EFAULT));
    };
    if raw < 0 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(Some(raw as usize))
}

/// Stores an updated optional offset back to userspace when a pointer was supplied.
pub(crate) fn write_optional_offset(ptr: usize, value: usize) -> Result<(), isize> {
    if ptr == 0 {
        return Ok(());
    }
    let next = value as i64;
    if try_write_user_value(get_current_token(), ptr as *mut i64, &next).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok(())
}

/// Returns whether the file is backed by a pipe object.
pub(crate) fn file_is_pipe(file: &alloc::sync::Arc<dyn File + Send + Sync>) -> bool {
    file.as_any().downcast_ref::<Pipe>().is_some()
}

/// Pulls bytes from a pipe into a kernel buffer.
pub(crate) fn pipe_read_to_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    out: &mut [u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        return pipe.read_to_slice(out, nonblock);
    }
    Err(err(SyscallError::EINVAL))
}

/// Pushes bytes from a kernel buffer into a pipe.
pub(crate) fn pipe_write_from_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    data: &[u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        return pipe.write_from_slice(data, nonblock);
    }
    Err(err(SyscallError::EINVAL))
}

/// Pushes bytes from a kernel buffer into a socketpair endpoint.
pub(crate) fn socketpair_write_from_kernel(
    file: &alloc::sync::Arc<dyn File + Send + Sync>,
    data: &[u8],
    nonblock: bool,
) -> Result<usize, isize> {
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        return sock.write_from_slice(data, nonblock);
    }
    Err(err(SyscallError::EINVAL))
}

/// Extracts the per-fd flags that should be persisted in the descriptor table.
pub(crate) fn open_descriptor_flags(flags: usize, o_path: bool) -> u32 {
    let mut descriptor_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    if (flags & O_NONBLOCK) != 0 {
        descriptor_flags |= O_NONBLOCK as u32;
    }
    if (flags & O_APPEND) != 0 {
        descriptor_flags |= O_APPEND as u32;
    }
    if (flags & O_DIRECT) != 0 {
        descriptor_flags |= O_DIRECT as u32;
    }
    if (flags & O_ASYNC) != 0 {
        descriptor_flags |= O_ASYNC as u32;
    }
    if (flags & O_NOATIME) != 0 {
        descriptor_flags |= O_NOATIME as u32;
    }
    if o_path {
        descriptor_flags |= O_PATH as u32;
    }
    descriptor_flags
}

/// Allocates a new descriptor slot and installs the opened file with derived fd flags.
pub(crate) fn install_open_file_fd(
    file: alloc::sync::Arc<dyn File + Send + Sync>,
    flags: usize,
    o_path: bool,
) -> Result<usize, isize> {
    let (files, limit) = current_files_and_nofile_limit();
    let installed = files
        .lock()
        .install_fd(file, open_descriptor_flags(flags, o_path), limit);
    let fd = match installed {
        Ok(fd) => fd,
        Err(rejected) => {
            rejected.discard();
            return Err(err(SyscallError::EMFILE));
        }
    };
    Ok(fd)
}

/// Returns the shared pipe state for one filesystem/node identity, recreating
/// it once all ends are gone.
///
/// Linux keys a FIFO's pipe state by the inode object, not by `i_ino` alone;
/// inode numbers can overlap across mounts and independent tmpfs instances.
pub(crate) fn fifo_pipe_state_for_inode(filesystem_id: u64, inode_num: u64) -> Arc<FifoPipeState> {
    let key = (filesystem_id, inode_num);
    let mut states = FIFO_PIPE_STATES.lock();
    if let Some(state) = states.get(&key) {
        // Drop idle state so reopened FIFOs start with an empty buffer.
        if !state.has_open_readers() && !state.has_open_writers() {
            states.remove(&key);
        } else {
            return state.clone();
        }
    }
    let state = Arc::new(FifoPipeState::new());
    states.insert(key, state.clone());
    state
}

/// Returns the ext4 inode currently referenced by `fd`, if the descriptor targets one.
#[allow(dead_code)]
pub(crate) fn get_fd_inode(fd: usize) -> Option<alloc::sync::Arc<ext4_fs::Inode>> {
    let file = get_fd_file(fd)?;
    file.as_any()
        .downcast_ref::<OSInode>()
        .map(|o| o.ext4_inode())
}
