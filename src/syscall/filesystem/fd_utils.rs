use super::*;
use lazy_static::lazy_static;

pub(crate) struct FifoDuplexFile {
    pub(crate) read_end: Arc<Pipe>,
    pub(crate) write_end: Arc<Pipe>,
}

impl FifoDuplexFile {
    pub(crate) fn new(read_end: Arc<Pipe>, write_end: Arc<Pipe>) -> Self {
        Self {
            read_end,
            write_end,
        }
    }

    pub(crate) fn write_end_closed(&self) -> bool {
        self.write_end.all_read_ends_closed()
    }

    pub(crate) fn poll_readable(&self) -> bool {
        self.read_end.poll_readable()
    }

    pub(crate) fn poll_writable(&self) -> bool {
        self.write_end.poll_writable()
    }

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

    pub(crate) fn has_open_readers(&self) -> bool {
        self.read_end.open_read_end_count() > 0
    }

    pub(crate) fn has_open_writers(&self) -> bool {
        self.write_end.open_write_end_count() > 0
    }

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
    pub(crate) static ref FIFO_PIPE_STATES: Mutex<BTreeMap<u64, Arc<FifoPipeState>>> =
        Mutex::new(BTreeMap::new());
}

pub(crate) fn get_fd_file(fd: usize) -> Option<alloc::sync::Arc<dyn File + Send + Sync>> {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return None;
    }
    inner.fd_table[fd].clone()
}

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

pub(crate) fn fd_is_writable_proc_pseudo(fd: usize) -> bool {
    let Some(file) = get_fd_file(fd) else {
        return false;
    };
    file.as_any()
        .downcast_ref::<ProcPseudoFile>()
        .map(|proc_file| proc_file.writable())
        .unwrap_or(false)
}

pub(crate) fn write_proc_pseudo_fd(fd: usize, data: &[u8], offset: Option<usize>) -> Option<isize> {
    let file = get_fd_file(fd)?;
    let effective_offset = if let Some(offset) = offset {
        offset
    } else {
        file.as_any().downcast_ref::<ProcPseudoFile>()?.offset()
    };
    try_write_proc_pseudo_file(&file, data, effective_offset, offset.is_none())
}

pub(crate) fn file_is_seekable_for_preadwrite(file: &alloc::sync::Arc<dyn File + Send + Sync>) -> bool {
    if file.as_any().downcast_ref::<OSInode>().is_some() {
        return true;
    }
    if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
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

pub(crate) fn fd_has_o_path(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_PATH as u32) != 0
}

pub(crate) fn fd_has_nonblock(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_NONBLOCK as u32) != 0
}

pub(crate) fn fd_has_append(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_APPEND as u32) != 0
}

pub(crate) fn fd_has_odirect(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_DIRECT as u32) != 0
}

pub(crate) fn fd_has_noatime(fd: usize) -> bool {
    let process = current_files_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_flags.len() {
        return false;
    }
    (inner.fd_flags[fd] & O_NOATIME as u32) != 0
}

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
    let is_regular = {
        let _ext4_guard = ext4_lock();
        inode.is_file()
    };
    if !is_regular {
        return Ok(());
    }
    let mask = DIRECT_IO_ALIGN - 1;
    if (user_ptr & mask) != 0 || (len & mask) != 0 || (offset & mask) != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(())
}

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

pub(crate) fn file_is_pipe(file: &alloc::sync::Arc<dyn File + Send + Sync>) -> bool {
    file.as_any().downcast_ref::<Pipe>().is_some()
}

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

pub(crate) fn open_fd_flags(flags: usize, o_path: bool) -> u32 {
    let mut fd_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    if (flags & O_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK as u32;
    }
    if (flags & O_APPEND) != 0 {
        fd_flags |= O_APPEND as u32;
    }
    if (flags & O_DIRECT) != 0 {
        fd_flags |= O_DIRECT as u32;
    }
    if (flags & O_ASYNC) != 0 {
        fd_flags |= O_ASYNC as u32;
    }
    if (flags & O_NOATIME) != 0 {
        fd_flags |= O_NOATIME as u32;
    }
    if o_path {
        fd_flags |= O_PATH as u32;
    }
    fd_flags
}

pub(crate) fn install_open_file_fd(
    file: alloc::sync::Arc<dyn File + Send + Sync>,
    flags: usize,
    o_path: bool,
) -> Result<usize, isize> {
    let process = current_files_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return Err(err(SyscallError::EMFILE));
    };
    inner.fd_table[fd] = Some(file);
    inner.fd_flags[fd] = open_fd_flags(flags, o_path);
    Ok(fd)
}

pub(crate) fn fifo_pipe_state_for_inode(inode_num: u64) -> Arc<FifoPipeState> {
    let mut states = FIFO_PIPE_STATES.lock();
    if let Some(state) = states.get(&inode_num) {
        // Drop idle state so reopened FIFOs start with an empty buffer.
        if !state.has_open_readers() && !state.has_open_writers() {
            states.remove(&inode_num);
        } else {
            return state.clone();
        }
    }
    let state = Arc::new(FifoPipeState::new());
    states.insert(inode_num, state.clone());
    state
}

pub(crate) fn get_fd_inode(fd: usize) -> Option<alloc::sync::Arc<ext4_fs::Inode>> {
    let file = get_fd_file(fd)?;
    file.as_any()
        .downcast_ref::<OSInode>()
        .map(|o| o.ext4_inode())
}
