use super::{
    CgroupFile, EventFdFile, FifoDuplexFile, IOV_MAX, MapPermission, O_NOATIME, O_NONBLOCK, O_PATH,
    OSInode, PIPE_BUF, Pipe, ProcPseudoFile, PseudoBlock, PseudoDir, PseudoFile, PseudoShmFile,
    SIGXFSZ_NUM, SPLICE_F_GIFT, SPLICE_F_MORE, SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SocketPairEnd,
    SyscallError, TimerFdFile, UserBuffer, Vec, cgroup_charge_file_write, current_process, err,
    ext4_err_to_errno, fanotify_notify_access, fanotify_notify_modify, fanotify_permission_access,
    fanotify_read_result, fanotify_write_result, fd_has_append, fd_has_noatime, fd_has_nonblock,
    fd_has_o_path, file_is_pipe, file_is_seekable_for_preadwrite, get_current_token,
    get_fd_file_and_flags, inode_visible_size_with_disk_size, maybe_update_inode_atime,
    mirror_inode_kernel_write_to_shared_mmaps, mirror_inode_write_to_current_mmaps,
    pipe_read_to_kernel, pipe_write_from_kernel, queue_process_signal, read_optional_offset,
    read_vm_iovec, require_fd_file, socketpair_write_from_kernel, touch_inode_mtime_ctime_now,
    try_copy_from_user, try_copy_to_user, try_read_user_value, try_translated_byte_buffer,
    try_write_proc_pseudo_file, try_write_user_value, validate_direct_io_request,
    with_ext4_inode_read, write_optional_offset,
};
use crate::fs::{PseudoKindTag, PtyMasterFile, PtySlaveFile, TunTapFile};
use alloc::vec;

/// Reads from regular files and special waitable descriptors into a user buffer.
pub fn syscall_read(fd: usize, buffer: usize, len: usize) -> isize {
    let Some((file, descriptor_flags)) = get_fd_file_and_flags(fd) else {
        return err(SyscallError::EBADF);
    };
    if (descriptor_flags & O_PATH as u32) != 0 {
        return err(SyscallError::EBADF);
    }
    let nonblock = (descriptor_flags & O_NONBLOCK as u32) != 0;
    let noatime = (descriptor_flags & O_NOATIME as u32) != 0;
    if !file.readable() {
        return err(SyscallError::EBADF);
    }
    if len == 0 {
        return 0;
    }
    if crate::syscall::net::socket_read_uses_recvfrom(file.as_ref()) {
        return crate::syscall::net::syscall_recvfrom(fd, buffer, len, 0, 0, 0);
    }
    if let Some(ret) = fanotify_read_result(&file, buffer, len, nonblock) {
        return ret;
    }
    if let Some(pseudo) = file.as_any().downcast_ref::<PseudoFile>()
        && pseudo.kind_tag() == PseudoKindTag::Zero
    {
        return read_zero_to_user(buffer, len);
    }
    if let Some(pty) = file.as_any().downcast_ref::<PtyMasterFile>() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ) else {
            return err(SyscallError::EFAULT);
        };
        return match pty.read_result(UserBuffer::new(user_bufs)) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if let Some(pty) = file.as_any().downcast_ref::<PtySlaveFile>() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ) else {
            return err(SyscallError::EFAULT);
        };
        return match pty.read_result(UserBuffer::new(user_bufs)) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if let Some(tun) = file.as_any().downcast_ref::<TunTapFile>() {
        if len > 0
            && let Err(e) = tun.wait_readable(nonblock)
        {
            return e;
        }
        let buf = if len == 0 {
            UserBuffer::new(Vec::new())
        } else {
            let Ok(user_bufs) = try_translated_byte_buffer(
                get_current_token(),
                buffer as *mut u8,
                len,
                MapPermission::W,
            ) else {
                return err(SyscallError::EFAULT);
            };
            UserBuffer::new(user_bufs)
        };
        return match tun.read_packet(buf) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        if let Err(e) = validate_direct_io_request(fd, &file, buffer, len, os_inode.offset()) {
            return e;
        }
    }
    if let Some(os_inode) = file
        .as_any()
        .downcast_ref::<OSInode>()
        .filter(|os_inode| !os_inode.fanotify_silent())
    {
        let inode = os_inode.ext4_inode();
        let is_dir = with_ext4_inode_read(&inode, || inode.is_dir());
        if is_dir {
            return err(SyscallError::EISDIR);
        }
    }
    if nonblock {
        if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
            if !pipe.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
        } else if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
            if !sock.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
        } else if let Some(duplex) = file.as_any().downcast_ref::<FifoDuplexFile>() {
            if !duplex.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
        } else if let Some(eventfd) = file.as_any().downcast_ref::<EventFdFile>() {
            if !eventfd.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
        } else if let Some(timerfd) = file.as_any().downcast_ref::<TimerFdFile>() {
            if !timerfd.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
        }
    }
    if let Some(eventfd) = file.as_any().downcast_ref::<EventFdFile>() {
        if len < core::mem::size_of::<u64>() {
            return err(SyscallError::EINVAL);
        }
        let value = match eventfd.read_counter(nonblock) {
            Ok(value) => value,
            Err(e) => return e,
        };
        if try_write_user_value(get_current_token(), buffer as *mut u64, &value).is_err() {
            return err(SyscallError::EFAULT);
        }
        return core::mem::size_of::<u64>() as isize;
    }
    if let Some(timerfd) = file.as_any().downcast_ref::<TimerFdFile>() {
        if len < core::mem::size_of::<u64>() {
            return err(SyscallError::EINVAL);
        }
        let value = match timerfd.read_counter(nonblock) {
            Ok(value) => value,
            Err(e) => return e,
        };
        if try_write_user_value(get_current_token(), buffer as *mut u64, &value).is_err() {
            return err(SyscallError::EFAULT);
        }
        return core::mem::size_of::<u64>() as isize;
    }
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ) else {
            return err(SyscallError::EFAULT);
        };
        return match pipe.read_user_result(UserBuffer::new(user_bufs), nonblock) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if let Some(os_inode) = file
        .as_any()
        .downcast_ref::<OSInode>()
        .filter(|os_inode| !os_inode.fanotify_silent())
    {
        let inode = os_inode.ext4_inode();
        let fanotify_path = os_inode.fanotify_path();
        let is_dir = with_ext4_inode_read(&inode, || inode.is_dir());
        if let Err(e) = fanotify_permission_access(&inode, is_dir, fanotify_path.as_deref()) {
            return e;
        }
    }
    let Ok(user_bufs) = try_translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
        MapPermission::W,
    ) else {
        return err(SyscallError::EFAULT);
    };
    let buf = UserBuffer::new(user_bufs);
    let read_len = file.read(buf) as isize;
    if read_len >= 0 && !noatime {
        if let Some(os_inode) = file
            .as_any()
            .downcast_ref::<OSInode>()
            .filter(|os_inode| !os_inode.fanotify_silent())
        {
            let inode = os_inode.ext4_inode();
            maybe_update_inode_atime(&inode, false);
            if read_len > 0 {
                let fanotify_path = os_inode.fanotify_path();
                let is_dir = with_ext4_inode_read(&inode, || inode.is_dir());
                fanotify_notify_access(&inode, is_dir, fanotify_path.as_deref());
            }
        }
    }
    read_len
}

fn read_zero_to_user(buffer: usize, len: usize) -> isize {
    if buffer.checked_add(len).is_none() {
        return err(SyscallError::EFAULT);
    }

    let token = get_current_token();
    if len == 1 {
        let zero = 0u8;
        return if try_write_user_value(token, buffer as *mut u8, &zero).is_ok() {
            1
        } else {
            err(SyscallError::EFAULT)
        };
    }

    static ZERO_CHUNK: [u8; 256] = [0; 256];
    let mut copied = 0usize;
    while copied < len {
        let n = core::cmp::min(len - copied, ZERO_CHUNK.len());
        let dst = (buffer + copied) as *mut u8;
        if try_copy_to_user(token, dst, &ZERO_CHUNK[..n]).is_err() {
            return if copied > 0 {
                copied as isize
            } else {
                err(SyscallError::EFAULT)
            };
        }
        copied += n;
    }
    copied as isize
}

/// Writes to regular files and special descriptors with nonblocking and rlimit handling.
pub fn syscall_write(fd: usize, buffer: usize, len: usize) -> isize {
    let Some((file, descriptor_flags)) = get_fd_file_and_flags(fd) else {
        return err(SyscallError::EBADF);
    };
    if (descriptor_flags & O_PATH as u32) != 0 {
        return err(SyscallError::EBADF);
    }
    let nonblock = (descriptor_flags & O_NONBLOCK as u32) != 0;
    if file.as_any().downcast_ref::<TimerFdFile>().is_some() {
        return err(SyscallError::EINVAL);
    }
    if crate::syscall::net::socket_write_uses_sendto(file.as_ref()) {
        return crate::syscall::net::syscall_sendto(fd, buffer, len, 0, 0, 0);
    }
    if !file.writable() {
        return err(SyscallError::EBADF);
    }
    if let Some(ret) = fanotify_write_result(&file, buffer, len) {
        return ret;
    }
    if let Some(pseudo) = file.as_any().downcast_ref::<PseudoFile>()
        && pseudo.kind_tag() == PseudoKindTag::Null
    {
        return len as isize;
    }
    if let Some(pty) = file.as_any().downcast_ref::<PtyMasterFile>() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return err(SyscallError::EFAULT);
        };
        return match pty.write_result(UserBuffer::new(user_bufs)) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if let Some(pty) = file.as_any().downcast_ref::<PtySlaveFile>() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return err(SyscallError::EFAULT);
        };
        return match pty.write_result(UserBuffer::new(user_bufs)) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if let Some(tun) = file.as_any().downcast_ref::<TunTapFile>() {
        let buf = if len == 0 {
            UserBuffer::new(Vec::new())
        } else {
            let Ok(user_bufs) = try_translated_byte_buffer(
                get_current_token(),
                buffer as *mut u8,
                len,
                MapPermission::R,
            ) else {
                return err(SyscallError::EFAULT);
            };
            UserBuffer::new(user_bufs)
        };
        return match tun.write_packet(buf) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if len == 0 {
        return 0;
    }
    if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return err(SyscallError::EFAULT);
        };
        let mut data = Vec::with_capacity(len);
        for slice in user_bufs {
            data.extend_from_slice(slice);
        }
        return match cgroup.write_payload(&data) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    if file.as_any().downcast_ref::<ProcPseudoFile>().is_some() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return err(SyscallError::EFAULT);
        };
        let mut data = Vec::with_capacity(len);
        for slice in user_bufs {
            data.extend_from_slice(slice);
        }
        if let Some(ret) = try_write_proc_pseudo_file(
            &file,
            &data,
            file.as_any()
                .downcast_ref::<ProcPseudoFile>()
                .map(ProcPseudoFile::offset)
                .unwrap_or(0),
            true,
        ) {
            return ret;
        }
    }
    let write_start_off = if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let start = if os_inode.append() {
            os_inode.visible_end()
        } else {
            os_inode.offset()
        };
        if let Err(e) = validate_direct_io_request(fd, &file, buffer, len, start) {
            return e;
        }
        Some(start)
    } else {
        None
    };
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>()
        && let Some(e) = pipe.closed_read_end_write_error()
    {
        return e;
    }
    let mut write_len = len;
    if nonblock {
        if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
            let avail = pipe.available_write();
            if avail == 0 {
                if let Some(e) = pipe.closed_read_end_write_error() {
                    return e;
                }
                return err(SyscallError::EAGAIN);
            }
            if write_len <= PIPE_BUF {
                if avail < write_len {
                    if let Some(e) = pipe.closed_read_end_write_error() {
                        return e;
                    }
                    return err(SyscallError::EAGAIN);
                }
            } else {
                write_len = write_len.min(avail);
            }
        } else if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
            if !sock.poll_writable() {
                return err(SyscallError::EAGAIN);
            }
        } else if let Some(duplex) = file.as_any().downcast_ref::<FifoDuplexFile>() {
            if duplex.write_end_closed() {
                return err(SyscallError::EPIPE);
            }
            let avail = duplex.available_write();
            if avail == 0 {
                return err(SyscallError::EAGAIN);
            }
            if write_len <= PIPE_BUF {
                if avail < write_len {
                    return err(SyscallError::EAGAIN);
                }
            } else {
                write_len = write_len.min(avail);
            }
        } else if let Some(eventfd) = file.as_any().downcast_ref::<EventFdFile>() {
            if !eventfd.poll_writable() {
                return err(SyscallError::EAGAIN);
            }
        }
    }
    if let Some(eventfd) = file.as_any().downcast_ref::<EventFdFile>() {
        if len < core::mem::size_of::<u64>() {
            return err(SyscallError::EINVAL);
        }
        let Some(value) = try_read_user_value(get_current_token(), buffer as *const u64) else {
            return err(SyscallError::EFAULT);
        };
        match eventfd.write_counter(value, nonblock) {
            Ok(()) => return core::mem::size_of::<u64>() as isize,
            Err(e) => return e,
        }
    }
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return err(SyscallError::EFAULT);
        };
        return match pipe.write_user_result(UserBuffer::new(user_bufs), nonblock) {
            Ok(0) if len > 0 && pipe.all_read_ends_closed() => err(SyscallError::EPIPE),
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }
    let mut hit_fsize_limit = false;
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let fsize_limit = {
            let process = current_process();
            let inner = process.borrow_mut();
            inner.rlimits.rlimit_fsize_cur
        };
        if fsize_limit != u64::MAX {
            let start = write_start_off.unwrap_or_else(|| os_inode.offset()) as u64;
            if start >= fsize_limit && len > 0 {
                let pid = current_process().getpid();
                queue_process_signal(pid, SIGXFSZ_NUM);
                return err(SyscallError::EFBIG);
            }
            let remain = (fsize_limit.saturating_sub(start)).min(usize::MAX as u64) as usize;
            if write_len > remain {
                write_len = remain;
                hit_fsize_limit = true;
            }
        }
    }
    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE) {
            return err(SyscallError::EPERM);
        }
        let start = shm.offset();
        let end = start.saturating_add(write_len);
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_GROW) && end > shm.len() {
            return err(SyscallError::EPERM);
        }
    }
    let Ok(user_bufs) = try_translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        write_len,
        MapPermission::R,
    ) else {
        return err(SyscallError::EFAULT);
    };
    let buf = UserBuffer::new(user_bufs);
    let written = file.write(buf) as isize;
    if written == 0 && write_len > 0 {
        if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
            if pipe.all_read_ends_closed() {
                return err(SyscallError::EPIPE);
            }
        }
        if let Some(duplex) = file.as_any().downcast_ref::<FifoDuplexFile>() {
            if duplex.write_end_closed() {
                return err(SyscallError::EPIPE);
            }
        }
    }
    if written > 0 {
        if let Some(os_inode) = file
            .as_any()
            .downcast_ref::<OSInode>()
            .filter(|os_inode| !os_inode.fanotify_silent())
        {
            cgroup_charge_file_write(current_process().getpid(), written as usize);
            mirror_inode_write_to_current_mmaps(
                os_inode,
                write_start_off.unwrap_or(0),
                buffer,
                written as usize,
            );
            if let Err(e) = os_inode.flush_with_error() {
                return ext4_err_to_errno(e);
            }
            let inode = os_inode.ext4_inode();
            let fanotify_path = os_inode.fanotify_path();
            let is_dir = with_ext4_inode_read(&inode, || inode.is_dir());
            fanotify_notify_modify(&inode, is_dir, fanotify_path.as_deref());
        }
    }
    if hit_fsize_limit {
        let pid = current_process().getpid();
        queue_process_signal(pid, SIGXFSZ_NUM);
    }
    written
}

/// Reads from a fixed offset without advancing the shared file position.
pub fn syscall_pread64(fd: usize, buffer: usize, len: usize, pos: isize) -> isize {
    if pos < 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    let file = require_fd_file!(fd);
    if !file_is_seekable_for_preadwrite(&file) {
        return err(SyscallError::ESPIPE);
    }
    if !file.readable() {
        return err(SyscallError::EBADF);
    }
    if let Err(e) = validate_direct_io_request(fd, &file, buffer, len, pos as usize) {
        return e;
    }

    // ext4 regular files
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = with_ext4_inode_read(&inode, || inode.is_dir());
        if is_dir {
            return err(SyscallError::EISDIR);
        }

        let mut total = 0usize;
        let token = get_current_token();
        let mut off = pos as usize;
        let mut user_ptr = buffer;
        const CHUNK_MAX: usize = 16 * 1024;
        let buf_cap = core::cmp::min(len, CHUNK_MAX);
        let mut kbuf = vec![0u8; buf_cap];
        while total < len {
            let want = core::cmp::min(len - total, buf_cap);
            let n = os_inode.pread_at(off, &mut kbuf[..want]);
            if n == 0 {
                break;
            }
            if try_copy_to_user(token, user_ptr as *mut u8, &kbuf[..n]).is_err() {
                return if total > 0 {
                    total as isize
                } else {
                    err(SyscallError::EFAULT)
                };
            }
            total += n;
            off += n;
            user_ptr += n;
            if n < want {
                break;
            }
        }
        if !fd_has_noatime(fd) {
            maybe_update_inode_atime(&inode, false);
        }
        return total as isize;
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        let old = shm.offset();
        shm.set_offset(pos as usize);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ) else {
            shm.set_offset(old);
            return err(SyscallError::EFAULT);
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.read(buf) as isize;
        shm.set_offset(old);
        return n;
    }

    if let Some(proc_file) = file.as_any().downcast_ref::<ProcPseudoFile>() {
        let old = proc_file.offset();
        proc_file.set_offset(pos as usize);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ) else {
            proc_file.set_offset(old);
            return err(SyscallError::EFAULT);
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.read(buf) as isize;
        proc_file.set_offset(old);
        return n;
    }

    // Seekable pseudo files: emulate by temporarily adjusting the per-fd offset.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        if pf.len().is_none() {
            return err(SyscallError::ESPIPE);
        }
        let old = pf.offset();
        pf.set_offset(pos as usize);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::W,
        ) else {
            pf.set_offset(old);
            return err(SyscallError::EFAULT);
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.read(buf) as isize;
        pf.set_offset(old);
        return n;
    }

    err(SyscallError::ESPIPE)
}

/// Writes to a fixed offset without advancing the shared file position.
pub fn syscall_pwrite64(fd: usize, buffer: usize, len: usize, pos: isize) -> isize {
    if pos < 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    let file = require_fd_file!(fd);
    if !file_is_seekable_for_preadwrite(&file) {
        return err(SyscallError::ESPIPE);
    }
    if !file.writable() {
        return err(SyscallError::EBADF);
    }
    if let Err(e) = validate_direct_io_request(fd, &file, buffer, len, pos as usize) {
        return e;
    }

    // ext4 regular files
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = with_ext4_inode_read(&inode, || inode.is_dir());
        if is_dir {
            return err(SyscallError::EISDIR);
        }

        let effective_pos = if os_inode.append() {
            let disk_end = with_ext4_inode_read(&inode, || inode.size() as usize);
            inode_visible_size_with_disk_size(&inode, disk_end)
        } else {
            pos as usize
        };

        let mut write_len = len;
        let mut hit_fsize_limit = false;
        let fsize_limit = {
            let process = current_process();
            let inner = process.borrow_mut();
            inner.rlimits.rlimit_fsize_cur
        };
        if fsize_limit != u64::MAX {
            let start = effective_pos as u64;
            if start >= fsize_limit && len > 0 {
                let pid = current_process().getpid();
                queue_process_signal(pid, SIGXFSZ_NUM);
                return err(SyscallError::EFBIG);
            }
            let remain = (fsize_limit.saturating_sub(start)).min(usize::MAX as u64) as usize;
            if write_len > remain {
                write_len = remain;
                hit_fsize_limit = true;
            }
        }
        let mut total = 0usize;
        let token = get_current_token();
        let mut off = effective_pos;
        let mut user_ptr = buffer;
        const CHUNK_MAX: usize = 16 * 1024;
        let buf_cap = core::cmp::min(write_len, CHUNK_MAX);
        let mut kbuf = vec![0u8; buf_cap];
        while total < write_len {
            let want = core::cmp::min(write_len - total, buf_cap);
            if try_copy_from_user(token, user_ptr as *const u8, &mut kbuf[..want]).is_err() {
                return if total > 0 {
                    mirror_inode_write_to_current_mmaps(os_inode, effective_pos, buffer, total);
                    cgroup_charge_file_write(current_process().getpid(), total);
                    total as isize
                } else {
                    err(SyscallError::EFAULT)
                };
            }
            match os_inode.pwrite_at(off, &kbuf[..want]) {
                Ok(n) => {
                    mirror_inode_kernel_write_to_shared_mmaps(os_inode, off, &kbuf[..n]);
                    total += n;
                    off += n;
                    user_ptr += n;
                    if n < want {
                        break;
                    }
                }
                Err(_) => {
                    crate::println!("[ext4] Warning: pwrite failed");
                    return if total > 0 {
                        mirror_inode_write_to_current_mmaps(os_inode, effective_pos, buffer, total);
                        cgroup_charge_file_write(current_process().getpid(), total);
                        total as isize
                    } else {
                        err(SyscallError::EIO)
                    };
                }
            }
        }
        if hit_fsize_limit {
            let pid = current_process().getpid();
            queue_process_signal(pid, SIGXFSZ_NUM);
        }
        if total > 0 {
            mirror_inode_write_to_current_mmaps(os_inode, effective_pos, buffer, total);
            cgroup_charge_file_write(current_process().getpid(), total);
        }
        return total as isize;
    }

    if file.as_any().downcast_ref::<ProcPseudoFile>().is_some() {
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return err(SyscallError::EFAULT);
        };
        let mut data = Vec::with_capacity(len);
        for slice in user_bufs {
            data.extend_from_slice(slice);
        }
        if let Some(ret) = try_write_proc_pseudo_file(&file, &data, pos as usize, false) {
            return ret;
        }
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_WRITE) {
            return err(SyscallError::EPERM);
        }
        let start = pos as usize;
        let end = start.saturating_add(len);
        if shm.has_memfd_seal(PseudoShmFile::F_SEAL_GROW) && end > shm.len() {
            return err(SyscallError::EPERM);
        }
        let old = shm.offset();
        shm.set_offset(start);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            shm.set_offset(old);
            return err(SyscallError::EFAULT);
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.write(buf) as isize;
        shm.set_offset(old);
        return n;
    }

    // Seekable pseudo files: emulate by temporarily adjusting the per-fd offset.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        if pf.len().is_none() {
            return err(SyscallError::ESPIPE);
        }
        let old = pf.offset();
        pf.set_offset(pos as usize);
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            pf.set_offset(old);
            return err(SyscallError::EFAULT);
        };
        let buf = UserBuffer::new(user_bufs);
        let n = file.write(buf) as isize;
        pf.set_offset(old);
        return n;
    }

    if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
        if pos != 0 {
            return err(SyscallError::EINVAL);
        }
        let Ok(user_bufs) = try_translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
            MapPermission::R,
        ) else {
            return err(SyscallError::EFAULT);
        };
        let mut data = Vec::with_capacity(len);
        for slice in user_bufs {
            data.extend_from_slice(slice);
        }
        return match cgroup.write_payload(&data) {
            Ok(n) => n as isize,
            Err(e) => e,
        };
    }

    err(SyscallError::ESPIPE)
}

/// Copies bytes from one fd to another using kernel-side buffering.
pub fn syscall_sendfile(out_fd: usize, in_fd: usize, offset: usize, count: usize) -> isize {
    if count == 0 {
        return 0;
    }
    if fd_has_o_path(in_fd) || fd_has_o_path(out_fd) {
        return err(SyscallError::EBADF);
    }
    let in_file = require_fd_file!(in_fd);
    let out_file = require_fd_file!(out_fd);
    if !in_file.readable() || !out_file.writable() {
        return err(SyscallError::EBADF);
    }

    let Some(in_inode) = in_file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::EINVAL);
    };
    let raw_in_pos = match read_optional_offset(offset) {
        Ok(Some(v)) => v,
        Ok(None) => in_inode.offset(),
        Err(e) => return e,
    };

    let out_net_socket = out_file.as_any().downcast_ref::<crate::fs::NetSocketFile>();
    let out_is_socketpair = out_file.as_any().downcast_ref::<SocketPairEnd>().is_some();
    let nonblock = fd_has_nonblock(out_fd);
    if nonblock && out_is_socketpair {
        let Some(sock) = out_file.as_any().downcast_ref::<SocketPairEnd>() else {
            return err(SyscallError::EINVAL);
        };
        if !sock.poll_writable() {
            return err(SyscallError::EAGAIN);
        }
    }
    let mut in_pos = raw_in_pos;
    let mut total = 0usize;
    let mut remaining = count;
    let mut out_pos = 0usize;
    let out_inode_opt = out_file.as_any().downcast_ref::<OSInode>();
    if let Some(out_inode) = out_inode_opt {
        if out_inode.readonly_fs() {
            return err(SyscallError::EROFS);
        }
        out_pos = out_inode.offset();
    }
    let mut buf = vec![0u8; core::cmp::min(remaining, 16 * 1024)];
    while remaining > 0 {
        let want = core::cmp::min(remaining, buf.len());
        let read = in_inode.pread_at(in_pos, &mut buf[..want]);
        if read == 0 {
            break;
        }
        let wrote = if let Some(out_inode) = out_inode_opt {
            match out_inode.pwrite_at(out_pos, &buf[..read]) {
                Ok(n) => {
                    mirror_inode_kernel_write_to_shared_mmaps(out_inode, out_pos, &buf[..n]);
                    n
                }
                Err(_) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        err(SyscallError::EIO)
                    };
                }
            }
        } else if out_is_socketpair {
            match socketpair_write_from_kernel(&out_file, &buf[..read], nonblock) {
                Ok(n) => n,
                Err(e) => return if total > 0 { total as isize } else { e },
            }
        } else if let Some(sock) = out_net_socket {
            if sock.kind() != crate::fs::NetSocketKind::TcpStream {
                return if total > 0 {
                    total as isize
                } else {
                    err(SyscallError::EINVAL)
                };
            }
            match sock.tcp_send(&buf[..read], nonblock) {
                Ok(n) => n,
                Err(e) => return if total > 0 { total as isize } else { e },
            }
        } else {
            return if total > 0 {
                total as isize
            } else {
                err(SyscallError::EINVAL)
            };
        };
        if wrote == 0 {
            break;
        }
        total += wrote;
        remaining -= wrote;
        in_pos += wrote;
        if out_inode_opt.is_some() {
            out_pos += wrote;
        }
        if wrote < read {
            break;
        }
    }

    let mut flush_failed = false;
    if let Some(out_inode) = out_inode_opt {
        flush_failed = total > 0 && out_inode.flush().is_err();
        out_inode.set_offset(out_pos);
    }

    if offset == 0 {
        in_inode.set_offset(in_pos);
    } else if let Err(e) = write_optional_offset(offset, in_pos) {
        return e;
    }
    if flush_failed {
        return err(SyscallError::EIO);
    }
    total as isize
}

/// Moves data between pipes and seekable files while honoring optional offset pointers.
pub fn syscall_splice(
    fd_in: usize,
    off_in: usize,
    fd_out: usize,
    off_out: usize,
    len: usize,
    flags: usize,
) -> isize {
    let valid_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    if fd_has_o_path(fd_in) || fd_has_o_path(fd_out) {
        return err(SyscallError::EBADF);
    }
    let in_file = require_fd_file!(fd_in);
    let out_file = require_fd_file!(fd_out);
    if !in_file.readable() || !out_file.writable() {
        return err(SyscallError::EBADF);
    }
    let in_is_pipe = file_is_pipe(&in_file);
    let out_is_pipe = file_is_pipe(&out_file);
    if !in_is_pipe && !out_is_pipe {
        return err(SyscallError::EINVAL);
    }
    if in_is_pipe && off_in != 0 {
        return err(SyscallError::ESPIPE);
    }
    if out_is_pipe && off_out != 0 {
        return err(SyscallError::ESPIPE);
    }
    if !out_is_pipe
        && (fd_has_append(fd_out)
            || out_file
                .as_any()
                .downcast_ref::<OSInode>()
                .map(|f| f.append())
                .unwrap_or(false))
    {
        return err(SyscallError::EINVAL);
    }
    let out_is_inode = out_file.as_any().downcast_ref::<OSInode>().is_some();
    let out_is_socketpair = out_file.as_any().downcast_ref::<SocketPairEnd>().is_some();
    if !out_is_pipe && !out_is_inode && !out_is_socketpair {
        return err(SyscallError::EINVAL);
    }
    let in_is_inode = in_file.as_any().downcast_ref::<OSInode>().is_some();
    if !in_is_pipe && !in_is_inode {
        return err(SyscallError::EINVAL);
    }

    let nonblock =
        (flags & SPLICE_F_NONBLOCK) != 0 || fd_has_nonblock(fd_in) || fd_has_nonblock(fd_out);
    let mut in_pos = if in_is_pipe {
        0usize
    } else {
        match read_optional_offset(off_in) {
            Ok(Some(v)) => v,
            Ok(None) => {
                let Some(in_inode) = in_file.as_any().downcast_ref::<OSInode>() else {
                    return err(SyscallError::EINVAL);
                };
                in_inode.offset()
            }
            Err(e) => return e,
        }
    };
    let mut out_pos = if out_is_pipe {
        0usize
    } else {
        match read_optional_offset(off_out) {
            Ok(Some(v)) => v,
            Ok(None) => {
                if let Some(out_inode) = out_file.as_any().downcast_ref::<OSInode>() {
                    out_inode.offset()
                } else {
                    0
                }
            }
            Err(e) => return e,
        }
    };

    let mut moved = 0usize;
    let mut buf = vec![0u8; core::cmp::min(len, PIPE_BUF)];
    while moved < len {
        let want = core::cmp::min(buf.len(), len - moved);
        let read = if in_is_pipe {
            if nonblock {
                if let Some(pipe) = out_file.as_any().downcast_ref::<Pipe>() {
                    if !pipe.poll_writable() {
                        return if moved > 0 {
                            moved as isize
                        } else {
                            err(SyscallError::EAGAIN)
                        };
                    }
                } else if let Some(sock) = out_file.as_any().downcast_ref::<SocketPairEnd>() {
                    if !sock.poll_writable() {
                        return if moved > 0 {
                            moved as isize
                        } else {
                            err(SyscallError::EAGAIN)
                        };
                    }
                }
            }
            match pipe_read_to_kernel(&in_file, &mut buf[..want], nonblock) {
                Ok(n) => n,
                Err(e) => return if moved > 0 { moved as isize } else { e },
            }
        } else {
            let Some(in_inode) = in_file.as_any().downcast_ref::<OSInode>() else {
                return if moved > 0 {
                    moved as isize
                } else {
                    err(SyscallError::EINVAL)
                };
            };
            let is_file = {
                let inode = in_inode.ext4_inode();
                with_ext4_inode_read(&inode, || inode.is_file())
            };
            if !is_file {
                return if moved > 0 {
                    moved as isize
                } else {
                    err(SyscallError::EINVAL)
                };
            }
            let n = in_inode.pread_at(in_pos, &mut buf[..want]);
            if n == 0 {
                break;
            }
            n
        };
        if read == 0 {
            break;
        }

        let wrote = if out_is_pipe {
            match pipe_write_from_kernel(&out_file, &buf[..read], nonblock) {
                Ok(n) => n,
                Err(e) => return if moved > 0 { moved as isize } else { e },
            }
        } else if let Some(out_inode) = out_file.as_any().downcast_ref::<OSInode>() {
            let is_file = {
                let inode = out_inode.ext4_inode();
                with_ext4_inode_read(&inode, || inode.is_file())
            };
            if !is_file {
                return if moved > 0 {
                    moved as isize
                } else {
                    err(SyscallError::EINVAL)
                };
            }
            if out_inode.readonly_fs() {
                return if moved > 0 {
                    moved as isize
                } else {
                    err(SyscallError::EROFS)
                };
            }
            match out_inode.pwrite_at(out_pos, &buf[..read]) {
                Ok(n) => {
                    mirror_inode_kernel_write_to_shared_mmaps(out_inode, out_pos, &buf[..n]);
                    n
                }
                Err(_) => {
                    return if moved > 0 {
                        moved as isize
                    } else {
                        err(SyscallError::EIO)
                    };
                }
            }
        } else if out_file.as_any().downcast_ref::<SocketPairEnd>().is_some() {
            match socketpair_write_from_kernel(&out_file, &buf[..read], nonblock) {
                Ok(n) => n,
                Err(e) => return if moved > 0 { moved as isize } else { e },
            }
        } else {
            return if moved > 0 {
                moved as isize
            } else {
                err(SyscallError::EINVAL)
            };
        };
        if wrote == 0 {
            break;
        }
        moved += wrote;
        if !in_is_pipe {
            in_pos += wrote;
        }
        if !out_is_pipe && out_file.as_any().downcast_ref::<OSInode>().is_some() {
            out_pos += wrote;
        }
        if wrote < read {
            break;
        }
    }

    if !in_is_pipe {
        if off_in == 0 {
            if let Some(in_inode) = in_file.as_any().downcast_ref::<OSInode>() {
                in_inode.set_offset(in_pos);
            }
        } else if let Err(e) = write_optional_offset(off_in, in_pos) {
            return e;
        }
    }
    if !out_is_pipe {
        if let Some(out_inode) = out_file.as_any().downcast_ref::<OSInode>() {
            if moved > 0 && out_inode.flush().is_err() {
                return err(SyscallError::EIO);
            }
            if off_out == 0 {
                out_inode.set_offset(out_pos);
            } else if let Err(e) = write_optional_offset(off_out, out_pos) {
                return e;
            }
        }
    }
    moved as isize
}

/// Duplicates pipe data into another pipe without consuming the input stream.
pub fn syscall_tee(fd_in: usize, fd_out: usize, len: usize, flags: usize) -> isize {
    let valid_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    if fd_has_o_path(fd_in) || fd_has_o_path(fd_out) {
        return err(SyscallError::EBADF);
    }
    let in_file = require_fd_file!(fd_in);
    let out_file = require_fd_file!(fd_out);
    if !in_file.readable() || !out_file.writable() {
        return err(SyscallError::EBADF);
    }
    let Some(in_pipe) = in_file.as_any().downcast_ref::<Pipe>() else {
        return err(SyscallError::EINVAL);
    };
    let Some(out_pipe) = out_file.as_any().downcast_ref::<Pipe>() else {
        return err(SyscallError::EINVAL);
    };
    if in_pipe.same_buffer(out_pipe) {
        return err(SyscallError::EINVAL);
    }
    let nonblock =
        (flags & SPLICE_F_NONBLOCK) != 0 || fd_has_nonblock(fd_in) || fd_has_nonblock(fd_out);
    let mut copied = 0usize;
    let mut buf = vec![0u8; core::cmp::min(len, PIPE_BUF)];
    let mut consume_buf = vec![0u8; core::cmp::min(len, PIPE_BUF)];
    while copied < len {
        let want = core::cmp::min(len - copied, buf.len());
        let peeked = match in_pipe.peek_to_slice(&mut buf[..want], nonblock) {
            Ok(n) => n,
            Err(e) => return if copied > 0 { copied as isize } else { e },
        };
        if peeked == 0 {
            break;
        }
        let wrote = match out_pipe.write_from_slice(&buf[..peeked], nonblock) {
            Ok(n) => n,
            Err(e) => return if copied > 0 { copied as isize } else { e },
        };
        if wrote == 0 {
            break;
        }
        let consumed = match in_pipe.read_to_slice(&mut consume_buf[..wrote], true) {
            Ok(n) => n,
            Err(e) => return if copied > 0 { copied as isize } else { e },
        };
        if consumed == 0 {
            break;
        }
        copied += consumed;
        if consumed < peeked {
            break;
        }
    }
    copied as isize
}

/// Feeds pipe buffers from an iovec array supplied by userspace.
pub fn syscall_vmsplice(fd: usize, iov_ptr: usize, nr_segs: usize, flags: usize) -> isize {
    let valid_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if (flags & !valid_flags) != 0 {
        return err(SyscallError::EINVAL);
    }
    if fd_has_o_path(fd) {
        return err(SyscallError::EBADF);
    }
    let file = require_fd_file!(fd);
    let Some(pipe) = file.as_any().downcast_ref::<Pipe>() else {
        return err(SyscallError::EBADF);
    };
    if nr_segs > IOV_MAX {
        return err(SyscallError::EINVAL);
    }
    if nr_segs == 0 {
        return 0;
    }
    let nonblock = (flags & SPLICE_F_NONBLOCK) != 0 || fd_has_nonblock(fd);
    let token = get_current_token();
    let mut total = 0usize;
    let mut scratch = vec![0u8; PIPE_BUF];
    for i in 0..nr_segs {
        let iv = match read_vm_iovec(token, iov_ptr, i) {
            Ok(v) => v,
            Err(e) => return if total > 0 { total as isize } else { e },
        };
        if iv.iov_len == 0 {
            continue;
        }
        if file.writable() {
            let mut seg_off = 0usize;
            while seg_off < iv.iov_len {
                let want = core::cmp::min(iv.iov_len - seg_off, scratch.len());
                let src_ptr = (iv.iov_base + seg_off) as *const u8;
                if try_copy_from_user(token, src_ptr, &mut scratch[..want]).is_err() {
                    return if total > 0 {
                        total as isize
                    } else {
                        err(SyscallError::EFAULT)
                    };
                }
                // Linux may return a short vmsplice() once some bytes are moved.
                // Avoid blocking indefinitely trying to drain very large iovecs.
                let write_nonblock = nonblock || total > 0 || seg_off > 0;
                let wrote = match pipe.write_from_slice(&scratch[..want], write_nonblock) {
                    Ok(n) => n,
                    Err(e) => return if total > 0 { total as isize } else { e },
                };
                if wrote == 0 {
                    return if total > 0 {
                        total as isize
                    } else {
                        err(SyscallError::EPIPE)
                    };
                }
                total += wrote;
                seg_off += wrote;
                if wrote < want {
                    break;
                }
            }
        } else if file.readable() {
            let mut seg_off = 0usize;
            while seg_off < iv.iov_len {
                let want = core::cmp::min(iv.iov_len - seg_off, scratch.len());
                let read = match pipe.read_to_slice(&mut scratch[..want], nonblock) {
                    Ok(n) => n,
                    Err(e) => return if total > 0 { total as isize } else { e },
                };
                if read == 0 {
                    return total as isize;
                }
                let dst_ptr = (iv.iov_base + seg_off) as *mut u8;
                if try_copy_to_user(token, dst_ptr, &scratch[..read]).is_err() {
                    return if total > 0 {
                        total as isize
                    } else {
                        err(SyscallError::EFAULT)
                    };
                }
                total += read;
                seg_off += read;
                if read < want {
                    break;
                }
            }
        } else {
            return if total > 0 {
                total as isize
            } else {
                err(SyscallError::EBADF)
            };
        }
    }
    total as isize
}

/// Copies a byte range between regular files with optional explicit offsets.
pub fn syscall_copy_file_range(
    fd_in: usize,
    off_in: usize,
    fd_out: usize,
    off_out: usize,
    len: usize,
    flags: usize,
) -> isize {
    // Keep an explicit max file-size guard so oversized ranges still report err(SyscallError::EFBIG)
    // (used by LTP copy_file_range02), but do not cap normal file copies too low.
    const COPY_FILE_RANGE_MAX_FILE_SIZE: u64 = 1u64 << 40; // 1 TiB
    if flags != 0 {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    if len > i64::MAX as usize {
        return err(SyscallError::EOVERFLOW);
    }
    if fd_has_o_path(fd_in) || fd_has_o_path(fd_out) {
        return err(SyscallError::EBADF);
    }
    let in_file = require_fd_file!(fd_in);
    let out_file = require_fd_file!(fd_out);
    if !in_file.readable() {
        return err(SyscallError::EBADF);
    }
    let Some(in_os_inode) = in_file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::EINVAL);
    };
    let Some(out_os_inode) = out_file.as_any().downcast_ref::<OSInode>() else {
        return err(SyscallError::EINVAL);
    };
    let in_inode = in_os_inode.ext4_inode();
    let out_inode = out_os_inode.ext4_inode();
    if out_inode.is_dir() {
        return err(SyscallError::EISDIR);
    }
    if !out_file.writable() {
        return err(SyscallError::EBADF);
    }
    if out_os_inode.append() {
        return err(SyscallError::EBADF);
    }
    if out_os_inode.readonly_fs() {
        return err(SyscallError::EROFS);
    }
    if in_inode.device_id() != out_inode.device_id() {
        return err(SyscallError::EXDEV);
    }
    if !in_inode.is_file() || !out_inode.is_file() {
        return err(SyscallError::EINVAL);
    }

    let token = get_current_token();
    let mut in_pos = if off_in == 0 {
        in_os_inode.offset()
    } else {
        let Some(v) = try_read_user_value(token, off_in as *const i64) else {
            return err(SyscallError::EFAULT);
        };
        if v < 0 {
            return err(SyscallError::EINVAL);
        }
        v as usize
    };
    let mut out_pos = if off_out == 0 {
        out_os_inode.offset()
    } else {
        let Some(v) = try_read_user_value(token, off_out as *const i64) else {
            return err(SyscallError::EFAULT);
        };
        if v < 0 {
            return err(SyscallError::EINVAL);
        }
        v as usize
    };

    if len > 0 && (out_pos as u64) >= COPY_FILE_RANGE_MAX_FILE_SIZE {
        return err(SyscallError::EFBIG);
    }
    if in_inode.inode_num() == out_inode.inode_num() {
        let in_end = in_pos.saturating_add(len);
        let out_end = out_pos.saturating_add(len);
        if in_pos < out_end && out_pos < in_end {
            return err(SyscallError::EINVAL);
        }
    }

    let mut copied = 0usize;
    let mut remaining = len;
    let mut buf = vec![0u8; core::cmp::min(remaining, 16 * 1024)];
    while remaining > 0 {
        let room = COPY_FILE_RANGE_MAX_FILE_SIZE.saturating_sub(out_pos as u64) as usize;
        if room == 0 {
            if copied == 0 {
                return err(SyscallError::EFBIG);
            }
            break;
        }
        let want = core::cmp::min(remaining, core::cmp::min(buf.len(), room));
        let read = in_os_inode.pread_at(in_pos, &mut buf[..want]);
        if read == 0 {
            break;
        }
        let written = match out_os_inode.pwrite_at(out_pos, &buf[..read]) {
            Ok(v) => {
                mirror_inode_kernel_write_to_shared_mmaps(out_os_inode, out_pos, &buf[..v]);
                v
            }
            Err(_) => return err(SyscallError::EIO),
        };
        if written == 0 {
            break;
        }
        copied += written;
        in_pos += written;
        out_pos += written;
        remaining -= written;
        if written < read {
            break;
        }
    }
    if copied > 0 {
        let _ = out_os_inode.flush();
        touch_inode_mtime_ctime_now(&out_inode);
    }

    if off_in == 0 {
        in_os_inode.set_offset(in_pos);
    } else {
        let next = in_pos as i64;
        if try_write_user_value(token, off_in as *mut i64, &next).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    if off_out == 0 {
        out_os_inode.set_offset(out_pos);
    } else {
        let next = out_pos as i64;
        if try_write_user_value(token, off_out as *mut i64, &next).is_err() {
            return err(SyscallError::EFAULT);
        }
    }

    copied as isize
}

/// Repositions the offset of a seekable file descriptor.
pub fn syscall_lseek(fd: usize, offset: isize, whence: usize) -> isize {
    const SEEK_SET: usize = 0;
    const SEEK_CUR: usize = 1;
    const SEEK_END: usize = 2;
    const PSEUDO_ROOT_DEV_BYTES: usize = 1024 * 1024 * 1024;

    let file = require_fd_file!(fd);

    // Directories: map seek position to our per-fd `dir_offset`.
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        let cur = pdir.index() as isize;
        let end = pdir.entries().len() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return err(SyscallError::EINVAL),
        };
        if new < 0 {
            return err(SyscallError::EINVAL);
        }
        pdir.set_index(new as usize);
        return new;
    }

    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let (is_dir, is_fifo, disk_end) = with_ext4_inode_read(&inode, || {
            (inode.is_dir(), inode.is_fifo(), inode.size() as usize)
        });
        let end = inode_visible_size_with_disk_size(&inode, disk_end) as isize;
        if is_fifo {
            return err(SyscallError::ESPIPE);
        }

        if is_dir {
            let cur = os_inode.dir_offset() as isize;
            let new = match whence {
                SEEK_SET => offset,
                SEEK_CUR => cur.saturating_add(offset),
                SEEK_END => end.saturating_add(offset),
                _ => return err(SyscallError::EINVAL),
            };
            if new < 0 {
                return err(SyscallError::EINVAL);
            }
            os_inode.set_dir_offset(new as usize);
            return new;
        }

        // Regular files: adjust read/write offset.
        let cur = os_inode.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return err(SyscallError::EINVAL),
        };
        if new < 0 {
            return err(SyscallError::EINVAL);
        }
        os_inode.set_offset(new as usize);
        return new;
    }

    if let Some(pblk) = file.as_any().downcast_ref::<PseudoBlock>() {
        let cur = pblk.offset() as isize;
        let end = PSEUDO_ROOT_DEV_BYTES as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return err(SyscallError::EINVAL),
        };
        if new < 0 {
            return err(SyscallError::EINVAL);
        }
        pblk.set_offset(new as usize);
        return new;
    }

    // Pseudo regular files: allow seeking for static content (e.g., `/dev` nodes),
    // which libc helpers (busybox `df`) may `rewind()` via lseek.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        let Some(end) = pf.len().map(|n| n as isize) else {
            return err(SyscallError::ESPIPE);
        };
        let cur = pf.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return err(SyscallError::EINVAL),
        };
        if new < 0 {
            return err(SyscallError::EINVAL);
        }
        pf.set_offset(new as usize);
        return new;
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        let end = shm.len() as isize;
        let cur = shm.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return err(SyscallError::EINVAL),
        };
        if new < 0 {
            return err(SyscallError::EINVAL);
        }
        shm.set_offset(new as usize);
        return new;
    }

    if let Some(proc_file) = file.as_any().downcast_ref::<ProcPseudoFile>() {
        let cur = proc_file.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => proc_file.seek_end().saturating_add(offset),
            _ => return err(SyscallError::EINVAL),
        };
        if new < 0 {
            return err(SyscallError::EINVAL);
        }
        proc_file.set_offset(new as usize);
        return new;
    }

    if let Some(cgroup) = file.as_any().downcast_ref::<CgroupFile>() {
        let cur = cgroup.offset() as isize;
        let end = cgroup.len() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return err(SyscallError::EINVAL),
        };
        if new < 0 {
            return err(SyscallError::EINVAL);
        }
        cgroup.set_offset(new as usize);
        return new;
    }

    err(SyscallError::ESPIPE)
}
