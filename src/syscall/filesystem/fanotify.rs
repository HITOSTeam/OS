use super::{
    AT_FDCWD, FanotifyFile, File, MapPermission, SyscallError, current_files,
    current_files_and_nofile_limit, current_fsuid_gid, err, get_current_token, read_user_cstring,
    resolve_at_inode_with_vfs_path, resolve_at_path, try_translated_byte_buffer,
    with_ext4_inode_read,
};
use alloc::sync::Arc;

const FAN_MARK_DONT_FOLLOW: usize = 0x0000_0004;
const FAN_MARK_FLUSH: usize = 0x0000_0080;

pub fn syscall_fanotify_init(flags: usize, _event_f_flags: usize) -> isize {
    let file = match FanotifyFile::new(flags) {
        Ok(file) => file,
        Err(e) => return e,
    };
    let file: Arc<dyn File + Send + Sync> = file;
    let (files, limit) = current_files_and_nofile_limit();
    let installed =
        files
            .lock()
            .install_fd(file, crate::fs::fanotify_descriptor_flags(flags), limit);
    installed.map(|fd| fd as isize).unwrap_or_else(|rejected| {
        rejected.discard();
        err(SyscallError::EMFILE)
    })
}

pub fn syscall_fanotify_mark(
    fanotify_fd: usize,
    flags: usize,
    mask: u64,
    dirfd: isize,
    pathname: usize,
) -> isize {
    let fanotify_file = {
        let Some(file) = current_files().lock().get_file(fanotify_fd) else {
            return err(SyscallError::EBADF);
        };
        if file.as_any().downcast_ref::<FanotifyFile>().is_none() {
            return err(SyscallError::EINVAL);
        }
        file
    };

    if (flags & FAN_MARK_FLUSH) != 0 {
        let Some(group) = fanotify_file.as_any().downcast_ref::<FanotifyFile>() else {
            return err(SyscallError::EINVAL);
        };
        return match group.flush_marks(flags) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }

    let path = if pathname == 0 {
        if dirfd == AT_FDCWD {
            return err(SyscallError::EFAULT);
        }
        alloc::string::String::new()
    } else {
        match read_user_cstring(get_current_token(), pathname) {
            Ok(path) => path,
            Err(e) => return e,
        }
    };
    let at = match resolve_at_path(dirfd, &path) {
        Ok(at) => at,
        Err(e) => return e,
    };
    let (fsuid, fsgid) = current_fsuid_gid();
    let follow = (flags & FAN_MARK_DONT_FOLLOW) == 0;
    let (inode, mark_path) = match resolve_at_inode_with_vfs_path(&at, fsuid, fsgid, follow) {
        Ok(resolved) => resolved,
        Err(e) => return e,
    };
    let is_dir = with_ext4_inode_read(&inode, || inode.is_dir());

    let Some(fanotify_file) = fanotify_file.as_any().downcast_ref::<FanotifyFile>() else {
        return err(SyscallError::EINVAL);
    };
    match fanotify_file.modify_mark(flags, mask, inode, is_dir, Some(mark_path)) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub(crate) fn fanotify_read_result(
    file: &Arc<dyn File + Send + Sync>,
    buffer: usize,
    len: usize,
    nonblock: bool,
) -> Option<isize> {
    let fanotify = file.as_any().downcast_ref::<FanotifyFile>()?;
    let Ok(user_bufs) = try_translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
        MapPermission::W,
    ) else {
        return Some(err(SyscallError::EFAULT));
    };
    Some(
        match fanotify.read_events(super::UserBuffer::new(user_bufs), nonblock) {
            Ok(n) => n as isize,
            Err(e) => e,
        },
    )
}

pub(crate) fn fanotify_write_result(
    file: &Arc<dyn File + Send + Sync>,
    buffer: usize,
    len: usize,
) -> Option<isize> {
    let fanotify = file.as_any().downcast_ref::<FanotifyFile>()?;
    let Ok(user_bufs) = try_translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
        MapPermission::R,
    ) else {
        return Some(err(SyscallError::EFAULT));
    };
    Some(
        match fanotify.write_response(super::UserBuffer::new(user_bufs)) {
            Ok(n) => n as isize,
            Err(e) => e,
        },
    )
}
