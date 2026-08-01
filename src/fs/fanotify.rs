use alloc::{
    collections::VecDeque,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    any::Any,
    fmt::Write,
    mem::size_of,
    sync::atomic::{AtomicUsize, Ordering},
};
use ext4_fs::Inode;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::{
    fs::{
        File, OSInode, POLLIN, POLLOUT, PollWaitQueue, find_path_in_roots, inode_raw_logical_path,
        wake_tasks,
    },
    mm::UserBuffer,
    syscall::{
        error::{SyscallError, err},
        filesystem::translate_mount_abs,
        misc::encode_linux_tid,
    },
    task::{
        processor::{
            block_current_and_run_next, current_files_and_nofile_limit, current_process,
            current_task,
        },
        signal::has_wait_interrupting_pending,
        task_block::TaskControlBlock,
    },
};

pub(crate) const FAN_ACCESS: u64 = 0x0000_0001;
pub(crate) const FAN_MODIFY: u64 = 0x0000_0002;
pub(crate) const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
pub(crate) const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
pub(crate) const FAN_OPEN: u64 = 0x0000_0020;
pub(crate) const FAN_OPEN_EXEC: u64 = 0x0000_1000;
pub(crate) const FAN_OPEN_PERM: u64 = 0x0001_0000;
pub(crate) const FAN_ACCESS_PERM: u64 = 0x0002_0000;
pub(crate) const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
pub(crate) const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
pub(crate) const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
pub(crate) const FAN_ONDIR: u64 = 0x4000_0000;

const FANOTIFY_METADATA_VERSION: u8 = 3;
const FAN_EVENT_METADATA_LEN: usize = 24;
const FANOTIFY_DEFAULT_MAX_QUEUED_EVENTS: usize = 64;
const FAN_NOFD: i32 = -1;
const FAN_CLOEXEC: usize = 0x0000_0001;
const FAN_NONBLOCK: usize = 0x0000_0002;
const FAN_CLASS_CONTENT: usize = 0x0000_0004;
const FAN_CLASS_PRE_CONTENT: usize = 0x0000_0008;
const FAN_UNLIMITED_QUEUE: usize = 0x0000_0010;
const FAN_UNLIMITED_MARKS: usize = 0x0000_0020;
const FAN_ENABLE_AUDIT: usize = 0x0000_0040;
const FAN_REPORT_TID: usize = 0x0000_0100;
const FAN_REPORT_FLAGS: usize = 0x0000_7f80;
const FAN_SUPPORTED_INIT_FLAGS: usize = FAN_CLOEXEC
    | FAN_NONBLOCK
    | FAN_CLASS_CONTENT
    | FAN_CLASS_PRE_CONTENT
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS
    | FAN_ENABLE_AUDIT
    | FAN_REPORT_TID;

pub(crate) const FAN_MARK_ADD: usize = 0x0000_0001;
pub(crate) const FAN_MARK_REMOVE: usize = 0x0000_0002;
const FAN_MARK_DONT_FOLLOW: usize = 0x0000_0004;
const FAN_MARK_ONLYDIR: usize = 0x0000_0008;
const FAN_MARK_MOUNT: usize = 0x0000_0010;
pub(crate) const FAN_MARK_IGNORED_MASK: usize = 0x0000_0020;
pub(crate) const FAN_MARK_IGNORED_SURV_MODIFY: usize = 0x0000_0040;
const FAN_MARK_FLUSH: usize = 0x0000_0080;
const FAN_MARK_FILESYSTEM: usize = 0x0000_0100;
const FAN_MARK_EVICTABLE: usize = 0x0000_0200;
const FAN_MARK_IGNORE: usize = 0x0000_0400;
const FAN_MARK_TYPE_BITS: usize = FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM;
const FAN_SUPPORTED_MARK_FLAGS: usize = FAN_MARK_ADD
    | FAN_MARK_REMOVE
    | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR
    | FAN_MARK_MOUNT
    | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY
    | FAN_MARK_FLUSH
    | FAN_MARK_FILESYSTEM;

const FANOTIFY_EVENT_MASK: u64 = FAN_ACCESS
    | FAN_MODIFY
    | FAN_CLOSE_WRITE
    | FAN_CLOSE_NOWRITE
    | FAN_OPEN
    | FAN_OPEN_EXEC
    | FAN_OPEN_PERM
    | FAN_ACCESS_PERM
    | FAN_OPEN_EXEC_PERM
    | FAN_EVENT_ON_CHILD
    | FAN_ONDIR;
const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FanotifyInodeKey {
    dev: usize,
    ino: u32,
}

impl FanotifyInodeKey {
    fn from_inode(inode: &Arc<Inode>) -> Self {
        Self {
            dev: inode.device_id(),
            ino: inode.inode_num(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FanotifyMarkScope {
    Inode,
    Mount,
    Filesystem,
}

struct FanotifyMark {
    scope: FanotifyMarkScope,
    target: FanotifyInodeKey,
    target_dev: usize,
    target_path: Option<String>,
    target_source_path: Option<String>,
    mask: u64,
    ignored_mask: u64,
    ignore_survives_modify: bool,
}

struct FanotifyEvent {
    mask: u64,
    pid: i32,
    inode: Option<Arc<Inode>>,
    permission: Option<Arc<FanotifyPermission>>,
}

struct FanotifyPermission {
    inner: Mutex<FanotifyPermissionInner>,
}

struct FanotifyPermissionInner {
    event_fd: Option<i32>,
    response: Option<u32>,
    waiters: VecDeque<Weak<TaskControlBlock>>,
}

struct FanotifyInner {
    marks: Vec<FanotifyMark>,
    events: VecDeque<FanotifyEvent>,
    pending_permissions: Vec<Arc<FanotifyPermission>>,
    read_waiters: VecDeque<Weak<TaskControlBlock>>,
    poll_waiters: PollWaitQueue,
}

pub struct FanotifyFile {
    nonblock: bool,
    unlimited_queue: bool,
    report_tid: bool,
    inner: Mutex<FanotifyInner>,
}

lazy_static! {
    static ref FANOTIFY_GROUPS: Mutex<Vec<Weak<FanotifyFile>>> = Mutex::new(Vec::new());
}

static FANOTIFY_MAX_QUEUED_EVENTS: AtomicUsize =
    AtomicUsize::new(FANOTIFY_DEFAULT_MAX_QUEUED_EVENTS);

impl FanotifyFile {
    pub(crate) fn new(init_flags: usize) -> Result<Arc<Self>, isize> {
        if !fanotify_init_flags_valid(init_flags) {
            return Err(err(SyscallError::EINVAL));
        }
        let file = Arc::new(Self {
            nonblock: (init_flags & FAN_NONBLOCK) != 0,
            unlimited_queue: (init_flags & FAN_UNLIMITED_QUEUE) != 0,
            report_tid: (init_flags & FAN_REPORT_TID) != 0,
            inner: Mutex::new(FanotifyInner {
                marks: Vec::new(),
                events: VecDeque::new(),
                pending_permissions: Vec::new(),
                read_waiters: VecDeque::new(),
                poll_waiters: PollWaitQueue::default(),
            }),
        });
        let mut groups = FANOTIFY_GROUPS.lock();
        groups.retain(|group| group.upgrade().is_some());
        groups.push(Arc::downgrade(&file));
        Ok(file)
    }

    pub(crate) fn read_events(&self, mut buf: UserBuffer, nonblock: bool) -> Result<usize, isize> {
        if buf.len() < FAN_EVENT_METADATA_LEN {
            return Err(err(SyscallError::EINVAL));
        }
        loop {
            let mut inner = self.inner.lock();
            if !inner.events.is_empty() {
                let mut written = 0usize;
                while written + FAN_EVENT_METADATA_LEN <= buf.len() {
                    let Some(event) = inner.events.pop_front() else {
                        break;
                    };
                    let fd = match event.inode.as_ref() {
                        Some(inode) => install_event_fd(Arc::clone(inode))?,
                        None => FAN_NOFD,
                    };
                    let meta = FanotifyEventMetadata {
                        event_len: FAN_EVENT_METADATA_LEN as u32,
                        vers: FANOTIFY_METADATA_VERSION,
                        reserved: 0,
                        metadata_len: FAN_EVENT_METADATA_LEN as u16,
                        mask: event.mask,
                        fd,
                        pid: event.pid,
                    };
                    if let Some(permission) = event.permission {
                        permission.inner.lock().event_fd = Some(fd);
                        inner.pending_permissions.push(permission);
                    }
                    write_metadata(&mut buf, written, &meta);
                    written += FAN_EVENT_METADATA_LEN;
                }
                return Ok(written);
            }
            if nonblock || self.nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            if current_has_wait_interrupting_signal() {
                return Err(err(SyscallError::EINTR));
            }
            let Some(task) = current_task() else {
                return Err(err(SyscallError::EAGAIN));
            };
            add_waiter_once(&mut inner.read_waiters, &task);
            drop(inner);
            block_current_and_run_next();
            if current_has_wait_interrupting_signal() {
                return Err(err(SyscallError::EINTR));
            }
        }
    }

    pub(crate) fn write_response(&self, buf: UserBuffer) -> Result<usize, isize> {
        if buf.len() < size_of::<FanotifyResponse>() {
            return Err(err(SyscallError::EINVAL));
        }
        let Some(response) = read_response(buf) else {
            return Err(err(SyscallError::EINVAL));
        };
        if response.response & (FAN_ALLOW | FAN_DENY) == 0 {
            return Err(err(SyscallError::EINVAL));
        }
        let permission = {
            let mut inner = self.inner.lock();
            let Some(pos) = inner
                .pending_permissions
                .iter()
                .position(|permission| permission.inner.lock().event_fd == Some(response.fd))
            else {
                return Err(err(SyscallError::ENOENT));
            };
            inner.pending_permissions.remove(pos)
        };
        let mut perm_inner = permission.inner.lock();
        perm_inner.response = Some(response.response);
        wake_permission_waiters(&mut perm_inner);
        Ok(size_of::<FanotifyResponse>())
    }

    pub(crate) fn modify_mark(
        &self,
        flags: usize,
        mask: u64,
        inode: Arc<Inode>,
        is_dir: bool,
        target_path: Option<String>,
        target_source_path: Option<String>,
    ) -> Result<(), isize> {
        if (flags & !FAN_SUPPORTED_MARK_FLAGS) != 0 {
            return Err(err(SyscallError::EINVAL));
        }
        if (flags & FAN_MARK_IGNORE) != 0 || (flags & FAN_MARK_EVICTABLE) != 0 {
            return Err(err(SyscallError::EINVAL));
        }
        let op_bits = flags & (FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH);
        if op_bits.count_ones() != 1 {
            return Err(err(SyscallError::EINVAL));
        }
        if (flags & FAN_MARK_ONLYDIR) != 0 && !is_dir {
            return Err(err(SyscallError::ENOTDIR));
        }
        if mask & !FANOTIFY_EVENT_MASK != 0 {
            return Err(err(SyscallError::EINVAL));
        }
        let scope = match flags & FAN_MARK_TYPE_BITS {
            0 => FanotifyMarkScope::Inode,
            FAN_MARK_MOUNT => FanotifyMarkScope::Mount,
            FAN_MARK_FILESYSTEM => FanotifyMarkScope::Filesystem,
            _ => return Err(err(SyscallError::EINVAL)),
        };
        let mut inner = self.inner.lock();
        if (flags & FAN_MARK_FLUSH) != 0 {
            inner.marks.retain(|mark| mark.scope != scope);
            return Ok(());
        }
        let key = FanotifyInodeKey::from_inode(&inode);
        let target_dev = inode.device_id();
        let Some(mark) = inner
            .marks
            .iter_mut()
            .find(|mark| mark.scope == scope && mark.target == key)
        else {
            if (flags & FAN_MARK_REMOVE) != 0 {
                return Err(err(SyscallError::ENOENT));
            }
            inner.marks.push(FanotifyMark {
                scope,
                target: key,
                target_dev,
                target_path,
                target_source_path,
                mask: if (flags & FAN_MARK_IGNORED_MASK) != 0 {
                    0
                } else {
                    mask
                },
                ignored_mask: if (flags & FAN_MARK_IGNORED_MASK) != 0 {
                    mask
                } else {
                    0
                },
                ignore_survives_modify: (flags & FAN_MARK_IGNORED_SURV_MODIFY) != 0,
            });
            return Ok(());
        };
        if mark.target_path.is_none() && target_path.is_some() {
            mark.target_path = target_path;
        }
        if mark.target_source_path.is_none() && target_source_path.is_some() {
            mark.target_source_path = target_source_path;
        }
        if (flags & FAN_MARK_REMOVE) != 0 {
            if (flags & FAN_MARK_IGNORED_MASK) != 0 {
                mark.ignored_mask &= !mask;
                mark.ignore_survives_modify = mark.ignore_survives_modify && mark.ignored_mask != 0;
            } else {
                mark.mask &= !mask;
            }
        } else if (flags & FAN_MARK_IGNORED_MASK) != 0 {
            mark.ignored_mask |= mask;
            if (flags & FAN_MARK_IGNORED_SURV_MODIFY) != 0 {
                mark.ignore_survives_modify = true;
            }
        } else {
            mark.mask |= mask;
        }
        inner
            .marks
            .retain(|mark| mark.mask != 0 || mark.ignored_mask != 0);
        Ok(())
    }

    pub(crate) fn fdinfo_marks(&self) -> String {
        let inner = self.inner.lock();
        let mut out = String::new();
        for mark in inner.marks.iter() {
            let _ = writeln!(
                out,
                "fanotify ino:{:x} sdev:{:x} mflags: {:x} mask:{:x} ignored_mask:{:x}",
                mark.target.ino,
                mark.target.dev,
                fdinfo_mark_flags(mark),
                mark.mask,
                mark.ignored_mask
            );
        }
        out
    }

    fn notify(
        &self,
        inode: Arc<Inode>,
        inode_key: FanotifyInodeKey,
        parent_key: Option<FanotifyInodeKey>,
        event_path: Option<&str>,
        event_mask: u64,
        is_dir: bool,
        pid: i32,
    ) {
        let mut inner = self.inner.lock();
        let mut ignored = 0u64;
        for mark in inner.marks.iter() {
            if !mark_matches(mark, inode_key, parent_key, event_path, inode.device_id()) {
                continue;
            }
            ignored |= mark_event_bits(mark.ignored_mask, event_mask, is_dir);
        }
        let mut matched = 0u64;
        for mark in inner.marks.iter() {
            if !mark_matches(mark, inode_key, parent_key, event_path, inode.device_id()) {
                continue;
            }
            matched |= mark_event_bits(mark.mask, event_mask, is_dir) & !ignored;
        }
        if (event_mask & FAN_MODIFY) != 0 {
            for mark in inner.marks.iter_mut() {
                if mark.ignore_survives_modify
                    || !mark_matches(mark, inode_key, parent_key, event_path, inode.device_id())
                {
                    continue;
                }
                mark.ignored_mask = 0;
                mark.ignore_survives_modify = false;
            }
        }
        if matched == 0 {
            return;
        }
        if self.queue_overflowed(&mut inner) {
            return;
        }
        inner.events.push_back(FanotifyEvent {
            mask: matched,
            pid,
            inode: Some(inode),
            permission: None,
        });
        wake_readers(&mut inner);
    }

    fn permission_event(
        &self,
        inode: Arc<Inode>,
        inode_key: FanotifyInodeKey,
        parent_key: Option<FanotifyInodeKey>,
        event_path: Option<&str>,
        event_candidates: u64,
        is_dir: bool,
        pid: i32,
    ) -> Option<Arc<FanotifyPermission>> {
        let mut inner = self.inner.lock();
        let mut ignored = 0u64;
        for mark in inner.marks.iter() {
            if !mark_matches(mark, inode_key, parent_key, event_path, inode.device_id()) {
                continue;
            }
            let Some(event_mask) =
                select_permission_event(mark.mask | mark.ignored_mask, event_candidates)
            else {
                continue;
            };
            ignored |= mark_event_bits(mark.ignored_mask, event_mask, is_dir);
        }
        let mut matched = 0u64;
        for mark in inner.marks.iter() {
            if !mark_matches(mark, inode_key, parent_key, event_path, inode.device_id()) {
                continue;
            }
            let Some(event_mask) = select_permission_event(mark.mask, event_candidates) else {
                continue;
            };
            matched |= mark_event_bits(mark.mask, event_mask, is_dir) & !ignored;
        }
        if matched == 0 {
            return None;
        }
        if self.queue_overflowed(&mut inner) {
            return None;
        }
        let permission = Arc::new(FanotifyPermission {
            inner: Mutex::new(FanotifyPermissionInner {
                event_fd: None,
                response: None,
                waiters: VecDeque::new(),
            }),
        });
        inner.events.push_back(FanotifyEvent {
            mask: matched,
            pid,
            inode: Some(inode),
            permission: Some(Arc::clone(&permission)),
        });
        wake_readers(&mut inner);
        Some(permission)
    }

    fn queue_overflowed(&self, inner: &mut FanotifyInner) -> bool {
        if self.unlimited_queue
            || inner.events.len() < FANOTIFY_MAX_QUEUED_EVENTS.load(Ordering::Relaxed)
        {
            return false;
        }
        if !inner
            .events
            .iter()
            .any(|event| event.mask == FAN_Q_OVERFLOW)
        {
            inner.events.push_back(FanotifyEvent {
                mask: FAN_Q_OVERFLOW,
                pid: 0,
                inode: None,
                permission: None,
            });
            wake_readers(inner);
        }
        true
    }
}

impl Drop for FanotifyFile {
    fn drop(&mut self) {
        let permissions = {
            let mut inner = self.inner.lock();
            let mut permissions = Vec::new();
            for event in inner.events.iter() {
                if let Some(permission) = event.permission.as_ref() {
                    permissions.push(Arc::clone(permission));
                }
            }
            permissions.extend(inner.pending_permissions.iter().cloned());
            inner.events.clear();
            inner.pending_permissions.clear();
            wake_readers(&mut inner);
            permissions
        };
        for permission in permissions {
            let mut inner = permission.inner.lock();
            if inner.response.is_none() {
                inner.response = Some(FAN_DENY);
                wake_permission_waiters(&mut inner);
            }
        }
    }
}

impl File for FanotifyFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        self.read_events(buf, false).unwrap_or(0)
    }

    fn write(&self, buf: UserBuffer) -> usize {
        self.write_response(buf).unwrap_or(0)
    }

    fn poll_mask(&self) -> i16 {
        let mut mask = POLLOUT;
        if !self.inner.lock().events.is_empty() {
            mask |= POLLIN;
        }
        mask
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        self.inner.lock().poll_waiters.register_waiter(task)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) fn fanotify_init_flags_valid(flags: usize) -> bool {
    if (flags & !FAN_SUPPORTED_INIT_FLAGS) != 0 {
        return false;
    }
    let class_bits = flags & (FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT);
    if class_bits == (FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT) {
        return false;
    }
    if (flags & (FAN_REPORT_FLAGS & !FAN_REPORT_TID)) != 0 {
        return false;
    }
    true
}

pub(crate) fn fanotify_descriptor_flags(init_flags: usize) -> u32 {
    let mut fd_flags = 0u32;
    if (init_flags & FAN_CLOEXEC) != 0 {
        fd_flags |= crate::syscall::filesystem::FD_CLOEXEC;
    }
    if (init_flags & FAN_NONBLOCK) != 0 {
        fd_flags |= crate::syscall::filesystem::O_NONBLOCK as u32;
    }
    fd_flags
}

pub(crate) fn max_queued_events_for_procfs() -> usize {
    FANOTIFY_MAX_QUEUED_EVENTS.load(Ordering::Relaxed)
}

pub(crate) fn notify_open(inode: &Arc<Inode>, is_dir: bool, path: Option<&str>) {
    notify_inode_event(inode, FAN_OPEN, is_dir, path);
}

pub(crate) fn notify_open_exec(inode: &Arc<Inode>, is_dir: bool, path: Option<&str>) {
    notify_inode_event(inode, FAN_OPEN | FAN_OPEN_EXEC, is_dir, path);
}

pub(crate) fn notify_access(inode: &Arc<Inode>, is_dir: bool, path: Option<&str>) {
    notify_inode_event(inode, FAN_ACCESS, is_dir, path);
}

pub(crate) fn notify_modify(inode: &Arc<Inode>, is_dir: bool, path: Option<&str>) {
    notify_inode_event(inode, FAN_MODIFY, is_dir, path);
}

pub(crate) fn notify_close(inode: &Arc<Inode>, writable: bool, is_dir: bool, path: Option<&str>) {
    notify_inode_event(
        inode,
        if writable {
            FAN_CLOSE_WRITE
        } else {
            FAN_CLOSE_NOWRITE
        },
        is_dir,
        path,
    );
}

pub(crate) fn permission_open(
    inode: &Arc<Inode>,
    exec: bool,
    is_dir: bool,
    path: Option<&str>,
) -> Result<(), isize> {
    notify_permission_event(
        inode,
        if exec {
            FAN_OPEN_EXEC_PERM | FAN_OPEN_PERM
        } else {
            FAN_OPEN_PERM
        },
        is_dir,
        path,
    )
}

pub(crate) fn permission_access(
    inode: &Arc<Inode>,
    is_dir: bool,
    path: Option<&str>,
) -> Result<(), isize> {
    notify_permission_event(inode, FAN_ACCESS_PERM, is_dir, path)
}

fn notify_inode_event(inode: &Arc<Inode>, mask: u64, is_dir: bool, path: Option<&str>) {
    let groups = {
        let mut groups = FANOTIFY_GROUPS.lock();
        groups.retain(|group| group.upgrade().is_some());
        groups
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<Arc<FanotifyFile>>>()
    };
    if groups.is_empty() {
        return;
    }
    let inode_key = FanotifyInodeKey::from_inode(inode);
    let event_path = path
        .map(String::from)
        .or_else(|| event_path_for_inode(inode));
    let parent_key = parent_key_for_event_path(event_path.as_deref());
    for group in groups {
        let pid = event_pid_for_group(&group);
        group.notify(
            inode.clone(),
            inode_key,
            parent_key,
            event_path.as_deref(),
            mask,
            is_dir,
            pid,
        );
    }
}

fn notify_permission_event(
    inode: &Arc<Inode>,
    mask: u64,
    is_dir: bool,
    path: Option<&str>,
) -> Result<(), isize> {
    let groups = {
        let mut groups = FANOTIFY_GROUPS.lock();
        groups.retain(|group| group.upgrade().is_some());
        groups
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<Arc<FanotifyFile>>>()
    };
    if groups.is_empty() {
        return Ok(());
    }
    let inode_key = FanotifyInodeKey::from_inode(inode);
    let event_path = path
        .map(String::from)
        .or_else(|| event_path_for_inode(inode));
    let parent_key = parent_key_for_event_path(event_path.as_deref());
    for group in groups {
        let pid = event_pid_for_group(&group);
        if let Some(permission) = group.permission_event(
            inode.clone(),
            inode_key,
            parent_key,
            event_path.as_deref(),
            mask,
            is_dir,
            pid,
        ) {
            wait_permission_response(&permission)?;
        }
    }
    Ok(())
}

fn event_pid_for_group(group: &FanotifyFile) -> i32 {
    if group.report_tid {
        current_linux_tid_for_event() as i32
    } else {
        current_process().getpid() as i32
    }
}

fn current_linux_tid_for_event() -> usize {
    let tid_index = current_task()
        .and_then(|task| task.borrow_mut().res.as_ref().map(|res| res.tid))
        .unwrap_or(0);
    encode_linux_tid(current_process().getpid(), tid_index)
}

fn event_path_for_inode(inode: &Arc<Inode>) -> Option<String> {
    let path = inode_raw_logical_path(inode)?;
    Some(translate_mount_abs(&path))
}

fn parent_key_for_event_path(path: Option<&str>) -> Option<FanotifyInodeKey> {
    let path = path?;
    let trimmed = path.trim_end_matches('/');
    if trimmed == "/" || trimmed.is_empty() {
        return None;
    }
    let parent = match trimmed.rfind('/') {
        Some(0) => "/",
        Some(pos) => &trimmed[..pos],
        None => return None,
    };
    find_path_in_roots(&translate_mount_abs(parent))
        .map(|inode| FanotifyInodeKey::from_inode(&inode))
}

fn mark_matches(
    mark: &FanotifyMark,
    inode_key: FanotifyInodeKey,
    parent_key: Option<FanotifyInodeKey>,
    event_path: Option<&str>,
    event_dev: usize,
) -> bool {
    match mark.scope {
        FanotifyMarkScope::Inode => {
            mark.target == inode_key
                || ((mark.mask | mark.ignored_mask) & FAN_EVENT_ON_CHILD) != 0
                    && parent_key.is_some_and(|key| key == mark.target)
        }
        FanotifyMarkScope::Mount => {
            mark.target_dev == event_dev
                && mark.target_path.as_ref().is_none_or(|target_path| {
                    event_path.is_some_and(|path| path_under_or_at(path, target_path))
                })
        }
        FanotifyMarkScope::Filesystem => {
            mark.target_dev == event_dev
                && mark.target_source_path.as_ref().is_none_or(|target_path| {
                    event_path.is_some_and(|path| {
                        path_under_or_at(&translate_mount_abs(path), target_path)
                    })
                })
        }
    }
}

fn path_under_or_at(path: &str, root: &str) -> bool {
    root == "/"
        || path == root
        || (path.starts_with(root) && path.as_bytes().get(root.len()) == Some(&b'/'))
}

fn fdinfo_mark_flags(mark: &FanotifyMark) -> usize {
    let mut flags = match mark.scope {
        FanotifyMarkScope::Inode => 0,
        FanotifyMarkScope::Mount => FAN_MARK_MOUNT,
        FanotifyMarkScope::Filesystem => FAN_MARK_FILESYSTEM,
    };
    if mark.ignored_mask != 0 {
        flags |= FAN_MARK_IGNORED_MASK;
    }
    if mark.ignore_survives_modify {
        flags |= FAN_MARK_IGNORED_SURV_MODIFY;
    }
    flags
}

fn mark_event_bits(mask: u64, event_mask: u64, is_dir: bool) -> u64 {
    if is_dir && (mask & FAN_ONDIR) == 0 {
        return 0;
    }
    mask & event_mask
}

fn select_permission_event(mark_mask: u64, candidates: u64) -> Option<u64> {
    if (candidates & FAN_OPEN_EXEC_PERM) != 0 && (mark_mask & FAN_OPEN_EXEC_PERM) != 0 {
        return Some(FAN_OPEN_EXEC_PERM);
    }
    if (candidates & FAN_OPEN_PERM) != 0 && (mark_mask & FAN_OPEN_PERM) != 0 {
        return Some(FAN_OPEN_PERM);
    }
    if (candidates & FAN_ACCESS_PERM) != 0 && (mark_mask & FAN_ACCESS_PERM) != 0 {
        return Some(FAN_ACCESS_PERM);
    }
    None
}

fn install_event_fd(inode: Arc<Inode>) -> Result<i32, isize> {
    let file: Arc<dyn File + Send + Sync> = Arc::new(OSInode::new_fanotify_event(inode));
    let (files, limit) = current_files_and_nofile_limit();
    let installed = files.lock().install_fd(file, 0, limit);
    installed.map(|fd| fd as i32).map_err(|rejected| {
        rejected.discard();
        err(SyscallError::EMFILE)
    })
}

fn wait_permission_response(permission: &Arc<FanotifyPermission>) -> Result<(), isize> {
    loop {
        let mut inner = permission.inner.lock();
        if let Some(response) = inner.response {
            return if (response & FAN_ALLOW) != 0 {
                Ok(())
            } else {
                Err(err(SyscallError::EACCES))
            };
        }
        let Some(task) = current_task() else {
            return Err(err(SyscallError::EAGAIN));
        };
        add_waiter_once(&mut inner.waiters, &task);
        drop(inner);
        block_current_and_run_next();
    }
}

fn wake_permission_waiters(inner: &mut FanotifyPermissionInner) {
    let mut ready = Vec::new();
    inner.waiters.retain(|waiter| {
        let Some(task) = waiter.upgrade() else {
            return false;
        };
        ready.push(task);
        false
    });
    wake_tasks(ready);
}

fn current_has_wait_interrupting_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
}

fn read_response(buf: UserBuffer) -> Option<FanotifyResponse> {
    let mut bytes = [0u8; size_of::<FanotifyResponse>()];
    let mut copied = 0usize;
    for slice in buf.buffers.iter() {
        let n = slice.len().min(bytes.len().saturating_sub(copied));
        bytes[copied..copied + n].copy_from_slice(&slice[..n]);
        copied += n;
        if copied == bytes.len() {
            break;
        }
    }
    if copied < bytes.len() {
        return None;
    }
    Some(FanotifyResponse {
        fd: i32::from_ne_bytes(bytes[0..4].try_into().ok()?),
        response: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
    })
}

fn write_metadata(buf: &mut UserBuffer, offset: usize, meta: &FanotifyEventMetadata) {
    let mut bytes = [0u8; FAN_EVENT_METADATA_LEN];
    bytes[0..4].copy_from_slice(&meta.event_len.to_ne_bytes());
    bytes[4] = meta.vers;
    bytes[5] = meta.reserved;
    bytes[6..8].copy_from_slice(&meta.metadata_len.to_ne_bytes());
    bytes[8..16].copy_from_slice(&meta.mask.to_ne_bytes());
    bytes[16..20].copy_from_slice(&meta.fd.to_ne_bytes());
    bytes[20..24].copy_from_slice(&meta.pid.to_ne_bytes());

    let mut skip = offset;
    let mut copied = 0usize;
    for slice in buf.buffers.iter_mut() {
        if skip >= slice.len() {
            skip -= slice.len();
            continue;
        }
        let start = skip;
        skip = 0;
        let n = (slice.len() - start).min(bytes.len() - copied);
        slice[start..start + n].copy_from_slice(&bytes[copied..copied + n]);
        copied += n;
        if copied == bytes.len() {
            break;
        }
    }
}

fn add_waiter_once(waiters: &mut VecDeque<Weak<TaskControlBlock>>, task: &Arc<TaskControlBlock>) {
    waiters.retain(|waiter| waiter.upgrade().is_some());
    if waiters
        .iter()
        .any(|waiter| waiter.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
    {
        return;
    }
    waiters.push_back(Arc::downgrade(task));
}

fn wake_readers(inner: &mut FanotifyInner) {
    let mut ready = Vec::new();
    inner.read_waiters.retain(|waiter| {
        let Some(task) = waiter.upgrade() else {
            return false;
        };
        ready.push(task);
        false
    });
    wake_tasks(ready);
    wake_tasks(inner.poll_waiters.take_wakeups());
}

#[repr(C)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}
