//! File system in os
mod cgroupfs;
mod dummy;
mod inode;
mod mountns;
mod net_socket;
mod pipe;
mod procfs;
mod pseudo;
mod socketpair;
mod stdio;
mod tty;
use crate::mm::UserBuffer;
use crate::task::{
    manager::wakeup_task,
    task_block::{TaskControlBlock, TaskStatus},
};
use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::any::Any;

pub(crate) const POLLIN: i16 = 0x0001;
pub(crate) const POLLPRI: i16 = 0x0002;
pub(crate) const POLLOUT: i16 = 0x0004;
pub(crate) const POLLERR: i16 = 0x0008;
pub(crate) const POLLHUP: i16 = 0x0010;
pub(crate) const POLLNVAL: i16 = 0x0020;
pub(crate) const POLLRDHUP: i16 = 0x2000;

/// File trait
pub trait File: Send + Sync {
    /// If readable
    fn readable(&self) -> bool;
    /// If writable
    fn writable(&self) -> bool;
    /// Read file to `UserBuffer`
    fn read(&self, buf: UserBuffer) -> usize;
    /// Write `UserBuffer` to file
    fn write(&self, buf: UserBuffer) -> usize;
    /// Linux-style readiness mask used by select/poll/epoll family syscalls.
    fn poll_mask(&self) -> i16 {
        let mut mask = 0;
        if self.readable() {
            mask |= POLLIN;
        }
        if self.writable() {
            mask |= POLLOUT;
        }
        mask
    }
    /// Whether this file can be registered in an epoll set.
    fn supports_poll(&self) -> bool {
        false
    }
    /// Register a task that should be woken when this file's readiness may have changed.
    ///
    /// Returns true when the file supports a real waiter path and can actively wake the task.
    fn register_poll_waiter(&self, _task: &Arc<TaskControlBlock>) -> bool {
        false
    }
    fn as_any(&self) -> &dyn Any;
}

#[derive(Default)]
pub(crate) struct PollWaitQueue {
    waiters: VecDeque<Weak<TaskControlBlock>>,
}

impl PollWaitQueue {
    fn retain_waitable(&mut self) {
        self.waiters.retain(|waiter| {
            let Some(task) = waiter.upgrade() else {
                return false;
            };
            let inner = task.borrow_mut();
            inner.res.is_some() && inner.task_status != TaskStatus::Ready
        });
    }

    pub(crate) fn add_waiter_once(&mut self, task: &Arc<TaskControlBlock>) -> bool {
        self.retain_waitable();
        if self
            .waiters
            .iter()
            .any(|waiter| waiter.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
        {
            return false;
        }
        self.waiters.push_back(Arc::downgrade(task));
        true
    }

    pub(crate) fn register_waiter(&mut self, task: &Arc<TaskControlBlock>) -> bool {
        let _ = self.add_waiter_once(task);
        true
    }

    pub(crate) fn has_waiters(&mut self) -> bool {
        self.retain_waitable();
        !self.waiters.is_empty()
    }

    pub(crate) fn take_wakeups(&mut self) -> Vec<Arc<TaskControlBlock>> {
        self.retain_waitable();
        self.waiters
            .drain(..)
            .filter_map(|waiter| waiter.upgrade())
            .collect()
    }
}

pub(crate) fn wake_tasks(tasks: Vec<Arc<TaskControlBlock>>) {
    for task in tasks {
        wakeup_task(task);
    }
}

pub use cgroupfs::{
    CgroupFile, CgroupMountSpec, cgroup_attach_fork_child, cgroup_attach_thread,
    cgroup_charge_anon_current, cgroup_charge_file_write, cgroup_current_path, cgroup_exit_process,
    cgroup_exit_thread, cgroup_fork_precheck, cgroup_logical_path_for_file,
    cgroup_maybe_block_current, cgroup_mkdir, cgroup_mount, cgroup_proc_cgroups_content,
    cgroup_proc_pid_content, cgroup_rename, cgroup_rmdir, cgroup_umount, is_cgroup_pseudo_path,
    legacy_cpu_fair_group, open_cgroup_pseudo,
};
pub use dummy::{
    DummyFile, EventFdFile, NamespaceFile, NamespaceKind, PidFdFile, TimerFdFile, UserfaultfdFile,
};
pub(crate) use dummy::{
    cancel_realtime_timerfds_on_set, has_pending_timerfds, process_timerfd_expirations,
    wake_pidfd_poll_waiters,
};
pub use inode::{EXT4_FS, OSInode, OpenFlags, ROOT_INODE, USER_INODE, list_apps, open_file};
pub(crate) use inode::{
    debug_track_iozone_inode, ext4_lock, find_path_in_roots, register_deferred_unlink_cleanup,
    root_inode_for_path, secondary_root_inode,
};
pub(crate) use mountns::{
    MountNamespace, MountNamespaceState, MountPropagation, MountRecord, clone_mount_namespace,
    initial_mount_namespace, mount_namespace_id,
};
pub(crate) use net_socket::notify_net_poll_events;
pub use net_socket::{NetSocketFile, NetSocketKind};
pub(crate) use pipe::remove_task_waiters as remove_pipe_waiters_for_task;
pub use pipe::{
    Pipe, debug_count_task_waiters as debug_count_pipe_waiters_for_task, make_pipe,
    pipe_max_size_limit_for_procfs, write_pipe_sysctl,
};
pub(crate) use procfs::parse_proc_sys_usize;
pub use procfs::{
    ProcMagicLinkFile, ProcMagicLinkFollowTarget, ProcPseudoFile, is_proc_pseudo_path,
    normalize_proc_magic_path, open_proc_pseudo, proc_fd_link_file, proc_magic_link_exists,
    proc_magic_link_follow_target, proc_readlink, vm_commit_limit_bytes, vm_committed_as_bytes,
    vm_overcommit_memory,
};
pub use pseudo::PseudoBlock;
pub use pseudo::{PseudoDir, PseudoDirent, PseudoFile, PseudoKindTag, PseudoShmFile, RtcFile};
pub(crate) use pseudo::{
    open_pseudo_dev_dir, pseudo_block_is_read_only, pseudo_block_note_sync,
    pseudo_block_read_ahead, pseudo_block_set_read_ahead, pseudo_block_set_read_only,
    pseudo_block_stat_snapshot, pseudo_dev_dir_entries, pseudo_dev_dir_exists,
    pseudo_dev_dir_mkdir, pseudo_dev_dir_rmdir, shm_create, shm_create_anonymous, shm_get,
    shm_list, shm_remove,
};
pub use socketpair::{SocketPairEnd, make_socketpair};
pub use stdio::{Stdin, Stdout};
pub use tty::{
    LinuxTermio, LinuxTermios, PtyMasterFile, PtySlaveFile, TtyFile, list_dev_pts, open_dev_ptmx,
    open_dev_pts, open_dev_tty,
};
