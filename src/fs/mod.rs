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
    string::String,
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

pub(crate) fn shm_object_name(abs: &str) -> Option<&str> {
    // Only accept `/dev/shm/<name>` (single path component).
    let rest = abs.strip_prefix("/dev/shm/")?;
    let name = rest.trim_start_matches('/');
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some(name)
}

pub(crate) fn is_builtin_pseudo_path(abs: &str) -> bool {
    abs == "/sys"
        || abs.starts_with("/sys/")
        || abs == "/dev"
        || abs.starts_with("/dev/")
        || abs == "/proc/sys"
        || abs.starts_with("/proc/sys/")
        || abs == "/etc"
        || abs.starts_with("/etc/")
}

pub(crate) fn open_pseudo(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    if let Some(node) = cgroupfs::open_cgroup_pseudo(path) {
        return Some(node);
    }
    if let Some(node) = procfs::open_proc_pseudo(path) {
        return Some(node);
    }
    if path == "/sys" || path == "/sys/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("devices"),
                ino: 2,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("block"),
                ino: 3,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("dev"),
                ino: 4,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys", entries)));
    }
    if path == "/dev" || path == "/dev/" {
        let mut entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("root"),
                ino: 6,
                dtype: 6,
            },
            pseudo::PseudoDirent {
                name: String::from("ptmx"),
                ino: 9,
                dtype: 2,
            },
            pseudo::PseudoDirent {
                name: String::from("tty"),
                ino: 10,
                dtype: 2,
            },
            pseudo::PseudoDirent {
                name: String::from("pts"),
                ino: 11,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("shm"),
                ino: 8,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("cgroup"),
                ino: 12,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("null"),
                ino: 2,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("zero"),
                ino: 3,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("urandom"),
                ino: 4,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("random"),
                ino: 5,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("misc"),
                ino: 7,
                dtype: 4,
            },
        ];
        entries.extend(pseudo::pseudo_dev_dir_entries());
        return Some(Arc::new(pseudo::PseudoDir::new("/dev", entries)));
    }
    if path == "/dev/cgroup" || path == "/dev/cgroup/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 12,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/cgroup", entries)));
    }
    if path == "/dev/pts" || path == "/dev/pts/" {
        let mut entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
        ];
        for idx in tty::list_dev_pts() {
            entries.push(pseudo::PseudoDirent {
                name: alloc::format!("{}", idx),
                ino: 2000 + idx as u64,
                dtype: 2,
            });
        }
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/pts", entries)));
    }
    if let Some(rest) = path.strip_prefix("/dev/pts/") {
        if !rest.is_empty() && !rest.contains('/') && rest.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(idx) = rest.parse::<u32>() {
                if let Some(node) = tty::open_dev_pts(idx) {
                    return Some(node);
                }
            }
        }
    }
    if path == "/dev/shm" || path == "/dev/shm/" {
        let mut entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
        ];
        for (idx, name) in pseudo::shm_list().into_iter().enumerate() {
            entries.push(pseudo::PseudoDirent {
                name,
                ino: (1000 + idx) as u64,
                dtype: 8,
            });
        }
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/shm", entries)));
    }
    if path == "/dev/misc" || path == "/dev/misc/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("rtc"),
                ino: 2,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/misc", entries)));
    }
    if path == "/etc" || path == "/etc/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("passwd"),
                ino: 2,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("group"),
                ino: 3,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/etc", entries)));
    }
    if path == "/etc/passwd" {
        return Some(Arc::new(pseudo::PseudoFile::new_static(
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:\n",
        )));
    }
    if path == "/etc/group" {
        return Some(Arc::new(pseudo::PseudoFile::new_static(
            "root:x:0:\ndaemon:x:1:\nusers:x:100:\nnobody:x:65534:\nnogroup:x:65534:\n",
        )));
    }

    if path == "/sys/block" || path == "/sys/block/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("root"),
                ino: 2,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/block", entries)));
    }
    if path == "/sys/block/root" || path == "/sys/block/root/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("queue"),
                ino: 2,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("size"),
                ino: 3,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("stat"),
                ino: 4,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("dev"),
                ino: 5,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("removable"),
                ino: 6,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/block/root", entries)));
    }
    if path == "/sys/block/root/queue" || path == "/sys/block/root/queue/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("logical_block_size"),
                ino: 2,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("physical_block_size"),
                ino: 3,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("minimum_io_size"),
                ino: 4,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("optimal_io_size"),
                ino: 5,
                dtype: 8,
            },
            pseudo::PseudoDirent {
                name: String::from("dma_alignment"),
                ino: 6,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/block/root/queue", entries)));
    }
    if path == "/sys/block/root/size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("2097152\n")));
    }
    if path == "/sys/block/root/stat" {
        let stat = pseudo::pseudo_block_stat_snapshot();
        return Some(Arc::new(pseudo::PseudoFile::new_static(&stat)));
    }
    if path == "/sys/block/root/dev" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("1:0\n")));
    }
    if path == "/sys/block/root/removable" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("0\n")));
    }
    if path == "/sys/block/root/queue/logical_block_size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("512\n")));
    }
    if path == "/sys/block/root/queue/physical_block_size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("4096\n")));
    }
    if path == "/sys/block/root/queue/minimum_io_size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("512\n")));
    }
    if path == "/sys/block/root/queue/optimal_io_size" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("0\n")));
    }
    if path == "/sys/block/root/queue/dma_alignment" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("0\n")));
    }
    if path == "/sys/dev" || path == "/sys/dev/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("block"),
                ino: 2,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/dev", entries)));
    }
    if path == "/sys/dev/block" || path == "/sys/dev/block/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("1:0"),
                ino: 2,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/dev/block", entries)));
    }
    if path == "/sys/dev/block/1:0" || path == "/sys/dev/block/1:0/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("uevent"),
                ino: 2,
                dtype: 8,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/dev/block/1:0", entries)));
    }
    if path == "/sys/dev/block/1:0/uevent" {
        return Some(Arc::new(pseudo::PseudoFile::new_static(
            "MAJOR=1\nMINOR=0\nDEVNAME=root\nDEVTYPE=disk\n",
        )));
    }

    if path == "/sys/devices/system/cpu/possible"
        || path == "/sys/devices/system/cpu/present"
        || path == "/sys/devices/system/cpu/online"
    {
        let n = crate::config::MAX_HARTS;
        let s = if n == 0 {
            String::from("\n")
        } else if n == 1 {
            String::from("0\n")
        } else {
            alloc::format!("0-{}\n", n - 1)
        };
        return Some(Arc::new(pseudo::PseudoFile::new_static(&s)));
    }
    if path == "/sys/devices/system/cpu/kernel_max" {
        let n = crate::config::MAX_HARTS;
        let s = if n == 0 {
            String::from("0\n")
        } else {
            alloc::format!("{}\n", n - 1)
        };
        return Some(Arc::new(pseudo::PseudoFile::new_static(&s)));
    }
    if path == "/sys/devices/system/node/online" || path == "/sys/devices/system/node/possible" {
        return Some(Arc::new(pseudo::PseudoFile::new_static("0\n")));
    }
    if path == "/dev/ptmx" {
        return Some(tty::open_dev_ptmx());
    }
    if path == "/dev/tty" {
        return Some(tty::open_dev_tty());
    }
    if path == "/dev/root" {
        return Some(Arc::new(pseudo::PseudoBlock::new()));
    }
    if let Some(name) = shm_object_name(path) {
        let data = pseudo::shm_get(name)?;
        return Some(Arc::new(pseudo::PseudoShmFile::new(data)));
    }
    if path == "/dev/null" {
        return Some(Arc::new(pseudo::PseudoFile::new_null()));
    }
    if path == "/dev/zero" {
        return Some(Arc::new(pseudo::PseudoFile::new_zero()));
    }
    if path == "/dev/urandom" || path == "/dev/random" {
        let seed =
            (crate::time::get_time() as u64) ^ ((crate::task::processor::hart_id() as u64) << 32);
        return Some(Arc::new(pseudo::PseudoFile::new_urandom(seed)));
    }
    if path == "/dev/misc/rtc" {
        return Some(Arc::new(pseudo::RtcFile::new()));
    }
    if let Some(node) = pseudo::open_pseudo_dev_dir(path) {
        return Some(node);
    }
    None
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
    debug_track_iozone_inode, ext4_lock, find_path_in_roots, inode_path_hint,
    inode_path_in_roots, note_inode_path_hint, path_resolves_to_inode,
    register_deferred_unlink_cleanup, resolve_final_symlink_abs_path,
    resolve_final_symlink_abs_path_locked, root_inode_for_path, secondary_root_inode,
};
pub(crate) use mountns::{
    ClassifiedAbsPath, MountNamespace, MountNamespaceState, MountPropagation, MountRecord,
    clone_mount_namespace, initial_mount_namespace, mount_namespace_id,
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
    ProcMagicLinkFile, ProcPseudoFile, is_proc_pseudo_path, normalize_proc_magic_path,
    proc_fd_link_file, proc_magic_link_exists, proc_readlink, vm_commit_limit_bytes,
    vm_committed_as_bytes, vm_overcommit_memory,
};
pub(crate) use procfs::resolve_proc_magic_intermediate_abs_path;
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
