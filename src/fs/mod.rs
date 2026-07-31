//! File system in os
//!
//! 本模块是内核文件系统层的聚合入口：对外统一暴露 `File` trait 与各类文件实现，
//! 连接过渡期 pathname 分发，并提供 poll/epoll 就绪等待队列等通用机制。通用
//! 对象模型位于 `vfs`，ext4、tmpfs、procfs、sysfs、devtmpfs 与 cgroupfs 均为
//! 同级具体后端。

// ---- 各类文件实现与文件系统子模块 ----
mod cgroupfs; // cgroup 文件系统视图；领域状态将在节点化时继续拆分
mod devtmpfs; // /dev 设备文件系统视图
mod dummy; // 占位/哑文件
mod eventfd; // eventfd
#[cfg(target_os = "none")]
#[allow(dead_code)]
pub(crate) mod ext4; // ext4 对对象 VFS 的具体适配器
mod fanotify; // fanotify notification groups
mod inode; // ext4 真实文件 inode 与打开逻辑
mod mountns; // 挂载命名空间
mod namespace_file; // /proc/[pid]/ns/* 命名空间文件
mod net_socket; // 网络 socket 文件
mod pidfd; // pidfd
mod pipe; // 匿名/命名管道
mod procfs; // /proc 伪文件系统
mod pseudo; // 通用伪文件/伪目录（/sys、/dev 等）
mod socketpair; // socketpair 两端
mod stdio; // 标准输入输出
mod sysfs; // /sys 内核对象文件系统视图
mod timerfd; // timerfd
#[allow(dead_code)]
pub(crate) mod tmpfs; // 独立实例的内存文件系统实现
mod tty; // tty / pty
mod userfaultfd; // userfaultfd
#[allow(dead_code)]
pub(crate) mod vfs; // 仅包含对象模型、dcache、mount graph 与 REF-walk
use crate::mm::UserBuffer;
use crate::task::{
    manager::wakeup_tasks,
    processor::current_process,
    task_block::{TaskControlBlock, TaskStatus},
};
use alloc::{
    collections::VecDeque,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::any::Any;

// ---- poll/select/epoll 就绪事件位（对应 Linux <poll.h> 的 POLL* 常量）----
/// 有数据可读。
pub(crate) const POLLIN: i16 = 0x0001;
/// 有紧急（带外）数据可读。
pub(crate) const POLLPRI: i16 = 0x0002;
/// 可写而不阻塞。
pub(crate) const POLLOUT: i16 = 0x0004;
/// 发生错误条件（始终被 poll 返回，无需在 events 中请求）。
pub(crate) const POLLERR: i16 = 0x0008;
/// 对端挂断/连接关闭。
pub(crate) const POLLHUP: i16 = 0x0010;
/// 传入的 fd 非法（始终被返回）。
pub(crate) const POLLNVAL: i16 = 0x0020;
/// 对端关闭了写方向（半关闭）。
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
    /// Return a readiness mask that is stable for this file object without
    /// consulting mutable device state.  Callers may use this while holding the
    /// descriptor-table lock to avoid cloning file references for always-ready
    /// files such as regular inodes.
    fn fixed_poll_mask(&self) -> Option<i16> {
        None
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
    /// Called when this file object is installed into a descriptor table.
    fn on_fd_install(&self) {}
    /// Called when a descriptor table semantically closes one reference to this file object.
    fn on_fd_close(&self) {}
    /// 向下转型支持：返回 `&dyn Any`，便于按具体文件类型 downcast。
    fn as_any(&self) -> &dyn Any;
}

/// `poll`/`epoll`/`select` I/O 就绪等待队列。
///
/// 当任务调用 `epoll_wait`/`select` 阻塞等待某个文件就绪时，通过
/// `register_waiter` 将自身注册到对应文件的 `PollWaitQueue` 中。
/// 文件状态发生变化（如 pipe 有数据写入、timer 到期）时，调用
/// `take_wakeups` 取出所有等待者并交给调度器唤醒。
///
/// 与 `read_waiters`/`write_waiters` 的区别：后者阻塞的是 `read`/`write`
/// 系统调用本身（等待数据），本队列阻塞的是 `epoll_wait` 等就绪通知机制。
/// 对应 Linux 内核中 `poll_wait` + `wait_queue_head_t` 的用法。
#[derive(Default)]
pub(crate) struct PollWaitQueue {
    /// 等待就绪通知的任务列表。使用弱引用，避免阻止任务被正常释放。
    /// 在每次操作前通过 `retain_waitable` 清理已失效或已就绪的条目。
    waiters: VecDeque<Weak<TaskControlBlock>>,
}

impl PollWaitQueue {
    /// 清理队列中已失效（task 已释放）或已不再需要等待（已有结果且非 Ready 状态）的条目。
    /// 每次读写队列前调用，防止积累无效弱引用。
    fn retain_waitable(&mut self) {
        self.waiters.retain(|waiter| {
            let Some(task) = waiter.upgrade() else {
                return false;
            };
            let inner = task.borrow_mut();
            inner.res.is_some() && inner.task_status != TaskStatus::Ready
        });
    }

    /// 将 `task` 加入等待队列（去重）。
    /// 若 `task` 已在队列中则返回 `false`，否则加入并返回 `true`。
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

    /// 注册等待者，忽略重复注册，始终返回 `true` 表示支持 poll。
    pub(crate) fn register_waiter(&mut self, task: &Arc<TaskControlBlock>) -> bool {
        let _ = self.add_waiter_once(task);
        true
    }

    /// 返回当前是否有有效的等待者（清理无效条目后判断）。
    pub(crate) fn has_waiters(&mut self) -> bool {
        self.retain_waitable();
        !self.waiters.is_empty()
    }

    /// 取出所有有效等待者并清空队列，供调用方调用 `wake_tasks` 唤醒。
    /// 调用后队列为空；等待者需在文件就绪时重新注册。
    pub(crate) fn take_wakeups(&mut self) -> Vec<Arc<TaskControlBlock>> {
        self.retain_waitable();
        self.waiters
            .drain(..)
            .filter_map(|waiter| waiter.upgrade())
            .collect()
    }
}

/// 批量唤醒一组任务（通常配合 `PollWaitQueue::take_wakeups` 使用）。
pub(crate) fn wake_tasks(tasks: Vec<Arc<TaskControlBlock>>) {
    wakeup_tasks(tasks);
}

/// 从绝对路径中解析 POSIX 共享内存对象名。
/// 仅接受形如 `/dev/shm/<name>` 的单层路径（name 非空且不含 `/`），否则返回 None。
pub(crate) fn shm_object_name(abs: &str) -> Option<&str> {
    // Only accept `/dev/shm/<name>` (single path component).
    let rest = abs.strip_prefix("/dev/shm/")?;
    let name = rest.trim_start_matches('/');
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some(name)
}

/// 把内核内部的绝对路径翻译成当前进程挂载命名空间下用户可见的显示路径。
pub(crate) fn current_mount_display_abs(abs: &str) -> String {
    let ns = current_process().mount_namespace();
    let state = ns.lock();
    state.display_mount_abs(abs)
}

pub(crate) fn mounted_file_for_abs(abs: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let ns = current_process().mount_namespace();
    let state = ns.lock();
    state.bound_file_for_path(abs)
}

/// Resolve a logical path through the currently selected virtual mount.
pub(crate) fn current_pseudo_canonical_abs(abs: &str) -> Option<(mountns::MountRecord, String)> {
    let ns = current_process().mount_namespace();
    let state = ns.lock();
    state.canonical_pseudo_abs(abs)
}

fn current_proc_provider_abs(abs: &str) -> Option<(mountns::MountRecord, String, String)> {
    let (mount, canonical) = current_pseudo_canonical_abs(abs)?;
    let pid_namespace_id = match &mount.backend {
        mountns::MountBackend::Proc { pid_namespace_id } => *pid_namespace_id,
        _ => return None,
    };
    let provider = procfs::proc_provider_path_for_namespace(&canonical, pid_namespace_id)?;
    Some((mount, canonical, provider))
}

pub(crate) fn mounted_proc_provider_path(abs: &str) -> Option<String> {
    current_proc_provider_abs(abs).map(|(_, _, provider)| provider)
}

pub(crate) fn mounted_proc_magic_link_exists(abs: &str) -> bool {
    let Some((_mount, canonical, provider)) = current_proc_provider_abs(abs) else {
        return false;
    };
    canonical == "/proc/self"
        || canonical == "/proc/thread-self"
        || procfs::proc_magic_link_exists(&provider)
}

pub(crate) fn mounted_proc_fd_link_file(abs: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let (_, _, provider) = current_proc_provider_abs(abs)?;
    procfs::proc_fd_link_file(&provider)
}

pub(crate) fn mounted_proc_readlink(abs: &str) -> Option<String> {
    let (mount, canonical, provider) = current_proc_provider_abs(abs)?;
    let pid_namespace_id = match &mount.backend {
        mountns::MountBackend::Proc { pid_namespace_id } => *pid_namespace_id,
        _ => return None,
    };
    if canonical == "/proc/self" {
        let process = current_process();
        let pid = crate::task::process_pid_in_pid_namespace(&process, pid_namespace_id)?;
        return Some(alloc::format!("{pid}"));
    }
    if canonical == "/proc/thread-self" {
        let process = current_process();
        let global_pid = process.getpid();
        let visible_pid = crate::task::process_pid_in_pid_namespace(&process, pid_namespace_id)?;
        let target = procfs::proc_readlink("/proc/thread-self")?;
        return Some(target.replacen(
            &alloc::format!("{global_pid}/"),
            &alloc::format!("{visible_pid}/"),
            1,
        ));
    }
    procfs::proc_readlink(&provider)
}

/// 根据 inode 的路径提示反查其逻辑路径，并转换为当前挂载命名空间下的可见路径。
pub(crate) fn inode_logical_path(inode: &Arc<ext4_fs::Inode>) -> Option<String> {
    inode::inode_path_hint(inode).map(|path| current_mount_display_abs(&path))
}

/// 返回 inode 记录的原始逻辑路径，不经过当前挂载命名空间的显示路径转换。
pub(crate) fn inode_raw_logical_path(inode: &Arc<ext4_fs::Inode>) -> Option<String> {
    inode::inode_path_hint(inode)
}

/// 伪文件系统的按路径打开分发器。
///
/// 依次尝试 cgroup、procfs，然后按固定路径表匹配 `/sys`、`/dev`、`/sys/block`、
/// `/sys/devices/...` 等伪目录/伪文件，以及 `/dev/{null,zero,urandom,ptmx,tty,...}`
/// 和 `/dev/shm/<name>` 共享内存对象。命中则返回对应的 `File` 实现，未命中返回 None
/// （交由上层走真实文件系统）。
pub(crate) fn open_pseudo(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    if let Some(node) = mounted_file_for_abs(path) {
        return Some(node);
    }
    let ns = current_process().mount_namespace();
    let (mount, canonical) = {
        let state = ns.lock();
        let mount = state.mount_record_for_path(path)?;
        if matches!(mount.backend, mountns::MountBackend::Cgroup) {
            drop(state);
            return cgroupfs::open_cgroup_pseudo(path);
        }
        state.canonical_pseudo_abs(path)?
    };

    let node = match mount.backend {
        mountns::MountBackend::Proc { pid_namespace_id } => {
            procfs::open_proc_pseudo_in(&canonical, pid_namespace_id)?
        }
        _ => open_canonical_pseudo(&canonical)?,
    };
    if canonical == path {
        return Some(node);
    }
    if let Some(dir) = node.as_any().downcast_ref::<pseudo::PseudoDir>() {
        return Some(Arc::new(dir.remapped(path)));
    }
    Some(node)
}

/// Dispatch a path in the canonical namespace used internally by the existing
/// virtual filesystem providers. Callers must first select a mounted backend.
fn open_canonical_pseudo(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    procfs::open_proc_pseudo(path)
        .or_else(|| sysfs::open_legacy(path))
        .or_else(|| devtmpfs::open_legacy(path))
}

// ---- 子模块的对外重导出（汇总各文件系统/文件类型供 crate 其余部分使用）----
pub(crate) use cgroupfs::{
    CgroupAttachTarget, cgroup_attach_process_to_target, cgroup_clone_into_target_from_file,
};
pub use cgroupfs::{
    CgroupFile, CgroupMountSpec, cgroup_attach_fork_child, cgroup_attach_thread,
    cgroup_charge_anon_current, cgroup_charge_file_write, cgroup_current_path, cgroup_exit_process,
    cgroup_exit_thread, cgroup_fork_precheck, cgroup_logical_path_for_file,
    cgroup_maybe_block_current, cgroup_mkdir, cgroup_mount, cgroup_proc_cgroups_content,
    cgroup_proc_pid_content, cgroup_rename, cgroup_rmdir, cgroup_umount, is_cgroup_pseudo_path,
    refresh_thread_legacy_cpu_fair_group_cache,
};
pub use dummy::{DummyFile, SignalfdFile};
pub use eventfd::EventFdFile;
pub(crate) use fanotify::{
    FanotifyFile, fanotify_descriptor_flags,
    max_queued_events_for_procfs as fanotify_max_queued_events_for_procfs,
    notify_access as fanotify_notify_access, notify_close as fanotify_notify_close,
    notify_modify as fanotify_notify_modify, notify_open as fanotify_notify_open,
    notify_open_exec as fanotify_notify_open_exec, permission_access as fanotify_permission_access,
    permission_open as fanotify_permission_open,
};
#[allow(unused_imports)]
pub use inode::{EXT4_FS, OSInode, OpenFlags, list_apps, open_file};
pub(crate) use inode::{
    ExecInodeReservation, block_device_source_path, clear_ext4_path_cache,
    debug_track_iozone_inode, ensure_root_mount_directory, ext4_inode_lock, ext4_topology_lock,
    find_path_in_roots, inode_path_hint, inode_path_in_roots, invalidate_ext4_path_cache,
    invalidate_ext4_path_cache_inode, invalidate_ext4_path_cache_subtree,
    is_inode_currently_executed, note_ext4_path_cache, note_inode_path_hint,
    path_resolves_to_inode, path_within_filesystem, register_deferred_unlink_cleanup,
    register_executing_inode, resolve_final_symlink_abs_path,
    resolve_final_symlink_abs_path_locked, root_inode_for_device, root_inode_for_path,
    unregister_executing_inode, with_ext4_inode_read, with_ext4_inode_write,
    with_ext4_inode_write_set,
};
pub(crate) use inode::{
    discard_inode_pending_writes_after_truncate, flush_inode_pending_writes_before_truncate,
    pending_inode_write_end,
};
pub(crate) use mountns::{
    ClassifiedAbsPath, FdMountRef, MountBackend, MountNamespace, MountNamespaceState,
    MountPropagation, MountRecord, clone_mount_namespace, initial_mount_namespace,
    mount_namespace_id,
};
pub(crate) use namespace_file::net_namespace_file_refs;
pub use namespace_file::{NamespaceFile, NamespaceKind};
pub use net_socket::{Ipv4SourceFilterMode, NetSocketFile, NetSocketKind, ProcNetSocketSnapshot};
pub(crate) use net_socket::{
    cleanup_net_namespace as cleanup_net_socket_namespace, debug_net_socket_atomic_heap_state,
    notify_net_poll_events_in,
};
pub use pidfd::PidFdFile;
pub(crate) use pidfd::wake_pidfd_poll_waiters;
pub(crate) use pipe::remove_task_waiters as remove_pipe_waiters_for_task;
pub use pipe::{
    Pipe, debug_count_task_waiters as debug_count_pipe_waiters_for_task, make_pipe,
    pipe_max_size_limit_for_procfs, write_pipe_sysctl,
};
pub(crate) use procfs::resolve_proc_magic_intermediate_abs_path;
pub(crate) use procfs::vm_max_map_count;
pub use procfs::{
    ProcMagicLinkFile, ProcPseudoFile, is_proc_pseudo_path, normalize_proc_magic_path,
    proc_fd_link_file, proc_magic_link_exists, proc_readlink, vm_commit_limit_bytes,
    vm_committed_as_bytes, vm_overcommit_memory,
};
pub(crate) use procfs::{parse_proc_sys_usize, proc_provider_path_for_namespace};
pub use pseudo::PseudoBlock;
pub use pseudo::TunTapFile;
pub use pseudo::{PseudoDir, PseudoDirent, PseudoFile, PseudoKindTag, PseudoShmFile, RtcFile};
pub(crate) use pseudo::{
    enqueue_tuntap_packet, pseudo_block_is_read_only, pseudo_block_note_sync,
    pseudo_block_read_ahead, pseudo_block_set_read_ahead, pseudo_block_set_read_only,
    pseudo_dev_dir_exists, pseudo_dev_dir_mkdir, pseudo_dev_dir_rmdir, shm_create,
    shm_create_anonymous, shm_get, shm_remove,
};
pub(crate) use pseudo::{tuntap_link_owner_group, tuntap_link_sysfs_info};
pub use socketpair::{SocketPairEnd, make_socketpair, make_socketpair_with_type};
pub use stdio::{Stdin, Stdout};
pub use timerfd::TimerFdFile;
pub(crate) use timerfd::{
    cancel_realtime_timerfds_on_set, process_timerfd_expirations,
    timerfd_work_pending_for_user_return,
};
pub use tty::{
    LinuxTermio, LinuxTermios, LinuxWinSize, PtyMasterFile, PtySlaveFile, TtyFile, dev_pts_exists,
    dev_pts_index_from_path,
};
pub use userfaultfd::{UserfaultfdFile, userfaultfd_active};
