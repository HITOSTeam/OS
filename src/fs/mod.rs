//! File system in os
//!
//! 本模块是内核文件系统层的聚合入口：对外统一暴露 `File` trait 与各类文件实现，
//! 负责伪文件系统（/proc、/sys、/dev、cgroup 等）的按路径分发，以及 poll/epoll
//! 就绪等待队列等通用机制。真实数据落盘走 ext4（见 `inode` 子模块），其余多为内存态伪文件。

// ---- 各类文件实现与文件系统子模块 ----
mod cgroupfs; // cgroup v2 伪文件系统
mod dummy; // 占位/哑文件
mod eventfd; // eventfd
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
mod timerfd; // timerfd
mod tty; // tty / pty
mod userfaultfd; // userfaultfd
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
use core::{any::Any, fmt::Write};

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

fn cpu_list_from_mask(mask: usize) -> String {
    let mut out = String::new();
    let mask = if mask == 0 { 1 } else { mask };
    let mut first = true;
    let mut cpu = 0;
    while cpu < usize::BITS as usize {
        if (mask & (1usize << cpu)) == 0 {
            cpu += 1;
            continue;
        }
        let start = cpu;
        while cpu + 1 < usize::BITS as usize && (mask & (1usize << (cpu + 1))) != 0 {
            cpu += 1;
        }
        if !first {
            out.push(',');
        }
        first = false;
        if start == cpu {
            let _ = write!(out, "{}", start);
        } else {
            let _ = write!(out, "{}-{}", start, cpu);
        }
        cpu += 1;
    }
    out.push('\n');
    out
}

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

/// 判断某绝对路径是否落在内核内置的伪文件系统命名空间下（/sys、/dev、/proc/sys）。
/// 这些路径由 `open_pseudo` 提供，不走真实 ext4。
pub(crate) fn is_builtin_pseudo_path(abs: &str) -> bool {
    abs == "/sys"
        || abs.starts_with("/sys/")
        || abs == "/dev"
        || abs.starts_with("/dev/")
        || abs == "/proc/sys"
        || abs.starts_with("/proc/sys/")
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
            pseudo::PseudoDirent {
                name: String::from("class"),
                ino: 5,
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
            pseudo::PseudoDirent {
                name: String::from("net"),
                ino: 13,
                dtype: 4,
            },
        ];
        entries.extend(pseudo::pseudo_dev_dir_entries());
        return Some(Arc::new(pseudo::PseudoDir::new("/dev", entries)));
    }
    if path == "/dev/net" || path == "/dev/net/" {
        let entries = alloc::vec![
            pseudo::PseudoDirent {
                name: String::from("."),
                ino: 13,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            pseudo::PseudoDirent {
                name: String::from("tun"),
                ino: 14,
                dtype: 2,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/dev/net", entries)));
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
    if path == "/sys/class" || path == "/sys/class/" {
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
                name: String::from("net"),
                ino: 2,
                dtype: 4,
            },
        ];
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/class", entries)));
    }
    if path == "/sys/class/net" || path == "/sys/class/net/" {
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
        for (idx, (name, dtype)) in crate::syscall::net::netdev::sys_class_net_entries()
            .into_iter()
            .enumerate()
        {
            entries.push(pseudo::PseudoDirent {
                name,
                ino: (10 + idx) as u64,
                dtype,
            });
        }
        return Some(Arc::new(pseudo::PseudoDir::new("/sys/class/net", entries)));
    }
    if let Some(rest) = path.strip_prefix("/sys/class/net/") {
        let trimmed = rest.trim_end_matches('/');
        if !trimmed.is_empty() && !trimmed.contains('/') {
            if crate::syscall::net::netdev::device_snapshot_by_name(trimmed).is_some() {
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
                for (idx, (name, dtype)) in
                    crate::syscall::net::netdev::sys_class_net_device_entries(trimmed)
                        .into_iter()
                        .enumerate()
                {
                    entries.push(pseudo::PseudoDirent {
                        name: String::from(name),
                        ino: (20 + idx) as u64,
                        dtype,
                    });
                }
                return Some(Arc::new(pseudo::PseudoDir::new(path, entries)));
            }
        }
        if let Some(content) = crate::syscall::net::netdev::sys_class_net_file_content(path) {
            return Some(Arc::new(pseudo::PseudoFile::new_static(&content)));
        }
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
        return Some(Arc::new(pseudo::PseudoDir::new(
            "/sys/block/root/queue",
            entries,
        )));
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
        return Some(Arc::new(pseudo::PseudoDir::new(
            "/sys/dev/block/1:0",
            entries,
        )));
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
        let s = cpu_list_from_mask(crate::task::manager::online_hart_mask());
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
    if path == "/dev/net/tun" {
        return Some(Arc::new(pseudo::TunTapFile::new()));
    }
    if let Some(node) = pseudo::open_pseudo_dev_dir(path) {
        return Some(node);
    }
    None
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
#[allow(unused_imports)]
pub use inode::{EXT4_FS, OSInode, OpenFlags, list_apps, open_file};
pub(crate) use inode::{
    clear_ext4_path_cache, debug_track_iozone_inode, ext4_lock, ext4_path_cache_lookup,
    find_path_in_roots, inode_path_hint, inode_path_in_roots, note_ext4_path_cache,
    note_inode_path_hint, path_resolves_to_inode, register_deferred_unlink_cleanup,
    resolve_final_symlink_abs_path, resolve_final_symlink_abs_path_locked, root_inode_for_path,
    secondary_root_inode,
};
pub(crate) use mountns::{
    ClassifiedAbsPath, MountNamespace, MountNamespaceState, MountPropagation, MountRecord,
    clone_mount_namespace, initial_mount_namespace, mount_namespace_id,
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
pub(crate) use procfs::parse_proc_sys_usize;
pub(crate) use procfs::resolve_proc_magic_intermediate_abs_path;
pub(crate) use procfs::vm_max_map_count;
pub use procfs::{
    ProcMagicLinkFile, ProcPseudoFile, is_proc_pseudo_path, normalize_proc_magic_path,
    proc_fd_link_file, proc_magic_link_exists, proc_readlink, vm_commit_limit_bytes,
    vm_committed_as_bytes, vm_overcommit_memory,
};
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
pub use userfaultfd::UserfaultfdFile;
