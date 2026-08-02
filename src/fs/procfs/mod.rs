//! procfs filesystem view.
//!
//! procfs is a concrete VFS backend and therefore remains a sibling of
//! `fs::vfs`, rather than becoming part of its generic object model.  This
//! Its VFS adapter performs component lookup and returns `VfsPath` targets for
//! proc magic links.  The older path-shaped provider is now only an internal
//! node-construction detail; pathname syscalls never dispatch through it.
//! Process and PID-namespace state stays owned by the task layer.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use crate::fs::File;
use crate::mm::UserBuffer;
use crate::syscall::error::{SyscallError, err};

pub(crate) mod content;
pub(crate) mod entries;
pub(crate) mod magic_link;
pub(crate) mod open;
#[allow(dead_code)]
pub(crate) mod vfs;

pub use content::{vm_commit_limit_bytes, vm_committed_as_bytes, vm_overcommit_memory};
pub(crate) use entries::{net_core_busy_poll_usecs, net_core_busy_read_usecs, vm_max_map_count};
pub use magic_link::{normalize_proc_magic_path, proc_magic_link_exists, proc_readlink};
pub(crate) use open::{open_proc_pseudo_in, proc_provider_path_for_namespace};

#[derive(Clone, Copy, Debug)]
pub enum ProcFileKind {
    Mounts,
    Mountinfo,
    Filesystems,
    Cgroups,
    Meminfo,
    Cpuinfo,
    Cmdline,
    Interrupts,
    Loadavg,
    Uptime,
    Stat,
    Perf,
    Kallsyms,
    Kpageflags,
    Modules,
    NetDev,
    NetDevMcast,
    NetIfInet6,
    NetRoute,
    NetArp,
    NetIgmp,
    NetSnmp,
    NetNetstat,
    NetSockstat,
    NetTcp,
    NetUdp,
    NetRaw,
    NetUnix,
    NetNetlink,
    SysvipcMsg,
    SysvipcSem,
    SysvipcShm,
    VmMinFreeKbytes,
    VmOvercommitMemory,
    VmOvercommitRatio,
    VmDropCaches,
    VmCompactMemory,
    FsFileMax,
    FsPipeMaxSize,
    FsFanotifyMaxQueuedEvents,
    FsMqueueQueuesMax,
    KernelPidMax,
    KernelMsgmax,
    KernelMsgmnb,
    KernelMsgmni,
    KernelSem,
    KernelShmmax,
    KernelShmmni,
    KernelShmall,
    KernelSchedRtPeriodUs,
    KernelSchedRtRuntimeUs,
    KernelSchedRrTimesliceMs,
    SimpleText(&'static str),
    PidStat(u32),
    PidCmdline(u32),
    PidStatus(u32),
    PidComm(u32),
    PidUidMap(u32),
    PidGidMap(u32),
    PidSetgroups(u32),
    PidMaps(u32),
    PidPagemap(u32),
    PidSmaps(u32),
    PidCoredumpFilter,
    PidMounts(u32),
    PidMountinfo(u32),
    PidCgroup(u32),
    PidFdInfo(u32, usize),
    PidTaskStat(u32, u32),
    PidTaskComm(u32, u32),
}

struct ProcPseudoInner {
    offset: usize,
    cache: Option<String>,
}

pub struct ProcPseudoFile {
    kind: ProcFileKind,
    inner: Mutex<ProcPseudoInner>,
}

pub struct ProcMagicLinkFile {
    link_path: String,
    target_len_hint: usize,
}

impl ProcPseudoFile {
    pub fn new(kind: ProcFileKind) -> Arc<Self> {
        Arc::new(Self {
            kind,
            inner: Mutex::new(ProcPseudoInner {
                offset: 0,
                cache: None,
            }),
        })
    }

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        let mut inner = self.inner.lock();
        inner.offset = offset;
        inner.cache = None;
    }

    pub fn seek_end(&self) -> isize {
        proc_file_len(&self.kind) as isize
    }

    pub fn len(&self) -> Option<usize> {
        Some(proc_file_len(&self.kind))
    }

    /// Read without using the transitional file object's cursor.  Linux keeps
    /// `f_pos` in `struct file`; the object VFS mirrors that by passing an
    /// explicit offset into backend operations.
    pub(crate) fn pread_bytes(&self, offset: usize, output: &mut [u8]) -> usize {
        match self.kind {
            ProcFileKind::PidPagemap(pid) => {
                return content::proc_pid_pagemap_read_at(pid, offset, output);
            }
            ProcFileKind::Kpageflags => {
                return content::proc_kpageflags_read_at(offset, output);
            }
            _ => {}
        }
        let mut inner = self.inner.lock();
        if inner.cache.is_none() {
            inner.cache = Some(content::proc_file_content(&self.kind));
        }
        let bytes = inner
            .cache
            .as_ref()
            .expect("proc cache populated")
            .as_bytes();
        if offset >= bytes.len() {
            return 0;
        }
        let read = core::cmp::min(output.len(), bytes.len() - offset);
        output[..read].copy_from_slice(&bytes[offset..offset + read]);
        read
    }

    pub fn pwrite_bytes(&self, offset: usize, data: &[u8]) -> Result<usize, isize> {
        if offset != 0 {
            return Err(err(SyscallError::EINVAL));
        }
        let _normalized = match self.kind {
            ProcFileKind::VmMinFreeKbytes => {
                content::write_vm_sysctl("/proc/sys/vm/min_free_kbytes", data)?
            }
            ProcFileKind::VmOvercommitMemory => {
                content::write_vm_sysctl("/proc/sys/vm/overcommit_memory", data)?
            }
            ProcFileKind::VmOvercommitRatio => {
                content::write_vm_sysctl("/proc/sys/vm/overcommit_ratio", data)?
            }
            ProcFileKind::VmDropCaches => {
                entries::write_vm_trigger_sysctl("/proc/sys/vm/drop_caches", data)?
            }
            ProcFileKind::VmCompactMemory => {
                entries::write_vm_trigger_sysctl("/proc/sys/vm/compact_memory", data)?
            }
            ProcFileKind::FsFileMax => content::write_fs_file_max_sysctl(data)?,
            ProcFileKind::FsPipeMaxSize => {
                crate::fs::write_pipe_sysctl("/proc/sys/fs/pipe-max-size", data)?
            }
            ProcFileKind::FsFanotifyMaxQueuedEvents => return Err(err(SyscallError::EINVAL)),
            ProcFileKind::FsMqueueQueuesMax => crate::syscall::posix_mq::write_mqueue_sysctl(
                "/proc/sys/fs/mqueue/queues_max",
                data,
            )?,
            ProcFileKind::KernelPidMax => entries::write_pid_max_sysctl(data)?,
            ProcFileKind::KernelMsgmax => {
                crate::syscall::sysv_ipc::write_msg_sysctl("/proc/sys/kernel/msgmax", data)?
            }
            ProcFileKind::KernelMsgmnb => {
                crate::syscall::sysv_ipc::write_msg_sysctl("/proc/sys/kernel/msgmnb", data)?
            }
            ProcFileKind::KernelMsgmni => {
                crate::syscall::sysv_ipc::write_msg_sysctl("/proc/sys/kernel/msgmni", data)?
            }
            ProcFileKind::KernelSem => {
                crate::syscall::sysv_ipc::write_sem_sysctl("/proc/sys/kernel/sem", data)?
            }
            ProcFileKind::KernelShmmax => {
                crate::syscall::sysv_shm::write_shm_sysctl("/proc/sys/kernel/shmmax", data)?
            }
            ProcFileKind::KernelShmmni => {
                crate::syscall::sysv_shm::write_shm_sysctl("/proc/sys/kernel/shmmni", data)?
            }
            ProcFileKind::KernelShmall => {
                crate::syscall::sysv_shm::write_shm_sysctl("/proc/sys/kernel/shmall", data)?
            }
            ProcFileKind::KernelSchedRtPeriodUs => {
                content::write_sched_sysctl("/proc/sys/kernel/sched_rt_period_us", data)?
            }
            ProcFileKind::KernelSchedRtRuntimeUs => {
                content::write_sched_sysctl("/proc/sys/kernel/sched_rt_runtime_us", data)?
            }
            ProcFileKind::KernelSchedRrTimesliceMs => {
                content::write_sched_sysctl("/proc/sys/kernel/sched_rr_timeslice_ms", data)?
            }
            ProcFileKind::PidUidMap(pid) => content::write_proc_pid_uid_map(pid, data)?,
            ProcFileKind::PidGidMap(pid) => content::write_proc_pid_gid_map(pid, data)?,
            ProcFileKind::PidSetgroups(pid) => content::write_proc_pid_setgroups(pid, data)?,
            ProcFileKind::SimpleText(path) => entries::write_proc_simple_text(path, data)?,
            _ => return Err(err(SyscallError::EINVAL)),
        };
        self.inner.lock().cache = None;
        Ok(data.len())
    }
}

impl ProcMagicLinkFile {
    pub fn new(path: &str) -> Arc<Self> {
        let link_path = magic_link::normalize_proc_magic_path(path).into_owned();
        let target_len_hint =
            magic_link::proc_readlink(&link_path).map_or(0, |target| target.len());
        Arc::new(Self {
            link_path,
            target_len_hint,
        })
    }

    pub fn link_path(&self) -> &str {
        &self.link_path
    }

    pub fn readlink_target(&self) -> Option<String> {
        magic_link::proc_readlink(&self.link_path)
    }

    pub fn target_len_hint(&self) -> usize {
        self.target_len_hint
    }
}

impl File for ProcPseudoFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        match self.kind {
            ProcFileKind::VmOvercommitMemory
            | ProcFileKind::VmMinFreeKbytes
            | ProcFileKind::VmOvercommitRatio
            | ProcFileKind::VmDropCaches
            | ProcFileKind::VmCompactMemory
            | ProcFileKind::FsFileMax
            | ProcFileKind::FsPipeMaxSize
            | ProcFileKind::FsMqueueQueuesMax
            | ProcFileKind::KernelPidMax
            | ProcFileKind::KernelMsgmax
            | ProcFileKind::KernelMsgmnb
            | ProcFileKind::KernelMsgmni
            | ProcFileKind::KernelSem
            | ProcFileKind::KernelShmmax
            | ProcFileKind::KernelShmmni
            | ProcFileKind::KernelShmall
            | ProcFileKind::KernelSchedRtPeriodUs
            | ProcFileKind::KernelSchedRtRuntimeUs
            | ProcFileKind::KernelSchedRrTimesliceMs
            | ProcFileKind::PidUidMap(_)
            | ProcFileKind::PidGidMap(_)
            | ProcFileKind::PidSetgroups(_) => true,
            ProcFileKind::SimpleText(path) => entries::proc_simple_text_is_writable(path),
            _ => false,
        }
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        if let ProcFileKind::PidPagemap(pid) = self.kind {
            return content::proc_pid_pagemap_read(pid, &mut inner.offset, &mut buf);
        }
        if let ProcFileKind::Kpageflags = self.kind {
            return content::proc_kpageflags_read(&mut inner.offset, &mut buf);
        }
        if inner.cache.is_none() {
            inner.cache = Some(content::proc_file_content(&self.kind));
        }
        let mut offset = inner.offset;
        let bytes = inner
            .cache
            .as_ref()
            .expect("proc cache populated")
            .as_bytes();
        if offset >= bytes.len() {
            return 0;
        }
        let mut total = 0usize;
        for slice in buf.buffers.iter_mut() {
            if offset >= bytes.len() {
                break;
            }
            let n = core::cmp::min(slice.len(), bytes.len() - offset);
            slice[..n].copy_from_slice(&bytes[offset..offset + n]);
            offset += n;
            total += n;
            if n < slice.len() {
                break;
            }
        }
        inner.offset = offset;
        total
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl File for ProcMagicLinkFile {
    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn proc_file_len(kind: &ProcFileKind) -> usize {
    match kind {
        ProcFileKind::Kpageflags => content::proc_kpageflags_len(),
        ProcFileKind::PidPagemap(pid) => content::proc_pid_pagemap_len(*pid),
        _ => content::proc_file_content(kind).len(),
    }
}

pub(crate) fn parse_proc_sys_usize(data: &[u8]) -> Result<usize, isize> {
    let Ok(raw) = core::str::from_utf8(data) else {
        return Err(err(SyscallError::EINVAL));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(err(SyscallError::EINVAL));
    }
    trimmed
        .parse::<usize>()
        .map_err(|_| err(SyscallError::EINVAL))
}

/// 解析 procfs 写入的有符号整数（与 `parse_proc_sys_usize` 对应，但允许负数，
/// 例如 `-1` 这类“复位 / 不限制”语义）。空或非法返回 EINVAL。
pub(crate) fn parse_proc_sys_i64(data: &[u8]) -> Result<i64, isize> {
    let Ok(raw) = core::str::from_utf8(data) else {
        return Err(err(SyscallError::EINVAL));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(err(SyscallError::EINVAL));
    }
    trimmed
        .parse::<i64>()
        .map_err(|_| err(SyscallError::EINVAL))
}
