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

pub use content::{vm_commit_limit_bytes, vm_committed_as_bytes, vm_overcommit_memory};
pub(crate) use magic_link::resolve_proc_magic_intermediate_abs_path;
pub use magic_link::{
    normalize_proc_magic_path, proc_fd_link_file, proc_magic_link_exists, proc_readlink,
};
pub use open::open_proc_pseudo;

#[derive(Clone, Copy, Debug)]
pub enum ProcFileKind {
    Mounts,
    Cgroups,
    Meminfo,
    Cpuinfo,
    Cmdline,
    Loadavg,
    Uptime,
    Stat,
    Perf,
    Kpageflags,
    SysvipcMsg,
    SysvipcSem,
    SysvipcShm,
    VmOvercommitMemory,
    VmOvercommitRatio,
    VmDropCaches,
    VmCompactMemory,
    FsFileMax,
    FsPipeMaxSize,
    FsMqueueQueuesMax,
    KernelPidMax,
    KernelMsgmax,
    KernelMsgmnb,
    KernelMsgmni,
    KernelSem,
    KernelShmmax,
    KernelShmmni,
    KernelShmall,
    SimpleText(&'static str),
    PidStat(u32),
    PidCmdline(u32),
    PidStatus(u32),
    PidComm(u32),
    PidMaps(u32),
    PidPagemap(u32),
    PidSmaps(u32),
    PidCoredumpFilter,
    PidMounts(u32),
    PidCgroup(u32),
    PidTaskStat(u32, u32),
    PidTaskComm(u32, u32),
}

struct ProcPseudoInner {
    offset: usize,
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
            inner: Mutex::new(ProcPseudoInner { offset: 0 }),
        })
    }

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        self.inner.lock().offset = offset;
    }

    pub fn seek_end(&self) -> isize {
        proc_file_len(&self.kind) as isize
    }

    pub fn len(&self) -> Option<usize> {
        Some(proc_file_len(&self.kind))
    }

    pub fn pwrite_bytes(&self, offset: usize, data: &[u8]) -> Result<usize, isize> {
        if offset != 0 {
            return Err(err(SyscallError::EINVAL));
        }
        let _normalized = match self.kind {
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
            ProcFileKind::SimpleText(path) => entries::write_proc_simple_text(path, data)?,
            _ => return Err(err(SyscallError::EINVAL)),
        };
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
            | ProcFileKind::KernelShmall => true,
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
        let data = content::proc_file_content(&self.kind);
        let bytes = data.as_bytes();
        if inner.offset >= bytes.len() {
            return 0;
        }
        let mut total = 0usize;
        for slice in buf.buffers.iter_mut() {
            if inner.offset >= bytes.len() {
                break;
            }
            let n = core::cmp::min(slice.len(), bytes.len() - inner.offset);
            slice[..n].copy_from_slice(&bytes[inner.offset..inner.offset + n]);
            inner.offset += n;
            total += n;
            if n < slice.len() {
                break;
            }
        }
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

pub fn is_proc_pseudo_path(abs: &str) -> bool {
    abs == "/proc" || abs.starts_with("/proc/")
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
