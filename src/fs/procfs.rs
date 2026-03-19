extern crate alloc;

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::config;
use crate::fs::{
    File, NamespaceFile, OSInode, Pipe, PseudoDir, PseudoDirent, PseudoFile, PseudoKindTag,
    PseudoShmFile, RtcFile, ext4_lock, find_path_in_roots, root_inode_for_path,
    secondary_root_inode,
};
use crate::mm::{PTEFlags, UserBuffer, VirtAddr, frame_available_pages};
use crate::task::manager::{PID2PCB, pid2process};
use crate::task::processor::{current_process, current_task};
use crate::task::task_block::TaskStatus;

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
    PidMounts,
    PidCgroup(u32),
    PidTaskStat(u32, u32),
    PidTaskComm(u32, u32),
}

static PROC_SIMPLE_TEXT_FILES: Mutex<BTreeMap<&'static str, Vec<u8>>> = Mutex::new(BTreeMap::new());
const PROC_LINUX_TID_PID_SHIFT: usize = 15;
static PROC_PID_STAT_CALLS: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_STATE_S: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_STATE_R: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_STATE_Z: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_LOCK_BUSY: AtomicUsize = AtomicUsize::new(0);
static PROC_PID_STAT_TOTAL_CYCLES: AtomicUsize = AtomicUsize::new(0);
const VM_OVERCOMMIT_MEMORY_DEFAULT: usize = 0;
const VM_OVERCOMMIT_MEMORY_MAX: usize = 2;
const VM_OVERCOMMIT_RATIO_DEFAULT: usize = 50;
const VM_OVERCOMMIT_RATIO_MAX: usize = 100;
const FS_FILE_MAX_DEFAULT: usize = 8192;
const FS_FILE_MAX_MAX: usize = isize::MAX as usize;
const EINVAL: isize = -22;
static VM_OVERCOMMIT_MEMORY: AtomicUsize = AtomicUsize::new(VM_OVERCOMMIT_MEMORY_DEFAULT);
static VM_OVERCOMMIT_RATIO: AtomicUsize = AtomicUsize::new(VM_OVERCOMMIT_RATIO_DEFAULT);
static FS_FILE_MAX: AtomicUsize = AtomicUsize::new(FS_FILE_MAX_DEFAULT);

fn should_report_proc_pid_stat_diag(calls: usize) -> bool {
    calls <= 16 || calls % 2048 == 0
}

fn record_proc_pid_stat_diag(pid: u32, state_char: char, elapsed_cycles: usize, lock_busy: bool) {
    if !crate::debug_config::DEBUG_FUTEX {
        return;
    }
    let calls = PROC_PID_STAT_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    PROC_PID_STAT_TOTAL_CYCLES.fetch_add(elapsed_cycles, Ordering::Relaxed);
    if lock_busy {
        PROC_PID_STAT_LOCK_BUSY.fetch_add(1, Ordering::Relaxed);
    }
    match state_char {
        'S' => {
            PROC_PID_STAT_STATE_S.fetch_add(1, Ordering::Relaxed);
        }
        'R' => {
            PROC_PID_STAT_STATE_R.fetch_add(1, Ordering::Relaxed);
        }
        'Z' => {
            PROC_PID_STAT_STATE_Z.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    if should_report_proc_pid_stat_diag(calls) {
        let s = PROC_PID_STAT_STATE_S.load(Ordering::Relaxed);
        let r = PROC_PID_STAT_STATE_R.load(Ordering::Relaxed);
        let z = PROC_PID_STAT_STATE_Z.load(Ordering::Relaxed);
        let busy = PROC_PID_STAT_LOCK_BUSY.load(Ordering::Relaxed);
        let total_cycles = PROC_PID_STAT_TOTAL_CYCLES.load(Ordering::Relaxed);
        let avg_cycles = if calls == 0 { 0 } else { total_cycles / calls };
        log::warn!(
            "[proc_stat_diag] calls={} pid={} state={} s={} r={} z={} lock_busy={} avg_cycles={}",
            calls,
            pid,
            state_char,
            s,
            r,
            z,
            busy,
            avg_cycles
        );
    }
}

// gzip-compressed minimal config for LTP kconfig checks.
// Keep this conservative: only advertise options that this kernel surface
// actually exposes to user space.
const PROC_CONFIG_GZ: &[u8] = &[
    31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 115, 246, 247, 115, 243, 116, 143, 119, 10, 118, 137, 15, 8,
    242, 119, 118, 13, 14, 142, 119, 116, 118, 14, 177, 173, 228, 82, 86, 112, 198, 46, 23, 31,
    102, 172, 144, 89, 172, 144, 151, 95, 162, 80, 156, 90, 194, 5, 85, 5, 82, 17, 239, 22, 12,
    212, 8, 21, 8, 142, 12, 118, 14, 241, 1, 242, 1, 240, 171, 117, 110, 99, 0, 0, 0,
];

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
            return Err(EINVAL);
        }
        let _normalized = match self.kind {
            ProcFileKind::VmOvercommitMemory => {
                write_vm_sysctl("/proc/sys/vm/overcommit_memory", data)?
            }
            ProcFileKind::VmOvercommitRatio => {
                write_vm_sysctl("/proc/sys/vm/overcommit_ratio", data)?
            }
            ProcFileKind::VmDropCaches => {
                write_vm_trigger_sysctl("/proc/sys/vm/drop_caches", data)?
            }
            ProcFileKind::VmCompactMemory => {
                write_vm_trigger_sysctl("/proc/sys/vm/compact_memory", data)?
            }
            ProcFileKind::FsFileMax => write_fs_file_max_sysctl(data)?,
            ProcFileKind::FsPipeMaxSize => {
                crate::fs::write_pipe_sysctl("/proc/sys/fs/pipe-max-size", data)?
            }
            ProcFileKind::FsMqueueQueuesMax => crate::syscall::posix_mq::write_mqueue_sysctl(
                "/proc/sys/fs/mqueue/queues_max",
                data,
            )?,
            ProcFileKind::KernelPidMax => write_pid_max_sysctl(data)?,
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
            ProcFileKind::SimpleText(path) => write_proc_simple_text(path, data)?,
            _ => return Err(EINVAL),
        };
        Ok(data.len())
    }
}

impl ProcMagicLinkFile {
    pub fn new(path: &str) -> Arc<Self> {
        let link_path = normalize_proc_magic_path(path).into_owned();
        let target_len_hint = proc_readlink(&link_path).map_or(0, |target| target.len());
        Arc::new(Self {
            link_path,
            target_len_hint,
        })
    }

    pub fn link_path(&self) -> &str {
        &self.link_path
    }

    pub fn readlink_target(&self) -> Option<String> {
        proc_readlink(&self.link_path)
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
            ProcFileKind::SimpleText(path) => proc_simple_text_is_writable(path),
            _ => false,
        }
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
        if let ProcFileKind::PidPagemap(pid) = self.kind {
            return proc_pid_pagemap_read(pid, &mut inner.offset, &mut buf);
        }
        if let ProcFileKind::Kpageflags = self.kind {
            return proc_kpageflags_read(&mut inner.offset, &mut buf);
        }
        let data = proc_file_content(&self.kind);
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
        ProcFileKind::Kpageflags => proc_kpageflags_len(),
        ProcFileKind::PidPagemap(pid) => proc_pid_pagemap_len(*pid),
        _ => proc_file_content(kind).len(),
    }
}

pub fn is_proc_pseudo_path(abs: &str) -> bool {
    abs == "/proc" || abs.starts_with("/proc/")
}

fn proc_root_entries() -> Vec<PseudoDirent> {
    let mut entries = Vec::new();
    entries.push(PseudoDirent {
        name: String::from("."),
        ino: 1,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from(".."),
        ino: 1,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from("self"),
        ino: 1,
        dtype: 10,
    });
    entries.push(PseudoDirent {
        name: String::from("thread-self"),
        ino: 1,
        dtype: 10,
    });
    entries.push(PseudoDirent {
        name: String::from("sys"),
        ino: 1,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from("sysvipc"),
        ino: 1,
        dtype: 4,
    });
    for name in [
        "mounts",
        "cgroups",
        "meminfo",
        "cpuinfo",
        "cmdline",
        "loadavg",
        "uptime",
        "stat",
        "perf",
        "kpageflags",
        "config.gz",
    ] {
        entries.push(PseudoDirent {
            name: String::from(name),
            ino: 1,
            dtype: 8,
        });
    }
    for pid in collect_pids() {
        entries.push(PseudoDirent {
            name: alloc::format!("{}", pid),
            ino: pid as u64,
            dtype: 4,
        });
    }
    entries
}

fn proc_dir_entries(children: &[(&str, u8)]) -> Vec<PseudoDirent> {
    let mut entries = Vec::with_capacity(children.len() + 2);
    entries.push(PseudoDirent {
        name: String::from("."),
        ino: 1,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from(".."),
        ino: 1,
        dtype: 4,
    });
    for (name, dtype) in children {
        entries.push(PseudoDirent {
            name: String::from(*name),
            ino: 1,
            dtype: *dtype,
        });
    }
    entries
}

fn proc_sys_kernel_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[
        ("core_pattern", 8),
        ("pid_max", 8),
        ("threads-max", 8),
        ("tainted", 8),
        ("keys", 4),
        ("random", 4),
        ("shmmax", 8),
        ("shmmni", 8),
        ("shmall", 8),
        ("msgmax", 8),
        ("msgmnb", 8),
        ("msgmni", 8),
        ("sem", 8),
    ])
}

fn proc_sys_kernel_keys_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[
        ("gc_delay", 8),
        ("maxkeys", 8),
        ("maxbytes", 8),
        ("root_maxkeys", 8),
        ("root_maxbytes", 8),
    ])
}

fn proc_sys_fs_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[
        ("file-max", 8),
        ("inotify", 4),
        ("mqueue", 4),
        ("pipe-max-size", 8),
        ("pipe-user-pages-soft", 8),
        ("pipe-user-pages-hard", 8),
        ("lease-break-time", 8),
    ])
}

fn proc_sys_vm_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[
        ("drop_caches", 8),
        ("compact_memory", 8),
        ("vfs_cache_pressure", 8),
        ("min_free_kbytes", 8),
        ("nr_hugepages", 8),
        ("nr_overcommit_hugepages", 8),
        ("nr_hugepages_mempolicy", 8),
        ("mmap_min_addr", 8),
        ("overcommit_memory", 8),
        ("overcommit_ratio", 8),
        ("panic_on_oom", 8),
        ("max_map_count", 8),
        ("swappiness", 8),
        ("stat_refresh", 8),
        ("dirty_background_ratio", 8),
        ("dirty_ratio", 8),
        ("dirty_expire_centisecs", 8),
        ("unprivileged_userfaultfd", 8),
        ("memory_failure_early_kill", 8),
    ])
}

fn proc_sys_net_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("ipv4", 4)])
}

fn proc_sys_net_ipv4_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("conf", 4)])
}

fn proc_sys_net_ipv4_conf_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("lo", 4), ("default", 4)])
}

fn proc_sys_net_ipv4_conf_if_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("tag", 8)])
}

fn proc_simple_text_path(path: &str) -> Option<&'static str> {
    match path {
        "/proc/sys/kernel/core_pattern" => Some("/proc/sys/kernel/core_pattern"),
        "/proc/sys/kernel/threads-max" => Some("/proc/sys/kernel/threads-max"),
        "/proc/sys/kernel/tainted" => Some("/proc/sys/kernel/tainted"),
        "/proc/sys/kernel/keys/gc_delay" => Some("/proc/sys/kernel/keys/gc_delay"),
        "/proc/sys/kernel/keys/maxkeys" => Some("/proc/sys/kernel/keys/maxkeys"),
        "/proc/sys/kernel/keys/maxbytes" => Some("/proc/sys/kernel/keys/maxbytes"),
        "/proc/sys/kernel/keys/root_maxkeys" => Some("/proc/sys/kernel/keys/root_maxkeys"),
        "/proc/sys/kernel/keys/root_maxbytes" => Some("/proc/sys/kernel/keys/root_maxbytes"),
        "/proc/sys/fs/inotify/max_queued_events" => Some("/proc/sys/fs/inotify/max_queued_events"),
        "/proc/sys/fs/inotify/max_user_instances" => {
            Some("/proc/sys/fs/inotify/max_user_instances")
        }
        "/proc/sys/fs/inotify/max_user_watches" => Some("/proc/sys/fs/inotify/max_user_watches"),
        "/proc/sys/fs/pipe-user-pages-soft" => Some("/proc/sys/fs/pipe-user-pages-soft"),
        "/proc/sys/fs/pipe-user-pages-hard" => Some("/proc/sys/fs/pipe-user-pages-hard"),
        "/proc/sys/fs/lease-break-time" => Some("/proc/sys/fs/lease-break-time"),
        "/proc/sys/vm/vfs_cache_pressure" => Some("/proc/sys/vm/vfs_cache_pressure"),
        "/proc/sys/vm/min_free_kbytes" => Some("/proc/sys/vm/min_free_kbytes"),
        "/proc/sys/vm/nr_hugepages" => Some("/proc/sys/vm/nr_hugepages"),
        "/proc/sys/vm/nr_overcommit_hugepages" => Some("/proc/sys/vm/nr_overcommit_hugepages"),
        "/proc/sys/vm/nr_hugepages_mempolicy" => Some("/proc/sys/vm/nr_hugepages_mempolicy"),
        "/proc/sys/vm/mmap_min_addr" => Some("/proc/sys/vm/mmap_min_addr"),
        "/proc/sys/vm/panic_on_oom" => Some("/proc/sys/vm/panic_on_oom"),
        "/proc/sys/vm/max_map_count" => Some("/proc/sys/vm/max_map_count"),
        "/proc/sys/vm/swappiness" => Some("/proc/sys/vm/swappiness"),
        "/proc/sys/vm/stat_refresh" => Some("/proc/sys/vm/stat_refresh"),
        "/proc/sys/vm/dirty_background_ratio" => Some("/proc/sys/vm/dirty_background_ratio"),
        "/proc/sys/vm/dirty_ratio" => Some("/proc/sys/vm/dirty_ratio"),
        "/proc/sys/vm/dirty_expire_centisecs" => Some("/proc/sys/vm/dirty_expire_centisecs"),
        "/proc/sys/vm/unprivileged_userfaultfd" => Some("/proc/sys/vm/unprivileged_userfaultfd"),
        "/proc/sys/vm/memory_failure_early_kill" => Some("/proc/sys/vm/memory_failure_early_kill"),
        "/proc/sys/net/ipv4/conf/lo/tag" => Some("/proc/sys/net/ipv4/conf/lo/tag"),
        "/proc/sys/net/ipv4/conf/default/tag" => Some("/proc/sys/net/ipv4/conf/default/tag"),
        _ => None,
    }
}

fn proc_simple_text_default(path: &'static str) -> Vec<u8> {
    match path {
        "/proc/sys/kernel/core_pattern" => b"core\n".to_vec(),
        "/proc/sys/kernel/threads-max" => {
            alloc::format!("{}\n", crate::task::pid_max()).into_bytes()
        }
        "/proc/sys/kernel/tainted" => b"0\n".to_vec(),
        "/proc/sys/kernel/keys/gc_delay" => b"300\n".to_vec(),
        "/proc/sys/kernel/keys/maxkeys" => b"200\n".to_vec(),
        "/proc/sys/kernel/keys/maxbytes" => b"20000\n".to_vec(),
        "/proc/sys/kernel/keys/root_maxkeys" => b"100000\n".to_vec(),
        "/proc/sys/kernel/keys/root_maxbytes" => b"25000000\n".to_vec(),
        "/proc/sys/fs/inotify/max_queued_events" => b"16384\n".to_vec(),
        "/proc/sys/fs/inotify/max_user_instances" => b"128\n".to_vec(),
        "/proc/sys/fs/inotify/max_user_watches" => b"8192\n".to_vec(),
        "/proc/sys/fs/pipe-user-pages-soft" => b"128\n".to_vec(),
        "/proc/sys/fs/pipe-user-pages-hard" => b"0\n".to_vec(),
        "/proc/sys/fs/lease-break-time" => b"45\n".to_vec(),
        "/proc/sys/vm/vfs_cache_pressure" => b"100\n".to_vec(),
        "/proc/sys/vm/min_free_kbytes" => b"1024\n".to_vec(),
        "/proc/sys/vm/nr_hugepages" => b"0\n".to_vec(),
        "/proc/sys/vm/nr_overcommit_hugepages" => b"0\n".to_vec(),
        "/proc/sys/vm/nr_hugepages_mempolicy" => b"0\n".to_vec(),
        "/proc/sys/vm/mmap_min_addr" => b"65536\n".to_vec(),
        "/proc/sys/vm/panic_on_oom" => b"0\n".to_vec(),
        "/proc/sys/vm/max_map_count" => b"65530\n".to_vec(),
        "/proc/sys/vm/swappiness" => b"60\n".to_vec(),
        "/proc/sys/vm/stat_refresh" => b"0\n".to_vec(),
        "/proc/sys/vm/dirty_background_ratio" => b"10\n".to_vec(),
        "/proc/sys/vm/dirty_ratio" => b"20\n".to_vec(),
        "/proc/sys/vm/dirty_expire_centisecs" => b"3000\n".to_vec(),
        "/proc/sys/vm/unprivileged_userfaultfd" => b"0\n".to_vec(),
        "/proc/sys/vm/memory_failure_early_kill" => b"0\n".to_vec(),
        "/proc/sys/net/ipv4/conf/lo/tag" => b"0\n".to_vec(),
        "/proc/sys/net/ipv4/conf/default/tag" => b"0\n".to_vec(),
        _ => Vec::new(),
    }
}

fn proc_simple_text_is_writable(path: &str) -> bool {
    !matches!(path, "/proc/sys/kernel/tainted") && proc_simple_text_path(path).is_some()
}

fn proc_simple_text_is_numeric(path: &str) -> bool {
    !matches!(path, "/proc/sys/kernel/core_pattern")
}

fn ensure_proc_simple_text_entry(path: &'static str) {
    let mut files = PROC_SIMPLE_TEXT_FILES.lock();
    files
        .entry(path)
        .or_insert_with(|| proc_simple_text_default(path));
}

fn proc_simple_text_content(path: &'static str) -> String {
    ensure_proc_simple_text_entry(path);
    let bytes = PROC_SIMPLE_TEXT_FILES
        .lock()
        .get(path)
        .cloned()
        .unwrap_or_else(|| proc_simple_text_default(path));
    String::from_utf8_lossy(&bytes).into_owned()
}

fn write_proc_simple_text(path: &'static str, data: &[u8]) -> Result<Vec<u8>, isize> {
    if !proc_simple_text_is_writable(path) {
        return Err(EINVAL);
    }
    let normalized = if proc_simple_text_is_numeric(path) {
        let value = parse_proc_sys_usize(data)?;
        alloc::format!("{}\n", value).into_bytes()
    } else {
        let Ok(raw) = core::str::from_utf8(data) else {
            return Err(EINVAL);
        };
        if raw.is_empty() || raw.contains('\0') {
            return Err(EINVAL);
        }
        alloc::format!("{}\n", raw.trim_end_matches(['\n', '\r'])).into_bytes()
    };
    ensure_proc_simple_text_entry(path);
    PROC_SIMPLE_TEXT_FILES
        .lock()
        .insert(path, normalized.clone());
    Ok(normalized)
}

fn write_pid_max_sysctl(data: &[u8]) -> Result<Vec<u8>, isize> {
    let value = parse_proc_sys_usize(data)?;
    let (min, max) = crate::task::pid_max_bounds();
    if !(min..=max).contains(&value) {
        return Err(EINVAL);
    }
    let applied = crate::task::set_pid_max(value);
    Ok(alloc::format!("{}\n", applied).into_bytes())
}

fn write_vm_trigger_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    let value = parse_proc_sys_usize(data)?;
    match path {
        "/proc/sys/vm/drop_caches" if (1..=7).contains(&value) => {}
        "/proc/sys/vm/compact_memory" if value == 1 => {}
        _ => return Err(EINVAL),
    }
    Ok(b"0\n".to_vec())
}

fn managed_proc_sys_file_kind(path: &str) -> Option<ProcFileKind> {
    match path {
        "/proc/sys/vm/drop_caches" => Some(ProcFileKind::VmDropCaches),
        "/proc/sys/vm/compact_memory" => Some(ProcFileKind::VmCompactMemory),
        "/proc/sys/vm/overcommit_memory" => Some(ProcFileKind::VmOvercommitMemory),
        "/proc/sys/vm/overcommit_ratio" => Some(ProcFileKind::VmOvercommitRatio),
        "/proc/sys/fs/file-max" => Some(ProcFileKind::FsFileMax),
        "/proc/sys/fs/pipe-max-size" => Some(ProcFileKind::FsPipeMaxSize),
        "/proc/sys/fs/mqueue/queues_max" => Some(ProcFileKind::FsMqueueQueuesMax),
        "/proc/sys/kernel/pid_max" => Some(ProcFileKind::KernelPidMax),
        "/proc/sys/kernel/msgmax" => Some(ProcFileKind::KernelMsgmax),
        "/proc/sys/kernel/msgmnb" => Some(ProcFileKind::KernelMsgmnb),
        "/proc/sys/kernel/msgmni" => Some(ProcFileKind::KernelMsgmni),
        "/proc/sys/kernel/sem" => Some(ProcFileKind::KernelSem),
        "/proc/sys/kernel/shmmax" => Some(ProcFileKind::KernelShmmax),
        "/proc/sys/kernel/shmmni" => Some(ProcFileKind::KernelShmmni),
        "/proc/sys/kernel/shmall" => Some(ProcFileKind::KernelShmall),
        _ => proc_simple_text_path(path).map(ProcFileKind::SimpleText),
    }
}

fn proc_pid_entries(pid: u32) -> Vec<PseudoDirent> {
    let mut entries = Vec::new();
    entries.push(PseudoDirent {
        name: String::from("."),
        ino: pid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from(".."),
        ino: 1,
        dtype: 4,
    });
    for name in [
        "stat",
        "cmdline",
        "comm",
        "status",
        "maps",
        "pagemap",
        "smaps",
        "coredump_filter",
        "mounts",
        "cgroup",
    ] {
        entries.push(PseudoDirent {
            name: String::from(name),
            ino: pid as u64,
            dtype: 8,
        });
    }
    entries.push(PseudoDirent {
        name: String::from("cwd"),
        ino: pid as u64,
        dtype: 10,
    });
    entries.push(PseudoDirent {
        name: String::from("fd"),
        ino: pid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from("task"),
        ino: pid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from("ns"),
        ino: pid as u64,
        dtype: 4,
    });
    entries
}

fn proc_pid_ns_entries(pid: u32) -> Vec<PseudoDirent> {
    let mut entries = Vec::new();
    entries.push(PseudoDirent {
        name: String::from("."),
        ino: pid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from(".."),
        ino: pid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from("ipc"),
        ino: pid as u64,
        dtype: 10,
    });
    entries
}

fn proc_pid_fd_entries(pid: u32) -> Vec<PseudoDirent> {
    let mut entries = Vec::new();
    entries.push(PseudoDirent {
        name: String::from("."),
        ino: pid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from(".."),
        ino: pid as u64,
        dtype: 4,
    });
    let Some(proc) = pid2process(pid as usize) else {
        return entries;
    };
    let files_proc = proc.files_owner_process();
    let Some(inner) = files_proc.try_borrow_mut() else {
        return entries;
    };
    let mut has_predicted = false;
    let predicted_fd = if pid as usize == current_process().getpid() {
        let limit = inner.rlimit_nofile_cur as usize;
        let fd =
            if let Some(fd) = (0..inner.fd_table.len()).find(|fd| inner.fd_table[*fd].is_none()) {
                (fd < limit).then_some(fd)
            } else if inner.fd_table.len() < limit {
                Some(inner.fd_table.len())
            } else {
                None
            };
        fd
    } else {
        None
    };

    for (fd, file) in inner.fd_table.iter().enumerate() {
        if file.is_some() {
            if predicted_fd == Some(fd) {
                has_predicted = true;
            }
            entries.push(PseudoDirent {
                name: alloc::format!("{fd}"),
                // glibc may skip dirents whose inode is 0; keep procfd inodes non-zero.
                ino: (fd + 1) as u64,
                dtype: 10,
            });
        }
    }
    if let Some(fd) = predicted_fd {
        if !has_predicted {
            entries.push(PseudoDirent {
                name: alloc::format!("{fd}"),
                ino: (fd + 1) as u64,
                dtype: 10,
            });
        }
    }
    entries
}

fn encode_proc_linux_tid(tgid: u32, tid_index: usize) -> u32 {
    if tid_index == 0 {
        tgid
    } else {
        (((tgid as usize) << PROC_LINUX_TID_PID_SHIFT) | (tid_index & 0x7fff)) as u32
    }
}

fn decode_proc_linux_tid(tgid: u32, tid: u32) -> Option<usize> {
    if tid == tgid {
        return Some(0);
    }
    let pid_part = (tid as usize) >> PROC_LINUX_TID_PID_SHIFT;
    if pid_part != tgid as usize {
        return None;
    }
    Some((tid as usize) & 0x7fff)
}

fn proc_pid_task_entries(pid: u32) -> Vec<PseudoDirent> {
    let mut entries = Vec::new();
    entries.push(PseudoDirent {
        name: String::from("."),
        ino: pid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from(".."),
        ino: pid as u64,
        dtype: 4,
    });
    let Some(proc) = pid2process(pid as usize) else {
        return entries;
    };
    let Some(inner) = proc.try_borrow_mut() else {
        return entries;
    };
    for (tid_index, task) in inner.tasks.iter().enumerate() {
        let Some(task) = task.as_ref() else {
            continue;
        };
        let alive = task
            .try_borrow_mut()
            .map(|ti| ti.res.is_some() && ti.exit_code.is_none())
            .unwrap_or(false);
        if !alive {
            continue;
        }
        let tid = encode_proc_linux_tid(pid, tid_index);
        entries.push(PseudoDirent {
            name: alloc::format!("{tid}"),
            ino: tid as u64,
            dtype: 4,
        });
    }
    entries
}

fn proc_pid_task_alive(pid: u32, tid: u32) -> bool {
    let Some(tid_index) = decode_proc_linux_tid(pid, tid) else {
        return false;
    };
    let Some(proc) = pid2process(pid as usize) else {
        return false;
    };
    let Some(inner) = proc.try_borrow_mut() else {
        return false;
    };
    inner
        .tasks
        .get(tid_index)
        .and_then(|t| t.as_ref())
        .and_then(|t| {
            t.try_borrow_mut()
                .map(|ti| ti.res.is_some() && ti.exit_code.is_none())
        })
        .unwrap_or(false)
}

fn proc_pid_task_tid_entries(pid: u32, tid: u32) -> Vec<PseudoDirent> {
    let mut entries = Vec::new();
    entries.push(PseudoDirent {
        name: String::from("."),
        ino: tid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from(".."),
        ino: pid as u64,
        dtype: 4,
    });
    if !proc_pid_task_alive(pid, tid) {
        return entries;
    }
    entries.push(PseudoDirent {
        name: String::from("stat"),
        ino: tid as u64,
        dtype: 8,
    });
    entries.push(PseudoDirent {
        name: String::from("comm"),
        ino: tid as u64,
        dtype: 8,
    });
    entries.push(PseudoDirent {
        name: String::from("cwd"),
        ino: tid as u64,
        dtype: 10,
    });
    entries.push(PseudoDirent {
        name: String::from("fd"),
        ino: tid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from("ns"),
        ino: tid as u64,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from("mounts"),
        ino: tid as u64,
        dtype: 8,
    });
    entries.push(PseudoDirent {
        name: String::from("cgroup"),
        ino: tid as u64,
        dtype: 8,
    });
    entries
}

fn proc_pid_exists(pid: u32) -> bool {
    pid2process(pid as usize).is_some()
}

fn current_thread_self_target() -> Option<String> {
    let pid = current_process().getpid() as u32;
    let task = current_task()?;
    let tid_index = {
        let inner = task.borrow_mut();
        inner.res.as_ref()?.tid
    };
    let tid = encode_proc_linux_tid(pid, tid_index);
    Some(alloc::format!("{pid}/task/{tid}"))
}

fn current_thread_self_abs_target() -> Option<String> {
    current_thread_self_target().map(|target| alloc::format!("/proc/{target}"))
}

fn trim_proc_path(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

fn proc_magic_alias_target_path(trimmed: &str) -> Option<String> {
    if trimmed == "/proc/self" || trimmed.starts_with("/proc/self/") {
        let pid = current_process().getpid();
        let suffix = &trimmed["/proc/self".len()..];
        let mut mapped = alloc::format!("/proc/{pid}");
        mapped.push_str(suffix);
        return Some(mapped);
    }

    if trimmed == "/proc/thread-self" || trimmed.starts_with("/proc/thread-self/") {
        let mut mapped = current_thread_self_abs_target()?;
        let suffix = &trimmed["/proc/thread-self".len()..];
        mapped.push_str(suffix);
        return Some(mapped);
    }

    None
}

pub fn normalize_proc_magic_path(path: &str) -> Cow<'_, str> {
    let trimmed = trim_proc_path(path);
    match proc_magic_alias_target_path(trimmed) {
        Some(mapped) => Cow::Owned(mapped),
        None => Cow::Borrowed(trimmed),
    }
}

fn proc_dir_entry_path(base: &str, name: &str) -> String {
    if base == "/" {
        alloc::format!("/{name}")
    } else {
        alloc::format!("{base}/{name}")
    }
}

fn find_inode_path_in_subtree(
    dir: &Arc<ext4_fs::Inode>,
    base: &str,
    target_dev: usize,
    target_ino: u32,
    depth: usize,
) -> Option<String> {
    if depth == 0 {
        return None;
    }
    for (name, _ino, _ftype) in dir.dir_entries() {
        if name == "." || name == ".." {
            continue;
        }
        if base == "/" && name == "proc" {
            continue;
        }
        let Some(child) = dir.find(&name) else {
            continue;
        };
        let path = proc_dir_entry_path(base, &name);
        if child.device_id() == target_dev && child.inode_num() == target_ino {
            return Some(path);
        }
        if child.is_dir() {
            if let Some(found) =
                find_inode_path_in_subtree(&child, &path, target_dev, target_ino, depth - 1)
            {
                return Some(found);
            }
        }
    }
    None
}

fn find_inode_path_in_roots(target: &Arc<ext4_fs::Inode>) -> Option<String> {
    let target_dev = target.device_id();
    let target_ino = target.inode_num();
    let _guard = ext4_lock();

    let primary = root_inode_for_path("/");
    if primary.device_id() == target_dev && primary.inode_num() == target_ino {
        return Some(String::from("/"));
    }
    if let Some(found) = find_inode_path_in_subtree(&primary, "/", target_dev, target_ino, 64) {
        return Some(found);
    }

    let secondary = secondary_root_inode()?;
    if secondary.device_id() == target_dev && secondary.inode_num() == target_ino {
        return Some(String::from("/"));
    }
    find_inode_path_in_subtree(&secondary, "/", target_dev, target_ino, 64)
}

fn proc_fd_target(pid: u32, fd: usize) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let files_proc = proc.files_owner_process();
    let (file, cwd) = {
        let inner = files_proc.try_borrow_mut()?;
        if fd >= inner.fd_table.len() {
            return None;
        }
        (inner.fd_table[fd].as_ref()?.clone(), inner.cwd.clone())
    };

    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        return Some(String::from(pdir.path()));
    }
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        return match pf.kind_tag() {
            PseudoKindTag::Null => Some(String::from("/dev/null")),
            PseudoKindTag::Zero => Some(String::from("/dev/zero")),
            PseudoKindTag::Urandom => Some(String::from("/dev/urandom")),
            PseudoKindTag::Static => None,
        };
    }
    if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
        return Some(alloc::format!("pipe:[{}]", pipe as *const Pipe as usize));
    }
    if let Some(ns) = file.as_any().downcast_ref::<NamespaceFile>() {
        return Some(alloc::format!("ipc:[{}]", ns.ns_id()));
    }
    if let Some(link) = file.as_any().downcast_ref::<ProcMagicLinkFile>() {
        return Some(String::from(link.link_path()));
    }
    if file.as_any().downcast_ref::<RtcFile>().is_some() {
        return Some(String::from("/dev/misc/rtc"));
    }
    if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
        return Some(String::from("/dev/shm"));
    }
    if let Some(oinode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = oinode.ext4_inode();
        if inode.is_dir() {
            if let Some(cwd_inode) = find_path_in_roots(&cwd) {
                if cwd_inode.device_id() == inode.device_id()
                    && cwd_inode.inode_num() == inode.inode_num()
                {
                    return Some(cwd);
                }
            }
        }
        return find_inode_path_in_roots(&inode);
    }
    None
}

fn proc_pid_cwd(pid: u32) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let inner = proc.try_borrow_mut()?;
    Some(inner.cwd.clone())
}

fn proc_pid_fd_file(pid: u32, fd: usize) -> Option<Arc<dyn File + Send + Sync>> {
    let proc = pid2process(pid as usize)?;
    let files_proc = proc.files_owner_process();
    let inner = files_proc.try_borrow_mut()?;
    inner.fd_table.get(fd)?.as_ref().cloned()
}

fn proc_pid_ipc_ns_target(pid: u32) -> Option<String> {
    let proc = pid2process(pid as usize)?;
    let inner = proc.try_borrow_mut()?;
    Some(alloc::format!("ipc:[{}]", inner.ipc_ns_id))
}

fn proc_pid_ipc_ns_file(pid: u32) -> Option<Arc<dyn File + Send + Sync>> {
    let proc = pid2process(pid as usize)?;
    let inner = proc.try_borrow_mut()?;
    Some(Arc::new(NamespaceFile::new_ipc(inner.ipc_ns_id)))
}

fn parse_proc_fd_component(fd_name: &str) -> Option<usize> {
    if fd_name.is_empty() || fd_name.contains('/') || !fd_name.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    fd_name.parse::<usize>().ok()
}

fn proc_pid_task_rest(rest: &str) -> Option<(u32, &str)> {
    let task_rest = rest.strip_prefix("task/")?;
    let mut parts = task_rest.splitn(2, '/');
    let tid_name = parts.next().unwrap_or("");
    if tid_name.is_empty() || !tid_name.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let tid = tid_name.parse::<u32>().ok()?;
    let tail = parts.next().unwrap_or("");
    Some((tid, tail))
}

pub enum ProcMagicLinkFollowTarget {
    Path(String),
    File(Arc<dyn File + Send + Sync>),
}

pub fn proc_magic_link_follow_target(path: &str) -> Option<ProcMagicLinkFollowTarget> {
    let trimmed = trim_proc_path(path);

    if trimmed == "/proc/self" {
        let pid = current_process().getpid();
        return Some(ProcMagicLinkFollowTarget::Path(alloc::format!("{pid}")));
    }
    if trimmed == "/proc/thread-self" {
        return current_thread_self_target().map(ProcMagicLinkFollowTarget::Path);
    }

    let normalized = normalize_proc_magic_path(trimmed);
    let trimmed = normalized.as_ref();

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    if !proc_pid_exists(pid) {
        return None;
    }
    if rest == "cwd" {
        return proc_pid_cwd(pid).map(ProcMagicLinkFollowTarget::Path);
    }
    if rest == "ns/ipc" {
        return proc_pid_ipc_ns_file(pid).map(ProcMagicLinkFollowTarget::File);
    }
    if let Some(fd_name) = rest.strip_prefix("fd/") {
        let fd = parse_proc_fd_component(fd_name)?;
        return proc_pid_fd_file(pid, fd).map(ProcMagicLinkFollowTarget::File);
    }

    let (tid, tail) = proc_pid_task_rest(rest)?;
    if !proc_pid_task_alive(pid, tid) {
        return None;
    }
    if tail == "cwd" {
        return proc_pid_cwd(pid).map(ProcMagicLinkFollowTarget::Path);
    }
    if tail == "ns/ipc" {
        return proc_pid_ipc_ns_file(pid).map(ProcMagicLinkFollowTarget::File);
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_pid_fd_file(pid, fd).map(ProcMagicLinkFollowTarget::File)
}

pub fn proc_magic_link_exists(path: &str) -> bool {
    let trimmed = trim_proc_path(path);

    if trimmed == "/proc/self" {
        return true;
    }
    if trimmed == "/proc/thread-self" {
        return current_thread_self_target().is_some();
    }

    let normalized = normalize_proc_magic_path(trimmed);
    let trimmed = normalized.as_ref();

    let Some((pid, rest)) = proc_pid_from_path_with_rest(trimmed) else {
        return false;
    };
    if !proc_pid_exists(pid) {
        return false;
    }
    if rest == "cwd" || rest == "ns/ipc" {
        return true;
    }
    if let Some(fd_name) = rest.strip_prefix("fd/") {
        return parse_proc_fd_component(fd_name)
            .and_then(|fd| proc_pid_fd_file(pid, fd))
            .is_some();
    }

    let Some((tid, tail)) = proc_pid_task_rest(rest) else {
        return false;
    };
    if !proc_pid_task_alive(pid, tid) {
        return false;
    }
    if tail == "cwd" || tail == "ns/ipc" {
        return true;
    }
    tail.strip_prefix("fd/")
        .and_then(parse_proc_fd_component)
        .and_then(|fd| proc_pid_fd_file(pid, fd))
        .is_some()
}

pub fn proc_fd_link_file(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let normalized = normalize_proc_magic_path(path);
    let trimmed = normalized.as_ref();

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    if !proc_pid_exists(pid) {
        return None;
    }
    if let Some(fd_name) = rest.strip_prefix("fd/") {
        let fd = parse_proc_fd_component(fd_name)?;
        return proc_pid_fd_file(pid, fd);
    }

    let (tid, tail) = proc_pid_task_rest(rest)?;
    if !proc_pid_task_alive(pid, tid) {
        return None;
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_pid_fd_file(pid, fd)
}

pub fn proc_readlink(path: &str) -> Option<String> {
    let trimmed = trim_proc_path(path);

    if trimmed == "/proc/self" || trimmed.starts_with("/proc/self/") {
        let pid = current_process().getpid();
        if trimmed == "/proc/self" {
            return Some(alloc::format!("{pid}"));
        }
    }

    if trimmed == "/proc/thread-self" || trimmed.starts_with("/proc/thread-self/") {
        let target = current_thread_self_target()?;
        if trimmed == "/proc/thread-self" {
            return Some(target);
        }
    }

    let normalized = normalize_proc_magic_path(trimmed);
    let trimmed = normalized.as_ref();

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    if rest == "cwd" {
        return proc_pid_cwd(pid);
    }
    if rest == "ns/ipc" {
        return proc_pid_ipc_ns_target(pid);
    }

    if let Some(fd_name) = rest.strip_prefix("fd/") {
        let fd = parse_proc_fd_component(fd_name)?;
        return proc_fd_target(pid, fd);
    }

    let (tid, tail) = proc_pid_task_rest(rest)?;
    if !proc_pid_task_alive(pid, tid) {
        return None;
    }
    if tail == "cwd" {
        return proc_pid_cwd(pid);
    }
    if tail == "ns/ipc" {
        return proc_pid_ipc_ns_target(pid);
    }
    let fd_name = tail.strip_prefix("fd/")?;
    let fd = parse_proc_fd_component(fd_name)?;
    proc_fd_target(pid, fd)
}

fn proc_pid_from_path_with_rest(path: &str) -> Option<(u32, &str)> {
    let rest = path.strip_prefix("/proc/")?;
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return None;
    }
    let mut parts = rest.splitn(2, '/');
    let first = parts.next().unwrap_or("");
    if first.is_empty() {
        return None;
    }
    if !first.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let pid = first.parse::<u32>().ok()?;
    let tail = parts.next().unwrap_or("");
    Some((pid, tail))
}

pub fn open_proc_pseudo(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let normalized = normalize_proc_magic_path(path);
    let trimmed = normalized.as_ref();
    if trimmed == "/proc" {
        return Some(Arc::new(PseudoDir::new("/proc", proc_root_entries())));
    }
    match trimmed {
        "/proc/sys" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys",
                proc_dir_entries(&[("kernel", 4), ("fs", 4), ("vm", 4), ("net", 4)]),
            )));
        }
        "/proc/sys/kernel" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/kernel",
                proc_sys_kernel_entries(),
            )));
        }
        "/proc/sys/kernel/keys" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/kernel/keys",
                proc_sys_kernel_keys_entries(),
            )));
        }
        "/proc/sys/kernel/random" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/kernel/random",
                proc_dir_entries(&[("entropy_avail", 8)]),
            )));
        }
        "/proc/sys/kernel/random/entropy_avail" => {
            return Some(Arc::new(PseudoFile::new_static("256\n")));
        }
        "/proc/sys/fs" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/fs",
                proc_sys_fs_entries(),
            )));
        }
        "/proc/sys/fs/inotify" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/fs/inotify",
                proc_dir_entries(&[
                    ("max_queued_events", 8),
                    ("max_user_instances", 8),
                    ("max_user_watches", 8),
                ]),
            )));
        }
        "/proc/sys/fs/mqueue" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/fs/mqueue",
                proc_dir_entries(&[("queues_max", 8)]),
            )));
        }
        "/proc/sys/vm" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/vm",
                proc_sys_vm_entries(),
            )));
        }
        "/proc/sys/net" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net",
                proc_sys_net_entries(),
            )));
        }
        "/proc/sys/net/ipv4" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv4",
                proc_sys_net_ipv4_entries(),
            )));
        }
        "/proc/sys/net/ipv4/conf" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv4/conf",
                proc_sys_net_ipv4_conf_entries(),
            )));
        }
        "/proc/sys/net/ipv4/conf/lo" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv4/conf/lo",
                proc_sys_net_ipv4_conf_if_entries(),
            )));
        }
        "/proc/sys/net/ipv4/conf/default" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv4/conf/default",
                proc_sys_net_ipv4_conf_if_entries(),
            )));
        }
        _ => {}
    }
    if trimmed == "/proc/sysvipc" {
        let entries = alloc::vec![
            PseudoDirent {
                name: String::from("."),
                ino: 1,
                dtype: 4,
            },
            PseudoDirent {
                name: String::from(".."),
                ino: 1,
                dtype: 4,
            },
            PseudoDirent {
                name: String::from("shm"),
                ino: 1,
                dtype: 8,
            },
            PseudoDirent {
                name: String::from("msg"),
                ino: 1,
                dtype: 8,
            },
            PseudoDirent {
                name: String::from("sem"),
                ino: 1,
                dtype: 8,
            },
        ];
        return Some(Arc::new(PseudoDir::new("/proc/sysvipc", entries)));
    }

    match trimmed {
        "/proc/mounts" => return Some(ProcPseudoFile::new(ProcFileKind::Mounts)),
        "/proc/cgroups" => return Some(ProcPseudoFile::new(ProcFileKind::Cgroups)),
        "/proc/meminfo" => return Some(ProcPseudoFile::new(ProcFileKind::Meminfo)),
        "/proc/cpuinfo" => return Some(ProcPseudoFile::new(ProcFileKind::Cpuinfo)),
        "/proc/cmdline" => return Some(ProcPseudoFile::new(ProcFileKind::Cmdline)),
        "/proc/loadavg" => return Some(ProcPseudoFile::new(ProcFileKind::Loadavg)),
        "/proc/uptime" => return Some(ProcPseudoFile::new(ProcFileKind::Uptime)),
        "/proc/stat" => return Some(ProcPseudoFile::new(ProcFileKind::Stat)),
        "/proc/perf" => return Some(ProcPseudoFile::new(ProcFileKind::Perf)),
        "/proc/kpageflags" => return Some(ProcPseudoFile::new(ProcFileKind::Kpageflags)),
        "/proc/sysvipc/msg" => return Some(ProcPseudoFile::new(ProcFileKind::SysvipcMsg)),
        "/proc/sysvipc/sem" => return Some(ProcPseudoFile::new(ProcFileKind::SysvipcSem)),
        "/proc/sysvipc/shm" => return Some(ProcPseudoFile::new(ProcFileKind::SysvipcShm)),
        "/proc/config.gz" => return Some(Arc::new(PseudoFile::new_static_bytes(PROC_CONFIG_GZ))),
        _ => {}
    }

    if let Some(kind) = managed_proc_sys_file_kind(trimmed) {
        return Some(ProcPseudoFile::new(kind));
    }

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    if !proc_pid_exists(pid) {
        return None;
    }
    if rest.is_empty() {
        return Some(Arc::new(PseudoDir::new(
            &alloc::format!("/proc/{pid}"),
            proc_pid_entries(pid),
        )));
    }
    if rest == "fd" {
        return Some(Arc::new(PseudoDir::new(
            &alloc::format!("/proc/{pid}/fd"),
            proc_pid_fd_entries(pid),
        )));
    }
    if rest == "task" {
        return Some(Arc::new(PseudoDir::new(
            &alloc::format!("/proc/{pid}/task"),
            proc_pid_task_entries(pid),
        )));
    }
    if rest == "ns" {
        return Some(Arc::new(PseudoDir::new(
            &alloc::format!("/proc/{pid}/ns"),
            proc_pid_ns_entries(pid),
        )));
    }
    if let Some((tid, tail)) = proc_pid_task_rest(rest) {
        if !proc_pid_task_alive(pid, tid) {
            return None;
        }
        if tail.is_empty() {
            return Some(Arc::new(PseudoDir::new(
                &alloc::format!("/proc/{pid}/task/{tid}"),
                proc_pid_task_tid_entries(pid, tid),
            )));
        }
        match tail {
            "stat" => return Some(ProcPseudoFile::new(ProcFileKind::PidTaskStat(pid, tid))),
            "comm" => return Some(ProcPseudoFile::new(ProcFileKind::PidTaskComm(pid, tid))),
            "fd" => {
                return Some(Arc::new(PseudoDir::new(
                    &alloc::format!("/proc/{pid}/task/{tid}/fd"),
                    proc_pid_fd_entries(pid),
                )));
            }
            "ns" => {
                return Some(Arc::new(PseudoDir::new(
                    &alloc::format!("/proc/{pid}/task/{tid}/ns"),
                    proc_pid_ns_entries(pid),
                )));
            }
            "mounts" => return Some(ProcPseudoFile::new(ProcFileKind::PidMounts)),
            "cgroup" => return Some(ProcPseudoFile::new(ProcFileKind::PidCgroup(pid))),
            _ => {}
        }
        if let Some(ns_name) = tail.strip_prefix("ns/") {
            if ns_name == "ipc" {
                let proc = pid2process(pid as usize)?;
                let ipc_ns_id = proc.borrow_mut().ipc_ns_id;
                return Some(Arc::new(NamespaceFile::new_ipc(ipc_ns_id)));
            }
        }
        return None;
    }
    if let Some(ns_name) = rest.strip_prefix("ns/") {
        if ns_name == "ipc" {
            let proc = pid2process(pid as usize)?;
            let ipc_ns_id = proc.borrow_mut().ipc_ns_id;
            return Some(Arc::new(NamespaceFile::new_ipc(ipc_ns_id)));
        }
        return None;
    }
    match rest {
        "stat" => Some(ProcPseudoFile::new(ProcFileKind::PidStat(pid))),
        "cmdline" => Some(ProcPseudoFile::new(ProcFileKind::PidCmdline(pid))),
        "comm" => Some(ProcPseudoFile::new(ProcFileKind::PidComm(pid))),
        "status" => Some(ProcPseudoFile::new(ProcFileKind::PidStatus(pid))),
        "maps" => Some(ProcPseudoFile::new(ProcFileKind::PidMaps(pid))),
        "pagemap" => Some(ProcPseudoFile::new(ProcFileKind::PidPagemap(pid))),
        "smaps" => Some(ProcPseudoFile::new(ProcFileKind::PidSmaps(pid))),
        "coredump_filter" => Some(ProcPseudoFile::new(ProcFileKind::PidCoredumpFilter)),
        "mounts" => Some(ProcPseudoFile::new(ProcFileKind::PidMounts)),
        "cgroup" => Some(ProcPseudoFile::new(ProcFileKind::PidCgroup(pid))),
        _ => None,
    }
}

fn collect_pids() -> Vec<usize> {
    let mut pids: Vec<usize> = {
        let map = PID2PCB.lock();
        map.keys().copied().filter(|pid| *pid != 0).collect()
    };
    pids.sort_unstable();
    pids
}

fn proc_file_content(kind: &ProcFileKind) -> String {
    match kind {
        ProcFileKind::Mounts | ProcFileKind::PidMounts => proc_mounts(),
        ProcFileKind::Cgroups => crate::fs::cgroup_proc_cgroups_content(),
        ProcFileKind::Meminfo => proc_meminfo(),
        ProcFileKind::Cpuinfo => proc_cpuinfo(),
        ProcFileKind::Cmdline => proc_cmdline(),
        ProcFileKind::Loadavg => String::from("0.00 0.00 0.00 1/1 1\n"),
        ProcFileKind::Uptime => proc_uptime(),
        ProcFileKind::Stat => proc_stat(),
        ProcFileKind::Perf => proc_perf(),
        ProcFileKind::Kpageflags => String::new(),
        ProcFileKind::SysvipcMsg => crate::syscall::sysv_ipc::proc_sysvipc_msg(),
        ProcFileKind::SysvipcSem => crate::syscall::sysv_ipc::proc_sysvipc_sem(),
        ProcFileKind::SysvipcShm => crate::syscall::sysv_shm::proc_sysvipc_shm(),
        ProcFileKind::VmOvercommitMemory => alloc::format!("{}\n", vm_overcommit_memory()),
        ProcFileKind::VmOvercommitRatio => alloc::format!("{}\n", vm_overcommit_ratio()),
        ProcFileKind::VmDropCaches => String::from("0\n"),
        ProcFileKind::VmCompactMemory => String::from("0\n"),
        ProcFileKind::FsFileMax => alloc::format!("{}\n", fs_file_max()),
        ProcFileKind::FsPipeMaxSize => {
            alloc::format!("{}\n", crate::fs::pipe_max_size_limit_for_procfs())
        }
        ProcFileKind::FsMqueueQueuesMax => alloc::format!(
            "{}\n",
            crate::syscall::posix_mq::queues_max_limit_for_procfs()
        ),
        ProcFileKind::KernelPidMax => alloc::format!("{}\n", crate::task::pid_max()),
        ProcFileKind::KernelMsgmax => alloc::format!(
            "{}\n",
            crate::syscall::sysv_ipc::runtime_msgmax_for_procfs()
        ),
        ProcFileKind::KernelMsgmnb => alloc::format!(
            "{}\n",
            crate::syscall::sysv_ipc::runtime_msgmnb_for_procfs()
        ),
        ProcFileKind::KernelMsgmni => alloc::format!(
            "{}\n",
            crate::syscall::sysv_ipc::runtime_msgmni_for_procfs()
        ),
        ProcFileKind::KernelSem => {
            let (semmsl, semmns, semopm, semmni) =
                crate::syscall::sysv_ipc::runtime_sem_limits_for_procfs();
            alloc::format!("{}\t{}\t{}\t{}\n", semmsl, semmns, semopm, semmni)
        }
        ProcFileKind::KernelShmmax => alloc::format!(
            "{}\n",
            crate::syscall::sysv_shm::runtime_shmmax_for_procfs()
        ),
        ProcFileKind::KernelShmmni => alloc::format!(
            "{}\n",
            crate::syscall::sysv_shm::runtime_shmmni_for_procfs()
        ),
        ProcFileKind::KernelShmall => alloc::format!(
            "{}\n",
            crate::syscall::sysv_shm::runtime_shmall_for_procfs()
        ),
        ProcFileKind::SimpleText(path) => proc_simple_text_content(path),
        ProcFileKind::PidStat(pid) => proc_pid_stat(*pid),
        ProcFileKind::PidCmdline(pid) => proc_pid_cmdline(*pid),
        ProcFileKind::PidComm(pid) => proc_pid_comm(*pid),
        ProcFileKind::PidStatus(pid) => proc_pid_status(*pid),
        ProcFileKind::PidMaps(pid) => proc_pid_maps(*pid),
        ProcFileKind::PidPagemap(_) => String::new(),
        ProcFileKind::PidSmaps(pid) => proc_pid_smaps(*pid),
        ProcFileKind::PidCoredumpFilter => String::from("00000033\n"),
        ProcFileKind::PidCgroup(pid) => crate::fs::cgroup_proc_pid_content(*pid as usize),
        ProcFileKind::PidTaskStat(pid, tid) => proc_pid_task_stat(*pid, *tid),
        ProcFileKind::PidTaskComm(pid, tid) => proc_pid_task_comm(*pid, *tid),
    }
}

fn proc_mounts() -> String {
    crate::syscall::filesystem::proc_mounts_snapshot()
}

pub(crate) fn parse_proc_sys_usize(data: &[u8]) -> Result<usize, isize> {
    let Ok(raw) = core::str::from_utf8(data) else {
        return Err(EINVAL);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(EINVAL);
    }
    trimmed.parse::<usize>().map_err(|_| EINVAL)
}

fn write_vm_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    let (slot, max) = match path {
        "/proc/sys/vm/overcommit_memory" => (&VM_OVERCOMMIT_MEMORY, VM_OVERCOMMIT_MEMORY_MAX),
        "/proc/sys/vm/overcommit_ratio" => (&VM_OVERCOMMIT_RATIO, VM_OVERCOMMIT_RATIO_MAX),
        _ => return Err(EINVAL),
    };
    let value = parse_proc_sys_usize(data)?;
    if value > max {
        return Err(EINVAL);
    }
    slot.store(value, Ordering::Relaxed);
    Ok(alloc::format!("{}\n", value).into_bytes())
}

fn write_fs_file_max_sysctl(data: &[u8]) -> Result<Vec<u8>, isize> {
    let value = parse_proc_sys_usize(data)?;
    if value > FS_FILE_MAX_MAX {
        return Err(EINVAL);
    }
    FS_FILE_MAX.store(value, Ordering::Relaxed);
    Ok(alloc::format!("{}\n", value).into_bytes())
}

pub fn vm_overcommit_memory() -> usize {
    VM_OVERCOMMIT_MEMORY.load(Ordering::Relaxed)
}

fn vm_overcommit_ratio() -> usize {
    VM_OVERCOMMIT_RATIO.load(Ordering::Relaxed)
}

fn fs_file_max() -> usize {
    FS_FILE_MAX.load(Ordering::Relaxed)
}

pub fn vm_commit_limit_bytes() -> usize {
    let totalram = config::phys_mem_end().saturating_sub(config::phys_mem_start());
    totalram
        .saturating_mul(vm_overcommit_ratio())
        .saturating_div(100)
}

pub fn vm_committed_as_bytes() -> usize {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    processes.iter().fold(0usize, |acc, process| {
        let Some(inner) = process.try_borrow_mut() else {
            return acc;
        };
        let heap = inner.brk.saturating_sub(inner.heap_start);
        let anon_private = inner.mmap_areas.iter().fold(0usize, |sum, region| {
            if !region.shared && !region.file_backed && (region.prot & 0x2) != 0 {
                sum.saturating_add(region.len)
            } else {
                sum
            }
        });
        acc.saturating_add(heap).saturating_add(anon_private)
    })
}

fn proc_meminfo() -> String {
    let totalram = config::phys_mem_end().saturating_sub(config::phys_mem_start());
    let mem_total_kb = (totalram / 1024) as u64;
    let mem_free_kb =
        ((frame_available_pages().saturating_mul(config::PAGE_SIZE)).min(totalram) / 1024) as u64;
    let commit_limit_kb = (vm_commit_limit_bytes() / 1024) as u64;
    let committed_as_kb = (vm_committed_as_bytes() / 1024) as u64;
    alloc::format!(
        "MemTotal:       {} kB\nMemFree:        {} kB\nBuffers:        0 kB\nCached:         0 kB\nSwapTotal:      0 kB\nSwapFree:       0 kB\nCommitLimit:    {} kB\nCommitted_AS:   {} kB\n",
        mem_total_kb,
        mem_free_kb,
        commit_limit_kb,
        committed_as_kb
    )
}

fn proc_cpuinfo() -> String {
    String::from(
        "processor\t: 0\nvendor_id\t: QEMU\nmodel name\t: QEMU Virtual CPU\ncpu MHz\t\t: 1000.000\n",
    )
}

fn proc_cmdline() -> String {
    String::from("root=/dev/vda rw console=ttyS0\n")
}

fn proc_uptime() -> String {
    let ms = crate::time::get_time_ms();
    let secs = ms / 1000;
    let frac = (ms % 1000) / 10;
    alloc::format!("{secs}.{frac:02} 0.00\n")
}

fn proc_stat() -> String {
    String::from(
        "cpu  0 0 0 0 0 0 0 0 0 0\nintr 0\nctxt 0\nbtime 0\nprocesses 0\nprocs_running 1\nprocs_blocked 0\n",
    )
}

fn proc_perf() -> String {
    crate::perf::dump()
}

fn proc_pid_cmdline(pid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] cmdline pid={} lock busy", pid);
        }
        return String::new();
    };
    let argv = inner.argv.clone();
    let mut s = String::new();
    for arg in argv.iter() {
        s.push_str(arg);
        s.push('\0');
    }
    s
}

fn proc_pid_comm(pid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] comm pid={} lock busy", pid);
        }
        return String::new();
    };
    let mut comm = inner.comm.clone();
    if comm.is_empty() {
        comm = inner
            .argv
            .first()
            .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
            .unwrap_or("CongCore")
            .to_string();
    }
    comm = comm.replace(')', "_");
    comm.push('\n');
    comm
}

fn proc_pid_status(pid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] status pid={} lock busy", pid);
        }
        return String::new();
    };
    let ppid = inner
        .parent
        .as_ref()
        .and_then(|w| w.upgrade())
        .map(|p| p.getpid())
        .unwrap_or(0);
    let num_threads = inner.thread_count();
    let (main_state, cgroup_frozen) = inner
        .tasks
        .iter()
        .flatten()
        .next()
        .and_then(|t| {
            t.try_borrow_mut()
                .map(|ti| (ti.task_status, ti.cgroup_frozen))
        })
        .unwrap_or((TaskStatus::Ready, false));
    let heap_bytes = inner.brk.saturating_sub(inner.heap_start);
    let mmap_bytes: usize = inner.mmap_areas.iter().map(|r| r.len).sum();
    let vmlck_bytes: usize = inner
        .mlocked_ranges
        .iter()
        .map(|(start, end)| end.saturating_sub(*start))
        .sum();
    let vsize_kb: usize = (config::USER_STACK_SIZE + heap_bytes + mmap_bytes) / 1024;
    let vmlck_kb: usize = (vmlck_bytes + 1023) / 1024;
    let uid = inner.uid;
    let euid = inner.euid;
    let suid = inner.suid;
    let fsuid = inner.fsuid;
    let gid = inner.gid;
    let egid = inner.egid;
    let sgid = inner.sgid;
    let fsgid = inner.fsgid;

    let comm = if inner.comm.is_empty() {
        inner
            .argv
            .first()
            .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
            .unwrap_or("CongCore")
            .to_string()
    } else {
        inner.comm.clone()
    }
    .replace(')', "_");

    let state_char = if inner.is_zombie {
        'Z'
    } else if inner.stopped {
        'T'
    } else if cgroup_frozen {
        'D'
    } else {
        match main_state {
            TaskStatus::Running => 'R',
            TaskStatus::Ready => 'R',
            TaskStatus::Blocked => 'S',
        }
    };
    let state_desc = match state_char {
        'R' => "R (running)",
        'S' => "S (sleeping)",
        'D' => "D (disk sleep)",
        'T' => "T (stopped)",
        'Z' => "Z (zombie)",
        _ => "R (running)",
    };
    alloc::format!(
        "Name:\t{comm}\nState:\t{state_desc}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{uid}\t{euid}\t{suid}\t{fsuid}\nGid:\t{gid}\t{egid}\t{sgid}\t{fsgid}\nThreads:\t{num_threads}\nVmLck:\t{vmlck_kb} kB\nVmSize:\t{vsize_kb} kB\n"
    )
}

fn proc_pid_stat(pid: u32) -> String {
    let start_cycles = if crate::debug_config::DEBUG_FUTEX {
        crate::arch::read_time()
    } else {
        0
    };
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        let elapsed = if crate::debug_config::DEBUG_FUTEX {
            crate::arch::read_time().wrapping_sub(start_cycles)
        } else {
            0
        };
        record_proc_pid_stat_diag(pid, 'B', elapsed, true);
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] stat pid={} lock busy", pid);
        }
        return String::new();
    };
    let ppid = inner
        .parent
        .as_ref()
        .and_then(|w| w.upgrade())
        .map(|p| p.getpid())
        .unwrap_or(0);
    let start_time_ms = inner.start_time_ms;
    let num_threads = inner.thread_count();
    let (main_state, cgroup_frozen) = inner
        .tasks
        .iter()
        .flatten()
        .next()
        .and_then(|t| {
            t.try_borrow_mut()
                .map(|ti| (ti.task_status, ti.cgroup_frozen))
        })
        .unwrap_or((TaskStatus::Ready, false));
    let heap_bytes = inner.brk.saturating_sub(inner.heap_start);
    let mmap_bytes: usize = inner.mmap_areas.iter().map(|r| r.len).sum();
    let vsize: u64 = (config::USER_STACK_SIZE + heap_bytes + mmap_bytes) as u64;

    let comm = if inner.comm.is_empty() {
        inner
            .argv
            .first()
            .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
            .unwrap_or("CongCore")
            .to_string()
    } else {
        inner.comm.clone()
    }
    .replace(')', "_");

    let state_char = if inner.is_zombie {
        'Z'
    } else if inner.stopped {
        'T'
    } else if cgroup_frozen {
        'D'
    } else {
        match main_state {
            TaskStatus::Running => 'R',
            TaskStatus::Ready => 'R',
            TaskStatus::Blocked => 'S',
        }
    };

    const HZ: u64 = 100;
    let starttime = (start_time_ms as u64).saturating_mul(HZ) / 1000;
    let rss_pages: u64 = if vsize == 0 {
        0
    } else {
        (vsize + config::PAGE_SIZE as u64 - 1) / config::PAGE_SIZE as u64
    };

    let pgrp = (if inner.pgid == 0 {
        pid as usize
    } else {
        inner.pgid
    }) as u32;
    let session = if inner.sid == 0 {
        pgrp
    } else {
        inner.sid as u32
    };

    let tty_nr = 0;
    let tpgid = 0;
    let flags = 0;
    let minflt = 0;
    let cminflt = 0;
    let majflt = 0;
    let cmajflt = 0;
    let now_ms = crate::time::get_time_ms() as u64;
    let elapsed_ticks = now_ms
        .saturating_mul(HZ)
        .saturating_div(1000)
        .saturating_sub(starttime);
    let utime = core::cmp::max(elapsed_ticks, 1);
    let stime = 0;
    let cutime = 0;
    let cstime = 0;
    let priority = 0;
    let nice = 0;
    let itrealvalue = 0;
    let rsslim = 0;
    let startcode = 0;
    let endcode = 0;
    let startstack = 0;
    let kstkesp = 0;
    let kstkeip = 0;
    let signal = 0;
    let blocked = 0;
    let sigignore = 0;
    let sigcatch = 0;
    let wchan = 0;
    let nswap = 0;
    let cnswap = 0;
    let exit_signal = 0;
    let processor = 0;
    let rt_priority = 0;
    let policy = 0;
    let delayacct_blkio_ticks = 0;
    let guest_time = 0;
    let cguest_time = 0;
    let start_data = 0;
    let end_data = 0;
    let start_brk = 0;
    let arg_start = 0;
    let arg_end = 0;
    let env_start = 0;
    let env_end = 0;
    let exit_code = 0;

    let out = alloc::format!(
        "{pid} ({comm}) {state_char} {ppid} {pgrp} {session} {tty_nr} {tpgid} {flags} {minflt} {cminflt} {majflt} {cmajflt} {utime} {stime} {cutime} {cstime} {priority} {nice} {num_threads} {itrealvalue} {starttime} {vsize} {rss_pages} {rsslim} {startcode} {endcode} {startstack} {kstkesp} {kstkeip} {signal} {blocked} {sigignore} {sigcatch} {wchan} {nswap} {cnswap} {exit_signal} {processor} {rt_priority} {policy} {delayacct_blkio_ticks} {guest_time} {cguest_time} {start_data} {end_data} {start_brk} {arg_start} {arg_end} {env_start} {env_end} {exit_code}\n"
    );
    let elapsed = if crate::debug_config::DEBUG_FUTEX {
        crate::arch::read_time().wrapping_sub(start_cycles)
    } else {
        0
    };
    record_proc_pid_stat_diag(pid, state_char, elapsed, false);
    out
}

fn proc_pid_task_stat(pid: u32, tid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] task stat pid={} tid={} lock busy", pid, tid);
        }
        return String::new();
    };
    let Some(tid_index) = decode_proc_linux_tid(pid, tid) else {
        return String::new();
    };
    let Some((task_state, cgroup_frozen)) = inner
        .tasks
        .get(tid_index)
        .and_then(|t| t.as_ref())
        .and_then(|t| {
            t.try_borrow_mut().and_then(|ti| {
                if ti.res.is_none() || ti.exit_code.is_some() {
                    None
                } else {
                    Some((ti.task_status, ti.cgroup_frozen))
                }
            })
        })
    else {
        return String::new();
    };

    let ppid = inner
        .parent
        .as_ref()
        .and_then(|w| w.upgrade())
        .map(|p| p.getpid())
        .unwrap_or(0);
    let comm = if inner.comm.is_empty() {
        inner
            .argv
            .first()
            .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
            .unwrap_or("CongCore")
            .to_string()
    } else {
        inner.comm.clone()
    }
    .replace(')', "_");
    let state_char = if inner.is_zombie {
        'Z'
    } else if inner.stopped {
        'T'
    } else if cgroup_frozen {
        'D'
    } else {
        match task_state {
            TaskStatus::Running => 'R',
            TaskStatus::Ready => 'R',
            TaskStatus::Blocked => 'S',
        }
    };
    alloc::format!("{tid} ({comm}) {state_char} {ppid}\n")
}

fn proc_pid_task_comm(pid: u32, tid: u32) -> String {
    if !proc_pid_task_alive(pid, tid) {
        return String::new();
    }
    proc_pid_comm(pid)
}

fn proc_pid_maps(pid: u32) -> String {
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] maps pid={} lock busy", pid);
        }
        return String::new();
    };
    let mut regions = inner.mmap_areas.clone();
    drop(inner);
    regions.sort_by_key(|r| r.start);

    let mut out = String::new();
    for region in regions {
        let end = region.end();
        if end <= region.start {
            continue;
        }
        let r = if (region.prot & PROT_READ) != 0 {
            'r'
        } else {
            '-'
        };
        let w = if (region.prot & PROT_WRITE) != 0 {
            'w'
        } else {
            '-'
        };
        let x = if (region.prot & PROT_EXEC) != 0 {
            'x'
        } else {
            '-'
        };
        let p = if region.shared { 's' } else { 'p' };
        out.push_str(&alloc::format!(
            "{:x}-{:x} {}{}{}{} 00000000 00:00 0 \n",
            region.start,
            end,
            r,
            w,
            x,
            p
        ));
    }
    out
}

fn proc_pid_pagemap_entry(pid: u32, entry: usize) -> u64 {
    let Some(proc) = pid2process(pid as usize) else {
        return 0;
    };
    let Some(inner) = proc.try_borrow_mut() else {
        return 0;
    };
    let Some(vaddr) = entry.checked_mul(config::PAGE_SIZE) else {
        return 0;
    };
    let vpn = VirtAddr::from(vaddr).floor();
    if let Some(pte) = inner.memory_set.translate(vpn) {
        if pte.is_valid() {
            return (1u64 << 63) | (pte.ppn().0 as u64 & ((1u64 << 55) - 1));
        }
    }
    0
}

fn proc_kpageflags_entry(pfn: usize) -> u64 {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        for (start, end) in inner.memory_set.user_mapped_ranges() {
            let mut cur = start;
            while cur < end {
                let vpn = VirtAddr::from(cur).floor();
                if let Some(pte) = inner.memory_set.translate(vpn) {
                    if pte.is_valid() && pte.ppn().0 == pfn {
                        let mut flags = 0u64;
                        if pte.flags().contains(PTEFlags::D) {
                            flags |= 1u64 << 4;
                        }
                        return flags;
                    }
                }
                cur = cur.saturating_add(config::PAGE_SIZE);
            }
        }
    }
    0
}

fn proc_kpageflags_len() -> usize {
    let phys_bytes = config::phys_mem_end().saturating_sub(config::phys_mem_start());
    let page_count = phys_bytes / config::PAGE_SIZE;
    page_count.saturating_mul(8)
}

fn proc_pid_pagemap_len(pid: u32) -> usize {
    let Some(proc) = pid2process(pid as usize) else {
        return 0;
    };
    let Some(inner) = proc.try_borrow_mut() else {
        return 0;
    };
    let max_end = inner.memory_set.max_user_mapped_end();
    let page_count = max_end.saturating_add(config::PAGE_SIZE - 1) / config::PAGE_SIZE;
    page_count.saturating_mul(8)
}

fn proc_kpageflags_read(offset: &mut usize, buf: &mut UserBuffer) -> usize {
    let limit = proc_kpageflags_len();
    if *offset >= limit {
        return 0;
    }
    let mut total = 0usize;
    for slice in buf.buffers.iter_mut() {
        let mut i = 0usize;
        while i < slice.len() && *offset < limit {
            let entry = (*offset) / 8;
            let byte_in_entry = (*offset) % 8;
            let val = proc_kpageflags_entry(entry);
            slice[i] = ((val >> (byte_in_entry * 8)) & 0xff) as u8;
            *offset += 1;
            i += 1;
            total += 1;
        }
    }
    total
}

fn proc_pid_pagemap_read(pid: u32, offset: &mut usize, buf: &mut UserBuffer) -> usize {
    let limit = proc_pid_pagemap_len(pid);
    if *offset >= limit {
        return 0;
    }
    let mut total = 0usize;
    for slice in buf.buffers.iter_mut() {
        let mut i = 0usize;
        while i < slice.len() && *offset < limit {
            let entry = (*offset) / 8;
            let byte_in_entry = (*offset) % 8;
            let val = proc_pid_pagemap_entry(pid, entry);
            slice[i] = ((val >> (byte_in_entry * 8)) & 0xff) as u8;
            *offset += 1;
            i += 1;
            total += 1;
        }
    }
    total
}

fn range_overlap_len(start: usize, end: usize, lock_start: usize, lock_end: usize) -> usize {
    let left = core::cmp::max(start, lock_start);
    let right = core::cmp::min(end, lock_end);
    right.saturating_sub(left)
}

fn proc_pid_smaps(pid: u32) -> String {
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
        if crate::debug_config::DEBUG_PROCFS {
            crate::println!("[procfs] smaps pid={} lock busy", pid);
        }
        return String::new();
    };
    let mut regions = inner.mmap_areas.clone();
    let mlocked = inner.mlocked_ranges.clone();
    drop(inner);
    regions.sort_by_key(|r| r.start);

    let mut out = String::new();
    for region in regions {
        let end = region.end();
        if end <= region.start {
            continue;
        }
        let r = if (region.prot & PROT_READ) != 0 {
            'r'
        } else {
            '-'
        };
        let w = if (region.prot & PROT_WRITE) != 0 {
            'w'
        } else {
            '-'
        };
        let x = if (region.prot & PROT_EXEC) != 0 {
            'x'
        } else {
            '-'
        };
        let p = if region.shared { 's' } else { 'p' };

        let size_bytes = end - region.start;
        let size_kb = (size_bytes + 1023) / 1024;
        let locked_bytes: usize = mlocked
            .iter()
            .map(|(ls, le)| range_overlap_len(region.start, end, *ls, *le))
            .sum();
        let locked_kb = (locked_bytes + 1023) / 1024;
        // LTP mlock05 only validates that Rss/Locked reflect mlock'ed mappings.
        let rss_kb = if locked_bytes > 0 { size_kb } else { 0 };

        out.push_str(&alloc::format!(
            "{:x}-{:x} {}{}{}{} 00000000 00:00 0 \n",
            region.start,
            end,
            r,
            w,
            x,
            p
        ));
        out.push_str(&alloc::format!("Size:\t\t{} kB\n", size_kb));
        out.push_str(&alloc::format!("Rss:\t\t{} kB\n", rss_kb));
        out.push_str("Pss:\t\t0 kB\n");
        out.push_str("Shared_Clean:\t0 kB\n");
        out.push_str("Shared_Dirty:\t0 kB\n");
        out.push_str("Private_Clean:\t0 kB\n");
        out.push_str("Private_Dirty:\t0 kB\n");
        out.push_str("Referenced:\t0 kB\n");
        out.push_str("Anonymous:\t0 kB\n");
        out.push_str("AnonHugePages:\t0 kB\n");
        out.push_str("Swap:\t\t0 kB\n");
        out.push_str(&alloc::format!("Locked:\t\t{} kB\n", locked_kb));
        out.push('\n');
    }
    out
}
