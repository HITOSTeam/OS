extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use spin::Mutex;

use crate::config;
use crate::fs::{
    ext4_lock, find_path_in_roots, root_inode_for_path, File, PseudoDir, PseudoDirent, PseudoFile,
};
use crate::mm::UserBuffer;
use crate::task::manager::{pid2process, PID2PCB};
use crate::task::processor::current_process;
use crate::task::task_block::TaskStatus;

#[derive(Clone, Debug)]
pub enum ProcFileKind {
    Mounts,
    Meminfo,
    Loadavg,
    Uptime,
    Stat,
    Perf,
    PidStat(u32),
    PidCmdline(u32),
    PidStatus(u32),
    PidMaps(u32),
    PidMounts(u32),
}

static PROC_ROOT_INO: AtomicU32 = AtomicU32::new(0);
static PROC_ROOT_DEV: AtomicUsize = AtomicUsize::new(0);
static PROC_FILES: Mutex<BTreeMap<u32, ProcFileKind>> = Mutex::new(BTreeMap::new());

// gzip-compressed minimal config for LTP kconfig checks.
const PROC_CONFIG_GZ: &[u8] = &[
    31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 115, 246, 247, 115, 243, 116, 143, 119, 10, 118, 137, 15, 8,
    242, 119, 118, 13, 14, 142, 119, 116, 118, 14, 177, 173, 228, 82, 86, 112, 198, 46, 23, 31,
    102, 172, 144, 89, 172, 144, 151, 95, 162, 80, 156, 90, 194, 5, 0, 236, 87, 124, 248, 66, 0, 0,
    0,
];

struct ProcPseudoInner {
    offset: usize,
}

pub struct ProcPseudoFile {
    kind: ProcFileKind,
    inner: Mutex<ProcPseudoInner>,
}

impl ProcPseudoFile {
    pub fn new(kind: ProcFileKind) -> Arc<Self> {
        Arc::new(Self {
            kind,
            inner: Mutex::new(ProcPseudoInner { offset: 0 }),
        })
    }
}

impl File for ProcPseudoFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let mut inner = self.inner.lock();
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

pub fn proc_root_inode_num() -> Option<u32> {
    let ino = PROC_ROOT_INO.load(Ordering::Relaxed);
    if ino == 0 {
        None
    } else {
        Some(ino)
    }
}

pub fn is_proc_root(inode: &ext4_fs::Inode) -> bool {
    let ino = PROC_ROOT_INO.load(Ordering::Relaxed);
    let dev = PROC_ROOT_DEV.load(Ordering::Relaxed);
    ino != 0 && dev != 0 && inode.inode_num() == ino && inode.device_id() == dev
}

pub fn proc_file_kind(inode_num: u32) -> Option<ProcFileKind> {
    PROC_FILES.lock().get(&inode_num).cloned()
}

pub fn proc_file_len(kind: &ProcFileKind) -> usize {
    proc_file_content(kind).len()
}

pub fn init_procfs() {
    let _guard = ext4_lock();
    let root = root_inode_for_path("/");
    let proc_inode = match root.find("proc") {
        Some(v) => v,
        None => match root.create_dir("proc") {
            Ok(v) => v,
            Err(_) => return,
        },
    };
    proc_inode.set_mode(0o555);
    PROC_ROOT_INO.store(proc_inode.inode_num(), Ordering::Relaxed);
    PROC_ROOT_DEV.store(proc_inode.device_id(), Ordering::Relaxed);

    let _ = ensure_proc_file(&proc_inode, "mounts", ProcFileKind::Mounts, 0o444);
    let _ = ensure_proc_file(&proc_inode, "meminfo", ProcFileKind::Meminfo, 0o444);
    let _ = ensure_proc_file(&proc_inode, "loadavg", ProcFileKind::Loadavg, 0o444);
    let _ = ensure_proc_file(&proc_inode, "uptime", ProcFileKind::Uptime, 0o444);
    let _ = ensure_proc_file(&proc_inode, "stat", ProcFileKind::Stat, 0o444);
    let _ = ensure_proc_file(&proc_inode, "perf", ProcFileKind::Perf, 0o444);

    let sys_dir = ensure_dir(&proc_inode, "sys", 0o555);
    if let Some(sys_dir) = sys_dir {
        let kernel_dir = ensure_dir(&sys_dir, "kernel", 0o555);
        if let Some(kernel_dir) = kernel_dir {
            let core_pattern = ensure_file(&kernel_dir, "core_pattern", 0o644);
            if let Some(core_pattern) = core_pattern {
                let _ = core_pattern.write_at(0, b"core\n");
            }
            let pid_max_file = ensure_file(&kernel_dir, "pid_max", 0o644);
            if let Some(pid_max_file) = pid_max_file {
                let value = alloc::format!("{}\n", crate::task::pid_max());
                let _ = pid_max_file.write_at(0, value.as_bytes());
            }
        }
        let fs_dir = ensure_dir(&sys_dir, "fs", 0o555);
        if let Some(fs_dir) = fs_dir {
            let pipe_max = ensure_file(&fs_dir, "pipe-max-size", 0o444);
            if let Some(pipe_max) = pipe_max {
                let _ = pipe_max.write_at(0, b"4096");
            }
        }
    }

    if proc_inode.find("config.gz").is_none() {
        if find_path_in_roots("/config.gz").is_some() {
            let _ = proc_inode.create_symlink("config.gz", "/config.gz");
        }
    }
}

pub fn sync_proc_path(abs: &str) {
    let pid = match proc_pid_from_path(abs) {
        Some(v) => v,
        None => return,
    };
    if pid == 0 {
        return;
    }
    sync_proc_pid(pid);
}

pub fn is_proc_pseudo_path(abs: &str) -> bool {
    if abs == "/proc" || abs.starts_with("/proc/") {
        return !(abs == "/proc/sys" || abs.starts_with("/proc/sys/"));
    }
    false
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
        name: String::from("sys"),
        ino: 1,
        dtype: 4,
    });
    for name in [
        "mounts",
        "meminfo",
        "loadavg",
        "uptime",
        "stat",
        "perf",
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
    for name in ["stat", "cmdline", "status", "maps", "mounts"] {
        entries.push(PseudoDirent {
            name: String::from(name),
            ino: pid as u64,
            dtype: 8,
        });
    }
    entries
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
    let trimmed = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };
    if trimmed == "/proc" {
        return Some(Arc::new(PseudoDir::new("/proc", proc_root_entries())));
    }
    if trimmed == "/proc/self" || trimmed.starts_with("/proc/self/") {
        let pid = current_process().getpid();
        let suffix = &trimmed["/proc/self".len()..];
        let mapped = alloc::format!("/proc/{pid}{suffix}");
        return open_proc_pseudo(&mapped);
    }

    match trimmed {
        "/proc/mounts" => return Some(ProcPseudoFile::new(ProcFileKind::Mounts)),
        "/proc/meminfo" => return Some(ProcPseudoFile::new(ProcFileKind::Meminfo)),
        "/proc/loadavg" => return Some(ProcPseudoFile::new(ProcFileKind::Loadavg)),
        "/proc/uptime" => return Some(ProcPseudoFile::new(ProcFileKind::Uptime)),
        "/proc/stat" => return Some(ProcPseudoFile::new(ProcFileKind::Stat)),
        "/proc/perf" => return Some(ProcPseudoFile::new(ProcFileKind::Perf)),
        "/proc/config.gz" => return Some(Arc::new(PseudoFile::new_static_bytes(PROC_CONFIG_GZ))),
        _ => {}
    }

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    if rest.is_empty() {
        return Some(Arc::new(PseudoDir::new(
            &alloc::format!("/proc/{pid}"),
            proc_pid_entries(pid),
        )));
    }
    match rest {
        "stat" => Some(ProcPseudoFile::new(ProcFileKind::PidStat(pid))),
        "cmdline" => Some(ProcPseudoFile::new(ProcFileKind::PidCmdline(pid))),
        "status" => Some(ProcPseudoFile::new(ProcFileKind::PidStatus(pid))),
        "maps" => Some(ProcPseudoFile::new(ProcFileKind::PidMaps(pid))),
        "mounts" => Some(ProcPseudoFile::new(ProcFileKind::PidMounts(pid))),
        _ => None,
    }
}

pub fn build_proc_root_entries(
    static_entries: Vec<(String, u32, u8)>,
    pids: Vec<usize>,
) -> Vec<PseudoDirent> {
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
    for (name, ino, ftype) in static_entries {
        if name == "." || name == ".." || name == "self" {
            continue;
        }
        if name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        entries.push(PseudoDirent {
            name,
            ino: ino as u64,
            dtype: dt_type_from_ext4(ftype),
        });
    }
    entries.push(PseudoDirent {
        name: String::from("self"),
        ino: 1,
        dtype: 10,
    });
    for pid in pids {
        entries.push(PseudoDirent {
            name: alloc::format!("{}", pid),
            ino: pid as u64,
            dtype: 4,
        });
    }
    entries
}

pub fn collect_pids() -> Vec<usize> {
    let mut pids: Vec<usize> = {
        let map = PID2PCB.lock();
        map.keys().copied().filter(|pid| *pid != 0).collect()
    };
    pids.sort_unstable();
    pids
}

pub fn proc_file_content(kind: &ProcFileKind) -> String {
    match kind {
        ProcFileKind::Mounts | ProcFileKind::PidMounts(_) => proc_mounts(),
        ProcFileKind::Meminfo => proc_meminfo(),
        ProcFileKind::Loadavg => String::from("0.00 0.00 0.00 1/1 1\n"),
        ProcFileKind::Uptime => proc_uptime(),
        ProcFileKind::Stat => proc_stat(),
        ProcFileKind::Perf => proc_perf(),
        ProcFileKind::PidStat(pid) => proc_pid_stat(*pid),
        ProcFileKind::PidCmdline(pid) => proc_pid_cmdline(*pid),
        ProcFileKind::PidStatus(pid) => proc_pid_status(*pid),
        ProcFileKind::PidMaps(_) => String::from("00000000-00000000 r--p 00000000 00:00 0 \n"),
    }
}

fn proc_pid_from_path(path: &str) -> Option<usize> {
    let rest = path.strip_prefix("/proc/")?;
    let first = rest.split('/').next().unwrap_or("");
    if first.is_empty() {
        return None;
    }
    if !first.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    first.parse::<usize>().ok()
}

fn sync_proc_pid(pid: usize) {
    if crate::debug_config::DEBUG_PROCFS {
        crate::println!("[procfs] sync pid={} begin", pid);
    }
    let _guard = ext4_lock();
    let proc_inode = match find_path_in_roots("/proc") {
        Some(v) => v,
        None => return,
    };
    let name = alloc::format!("{}", pid);
    let pid_dir = match proc_inode.find(&name) {
        Some(v) => v,
        None => match proc_inode.create_dir(&name) {
            Ok(v) => v,
            Err(_) => return,
        },
    };
    pid_dir.set_mode(0o555);

    let pid_u32 = pid as u32;
    let _ = ensure_proc_file(&pid_dir, "stat", ProcFileKind::PidStat(pid_u32), 0o444);
    let _ = ensure_proc_file(
        &pid_dir,
        "cmdline",
        ProcFileKind::PidCmdline(pid_u32),
        0o444,
    );
    let _ = ensure_proc_file(&pid_dir, "status", ProcFileKind::PidStatus(pid_u32), 0o444);
    let _ = ensure_proc_file(&pid_dir, "maps", ProcFileKind::PidMaps(pid_u32), 0o444);
    let _ = ensure_proc_file(&pid_dir, "mounts", ProcFileKind::PidMounts(pid_u32), 0o444);
    if crate::debug_config::DEBUG_PROCFS {
        crate::println!("[procfs] sync pid={} end", pid);
    }
}

fn ensure_dir(parent: &Arc<ext4_fs::Inode>, name: &str, mode: u16) -> Option<Arc<ext4_fs::Inode>> {
    let inode = match parent.find(name) {
        Some(v) => v,
        None => parent.create_dir(name).ok()?,
    };
    inode.set_mode(mode);
    Some(inode)
}

fn ensure_file(parent: &Arc<ext4_fs::Inode>, name: &str, mode: u16) -> Option<Arc<ext4_fs::Inode>> {
    let inode = match parent.find(name) {
        Some(v) => v,
        None => parent.create_file(name).ok()?,
    };
    inode.set_mode(mode);
    Some(inode)
}

fn ensure_proc_file(
    parent: &Arc<ext4_fs::Inode>,
    name: &str,
    kind: ProcFileKind,
    mode: u16,
) -> Option<Arc<ext4_fs::Inode>> {
    let inode = ensure_file(parent, name, mode)?;
    PROC_FILES.lock().insert(inode.inode_num(), kind);
    Some(inode)
}

fn dt_type_from_ext4(ftype: u8) -> u8 {
    match ftype {
        2 => 4,  // DT_DIR
        1 => 8,  // DT_REG
        7 => 10, // DT_LNK
        _ => 0,  // DT_UNKNOWN
    }
}

fn proc_mounts() -> String {
    String::from("/dev/root / ext4 rw 0 0\n")
}

fn proc_meminfo() -> String {
    let mem_total_kb = ((config::phys_mem_end() - config::phys_mem_start()) / 1024) as u64;
    alloc::format!(
        "MemTotal:       {} kB\nMemFree:        {} kB\nBuffers:        0 kB\nCached:         0 kB\nSwapTotal:      0 kB\nSwapFree:       0 kB\n",
        mem_total_kb,
        mem_total_kb / 2
    )
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
    let argv = inner.argv.clone();
    let num_threads = inner.thread_count();
    let main_state = inner
        .tasks
        .iter()
        .flatten()
        .next()
        .and_then(|t| t.try_borrow_mut().map(|ti| ti.task_status))
        .unwrap_or(TaskStatus::Ready);
    let heap_bytes = inner.brk.saturating_sub(inner.heap_start);
    let mmap_bytes: usize = inner
        .mmap_areas
        .iter()
        .map(|(s, e)| e.saturating_sub(*s))
        .sum();
    let vsize_kb: usize = (config::USER_STACK_SIZE + heap_bytes + mmap_bytes) / 1024;

    let comm = argv
        .first()
        .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
        .unwrap_or("CongCore")
        .replace(')', "_");

    let state_char = if inner.stopped {
        'T'
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
        'T' => "T (stopped)",
        _ => "R (running)",
    };
    alloc::format!(
        "Name:\t{comm}\nState:\t{state_desc}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nThreads:\t{num_threads}\nVmSize:\t{vsize_kb} kB\n"
    )
}

fn proc_pid_stat(pid: u32) -> String {
    let Some(proc) = pid2process(pid as usize) else {
        return String::new();
    };
    let Some(inner) = proc.try_borrow_mut() else {
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
    let argv = inner.argv.clone();
    let start_time_ms = inner.start_time_ms;
    let num_threads = inner.thread_count();
    let main_state = inner
        .tasks
        .iter()
        .flatten()
        .next()
        .and_then(|t| t.try_borrow_mut().map(|ti| ti.task_status))
        .unwrap_or(TaskStatus::Ready);
    let heap_bytes = inner.brk.saturating_sub(inner.heap_start);
    let mmap_bytes: usize = inner
        .mmap_areas
        .iter()
        .map(|(s, e)| e.saturating_sub(*s))
        .sum();
    let vsize: u64 = (config::USER_STACK_SIZE + heap_bytes + mmap_bytes) as u64;

    let comm = argv
        .first()
        .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
        .unwrap_or("CongCore")
        .replace(')', "_");

    let state_char = if inner.stopped {
        'T'
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

    let pgrp = inner.pgid as u32;
    let session = pid;
    let tty_nr = 0;
    let tpgid = 0;
    let flags = 0;
    let minflt = 0;
    let cminflt = 0;
    let majflt = 0;
    let cmajflt = 0;
    let utime = 0;
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

    alloc::format!(
        "{pid} ({comm}) {state_char} {ppid} {pgrp} {session} {tty_nr} {tpgid} {flags} {minflt} {cminflt} {majflt} {cmajflt} {utime} {stime} {cutime} {cstime} {priority} {nice} {num_threads} {itrealvalue} {starttime} {vsize} {rss_pages} {rsslim} {startcode} {endcode} {startstack} {kstkesp} {kstkeip} {signal} {blocked} {sigignore} {sigcatch} {wchan} {nswap} {cnswap} {exit_signal} {processor} {rt_priority} {policy} {delayacct_blkio_ticks} {guest_time} {cguest_time} {start_data} {end_data} {start_brk} {arg_start} {arg_end} {env_start} {env_end} {exit_code}\n"
    )
}
