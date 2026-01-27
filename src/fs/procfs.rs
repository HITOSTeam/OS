extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::config;
use crate::fs::{ext4_lock, find_path_in_roots, root_inode_for_path, PseudoDirent};
use crate::task::manager::{pid2process, PID2PCB};
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
static PROC_FILES: Mutex<BTreeMap<u32, ProcFileKind>> = Mutex::new(BTreeMap::new());

pub fn proc_root_inode_num() -> Option<u32> {
    let ino = PROC_ROOT_INO.load(Ordering::Relaxed);
    if ino == 0 { None } else { Some(ino) }
}

pub fn is_proc_root(inode_num: u32) -> bool {
    proc_root_inode_num() == Some(inode_num)
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

    let _ = ensure_proc_file(&proc_inode, "mounts", ProcFileKind::Mounts, 0o444);
    let _ = ensure_proc_file(&proc_inode, "meminfo", ProcFileKind::Meminfo, 0o444);
    let _ = ensure_proc_file(&proc_inode, "loadavg", ProcFileKind::Loadavg, 0o444);
    let _ = ensure_proc_file(&proc_inode, "uptime", ProcFileKind::Uptime, 0o444);
    let _ = ensure_proc_file(&proc_inode, "stat", ProcFileKind::Stat, 0o444);
    let _ = ensure_proc_file(&proc_inode, "perf", ProcFileKind::Perf, 0o444);

    let sys_dir = ensure_dir(&proc_inode, "sys", 0o555);
    if let Some(sys_dir) = sys_dir {
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
    sync_proc_pid(pid);
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
        map.keys().copied().collect()
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
    let _ = ensure_proc_file(&pid_dir, "cmdline", ProcFileKind::PidCmdline(pid_u32), 0o444);
    let _ = ensure_proc_file(&pid_dir, "status", ProcFileKind::PidStatus(pid_u32), 0o444);
    let _ = ensure_proc_file(&pid_dir, "maps", ProcFileKind::PidMaps(pid_u32), 0o444);
    let _ = ensure_proc_file(&pid_dir, "mounts", ProcFileKind::PidMounts(pid_u32), 0o444);
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
    let mem_total_kb =
        ((config::phys_mem_end() - config::phys_mem_start()) / 1024) as u64;
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
    let argv = { proc.borrow_mut().argv.clone() };
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
    let (ppid, argv, num_threads, main_state, vsize_kb) = {
        let inner = proc.borrow_mut();
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
        let vsize_kb: usize =
            (config::USER_STACK_SIZE + heap_bytes + mmap_bytes) / 1024;
        (ppid, argv, num_threads, main_state, vsize_kb)
    };

    let comm = argv
        .first()
        .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
        .unwrap_or("CongCore")
        .replace(')', "_");

    let state_char = match main_state {
        TaskStatus::Running => 'R',
        TaskStatus::Ready => 'R',
        TaskStatus::Blocked => 'S',
    };
    let state_desc = match state_char {
        'R' => "R (running)",
        'S' => "S (sleeping)",
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
    let (ppid, argv, start_time_ms, num_threads, main_state, vsize) = {
        let inner = proc.borrow_mut();
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
        let vsize: u64 =
            (config::USER_STACK_SIZE + heap_bytes + mmap_bytes) as u64;
        (ppid, argv, start_time_ms, num_threads, main_state, vsize)
    };

    let comm = argv
        .first()
        .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
        .unwrap_or("CongCore")
        .replace(')', "_");

    let state_char = match main_state {
        TaskStatus::Running => 'R',
        TaskStatus::Ready => 'R',
        TaskStatus::Blocked => 'S',
    };

    const HZ: u64 = 100;
    let starttime = (start_time_ms as u64).saturating_mul(HZ) / 1000;
    let rss_pages: u64 = if vsize == 0 {
        0
    } else {
        (vsize + config::PAGE_SIZE as u64 - 1) / config::PAGE_SIZE as u64
    };

    let pgrp = pid;
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
