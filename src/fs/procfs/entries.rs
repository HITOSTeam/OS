extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::PseudoDirent;
use crate::task::manager::{PID2PCB, pid2process};
use crate::task::processor::current_process;

use super::ProcFileKind;
use crate::syscall::error::{SyscallError, err};

const PROC_LINUX_TID_PID_SHIFT: usize = 15;
static PROC_SIMPLE_TEXT_FILES: Mutex<BTreeMap<&'static str, Vec<u8>>> = Mutex::new(BTreeMap::new());

pub(crate) fn collect_pids() -> Vec<usize> {
    let mut pids: Vec<usize> = {
        let map = PID2PCB.lock();
        map.keys().copied().filter(|pid| *pid != 0).collect()
    };
    pids.sort_unstable();
    pids
}

pub(crate) fn proc_root_entries() -> Vec<PseudoDirent> {
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

pub(crate) fn proc_dir_entries(children: &[(&str, u8)]) -> Vec<PseudoDirent> {
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

pub(crate) fn proc_sys_kernel_entries() -> Vec<PseudoDirent> {
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

pub(crate) fn proc_sys_kernel_keys_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[
        ("gc_delay", 8),
        ("maxkeys", 8),
        ("maxbytes", 8),
        ("root_maxkeys", 8),
        ("root_maxbytes", 8),
    ])
}

pub(crate) fn proc_sys_fs_entries() -> Vec<PseudoDirent> {
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

pub(crate) fn proc_sys_vm_entries() -> Vec<PseudoDirent> {
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

pub(crate) fn proc_sys_net_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("ipv4", 4)])
}

pub(crate) fn proc_sys_net_ipv4_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("conf", 4)])
}

pub(crate) fn proc_sys_net_ipv4_conf_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("lo", 4), ("default", 4)])
}

pub(crate) fn proc_sys_net_ipv4_conf_if_entries() -> Vec<PseudoDirent> {
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

pub(super) fn proc_simple_text_is_writable(path: &str) -> bool {
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

pub(crate) fn proc_simple_text_content(path: &'static str) -> String {
    ensure_proc_simple_text_entry(path);
    let bytes = PROC_SIMPLE_TEXT_FILES
        .lock()
        .get(path)
        .cloned()
        .unwrap_or_else(|| proc_simple_text_default(path));
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(super) fn write_proc_simple_text(path: &'static str, data: &[u8]) -> Result<Vec<u8>, isize> {
    if !proc_simple_text_is_writable(path) {
        return Err(err(SyscallError::EINVAL));
    }
    let normalized = if proc_simple_text_is_numeric(path) {
        let value = super::parse_proc_sys_usize(data)?;
        alloc::format!("{}\n", value).into_bytes()
    } else {
        let Ok(raw) = core::str::from_utf8(data) else {
            return Err(err(SyscallError::EINVAL));
        };
        if raw.is_empty() || raw.contains('\0') {
            return Err(err(SyscallError::EINVAL));
        }
        alloc::format!("{}\n", raw.trim_end_matches(['\n', '\r'])).into_bytes()
    };
    ensure_proc_simple_text_entry(path);
    PROC_SIMPLE_TEXT_FILES
        .lock()
        .insert(path, normalized.clone());
    Ok(normalized)
}

pub(super) fn write_pid_max_sysctl(data: &[u8]) -> Result<Vec<u8>, isize> {
    let value = super::parse_proc_sys_usize(data)?;
    let (min, max) = crate::task::pid_max_bounds();
    if !(min..=max).contains(&value) {
        return Err(err(SyscallError::EINVAL));
    }
    let applied = crate::task::set_pid_max(value);
    Ok(alloc::format!("{}\n", applied).into_bytes())
}

pub(super) fn write_vm_trigger_sysctl(path: &str, data: &[u8]) -> Result<Vec<u8>, isize> {
    let value = super::parse_proc_sys_usize(data)?;
    match path {
        "/proc/sys/vm/drop_caches" if (1..=7).contains(&value) => {}
        "/proc/sys/vm/compact_memory" if value == 1 => {}
        _ => return Err(err(SyscallError::EINVAL)),
    }
    Ok(b"0\n".to_vec())
}

pub(crate) fn managed_proc_sys_file_kind(path: &str) -> Option<ProcFileKind> {
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

pub(crate) fn proc_pid_entries(pid: u32) -> Vec<PseudoDirent> {
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

pub(crate) fn proc_pid_ns_entries(pid: u32) -> Vec<PseudoDirent> {
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
    entries.push(PseudoDirent {
        name: String::from("mnt"),
        ino: pid as u64,
        dtype: 10,
    });
    entries
}

pub(crate) fn proc_pid_fd_entries(pid: u32) -> Vec<PseudoDirent> {
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
    let files = alloc::sync::Arc::clone(&inner.files);
    let limit = inner.rlimits.rlimit_nofile_cur as usize;
    drop(inner);
    let files_guard = files.lock();
    let mut has_predicted = false;
    let predicted_fd = if pid as usize == current_process().getpid() {
        let fd = if let Some(fd) = (0..files_guard.len()).find(|fd| !files_guard.is_fd_open(*fd)) {
            (fd < limit).then_some(fd)
        } else if files_guard.len() < limit {
            Some(files_guard.len())
        } else {
            None
        };
        fd
    } else {
        None
    };

    for (fd, _file) in files_guard.iter_files_snapshot() {
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

pub(crate) fn encode_proc_linux_tid(tgid: u32, tid_index: usize) -> u32 {
    if tid_index == 0 {
        tgid
    } else {
        (((tgid as usize) << PROC_LINUX_TID_PID_SHIFT) | (tid_index & 0x7fff)) as u32
    }
}

pub(crate) fn decode_proc_linux_tid(tgid: u32, tid: u32) -> Option<usize> {
    if tid == tgid {
        return Some(0);
    }
    let pid_part = (tid as usize) >> PROC_LINUX_TID_PID_SHIFT;
    if pid_part != tgid as usize {
        return None;
    }
    Some((tid as usize) & 0x7fff)
}

pub(crate) fn proc_pid_task_entries(pid: u32) -> Vec<PseudoDirent> {
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

pub(crate) fn proc_pid_task_alive(pid: u32, tid: u32) -> bool {
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

pub(crate) fn proc_pid_task_tid_entries(pid: u32, tid: u32) -> Vec<PseudoDirent> {
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

pub(crate) fn proc_pid_exists(pid: u32) -> bool {
    pid2process(pid as usize).is_some()
}
