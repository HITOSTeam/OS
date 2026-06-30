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
const VM_MAX_MAP_COUNT_DEFAULT: usize = 65530;

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
    entries.push(PseudoDirent {
        name: String::from("irq"),
        ino: 1,
        dtype: 4,
    });
    entries.push(PseudoDirent {
        name: String::from("net"),
        ino: 1,
        dtype: 4,
    });
    for name in [
        "mounts",
        "mountinfo",
        "cgroups",
        "meminfo",
        "cpuinfo",
        "cmdline",
        "interrupts",
        "loadavg",
        "uptime",
        "stat",
        "perf",
        "kallsyms",
        "kpageflags",
        "config.gz",
        "modules",
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

pub(crate) fn proc_irq_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("default_smp_affinity", 8), ("5", 4), ("7", 4), ("8", 4)])
}

pub(crate) fn proc_irq_number_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("smp_affinity", 8)])
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
        ("sched_rt_period_us", 8),
        ("sched_rt_runtime_us", 8),
        ("sched_rr_timeslice_ms", 8),
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
        ("fanotify", 4),
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
    proc_dir_entries(&[("core", 4), ("ipv4", 4), ("ipv6", 4)])
}

pub(crate) fn proc_sys_net_core_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[
        ("busy_poll", 8),
        ("busy_read", 8),
        ("rmem_default", 8),
        ("rmem_max", 8),
        ("wmem_default", 8),
        ("wmem_max", 8),
    ])
}

pub(crate) fn proc_sys_net_ipv4_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[
        ("conf", 4),
        ("igmp_max_memberships", 8),
        ("igmp_max_msf", 8),
        ("tcp_syn_retries", 8),
    ])
}

pub(crate) fn proc_sys_net_ipv4_conf_entries() -> Vec<PseudoDirent> {
    let mut entries = proc_dir_entries(&[("all", 4), ("default", 4)]);
    for dev in crate::syscall::net::netdev::devices_snapshot() {
        if entries.iter().any(|entry| entry.name == dev.name) {
            continue;
        }
        entries.push(PseudoDirent {
            name: dev.name,
            ino: 1,
            dtype: 4,
        });
    }
    entries
}

pub(crate) fn proc_sys_net_ipv4_conf_if_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[
        ("accept_redirects", 8),
        ("force_igmp_version", 8),
        ("secure_redirects", 8),
        ("tag", 8),
    ])
}

pub(crate) fn proc_sys_net_ipv6_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("conf", 4)])
}

pub(crate) fn proc_sys_net_ipv6_conf_entries() -> Vec<PseudoDirent> {
    let mut entries = proc_dir_entries(&[("all", 4), ("default", 4)]);
    for dev in crate::syscall::net::netdev::devices_snapshot() {
        if entries.iter().any(|entry| entry.name == dev.name) {
            continue;
        }
        entries.push(PseudoDirent {
            name: dev.name,
            ino: 1,
            dtype: 4,
        });
    }
    entries
}

pub(crate) fn proc_sys_net_ipv6_conf_if_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("accept_dad", 8), ("disable_ipv6", 8)])
}

pub(crate) fn proc_sys_user_entries() -> Vec<PseudoDirent> {
    proc_dir_entries(&[("max_user_namespaces", 8), ("max_mnt_namespaces", 8)])
}

fn proc_sys_net_ipv4_conf_simple_path(path: &str) -> Option<&'static str> {
    let rest = path.strip_prefix("/proc/sys/net/ipv4/conf/")?;
    let mut parts = rest.split('/');
    let iface = parts.next()?;
    let file = parts.next()?;
    if iface.is_empty() || parts.next().is_some() {
        return None;
    }
    match file {
        "accept_redirects" => Some("/proc/sys/net/ipv4/conf/default/accept_redirects"),
        "force_igmp_version" if iface == "all" => {
            Some("/proc/sys/net/ipv4/conf/all/force_igmp_version")
        }
        "force_igmp_version" => Some("/proc/sys/net/ipv4/conf/default/force_igmp_version"),
        "secure_redirects" => Some("/proc/sys/net/ipv4/conf/default/secure_redirects"),
        "tag" => Some("/proc/sys/net/ipv4/conf/default/tag"),
        _ => None,
    }
}

fn proc_sys_net_ipv6_conf_simple_path(path: &str) -> Option<&'static str> {
    let rest = path.strip_prefix("/proc/sys/net/ipv6/conf/")?;
    let mut parts = rest.split('/');
    let iface = parts.next()?;
    let file = parts.next()?;
    if iface.is_empty() || parts.next().is_some() || !matches!(file, "accept_dad" | "disable_ipv6")
    {
        return None;
    }
    match (iface, file) {
        ("all", "accept_dad") => Some("/proc/sys/net/ipv6/conf/all/accept_dad"),
        (_, "accept_dad") => Some("/proc/sys/net/ipv6/conf/default/accept_dad"),
        ("all", "disable_ipv6") => Some("/proc/sys/net/ipv6/conf/all/disable_ipv6"),
        (_, "disable_ipv6") => Some("/proc/sys/net/ipv6/conf/default/disable_ipv6"),
        _ => None,
    }
}

fn proc_simple_text_path(path: &str) -> Option<&'static str> {
    if let Some(path) = proc_sys_net_ipv4_conf_simple_path(path) {
        return Some(path);
    }
    if let Some(path) = proc_sys_net_ipv6_conf_simple_path(path) {
        return Some(path);
    }
    match path {
        "/proc/sys/kernel/core_pattern" => Some("/proc/sys/kernel/core_pattern"),
        "/proc/sys/kernel/threads-max" => Some("/proc/sys/kernel/threads-max"),
        "/proc/sys/kernel/tainted" => Some("/proc/sys/kernel/tainted"),
        "/proc/sys/kernel/keys/gc_delay" => Some("/proc/sys/kernel/keys/gc_delay"),
        "/proc/sys/kernel/keys/maxkeys" => Some("/proc/sys/kernel/keys/maxkeys"),
        "/proc/sys/kernel/keys/maxbytes" => Some("/proc/sys/kernel/keys/maxbytes"),
        "/proc/sys/kernel/keys/root_maxkeys" => Some("/proc/sys/kernel/keys/root_maxkeys"),
        "/proc/sys/kernel/keys/root_maxbytes" => Some("/proc/sys/kernel/keys/root_maxbytes"),
        "/proc/sys/fs/fanotify/max_queued_events" => {
            Some("/proc/sys/fs/fanotify/max_queued_events")
        }
        "/proc/sys/fs/inotify/max_queued_events" => Some("/proc/sys/fs/inotify/max_queued_events"),
        "/proc/sys/fs/inotify/max_user_instances" => {
            Some("/proc/sys/fs/inotify/max_user_instances")
        }
        "/proc/sys/fs/inotify/max_user_watches" => Some("/proc/sys/fs/inotify/max_user_watches"),
        "/proc/sys/fs/pipe-user-pages-soft" => Some("/proc/sys/fs/pipe-user-pages-soft"),
        "/proc/sys/fs/pipe-user-pages-hard" => Some("/proc/sys/fs/pipe-user-pages-hard"),
        "/proc/sys/fs/lease-break-time" => Some("/proc/sys/fs/lease-break-time"),
        "/proc/sys/user/max_user_namespaces" => Some("/proc/sys/user/max_user_namespaces"),
        "/proc/sys/user/max_mnt_namespaces" => Some("/proc/sys/user/max_mnt_namespaces"),
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
        "/proc/sys/net/ipv4/igmp_max_memberships" => {
            Some("/proc/sys/net/ipv4/igmp_max_memberships")
        }
        "/proc/sys/net/ipv4/igmp_max_msf" => Some("/proc/sys/net/ipv4/igmp_max_msf"),
        "/proc/sys/net/ipv4/tcp_syn_retries" => Some("/proc/sys/net/ipv4/tcp_syn_retries"),
        "/proc/sys/net/core/busy_poll" => Some("/proc/sys/net/core/busy_poll"),
        "/proc/sys/net/core/busy_read" => Some("/proc/sys/net/core/busy_read"),
        "/proc/sys/net/core/rmem_default" => Some("/proc/sys/net/core/rmem_default"),
        "/proc/sys/net/core/rmem_max" => Some("/proc/sys/net/core/rmem_max"),
        "/proc/sys/net/core/wmem_default" => Some("/proc/sys/net/core/wmem_default"),
        "/proc/sys/net/core/wmem_max" => Some("/proc/sys/net/core/wmem_max"),
        "/proc/sys/net/ipv4/conf/lo/accept_redirects" => {
            Some("/proc/sys/net/ipv4/conf/default/accept_redirects")
        }
        "/proc/sys/net/ipv4/conf/lo/force_igmp_version" => {
            Some("/proc/sys/net/ipv4/conf/default/force_igmp_version")
        }
        "/proc/sys/net/ipv4/conf/lo/secure_redirects" => {
            Some("/proc/sys/net/ipv4/conf/default/secure_redirects")
        }
        "/proc/sys/net/ipv4/conf/lo/tag" => Some("/proc/sys/net/ipv4/conf/lo/tag"),
        "/proc/sys/net/ipv4/conf/default/accept_redirects" => {
            Some("/proc/sys/net/ipv4/conf/default/accept_redirects")
        }
        "/proc/sys/net/ipv4/conf/default/force_igmp_version" => {
            Some("/proc/sys/net/ipv4/conf/default/force_igmp_version")
        }
        "/proc/sys/net/ipv4/conf/default/secure_redirects" => {
            Some("/proc/sys/net/ipv4/conf/default/secure_redirects")
        }
        "/proc/sys/net/ipv4/conf/default/tag" => Some("/proc/sys/net/ipv4/conf/default/tag"),
        "/proc/sys/net/ipv4/conf/all/force_igmp_version" => {
            Some("/proc/sys/net/ipv4/conf/all/force_igmp_version")
        }
        "/proc/sys/net/ipv6/conf/all/accept_dad" => Some("/proc/sys/net/ipv6/conf/all/accept_dad"),
        "/proc/sys/net/ipv6/conf/all/disable_ipv6" => {
            Some("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        }
        "/proc/sys/net/ipv6/conf/default/accept_dad" => {
            Some("/proc/sys/net/ipv6/conf/default/accept_dad")
        }
        "/proc/sys/net/ipv6/conf/default/disable_ipv6" => {
            Some("/proc/sys/net/ipv6/conf/default/disable_ipv6")
        }
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
        "/proc/sys/fs/fanotify/max_queued_events" => {
            alloc::format!("{}\n", crate::fs::fanotify_max_queued_events_for_procfs()).into_bytes()
        }
        "/proc/sys/fs/inotify/max_queued_events" => b"16384\n".to_vec(),
        "/proc/sys/fs/inotify/max_user_instances" => b"128\n".to_vec(),
        "/proc/sys/fs/inotify/max_user_watches" => b"8192\n".to_vec(),
        "/proc/sys/fs/pipe-user-pages-soft" => b"128\n".to_vec(),
        "/proc/sys/fs/pipe-user-pages-hard" => b"0\n".to_vec(),
        "/proc/sys/fs/lease-break-time" => b"45\n".to_vec(),
        "/proc/sys/user/max_user_namespaces" => b"1024\n".to_vec(),
        "/proc/sys/user/max_mnt_namespaces" => b"1024\n".to_vec(),
        "/proc/sys/vm/vfs_cache_pressure" => b"100\n".to_vec(),
        "/proc/sys/vm/nr_hugepages" => b"0\n".to_vec(),
        "/proc/sys/vm/nr_overcommit_hugepages" => b"0\n".to_vec(),
        "/proc/sys/vm/nr_hugepages_mempolicy" => b"0\n".to_vec(),
        "/proc/sys/vm/mmap_min_addr" => b"65536\n".to_vec(),
        "/proc/sys/vm/panic_on_oom" => b"0\n".to_vec(),
        "/proc/sys/vm/max_map_count" => {
            alloc::format!("{}\n", VM_MAX_MAP_COUNT_DEFAULT).into_bytes()
        }
        "/proc/sys/vm/swappiness" => b"60\n".to_vec(),
        "/proc/sys/vm/stat_refresh" => b"0\n".to_vec(),
        "/proc/sys/vm/dirty_background_ratio" => b"10\n".to_vec(),
        "/proc/sys/vm/dirty_ratio" => b"20\n".to_vec(),
        "/proc/sys/vm/dirty_expire_centisecs" => b"3000\n".to_vec(),
        "/proc/sys/vm/unprivileged_userfaultfd" => b"0\n".to_vec(),
        "/proc/sys/vm/memory_failure_early_kill" => b"0\n".to_vec(),
        "/proc/sys/net/ipv4/igmp_max_memberships" => b"20\n".to_vec(),
        "/proc/sys/net/ipv4/igmp_max_msf" => b"10\n".to_vec(),
        "/proc/sys/net/ipv4/tcp_syn_retries" => b"6\n".to_vec(),
        "/proc/sys/net/core/busy_poll" => b"0\n".to_vec(),
        "/proc/sys/net/core/busy_read" => b"0\n".to_vec(),
        "/proc/sys/net/core/rmem_default" => b"212992\n".to_vec(),
        "/proc/sys/net/core/rmem_max" => b"212992\n".to_vec(),
        "/proc/sys/net/core/wmem_default" => b"212992\n".to_vec(),
        "/proc/sys/net/core/wmem_max" => b"212992\n".to_vec(),
        "/proc/sys/net/ipv4/conf/all/force_igmp_version" => b"0\n".to_vec(),
        "/proc/sys/net/ipv4/conf/default/accept_redirects" => b"0\n".to_vec(),
        "/proc/sys/net/ipv4/conf/default/force_igmp_version" => b"0\n".to_vec(),
        "/proc/sys/net/ipv4/conf/default/secure_redirects" => b"0\n".to_vec(),
        "/proc/sys/net/ipv4/conf/lo/tag" => b"0\n".to_vec(),
        "/proc/sys/net/ipv4/conf/default/tag" => b"0\n".to_vec(),
        "/proc/sys/net/ipv6/conf/all/accept_dad" => b"1\n".to_vec(),
        "/proc/sys/net/ipv6/conf/all/disable_ipv6" => b"0\n".to_vec(),
        "/proc/sys/net/ipv6/conf/default/accept_dad" => b"1\n".to_vec(),
        "/proc/sys/net/ipv6/conf/default/disable_ipv6" => b"0\n".to_vec(),
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

pub(crate) fn vm_max_map_count() -> usize {
    let text = proc_simple_text_content("/proc/sys/vm/max_map_count");
    text.trim().parse().unwrap_or(VM_MAX_MAP_COUNT_DEFAULT)
}

pub(crate) fn net_core_busy_read_usecs() -> u32 {
    let text = proc_simple_text_content("/proc/sys/net/core/busy_read");
    text.trim().parse::<u32>().unwrap_or(0)
}

pub(crate) fn net_core_busy_poll_usecs() -> u32 {
    let text = proc_simple_text_content("/proc/sys/net/core/busy_poll");
    text.trim().parse::<u32>().unwrap_or(0)
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
        "/proc/sys/vm/min_free_kbytes" => Some(ProcFileKind::VmMinFreeKbytes),
        "/proc/sys/vm/overcommit_memory" => Some(ProcFileKind::VmOvercommitMemory),
        "/proc/sys/vm/overcommit_ratio" => Some(ProcFileKind::VmOvercommitRatio),
        "/proc/sys/fs/file-max" => Some(ProcFileKind::FsFileMax),
        "/proc/sys/fs/pipe-max-size" => Some(ProcFileKind::FsPipeMaxSize),
        "/proc/sys/fs/fanotify/max_queued_events" => Some(ProcFileKind::FsFanotifyMaxQueuedEvents),
        "/proc/sys/fs/mqueue/queues_max" => Some(ProcFileKind::FsMqueueQueuesMax),
        "/proc/sys/kernel/pid_max" => Some(ProcFileKind::KernelPidMax),
        "/proc/sys/kernel/msgmax" => Some(ProcFileKind::KernelMsgmax),
        "/proc/sys/kernel/msgmnb" => Some(ProcFileKind::KernelMsgmnb),
        "/proc/sys/kernel/msgmni" => Some(ProcFileKind::KernelMsgmni),
        "/proc/sys/kernel/sem" => Some(ProcFileKind::KernelSem),
        "/proc/sys/kernel/shmmax" => Some(ProcFileKind::KernelShmmax),
        "/proc/sys/kernel/shmmni" => Some(ProcFileKind::KernelShmmni),
        "/proc/sys/kernel/shmall" => Some(ProcFileKind::KernelShmall),
        "/proc/sys/kernel/sched_rt_period_us" => Some(ProcFileKind::KernelSchedRtPeriodUs),
        "/proc/sys/kernel/sched_rt_runtime_us" => Some(ProcFileKind::KernelSchedRtRuntimeUs),
        "/proc/sys/kernel/sched_rr_timeslice_ms" => Some(ProcFileKind::KernelSchedRrTimesliceMs),
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
        "uid_map",
        "gid_map",
        "setgroups",
        "mounts",
        "mountinfo",
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
        name: String::from("fdinfo"),
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
    entries.push(PseudoDirent {
        name: String::from("net"),
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

pub(crate) fn proc_pid_fd_exists(pid: u32, fd: usize) -> bool {
    let Some(proc) = pid2process(pid as usize) else {
        return false;
    };
    let Some(inner) = proc.try_borrow_mut() else {
        return false;
    };
    let files = alloc::sync::Arc::clone(&inner.files);
    drop(inner);
    files.lock().is_fd_open(fd)
}

pub(crate) fn proc_pid_fdinfo_entries(pid: u32) -> Vec<PseudoDirent> {
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
    drop(inner);
    let files_guard = files.lock();
    for (fd, _file) in files_guard.iter_files_snapshot() {
        entries.push(PseudoDirent {
            name: alloc::format!("{fd}"),
            ino: (fd + 1) as u64,
            dtype: 8,
        });
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
        name: String::from("fdinfo"),
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
        name: String::from("mountinfo"),
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
