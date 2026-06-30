extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use crate::fs::{File, NamespaceKind, PseudoDir, PseudoDirent, PseudoFile};

use super::entries::{
    managed_proc_sys_file_kind, proc_dir_entries, proc_irq_entries, proc_irq_number_entries,
    proc_pid_entries, proc_pid_exists, proc_pid_fd_entries, proc_pid_fd_exists,
    proc_pid_fdinfo_entries, proc_pid_ns_entries, proc_pid_task_alive, proc_pid_task_entries,
    proc_pid_task_tid_entries, proc_root_entries, proc_sys_fs_entries, proc_sys_kernel_entries,
    proc_sys_kernel_keys_entries, proc_sys_net_core_entries, proc_sys_net_entries,
    proc_sys_net_ipv4_conf_entries, proc_sys_net_ipv4_conf_if_entries, proc_sys_net_ipv4_entries,
    proc_sys_net_ipv6_conf_entries, proc_sys_net_ipv6_conf_if_entries, proc_sys_net_ipv6_entries,
    proc_sys_user_entries, proc_sys_vm_entries,
};
use super::magic_link::{
    normalize_proc_magic_path, proc_pid_from_path_with_rest, proc_pid_namespace_file,
    proc_pid_task_rest,
};
use super::{ProcFileKind, ProcPseudoFile};

// gzip-compressed minimal config for LTP kconfig checks.
const PROC_CONFIG_GZ: &[u8] = &[
    31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 115, 246, 247, 115, 243, 116, 143, 119, 10, 118, 137, 15, 8,
    242, 119, 118, 13, 14, 142, 119, 116, 118, 14, 177, 173, 228, 82, 86, 112, 198, 46, 23, 31,
    102, 172, 144, 89, 172, 144, 151, 95, 162, 80, 156, 90, 194, 5, 85, 229, 231, 232, 235, 26, 28,
    224, 8, 84, 5, 212, 11, 19, 115, 13, 137, 247, 67, 226, 135, 132, 250, 33, 56, 161, 193, 174,
    65, 40, 178, 32, 59, 226, 221, 144, 4, 130, 35, 131, 157, 67, 124, 16, 252, 176, 96, 127, 103,
    111, 215, 144, 96, 76, 145, 120, 31, 127, 255, 0, 39, 71, 103, 111, 160, 20, 0, 92, 222, 90,
    238, 210, 0, 0, 0,
];

fn parse_proc_fd_component(fd_name: &str) -> Option<usize> {
    if fd_name.is_empty() || fd_name.contains('/') || !fd_name.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    fd_name.parse::<usize>().ok()
}

/// procfs 的统一入口：将绝对路径映射到对应的伪文件或伪目录对象。
///
/// 匹配顺序：
/// 1. `/proc` 根目录及 `/proc/sys/**` 静态目录树
/// 2. `/proc/sysvipc` 目录
/// 3. 固定内容的 `/proc/<name>` 文件（`meminfo`、`cpuinfo` 等）
/// 4. 由 `managed_proc_sys_file_kind` 管理的可读写 `/proc/sys/**` 文件
/// 5. `/proc/<pid>[/…]` per-process 条目，包括：
///    - `/proc/<pid>`：绑定进程身份的 `PseudoDir`，供 `pidfd_send_signal` 使用
///    - `fd`、`task`、`ns`、`task/<tid>/**`：各子目录
///    - `stat`、`status`、`maps`、`cgroup` 等文本文件
///
/// 路径经 `normalize_proc_magic_path` 规范化后再匹配，路径格式不合法或进程不存在时返回 `None`。
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
                proc_dir_entries(&[("kernel", 4), ("fs", 4), ("vm", 4), ("net", 4), ("user", 4)]),
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
        "/proc/sys/fs/fanotify" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/fs/fanotify",
                proc_dir_entries(&[("max_queued_events", 8)]),
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
        "/proc/sys/user" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/user",
                proc_sys_user_entries(),
            )));
        }
        "/proc/sys/net" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net",
                proc_sys_net_entries(),
            )));
        }
        "/proc/sys/net/core" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/core",
                proc_sys_net_core_entries(),
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
        "/proc/sys/net/ipv4/conf/all" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv4/conf/all",
                proc_sys_net_ipv4_conf_if_entries(),
            )));
        }
        "/proc/sys/net/ipv4/conf/default" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv4/conf/default",
                proc_sys_net_ipv4_conf_if_entries(),
            )));
        }
        "/proc/sys/net/ipv6" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv6",
                proc_sys_net_ipv6_entries(),
            )));
        }
        "/proc/sys/net/ipv6/conf" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv6/conf",
                proc_sys_net_ipv6_conf_entries(),
            )));
        }
        "/proc/sys/net/ipv6/conf/lo" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv6/conf/lo",
                proc_sys_net_ipv6_conf_if_entries(),
            )));
        }
        "/proc/sys/net/ipv6/conf/all" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv6/conf/all",
                proc_sys_net_ipv6_conf_if_entries(),
            )));
        }
        "/proc/sys/net/ipv6/conf/default" => {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv6/conf/default",
                proc_sys_net_ipv6_conf_if_entries(),
            )));
        }
        _ => {}
    }
    if let Some(iface) = trimmed.strip_prefix("/proc/sys/net/ipv4/conf/") {
        if !iface.is_empty()
            && !iface.contains('/')
            && crate::syscall::net::netdev::device_snapshot_by_name(iface).is_some()
        {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv4/conf",
                proc_sys_net_ipv4_conf_if_entries(),
            )));
        }
    }
    if let Some(iface) = trimmed.strip_prefix("/proc/sys/net/ipv6/conf/") {
        if !iface.is_empty()
            && !iface.contains('/')
            && crate::syscall::net::netdev::device_snapshot_by_name(iface).is_some()
        {
            return Some(Arc::new(PseudoDir::new(
                "/proc/sys/net/ipv6/conf",
                proc_sys_net_ipv6_conf_if_entries(),
            )));
        }
    }
    if trimmed == "/proc/net" {
        return Some(Arc::new(PseudoDir::new(
            "/proc/net",
            proc_dir_entries(&[
                ("arp", 8),
                ("dev", 8),
                ("dev_mcast", 8),
                ("igmp", 8),
                ("if_inet6", 8),
                ("netlink", 8),
                ("netstat", 8),
                ("raw", 8),
                ("route", 8),
                ("snmp", 8),
                ("sockstat", 8),
                ("tcp", 8),
                ("udp", 8),
                ("unix", 8),
            ]),
        )));
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
        "/proc/mountinfo" => return Some(ProcPseudoFile::new(ProcFileKind::Mountinfo)),
        "/proc/cgroups" => return Some(ProcPseudoFile::new(ProcFileKind::Cgroups)),
        "/proc/meminfo" => return Some(ProcPseudoFile::new(ProcFileKind::Meminfo)),
        "/proc/cpuinfo" => return Some(ProcPseudoFile::new(ProcFileKind::Cpuinfo)),
        "/proc/cmdline" => return Some(ProcPseudoFile::new(ProcFileKind::Cmdline)),
        "/proc/loadavg" => return Some(ProcPseudoFile::new(ProcFileKind::Loadavg)),
        "/proc/uptime" => return Some(ProcPseudoFile::new(ProcFileKind::Uptime)),
        "/proc/stat" => return Some(ProcPseudoFile::new(ProcFileKind::Stat)),
        "/proc/perf" => return Some(ProcPseudoFile::new(ProcFileKind::Perf)),
        "/proc/kallsyms" => return Some(ProcPseudoFile::new(ProcFileKind::Kallsyms)),
        "/proc/kpageflags" => return Some(ProcPseudoFile::new(ProcFileKind::Kpageflags)),
        "/proc/modules" => return Some(ProcPseudoFile::new(ProcFileKind::Modules)),
        "/proc/net/arp" => return Some(ProcPseudoFile::new(ProcFileKind::NetArp)),
        "/proc/net/dev" => return Some(ProcPseudoFile::new(ProcFileKind::NetDev)),
        "/proc/net/dev_mcast" => return Some(ProcPseudoFile::new(ProcFileKind::NetDevMcast)),
        "/proc/net/if_inet6" => return Some(ProcPseudoFile::new(ProcFileKind::NetIfInet6)),
        "/proc/net/igmp" => return Some(ProcPseudoFile::new(ProcFileKind::NetIgmp)),
        "/proc/net/netlink" => return Some(ProcPseudoFile::new(ProcFileKind::NetNetlink)),
        "/proc/net/netstat" => return Some(ProcPseudoFile::new(ProcFileKind::NetNetstat)),
        "/proc/net/raw" => return Some(ProcPseudoFile::new(ProcFileKind::NetRaw)),
        "/proc/net/route" => return Some(ProcPseudoFile::new(ProcFileKind::NetRoute)),
        "/proc/net/snmp" => return Some(ProcPseudoFile::new(ProcFileKind::NetSnmp)),
        "/proc/net/sockstat" => return Some(ProcPseudoFile::new(ProcFileKind::NetSockstat)),
        "/proc/net/tcp" => return Some(ProcPseudoFile::new(ProcFileKind::NetTcp)),
        "/proc/net/udp" => return Some(ProcPseudoFile::new(ProcFileKind::NetUdp)),
        "/proc/net/unix" => return Some(ProcPseudoFile::new(ProcFileKind::NetUnix)),
        "/proc/sysvipc/msg" => return Some(ProcPseudoFile::new(ProcFileKind::SysvipcMsg)),
        "/proc/sysvipc/sem" => return Some(ProcPseudoFile::new(ProcFileKind::SysvipcSem)),
        "/proc/sysvipc/shm" => return Some(ProcPseudoFile::new(ProcFileKind::SysvipcShm)),
        "/proc/interrupts" => return Some(ProcPseudoFile::new(ProcFileKind::Interrupts)),
        "/proc/config.gz" => return Some(Arc::new(PseudoFile::new_static_bytes(PROC_CONFIG_GZ))),
        _ => {}
    }

    if trimmed == "/proc/irq" {
        return Some(Arc::new(PseudoDir::new("/proc/irq", proc_irq_entries())));
    }
    if trimmed == "/proc/irq/default_smp_affinity" {
        let content = super::content::proc_irq_smp_affinity();
        return Some(Arc::new(PseudoFile::new_static(&content)));
    }
    if let Some(rest) = trimmed.strip_prefix("/proc/irq/") {
        if let Some((irq, file)) = rest.split_once('/') {
            if !irq.is_empty() && irq.bytes().all(|b| b.is_ascii_digit()) && file == "smp_affinity"
            {
                let content = super::content::proc_irq_smp_affinity();
                return Some(Arc::new(PseudoFile::new_static(&content)));
            }
        } else if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            return Some(Arc::new(PseudoDir::new(
                &alloc::format!("/proc/irq/{rest}"),
                proc_irq_number_entries(),
            )));
        }
    }

    if let Some(kind) = managed_proc_sys_file_kind(trimmed) {
        return Some(ProcPseudoFile::new(kind));
    }

    let (pid, rest) = proc_pid_from_path_with_rest(trimmed)?;
    let process = crate::task::manager::pid2process(pid as usize);
    if !proc_pid_exists(pid) {
        return None;
    }
    if rest.is_empty() {
        let process = process?;
        return Some(Arc::new(PseudoDir::new_proc_pid(
            &alloc::format!("/proc/{pid}"),
            proc_pid_entries(pid),
            &process,
        )));
    }
    if rest == "fd" {
        return Some(Arc::new(PseudoDir::new(
            &alloc::format!("/proc/{pid}/fd"),
            proc_pid_fd_entries(pid),
        )));
    }
    if rest == "fdinfo" {
        return Some(Arc::new(PseudoDir::new(
            &alloc::format!("/proc/{pid}/fdinfo"),
            proc_pid_fdinfo_entries(pid),
        )));
    }
    if let Some(fd_name) = rest.strip_prefix("fdinfo/") {
        let fd = parse_proc_fd_component(fd_name)?;
        if proc_pid_fd_exists(pid, fd) {
            return Some(ProcPseudoFile::new(ProcFileKind::PidFdInfo(pid, fd)));
        }
        return None;
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
            "fdinfo" => {
                return Some(Arc::new(PseudoDir::new(
                    &alloc::format!("/proc/{pid}/task/{tid}/fdinfo"),
                    proc_pid_fdinfo_entries(pid),
                )));
            }
            "ns" => {
                return Some(Arc::new(PseudoDir::new(
                    &alloc::format!("/proc/{pid}/task/{tid}/ns"),
                    proc_pid_ns_entries(pid),
                )));
            }
            "mounts" => return Some(ProcPseudoFile::new(ProcFileKind::PidMounts(pid))),
            "mountinfo" => return Some(ProcPseudoFile::new(ProcFileKind::PidMountinfo(pid))),
            "cgroup" => return Some(ProcPseudoFile::new(ProcFileKind::PidCgroup(pid))),
            _ => {}
        }
        if let Some(ns_name) = tail.strip_prefix("ns/") {
            return match ns_name {
                "ipc" => proc_pid_namespace_file(pid, NamespaceKind::Ipc),
                "mnt" => proc_pid_namespace_file(pid, NamespaceKind::Mount),
                "net" => proc_pid_namespace_file(pid, NamespaceKind::Net),
                _ => None,
            };
        }
        if let Some(fd_name) = tail.strip_prefix("fdinfo/") {
            let fd = parse_proc_fd_component(fd_name)?;
            if proc_pid_fd_exists(pid, fd) {
                return Some(ProcPseudoFile::new(ProcFileKind::PidFdInfo(pid, fd)));
            }
            return None;
        }
        return None;
    }
    if let Some(ns_name) = rest.strip_prefix("ns/") {
        return match ns_name {
            "ipc" => proc_pid_namespace_file(pid, NamespaceKind::Ipc),
            "mnt" => proc_pid_namespace_file(pid, NamespaceKind::Mount),
            "net" => proc_pid_namespace_file(pid, NamespaceKind::Net),
            _ => None,
        };
    }
    match rest {
        "stat" => Some(ProcPseudoFile::new(ProcFileKind::PidStat(pid))),
        "cmdline" => Some(ProcPseudoFile::new(ProcFileKind::PidCmdline(pid))),
        "comm" => Some(ProcPseudoFile::new(ProcFileKind::PidComm(pid))),
        "status" => Some(ProcPseudoFile::new(ProcFileKind::PidStatus(pid))),
        "uid_map" => Some(ProcPseudoFile::new(ProcFileKind::PidUidMap(pid))),
        "gid_map" => Some(ProcPseudoFile::new(ProcFileKind::PidGidMap(pid))),
        "setgroups" => Some(ProcPseudoFile::new(ProcFileKind::PidSetgroups(pid))),
        "maps" => Some(ProcPseudoFile::new(ProcFileKind::PidMaps(pid))),
        "pagemap" => Some(ProcPseudoFile::new(ProcFileKind::PidPagemap(pid))),
        "smaps" => Some(ProcPseudoFile::new(ProcFileKind::PidSmaps(pid))),
        "coredump_filter" => Some(ProcPseudoFile::new(ProcFileKind::PidCoredumpFilter)),
        "mounts" => Some(ProcPseudoFile::new(ProcFileKind::PidMounts(pid))),
        "mountinfo" => Some(ProcPseudoFile::new(ProcFileKind::PidMountinfo(pid))),
        "cgroup" => Some(ProcPseudoFile::new(ProcFileKind::PidCgroup(pid))),
        _ => None,
    }
}
