//! cgroupfs 文件系统视图。
//!
//! cgroupfs 是 `fs::vfs` 的具体后端，因此与 VFS 核心保持同级。当前过渡实现仍
//! 同时包含路径视图和部分 cgroup 领域状态；节点化时应把进程/线程关联、资源
//! 统计与限制移入独立领域层，让本模块只保留 `VfsFileSystem`/`VfsNode` 投影。
//! 在完成迁移前不要继续增加 canonical path 翻译。支持 unified (cgroup v2)
//! 和 legacy (cgroup v1) 两种层次结构。

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::File;
use crate::mm::UserBuffer;
use crate::syscall::misc::{decode_linux_tid_strict, encode_linux_tid};
use crate::task::{
    ProcessControlBlock,
    manager::{PID2PCB, pid2process},
    manager::{refresh_process_runqueues, wakeup_task},
    process_visible_in_pid_namespace,
    processor::{block_current_and_run_next, current_process, current_task},
    resolve_process_in_pid_namespace,
    sched::{SchedClass, sched_class},
    signal::{SIGKILL_NUM, queue_process_signal},
    task_block::TaskStatus,
};

/// 权限不足的错误码
const EACCES: isize = -13;
/// 参数无效的错误码
const EINVAL: isize = -22;
/// 文件或路径不存在的错误码
const ENOENT: isize = -2;
/// 设备不存在的错误码
const ENODEV: isize = -19;
/// 设备或资源忙的错误码
const EBUSY: isize = -16;
/// 资源暂时不可用的错误码（fork 检查时用）
const EAGAIN: isize = -11;
/// 目标进程不存在的错误码
const ESRCH: isize = -3;
/// 只读文件系统的错误码
const EROFS: isize = -30;
/// 操作不支持的错误码
const EOPNOTSUPP: isize = -95;
/// PID 与 TID 互转时的位移量（高 17 位存 PID，低 15 位存线程索引）
const LINUX_TID_PID_SHIFT: usize = 15;

/// 全局单调递增的 cgroup inode 号分配器，起始值从 0x63_0000 开始
pub(crate) static NEXT_CGROUP_INO: AtomicU64 = AtomicU64::new(0x63_0000);
/// Stable superblock identity allocated once per cgroup hierarchy.
pub(crate) static NEXT_CGROUP_FS_ID: AtomicU64 = AtomicU64::new(0x63_0000_0000);

lazy_static! {
    /// 全局 cgroup 注册表，管理所有已挂载的 cgroup 层次结构
    pub(crate) static ref CGROUP_REGISTRY: Mutex<CgroupRegistry> =
        Mutex::new(CgroupRegistry::new());
}

/// pids 控制器的位掩码
const CTRL_PIDS: u32 = 1 << 0;
/// memory 控制器的位掩码
const CTRL_MEMORY: u32 = 1 << 1;
/// 根 cgroup 默认启用的控制器（pids + memory）
const ROOT_CONTROLLERS: u32 = CTRL_PIDS | CTRL_MEMORY;
/// legacy cpu 控制器默认 shares 值（1024 = 1 个 CPU 的权重）
const LEGACY_CPU_SHARES_DEFAULT: u64 = 1024;
/// legacy cpu 控制器 shares 最小值
const LEGACY_CPU_SHARES_MIN: u64 = 2;
/// legacy cpu 控制器 shares 最大值
const LEGACY_CPU_SHARES_MAX: u64 = 262_144;
/// legacy cpu 控制器默认 period（微秒）
const LEGACY_CPU_RT_PERIOD_DEFAULT_US: u64 = 1_000_000;
/// legacy cpu 控制器非根节点默认实时运行时间（0，表示不限制）
const LEGACY_CPU_RT_RUNTIME_DEFAULT_US: i64 = 0;
/// legacy cpu 控制器根节点默认实时运行时间（950ms/period）
const LEGACY_CPU_RT_RUNTIME_ROOT_DEFAULT_US: i64 = 950_000;

/// cgroup 挂载类型，标识 cgroup v1 的各个子系统或 cgroup v2 unified
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CgroupMountKind {
    /// cgroup v2 统一层次结构（cgroup2）
    Unified,
    /// debug 控制器，用于内核调试
    LegacyDebug,
    /// cpuset 控制器，绑定进程到指定 CPU 和内存节点
    LegacyCpuset,
    /// cpu 控制器，按 shares 权重分配 CPU 时间
    LegacyCpu,
    /// cpuacct 控制器，统计 CPU 使用量
    LegacyCpuAcct,
    /// memory 控制器，限制和统计内存使用
    LegacyMemory,
    /// freezer 控制器，挂起/恢复一组进程
    LegacyFreezer,
    /// devices 控制器，控制进程对设备的访问权限
    LegacyDevices,
    /// blkio 控制器，限制块设备 I/O
    LegacyBlkio,
    /// net_cls 控制器，给网络包打类别标签
    LegacyNetCls,
    /// perf_event 控制器，按 cgroup 监控性能事件
    LegacyPerfEvent,
    /// net_prio 控制器，设置网络包优先级
    LegacyNetPrio,
    /// hugetlb 控制器，限制大页内存使用
    LegacyHugetlb,
}

/// cgroup 层次结构在注册表中的查找键
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CgroupHierarchyKey {
    /// cgroup v2 统一键
    Unified,
    /// cgroup v1 通过控制器类型和源标签标识
    Legacy {
        source_label: String,
        kind: CgroupMountKind,
    },
}

mod file; // cgroup 控制文件（tasks、cgroup.procs、cpu.shares 等）的读写实现
mod helpers; // 路径解析、命名空间可见性、祖先遍历等辅助函数
mod mount_state; // 单个 cgroup 层次结构的状态管理（节点树、进程/线程关联、资源限制执行）
mod node; // CgroupNode 数据结构（控制器字段、统计计数器、限制值）
mod registry; // 全局 cgroup 注册表（管理所有已挂载层次结构、挂载/卸载生命周期）
pub(crate) mod vfs; // mountpoint-independent VFS/kernfs-style node projection

pub use file::{CgroupFile, cgroup_maybe_block_current};
pub(crate) use file::{CgroupFileKind, cgroup_file_names};
pub(crate) use helpers::*;
pub(crate) use mount_state::CgroupMountState;
pub(crate) use node::{CgroupControlNode, CgroupNode, CgroupThreadId, LegacyFreezerState};
pub(crate) use registry::CgroupRegistry;

#[derive(Clone)]
pub(crate) struct CgroupAttachTarget {
    hierarchy_key: CgroupHierarchyKey,
    rel_path: String,
}

/// 描述一次 cgroup 挂载操作的完整规格，包含类型、标签和层次结构键
#[derive(Clone)]
pub struct CgroupMountSpec {
    kind: CgroupMountKind,
    source_label: String,
    hierarchy_key: CgroupHierarchyKey,
}

impl CgroupMountSpec {
    /// 构造一个 cgroup v2 (unified) 挂载规格
    pub fn unified() -> Self {
        Self {
            kind: CgroupMountKind::Unified,
            source_label: String::from("cgroup2"),
            hierarchy_key: CgroupHierarchyKey::Unified,
        }
    }

    /// 解析 cgroup v1 的挂载选项字符串（逗号分隔），提取控制器类型和源标签
    ///
    /// 支持 "cpu", "memory", "cpuset" 等标准控制器名，以及 "name=xxx" 的自定义标签。
    pub fn parse_legacy_options(options: &str) -> Result<Self, isize> {
        let mut source_label = String::from("none");
        let mut kind = CgroupMountKind::LegacyDebug;
        let mut found_controller = false;
        // 按逗号分割，逐个解析挂载选项
        for token in options
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            let parsed = match token {
                // mount(8) commonly leaves generic VFS options in the data
                // string (for example `rw,cpu`). Linux's fs_context layer
                // consumes these before cgroup1_parse_param().
                "rw" | "ro" | "suid" | "nosuid" | "dev" | "nodev" | "exec" | "noexec" | "sync"
                | "async" | "dirsync" | "atime" | "noatime" | "diratime" | "nodiratime"
                | "relatime" | "norelatime" | "strictatime" | "lazytime" | "nolazytime" => None,
                "none" => None,
                "debug" => Some((token, CgroupMountKind::LegacyDebug)),
                "cpuset" => Some((token, CgroupMountKind::LegacyCpuset)),
                "cpu" => Some((token, CgroupMountKind::LegacyCpu)),
                "cpuacct" => Some((token, CgroupMountKind::LegacyCpuAcct)),
                "memory" => Some((token, CgroupMountKind::LegacyMemory)),
                "freezer" => Some((token, CgroupMountKind::LegacyFreezer)),
                "devices" => Some((token, CgroupMountKind::LegacyDevices)),
                "blkio" => Some((token, CgroupMountKind::LegacyBlkio)),
                "net_cls" => Some((token, CgroupMountKind::LegacyNetCls)),
                "perf_event" => Some((token, CgroupMountKind::LegacyPerfEvent)),
                "net_prio" => Some((token, CgroupMountKind::LegacyNetPrio)),
                "hugetlb" => Some((token, CgroupMountKind::LegacyHugetlb)),
                // "name=xxx" 自定义标签，不关联实际控制器
                _ if token.starts_with("name=") => {
                    source_label = String::from(token);
                    None
                }
                // 无法识别的选项返回 ENODEV
                _ => return Err(ENODEV),
            };
            if let Some((controller, mount_kind)) = parsed {
                source_label = String::from(controller);
                kind = mount_kind;
                found_controller = true;
            }
        }
        // 未指定任何控制器时，使用 "none" 作为标签
        if !found_controller && options.is_empty() {
            source_label = String::from("none");
        }
        Ok(Self {
            kind,
            hierarchy_key: CgroupHierarchyKey::Legacy {
                source_label: source_label.clone(),
                kind,
            },
            source_label,
        })
    }

    /// 返回该挂载规格对应的控制器类型
    pub(crate) fn kind(&self) -> CgroupMountKind {
        self.kind
    }

    /// 返回该挂载规格的源标签
    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    /// 返回该挂载规格的层次结构查找键
    pub(crate) fn hierarchy_key(&self) -> &CgroupHierarchyKey {
        &self.hierarchy_key
    }
}

/// 将路径中所有以 `old_prefix` 开头的部分替换为 `new_prefix`
///
/// 用于 cgroup 重命名时更新所有相关路径引用。
fn rename_subtree_path(path: &str, old_prefix: &str, new_prefix: &str) -> String {
    if path == old_prefix {
        return String::from(new_prefix);
    }
    // 剥离 old_prefix 后拼接 new_prefix
    let suffix = path.strip_prefix(old_prefix).unwrap_or("");
    alloc::format!("{new_prefix}{suffix}")
}

/// cgroup 重命名后，遍历所有进程，将各进程中匹配 `old_prefix` 的 cgroup 命名空间根路径更新为新前缀
fn rename_cgroup_namespace_roots(old_prefix: &str, new_prefix: &str) {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes {
        let current_root = process.cgroup_namespace_root();
        if CgroupMountState::is_descendant_or_self(&current_root, old_prefix) {
            process.set_cgroup_namespace_root(rename_subtree_path(
                &current_root,
                old_prefix,
                new_prefix,
            ));
        }
    }
}

/// 返回 `/proc/cgroups` 的内容，列出所有支持的 cgroup 子系统及其状态
pub fn cgroup_proc_cgroups_content() -> String {
    String::from(
        "#subsys_name\thierarchy\tnum_cgroups\tenabled\n\
debug\t0\t1\t1\n\
cpuset\t0\t1\t1\n\
cpu\t0\t1\t1\n\
cpuacct\t0\t1\t1\n\
memory\t0\t1\t1\n\
freezer\t0\t1\t1\n\
devices\t0\t1\t1\n\
blkio\t0\t1\t1\n\
net_cls\t0\t1\t1\n\
perf_event\t0\t1\t1\n\
net_prio\t0\t1\t1\n\
hugetlb\t0\t1\t1\n\
pids\t0\t1\t1\n",
    )
}

/// 返回 `/proc/<pid>/cgroup` 的内容，显示指定进程所属的 cgroup 路径
pub fn cgroup_proc_pid_content(pid: usize) -> String {
    let ns_root = pid2process(pid)
        .map(|process| process.cgroup_namespace_root())
        .unwrap_or_else(|| String::from("/"));
    let registry = CGROUP_REGISTRY.lock();
    // 优先选择 cgroup v2 层次结构（unified），若不存在则返回默认空路径
    let Some(state) = registry.preferred_proc_hierarchy() else {
        return String::from("0::/\n");
    };
    let path = namespace_visible_path(&state.path_for_pid(pid), &ns_root);
    alloc::format!("0::{path}\n")
}

/// 返回指定进程当前的 cgroup 路径（用于内核内部查询）
pub fn cgroup_current_path(pid: usize) -> String {
    let registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.preferred_proc_hierarchy() else {
        return String::from("/");
    };
    state.path_for_pid(pid)
}

pub(crate) fn cgroup_clone_into_target_from_file(
    file: &Arc<dyn File + Send + Sync>,
) -> Result<CgroupAttachTarget, isize> {
    let path = file.object_path().ok_or(EINVAL)?;
    vfs::attach_target_from_path(path)
}

pub(crate) fn cgroup_attach_process_to_target(
    pid: usize,
    target: &CgroupAttachTarget,
) -> Result<(), isize> {
    if pid2process(pid).is_none() {
        return Err(ESRCH);
    }
    let mut registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get_mut(&target.hierarchy_key) else {
        return Err(ENOENT);
    };
    if !state.is_unified() {
        return Err(EINVAL);
    }
    if !state.nodes.contains_key(&target.rel_path) {
        return Err(ENOENT);
    }
    // clone3(CLONE_INTO_CGROUP) 到这里时，子进程已先挂到父进程所在 cgroup。
    // 先保存旧路径，后面的 pids.max 只统计真正新增进入目标祖先节点的线程，
    // 避免共享祖先已计数的线程在 limit 边界被重复计算。
    let live_threads = live_thread_ids_for_process(pid)
        .into_iter()
        .map(|thread_id| {
            let old_path = state.path_for_thread(thread_id);
            (thread_id, old_path)
        })
        .collect::<Vec<_>>();
    for ancestor in CgroupMountState::ancestor_paths(&target.rel_path) {
        let Some(node) = state.nodes.get(&ancestor) else {
            continue;
        };
        if let Some(limit) = node.pids_max {
            let incoming = live_threads
                .iter()
                .filter(|(_, old_path)| {
                    !CgroupMountState::is_descendant_or_self(old_path, &ancestor)
                })
                .count();
            if state.subtree_pid_count(&ancestor).saturating_add(incoming) > limit {
                return Err(EAGAIN);
            }
        }
    }
    for (thread_id, old_path) in live_threads {
        state.flush_thread_cpu_usage(thread_id, &old_path);
    }
    state.attach_process(pid, &target.rel_path);
    Ok(())
}

/// fork 前检查父进程所在 cgroup 的 `pids.max` 限制是否允许创建新进程
///
/// 逐层向上检查所有祖先 cgroup 的 pids 限制，任一超标则返回 EAGAIN。
pub fn cgroup_fork_precheck(parent_pid: usize) -> Result<(), isize> {
    let registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values() {
        let path = state.path_for_pid(parent_pid);
        // 沿路径从下往上检查每个祖先节点的 pids_max 限制
        for ancestor in CgroupMountState::ancestor_paths(&path) {
            let Some(node) = state.nodes.get(&ancestor) else {
                continue;
            };
            let Some(limit) = node.pids_max else {
                continue;
            };
            if state.subtree_pid_count(&ancestor) >= limit {
                return Err(EAGAIN);
            }
        }
    }
    Ok(())
}

/// 将 fork 产生的子进程关联到父进程所在的所有 cgroup 层次结构中
pub fn cgroup_attach_fork_child(parent_pid: usize, child_pid: usize) {
    {
        let mut registry = CGROUP_REGISTRY.lock();
        for state in registry.hierarchies.values_mut() {
            let path = state.path_for_pid(parent_pid);
            state.attach_process(child_pid, &path);
        }
    }
    if let Some(process) = pid2process(child_pid) {
        refresh_process_legacy_cpu_fair_group_cache(&process);
    }
}

fn cgroup_thread_destination_path(
    state: &CgroupMountState,
    hierarchy_key: &CgroupHierarchyKey,
    parent_thread_id: CgroupThreadId,
    clone_into_target: Option<&CgroupAttachTarget>,
) -> Result<(String, bool), isize> {
    if let Some(target) = clone_into_target {
        if hierarchy_key == &target.hierarchy_key {
            if !state.is_unified() {
                return Err(EINVAL);
            }
            if !state.nodes.contains_key(&target.rel_path) {
                return Err(ENOENT);
            }
            return Ok((target.rel_path.clone(), true));
        }
    }
    Ok((state.path_for_thread(parent_thread_id), false))
}

/// 将新创建的线程关联到 cgroup 路径。
///
/// 普通线程继承父线程所在路径；clone3(CLONE_INTO_CGROUP) 只覆盖 fd 对应的
/// unified hierarchy，其他 hierarchy 仍继承父线程路径。
pub fn cgroup_attach_thread(
    process_pid: usize,
    parent_tid_index: usize,
    child_tid_index: usize,
    clone_into_target: Option<&CgroupAttachTarget>,
) -> Result<(), isize> {
    let mut registry = CGROUP_REGISTRY.lock();
    let parent_thread_id = CgroupThreadId::new(process_pid, parent_tid_index);
    let child_thread_id = CgroupThreadId::new(process_pid, child_tid_index);

    let mut saw_target = clone_into_target.is_none();
    for (hierarchy_key, state) in registry.hierarchies.iter() {
        let (path, used_target) = cgroup_thread_destination_path(
            state,
            hierarchy_key,
            parent_thread_id,
            clone_into_target,
        )?;
        saw_target |= used_target;
        for ancestor in CgroupMountState::ancestor_paths(&path) {
            let Some(node) = state.nodes.get(&ancestor) else {
                continue;
            };
            if let Some(limit) = node.pids_max {
                if state.subtree_pid_count(&ancestor).saturating_add(1) > limit {
                    return Err(EAGAIN);
                }
            }
        }
    }
    if !saw_target {
        return Err(ENOENT);
    }

    for (hierarchy_key, state) in registry.hierarchies.iter_mut() {
        let (path, _) = cgroup_thread_destination_path(
            state,
            hierarchy_key,
            parent_thread_id,
            clone_into_target,
        )?;
        state.attach_thread(child_thread_id, &path);
    }
    Ok(())
}

/// 线程退出时清理其 cgroup 关联，并刷新 CPU 使用统计
pub fn cgroup_exit_thread(process_pid: usize, tid_index: usize) {
    let mut registry = CGROUP_REGISTRY.lock();
    let thread_id = CgroupThreadId::new(process_pid, tid_index);
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_thread(thread_id);
        state.flush_thread_cpu_usage(thread_id, &path);
        state.remove_thread(thread_id);
    }
}

fn legacy_cpu_fair_group_from_registry(
    registry: &CgroupRegistry,
    thread_id: CgroupThreadId,
) -> (u64, u64) {
    for state in registry.hierarchies.values() {
        if state.kind != CgroupMountKind::LegacyCpu {
            continue;
        }
        let path = state.path_for_thread(thread_id);
        if let Some(node) = state.nodes.get(&path) {
            return (node.ino, node.cpu_shares);
        }
        if let Some(root) = state.nodes.get("/") {
            return (root.ino, root.cpu_shares);
        }
    }
    (0, LEGACY_CPU_SHARES_DEFAULT)
}

fn set_task_legacy_cpu_fair_group(
    task: &Arc<crate::task::task_block::TaskControlBlock>,
    group_id: u64,
    shares: u64,
) {
    let mut inner = task.borrow_mut();
    inner.fair_group_id = group_id;
    inner.fair_group_shares = shares.max(1);
}

pub fn refresh_thread_legacy_cpu_fair_group_cache(process_pid: usize, tid_index: usize) {
    let Some(process) = pid2process(process_pid) else {
        return;
    };
    let task = {
        let inner = process.borrow_mut();
        inner
            .tasks
            .get(tid_index)
            .and_then(|slot| slot.as_ref().cloned())
    };
    let Some(task) = task else {
        return;
    };
    let (group_id, shares) = legacy_cpu_fair_group(process_pid, tid_index);
    set_task_legacy_cpu_fair_group(&task, group_id, shares);
}

pub fn refresh_process_legacy_cpu_fair_group_cache(process: &Arc<ProcessControlBlock>) {
    let pid = process.getpid();
    let tasks = {
        let inner = process.borrow_mut();
        let mut tasks = Vec::new();
        for slot in inner.tasks.iter() {
            let Some(task) = slot.as_ref().cloned() else {
                continue;
            };
            let Some(tid) = task.borrow_mut().res.as_ref().map(|res| res.tid) else {
                continue;
            };
            tasks.push((task, tid));
        }
        tasks
    };
    if tasks.is_empty() {
        return;
    }
    let memberships = {
        let registry = CGROUP_REGISTRY.lock();
        tasks
            .iter()
            .map(|(_, tid)| {
                legacy_cpu_fair_group_from_registry(&registry, CgroupThreadId::new(pid, *tid))
            })
            .collect::<Vec<_>>()
    };
    for ((task, _), (group_id, shares)) in tasks.into_iter().zip(memberships.into_iter()) {
        set_task_legacy_cpu_fair_group(&task, group_id, shares);
    }
}

fn refresh_all_legacy_cpu_fair_group_caches() {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    for process in processes {
        refresh_process_legacy_cpu_fair_group_cache(&process);
        refresh_process_runqueues(&process);
    }
}

/// 获取 legacy cpu 调度中指定线程的 cgroup inode 和 shares 权重
///
/// 用于计算 CFS 的组调度权重，若节点不存在则返回根节点的值或默认值。
pub fn legacy_cpu_fair_group(tgid: usize, tid_index: usize) -> (u64, u64) {
    let thread_id = CgroupThreadId::new(tgid, tid_index);
    let registry = CGROUP_REGISTRY.lock();
    legacy_cpu_fair_group_from_registry(&registry, thread_id)
}

/// 进程退出时清理其所有 cgroup 关联、CPU 使用统计和匿名页计费
pub fn cgroup_exit_process(pid: usize) {
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        // `thread_assignments` is keyed by (tgid, tid). Use the ordered PID
        // range instead of scanning every live task on each exit; fork-heavy
        // workloads such as hackbench otherwise turn cgroup cleanup into O(N^2).
        let thread_assignments = state.process_thread_assignments(pid);
        for (thread_id, path) in thread_assignments {
            state.flush_thread_cpu_usage(thread_id, &path);
            state.remove_thread(thread_id);
        }
        state.process_assignments.remove(&pid);
        state.process_anon_bytes.remove(&pid);
    }
}

/// 对当前进程在 cgroup memory 层次结构中计费指定字节的匿名内存
///
/// 若超出限制则回滚计费并返回 false，否则返回 true 表示计费成功。
pub fn cgroup_charge_anon_current(pid: usize, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_pid(pid);
        // 读取该路径上的已有计费值，用于后续可能的回滚
        let previous = state
            .process_anon_bytes
            .get(&pid)
            .and_then(|charges| charges.get(&path).copied())
            .unwrap_or(0);
        // 先完成计费
        state
            .process_anon_bytes
            .entry(pid)
            .or_default()
            .insert(path.clone(), previous.saturating_add(bytes));
        // 若超过 memory 限制则回滚
        if !state.enforce_memory_limits(&path) {
            if let Some(charges) = state.process_anon_bytes.get_mut(&pid) {
                if previous == 0 {
                    charges.remove(&path);
                } else {
                    charges.insert(path.clone(), previous);
                }
                if charges.is_empty() {
                    state.process_anon_bytes.remove(&pid);
                }
            }
            return false;
        }
    }
    true
}

/// 对当前进程在 cgroup memory 层次结构中计费指定字节的文件写操作
pub fn cgroup_charge_file_write(pid: usize, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_pid(pid);
        if let Some(node) = state.nodes.get_mut(&path) {
            node.local_file_bytes = node.local_file_bytes.saturating_add(bytes);
            // 文件写计费后检查是否超出 memory 限制
            let _ = state.enforce_memory_limits(&path);
        }
    }
}
