//! Cgroup 虚拟文件系统的核心模块。
//!
//! 提供 cgroupfs 的挂载、节点管理、进程/线程关联、资源统计与限制等关键功能。
//! 同时支持 unified (cgroup v2) 和 legacy (cgroup v1) 两种层次结构。

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

use crate::fs::{File, PseudoDir, PseudoDirent};
use crate::mm::UserBuffer;
use crate::syscall::misc::{decode_linux_tid_strict, encode_linux_tid};
use crate::task::{
    manager::{PID2PCB, pid2process},
    manager::{refresh_process_runqueues, wakeup_task},
    process_visible_in_pid_namespace,
    processor::{block_current_and_run_next, current_process, current_task},
    resolve_process_in_pid_namespace,
    sched::{SchedClass, sched_class},
    signal::{SIGKILL_NUM, queue_process_signal},
    task_block::TaskStatus,
};

/// 文件已存在的错误码
const EEXIST: isize = -17;
/// 权限不足的错误码
const EACCES: isize = -13;
/// 参数无效的错误码
const EINVAL: isize = -22;
/// 文件或路径不存在的错误码
const ENOENT: isize = -2;
/// 设备不存在的错误码
const ENODEV: isize = -19;
/// 目录非空的错误码
const ENOTEMPTY: isize = -39;
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

pub use file::{CgroupFile, cgroup_maybe_block_current};
pub(crate) use file::{CgroupFileKind, build_dir_entries};
pub(crate) use helpers::*;
pub(crate) use mount_state::CgroupMountState;
pub(crate) use node::{CgroupNode, CgroupThreadId, LegacyFreezerState};
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

/// 在指定挂载目标上挂载 cgroup 层次结构，委托给全局注册表处理
pub fn cgroup_mount(target: &str, spec: &CgroupMountSpec) -> isize {
    CGROUP_REGISTRY.lock().mount(target, spec)
}

/// 卸载指定挂载目标上的 cgroup 层次结构
pub fn cgroup_umount(target: &str) -> isize {
    CGROUP_REGISTRY.lock().umount(target)
}

/// 判断给定绝对路径是否位于 cgroup 伪文件系统的挂载点下
pub fn is_cgroup_pseudo_path(abs: &str) -> bool {
    split_mount_path(abs).is_some()
}

/// 通过路径在 cgroup 伪文件系统中打开一个文件或目录
///
/// 若路径匹配已有 cgroup 节点则返回伪目录，否则返回具体的 cgroup 控制文件。
pub fn open_cgroup_pseudo(path: &str) -> Option<Arc<dyn File + Send + Sync>> {
    let (_mount_target, mount_rel_path, hierarchy_key) = split_mount_path(path)?;
    let process = current_process();
    let (open_euid, open_cgroup_ns_root) = {
        let inner = process.borrow_mut();
        (inner.euid, inner.cgroup_ns_root.clone())
    };
    // 在 cgroup 命名空间内解析相对路径
    let rel_path = namespace_resolve_rel_path(&open_cgroup_ns_root, &mount_rel_path)?;
    let registry = CGROUP_REGISTRY.lock();
    let state = registry.hierarchies.get(&hierarchy_key)?;
    if state.nodes.contains_key(&rel_path) {
        // 路径对应已有 cgroup 节点，返回伪目录及其目录项
        let entries = build_dir_entries(&rel_path, &open_cgroup_ns_root, state);
        return Some(Arc::new(PseudoDir::new(path, entries)));
    }
    // 否则返回具体的 cgroup 控制文件（如 tasks, cgroup.procs 等）
    let (parent, name) = split_rel_parent(&rel_path)?;
    state.nodes.get(&parent)?;
    let kind = CgroupFileKind::from_name(&name, state.kind)?;
    Some(CgroupFile::new(
        path,
        hierarchy_key,
        &parent,
        kind,
        open_euid,
        &open_cgroup_ns_root,
    ))
}

/// 在 cgroup 层次结构中创建一个新的 cgroup 目录节点
pub fn cgroup_mkdir(abs: &str) -> isize {
    let ns_root = current_cgroup_namespace_root();
    let (.., rel_path, hierarchy_key) = match resolve_mount_path_in_namespace(&ns_root, abs) {
        Ok(resolved) => resolved,
        Err(err) => return err,
    };
    // 不允许在命名空间根节点上再创建同名节点
    if rel_path == ns_root {
        return EEXIST;
    }
    let Some((parent, _name)) = split_rel_parent(&rel_path) else {
        return EINVAL;
    };
    let mut registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get_mut(&hierarchy_key) else {
        return ENOENT;
    };
    // 父节点必须存在
    if !state.nodes.contains_key(&parent) {
        return ENOENT;
    }
    // 目标节点不能已存在
    if state.nodes.contains_key(&rel_path) {
        return EEXIST;
    }
    let mut node = CgroupNode::new();
    // 从父节点继承 clone_children 和 notify_on_release 标志
    if let Some(parent_node) = state.nodes.get(&parent) {
        node.clone_children = parent_node.clone_children;
        node.notify_on_release = parent_node.notify_on_release;
    }
    state.nodes.insert(rel_path, node);
    0
}

/// 删除 cgroup 层次结构中的一个节点（目录必须为空且无进程/线程关联）
pub fn cgroup_rmdir(abs: &str) -> isize {
    let ns_root = current_cgroup_namespace_root();
    let (.., rel_path, hierarchy_key) = match resolve_mount_path_in_namespace(&ns_root, abs) {
        Ok(resolved) => resolved,
        Err(err) => return err,
    };
    // 不允许删除命名空间根节点
    if rel_path == ns_root {
        return EBUSY;
    }
    let mut registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get_mut(&hierarchy_key) else {
        return ENOENT;
    };
    if !state.nodes.contains_key(&rel_path) {
        return ENOENT;
    }
    // 节点下还有子节点则拒绝删除
    if !state.direct_children(&rel_path).is_empty() {
        return ENOTEMPTY;
    }
    // 有进程或线程关联到此节点时拒绝删除
    if state
        .process_assignments
        .values()
        .any(|path| path == &rel_path)
        || state
            .thread_assignments
            .values()
            .any(|path| path == &rel_path)
    {
        return EBUSY;
    }
    state.nodes.remove(&rel_path);
    0
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

/// 重命名（移动）cgroup 树中的一个节点及其所有子节点
///
/// `no_replace` 参数保留目前未使用，语义上若目标已存在应当返回 EEXIST。
pub fn cgroup_rename(old_abs: &str, new_abs: &str, no_replace: bool) -> isize {
    let ns_root = current_cgroup_namespace_root();
    let (old_mount, old_rel, hierarchy_key) =
        match resolve_mount_path_in_namespace(&ns_root, old_abs) {
            Ok(resolved) => resolved,
            Err(err) => return err,
        };
    let (new_mount, new_rel, new_hierarchy_key) =
        match resolve_mount_path_in_namespace(&ns_root, new_abs) {
            Ok(resolved) => resolved,
            Err(err) => return err,
        };
    // 跨挂载点或跨层次结构的重命名不允许
    if old_mount != new_mount || hierarchy_key != new_hierarchy_key {
        return EROFS;
    }
    // 不允许重命名命名空间根节点
    if old_rel == ns_root || new_rel == ns_root {
        return EBUSY;
    }
    // 源和目标相同则直接成功
    if old_rel == new_rel {
        return 0;
    }
    let Some((old_parent, _)) = split_rel_parent(&old_rel) else {
        return EINVAL;
    };
    // 不允许将节点移动到自身的子树中（形成循环）
    if CgroupMountState::is_descendant_or_self(&new_rel, &old_rel) {
        return EINVAL;
    }
    let Some((new_parent, _)) = split_rel_parent(&new_rel) else {
        return EINVAL;
    };
    // 跨父节点的重命名（即移动）不允许，只支持同一父节点下的改名
    if old_parent != new_parent {
        return EROFS;
    }

    let mut registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get_mut(&hierarchy_key) else {
        return ENOENT;
    };
    if !state.nodes.contains_key(&old_rel) {
        return ENOENT;
    }
    if !state.nodes.contains_key(&new_parent) {
        return ENOENT;
    }
    // 目标名已存在
    if state.nodes.contains_key(&new_rel) {
        let _ = no_replace;
        return EEXIST;
    }

    // 收集所有需要重命名的子树节点（包括自身和所有子孙）
    let renamed_keys = state
        .nodes
        .keys()
        .filter(|path| CgroupMountState::is_descendant_or_self(path, &old_rel))
        .cloned()
        .collect::<Vec<_>>();
    // 先从 nodes 中移出，再以新路径重新插入
    let renamed_nodes = renamed_keys
        .iter()
        .filter_map(|path| state.nodes.remove(path).map(|node| (path.clone(), node)))
        .collect::<Vec<_>>();
    for (old_path, node) in renamed_nodes {
        let new_path = rename_subtree_path(&old_path, &old_rel, &new_rel);
        state.nodes.insert(new_path, node);
    }
    // 更新所有进程关联路径中的旧前缀
    for path in state.process_assignments.values_mut() {
        if CgroupMountState::is_descendant_or_self(path, &old_rel) {
            *path = rename_subtree_path(path, &old_rel, &new_rel);
        }
    }
    // 更新所有线程关联路径中的旧前缀
    for path in state.thread_assignments.values_mut() {
        if CgroupMountState::is_descendant_or_self(path, &old_rel) {
            *path = rename_subtree_path(path, &old_rel, &new_rel);
        }
    }
    drop(registry);
    // 更新各进程的 cgroup 命名空间根路径
    rename_cgroup_namespace_roots(&old_rel, &new_rel);
    0
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
    let Some(dir) = file.as_any().downcast_ref::<PseudoDir>() else {
        return Err(EINVAL);
    };
    let ns_root = current_cgroup_namespace_root();
    let (_, rel_path, hierarchy_key) = resolve_mount_path_in_namespace(&ns_root, dir.path())?;
    let registry = CGROUP_REGISTRY.lock();
    let Some(state) = registry.hierarchies.get(&hierarchy_key) else {
        return Err(ENOENT);
    };
    if !state.is_unified() {
        return Err(EINVAL);
    }
    if !state.nodes.contains_key(&rel_path) {
        return Err(ENOENT);
    }
    Ok(CgroupAttachTarget {
        hierarchy_key,
        rel_path,
    })
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
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_pid(parent_pid);
        state.attach_process(child_pid, &path);
    }
}

/// 将新创建的线程关联到其进程所在的 cgroup 路径
pub fn cgroup_attach_thread(process_pid: usize, parent_tid_index: usize, child_tid_index: usize) {
    let mut registry = CGROUP_REGISTRY.lock();
    let parent_thread_id = CgroupThreadId::new(process_pid, parent_tid_index);
    let child_thread_id = CgroupThreadId::new(process_pid, child_tid_index);
    for state in registry.hierarchies.values_mut() {
        let path = state.path_for_thread(parent_thread_id);
        state.attach_thread(child_thread_id, &path);
    }
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

/// 获取 legacy cpu 调度中指定线程的 cgroup inode 和 shares 权重
///
/// 用于计算 CFS 的组调度权重，若节点不存在则返回根节点的值或默认值。
pub fn legacy_cpu_fair_group(tgid: usize, tid_index: usize) -> (u64, u64) {
    let thread_id = CgroupThreadId::new(tgid, tid_index);
    let registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values() {
        if state.kind != CgroupMountKind::LegacyCpu {
            continue;
        }
        let path = state.path_for_thread(thread_id);
        if let Some(node) = state.nodes.get(&path) {
            return (node.ino, node.cpu_shares);
        }
        // 若线程没有明确的 cgroup 关联，回退到根节点的 shares
        if let Some(root) = state.nodes.get("/") {
            return (root.ino, root.cpu_shares);
        }
    }
    // 未找到任何 LegacyCpu 层次结构时返回默认值
    (0, LEGACY_CPU_SHARES_DEFAULT)
}

/// 进程退出时清理其所有 cgroup 关联、CPU 使用统计和匿名页计费
pub fn cgroup_exit_process(pid: usize) {
    let mut registry = CGROUP_REGISTRY.lock();
    for state in registry.hierarchies.values_mut() {
        // 收集该进程的所有线程 ID，避免遍历时修改 map
        let thread_ids = state
            .thread_assignments
            .keys()
            .copied()
            .filter(|thread_id| thread_id.tgid == pid)
            .collect::<Vec<_>>();
        for thread_id in thread_ids {
            let path = state.path_for_thread(thread_id);
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

/// 获取 cgroup 文件在 cgroup 层次结构中的逻辑路径（若该文件确实是 CgroupFile）
pub fn cgroup_logical_path_for_file(file: &Arc<dyn File + Send + Sync>) -> Option<String> {
    file.as_any()
        .downcast_ref::<CgroupFile>()
        .map(|file| file.path().to_string())
}
