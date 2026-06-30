use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::task::process_block::ProcessControlBlock;
use lazy_static::lazy_static;
use spin::Mutex;

use super::PID2PCB;

lazy_static! {
    static ref SHARED_MM_PROCESS_OWNERS: Mutex<BTreeMap<usize, usize>> =
        Mutex::new(BTreeMap::new());
}
static SHARED_MM_PROCESS_TOKEN_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 根据 PID 从全局映射表中查询对应的进程控制块
pub fn pid2process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let map = PID2PCB.lock();
    map.get(&pid).map(Arc::clone)
}

/// 将进程插入全局 PID->PCB 映射表，当 map 大小达到 2 的幂时输出调试日志
pub fn insert_into_pid2process(pid: usize, process: Arc<ProcessControlBlock>) {
    let mut map = PID2PCB.lock();
    map.insert(pid, process);
    let len = map.len();
    if crate::debug_config::DEBUG_PID_MAP && len >= 64 && (len & (len - 1)) == 0 {
        crate::println!("[pid-debug] insert pid={} map_len={}", pid, len);
    }
}

/// 从全局 PID->PCB 映射表中移除指定 PID，找不到时输出警告
pub fn remove_from_pid2process(pid: usize) {
    let mut map = PID2PCB.lock();
    let removed = map.remove(&pid);
    let len = map.len();
    drop(map);
    let Some(process) = removed else {
        log::warn!(
            "remove_from_pid2process: pid {} not found (already reaped?)",
            pid
        );
        return;
    };
    crate::task::unregister_pid_namespace_reaper_for_process(&process);
    if crate::debug_config::DEBUG_PID_MAP && len >= 64 && (len & (len - 1)) == 0 {
        crate::println!("[pid-debug] remove pid={} map_len={}", pid, len);
    }
}

/// 返回是否仍有非 zombie 进程持有指定网络 namespace。
///
/// Zombie PCB 会留在 `PID2PCB` 中直到 wait4() 回收，但它们的 fd table 和地址空间
/// 已经释放。因此网络 namespace teardown 必须忽略 zombie，只把存活进程
/// 当作持有者。
pub fn live_process_uses_net_namespace(ns_id: usize) -> bool {
    let map = PID2PCB.lock();
    for process in map.values() {
        let Some(inner) = process.try_borrow_mut() else {
            // 正在竞争的 PCB 可能处于 clone/exit/setns 中。此时保留 namespace，
            // 不要让 teardown 与它竞态。
            return true;
        };
        if !inner.is_zombie && inner.net_ns_id == ns_id {
            return true;
        }
    }
    false
}

/// Register a newly created process-style CLONE_VM owner of `token`.
///
/// Normal fork gives the child a private mm, but vfork and clone(CLONE_VM
/// without CLONE_THREAD) create a second process owner of the same mm.  Keep a
/// process-owner count so mm teardown paths can avoid O(nr_processes) scans.
pub fn register_shared_mm_process_owner(token: usize) {
    let mut owners = SHARED_MM_PROCESS_OWNERS.lock();
    let is_new_token = !owners.contains_key(&token);
    let count = owners.entry(token).or_insert(1);
    *count = count.saturating_add(1);
    if is_new_token {
        SHARED_MM_PROCESS_TOKEN_COUNT.fetch_add(1, Ordering::Release);
    }
}

/// Drop one process owner of `token`.
///
/// Returns true when another live process still owns this mm, so VMA-close style
/// cleanup must be deferred to the eventual last owner.
pub fn release_process_mm_owner(token: usize) -> bool {
    if SHARED_MM_PROCESS_TOKEN_COUNT.load(Ordering::Acquire) == 0 {
        return false;
    }
    let mut owners = SHARED_MM_PROCESS_OWNERS.lock();
    let Some(count) = owners.get_mut(&token) else {
        return false;
    };
    match *count {
        0 | 1 => {
            owners.remove(&token);
            SHARED_MM_PROCESS_TOKEN_COUNT.fetch_sub(1, Ordering::Release);
            false
        }
        2 => {
            owners.remove(&token);
            SHARED_MM_PROCESS_TOKEN_COUNT.fetch_sub(1, Ordering::Release);
            true
        }
        _ => {
            *count -= 1;
            true
        }
    }
}
