use alloc::sync::Arc;

use crate::task::process_block::ProcessControlBlock;

use super::PID2PCB;

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
    if map.remove(&pid).is_none() {
        log::warn!(
            "remove_from_pid2process: pid {} not found (already reaped?)",
            pid
        );
        return;
    }
    let len = map.len();
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
