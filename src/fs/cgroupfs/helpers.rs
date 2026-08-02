use super::*;

pub(crate) fn live_thread_ids_for_process(tgid: usize) -> Vec<CgroupThreadId> {
    let Some(process) = pid2process(tgid) else {
        return Vec::new();
    };
    let inner = process.borrow_mut();
    inner
        .tasks
        .iter()
        .enumerate()
        .filter_map(|(tid_index, task)| {
            task.as_ref().and_then(|task| {
                task.try_borrow_mut()
                    .and_then(|inner| {
                        (inner.res.is_some() && inner.exit_code.is_none()).then_some(())
                    })
                    .map(|_| CgroupThreadId::new(tgid, tid_index))
            })
        })
        .collect()
}

pub(crate) fn live_process_ids() -> Vec<usize> {
    let mut pids = PID2PCB.lock().keys().copied().collect::<Vec<_>>();
    pids.sort_unstable();
    pids
}

pub(crate) fn visible_pid_in_namespace(pid: usize, pid_ns_id: usize) -> Option<usize> {
    let process = pid2process(pid)?;
    if pid_ns_id == 0 {
        return Some(pid);
    }
    process_visible_in_pid_namespace(&process, pid_ns_id).then(|| process.visible_pid())
}

pub(crate) fn visible_tid_in_pid_namespace(
    thread_id: CgroupThreadId,
    pid_ns_id: usize,
) -> Option<usize> {
    let visible_pid = visible_pid_in_namespace(thread_id.tgid, pid_ns_id)?;
    Some(encode_linux_tid(visible_pid, thread_id.tid_index))
}

pub(crate) fn visible_tid_to_thread_id(pid_ns_id: usize, tid: usize) -> Option<CgroupThreadId> {
    if pid_ns_id == 0 {
        if pid2process(tid).is_some() {
            return Some(CgroupThreadId::new(tid, 0));
        }
        let tgid = tid >> LINUX_TID_PID_SHIFT;
        let tid_index = decode_linux_tid_strict(tgid, tid)?;
        let process = pid2process(tgid)?;
        let inner = process.borrow_mut();
        inner
            .tasks
            .get(tid_index)
            .and_then(|task| task.as_ref())
            .and_then(|task| {
                task.try_borrow_mut().and_then(|task_inner| {
                    (task_inner.res.is_some() && task_inner.exit_code.is_none()).then_some(())
                })
            })?;
        return Some(CgroupThreadId::new(tgid, tid_index));
    }

    if let Some(process) = resolve_process_in_pid_namespace(pid_ns_id, tid) {
        let tgid = process.getpid();
        let main_alive = {
            let inner = process.borrow_mut();
            inner
                .tasks
                .first()
                .and_then(|task| task.as_ref())
                .and_then(|task| {
                    task.try_borrow_mut().and_then(|task_inner| {
                        (task_inner.res.is_some() && task_inner.exit_code.is_none()).then_some(())
                    })
                })
                .is_some()
        };
        if main_alive {
            return Some(CgroupThreadId::new(tgid, 0));
        }
    }

    let visible_tgid = tid >> LINUX_TID_PID_SHIFT;
    let process = resolve_process_in_pid_namespace(pid_ns_id, visible_tgid)?;
    let tgid = process.getpid();
    let tid_index = decode_linux_tid_strict(visible_tgid, tid)?;
    let inner = process.borrow_mut();
    inner
        .tasks
        .get(tid_index)
        .and_then(|task| task.as_ref())
        .and_then(|task| {
            task.try_borrow_mut().and_then(|task_inner| {
                (task_inner.res.is_some() && task_inner.exit_code.is_none()).then_some(())
            })
        })?;
    Some(CgroupThreadId::new(tgid, tid_index))
}

pub(crate) fn current_cgroup_thread_id() -> Option<CgroupThreadId> {
    let tgid = current_process().getpid();
    let tid_index =
        current_task().and_then(|task| task.borrow_mut().res.as_ref().map(|res| res.tid))?;
    Some(CgroupThreadId::new(tgid, tid_index))
}

pub(crate) fn process_sched_class(tgid: usize) -> Option<SchedClass> {
    let process = pid2process(tgid)?;
    let policy = process.borrow_mut().scheduling.sched_policy;
    sched_class(policy)
}

pub(crate) fn descendant_processes(state: &CgroupMountState, path: &str) -> Vec<usize> {
    state
        .thread_assignments
        .iter()
        .filter_map(|(thread_id, thread_path)| {
            CgroupMountState::is_descendant_or_self(thread_path, path).then_some(thread_id.tgid)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn parse_decimal_u64_strict(text: &str) -> Result<u64, isize> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EINVAL);
    }
    text.parse::<u64>().map_err(|_| EINVAL)
}

pub(crate) fn normalize_legacy_cpu_shares(value: u64) -> u64 {
    value.clamp(LEGACY_CPU_SHARES_MIN, LEGACY_CPU_SHARES_MAX)
}

pub(crate) fn parse_legacy_cpu_shares(text: &str) -> Result<u64, isize> {
    Ok(normalize_legacy_cpu_shares(parse_decimal_u64_strict(text)?))
}

pub(crate) fn parse_legacy_cpu_rt_runtime_us(text: &str, period_us: u64) -> Result<i64, isize> {
    if text == "-1" {
        return Ok(-1);
    }
    let runtime = parse_decimal_u64_strict(text)?;
    if runtime > period_us {
        return Err(EINVAL);
    }
    i64::try_from(runtime).map_err(|_| EINVAL)
}

pub(crate) fn parse_legacy_cpu_rt_period_us(text: &str, runtime_us: i64) -> Result<u64, isize> {
    let period = parse_decimal_u64_strict(text)?;
    if period == 0 {
        return Err(EINVAL);
    }
    if runtime_us >= 0 && u64::try_from(runtime_us).map_err(|_| EINVAL)? > period {
        return Err(EINVAL);
    }
    Ok(period)
}

pub(crate) fn thread_cpu_time_ns(thread_id: CgroupThreadId) -> u64 {
    let Some(process) = pid2process(thread_id.tgid) else {
        return 0;
    };
    let Some(task) = crate::task::runtime::process_task_by_index(&process, thread_id.tid_index)
    else {
        return 0;
    };
    crate::task::runtime::task_cpu_time_ns(&task)
}

pub(crate) fn normalize_rel_path(rel: &str) -> String {
    let trimmed = rel.trim_matches('/');
    if trimmed.is_empty() {
        String::from("/")
    } else {
        let mut out = String::from("/");
        out.push_str(trimmed);
        out
    }
}

pub(crate) fn split_rel_parent(path: &str) -> Option<(String, String)> {
    if path == "/" {
        return None;
    }
    let trimmed = path.trim_end_matches('/');
    let idx = trimmed.rfind('/')?;
    let parent = if idx == 0 {
        String::from("/")
    } else {
        String::from(&trimmed[..idx])
    };
    let name = String::from(&trimmed[idx + 1..]);
    Some((parent, name))
}

pub(crate) fn namespace_visible_path(actual_path: &str, ns_root: &str) -> String {
    if ns_root == "/" {
        return String::from(actual_path);
    }
    if actual_path == ns_root {
        return String::from("/");
    }
    if let Some(suffix) = actual_path.strip_prefix(ns_root) {
        if suffix.starts_with('/') {
            return normalize_rel_path(suffix);
        }
    }
    String::from("/")
}
