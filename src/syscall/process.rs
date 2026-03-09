use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::{
    mem::size_of,
    sync::atomic::{AtomicUsize, Ordering},
};
use lazy_static::lazy_static;
use spin::{Mutex, MutexGuard};

use crate::{
    arch::{REG_A0, REG_SP, REG_TP},
    debug_config::{DEBUG_EXEC, DEBUG_FUTEX, DEBUG_PTHREAD, DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    fs::{
        cgroup_attach_thread, cgroup_current_path, cgroup_fork_precheck, ext4_lock,
        root_inode_for_path, secondary_root_inode, PidFdFile,
    },
    mm::{
        kernel_token, try_read_user_value, try_write_user_value, write_user_value, MapPermission,
        MemorySet,
    },
    println,
    syscall::{
        filesystem::{
            normalize_path, resolve_exec_inode, resolve_exec_inode_at, resolve_read_inode,
        },
        misc::encode_linux_tid,
        signal::{ERESTARTSYS, SA_RESTART},
    },
    task::{
        manager::{
            add_task, pid2process, remove_inactive_task, select_hart_for_new_task, wakeup_task,
            PID2PCB,
        },
        processor::{
            block_current_and_run_next, current_files_process, current_process, current_task,
        },
        signal::{
            pending_unmasked_bits, queue_process_signal, SignalFlags, MAX_SIG, RT_SIG_MAX,
            SIGCHLD_NUM, SIGKILL_NUM, SIGSTOP_NUM, SIG_DFL, SIG_IGN,
        },
        task_block::{TaskControlBlock, TaskStatus},
        ProcessControlBlock,
    },
    trap::{get_current_token, trap_handler},
};

lazy_static! {
    static ref EXECUTING_INODES: Mutex<BTreeMap<(usize, u32), usize>> = Mutex::new(BTreeMap::new());
}

pub(crate) type ExecutingInodesGuard = MutexGuard<'static, BTreeMap<(usize, u32), usize>>;

const EPERM: isize = -1;
const ENOENT: isize = -2;
const ESRCH: isize = -3;
const EIO: isize = -5;
const EACCES: isize = -13;
const EFAULT: isize = -14;
const EINVAL: isize = -22;
const ENAMETOOLONG: isize = -36;
const E2BIG: isize = -7;
const ETXTBSY: isize = -26;

const PTRACE_TRACEME: usize = 0;
const PTRACE_CONT: usize = 7;
const PTRACE_KILL: usize = 8;
const PTRACE_ATTACH: usize = 16;
const PTRACE_DETACH: usize = 17;
const PTRACE_SIGTRAP: i32 = 5;

static FORK_DIAG_PARENT_PID: AtomicUsize = AtomicUsize::new(usize::MAX);
static FORK_DIAG_START_MS: AtomicUsize = AtomicUsize::new(0);
static FORK_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);
static REAP_LINGER_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);
static REAP_CHILD_ARC_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);

#[allow(clippy::type_complexity)]
fn debug_task_ref_breakdown(
    task: &Arc<TaskControlBlock>,
) -> (
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) {
    let runqueue_refs = crate::task::manager::debug_count_task_refs_in_runqueues(task);
    let processor_refs = crate::task::processor::debug_count_task_refs_in_processors(task);
    let timer_refs = crate::task::block_sleep::debug_count_task_refs_in_timers(task);
    let futex_refs = crate::syscall::futex::debug_count_task_waiters(task);
    let record_lock_refs =
        crate::syscall::filesystem::debug_count_record_lock_waiters_for_task(task);

    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut task_slot_refs = 0usize;
    let mut wait_queue_refs = 0usize;
    let mut join_waiter_refs = 0usize;
    let mut sem_waiter_refs = 0usize;
    let mut condvar_waiter_refs = 0usize;
    let mut mutex_waiter_refs = 0usize;
    for process in processes {
        let inner = process.borrow_mut();
        task_slot_refs = task_slot_refs.saturating_add(
            inner
                .tasks
                .iter()
                .filter(|slot| {
                    slot.as_ref()
                        .map(|holder| Arc::ptr_eq(holder, task))
                        .unwrap_or(false)
                })
                .count(),
        );
        wait_queue_refs = wait_queue_refs.saturating_add(
            inner
                .wait_queue
                .iter()
                .filter(|holder| Arc::ptr_eq(holder, task))
                .count(),
        );
        for holder in inner.tasks.iter().filter_map(|slot| slot.as_ref()) {
            if let Some(holder_inner) = holder.try_borrow_mut() {
                join_waiter_refs = join_waiter_refs.saturating_add(
                    holder_inner
                        .join_waiters
                        .iter()
                        .filter(|w| Arc::ptr_eq(w, task))
                        .count(),
                );
            }
        }
        for sem in inner.semaphore_list.iter().filter_map(|s| s.as_ref()) {
            sem_waiter_refs = sem_waiter_refs.saturating_add(
                sem.inner
                    .lock()
                    .wait_queue
                    .iter()
                    .filter(|w| Arc::ptr_eq(w, task))
                    .count(),
            );
        }
        for condvar in inner.condvar_list.iter().filter_map(|c| c.as_ref()) {
            condvar_waiter_refs = condvar_waiter_refs.saturating_add(
                condvar
                    .inner
                    .lock()
                    .wait_queue
                    .iter()
                    .filter(|w| Arc::ptr_eq(w, task))
                    .count(),
            );
        }
        for mutex in inner.mutex_list.iter().filter_map(|m| m.as_ref()) {
            mutex_waiter_refs =
                mutex_waiter_refs.saturating_add(mutex.debug_count_waiters_for_task(task));
        }
    }
    let pipe_waiter_refs = crate::fs::debug_count_pipe_waiters_for_task(task);

    (
        runqueue_refs,
        processor_refs,
        timer_refs,
        futex_refs,
        record_lock_refs,
        task_slot_refs,
        wait_queue_refs,
        join_waiter_refs,
        sem_waiter_refs
            .saturating_add(condvar_waiter_refs)
            .saturating_add(mutex_waiter_refs),
        pipe_waiter_refs,
    )
}

fn should_report_fork_diag(count: usize) -> bool {
    count <= 16 || count % 128 == 0
}

fn record_fork_diag(parent_pid: usize, child_pid: usize, flags: usize, fork_elapsed_us: usize) {
    if !DEBUG_FUTEX {
        return;
    }
    let now_ms = crate::time::get_time_ms();
    let prev_parent = FORK_DIAG_PARENT_PID.load(Ordering::Relaxed);
    if prev_parent != parent_pid {
        FORK_DIAG_PARENT_PID.store(parent_pid, Ordering::Relaxed);
        FORK_DIAG_START_MS.store(now_ms, Ordering::Relaxed);
        FORK_DIAG_COUNT.store(0, Ordering::Relaxed);
    }
    let count = FORK_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let start_ms = FORK_DIAG_START_MS.load(Ordering::Relaxed);
    let elapsed_ms = now_ms.saturating_sub(start_ms);
    if should_report_fork_diag(count) {
        log::warn!(
            "[fork_diag] parent_pid={} child_pid={} count={} elapsed_ms={} fork_elapsed_us={} flags={:#x}",
            parent_pid,
            child_pid,
            count,
            elapsed_ms,
            fork_elapsed_us,
            flags
        );
    }
}

fn try_read_usize_user(token: usize, ptr: usize) -> Result<usize, isize> {
    try_read_user_value(token, ptr as *const usize).ok_or(EFAULT)
}

fn try_read_user_cstr(token: usize, ptr: usize) -> Result<String, isize> {
    const MAX_USER_CSTR: usize = 256 * 1024;
    let mut s = String::new();
    for i in 0..MAX_USER_CSTR {
        let ch = try_read_user_value(token, (ptr + i) as *const u8).ok_or(EFAULT)?;
        if ch == 0 {
            return Ok(s);
        }
        s.push(ch as char);
    }
    Err(ENAMETOOLONG)
}

fn read_user_str_array(token: usize, vec_ptr: usize) -> Result<Vec<String>, isize> {
    let mut out = Vec::new();
    if vec_ptr == 0 {
        return Ok(out);
    }
    for i in 0..4096usize {
        let p = try_read_usize_user(token, vec_ptr + i * size_of::<usize>())?;
        if p == 0 {
            return Ok(out);
        }
        out.push(try_read_user_cstr(token, p)?);
    }
    Err(E2BIG)
}

pub(crate) fn is_inode_currently_executed(device_id: usize, inode_num: u32) -> bool {
    if device_id == 0 && inode_num == 0 {
        return false;
    }
    let guard = lock_executing_inodes();
    is_inode_currently_executed_locked(&guard, device_id, inode_num)
}

pub(crate) fn lock_executing_inodes() -> ExecutingInodesGuard {
    EXECUTING_INODES.lock()
}

pub(crate) fn is_inode_currently_executed_locked(
    guard: &ExecutingInodesGuard,
    device_id: usize,
    inode_num: u32,
) -> bool {
    guard.get(&(device_id, inode_num)).copied().unwrap_or(0) > 0
}

pub(crate) fn register_executing_inode(dev: usize, ino: u32) {
    let mut guard = lock_executing_inodes();
    register_executing_inode_locked(&mut guard, dev, ino);
}

pub(crate) fn unregister_executing_inode(dev: usize, ino: u32) {
    let mut guard = lock_executing_inodes();
    unregister_executing_inode_locked(&mut guard, dev, ino);
}

pub(crate) fn register_executing_inode_locked(
    guard: &mut ExecutingInodesGuard,
    dev: usize,
    ino: u32,
) {
    if dev != 0 || ino != 0 {
        let count = guard.entry((dev, ino)).or_insert(0);
        *count = count.saturating_add(1);
    }
}

pub(crate) fn unregister_executing_inode_locked(
    guard: &mut ExecutingInodesGuard,
    dev: usize,
    ino: u32,
) {
    if dev != 0 || ino != 0 {
        if let Some(count) = guard.get_mut(&(dev, ino)) {
            if *count > 1 {
                *count -= 1;
            } else {
                guard.remove(&(dev, ino));
            }
        }
    }
}

fn is_inode_open_for_write(inode_num: u32) -> bool {
    let processes: Vec<_> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    for process in processes {
        let inner = process.borrow_mut();
        for file in inner.fd_table.iter() {
            let Some(file) = file else {
                continue;
            };
            if !file.writable() {
                continue;
            }
            let Some(inode_file) = file.as_any().downcast_ref::<crate::fs::OSInode>() else {
                continue;
            };
            if inode_file.ext4_inode().inode_num() == inode_num {
                return true;
            }
        }
    }
    false
}

/// This function tries to load a file from the given path.
fn load_file_from_path(path: &str) -> Result<Vec<u8>, isize> {
    match resolve_exec_inode(path) {
        Ok(inode) => {
            let _ext4_guard = ext4_lock();
            return Ok(inode.read_all());
        }
        Err(e) if e != ENOENT => return Err(e),
        Err(_) => {}
    }
    if path == "busybox" || path == "./busybox" {
        let fallbacks = [
            "/musl/busybox",
            "/glibc/busybox",
            "/bin/busybox",
            "/busybox",
        ];
        for cand in fallbacks {
            match resolve_exec_inode(cand) {
                Ok(inode) => {
                    let _ext4_guard = ext4_lock();
                    return Ok(inode.read_all());
                }
                Err(ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
    }
    if !path.ends_with(".bin") {
        let mut with_bin = String::from(path);
        with_bin.push_str(".bin");
        return match resolve_exec_inode(&with_bin) {
            Ok(inode) => {
                let _ext4_guard = ext4_lock();
                Ok(inode.read_all())
            }
            Err(e) => Err(e),
        };
    }
    Err(ENOENT)
}

fn load_file_readonly(path: &str) -> Result<Vec<u8>, isize> {
    match resolve_read_inode(path) {
        Ok(inode) => {
            let _ext4_guard = ext4_lock();
            Ok(inode.read_all())
        }
        Err(e) => Err(e),
    }
}

fn resolve_exec_inode_with_fallback(path: &str) -> Result<Arc<ext4_fs::Inode>, isize> {
    match resolve_exec_inode(path) {
        Ok(inode) => return Ok(inode),
        Err(e) if e != ENOENT => return Err(e),
        Err(_) => {}
    }
    if path == "busybox" || path == "./busybox" {
        let fallbacks = [
            "/musl/busybox",
            "/glibc/busybox",
            "/bin/busybox",
            "/busybox",
        ];
        for cand in fallbacks {
            match resolve_exec_inode(cand) {
                Ok(inode) => return Ok(inode),
                Err(ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
    }
    if !path.ends_with(".bin") {
        let mut with_bin = String::from(path);
        with_bin.push_str(".bin");
        return resolve_exec_inode(&with_bin);
    }
    Err(ENOENT)
}

fn find_shell_interpreter() -> Result<Option<(String, Vec<u8>, bool)>, isize> {
    let candidates = [
        ("./busybox", true),
        ("busybox", true),
        ("/musl/busybox", true),
        ("/glibc/busybox", true),
        ("/riscv/musl/busybox", true),
        ("/riscv/glibc/busybox", true),
        ("/bin/busybox", true),
        ("/busybox", true),
        ("/bin/sh", false),
        ("/sh", false),
    ];
    for (candidate, needs_sh_arg) in candidates {
        match load_file_from_path(candidate) {
            Ok(data) => {
                return Ok(Some((String::from(candidate), data, needs_sh_arg)));
            }
            Err(ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

fn is_system_shell_path(path: &str) -> bool {
    matches!(
        path,
        "/bin/sh" | "/bin/dash" | "/usr/bin/sh" | "/usr/bin/dash"
    )
}

fn find_busybox_shell() -> Result<Option<(String, Vec<u8>)>, isize> {
    let candidates = [
        "./busybox",
        "busybox",
        "/musl/busybox",
        "/glibc/busybox",
        "/riscv/musl/busybox",
        "/riscv/glibc/busybox",
        "/extra/riscv/musl/busybox",
        "/extra/riscv/glibc/busybox",
        "/bin/busybox",
        "/busybox",
    ];
    for cand in candidates {
        match load_file_from_path(cand) {
            Ok(data) => return Ok(Some((String::from(cand), data))),
            Err(ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

fn busybox_shell_applet(interp_name: &str, opt_arg: Option<&str>) -> &'static str {
    let shell_name = if interp_name == "env" {
        opt_arg.unwrap_or("sh")
    } else {
        interp_name
    };
    match shell_name {
        "bash" => "bash",
        "dash" | "sh" => "sh",
        "busybox" => "sh",
        _ => "sh",
    }
}

fn shebang_shell_extra_arg<'a>(interp_name: &str, opt_arg: Option<&'a str>) -> Option<&'a str> {
    if interp_name == "env" && matches!(opt_arg, Some("sh") | Some("bash")) {
        None
    } else {
        opt_arg
    }
}

fn exec_interpreter(interp_data: Vec<u8>, args: Vec<String>, envs: Vec<String>) -> isize {
    let process = current_process();
    if let Some(interp_interp) = elf_interp_path(&interp_data) {
        let interp_interp_data = match load_interp_data(&interp_interp) {
            Ok(data) => data,
            Err(e) => return e,
        };
        process.exec_dyn(&interp_data, &interp_interp_data, args, envs);
    } else {
        process.exec(&interp_data, args, envs);
    }
    maybe_stop_after_ptrace_exec();
    0
}

fn load_interp_data(interp: &str) -> Result<Vec<u8>, isize> {
    match load_file_from_path(interp) {
        Ok(data) => return Ok(data),
        Err(EACCES) => {
            if let Ok(data) = load_file_readonly(interp) {
                return Ok(data);
            }
        }
        Err(ENOENT) => {}
        Err(e) => return Err(e),
    }

    let mut candidates: Vec<&str> = Vec::new();
    if interp.starts_with("/lib/ld-musl") {
        candidates.extend([
            "/lib/libc.so",
            "/musl/lib/libc.so",
            "/riscv/musl/lib/libc.so",
        ]);
    } else if interp.starts_with("/lib/ld-linux") || interp.starts_with("/lib64/ld-linux") {
        if interp.contains("loongarch") {
            candidates.extend([
                "/glibc/lib/ld-linux-loongarch-lp64d.so.1",
                "/lib64/ld-linux-loongarch-lp64d.so.1",
                "/glibc/lib/libc.so.6",
                "/glibc/lib/libc.so",
            ]);
        } else {
            candidates.extend([
                "/glibc/lib/ld-linux-riscv64-lp64d.so.1",
                "/glibc/lib/ld-linux-riscv64-lp64.so.1",
                "/glibc/lib/libc.so.6",
                "/glibc/lib/libc.so",
            ]);
        }
    } else {
        candidates.extend([
            "/musl/lib/libc.so",
            "/glibc/lib/ld-linux-loongarch-lp64d.so.1",
            "/glibc/lib/ld-linux-riscv64-lp64d.so.1",
            "/glibc/lib/libc.so.6",
        ]);
    }

    for cand in candidates {
        match load_file_from_path(cand) {
            Ok(data) => return Ok(data),
            Err(EACCES) => {
                if let Ok(data) = load_file_readonly(cand) {
                    return Ok(data);
                }
            }
            Err(ENOENT) => {}
            Err(e) => return Err(e),
        }
    }

    Err(ENOENT)
}

fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x7f, b'E', b'L', b'F']
}

fn elf_interp_path(data: &[u8]) -> Option<String> {
    let elf = xmas_elf::ElfFile::new(data).ok()?;
    for i in 0..elf.header.pt2.ph_count() {
        let ph = elf.program_header(i).ok()?;
        if ph.get_type().ok()? == xmas_elf::program::Type::Interp {
            let off = ph.offset() as usize;
            let sz = ph.file_size() as usize;
            if off.checked_add(sz)? > elf.input.len() {
                return None;
            }
            let raw = &elf.input[off..off + sz];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            return core::str::from_utf8(&raw[..end]).ok().map(String::from);
        }
    }
    None
}

fn parse_shebang(data: &[u8]) -> Option<(String, Option<String>)> {
    if data.len() < 2 || &data[0..2] != b"#!" {
        return None;
    }
    let line_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let mut line = &data[2..line_end];
    // Trim leading spaces/tabs.
    while !line.is_empty() && (line[0] == b' ' || line[0] == b'\t') {
        line = &line[1..];
    }
    // Trim trailing CR/spaces.
    while !line.is_empty() && (line[line.len() - 1] == b'\r' || line[line.len() - 1] == b' ') {
        line = &line[..line.len() - 1];
    }
    let Ok(s) = core::str::from_utf8(line) else {
        return None;
    };
    let mut it = s.split_whitespace();
    let interp = String::from(it.next()?);
    let arg = it.next().map(String::from);
    Some((interp, arg))
}

pub fn syscall_clone(flags: usize, stack: usize, _ptid: usize, _tls: usize, _ctid: usize) -> isize {
    const CLONE_VM: usize = 0x0000_0100;
    const CLONE_FILES: usize = 0x0000_0400;
    const CLONE_VFORK: usize = 0x0000_4000;
    const CLONE_PARENT: usize = 0x0000_8000;
    const CLONE_SIGHAND: usize = 0x0000_0800;
    const CLONE_THREAD: usize = 0x0001_0000;
    const CLONE_SETTLS: usize = 0x0008_0000;
    const CLONE_PARENT_SETTID: usize = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
    const CLONE_NEWCGROUP: usize = 0x0200_0000;
    const CLONE_NEWIPC: usize = 0x0800_0000;
    const CLONE_NEWUTS: usize = 0x0400_0000;
    const CLONE_CHILD_SETTID: usize = 0x0100_0000;
    const CLONE_NEWPID: usize = 0x2000_0000;
    const CLONE_NEWNET: usize = 0x4000_0000;
    const EINVAL: isize = -22;
    const EFAULT: isize = -14;

    // LoongArch syscall ABI uses a different argument order:
    // clone(flags, stack, ptid, ctid, tls). Swap tls/ctid here.
    #[cfg(target_arch = "loongarch64")]
    let (_tls, _ctid) = (_ctid, _tls);

    // Network namespace is not implemented yet.
    if (flags & CLONE_NEWNET) != 0 {
        return EINVAL;
    }

    // Linux flag constraints:
    // - CLONE_SIGHAND requires CLONE_VM.
    // - CLONE_THREAD requires CLONE_SIGHAND (and therefore CLONE_VM).
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_VM) == 0 {
        return EINVAL;
    }
    if (flags & CLONE_THREAD) != 0 && (flags & CLONE_SIGHAND) == 0 {
        return EINVAL;
    }
    if (flags & CLONE_NEWIPC) != 0 && (flags & CLONE_THREAD) != 0 {
        return EINVAL;
    }
    if (flags & (CLONE_NEWUTS | CLONE_NEWCGROUP)) != 0 && current_process().borrow_mut().euid != 0 {
        return EPERM;
    }
    if stack == 0 {
        // Linux permits fork-like clone(SIGCHLD, NULL, ...) but rejects NULL
        // stack for plain clone(0, ...) and thread-like clone variants.
        let exit_signal = flags & 0xff;
        let requires_child_stack =
            (flags & (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_SETTLS)) != 0;
        if exit_signal == 0 || requires_child_stack {
            return EINVAL;
        }
    }

    // Thread-like clone is strictly CLONE_THREAD-based. CLONE_SIGHAND without
    // CLONE_THREAD still creates a child process that wait()/getppid() must see.
    let is_thread_like = (flags & CLONE_THREAD) != 0 && (flags & CLONE_VM) != 0;
    if is_thread_like {
        const ENOMEM: isize = -12;
        let task = current_task().unwrap();
        let parent_mask = {
            let inner = task.borrow_mut();
            inner.signal_mask
        };
        let parent_tid_index = {
            let inner = task.borrow_mut();
            inner.res.as_ref().map(|res| res.tid).unwrap_or(0)
        };
        let parent_cx = {
            let inner = task.borrow_mut();
            *inner.get_trap_cx()
        };
        let process = current_process();
        if let Err(e) = cgroup_fork_precheck(process.getpid()) {
            return e;
        }
        let Some(new_task) =
            TaskControlBlock::try_new_linux_thread(Arc::clone(&process)).map(Arc::new)
        else {
            return ENOMEM;
        };
        new_task.set_cpu_id(select_hart_for_new_task());

        let (_tid_index, linux_tid) = {
            let mut new_inner = new_task.borrow_mut();
            let res = new_inner.res.as_ref().unwrap();
            let tid_index = res.tid;
            let linux_tid = encode_linux_tid(process.getpid(), tid_index);

            // Attach to process thread table.
            {
                let mut process_inner = process.borrow_mut();
                let tasks = &mut process_inner.tasks;
                while tasks.len() < tid_index + 1 {
                    tasks.push(None);
                }
                tasks[tid_index] = Some(Arc::clone(&new_task));
            }

            new_inner.signal_mask = parent_mask;
            let trap_cx = new_inner.get_trap_cx();
            *trap_cx = parent_cx;
            trap_cx.x[REG_A0] = 0; // child returns 0 from syscall
            if stack != 0 {
                trap_cx.x[REG_SP] = stack;
            }
            if (flags & CLONE_SETTLS) != 0 {
                trap_cx.x[REG_TP] = _tls; // tp (TLS)
            }
            trap_cx.kernel_satp = kernel_token();
            trap_cx.kernel_sp = new_task.kstack_top();
            trap_cx.trap_handler = trap_handler as usize;
            if (flags & CLONE_CHILD_CLEARTID) != 0 && _ctid != 0 {
                new_inner.clear_child_tid = Some(_ctid);
            }
            cgroup_attach_thread(process.getpid(), parent_tid_index, tid_index);
            (tid_index, linux_tid)
        };

        if DEBUG_PTHREAD {
            log::debug!(
                "[clone] vm flags={:#x} stack={:#x} ptid={:#x} tls={:#x} ctid={:#x} tid={} linux_tid={}",
                flags,
                stack,
                _ptid,
                _tls,
                _ctid,
                _tid_index,
                linux_tid
            );
        }

        // Parent/child tid pointers live in the shared address space.
        let token = get_current_token();
        if (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
            if try_write_user_value(token, _ptid as *mut i32, &(linux_tid as i32)).is_err() {
                return EFAULT;
            }
        }
        if (flags & CLONE_CHILD_SETTID) != 0 && _ctid != 0 {
            if try_write_user_value(token, _ctid as *mut i32, &(linux_tid as i32)).is_err() {
                return EFAULT;
            }
        }

        add_task(new_task);
        return linux_tid as isize;
    }

    // Fork-like clone (process).
    let task = current_task().unwrap();
    let parent_cx = {
        let inner = task.borrow_mut();
        *inner.get_trap_cx()
    };
    let process = current_process();
    let share_files = (flags & CLONE_FILES) != 0;
    let share_vm = (flags & CLONE_VM) != 0;

    // For CLONE_VM + CLONE_PARENT_SETTID, ensure the parent-tid page is
    // materialized before cloning so the child shares the same backing frame.
    if share_vm && (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
        let token = get_current_token();
        let _ = try_write_user_value(token, _ptid as *mut i32, &0);
    }

    let fork_start_cycles = if DEBUG_FUTEX {
        crate::arch::read_time()
    } else {
        0
    };
    if let Err(e) = cgroup_fork_precheck(process.getpid()) {
        return e;
    }
    let Some((child, task)) = process.fork_with_task(share_files, share_vm) else {
        return -12;
    };
    if (flags & CLONE_NEWIPC) != 0 {
        let (parent_ipc_ns_id, inherited_attaches) = {
            let child_inner = child.borrow_mut();
            (child_inner.ipc_ns_id, child_inner.sysv_shm_attaches.clone())
        };
        if !inherited_attaches.is_empty() {
            crate::syscall::sysv_shm::rollback_fork_inherit(parent_ipc_ns_id, &inherited_attaches);
        }
        let mut child_inner = child.borrow_mut();
        child_inner.sysv_shm_attaches.clear();
        child_inner.ipc_ns_id = crate::task::alloc_ipc_namespace_id();
    }
    if (flags & CLONE_NEWUTS) != 0 {
        child.unshare_uts_namespace();
    }
    if (flags & CLONE_NEWCGROUP) != 0 {
        child.set_cgroup_namespace_root(cgroup_current_path(child.getpid()));
    }
    if (flags & CLONE_NEWPID) != 0 {
        let parent_ns_id = process.pid_namespace_id();
        let child_ns_id = crate::task::alloc_pid_namespace_id();
        crate::task::register_pid_namespace(parent_ns_id, child_ns_id);
        let mut child_inner = child.borrow_mut();
        child_inner.pid_ns_id = child_ns_id;
        child_inner.pid_ns_vpid = 1;
        child_inner.pid_ns_init = true;
    }
    let fork_elapsed_us = if DEBUG_FUTEX {
        let delta = crate::arch::read_time().wrapping_sub(fork_start_cycles) as u128;
        let freq = crate::config::clock_freq() as u128;
        if freq == 0 {
            0
        } else {
            (delta.saturating_mul(1_000_000) / freq) as usize
        }
    } else {
        0
    };
    let child_pid = child.getpid();

    {
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        *trap_cx = parent_cx;
        trap_cx.x[REG_A0] = 0; // child returns 0 from syscall
        if stack != 0 {
            trap_cx.x[REG_SP] = stack;
        }
        trap_cx.kernel_satp = kernel_token();
        trap_cx.kernel_sp = task.kstack_top();
        trap_cx.trap_handler = trap_handler as usize;
        if (flags & CLONE_CHILD_CLEARTID) != 0 && _ctid != 0 {
            task_inner.clear_child_tid = Some(_ctid);
        }
    }

    if (flags & CLONE_PARENT) != 0 {
        let real_parent = {
            let inner = process.borrow_mut();
            inner.parent.as_ref().and_then(|p| p.upgrade())
        };
        if let Some(real_parent) = real_parent {
            {
                let mut caller_inner = process.borrow_mut();
                caller_inner.children.retain(|c| !Arc::ptr_eq(c, &child));
            }
            {
                let mut child_inner = child.borrow_mut();
                child_inner.parent = Some(Arc::downgrade(&real_parent));
            }
            {
                let mut real_parent_inner = real_parent.borrow_mut();
                real_parent_inner.children.push(Arc::clone(&child));
            }
        }
    }

    if (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
        let token = get_current_token();
        let _ = try_write_user_value(token, _ptid as *mut i32, &(child_pid as i32));
    }

    if (flags & CLONE_CHILD_SETTID) != 0 && _ctid != 0 {
        let child_token = {
            let mut inner = child.borrow_mut();
            let _ = inner.memory_set.resolve_cow_fault(_ctid);
            let _ = inner.memory_set.resolve_lazy_fault(_ctid, MapPermission::W);
            inner.memory_set.token()
        };
        if try_write_user_value(child_token, _ctid as *mut i32, &(child_pid as i32)).is_err() {
            return EFAULT;
        }
    }
    if crate::debug_config::DEBUG_TASK_LIFECYCLE
        && (child_pid <= 16 || (child_pid & (child_pid - 1)) == 0)
    {
        crate::println!(
            "[fork-task-ref] phase=pre_add child_pid={} strong_refs={}",
            child_pid,
            Arc::strong_count(&task)
        );
    }
    add_task(task);
    record_fork_diag(process.getpid(), child_pid, flags, fork_elapsed_us);

    if (flags & CLONE_VFORK) != 0 {
        let parent_task = current_task().unwrap();
        loop {
            let done = {
                let inner = child.borrow_mut();
                inner.is_zombie || inner.did_exec
            };
            if done {
                break;
            }
            {
                let mut inner = process.borrow_mut();
                enqueue_waiter_once(&mut inner.wait_queue, &parent_task);
            }
            block_current_and_run_next();
        }
        {
            let mut inner = process.borrow_mut();
            remove_wait_queue_entry(&mut inner.wait_queue, &parent_task);
        }
    }

    crate::log_if!(
        DEBUG_SIGNAL,
        info,
        "[fork] parent_pid={} child_pid={} flags={:#x} stack={:#x}",
        process.getpid(),
        child_pid,
        flags,
        stack
    );
    child_pid as isize
}

/// Linux `vfork(2)` compatibility.
///
/// For now, treat it as a normal `fork(2)` (copy address space). This is
/// sufficient for busybox/ash and many OSComp scripts, and avoids the strict
/// parent-blocking/VM-sharing semantics of true vfork.
pub fn syscall_vfork() -> isize {
    let process = current_process();
    if let Err(e) = cgroup_fork_precheck(process.getpid()) {
        return e;
    }
    match process.fork() {
        Some(child) => {
            crate::log_if!(
                DEBUG_SIGNAL,
                info,
                "[vfork] parent_pid={} child_pid={}",
                process.getpid(),
                child.getpid()
            );
            child.getpid() as isize
        }
        None => -12,
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad0: i32,
    si_pid: i32,
    si_uid: u32,
    si_status: i32,
    _pad1: i32,
    si_utime: i64,
    si_stime: i64,
    _pad2: [u8; 80],
}

impl Default for SigInfo {
    fn default() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_pid: 0,
            si_uid: 0,
            si_status: 0,
            _pad1: 0,
            si_utime: 0,
            si_stime: 0,
            _pad2: [0u8; 80],
        }
    }
}

fn remove_wait_queue_entry(
    queue: &mut alloc::collections::VecDeque<Arc<TaskControlBlock>>,
    task: &Arc<TaskControlBlock>,
) {
    queue.retain(|t| !Arc::ptr_eq(t, task));
}

fn enqueue_waiter_once(
    queue: &mut alloc::collections::VecDeque<Arc<TaskControlBlock>>,
    task: &Arc<TaskControlBlock>,
) -> bool {
    if queue.iter().any(|t| Arc::ptr_eq(t, task)) {
        return false;
    }
    queue.push_back(task.clone());
    true
}

fn reap_zombie_child(child: &Arc<ProcessControlBlock>) -> u64 {
    // Main-thread resources are already detached in exit path; this aggressively
    // drops lingering task Arcs so kernel stacks are reclaimed on reap.
    let (tasks, cpu_ns) = {
        let mut inner = child.borrow_mut();
        let cpu_ns = inner
            .tasks
            .iter()
            .filter_map(|task| task.as_ref())
            .map(|task| task.borrow_mut().cpu_time_ns)
            .fold(0u64, |acc, v| acc.saturating_add(v));
        (core::mem::take(&mut inner.tasks), cpu_ns)
    };
    let child_pid = child.getpid();
    for task in tasks.into_iter().flatten() {
        remove_inactive_task(task.clone());
        let strong = Arc::strong_count(&task);
        if strong > 1 {
            // Retry once so duplicate stale queue entries are aggressively dropped.
            remove_inactive_task(task.clone());
            let count = REAP_LINGER_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if count <= 16 || (count & (count - 1)) == 0 {
                let tid = task
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                let (
                    runqueue_refs,
                    processor_refs,
                    timer_refs,
                    futex_refs,
                    record_lock_refs,
                    task_slot_refs,
                    wait_queue_refs,
                    join_waiter_refs,
                    sync_waiter_refs,
                    pipe_waiter_refs,
                ) = debug_task_ref_breakdown(&task);
                let known_refs = runqueue_refs
                    .saturating_add(processor_refs)
                    .saturating_add(timer_refs)
                    .saturating_add(futex_refs)
                    .saturating_add(record_lock_refs)
                    .saturating_add(task_slot_refs)
                    .saturating_add(wait_queue_refs)
                    .saturating_add(join_waiter_refs)
                    .saturating_add(sync_waiter_refs)
                    .saturating_add(pipe_waiter_refs);
                let unknown_refs = strong.saturating_sub(1 + known_refs);
                crate::println!(
                    "[reap-debug] child_pid={} tid={} lingering_refs={} seq={} rq={} proc={} timer={} futex={} rec_lock={} task_slot={} waitq={} join={} sync={} pipe={} unknown={}",
                    child_pid,
                    tid,
                    strong,
                    count,
                    runqueue_refs,
                    processor_refs,
                    timer_refs,
                    futex_refs,
                    record_lock_refs,
                    task_slot_refs,
                    wait_queue_refs,
                    join_waiter_refs,
                    sync_waiter_refs,
                    pipe_waiter_refs,
                    unknown_refs
                );
            }
        }
        drop(task);
    }
    cpu_ns
}

fn wait4_pending_action(task: &Arc<TaskControlBlock>) -> Option<isize> {
    const EINTR: isize = -4;
    let (pending, mask) = {
        let inner = task.borrow_mut();
        (inner.pending_signals, inner.signal_mask)
    };
    let mut bits = pending_unmasked_bits(pending, mask, true);
    if bits == 0 {
        return None;
    }
    let mut clear_bits = 0u64;
    let mut saw_restart = false;
    let mut saw_interrupt = false;
    let mut first_sig = None;
    let process = current_process();
    let inner = process.borrow_mut();
    while bits != 0 {
        let signum = bits.trailing_zeros() as usize + 1;
        let bit = 1u64 << (signum - 1);
        bits &= bits - 1;
        if first_sig.is_none() {
            first_sig = Some(signum);
        }
        let action = inner
            .rt_sig_handlers
            .get(signum)
            .copied()
            .unwrap_or_default();
        if action.handler == SIG_IGN {
            clear_bits |= bit;
            continue;
        }
        if action.handler == SIG_DFL {
            if signum <= MAX_SIG {
                if let Some(flag) = SignalFlags::from_bits(1u32 << signum) {
                    if flag.check_error().is_none() {
                        clear_bits |= bit;
                        continue;
                    }
                }
            }
            saw_interrupt = true;
            break;
        }
        if (action.flags & SA_RESTART) != 0 {
            saw_restart = true;
        } else {
            saw_interrupt = true;
            break;
        }
    }
    drop(inner);
    if clear_bits != 0 {
        let mut inner = task.borrow_mut();
        inner.pending_signals &= !clear_bits;
    }
    if saw_interrupt || saw_restart {
        let pid = current_process().getpid();
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        crate::log_if!(
            DEBUG_SIGNAL,
            info,
            "[wait4] pid={} tid={} pending={:#x} mask={:#x} sig={:?} action={}",
            pid,
            tid,
            pending,
            mask,
            first_sig,
            if saw_interrupt { "eintr" } else { "restart" }
        );
    }
    if saw_interrupt {
        Some(EINTR)
    } else if saw_restart {
        Some(ERESTARTSYS)
    } else {
        None
    }
}

fn path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn wake_waiters_on(process: &Arc<ProcessControlBlock>) {
    queue_process_signal(process.getpid(), SIGCHLD_NUM);
    let waiters = {
        let mut inner = process.borrow_mut();
        inner.wait_queue.drain(..).collect::<Vec<_>>()
    };
    for waiter in waiters {
        wakeup_task(waiter);
    }
}

fn wake_parent_waiters_for(process: &Arc<ProcessControlBlock>) {
    let (parent, tracer_pid) = {
        let inner = process.borrow_mut();
        (
            inner.parent.as_ref().and_then(|w| w.upgrade()),
            inner.ptrace_tracer_pid,
        )
    };

    let mut parent_pid = None;
    if let Some(parent) = parent {
        parent_pid = Some(parent.getpid());
        wake_waiters_on(&parent);
    }
    if let Some(tracer_pid) = tracer_pid {
        if parent_pid != Some(tracer_pid) {
            if let Some(tracer) = pid2process(tracer_pid) {
                wake_waiters_on(&tracer);
            }
        }
    }
}

fn enter_ptrace_stop(process: &Arc<ProcessControlBlock>, signum: i32) {
    let tasks = {
        let mut inner = process.borrow_mut();
        if inner.ptrace_tracer_pid.is_none() {
            return;
        }
        inner.stopped = true;
        inner.stop_signal = signum;
        inner.stop_pending = true;
        inner.continued = false;
        inner
            .tasks
            .iter()
            .filter_map(|t| t.as_ref().cloned())
            .collect::<Vec<_>>()
    };
    for task in tasks {
        let mut task_inner = task.borrow_mut();
        if task_inner.task_status != TaskStatus::Blocked {
            task_inner.task_status = TaskStatus::Blocked;
            task_inner.stopped_by_signal = true;
        }
    }
    wake_parent_waiters_for(process);
    block_current_and_run_next();
}

fn maybe_stop_after_ptrace_exec() {
    let process = current_process();
    enter_ptrace_stop(&process, PTRACE_SIGTRAP);
}

fn try_exec_busybox_applet(path: &str, args: &[String], envs: &[String]) -> Option<isize> {
    let applet_src = args.get(0).map(|s| s.as_str()).unwrap_or(path);
    let applet = path_basename(applet_src);
    if applet.is_empty() || applet == "busybox" {
        return None;
    }
    if applet.ends_with(".sh") {
        return None;
    }
    if !super::busybox_applet_allowed(applet) {
        return None;
    }
    let Ok(Some((bb_path, bb_data))) = find_busybox_shell() else {
        return None;
    };
    let mut new_args: Vec<String> = Vec::new();
    new_args.push(bb_path);
    new_args.push(String::from(applet));
    for a in args.iter().skip(1) {
        new_args.push(a.clone());
    }
    Some(exec_interpreter(bb_data, new_args, envs.to_vec()))
}

pub fn syscall_wait4(pid: isize, wstatus_ptr: usize, options: usize, _rusage: usize) -> isize {
    const WNOHANG: usize = 0x00000001;
    const WUNTRACED: usize = 0x00000002;
    const WCONTINUED: usize = 0x00000008;
    const ECHILD: isize = -10;
    const EINVAL: isize = -22;
    const ESRCH: isize = -3;
    let allowed = WNOHANG | WUNTRACED | WCONTINUED;
    if (options & !allowed) != 0 {
        return EINVAL;
    }
    if pid == isize::MIN || pid == (i32::MIN as isize) {
        return ESRCH;
    }
    let token = get_current_token();
    let mut temp_exit_code: i32 = 0;
    let mut temp_signal: Option<i32> = None;
    let mut temp_coredump = false;
    loop {
        let cur_process = current_process();
        let task = current_task().unwrap();
        if let Some(action) = wait4_pending_action(&task) {
            let mut process_inner = cur_process.borrow_mut();
            remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
            drop(process_inner);
            return action;
        }
        let mut process_inner = cur_process.borrow_mut();
        remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
        let parent_pgid = process_inner.pgid;
        let parent_pid = cur_process.getpid();
        let mut stop_event: Option<(Arc<ProcessControlBlock>, i32)> = None;
        let mut cont_event: Option<Arc<ProcessControlBlock>> = None;
        let (has_matching_child, zombie_child) = if process_inner.children.is_empty() {
            (false, None)
        } else {
            let mut found: Option<usize> = None;
            let mut has_match = false;
            for (index, child) in process_inner.children.iter().enumerate() {
                let child_inner = child.borrow_mut();
                let matches = match pid {
                    -1 => true, // any child
                    0 => child_inner.pgid == parent_pgid,
                    p if p > 0 => child.pid.0 == p as usize,
                    p => child_inner.pgid == (-p) as usize,
                };
                if matches {
                    has_match = true;
                }
                if matches && child_inner.is_zombie {
                    temp_exit_code = child_inner.exit_code;
                    temp_signal = if temp_exit_code < 0 {
                        Some(-temp_exit_code)
                    } else {
                        None
                    };
                    // Only report WCOREDUMP when a core file is actually emitted.
                    // Current kernel path does not materialize core files yet.
                    temp_coredump = false;
                    found = Some(index);
                    break;
                }
                let ptrace_stop_visible = child_inner.ptrace_tracer_pid == Some(parent_pid);
                if matches
                    && child_inner.stopped
                    && child_inner.stop_pending
                    && ((options & WUNTRACED) != 0 || ptrace_stop_visible)
                {
                    let sig = if child_inner.stop_signal != 0 {
                        child_inner.stop_signal
                    } else {
                        crate::task::signal::SIGSTOP_NUM as i32
                    };
                    stop_event = Some((child.clone(), sig));
                    break;
                }
                if matches && (options & WCONTINUED) != 0 && child_inner.continued {
                    cont_event = Some(child.clone());
                    break;
                }
            }
            if let Some(index) = found {
                let child = process_inner.children.remove(index);
                (true, Some(child))
            } else {
                (has_match, None)
            }
        };

        let mut has_matching_ptrace = false;
        if stop_event.is_none() && zombie_child.is_none() {
            let traced_processes = {
                let map = PID2PCB.lock();
                map.values().cloned().collect::<Vec<_>>()
            };
            for traced in traced_processes {
                if Arc::ptr_eq(&traced, &cur_process) {
                    continue;
                }
                let traced_pid = traced.getpid();
                let traced_inner = traced.borrow_mut();
                if traced_inner.ptrace_tracer_pid != Some(parent_pid) {
                    continue;
                }
                let matches = match pid {
                    -1 => true,
                    p if p > 0 => traced_pid == p as usize,
                    _ => false,
                };
                if !matches {
                    continue;
                }
                has_matching_ptrace = true;
                if traced_inner.stopped && traced_inner.stop_pending {
                    let sig = if traced_inner.stop_signal != 0 {
                        traced_inner.stop_signal
                    } else {
                        SIGSTOP_NUM as i32
                    };
                    stop_event = Some((traced.clone(), sig));
                    break;
                }
                if (options & WCONTINUED) != 0 && traced_inner.continued {
                    cont_event = Some(traced.clone());
                    break;
                }
            }
        }

        if let Some((target, sig)) = stop_event {
            let pid = target.getpid();
            let mut target_inner = target.borrow_mut();
            target_inner.stop_pending = false;
            target_inner.stop_signal = sig;
            drop(target_inner);
            drop(process_inner);
            if wstatus_ptr != 0 {
                let status = ((sig & 0xff) << 8) | 0x7f;
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }
        if let Some(target) = cont_event {
            let pid = target.getpid();
            let mut target_inner = target.borrow_mut();
            target_inner.continued = false;
            drop(target_inner);
            drop(process_inner);
            if wstatus_ptr != 0 {
                let status = 0xffff;
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }

        if let Some(child) = zombie_child {
            let pid = child.getpid();
            drop(process_inner);
            // Keep exited processes visible (e.g., for `kill $!`) until they are reaped.
            let child_cpu_ns = reap_zombie_child(&child);
            // Reaping is complete now; remove it from the global PID table.
            crate::task::manager::remove_from_pid2process(pid);
            let child_refs = Arc::strong_count(&child);
            if child_refs > 1 {
                let seq = REAP_CHILD_ARC_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if seq <= 16 || (seq & (seq - 1)) == 0 {
                    crate::println!(
                        "[reap-child-debug] child_pid={} refs_after_reap={} seq={}",
                        pid,
                        child_refs,
                        seq
                    );
                }
            }
            {
                let mut parent_inner = cur_process.borrow_mut();
                parent_inner.child_cpu_time_ns =
                    parent_inner.child_cpu_time_ns.saturating_add(child_cpu_ns);
            }
            drop(child);
            if wstatus_ptr != 0 {
                // Linux wait status encoding:
                // - normal exit: (code & 0xff) << 8
                // - signaled: signal number in low 7 bits
                let status = if let Some(sig) = temp_signal {
                    let mut status = sig & 0x7f;
                    if temp_coredump {
                        status |= 0x80;
                    }
                    status
                } else {
                    (((temp_exit_code as u32) & 0xff) << 8) as i32
                };
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }

        if !has_matching_child && !has_matching_ptrace {
            if DEBUG_PTHREAD {
                let child_pids = process_inner
                    .children
                    .iter()
                    .map(|c| c.getpid())
                    .collect::<Vec<_>>();
                let traced_pids = {
                    let map = PID2PCB.lock();
                    map.values()
                        .filter_map(|p| {
                            if Arc::ptr_eq(p, &cur_process) {
                                return None;
                            }
                            let inner = p.borrow_mut();
                            if inner.ptrace_tracer_pid == Some(parent_pid) {
                                Some(p.getpid())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                };
                log::debug!(
                    "[wait4] pid={} wait_pid={} no matching child children={:?} traced={:?}",
                    cur_process.getpid(),
                    pid,
                    child_pids,
                    traced_pids
                );
            }
            drop(process_inner);
            return ECHILD;
        }

        // Non-blocking wait: return immediately if no child has exited yet.
        if (options & WNOHANG) != 0 {
            drop(process_inner);
            return 0;
        }

        // Block until a child exits or changes state.
        let inserted = enqueue_waiter_once(&mut process_inner.wait_queue, &task);
        if inserted {
            let qlen = process_inner.wait_queue.len();
            if qlen >= 64 && (qlen & (qlen - 1)) == 0 {
                crate::println!(
                    "[wait4-debug] pid={} wait_queue_len={} children={} wait_pid={} options=0x{:x}",
                    cur_process.getpid(),
                    qlen,
                    process_inner.children.len(),
                    pid,
                    options
                );
            }
        }
        drop(process_inner);
        block_current_and_run_next();
    }
}

pub fn syscall_waitid(idtype: usize, id: usize, infop: usize, options: usize) -> isize {
    const P_ALL: usize = 0;
    const P_PID: usize = 1;
    const P_PGID: usize = 2;
    const P_PIDFD: usize = 3;
    const WNOHANG: usize = 0x00000001;
    const WSTOPPED: usize = 0x00000002;
    const WEXITED: usize = 0x00000004;
    const WCONTINUED: usize = 0x00000008;
    const WNOWAIT: usize = 0x01000000;
    const SIGCHLD: i32 = 17;
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    const CLD_STOPPED: i32 = 5;
    const CLD_CONTINUED: i32 = 6;
    const ECHILD: isize = -10;
    const EINVAL: isize = -22;
    const EFAULT: isize = -14;
    const EBADF: isize = -9;
    const EAGAIN: isize = -11;
    const O_NONBLOCK: u32 = 0x800;

    let allowed = WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT;
    if (options & !allowed) != 0 {
        return EINVAL;
    }
    if (options & (WEXITED | WSTOPPED | WCONTINUED)) == 0 {
        return EINVAL;
    }
    if infop == 0 {
        return EFAULT;
    }
    if matches!(idtype, P_PID) && id == 0 {
        return EINVAL;
    }
    let mut pidfd_target_pid = 0usize;
    let mut pidfd_nonblock = false;
    if idtype == P_PIDFD {
        let files_process = current_files_process();
        let (file, fd_flags) = {
            let files_inner = files_process.borrow_mut();
            if id >= files_inner.fd_table.len() {
                return EBADF;
            }
            let Some(file) = files_inner.fd_table[id].as_ref().cloned() else {
                return EBADF;
            };
            let fd_flags = files_inner.fd_flags.get(id).copied().unwrap_or(0);
            (file, fd_flags)
        };
        let Some(pidfd) = file.as_any().downcast_ref::<PidFdFile>() else {
            return EBADF;
        };
        pidfd_target_pid = pidfd.target_pid();
        pidfd_nonblock = (fd_flags & O_NONBLOCK) != 0;
    }

    let token = get_current_token();
    loop {
        let cur_process = current_process();
        let task = current_task().unwrap();
        if let Some(action) = wait4_pending_action(&task) {
            let mut process_inner = cur_process.borrow_mut();
            remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
            drop(process_inner);
            return action;
        }

        let mut process_inner = cur_process.borrow_mut();
        remove_wait_queue_entry(&mut process_inner.wait_queue, &task);
        let parent_pgid = process_inner.pgid;
        let mut has_match = false;
        let mut found_zombie: Option<(usize, i32, Option<i32>, bool, u32)> = None;
        let mut found_stop: Option<(usize, i32, u32)> = None;
        let mut found_cont: Option<(usize, u32)> = None;

        for (index, child) in process_inner.children.iter().enumerate() {
            let child_inner = child.borrow_mut();
            let matches = match idtype {
                P_ALL => true,
                P_PID => child.pid.0 == id,
                P_PGID => {
                    let target = if id == 0 { parent_pgid } else { id };
                    child_inner.pgid == target
                }
                P_PIDFD => child.pid.0 == pidfd_target_pid,
                _ => return EINVAL,
            };
            if !matches {
                continue;
            }
            has_match = true;
            if (options & WEXITED) != 0 && child_inner.is_zombie {
                let exit_code = child_inner.exit_code;
                let signal = if exit_code < 0 {
                    Some(-exit_code)
                } else {
                    None
                };
                // Keep waitid() consistent with wait4(): no synthetic CLD_DUMPED
                // without real core-file generation support.
                let coredump = false;
                found_zombie = Some((index, exit_code, signal, coredump, child_inner.uid));
                break;
            }
            if (options & WSTOPPED) != 0 && child_inner.stopped && child_inner.stop_pending {
                let sig = if child_inner.stop_signal != 0 {
                    child_inner.stop_signal
                } else {
                    crate::task::signal::SIGSTOP_NUM as i32
                };
                found_stop = Some((child.pid.0, sig, child_inner.uid));
                break;
            }
            if (options & WCONTINUED) != 0 && child_inner.continued {
                found_cont = Some((child.pid.0, child_inner.uid));
                break;
            }
        }

        if let Some((index, exit_code, signal, coredump, uid)) = found_zombie {
            let child_pid = process_inner.children[index].pid.0;
            let child = if (options & WNOWAIT) == 0 {
                Some(process_inner.children.remove(index))
            } else {
                None
            };
            drop(process_inner);
            if (options & WNOWAIT) == 0 {
                if let Some(child) = child.as_ref() {
                    let child_cpu_ns = reap_zombie_child(child);
                    crate::task::manager::remove_from_pid2process(child_pid);
                    let mut parent_inner = cur_process.borrow_mut();
                    parent_inner.child_cpu_time_ns =
                        parent_inner.child_cpu_time_ns.saturating_add(child_cpu_ns);
                }
            }
            let (si_status, si_code) = if let Some(sig) = signal {
                (sig, if coredump { CLD_DUMPED } else { CLD_KILLED })
            } else {
                (exit_code & 0xff, CLD_EXITED)
            };
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = si_code;
            info.si_pid = child_pid as i32;
            info.si_uid = uid;
            info.si_status = si_status;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if let Some((pid, sig, uid)) = found_stop {
            if (options & WNOWAIT) == 0 {
                if let Some(child) = process_inner.children.iter().find(|c| c.getpid() == pid) {
                    let mut child_inner = child.borrow_mut();
                    child_inner.stop_pending = false;
                }
            }
            drop(process_inner);
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = CLD_STOPPED;
            info.si_pid = pid as i32;
            info.si_uid = uid;
            info.si_status = sig;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if let Some((pid, uid)) = found_cont {
            if (options & WNOWAIT) == 0 {
                if let Some(child) = process_inner.children.iter().find(|c| c.getpid() == pid) {
                    let mut child_inner = child.borrow_mut();
                    child_inner.continued = false;
                }
            }
            drop(process_inner);
            let mut info = SigInfo::default();
            info.si_signo = SIGCHLD;
            info.si_code = CLD_CONTINUED;
            info.si_pid = pid as i32;
            info.si_uid = uid;
            info.si_status = crate::task::signal::SIGCONT_NUM as i32;
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if !has_match {
            drop(process_inner);
            return ECHILD;
        }

        if (options & WNOHANG) != 0 {
            drop(process_inner);
            let info = SigInfo::default();
            write_user_value(token, infop as *mut SigInfo, &info);
            return 0;
        }

        if idtype == P_PIDFD && pidfd_nonblock {
            drop(process_inner);
            return EAGAIN;
        }

        let inserted = enqueue_waiter_once(&mut process_inner.wait_queue, &task);
        if inserted {
            let qlen = process_inner.wait_queue.len();
            if qlen >= 64 && (qlen & (qlen - 1)) == 0 {
                crate::println!(
                    "[waitid-debug] pid={} wait_queue_len={} children={} idtype={} id={} options=0x{:x}",
                    cur_process.getpid(),
                    qlen,
                    process_inner.children.len(),
                    idtype,
                    id,
                    options
                );
            }
        }
        drop(process_inner);
        block_current_and_run_next();
    }
}

fn execve_with_inode(
    path: String,
    args_vec: Vec<String>,
    envs_vec: Vec<String>,
    inode: Arc<ext4_fs::Inode>,
) -> isize {
    const ENOEXEC: isize = -8;
    // Try lazy ELF loading to avoid reading large binaries into kernel heap.
    let interp = {
        let inode = Arc::clone(&inode);
        let mut read_at = |offset: usize, buf: &mut [u8]| {
            let _ext4_guard = ext4_lock();
            inode.read_at(offset, buf)
        };
        match crate::mm::elf_interp_path_from_reader(&mut read_at) {
            Ok(v) => Some(v),
            Err(ENOEXEC) => None,
            Err(e) => return e,
        }
    };
    let exec_inode = {
        let _ext4_guard = ext4_lock();
        (inode.device_id(), inode.inode_num())
    };
    if let Some(Some(interp)) = interp {
        let interp_data = match load_interp_data(&interp) {
            Ok(data) => data,
            Err(e) => return e,
        };
        if !is_elf(&interp_data) {
            return ENOEXEC;
        }
        let inode = Arc::clone(&inode);
        let loader = |offset: usize, buf: &mut [u8]| {
            let _ext4_guard = ext4_lock();
            inode.read_at(offset, buf)
        };
        let (memory_set, ustack_base, interp_entry, main_entry, main_aux, interp_base) =
            match MemorySet::from_elf_with_interp_reader(loader, &interp_data) {
                Ok(v) => v,
                Err(e) => return e,
            };
        let process = current_process();
        process.exec_dyn_with_memory_set(
            memory_set,
            ustack_base,
            interp_entry,
            main_entry,
            main_aux,
            interp_base,
            &interp_data,
            args_vec,
            envs_vec,
            exec_inode,
        );
        maybe_stop_after_ptrace_exec();
        return 0;
    }
    if let Some(None) = interp {
        let inode = Arc::clone(&inode);
        let loader = |offset: usize, buf: &mut [u8]| {
            let _ext4_guard = ext4_lock();
            inode.read_at(offset, buf)
        };
        let (memory_set, ustack_base, entry_point, elf_aux) =
            match MemorySet::from_elf_reader(loader) {
                Ok(v) => v,
                Err(e) => return e,
            };
        let process = current_process();
        process.exec_with_memory_set(
            memory_set,
            ustack_base,
            entry_point,
            args_vec,
            envs_vec,
            elf_aux,
            exec_inode,
        );
        maybe_stop_after_ptrace_exec();
        return 0;
    }

    // Not an ELF: check for shebang using a small prefix to avoid big allocations.
    let mut head = [0u8; 256];
    let head_len = {
        let _ext4_guard = ext4_lock();
        inode.read_at(0, &mut head)
    };
    let head = &head[..head_len];

    // Script with shebang: emulate Linux `#!` handling in-kernel so that
    // busybox/ash can run `./script.sh` directly.
    if let Some((interp, opt_arg)) = parse_shebang(head) {
        let interp_name = interp.rsplit('/').next().unwrap_or(interp.as_str());
        let env_shell =
            interp_name == "env" && matches!(opt_arg.as_deref(), Some("sh") | Some("bash"));
        let wants_shell = matches!(interp_name, "sh" | "bash" | "busybox") || env_shell;
        let opt_arg_ref = opt_arg.as_deref();
        let extra_shell_arg = shebang_shell_extra_arg(interp_name, opt_arg_ref);
        match load_file_from_path(&interp) {
            Ok(interp_data) if is_elf(&interp_data) => {
                let mut new_args: Vec<String> = Vec::new();
                new_args.push(interp.clone());
                if let Some(a) = opt_arg_ref {
                    new_args.push(String::from(a));
                }
                new_args.push(path.clone());
                for a in args_vec.iter().skip(1) {
                    new_args.push(a.clone());
                }
                return exec_interpreter(interp_data, new_args, envs_vec);
            }
            Ok(_) => {}
            Err(ENOENT) => {}
            Err(e) => return e,
        }
        if wants_shell && is_system_shell_path(&interp) {
            if let Ok(Some((bb_path, bb_data))) = find_busybox_shell() {
                let mut new_args: Vec<String> = Vec::new();
                new_args.push(bb_path);
                new_args.push(String::from(busybox_shell_applet(interp_name, opt_arg_ref)));
                if let Some(a) = extra_shell_arg {
                    new_args.push(String::from(a));
                }
                new_args.push(path.clone());
                for a in args_vec.iter().skip(1) {
                    new_args.push(a.clone());
                }
                return exec_interpreter(bb_data, new_args, envs_vec);
            }
        }
        if wants_shell {
            if let Ok(Some((interp_path, interp_data, needs_sh_arg))) = find_shell_interpreter() {
                if !is_elf(&interp_data) {
                    return ENOEXEC;
                }
                let mut new_args: Vec<String> = Vec::new();
                new_args.push(interp_path.clone());
                if needs_sh_arg {
                    new_args.push(String::from(busybox_shell_applet(interp_name, opt_arg_ref)));
                }
                if let Some(a) = extra_shell_arg {
                    new_args.push(String::from(a));
                }
                new_args.push(path.clone());
                for a in args_vec.iter().skip(1) {
                    new_args.push(a.clone());
                }
                return exec_interpreter(interp_data, new_args, envs_vec);
            }
        }
        match load_file_from_path(&interp) {
            Ok(interp_data) => {
                if is_elf(&interp_data) {
                    let mut new_args: Vec<String> = Vec::new();
                    new_args.push(interp.clone());
                    if let Some(a) = opt_arg_ref {
                        new_args.push(String::from(a));
                    }
                    // Pass script path as argv[1] (or argv[2] with opt arg), like Linux.
                    new_args.push(path.clone());
                    // Append original args after argv[0].
                    for a in args_vec.iter().skip(1) {
                        new_args.push(a.clone());
                    }
                    return exec_interpreter(interp_data, new_args, envs_vec);
                }
                if !wants_shell {
                    return ENOEXEC;
                }
            }
            Err(ENOENT) if wants_shell => {
                // handled below
            }
            Err(e) => return e,
        }
        if wants_shell {
            let fallback_opt_arg = if env_shell { None } else { opt_arg_ref };
            let interp = match find_shell_interpreter() {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Some((interp_path, interp_data, needs_sh_arg)) = interp else {
                return ENOENT;
            };
            if !is_elf(&interp_data) {
                return ENOEXEC;
            }
            let mut new_args: Vec<String> = Vec::new();
            new_args.push(interp_path.clone());
            if needs_sh_arg && fallback_opt_arg != Some("sh") {
                new_args.push(String::from("sh"));
            }
            if let Some(a) = fallback_opt_arg {
                new_args.push(String::from(a));
            }
            new_args.push(path.clone());
            for a in args_vec.iter().skip(1) {
                new_args.push(a.clone());
            }
            let process = current_process();
            if let Some(interp_interp) = elf_interp_path(&interp_data) {
                let interp_interp_data = match load_interp_data(&interp_interp) {
                    Ok(data) => data,
                    Err(e) => return e,
                };
                process.exec_dyn(&interp_data, &interp_interp_data, new_args, envs_vec);
            } else {
                process.exec(&interp_data, new_args, envs_vec);
            }
            maybe_stop_after_ptrace_exec();
            return 0;
        }
        return ENOEXEC;
    }

    // ExampleOs-style fallback for .sh files without shebangs.
    // Note: this diverges from Linux (which returns ENOEXEC) but keeps OSComp
    // scripts working when shells don't retry on ENOEXEC.
    if path.ends_with(".sh") {
        let interp = match find_shell_interpreter() {
            Ok(v) => v,
            Err(e) => return e,
        };
        let Some((interp_path, interp_data, needs_sh_arg)) = interp else {
            return ENOENT;
        };
        if !is_elf(&interp_data) {
            return ENOEXEC;
        }
        let mut new_args: Vec<String> = Vec::new();
        new_args.push(interp_path.clone());
        if needs_sh_arg {
            new_args.push(String::from("sh"));
        }
        new_args.push(path.clone());
        for a in args_vec.iter().skip(1) {
            new_args.push(a.clone());
        }
        let process = current_process();
        if let Some(interp_interp) = elf_interp_path(&interp_data) {
            let interp_interp_data = match load_interp_data(&interp_interp) {
                Ok(data) => data,
                Err(e) => return e,
            };
            process.exec_dyn(&interp_data, &interp_interp_data, new_args, envs_vec);
        } else {
            process.exec(&interp_data, new_args, envs_vec);
        }
        maybe_stop_after_ptrace_exec();
        return 0;
    }

    // Non-ELF without shebang: let shells interpret it.
    ENOEXEC
}

pub fn syscall_execve(path_ptr: usize, argv_ptr: usize, envp_ptr: usize) -> isize {
    let token = get_current_token();
    if path_ptr == 0 {
        return EFAULT;
    }
    let path = match try_read_user_cstr(token, path_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };

    let mut args_vec: Vec<String> = Vec::new();
    if argv_ptr != 0 {
        let mut i = 0usize;
        loop {
            if i >= 4096 {
                return E2BIG;
            }
            let arg_ptr = match try_read_usize_user(token, argv_ptr + i * size_of::<usize>()) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if arg_ptr == 0 {
                break;
            }
            match try_read_user_cstr(token, arg_ptr) {
                Ok(s) => args_vec.push(s),
                Err(e) => return e,
            }
            i += 1;
        }
    }
    if args_vec.is_empty() {
        args_vec.push(path.clone());
    }
    crate::log_if!(
        DEBUG_SIGNAL,
        info,
        "[execve] pid={} path='{}' argv0='{}' argv1='{}'",
        current_process().getpid(),
        path,
        args_vec.get(0).map(|s| s.as_str()).unwrap_or(""),
        args_vec.get(1).map(|s| s.as_str()).unwrap_or("")
    );

    let mut envs_vec: Vec<String> = Vec::new();
    if envp_ptr != 0 {
        let mut i = 0usize;
        loop {
            if i >= 4096 {
                return E2BIG;
            }
            let env_ptr = match try_read_usize_user(token, envp_ptr + i * size_of::<usize>()) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if env_ptr == 0 {
                break;
            }
            match try_read_user_cstr(token, env_ptr) {
                Ok(s) => envs_vec.push(s),
                Err(e) => return e,
            }
            i += 1;
        }
    }
    if is_system_shell_path(&path) {
        if let Ok(Some((bb_path, bb_data))) = find_busybox_shell() {
            let mut new_args: Vec<String> = Vec::new();
            new_args.push(bb_path);
            new_args.push(String::from("sh"));
            for a in args_vec.iter().skip(1) {
                new_args.push(a.clone());
            }
            return exec_interpreter(bb_data, new_args, envs_vec);
        }
    }

    let inode = match resolve_exec_inode_with_fallback(&path) {
        Ok(inode) => inode,
        Err(e) => {
            if e == ENOENT {
                if let Some(ret) = try_exec_busybox_applet(&path, &args_vec, &envs_vec) {
                    return ret;
                }
            }
            if DEBUG_EXEC {
                let cwd = { current_process().borrow_mut().cwd.clone() };
                let abs = if path.starts_with('/') {
                    normalize_path("/", &path)
                } else {
                    normalize_path(&cwd, &path)
                };
                let (primary_hit, secondary_hit) = {
                    let _ext4_guard = ext4_lock();
                    let primary_hit = root_inode_for_path(&abs).find_path(&abs).is_some();
                    let secondary_hit = secondary_root_inode()
                        .and_then(|root| root.find_path(&abs))
                        .is_some();
                    (primary_hit, secondary_hit)
                };
                println!(
                    "[exec] path='{}' abs='{}' cwd='{}' err={} primary_hit={} secondary_hit={}",
                    path, abs, cwd, e, primary_hit, secondary_hit
                );
            }
            return e;
        }
    };
    if is_inode_open_for_write(inode.inode_num()) {
        return ETXTBSY;
    }

    execve_with_inode(path, args_vec, envs_vec, inode)
}

pub fn syscall_execveat(
    dirfd: isize,
    path_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
    flags: usize,
) -> isize {
    let token = get_current_token();
    if path_ptr == 0 {
        return EFAULT;
    }
    let path = match try_read_user_cstr(token, path_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut args_vec = match read_user_str_array(token, argv_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if args_vec.is_empty() {
        args_vec.push(path.clone());
    }
    let envs_vec = match read_user_str_array(token, envp_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let inode = match resolve_exec_inode_at(dirfd, &path, flags) {
        Ok(inode) => inode,
        Err(e) => return e,
    };
    if is_inode_open_for_write(inode.inode_num()) {
        return ETXTBSY;
    }
    execve_with_inode(path, args_vec, envs_vec, inode)
}

pub fn syscall_getpid() -> isize {
    current_task()
        .unwrap()
        .process
        .upgrade()
        .unwrap()
        .visible_pid() as isize
}

fn ptrace_target_for_current(pid: usize) -> Result<Arc<ProcessControlBlock>, isize> {
    if pid == 0 {
        return Err(ESRCH);
    }
    let Some(target) = pid2process(pid) else {
        return Err(ESRCH);
    };
    let tracer_pid = current_process().getpid();
    let traced_by_current = {
        let inner = target.borrow_mut();
        if inner.is_zombie {
            return Err(ESRCH);
        }
        inner.ptrace_tracer_pid == Some(tracer_pid)
    };
    if !traced_by_current {
        return Err(EPERM);
    }
    Ok(target)
}

pub fn syscall_ptrace(request: usize, pid: usize, _addr: usize, data: usize) -> isize {
    match request {
        PTRACE_TRACEME => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if inner.ptrace_tracer_pid.is_some() {
                return EPERM;
            }
            let Some(parent_pid) = inner
                .parent
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|p| p.getpid())
            else {
                return EPERM;
            };
            inner.ptrace_tracer_pid = Some(parent_pid);
            0
        }
        PTRACE_ATTACH => {
            let tracer_pid = current_process().getpid();
            if pid == tracer_pid {
                return EPERM;
            }
            let Some(target) = pid2process(pid) else {
                return ESRCH;
            };
            if !crate::task::signal::can_signal_process(&target, SIGSTOP_NUM as i32) {
                return EPERM;
            }
            let tasks = {
                let mut inner = target.borrow_mut();
                if inner.is_zombie {
                    return ESRCH;
                }
                if inner.ptrace_tracer_pid.is_some() {
                    return EPERM;
                }
                inner.ptrace_tracer_pid = Some(tracer_pid);
                inner.stopped = true;
                inner.stop_pending = true;
                inner.stop_signal = SIGSTOP_NUM as i32;
                inner.continued = false;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if task_inner.task_status != TaskStatus::Blocked {
                    task_inner.task_status = TaskStatus::Blocked;
                    task_inner.stopped_by_signal = true;
                }
            }
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_DETACH => {
            let sig = data as isize;
            if sig < 0 || sig as usize > RT_SIG_MAX {
                return EINVAL;
            }
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let tasks = {
                let mut inner = target.borrow_mut();
                inner.ptrace_tracer_pid = None;
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = true;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            if sig != 0 {
                queue_process_signal(pid, sig as usize);
            }
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_CONT => {
            let sig = data as isize;
            if sig < 0 || sig as usize > RT_SIG_MAX {
                return EINVAL;
            }
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let tasks = {
                let mut inner = target.borrow_mut();
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = true;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            if sig != 0 {
                queue_process_signal(pid, sig as usize);
            }
            wake_parent_waiters_for(&target);
            0
        }
        PTRACE_KILL => {
            let target = match ptrace_target_for_current(pid) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let tasks = {
                let mut inner = target.borrow_mut();
                inner.stopped = false;
                inner.stop_pending = false;
                inner.stop_signal = 0;
                inner.continued = false;
                inner
                    .tasks
                    .iter()
                    .filter_map(|t| t.as_ref().cloned())
                    .collect::<Vec<_>>()
            };
            queue_process_signal(pid, SIGKILL_NUM);
            for task in tasks {
                let mut task_inner = task.borrow_mut();
                if !task_inner.stopped_by_signal {
                    continue;
                }
                task_inner.stopped_by_signal = false;
                drop(task_inner);
                wakeup_task(task);
            }
            0
        }
        _ => {
            // Keep invalid memory/register ptrace operations Linux-like for LTP:
            // return EIO (tests also accept EFAULT).
            if let Err(e) = ptrace_target_for_current(pid) {
                return e;
            }
            EIO
        }
    }
}
