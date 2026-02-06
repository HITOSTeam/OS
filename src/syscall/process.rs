use alloc::{string::String, sync::Arc, vec::Vec};
use core::{mem::size_of, sync::atomic::Ordering};

use crate::{
    arch::{REG_A0, REG_SP, REG_TP},
    debug_config::{DEBUG_EXEC, DEBUG_PTHREAD, DEBUG_SIGNAL, DEBUG_UNIXBENCH},
    fs::{ext4_lock, root_inode_for_path, secondary_root_inode},
    mm::{kernel_token, translated_single_address, translated_str, write_user_value, MemorySet},
    println,
    syscall::{
        filesystem::{normalize_path, resolve_exec_inode, resolve_read_inode},
        misc::encode_linux_tid,
        signal::{ERESTARTSYS, SA_RESTART},
    },
    task::{
        manager::{add_task, select_hart_for_new_task},
        processor::{block_current_and_run_next, current_process, current_task},
        signal::{pending_unmasked_bits, SignalFlags, MAX_SIG, SIG_DFL, SIG_IGN},
        task_block::TaskControlBlock,
    },
    trap::{get_current_token, trap_handler},
};

const ENOENT: isize = -2;
const EACCES: isize = -13;

fn read_usize_user(token: usize, ptr: usize) -> usize {
    let mut raw = [0u8; size_of::<usize>()];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = *translated_single_address(token, (ptr + i) as *const u8);
    }
    usize::from_ne_bytes(raw)
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
        let fallbacks = ["/musl/busybox", "/glibc/busybox", "/bin/busybox", "/busybox"];
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
        let fallbacks = ["/musl/busybox", "/glibc/busybox", "/bin/busybox", "/busybox"];
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
    matches!(path, "/bin/sh" | "/bin/dash" | "/usr/bin/sh" | "/usr/bin/dash")
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

fn exec_interpreter(
    interp_data: Vec<u8>,
    args: Vec<String>,
    envs: Vec<String>,
) -> isize {
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
    const CLONE_SIGHAND: usize = 0x0000_0800;
    const CLONE_THREAD: usize = 0x0001_0000;
    const CLONE_SETTLS: usize = 0x0008_0000;
    const CLONE_PARENT_SETTID: usize = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
    const CLONE_CHILD_SETTID: usize = 0x0100_0000;

    // LoongArch syscall ABI uses a different argument order:
    // clone(flags, stack, ptid, ctid, tls). Swap tls/ctid here.
    #[cfg(target_arch = "loongarch64")]
    let (_tls, _ctid) = (_ctid, _tls);

    // Thread-like clone: share address space (glibc pthreads).
    let is_thread_like =
        (flags & CLONE_VM) != 0 && ((flags & CLONE_THREAD) != 0 || (flags & CLONE_SIGHAND) != 0);
    if is_thread_like {
        const ENOMEM: isize = -12;
        let task = current_task().unwrap();
        let parent_mask = {
            let inner = task.borrow_mut();
            inner.signal_mask
        };
        let parent_cx = {
            let inner = task.borrow_mut();
            *inner.get_trap_cx()
        };
        let process = current_process();
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
            trap_cx.kernel_sp = new_task.kstack.get_top();
            trap_cx.trap_handler = trap_handler as usize;
            if (flags & CLONE_CHILD_CLEARTID) != 0 && _ctid != 0 {
                new_inner.clear_child_tid = Some(_ctid);
            }
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
            write_user_value(token, _ptid as *mut i32, &(linux_tid as i32));
        }
        if (flags & CLONE_CHILD_SETTID) != 0 && _ctid != 0 {
            write_user_value(token, _ctid as *mut i32, &(linux_tid as i32));
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
    let Some((child, task)) = process.fork_with_task() else {
        return -12;
    };

    {
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        *trap_cx = parent_cx;
        trap_cx.x[REG_A0] = 0; // child returns 0 from syscall
        if stack != 0 {
            trap_cx.x[REG_SP] = stack;
        }
        trap_cx.kernel_satp = kernel_token();
        trap_cx.kernel_sp = task.kstack.get_top();
        trap_cx.trap_handler = trap_handler as usize;
    }
    add_task(task);
    crate::log_if!(
        DEBUG_SIGNAL,
        info,
        "[fork] parent_pid={} child_pid={} flags={:#x} stack={:#x}",
        process.getpid(),
        child.getpid(),
        flags,
        stack
    );
    child.getpid() as isize
}

/// Linux `vfork(2)` compatibility.
///
/// For now, treat it as a normal `fork(2)` (copy address space). This is
/// sufficient for busybox/ash and many OSComp scripts, and avoids the strict
/// parent-blocking/VM-sharing semantics of true vfork.
pub fn syscall_vfork() -> isize {
    let process = current_process();
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

fn is_core_dump_signal(sig: i32) -> bool {
    matches!(sig, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31)
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

fn try_exec_busybox_applet(
    path: &str,
    args: &[String],
    envs: &[String],
) -> Option<isize> {
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
            process_inner.wait_queue.retain(|t| !Arc::ptr_eq(t, &task));
            drop(process_inner);
            return action;
        }
        let mut process_inner = cur_process.borrow_mut();
        let parent_pgid = process_inner.pgid;
        let mut stop_event: Option<(usize, i32)> = None;
        let mut cont_event: Option<usize> = None;
        let (has_matching_child, zombie_pid) = if process_inner.children.is_empty() {
            (false, None)
        } else {
            let mut found: Option<(usize, usize)> = None; // (index, pid)
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
                    temp_coredump = temp_signal
                        .map(|sig| is_core_dump_signal(sig) && child_inner.rlimit_core_cur > 0)
                        .unwrap_or(false);
                    found = Some((index, child.pid.0));
                    break;
                }
                if matches
                    && (options & WUNTRACED) != 0
                    && child_inner.stopped
                    && child_inner.stop_pending
                {
                    let sig = if child_inner.stop_signal != 0 {
                        child_inner.stop_signal
                    } else {
                        crate::task::signal::SIGSTOP_NUM as i32
                    };
                    stop_event = Some((child.pid.0, sig));
                    break;
                }
                if matches && (options & WCONTINUED) != 0 && child_inner.continued {
                    cont_event = Some(child.pid.0);
                    break;
                }
            }
            if let Some((index, pid)) = found {
                process_inner.children.remove(index);
                (true, Some(pid))
            } else {
                (has_match, None)
            }
        };

        if let Some((pid, sig)) = stop_event {
            let child = process_inner
                .children
                .iter()
                .find(|c| c.getpid() == pid)
                .cloned();
            if let Some(child) = child {
                let mut child_inner = child.borrow_mut();
                child_inner.stop_pending = false;
                child_inner.stop_signal = sig;
            }
            drop(process_inner);
            if wstatus_ptr != 0 {
                let status = ((sig & 0xff) << 8) | 0x7f;
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }
        if let Some(pid) = cont_event {
            let child = process_inner
                .children
                .iter()
                .find(|c| c.getpid() == pid)
                .cloned();
            if let Some(child) = child {
                let mut child_inner = child.borrow_mut();
                child_inner.continued = false;
            }
            drop(process_inner);
            if wstatus_ptr != 0 {
                let status = 0xffff;
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }

        if let Some(pid) = zombie_pid {
            drop(process_inner);
            // Keep exited processes visible (e.g., for `kill $!`) until they are reaped.
            // Reaping happens here (wait4), so remove it from the global PID table now.
            crate::task::manager::remove_from_pid2process(pid);
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

        if !has_matching_child {
            if DEBUG_PTHREAD {
                let child_pids = process_inner
                    .children
                    .iter()
                    .map(|c| c.getpid())
                    .collect::<Vec<_>>();
                log::debug!(
                    "[wait4] pid={} wait_pid={} no matching child children={:?}",
                    cur_process.getpid(),
                    pid,
                    child_pids
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
        process_inner.wait_queue.push_back(task);
        drop(process_inner);
        block_current_and_run_next();
    }
}

pub fn syscall_waitid(idtype: usize, id: usize, infop: usize, options: usize) -> isize {
    const P_ALL: usize = 0;
    const P_PID: usize = 1;
    const P_PGID: usize = 2;
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

    let token = get_current_token();
    loop {
        let cur_process = current_process();
        let task = current_task().unwrap();
        if let Some(action) = wait4_pending_action(&task) {
            let mut process_inner = cur_process.borrow_mut();
            process_inner.wait_queue.retain(|t| !Arc::ptr_eq(t, &task));
            drop(process_inner);
            return action;
        }

        let mut process_inner = cur_process.borrow_mut();
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
                _ => return EINVAL,
            };
            if !matches {
                continue;
            }
            has_match = true;
            if (options & WEXITED) != 0 && child_inner.is_zombie {
                let exit_code = child_inner.exit_code;
                let signal = if exit_code < 0 { Some(-exit_code) } else { None };
                let coredump = signal
                    .map(|sig| is_core_dump_signal(sig) && child_inner.rlimit_core_cur > 0)
                    .unwrap_or(false);
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
            if (options & WNOWAIT) == 0 {
                process_inner.children.remove(index);
            }
            drop(process_inner);
            if (options & WNOWAIT) == 0 {
                crate::task::manager::remove_from_pid2process(child_pid);
            }
            let (si_status, si_code) = if let Some(sig) = signal {
                (
                    sig,
                    if coredump { CLD_DUMPED } else { CLD_KILLED },
                )
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

        process_inner.wait_queue.push_back(task);
        drop(process_inner);
        block_current_and_run_next();
    }
}

pub fn syscall_execve(path_ptr: usize, argv_ptr: usize, envp_ptr: usize) -> isize {
    const ENOEXEC: isize = -8;
    let token = get_current_token();
    let path = translated_str(token, path_ptr as *const u8);

    let mut args_vec: Vec<String> = Vec::new();
    if argv_ptr != 0 {
        let mut i = 0usize;
        loop {
            let arg_ptr = read_usize_user(token, argv_ptr + i * size_of::<usize>());
            if arg_ptr == 0 {
                break;
            }
            args_vec.push(translated_str(token, arg_ptr as *const u8));
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
            let env_ptr = read_usize_user(token, envp_ptr + i * size_of::<usize>());
            if env_ptr == 0 {
                break;
            }
            envs_vec.push(translated_str(token, env_ptr as *const u8));
            i += 1;
        }
    }
    if envs_vec.is_empty() {
        // Include LTP testcases bin dirs so helper binaries (e.g. acct02_helper)
        // can be resolved via tst_get_path() in LTP.
        envs_vec.push(String::from(
            "PATH=/user:/:/bin:/usr/bin:/musl:/glibc:/musl/ltp/testcases/bin:/glibc/ltp/testcases/bin",
        ));
    } else if !envs_vec.iter().any(|e| e.starts_with("PATH=")) {
        // Ensure PATH contains LTP testcases bin dirs for helper lookups.
        envs_vec.push(String::from(
            "PATH=/user:/:/bin:/usr/bin:/musl:/glibc:/musl/ltp/testcases/bin:/glibc/ltp/testcases/bin",
        ));
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
        );
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
        );
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
        if wants_shell && is_system_shell_path(&interp) {
            if let Ok(Some((bb_path, bb_data))) = find_busybox_shell() {
                let mut new_args: Vec<String> = Vec::new();
                new_args.push(bb_path);
                new_args.push(String::from("sh"));
                if let Some(a) = opt_arg_ref {
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
                if needs_sh_arg && opt_arg_ref != Some("sh") {
                    new_args.push(String::from("sh"));
                }
                if let Some(a) = opt_arg_ref {
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
        return 0;
    }

    // Non-ELF without shebang: let shells interpret it.
    return ENOEXEC;

    // unreachable
}

pub fn syscall_getpid() -> isize {
    current_task().unwrap().process.upgrade().unwrap().getpid() as isize
}
