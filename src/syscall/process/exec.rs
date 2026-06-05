use super::*;
use alloc::sync::Arc;

fn is_inode_open_for_write(inode_num: u32) -> bool {
    let processes: Vec<_> = {
        let map = PID2PCB.lock();
        map.values().cloned().collect()
    };
    let mut seen_tables = alloc::collections::BTreeSet::new();
    for process in processes {
        let inner = process.borrow_mut();
        let files = Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        for (_fd, file) in files.lock().iter_files_snapshot() {
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
        Err(e) if e != err(SyscallError::ENOENT) => return Err(e),
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
                Err(e) if e == err(SyscallError::ENOENT) => {}
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
    Err(err(SyscallError::ENOENT))
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
        Err(e) if e != err(SyscallError::ENOENT) => return Err(e),
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
                Err(e) if e == err(SyscallError::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
    }
    if !path.ends_with(".bin") {
        let mut with_bin = String::from(path);
        with_bin.push_str(".bin");
        return resolve_exec_inode(&with_bin);
    }
    Err(err(SyscallError::ENOENT))
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
            Err(e) if e == err(SyscallError::ENOENT) => {}
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
            Err(e) if e == err(SyscallError::ENOENT) => {}
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

///eg 如果是#!/bin/sh
/// interp_name = "sh" opt_arg = None
/// 就是busybox sh {脚本路径}
/// 
/// #!/usr/bin/env sh
/// interp_name = "env" opt_arg = Some("sh")
/// 这个时候不能返回opt_arg 也应该是none,不然执行lua测试的时候会报错

fn shebang_shell_extra_arg<'a>(interp_name: &str, opt_arg: Option<&'a str>) -> Option<&'a str> {
    if interp_name == "env" && matches!(opt_arg, Some("sh") | Some("bash")) {
        None
    } else if interp_name == "busybox" && matches!(opt_arg, Some("sh") | Some("bash")) {
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
        if let Err(e) = process.exec_dyn(&interp_data, &interp_interp_data, args, envs) {
            return e;
        }
    } else {
        if let Err(e) = process.exec(&interp_data, args, envs) {
            return e;
        }
    }
    maybe_stop_after_ptrace_exec();
    0
}

fn load_interp_data(interp: &str) -> Result<Vec<u8>, isize> {
    match load_file_from_path(interp) {
        Ok(data) => return Ok(data),
        Err(e) if e == err(SyscallError::EACCES) => {
            if let Ok(data) = load_file_readonly(interp) {
                return Ok(data);
            }
        }
        Err(e) if e == err(SyscallError::ENOENT) => {}
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
            Err(e) if e == err(SyscallError::EACCES) => {
                if let Ok(data) = load_file_readonly(cand) {
                    return Ok(data);
                }
            }
            Err(e) if e == err(SyscallError::ENOENT) => {}
            Err(e) => return Err(e),
        }
    }

    Err(err(SyscallError::ENOENT))
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

fn maybe_stop_after_ptrace_exec() {
    let process = current_process();
    super::wait::enter_ptrace_stop(&process, PTRACE_SIGTRAP);
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
    if !crate::syscall::busybox_applet_allowed(applet) {
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

pub(super) fn path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

const PTRACE_SIGTRAP: i32 = 5;

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
            Err(e) if e == err(SyscallError::ENOENT) => {}
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
            Err(e) if e == err(SyscallError::ENOENT) && wants_shell => {
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
                return err(SyscallError::ENOENT);
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
                if let Err(e) =
                    process.exec_dyn(&interp_data, &interp_interp_data, new_args, envs_vec)
                {
                    return e;
                }
            } else {
                if let Err(e) = process.exec(&interp_data, new_args, envs_vec) {
                    return e;
                }
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
            return err(SyscallError::ENOENT);
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
            if let Err(e) = process.exec_dyn(&interp_data, &interp_interp_data, new_args, envs_vec)
            {
                return e;
            }
        } else {
            if let Err(e) = process.exec(&interp_data, new_args, envs_vec) {
                return e;
            }
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
        return err(SyscallError::EFAULT);
    }
    let path = match try_read_user_cstr(token, path_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };

    let mut args_vec: Vec<String> = Vec::new();
    // try to read the arg from the args vector(arg_v)
    if argv_ptr != 0 {
        let mut i = 0usize;
        loop {
            if i >= 4096 {
                return err(SyscallError::E2BIG);
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
                return err(SyscallError::E2BIG);
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
            if e == err(SyscallError::ENOENT) {
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
        return err(SyscallError::ETXTBSY);
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
        return err(SyscallError::EFAULT);
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
        return err(SyscallError::ETXTBSY);
    }
    execve_with_inode(path, args_vec, envs_vec, inode)
}
