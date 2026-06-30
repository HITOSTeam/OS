use super::*;
use alloc::sync::Arc;

struct LoadedExecImage {
    data: Vec<u8>,
    exec_inode: (usize, u32),
    _reservation: crate::fs::ExecInodeReservation,
}

fn load_exec_inode_image(inode: Arc<ext4_fs::Inode>) -> Result<LoadedExecImage, isize> {
    let reservation = crate::fs::ExecInodeReservation::new(inode.device_id(), inode.inode_num())?;
    let exec_inode = reservation.key();
    let data = {
        let _ext4_guard = ext4_lock();
        inode.read_all()
    };
    Ok(LoadedExecImage {
        data,
        exec_inode,
        _reservation: reservation,
    })
}

/// This function tries to load a file from the given path.
fn load_file_from_path(path: &str) -> Result<LoadedExecImage, isize> {
    match resolve_exec_inode(path) {
        Ok(inode) => return load_exec_inode_image(inode),
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
                Ok(inode) => return load_exec_inode_image(inode),
                Err(e) if e == err(SyscallError::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
    }
    if !path.ends_with(".bin") {
        let mut with_bin = String::from(path);
        with_bin.push_str(".bin");
        return match resolve_exec_inode(&with_bin) {
            Ok(inode) => load_exec_inode_image(inode),
            Err(e) => Err(e),
        };
    }
    Err(err(SyscallError::ENOENT))
}

/// 以只读方式加载文件内容，不做可执行权限检查。
/// 用于加载动态链接器（`ld.so`）等不需要执行权限的场景。
fn load_file_readonly(path: &str) -> Result<LoadedExecImage, isize> {
    match resolve_read_inode(path) {
        Ok(inode) => load_exec_inode_image(inode),
        Err(e) => Err(e),
    }
}

/// 解析可执行文件的 inode，若路径不存在则尝试 busybox / `.bin` 后缀等回退路径。
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

/// 按优先级搜索系统中可用的 shell 解释器（优先 busybox，其次 `/bin/sh`）。
/// 返回 `(路径, 文件内容, 是否需要额外传入 "sh" applet 参数)`。
fn find_shell_interpreter() -> Result<Option<(String, LoadedExecImage, bool)>, isize> {
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

/// 判断路径是否是标准 POSIX shell 路径（`/bin/sh`、`/bin/dash` 等）。
/// 用于 shebang 处理时决定是否重定向到 busybox sh。
fn is_system_shell_path(path: &str) -> bool {
    matches!(
        path,
        "/bin/sh" | "/bin/dash" | "/usr/bin/sh" | "/usr/bin/dash"
    )
}

/// 在常见路径中搜索 busybox 可执行文件，返回第一个找到的 `(路径, 文件内容)`。
fn find_busybox_shell() -> Result<Option<(String, LoadedExecImage)>, isize> {
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

/// 根据 shebang 解释器名称（如 `sh`、`dash`、`env`）返回对应的 busybox applet 名。
/// 用于将缺失的系统 `/bin/sh`/`dash` 解释器映射到 `busybox sh`。
fn busybox_shell_applet(interp_name: &str, opt_arg: Option<&str>) -> &'static str {
    let shell_name = if interp_name == "env" {
        opt_arg.unwrap_or("sh")
    } else {
        interp_name
    };
    match shell_name {
        "dash" | "sh" => "sh",
        "busybox" => "sh",
        _ => "sh",
    }
}

/// lua的shebnag是 #!/bin/busybox sh 解析后 interp_name = "busybox" opt_arg = Some("sh")
/// 所以需要再额外判断解释器是不是busybox
/// 决定 shebang 的可选参数（如 `#!/usr/bin/env sh` 中的 `sh`）是否应透传给解释器。
/// 当解释器是 `env` 且参数已被识别为 shell 名称时，不再重复传递。
fn shebang_shell_extra_arg<'a>(interp_name: &str, opt_arg: Option<&'a str>) -> Option<&'a str> {
    if matches!(interp_name, "busybox" | "env") && matches!(opt_arg, Some("sh") | Some("dash")) {
        None
    } else {
        opt_arg
    }
}
/// 将当前进程替换为已在内存中的解释器镜像（`interp_data`）。
/// 若解释器本身也有 `PT_INTERP`（即 glibc 动态链接的 ld.so），则走动态加载路径。
fn exec_interpreter(interp: LoadedExecImage, args: Vec<String>, envs: Vec<String>) -> isize {
    if let Err(e) = validate_exec_stack_args(&args, &envs) {
        return e;
    }
    let process = current_process();
    let interp_abi = crate::mm::elf_arch_abi_from_bytes(&interp.data).ok();
    if let Some(interp_interp) = elf_interp_path(&interp.data) {
        let interp_interp_data = match load_interp_data(&interp_interp, interp_abi) {
            Ok(data) => data,
            Err(e) => return e,
        };
        if let Err(e) = process.exec_dyn(
            &interp.data,
            &interp_interp_data.data,
            args,
            envs,
            interp.exec_inode,
        ) {
            return e;
        }
    } else {
        if let Err(e) = process.exec(&interp.data, args, envs, interp.exec_inode) {
            return e;
        }
    }
    maybe_stop_after_ptrace_exec();
    0
}

/// 校验解释器（`ld.so`）的架构 ABI 与主程序是否匹配。
/// 若 `expected_main_abi` 为 `None`（架构未知），则跳过校验。
fn check_interp_abi(
    interp_data: &[u8],
    expected_main_abi: Option<crate::mm::ElfArchAbi>,
) -> Result<(), isize> {
    if let Some(main_abi) = expected_main_abi {
        let interp_abi = crate::mm::elf_arch_abi_from_bytes(interp_data)?;
        crate::mm::validate_elf_interp_abi(main_abi, interp_abi)?;
    }
    Ok(())
}

/// 尝试加载单个解释器候选路径。
/// - `ENOENT`：文件不存在，返回 `Ok(None)` 让调用方继续尝试下一个候选。
/// - `EACCES`：无执行权限，回退到只读加载（`ld.so` 有时权限位不含 x）。
/// - 其他错误：直接向上传播。
fn load_interp_candidate(path: &str) -> Result<Option<LoadedExecImage>, isize> {
    match load_file_from_path(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e == err(SyscallError::EACCES) => match load_file_readonly(path) {
            Ok(data) => Ok(Some(data)),
            Err(_) => Err(e),
        },
        Err(e) if e == err(SyscallError::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// 加载动态链接器（`PT_INTERP` 路径），并校验其 ABI 与主程序一致。
///
/// 若按 `interp` 原路径找不到，则按类型（musl / glibc / loongarch / riscv）
/// 尝试一组预设候选路径，优先选 ABI 匹配的，全部 ABI 不符时返回 `ENOEXEC`。
fn load_interp_data(
    interp: &str,
    expected_main_abi: Option<crate::mm::ElfArchAbi>,
) -> Result<LoadedExecImage, isize> {
    match load_file_from_path(interp) {
        Ok(image) => {
            check_interp_abi(&image.data, expected_main_abi)?;
            return Ok(image);
        }
        Err(e) if e == err(SyscallError::EACCES) => {
            if let Ok(image) = load_file_readonly(interp) {
                check_interp_abi(&image.data, expected_main_abi)?;
                return Ok(image);
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

    let mut found_wrong_abi = false;
    for cand in candidates {
        let Some(data) = load_interp_candidate(cand)? else {
            continue;
        };
        match check_interp_abi(&data.data, expected_main_abi) {
            Ok(()) => return Ok(data),
            Err(e) if e == err(SyscallError::ENOEXEC) => {
                found_wrong_abi = true;
            }
            Err(e) => return Err(e),
        }
    }

    if found_wrong_abi {
        return Err(err(SyscallError::ENOEXEC));
    }
    Err(err(SyscallError::ENOENT))
}

/// 通过魔数快速判断字节切片是否为 ELF 文件。
fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x7f, b'E', b'L', b'F']
}

/// 从 ELF 数据中读取 `PT_INTERP` 段，返回动态链接器路径字符串。
/// 静态可执行文件或格式异常时返回 `None`。
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

/// 解析文件开头的 shebang 行（`#!interpreter [arg]`）。
/// 返回 `(解释器路径, 可选参数)`，格式非法或不含 `#!` 时返回 `None`。
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

/// `execve` 成功后，若当前进程正被 ptrace 跟踪，则投递 `SIGTRAP` 并进入停止状态，
/// 让调试器有机会在新镜像的入口点之前介入（对应 Linux `PTRACE_EVENT_EXEC`）。
fn maybe_stop_after_ptrace_exec() {
    let process = current_process();
    super::wait::enter_ptrace_stop(&process, PTRACE_SIGTRAP);
}

/// 尝试将 `path` 作为 busybox applet 执行。
/// 若 `path` 的 basename 是已知 busybox applet，则找到 busybox 并以
/// `busybox <applet> [args...]` 的形式替换当前进程，返回执行结果。
/// 不符合条件（basename 为空、是 busybox 本身、是 `.sh` 文件、applet 不在白名单、
/// 或找不到 busybox）时返回 `None`，由调用方继续处理。
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
const LINUX_STK_LIM: usize = 8 * 1024 * 1024;
const LINUX_ARG_MAX: usize = EXEC_MAX_ARG_STRLEN;
const EXEC_AUXV_ENTRIES_MAX: usize = 19;
const EXEC_STACK_RUNTIME_RESERVE: usize = crate::config::PAGE_SIZE * 32;
#[cfg(target_arch = "loongarch64")]
const EXEC_PLATFORM: &str = "loongarch64";
#[cfg(not(target_arch = "loongarch64"))]
const EXEC_PLATFORM: &str = "RISC-V64";

/// 计算字符串 `s` 在 exec 初始栈上实际占用的字节数（含末尾 `\0`）。
///
/// - 超过 `EXEC_MAX_ARG_STRLEN` 时返回 `E2BIG`。
/// - LoongArch：按字（8 字节）向上对齐，匹配 `build_linux_stack_loongarch` 的布局。
/// - RISC-V：字符串紧密堆叠，返回 `raw_len`（无对齐填充）。
// 检查 exec arg 的 长度
fn exec_arg_string_stack_len(s: &str) -> Result<usize, isize> {
    let raw_len = s.len().checked_add(1).ok_or(err(SyscallError::E2BIG))?;
    if raw_len > EXEC_MAX_ARG_STRLEN {
        return Err(err(SyscallError::E2BIG));
    }
    #[cfg(target_arch = "loongarch64")]
    {
        // Round each string up to a word boundary to match the LoongArch
        // initial-stack layout. raw_len <= EXEC_MAX_ARG_STRLEN, so no overflow.
        let word = size_of::<usize>();
        Ok((raw_len + word - 1) & !(word - 1))
    }
    #[cfg(not(target_arch = "loongarch64"))]
    {
        Ok(raw_len)
    }
}

/// 计算每次 exec 在初始栈上固定消耗的字节数（不含 argv/envp 字符串和指针表）：
/// 运行时预留 + AT_PLATFORM 字符串 + AT_RANDOM（16B）+ auxv 表 + 对齐填充
/// + argc/argv/envp NULL 终止符，以及 RISC-V 额外的 AT_EXECFN 字符串。
fn exec_stack_fixed_reserve(execfn_len: usize) -> Result<usize, isize> {
    let word = size_of::<usize>();
    // Fixed per-exec stack overhead: a runtime slop reserve, the platform
    // string, AT_RANDOM (16B), the auxv table, the argc/argv/envp NULL
    // terminators, and the initial alignment padding. All terms are small and
    // bounded, so plain addition cannot overflow usize.
    let base = EXEC_STACK_RUNTIME_RESERVE
        + exec_arg_string_stack_len(EXEC_PLATFORM)?
        + 16
        + (EXEC_AUXV_ENTRIES_MAX + 1) * 2 * word
        + 3 * word
        + 16
        + word;
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = execfn_len;
        Ok(base)
    }
    #[cfg(not(target_arch = "loongarch64"))]
    {
        // RISC-V also reserves AT_EXECFN's string copy on the initial stack.
        let execfn_reserve = if execfn_len != 0 { execfn_len + 1 } else { 0 };
        Ok(base + execfn_reserve)
    }
}

/// 返回当前进程 `RLIMIT_STACK` 软限制的四分之一，对应 Linux `bprm_stack_limits`
/// 中 `rlimit / 4` 的用法。`RLIM_INFINITY` 时返回 `usize::MAX`。
fn rlimit_stack_quarter() -> usize {
    let rlimit = current_process().borrow_mut().rlimits.rlimit_stack_cur;
    if rlimit == u64::MAX {
        usize::MAX
    } else {
        usize::try_from(rlimit).unwrap_or(usize::MAX) / 4
    }
}

/// 根据 argv/envp 的数量计算字符串区的字节预算上限。
///
/// 仿照 Linux `bprm_stack_limits()`：
/// 1. 以 `min(3/4 * _STK_LIM, RLIMIT_STACK/4, ARG_MAX)` 为基础预算；
/// 2. 减去指针表开销（`(argc + envc) * word`）得到字符串预算；
/// 3. 再与本内核固定栈大小减去固定保留区取 min，防止实际超出用户栈。
fn exec_string_limit_for_counts(
    argc: usize,
    envc: usize,
    execfn_len: usize,
) -> Result<usize, isize> {
    let word = size_of::<usize>();
    let ptr_count = argc
        .max(1)
        .checked_add(envc)
        .ok_or(err(SyscallError::E2BIG))?;
    let ptr_size = ptr_count
        .checked_mul(word)
        .ok_or(err(SyscallError::E2BIG))?;
    let linux_limit = (LINUX_STK_LIM / 4 * 3)
        .min(rlimit_stack_quarter())
        .max(LINUX_ARG_MAX);
    if linux_limit <= ptr_size {
        return Err(err(SyscallError::E2BIG));
    }
    let linux_string_limit = linux_limit - ptr_size;
    let fixed_reserve = exec_stack_fixed_reserve(execfn_len)?;
    let usable = crate::config::USER_STACK_SIZE
        .checked_sub(fixed_reserve)
        .ok_or(err(SyscallError::E2BIG))?;
    if usable <= ptr_size {
        return Err(err(SyscallError::E2BIG));
    }
    Ok(linux_string_limit.min(usable - ptr_size))
}

/// 校验 `execve` 的 `argv` 和 `envp` 是否超出内核允许的栈空间限制。
///
/// 对应 Linux `bprm_stack_limits()` 策略，依次检查：
/// 1. **指针数量**：`args` 和 `envs` 的元素个数均不得超过
///    `EXEC_ARG_PTR_LIMIT`（用户栈大小 / 指针宽度），否则 `E2BIG`。
/// 2. **字符串总字节数**：所有 argv/envp 字符串（含末尾 `\0` 及对齐填充）
///    的累计大小不得超过由 `_STK_LIM`、`RLIMIT_STACK`、`ARG_MAX` 推导出的
///    字符串预算（已减去指针表开销）。超出则返回 `E2BIG`。
///
/// 本内核的 exec 栈大小固定，因此在 Linux 预算基础上还额外以映射用户栈
/// 大小为上限，确保在地址空间切换之前就以 `E2BIG` 拒绝不可能放下的参数，
/// 避免切换后再失败导致进程被异常终止。
fn validate_exec_stack_args(args: &[String], envs: &[String]) -> Result<(), isize> {
    //1. 检查 最基本的 参数大小
    if args.len() > EXEC_ARG_PTR_LIMIT || envs.len() > EXEC_ARG_PTR_LIMIT {
        return Err(err(SyscallError::E2BIG));
    }

    let execfn_len = args.first().map(|s| s.len()).unwrap_or(0);
    let string_limit = exec_string_limit_for_counts(args.len(), envs.len(), execfn_len)?;
    let mut string_bytes = 0usize;
    for s in args.iter().chain(envs.iter()) {
        string_bytes = string_bytes
            .checked_add(exec_arg_string_stack_len(s)?)
            .ok_or(err(SyscallError::E2BIG))?;
    }

    // Match Linux's bprm_stack_limits() policy for argv/env strings: derive a
    // string budget from _STK_LIM, RLIMIT_STACK and ARG_MAX, then subtract the
    // argv/env pointer table. Our current exec stack is fixed-size, so cap the
    // Linux budget by the mapped user stack to fail with E2BIG before mm switch.
    if string_bytes > string_limit {
        return Err(err(SyscallError::E2BIG));
    }
    Ok(())
}

/// 从用户地址空间读取 `argv` 和 `envp` 字符串数组。
///
/// 边读边扣减字符串预算，一旦超限立即返回 `E2BIG`，避免把超大参数表
/// 完整复制进内核后才发现超限。`argv[0]` 缺失时以 `path` 补充。
fn read_exec_args_envs(
    token: usize,
    path: &str,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<(Vec<String>, Vec<String>), isize> {
    let arg_ptrs = read_user_ptr_array(token, argv_ptr)?;
    let env_ptrs = read_user_ptr_array(token, envp_ptr)?;
    let argc = arg_ptrs.len().max(1);

    // argv[0] defaults to the program path when the user passes an empty argv.
    let first_arg = if let Some(ptr) = arg_ptrs.first().copied() {
        try_read_user_exec_cstr(token, ptr)?
    } else {
        String::from(path)
    };

    // Charge each string against the stack budget as it is read, so an oversized
    // argv/env block fails with E2BIG before it is fully copied into the kernel.
    let mut remaining = exec_string_limit_for_counts(argc, env_ptrs.len(), first_arg.len())?;
    let charge = |remaining: &mut usize, s: &str| -> Result<(), isize> {
        *remaining = remaining
            .checked_sub(exec_arg_string_stack_len(s)?)
            .ok_or(err(SyscallError::E2BIG))?;
        Ok(())
    };

    let mut args = Vec::with_capacity(argc);
    charge(&mut remaining, &first_arg)?;
    args.push(first_arg);
    for ptr in arg_ptrs.iter().skip(1).copied() {
        let arg = try_read_user_exec_cstr(token, ptr)?;
        charge(&mut remaining, &arg)?;
        args.push(arg);
    }

    let mut envs = Vec::with_capacity(env_ptrs.len());
    for ptr in env_ptrs {
        let env = try_read_user_exec_cstr(token, ptr)?;
        charge(&mut remaining, &env)?;
        envs.push(env);
    }
    Ok((args, envs))
}

/// 核心 exec 实现：给定已解析的 inode，将当前进程替换为目标程序。
///
/// 处理顺序：
/// 1. 校验 argv/envp 大小。
/// 2. 尝试惰性 ELF 解析（避免将整个二进制读入堆）；若成功且有 `PT_INTERP`，
///    走动态链接路径，否则走静态 ELF 路径。
/// 3. 若不是 ELF，检查 shebang，递归调用解释器。
/// 4. 对 `.sh` 文件做无 shebang 兜底（ExampleOs 兼容）。
/// 5. 其他情况返回 `ENOEXEC`。
fn execve_with_inode(
    path: String,
    args_vec: Vec<String>,
    envs_vec: Vec<String>,
    inode: Arc<ext4_fs::Inode>,
    _exec_reservation: crate::fs::ExecInodeReservation,
) -> isize {
    const ENOEXEC: isize = -8;
    if let Err(e) = validate_exec_stack_args(&args_vec, &envs_vec) {
        return e;
    }
    // Try lazy ELF loading to avoid reading large binaries into kernel heap.
    let elf_info = {
        let inode = Arc::clone(&inode);
        let mut read_at = |offset: usize, buf: &mut [u8]| {
            let _ext4_guard = ext4_lock();
            inode.read_at(offset, buf)
        };
        match crate::mm::elf_load_info_from_reader(&mut read_at) {
            Ok(v) => Some(v),
            Err(ENOEXEC) => None,
            Err(e) => return e,
        }
    };
    let exec_inode = {
        let _ext4_guard = ext4_lock();
        (inode.device_id(), inode.inode_num())
    };
    if let Some(info) = elf_info {
        if let Some(interp) = info.interp.as_deref() {
            let interp_data = match load_interp_data(interp, Some(info.arch_abi)) {
                Ok(data) => data,
                Err(e) => return e,
            };
            if !is_elf(&interp_data.data) {
                return ENOEXEC;
            }
            let inode = Arc::clone(&inode);
            let loader = |offset: usize, buf: &mut [u8]| {
                let _ext4_guard = ext4_lock();
                inode.read_at(offset, buf)
            };
            let (memory_set, ustack_base, interp_entry, main_entry, main_aux, interp_base) =
                match MemorySet::from_elf_with_interp_info_reader(loader, &info, &interp_data.data)
                {
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
                &interp_data.data,
                args_vec,
                envs_vec,
                exec_inode,
            );
            maybe_stop_after_ptrace_exec();
            return 0;
        }

        let inode = Arc::clone(&inode);
        let loader = |offset: usize, buf: &mut [u8]| {
            let _ext4_guard = ext4_lock();
            inode.read_at(offset, buf)
        };
        let (memory_set, ustack_base, entry_point, elf_aux) =
            match MemorySet::from_elf_info_reader(loader, &info) {
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
        let opt_arg_ref = opt_arg.as_deref();
        let env_shell = interp_name == "env" && matches!(opt_arg_ref, Some("sh") | Some("dash"));
        let busybox_shell =
            interp_name == "busybox" && matches!(opt_arg_ref, Some("sh") | Some("dash"));
        let wants_shell = matches!(interp_name, "sh" | "dash") || env_shell || busybox_shell;
        let extra_shell_arg = shebang_shell_extra_arg(interp_name, opt_arg_ref);
        match load_file_from_path(&interp) {
            Ok(interp_data) if is_elf(&interp_data.data) => {
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
                if !is_elf(&interp_data.data) {
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
                if is_elf(&interp_data.data) {
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
            if !is_elf(&interp_data.data) {
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
            if let Err(e) = validate_exec_stack_args(&new_args, &envs_vec) {
                return e;
            }
            return exec_interpreter(interp_data, new_args, envs_vec);
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
        if !is_elf(&interp_data.data) {
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
        if let Err(e) = validate_exec_stack_args(&new_args, &envs_vec) {
            return e;
        }
        return exec_interpreter(interp_data, new_args, envs_vec);
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

    let (args_vec, envs_vec) = match read_exec_args_envs(token, &path, argv_ptr, envp_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    crate::log_if!(
        DEBUG_SIGNAL,
        info,
        "[execve] pid={} path='{}' argv0='{}' argv1='{}'",
        current_process().getpid(),
        path,
        args_vec.get(0).map(|s| s.as_str()).unwrap_or(""),
        args_vec.get(1).map(|s| s.as_str()).unwrap_or("")
    );

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
    let exec_reservation =
        match crate::fs::ExecInodeReservation::new(inode.device_id(), inode.inode_num()) {
            Ok(reservation) => reservation,
            Err(e) => return e,
        };

    execve_with_inode(path, args_vec, envs_vec, inode, exec_reservation)
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
    let (args_vec, envs_vec) = match read_exec_args_envs(token, &path, argv_ptr, envp_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let inode = match resolve_exec_inode_at(dirfd, &path, flags) {
        Ok(inode) => inode,
        Err(e) => return e,
    };
    let exec_reservation =
        match crate::fs::ExecInodeReservation::new(inode.device_id(), inode.inode_num()) {
            Ok(reservation) => reservation,
            Err(e) => return e,
        };
    execve_with_inode(path, args_vec, envs_vec, inode, exec_reservation)
}
