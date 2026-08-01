use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};

use crate::{
    fs::File,
    mm::{try_copy_from_user, try_copy_to_user},
    syscall::error::{
        SyscallError::{E2BIG, EACCES, EBADF, EFAULT, EINVAL, EMFILE, ENOENT, ENOMEM, ENOSYS},
        err,
    },
    task::processor::{current_files, current_files_and_nofile_limit},
    trap::get_current_token,
};

use super::{
    BpfResult,
    map::{BpfMapFile, BpfMapKind},
    prog::BpfProgFile,
    uapi::{
        BPF_CLASS_MASK, BPF_DW, BPF_IMM, BPF_LD, BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM,
        BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_RINGBUF, BPF_MAP_UPDATE_ELEM,
        BPF_MAXINSNS, BPF_MODE_MASK, BPF_PROG_LOAD, BPF_PROG_TYPE_SOCKET_FILTER, BPF_PSEUDO_MAP_FD,
        BPF_SIZE_MASK, BpfInsn, BpfMapCreateAttr, BpfMapElemAttr, BpfProgLoadAttr,
    },
    verifier::verify_program,
};

/// 扫描指令序列，收集所有 BPF_PSEUDO_MAP_FD ldimm64 引用的 map fd，
/// 返回 fd → Arc<File> 映射（用于程序运行时快速访问 map）。
fn collect_prog_map_refs(
    insns: &[BpfInsn],
) -> BpfResult<BTreeMap<u32, Arc<dyn File + Send + Sync>>> {
    let files = current_files();
    let files = files.lock();
    let mut maps = BTreeMap::new();
    let mut pc = 0usize;
    while pc < insns.len() {
        let insn = insns[pc];
        if (insn.code & BPF_CLASS_MASK) == BPF_LD
            && (insn.code & BPF_MODE_MASK) == BPF_IMM
            && (insn.code & BPF_SIZE_MASK) == BPF_DW
        {
            if pc + 1 >= insns.len() {
                return Err(EINVAL);
            }
            if insn.src_reg() as u8 == BPF_PSEUDO_MAP_FD {
                let fd = insn.imm as u32;
                let file = files.get_file(fd as usize).ok_or(EBADF)?;
                if file.as_any().downcast_ref::<BpfMapFile>().is_none() {
                    return Err(EBADF);
                }
                maps.insert(fd, file);
            }
            pc += 2;
            continue;
        }
        pc += 1;
    }
    Ok(maps)
}

/// 从用户空间地址 `user_ptr` 拷贝一个 `T` 类型的结构体。
fn copy_user_struct<T: Copy + Default>(user_ptr: usize) -> BpfResult<T> {
    let token = get_current_token();
    let mut value = T::default();
    let dst = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut value as *mut T).cast::<u8>(),
            core::mem::size_of::<T>(),
        )
    };
    if try_copy_from_user(token, user_ptr as *const u8, dst).is_err() {
        return Err(EFAULT);
    }
    Ok(value)
}

/// 从用户空间地址 `user_ptr` 拷贝 `count` 条 BpfInsn 指令。
fn copy_user_insns(user_ptr: usize, count: usize) -> BpfResult<Vec<BpfInsn>> {
    let size = count
        .checked_mul(core::mem::size_of::<BpfInsn>())
        .ok_or(ENOMEM)?;
    let token = get_current_token();
    let mut raw = vec![0u8; size];
    if try_copy_from_user(token, user_ptr as *const u8, raw.as_mut_slice()).is_err() {
        return Err(EFAULT);
    }
    let mut out = Vec::with_capacity(count);
    for chunk in raw.chunks_exact(core::mem::size_of::<BpfInsn>()) {
        let mut insn = BpfInsn::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                (&mut insn as *mut BpfInsn).cast::<u8>(),
                core::mem::size_of::<BpfInsn>(),
            );
        }
        out.push(insn);
    }
    Ok(out)
}

/// 将文件对象安装到当前进程的文件描述符表，返回分配的 fd 或 EMFILE。
fn alloc_fd(file: Arc<dyn File + Send + Sync>) -> isize {
    let (files, limit) = current_files_and_nofile_limit();
    let installed = files.lock().install_fd(file, 0, limit);
    installed.map(|fd| fd as isize).unwrap_or_else(|rejected| {
        rejected.discard();
        err(EMFILE)
    })
}

/// 将验证器错误信息写入用户空间日志缓冲区（若 attr 中指定了 log_buf）。
fn write_verifier_log(attr: &BpfProgLoadAttr, msg: &str) {
    if attr.log_buf == 0 || attr.log_size == 0 {
        return;
    }
    let token = get_current_token();
    // 允许输入的最大大小 注意末尾手动加上 \0控制符号
    let max_payload = attr.log_size.saturating_sub(1) as usize;
    let bytes = msg.as_bytes();
    let copy_len = bytes.len().min(max_payload);
    let _ = try_copy_to_user(token, attr.log_buf as *mut u8, &bytes[..copy_len]);
    let _ = try_copy_to_user(token, (attr.log_buf as usize + copy_len) as *mut u8, &[0]);
}

/// 通过文件描述符 `fd` 获取 BPF 程序的克隆（供 socket 过滤器使用）。
pub fn get_prog_clone(fd: usize) -> Option<Arc<BpfProgFile>> {
    let file = current_files().lock().get_file(fd)?;
    let prog = file.as_any().downcast_ref::<BpfProgFile>()?;
    Some(Arc::new(prog.clone()))
}

/// `bpf()` 系统调用入口，根据 `cmd` 分发到各子命令处理函数。
pub fn syscall_bpf(cmd: usize, attr: usize, size: usize) -> isize {
    match cmd {
        BPF_MAP_CREATE => syscall_bpf_map_create(attr, size),
        BPF_MAP_LOOKUP_ELEM => syscall_bpf_map_lookup_elem(attr, size),
        BPF_MAP_UPDATE_ELEM => syscall_bpf_map_update_elem(attr, size),
        BPF_PROG_LOAD => syscall_bpf_prog_load(attr, size),
        _ => err(ENOSYS),
    }
}

/// 处理 BPF_MAP_CREATE：根据 attr 创建 map 并返回新分配的 fd。
fn syscall_bpf_map_create(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapCreateAttr>() {
        return err(EINVAL);
    }
    let attr = match copy_user_struct::<BpfMapCreateAttr>(attr) {
        Ok(attr) => attr,
        Err(e) => return err(e),
    };
    let kind = match attr.map_type {
        BPF_MAP_TYPE_HASH => BpfMapKind::Hash,
        BPF_MAP_TYPE_ARRAY => BpfMapKind::Array,
        BPF_MAP_TYPE_RINGBUF => BpfMapKind::RingBuf,
        _ => return err(ENOSYS),
    };
    let file = match BpfMapFile::new(kind, attr.key_size, attr.value_size, attr.max_entries) {
        Ok(file) => file,
        Err(e) => return err(e),
    };
    alloc_fd(Arc::new(file))
}

/// 处理 BPF_MAP_LOOKUP_ELEM：从用户空间读取 key，查找 map 后将 value 写回用户空间。
fn syscall_bpf_map_lookup_elem(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapElemAttr>() {
        return err(EINVAL);
    }
    // 读取参数结构体
    let attr = match copy_user_struct::<BpfMapElemAttr>(attr) {
        Ok(attr) => attr,
        Err(e) => return err(e),
    };
    // 解析对应fd为bpf map
    let Some(file) = current_files().lock().get_file(attr.map_fd as usize) else {
        return err(EBADF);
    };
    let Some(map) = file.as_any().downcast_ref::<BpfMapFile>() else {
        return err(EBADF);
    };

    // 根据结构体信息 读取对应的 key
    let token = get_current_token();
    let mut key = vec![0u8; map.key_size as usize];

    if try_copy_from_user(token, attr.key as *const u8, key.as_mut_slice()).is_err() {
        return err(EFAULT);
    }
    // 获取对应的 value
    let value = match map.lookup(key.as_slice()) {
        Ok(Some(value)) => value,
        Ok(None) => return err(ENOENT),
        Err(e) => return err(e),
    };
    if try_copy_to_user(token, attr.value as *mut u8, value.as_slice()).is_err() {
        return err(EFAULT);
    }
    0
}

/// 处理 BPF_MAP_UPDATE_ELEM：从用户空间读取 key/value 并按 flags 更新 map。
fn syscall_bpf_map_update_elem(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapElemAttr>() {
        return err(EINVAL);
    }
    let attr = match copy_user_struct::<BpfMapElemAttr>(attr) {
        Ok(attr) => attr,
        Err(e) => return err(e),
    };
    let Some(file) = current_files().lock().get_file(attr.map_fd as usize) else {
        return err(EBADF);
    };
    let Some(map) = file.as_any().downcast_ref::<BpfMapFile>() else {
        return err(EBADF);
    };
    let token = get_current_token();
    let mut key = vec![0u8; map.key_size as usize];
    let mut value = vec![0u8; map.value_size as usize];
    if try_copy_from_user(token, attr.key as *const u8, key.as_mut_slice()).is_err() {
        return err(EFAULT);
    }
    if try_copy_from_user(token, attr.value as *const u8, value.as_mut_slice()).is_err() {
        return err(EFAULT);
    }
    match map.update(key.as_slice(), value.as_slice(), attr.flags) {
        Ok(()) => 0,
        Err(e) => err(e),
    }
}

/// 处理 BPF_PROG_LOAD：拷贝指令、静态验证、收集 map 引用，成功则返回新 fd。
fn syscall_bpf_prog_load(attr_ptr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfProgLoadAttr>() {
        return err(EINVAL);
    }
    let attr = match copy_user_struct::<BpfProgLoadAttr>(attr_ptr) {
        Ok(attr) => attr,
        Err(e) => return err(e),
    };
    // 目前只支持 socket filter 程序类型。
    if attr.prog_type != BPF_PROG_TYPE_SOCKET_FILTER || attr.insn_cnt == 0 {
        write_verifier_log(&attr, "unsupported program type\n");
        return err(EINVAL);
    }
    if attr.insn_cnt > BPF_MAXINSNS {
        write_verifier_log(&attr, "program too large\n");
        return err(E2BIG);
    }
    // 拷贝指令
    let insns = match copy_user_insns(attr.insns as usize, attr.insn_cnt as usize) {
        Ok(insns) => insns,
        Err(e) => return err(e),
    };
    match verify_program(insns.as_slice()) {
        Ok(()) => {
            let maps = match collect_prog_map_refs(insns.as_slice()) {
                Ok(maps) => maps,
                Err(e) => return err(e),
            };
            alloc_fd(Arc::new(BpfProgFile::new(insns, maps)))
        }
        Err(msg) => {
            write_verifier_log(&attr, msg);
            err(EACCES)
        }
    }
}
