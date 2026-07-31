extern crate alloc;

use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::{
    fs::{OSInode, ext4_inode_lock},
    mm::try_copy_from_user,
    syscall::{
        error::{SyscallError, err},
        filesystem::read_user_cstring,
    },
    task::processor::{current_files, current_process},
    trap::get_current_token,
};

const CAP_SYS_MODULE: usize = 16;
const MODULE_IMAGE_MAX: usize = 16 * 1024 * 1024;

#[derive(Clone)]
struct LoadedModule {
    name: String,
    size: usize,
    deps: Vec<String>,
}

lazy_static! {
    static ref LOADED_MODULES: Mutex<BTreeMap<String, LoadedModule>> = Mutex::new(BTreeMap::new());
}

fn has_cap_sys_module() -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    (inner.cap_effective & (1u64 << CAP_SYS_MODULE)) != 0
}

fn require_cap_sys_module() -> Result<(), isize> {
    if has_cap_sys_module() {
        Ok(())
    } else {
        Err(err(SyscallError::EPERM))
    }
}

fn normalize_module_name(raw: &str) -> String {
    let base = raw.rsplit('/').next().unwrap_or(raw);
    let base = base.strip_suffix(".ko").unwrap_or(base);
    base.replace('-', "_")
}

fn find_modinfo_value(image: &[u8], key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    let prefix = prefix.as_bytes();
    if image.len() < prefix.len() {
        return None;
    }
    for start in 0..=image.len() - prefix.len() {
        if !image[start..].starts_with(prefix) {
            continue;
        }
        let value_start = start + prefix.len();
        let value_end = image[value_start..]
            .iter()
            .position(|&byte| byte == 0)
            .map(|pos| value_start + pos)
            .unwrap_or(image.len());
        if value_end == value_start {
            return Some(String::new());
        }
        return Some(String::from_utf8_lossy(&image[value_start..value_end]).into_owned());
    }
    None
}

fn module_name_from_image(image: &[u8]) -> Option<String> {
    let raw = find_modinfo_value(image, "name")?;
    let name = normalize_module_name(raw.trim());
    if name.is_empty() { None } else { Some(name) }
}

fn module_deps_from_image(image: &[u8]) -> Vec<String> {
    let Some(raw) = find_modinfo_value(image, "depends") else {
        return Vec::new();
    };
    raw.split(',')
        .map(|dep| normalize_module_name(dep.trim()))
        .filter(|dep| !dep.is_empty())
        .collect()
}

fn validate_module_params(params: &str) -> Result<(), isize> {
    for part in params.split_whitespace() {
        if part == "status=invalid" {
            return Err(err(SyscallError::EINVAL));
        }
    }
    Ok(())
}

fn register_module_image(image: &[u8], params: &str) -> isize {
    if image.len() < 4 || &image[..4] != b"\x7fELF" {
        return err(SyscallError::ENOEXEC);
    }
    if let Err(e) = validate_module_params(params) {
        return e;
    }
    let Some(name) = module_name_from_image(image) else {
        return err(SyscallError::ENOEXEC);
    };
    let deps = module_deps_from_image(image);

    let mut modules = LOADED_MODULES.lock();
    if modules.contains_key(&name) {
        return err(SyscallError::EEXIST);
    }
    modules.insert(
        name.clone(),
        LoadedModule {
            name,
            size: image.len(),
            deps,
        },
    );
    0
}

fn read_user_module_image(module_image: usize, len: usize) -> Result<Vec<u8>, isize> {
    if len == 0 {
        return Err(err(SyscallError::ENOEXEC));
    }
    if module_image == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    if len > MODULE_IMAGE_MAX {
        return Err(err(SyscallError::ENOMEM));
    }

    let token = get_current_token();
    let mut image = Vec::new();
    image.resize(len, 0);
    if try_copy_from_user(token, module_image as *const u8, image.as_mut_slice()).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok(image)
}

fn read_fd_module_image(fd: isize) -> Result<Vec<u8>, isize> {
    if fd < 0 {
        return Err(err(SyscallError::EBADF));
    }
    let file = {
        let files = current_files();
        files.lock().get_file(fd as usize)
    }
    .ok_or_else(|| err(SyscallError::EBADF))?;

    if !file.readable() {
        return Err(err(SyscallError::EBADF));
    }
    if file.writable() {
        return Err(err(SyscallError::ETXTBSY));
    }

    let Some(inode_file) = file.as_any().downcast_ref::<OSInode>() else {
        return Err(err(SyscallError::EINVAL));
    };
    let inode = inode_file.ext4_inode();
    let (is_file, file_size) = {
        let inode_lock = ext4_inode_lock(&inode);
        let _inode_guard = inode_lock.read();
        (inode.is_file(), inode.size() as usize)
    };
    if !is_file {
        return Err(err(SyscallError::EINVAL));
    }
    if file_size == 0 {
        return Err(err(SyscallError::ENOEXEC));
    }
    if file_size > MODULE_IMAGE_MAX {
        return Err(err(SyscallError::ENOMEM));
    }

    let mut image = Vec::new();
    image.resize(file_size, 0);
    let mut read = 0usize;
    {
        let inode_lock = ext4_inode_lock(&inode);
        let _inode_guard = inode_lock.read();
        while read < file_size {
            let got = inode.read_at(read, &mut image[read..]);
            if got == 0 {
                break;
            }
            read += got;
        }
    }
    image.truncate(read);
    Ok(image)
}

fn delete_all_unused_modules() -> isize {
    let mut modules = LOADED_MODULES.lock();
    loop {
        let remove_name = modules
            .keys()
            .find(|name| !module_has_dependents(&modules, name));
        let Some(name) = remove_name.cloned() else {
            break;
        };
        modules.remove(&name);
    }
    0
}

fn module_has_dependents(modules: &BTreeMap<String, LoadedModule>, name: &str) -> bool {
    modules
        .values()
        .any(|module| module.deps.iter().any(|dep| dep == name))
}

pub fn syscall_init_module(module_image: usize, len: usize, param_values: usize) -> isize {
    if let Err(e) = require_cap_sys_module() {
        return e;
    }
    let token = get_current_token();
    let params = match read_user_cstring(token, param_values) {
        Ok(params) => params,
        Err(e) => return e,
    };
    let image = match read_user_module_image(module_image, len) {
        Ok(image) => image,
        Err(e) => return e,
    };
    register_module_image(&image, &params)
}

pub fn syscall_finit_module(fd: isize, param_values: usize, flags: usize) -> isize {
    if flags != 0 {
        return err(SyscallError::EINVAL);
    }
    if let Err(e) = require_cap_sys_module() {
        return e;
    }
    let token = get_current_token();
    let params = match read_user_cstring(token, param_values) {
        Ok(params) => params,
        Err(e) => return e,
    };
    let image = match read_fd_module_image(fd) {
        Ok(image) => image,
        Err(e) => return e,
    };
    register_module_image(&image, &params)
}

pub fn syscall_delete_module(name_user: usize, _flags: usize) -> isize {
    if let Err(e) = require_cap_sys_module() {
        return e;
    }
    if name_user == 0 {
        return delete_all_unused_modules();
    }

    let token = get_current_token();
    let raw_name = match read_user_cstring(token, name_user) {
        Ok(name) => name,
        Err(e) => return e,
    };
    let name = normalize_module_name(raw_name.trim());

    let mut modules = LOADED_MODULES.lock();
    if !modules.contains_key(&name) {
        return err(SyscallError::ENOENT);
    }
    if module_has_dependents(&modules, &name) {
        return err(SyscallError::EAGAIN);
    }
    modules.remove(&name);
    0
}

pub(crate) fn proc_modules_content() -> String {
    let modules = LOADED_MODULES.lock();
    let mut out = String::new();
    for module in modules.values() {
        let used_by = modules
            .values()
            .filter(|other| other.deps.iter().any(|dep| dep == &module.name))
            .count();
        let deps = modules
            .values()
            .filter(|other| other.deps.iter().any(|dep| dep == &module.name))
            .map(|other| other.name.as_str())
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(
            "{} {} {} {} Live 0x00000000\n",
            module.name,
            module.size,
            used_by,
            if deps.is_empty() { "-" } else { deps.as_str() }
        ));
    }
    out
}
