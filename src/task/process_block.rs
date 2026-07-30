use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::mutex::Mutex;
use crate::arch::{REG_A0, REG_A1, REG_A2, REG_A3};
use crate::config::{MAX_HARTS, PAGE_SIZE, TRAP_CONTEXT_BASE, USER_STACK_SIZE};
use crate::debug_config::{DEBUG_EXEC, DEBUG_FUTEX, DEBUG_LOONGARCH_FULL_COPY_FORK, DEBUG_SYSCALL};
use crate::fs::{
    MountNamespace, PollWaitQueue, cgroup_attach_fork_child, clone_mount_namespace,
    initial_mount_namespace, mount_namespace_id,
};
use crate::mm::{
    ElfAux, KERNEL_SPACE, MemorySet, MmRef, read_user_value, translated_mutref, write_user_value,
};
use crate::println;
use crate::task::FilesStruct;
use crate::task::condvar::Condvar;
use crate::task::id::{PidAllocError, PidHandle, pid_alloc};
use crate::task::manager::{
    PID2PCB, add_task, insert_into_pid2process, prime_fair_exec_start, release_process_mm_owner,
    remove_inactive_task, select_hart_for_new_task, wakeup_task,
};
use crate::task::processor::current_task;
use crate::task::sched::{SCHED_DEADLINE, SCHED_FIFO, SCHED_OTHER, SCHED_RR};
use crate::task::semaphore::Semaphore;
use crate::task::signal::{
    RT_SIG_MAX, RtSigAction, SIG_IGN, SIGCHLD_NUM, SignalAction, SignalActions, SignalFlags,
};
use crate::task::task_block::{TaskAllocError, TaskControlBlock};
use crate::trap::context::TrapContext;
use crate::trap::trap_handler;
use crate::utils::RecycleAllocator;
use lazy_static::lazy_static;
use spin::{Mutex as SpinMutex, MutexGuard, RwLock};

const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;
static FORK_IMPL_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);
static FORK_PRE_COW_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);
static NEXT_IPC_NS_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_USER_NS_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_PID_NS_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_NET_NS_ID: AtomicUsize = AtomicUsize::new(1);

/// Reason why `fork_impl()` failed.
#[derive(Debug)]
pub enum ForkError {
    /// All PIDs in the PID space are in use.
    PidExhausted,
    /// RLIMIT_NPROC would be exceeded (not yet enforced).
    RlimitNprocExceeded,
    /// cgroup pids.max would be exceeded.
    CgroupPidsMaxExceeded,
    /// Kernel-stack frame allocation failed (OOM).
    KernelStackOom,
    /// Mapping the child's trap-context page failed (OOM).
    TrapCxAllocFailed,
    /// Cloning the parent address space failed (OOM).
    VmCloneOom,
}

impl From<PidAllocError> for ForkError {
    fn from(e: PidAllocError) -> Self {
        match e {
            PidAllocError::Exhausted => ForkError::PidExhausted,
        }
    }
}

impl From<TaskAllocError> for ForkError {
    fn from(e: TaskAllocError) -> Self {
        match e {
            TaskAllocError::TrapCxAllocFailed => ForkError::TrapCxAllocFailed,
            TaskAllocError::KernelStackOom => ForkError::KernelStackOom,
        }
    }
}

pub fn alloc_ipc_namespace_id() -> usize {
    NEXT_IPC_NS_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn alloc_user_namespace_id() -> usize {
    NEXT_USER_NS_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn alloc_pid_namespace_id() -> usize {
    NEXT_PID_NS_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn alloc_net_namespace_id() -> usize {
    NEXT_NET_NS_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn register_pid_namespace(parent_ns_id: usize, child_ns_id: usize) {
    if child_ns_id == 0 {
        return;
    }
    PID_NAMESPACE_PARENTS
        .write()
        .insert(child_ns_id, parent_ns_id);
}

pub fn pid_namespace_parent(namespace_id: usize) -> Option<usize> {
    if namespace_id == 0 {
        return None;
    }
    PID_NAMESPACE_PARENTS.read().get(&namespace_id).copied()
}

pub fn register_pid_namespace_reaper(namespace_id: usize, reaper_pid: usize) {
    PID_NAMESPACE_REAPERS
        .write()
        .insert(namespace_id, reaper_pid);
}

pub fn unregister_pid_namespace_reaper(namespace_id: usize, reaper_pid: usize) {
    let mut reapers = PID_NAMESPACE_REAPERS.write();
    if reapers
        .get(&namespace_id)
        .is_some_and(|registered| *registered == reaper_pid)
    {
        reapers.remove(&namespace_id);
    }
}

pub fn unregister_pid_namespace_reaper_for_process(process: &ProcessControlBlock) {
    let (namespace_id, is_namespace_init) = {
        let inner = process.borrow_mut();
        (inner.pid_ns_id, inner.pid_ns_init)
    };
    if is_namespace_init {
        unregister_pid_namespace_reaper(namespace_id, process.getpid());
    }
}

pub fn pid_namespace_reaper(namespace_id: usize) -> Option<Arc<ProcessControlBlock>> {
    let reaper_pid = PID_NAMESPACE_REAPERS.read().get(&namespace_id).copied()?;
    let map = PID2PCB.lock();
    map.get(&reaper_pid).map(Arc::clone)
}

pub fn pid_namespace_descends_from(ns_id: usize, ancestor_ns_id: usize) -> bool {
    if ancestor_ns_id == 0 {
        return true;
    }
    if ns_id == ancestor_ns_id {
        return true;
    }
    let parents = PID_NAMESPACE_PARENTS.read();
    let mut current = ns_id;
    while current != 0 {
        let Some(parent) = parents.get(&current).copied() else {
            break;
        };
        if parent == ancestor_ns_id {
            return true;
        }
        current = parent;
    }
    false
}

pub fn process_visible_in_pid_namespace(
    process: &Arc<ProcessControlBlock>,
    namespace_id: usize,
) -> bool {
    if namespace_id == 0 {
        return true;
    }
    pid_namespace_descends_from(process.pid_namespace_id(), namespace_id)
}

pub fn resolve_process_in_pid_namespace(
    namespace_id: usize,
    pid: usize,
) -> Option<Arc<ProcessControlBlock>> {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    if namespace_id == 0 {
        return processes
            .into_iter()
            .find(|process| process.getpid() == pid);
    }
    for process in processes {
        if process.pid_namespace_id() != namespace_id {
            continue;
        }
        if process.visible_pid() == pid {
            return Some(process);
        }
    }
    None
}

pub fn pid_namespace_member_pids(namespace_id: usize) -> Vec<usize> {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    processes
        .into_iter()
        .filter(|process| process_visible_in_pid_namespace(process, namespace_id))
        .map(|process| process.getpid())
        .collect()
}

#[derive(Clone, Copy)]
pub struct UtsNamespaceState {
    pub nodename: [u8; 65],
    pub domainname: [u8; 65],
}

impl UtsNamespaceState {
    pub fn new() -> Self {
        let mut state = Self {
            nodename: [0; 65],
            domainname: [0; 65],
        };
        Self::write_name_field(&mut state.nodename, b"localhost");
        Self::write_name_field(&mut state.domainname, b"localdomain");
        state
    }

    fn write_name_field(dst: &mut [u8; 65], src: &[u8]) {
        dst.fill(0);
        let n = src.len().min(64);
        dst[..n].copy_from_slice(&src[..n]);
    }
}

pub(crate) fn remove_task_from_wait_queues(task: &Arc<TaskControlBlock>) {
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };

    for process in processes {
        let tasks = process.tasks_snapshot();
        for holder in tasks {
            if Arc::ptr_eq(&holder, task) {
                continue;
            }
            if let Some(mut holder_inner) = holder.try_borrow_mut() {
                holder_inner.join_waiters.retain(|w| !Arc::ptr_eq(w, task));
            }
        }
        let Some(mut inner) = process.try_borrow_mut() else {
            continue;
        };
        inner.wait_queue.retain(|t| !Arc::ptr_eq(t, task));
        inner.vfork_wait_queue.retain(|t| !Arc::ptr_eq(t, task));

        for mutex in inner.mutex_list.iter().filter_map(|m| m.as_ref()) {
            let _ = mutex.remove_waiter(task);
        }

        for sem in inner.semaphore_list.iter().filter_map(|s| s.as_ref()) {
            sem.inner
                .lock()
                .wait_queue
                .retain(|w| !Arc::ptr_eq(w, task));
        }

        for condvar in inner.condvar_list.iter().filter_map(|c| c.as_ref()) {
            condvar
                .inner
                .lock()
                .wait_queue
                .retain(|w| !Arc::ptr_eq(w, task));
        }
    }

    let _ = crate::fs::remove_pipe_waiters_for_task(task);
}

fn fork_diag_cycles_to_us(delta_cycles: usize) -> usize {
    let freq = crate::config::clock_freq() as u128;
    if freq == 0 {
        0
    } else {
        ((delta_cycles as u128).saturating_mul(1_000_000) / freq) as usize
    }
}

fn should_report_fork_impl_diag(seq: usize, total_us: usize) -> bool {
    seq <= 16 || seq % 128 == 0 || total_us >= 50_000
}

fn process_comm_from_name(name: &str) -> String {
    let src = name.rsplit('/').next().unwrap_or(name);
    let mut out = String::new();
    for b in src.as_bytes().iter().copied().take(15) {
        if b == 0 {
            break;
        }
        out.push(b as char);
    }
    if out.is_empty() {
        String::from("CongCore")
    } else {
        out
    }
}

fn process_comm_from_argv(argv: &[String]) -> String {
    let src = argv.first().map(|s| s.as_str()).unwrap_or("CongCore");
    process_comm_from_name(src)
}

lazy_static! {
    /// child pid namespace id -> parent pid namespace id.
    static ref PID_NAMESPACE_PARENTS: RwLock<BTreeMap<usize, usize>> =
        RwLock::new(BTreeMap::new());
    /// pid namespace id -> namespace init/reaper global pid.
    static ref PID_NAMESPACE_REAPERS: RwLock<BTreeMap<usize, usize>> =
        RwLock::new(BTreeMap::new());
}

fn reset_signal_handlers_on_exec(signal: &mut ProcessSignalState) {
    for (signum, action) in signal.rt_sig_handlers.iter_mut().enumerate() {
        if signum == 0 {
            continue;
        }
        if action.handler != SIG_IGN {
            *action = RtSigAction::default();
        }
    }
    for (signum, action) in signal.signals_actions.table.iter_mut().enumerate() {
        if signum == 0 {
            continue;
        }
        if action.handler != SIG_IGN {
            *action = SignalAction::default();
        }
    }
}

fn patch_glibc_ld_linux_symtab_dyn(token: usize, interp_base: usize, interp_data: &[u8]) {
    // Workaround for early ld-linux crash on some setups: glibc's rtld expects a
    // non-null DT_SYMTAB dynamic entry pointer cached in `_rtld_global`.
    //
    // The crashing instruction sequence is:
    //   ld a3, -1248(s10)   # a3 == 0
    //   ld a6, 8(a3)        # deref NULL -> stval=0x8
    //
    // For the tested riscv64 glibc ld.so build, this cache lives at:
    //   _rtld_global + 0xb20 == 0x21b70 (relative to interpreter base).
    //
    // We only apply this patch when we positively identify the interpreter SONAME.
    const DT_NULL: u64 = 0;
    const DT_STRTAB: u64 = 5;
    const DT_SYMTAB: u64 = 6;
    const DT_STRSZ: u64 = 10;
    const DT_SONAME: u64 = 14;

    if DEBUG_SYSCALL {
        crate::println!(
            "[exec_dyn] try patch ld-linux: base={:#x} len={}",
            interp_base,
            interp_data.len()
        );
    }

    let elf = match xmas_elf::ElfFile::new(interp_data) {
        Ok(e) => e,
        Err(_) => {
            if DEBUG_SYSCALL {
                crate::println!("[exec_dyn] patch ld-linux: invalid ELF");
            }
            return;
        }
    };

    // Prefer PT_DYNAMIC, but fall back to the .dynamic section if parsing fails.
    let mut dyn_off: Option<usize> = None;
    let mut dyn_vaddr: Option<usize> = None;
    let mut dyn_size: Option<usize> = None;
    let ph_count = elf.header.pt2.ph_count();
    for i in 0..ph_count {
        let Ok(ph) = elf.program_header(i) else {
            continue;
        };
        if ph.get_type() == Ok(xmas_elf::program::Type::Dynamic) {
            dyn_off = Some(ph.offset() as usize);
            dyn_vaddr = Some(ph.virtual_addr() as usize);
            dyn_size = Some(ph.file_size() as usize);
            break;
        }
    }
    if DEBUG_SYSCALL {
        crate::println!(
            "[exec_dyn] patch ld-linux: PT_DYNAMIC off={:?} vaddr={:?} size={:?}",
            dyn_off,
            dyn_vaddr,
            dyn_size
        );
    }

    let mut dyn_bytes: Option<&[u8]> = None;
    if let (Some(off), Some(size)) = (dyn_off, dyn_size) {
        if size != 0 && off.saturating_add(size) <= interp_data.len() {
            dyn_bytes = Some(&interp_data[off..off + size]);
        }
    }
    let mut dyn_vaddr_final = dyn_vaddr;

    // If PT_DYNAMIC isn't present/usable, fall back to section header.
    if dyn_bytes.is_none() || dyn_vaddr_final.is_none() {
        if let Some(sec) = elf.find_section_by_name(".dynamic") {
            dyn_bytes = Some(sec.raw_data(&elf));
            dyn_vaddr_final = Some(sec.address() as usize);
            if DEBUG_SYSCALL {
                crate::println!(
                    "[exec_dyn] patch ld-linux: use .dynamic section vaddr={:#x} size={:#x}",
                    sec.address(),
                    sec.size()
                );
            }
        }
    }

    let (Some(dyn_bytes), Some(dyn_vaddr)) = (dyn_bytes, dyn_vaddr_final) else {
        if DEBUG_SYSCALL {
            crate::println!("[exec_dyn] patch ld-linux: no dynamic table bytes");
        }
        return;
    };

    let mut strtab_vaddr = None;
    let mut strsz = None;
    let mut soname_off = None;
    let mut symtab_dyn_index = None;
    for (idx, chunk) in dyn_bytes.chunks_exact(16).enumerate() {
        let tag = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let val = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_STRTAB => strtab_vaddr = Some(val as usize),
            DT_STRSZ => strsz = Some(val as usize),
            DT_SONAME => soname_off = Some(val as usize),
            DT_SYMTAB => symtab_dyn_index = Some(idx),
            _ => {}
        }
    }

    let (Some(strtab_vaddr), Some(strsz), Some(soname_off), Some(symtab_dyn_index)) =
        (strtab_vaddr, strsz, soname_off, symtab_dyn_index)
    else {
        if DEBUG_SYSCALL {
            if dyn_bytes.len() >= 16 {
                let tag0 = u64::from_le_bytes(dyn_bytes[0..8].try_into().unwrap());
                let val0 = u64::from_le_bytes(dyn_bytes[8..16].try_into().unwrap());
                crate::println!(
                    "[exec_dyn] patch ld-linux: dyn[0] tag={:#x} val={:#x}",
                    tag0,
                    val0
                );
            }
            crate::println!(
                "[exec_dyn] patch ld-linux: missing tags strtab={:?} strsz={:?} soname={:?} symtab_idx={:?}",
                strtab_vaddr,
                strsz,
                soname_off,
                symtab_dyn_index
            );
        }
        return;
    };

    // ld-linux's STRTAB is in the first PT_LOAD with p_offset==p_vaddr==0, so vaddr==file offset.
    if strtab_vaddr.saturating_add(strsz) > interp_data.len() || soname_off >= strsz {
        if DEBUG_SYSCALL {
            crate::println!(
                "[exec_dyn] patch ld-linux: bad strtab vaddr={:#x} strsz={:#x} soname_off={:#x}",
                strtab_vaddr,
                strsz,
                soname_off
            );
        }
        return;
    }
    let strtab = &interp_data[strtab_vaddr..strtab_vaddr + strsz];
    let mut end = soname_off;
    while end < strtab.len() && strtab[end] != 0 {
        end += 1;
    }
    let Ok(soname) = core::str::from_utf8(&strtab[soname_off..end]) else {
        if DEBUG_SYSCALL {
            crate::println!("[exec_dyn] patch ld-linux: SONAME not utf8");
        }
        return;
    };
    if DEBUG_SYSCALL {
        crate::println!(
            "[exec_dyn] patch ld-linux: SONAME='{}' dyn_vaddr={:#x} symtab_dyn_idx={}",
            soname,
            dyn_vaddr,
            symtab_dyn_index
        );
    }
    if soname != "ld-linux-riscv64-lp64d.so.1" {
        if DEBUG_SYSCALL {
            crate::println!("[exec_dyn] patch ld-linux: skip (not glibc ld-linux)");
        }
        return;
    }

    let symtab_dyn_ptr = interp_base + dyn_vaddr + symtab_dyn_index * 16;
    let rtld_global_symtab_slot = interp_base + 0x21b70;
    write_user_value(
        token,
        rtld_global_symtab_slot as *mut usize,
        &symtab_dyn_ptr,
    );
    let verify = read_user_value(token, rtld_global_symtab_slot as *const usize);

    if DEBUG_SYSCALL {
        crate::println!(
            "[exec_dyn] patched ld-linux DT_SYMTAB dyn*={:#x} into _rtld_global+0xb20 ({:#x}), verify={:#x}",
            symtab_dyn_ptr,
            rtld_global_symtab_slot,
            verify
        );
    }
}

const AT_NULL: usize = 0;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;
const AT_PAGESZ: usize = 6;
const AT_BASE: usize = 7;
const AT_ENTRY: usize = 9;
const AT_UID: usize = 11;
const AT_EUID: usize = 12;
const AT_GID: usize = 13;
const AT_EGID: usize = 14;
const AT_PLATFORM: usize = 15;
const AT_HWCAP: usize = 16;
const AT_CLKTCK: usize = 17;
const AT_FLAGS: usize = 8;
const AT_SECURE: usize = 23;
const AT_BASE_PLATFORM: usize = 24;
const AT_RANDOM: usize = 25;
const AT_HWCAP2: usize = 26;
const AT_EXECFN: usize = 31;

/// 按 Linux ELF ABI 构造新程序的初始用户栈。
///
/// 返回值依次为 `(sp, argv_base, envp_base, auxv_base)`，调用方会把它们放入
/// trap context 的 a0-a3，供新程序或动态链接器启动时读取。栈内容从低地址到
/// 高地址为：argc、argv 指针数组、envp 指针数组、auxv 表、字符串和随机数据。
fn build_linux_stack(
    token: usize,
    mut sp: usize,
    args: &[String],
    envs: &[String],
    elf_aux: crate::mm::ElfAux,
    at_entry: usize,
    at_base: usize,
) -> (usize, usize, usize, usize) {
    #[cfg(target_arch = "loongarch64")]
    {
        // LoongArch 的字符串对齐和入口寄存器约定与 RISC-V 略有差异，单独实现。
        return build_linux_stack_loongarch(token, sp, args, envs, elf_aux, at_entry, at_base);
    }
    #[cfg(not(target_arch = "loongarch64"))]
    {
        // 下面是 RISC-V 等通用 64 位路径。所有写入都发生在新地址空间 token 下。
        fn write_bytes(token: usize, addr: usize, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                *translated_mutref(token, (addr + i) as *mut u8) = *b;
            }
        }

        // 栈向低地址增长，压入一个 usize 后更新 sp。
        fn push_usize(token: usize, sp: &mut usize, value: usize) {
            *sp -= core::mem::size_of::<usize>();
            write_user_value(token, *sp as *mut usize, &value);
        }

        let argc = args.len();
        let envc = envs.len();

        // 先把 argv/env 字符串拷到栈顶区域，并记录每个字符串的用户态地址。
        let mut arg_ptrs: Vec<usize> = Vec::with_capacity(argc);
        for arg in args.iter().rev() {
            let bytes = arg.as_bytes();
            sp -= bytes.len() + 1;
            write_bytes(token, sp, bytes);
            *translated_mutref(token, (sp + bytes.len()) as *mut u8) = 0;
            arg_ptrs.push(sp);
        }
        arg_ptrs.reverse();

        let mut env_ptrs: Vec<usize> = Vec::with_capacity(envc);
        for env in envs.iter().rev() {
            let bytes = env.as_bytes();
            sp -= bytes.len() + 1;
            write_bytes(token, sp, bytes);
            *translated_mutref(token, (sp + bytes.len()) as *mut u8) = 0;
            env_ptrs.push(sp);
        }
        env_ptrs.reverse();

        // AT_PLATFORM: a small string describing the CPU architecture.
        // Keep consistent with the userland ABI expectations per-arch.
        #[cfg(target_arch = "loongarch64")]
        let platform = "loongarch64";
        #[cfg(not(target_arch = "loongarch64"))]
        let platform = "RISC-V64";
        sp -= platform.len() + 1;
        write_bytes(token, sp, platform.as_bytes());
        *translated_mutref(token, (sp + platform.len()) as *mut u8) = 0;
        let platform_ptr = sp;

        // AT_EXECFN: filename of the executed program.
        // Best-effort: use argv[0] (should match the execve path in most cases).
        let execfn = args.first().map(|s| s.as_str()).unwrap_or("");
        if !execfn.is_empty() {
            sp -= execfn.len() + 1;
            write_bytes(token, sp, execfn.as_bytes());
            *translated_mutref(token, (sp + execfn.len()) as *mut u8) = 0;
        }
        let execfn_ptr = sp;

        // AT_RANDOM: 16 bytes.
        sp -= 16;
        let random_ptr = sp;
        let mut x = (at_entry as u64) ^ (sp as u64).rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
        for i in 0..16usize {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            *translated_mutref(token, (random_ptr + i) as *mut u8) = (x >> 56) as u8;
        }

        let mut auxv: Vec<(usize, usize)> = vec![
            (AT_HWCAP, 0),
            (AT_HWCAP2, 0),
            (AT_PHDR, elf_aux.phdr),
            (AT_PHENT, elf_aux.phent),
            (AT_PHNUM, elf_aux.phnum),
            (AT_PAGESZ, crate::config::PAGE_SIZE),
            (AT_ENTRY, at_entry),
            (AT_FLAGS, 0),
            (AT_CLKTCK, 100),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
            (AT_SECURE, 0),
            (AT_PLATFORM, platform_ptr),
            (AT_BASE_PLATFORM, platform_ptr),
            (AT_EXECFN, execfn_ptr),
            (AT_RANDOM, random_ptr),
        ];
        // We do not provide a VDSO (AT_SYSINFO_EHDR). glibc should fall back to syscalls.
        if at_base != 0 {
            // 动态链接程序通过 AT_BASE 得知解释器自身的加载基址；静态 ELF 为 0。
            auxv.push((AT_BASE, at_base));
        }

        // 入口栈指针需要 16 字节对齐。下面先按将要压入的 word 数预留一次
        // 对齐填充，避免最终 sp 因奇数个 usize 破坏 ABI 对齐要求。
        let aux_words = (auxv.len() + 1) * 2; // + AT_NULL
        let envp_words = envc + 1; // NULL-terminated
        let argv_words = argc + 1; // NULL-terminated
        let total_words = aux_words + envp_words + argv_words + 1; // + argc
        sp &= !0xf;
        if total_words % 2 == 1 {
            sp -= core::mem::size_of::<usize>();
        }

        // auxv 按 (type, value) 成对存放，以 AT_NULL 结束。
        push_usize(token, &mut sp, 0);
        push_usize(token, &mut sp, AT_NULL);
        for (t, v) in auxv.iter().rev() {
            push_usize(token, &mut sp, *v);
            push_usize(token, &mut sp, *t);
        }
        let auxv_base = sp;

        // envp 指针数组，末尾以 NULL 结束。
        push_usize(token, &mut sp, 0);
        for p in env_ptrs.iter().rev() {
            push_usize(token, &mut sp, *p);
        }
        let envp_base = sp;

        // argv 指针数组，末尾以 NULL 结束。
        push_usize(token, &mut sp, 0);
        for p in arg_ptrs.iter().rev() {
            push_usize(token, &mut sp, *p);
        }
        let argv_base = sp;

        // 最低地址处放 argc，动态链接器和 libc 从这里开始解析整个初始栈。
        push_usize(token, &mut sp, argc);

        (sp, argv_base, envp_base, auxv_base)
    }
}

#[cfg(target_arch = "loongarch64")]
fn build_linux_stack_loongarch(
    token: usize,
    mut sp: usize,
    args: &[String],
    envs: &[String],
    elf_aux: crate::mm::ElfAux,
    at_entry: usize,
    at_base: usize,
) -> (usize, usize, usize, usize) {
    fn write_bytes(token: usize, addr: usize, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            *translated_mutref(token, (addr + i) as *mut u8) = *b;
        }
    }

    fn push_usize(token: usize, sp: &mut usize, value: usize) {
        *sp -= core::mem::size_of::<usize>();
        write_user_value(token, *sp as *mut usize, &value);
    }

    fn align_down(value: usize, align: usize) -> usize {
        value & !(align - 1)
    }

    let argc = args.len();
    let envc = envs.len();

    let mut env_ptrs: Vec<usize> = Vec::with_capacity(envc);
    for env in envs.iter().rev() {
        let bytes = env.as_bytes();
        sp -= bytes.len() + 1;
        sp = align_down(sp, core::mem::size_of::<usize>());
        write_bytes(token, sp, bytes);
        *translated_mutref(token, (sp + bytes.len()) as *mut u8) = 0;
        env_ptrs.push(sp);
    }
    env_ptrs.reverse();

    let mut arg_ptrs: Vec<usize> = Vec::with_capacity(argc);
    for arg in args.iter().rev() {
        let bytes = arg.as_bytes();
        sp -= bytes.len() + 1;
        sp = align_down(sp, core::mem::size_of::<usize>());
        write_bytes(token, sp, bytes);
        *translated_mutref(token, (sp + bytes.len()) as *mut u8) = 0;
        arg_ptrs.push(sp);
    }
    arg_ptrs.reverse();

    let platform = "loongarch64";
    sp -= platform.len() + 1;
    sp = align_down(sp, core::mem::size_of::<usize>());
    write_bytes(token, sp, platform.as_bytes());
    *translated_mutref(token, (sp + platform.len()) as *mut u8) = 0;
    let platform_ptr = sp;

    // AT_RANDOM: 16 bytes.
    sp -= 16;
    let random_ptr = sp;
    let mut x = (at_entry as u64) ^ (sp as u64).rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
    for i in 0..16usize {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        *translated_mutref(token, (random_ptr + i) as *mut u8) = (x >> 56) as u8;
    }

    // Align stack to 16 bytes.
    sp = align_down(sp, 16);

    let mut auxv: Vec<(usize, usize)> = vec![
        (AT_HWCAP, 0),
        (AT_HWCAP2, 0),
        (AT_PHDR, elf_aux.phdr),
        (AT_PHENT, elf_aux.phent),
        (AT_PHNUM, elf_aux.phnum),
        (AT_PAGESZ, crate::config::PAGE_SIZE),
        (AT_ENTRY, at_entry),
        (AT_FLAGS, 0),
        (AT_CLKTCK, 100),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_PLATFORM, platform_ptr),
        (AT_BASE_PLATFORM, platform_ptr),
        (AT_RANDOM, random_ptr),
    ];
    if let Some(execfn_ptr) = arg_ptrs.first().copied() {
        auxv.push((AT_EXECFN, execfn_ptr));
    }
    if at_base != 0 {
        auxv.push((AT_BASE, at_base));
    }

    push_usize(token, &mut sp, 0);
    push_usize(token, &mut sp, AT_NULL);
    for (t, v) in auxv.iter().rev() {
        push_usize(token, &mut sp, *v);
        push_usize(token, &mut sp, *t);
    }
    let auxv_base = sp;

    push_usize(token, &mut sp, 0);
    for p in env_ptrs.iter().rev() {
        push_usize(token, &mut sp, *p);
    }
    let envp_base = sp;

    push_usize(token, &mut sp, 0);
    for p in arg_ptrs.iter().rev() {
        push_usize(token, &mut sp, *p);
    }
    let argv_base = sp;

    push_usize(token, &mut sp, argc);

    (sp, argv_base, envp_base, auxv_base)
}

/// 调试用：按 Linux 初始栈布局打印 exec 后的 argc/argv 和关键 auxv 项。
///
/// 该函数只在 `DEBUG_SYSCALL` 或 `DEBUG_EXEC` 打开时工作，用于排查
/// glibc/ld-linux 启动阶段的问题。它只做 best-effort 读取，不参与
/// exec 语义，也不修改用户栈。
fn dump_linux_initial_stack(token: usize, sp: usize) {
    if !(DEBUG_SYSCALL || DEBUG_EXEC) {
        return;
    }
    // Linux 初始栈从低地址开始依次是 argc、argv 指针数组、envp 指针数组、
    // auxv 表；argv/env 字符串和 AT_* 指向的数据放在更高地址区域。
    let argc = read_user_value(token, sp as *const usize);
    let argv0_ptr = read_user_value(token, (sp + core::mem::size_of::<usize>()) as *const usize);
    let mut argv0 = alloc::string::String::new();
    if argv0_ptr != 0 {
        // 只读前 64 字节，避免调试输出因异常字符串或缺少 NUL 结束符无限扩张。
        for i in 0..64usize {
            let ch = *translated_mutref(token, (argv0_ptr + i) as *mut u8);
            if ch == 0 {
                break;
            }
            argv0.push(ch as char);
        }
    }
    crate::println!(
        "[exec_dyn] initial_stack sp={:#x} argc={} argv0_ptr={:#x} argv0='{}'",
        sp,
        argc,
        argv0_ptr,
        argv0
    );
    // 打印前 16 个 argv，足够定位 exec 参数布局问题，同时避免日志过大。
    for idx in 0..argc.min(16) {
        let ptr = read_user_value(
            token,
            (sp + (idx + 1) * core::mem::size_of::<usize>()) as *const usize,
        );
        let mut arg = alloc::string::String::new();
        if ptr != 0 {
            // 每个参数同样限制 128 字节，调试函数不能让日志量由用户输入放大。
            for i in 0..128usize {
                let ch = *translated_mutref(token, (ptr + i) as *mut u8);
                if ch == 0 {
                    break;
                }
                arg.push(ch as char);
            }
        }
        crate::println!("[exec_dyn] argv[{}]='{}'", idx, arg);
    }

    // 跳过 argv 指针数组及其 NULL 结束项，继续跳过 envp，最终定位 auxv 起点。
    let argv_base = sp + core::mem::size_of::<usize>();
    let mut p = argv_base + (argc + 1) * core::mem::size_of::<usize>(); // skip argv + NULL
    // envp 以 NULL 指针结束；设置 256 的上限是为了防止坏栈导致无限扫描。
    for _ in 0..256usize {
        let v = read_user_value(token, p as *const usize);
        p += core::mem::size_of::<usize>();
        if v == 0 {
            break;
        }
    }
    // auxv 是 (type, value) 成对存放，以 AT_NULL 结束；只打印动态链接器
    // 启动时最关键的几项，便于核对 PHDR/ENTRY/BASE/RANDOM 等值。
    let mut aux_p = p;
    for _ in 0..64usize {
        let t = read_user_value(token, aux_p as *const usize);
        let v = read_user_value(
            token,
            (aux_p + core::mem::size_of::<usize>()) as *const usize,
        );
        aux_p += 2 * core::mem::size_of::<usize>();
        if t == AT_NULL {
            break;
        }
        if matches!(
            t,
            AT_PHDR
                | AT_PHENT
                | AT_PHNUM
                | AT_PAGESZ
                | AT_BASE
                | AT_ENTRY
                | AT_PLATFORM
                | AT_EXECFN
                | AT_RANDOM
                | AT_HWCAP
        ) {
            crate::println!("[exec_dyn] auxv type={} val={:#x}", t, v);
        }
    }
}
/// All POSIX resource limits (`getrlimit`/`setrlimit`) plus CPU-limit tracking state.
#[derive(Clone)]
pub struct ProcessResourceLimits {
    pub rlimit_nofile_cur: u64,
    pub rlimit_nofile_max: u64,
    pub rlimit_nproc_cur: u64,
    pub rlimit_nproc_max: u64,
    pub rlimit_fsize_cur: u64,
    pub rlimit_fsize_max: u64,
    pub rlimit_data_cur: u64,
    pub rlimit_data_max: u64,
    pub rlimit_stack_cur: u64,
    pub rlimit_stack_max: u64,
    pub rlimit_cpu_cur: u64,
    pub rlimit_cpu_max: u64,
    /// Wall-clock ms at which the current RLIMIT_CPU interval started.
    pub rlimit_cpu_start_ms: usize,
    /// True after SIGXCPU has been sent for the soft CPU limit.
    pub rlimit_cpu_soft_sent: bool,
    pub rlimit_core_cur: u64,
    pub rlimit_core_max: u64,
    pub rlimit_rss_cur: u64,
    pub rlimit_rss_max: u64,
    pub rlimit_memlock_cur: u64,
    pub rlimit_memlock_max: u64,
    pub rlimit_as_cur: u64,
    pub rlimit_as_max: u64,
    pub rlimit_locks_cur: u64,
    pub rlimit_locks_max: u64,
    pub rlimit_msgqueue_cur: u64,
    pub rlimit_msgqueue_max: u64,
    pub rlimit_nice_cur: u64,
    pub rlimit_nice_max: u64,
    pub rlimit_rtprio_cur: u64,
    pub rlimit_rtprio_max: u64,
    pub rlimit_sigpending_cur: u64,
    pub rlimit_sigpending_max: u64,
    pub rlimit_rttime_cur: u64,
    pub rlimit_rttime_max: u64,
}

/// Linux 风格调度参数：调度策略、RT 优先级、deadline 属性、nice 和 CPU 亲和性。
#[derive(Clone)]
pub struct ProcessScheduling {
    /// 调度策略，对应 Linux `SCHED_OTHER`/`SCHED_FIFO`/`SCHED_RR` 等。
    pub sched_policy: i32,
    /// CPU 亲和性掩码，供 `sched_*affinity` 和 `getcpu` 使用。
    ///
    /// 对 PCB 来说这是新建 task 继承的默认值；实际运行时的 per-task 值保存在 TCB 中。
    pub cpu_affinity_mask: usize,
    /// 实时调度优先级；普通 fair 调度策略下通常为 0。
    pub sched_priority: i32,
    /// `SCHED_DEADLINE` 的运行时间参数。
    pub sched_runtime: u64,
    /// `SCHED_DEADLINE` 的相对截止时间参数。
    pub sched_deadline: u64,
    /// `SCHED_DEADLINE` 的周期参数。
    pub sched_period: u64,
    /// POSIX nice 值，供 getpriority/setpriority 使用。
    pub nice: i32,
    /// Linux SCHED_RESET_ON_FORK / SCHED_FLAG_RESET_ON_FORK 状态。
    pub reset_on_fork: bool,
}

// TODO(credentials): ProcessCredentials (uid/euid/suid/fsuid, gid/egid/sgid/fsgid,
// supplementary_gids, cap_*, securebits) has 200+ external access sites; defer to a
// later refactoring pass once the access patterns are stabilised.

pub struct ProcessControlBlock {
    // 不可变的进程标识。
    pub pid: PidHandle,
    parent_visible_pid: AtomicUsize,
    /// 文件描述符表属于独立共享域。
    ///
    /// Linux 的 `task_struct::files` 和 StarryOS 的资源域都不会依赖进程
    /// 元数据总锁。这里的外层锁只保护 CLONE_FILES/unshare 时替换 Arc，
    /// 真正的 fd 操作仍由 FilesStruct 自己的锁保护。
    files: SpinMutex<Arc<SpinMutex<FilesStruct>>>,
    /// 线程组只保护 TID 分配与线程表，不再与进程身份、文件表或地址空间共锁。
    threads: SpinMutex<ThreadGroup>,
    /// 地址空间句柄独立于进程元数据。
    ///
    /// 外层锁只保护 exec/exit 时替换 `MmRef`；页表、VMA 与 COW 操作由
    /// `MmRef` 自身同步，普通缺页和用户态访问不再争用 PCB 总锁。
    memory_set: SpinMutex<MmRef>,
    /// 进程级信号动作与共享 pending 状态，对应 Linux `signal_struct/sighand`。
    signal: SpinMutex<ProcessSignalState>,
    /// 低频进程元数据。地址空间、线程组、信号等热点域会逐步从这里拆出。
    inner: SpinMutex<ProcessControlBlockInner>,
}

// 进程控制块
// 里面存放线程共用的 资源
pub struct ProcessControlBlockInner {
    pub is_zombie: bool,
    /// 终止进程的信号是否应报告为会产生 core dump 的信号。
    pub dumped_core: bool,
    /// 进程组 ID（PGID）。
    pub pgid: usize,
    /// 会话 ID（SID）。
    pub sid: usize,
    /// 进程至少执行过一次 execve() 后置为 true。
    pub did_exec: bool,
    /// waitpid 作业控制使用的停止/继续状态。
    pub stopped: bool,
    pub stop_signal: i32,
    pub stop_pending: bool,
    pub continued: bool,
    /// 基础 ptrace 支持使用的 tracer pid（`PTRACE_TRACEME`）。
    pub ptrace_tracer_pid: Option<usize>,
    /// 当前进程作为 tracer 时，仍然存活并指向它的 tracee 数量。
    ///
    /// Linux 会把被追踪进程挂在父进程/tracer 本地链表上，因此 wait 路径在
    /// 调用者没有 ptrace 子进程时，不需要扫描全局进程表。这个计数器保留了
    /// `wait4()` 同样的“没有 tracee 就快速跳过”判断，同时仍让每个 tracee
    /// 通过自己的 `ptrace_tracer_pid` 记录所属 tracer。
    pub ptrace_tracee_count: usize,
    pub parent: Option<Weak<ProcessControlBlock>>,
    /// 当前进程在父进程 `children` 向量中的下标；`None` 表示当前未挂在父进程子列表中。
    ///
    /// Linux 使用侵入式 child/sibling 链表，所以 wait/reparent 可以在不扫描
    /// 所有兄弟进程的情况下摘除已知子进程。这里缓存 Vec 下标，并在删除时使用
    /// `swap_remove`，在不保留子进程顺序的前提下实现 O(1) 摘除，而不需要为
    /// 每个父进程维护额外 map。
    pub child_parent_index: Option<usize>,
    pub children: Vec<Arc<ProcessControlBlock>>,
    /// 已进入 zombie 状态、可被 wait4(-1) 回收的子进程。
    ///
    /// Linux 会让可 wait 的子进程可直接发现，避免反复扫描整个进程列表。这里把它
    /// 作为父进程本地的加速队列；规范的父子所有权仍然保存在 `children` 中。
    pub exited_children: VecDeque<Arc<ProcessControlBlock>>,
    /// 当前拥有这个 zombie 条目的 `exited_children` 队列所属父进程 PID。
    ///
    /// 相比每次退出时扫描父进程队列去重，这更接近 Linux 中 waitable child
    /// 的单向状态转移。
    pub exited_parent_queue_pid: Option<usize>,
    pub exit_code: i32,
    /// 当前子进程变为可 wait 状态时发送给父进程的信号。
    pub exit_signal: i32,
    /// 用于 `/proc/<pid>/cmdline` 和 ps 的 Linux 风格 argv。
    pub argv: Vec<String>,
    /// 显示在 /proc/*/{stat,status,comm} 中的线程组命令名。
    pub comm: String,
    /// 当前进程的 `PR_SET_PDEATHSIG` 设置。
    pub pdeath_signal: i32,
    /// 可执行文件 inode 身份，用于可写打开时的 ETXTBSY 检查。
    pub exec_inode_dev: usize,
    pub exec_inode_num: u32,
    /// `prctl(PR_*_TIMERSLACK)` 使用的当前/默认 timer slack。
    pub timer_slack_ns: u64,
    pub timer_slack_default_ns: u64,
    /// 从启动开始计算的进程创建时间（ms）。
    pub start_time_ms: usize,
    /// 本进程已退出线程或 zombie 快照中的 CPU 时间（ns）。
    pub cpu_time_ns: u64,
    /// 已 wait 子进程及其后代的 CPU 时间（ns），用于 `times(2)`/`getrusage`。
    pub child_cpu_time_ns: u64,
    /// 真实/有效/保存的用户 ID，以及文件系统 UID。
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    /// 真实/有效/保存的组 ID，以及文件系统 GID。
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    /// 附加组 ID 列表。
    pub supplementary_gids: Vec<u32>,
    /// Linux capability 集合（v2/v3 用户 API 最多保存 64 位）。
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
    /// PR_CAPBSET_DROP 检查使用的 capability bounding set。
    pub cap_bounding: u64,
    /// `PR_SET_KEEPCAPS` / `SECBIT_KEEP_CAPS` 状态。
    pub keep_caps: bool,
    /// Linux personality(2) 标志（默认 PER_LINUX）。
    pub personality: u32,
    /// 按 Linux `ioprio_get/set(2)` 编码的进程级 I/O 优先级。
    pub ioprio: u16,
    /// 进程级文件创建模式掩码（umask）。
    pub umask: usize,
    /// 所有 POSIX 资源限制。
    pub rlimits: ProcessResourceLimits,
    /// 进程根目录（宿主绝对路径），用于 `chroot`。
    pub root: String,
    pub cwd: String,
    /// SysV IPC / POSIX MQ 隔离使用的 IPC namespace id。
    pub ipc_ns_id: usize,
    /// 用户 namespace id。完整的 uid/gid 转换尚未实现；这里用于跟踪 Linux
    /// namespace 控制面，以支持 unshare/procfs 测试。
    pub user_ns_id: usize,
    pub userns_uid_map: String,
    pub userns_gid_map: String,
    pub userns_setgroups: String,
    /// 网络 namespace id。网络设备目前仍全局共享；保留这个 id 是为了让
    /// Linux namespace 句柄以及 setns/clone3 ABI 行为正确。
    pub net_ns_id: usize,
    /// 共享的 UTS namespace 状态（hostname/domainname）。
    pub uts_ns: Arc<SpinMutex<UtsNamespaceState>>,
    /// mount/umount/path 视图系统调用使用的共享 mount namespace 状态。
    pub mnt_ns: MountNamespace,
    /// cgroup namespace 根路径。"/" 表示初始 namespace。
    pub cgroup_ns_root: String,
    /// PID namespace id；0 表示初始 namespace。
    pub pid_ns_id: usize,
    /// 在进程自身 PID namespace 内可见的 PID。
    pub pid_ns_vpid: usize,
    /// 当前进程是否是其 PID namespace 内的 PID 1。
    pub pid_ns_init: bool,
    /// rt-tests（cyclictest/hackbench）使用的 Linux 风格调度状态。
    pub scheduling: ProcessScheduling,
    pub mutex_list: Vec<Option<Arc<dyn Mutex>>>,
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
    /// 在 `waitpid(-1/...)` 中等待当前进程子进程状态变化的 task。
    pub wait_queue: VecDeque<Arc<TaskControlBlock>>,
    /// CLONE_VFORK 父进程等待子进程 exec/exit 的专用队列。
    pub vfork_wait_queue: VecDeque<Arc<TaskControlBlock>>,
    /// 等待当前进程变为可 wait 状态、从而让 pidfd 就绪的 task。
    pub pidfd_poll_waiters: PollWaitQueue,
}

pub struct ProcessSignalState {
    pub signals: SignalFlags,
    pub signals_actions: SignalActions,
    pub signals_masks: SignalFlags,
    pub handling_signal: i32,
    /// 按信号编号索引的 Linux rt_sigaction 处理器。
    pub rt_sig_handlers: Vec<RtSigAction>,
}

impl ProcessSignalState {
    fn new() -> Self {
        Self {
            signals: SignalFlags::empty(),
            signals_actions: SignalActions::default(),
            signals_masks: SignalFlags::empty(),
            handling_signal: -1,
            rt_sig_handlers: vec![RtSigAction::default(); RT_SIG_MAX + 1],
        }
    }
}

impl ProcessControlBlockInner {
    /// 添加 child 进程
    pub fn add_child(&mut self, child: Arc<ProcessControlBlock>) {
        child.borrow_mut().child_parent_index = Some(self.children.len());
        self.children.push(child);
    }

    /// 移除  index 处的child 进程,这里使用了 swap_remove 将最后一个元素换入的方式来提高速度
    pub fn remove_child_at(&mut self, index: usize) -> Arc<ProcessControlBlock> {
        let child = self.children.swap_remove(index);
        child.borrow_mut().child_parent_index = None;
        /// 记得 更新下 标
        if index < self.children.len() {
            self.children[index].borrow_mut().child_parent_index = Some(index);
        }
        child
    }

    /// 使用child 中的 记录下标，快速定位 要删除的 child
    pub fn remove_child(
        &mut self,
        child: &Arc<ProcessControlBlock>,
    ) -> Option<Arc<ProcessControlBlock>> {
        let cached_index = {
            let child_inner = child.borrow_mut();
            child_inner.child_parent_index
        };
        if let Some(index) = cached_index {
            if index < self.children.len() && Arc::ptr_eq(&self.children[index], child) {
                return Some(self.remove_child_at(index));
            }
            debug_assert!(
                index >= self.children.len() || Arc::ptr_eq(&self.children[index], child),
                "stale child_parent_index"
            );
        }
        // TODO: REMOVE
        let Some(index) = self
            .children
            .iter()
            .position(|owned| Arc::ptr_eq(owned, child))
        else {
            return None;
        };
        Some(self.remove_child_at(index))
    }

    pub fn clear_children(&mut self) {
        self.children.clear();
    }
}

/// 一个线程组中仅与线程成员关系有关的状态。
///
/// Linux 使用独立的 task list/signal_struct 管理线程组；StarryOS 也把
/// `Thread` 从 `ProcessData` 中分离。这里先把最常竞争的线程表从 PCB 总锁
/// 中拆出，后续 fork/exit 只需要短暂持有这把锁取得 Arc 快照。
pub struct ThreadGroup {
    pub tasks: Vec<Option<Arc<TaskControlBlock>>>,
    tid_allocator: RecycleAllocator,
}

impl ThreadGroup {
    fn new() -> Self {
        Self {
            tasks: Vec::new(),
            tid_allocator: RecycleAllocator::new(),
        }
    }

    pub fn alloc_tid(&mut self) -> usize {
        self.tid_allocator.alloc()
    }

    pub fn dealloc_tid(&mut self, _tid: usize) {
        // Keep thread IDs monotonic within a process to avoid immediate reuse.
        // Linux TIDs are globally unique for a long period; reusing tiny per-process
        // indexes too early breaks gettid-based uniqueness checks in pthread tests.
    }

    pub fn get_task(&self, tid: usize) -> Arc<TaskControlBlock> {
        self.tasks[tid].as_ref().unwrap().clone()
    }
}

impl ProcessControlBlock {
    fn cached_parent_visible_pid(
        child_pid_ns_id: usize,
        parent_pid_ns_id: usize,
        parent_visible_pid: usize,
    ) -> usize {
        if child_pid_ns_id == 0 || child_pid_ns_id == parent_pid_ns_id {
            parent_visible_pid
        } else {
            0
        }
    }

    pub fn fast_parent_visible_pid(&self) -> usize {
        self.parent_visible_pid.load(Ordering::Acquire)
    }

    pub fn update_parent_visible_pid(&self, parent_pid_ns_id: usize, parent_visible_pid: usize) {
        let child_pid_ns_id = {
            let inner = self.borrow_mut();
            inner.pid_ns_id
        };
        let cached =
            Self::cached_parent_visible_pid(child_pid_ns_id, parent_pid_ns_id, parent_visible_pid);
        self.parent_visible_pid.store(cached, Ordering::Release);
    }

    pub fn update_parent_visible_pid_from_locked_child(
        &self,
        child_pid_ns_id: usize,
        parent_pid_ns_id: usize,
        parent_visible_pid: usize,
    ) {
        let cached =
            Self::cached_parent_visible_pid(child_pid_ns_id, parent_pid_ns_id, parent_visible_pid);
        self.parent_visible_pid.store(cached, Ordering::Release);
    }

    /// CLONE_VFORK blocks the parent until the child either execs or exits.
    /// Exit wakes this queue through the normal child-exit path; exec must
    /// drain the same parent-owned queue before replacing the child's mm.
    fn wake_vfork_parent_waiters_after_exec(&self) {
        let parent = {
            let inner = self.borrow_mut();
            inner.parent.as_ref().and_then(|parent| parent.upgrade())
        };
        let Some(parent) = parent else {
            return;
        };
        let waiters = {
            let mut parent_inner = parent.borrow_mut();
            parent_inner.vfork_wait_queue.drain(..).collect::<Vec<_>>()
        };
        for waiter in waiters {
            crate::task::manager::prime_fair_sync_wakeup_lag(&waiter);
            wakeup_task(waiter);
        }
    }

    fn terminate_other_threads(&self) {
        let current = current_task();
        let current_ptr = current.as_ref().map(Arc::as_ptr);
        let mut to_cleanup = Vec::new();
        {
            let mut threads = self.threads();
            for slot in threads.tasks.iter_mut() {
                let Some(task) = slot.as_ref() else {
                    continue;
                };
                if current_ptr
                    .map(|ptr| ptr == Arc::as_ptr(task))
                    .unwrap_or(false)
                {
                    continue;
                }
                to_cleanup.push(task.clone());
                *slot = None;
            }
        }
        let mut deferred_cleanup = Vec::new();
        for task in &to_cleanup {
            remove_inactive_task(Arc::clone(task));
            let (res, join_waiters) = {
                let mut inner = task.borrow_mut();
                inner.exit_code = Some(0);
                let res = inner.res.take();
                let join_waiters = inner.join_waiters.drain(..).collect::<Vec<_>>();
                (res, join_waiters)
            };
            deferred_cleanup.push((res, join_waiters));
        }

        // exec 对应 Linux/StarryOS 的 de_thread：只有其他线程真正离开各自
        // CPU 后，当前线程才能替换共享 mm。清空 res 会让远端线程在
        // trap_return 检查点退出；每个仍运行的 hart 只发送一次 IPI，避免
        // IPI 风暴反而阻塞 OpenSBI/中断处理。
        let mut kicked_mask = 0usize;
        loop {
            let mut running_mask = 0usize;
            for task in &to_cleanup {
                let running_hart = task.on_cpu.load(Ordering::Acquire);
                if running_hart < MAX_HARTS {
                    running_mask |= 1usize << running_hart;
                }
            }
            if running_mask == 0 {
                break;
            }
            let new_kicks = running_mask & !kicked_mask;
            for hart in 0..MAX_HARTS {
                if (new_kicks & (1usize << hart)) != 0 {
                    crate::arch::send_ipi(hart);
                }
            }
            kicked_mask |= new_kicks;
            core::hint::spin_loop();
        }

        for (res, join_waiters) in deferred_cleanup {
            drop(res);
            for waiter in join_waiters {
                wakeup_task(waiter);
            }
        }
    }

    pub fn borrow_mut(&self) -> MutexGuard<'_, ProcessControlBlockInner> {
        self.inner.lock()
    }

    pub fn try_borrow_mut(&self) -> Option<MutexGuard<'_, ProcessControlBlockInner>> {
        self.inner.try_lock()
    }

    /// 主动调度前只探测一次 PCB 元数据锁，避免持锁调用者切走后在同一 hart
    /// 上运行的任务反向等待这把锁。锁忙时由调用者保留 CPU 并短暂重试。
    #[inline]
    pub(crate) fn inner_lock_available_for_scheduling(&self) -> bool {
        self.inner.try_lock().is_some()
    }

    pub(crate) fn files(&self) -> Arc<SpinMutex<FilesStruct>> {
        Arc::clone(&self.files.lock())
    }

    pub(crate) fn threads(&self) -> MutexGuard<'_, ThreadGroup> {
        self.threads.lock()
    }

    pub fn memory_set(&self) -> MmRef {
        self.memory_set.lock().clone()
    }

    pub fn signal(&self) -> MutexGuard<'_, ProcessSignalState> {
        self.signal.lock()
    }

    pub fn replace_memory_set(&self, memory_set: MmRef) -> MmRef {
        core::mem::replace(&mut *self.memory_set.lock(), memory_set)
    }

    #[allow(unused)]
    pub fn get_user_token(&self) -> usize {
        self.memory_set().token()
    }

    pub fn alloc_tid(&self) -> usize {
        self.threads.lock().alloc_tid()
    }

    pub fn dealloc_tid(&self, tid: usize) {
        self.threads.lock().dealloc_tid(tid);
    }

    pub fn thread_count(&self) -> usize {
        self.tasks_snapshot()
            .iter()
            .filter(|task| task.borrow_mut().res.is_some())
            .count()
    }

    pub fn get_task(&self, tid: usize) -> Arc<TaskControlBlock> {
        self.threads.lock().get_task(tid)
    }

    /// 在线程组锁内只克隆任务引用，TCB 检查必须在锁外完成。
    pub fn task_at(&self, tid: usize) -> Option<Arc<TaskControlBlock>> {
        self.threads
            .lock()
            .tasks
            .get(tid)
            .and_then(|slot| slot.as_ref().cloned())
    }

    pub fn tasks_snapshot(&self) -> Vec<Arc<TaskControlBlock>> {
        self.threads
            .lock()
            .tasks
            .iter()
            .filter_map(|slot| slot.as_ref().cloned())
            .collect()
    }

    pub fn indexed_tasks_snapshot(&self) -> Vec<(usize, Arc<TaskControlBlock>)> {
        self.threads
            .lock()
            .tasks
            .iter()
            .enumerate()
            .filter_map(|(tid, slot)| slot.as_ref().cloned().map(|task| (tid, task)))
            .collect()
    }

    pub fn remove_task(&self, tid: usize) -> Option<Arc<TaskControlBlock>> {
        self.threads
            .lock()
            .tasks
            .get_mut(tid)
            .and_then(Option::take)
    }

    pub fn install_task(&self, tid: usize, task: Arc<TaskControlBlock>) {
        let mut threads = self.threads.lock();
        threads.tasks.resize_with(tid + 1, || None);
        threads.tasks[tid] = Some(task);
    }

    pub fn remove_task_if(&self, tid: usize, expected: &Arc<TaskControlBlock>) -> bool {
        let mut threads = self.threads.lock();
        let Some(slot) = threads.tasks.get_mut(tid) else {
            return false;
        };
        if slot
            .as_ref()
            .is_some_and(|task| Arc::ptr_eq(task, expected))
        {
            *slot = None;
            true
        } else {
            false
        }
    }

    pub fn remove_task_ref(&self, expected: &Arc<TaskControlBlock>) -> bool {
        let mut threads = self.threads.lock();
        let Some(slot) = threads.tasks.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|task| Arc::ptr_eq(task, expected))
        }) else {
            return false;
        };
        *slot = None;
        true
    }

    pub fn take_all_tasks(&self) -> Vec<Option<Arc<TaskControlBlock>>> {
        core::mem::take(&mut self.threads.lock().tasks)
    }

    /// 原子替换进程持有的 fd 表引用，供 exec/exit/unshare 使用。
    pub(crate) fn replace_files(
        &self,
        files: Arc<SpinMutex<FilesStruct>>,
    ) -> Arc<SpinMutex<FilesStruct>> {
        core::mem::replace(&mut *self.files.lock(), files)
    }

    pub(crate) fn nofile_limit(&self) -> usize {
        self.borrow_mut().rlimits.rlimit_nofile_cur as usize
    }

    /// Materialize a private descriptor table when this process shares one.
    ///
    /// The fast path is safe because fork/clone are the paths that add a
    /// process-held reference to `files`, and they take the parent PCB lock
    /// while doing so.  `unshare_files()` checks and replaces this process's
    /// reference under the same PCB lock.  Temporary helper clones can only make
    /// the count larger, causing an unnecessary but harmless copy.
    pub fn unshare_files(self: &Arc<Self>) {
        let old_files = {
            let files = self.files.lock();
            if Arc::strong_count(&files) == 1 {
                return;
            }
            Arc::clone(&files)
        };
        let new_files = {
            let files = old_files.lock();
            Arc::new(SpinMutex::new(files.clone_private()))
        };
        let mut files = self.files.lock();
        if Arc::ptr_eq(&files, &old_files) && Arc::strong_count(&files) > 1 {
            *files = new_files;
        }
    }
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, ustack_base, entry_point, elf_aux) =
            MemorySet::from_elf(elf_data).expect("failed to parse init_proc ELF");
        let new_token = memory_set.token();
        // allocate a pid
        let pid_handle =
            pid_alloc().expect("failed to allocate PID for init process (PID exhausted)");
        let pid = pid_handle.0;
        let args = vec![String::from("init_proc")];
        let (user_sp, argv_base, envp_base, auxv_base) = build_linux_stack(
            new_token,
            ustack_base + USER_STACK_SIZE,
            &args,
            &[],
            elf_aux,
            entry_point,
            0,
        );
        let process = Arc::new(Self {
            pid: pid_handle,
            parent_visible_pid: AtomicUsize::new(0),
            files: SpinMutex::new(Arc::new(SpinMutex::new(FilesStruct::with_stdio()))),
            threads: SpinMutex::new(ThreadGroup::new()),
            memory_set: SpinMutex::new(MmRef::new(memory_set)),
            signal: SpinMutex::new(ProcessSignalState::new()),
            inner: SpinMutex::new(ProcessControlBlockInner {
                is_zombie: false,
                dumped_core: false,
                // Keep init/user space in a Linux-like non-zero job-control domain.
                pgid: if pid == 0 { 1 } else { pid },
                sid: if pid == 0 { 1 } else { pid },
                did_exec: false,
                stopped: false,
                stop_signal: 0,
                stop_pending: false,
                continued: false,
                ptrace_tracer_pid: None,
                ptrace_tracee_count: 0,
                parent: None,
                child_parent_index: None,
                children: Vec::new(),
                exited_children: VecDeque::new(),
                exited_parent_queue_pid: None,
                exit_code: 0,
                exit_signal: SIGCHLD_NUM as i32,
                argv: args.clone(),
                comm: process_comm_from_argv(&args),
                pdeath_signal: 0,
                exec_inode_dev: 0,
                exec_inode_num: 0,
                timer_slack_ns: DEFAULT_TIMER_SLACK_NS,
                timer_slack_default_ns: DEFAULT_TIMER_SLACK_NS,
                start_time_ms: crate::time::get_time_ms(),
                cpu_time_ns: 0,
                child_cpu_time_ns: 0,
                uid: 0,
                euid: 0,
                suid: 0,
                fsuid: 0,
                gid: 0,
                egid: 0,
                sgid: 0,
                fsgid: 0,
                supplementary_gids: vec![0],
                cap_effective: u64::MAX,
                cap_permitted: u64::MAX,
                cap_inheritable: u64::MAX,
                cap_bounding: u64::MAX,
                keep_caps: false,
                personality: 0,
                ioprio: 0,
                umask: 0,
                rlimits: ProcessResourceLimits {
                    rlimit_nofile_cur: 1024,
                    rlimit_nofile_max: 1024,
                    rlimit_nproc_cur: u64::MAX,
                    rlimit_nproc_max: u64::MAX,
                    rlimit_fsize_cur: u64::MAX,
                    rlimit_fsize_max: u64::MAX,
                    rlimit_data_cur: u64::MAX,
                    rlimit_data_max: u64::MAX,
                    rlimit_stack_cur: USER_STACK_SIZE as u64,
                    rlimit_stack_max: USER_STACK_SIZE as u64,
                    rlimit_cpu_cur: u64::MAX,
                    rlimit_cpu_max: u64::MAX,
                    rlimit_cpu_start_ms: crate::time::get_time_ms(),
                    rlimit_cpu_soft_sent: false,
                    rlimit_core_cur: 8 * 1024 * 1024,
                    rlimit_core_max: 8 * 1024 * 1024,
                    rlimit_rss_cur: u64::MAX,
                    rlimit_rss_max: u64::MAX,
                    rlimit_memlock_cur: 64 * 1024,
                    rlimit_memlock_max: 64 * 1024,
                    rlimit_as_cur: u64::MAX,
                    rlimit_as_max: u64::MAX,
                    rlimit_locks_cur: u64::MAX,
                    rlimit_locks_max: u64::MAX,
                    rlimit_msgqueue_cur: 819_200,
                    rlimit_msgqueue_max: 819_200,
                    rlimit_nice_cur: 0,
                    rlimit_nice_max: 0,
                    rlimit_rtprio_cur: 0,
                    rlimit_rtprio_max: 0,
                    rlimit_sigpending_cur: u64::MAX,
                    rlimit_sigpending_max: u64::MAX,
                    rlimit_rttime_cur: u64::MAX,
                    rlimit_rttime_max: u64::MAX,
                },
                root: String::from("/"),
                cwd: String::from("/user"),
                ipc_ns_id: 0,
                user_ns_id: 0,
                userns_uid_map: String::from("0 0 4294967295\n"),
                userns_gid_map: String::from("0 0 4294967295\n"),
                userns_setgroups: String::from("allow\n"),
                net_ns_id: 0,
                uts_ns: Arc::new(SpinMutex::new(UtsNamespaceState::new())),
                mnt_ns: initial_mount_namespace(),
                cgroup_ns_root: String::from("/"),
                pid_ns_id: 0,
                pid_ns_vpid: pid,
                pid_ns_init: true,
                scheduling: ProcessScheduling {
                    sched_policy: 0,
                    cpu_affinity_mask: if MAX_HARTS >= usize::BITS as usize {
                        usize::MAX
                    } else {
                        (1usize << MAX_HARTS) - 1
                    },
                    sched_priority: 0,
                    sched_runtime: 0,
                    sched_deadline: 0,
                    sched_period: 0,
                    nice: 0,
                    reset_on_fork: false,
                },
                mutex_list: Vec::new(),
                semaphore_list: Vec::new(),
                condvar_list: Vec::new(),
                wait_queue: VecDeque::new(),
                vfork_wait_queue: VecDeque::new(),
                pidfd_poll_waiters: PollWaitQueue::default(),
            }),
        });
        // new只会被主线程调用?,反正这里我们要手动创建一个 Task线程
        // NOTE: Pass false for alloc_user_res because from_elf has already
        // allocated user stack and trap context for the main thread (tid=0)
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&process),
            ustack_base,
            false, // Don't allocate again!
        ));
        // prepare trap_cx of main thread
        let task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        let kstack_top = task.kstack_top();
        drop(task_inner);
        let mut tcx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.lock().token(),
            kstack_top,
            trap_handler as usize,
        );
        tcx.x[REG_A0] = args.len();
        tcx.x[REG_A1] = argv_base;
        tcx.x[REG_A2] = envp_base;
        tcx.x[REG_A3] = auxv_base;
        *trap_cx = tcx;
        // println!(
        //     "[DEBUG] ProcessControlBlock::new - entry_point={:#x}, ustack_top={:#x}, kstack_top={:#x}",
        //     entry_point, ustack_top, kstack_top
        // );
        // add main thread to the process
        process.threads().tasks.push(Some(Arc::clone(&task)));
        insert_into_pid2process(process.getpid(), Arc::clone(&process));
        register_pid_namespace_reaper(0, process.getpid());
        // add main thread to scheduler
        crate::println!(
            "[proc] init main thread pid={} tid=0 entry={:#x} ustack_top={:#x} kstack_top={:#x}",
            process.getpid(),
            entry_point,
            ustack_base + USER_STACK_SIZE,
            kstack_top
        );
        // Bootstrap initproc onto the current hart (loongarch64 may not start hart 0).
        let boot_hart = crate::task::processor::hart_id();
        task.set_cpu_id(boot_hart);
        add_task(task);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(
        self: &Arc<Self>,
        elf_data: &[u8],
        args: Vec<String>,
        envs: Vec<String>,
        exec_inode: (usize, u32),
        comm_override: Option<String>,
    ) -> Result<(), isize> {
        let (memory_set, ustack_base, entry_point, elf_aux) = MemorySet::from_elf(elf_data)?;
        self.exec_with_memory_set(
            memory_set,
            ustack_base,
            entry_point,
            args,
            envs,
            elf_aux,
            exec_inode,
            comm_override,
        );
        Ok(())
    }

    /// Exec a dynamically-linked ELF (with PT_INTERP) in a Linux-like way:
    /// map both the main program and the interpreter, then start at the interpreter entry
    /// while exposing the main program metadata via auxv (AT_PHDR/AT_ENTRY) and AT_BASE.
    pub fn exec_dyn(
        self: &Arc<Self>,
        elf_data: &[u8],
        interp_data: &[u8],
        args: Vec<String>,
        envs: Vec<String>,
        exec_inode: (usize, u32),
        comm_override: Option<String>,
    ) -> Result<(), isize> {
        let (memory_set, ustack_base, interp_entry, main_entry, main_aux, interp_base) =
            MemorySet::from_elf_with_interp(elf_data, interp_data)?;
        self.exec_dyn_with_memory_set(
            memory_set,
            ustack_base,
            interp_entry,
            main_entry,
            main_aux,
            interp_base,
            interp_data,
            args,
            envs,
            exec_inode,
            comm_override,
        );
        Ok(())
    }

    pub fn exec_with_memory_set(
        self: &Arc<Self>,
        memory_set: MemorySet,
        ustack_base: usize,
        entry_point: usize,
        args: Vec<String>,
        envs: Vec<String>,
        elf_aux: ElfAux,
        exec_inode: (usize, u32),
        comm_override: Option<String>,
    ) {
        // Linux execve unshares CLONE_FILES state before applying CLOEXEC.
        self.unshare_files();
        let thread_count = self.thread_count();
        if thread_count != 1 {
            log::warn!(
                "[exec] pid={} thread_count={} (terminating other threads)",
                self.getpid(),
                thread_count
            );
            self.terminate_other_threads();
        }
        self.files().lock().close_cloexec_fds();
        let new_token = memory_set.token();
        let new_memory_set = MmRef::new(memory_set);
        let task = self.get_task(0);
        let old_trap_cx_slot = {
            let task_inner = task.borrow_mut();
            task_inner.res.as_ref().map(|res| res.trap_cx_slot())
        };
        let mut old_memory_set = self.memory_set();
        let old_mm_token = old_memory_set.token();
        if let Some(slot) = old_trap_cx_slot {
            let trap_cx_bottom = TRAP_CONTEXT_BASE - slot * PAGE_SIZE;
            old_memory_set.remove_area_with_start_vpn(trap_cx_bottom.into());
            old_memory_set.dealloc_trap_context_slot(slot);
        }
        let old_shm_cleanup = old_memory_set.take_sysv_shm_attaches_for_cleanup();
        #[cfg(target_arch = "riscv64")]
        // Trap entry may still be running on the old user SATP; switch away
        // before replacing and potentially dropping that address space.
        crate::mm::activate_kernel_space();
        drop(self.replace_memory_set(new_memory_set.clone()));
        reset_signal_handlers_on_exec(&mut self.signal());
        {
            let mut inner = self.borrow_mut();
            inner.scheduling.reset_on_fork = false;
            inner.keep_caps = false;
            inner.argv = args.clone();
            inner.comm = comm_override
                .as_deref()
                .map(process_comm_from_name)
                .unwrap_or_else(|| process_comm_from_argv(&args));
            crate::syscall::process::unregister_executing_inode(
                inner.exec_inode_dev,
                inner.exec_inode_num,
            );
            inner.exec_inode_dev = exec_inode.0;
            inner.exec_inode_num = exec_inode.1;
            crate::syscall::process::register_executing_inode(exec_inode.0, exec_inode.1);
            inner.did_exec = true;
        }
        task.set_memory_set(new_memory_set);
        let old_mm_still_owned = release_process_mm_owner(old_mm_token);
        self.wake_vfork_parent_waiters_after_exec();
        if !old_mm_still_owned {
            crate::syscall::net::clear_packet_ring_mmaps_for_token(old_mm_token);
        }
        if let Some(old_shm) = old_shm_cleanup {
            crate::syscall::sysv_shm::exit_cleanup(&old_shm);
        }
        let mut task_inner = task.borrow_mut();
        let res = task_inner.res.as_mut().unwrap();
        res.reset_for_exec(ustack_base);
        task_inner.trap_cx_ppn = res.trap_cx_ppn();
        let (user_sp, argv_base, envp_base, auxv_base) = build_linux_stack(
            new_token,
            task_inner.res.as_mut().unwrap().ustack_top(),
            &args,
            &envs,
            elf_aux,
            entry_point,
            0,
        );
        let mut trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.lock().token(),
            task.kstack_top(),
            trap_handler as usize,
        );
        trap_cx.x[REG_A0] = args.len();
        trap_cx.x[REG_A1] = argv_base;
        trap_cx.x[REG_A2] = envp_base;
        trap_cx.x[REG_A3] = auxv_base;
        *task_inner.get_trap_cx() = trap_cx;
        drop(task_inner);
        task.reset_fp_state();
        crate::arch::restore_user_fp_state(&task);
        prime_fair_exec_start(&task);
    }

    pub fn exec_dyn_with_memory_set(
        self: &Arc<Self>,
        memory_set: MemorySet,
        ustack_base: usize,
        interp_entry: usize,
        main_entry: usize,
        main_aux: ElfAux,
        interp_base: usize,
        interp_data: &[u8],
        args: Vec<String>,
        envs: Vec<String>,
        exec_inode: (usize, u32),
        comm_override: Option<String>,
    ) {
        // Linux execve unshares CLONE_FILES state before applying CLOEXEC.
        self.unshare_files();
        let thread_count = self.thread_count();
        if thread_count != 1 {
            log::warn!(
                "[exec_dyn] pid={} thread_count={} (terminating other threads)",
                self.getpid(),
                thread_count
            );
            self.terminate_other_threads();
        }
        self.files().lock().close_cloexec_fds();
        let new_token = memory_set.token();
        let new_memory_set = MmRef::new(memory_set);
        let task = self.get_task(0);
        let old_trap_cx_slot = {
            let task_inner = task.borrow_mut();
            task_inner.res.as_ref().map(|res| res.trap_cx_slot())
        };
        let mut old_memory_set = self.memory_set();
        let old_mm_token = old_memory_set.token();
        if let Some(slot) = old_trap_cx_slot {
            let trap_cx_bottom = TRAP_CONTEXT_BASE - slot * PAGE_SIZE;
            old_memory_set.remove_area_with_start_vpn(trap_cx_bottom.into());
            old_memory_set.dealloc_trap_context_slot(slot);
        }
        let old_shm_cleanup = old_memory_set.take_sysv_shm_attaches_for_cleanup();
        #[cfg(target_arch = "riscv64")]
        // Trap entry may still be running on the old user SATP; switch away
        // before replacing and potentially dropping that address space.
        crate::mm::activate_kernel_space();
        drop(self.replace_memory_set(new_memory_set.clone()));
        reset_signal_handlers_on_exec(&mut self.signal());
        {
            let mut inner = self.borrow_mut();
            inner.scheduling.reset_on_fork = false;
            inner.keep_caps = false;
            inner.argv = args.clone();
            inner.comm = comm_override
                .as_deref()
                .map(process_comm_from_name)
                .unwrap_or_else(|| process_comm_from_argv(&args));
            crate::syscall::process::unregister_executing_inode(
                inner.exec_inode_dev,
                inner.exec_inode_num,
            );
            inner.exec_inode_dev = exec_inode.0;
            inner.exec_inode_num = exec_inode.1;
            crate::syscall::process::register_executing_inode(exec_inode.0, exec_inode.1);
            inner.did_exec = true;
        }
        task.set_memory_set(new_memory_set);
        let old_mm_still_owned = release_process_mm_owner(old_mm_token);
        self.wake_vfork_parent_waiters_after_exec();
        if !old_mm_still_owned {
            crate::syscall::net::clear_packet_ring_mmaps_for_token(old_mm_token);
        }
        if let Some(old_shm) = old_shm_cleanup {
            crate::syscall::sysv_shm::exit_cleanup(&old_shm);
        }

        // Workaround glibc ld-linux early crash by seeding an internal cached
        // DT_SYMTAB dynamic-entry pointer before entering the interpreter.
        patch_glibc_ld_linux_symtab_dyn(new_token, interp_base, interp_data);

        let mut task_inner = task.borrow_mut();
        let res = task_inner.res.as_mut().unwrap();
        res.reset_for_exec(ustack_base);
        task_inner.trap_cx_ppn = res.trap_cx_ppn();

        let (user_sp, argv_base, envp_base, auxv_base) = build_linux_stack(
            new_token,
            task_inner.res.as_mut().unwrap().ustack_top(),
            &args,
            &envs,
            main_aux,
            main_entry,
            interp_base,
        );
        dump_linux_initial_stack(new_token, user_sp);

        let mut trap_cx = TrapContext::app_init_context(
            interp_entry,
            user_sp,
            KERNEL_SPACE.lock().token(),
            task.kstack_top(),
            trap_handler as usize,
        );
        trap_cx.x[REG_A0] = args.len();
        trap_cx.x[REG_A1] = argv_base;
        trap_cx.x[REG_A2] = envp_base;
        trap_cx.x[REG_A3] = auxv_base;
        *task_inner.get_trap_cx() = trap_cx;
        drop(task_inner);
        task.reset_fp_state();
        crate::arch::restore_user_fp_state(&task);
        prime_fair_exec_start(&task);
    }

    fn fork_impl(
        self: &Arc<Self>,
        share_files: bool,
        share_vm: bool,
    ) -> Result<(Arc<Self>, Arc<TaskControlBlock>), ForkError> {
        let caller_task = crate::task::processor::current_task();
        if let Some(task) = caller_task.as_ref() {
            crate::arch::save_user_fp_state(task);
        }
        let caller_scheduling = caller_task.as_ref().map(|task| task.scheduling_snapshot());
        let caller_task_res = caller_task.as_ref().and_then(|t| {
            let inner = t.borrow_mut();
            inner.res.as_ref().map(|r| (r.tid, r.ustack_base()))
        });
        let caller_tid = caller_task_res.map(|(tid, _)| tid).unwrap_or(0);
        let diag_enabled = DEBUG_FUTEX;
        let fork_start_cycles = if diag_enabled {
            crate::arch::read_time()
        } else {
            0
        };
        let mut after_mem_cycles = fork_start_cycles;
        let mut after_pcb_cycles = fork_start_cycles;
        let mut after_task_cycles = fork_start_cycles;

        // 线程表和地址空间各自取引用快照，随后才读取低频 PCB 元数据。
        // COW 和 TCB 访问都不会嵌套在这些锁内。
        let parent_tasks_snapshot = self.tasks_snapshot();
        let parent_memory_set = self.memory_set();
        let thread_count = parent_tasks_snapshot.len();
        let mut parent = self.borrow_mut();
        if thread_count != 1 {
            log::warn!(
                "[fork] pid={} thread_count={} (forking only current thread)",
                self.getpid(),
                thread_count
            );
        }
        let parent_scheduling = caller_scheduling.unwrap_or_else(|| parent.scheduling.clone());
        let sched_policy = parent_scheduling.sched_policy;
        let sched_priority = parent_scheduling.sched_priority;
        let sched_runtime = parent_scheduling.sched_runtime;
        let sched_deadline = parent_scheduling.sched_deadline;
        let sched_period = parent_scheduling.sched_period;
        let nice = parent_scheduling.nice;
        let reset_on_fork = parent_scheduling.reset_on_fork;
        let (
            child_sched_policy,
            child_sched_priority,
            child_sched_runtime,
            child_sched_deadline,
            child_sched_period,
            child_nice,
        ) = if reset_on_fork {
            let (policy, priority, runtime, deadline, period) = match sched_policy {
                SCHED_FIFO | SCHED_RR | SCHED_DEADLINE => (SCHED_OTHER, 0, 0, 0, 0),
                _ => (
                    sched_policy,
                    sched_priority,
                    sched_runtime,
                    sched_deadline,
                    sched_period,
                ),
            };
            (policy, priority, runtime, deadline, period, nice.max(0))
        } else {
            (
                sched_policy,
                sched_priority,
                sched_runtime,
                sched_deadline,
                sched_period,
                nice,
            )
        };
        let cpu_affinity_mask = parent_scheduling.cpu_affinity_mask;
        let rt_sig_handlers = self.signal().rt_sig_handlers.clone();
        let argv = parent.argv.clone();
        if crate::debug_config::DEBUG_PID_MAP {
            let seq = FORK_PRE_COW_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if seq <= 8 || (seq & (seq - 1)) == 0 {
                let (areas, data_frames, ident_vpns, lazy_areas, framed_areas, ident_areas) =
                    parent_memory_set.cow_diag_stats();
                crate::println!(
                    "[fork-cow-pre] seq={} pid={} areas={} data_frames={} ident_vpns={} lazy={} framed={} ident={}",
                    seq,
                    self.getpid(),
                    areas,
                    data_frames,
                    ident_vpns,
                    lazy_areas,
                    framed_areas,
                    ident_areas
                );
            }
        }
        // Starry/Linux 的 fork 会把 task 元数据锁和 mmap 锁分层。COW 可能遍历
        // 大量 VMA，并与其他线程的缺页路径竞争 mm 锁；若仍持有 PCB 锁，
        // 另一线程在持有 mm 锁时读取 PCB 就会形成锁序反转。
        drop(parent);
        let child_excluded_trap_slots = if thread_count > 1 && !share_vm {
            parent_tasks_snapshot
                .iter()
                .filter_map(|task| {
                    let task_inner = task.borrow_mut();
                    let res = task_inner.res.as_ref()?;
                    (res.tid != 0).then_some(res.trap_cx_slot())
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let inherited_shm = parent_memory_set.sysv_shm_attaches_snapshot();
        let parent_mm_token = parent_memory_set.token();

        // Fork address space (COW by default, full copy on LoongArch).
        #[cfg(target_arch = "loongarch64")]
        let memory_set = if DEBUG_LOONGARCH_FULL_COPY_FORK {
            MmRef::from_existed_user_deep(&parent_memory_set)
        } else if share_vm {
            parent_memory_set.clone()
        } else {
            MmRef::from_existed_user_cow(&parent_memory_set)
        };
        #[cfg(not(target_arch = "loongarch64"))]
        let memory_set = if share_vm {
            parent_memory_set.clone()
        } else {
            MmRef::from_existed_user_cow(&parent_memory_set)
        };
        let child_mm_token = memory_set.token();
        if !child_excluded_trap_slots.is_empty() {
            let mut child_mm = memory_set.lock();
            for trap_cx_slot in child_excluded_trap_slots {
                let trap_cx_bottom = TRAP_CONTEXT_BASE - trap_cx_slot * PAGE_SIZE;
                child_mm.remove_area_with_start_vpn(trap_cx_bottom.into());
                child_mm.dealloc_trap_context_slot(trap_cx_slot);
            }
        }
        let mut parent = self.borrow_mut();
        if diag_enabled {
            after_mem_cycles = crate::arch::read_time();
        }
        // alloc a pid
        let pid = pid_alloc()?;
        let pid_value = pid.0;
        let parent_visible_pid = parent.pid_ns_vpid;
        let pgid = parent.pgid;
        let sid = parent.sid;
        let comm = parent.comm.clone();
        let timer_slack_ns = parent.timer_slack_ns;
        let uid = parent.uid;
        let euid = parent.euid;
        let suid = parent.suid;
        let fsuid = parent.fsuid;
        let gid = parent.gid;
        let egid = parent.egid;
        let sgid = parent.sgid;
        let fsgid = parent.fsgid;
        let supplementary_gids = parent.supplementary_gids.clone();
        let cap_effective = parent.cap_effective;
        let cap_permitted = parent.cap_permitted;
        let cap_inheritable = parent.cap_inheritable;
        let cap_bounding = parent.cap_bounding;
        let keep_caps = parent.keep_caps;
        let personality = parent.personality;
        let ioprio = parent.ioprio;
        let umask = parent.umask;
        let rlimits = parent.rlimits.clone();
        let root = parent.root.clone();
        let cwd = parent.cwd.clone();
        let ipc_ns_id = parent.ipc_ns_id;
        let user_ns_id = parent.user_ns_id;
        let userns_uid_map = parent.userns_uid_map.clone();
        let userns_gid_map = parent.userns_gid_map.clone();
        let userns_setgroups = parent.userns_setgroups.clone();
        let net_ns_id = parent.net_ns_id;
        let uts_ns = Arc::clone(&parent.uts_ns);
        let mnt_ns = Arc::clone(&parent.mnt_ns);
        let cgroup_ns_root = parent.cgroup_ns_root.clone();
        let pid_ns_id = parent.pid_ns_id;
        let exec_inode_dev = parent.exec_inode_dev;
        let exec_inode_num = parent.exec_inode_num;
        // Remember parent's user-stack base for the calling thread.
        let parent_ustack_base = caller_task_res.map(|(_, base)| base).unwrap_or_else(|| {
            self.get_task(0)
                .borrow_mut()
                .res
                .as_ref()
                .unwrap()
                .ustack_base()
        });
        // Fork state is not a single atomic snapshot across all PCB fields and
        // the descriptor table.  Linux allows those domains to move separately;
        // here that choice also keeps the PCB lock from nesting with the files
        // lock.
        drop(parent);
        let parent_files = self.files();
        let child_files = if share_files {
            Arc::clone(&parent_files)
        } else {
            Arc::new(SpinMutex::new(parent_files.lock().clone_private()))
        };

        // create child process pcb
        let child = Arc::new(Self {
            pid,
            parent_visible_pid: AtomicUsize::new(parent_visible_pid),
            files: SpinMutex::new(child_files),
            threads: SpinMutex::new(ThreadGroup::new()),
            memory_set: SpinMutex::new(memory_set),
            signal: SpinMutex::new(ProcessSignalState {
                rt_sig_handlers,
                ..ProcessSignalState::new()
            }),
            inner: SpinMutex::new(ProcessControlBlockInner {
                is_zombie: false,
                dumped_core: false,
                pgid,
                sid,
                did_exec: false,
                stopped: false,
                stop_signal: 0,
                stop_pending: false,
                continued: false,
                ptrace_tracer_pid: None,
                ptrace_tracee_count: 0,
                parent: Some(Arc::downgrade(self)),
                child_parent_index: None,
                children: Vec::new(),
                exited_children: VecDeque::new(),
                exited_parent_queue_pid: None,
                exit_code: 0,
                exit_signal: SIGCHLD_NUM as i32,
                argv,
                comm,
                pdeath_signal: 0,
                timer_slack_ns,
                timer_slack_default_ns: timer_slack_ns,
                start_time_ms: crate::time::get_time_ms(),
                cpu_time_ns: 0,
                child_cpu_time_ns: 0,
                uid,
                euid,
                suid,
                fsuid,
                gid,
                egid,
                sgid,
                fsgid,
                supplementary_gids,
                cap_effective,
                cap_permitted,
                cap_inheritable,
                cap_bounding,
                keep_caps,
                personality,
                ioprio,
                umask,
                rlimits,
                root,
                cwd,
                ipc_ns_id,
                user_ns_id,
                userns_uid_map,
                userns_gid_map,
                userns_setgroups,
                net_ns_id,
                uts_ns,
                mnt_ns,
                cgroup_ns_root,
                pid_ns_id,
                pid_ns_vpid: pid_value,
                pid_ns_init: false,
                exec_inode_dev,
                exec_inode_num,
                scheduling: ProcessScheduling {
                    sched_policy: child_sched_policy,
                    cpu_affinity_mask,
                    sched_priority: child_sched_priority,
                    sched_runtime: child_sched_runtime,
                    sched_deadline: child_sched_deadline,
                    sched_period: child_sched_period,
                    nice: child_nice,
                    reset_on_fork: false,
                },
                mutex_list: Vec::new(),
                semaphore_list: Vec::new(),
                condvar_list: Vec::new(),
                wait_queue: VecDeque::new(),
                vfork_wait_queue: VecDeque::new(),
                pidfd_poll_waiters: PollWaitQueue::default(),
            }),
        });
        if diag_enabled {
            after_pcb_cycles = crate::arch::read_time();
        }

        // create main thread of child process (allocates a fresh kernel stack)
        let task = Arc::new(if share_vm {
            // Process-style CLONE_VM shares the mm but is not a thread-group
            // member. Its user stack is supplied by clone(2), so only allocate
            // a distinct trap-context slot in the shared mm.
            TaskControlBlock::try_new_linux_thread(Arc::clone(&child))?
        } else {
            TaskControlBlock::try_new(
                Arc::clone(&child),
                parent_ustack_base,
                // here we do not allocate trap_cx or ustack again
                // but mention that we allocate a new kstack here
                false,
            )?
        });
        if !share_vm {
            crate::syscall::net::clone_packet_ring_mmaps_for_fork(parent_mm_token, child_mm_token);
        }
        if !share_vm {
            crate::syscall::sysv_shm::fork_inherit(&inherited_shm);
        }
        // Distribute child processes across harts.
        task.set_cpu_id(select_hart_for_new_task());
        // attach task to child process
        child.threads().tasks.push(Some(Arc::clone(&task)));
        // Publish the child before cgroup inheritance so per-thread membership
        // can resolve the freshly created main task.
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        cgroup_attach_fork_child(self.getpid(), child.getpid());
        // Seed trap context from the calling thread when available.
        let parent_trap_cx = caller_task.as_ref().map(|t| *t.borrow_mut().get_trap_cx());
        // modify kstack_top in trap_cx of this thread
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        if let Some(parent_trap_cx) = parent_trap_cx {
            *trap_cx = parent_trap_cx;
        }
        trap_cx.kernel_sp = task.kstack_top();
        // set return value for child process
        trap_cx.x[REG_A0] = 0;
        if !share_vm && caller_tid != 0 {
            if let Some(res) = task_inner.res.as_mut() {
                let caller_stack_bottom =
                    parent_ustack_base + caller_tid * (PAGE_SIZE + USER_STACK_SIZE);
                res.ustack_base = caller_stack_bottom;
            }
        }

        // println!(
        //     "[DEBUG] fork - child trap_cx: sepc={:#x}, sp={:#x}, kernel_sp={:#x}, a0={:#x}",
        //     trap_cx.sepc, trap_cx.x[2], trap_cx.kernel_sp, trap_cx.x[10]
        // );

        drop(task_inner);
        if let Some(parent_task) = caller_task.as_ref() {
            task.inherit_fp_state_from(parent_task);
        }
        if diag_enabled {
            after_task_cycles = crate::arch::read_time();
        }
        {
            let child_inner = child.borrow_mut();
            crate::syscall::process::register_executing_inode(
                child_inner.exec_inode_dev,
                child_inner.exec_inode_num,
            );
        }
        // add child to parent's children list (after success)
        self.borrow_mut().add_child(Arc::clone(&child));
        if diag_enabled {
            let end_cycles = crate::arch::read_time();
            let seq = FORK_IMPL_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            let total_us = fork_diag_cycles_to_us(end_cycles.wrapping_sub(fork_start_cycles));
            if should_report_fork_impl_diag(seq, total_us) {
                let mem_us =
                    fork_diag_cycles_to_us(after_mem_cycles.wrapping_sub(fork_start_cycles));
                let pcb_us =
                    fork_diag_cycles_to_us(after_pcb_cycles.wrapping_sub(after_mem_cycles));
                let task_us =
                    fork_diag_cycles_to_us(after_task_cycles.wrapping_sub(after_pcb_cycles));
                let final_us = fork_diag_cycles_to_us(end_cycles.wrapping_sub(after_task_cycles));
                log::warn!(
                    "[fork_impl_diag] seq={} parent_pid={} child_pid={} share_vm={} share_files={} total_us={} mem_clone_us={} child_pcb_us={} child_task_us={} publish_us={}",
                    seq,
                    self.getpid(),
                    child.getpid(),
                    share_vm,
                    share_files,
                    total_us,
                    mem_us,
                    pcb_us,
                    task_us,
                    final_us
                );
            }
        }
        Ok((child, task))
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Result<Arc<Self>, ForkError> {
        let (child, task) = self.fork_impl(false, false)?;
        // add this thread to scheduler
        add_task(task);
        Ok(child)
    }

    /// Fork and return both the child process and its main task, without scheduling it.
    pub fn fork_with_task(
        self: &Arc<Self>,
        share_files: bool,
        share_vm: bool,
    ) -> Result<(Arc<Self>, Arc<TaskControlBlock>), ForkError> {
        self.fork_impl(share_files, share_vm)
    }

    pub fn getpid(&self) -> usize {
        self.pid.0
    }

    pub fn visible_pid(&self) -> usize {
        let inner = self.borrow_mut();
        if inner.pid_ns_id == 0 {
            self.pid.0
        } else {
            inner.pid_ns_vpid
        }
    }

    pub fn pid_namespace_id(&self) -> usize {
        self.borrow_mut().pid_ns_id
    }

    pub fn user_namespace_id(&self) -> usize {
        self.borrow_mut().user_ns_id
    }

    pub fn unshare_user_namespace(&self) {
        let mut inner = self.borrow_mut();
        inner.user_ns_id = alloc_user_namespace_id();
        inner.userns_uid_map.clear();
        inner.userns_gid_map.clear();
        inner.userns_setgroups = String::from("allow\n");
    }

    pub fn net_namespace_id(&self) -> usize {
        self.borrow_mut().net_ns_id
    }

    pub fn set_net_namespace_id(&self, ns_id: usize) {
        self.borrow_mut().net_ns_id = ns_id;
    }

    pub fn unshare_net_namespace(&self) {
        self.borrow_mut().net_ns_id = alloc_net_namespace_id();
    }

    pub fn uts_namespace(self: &Arc<Self>) -> Arc<SpinMutex<UtsNamespaceState>> {
        let inner = self.borrow_mut();
        Arc::clone(&inner.uts_ns)
    }

    pub fn mount_namespace(&self) -> MountNamespace {
        let inner = self.borrow_mut();
        Arc::clone(&inner.mnt_ns)
    }

    pub fn mount_namespace_id(&self) -> usize {
        mount_namespace_id(&self.mount_namespace())
    }

    pub fn set_mount_namespace(&self, namespace: MountNamespace) {
        self.borrow_mut().mnt_ns = namespace;
    }

    pub fn unshare_mount_namespace(&self) {
        let namespace = {
            let inner = self.borrow_mut();
            clone_mount_namespace(&inner.mnt_ns)
        };
        self.borrow_mut().mnt_ns = namespace;
    }

    pub fn cgroup_namespace_root(&self) -> String {
        self.borrow_mut().cgroup_ns_root.clone()
    }

    pub fn set_cgroup_namespace_root(&self, path: String) {
        self.borrow_mut().cgroup_ns_root = path;
    }

    pub fn unshare_uts_namespace(self: &Arc<Self>) {
        let snapshot = {
            let uts_ns = self.uts_namespace();
            *uts_ns.lock()
        };
        let mut inner = self.borrow_mut();
        inner.uts_ns = Arc::new(SpinMutex::new(snapshot));
    }

    pub fn is_pid_namespace_init(&self) -> bool {
        self.borrow_mut().pid_ns_init
    }
}
