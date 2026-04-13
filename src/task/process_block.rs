use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::mutex::Mutex;
use crate::arch::{REG_A0, REG_A1, REG_A2, REG_A3};
use crate::config::{MAX_HARTS, PAGE_SIZE, TRAP_CONTEXT_BASE, USER_HEAP_GAP, USER_STACK_SIZE};
use crate::debug_config::{DEBUG_FUTEX, DEBUG_LOONGARCH_FULL_COPY_FORK, DEBUG_SYSCALL};
use crate::fs::{
    File, MountNamespace, PollWaitQueue, Stdin, Stdout, cgroup_attach_fork_child,
    clone_mount_namespace, initial_mount_namespace, mount_namespace_id,
};
use crate::mm::{
    ElfAux, KERNEL_SPACE, MemorySet, read_user_value, translated_mutref, write_user_value,
};
use crate::println;
use crate::task::condvar::Condvar;
use crate::task::id::{PidHandle, pid_alloc};
use crate::task::manager::{
    PID2PCB, add_task, insert_into_pid2process, remove_inactive_task, select_hart_for_new_task,
    wakeup_task,
};
use crate::task::processor::current_task;
use crate::task::semaphore::Semaphore;
use crate::task::signal::{
    RT_SIG_MAX, RtSigAction, SIG_IGN, SignalAction, SignalActions, SignalFlags,
};
use crate::task::task_block::TaskControlBlock;
use crate::trap::context::TrapContext;
use crate::trap::trap_handler;
use crate::utils::RecycleAllocator;
use lazy_static::lazy_static;
use spin::{Mutex as SpinMutex, MutexGuard};

const DEFAULT_MMAP_BASE: usize = 0x34_0000_0000;
const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;
static FORK_IMPL_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);
static FORK_PRE_COW_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);
static NEXT_IPC_NS_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_PID_NS_ID: AtomicUsize = AtomicUsize::new(1);

pub fn alloc_ipc_namespace_id() -> usize {
    NEXT_IPC_NS_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn alloc_pid_namespace_id() -> usize {
    NEXT_PID_NS_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn register_pid_namespace(parent_ns_id: usize, child_ns_id: usize) {
    if child_ns_id == 0 {
        return;
    }
    PID_NAMESPACE_PARENTS
        .lock()
        .insert(child_ns_id, parent_ns_id);
}

pub fn pid_namespace_descends_from(ns_id: usize, ancestor_ns_id: usize) -> bool {
    if ancestor_ns_id == 0 {
        return true;
    }
    if ns_id == ancestor_ns_id {
        return true;
    }
    let parents = PID_NAMESPACE_PARENTS.lock();
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
        let Some(mut inner) = process.try_borrow_mut() else {
            continue;
        };
        inner.wait_queue.retain(|t| !Arc::ptr_eq(t, task));

        for holder in inner.tasks.iter().filter_map(|slot| slot.as_ref()) {
            if Arc::ptr_eq(holder, task) {
                continue;
            }
            if let Some(mut holder_inner) = holder.try_borrow_mut() {
                holder_inner.join_waiters.retain(|w| !Arc::ptr_eq(w, task));
            }
        }

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

fn process_comm_from_argv(argv: &[String]) -> String {
    let src = argv
        .first()
        .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
        .unwrap_or("CongCore");
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmapRegion {
    pub start: usize,
    pub len: usize,
    pub prot: usize,
    pub shared: bool,
    /// False for shared file mappings on descriptors without write access.
    pub may_write_upgrade: bool,
    /// File-backed mapping identity for write/mmap coherence.
    pub file_backed: bool,
    pub file_dev: usize,
    pub file_ino: u32,
    pub file_offset: usize,
    /// Stable backing entry for file-backed mmap writeback after close(fd).
    pub backing_id: usize,
    /// Non-zero for `PseudoShmFile`/memfd-backed mappings.
    pub memfd_id: u64,
    /// Whether this region should expand downward on guard-page faults.
    pub growsdown: bool,
    /// Start address (inclusive) of the SIGBUS tail for file mappings.
    /// `>= end()` means no SIGBUS tail.
    pub sigbus_start: usize,
}

impl MmapRegion {
    pub fn end(&self) -> usize {
        self.start.saturating_add(self.len)
    }
}

lazy_static! {
    /// owner_pid -> processes currently sharing that owner's file table.
    static ref SHARED_FILES_SHARERS: SpinMutex<BTreeMap<usize, Vec<Weak<ProcessControlBlock>>>> =
        SpinMutex::new(BTreeMap::new());
    /// child pid namespace id -> parent pid namespace id.
    static ref PID_NAMESPACE_PARENTS: SpinMutex<BTreeMap<usize, usize>> =
        SpinMutex::new(BTreeMap::new());
}

fn reset_signal_handlers_on_exec(inner: &mut ProcessControlBlockInner) {
    for (signum, action) in inner.rt_sig_handlers.iter_mut().enumerate() {
        if signum == 0 {
            continue;
        }
        if action.handler != SIG_IGN {
            *action = RtSigAction::default();
        }
    }
    for (signum, action) in inner.signals_actions.table.iter_mut().enumerate() {
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
        return build_linux_stack_loongarch(token, sp, args, envs, elf_aux, at_entry, at_base);
    }
    #[cfg(not(target_arch = "loongarch64"))]
    {
        fn write_bytes(token: usize, addr: usize, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                *translated_mutref(token, (addr + i) as *mut u8) = *b;
            }
        }

        fn push_usize(token: usize, sp: &mut usize, value: usize) {
            *sp -= core::mem::size_of::<usize>();
            write_user_value(token, *sp as *mut usize, &value);
        }

        let argc = args.len();
        let envc = envs.len();

        // Push argument and environment strings (top-down).
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
            auxv.push((AT_BASE, at_base));
        }

        // Make the final entry stack pointer 16-byte aligned.
        // Starting from a 16-byte boundary, pushing an odd number of usize words flips alignment.
        let aux_words = (auxv.len() + 1) * 2; // + AT_NULL
        let envp_words = envc + 1; // NULL-terminated
        let argv_words = argc + 1; // NULL-terminated
        let total_words = aux_words + envp_words + argv_words + 1; // + argc
        sp &= !0xf;
        if total_words % 2 == 1 {
            sp -= core::mem::size_of::<usize>();
        }

        // auxv (type, val) pairs, ends with AT_NULL.
        push_usize(token, &mut sp, 0);
        push_usize(token, &mut sp, AT_NULL);
        for (t, v) in auxv.iter().rev() {
            push_usize(token, &mut sp, *v);
            push_usize(token, &mut sp, *t);
        }
        let auxv_base = sp;

        // envp pointers array (envc + 1), with trailing NULL.
        push_usize(token, &mut sp, 0);
        for p in env_ptrs.iter().rev() {
            push_usize(token, &mut sp, *p);
        }
        let envp_base = sp;

        // argv pointers array (argc + 1), with trailing NULL.
        push_usize(token, &mut sp, 0);
        for p in arg_ptrs.iter().rev() {
            push_usize(token, &mut sp, *p);
        }
        let argv_base = sp;

        // argc.
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

fn dump_linux_initial_stack(token: usize, sp: usize) {
    if !DEBUG_SYSCALL {
        return;
    }
    // Best-effort stack dump for diagnosing glibc/ld-linux startup issues.
    let argc = read_user_value(token, sp as *const usize);
    let argv0_ptr = read_user_value(token, (sp + core::mem::size_of::<usize>()) as *const usize);
    let mut argv0 = alloc::string::String::new();
    if argv0_ptr != 0 {
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

    // Walk argv/envp to find auxv.
    let argv_base = sp + core::mem::size_of::<usize>();
    let mut p = argv_base + (argc + 1) * core::mem::size_of::<usize>(); // skip argv + NULL
    // Skip envp pointers (NULL terminated).
    for _ in 0..256usize {
        let v = read_user_value(token, p as *const usize);
        p += core::mem::size_of::<usize>();
        if v == 0 {
            break;
        }
    }
    // Now p points just past envp NULL, i.e. auxv starts here.
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

/// Linux-like scheduler parameters: policy, RT priority, deadline attrs, nice, affinity.
#[derive(Clone)]
pub struct ProcessScheduling {
    pub sched_policy: i32,
    /// Process-wide CPU affinity mask used by `sched_*affinity` and `getcpu`.
    pub cpu_affinity_mask: usize,
    pub sched_priority: i32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
    /// POSIX nice value used by getpriority/setpriority.
    pub nice: i32,
}

// TODO(credentials): ProcessCredentials (uid/euid/suid/fsuid, gid/egid/sgid/fsgid,
// supplementary_gids, cap_*, securebits) has 200+ external access sites; defer to a
// later refactoring pass once the access patterns are stabilised.

pub struct ProcessControlBlock {
    // immutable
    pub pid: PidHandle,
    // mutable
    inner: SpinMutex<ProcessControlBlockInner>,
}

// 进程控制块
// 里面存放线程共用的 资源
pub struct ProcessControlBlockInner {
    pub is_zombie: bool,
    /// Whether the terminating signal should be reported as a core-dumping one.
    pub dumped_core: bool,
    /// Process group ID (PGID).
    pub pgid: usize,
    /// Session ID (SID).
    pub sid: usize,
    /// True after the process has performed at least one execve().
    pub did_exec: bool,
    /// Stop/continue state for waitpid job-control.
    pub stopped: bool,
    pub stop_signal: i32,
    pub stop_pending: bool,
    pub continued: bool,
    /// Tracer pid for basic ptrace support (`PTRACE_TRACEME`).
    pub ptrace_tracer_pid: Option<usize>,
    pub memory_set: MemorySet,
    pub parent: Option<Weak<ProcessControlBlock>>,
    pub children: Vec<Arc<ProcessControlBlock>>,
    pub exit_code: i32,
    /// Linux-like argv for `/proc/<pid>/cmdline` and ps.
    pub argv: Vec<String>,
    /// Thread-group command name shown in /proc/*/{stat,status,comm}.
    pub comm: String,
    /// `PR_SET_PDEATHSIG` setting for this process.
    pub pdeath_signal: i32,
    /// Executable inode identity for ETXTBSY checks on writable opens.
    pub exec_inode_dev: usize,
    pub exec_inode_num: u32,
    /// Current/default timer slack used by `prctl(PR_*_TIMERSLACK)`.
    pub timer_slack_ns: u64,
    pub timer_slack_default_ns: u64,
    /// Process creation time since boot (ms).
    pub start_time_ms: usize,
    /// Accumulated CPU time of reaped children (ns), used by `times(2)`.
    pub child_cpu_time_ns: u64,
    /// Real/effective/saved user IDs and filesystem UID.
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    /// Real/effective/saved group IDs and filesystem GID.
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    /// Supplementary group IDs.
    pub supplementary_gids: Vec<u32>,
    /// Linux capability sets (v2/v3 user API stores up to 64 bits).
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
    /// Capability bounding set used by PR_CAPBSET_DROP checks.
    pub cap_bounding: u64,
    /// Linux personality(2) flags (PER_LINUX by default).
    pub personality: u32,
    /// Per-process I/O priority encoded like Linux `ioprio_get/set(2)`.
    pub ioprio: u16,
    /// Per-process file mode creation mask (umask).
    pub umask: usize,
    //
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    /// Per-fd flags (e.g., FD_CLOEXEC, O_NONBLOCK).
    pub fd_flags: Vec<u32>,
    /// When set, file-descriptor operations are delegated to this owner process
    /// (Linux CLONE_FILES-style shared file table).
    pub files_owner: Option<Weak<ProcessControlBlock>>,
    /// All POSIX resource limits.
    pub rlimits: ProcessResourceLimits,
    /// Process root directory (host-absolute path), used for `chroot`.
    pub root: String,
    pub cwd: String,
    pub heap_start: usize,
    pub brk: usize,
    pub mmap_next: usize,
    pub mmap_areas: Vec<MmapRegion>,
    pub mmap_backings: BTreeMap<usize, Arc<dyn File + Send + Sync>>,
    pub next_mmap_backing_id: usize,
    /// Virtual ranges currently locked by mlock/mlockall.
    pub mlocked_ranges: Vec<(usize, usize)>,
    /// Whether MCL_FUTURE is currently enabled.
    pub mlockall_future: bool,
    /// IPC namespace id used by SysV IPC / POSIX MQ isolation.
    pub ipc_ns_id: usize,
    /// Shared UTS namespace state (hostname/domainname).
    pub uts_ns: Arc<SpinMutex<UtsNamespaceState>>,
    /// Shared mount namespace state used by mount/umount/path view syscalls.
    pub mnt_ns: MountNamespace,
    /// cgroup namespace root path. "/" means the initial namespace.
    pub cgroup_ns_root: String,
    /// PID namespace id; 0 is the initial namespace.
    pub pid_ns_id: usize,
    /// PID visible from within the process's own PID namespace.
    pub pid_ns_vpid: usize,
    /// Whether this process is PID 1 inside its PID namespace.
    pub pid_ns_init: bool,
    /// System V shared memory attachments (shmat/shmdt).
    pub sysv_shm_attaches: Vec<crate::syscall::sysv_shm::ShmAttach>,
    pub signals: SignalFlags,
    pub signals_actions: SignalActions,
    pub signals_masks: SignalFlags,
    pub handling_signal: i32,
    /// Linux rt_sigaction handlers indexed by signal number.
    pub rt_sig_handlers: Vec<RtSigAction>,
    /// Linux-like scheduler state used by rt-tests (cyclictest/hackbench).
    pub scheduling: ProcessScheduling,
    // TaskControlBlock实际上现在是线程
    pub tasks: Vec<Option<Arc<TaskControlBlock>>>,
    // 进程控制块 有一个分配 线程ID的分配器
    pub task_res_allocator: RecycleAllocator,
    pub mutex_list: Vec<Option<Arc<dyn Mutex>>>,
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
    /// Tasks waiting in `waitpid(-1/...)` for this process's children.
    pub wait_queue: VecDeque<Arc<TaskControlBlock>>,
    /// Tasks waiting on pidfd readiness for this process to become waitable.
    pub pidfd_poll_waiters: PollWaitQueue,
}

impl ProcessControlBlockInner {
    fn effective_fd_state_len(&self) -> usize {
        let mut len = self.fd_table.len();
        while len > 0 {
            let idx = len - 1;
            let has_file = self.fd_table[idx].is_some();
            let has_flag = self.fd_flags.get(idx).copied().unwrap_or(0) != 0;
            if has_file || has_flag {
                break;
            }
            len -= 1;
        }
        len
    }

    fn trim_fd_state(&mut self) {
        let len = self.effective_fd_state_len();
        self.fd_table.truncate(len);
        self.fd_flags.truncate(len);
    }

    pub fn snapshot_fd_state(&self) -> (Vec<Option<Arc<dyn File + Send + Sync>>>, Vec<u32>) {
        let len = self.effective_fd_state_len();
        let fd_table = self
            .fd_table
            .iter()
            .take(len)
            .map(|fd| fd.as_ref().map(Arc::clone))
            .collect::<Vec<_>>();
        let mut fd_flags = self.fd_flags.iter().take(len).copied().collect::<Vec<_>>();
        if fd_flags.len() < fd_table.len() {
            fd_flags.resize(fd_table.len(), 0);
        }
        (fd_table, fd_flags)
    }

    fn close_cloexec_fds(&mut self) {
        const FD_CLOEXEC: u32 = 1;
        self.ensure_fd_flags_len();
        for (idx, flags) in self.fd_flags.iter_mut().enumerate() {
            if (*flags & FD_CLOEXEC) != 0 {
                self.fd_table[idx] = None;
                *flags = 0;
            }
        }
        self.trim_fd_state();
    }

    /// Keep `fd_flags` aligned with `fd_table` length.
    pub fn ensure_fd_flags_len(&mut self) {
        if self.fd_flags.len() < self.fd_table.len() {
            self.fd_flags.resize(self.fd_table.len(), 0);
        }
    }

    /// True when `fd` currently refers to an open file descriptor.
    pub fn is_fd_open(&self, fd: usize) -> bool {
        fd < self.fd_table.len() && self.fd_table[fd].is_some()
    }

    /// Close an fd slot and clear its per-fd flags.
    ///
    /// Returns `false` if `fd` is out of range.
    pub fn clear_fd(&mut self, fd: usize) -> bool {
        if fd >= self.fd_table.len() {
            return false;
        }
        self.fd_table[fd] = None;
        self.ensure_fd_flags_len();
        self.fd_flags[fd] = 0;
        self.trim_fd_state();
        true
    }

    #[allow(unused)]
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }

    pub fn alloc_fd(&mut self) -> Option<usize> {
        let limit = self.rlimits.rlimit_nofile_cur as usize;
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            if fd >= limit {
                return None;
            }
            self.ensure_fd_flags_len();
            self.fd_flags[fd] = 0;
            Some(fd)
        } else {
            if self.fd_table.len() >= limit {
                return None;
            }
            self.fd_table.push(None);
            self.fd_flags.push(0);
            Some(self.fd_table.len() - 1)
        }
    }

    pub fn alloc_tid(&mut self) -> usize {
        self.task_res_allocator.alloc()
    }

    pub fn dealloc_tid(&mut self, _tid: usize) {
        // Keep thread IDs monotonic within a process to avoid immediate reuse.
        // Linux TIDs are globally unique for a long period; reusing tiny per-process
        // indexes too early breaks gettid-based uniqueness checks in pthread tests.
    }

    pub fn thread_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| {
                t.as_ref()
                    .map(|t| t.borrow_mut().res.is_some())
                    .unwrap_or(false)
            })
            .count()
    }

    pub fn get_task(&self, tid: usize) -> Arc<TaskControlBlock> {
        self.tasks[tid].as_ref().unwrap().clone()
    }
}

impl ProcessControlBlock {
    fn register_files_sharer(owner: &Arc<Self>, sharer: &Arc<Self>) {
        if Arc::ptr_eq(owner, sharer) {
            return;
        }
        let mut map = SHARED_FILES_SHARERS.lock();
        let entry = map.entry(owner.getpid()).or_default();
        entry.retain(|w| w.upgrade().is_some());
        if entry
            .iter()
            .filter_map(Weak::upgrade)
            .any(|p| Arc::ptr_eq(&p, sharer))
        {
            return;
        }
        entry.push(Arc::downgrade(sharer));
    }

    fn unregister_files_sharer(owner_pid: usize, sharer: &Arc<Self>) {
        let mut map = SHARED_FILES_SHARERS.lock();
        let Some(entry) = map.get_mut(&owner_pid) else {
            return;
        };
        entry.retain(|w| w.upgrade().is_some_and(|p| !Arc::ptr_eq(&p, sharer)));
        if entry.is_empty() {
            map.remove(&owner_pid);
        }
    }

    fn clone_fd_table(
        src: &[Option<Arc<dyn File + Send + Sync>>],
    ) -> Vec<Option<Arc<dyn File + Send + Sync>>> {
        src.iter()
            .map(|fd| fd.as_ref().map(Arc::clone))
            .collect::<Vec<_>>()
    }

    /// If this process owns a shared file table and exits, transfer ownership
    /// to one alive sharer so CLONE_FILES users keep Linux-like semantics.
    pub fn handoff_files_owner_on_exit(self: &Arc<Self>) {
        let sharers = {
            let mut map = SHARED_FILES_SHARERS.lock();
            map.remove(&self.getpid()).unwrap_or_default()
        };
        if sharers.is_empty() {
            return;
        }
        let mut alive = sharers
            .into_iter()
            .filter_map(|w| w.upgrade())
            .filter(|p| !Arc::ptr_eq(p, self))
            .collect::<Vec<_>>();
        if alive.is_empty() {
            return;
        }

        let (fd_table, fd_flags) = {
            let inner = self.borrow_mut();
            inner.snapshot_fd_state()
        };

        let new_owner = alive.swap_remove(0);
        {
            let mut inner = new_owner.borrow_mut();
            inner.fd_table = Self::clone_fd_table(fd_table.as_slice());
            inner.fd_flags = fd_flags.clone();
            inner.files_owner = None;
        }

        let mut reassigned = Vec::new();
        for sharer in alive {
            {
                let mut inner = sharer.borrow_mut();
                inner.fd_table = Self::clone_fd_table(fd_table.as_slice());
                inner.fd_flags = fd_flags.clone();
                inner.files_owner = Some(Arc::downgrade(&new_owner));
            }
            reassigned.push(Arc::downgrade(&sharer));
        }

        if !reassigned.is_empty() {
            let mut map = SHARED_FILES_SHARERS.lock();
            let entry = map.entry(new_owner.getpid()).or_default();
            entry.retain(|w| w.upgrade().is_some());
            entry.extend(reassigned);
        }
    }

    fn terminate_other_threads(&self) {
        let current = current_task();
        let current_ptr = current.as_ref().map(Arc::as_ptr);
        let mut to_cleanup = Vec::new();
        {
            let mut inner = self.borrow_mut();
            for slot in inner.tasks.iter_mut() {
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
        for task in to_cleanup {
            remove_inactive_task(task.clone());
            let (res, join_waiters) = {
                let mut inner = task.borrow_mut();
                inner.exit_code = Some(0);
                let res = inner.res.take();
                let join_waiters = inner.join_waiters.drain(..).collect::<Vec<_>>();
                (res, join_waiters)
            };
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

    /// Resolve the process that currently owns this process's file table.
    pub fn files_owner_process(self: &Arc<Self>) -> Arc<Self> {
        let direct_owner = {
            let mut inner = self.borrow_mut();
            let owner = inner.files_owner.as_ref().and_then(Weak::upgrade);
            if owner.is_none() {
                inner.files_owner = None;
            }
            owner
        };
        if let Some(owner) = direct_owner {
            if Arc::ptr_eq(&owner, self) {
                return Arc::clone(self);
            }
            return owner;
        }
        Arc::clone(self)
    }

    /// Materialize a private fd table for this process when it currently
    /// shares another process's table (close_range UNSHARE semantics).
    pub fn unshare_files(self: &Arc<Self>) {
        let owner = self.files_owner_process();
        if Arc::ptr_eq(&owner, self) {
            return;
        }
        let (fd_table, fd_flags) = {
            let owner_inner = owner.borrow_mut();
            owner_inner.snapshot_fd_state()
        };
        let mut unshared = false;
        {
            let mut inner = self.borrow_mut();
            if inner.files_owner.is_some() {
                inner.fd_table = fd_table;
                inner.fd_flags = fd_flags;
                inner.files_owner = None;
                unshared = true;
            }
        }
        if unshared {
            Self::unregister_files_sharer(owner.getpid(), self);
        }
    }

    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, ustack_base, entry_point, elf_aux) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        let heap_start = ustack_base + USER_STACK_SIZE + USER_HEAP_GAP;
        // allocate a pid
        let pid_handle = pid_alloc();
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
                memory_set,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                argv: args.clone(),
                comm: process_comm_from_argv(&args),
                pdeath_signal: 0,
                exec_inode_dev: 0,
                exec_inode_num: 0,
                timer_slack_ns: DEFAULT_TIMER_SLACK_NS,
                timer_slack_default_ns: DEFAULT_TIMER_SLACK_NS,
                start_time_ms: crate::time::get_time_ms(),
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
                personality: 0,
                ioprio: 0,
                umask: 0,
                fd_table: vec![
                    // 0 -> stdin
                    Some(Arc::new(Stdin)),
                    // 1 -> stdout
                    Some(Arc::new(Stdout)),
                    // 2 -> stderr
                    Some(Arc::new(Stdout)),
                ],
                fd_flags: vec![0; 3],
                files_owner: None,
                rlimits: ProcessResourceLimits {
                    rlimit_nofile_cur: 1024,
                    rlimit_nofile_max: 1024,
                    rlimit_nproc_cur: u64::MAX,
                    rlimit_nproc_max: u64::MAX,
                    rlimit_fsize_cur: u64::MAX,
                    rlimit_fsize_max: u64::MAX,
                    rlimit_data_cur: u64::MAX,
                    rlimit_data_max: u64::MAX,
                    rlimit_stack_cur: 1 * 1024 * 1024,
                    rlimit_stack_max: 1 * 1024 * 1024,
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
                heap_start,
                brk: heap_start,
                // Keep anonymous/file mmaps high to avoid colliding with ELF segments.
                mmap_next: DEFAULT_MMAP_BASE,
                mmap_areas: Vec::new(),
                mmap_backings: BTreeMap::new(),
                next_mmap_backing_id: 1,
                mlocked_ranges: Vec::new(),
                mlockall_future: false,
                ipc_ns_id: 0,
                uts_ns: Arc::new(SpinMutex::new(UtsNamespaceState::new())),
                mnt_ns: initial_mount_namespace(),
                cgroup_ns_root: String::from("/"),
                pid_ns_id: 0,
                pid_ns_vpid: pid,
                pid_ns_init: false,
                sysv_shm_attaches: Vec::new(),
                signals: SignalFlags::empty(),
                signals_actions: SignalActions::default(),
                signals_masks: SignalFlags::empty(),
                handling_signal: -1,
                rt_sig_handlers: vec![RtSigAction::default(); RT_SIG_MAX + 1],
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
                },
                tasks: Vec::new(),
                task_res_allocator: RecycleAllocator::new(),
                mutex_list: Vec::new(),
                semaphore_list: Vec::new(),
                condvar_list: Vec::new(),
                wait_queue: VecDeque::new(),
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
        let mut process_inner = process.borrow_mut();
        process_inner.tasks.push(Some(Arc::clone(&task)));
        drop(process_inner);
        insert_into_pid2process(process.getpid(), Arc::clone(&process));
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
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>, envs: Vec<String>) {
        let (memory_set, ustack_base, entry_point, elf_aux) = MemorySet::from_elf(elf_data);
        self.exec_with_memory_set(
            memory_set,
            ustack_base,
            entry_point,
            args,
            envs,
            elf_aux,
            (0, 0),
        );
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
    ) {
        let (memory_set, ustack_base, interp_entry, main_entry, main_aux, interp_base) =
            MemorySet::from_elf_with_interp(elf_data, interp_data);
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
            (0, 0),
        );
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
    ) {
        // Linux execve unshares CLONE_FILES state before applying CLOEXEC.
        self.unshare_files();
        let thread_count = { self.borrow_mut().thread_count() };
        if thread_count != 1 {
            log::warn!(
                "[exec] pid={} thread_count={} (terminating other threads)",
                self.getpid(),
                thread_count
            );
            self.terminate_other_threads();
        }
        let new_token = memory_set.token();
        let heap_start = ustack_base + USER_STACK_SIZE + USER_HEAP_GAP;
        {
            let mut inner = self.borrow_mut();
            inner.close_cloexec_fds();
            let old_shm = core::mem::take(&mut inner.sysv_shm_attaches);
            crate::syscall::sysv_shm::exit_cleanup(inner.ipc_ns_id, &old_shm);
            reset_signal_handlers_on_exec(&mut inner);
            inner.memory_set = memory_set;
            inner.heap_start = heap_start;
            inner.brk = heap_start;
            inner.mmap_next = DEFAULT_MMAP_BASE;
            inner.mmap_areas.clear();
            inner.mlocked_ranges.clear();
            inner.mlockall_future = false;
            inner.argv = args.clone();
            inner.comm = process_comm_from_argv(&args);
            let mut executing_inodes = crate::syscall::process::lock_executing_inodes();
            crate::syscall::process::unregister_executing_inode_locked(
                &mut executing_inodes,
                inner.exec_inode_dev,
                inner.exec_inode_num,
            );
            inner.exec_inode_dev = exec_inode.0;
            inner.exec_inode_num = exec_inode.1;
            crate::syscall::process::register_executing_inode_locked(
                &mut executing_inodes,
                exec_inode.0,
                exec_inode.1,
            );
            inner.did_exec = true;
        }
        let task = self.borrow_mut().get_task(0);
        let mut task_inner = task.borrow_mut();
        let res = task_inner.res.as_mut().unwrap();
        res.ustack_base = ustack_base;
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
    ) {
        // Linux execve unshares CLONE_FILES state before applying CLOEXEC.
        self.unshare_files();
        let thread_count = { self.borrow_mut().thread_count() };
        if thread_count != 1 {
            log::warn!(
                "[exec_dyn] pid={} thread_count={} (terminating other threads)",
                self.getpid(),
                thread_count
            );
            self.terminate_other_threads();
        }
        let new_token = memory_set.token();
        let heap_start = ustack_base + USER_STACK_SIZE + USER_HEAP_GAP;
        {
            let mut inner = self.borrow_mut();
            inner.close_cloexec_fds();
            let old_shm = core::mem::take(&mut inner.sysv_shm_attaches);
            crate::syscall::sysv_shm::exit_cleanup(inner.ipc_ns_id, &old_shm);
            reset_signal_handlers_on_exec(&mut inner);
            inner.memory_set = memory_set;
            inner.heap_start = heap_start;
            inner.brk = heap_start;
            inner.mmap_next = DEFAULT_MMAP_BASE;
            inner.mmap_areas.clear();
            inner.mlocked_ranges.clear();
            inner.mlockall_future = false;
            inner.argv = args.clone();
            inner.comm = process_comm_from_argv(&args);
            let mut executing_inodes = crate::syscall::process::lock_executing_inodes();
            crate::syscall::process::unregister_executing_inode_locked(
                &mut executing_inodes,
                inner.exec_inode_dev,
                inner.exec_inode_num,
            );
            inner.exec_inode_dev = exec_inode.0;
            inner.exec_inode_num = exec_inode.1;
            crate::syscall::process::register_executing_inode_locked(
                &mut executing_inodes,
                exec_inode.0,
                exec_inode.1,
            );
            inner.did_exec = true;
        }

        // Workaround glibc ld-linux early crash by seeding an internal cached
        // DT_SYMTAB dynamic-entry pointer before entering the interpreter.
        patch_glibc_ld_linux_symtab_dyn(new_token, interp_base, interp_data);

        let task = self.borrow_mut().get_task(0);
        let mut task_inner = task.borrow_mut();
        let res = task_inner.res.as_mut().unwrap();
        res.ustack_base = ustack_base;
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
    }

    fn fork_impl(
        self: &Arc<Self>,
        share_files: bool,
        share_vm: bool,
    ) -> Option<(Arc<Self>, Arc<TaskControlBlock>)> {
        let diag_enabled = DEBUG_FUTEX;
        let fork_start_cycles = if diag_enabled {
            crate::arch::read_time()
        } else {
            0
        };
        let mut after_mem_cycles = fork_start_cycles;
        let mut after_pcb_cycles = fork_start_cycles;
        let mut after_task_cycles = fork_start_cycles;

        let mut parent = self.borrow_mut();
        let thread_count = parent.thread_count();
        if thread_count != 1 {
            log::warn!(
                "[fork] pid={} thread_count={} (forking only current thread)",
                self.getpid(),
                thread_count
            );
        }
        let sched_policy = parent.scheduling.sched_policy;
        let sched_priority = parent.scheduling.sched_priority;
        let sched_runtime = parent.scheduling.sched_runtime;
        let sched_deadline = parent.scheduling.sched_deadline;
        let sched_period = parent.scheduling.sched_period;
        let nice = parent.scheduling.nice;
        let rt_sig_handlers = parent.rt_sig_handlers.clone();
        let argv = parent.argv.clone();
        let inherited_shm = parent.sysv_shm_attaches.clone();
        if crate::debug_config::DEBUG_PID_MAP {
            let seq = FORK_PRE_COW_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if seq <= 8 || (seq & (seq - 1)) == 0 {
                let (areas, data_frames, ident_vpns, lazy_areas, framed_areas, ident_areas) =
                    parent.memory_set.cow_diag_stats();
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
        // Fork address space (COW by default, full copy on LoongArch).
        let caller_tid = crate::task::processor::current_task()
            .and_then(|t| t.borrow_mut().res.as_ref().map(|r| r.tid))
            .unwrap_or(0);
        #[cfg(target_arch = "loongarch64")]
        let mut memory_set = if DEBUG_LOONGARCH_FULL_COPY_FORK {
            MemorySet::from_existed_user(&parent.memory_set)
        } else if share_vm {
            MemorySet::from_existed_user_shared(&parent.memory_set)
        } else {
            MemorySet::from_existed_user_cow(&mut parent.memory_set)
        };
        #[cfg(not(target_arch = "loongarch64"))]
        let mut memory_set = if share_vm {
            MemorySet::from_existed_user_shared(&parent.memory_set)
        } else {
            MemorySet::from_existed_user_cow(&mut parent.memory_set)
        };
        if thread_count > 1 {
            for task in parent.tasks.iter().filter_map(|t| t.as_ref()) {
                let mut task_inner = task.borrow_mut();
                let Some(res) = task_inner.res.as_ref() else {
                    continue;
                };
                if res.tid == 0 {
                    continue;
                }
                let trap_cx_bottom = TRAP_CONTEXT_BASE - res.tid * PAGE_SIZE;
                memory_set.remove_area_with_start_vpn(trap_cx_bottom.into());
            }
        }
        if diag_enabled {
            after_mem_cycles = crate::arch::read_time();
        }
        // alloc a pid
        let pid = pid_alloc();
        let pid_value = pid.0;
        let inherited_owner = parent.files_owner.as_ref().and_then(Weak::upgrade);
        if parent.files_owner.is_some() && inherited_owner.is_none() {
            parent.files_owner = None;
        }
        let (new_fd_table, new_fd_flags) = if let Some(owner) = inherited_owner.as_ref() {
            if Arc::ptr_eq(owner, self) {
                parent.snapshot_fd_state()
            } else {
                let owner_inner = owner.borrow_mut();
                owner_inner.snapshot_fd_state()
            }
        } else {
            parent.snapshot_fd_state()
        };
        let root_files_owner = inherited_owner
            .as_ref()
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::clone(self));
        let child_files_owner = if share_files {
            Some(Arc::downgrade(&root_files_owner))
        } else {
            None
        };
        // Remember parent's user-stack base for the calling thread.
        let parent_ustack_base = crate::task::processor::current_task()
            .and_then(|t| t.borrow_mut().res.as_ref().map(|r| r.ustack_base()))
            .unwrap_or_else(|| {
                parent
                    .get_task(0)
                    .borrow_mut()
                    .res
                    .as_ref()
                    .unwrap()
                    .ustack_base()
            });

        // create child process pcb
        let child = Arc::new(Self {
            pid,
            inner: SpinMutex::new(ProcessControlBlockInner {
                is_zombie: false,
                dumped_core: false,
                pgid: parent.pgid,
                sid: parent.sid,
                did_exec: false,
                stopped: false,
                stop_signal: 0,
                stop_pending: false,
                continued: false,
                ptrace_tracer_pid: None,
                memory_set,
                parent: Some(Arc::downgrade(self)),
                children: Vec::new(),
                exit_code: 0,
                argv,
                comm: parent.comm.clone(),
                pdeath_signal: 0,
                timer_slack_ns: parent.timer_slack_ns,
                timer_slack_default_ns: parent.timer_slack_ns,
                start_time_ms: crate::time::get_time_ms(),
                child_cpu_time_ns: 0,
                uid: parent.uid,
                euid: parent.euid,
                suid: parent.suid,
                fsuid: parent.fsuid,
                gid: parent.gid,
                egid: parent.egid,
                sgid: parent.sgid,
                fsgid: parent.fsgid,
                supplementary_gids: parent.supplementary_gids.clone(),
                cap_effective: parent.cap_effective,
                cap_permitted: parent.cap_permitted,
                cap_inheritable: parent.cap_inheritable,
                cap_bounding: parent.cap_bounding,
                personality: parent.personality,
                ioprio: parent.ioprio,
                umask: parent.umask,
                fd_table: new_fd_table,
                fd_flags: new_fd_flags,
                files_owner: child_files_owner,
                rlimits: parent.rlimits.clone(),
                root: parent.root.clone(),
                cwd: parent.cwd.clone(),
                heap_start: parent.heap_start,
                brk: parent.brk,
                mmap_next: parent.mmap_next,
                mmap_areas: parent.mmap_areas.clone(),
                mmap_backings: parent.mmap_backings.clone(),
                next_mmap_backing_id: parent.next_mmap_backing_id,
                // Linux does not inherit mlock/mlockall locks across fork.
                mlocked_ranges: Vec::new(),
                mlockall_future: false,
                ipc_ns_id: parent.ipc_ns_id,
                uts_ns: Arc::clone(&parent.uts_ns),
                mnt_ns: Arc::clone(&parent.mnt_ns),
                cgroup_ns_root: parent.cgroup_ns_root.clone(),
                pid_ns_id: parent.pid_ns_id,
                pid_ns_vpid: pid_value,
                pid_ns_init: false,
                sysv_shm_attaches: inherited_shm.clone(),
                exec_inode_dev: parent.exec_inode_dev,
                exec_inode_num: parent.exec_inode_num,
                // is right here?
                signals: SignalFlags::empty(),
                signals_actions: SignalActions::default(),
                signals_masks: SignalFlags::empty(),
                handling_signal: -1,
                rt_sig_handlers,
                scheduling: ProcessScheduling {
                    sched_policy,
                    cpu_affinity_mask: parent.scheduling.cpu_affinity_mask,
                    sched_priority,
                    sched_runtime,
                    sched_deadline,
                    sched_period,
                    nice,
                },
                tasks: Vec::new(),
                task_res_allocator: RecycleAllocator::new(),
                mutex_list: Vec::new(),
                semaphore_list: Vec::new(),
                condvar_list: Vec::new(),
                wait_queue: VecDeque::new(),
                pidfd_poll_waiters: PollWaitQueue::default(),
            }),
        });
        if share_files {
            Self::register_files_sharer(&root_files_owner, &child);
        }
        crate::syscall::sysv_shm::fork_inherit(parent.ipc_ns_id, &inherited_shm);
        if diag_enabled {
            after_pcb_cycles = crate::arch::read_time();
        }

        // Drop parent lock before allocating child task resources.
        drop(parent);

        // create main thread of child process (allocates a fresh kernel stack)
        let task = match TaskControlBlock::try_new(
            Arc::clone(&child),
            parent_ustack_base,
            // here we do not allocate trap_cx or ustack again
            // but mention that we allocate a new kstack here
            false,
        ) {
            Some(task) => Arc::new(task),
            None => return None,
        };
        // Distribute child processes across harts.
        task.set_cpu_id(select_hart_for_new_task());
        // attach task to child process
        let mut child_inner = child.borrow_mut();
        child_inner.tasks.push(Some(Arc::clone(&task)));
        drop(child_inner);
        // Publish the child before cgroup inheritance so per-thread membership
        // can resolve the freshly created main task.
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        cgroup_attach_fork_child(self.getpid(), child.getpid());
        // Seed trap context from the calling thread when available.
        let parent_trap_cx =
            crate::task::processor::current_task().map(|t| *t.borrow_mut().get_trap_cx());
        // modify kstack_top in trap_cx of this thread
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        if let Some(parent_trap_cx) = parent_trap_cx {
            *trap_cx = parent_trap_cx;
        }
        trap_cx.kernel_sp = task.kstack_top();
        // set return value for child process
        trap_cx.x[REG_A0] = 0;
        if caller_tid != 0 {
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
        self.borrow_mut().children.push(Arc::clone(&child));
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
        Some((child, task))
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Option<Arc<Self>> {
        let (child, task) = self.fork_impl(false, false)?;
        // add this thread to scheduler
        add_task(task);
        Some(child)
    }

    /// Fork and return both the child process and its main task, without scheduling it.
    pub fn fork_with_task(
        self: &Arc<Self>,
        share_files: bool,
        share_vm: bool,
    ) -> Option<(Arc<Self>, Arc<TaskControlBlock>)> {
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
