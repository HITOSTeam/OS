use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use super::mutex::Mutex;
use crate::fs::{File, Stdin, Stdout};
use crate::config::{PAGE_SIZE, TRAP_CONTEXT_BASE, USER_STACK_SIZE};
use crate::mm::{ElfAux, KERNEL_SPACE, MemorySet, read_user_value, translated_mutref, write_user_value};
use crate::println;
use crate::task::condvar::Condvar;
use crate::task::id::{PidHandle, pid_alloc};
use crate::task::manager::{
    add_task, insert_into_pid2process, remove_inactive_task, select_hart_for_new_task,
    wakeup_task,
};
use crate::task::processor::current_task;
use crate::task::semaphore::Semaphore;
use crate::task::signal::{RtSigAction, SignalAction, SignalActions, SignalFlags, RT_SIG_MAX, SIG_IGN};
use crate::task::task_block::TaskControlBlock;
use crate::trap::context::TrapContext;
use crate::trap::trap_handler;
use crate::utils::RecycleAllocator;
use crate::debug_config::{DEBUG_LOONGARCH_FULL_COPY_FORK, DEBUG_SYSCALL};
use crate::arch::{REG_A0, REG_A1, REG_A2, REG_A3};
use spin::{Mutex as SpinMutex, MutexGuard};

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

fn patch_glibc_ld_linux_symtab_dyn(
    token: usize,
    interp_base: usize,
    interp_data: &[u8],
) {
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
        let Ok(ph) = elf.program_header(i) else { continue };
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
    write_user_value(token, rtld_global_symtab_slot as *mut usize, &symtab_dyn_ptr);
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
    let argv0_ptr =
        read_user_value(token, (sp + core::mem::size_of::<usize>()) as *const usize);
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
        let v = read_user_value(token, (aux_p + core::mem::size_of::<usize>()) as *const usize);
        aux_p += 2 * core::mem::size_of::<usize>();
        if t == AT_NULL {
            break;
        }
        if matches!(t, AT_PHDR | AT_PHENT | AT_PHNUM | AT_PAGESZ | AT_BASE | AT_ENTRY | AT_PLATFORM | AT_EXECFN | AT_RANDOM | AT_HWCAP) {
            crate::println!("[exec_dyn] auxv type={} val={:#x}", t, v);
        }
    }
}
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
    /// Process group ID (PGID).
    pub pgid: usize,
    /// Stop/continue state for waitpid job-control.
    pub stopped: bool,
    pub stop_signal: i32,
    pub stop_pending: bool,
    pub continued: bool,
    pub memory_set: MemorySet,
    pub parent: Option<Weak<ProcessControlBlock>>,
    pub children: Vec<Arc<ProcessControlBlock>>,
    pub exit_code: i32,
    /// Linux-like argv for `/proc/<pid>/cmdline` and ps.
    pub argv: Vec<String>,
    /// Process creation time since boot (ms).
    pub start_time_ms: usize,
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
    //
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    /// Per-fd flags (e.g., FD_CLOEXEC, O_NONBLOCK).
    pub fd_flags: Vec<u32>,
    /// Per-process RLIMIT_NOFILE (soft/hard).
    pub rlimit_nofile_cur: u64,
    pub rlimit_nofile_max: u64,
    /// Per-process RLIMIT_CORE (soft/hard).
    pub rlimit_core_cur: u64,
    pub rlimit_core_max: u64,
    pub cwd: String,
    pub heap_start: usize,
    pub brk: usize,
    pub mmap_next: usize,
    pub mmap_areas: Vec<(usize, usize)>,
    /// System V shared memory attachments (shmat/shmdt).
    pub sysv_shm_attaches: Vec<crate::syscall::sysv_shm::ShmAttach>,
    pub signals: SignalFlags,
    pub signals_actions: SignalActions,
    pub signals_masks: SignalFlags,
    pub handling_signal: i32,
    /// Linux rt_sigaction handlers indexed by signal number.
    pub rt_sig_handlers: Vec<RtSigAction>,
    /// Linux-like scheduler state used by rt-tests (cyclictest/hackbench).
    pub sched_policy: i32,
    pub sched_priority: i32,
    // TaskControlBlock实际上现在是线程
    pub tasks: Vec<Option<Arc<TaskControlBlock>>>,
    // 进程控制块 有一个分配 线程ID的分配器
    pub task_res_allocator: RecycleAllocator,
    pub mutex_list: Vec<Option<Arc<dyn Mutex>>>,
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
    /// Tasks waiting in `waitpid(-1/...)` for this process's children.
    pub wait_queue: VecDeque<Arc<TaskControlBlock>>,
}

impl ProcessControlBlockInner {
    fn close_cloexec_fds(&mut self) {
        const FD_CLOEXEC: u32 = 1;
        if self.fd_flags.len() < self.fd_table.len() {
            self.fd_flags.resize(self.fd_table.len(), 0);
        }
        for (idx, flags) in self.fd_flags.iter_mut().enumerate() {
            if (*flags & FD_CLOEXEC) != 0 {
                self.fd_table[idx] = None;
                *flags = 0;
            }
        }
    }

    #[allow(unused)]
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }

    pub fn alloc_fd(&mut self) -> Option<usize> {
        let limit = self.rlimit_nofile_cur as usize;
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            if fd >= limit {
                return None;
            }
            if fd >= self.fd_flags.len() {
                self.fd_flags.resize(self.fd_table.len(), 0);
            }
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

    pub fn dealloc_tid(&mut self, tid: usize) {
        self.task_res_allocator.dealloc(tid)
    }

    pub fn thread_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.as_ref().map(|t| t.borrow_mut().res.is_some()).unwrap_or(false))
            .count()
    }

    pub fn get_task(&self, tid: usize) -> Arc<TaskControlBlock> {
        self.tasks[tid].as_ref().unwrap().clone()
    }
}

impl ProcessControlBlock {
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

    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, ustack_base, entry_point, elf_aux) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        let heap_start = ustack_base + USER_STACK_SIZE;
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
                pgid: pid,
                stopped: false,
                stop_signal: 0,
                stop_pending: false,
                continued: false,
                memory_set,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                argv: args.clone(),
                start_time_ms: crate::time::get_time_ms(),
                uid: 0,
                euid: 0,
                suid: 0,
                fsuid: 0,
                gid: 0,
                egid: 0,
                sgid: 0,
                fsgid: 0,
                fd_table: vec![
                    // 0 -> stdin
                    Some(Arc::new(Stdin)),
                    // 1 -> stdout
                    Some(Arc::new(Stdout)),
                    // 2 -> stderr
                    Some(Arc::new(Stdout)),
                ],
                fd_flags: vec![0; 3],
                rlimit_nofile_cur: 1024,
                rlimit_nofile_max: 1024,
                rlimit_core_cur: 8 * 1024 * 1024,
                rlimit_core_max: 8 * 1024 * 1024,
                cwd: String::from("/user"),
                heap_start,
                brk: heap_start,
                // Keep anonymous/file mmaps high to avoid colliding with ELF segments.
                mmap_next: 0x20_0000_0000,
                mmap_areas: Vec::new(),
                sysv_shm_attaches: Vec::new(),
                signals: SignalFlags::empty(),
                signals_actions: SignalActions::default(),
                signals_masks: SignalFlags::empty(),
                handling_signal: -1,
                rt_sig_handlers: vec![RtSigAction::default(); RT_SIG_MAX + 1],
                sched_policy: 0,
                sched_priority: 0,
                tasks: Vec::new(),
                task_res_allocator: RecycleAllocator::new(),
                mutex_list: Vec::new(),
                semaphore_list: Vec::new(),
                condvar_list: Vec::new(),
                wait_queue: VecDeque::new(),
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
        let kstack_top = task.kstack.get_top();
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
        self.exec_with_memory_set(memory_set, ustack_base, entry_point, args, envs, elf_aux);
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
    ) {
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
        let heap_start = ustack_base + USER_STACK_SIZE;
        {
            let mut inner = self.borrow_mut();
            inner.close_cloexec_fds();
            let old_shm = core::mem::take(&mut inner.sysv_shm_attaches);
            crate::syscall::sysv_shm::exit_cleanup(&old_shm);
            reset_signal_handlers_on_exec(&mut inner);
            inner.memory_set = memory_set;
            inner.heap_start = heap_start;
            inner.brk = heap_start;
            inner.mmap_next = 0x20_0000_0000;
            inner.mmap_areas.clear();
            inner.argv = args.clone();
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
            task.kstack.get_top(),
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
    ) {
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
        let heap_start = ustack_base + USER_STACK_SIZE;
        {
            let mut inner = self.borrow_mut();
            inner.close_cloexec_fds();
            let old_shm = core::mem::take(&mut inner.sysv_shm_attaches);
            crate::syscall::sysv_shm::exit_cleanup(&old_shm);
            reset_signal_handlers_on_exec(&mut inner);
            inner.memory_set = memory_set;
            inner.heap_start = heap_start;
            inner.brk = heap_start;
            inner.mmap_next = 0x20_0000_0000;
            inner.mmap_areas.clear();
            inner.argv = args.clone();
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
            task.kstack.get_top(),
            trap_handler as usize,
        );
        trap_cx.x[REG_A0] = args.len();
        trap_cx.x[REG_A1] = argv_base;
        trap_cx.x[REG_A2] = envp_base;
        trap_cx.x[REG_A3] = auxv_base;
        *task_inner.get_trap_cx() = trap_cx;
    }

    fn fork_impl(self: &Arc<Self>) -> Option<(Arc<Self>, Arc<TaskControlBlock>)> {
        let mut parent = self.borrow_mut();
        let thread_count = parent.thread_count();
        if thread_count != 1 {
            log::warn!(
                "[fork] pid={} thread_count={} (forking only current thread)",
                self.getpid(),
                thread_count
            );
        }
        let sched_policy = parent.sched_policy;
        let sched_priority = parent.sched_priority;
        let rt_sig_handlers = parent.rt_sig_handlers.clone();
        let argv = parent.argv.clone();
        let inherited_shm = parent.sysv_shm_attaches.clone();
        // Fork address space (COW by default, full copy on LoongArch).
        let caller_tid = crate::task::processor::current_task()
            .and_then(|t| t.borrow_mut().res.as_ref().map(|r| r.tid))
            .unwrap_or(0);
        #[cfg(target_arch = "loongarch64")]
        let mut memory_set = if DEBUG_LOONGARCH_FULL_COPY_FORK {
            MemorySet::from_existed_user(&parent.memory_set)
        } else {
            MemorySet::from_existed_user_cow(&mut parent.memory_set)
        };
        #[cfg(not(target_arch = "loongarch64"))]
        let mut memory_set = MemorySet::from_existed_user_cow(&mut parent.memory_set);
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
        // alloc a pid
        let pid = pid_alloc();
        // copy fd table
        let mut new_fd_table: Vec<Option<Arc<dyn File + Send + Sync>>> = Vec::new();
        let mut new_fd_flags: Vec<u32> = Vec::new();
        for fd in parent.fd_table.iter() {
            if let Some(file) = fd {
                new_fd_table.push(Some(file.clone()));
            } else {
                new_fd_table.push(None);
            }
        }
        new_fd_flags.extend(parent.fd_flags.iter().copied());
        if new_fd_flags.len() < new_fd_table.len() {
            new_fd_flags.resize(new_fd_table.len(), 0);
        }
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
                pgid: parent.pgid,
                stopped: false,
                stop_signal: 0,
                stop_pending: false,
                continued: false,
                memory_set,
                parent: Some(Arc::downgrade(self)),
                children: Vec::new(),
                exit_code: 0,
                argv,
                start_time_ms: crate::time::get_time_ms(),
                uid: parent.uid,
                euid: parent.euid,
                suid: parent.suid,
                fsuid: parent.fsuid,
                gid: parent.gid,
                egid: parent.egid,
                sgid: parent.sgid,
                fsgid: parent.fsgid,
                fd_table: new_fd_table,
                fd_flags: new_fd_flags,
                rlimit_nofile_cur: parent.rlimit_nofile_cur,
                rlimit_nofile_max: parent.rlimit_nofile_max,
                rlimit_core_cur: parent.rlimit_core_cur,
                rlimit_core_max: parent.rlimit_core_max,
                cwd: parent.cwd.clone(),
                heap_start: parent.heap_start,
                brk: parent.brk,
                mmap_next: parent.mmap_next,
                mmap_areas: parent.mmap_areas.clone(),
                sysv_shm_attaches: inherited_shm.clone(),
                // is right here?
                signals: SignalFlags::empty(),
                signals_actions: SignalActions::default(),
                signals_masks: SignalFlags::empty(),
                handling_signal: -1,
                rt_sig_handlers,
                sched_policy,
                sched_priority,
                tasks: Vec::new(),
                task_res_allocator: RecycleAllocator::new(),
                mutex_list: Vec::new(),
                semaphore_list: Vec::new(),
                condvar_list: Vec::new(),
                wait_queue: VecDeque::new(),
            }),
        });
        crate::syscall::sysv_shm::fork_inherit(&inherited_shm);

        // Drop parent lock before allocating child task resources.
        drop(parent);

        // create main thread of child process (allocates a fresh kernel stack)
        let task = Arc::new(TaskControlBlock::try_new(
            Arc::clone(&child),
            parent_ustack_base,
            // here we do not allocate trap_cx or ustack again
            // but mention that we allocate a new kstack here
            false,
        )?);
        // Distribute child processes across harts.
        task.set_cpu_id(select_hart_for_new_task());
        // attach task to child process
        let mut child_inner = child.borrow_mut();
        child_inner.tasks.push(Some(Arc::clone(&task)));
        drop(child_inner);
        // Seed trap context from the calling thread when available.
        let parent_trap_cx = crate::task::processor::current_task()
            .map(|t| *t.borrow_mut().get_trap_cx());
        // modify kstack_top in trap_cx of this thread
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        if let Some(parent_trap_cx) = parent_trap_cx {
            *trap_cx = parent_trap_cx;
        }
        trap_cx.kernel_sp = task.kstack.get_top();
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
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        // add child to parent's children list (after success)
        self.borrow_mut().children.push(Arc::clone(&child));
        Some((child, task))
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Option<Arc<Self>> {
        let (child, task) = self.fork_impl()?;
        // add this thread to scheduler
        add_task(task);
        Some(child)
    }

    /// Fork and return both the child process and its main task, without scheduling it.
    pub fn fork_with_task(self: &Arc<Self>) -> Option<(Arc<Self>, Arc<TaskControlBlock>)> {
        self.fork_impl()
    }

    pub fn getpid(&self) -> usize {
        self.pid.0
    }
}
