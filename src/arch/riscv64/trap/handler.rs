use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use super::context::TrapContext;
use crate::config::{PAGE_SIZE, TRAMPOLINE};
use crate::debug_config::DEBUG_TRAP;
use crate::mm::{LazyFaultResult, MapPermission, PageTable, VirtAddr};
use crate::println;
use crate::syscall::syscall;
use crate::task::block_sleep::check_timer;
use crate::task::processor::{
    exit_current_and_run_next, exit_group_and_run_next, suspend_current_and_run_next,
};
use crate::task::signal::{MAX_SIG, SIG_DFL, SIG_IGN, check_if_current_signals_error, signal_bit};
use crate::time::set_next_trigger;
use riscv::{
    interrupt::Trap,
    register::{scause, sstatus, stval},
};

#[allow(unused)]
fn log_for_trap_context(context: &TrapContext) {
    println!("--- Trap Context ---");
    for i in 0..32 {
        println!("x[{}] = {:#x}", i, context.x[i]);
    }
    // println!("sstatus = {:#x}", context.sstatus);
    println!("sepc    = {:#x}", context.sepc);
    println!("--------------------");
}

const USER_ENV_CALL: usize = 8;
const INSTRUCTION_ADDRESS_MISALIGNED: usize = 0;
const INSTRUCTION_ACCESS_FAULT: usize = 1;
const ILLEGAL_INSTRUCTION: usize = 2;
const BREAKPOINT: usize = 3;
const LOAD_ADDRESS_MISALIGNED: usize = 4;
const LOAD_ACCESS_FAULT: usize = 5;
const STORE_ADDRESS_MISALIGNED: usize = 6;
const STORE_ACCESS_FAULT: usize = 7;
const INSTRUCTION_PAGE_FAULT: usize = 12;
const LOAD_PAGE_FAULT: usize = 13;
const STORE_PAGE_FAULT: usize = 15;
const TIME_INTERVAL: usize = 5;
const SOFTWARE_INTERRUPT: usize = 1;

/// Log only the first trap_return to see initial user entry.
static FIRST_TRAP_RETURN_LOGGED: AtomicBool = AtomicBool::new(false);
/// Count trap_return invocations for debugging.
static TRAP_RETURN_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Count trap_handler invocations for debugging.
static TRAP_HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);

type KernelTrap = Trap<usize, usize>;

pub fn init_trap() {
    set_kernel_trap_entry();
}

// kernel_interupt made the os able to stop when time is up.
// so some sleeping task can be waked up.
fn set_kernel_trap_entry() {
    unsafe extern "C" {
        #[allow(dead_code)]
        fn alltraps();
        fn alltraps_k();
    }
    let alltraps_k_va = alltraps_k as usize;
    // SAFETY: stvec write is valid in S-mode; alltraps_k_va is a valid kernel trap entry address.
    unsafe {
        let to_write = riscv::register::stvec::Stvec::new(
            alltraps_k_va,
            riscv::register::stvec::TrapMode::Direct,
        );
        riscv::register::stvec::write(to_write);
    }
}

fn set_user_trap_entry() {
    // SAFETY: stvec write is valid in S-mode; TRAMPOLINE is a valid user trap entry address.
    unsafe {
        let to_write = riscv::register::stvec::Stvec::new(
            TRAMPOLINE as usize,
            riscv::register::stvec::TrapMode::Direct,
        );
        riscv::register::stvec::write(to_write);
    }
}

#[allow(dead_code)]
fn enable_supervisor_interrupt() {
    // SAFETY: sstatus CSR write is valid in S-mode.
    unsafe {
        sstatus::set_sie();
    }
}

fn disable_supervisor_interrupt() {
    // SAFETY: sstatus CSR write is valid in S-mode.
    unsafe {
        sstatus::clear_sie();
    }
}

#[unsafe(no_mangle)]
pub fn trap_from_kernel(trap_cx: &mut TrapContext) {
    let scause = scause::read();
    let stval = stval::read();
    let cause = scause.cause();
    match cause {
        Trap::Interrupt(TIME_INTERVAL) => {
            let hart = {
                let h: usize;
                // SAFETY: tp register holds the current hart ID in our convention.
                unsafe { asm!("mv {}, tp", out(reg) h) };
                h
            };
            static KERNEL_TIMER_LOG: AtomicUsize = AtomicUsize::new(0);
            let kcnt = KERNEL_TIMER_LOG.fetch_add(1, Ordering::SeqCst);
            if DEBUG_TRAP && kcnt < 4 {
                log::debug!("[trap_from_kernel] hart={} timer interrupt", hart);
            }
            set_next_trigger();
            check_timer();
        }
        //
        Trap::Interrupt(_) => {
            // TODO: 这里是否有可能出现其他态的中断？ 查看其他OS 是如何处理
            // 目前只是处理 内核间唤醒，有可能会出现需要处理其他
            //
            // Clear possible software interrupt and ignore others
            // SAFETY: sip CSR write is valid in S-mode.
            unsafe { riscv::register::sip::clear_ssoft() };
        }
        Trap::Exception(BREAKPOINT) => {
            // Skip the ebreak
            trap_cx.sepc += 2;
        }
        Trap::Exception(ILLEGAL_INSTRUCTION) => {
            panic!(
                "Illegal instruction in kernel: sepc = {:#x}, stval = {:#x}",
                trap_cx.sepc, stval
            );
        }
        c @ (Trap::Exception(INSTRUCTION_PAGE_FAULT)
        | Trap::Exception(LOAD_PAGE_FAULT)
        | Trap::Exception(STORE_PAGE_FAULT)) => {
            if try_handle_kernel_page_fault(c, stval) {
                return;
            }
            if DEBUG_TRAP {
                let satp = riscv::register::satp::read().bits();
                let sstatus_bits = sstatus::read().bits();
                let stvec_bits = riscv::register::stvec::read().bits();
                let sp: usize;
                // SAFETY: sp register read is always valid.
                unsafe { asm!("mv {}, sp", out(reg) sp) };
                let ra = trap_cx.x[1];
                log::error!(
                    "[kpf] cause={:?} scause={:#x} stval={:#x} sepc={:#x} sstatus={:#x} satp={:#x} stvec={:#x} sp={:#x} ra={:#x}",
                    c,
                    scause.bits(),
                    stval,
                    trap_cx.sepc,
                    sstatus_bits,
                    satp,
                    stvec_bits,
                    sp,
                    ra
                );
            }
            panic!(
                "Kernel page fault: cause = {:?}, sepc = {:#x}, stval = {:#x}",
                c, trap_cx.sepc, stval
            );
        }
        c => {
            panic!(
                "Unsupported trap from kernel: {:?}, stval = {:#x}!",
                c, stval
            );
        }
    }
}

fn try_handle_kernel_page_fault(cause: KernelTrap, stval: usize) -> bool {
    let Some(task) = crate::task::processor::current_task() else {
        return false;
    };
    let Some(process) = task.process.upgrade() else {
        return false;
    };
    let Some(mut inner) = process.try_borrow_mut() else {
        return false;
    };
    if matches!(cause, Trap::Exception(STORE_PAGE_FAULT))
        && inner.memory_set.resolve_cow_fault(stval)
    {
        return true;
    }
    let access = match cause {
        Trap::Exception(LOAD_PAGE_FAULT) => MapPermission::R,
        Trap::Exception(STORE_PAGE_FAULT) => MapPermission::W,
        Trap::Exception(INSTRUCTION_PAGE_FAULT) => MapPermission::X,
        _ => return false,
    };
    match inner.memory_set.resolve_lazy_fault(stval, access) {
        LazyFaultResult::Resolved => true,
        LazyFaultResult::Oom => {
            drop(inner);
            exit_group_and_run_next(-9);
        }
        LazyFaultResult::Invalid => false,
    }
}
// todo : avoid cloning here..
fn get_trap_context() -> &'static mut TrapContext {
    let now_task_block = crate::task::processor::current_task().unwrap();
    let now_task_block_inner = now_task_block.borrow_mut();
    let trap_cx_ppn = now_task_block_inner.trap_cx_ppn;
    // IMPORTANT: Drop the borrow before returning the reference
    // This is safe because:
    // 1. trap_cx_ppn is a PhysPageNum (Copy type)
    // 2. The physical page won't be deallocated while the task is running
    // 3. We're in kernel space with traps disabled
    drop(now_task_block_inner);
    trap_cx_ppn.get_mut()
}
pub fn get_current_token() -> usize {
    let now_task_block = crate::task::processor::current_task().unwrap();
    let process = now_task_block.process.upgrade().unwrap();
    let process_inner = process.borrow_mut();
    process_inner.memory_set.token()
}
#[unsafe(no_mangle)]
pub fn trap_handler() {
    let idx = TRAP_HANDLER_COUNT.fetch_add(1, Ordering::SeqCst);
    if DEBUG_TRAP && idx < 6 {
        let hart = {
            let h: usize;
            // SAFETY: tp register holds the current hart ID in our convention.
            unsafe { asm!("mv {}, tp", out(reg) h) };
            h
        };
        log::debug!(
            "[trap_handler#{}] hart={} scause={:?} stval={:#x}",
            idx,
            hart,
            scause::read().cause(),
            stval::read()
        );
    }
    // now is kernel space
    set_kernel_trap_entry();
    let scause = scause::read();
    let stval = stval::read();
    let code = scause.cause(); // usize
    match code {
        // user env call ...
        Trap::Exception(USER_ENV_CALL) => {
            // Get syscall arguments
            let (syscall_id, args) = {
                let cx = get_trap_context();
                cx.sepc += 4;
                (
                    cx.x[17],
                    [cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15]],
                )
            }; // cx is dropped here, releasing the borrow
            if let Some(task) = crate::task::processor::current_task() {
                let mut inner = task.borrow_mut();
                inner.last_syscall_id = syscall_id;
                inner.last_syscall_args = args;
                inner.last_syscall_valid = true;
            }

            // NOTE: Do NOT enable interrupts during syscall execution.
            // This is because syscalls may acquire spin::Mutex locks (e.g., heap allocator,
            // VirtIO block device), and if a timer interrupt fires while a lock is held,
            // the interrupt handler might try to allocate memory (via wakeup_task -> add_task
            // -> VecDeque::push_back), causing a deadlock.
            //
            // The tradeoff is that long-running syscalls (like exec) won't be preemptible,
            // but this is acceptable for correctness.
            //
            //  todo:
            // 1. Using interrupt-safe allocators
            // 2. Avoiding memory allocation in interrupt handlers
            // 3. Selectively enabling interrupts only for syscalls that don't use spin::Mutex

            // Execute syscall (may change memory layout via exec)
            let result = syscall(syscall_id, args);

            // Get trap context again (may be different after exec)
            let cx = get_trap_context();
            cx.x[10] = result as usize;
        }
        Trap::Exception(code) => {
            handle_user_exception(code, stval);
        }
        Trap::Interrupt(TIME_INTERVAL) => {
            set_next_trigger();
            check_timer();
            crate::task::processor::account_current_task_tick();
            crate::syscall::misc::check_current_rlimit_cpu();
            // Also handle pending fatal signals on timer ticks.
            // Without this, CPU-bound tasks that never enter syscalls would never observe
            // signals like SIGINT/SIGKILL and could run forever.
            if let Some((errno, msg)) = check_if_current_signals_error() {
                println!("[kernel] {}", msg);
                exit_group_and_run_next(errno);
            }
            crate::fs::cgroup_maybe_block_current();
            if crate::task::processor::should_preempt_current_on_tick() {
                suspend_current_and_run_next();
            }
        }
        Trap::Interrupt(SOFTWARE_INTERRUPT) => {
            // Used as an IPI to wake up harts from `wfi` (e.g., when a remote hart enqueues a task).
            // SAFETY: sip CSR write is valid in S-mode.
            unsafe { riscv::register::sip::clear_ssoft() };
        }
        Trap::Interrupt(interrupt) => {
            panic!(
                "Unsupported interrupt: cause = {:?}, stval = {:#x}",
                interrupt, stval
            );
        }
    }

    if let Some((errno, msg)) = check_if_current_signals_error() {
        println!("[kernel] {}", msg);
        exit_group_and_run_next(errno);
    }
    // Progress timers even if S-mode timer interrupts are disabled during syscalls.
    // This avoids long-running syscall-heavy workloads (e.g., hackbench fork storms)
    // from starving `sleep()/nanosleep()` wakeups.
    check_timer();
    crate::syscall::signal::maybe_deliver_signal();
    crate::fs::cgroup_maybe_block_current();
    trap_return();
}

fn exception_name(code: usize) -> &'static str {
    match code {
        INSTRUCTION_ADDRESS_MISALIGNED => "Instruction address misaligned",
        INSTRUCTION_ACCESS_FAULT => "Instruction access fault",
        ILLEGAL_INSTRUCTION => "Illegal instruction",
        BREAKPOINT => "Breakpoint",
        LOAD_ADDRESS_MISALIGNED => "Load address misaligned",
        LOAD_ACCESS_FAULT => "Load access fault",
        STORE_ADDRESS_MISALIGNED => "Store address misaligned",
        STORE_ACCESS_FAULT => "Store access fault",
        INSTRUCTION_PAGE_FAULT => "Instruction page fault",
        LOAD_PAGE_FAULT => "Load page fault",
        STORE_PAGE_FAULT => "Store page fault",
        USER_ENV_CALL => "Environment call from U-mode",
        _ => "Unknown exception",
    }
}

fn try_expand_mmap_growsdown(fault_va: usize, access: MapPermission) -> bool {
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    let fault_page = fault_va & !(PAGE_SIZE - 1);
    let process = crate::task::processor::current_process();
    let mut inner = process.borrow_mut();

    for idx in 0..inner.mmap_areas.len() {
        let region = inner.mmap_areas[idx];
        if !region.growsdown {
            continue;
        }
        let Some(expected) = region.start.checked_sub(PAGE_SIZE) else {
            continue;
        };
        if fault_page != expected {
            continue;
        }

        let mut perm = MapPermission::U;
        if (region.prot & PROT_READ) != 0 {
            perm |= MapPermission::R;
        }
        if (region.prot & PROT_WRITE) != 0 {
            perm |= MapPermission::W;
        }
        if (region.prot & PROT_EXEC) != 0 {
            perm |= MapPermission::X;
        }
        if !perm.contains(access) {
            return false;
        }
        if inner
            .memory_set
            .range_overlaps(fault_page.into(), region.start.into())
        {
            return false;
        }
        // Keep one-page guard below the expanded stack segment.
        let Some(next_guard_start) = fault_page.checked_sub(PAGE_SIZE) else {
            return false;
        };
        if inner
            .memory_set
            .range_overlaps(next_guard_start.into(), fault_page.into())
        {
            return false;
        }
        if !inner
            .memory_set
            .try_insert_lazy_area(fault_page.into(), region.start.into(), perm)
        {
            return false;
        }

        let grown = region.start - fault_page;
        inner.mmap_areas[idx].start = fault_page;
        inner.mmap_areas[idx].len += grown;
        return match inner.memory_set.resolve_lazy_fault(fault_va, access) {
            LazyFaultResult::Resolved => true,
            LazyFaultResult::Oom => {
                drop(inner);
                exit_group_and_run_next(-9);
            }
            LazyFaultResult::Invalid => false,
        };
    }
    false
}

fn fault_hits_mmap_sigbus_tail(addr: usize) -> bool {
    let process = crate::task::processor::current_process();
    let inner = process.borrow_mut();
    inner
        .mmap_areas
        .iter()
        .any(|region| addr >= region.start && addr < region.end() && addr >= region.sigbus_start)
}

fn current_signal_handler(signum: usize) -> usize {
    let process = crate::task::processor::current_process();
    let inner = process.borrow_mut();
    if signum <= MAX_SIG {
        let legacy = inner.signals_actions.table[signum].handler;
        if legacy != 0 {
            legacy
        } else {
            inner
                .rt_sig_handlers
                .get(signum)
                .map(|a| a.handler)
                .unwrap_or(SIG_DFL)
        }
    } else {
        inner
            .rt_sig_handlers
            .get(signum)
            .map(|a| a.handler)
            .unwrap_or(SIG_DFL)
    }
}

fn handle_user_exception(code: usize, stval: usize) {
    fn try_read_user_u64(token: usize, addr: usize) -> Option<u64> {
        let page_table = PageTable::from_token(token);
        let mut bytes = [0u8; 8];
        for i in 0..8usize {
            let va = VirtAddr::from(addr.wrapping_add(i));
            let vpn = va.floor();
            let pte = page_table.translate(vpn)?;
            let ppn = pte.ppn();
            bytes[i] = ppn.get_bytes_array()[va.page_offset()];
        }
        Some(u64::from_le_bytes(bytes))
    }

    if code == INSTRUCTION_PAGE_FAULT && stval == 0 {
        if crate::syscall::signal::try_sigreturn_from_fault() {
            return;
        }
    }
    // Copy-on-write: resolve store faults on COW-tagged pages instead of killing the process.
    if code == STORE_PAGE_FAULT {
        let process = crate::task::processor::current_process();
        let mut inner = process.borrow_mut();
        if inner.memory_set.resolve_cow_fault(stval) {
            return;
        }
    }
    if (code == LOAD_PAGE_FAULT || code == STORE_PAGE_FAULT)
        && crate::syscall::dummy::try_handle_userfaultfd_page_fault(stval, code == STORE_PAGE_FAULT)
    {
        return;
    }
    if code == LOAD_PAGE_FAULT || code == STORE_PAGE_FAULT || code == INSTRUCTION_PAGE_FAULT {
        let process = crate::task::processor::current_process();
        let mut inner = process.borrow_mut();
        let access = match code {
            LOAD_PAGE_FAULT => MapPermission::R,
            STORE_PAGE_FAULT => MapPermission::W,
            INSTRUCTION_PAGE_FAULT => MapPermission::X,
            _ => MapPermission::R,
        };
        match inner.memory_set.resolve_lazy_fault(stval, access) {
            LazyFaultResult::Resolved => return,
            LazyFaultResult::Oom => {
                drop(inner);
                exit_group_and_run_next(-9);
            }
            LazyFaultResult::Invalid => {}
        }
    }
    if code == LOAD_PAGE_FAULT || code == STORE_PAGE_FAULT || code == INSTRUCTION_PAGE_FAULT {
        let access = match code {
            LOAD_PAGE_FAULT => MapPermission::R,
            STORE_PAGE_FAULT => MapPermission::W,
            INSTRUCTION_PAGE_FAULT => MapPermission::X,
            _ => MapPermission::R,
        };
        if try_expand_mmap_growsdown(stval, access) {
            return;
        }
    }
    let cx = get_trap_context();
    if crate::debug_config::DEBUG_SYSCALL
        && (code == LOAD_PAGE_FAULT || code == STORE_PAGE_FAULT || code == INSTRUCTION_PAGE_FAULT)
    {
        let pid = crate::task::processor::current_process().getpid();
        crate::println!(
            "[user_exn_regs] pid={} code={} ({}) sepc={:#x} stval={:#x}",
            pid,
            code,
            exception_name(code),
            cx.sepc,
            stval
        );
        // Print a subset of registers that are most useful for diagnosing page faults.
        // a0-a7: x10-x17, s0-s11: x8-x9 + x18-x27, sp: x2, ra: x1, gp: x3, tp: x4.
        crate::println!(
            "[user_exn_regs] ra={:#x} sp={:#x} gp={:#x} tp={:#x}",
            cx.x[1],
            cx.x[2],
            cx.x[3],
            cx.x[4]
        );
        crate::println!(
            "[user_exn_regs] a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x} a6={:#x} a7={:#x}",
            cx.x[10],
            cx.x[11],
            cx.x[12],
            cx.x[13],
            cx.x[14],
            cx.x[15],
            cx.x[16],
            cx.x[17]
        );
        crate::println!(
            "[user_exn_regs] s0={:#x} s1={:#x} s2={:#x} s3={:#x} s4={:#x} s5={:#x} s6={:#x} s7={:#x} s8={:#x} s9={:#x} s10={:#x} s11={:#x}",
            cx.x[8],
            cx.x[9],
            cx.x[18],
            cx.x[19],
            cx.x[20],
            cx.x[21],
            cx.x[22],
            cx.x[23],
            cx.x[24],
            cx.x[25],
            cx.x[26],
            cx.x[27]
        );

        // Extra diagnostics for the recurring glibc ld-linux crash:
        // sepc ends with 0x11dce and stval==0x8 (NULL+8 deref).
        if code == LOAD_PAGE_FAULT && stval == 0x8 && (cx.sepc & 0xfffff) == 0x11dce {
            let token = get_current_token();
            let s9 = cx.x[25];
            let s10 = cx.x[26];
            let slot = s10.wrapping_sub(1248); // ld a3,-1248(s10)
            let slot_val = try_read_user_u64(token, slot).unwrap_or(0);
            crate::println!(
                "[ld-linux_diag] sepc={:#x} base(s9)={:#x} s10={:#x} slot={:#x} slot_val={:#x}",
                cx.sepc,
                s9,
                s10,
                slot,
                slot_val
            );
            if slot_val != 0 {
                let tag = try_read_user_u64(token, slot_val as usize).unwrap_or(0);
                let val =
                    try_read_user_u64(token, (slot_val as usize).wrapping_add(8)).unwrap_or(0);
                crate::println!(
                    "[ld-linux_diag] dyn@{:#x}: tag={} val={:#x}",
                    slot_val,
                    tag,
                    val
                );
            }
        }
    }
    if let Some(sig) = match code {
        ILLEGAL_INSTRUCTION => Some(4), // SIGILL
        INSTRUCTION_PAGE_FAULT | LOAD_PAGE_FAULT | STORE_PAGE_FAULT => {
            if fault_hits_mmap_sigbus_tail(stval) {
                Some(7) // SIGBUS
            } else {
                Some(11) // SIGSEGV
            }
        }
        _ => None,
    } {
        let handler = current_signal_handler(sig as usize);
        if handler == SIG_IGN {
            return;
        }
        if handler == SIG_DFL {
            // Synchronous faults with default action terminate the whole process.
            exit_group_and_run_next(-(sig as i32));
        }
        if let Some(task) = crate::task::processor::current_task() {
            if let Some(bit) = signal_bit(sig) {
                task.borrow_mut().pending_signals |= bit;
            }
        }
        return;
    }
    log::warn!(
        "[user_exn] code={} ({}) sepc={:#x} stval={:#x}",
        code,
        exception_name(code),
        cx.sepc,
        stval
    );
    exit_current_and_run_next(-1);
}

#[unsafe(no_mangle)]
/// set the new addr of __restore asm function in TRAMPOLINE page,
/// set the reg a0 = trap_cx_ptr, reg a1 = phy addr of usr page table,
/// finally, jump to new addr of __restore asm function
pub fn trap_return() -> ! {
    let entered = TRAP_RETURN_COUNT.load(Ordering::SeqCst);
    if DEBUG_TRAP && entered < 4 {
        let hart = {
            let h: usize;
            // SAFETY: tp register holds the current hart ID in our convention.
            unsafe { asm!("mv {}, tp", out(reg) h) };
            h
        };
        log::debug!("[trap_return entry#{}] hart={} sp={:#x}", entered, hart, {
            let s: usize;
            // SAFETY: sp register read is always valid.
            unsafe { asm!("mv {}, sp", out(reg) s) };
            s
        });
    }
    // this shouln't be interrupted
    disable_supervisor_interrupt();
    set_user_trap_entry();

    // Ensure we always return to user mode even if the trap context got corrupted.
    let cx = get_trap_context();
    cx.sstatus.set_spp(sstatus::SPP::User);
    cx.sstatus.set_spie(true);

    // IMPORTANT: `trap_return()` never returns. Keep `Arc` owners in a short scope,
    // otherwise every trap leaks one strong reference.
    let (trap_cx_ptr, user_satp) = {
        let task = crate::task::processor::current_task().unwrap();
        let trap_cx_ptr = {
            let task_inner = task.borrow_mut();
            if let Some(res) = task_inner.res.as_ref() {
                res.trap_cx_user_va()
            } else {
                drop(task_inner);
                exit_current_and_run_next(-1)
            }
        };
        let user_satp = task
            .process
            .upgrade()
            .unwrap()
            .borrow_mut()
            .memory_set
            .token();
        (trap_cx_ptr, user_satp)
    };

    let cnt = TRAP_RETURN_COUNT.fetch_add(1, Ordering::SeqCst);
    if DEBUG_TRAP && cnt < 4 {
        let hart = {
            let h: usize;
            // SAFETY: tp register holds the current hart ID in our convention.
            unsafe { asm!("mv {}, tp", out(reg) h) };
            h
        };
        if !FIRST_TRAP_RETURN_LOGGED.swap(true, Ordering::SeqCst) {
            let cx = get_trap_context();
            let tp_kernel: usize;
            // SAFETY: tp register read is always valid.
            unsafe { asm!("mv {}, tp", out(reg) tp_kernel) };
            log::debug!(
                "[trap_return#{}] hart={} trap_cx_ptr={:#x} sepc={:#x} user_satp={:#x} tp={:#x}",
                cnt,
                hart,
                trap_cx_ptr,
                cx.sepc,
                user_satp,
                tp_kernel
            );
        } else {
            log::debug!(
                "[trap_return#{}] hart={} trap_cx_ptr={:#x} user_satp={:#x}",
                cnt,
                hart,
                trap_cx_ptr,
                user_satp,
            );
        }
        let tramp_vpn = VirtAddr::from(TRAMPOLINE).floor();
        let kernel_satp = riscv::register::satp::read().bits();
        let kernel_pt = PageTable::from_token(kernel_satp);
        let user_pt = PageTable::from_token(user_satp);
        let kernel_pte = kernel_pt
            .translate(tramp_vpn)
            .filter(|pte| pte.is_valid())
            .map(|pte| (pte.ppn(), pte.flags()));
        let user_pte = user_pt
            .translate(tramp_vpn)
            .filter(|pte| pte.is_valid())
            .map(|pte| (pte.ppn(), pte.flags()));
        log::debug!(
            "[trap_return#{}] tramp vpn={:?} kernel_satp={:#x} user_satp={:#x} kernel_pte={:?} user_pte={:?}",
            cnt,
            tramp_vpn,
            kernel_satp,
            user_satp,
            kernel_pte,
            user_pte
        );
    }

    unsafe extern "C" {
        fn alltraps();
        fn restore();
    }
    let restore_va = restore as usize - alltraps as usize + TRAMPOLINE;
    // SAFETY: restore_va points to valid trampoline code; trap_cx_ptr and user_satp are valid.
    // This asm block never returns; control transfers to user mode via sret in the trampoline.
    unsafe {
        asm!(
            "fence.i",
            "jr {restore_va}",             // jump to new addr of __restore asm function
            restore_va = in(reg) restore_va,
            in("a0") trap_cx_ptr,      // a0 = virt addr of Trap Context
            in("a1") user_satp,        // a1 = phy addr of usr page table
            options(noreturn)
        );
    }
}
