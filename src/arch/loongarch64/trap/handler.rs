use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use super::context::TrapContext;
use crate::config::TRAMPOLINE;
use crate::debug_config::DEBUG_TRAP;
use crate::mm::{LazyFaultResult, MapPermission, VirtAddr};
use crate::println;
use crate::syscall::syscall;
use crate::task::block_sleep::check_timer;
use crate::task::processor::{
    exit_current_and_run_next, exit_group_and_run_next, suspend_current_and_run_next,
};
use crate::task::signal::{check_if_current_signals_error, check_task_signals_error};
use crate::time::set_next_trigger;

const ECODE_SYSCALL: usize = 0xB;
const ECODE_PAGE_INVALID_LOAD: usize = 0x1;
const ECODE_PAGE_INVALID_STORE: usize = 0x2;
const ECODE_PAGE_INVALID_FETCH: usize = 0x3;
const ECODE_PAGE_MODIFY: usize = 0x4;
const ECODE_PAGE_NON_READ: usize = 0x5;
const ECODE_PAGE_NON_EXEC: usize = 0x6;
const ECODE_PAGE_PRIV: usize = 0x7;
const ECODE_ADDR_ERROR: usize = 0x8;
const ECODE_ADDR_ALIGN: usize = 0x9;
const ECODE_INSTRUCTION_NOT_EXIST: usize = 0xd;
const ECODE_INSTRUCTION_PRIVILEGE: usize = 0xe;
const ECODE_FP_DISABLED: usize = 0xf;
const ECODE_LSX_DISABLED: usize = 0x10;
const ECODE_LASX_DISABLED: usize = 0x11;
const ECODE_FP_EXCEPTION: usize = 0x12;

const SIGILL: usize = 4;
const SIGBUS: usize = 7;
const SIGFPE: usize = 8;
const SIGSEGV: usize = 11;

// Linux uapi siginfo codes. Keep these next to the architecture exception
// translation so an unresolved hardware fault always carries useful metadata.
const BUS_ADRALN: i32 = 1;
const BUS_ADRERR: i32 = 2;
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;

use super::super::csr_defs::{
    ESTAT_ECODE_MASK, ESTAT_ECODE_SHIFT, ESTAT_INTERRUPT_MASK, ESTAT_IS_EIOINTC, ESTAT_IS_IPI,
    ESTAT_IS_TIMER, PRMD_USER_IE, PRMD_USER_IE_MASK,
};

/// Log only the first trap_return to see initial user entry.
static FIRST_TRAP_RETURN_LOGGED: AtomicBool = AtomicBool::new(false);
/// Count trap_return invocations for debugging.
static TRAP_RETURN_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Log the first entry into trap_return before any memory access.
static TRAP_RETURN_ENTER_LOGGED: AtomicBool = AtomicBool::new(false);
/// Count trap_handler invocations for debugging.
static TRAP_HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
fn read_estat() -> usize {
    let val: usize;
    // SAFETY: Reading ESTAT is valid in kernel mode and returns the current exception status.
    // Using the wrong CSR would misdecode the active trap cause.
    unsafe { asm!("csrrd {}, 0x5", out(reg) val) };
    val
}

#[inline(always)]
fn read_badv() -> usize {
    let val: usize;
    // SAFETY: Reading BADV is valid in kernel mode and reports the faulting virtual address.
    // If this read were wrong, page-fault reporting and recovery would use a bogus address.
    unsafe { asm!("csrrd {}, 0x7", out(reg) val) };
    val
}

#[inline(always)]
fn read_badi() -> usize {
    let val: usize;
    // SAFETY: Reading BADI is valid in kernel mode and exposes the trapped instruction metadata.
    // Reading an unrelated CSR here would make trap diagnostics and emulation incorrect.
    unsafe { asm!("csrrd {}, 0x8", out(reg) val) };
    val
}

#[inline(always)]
fn write_eentry(val: usize) {
    // SAFETY: `val` is a kernel trap-entry address chosen by the caller, and writing EENTRY is
    // only valid in kernel mode. A bad address here would redirect traps to invalid code.
    unsafe { super::super::csr_write::<0xc>(val) };
}

fn set_kernel_trap_entry() {
    unsafe extern "C" {
        fn alltraps_k();
    }
    write_eentry(alltraps_k as *const () as usize);
}

fn set_user_trap_entry() {
    // Use the trampoline VA so traps from user mode always enter via a
    // user-mapped page (matches the RISC-V flow).
    write_eentry(TRAMPOLINE as usize);
}

#[inline]
fn is_user_page_fault(ecode: usize) -> bool {
    matches!(
        ecode,
        ECODE_PAGE_INVALID_LOAD
            | ECODE_PAGE_INVALID_STORE
            | ECODE_PAGE_INVALID_FETCH
            | ECODE_PAGE_MODIFY
            | ECODE_PAGE_NON_READ
            | ECODE_PAGE_NON_EXEC
            | ECODE_PAGE_PRIV
    )
}

#[inline]
fn page_fault_access(ecode: usize) -> MapPermission {
    match ecode {
        ECODE_PAGE_INVALID_LOAD | ECODE_PAGE_NON_READ => MapPermission::R,
        ECODE_PAGE_INVALID_FETCH | ECODE_PAGE_NON_EXEC => MapPermission::X,
        _ => MapPermission::W,
    }
}

fn get_trap_context() -> &'static mut TrapContext {
    let now_task_block = crate::task::processor::current_task().unwrap();
    let now_task_block_inner = now_task_block.borrow_mut();
    let trap_cx_ppn = now_task_block_inner.trap_cx_ppn;
    // Drop the borrow before returning the reference (PPN is Copy).
    drop(now_task_block_inner);
    trap_cx_ppn.get_mut()
}

pub fn init_trap() {
    set_kernel_trap_entry();
}

#[unsafe(no_mangle)]
pub fn trap_from_kernel(trap_cx: &mut TrapContext) {
    let estat = read_estat();
    let ecode = (estat >> ESTAT_ECODE_SHIFT) & ESTAT_ECODE_MASK;
    if ecode == 0 {
        if (estat & ESTAT_IS_TIMER) != 0 {
            super::super::clear_timer_interrupt();
            set_next_trigger();
            crate::task::block_sleep::note_kernel_timer_tick();
            crate::drivers::block::poll_all();
            return;
        }
        if (estat & ESTAT_IS_EIOINTC) != 0 {
            crate::arch::handle_external_interrupt();
            return;
        }
        if (estat & ESTAT_IS_IPI) != 0 {
            super::super::handle_ipi_interrupt();
            return;
        }
        // A live level source can disappear after trap entry but before this
        // CSR read, for example when another hart completes fallback polling.
        // Linux's LoongArch CPUINTC treats an empty pending bitmap as a no-op.
        if (estat & ESTAT_INTERRUPT_MASK) == 0 {
            return;
        }
    }
    panic!(
        "Unhandled kernel trap: hart={} estat={:#x} ecode={} badv={:#x} badi={:#x} era={:#x}",
        super::super::hart_id(),
        estat,
        ecode,
        read_badv(),
        read_badi(),
        trap_cx.sepc
    );
}

fn handle_user_exception(ecode: usize, badv: usize) {
    // Linux LoongArch reports address-error and alignment exceptions as
    // thread-directed SIGBUS faults. They are not page faults and therefore
    // must not enter the COW/lazy/growsdown recovery chain.
    if ecode == ECODE_ADDR_ERROR {
        crate::task::signal::force_current_fault_signal(SIGBUS, BUS_ADRERR, badv);
        return;
    }
    if ecode == ECODE_ADDR_ALIGN {
        crate::task::signal::force_current_fault_signal(SIGBUS, BUS_ADRALN, badv);
        return;
    }

    if ecode == ECODE_PAGE_INVALID_FETCH && badv == 0 {
        if crate::syscall::signal::try_sigreturn_from_fault() {
            return;
        }
    }
    if matches!(ecode, ECODE_PAGE_INVALID_STORE | ECODE_PAGE_MODIFY) {
        let memory_set = crate::task::processor::current_task().unwrap().memory_set();
        if memory_set.resolve_cow_fault(badv) {
            return;
        }
    }
    if is_user_page_fault(ecode) {
        let access = page_fault_access(ecode);
        let memory_set = crate::task::processor::current_task().unwrap().memory_set();
        match memory_set.resolve_lazy_fault(badv, access) {
            LazyFaultResult::Resolved => return,
            LazyFaultResult::Oom => exit_group_and_run_next(-9),
            LazyFaultResult::Invalid => {}
        }
    }
    if is_user_page_fault(ecode) {
        let access = page_fault_access(ecode);
        let memory_set = crate::task::processor::current_task().unwrap().memory_set();
        match memory_set.try_expand_growsdown(badv, access) {
            LazyFaultResult::Resolved => return,
            LazyFaultResult::Oom => exit_group_and_run_next(-9),
            LazyFaultResult::Invalid => {}
        }
    }

    if is_user_page_fault(ecode) {
        // Linux starts a page fault as SEGV_MAPERR and changes it to
        // SEGV_ACCERR once a VMA has been found. Preserve the mmap EOF-tail
        // exception as SIGBUS/BUS_ADRERR, matching VM_FAULT_SIGBUS.
        let memory_set = crate::task::processor::current_task().unwrap().memory_set();
        let region = badv
            .checked_add(1)
            .and_then(|end| memory_set.lock().vm_region_containing(badv, end));
        match region {
            Some(region) if badv >= region.sigbus_start() => {
                crate::task::signal::force_current_fault_signal(SIGBUS, BUS_ADRERR, badv);
            }
            Some(_) => {
                crate::task::signal::force_current_fault_signal(SIGSEGV, SEGV_ACCERR, badv);
            }
            None => {
                crate::task::signal::force_current_fault_signal(SIGSEGV, SEGV_MAPERR, badv);
            }
        }
        return;
    }

    if let Some((errno, msg)) = check_if_current_signals_error() {
        crate::task::signal::log_signal_exit(msg);
        exit_group_and_run_next(errno);
    }
    let cx = get_trap_context();
    println!(
        "[user_exn] ecode={} badv={:#x} era={:#x} ra={:#x} sp={:#x} tp={:#x}",
        ecode,
        badv,
        cx.sepc,
        cx.x[super::super::REG_RA],
        cx.x[super::super::REG_SP],
        cx.x[super::super::REG_TP]
    );
    exit_group_and_run_next(-11);
}

#[unsafe(no_mangle)]
pub fn trap_handler() {
    // The trampoline has already selected kernel PGD/ASID 0. A synchronous
    // invalidator may hold this mm's write lock while waiting for our ack, so
    // service its lockless request before taking task/mm locks, then withdraw
    // this hart from the address space's user-active mask.
    super::super::service_pending_tlb_shootdowns();
    if let Some(task) = crate::task::processor::current_task() {
        task.leave_user_asid();
    }

    if DEBUG_TRAP {
        let idx = TRAP_HANDLER_COUNT.fetch_add(1, Ordering::SeqCst);
        if idx < 4 {
            let hart = super::super::hart_id();
            println!("[trap_handler#{}] hart={}", idx, hart);
        }
    }

    //从用户态上来的时候需要设置trap入口,不然等下容易死循环
    set_kernel_trap_entry();

    //记录trap类型
    let estat = read_estat();
    //
    let ecode = (estat >> ESTAT_ECODE_SHIFT) & ESTAT_ECODE_MASK;
    let badv = read_badv();
    let badi = read_badi();
    let mut syscall_return = false;

    /*

       ecode == 0              -> 中断类，当前主要处理 timer interrupt
       ecode == ECODE_SYSCALL  -> syscall
       其他 ecode              -> 用户异常，例如缺页、非法访问、权限错误、地址未对齐
    */
    if ecode == 0 {
        if (estat & ESTAT_IS_TIMER) != 0 {
            //清理对应的寄存器,否则返回用户态之后即使计时器没有到,还会继续触发时钟中断
            super::super::clear_timer_interrupt();
            crate::time::loongarch_record_timer_tick();
            set_next_trigger();
            // Linux keeps lengthy timer work interruptible. Nested timer
            // interrupts are converted to deferred work by trap_from_kernel,
            // while call-function IPIs must remain serviceable for TLB acks.
            super::super::enable_interrupts();
            crate::drivers::block::poll_all();
            check_timer();
            crate::task::processor::account_current_task_tick();
            crate::syscall::misc::check_current_rlimit_cpu();
            if crate::debug_config::DEBUG_SIGNAL {
                static LAST_SLEEP_TIMER_LOG: AtomicUsize = AtomicUsize::new(0);
                let proc = crate::task::processor::current_process();
                let inner = proc.borrow_mut();
                let argv0 = inner.argv.first().map(|s| s.as_str()).unwrap_or("");
                if argv0 == "sleep" {
                    let now_ms = crate::time::get_time_ms();
                    let last = LAST_SLEEP_TIMER_LOG.load(Ordering::Relaxed);
                    if now_ms.saturating_sub(last) >= 200 {
                        LAST_SLEEP_TIMER_LOG.store(now_ms, Ordering::Relaxed);
                        crate::log_if!(
                            crate::debug_config::DEBUG_SIGNAL,
                            info,
                            "[timer_irq_sleep] pid={} now_ms={}",
                            proc.getpid(),
                            now_ms
                        );
                    }
                }
            }
            crate::syscall::signal::maybe_deliver_signal();
            if let Some((errno, msg)) = check_if_current_signals_error() {
                crate::task::signal::log_signal_exit(msg);
                exit_group_and_run_next(errno);
            }
            crate::fs::cgroup_maybe_block_current();
            if crate::task::processor::should_preempt_current_on_tick() {
                suspend_current_and_run_next();
            }
            super::super::disable_interrupts();
        } else if (estat & ESTAT_IS_EIOINTC) != 0 {
            crate::arch::handle_external_interrupt();
        } else if (estat & ESTAT_IS_IPI) != 0 {
            super::super::handle_ipi_interrupt();
        } else if (estat & ESTAT_INTERRUPT_MASK) == 0 {
            // The source was withdrawn after trap entry; resume user mode.
        } else {
            // A nonzero, unsupported pending source is a real dispatch bug.
            panic!(
                "Unhandled interrupt: estat={:#x} badv={:#x} badi={:#x}",
                estat, badv, badi
            );
        }
    } else if ecode == ECODE_SYSCALL {
        syscall_return = true;
        let cx = get_trap_context();
        cx.sepc = cx.sepc.wrapping_add(4);
        let args = [
            cx.x[super::super::REG_A0],
            cx.x[super::super::REG_A1],
            cx.x[super::super::REG_A2],
            cx.x[super::super::REG_A3],
            cx.x[super::super::REG_A4],
            cx.x[super::super::REG_A5],
        ];
        let syscall_id = cx.x[super::super::REG_A7];
        if let Some(task) = crate::task::processor::current_task() {
            let mut inner = task.borrow_mut();
            inner.last_syscall_id = syscall_id;
            inner.last_syscall_args = args;
            inner.last_syscall_valid = true;
        }
        // Normal Linux syscall work is interruptible. This also prevents a
        // deadlock where another hart holds an mm lock and waits for our TLB
        // shootdown acknowledgement while this syscall waits for that lock.
        super::super::enable_interrupts();
        let result = syscall(syscall_id, args);
        super::super::disable_interrupts();
        let cx = get_trap_context();
        cx.x[super::super::REG_A0] = result as usize;
    } else if ecode == ECODE_FP_DISABLED && super::super::handle_user_fp_disabled() {
        // Lazy-FPU path: enable/restore the task's FP state and retry the
        // trapped user instruction instead of saving FP on every context switch.
    } else if ecode == ECODE_LSX_DISABLED && super::super::handle_user_lsx_disabled() {
        // LSX overlaps the scalar FPR file. The architecture helper preserves
        // the live low halves, restores/initializes the upper halves, and
        // retries this instruction without advancing ERA.
    } else if ecode == ECODE_FP_EXCEPTION {
        let si_code = super::super::handle_user_fp_exception();
        let era = get_trap_context().sepc;
        crate::task::signal::force_current_fault_signal(SIGFPE, si_code, era);
    } else if matches!(
        ecode,
        ECODE_INSTRUCTION_NOT_EXIST
            | ECODE_INSTRUCTION_PRIVILEGE
            | ECODE_FP_DISABLED
            | ECODE_LSX_DISABLED
            | ECODE_LASX_DISABLED
    ) {
        // Unsupported FP/SIMD and illegal instructions are synchronous,
        // thread-directed SIGILL faults. LASX remains deliberately gated
        // until its 256-bit context implementation exists.
        let si_code = if ecode == ECODE_INSTRUCTION_PRIVILEGE {
            5 // ILL_PRVOPC
        } else {
            1 // ILL_ILLOPC
        };
        let era = get_trap_context().sepc;
        crate::task::signal::force_current_fault_signal(SIGILL, si_code, era);
    } else {
        super::super::enable_interrupts();
        match ecode {
            ECODE_ADDR_ERROR | ECODE_ADDR_ALIGN => handle_user_exception(ecode, badv),
            _ => handle_user_exception(ecode, badv),
        }
        super::super::disable_interrupts();
    }

    crate::trap::exit_to_user_mode_loop(syscall_return);
    trap_return();
}
pub fn trap_return() -> ! {
    if DEBUG_TRAP {
        if !TRAP_RETURN_ENTER_LOGGED.swap(true, Ordering::SeqCst) {
            println!(
                "[trap_return] enter hart={} trap_return_va={:#x}",
                super::super::hart_id(),
                trap_return as *const () as usize
            );
        }
    }
    // Keep kernel trap entry active while we are still running in kernel mode.
    set_kernel_trap_entry();
    // A task can receive a signal while it is already runnable. When the
    // scheduler later restores it, execution reaches this path directly without
    // another trap handler pass, so honor pending signals before userspace.
    if let Some(task) = crate::task::processor::current_task()
        && (task.has_signal_pending() || task.exec_exit_requested())
    {
        if let Some((errno, msg)) = check_task_signals_error(&task) {
            crate::task::signal::log_signal_exit(msg);
            exit_group_and_run_next(errno);
        }
        crate::syscall::signal::maybe_deliver_signal();
    }
    {
        let cx = get_trap_context();
        cx.sstatus = (cx.sstatus & !PRMD_USER_IE_MASK) | PRMD_USER_IE;
    }
    if let Some(task) = crate::task::processor::current_task() {
        // LoongArch returns with the user ASID programmed in the trampoline.
        // Prepare the lazy-FPU gate before switching away from kernel ASID 0.
        super::super::prepare_user_fp_state(&task);
    }
    // IMPORTANT: `trap_return()` diverges, so keep Arc owners in a short scope.
    let (trap_cx_ptr, user_token, user_asid, need_flush) = {
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
        let user_token = task.get_user_token();
        // ASID allocation can request a one-time flush after generation wrap;
        // normal context switches keep tagged user translations hot.
        let (user_asid, need_flush) = task.prepare_user_asid();
        (trap_cx_ptr, user_token, user_asid, need_flush)
    };

    if DEBUG_TRAP {
        let cnt = TRAP_RETURN_COUNT.fetch_add(1, Ordering::SeqCst);
        if cnt < 4 {
            let hart = super::super::hart_id();
            if !FIRST_TRAP_RETURN_LOGGED.swap(true, Ordering::SeqCst) {
                let cx = get_trap_context();
                println!(
                    "[trap_return#{}] hart={} trap_cx_ptr={:#x} era={:#x} user_token={:#x} asid={} need_flush={}",
                    cnt, hart, trap_cx_ptr, cx.sepc, user_token, user_asid, need_flush
                );
                let user_pt = crate::mm::PageTable::from_token(user_token);
                let tramp_pte = user_pt.translate(VirtAddr::from(TRAMPOLINE).floor());
                let entry_pte = user_pt.translate(VirtAddr::from(cx.sepc).floor());
                let trap_pte = user_pt.translate(VirtAddr::from(trap_cx_ptr).floor());
                let sp = cx.x[super::super::REG_SP];
                let sp_pte = user_pt.translate(VirtAddr::from(sp).floor());
                let kernel_token = crate::mm::cached_kernel_token();
                let kernel_pt = crate::mm::PageTable::from_token(kernel_token);
                let k_tramp_pte = kernel_pt.translate(VirtAddr::from(TRAMPOLINE).floor());
                println!(
                    "[trap_return#{}] pte tramp={:?} entry={:?} trapcx={:?} sp={:?}",
                    cnt,
                    tramp_pte.map(|pte| (pte.ppn().0, pte.flags().bits())),
                    entry_pte.map(|pte| (pte.ppn().0, pte.flags().bits())),
                    trap_pte.map(|pte| (pte.ppn().0, pte.flags().bits())),
                    sp_pte.map(|pte| (pte.ppn().0, pte.flags().bits()))
                );
                println!(
                    "[trap_return#{}] prmd={:#x} sp={:#x} ktramp={:?} ktoken={:#x}",
                    cnt,
                    cx.sstatus,
                    sp,
                    k_tramp_pte.map(|pte| (pte.ppn().0, pte.flags().bits())),
                    kernel_token
                );
            }
        }
    }

    unsafe extern "C" {
        fn alltraps();
        fn restore();
    }

    //利用TRAMPOLINE相对于大家的地址都是一样的,每个 TRAMPOLINE 内部结构也是一样的
    let restore_va = restore as *const () as usize - alltraps as *const () as usize + TRAMPOLINE;
    // SAFETY: `restore_va` points at the trampoline restore stub, and the argument registers are
    // loaded with the trap context pointer and user token expected by that stub. Jumping to the
    // wrong address or with mismatched registers would not return to userspace correctly.
    unsafe {
        asm!(
            "jirl $r0, {restore_va}, 0",
            restore_va = in(reg) restore_va,
            in("$r4") trap_cx_ptr,
            in("$r5") user_token,
            in("$r6") user_asid,
            in("$r7") usize::from(need_flush),
            options(noreturn)
        );
    }
}

pub fn get_current_token() -> usize {
    crate::task::processor::current_task()
        .expect("get_current_token without current task")
        .get_user_token()
}
