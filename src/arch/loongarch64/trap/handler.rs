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
use crate::task::block_sleep::{
    check_timer, take_deferred_kernel_timer_tick, timer_work_pending_for_user_return,
};
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
const ECODE_FP_DISABLED: usize = 0xf;
const ECODE_LSX_DISABLED: usize = 0x10;
const ECODE_LASX_DISABLED: usize = 0x11;

use super::super::csr_defs::{
    ESTAT_ECODE_MASK, ESTAT_ECODE_SHIFT, ESTAT_IS_IPI, ESTAT_IS_TIMER, PRMD_USER_IE,
    PRMD_USER_IE_MASK,
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
    unsafe { asm!("csrwr {}, 0xc", inout(reg) val => _) };
}

fn set_kernel_trap_entry() {
    unsafe extern "C" {
        fn alltraps_k();
    }
    write_eentry(alltraps_k as usize);
}

fn set_user_trap_entry() {
    // Use the trampoline VA so traps from user mode always enter via a
    // user-mapped page (matches the RISC-V flow).
    write_eentry(TRAMPOLINE as usize);
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
            return;
        }
        if (estat & ESTAT_IS_IPI) != 0 {
            super::super::clear_ipi_interrupt();
            return;
        }
    }
    let current = crate::task::processor::current_task();
    let (pid, tid, task_ra, task_sp, on_cpu) = current
        .as_ref()
        .map(|task| {
            let pid = task
                .process
                .upgrade()
                .map(|process| process.getpid())
                .unwrap_or(usize::MAX);
            let inner = task.borrow_mut();
            (
                pid,
                inner
                    .res
                    .as_ref()
                    .map(|res| res.tid)
                    .unwrap_or(usize::MAX),
                inner.task_cx.ra,
                inner.task_cx.sp,
                task.on_cpu.load(Ordering::Acquire),
            )
        })
        .unwrap_or((usize::MAX, usize::MAX, 0, 0, usize::MAX));
    panic!(
        "Unhandled kernel trap: hart={} ecode={} badv={:#x} badi={:#x} era={:#x} ra={:#x} sp={:#x} a0={:#x} pid={} tid={} task_ra={:#x} task_sp={:#x} on_cpu={}",
        super::super::hart_id(),
        ecode,
        read_badv(),
        read_badi(),
        trap_cx.sepc,
        trap_cx.x[super::super::REG_RA],
        trap_cx.x[super::super::REG_SP],
        trap_cx.x[4],
        pid,
        tid,
        task_ra,
        task_sp,
        on_cpu,
    );
}

fn handle_user_exception(ecode: usize, badv: usize) {
    if ecode == ECODE_PAGE_INVALID_FETCH && badv == 0 {
        if crate::syscall::signal::try_sigreturn_from_fault() {
            return;
        }
    }
    if matches!(ecode, ECODE_PAGE_INVALID_STORE | ECODE_PAGE_MODIFY) {
        let process = crate::task::processor::current_process();
        let inner = process.borrow_mut();
        if inner.memory_set.resolve_cow_fault(badv) {
            return;
        }
    }
    if matches!(
        ecode,
        ECODE_PAGE_INVALID_LOAD
            | ECODE_PAGE_INVALID_STORE
            | ECODE_PAGE_INVALID_FETCH
            | ECODE_PAGE_MODIFY
            | ECODE_PAGE_NON_READ
            | ECODE_PAGE_NON_EXEC
            | ECODE_PAGE_PRIV
    ) {
        let process = crate::task::processor::current_process();
        let inner = process.borrow_mut();
        let access = match ecode {
            ECODE_PAGE_INVALID_LOAD | ECODE_PAGE_NON_READ => MapPermission::R,
            ECODE_PAGE_INVALID_FETCH | ECODE_PAGE_NON_EXEC => MapPermission::X,
            _ => MapPermission::W,
        };
        match inner.memory_set.resolve_lazy_fault(badv, access) {
            LazyFaultResult::Resolved => return,
            LazyFaultResult::Oom => {
                drop(inner);
                exit_group_and_run_next(-9);
            }
            LazyFaultResult::Invalid => {}
        }
    }
    if matches!(
        ecode,
        ECODE_PAGE_INVALID_LOAD
            | ECODE_PAGE_INVALID_STORE
            | ECODE_PAGE_INVALID_FETCH
            | ECODE_PAGE_MODIFY
            | ECODE_PAGE_NON_READ
            | ECODE_PAGE_NON_EXEC
            | ECODE_PAGE_PRIV
    ) {
        let process = crate::task::processor::current_process();
        let inner = process.borrow_mut();
        let access = match ecode {
            ECODE_PAGE_INVALID_LOAD | ECODE_PAGE_NON_READ => MapPermission::R,
            ECODE_PAGE_INVALID_FETCH | ECODE_PAGE_NON_EXEC => MapPermission::X,
            _ => MapPermission::W,
        };
        match inner.memory_set.try_expand_growsdown(badv, access) {
            LazyFaultResult::Resolved => return,
            LazyFaultResult::Oom => {
                drop(inner);
                exit_group_and_run_next(-9);
            }
            LazyFaultResult::Invalid => {}
        }
    }
    if let Some((errno, msg)) = check_if_current_signals_error() {
        crate::task::signal::log_signal_exit(msg);
        exit_group_and_run_next(errno);
    }
    let cx = get_trap_context();
    let badi = read_badi();
    println!(
        "[user_exn] ecode={} badv={:#x} badi={:#010x} era={:#x} ra={:#x} sp={:#x} tp={:#x}",
        ecode,
        badv,
        badi,
        cx.sepc,
        cx.x[super::super::REG_RA],
        cx.x[super::super::REG_SP],
        cx.x[super::super::REG_TP]
    );
    exit_group_and_run_next(-11);
}

#[unsafe(no_mangle)]
pub fn trap_handler() {
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
        } else if (estat & ESTAT_IS_IPI) != 0 {
            super::super::clear_ipi_interrupt();
        } else {
            //非时钟中断目前先panic
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
        let result = syscall(syscall_id, args);
        let cx = get_trap_context();
        cx.x[super::super::REG_A0] = result as usize;
    } else if ecode == ECODE_FP_DISABLED {
        // Lazy-FPU path: enable/restore the task's FP state and retry the
        // trapped user instruction instead of saving FP on every context switch.
        super::super::handle_user_fp_disabled();
    } else if ecode == ECODE_LSX_DISABLED {
        // LSX shares the FP register file. Restore the task's state, enable
        // LSX for this quantum and retry the trapped vector instruction.
        super::super::handle_user_lsx_disabled();
    } else if ecode == ECODE_LASX_DISABLED {
        // LASX is layered on LSX and the scalar FPU, so all three gates must
        // be enabled before retrying.
        super::super::handle_user_lasx_disabled();
    } else {
        match ecode {
            ECODE_ADDR_ERROR | ECODE_ADDR_ALIGN => handle_user_exception(ecode, badv),
            _ => handle_user_exception(ecode, badv),
        }
    }

    if let Some((errno, msg)) = check_if_current_signals_error() {
        crate::task::signal::log_signal_exit(msg);
        exit_group_and_run_next(errno);
    }
    let deferred_scheduler_tick = take_deferred_kernel_timer_tick();
    if deferred_scheduler_tick || timer_work_pending_for_user_return() {
        check_timer();
        crate::task::processor::account_current_task_tick();
        crate::syscall::misc::check_current_rlimit_cpu();
        if crate::task::processor::should_preempt_current_on_tick() {
            suspend_current_and_run_next();
        }
    }
    if deferred_scheduler_tick {
        crate::task::processor::account_current_task_tick();
        crate::syscall::misc::check_current_rlimit_cpu();
        if let Some((errno, msg)) = check_if_current_signals_error() {
            crate::task::signal::log_signal_exit(msg);
            exit_group_and_run_next(errno);
        }
        crate::fs::cgroup_maybe_block_current();
        if crate::task::processor::should_preempt_current_on_tick() {
            suspend_current_and_run_next();
        }
    }
    crate::syscall::signal::maybe_deliver_signal();
    crate::fs::cgroup_maybe_block_current();
    if syscall_return && crate::task::processor::should_preempt_current_on_syscall_return() {
        suspend_current_and_run_next();
    }
    // 返回用户态前的抢占点：消费本 hart 的 NEED_RESCHED，让刚唤醒的高优先级
    // 任务尽快运行（见 processor::reschedule_before_user_return_if_needed）。
    crate::task::processor::reschedule_before_user_return_if_needed();
    trap_return();
}
pub fn trap_return() -> ! {
    if DEBUG_TRAP {
        if !TRAP_RETURN_ENTER_LOGGED.swap(true, Ordering::SeqCst) {
            println!(
                "[trap_return] enter hart={} trap_return_va={:#x}",
                super::super::hart_id(),
                trap_return as usize
            );
        }
    }
    // Keep kernel trap entry active while we are still running in kernel mode.
    set_kernel_trap_entry();
    // A task can receive a signal while it is already runnable. When the
    // scheduler later restores it, execution reaches this path directly without
    // another trap handler pass, so honor pending signals before userspace.
    if let Some(task) = crate::task::processor::current_task()
        && task.has_signal_pending()
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
    let restore_va = restore as usize - alltraps as usize + TRAMPOLINE;
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
    let now_task_block = crate::task::processor::current_task().unwrap();
    let process = now_task_block.process.upgrade().unwrap();
    let process_inner = process.borrow_mut();
    process_inner.memory_set.token()
}
