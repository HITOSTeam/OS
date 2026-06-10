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
use crate::task::signal::check_if_current_signals_error;
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

use super::super::csr_defs::{
    ECFG_LIE_TI, ESTAT_ECODE_MASK, ESTAT_ECODE_SHIFT, PRMD_USER_IE, PRMD_USER_IE_MASK,
};

const ESTAT_TIMER_BIT: usize = 11;

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
    unsafe { asm!("csrwr {}, 0xc", in(reg) val) };
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
    if ecode == 0 && (estat & (1 << ESTAT_TIMER_BIT)) != 0 {
        super::super::clear_timer_interrupt();
        set_next_trigger();
        check_timer();
        return;
    }
    panic!(
        "Unhandled kernel trap: ecode={} badv={:#x} badi={:#x} era={:#x}",
        ecode,
        read_badv(),
        read_badi(),
        trap_cx.sepc
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
        println!("[kernel] {}", msg);
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
    let idx = TRAP_HANDLER_COUNT.fetch_add(1, Ordering::SeqCst);
    if DEBUG_TRAP && idx < 4 {
        let hart = super::super::hart_id();
        println!("[trap_handler#{}] hart={}", idx, hart);
    }

    //从用户态上来的时候需要设置trap入口,不然等下容易死循环
    set_kernel_trap_entry();

    //记录trap类型
    let estat = read_estat();
    //
    let ecode = (estat >> ESTAT_ECODE_SHIFT) & ESTAT_ECODE_MASK;
    let badv = read_badv();
    let badi = read_badi();

    /*
    
        ecode == 0              -> 中断类，当前主要处理 timer interrupt
        ecode == ECODE_SYSCALL  -> syscall
        其他 ecode              -> 用户异常，例如缺页、非法访问、权限错误、地址未对齐
     */
    if ecode == 0 {
        if (estat & (1 << ESTAT_TIMER_BIT)) != 0 {
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
                println!("[kernel] {}", msg);
                exit_group_and_run_next(errno);
            }
            crate::fs::cgroup_maybe_block_current();
            if crate::task::processor::should_preempt_current_on_tick() {
                suspend_current_and_run_next();
            }
        } else {
            //非时钟中断目前先panic 
            panic!(
                "Unhandled interrupt: estat={:#x} badv={:#x} badi={:#x}",
                estat, badv, badi
            );
        }
    } else if ecode == ECODE_SYSCALL {
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
        let result = syscall(syscall_id, args);
        let cx = get_trap_context();
        cx.x[super::super::REG_A0] = result as usize;
    } else {
        match ecode {
            ECODE_ADDR_ERROR | ECODE_ADDR_ALIGN => handle_user_exception(ecode, badv),
            _ => handle_user_exception(ecode, badv),
        }
    }

    if let Some((errno, msg)) = check_if_current_signals_error() {
        println!("[kernel] {}", msg);
        exit_group_and_run_next(errno);
    }
    check_timer();
    crate::syscall::signal::maybe_deliver_signal();
    crate::fs::cgroup_maybe_block_current();
    // 返回用户态前的抢占点：消费本 hart 的 NEED_RESCHED，让刚唤醒的高优先级
    // 任务尽快运行（见 processor::reschedule_before_user_return_if_needed）。
    crate::task::processor::reschedule_before_user_return_if_needed();
    trap_return();
}

pub fn trap_return() -> ! {
    // let trace_first_return =  !TRAP_RETURN_ENTER_LOGGED.swap(true, Ordering::SeqCst);
    // if trace_first_return {
    //     println!(
    //         "[trap_return] enter hart={} trap_return_va={:#x}",
    //         super::super::hart_id(),
    //         trap_return as usize
    //     );
    // }
    // Keep kernel trap entry active while we are still running in kernel mode.
    set_kernel_trap_entry();
    // if trace_first_return {
    //     let task = crate::task::processor::current_task().unwrap();
    //     let (trap_cx_ppn, trap_cx_user_va) = {
    //         let task_inner = task.borrow_mut();
    //         let trap_cx_user_va = task_inner
    //             .res
    //             .as_ref()
    //             .map(|res| res.trap_cx_user_va())
    //             .unwrap_or(0);
    //         (task_inner.trap_cx_ppn, trap_cx_user_va)
    //     };
    //     println!(
    //         "[trap_return] stage1 task_ptr={:#x} trap_cx_ppn={:#x} trap_cx_user_va={:#x}",
    //         (&*task as *const _) as usize,
    //         trap_cx_ppn.0,
    //         trap_cx_user_va
    //     );
    // }
    {
        let cx = get_trap_context();
        // if trace_first_return {
        //     println!(
        //         "[trap_return] stage2 trap_cx_ptr={:#x} era={:#x} kernel_sp={:#x} kernel_tp={:#x}",
        //         (cx as *mut TrapContext) as usize,
        //         cx.sepc,
        //         cx.kernel_sp,
        //         cx.kernel_tp
        //     );
        // }
        cx.sstatus = (cx.sstatus & !PRMD_USER_IE_MASK) | PRMD_USER_IE;
    }
    // IMPORTANT: `trap_return()` diverges, so keep Arc owners in a short scope.
    let (trap_cx_ptr, user_token) = {
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
        let user_token = task
            .process
            .upgrade()
            .unwrap()
            .borrow_mut()
            .memory_set
            .token();
        (trap_cx_ptr, user_token)
    };

    let cnt = TRAP_RETURN_COUNT.fetch_add(1, Ordering::SeqCst);
    if DEBUG_TRAP && cnt < 4 {
        let hart = super::super::hart_id();
        if !FIRST_TRAP_RETURN_LOGGED.swap(true, Ordering::SeqCst) {
            let cx = get_trap_context();
            println!(
                "[trap_return#{}] hart={} trap_cx_ptr={:#x} era={:#x} user_token={:#x}",
                cnt, hart, trap_cx_ptr, cx.sepc, user_token
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

    unsafe extern "C" {
        fn alltraps();
        fn restore();
    }
    //这两个函数都在TRAMPOLINE那个地址处,然后alltraps对应地址0 相减计算出对应的汇编地址
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
