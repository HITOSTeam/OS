#[cfg(target_arch = "loongarch64")]
pub use crate::arch::loongarch64::trap;
#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::trap;

#[cfg(target_arch = "loongarch64")]
pub use crate::arch::loongarch64::trap::context;
#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::trap::context;

#[cfg(target_arch = "loongarch64")]
pub use crate::arch::loongarch64::trap::{
    get_current_token, init_trap, trap_handler, trap_return,
};
#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::trap::{get_current_token, init_trap, trap_handler, trap_return};

/// Run the architecture-independent work required before returning to user
/// mode.
///
/// Architecture trap handlers only decode the hardware event and update the
/// saved register state. Timer accounting, signal delivery, cgroup freezing,
/// and scheduler preemption are common kernel semantics and must have one
/// implementation. In particular, a deferred kernel tick is consumed and
/// charged exactly once here.
pub(crate) fn exit_to_user_mode_loop(syscall_return: bool) {
    use crate::task::{
        block_sleep::{
            check_timer, take_deferred_kernel_timer_tick, timer_work_pending_for_user_return,
        },
        processor::{
            exit_group_and_run_next, reschedule_before_user_return_if_needed,
            should_preempt_current_on_syscall_return, should_preempt_current_on_tick,
            suspend_current_and_run_next,
        },
        signal::check_if_current_signals_error,
    };

    if let Some((errno, msg)) = check_if_current_signals_error() {
        crate::task::signal::log_signal_exit(msg);
        exit_group_and_run_next(errno);
    }

    // 硬件 tick 有两个相互独立的职责：调度记账，以及使墙钟定时器到期。
    // 消费一个普通调度 tick 不应该强制扫描全局 sleep/alarm/POSIX/timerfd 表；
    // 这些表已经发布了活跃计数和最近 deadline，只有 O(1) 快速判断确认有
    // 定时器真正到期时才进入 `check_timer()`。
    let deferred_scheduler_tick = take_deferred_kernel_timer_tick();
    if timer_work_pending_for_user_return() {
        check_timer();
    }
    if deferred_scheduler_tick {
        crate::task::processor::account_current_task_tick();
        crate::syscall::misc::check_current_rlimit_cpu();
        if let Some((errno, msg)) = check_if_current_signals_error() {
            crate::task::signal::log_signal_exit(msg);
            exit_group_and_run_next(errno);
        }
        crate::fs::cgroup_maybe_block_current();
        if should_preempt_current_on_tick() {
            suspend_current_and_run_next();
        }
    }

    crate::syscall::signal::maybe_deliver_signal();
    crate::fs::cgroup_maybe_block_current();
    if syscall_return && should_preempt_current_on_syscall_return() {
        suspend_current_and_run_next();
    }
    // Consume the common NEED_RESCHED work bit last, matching Linux's
    // exit-to-user ordering after signal and scheduler-tick work.
    reschedule_before_user_return_if_needed();
}
