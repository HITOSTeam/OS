//! POSIX 消息队列——异步通知（`mq_notify`）的注册与投递
//!
//! 本文件负责两件事：
//!
//! 1. **注册解析**（`parse_notify_registration`）：从用户空间读取 `sigevent` 结构体，
//!    校验参数合法性，构造内核侧的 `NotifyRegistration`，支持四种通知模式：
//!    - `SIGEV_SIGNAL`：消息到达时向注册进程发送指定实时信号
//!    - `SIGEV_NONE`：占据注册槽但不发送任何通知（防止其他进程抢注）
//!    - `SIGEV_THREAD`：通过 Unix domain socket 向用户态线程池发送 cookie，
//!      由线程池负责分发任务（`sigev_signo` 字段被复用为 socket fd）
//!    - `SIGEV_THREAD_ID`：向同进程内的指定线程（tid）发送信号
//!
//! 2. **通知投递**（`deliver_notification`、`send_removed_if_thread`、
//!    `maybe_clear_notify_for_owner`）：在消息到达（从空变非空）或注册被撤销时
//!    执行实际的信号发送或 socket 写入，并保证通知只触发一次（触发后自动清除注册）。

use alloc::sync::Arc;

use super::abi::{
    MQ_NOTIFY_COOKIE_LEN, MQ_NOTIFY_REMOVED, MQ_NOTIFY_WOKENUP, SI_MESGQ, SIGEV_NONE, SIGEV_SIGNAL,
    SIGEV_THREAD, SIGEV_THREAD_ID, SigeventUser, valid_realtime_signal,
};
use super::object::{Cred, MqQueue};
use crate::mm::{try_copy_from_user, try_read_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::signal::RT_SIG_MAX;
use crate::trap::get_current_token;

/// mq_notify 注册记录，每个队列至多一个，first-come-first-serve
#[derive(Clone, Copy)]
pub(super) struct NotifyRegistration {
    pub(super) owner_pid: usize, // 注册进程 pid，关闭 fd 时清除属于该 pid 的注册
    pub(super) notify: i32,      // 通知方式（SIGEV_* 常量）
    pub(super) signo: i32,       // 信号号（SIGEV_SIGNAL/THREAD_ID）或 socket fd（SIGEV_THREAD）
    pub(super) sig_value: usize, // 随信号/通知一并传递的附加值
    pub(super) tid: Option<usize>, // SIGEV_THREAD_ID 时的目标线程 tid
    pub(super) thread_sockfd: usize, // SIGEV_THREAD 时的 socket fd
    pub(super) thread_cookie: [u8; MQ_NOTIFY_COOKIE_LEN], // SIGEV_THREAD 时写入 socket 的 cookie
}

/// 解析 `mq_notify` 系统调用传入的 `sigevent`，构造内核侧的 `NotifyRegistration`
///
/// 返回三种情形：
/// - `Ok(None)`：`notification == 0`，调用者意图取消注册（实际清除工作在 mod.rs 中完成）
/// - `Ok(Some(reg))`：解析成功，可写入 `MqQueueState::notify`
/// - `Err(errno)`：参数非法（无效信号号、无效 socket fd、tid 缺失等）
///
/// 各 `SIGEV_*` 模式的关键校验：
/// - `SIGEV_SIGNAL` / `SIGEV_THREAD_ID`：要求 `sigev_signo` 是合法可投递信号
/// - `SIGEV_THREAD`：复用 `sigev_signo` 字段为 socket fd，并从 `sigev_value`
///   指向的用户内存读取 32 字节 cookie；socket 本身的可用性由
///   `mq_notify_validate_thread_sockfd` 校验
/// - `SIGEV_THREAD_ID`：从 `sigev_data[0]` 中取低 30 bit 作为目标 tid
/// - `SIGEV_NONE`：仅占据注册槽位，不携带任何投递目标信息
///
/// # 参数
/// - `notification`：用户空间 `sigevent*`；为 0 表示撤销注册
/// - `cred`：当前进程凭证快照，注册的 `owner_pid` 由此填充
pub(super) fn parse_notify_registration(
    notification: usize,
    cred: &Cred,
) -> Result<Option<NotifyRegistration>, isize> {
    if notification == 0 {
        return Ok(None);
    }
    let token = get_current_token();
    let Some(ev) = try_read_user_value(token, notification as *const SigeventUser) else {
        return Err(err(SyscallError::EFAULT));
    };
    let parsed_ev = match ev.sigev_notify {
        SIGEV_NONE => NotifyRegistration {
            owner_pid: cred.pid,
            notify: SIGEV_NONE,
            signo: 0,
            sig_value: ev.sigev_value,
            tid: None,
            thread_sockfd: 0,
            thread_cookie: [0; MQ_NOTIFY_COOKIE_LEN],
        },
        SIGEV_SIGNAL => {
            if ev.sigev_signo <= 0 || ev.sigev_signo as usize > RT_SIG_MAX {
                return Err(err(SyscallError::EINVAL));
            }
            NotifyRegistration {
                owner_pid: cred.pid,
                notify: SIGEV_SIGNAL,
                signo: ev.sigev_signo,
                sig_value: ev.sigev_value,
                tid: None,
                thread_sockfd: 0,
                thread_cookie: [0; MQ_NOTIFY_COOKIE_LEN],
            }
        }
        SIGEV_THREAD => {
            if ev.sigev_signo < 0 {
                return Err(err(SyscallError::EBADF));
            }
            let sockfd = ev.sigev_signo as usize;
            let sock_ok = crate::syscall::net::mq_notify_validate_thread_sockfd(cred.pid, sockfd);
            if sock_ok != 0 {
                return Err(sock_ok);
            }
            let mut cookie = [0u8; MQ_NOTIFY_COOKIE_LEN];
            if try_copy_from_user(token, ev.sigev_value as *const u8, &mut cookie).is_err() {
                return Err(err(SyscallError::EFAULT));
            }
            NotifyRegistration {
                owner_pid: cred.pid,
                notify: SIGEV_THREAD,
                signo: ev.sigev_signo,
                sig_value: ev.sigev_value,
                tid: None,
                thread_sockfd: sockfd,
                thread_cookie: cookie,
            }
        }
        SIGEV_THREAD_ID => {
            if ev.sigev_signo <= 0 || ev.sigev_signo as usize > RT_SIG_MAX {
                return Err(err(SyscallError::EINVAL));
            }
            let tid = ev.sigev_data[0] & 0x3fff_ffff;
            if tid == 0 {
                return Err(err(SyscallError::EINVAL));
            }
            NotifyRegistration {
                owner_pid: cred.pid,
                notify: SIGEV_THREAD_ID,
                signo: ev.sigev_signo,
                sig_value: ev.sigev_value,
                tid: Some(tid),
                thread_sockfd: 0,
                thread_cookie: [0; MQ_NOTIFY_COOKIE_LEN],
            }
        }
        _ => return Err(err(SyscallError::EINVAL)),
    };
    Ok(Some(parsed_ev))
}

/// 在注册被取消时通知 `SIGEV_THREAD` 模式下的用户态线程池
///
/// 仅 `SIGEV_THREAD` 注册需要发送 REMOVED cookie，其他模式下本函数为 no-op。
/// 失败（例如 socket 已关闭）时静默忽略——cookie 发送是尽力而为的清理操作。
///
/// # 参数
/// - `reg`：被撤销/失效的注册项；按值传入，调用方已经从 `state.notify` 中取走
pub(super) fn send_removed_if_thread(reg: NotifyRegistration) {
    if reg.notify == SIGEV_THREAD {
        let _ = crate::syscall::net::mq_notify_send_thread_event(
            reg.owner_pid,
            reg.thread_sockfd,
            reg.thread_cookie,
            MQ_NOTIFY_REMOVED,
        );
    }
}

/// 当进程关闭 mq fd 时，若该进程注册了 notify，需清除注册
/// SIGEV_THREAD 模式下还需向 socket 发送 REMOVED 事件告知用户态线程池
///
/// # 参数
/// - `queue`：被关闭 fd 所引用的共享队列对象
/// - `owner_pid`：发起本次清理的进程 pid；只清除属于该 pid 的注册
pub(super) fn maybe_clear_notify_for_owner(queue: &Arc<MqQueue>, owner_pid: usize) {
    let notify = {
        let mut state = queue.state.lock();
        if state
            .notify
            .is_some_and(|notify| notify.owner_pid == owner_pid)
        {
            state.notify.take()
        } else {
            None
        }
    };
    if let Some(reg) = notify {
        send_removed_if_thread(reg);
    }
}

/// 触发 mq_notify 注册的通知
/// SIGEV_THREAD：向 socket 发送 WOKENUP cookie，用户态线程池据此分发任务
/// SIGEV_SIGNAL/THREAD_ID：向目标进程/线程投递带 SI_MESGQ 的实时信号
///
/// # 参数
/// - `reg`：要触发的注册项（来自 `state.notify.take()`，触发后即被消费）
/// - `sender_pid`：触发本次通知的发送者 pid，写入 `siginfo.si_pid`
/// - `sender_uid`：触发本次通知的发送者真实 uid，写入 `siginfo.si_uid`
pub(super) fn deliver_notification(reg: NotifyRegistration, sender_pid: i32, sender_uid: u32) {
    if reg.notify == SIGEV_THREAD {
        let _ = crate::syscall::net::mq_notify_send_thread_event(
            reg.owner_pid,
            reg.thread_sockfd,
            reg.thread_cookie,
            MQ_NOTIFY_WOKENUP,
        );
        return;
    }
    let signo = reg.signo as usize;
    if !valid_realtime_signal(signo) {
        return;
    }
    let _ = crate::syscall::signal::queue_signal_with_info(
        reg.owner_pid,
        reg.tid,
        signo,
        sender_pid,
        sender_uid,
        SI_MESGQ,
        reg.sig_value,
    );
}
