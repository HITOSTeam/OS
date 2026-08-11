//! POSIX 消息队列——ABI 常量、用户空间结构体及跨模块共用的辅助函数
//!
//! 本文件集中存放三类内容：
//! 1. **常量**：文件打开标志（O_*）、sigevent 通知类型（SIGEV_*）、
//!    队列名称长度限制、消息优先级上限、队列数量上限等，均与 Linux ABI 保持一致。
//! 2. **用户空间 ABI 结构体**：`MqAttrUser`、`TimeSpecUser`、`SigeventUser`，
//!    直接映射用户空间内存布局，通过 `try_read/write_user_value` 读写。
//! 3. **辅助函数**：时钟转换（`monotonic_now_ns`、`realtime_now_ns`）、超时解析
//!    （`parse_abs_timeout`、`timed_out`、`arm_timeout_timer`）、队列名称校验
//!    （`read_queue_name`）、信号/阻塞检查（`has_pending_unmasked_signal`）等，
//!    供 `mod.rs`、`notify.rs` 等上层模块共享使用。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::mm::try_read_user_value;
use crate::syscall::error::{SyscallError, err};
use crate::task::block_sleep::add_timer;
use crate::task::processor::{current_process, current_task};
use crate::task::signal::{RT_SIG_MAX, has_wait_interrupting_pending, signal_bit};
use crate::task::task_block::TaskControlBlock;
use crate::trap::get_current_token;

// --- 文件打开标志（与 Linux open(2) 标志位一致）---
pub(super) const O_ACCMODE: usize = 0x3; // 访问模式掩码
pub(super) const O_RDONLY: usize = 0x0; // 只读
pub(super) const O_WRONLY: usize = 0x1; // 只写
pub(super) const O_RDWR: usize = 0x2; // 读写
pub(super) const O_CREAT: usize = 0x40; // 不存在时创建
pub(super) const O_EXCL: usize = 0x80; // 与 O_CREAT 配合，已存在则报 EEXIST
pub(super) const O_NONBLOCK: usize = 0x800; // 非阻塞模式
pub(super) const O_CLOEXEC: usize = 0x80000; // exec 时自动关闭
pub(super) const FD_CLOEXEC: u32 = 1; // fcntl 文件描述符级 close-on-exec 标志

// --- sigevent 通知类型（POSIX sigevent.sigev_notify 取值）---
pub(super) const SIGEV_SIGNAL: i32 = 0; // 发送信号
pub(super) const SIGEV_NONE: i32 = 1; // 不通知（仅占用注册位，阻止其他进程注册）
pub(super) const SIGEV_THREAD: i32 = 2; // 通过线程/socket 通知（用户态线程池模式）
pub(super) const SIGEV_THREAD_ID: i32 = 4; // 向指定线程发送信号
// SI_MESGQ 是信号 siginfo.si_code 的值，表示信号由消息队列触发
pub(super) const SI_MESGQ: i32 = -3;

// --- 队列名称与容量限制 ---
pub(super) const MQ_NAME_MAX: usize = 255; // 队列名最大字节数（不含前导 '/'）
pub(super) const MQ_NAME_MAX_WITH_SLASH: usize = MQ_NAME_MAX + 1; // 含前导 '/' 时的最大长度
pub(super) const MQ_PRIO_MAX: usize = 32768; // 消息优先级上限（不含，0..32767 有效）
pub(super) const MQ_DEFAULT_MAXMSG: usize = 10; // 新建队列默认最大消息条数
pub(super) const MQ_DEFAULT_MSGSIZE: usize = 8192; // 新建队列默认单条消息最大字节数
pub(super) const MQ_DEFAULT_QUEUES_MAX: usize = 256; // 系统默认允许的队列总数上限
pub(super) const MQ_HARD_QUEUES_MAX: usize = 65536; // 通过 procfs 可设置的硬上限
pub(super) const MQ_NOTIFY_COOKIE_LEN: usize = 32; // SIGEV_THREAD 通知 cookie 的字节长度
pub(super) const MQ_NOTIFY_WOKENUP: u8 = 1; // cookie 首字节：消息到达，触发通知
pub(super) const MQ_NOTIFY_REMOVED: u8 = 2; // cookie 首字节：队列被关闭/unlink，注册失效
pub(super) const PROCFS_QUEUES_MAX: &str = "/proc/sys/fs/mqueue/queues_max"; // sysctl 路径
const NSEC_PER_SEC: u64 = 1_000_000_000;

/// 用户空间 mq_attr 结构体（与 glibc/musl ABI 对应）
/// mq_getsetattr 通过该结构在用户/内核间传递队列属性
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct MqAttrUser {
    pub(super) mq_flags: i64,   // 队列标志，当前仅 O_NONBLOCK 有效
    pub(super) mq_maxmsg: i64,  // 队列最大消息条数（只读，创建时确定）
    pub(super) mq_msgsize: i64, // 单条消息最大字节数（只读，创建时确定）
    pub(super) mq_curmsgs: i64, // 当前队列中的消息数（只读）
    pub(super) __reserved: [i64; 4],
}

/// 用户空间 timespec 结构体，用于表示绝对超时时间（CLOCK_REALTIME）
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TimeSpecUser {
    tv_sec: i64,
    tv_nsec: i64,
}

/// 用户空间 sigevent 结构体，用于 mq_notify 注册通知方式
/// 布局与 Linux ABI 一致：sigev_notify 决定如何通知
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct SigeventUser {
    pub(super) sigev_value: usize, // 传递给信号处理函数的附加值（sigval）
    pub(super) sigev_signo: i32,   // SIGEV_SIGNAL/THREAD_ID: 信号号；SIGEV_THREAD: socket fd
    pub(super) sigev_notify: i32, // 通知类型：SIGEV_SIGNAL / SIGEV_NONE / SIGEV_THREAD / SIGEV_THREAD_ID
    pub(super) sigev_data: [usize; 2], // SIGEV_THREAD_ID 时 [0] 存放目标线程 tid
}

/// 单调时钟当前时间（纳秒），基于硬件 tick 计数换算
fn monotonic_now_ns() -> u64 {
    crate::time::get_time_ns()
}

/// 实时时钟当前时间（纳秒），与超时参数使用相同的时钟基准（CLOCK_REALTIME）
fn realtime_now_ns() -> u64 {
    let sec = crate::syscall::time_sys::realtime_now_seconds();
    sec.saturating_mul(NSEC_PER_SEC)
        .saturating_add(monotonic_now_ns() % NSEC_PER_SEC)
}

/// 从用户空间读取绝对超时时间，转换为纳秒
/// timeout_ptr == 0 表示无超时（阻塞等待），返回 None
///
/// # 参数
/// - `timeout_ptr`：用户空间 `timespec*` 指针；为 0 表示无超时
pub(super) fn parse_abs_timeout(timeout_ptr: usize) -> Result<Option<u64>, isize> {
    if timeout_ptr == 0 {
        return Ok(None);
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value(token, timeout_ptr as *const TimeSpecUser) else {
        return Err(err(SyscallError::EFAULT));
    };
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NSEC_PER_SEC as i64 {
        return Err(err(SyscallError::EINVAL));
    }
    let sec = ts.tv_sec as u64;
    let nsec = ts.tv_nsec as u64;
    Ok(Some(sec.saturating_mul(NSEC_PER_SEC).saturating_add(nsec)))
}

/// 判断给定的绝对截止时间是否已过期
pub(super) fn timed_out(deadline_ns: Option<u64>) -> bool {
    deadline_ns.is_some_and(|deadline| realtime_now_ns() >= deadline)
}

/// 为当前任务设置超时定时器，到期后将任务从 Blocked 状态唤醒
/// 向上取整到毫秒，且至少等待 1ms，避免 add_timer(0) 语义问题
///
/// # 参数
/// - `task`：需要设置超时的任务（通常为当前任务）
/// - `deadline_ns`：基于 `CLOCK_REALTIME` 的绝对截止纳秒数
pub(super) fn arm_timeout_timer(task: &Arc<TaskControlBlock>, deadline_ns: u64) {
    let now = realtime_now_ns();
    let remain_ns = deadline_ns.saturating_sub(now);
    let mut wait_ms = remain_ns / 1_000_000;
    if remain_ns % 1_000_000 != 0 {
        wait_ms = wait_ms.saturating_add(1);
    }
    let wait_ms = (wait_ms as usize).max(1);
    add_timer(Arc::clone(task), wait_ms);
}

/// 检查当前任务是否有未屏蔽的待处理信号，用于决定是否以 EINTR 中断阻塞等待
pub(super) fn has_pending_unmasked_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
}

/// 取得当前进程所属的 IPC 命名空间 ID
///
/// POSIX 消息队列在命名空间维度完全隔离：不同命名空间下即便重名也是不同的队列对象，
/// `MQ_MANAGERS` 即以该 ID 作为外层索引键。
pub(super) fn current_ipc_namespace_id() -> usize {
    let process = current_process();
    process.borrow_mut().ipc_ns_id
}

/// 从用户空间读取队列名称字符串并验证合法性
/// POSIX 要求队列名以 '/' 开头，内部不含 '/'，长度 <= MQ_NAME_MAX
/// 返回不含前导 '/' 的规范名称
///
/// # 参数
/// - `ptr`：用户空间 C 字符串指针；为 0 返回 EFAULT
pub(super) fn read_queue_name(ptr: usize) -> Result<String, isize> {
    if ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut bytes = Vec::new();
    let mut cur = ptr;
    loop {
        let Some(ch) = try_read_user_value(token, cur as *const u8) else {
            return Err(err(SyscallError::EFAULT));
        };
        if ch == 0 {
            break;
        }
        bytes.push(ch);
        // 提前截断，避免无界循环读取超长用户空间字符串
        if bytes.len() > MQ_NAME_MAX_WITH_SLASH {
            return Err(err(SyscallError::ENAMETOOLONG));
        }
        cur = cur.saturating_add(1);
    }
    if bytes.is_empty() {
        return Err(err(SyscallError::EINVAL));
    }
    let name = if bytes[0] == b'/' {
        if bytes.len() == 1 {
            return Err(err(SyscallError::EINVAL)); // 名称不能只是 "/"
        }
        &bytes[1..] // 去掉前导 '/'，内核内部以不含斜杠的名称作为 key
    } else {
        &bytes[..]
    };
    if name.is_empty() {
        return Err(err(SyscallError::EINVAL));
    }
    if name.len() > MQ_NAME_MAX {
        return Err(err(SyscallError::ENAMETOOLONG));
    }
    if name.iter().any(|ch| *ch == b'/') {
        return Err(err(SyscallError::EINVAL)); // 名称中不允许有斜杠
    }
    String::from_utf8(name.to_vec()).map_err(|_| err(SyscallError::EINVAL))
}

/// 检查给定信号号是否为合法的可投递信号
///
/// `mq_notify` 仅接受真实存在且可被进程接收的信号；要求 `signo != 0`、
/// 在系统支持范围内（`<= RT_SIG_MAX`），并且 `signal_bit` 能为其分配位掩码。
pub(super) fn valid_realtime_signal(signo: usize) -> bool {
    signo != 0 && signo <= RT_SIG_MAX && signal_bit(signo).is_some()
}
