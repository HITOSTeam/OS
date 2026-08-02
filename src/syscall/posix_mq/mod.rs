//! POSIX 消息队列（mqueue）子系统
//!
//! 本模块实现 POSIX.1-2008 规定的消息队列接口，对外暴露六个系统调用入口：
//!
//! | 函数                      | 系统调用号       | 说明                         |
//! |---------------------------|-----------------|------------------------------|
//! | `syscall_mq_open`         | 180 / -         | 打开或创建消息队列             |
//! | `syscall_mq_unlink`       | 181             | 从命名空间中移除队列名称        |
//! | `syscall_mq_timedsend`    | 182 / 418(time64) | 发送消息，支持超时阻塞        |
//! | `syscall_mq_timedreceive` | 183 / 419(time64) | 接收消息，支持超时阻塞        |
//! | `syscall_mq_notify`       | 184             | 注册/取消异步到达通知          |
//! | `syscall_mq_getsetattr`   | 185             | 原子读写队列属性               |
//!
//! ## 子模块职责
//! - `abi`：Linux ABI 常量、用户空间结构体、超时/名称解析等跨模块工具函数
//! - `object`：核心数据结构（`MqQueue`、`MqQueueState`、`MqMessage` 等）及等待者管理
//! - `descriptor`：`MqDescriptor`（实现 `File` trait，支持 epoll/poll）
//! - `notify`：`NotifyRegistration` 及通知的解析与投递逻辑

mod abi;
mod descriptor;
mod notify;
mod object;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;

use spin::Mutex;

use abi::{
    FD_CLOEXEC, MQ_DEFAULT_MAXMSG, MQ_DEFAULT_MSGSIZE, MQ_PRIO_MAX, MqAttrUser, O_ACCMODE,
    O_CLOEXEC, O_CREAT, O_EXCL, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, arm_timeout_timer,
    current_ipc_namespace_id, has_pending_unmasked_signal, parse_abs_timeout, read_queue_name,
    timed_out,
};
use descriptor::MqDescriptor;
use notify::{deliver_notification, parse_notify_registration, send_removed_if_thread};
use object::{
    MQ_MANAGERS, MqMessage, MqPerm, MqQueue, MqQueueState, add_waiter_once, check_access,
    current_cred, gc_unlinked_queue, is_owner_or_root, wake_all_waiters, wake_poll_waiters,
};

pub use object::{queues_max_limit_for_procfs, write_mqueue_sysctl};

/// 返回单个 IPC 命名空间下消息队列数量的默认上限
///
/// 仅作为薄封装暴露给同 crate 其他模块使用，便于在不直接依赖 `object`
/// 子模块的情况下读取该限制值（实际生效值由 `queues_max_limit_for_procfs`
/// 给出，可被 `/proc/sys/fs/mqueue/queues_max` 修改）。
#[allow(dead_code)]
pub fn mq_queues_default_limit() -> usize {
    object::mq_queues_default_limit()
}

use crate::fs::{File, PollWaitQueue};
use crate::mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::processor::{current_files, current_files_and_nofile_limit, current_task};
use crate::trap::get_current_token;

/// 通过 fd 获取对应的 File 对象，fd 无效则返回 EBADF
///
/// # 参数
/// - `fd`：调用方提供的文件描述符（mqd_t）
fn resolve_fd_file(fd: usize) -> Result<Arc<dyn File + Send + Sync>, isize> {
    current_files()
        .lock()
        .get_file(fd)
        .ok_or(err(SyscallError::EBADF))
}

/// 将 MqDescriptor 安装到当前进程的文件描述符表，返回分配的 fd 号
///
/// # 参数
/// - `desc`：刚构造好的 `MqDescriptor`，会被向上转型为 `Arc<dyn File>` 后注入 fd 表
/// - `oflag`：`mq_open` 原始 flags，用于推断 fd 级标志（`O_CLOEXEC` → `FD_CLOEXEC`、
///   `O_NONBLOCK` 透传到 fd 标志位以便 `fcntl(F_GETFD/F_GETFL)` 反查）
fn install_descriptor(desc: Arc<MqDescriptor>, oflag: usize) -> Result<usize, isize> {
    let file: Arc<dyn File + Send + Sync> = desc;
    let mut descriptor_flags = 0u32;
    if (oflag & O_CLOEXEC) != 0 {
        descriptor_flags |= FD_CLOEXEC;
    }
    if (oflag & O_NONBLOCK) != 0 {
        descriptor_flags |= O_NONBLOCK as u32;
    }
    let (files, limit) = current_files_and_nofile_limit();
    files
        .lock()
        .install_fd(file, descriptor_flags, limit)
        .ok_or(err(SyscallError::EMFILE))
}

/// mq_open(2)：打开或创建一个 POSIX 消息队列，返回消息队列文件描述符（mqd_t）
///
/// 语义与文件 open 类似：
/// - 若队列不存在且设置了 O_CREAT，则创建；队列容量/消息大小由 `attr` 指定，
///   `attr` 为 NULL 时使用系统默认值（`MQ_DEFAULT_MAXMSG` / `MQ_DEFAULT_MSGSIZE`）
/// - 若队列已存在且同时设置了 `O_CREAT | O_EXCL`，返回 EEXIST
/// - 打开已有队列时按 Unix DAC 规则检查读/写权限；创建时以当前进程 euid/egid 为所有者
/// - fd 安装失败（如 EMFILE）时会回滚已创建的队列，保证操作的原子性
///
/// # 参数
/// - `name`：用户空间字符串指针，队列名（POSIX 要求以 `/` 开头），由 `read_queue_name` 解析
/// - `oflag`：访问模式（`O_RDONLY`/`O_WRONLY`/`O_RDWR`）与可选标志（`O_CREAT`、`O_EXCL`、
///   `O_NONBLOCK`、`O_CLOEXEC`）的按位或
/// - `mode`：仅 `O_CREAT` 路径有效，新建队列的权限位（仅低 9 位 rwxrwxrwx 生效）
/// - `attr`：用户空间 `mq_attr` 指针，仅 `O_CREAT` 路径生效；为 0 时使用默认容量
pub fn syscall_mq_open(name: usize, oflag: usize, mode: usize, attr: usize) -> isize {
    // 解析queue name
    let qname = match read_queue_name(name) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // 取出访问模式掩码 0x000 末尾三位
    let accmode = oflag & O_ACCMODE;
    let (readable, writable) = match accmode {
        O_RDONLY => (true, false),
        O_WRONLY => (false, true),
        O_RDWR => (true, true),
        _ => return err(SyscallError::EINVAL),
    };
    // 权限位uid
    let cred = current_cred();
    let ipc_ns_id = current_ipc_namespace_id();
    let mut created_new_queue = false;

    let queue = {
        let mut managers = MQ_MANAGERS.lock();
        // 获取当前mapce space 的mqmanger
        let mgr = managers.entry(ipc_ns_id).or_default();
        if let Some(id) = mgr.by_name.get(&qname).copied() {
            // 队列已存在：检查 O_EXCL 互斥，验证访问权限
            if (oflag & O_CREAT) != 0 && (oflag & O_EXCL) != 0 {
                return err(SyscallError::EEXIST);
            }
            let Some(queue) = mgr.by_id.get(&id).cloned() else {
                return err(SyscallError::ENOENT);
            };
            let state = queue.state.lock();
            //  权限检查
            if !check_access(&state.perm, &cred, readable, writable) {
                return err(SyscallError::EACCES);
            }
            drop(state);
            queue
        } else {
            // 队列不存在：必须有 O_CREAT 才能创建
            if (oflag & O_CREAT) == 0 {
                return err(SyscallError::ENOENT);
            }
            let mut mq_maxmsg = MQ_DEFAULT_MAXMSG;
            let mut mq_msgsize = MQ_DEFAULT_MSGSIZE;
            if attr != 0 {
                let token = get_current_token();
                let Some(user_attr) = try_read_user_value(token, attr as *const MqAttrUser) else {
                    return err(SyscallError::EFAULT);
                };
                if user_attr.mq_maxmsg <= 0 || user_attr.mq_msgsize <= 0 {
                    return err(SyscallError::EINVAL);
                }
                mq_maxmsg = user_attr.mq_maxmsg as usize;
                mq_msgsize = user_attr.mq_msgsize as usize;
            }
            if mgr.by_id.len() >= queues_max_limit_for_procfs() {
                return err(SyscallError::ENOSPC);
            }
            let id = mgr.alloc_id();
            let queue = Arc::new(MqQueue {
                id,
                ipc_ns_id,
                name: Mutex::new(Some(qname.clone())),
                state: Mutex::new(MqQueueState {
                    perm: MqPerm {
                        uid: cred.euid,
                        gid: cred.egid,
                        mode: (mode as u16) & 0o777,
                    },
                    maxmsg: mq_maxmsg,
                    msgsize: mq_msgsize,
                    messages: VecDeque::new(),
                    recv_waiters: VecDeque::new(),
                    send_waiters: VecDeque::new(),
                    poll_waiters: PollWaitQueue::default(),
                    notify: None,
                }),
            });
            mgr.by_name.insert(qname.clone(), id);
            mgr.by_id.insert(id, queue.clone());
            created_new_queue = true;
            queue
        }
    };
    let queue_id = queue.id;

    let desc = Arc::new(MqDescriptor::new(
        queue,
        readable,
        writable,
        (oflag & O_NONBLOCK) != 0,
        cred.pid,
    ));
    match install_descriptor(desc, oflag) {
        Ok(fd) => fd as isize,
        Err(e) => {
            // 保证 mq_open 原子性：fd 安装失败（如 EMFILE）时，
            // 回滚已创建的队列，避免命名空间中遗留无法访问的孤儿队列
            if created_new_queue {
                let mut managers = MQ_MANAGERS.lock();
                let Some(mgr) = managers.get_mut(&ipc_ns_id) else {
                    return e;
                };
                if mgr.by_name.get(&qname).is_some_and(|id| *id == queue_id) {
                    mgr.by_name.remove(&qname);
                }
                mgr.by_id.remove(&queue_id);
            }
            e
        }
    }
}

/// mq_unlink(2)：从命名空间中移除队列名称，仅允许所有者或 root 执行
///
/// 调用后新的 `mq_open` 无法再通过该名称找到队列，但已打开的 fd 仍然有效——
/// 队列对象本身要等到所有 fd 关闭（引用计数归零）后才被 GC 回收，
/// 语义与文件系统的 unlink(2) 一致。
///
/// # 参数
/// - `name`：用户空间字符串指针，待移除的队列名（与 `mq_open` 同样的命名规范）
pub fn syscall_mq_unlink(name: usize) -> isize {
    let qname = match read_queue_name(name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let cred = current_cred();
    let ipc_ns_id = current_ipc_namespace_id();
    let queue = {
        // 进入命名空间管理器：依次完成 name → id → queue 的查找，并校验权限后摘除名字
        let mut managers = MQ_MANAGERS.lock();
        let Some(mgr) = managers.get_mut(&ipc_ns_id) else {
            return err(SyscallError::ENOENT);
        };
        let Some(id) = mgr.by_name.get(&qname).copied() else {
            return err(SyscallError::ENOENT);
        };
        let Some(queue) = mgr.by_id.get(&id).cloned() else {
            return err(SyscallError::ENOENT);
        };
        // 仅所有者或 root 可以 unlink，其他用户即便有读写权限也不能改命名空间
        let allowed = {
            let state = queue.state.lock();
            is_owner_or_root(&state.perm, &cred)
        };
        if !allowed {
            return err(SyscallError::EACCES);
        }
        // 先从 by_name 中移除使新的 mq_open 找不到该名字；by_id 暂时保留，
        // 由后续 gc_unlinked_queue 在引用计数归零时统一回收
        mgr.by_name.remove(&qname);
        queue
    };
    // 标记队列已无名字（影响 /proc/<pid>/fd/* 的链接显示）
    *queue.name.lock() = None;
    gc_unlinked_queue(&queue);
    0
}

/// mq_getsetattr(2)：原子地读取旧属性并（可选地）设置新属性
///
/// - `oldattr != 0`：将当前属性写回用户空间
/// - `newattr != 0`：应用新属性（仅支持修改 `O_NONBLOCK` 标志；
///   `mq_maxmsg` / `mq_msgsize` 创建后只读，写入会被忽略）
///
/// # 参数
/// - `mqdes`：消息队列文件描述符
/// - `newattr`：用户空间 `mq_attr*`，欲设置的新属性；传 0 表示只查不设
/// - `oldattr`：用户空间 `mq_attr*`，用于回写旧属性；传 0 表示不关心旧值
pub fn syscall_mq_getsetattr(mqdes: usize, newattr: usize, oldattr: usize) -> isize {
    let file = match resolve_fd_file(mqdes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // 必须是 MqDescriptor，普通文件描述符不接受 mq_* 系列调用
    let Some(desc) = file.as_any().downcast_ref::<MqDescriptor>() else {
        return err(SyscallError::EBADF);
    };
    // 在锁内构造旧属性快照：mq_flags 来自 fd 私有标志（O_NONBLOCK），
    // 其余几项来自共享队列状态。读完即释放锁，避免持锁跨越用户空间访问
    let state = desc.queue.state.lock();
    let old = MqAttrUser {
        mq_flags: if desc.nonblock() {
            O_NONBLOCK as i64
        } else {
            0
        },
        mq_maxmsg: state.maxmsg as i64,
        mq_msgsize: state.msgsize as i64,
        mq_curmsgs: state.messages.len() as i64,
        __reserved: [0; 4],
    };
    drop(state);

    let token = get_current_token();
    // 先回写旧属性再应用新属性：即便后续 newattr 写入失败，也能保证调用者
    // 拿到一份准确的旧值，与 Linux 行为保持一致
    if oldattr != 0 && try_write_user_value(token, oldattr as *mut MqAttrUser, &old).is_err() {
        return err(SyscallError::EFAULT);
    }
    if newattr != 0 {
        let Some(new_attr) = try_read_user_value(token, newattr as *const MqAttrUser) else {
            return err(SyscallError::EFAULT);
        };
        // 仅 O_NONBLOCK 可被运行时修改，maxmsg/msgsize 在 mq_open 时确定后即只读
        desc.set_nonblock((new_attr.mq_flags as usize & O_NONBLOCK) != 0);
    }
    0
}

/// mq_notify(2)：注册或取消消息到达时的异步通知
///
/// - `notification != 0`：注册通知，队列从空变非空时触发一次后自动注销；
///   每个队列同一时刻只允许一个进程注册，已有注册时返回 EBUSY
/// - `notification == 0`：取消当前进程在该队列上的注册；
///   若注册使用了 `SIGEV_THREAD` 模式，内核会向对应 socket 发送 REMOVED 事件
///   通知用户态线程池清理资源
///
/// # 参数
/// - `mqdes`：消息队列文件描述符
/// - `notification`：用户空间 `sigevent*`；为 0 表示撤销注册（仅注册者本人有效）
pub fn syscall_mq_notify(mqdes: usize, notification: usize) -> isize {
    let cred = current_cred();
    let parsed = match parse_notify_registration(notification, &cred) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let file = match resolve_fd_file(mqdes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(desc) = file.as_any().downcast_ref::<MqDescriptor>() else {
        return err(SyscallError::EBADF);
    };
    let mut state = desc.queue.state.lock();
    if let Some(reg) = parsed {
        // 注册：队列已有其他进程注册时返回 EBUSY（POSIX first-come-first-serve 语义）
        if state.notify.is_some() {
            return err(SyscallError::EBUSY);
        }
        state.notify = Some(reg);
        return 0;
    }
    // 取消注册：只允许注册者自行撤销，其他进程的请求静默忽略
    let removed = if state
        .notify
        .is_some_and(|notify| notify.owner_pid == cred.pid)
    {
        state.notify.take()
    } else {
        None
    };
    drop(state);
    if let Some(reg) = removed {
        send_removed_if_thread(reg);
    }
    0
}

/// mq_timedsend(2)：向消息队列发送一条消息，支持超时阻塞
///
/// 消息按优先级降序插入，高优先级排在队列头部，同优先级保持 FIFO 顺序。
/// 队列从空变非空时触发一次 `mq_notify` 通知（触发后自动清除注册）。
///
/// - 队列已满 + 非阻塞模式：立即返回 EAGAIN
/// - 队列已满 + 阻塞模式：挂起当前任务，直到有空位、到达截止时间或收到信号
/// - `timeout_ptr == 0` 表示无限等待；超时基准为 `CLOCK_REALTIME`
///
/// # 参数
/// - `mqdes`：消息队列文件描述符（必须以可写方式打开，否则返回 EBADF）
/// - `msg_ptr`：用户空间消息缓冲区起始地址
/// - `msg_len`：消息字节数，必须 ≤ 队列 `mq_msgsize`，否则返回 EMSGSIZE
/// - `msg_prio`：消息优先级，合法范围 `[0, MQ_PRIO_MAX)`
/// - `timeout_ptr`：用户空间 `timespec*` 绝对截止时间；为 0 表示无超时
pub fn syscall_mq_timedsend(
    mqdes: usize,
    msg_ptr: usize,
    msg_len: usize,
    msg_prio: usize,
    timeout_ptr: usize,
) -> isize {
    // 优先级超出预设值
    if msg_prio >= MQ_PRIO_MAX {
        return err(SyscallError::EINVAL);
    }
    // 读取具体值
    let deadline_ns = match parse_abs_timeout(timeout_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let file = match resolve_fd_file(mqdes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(desc) = file.as_any().downcast_ref::<MqDescriptor>() else {
        return err(SyscallError::EBADF);
    };
    if !desc.writable {
        return err(SyscallError::EBADF);
    }

    // 提前读取 msgsize 后释放锁，避免在用户空间拷贝期间持锁
    // 消息大小由 队列创建时候指定，在state中保存
    let msgsize = {
        let state = desc.queue.state.lock();
        state.msgsize
    };
    if msg_len > msgsize {
        return err(SyscallError::EMSGSIZE);
    }
    // 读取具体值
    let mut payload = vec![0u8; msg_len];
    if msg_len > 0 {
        let token = get_current_token();
        if try_copy_from_user(token, msg_ptr as *const u8, &mut payload).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    let cred = current_cred();

    loop {
        let mut state = desc.queue.state.lock();
        // 如果队列有空间
        if state.messages.len() < state.maxmsg {
            let was_empty = state.messages.is_empty();
            // 线性扫描找第一个优先级低于当前消息的位置并插入，
            // 保证高优先级在前，同优先级维持 FIFO 顺序
            let insert_at = state
                .messages
                .iter()
                .position(|m| m.prio < msg_prio as u32)
                .unwrap_or(state.messages.len());
            state.messages.insert(insert_at, MqMessage {
                prio: msg_prio as u32,
                data: payload.clone(),
            });
            wake_all_waiters(&mut state.recv_waiters);
            wake_poll_waiters(&mut state);
            // 仅在队列从空变非空时触发通知，且通知只触发一次（取走后清空注册）
            let notify = if was_empty { state.notify.take() } else { None };
            drop(state);
            if let Some(reg) = notify {
                deliver_notification(reg, cred.pid as i32, cred.uid);
            }
            return 0;
        }

        // 队列已满，进入阻塞等待
        //
        // non block 则推出
        if desc.nonblock() {
            return err(SyscallError::EAGAIN);
        }
        // 超出时间
        if timed_out(deadline_ns) {
            return err(SyscallError::ETIMEDOUT);
        }
        // 有信号需要处理
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        let Some(task) = current_task() else {
            return err(SyscallError::EINVAL);
        };

        // 加入当前任务到等待队列
        add_waiter_once(&mut state.send_waiters, &task);
        if let Some(deadline) = deadline_ns {
            arm_timeout_timer(&task, deadline);
        }
        drop(state);
        crate::task::processor::block_current_and_run_next();
        // 被唤醒后重新检查中断条件，防止虚假唤醒直接重试发送
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        if timed_out(deadline_ns) {
            return err(SyscallError::ETIMEDOUT);
        }
    }
}

/// mq_timedreceive(2)：从消息队列接收优先级最高的消息，支持超时阻塞
///
/// 总是取队列头部消息（优先级最高、同优先级中最早到达的那条），成功时返回消息字节数。
/// 调用方提供的缓冲区 `msg_len` 必须 >= 消息实际长度，否则返回 EMSGSIZE 且不弹出消息。
/// `msg_prio` 非零时，将消息优先级写回该指针指向的地址（传 NULL 表示不关心优先级）。
///
/// - 队列为空 + 非阻塞模式：立即返回 EAGAIN
/// - 队列为空 + 阻塞模式：挂起当前任务，直到有消息到达、到达截止时间或收到信号
///
/// # 参数
/// - `mqdes`：消息队列文件描述符（必须以可读方式打开，否则返回 EBADF）
/// - `msg_ptr`：用户空间接收缓冲区起始地址
/// - `msg_len`：缓冲区容量；不足以容纳队首消息时返回 EMSGSIZE 并保留消息
/// - `msg_prio`：用户空间 `u32*`，用于回写消息优先级；传 0 表示不关心
/// - `timeout_ptr`：用户空间 `timespec*` 绝对截止时间；为 0 表示无超时
pub fn syscall_mq_timedreceive(
    mqdes: usize,
    msg_ptr: usize,
    msg_len: usize,
    msg_prio: usize,
    timeout_ptr: usize,
) -> isize {
    let deadline_ns = match parse_abs_timeout(timeout_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let file = match resolve_fd_file(mqdes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(desc) = file.as_any().downcast_ref::<MqDescriptor>() else {
        return err(SyscallError::EBADF);
    };
    if !desc.readable {
        return err(SyscallError::EBADF);
    }
    let token = get_current_token();

    loop {
        let mut state = desc.queue.state.lock();
        if let Some(front) = state.messages.front() {
            // 先检查缓冲区够不够，不够时不弹出消息，保证操作原子性
            if msg_len < front.data.len() {
                return err(SyscallError::EMSGSIZE);
            }
            let msg = state.messages.pop_front().unwrap();
            // 取出消息后立即唤醒等待发送的任务和 poll 等待者
            wake_all_waiters(&mut state.send_waiters);
            wake_poll_waiters(&mut state);
            // 释放锁后再做用户空间写入，避免持锁跨越可能 fault 的内存访问
            drop(state);
            if !msg.data.is_empty()
                && try_copy_to_user(token, msg_ptr as *mut u8, msg.data.as_slice()).is_err()
            {
                return err(SyscallError::EFAULT);
            }
            if msg_prio != 0
                && try_write_user_value(token, msg_prio as *mut u32, &(msg.prio as u32)).is_err()
            {
                return err(SyscallError::EFAULT);
            }
            return msg.data.len() as isize;
        }

        // 队列为空，进入阻塞等待
        if desc.nonblock() {
            return err(SyscallError::EAGAIN);
        }
        if timed_out(deadline_ns) {
            return err(SyscallError::ETIMEDOUT);
        }
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        let Some(task) = current_task() else {
            return err(SyscallError::EINVAL);
        };
        add_waiter_once(&mut state.recv_waiters, &task);
        if let Some(deadline) = deadline_ns {
            arm_timeout_timer(&task, deadline);
        }
        drop(state);
        crate::task::processor::block_current_and_run_next();
        // 被唤醒后重新检查中断条件，防止虚假唤醒直接重试接收
        if has_pending_unmasked_signal() {
            return err(SyscallError::EINTR);
        }
        if timed_out(deadline_ns) {
            return err(SyscallError::ETIMEDOUT);
        }
    }
}
