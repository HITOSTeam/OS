//! 网络收发系统调用实现。
//!
//! 本模块负责将用户态的 `sendmsg` / `recvmsg` / `sendmmsg` / `recvmmsg` /
//! `sendto` / `recvfrom` 系统调用分发到三类内核 socket：
//! - **UnixSocketFile**：域内流式（SEQPACKET/STREAM）与数据报（DGRAM）
//! - **NetlinkSocketFile**：内核 netlink 控制通道
//! - **NetSocketFile**：TCP 流 / UDP 数据报（基于 smoltcp）
//!
//! 此外，模块维护一张全局的 `MSG_MORE` 积累表（[`MSG_MORE_PENDING`]），在
//! 用户连续使用 `MSG_MORE` 标志时将分片数据暂存，待最后一次不带该标志的调用
//! 时统一发送，从而减少协议栈调用次数并保证数据报的原子性。

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::{NetSocketFile, SocketPairEnd};
use crate::mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::{
    block_sleep::add_timer,
    processor::{
        current_files, current_files_and_nofile_limit, current_process, current_task,
        suspend_current_and_run_next,
    },
    signal::has_wait_interrupting_pending,
};
use crate::trap::get_current_token;

use super::*;

/// UDP 发送目标：IP 地址 + 目的端口号。
type UdpTarget = (smoltcp::wire::IpAddress, u16);

const CAP_SETGID: usize = 6;
const CAP_SETUID: usize = 7;
const CAP_SYS_ADMIN: usize = 21;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScmParseMode {
    /// Unix sockets use scm_send(): SCM_RIGHTS transfers file descriptors and
    /// SCM_CREDENTIALS installs caller-supplied credentials after permission checks.
    Unix,
    /// Netlink also uses scm_send(), but it is not PF_UNIX, so SCM_RIGHTS fails.
    Netlink,
    /// IPv4/raw/packet sockets use sock_cmsg_send(); Linux treats SCM_* as
    /// SOL_UNIX-only metadata and ignores it on these generic socket paths.
    Generic,
}

// MSG_MORE 积累缓冲：user 带 MSG_MORE 发送时字节先攒在这里，最后一次不带 MSG_MORE
// 的调用才触发真正发送。用 socket Arc 指针作 key，无需侵入 socket 内部状态。
/// MSG_MORE 模式下单个 socket 的待发缓冲状态。
///
/// 当用户连续调用带 `MSG_MORE` 标志的发送接口时，每次的载荷先追加到 `data`，
/// 直到不带 `MSG_MORE` 的最后一次调用才将 `data` 一并交给底层协议栈发送。
struct PendingMoreState {
    /// 已积累但尚未下发的字节序列。
    data: Vec<u8>,
    /// UDP 目标地址（仅对 UDP socket 有意义）；对 TCP / Unix 流式 socket 始终为 `None`。
    udp_target: Option<UdpTarget>,
    /// UDP `sendmsg(IP_PKTINFO)` 在 MSG_MORE cork 期间保存的 per-message 源地址/接口提示。
    udp_pktinfo: Option<SendIpv4PktInfo>,
    /// UDP `sendmsg(IP_TTL)` 在 MSG_MORE cork 期间保存的 per-message TTL。
    udp_ttl_override: Option<u8>,
    /// UDP `sendmsg(IP_TOS)` 在 MSG_MORE cork 期间保存的 per-message TOS。
    udp_tos_override: Option<u8>,
    /// UDP cork 期间是否出现过 MSG_DONTROUTE。
    udp_dontroute: bool,
    /// UDP cork 期间是否出现过 MSG_CONFIRM。
    udp_confirm: bool,
}

lazy_static! {
    /// 全局 MSG_MORE 积累表，键为 socket 文件的 Arc 指针地址。
    ///
    /// 选用全局 BTreeMap 而非在 socket 结构体中增加字段，是为了**避免侵入**
    /// UnixSocketFile / NetSocketFile 等各自的内部状态，保持 socket 实现的纯净性。
    /// 键使用 [`file_key`] 取 Arc 分配地址（在 Arc 存活期间全局唯一），无需在
    /// socket 类型上引入额外 ID 字段。
    static ref MSG_MORE_PENDING: Mutex<BTreeMap<usize, PendingMoreState>> =
        Mutex::new(BTreeMap::new());
}

/// 将 socket 文件的 `Arc` 指针地址转换为 `MSG_MORE_PENDING` 的键。
///
/// Arc 分配在堆上，同一个 Arc 存活期间地址不变且全局唯一，因此可作为
/// socket 的轻量标识——无需在 socket 类型上引入额外 ID 字段。
fn file_key(file: &FileArc) -> usize {
    Arc::as_ptr(file) as *const () as usize
}

fn has_cap(cap_effective: u64, cap: usize) -> bool {
    (cap_effective & (1u64 << cap)) != 0
}

fn check_scm_credentials(cred: UCred) -> Result<(), isize> {
    if cred.uid == u32::MAX || cred.gid == u32::MAX {
        return Err(err(SyscallError::EINVAL));
    }
    let process = current_process();
    let inner = process.borrow_mut();
    let caps = inner.cap_effective;
    let pid_ok = cred.pid == process.pid.0 as u32 || has_cap(caps, CAP_SYS_ADMIN);
    let uid_ok = cred.uid == inner.uid
        || cred.uid == inner.euid
        || cred.uid == inner.suid
        || has_cap(caps, CAP_SETUID);
    let gid_ok = cred.gid == inner.gid
        || cred.gid == inner.egid
        || cred.gid == inner.sgid
        || has_cap(caps, CAP_SETGID);
    if pid_ok && uid_ok && gid_ok {
        Ok(())
    } else {
        Err(err(SyscallError::EPERM))
    }
}

pub(crate) fn clear_msg_more_pending_for_addr(addr: usize) {
    MSG_MORE_PENDING.lock().remove(&addr);
}

fn flush_tcp_msg_more_pending_for_addr_inner(addr: usize, sock: &NetSocketFile, keep_unsent: bool) {
    if let Some(pending) = MSG_MORE_PENDING.lock().remove(&addr) {
        if !pending.data.is_empty() {
            let sent = sock.tcp_try_flush_send_buffer(&pending.data);
            if keep_unsent && sent < pending.data.len() {
                put_pending_more(
                    addr,
                    PendingMoreState {
                        data: pending.data[sent..].to_vec(),
                        udp_target: pending.udp_target,
                        udp_pktinfo: pending.udp_pktinfo,
                        udp_ttl_override: pending.udp_ttl_override,
                        udp_tos_override: pending.udp_tos_override,
                        udp_dontroute: pending.udp_dontroute,
                        udp_confirm: pending.udp_confirm,
                    },
                );
            }
        }
    }
}

pub(crate) fn flush_tcp_msg_more_pending_for_addr(addr: usize, sock: &NetSocketFile) {
    flush_tcp_msg_more_pending_for_addr_inner(addr, sock, true);
}

pub(crate) fn drop_tcp_msg_more_pending_for_addr(addr: usize, sock: &NetSocketFile) {
    flush_tcp_msg_more_pending_for_addr_inner(addr, sock, false);
}

pub(crate) fn queue_tcp_msg_more_pending_for_addr(addr: usize, chunk: &[u8]) {
    queue_pending_more_chunk(addr, chunk, None, None, None, None, false, false);
}

/// 从积累表取出并移除指定 socket 的待发状态（若不存在则返回 `None`）。
fn take_pending_more(key: usize) -> Option<PendingMoreState> {
    MSG_MORE_PENDING.lock().remove(&key)
}

fn pending_more_udp_state(
    key: usize,
) -> (
    usize,
    Option<UdpTarget>,
    Option<SendIpv4PktInfo>,
    Option<u8>,
    Option<u8>,
    bool,
    bool,
) {
    let pending = MSG_MORE_PENDING.lock();
    let Some(pending) = pending.get(&key) else {
        return (0, None, None, None, None, false, false);
    };
    (
        pending.data.len(),
        pending.udp_target,
        pending.udp_pktinfo,
        pending.udp_ttl_override,
        pending.udp_tos_override,
        pending.udp_dontroute,
        pending.udp_confirm,
    )
}

/// 将待发状态写回积累表。
fn put_pending_more(key: usize, state: PendingMoreState) {
    MSG_MORE_PENDING.lock().insert(key, state);
}

/// 将 `chunk` 追加到指定 socket 的 MSG_MORE 积累缓冲中。
///
/// 若该 socket 尚无积累状态则新建；UDP 目标地址以**首次指定**的为准，
/// 后续同一批 MSG_MORE 调用传入的地址会被忽略（详见函数体内注释）。
fn queue_pending_more_chunk(
    key: usize,
    chunk: &[u8],
    udp_target: Option<UdpTarget>,
    udp_pktinfo: Option<SendIpv4PktInfo>,
    udp_ttl_override: Option<u8>,
    udp_tos_override: Option<u8>,
    udp_dontroute: bool,
    udp_confirm: bool,
) {
    let mut pending = take_pending_more(key).unwrap_or(PendingMoreState {
        data: Vec::new(),
        udp_target,
        udp_pktinfo,
        udp_ttl_override,
        udp_tos_override,
        udp_dontroute,
        udp_confirm,
    });
    // UDP 目标地址以第一次指定的为准，后续同一批 MSG_MORE 调用的地址忽略。
    if pending.udp_target.is_none() {
        pending.udp_target = udp_target;
    }
    if pending.udp_pktinfo.is_none() {
        pending.udp_pktinfo = udp_pktinfo;
    }
    if pending.udp_ttl_override.is_none() {
        pending.udp_ttl_override = udp_ttl_override;
    }
    if pending.udp_tos_override.is_none() {
        pending.udp_tos_override = udp_tos_override;
    }
    pending.udp_dontroute |= udp_dontroute;
    pending.udp_confirm |= udp_confirm;
    pending.data.extend_from_slice(chunk);
    put_pending_more(key, pending);
}

/// 将积累缓冲与本次 `payload` 合并，返回 `(合并后载荷, 是否有待发数据, UDP目标地址)`。
///
/// 若存在积累数据，则将 `payload` 追加到其末尾，并返回 `had_pending = true`，
/// 供 [`visible_send_len`] 据此决定向用户报告的字节数。
fn consume_pending_more(
    key: usize,
    payload: Vec<u8>,
) -> (
    Vec<u8>,
    bool,
    Option<UdpTarget>,
    Option<SendIpv4PktInfo>,
    Option<u8>,
    Option<u8>,
    bool,
    bool,
) {
    if let Some(mut pending) = take_pending_more(key) {
        let pending_target = pending.udp_target;
        let pending_pktinfo = pending.udp_pktinfo;
        let pending_ttl_override = pending.udp_ttl_override;
        let pending_tos_override = pending.udp_tos_override;
        let pending_dontroute = pending.udp_dontroute;
        let pending_confirm = pending.udp_confirm;
        pending.data.extend_from_slice(&payload);
        (
            pending.data,
            true,
            pending_target,
            pending_pktinfo,
            pending_ttl_override,
            pending_tos_override,
            pending_dontroute,
            pending_confirm,
        )
    } else {
        (payload, false, None, None, None, None, false, false)
    }
}

fn flush_tcp_pending_before_current(
    key: usize,
    sock: &NetSocketFile,
    nonblock: bool,
) -> Result<(), isize> {
    let Some(pending) = take_pending_more(key) else {
        return Ok(());
    };
    if pending.data.is_empty() {
        return Ok(());
    }
    match sock.tcp_send(&pending.data, nonblock) {
        Ok(sent) if sent >= pending.data.len() => Ok(()),
        Ok(sent) => {
            put_pending_more(
                key,
                PendingMoreState {
                    data: pending.data[sent..].to_vec(),
                    udp_target: pending.udp_target,
                    udp_pktinfo: pending.udp_pktinfo,
                    udp_ttl_override: pending.udp_ttl_override,
                    udp_tos_override: pending.udp_tos_override,
                    udp_dontroute: pending.udp_dontroute,
                    udp_confirm: pending.udp_confirm,
                },
            );
            Err(err(SyscallError::EAGAIN))
        }
        Err(e) => {
            put_pending_more(key, pending);
            Err(e)
        }
    }
}

// MSG_MORE 场景下返回 user_len 而非底层实际发送字节数：user 期望看到本次调用传入的
// 字节数，而不是被底层合并后的总量，否则上层计算进度会出错。
/// 计算向用户报告的发送字节数。
///
/// 若本次发送合并了之前 MSG_MORE 积累的数据（`had_pending == true`），底层
/// `sent` 会大于用户本次实际传入的字节数 `user_len`。此时必须返回 `user_len`，
/// 因为用户依赖返回值来追踪"本次调用消费了多少字节"，返回底层总量会破坏其进度计算。
fn visible_send_len(sent: usize, user_len: usize, had_pending: bool) -> isize {
    if had_pending {
        user_len as isize
    } else {
        sent as isize
    }
}

/// [`visible_send_len`] 的错误透传包装：`ret < 0` 时直接返回错误码，否则调用
/// `visible_send_len` 修正字节数。
fn visible_send_result(ret: isize, user_len: usize, had_pending: bool) -> isize {
    if ret < 0 {
        ret
    } else {
        visible_send_len(ret as usize, user_len, had_pending)
    }
}

fn user_timespec_to_ms(ts: UserTimespec) -> Result<usize, isize> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(err(SyscallError::EINVAL));
    }
    let sec_ms = (ts.tv_sec as u128).saturating_mul(1_000);
    let nsec_ms = if ts.tv_nsec == 0 {
        0
    } else {
        ((ts.tv_nsec as u128).saturating_add(999_999)) / 1_000_000
    };
    Ok(sec_ms.saturating_add(nsec_ms).min(usize::MAX as u128) as usize)
}

fn recvmmsg_timeout_deadline(timeout: usize) -> Result<Option<usize>, isize> {
    if timeout == 0 {
        return Ok(None);
    }
    let token = get_current_token();
    let Some(ts) = try_read_user_value::<UserTimespec>(token, timeout as *const UserTimespec)
    else {
        return Err(err(SyscallError::EFAULT));
    };
    let wait_ms = user_timespec_to_ms(ts)?;
    Ok(Some(crate::time::get_time_ms().saturating_add(wait_ms)))
}

fn recvmmsg_write_remaining_timeout(timeout: usize, deadline_ms: Option<usize>) -> isize {
    if timeout == 0 {
        return 0;
    }
    let Some(deadline_ms) = deadline_ms else {
        return 0;
    };
    let remaining_ms = deadline_ms.saturating_sub(crate::time::get_time_ms());
    let ts = UserTimespec {
        tv_sec: (remaining_ms / 1_000) as i64,
        tv_nsec: ((remaining_ms % 1_000) * 1_000_000) as i64,
    };
    if try_write_user_value(get_current_token(), timeout as *mut UserTimespec, &ts).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

fn recvmmsg_finish(ret: isize, timeout: usize, deadline_ms: Option<usize>) -> isize {
    if ret > 0 {
        let timeout_write = recvmmsg_write_remaining_timeout(timeout, deadline_ms);
        if timeout_write < 0 {
            return timeout_write;
        }
    }
    ret
}

fn recvmmsg_interrupted_by_signal() -> bool {
    let Some(task) = current_task() else {
        return false;
    };
    let inner = task.borrow_mut();
    has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask)
}

fn arm_recvmmsg_timeout_timer(deadline_ms: usize) {
    let Some(task) = current_task() else {
        return;
    };
    let wait_ms = deadline_ms
        .saturating_sub(crate::time::get_time_ms())
        .max(1);
    add_timer(task, wait_ms);
}

fn wait_for_recv_deadline(deadline_ms: usize) -> isize {
    if crate::time::get_time_ms() >= deadline_ms {
        return err(SyscallError::EAGAIN);
    }
    if recvmmsg_interrupted_by_signal() {
        return err(SyscallError::EINTR);
    }
    arm_recvmmsg_timeout_timer(deadline_ms);
    suspend_current_and_run_next();
    0
}

fn wait_for_socket_recv_event(deadline_ms: Option<usize>) -> isize {
    if let Some(deadline_ms) = deadline_ms {
        return wait_for_recv_deadline(deadline_ms);
    }
    if recvmmsg_interrupted_by_signal() {
        return err(SyscallError::EINTR);
    }
    suspend_current_and_run_next();
    0
}

fn recvmsg_deadline_waitall_stream(fd: usize, flags: usize) -> bool {
    let Ok((file, effective_flags)) = get_file_with_effective_flags(fd, flags) else {
        return false;
    };
    if (effective_flags & MSG_WAITALL) == 0
        || (effective_flags & MSG_DONTWAIT) != 0
        || (effective_flags & MSG_PEEK) != 0
    {
        return false;
    }
    file.as_any()
        .downcast_ref::<SocketPairEnd>()
        .is_some_and(|sock| !sock.is_record_oriented())
        || file
            .as_any()
            .downcast_ref::<UnixSocketFile>()
            .is_some_and(|sock| sock.is_stream_like())
        || file
            .as_any()
            .downcast_ref::<NetSocketFile>()
            .is_some_and(|sock| sock.kind() == crate::fs::NetSocketKind::TcpStream)
}

fn recvmsg_inner_with_deadline(
    fd: usize,
    msg: &mut MsgHdr,
    flags: usize,
    deadline_ms: Option<usize>,
) -> isize {
    let Some(deadline_ms) = deadline_ms else {
        return recvmsg_inner(fd, msg, flags, None);
    };
    if get_file_with_effective_flags(fd, flags)
        .map(|(_, effective_flags)| (effective_flags & MSG_DONTWAIT) != 0)
        .unwrap_or(false)
    {
        return recvmsg_inner(fd, msg, flags, None);
    }
    if recvmsg_deadline_waitall_stream(fd, flags) {
        return recvmsg_inner(fd, msg, flags, Some(deadline_ms));
    }
    let eagain = err(SyscallError::EAGAIN);
    let mut timer_armed = false;
    loop {
        let ret = recvmsg_inner(fd, msg, flags | MSG_DONTWAIT, None);
        if ret != eagain {
            return ret;
        }
        if (flags & MSG_DONTWAIT) != 0 {
            return ret;
        }
        if crate::time::get_time_ms() >= deadline_ms {
            return eagain;
        }
        if recvmmsg_interrupted_by_signal() {
            return err(SyscallError::EINTR);
        }
        if !timer_armed {
            arm_recvmmsg_timeout_timer(deadline_ms);
            timer_armed = true;
        }
        suspend_current_and_run_next();
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CMsgHdr {
    cmsg_len: usize,
    cmsg_level: i32,
    cmsg_type: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TPacketAuxData {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockTimeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockExtendedErr {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InPktInfo {
    ipi_ifindex: i32,
    ipi_spec_dst: [u8; 4],
    ipi_addr: [u8; 4],
}

const TP_STATUS_USER: u32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const SCM_MAX_FD: usize = 253;

#[derive(Default)]
struct SendControl {
    scm: ScmControl,
    mark: Option<u32>,
    priority: Option<u32>,
    ipv4_pktinfo: Option<SendIpv4PktInfo>,
    ipv4_ttl: Option<u8>,
    ipv4_tos: Option<u8>,
}

#[derive(Clone, Copy)]
struct SendIpv4PktInfo {
    ifindex: i32,
    spec_dst: Option<smoltcp::wire::Ipv4Address>,
}

impl SendControl {
    fn is_empty(&self) -> bool {
        self.scm.is_empty()
            && self.mark.is_none()
            && self.priority.is_none()
            && self.ipv4_pktinfo.is_none()
            && self.ipv4_ttl.is_none()
            && self.ipv4_tos.is_none()
    }

    fn has_scm(&self) -> bool {
        !self.scm.is_empty()
    }

    fn has_packet_metadata(&self) -> bool {
        self.mark.is_some() || self.priority.is_some()
    }

    fn has_ipv4_control(&self) -> bool {
        self.ipv4_pktinfo.is_some() || self.ipv4_ttl.is_some() || self.ipv4_tos.is_some()
    }

    fn udp_unsupported_control(&self) -> bool {
        !self.scm.is_empty() || self.has_packet_metadata()
    }

    fn udp_pktinfo(&self) -> Option<SendIpv4PktInfo> {
        self.ipv4_pktinfo
    }

    fn udp_ttl_override(&self) -> Option<u8> {
        self.ipv4_ttl
    }

    fn udp_tos_override(&self) -> Option<u8> {
        self.ipv4_tos
    }

    fn packet_metadata(&self, default: PacketMetadata) -> PacketMetadata {
        PacketMetadata {
            mark: self.mark.unwrap_or(default.mark),
            priority: self.priority.unwrap_or(default.priority),
            orig_ifindex: default.orig_ifindex,
        }
    }

    fn raw_ipv4_overrides(
        &self,
    ) -> (
        Option<i32>,
        Option<smoltcp::wire::Ipv4Address>,
        Option<u8>,
        Option<u8>,
    ) {
        (
            self.ipv4_pktinfo
                .and_then(|info| (info.ifindex > 0).then_some(info.ifindex)),
            self.ipv4_pktinfo.and_then(|info| info.spec_dst),
            self.ipv4_ttl,
            self.ipv4_tos,
        )
    }
}

fn cmsg_align(len: usize) -> usize {
    (len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

fn cmsg_len(payload_len: usize) -> usize {
    size_of::<CMsgHdr>() + payload_len
}

fn cmsg_space(payload_len: usize) -> usize {
    size_of::<CMsgHdr>() + cmsg_align(payload_len)
}

fn append_control_cmsg(raw: &mut Vec<u8>, level: i32, ty: i32, payload: &[u8]) {
    let hdr = CMsgHdr {
        cmsg_len: cmsg_len(payload.len()),
        cmsg_level: level,
        cmsg_type: ty,
    };
    let hdr_len = size_of::<CMsgHdr>();
    let start = raw.len();
    let space = cmsg_space(payload.len());
    raw.resize(start + space, 0);
    let hdr_bytes =
        unsafe { core::slice::from_raw_parts((&hdr as *const CMsgHdr) as *const u8, hdr_len) };
    raw[start..start + hdr_len].copy_from_slice(hdr_bytes);
    raw[start + hdr_len..start + hdr_len + payload.len()].copy_from_slice(payload);
}

fn append_checked_cmsg(
    msg: &mut MsgHdr,
    raw: &mut Vec<u8>,
    control_len: usize,
    level: i32,
    ty: i32,
    payload: &[u8],
) {
    let hdr_len = size_of::<CMsgHdr>();
    if control_len < hdr_len {
        msg.msg_flags |= MSG_CTRUNC as i32;
        return;
    }
    let need = cmsg_space(payload.len());
    if raw.len().saturating_add(need) <= control_len {
        append_control_cmsg(raw, level, ty, payload);
    } else {
        msg.msg_flags |= MSG_CTRUNC as i32;
    }
}

fn append_ipv4_pktinfo_cmsg(
    msg: &mut MsgHdr,
    raw: &mut Vec<u8>,
    control_len: usize,
    ifindex: i32,
    dst: smoltcp::wire::Ipv4Address,
) {
    let dst = {
        let bytes = dst.as_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3]]
    };
    let pktinfo = InPktInfo {
        ipi_ifindex: ifindex,
        ipi_spec_dst: dst,
        ipi_addr: dst,
    };
    let payload = unsafe {
        core::slice::from_raw_parts(
            (&pktinfo as *const InPktInfo) as *const u8,
            size_of::<InPktInfo>(),
        )
    };
    append_checked_cmsg(
        msg,
        raw,
        control_len,
        SOL_IP as i32,
        IP_PKTINFO as i32,
        payload,
    );
}

fn write_raw_cmsgs(msg: &mut MsgHdr, control_ptr: usize, control_len: usize, raw: &[u8]) -> isize {
    if raw.is_empty() {
        return 0;
    }
    if control_ptr == 0 || control_len < size_of::<CMsgHdr>() {
        msg.msg_flags |= MSG_CTRUNC as i32;
        msg.msg_controllen = 0;
        return 0;
    }
    let token = get_current_token();
    if try_copy_to_user(token, control_ptr as *mut u8, raw).is_err() {
        return err(SyscallError::EFAULT);
    }
    msg.msg_controllen = raw.len();
    0
}

fn append_timestamp_cmsg_for_file(
    file: &(dyn crate::fs::File + Send + Sync),
    msg: &mut MsgHdr,
    raw: &mut Vec<u8>,
    control_len: usize,
    received_packet: bool,
) {
    if !received_packet {
        return;
    }
    let mode = crate::syscall::net::socket_timestamp_mode(file);
    if mode == SocketTimestampMode::Off {
        return;
    }
    let stamp =
        crate::syscall::net::socket_last_timestamp(file).unwrap_or_else(SocketTimestamp::now);
    match mode {
        SocketTimestampMode::Off => {}
        SocketTimestampMode::TimevalOld | SocketTimestampMode::TimevalNew => {
            let tv = SockTimeval {
                tv_sec: stamp.sec,
                tv_usec: stamp.nsec / 1_000,
            };
            let payload = unsafe {
                core::slice::from_raw_parts(
                    (&tv as *const SockTimeval) as *const u8,
                    size_of::<SockTimeval>(),
                )
            };
            let ty = if mode == SocketTimestampMode::TimevalNew {
                SO_TIMESTAMP_NEW
            } else {
                SO_TIMESTAMP_OLD
            };
            append_checked_cmsg(msg, raw, control_len, SOL_SOCKET as i32, ty as i32, payload);
        }
        SocketTimestampMode::TimespecOld | SocketTimestampMode::TimespecNew => {
            let ts = SockTimespec {
                tv_sec: stamp.sec,
                tv_nsec: stamp.nsec,
            };
            let payload = unsafe {
                core::slice::from_raw_parts(
                    (&ts as *const SockTimespec) as *const u8,
                    size_of::<SockTimespec>(),
                )
            };
            let ty = if mode == SocketTimestampMode::TimespecNew {
                SO_TIMESTAMPNS_NEW
            } else {
                SO_TIMESTAMPNS_OLD
            };
            append_checked_cmsg(msg, raw, control_len, SOL_SOCKET as i32, ty as i32, payload);
        }
    }
}

fn append_mark_priority_cmsgs_for_file(
    file: &(dyn crate::fs::File + Send + Sync),
    msg: &mut MsgHdr,
    raw: &mut Vec<u8>,
    control_len: usize,
    received_packet: bool,
) {
    if !received_packet {
        return;
    }
    let metadata = file.as_any().downcast_ref::<NetSocketFile>().map(|sock| {
        (
            sock.rcvmark().then_some(sock.mark()),
            sock.rcvpriority().then_some(sock.priority()),
        )
    });
    let Some((mark, priority)) = metadata else {
        return;
    };
    append_mark_priority_cmsgs(msg, raw, control_len, mark, priority);
}

fn append_mark_priority_cmsgs(
    msg: &mut MsgHdr,
    raw: &mut Vec<u8>,
    control_len: usize,
    mark: Option<u32>,
    priority: Option<u32>,
) {
    if let Some(mark) = mark {
        append_checked_cmsg(
            msg,
            raw,
            control_len,
            SOL_SOCKET as i32,
            SO_MARK as i32,
            &mark.to_ne_bytes(),
        );
    }
    if let Some(priority) = priority {
        append_checked_cmsg(
            msg,
            raw,
            control_len,
            SOL_SOCKET as i32,
            SO_PRIORITY as i32,
            &priority.to_ne_bytes(),
        );
    }
}

fn ipv4_error_cmsg_payload(entry: &Ipv4ErrorQueueEntry) -> Vec<u8> {
    let ext = SockExtendedErr {
        ee_errno: entry.errno,
        ee_origin: entry.origin,
        ee_type: entry.ty,
        ee_code: entry.code,
        ee_pad: 0,
        ee_info: entry.info,
        ee_data: entry.data,
    };
    let offender = if let Some((addr, port)) = entry.offender {
        SockAddrIn {
            sin_family: AF_INET,
            sin_port: port.to_be(),
            sin_addr: u32::from_be_bytes(addr).to_be(),
            sin_zero: [0; 8],
        }
    } else {
        SockAddrIn {
            sin_family: AF_UNSPEC,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0; 8],
        }
    };
    let mut payload = Vec::with_capacity(size_of::<SockExtendedErr>() + size_of::<SockAddrIn>());
    // SAFETY: both structs are #[repr(C)] plain ABI payloads copied out by value.
    let ext_bytes = unsafe {
        core::slice::from_raw_parts(
            (&ext as *const SockExtendedErr) as *const u8,
            size_of::<SockExtendedErr>(),
        )
    };
    payload.extend_from_slice(ext_bytes);
    // SAFETY: `offender` is a fully initialized sockaddr_in-compatible value.
    let offender_bytes = unsafe {
        core::slice::from_raw_parts(
            (&offender as *const SockAddrIn) as *const u8,
            size_of::<SockAddrIn>(),
        )
    };
    payload.extend_from_slice(offender_bytes);
    payload
}

fn recv_ipv4_error_queue_entry(
    msg: &mut MsgHdr,
    iovs: &[IoVec],
    control_ptr: usize,
    control_len: usize,
    flags: usize,
    entry: Option<Ipv4ErrorQueueEntry>,
) -> isize {
    let Some(entry) = entry else {
        return err(SyscallError::EAGAIN);
    };
    let copied = match scatter_iovecs_data(iovs, &entry.payload) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if copied < entry.payload.len() {
        msg.msg_flags |= MSG_TRUNC as i32;
    }
    msg.msg_namelen = 0;
    let mut cmsgs = Vec::new();
    let payload = ipv4_error_cmsg_payload(&entry);
    append_checked_cmsg(
        msg,
        &mut cmsgs,
        control_len,
        SOL_IP as i32,
        IP_RECVERR as i32,
        &payload,
    );
    let r = write_raw_cmsgs(msg, control_ptr, control_len, &cmsgs);
    if r != 0 {
        return r;
    }
    if (flags & MSG_TRUNC) != 0 {
        entry.payload.len() as isize
    } else {
        copied as isize
    }
}

fn write_empty_sockaddr_len(user_len_ptr: usize) -> isize {
    if user_len_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(len) = try_read_user_value::<u32>(token, user_len_ptr as *const u32) else {
        return err(SyscallError::EFAULT);
    };
    if (len as usize) > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    if try_write_user_value(token, user_len_ptr as *mut u32, &0u32).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

fn write_scm_control_cmsgs(
    msg: &mut MsgHdr,
    control_ptr: usize,
    control_len: usize,
    mut control: ScmControl,
    flags: usize,
) -> isize {
    if control.is_empty() {
        return 0;
    }
    let hdr_len = size_of::<CMsgHdr>();
    if control_ptr == 0 || control_len < hdr_len {
        msg.msg_flags |= MSG_CTRUNC as i32;
        msg.msg_controllen = 0;
        return 0;
    }

    let mut raw = Vec::new();
    let mut installed = Vec::new();
    if let Some(rights) = control.take_rights() {
        let remaining = control_len.saturating_sub(raw.len());
        if remaining < hdr_len + size_of::<i32>() {
            msg.msg_flags |= MSG_CTRUNC as i32;
        } else {
            let max_fds = (remaining - hdr_len) / size_of::<i32>();
            let mut pass_count = core::cmp::min(rights.len(), max_fds);
            while pass_count > 0 && cmsg_space(pass_count * size_of::<i32>()) > remaining {
                pass_count -= 1;
            }
            if pass_count < rights.len() {
                msg.msg_flags |= MSG_CTRUNC as i32;
            }
            if pass_count > 0 {
                let fd_flags = if (flags & MSG_CMSG_CLOEXEC) != 0 {
                    FD_CLOEXEC
                } else {
                    0
                };
                let (files_table, limit) = current_files_and_nofile_limit();
                let mut files_table = files_table.lock();
                for file in rights.iter().take(pass_count) {
                    let fd = match files_table.install_fd(Arc::clone(file), fd_flags, limit) {
                        Ok(fd) => fd,
                        Err(rejected) => {
                            let mut detached = Vec::new();
                            for fd in installed.drain(..) {
                                if let Some(removed) = files_table.clear_fd(fd) {
                                    detached.push(removed);
                                }
                            }
                            drop(files_table);
                            rejected.discard();
                            crate::task::complete_fd_closes(detached);
                            return err(SyscallError::EMFILE);
                        }
                    };
                    installed.push(fd);
                }
                drop(files_table);

                let mut payload = vec![0u8; pass_count * size_of::<i32>()];
                for (idx, fd) in installed.iter().copied().enumerate() {
                    payload[idx * size_of::<i32>()..(idx + 1) * size_of::<i32>()]
                        .copy_from_slice(&(fd as i32).to_ne_bytes());
                }
                let need = cmsg_space(payload.len());
                if raw.len().saturating_add(need) <= control_len {
                    append_control_cmsg(&mut raw, SOL_SOCKET as i32, SCM_RIGHTS, &payload);
                } else {
                    msg.msg_flags |= MSG_CTRUNC as i32;
                }
            }
        }
    }

    if let Some(cred) = control.credentials {
        let payload = unsafe {
            core::slice::from_raw_parts((&cred as *const UCred) as *const u8, size_of::<UCred>())
        };
        let need = cmsg_space(payload.len());
        if raw.len().saturating_add(need) <= control_len {
            append_control_cmsg(&mut raw, SOL_SOCKET as i32, SCM_CREDENTIALS, payload);
        } else {
            msg.msg_flags |= MSG_CTRUNC as i32;
        }
    }

    if raw.is_empty() {
        msg.msg_controllen = 0;
        return 0;
    }
    let token = get_current_token();
    let ret = if try_copy_to_user(token, control_ptr as *mut u8, &raw).is_err() {
        err(SyscallError::EFAULT)
    } else {
        msg.msg_controllen = raw.len();
        0
    };
    if ret < 0 {
        let files_table = current_files();
        let mut files_table = files_table.lock();
        let mut detached = Vec::new();
        for fd in installed {
            if let Some(removed) = files_table.clear_fd(fd) {
                detached.push(removed);
            }
        }
        drop(files_table);
        crate::task::complete_fd_closes(detached);
    }
    ret
}

fn packet_auxdata_bytes(packet: &PacketFrame) -> [u8; size_of::<TPacketAuxData>()] {
    let len = packet.data.len() as u32;
    let aux = TPacketAuxData {
        tp_status: TP_STATUS_USER,
        tp_len: len,
        tp_snaplen: len,
        tp_mac: 0,
        tp_net: 0,
        tp_vlan_tci: 0,
        tp_vlan_tpid: 0,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&aux as *const TPacketAuxData) as *const u8,
            size_of::<TPacketAuxData>(),
        )
    };
    let mut out = [0u8; size_of::<TPacketAuxData>()];
    out.copy_from_slice(bytes);
    out
}

fn read_sendmsg_control(msg: &MsgHdr, scm_mode: ScmParseMode) -> Result<SendControl, isize> {
    const CONTROL_COPY_CHUNK: usize = 256;

    if msg.msg_controllen == 0 {
        return Ok(SendControl::default());
    }
    if msg.msg_control == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    if msg.msg_controllen > i32::MAX as usize {
        return Err(err(SyscallError::ENOBUFS));
    }

    let token = get_current_token();
    let hdr_len = size_of::<CMsgHdr>();
    let mut offset = 0usize;
    let mut files_to_pass = Vec::new();
    let mut credentials = None;
    let mut mark = None;
    let mut priority = None;
    let mut ipv4_pktinfo = None;
    let mut ipv4_ttl = None;
    let mut ipv4_tos = None;
    while offset + hdr_len <= msg.msg_controllen {
        let Some(ptr) = msg.msg_control.checked_add(offset) else {
            return Err(err(SyscallError::EFAULT));
        };
        let Some(hdr) = try_read_user_value::<CMsgHdr>(token, ptr as *const CMsgHdr) else {
            return Err(err(SyscallError::EFAULT));
        };
        if hdr.cmsg_len < hdr_len || hdr.cmsg_len > msg.msg_controllen - offset {
            return Err(err(SyscallError::EINVAL));
        }
        let payload_len = hdr.cmsg_len - hdr_len;
        let Some(payload_ptr) = ptr.checked_add(hdr_len) else {
            return Err(err(SyscallError::EFAULT));
        };
        if hdr.cmsg_level == SOL_SOCKET as i32 && hdr.cmsg_type == SCM_RIGHTS {
            if scm_mode == ScmParseMode::Generic {
                // sock_cmsg_send() ignores SCM_RIGHTS on non-Unix socket families.
                // Do not inspect the fd array; Linux would not report EBADF here.
                let aligned = cmsg_align(hdr.cmsg_len);
                if aligned == 0 {
                    return Err(err(SyscallError::EINVAL));
                }
                if aligned > msg.msg_controllen - offset {
                    break;
                }
                offset += aligned;
                continue;
            }
            if scm_mode == ScmParseMode::Netlink {
                return Err(err(SyscallError::EINVAL));
            }
            if payload_len % size_of::<i32>() != 0 {
                return Err(err(SyscallError::EINVAL));
            }
            let fd_count = payload_len / size_of::<i32>();
            if files_to_pass.len().saturating_add(fd_count) > SCM_MAX_FD {
                return Err(err(SyscallError::EINVAL));
            }
            let files = current_files();
            let files = files.lock();
            for i in 0..fd_count {
                let Some(fd_ptr) = i
                    .checked_mul(size_of::<i32>())
                    .and_then(|off| payload_ptr.checked_add(off))
                else {
                    return Err(err(SyscallError::EFAULT));
                };
                let Some(fd) = try_read_user_value::<i32>(token, fd_ptr as *const i32) else {
                    return Err(err(SyscallError::EFAULT));
                };
                if fd < 0 {
                    return Err(err(SyscallError::EBADF));
                }
                let Some(file) = files.get_file(fd as usize) else {
                    return Err(err(SyscallError::EBADF));
                };
                files_to_pass.push(file);
            }
        } else if hdr.cmsg_level == SOL_SOCKET as i32 && hdr.cmsg_type == SCM_CREDENTIALS {
            if scm_mode == ScmParseMode::Generic {
                // sock_cmsg_send() ignores SCM_CREDENTIALS outside Unix-style
                // scm_send() users, including malformed payload sizes.
                let aligned = cmsg_align(hdr.cmsg_len);
                if aligned == 0 {
                    return Err(err(SyscallError::EINVAL));
                }
                if aligned > msg.msg_controllen - offset {
                    break;
                }
                offset += aligned;
                continue;
            }
            if payload_len != size_of::<UCred>() || credentials.is_some() {
                return Err(err(SyscallError::EINVAL));
            }
            let Some(cred) = try_read_user_value::<UCred>(token, payload_ptr as *const UCred)
            else {
                return Err(err(SyscallError::EFAULT));
            };
            if scm_mode != ScmParseMode::Generic {
                check_scm_credentials(cred)?;
                credentials = Some(cred);
            }
        } else if hdr.cmsg_level == SOL_SOCKET as i32 && hdr.cmsg_type == SO_MARK as i32 {
            if !super::sockopt::socket_mark_allowed() {
                return Err(err(SyscallError::EPERM));
            }
            if payload_len != size_of::<u32>() || mark.is_some() {
                return Err(err(SyscallError::EINVAL));
            }
            let Some(raw_mark) = try_read_user_value::<u32>(token, payload_ptr as *const u32)
            else {
                return Err(err(SyscallError::EFAULT));
            };
            mark = Some(super::sockopt::socket_mark_value(raw_mark as i32)?);
        } else if hdr.cmsg_level == SOL_SOCKET as i32 && hdr.cmsg_type == SO_PRIORITY as i32 {
            if payload_len != size_of::<u32>() || priority.is_some() {
                return Err(err(SyscallError::EINVAL));
            }
            let Some(raw_priority) = try_read_user_value::<u32>(token, payload_ptr as *const u32)
            else {
                return Err(err(SyscallError::EFAULT));
            };
            priority = Some(super::sockopt::socket_priority_value(raw_priority as i32)?);
        } else if hdr.cmsg_level == SOL_IP as i32 && hdr.cmsg_type == IP_TTL as i32 {
            if payload_len != size_of::<i32>() || ipv4_ttl.is_some() {
                return Err(err(SyscallError::EINVAL));
            }
            let Some(ttl) = try_read_user_value::<i32>(token, payload_ptr as *const i32) else {
                return Err(err(SyscallError::EFAULT));
            };
            if !(1..=255).contains(&ttl) {
                return Err(err(SyscallError::EINVAL));
            }
            ipv4_ttl = Some(ttl as u8);
        } else if hdr.cmsg_level == SOL_IP as i32 && hdr.cmsg_type == IP_TOS as i32 {
            if payload_len != size_of::<i32>() || ipv4_tos.is_some() {
                return Err(err(SyscallError::EINVAL));
            }
            let Some(tos) = try_read_user_value::<i32>(token, payload_ptr as *const i32) else {
                return Err(err(SyscallError::EFAULT));
            };
            if !(0..=255).contains(&tos) {
                return Err(err(SyscallError::EINVAL));
            }
            ipv4_tos = Some(tos as u8);
        } else if hdr.cmsg_level == SOL_IP as i32 && hdr.cmsg_type == IP_PKTINFO as i32 {
            if payload_len != size_of::<InPktInfo>() || ipv4_pktinfo.is_some() {
                return Err(err(SyscallError::EINVAL));
            }
            let Some(pktinfo) =
                try_read_user_value::<InPktInfo>(token, payload_ptr as *const InPktInfo)
            else {
                return Err(err(SyscallError::EFAULT));
            };
            if pktinfo.ipi_ifindex < 0 {
                return Err(err(SyscallError::EINVAL));
            }
            let spec_dst = (pktinfo.ipi_spec_dst != [0; 4])
                .then(|| smoltcp::wire::Ipv4Address::from_bytes(&pktinfo.ipi_spec_dst));
            ipv4_pktinfo = Some(SendIpv4PktInfo {
                ifindex: pktinfo.ipi_ifindex,
                spec_dst,
            });
        } else if hdr.cmsg_level == SOL_SOCKET as i32 || hdr.cmsg_level == SOL_IP as i32 {
            return Err(err(SyscallError::EINVAL));
        } else {
            let mut scratch = [0u8; CONTROL_COPY_CHUNK];
            let mut copied = 0usize;
            while copied < payload_len {
                let n = core::cmp::min(CONTROL_COPY_CHUNK, payload_len - copied);
                let Some(chunk_ptr) = payload_ptr.checked_add(copied) else {
                    return Err(err(SyscallError::EFAULT));
                };
                if try_copy_from_user(token, chunk_ptr as *const u8, &mut scratch[..n]).is_err() {
                    return Err(err(SyscallError::EFAULT));
                }
                copied += n;
            }
        }

        let aligned = cmsg_align(hdr.cmsg_len);
        if aligned == 0 {
            return Err(err(SyscallError::EINVAL));
        }
        if aligned > msg.msg_controllen - offset {
            break;
        }
        offset += aligned;
    }

    let rights = (!files_to_pass.is_empty()).then(|| ScmRights::new(files_to_pass));
    Ok(SendControl {
        scm: ScmControl {
            rights,
            credentials,
        },
        mark,
        priority,
        ipv4_pktinfo,
        ipv4_ttl,
        ipv4_tos,
    })
}

fn normalize_send_msghdr(mut msg: MsgHdr) -> MsgHdr {
    if msg.msg_name == 0 || msg.msg_namelen == 0 {
        msg.msg_name = 0;
        msg.msg_namelen = 0;
    } else if msg.msg_namelen as usize > SOCKADDR_STORAGE_SIZE {
        msg.msg_namelen = SOCKADDR_STORAGE_SIZE as u32;
    }
    msg
}

fn touch_sockaddr_arg(user_ptr: usize, len: usize) -> isize {
    if len > SOCKADDR_STORAGE_SIZE {
        return err(SyscallError::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    if user_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let mut storage = [0u8; SOCKADDR_STORAGE_SIZE];
    if try_copy_from_user(token, user_ptr as *const u8, &mut storage[..len]).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

fn get_file_with_effective_flags(fd: usize, flags: usize) -> Result<(FileArc, usize), isize> {
    let files = current_files();
    let files = files.lock();
    let Some((file, descriptor_flags)) = files.get_file_and_flags(fd) else {
        return Err(err(SyscallError::EBADF));
    };
    if (descriptor_flags & O_PATH) != 0 {
        return Err(err(SyscallError::EBADF));
    }
    let flags = if (descriptor_flags & O_NONBLOCK) != 0 {
        flags | MSG_DONTWAIT
    } else {
        flags
    };
    Ok((file, flags))
}

/// `sendmsg` / `sendmmsg` 的核心实现，支持三类 socket。
///
/// 按以下顺序尝试 downcast：
/// 1. **UnixSocketFile**：流式 socket 逐 iovec 写入；数据报 socket 将所有 iovec
///    聚合后一次性发送。AF_UNIX 按 Linux 行为忽略 `MSG_MORE`。
/// 2. **NetlinkSocketFile**：iovec 聚合后交给 `handle_outbound` 同步处理，
///    返回值始终等于发送字节数。
/// 3. **NetSocketFile**：TCP 和 UDP 均支持 MSG_MORE 积累语义。
///
/// `flags` 中支持的标志见 [`validate_send_flags`]。
fn sendmsg_inner(fd: usize, msg: &MsgHdr, flags: usize) -> isize {
    if msg.msg_iovlen > UIO_MAXIOV {
        return err(SyscallError::EMSGSIZE);
    }
    let iovs = match read_iovecs(msg.msg_iov, msg.msg_iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (file, flags) = match get_file_with_effective_flags(fd, flags) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let scm_mode = if file.as_any().downcast_ref::<UnixSocketFile>().is_some()
        || file.as_any().downcast_ref::<SocketPairEnd>().is_some()
    {
        ScmParseMode::Unix
    } else if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some() {
        ScmParseMode::Netlink
    } else {
        ScmParseMode::Generic
    };
    let control = match read_sendmsg_control(msg, scm_mode) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if control.has_packet_metadata() || control.has_ipv4_control() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let scm = control.scm;
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        if unix_sock.is_stream_like() {
            if !scm.is_empty() {
                if msg.msg_name != 0 {
                    let addr_check = touch_sockaddr_arg(msg.msg_name, msg.msg_namelen as usize);
                    if addr_check != 0 {
                        return addr_check;
                    }
                    if msg.msg_namelen != 0 {
                        return err(SyscallError::EISCONN);
                    }
                }
                let kbuf = match gather_iovecs_data(&iovs) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let Some(end) = unix_sock.stream_end() else {
                    return err(SyscallError::ENOTCONN);
                };
                if kbuf.is_empty() {
                    return err(SyscallError::EINVAL);
                }
                let user_len = kbuf.len();
                return visible_send_result(
                    match end.write_from_slice_with_control(&kbuf, (flags & MSG_DONTWAIT) != 0, scm)
                    {
                        Ok(n) => n as isize,
                        Err(e) => e,
                    },
                    user_len,
                    false,
                );
            }
            if iovs.is_empty() {
                if unix_sock.stream_end().is_none() {
                    return err(SyscallError::ENOTCONN);
                }
                return 0;
            }
            let mut total = 0isize;
            // 除最后一个 iovec 外都注入 MSG_MORE，让底层把所有分片合并成一次发送。
            for (idx, iv) in iovs.iter().enumerate() {
                let mut f = flags;
                if idx + 1 < iovs.len() {
                    f |= MSG_MORE;
                }
                let n = syscall_sendto(
                    fd,
                    iv.base,
                    iv.len,
                    f,
                    msg.msg_name,
                    msg.msg_namelen as usize,
                );
                if n < 0 {
                    return if total > 0 { total } else { n };
                }
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
            }
            return total;
        }
        if !unix_sock.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let kbuf = match gather_iovecs_data(&iovs) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let user_len = kbuf.len();
        let target = if msg.msg_name == 0 || msg.msg_namelen == 0 {
            None
        } else {
            match parse_unix_bound_addr(msg.msg_name, msg.msg_namelen as usize) {
                Ok(v) => Some(v),
                Err(e) => return e,
            }
        };
        return visible_send_result(
            unix_sock.send_dgram_with_control(kbuf, target, scm),
            user_len,
            false,
        );
    }
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        if control.has_packet_metadata() || control.has_ipv4_control() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let scm = control.scm;
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        let kbuf = match gather_iovecs_data(&iovs) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if !sock.is_record_oriented() && kbuf.is_empty() {
            if scm.is_empty() {
                return 0;
            }
            return err(SyscallError::EINVAL);
        }
        let user_len = kbuf.len();
        return visible_send_result(
            match sock.write_from_slice_with_control(&kbuf, (flags & MSG_DONTWAIT) != 0, scm) {
                Ok(n) => n as isize,
                Err(e) => e,
            },
            user_len,
            false,
        );
    }
    // sendmsg 的 netlink 分支:把 iovec 拼起来交给 handle_outbound,由它解析 nlmsghdr
    // 并立刻构造好回复入队。msg_name 是 user 指定的"发给谁",但这里 kernel 是唯一
    // 对端,只 parse 一遍校验合法性再丢弃。返回值按"全部成功发送"上报,因为我们已经
    // 在 handle_outbound 里把整批字节处理完了。
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        if control.has_packet_metadata() || control.has_ipv4_control() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        let kbuf = match gather_iovecs_data(&iovs) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if msg.msg_name != 0 && msg.msg_namelen != 0 {
            if let Err(e) = parse_sockaddr_nl_kernel_peer(msg.msg_name, msg.msg_namelen as usize) {
                return e;
            }
        }
        if kbuf.is_empty() {
            return err(SyscallError::ENODATA);
        }
        netlink_sock.handle_outbound(
            &kbuf,
            NetlinkSender::current_with_credentials(control.scm.credentials),
        );
        return kbuf.len() as isize;
    }
    if let Some(packet_sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        if control.has_scm() || control.has_ipv4_control() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        let kbuf = match gather_iovecs_data(&iovs) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let dest = if msg.msg_name != 0 && msg.msg_namelen != 0 {
            match parse_sockaddr_ll(msg.msg_name, msg.msg_namelen as usize) {
                Ok(v) => {
                    if let Err(e) = validate_sockaddr_ll_send(&v) {
                        return e;
                    }
                    Some(v)
                }
                Err(e) => return e,
            }
        } else {
            None
        };
        let metadata = control.packet_metadata(packet_sock.packet_metadata());
        if let Err(e) = packet_sock.handle_outbound_packet(&kbuf, dest.as_ref(), metadata) {
            return e;
        }
        return kbuf.len() as isize;
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        if control.has_scm() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        let kbuf = match gather_iovecs_data(&iovs) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if !raw_protocol_supported(raw_sock.protocol()) {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let mut target = raw_sock.remote_addr_v4();
        if msg.msg_name != 0 && msg.msg_namelen != 0 {
            let (ip, _port) = match parse_sockaddr_in(msg.msg_name, msg.msg_namelen as usize) {
                Ok(v) => v,
                Err(e) => return e,
            };
            target = Some(ip);
        }
        let metadata = control.packet_metadata(raw_sock.packet_metadata());
        let (ifindex_override, local_override, ttl_override, tos_override) =
            control.raw_ipv4_overrides();
        if let Err(e) = raw_sock.handle_outbound_probe(
            &kbuf,
            target,
            metadata,
            (flags & MSG_DONTROUTE) != 0,
            (flags & MSG_CONFIRM) != 0,
            ifindex_override,
            local_override,
            ttl_override,
            tos_override,
        ) {
            return e;
        }
        return kbuf.len() as isize;
    }
    if file.as_any().downcast_ref::<VsockSocketFile>().is_some() {
        return err(SyscallError::ENOTCONN);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let send_flag_check = validate_send_flags(flags);
    if send_flag_check != 0 {
        return send_flag_check;
    }
    let kbuf = match gather_iovecs_data(&iovs) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let user_len = kbuf.len();
    let key = file_key(&file);
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            if !control.is_empty() {
                return err(SyscallError::EOPNOTSUPP);
            }
            if kbuf.is_empty() {
                return 0;
            }
            let tcp_cork = match sock.tcp_cork() {
                Ok(v) => v,
                Err(e) => return e,
            };
            if (flags & MSG_MORE) != 0 || tcp_cork {
                if let Err(e) = sock.tcp_prepare_cork_send((flags & MSG_DONTWAIT) != 0) {
                    return e;
                }
                queue_pending_more_chunk(key, &kbuf, None, None, None, None, false, false);
                return kbuf.len() as isize;
            }
            if let Err(e) = flush_tcp_pending_before_current(key, sock, (flags & MSG_DONTWAIT) != 0)
            {
                return e;
            }
            match sock.tcp_send(&kbuf, (flags & MSG_DONTWAIT) != 0) {
                Ok(n) => visible_send_len(n, user_len, false),
                Err(e) => e,
            }
        }
        crate::fs::NetSocketKind::Udp => {
            if control.udp_unsupported_control() {
                return err(SyscallError::EOPNOTSUPP);
            }
            let pktinfo = control.udp_pktinfo();
            let ttl_override = control.udp_ttl_override();
            let tos_override = control.udp_tos_override();
            if kbuf.len() > IPV4_UDP_MAX_PAYLOAD {
                return err(SyscallError::EMSGSIZE);
            }
            let target = if msg.msg_name == 0 {
                None
            } else {
                match parse_sockaddr_in_for_domain(
                    msg.msg_name,
                    msg.msg_namelen as usize,
                    sock.domain(),
                ) {
                    Ok(v) => Some(v),
                    Err(e) => return e,
                }
            };
            if (flags & MSG_MORE) != 0 {
                let (
                    pending_len,
                    pending_target,
                    pending_pktinfo,
                    pending_ttl_override,
                    pending_tos_override,
                    pending_dontroute,
                    pending_confirm,
                ) = pending_more_udp_state(key);
                let queued_len = match pending_len.checked_add(kbuf.len()) {
                    Some(v) => v,
                    None => return err(SyscallError::EMSGSIZE),
                };
                if queued_len > IPV4_UDP_MAX_PAYLOAD {
                    return err(SyscallError::EMSGSIZE);
                }
                let effective_target = pending_target.or(target);
                let effective_pktinfo = pending_pktinfo.or(pktinfo);
                let effective_ttl = pending_ttl_override.or(ttl_override);
                let effective_tos = pending_tos_override.or(tos_override);
                let effective_dontroute = pending_dontroute || (flags & MSG_DONTROUTE) != 0;
                let effective_confirm = pending_confirm || (flags & MSG_CONFIRM) != 0;
                let prepare = if let Some((ip, port)) = effective_target {
                    let (ifindex_override, local_override) = effective_pktinfo
                        .map(|info| ((info.ifindex > 0).then_some(info.ifindex), info.spec_dst))
                        .unwrap_or((None, None));
                    sock.udp_prepare_send_to_ip(
                        ip,
                        port,
                        queued_len,
                        (flags & MSG_DONTWAIT) != 0,
                        effective_dontroute,
                        effective_confirm,
                        effective_ttl,
                        effective_tos,
                        ifindex_override,
                        local_override,
                    )
                } else {
                    let (ifindex_override, local_override) = effective_pktinfo
                        .map(|info| ((info.ifindex > 0).then_some(info.ifindex), info.spec_dst))
                        .unwrap_or((None, None));
                    sock.udp_prepare_connected_send(
                        queued_len,
                        (flags & MSG_DONTWAIT) != 0,
                        effective_dontroute,
                        effective_confirm,
                        effective_ttl,
                        effective_tos,
                        ifindex_override,
                        local_override,
                    )
                };
                if let Err(e) = prepare {
                    return e;
                }
                queue_pending_more_chunk(
                    key,
                    &kbuf,
                    target,
                    pktinfo,
                    ttl_override,
                    tos_override,
                    (flags & MSG_DONTROUTE) != 0,
                    (flags & MSG_CONFIRM) != 0,
                );
                return kbuf.len() as isize;
            }
            let (
                kbuf,
                had_pending,
                pending_target,
                pending_pktinfo,
                pending_ttl_override,
                pending_tos_override,
                pending_dontroute,
                pending_confirm,
            ) = consume_pending_more(key, kbuf);
            if kbuf.len() > IPV4_UDP_MAX_PAYLOAD {
                return err(SyscallError::EMSGSIZE);
            }
            let target = target.or(pending_target);
            let pktinfo = pktinfo.or(pending_pktinfo);
            let ttl_override = ttl_override.or(pending_ttl_override);
            let tos_override = tos_override.or(pending_tos_override);
            let (ifindex_override, local_override) = pktinfo
                .map(|info| ((info.ifindex > 0).then_some(info.ifindex), info.spec_dst))
                .unwrap_or((None, None));
            if let Some((ip, port)) = target {
                match sock.udp_send_to_ip(
                    ip,
                    port,
                    &kbuf,
                    (flags & MSG_DONTWAIT) != 0,
                    ((flags & MSG_DONTROUTE) != 0) || pending_dontroute,
                    ((flags & MSG_CONFIRM) != 0) || pending_confirm,
                    ttl_override,
                    tos_override,
                    ifindex_override,
                    local_override,
                ) {
                    Ok(n) => visible_send_len(n, user_len, had_pending),
                    Err(e) => e,
                }
            } else {
                match sock.udp_send_connected(
                    &kbuf,
                    (flags & MSG_DONTWAIT) != 0,
                    ((flags & MSG_DONTROUTE) != 0) || pending_dontroute,
                    ((flags & MSG_CONFIRM) != 0) || pending_confirm,
                    ttl_override,
                    tos_override,
                    ifindex_override,
                    local_override,
                ) {
                    Ok(n) => visible_send_len(n, user_len, had_pending),
                    Err(e) => e,
                }
            }
        }
        crate::fs::NetSocketKind::TcpListener => err(SyscallError::EOPNOTSUPP),
    }
}

/// `recvmsg` / `recvmmsg` 的核心实现，支持三类 socket。
///
/// 按以下顺序尝试 downcast：
/// 1. **UnixSocketFile**：流式 socket 逐 iovec 阻塞读首片、非阻塞探测后续；
///    数据报 socket 阻塞等待一整个 dgram，超出 iovec 总长的字节设 `MSG_TRUNC`。
/// 2. **NetlinkSocketFile**：从接收队列取一整条 reply 并 scatter 到 iovec；
///    在 `msg_name` 非空时回填 kernel 地址（`nl_pid = 0`）。
/// 3. **NetSocketFile**：TCP 逐 iovec 读取；UDP 一次性读取并回填对端地址。
///
/// 成功时返回实际复制的字节数，失败时返回负的 errno。
fn recvmsg_inner(fd: usize, msg: &mut MsgHdr, flags: usize, deadline_ms: Option<usize>) -> isize {
    let recv_flag_check = validate_recv_flags(flags);
    if recv_flag_check != 0 {
        return recv_flag_check;
    }
    if msg.msg_iovlen > UIO_MAXIOV {
        return err(SyscallError::EMSGSIZE);
    }
    let iovs = match read_iovecs(msg.msg_iov, msg.msg_iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let total_len = match iovecs_total_len(&iovs) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let control_ptr = msg.msg_control;
    let control_len = msg.msg_controllen;
    msg.msg_flags = 0;
    msg.msg_controllen = 0;
    let (file, flags) = match get_file_with_effective_flags(fd, flags) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if (flags & MSG_ERRQUEUE) != 0 {
        if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
            return recv_ipv4_error_queue_entry(
                msg,
                &iovs,
                control_ptr,
                control_len,
                flags,
                raw_sock.pop_ipv4_error_queue(),
            );
        }
        if let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() {
            return recv_ipv4_error_queue_entry(
                msg,
                &iovs,
                control_ptr,
                control_len,
                flags,
                sock.pop_ipv4_error_queue(),
            );
        }
        return err(SyscallError::EAGAIN);
    }
    // Netlink is datagram-based.  iproute2 probes packet length with
    // `recvmsg(MSG_PEEK | MSG_TRUNC)` and may provide a zero-length iovec;
    // Linux still returns the full datagram length in that case.
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let packet = match netlink_sock.recv_packet_with_nsid(total_len, flags) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let data = &packet.data;
        let copied = match scatter_iovecs_data(&iovs, &data[..total_len.min(data.len())]) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if copied < data.len() {
            msg.msg_flags |= MSG_TRUNC as i32;
        }
        if msg.msg_name != 0 {
            let sa = netlink_sock.kernel_addr();
            // SAFETY: `sa` is a fully initialized stack local `SockAddrNl`, and we expose
            // exactly its in-memory bytes for the duration of this call. A wrong pointer or
            // length here would read invalid memory and copy garbage into userspace.
            let r = write_msg_name_bytes(msg, unsafe {
                core::slice::from_raw_parts(
                    (&sa as *const SockAddrNl) as *const u8,
                    size_of::<SockAddrNl>(),
                )
            });
            if r != 0 {
                return r;
            }
        } else {
            msg.msg_namelen = 0;
        }
        let mut cmsgs = Vec::new();
        if netlink_sock.netlink_flag(NETLINK_LISTEN_ALL_NSID)
            && let Some(nsid) = packet.nsid
        {
            append_checked_cmsg(
                msg,
                &mut cmsgs,
                control_len,
                SOL_NETLINK as i32,
                NETLINK_LISTEN_ALL_NSID as i32,
                &nsid.to_ne_bytes(),
            );
        }
        if netlink_sock.netlink_flag(NETLINK_PKTINFO) {
            let group = packet.group.to_ne_bytes();
            append_checked_cmsg(
                msg,
                &mut cmsgs,
                control_len,
                SOL_NETLINK as i32,
                NETLINK_PKTINFO as i32,
                &group,
            );
        }
        let r = write_raw_cmsgs(msg, control_ptr, control_len, &cmsgs);
        if r != 0 {
            return r;
        }
        return if (flags & MSG_TRUNC) != 0 {
            data.len() as isize
        } else {
            copied as isize
        };
    }
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        let mut scratch = vec![0u8; total_len];
        let (copied, packet_len, control) = if sock.is_record_oriented() {
            match sock.recv_to_slice(
                &mut scratch,
                (flags & MSG_DONTWAIT) != 0,
                (flags & MSG_PEEK) != 0,
            ) {
                Ok(v) => v,
                Err(e) => return e,
            }
        } else {
            let wait_all = (flags & MSG_WAITALL) != 0
                && (flags & MSG_DONTWAIT) == 0
                && (flags & MSG_PEEK) == 0;
            let wait_deadline = deadline_ms.is_some() && wait_all;
            let peek = (flags & MSG_PEEK) != 0;
            let passcred = sock.passcred();
            let mut total = 0usize;
            let mut control = ScmControl::default();
            while total < total_len {
                if total > 0 && !wait_all && !sock.poll_readable() {
                    break;
                }
                let nonblock =
                    (flags & MSG_DONTWAIT) != 0 || (total > 0 && !wait_all) || wait_deadline;
                let (n, _, received_control) =
                    match sock.recv_to_slice(&mut scratch[total..], nonblock, peek) {
                        Ok(v) => v,
                        Err(e) => {
                            if e == err(SyscallError::EAGAIN)
                                && wait_deadline
                                && let Some(deadline) = deadline_ms
                            {
                                let wait = wait_for_recv_deadline(deadline);
                                if wait == 0 {
                                    continue;
                                }
                                if total > 0 {
                                    break;
                                }
                                return wait;
                            }
                            if total > 0 {
                                break;
                            }
                            return e;
                        }
                    };
                let saw_control = received_control.visible_for_passcred(passcred);
                control.merge_from(received_control);
                if n == 0 {
                    break;
                }
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
                if saw_control || !wait_all {
                    break;
                }
            }
            (total, total, control)
        };
        let copied_to_user = match scatter_iovecs_data(&iovs, &scratch[..copied]) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if sock.is_record_oriented() && copied_to_user < packet_len {
            msg.msg_flags |= MSG_TRUNC as i32;
        }
        let r = write_msg_name_un(msg, None);
        if r != 0 {
            return r;
        }
        let control = if sock.passcred() {
            control
        } else {
            control.without_credentials()
        };
        let r = write_scm_control_cmsgs(msg, control_ptr, control_len, control, flags);
        if r != 0 {
            return r;
        }
        return if sock.is_record_oriented() && (flags & MSG_TRUNC) != 0 {
            packet_len as isize
        } else {
            copied_to_user as isize
        };
    }
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if unix_sock.is_stream_like() {
            let Some(end) = unix_sock.stream_end() else {
                return err(SyscallError::EINVAL);
            };
            let wait_all = (flags & MSG_WAITALL) != 0
                && (flags & MSG_DONTWAIT) == 0
                && (flags & MSG_PEEK) == 0;
            let wait_deadline = deadline_ms.is_some() && wait_all;
            let peek = (flags & MSG_PEEK) != 0;
            let passcred = unix_sock.passcred();
            let mut scratch = vec![0u8; total_len];
            let mut total = 0usize;
            let mut control = ScmControl::default();
            while total < total_len {
                if total > 0 && !wait_all && !unix_sock.poll_readable() {
                    break;
                }
                let nonblock =
                    (flags & MSG_DONTWAIT) != 0 || (total > 0 && !wait_all) || wait_deadline;
                let (n, _, received_control) =
                    match end.recv_to_slice(&mut scratch[total..], nonblock, peek) {
                        Ok(v) => v,
                        Err(e) => {
                            if e == err(SyscallError::EAGAIN)
                                && wait_deadline
                                && let Some(deadline) = deadline_ms
                            {
                                let wait = wait_for_recv_deadline(deadline);
                                if wait == 0 {
                                    continue;
                                }
                                if total > 0 {
                                    break;
                                }
                                return wait;
                            }
                            if total > 0 {
                                break;
                            }
                            return e;
                        }
                    };
                let saw_control = received_control.visible_for_passcred(passcred);
                control.merge_from(received_control);
                if n == 0 {
                    break;
                }
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
                if saw_control || !wait_all {
                    break;
                }
            }
            let copied = match scatter_iovecs_data(&iovs, &scratch[..total]) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if copied < total {
                msg.msg_flags |= MSG_TRUNC as i32;
            }
            let peer = unix_sock.peer_addr();
            let r = write_msg_name_un(msg, peer.as_ref());
            if r != 0 {
                return r;
            }
            let control = if unix_sock.passcred() {
                control
            } else {
                control.without_credentials()
            };
            let r = write_scm_control_cmsgs(msg, control_ptr, control_len, control, flags);
            if r != 0 {
                return r;
            }
            return copied as isize;
        }
        if !unix_sock.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let dgram = match unix_sock.recv_dgram((flags & MSG_DONTWAIT) != 0, (flags & MSG_PEEK) != 0)
        {
            Ok(v) => v,
            Err(e) => return e,
        };
        let copied = match scatter_iovecs_data(&iovs, &dgram.payload) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if copied < dgram.payload.len() {
            msg.msg_flags |= MSG_TRUNC as i32;
        }
        let r = write_msg_name_un(msg, dgram.from.as_ref());
        if r != 0 {
            return r;
        }
        let control = if unix_sock.passcred() {
            dgram.control
        } else {
            dgram.control.without_credentials()
        };
        let r = write_scm_control_cmsgs(msg, control_ptr, control_len, control, flags);
        if r != 0 {
            return r;
        }
        return if (flags & MSG_TRUNC) != 0 {
            dgram.payload.len() as isize
        } else {
            copied as isize
        };
    }
    if let Some(packet_sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        let deadline_ms = ((flags & MSG_DONTWAIT) == 0)
            .then(|| packet_sock.rcvtimeo_deadline_ms())
            .flatten();
        let packet = loop {
            crate::net::poll_in(packet_sock.net_ns_id());
            if let Some(packet) = packet_sock.recv_packet((flags & MSG_PEEK) != 0) {
                break packet;
            }
            if (flags & MSG_DONTWAIT) != 0 {
                return err(SyscallError::EAGAIN);
            }
            let wait = wait_for_socket_recv_event(deadline_ms);
            if wait != 0 {
                return wait;
            }
        };
        let copied =
            match scatter_iovecs_data(&iovs, &packet.data[..total_len.min(packet.data.len())]) {
                Ok(v) => v,
                Err(e) => return e,
            };
        if copied < packet.data.len() {
            msg.msg_flags |= MSG_TRUNC as i32;
        }
        if msg.msg_name != 0 {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&packet.addr as *const SockAddrLl) as *const u8,
                    size_of::<SockAddrLl>(),
                )
            };
            let r = write_msg_name_bytes(msg, bytes);
            if r != 0 {
                return r;
            }
        } else {
            msg.msg_namelen = 0;
        }
        let mut cmsgs = Vec::new();
        if packet_sock.packet_auxdata() {
            let aux = packet_auxdata_bytes(&packet);
            append_checked_cmsg(
                msg,
                &mut cmsgs,
                control_len,
                SOL_PACKET as i32,
                PACKET_AUXDATA as i32,
                &aux,
            );
        }
        append_timestamp_cmsg_for_file(file.as_ref(), msg, &mut cmsgs, control_len, true);
        append_mark_priority_cmsgs(
            msg,
            &mut cmsgs,
            control_len,
            packet_sock.rcvmark().then_some(packet.metadata.mark),
            packet_sock
                .rcvpriority()
                .then_some(packet.metadata.priority),
        );
        let r = write_raw_cmsgs(msg, control_ptr, control_len, &cmsgs);
        if r != 0 {
            return r;
        }
        return if (flags & MSG_TRUNC) != 0 {
            packet.data.len() as isize
        } else {
            copied as isize
        };
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        if raw_sock.read_shutdown() {
            return 0;
        }
        let deadline_ms = ((flags & MSG_DONTWAIT) == 0)
            .then(|| raw_sock.rcvtimeo_deadline_ms())
            .flatten();
        let packet = loop {
            crate::net::poll_in(raw_sock.net_ns_id());
            if let Some(packet) = raw_sock.recv_packet((flags & MSG_PEEK) != 0) {
                break packet;
            }
            if (flags & MSG_DONTWAIT) != 0 {
                return err(SyscallError::EAGAIN);
            }
            let wait = wait_for_socket_recv_event(deadline_ms);
            if wait != 0 {
                return wait;
            }
        };
        let copied =
            match scatter_iovecs_data(&iovs, &packet.data[..total_len.min(packet.data.len())]) {
                Ok(v) => v,
                Err(e) => return e,
            };
        if copied < packet.data.len() {
            msg.msg_flags |= MSG_TRUNC as i32;
        }
        let r = write_msg_name_in(msg, packet.from, 0);
        if r != 0 {
            return r;
        }
        let mut cmsgs = Vec::new();
        if raw_sock.ipv4_pktinfo() {
            append_ipv4_pktinfo_cmsg(msg, &mut cmsgs, control_len, packet.ifindex, packet.dst);
        }
        if raw_sock.ipv4_recvttl() {
            let ttl = (packet.ttl as i32).to_ne_bytes();
            append_checked_cmsg(
                msg,
                &mut cmsgs,
                control_len,
                SOL_IP as i32,
                IP_TTL as i32,
                &ttl,
            );
        }
        if raw_sock.ipv4_recvtos() {
            let tos = [packet.tos];
            append_checked_cmsg(
                msg,
                &mut cmsgs,
                control_len,
                SOL_IP as i32,
                IP_TOS as i32,
                &tos,
            );
        }
        append_timestamp_cmsg_for_file(file.as_ref(), msg, &mut cmsgs, control_len, true);
        append_mark_priority_cmsgs(
            msg,
            &mut cmsgs,
            control_len,
            raw_sock.rcvmark().then_some(packet.metadata.mark),
            raw_sock.rcvpriority().then_some(packet.metadata.priority),
        );
        let r = write_raw_cmsgs(msg, control_ptr, control_len, &cmsgs);
        if r != 0 {
            return r;
        }
        return if (flags & MSG_TRUNC) != 0 {
            packet.data.len() as isize
        } else {
            copied as isize
        };
    }
    if file.as_any().downcast_ref::<VsockSocketFile>().is_some() {
        return err(SyscallError::ENOTCONN);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            if total_len == 0 {
                msg.msg_namelen = 0;
                return 0;
            }
            if (flags & MSG_PEEK) != 0 {
                let mut kbuf = vec![0u8; total_len];
                let recv = if (flags & MSG_DONTWAIT) != 0 {
                    sock.tcp_recv_nonblock(&mut kbuf, true)
                } else {
                    sock.tcp_recv(&mut kbuf, true)
                };
                let n = match recv {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let copied = match scatter_iovecs_data(&iovs, &kbuf[..n]) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                // Linux tcp_recvmsg() ignores msg_name/msg_namelen for connected stream sockets.
                msg.msg_namelen = 0;
                let mut cmsgs = Vec::new();
                append_timestamp_cmsg_for_file(file.as_ref(), msg, &mut cmsgs, control_len, n > 0);
                append_mark_priority_cmsgs_for_file(
                    file.as_ref(),
                    msg,
                    &mut cmsgs,
                    control_len,
                    n > 0,
                );
                let r = write_raw_cmsgs(msg, control_ptr, control_len, &cmsgs);
                if r != 0 {
                    return r;
                }
                return copied as isize;
            }
            let wait_all = (flags & MSG_WAITALL) != 0 && (flags & MSG_DONTWAIT) == 0;
            let wait_deadline = deadline_ms.is_some() && wait_all;
            let nonblock_recv = (flags & MSG_DONTWAIT) != 0 || wait_deadline;
            let mut total = 0usize;
            'iovecs: for iv in iovs.iter() {
                let mut off = 0usize;
                while off < iv.len {
                    if total > 0 && !wait_all && !sock.poll_readable() {
                        break 'iovecs;
                    }
                    let mut kbuf = vec![0u8; iv.len - off];
                    let recv = if nonblock_recv {
                        sock.tcp_recv_nonblock(&mut kbuf, false)
                    } else {
                        sock.tcp_recv(&mut kbuf, false)
                    };
                    let n = match recv {
                        Ok(v) => v,
                        Err(e) => {
                            if e == err(SyscallError::EAGAIN)
                                && wait_deadline
                                && let Some(deadline) = deadline_ms
                            {
                                let wait = wait_for_recv_deadline(deadline);
                                if wait == 0 {
                                    continue;
                                }
                                return if total > 0 { total as isize } else { wait };
                            }
                            return if total > 0 { total as isize } else { e };
                        }
                    };
                    if n == 0 {
                        break 'iovecs;
                    }
                    let Some(base) = iv.base.checked_add(off) else {
                        return err(SyscallError::EINVAL);
                    };
                    let token = get_current_token();
                    if try_copy_to_user(token, base as *mut u8, &kbuf[..n]).is_err() {
                        return err(SyscallError::EFAULT);
                    }
                    off += n;
                    total = match total.checked_add(n) {
                        Some(v) => v,
                        None => return err(SyscallError::EINVAL),
                    };
                    if !wait_all {
                        break;
                    }
                }
            }
            // Linux tcp_recvmsg() ignores msg_name/msg_namelen for connected stream sockets.
            msg.msg_namelen = 0;
            let mut cmsgs = Vec::new();
            append_timestamp_cmsg_for_file(file.as_ref(), msg, &mut cmsgs, control_len, total > 0);
            append_mark_priority_cmsgs_for_file(
                file.as_ref(),
                msg,
                &mut cmsgs,
                control_len,
                total > 0,
            );
            let r = write_raw_cmsgs(msg, control_ptr, control_len, &cmsgs);
            if r != 0 {
                return r;
            }
            total as isize
        }
        crate::fs::NetSocketKind::Udp => {
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
            let mut kbuf = vec![0u8; total_len];
            let (n, packet_len, ip, port, rx_info) = match sock.udp_recv_from(
                &mut kbuf,
                (flags & MSG_PEEK) != 0,
                (flags & MSG_DONTWAIT) != 0,
            ) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let copied = match scatter_iovecs_data(&iovs, &kbuf[..n]) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let r = write_msg_name_in_for_domain(msg, sock.domain(), ip, port);
            if r != 0 {
                return r;
            }
            if copied < packet_len {
                msg.msg_flags |= MSG_TRUNC as i32;
            }
            let mut cmsgs = Vec::new();
            if sock.ipv4_pktinfo()
                && let Some(info) = rx_info
            {
                append_ipv4_pktinfo_cmsg(msg, &mut cmsgs, control_len, info.ifindex, info.dst);
            }
            if sock.ipv4_recvttl()
                && let Some(info) = rx_info
            {
                let ttl = (info.ttl as i32).to_ne_bytes();
                append_checked_cmsg(
                    msg,
                    &mut cmsgs,
                    control_len,
                    SOL_IP as i32,
                    IP_TTL as i32,
                    &ttl,
                );
            }
            if sock.ipv4_recvtos()
                && let Some(info) = rx_info
            {
                let tos = [info.tos];
                append_checked_cmsg(
                    msg,
                    &mut cmsgs,
                    control_len,
                    SOL_IP as i32,
                    IP_TOS as i32,
                    &tos,
                );
            }
            append_timestamp_cmsg_for_file(file.as_ref(), msg, &mut cmsgs, control_len, true);
            append_mark_priority_cmsgs_for_file(file.as_ref(), msg, &mut cmsgs, control_len, true);
            let r = write_raw_cmsgs(msg, control_ptr, control_len, &cmsgs);
            if r != 0 {
                return r;
            }
            if (flags & MSG_TRUNC) != 0 {
                packet_len as isize
            } else {
                copied as isize
            }
        }
        crate::fs::NetSocketKind::TcpListener => err(SyscallError::EOPNOTSUPP),
    }
}

/// `sendmsg(2)` 系统调用入口。
///
/// 从用户态读取 [`MsgHdr`] 后委托给 [`sendmsg_inner`] 处理。
///
/// # 参数
/// - `fd`：已打开的 socket 文件描述符
/// - `msg`：用户态 `struct msghdr *` 指针
/// - `flags`：发送标志（`MSG_MORE`、`MSG_DONTWAIT` 等）
///
/// # 返回值
/// 成功时返回发送字节数，失败时返回负的 errno。
pub fn syscall_sendmsg(fd: usize, msg: usize, flags: usize) -> isize {
    let msghdr = match read_msghdr(msg) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let msghdr = normalize_send_msghdr(msghdr);
    sendmsg_inner(fd, &msghdr, flags)
}

/// `recvmsg(2)` 系统调用入口。
///
/// 从用户态读取 [`MsgHdr`]，调用 [`recvmsg_inner`] 后将修改后的
/// `MsgHdr`（含 `msg_namelen`、`msg_flags`、`msg_controllen`）写回用户态。
///
/// # 参数
/// - `fd`：已打开的 socket 文件描述符
/// - `msg`：用户态 `struct msghdr *` 指针（调用后内核会更新其字段）
/// - `flags`：接收标志（`MSG_DONTWAIT`、`MSG_PEEK` 等）
///
/// # 返回值
/// 成功时返回接收字节数，失败时返回负的 errno。
pub fn syscall_recvmsg(fd: usize, msg: usize, flags: usize) -> isize {
    let mut msghdr = match read_msghdr(msg) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let ret = recvmsg_inner(fd, &mut msghdr, flags, None);
    if ret < 0 {
        return ret;
    }
    let token = get_current_token();
    if try_write_user_value(token, msg as *mut MsgHdr, &msghdr).is_err() {
        return err(SyscallError::EFAULT);
    }
    ret
}

/// `writev(2)` on sockets is Linux `sock_write_iter()` and therefore shares
/// `sendmsg(2)` semantics: all iovecs describe one logical socket send.
pub(crate) fn syscall_sendmsg_iov(fd: usize, iov_ptr: usize, iovcnt: usize, flags: usize) -> isize {
    let msghdr = MsgHdr {
        msg_iov: iov_ptr,
        msg_iovlen: iovcnt,
        ..MsgHdr::default()
    };
    sendmsg_inner(fd, &msghdr, flags)
}

/// `readv(2)` on sockets is Linux `sock_read_iter()` and therefore shares
/// `recvmsg(2)` semantics: one receive operation scatters into all iovecs.
pub(crate) fn syscall_recvmsg_iov(fd: usize, iov_ptr: usize, iovcnt: usize, flags: usize) -> isize {
    let mut msghdr = MsgHdr {
        msg_iov: iov_ptr,
        msg_iovlen: iovcnt,
        ..MsgHdr::default()
    };
    recvmsg_inner(fd, &mut msghdr, flags, None)
}

/// `sendmmsg(2)` 系统调用入口：批量发送多条消息。
///
/// 依次处理 `msgvec[0..min(vlen, UIO_MAXIOV)]` 中的每条 [`MMsgHdr`]，每条成功后
/// 将实际发送字节数写回对应的 `msg_len` 字段。Linux 对过大的 `vlen` 采用封顶
/// 而非报错，避免单次系统调用扫描无限长的用户数组。
///
/// **POSIX 错误语义**：若在第 `i` 条（`i > 0`）消息处出错，返回已成功发送的消息
/// 计数而非错误码，确保调用方能感知部分成功。仅在第一条就失败时才返回错误码。
///
/// # 返回值
/// 成功时返回发送的消息条数（`≥ 0`），失败时返回负的 errno。
pub fn syscall_sendmmsg(fd: usize, msgvec: usize, vlen: usize, flags: usize) -> isize {
    if vlen == 0 {
        return 0;
    }
    if msgvec == 0 {
        return err(SyscallError::EFAULT);
    }
    let vlen = vlen.min(UIO_MAXIOV);
    let mut sent = 0usize;
    for i in 0..vlen {
        let token = get_current_token();
        let Some(ptr) = i
            .checked_mul(size_of::<MMsgHdr>())
            .and_then(|off| msgvec.checked_add(off))
        else {
            return if sent > 0 {
                sent as isize
            } else {
                err(SyscallError::EFAULT)
            };
        };
        let ptr = ptr as *const MMsgHdr;
        let Some(mut mmsg) = try_read_user_value::<MMsgHdr>(token, ptr) else {
            return if sent > 0 {
                sent as isize
            } else {
                err(SyscallError::EFAULT)
            };
        };
        mmsg.msg_hdr = normalize_send_msghdr(mmsg.msg_hdr);
        let ret = sendmsg_inner(fd, &mmsg.msg_hdr, flags);
        if ret < 0 {
            return if sent > 0 { sent as isize } else { ret };
        }
        let wr = write_mmsghdr_msg_len(msgvec, i, ret as u32);
        if wr < 0 {
            return if sent > 0 { sent as isize } else { wr };
        }
        sent += 1;
    }
    sent as isize
}

/// `recvmmsg(2)` 系统调用入口：批量接收多条消息。
///
/// 依次接收最多 `min(vlen, UIO_MAXIOV)` 条消息，每条成功后将实际接收字节数写回
/// `msg_len`，并将更新后的 [`MMsgHdr`] 写回用户态。
///
/// **POSIX 错误语义**：与 [`syscall_sendmmsg`] 相同——已收到至少一条消息时，
/// 后续错误不传播，直接返回已接收的消息计数。
///
/// **`MSG_WAITFORONE`**：收到第一条消息后，后续接收均改为非阻塞（追加
/// `MSG_DONTWAIT`），实现"至少一条、尽量多收"的高效语义。
///
/// `timeout` 为相对超时。非空时外层按绝对 deadline 驱动非阻塞接收与 timer
/// 睡眠，避免首条消息永远阻塞；成功收到至少一条后按 Linux 习惯写回剩余时间。
///
/// # 返回值
/// 成功时返回接收的消息条数（`≥ 0`），失败时返回负的 errno。
pub fn syscall_recvmmsg(
    fd: usize,
    msgvec: usize,
    vlen: usize,
    flags: usize,
    timeout: usize,
) -> isize {
    if vlen == 0 {
        return 0;
    }
    if msgvec == 0 {
        return err(SyscallError::EFAULT);
    }
    let vlen = vlen.min(UIO_MAXIOV);
    let deadline_ms = match recvmmsg_timeout_deadline(timeout) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut recvd = 0usize;
    for i in 0..vlen {
        let token = get_current_token();
        let Some(ptr) = i
            .checked_mul(size_of::<MMsgHdr>())
            .and_then(|off| msgvec.checked_add(off))
        else {
            return if recvd > 0 {
                recvmmsg_finish(recvd as isize, timeout, deadline_ms)
            } else {
                err(SyscallError::EFAULT)
            };
        };
        let ptr = ptr as *const MMsgHdr;
        let Some(mut mmsg) = try_read_user_value::<MMsgHdr>(token, ptr) else {
            return if recvd > 0 {
                recvmmsg_finish(recvd as isize, timeout, deadline_ms)
            } else {
                err(SyscallError::EFAULT)
            };
        };
        let mut recv_flags = flags;
        // MSG_WAITFORONE：第一条收到后，剩余都改非阻塞，实现"至少一条、尽量多收"语义。
        if recvd > 0 && (flags & MSG_WAITFORONE) != 0 {
            recv_flags |= MSG_DONTWAIT;
        }
        let ret = recvmsg_inner_with_deadline(fd, &mut mmsg.msg_hdr, recv_flags, deadline_ms);
        if ret < 0 {
            return if recvd > 0 {
                recvmmsg_finish(recvd as isize, timeout, deadline_ms)
            } else {
                ret
            };
        }
        mmsg.msg_len = ret as u32;
        let wr = write_mmsghdr(msgvec, i, &mmsg);
        if wr < 0 {
            return if recvd > 0 {
                recvmmsg_finish(recvd as isize, timeout, deadline_ms)
            } else {
                wr
            };
        }
        recvd += 1;
        if deadline_ms.is_some_and(|deadline| crate::time::get_time_ms() >= deadline) {
            break;
        }
        if ret == 0 {
            break;
        }
    }
    recvmmsg_finish(recvd as isize, timeout, deadline_ms)
}

/// `sendto(2)` 系统调用入口。
///
/// 支持 Unix socket（流式 / 数据报）、netlink socket 和 TCP/UDP socket。
/// AF_UNIX 按 Linux 行为忽略 `MSG_MORE`；IPv4 TCP/UDP 保留 `MSG_MORE` 积累语义。
///
/// # 参数
/// - `fd`：已打开的 socket 文件描述符
/// - `buf_ptr`：用户态发送缓冲区指针
/// - `len`：发送字节数
/// - `flags`：发送标志（`MSG_MORE`、`MSG_DONTWAIT` 等）
/// - `addr`：目标地址结构体指针（`struct sockaddr *`），连接态 socket 可传 `0`
/// - `addrlen`：`addr` 指向结构体的字节长度
///
/// # 返回值
/// 成功时返回本次调用消费的用户字节数，失败时返回负的 errno。
pub fn syscall_sendto(
    fd: usize,
    buf_ptr: usize,
    len: usize,
    flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    let (file, flags) = match get_file_with_effective_flags(fd, flags) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        if unix_sock.is_stream_like() {
            if addr != 0 {
                let addr_check = touch_sockaddr_arg(addr, addrlen);
                if addr_check != 0 {
                    return addr_check;
                }
                if addrlen != 0 {
                    return err(SyscallError::EISCONN);
                }
            }
            let Some(end) = unix_sock.stream_end() else {
                return err(SyscallError::ENOTCONN);
            };
            if len == 0 {
                return 0;
            }
            let token = get_current_token();
            let mut kbuf = alloc::vec![0u8; len];
            if try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err() {
                return err(SyscallError::EFAULT);
            }
            return match end.write_from_slice(&kbuf, (flags & MSG_DONTWAIT) != 0) {
                Ok(n) => n as isize,
                Err(e) => e,
            };
        }
        if !unix_sock.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let target = if addr == 0 || addrlen == 0 {
            None
        } else {
            let t = match parse_unix_bound_addr(addr, addrlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
            Some(t)
        };
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        if len > 0 && try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err()
        {
            return err(SyscallError::EFAULT);
        }
        let user_len = kbuf.len();
        return visible_send_result(unix_sock.send_dgram(kbuf, target), user_len, false);
    }
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        if !sock.is_record_oriented() && len == 0 {
            return 0;
        }
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        if len > 0 && try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err()
        {
            return err(SyscallError::EFAULT);
        }
        return visible_send_result(
            match sock.write_from_slice(&kbuf, (flags & MSG_DONTWAIT) != 0) {
                Ok(n) => n as isize,
                Err(e) => e,
            },
            len,
            false,
        );
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        if addr != 0 {
            let addr_check = touch_sockaddr_arg(addr, addrlen);
            if addr_check != 0 {
                return addr_check;
            }
        }
        if len == 0 {
            return err(SyscallError::ENODATA);
        }
        if addr != 0 && addrlen != 0 {
            if let Err(e) = parse_sockaddr_nl_kernel_peer(addr, addrlen) {
                return e;
            }
        }
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        if try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err() {
            return err(SyscallError::EFAULT);
        }
        netlink_sock.handle_outbound(&kbuf, NetlinkSender::current());
        return len as isize;
    }
    if let Some(packet_sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        let dest = if addr != 0 {
            match parse_sockaddr_ll(addr, addrlen) {
                Ok(v) => {
                    if let Err(e) = validate_sockaddr_ll_send(&v) {
                        return e;
                    }
                    Some(v)
                }
                Err(e) => return e,
            }
        } else {
            None
        };
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        if try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err() {
            return err(SyscallError::EFAULT);
        }
        if let Err(e) =
            packet_sock.handle_outbound_packet(&kbuf, dest.as_ref(), packet_sock.packet_metadata())
        {
            return e;
        }
        return len as isize;
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        let send_flag_check = validate_send_flags(flags);
        if send_flag_check != 0 {
            return send_flag_check;
        }
        if !raw_protocol_supported(raw_sock.protocol()) {
            return err(SyscallError::EPROTONOSUPPORT);
        }
        let mut target = raw_sock.remote_addr_v4();
        if addr != 0 && addrlen != 0 {
            let (ip, _port) = match parse_sockaddr_in(addr, addrlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
            target = Some(ip);
        }
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        if len > 0 && try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err()
        {
            return err(SyscallError::EFAULT);
        }
        if let Err(e) = raw_sock.handle_outbound_probe(
            &kbuf,
            target,
            raw_sock.packet_metadata(),
            (flags & MSG_DONTROUTE) != 0,
            (flags & MSG_CONFIRM) != 0,
            None,
            None,
            None,
            None,
        ) {
            return e;
        }
        return len as isize;
    }
    if file.as_any().downcast_ref::<VsockSocketFile>().is_some() {
        return err(SyscallError::ENOTCONN);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let send_flag_check = validate_send_flags(flags);
    if send_flag_check != 0 {
        return send_flag_check;
    }
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            let token = get_current_token();
            let mut kbuf = alloc::vec![0u8; len];
            if len > 0
                && try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err()
            {
                return err(SyscallError::EFAULT);
            }
            let key = file_key(&file);
            let user_len = kbuf.len();
            let tcp_cork = match sock.tcp_cork() {
                Ok(v) => v,
                Err(e) => return e,
            };
            if (flags & MSG_MORE) != 0 || tcp_cork {
                if let Err(e) = sock.tcp_prepare_cork_send((flags & MSG_DONTWAIT) != 0) {
                    return e;
                }
                queue_pending_more_chunk(key, &kbuf, None, None, None, None, false, false);
                return len as isize;
            }
            if let Err(e) = flush_tcp_pending_before_current(key, sock, (flags & MSG_DONTWAIT) != 0)
            {
                return e;
            }
            match sock.tcp_send(&kbuf, (flags & MSG_DONTWAIT) != 0) {
                Ok(n) => visible_send_len(n, user_len, false),
                Err(e) => e,
            }
        }
        crate::fs::NetSocketKind::Udp => {
            let target = if addr == 0 {
                None
            } else {
                let (ip, port) = match parse_sockaddr_in_for_domain(addr, addrlen, sock.domain()) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                Some((ip, port))
            };
            let token = get_current_token();
            let mut kbuf = alloc::vec![0u8; len];
            if len > 0
                && try_copy_from_user(token, buf_ptr as *const u8, kbuf.as_mut_slice()).is_err()
            {
                return err(SyscallError::EFAULT);
            }
            let key = file_key(&file);
            let user_len = kbuf.len();
            if kbuf.len() > IPV4_UDP_MAX_PAYLOAD {
                return err(SyscallError::EMSGSIZE);
            }
            if (flags & MSG_MORE) != 0 {
                let (
                    pending_len,
                    pending_target,
                    pending_pktinfo,
                    pending_ttl_override,
                    pending_tos_override,
                    pending_dontroute,
                    pending_confirm,
                ) = pending_more_udp_state(key);
                let queued_len = match pending_len.checked_add(kbuf.len()) {
                    Some(v) => v,
                    None => return err(SyscallError::EMSGSIZE),
                };
                if queued_len > IPV4_UDP_MAX_PAYLOAD {
                    return err(SyscallError::EMSGSIZE);
                }
                let effective_target = pending_target.or(target);
                let effective_pktinfo = pending_pktinfo;
                let effective_dontroute = pending_dontroute || (flags & MSG_DONTROUTE) != 0;
                let effective_confirm = pending_confirm || (flags & MSG_CONFIRM) != 0;
                let prepare = if let Some((ip, port)) = effective_target {
                    let (ifindex_override, local_override) = effective_pktinfo
                        .map(|info| ((info.ifindex > 0).then_some(info.ifindex), info.spec_dst))
                        .unwrap_or((None, None));
                    sock.udp_prepare_send_to_ip(
                        ip,
                        port,
                        queued_len,
                        (flags & MSG_DONTWAIT) != 0,
                        effective_dontroute,
                        effective_confirm,
                        pending_ttl_override,
                        pending_tos_override,
                        ifindex_override,
                        local_override,
                    )
                } else {
                    let (ifindex_override, local_override) = effective_pktinfo
                        .map(|info| ((info.ifindex > 0).then_some(info.ifindex), info.spec_dst))
                        .unwrap_or((None, None));
                    sock.udp_prepare_connected_send(
                        queued_len,
                        (flags & MSG_DONTWAIT) != 0,
                        effective_dontroute,
                        effective_confirm,
                        pending_ttl_override,
                        pending_tos_override,
                        ifindex_override,
                        local_override,
                    )
                };
                if let Err(e) = prepare {
                    return e;
                }
                queue_pending_more_chunk(
                    key,
                    &kbuf,
                    target,
                    None,
                    None,
                    None,
                    (flags & MSG_DONTROUTE) != 0,
                    (flags & MSG_CONFIRM) != 0,
                );
                return len as isize;
            }
            let (
                kbuf,
                had_pending,
                pending_target,
                pending_pktinfo,
                pending_ttl_override,
                pending_tos_override,
                pending_dontroute,
                pending_confirm,
            ) = consume_pending_more(key, kbuf);
            if kbuf.len() > IPV4_UDP_MAX_PAYLOAD {
                return err(SyscallError::EMSGSIZE);
            }
            let target = target.or(pending_target);
            let ttl_override = pending_ttl_override;
            let tos_override = pending_tos_override;
            let (ifindex_override, local_override) = pending_pktinfo
                .map(|info| ((info.ifindex > 0).then_some(info.ifindex), info.spec_dst))
                .unwrap_or((None, None));
            if let Some((ip, port)) = target {
                match sock.udp_send_to_ip(
                    ip,
                    port,
                    &kbuf,
                    (flags & MSG_DONTWAIT) != 0,
                    ((flags & MSG_DONTROUTE) != 0) || pending_dontroute,
                    ((flags & MSG_CONFIRM) != 0) || pending_confirm,
                    ttl_override,
                    tos_override,
                    ifindex_override,
                    local_override,
                ) {
                    Ok(n) => visible_send_len(n, user_len, had_pending),
                    Err(e) => e,
                }
            } else {
                match sock.udp_send_connected(
                    &kbuf,
                    (flags & MSG_DONTWAIT) != 0,
                    ((flags & MSG_DONTROUTE) != 0) || pending_dontroute,
                    ((flags & MSG_CONFIRM) != 0) || pending_confirm,
                    ttl_override,
                    tos_override,
                    ifindex_override,
                    local_override,
                ) {
                    Ok(n) => visible_send_len(n, user_len, had_pending),
                    Err(e) => e,
                }
            }
        }
        crate::fs::NetSocketKind::TcpListener => err(SyscallError::EOPNOTSUPP),
    }
}

/// `recvfrom(2)` 系统调用入口。
///
/// 支持 Unix socket（流式 / 数据报）、netlink socket 和 TCP/UDP socket。
/// 若 `addr` 非空，调用成功后将对端地址写回用户态。
///
/// # 参数
/// - `fd`：已打开的 socket 文件描述符
/// - `buf_ptr`：用户态接收缓冲区指针
/// - `len`：缓冲区字节长度
/// - `flags`：接收标志（`MSG_DONTWAIT`、`MSG_PEEK` 等）
/// - `addr`：用于写回对端地址的 `struct sockaddr *`，不需要时传 `0`
/// - `addrlen`：`addr` 缓冲区长度的用户态指针（`socklen_t *`），不需要时传 `0`
///
/// # 返回值
/// 成功时返回接收字节数，失败时返回负的 errno。
pub fn syscall_recvfrom(
    fd: usize,
    buf_ptr: usize,
    len: usize,
    flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    let recv_flag_check = validate_recv_flags(flags);
    if recv_flag_check != 0 {
        return recv_flag_check;
    }
    let (file, flags) = match get_file_with_effective_flags(fd, flags) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // MSG_ERRQUEUE: drain the IPv4 error queue (IP_RECVERR). recvfrom has no
    // msg_control, so we only return the queued payload (or EAGAIN when empty),
    // matching what LTP recv01/recvfrom01 expect on a connected TCP socket.
    if (flags & MSG_ERRQUEUE) != 0 {
        let entry = if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
            raw_sock.pop_ipv4_error_queue()
        } else if let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() {
            sock.pop_ipv4_error_queue()
        } else {
            None
        };
        let Some(entry) = entry else {
            return err(SyscallError::EAGAIN);
        };
        let token = get_current_token();
        let n = len.min(entry.payload.len());
        if n > 0 && try_copy_to_user(token, buf_ptr as *mut u8, &entry.payload[..n]).is_err() {
            return err(SyscallError::EFAULT);
        }
        return if (flags & MSG_TRUNC) != 0 {
            entry.payload.len() as isize
        } else {
            n as isize
        };
    }
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if unix_sock.is_stream_like() {
            if len == 0 {
                return 0;
            }
            let Some(end) = unix_sock.stream_end() else {
                return err(SyscallError::EINVAL);
            };
            let wait_all = (flags & MSG_WAITALL) != 0
                && (flags & MSG_DONTWAIT) == 0
                && (flags & MSG_PEEK) == 0;
            let peek = (flags & MSG_PEEK) != 0;
            let passcred = unix_sock.passcred();
            let mut kbuf = alloc::vec![0u8; len];
            let mut total = 0usize;
            while total < len {
                if total > 0 && !wait_all && !unix_sock.poll_readable() {
                    break;
                }
                let nonblock = (flags & MSG_DONTWAIT) != 0 || (total > 0 && !wait_all);
                let (n, saw_control) = match end.recv_to_slice(&mut kbuf[total..], nonblock, peek) {
                    Ok((n, _, control)) => (n, control.visible_for_passcred(passcred)),
                    Err(e) => {
                        if total > 0 {
                            break;
                        }
                        return e;
                    }
                };
                if n == 0 {
                    break;
                }
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
                if saw_control || !wait_all {
                    break;
                }
            }
            let token = get_current_token();
            if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..total]).is_err() {
                return err(SyscallError::EFAULT);
            }
            if addr != 0 {
                let peer = unix_sock.peer_addr();
                let r = write_sockaddr_un(addr, addrlen, peer.as_ref());
                if r != 0 {
                    return r;
                }
            }
            return total as isize;
        }
        if !unix_sock.is_dgram() {
            return err(SyscallError::EOPNOTSUPP);
        }
        let msg = match unix_sock.recv_dgram((flags & MSG_DONTWAIT) != 0, (flags & MSG_PEEK) != 0) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let n = len.min(msg.payload.len());
        let token = get_current_token();
        if try_copy_to_user(token, buf_ptr as *mut u8, &msg.payload[..n]).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 {
            let r = write_sockaddr_un(addr, addrlen, msg.from.as_ref());
            if r != 0 {
                return r;
            }
        }
        return if (flags & MSG_TRUNC) != 0 {
            msg.payload.len() as isize
        } else {
            n as isize
        };
    }
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        if !sock.is_record_oriented() && len == 0 {
            return 0;
        }
        let token = get_current_token();
        let mut kbuf = alloc::vec![0u8; len];
        let (copied, packet_len) = if sock.is_record_oriented() {
            match sock.recv_to_slice(
                &mut kbuf,
                (flags & MSG_DONTWAIT) != 0,
                (flags & MSG_PEEK) != 0,
            ) {
                Ok((copied, packet_len, _)) => (copied, packet_len),
                Err(e) => return e,
            }
        } else {
            let wait_all = (flags & MSG_WAITALL) != 0
                && (flags & MSG_DONTWAIT) == 0
                && (flags & MSG_PEEK) == 0;
            let peek = (flags & MSG_PEEK) != 0;
            let passcred = sock.passcred();
            let mut total = 0usize;
            while total < len {
                if total > 0 && !wait_all && !sock.poll_readable() {
                    break;
                }
                let nonblock = (flags & MSG_DONTWAIT) != 0 || (total > 0 && !wait_all);
                let (n, saw_control) = match sock.recv_to_slice(&mut kbuf[total..], nonblock, peek)
                {
                    Ok((n, _, control)) => (n, control.visible_for_passcred(passcred)),
                    Err(e) => {
                        if total > 0 {
                            break;
                        }
                        return e;
                    }
                };
                if n == 0 {
                    break;
                }
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
                if saw_control || !wait_all {
                    break;
                }
            }
            (total, total)
        };
        if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..copied]).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 {
            let r = write_sockaddr_un(addr, addrlen, None);
            if r != 0 {
                return r;
            }
        }
        return if sock.is_record_oriented() && (flags & MSG_TRUNC) != 0 {
            packet_len as isize
        } else {
            copied as isize
        };
    }
    // recvfrom 的 netlink 分支(与上面 recvmsg 分支语义一致,只是参数风格不同):
    // 即使用户给 0 长缓冲，Linux 也会取出一条 skb；带 MSG_TRUNC 时返回完整长度。
    // 同样在 addr 非空时回填 kernel netlink 地址(nl_pid = 0)。
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let packet = match netlink_sock.recv_packet(len, flags) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let copied = core::cmp::min(len, packet.len());
        let token = get_current_token();
        if try_copy_to_user(token, buf_ptr as *mut u8, &packet[..copied]).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 {
            let sa = netlink_sock.kernel_addr();
            let r = write_sockaddr_nl(addr, addrlen, &sa);
            if r != 0 {
                return r;
            }
        }
        return if (flags & MSG_TRUNC) != 0 {
            packet.len() as isize
        } else {
            copied as isize
        };
    }
    if let Some(packet_sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        let deadline_ms = ((flags & MSG_DONTWAIT) == 0)
            .then(|| packet_sock.rcvtimeo_deadline_ms())
            .flatten();
        let packet = loop {
            crate::net::poll_in(packet_sock.net_ns_id());
            if let Some(packet) = packet_sock.recv_packet((flags & MSG_PEEK) != 0) {
                break packet;
            }
            if (flags & MSG_DONTWAIT) != 0 {
                return err(SyscallError::EAGAIN);
            }
            let wait = wait_for_socket_recv_event(deadline_ms);
            if wait != 0 {
                return wait;
            }
        };
        let copied = core::cmp::min(len, packet.data.len());
        let token = get_current_token();
        if try_copy_to_user(token, buf_ptr as *mut u8, &packet.data[..copied]).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 {
            let r = write_recv_sockaddr_ll(addr, addrlen, &packet.addr);
            if r != 0 {
                return r;
            }
        }
        return if (flags & MSG_TRUNC) != 0 {
            packet.data.len() as isize
        } else {
            copied as isize
        };
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        if raw_sock.read_shutdown() {
            return 0;
        }
        let deadline_ms = ((flags & MSG_DONTWAIT) == 0)
            .then(|| raw_sock.rcvtimeo_deadline_ms())
            .flatten();
        let packet = loop {
            crate::net::poll_in(raw_sock.net_ns_id());
            if let Some(packet) = raw_sock.recv_packet((flags & MSG_PEEK) != 0) {
                break packet;
            }
            if (flags & MSG_DONTWAIT) != 0 {
                return err(SyscallError::EAGAIN);
            }
            let wait = wait_for_socket_recv_event(deadline_ms);
            if wait != 0 {
                return wait;
            }
        };
        let copied = core::cmp::min(len, packet.data.len());
        let token = get_current_token();
        if try_copy_to_user(token, buf_ptr as *mut u8, &packet.data[..copied]).is_err() {
            return err(SyscallError::EFAULT);
        }
        if addr != 0 {
            let r = write_sockaddr_in(addr, addrlen, packet.from, 0);
            if r != 0 {
                return r;
            }
        }
        return if (flags & MSG_TRUNC) != 0 {
            packet.data.len() as isize
        } else {
            copied as isize
        };
    }
    if file.as_any().downcast_ref::<VsockSocketFile>().is_some() {
        return err(SyscallError::ENOTCONN);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => {
            if len == 0 {
                if addr != 0 {
                    return write_empty_sockaddr_len(addrlen);
                }
                return 0;
            }
            if addr != 0 {
                if addrlen == 0 {
                    return err(SyscallError::EFAULT);
                }
                let token = get_current_token();
                let Some(name_len) = try_read_user_value::<u32>(token, addrlen as *const u32)
                else {
                    return err(SyscallError::EFAULT);
                };
                if (name_len as usize) > i32::MAX as usize {
                    return err(SyscallError::EINVAL);
                }
            }
            let mut kbuf = alloc::vec![0u8; len];
            if (flags & MSG_PEEK) != 0 {
                let recv = if (flags & MSG_DONTWAIT) != 0 {
                    sock.tcp_recv_nonblock(&mut kbuf, true)
                } else {
                    sock.tcp_recv(&mut kbuf, true)
                };
                let n = match recv {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let token = get_current_token();
                if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]).is_err() {
                    return err(SyscallError::EFAULT);
                }
                if addr != 0 {
                    // Linux tcp_recvmsg() leaves kaddr length at 0; recvfrom then writes
                    // *addrlen = 0 and copies no sockaddr bytes.
                    let r = write_empty_sockaddr_len(addrlen);
                    if r != 0 {
                        return r;
                    }
                }
                return n as isize;
            }
            let wait_all = (flags & MSG_WAITALL) != 0 && (flags & MSG_DONTWAIT) == 0;
            let nonblock_recv = (flags & MSG_DONTWAIT) != 0;
            let mut n = 0usize;
            while n < len {
                if n > 0 && !wait_all && !sock.poll_readable() {
                    break;
                }
                let recv = if nonblock_recv {
                    sock.tcp_recv_nonblock(&mut kbuf[n..], false)
                } else {
                    sock.tcp_recv(&mut kbuf[n..], false)
                };
                let got = match recv {
                    Ok(v) => v,
                    Err(e) => return if n > 0 { n as isize } else { e },
                };
                if got == 0 {
                    break;
                }
                n = match n.checked_add(got) {
                    Some(v) => v,
                    None => return err(SyscallError::EINVAL),
                };
                if !wait_all {
                    break;
                }
            }
            let token = get_current_token();
            if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]).is_err() {
                return err(SyscallError::EFAULT);
            }
            if addr != 0 {
                // Linux tcp_recvmsg() leaves kaddr length at 0; recvfrom then writes
                // *addrlen = 0 and copies no sockaddr bytes.
                let r = write_empty_sockaddr_len(addrlen);
                if r != 0 {
                    return r;
                }
            }
            n as isize
        }
        crate::fs::NetSocketKind::Udp => {
            if (flags & MSG_DONTWAIT) != 0 && !sock.poll_readable() {
                return err(SyscallError::EAGAIN);
            }
            let mut kbuf = alloc::vec![0u8; len];
            let (n, packet_len, ip, port, _) = match sock.udp_recv_from(
                &mut kbuf,
                (flags & MSG_PEEK) != 0,
                (flags & MSG_DONTWAIT) != 0,
            ) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let token = get_current_token();
            if try_copy_to_user(token, buf_ptr as *mut u8, &kbuf[..n]).is_err() {
                return err(SyscallError::EFAULT);
            }
            if addr != 0 {
                let r = write_sockaddr_in_for_domain(addr, addrlen, sock.domain(), ip, port);
                if r != 0 {
                    return r;
                }
            }
            if (flags & MSG_TRUNC) != 0 {
                packet_len as isize
            } else {
                n as isize
            }
        }
        crate::fs::NetSocketKind::TcpListener => err(SyscallError::EOPNOTSUPP),
    }
}
