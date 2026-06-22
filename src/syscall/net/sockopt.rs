//! 套接字选项与地址查询系统调用。
//!
//! 本模块实现以下五个系统调用：
//! - [`syscall_getsockname`]：获取套接字本端绑定地址
//! - [`syscall_getpeername`]：获取套接字对端地址
//! - [`syscall_setsockopt`]：设置套接字选项
//! - [`syscall_getsockopt`]：读取套接字选项
//! - [`syscall_shutdown`]：关闭套接字的读写通道
//!
//! 内部辅助函数 [`write_sockopt_bytes`] 负责将选项值安全写回用户空间，
//! 并按 POSIX `getsockopt` 语义将实际选项长度写回 `optlen` 指针。

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use crate::bpf::get_prog_clone;
use crate::fs::{Ipv4SourceFilterMode, NetSocketFile, SocketPairEnd};
use crate::mm::{try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::processor::current_process;
use crate::trap::get_current_token;

use super::cbpf::ClassicBpfProgram;
use super::*;

const SOCKBUF_MAX: u32 = 212_992;
const SOCK_MIN_RCVBUF: u32 = 2_304;
const SOCK_MIN_SNDBUF: u32 = SOCK_MIN_RCVBUF * 2;
const CAP_NET_ADMIN: usize = 12;
const CAP_NET_RAW: usize = 13;
const TC_PRIO_BESTEFFORT: i32 = 0;
const TC_PRIO_INTERACTIVE: i32 = 6;
const MAX_TCP_KEEPIDLE: i32 = 32_767;
const MAX_TCP_KEEPINTVL: i32 = 32_767;
const MAX_TCP_KEEPCNT: i32 = 127;

#[repr(C)]
#[derive(Clone, Copy)]
struct Linger {
    l_onoff: i32,
    l_linger: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockTimeval {
    tv_sec: i64,
    tv_usec: i64,
}

fn is_so_rcvtimeo(optname: usize) -> bool {
    matches!(optname, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW)
}

fn is_so_sndtimeo(optname: usize) -> bool {
    matches!(optname, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW)
}

fn read_sockopt_int(optval: usize, optlen: usize) -> Result<i32, isize> {
    if optlen == 0 {
        return Ok(0);
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    if optlen >= size_of::<i32>() {
        let Some(v) = try_read_user_value::<i32>(token, optval as *const i32) else {
            return Err(err(SyscallError::EFAULT));
        };
        return Ok(v);
    }
    let Some(v) = try_read_user_value::<u8>(token, optval as *const u8) else {
        return Err(err(SyscallError::EFAULT));
    };
    Ok(v as i32)
}

fn read_sockopt_u64(optval: usize, optlen: usize) -> Result<u64, isize> {
    if optlen < size_of::<u64>() {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let Some(v) = try_read_user_value::<u64>(token, optval as *const u64) else {
        return Err(err(SyscallError::EFAULT));
    };
    Ok(v)
}

fn linux_sockbuf_value(val: i32, optname: usize) -> u32 {
    let force = matches!(optname, SO_SNDBUFFORCE | SO_RCVBUFFORCE);
    let raw = if val < 0 {
        if force { 0 } else { SOCKBUF_MAX }
    } else {
        val as u32
    };
    let capped = if force { raw } else { raw.min(SOCKBUF_MAX) };
    let capped = capped.min((i32::MAX as u32) / 2);
    let min = if matches!(optname, SO_SNDBUF | SO_SNDBUFFORCE) {
        SOCK_MIN_SNDBUF
    } else {
        SOCK_MIN_RCVBUF
    };
    capped.saturating_mul(2).max(min)
}

fn linux_rcvlowat_value(val: i32) -> i32 {
    if val < 0 { i32::MAX } else { val.max(1) }
}

fn tcp_keepalive_sockopt_value(val: i32, max: i32) -> Result<u32, isize> {
    if val < 1 || val > max {
        Err(err(SyscallError::EINVAL))
    } else {
        Ok(val as u32)
    }
}

fn timestamp_mode_for_sockopt(optname: usize, enabled: bool) -> Option<SocketTimestampMode> {
    if !enabled {
        return Some(SocketTimestampMode::Off);
    }
    match optname {
        SO_TIMESTAMP_OLD => Some(SocketTimestampMode::TimevalOld),
        SO_TIMESTAMPNS_OLD => Some(SocketTimestampMode::TimespecOld),
        SO_TIMESTAMP_NEW => Some(SocketTimestampMode::TimevalNew),
        SO_TIMESTAMPNS_NEW => Some(SocketTimestampMode::TimespecNew),
        _ => None,
    }
}

fn timestamp_mode_getsockopt(mode: SocketTimestampMode, optname: usize) -> Option<u32> {
    let enabled = match optname {
        SO_TIMESTAMP_OLD => mode == SocketTimestampMode::TimevalOld,
        SO_TIMESTAMPNS_OLD => mode == SocketTimestampMode::TimespecOld,
        SO_TIMESTAMP_NEW => mode == SocketTimestampMode::TimevalNew,
        SO_TIMESTAMPNS_NEW => mode == SocketTimestampMode::TimespecNew,
        _ => return None,
    };
    Some(enabled as u32)
}

fn has_effective_cap(cap: usize) -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    (inner.cap_effective & (1u64 << cap)) != 0
}

fn has_cap_net_admin() -> bool {
    has_effective_cap(CAP_NET_ADMIN)
}

fn require_cap_net_admin_for_sockbuf_force(optname: usize) -> Result<(), isize> {
    if !matches!(optname, SO_SNDBUFFORCE | SO_RCVBUFFORCE) || has_cap_net_admin() {
        Ok(())
    } else {
        Err(err(SyscallError::EPERM))
    }
}

pub(super) fn socket_priority_value(priority: i32) -> Result<u32, isize> {
    if (TC_PRIO_BESTEFFORT..=TC_PRIO_INTERACTIVE).contains(&priority)
        || has_effective_cap(CAP_NET_RAW)
        || has_cap_net_admin()
    {
        Ok(priority as u32)
    } else {
        Err(err(SyscallError::EPERM))
    }
}

pub(super) fn socket_mark_allowed() -> bool {
    has_effective_cap(CAP_NET_RAW) || has_cap_net_admin()
}

pub(super) fn socket_mark_value(mark: i32) -> Result<u32, isize> {
    if socket_mark_allowed() {
        Ok(mark as u32)
    } else {
        Err(err(SyscallError::EPERM))
    }
}

fn require_bound_device_rebind(already_bound: bool) -> Result<(), isize> {
    if !already_bound || has_effective_cap(CAP_NET_RAW) {
        Ok(())
    } else {
        Err(err(SyscallError::EPERM))
    }
}

fn read_linger(optval: usize, optlen: usize) -> Result<(bool, i32), isize> {
    if optlen < size_of::<Linger>() {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let Some(linger) = try_read_user_value::<Linger>(token, optval as *const Linger) else {
        return Err(err(SyscallError::EFAULT));
    };
    let sec = if linger.l_linger < 0 {
        i32::MAX
    } else {
        linger.l_linger
    };
    Ok((linger.l_onoff != 0, sec))
}

fn write_linger(optval: usize, optlen: usize, user_len: usize, on: bool, sec: i32) -> isize {
    let linger = Linger {
        l_onoff: on as i32,
        l_linger: sec,
    };
    // SAFETY: `linger` is a fully initialized C-compatible pair of i32 values.
    let bytes = unsafe {
        core::slice::from_raw_parts((&linger as *const Linger) as *const u8, size_of::<Linger>())
    };
    write_sockopt_bytes(optval, optlen, user_len, bytes)
}

fn read_socket_timeval_ms(optval: usize, optlen: usize) -> Result<Option<usize>, isize> {
    if optlen < size_of::<SockTimeval>() {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let Some(tv) = try_read_user_value::<SockTimeval>(token, optval as *const SockTimeval) else {
        return Err(err(SyscallError::EFAULT));
    };
    if tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= 1_000_000 {
        return Err(err(SyscallError::EDOM));
    }
    if tv.tv_sec == 0 && tv.tv_usec == 0 {
        return Ok(None);
    }
    let sec_ms = (tv.tv_sec as u128).saturating_mul(1_000);
    let usec_ms = ((tv.tv_usec as u128).saturating_add(999)) / 1_000;
    Ok(Some(
        sec_ms.saturating_add(usec_ms).min(usize::MAX as u128) as usize
    ))
}

fn write_socket_timeval_ms(
    optval: usize,
    optlen: usize,
    user_len: usize,
    timeout_ms: Option<usize>,
) -> isize {
    let timeout_ms = timeout_ms.unwrap_or(0);
    let tv = SockTimeval {
        tv_sec: (timeout_ms / 1_000) as i64,
        tv_usec: ((timeout_ms % 1_000) * 1_000) as i64,
    };
    // SAFETY: `tv` is a fully initialized C-compatible `__kernel_sock_timeval`.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&tv as *const SockTimeval) as *const u8,
            size_of::<SockTimeval>(),
        )
    };
    write_sockopt_bytes(optval, optlen, user_len, bytes)
}

fn read_sockopt_ifname(optval: usize, optlen: usize) -> Result<String, isize> {
    if optlen == 0 {
        return Ok(String::new());
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let len = core::cmp::min(optlen, 16);
    let token = get_current_token();
    let mut raw = [0u8; 16];
    if try_copy_from_user(token, optval as *const u8, &mut raw[..len]).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let end = raw[..len].iter().position(|&b| b == 0).unwrap_or(len);
    core::str::from_utf8(&raw[..end])
        .map(String::from)
        .map_err(|_| err(SyscallError::EINVAL))
}

fn read_packet_ring_req(optval: usize, optlen: usize, version: i32) -> Result<[u32; 7], isize> {
    let req_len = match version {
        TPACKET_V1 | TPACKET_V2 => 4 * size_of::<u32>(),
        TPACKET_V3 => 7 * size_of::<u32>(),
        _ => return Err(err(SyscallError::EINVAL)),
    };
    if optlen < req_len {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EINVAL));
    }
    let token = get_current_token();
    let mut raw = [0u8; 28];
    if try_copy_from_user(token, optval as *const u8, &mut raw[..req_len]).is_err() {
        return Err(err(SyscallError::EINVAL));
    }
    let mut fields = [0u32; 7];
    for (idx, chunk) in raw[..req_len].chunks_exact(size_of::<u32>()).enumerate() {
        fields[idx] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }
    Ok(fields)
}

fn read_packet_fanout(optval: usize, optlen: usize) -> Result<(u32, u32), isize> {
    if optlen != size_of::<i32>() && optlen != 2 * size_of::<u32>() {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut raw = [0u8; 8];
    if try_copy_from_user(token, optval as *const u8, &mut raw[..optlen]).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let fanout = u32::from_ne_bytes(raw[0..4].try_into().unwrap());
    let max_members = if optlen == 2 * size_of::<u32>() {
        u32::from_ne_bytes(raw[4..8].try_into().unwrap())
    } else {
        0
    };
    Ok((fanout, max_members))
}

fn read_packet_mreq(optval: usize, optlen: usize) -> Result<(i32, u16, u16, [u8; 8]), isize> {
    if optlen < 16 {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut raw = [0u8; 16];
    if try_copy_from_user(token, optval as *const u8, &mut raw).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let ifindex = i32::from_ne_bytes(raw[0..4].try_into().unwrap());
    let mr_type = u16::from_ne_bytes(raw[4..6].try_into().unwrap());
    let mr_alen = u16::from_ne_bytes(raw[6..8].try_into().unwrap());
    if mr_alen > 8 || optlen < 8 + mr_alen as usize {
        return Err(err(SyscallError::EINVAL));
    }
    let mut addr = [0u8; 8];
    addr.copy_from_slice(&raw[8..16]);
    Ok((ifindex, mr_type, mr_alen, addr))
}

fn read_ipv4_multicast_if(optval: usize, optlen: usize) -> Result<(i32, [u8; 4]), isize> {
    if optlen < 4 {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut raw = [0u8; 12];
    if optlen >= 12 {
        if try_copy_from_user(token, optval as *const u8, &mut raw).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        let ifindex = i32::from_ne_bytes(raw[8..12].try_into().unwrap());
        return Ok((ifindex, raw[4..8].try_into().unwrap()));
    }
    if optlen >= 8 {
        if try_copy_from_user(token, optval as *const u8, &mut raw[..8]).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        return Ok((0, raw[4..8].try_into().unwrap()));
    }
    if try_copy_from_user(token, optval as *const u8, &mut raw[..4]).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok((0, raw[..4].try_into().unwrap()))
}

fn read_ipv4_options(optval: usize, optlen: usize) -> Result<Vec<u8>, isize> {
    if optlen > 40 {
        return Err(err(SyscallError::EINVAL));
    }
    if optlen == 0 {
        return Ok(Vec::new());
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let padded_len = (optlen + 3) & !3;
    let mut options = vec![0u8; padded_len];
    if try_copy_from_user(token, optval as *const u8, &mut options[..optlen]).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok(options)
}

fn read_ip_mreqn(optval: usize, optlen: usize) -> Result<([u8; 4], i32, [u8; 4]), isize> {
    if optlen < 8 {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut raw = [0u8; 12];
    if optlen >= 12 {
        if try_copy_from_user(token, optval as *const u8, &mut raw).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        let ifindex = i32::from_ne_bytes(raw[8..12].try_into().unwrap());
        return Ok((
            raw[0..4].try_into().unwrap(),
            ifindex,
            raw[4..8].try_into().unwrap(),
        ));
    }
    if try_copy_from_user(token, optval as *const u8, &mut raw[..8]).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok((
        raw[0..4].try_into().unwrap(),
        0,
        raw[4..8].try_into().unwrap(),
    ))
}

fn read_group_req(optval: usize, optlen: usize) -> Result<([u8; 4], i32), isize> {
    const GROUP_REQ_LEN: usize = 136;
    const GROUP_ADDR_OFFSET: usize = 8;
    if optlen < GROUP_REQ_LEN {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut raw = [0u8; GROUP_REQ_LEN];
    if try_copy_from_user(token, optval as *const u8, &mut raw).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let ifindex = u32::from_ne_bytes(raw[0..4].try_into().unwrap()) as i32;
    let family = u16::from_ne_bytes(
        raw[GROUP_ADDR_OFFSET..GROUP_ADDR_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    if family != AF_INET {
        return Err(err(SyscallError::EINVAL));
    }
    let addr_offset = GROUP_ADDR_OFFSET + 4;
    Ok((
        raw[addr_offset..addr_offset + 4].try_into().unwrap(),
        ifindex,
    ))
}

fn read_ip_mreq_source(optval: usize, optlen: usize) -> Result<([u8; 4], [u8; 4], [u8; 4]), isize> {
    if optlen != 12 {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut raw = [0u8; 12];
    if try_copy_from_user(token, optval as *const u8, &mut raw).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok((
        raw[0..4].try_into().unwrap(),
        raw[4..8].try_into().unwrap(),
        raw[8..12].try_into().unwrap(),
    ))
}

fn read_ip_msfilter(
    optval: usize,
    optlen: usize,
) -> Result<([u8; 4], [u8; 4], u32, Vec<[u8; 4]>), isize> {
    const IP_MSFILTER_BASE_LEN: usize = 16;
    if optlen < IP_MSFILTER_BASE_LEN {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut head = [0u8; IP_MSFILTER_BASE_LEN];
    if try_copy_from_user(token, optval as *const u8, &mut head).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let numsrc = u32::from_ne_bytes(head[12..16].try_into().unwrap()) as usize;
    let needed = IP_MSFILTER_BASE_LEN
        .checked_add(
            numsrc
                .checked_mul(4)
                .ok_or_else(|| err(SyscallError::ENOBUFS))?,
        )
        .ok_or_else(|| err(SyscallError::ENOBUFS))?;
    if optlen < needed {
        return Err(err(SyscallError::EINVAL));
    }
    let mut sources = Vec::new();
    if numsrc > 0 {
        let mut raw_sources = vec![0u8; numsrc * 4];
        let Some(src_ptr) = optval.checked_add(IP_MSFILTER_BASE_LEN) else {
            return Err(err(SyscallError::EFAULT));
        };
        if try_copy_from_user(token, src_ptr as *const u8, &mut raw_sources).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        for chunk in raw_sources.chunks_exact(4) {
            sources.push(chunk.try_into().unwrap());
        }
    }
    Ok((
        head[0..4].try_into().unwrap(),
        head[4..8].try_into().unwrap(),
        u32::from_ne_bytes(head[8..12].try_into().unwrap()),
        sources,
    ))
}

fn read_ip_msfilter_query(
    optval: usize,
    optlen: usize,
) -> Result<([u8; 4], [u8; 4], usize), isize> {
    const IP_MSFILTER_BASE_LEN: usize = 16;
    if optlen < IP_MSFILTER_BASE_LEN {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut head = [0u8; IP_MSFILTER_BASE_LEN];
    if try_copy_from_user(token, optval as *const u8, &mut head).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    Ok((
        head[0..4].try_into().unwrap(),
        head[4..8].try_into().unwrap(),
        u32::from_ne_bytes(head[12..16].try_into().unwrap()) as usize,
    ))
}

fn read_group_source_req(optval: usize, optlen: usize) -> Result<([u8; 4], i32, [u8; 4]), isize> {
    const GROUP_SOURCE_REQ_LEN: usize = 264;
    const GROUP_ADDR_OFFSET: usize = 8;
    const SOURCE_ADDR_OFFSET: usize = 136;
    if optlen != GROUP_SOURCE_REQ_LEN {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut raw = [0u8; GROUP_SOURCE_REQ_LEN];
    if try_copy_from_user(token, optval as *const u8, &mut raw).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let group_family = u16::from_ne_bytes(
        raw[GROUP_ADDR_OFFSET..GROUP_ADDR_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    let source_family = u16::from_ne_bytes(
        raw[SOURCE_ADDR_OFFSET..SOURCE_ADDR_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    if group_family != AF_INET || source_family != AF_INET {
        return Err(err(SyscallError::EADDRNOTAVAIL));
    }
    let ifindex = u32::from_ne_bytes(raw[0..4].try_into().unwrap()) as i32;
    Ok((
        raw[GROUP_ADDR_OFFSET + 4..GROUP_ADDR_OFFSET + 8]
            .try_into()
            .unwrap(),
        ifindex,
        raw[SOURCE_ADDR_OFFSET + 4..SOURCE_ADDR_OFFSET + 8]
            .try_into()
            .unwrap(),
    ))
}

fn read_group_filter(
    optval: usize,
    optlen: usize,
) -> Result<([u8; 4], i32, u32, Vec<[u8; 4]>), isize> {
    const GROUP_FILTER_BASE_LEN: usize = 144;
    const GROUP_ADDR_OFFSET: usize = 8;
    const FMODE_OFFSET: usize = 136;
    const NUMSRC_OFFSET: usize = 140;
    if optlen < GROUP_FILTER_BASE_LEN {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut head = [0u8; GROUP_FILTER_BASE_LEN];
    if try_copy_from_user(token, optval as *const u8, &mut head).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let family = u16::from_ne_bytes(
        head[GROUP_ADDR_OFFSET..GROUP_ADDR_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    if family != AF_INET {
        return Err(err(SyscallError::EADDRNOTAVAIL));
    }
    let numsrc =
        u32::from_ne_bytes(head[NUMSRC_OFFSET..NUMSRC_OFFSET + 4].try_into().unwrap()) as usize;
    let needed = GROUP_FILTER_BASE_LEN
        .checked_add(
            numsrc
                .checked_mul(128)
                .ok_or_else(|| err(SyscallError::ENOBUFS))?,
        )
        .ok_or_else(|| err(SyscallError::ENOBUFS))?;
    if optlen < needed {
        return Err(err(SyscallError::EINVAL));
    }
    let mut sources = Vec::new();
    for idx in 0..numsrc {
        let Some(src_ptr) = optval
            .checked_add(GROUP_FILTER_BASE_LEN)
            .and_then(|base| base.checked_add(idx * 128))
        else {
            return Err(err(SyscallError::EFAULT));
        };
        let mut storage = [0u8; 128];
        if try_copy_from_user(token, src_ptr as *const u8, &mut storage).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        let family = u16::from_ne_bytes(storage[0..2].try_into().unwrap());
        if family != AF_INET {
            return Err(err(SyscallError::EADDRNOTAVAIL));
        }
        sources.push(storage[4..8].try_into().unwrap());
    }
    Ok((
        head[GROUP_ADDR_OFFSET + 4..GROUP_ADDR_OFFSET + 8]
            .try_into()
            .unwrap(),
        u32::from_ne_bytes(head[0..4].try_into().unwrap()) as i32,
        u32::from_ne_bytes(head[FMODE_OFFSET..FMODE_OFFSET + 4].try_into().unwrap()),
        sources,
    ))
}

fn read_group_filter_query(optval: usize, optlen: usize) -> Result<([u8; 4], i32, usize), isize> {
    const GROUP_FILTER_BASE_LEN: usize = 144;
    const GROUP_ADDR_OFFSET: usize = 8;
    const NUMSRC_OFFSET: usize = 140;
    if optlen < GROUP_FILTER_BASE_LEN {
        return Err(err(SyscallError::EINVAL));
    }
    if optval == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut head = [0u8; GROUP_FILTER_BASE_LEN];
    if try_copy_from_user(token, optval as *const u8, &mut head).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let family = u16::from_ne_bytes(
        head[GROUP_ADDR_OFFSET..GROUP_ADDR_OFFSET + 2]
            .try_into()
            .unwrap(),
    );
    if family != AF_INET {
        return Err(err(SyscallError::EADDRNOTAVAIL));
    }
    Ok((
        head[GROUP_ADDR_OFFSET + 4..GROUP_ADDR_OFFSET + 8]
            .try_into()
            .unwrap(),
        u32::from_ne_bytes(head[0..4].try_into().unwrap()) as i32,
        u32::from_ne_bytes(head[NUMSRC_OFFSET..NUMSRC_OFFSET + 4].try_into().unwrap()) as usize,
    ))
}

fn ipv4_source_filter_mode(fmode: u32) -> Result<Ipv4SourceFilterMode, isize> {
    match fmode {
        MCAST_EXCLUDE => Ok(Ipv4SourceFilterMode::Exclude),
        MCAST_INCLUDE => Ok(Ipv4SourceFilterMode::Include),
        _ => Err(err(SyscallError::EINVAL)),
    }
}

fn raw_ipv4_source_filter_mode(fmode: u32) -> Result<RawIpv4SourceFilterMode, isize> {
    match fmode {
        MCAST_EXCLUDE => Ok(RawIpv4SourceFilterMode::Exclude),
        MCAST_INCLUDE => Ok(RawIpv4SourceFilterMode::Include),
        _ => Err(err(SyscallError::EINVAL)),
    }
}

fn ipv4_source_filter_mode_bits(mode: Ipv4SourceFilterMode) -> u32 {
    match mode {
        Ipv4SourceFilterMode::Exclude => MCAST_EXCLUDE,
        Ipv4SourceFilterMode::Include => MCAST_INCLUDE,
    }
}

fn raw_ipv4_source_filter_mode_bits(mode: RawIpv4SourceFilterMode) -> u32 {
    match mode {
        RawIpv4SourceFilterMode::Exclude => MCAST_EXCLUDE,
        RawIpv4SourceFilterMode::Include => MCAST_INCLUDE,
    }
}

fn packet_membership(
    packet_sock: &PacketSocketFile,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    let (ifindex, mr_type, mr_alen, addr) = match read_packet_mreq(optval, optlen) {
        Ok(req) => req,
        Err(e) => return e,
    };
    match optname {
        PACKET_ADD_MEMBERSHIP => packet_sock.add_membership(ifindex, mr_type, mr_alen, addr),
        PACKET_DROP_MEMBERSHIP => packet_sock.drop_membership(ifindex, mr_type, mr_alen, addr),
        _ => err(SyscallError::EINVAL),
    }
}

fn setsockopt_netlink(
    sock: &NetlinkSocketFile,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    match level {
        SOL_NETLINK => match optname {
            NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP => {
                if optlen < size_of::<i32>() {
                    return err(SyscallError::EINVAL);
                }
                let group = match read_sockopt_int(optval, optlen) {
                    Ok(group) => group,
                    Err(e) => return e,
                };
                sock.set_membership(group, optname == NETLINK_ADD_MEMBERSHIP)
            }
            NETLINK_PKTINFO
            | NETLINK_BROADCAST_ERROR
            | NETLINK_NO_ENOBUFS
            | NETLINK_LISTEN_ALL_NSID
            | NETLINK_CAP_ACK
            | NETLINK_EXT_ACK
            | NETLINK_GET_STRICT_CHK => {
                if optlen < size_of::<i32>() {
                    return err(SyscallError::EINVAL);
                }
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_netlink_flag(optname, val != 0)
            }
            _ => err(SyscallError::ENOPROTOOPT),
        },
        SOL_SOCKET => match optname {
            opt if is_so_rcvtimeo(opt) => {
                let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_rcvtimeo_ms(timeout_ms);
                0
            }
            opt if is_so_sndtimeo(opt) => {
                let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_sndtimeo_ms(timeout_ms);
                0
            }
            SO_LINGER => {
                let (on, sec) = match read_linger(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_linger(on, sec);
                0
            }
            SO_SNDBUF | SO_SNDBUFFORCE | SO_RCVBUF | SO_RCVBUFFORCE => {
                if optlen < size_of::<i32>() {
                    return err(SyscallError::EINVAL);
                }
                let raw = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if let Err(e) = require_cap_net_admin_for_sockbuf_force(optname) {
                    return e;
                }
                let v = linux_sockbuf_value(raw, optname);
                match optname {
                    SO_SNDBUF | SO_SNDBUFFORCE => sock.set_sockbuf(Some(v), None),
                    SO_RCVBUF | SO_RCVBUFFORCE => sock.set_sockbuf(None, Some(v)),
                    _ => {}
                }
                0
            }
            SO_REUSEADDR | SO_DONTROUTE | SO_BROADCAST | SO_KEEPALIVE | SO_OOBINLINE
            | SO_RCVLOWAT | SO_BSDCOMPAT | SO_REUSEPORT => {
                if optlen < size_of::<i32>() {
                    return err(SyscallError::EINVAL);
                }
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match optname {
                    SO_REUSEADDR => sock.set_reuseaddr(val != 0),
                    SO_DONTROUTE => sock.set_dontroute(val != 0),
                    SO_BROADCAST => sock.set_broadcast(val != 0),
                    SO_KEEPALIVE => sock.set_keepalive(val != 0),
                    SO_OOBINLINE => sock.set_oobinline(val != 0),
                    SO_RCVLOWAT => sock.set_rcvlowat(linux_rcvlowat_value(val)),
                    SO_BSDCOMPAT => {}
                    SO_REUSEPORT => {
                        if val != 0 {
                            return err(SyscallError::EOPNOTSUPP);
                        }
                    }
                    _ => {}
                }
                0
            }
            SO_SNDLOWAT => err(SyscallError::ENOPROTOOPT),
            _ => err(SyscallError::ENOPROTOOPT),
        },
        _ => err(SyscallError::ENOPROTOOPT),
    }
}

fn getsockopt_netlink(
    sock: &NetlinkSocketFile,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
    user_len: usize,
) -> isize {
    if level == SOL_SOCKET && optname == SO_LINGER {
        let (on, sec) = sock.linger();
        return write_linger(optval, optlen, user_len, on, sec);
    }
    if level == SOL_SOCKET && is_so_rcvtimeo(optname) {
        return write_socket_timeval_ms(optval, optlen, user_len, sock.rcvtimeo_ms());
    }
    if level == SOL_SOCKET && is_so_sndtimeo(optname) {
        return write_socket_timeval_ms(optval, optlen, user_len, sock.sndtimeo_ms());
    }
    let val: u32 = match level {
        SOL_SOCKET => match optname {
            SO_ERROR => sock.take_socket_error(),
            SO_TYPE => sock.socket_type() as u32,
            SO_ACCEPTCONN => 0,
            SO_PROTOCOL => 0,
            SO_DOMAIN => AF_NETLINK as u32,
            SO_BPF_EXTENSIONS => 0,
            SO_SNDBUF => sock.sockbuf().0,
            SO_RCVBUF => sock.sockbuf().1,
            SO_REUSEADDR => sock.reuseaddr() as u32,
            SO_DONTROUTE => sock.dontroute() as u32,
            SO_BROADCAST => sock.broadcast() as u32,
            SO_KEEPALIVE => sock.keepalive() as u32,
            SO_OOBINLINE => sock.oobinline() as u32,
            SO_REUSEPORT => 0,
            SO_RCVLOWAT => sock.rcvlowat() as u32,
            SO_SNDLOWAT => 1,
            SO_BSDCOMPAT => 0,
            _ => return err(SyscallError::ENOPROTOOPT),
        },
        SOL_NETLINK => match optname {
            NETLINK_PKTINFO
            | NETLINK_BROADCAST_ERROR
            | NETLINK_NO_ENOBUFS
            | NETLINK_LISTEN_ALL_NSID
            | NETLINK_CAP_ACK
            | NETLINK_EXT_ACK
            | NETLINK_GET_STRICT_CHK => sock.netlink_flag(optname) as u32,
            _ => return err(SyscallError::ENOPROTOOPT),
        },
        _ => return err(SyscallError::ENOPROTOOPT),
    };
    write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes())
}

/// 获取套接字本端绑定的地址（`getsockname(2)`）。
///
/// 按以下顺序分派到各套接字类型：
/// 1. Unix 域套接字 —— 返回已绑定的路径（若未绑定则返回空地址）
/// 2. SocketPair 端点 —— 匿名对，无绑定路径，始终写入空地址
/// 3. Netlink 套接字 —— 返回内核侧本地 `sockaddr_nl`
/// 4. TCP/UDP 套接字 —— 依次尝试 TCP 已连接端点、TCP 仅监听端点、UDP 端点
///
/// # 参数
/// - `fd`：套接字文件描述符
/// - `addr`：用户空间 `sockaddr` 缓冲区指针（不可为 null）
/// - `addrlen`：指向缓冲区长度的用户空间指针（不可为 null）
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_getsockname(fd: usize, addr: usize, addrlen: usize) -> isize {
    if addr == 0 || addrlen == 0 {
        return err(SyscallError::EFAULT);
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let bound = unix_sock.bound_addr();
        return write_sockaddr_un(addr, addrlen, bound.as_ref());
    }
    // SocketPair 是匿名对，没有绑定路径，传 None 写入零长地址
    if file.as_any().downcast_ref::<SocketPairEnd>().is_some() {
        return write_sockaddr_un(addr, addrlen, None);
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let sa = netlink_sock.local_addr();
        return write_sockaddr_nl(addr, addrlen, &sa);
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        return write_sockaddr_in(addr, addrlen, raw_sock.local_addr_v4(), 0);
    }
    if let Some(packet_sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        let sa = packet_sock.local_addr_ll();
        return write_sockaddr_ll(addr, addrlen, &sa);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    // 已建立连接的 TCP：从四元组中取本端 IP 和端口
    if let Some((lip, lport, _rip, _rport)) = sock.tcp_endpoints() {
        return write_sockaddr_in_for_domain(addr, addrlen, sock.domain(), lip, lport);
    }
    // 仅监听（未连接）的 TCP：使用本地端点
    if let Some((lip, lport)) = sock.tcp_local_endpoint() {
        return write_sockaddr_in_for_domain(addr, addrlen, sock.domain(), lip, lport);
    }
    if let Some((ip, port)) = sock.udp_endpoint() {
        return write_sockaddr_in_for_domain(addr, addrlen, sock.domain(), ip, port);
    }
    err(SyscallError::ENOTCONN)
}

/// 获取套接字对端（远端）地址（`getpeername(2)`）。
///
/// 按以下顺序分派到各套接字类型：
/// 1. Unix 域套接字 —— 返回对端绑定路径；若未连接则返回 `ENOTCONN`
/// 2. SocketPair 端点 —— 匿名对，写入空地址（对端同样无路径）
/// 3. Netlink 套接字 —— 返回 connect(2) 记录的默认对端，未连接则 `ENOTCONN`
/// 4. TCP/UDP 套接字 —— 从四元组或 UDP peer 中取远端地址
///
/// # 参数
/// - `fd`：套接字文件描述符
/// - `addr`：用户空间 `sockaddr` 缓冲区指针（不可为 null）
/// - `addrlen`：指向缓冲区长度的用户空间指针（不可为 null）
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_getpeername(fd: usize, addr: usize, addrlen: usize) -> isize {
    if addr == 0 || addrlen == 0 {
        return err(SyscallError::EFAULT);
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let peer = unix_sock.peer_addr();
        let Some(peer) = peer else {
            return err(SyscallError::ENOTCONN);
        };
        return write_sockaddr_un(addr, addrlen, Some(&peer));
    }
    // SocketPair 匿名对：对端同样无路径，写入空地址
    if file.as_any().downcast_ref::<SocketPairEnd>().is_some() {
        return write_sockaddr_un(addr, addrlen, None);
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let Some(peer) = netlink_sock.peer_addr() else {
            return err(SyscallError::ENOTCONN);
        };
        return write_sockaddr_nl(addr, addrlen, &peer);
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        let Some(ip) = raw_sock.remote_addr_v4() else {
            return err(SyscallError::ENOTCONN);
        };
        return write_sockaddr_in(addr, addrlen, ip, 0);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    // 已连接的 TCP：SYN-SENT 期间按 Linux 返回 ENOTCONN，不提前暴露 remote endpoint。
    if let Some((rip, rport)) = sock.tcp_peer_endpoint() {
        return write_sockaddr_in_for_domain(addr, addrlen, sock.domain(), rip, rport);
    }
    if let Some((rip, rport)) = sock.udp_peer() {
        return write_sockaddr_in_for_domain(addr, addrlen, sock.domain(), rip, rport);
    }
    err(SyscallError::ENOTCONN)
}

/// 设置套接字选项（`setsockopt(2)`）。
///
/// 支持以下选项层级与名称：
/// - `SOL_SOCKET / SO_ATTACH_BPF`：将 eBPF 程序附加到套接字
/// - `SOL_SOCKET / SO_REUSEADDR`：记录并由 AF_INET TCP/UDP bind 冲突判定消费
/// - `SOL_SOCKET / SO_OOBINLINE`：记录并回读兼容状态
/// - `SOL_SOCKET / SO_KEEPALIVE`：记录状态，AF_INET TCP 同步到底层 keepalive 定时器
/// - `SOL_SOCKET / SO_DONTROUTE`：记录状态，并由 UDP/RAW IPv4 发送路径消费
/// - `SOL_SOCKET / SO_SNDBUF | SO_SNDBUFFORCE`：设置发送缓冲区大小
/// - `SOL_SOCKET / SO_RCVBUF | SO_RCVBUFFORCE`：设置接收缓冲区大小
/// - `SOL_SOCKET / SO_PRIORITY`：记录 socket 优先级
/// - `SOL_PACKET / PACKET_*`：记录或校验 AF_PACKET fanout/ring 控制面配置
/// - `SOL_TCP / TCP_NODELAY | TCP_CORK | TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT`：
///   `TCP_NODELAY` 同步 Nagle 控制，`TCP_CORK` 接入 pending buffer，keepalive 三元参数
///   同步到底层 TCP keepalive/timeout 近似实现
/// - `SOL_IP / MCAST_JOIN_GROUP`：加入组播组
/// - `SOL_IP / MCAST_LEAVE_GROUP`：离开组播组
///
/// # 参数
/// - `fd`：套接字文件描述符
/// - `level`：选项层级（`SOL_SOCKET`、`SOL_IP` 等）
/// - `optname`：选项名称
/// - `optval`：指向选项值的用户空间指针
/// - `optlen`：选项值的字节长度
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_setsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if level == SOL_SOCKET && optname == SO_ATTACH_BPF {
        if !is_socket_file(file.as_ref()) {
            return err(SyscallError::ENOTSOCK);
        }
        // SO_ATTACH_BPF 的语义与普通 sockopt 不同：
        // optval 指向的是一个 **eBPF 程序的文件描述符**（u32），而非程序本身的指针。
        // 需要先从用户空间读出该 fd 整数，再通过 get_prog_clone 解析为内核 BPF 程序句柄。
        if optlen != size_of::<u32>() {
            return err(SyscallError::EINVAL);
        }
        if optval == 0 {
            return err(SyscallError::EFAULT);
        }
        let token = get_current_token();
        // 读取用户空间传入的 BPF 程序 fd 整数
        let Some(prog_fd) = try_read_user_value::<u32>(token, optval as *const u32) else {
            return err(SyscallError::EFAULT);
        };
        // 通过 fd 取出对应的 eBPF 程序克隆句柄
        let Some(prog) = get_prog_clone(prog_fd as usize) else {
            return err(SyscallError::EBADF);
        };
        if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
            return sock.attach_bpf(prog);
        }
        if let Some(sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
            return sock.attach_bpf(prog);
        }
        if let Some(sock) = file.as_any().downcast_ref::<RawSocketFile>() {
            return sock.attach_bpf(prog);
        }
        if let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() {
            return sock.attach_bpf(prog);
        }
        if let Some(sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
            return sock.attach_bpf(prog);
        }
        return err(SyscallError::ENOPROTOOPT);
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        return setsockopt_netlink(netlink_sock, level, optname, optval, optlen);
    }
    if let Some(vsock) = file.as_any().downcast_ref::<VsockSocketFile>() {
        if level == AF_VSOCK as usize || level == SOL_VSOCK {
            return match optname {
                SO_VM_SOCKETS_BUFFER_SIZE => {
                    let value = match read_sockopt_u64(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    vsock.set_buffer_size(value);
                    0
                }
                SO_VM_SOCKETS_BUFFER_MIN_SIZE => {
                    let value = match read_sockopt_u64(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    vsock.set_buffer_min_size(value);
                    0
                }
                SO_VM_SOCKETS_BUFFER_MAX_SIZE => {
                    let value = match read_sockopt_u64(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    vsock.set_buffer_max_size(value);
                    0
                }
                SO_VM_SOCKETS_CONNECT_TIMEOUT_OLD | SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW => {
                    let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    vsock.set_connect_timeout_ms(timeout_ms);
                    0
                }
                _ => err(SyscallError::ENOPROTOOPT),
            };
        }
        return err(SyscallError::EOPNOTSUPP);
    }
    if let Some(packet_sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        if level == SOL_SOCKET {
            return match optname {
                SO_BINDTODEVICE => {
                    let name = match read_sockopt_ifname(optval, optlen) {
                        Ok(name) => name,
                        Err(e) => return e,
                    };
                    if let Err(e) =
                        require_bound_device_rebind(packet_sock.bound_device_name().is_some())
                    {
                        return e;
                    }
                    packet_sock.bind_to_device_name(&name)
                }
                SO_ATTACH_FILTER => {
                    let filter = match ClassicBpfProgram::from_sock_fprog_user(optval, optlen) {
                        Ok(filter) => filter,
                        Err(e) => return e,
                    };
                    packet_sock.attach_filter(filter)
                }
                SO_DETACH_FILTER => packet_sock.detach_filter(),
                SO_LOCK_FILTER => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_filter_locked(val != 0)
                }
                SO_DONTROUTE => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_dontroute(val != 0);
                    0
                }
                SO_REUSEADDR | SO_OOBINLINE | SO_BROADCAST | SO_KEEPALIVE | SO_RCVLOWAT
                | SO_BSDCOMPAT | SO_REUSEPORT | SO_TIMESTAMP_OLD | SO_TIMESTAMPNS_OLD
                | SO_TIMESTAMP_NEW | SO_TIMESTAMPNS_NEW => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    match optname {
                        SO_REUSEADDR => packet_sock.set_reuseaddr(val != 0),
                        SO_OOBINLINE => packet_sock.set_oobinline(val != 0),
                        SO_BROADCAST => packet_sock.set_broadcast(val != 0),
                        SO_KEEPALIVE => packet_sock.set_keepalive(val != 0),
                        SO_RCVLOWAT => packet_sock.set_rcvlowat(linux_rcvlowat_value(val)),
                        SO_TIMESTAMP_OLD | SO_TIMESTAMPNS_OLD | SO_TIMESTAMP_NEW
                        | SO_TIMESTAMPNS_NEW => {
                            let Some(mode) = timestamp_mode_for_sockopt(optname, val != 0) else {
                                return err(SyscallError::ENOPROTOOPT);
                            };
                            packet_sock.set_timestamp_mode(mode);
                        }
                        SO_BSDCOMPAT => {}
                        SO_REUSEPORT => {
                            if val != 0 {
                                return err(SyscallError::EOPNOTSUPP);
                            }
                        }
                        _ => {}
                    }
                    0
                }
                SO_LINGER => {
                    let (on, sec) = match read_linger(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_linger(on, sec);
                    0
                }
                opt if is_so_rcvtimeo(opt) => {
                    let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_rcvtimeo_ms(timeout_ms);
                    0
                }
                opt if is_so_sndtimeo(opt) => {
                    let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_sndtimeo_ms(timeout_ms);
                    0
                }
                SO_SNDLOWAT => err(SyscallError::ENOPROTOOPT),
                SO_SNDBUF | SO_SNDBUFFORCE | SO_RCVBUF | SO_RCVBUFFORCE => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = require_cap_net_admin_for_sockbuf_force(optname) {
                        return e;
                    }
                    let v = linux_sockbuf_value(val, optname);
                    if matches!(optname, SO_SNDBUF | SO_SNDBUFFORCE) {
                        packet_sock.set_sockbuf(Some(v), None);
                    } else {
                        packet_sock.set_sockbuf(None, Some(v));
                    }
                    0
                }
                SO_PRIORITY => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let val = match socket_priority_value(val) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_priority(val);
                    0
                }
                SO_MARK => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let val = match socket_mark_value(val) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_mark(val);
                    0
                }
                SO_RCVMARK => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_rcvmark(val != 0);
                    0
                }
                SO_RCVPRIORITY => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_rcvpriority(val != 0);
                    0
                }
                _ => err(SyscallError::ENOPROTOOPT),
            };
        }
        if level == SOL_PACKET {
            return match optname {
                PACKET_ADD_MEMBERSHIP | PACKET_DROP_MEMBERSHIP => {
                    packet_membership(packet_sock, optname, optval, optlen)
                }
                PACKET_VERSION => {
                    if optlen != size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_packet_version(val)
                }
                PACKET_RESERVE => {
                    if optlen != size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_packet_reserve(val)
                }
                PACKET_VNET_HDR | PACKET_VNET_HDR_SZ => {
                    if packet_sock.socket_type() != SOCK_RAW {
                        return err(SyscallError::EINVAL);
                    }
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if optname == PACKET_VNET_HDR_SZ && !matches!(val, 0 | 10 | 12) {
                        return err(SyscallError::EINVAL);
                    }
                    if val == 0 {
                        packet_sock.set_packet_vnet_hdr(false)
                    } else {
                        return err(SyscallError::EOPNOTSUPP);
                    }
                }
                PACKET_COPY_THRESH => {
                    if optlen != size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val != 0 {
                        // Linux uses this only to decide whether to copy packets
                        // when packet_mmap rings are congested. That slow-path is
                        // not modeled here, so non-zero thresholds would be
                        // state-only and misleading.
                        return err(SyscallError::EOPNOTSUPP);
                    }
                    packet_sock.set_packet_copy_thresh(val);
                    0
                }
                PACKET_AUXDATA | PACKET_ORIGDEV => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if optname == PACKET_AUXDATA {
                        packet_sock.set_packet_auxdata(val != 0);
                    } else {
                        packet_sock.set_packet_origdev(val != 0);
                    }
                    0
                }
                PACKET_QDISC_BYPASS => {
                    if optlen != size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if val != 0 {
                        // No qdisc layer exists in this network stack, so there is
                        // no alternate transmit path for this flag to select.
                        return err(SyscallError::EOPNOTSUPP);
                    }
                    packet_sock.set_packet_qdisc_bypass(val != 0);
                    0
                }
                PACKET_IGNORE_OUTGOING => {
                    if optlen != size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if !(0..=1).contains(&val) {
                        return err(SyscallError::EINVAL);
                    }
                    packet_sock.set_packet_ignore_outgoing(val != 0)
                }
                PACKET_RX_RING => {
                    let fields =
                        match read_packet_ring_req(optval, optlen, packet_sock.packet_version()) {
                            Ok(fields) => fields,
                            Err(e) => return e,
                        };
                    // TPACKET_V3: tp_sizeof_priv (fields[5]) must fit inside a block.
                    // Reject the CVE-2017-1000111 oversized value where
                    // tp_block_size < tp_sizeof_priv (Linux packet_set_ring -> EINVAL).
                    if packet_sock.packet_version() == TPACKET_V3
                        && fields[0] != 0
                        && fields[5] >= fields[0]
                    {
                        return err(SyscallError::EINVAL);
                    }
                    packet_sock.set_packet_ring(
                        true, fields[0], fields[1], fields[2], fields[3], fields[6],
                    )
                }
                PACKET_TX_RING => {
                    let fields =
                        match read_packet_ring_req(optval, optlen, packet_sock.packet_version()) {
                            Ok(fields) => fields,
                            Err(e) => return e,
                        };
                    if fields[0] == 0 && fields[1] == 0 && fields[2] == 0 && fields[3] == 0 {
                        return 0;
                    }
                    err(SyscallError::EOPNOTSUPP)
                }
                PACKET_FANOUT => {
                    let (val, max_members) = match read_packet_fanout(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    packet_sock.set_fanout(val, max_members)
                }
                _ => err(SyscallError::ENOPROTOOPT),
            };
        }
        return err(SyscallError::ENOPROTOOPT);
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        if level == SOL_SOCKET {
            return match optname {
                SO_BINDTODEVICE => {
                    let name = match read_sockopt_ifname(optval, optlen) {
                        Ok(name) => name,
                        Err(e) => return e,
                    };
                    if let Err(e) =
                        require_bound_device_rebind(raw_sock.bound_device_name().is_some())
                    {
                        return e;
                    }
                    raw_sock.bind_to_device_name(&name)
                }
                SO_ATTACH_FILTER => {
                    let filter = match ClassicBpfProgram::from_sock_fprog_user(optval, optlen) {
                        Ok(filter) => filter,
                        Err(e) => return e,
                    };
                    raw_sock.attach_filter(filter)
                }
                SO_DETACH_FILTER => raw_sock.detach_filter(),
                SO_LOCK_FILTER => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_filter_locked(val != 0)
                }
                SO_DONTROUTE => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_dontroute(val != 0);
                    0
                }
                SO_REUSEADDR | SO_REUSEPORT | SO_OOBINLINE | SO_BROADCAST | SO_KEEPALIVE
                | SO_RCVLOWAT | SO_BSDCOMPAT | SO_TIMESTAMP_OLD | SO_TIMESTAMPNS_OLD
                | SO_TIMESTAMP_NEW | SO_TIMESTAMPNS_NEW => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    match optname {
                        SO_REUSEADDR => raw_sock.set_reuseaddr(val != 0),
                        SO_REUSEPORT => {
                            if val != 0 {
                                return err(SyscallError::EOPNOTSUPP);
                            }
                        }
                        SO_OOBINLINE => raw_sock.set_oobinline(val != 0),
                        SO_BROADCAST => raw_sock.set_broadcast(val != 0),
                        SO_KEEPALIVE => raw_sock.set_keepalive(val != 0),
                        SO_RCVLOWAT => raw_sock.set_rcvlowat(linux_rcvlowat_value(val)),
                        SO_TIMESTAMP_OLD | SO_TIMESTAMPNS_OLD | SO_TIMESTAMP_NEW
                        | SO_TIMESTAMPNS_NEW => {
                            let Some(mode) = timestamp_mode_for_sockopt(optname, val != 0) else {
                                return err(SyscallError::ENOPROTOOPT);
                            };
                            raw_sock.set_timestamp_mode(mode);
                        }
                        SO_BSDCOMPAT => {}
                        _ => {}
                    }
                    0
                }
                SO_LINGER => {
                    let (on, sec) = match read_linger(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_linger(on, sec);
                    0
                }
                opt if is_so_rcvtimeo(opt) => {
                    let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_rcvtimeo_ms(timeout_ms);
                    0
                }
                opt if is_so_sndtimeo(opt) => {
                    let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_sndtimeo_ms(timeout_ms);
                    0
                }
                SO_SNDLOWAT => err(SyscallError::ENOPROTOOPT),
                SO_SNDBUF | SO_SNDBUFFORCE | SO_RCVBUF | SO_RCVBUFFORCE => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if let Err(e) = require_cap_net_admin_for_sockbuf_force(optname) {
                        return e;
                    }
                    let v = linux_sockbuf_value(val, optname);
                    if matches!(optname, SO_SNDBUF | SO_SNDBUFFORCE) {
                        raw_sock.set_sockbuf(Some(v), None);
                    } else {
                        raw_sock.set_sockbuf(None, Some(v));
                    }
                    0
                }
                SO_PRIORITY => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let val = match socket_priority_value(val) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_priority(val);
                    0
                }
                SO_MARK => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let val = match socket_mark_value(val) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_mark(val);
                    0
                }
                SO_RCVMARK => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_rcvmark(val != 0);
                    0
                }
                SO_RCVPRIORITY => {
                    if optlen < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_rcvpriority(val != 0);
                    0
                }
                _ => err(SyscallError::ENOPROTOOPT),
            };
        }
        if level == SOL_IP {
            return match optname {
                IP_OPTIONS => {
                    let options = match read_ipv4_options(optval, optlen) {
                        Ok(options) => options,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_options(options)
                }
                IP_MULTICAST_IF => {
                    let (ifindex, addr) = match read_ipv4_multicast_if(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_multicast_if(ifindex, addr)
                }
                IP_MULTICAST_TTL => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if optlen < 1 {
                        err(SyscallError::EINVAL)
                    } else {
                        let val = if val == -1 { 1 } else { val };
                        if !(0..=255).contains(&val) {
                            err(SyscallError::EINVAL)
                        } else {
                            raw_sock.set_ipv4_multicast_ttl(val as u8);
                            0
                        }
                    }
                }
                IP_MULTICAST_LOOP => {
                    if optlen < 1 {
                        return err(SyscallError::EINVAL);
                    }
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_multicast_loop(val != 0);
                    0
                }
                IP_ADD_MEMBERSHIP => {
                    let (group, ifindex, ifaddr) = match read_ip_mreqn(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.join_ipv4_multicast(group, ifindex, ifaddr)
                }
                IP_DROP_MEMBERSHIP => {
                    let (group, ifindex, ifaddr) = match read_ip_mreqn(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.leave_ipv4_multicast(group, ifindex, ifaddr)
                }
                IP_BLOCK_SOURCE | IP_UNBLOCK_SOURCE => {
                    let (group, ifaddr, source) = match read_ip_mreq_source(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if optname == IP_BLOCK_SOURCE {
                        raw_sock.block_ipv4_multicast_source(group, 0, ifaddr, source)
                    } else {
                        raw_sock.unblock_ipv4_multicast_source(group, 0, ifaddr, source)
                    }
                }
                IP_ADD_SOURCE_MEMBERSHIP | IP_DROP_SOURCE_MEMBERSHIP => {
                    let (group, ifaddr, source) = match read_ip_mreq_source(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if optname == IP_ADD_SOURCE_MEMBERSHIP {
                        raw_sock.join_ipv4_multicast_source(group, 0, ifaddr, source)
                    } else {
                        raw_sock.leave_ipv4_multicast_source(group, 0, ifaddr, source)
                    }
                }
                IP_MSFILTER => {
                    let (group, ifaddr, fmode, sources) = match read_ip_msfilter(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let mode = match raw_ipv4_source_filter_mode(fmode) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_multicast_source_filter(group, 0, ifaddr, mode, sources)
                }
                MCAST_JOIN_GROUP => {
                    let (group, ifindex) = match read_group_req(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.join_ipv4_multicast(group, ifindex, [0; 4])
                }
                MCAST_LEAVE_GROUP => {
                    let (group, ifindex) = match read_group_req(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.leave_ipv4_multicast(group, ifindex, [0; 4])
                }
                MCAST_JOIN_SOURCE_GROUP | MCAST_LEAVE_SOURCE_GROUP => {
                    let (group, ifindex, source) = match read_group_source_req(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if optname == MCAST_JOIN_SOURCE_GROUP {
                        raw_sock.join_ipv4_multicast_source(group, ifindex, [0; 4], source)
                    } else {
                        raw_sock.leave_ipv4_multicast_source(group, ifindex, [0; 4], source)
                    }
                }
                MCAST_BLOCK_SOURCE | MCAST_UNBLOCK_SOURCE => {
                    let (group, ifindex, source) = match read_group_source_req(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if optname == MCAST_BLOCK_SOURCE {
                        raw_sock.block_ipv4_multicast_source(group, ifindex, [0; 4], source)
                    } else {
                        raw_sock.unblock_ipv4_multicast_source(group, ifindex, [0; 4], source)
                    }
                }
                MCAST_MSFILTER => {
                    let (group, ifindex, fmode, sources) = match read_group_filter(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let mode = match raw_ipv4_source_filter_mode(fmode) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_multicast_source_filter(group, ifindex, [0; 4], mode, sources)
                }
                IP_HDRINCL => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ip_hdrincl(val != 0);
                    0
                }
                IP_RECVERR => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_recverr(val != 0);
                    0
                }
                IP_PKTINFO => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_pktinfo(val != 0);
                    0
                }
                IP_RECVTTL => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_recvttl(val != 0);
                    0
                }
                IP_RECVTOS => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_recvtos(val != 0);
                    0
                }
                IP_TOS => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    raw_sock.set_ipv4_tos(val);
                    0
                }
                IP_TTL => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if optlen < 1 || (val != -1 && !(1..=255).contains(&val)) {
                        err(SyscallError::EINVAL)
                    } else {
                        raw_sock.set_ipv4_ttl(if val == -1 { 64 } else { val });
                        0
                    }
                }
                IP_MTU_DISCOVER => {
                    let val = match read_sockopt_int(optval, optlen) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if !(IP_PMTUDISC_DONT..=IP_PMTUDISC_OMIT).contains(&val) {
                        err(SyscallError::EINVAL)
                    } else {
                        raw_sock.set_ipv4_mtu_discover(val);
                        0
                    }
                }
                _ => err(SyscallError::ENOPROTOOPT),
            };
        }
        return err(SyscallError::ENOPROTOOPT);
    }
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if level != SOL_SOCKET {
            return err(SyscallError::ENOPROTOOPT);
        }
        return match optname {
            SO_ATTACH_FILTER => {
                let filter = match ClassicBpfProgram::from_sock_fprog_user(optval, optlen) {
                    Ok(filter) => filter,
                    Err(e) => return e,
                };
                unix_sock.attach_filter(filter)
            }
            SO_DETACH_FILTER => unix_sock.detach_filter(),
            SO_LOCK_FILTER => {
                if optlen < size_of::<i32>() {
                    return err(SyscallError::EINVAL);
                }
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                unix_sock.set_filter_locked(val != 0)
            }
            SO_LINGER => {
                let (on, sec) = match read_linger(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                unix_sock.set_linger(on, sec);
                0
            }
            opt if is_so_rcvtimeo(opt) => {
                let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                unix_sock.set_rcvtimeo_ms(timeout_ms);
                0
            }
            opt if is_so_sndtimeo(opt) => {
                let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                unix_sock.set_sndtimeo_ms(timeout_ms);
                0
            }
            SO_REUSEADDR | SO_DONTROUTE | SO_BROADCAST | SO_KEEPALIVE | SO_OOBINLINE
            | SO_RCVLOWAT | SO_PASSCRED | SO_BSDCOMPAT | SO_REUSEPORT => {
                if optlen < size_of::<i32>() {
                    return err(SyscallError::EINVAL);
                }
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match optname {
                    SO_REUSEADDR => unix_sock.set_reuseaddr(val != 0),
                    SO_DONTROUTE => unix_sock.set_dontroute(val != 0),
                    SO_BROADCAST => unix_sock.set_broadcast(val != 0),
                    SO_KEEPALIVE => unix_sock.set_keepalive(val != 0),
                    SO_OOBINLINE => unix_sock.set_oobinline(val != 0),
                    SO_RCVLOWAT => unix_sock.set_rcvlowat(linux_rcvlowat_value(val)),
                    SO_PASSCRED => unix_sock.set_passcred(val != 0),
                    SO_BSDCOMPAT => {}
                    SO_REUSEPORT => {
                        if val != 0 {
                            return err(SyscallError::EOPNOTSUPP);
                        }
                    }
                    _ => {}
                }
                0
            }
            SO_SNDLOWAT => err(SyscallError::ENOPROTOOPT),
            _ => err(SyscallError::ENOPROTOOPT),
        };
    }
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        if level != SOL_SOCKET {
            return err(SyscallError::ENOPROTOOPT);
        }
        return match optname {
            SO_ATTACH_FILTER => {
                let filter = match ClassicBpfProgram::from_sock_fprog_user(optval, optlen) {
                    Ok(filter) => filter,
                    Err(e) => return e,
                };
                sock.attach_filter(filter)
            }
            SO_DETACH_FILTER => sock.detach_filter(),
            SO_LOCK_FILTER => {
                if optlen < size_of::<i32>() {
                    return err(SyscallError::EINVAL);
                }
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_filter_locked(val != 0)
            }
            SO_LINGER => {
                let (on, sec) = match read_linger(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_linger(on, sec);
                0
            }
            opt if is_so_rcvtimeo(opt) => {
                let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_rcvtimeo_ms(timeout_ms);
                0
            }
            opt if is_so_sndtimeo(opt) => {
                let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_sndtimeo_ms(timeout_ms);
                0
            }
            SO_REUSEADDR | SO_DONTROUTE | SO_BROADCAST | SO_KEEPALIVE | SO_OOBINLINE
            | SO_RCVLOWAT | SO_PASSCRED | SO_BSDCOMPAT | SO_REUSEPORT => {
                if optlen < size_of::<i32>() {
                    return err(SyscallError::EINVAL);
                }
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match optname {
                    SO_REUSEADDR => sock.set_reuseaddr(val != 0),
                    SO_DONTROUTE => sock.set_dontroute(val != 0),
                    SO_BROADCAST => sock.set_broadcast(val != 0),
                    SO_KEEPALIVE => sock.set_keepalive(val != 0),
                    SO_OOBINLINE => sock.set_oobinline(val != 0),
                    SO_RCVLOWAT => sock.set_rcvlowat(linux_rcvlowat_value(val)),
                    SO_PASSCRED => sock.set_passcred(val != 0),
                    SO_BSDCOMPAT => {}
                    SO_REUSEPORT => {
                        if val != 0 {
                            return err(SyscallError::EOPNOTSUPP);
                        }
                    }
                    _ => {}
                }
                0
            }
            SO_SNDLOWAT => err(SyscallError::ENOPROTOOPT),
            _ => err(SyscallError::ENOPROTOOPT),
        };
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    if level == SOL_TCP {
        if optlen < size_of::<i32>() {
            return err(SyscallError::EINVAL);
        }
        let val = match read_sockopt_int(optval, optlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return match optname {
            TCP_NODELAY => match sock.set_tcp_nodelay(val != 0) {
                Ok(()) => 0,
                Err(e) => e,
            },
            TCP_CORK => match sock.set_tcp_cork(val != 0) {
                Ok(()) => 0,
                Err(e) => e,
            },
            TCP_KEEPIDLE => {
                let secs = match tcp_keepalive_sockopt_value(val, MAX_TCP_KEEPIDLE) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match sock.set_tcp_keepidle_secs(secs) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            TCP_KEEPINTVL => {
                let secs = match tcp_keepalive_sockopt_value(val, MAX_TCP_KEEPINTVL) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match sock.set_tcp_keepintvl_secs(secs) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            TCP_KEEPCNT => {
                let count = match tcp_keepalive_sockopt_value(val, MAX_TCP_KEEPCNT) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                match sock.set_tcp_keepcnt(count) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            _ => err(SyscallError::ENOPROTOOPT),
        };
    }
    if level == SOL_UDPLITE {
        if optlen < size_of::<i32>() {
            return err(SyscallError::EINVAL);
        }
        let val = match read_sockopt_int(optval, optlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return match sock.set_udplite_checksum_coverage(optname, val) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }
    if level == SOL_SOCKET {
        if optname == SO_BINDTODEVICE {
            let name = match read_sockopt_ifname(optval, optlen) {
                Ok(name) => name,
                Err(e) => return e,
            };
            let target_ifindex = if name.is_empty() {
                0
            } else {
                let Some(ifindex) = netdev::ifindex_by_name_in_namespace(sock.net_ns_id(), &name)
                else {
                    return err(SyscallError::ENODEV);
                };
                ifindex
            };
            if let Err(e) = require_bound_device_rebind(sock.bound_device_ifindex() > 0) {
                return e;
            }
            if name.is_empty() {
                sock.set_bound_device_ifindex(0);
                return 0;
            }
            sock.set_bound_device_ifindex(target_ifindex);
            return 0;
        }
        if optname == SO_LINGER {
            let (on, sec) = match read_linger(optval, optlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.set_linger(on, sec);
            return 0;
        }
        if is_so_rcvtimeo(optname) {
            let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.set_rcvtimeo_ms(timeout_ms);
            return 0;
        }
        if is_so_sndtimeo(optname) {
            let timeout_ms = match read_socket_timeval_ms(optval, optlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.set_sndtimeo_ms(timeout_ms);
            return 0;
        }
        if optname == SO_ATTACH_FILTER {
            let filter = match ClassicBpfProgram::from_sock_fprog_user(optval, optlen) {
                Ok(filter) => filter,
                Err(e) => return e,
            };
            return sock.attach_filter(filter);
        }
        if optname == SO_DETACH_FILTER {
            return sock.detach_filter();
        }
        if optname == SO_LOCK_FILTER {
            if optlen < size_of::<i32>() {
                return err(SyscallError::EINVAL);
            }
            let val = match read_sockopt_int(optval, optlen) {
                Ok(v) => v,
                Err(e) => return e,
            };
            return sock.set_filter_locked(val != 0);
        }
        if optlen < size_of::<i32>() {
            return err(SyscallError::EINVAL);
        }
        if optval == 0 {
            return err(SyscallError::EFAULT);
        }
        let token = get_current_token();
        let Some(v_i32) = try_read_user_value::<i32>(token, optval as *const i32) else {
            return err(SyscallError::EFAULT);
        };
        if let Err(e) = require_cap_net_admin_for_sockbuf_force(optname) {
            return e;
        }
        let sockbuf_value = linux_sockbuf_value(v_i32, optname);
        if crate::debug_config::DEBUG_NET && (optname == SO_SNDBUF || optname == SO_RCVBUF) {
            crate::println!(
                "[net] pid={} setsockopt(fd={}, opt={}) = {}",
                current_process().pid.0,
                fd,
                optname,
                sockbuf_value
            );
        }
        match optname {
            SO_REUSEADDR => sock.set_reuseaddr(v_i32 != 0),
            // Linux 的 SO_REUSEPORT 需要 bind 侧 reuseport group 与收包分发配合。
            // 当前 AF_INET socket 没有这套机制，启用时必须显式拒绝，避免只保存
            // 布尔值造成“setsockopt 成功但复用语义不存在”的假支持。
            SO_REUSEPORT => {
                if v_i32 != 0 {
                    return err(SyscallError::EOPNOTSUPP);
                }
            }
            SO_DONTROUTE => sock.set_dontroute(v_i32 != 0),
            SO_BROADCAST => sock.set_broadcast(v_i32 != 0),
            SO_KEEPALIVE => sock.set_keepalive(v_i32 != 0),
            SO_SNDBUF | SO_SNDBUFFORCE => sock.set_sockbuf(Some(sockbuf_value), None),
            SO_RCVBUF | SO_RCVBUFFORCE => sock.set_sockbuf(None, Some(sockbuf_value)),
            SO_OOBINLINE => sock.set_oobinline(v_i32 != 0),
            SO_NO_CHECK => sock.set_no_check(v_i32 != 0),
            SO_RCVLOWAT => sock.set_rcvlowat(linux_rcvlowat_value(v_i32)),
            SO_BUSY_POLL => {
                if v_i32 < 0 {
                    return err(SyscallError::EINVAL);
                }
                sock.set_busy_poll(v_i32 as u32);
            }
            SO_TIMESTAMP_OLD | SO_TIMESTAMPNS_OLD | SO_TIMESTAMP_NEW | SO_TIMESTAMPNS_NEW => {
                let Some(mode) = timestamp_mode_for_sockopt(optname, v_i32 != 0) else {
                    return err(SyscallError::ENOPROTOOPT);
                };
                sock.set_timestamp_mode(mode);
            }
            SO_BSDCOMPAT => {}
            SO_SNDLOWAT => return err(SyscallError::ENOPROTOOPT),
            SO_PRIORITY => {
                let priority = match socket_priority_value(v_i32) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_priority(priority);
            }
            SO_MARK => {
                let mark = match socket_mark_value(v_i32) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_mark(mark);
            }
            SO_RCVMARK => sock.set_rcvmark(v_i32 != 0),
            SO_RCVPRIORITY => sock.set_rcvpriority(v_i32 != 0),
            _ => return err(SyscallError::ENOPROTOOPT),
        }
        return 0;
    }
    if level == SOL_IP {
        match optname {
            IP_PKTINFO => {
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_ipv4_pktinfo(val != 0);
                return 0;
            }
            IP_MTU_DISCOVER => {
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if !(IP_PMTUDISC_DONT..=IP_PMTUDISC_OMIT).contains(&val) {
                    return err(SyscallError::EINVAL);
                }
                sock.set_ipv4_mtu_discover(val);
                return 0;
            }
            IP_RECVERR => {
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_ipv4_recverr(val != 0);
                return 0;
            }
            IP_RECVTTL => {
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_ipv4_recvttl(val != 0);
                return 0;
            }
            IP_RECVTOS => {
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_ipv4_recvtos(val != 0);
                return 0;
            }
            IP_TOS => {
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_ipv4_tos(val);
                return 0;
            }
            IP_TTL => {
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if optlen < 1 || (val != -1 && !(1..=255).contains(&val)) {
                    return err(SyscallError::EINVAL);
                }
                sock.set_ipv4_ttl(val);
                return 0;
            }
            IP_MULTICAST_IF => {
                let (ifindex, addr) = match read_ipv4_multicast_if(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                return sock.set_ipv4_multicast_if(ifindex, addr);
            }
            IP_MULTICAST_TTL => {
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if sock.kind() == crate::fs::NetSocketKind::TcpStream || optlen < 1 {
                    return err(SyscallError::EINVAL);
                }
                let val = if val == -1 { 1 } else { val };
                if !(0..=255).contains(&val) {
                    return err(SyscallError::EINVAL);
                }
                sock.set_ipv4_multicast_ttl(val as u8);
                return 0;
            }
            IP_MULTICAST_LOOP => {
                if optlen < 1 {
                    return err(SyscallError::EINVAL);
                }
                let val = match read_sockopt_int(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                sock.set_ipv4_multicast_loop(val != 0);
                return 0;
            }
            IP_ADD_MEMBERSHIP => {
                let (group, ifindex, ifaddr) = match read_ip_mreqn(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                return sock.join_ipv4_multicast(group, ifindex, ifaddr);
            }
            IP_DROP_MEMBERSHIP => {
                let (group, ifindex, ifaddr) = match read_ip_mreqn(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                return sock.leave_ipv4_multicast(group, ifindex, ifaddr);
            }
            IP_BLOCK_SOURCE | IP_UNBLOCK_SOURCE => {
                let (group, ifaddr, source) = match read_ip_mreq_source(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if optname == IP_BLOCK_SOURCE {
                    return sock.block_ipv4_multicast_source(group, 0, ifaddr, source);
                }
                return sock.unblock_ipv4_multicast_source(group, 0, ifaddr, source);
            }
            IP_ADD_SOURCE_MEMBERSHIP | IP_DROP_SOURCE_MEMBERSHIP => {
                let (group, ifaddr, source) = match read_ip_mreq_source(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if optname == IP_ADD_SOURCE_MEMBERSHIP {
                    return sock.join_ipv4_multicast_source(group, 0, ifaddr, source);
                }
                return sock.leave_ipv4_multicast_source(group, 0, ifaddr, source);
            }
            IP_MSFILTER => {
                let (group, ifaddr, fmode, sources) = match read_ip_msfilter(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let mode = match ipv4_source_filter_mode(fmode) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                return sock.set_ipv4_multicast_source_filter(group, 0, ifaddr, mode, sources);
            }
            MCAST_JOIN_GROUP => {
                let (group, ifindex) = match read_group_req(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                return sock.join_ipv4_multicast_group(group, ifindex, [0; 4]);
            }
            MCAST_LEAVE_GROUP => {
                let (group, ifindex) = match read_group_req(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                return sock.leave_ipv4_multicast_group(group, ifindex, [0; 4]);
            }
            MCAST_JOIN_SOURCE_GROUP | MCAST_LEAVE_SOURCE_GROUP => {
                let (group, ifindex, source) = match read_group_source_req(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if optname == MCAST_JOIN_SOURCE_GROUP {
                    return sock.join_ipv4_multicast_source(group, ifindex, [0; 4], source);
                }
                return sock.leave_ipv4_multicast_source(group, ifindex, [0; 4], source);
            }
            MCAST_BLOCK_SOURCE | MCAST_UNBLOCK_SOURCE => {
                let (group, ifindex, source) = match read_group_source_req(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if optname == MCAST_BLOCK_SOURCE {
                    return sock.block_ipv4_multicast_source(group, ifindex, [0; 4], source);
                }
                return sock.unblock_ipv4_multicast_source(group, ifindex, [0; 4], source);
            }
            MCAST_MSFILTER => {
                let (group, ifindex, fmode, sources) = match read_group_filter(optval, optlen) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let mode = match ipv4_source_filter_mode(fmode) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                return sock
                    .set_ipv4_multicast_source_filter(group, ifindex, [0; 4], mode, sources);
            }
            _ => return err(SyscallError::ENOPROTOOPT),
        }
    }
    if level == SOL_TCP || level == SOL_UDP || level == SOL_UDPLITE {
        return err(SyscallError::ENOPROTOOPT);
    }
    err(SyscallError::ENOPROTOOPT)
}

/// 将套接字选项值安全写回用户空间（内部辅助）。
///
/// 按 POSIX `getsockopt(2)` 语义处理缓冲区长度：
/// - 实际拷贝长度为 `min(user_len, value.len())`，超出部分截断，不报错。
/// - 无论是否发生截断，均将**选项的完整长度**（`value.len()`）写回 `optlen` 指针，
///   使调用方可以感知缓冲区不足并按需重新分配。
///
/// # 参数
/// - `optval`：用户空间目标缓冲区指针
/// - `optlen`：用户空间 `socklen_t *` 指针，调用后被更新为实际选项长度
/// - `user_len`：用户提供的缓冲区大小（字节）
/// - `value`：要写入的选项值字节切片
///
/// # 返回值
/// 成功返回 `0`；写入失败返回 `EFAULT`。
fn write_sockopt_bytes(optval: usize, optlen: usize, user_len: usize, value: &[u8]) -> isize {
    let token = get_current_token();
    // 以用户缓冲区大小为上限截断，防止越界写入
    let copy_len = core::cmp::min(user_len, value.len());
    if copy_len > 0 && try_copy_to_user(token, optval as *mut u8, &value[..copy_len]).is_err() {
        return err(SyscallError::EFAULT);
    }
    // 回写完整的选项长度（非截断后的长度），符合 POSIX getsockopt 语义
    if try_write_user_value(token, optlen as *mut u32, &(value.len() as u32)).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

fn write_sock_filter_len(optlen: usize, count: usize) -> isize {
    let token = get_current_token();
    if try_write_user_value(token, optlen as *mut u32, &(count as u32)).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}

fn getsockopt_classic_filter(
    optval: usize,
    optlen: usize,
    user_len: usize,
    classic_filter: Option<ClassicBpfProgram>,
    has_ebpf_filter: bool,
) -> isize {
    let Some(filter) = classic_filter else {
        return if has_ebpf_filter {
            err(SyscallError::EACCES)
        } else {
            write_sock_filter_len(optlen, 0)
        };
    };
    let count = filter.instruction_count();
    if user_len == 0 {
        return write_sock_filter_len(optlen, count);
    }
    if user_len < count {
        return err(SyscallError::EINVAL);
    }
    if optval == 0 {
        return err(SyscallError::EFAULT);
    }
    let raw = filter.to_sock_filter_bytes();
    let token = get_current_token();
    if try_copy_to_user(token, optval as *mut u8, &raw).is_err() {
        return err(SyscallError::EFAULT);
    }
    write_sock_filter_len(optlen, count)
}

fn write_sockopt_ifname(
    optval: usize,
    optlen: usize,
    user_len: usize,
    name: Option<alloc::string::String>,
) -> isize {
    let Some(name) = name else {
        return write_sockopt_bytes(optval, optlen, user_len, &[]);
    };
    let mut raw = [0u8; 16];
    if user_len < raw.len() {
        return err(SyscallError::EINVAL);
    }
    let bytes = name.as_bytes();
    let copy_len = core::cmp::min(bytes.len(), raw.len().saturating_sub(1));
    raw[..copy_len].copy_from_slice(&bytes[..copy_len]);
    write_sockopt_bytes(optval, optlen, user_len, &raw[..copy_len + 1])
}

fn write_ip_msfilter(
    optval: usize,
    optlen: usize,
    user_len: usize,
    group: [u8; 4],
    ifaddr: [u8; 4],
    fmode: u32,
    capacity: usize,
    sources: &[[u8; 4]],
) -> isize {
    const IP_MSFILTER_BASE_LEN: usize = 16;
    let copy_count = core::cmp::min(capacity, sources.len());
    let len = IP_MSFILTER_BASE_LEN + copy_count * 4;
    let mut raw = vec![0u8; len];
    raw[0..4].copy_from_slice(&group);
    raw[4..8].copy_from_slice(&ifaddr);
    raw[8..12].copy_from_slice(&fmode.to_ne_bytes());
    raw[12..16].copy_from_slice(&(sources.len() as u32).to_ne_bytes());
    for (idx, source) in sources.iter().take(copy_count).enumerate() {
        let off = IP_MSFILTER_BASE_LEN + idx * 4;
        raw[off..off + 4].copy_from_slice(source);
    }
    write_sockopt_bytes(optval, optlen, user_len, &raw)
}

fn write_group_filter(
    optval: usize,
    optlen: usize,
    user_len: usize,
    group: [u8; 4],
    ifindex: i32,
    fmode: u32,
    capacity: usize,
    sources: &[[u8; 4]],
) -> isize {
    const GROUP_FILTER_BASE_LEN: usize = 144;
    const GROUP_ADDR_OFFSET: usize = 8;
    const FMODE_OFFSET: usize = 136;
    const NUMSRC_OFFSET: usize = 140;
    let copy_count = core::cmp::min(capacity, sources.len());
    let len = GROUP_FILTER_BASE_LEN + copy_count * 128;
    let mut raw = vec![0u8; len];
    raw[0..4].copy_from_slice(&(ifindex as u32).to_ne_bytes());
    raw[GROUP_ADDR_OFFSET..GROUP_ADDR_OFFSET + 2].copy_from_slice(&AF_INET.to_ne_bytes());
    raw[GROUP_ADDR_OFFSET + 4..GROUP_ADDR_OFFSET + 8].copy_from_slice(&group);
    raw[FMODE_OFFSET..FMODE_OFFSET + 4].copy_from_slice(&fmode.to_ne_bytes());
    raw[NUMSRC_OFFSET..NUMSRC_OFFSET + 4].copy_from_slice(&(sources.len() as u32).to_ne_bytes());
    for (idx, source) in sources.iter().take(copy_count).enumerate() {
        let off = GROUP_FILTER_BASE_LEN + idx * 128;
        raw[off..off + 2].copy_from_slice(&AF_INET.to_ne_bytes());
        raw[off + 4..off + 8].copy_from_slice(source);
    }
    write_sockopt_bytes(optval, optlen, user_len, &raw)
}

/// 读取套接字选项（`getsockopt(2)`）。
///
/// 支持的选项层级与名称：
/// - Netlink 套接字：`SO_TYPE`、`SO_ERROR` 与明确支持的 `SOL_NETLINK` 控制项
/// - Unix 域套接字：`SOL_SOCKET / SO_PEERCRED`（对端凭证）、`SO_OOBINLINE`
/// - TCP/UDP 套接字：常用 `SOL_SOCKET` 状态、IPv4 TTL/MTU/组播状态
///
/// # 参数
/// - `fd`：套接字文件描述符
/// - `level`：选项层级（`SOL_SOCKET`、`SOL_IP` 等）
/// - `optname`：选项名称
/// - `optval`：用户空间接收缓冲区指针（不可为 null）
/// - `optlen`：指向缓冲区长度的用户空间指针（不可为 null）；调用后被更新为实际选项长度
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_getsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    if optlen == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(user_len_u32) = try_read_user_value::<u32>(token, optlen as *const u32) else {
        return err(SyscallError::EFAULT);
    };
    let user_len = user_len_u32 as usize;
    let is_get_filter = level == SOL_SOCKET && optname == SO_ATTACH_FILTER;
    if optval == 0 && !is_get_filter {
        return err(SyscallError::EFAULT);
    }
    // 防止后续长度运算溢出：optlen 不应超过 i32::MAX
    if user_len > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    if user_len == 0 && !is_get_filter {
        return err(SyscallError::EINVAL);
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        return getsockopt_netlink(netlink_sock, level, optname, optval, optlen, user_len);
    }
    if let Some(vsock) = file.as_any().downcast_ref::<VsockSocketFile>() {
        if level == AF_VSOCK as usize || level == SOL_VSOCK {
            match optname {
                SO_VM_SOCKETS_BUFFER_SIZE => {
                    let value = vsock.buffer_size();
                    return write_sockopt_bytes(optval, optlen, user_len, &value.to_ne_bytes());
                }
                SO_VM_SOCKETS_BUFFER_MIN_SIZE => {
                    let value = vsock.buffer_min_size();
                    return write_sockopt_bytes(optval, optlen, user_len, &value.to_ne_bytes());
                }
                SO_VM_SOCKETS_BUFFER_MAX_SIZE => {
                    let value = vsock.buffer_max_size();
                    return write_sockopt_bytes(optval, optlen, user_len, &value.to_ne_bytes());
                }
                SO_VM_SOCKETS_CONNECT_TIMEOUT_OLD | SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW => {
                    return write_socket_timeval_ms(
                        optval,
                        optlen,
                        user_len,
                        vsock.connect_timeout_ms(),
                    );
                }
                _ => return err(SyscallError::ENOPROTOOPT),
            }
        }
        if level == SOL_SOCKET {
            let val: u32 = match optname {
                SO_ERROR => 0,
                SO_TYPE => vsock.socket_type() as u32,
                SO_ACCEPTCONN => 0,
                SO_PROTOCOL => vsock.protocol() as u32,
                SO_DOMAIN => AF_VSOCK as u32,
                SO_SNDBUF => vsock.buffer_size().min(u32::MAX as u64) as u32,
                SO_RCVBUF => vsock.buffer_size().min(u32::MAX as u64) as u32,
                SO_SNDLOWAT => 1,
                SO_RCVLOWAT => 1,
                _ => return err(SyscallError::EOPNOTSUPP),
            };
            return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
        }
        return err(SyscallError::EOPNOTSUPP);
    }
    if let Some(packet_sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        if level == SOL_PACKET {
            match optname {
                PACKET_STATISTICS => {
                    let (packets, drops, v3) = packet_sock.take_packet_statistics();
                    if v3 {
                        let mut stats = [0u8; 12];
                        stats[0..4].copy_from_slice(&packets.to_ne_bytes());
                        stats[4..8].copy_from_slice(&drops.to_ne_bytes());
                        return write_sockopt_bytes(optval, optlen, user_len, &stats);
                    }
                    let mut stats = [0u8; 8];
                    stats[0..4].copy_from_slice(&packets.to_ne_bytes());
                    stats[4..8].copy_from_slice(&drops.to_ne_bytes());
                    return write_sockopt_bytes(optval, optlen, user_len, &stats);
                }
                PACKET_RESERVE => {
                    let val = packet_sock.packet_reserve();
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_VERSION => {
                    let val = packet_sock.packet_version();
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_COPY_THRESH => {
                    let val = packet_sock.packet_copy_thresh();
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_AUXDATA => {
                    let val = packet_sock.packet_auxdata() as u32;
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_ORIGDEV => {
                    let val = packet_sock.packet_origdev() as u32;
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_VNET_HDR => {
                    let val = packet_sock.packet_vnet_hdr() as u32;
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_VNET_HDR_SZ => {
                    let val = if packet_sock.packet_vnet_hdr() {
                        10u32
                    } else {
                        0
                    };
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_QDISC_BYPASS => {
                    let val = packet_sock.packet_qdisc_bypass() as u32;
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_IGNORE_OUTGOING => {
                    let val = packet_sock.packet_ignore_outgoing() as u32;
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_HDRLEN => {
                    if user_len < size_of::<i32>() {
                        return err(SyscallError::EINVAL);
                    }
                    if optval == 0 {
                        return err(SyscallError::EFAULT);
                    }
                    let token = get_current_token();
                    let Some(version) = try_read_user_value::<i32>(token, optval as *const i32)
                    else {
                        return err(SyscallError::EFAULT);
                    };
                    let val = match PacketSocketFile::packet_header_len_for_version(version) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                PACKET_FANOUT => {
                    let val = packet_sock.fanout_value();
                    return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
                }
                _ => {
                    return err(SyscallError::ENOPROTOOPT);
                }
            }
        }
        if level == SOL_SOCKET {
            if optname == SO_ATTACH_FILTER {
                let (filter, has_ebpf) = packet_sock.classic_filter_snapshot();
                return getsockopt_classic_filter(optval, optlen, user_len, filter, has_ebpf);
            }
            if optname == SO_BINDTODEVICE {
                return write_sockopt_ifname(
                    optval,
                    optlen,
                    user_len,
                    packet_sock.bound_device_name(),
                );
            }
            if optname == SO_LINGER {
                let (on, sec) = packet_sock.linger();
                return write_linger(optval, optlen, user_len, on, sec);
            }
            if is_so_rcvtimeo(optname) {
                return write_socket_timeval_ms(
                    optval,
                    optlen,
                    user_len,
                    packet_sock.rcvtimeo_ms(),
                );
            }
            if is_so_sndtimeo(optname) {
                return write_socket_timeval_ms(
                    optval,
                    optlen,
                    user_len,
                    packet_sock.sndtimeo_ms(),
                );
            }
            let val: u32 = match optname {
                SO_ERROR => packet_sock.take_socket_error(),
                SO_TYPE => packet_sock.socket_type() as u32,
                SO_ACCEPTCONN => 0,
                SO_PROTOCOL => packet_sock.protocol(),
                SO_DOMAIN => AF_PACKET as u32,
                SO_LOCK_FILTER => packet_sock.filter_locked() as u32,
                SO_BPF_EXTENSIONS => 0,
                SO_REUSEADDR => packet_sock.reuseaddr() as u32,
                SO_REUSEPORT => 0,
                SO_DONTROUTE => packet_sock.dontroute() as u32,
                SO_BROADCAST => packet_sock.broadcast() as u32,
                SO_KEEPALIVE => packet_sock.keepalive() as u32,
                SO_SNDBUF => packet_sock.getsockopt_sndbuf(),
                SO_RCVBUF => packet_sock.getsockopt_rcvbuf(),
                SO_OOBINLINE => packet_sock.oobinline() as u32,
                SO_PRIORITY => packet_sock.priority(),
                SO_MARK => packet_sock.mark(),
                SO_RCVMARK => packet_sock.rcvmark() as u32,
                SO_RCVPRIORITY => packet_sock.rcvpriority() as u32,
                SO_RCVLOWAT => packet_sock.rcvlowat() as u32,
                SO_TIMESTAMP_OLD | SO_TIMESTAMPNS_OLD | SO_TIMESTAMP_NEW | SO_TIMESTAMPNS_NEW => {
                    match timestamp_mode_getsockopt(packet_sock.timestamp_mode(), optname) {
                        Some(v) => v,
                        None => return err(SyscallError::ENOPROTOOPT),
                    }
                }
                SO_SNDLOWAT => 1,
                SO_BSDCOMPAT => 0,
                _ => {
                    return err(SyscallError::ENOPROTOOPT);
                }
            };
            return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
        }
        return err(SyscallError::ENOPROTOOPT);
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        if level == SOL_SOCKET && optname == SO_ATTACH_FILTER {
            let (filter, has_ebpf) = raw_sock.classic_filter_snapshot();
            return getsockopt_classic_filter(optval, optlen, user_len, filter, has_ebpf);
        }
        if level == SOL_SOCKET && optname == SO_BINDTODEVICE {
            return write_sockopt_ifname(optval, optlen, user_len, raw_sock.bound_device_name());
        }
        if level == SOL_SOCKET && optname == SO_LINGER {
            let (on, sec) = raw_sock.linger();
            return write_linger(optval, optlen, user_len, on, sec);
        }
        if level == SOL_SOCKET && is_so_rcvtimeo(optname) {
            return write_socket_timeval_ms(optval, optlen, user_len, raw_sock.rcvtimeo_ms());
        }
        if level == SOL_SOCKET && is_so_sndtimeo(optname) {
            return write_socket_timeval_ms(optval, optlen, user_len, raw_sock.sndtimeo_ms());
        }
        let val: u32 = match level {
            SOL_SOCKET => match optname {
                SO_ERROR => raw_sock.take_socket_error(),
                SO_TYPE => raw_sock.socket_type() as u32,
                SO_ACCEPTCONN => 0,
                SO_PROTOCOL => raw_sock.protocol() as u32,
                SO_DOMAIN => AF_INET as u32,
                SO_LOCK_FILTER => raw_sock.filter_locked() as u32,
                SO_BPF_EXTENSIONS => 0,
                SO_REUSEADDR => raw_sock.reuseaddr() as u32,
                SO_REUSEPORT => 0,
                SO_DONTROUTE => raw_sock.dontroute() as u32,
                SO_BROADCAST => raw_sock.broadcast() as u32,
                SO_KEEPALIVE => raw_sock.keepalive() as u32,
                SO_SNDBUF => raw_sock.getsockopt_sndbuf(),
                SO_RCVBUF => raw_sock.getsockopt_rcvbuf(),
                SO_OOBINLINE => raw_sock.oobinline() as u32,
                SO_PRIORITY => raw_sock.priority(),
                SO_MARK => raw_sock.mark(),
                SO_RCVMARK => raw_sock.rcvmark() as u32,
                SO_RCVPRIORITY => raw_sock.rcvpriority() as u32,
                SO_RCVLOWAT => raw_sock.rcvlowat() as u32,
                SO_TIMESTAMP_OLD | SO_TIMESTAMPNS_OLD | SO_TIMESTAMP_NEW | SO_TIMESTAMPNS_NEW => {
                    match timestamp_mode_getsockopt(raw_sock.timestamp_mode(), optname) {
                        Some(v) => v,
                        None => return err(SyscallError::ENOPROTOOPT),
                    }
                }
                SO_SNDLOWAT => 1,
                SO_BSDCOMPAT => 0,
                _ => return err(SyscallError::ENOPROTOOPT),
            },
            SOL_IP => match optname {
                IP_OPTIONS => {
                    let options = raw_sock.ipv4_options();
                    return write_sockopt_bytes(optval, optlen, user_len, &options);
                }
                IP_MULTICAST_IF => {
                    let addr = raw_sock.ipv4_multicast_if_addr();
                    return write_sockopt_bytes(optval, optlen, user_len, &addr);
                }
                IP_MTU_DISCOVER => raw_sock.ipv4_mtu_discover() as u32,
                IP_PKTINFO => raw_sock.ipv4_pktinfo() as u32,
                IP_RECVERR => raw_sock.ipv4_recverr() as u32,
                IP_RECVTTL => raw_sock.ipv4_recvttl() as u32,
                IP_RECVTOS => raw_sock.ipv4_recvtos() as u32,
                IP_TOS => raw_sock.ipv4_tos(),
                IP_TTL => raw_sock.ipv4_ttl() as u32,
                IP_MULTICAST_TTL => raw_sock.ipv4_multicast_ttl() as u32,
                IP_MULTICAST_LOOP => raw_sock.ipv4_multicast_loop() as u32,
                IP_MTU => match raw_sock.ipv4_path_mtu() {
                    Some(mtu) => mtu,
                    None => return err(SyscallError::ENOTCONN),
                },
                IP_HDRINCL => raw_sock.ip_hdrincl() as u32,
                IP_MSFILTER => {
                    let (group, ifaddr, capacity) = match read_ip_msfilter_query(optval, user_len) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let (mode, sources) =
                        match raw_sock.ipv4_multicast_source_filter(group, 0, ifaddr) {
                            Ok(v) => v,
                            Err(e) => return e,
                        };
                    return write_ip_msfilter(
                        optval,
                        optlen,
                        user_len,
                        group,
                        ifaddr,
                        raw_ipv4_source_filter_mode_bits(mode),
                        capacity,
                        &sources,
                    );
                }
                MCAST_MSFILTER => {
                    let (group, ifindex, capacity) = match read_group_filter_query(optval, user_len)
                    {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    let (mode, sources) =
                        match raw_sock.ipv4_multicast_source_filter(group, ifindex, [0; 4]) {
                            Ok(v) => v,
                            Err(e) => return e,
                        };
                    return write_group_filter(
                        optval,
                        optlen,
                        user_len,
                        group,
                        ifindex,
                        raw_ipv4_source_filter_mode_bits(mode),
                        capacity,
                        &sources,
                    );
                }
                _ => return err(SyscallError::ENOPROTOOPT),
            },
            SOL_TCP | SOL_UDP => return err(SyscallError::ENOPROTOOPT),
            _ => return err(SyscallError::EOPNOTSUPP),
        };
        return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
    }
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        if level == SOL_SOCKET && optname == SO_ATTACH_FILTER {
            let (filter, has_ebpf) = unix_sock.classic_filter_snapshot();
            return getsockopt_classic_filter(optval, optlen, user_len, filter, has_ebpf);
        }
        if level == SOL_SOCKET && optname == SO_PEERCRED {
            let Some(cred) = unix_sock.peer_cred() else {
                return err(SyscallError::ENOTCONN);
            };
            // SAFETY: `cred` is a fully initialized local `UCred`, and we reborrow exactly
            // `size_of::<UCred>()` bytes from it while `cred` stays alive. If the layout or
            // length were wrong, userspace would observe uninitialized or out-of-bounds bytes.
            let cred_bytes = unsafe {
                core::slice::from_raw_parts(
                    (&cred as *const UCred) as *const u8,
                    size_of::<UCred>(),
                )
            };
            return write_sockopt_bytes(optval, optlen, user_len, cred_bytes);
        }
        if level == SOL_SOCKET {
            if optname == SO_LINGER {
                let (on, sec) = unix_sock.linger();
                return write_linger(optval, optlen, user_len, on, sec);
            }
            if is_so_rcvtimeo(optname) {
                return write_socket_timeval_ms(optval, optlen, user_len, unix_sock.rcvtimeo_ms());
            }
            if is_so_sndtimeo(optname) {
                return write_socket_timeval_ms(optval, optlen, user_len, unix_sock.sndtimeo_ms());
            }
            let val: u32 = match optname {
                SO_ERROR => unix_sock.take_socket_error(),
                SO_TYPE => unix_sock.socket_type() as u32,
                SO_ACCEPTCONN => unix_sock.is_listening() as u32,
                SO_PROTOCOL => 0,
                SO_DOMAIN => AF_UNIX as u32,
                SO_LOCK_FILTER => unix_sock.filter_locked() as u32,
                SO_REUSEADDR => unix_sock.reuseaddr() as u32,
                SO_REUSEPORT => 0,
                SO_DONTROUTE => unix_sock.dontroute() as u32,
                SO_BROADCAST => unix_sock.broadcast() as u32,
                SO_KEEPALIVE => unix_sock.keepalive() as u32,
                SO_OOBINLINE => unix_sock.oobinline() as u32,
                SO_RCVLOWAT => unix_sock.rcvlowat() as u32,
                SO_PASSCRED => unix_sock.passcred() as u32,
                SO_SNDLOWAT => 1,
                SO_BSDCOMPAT => 0,
                _ => return err(SyscallError::EOPNOTSUPP),
            };
            return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
        }
        if level == SOL_UDP {
            return err(SyscallError::EOPNOTSUPP);
        }
        if level == SOL_IP || level == SOL_TCP {
            return err(SyscallError::ENOPROTOOPT);
        }
        return err(SyscallError::EOPNOTSUPP);
    }
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        if level != SOL_SOCKET {
            return err(SyscallError::EOPNOTSUPP);
        }
        if optname == SO_ATTACH_FILTER {
            let (filter, has_ebpf) = sock.classic_filter_snapshot();
            return getsockopt_classic_filter(optval, optlen, user_len, filter, has_ebpf);
        }
        if optname == SO_PEERCRED {
            let cred = sock.peer_cred();
            // SAFETY: `cred` is a fully initialized local `UCred`, and the byte slice
            // is limited to its exact ABI size while `cred` is still alive.
            let cred_bytes = unsafe {
                core::slice::from_raw_parts(
                    (&cred as *const UCred) as *const u8,
                    size_of::<UCred>(),
                )
            };
            return write_sockopt_bytes(optval, optlen, user_len, cred_bytes);
        }
        if optname == SO_LINGER {
            let (on, sec) = sock.linger();
            return write_linger(optval, optlen, user_len, on, sec);
        }
        if is_so_rcvtimeo(optname) {
            return write_socket_timeval_ms(optval, optlen, user_len, sock.rcvtimeo_ms());
        }
        if is_so_sndtimeo(optname) {
            return write_socket_timeval_ms(optval, optlen, user_len, sock.sndtimeo_ms());
        }
        let val: u32 = match optname {
            SO_ERROR => sock.take_socket_error(),
            SO_TYPE => sock.socket_type() as u32,
            SO_ACCEPTCONN => 0,
            SO_PROTOCOL => 0,
            SO_DOMAIN => AF_UNIX as u32,
            SO_LOCK_FILTER => sock.filter_locked() as u32,
            SO_REUSEADDR => sock.reuseaddr() as u32,
            SO_REUSEPORT => 0,
            SO_DONTROUTE => sock.dontroute() as u32,
            SO_BROADCAST => sock.broadcast() as u32,
            SO_KEEPALIVE => sock.keepalive() as u32,
            SO_OOBINLINE => sock.oobinline() as u32,
            SO_RCVLOWAT => sock.rcvlowat() as u32,
            SO_PASSCRED => sock.passcred() as u32,
            SO_SNDLOWAT => 1,
            SO_BSDCOMPAT => 0,
            _ => return err(SyscallError::EOPNOTSUPP),
        };
        return write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes());
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let val: u32 = match level {
        SOL_SOCKET => match optname {
            SO_BINDTODEVICE => {
                let name = (sock.bound_device_ifindex() > 0)
                    .then(|| {
                        netdev::name_by_ifindex_in_namespace(
                            sock.net_ns_id(),
                            sock.bound_device_ifindex(),
                        )
                    })
                    .flatten();
                return write_sockopt_ifname(optval, optlen, user_len, name);
            }
            SO_ATTACH_FILTER => {
                let (filter, has_ebpf) = sock.classic_filter_snapshot();
                return getsockopt_classic_filter(optval, optlen, user_len, filter, has_ebpf);
            }
            SO_LINGER => {
                let (on, sec) = sock.linger();
                return write_linger(optval, optlen, user_len, on, sec);
            }
            SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW => {
                return write_socket_timeval_ms(optval, optlen, user_len, sock.rcvtimeo_ms());
            }
            SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => {
                return write_socket_timeval_ms(optval, optlen, user_len, sock.sndtimeo_ms());
            }
            SO_ERROR => sock.take_socket_error(),
            SO_BPF_EXTENSIONS => 0,
            SO_LOCK_FILTER => sock.filter_locked() as u32,
            SO_TYPE => match sock.kind() {
                crate::fs::NetSocketKind::TcpStream | crate::fs::NetSocketKind::TcpListener => {
                    SOCK_STREAM as u32
                }
                crate::fs::NetSocketKind::Udp => SOCK_DGRAM as u32,
            },
            SO_ACCEPTCONN => (sock.kind() == crate::fs::NetSocketKind::TcpListener) as u32,
            SO_PROTOCOL => sock.protocol() as u32,
            SO_DOMAIN => sock.domain() as u32,
            SO_REUSEADDR => sock.reuseaddr() as u32,
            SO_REUSEPORT => 0,
            SO_DONTROUTE => sock.dontroute() as u32,
            SO_BROADCAST => sock.broadcast() as u32,
            SO_KEEPALIVE => sock.keepalive() as u32,
            SO_SNDBUF => sock.getsockopt_sndbuf(),
            SO_RCVBUF => sock.getsockopt_rcvbuf(),
            SO_OOBINLINE => sock.oobinline() as u32,
            SO_NO_CHECK => sock.no_check() as u32,
            SO_PRIORITY => sock.priority(),
            SO_MARK => sock.mark(),
            SO_RCVMARK => sock.rcvmark() as u32,
            SO_RCVPRIORITY => sock.rcvpriority() as u32,
            SO_RCVLOWAT => sock.rcvlowat() as u32,
            SO_BUSY_POLL => sock.busy_poll(),
            SO_TIMESTAMP_OLD | SO_TIMESTAMPNS_OLD | SO_TIMESTAMP_NEW | SO_TIMESTAMPNS_NEW => {
                match timestamp_mode_getsockopt(sock.timestamp_mode(), optname) {
                    Some(v) => v,
                    None => return err(SyscallError::EOPNOTSUPP),
                }
            }
            SO_SNDLOWAT => 1,
            SO_BSDCOMPAT => 0,
            _ => return err(SyscallError::EOPNOTSUPP),
        },
        SOL_UDP => return err(SyscallError::EOPNOTSUPP),
        SOL_UDPLITE => match optname {
            UDPLITE_SEND_CSCOV => match sock.udplite_send_cscov() {
                Ok(v) => v,
                Err(e) => return e,
            },
            UDPLITE_RECV_CSCOV => match sock.udplite_recv_cscov() {
                Ok(v) => v,
                Err(e) => return e,
            },
            _ => return err(SyscallError::ENOPROTOOPT),
        },
        SOL_IP => match optname {
            IP_MULTICAST_IF => {
                let addr = sock.ipv4_multicast_if_addr();
                return write_sockopt_bytes(optval, optlen, user_len, &addr);
            }
            IP_PKTINFO => sock.ipv4_pktinfo() as u32,
            IP_MTU_DISCOVER => sock.ipv4_mtu_discover() as u32,
            IP_RECVERR => sock.ipv4_recverr() as u32,
            IP_RECVTTL => sock.ipv4_recvttl() as u32,
            IP_RECVTOS => sock.ipv4_recvtos() as u32,
            IP_TOS => sock.ipv4_tos(),
            IP_TTL => sock.ipv4_ttl() as u32,
            IP_MULTICAST_TTL => sock.ipv4_multicast_ttl() as u32,
            IP_MULTICAST_LOOP => sock.ipv4_multicast_loop() as u32,
            IP_MTU => match sock.ipv4_path_mtu() {
                Some(mtu) => mtu,
                None => return err(SyscallError::ENOTCONN),
            },
            IP_MSFILTER => {
                let (group, ifaddr, capacity) = match read_ip_msfilter_query(optval, user_len) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let (mode, sources) = match sock.ipv4_multicast_source_filter(group, 0, ifaddr) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                return write_ip_msfilter(
                    optval,
                    optlen,
                    user_len,
                    group,
                    ifaddr,
                    ipv4_source_filter_mode_bits(mode),
                    capacity,
                    &sources,
                );
            }
            MCAST_MSFILTER => {
                let (group, ifindex, capacity) = match read_group_filter_query(optval, user_len) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let (mode, sources) =
                    match sock.ipv4_multicast_source_filter(group, ifindex, [0; 4]) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                return write_group_filter(
                    optval,
                    optlen,
                    user_len,
                    group,
                    ifindex,
                    ipv4_source_filter_mode_bits(mode),
                    capacity,
                    &sources,
                );
            }
            _ => return err(SyscallError::ENOPROTOOPT),
        },
        SOL_TCP => match optname {
            TCP_NODELAY => match sock.tcp_nodelay() {
                Ok(v) => v as u32,
                Err(e) => return e,
            },
            TCP_CORK => match sock.tcp_cork() {
                Ok(v) => v as u32,
                Err(e) => return e,
            },
            TCP_KEEPIDLE => match sock.tcp_keepidle_secs() {
                Ok(v) => v,
                Err(e) => return e,
            },
            TCP_KEEPINTVL => match sock.tcp_keepintvl_secs() {
                Ok(v) => v,
                Err(e) => return e,
            },
            TCP_KEEPCNT => match sock.tcp_keepcnt() {
                Ok(v) => v,
                Err(e) => return e,
            },
            _ => return err(SyscallError::ENOPROTOOPT),
        },
        _ => return err(SyscallError::EOPNOTSUPP),
    };
    if crate::debug_config::DEBUG_NET && (optname == SO_SNDBUF || optname == SO_RCVBUF) {
        crate::println!(
            "[net] pid={} getsockopt(fd={}, opt={}) -> {}",
            current_process().pid.0,
            fd,
            optname,
            val
        );
    }
    write_sockopt_bytes(optval, optlen, user_len, &val.to_ne_bytes())
}

/// 关闭套接字的读写通道（`shutdown(2)`）。
///
/// `how` 参数含义：
/// - `SHUT_RD (0)`：关闭读端，调用 `shutdown_read`
/// - `SHUT_WR (1)`：关闭写端，调用 `tcp_close`
/// - `SHUT_RDWR (2)`：同时关闭读写两端，**依次**调用 `shutdown_read` 和 `tcp_close`
///
/// Unix stream/socketpair 会把写半关闭传递到底层 pipe，使对端读到 EOF；
/// TCP/UDP/RAW 走各自协议状态检查，未连接时返回 Linux 风格的 `ENOTCONN`。
/// AF_PACKET/AF_NETLINK 对应 Linux `sock_no_shutdown()`，返回 `EOPNOTSUPP`。
///
/// # 参数
/// - `_fd`：套接字文件描述符
/// - `_how`：关闭方向（`SHUT_RD`、`SHUT_WR` 或 `SHUT_RDWR`）
///
/// # 返回值
/// 成功返回 `0`；失败返回负的 `errno`。
pub fn syscall_shutdown(fd: usize, how: usize) -> isize {
    const SHUT_RD: usize = 0;
    const SHUT_WR: usize = 1;
    const SHUT_RDWR: usize = 2;
    if !matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR) {
        return err(SyscallError::EINVAL);
    }
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        return unix_sock.shutdown(how);
    }
    if let Some(sock) = file.as_any().downcast_ref::<SocketPairEnd>() {
        return match sock.shutdown(how) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }
    if file.as_any().downcast_ref::<NetlinkSocketFile>().is_some()
        || file.as_any().downcast_ref::<PacketSocketFile>().is_some()
    {
        return err(SyscallError::EOPNOTSUPP);
    }
    if file.as_any().downcast_ref::<VsockSocketFile>().is_some() {
        return err(SyscallError::ENOTCONN);
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        return match raw_sock.shutdown(how) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }
    if let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() {
        return match sock.shutdown_v4(how) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }
    err(SyscallError::ENOTSOCK)
}
