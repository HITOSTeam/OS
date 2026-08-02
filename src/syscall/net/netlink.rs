//! AF_NETLINK socket 实现，模拟 Linux rtnetlink 子集供 glibc/getaddrinfo 使用。
//!
//! 本模块不依赖真实网卡，仅向 user 空间暴露足以让 `getaddrinfo(AI_ADDRCONFIG)` 通过
//! 的最小接口：响应常见 rtnetlink 查询与变更请求；未知消息按 Linux 风格返回
//! `NLMSG_ERROR(-EOPNOTSUPP)`，避免把未实现能力伪装成成功。

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::mem::size_of;

use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::{
    File, NamespaceFile, NamespaceKind, POLLERR, POLLIN, POLLOUT, PollWaitQueue, wake_tasks,
};
use crate::mm::{
    UserBuffer, try_copy_from_user, try_copy_to_user, try_read_user_value, try_write_user_value,
};
use crate::syscall::error::{SyscallError, err};
use crate::task::manager::pid2process;
use crate::task::processor::{
    block_current_and_run_next, current_files, current_process, current_task,
};
use crate::task::signal::has_wait_interrupting_pending;
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use crate::trap::get_current_token;

use super::netdev::{self, NetDeviceKind, NetDeviceSnapshot};
use super::*;

// --- netlink 报文头部与对齐 ---
const NLMSG_HDR_LEN: usize = 16; // struct nlmsghdr 固定大小
const NLMSG_ALIGNTO: usize = 4; // 报文整体按 4 字节对齐
const RTA_ALIGNTO: usize = 4; // rtattr TLV 按 4 字节对齐
const RTATTR_HDR_LEN: usize = 4; // struct rtattr 头部：u16 len + u16 type
const NLA_TYPE_MASK: u16 = 0x3fff; // attr type 低 14 位才是真实类型

// --- netlink 消息标志与类型 ---
const NLM_F_MULTI: u16 = 0x02; // 多部分消息标志，最后一条改用 NLMSG_DONE 结尾
const NLM_F_ACK: u16 = 0x04; // 请求内核返回 NLMSG_ERROR 形式的 ACK
const NLM_F_CAPPED: u16 = 0x100; // ACK 中原始请求被裁剪
const NLM_F_ACK_TLVS: u16 = 0x200; // ACK 后追加扩展错误 TLV
const NLM_F_REPLACE: u16 = 0x100; // 路由已存在时替换
const NLM_F_EXCL: u16 = 0x200; // 路由已存在时报 EEXIST
const NLM_F_CREATE: u16 = 0x400; // 路由不存在时创建

const NLMSG_ERROR: u16 = 2; // netlink ACK / error
const NLMSG_DONE: u16 = 3; // 多部分回复的终止帧
const NLMSGERR_ATTR_MSG: u16 = 1; // 扩展 ACK 的错误字符串
const NETLINK_ROUTE: usize = 0;
const NETLINK_SOCK_DIAG: usize = 4;
const NETLINK_GENERIC: usize = 16;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const RTM_NEWLINK: u16 = 16; // 通知：网络接口信息
const RTM_DELLINK: u16 = 17; // 删除网络接口
const RTM_GETLINK: u16 = 18; // 请求：获取网络接口列表
const RTM_SETLINK: u16 = 19; // 修改网络接口属性
const RTM_NEWADDR: u16 = 20; // 通知：接口地址信息
const RTM_DELADDR: u16 = 21; // 删除接口地址
const RTM_GETADDR: u16 = 22; // 请求：获取接口地址列表
const RTM_NEWROUTE: u16 = 24; // 添加路由
const RTM_DELROUTE: u16 = 25; // 删除路由
const RTM_GETROUTE: u16 = 26; // 查询路由
const RTM_NEWNEIGH: u16 = 28; // 添加/替换邻居
const RTM_DELNEIGH: u16 = 29; // 删除邻居
const RTM_GETNEIGH: u16 = 30; // 查询邻居
const RTM_NEWQDISC: u16 = 36; // 添加/替换队列规则
const RTM_DELQDISC: u16 = 37; // 删除队列规则
const RTM_GETQDISC: u16 = 38; // 查询队列规则
const RTM_NEWMULTICAST: u16 = 56; // 添加链路组播地址
const RTM_DELMULTICAST: u16 = 57; // 删除链路组播地址
const RTM_GETMULTICAST: u16 = 58; // 查询链路组播地址
const RTNLGRP_LINK_GROUP: i32 = 1;
const RTMGRP_LINK: u32 = 1; // 链路变更组播组
const SUPPORTED_RTMGRP_MASK: u32 = RTMGRP_LINK;
const NETLINK_DEFAULT_SOCKBUF: u32 = 212_992; // Linux 常见默认 SO_SNDBUF/SO_RCVBUF
const CAP_NET_BROADCAST: usize = 11;
const CAP_NET_ADMIN: usize = 12;
const INET_DIAG_REQ_V2_MIN_LEN: usize = 8;
const INET_DIAG_MSG_LEN: usize = 72;
const GENL_ID_CTRL: u16 = 16;
const GENL_HDR_LEN: usize = 4;
const CTRL_CMD_GETFAMILY: u8 = 3;

// --- 硬件类型与接口标志（来自 linux/if_arp.h 和 linux/if.h）---
const IFF_UP: u32 = netdev::IFF_UP;

// --- rtnetlink TLV 属性类型（来自 linux/if_link.h 和 linux/if_addr.h）---
const IFLA_ADDRESS_ATTR: u16 = 1; // 接口硬件（MAC）地址
const IFLA_BROADCAST: u16 = 2; // 接口二层广播地址
const IFLA_IFNAME: u16 = 3; // 接口名称字符串
const IFLA_MTU: u16 = 4; // 最大传输单元
const IFLA_LINK: u16 = 5; // upper 设备所挂载的 lower ifindex
const IFLA_TXQLEN: u16 = 13; // 发送队列长度
const IFLA_LINKINFO: u16 = 18; // 嵌套的 link kind 信息
const IFLA_NET_NS_PID: u16 = 19; // 将接口移动到目标 netns
const IFLA_NET_NS_FD: u16 = 28; // 通过 namespace fd 指定目标 netns
const IFLA_OPERSTATE: u16 = 16; // 运行状态（RFC 2863）
const IFLA_INFO_KIND: u16 = 1; // IFLA_LINKINFO 内的设备类型字符串
const IFLA_INFO_DATA: u16 = 2; // IFLA_LINKINFO 内的设备类型私有数据
const IFLA_MACVLAN_MODE: u16 = 1;
const IFLA_MACVLAN_FLAGS: u16 = 2;
const IFLA_IPVLAN_MODE: u16 = 1;
const IFLA_IPVLAN_FLAGS: u16 = 2;
const IFA_ADDRESS: u16 = 1; // 接口地址
const IFA_LOCAL: u16 = 2; // 本地地址（点对点链路有别于目的地址）
const IFA_LABEL: u16 = 3; // 地址所属接口名称
const IFA_BROADCAST: u16 = 4; // IPv4 广播地址
const IFA_F_PERMANENT: u8 = 0x80; // 地址为永久配置（非临时/动态）
const RTA_DST: u16 = 1; // 路由目的地址
const RTA_OIF: u16 = 4; // 路由输出接口
const RTA_GATEWAY: u16 = 5; // 路由网关
const NDA_DST: u16 = 1; // 邻居目的地址
const NDA_LLADDR: u16 = 2; // 邻居链路层地址
const TCA_KIND: u16 = 1; // qdisc kind 字符串，例如 "netem"
const TCA_OPTIONS: u16 = 2; // qdisc 私有参数块
const RT_SCOPE_UNIVERSE: u8 = 0; // 全局路由可达范围
const TC_H_ROOT: u32 = 0xffff_ffff;
const MACVLAN_MODE_PRIVATE: u32 = 1;
const MACVLAN_MODE_VEPA: u32 = 2;
const MACVLAN_MODE_BRIDGE: u32 = 4;
const MACVLAN_MODE_PASSTHRU: u32 = 8;
const MACVLAN_MODE_SOURCE: u32 = 16;
const MACVLAN_FLAG_NOPROMISC: u16 = 1;
const MACVLAN_FLAG_NODST: u16 = 2;
const IPVLAN_MODE_L2: u16 = 0;
const IPVLAN_MODE_L3: u16 = 1;
const IPVLAN_MODE_L3S: u16 = 2;
const IPVLAN_F_PRIVATE: u16 = 0x01;
const IPVLAN_F_VEPA: u16 = 0x02;

/// `struct sockaddr_nl` 的 Rust 镜像（`#[repr(C)]` 保证内存布局一致）。
///
/// - `nl_family`：地址族，固定为 `AF_NETLINK`
/// - `nl_pad`：填充字节，必须为 0
/// - `nl_pid`：port id，标识 socket 端点；内核端固定为 0，用户端通常为进程 PID
/// - `nl_groups`：组播组位掩码，不使用时置 0
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

// 将 value 向上对齐到 align 的整数倍（align 必须是 2 的幂）。
fn align_to(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

// 从 buf[offset..offset+2] 读取一个主机序 u16，越界时返回 None。
fn read_u16_ne(buf: &[u8], offset: usize) -> Option<u16> {
    (offset + 2 <= buf.len()).then(|| u16::from_ne_bytes([buf[offset], buf[offset + 1]]))
}

// 从 buf[offset..offset+4] 读取一个主机序 u32，越界时返回 None。
fn read_u32_ne(buf: &[u8], offset: usize) -> Option<u32> {
    (offset + 4 <= buf.len()).then(|| {
        u32::from_ne_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    })
}

fn read_i32_ne(buf: &[u8], offset: usize) -> Option<i32> {
    read_u32_ne(buf, offset).map(|v| v as i32)
}

fn read_ipv4_attr(attrs: &[(u16, Vec<u8>)], attr_type: u16) -> Option<[u8; 4]> {
    attrs
        .iter()
        .find(|(kind, data)| *kind == attr_type && data.len() >= 4)
        .map(|(_, data)| [data[0], data[1], data[2], data[3]])
}

fn read_ipv4_attr_checked(
    attrs: &[(u16, Vec<u8>)],
    attr_type: u16,
) -> Result<Option<[u8; 4]>, isize> {
    let Some((_, data)) = attrs.iter().find(|(kind, _)| *kind == attr_type) else {
        return Ok(None);
    };
    if data.len() != 4 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(Some([data[0], data[1], data[2], data[3]]))
}

fn read_ipv6_attr(attrs: &[(u16, Vec<u8>)], attr_type: u16) -> Option<[u8; 16]> {
    attrs
        .iter()
        .find(|(kind, data)| *kind == attr_type && data.len() >= 16)
        .and_then(|(_, data)| data[..16].try_into().ok())
}

fn read_ipv6_attr_checked(
    attrs: &[(u16, Vec<u8>)],
    attr_type: u16,
) -> Result<Option<[u8; 16]>, isize> {
    let Some((_, data)) = attrs.iter().find(|(kind, _)| *kind == attr_type) else {
        return Ok(None);
    };
    if data.len() != 16 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(Some(
        data[..16]
            .try_into()
            .map_err(|_| err(SyscallError::EINVAL))?,
    ))
}

fn read_mac_attr(attrs: &[(u16, Vec<u8>)], attr_type: u16) -> Option<[u8; 6]> {
    attrs
        .iter()
        .find(|(kind, data)| *kind == attr_type && data.len() >= 6)
        .map(|(_, data)| [data[0], data[1], data[2], data[3], data[4], data[5]])
}

fn read_u32_attr(attrs: &[(u16, Vec<u8>)], attr_type: u16) -> Option<u32> {
    attrs
        .iter()
        .find(|(kind, data)| *kind == attr_type && data.len() >= 4)
        .map(|(_, data)| u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
}

pub(super) fn read_u32_attr_checked(
    attrs: &[(u16, Vec<u8>)],
    attr_type: u16,
) -> Result<Option<u32>, isize> {
    let Some((_, data)) = attrs.iter().find(|(kind, _)| *kind == attr_type) else {
        return Ok(None);
    };
    if data.len() != 4 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(Some(u32::from_ne_bytes([
        data[0], data[1], data[2], data[3],
    ])))
}

pub(super) fn read_u16_attr_checked(
    attrs: &[(u16, Vec<u8>)],
    attr_type: u16,
) -> Result<Option<u16>, isize> {
    let Some((_, data)) = attrs.iter().find(|(kind, _)| *kind == attr_type) else {
        return Ok(None);
    };
    if data.len() != 2 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(Some(u16::from_ne_bytes([data[0], data[1]])))
}

pub(super) fn read_string_attr(attrs: &[(u16, Vec<u8>)], attr_type: u16) -> Option<&str> {
    attrs
        .iter()
        .find(|(kind, _)| *kind == attr_type)
        .and_then(|(_, data)| {
            let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
            core::str::from_utf8(&data[..end]).ok()
        })
}

fn parse_rtattrs(buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut attrs = Vec::new();
    let mut offset = 0usize;
    while offset + RTATTR_HDR_LEN <= buf.len() {
        let len = read_u16_ne(buf, offset).unwrap_or(0) as usize;
        let attr_type = read_u16_ne(buf, offset + 2).unwrap_or(0) & NLA_TYPE_MASK;
        if len < RTATTR_HDR_LEN || offset + len > buf.len() {
            break;
        }
        attrs.push((
            attr_type,
            buf[offset + RTATTR_HDR_LEN..offset + len].to_vec(),
        ));
        offset += align_to(len, RTA_ALIGNTO);
    }
    attrs
}

pub(super) fn parse_rtattrs_checked(buf: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, isize> {
    let mut attrs = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        if buf.len() - offset < RTATTR_HDR_LEN {
            if buf[offset..].iter().all(|b| *b == 0) {
                break;
            }
            return Err(err(SyscallError::EINVAL));
        }
        let len = read_u16_ne(buf, offset).ok_or(err(SyscallError::EINVAL))? as usize;
        let attr_type =
            read_u16_ne(buf, offset + 2).ok_or(err(SyscallError::EINVAL))? & NLA_TYPE_MASK;
        if len < RTATTR_HDR_LEN || len > buf.len() - offset {
            return Err(err(SyscallError::EINVAL));
        }
        attrs.push((
            attr_type,
            buf[offset + RTATTR_HDR_LEN..offset + len].to_vec(),
        ));
        let aligned = align_to(len, RTA_ALIGNTO);
        if aligned > buf.len() - offset {
            if offset + len == buf.len() {
                break;
            }
            return Err(err(SyscallError::EINVAL));
        }
        offset += aligned;
    }
    Ok(attrs)
}

fn nested_attrs_checked(
    attrs: &[(u16, Vec<u8>)],
    attr_type: u16,
) -> Result<Vec<(u16, Vec<u8>)>, isize> {
    attrs
        .iter()
        .find(|(kind, _)| *kind == attr_type)
        .map(|(_, data)| parse_rtattrs_checked(data))
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn supports_ipv4_rtnl_family(family: u8) -> bool {
    family == AF_UNSPEC as u8 || family == AF_INET as u8
}

fn require_ipv4_rtnl_family(payload: &[u8]) -> Result<(), isize> {
    if supports_ipv4_rtnl_family(payload[0]) {
        Ok(())
    } else if payload[0] == AF_INET6 as u8 {
        Err(err(SyscallError::EAFNOSUPPORT))
    } else {
        Err(err(SyscallError::EAFNOSUPPORT))
    }
}

fn done_only(seq: u32, port_id: u32) -> Vec<Vec<u8>> {
    alloc::vec![build_done(seq, port_id)]
}

fn read_string_attr_owned(attrs: &[(u16, Vec<u8>)], attr_type: u16) -> Option<String> {
    read_string_attr(attrs, attr_type).map(ToString::to_string)
}

fn find_link_kind_recursive(attrs: &[(u16, Vec<u8>)], depth: usize) -> Option<String> {
    if depth > 4 {
        return None;
    }
    for (kind, data) in attrs {
        if *kind == IFLA_INFO_KIND {
            let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
            if let Ok(value) = core::str::from_utf8(&data[..end]) {
                if matches!(
                    value,
                    "dummy" | "veth" | "macvlan" | "ipvlan" | "macvtap" | "wireguard"
                ) {
                    return Some(value.to_string());
                }
            }
        }
        let nested = parse_rtattrs(data);
        if nested.is_empty() {
            continue;
        }
        if let Some(value) = find_link_kind_recursive(&nested, depth + 1) {
            return Some(value);
        }
    }
    None
}

fn find_nested_attrs_recursive(
    attrs: &[(u16, Vec<u8>)],
    attr_type: u16,
    depth: usize,
) -> Vec<(u16, Vec<u8>)> {
    if depth > 4 {
        return Vec::new();
    }
    for (kind, data) in attrs {
        if *kind == attr_type {
            let nested = parse_rtattrs(data);
            if !nested.is_empty() {
                return nested;
            }
        }
        let nested = parse_rtattrs(data);
        if nested.is_empty() {
            continue;
        }
        let found = find_nested_attrs_recursive(&nested, attr_type, depth + 1);
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

fn find_string_attr_recursive(
    attrs: &[(u16, Vec<u8>)],
    attr_type: u16,
    depth: usize,
) -> Option<String> {
    if depth > 4 {
        return None;
    }
    if let Some(value) = read_string_attr_owned(attrs, attr_type) {
        return Some(value);
    }
    for (_, data) in attrs {
        let nested = parse_rtattrs(data);
        if let Some(value) = find_string_attr_recursive(&nested, attr_type, depth + 1) {
            return Some(value);
        }
        if data.len() > 16 {
            let nested = parse_rtattrs(&data[16..]);
            if let Some(value) = find_string_attr_recursive(&nested, attr_type, depth + 1) {
                return Some(value);
            }
        }
    }
    None
}

// 追加一条 rtnetlink TLV(rtattr):`{u16 len, u16 type, payload, 4字节对齐填充}`。
// rtnetlink 报文里 IFLA_*/IFA_* 这些字段都靠这种 TLV 串联;少一个对齐填充字节,
// glibc 解析时会以为后面还有更多 attr 然后越界读 → 死循环或 EAI_FAIL。
pub(super) fn append_rtattr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = RTATTR_HDR_LEN + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % RTA_ALIGNTO != 0 {
        buf.push(0);
    }
}

// 拼出一条完整的 nlmsghdr + payload 的 netlink 消息,字节序按主机序(netlink 不用网络序)。
// 头部 16 字节:{u32 len, u16 type, u16 flags, u32 seq, u32 pid}。
// `port_id` 写在 pid 位置,user 端用它做 reply 匹配,所以必须等于 user bind 时拿到的 nl_pid。
fn build_nlmsg(msg_type: u16, flags: u16, seq: u32, port_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDR_LEN + payload.len();
    let mut buf = Vec::with_capacity(align_to(len, NLMSG_ALIGNTO));
    buf.extend_from_slice(&(len as u32).to_ne_bytes());
    buf.extend_from_slice(&msg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&port_id.to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % NLMSG_ALIGNTO != 0 {
        buf.push(0);
    }
    buf
}

pub(super) fn build_genlmsg(
    msg_type: u16,
    cmd: u8,
    version: u8,
    seq: u32,
    flags: u16,
    port_id: u32,
    attrs: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(GENL_HDR_LEN + attrs.len());
    payload.push(cmd);
    payload.push(version);
    payload.extend_from_slice(&0u16.to_ne_bytes());
    payload.extend_from_slice(attrs);
    build_nlmsg(msg_type, flags, seq, port_id, &payload)
}

fn build_link_with_type(
    msg_type: u16,
    dev: &NetDeviceSnapshot,
    seq: u32,
    flags: u16,
    port_id: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_UNSPEC as u8);
    payload.push(0);
    payload.extend_from_slice(&dev.link_type.to_ne_bytes());
    payload.extend_from_slice(&dev.ifindex.to_ne_bytes());
    payload.extend_from_slice(&dev.flags.to_ne_bytes());
    payload.extend_from_slice(&u32::MAX.to_ne_bytes());
    append_rtattr(&mut payload, IFLA_ADDRESS_ATTR, &dev.hwaddr);
    let broadcast = match dev.kind {
        NetDeviceKind::Loopback => [0u8; 6],
        NetDeviceKind::Ethernet
        | NetDeviceKind::Dummy
        | NetDeviceKind::Veth
        | NetDeviceKind::Macvlan
        | NetDeviceKind::Ipvlan
        | NetDeviceKind::Macvtap
        | NetDeviceKind::Tap => [0xff; 6],
        NetDeviceKind::Tun | NetDeviceKind::Wireguard => [0u8; 6],
    };
    append_rtattr(&mut payload, IFLA_BROADCAST, &broadcast);
    let mut ifname = dev.name.as_bytes().to_vec();
    ifname.push(0);
    append_rtattr(&mut payload, IFLA_IFNAME, &ifname);
    append_rtattr(&mut payload, IFLA_MTU, &dev.mtu.to_ne_bytes());
    if let Some(link_ifindex) = dev.link_ifindex {
        append_rtattr(&mut payload, IFLA_LINK, &link_ifindex.to_ne_bytes());
    }
    append_rtattr(&mut payload, IFLA_TXQLEN, &dev.tx_queue_len.to_ne_bytes());
    append_rtattr(&mut payload, IFLA_OPERSTATE, &[dev.operstate()]);
    let mut linkinfo = Vec::new();
    let mut kind = dev.kind.link_kind().as_bytes().to_vec();
    kind.push(0);
    append_rtattr(&mut linkinfo, IFLA_INFO_KIND, &kind);
    append_rtattr(&mut payload, IFLA_LINKINFO, &linkinfo);
    build_nlmsg(msg_type, flags, seq, port_id, &payload)
}

fn build_link(dev: &NetDeviceSnapshot, seq: u32, flags: u16, port_id: u32) -> Vec<u8> {
    build_link_with_type(RTM_NEWLINK, dev, seq, flags, port_id)
}

fn build_addr(
    dev: &NetDeviceSnapshot,
    addr: &netdev::Ipv4AddrEntry,
    seq: u32,
    flags: u16,
    port_id: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_INET as u8);
    payload.push(addr.prefix_len);
    payload.push(IFA_F_PERMANENT);
    payload.push(addr.scope);
    payload.extend_from_slice(&(dev.ifindex as u32).to_ne_bytes());
    append_rtattr(&mut payload, IFA_ADDRESS, &addr.peer_addr);
    append_rtattr(&mut payload, IFA_LOCAL, &addr.addr);
    if let Some(broadcast) = addr.broadcast_addr {
        append_rtattr(&mut payload, IFA_BROADCAST, &broadcast);
    }
    let mut label = netdev::ipv4_addr_label(&dev.name, addr).as_bytes().to_vec();
    label.push(0);
    append_rtattr(&mut payload, IFA_LABEL, &label);
    build_nlmsg(RTM_NEWADDR, flags, seq, port_id, &payload)
}

fn build_addr6(
    dev: &NetDeviceSnapshot,
    addr: &netdev::Ipv6AddrEntry,
    seq: u32,
    flags: u16,
    port_id: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_INET6 as u8);
    payload.push(addr.prefix_len);
    payload.push(IFA_F_PERMANENT);
    payload.push(addr.scope);
    payload.extend_from_slice(&(dev.ifindex as u32).to_ne_bytes());
    append_rtattr(&mut payload, IFA_ADDRESS, &addr.addr);
    append_rtattr(&mut payload, IFA_LOCAL, &addr.addr);
    let mut label = addr
        .label
        .as_deref()
        .unwrap_or(&dev.name)
        .as_bytes()
        .to_vec();
    label.push(0);
    append_rtattr(&mut payload, IFA_LABEL, &label);
    build_nlmsg(RTM_NEWADDR, flags, seq, port_id, &payload)
}

fn build_route(route: &netdev::RouteEntry, seq: u32, flags: u16, port_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_INET as u8);
    payload.push(route.prefix_len);
    payload.push(0);
    payload.push(0);
    payload.push(254);
    payload.push(3);
    payload.push(RT_SCOPE_UNIVERSE);
    payload.push(1);
    payload.extend_from_slice(&0u32.to_ne_bytes());
    append_rtattr(&mut payload, RTA_DST, &route.dst);
    append_rtattr(&mut payload, RTA_OIF, &(route.ifindex as u32).to_ne_bytes());
    if let Some(gateway) = route.gateway {
        append_rtattr(&mut payload, RTA_GATEWAY, &gateway);
    }
    build_nlmsg(RTM_NEWROUTE, flags, seq, port_id, &payload)
}

fn build_neigh(neigh: &netdev::NeighEntry, seq: u32, flags: u16, port_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_INET as u8);
    payload.push(0);
    payload.extend_from_slice(&0u16.to_ne_bytes());
    payload.extend_from_slice(&neigh.ifindex.to_ne_bytes());
    payload.extend_from_slice(&0x02u16.to_ne_bytes());
    payload.push(0);
    payload.push(0);
    append_rtattr(&mut payload, NDA_DST, &neigh.dst);
    append_rtattr(&mut payload, NDA_LLADDR, &neigh.lladdr);
    build_nlmsg(RTM_NEWNEIGH, flags, seq, port_id, &payload)
}

fn build_maddr(
    dev: &NetDeviceSnapshot,
    mac: &[u8; 6],
    seq: u32,
    flags: u16,
    port_id: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_UNSPEC as u8);
    payload.push(0);
    payload.extend_from_slice(&dev.link_type.to_ne_bytes());
    payload.extend_from_slice(&dev.ifindex.to_ne_bytes());
    payload.extend_from_slice(&dev.flags.to_ne_bytes());
    payload.extend_from_slice(&u32::MAX.to_ne_bytes());
    append_rtattr(&mut payload, IFLA_ADDRESS_ATTR, mac);
    build_nlmsg(RTM_NEWMULTICAST, flags, seq, port_id, &payload)
}

fn build_qdisc(qdisc: &netdev::QdiscEntry, seq: u32, flags: u16, port_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(AF_UNSPEC as u8);
    payload.extend_from_slice(&[0, 0, 0]);
    payload.extend_from_slice(&qdisc.ifindex.to_ne_bytes());
    payload.extend_from_slice(&qdisc.handle.to_ne_bytes());
    payload.extend_from_slice(&qdisc.parent.to_ne_bytes());
    payload.extend_from_slice(&0u32.to_ne_bytes());
    let mut kind = qdisc.kind.as_bytes().to_vec();
    kind.push(0);
    append_rtattr(&mut payload, TCA_KIND, &kind);
    if !qdisc.options.is_empty() {
        append_rtattr(&mut payload, TCA_OPTIONS, &qdisc.options);
    }
    build_nlmsg(RTM_NEWQDISC, flags, seq, port_id, &payload)
}

// 一条 multipart netlink 应答必须以 NLMSG_DONE 收尾,user 端的 mnl/libnl/glibc
// 都靠看到 DONE 才会停止 recv 循环。Linux 的 DONE 带一个 i32 error 状态,
// iproute2 会按这个长度解析;空 payload 会被判成 "DONE truncated"。
pub(super) fn build_done(seq: u32, port_id: u32) -> Vec<u8> {
    build_nlmsg(NLMSG_DONE, NLM_F_MULTI, seq, port_id, &0i32.to_ne_bytes())
}

fn inet_diag_state_in_mask(state: u8, states: u32) -> bool {
    state < 32 && (states & (1u32 << state)) != 0
}

fn append_inet_diag_addr(payload: &mut Vec<u8>, addr: [u8; 4]) {
    payload.extend_from_slice(&addr);
    payload.extend_from_slice(&[0; 12]);
}

fn build_inet_diag_msg(row: crate::fs::ProcNetSocketSnapshot, seq: u32, port_id: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(INET_DIAG_MSG_LEN);
    payload.push(AF_INET as u8);
    payload.push(row.state);
    payload.push(0);
    payload.push(0);
    payload.extend_from_slice(&row.local_port.to_be_bytes());
    payload.extend_from_slice(&row.remote_port.to_be_bytes());
    append_inet_diag_addr(&mut payload, row.local_addr);
    append_inet_diag_addr(&mut payload, row.remote_addr);
    payload.extend_from_slice(&0u32.to_ne_bytes());
    payload.extend_from_slice(&[0xff; 8]);
    payload.extend_from_slice(&0u32.to_ne_bytes());
    payload.extend_from_slice(&(row.rx_queue as u32).to_ne_bytes());
    payload.extend_from_slice(&(row.tx_queue as u32).to_ne_bytes());
    payload.extend_from_slice(&row.uid.to_ne_bytes());
    payload.extend_from_slice(&(row.inode as u32).to_ne_bytes());
    build_nlmsg(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, seq, port_id, &payload)
}

#[derive(Clone, Copy, Default)]
struct NetlinkAckOptions {
    cap_ack: bool,
    ext_ack: bool,
    strict_chk: bool,
}

/// Netlink sender context carried with each request batch.
///
/// Linux attaches credentials and capabilities to the skb before rtnetlink
/// dispatch. Keeping that state explicit prevents send-side control messages
/// from being validated and then silently ignored.
#[derive(Clone, Copy)]
pub(super) struct NetlinkSender {
    _cred: UCred,
    cap_effective: u64,
}

impl NetlinkSender {
    pub(super) fn current() -> Self {
        let process = current_process();
        let inner = process.borrow_mut();
        Self {
            _cred: UCred {
                pid: process.pid.0 as u32,
                uid: inner.uid,
                gid: inner.gid,
            },
            cap_effective: inner.cap_effective,
        }
    }

    pub(super) fn current_with_credentials(credentials: Option<UCred>) -> Self {
        let mut sender = Self::current();
        if let Some(cred) = credentials {
            sender._cred = cred;
        }
        sender
    }

    fn has_cap(self, cap: usize) -> bool {
        (self.cap_effective & (1u64 << cap)) != 0
    }
}

#[derive(Clone)]
pub(super) struct QueuedNetlinkMessage {
    pub(super) data: Vec<u8>,
    pub(super) nsid: Option<i32>,
    pub(super) group: u32,
}

fn build_ack(
    seq: u32,
    port_id: u32,
    request_msg: &[u8],
    rc: isize,
    options: NetlinkAckOptions,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(rc as i32).to_ne_bytes());
    payload.extend_from_slice(&request_msg[..NLMSG_HDR_LEN.min(request_msg.len())]);
    let capped = rc == 0 || options.cap_ack;
    if rc != 0 && !options.cap_ack && request_msg.len() > NLMSG_HDR_LEN {
        payload.extend_from_slice(&request_msg[NLMSG_HDR_LEN..]);
    }
    let mut flags = if capped { NLM_F_CAPPED } else { 0 };
    if options.ext_ack
        && let Some(msg) = netlink_ext_ack_message(rc)
    {
        let mut msg = Vec::from(msg.as_bytes());
        msg.push(0);
        append_rtattr(&mut payload, NLMSGERR_ATTR_MSG, &msg);
        flags |= NLM_F_ACK_TLVS;
    }
    build_nlmsg(NLMSG_ERROR, flags, seq, port_id, &payload)
}

fn netlink_ext_ack_message(rc: isize) -> Option<&'static str> {
    match rc {
        e if e == err(SyscallError::EINVAL) => Some("Invalid netlink request"),
        e if e == err(SyscallError::EPERM) => Some("Operation requires net admin capability"),
        e if e == err(SyscallError::ENODEV) => Some("Network device not found"),
        e if e == err(SyscallError::EOPNOTSUPP) => Some("Netlink operation is not supported"),
        e if e == err(SyscallError::EEXIST) => Some("Netlink object already exists"),
        e if e == err(SyscallError::ENOENT) => Some("Netlink object does not exist"),
        e if e < 0 => Some("Netlink request failed"),
        _ => None,
    }
}

fn push_ack_if_needed(
    replies: &mut Vec<Vec<u8>>,
    seq: u32,
    port_id: u32,
    request_msg: &[u8],
    msg_flags: u16,
    rc: isize,
    options: NetlinkAckOptions,
) {
    if rc != 0 || (msg_flags & NLM_F_ACK) != 0 {
        replies.push(build_ack(seq, port_id, request_msg, rc, options));
    }
}

fn require_rtnl_net_admin(sender: NetlinkSender) -> Result<(), isize> {
    if sender.has_cap(CAP_NET_ADMIN) {
        Ok(())
    } else {
        Err(err(SyscallError::EPERM))
    }
}

fn ifindex_from_attrs_or_msg(attrs: &[(u16, Vec<u8>)], ifindex: i32) -> Option<i32> {
    if ifindex > 0 {
        return Some(ifindex);
    }
    let name = read_string_attr(attrs, IFLA_IFNAME)?;
    netdev::ifindex_by_name(name)
}

fn target_net_ns_from_attrs(attrs: &[(u16, Vec<u8>)]) -> Result<Option<usize>, isize> {
    if let Some(pid) = read_u32_attr(attrs, IFLA_NET_NS_PID) {
        let Some(process) = pid2process(pid as usize) else {
            return Err(err(SyscallError::ESRCH));
        };
        return Ok(Some(process.net_namespace_id()));
    }

    if let Some(fd) = read_u32_attr(attrs, IFLA_NET_NS_FD) {
        let files = current_files();
        let Some(file) = files.lock().get_file(fd as usize) else {
            return Err(err(SyscallError::EBADF));
        };
        let Some(ns_file) = file.as_any().downcast_ref::<NamespaceFile>() else {
            return Err(err(SyscallError::EINVAL));
        };
        if ns_file.kind() != NamespaceKind::Net {
            return Err(err(SyscallError::EINVAL));
        }
        return Ok(Some(ns_file.ns_id()));
    }

    Ok(None)
}

#[derive(Clone, Copy, Default)]
struct LinkUpdate {
    mtu: Option<u32>,
    tx_queue_len: Option<u32>,
    flags: Option<(u32, u32)>,
}

fn link_update_from_attrs(attrs: &[(u16, Vec<u8>)], flags: u32, change: u32) -> LinkUpdate {
    LinkUpdate {
        mtu: read_u32_attr(attrs, IFLA_MTU),
        tx_queue_len: read_u32_attr(attrs, IFLA_TXQLEN),
        flags: if change != 0 || (flags & IFF_UP) != 0 {
            Some((flags, change))
        } else {
            None
        },
    }
}

fn apply_link_update_by_name_in_namespace(
    ns_id: usize,
    name: &str,
    update: LinkUpdate,
) -> Result<(), isize> {
    if update.mtu.is_none() && update.tx_queue_len.is_none() && update.flags.is_none() {
        return Ok(());
    }
    let ifindex =
        netdev::ifindex_by_name_in_namespace(ns_id, name).ok_or(err(SyscallError::ENODEV))?;
    netdev::set_link_in_namespace(
        ns_id,
        ifindex,
        update.mtu,
        update.tx_queue_len,
        update.flags,
    )
}

fn create_link_with_update_in_namespace(
    ns_id: usize,
    name: &str,
    kind: NetDeviceKind,
    update: LinkUpdate,
    link_ifindex: Option<i32>,
) -> Result<(), isize> {
    netdev::create_link_with_iflink_in_namespace(ns_id, name, kind, link_ifindex)?;
    if let Err(e) = apply_link_update_by_name_in_namespace(ns_id, name, update) {
        let _ = netdev::delete_link_by_name_in_namespace(ns_id, name);
        return Err(e);
    }
    Ok(())
}

fn rollback_created_veth_pair(ns_id: usize, name: &str, peer_ns_id: usize, peer_name: &str) {
    let _ = netdev::delete_link_by_name_in_namespace(peer_ns_id, peer_name);
    let _ = netdev::delete_link_by_name_in_namespace(ns_id, name);
}

fn create_veth_pair_in_namespace(
    ns_id: usize,
    name: &str,
    data_attrs: &[(u16, Vec<u8>)],
    update: LinkUpdate,
) -> Result<(), isize> {
    const VETH_INFO_PEER: u16 = 1;
    let mut peer_name = None;
    let mut peer_ns_id = ns_id;
    let mut peer_update = LinkUpdate::default();
    if let Some((_, data)) = data_attrs
        .iter()
        .find(|(kind, data)| *kind == VETH_INFO_PEER && data.len() >= 16)
    {
        let peer_flags = read_u32_ne(data, 8).unwrap_or(0);
        let peer_change = read_u32_ne(data, 12).unwrap_or(0);
        let peer_attrs = parse_rtattrs_checked(&data[16..])?;
        peer_name = read_string_attr_owned(&peer_attrs, IFLA_IFNAME)
            .or_else(|| find_string_attr_recursive(&peer_attrs, IFLA_IFNAME, 0));
        peer_ns_id = target_net_ns_from_attrs(&peer_attrs)?.unwrap_or(ns_id);
        peer_update = link_update_from_attrs(&peer_attrs, peer_flags, peer_change);
        if peer_name.is_none() {
            let nested = parse_rtattrs_checked(data)?;
            peer_name = find_string_attr_recursive(&nested, IFLA_IFNAME, 0);
        }
    }
    let peer_name = peer_name.unwrap_or_else(|| alloc::format!("{name}p"));
    netdev::create_veth_pair_between_namespaces(ns_id, name, peer_ns_id, &peer_name)?;
    if let Err(e) = apply_link_update_by_name_in_namespace(ns_id, name, update) {
        rollback_created_veth_pair(ns_id, name, peer_ns_id, &peer_name);
        return Err(e);
    }
    if let Err(e) = apply_link_update_by_name_in_namespace(peer_ns_id, &peer_name, peer_update) {
        rollback_created_veth_pair(ns_id, name, peer_ns_id, &peer_name);
        return Err(e);
    }
    Ok(())
}

fn validate_macvlan_data_attrs(data_attrs: &[(u16, Vec<u8>)]) -> Result<(), isize> {
    if let Some(mode) = read_u32_attr_checked(data_attrs, IFLA_MACVLAN_MODE)?
        && !matches!(
            mode,
            MACVLAN_MODE_PRIVATE
                | MACVLAN_MODE_VEPA
                | MACVLAN_MODE_BRIDGE
                | MACVLAN_MODE_PASSTHRU
                | MACVLAN_MODE_SOURCE
        )
    {
        return Err(err(SyscallError::EINVAL));
    }
    if let Some(flags) = read_u16_attr_checked(data_attrs, IFLA_MACVLAN_FLAGS)?
        && (flags & !(MACVLAN_FLAG_NOPROMISC | MACVLAN_FLAG_NODST)) != 0
    {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(())
}

fn validate_ipvlan_data_attrs(data_attrs: &[(u16, Vec<u8>)]) -> Result<(), isize> {
    if let Some(mode) = read_u16_attr_checked(data_attrs, IFLA_IPVLAN_MODE)?
        && !matches!(mode, IPVLAN_MODE_L2 | IPVLAN_MODE_L3 | IPVLAN_MODE_L3S)
    {
        return Err(err(SyscallError::EINVAL));
    }
    if let Some(flags) = read_u16_attr_checked(data_attrs, IFLA_IPVLAN_FLAGS)?
        && (flags & !(IPVLAN_F_PRIVATE | IPVLAN_F_VEPA)) != 0
    {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(())
}

fn handle_new_or_set_link(msg_type: u16, payload: &[u8]) -> Result<(), isize> {
    if payload.len() < 16 {
        return Err(err(SyscallError::EINVAL));
    }
    let ifindex = read_i32_ne(payload, 4).unwrap_or(0);
    let flags = read_u32_ne(payload, 8).unwrap_or(0);
    let change = read_u32_ne(payload, 12).unwrap_or(0);
    let attrs = parse_rtattrs_checked(&payload[16..])?;
    let link_update = link_update_from_attrs(&attrs, flags, change);
    let linkinfo = nested_attrs_checked(&attrs, IFLA_LINKINFO)?;
    let mut info_data = nested_attrs_checked(&linkinfo, IFLA_INFO_DATA)?;
    if info_data.is_empty() {
        info_data = find_nested_attrs_recursive(&attrs, IFLA_INFO_DATA, 0);
    }

    if msg_type == RTM_NEWLINK && ifindex == 0 && attrs.is_empty() {
        return Err(err(SyscallError::EINVAL));
    }

    let target_ns_id = target_net_ns_from_attrs(&attrs)?;

    if msg_type == RTM_NEWLINK {
        let kind = read_string_attr_owned(&linkinfo, IFLA_INFO_KIND)
            .or_else(|| find_link_kind_recursive(&attrs, 0));
        if let Some(kind) = kind {
            let name = read_string_attr(&attrs, IFLA_IFNAME).ok_or(err(SyscallError::EINVAL))?;
            let create_ns_id = target_ns_id.unwrap_or_else(|| current_process().net_namespace_id());
            // Linux 将 `ip link add ... netns ... type ...` 创建在目标 netns；
            // 只有没有 type/kind 的 NEWLINK/SETLINK 才表示移动已有设备。
            match kind.as_str() {
                "dummy" => {
                    return create_link_with_update_in_namespace(
                        create_ns_id,
                        name,
                        NetDeviceKind::Dummy,
                        link_update,
                        None,
                    );
                }
                "veth" => {
                    return create_veth_pair_in_namespace(
                        create_ns_id,
                        name,
                        &info_data,
                        link_update,
                    );
                }
                "macvlan" => {
                    let Some(lower_ifindex) = read_u32_attr_checked(&attrs, IFLA_LINK)? else {
                        return Err(err(SyscallError::EINVAL));
                    };
                    let lower_ifindex =
                        i32::try_from(lower_ifindex).map_err(|_| err(SyscallError::ENODEV))?;
                    validate_macvlan_data_attrs(&info_data)?;
                    return create_link_with_update_in_namespace(
                        create_ns_id,
                        name,
                        NetDeviceKind::Macvlan,
                        link_update,
                        Some(lower_ifindex),
                    );
                }
                "ipvlan" => {
                    let Some(lower_ifindex) = read_u32_attr_checked(&attrs, IFLA_LINK)? else {
                        return Err(err(SyscallError::EINVAL));
                    };
                    let lower_ifindex =
                        i32::try_from(lower_ifindex).map_err(|_| err(SyscallError::ENODEV))?;
                    validate_ipvlan_data_attrs(&info_data)?;
                    return create_link_with_update_in_namespace(
                        create_ns_id,
                        name,
                        NetDeviceKind::Ipvlan,
                        link_update,
                        Some(lower_ifindex),
                    );
                }
                "macvtap" => {
                    let Some(lower_ifindex) = read_u32_attr_checked(&attrs, IFLA_LINK)? else {
                        return Err(err(SyscallError::EINVAL));
                    };
                    let lower_ifindex =
                        i32::try_from(lower_ifindex).map_err(|_| err(SyscallError::ENODEV))?;
                    validate_macvlan_data_attrs(&info_data)?;
                    return create_link_with_update_in_namespace(
                        create_ns_id,
                        name,
                        NetDeviceKind::Macvtap,
                        link_update,
                        Some(lower_ifindex),
                    );
                }
                "wireguard" => {
                    if read_u32_attr_checked(&attrs, IFLA_LINK)?.is_some() {
                        return Err(err(SyscallError::EINVAL));
                    }
                    return create_link_with_update_in_namespace(
                        create_ns_id,
                        name,
                        NetDeviceKind::Wireguard,
                        link_update,
                        None,
                    );
                }
                _ => return Err(err(SyscallError::EOPNOTSUPP)),
            }
        }
    }

    if let Some(target_ns_id) = target_ns_id {
        let ifindex =
            ifindex_from_attrs_or_msg(&attrs, ifindex).ok_or(err(SyscallError::ENODEV))?;
        let new_name = (msg_type == RTM_SETLINK)
            .then(|| read_string_attr(&attrs, IFLA_IFNAME))
            .flatten();
        return netdev::move_link_to_namespace_with_name(ifindex, target_ns_id, new_name);
    }

    let ifindex = ifindex_from_attrs_or_msg(&attrs, ifindex).ok_or(err(SyscallError::ENODEV))?;
    let new_name = (msg_type == RTM_SETLINK)
        .then(|| read_string_attr(&attrs, IFLA_IFNAME))
        .flatten();
    netdev::set_link_with_name(
        ifindex,
        new_name,
        link_update.mtu,
        link_update.tx_queue_len,
        link_update.flags,
    )
}

fn handle_del_link(payload: &[u8]) -> Result<(), isize> {
    if payload.len() < 16 {
        return Err(err(SyscallError::EINVAL));
    }
    let ifindex = read_i32_ne(payload, 4).unwrap_or(0);
    let attrs = parse_rtattrs_checked(&payload[16..])?;
    let ifindex = ifindex_from_attrs_or_msg(&attrs, ifindex).ok_or(err(SyscallError::ENODEV))?;
    netdev::delete_link_by_index(ifindex)?;
    super::wireguard::remove_config(ifindex);
    Ok(())
}

fn handle_addr(msg_type: u16, payload: &[u8]) -> Result<(), isize> {
    if payload.len() < 8 {
        return Err(err(SyscallError::EINVAL));
    }
    let family = payload[0] as u16;
    let prefix_len = payload[1];
    let scope = payload[3];
    let ifindex = read_u32_ne(payload, 4).unwrap_or(0) as i32;
    let attrs = parse_rtattrs_checked(&payload[8..])?;
    if family == AF_INET6 {
        let local_addr = read_ipv6_attr_checked(&attrs, IFA_LOCAL)?
            .or(read_ipv6_attr_checked(&attrs, IFA_ADDRESS)?);
        let label = read_string_attr(&attrs, IFA_LABEL);
        return match msg_type {
            RTM_NEWADDR => {
                let local_addr = local_addr.ok_or(err(SyscallError::EINVAL))?;
                netdev::add_ipv6_addr_with_attrs(ifindex, local_addr, prefix_len, scope, label)
            }
            RTM_DELADDR => {
                if let Some(addr) = local_addr {
                    netdev::del_ipv6_addr(ifindex, addr, prefix_len)
                } else {
                    netdev::flush_ipv6_addrs(ifindex)
                }
            }
            _ => Err(err(SyscallError::EINVAL)),
        };
    }
    require_ipv4_rtnl_family(payload)?;
    let local_addr =
        read_ipv4_attr_checked(&attrs, IFA_LOCAL)?.or(read_ipv4_attr_checked(&attrs, IFA_ADDRESS)?);
    let peer_addr = read_ipv4_attr_checked(&attrs, IFA_ADDRESS)?.or(local_addr);
    let broadcast_addr = read_ipv4_attr_checked(&attrs, IFA_BROADCAST)?;
    let label = read_string_attr(&attrs, IFA_LABEL);
    match msg_type {
        RTM_NEWADDR => {
            let local_addr = local_addr.ok_or(err(SyscallError::EINVAL))?;
            let peer_addr = peer_addr.unwrap_or(local_addr);
            netdev::add_ipv4_addr_with_attrs(
                ifindex,
                local_addr,
                peer_addr,
                prefix_len,
                broadcast_addr,
                scope,
                label,
            )
        }
        RTM_DELADDR => {
            if let Some(addr) = local_addr {
                netdev::del_ipv4_addr(ifindex, addr, prefix_len)
            } else {
                netdev::flush_ipv4_addrs(ifindex)
            }
        }
        _ => Err(err(SyscallError::EINVAL)),
    }
}

fn infer_route_ifindex(gateway: Option<[u8; 4]>) -> Result<i32, isize> {
    let ns_id = current_process().net_namespace_id();
    if gateway.is_some_and(|addr| addr[0] == 127) {
        return netdev::ifindex_by_name_in_namespace(ns_id, "lo").ok_or(err(SyscallError::ENODEV));
    }
    netdev::route_ifindex_for_gateway_in_namespace(ns_id, gateway).ok_or(err(SyscallError::ENODEV))
}

fn handle_route(msg_type: u16, msg_flags: u16, payload: &[u8]) -> Result<(), isize> {
    if payload.len() < 12 {
        return Err(err(SyscallError::EINVAL));
    }
    require_ipv4_rtnl_family(payload)?;
    let prefix_len = payload[1];
    let attrs = parse_rtattrs_checked(&payload[12..])?;
    let requested_dst = read_ipv4_attr_checked(&attrs, RTA_DST)?;
    let dst = requested_dst.unwrap_or([0; 4]);
    let gateway = read_ipv4_attr_checked(&attrs, RTA_GATEWAY)?;
    let requested_ifindex = read_u32_attr(&attrs, RTA_OIF).map(|v| v as i32);
    let ifindex = match requested_ifindex {
        Some(ifindex) => ifindex,
        None => infer_route_ifindex(gateway)?,
    };
    match msg_type {
        RTM_NEWROUTE => netdev::add_route(
            dst,
            prefix_len,
            gateway,
            ifindex,
            (msg_flags & NLM_F_CREATE) != 0,
            (msg_flags & NLM_F_REPLACE) != 0,
            (msg_flags & NLM_F_EXCL) != 0,
        ),
        RTM_DELROUTE => {
            if requested_dst.is_none() && gateway.is_none() {
                netdev::flush_routes(requested_ifindex.unwrap_or(0))
            } else {
                netdev::del_route(dst, prefix_len, gateway, requested_ifindex)
            }
        }
        _ => Err(err(SyscallError::EINVAL)),
    }
}

fn handle_neigh(msg_type: u16, payload: &[u8]) -> Result<(), isize> {
    if payload.len() < 12 {
        return Err(err(SyscallError::EINVAL));
    }
    require_ipv4_rtnl_family(payload)?;
    let ifindex = read_i32_ne(payload, 4).unwrap_or(0);
    let attrs = parse_rtattrs_checked(&payload[12..])?;
    let dst = read_ipv4_attr_checked(&attrs, NDA_DST)?.ok_or(err(SyscallError::EINVAL))?;
    match msg_type {
        RTM_NEWNEIGH => {
            let lladdr = read_mac_attr(&attrs, NDA_LLADDR).ok_or(err(SyscallError::EINVAL))?;
            netdev::add_neigh(ifindex, dst, lladdr)
        }
        RTM_DELNEIGH => netdev::del_neigh(ifindex, dst),
        _ => Err(err(SyscallError::EINVAL)),
    }
}

fn handle_maddr(msg_type: u16, payload: &[u8]) -> Result<(), isize> {
    if payload.len() < 16 {
        return Err(err(SyscallError::EINVAL));
    }
    let ifindex = read_i32_ne(payload, 4).unwrap_or(0);
    let attrs = parse_rtattrs_checked(&payload[16..])?;
    let mac = read_mac_attr(&attrs, IFLA_ADDRESS_ATTR).ok_or(err(SyscallError::EINVAL))?;
    match msg_type {
        RTM_NEWMULTICAST => netdev::add_maddr(ifindex, mac),
        RTM_DELMULTICAST => netdev::del_maddr(ifindex, mac),
        _ => Err(err(SyscallError::EINVAL)),
    }
}

fn handle_qdisc(msg_type: u16, msg_flags: u16, payload: &[u8]) -> Result<(), isize> {
    if payload.len() < 20 {
        return Err(err(SyscallError::EINVAL));
    }
    let ifindex = read_i32_ne(payload, 4).unwrap_or(0);
    if ifindex <= 0 {
        return Err(err(SyscallError::ENODEV));
    }
    let handle = read_u32_ne(payload, 8).unwrap_or(0);
    let parent = read_u32_ne(payload, 12).unwrap_or(0);
    let attrs = parse_rtattrs_checked(&payload[20..])?;
    let kind = read_string_attr(&attrs, TCA_KIND);
    match msg_type {
        RTM_NEWQDISC => {
            let kind = kind.ok_or(err(SyscallError::EINVAL))?;
            let options = attrs
                .iter()
                .find(|(attr, _)| *attr == TCA_OPTIONS)
                .map(|(_, data)| data.clone())
                .unwrap_or_default();
            netdev::set_qdisc(
                ifindex,
                handle,
                if parent == 0 { TC_H_ROOT } else { parent },
                kind,
                options,
                (msg_flags & NLM_F_CREATE) != 0,
                (msg_flags & NLM_F_REPLACE) != 0,
                (msg_flags & NLM_F_EXCL) != 0,
            )
        }
        RTM_DELQDISC => {
            netdev::delete_qdisc(ifindex, if parent == 0 { TC_H_ROOT } else { parent }, kind)
        }
        _ => Err(err(SyscallError::EINVAL)),
    }
}

fn dump_links(seq: u32, port_id: u32) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    for dev in netdev::devices_snapshot() {
        replies.push(build_link(&dev, seq, NLM_F_MULTI, port_id));
    }
    replies.push(build_done(seq, port_id));
    replies
}

fn dump_links_for_request(
    payload: &[u8],
    seq: u32,
    port_id: u32,
    strict_chk: bool,
) -> Result<Vec<Vec<u8>>, isize> {
    if payload.len() < 16 {
        return if strict_chk {
            Err(err(SyscallError::EINVAL))
        } else {
            Ok(dump_links(seq, port_id))
        };
    }
    if strict_chk
        && (payload[1] != 0
            || read_u16_ne(payload, 2).unwrap_or(0) != 0
            || read_u32_ne(payload, 8).unwrap_or(0) != 0
            || read_u32_ne(payload, 12).unwrap_or(0) != 0)
    {
        return Err(err(SyscallError::EINVAL));
    }
    let ifindex = read_i32_ne(payload, 4).unwrap_or(0);
    let attrs = if strict_chk {
        parse_rtattrs_checked(&payload[16..])?
    } else {
        parse_rtattrs(&payload[16..])
    };
    let name = read_string_attr(&attrs, IFLA_IFNAME);
    let mut replies = Vec::new();
    for dev in netdev::devices_snapshot() {
        let index_matches = ifindex <= 0 || dev.ifindex == ifindex;
        let name_matches = name.is_none_or(|requested| dev.name == requested);
        if index_matches && name_matches {
            replies.push(build_link(&dev, seq, NLM_F_MULTI, port_id));
        }
    }
    replies.push(build_done(seq, port_id));
    Ok(replies)
}

fn dump_addrs(seq: u32, port_id: u32) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    for dev in netdev::devices_snapshot() {
        for addr in &dev.addrs {
            replies.push(build_addr(&dev, addr, seq, NLM_F_MULTI, port_id));
        }
        for addr in &dev.addrs6 {
            replies.push(build_addr6(&dev, addr, seq, NLM_F_MULTI, port_id));
        }
    }
    replies.push(build_done(seq, port_id));
    replies
}

fn dump_addrs_for_request(
    payload: &[u8],
    seq: u32,
    port_id: u32,
    strict_chk: bool,
) -> Result<Vec<Vec<u8>>, isize> {
    if payload.is_empty() {
        return Ok(dump_addrs(seq, port_id));
    }
    if payload.len() < 8 {
        return if strict_chk {
            Err(err(SyscallError::EINVAL))
        } else {
            Ok(dump_addrs(seq, port_id))
        };
    }
    if payload[0] == AF_INET6 as u8 {
        let ifindex = read_u32_ne(payload, 4).unwrap_or(0) as i32;
        let attrs = if strict_chk {
            parse_rtattrs_checked(&payload[8..])?
        } else {
            parse_rtattrs(&payload[8..])
        };
        let requested_addr =
            read_ipv6_attr(&attrs, IFA_LOCAL).or_else(|| read_ipv6_attr(&attrs, IFA_ADDRESS));
        let requested_label = read_string_attr(&attrs, IFA_LABEL);
        let mut replies = Vec::new();
        for dev in netdev::devices_snapshot() {
            if ifindex > 0 && dev.ifindex != ifindex {
                continue;
            }
            for addr in &dev.addrs6 {
                if requested_label
                    .is_some_and(|label| addr.label.as_deref().unwrap_or(&dev.name) != label)
                {
                    continue;
                }
                if requested_addr.is_none_or(|wanted| wanted == addr.addr) {
                    replies.push(build_addr6(&dev, addr, seq, NLM_F_MULTI, port_id));
                }
            }
        }
        replies.push(build_done(seq, port_id));
        return Ok(replies);
    }
    if !supports_ipv4_rtnl_family(payload[0]) {
        return Ok(done_only(seq, port_id));
    }
    let ifindex = read_u32_ne(payload, 4).unwrap_or(0) as i32;
    let attrs = if strict_chk {
        parse_rtattrs_checked(&payload[8..])?
    } else {
        parse_rtattrs(&payload[8..])
    };
    let requested_addr =
        read_ipv4_attr(&attrs, IFA_LOCAL).or_else(|| read_ipv4_attr(&attrs, IFA_ADDRESS));
    let requested_label = read_string_attr(&attrs, IFA_LABEL);
    let mut replies = Vec::new();
    for dev in netdev::devices_snapshot() {
        if ifindex > 0 && dev.ifindex != ifindex {
            continue;
        }
        for addr in &dev.addrs {
            if requested_label
                .is_some_and(|label| netdev::ipv4_addr_label(&dev.name, addr) != label)
            {
                continue;
            }
            if requested_addr.is_none_or(|wanted| wanted == addr.addr || wanted == addr.peer_addr) {
                replies.push(build_addr(&dev, addr, seq, NLM_F_MULTI, port_id));
            }
        }
    }
    replies.push(build_done(seq, port_id));
    Ok(replies)
}

fn dump_routes(seq: u32, port_id: u32) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    for route in netdev::routes_snapshot() {
        replies.push(build_route(&route, seq, NLM_F_MULTI, port_id));
    }
    replies.push(build_done(seq, port_id));
    replies
}

fn dump_routes_for_request(
    payload: &[u8],
    seq: u32,
    port_id: u32,
    strict_chk: bool,
) -> Result<Vec<Vec<u8>>, isize> {
    if payload.len() < 12 {
        return if strict_chk {
            Err(err(SyscallError::EINVAL))
        } else {
            Ok(dump_routes(seq, port_id))
        };
    }
    if !supports_ipv4_rtnl_family(payload[0]) {
        return Ok(done_only(seq, port_id));
    }
    let prefix_len = payload[1];
    let attrs = if strict_chk {
        parse_rtattrs_checked(&payload[12..])?
    } else {
        parse_rtattrs(&payload[12..])
    };
    let requested_dst = read_ipv4_attr(&attrs, RTA_DST);
    let requested_gateway = read_ipv4_attr(&attrs, RTA_GATEWAY);
    let requested_ifindex = read_u32_attr(&attrs, RTA_OIF).map(|v| v as i32);
    let mut replies = Vec::new();
    for route in netdev::routes_snapshot() {
        if requested_ifindex.is_some_and(|ifindex| route.ifindex != ifindex) {
            continue;
        }
        if requested_dst.is_some_and(|dst| route.dst != dst || route.prefix_len != prefix_len) {
            continue;
        }
        if requested_gateway.is_some_and(|gateway| route.gateway != Some(gateway)) {
            continue;
        }
        replies.push(build_route(&route, seq, NLM_F_MULTI, port_id));
    }
    replies.push(build_done(seq, port_id));
    Ok(replies)
}

fn dump_neighs(seq: u32, port_id: u32) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    for neigh in netdev::neighs_snapshot() {
        replies.push(build_neigh(&neigh, seq, NLM_F_MULTI, port_id));
    }
    replies.push(build_done(seq, port_id));
    replies
}

fn dump_neighs_for_request(
    payload: &[u8],
    seq: u32,
    port_id: u32,
    strict_chk: bool,
) -> Result<Vec<Vec<u8>>, isize> {
    if payload.len() < 12 {
        return if strict_chk {
            Err(err(SyscallError::EINVAL))
        } else {
            Ok(dump_neighs(seq, port_id))
        };
    }
    if !supports_ipv4_rtnl_family(payload[0]) {
        return Ok(done_only(seq, port_id));
    }
    let ifindex = read_i32_ne(payload, 4).unwrap_or(0);
    let attrs = if strict_chk {
        parse_rtattrs_checked(&payload[12..])?
    } else {
        parse_rtattrs(&payload[12..])
    };
    let requested_dst = read_ipv4_attr(&attrs, NDA_DST);
    let mut replies = Vec::new();
    for neigh in netdev::neighs_snapshot() {
        if ifindex > 0 && neigh.ifindex != ifindex {
            continue;
        }
        if requested_dst.is_none_or(|wanted| wanted == neigh.dst) {
            replies.push(build_neigh(&neigh, seq, NLM_F_MULTI, port_id));
        }
    }
    replies.push(build_done(seq, port_id));
    Ok(replies)
}

fn dump_maddrs_for_request(
    payload: &[u8],
    seq: u32,
    port_id: u32,
    strict_chk: bool,
) -> Result<Vec<Vec<u8>>, isize> {
    if strict_chk && payload.len() < 16 {
        return Err(err(SyscallError::EINVAL));
    }
    let ifindex = if payload.len() >= 16 {
        if strict_chk {
            parse_rtattrs_checked(&payload[16..])?;
        }
        read_i32_ne(payload, 4).unwrap_or(0)
    } else {
        0
    };
    let mut replies = Vec::new();
    for dev in netdev::devices_snapshot() {
        if ifindex > 0 && dev.ifindex != ifindex {
            continue;
        }
        for mac in &dev.maddrs {
            replies.push(build_maddr(&dev, mac, seq, NLM_F_MULTI, port_id));
        }
    }
    replies.push(build_done(seq, port_id));
    Ok(replies)
}

fn dump_qdiscs(seq: u32, port_id: u32) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    for qdisc in netdev::qdiscs_snapshot() {
        replies.push(build_qdisc(&qdisc, seq, NLM_F_MULTI, port_id));
    }
    replies.push(build_done(seq, port_id));
    replies
}

fn dump_qdiscs_for_request(
    payload: &[u8],
    seq: u32,
    port_id: u32,
    strict_chk: bool,
) -> Result<Vec<Vec<u8>>, isize> {
    if payload.len() < 20 {
        return if strict_chk {
            Err(err(SyscallError::EINVAL))
        } else {
            Ok(dump_qdiscs(seq, port_id))
        };
    }
    if payload[0] != AF_UNSPEC as u8 {
        return Ok(done_only(seq, port_id));
    }
    let ifindex = read_i32_ne(payload, 4).unwrap_or(0);
    let attrs = if strict_chk {
        parse_rtattrs_checked(&payload[20..])?
    } else {
        parse_rtattrs(&payload[20..])
    };
    let requested_kind = read_string_attr(&attrs, TCA_KIND);
    let mut replies = Vec::new();
    for qdisc in netdev::qdiscs_snapshot() {
        if ifindex > 0 && qdisc.ifindex != ifindex {
            continue;
        }
        if requested_kind.is_some_and(|kind| qdisc.kind != kind) {
            continue;
        }
        replies.push(build_qdisc(&qdisc, seq, NLM_F_MULTI, port_id));
    }
    replies.push(build_done(seq, port_id));
    Ok(replies)
}

fn push_rtnl_result(
    replies: &mut Vec<Vec<u8>>,
    result: Result<Vec<Vec<u8>>, isize>,
    seq: u32,
    port_id: u32,
    request_msg: &[u8],
    msg_flags: u16,
    ack_options: NetlinkAckOptions,
) {
    match result {
        Ok(mut messages) => replies.append(&mut messages),
        Err(rc) => push_ack_if_needed(
            replies,
            seq,
            port_id,
            request_msg,
            msg_flags | NLM_F_ACK,
            rc,
            ack_options,
        ),
    }
}

// rtnetlink 应答总调度。
//
// Linux 的 `ip`/`netstat` 通过 rtnetlink 操作一个统一的 net_device 表。
// 这里不实现真实发包路径，但保持同一个可变设备表，并给变更类请求返回
// NLMSG_ERROR(error=0) 形式的 ACK，避免 user 端一直等待确认。
fn build_route_netlink_replies(
    request: &[u8],
    port_id: u32,
    ack_options: NetlinkAckOptions,
    sender: NetlinkSender,
) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    let mut offset = 0usize;
    while offset + NLMSG_HDR_LEN <= request.len() {
        let Some(nlmsg_len) = read_u32_ne(request, offset).map(|v| v as usize) else {
            break;
        };
        if nlmsg_len < NLMSG_HDR_LEN || offset + nlmsg_len > request.len() {
            // iproute2 sometimes passes a buffer larger than nlmsg_len and
            // leaves the tail zero-filled. Linux stops at that padding instead
            // of treating it as a second malformed message.
            if request[offset..].iter().all(|b| *b == 0) {
                break;
            }
            let msg_flags = read_u16_ne(request, offset + 6).unwrap_or(0);
            let seq = read_u32_ne(request, offset + 8).unwrap_or(0);
            let request_msg = &request[offset..offset + NLMSG_HDR_LEN];
            push_ack_if_needed(
                &mut replies,
                seq,
                port_id,
                request_msg,
                msg_flags | NLM_F_ACK,
                err(SyscallError::EINVAL),
                ack_options,
            );
            break;
        }
        let msg_type = read_u16_ne(request, offset + 4).unwrap_or(0);
        let msg_flags = read_u16_ne(request, offset + 6).unwrap_or(0);
        let seq = read_u32_ne(request, offset + 8).unwrap_or(0);
        let request_msg = &request[offset..offset + nlmsg_len];
        let payload = &request[offset + NLMSG_HDR_LEN..offset + nlmsg_len];
        match msg_type {
            RTM_GETLINK => push_rtnl_result(
                &mut replies,
                dump_links_for_request(payload, seq, port_id, ack_options.strict_chk),
                seq,
                port_id,
                request_msg,
                msg_flags,
                ack_options,
            ),
            RTM_GETADDR => push_rtnl_result(
                &mut replies,
                dump_addrs_for_request(payload, seq, port_id, ack_options.strict_chk),
                seq,
                port_id,
                request_msg,
                msg_flags,
                ack_options,
            ),
            RTM_GETROUTE => push_rtnl_result(
                &mut replies,
                dump_routes_for_request(payload, seq, port_id, ack_options.strict_chk),
                seq,
                port_id,
                request_msg,
                msg_flags,
                ack_options,
            ),
            RTM_GETNEIGH => push_rtnl_result(
                &mut replies,
                dump_neighs_for_request(payload, seq, port_id, ack_options.strict_chk),
                seq,
                port_id,
                request_msg,
                msg_flags,
                ack_options,
            ),
            RTM_GETMULTICAST => push_rtnl_result(
                &mut replies,
                dump_maddrs_for_request(payload, seq, port_id, ack_options.strict_chk),
                seq,
                port_id,
                request_msg,
                msg_flags,
                ack_options,
            ),
            RTM_GETQDISC => push_rtnl_result(
                &mut replies,
                dump_qdiscs_for_request(payload, seq, port_id, ack_options.strict_chk),
                seq,
                port_id,
                request_msg,
                msg_flags,
                ack_options,
            ),
            RTM_NEWLINK | RTM_SETLINK => {
                let rc = match require_rtnl_net_admin(sender)
                    .and_then(|_| handle_new_or_set_link(msg_type, payload))
                {
                    Ok(()) => 0,
                    Err(e) => e,
                };
                push_ack_if_needed(
                    &mut replies,
                    seq,
                    port_id,
                    request_msg,
                    msg_flags,
                    rc,
                    ack_options,
                );
            }
            RTM_DELLINK => {
                let rc = match require_rtnl_net_admin(sender).and_then(|_| handle_del_link(payload))
                {
                    Ok(()) => 0,
                    Err(e) => e,
                };
                push_ack_if_needed(
                    &mut replies,
                    seq,
                    port_id,
                    request_msg,
                    msg_flags,
                    rc,
                    ack_options,
                );
            }
            RTM_NEWADDR | RTM_DELADDR => {
                let rc = match require_rtnl_net_admin(sender)
                    .and_then(|_| handle_addr(msg_type, payload))
                {
                    Ok(()) => 0,
                    Err(e) => e,
                };
                push_ack_if_needed(
                    &mut replies,
                    seq,
                    port_id,
                    request_msg,
                    msg_flags,
                    rc,
                    ack_options,
                );
            }
            RTM_NEWROUTE | RTM_DELROUTE => {
                let rc = match require_rtnl_net_admin(sender)
                    .and_then(|_| handle_route(msg_type, msg_flags, payload))
                {
                    Ok(()) => 0,
                    Err(e) => e,
                };
                push_ack_if_needed(
                    &mut replies,
                    seq,
                    port_id,
                    request_msg,
                    msg_flags,
                    rc,
                    ack_options,
                );
            }
            RTM_NEWNEIGH | RTM_DELNEIGH => {
                let rc = match require_rtnl_net_admin(sender)
                    .and_then(|_| handle_neigh(msg_type, payload))
                {
                    Ok(()) => 0,
                    Err(e) => e,
                };
                push_ack_if_needed(
                    &mut replies,
                    seq,
                    port_id,
                    request_msg,
                    msg_flags,
                    rc,
                    ack_options,
                );
            }
            RTM_NEWMULTICAST | RTM_DELMULTICAST => {
                let rc = match require_rtnl_net_admin(sender)
                    .and_then(|_| handle_maddr(msg_type, payload))
                {
                    Ok(()) => 0,
                    Err(e) => e,
                };
                push_ack_if_needed(
                    &mut replies,
                    seq,
                    port_id,
                    request_msg,
                    msg_flags,
                    rc,
                    ack_options,
                );
            }
            RTM_NEWQDISC | RTM_DELQDISC => {
                let rc = match require_rtnl_net_admin(sender)
                    .and_then(|_| handle_qdisc(msg_type, msg_flags, payload))
                {
                    Ok(()) => 0,
                    Err(e) => e,
                };
                push_ack_if_needed(
                    &mut replies,
                    seq,
                    port_id,
                    request_msg,
                    msg_flags,
                    rc,
                    ack_options,
                );
            }
            _ => replies.push(build_ack(
                seq,
                port_id,
                request_msg,
                err(SyscallError::EOPNOTSUPP),
                ack_options,
            )),
        }
        offset += align_to(nlmsg_len, NLMSG_ALIGNTO);
    }
    replies
}

fn build_sock_diag_replies(
    request: &[u8],
    port_id: u32,
    ack_options: NetlinkAckOptions,
) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    let mut offset = 0usize;
    while offset + NLMSG_HDR_LEN <= request.len() {
        let Some(nlmsg_len) = read_u32_ne(request, offset).map(|v| v as usize) else {
            break;
        };
        if nlmsg_len < NLMSG_HDR_LEN || offset + nlmsg_len > request.len() {
            if request[offset..].iter().all(|b| *b == 0) {
                break;
            }
            let msg_flags = read_u16_ne(request, offset + 6).unwrap_or(0);
            let seq = read_u32_ne(request, offset + 8).unwrap_or(0);
            let request_msg = &request[offset..offset + NLMSG_HDR_LEN];
            push_ack_if_needed(
                &mut replies,
                seq,
                port_id,
                request_msg,
                msg_flags | NLM_F_ACK,
                err(SyscallError::EINVAL),
                ack_options,
            );
            break;
        }

        let msg_type = read_u16_ne(request, offset + 4).unwrap_or(0);
        let msg_flags = read_u16_ne(request, offset + 6).unwrap_or(0);
        let seq = read_u32_ne(request, offset + 8).unwrap_or(0);
        let request_msg = &request[offset..offset + nlmsg_len];
        let payload = &request[offset + NLMSG_HDR_LEN..offset + nlmsg_len];

        if msg_type != SOCK_DIAG_BY_FAMILY || payload.len() < INET_DIAG_REQ_V2_MIN_LEN {
            replies.push(build_ack(
                seq,
                port_id,
                request_msg,
                err(SyscallError::EOPNOTSUPP),
                ack_options,
            ));
            offset += align_to(nlmsg_len, NLMSG_ALIGNTO);
            continue;
        }

        let family = payload[0];
        let protocol = payload[1];
        let states = read_u32_ne(payload, 4).unwrap_or(0);
        if family != AF_INET as u8 || protocol != IPPROTO_TCP as u8 {
            replies.push(build_ack(
                seq,
                port_id,
                request_msg,
                err(SyscallError::EOPNOTSUPP),
                ack_options,
            ));
            offset += align_to(nlmsg_len, NLMSG_ALIGNTO);
            continue;
        }

        for row in netdev::proc_net_tcp_snapshots() {
            if inet_diag_state_in_mask(row.state, states) {
                replies.push(build_inet_diag_msg(row, seq, port_id));
            }
        }
        replies.push(build_done(seq, port_id));
        if (msg_flags & NLM_F_ACK) != 0 {
            replies.push(build_ack(seq, port_id, request_msg, 0, ack_options));
        }
        offset += align_to(nlmsg_len, NLMSG_ALIGNTO);
    }
    replies
}

fn build_generic_netlink_replies(
    request: &[u8],
    port_id: u32,
    ack_options: NetlinkAckOptions,
) -> Vec<Vec<u8>> {
    let mut replies = Vec::new();
    let mut offset = 0usize;
    while offset + NLMSG_HDR_LEN <= request.len() {
        let Some(nlmsg_len) = read_u32_ne(request, offset).map(|v| v as usize) else {
            break;
        };
        if nlmsg_len < NLMSG_HDR_LEN || offset + nlmsg_len > request.len() {
            if request[offset..].iter().all(|b| *b == 0) {
                break;
            }
            let msg_flags = read_u16_ne(request, offset + 6).unwrap_or(0);
            let seq = read_u32_ne(request, offset + 8).unwrap_or(0);
            let request_msg = &request[offset..offset + NLMSG_HDR_LEN];
            push_ack_if_needed(
                &mut replies,
                seq,
                port_id,
                request_msg,
                msg_flags | NLM_F_ACK,
                err(SyscallError::EINVAL),
                ack_options,
            );
            break;
        }

        let msg_type = read_u16_ne(request, offset + 4).unwrap_or(0);
        let msg_flags = read_u16_ne(request, offset + 6).unwrap_or(0);
        let seq = read_u32_ne(request, offset + 8).unwrap_or(0);
        let request_msg = &request[offset..offset + nlmsg_len];
        let payload = &request[offset + NLMSG_HDR_LEN..offset + nlmsg_len];
        let rc = if payload.len() < GENL_HDR_LEN {
            err(SyscallError::EINVAL)
        } else if msg_type == GENL_ID_CTRL && payload[0] == CTRL_CMD_GETFAMILY {
            let attrs = if ack_options.strict_chk {
                match parse_rtattrs_checked(&payload[GENL_HDR_LEN..]) {
                    Ok(attrs) => attrs,
                    Err(e) => {
                        push_ack_if_needed(
                            &mut replies,
                            seq,
                            port_id,
                            request_msg,
                            msg_flags | NLM_F_ACK,
                            e,
                            ack_options,
                        );
                        offset += align_to(nlmsg_len, NLMSG_ALIGNTO);
                        continue;
                    }
                }
            } else {
                parse_rtattrs(&payload[GENL_HDR_LEN..])
            };
            if super::wireguard::is_family_request(&attrs) {
                replies.push(super::wireguard::build_family_msg(seq, port_id));
                0
            } else {
                err(SyscallError::ENOENT)
            }
        } else if msg_type == super::wireguard::GENL_FAMILY_ID {
            let attrs = if ack_options.strict_chk {
                match parse_rtattrs_checked(&payload[GENL_HDR_LEN..]) {
                    Ok(attrs) => attrs,
                    Err(e) => {
                        push_ack_if_needed(
                            &mut replies,
                            seq,
                            port_id,
                            request_msg,
                            msg_flags | NLM_F_ACK,
                            e,
                            ack_options,
                        );
                        offset += align_to(nlmsg_len, NLMSG_ALIGNTO);
                        continue;
                    }
                }
            } else {
                parse_rtattrs(&payload[GENL_HDR_LEN..])
            };
            match super::wireguard::handle_message(payload[0], &attrs, seq, port_id) {
                Ok(mut wireguard_replies) => {
                    replies.append(&mut wireguard_replies);
                    0
                }
                Err(e) => e,
            }
        } else {
            err(SyscallError::EOPNOTSUPP)
        };

        if rc != 0 || (msg_flags & NLM_F_ACK) != 0 {
            push_ack_if_needed(
                &mut replies,
                seq,
                port_id,
                request_msg,
                msg_flags | NLM_F_ACK,
                rc,
                ack_options,
            );
        }
        offset += align_to(nlmsg_len, NLMSG_ALIGNTO);
    }
    replies
}

// netlink socket 的核心可变状态。
// `messages` 之前是定长 `[u8; 32]` 数组,只够装一条最短的 NLMSG_DONE。rtnetlink 的
// RTM_NEWLINK / RTM_NEWADDR 通常 64~128 字节,且一次回复有多条,所以改成 `Vec<u8>`
// 的队列:每个元素就是一条完整的 nlmsghdr+payload，可附带跨 netns 组播来源。
struct NetlinkSocketState {
    /// 本端 netlink 地址（nl_pid 即 port id）。
    /// 由 `bind()` 显式设置，或在第一次 `sendmsg` 时由 `ensure_port_id` 懒分配。
    bound: Option<SockAddrNl>,
    /// 内核已构造好、等待 user 端 `recvmsg` 取走的 netlink 报文队列。
    /// 每个元素是一条完整的 `nlmsghdr + payload`，遵循数据报语义，不可拆分。
    messages: VecDeque<QueuedNetlinkMessage>,
    /// 阻塞在 `recvmsg` 上的任务列表。
    /// 内核把回复入队后会逐个唤醒，使用 `Weak` 避免循环引用。
    recv_waiters: VecDeque<Weak<TaskControlBlock>>,
    /// `poll`/`select`/`epoll` 等待队列，有消息可读时触发。
    poll_waiters: PollWaitQueue,
    /// connect(2) 记录的默认对端；当前 rtnetlink 子集只支持内核端 pid=0。
    peer: Option<SockAddrNl>,
    reuseaddr: bool,
    dontroute: bool,
    oobinline: bool,
    sndbuf: u32,
    rcvbuf: u32,
    broadcast: bool,
    keepalive: bool,
    linger_on: bool,
    linger_sec: i32,
    rcvlowat: i32,
    recv_pktinfo: bool,
    broadcast_error: bool,
    no_enobufs: bool,
    listen_all_nsid: bool,
    cap_ack: bool,
    ext_ack: bool,
    strict_chk: bool,
    pending_error: i32,
    rcvtimeo_ms: Option<usize>,
    sndtimeo_ms: Option<usize>,
}

lazy_static! {
    static ref ROUTE_NETLINK_SOCKETS: Mutex<Vec<Weak<NetlinkSocketFile>>> = Mutex::new(Vec::new());
    static ref NEXT_NETLINK_SOCKET_ID: Mutex<usize> = Mutex::new(1);
    static ref NEXT_NETLINK_AUTO_PORT_ID: Mutex<u32> = Mutex::new(0x8000_0000);
}

fn alloc_netlink_socket_id() -> usize {
    let mut next = NEXT_NETLINK_SOCKET_ID.lock();
    let id = *next;
    *next = next.saturating_add(1).max(1);
    id
}

fn has_effective_cap(cap: usize) -> bool {
    let process = current_process();
    let inner = process.borrow_mut();
    (inner.cap_effective & (1u64 << cap)) != 0
}

/// AF_NETLINK 套接字文件对象，模拟 Linux rtnetlink 子集。
///
/// 支持的请求类型：
/// - `RTM_GETLINK`：返回 lo + 伪 eth0 的接口信息
/// - `RTM_GETADDR`：返回 127.0.0.1 + 10.0.2.15 的地址信息
///
/// glibc 的 `getaddrinfo` 内部会通过此接口查询本机地址配置。
pub(crate) struct NetlinkSocketFile {
    /// 仅用于在全局 registry 中识别自身，避免检查 port id 冲突时把自己算进去。
    id: usize,
    /// `/proc/net/netlink` 使用的稳定 inode，创建后不随 fd 枚举顺序变化。
    proc_inode: u64,
    /// 受 Mutex 保护的可变状态，包含绑定地址、消息队列和等待者列表。
    state: Mutex<NetlinkSocketState>,
    /// socket 创建时所在的 network namespace。Linux netlink 组播按 netns 隔离。
    net_ns_id: usize,
    /// 创建时传入的 SOCK_RAW / SOCK_DGRAM 类型，用于 getsockopt(SO_TYPE)。
    socket_type: usize,
    /// NETLINK_ROUTE / NETLINK_SOCK_DIAG 等协议号决定控制面语义。
    protocol: usize,
}

impl NetlinkSocketFile {
    /// 创建一个未绑定的 netlink socket，消息队列和等待者列表均为空。
    pub(super) fn new(socket_type: usize, protocol: usize) -> Self {
        let net_ns_id = current_process().acquire_net_namespace_for_socket();
        let socket = Self {
            id: alloc_netlink_socket_id(),
            proc_inode: alloc_socket_inode(),
            state: Mutex::new(NetlinkSocketState {
                bound: None,
                messages: VecDeque::new(),
                recv_waiters: VecDeque::new(),
                poll_waiters: PollWaitQueue::default(),
                peer: None,
                reuseaddr: false,
                dontroute: false,
                oobinline: false,
                sndbuf: NETLINK_DEFAULT_SOCKBUF,
                rcvbuf: NETLINK_DEFAULT_SOCKBUF,
                broadcast: false,
                keepalive: false,
                linger_on: false,
                linger_sec: 0,
                rcvlowat: 1,
                recv_pktinfo: false,
                broadcast_error: false,
                no_enobufs: false,
                listen_all_nsid: false,
                cap_ack: false,
                ext_ack: false,
                strict_chk: false,
                pending_error: 0,
                rcvtimeo_ms: None,
                sndtimeo_ms: None,
            }),
            net_ns_id,
            socket_type,
            protocol,
        };
        socket
    }

    pub(super) fn new_registered(socket_type: usize, protocol: usize) -> Arc<Self> {
        let sock = Arc::new(Self::new(socket_type, protocol));
        ROUTE_NETLINK_SOCKETS.lock().push(Arc::downgrade(&sock));
        sock
    }

    pub(super) fn cleanup_net_namespace(ns_id: usize) {
        ROUTE_NETLINK_SOCKETS
            .lock()
            .retain(|weak| weak.upgrade().is_some_and(|sock| sock.net_ns_id != ns_id));
    }

    fn port_id_in_use(&self, port_id: u32) -> bool {
        if port_id == 0 {
            return true;
        }
        let mut used = false;
        let mut registry = ROUTE_NETLINK_SOCKETS.lock();
        registry.retain(|weak| {
            let Some(sock) = weak.upgrade() else {
                return false;
            };
            if sock.protocol == self.protocol
                && sock.id != self.id
                && sock.net_ns_id == self.net_ns_id
                && sock
                    .state
                    .lock()
                    .bound
                    .is_some_and(|addr| addr.nl_pid == port_id)
            {
                used = true;
            }
            true
        });
        used
    }

    fn allocate_port_id(&self, preferred: u32) -> u32 {
        if preferred != 0 && !self.port_id_in_use(preferred) {
            return preferred;
        }
        loop {
            let candidate = {
                let mut next = NEXT_NETLINK_AUTO_PORT_ID.lock();
                let candidate = *next;
                *next = next.wrapping_add(1).max(0x8000_0000);
                candidate
            };
            if !self.port_id_in_use(candidate) {
                return candidate;
            }
        }
    }

    pub(super) fn socket_type(&self) -> usize {
        self.socket_type
    }

    pub(super) fn set_sockbuf(&self, sndbuf: Option<u32>, rcvbuf: Option<u32>) {
        let mut st = self.state.lock();
        if let Some(v) = sndbuf {
            st.sndbuf = v;
        }
        if let Some(v) = rcvbuf {
            st.rcvbuf = v;
        }
    }

    pub(super) fn sockbuf(&self) -> (u32, u32) {
        let st = self.state.lock();
        (st.sndbuf, st.rcvbuf)
    }

    pub(super) fn set_reuseaddr(&self, enabled: bool) {
        self.state.lock().reuseaddr = enabled;
    }

    pub(super) fn reuseaddr(&self) -> bool {
        self.state.lock().reuseaddr
    }

    pub(super) fn set_dontroute(&self, enabled: bool) {
        self.state.lock().dontroute = enabled;
    }

    pub(super) fn dontroute(&self) -> bool {
        self.state.lock().dontroute
    }

    pub(super) fn set_broadcast(&self, enabled: bool) {
        self.state.lock().broadcast = enabled;
    }

    pub(super) fn broadcast(&self) -> bool {
        self.state.lock().broadcast
    }

    pub(super) fn set_keepalive(&self, enabled: bool) {
        self.state.lock().keepalive = enabled;
    }

    pub(super) fn keepalive(&self) -> bool {
        self.state.lock().keepalive
    }

    pub(super) fn set_oobinline(&self, enabled: bool) {
        self.state.lock().oobinline = enabled;
    }

    pub(super) fn oobinline(&self) -> bool {
        self.state.lock().oobinline
    }

    pub(super) fn set_linger(&self, on: bool, sec: i32) {
        let mut st = self.state.lock();
        st.linger_on = on;
        st.linger_sec = sec;
    }

    pub(super) fn linger(&self) -> (bool, i32) {
        let st = self.state.lock();
        (st.linger_on, st.linger_sec)
    }

    pub(super) fn set_rcvlowat(&self, value: i32) {
        self.state.lock().rcvlowat = value;
    }

    pub(super) fn rcvlowat(&self) -> i32 {
        self.state.lock().rcvlowat
    }

    pub(super) fn set_rcvtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.state.lock().rcvtimeo_ms = timeout_ms;
    }

    pub(super) fn rcvtimeo_ms(&self) -> Option<usize> {
        self.state.lock().rcvtimeo_ms
    }

    fn rcvtimeo_deadline_ms(&self) -> Option<usize> {
        self.rcvtimeo_ms()
            .map(|ms| crate::time::get_time_ms().saturating_add(ms))
    }

    pub(super) fn set_sndtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.state.lock().sndtimeo_ms = timeout_ms;
    }

    pub(super) fn sndtimeo_ms(&self) -> Option<usize> {
        self.state.lock().sndtimeo_ms
    }

    pub(super) fn take_socket_error(&self) -> u32 {
        let mut st = self.state.lock();
        let errno = st.pending_error.max(0) as u32;
        st.pending_error = 0;
        errno
    }

    pub(super) fn set_netlink_flag(&self, optname: usize, enabled: bool) -> isize {
        let mut st = self.state.lock();
        match optname {
            NETLINK_PKTINFO => st.recv_pktinfo = enabled,
            NETLINK_BROADCAST_ERROR => {
                // Linux uses this on the sending socket to propagate multicast
                // delivery failures. User-origin netlink broadcast is not
                // implemented here, so accepting the flag would be state-only.
                return err(SyscallError::EOPNOTSUPP);
            }
            NETLINK_NO_ENOBUFS => st.no_enobufs = enabled,
            NETLINK_LISTEN_ALL_NSID => {
                if enabled && !has_effective_cap(CAP_NET_BROADCAST) {
                    return err(SyscallError::EPERM);
                }
                st.listen_all_nsid = enabled;
            }
            NETLINK_CAP_ACK => st.cap_ack = enabled,
            NETLINK_EXT_ACK => st.ext_ack = enabled,
            NETLINK_GET_STRICT_CHK => st.strict_chk = enabled,
            _ => return err(SyscallError::ENOPROTOOPT),
        }
        0
    }

    pub(super) fn netlink_flag(&self, optname: usize) -> bool {
        let st = self.state.lock();
        match optname {
            NETLINK_PKTINFO => st.recv_pktinfo,
            NETLINK_BROADCAST_ERROR => st.broadcast_error,
            NETLINK_NO_ENOBUFS => st.no_enobufs,
            NETLINK_LISTEN_ALL_NSID => st.listen_all_nsid,
            NETLINK_CAP_ACK => st.cap_ack,
            NETLINK_EXT_ACK => st.ext_ack,
            NETLINK_GET_STRICT_CHK => st.strict_chk,
            _ => false,
        }
    }

    fn ack_options(&self) -> NetlinkAckOptions {
        let st = self.state.lock();
        NetlinkAckOptions {
            cap_ack: st.cap_ack,
            ext_ack: st.ext_ack,
            strict_chk: st.strict_chk,
        }
    }

    pub(crate) fn proc_net_snapshot(&self) -> (u64, u32, u32, u32, u32) {
        let st = self.state.lock();
        let addr = st.bound.unwrap_or(SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        });
        (
            self.proc_inode,
            addr.nl_pid,
            addr.nl_groups,
            st.rcvbuf,
            st.sndbuf,
        )
    }

    pub(crate) fn net_ns_id(&self) -> usize {
        self.net_ns_id
    }

    pub(super) fn set_membership(&self, group: i32, join: bool) -> isize {
        if self.protocol != NETLINK_ROUTE {
            return err(SyscallError::EOPNOTSUPP);
        }
        if !(1..=32).contains(&group) {
            return err(SyscallError::EINVAL);
        }
        if group != RTNLGRP_LINK_GROUP {
            return err(SyscallError::EOPNOTSUPP);
        }
        let bit = 1u32 << ((group as u32) - 1);
        let mut st = self.state.lock();
        let mut addr = st.bound.unwrap_or_else(|| SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: self.allocate_port_id(current_process().pid.0 as u32),
            nl_groups: 0,
        });
        if join {
            addr.nl_groups |= bit;
        } else {
            addr.nl_groups &= !bit;
        }
        st.bound = Some(addr);
        0
    }

    fn subscribes_link_events(&self, ns_id: usize) -> bool {
        if self.protocol != NETLINK_ROUTE {
            return false;
        }
        let st = self.state.lock();
        let joined_link_group = st
            .bound
            .is_some_and(|addr| (addr.nl_groups & RTMGRP_LINK) != 0);
        joined_link_group && (self.net_ns_id == ns_id || st.listen_all_nsid)
    }

    /// 清理等待者列表中已不处于 Blocked 状态的僵尸条目。
    /// 在每次唤醒前调用，防止列表无限增长。
    fn retain_blocked_waiters(waiters: &mut VecDeque<Weak<TaskControlBlock>>) {
        waiters.retain(|w| {
            let Some(task) = w.upgrade() else {
                return false;
            };
            task.borrow_mut().task_status == TaskStatus::Blocked
        });
    }

    /// 将任务加入等待者列表，若已存在则跳过（去重）。
    fn add_waiter_once(
        waiters: &mut VecDeque<Weak<TaskControlBlock>>,
        task: &Arc<TaskControlBlock>,
    ) {
        if waiters
            .iter()
            .any(|w| w.upgrade().is_some_and(|t| Arc::ptr_eq(&t, task)))
        {
            return;
        }
        waiters.push_back(Arc::downgrade(task));
    }

    fn remove_waiter(waiters: &mut VecDeque<Weak<TaskControlBlock>>, task: &Arc<TaskControlBlock>) {
        waiters.retain(|w| w.upgrade().is_some_and(|t| !Arc::ptr_eq(&t, task)));
    }

    /// 绑定本端 netlink 地址。
    /// `nl_pid == 0` 时自动使用当前进程 PID 作为 port id（Linux 约定）。
    /// 已绑定的 socket 再次 bind 返回 EINVAL。
    pub(super) fn bind_local(&self, addr: SockAddrNl) -> isize {
        if addr.nl_family != AF_NETLINK {
            return err(SyscallError::EAFNOSUPPORT);
        }
        if self.protocol != NETLINK_ROUTE && addr.nl_groups != 0 {
            return err(SyscallError::EOPNOTSUPP);
        }
        if addr.nl_groups & !SUPPORTED_RTMGRP_MASK != 0 {
            return err(SyscallError::EOPNOTSUPP);
        }
        let port_id = if addr.nl_pid == 0 {
            self.allocate_port_id(current_process().pid.0 as u32)
        } else if self.port_id_in_use(addr.nl_pid) {
            return err(SyscallError::EADDRINUSE);
        } else {
            addr.nl_pid
        };
        let mut st = self.state.lock();
        if st.bound.is_some() {
            return err(SyscallError::EINVAL);
        }
        if self.port_id_in_use(port_id) {
            return err(SyscallError::EADDRINUSE);
        }
        st.bound = Some(SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: port_id,
            nl_groups: addr.nl_groups,
        });
        0
    }

    /// 连接默认 netlink 对端。Linux 允许 AF_UNSPEC 断开；本实现只支持内核端。
    pub(super) fn connect_peer(&self, addr: SockAddrNl) -> isize {
        if addr.nl_family == 0 {
            self.state.lock().peer = None;
            return 0;
        }
        if addr.nl_family != AF_NETLINK {
            return err(SyscallError::EINVAL);
        }
        if addr.nl_pid != 0 || addr.nl_groups != 0 {
            return err(SyscallError::EOPNOTSUPP);
        }
        self.state.lock().peer = Some(SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        });
        0
    }

    /// 返回本端地址；未绑定时返回全零地址（nl_pid = 0）。
    pub(super) fn local_addr(&self) -> SockAddrNl {
        self.state.lock().bound.unwrap_or(SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        })
    }

    pub(super) fn peer_addr(&self) -> Option<SockAddrNl> {
        self.state.lock().peer
    }

    // 内核 netlink 端的地址固定 nl_pid = 0(POSIX/Linux 约定)。
    // recvmsg/recvfrom 在 user 提供 msg_name 时要把"包的来源"回填给 user,user 端的
    // libmnl/glibc 用它来区分这是 kernel 主动发的 reply,还是另一个进程发的 unicast。
    // 不正确地填会让 getaddrinfo 把回复当成无关消息丢弃。
    /// 返回内核侧 netlink 地址（nl_pid 固定为 0）。
    /// `recvmsg` 回填 `msg_name` 时使用，glibc 用此值验证回复来自内核而非其他进程。
    pub(super) fn kernel_addr(&self) -> SockAddrNl {
        SockAddrNl {
            nl_family: AF_NETLINK,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        }
    }

    /// 取出所有阻塞在 recv 或 poll 上的等待任务，准备唤醒。
    fn wake_readers(st: &mut NetlinkSocketState) -> Vec<Arc<TaskControlBlock>> {
        let mut wake = Vec::new();
        Self::retain_blocked_waiters(&mut st.recv_waiters);
        for waiter in st.recv_waiters.drain(..) {
            if let Some(task) = waiter.upgrade() {
                wake.push(task);
            }
        }
        wake.extend(st.poll_waiters.take_wakeups());
        wake
    }

    /// 将一批报文入队，并唤醒所有等待读取的任务。
    fn enqueue_packets(&self, packets: Vec<Vec<u8>>) {
        if packets.is_empty() {
            return;
        }
        self.enqueue_packets_with_nsid(packets, None);
    }

    fn enqueue_packets_with_nsid(&self, packets: Vec<Vec<u8>>, nsid: Option<i32>) {
        self.enqueue_packets_with_metadata(packets, nsid, 0);
    }

    fn enqueue_packets_with_metadata(&self, packets: Vec<Vec<u8>>, nsid: Option<i32>, group: u32) {
        if packets.is_empty() {
            return;
        }
        let wake = {
            let mut st = self.state.lock();
            for packet in packets {
                if Self::can_enqueue_packet(&st, packet.len()) {
                    st.messages.push_back(QueuedNetlinkMessage {
                        data: packet,
                        nsid,
                        group,
                    });
                } else if !st.no_enobufs {
                    st.pending_error = SyscallError::ENOBUFS as i32;
                }
            }
            Self::wake_readers(&mut st)
        };
        wake_tasks(wake);
    }

    fn queued_message_bytes(st: &NetlinkSocketState) -> usize {
        st.messages
            .iter()
            .map(|msg| msg.data.len())
            .fold(0usize, usize::saturating_add)
    }

    fn can_enqueue_packet(st: &NetlinkSocketState, packet_len: usize) -> bool {
        let queued = Self::queued_message_bytes(st);
        queued == 0 || queued.saturating_add(packet_len) <= st.rcvbuf as usize
    }

    // 给一个未 bind 的 netlink socket 即时分配 port id(用 pid 当默认值)。
    //
    // Why: 很多 user 端(包括 glibc resolver)发请求前从来不调用 bind(),只是
    // socket()+sendmsg。但回复里的 nlmsghdr.pid 必须等于"该 socket 在 kernel 侧
    // 看到的 port id",否则 user 端做的 seq/port 过滤会把我们的 reply 全丢掉,
    // 看起来就是"发请求没回应"。这里在第一次 sendmsg 路径上 lazy 分配,保证回复
    // 一定带着 user 能识别的 port id。
    /// 懒分配 port id：若已绑定则直接返回 nl_pid，否则用当前 PID 自动绑定。
    ///
    /// 保证回复报文中的 `nlmsghdr.pid` 与 user 端过滤条件一致，
    /// 避免 glibc 因 port id 不匹配而丢弃内核回复。
    fn ensure_port_id(&self) -> u32 {
        let mut st = self.state.lock();
        match st.bound {
            Some(addr) => addr.nl_pid,
            None => {
                let port_id = self.allocate_port_id(current_process().pid.0 as u32);
                st.bound = Some(SockAddrNl {
                    nl_family: AF_NETLINK,
                    nl_pad: 0,
                    nl_pid: port_id,
                    nl_groups: 0,
                });
                port_id
            }
        }
    }

    // user 通过 sendmsg/write 写入的 netlink 请求最终落到这里。
    //
    // 原 netlink 实现直接丢弃 user 字节,导致 user 端 recvmsg 永远阻塞。这里改成:
    //   1) 解析 user 字节流里所有 nlmsghdr
    //   2) 对每条请求构造对应的 multipart 应答
    //   3) 把所有应答一次性 enqueue 到 messages,并唤醒等在 recvmsg 上的任务
    /// 处理 user 端通过 `sendmsg`/`write` 发来的 netlink 请求。
    ///
    /// 解析字节流中的所有 `nlmsghdr`，为每条请求构造 multipart 应答，
    /// 一次性入队并唤醒阻塞在 `recvmsg` 上的任务。
    pub(super) fn handle_outbound(&self, buf: &[u8], sender: NetlinkSender) {
        let port_id = self.ensure_port_id();
        let ack_options = self.ack_options();
        let replies = match self.protocol {
            NETLINK_ROUTE => build_route_netlink_replies(buf, port_id, ack_options, sender),
            NETLINK_SOCK_DIAG => build_sock_diag_replies(buf, port_id, ack_options),
            NETLINK_GENERIC => build_generic_netlink_replies(buf, port_id, ack_options),
            _ => Vec::new(),
        };
        self.enqueue_packets(replies);
    }

    /// 将 POSIX 消息队列通知投递到此 netlink socket。
    ///
    /// `mq_notify` 使用 `SIGEV_THREAD` 时，内核通过此接口把 cookie 写入
    /// user 注册的 netlink socket，user 端线程池读取后触发回调。
    pub(crate) fn enqueue_mq_notify(
        &self,
        mut cookie: [u8; MQ_THREAD_NOTIFY_COOKIE_LEN],
        notify_kind: u8,
    ) {
        cookie[MQ_THREAD_NOTIFY_COOKIE_LEN - 1] = notify_kind;
        let wake = {
            let mut st = self.state.lock();
            st.messages.push_back(QueuedNetlinkMessage {
                data: cookie.to_vec(),
                nsid: None,
                group: 0,
            });
            Self::wake_readers(&mut st)
        };
        wake_tasks(wake);
    }

    // 从 messages 队列里取走(或 peek)一条完整的 netlink 报文。
    //
    // 关键点:netlink 是"数据报"语义,每条 message 必须整条出/整条进,不能像 TCP
    // 那样切片;所以队列元素是 `Vec<u8>`,这里直接 pop 整条。`_len` 由调用者负责
    // 截断,这层不做任何 partial-read。
    //
    // 队列空时:MSG_DONTWAIT → EAGAIN;否则把自己挂进 recv_waiters 然后 block,
    // 等下一次 handle_outbound 入队回复时把自己唤醒。
    /// 从消息队列取出（或 peek）一条完整的 netlink 报文。
    ///
    /// - `MSG_PEEK`：不消费，仅返回队首副本
    /// - `MSG_DONTWAIT`：队列空时立即返回 `EAGAIN`
    /// - 否则：阻塞直到有消息可读
    ///
    /// 截断由调用者（`recvmsg`）负责，此层不做 partial-read。
    pub(super) fn recv_packet(&self, len: usize, flags: usize) -> Result<Vec<u8>, isize> {
        self.recv_packet_with_nsid(len, flags)
            .map(|packet| packet.data)
    }

    pub(super) fn recv_packet_with_nsid(
        &self,
        _len: usize,
        flags: usize,
    ) -> Result<QueuedNetlinkMessage, isize> {
        let peek = (flags & MSG_PEEK) != 0;
        let nonblock = (flags & MSG_DONTWAIT) != 0;
        let deadline_ms = (!nonblock).then(|| self.rcvtimeo_deadline_ms()).flatten();
        loop {
            let mut st = self.state.lock();
            if st.pending_error != 0 {
                let errno = st.pending_error;
                st.pending_error = 0;
                return Err(-(errno as isize));
            }
            let msg = if peek {
                st.messages.front().cloned()
            } else {
                st.messages.pop_front()
            };
            if let Some(msg) = msg {
                drop(st);
                return Ok(msg);
            }
            if nonblock {
                return Err(err(SyscallError::EAGAIN));
            }
            let Some(task) = current_task() else {
                return Err(err(SyscallError::EAGAIN));
            };
            crate::task::block_sleep::check_timer();
            let inner = task.borrow_mut();
            if has_wait_interrupting_pending(inner.pending_signals, inner.signal_mask) {
                Self::remove_waiter(&mut st.recv_waiters, &task);
                return Err(err(SyscallError::EINTR));
            }
            if let Some(deadline_ms) = deadline_ms {
                let now = crate::time::get_time_ms();
                if now >= deadline_ms {
                    Self::remove_waiter(&mut st.recv_waiters, &task);
                    return Err(err(SyscallError::EAGAIN));
                }
                crate::task::block_sleep::add_timer(task.clone(), deadline_ms - now);
            }
            drop(inner);
            Self::add_waiter_once(&mut st.recv_waiters, &task);
            drop(st);
            block_current_and_run_next();
        }
    }

    /// 消息队列非空时返回 `true`，供 `poll`/`epoll` 使用。
    #[allow(dead_code)]
    pub(crate) fn poll_readable(&self) -> bool {
        !self.state.lock().messages.is_empty()
    }

    /// netlink socket 始终可写（内核侧无发送缓冲区限制）。
    #[allow(dead_code)]
    pub(crate) fn poll_writable(&self) -> bool {
        true
    }
}

impl Drop for NetlinkSocketFile {
    fn drop(&mut self) {
        crate::fs::release_net_namespace_socket_ref(self.net_ns_id);
    }
}

fn multicast_link_event(ns_id: usize, msg_type: u16, dev: NetDeviceSnapshot) {
    let subscribers = {
        let mut registry = ROUTE_NETLINK_SOCKETS.lock();
        let mut subscribers = Vec::new();
        registry.retain(|weak| {
            let Some(sock) = weak.upgrade() else {
                return false;
            };
            if sock.subscribes_link_events(ns_id) {
                subscribers.push(sock);
            }
            true
        });
        subscribers
    };
    if subscribers.is_empty() {
        return;
    }
    let packet = build_link_with_type(msg_type, &dev, 0, 0, 0);
    for sock in subscribers {
        let nsid = (sock.net_ns_id != ns_id).then_some(ns_id as i32);
        sock.enqueue_packets_with_metadata(
            alloc::vec![packet.clone()],
            nsid,
            RTNLGRP_LINK_GROUP as u32,
        );
    }
}

pub(crate) fn notify_link_created(ns_id: usize, dev: NetDeviceSnapshot) {
    multicast_link_event(ns_id, RTM_NEWLINK, dev);
}

pub(crate) fn notify_link_changed(ns_id: usize, dev: NetDeviceSnapshot) {
    multicast_link_event(ns_id, RTM_NEWLINK, dev);
}

pub(crate) fn notify_link_deleted(ns_id: usize, dev: NetDeviceSnapshot) {
    multicast_link_event(ns_id, RTM_DELLINK, dev);
}

impl File for NetlinkSocketFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        let len = buf.len();
        if len == 0 {
            return 0;
        }
        match self.recv_packet(len, 0) {
            Ok(msg) => copy_slice_to_user_buffer(buf, &msg[..len.min(msg.len())]),
            Err(_) => 0,
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        let data = copy_user_buffer_to_vec(buf);
        let len = data.len();
        self.handle_outbound(&data, NetlinkSender::current());
        len
    }

    fn poll_mask(&self) -> i16 {
        let st = self.state.lock();
        let mut mask = POLLOUT;
        if st.pending_error != 0 {
            mask |= POLLERR;
        }
        if !st.messages.is_empty() {
            mask |= POLLIN;
        }
        mask
    }

    fn supports_poll(&self) -> bool {
        true
    }

    fn register_poll_waiter(&self, task: &Arc<TaskControlBlock>) -> bool {
        let mut st = self.state.lock();
        st.poll_waiters.register_waiter(task)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// 从用户空间读取并校验一个 `SockAddrNl`。
///
/// # 参数
/// - `user_ptr`：用户空间 `sockaddr_nl` 指针
/// - `len`：用户传入的地址长度，必须 `>= size_of::<SockAddrNl>()`
///
/// # 错误
/// - `EINVAL`：指针为空或长度不足
/// - `EFAULT`：读取用户内存失败
/// - `EAFNOSUPPORT`：`nl_family` 非零且不等于 `AF_NETLINK`
pub(super) fn parse_sockaddr_nl(user_ptr: usize, len: usize) -> Result<SockAddrNl, isize> {
    if len > SOCKADDR_STORAGE_SIZE {
        return Err(err(SyscallError::EINVAL));
    }
    if len < size_of::<SockAddrNl>() {
        return Err(err(SyscallError::EINVAL));
    }
    if user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut storage = [0u8; SOCKADDR_STORAGE_SIZE];
    if try_copy_from_user(token, user_ptr as *const u8, &mut storage[..len]).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let sa = unsafe { core::ptr::read_unaligned(storage.as_ptr() as *const SockAddrNl) };
    if sa.nl_family != AF_NETLINK {
        if sa.nl_family != 0 {
            return Err(err(SyscallError::EAFNOSUPPORT));
        }
    }
    Ok(sa)
}

/// `sendmsg/sendto(AF_NETLINK)` 当前只支持发往内核端(`nl_pid=0,nl_groups=0`)。
///
/// Linux 会把非零 port id / groups 当成真实的用户端或组播目的地处理；本内核尚未实现
/// 这条发送路径，因此显式拒绝，避免把用户指定的目的地静默改写成 kernel。
pub(super) fn parse_sockaddr_nl_kernel_peer(user_ptr: usize, len: usize) -> Result<(), isize> {
    let sa = parse_sockaddr_nl(user_ptr, len)?;
    if sa.nl_family != AF_NETLINK {
        return Err(err(SyscallError::EINVAL));
    }
    if sa.nl_pid != 0 || sa.nl_groups != 0 {
        return Err(err(SyscallError::EOPNOTSUPP));
    }
    Ok(())
}

/// `connect(AF_NETLINK)` 的地址解析。Linux 允许 `AF_UNSPEC` 只传 `sa_family`
/// 长度来断开默认对端；非断开路径仍要求完整 `sockaddr_nl`。
pub(super) fn parse_sockaddr_nl_connect(user_ptr: usize, len: usize) -> Result<SockAddrNl, isize> {
    if len > SOCKADDR_STORAGE_SIZE || len < size_of::<u16>() {
        return Err(err(SyscallError::EINVAL));
    }
    if user_ptr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    let token = get_current_token();
    let mut family = [0u8; size_of::<u16>()];
    if try_copy_from_user(token, user_ptr as *const u8, &mut family).is_err() {
        return Err(err(SyscallError::EFAULT));
    }
    let family = u16::from_ne_bytes(family);
    if family == 0 {
        return Ok(SockAddrNl {
            nl_family: 0,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        });
    }
    if family != AF_NETLINK {
        return Err(err(SyscallError::EINVAL));
    }
    if len < size_of::<SockAddrNl>() {
        return Err(err(SyscallError::EINVAL));
    }
    parse_sockaddr_nl(user_ptr, len).map_err(|e| {
        if e == err(SyscallError::EAFNOSUPPORT) {
            err(SyscallError::EINVAL)
        } else {
            e
        }
    })
}

/// 将 `SockAddrNl` 写回用户空间，并更新用户提供的长度字段。
///
/// 遵循 `getsockname`/`recvmsg` 的 POSIX 截断语义：若用户缓冲区小于结构体大小，
/// 只复制用户缓冲区能容纳的字节，但长度字段仍回写实际所需的完整大小。
///
/// # 参数
/// - `user_ptr`：目标 `sockaddr_nl` 指针
/// - `user_len_ptr`：指向长度字段（`socklen_t *`）的指针，读入后回写实际长度
/// - `sa`：待写入的地址结构引用
///
/// # 错误
/// - `EFAULT`：任一指针为空或用户内存访问失败
/// - `EINVAL`：用户传入的长度值超出合法范围
pub(super) fn write_sockaddr_nl(user_ptr: usize, user_len_ptr: usize, sa: &SockAddrNl) -> isize {
    if user_ptr == 0 || user_len_ptr == 0 {
        return err(SyscallError::EFAULT);
    }
    let token = get_current_token();
    let Some(len_u32) = try_read_user_value::<u32>(token, user_len_ptr as *const u32) else {
        return err(SyscallError::EFAULT);
    };
    let len = len_u32 as usize;
    if len > i32::MAX as usize {
        return err(SyscallError::EINVAL);
    }
    let required = size_of::<SockAddrNl>();
    let copy_len = core::cmp::min(len, required);
    if copy_len > 0 {
        // SAFETY: sa is a reference to a valid SockAddrNl; copy_len <= size_of::<SockAddrNl>().
        let bytes = unsafe {
            core::slice::from_raw_parts((&*sa as *const SockAddrNl) as *const u8, copy_len)
        };
        if try_copy_to_user(token, user_ptr as *mut u8, bytes).is_err() {
            return err(SyscallError::EFAULT);
        }
    }
    if try_write_user_value(token, user_len_ptr as *mut u32, &(required as u32)).is_err() {
        return err(SyscallError::EFAULT);
    }
    0
}
