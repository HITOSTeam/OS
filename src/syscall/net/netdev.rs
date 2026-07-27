extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::fs::{NetSocketFile, NetSocketKind};
use crate::syscall::error::{SyscallError, err};
use crate::task::manager::PID2PCB;
use crate::task::processor::current_process;

pub(crate) const ARPHRD_ETHER: u16 = 1;
pub(crate) const ARPHRD_LOOPBACK: u16 = 772;
pub(crate) const ARPHRD_NONE: u16 = 0xfffe;

pub(crate) const IFF_UP: u32 = 0x1;
pub(crate) const IFF_BROADCAST: u32 = 0x2;
pub(crate) const IFF_LOOPBACK: u32 = 0x8;
pub(crate) const IFF_POINTOPOINT: u32 = 0x10;
pub(crate) const IFF_RUNNING: u32 = 0x40;
pub(crate) const IFF_NOARP: u32 = 0x80;
pub(crate) const IFF_PROMISC: u32 = 0x100;
pub(crate) const IFF_ALLMULTI: u32 = 0x200;
pub(crate) const IFF_MULTICAST: u32 = 0x1000;

const TUNTAP_SYSFS_IFF_TUN: u16 = 0x0001;
const TUNTAP_SYSFS_IFF_TAP: u16 = 0x0002;

const BUILTIN_LO: &str = "lo";
const BUILTIN_ETH0: &str = "eth0";
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const ICMP_ECHOREPLY: u8 = 0;
const ICMP_ECHO: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetDeviceKind {
    Loopback,
    Ethernet,
    Dummy,
    Veth,
    Macvlan,
    Ipvlan,
    Macvtap,
    Wireguard,
    Tun,
    Tap,
}

impl NetDeviceKind {
    pub(crate) fn link_kind(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Ethernet => "ether",
            Self::Dummy => "dummy",
            Self::Veth => "veth",
            Self::Macvlan => "macvlan",
            Self::Ipvlan => "ipvlan",
            Self::Macvtap => "macvtap",
            Self::Wireguard => "wireguard",
            Self::Tun | Self::Tap => "tun",
        }
    }

    pub(crate) fn arp_type(self) -> u16 {
        match self {
            Self::Loopback => ARPHRD_LOOPBACK,
            Self::Tun | Self::Wireguard => ARPHRD_NONE,
            Self::Ethernet
            | Self::Dummy
            | Self::Veth
            | Self::Macvlan
            | Self::Ipvlan
            | Self::Macvtap
            | Self::Tap => ARPHRD_ETHER,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Ipv4AddrEntry {
    /// Linux `ifa_local`：本机 IPv4 地址。
    pub(crate) addr: [u8; 4],
    /// Linux `ifa_address`：点到点目的地址；普通以太网默认等于本机地址。
    pub(crate) peer_addr: [u8; 4],
    pub(crate) prefix_len: u8,
    /// Linux `ifa_label`：primary 地址使用设备名，alias 地址使用 `eth0:1` 这种标签。
    pub(crate) label: Option<String>,
    /// Linux `ifa_broadcast`：用户显式设置或根据前缀自动派生的广播地址。
    pub(crate) broadcast_addr: Option<[u8; 4]>,
    pub(crate) scope: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct Ipv6AddrEntry {
    pub(crate) addr: [u8; 16],
    pub(crate) prefix_len: u8,
    pub(crate) label: Option<String>,
    pub(crate) scope: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct RouteEntry {
    pub(crate) dst: [u8; 4],
    pub(crate) prefix_len: u8,
    pub(crate) gateway: Option<[u8; 4]>,
    pub(crate) ifindex: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct NeighEntry {
    pub(crate) dst: [u8; 4],
    pub(crate) lladdr: [u8; 6],
    pub(crate) ifindex: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct QdiscEntry {
    pub(crate) ifindex: i32,
    pub(crate) handle: u32,
    pub(crate) parent: u32,
    pub(crate) kind: String,
    pub(crate) options: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct NetDeviceSnapshot {
    pub(crate) ifindex: i32,
    pub(crate) name: String,
    pub(crate) kind: NetDeviceKind,
    pub(crate) link_ifindex: Option<i32>,
    pub(crate) link_type: u16,
    pub(crate) flags: u32,
    pub(crate) mtu: u32,
    pub(crate) tx_queue_len: u32,
    pub(crate) hwaddr: [u8; 6],
    pub(crate) addrs: Vec<Ipv4AddrEntry>,
    pub(crate) addrs6: Vec<Ipv6AddrEntry>,
    pub(crate) maddrs: Vec<[u8; 6]>,
    pub(crate) stats: NetDeviceStats,
}

impl NetDeviceSnapshot {
    pub(crate) fn operstate(&self) -> u8 {
        if (self.flags & IFF_UP) != 0 { 6 } else { 2 }
    }
}

#[derive(Clone, Debug)]
struct NetDevice {
    net_ns_id: usize,
    ifindex: i32,
    name: String,
    kind: NetDeviceKind,
    link_ifindex: Option<i32>,
    link_type: u16,
    flags: u32,
    mtu: u32,
    tx_queue_len: u32,
    hwaddr: [u8; 6],
    addrs: Vec<Ipv4AddrEntry>,
    addrs6: Vec<Ipv6AddrEntry>,
    maddrs: Vec<MacAddrRef>,
    uaddrs: Vec<MacAddrRef>,
    promiscuity: u32,
    allmulti: u32,
    stats: NetDeviceStats,
    qdisc: Option<QdiscEntry>,
    builtin: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NetDeviceStats {
    pub(crate) rx_bytes: u64,
    pub(crate) rx_packets: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) tx_packets: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct NetProtocolStats {
    ip_in_receives: u64,
    ip_in_delivers: u64,
    ip_out_requests: u64,
    ip_in_octets: u64,
    ip_out_octets: u64,
    icmp_in_msgs: u64,
    icmp_out_msgs: u64,
    icmp_in_echos: u64,
    icmp_in_echo_reps: u64,
    icmp_out_echos: u64,
    icmp_out_echo_reps: u64,
    tcp_in_segs: u64,
    tcp_out_segs: u64,
    udp_in_datagrams: u64,
    udp_out_datagrams: u64,
}

impl NetDevice {
    fn snapshot(&self) -> NetDeviceSnapshot {
        NetDeviceSnapshot {
            ifindex: self.ifindex,
            name: self.name.clone(),
            kind: self.kind,
            link_ifindex: self.link_ifindex,
            link_type: self.link_type,
            flags: self.flags,
            mtu: self.mtu,
            tx_queue_len: self.tx_queue_len,
            hwaddr: self.hwaddr,
            addrs: self.addrs.clone(),
            addrs6: self.addrs6.clone(),
            maddrs: self.maddrs.iter().map(|entry| entry.addr).collect(),
            stats: self.stats,
        }
    }
}

#[derive(Clone, Debug)]
struct MacAddrRef {
    addr: [u8; 6],
    count: u32,
}

struct NetState {
    devices: Vec<NetDevice>,
    routes: Vec<RouteEntry>,
    neighs: Vec<NeighEntry>,
    protocol_stats: Vec<(usize, NetProtocolStats)>,
    next_ifindex: i32,
}

impl NetState {
    fn new() -> Self {
        Self {
            devices: alloc::vec![
                NetDevice {
                    net_ns_id: 0,
                    ifindex: 1,
                    name: String::from(BUILTIN_LO),
                    kind: NetDeviceKind::Loopback,
                    link_ifindex: None,
                    link_type: NetDeviceKind::Loopback.arp_type(),
                    flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
                    mtu: 65536,
                    tx_queue_len: 1000,
                    hwaddr: [0; 6],
                    addrs: alloc::vec![Ipv4AddrEntry {
                        addr: [127, 0, 0, 1],
                        peer_addr: [127, 0, 0, 1],
                        prefix_len: 8,
                        label: None,
                        broadcast_addr: None,
                        scope: 254,
                    }],
                    addrs6: alloc::vec![Ipv6AddrEntry {
                        addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        prefix_len: 128,
                        label: None,
                        scope: 254,
                    }],
                    maddrs: Vec::new(),
                    uaddrs: Vec::new(),
                    promiscuity: 0,
                    allmulti: 0,
                    stats: NetDeviceStats::default(),
                    qdisc: None,
                    builtin: true,
                },
                NetDevice {
                    net_ns_id: 0,
                    ifindex: 2,
                    name: String::from(BUILTIN_ETH0),
                    kind: NetDeviceKind::Ethernet,
                    link_ifindex: None,
                    link_type: NetDeviceKind::Ethernet.arp_type(),
                    flags: IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST,
                    mtu: 1500,
                    tx_queue_len: 1000,
                    hwaddr: [0x02, 0, 0, 0, 0, 1],
                    addrs: alloc::vec![Ipv4AddrEntry {
                        addr: [10, 0, 2, 15],
                        peer_addr: [10, 0, 2, 15],
                        prefix_len: 24,
                        label: None,
                        broadcast_addr: Some([10, 0, 2, 255]),
                        scope: 0,
                    }],
                    addrs6: Vec::new(),
                    maddrs: Vec::new(),
                    uaddrs: Vec::new(),
                    promiscuity: 0,
                    allmulti: 0,
                    stats: NetDeviceStats::default(),
                    qdisc: None,
                    builtin: true,
                },
            ],
            routes: Vec::new(),
            neighs: Vec::new(),
            protocol_stats: Vec::new(),
            next_ifindex: 3,
        }
    }

    fn device_by_name_in(&self, ns_id: usize, name: &str) -> Option<&NetDevice> {
        self.devices
            .iter()
            .find(|dev| dev.net_ns_id == ns_id && dev.name == name)
    }

    fn device_by_index_in(&self, ns_id: usize, ifindex: i32) -> Option<&NetDevice> {
        self.devices
            .iter()
            .find(|dev| dev.net_ns_id == ns_id && dev.ifindex == ifindex)
    }

    fn device_by_index_mut_in(&mut self, ns_id: usize, ifindex: i32) -> Option<&mut NetDevice> {
        self.devices
            .iter_mut()
            .find(|dev| dev.net_ns_id == ns_id && dev.ifindex == ifindex)
    }

    fn alloc_ifindex(&mut self) -> i32 {
        let ifindex = self.next_ifindex;
        self.next_ifindex = self.next_ifindex.saturating_add(1).max(3);
        ifindex
    }

    fn ensure_namespace(&mut self, ns_id: usize) {
        if self
            .devices
            .iter()
            .any(|dev| dev.net_ns_id == ns_id && dev.name == BUILTIN_LO)
        {
            return;
        }
        let ifindex = self.alloc_ifindex();
        self.devices.push(NetDevice {
            net_ns_id: ns_id,
            ifindex,
            name: String::from(BUILTIN_LO),
            kind: NetDeviceKind::Loopback,
            link_ifindex: None,
            link_type: NetDeviceKind::Loopback.arp_type(),
            flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
            mtu: 65536,
            tx_queue_len: 1000,
            hwaddr: [0; 6],
            addrs: alloc::vec![Ipv4AddrEntry {
                addr: [127, 0, 0, 1],
                peer_addr: [127, 0, 0, 1],
                prefix_len: 8,
                label: None,
                broadcast_addr: None,
                scope: 254,
            }],
            addrs6: alloc::vec![Ipv6AddrEntry {
                addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefix_len: 128,
                label: None,
                scope: 254,
            }],
            maddrs: Vec::new(),
            uaddrs: Vec::new(),
            promiscuity: 0,
            allmulti: 0,
            stats: NetDeviceStats::default(),
            qdisc: None,
            builtin: true,
        });
    }

    fn protocol_stats_mut_in(&mut self, ns_id: usize) -> &mut NetProtocolStats {
        if let Some(pos) = self
            .protocol_stats
            .iter()
            .position(|(stats_ns_id, _)| *stats_ns_id == ns_id)
        {
            return &mut self.protocol_stats[pos].1;
        }
        self.protocol_stats
            .push((ns_id, NetProtocolStats::default()));
        let pos = self.protocol_stats.len() - 1;
        &mut self.protocol_stats[pos].1
    }

    fn protocol_stats_in(&self, ns_id: usize) -> NetProtocolStats {
        self.protocol_stats
            .iter()
            .find(|(stats_ns_id, _)| *stats_ns_id == ns_id)
            .map(|(_, stats)| *stats)
            .unwrap_or_default()
    }
}

lazy_static! {
    static ref NET_STATE: Mutex<NetState> = Mutex::new(NetState::new());
}

fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && !name.contains('/')
        && !name.contains(char::from(0))
        && name != "."
        && name != ".."
}

fn valid_addr_label(dev_name: &str, label: &str) -> bool {
    if !valid_ifname(label) {
        return false;
    }
    if label == dev_name {
        return true;
    }
    label
        .strip_prefix(dev_name)
        .is_some_and(|suffix| suffix.len() > 1 && suffix.starts_with(':'))
}

fn normalize_addr_label(dev_name: &str, label: Option<&str>) -> Result<Option<String>, isize> {
    let Some(label) = label else {
        return Ok(None);
    };
    if !valid_addr_label(dev_name, label) {
        return Err(errno(SyscallError::EINVAL));
    }
    if label == dev_name {
        Ok(None)
    } else {
        Ok(Some(label.to_string()))
    }
}

pub(crate) fn ipv4_addr_label<'a>(dev_name: &'a str, entry: &'a Ipv4AddrEntry) -> &'a str {
    entry.label.as_deref().unwrap_or(dev_name)
}

fn errno(e: SyscallError) -> isize {
    err(e)
}

fn generated_hwaddr(ifindex: i32) -> [u8; 6] {
    [
        0x02,
        0,
        0,
        ((ifindex >> 16) & 0xff) as u8,
        ((ifindex >> 8) & 0xff) as u8,
        (ifindex & 0xff) as u8,
    ]
}

fn ipv4_same_prefix(left: [u8; 4], right: [u8; 4], prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = (!0u32) << (32 - prefix_len as u32);
    (u32::from_be_bytes(left) & mask) == (u32::from_be_bytes(right) & mask)
}

fn ipv6_same_prefix(left: [u8; 16], right: [u8; 16], prefix_len: u8) -> bool {
    let prefix_len = prefix_len.min(128);
    let full_bytes = usize::from(prefix_len / 8);
    let rest_bits = prefix_len % 8;
    if left[..full_bytes] != right[..full_bytes] {
        return false;
    }
    if rest_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - rest_bits);
    (left[full_bytes] & mask) == (right[full_bytes] & mask)
}

fn ipv4_directed_broadcast(addr: [u8; 4], prefix_len: u8) -> Option<[u8; 4]> {
    if prefix_len >= 31 {
        return None;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        (!0u32) << (32 - prefix_len as u32)
    };
    let network = u32::from_be_bytes(addr) & mask;
    Some((network | !mask).to_be_bytes())
}

fn default_broadcast_addr(flags: u32, addr: [u8; 4], prefix_len: u8) -> Option<[u8; 4]> {
    if (flags & IFF_BROADCAST) == 0 {
        return None;
    }
    ipv4_directed_broadcast(addr, prefix_len)
}

fn device_has_ipv4_broadcast_addr(dev: &NetDevice, addr: [u8; 4]) -> bool {
    if addr == [255, 255, 255, 255] {
        return true;
    }
    if (dev.flags & IFF_BROADCAST) == 0 {
        return false;
    }
    dev.addrs
        .iter()
        .filter_map(|entry| entry.broadcast_addr)
        .any(|broadcast| broadcast == addr)
}

pub(crate) fn ipv4_is_multicast_addr(addr: [u8; 4]) -> bool {
    (224..=239).contains(&addr[0])
}

pub(crate) fn ipv4_is_broadcast_addr(addr: [u8; 4], bound_ifindex: i32) -> bool {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    if bound_ifindex > 0 {
        return state
            .device_by_index_in(ns_id, bound_ifindex)
            .is_some_and(|dev| device_has_ipv4_broadcast_addr(dev, addr));
    }
    state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .any(|dev| device_has_ipv4_broadcast_addr(dev, addr))
}

pub(crate) fn ipv4_multicast_mac(addr: [u8; 4]) -> [u8; 6] {
    [0x01, 0x00, 0x5e, addr[1] & 0x7f, addr[2], addr[3]]
}

fn current_net_ns_id() -> usize {
    current_process().net_namespace_id()
}

pub(crate) fn devices_snapshot() -> Vec<NetDeviceSnapshot> {
    let ns_id = current_net_ns_id();
    devices_snapshot_in_namespace(ns_id)
}

pub(crate) fn devices_snapshot_in_namespace(ns_id: usize) -> Vec<NetDeviceSnapshot> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .map(NetDevice::snapshot)
        .collect()
}

pub(crate) fn routes_snapshot() -> Vec<RouteEntry> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let visible_ifindexes: Vec<i32> = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .map(|dev| dev.ifindex)
        .collect();
    state
        .routes
        .iter()
        .filter(|route| visible_ifindexes.contains(&route.ifindex))
        .cloned()
        .collect()
}

pub(crate) fn neighs_snapshot() -> Vec<NeighEntry> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let visible_ifindexes: Vec<i32> = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .map(|dev| dev.ifindex)
        .collect();
    state
        .neighs
        .iter()
        .filter(|neigh| visible_ifindexes.contains(&neigh.ifindex))
        .cloned()
        .collect()
}

fn default_qdisc_for(dev: &NetDevice) -> QdiscEntry {
    QdiscEntry {
        ifindex: dev.ifindex,
        handle: 0,
        parent: 0xffff_ffff,
        kind: String::from("noqueue"),
        options: Vec::new(),
    }
}

pub(crate) fn qdiscs_snapshot() -> Vec<QdiscEntry> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .map(|dev| dev.qdisc.clone().unwrap_or_else(|| default_qdisc_for(dev)))
        .collect()
}

pub(crate) fn set_qdisc(
    ifindex: i32,
    handle: u32,
    parent: u32,
    kind: &str,
    options: Vec<u8>,
    create: bool,
    replace: bool,
    excl: bool,
) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let dev = state
        .device_by_index_mut_in(ns_id, ifindex)
        .ok_or_else(|| errno(SyscallError::ENODEV))?;
    if parent != 0 && parent != 0xffff_ffff {
        return Err(errno(SyscallError::EOPNOTSUPP));
    }
    let existing = dev.qdisc.is_some();
    if kind == "noqueue" {
        dev.qdisc = None;
        return Ok(());
    }
    if !matches!(kind, "netem" | "pfifo" | "pfifo_fast" | "fq_codel") {
        return Err(errno(SyscallError::EOPNOTSUPP));
    }
    if existing && excl && !replace {
        return Err(errno(SyscallError::EEXIST));
    }
    if !existing && !create && !replace {
        return Err(errno(SyscallError::ENOENT));
    }
    dev.qdisc = Some(QdiscEntry {
        ifindex,
        handle,
        parent: 0xffff_ffff,
        kind: kind.to_string(),
        options,
    });
    Ok(())
}

pub(crate) fn delete_qdisc(
    ifindex: i32,
    parent: u32,
    requested_kind: Option<&str>,
) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let dev = state
        .device_by_index_mut_in(ns_id, ifindex)
        .ok_or_else(|| errno(SyscallError::ENODEV))?;
    if parent != 0 && parent != 0xffff_ffff {
        return Err(errno(SyscallError::EOPNOTSUPP));
    }
    let Some(qdisc) = dev.qdisc.as_ref() else {
        return Err(errno(SyscallError::ENOENT));
    };
    if requested_kind.is_some_and(|kind| kind != qdisc.kind) {
        return Err(errno(SyscallError::ENOENT));
    }
    dev.qdisc = None;
    Ok(())
}

pub(crate) fn device_snapshot_by_name(name: &str) -> Option<NetDeviceSnapshot> {
    let ns_id = current_net_ns_id();
    device_snapshot_by_name_in_namespace(ns_id, name)
}

pub(crate) fn device_snapshot_by_name_in_namespace(
    ns_id: usize,
    name: &str,
) -> Option<NetDeviceSnapshot> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .device_by_name_in(ns_id, name)
        .map(NetDevice::snapshot)
}

pub(crate) fn device_snapshot_by_index(ifindex: i32) -> Option<NetDeviceSnapshot> {
    let ns_id = current_net_ns_id();
    device_snapshot_by_index_in_namespace(ns_id, ifindex)
}

pub(crate) fn device_snapshot_by_index_in_namespace(
    ns_id: usize,
    ifindex: i32,
) -> Option<NetDeviceSnapshot> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .device_by_index_in(ns_id, ifindex)
        .map(NetDevice::snapshot)
}

pub(crate) fn device_snapshot_by_global_ifindex(
    ifindex: i32,
) -> Option<(usize, NetDeviceSnapshot)> {
    let state = NET_STATE.lock();
    state
        .devices
        .iter()
        .find(|dev| dev.ifindex == ifindex)
        .map(|dev| (dev.net_ns_id, dev.snapshot()))
}

pub(crate) fn veth_peer_snapshot_by_index_in_namespace(
    ns_id: usize,
    ifindex: i32,
) -> Option<(usize, NetDeviceSnapshot)> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let dev = state.device_by_index_in(ns_id, ifindex)?;
    if dev.kind != NetDeviceKind::Veth || (dev.flags & IFF_UP) == 0 {
        return None;
    }
    let peer_ifindex = dev.link_ifindex?;
    let peer = state.devices.iter().find(|peer| {
        peer.ifindex == peer_ifindex
            && peer.kind == NetDeviceKind::Veth
            && peer.link_ifindex == Some(ifindex)
    })?;
    if peer.kind != NetDeviceKind::Veth
        || peer.link_ifindex != Some(ifindex)
        || (peer.flags & IFF_UP) == 0
    {
        return None;
    }
    Some((peer.net_ns_id, peer.snapshot()))
}

pub(crate) fn macvlan_upper_snapshots_by_link_in_namespace(
    ns_id: usize,
    lower_ifindex: i32,
) -> Vec<NetDeviceSnapshot> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .devices
        .iter()
        .filter(|dev| {
            dev.net_ns_id == ns_id
                && dev.kind == NetDeviceKind::Macvlan
                && dev.link_ifindex == Some(lower_ifindex)
                && (dev.flags & IFF_UP) != 0
        })
        .map(NetDevice::snapshot)
        .collect()
}

pub(crate) fn record_device_traffic_in_namespace(
    ns_id: usize,
    ifindex: i32,
    bytes: usize,
    outgoing: bool,
) {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return;
    };
    let bytes = bytes as u64;
    if outgoing {
        dev.stats.tx_bytes = dev.stats.tx_bytes.saturating_add(bytes);
        dev.stats.tx_packets = dev.stats.tx_packets.saturating_add(1);
    } else {
        dev.stats.rx_bytes = dev.stats.rx_bytes.saturating_add(bytes);
        dev.stats.rx_packets = dev.stats.rx_packets.saturating_add(1);
    }
}

fn ipv4_packet_summary(payload: &[u8]) -> Option<(u8, u64, Option<u8>)> {
    if payload.len() < 20 || (payload[0] >> 4) != 4 {
        return None;
    }
    let ihl = usize::from(payload[0] & 0x0f) * 4;
    if ihl < 20 || ihl > payload.len() {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if total_len < ihl {
        return None;
    }
    let packet_len = total_len.min(payload.len());
    let protocol = payload[9];
    let icmp_type = (protocol == IPPROTO_ICMP && packet_len > ihl).then_some(payload[ihl]);
    Some((protocol, packet_len as u64, icmp_type))
}

pub(crate) fn record_protocol_packet_in_namespace(ns_id: usize, payload: &[u8], outgoing: bool) {
    let Some((protocol, bytes, icmp_type)) = ipv4_packet_summary(payload) else {
        return;
    };
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let stats = state.protocol_stats_mut_in(ns_id);
    if outgoing {
        stats.ip_out_requests = stats.ip_out_requests.saturating_add(1);
        stats.ip_out_octets = stats.ip_out_octets.saturating_add(bytes);
        match protocol {
            IPPROTO_ICMP => {
                stats.icmp_out_msgs = stats.icmp_out_msgs.saturating_add(1);
                match icmp_type {
                    Some(ICMP_ECHO) => {
                        stats.icmp_out_echos = stats.icmp_out_echos.saturating_add(1)
                    }
                    Some(ICMP_ECHOREPLY) => {
                        stats.icmp_out_echo_reps = stats.icmp_out_echo_reps.saturating_add(1)
                    }
                    _ => {}
                }
            }
            IPPROTO_TCP => stats.tcp_out_segs = stats.tcp_out_segs.saturating_add(1),
            IPPROTO_UDP => stats.udp_out_datagrams = stats.udp_out_datagrams.saturating_add(1),
            _ => {}
        }
    } else {
        stats.ip_in_receives = stats.ip_in_receives.saturating_add(1);
        stats.ip_in_delivers = stats.ip_in_delivers.saturating_add(1);
        stats.ip_in_octets = stats.ip_in_octets.saturating_add(bytes);
        match protocol {
            IPPROTO_ICMP => {
                stats.icmp_in_msgs = stats.icmp_in_msgs.saturating_add(1);
                match icmp_type {
                    Some(ICMP_ECHO) => stats.icmp_in_echos = stats.icmp_in_echos.saturating_add(1),
                    Some(ICMP_ECHOREPLY) => {
                        stats.icmp_in_echo_reps = stats.icmp_in_echo_reps.saturating_add(1)
                    }
                    _ => {}
                }
            }
            IPPROTO_TCP => stats.tcp_in_segs = stats.tcp_in_segs.saturating_add(1),
            IPPROTO_UDP => stats.udp_in_datagrams = stats.udp_in_datagrams.saturating_add(1),
            _ => {}
        }
    }
}

fn protocol_stats_snapshot() -> NetProtocolStats {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state.protocol_stats_in(ns_id)
}

pub(crate) fn is_local_ipv4_addr_in_namespace(ns_id: usize, addr: [u8; 4]) -> bool {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .devices
        .iter()
        .any(|dev| dev.net_ns_id == ns_id && dev.addrs.iter().any(|entry| entry.addr == addr))
}

pub(crate) fn is_local_ipv4_addr_on_device_in_namespace(
    ns_id: usize,
    ifindex: i32,
    addr: [u8; 4],
) -> bool {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .device_by_index_in(ns_id, ifindex)
        .is_some_and(|dev| dev.addrs.iter().any(|entry| entry.addr == addr))
}

pub(crate) fn ifindex_by_ipv4_addr_in_namespace(ns_id: usize, addr: [u8; 4]) -> Option<i32> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .devices
        .iter()
        .find(|dev| dev.net_ns_id == ns_id && dev.addrs.iter().any(|entry| entry.addr == addr))
        .map(|dev| dev.ifindex)
}

pub(crate) fn primary_ipv4_addr_by_ifindex_in_namespace(
    ns_id: usize,
    ifindex: i32,
) -> Option<[u8; 4]> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .device_by_index_in(ns_id, ifindex)
        .and_then(|dev| dev.addrs.first().map(|entry| entry.addr))
}

pub(crate) fn is_local_ipv6_addr_in_namespace(ns_id: usize, addr: [u8; 16]) -> bool {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .devices
        .iter()
        .any(|dev| dev.net_ns_id == ns_id && dev.addrs6.iter().any(|entry| entry.addr == addr))
}

pub(crate) fn is_local_ipv6_addr_on_device_in_namespace(
    ns_id: usize,
    ifindex: i32,
    addr: [u8; 16],
) -> bool {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .device_by_index_in(ns_id, ifindex)
        .is_some_and(|dev| dev.addrs6.iter().any(|entry| entry.addr == addr))
}

pub(crate) fn ifindex_by_ipv6_addr_in_namespace(ns_id: usize, addr: [u8; 16]) -> Option<i32> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .devices
        .iter()
        .find(|dev| dev.net_ns_id == ns_id && dev.addrs6.iter().any(|entry| entry.addr == addr))
        .map(|dev| dev.ifindex)
}

pub(crate) fn direct_veth_peer_for_ipv6_destination(
    ns_id: usize,
    bound_ifindex: i32,
    local: Option<[u8; 16]>,
    dst: [u8; 16],
) -> Option<(usize, NetDeviceSnapshot)> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);

    let selected = if bound_ifindex > 0 {
        state.devices.iter().position(|dev| {
            dev.net_ns_id == ns_id && dev.ifindex == bound_ifindex && (dev.flags & IFF_UP) != 0
        })?
    } else if let Some(local) = local {
        state.devices.iter().position(|dev| {
            dev.net_ns_id == ns_id
                && (dev.flags & IFF_UP) != 0
                && dev.addrs6.iter().any(|entry| entry.addr == local)
        })?
    } else {
        state
            .devices
            .iter()
            .enumerate()
            .filter(|(_, dev)| dev.net_ns_id == ns_id && (dev.flags & IFF_UP) != 0)
            .filter_map(|(idx, dev)| {
                dev.addrs6
                    .iter()
                    .filter(|entry| ipv6_same_prefix(entry.addr, dst, entry.prefix_len))
                    .map(|entry| (idx, entry.prefix_len))
                    .max_by_key(|(_, prefix_len)| *prefix_len)
            })
            .max_by_key(|(_, prefix_len)| *prefix_len)
            .map(|(idx, _)| idx)?
    };

    let dev = &state.devices[selected];
    if dev.kind != NetDeviceKind::Veth {
        return None;
    }
    let peer_ifindex = dev.link_ifindex?;
    let peer = state.devices.iter().find(|peer| {
        peer.ifindex == peer_ifindex
            && peer.kind == NetDeviceKind::Veth
            && peer.link_ifindex == Some(dev.ifindex)
            && (peer.flags & IFF_UP) != 0
            && peer.addrs6.iter().any(|entry| entry.addr == dst)
    })?;
    Some((peer.net_ns_id, peer.snapshot()))
}

pub(crate) fn direct_veth_peer_for_ipv4_destination(
    ns_id: usize,
    bound_ifindex: i32,
    local: Option<[u8; 4]>,
    dst: [u8; 4],
) -> Option<(usize, NetDeviceSnapshot)> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);

    let selected = if bound_ifindex > 0 {
        state.devices.iter().position(|dev| {
            dev.net_ns_id == ns_id && dev.ifindex == bound_ifindex && (dev.flags & IFF_UP) != 0
        })?
    } else if let Some(local) = local {
        state.devices.iter().position(|dev| {
            dev.net_ns_id == ns_id
                && (dev.flags & IFF_UP) != 0
                && dev.addrs.iter().any(|entry| entry.addr == local)
        })?
    } else {
        state
            .devices
            .iter()
            .enumerate()
            .filter(|(_, dev)| dev.net_ns_id == ns_id && (dev.flags & IFF_UP) != 0)
            .filter_map(|(idx, dev)| {
                dev.addrs
                    .iter()
                    .filter(|entry| ipv4_same_prefix(entry.addr, dst, entry.prefix_len))
                    .map(|entry| (idx, entry.prefix_len))
                    .max_by_key(|(_, prefix_len)| *prefix_len)
            })
            .max_by_key(|(_, prefix_len)| *prefix_len)
            .map(|(idx, _)| idx)?
    };

    let dev = &state.devices[selected];
    if dev.kind != NetDeviceKind::Veth {
        return None;
    }
    let peer_ifindex = dev.link_ifindex?;
    let peer = state.devices.iter().find(|peer| {
        peer.ifindex == peer_ifindex
            && peer.kind == NetDeviceKind::Veth
            && peer.link_ifindex == Some(dev.ifindex)
            && (peer.flags & IFF_UP) != 0
            && peer
                .addrs
                .iter()
                .any(|entry| entry.addr == dst || entry.peer_addr == dst)
    })?;
    Some((peer.net_ns_id, peer.snapshot()))
}

pub(crate) fn default_ipv4_ifindex_in_namespace(ns_id: usize) -> Option<i32> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .devices
        .iter()
        .find(|dev| {
            dev.net_ns_id == ns_id
                && dev.kind != NetDeviceKind::Loopback
                && (dev.flags & IFF_UP) != 0
                && !dev.addrs.is_empty()
        })
        .or_else(|| {
            state
                .devices
                .iter()
                .find(|dev| dev.net_ns_id == ns_id && !dev.addrs.is_empty())
        })
        .map(|dev| dev.ifindex)
}

pub(crate) fn route_ifindex_for_gateway_in_namespace(
    ns_id: usize,
    gateway: Option<[u8; 4]>,
) -> Option<i32> {
    let Some(gateway) = gateway else {
        return default_ipv4_ifindex_in_namespace(ns_id);
    };
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);

    state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id && (dev.flags & IFF_UP) != 0)
        .filter_map(|dev| {
            dev.addrs
                .iter()
                .filter(|entry| ipv4_same_prefix(entry.addr, gateway, entry.prefix_len))
                .map(|entry| (dev.ifindex, entry.prefix_len))
                .max_by_key(|(_, prefix_len)| *prefix_len)
        })
        .max_by_key(|(_, prefix_len)| *prefix_len)
        .map(|(ifindex, _)| ifindex)
        .or_else(|| {
            state
                .devices
                .iter()
                .find(|dev| {
                    dev.net_ns_id == ns_id
                        && dev.kind != NetDeviceKind::Loopback
                        && (dev.flags & IFF_UP) != 0
                        && !dev.addrs.is_empty()
                })
                .or_else(|| {
                    state.devices.iter().find(|dev| {
                        dev.net_ns_id == ns_id && (dev.flags & IFF_UP) != 0 && !dev.addrs.is_empty()
                    })
                })
                .map(|dev| dev.ifindex)
        })
}

pub(crate) fn ipv4_path_mtu_in_namespace(
    ns_id: usize,
    bound_ifindex: i32,
    local: Option<[u8; 4]>,
    dst: Option<[u8; 4]>,
) -> Option<u32> {
    let dst = dst?;
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);

    if bound_ifindex > 0 {
        return state
            .device_by_index_in(ns_id, bound_ifindex)
            .map(|dev| dev.mtu);
    }

    if let Some(local) = local
        && let Some(dev) = state
            .devices
            .iter()
            .find(|dev| dev.net_ns_id == ns_id && dev.addrs.iter().any(|entry| entry.addr == local))
    {
        return Some(dev.mtu);
    }

    if let Some(dev) = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id && (dev.flags & IFF_UP) != 0)
        .filter_map(|dev| {
            dev.addrs
                .iter()
                .filter(|entry| ipv4_same_prefix(entry.addr, dst, entry.prefix_len))
                .map(|entry| (dev, entry.prefix_len))
                .max_by_key(|(_, prefix_len)| *prefix_len)
        })
        .max_by_key(|(_, prefix_len)| *prefix_len)
        .map(|(dev, _)| dev)
    {
        return Some(dev.mtu);
    }

    if let Some(dev) = state
        .routes
        .iter()
        .filter(|route| ipv4_same_prefix(route.dst, dst, route.prefix_len))
        .max_by_key(|route| route.prefix_len)
        .and_then(|route| {
            state
                .device_by_index_in(ns_id, route.ifindex)
                .filter(|dev| (dev.flags & IFF_UP) != 0)
        })
    {
        return Some(dev.mtu);
    }

    state
        .devices
        .iter()
        .find(|dev| {
            dev.net_ns_id == ns_id
                && dev.kind != NetDeviceKind::Loopback
                && (dev.flags & IFF_UP) != 0
        })
        .or_else(|| state.devices.iter().find(|dev| dev.net_ns_id == ns_id))
        .map(|dev| dev.mtu)
}

pub(crate) fn ipv4_link_scope_reachable_in_namespace(
    ns_id: usize,
    bound_ifindex: i32,
    local: Option<[u8; 4]>,
    dst: [u8; 4],
) -> bool {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);

    let device_accepts = |dev: &NetDevice| {
        if (dev.flags & IFF_UP) == 0 {
            return false;
        }
        if let Some(local) = local
            && !dev.addrs.iter().any(|entry| entry.addr == local)
        {
            return false;
        }
        if ipv4_is_multicast_addr(dst) || device_has_ipv4_broadcast_addr(dev, dst) {
            return true;
        }
        dev.addrs
            .iter()
            .any(|entry| ipv4_same_prefix(entry.addr, dst, entry.prefix_len))
    };

    if bound_ifindex > 0 {
        return state
            .device_by_index_in(ns_id, bound_ifindex)
            .is_some_and(device_accepts);
    }

    if let Some(local) = local {
        return state
            .devices
            .iter()
            .find(|dev| dev.net_ns_id == ns_id && dev.addrs.iter().any(|entry| entry.addr == local))
            .is_some_and(device_accepts);
    }

    state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .any(device_accepts)
}

pub(crate) fn select_ipv4_source_addr_in_namespace(ns_id: usize, dst: [u8; 4]) -> Option<[u8; 4]> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);

    if let Some((addr, _prefix_len)) = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id && (dev.flags & IFF_UP) != 0)
        .flat_map(|dev| dev.addrs.iter())
        .filter(|entry| ipv4_same_prefix(entry.addr, dst, entry.prefix_len))
        .map(|entry| (entry.addr, entry.prefix_len))
        .max_by_key(|(_, prefix_len)| *prefix_len)
    {
        return Some(addr);
    }

    if let Some(addr) = state
        .routes
        .iter()
        .filter(|route| ipv4_same_prefix(route.dst, dst, route.prefix_len))
        .max_by_key(|route| route.prefix_len)
        .and_then(|route| {
            state
                .device_by_index_in(ns_id, route.ifindex)
                .filter(|dev| (dev.flags & IFF_UP) != 0)
                .and_then(|dev| dev.addrs.first().map(|entry| entry.addr))
        })
    {
        return Some(addr);
    }

    state
        .devices
        .iter()
        .find(|dev| {
            dev.net_ns_id == ns_id
                && dev.kind != NetDeviceKind::Loopback
                && (dev.flags & IFF_UP) != 0
                && !dev.addrs.is_empty()
        })
        .and_then(|dev| dev.addrs.first().map(|entry| entry.addr))
}

pub(crate) fn select_ipv6_source_addr_in_namespace(
    ns_id: usize,
    dst: [u8; 16],
) -> Option<[u8; 16]> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);

    if let Some((addr, _prefix_len)) = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id && (dev.flags & IFF_UP) != 0)
        .flat_map(|dev| dev.addrs6.iter())
        .filter(|entry| ipv6_same_prefix(entry.addr, dst, entry.prefix_len))
        .map(|entry| (entry.addr, entry.prefix_len))
        .max_by_key(|(_, prefix_len)| *prefix_len)
    {
        return Some(addr);
    }

    state
        .devices
        .iter()
        .find(|dev| {
            dev.net_ns_id == ns_id
                && dev.kind != NetDeviceKind::Loopback
                && (dev.flags & IFF_UP) != 0
                && !dev.addrs6.is_empty()
        })
        .and_then(|dev| dev.addrs6.first().map(|entry| entry.addr))
        .or_else(|| {
            state
                .devices
                .iter()
                .find(|dev| {
                    dev.net_ns_id == ns_id
                        && dev.kind == NetDeviceKind::Loopback
                        && (dev.flags & IFF_UP) != 0
                })
                .and_then(|dev| dev.addrs6.first().map(|entry| entry.addr))
        })
}

pub(crate) fn select_ipv4_source_addr_on_device_in_namespace(
    ns_id: usize,
    ifindex: i32,
    dst: [u8; 4],
) -> Option<[u8; 4]> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let dev = state.device_by_index_in(ns_id, ifindex)?;
    if (dev.flags & IFF_UP) == 0 {
        return None;
    }
    dev.addrs
        .iter()
        .filter(|entry| ipv4_same_prefix(entry.addr, dst, entry.prefix_len))
        .max_by_key(|entry| entry.prefix_len)
        .or_else(|| dev.addrs.first())
        .map(|entry| entry.addr)
}

pub(crate) fn select_ipv6_source_addr_on_device_in_namespace(
    ns_id: usize,
    ifindex: i32,
    dst: [u8; 16],
) -> Option<[u8; 16]> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let dev = state.device_by_index_in(ns_id, ifindex)?;
    if (dev.flags & IFF_UP) == 0 {
        return None;
    }
    dev.addrs6
        .iter()
        .filter(|entry| ipv6_same_prefix(entry.addr, dst, entry.prefix_len))
        .max_by_key(|entry| entry.prefix_len)
        .or_else(|| dev.addrs6.first())
        .map(|entry| entry.addr)
}

pub(crate) fn ifindex_by_name(name: &str) -> Option<i32> {
    let ns_id = current_net_ns_id();
    ifindex_by_name_in_namespace(ns_id, name)
}

pub(crate) fn ifindex_by_name_in_namespace(ns_id: usize, name: &str) -> Option<i32> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state.device_by_name_in(ns_id, name).map(|dev| dev.ifindex)
}

pub(crate) fn name_by_ifindex(ifindex: i32) -> Option<String> {
    let ns_id = current_net_ns_id();
    name_by_ifindex_in_namespace(ns_id, ifindex)
}

pub(crate) fn name_by_ifindex_in_namespace(ns_id: usize, ifindex: i32) -> Option<String> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state
        .device_by_index_in(ns_id, ifindex)
        .map(|dev| dev.name.clone())
}

pub(crate) fn create_link(name: &str, kind: NetDeviceKind) -> Result<(), isize> {
    create_link_in_namespace(current_net_ns_id(), name, kind)
}

pub(crate) fn create_link_in_namespace(
    ns_id: usize,
    name: &str,
    kind: NetDeviceKind,
) -> Result<(), isize> {
    create_link_with_iflink_in_namespace(ns_id, name, kind, None)
}

pub(crate) fn create_link_with_iflink_in_namespace(
    ns_id: usize,
    name: &str,
    kind: NetDeviceKind,
    link_ifindex: Option<i32>,
) -> Result<(), isize> {
    if !valid_ifname(name) {
        return Err(errno(SyscallError::EINVAL));
    }
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    if state.device_by_name_in(ns_id, name).is_some() {
        return Err(errno(SyscallError::EEXIST));
    }
    if let Some(link_ifindex) = link_ifindex
        && state.device_by_index_in(ns_id, link_ifindex).is_none()
    {
        return Err(errno(SyscallError::ENODEV));
    }
    let ifindex = state.alloc_ifindex();
    let flags = match kind {
        NetDeviceKind::Dummy => IFF_BROADCAST | IFF_NOARP,
        NetDeviceKind::Veth
        | NetDeviceKind::Macvlan
        | NetDeviceKind::Ipvlan
        | NetDeviceKind::Macvtap
        | NetDeviceKind::Tap => IFF_BROADCAST | IFF_MULTICAST,
        NetDeviceKind::Wireguard => IFF_POINTOPOINT | IFF_NOARP,
        NetDeviceKind::Tun => IFF_NOARP | IFF_MULTICAST,
        NetDeviceKind::Loopback | NetDeviceKind::Ethernet => {
            return Err(errno(SyscallError::EOPNOTSUPP));
        }
    };
    let dev = NetDevice {
        net_ns_id: ns_id,
        ifindex,
        name: name.to_string(),
        kind,
        link_ifindex,
        link_type: kind.arp_type(),
        flags,
        mtu: if kind == NetDeviceKind::Wireguard {
            1420
        } else {
            1500
        },
        tx_queue_len: 1000,
        hwaddr: if kind == NetDeviceKind::Wireguard {
            [0; 6]
        } else {
            generated_hwaddr(ifindex)
        },
        addrs: Vec::new(),
        addrs6: Vec::new(),
        maddrs: Vec::new(),
        uaddrs: Vec::new(),
        promiscuity: 0,
        allmulti: 0,
        stats: NetDeviceStats::default(),
        qdisc: None,
        builtin: false,
    };
    let snapshot = dev.snapshot();
    state.devices.push(dev);
    drop(state);
    super::netlink::notify_link_created(ns_id, snapshot);
    Ok(())
}

pub(crate) fn create_veth_pair_between_namespaces(
    ns_id: usize,
    name: &str,
    peer_ns_id: usize,
    peer_name: &str,
) -> Result<(), isize> {
    if !valid_ifname(name) || !valid_ifname(peer_name) {
        return Err(errno(SyscallError::EINVAL));
    }
    if ns_id == peer_ns_id && name == peer_name {
        return Err(errno(SyscallError::EEXIST));
    }
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    state.ensure_namespace(peer_ns_id);
    if state.device_by_name_in(ns_id, name).is_some() {
        return Err(errno(SyscallError::EEXIST));
    }
    if state.device_by_name_in(peer_ns_id, peer_name).is_some() {
        return Err(errno(SyscallError::EEXIST));
    }
    let ifindex = state.alloc_ifindex();
    let peer_ifindex = state.alloc_ifindex();
    let flags = IFF_BROADCAST | IFF_MULTICAST;
    let dev = NetDevice {
        net_ns_id: ns_id,
        ifindex,
        name: name.to_string(),
        kind: NetDeviceKind::Veth,
        link_ifindex: Some(peer_ifindex),
        link_type: NetDeviceKind::Veth.arp_type(),
        flags,
        mtu: 1500,
        tx_queue_len: 1000,
        hwaddr: generated_hwaddr(ifindex),
        addrs: Vec::new(),
        addrs6: Vec::new(),
        maddrs: Vec::new(),
        uaddrs: Vec::new(),
        promiscuity: 0,
        allmulti: 0,
        stats: NetDeviceStats::default(),
        qdisc: None,
        builtin: false,
    };
    let peer = NetDevice {
        net_ns_id: peer_ns_id,
        ifindex: peer_ifindex,
        name: peer_name.to_string(),
        kind: NetDeviceKind::Veth,
        link_ifindex: Some(ifindex),
        link_type: NetDeviceKind::Veth.arp_type(),
        flags,
        mtu: 1500,
        tx_queue_len: 1000,
        hwaddr: generated_hwaddr(peer_ifindex),
        addrs: Vec::new(),
        addrs6: Vec::new(),
        maddrs: Vec::new(),
        uaddrs: Vec::new(),
        promiscuity: 0,
        allmulti: 0,
        stats: NetDeviceStats::default(),
        qdisc: None,
        builtin: false,
    };
    let snapshot = dev.snapshot();
    let peer_snapshot = peer.snapshot();
    state.devices.push(dev);
    state.devices.push(peer);
    drop(state);
    super::netlink::notify_link_created(ns_id, snapshot);
    super::netlink::notify_link_created(peer_ns_id, peer_snapshot);
    Ok(())
}

fn remove_link_at(state: &mut NetState, pos: usize) -> Vec<(usize, NetDeviceSnapshot)> {
    let ifindex = state.devices[pos].ifindex;
    let peer_ifindex = (state.devices[pos].kind == NetDeviceKind::Veth)
        .then_some(state.devices[pos].link_ifindex)
        .flatten();
    let mut removed = Vec::new();
    let dev = state.devices.remove(pos);
    if dev.kind == NetDeviceKind::Wireguard {
        super::wireguard::remove_config(dev.ifindex);
    }
    removed.push((dev.net_ns_id, dev.snapshot()));

    if let Some(peer_ifindex) = peer_ifindex
        && let Some(peer_pos) = state.devices.iter().position(|dev| {
            dev.kind == NetDeviceKind::Veth
                && dev.ifindex == peer_ifindex
                && dev.link_ifindex == Some(ifindex)
        })
    {
        let peer = state.devices.remove(peer_pos);
        if peer.kind == NetDeviceKind::Wireguard {
            super::wireguard::remove_config(peer.ifindex);
        }
        removed.push((peer.net_ns_id, peer.snapshot()));
    }

    let removed_ifindexes: Vec<i32> = removed.iter().map(|(_, dev)| dev.ifindex).collect();
    state
        .routes
        .retain(|route| !removed_ifindexes.contains(&route.ifindex));
    state
        .neighs
        .retain(|neigh| !removed_ifindexes.contains(&neigh.ifindex));
    removed
}

pub(crate) fn cleanup_net_namespace(ns_id: usize) {
    if ns_id == 0 {
        return;
    }
    let mut removed = Vec::new();
    {
        let mut state = NET_STATE.lock();
        while let Some(pos) = state.devices.iter().position(|dev| dev.net_ns_id == ns_id) {
            removed.extend(remove_link_at(&mut state, pos));
        }
        let live_ifindexes: Vec<i32> = state.devices.iter().map(|dev| dev.ifindex).collect();
        state
            .routes
            .retain(|route| live_ifindexes.contains(&route.ifindex));
        state
            .neighs
            .retain(|neigh| live_ifindexes.contains(&neigh.ifindex));
    }
    for (removed_ns_id, snapshot) in removed {
        super::netlink::notify_link_deleted(removed_ns_id, snapshot);
    }
}

fn set_link_in_namespace_inner(
    ns_id: usize,
    ifindex: i32,
    new_name: Option<&str>,
    mtu: Option<u32>,
    tx_queue_len: Option<u32>,
    flags: Option<(u32, u32)>,
    notify: bool,
) -> Result<(), isize> {
    if let Some(name) = new_name
        && !valid_ifname(name)
    {
        return Err(errno(SyscallError::EINVAL));
    }
    let changed = {
        let mut state = NET_STATE.lock();
        state.ensure_namespace(ns_id);
        let Some(pos) = state
            .devices
            .iter()
            .position(|dev| dev.net_ns_id == ns_id && dev.ifindex == ifindex)
        else {
            return Err(errno(SyscallError::ENODEV));
        };

        let mut renamed = false;
        if let Some(name) = new_name
            && state.devices[pos].name != name
        {
            if (state.devices[pos].flags & IFF_UP) != 0 {
                return Err(errno(SyscallError::EBUSY));
            }
            if state.device_by_name_in(ns_id, name).is_some() {
                return Err(errno(SyscallError::EEXIST));
            }
            state.devices[pos].name = name.to_string();
            renamed = true;
        }

        let dev = &mut state.devices[pos];
        let mut changed = renamed;
        if let Some(mtu) = mtu {
            if mtu == 0 {
                return Err(errno(SyscallError::EINVAL));
            }
            if dev.mtu != mtu {
                dev.mtu = mtu;
                changed = true;
            }
        }
        if let Some(tx_queue_len) = tx_queue_len
            && dev.tx_queue_len != tx_queue_len
        {
            dev.tx_queue_len = tx_queue_len;
            changed = true;
        }
        if let Some((new_flags, change)) = flags {
            let mask = if change == 0 { IFF_UP } else { change };
            let mut flags = (dev.flags & !mask) | (new_flags & mask);
            if (flags & IFF_UP) != 0 {
                flags |= IFF_RUNNING;
            } else if dev.kind != NetDeviceKind::Loopback {
                flags &= !IFF_RUNNING;
            }
            if dev.flags != flags {
                dev.flags = flags;
                changed = true;
            }
        }
        changed.then(|| dev.snapshot())
    };
    if notify && let Some(snapshot) = changed {
        super::netlink::notify_link_changed(ns_id, snapshot);
    }
    Ok(())
}

pub(crate) fn delete_link_by_index(ifindex: i32) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(pos) = state
        .devices
        .iter()
        .position(|dev| dev.net_ns_id == ns_id && dev.ifindex == ifindex)
    else {
        return Err(errno(SyscallError::ENODEV));
    };
    if state.devices[pos].builtin {
        return Err(errno(SyscallError::EOPNOTSUPP));
    }
    let removed = remove_link_at(&mut state, pos);
    drop(state);
    for (removed_ns_id, snapshot) in removed {
        super::netlink::notify_link_deleted(removed_ns_id, snapshot);
    }
    Ok(())
}

pub(crate) fn delete_link_by_global_ifindex(ifindex: i32) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    let Some(pos) = state.devices.iter().position(|dev| dev.ifindex == ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    if state.devices[pos].builtin {
        return Err(errno(SyscallError::EOPNOTSUPP));
    }
    let removed = remove_link_at(&mut state, pos);
    drop(state);
    for (ns_id, snapshot) in removed {
        super::netlink::notify_link_deleted(ns_id, snapshot);
    }
    Ok(())
}

pub(crate) fn delete_link_by_name_in_namespace(ns_id: usize, name: &str) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(pos) = state
        .devices
        .iter()
        .position(|dev| dev.net_ns_id == ns_id && dev.name == name)
    else {
        return Err(errno(SyscallError::ENODEV));
    };
    if state.devices[pos].builtin {
        return Err(errno(SyscallError::EOPNOTSUPP));
    }
    let removed = remove_link_at(&mut state, pos);
    drop(state);
    for (removed_ns_id, snapshot) in removed {
        super::netlink::notify_link_deleted(removed_ns_id, snapshot);
    }
    Ok(())
}

pub(crate) fn set_link(
    ifindex: i32,
    mtu: Option<u32>,
    tx_queue_len: Option<u32>,
    flags: Option<(u32, u32)>,
) -> Result<(), isize> {
    set_link_with_name(ifindex, None, mtu, tx_queue_len, flags)
}

pub(crate) fn set_link_with_name(
    ifindex: i32,
    new_name: Option<&str>,
    mtu: Option<u32>,
    tx_queue_len: Option<u32>,
    flags: Option<(u32, u32)>,
) -> Result<(), isize> {
    set_link_in_namespace_inner(
        current_net_ns_id(),
        ifindex,
        new_name,
        mtu,
        tx_queue_len,
        flags,
        true,
    )
}

pub(crate) fn set_link_in_namespace(
    ns_id: usize,
    ifindex: i32,
    mtu: Option<u32>,
    tx_queue_len: Option<u32>,
    flags: Option<(u32, u32)>,
) -> Result<(), isize> {
    set_link_in_namespace_inner(ns_id, ifindex, None, mtu, tx_queue_len, flags, false)
}

pub(crate) fn set_link_type_by_global_ifindex(ifindex: i32, link_type: u16) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    let Some(dev) = state.devices.iter_mut().find(|dev| dev.ifindex == ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    if (dev.flags & IFF_UP) != 0 {
        return Err(errno(SyscallError::EBUSY));
    }
    dev.link_type = link_type;
    Ok(())
}

pub(crate) fn add_ipv4_addr_with_attrs(
    ifindex: i32,
    addr: [u8; 4],
    peer_addr: [u8; 4],
    prefix_len: u8,
    broadcast_addr: Option<[u8; 4]>,
    scope: u8,
    label: Option<&str>,
) -> Result<(), isize> {
    if prefix_len > 32 {
        return Err(errno(SyscallError::EINVAL));
    }
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let label = normalize_addr_label(&dev.name, label)?;
    let broadcast_addr =
        broadcast_addr.or_else(|| default_broadcast_addr(dev.flags, addr, prefix_len));
    let slot = if label.is_some() {
        dev.addrs
            .iter_mut()
            .find(|entry| entry.label.as_deref() == label.as_deref())
    } else {
        dev.addrs.iter_mut().find(|entry| {
            entry.label.is_none() && entry.addr == addr && entry.prefix_len == prefix_len
        })
    };
    if let Some(slot) = slot {
        slot.addr = addr;
        slot.peer_addr = peer_addr;
        slot.prefix_len = prefix_len;
        slot.label = label;
        slot.broadcast_addr = broadcast_addr;
        slot.scope = scope;
    } else {
        dev.addrs.push(Ipv4AddrEntry {
            addr,
            peer_addr,
            prefix_len,
            label,
            broadcast_addr,
            scope,
        });
    }
    Ok(())
}

pub(crate) fn add_ipv6_addr_with_attrs(
    ifindex: i32,
    addr: [u8; 16],
    prefix_len: u8,
    scope: u8,
    label: Option<&str>,
) -> Result<(), isize> {
    if prefix_len > 128 {
        return Err(errno(SyscallError::EINVAL));
    }
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let label = normalize_addr_label(&dev.name, label)?;
    let slot = if label.is_some() {
        dev.addrs6
            .iter_mut()
            .find(|entry| entry.label.as_deref() == label.as_deref())
    } else {
        dev.addrs6.iter_mut().find(|entry| {
            entry.label.is_none() && entry.addr == addr && entry.prefix_len == prefix_len
        })
    };
    if let Some(slot) = slot {
        slot.addr = addr;
        slot.prefix_len = prefix_len;
        slot.label = label;
        slot.scope = scope;
    } else {
        dev.addrs6.push(Ipv6AddrEntry {
            addr,
            prefix_len,
            label,
            scope,
        });
    }
    Ok(())
}

pub(crate) fn set_primary_ipv4_addr(
    ifindex: i32,
    addr: [u8; 4],
    prefix_len: u8,
    scope: u8,
) -> Result<(), isize> {
    if prefix_len > 32 {
        return Err(errno(SyscallError::EINVAL));
    }
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let broadcast_addr = default_broadcast_addr(dev.flags, addr, prefix_len);
    if let Some(entry) = dev.addrs.iter_mut().find(|entry| entry.label.is_none()) {
        if entry.addr == addr {
            return Ok(());
        }
        entry.addr = addr;
        entry.peer_addr = addr;
        entry.prefix_len = prefix_len;
        entry.label = None;
        entry.broadcast_addr = broadcast_addr;
        entry.scope = scope;
    } else {
        dev.addrs.insert(0, Ipv4AddrEntry {
            addr,
            peer_addr: addr,
            prefix_len,
            label: None,
            broadcast_addr,
            scope,
        });
    }
    Ok(())
}

pub(crate) fn add_labeled_ipv4_addr(
    ifindex: i32,
    label: &str,
    addr: [u8; 4],
    prefix_len: u8,
    scope: u8,
) -> Result<(), isize> {
    add_ipv4_addr_with_attrs(ifindex, addr, addr, prefix_len, None, scope, Some(label))
}

pub(crate) fn set_primary_ipv4_prefix(ifindex: i32, prefix_len: u8) -> Result<(), isize> {
    if prefix_len > 32 {
        return Err(errno(SyscallError::EINVAL));
    }
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let flags = dev.flags;
    let Some(entry) = dev.addrs.iter_mut().find(|entry| entry.label.is_none()) else {
        return Err(errno(SyscallError::EADDRNOTAVAIL));
    };
    let old_auto = default_broadcast_addr(flags, entry.addr, entry.prefix_len);
    let new_auto = default_broadcast_addr(flags, entry.addr, prefix_len);
    entry.prefix_len = prefix_len;
    if entry.broadcast_addr == old_auto {
        entry.broadcast_addr = new_auto;
    }
    Ok(())
}

pub(crate) fn set_labeled_ipv4_prefix(
    ifindex: i32,
    label: &str,
    prefix_len: u8,
) -> Result<(), isize> {
    if prefix_len > 32 {
        return Err(errno(SyscallError::EINVAL));
    }
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let label = normalize_addr_label(&dev.name, Some(label))?;
    let flags = dev.flags;
    let Some(entry) = dev
        .addrs
        .iter_mut()
        .find(|entry| entry.label.as_deref() == label.as_deref())
    else {
        return Err(errno(SyscallError::EADDRNOTAVAIL));
    };
    let old_auto = default_broadcast_addr(flags, entry.addr, entry.prefix_len);
    let new_auto = default_broadcast_addr(flags, entry.addr, prefix_len);
    entry.prefix_len = prefix_len;
    if entry.broadcast_addr == old_auto {
        entry.broadcast_addr = new_auto;
    }
    Ok(())
}

pub(crate) fn set_primary_ipv4_peer_addr(ifindex: i32, peer_addr: [u8; 4]) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let Some(entry) = dev.addrs.iter_mut().find(|entry| entry.label.is_none()) else {
        return Err(errno(SyscallError::EADDRNOTAVAIL));
    };
    entry.peer_addr = peer_addr;
    Ok(())
}

pub(crate) fn set_primary_ipv4_broadcast_addr(
    ifindex: i32,
    broadcast_addr: [u8; 4],
) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let Some(entry) = dev.addrs.iter_mut().find(|entry| entry.label.is_none()) else {
        return Err(errno(SyscallError::EADDRNOTAVAIL));
    };
    entry.broadcast_addr = Some(broadcast_addr);
    Ok(())
}

pub(crate) fn del_ipv4_addr(ifindex: i32, addr: [u8; 4], prefix_len: u8) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let old_len = dev.addrs.len();
    dev.addrs
        .retain(|entry| !(entry.addr == addr && entry.prefix_len == prefix_len));
    if dev.addrs.len() == old_len {
        return Err(errno(SyscallError::ENOENT));
    }
    Ok(())
}

pub(crate) fn del_ipv6_addr(ifindex: i32, addr: [u8; 16], prefix_len: u8) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let old_len = dev.addrs6.len();
    dev.addrs6
        .retain(|entry| !(entry.addr == addr && entry.prefix_len == prefix_len));
    if dev.addrs6.len() == old_len {
        return Err(errno(SyscallError::ENOENT));
    }
    Ok(())
}

pub(crate) fn del_ipv4_addr_any_prefix(ifindex: i32, addr: [u8; 4]) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let old_len = dev.addrs.len();
    dev.addrs.retain(|entry| entry.addr != addr);
    if dev.addrs.len() == old_len {
        return Err(errno(SyscallError::EADDRNOTAVAIL));
    }
    Ok(())
}

pub(crate) fn del_ipv4_addr_by_label(ifindex: i32, label: &str) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    let label = normalize_addr_label(&dev.name, Some(label))?;
    let old_len = dev.addrs.len();
    dev.addrs
        .retain(|entry| entry.label.as_deref() != label.as_deref());
    if dev.addrs.len() == old_len {
        return Err(errno(SyscallError::EADDRNOTAVAIL));
    }
    Ok(())
}

pub(crate) fn flush_ipv4_addrs(ifindex: i32) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    if ifindex > 0 {
        let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
            return Err(errno(SyscallError::ENODEV));
        };
        dev.addrs.clear();
        return Ok(());
    }
    for dev in state
        .devices
        .iter_mut()
        .filter(|dev| dev.net_ns_id == ns_id)
    {
        dev.addrs.clear();
    }
    Ok(())
}

pub(crate) fn flush_ipv6_addrs(ifindex: i32) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    if ifindex > 0 {
        let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
            return Err(errno(SyscallError::ENODEV));
        };
        dev.addrs6.clear();
        return Ok(());
    }
    for dev in state
        .devices
        .iter_mut()
        .filter(|dev| dev.net_ns_id == ns_id)
    {
        dev.addrs6.clear();
    }
    Ok(())
}

pub(crate) fn move_link_to_namespace_with_name(
    ifindex: i32,
    target_ns_id: usize,
    new_name: Option<&str>,
) -> Result<(), isize> {
    if let Some(name) = new_name
        && !valid_ifname(name)
    {
        return Err(errno(SyscallError::EINVAL));
    }
    let source_ns_id = current_net_ns_id();
    if source_ns_id == target_ns_id {
        return set_link_with_name(ifindex, new_name, None, None, None);
    }
    let mut state = NET_STATE.lock();
    state.ensure_namespace(source_ns_id);
    state.ensure_namespace(target_ns_id);
    let Some(pos) = state
        .devices
        .iter()
        .position(|dev| dev.net_ns_id == source_ns_id && dev.ifindex == ifindex)
    else {
        return Err(errno(SyscallError::ENODEV));
    };
    if state.devices[pos].builtin {
        return Err(errno(SyscallError::EINVAL));
    }
    let final_name = new_name.unwrap_or(&state.devices[pos].name).to_string();
    if state.device_by_name_in(target_ns_id, &final_name).is_some() {
        return Err(errno(SyscallError::EEXIST));
    }
    let old_snapshot = state.devices[pos].snapshot();
    state.devices[pos].net_ns_id = target_ns_id;
    state.devices[pos].name = final_name;
    let new_snapshot = state.devices[pos].snapshot();
    state.routes.retain(|route| route.ifindex != ifindex);
    state.neighs.retain(|neigh| neigh.ifindex != ifindex);
    drop(state);
    super::netlink::notify_link_deleted(source_ns_id, old_snapshot);
    super::netlink::notify_link_created(target_ns_id, new_snapshot);
    Ok(())
}

pub(crate) fn add_route(
    dst: [u8; 4],
    prefix_len: u8,
    gateway: Option<[u8; 4]>,
    ifindex: i32,
    create: bool,
    replace: bool,
    excl: bool,
) -> Result<(), isize> {
    if prefix_len > 32 {
        return Err(errno(SyscallError::EINVAL));
    }
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    if state.device_by_index_in(ns_id, ifindex).is_none() {
        return Err(errno(SyscallError::ENODEV));
    }
    let visible_ifindexes: Vec<i32> = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .map(|dev| dev.ifindex)
        .collect();

    let same_prefix = |r: &RouteEntry| {
        visible_ifindexes.contains(&r.ifindex) && r.dst == dst && r.prefix_len == prefix_len
    };
    let prefix_pos = state.routes.iter().position(same_prefix);
    if excl && prefix_pos.is_some() {
        return Err(errno(SyscallError::EEXIST));
    }

    let exact_pos = state
        .routes
        .iter()
        .position(|r| same_prefix(r) && r.gateway == gateway && r.ifindex == ifindex);
    if let Some(pos) = exact_pos {
        if replace {
            state.routes[pos] = RouteEntry {
                dst,
                prefix_len,
                gateway,
                ifindex,
            };
            return Ok(());
        }
        return Err(errno(SyscallError::EEXIST));
    }

    if let Some(pos) = prefix_pos {
        if replace {
            state.routes[pos] = RouteEntry {
                dst,
                prefix_len,
                gateway,
                ifindex,
            };
            return Ok(());
        }
        if !create {
            return Err(errno(SyscallError::ENOENT));
        }
    }

    if !create {
        return Err(errno(SyscallError::ENOENT));
    }
    state.routes.push(RouteEntry {
        dst,
        prefix_len,
        gateway,
        ifindex,
    });
    Ok(())
}

pub(crate) fn del_route(
    dst: [u8; 4],
    prefix_len: u8,
    gateway: Option<[u8; 4]>,
    ifindex: Option<i32>,
) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let ifindex = ifindex.filter(|ifindex| *ifindex > 0);
    if let Some(ifindex) = ifindex
        && state.device_by_index_in(ns_id, ifindex).is_none()
    {
        return Err(errno(SyscallError::ENODEV));
    }
    let visible_ifindexes: Vec<i32> = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .map(|dev| dev.ifindex)
        .collect();
    let Some(pos) = state.routes.iter().position(|r| {
        visible_ifindexes.contains(&r.ifindex)
            && r.dst == dst
            && r.prefix_len == prefix_len
            && gateway.is_none_or(|gateway| r.gateway == Some(gateway))
            && ifindex.is_none_or(|ifindex| r.ifindex == ifindex)
    }) else {
        return Err(errno(SyscallError::ENOENT));
    };
    state.routes.remove(pos);
    Ok(())
}

pub(crate) fn flush_routes(ifindex: i32) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    if ifindex > 0 {
        if state.device_by_index_in(ns_id, ifindex).is_none() {
            return Err(errno(SyscallError::ENODEV));
        }
        state.routes.retain(|route| route.ifindex != ifindex);
    } else {
        let visible_ifindexes: Vec<i32> = state
            .devices
            .iter()
            .filter(|dev| dev.net_ns_id == ns_id)
            .map(|dev| dev.ifindex)
            .collect();
        state
            .routes
            .retain(|route| !visible_ifindexes.contains(&route.ifindex));
    }
    Ok(())
}

pub(crate) fn add_neigh(ifindex: i32, dst: [u8; 4], lladdr: [u8; 6]) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    if state.device_by_index_in(ns_id, ifindex).is_none() {
        return Err(errno(SyscallError::ENODEV));
    }
    if let Some(entry) = state
        .neighs
        .iter_mut()
        .find(|entry| entry.ifindex == ifindex && entry.dst == dst)
    {
        entry.lladdr = lladdr;
    } else {
        state.neighs.push(NeighEntry {
            dst,
            lladdr,
            ifindex,
        });
    }
    Ok(())
}

pub(crate) fn neigh_snapshot(ifindex: Option<i32>, dst: [u8; 4]) -> Option<NeighEntry> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let visible_ifindexes: Vec<i32> = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .map(|dev| dev.ifindex)
        .collect();
    if let Some(ifindex) = ifindex
        && !visible_ifindexes.contains(&ifindex)
    {
        return None;
    }
    state
        .neighs
        .iter()
        .find(|entry| {
            entry.dst == dst
                && ifindex
                    .map(|ifindex| entry.ifindex == ifindex)
                    .unwrap_or_else(|| visible_ifindexes.contains(&entry.ifindex))
        })
        .cloned()
}

pub(crate) fn learn_ipv4_neighbor(
    local: Option<[u8; 4]>,
    dst: [u8; 4],
) -> Option<(NetDeviceSnapshot, [u8; 6])> {
    let ns_id = current_net_ns_id();
    learn_ipv4_neighbor_in_namespace(ns_id, local, dst)
}

pub(crate) fn learn_ipv4_neighbor_in_namespace(
    ns_id: usize,
    local: Option<[u8; 4]>,
    dst: [u8; 4],
) -> Option<(NetDeviceSnapshot, [u8; 6])> {
    learn_ipv4_neighbor_in_namespace_inner(ns_id, local, dst, None, true)
}

pub(crate) fn learn_ipv4_neighbor_on_device_in_namespace_with_routing(
    ns_id: usize,
    ifindex: i32,
    local: Option<[u8; 4]>,
    dst: [u8; 4],
    allow_routed: bool,
) -> Option<(NetDeviceSnapshot, [u8; 6])> {
    if ifindex <= 0 {
        return learn_ipv4_neighbor_in_namespace_inner(ns_id, local, dst, None, allow_routed);
    }
    learn_ipv4_neighbor_in_namespace_inner(ns_id, local, dst, Some(ifindex), allow_routed)
}

/// Linux `MSG_CONFIRM` 用来告诉邻居子系统“这条邻居项仍然可达”。
///
/// 当前邻居模型没有独立的 STALE/DELAY/PROBE 状态机；成功解析邻居时会刷新/创建
/// `NeighEntry`，因此确认路径复用同一套解析逻辑，但调用方不应把确认失败当成发送失败。
pub(crate) fn confirm_ipv4_neighbor_on_device_in_namespace_with_routing(
    ns_id: usize,
    ifindex: i32,
    local: Option<[u8; 4]>,
    dst: [u8; 4],
    allow_routed: bool,
) -> Option<(NetDeviceSnapshot, [u8; 6])> {
    learn_ipv4_neighbor_on_device_in_namespace_with_routing(
        ns_id,
        ifindex,
        local,
        dst,
        allow_routed,
    )
}

fn learn_ipv4_neighbor_in_namespace_inner(
    ns_id: usize,
    local: Option<[u8; 4]>,
    dst: [u8; 4],
    ifindex: Option<i32>,
    allow_routed: bool,
) -> Option<(NetDeviceSnapshot, [u8; 6])> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);

    let mut selected: Option<usize> = None;
    if let Some(ifindex) = ifindex {
        let idx = state.devices.iter().position(|dev| {
            dev.net_ns_id == ns_id && dev.ifindex == ifindex && (dev.flags & IFF_UP) != 0
        })?;
        if let Some(local) = local
            && !state.devices[idx]
                .addrs
                .iter()
                .any(|entry| entry.addr == local)
        {
            return None;
        }
        selected = Some(idx);
    } else if let Some(local) = local {
        selected = state.devices.iter().position(|dev| {
            dev.net_ns_id == ns_id && dev.addrs.iter().any(|entry| entry.addr == local)
        });
    }

    if selected.is_none() {
        selected = state
            .devices
            .iter()
            .enumerate()
            .filter(|(_, dev)| dev.net_ns_id == ns_id && (dev.flags & IFF_UP) != 0)
            .filter_map(|(idx, dev)| {
                dev.addrs
                    .iter()
                    .filter(|entry| ipv4_same_prefix(entry.addr, dst, entry.prefix_len))
                    .map(|entry| (idx, entry.prefix_len))
                    .max_by_key(|(_, prefix_len)| *prefix_len)
            })
            .max_by_key(|(_, prefix_len)| *prefix_len)
            .map(|(idx, _)| idx);
    }

    if selected.is_none() && allow_routed {
        selected = state
            .routes
            .iter()
            .filter(|route| ipv4_same_prefix(route.dst, dst, route.prefix_len))
            .max_by_key(|route| route.prefix_len)
            .and_then(|route| {
                state.devices.iter().position(|dev| {
                    dev.net_ns_id == ns_id
                        && dev.ifindex == route.ifindex
                        && (dev.flags & IFF_UP) != 0
                })
            });
    }

    if selected.is_none() && allow_routed {
        selected = state.devices.iter().position(|dev| {
            dev.net_ns_id == ns_id
                && dev.kind != NetDeviceKind::Loopback
                && (dev.flags & IFF_UP) != 0
        });
    }

    let selected = selected?;
    let dev = state.devices[selected].snapshot();
    if ipv4_is_multicast_addr(dst) {
        return Some((dev, ipv4_multicast_mac(dst)));
    }
    if device_has_ipv4_broadcast_addr(&state.devices[selected], dst) {
        return Some((dev, [0xff; 6]));
    }
    let selected_dev = &state.devices[selected];
    let lladdr = if let Some(hwaddr) = state
        .devices
        .iter()
        .find(|other| {
            other.net_ns_id == ns_id
                && other
                    .addrs
                    .iter()
                    .any(|entry| entry.addr == dst || entry.peer_addr == dst)
        })
        .map(|other| other.hwaddr)
    {
        hwaddr
    } else if selected_dev.kind == NetDeviceKind::Veth {
        let peer_ifindex = selected_dev.link_ifindex?;
        state
            .devices
            .iter()
            .find(|peer| {
                peer.ifindex == peer_ifindex
                    && peer.kind == NetDeviceKind::Veth
                    && peer.link_ifindex == Some(selected_dev.ifindex)
                    && (peer.flags & IFF_UP) != 0
                    && peer
                        .addrs
                        .iter()
                        .any(|entry| entry.addr == dst || entry.peer_addr == dst)
            })
            .map(|peer| peer.hwaddr)?
    } else if selected_dev.kind == NetDeviceKind::Macvlan {
        let lower_ifindex = selected_dev.link_ifindex?;
        let lower = state.devices.iter().find(|lower| {
            lower.net_ns_id == ns_id
                && lower.ifindex == lower_ifindex
                && lower.kind == NetDeviceKind::Veth
                && (lower.flags & IFF_UP) != 0
        })?;
        let peer_ifindex = lower.link_ifindex?;
        let peer_lower = state.devices.iter().find(|peer| {
            peer.ifindex == peer_ifindex
                && peer.kind == NetDeviceKind::Veth
                && peer.link_ifindex == Some(lower.ifindex)
                && (peer.flags & IFF_UP) != 0
        })?;
        if peer_lower
            .addrs
            .iter()
            .any(|entry| entry.addr == dst || entry.peer_addr == dst)
        {
            peer_lower.hwaddr
        } else {
            state
                .devices
                .iter()
                .find(|upper| {
                    upper.net_ns_id == peer_lower.net_ns_id
                        && upper.kind == NetDeviceKind::Macvlan
                        && upper.link_ifindex == Some(peer_lower.ifindex)
                        && (upper.flags & IFF_UP) != 0
                        && upper
                            .addrs
                            .iter()
                            .any(|entry| entry.addr == dst || entry.peer_addr == dst)
                })
                .map(|upper| upper.hwaddr)?
        }
    } else if let Some(entry) = state
        .neighs
        .iter()
        .find(|entry| entry.ifindex == dev.ifindex && entry.dst == dst)
    {
        entry.lladdr
    } else {
        return None;
    };

    if let Some(entry) = state
        .neighs
        .iter_mut()
        .find(|entry| entry.ifindex == dev.ifindex && entry.dst == dst)
    {
        entry.lladdr = lladdr;
    } else {
        state.neighs.push(NeighEntry {
            dst,
            lladdr,
            ifindex: dev.ifindex,
        });
    }

    Some((dev, lladdr))
}

pub(crate) fn del_neigh(ifindex: i32, dst: [u8; 4]) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    if state.device_by_index_in(ns_id, ifindex).is_none() {
        return Err(errno(SyscallError::ENODEV));
    }
    let visible_ifindexes: Vec<i32> = state
        .devices
        .iter()
        .filter(|dev| dev.net_ns_id == ns_id)
        .map(|dev| dev.ifindex)
        .collect();
    let removed_lladdrs: Vec<[u8; 6]> = state
        .neighs
        .iter()
        .filter(|entry| entry.ifindex == ifindex && entry.dst == dst)
        .map(|entry| entry.lladdr)
        .collect();
    if removed_lladdrs.is_empty() {
        return Err(errno(SyscallError::ENOENT));
    }
    let old_len = state.neighs.len();
    state.neighs.retain(|entry| {
        if entry.ifindex == ifindex && entry.dst == dst {
            return false;
        }
        if entry.dst == dst
            && visible_ifindexes.contains(&entry.ifindex)
            && removed_lladdrs.contains(&entry.lladdr)
        {
            return false;
        }
        true
    });
    if state.neighs.len() == old_len {
        return Err(errno(SyscallError::ENOENT));
    }
    Ok(())
}

fn add_mac_ref(list: &mut Vec<MacAddrRef>, mac: [u8; 6]) -> Result<(), isize> {
    if let Some(entry) = list.iter_mut().find(|entry| entry.addr == mac) {
        entry.count = entry
            .count
            .checked_add(1)
            .ok_or_else(|| errno(SyscallError::EOVERFLOW))?;
    } else {
        list.push(MacAddrRef {
            addr: mac,
            count: 1,
        });
    }
    Ok(())
}

fn del_mac_ref(list: &mut Vec<MacAddrRef>, mac: [u8; 6]) -> Result<(), isize> {
    let Some(pos) = list.iter().position(|entry| entry.addr == mac) else {
        return Err(errno(SyscallError::ENOENT));
    };
    if list[pos].count > 1 {
        list[pos].count -= 1;
    } else {
        list.remove(pos);
    }
    Ok(())
}

pub(crate) fn add_maddr(ifindex: i32, mac: [u8; 6]) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    add_maddr_in_namespace(ns_id, ifindex, mac)
}

pub(crate) fn add_maddr_in_namespace(
    ns_id: usize,
    ifindex: i32,
    mac: [u8; 6],
) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    add_mac_ref(&mut dev.maddrs, mac)
}

pub(crate) fn del_maddr(ifindex: i32, mac: [u8; 6]) -> Result<(), isize> {
    let ns_id = current_net_ns_id();
    del_maddr_in_namespace(ns_id, ifindex, mac)
}

pub(crate) fn del_maddr_in_namespace(
    ns_id: usize,
    ifindex: i32,
    mac: [u8; 6],
) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    del_mac_ref(&mut dev.maddrs, mac)
}

pub(crate) fn add_uaddr_in_namespace(
    ns_id: usize,
    ifindex: i32,
    mac: [u8; 6],
) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    add_mac_ref(&mut dev.uaddrs, mac)
}

pub(crate) fn del_uaddr_in_namespace(
    ns_id: usize,
    ifindex: i32,
    mac: [u8; 6],
) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    del_mac_ref(&mut dev.uaddrs, mac)
}

pub(crate) fn set_promiscuity_in_namespace(
    ns_id: usize,
    ifindex: i32,
    enable: bool,
) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    if enable {
        dev.promiscuity = dev
            .promiscuity
            .checked_add(1)
            .ok_or_else(|| errno(SyscallError::EOVERFLOW))?;
    } else if dev.promiscuity == 0 {
        return Err(errno(SyscallError::EINVAL));
    } else {
        dev.promiscuity -= 1;
    }
    if dev.promiscuity > 0 {
        dev.flags |= IFF_PROMISC;
    } else {
        dev.flags &= !IFF_PROMISC;
    }
    Ok(())
}

pub(crate) fn set_allmulti_in_namespace(
    ns_id: usize,
    ifindex: i32,
    enable: bool,
) -> Result<(), isize> {
    let mut state = NET_STATE.lock();
    state.ensure_namespace(ns_id);
    let Some(dev) = state.device_by_index_mut_in(ns_id, ifindex) else {
        return Err(errno(SyscallError::ENODEV));
    };
    if enable {
        dev.allmulti = dev
            .allmulti
            .checked_add(1)
            .ok_or_else(|| errno(SyscallError::EOVERFLOW))?;
    } else if dev.allmulti == 0 {
        return Err(errno(SyscallError::EINVAL));
    } else {
        dev.allmulti -= 1;
    }
    if dev.allmulti > 0 {
        dev.flags |= IFF_ALLMULTI;
    } else {
        dev.flags &= !IFF_ALLMULTI;
    }
    Ok(())
}

fn ipv4_to_hex_le(addr: [u8; 4]) -> u32 {
    u32::from_le_bytes(addr)
}

fn prefix_mask(prefix_len: u8) -> [u8; 4] {
    if prefix_len == 0 {
        return [0; 4];
    }
    let mask = (!0u32) << (32 - prefix_len as u32);
    mask.to_be_bytes()
}

pub(crate) fn proc_net_dev_content() -> String {
    let mut out = String::from(
        "Inter-|   Receive                                                |  Transmit\n\
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for dev in devices_snapshot() {
        let stats = dev.stats;
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{:>6}: {:>7} {:>7} {:>4} {:>4} {:>4} {:>5} {:>10} {:>9} {:>8} {:>7} {:>4} {:>4} {:>4} {:>5} {:>7} {:>10}\n",
                dev.name,
                stats.rx_bytes,
                stats.rx_packets,
                0,
                0,
                0,
                0,
                0,
                0,
                stats.tx_bytes,
                stats.tx_packets,
                0,
                0,
                0,
                0,
                0,
                0
            ),
        );
    }
    out
}

pub(crate) fn proc_net_route_content() -> String {
    let mut out = String::from(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
    );
    for route in routes_snapshot() {
        let iface = name_by_ifindex(route.ifindex).unwrap_or_else(|| String::from("*"));
        let flags = if route.gateway.is_some() { 0x3 } else { 0x1 };
        let mask = prefix_mask(route.prefix_len);
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{}\t{:08X}\t{:08X}\t{:04X}\t0\t0\t0\t{:08X}\t0\t0\t0\n",
                iface,
                ipv4_to_hex_le(route.dst),
                ipv4_to_hex_le(route.gateway.unwrap_or([0; 4])),
                flags,
                ipv4_to_hex_le(mask),
            ),
        );
    }
    out
}

pub(crate) fn proc_net_arp_content() -> String {
    let mut out = String::from(
        "IP address       HW type     Flags       HW address            Mask     Device\n",
    );
    for neigh in neighs_snapshot() {
        let iface = name_by_ifindex(neigh.ifindex).unwrap_or_else(|| String::from("*"));
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{}.{}.{}.{}     0x1         0x2         {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}     *        {}\n",
                neigh.dst[0],
                neigh.dst[1],
                neigh.dst[2],
                neigh.dst[3],
                neigh.lladdr[0],
                neigh.lladdr[1],
                neigh.lladdr[2],
                neigh.lladdr[3],
                neigh.lladdr[4],
                neigh.lladdr[5],
                iface,
            ),
        );
    }
    out
}

pub(crate) fn proc_net_igmp_content() -> String {
    let mut out = String::from("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n");
    for dev in devices_snapshot() {
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{}\t{}    :     {}\t      V3\n",
                dev.ifindex,
                dev.name,
                dev.maddrs.len()
            ),
        );
    }
    out
}

pub(crate) fn proc_net_dev_mcast_content() -> String {
    let mut out = String::new();
    for dev in devices_snapshot() {
        for mac in &dev.maddrs {
            let _ = core::fmt::Write::write_fmt(
                &mut out,
                format_args!(
                    "{:<4} {:<15} {:<5} {:<5} {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\n",
                    dev.ifindex, dev.name, 1, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                ),
            );
        }
    }
    out
}

pub(crate) fn proc_net_if_inet6_content() -> String {
    let mut out = String::new();
    for dev in devices_snapshot() {
        for entry in &dev.addrs6 {
            for byte in entry.addr {
                let _ = core::fmt::Write::write_fmt(&mut out, format_args!("{:02x}", byte));
            }
            let _ = core::fmt::Write::write_fmt(
                &mut out,
                format_args!(
                    " {:02x} {:02x} {:02x} {:08x} {}\n",
                    dev.ifindex.max(0) as u32,
                    entry.prefix_len,
                    entry.scope,
                    0u32,
                    dev.name
                ),
            );
        }
    }
    out
}

struct RawProcEntry {
    local_addr: [u8; 4],
    remote_addr: [u8; 4],
    protocol: u16,
    tx_queue: usize,
    rx_queue: usize,
    uid: u32,
    inode: u64,
}

struct UnixProcEntry {
    inode: u64,
    sock_type: usize,
    state: u8,
    path: String,
}

struct NetlinkProcEntry {
    inode: u64,
    pid: u32,
    groups: u32,
    rmem: u32,
    wmem: u32,
}

struct ProcSocketSnapshot {
    socket_count: usize,
    tcp: Vec<crate::fs::ProcNetSocketSnapshot>,
    udp: Vec<crate::fs::ProcNetSocketSnapshot>,
    raw: Vec<RawProcEntry>,
    unix: Vec<UnixProcEntry>,
    netlink: Vec<NetlinkProcEntry>,
}

impl ProcSocketSnapshot {
    fn new() -> Self {
        Self {
            socket_count: 0,
            tcp: Vec::new(),
            udp: Vec::new(),
            raw: Vec::new(),
            unix: Vec::new(),
            netlink: Vec::new(),
        }
    }
}

fn ipv4_from_smoltcp(ip: smoltcp::wire::Ipv4Address) -> [u8; 4] {
    let b = ip.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

fn collect_proc_sockets() -> ProcSocketSnapshot {
    let current_ns_id = current_net_ns_id();
    let processes = {
        let map = PID2PCB.lock();
        map.values().cloned().collect::<Vec<_>>()
    };
    let mut snapshot = ProcSocketSnapshot::new();
    let mut seen_tables = BTreeSet::new();
    let mut seen_files = BTreeSet::new();
    for process in processes {
        let Some(inner) = process.try_borrow_mut() else {
            continue;
        };
        let files = Arc::clone(&inner.files);
        drop(inner);
        if !seen_tables.insert(Arc::as_ptr(&files) as usize) {
            continue;
        }
        let files = files.lock().iter_files_snapshot();
        for (_fd, file) in files {
            let key = Arc::as_ptr(&file) as *const () as usize;
            if !seen_files.insert(key) {
                continue;
            }
            if let Some(sock) = file.as_any().downcast_ref::<NetSocketFile>() {
                if sock.net_ns_id() != current_ns_id {
                    continue;
                }
                snapshot.socket_count += 1;
                if let Some(entry) = sock.proc_net_snapshot() {
                    match entry.kind {
                        NetSocketKind::TcpStream | NetSocketKind::TcpListener => {
                            snapshot.tcp.push(entry)
                        }
                        NetSocketKind::Udp => snapshot.udp.push(entry),
                    }
                }
                continue;
            }
            if let Some(raw) = file.as_any().downcast_ref::<super::RawSocketFile>() {
                if raw.net_ns_id() != current_ns_id {
                    continue;
                }
                snapshot.socket_count += 1;
                let (tx_queue, rx_queue) = raw.proc_queue_lengths();
                snapshot.raw.push(RawProcEntry {
                    local_addr: ipv4_from_smoltcp(raw.local_addr_v4()),
                    remote_addr: raw
                        .remote_addr_v4()
                        .map(ipv4_from_smoltcp)
                        .unwrap_or([0; 4]),
                    protocol: raw.protocol() as u16,
                    tx_queue,
                    rx_queue,
                    uid: raw.proc_uid(),
                    inode: raw.proc_inode(),
                });
                continue;
            }
            if let Some(unix) = file.as_any().downcast_ref::<super::UnixSocketFile>() {
                if unix.net_ns_id() != current_ns_id {
                    continue;
                }
                snapshot.socket_count += 1;
                let (inode, sock_type, state, path) = unix.proc_net_snapshot();
                snapshot.unix.push(UnixProcEntry {
                    inode,
                    sock_type,
                    state,
                    path,
                });
                continue;
            }
            if let Some(netlink) = file.as_any().downcast_ref::<super::NetlinkSocketFile>() {
                if netlink.net_ns_id() != current_ns_id {
                    continue;
                }
                snapshot.socket_count += 1;
                let (inode, pid, groups, rmem, wmem) = netlink.proc_net_snapshot();
                snapshot.netlink.push(NetlinkProcEntry {
                    inode,
                    pid,
                    groups,
                    rmem,
                    wmem,
                });
                continue;
            }
            if file
                .as_any()
                .downcast_ref::<super::PacketSocketFile>()
                .is_some_and(|packet| packet.net_ns_id() == current_ns_id)
            {
                snapshot.socket_count += 1;
            }
        }
    }
    snapshot
}

fn proc_inet_table(rows: &[crate::fs::ProcNetSocketSnapshot]) -> String {
    let mut out = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    for (idx, row) in rows.iter().enumerate() {
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{:4}: {:08X}:{:04X} {:08X}:{:04X} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {:>5}\n",
                idx,
                ipv4_to_hex_le(row.local_addr),
                row.local_port,
                ipv4_to_hex_le(row.remote_addr),
                row.remote_port,
                row.state,
                row.tx_queue,
                row.rx_queue,
                row.uid,
                0,
                row.inode,
            ),
        );
    }
    out
}

pub(crate) fn proc_net_tcp_content() -> String {
    proc_inet_table(&collect_proc_sockets().tcp)
}

pub(crate) fn proc_net_tcp_snapshots() -> Vec<crate::fs::ProcNetSocketSnapshot> {
    collect_proc_sockets().tcp
}

pub(crate) fn proc_net_udp_content() -> String {
    proc_inet_table(&collect_proc_sockets().udp)
}

pub(crate) fn proc_net_raw_content() -> String {
    let snapshot = collect_proc_sockets();
    let mut out = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    for (idx, row) in snapshot.raw.iter().enumerate() {
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{:4}: {:08X}:{:04X} {:08X}:0000 07 {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {:>5}\n",
                idx,
                ipv4_to_hex_le(row.local_addr),
                row.protocol,
                ipv4_to_hex_le(row.remote_addr),
                row.tx_queue,
                row.rx_queue,
                row.uid,
                0,
                row.inode,
            ),
        );
    }
    out
}

pub(crate) fn proc_net_unix_content() -> String {
    let snapshot = collect_proc_sockets();
    let mut out = String::from("Num       RefCount Protocol Flags    Type St Inode Path\n");
    for row in &snapshot.unix {
        let flags = if row.state == 0x0a { 0x0001_0000 } else { 0 };
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{:08x}: {:08x} {:08x} {:08x} {:04x} {:02x} {:5} {}\n",
                row.inode, 2, 0, flags, row.sock_type, row.state, row.inode, row.path,
            ),
        );
    }
    out
}

pub(crate) fn proc_net_netlink_content() -> String {
    let snapshot = collect_proc_sockets();
    let mut out = String::from(
        "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n",
    );
    for row in &snapshot.netlink {
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{:016x} {:<3} {:<10} {:08x} {:<8} {:<8} {:<5} {:<8} {:<8} {}\n",
                row.inode, 0, row.pid, row.groups, row.rmem, row.wmem, 0, 2, 0, row.inode,
            ),
        );
    }
    out
}

pub(crate) fn proc_net_snmp_content() -> String {
    let stats = protocol_stats_snapshot();
    format!(
        "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits\n\
         Ip: 2 64 {} 0 0 0 0 0 {} {} 0 0 0 0 0 0 0 0 0 {}\n\
         Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
         Icmp: {} 0 0 0 0 0 0 0 {} {} 0 0 0 0 {} 0 0 0 0 0 0 0 0 {} {} 0 0 0 0\n\
         Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
         Tcp: 1 200 120000 -1 0 0 0 0 0 {} {} 0 0 0 0\n\
         Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
         Udp: {} 0 0 {} 0 0 0 0 0\n\
         UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
         UdpLite: 0 0 0 0 0 0 0 0 0\n",
        stats.ip_in_receives,
        stats.ip_in_delivers,
        stats.ip_out_requests,
        stats.ip_out_requests,
        stats.icmp_in_msgs,
        stats.icmp_in_echos,
        stats.icmp_in_echo_reps,
        stats.icmp_out_msgs,
        stats.icmp_out_echos,
        stats.icmp_out_echo_reps,
        stats.tcp_in_segs,
        stats.tcp_out_segs,
        stats.udp_in_datagrams,
        stats.udp_out_datagrams,
    )
}

pub(crate) fn proc_net_netstat_content() -> String {
    let stats = protocol_stats_snapshot();
    format!(
        "TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled\n\
         TcpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
         IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors InNoECTPkts InECT1Pkts InECT0Pkts InCEPkts ReasmOverlaps\n\
         IpExt: 0 0 0 0 0 0 {} {} 0 0 0 0 0 0 0 0 0 0\n",
        stats.ip_in_octets, stats.ip_out_octets,
    )
}

pub(crate) fn proc_net_sockstat_content() -> String {
    let snapshot = collect_proc_sockets();
    format!(
        "sockets: used {}\nTCP: inuse {} orphan 0 tw 0 alloc {} mem 0\nUDP: inuse {} mem 0\nRAW: inuse {}\nFRAG: inuse 0 memory 0\n",
        snapshot.socket_count,
        snapshot.tcp.len(),
        snapshot.tcp.len(),
        snapshot.udp.len(),
        snapshot.raw.len(),
    )
}

pub(crate) fn sys_class_net_entries() -> Vec<(String, u8)> {
    devices_snapshot()
        .into_iter()
        .map(|dev| (dev.name, 10))
        .collect()
}

pub(crate) fn sys_class_net_device_entries(name: &str) -> Vec<(&'static str, u8)> {
    let mut entries = alloc::vec![
        ("address", 8),
        ("carrier", 8),
        ("flags", 8),
        ("ifindex", 8),
        ("mtu", 8),
        ("operstate", 8),
        ("type", 8),
        ("uevent", 8),
    ];
    if device_snapshot_by_name(name)
        .is_some_and(|dev| matches!(dev.kind, NetDeviceKind::Tun | NetDeviceKind::Tap))
    {
        entries.push(("owner", 8));
        entries.push(("group", 8));
        entries.push(("tun_flags", 8));
    }
    entries
}

pub(crate) fn sys_class_net_file_content(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/sys/class/net/")?;
    let mut parts = rest.split('/');
    let name = parts.next()?;
    let file = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let dev = device_snapshot_by_name(name)?;
    let text = match file {
        "address" => format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            dev.hwaddr[0],
            dev.hwaddr[1],
            dev.hwaddr[2],
            dev.hwaddr[3],
            dev.hwaddr[4],
            dev.hwaddr[5]
        ),
        "carrier" => {
            if (dev.flags & IFF_RUNNING) != 0 {
                String::from("1\n")
            } else {
                String::from("0\n")
            }
        }
        "flags" => format!("0x{:x}\n", dev.flags),
        "ifindex" => format!("{}\n", dev.ifindex),
        "mtu" => format!("{}\n", dev.mtu),
        "operstate" => {
            if (dev.flags & IFF_UP) != 0 {
                String::from("up\n")
            } else {
                String::from("down\n")
            }
        }
        "type" => format!("{}\n", dev.link_type),
        "uevent" => format!("INTERFACE={}\nIFINDEX={}\n", dev.name, dev.ifindex),
        "owner" if matches!(dev.kind, NetDeviceKind::Tun | NetDeviceKind::Tap) => {
            let owner = crate::fs::tuntap_link_sysfs_info(&dev.name)
                .and_then(|(owner, _, _)| owner)
                .map(|uid| uid.to_string())
                .unwrap_or_else(|| String::from("-1"));
            format!("{}\n", owner)
        }
        "group" if matches!(dev.kind, NetDeviceKind::Tun | NetDeviceKind::Tap) => {
            let group = crate::fs::tuntap_link_sysfs_info(&dev.name)
                .and_then(|(_, group, _)| group)
                .map(|gid| gid.to_string())
                .unwrap_or_else(|| String::from("-1"));
            format!("{}\n", group)
        }
        "tun_flags" if matches!(dev.kind, NetDeviceKind::Tun | NetDeviceKind::Tap) => {
            let fallback = match dev.kind {
                NetDeviceKind::Tun => TUNTAP_SYSFS_IFF_TUN,
                NetDeviceKind::Tap => TUNTAP_SYSFS_IFF_TAP,
                _ => 0,
            };
            let flags = crate::fs::tuntap_link_sysfs_info(&dev.name)
                .map(|(_, _, flags)| flags)
                .unwrap_or(fallback);
            format!("0x{:x}\n", flags)
        }
        _ => return None,
    };
    Some(text)
}
