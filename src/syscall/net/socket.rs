//! 核心套接字系统调用实现。
//!
//! 本模块提供 `socket`、`bind`、`listen`、`accept`/`accept4`、`connect`
//! 六个系统调用的内核侧实现，支持 AF_INET（TCP/UDP）、AF_UNIX 及
//! AF_NETLINK、AF_PACKET 等协议族。

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::{any::Any, mem::size_of};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::bpf::BpfProgFile;
use crate::fs::{File, NetSocketFile, POLLERR, POLLIN, POLLOUT};
use crate::mm::{UserBuffer, try_copy_to_user, try_read_user_value, try_write_user_value};
use crate::syscall::error::{SyscallError, err};
use crate::task::processor::{current_files, current_files_and_nofile_limit, current_process};
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};

use super::cbpf::ClassicBpfProgram;
use super::*;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_ALL: u16 = 0x0003;
const ETH_HDR_LEN: usize = 14;
const VLAN_HLEN: usize = 4;
const PACKET_HOST: u8 = 0;
const PACKET_OUTGOING: u8 = 4;
const PACKET_RECV_QUEUE_LIMIT: usize = 256;
const RAW_RECV_QUEUE_LIMIT: usize = 256;
const RAW_ERROR_QUEUE_LIMIT: usize = 16;
const DEFAULT_VSOCK_BUFFER_SIZE: u64 = 256 * 1024;
const MIN_VSOCK_BUFFER_SIZE: u64 = 128;
const MAX_VSOCK_BUFFER_SIZE: u64 = 256 * 1024;
const TPACKET_HDR_SIZE: u32 = 32;
const TPACKET2_HDR_SIZE: u32 = 32;
const TPACKET3_HDR_SIZE: u32 = 48;
const TPACKET2_HDRLEN_ALIGNED: u32 = 64;
const TPACKET3_BLOCK_DESC_LEN: u32 = 48;
const TPACKET3_HDRLEN: u32 = 68;
const TP_STATUS_KERNEL: u32 = 0;
const TP_STATUS_USER: u32 = 1;
const DEFAULT_SOCKBUF: u32 = 212_992;
const UDP_RX_META_LIMIT: usize = 512;

fn ipv4_pmtu_reports_oversize(pmtudisc: i32) -> bool {
    matches!(pmtudisc, IP_PMTUDISC_DO | IP_PMTUDISC_PROBE)
}

lazy_static! {
    static ref PACKET_SOCKETS: Mutex<Vec<Weak<PacketSocketFile>>> = Mutex::new(Vec::new());
    static ref RAW_SOCKETS: Mutex<Vec<Weak<RawSocketFile>>> = Mutex::new(Vec::new());
    static ref PACKET_FANOUT_COUNTERS: Mutex<Vec<PacketFanoutCounter>> = Mutex::new(Vec::new());
    static ref PACKET_FANOUT_NEXT_ID: Mutex<u16> = Mutex::new(0);
    static ref PING_IDENT_ROVER: Mutex<u16> = Mutex::new(0);
    static ref UDP_RX_METADATA: Mutex<VecDeque<UdpIpv4RxMeta>> = Mutex::new(VecDeque::new());
}

#[derive(Clone, Copy)]
pub(crate) struct UdpIpv4RxInfo {
    pub(crate) ifindex: i32,
    pub(crate) dst: Ipv4Address,
    pub(crate) ttl: u8,
    pub(crate) tos: u8,
}

#[derive(Clone, Copy)]
struct UdpIpv4RxMeta {
    ifindex: i32,
    src: Ipv4Address,
    dst: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    ttl: u8,
    tos: u8,
}

impl UdpIpv4RxMeta {
    fn matches(
        self,
        local_addr: Ipv4Address,
        local_port: u16,
        remote_addr: Ipv4Address,
        remote_port: u16,
        payload_len: usize,
    ) -> bool {
        self.dst_port == local_port
            && self.src_port == remote_port
            && self.src == remote_addr
            && (local_addr == Ipv4Address::UNSPECIFIED || self.dst == local_addr)
            && self.payload_len == payload_len
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_flags: u8,
    svm_zero: [u8; 3],
}

fn read_sockaddr_vm(addr: usize, addrlen: usize) -> Result<SockAddrVm, isize> {
    if addr == 0 {
        return Err(err(SyscallError::EFAULT));
    }
    if addrlen < size_of::<SockAddrVm>() {
        return Err(err(SyscallError::EINVAL));
    }
    let token = crate::trap::get_current_token();
    let Some(sa) = try_read_user_value::<SockAddrVm>(token, addr as *const SockAddrVm) else {
        return Err(err(SyscallError::EFAULT));
    };
    Ok(sa)
}

/// Minimal AF_VSOCK control-plane socket.
///
/// The kernel exposes the Linux ABI surface needed by LTP's vsock transport
/// race test: socket creation, vSockets sockopts and closed-port connect
/// errors.  It intentionally does not claim a working data path.
pub(crate) struct VsockSocketFile {
    socket_type: usize,
    protocol: usize,
    state: Mutex<VsockSocketState>,
}

struct VsockSocketState {
    buffer_size: u64,
    buffer_min_size: u64,
    buffer_max_size: u64,
    connect_timeout_ms: Option<usize>,
}

impl VsockSocketFile {
    fn new(socket_type: usize, protocol: usize) -> FileArc {
        Arc::new(Self {
            socket_type,
            protocol,
            state: Mutex::new(VsockSocketState {
                buffer_size: DEFAULT_VSOCK_BUFFER_SIZE,
                buffer_min_size: MIN_VSOCK_BUFFER_SIZE,
                buffer_max_size: MAX_VSOCK_BUFFER_SIZE,
                connect_timeout_ms: None,
            }),
        })
    }

    pub(crate) fn socket_type(&self) -> usize {
        self.socket_type
    }

    pub(crate) fn protocol(&self) -> usize {
        self.protocol
    }

    pub(crate) fn set_buffer_size(&self, value: u64) {
        let mut state = self.state.lock();
        state.buffer_size = value.clamp(state.buffer_min_size, state.buffer_max_size);
    }

    pub(crate) fn set_buffer_min_size(&self, value: u64) {
        let mut state = self.state.lock();
        state.buffer_min_size = value.min(state.buffer_max_size);
        state.buffer_size = state
            .buffer_size
            .clamp(state.buffer_min_size, state.buffer_max_size);
    }

    pub(crate) fn set_buffer_max_size(&self, value: u64) {
        let mut state = self.state.lock();
        state.buffer_max_size = value.max(state.buffer_min_size);
        state.buffer_size = state
            .buffer_size
            .clamp(state.buffer_min_size, state.buffer_max_size);
    }

    pub(crate) fn buffer_size(&self) -> u64 {
        self.state.lock().buffer_size
    }

    pub(crate) fn buffer_min_size(&self) -> u64 {
        self.state.lock().buffer_min_size
    }

    pub(crate) fn buffer_max_size(&self) -> u64 {
        self.state.lock().buffer_max_size
    }

    pub(crate) fn set_connect_timeout_ms(&self, timeout_ms: Option<usize>) {
        self.state.lock().connect_timeout_ms = timeout_ms;
    }

    pub(crate) fn connect_timeout_ms(&self) -> Option<usize> {
        self.state.lock().connect_timeout_ms
    }

    fn connect_vm(&self, addr: usize, addrlen: usize) -> isize {
        let sa = match read_sockaddr_vm(addr, addrlen) {
            Ok(sa) => sa,
            Err(e) => return e,
        };
        if sa.svm_family == AF_UNSPEC {
            return 0;
        }
        if sa.svm_family != AF_VSOCK {
            return err(SyscallError::EAFNOSUPPORT);
        }
        if sa.svm_cid == VMADDR_CID_ANY || sa.svm_port == VMADDR_PORT_ANY {
            return err(SyscallError::EINVAL);
        }
        if self.socket_type != SOCK_STREAM {
            return err(SyscallError::EOPNOTSUPP);
        }
        // Loopback transport exists, but no in-kernel VSOCK listener/data path
        // is modeled yet. Linux reports a refused connection for a closed port.
        err(SyscallError::ECONNREFUSED)
    }
}

impl File for VsockSocketFile {
    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// 轻量 AF_PACKET socket。
///
/// LTP 的网络 helper 主要用它承载 ifreq ioctl，以及按 Linux ABI 接受
/// `bind(sockaddr_ll)` / `sendto(sockaddr_ll)`。这里保留一个小接收队列，
/// 用于观察内核网络路径里实际出现的二层帧。
pub(crate) struct PacketSocketFile {
    socket_type: usize,
    protocol: u16,
    net_ns_id: usize,
    state: Mutex<PacketSocketState>,
}

#[derive(Clone)]
pub(super) struct PacketFrame {
    pub(super) data: Vec<u8>,
    pub(super) addr: SockAddrLl,
    pub(super) metadata: PacketMetadata,
}

struct PacketSocketState {
    bound_ifindex: i32,
    bound_protocol: u16,
    reuseaddr: bool,
    dontroute: bool,
    broadcast: bool,
    keepalive: bool,
    sndbuf: u32,
    rcvbuf: u32,
    oobinline: bool,
    priority: u32,
    mark: u32,
    rcvmark: bool,
    rcvpriority: bool,
    linger_on: bool,
    linger_sec: i32,
    rcvlowat: i32,
    fanout: Option<PacketFanout>,
    packet_version: i32,
    packet_reserve: u32,
    packet_vnet_hdr: bool,
    packet_copy_thresh: i32,
    packet_auxdata: bool,
    packet_origdev: bool,
    packet_qdisc_bypass: bool,
    ignore_outgoing: bool,
    filter_locked: bool,
    filter: Option<ClassicBpfProgram>,
    ebpf_filter: Option<Arc<BpfProgFile>>,
    memberships: Vec<PacketMembership>,
    rx_ring: Option<PacketRing>,
    tx_ring: Option<PacketRing>,
    recv_queue: VecDeque<PacketFrame>,
    pending_error: i32,
    timestamp_mode: SocketTimestampMode,
    last_timestamp: Option<SocketTimestamp>,
    rcvtimeo_ms: Option<usize>,
    sndtimeo_ms: Option<usize>,
    rx_packets: u32,
    rx_drops: u32,
}

impl Default for PacketSocketState {
    fn default() -> Self {
        Self {
            bound_ifindex: 0,
            bound_protocol: 0,
            reuseaddr: false,
            dontroute: false,
            broadcast: false,
            keepalive: false,
            sndbuf: DEFAULT_SOCKBUF,
            rcvbuf: DEFAULT_SOCKBUF,
            oobinline: false,
            priority: 0,
            mark: 0,
            rcvmark: false,
            rcvpriority: false,
            linger_on: false,
            linger_sec: 0,
            rcvlowat: 1,
            fanout: None,
            packet_version: TPACKET_V1,
            packet_reserve: 0,
            packet_vnet_hdr: false,
            packet_copy_thresh: 0,
            packet_auxdata: false,
            packet_origdev: false,
            packet_qdisc_bypass: false,
            ignore_outgoing: false,
            filter_locked: false,
            filter: None,
            ebpf_filter: None,
            memberships: Vec::new(),
            rx_ring: None,
            tx_ring: None,
            recv_queue: VecDeque::new(),
            pending_error: 0,
            timestamp_mode: SocketTimestampMode::Off,
            last_timestamp: None,
            rcvtimeo_ms: None,
            sndtimeo_ms: None,
            rx_packets: 0,
            rx_drops: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct PacketMembership {
    ifindex: i32,
    mr_type: u16,
    mr_alen: u16,
    addr: [u8; 8],
    count: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PacketFanoutKey {
    net_ns_id: usize,
    id: u16,
    mode: u8,
    flags: u8,
    ifindex: i32,
    protocol: u16,
}

#[derive(Clone, Copy)]
struct PacketFanout {
    key: PacketFanoutKey,
    max_members: u32,
}

struct PacketFanoutCounter {
    key: PacketFanoutKey,
    next: u32,
}

struct PacketFanoutGroup {
    key: PacketFanoutKey,
    sockets: Vec<Arc<PacketSocketFile>>,
}

struct PacketRing {
    version: i32,
    block_size: u32,
    block_nr: u32,
    frame_size: u32,
    frame_nr: u32,
    mappings: Vec<PacketRingMapping>,
}

#[derive(Clone, Copy)]
struct PacketRingMapping {
    base: usize,
    len: usize,
    token: usize,
    next_frame: u32,
    pending_frame: Option<u32>,
}

impl PacketSocketFile {
    fn new(socket_type: usize, protocol: usize) -> Arc<Self> {
        let net_ns_id = current_process().acquire_net_namespace_for_socket();
        let sock = Arc::new(Self {
            socket_type,
            protocol: protocol as u16,
            net_ns_id,
            state: Mutex::new(PacketSocketState::default()),
        });
        PACKET_SOCKETS.lock().push(Arc::downgrade(&sock));
        sock
    }

    fn device_snapshot_by_index(&self, ifindex: i32) -> Option<netdev::NetDeviceSnapshot> {
        netdev::device_snapshot_by_index_in_namespace(self.net_ns_id, ifindex)
    }

    pub(crate) fn net_ns_id(&self) -> usize {
        self.net_ns_id
    }

    fn bind_ll(&self, sa: &SockAddrLl) -> isize {
        if sa.sll_ifindex < 0
            || (sa.sll_ifindex > 0 && self.device_snapshot_by_index(sa.sll_ifindex).is_none())
        {
            return err(SyscallError::ENODEV);
        }
        let mut state = self.state.lock();
        state.bound_ifindex = sa.sll_ifindex;
        state.bound_protocol = sa.sll_protocol;
        0
    }

    pub(super) fn bind_to_device_name(&self, name: &str) -> isize {
        if name.is_empty() {
            self.state.lock().bound_ifindex = 0;
            return 0;
        }
        let Some(ifindex) = netdev::ifindex_by_name_in_namespace(self.net_ns_id, name) else {
            return err(SyscallError::ENODEV);
        };
        self.state.lock().bound_ifindex = ifindex;
        0
    }

    pub(super) fn bound_device_name(&self) -> Option<alloc::string::String> {
        let ifindex = self.state.lock().bound_ifindex;
        (ifindex > 0)
            .then(|| netdev::name_by_ifindex_in_namespace(self.net_ns_id, ifindex))
            .flatten()
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

    pub(super) fn set_sockbuf(&self, sndbuf: Option<u32>, rcvbuf: Option<u32>) {
        let mut state = self.state.lock();
        if let Some(v) = sndbuf {
            state.sndbuf = v;
        }
        if let Some(v) = rcvbuf {
            state.rcvbuf = v;
        }
    }

    pub(super) fn getsockopt_sndbuf(&self) -> u32 {
        self.state.lock().sndbuf
    }

    pub(super) fn getsockopt_rcvbuf(&self) -> u32 {
        self.state.lock().rcvbuf
    }

    pub(super) fn set_oobinline(&self, enabled: bool) {
        self.state.lock().oobinline = enabled;
    }

    pub(super) fn oobinline(&self) -> bool {
        self.state.lock().oobinline
    }

    pub(super) fn set_priority(&self, priority: u32) {
        self.state.lock().priority = priority;
    }

    pub(super) fn priority(&self) -> u32 {
        self.state.lock().priority
    }

    pub(super) fn set_mark(&self, mark: u32) {
        self.state.lock().mark = mark;
    }

    pub(super) fn mark(&self) -> u32 {
        self.state.lock().mark
    }

    pub(super) fn packet_metadata(&self) -> PacketMetadata {
        let state = self.state.lock();
        PacketMetadata {
            mark: state.mark,
            priority: state.priority,
            orig_ifindex: 0,
        }
    }

    pub(super) fn set_rcvmark(&self, enabled: bool) {
        self.state.lock().rcvmark = enabled;
    }

    pub(super) fn rcvmark(&self) -> bool {
        self.state.lock().rcvmark
    }

    pub(super) fn set_rcvpriority(&self, enabled: bool) {
        self.state.lock().rcvpriority = enabled;
    }

    pub(super) fn rcvpriority(&self) -> bool {
        self.state.lock().rcvpriority
    }

    pub(super) fn set_linger(&self, on: bool, sec: i32) {
        let mut state = self.state.lock();
        state.linger_on = on;
        state.linger_sec = sec;
    }

    pub(super) fn linger(&self) -> (bool, i32) {
        let state = self.state.lock();
        (state.linger_on, state.linger_sec)
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

    pub(super) fn rcvtimeo_deadline_ms(&self) -> Option<usize> {
        self.rcvtimeo_ms()
            .map(|ms| crate::time::get_time_ms().saturating_add(ms))
    }

    pub(super) fn set_sndtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.state.lock().sndtimeo_ms = timeout_ms;
    }

    pub(super) fn sndtimeo_ms(&self) -> Option<usize> {
        self.state.lock().sndtimeo_ms
    }

    pub(super) fn set_fanout(&self, value: u32, max_members: u32) -> isize {
        let type_flags = (value >> 16) & 0xffff;
        let mode = type_flags & 0x00ff;
        let mut flags = type_flags & !0x00ff;
        let max_members = if max_members == 0 { 256 } else { max_members };
        if max_members > (1 << 16) {
            return err(SyscallError::EINVAL);
        }
        if !matches!(
            mode,
            PACKET_FANOUT_HASH
                | PACKET_FANOUT_LB
                | PACKET_FANOUT_CPU
                | PACKET_FANOUT_ROLLOVER
                | PACKET_FANOUT_RND
                | PACKET_FANOUT_QM
                | PACKET_FANOUT_CBPF
                | PACKET_FANOUT_EBPF
        ) || (flags & !PACKET_FANOUT_FLAG_MASK) != 0
            || (mode == PACKET_FANOUT_ROLLOVER && (flags & PACKET_FANOUT_FLAG_ROLLOVER) != 0)
        {
            return err(SyscallError::EINVAL);
        }
        if matches!(
            mode,
            PACKET_FANOUT_QM | PACKET_FANOUT_CBPF | PACKET_FANOUT_EBPF
        ) {
            return err(SyscallError::EOPNOTSUPP);
        }
        if (flags & PACKET_FANOUT_FLAG_DEFRAG) != 0 {
            return err(SyscallError::EOPNOTSUPP);
        }

        let (bound_ifindex, protocol) = {
            let state = self.state.lock();
            if state.fanout.is_some() {
                return err(SyscallError::EALREADY);
            }
            let protocol = if state.bound_protocol != 0 {
                state.bound_protocol
            } else {
                self.protocol
            };
            (state.bound_ifindex, protocol)
        };
        let mut id = (value & 0xffff) as u16;
        if (flags & PACKET_FANOUT_FLAG_UNIQUEID) != 0 {
            if id != 0 {
                return err(SyscallError::EINVAL);
            }
            let Some(new_id) = allocate_packet_fanout_id(self.net_ns_id) else {
                return err(SyscallError::ENOMEM);
            };
            id = new_id;
            flags &= !PACKET_FANOUT_FLAG_UNIQUEID;
        }
        let key = PacketFanoutKey {
            id,
            net_ns_id: self.net_ns_id,
            mode: mode as u8,
            flags: (flags >> 8) as u8,
            ifindex: bound_ifindex,
            protocol,
        };

        let mut group_members = 0u32;
        for sock in packet_socket_snapshot_in(self.net_ns_id) {
            let state = sock.state.lock();
            if let Some(existing) = state.fanout
                && existing.key.id == key.id
            {
                if existing.key != key || existing.max_members != max_members {
                    return err(SyscallError::EINVAL);
                }
                group_members = group_members.saturating_add(1);
            }
        }
        if group_members >= max_members {
            return err(SyscallError::ENOSPC);
        }

        self.state.lock().fanout = Some(PacketFanout { key, max_members });
        0
    }

    pub(super) fn set_packet_version(&self, version: i32) -> isize {
        if !matches!(version, TPACKET_V1 | TPACKET_V2 | TPACKET_V3) {
            return err(SyscallError::EINVAL);
        }
        let mut state = self.state.lock();
        if state.rx_ring.is_some() || state.tx_ring.is_some() {
            return err(SyscallError::EBUSY);
        }
        state.packet_version = version;
        0
    }

    pub(super) fn set_packet_reserve(&self, reserve: i32) -> isize {
        if reserve < 0 {
            return err(SyscallError::EINVAL);
        }
        let mut state = self.state.lock();
        if state.rx_ring.is_some() || state.tx_ring.is_some() {
            return err(SyscallError::EBUSY);
        }
        state.packet_reserve = reserve as u32;
        0
    }

    pub(super) fn packet_reserve(&self) -> u32 {
        self.state.lock().packet_reserve
    }

    pub(super) fn packet_version(&self) -> i32 {
        self.state.lock().packet_version
    }

    pub(super) fn packet_header_len_for_version(version: i32) -> Result<u32, isize> {
        match version {
            TPACKET_V1 => Ok(TPACKET_HDR_SIZE),
            TPACKET_V2 => Ok(TPACKET2_HDR_SIZE),
            TPACKET_V3 => Ok(TPACKET3_HDR_SIZE),
            _ => Err(err(SyscallError::EINVAL)),
        }
    }

    pub(super) fn socket_type(&self) -> usize {
        self.socket_type
    }

    pub(super) fn protocol(&self) -> u32 {
        self.protocol as u32
    }

    pub(super) fn set_packet_vnet_hdr(&self, enabled: bool) -> isize {
        let mut state = self.state.lock();
        if state.rx_ring.is_some() || state.tx_ring.is_some() {
            return err(SyscallError::EBUSY);
        }
        if enabled {
            return err(SyscallError::EOPNOTSUPP);
        }
        state.packet_vnet_hdr = false;
        0
    }

    pub(super) fn packet_vnet_hdr(&self) -> bool {
        self.state.lock().packet_vnet_hdr
    }

    pub(super) fn set_packet_copy_thresh(&self, value: i32) {
        self.state.lock().packet_copy_thresh = value;
    }

    pub(super) fn packet_copy_thresh(&self) -> i32 {
        self.state.lock().packet_copy_thresh
    }

    pub(super) fn set_packet_auxdata(&self, enabled: bool) {
        self.state.lock().packet_auxdata = enabled;
    }

    pub(super) fn packet_auxdata(&self) -> bool {
        self.state.lock().packet_auxdata
    }

    pub(super) fn set_packet_origdev(&self, enabled: bool) {
        self.state.lock().packet_origdev = enabled;
    }

    pub(super) fn packet_origdev(&self) -> bool {
        self.state.lock().packet_origdev
    }

    pub(super) fn set_packet_qdisc_bypass(&self, enabled: bool) {
        self.state.lock().packet_qdisc_bypass = enabled;
    }

    pub(super) fn packet_qdisc_bypass(&self) -> bool {
        self.state.lock().packet_qdisc_bypass
    }

    pub(super) fn take_packet_statistics(&self) -> (u32, u32, bool) {
        let mut state = self.state.lock();
        let packets = state.rx_packets;
        let drops = state.rx_drops;
        state.rx_packets = 0;
        state.rx_drops = 0;
        (packets, drops, state.packet_version == TPACKET_V3)
    }

    pub(super) fn set_packet_ignore_outgoing(&self, enabled: bool) -> isize {
        self.state.lock().ignore_outgoing = enabled;
        0
    }

    pub(super) fn packet_ignore_outgoing(&self) -> bool {
        self.state.lock().ignore_outgoing
    }

    pub(super) fn fanout_value(&self) -> u32 {
        self.state
            .lock()
            .fanout
            .map(|fanout| {
                fanout.key.id as u32
                    | ((fanout.key.mode as u32) << 16)
                    | ((fanout.key.flags as u32) << 24)
            })
            .unwrap_or(0)
    }

    pub(super) fn attach_filter(&self, filter: ClassicBpfProgram) -> isize {
        let mut state = self.state.lock();
        if state.filter_locked {
            return err(SyscallError::EPERM);
        }
        state.filter = Some(filter);
        state.ebpf_filter = None;
        0
    }

    pub(super) fn attach_bpf(&self, filter: Arc<BpfProgFile>) -> isize {
        let mut state = self.state.lock();
        if state.filter_locked {
            return err(SyscallError::EPERM);
        }
        state.filter = None;
        state.ebpf_filter = Some(filter);
        0
    }

    pub(super) fn detach_filter(&self) -> isize {
        let mut state = self.state.lock();
        if state.filter_locked {
            return err(SyscallError::EPERM);
        }
        let had_filter = state.filter.take().is_some() | state.ebpf_filter.take().is_some();
        if had_filter {
            0
        } else {
            err(SyscallError::ENOENT)
        }
    }

    pub(super) fn set_filter_locked(&self, locked: bool) -> isize {
        let mut state = self.state.lock();
        if state.filter_locked && !locked {
            return err(SyscallError::EPERM);
        }
        state.filter_locked = locked;
        0
    }

    pub(super) fn filter_locked(&self) -> bool {
        self.state.lock().filter_locked
    }

    pub(super) fn classic_filter_snapshot(&self) -> (Option<ClassicBpfProgram>, bool) {
        let state = self.state.lock();
        (state.filter.clone(), state.ebpf_filter.is_some())
    }

    fn apply_membership_to_device(
        ns_id: usize,
        ifindex: i32,
        mr_type: u16,
        mr_alen: u16,
        addr: [u8; 8],
        enable: bool,
    ) -> Result<(), isize> {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&addr[..6]);
        match mr_type {
            PACKET_MR_MULTICAST => {
                if mr_alen != 6 {
                    return Err(err(SyscallError::EINVAL));
                }
                if enable {
                    netdev::add_maddr_in_namespace(ns_id, ifindex, mac)
                } else {
                    netdev::del_maddr_in_namespace(ns_id, ifindex, mac)
                }
            }
            PACKET_MR_PROMISC => netdev::set_promiscuity_in_namespace(ns_id, ifindex, enable),
            PACKET_MR_ALLMULTI => netdev::set_allmulti_in_namespace(ns_id, ifindex, enable),
            PACKET_MR_UNICAST => {
                if mr_alen != 6 {
                    return Err(err(SyscallError::EINVAL));
                }
                if enable {
                    netdev::add_uaddr_in_namespace(ns_id, ifindex, mac)
                } else {
                    netdev::del_uaddr_in_namespace(ns_id, ifindex, mac)
                }
            }
            _ => Err(err(SyscallError::EINVAL)),
        }
    }

    pub(super) fn add_membership(
        &self,
        ifindex: i32,
        mr_type: u16,
        mr_alen: u16,
        addr: [u8; 8],
    ) -> isize {
        let Some(_dev) = self.device_snapshot_by_index(ifindex) else {
            return err(SyscallError::ENODEV);
        };
        if mr_alen > 6 {
            return err(SyscallError::EINVAL);
        }
        if !matches!(
            mr_type,
            PACKET_MR_MULTICAST | PACKET_MR_PROMISC | PACKET_MR_ALLMULTI | PACKET_MR_UNICAST
        ) {
            return err(SyscallError::EINVAL);
        }

        let mut state = self.state.lock();
        if let Some(existing) = state.memberships.iter_mut().find(|entry| {
            entry.ifindex == ifindex
                && entry.mr_type == mr_type
                && entry.mr_alen == mr_alen
                && entry.addr == addr
        }) {
            let Some(count) = existing.count.checked_add(1) else {
                return err(SyscallError::EOVERFLOW);
            };
            existing.count = count;
            return 0;
        }

        match Self::apply_membership_to_device(
            self.net_ns_id,
            ifindex,
            mr_type,
            mr_alen,
            addr,
            true,
        ) {
            Ok(()) => {
                state.memberships.push(PacketMembership {
                    ifindex,
                    mr_type,
                    mr_alen,
                    addr,
                    count: 1,
                });
                0
            }
            Err(e) => e,
        }
    }

    pub(super) fn drop_membership(
        &self,
        ifindex: i32,
        mr_type: u16,
        mr_alen: u16,
        addr: [u8; 8],
    ) -> isize {
        let mut state = self.state.lock();
        let Some(pos) = state.memberships.iter().position(|entry| {
            entry.ifindex == ifindex
                && entry.mr_type == mr_type
                && entry.mr_alen == mr_alen
                && entry.addr == addr
        }) else {
            return 0;
        };
        if state.memberships[pos].count > 1 {
            state.memberships[pos].count -= 1;
            return 0;
        }
        let entry = state.memberships.remove(pos);
        drop(state);

        let _ = Self::apply_membership_to_device(
            self.net_ns_id,
            entry.ifindex,
            entry.mr_type,
            entry.mr_alen,
            entry.addr,
            false,
        );
        0
    }

    fn release_memberships(&self) {
        let memberships = {
            let mut state = self.state.lock();
            core::mem::take(&mut state.memberships)
        };
        for entry in memberships {
            let _ = Self::apply_membership_to_device(
                self.net_ns_id,
                entry.ifindex,
                entry.mr_type,
                entry.mr_alen,
                entry.addr,
                false,
            );
        }
    }

    pub(super) fn set_packet_ring(
        &self,
        is_rx: bool,
        block_size: u32,
        block_nr: u32,
        frame_size: u32,
        frame_nr: u32,
        private_size: u32,
    ) -> isize {
        const TPACKET_ALIGNMENT: u32 = 16;

        if block_nr == 0 || frame_nr == 0 {
            if block_nr != 0 || frame_nr != 0 {
                return err(SyscallError::EINVAL);
            }
            let mut state = self.state.lock();
            if Self::packet_ring_mapped(&state) {
                return err(SyscallError::EBUSY);
            }
            if is_rx {
                state.rx_ring = None;
            } else {
                state.tx_ring = None;
            }
            return 0;
        }

        if block_size == 0 || block_nr == 0 || frame_size == 0 || frame_nr == 0 {
            return err(SyscallError::EINVAL);
        }
        if block_size as usize % crate::config::PAGE_SIZE != 0
            || frame_size % TPACKET_ALIGNMENT != 0
            || frame_size < TPACKET2_HDRLEN_ALIGNED
            || block_size < frame_size
        {
            return err(SyscallError::EINVAL);
        }
        let frames_per_block = block_size / frame_size;
        if frames_per_block == 0 || frame_nr != frames_per_block.saturating_mul(block_nr) {
            return err(SyscallError::EINVAL);
        }
        if private_size > block_size {
            return err(SyscallError::EINVAL);
        }

        let mut state = self.state.lock();
        if Self::packet_ring_mapped(&state) {
            return err(SyscallError::EBUSY);
        }
        if state.packet_reserve >= frame_size {
            return err(SyscallError::EINVAL);
        }
        if is_rx && state.packet_vnet_hdr {
            return err(SyscallError::EINVAL);
        }
        if is_rx && state.rx_ring.is_some() {
            return err(SyscallError::EBUSY);
        }
        if !is_rx && state.tx_ring.is_some() {
            return err(SyscallError::EBUSY);
        }
        let ring = PacketRing {
            version: state.packet_version,
            block_size,
            block_nr,
            frame_size,
            frame_nr,
            mappings: Vec::new(),
        };
        if is_rx {
            state.rx_ring = Some(ring);
        } else {
            state.tx_ring = Some(ring);
        }
        0
    }

    fn packet_ring_mapped(state: &PacketSocketState) -> bool {
        state
            .rx_ring
            .as_ref()
            .is_some_and(|ring| !ring.mappings.is_empty())
            || state
                .tx_ring
                .as_ref()
                .is_some_and(|ring| !ring.mappings.is_empty())
    }

    pub(crate) fn rx_ring_mmap_len(&self) -> Option<usize> {
        self.state
            .lock()
            .rx_ring
            .as_ref()
            .map(|ring| (ring.block_size as usize).saturating_mul(ring.block_nr as usize))
    }

    pub(crate) fn set_rx_ring_mmap(&self, base: usize, len: usize, token: usize) -> isize {
        let mut state = self.state.lock();
        let Some(ring) = state.rx_ring.as_mut() else {
            return err(SyscallError::EINVAL);
        };
        let expected = (ring.block_size as usize).saturating_mul(ring.block_nr as usize);
        if len != expected {
            return err(SyscallError::EINVAL);
        }
        if ring
            .mappings
            .iter()
            .any(|mapping| mapping.token == token && mapping.base == base)
        {
            return err(SyscallError::EBUSY);
        }
        ring.mappings.push(PacketRingMapping {
            base,
            len,
            token,
            next_frame: 0,
            pending_frame: None,
        });
        0
    }

    fn packet_ring_mmap_overlaps(
        mapping: &PacketRingMapping,
        token: usize,
        start: usize,
        end: usize,
    ) -> bool {
        if mapping.len == 0 || mapping.token != token {
            return false;
        }
        let Some(ring_end) = mapping.base.checked_add(mapping.len) else {
            return true;
        };
        start < ring_end && mapping.base < end
    }

    fn clear_packet_ring_mmap_range(&self, token: usize, start: usize, end: usize) {
        let mut state = self.state.lock();
        if let Some(ring) = state.rx_ring.as_mut() {
            ring.mappings
                .retain(|mapping| !Self::packet_ring_mmap_overlaps(mapping, token, start, end));
        }
        if let Some(ring) = state.tx_ring.as_mut() {
            ring.mappings
                .retain(|mapping| !Self::packet_ring_mmap_overlaps(mapping, token, start, end));
        }
    }

    fn clear_packet_ring_mmap_token(&self, token: usize) {
        let mut state = self.state.lock();
        if let Some(ring) = state.rx_ring.as_mut() {
            ring.mappings.retain(|mapping| mapping.token != token);
        }
        if let Some(ring) = state.tx_ring.as_mut() {
            ring.mappings.retain(|mapping| mapping.token != token);
        }
    }

    fn clone_packet_ring_mmap_token(&self, parent_token: usize, child_token: usize) {
        fn clone_ring_mappings(ring: &mut PacketRing, parent_token: usize, child_token: usize) {
            let inherited = ring
                .mappings
                .iter()
                .filter(|mapping| mapping.token == parent_token)
                .filter(|mapping| {
                    !ring.mappings.iter().any(|existing| {
                        existing.token == child_token && existing.base == mapping.base
                    })
                })
                .map(|mapping| PacketRingMapping {
                    token: child_token,
                    ..*mapping
                })
                .collect::<Vec<_>>();
            ring.mappings.extend(inherited);
        }

        let mut state = self.state.lock();
        if let Some(ring) = state.rx_ring.as_mut() {
            clone_ring_mappings(ring, parent_token, child_token);
        }
        if let Some(ring) = state.tx_ring.as_mut() {
            clone_ring_mappings(ring, parent_token, child_token);
        }
    }

    fn packet_ring_mmap_range_overlaps(&self, token: usize, start: usize, end: usize) -> bool {
        let state = self.state.lock();
        state.rx_ring.as_ref().is_some_and(|ring| {
            ring.mappings
                .iter()
                .any(|mapping| Self::packet_ring_mmap_overlaps(mapping, token, start, end))
        }) || state.tx_ring.as_ref().is_some_and(|ring| {
            ring.mappings
                .iter()
                .any(|mapping| Self::packet_ring_mmap_overlaps(mapping, token, start, end))
        })
    }

    pub(super) fn local_addr_ll(&self) -> SockAddrLl {
        let state = self.state.lock();
        let dev = if state.bound_ifindex > 0 {
            self.device_snapshot_by_index(state.bound_ifindex)
        } else {
            None
        };
        let mut sa = SockAddrLl {
            sll_family: AF_PACKET,
            sll_protocol: if state.bound_protocol != 0 {
                state.bound_protocol
            } else {
                self.protocol
            },
            sll_ifindex: state.bound_ifindex,
            sll_hatype: dev.as_ref().map(|dev| dev.link_type).unwrap_or(0),
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        if let Some(dev) = dev {
            sa.sll_halen = 6;
            sa.sll_addr[..6].copy_from_slice(&dev.hwaddr);
        }
        sa
    }

    pub(crate) fn poll_readable(&self) -> bool {
        !self.state.lock().recv_queue.is_empty()
    }

    pub(super) fn recv_packet(&self, peek: bool) -> Option<PacketFrame> {
        let mut state = self.state.lock();
        let packet = if peek {
            state.recv_queue.front().cloned()
        } else {
            state.recv_queue.pop_front()
        };
        if !peek && packet.is_some() {
            state.last_timestamp = Some(SocketTimestamp::now());
        }
        packet
    }

    fn set_socket_error(&self, errno: isize) {
        if errno < 0 {
            self.state.lock().pending_error = (-errno) as i32;
        }
    }

    pub(super) fn take_socket_error(&self) -> u32 {
        let mut state = self.state.lock();
        let errno = state.pending_error.max(0) as u32;
        state.pending_error = 0;
        errno
    }

    pub(crate) fn socket_timestamp(&self) -> Option<SocketTimestamp> {
        self.state.lock().last_timestamp
    }

    pub(super) fn set_timestamp_mode(&self, mode: SocketTimestampMode) {
        self.state.lock().timestamp_mode = mode;
    }

    pub(super) fn timestamp_mode(&self) -> SocketTimestampMode {
        self.state.lock().timestamp_mode
    }

    fn ring_slot_count(ring: &PacketRing) -> u32 {
        if ring.version == TPACKET_V3 {
            ring.block_nr
        } else {
            ring.frame_nr
        }
    }

    fn ring_status_addr(
        ring: &PacketRing,
        mapping: &PacketRingMapping,
        slot_idx: u32,
    ) -> Option<usize> {
        let base = Self::ring_slot_addr(ring, mapping, slot_idx)?;
        if ring.version == TPACKET_V3 {
            base.checked_add(8)
        } else {
            Some(base)
        }
    }

    fn ring_slot_addr(
        ring: &PacketRing,
        mapping: &PacketRingMapping,
        slot_idx: u32,
    ) -> Option<usize> {
        let slot_count = Self::ring_slot_count(ring);
        if mapping.len == 0 || slot_count == 0 || slot_idx >= slot_count {
            return None;
        }
        let slot_size = if ring.version == TPACKET_V3 {
            ring.block_size
        } else {
            ring.frame_size
        } as usize;
        let offset = (slot_idx as usize).checked_mul(slot_size)?;
        if offset.checked_add(slot_size)? > mapping.len {
            return None;
        }
        mapping.base.checked_add(offset)
    }

    fn write_ring_frame(
        token: usize,
        base: usize,
        frame_size: u32,
        reserve: u32,
        frame: &PacketFrame,
    ) -> Result<(), ()> {
        let frame_size = frame_size as usize;
        let data_offset = (TPACKET2_HDRLEN_ALIGNED + reserve) as usize;
        if data_offset >= frame_size {
            return Err(());
        }
        let snaplen = core::cmp::min(frame.data.len(), frame_size - data_offset);
        let zero = [0u8; 128];
        let mut cleared = 0usize;
        while cleared < frame_size {
            let n = core::cmp::min(zero.len(), frame_size - cleared);
            try_copy_to_user(token, (base + cleared) as *mut u8, &zero[..n])?;
            cleared += n;
        }

        let now = crate::syscall::time_sys::realtime_now_timespec();
        let mut hdr = [0u8; TPACKET2_HDRLEN_ALIGNED as usize];
        fn put_u16(dst: &mut [u8], off: usize, val: u16) {
            dst[off..off + 2].copy_from_slice(&val.to_ne_bytes());
        }
        fn put_u32(dst: &mut [u8], off: usize, val: u32) {
            dst[off..off + 4].copy_from_slice(&val.to_ne_bytes());
        }
        put_u32(&mut hdr, 4, frame.data.len() as u32);
        put_u32(&mut hdr, 8, snaplen as u32);
        put_u16(&mut hdr, 12, data_offset as u16);
        put_u16(
            &mut hdr,
            14,
            (data_offset + 14).min(u16::MAX as usize) as u16,
        );
        put_u32(&mut hdr, 16, now.0 as u32);
        put_u32(&mut hdr, 20, now.1 as u32);
        hdr[32..34].copy_from_slice(&frame.addr.sll_family.to_ne_bytes());
        hdr[34..36].copy_from_slice(&frame.addr.sll_protocol.to_ne_bytes());
        hdr[36..40].copy_from_slice(&frame.addr.sll_ifindex.to_ne_bytes());
        hdr[40..42].copy_from_slice(&frame.addr.sll_hatype.to_ne_bytes());
        hdr[42] = frame.addr.sll_pkttype;
        hdr[43] = frame.addr.sll_halen;
        hdr[44..52].copy_from_slice(&frame.addr.sll_addr);

        try_copy_to_user(token, base as *mut u8, &hdr)?;
        try_copy_to_user(
            token,
            (base + data_offset) as *mut u8,
            &frame.data[..snaplen],
        )?;
        try_write_user_value(token, base as *mut u32, &TP_STATUS_USER)
    }

    fn write_ring_block_v3(
        token: usize,
        base: usize,
        block_size: u32,
        reserve: u32,
        frame: &PacketFrame,
    ) -> Result<(), ()> {
        let block_size = block_size as usize;
        let packet_off = TPACKET3_BLOCK_DESC_LEN as usize;
        let data_offset = (TPACKET3_HDRLEN + reserve) as usize;
        let packet_data = packet_off.checked_add(data_offset).ok_or(())?;
        if packet_data >= block_size {
            return Err(());
        }
        let snaplen = core::cmp::min(frame.data.len(), block_size - packet_data);
        let packet_len_aligned = (data_offset + snaplen + 15) & !15;
        let block_len = packet_off + packet_len_aligned;

        let zero = [0u8; 128];
        let mut cleared = 0usize;
        while cleared < block_size {
            let n = core::cmp::min(zero.len(), block_size - cleared);
            try_copy_to_user(token, (base + cleared) as *mut u8, &zero[..n])?;
            cleared += n;
        }

        let now = crate::syscall::time_sys::realtime_now_timespec();
        let mut block = [0u8; TPACKET3_BLOCK_DESC_LEN as usize];
        fn put_u16(dst: &mut [u8], off: usize, val: u16) {
            dst[off..off + 2].copy_from_slice(&val.to_ne_bytes());
        }
        fn put_u32(dst: &mut [u8], off: usize, val: u32) {
            dst[off..off + 4].copy_from_slice(&val.to_ne_bytes());
        }
        fn put_u64(dst: &mut [u8], off: usize, val: u64) {
            dst[off..off + 8].copy_from_slice(&val.to_ne_bytes());
        }
        put_u32(&mut block, 0, TPACKET_V3 as u32);
        put_u32(&mut block, 8, TP_STATUS_USER);
        put_u32(&mut block, 12, 1);
        put_u32(&mut block, 16, TPACKET3_BLOCK_DESC_LEN);
        put_u32(&mut block, 20, block_len as u32);
        put_u64(&mut block, 24, now.0 as u64);
        put_u32(&mut block, 32, now.0 as u32);
        put_u32(&mut block, 36, now.1 as u32);
        put_u32(&mut block, 40, now.0 as u32);
        put_u32(&mut block, 44, now.1 as u32);

        let mut hdr = [0u8; TPACKET3_HDRLEN as usize];
        put_u32(&mut hdr, 0, 0);
        put_u32(&mut hdr, 4, now.0 as u32);
        put_u32(&mut hdr, 8, now.1 as u32);
        put_u32(&mut hdr, 12, snaplen as u32);
        put_u32(&mut hdr, 16, frame.data.len() as u32);
        put_u32(&mut hdr, 20, TP_STATUS_USER);
        put_u16(&mut hdr, 24, data_offset as u16);
        put_u16(
            &mut hdr,
            26,
            (data_offset + 14).min(u16::MAX as usize) as u16,
        );
        hdr[48..50].copy_from_slice(&frame.addr.sll_family.to_ne_bytes());
        hdr[50..52].copy_from_slice(&frame.addr.sll_protocol.to_ne_bytes());
        hdr[52..56].copy_from_slice(&frame.addr.sll_ifindex.to_ne_bytes());
        hdr[56..58].copy_from_slice(&frame.addr.sll_hatype.to_ne_bytes());
        hdr[58] = frame.addr.sll_pkttype;
        hdr[59] = frame.addr.sll_halen;
        hdr[60..68].copy_from_slice(&frame.addr.sll_addr);

        try_copy_to_user(token, base as *mut u8, &block)?;
        try_copy_to_user(token, (base + packet_off) as *mut u8, &hdr)?;
        try_copy_to_user(
            token,
            (base + packet_data) as *mut u8,
            &frame.data[..snaplen],
        )
    }

    fn materialize_rx_ring_frame(&self) -> bool {
        let current_token = get_current_token();
        let mut state = self.state.lock();
        let reserve = state.packet_reserve;
        let Some(ring) = state.rx_ring.as_mut() else {
            return false;
        };
        let Some(mapping_idx) = ring
            .mappings
            .iter()
            .position(|mapping| mapping.token == current_token)
        else {
            return false;
        };
        if let Some(pending_idx) = ring.mappings[mapping_idx].pending_frame {
            let mapping = ring.mappings[mapping_idx];
            let Some(status_addr) = Self::ring_status_addr(ring, &mapping, pending_idx) else {
                return false;
            };
            match try_read_user_value::<u32>(mapping.token, status_addr as *const u32) {
                Some(status) if status != TP_STATUS_KERNEL => return true,
                Some(_) => {
                    let slot_count = Self::ring_slot_count(ring).max(1);
                    ring.mappings[mapping_idx].pending_frame = None;
                    ring.mappings[mapping_idx].next_frame = (pending_idx + 1) % slot_count;
                }
                None => return false,
            }
        }

        if state.recv_queue.is_empty() {
            return false;
        }
        let (mapping, next_frame, slot_addr, version, block_size, frame_size) = {
            let Some(ring) = state.rx_ring.as_mut() else {
                return false;
            };
            let Some(mapping_idx) = ring
                .mappings
                .iter()
                .position(|mapping| mapping.token == current_token)
            else {
                return false;
            };
            let mapping = ring.mappings[mapping_idx];
            let Some(slot_addr) = Self::ring_slot_addr(ring, &mapping, mapping.next_frame) else {
                return false;
            };
            let Some(status_addr) = Self::ring_status_addr(ring, &mapping, mapping.next_frame)
            else {
                return false;
            };
            let status = match try_read_user_value::<u32>(mapping.token, status_addr as *const u32)
            {
                Some(status) => status,
                None => return false,
            };
            if status != TP_STATUS_KERNEL {
                ring.mappings[mapping_idx].pending_frame = Some(mapping.next_frame);
                return true;
            }
            (
                mapping,
                mapping.next_frame,
                slot_addr,
                ring.version,
                ring.block_size,
                ring.frame_size,
            )
        };
        let Some(frame) = state.recv_queue.pop_front() else {
            return false;
        };
        let wrote = if version == TPACKET_V3 {
            Self::write_ring_block_v3(mapping.token, slot_addr, block_size, reserve, &frame)
        } else {
            Self::write_ring_frame(mapping.token, slot_addr, frame_size, reserve, &frame)
        };
        if wrote.is_err() {
            state.recv_queue.push_front(frame);
            return false;
        }
        if let Some(ring) = state.rx_ring.as_mut() {
            if let Some(mapping) = ring.mappings.iter_mut().find(|candidate| {
                candidate.token == current_token && candidate.base == mapping.base
            }) {
                mapping.pending_frame = Some(next_frame);
            }
        }
        true
    }

    pub(super) fn handle_outbound_packet(
        &self,
        payload: &[u8],
        dest: Option<&SockAddrLl>,
        metadata: PacketMetadata,
    ) -> Result<(), isize> {
        let user_len = payload.len();
        let (ifindex, ethertype, src_mac, dst_mac, payload) =
            self.outgoing_packet_frame(payload, dest)?;
        let Some(dev) = self.device_snapshot_by_index(ifindex) else {
            return Err(err(SyscallError::ENXIO));
        };
        let reserve = if self.socket_type == SOCK_RAW {
            ETH_HDR_LEN
        } else {
            0
        };
        if user_len > dev.mtu as usize + reserve + VLAN_HLEN {
            return Err(err(SyscallError::EMSGSIZE));
        }
        let deliver_to_local_stack = dev.kind == netdev::NetDeviceKind::Loopback;
        match dev.kind {
            netdev::NetDeviceKind::Tun if ethertype == ETH_P_IP => {
                crate::fs::enqueue_tuntap_packet(ifindex, payload.to_vec());
            }
            netdev::NetDeviceKind::Tap => {
                let mut frame = Vec::with_capacity(ETH_HDR_LEN + payload.len());
                frame.extend_from_slice(&dst_mac);
                frame.extend_from_slice(&src_mac);
                frame.extend_from_slice(&ethertype.to_be_bytes());
                frame.extend_from_slice(payload);
                crate::fs::enqueue_tuntap_packet(ifindex, frame);
            }
            _ => {}
        }
        netdev::record_device_traffic_in_namespace(
            self.net_ns_id,
            ifindex,
            device_frame_len(&dev, payload.len()),
            true,
        );
        transmit_packet_frame_from_device(
            self.net_ns_id,
            &dev,
            ethertype,
            src_mac,
            dst_mac,
            payload,
            metadata,
        );
        if ethertype == ETH_P_IP {
            netdev::record_protocol_packet_in_namespace(self.net_ns_id, payload, true);
            if deliver_to_local_stack {
                crate::net::inject_loopback_ip_packet_in(self.net_ns_id, payload);
            }
        }
        Ok(())
    }

    fn push_frame(&self, frame: PacketFrame) {
        let mut state = self.state.lock();
        state.rx_packets = state.rx_packets.saturating_add(1);
        if state.recv_queue.len() >= PACKET_RECV_QUEUE_LIMIT {
            state.recv_queue.pop_front();
            state.rx_drops = state.rx_drops.saturating_add(1);
        }
        state.recv_queue.push_back(frame);
    }

    fn protocol_matches(requested_be: u16, ethertype: u16) -> bool {
        requested_be == 0 || requested_be == ETH_P_ALL.to_be() || requested_be == ethertype.to_be()
    }

    fn fanout_key_for_frame(
        &self,
        ifindex: i32,
        ethertype: u16,
        pkttype: u8,
    ) -> Option<PacketFanoutKey> {
        let state = self.state.lock();
        let fanout = state.fanout?;
        if pkttype == PACKET_OUTGOING
            && (state.ignore_outgoing
                || (fanout.key.flags & ((PACKET_FANOUT_FLAG_IGNORE_OUTGOING >> 8) as u8)) != 0)
        {
            return None;
        }
        let protocol = if state.bound_protocol != 0 {
            state.bound_protocol
        } else {
            self.protocol
        };
        if state.bound_ifindex > 0 && state.bound_ifindex != ifindex {
            return None;
        }
        if !Self::protocol_matches(protocol, ethertype) {
            return None;
        }
        Some(fanout.key)
    }

    fn fanout_key(&self) -> Option<PacketFanoutKey> {
        self.state.lock().fanout.map(|fanout| fanout.key)
    }

    fn recv_queue_full(&self) -> bool {
        self.state.lock().recv_queue.len() >= PACKET_RECV_QUEUE_LIMIT
    }

    fn observed_frame(
        &self,
        ifindex: i32,
        ethertype: u16,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        payload: &[u8],
        pkttype: u8,
        metadata: PacketMetadata,
    ) -> Option<PacketFrame> {
        let (bound_ifindex, requested_protocol, packet_origdev, filter, ebpf_filter) = {
            let state = self.state.lock();
            if pkttype == PACKET_OUTGOING && state.ignore_outgoing {
                return None;
            }
            let protocol = if state.bound_protocol != 0 {
                state.bound_protocol
            } else {
                self.protocol
            };
            (
                state.bound_ifindex,
                protocol,
                state.packet_origdev,
                state.filter.clone(),
                state.ebpf_filter.clone(),
            )
        };
        if bound_ifindex > 0 && bound_ifindex != ifindex {
            return None;
        }
        if !Self::protocol_matches(requested_protocol, ethertype) {
            return None;
        }

        let dev = self.device_snapshot_by_index(ifindex);
        let visible_ifindex = if packet_origdev && metadata.orig_ifindex > 0 {
            metadata.orig_ifindex
        } else {
            ifindex
        };
        let mut addr = SockAddrLl {
            sll_family: AF_PACKET,
            sll_protocol: ethertype.to_be(),
            sll_ifindex: visible_ifindex,
            sll_hatype: dev
                .as_ref()
                .map(|dev| dev.link_type)
                .unwrap_or(netdev::ARPHRD_ETHER),
            sll_pkttype: pkttype,
            sll_halen: 6,
            sll_addr: [0; 8],
        };
        addr.sll_addr[..6].copy_from_slice(&src_mac);

        let mut data = if self.socket_type == SOCK_RAW {
            let mut frame = Vec::with_capacity(14 + payload.len());
            frame.extend_from_slice(&dst_mac);
            frame.extend_from_slice(&src_mac);
            frame.extend_from_slice(&ethertype.to_be_bytes());
            frame.extend_from_slice(payload);
            frame
        } else {
            payload.to_vec()
        };
        if let Some(filter) = filter {
            let Some(snaplen) = filter.filter_len(&data) else {
                return None;
            };
            data.truncate(snaplen);
        }
        if let Some(filter) = ebpf_filter {
            let Some(snaplen) = filter.filter_len(&data) else {
                return None;
            };
            data.truncate(snaplen);
        }
        Some(PacketFrame {
            data,
            addr,
            metadata,
        })
    }

    fn enqueue_observed_frame(
        &self,
        ifindex: i32,
        ethertype: u16,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        payload: &[u8],
        pkttype: u8,
        metadata: PacketMetadata,
    ) {
        if let Some(frame) = self.observed_frame(
            ifindex, ethertype, src_mac, dst_mac, payload, pkttype, metadata,
        ) {
            self.push_frame(frame);
        }
    }

    fn current_ifindex(&self, dest: Option<&SockAddrLl>) -> Option<i32> {
        if let Some(sa) = dest {
            if sa.sll_ifindex <= 0 {
                return None;
            }
            return self
                .device_snapshot_by_index(sa.sll_ifindex)
                .map(|dev| dev.ifindex);
        }
        let state = self.state.lock();
        (state.bound_ifindex > 0)
            .then(|| {
                self.device_snapshot_by_index(state.bound_ifindex)
                    .map(|dev| dev.ifindex)
            })
            .flatten()
    }

    fn current_protocol(&self, dest: Option<&SockAddrLl>) -> u16 {
        if let Some(sa) = dest {
            return sa.sll_protocol;
        }
        let state = self.state.lock();
        if state.bound_protocol != 0 {
            state.bound_protocol
        } else {
            self.protocol
        }
    }

    fn outgoing_packet_frame<'a>(
        &self,
        payload: &'a [u8],
        dest: Option<&SockAddrLl>,
    ) -> Result<(i32, u16, [u8; 6], [u8; 6], &'a [u8]), isize> {
        if self.socket_type == SOCK_RAW {
            if payload.len() < ETH_HDR_LEN {
                return Err(err(SyscallError::EINVAL));
            }
            let mut dst_mac = [0u8; 6];
            let mut src_mac = [0u8; 6];
            dst_mac.copy_from_slice(&payload[0..6]);
            src_mac.copy_from_slice(&payload[6..12]);
            let ethertype = u16::from_be_bytes([payload[12], payload[13]]);
            let Some(ifindex) = self.current_ifindex(dest) else {
                return Err(err(SyscallError::ENXIO));
            };
            let Some(dev) = self.device_snapshot_by_index(ifindex) else {
                return Err(err(SyscallError::ENXIO));
            };
            if (dev.flags & netdev::IFF_UP) == 0 {
                return Err(err(SyscallError::ENETDOWN));
            }
            return Ok((
                ifindex,
                ethertype,
                src_mac,
                dst_mac,
                &payload[ETH_HDR_LEN..],
            ));
        }

        let Some(ifindex) = self.current_ifindex(dest) else {
            return Err(err(SyscallError::ENXIO));
        };
        let Some(dev) = self.device_snapshot_by_index(ifindex) else {
            return Err(err(SyscallError::ENXIO));
        };
        if (dev.flags & netdev::IFF_UP) == 0 {
            return Err(err(SyscallError::ENETDOWN));
        }
        let protocol_be = self.current_protocol(dest);
        let ethertype = u16::from_be(protocol_be);
        let mut dst_mac = [0xff; 6];
        if let Some(dest) = dest {
            dst_mac.copy_from_slice(&dest.sll_addr[..6]);
        }
        Ok((ifindex, ethertype, dev.hwaddr, dst_mac, payload))
    }
}

impl Drop for PacketSocketFile {
    fn drop(&mut self) {
        self.release_memberships();
        crate::fs::release_net_namespace_socket_ref(self.net_ns_id);
    }
}

fn deliver_packet_frame_to_packet_sockets(
    ns_id: usize,
    ifindex: i32,
    ethertype: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    payload: &[u8],
    pkttype: u8,
    metadata: PacketMetadata,
) {
    let sockets = packet_socket_snapshot_in(ns_id);
    let mut fanout_groups: Vec<PacketFanoutGroup> = Vec::new();

    for sock in sockets {
        if sock.fanout_key().is_none() {
            sock.enqueue_observed_frame(
                ifindex, ethertype, src_mac, dst_mac, payload, pkttype, metadata,
            );
        } else if let Some(key) = sock.fanout_key_for_frame(ifindex, ethertype, pkttype) {
            add_fanout_candidate(&mut fanout_groups, key, sock);
        }
    }

    for group in fanout_groups {
        if group.sockets.is_empty() {
            continue;
        }
        let mut idx = select_fanout_member(
            group.key,
            ifindex,
            ethertype,
            src_mac,
            dst_mac,
            payload,
            group.sockets.len(),
        );
        if group.key.mode as u32 == PACKET_FANOUT_ROLLOVER
            || (group.key.flags & ((PACKET_FANOUT_FLAG_ROLLOVER >> 8) as u8)) != 0
        {
            idx = select_rollover_member(&group.sockets, idx);
        }
        let sock = &group.sockets[idx % group.sockets.len()];
        sock.enqueue_observed_frame(
            ifindex, ethertype, src_mac, dst_mac, payload, pkttype, metadata,
        );
    }
}

fn macvlan_accepts_frame(dev: &netdev::NetDeviceSnapshot, dst_mac: [u8; 6]) -> bool {
    dst_mac == dev.hwaddr || dst_mac == [0xff; 6] || (dst_mac[0] & 1) != 0
}

fn broadcast_packet_frame(
    ns_id: usize,
    ifindex: i32,
    ethertype: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    payload: &[u8],
    pkttype: u8,
    metadata: PacketMetadata,
) {
    let metadata = if metadata.orig_ifindex > 0 {
        metadata
    } else {
        PacketMetadata {
            orig_ifindex: ifindex,
            ..metadata
        }
    };

    deliver_packet_frame_to_packet_sockets(
        ns_id, ifindex, ethertype, src_mac, dst_mac, payload, pkttype, metadata,
    );

    if pkttype == PACKET_HOST {
        for upper in netdev::macvlan_upper_snapshots_by_link_in_namespace(ns_id, ifindex) {
            if macvlan_accepts_frame(&upper, dst_mac) {
                netdev::record_device_traffic_in_namespace(
                    ns_id,
                    upper.ifindex,
                    device_frame_len(&upper, payload.len()),
                    false,
                );
                deliver_packet_frame_to_packet_sockets(
                    ns_id,
                    upper.ifindex,
                    ethertype,
                    src_mac,
                    dst_mac,
                    payload,
                    pkttype,
                    metadata,
                );
            }
        }
    }

    if ethertype == ETH_P_IP && pkttype == PACKET_HOST {
        broadcast_raw_ipv4_packet(ns_id, ifindex, payload, pkttype, metadata);
    }
}

fn transmit_packet_frame_from_device(
    ns_id: usize,
    dev: &netdev::NetDeviceSnapshot,
    ethertype: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    payload: &[u8],
    metadata: PacketMetadata,
) {
    let metadata = if metadata.orig_ifindex > 0 {
        metadata
    } else {
        PacketMetadata {
            orig_ifindex: dev.ifindex,
            ..metadata
        }
    };

    broadcast_packet_frame(
        ns_id,
        dev.ifindex,
        ethertype,
        src_mac,
        dst_mac,
        payload,
        PACKET_OUTGOING,
        metadata,
    );

    if dev.kind == netdev::NetDeviceKind::Macvlan
        && let Some(lower_ifindex) = dev.link_ifindex
        && let Some(lower) = netdev::device_snapshot_by_index_in_namespace(ns_id, lower_ifindex)
        && (lower.flags & netdev::IFF_UP) != 0
    {
        netdev::record_device_traffic_in_namespace(
            ns_id,
            lower.ifindex,
            device_frame_len(&lower, payload.len()),
            true,
        );
        broadcast_packet_frame(
            ns_id,
            lower.ifindex,
            ethertype,
            src_mac,
            dst_mac,
            payload,
            PACKET_OUTGOING,
            metadata,
        );
        forward_veth_peer_frame(
            ns_id,
            lower.ifindex,
            ethertype,
            src_mac,
            dst_mac,
            payload,
            metadata,
        );
    } else {
        forward_veth_peer_frame(
            ns_id,
            dev.ifindex,
            ethertype,
            src_mac,
            dst_mac,
            payload,
            metadata,
        );
    }
}

fn forward_veth_peer_frame(
    ns_id: usize,
    ifindex: i32,
    ethertype: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    payload: &[u8],
    metadata: PacketMetadata,
) {
    let Some((peer_ns_id, peer)) = netdev::veth_peer_snapshot_by_index_in_namespace(ns_id, ifindex)
    else {
        return;
    };
    netdev::record_device_traffic_in_namespace(
        peer_ns_id,
        peer.ifindex,
        device_frame_len(&peer, payload.len()),
        false,
    );
    broadcast_packet_frame(
        peer_ns_id,
        peer.ifindex,
        ethertype,
        src_mac,
        dst_mac,
        payload,
        PACKET_HOST,
        metadata,
    );
    if ethertype == ETH_P_IP {
        netdev::record_protocol_packet_in_namespace(peer_ns_id, payload, false);
        if let Some(reply) = build_veth_local_ipv4_reply(peer_ns_id, peer.ifindex, payload) {
            deliver_veth_ipv4_reply(ns_id, ifindex, peer_ns_id, &peer, src_mac, dst_mac, &reply);
        }
    } else if ethertype == ETH_P_ARP {
        if let Some(reply) = build_veth_arp_reply(peer_ns_id, &peer, payload) {
            deliver_veth_arp_reply(ns_id, ifindex, peer_ns_id, &peer, src_mac, &reply);
        }
    }
}

fn deliver_veth_ipv4_reply(
    ns_id: usize,
    ifindex: i32,
    peer_ns_id: usize,
    peer: &netdev::NetDeviceSnapshot,
    request_src_mac: [u8; 6],
    request_dst_mac: [u8; 6],
    reply: &[u8],
) {
    netdev::record_device_traffic_in_namespace(
        peer_ns_id,
        peer.ifindex,
        device_frame_len(peer, reply.len()),
        true,
    );
    netdev::record_protocol_packet_in_namespace(peer_ns_id, reply, true);
    broadcast_packet_frame(
        peer_ns_id,
        peer.ifindex,
        ETH_P_IP,
        request_dst_mac,
        request_src_mac,
        reply,
        PACKET_OUTGOING,
        PacketMetadata::default(),
    );

    if let Some(dev) = netdev::device_snapshot_by_index_in_namespace(ns_id, ifindex) {
        netdev::record_device_traffic_in_namespace(
            ns_id,
            ifindex,
            device_frame_len(&dev, reply.len()),
            false,
        );
    }
    netdev::record_protocol_packet_in_namespace(ns_id, reply, false);
    broadcast_packet_frame(
        ns_id,
        ifindex,
        ETH_P_IP,
        request_dst_mac,
        request_src_mac,
        reply,
        PACKET_HOST,
        PacketMetadata::default(),
    );
}

fn deliver_veth_arp_reply(
    ns_id: usize,
    ifindex: i32,
    peer_ns_id: usize,
    peer: &netdev::NetDeviceSnapshot,
    request_src_mac: [u8; 6],
    reply: &[u8],
) {
    netdev::record_device_traffic_in_namespace(
        peer_ns_id,
        peer.ifindex,
        device_frame_len(peer, reply.len()),
        true,
    );
    broadcast_packet_frame(
        peer_ns_id,
        peer.ifindex,
        ETH_P_ARP,
        peer.hwaddr,
        request_src_mac,
        reply,
        PACKET_OUTGOING,
        PacketMetadata::default(),
    );

    if let Some(dev) = netdev::device_snapshot_by_index_in_namespace(ns_id, ifindex) {
        netdev::record_device_traffic_in_namespace(
            ns_id,
            ifindex,
            device_frame_len(&dev, reply.len()),
            false,
        );
    }
    broadcast_packet_frame(
        ns_id,
        ifindex,
        ETH_P_ARP,
        peer.hwaddr,
        request_src_mac,
        reply,
        PACKET_HOST,
        PacketMetadata::default(),
    );
}

fn build_veth_arp_reply(
    peer_ns_id: usize,
    peer: &netdev::NetDeviceSnapshot,
    packet: &[u8],
) -> Option<Vec<u8>> {
    const ARP_HTYPE_ETHERNET: u16 = 1;
    const ARP_OP_REQUEST: u16 = 1;
    const ARP_OP_REPLY: u16 = 2;

    if packet.len() < 28 || (peer.flags & netdev::IFF_NOARP) != 0 {
        return None;
    }
    let htype = u16::from_be_bytes([packet[0], packet[1]]);
    let ptype = u16::from_be_bytes([packet[2], packet[3]]);
    let hlen = packet[4];
    let plen = packet[5];
    let oper = u16::from_be_bytes([packet[6], packet[7]]);
    if htype != ARP_HTYPE_ETHERNET
        || ptype != ETH_P_IP
        || hlen != 6
        || plen != 4
        || oper != ARP_OP_REQUEST
    {
        return None;
    }

    let mut sender_hw = [0u8; 6];
    sender_hw.copy_from_slice(&packet[8..14]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&packet[14..18]);
    let mut target_ip = [0u8; 4];
    target_ip.copy_from_slice(&packet[24..28]);
    if !netdev::is_local_ipv4_addr_on_device_in_namespace(peer_ns_id, peer.ifindex, target_ip) {
        return None;
    }

    let mut reply = vec![0u8; 28];
    reply[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    reply[2..4].copy_from_slice(&ETH_P_IP.to_be_bytes());
    reply[4] = 6;
    reply[5] = 4;
    reply[6..8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    reply[8..14].copy_from_slice(&peer.hwaddr);
    reply[14..18].copy_from_slice(&target_ip);
    reply[18..24].copy_from_slice(&sender_hw);
    reply[24..28].copy_from_slice(&sender_ip);
    Some(reply)
}

fn build_veth_local_ipv4_reply(
    peer_ns_id: usize,
    peer_ifindex: i32,
    packet: &[u8],
) -> Option<Vec<u8>> {
    let parsed = parse_ipv4_packet(packet)?;
    if !netdev::is_local_ipv4_addr_on_device_in_namespace(peer_ns_id, peer_ifindex, parsed.dst) {
        return None;
    }
    match parsed.protocol {
        protocol if protocol == IPPROTO_ICMP as u8 => build_icmp_echo_reply(parsed),
        protocol if protocol == IPPROTO_TCP as u8 => build_tcp_closed_port_reply(parsed),
        _ => None,
    }
}

struct ParsedIpv4Packet<'a> {
    tos: u8,
    protocol: u8,
    src: [u8; 4],
    dst: [u8; 4],
    payload: &'a [u8],
}

fn parse_ipv4_packet(packet: &[u8]) -> Option<ParsedIpv4Packet<'_>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl > packet.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl || total_len > packet.len() {
        return None;
    }
    Some(ParsedIpv4Packet {
        tos: packet[1],
        protocol: packet[9],
        src: packet[12..16].try_into().ok()?,
        dst: packet[16..20].try_into().ok()?,
        payload: &packet[ihl..total_len],
    })
}

fn build_icmp_echo_reply(packet: ParsedIpv4Packet<'_>) -> Option<Vec<u8>> {
    let mut icmp = packet.payload.to_vec();
    if icmp.len() < 8 || icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    icmp[0] = 0;
    icmp[2..4].fill(0);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    build_ipv4_packet(
        Ipv4Address::from_bytes(&packet.dst),
        Ipv4Address::from_bytes(&packet.src),
        IPPROTO_ICMP as u8,
        &icmp,
        packet.tos,
        64,
        &[],
    )
    .ok()
}

fn build_tcp_closed_port_reply(packet: ParsedIpv4Packet<'_>) -> Option<Vec<u8>> {
    const TCP_FLAG_FIN: u8 = 0x01;
    const TCP_FLAG_SYN: u8 = 0x02;
    const TCP_FLAG_RST: u8 = 0x04;
    const TCP_FLAG_ACK: u8 = 0x10;

    let tcp = packet.payload;
    if tcp.len() < 20 {
        return None;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || data_offset > tcp.len() {
        return None;
    }
    let flags = tcp[13];
    if (flags & TCP_FLAG_RST) != 0 {
        return None;
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let seg_len = (tcp.len() - data_offset) as u32
        + u32::from((flags & TCP_FLAG_SYN) != 0)
        + u32::from((flags & TCP_FLAG_FIN) != 0);

    let mut reply = vec![0u8; 20];
    reply[0..2].copy_from_slice(&dst_port.to_be_bytes());
    reply[2..4].copy_from_slice(&src_port.to_be_bytes());
    if (flags & TCP_FLAG_ACK) != 0 {
        reply[4..8].copy_from_slice(&ack.to_be_bytes());
        reply[13] = TCP_FLAG_RST;
    } else {
        reply[8..12].copy_from_slice(&seq.wrapping_add(seg_len).to_be_bytes());
        reply[13] = TCP_FLAG_RST | TCP_FLAG_ACK;
    }
    reply[12] = 5 << 4;
    let checksum = tcp_ipv4_checksum(packet.dst, packet.src, &reply);
    reply[16..18].copy_from_slice(&checksum.to_be_bytes());

    build_ipv4_packet(
        Ipv4Address::from_bytes(&packet.dst),
        Ipv4Address::from_bytes(&packet.src),
        IPPROTO_TCP as u8,
        &reply,
        packet.tos,
        64,
        &[],
    )
    .ok()
}

fn tcp_ipv4_checksum(src: [u8; 4], dst: [u8; 4], tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len() + 1);
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0);
    pseudo.push(IPPROTO_TCP as u8);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    internet_checksum(&pseudo)
}

fn device_frame_len(dev: &netdev::NetDeviceSnapshot, payload_len: usize) -> usize {
    match dev.kind {
        netdev::NetDeviceKind::Tun | netdev::NetDeviceKind::Loopback => payload_len,
        _ => ETH_HDR_LEN.saturating_add(payload_len),
    }
}

/// 把 loopback 上流过的一个 IPv4 包同步到“观察路径”。
///
/// smoltcp 的回环设备本身只负责把包交给协议栈；Linux 里同一个包还会反映到
/// 网卡统计、协议统计以及 AF_PACKET/tcpdump 这类抓包 socket。这个函数负责补齐
/// 那部分可观察副作用。`outgoing = true` 表示 TX 方向，用 `PACKET_OUTGOING`；
/// `outgoing = false` 表示 RX 方向，用 `PACKET_HOST`。
pub(crate) fn observe_loopback_ip_packet_in(ns_id: usize, payload: &[u8], outgoing: bool) {
    let dev = netdev::device_snapshot_by_name_in_namespace(ns_id, "lo");
    // lo 设备尚未建模完成时退回 Linux 常见的 ifindex=1 和零 MAC，避免观察路径丢包。
    let ifindex = dev.as_ref().map(|dev| dev.ifindex).unwrap_or(1);
    let mac = dev.as_ref().map(|dev| dev.hwaddr).unwrap_or([0; 6]);
    let pkttype = if outgoing {
        PACKET_OUTGOING
    } else {
        PACKET_HOST
    };
    if !outgoing {
        // recvmsg 辅助数据需要知道 UDP 包实际从哪个 ifindex 收到。
        record_udp_ipv4_rx_metadata(ifindex, payload);
    }
    netdev::record_device_traffic_in_namespace(ns_id, ifindex, payload.len(), outgoing);
    netdev::record_protocol_packet_in_namespace(ns_id, payload, outgoing);
    broadcast_packet_frame(
        ns_id,
        ifindex,
        ETH_P_IP,
        mac,
        mac,
        payload,
        pkttype,
        PacketMetadata::default(),
    );
}

pub(crate) fn observe_tuntap_ip_packet(ns_id: usize, ifindex: i32, payload: &[u8]) {
    let Some(dev) = netdev::device_snapshot_by_index_in_namespace(ns_id, ifindex) else {
        return;
    };
    netdev::record_device_traffic_in_namespace(ns_id, ifindex, payload.len(), false);
    netdev::record_protocol_packet_in_namespace(ns_id, payload, false);
    broadcast_packet_frame(
        ns_id,
        ifindex,
        ETH_P_IP,
        dev.hwaddr,
        dev.hwaddr,
        payload,
        PACKET_HOST,
        PacketMetadata::default(),
    );
    crate::net::inject_loopback_ip_packet_in_silent(ns_id, payload);
}

pub(crate) fn observe_tuntap_ethernet_frame(ns_id: usize, ifindex: i32, frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&frame[..6]);
    src_mac.copy_from_slice(&frame[6..12]);
    let payload = &frame[14..];
    netdev::record_device_traffic_in_namespace(ns_id, ifindex, frame.len(), false);
    broadcast_packet_frame(
        ns_id,
        ifindex,
        ethertype,
        src_mac,
        dst_mac,
        payload,
        PACKET_HOST,
        PacketMetadata::default(),
    );
    if ethertype == ETH_P_IP {
        netdev::record_protocol_packet_in_namespace(ns_id, payload, false);
        crate::net::inject_loopback_ip_packet_in_silent(ns_id, payload);
    }
}

fn record_udp_ipv4_rx_metadata(ifindex: i32, packet: &[u8]) {
    let Some(meta) = parse_udp_ipv4_rx_metadata(ifindex, packet) else {
        return;
    };
    let mut queue = UDP_RX_METADATA.lock();
    if queue.len() >= UDP_RX_META_LIMIT {
        queue.pop_front();
    }
    queue.push_back(meta);
}

fn parse_udp_ipv4_rx_metadata(ifindex: i32, packet: &[u8]) -> Option<UdpIpv4RxMeta> {
    if packet.len() < 28 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if version != 4 || ihl < 20 || ihl.checked_add(8)? > packet.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl + 8 || total_len > packet.len() || packet[9] != IPPROTO_UDP as u8 {
        return None;
    }
    let udp = &packet[ihl..total_len];
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    Some(UdpIpv4RxMeta {
        ifindex,
        src: Ipv4Address::from_bytes(&packet[12..16]),
        dst: Ipv4Address::from_bytes(&packet[16..20]),
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload_len: udp_len - 8,
        ttl: packet[8],
        tos: packet[1],
    })
}

pub(crate) fn udp_ipv4_rx_info(
    local_addr: Ipv4Address,
    local_port: u16,
    remote_addr: Ipv4Address,
    remote_port: u16,
    payload_len: usize,
    peek: bool,
) -> Option<UdpIpv4RxInfo> {
    let mut queue = UDP_RX_METADATA.lock();
    let idx = queue.iter().position(|meta| {
        meta.matches(
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            payload_len,
        )
    })?;
    let info = UdpIpv4RxInfo {
        ifindex: queue[idx].ifindex,
        dst: queue[idx].dst,
        ttl: queue[idx].ttl,
        tos: queue[idx].tos,
    };
    if !peek {
        queue.remove(idx);
    }
    Some(info)
}

fn packet_socket_snapshot_in(ns_id: usize) -> Vec<Arc<PacketSocketFile>> {
    let mut live = Vec::new();
    PACKET_SOCKETS.lock().retain(|weak| {
        let Some(sock) = weak.upgrade() else {
            return false;
        };
        if sock.net_ns_id == ns_id {
            live.push(sock);
        }
        true
    });
    live
}

fn packet_socket_snapshot_all() -> Vec<Arc<PacketSocketFile>> {
    let mut live = Vec::new();
    PACKET_SOCKETS.lock().retain(|weak| {
        let Some(sock) = weak.upgrade() else {
            return false;
        };
        live.push(sock);
        true
    });
    live
}

/// Clear AF_PACKET mmap ring registrations that overlap a successfully
/// unmapped VMA range. Linux packet sockets receive this through VMA close
/// callbacks; this kernel has no VMA file operations, so mmap/munmap/mremap
/// and mm teardown paths call here explicitly.
pub(crate) fn clear_packet_ring_mmaps_for_range(token: usize, start: usize, end: usize) {
    if start >= end {
        return;
    }
    for sock in packet_socket_snapshot_all() {
        sock.clear_packet_ring_mmap_range(token, start, end);
    }
}

/// Clear all AF_PACKET mmap ring registrations backed by a disappearing mm.
pub(crate) fn clear_packet_ring_mmaps_for_token(token: usize) {
    for sock in packet_socket_snapshot_all() {
        sock.clear_packet_ring_mmap_token(token);
    }
}

/// Mirror AF_PACKET mmap ring registrations into a freshly forked mm.
///
/// Linux packet_mmap() tracks this through `vm_ops.open`; our VMA layer has no
/// file callbacks, so fork explicitly mirrors the userspace mapping metadata.
pub(crate) fn clone_packet_ring_mmaps_for_fork(parent_token: usize, child_token: usize) {
    if parent_token == child_token {
        return;
    }
    for sock in packet_socket_snapshot_all() {
        sock.clone_packet_ring_mmap_token(parent_token, child_token);
    }
}

/// Whether a user VMA range still backs any AF_PACKET mmap ring.
///
/// Linux stores packet ring lifetime in VMA open/close callbacks. Until this
/// kernel grows file-backed VMA ops, callers that move or resize VMAs must use
/// this check to avoid reporting success while the socket still points at the
/// old userspace address.
pub(crate) fn packet_ring_mmap_overlaps_range(token: usize, start: usize, end: usize) -> bool {
    if start >= end {
        return false;
    }
    packet_socket_snapshot_all()
        .into_iter()
        .any(|sock| sock.packet_ring_mmap_range_overlaps(token, start, end))
}

fn raw_socket_snapshot_in(ns_id: usize) -> Vec<Arc<RawSocketFile>> {
    let mut live = Vec::new();
    RAW_SOCKETS.lock().retain(|weak| {
        let Some(sock) = weak.upgrade() else {
            return false;
        };
        if sock.net_ns_id == ns_id {
            live.push(sock);
        }
        true
    });
    live
}

pub(super) fn cleanup_net_namespace(ns_id: usize) {
    PACKET_SOCKETS
        .lock()
        .retain(|weak| weak.upgrade().is_some_and(|sock| sock.net_ns_id() != ns_id));
    RAW_SOCKETS
        .lock()
        .retain(|weak| weak.upgrade().is_some_and(|sock| sock.net_ns_id() != ns_id));
    PACKET_FANOUT_COUNTERS
        .lock()
        .retain(|counter| counter.key.net_ns_id != ns_id);
}

fn ping_ident_conflicts(
    this: *const RawSocketFile,
    ns_id: usize,
    ident: u16,
    reuseaddr: bool,
) -> bool {
    raw_socket_snapshot_in(ns_id).into_iter().any(|sock| {
        if Arc::as_ptr(&sock) == this {
            return false;
        }
        if sock.socket_type != SOCK_DGRAM || sock.protocol != IPPROTO_ICMP {
            return false;
        }
        let state = sock.state.lock();
        state.local_port == ident && (!state.reuseaddr || !reuseaddr)
    })
}

fn next_free_ping_ident(
    this: *const RawSocketFile,
    ns_id: usize,
    reuseaddr: bool,
    rover: &mut u16,
) -> Option<u16> {
    let mut ident = rover.wrapping_add(1);
    for _ in 0..u16::MAX {
        if ident == 0 {
            ident = 1;
        }
        if !ping_ident_conflicts(this, ns_id, ident, reuseaddr) {
            *rover = ident;
            return Some(ident);
        }
        ident = ident.wrapping_add(1);
    }
    None
}

fn broadcast_raw_ipv4_packet(
    ns_id: usize,
    ifindex: i32,
    payload: &[u8],
    pkttype: u8,
    metadata: PacketMetadata,
) {
    for sock in raw_socket_snapshot_in(ns_id) {
        sock.enqueue_observed_ipv4_packet(ifindex, payload, pkttype, metadata);
    }
}

fn allocate_packet_fanout_id(ns_id: usize) -> Option<u16> {
    let mut next = PACKET_FANOUT_NEXT_ID.lock();
    let start = *next;
    let mut id = start;
    loop {
        if packet_fanout_id_is_free(ns_id, id) {
            *next = id.wrapping_add(1);
            return Some(id);
        }
        id = id.wrapping_add(1);
        if id == start {
            return None;
        }
    }
}

fn packet_fanout_id_is_free(ns_id: usize, id: u16) -> bool {
    packet_socket_snapshot_in(ns_id).into_iter().all(|sock| {
        sock.state
            .lock()
            .fanout
            .is_none_or(|fanout| fanout.key.id != id)
    })
}

fn add_fanout_candidate(
    groups: &mut Vec<PacketFanoutGroup>,
    key: PacketFanoutKey,
    sock: Arc<PacketSocketFile>,
) {
    if let Some(group) = groups.iter_mut().find(|group| group.key == key) {
        group.sockets.push(sock);
    } else {
        groups.push(PacketFanoutGroup {
            key,
            sockets: vec![sock],
        });
    }
}

fn select_fanout_member(
    key: PacketFanoutKey,
    ifindex: i32,
    ethertype: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    payload: &[u8],
    count: usize,
) -> usize {
    match key.mode as u32 {
        PACKET_FANOUT_HASH => {
            packet_fanout_hash(ifindex, ethertype, src_mac, dst_mac, payload) as usize % count
        }
        PACKET_FANOUT_LB => packet_fanout_next(key, count),
        PACKET_FANOUT_CPU => crate::task::processor::hart_id() % count,
        PACKET_FANOUT_RND => packet_fanout_random(count),
        PACKET_FANOUT_ROLLOVER => 0,
        _ => 0,
    }
}

fn select_rollover_member(sockets: &[Arc<PacketSocketFile>], start: usize) -> usize {
    if sockets.is_empty() {
        return 0;
    }
    let count = sockets.len();
    for off in 0..count {
        let idx = (start + off) % count;
        if !sockets[idx].recv_queue_full() {
            return idx;
        }
    }
    start % count
}

fn packet_fanout_random(count: usize) -> usize {
    if count == 0 {
        return 0;
    }
    (crate::time::get_time_ns() as usize) % count
}

fn packet_fanout_next(key: PacketFanoutKey, count: usize) -> usize {
    let mut counters = PACKET_FANOUT_COUNTERS.lock();
    if let Some(counter) = counters.iter_mut().find(|counter| counter.key == key) {
        let idx = counter.next as usize % count;
        counter.next = counter.next.wrapping_add(1);
        return idx;
    }
    counters.push(PacketFanoutCounter { key, next: 1 });
    0
}

fn packet_fanout_hash(
    ifindex: i32,
    ethertype: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    payload: &[u8],
) -> u32 {
    fn mix(hash: &mut u32, byte: u8) {
        *hash ^= byte as u32;
        *hash = hash.wrapping_mul(16_777_619);
    }

    let mut hash = 2_166_136_261u32;
    for byte in ifindex.to_ne_bytes() {
        mix(&mut hash, byte);
    }
    for byte in ethertype.to_be_bytes() {
        mix(&mut hash, byte);
    }
    for byte in src_mac {
        mix(&mut hash, byte);
    }
    for byte in dst_mac {
        mix(&mut hash, byte);
    }
    for byte in payload {
        mix(&mut hash, *byte);
    }
    hash
}

fn icmp_echo_identifier_matches(icmp: &[u8], ident: u16) -> bool {
    icmp.len() >= 8 && u16::from_be_bytes([icmp[4], icmp[5]]) == ident
}

fn prepare_ping_payload(payload: &[u8], ident: u16) -> Result<Vec<u8>, isize> {
    if payload.len() < 8 || payload[0] != 8 || payload[1] != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    let mut packet = payload.to_vec();
    packet[2..4].fill(0);
    if ident != 0 {
        packet[4..6].copy_from_slice(&ident.to_be_bytes());
    }
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

impl File for PacketSocketFile {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let cap = buf.len();
        if cap == 0 {
            return 0;
        }
        loop {
            if let Some(packet) = self.recv_packet(false) {
                let total = core::cmp::min(cap, packet.data.len());
                return buf.copy_from_slice(&packet.data[..total]);
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        let data = copy_user_buffer_to_vec(buf);
        if data.is_empty() {
            return 0;
        }
        let len = data.len();
        match self.handle_outbound_packet(&data, None, self.packet_metadata()) {
            Ok(()) => len,
            Err(e) => {
                self.set_socket_error(e);
                0
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn poll_mask(&self) -> i16 {
        let pending_error = self.state.lock().pending_error != 0;
        let mut mask = POLLOUT;
        if pending_error {
            mask |= POLLERR;
        }
        if self.materialize_rx_ring_frame() || self.poll_readable() {
            mask |= POLLIN;
        }
        mask
    }
}

fn ipv4_octets(ip: Ipv4Address) -> [u8; 4] {
    let bytes = ip.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

/// 轻量 AF_INET raw socket。
///
/// 当前覆盖 LTP 使用的 IGMP 发送、traceroute ICMP echo/TCP SYN 探测等
/// Linux ABI 路径；不是完整 IP 协议栈。
pub(crate) struct RawSocketFile {
    socket_type: usize,
    protocol: usize,
    net_ns_id: usize,
    proc_inode: u64,
    proc_uid: u32,
    state: Mutex<RawSocketState>,
}

#[derive(Clone)]
struct RawSocketState {
    local_addr: Option<Ipv4Address>,
    local_port: u16,
    remote_addr: Option<Ipv4Address>,
    bound_ifindex: i32,
    reuseaddr: bool,
    dontroute: bool,
    broadcast: bool,
    keepalive: bool,
    sndbuf: u32,
    rcvbuf: u32,
    oobinline: bool,
    priority: u32,
    mark: u32,
    rcvmark: bool,
    rcvpriority: bool,
    linger_on: bool,
    linger_sec: i32,
    rcvlowat: i32,
    ip_hdrincl: bool,
    ip_options: Vec<u8>,
    ip_tos: u8,
    ip_ttl: i32,
    ip_pmtudisc: i32,
    ip_pktinfo: bool,
    ip_recverr: bool,
    ip_recvttl: bool,
    ip_recvtos: bool,
    mcast_ifindex: i32,
    mcast_ifaddr: [u8; 4],
    mcast_ttl: u8,
    mcast_loop: bool,
    mcast_memberships: Vec<RawIpv4MulticastMembership>,
    filter_locked: bool,
    filter: Option<ClassicBpfProgram>,
    ebpf_filter: Option<Arc<BpfProgFile>>,
    recv_queue: VecDeque<RawPacket>,
    error_queue: VecDeque<Ipv4ErrorQueueEntry>,
    pending_error: i32,
    timestamp_mode: SocketTimestampMode,
    last_timestamp: Option<SocketTimestamp>,
    rcvtimeo_ms: Option<usize>,
    sndtimeo_ms: Option<usize>,
    rd_shutdown: bool,
    wr_shutdown: bool,
}

impl Default for RawSocketState {
    fn default() -> Self {
        Self {
            local_addr: None,
            local_port: 0,
            remote_addr: None,
            bound_ifindex: 0,
            reuseaddr: false,
            dontroute: false,
            broadcast: false,
            keepalive: false,
            sndbuf: DEFAULT_SOCKBUF,
            rcvbuf: DEFAULT_SOCKBUF,
            oobinline: false,
            priority: 0,
            mark: 0,
            rcvmark: false,
            rcvpriority: false,
            linger_on: false,
            linger_sec: 0,
            rcvlowat: 1,
            ip_hdrincl: false,
            ip_options: Vec::new(),
            ip_tos: 0,
            ip_ttl: 64,
            ip_pmtudisc: IP_PMTUDISC_WANT,
            ip_pktinfo: false,
            ip_recverr: false,
            ip_recvttl: false,
            ip_recvtos: false,
            mcast_ifindex: 0,
            mcast_ifaddr: [0; 4],
            mcast_ttl: 1,
            mcast_loop: true,
            mcast_memberships: Vec::new(),
            filter_locked: false,
            filter: None,
            ebpf_filter: None,
            recv_queue: VecDeque::new(),
            error_queue: VecDeque::new(),
            pending_error: 0,
            timestamp_mode: SocketTimestampMode::Off,
            last_timestamp: None,
            rcvtimeo_ms: None,
            sndtimeo_ms: None,
            rd_shutdown: false,
            wr_shutdown: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawIpv4SourceFilterMode {
    Exclude,
    Include,
}

#[derive(Clone)]
struct RawIpv4MulticastMembership {
    group: [u8; 4],
    ifindex: i32,
    ifaddr: [u8; 4],
    filter_mode: RawIpv4SourceFilterMode,
    sources: Vec<[u8; 4]>,
}

#[derive(Clone)]
pub(crate) struct RawPacket {
    pub(crate) from: Ipv4Address,
    pub(crate) ifindex: i32,
    pub(crate) dst: Ipv4Address,
    pub(crate) ttl: u8,
    pub(crate) tos: u8,
    pub(crate) metadata: PacketMetadata,
    pub(crate) data: Vec<u8>,
}

impl RawSocketFile {
    fn new(socket_type: usize, protocol: usize) -> Arc<Self> {
        let process = current_process();
        let net_ns_id = process.acquire_net_namespace_for_socket();
        let proc_uid = process.borrow_mut().euid;
        let sock = Arc::new(Self {
            socket_type,
            protocol,
            net_ns_id,
            proc_inode: alloc_socket_inode(),
            proc_uid,
            state: Mutex::new(RawSocketState {
                ip_hdrincl: protocol == IPPROTO_RAW,
                ..RawSocketState::default()
            }),
        });
        RAW_SOCKETS.lock().push(Arc::downgrade(&sock));
        sock
    }

    fn device_snapshot_by_index(&self, ifindex: i32) -> Option<netdev::NetDeviceSnapshot> {
        netdev::device_snapshot_by_index_in_namespace(self.net_ns_id, ifindex)
    }

    pub(crate) fn net_ns_id(&self) -> usize {
        self.net_ns_id
    }

    pub(crate) fn protocol(&self) -> usize {
        self.protocol
    }

    pub(crate) fn proc_inode(&self) -> u64 {
        self.proc_inode
    }

    pub(crate) fn proc_uid(&self) -> u32 {
        self.proc_uid
    }

    pub(crate) fn proc_queue_lengths(&self) -> (usize, usize) {
        let state = self.state.lock();
        let rx_queue = state
            .recv_queue
            .iter()
            .fold(0usize, |acc, packet| acc.saturating_add(packet.data.len()));
        (0, rx_queue)
    }

    pub(crate) fn socket_type(&self) -> usize {
        self.socket_type
    }

    pub(super) fn attach_filter(&self, filter: ClassicBpfProgram) -> isize {
        let mut state = self.state.lock();
        if state.filter_locked {
            return err(SyscallError::EPERM);
        }
        state.filter = Some(filter);
        state.ebpf_filter = None;
        0
    }

    pub(super) fn attach_bpf(&self, filter: Arc<BpfProgFile>) -> isize {
        let mut state = self.state.lock();
        if state.filter_locked {
            return err(SyscallError::EPERM);
        }
        state.filter = None;
        state.ebpf_filter = Some(filter);
        0
    }

    pub(super) fn detach_filter(&self) -> isize {
        let mut state = self.state.lock();
        if state.filter_locked {
            return err(SyscallError::EPERM);
        }
        let had_filter = state.filter.take().is_some() | state.ebpf_filter.take().is_some();
        if had_filter {
            0
        } else {
            err(SyscallError::ENOENT)
        }
    }

    pub(super) fn set_filter_locked(&self, locked: bool) -> isize {
        let mut state = self.state.lock();
        if state.filter_locked && !locked {
            return err(SyscallError::EPERM);
        }
        state.filter_locked = locked;
        0
    }

    pub(super) fn filter_locked(&self) -> bool {
        self.state.lock().filter_locked
    }

    pub(super) fn classic_filter_snapshot(&self) -> (Option<ClassicBpfProgram>, bool) {
        let state = self.state.lock();
        (state.filter.clone(), state.ebpf_filter.is_some())
    }

    fn bind_v4(&self, ip: Ipv4Address, port: u16) -> isize {
        if self.socket_type == SOCK_DGRAM && self.protocol == IPPROTO_ICMP {
            return self.bind_ping_v4(ip, port);
        }
        let mut state = self.state.lock();
        state.local_addr = if ip == Ipv4Address::UNSPECIFIED {
            None
        } else {
            Some(ip)
        };
        0
    }

    fn bind_ping_v4(&self, ip: Ipv4Address, port: u16) -> isize {
        let this = self as *const RawSocketFile;
        let mut rover = PING_IDENT_ROVER.lock();
        let (already_bound, reuseaddr) = {
            let state = self.state.lock();
            (state.local_port != 0, state.reuseaddr)
        };
        if already_bound {
            return err(SyscallError::EINVAL);
        }

        let ident = if port == 0 {
            let Some(ident) = next_free_ping_ident(this, self.net_ns_id, reuseaddr, &mut rover)
            else {
                return err(SyscallError::EADDRINUSE);
            };
            ident
        } else {
            if ping_ident_conflicts(this, self.net_ns_id, port, reuseaddr) {
                return err(SyscallError::EADDRINUSE);
            }
            port
        };

        let mut state = self.state.lock();
        state.local_addr = if ip == Ipv4Address::UNSPECIFIED {
            None
        } else {
            Some(ip)
        };
        state.local_port = ident;
        0
    }

    fn connect_v4(&self, ip: Ipv4Address) -> isize {
        self.state.lock().remote_addr = if ip == Ipv4Address::UNSPECIFIED {
            None
        } else {
            Some(ip)
        };
        0
    }

    pub(crate) fn bind_to_device_name(&self, name: &str) -> isize {
        if name.is_empty() {
            self.state.lock().bound_ifindex = 0;
            return 0;
        }
        let Some(ifindex) = netdev::ifindex_by_name_in_namespace(self.net_ns_id, name) else {
            return err(SyscallError::ENODEV);
        };
        self.state.lock().bound_ifindex = ifindex;
        0
    }

    pub(crate) fn bound_device_name(&self) -> Option<alloc::string::String> {
        let ifindex = self.state.lock().bound_ifindex;
        (ifindex > 0)
            .then(|| netdev::name_by_ifindex_in_namespace(self.net_ns_id, ifindex))
            .flatten()
    }

    pub(crate) fn set_reuseaddr(&self, enabled: bool) {
        self.state.lock().reuseaddr = enabled;
    }

    pub(crate) fn reuseaddr(&self) -> bool {
        self.state.lock().reuseaddr
    }

    pub(crate) fn set_dontroute(&self, enabled: bool) {
        self.state.lock().dontroute = enabled;
    }

    pub(crate) fn dontroute(&self) -> bool {
        self.state.lock().dontroute
    }

    pub(crate) fn set_broadcast(&self, enabled: bool) {
        self.state.lock().broadcast = enabled;
    }

    pub(crate) fn broadcast(&self) -> bool {
        self.state.lock().broadcast
    }

    pub(crate) fn set_keepalive(&self, enabled: bool) {
        self.state.lock().keepalive = enabled;
    }

    pub(crate) fn keepalive(&self) -> bool {
        self.state.lock().keepalive
    }

    pub(crate) fn set_sockbuf(&self, sndbuf: Option<u32>, rcvbuf: Option<u32>) {
        let mut state = self.state.lock();
        if let Some(v) = sndbuf {
            state.sndbuf = v;
        }
        if let Some(v) = rcvbuf {
            state.rcvbuf = v;
        }
    }

    pub(crate) fn getsockopt_sndbuf(&self) -> u32 {
        self.state.lock().sndbuf
    }

    pub(crate) fn getsockopt_rcvbuf(&self) -> u32 {
        self.state.lock().rcvbuf
    }

    pub(crate) fn set_oobinline(&self, enabled: bool) {
        self.state.lock().oobinline = enabled;
    }

    pub(crate) fn oobinline(&self) -> bool {
        self.state.lock().oobinline
    }

    pub(crate) fn set_priority(&self, priority: u32) {
        self.state.lock().priority = priority;
    }

    pub(crate) fn priority(&self) -> u32 {
        self.state.lock().priority
    }

    pub(crate) fn set_mark(&self, mark: u32) {
        self.state.lock().mark = mark;
    }

    pub(crate) fn mark(&self) -> u32 {
        self.state.lock().mark
    }

    pub(crate) fn packet_metadata(&self) -> PacketMetadata {
        let state = self.state.lock();
        PacketMetadata {
            mark: state.mark,
            priority: state.priority,
            orig_ifindex: 0,
        }
    }

    pub(crate) fn set_rcvmark(&self, enabled: bool) {
        self.state.lock().rcvmark = enabled;
    }

    pub(crate) fn rcvmark(&self) -> bool {
        self.state.lock().rcvmark
    }

    pub(crate) fn set_rcvpriority(&self, enabled: bool) {
        self.state.lock().rcvpriority = enabled;
    }

    pub(crate) fn rcvpriority(&self) -> bool {
        self.state.lock().rcvpriority
    }

    pub(crate) fn set_linger(&self, on: bool, sec: i32) {
        let mut state = self.state.lock();
        state.linger_on = on;
        state.linger_sec = sec;
    }

    pub(crate) fn linger(&self) -> (bool, i32) {
        let state = self.state.lock();
        (state.linger_on, state.linger_sec)
    }

    pub(crate) fn set_rcvlowat(&self, value: i32) {
        self.state.lock().rcvlowat = value;
    }

    pub(crate) fn rcvlowat(&self) -> i32 {
        self.state.lock().rcvlowat
    }

    pub(super) fn set_rcvtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.state.lock().rcvtimeo_ms = timeout_ms;
    }

    pub(super) fn rcvtimeo_ms(&self) -> Option<usize> {
        self.state.lock().rcvtimeo_ms
    }

    pub(super) fn rcvtimeo_deadline_ms(&self) -> Option<usize> {
        self.rcvtimeo_ms()
            .map(|ms| crate::time::get_time_ms().saturating_add(ms))
    }

    pub(super) fn set_sndtimeo_ms(&self, timeout_ms: Option<usize>) {
        self.state.lock().sndtimeo_ms = timeout_ms;
    }

    pub(super) fn sndtimeo_ms(&self) -> Option<usize> {
        self.state.lock().sndtimeo_ms
    }

    pub(crate) fn local_addr_v4(&self) -> Ipv4Address {
        self.state
            .lock()
            .local_addr
            .unwrap_or(Ipv4Address::UNSPECIFIED)
    }

    pub(crate) fn remote_addr_v4(&self) -> Option<Ipv4Address> {
        self.state.lock().remote_addr
    }

    pub(crate) fn set_ip_hdrincl(&self, enabled: bool) {
        self.state.lock().ip_hdrincl = enabled;
    }

    pub(crate) fn ip_hdrincl(&self) -> bool {
        self.state.lock().ip_hdrincl
    }

    pub(crate) fn set_ipv4_options(&self, options: Vec<u8>) -> isize {
        self.state.lock().ip_options = options;
        0
    }

    pub(crate) fn ipv4_options(&self) -> Vec<u8> {
        self.state.lock().ip_options.clone()
    }

    pub(crate) fn set_ipv4_tos(&self, tos: i32) {
        self.state.lock().ip_tos = tos as u8;
    }

    pub(crate) fn ipv4_tos(&self) -> u32 {
        self.state.lock().ip_tos as u32
    }

    pub(crate) fn set_ipv4_ttl(&self, ttl: i32) {
        self.state.lock().ip_ttl = ttl;
    }

    pub(crate) fn ipv4_ttl(&self) -> i32 {
        self.state.lock().ip_ttl
    }

    pub(crate) fn set_ipv4_mtu_discover(&self, value: i32) {
        self.state.lock().ip_pmtudisc = value;
    }

    pub(crate) fn ipv4_mtu_discover(&self) -> i32 {
        self.state.lock().ip_pmtudisc
    }

    pub(crate) fn ipv4_path_mtu(&self) -> Option<u32> {
        let state = self.state.lock();
        netdev::ipv4_path_mtu_in_namespace(
            self.net_ns_id,
            state.bound_ifindex,
            state.local_addr.map(ipv4_octets),
            state.remote_addr.map(ipv4_octets),
        )
    }

    pub(crate) fn set_ipv4_recverr(&self, enabled: bool) {
        let mut state = self.state.lock();
        state.ip_recverr = enabled;
        if !enabled {
            state.error_queue.clear();
        }
    }

    pub(crate) fn ipv4_recverr(&self) -> bool {
        self.state.lock().ip_recverr
    }

    pub(crate) fn pop_ipv4_error_queue(&self) -> Option<Ipv4ErrorQueueEntry> {
        self.state.lock().error_queue.pop_front()
    }

    pub(crate) fn set_ipv4_pktinfo(&self, enabled: bool) {
        self.state.lock().ip_pktinfo = enabled;
    }

    pub(crate) fn ipv4_pktinfo(&self) -> bool {
        self.state.lock().ip_pktinfo
    }

    pub(crate) fn set_ipv4_recvttl(&self, enabled: bool) {
        self.state.lock().ip_recvttl = enabled;
    }

    pub(crate) fn ipv4_recvttl(&self) -> bool {
        self.state.lock().ip_recvttl
    }

    pub(crate) fn set_ipv4_recvtos(&self, enabled: bool) {
        self.state.lock().ip_recvtos = enabled;
    }

    pub(crate) fn ipv4_recvtos(&self) -> bool {
        self.state.lock().ip_recvtos
    }

    fn resolve_ipv4_multicast_if(
        &self,
        requested_ifindex: i32,
        requested_addr: [u8; 4],
    ) -> Result<(i32, [u8; 4]), isize> {
        if requested_ifindex < 0 {
            return Err(err(SyscallError::EINVAL));
        }
        if requested_ifindex > 0 {
            if self.device_snapshot_by_index(requested_ifindex).is_none() {
                return Err(err(SyscallError::EADDRNOTAVAIL));
            }
            return Ok((requested_ifindex, requested_addr));
        }
        if requested_addr != [0; 4] {
            let Some(ifindex) =
                netdev::ifindex_by_ipv4_addr_in_namespace(self.net_ns_id, requested_addr)
            else {
                return Err(err(SyscallError::EADDRNOTAVAIL));
            };
            return Ok((ifindex, requested_addr));
        }
        let state = self.state.lock();
        if state.mcast_ifindex > 0 {
            return Ok((state.mcast_ifindex, state.mcast_ifaddr));
        }
        drop(state);
        let Some(ifindex) = netdev::default_ipv4_ifindex_in_namespace(self.net_ns_id) else {
            return Err(err(SyscallError::EADDRNOTAVAIL));
        };
        let addr = netdev::primary_ipv4_addr_by_ifindex_in_namespace(self.net_ns_id, ifindex)
            .unwrap_or([0; 4]);
        Ok((ifindex, addr))
    }

    pub(crate) fn set_ipv4_multicast_if(&self, ifindex: i32, addr: [u8; 4]) -> isize {
        if ifindex == 0 && addr == [0; 4] {
            let mut state = self.state.lock();
            state.mcast_ifindex = 0;
            state.mcast_ifaddr = [0; 4];
            return 0;
        }
        let (ifindex, addr) = match self.resolve_ipv4_multicast_if(ifindex, addr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut state = self.state.lock();
        if state.bound_ifindex > 0 && state.bound_ifindex != ifindex {
            return err(SyscallError::EINVAL);
        }
        state.mcast_ifindex = ifindex;
        state.mcast_ifaddr = addr;
        0
    }

    pub(crate) fn ipv4_multicast_if_addr(&self) -> [u8; 4] {
        self.state.lock().mcast_ifaddr
    }

    pub(crate) fn set_ipv4_multicast_ttl(&self, ttl: u8) {
        self.state.lock().mcast_ttl = ttl;
    }

    pub(crate) fn ipv4_multicast_ttl(&self) -> u8 {
        self.state.lock().mcast_ttl
    }

    pub(crate) fn set_ipv4_multicast_loop(&self, enabled: bool) {
        self.state.lock().mcast_loop = enabled;
    }

    pub(crate) fn ipv4_multicast_loop(&self) -> bool {
        self.state.lock().mcast_loop
    }

    pub(crate) fn join_ipv4_multicast(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
    ) -> isize {
        if !netdev::ipv4_is_multicast_addr(group) {
            return err(SyscallError::EINVAL);
        }
        let (ifindex, ifaddr) = match self.resolve_ipv4_multicast_if(ifindex, ifaddr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        {
            let state = self.state.lock();
            if state
                .mcast_memberships
                .iter()
                .any(|entry| entry.group == group && entry.ifindex == ifindex)
            {
                return err(SyscallError::EADDRINUSE);
            }
        }
        if let Err(e) = netdev::add_maddr(ifindex, netdev::ipv4_multicast_mac(group)) {
            return e;
        }
        self.state
            .lock()
            .mcast_memberships
            .push(RawIpv4MulticastMembership {
                group,
                ifindex,
                ifaddr,
                filter_mode: RawIpv4SourceFilterMode::Exclude,
                sources: Vec::new(),
            });
        0
    }

    pub(crate) fn join_ipv4_multicast_source(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        source: [u8; 4],
    ) -> isize {
        if !netdev::ipv4_is_multicast_addr(group) {
            return err(SyscallError::EINVAL);
        }
        let (ifindex, ifaddr) = match self.resolve_ipv4_multicast_if(ifindex, ifaddr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut state = self.state.lock();
        if let Some(entry) = state
            .mcast_memberships
            .iter_mut()
            .find(|entry| entry.group == group && entry.ifindex == ifindex)
        {
            if entry.filter_mode != RawIpv4SourceFilterMode::Include && !entry.sources.is_empty() {
                return err(SyscallError::EINVAL);
            }
            if entry.sources.contains(&source) {
                return err(SyscallError::EADDRNOTAVAIL);
            }
            entry.filter_mode = RawIpv4SourceFilterMode::Include;
            entry.sources.push(source);
            return 0;
        }
        drop(state);

        if let Err(e) = netdev::add_maddr(ifindex, netdev::ipv4_multicast_mac(group)) {
            return e;
        }
        self.state
            .lock()
            .mcast_memberships
            .push(RawIpv4MulticastMembership {
                group,
                ifindex,
                ifaddr,
                filter_mode: RawIpv4SourceFilterMode::Include,
                sources: vec![source],
            });
        0
    }

    pub(crate) fn leave_ipv4_multicast_source(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        source: [u8; 4],
    ) -> isize {
        let resolved = self.resolve_ipv4_multicast_if(ifindex, ifaddr).ok();
        let mut state = self.state.lock();
        let Some(pos) = state.mcast_memberships.iter().position(|entry| {
            if entry.group != group {
                return false;
            }
            if let Some((resolved_ifindex, resolved_addr)) = resolved {
                if ifindex > 0 {
                    return entry.ifindex == resolved_ifindex;
                }
                if ifaddr != [0; 4] {
                    return entry.ifaddr == resolved_addr;
                }
            }
            true
        }) else {
            return err(SyscallError::EADDRNOTAVAIL);
        };
        if state.mcast_memberships[pos].filter_mode != RawIpv4SourceFilterMode::Include {
            return err(SyscallError::EINVAL);
        }
        let Some(src_pos) = state.mcast_memberships[pos]
            .sources
            .iter()
            .position(|addr| *addr == source)
        else {
            return err(SyscallError::EADDRNOTAVAIL);
        };
        if state.mcast_memberships[pos].sources.len() == 1 {
            let entry = state.mcast_memberships.remove(pos);
            drop(state);
            let _ = netdev::del_maddr(entry.ifindex, netdev::ipv4_multicast_mac(entry.group));
        } else {
            state.mcast_memberships[pos].sources.remove(src_pos);
        }
        0
    }

    pub(crate) fn block_ipv4_multicast_source(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        source: [u8; 4],
    ) -> isize {
        if !netdev::ipv4_is_multicast_addr(group) {
            return err(SyscallError::EINVAL);
        }
        let resolved = self.resolve_ipv4_multicast_if(ifindex, ifaddr).ok();
        let mut state = self.state.lock();
        let Some(entry) = state.mcast_memberships.iter_mut().find(|entry| {
            if entry.group != group {
                return false;
            }
            if let Some((resolved_ifindex, resolved_addr)) = resolved {
                if ifindex > 0 {
                    return entry.ifindex == resolved_ifindex;
                }
                if ifaddr != [0; 4] {
                    return entry.ifaddr == resolved_addr;
                }
            }
            true
        }) else {
            return err(SyscallError::EINVAL);
        };
        if entry.filter_mode != RawIpv4SourceFilterMode::Exclude && !entry.sources.is_empty() {
            return err(SyscallError::EINVAL);
        }
        if entry.sources.contains(&source) {
            return err(SyscallError::EADDRNOTAVAIL);
        }
        entry.filter_mode = RawIpv4SourceFilterMode::Exclude;
        entry.sources.push(source);
        0
    }

    pub(crate) fn unblock_ipv4_multicast_source(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        source: [u8; 4],
    ) -> isize {
        let resolved = self.resolve_ipv4_multicast_if(ifindex, ifaddr).ok();
        let mut state = self.state.lock();
        let Some(entry) = state.mcast_memberships.iter_mut().find(|entry| {
            if entry.group != group {
                return false;
            }
            if let Some((resolved_ifindex, resolved_addr)) = resolved {
                if ifindex > 0 {
                    return entry.ifindex == resolved_ifindex;
                }
                if ifaddr != [0; 4] {
                    return entry.ifaddr == resolved_addr;
                }
            }
            true
        }) else {
            return err(SyscallError::EADDRNOTAVAIL);
        };
        if entry.filter_mode != RawIpv4SourceFilterMode::Exclude && !entry.sources.is_empty() {
            return err(SyscallError::EINVAL);
        }
        let Some(src_pos) = entry.sources.iter().position(|addr| *addr == source) else {
            return err(SyscallError::EADDRNOTAVAIL);
        };
        entry.filter_mode = RawIpv4SourceFilterMode::Exclude;
        entry.sources.remove(src_pos);
        0
    }

    pub(crate) fn set_ipv4_multicast_source_filter(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
        mode: RawIpv4SourceFilterMode,
        sources: Vec<[u8; 4]>,
    ) -> isize {
        if !netdev::ipv4_is_multicast_addr(group) {
            return err(SyscallError::EINVAL);
        }
        if mode == RawIpv4SourceFilterMode::Include && sources.is_empty() {
            return self.leave_ipv4_multicast(group, ifindex, ifaddr);
        }
        let (resolved_ifindex, resolved_addr) =
            match self.resolve_ipv4_multicast_if(ifindex, ifaddr) {
                Ok(v) => v,
                Err(e) => return e,
            };
        let mut state = self.state.lock();
        let Some(entry) = state
            .mcast_memberships
            .iter_mut()
            .find(|entry| entry.group == group && entry.ifindex == resolved_ifindex)
        else {
            return err(SyscallError::EINVAL);
        };
        if ifaddr != [0; 4] && entry.ifaddr != resolved_addr {
            return err(SyscallError::EADDRNOTAVAIL);
        }
        entry.filter_mode = mode;
        entry.sources = sources;
        0
    }

    pub(crate) fn ipv4_multicast_source_filter(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
    ) -> Result<(RawIpv4SourceFilterMode, Vec<[u8; 4]>), isize> {
        if !netdev::ipv4_is_multicast_addr(group) {
            return Err(err(SyscallError::EINVAL));
        }
        let (resolved_ifindex, resolved_addr) = self.resolve_ipv4_multicast_if(ifindex, ifaddr)?;
        let state = self.state.lock();
        let Some(entry) = state
            .mcast_memberships
            .iter()
            .find(|entry| entry.group == group && entry.ifindex == resolved_ifindex)
        else {
            return Err(err(SyscallError::EADDRNOTAVAIL));
        };
        if ifaddr != [0; 4] && entry.ifaddr != resolved_addr {
            return Err(err(SyscallError::EADDRNOTAVAIL));
        }
        Ok((entry.filter_mode, entry.sources.clone()))
    }

    fn multicast_source_allowed(&self, ifindex: i32, group: [u8; 4], source: [u8; 4]) -> bool {
        let state = self.state.lock();
        let Some(entry) = state
            .mcast_memberships
            .iter()
            .find(|entry| entry.group == group && entry.ifindex == ifindex)
        else {
            return true;
        };
        match entry.filter_mode {
            RawIpv4SourceFilterMode::Exclude => !entry.sources.contains(&source),
            RawIpv4SourceFilterMode::Include => entry.sources.contains(&source),
        }
    }

    pub(crate) fn leave_ipv4_multicast(
        &self,
        group: [u8; 4],
        ifindex: i32,
        ifaddr: [u8; 4],
    ) -> isize {
        let resolved = self.resolve_ipv4_multicast_if(ifindex, ifaddr).ok();
        let mut state = self.state.lock();
        let pos = state.mcast_memberships.iter().position(|entry| {
            if entry.group != group {
                return false;
            }
            if let Some((resolved_ifindex, resolved_addr)) = resolved {
                if ifindex > 0 {
                    return entry.ifindex == resolved_ifindex;
                }
                if ifaddr != [0; 4] {
                    return entry.ifaddr == resolved_addr;
                }
            }
            true
        });
        let Some(pos) = pos else {
            return err(SyscallError::EADDRNOTAVAIL);
        };
        let entry = state.mcast_memberships.remove(pos);
        drop(state);
        let _ = netdev::del_maddr(entry.ifindex, netdev::ipv4_multicast_mac(entry.group));
        0
    }

    fn release_ipv4_multicast_memberships(&self) {
        let memberships = {
            let mut state = self.state.lock();
            core::mem::take(&mut state.mcast_memberships)
        };
        for entry in memberships {
            let _ = netdev::del_maddr(entry.ifindex, netdev::ipv4_multicast_mac(entry.group));
        }
    }

    pub(crate) fn poll_readable(&self) -> bool {
        let state = self.state.lock();
        state.rd_shutdown || !state.recv_queue.is_empty()
    }

    pub(crate) fn recv_packet(&self, peek: bool) -> Option<RawPacket> {
        let mut state = self.state.lock();
        if state.rd_shutdown {
            return None;
        }
        let packet = if peek {
            state.recv_queue.front().cloned()
        } else {
            state.recv_queue.pop_front()
        };
        if !peek && packet.is_some() {
            state.last_timestamp = Some(SocketTimestamp::now());
        }
        packet
    }

    pub(crate) fn read_shutdown(&self) -> bool {
        self.state.lock().rd_shutdown
    }

    pub(super) fn shutdown(&self, how: usize) -> Result<(), isize> {
        const ENOTCONN: isize = -107;
        let mut state = self.state.lock();
        if state.remote_addr.is_none() {
            return Err(ENOTCONN);
        }
        if how == 0 || how == 2 {
            state.rd_shutdown = true;
            state.recv_queue.clear();
        }
        if how == 1 || how == 2 {
            state.wr_shutdown = true;
        }
        Ok(())
    }

    fn set_socket_error(&self, errno: isize) {
        self.set_socket_local_error(errno, 0, None);
    }

    fn set_socket_local_error(&self, errno: isize, info: u32, offender: Option<([u8; 4], u16)>) {
        if errno < 0 {
            let mut state = self.state.lock();
            let errno = (-errno) as i32;
            state.pending_error = errno;
            if state.ip_recverr {
                if state.error_queue.len() >= RAW_ERROR_QUEUE_LIMIT {
                    state.error_queue.pop_front();
                }
                state
                    .error_queue
                    .push_back(Ipv4ErrorQueueEntry::local_with_info(
                        errno,
                        info,
                        offender,
                        Vec::new(),
                    ));
            }
        }
    }

    pub(super) fn take_socket_error(&self) -> u32 {
        let mut state = self.state.lock();
        let errno = state.pending_error.max(0) as u32;
        state.pending_error = 0;
        errno
    }

    pub(crate) fn socket_timestamp(&self) -> Option<SocketTimestamp> {
        self.state.lock().last_timestamp
    }

    pub(super) fn set_timestamp_mode(&self, mode: SocketTimestampMode) {
        self.state.lock().timestamp_mode = mode;
    }

    pub(super) fn timestamp_mode(&self) -> SocketTimestampMode {
        self.state.lock().timestamp_mode
    }

    fn protocol_matches(&self, packet_protocol: u8) -> bool {
        match self.protocol {
            // Linux IPv4 raw sockets do not use IPPROTO_RAW as a receive-all wildcard.
            IPPROTO_RAW => false,
            0 => true,
            protocol => protocol == packet_protocol as usize,
        }
    }

    fn observed_ipv4_packet(
        &self,
        ifindex: i32,
        packet: &[u8],
        _pkttype: u8,
        metadata: PacketMetadata,
    ) -> Option<RawPacket> {
        if packet.len() < 20 {
            return None;
        }
        let version = packet[0] >> 4;
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        if version != 4 || ihl < 20 || ihl > packet.len() {
            return None;
        }
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if total_len < ihl || total_len > packet.len() {
            return None;
        }
        let tos = packet[1];
        let ttl = packet[8];
        let packet_protocol = packet[9];
        if !self.protocol_matches(packet_protocol) {
            return None;
        }

        let src = Ipv4Address::from_bytes(&packet[12..16]);
        let dst = Ipv4Address::from_bytes(&packet[16..20]);
        let src_octets = ipv4_octets(src);
        let dst_octets = ipv4_octets(dst);
        let (bound_ifindex, local_addr, local_port, remote_addr, filter, ebpf_filter) = {
            let state = self.state.lock();
            (
                state.bound_ifindex,
                state.local_addr,
                state.local_port,
                state.remote_addr,
                state.filter.clone(),
                state.ebpf_filter.clone(),
            )
        };
        if bound_ifindex > 0 && bound_ifindex != ifindex {
            return None;
        }
        if let Some(local) = local_addr
            && local != dst
        {
            return None;
        }
        if let Some(remote) = remote_addr
            && remote != src
        {
            return None;
        }
        if netdev::ipv4_is_multicast_addr(dst_octets)
            && !self.multicast_source_allowed(ifindex, dst_octets, src_octets)
        {
            return None;
        }
        if self.socket_type == SOCK_DGRAM
            && self.protocol == IPPROTO_ICMP
            && local_port != 0
            && !icmp_echo_identifier_matches(&packet[ihl..total_len], local_port)
        {
            return None;
        }

        let data_range = if self.socket_type == SOCK_DGRAM && self.protocol == IPPROTO_ICMP {
            // Linux ping sockets (`SOCK_DGRAM/IPPROTO_ICMP`) receive the ICMP
            // transport payload, while `SOCK_RAW` IPv4 sockets receive the IP
            // header as part of the user-visible packet.
            ihl..total_len
        } else {
            0..total_len
        };
        let mut data = packet[data_range].to_vec();
        if let Some(filter) = filter {
            let Some(snaplen) = filter.filter_len(&data) else {
                return None;
            };
            data.truncate(snaplen);
        }
        if let Some(filter) = ebpf_filter {
            let Some(snaplen) = filter.filter_len(&data) else {
                return None;
            };
            data.truncate(snaplen);
        }

        Some(RawPacket {
            from: src,
            ifindex,
            dst,
            ttl,
            tos,
            metadata,
            data,
        })
    }

    fn enqueue_observed_ipv4_packet(
        &self,
        ifindex: i32,
        packet: &[u8],
        pkttype: u8,
        metadata: PacketMetadata,
    ) {
        if self.state.lock().rd_shutdown {
            return;
        }
        let Some(packet) = self.observed_ipv4_packet(ifindex, packet, pkttype, metadata) else {
            return;
        };
        let mut state = self.state.lock();
        if state.recv_queue.len() >= RAW_RECV_QUEUE_LIMIT {
            state.recv_queue.pop_front();
        }
        state.recv_queue.push_back(packet);
    }

    pub(crate) fn handle_outbound_probe(
        &self,
        payload: &[u8],
        target: Option<Ipv4Address>,
        metadata: PacketMetadata,
        msg_dontroute: bool,
        msg_confirm: bool,
        ifindex_override: Option<i32>,
        local_override: Option<Ipv4Address>,
        ttl_override: Option<u8>,
        tos_override: Option<u8>,
    ) -> Result<(), isize> {
        if payload.len() > u16::MAX as usize {
            return Err(err(SyscallError::EMSGSIZE));
        }

        let (
            remote,
            local,
            packet,
            broadcast_enabled,
            bound_ifindex,
            pmtudisc,
            hdrincl,
            dont_route,
            mcast_loop,
        ) = {
            let state = self.state.lock();
            if state.wr_shutdown {
                return Err(err(SyscallError::EPIPE));
            }
            let dont_route = state.dontroute || msg_dontroute;
            if state.ip_hdrincl {
                let broadcast_enabled = state.broadcast;
                let bound_ifindex = ifindex_override.unwrap_or(state.bound_ifindex);
                if state.bound_ifindex > 0
                    && bound_ifindex > 0
                    && state.bound_ifindex != bound_ifindex
                {
                    return Err(err(SyscallError::EINVAL));
                }
                if !state.ip_options.is_empty() {
                    return Err(err(SyscallError::EINVAL));
                }
                let (remote, local, packet) = Self::prepare_hdrincl_packet(
                    self.net_ns_id,
                    payload,
                    target.or(state.remote_addr),
                    local_override.or(state.local_addr),
                    bound_ifindex,
                    if ifindex_override.is_some() {
                        bound_ifindex
                    } else {
                        state.mcast_ifindex
                    },
                    if local_override.is_some() || ifindex_override.is_some() {
                        [0; 4]
                    } else {
                        state.mcast_ifaddr
                    },
                )?;
                (
                    remote,
                    local,
                    packet,
                    broadcast_enabled,
                    bound_ifindex,
                    state.ip_pmtudisc,
                    true,
                    dont_route,
                    state.mcast_loop,
                )
            } else {
                let Some(remote) = target.or(state.remote_addr) else {
                    return Err(err(SyscallError::EDESTADDRREQ));
                };
                let broadcast_enabled = state.broadcast;
                let bound_ifindex = ifindex_override.unwrap_or(state.bound_ifindex);
                if state.bound_ifindex > 0
                    && bound_ifindex > 0
                    && state.bound_ifindex != bound_ifindex
                {
                    return Err(err(SyscallError::EINVAL));
                }
                let local = Self::select_local_addr(
                    self.net_ns_id,
                    local_override.or(state.local_addr),
                    bound_ifindex,
                    remote,
                    if ifindex_override.is_some() {
                        bound_ifindex
                    } else {
                        state.mcast_ifindex
                    },
                    if local_override.is_some() || ifindex_override.is_some() {
                        [0; 4]
                    } else {
                        state.mcast_ifaddr
                    },
                )?;
                let ttl = if netdev::ipv4_is_multicast_addr(ipv4_octets(remote)) {
                    state.mcast_ttl
                } else {
                    ttl_override.unwrap_or_else(|| state.ip_ttl.clamp(0, 255) as u8)
                };
                let tos = tos_override.unwrap_or(state.ip_tos);
                let payload = if self.socket_type == SOCK_DGRAM && self.protocol == IPPROTO_ICMP {
                    prepare_ping_payload(payload, state.local_port)?
                } else {
                    payload.to_vec()
                };
                let packet = build_ipv4_packet(
                    local,
                    remote,
                    self.protocol as u8,
                    &payload,
                    tos,
                    ttl,
                    &state.ip_options,
                )?;
                (
                    remote,
                    local,
                    packet,
                    broadcast_enabled,
                    bound_ifindex,
                    state.ip_pmtudisc,
                    false,
                    dont_route,
                    state.mcast_loop,
                )
            }
        };
        if !broadcast_enabled && netdev::ipv4_is_broadcast_addr(ipv4_octets(remote), bound_ifindex)
        {
            return Err(err(SyscallError::EACCES));
        }
        if !hdrincl
            && ipv4_pmtu_reports_oversize(pmtudisc)
            && let Some(mtu) = netdev::ipv4_path_mtu_in_namespace(
                self.net_ns_id,
                bound_ifindex,
                Some(ipv4_octets(local)),
                Some(ipv4_octets(remote)),
            )
            && packet.len() > mtu as usize
        {
            let e = err(SyscallError::EMSGSIZE);
            self.set_socket_local_error(e, mtu, Some((ipv4_octets(remote), 0)));
            return Err(e);
        }
        let resolved = if msg_confirm {
            netdev::confirm_ipv4_neighbor_on_device_in_namespace_with_routing(
                self.net_ns_id,
                bound_ifindex,
                Some(ipv4_octets(local)),
                ipv4_octets(remote),
                !dont_route,
            )
        } else {
            netdev::learn_ipv4_neighbor_on_device_in_namespace_with_routing(
                self.net_ns_id,
                bound_ifindex,
                Some(ipv4_octets(local)),
                ipv4_octets(remote),
                !dont_route,
            )
        };
        let Some((dev, remote_mac)) = resolved else {
            return Err(err(SyscallError::ENXIO));
        };
        netdev::record_device_traffic_in_namespace(
            self.net_ns_id,
            dev.ifindex,
            device_frame_len(&dev, packet.len()),
            true,
        );
        netdev::record_protocol_packet_in_namespace(self.net_ns_id, &packet, true);
        transmit_packet_frame_from_device(
            self.net_ns_id,
            &dev,
            ETH_P_IP,
            dev.hwaddr,
            remote_mac,
            &packet,
            metadata,
        );
        let suppress_multicast_loopback =
            netdev::ipv4_is_multicast_addr(ipv4_octets(remote)) && !mcast_loop;
        if dev.kind == netdev::NetDeviceKind::Loopback && !suppress_multicast_loopback {
            crate::net::inject_loopback_ip_packet_in(self.net_ns_id, &packet);
        }
        Ok(())
    }

    fn select_local_addr(
        net_ns_id: usize,
        explicit: Option<Ipv4Address>,
        bound_ifindex: i32,
        remote: Ipv4Address,
        mcast_ifindex: i32,
        mcast_ifaddr: [u8; 4],
    ) -> Result<Ipv4Address, isize> {
        if let Some(local) = explicit {
            return Ok(local);
        }
        let remote_octets = ipv4_octets(remote);
        if netdev::ipv4_is_multicast_addr(remote_octets) {
            if mcast_ifaddr != [0; 4] {
                return Ok(Ipv4Address::from_bytes(&mcast_ifaddr));
            }
            if mcast_ifindex > 0 {
                if let Some(dev) =
                    netdev::device_snapshot_by_index_in_namespace(net_ns_id, mcast_ifindex)
                    && (dev.flags & netdev::IFF_UP) == 0
                {
                    return Err(err(SyscallError::ENETDOWN));
                }
                return netdev::select_ipv4_source_addr_on_device_in_namespace(
                    net_ns_id,
                    mcast_ifindex,
                    remote_octets,
                )
                .or_else(|| {
                    netdev::primary_ipv4_addr_by_ifindex_in_namespace(net_ns_id, mcast_ifindex)
                })
                .map(|addr| Ipv4Address::from_bytes(&addr))
                .ok_or(err(SyscallError::ENXIO));
            }
        }
        let local = if bound_ifindex > 0 {
            if let Some(dev) =
                netdev::device_snapshot_by_index_in_namespace(net_ns_id, bound_ifindex)
                && (dev.flags & netdev::IFF_UP) == 0
            {
                return Err(err(SyscallError::ENETDOWN));
            }
            netdev::select_ipv4_source_addr_on_device_in_namespace(
                net_ns_id,
                bound_ifindex,
                remote_octets,
            )
        } else {
            netdev::select_ipv4_source_addr_in_namespace(net_ns_id, remote_octets)
        };
        local
            .map(|addr| Ipv4Address::from_bytes(&addr))
            .ok_or(err(SyscallError::ENXIO))
    }

    fn prepare_hdrincl_packet(
        net_ns_id: usize,
        payload: &[u8],
        target: Option<Ipv4Address>,
        local_addr: Option<Ipv4Address>,
        bound_ifindex: i32,
        mcast_ifindex: i32,
        mcast_ifaddr: [u8; 4],
    ) -> Result<(Ipv4Address, Ipv4Address, Vec<u8>), isize> {
        if payload.len() < 20 {
            return Err(err(SyscallError::EINVAL));
        }
        let version = payload[0] >> 4;
        let ihl = ((payload[0] & 0x0f) as usize) * 4;
        if version != 4 || !(20..=payload.len()).contains(&ihl) {
            return Err(err(SyscallError::EINVAL));
        }

        let header_dst = Ipv4Address::from_bytes(&payload[16..20]);
        let Some(remote) =
            target.or_else(|| (header_dst != Ipv4Address::UNSPECIFIED).then_some(header_dst))
        else {
            return Err(err(SyscallError::EDESTADDRREQ));
        };

        let header_src = Ipv4Address::from_bytes(&payload[12..16]);
        let local = if header_src == Ipv4Address::UNSPECIFIED {
            Self::select_local_addr(
                net_ns_id,
                local_addr,
                bound_ifindex,
                remote,
                mcast_ifindex,
                mcast_ifaddr,
            )?
        } else {
            header_src
        };

        let mut packet = payload.to_vec();
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        if header_src == Ipv4Address::UNSPECIFIED {
            packet[12..16].copy_from_slice(local.as_bytes());
        }
        packet[10..12].fill(0);
        let checksum = internet_checksum(&packet[..ihl]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok((remote, local, packet))
    }
}

impl Drop for RawSocketFile {
    fn drop(&mut self) {
        self.release_ipv4_multicast_memberships();
        crate::fs::release_net_namespace_socket_ref(self.net_ns_id);
    }
}

impl File for RawSocketFile {
    fn readable(&self) -> bool {
        self.poll_readable()
    }

    fn writable(&self) -> bool {
        !self.state.lock().wr_shutdown
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let cap = buf.len();
        if cap == 0 {
            return 0;
        }
        if self.read_shutdown() {
            return 0;
        }
        loop {
            if let Some(packet) = self.recv_packet(false) {
                let total = core::cmp::min(cap, packet.data.len());
                return buf.copy_from_slice(&packet.data[..total]);
            }
            crate::task::processor::suspend_current_and_run_next();
        }
    }

    fn write(&self, buf: UserBuffer) -> usize {
        let len = buf.len();
        if len == 0 {
            return 0;
        }
        let data = buf.to_vec();
        match self.handle_outbound_probe(
            &data,
            self.remote_addr_v4(),
            self.packet_metadata(),
            false,
            false,
            None,
            None,
            None,
            None,
        ) {
            Ok(()) => len,
            Err(e) => {
                self.set_socket_error(e);
                0
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn poll_mask(&self) -> i16 {
        let state = self.state.lock();
        let mut mask = if state.wr_shutdown { 0 } else { POLLOUT };
        if state.pending_error != 0 {
            mask |= POLLERR;
        }
        if state.rd_shutdown || !state.recv_queue.is_empty() {
            mask |= POLLIN;
        }
        mask
    }
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_ipv4_packet(
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: u8,
    payload: &[u8],
    tos: u8,
    ttl: u8,
    options: &[u8],
) -> Result<Vec<u8>, isize> {
    if options.len() > 40 || options.len() % 4 != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    let header_len = 20usize + options.len();
    let total_len = header_len
        .checked_add(payload.len())
        .ok_or(err(SyscallError::EMSGSIZE))?;
    if total_len > u16::MAX as usize {
        return Err(err(SyscallError::EMSGSIZE));
    }
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x40 | ((header_len / 4) as u8);
    packet[1] = tos;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(src.as_bytes());
    packet[16..20].copy_from_slice(dst.as_bytes());
    packet[20..header_len].copy_from_slice(options);
    let checksum = internet_checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[header_len..].copy_from_slice(payload);
    Ok(packet)
}

/// `socket(domain, type, protocol)` — 创建一个新 socket，返回文件描述符。
///
/// `socket_type` 低 4 位为实际类型（SOCK_STREAM / SOCK_DGRAM / …），
/// 高位只允许叠加 `SOCK_CLOEXEC` 和 `SOCK_NONBLOCK`。
pub fn syscall_socket(domain: usize, socket_type: usize, protocol: usize) -> isize {
    let flags = socket_type & !SOCK_TYPE_MASK;
    if (flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK)) != 0 {
        return err(SyscallError::EINVAL);
    }
    let st = socket_type & SOCK_TYPE_MASK;
    let cloexec = (socket_type & SOCK_CLOEXEC) != 0;
    let nonblock = (socket_type & SOCK_NONBLOCK) != 0;

    // 仅支持这四种类型，其他直接 EINVAL。
    if !matches!(st, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET) {
        return err(SyscallError::EINVAL);
    }

    let file: FileArc = match domain as u16 {
        AF_INET | AF_INET6 => match st {
            SOCK_STREAM => {
                // protocol=0 或 6（IPPROTO_TCP）均合法，其他拒绝。
                if protocol != 0 && protocol != IPPROTO_TCP {
                    return err(SyscallError::EPROTONOSUPPORT);
                }
                if domain as u16 == AF_INET {
                    NetSocketFile::new_tcp()
                } else {
                    NetSocketFile::new_tcp_with_domain(domain as u16)
                }
            }
            SOCK_DGRAM => {
                if protocol == IPPROTO_ICMP {
                    if domain as u16 != AF_INET {
                        return err(SyscallError::EPROTONOSUPPORT);
                    }
                    RawSocketFile::new(st, protocol)
                } else {
                    // protocol=0 或 UDP/UDP-Lite 均合法；UDP-Lite 先复用 UDP 收发队列，
                    // 但保留创建协议号和 SOL_UDPLITE 选项语义。
                    if protocol != 0 && protocol != IPPROTO_UDP && protocol != IPPROTO_UDPLITE {
                        return err(SyscallError::EPROTONOSUPPORT);
                    }
                    if protocol == IPPROTO_UDPLITE {
                        NetSocketFile::new_udp_lite_with_domain(domain as u16)
                    } else if domain as u16 == AF_INET {
                        NetSocketFile::new_udp()
                    } else {
                        NetSocketFile::new_udp_with_domain(domain as u16)
                    }
                }
            }
            SOCK_RAW => {
                if domain as u16 != AF_INET {
                    return err(SyscallError::EPROTONOSUPPORT);
                }
                if !raw_protocol_supported(protocol) {
                    return err(SyscallError::EPROTONOSUPPORT);
                }
                RawSocketFile::new(st, protocol)
            }
            SOCK_SEQPACKET => return err(SyscallError::EPROTONOSUPPORT),
            _ => return err(SyscallError::EINVAL),
        },
        AF_UNIX => {
            if protocol != 0 {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            if !matches!(st, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
                return err(SyscallError::EINVAL);
            }
            // AF_UNIX 由 UnixSocketFile 实现（内部队列，不经过 smoltcp）。
            Arc::new(UnixSocketFile::new(st))
        }
        // NETLINK 是一种特殊协议。告诉外部网络接口状态。ip addr等工具用的就是这个
        AF_NETLINK => {
            // 当前 netlink 子集支持 rtnetlink(0)、sock_diag(4)和 generic netlink(16)。
            if !matches!(st, SOCK_RAW | SOCK_DGRAM) {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            if !matches!(protocol, 0 | 4 | 16) {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            NetlinkSocketFile::new_registered(st, protocol)
        }
        AF_PACKET => {
            if !matches!(st, SOCK_RAW | SOCK_DGRAM) {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            PacketSocketFile::new(st, protocol)
        }
        AF_VSOCK => {
            if protocol != 0 {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            if !matches!(st, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
                return err(SyscallError::EPROTONOSUPPORT);
            }
            VsockSocketFile::new(st, protocol)
        }
        // 其他协议族一律 EAFNOSUPPORT。
        _ => {
            return err(SyscallError::EAFNOSUPPORT);
        }
    };

    // 将 SOCK_CLOEXEC / SOCK_NONBLOCK 转换为 fd 描述符 flag。
    let mut descriptor_flags = 0u32;
    if cloexec {
        descriptor_flags |= FD_CLOEXEC;
    }
    if nonblock {
        descriptor_flags |= O_NONBLOCK;
    }

    // 安装到进程 fd 表，超出 nofile 限制时返回 EMFILE。
    let (files, limit) = current_files_and_nofile_limit();
    let installed = files.lock().install_fd(file, descriptor_flags, limit);
    let fd = match installed {
        Ok(fd) => fd,
        Err(rejected) => {
            rejected.discard();
            return err(SyscallError::EMFILE);
        }
    };
    if crate::debug_config::DEBUG_NET {
        let pid = current_process().getpid();
        crate::println!(
            "[net] pid={} socket(domain={}, type={}, protocol={:#x}) -> fd={}",
            pid,
            domain,
            st,
            protocol,
            fd
        );
    }
    fd as isize
}

/// `bind(fd, addr, addrlen)` — 将 socket 绑定到指定本地地址和端口。
///
/// - `fd`：待绑定的 socket 文件描述符。
/// - `addr`：用户空间 `sockaddr` 指针（支持 `sockaddr_in` / `sockaddr_un` / `sockaddr_nl`）。
/// - `addrlen`：地址结构体长度（字节）。
///
/// 对 AF_INET socket，`0.0.0.0` 保留为通配绑定；其他地址必须属于当前
/// network namespace 中的本机网卡，否则返回 `EADDRNOTAVAIL`。
/// 端口 < 1024 属于 Linux 特权端口，须 `euid == 0` 方可绑定，否则返回 `EACCES`。
pub fn syscall_bind(fd: usize, addr: usize, addrlen: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        return bind_unix_socket(&file, unix_sock, addr, addrlen);
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let sa = match parse_sockaddr_nl_connect(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return netlink_sock.bind_local(sa);
    }
    if let Some(packet_sock) = file.as_any().downcast_ref::<PacketSocketFile>() {
        let sa = match parse_sockaddr_ll(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ret = packet_sock.bind_ll(&sa);
        if crate::debug_config::DEBUG_NET {
            crate::println!(
                "[net] pid={} packet bind(fd={}, ifindex={}, protocol={:#x}) -> {}",
                current_process().pid.0,
                fd,
                sa.sll_ifindex,
                sa.sll_protocol,
                ret
            );
        }
        return ret;
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        let sa = match read_sockaddr_in(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if sa.len < size_of::<SockAddrIn>() {
            return err(SyscallError::EINVAL);
        }
        let IpAddress::Ipv4(ip) = sa.ip else {
            return err(SyscallError::EAFNOSUPPORT);
        };
        return raw_sock.bind_v4(ip, sa.port);
    }
    if file.as_any().downcast_ref::<VsockSocketFile>().is_some() {
        let sa = match read_sockaddr_vm(addr, addrlen) {
            Ok(sa) => sa,
            Err(e) => return e,
        };
        if sa.svm_family != AF_VSOCK {
            return err(SyscallError::EAFNOSUPPORT);
        }
        if sa.svm_cid != VMADDR_CID_ANY && sa.svm_cid != VMADDR_CID_LOCAL {
            return err(SyscallError::EADDRNOTAVAIL);
        }
        return 0;
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let sa = match read_sockaddr_in_for_domain(addr, addrlen, sock.domain()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let required_len = if sa.family == AF_INET6 {
        size_of::<SockAddrIn6>()
    } else {
        size_of::<SockAddrIn>()
    };
    if sa.family != AF_UNSPEC && sa.len < required_len {
        return err(SyscallError::EINVAL);
    }
    if sa.family != sock.domain()
        && (sa.family != AF_UNSPEC
            || !matches!(
                sa.ip,
                IpAddress::Ipv4(Ipv4Address::UNSPECIFIED)
                    | IpAddress::Ipv6(Ipv6Address::UNSPECIFIED)
            ))
    {
        return err(SyscallError::EAFNOSUPPORT);
    }
    let ip = sa.ip;
    let port = sa.port;
    // 遵循 Linux 特权端口约定：0–1023 号端口仅 root 可绑定。
    if port < 1024 {
        let euid = current_process().borrow_mut().euid;
        if euid != 0 {
            return err(SyscallError::EACCES);
        }
    }
    let r = match sock.bind_ip(ip, port) {
        Ok(()) => 0,
        Err(e) => e,
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} bind(fd={}) -> {}:{} = {}",
            current_process().pid.0,
            fd,
            ip,
            port,
            r
        );
    }
    r
}

/// `listen(fd, backlog)` — 将 socket 转为监听状态，设置全连接队列上限。
///
/// - `fd`：已绑定地址的 TCP socket 或 AF_UNIX stream socket。
/// - `backlog`：已完成三次握手但尚未被 `accept` 取走的连接数上限。
///   实际队列容量由底层实现（smoltcp / UnixSocketFile）决定。
pub fn syscall_listen(fd: usize, backlog: usize) -> isize {
    let file = match get_file(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        return unix_sock.set_listening(backlog);
    }
    if file.as_any().downcast_ref::<VsockSocketFile>().is_some() {
        return err(SyscallError::EOPNOTSUPP);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} listen(fd={}, backlog={}) kind={:?}",
            current_process().pid.0,
            fd,
            backlog,
            sock.kind()
        );
    }
    let r = match sock.listen(backlog) {
        Ok(()) => 0,
        Err(e) => e,
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} listen(fd={}) -> {}",
            current_process().pid.0,
            fd,
            r
        );
    }
    r
}

/// `accept(fd, addr, addrlen)` — 从监听 socket 取出一条已完成三次握手的连接。
///
/// - `fd`：处于监听状态的 socket（TCP 或 AF_UNIX stream）。
/// - `addr`：用于接收对端地址的用户空间缓冲区指针；传 `NULL`（0）表示不关心对端地址。
/// - `addrlen`：指向缓冲区长度的用户空间指针（入参为缓冲区大小，出参为实际写入长度）。
///
/// Linux 在连接取出成功后才将 peer 地址写回用户空间；若写回失败，需要丢弃
/// 已创建的新 fd 并返回对应错误。
///
/// 返回新连接的文件描述符；出错时返回负的 errno。
pub fn syscall_accept(fd: usize, addr: usize, addrlen: usize) -> isize {
    syscall_accept_inner(fd, addr, addrlen, 0)
}

fn syscall_accept_inner(fd: usize, addr: usize, addrlen: usize, flags: usize) -> isize {
    let (file, listener_flags) = {
        let files = current_files();
        let files = files.lock();
        let Some((file, descriptor_flags)) = files.get_file_and_flags(fd) else {
            return err(SyscallError::EBADF);
        };
        if (descriptor_flags & O_PATH) != 0 {
            return err(SyscallError::EBADF);
        }
        (file, descriptor_flags)
    };
    let accept_nonblock = (listener_flags & O_NONBLOCK) != 0 || (flags & SOCK_NONBLOCK) != 0;
    let mut new_fd_flags = 0u32;
    if (flags & SOCK_CLOEXEC) != 0 {
        new_fd_flags |= FD_CLOEXEC;
    }
    if (flags & SOCK_NONBLOCK) != 0 {
        new_fd_flags |= O_NONBLOCK;
    }
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let new_sock = match unix_sock.accept_stream(accept_nonblock) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let peer_addr = new_sock.peer_addr();
        let (files, limit) = current_files_and_nofile_limit();
        let mut files = files.lock();
        let new_file: FileArc = new_sock;
        // Linux accept() 不继承监听 fd 的文件状态 flag；accept4() 仅按参数设置新 fd。
        let installed = files.install_fd(new_file, new_fd_flags, limit);
        drop(files);
        let newfd = match installed {
            Ok(fd) => fd,
            Err(rejected) => {
                rejected.discard();
                return err(SyscallError::EMFILE);
            }
        };
        if addr != 0 {
            let r = write_sockaddr_un(addr, addrlen, peer_addr.as_ref());
            if r != 0 {
                let detached = current_files().lock().clear_fd(newfd);
                if let Some(detached) = detached {
                    drop(detached.complete_close());
                }
                return r;
            }
        }
        return newfd as isize;
    }
    if file.as_any().downcast_ref::<VsockSocketFile>().is_some() {
        return err(SyscallError::EOPNOTSUPP);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let listener_domain = sock.domain();
    match sock.kind() {
        crate::fs::NetSocketKind::TcpStream => return err(SyscallError::EINVAL),
        crate::fs::NetSocketKind::Udp => return err(SyscallError::EOPNOTSUPP),
        crate::fs::NetSocketKind::TcpListener => {}
    }
    let new_sock = match sock.accept(accept_nonblock) {
        Ok(s) => s,
        Err(e) => {
            if crate::debug_config::DEBUG_NET {
                crate::println!(
                    "[net] pid={} accept(fd={}) kind={:?} -> {}",
                    current_process().pid.0,
                    fd,
                    sock.kind(),
                    e
                );
            }
            return e;
        }
    };
    let peer = new_sock.tcp_endpoints();
    let (files, limit) = current_files_and_nofile_limit();
    let mut files = files.lock();
    // Linux accept() 不继承监听 fd 的文件状态 flag；accept4() 仅按参数设置新 fd。
    let installed = files.install_fd(new_sock, new_fd_flags, limit);
    drop(files);
    let newfd = match installed {
        Ok(fd) => fd,
        Err(rejected) => {
            rejected.discard();
            return err(SyscallError::EMFILE);
        }
    };
    if addr != 0 {
        if let Some((_lip, _lport, rip, rport)) = peer {
            let r = write_sockaddr_in_for_domain(addr, addrlen, listener_domain, rip, rport);
            if r != 0 {
                let detached = current_files().lock().clear_fd(newfd);
                if let Some(detached) = detached {
                    drop(detached.complete_close());
                }
                return r;
            }
        }
    }
    newfd as isize
}

/// `accept4(fd, addr, addrlen, flags)` — `accept` 的扩展版本，可原子设置新 fd 的 flags。
///
/// - `flags`：仅允许 `SOCK_CLOEXEC`（exec 时关闭）和 `SOCK_NONBLOCK`（非阻塞）的组合，
///   其他位置位则返回 `EINVAL`。
///
/// `SOCK_NONBLOCK` 同时影响本次 accept 的等待行为和返回的新 fd；监听 fd 自身
/// 已有的 `O_NONBLOCK` 也会影响本次等待行为，但不会继承到新 fd。
pub fn syscall_accept4(fd: usize, addr: usize, addrlen: usize, flags: usize) -> isize {
    if (flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK)) != 0 {
        return err(SyscallError::EINVAL);
    }
    syscall_accept_inner(fd, addr, addrlen, flags)
}

/// `connect(fd, addr, addrlen)` — 向指定远端地址发起连接（或为无连接 socket 设置默认对端）。
///
/// - `fd`：待连接的 socket。
/// - `addr`：目标地址（`sockaddr_in` / `sockaddr_un` / `sockaddr_nl`）。
/// - `addrlen`：地址结构体长度（字节）。
///
/// 对 AF_NETLINK socket，`connect` 只接受内核端 `sockaddr_nl(pid=0, groups=0)`；
/// `AF_UNSPEC` 断开默认对端，非内核 netlink peer 明确返回不支持。
///
/// 对 AF_INET socket，目标 IP `0.0.0.0` 被映射到 `127.0.0.1`（同 `bind` 的处理逻辑）。
pub fn syscall_connect(fd: usize, addr: usize, addrlen: usize) -> isize {
    let (file, descriptor_flags) = {
        let files = current_files();
        let files = files.lock();
        let Some((file, descriptor_flags)) = files.get_file_and_flags(fd) else {
            return err(SyscallError::EBADF);
        };
        if (descriptor_flags & O_PATH) != 0 {
            return err(SyscallError::EBADF);
        }
        (file, descriptor_flags)
    };
    let nonblock = (descriptor_flags & O_NONBLOCK) != 0;
    if let Some(unix_sock) = file.as_any().downcast_ref::<UnixSocketFile>() {
        let family = match read_sockaddr_un_family(addr, addrlen) {
            Ok(family) => family,
            Err(e) => return e,
        };
        if family == AF_UNSPEC {
            return unix_sock.disconnect_unix();
        }
        let bound = match parse_unix_bound_addr(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return unix_sock.connect_unix(bound);
    }
    if let Some(netlink_sock) = file.as_any().downcast_ref::<NetlinkSocketFile>() {
        let sa = match parse_sockaddr_nl_connect(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        return netlink_sock.connect_peer(sa);
    }
    if let Some(raw_sock) = file.as_any().downcast_ref::<RawSocketFile>() {
        let sa = match read_sockaddr_in(addr, addrlen) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if sa.family == AF_UNSPEC {
            return raw_sock.connect_v4(smoltcp::wire::Ipv4Address::UNSPECIFIED);
        }
        if sa.len < size_of::<SockAddrIn>() {
            return err(SyscallError::EINVAL);
        }
        if sa.family != AF_INET {
            return err(SyscallError::EAFNOSUPPORT);
        }
        let IpAddress::Ipv4(ip) = sa.ip else {
            return err(SyscallError::EAFNOSUPPORT);
        };
        return raw_sock.connect_v4(ip);
    }
    if let Some(vsock) = file.as_any().downcast_ref::<VsockSocketFile>() {
        return vsock.connect_vm(addr, addrlen);
    }
    let sock = match file.as_any().downcast_ref::<NetSocketFile>() {
        Some(s) => s,
        None => return err(SyscallError::ENOTSOCK),
    };
    let sa = match read_sockaddr_in_for_domain(addr, addrlen, sock.domain()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if sa.family == AF_UNSPEC {
        return match sock.disconnect_v4() {
            Ok(()) => 0,
            Err(e) => e,
        };
    }
    if sa.family != sock.domain() {
        return err(SyscallError::EAFNOSUPPORT);
    }
    let ip = sa.ip;
    let port = sa.port;
    // 目标 0.0.0.0 无实际意义，统一映射到 loopback，与 bind 保持一致。
    let ip = match ip {
        IpAddress::Ipv4(Ipv4Address::UNSPECIFIED) => {
            IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1))
        }
        IpAddress::Ipv6(Ipv6Address::UNSPECIFIED) => IpAddress::Ipv6(Ipv6Address::LOOPBACK),
        ip => ip,
    };
    if crate::debug_config::DEBUG_NET {
        crate::println!(
            "[net] pid={} connect(fd={}) -> {}:{}",
            current_process().pid.0,
            fd,
            ip,
            port
        );
    }
    match sock.connect_ip(ip, port, None, nonblock) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
