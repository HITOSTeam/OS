//! WireGuard generic-netlink 控制面和最小数据面。
//!
//! 这里实现 Linux `wireguard` family 的配置接口，以及 LTP veth 场景需要的
//! Noise 握手、ChaCha20-Poly1305 封包、UDP 隧道和 allowed-ips 路由。
//! 仍不是完整驱动：cookie、漫游和真实网卡收发后续再补。

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU32, Ordering};

use lazy_static::lazy_static;
use spin::Mutex;

use crate::syscall::error::{SyscallError, err};

use super::netdev::{self, NetDeviceKind, NetDeviceSnapshot};
use super::netlink::{
    append_rtattr, build_done, build_genlmsg, parse_rtattrs_checked, read_string_attr,
    read_u16_attr_checked, read_u32_attr_checked,
};
use super::wireguard_crypto;
use super::{AF_INET, AF_INET6, IPPROTO_UDP};

pub(super) const GENL_FAMILY_ID: u16 = 19;

// generic-netlink 控制器本身的 family/attr 编号，用来回答
// `genl-ctrl-list wireguard` 这类“wireguard family 是否存在”的查询。
const GENL_ID_CTRL: u16 = 16;
const GENL_CTRL_VERSION: u8 = 2;
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_VERSION: u16 = 3;
const CTRL_ATTR_HDRSIZE: u16 = 4;
const CTRL_ATTR_MAXATTR: u16 = 5;

// Linux WireGuard generic-netlink ABI 中定义的 command/attribute 编号。
// `wg set`/`wg show` 最终都会通过这些编号把配置传进内核。
const WG_GENL_NAME: &str = "wireguard";
const WG_GENL_VERSION: u32 = 1;
const WGDEVICE_A_MAX: u32 = 8;
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;
pub(super) const WG_KEY_LEN: usize = 32;

// WireGuard ABI flag。这里按 Linux 语义解析更新/删除/替换请求。
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;
const WGPEER_F_REMOVE_ME: u32 = 1;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
const WGPEER_F_UPDATE_ONLY: u32 = 4;

// WGDEVICE_A_* 描述一个 wg 设备本身的属性。
const WGDEVICE_A_IFINDEX: u16 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;

// WGPEER_A_* 描述一个 peer；peer 下面还会嵌套 allowed-ips。
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_A_PROTOCOL_VERSION: u16 = 10;

// WGALLOWEDIP_A_* 是 WireGuard 的路由表：目标地址匹配哪个 peer。
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;
const WGALLOWEDIP_A_FLAGS: u16 = 4;
const WGALLOWEDIP_F_REMOVE_ME: u32 = 1;

// 嵌套 netlink attr 的标记，以及 `wg show all dump` 多包返回的标记。
const NLA_F_NESTED: u16 = 0x8000;
const NLM_F_MULTI: u16 = 0x02;

// WireGuard endpoint 用 sockaddr_in/sockaddr_in6 的原始字节保存。
const SOCKADDR_IN_LEN: usize = 16;
const SOCKADDR_IN6_LEN: usize = 28;

// 握手完成前先缓存少量数据包；限制队列是为了避免配置错误时无限吃内存。
const WG_PENDING_DATA_PER_PEER_LIMIT: usize = 64;
const WG_PENDING_DATA_GLOBAL_LIMIT: usize = 256;
const WG_HANDSHAKE_RETRY_MS: usize = 1_000;

#[derive(Clone, Debug)]
pub(super) enum WireguardEndpoint {
    /// sockaddr_in 原始布局，包含 family/port/IPv4 地址。
    Ipv4([u8; SOCKADDR_IN_LEN]),
    /// sockaddr_in6 原始布局；当前数据面只真正发送到 IPv4 endpoint。
    Ipv6([u8; SOCKADDR_IN6_LEN]),
}

impl WireguardEndpoint {
    fn as_sockaddr_bytes(&self) -> &[u8] {
        match self {
            Self::Ipv4(bytes) => bytes,
            Self::Ipv6(bytes) => bytes,
        }
    }

    fn ipv4_addr_port(&self) -> Option<([u8; 4], u16)> {
        let Self::Ipv4(bytes) = self else {
            return None;
        };
        Some((
            [bytes[4], bytes[5], bytes[6], bytes[7]],
            u16::from_be_bytes([bytes[2], bytes[3]]),
        ))
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(super) struct WireguardPeerRoute {
    /// 匹配到的 peer 公钥。
    pub(super) public_key: [u8; WG_KEY_LEN],
    /// peer 的外层 UDP 目的地址。
    pub(super) endpoint: Option<WireguardEndpoint>,
    /// 匹配到的 allowed-ip 地址族和前缀。
    pub(super) allowed_family: u16,
    pub(super) allowed_addr: Vec<u8>,
    pub(super) allowed_cidr: u8,
}

#[derive(Clone, Debug, Default)]
struct WireguardAllowedIpConfig {
    /// AF_INET 或 AF_INET6。
    family: u16,
    /// 网络字节序地址；IPv4 为 4 字节，IPv6 为 16 字节。
    addr: Vec<u8>,
    /// CIDR 前缀长度。
    cidr: u8,
    /// netlink 更新里携带 REMOVE_ME 时，不是新增路由而是删除路由。
    remove: bool,
}

#[derive(Clone, Debug)]
struct WireguardPeerConfig {
    /// peer 的身份公钥，也是配置、会话和统计的主键。
    public_key: [u8; WG_KEY_LEN],
    /// 可选 PSK，参与 Noise 派生。
    preshared_key: Option<[u8; WG_KEY_LEN]>,
    /// 本机私钥和 peer 公钥的 X25519 结果，配置变化后预计算。
    precomputed_static_static: Option<[u8; WG_KEY_LEN]>,
    /// 防重放时间戳。这里保存最近一次成功 initiation 的 timestamp。
    latest_handshake_timestamp: [u8; wireguard_crypto::NOISE_TIMESTAMP_LEN],
    /// 外层 UDP endpoint；没有 endpoint 时仍消费内层包，行为接近“配置未完整”。
    endpoint: Option<WireguardEndpoint>,
    persistent_keepalive: Option<u16>,
    /// allowed-ips 同时承担路由选择和入站源地址校验。
    allowed_ips: Vec<WireguardAllowedIpConfig>,
    /// `wg show` 能看到的累计流量统计。
    rx_bytes: u64,
    tx_bytes: u64,
}

#[derive(Clone, Debug)]
struct WireguardDeviceConfig {
    /// 对应 netdev 里的 wg 设备 ifindex。
    ifindex: i32,
    ifname: String,
    /// 设备身份；全 0 private key 会被当成清空身份。
    private_key: Option<[u8; WG_KEY_LEN]>,
    public_key: Option<[u8; WG_KEY_LEN]>,
    /// 外层 UDP 监听端口。
    listen_port: Option<u16>,
    fwmark: Option<u32>,
    peers: Vec<WireguardPeerConfig>,
}

#[derive(Clone, Debug)]
struct WireguardRouteTarget {
    /// 目标 wg 设备。
    ifindex: i32,
    /// 内层包匹配到的 peer。
    peer_public_key: [u8; WG_KEY_LEN],
    /// 外层 UDP 目的地址。
    endpoint: Option<WireguardEndpoint>,
    /// 外层 UDP 源端口，来自 wg 设备 listen-port。
    listen_port: Option<u16>,
    /// 最长前缀匹配时用来比较优先级。
    allowed_cidr: u8,
}

#[derive(Clone, Debug)]
struct WireguardPeerSession {
    /// 会话所属 wg 设备。
    ifindex: i32,
    peer_public_key: [u8; WG_KEY_LEN],
    /// 本端 sender index；入站响应/数据包靠它找到会话。
    local_index: u32,
    /// initiation 发出后、response 回来前保存的 Noise 中间状态。
    pending_state: Option<wireguard_crypto::NoiseHandshakeState>,
    pending_ephemeral_private: Option<[u8; WG_KEY_LEN]>,
    /// 握手完成后的收发密钥和计数器。
    keypair: Option<wireguard_crypto::NoiseKeypair>,
    /// 用于抑制短时间内重复发 handshake。
    created_ms: usize,
}

#[derive(Clone, Debug)]
struct WireguardPendingData {
    /// 握手尚未完成时，被 WireGuard 路由命中的内层 IP 包。
    ifindex: i32,
    peer_public_key: [u8; WG_KEY_LEN],
    /// 原包来自哪个 netns；握手完成后还要回到同一个 namespace 继续发送外层包。
    ns_id: usize,
    packet: Vec<u8>,
}

lazy_static! {
    /// WireGuard 配置面状态：由 generic-netlink `WG_CMD_SET_DEVICE` 更新。
    static ref WIREGUARD_CONFIGS: Mutex<Vec<WireguardDeviceConfig>> = Mutex::new(Vec::new());
    /// 数据面会话状态：保存握手进行中或已完成的 peer session。
    static ref WIREGUARD_SESSIONS: Mutex<Vec<WireguardPeerSession>> = Mutex::new(Vec::new());
    /// 握手完成前暂存的数据包。
    static ref WIREGUARD_PENDING_DATA: Mutex<VecDeque<WireguardPendingData>> =
        Mutex::new(VecDeque::new());
}

/// WireGuard sender index 不能为 0；用全局递增值模拟 Linux 中的随机 index 分配。
static WG_INDEX_COUNTER: AtomicU32 = AtomicU32::new(1);

/// 构造 generic-netlink controller 对 `wireguard` family 查询的响应。
pub(super) fn build_family_msg(seq: u32, port_id: u32) -> Vec<u8> {
    let mut attrs = Vec::new();
    append_rtattr(
        &mut attrs,
        CTRL_ATTR_FAMILY_ID,
        &GENL_FAMILY_ID.to_ne_bytes(),
    );
    let mut name = WG_GENL_NAME.as_bytes().to_vec();
    name.push(0);
    append_rtattr(&mut attrs, CTRL_ATTR_FAMILY_NAME, &name);
    append_rtattr(
        &mut attrs,
        CTRL_ATTR_VERSION,
        &WG_GENL_VERSION.to_ne_bytes(),
    );
    append_rtattr(&mut attrs, CTRL_ATTR_HDRSIZE, &0u32.to_ne_bytes());
    append_rtattr(&mut attrs, CTRL_ATTR_MAXATTR, &WGDEVICE_A_MAX.to_ne_bytes());
    build_genlmsg(
        GENL_ID_CTRL,
        CTRL_CMD_NEWFAMILY,
        GENL_CTRL_VERSION,
        seq,
        0,
        port_id,
        &attrs,
    )
}

/// 判断这是不是对 `wireguard` generic-netlink family 的查询。
pub(super) fn is_family_request(attrs: &[(u16, Vec<u8>)]) -> bool {
    if read_string_attr(attrs, CTRL_ATTR_FAMILY_NAME).is_some_and(|name| name == WG_GENL_NAME) {
        return true;
    }
    attrs
        .iter()
        .find(|(kind, data)| *kind == CTRL_ATTR_FAMILY_ID && data.len() >= 2)
        .is_some_and(|(_, data)| u16::from_ne_bytes([data[0], data[1]]) == GENL_FAMILY_ID)
}

/// WireGuard generic-netlink 入口。
///
/// `WG_CMD_SET_DEVICE` 修改内存中的 wg 配置；`WG_CMD_GET_DEVICE` 读取单个设备或 dump 全部设备。
pub(super) fn handle_message(
    cmd: u8,
    attrs: &[(u16, Vec<u8>)],
    seq: u32,
    port_id: u32,
) -> Result<Vec<Vec<u8>>, isize> {
    match cmd {
        WG_CMD_SET_DEVICE => {
            apply_set_device(attrs)?;
            Ok(Vec::new())
        }
        WG_CMD_GET_DEVICE if request_has_target(attrs) => {
            let (dev, cfg) = config_for_request(attrs)?;
            Ok(alloc::vec![build_device_msg(&dev, &cfg, seq, port_id, 0)])
        }
        WG_CMD_GET_DEVICE => {
            let mut replies = Vec::new();
            for (dev, cfg) in configs_for_dump() {
                replies.push(build_device_msg(&dev, &cfg, seq, port_id, NLM_F_MULTI));
            }
            replies.push(build_done(seq, port_id));
            Ok(replies)
        }
        _ => Err(err(SyscallError::EOPNOTSUPP)),
    }
}

/// 删除 netdev 时同步清理 WireGuard 配置、会话和待发送数据，避免 ifindex 复用后串状态。
pub(super) fn remove_config(ifindex: i32) {
    WIREGUARD_CONFIGS
        .lock()
        .retain(|cfg| cfg.ifindex != ifindex);
    WIREGUARD_SESSIONS
        .lock()
        .retain(|session| session.ifindex != ifindex);
    WIREGUARD_PENDING_DATA
        .lock()
        .retain(|pending| pending.ifindex != ifindex);
}

/// 查询设备是否已经设置有效私钥。
#[allow(dead_code)]
pub(super) fn has_private_key(ifindex: i32) -> bool {
    WIREGUARD_CONFIGS
        .lock()
        .iter()
        .find(|cfg| cfg.ifindex == ifindex)
        .is_some_and(|cfg| cfg.private_key.is_some())
}

/// 按 allowed-ips 做最长前缀匹配，找到某个目的地址应该走哪个 peer。
#[allow(dead_code)]
pub(super) fn lookup_peer_by_allowed_ip(
    ifindex: i32,
    family: u16,
    addr: &[u8],
) -> Option<WireguardPeerRoute> {
    if (family == AF_INET && addr.len() != 4) || (family == AF_INET6 && addr.len() != 16) {
        return None;
    }
    let configs = WIREGUARD_CONFIGS.lock();
    let cfg = configs.iter().find(|cfg| cfg.ifindex == ifindex)?;
    let mut best: Option<WireguardPeerRoute> = None;
    for peer in &cfg.peers {
        for allowed in &peer.allowed_ips {
            if allowed.remove
                || allowed.family != family
                || !prefix_matches(&allowed.addr, addr, allowed.cidr)
            {
                continue;
            }
            if best
                .as_ref()
                .map_or(true, |current| allowed.cidr > current.allowed_cidr)
            {
                best = Some(WireguardPeerRoute {
                    public_key: peer.public_key,
                    endpoint: peer.endpoint.clone(),
                    allowed_family: allowed.family,
                    allowed_addr: allowed.addr.clone(),
                    allowed_cidr: allowed.cidr,
                });
            }
        }
    }
    best
}

/// 判断 `addr` 是否落在 `prefix/cidr` 里。
#[allow(dead_code)]
fn prefix_matches(prefix: &[u8], addr: &[u8], cidr: u8) -> bool {
    if prefix.len() != addr.len() {
        return false;
    }
    let full_bytes = usize::from(cidr / 8);
    let rest_bits = cidr % 8;
    if prefix
        .iter()
        .zip(addr.iter())
        .take(full_bytes)
        .any(|(left, right)| left != right)
    {
        return false;
    }
    if rest_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - rest_bits);
    match (prefix.get(full_bytes), addr.get(full_bytes)) {
        (Some(left), Some(right)) => (left & mask) == (right & mask),
        _ => false,
    }
}

/// 读取 32 字节 WireGuard key 属性；长度不对按 Linux ABI 返回 EINVAL。
fn read_key_attr(
    attrs: &[(u16, Vec<u8>)],
    attr_type: u16,
) -> Result<Option<[u8; WG_KEY_LEN]>, isize> {
    let Some((_, data)) = attrs.iter().find(|(kind, _)| *kind == attr_type) else {
        return Ok(None);
    };
    if data.len() != WG_KEY_LEN {
        return Err(err(SyscallError::EINVAL));
    }
    let mut key = [0u8; WG_KEY_LEN];
    key.copy_from_slice(data);
    Ok(Some(key))
}

/// WireGuard 公钥就是 X25519 私钥对应的公钥。
fn derive_public_key(private_key: [u8; WG_KEY_LEN]) -> Option<[u8; WG_KEY_LEN]> {
    wireguard_crypto::public_key_from_private(private_key)
}

/// 预计算本机静态私钥和 peer 静态公钥的 X25519 共享值，握手时复用。
fn precompute_static_static(
    private_key: Option<[u8; WG_KEY_LEN]>,
    peer_public_key: [u8; WG_KEY_LEN],
) -> Option<[u8; WG_KEY_LEN]> {
    private_key.and_then(|key| wireguard_crypto::x25519_shared_secret(key, peer_public_key))
}

/// 分配本端 sender index，跳过 WireGuard 保留的 0。
fn fresh_sender_index() -> u32 {
    loop {
        let index = WG_INDEX_COUNTER.fetch_add(1, Ordering::Relaxed);
        if index != 0 {
            return index;
        }
    }
}

/// 用新 session 替换旧 session。
///
/// 握手完成的 session 会替换同 peer 的其它 session；握手进行中的 session 只替换相同 index。
fn replace_session(session: WireguardPeerSession) {
    let mut sessions = WIREGUARD_SESSIONS.lock();
    sessions.retain(|old| {
        if old.ifindex != session.ifindex || old.peer_public_key != session.peer_public_key {
            return true;
        }
        if session.keypair.is_some() {
            return false;
        }
        old.local_index != session.local_index
    });
    sessions.push(session);
}

/// 避免同一个 peer 在短时间内因为多个数据包反复触发 handshake initiation。
fn has_recent_pending_handshake(ifindex: i32, peer_public_key: [u8; WG_KEY_LEN]) -> bool {
    let now = crate::time::get_time_ms();
    WIREGUARD_SESSIONS.lock().iter().any(|session| {
        session.ifindex == ifindex
            && session.peer_public_key == peer_public_key
            && session.keypair.is_none()
            && now.saturating_sub(session.created_ms) < WG_HANDSHAKE_RETRY_MS
    })
}

/// 握手还没完成时缓存内层 IP 包。
///
/// 超过 per-peer/global 上限时丢最老的包，保证错误配置不会无限占内存。
fn queue_pending_data(
    ifindex: i32,
    peer_public_key: [u8; WG_KEY_LEN],
    ns_id: usize,
    packet: &[u8],
) {
    let mut pending = WIREGUARD_PENDING_DATA.lock();
    let peer_pending = pending
        .iter()
        .filter(|item| item.ifindex == ifindex && item.peer_public_key == peer_public_key)
        .count();
    if peer_pending >= WG_PENDING_DATA_PER_PEER_LIMIT
        && let Some(pos) = pending
            .iter()
            .position(|item| item.ifindex == ifindex && item.peer_public_key == peer_public_key)
    {
        // 同 peer 超限时先丢这个 peer 最早的包，避免一个 peer 挤爆全局队列。
        pending.remove(pos);
    }
    while pending.len() >= WG_PENDING_DATA_GLOBAL_LIMIT {
        pending.pop_front();
    }
    pending.push_back(WireguardPendingData {
        ifindex,
        peer_public_key,
        ns_id,
        packet: packet.to_vec(),
    });
}

/// 取出某个 peer 上所有等待握手完成的内层包。
fn take_pending_data(ifindex: i32, peer_public_key: [u8; WG_KEY_LEN]) -> Vec<WireguardPendingData> {
    let mut pending = WIREGUARD_PENDING_DATA.lock();
    let mut selected = Vec::new();
    let mut retained = VecDeque::new();
    while let Some(item) = pending.pop_front() {
        if item.ifindex == ifindex && item.peer_public_key == peer_public_key {
            selected.push(item);
        } else {
            retained.push_back(item);
        }
    }
    *pending = retained;
    selected
}

/// 握手成功后重放 pending 内层包，让它们重新走一次 WireGuard 封装路径。
fn flush_pending_data(ifindex: i32, peer_public_key: [u8; WG_KEY_LEN]) {
    for pending in take_pending_data(ifindex, peer_public_key) {
        match pending.packet.first().map(|byte| byte >> 4) {
            Some(4) => {
                let _ = encapsulate_outbound_ipv4(pending.ns_id, &pending.packet);
            }
            Some(6) => {
                let _ = encapsulate_outbound_ipv6(pending.ns_id, &pending.packet);
            }
            _ => {}
        }
    }
}

/// 更新 peer 的 `wg show` 流量统计。
fn add_peer_bytes(ifindex: i32, peer_public_key: [u8; WG_KEY_LEN], rx: usize, tx: usize) {
    let mut configs = WIREGUARD_CONFIGS.lock();
    let Some(cfg) = configs.iter_mut().find(|cfg| cfg.ifindex == ifindex) else {
        return;
    };
    let Some(peer) = cfg
        .peers
        .iter_mut()
        .find(|peer| peer.public_key == peer_public_key)
    else {
        return;
    };
    peer.rx_bytes = peer.rx_bytes.saturating_add(rx as u64);
    peer.tx_bytes = peer.tx_bytes.saturating_add(tx as u64);
}

/// 配置里的 peer 被删除后，对应 session 也必须失效。
fn prune_sessions_for_config(cfg: &WireguardDeviceConfig) {
    let ifindex = cfg.ifindex;
    let peers = cfg
        .peers
        .iter()
        .map(|peer| peer.public_key)
        .collect::<Vec<_>>();
    WIREGUARD_SESSIONS
        .lock()
        .retain(|session| session.ifindex != ifindex || peers.contains(&session.peer_public_key));
}

/// 私钥或 peer 变化后，重新计算握手要用的 static-static 共享值。
fn refresh_peer_precomputed_keys(cfg: &mut WireguardDeviceConfig) {
    for peer in &mut cfg.peers {
        peer.precomputed_static_static = precompute_static_static(cfg.private_key, peer.public_key);
    }
}

/// 读取单字节 netlink attr，比如 CIDR mask。
fn read_u8_attr_checked(attrs: &[(u16, Vec<u8>)], attr_type: u16) -> Result<Option<u8>, isize> {
    let Some((_, data)) = attrs.iter().find(|(kind, _)| *kind == attr_type) else {
        return Ok(None);
    };
    if data.len() != 1 {
        return Err(err(SyscallError::EINVAL));
    }
    Ok(Some(data[0]))
}

/// 从 WGDEVICE_A_IFINDEX 或 WGDEVICE_A_IFNAME 找到目标 netdev，并校验它确实是 wg 设备。
fn read_target(attrs: &[(u16, Vec<u8>)]) -> Result<NetDeviceSnapshot, isize> {
    let by_index = read_u32_attr_checked(attrs, WGDEVICE_A_IFINDEX)?
        .and_then(|ifindex| netdev::device_snapshot_by_index(ifindex as i32));
    let dev = if let Some(dev) = by_index {
        dev
    } else if let Some(name) = read_string_attr(attrs, WGDEVICE_A_IFNAME) {
        netdev::device_snapshot_by_name(name).ok_or(err(SyscallError::ENODEV))?
    } else {
        return Err(err(SyscallError::ENODEV));
    };
    if dev.kind != NetDeviceKind::Wireguard {
        return Err(err(SyscallError::ENODEV));
    }
    Ok(dev)
}

/// 解析 peer 下嵌套的 allowed-ips 列表。
fn parse_allowed_ips(data: &[u8]) -> Result<Vec<WireguardAllowedIpConfig>, isize> {
    let mut out = Vec::new();
    let entries = parse_rtattrs_checked(data)?;
    for (_, entry) in entries {
        let attrs = parse_rtattrs_checked(&entry)?;
        let family = read_u16_attr_checked(&attrs, WGALLOWEDIP_A_FAMILY)?
            .ok_or(err(SyscallError::EINVAL))?;
        let addr = attrs
            .iter()
            .find(|(kind, _)| *kind == WGALLOWEDIP_A_IPADDR)
            .map(|(_, data)| data.clone())
            .ok_or(err(SyscallError::EINVAL))?;
        let cidr = read_u8_attr_checked(&attrs, WGALLOWEDIP_A_CIDR_MASK)?
            .ok_or(err(SyscallError::EINVAL))?;
        let flags = read_u32_attr_checked(&attrs, WGALLOWEDIP_A_FLAGS)?.unwrap_or(0);
        if (flags & !WGALLOWEDIP_F_REMOVE_ME) != 0 {
            return Err(err(SyscallError::EINVAL));
        }
        if !matches!(family, AF_INET | AF_INET6) {
            return Err(err(SyscallError::EAFNOSUPPORT));
        }
        if (family == AF_INET && addr.len() != 4) || (family == AF_INET6 && addr.len() != 16) {
            return Err(err(SyscallError::EINVAL));
        }
        if (family == AF_INET && cidr > 32) || (family == AF_INET6 && cidr > 128) {
            return Err(err(SyscallError::EINVAL));
        }
        out.push(WireguardAllowedIpConfig {
            family,
            addr,
            cidr,
            remove: (flags & WGALLOWEDIP_F_REMOVE_ME) != 0,
        });
    }
    Ok(out)
}

/// 解析 peer endpoint。为了回显 `wg show`，这里保留 sockaddr 的原始字节布局。
fn parse_endpoint(data: &[u8]) -> Result<Option<WireguardEndpoint>, isize> {
    if data.len() < SOCKADDR_IN_LEN {
        return Err(err(SyscallError::EINVAL));
    }
    let family = u16::from_ne_bytes([data[0], data[1]]);
    if data.len() == SOCKADDR_IN_LEN && family == AF_INET {
        let mut bytes = [0u8; SOCKADDR_IN_LEN];
        bytes.copy_from_slice(data);
        Ok(Some(WireguardEndpoint::Ipv4(bytes)))
    } else if data.len() == SOCKADDR_IN6_LEN && family == AF_INET6 {
        let mut bytes = [0u8; SOCKADDR_IN6_LEN];
        bytes.copy_from_slice(data);
        Ok(Some(WireguardEndpoint::Ipv6(bytes)))
    } else {
        Ok(None)
    }
}

/// 判断两个 allowed-ip 是否指向同一个 family/address/prefix。
fn same_allowed_ip(a: &WireguardAllowedIpConfig, b: &WireguardAllowedIpConfig) -> bool {
    a.family == b.family && a.cidr == b.cidr && a.addr == b.addr
}

/// 按 Linux `wg set` 语义增删 allowed-ip。
fn apply_allowed_ip_update(
    allowed_ips: &mut Vec<WireguardAllowedIpConfig>,
    update: WireguardAllowedIpConfig,
) {
    if update.remove {
        allowed_ips.retain(|old| !same_allowed_ip(old, &update));
        return;
    }
    if !allowed_ips.iter().any(|old| same_allowed_ip(old, &update)) {
        allowed_ips.push(update);
    }
}

/// 解析一个 peer 的 nested netlink attr，并把 flags 单独返回给上层应用更新语义。
fn parse_peer(data: &[u8]) -> Result<(WireguardPeerConfig, u32), isize> {
    let attrs = parse_rtattrs_checked(data)?;
    let public_key =
        read_key_attr(&attrs, WGPEER_A_PUBLIC_KEY)?.ok_or(err(SyscallError::EINVAL))?;
    let preshared_key = read_key_attr(&attrs, WGPEER_A_PRESHARED_KEY)?;
    let flags = read_u32_attr_checked(&attrs, WGPEER_A_FLAGS)?.unwrap_or(0);
    if (flags & !(WGPEER_F_REMOVE_ME | WGPEER_F_REPLACE_ALLOWEDIPS | WGPEER_F_UPDATE_ONLY)) != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    if read_u32_attr_checked(&attrs, WGPEER_A_PROTOCOL_VERSION)?.is_some_and(|version| version != 1)
    {
        return Err(err(SyscallError::EPFNOSUPPORT));
    }
    let endpoint =
        if let Some((_, data)) = attrs.iter().find(|(kind, _)| *kind == WGPEER_A_ENDPOINT) {
            parse_endpoint(data)?
        } else {
            None
        };
    let persistent_keepalive =
        read_u16_attr_checked(&attrs, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL)?;
    let allowed_ips =
        if let Some((_, data)) = attrs.iter().find(|(kind, _)| *kind == WGPEER_A_ALLOWEDIPS) {
            parse_allowed_ips(data)?
        } else {
            Vec::new()
        };
    Ok((
        WireguardPeerConfig {
            public_key,
            preshared_key,
            precomputed_static_static: None,
            latest_handshake_timestamp: [0; wireguard_crypto::NOISE_TIMESTAMP_LEN],
            endpoint,
            persistent_keepalive,
            allowed_ips,
            rx_bytes: 0,
            tx_bytes: 0,
        },
        flags,
    ))
}

/// 应用 `WG_CMD_SET_DEVICE`。
///
/// 这个函数只维护配置面状态，不直接创建 netdev；netdev 已经由 `ip link add ... type wireguard`
/// 那条路径创建，这里根据 ifindex/ifname 找到它后写入 key、listen-port、peer 和 allowed-ips。
fn apply_set_device(attrs: &[(u16, Vec<u8>)]) -> Result<(), isize> {
    let dev = read_target(attrs)?;
    let flags = read_u32_attr_checked(attrs, WGDEVICE_A_FLAGS)?.unwrap_or(0);
    if (flags & !WGDEVICE_F_REPLACE_PEERS) != 0 {
        return Err(err(SyscallError::EINVAL));
    }
    let private_key = read_key_attr(attrs, WGDEVICE_A_PRIVATE_KEY)?;
    let listen_port = read_u16_attr_checked(attrs, WGDEVICE_A_LISTEN_PORT)?;
    let fwmark = read_u32_attr_checked(attrs, WGDEVICE_A_FWMARK)?;
    let mut configs = WIREGUARD_CONFIGS.lock();
    let pos = configs
        .iter()
        .position(|cfg| cfg.ifindex == dev.ifindex)
        .unwrap_or_else(|| {
            configs.push(WireguardDeviceConfig {
                ifindex: dev.ifindex,
                ifname: dev.name.clone(),
                private_key: None,
                public_key: None,
                listen_port: None,
                fwmark: None,
                peers: Vec::new(),
            });
            configs.len() - 1
        });
    let cfg = &mut configs[pos];
    cfg.ifname = dev.name.clone();
    if let Some(key) = private_key {
        // Linux 把全 0 private key 当作清空设备身份。
        cfg.public_key = derive_public_key(key);
        cfg.private_key = cfg.public_key.map(|_| key);
        if let Some(public_key) = cfg.public_key {
            // 不能把自己的 public key 配成 peer。
            cfg.peers.retain(|peer| peer.public_key != public_key);
        }
        refresh_peer_precomputed_keys(cfg);
        if cfg.private_key.is_none() {
            // 身份被清空后，旧 session 的密钥都不再有效。
            WIREGUARD_SESSIONS
                .lock()
                .retain(|session| session.ifindex != cfg.ifindex);
        }
    }
    if listen_port.is_some() {
        cfg.listen_port = listen_port;
    }
    if fwmark.is_some() {
        cfg.fwmark = fwmark;
    }
    if (flags & WGDEVICE_F_REPLACE_PEERS) != 0 {
        cfg.peers.clear();
    }
    if let Some((_, peers_data)) = attrs.iter().find(|(kind, _)| *kind == WGDEVICE_A_PEERS) {
        for (_, peer_data) in parse_rtattrs_checked(peers_data)? {
            let (peer, peer_flags) = parse_peer(&peer_data)?;
            let existing = cfg
                .peers
                .iter()
                .position(|old| old.public_key == peer.public_key);
            if (peer_flags & WGPEER_F_REMOVE_ME) != 0 {
                if let Some(pos) = existing {
                    cfg.peers.remove(pos);
                }
                continue;
            }
            if cfg.public_key == Some(peer.public_key) {
                // Linux 不允许把本机身份加成 peer；这里选择静默忽略。
                continue;
            }
            match existing {
                Some(pos) => {
                    let old = &mut cfg.peers[pos];
                    old.preshared_key = peer.preshared_key.or(old.preshared_key);
                    old.precomputed_static_static =
                        precompute_static_static(cfg.private_key, old.public_key);
                    old.endpoint = peer.endpoint.or_else(|| old.endpoint.clone());
                    old.persistent_keepalive =
                        peer.persistent_keepalive.or(old.persistent_keepalive);
                    if (peer_flags & WGPEER_F_REPLACE_ALLOWEDIPS) != 0 {
                        old.allowed_ips.clear();
                    }
                    for allowed_ip in peer.allowed_ips {
                        apply_allowed_ip_update(&mut old.allowed_ips, allowed_ip);
                    }
                }
                None if (peer_flags & WGPEER_F_UPDATE_ONLY) != 0 => {
                    return Err(err(SyscallError::ENOENT));
                }
                None => {
                    let mut peer = peer;
                    peer.allowed_ips.retain(|allowed_ip| !allowed_ip.remove);
                    peer.precomputed_static_static =
                        precompute_static_static(cfg.private_key, peer.public_key);
                    cfg.peers.push(peer);
                }
            }
        }
    }
    prune_sessions_for_config(cfg);
    Ok(())
}

/// 主动端构造 handshake initiation。
///
/// 这个包还不是普通数据包；它会作为 WireGuard UDP payload 发给 peer，等待对方回 response。
#[allow(dead_code)]
pub(super) fn prepare_handshake_initiation(
    ifindex: i32,
    peer_public_key: [u8; WG_KEY_LEN],
) -> Option<Vec<u8>> {
    let (local_public, precomputed_static_static) = {
        let configs = WIREGUARD_CONFIGS.lock();
        let cfg = configs.iter().find(|cfg| cfg.ifindex == ifindex)?;
        let local_public = cfg.public_key?;
        let peer = cfg
            .peers
            .iter()
            .find(|peer| peer.public_key == peer_public_key)?;
        (local_public, peer.precomputed_static_static?)
    };

    let sender_index = fresh_sender_index();
    let (initiation, state, ephemeral_private) = wireguard_crypto::create_handshake_initiation(
        local_public,
        peer_public_key,
        precomputed_static_static,
        sender_index,
    )?;
    let mut packet = wireguard_crypto::build_handshake_initiation(&initiation);
    let mac1_key = wireguard_crypto::message_mac1_key(&peer_public_key);
    wireguard_crypto::apply_mac1(&mut packet, &mac1_key)?;
    // 保存中间状态；response 回来时要用它派生最终收发密钥。
    replace_session(WireguardPeerSession {
        ifindex,
        peer_public_key,
        local_index: sender_index,
        pending_state: Some(state),
        pending_ephemeral_private: Some(ephemeral_private),
        keypair: None,
        created_ms: crate::time::get_time_ms(),
    });
    Some(packet)
}

/// 处理外层 UDP payload 里的 WireGuard 握手包。
#[allow(dead_code)]
pub(super) fn handle_handshake_packet(ifindex: i32, packet: &[u8]) -> Option<Vec<u8>> {
    match wireguard_crypto::message_type(packet)? {
        wireguard_crypto::WireguardMessageType::HandshakeInitiation => {
            handle_handshake_initiation(ifindex, packet)
        }
        wireguard_crypto::WireguardMessageType::HandshakeResponse => {
            handle_handshake_response(ifindex, packet);
            None
        }
        _ => None,
    }
}

/// 被动端消费 handshake initiation，并返回 handshake response。
fn handle_handshake_initiation(ifindex: i32, packet: &[u8]) -> Option<Vec<u8>> {
    let msg = wireguard_crypto::parse_handshake_initiation(packet)?;
    let mut configs = WIREGUARD_CONFIGS.lock();
    let cfg = configs.iter_mut().find(|cfg| cfg.ifindex == ifindex)?;
    let local_private = cfg.private_key?;
    let local_public = cfg.public_key?;
    let local_mac1_key = wireguard_crypto::message_mac1_key(&local_public);
    if !wireguard_crypto::validate_mac1(packet, &local_mac1_key) {
        return None;
    }

    // initiation 包里没有明文 peer 身份；要逐个 peer 尝试 Noise 解密来确认来源。
    for peer in &mut cfg.peers {
        let Some(precomputed_static_static) = peer.precomputed_static_static else {
            continue;
        };
        let Some(initiation) = wireguard_crypto::consume_handshake_initiation_for_peer(
            &msg,
            local_private,
            local_public,
            peer.public_key,
            precomputed_static_static,
            &peer.latest_handshake_timestamp,
        ) else {
            continue;
        };
        peer.latest_handshake_timestamp = initiation.timestamp;
        let preshared_key = peer.preshared_key.unwrap_or([0; WG_KEY_LEN]);
        let sender_index = fresh_sender_index();
        let (response, response_state, _ephemeral_private) =
            wireguard_crypto::create_handshake_response(&initiation, preshared_key, sender_index)?;
        let keypair =
            wireguard_crypto::derive_keypair(&response_state.chaining_key, msg.sender_index, false);
        let mut response_packet = wireguard_crypto::build_handshake_response(&response);
        let peer_mac1_key = wireguard_crypto::message_mac1_key(&peer.public_key);
        wireguard_crypto::apply_mac1(&mut response_packet, &peer_mac1_key)?;
        // 被动端在发 response 时已经能得到会话密钥，后续可以直接解密数据包。
        replace_session(WireguardPeerSession {
            ifindex,
            peer_public_key: peer.public_key,
            local_index: sender_index,
            pending_state: None,
            pending_ephemeral_private: None,
            keypair: Some(keypair),
            created_ms: crate::time::get_time_ms(),
        });
        return Some(response_packet);
    }
    None
}

/// 主动端消费 handshake response，并把 pending session 升级为可收发数据的 session。
fn handle_handshake_response(ifindex: i32, packet: &[u8]) -> Option<()> {
    let msg = wireguard_crypto::parse_handshake_response(packet)?;
    let session = {
        WIREGUARD_SESSIONS
            .lock()
            .iter()
            .find(|session| session.ifindex == ifindex && session.local_index == msg.receiver_index)
            .cloned()?
    };
    let (local_private, local_public, preshared_key) = {
        let configs = WIREGUARD_CONFIGS.lock();
        let cfg = configs.iter().find(|cfg| cfg.ifindex == ifindex)?;
        let peer = cfg
            .peers
            .iter()
            .find(|peer| peer.public_key == session.peer_public_key)?;
        (
            cfg.private_key?,
            cfg.public_key?,
            peer.preshared_key.unwrap_or([0; WG_KEY_LEN]),
        )
    };
    let local_mac1_key = wireguard_crypto::message_mac1_key(&local_public);
    if !wireguard_crypto::validate_mac1(packet, &local_mac1_key) {
        return None;
    }
    let state = session.pending_state?;
    let ephemeral_private = session.pending_ephemeral_private?;
    let consumed = wireguard_crypto::consume_handshake_response(
        &msg,
        state,
        local_private,
        ephemeral_private,
        preshared_key,
    )?;
    let keypair =
        wireguard_crypto::derive_keypair(&consumed.state.chaining_key, msg.sender_index, true);
    {
        let mut sessions = WIREGUARD_SESSIONS.lock();
        if let Some(slot) = sessions.iter_mut().find(|old| {
            old.ifindex == ifindex
                && old.local_index == msg.receiver_index
                && old.peer_public_key == session.peer_public_key
        }) {
            slot.keypair = Some(keypair);
            slot.pending_state = None;
            slot.pending_ephemeral_private = None;
            slot.created_ms = crate::time::get_time_ms();
        } else {
            return None;
        }
        sessions.retain(|old| {
            old.ifindex != ifindex
                || old.peer_public_key != session.peer_public_key
                || old.local_index == msg.receiver_index
        });
    }
    // 之前因为缺 session 被暂存的内层包，现在重新封装发送。
    flush_pending_data(ifindex, session.peer_public_key);
    Some(())
}

/// 用已完成的 session 把内层 IP 包加密成 WireGuard data message。
#[allow(dead_code)]
pub(super) fn encrypt_data_for_peer(
    ifindex: i32,
    peer_public_key: [u8; WG_KEY_LEN],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let packet = {
        let mut sessions = WIREGUARD_SESSIONS.lock();
        let session = sessions.iter_mut().find(|session| {
            session.ifindex == ifindex
                && session.peer_public_key == peer_public_key
                && session.keypair.is_some()
        })?;
        let keypair = session.keypair.as_mut()?;
        // 每个 data message 使用单调递增 counter；对端会用它做重放保护。
        let counter = keypair.next_sending_counter()?;
        let padded = wireguard_crypto::pad_data_plaintext(plaintext);
        let encrypted = wireguard_crypto::aead_encrypt(&padded, &[], counter, &keypair.sending.key);
        wireguard_crypto::build_data_packet(keypair.remote_index, counter, &encrypted)
    };
    add_peer_bytes(ifindex, peer_public_key, 0, plaintext.len());
    Some(packet)
}

/// 解密入站 WireGuard data message，返回 peer 和解出的内层 IP 包。
#[allow(dead_code)]
pub(super) fn decrypt_data_packet(
    ifindex: i32,
    packet: &[u8],
) -> Option<([u8; WG_KEY_LEN], Vec<u8>)> {
    let data = wireguard_crypto::parse_data_packet(packet)?;
    let (peer_public_key, plaintext) = {
        let mut sessions = WIREGUARD_SESSIONS.lock();
        let session = sessions.iter_mut().find(|session| {
            session.ifindex == ifindex
                && session.local_index == data.key_idx
                && session.keypair.is_some()
        })?;
        let peer_public_key = session.peer_public_key;
        let keypair = session.keypair.as_mut()?;
        let plaintext = wireguard_crypto::aead_decrypt(
            data.encrypted_payload,
            &[],
            data.counter,
            &keypair.receiving.key,
        )?;
        if !keypair.receiving_counter.validate(data.counter) {
            // counter 校验失败说明这是重放包或乱序超出窗口，直接丢弃。
            return None;
        }
        (peer_public_key, plaintext)
    };
    add_peer_bytes(ifindex, peer_public_key, plaintext.len(), 0);
    Some((peer_public_key, plaintext))
}

/// 出站 IPv4 数据面入口。
///
/// smoltcp/loopback 生成一个完整内层 IPv4 包后会先调用这里；如果目标地址命中
/// WireGuard allowed-ips，本函数负责握手、加密、封装成外层 UDP/IPv4 包并交给 veth。
/// 返回 true 表示包已经被 WireGuard 接管，调用者不应再把原包放回 lo。
pub(crate) fn encapsulate_outbound_ipv4(ns_id: usize, packet: &[u8]) -> bool {
    let Some(info) = parse_ipv4_packet_info(packet) else {
        return false;
    };
    let Some(target) = route_for_inner_ipv4(ns_id, info.dst) else {
        return false;
    };
    let Some(endpoint) = target
        .endpoint
        .as_ref()
        .and_then(|endpoint| endpoint.ipv4_addr_port())
    else {
        // 命中了 wg 路由但没有可用 endpoint：按“已由 wg 接管”处理，避免本地 lo 泄漏。
        return true;
    };
    let Some(listen_port) = target.listen_port else {
        // 没有 listen-port 时也不能退回 lo，否则语义会变成绕过隧道。
        return true;
    };

    let inner = &packet[..info.total_len];
    let payload = if let Some(encrypted) =
        encrypt_data_for_peer(target.ifindex, target.peer_public_key, inner)
    {
        Some(encrypted)
    } else {
        // 首包通常发生在握手前：先缓存内层包，再发 handshake initiation。
        queue_pending_data(target.ifindex, target.peer_public_key, ns_id, inner);
        if has_recent_pending_handshake(target.ifindex, target.peer_public_key) {
            None
        } else {
            prepare_handshake_initiation(target.ifindex, target.peer_public_key)
        }
    };
    let Some(payload) = payload else {
        return true;
    };
    let Some(src_ip) = netdev::select_ipv4_source_addr_in_namespace(ns_id, endpoint.0) else {
        return true;
    };
    let Some(outer) = build_udp_ipv4_packet(src_ip, endpoint.0, listen_port, endpoint.1, &payload)
    else {
        return true;
    };
    // 当前测试拓扑里外层包走 veth 到 peer namespace。
    let _ = crate::net::queue_veth_ipv4_delivery(ns_id, &outer);
    true
}

/// 出站 IPv6 数据面入口。
///
/// 内层可以是 IPv6，但当前 endpoint 仍只支持 IPv4 UDP 外层，因此后面同样构造 IPv4/UDP 包。
pub(crate) fn encapsulate_outbound_ipv6(ns_id: usize, packet: &[u8]) -> bool {
    let Some(info) = parse_ipv6_packet_info(packet) else {
        return false;
    };
    let Some(target) = route_for_inner_ipv6(ns_id, info.dst) else {
        return false;
    };
    let Some(endpoint) = target
        .endpoint
        .as_ref()
        .and_then(|endpoint| endpoint.ipv4_addr_port())
    else {
        // 命中了 wg 路由但没有可用 endpoint：包由 wg 消费，不回退 lo。
        return true;
    };
    let Some(listen_port) = target.listen_port else {
        // 没有外层源端口时无法发送，但也不能让内层包绕过 wg。
        return true;
    };

    let inner = &packet[..info.total_len];
    let payload = if let Some(encrypted) =
        encrypt_data_for_peer(target.ifindex, target.peer_public_key, inner)
    {
        Some(encrypted)
    } else {
        // 和 IPv4 一样，握手完成前先缓存内层包。
        queue_pending_data(target.ifindex, target.peer_public_key, ns_id, inner);
        if has_recent_pending_handshake(target.ifindex, target.peer_public_key) {
            None
        } else {
            prepare_handshake_initiation(target.ifindex, target.peer_public_key)
        }
    };
    let Some(payload) = payload else {
        return true;
    };
    let Some(src_ip) = netdev::select_ipv4_source_addr_in_namespace(ns_id, endpoint.0) else {
        return true;
    };
    let Some(outer) = build_udp_ipv4_packet(src_ip, endpoint.0, listen_port, endpoint.1, &payload)
    else {
        return true;
    };
    // 外层仍是 IPv4 UDP，交给 veth 模拟跨 namespace 发送。
    let _ = crate::net::queue_veth_ipv4_delivery(ns_id, &outer);
    true
}

/// 入站 IPv4 数据面入口。
///
/// veth 收到外层 UDP/IPv4 包后调用这里；如果目的端口对应某个 wg 设备，就消费
/// WireGuard payload。握手包返回空 Vec 表示“已处理但没有内层包”；data 包解密后返回内层 IP 包。
pub(crate) fn handle_inbound_ipv4_packet(ns_id: usize, packet: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (info, src_port, dst_port, payload) = parse_udp_ipv4_payload(packet)?;
    let ifindex = wireguard_ifindex_for_listen_port(ns_id, dst_port)?;
    match wireguard_crypto::message_type(payload) {
        Some(wireguard_crypto::WireguardMessageType::HandshakeInitiation)
        | Some(wireguard_crypto::WireguardMessageType::HandshakeResponse) => {
            if let Some(response) = handle_handshake_packet(ifindex, payload) {
                if let Some(packet) =
                    build_udp_ipv4_packet(info.dst, info.src, dst_port, src_port, &response)
                {
                    // initiation 需要回 response；response 自身只更新 session 状态。
                    let _ = crate::net::queue_veth_ipv4_delivery(ns_id, &packet);
                }
            }
            Some(Vec::new())
        }
        Some(wireguard_crypto::WireguardMessageType::Data) => {
            let Some((peer_public_key, plaintext)) = decrypt_data_packet(ifindex, payload) else {
                return Some(Vec::new());
            };
            match plaintext.first().map(|byte| byte >> 4) {
                Some(4) => {
                    // 入站内层源地址必须被该 peer 的 allowed-ips 覆盖，防止 peer 伪造来源。
                    if !peer_allows_inner_ipv4_source(ifindex, peer_public_key, &plaintext) {
                        return Some(Vec::new());
                    }
                    let inner = trim_ipv4_packet(&plaintext)?.to_vec();
                    Some(alloc::vec![inner])
                }
                Some(6) => {
                    // IPv6 内层包同样做 allowed-ips 源地址校验。
                    if !peer_allows_inner_ipv6_source(ifindex, peer_public_key, &plaintext) {
                        return Some(Vec::new());
                    }
                    let inner = trim_ipv6_packet(&plaintext)?.to_vec();
                    Some(alloc::vec![inner])
                }
                _ => Some(Vec::new()),
            }
        }
        Some(wireguard_crypto::WireguardMessageType::HandshakeCookie) | None => Some(Vec::new()),
    }
}

/// 根据内层 IPv4 目的地址查找 wg 路由。
///
/// WireGuard 没有传统下一跳表，allowed-ips 就是它的路由表；多个 peer 匹配时选最长前缀。
fn route_for_inner_ipv4(ns_id: usize, dst: [u8; 4]) -> Option<WireguardRouteTarget> {
    let configs = WIREGUARD_CONFIGS.lock().clone();
    let mut best: Option<WireguardRouteTarget> = None;
    for cfg in configs.iter() {
        let Some(dev) = netdev::device_snapshot_by_index_in_namespace(ns_id, cfg.ifindex) else {
            continue;
        };
        if dev.kind != NetDeviceKind::Wireguard || (dev.flags & netdev::IFF_UP) == 0 {
            // 只有当前 netns 中 UP 状态的 wg 设备能参与路由。
            continue;
        }
        for peer in &cfg.peers {
            for allowed in &peer.allowed_ips {
                if allowed.remove
                    || allowed.family != AF_INET
                    || allowed.addr.len() != 4
                    || !prefix_matches(&allowed.addr, &dst, allowed.cidr)
                {
                    continue;
                }
                if best
                    .as_ref()
                    .map_or(true, |current| allowed.cidr > current.allowed_cidr)
                {
                    best = Some(WireguardRouteTarget {
                        ifindex: cfg.ifindex,
                        peer_public_key: peer.public_key,
                        endpoint: peer.endpoint.clone(),
                        listen_port: cfg.listen_port,
                        allowed_cidr: allowed.cidr,
                    });
                }
            }
        }
    }
    best
}

/// 根据内层 IPv6 目的地址查找 wg 路由，规则同 IPv4。
fn route_for_inner_ipv6(ns_id: usize, dst: [u8; 16]) -> Option<WireguardRouteTarget> {
    let configs = WIREGUARD_CONFIGS.lock().clone();
    let mut best: Option<WireguardRouteTarget> = None;
    for cfg in configs.iter() {
        let Some(dev) = netdev::device_snapshot_by_index_in_namespace(ns_id, cfg.ifindex) else {
            continue;
        };
        if dev.kind != NetDeviceKind::Wireguard || (dev.flags & netdev::IFF_UP) == 0 {
            // 设备不在本 namespace 或未 UP 时不参与匹配。
            continue;
        }
        for peer in &cfg.peers {
            for allowed in &peer.allowed_ips {
                if allowed.remove
                    || allowed.family != AF_INET6
                    || allowed.addr.len() != 16
                    || !prefix_matches(&allowed.addr, &dst, allowed.cidr)
                {
                    continue;
                }
                if best
                    .as_ref()
                    .map_or(true, |current| allowed.cidr > current.allowed_cidr)
                {
                    best = Some(WireguardRouteTarget {
                        ifindex: cfg.ifindex,
                        peer_public_key: peer.public_key,
                        endpoint: peer.endpoint.clone(),
                        listen_port: cfg.listen_port,
                        allowed_cidr: allowed.cidr,
                    });
                }
            }
        }
    }
    best
}

/// 校验解密后的 IPv4 内层包来源是否属于该 peer 的 allowed-ips。
fn peer_allows_inner_ipv4_source(
    ifindex: i32,
    peer_public_key: [u8; WG_KEY_LEN],
    packet: &[u8],
) -> bool {
    let Some(info) = parse_ipv4_packet_info(packet) else {
        return false;
    };
    let configs = WIREGUARD_CONFIGS.lock();
    let Some(cfg) = configs.iter().find(|cfg| cfg.ifindex == ifindex) else {
        return false;
    };
    let Some(peer) = cfg
        .peers
        .iter()
        .find(|peer| peer.public_key == peer_public_key)
    else {
        return false;
    };
    peer.allowed_ips.iter().any(|allowed| {
        !allowed.remove
            && allowed.family == AF_INET
            && allowed.addr.len() == 4
            && prefix_matches(&allowed.addr, &info.src, allowed.cidr)
    })
}

/// 校验解密后的 IPv6 内层包来源是否属于该 peer 的 allowed-ips。
fn peer_allows_inner_ipv6_source(
    ifindex: i32,
    peer_public_key: [u8; WG_KEY_LEN],
    packet: &[u8],
) -> bool {
    let Some(info) = parse_ipv6_packet_info(packet) else {
        return false;
    };
    let configs = WIREGUARD_CONFIGS.lock();
    let Some(cfg) = configs.iter().find(|cfg| cfg.ifindex == ifindex) else {
        return false;
    };
    let Some(peer) = cfg
        .peers
        .iter()
        .find(|peer| peer.public_key == peer_public_key)
    else {
        return false;
    };
    peer.allowed_ips.iter().any(|allowed| {
        !allowed.remove
            && allowed.family == AF_INET6
            && allowed.addr.len() == 16
            && prefix_matches(&allowed.addr, &info.src, allowed.cidr)
    })
}

/// 根据外层 UDP 目的端口找到接收该包的 wg 设备。
fn wireguard_ifindex_for_listen_port(ns_id: usize, dst_port: u16) -> Option<i32> {
    let configs = WIREGUARD_CONFIGS.lock().clone();
    configs.iter().find_map(|cfg| {
        if cfg.listen_port != Some(dst_port) || cfg.private_key.is_none() {
            return None;
        }
        let dev = netdev::device_snapshot_by_index_in_namespace(ns_id, cfg.ifindex)?;
        (dev.kind == NetDeviceKind::Wireguard && (dev.flags & netdev::IFF_UP) != 0)
            .then_some(cfg.ifindex)
    })
}

/// 解析 IPv4 头后数据面需要用到的字段。
#[derive(Clone, Copy)]
struct Ipv4PacketInfo {
    src: [u8; 4],
    dst: [u8; 4],
    header_len: usize,
    total_len: usize,
    protocol: u8,
}

/// 解析 IPv6 固定头后数据面需要用到的字段。
#[derive(Clone, Copy)]
struct Ipv6PacketInfo {
    src: [u8; 16],
    dst: [u8; 16],
    total_len: usize,
}

/// 轻量解析 IPv4 包，只做长度和版本校验，不处理分片/选项语义。
fn parse_ipv4_packet_info(packet: &[u8]) -> Option<Ipv4PacketInfo> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len || total_len > packet.len() {
        return None;
    }
    Some(Ipv4PacketInfo {
        src: [packet[12], packet[13], packet[14], packet[15]],
        dst: [packet[16], packet[17], packet[18], packet[19]],
        header_len,
        total_len,
        protocol: packet[9],
    })
}

/// 轻量解析 IPv6 包；当前只支持没有扩展头的基本长度提取。
fn parse_ipv6_packet_info(packet: &[u8]) -> Option<Ipv6PacketInfo> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = 40usize.checked_add(payload_len)?;
    if total_len > packet.len() {
        return None;
    }
    Some(Ipv6PacketInfo {
        src: packet[8..24].try_into().ok()?,
        dst: packet[24..40].try_into().ok()?,
        total_len,
    })
}

/// 从外层 IPv4 包中取出 UDP payload，也就是 WireGuard message。
fn parse_udp_ipv4_payload(packet: &[u8]) -> Option<(Ipv4PacketInfo, u16, u16, &[u8])> {
    let info = parse_ipv4_packet_info(packet)?;
    if info.protocol != IPPROTO_UDP as u8 {
        return None;
    }
    let udp_start = info.header_len;
    let udp = packet.get(udp_start..info.total_len)?;
    if udp.len() < 8 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    Some((
        info,
        u16::from_be_bytes([udp[0], udp[1]]),
        u16::from_be_bytes([udp[2], udp[3]]),
        &udp[8..udp_len],
    ))
}

/// 按 IPv4 header 里的 total length 截掉 padding。
fn trim_ipv4_packet(packet: &[u8]) -> Option<&[u8]> {
    let info = parse_ipv4_packet_info(packet)?;
    Some(&packet[..info.total_len])
}

/// 按 IPv6 payload length 截掉 padding。
fn trim_ipv6_packet(packet: &[u8]) -> Option<&[u8]> {
    let info = parse_ipv6_packet_info(packet)?;
    Some(&packet[..info.total_len])
}

/// 构造外层 IPv4/UDP 包。
///
/// WireGuard data/handshake message 作为 UDP payload；这里为了测试拓扑只补 IPv4 header checksum，
/// UDP checksum 仍为 0。
fn build_udp_ipv4_packet(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    let total_len = 20usize.checked_add(udp_len)?;
    if total_len > u16::MAX as usize {
        return None;
    }
    let mut packet = Vec::new();
    packet.resize(total_len, 0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = IPPROTO_UDP as u8;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // IPv4 下 UDP checksum 为 0 表示未使用；LTP veth 场景不依赖 UDP 校验和。
    packet[28..].copy_from_slice(payload);
    Some(packet)
}

/// IPv4 header checksum。
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add((byte as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 读取单设备配置；没有显式配置过的 wg 设备也要能被 `wg show` 看到。
fn config_for_request(
    attrs: &[(u16, Vec<u8>)],
) -> Result<(NetDeviceSnapshot, WireguardDeviceConfig), isize> {
    let dev = read_target(attrs)?;
    let configs = WIREGUARD_CONFIGS.lock();
    let cfg = configs
        .iter()
        .find(|cfg| cfg.ifindex == dev.ifindex)
        .cloned()
        .unwrap_or(WireguardDeviceConfig {
            ifindex: dev.ifindex,
            ifname: dev.name.clone(),
            private_key: None,
            public_key: None,
            listen_port: None,
            fwmark: None,
            peers: Vec::new(),
        });
    Ok((dev, cfg))
}

/// dump 当前所有 WireGuard netdev，并为未配置的设备补空配置。
fn configs_for_dump() -> Vec<(NetDeviceSnapshot, WireguardDeviceConfig)> {
    let configs = WIREGUARD_CONFIGS.lock();
    netdev::devices_snapshot()
        .into_iter()
        .filter(|dev| dev.kind == NetDeviceKind::Wireguard)
        .map(|dev| {
            let cfg = configs
                .iter()
                .find(|cfg| cfg.ifindex == dev.ifindex)
                .cloned()
                .unwrap_or(WireguardDeviceConfig {
                    ifindex: dev.ifindex,
                    ifname: dev.name.clone(),
                    private_key: None,
                    public_key: None,
                    listen_port: None,
                    fwmark: None,
                    peers: Vec::new(),
                });
            (dev, cfg)
        })
        .collect()
}

/// `WG_CMD_GET_DEVICE` 带 ifindex/ifname 时是单设备查询，否则是 dump。
fn request_has_target(attrs: &[(u16, Vec<u8>)]) -> bool {
    attrs
        .iter()
        .any(|(kind, _)| *kind == WGDEVICE_A_IFINDEX || *kind == WGDEVICE_A_IFNAME)
}

/// 构造 `WG_CMD_GET_DEVICE` 的 netlink 响应。
///
/// 输出结构需要和 Linux WireGuard ABI 对齐：device attr 下嵌套 peers，peer 下再嵌套 allowed-ips。
fn build_device_msg(
    dev: &NetDeviceSnapshot,
    cfg: &WireguardDeviceConfig,
    seq: u32,
    port_id: u32,
    flags: u16,
) -> Vec<u8> {
    let mut attrs = Vec::new();
    append_rtattr(
        &mut attrs,
        WGDEVICE_A_IFINDEX,
        &(dev.ifindex as u32).to_ne_bytes(),
    );
    let mut ifname = dev.name.as_bytes().to_vec();
    ifname.push(0);
    append_rtattr(&mut attrs, WGDEVICE_A_IFNAME, &ifname);
    if let Some(public_key) = cfg.public_key {
        append_rtattr(&mut attrs, WGDEVICE_A_PUBLIC_KEY, &public_key);
    }
    if let Some(port) = cfg.listen_port {
        append_rtattr(&mut attrs, WGDEVICE_A_LISTEN_PORT, &port.to_ne_bytes());
    }
    if let Some(fwmark) = cfg.fwmark {
        append_rtattr(&mut attrs, WGDEVICE_A_FWMARK, &fwmark.to_ne_bytes());
    }
    let mut peers = Vec::new();
    for (idx, peer) in cfg.peers.iter().enumerate() {
        let mut peer_attrs = Vec::new();
        append_rtattr(&mut peer_attrs, WGPEER_A_PUBLIC_KEY, &peer.public_key);
        if let Some(key) = peer.preshared_key {
            append_rtattr(&mut peer_attrs, WGPEER_A_PRESHARED_KEY, &key);
        }
        if let Some(endpoint) = &peer.endpoint {
            append_rtattr(
                &mut peer_attrs,
                WGPEER_A_ENDPOINT,
                endpoint.as_sockaddr_bytes(),
            );
        }
        if let Some(keepalive) = peer.persistent_keepalive {
            append_rtattr(
                &mut peer_attrs,
                WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                &keepalive.to_ne_bytes(),
            );
        }
        append_rtattr(&mut peer_attrs, WGPEER_A_LAST_HANDSHAKE_TIME, &[0u8; 16]);
        append_rtattr(
            &mut peer_attrs,
            WGPEER_A_RX_BYTES,
            &peer.rx_bytes.to_ne_bytes(),
        );
        append_rtattr(
            &mut peer_attrs,
            WGPEER_A_TX_BYTES,
            &peer.tx_bytes.to_ne_bytes(),
        );
        // netlink nested attr 的 type 通常用 1-based 序号承载数组元素。
        let mut allowed = Vec::new();
        for (allowed_idx, allowed_ip) in peer.allowed_ips.iter().enumerate() {
            let mut allowed_attrs = Vec::new();
            append_rtattr(
                &mut allowed_attrs,
                WGALLOWEDIP_A_FAMILY,
                &allowed_ip.family.to_ne_bytes(),
            );
            append_rtattr(&mut allowed_attrs, WGALLOWEDIP_A_IPADDR, &allowed_ip.addr);
            append_rtattr(
                &mut allowed_attrs,
                WGALLOWEDIP_A_CIDR_MASK,
                &[allowed_ip.cidr],
            );
            append_rtattr(
                &mut allowed,
                NLA_F_NESTED | (allowed_idx as u16 + 1),
                &allowed_attrs,
            );
        }
        if !allowed.is_empty() {
            append_rtattr(
                &mut peer_attrs,
                NLA_F_NESTED | WGPEER_A_ALLOWEDIPS,
                &allowed,
            );
        }
        append_rtattr(&mut peers, NLA_F_NESTED | (idx as u16 + 1), &peer_attrs);
    }
    if !peers.is_empty() {
        append_rtattr(&mut attrs, NLA_F_NESTED | WGDEVICE_A_PEERS, &peers);
    }
    build_genlmsg(
        GENL_FAMILY_ID,
        WG_CMD_GET_DEVICE,
        WG_GENL_VERSION as u8,
        seq,
        flags,
        port_id,
        &attrs,
    )
}
