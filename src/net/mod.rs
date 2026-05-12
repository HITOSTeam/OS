use alloc::vec;
use core::sync::atomic::{AtomicU16, Ordering};

use lazy_static::lazy_static;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Loopback, Medium},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};
use spin::Mutex;

// RFC 6335：临时端口范围 49152–65535，用于 connect() 时自动分配源端口。
const EPHEMERAL_START: u16 = 49152;
const EPHEMERAL_END: u16 = 65535;

// 全局唯一网络栈，用 Mutex 保护。当前仅支持回环接口（127.0.0.1/8）。
// 所有网络操作（socket 读写、状态机推进）都需要持有此锁，是 SMP 下的性能瓶颈。
lazy_static! {
    static ref NET: Mutex<Option<NetStack>> = Mutex::new(None);
}

// 临时端口分配计数器，原子递增，wrap-around 后从 EPHEMERAL_START 重新开始。
static NEXT_EPHEMERAL: AtomicU16 = AtomicU16::new(EPHEMERAL_START);

/// 内核网络栈的三件套，必须同时持有才能驱动协议处理：
/// - `iface`：smoltcp 协议引擎，负责 IP 地址管理和 TCP/UDP 状态机；
/// - `dev`：虚拟回环网卡，充当数据包的收发队列；
/// - `sockets`：所有活跃 smoltcp socket 的集中存储池。
pub struct NetStack {
    iface: Interface,
    dev: Loopback,
    sockets: SocketSet<'static>,
}

/// 将内核时钟（毫秒）转换为 smoltcp 所需的 Instant 时间戳。
/// smoltcp 用它计算 TCP 超时、重传等定时事件。
fn now() -> Instant {
    Instant::from_millis(crate::time::get_time_ms() as i64)
}

/// 初始化全局网络栈（幂等，重复调用安全）。
/// 创建回环设备，绑定 127.0.0.1/8，并开启 any_ip 使任意本地地址均可接收。
pub fn init() {
    let mut net = NET.lock();
    if net.is_some() {
        return;
    }
    // Medium::Ip：不需要以太网帧头，直接收发 IP 数据包（适合虚拟/回环设备）。
    let mut dev = Loopback::new(Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    // 固定随机种子，使 TCP ISN 等伪随机值在每次启动时可复现（测试友好）。
    config.random_seed = 0xA2CE_05A2_CE05_A2CE;
    let mut iface = Interface::new(config, &mut dev, now());
    iface.update_ip_addrs(|addrs| {
        // 127.0.0.1/8 loopback.
        let cidr = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), 8);
        let _ = addrs.push(cidr);
    });
    // set_any_ip(true)：允许接收目标地址不在 iface 地址列表中的数据包，
    // 方便绑定 0.0.0.0 的 socket 也能收到 127.x.x.x 的流量。
    iface.set_any_ip(true);
    let sockets = SocketSet::new(vec![]);
    *net = Some(NetStack {
        iface,
        dev,
        sockets,
    });
}

/// 驱动网络栈前进一步：处理 dev 中积压的数据包，推进所有 socket 的状态机，
/// 并将待发送的应答包（ACK、SYN-ACK 等）写回 dev。
/// 完成后通知等待网络事件的 task 重新检查（类似软中断下半部）。
pub fn poll() {
    let mut net = NET.lock();
    let Some(stack) = net.as_mut() else {
        return;
    };
    let _ = stack.iface.poll(now(), &mut stack.dev, &mut stack.sockets);
    drop(net); // 先释放锁，再通知，避免被唤醒的 task 立刻死锁在 NET 上。
    crate::fs::notify_net_poll_events();
}

/// 分配一个可用的临时端口（49152–65535），用于 connect() 未显式 bind 时的源端口。
/// 简单自增，不检查端口是否已被占用（LTP 场景下冲突概率低，够用）。
/// TODO: BETTER
pub fn alloc_ephemeral_port() -> u16 {
    loop {
        let p = NEXT_EPHEMERAL.fetch_add(1, Ordering::Relaxed);
        if p < EPHEMERAL_START || p > EPHEMERAL_END {
            NEXT_EPHEMERAL.store(EPHEMERAL_START, Ordering::Relaxed);
            continue;
        }
        return p;
    }
}

/// 在持有全局 NET (目前暂时的唯一网络设备)锁的情况下，将 iface / dev / sockets 一并传入闭包。
/// 所有需要操作 smoltcp socket 的代码（bind/connect/send/recv）都通过此函数进入。
pub fn with_sockets_mut<R>(
    f: impl FnOnce(&mut Interface, &mut Loopback, &mut SocketSet<'static>) -> R,
) -> R {
    init();
    let mut net = NET.lock();
    let stack = net.as_mut().unwrap();
    f(&mut stack.iface, &mut stack.dev, &mut stack.sockets)
}

#[allow(dead_code)]
pub fn ip_endpoint_from_v4(ip: Ipv4Address, port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(ip), port)
}
