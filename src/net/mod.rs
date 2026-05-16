//! 内核网络栈封装层。
//!
//! 本模块基于 [`smoltcp`] 提供一份**全局唯一**的协议栈实例，所有 socket 系统调用
//! （`bind` / `connect` / `send` / `recv` 等）最终都通过这里访问 smoltcp 的
//! [`Interface`] 与 [`SocketSet`]。
//!
//! 当前能力：
//! - 仅有一块虚拟回环网卡（`127.0.0.1/8`），不接外部物理网络；
//! - 全局状态用 [`spin::Mutex`] 保护，SMP 下是已知的串行化点；
//! - TCP 临时端口由 [`NEXT_EPHEMERAL`] 顺序分配，没有冲突检测，仅满足 LTP 用例。
//!
//! 使用方式：
//! 1. 内核启动早期调用一次 [`init`]（也可由 [`with_sockets_mut`] 惰性触发）。
//! 2. 周期性调用 [`poll`] 推进协议栈定时事件、唤醒等待网络的任务。
//! 3. 业务代码通过 [`with_sockets_mut`] 在持锁状态下操作 smoltcp 对象。

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

/// 临时端口区间下界（含）。
///
/// 取值遵循 RFC 6335 推荐的 49152–65535 范围；`connect()` 没有显式 `bind()`
/// 时由 [`alloc_ephemeral_port`] 在该区间内挑选源端口。
const EPHEMERAL_START: u16 = 49152;
/// 临时端口区间上界（含）。计数器越过此值后回绕至 [`EPHEMERAL_START`]。
const EPHEMERAL_END: u16 = 65535;

// 全局唯一网络栈，用 Mutex 保护。当前仅支持回环接口（127.0.0.1/8）。
// 所有网络操作（socket 读写、状态机推进）都需要持有此锁，是 SMP 下的性能瓶颈。
lazy_static! {
    static ref NET: Mutex<Option<NetStack>> = Mutex::new(None);
}

/// 临时端口分配计数器：以原子方式自增，越过 [`EPHEMERAL_END`] 后绕回
/// [`EPHEMERAL_START`]。**不检测端口占用**，仅做轮询式发号。
static NEXT_EPHEMERAL: AtomicU16 = AtomicU16::new(EPHEMERAL_START);

/// 内核网络栈的三件套，必须同时持有才能驱动协议处理：
/// - `iface`：smoltcp 协议引擎，负责 IP 地址管理和 TCP/UDP 状态机；
/// - `dev`：虚拟回环网卡，充当数据包的收发队列；
/// - `sockets`：所有活跃 smoltcp socket 的集中存储池。
pub struct NetStack {
    /// smoltcp 协议引擎：管理本机 IP 地址、ARP/邻居表、TCP/UDP 状态机，
    /// 由 [`poll`] 在每次轮询时驱动一次。
    iface: Interface,
    /// 虚拟回环设备，扮演 `lo` 的角色。`Interface::poll` 会从此设备
    /// 取出 RX 报文、推入 TX 报文。
    dev: Loopback,
    /// 所有活跃 smoltcp socket 的存储池。socket 句柄（`SocketHandle`）
    /// 由文件描述符层（参见 `fs::socket`）持有，访问时通过此集合解引用。
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

/// 在持有全局 [`NET`] 锁的前提下，将 `iface` / `dev` / `sockets` 一并
/// 借给闭包 `f` 使用。
///
/// 所有需要读写 smoltcp socket 的代码（`bind` / `connect` / `send` / `recv` 等）
/// 都应通过本函数进入临界区；这是目前内核唯一的网络协议栈实例，因此
/// 同一时刻只允许一个 CPU 核进入闭包。
///
/// 函数内部会先调用 [`init`] 做幂等初始化，调用方无需自己保证启动顺序。
pub fn with_sockets_mut<R>(
    f: impl FnOnce(&mut Interface, &mut Loopback, &mut SocketSet<'static>) -> R,
) -> R {
    init();
    let mut net = NET.lock();
    let stack = net.as_mut().unwrap();
    f(&mut stack.iface, &mut stack.dev, &mut stack.sockets)
}

/// 由 IPv4 地址和端口构造 smoltcp 的 [`IpEndpoint`] 便捷函数。
///
/// 目前 syscall 层暂未直接调用，保留供后续 socket 相关代码复用，
/// 故标注 `#[allow(dead_code)]` 以避免编译告警。
#[allow(dead_code)]
pub fn ip_endpoint_from_v4(ip: Ipv4Address, port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(ip), port)
}
