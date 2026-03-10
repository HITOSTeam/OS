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

const EPHEMERAL_START: u16 = 49152;
const EPHEMERAL_END: u16 = 65535;

lazy_static! {
    static ref NET: Mutex<Option<NetStack>> = Mutex::new(None);
}

static NEXT_EPHEMERAL: AtomicU16 = AtomicU16::new(EPHEMERAL_START);

pub struct NetStack {
    iface: Interface,
    dev: Loopback,
    sockets: SocketSet<'static>,
}

fn now() -> Instant {
    Instant::from_millis(crate::time::get_time_ms() as i64)
}

pub fn init() {
    let mut net = NET.lock();
    if net.is_some() {
        return;
    }
    let mut dev = Loopback::new(Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0xA2CE_05A2_CE05_A2CE;
    let mut iface = Interface::new(config, &mut dev, now());
    iface.update_ip_addrs(|addrs| {
        // 127.0.0.1/8 loopback.
        let cidr = IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)), 8);
        let _ = addrs.push(cidr);
    });
    iface.set_any_ip(true);
    let sockets = SocketSet::new(vec![]);
    *net = Some(NetStack {
        iface,
        dev,
        sockets,
    });
}

pub fn poll() {
    let mut net = NET.lock();
    let Some(stack) = net.as_mut() else {
        return;
    };
    let _ = stack.iface.poll(now(), &mut stack.dev, &mut stack.sockets);
    drop(net);
    crate::fs::notify_net_poll_events();
}

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

pub fn with_sockets_mut<R>(
    f: impl FnOnce(&mut Interface, &mut Loopback, &mut SocketSet<'static>) -> R,
) -> R {
    init();
    let mut net = NET.lock();
    let stack = net.as_mut().unwrap();
    f(&mut stack.iface, &mut stack.dev, &mut stack.sockets)
}

pub fn ip_endpoint_from_v4(ip: Ipv4Address, port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(ip), port)
}
