mod async_queue;
mod virtio_blk;

pub use async_queue::AsyncBlockDiagnostics;
pub use virtio_blk::VirtIOBlock;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use ext4_fs::BlockDevice;
use lazy_static::*;

use crate::println;

pub type BlockDeviceImpl = crate::drivers::block::VirtIOBlock;
static BLOCK_REGISTRY_READY: AtomicBool = AtomicBool::new(false);
static NEXT_FALLBACK_POLL_MS: AtomicUsize = AtomicUsize::new(0);
const FALLBACK_POLL_INTERVAL_MS: usize = 10;

// VirtIO block devices in stable discovery order.
//
// QEMU attaches the first drive as `/dev/vda`, the second as `/dev/vdb`, and
// so on. Keep the registry independent from filesystem roles: whether a
// device is the system root, `/user`, or a test-data disk is decided by the
// mount configuration rather than by the block driver.
lazy_static! {
    static ref BLOCK_DRIVER_DEVICES: Vec<Arc<BlockDeviceImpl>> = {
        let devices = BlockDeviceImpl::probe_all()
            .into_iter()
            .map(Arc::new)
            .collect();
        BLOCK_REGISTRY_READY.store(true, Ordering::Release);
        devices
    };
    pub static ref BLOCK_DEVICES: Vec<Arc<dyn BlockDevice>> = BLOCK_DRIVER_DEVICES
        .iter()
        .cloned()
        .map(|dev| dev as Arc<dyn BlockDevice>)
        .collect();
}

/// Dispatch a platform interrupt to the matching VirtIO block device.
pub fn handle_irq(irq: usize) -> bool {
    let mut handled = false;
    for device in BLOCK_DRIVER_DEVICES.iter() {
        handled |= device.handle_irq(irq);
    }
    handled
}

/// Poll used rings as an early-boot/lost-interrupt fallback.
pub fn poll_all() {
    if !BLOCK_REGISTRY_READY.load(Ordering::Acquire) {
        return;
    }
    // Normal runtime completion is interrupt-driven, as in Linux virtio-blk.
    // Keep one low-rate queue-wide poll as a lost-interrupt/early-boot safety
    // net; do not make every hart scan every device on the same timer tick.
    let now_ms = crate::time::get_time_ms();
    let mut deadline = NEXT_FALLBACK_POLL_MS.load(Ordering::Acquire);
    loop {
        if now_ms < deadline {
            return;
        }
        match NEXT_FALLBACK_POLL_MS.compare_exchange_weak(
            deadline,
            now_ms.saturating_add(FALLBACK_POLL_INTERVAL_MS),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(observed) => deadline = observed,
        }
    }
    for device in BLOCK_DRIVER_DEVICES.iter() {
        device.poll();
    }
}

pub fn diagnostics() -> Vec<AsyncBlockDiagnostics> {
    BLOCK_DRIVER_DEVICES
        .iter()
        .map(|device| device.diagnostics())
        .collect()
}

#[allow(unused)]
pub fn block_device_test() {
    let block_device = BLOCK_DEVICES
        .first()
        .cloned()
        .expect("VirtIO root block device not found");
    let mut write_buffer = [0u8; 512];
    let mut read_buffer = [0u8; 512];
    for i in 0..512 {
        for byte in write_buffer.iter_mut() {
            *byte = i as u8;
        }
        block_device.write_block(i as usize, &write_buffer);
        block_device.read_block(i as usize, &mut read_buffer);
        assert_eq!(write_buffer, read_buffer);
    }
    println!("block device test passed!");
}
