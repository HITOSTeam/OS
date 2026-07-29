mod virtio_blk;

pub use virtio_blk::VirtIOBlock;

use alloc::sync::Arc;
use alloc::vec::Vec;
use ext4_fs::BlockDevice;
use lazy_static::*;

use crate::println;

pub type BlockDeviceImpl = crate::drivers::block::VirtIOBlock;

// VirtIO block devices in stable discovery order.
//
// QEMU attaches the first drive as `/dev/vda`, the second as `/dev/vdb`, and
// so on. Keep the registry independent from filesystem roles: whether a
// device is the system root, `/user`, or a test-data disk is decided by the
// mount configuration rather than by the block driver.
lazy_static! {
    pub static ref BLOCK_DEVICES: Vec<Arc<dyn BlockDevice>> = BlockDeviceImpl::probe_all()
        .into_iter()
        .map(|dev| Arc::new(dev) as Arc<dyn BlockDevice>)
        .collect();
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
