mod virtio_blk;

pub use virtio_blk::VirtIOBlock;

use alloc::sync::Arc;
use ext4_fs::BlockDevice;
use lazy_static::*;

use crate::println;

pub type BlockDeviceImpl = crate::drivers::block::VirtIOBlock;

// sdcard.img on the block device and disk.img on the second part
// 底层的块设备初始化在这个地方
lazy_static! {
    pub static ref BLOCK_DEVICE: Arc<dyn BlockDevice> = Arc::new(BlockDeviceImpl::new());
    pub static ref USER_BLOCK_DEVICE: Option<Arc<dyn BlockDevice>> =
        BlockDeviceImpl::try_new_second().map(|dev| Arc::new(dev) as Arc<dyn BlockDevice>);
}

#[allow(unused)]
pub fn block_device_test() {
    let block_device = BLOCK_DEVICE.clone();
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
