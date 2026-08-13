//! VisionFive 2 board support.
//!
//! Keep physical-board code here so the QEMU VirtIO path stays independent.

mod partition;
mod sdmmc;

use alloc::{sync::Arc, vec::Vec};
use ext4_fs::BlockDevice;

pub use sdmmc::VisionFiveSdCard;

/// Discover the SD card and expose GPT partitions 1 and 2 as the two logical
/// disks used by the existing QEMU root-selection code.
pub fn block_devices() -> Vec<Arc<dyn BlockDevice>> {
    let card: Arc<dyn BlockDevice> = Arc::new(
        VisionFiveSdCard::new().unwrap_or_else(|message| panic!("[vf2-sd] {message}")),
    );
    let mut devices = Vec::new();
    for number in 1..=2 {
        let partition = partition::gpt_partition(Arc::clone(&card), number)
            .unwrap_or_else(|| panic!("[vf2-sd] missing or unaligned GPT partition {number}"));
        devices.push(partition);
    }
    devices
}
