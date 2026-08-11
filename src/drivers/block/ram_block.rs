//! Fixed-address RAM block devices for non-persistent LS2K1000LA boots.

use super::AsyncBlockDiagnostics;
use alloc::vec::Vec;
use core::ptr;
use ext4_fs::{BLOCK_SZ, BlockDevice};
use spin::Mutex;

pub struct RamBlockDevice {
    base: usize,
    len: usize,
    io_lock: Mutex<()>,
}

impl RamBlockDevice {
    pub fn probe_all() -> Vec<Self> {
        crate::config::BOARD_RAM_DISKS
            .iter()
            .map(|&(base, len)| {
                crate::println!(
                    "[ramblk] registered [{:#x}, {:#x}) as {} blocks",
                    base,
                    base + len,
                    len / BLOCK_SZ
                );
                Self {
                    base,
                    len,
                    io_lock: Mutex::new(()),
                }
            })
            .collect()
    }

    fn byte_offset(&self, block_id: usize, len: usize) -> usize {
        assert_eq!(len % BLOCK_SZ, 0, "RAM block I/O must be block aligned");
        let offset = block_id
            .checked_mul(BLOCK_SZ)
            .expect("RAM block offset overflow");
        let end = offset.checked_add(len).expect("RAM block length overflow");
        assert!(end <= self.len, "RAM block I/O exceeds image");
        offset
    }

    pub fn handle_irq(&self, _irq: usize) -> bool {
        false
    }

    pub fn poll(&self) {}

    pub fn diagnostics(&self) -> AsyncBlockDiagnostics {
        AsyncBlockDiagnostics::default()
    }
}

impl BlockDevice for RamBlockDevice {
    fn io_relax(&self) {
        core::hint::spin_loop();
    }

    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        self.read_blocks(block_id, buf);
    }

    fn write_block(&self, block_id: usize, buf: &[u8]) {
        self.write_blocks(block_id, buf);
    }

    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) {
        let offset = self.byte_offset(block_id, buf.len());
        let _guard = self.io_lock.lock();
        // SAFETY: the linker/memory configuration reserves and identity-maps
        // `[base, base + len)`. Bounds above keep both regions valid and the
        // per-device lock excludes overlapping mutable access.
        unsafe {
            ptr::copy_nonoverlapping(
                (self.base + offset) as *const u8,
                buf.as_mut_ptr(),
                buf.len(),
            );
        }
    }

    fn write_blocks(&self, block_id: usize, buf: &[u8]) {
        let offset = self.byte_offset(block_id, buf.len());
        let _guard = self.io_lock.lock();
        // SAFETY: see `read_blocks`; this copy targets the reserved RAM image.
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), (self.base + offset) as *mut u8, buf.len());
        }
    }
}
