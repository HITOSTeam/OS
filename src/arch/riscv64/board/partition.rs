//! Tiny GPT partition adapter for the two ext4 partitions on the SD card.

use alloc::sync::Arc;
use ext4_fs::{BLOCK_SZ, BlockDevice};

const SECTOR_SIZE: usize = 512;
const SECTORS_PER_BLOCK: usize = BLOCK_SZ / SECTOR_SIZE;
const GPT_HEADER_OFFSET: usize = SECTOR_SIZE; // GPT header is LBA 1.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_ENTRIES_LBA: usize = 72;
const GPT_ENTRY_SIZE: usize = 84;
const GPT_FIRST_LBA: usize = 32;
const GPT_LAST_LBA: usize = 40;

pub struct Partition {
    parent: Arc<dyn BlockDevice>,
    first_block: usize,
    block_count: usize,
}

impl Partition {
    fn new(parent: Arc<dyn BlockDevice>, first_block: usize, block_count: usize) -> Self {
        Self { parent, first_block, block_count }
    }
}

impl BlockDevice for Partition {
    fn io_relax(&self) {
        self.parent.io_relax();
    }

    fn read_block(&self, block_id: usize, buffer: &mut [u8]) {
        assert_eq!(buffer.len() % BLOCK_SZ, 0);
        let blocks = buffer.len() / BLOCK_SZ;
        assert!(block_id.checked_add(blocks).is_some_and(|end| end <= self.block_count));
        self.parent.read_blocks(self.first_block + block_id, buffer);
    }

    fn write_block(&self, block_id: usize, buffer: &[u8]) {
        assert_eq!(buffer.len() % BLOCK_SZ, 0);
        let blocks = buffer.len() / BLOCK_SZ;
        assert!(block_id.checked_add(blocks).is_some_and(|end| end <= self.block_count));
        self.parent.write_blocks(self.first_block + block_id, buffer);
    }
}

/// Return one GPT partition as a 4-KiB-block device.  The image recipe aligns
/// partitions to MiB boundaries, so both ends must be 4-KiB aligned.
pub fn gpt_partition(parent: Arc<dyn BlockDevice>, number: usize) -> Option<Arc<dyn BlockDevice>> {
    if !(1..=2).contains(&number) {
        return None;
    }
    let mut first = [0u8; BLOCK_SZ];
    parent.read_block(0, &mut first);
    let header = first.get(GPT_HEADER_OFFSET..GPT_HEADER_OFFSET + SECTOR_SIZE)?;
    if header.get(..GPT_SIGNATURE.len())? != GPT_SIGNATURE {
        return None;
    }
    let entries_lba = le64(header, GPT_ENTRIES_LBA)? as usize;
    let entry_size = le32(header, GPT_ENTRY_SIZE)? as usize;
    if entry_size < GPT_LAST_LBA + 8 {
        return None;
    }
    let entry_byte = entries_lba.checked_mul(SECTOR_SIZE)?
        .checked_add((number - 1).checked_mul(entry_size)?)?;
    let block = entry_byte / BLOCK_SZ;
    let offset = entry_byte % BLOCK_SZ;
    if offset.checked_add(entry_size)? > BLOCK_SZ {
        return None;
    }
    let entry = if block == 0 { &first[offset..offset + entry_size] } else {
        let mut entries = [0u8; BLOCK_SZ];
        parent.read_block(block, &mut entries);
        // The first two standard 128-byte GPT entries fit in one 4-KiB block.
        return make_partition(parent, &entries[offset..offset + entry_size]);
    };
    make_partition(parent, entry)
}

fn make_partition(parent: Arc<dyn BlockDevice>, entry: &[u8]) -> Option<Arc<dyn BlockDevice>> {
    if entry.get(..16)?.iter().all(|byte| *byte == 0) {
        return None;
    }
    let first_lba = le64(entry, GPT_FIRST_LBA)? as usize;
    let last_lba = le64(entry, GPT_LAST_LBA)? as usize;
    if last_lba < first_lba || first_lba % SECTORS_PER_BLOCK != 0 {
        return None;
    }
    let sectors = last_lba.checked_sub(first_lba)?.checked_add(1)?;
    if sectors % SECTORS_PER_BLOCK != 0 {
        return None;
    }
    Some(Arc::new(Partition::new(
        parent,
        first_lba / SECTORS_PER_BLOCK,
        sectors / SECTORS_PER_BLOCK,
    )))
}

fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}
