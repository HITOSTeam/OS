//! Minimal polling/PIO driver for the VisionFive 2 SD-card slot.
//!
//! The slot is JH7110 SDIO1 (`snps,dw-mshc`) at 0x1602_0000.  This intentionally
//! uses single-block PIO: it is small, needs no DMA allocator or IRQ plumbing,
//! and is sufficient for initial board bring-up and ext4 test images.

use core::hint::spin_loop;
use ext4_fs::{BLOCK_SZ, BlockDevice};
use spin::Mutex;

// SDIO1 映射到内核高半 MMIO 窗口；该根页表项会共享给用户页表，轮询 I/O
// 在内核以用户 SATP 执行时也不会访问到低地址用户区。
const BASE: usize = crate::config::mmio_va(0x1602_0000);
const CTRL: usize = 0x00;
const PWREN: usize = 0x04;
const CLKDIV: usize = 0x08;
const CLKSRC: usize = 0x0c;
const CLKENA: usize = 0x10;
const TMOUT: usize = 0x14;
const CTYPE: usize = 0x18;
const BLKSIZ: usize = 0x1c;
const BYTCNT: usize = 0x20;
const CMDARG: usize = 0x28;
const CMD: usize = 0x2c;
const RESP0: usize = 0x30;
const RINTSTS: usize = 0x44;
const STATUS: usize = 0x48;
const FIFOTH: usize = 0x4c;
const UHS_REG: usize = 0x74;
const BMOD: usize = 0x80;
const IDSTS: usize = 0x8c;
const IDINTEN: usize = 0x90;
const DATA: usize = 0x200;
const RESET: u32 = 0x7;
const INT_ENABLE: u32 = 1 << 4;
const ALL: u32 = !0;
const START: u32 = 1 << 31;
const HOLD: u32 = 1 << 29;
const UPDATE: u32 = 1 << 21;
const INIT: u32 = 1 << 15;
const PREV_DATA: u32 = 1 << 13;
const DATA_EXPECT: u32 = 1 << 9;
const WRITE: u32 = 1 << 10;
const RESP: u32 = 1 << 6;
const LONG: u32 = 1 << 7;
const CRC: u32 = 1 << 8;
const CMD_DONE: u32 = 1 << 2;
const DATA_OVER: u32 = 1 << 3;
const DATA_BUSY: u32 = 1 << 9;
const FIFO_FULL: u32 = 1 << 3;
const FIFO_COUNT: u32 = 0x1fff << 17;
const ERR: u32 = (1 << 1) | (0x3ff << 6) | (1 << 15);
const OCR_READY: u32 = 1 << 31;
const OCR_HCS: u32 = 1 << 30;
const OCR_33V: u32 = 0x1f << 16;
const LIMIT: usize = 50_000_000;

#[derive(Clone, Copy)]
enum Response {
    None,
    Short,
    ShortCrc,
    LongCrc,
}
impl Response {
    const fn bits(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Short => RESP,
            Self::ShortCrc => RESP | CRC,
            Self::LongCrc => RESP | LONG | CRC,
        }
    }
}

struct Host {
    rca: u32,
    block_addressing: bool,
    capacity_blocks: usize,
}
pub struct VisionFiveSdCard(Mutex<Host>);

impl VisionFiveSdCard {
    pub fn new() -> Result<Self, &'static str> {
        let mut host = Host {
            rca: 0,
            block_addressing: false,
            capacity_blocks: 0,
        };
        host.init()?;
        Ok(Self(Mutex::new(host)))
    }
}

impl BlockDevice for VisionFiveSdCard {
    fn io_relax(&self) {
        if crate::task::processor::current_task().is_some() {
            crate::task::processor::suspend_current_and_run_next()
        } else {
            spin_loop()
        }
    }
    fn read_block(&self, block: usize, buffer: &mut [u8]) {
        assert_eq!(buffer.len() % BLOCK_SZ, 0);
        let mut host = self.0.lock();
        for (index, slice) in buffer.chunks_mut(BLOCK_SZ).enumerate() {
            host.read_ext4_block(block + index, slice)
                .expect("[vf2-sd] read failed");
        }
    }
    fn write_block(&self, block: usize, buffer: &[u8]) {
        assert_eq!(buffer.len() % BLOCK_SZ, 0);
        let mut host = self.0.lock();
        for (index, slice) in buffer.chunks(BLOCK_SZ).enumerate() {
            host.write_ext4_block(block + index, slice)
                .expect("[vf2-sd] write failed");
        }
    }
}

impl Host {
    fn init(&mut self) -> Result<(), &'static str> {
        self.w(CTRL, RESET);
        self.wait(|| self.r(CTRL) & RESET == 0, "reset")?;
        self.w(CTRL, INT_ENABLE);
        self.w(PWREN, 1);
        self.w(RINTSTS, ALL);
        self.w(IDSTS, ALL);
        self.w(IDINTEN, 0);
        self.w(BMOD, 0);
        self.w(TMOUT, ALL);
        self.w(FIFOTH, (2 << 28) | (0x10 << 16) | 0x10);
        self.w(CTYPE, 0);
        self.w(UHS_REG, 0);
        self.clock(495)?;
        self.cmd(0, 0, INIT, Response::None)?;
        let r7 = self.cmd(8, 0x1aa, 0, Response::ShortCrc)?;
        if r7[0] & 0xfff != 0x1aa {
            return Err("CMD8 response");
        }
        let mut ocr = 0;
        for _ in 0..10_000 {
            self.cmd(55, 0, 0, Response::ShortCrc)?;
            ocr = self.cmd(41, OCR_HCS | OCR_33V, 0, Response::Short)?[0];
            if ocr & OCR_READY != 0 {
                break;
            }
        }
        if ocr & OCR_READY == 0 {
            return Err("ACMD41 timeout");
        }
        self.block_addressing = ocr & OCR_HCS != 0;
        self.cmd(2, 0, 0, Response::LongCrc)?;
        self.rca = self.cmd(3, 0, 0, Response::ShortCrc)?[0] >> 16;
        if self.rca == 0 {
            return Err("invalid RCA");
        }
        let csd = self.cmd(9, self.rca << 16, 0, Response::LongCrc)?;
        self.capacity_blocks = csd_v2_blocks(csd).unwrap_or(0);
        self.cmd(7, self.rca << 16, 0, Response::ShortCrc)?;
        self.cmd(16, 512, 0, Response::ShortCrc)?;
        self.clock(4)?;
        crate::println!("[vf2-sd] SDIO1 ready: {} MiB", self.capacity_blocks / 2048);
        Ok(())
    }
    fn read_ext4_block(&mut self, block: usize, output: &mut [u8]) -> Result<(), &'static str> {
        for (i, sector) in output.chunks_mut(512).enumerate() {
            self.read_sector(
                block
                    .checked_mul(8)
                    .and_then(|x| x.checked_add(i))
                    .ok_or("LBA overflow")?,
                sector,
            )?;
        }
        Ok(())
    }
    fn write_ext4_block(&mut self, block: usize, input: &[u8]) -> Result<(), &'static str> {
        for (i, sector) in input.chunks(512).enumerate() {
            self.write_sector(
                block
                    .checked_mul(8)
                    .and_then(|x| x.checked_add(i))
                    .ok_or("LBA overflow")?,
                sector,
            )?;
        }
        Ok(())
    }
    fn address(&self, sector: usize) -> Result<u32, &'static str> {
        if sector >= self.capacity_blocks {
            return Err("LBA outside card");
        }
        let address = if self.block_addressing {
            sector
        } else {
            sector.checked_mul(512).ok_or("address overflow")?
        };
        u32::try_from(address).map_err(|_| "card too large")
    }
    fn read_sector(&mut self, sector: usize, output: &mut [u8]) -> Result<(), &'static str> {
        self.ready()?;
        self.setup_data();
        self.cmd(
            17,
            self.address(sector)?,
            DATA_EXPECT | HOLD,
            Response::ShortCrc,
        )?;
        for chunk in output.chunks_mut(4) {
            self.wait(|| self.r(STATUS) & FIFO_COUNT != 0, "RX FIFO")?;
            let word = self.r(DATA).to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        self.data_done()
    }
    fn write_sector(&mut self, sector: usize, input: &[u8]) -> Result<(), &'static str> {
        self.ready()?;
        self.setup_data();
        self.cmd(
            24,
            self.address(sector)?,
            DATA_EXPECT | WRITE | HOLD,
            Response::ShortCrc,
        )?;
        for chunk in input.chunks(4) {
            self.wait(|| self.r(STATUS) & FIFO_FULL == 0, "TX FIFO")?;
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.w(DATA, u32::from_le_bytes(word));
        }
        self.data_done()
    }
    fn setup_data(&self) {
        self.w(BLKSIZ, 512);
        self.w(BYTCNT, 512);
        self.w(RINTSTS, ALL);
    }
    fn data_done(&self) -> Result<(), &'static str> {
        self.wait(|| self.r(RINTSTS) & (DATA_OVER | ERR) != 0, "data")?;
        let status = self.r(RINTSTS);
        self.w(RINTSTS, status);
        if status & ERR != 0 {
            Err("data error")
        } else {
            Ok(())
        }
    }
    fn ready(&self) -> Result<(), &'static str> {
        self.wait(|| self.r(STATUS) & DATA_BUSY == 0, "data busy")
    }
    fn cmd(
        &self,
        index: u32,
        arg: u32,
        flags: u32,
        response: Response,
    ) -> Result<[u32; 4], &'static str> {
        self.wait(|| self.r(CMD) & START == 0, "command busy")?;
        self.w(RINTSTS, ALL);
        self.w(CMDARG, arg);
        self.w(CMD, START | flags | response.bits() | index);
        self.wait(|| self.r(RINTSTS) & (CMD_DONE | ERR) != 0, "command")?;
        let status = self.r(RINTSTS);
        self.w(RINTSTS, status);
        if status & ERR != 0 {
            return Err("command error");
        }
        Ok([
            self.r(RESP0),
            self.r(RESP0 + 4),
            self.r(RESP0 + 8),
            self.r(RESP0 + 12),
        ])
    }
    fn clock(&self, divider: u32) -> Result<(), &'static str> {
        self.w(CLKENA, 0);
        self.clock_update()?;
        self.w(CLKSRC, 0);
        self.w(CLKDIV, divider);
        self.clock_update()?;
        self.w(CLKENA, 1);
        self.clock_update()
    }
    fn clock_update(&self) -> Result<(), &'static str> {
        self.w(CMD, START | UPDATE | PREV_DATA);
        self.wait(|| self.r(CMD) & START == 0, "clock update")
    }
    fn wait(
        &self,
        predicate: impl Fn() -> bool,
        message: &'static str,
    ) -> Result<(), &'static str> {
        for _ in 0..LIMIT {
            if predicate() {
                return Ok(());
            }
            spin_loop();
        }
        Err(message)
    }
    #[inline]
    fn r(&self, offset: usize) -> u32 {
        unsafe { (BASE.wrapping_add(offset) as *const u32).read_volatile() }
    }
    #[inline]
    fn w(&self, offset: usize, value: u32) {
        unsafe { (BASE.wrapping_add(offset) as *mut u32).write_volatile(value) }
    }
}

fn csd_v2_blocks(response: [u32; 4]) -> Option<usize> {
    let mut csd = [0u8; 16];
    for (index, word) in response.iter().rev().enumerate() {
        csd[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    if bits(&csd, 127, 126) != 1 {
        return None;
    }
    usize::try_from((u64::from(bits(&csd, 69, 48)) + 1) * 1024).ok()
}

fn bits(bytes: &[u8; 16], msb: u32, lsb: u32) -> u32 {
    let mut value = 0;
    for bit in (lsb..=msb).rev() {
        value = (value << 1) | u32::from((bytes[(15 - bit / 8) as usize] >> (bit % 8)) & 1);
    }
    value
}
