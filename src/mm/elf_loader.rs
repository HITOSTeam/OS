//! ELF-64 binary parsing helpers.
//!
//! Provides lightweight, no-alloc-where-possible routines for reading ELF
//! headers and program headers through a generic `read_at` callback, plus a
//! convenience function for extracting the PT_INTERP interpreter path.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(super) const ENOEXEC: isize = -8;
pub(super) const ENOMEM: isize = -12;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
pub(super) const ET_DYN: u16 = 3;
pub(super) const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
pub(super) const PT_PHDR: u32 = 6;
pub(super) const PF_X: u32 = 1;
pub(super) const PF_W: u32 = 2;
pub(super) const PF_R: u32 = 4;

#[derive(Clone, Copy)]
pub(super) struct ElfHeader64 {
    pub e_type: u16,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_phentsize: u16,
    pub e_phnum: u16,
}

#[derive(Clone, Copy)]
pub(super) struct ElfPhdr64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
}

pub(super) fn read_exact_with<F>(read_at: &mut F, offset: usize, buf: &mut [u8]) -> Result<(), isize>
where
    F: FnMut(usize, &mut [u8]) -> usize,
{
    let mut done = 0usize;
    while done < buf.len() {
        let n = read_at(offset + done, &mut buf[done..]);
        if n == 0 {
            return Err(ENOEXEC);
        }
        done += n;
    }
    Ok(())
}

pub(super) fn parse_elf_headers<F>(read_at: &mut F) -> Result<(ElfHeader64, Vec<ElfPhdr64>), isize>
where
    F: FnMut(usize, &mut [u8]) -> usize,
{
    let mut hdr = [0u8; 64];
    read_exact_with(read_at, 0, &mut hdr)?;
    if hdr[0..4] != ELF_MAGIC {
        return Err(ENOEXEC);
    }
    if hdr[4] != ELFCLASS64 || hdr[5] != ELFDATA2LSB {
        return Err(ENOEXEC);
    }
    let e_type = u16::from_le_bytes([hdr[16], hdr[17]]);
    let e_entry = u64::from_le_bytes([
        hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31],
    ]);
    let e_phoff = u64::from_le_bytes([
        hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39],
    ]);
    let e_phentsize = u16::from_le_bytes([hdr[54], hdr[55]]);
    let e_phnum = u16::from_le_bytes([hdr[56], hdr[57]]);
    if e_phentsize < 56 {
        return Err(ENOEXEC);
    }
    let header = ElfHeader64 {
        e_type,
        e_entry,
        e_phoff,
        e_phentsize,
        e_phnum,
    };
    let mut phdrs = Vec::with_capacity(e_phnum as usize);
    let mut ph_buf = [0u8; 56];
    for idx in 0..e_phnum as usize {
        let off = e_phoff as usize + idx * e_phentsize as usize;
        read_exact_with(read_at, off, &mut ph_buf)?;
        let ph = ElfPhdr64 {
            p_type: u32::from_le_bytes([ph_buf[0], ph_buf[1], ph_buf[2], ph_buf[3]]),
            p_flags: u32::from_le_bytes([ph_buf[4], ph_buf[5], ph_buf[6], ph_buf[7]]),
            p_offset: u64::from_le_bytes([
                ph_buf[8], ph_buf[9], ph_buf[10], ph_buf[11], ph_buf[12], ph_buf[13], ph_buf[14],
                ph_buf[15],
            ]),
            p_vaddr: u64::from_le_bytes([
                ph_buf[16], ph_buf[17], ph_buf[18], ph_buf[19], ph_buf[20], ph_buf[21], ph_buf[22],
                ph_buf[23],
            ]),
            p_filesz: u64::from_le_bytes([
                ph_buf[32], ph_buf[33], ph_buf[34], ph_buf[35], ph_buf[36], ph_buf[37], ph_buf[38],
                ph_buf[39],
            ]),
            p_memsz: u64::from_le_bytes([
                ph_buf[40], ph_buf[41], ph_buf[42], ph_buf[43], ph_buf[44], ph_buf[45], ph_buf[46],
                ph_buf[47],
            ]),
        };
        phdrs.push(ph);
    }
    Ok((header, phdrs))
}

pub(crate) fn elf_interp_path_from_reader<F>(mut read_at: F) -> Result<Option<String>, isize>
where
    F: FnMut(usize, &mut [u8]) -> usize,
{
    let (_hdr, phdrs) = parse_elf_headers(&mut read_at)?;
    for ph in phdrs {
        if ph.p_type != PT_INTERP {
            continue;
        }
        let mut buf = vec![0u8; ph.p_filesz as usize];
        read_exact_with(&mut read_at, ph.p_offset as usize, &mut buf)?;
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let s = core::str::from_utf8(&buf[..end]).map_err(|_| ENOEXEC)?;
        return Ok(Some(String::from(s)));
    }
    Ok(None)
}
