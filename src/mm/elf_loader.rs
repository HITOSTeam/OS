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
#[cfg(target_arch = "riscv64")]
const EM_RISCV: u16 = 243;
#[cfg(target_arch = "loongarch64")]
const EM_LOONGARCH: u16 = 258;
#[cfg(target_arch = "riscv64")]
const EF_RISCV_FLOAT_ABI_MASK: u32 = 0x6;
#[cfg(target_arch = "loongarch64")]
const EF_LOONGARCH_ABI_MASK: u32 = 0x7;
pub(super) const ET_DYN: u16 = 3;
pub(super) const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
pub(super) const PT_PHDR: u32 = 6;
pub(super) const PF_X: u32 = 1;
pub(super) const PF_W: u32 = 2;
pub(super) const PF_R: u32 = 4;

/// ELF 头
#[derive(Clone, Copy)]
pub(super) struct ElfHeader64 {
    pub e_type: u16,
    pub e_machine: u16,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_flags: u32,
    pub e_phentsize: u16,
    pub e_phnum: u16,
}

/// ELF 体系结构与 ABI 标识，由 `e_machine` 和 `e_flags` 共同确定。
///
/// 内核用它来判断一个 ELF 二进制是否可以在当前硬件上运行：
/// - `machine`：目标指令集（如 EM_RISCV / EM_LOONGARCH）；
/// - `flags`：ABI 细节，包含浮点 ABI 位（RISC-V 取 `e_flags[2:1]`，
///   LoongArch 取 `e_flags[2:0]`）。浮点 ABI 决定浮点参数通过浮点
///   寄存器还是整数寄存器传递，若与运行环境不符则调用约定错位，
///   因此必须与当前内核 ABI 严格匹配。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ElfArchAbi {
    /// 对应 ELF 文件头的 `e_machine` 字段，标识目标指令集架构。
    pub machine: u16,
    /// 对应 ELF 文件头的 `e_flags` 字段，包含体系结构相关的 ABI 标志，
    /// 如浮点 ABI 等级（soft / single / double / quad）。
    pub flags: u32,
}

/// ELF 加载所需的摘要信息，在解析程序头之后、建立地址空间之前填充。
/// 检查 用 ，拒绝掉 不符合 的
#[derive(Clone)]
pub(crate) struct ElfLoadInfo {
    /// 动态链接器路径，来自 `PT_INTERP` 段；静态可执行文件为 `None`。
    pub interp: Option<String>,
    /// 该 ELF 文件的体系结构与 ABI 标识，用于校验兼容性。
    pub arch_abi: ElfArchAbi,
    /// 已解析的 ELF 文件头，供同一次 exec 后续建地址空间时复用。
    pub(super) header: ElfHeader64,
    /// 已解析的程序头表，避免同一次 exec 重复读取/解析 program headers。
    pub(super) phdrs: Vec<ElfPhdr64>,
}

impl ElfHeader64 {
    /// 从文件头提取体系结构与 ABI 标识。
    pub(super) fn arch_abi(&self) -> ElfArchAbi {
        ElfArchAbi {
            machine: self.e_machine,
            flags: self.e_flags,
        }
    }
}

// PH: program header
#[derive(Clone, Copy)]
pub(super) struct ElfPhdr64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
}

/// 使用read at函数 读取文件，从offset 开始，读入到buf  .大小 取决于 buf
pub(super) fn read_exact_with<F>(
    read_at: &mut F,
    offset: usize,
    buf: &mut [u8],
) -> Result<(), isize>
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

/// 解析 ELF 文件的文件头与程序头表，用于后续地址空间的创建。
///
/// # 参数
/// - `read_at`: 读取回调，签名为 `FnMut(offset, buf) -> 已读字节数`。返回 0 表示
///   到达文件末尾或读取失败；本函数据此判断是否读到了足够的数据。
///
/// # 返回
/// - `Ok((header, phdrs))`: 解析出的 ELF64 文件头，以及全部程序头（Program Header）。
/// - `Err(ENOEXEC)`: 文件不是合法的、本内核支持的 ELF64 小端可执行格式。
///
pub(super) fn parse_elf_headers<F>(read_at: &mut F) -> Result<(ElfHeader64, Vec<ElfPhdr64>), isize>
where
    F: FnMut(usize, &mut [u8]) -> usize,
{
    // 1. 读取文件头
    // ELF64 文件头固定为 64 字节，从文件偏移 0 处完整读入。
    let mut hdr = [0u8; 64];
    read_exact_with(read_at, 0, &mut hdr)?;
    // e_ident[0..4]：魔数 0x7F 'E' 'L' 'F'，用于确认这是一个 ELF 文件。
    if hdr[0..4] != ELF_MAGIC {
        return Err(ENOEXEC);
    }
    // e_ident[4] = EI_CLASS（必须为 64 位），e_ident[5] = EI_DATA（必须为小端）。
    if hdr[4] != ELFCLASS64 || hdr[5] != ELFDATA2LSB {
        return Err(ENOEXEC);
    }
    // 以下偏移均取自 ELF64 文件头布局，多字节字段按小端序解码。
    // 偏移 16：e_type（目标文件类型，如 ET_EXEC / ET_DYN）。
    let e_type = u16::from_le_bytes([hdr[16], hdr[17]]);
    // 偏移 18：e_machine（目标体系结构，如 EM_RISCV / EM_LOONGARCH）。
    let e_machine = u16::from_le_bytes([hdr[18], hdr[19]]);
    // 偏移 24：e_entry（程序入口虚拟地址）。
    let e_entry = u64::from_le_bytes([
        hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31],
    ]);
    // 偏移 32：e_phoff（程序头表在文件中的偏移）。
    let e_phoff = u64::from_le_bytes([
        hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39],
    ]);
    // 偏移 48：e_flags（体系结构相关标志，如浮点 ABI 等）。
    let e_flags = u32::from_le_bytes([hdr[48], hdr[49], hdr[50], hdr[51]]);
    // 偏移 54：e_phentsize（单个程序头表项的字节大小）。
    let e_phentsize = u16::from_le_bytes([hdr[54], hdr[55]]);
    // 偏移 56：e_phnum（程序头表项的个数）。
    let e_phnum = u16::from_le_bytes([hdr[56], hdr[57]]);
    // ELF64 程序头固定为 56 字节，表项过小说明格式异常，拒绝执行。
    if e_phentsize < 56 {
        return Err(ENOEXEC);
    }
    // 最终 文件头 结果
    let header = ElfHeader64 {
        e_type,
        e_machine,
        e_entry,
        e_phoff,
        e_flags,
        e_phentsize,
        e_phnum,
    };
    // 逐个读取并解析程序头表项；用 e_phnum 预留容量避免多次扩容。
    let mut phdrs = Vec::with_capacity(e_phnum as usize);
    let mut ph_buf = [0u8; 56];
    // 根据 ephnum 读取 程序头(program header)
    // program header 是用于构造 最终memoryset  的 核心
    for idx in 0..e_phnum as usize {
        // 第 idx 个程序头的文件偏移 = 表起始偏移 + idx * 表项大小。
        // 使用 e_phentsize（而非硬编码 56）来计算步长，以兼容更大的表项。
        let off = e_phoff as usize + idx * e_phentsize as usize;
        read_exact_with(read_at, off, &mut ph_buf)?;
        // 以下偏移取自 ELF64 程序头（Elf64_Phdr）布局。注意此处刻意跳过了
        // 偏移 24 的 p_paddr 和偏移 48 的 p_align：建立地址空间时用不到它们。
        let ph = ElfPhdr64 {
            // 偏移 0：p_type（段类型，如 PT_LOAD / PT_INTERP / PT_PHDR）。
            p_type: u32::from_le_bytes([ph_buf[0], ph_buf[1], ph_buf[2], ph_buf[3]]),
            // 偏移 4：p_flags（段权限标志 PF_R / PF_W / PF_X）。
            p_flags: u32::from_le_bytes([ph_buf[4], ph_buf[5], ph_buf[6], ph_buf[7]]),
            // 偏移 8：p_offset（段内容在文件中的偏移）。
            p_offset: u64::from_le_bytes([
                ph_buf[8], ph_buf[9], ph_buf[10], ph_buf[11], ph_buf[12], ph_buf[13], ph_buf[14],
                ph_buf[15],
            ]),
            // 偏移 16：p_vaddr（段要被映射到的虚拟地址）。
            p_vaddr: u64::from_le_bytes([
                ph_buf[16], ph_buf[17], ph_buf[18], ph_buf[19], ph_buf[20], ph_buf[21], ph_buf[22],
                ph_buf[23],
            ]),
            // 偏移 32：p_filesz（段在文件中的字节大小）。
            p_filesz: u64::from_le_bytes([
                ph_buf[32], ph_buf[33], ph_buf[34], ph_buf[35], ph_buf[36], ph_buf[37], ph_buf[38],
                ph_buf[39],
            ]),
            // 偏移 40：p_memsz（段在内存中的字节大小，可大于 p_filesz，多出部分清零，如 .bss）。
            p_memsz: u64::from_le_bytes([
                ph_buf[40], ph_buf[41], ph_buf[42], ph_buf[43], ph_buf[44], ph_buf[45], ph_buf[46],
                ph_buf[47],
            ]),
        };
        phdrs.push(ph);
    }
    Ok((header, phdrs))
}

pub(crate) fn elf_arch_abi_from_bytes(data: &[u8]) -> Result<ElfArchAbi, isize> {
    if data.len() < 64 {
        return Err(ENOEXEC);
    }
    if data[0..4] != ELF_MAGIC {
        return Err(ENOEXEC);
    }
    if data[4] != ELFCLASS64 || data[5] != ELFDATA2LSB {
        return Err(ENOEXEC);
    }
    Ok(ElfArchAbi {
        machine: u16::from_le_bytes([data[18], data[19]]),
        flags: u32::from_le_bytes([data[48], data[49], data[50], data[51]]),
    })
}

#[cfg(target_arch = "riscv64")]
fn current_elf_machine() -> u16 {
    EM_RISCV
}

#[cfg(target_arch = "loongarch64")]
fn current_elf_machine() -> u16 {
    EM_LOONGARCH
}

#[cfg(target_arch = "riscv64")]
fn elf_float_abi(abi: ElfArchAbi) -> u32 {
    abi.flags & EF_RISCV_FLOAT_ABI_MASK
}

#[cfg(target_arch = "loongarch64")]
fn elf_float_abi(abi: ElfArchAbi) -> u32 {
    abi.flags & EF_LOONGARCH_ABI_MASK
}

pub(crate) fn validate_elf_arch_abi(abi: ElfArchAbi) -> Result<(), isize> {
    if abi.machine != current_elf_machine() {
        return Err(ENOEXEC);
    }
    Ok(())
}

/// 检查 程序拥有的ABI 与 我们实际是否一致
/// 有些测试有问题 。
pub(crate) fn validate_elf_interp_abi(
    main_abi: ElfArchAbi,
    interp_abi: ElfArchAbi,
) -> Result<(), isize> {
    validate_elf_arch_abi(main_abi)?;
    validate_elf_arch_abi(interp_abi)?;
    if elf_float_abi(main_abi) != elf_float_abi(interp_abi) {
        return Err(ENOEXEC);
    }
    Ok(())
}

/// 加载PT_INterp，以及架构信息 用于检查，如果不符合 我们 会 提前终止
pub(crate) fn elf_load_info_from_reader<F>(mut read_at: F) -> Result<ElfLoadInfo, isize>
where
    F: FnMut(usize, &mut [u8]) -> usize,
{
    let (header, phdrs) = parse_elf_headers(&mut read_at)?;
    let arch_abi = header.arch_abi();
    validate_elf_arch_abi(arch_abi)?;
    let mut interp = None;
    for ph in phdrs.iter() {
        if ph.p_type != PT_INTERP {
            continue;
        }
        let mut buf = vec![0u8; ph.p_filesz as usize];
        read_exact_with(&mut read_at, ph.p_offset as usize, &mut buf)?;
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let s = core::str::from_utf8(&buf[..end]).map_err(|_| ENOEXEC)?;
        interp = Some(String::from(s));
        break;
    }
    Ok(ElfLoadInfo {
        interp,
        arch_abi,
        header,
        phdrs,
    })
}
