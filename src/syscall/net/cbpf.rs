//! classic BPF socket filter 的解析、校验和解释执行。
//!
//! Linux 的 `SO_ATTACH_FILTER` 传入的是 `struct sock_fprog`，里面指向一段
//! `struct sock_filter` 指令数组。这里把用户态指令复制进内核，先做静态校验，
//! 再在 AF_PACKET/raw/unix 等 socket 收包路径上解释执行。返回值为 0 表示丢包，
//! 非 0 表示允许接收并给出 snaplen。

use alloc::vec::Vec;
use core::mem::size_of;

use crate::mm::try_copy_from_user;
use crate::syscall::error::{SyscallError, err};
use crate::trap::get_current_token;

/// Linux classic BPF 允许的最大指令数。
const BPF_MAXINSNS: usize = 4096;
/// classic BPF 的 scratch memory，`M[0..15]`。
const BPF_MEMWORDS: usize = 16;
/// Linux 用负偏移表示 skb metadata load；当前不支持这些扩展。
const SKF_AD_OFF: u32 = 0xffff_f000;

// 指令 class。
const BPF_CLASS_MASK: u16 = 0x07;
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

// load/store 宽度。
const BPF_SIZE_MASK: u16 = 0x18;
const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

// load 寻址模式。
const BPF_MODE_MASK: u16 = 0xe0;
const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_MSH: u16 = 0xa0;

// ALU/JMP 操作码。
const BPF_OP_MASK: u16 = 0xf0;
const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

// 操作数来源：立即数 K、寄存器 X 或累加器 A。
const BPF_SRC_MASK: u16 = 0x08;
const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;

const BPF_MISCOP_MASK: u16 = 0xf8;
const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

/// 一条 classic BPF 指令，对应 Linux `struct sock_filter`。
#[derive(Clone, Copy)]
struct ClassicBpfInsn {
    /// opcode，包含 class/mode/size/op/src 等位域。
    code: u16,
    /// 条件跳转为真时的相对偏移。
    jt: u8,
    /// 条件跳转为假时的相对偏移。
    jf: u8,
    /// 立即数、packet offset、scratch memory index 或跳转距离。
    k: u32,
}

/// 已通过校验、可以挂到 socket 上的 classic BPF 程序。
#[derive(Clone)]
pub(crate) struct ClassicBpfProgram {
    insns: Vec<ClassicBpfInsn>,
}

impl ClassicBpfProgram {
    /// 从用户态 `struct sock_fprog` 复制并解析 classic BPF 程序。
    ///
    /// 这里同时兼容 32/64 位指针布局；复制完成后立即调用 [`Self::validate`]，
    /// 保证后续收包热路径只执行已验证的指令。
    pub(crate) fn from_sock_fprog_user(optval: usize, optlen: usize) -> Result<Self, isize> {
        let ptr_size = size_of::<usize>();
        let ptr_off = if ptr_size == 8 { 8 } else { 4 };
        let fprog_size = ptr_off + ptr_size;
        if optlen != fprog_size {
            return Err(err(SyscallError::EINVAL));
        }
        if optval == 0 {
            return Err(err(SyscallError::EFAULT));
        }

        let token = get_current_token();
        let mut fprog = [0u8; 16];
        if try_copy_from_user(token, optval as *const u8, &mut fprog[..fprog_size]).is_err() {
            return Err(err(SyscallError::EFAULT));
        }
        let len = u16::from_ne_bytes([fprog[0], fprog[1]]) as usize;
        if len == 0 || len > BPF_MAXINSNS {
            return Err(err(SyscallError::EINVAL));
        }

        let mut ptr_raw = [0u8; size_of::<usize>()];
        ptr_raw.copy_from_slice(&fprog[ptr_off..ptr_off + ptr_size]);
        let filter_ptr = usize::from_ne_bytes(ptr_raw);
        if filter_ptr == 0 {
            return Err(err(SyscallError::EINVAL));
        }

        let byte_len = len.checked_mul(8).ok_or(err(SyscallError::EINVAL))?;
        let mut raw = alloc::vec![0u8; byte_len];
        if try_copy_from_user(token, filter_ptr as *const u8, raw.as_mut_slice()).is_err() {
            return Err(err(SyscallError::EFAULT));
        }

        let mut insns = Vec::with_capacity(len);
        for chunk in raw.chunks_exact(8) {
            insns.push(ClassicBpfInsn {
                code: u16::from_ne_bytes([chunk[0], chunk[1]]),
                jt: chunk[2],
                jf: chunk[3],
                k: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            });
        }
        let program = Self { insns };
        program.validate()?;
        Ok(program)
    }

    /// 执行过滤器并返回允许复制给用户的长度。
    ///
    /// Linux cBPF 语义里返回 0 表示丢包，返回正数表示通过，且该值作为 snaplen。
    pub(crate) fn filter_len(&self, packet: &[u8]) -> Option<usize> {
        self.execute(packet).and_then(|snaplen| {
            if snaplen == 0 {
                None
            } else {
                Some(core::cmp::min(snaplen, packet.len()))
            }
        })
    }

    /// 用于 getsockopt(SO_GET_FILTER) 回显指令数。
    pub(crate) fn instruction_count(&self) -> usize {
        self.insns.len()
    }

    /// 按 `struct sock_filter` 的内存布局序列化，供 `SO_GET_FILTER` 返回给用户态。
    pub(crate) fn to_sock_filter_bytes(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(self.insns.len() * size_of::<ClassicBpfInsn>());
        for insn in self.insns.iter().copied() {
            raw.extend_from_slice(&insn.code.to_ne_bytes());
            raw.push(insn.jt);
            raw.push(insn.jf);
            raw.extend_from_slice(&insn.k.to_ne_bytes());
        }
        raw
    }

    /// 静态校验 cBPF 程序。
    ///
    /// 校验目标是让解释器执行时不会越界跳转、访问非法 scratch memory、执行除零，
    /// 并确保程序最终以 `RET K` 或 `RET A` 结束。
    fn validate(&self) -> Result<(), isize> {
        if self.insns.is_empty() || self.insns.len() > BPF_MAXINSNS {
            return Err(err(SyscallError::EINVAL));
        }
        for (pc, insn) in self.insns.iter().copied().enumerate() {
            if !Self::code_allowed(insn.code) {
                return Err(err(SyscallError::EINVAL));
            }
            match insn.code {
                code if code == (BPF_ALU | BPF_DIV | BPF_K)
                    || code == (BPF_ALU | BPF_MOD | BPF_K) =>
                {
                    if insn.k == 0 {
                        return Err(err(SyscallError::EINVAL));
                    }
                }
                code if code == (BPF_ALU | BPF_LSH | BPF_K)
                    || code == (BPF_ALU | BPF_RSH | BPF_K) =>
                {
                    if insn.k >= 32 {
                        return Err(err(SyscallError::EINVAL));
                    }
                }
                code if code == (BPF_LD | BPF_MEM)
                    || code == (BPF_LDX | BPF_MEM)
                    || code == BPF_ST
                    || code == BPF_STX =>
                {
                    if insn.k as usize >= BPF_MEMWORDS {
                        return Err(err(SyscallError::EINVAL));
                    }
                }
                code if (code & BPF_CLASS_MASK) == BPF_LD
                    && (code & BPF_MODE_MASK) == BPF_ABS
                    && insn.k >= SKF_AD_OFF =>
                {
                    // Linux 会把这些负偏移转换成 skb metadata load。当前我们对外报告
                    // `SO_BPF_EXTENSIONS = 0`，所以这里直接拒绝，避免过滤器被静默装上
                    // 但永远读不到它期望的 metadata。
                    return Err(err(SyscallError::EINVAL));
                }
                code if code == (BPF_JMP | BPF_JA) => {
                    if insn.k as usize >= self.insns.len() - pc - 1 {
                        return Err(err(SyscallError::EINVAL));
                    }
                }
                code if (code & BPF_CLASS_MASK) == BPF_JMP && (code & BPF_OP_MASK) != BPF_JA => {
                    if pc + insn.jt as usize + 1 >= self.insns.len()
                        || pc + insn.jf as usize + 1 >= self.insns.len()
                    {
                        return Err(err(SyscallError::EINVAL));
                    }
                }
                _ => {}
            }
        }

        match self.insns.last().map(|insn| insn.code) {
            Some(code) if code == (BPF_RET | BPF_K) || code == (BPF_RET | BPF_A) => Ok(()),
            _ => Err(err(SyscallError::EINVAL)),
        }
    }

    /// 白名单校验 opcode 组合，拒绝未实现或 Linux 不允许的 cBPF 指令形态。
    fn code_allowed(code: u16) -> bool {
        match code & BPF_CLASS_MASK {
            BPF_LD => matches!(
                (code & BPF_MODE_MASK, code & BPF_SIZE_MASK),
                (BPF_IMM, BPF_W)
                    | (BPF_MEM, BPF_W)
                    | (BPF_LEN, BPF_W)
                    | (BPF_ABS, BPF_W | BPF_H | BPF_B)
                    | (BPF_IND, BPF_W | BPF_H | BPF_B)
            ),
            BPF_LDX => matches!(
                (code & BPF_MODE_MASK, code & BPF_SIZE_MASK),
                (BPF_IMM, BPF_W) | (BPF_MEM, BPF_W) | (BPF_LEN, BPF_W) | (BPF_MSH, BPF_B)
            ),
            BPF_ST | BPF_STX => code == BPF_ST || code == BPF_STX,
            BPF_ALU => match code & BPF_OP_MASK {
                BPF_NEG => code == (BPF_ALU | BPF_NEG),
                BPF_ADD | BPF_SUB | BPF_MUL | BPF_DIV | BPF_OR | BPF_AND | BPF_LSH | BPF_RSH
                | BPF_MOD | BPF_XOR => matches!(code & BPF_SRC_MASK, BPF_K | BPF_X),
                _ => false,
            },
            BPF_JMP => match code & BPF_OP_MASK {
                BPF_JA => code == (BPF_JMP | BPF_JA),
                BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET => {
                    matches!(code & BPF_SRC_MASK, BPF_K | BPF_X)
                }
                _ => false,
            },
            BPF_RET => matches!(code & 0x18, BPF_K | BPF_A),
            BPF_MISC => matches!(code & BPF_MISCOP_MASK, BPF_TAX | BPF_TXA),
            _ => false,
        }
    }

    /// 解释执行 classic BPF。
    ///
    /// cBPF 只有两个寄存器：累加器 A 和索引寄存器 X；另有 16 个 scratch memory word。
    /// 所有 packet load 都使用网络字节序，和 Linux socket filter 语义保持一致。
    fn execute(&self, packet: &[u8]) -> Option<usize> {
        let mut a = 0u32;
        let mut x = 0u32;
        let mut mem = [0u32; BPF_MEMWORDS];
        let mut pc = 0usize;

        while pc < self.insns.len() {
            let insn = self.insns[pc];
            match insn.code & BPF_CLASS_MASK {
                BPF_LD => {
                    a = self.load_value(packet, insn, x, &mem)?;
                    pc += 1;
                }
                BPF_LDX => {
                    x = self.load_value(packet, insn, x, &mem)?;
                    pc += 1;
                }
                BPF_ST => {
                    mem[insn.k as usize] = a;
                    pc += 1;
                }
                BPF_STX => {
                    mem[insn.k as usize] = x;
                    pc += 1;
                }
                BPF_ALU => {
                    let rhs = if (insn.code & BPF_SRC_MASK) == BPF_X {
                        x
                    } else {
                        insn.k
                    };
                    a = match insn.code & BPF_OP_MASK {
                        BPF_ADD => a.wrapping_add(rhs),
                        BPF_SUB => a.wrapping_sub(rhs),
                        BPF_MUL => a.wrapping_mul(rhs),
                        BPF_DIV => {
                            if rhs == 0 {
                                return None;
                            }
                            a / rhs
                        }
                        BPF_OR => a | rhs,
                        BPF_AND => a & rhs,
                        BPF_LSH => a.wrapping_shl((rhs & 31) as u32),
                        BPF_RSH => a.wrapping_shr((rhs & 31) as u32),
                        BPF_NEG => a.wrapping_neg(),
                        BPF_MOD => {
                            if rhs == 0 {
                                return None;
                            }
                            a % rhs
                        }
                        BPF_XOR => a ^ rhs,
                        _ => return None,
                    };
                    pc += 1;
                }
                BPF_JMP => {
                    let rhs = if (insn.code & BPF_SRC_MASK) == BPF_X {
                        x
                    } else {
                        insn.k
                    };
                    let taken = match insn.code & BPF_OP_MASK {
                        BPF_JA => {
                            pc = pc.checked_add(1 + insn.k as usize)?;
                            continue;
                        }
                        BPF_JEQ => a == rhs,
                        BPF_JGT => a > rhs,
                        BPF_JGE => a >= rhs,
                        BPF_JSET => (a & rhs) != 0,
                        _ => return None,
                    };
                    let offset = if taken { insn.jt } else { insn.jf } as usize;
                    pc = pc.checked_add(1 + offset)?;
                }
                BPF_RET => {
                    let value = if (insn.code & 0x18) == BPF_A {
                        a
                    } else {
                        insn.k
                    };
                    return Some(value as usize);
                }
                BPF_MISC => {
                    match insn.code & BPF_MISCOP_MASK {
                        BPF_TAX => x = a,
                        BPF_TXA => a = x,
                        _ => return None,
                    }
                    pc += 1;
                }
                _ => return None,
            }
        }
        None
    }

    /// 实现 LD/LDX 的各种寻址模式。
    fn load_value(
        &self,
        packet: &[u8],
        insn: ClassicBpfInsn,
        x: u32,
        mem: &[u32; BPF_MEMWORDS],
    ) -> Option<u32> {
        match insn.code & BPF_MODE_MASK {
            BPF_IMM => Some(insn.k),
            BPF_MEM => mem.get(insn.k as usize).copied(),
            BPF_LEN => Some(packet.len() as u32),
            BPF_ABS => self.load_packet(packet, insn.k as usize, insn.code & BPF_SIZE_MASK),
            BPF_IND => {
                let offset = (x as usize).checked_add(insn.k as usize)?;
                self.load_packet(packet, offset, insn.code & BPF_SIZE_MASK)
            }
            BPF_MSH => {
                let offset = insn.k as usize;
                let byte = *packet.get(offset)?;
                Some(((byte & 0x0f) as u32) << 2)
            }
            _ => None,
        }
    }

    /// 从 packet 中按 cBPF 规则读取 1/2/4 字节，越界则让过滤器执行失败。
    fn load_packet(&self, packet: &[u8], offset: usize, size: u16) -> Option<u32> {
        match size {
            BPF_W => {
                let end = offset.checked_add(4)?;
                let bytes = packet.get(offset..end)?;
                Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            BPF_H => {
                let end = offset.checked_add(2)?;
                let bytes = packet.get(offset..end)?;
                Some(u16::from_be_bytes([bytes[0], bytes[1]]) as u32)
            }
            BPF_B => packet.get(offset).copied().map(u32::from),
            _ => None,
        }
    }
}
