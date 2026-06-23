use alloc::{vec, vec::Vec};

use crate::syscall::error::SyscallError::{EACCES, EFAULT, EINVAL, ENOSYS};

use super::{
    BpfResult,
    prog::BpfProgFile,
    uapi::{
        BPF_ADD, BPF_ALU, BPF_ALU64, BPF_B, BPF_CALL, BPF_CLASS_MASK, BPF_DIV, BPF_DW, BPF_EXIT,
        BPF_FUNC_MAP_LOOKUP_ELEM, BPF_H, BPF_IMM, BPF_JEQ, BPF_JMP, BPF_JNE, BPF_LD, BPF_LDX,
        BPF_LSH, BPF_MEM, BPF_MOD, BPF_MODE_MASK, BPF_MOV, BPF_OP_MASK, BPF_PSEUDO_MAP_FD,
        BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_10, BPF_RSH, BPF_SIZE_MASK, BPF_SRC_MASK, BPF_ST,
        BPF_STACK_SIZE, BPF_STX, BPF_SUB, BPF_W, BPF_X, MAX_BPF_REG,
    },
};

/// 执行 BPF 字节码，以 r0 的值作为返回值。
///
/// 初始状态：r1 = PacketPtr(0)，r2 = 包长度，r10 = FramePtr。
pub(super) fn execute(prog: &BpfProgFile, packet: &[u8]) -> BpfResult<u64> {
    let mut regs: [RuntimeValue; MAX_BPF_REG] = core::array::from_fn(|_| RuntimeValue::Scalar(0));
    regs[BPF_REG_1] = RuntimeValue::PacketPtr { offset: 0 };
    regs[BPF_REG_2] = RuntimeValue::Scalar(packet.len() as u64);
    regs[BPF_REG_10] = RuntimeValue::FramePtr;
    let mut stack = [0u8; BPF_STACK_SIZE];
    let mut pc = 0usize;
    while pc < prog.insns.len() {
        let insn = prog.insns[pc];
        let class = insn.code & BPF_CLASS_MASK;
        match class {
            BPF_LD
                if (insn.code & BPF_MODE_MASK) == BPF_IMM
                    && (insn.code & BPF_SIZE_MASK) == BPF_DW =>
            {
                if pc + 1 >= prog.insns.len() {
                    return Err(EINVAL);
                }
                let hi = prog.insns[pc + 1].imm as u32 as u64;
                let lo = insn.imm as u32 as u64;
                let imm64 = lo | (hi << 32);
                regs[insn.dst_reg()] = if insn.src_reg() as u8 == BPF_PSEUDO_MAP_FD {
                    RuntimeValue::MapFd(imm64 as u32)
                } else {
                    RuntimeValue::Scalar(imm64)
                };
                pc += 2;
                continue;
            }
            BPF_LDX if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                regs[insn.dst_reg()] = RuntimeValue::Scalar(load_value(
                    prog,
                    &stack,
                    packet,
                    &regs[insn.src_reg()],
                    insn.off,
                    insn.code & BPF_SIZE_MASK,
                )?);
            }
            BPF_ST if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                let data = imm_to_bytes(insn.imm, insn.code & BPF_SIZE_MASK);
                store_value(prog, &mut stack, &mut regs[insn.dst_reg()], insn.off, &data)?;
            }
            BPF_STX if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                let data = scalar_to_sized_bytes(
                    regs[insn.src_reg()].as_u64(),
                    insn.code & BPF_SIZE_MASK,
                )?;
                store_value(prog, &mut stack, &mut regs[insn.dst_reg()], insn.off, &data)?;
            }
            BPF_ALU | BPF_ALU64 => {
                let is_alu64 = class == BPF_ALU64;
                let op = insn.code & BPF_OP_MASK;
                let src_is_reg = (insn.code & BPF_SRC_MASK) == BPF_X;
                if op == BPF_MOV {
                    regs[insn.dst_reg()] = if src_is_reg {
                        regs[insn.src_reg()].clone()
                    } else if is_alu64 {
                        RuntimeValue::Scalar(insn.imm as i64 as u64)
                    } else {
                        RuntimeValue::Scalar((insn.imm as u32) as u64)
                    };
                } else {
                    let src = if src_is_reg {
                        regs[insn.src_reg()].as_u64()
                    } else {
                        insn.imm as i64 as u64
                    };
                    exec_alu(&mut regs[insn.dst_reg()], op, src, is_alu64)?;
                }
            }
            BPF_JMP => {
                let op = insn.code & BPF_OP_MASK;
                if op == BPF_CALL {
                    if insn.imm != BPF_FUNC_MAP_LOOKUP_ELEM {
                        return Err(ENOSYS);
                    }
                    let RuntimeValue::MapFd(map_fd) = regs[BPF_REG_1] else {
                        return Err(EINVAL);
                    };
                    let key = load_stack_key(&stack, &regs[BPF_REG_2], prog.map_key_size(map_fd)?)?;
                    regs[BPF_REG_0] = if prog.map_lookup_bytes(map_fd, key.as_slice())?.is_some() {
                        RuntimeValue::MapValuePtr {
                            map_fd,
                            key,
                            offset: 0,
                        }
                    } else {
                        RuntimeValue::Null
                    };
                } else if op == BPF_EXIT {
                    return Ok(regs[BPF_REG_0].as_u64());
                } else if op == BPF_JEQ || op == BPF_JNE {
                    let lhs = regs[insn.dst_reg()].as_u64();
                    let rhs = if (insn.code & BPF_SRC_MASK) == BPF_X {
                        regs[insn.src_reg()].as_u64()
                    } else {
                        insn.imm as i64 as u64
                    };
                    let taken = if op == BPF_JEQ {
                        lhs == rhs
                    } else {
                        lhs != rhs
                    };
                    if taken {
                        pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                        continue;
                    }
                } else {
                    return Err(ENOSYS);
                }
            }
            _ => return Err(ENOSYS),
        }
        pc += 1;
    }
    Ok(regs[BPF_REG_0].as_u64())
}

/// BPF 寄存器在运行时的值类型。
///
/// 除 Scalar 外的变体均携带指针语义，用于在执行器中进行安全的内存访问检查。
#[derive(Clone)]
enum RuntimeValue {
    /// 普通标量（整数）
    Scalar(u64),
    /// 空指针（map_lookup_elem 未命中时 r0 被置为 Null）
    Null,
    /// map 文件描述符（ldimm64 BPF_PSEUDO_MAP_FD）
    MapFd(u32),
    /// 帧指针 r10，指向栈底（BPF_STACK_SIZE 处）
    FramePtr,
    /// 相对于帧底的栈指针偏移（由帧指针加减运算产生）
    StackPtr(i64),
    /// map value 内部指针（map_lookup_elem 命中后 r0 被置为此变体）
    MapValuePtr {
        map_fd: u32,
        key: Vec<u8>,
        offset: i64,
    },
    /// 数据包内部指针，offset 为相对于包头的字节偏移
    PacketPtr { offset: i64 },
}

impl RuntimeValue {
    fn as_u64(&self) -> u64 {
        match self {
            Self::Scalar(value) => *value,
            Self::Null => 0,
            Self::MapFd(fd) => *fd as u64,
            Self::FramePtr => 0,
            Self::StackPtr(off) => *off as u64,
            Self::MapValuePtr { .. } => 1,
            Self::PacketPtr { offset } => *offset as u64,
        }
    }
}

/// 执行一条 ALU 指令，将结果写回 `dst`。
///
/// - 指针类型（FramePtr/StackPtr/PacketPtr）只允许加减，结果保持指针语义。
/// - MapValuePtr 上的算术一律拒绝（EACCES）。
/// - 标量支持完整操作集；32 位模式（!is_alu64）使用截断后的 u32 运算。
fn exec_alu(dst: &mut RuntimeValue, op: u8, src: u64, is_alu64: bool) -> BpfResult<()> {
    match dst {
        RuntimeValue::FramePtr | RuntimeValue::StackPtr(_) | RuntimeValue::PacketPtr { .. } => {
            let cur = match dst {
                RuntimeValue::FramePtr => 0,
                RuntimeValue::StackPtr(off) => *off,
                RuntimeValue::PacketPtr { offset } => *offset,
                _ => 0,
            };
            let src = src as i64;
            let was_packet_ptr = matches!(dst, RuntimeValue::PacketPtr { .. });
            *dst = match op {
                BPF_ADD if was_packet_ptr => RuntimeValue::PacketPtr {
                    offset: cur.wrapping_add(src),
                },
                BPF_SUB if was_packet_ptr => RuntimeValue::PacketPtr {
                    offset: cur.wrapping_sub(src),
                },
                BPF_ADD => RuntimeValue::StackPtr(cur.wrapping_add(src)),
                BPF_SUB => RuntimeValue::StackPtr(cur.wrapping_sub(src)),
                BPF_MOV => RuntimeValue::Scalar(src as u64),
                _ => return Err(ENOSYS),
            };
            Ok(())
        }
        RuntimeValue::MapValuePtr { .. } => Err(EACCES),
        _ => {
            let cur = dst.as_u64();
            let result = if is_alu64 {
                match op {
                    BPF_ADD => cur.wrapping_add(src),
                    BPF_SUB => cur.wrapping_sub(src),
                    BPF_LSH => cur.wrapping_shl((src & 63) as u32),
                    BPF_RSH => cur.wrapping_shr((src & 63) as u32),
                    BPF_MOV => src,
                    _ => return Err(ENOSYS),
                }
            } else {
                let dst32 = cur as u32;
                let src32 = src as u32;
                match op {
                    BPF_DIV => {
                        if src32 == 0 {
                            0
                        } else {
                            (dst32 / src32) as u64
                        }
                    }
                    BPF_MOD => {
                        if src32 == 0 {
                            dst32 as u64
                        } else {
                            (dst32 % src32) as u64
                        }
                    }
                    BPF_SUB => dst32.wrapping_sub(src32) as u64,
                    BPF_RSH => dst32.wrapping_shr((src32 & 31) as u32) as u64,
                    BPF_MOV => src32 as u64,
                    _ => return Err(ENOSYS),
                }
            };
            *dst = RuntimeValue::Scalar(result);
            Ok(())
        }
    }
}

/// 将 1/2/4/8 字节的 little-endian 字节数组转换为 u64 标量。
fn sized_bytes_to_scalar(bytes: &[u8]) -> BpfResult<u64> {
    Ok(match bytes.len() {
        1 => bytes[0] as u64,
        2 => u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
        4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
        8 => u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        _ => return Err(ENOSYS),
    })
}

/// 将 BPF_B/H/W/DW 宽度码转换为字节数。
fn size_to_len(size: u8) -> BpfResult<usize> {
    match size {
        BPF_B => Ok(1),
        BPF_H => Ok(2),
        BPF_W => Ok(4),
        BPF_DW => Ok(8),
        _ => Err(ENOSYS),
    }
}

/// 从 src 指针指向的内存中加载 `size` 宽度的值并返回 u64。
///
/// 支持的指针类型：FramePtr、StackPtr（读栈）、MapValuePtr（读 map）、PacketPtr（读包）。
fn load_value(
    prog: &BpfProgFile,
    stack: &[u8; BPF_STACK_SIZE],
    packet: &[u8],
    src: &RuntimeValue,
    off: i16,
    size: u8,
) -> BpfResult<u64> {
    let len = size_to_len(size)?;
    match src {
        RuntimeValue::FramePtr => {
            let start = pointer_offset_to_stack(0, off, len)?;
            sized_bytes_to_scalar(&stack[start..start + len])
        }
        RuntimeValue::StackPtr(base) => {
            let start = pointer_offset_to_stack(*base, off, len)?;
            sized_bytes_to_scalar(&stack[start..start + len])
        }
        RuntimeValue::MapValuePtr {
            map_fd,
            key,
            offset,
        } => {
            let start = offset.checked_add(off as i64).ok_or(EINVAL)?;
            if start < 0 {
                return Err(EACCES);
            }
            let data = prog.map_load_bytes(*map_fd, key.as_slice(), start as usize, len)?;
            sized_bytes_to_scalar(&data)
        }
        RuntimeValue::PacketPtr { offset } => {
            let start = offset.checked_add(off as i64).ok_or(EINVAL)?;
            if start < 0 {
                return Err(EACCES);
            }
            let start = start as usize;
            let end = start.checked_add(len).ok_or(EINVAL)?;
            if end > packet.len() {
                return Err(EACCES);
            }
            sized_bytes_to_scalar(&packet[start..end])
        }
        _ => Err(EINVAL),
    }
}

/// 将（帧底相对偏移 base + 指令 off）映射到栈数组的绝对下标。
///
/// BPF 栈从高地址向低地址增长（r10 指向 BPF_STACK_SIZE），因此
/// 实际下标 = BPF_STACK_SIZE + base + off，越界则返回 EFAULT。
fn pointer_offset_to_stack(base: i64, off: i16, len: usize) -> BpfResult<usize> {
    let start = (BPF_STACK_SIZE as i64)
        .checked_add(base)
        .and_then(|v| v.checked_add(off as i64))
        .ok_or(EFAULT)?;
    let end = start.checked_add(len as i64).ok_or(EFAULT)?;
    if start < 0 || end < 0 || end as usize > BPF_STACK_SIZE {
        return Err(EFAULT);
    }
    Ok(start as usize)
}

/// 将 `data` 写入 dst 指针指向的内存（栈或 map value）。
fn store_value(
    prog: &BpfProgFile,
    stack: &mut [u8; BPF_STACK_SIZE],
    dst: &mut RuntimeValue,
    off: i16,
    data: &[u8],
) -> BpfResult<()> {
    match dst {
        RuntimeValue::FramePtr => {
            let start = pointer_offset_to_stack(0, off, data.len())?;
            stack[start..start + data.len()].copy_from_slice(data);
            Ok(())
        }
        RuntimeValue::StackPtr(base) => {
            let start = pointer_offset_to_stack(*base, off, data.len())?;
            stack[start..start + data.len()].copy_from_slice(data);
            Ok(())
        }
        RuntimeValue::MapValuePtr {
            map_fd,
            key,
            offset,
        } => {
            let start = offset.checked_add(off as i64).ok_or(EINVAL)?;
            if start < 0 {
                return Err(EACCES);
            }
            prog.map_store_bytes(*map_fd, key.as_slice(), start as usize, data)
        }
        _ => Err(EINVAL),
    }
}

/// 从栈上读取 `len` 字节作为 map 查找的 key（由 r2 寄存器指向）。
fn load_stack_key(
    stack: &[u8; BPF_STACK_SIZE],
    reg: &RuntimeValue,
    len: usize,
) -> BpfResult<Vec<u8>> {
    let start = match reg {
        RuntimeValue::FramePtr => pointer_offset_to_stack(0, 0, len)?,
        RuntimeValue::StackPtr(base) => pointer_offset_to_stack(*base, 0, len)?,
        _ => return Err(EINVAL),
    };
    Ok(stack[start..start + len].to_vec())
}

/// 将 i32 立即数按指定宽度截断并转换为 little-endian 字节向量（用于 ST 指令）。
fn imm_to_bytes(imm: i32, size: u8) -> Vec<u8> {
    match size {
        BPF_B => vec![imm as u8],
        BPF_H => (imm as u16).to_le_bytes().to_vec(),
        BPF_W => (imm as u32).to_le_bytes().to_vec(),
        BPF_DW => (imm as i64 as u64).to_le_bytes().to_vec(),
        _ => vec![],
    }
}

/// 将 u64 标量按指定宽度截断并转换为 little-endian 字节向量（用于 STX 指令）。
fn scalar_to_sized_bytes(value: u64, size: u8) -> BpfResult<Vec<u8>> {
    Ok(match size {
        BPF_B => vec![value as u8],
        BPF_H => (value as u16).to_le_bytes().to_vec(),
        BPF_W => (value as u32).to_le_bytes().to_vec(),
        BPF_DW => value.to_le_bytes().to_vec(),
        _ => return Err(ENOSYS),
    })
}
