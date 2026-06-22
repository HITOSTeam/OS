use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::any::Any;
use spin::Mutex;

use crate::{
    fs::File,
    mm::{UserBuffer, try_copy_from_user, try_copy_to_user},
    task::processor::{current_files, current_files_and_nofile_limit},
    trap::get_current_token,
};

const EINVAL: isize = -22;
const EMFILE: isize = -24;
const EBADF: isize = -9;
const EFAULT: isize = -14;
const ENOSYS: isize = -38;
const ENOENT: isize = -2;
const EEXIST: isize = -17;
const ENOMEM: isize = -12;
const EACCES: isize = -13;
const E2BIG: isize = -7;

const BPF_MAP_CREATE: usize = 0;
const BPF_MAP_LOOKUP_ELEM: usize = 1;
const BPF_MAP_UPDATE_ELEM: usize = 2;
const BPF_PROG_LOAD: usize = 5;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;

const BPF_ANY: u64 = 0;
const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;

const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;

const BPF_CLASS_MASK: u8 = 0x07;
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;

const BPF_SIZE_MASK: u8 = 0x18;
const BPF_W: u8 = 0x00;
const BPF_H: u8 = 0x08;
const BPF_B: u8 = 0x10;
const BPF_DW: u8 = 0x18;

const BPF_MODE_MASK: u8 = 0xe0;
const BPF_IMM: u8 = 0x00;
const BPF_MEM: u8 = 0x60;

const BPF_SRC_MASK: u8 = 0x08;
const BPF_X: u8 = 0x08;

const BPF_OP_MASK: u8 = 0xf0;
const BPF_ADD: u8 = 0x00;
const BPF_SUB: u8 = 0x10;
const BPF_DIV: u8 = 0x30;
const BPF_JEQ: u8 = 0x10;
const BPF_JNE: u8 = 0x50;
const BPF_LSH: u8 = 0x60;
const BPF_RSH: u8 = 0x70;
const BPF_MOD: u8 = 0x90;
const BPF_MOV: u8 = 0xb0;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;

const BPF_REG_0: usize = 0;
const BPF_REG_1: usize = 1;
const BPF_REG_2: usize = 2;
const BPF_REG_10: usize = 10;
const MAX_BPF_REG: usize = 11;
const BPF_STACK_SIZE: usize = 512;
const BPF_MAXINSNS: u32 = 4096;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfMapElemAttr {
    map_fd: u32,
    pad0: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    fn dst_reg(self) -> usize {
        (self.regs & 0x0f) as usize
    }

    fn src_reg(self) -> usize {
        (self.regs >> 4) as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BpfMapKind {
    Hash,
    Array,
    RingBuf,
}

struct BpfMapInner {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

pub struct BpfMapFile {
    kind: BpfMapKind,
    pub key_size: u32,
    pub value_size: u32,
    max_entries: u32,
    inner: Mutex<BpfMapInner>,
}

impl BpfMapFile {
    fn new(
        kind: BpfMapKind,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Result<Self, isize> {
        if max_entries == 0 {
            return Err(EINVAL);
        }
        match kind {
            BpfMapKind::Hash | BpfMapKind::Array => {
                if key_size == 0 || value_size == 0 {
                    return Err(EINVAL);
                }
            }
            BpfMapKind::RingBuf => {
                if key_size != 0 || value_size != 0 {
                    return Err(EINVAL);
                }
            }
        }
        let mut entries = BTreeMap::new();
        if kind == BpfMapKind::Array {
            for index in 0..max_entries {
                let mut key = vec![0u8; key_size as usize];
                let raw = index.to_le_bytes();
                let n = key.len().min(raw.len());
                key[..n].copy_from_slice(&raw[..n]);
                entries.insert(key, vec![0u8; value_size as usize]);
            }
        }
        Ok(Self {
            kind,
            key_size,
            value_size,
            max_entries,
            inner: Mutex::new(BpfMapInner { entries }),
        })
    }

    fn validate_key(&self, key: &[u8]) -> bool {
        key.len() == self.key_size as usize
    }

    fn key_to_index(&self, key: &[u8]) -> Option<u32> {
        if !self.validate_key(key) {
            return None;
        }
        let mut raw = [0u8; 4];
        let n = key.len().min(raw.len());
        raw[..n].copy_from_slice(&key[..n]);
        Some(u32::from_le_bytes(raw))
    }

    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        if !self.validate_key(key) {
            return None;
        }
        if self.kind == BpfMapKind::Array && self.key_to_index(key)? >= self.max_entries {
            return None;
        }
        self.inner.lock().entries.get(key).cloned()
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), isize> {
        if !self.validate_key(key) || value.len() != self.value_size as usize {
            return Err(EINVAL);
        }
        if self.kind == BpfMapKind::RingBuf {
            return Err(EINVAL);
        }
        if self.kind == BpfMapKind::Array
            && self.key_to_index(key).ok_or(EINVAL)? >= self.max_entries
        {
            return Err(EINVAL);
        }
        let mut inner = self.inner.lock();
        let exists = inner.entries.contains_key(key);
        match flags {
            BPF_ANY => {}
            BPF_NOEXIST if exists => return Err(EEXIST),
            BPF_NOEXIST => {}
            BPF_EXIST if !exists => return Err(ENOENT),
            BPF_EXIST => {}
            _ => return Err(EINVAL),
        }
        inner.entries.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn store_bytes(&self, key: &[u8], offset: usize, data: &[u8]) -> Result<(), isize> {
        if self.kind == BpfMapKind::RingBuf {
            return Err(EINVAL);
        }
        let mut inner = self.inner.lock();
        let Some(value) = inner.entries.get_mut(key) else {
            return Err(ENOENT);
        };
        let end = offset.checked_add(data.len()).ok_or(EINVAL)?;
        if end > value.len() {
            return Err(EACCES);
        }
        value[offset..end].copy_from_slice(data);
        Ok(())
    }
}

impl File for BpfMapFile {
    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone)]
pub struct BpfProgFile {
    insns: Vec<BpfInsn>,
    maps: BTreeMap<u32, Arc<dyn File + Send + Sync>>,
}

impl BpfProgFile {
    fn new(insns: Vec<BpfInsn>, maps: BTreeMap<u32, Arc<dyn File + Send + Sync>>) -> Self {
        Self { insns, maps }
    }

    pub fn filter_len(&self, packet: &[u8]) -> Option<usize> {
        let len = self.execute(packet).ok()? as usize;
        (len != 0).then_some(len.min(packet.len()))
    }

    fn with_map<R>(&self, fd: u32, f: impl FnOnce(&BpfMapFile) -> R) -> Option<R> {
        let file = self.maps.get(&fd)?;
        let map = file.as_any().downcast_ref::<BpfMapFile>()?;
        Some(f(map))
    }

    fn map_key_size(&self, fd: u32) -> Result<usize, isize> {
        self.with_map(fd, |map| map.key_size as usize).ok_or(EBADF)
    }

    fn map_lookup_bytes(&self, fd: u32, key: &[u8]) -> Option<Vec<u8>> {
        self.with_map(fd, |map| map.lookup(key)).flatten()
    }

    fn map_load_bytes(
        &self,
        fd: u32,
        key: &[u8],
        offset: usize,
        len: usize,
    ) -> Result<Vec<u8>, isize> {
        let value = self.map_lookup_bytes(fd, key).ok_or(ENOENT)?;
        let end = offset.checked_add(len).ok_or(EINVAL)?;
        if end > value.len() {
            return Err(EACCES);
        }
        Ok(value[offset..end].to_vec())
    }

    fn map_store_bytes(
        &self,
        fd: u32,
        key: &[u8],
        offset: usize,
        data: &[u8],
    ) -> Result<(), isize> {
        self.with_map(fd, |map| map.store_bytes(key, offset, data))
            .ok_or(EBADF)?
    }

    fn execute(&self, packet: &[u8]) -> Result<u64, isize> {
        let mut regs: [RuntimeValue; MAX_BPF_REG] =
            core::array::from_fn(|_| RuntimeValue::Scalar(0));
        regs[BPF_REG_1] = RuntimeValue::PacketPtr { offset: 0 };
        regs[BPF_REG_2] = RuntimeValue::Scalar(packet.len() as u64);
        regs[BPF_REG_10] = RuntimeValue::FramePtr;
        let mut stack = [0u8; BPF_STACK_SIZE];
        let mut pc = 0usize;
        while pc < self.insns.len() {
            let insn = self.insns[pc];
            let class = insn.code & BPF_CLASS_MASK;
            match class {
                BPF_LD
                    if (insn.code & BPF_MODE_MASK) == BPF_IMM
                        && (insn.code & BPF_SIZE_MASK) == BPF_DW =>
                {
                    if pc + 1 >= self.insns.len() {
                        return Err(EINVAL);
                    }
                    let hi = self.insns[pc + 1].imm as u32 as u64;
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
                        self,
                        &stack,
                        packet,
                        &regs[insn.src_reg()],
                        insn.off,
                        insn.code & BPF_SIZE_MASK,
                    )?);
                }
                BPF_ST if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                    let data = imm_to_bytes(insn.imm, insn.code & BPF_SIZE_MASK);
                    store_value(self, &mut stack, &mut regs[insn.dst_reg()], insn.off, &data)?;
                }
                BPF_STX if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                    let data = scalar_to_sized_bytes(
                        regs[insn.src_reg()].as_u64(),
                        insn.code & BPF_SIZE_MASK,
                    )?;
                    store_value(self, &mut stack, &mut regs[insn.dst_reg()], insn.off, &data)?;
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
                        let key =
                            load_stack_key(&stack, &regs[BPF_REG_2], self.map_key_size(map_fd)?)?;
                        regs[BPF_REG_0] = if self.map_lookup_bytes(map_fd, key.as_slice()).is_some()
                        {
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
}

impl File for BpfProgFile {
    fn readable(&self) -> bool {
        false
    }

    fn writable(&self) -> bool {
        false
    }

    fn read(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone)]
enum RuntimeValue {
    Scalar(u64),
    Null,
    MapFd(u32),
    FramePtr,
    StackPtr(i64),
    MapValuePtr {
        map_fd: u32,
        key: Vec<u8>,
        offset: i64,
    },
    PacketPtr {
        offset: i64,
    },
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

fn exec_alu(dst: &mut RuntimeValue, op: u8, src: u64, is_alu64: bool) -> Result<(), isize> {
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

fn sized_bytes_to_scalar(bytes: &[u8]) -> Result<u64, isize> {
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

fn size_to_len(size: u8) -> Result<usize, isize> {
    match size {
        BPF_B => Ok(1),
        BPF_H => Ok(2),
        BPF_W => Ok(4),
        BPF_DW => Ok(8),
        _ => Err(ENOSYS),
    }
}

fn load_value(
    prog: &BpfProgFile,
    stack: &[u8; BPF_STACK_SIZE],
    packet: &[u8],
    src: &RuntimeValue,
    off: i16,
    size: u8,
) -> Result<u64, isize> {
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

fn pointer_offset_to_stack(base: i64, off: i16, len: usize) -> Result<usize, isize> {
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

fn store_value(
    prog: &BpfProgFile,
    stack: &mut [u8; BPF_STACK_SIZE],
    dst: &mut RuntimeValue,
    off: i16,
    data: &[u8],
) -> Result<(), isize> {
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

fn load_stack_key(
    stack: &[u8; BPF_STACK_SIZE],
    reg: &RuntimeValue,
    len: usize,
) -> Result<Vec<u8>, isize> {
    let start = match reg {
        RuntimeValue::FramePtr => pointer_offset_to_stack(0, 0, len)?,
        RuntimeValue::StackPtr(base) => pointer_offset_to_stack(*base, 0, len)?,
        _ => return Err(EINVAL),
    };
    Ok(stack[start..start + len].to_vec())
}

fn imm_to_bytes(imm: i32, size: u8) -> Vec<u8> {
    match size {
        BPF_B => vec![imm as u8],
        BPF_H => (imm as u16).to_le_bytes().to_vec(),
        BPF_W => (imm as u32).to_le_bytes().to_vec(),
        BPF_DW => (imm as i64 as u64).to_le_bytes().to_vec(),
        _ => vec![],
    }
}

fn scalar_to_sized_bytes(value: u64, size: u8) -> Result<Vec<u8>, isize> {
    Ok(match size {
        BPF_B => vec![value as u8],
        BPF_H => (value as u16).to_le_bytes().to_vec(),
        BPF_W => (value as u32).to_le_bytes().to_vec(),
        BPF_DW => value.to_le_bytes().to_vec(),
        _ => return Err(ENOSYS),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegKind {
    Scalar,
    MapFd,
    FramePtr,
    StackPtr,
    MapValuePtr,
    PacketPtr,
}

fn verify_program(insns: &[BpfInsn]) -> Result<(), &'static str> {
    if !insns.last().is_some_and(|insn| {
        (insn.code & BPF_CLASS_MASK) == BPF_JMP && (insn.code & BPF_OP_MASK) == BPF_EXIT
    }) {
        return Err("program must end with exit");
    }
    let mut regs = [RegKind::Scalar; MAX_BPF_REG];
    regs[BPF_REG_1] = RegKind::PacketPtr;
    regs[BPF_REG_10] = RegKind::FramePtr;
    let mut pc = 0usize;
    while pc < insns.len() {
        let insn = insns[pc];
        let dst = checked_reg(insn.dst_reg())?;
        let src = checked_reg(insn.src_reg())?;
        let class = insn.code & BPF_CLASS_MASK;
        match class {
            BPF_LD
                if (insn.code & BPF_MODE_MASK) == BPF_IMM
                    && (insn.code & BPF_SIZE_MASK) == BPF_DW =>
            {
                if pc + 1 >= insns.len() {
                    return Err("truncated ldimm64");
                }
                let next = insns[pc + 1];
                if next.code != 0 || next.dst_reg() != 0 || next.src_reg() != 0 || next.off != 0 {
                    return Err("invalid ldimm64 pair");
                }
                if insn.off != 0 {
                    return Err("ldimm64 uses reserved fields");
                }
                if !matches!(insn.src_reg() as u8, 0 | BPF_PSEUDO_MAP_FD) {
                    return Err("unsupported ldimm64 pseudo source");
                }
                regs[dst] = if insn.src_reg() as u8 == BPF_PSEUDO_MAP_FD {
                    RegKind::MapFd
                } else {
                    RegKind::Scalar
                };
                pc += 2;
                continue;
            }
            BPF_LDX if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                if !matches!(
                    regs[src],
                    RegKind::FramePtr
                        | RegKind::StackPtr
                        | RegKind::MapValuePtr
                        | RegKind::PacketPtr
                ) {
                    return Err("memory load requires valid pointer");
                }
                regs[dst] = RegKind::Scalar;
            }
            BPF_ST if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                if !matches!(
                    regs[dst],
                    RegKind::FramePtr | RegKind::StackPtr | RegKind::MapValuePtr
                ) {
                    return Err("memory store requires valid pointer");
                }
            }
            BPF_STX if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                if !matches!(
                    regs[dst],
                    RegKind::FramePtr | RegKind::StackPtr | RegKind::MapValuePtr
                ) {
                    return Err("memory store requires valid pointer");
                }
                if !matches!(regs[src], RegKind::Scalar) {
                    return Err("memory store value must be scalar");
                }
            }
            BPF_ALU | BPF_ALU64 => {
                let op = insn.code & BPF_OP_MASK;
                let src_is_reg = (insn.code & BPF_SRC_MASK) == BPF_X;
                if op == BPF_MOV {
                    regs[dst] = if src_is_reg {
                        regs[src]
                    } else {
                        RegKind::Scalar
                    };
                } else {
                    if src_is_reg && !matches!(regs[src], RegKind::Scalar) {
                        return Err("alu source must be scalar");
                    }
                    match regs[dst] {
                        RegKind::MapFd => {
                            return Err("map fd arithmetic rejected");
                        }
                        RegKind::MapValuePtr => {
                            return Err("pointer arithmetic on map value rejected");
                        }
                        RegKind::FramePtr | RegKind::StackPtr | RegKind::PacketPtr => {
                            if !matches!(op, BPF_ADD | BPF_SUB) {
                                return Err("unsupported pointer operation");
                            }
                            if regs[dst] != RegKind::PacketPtr {
                                regs[dst] = RegKind::StackPtr;
                            }
                        }
                        _ => regs[dst] = RegKind::Scalar,
                    }
                }
            }
            BPF_JMP => {
                let op = insn.code & BPF_OP_MASK;
                if op == BPF_CALL {
                    if insn.imm != BPF_FUNC_MAP_LOOKUP_ELEM {
                        return Err("unsupported bpf helper");
                    }
                    if !matches!(regs[BPF_REG_1], RegKind::MapFd) {
                        return Err("map_lookup_elem needs map fd in r1");
                    }
                    if !matches!(regs[BPF_REG_2], RegKind::FramePtr | RegKind::StackPtr) {
                        return Err("map_lookup_elem needs stack key pointer in r2");
                    }
                    regs[BPF_REG_0] = RegKind::MapValuePtr;
                } else if op == BPF_EXIT {
                    // Multiple return sites are valid; the final instruction check above
                    // prevents falling off the end without an explicit EXIT.
                } else if matches!(op, BPF_JEQ | BPF_JNE) {
                    let target = checked_jump_target(pc, insn.off, insns.len())?;
                    if target <= pc {
                        return Err("backward jumps unsupported");
                    }
                } else {
                    return Err("unsupported jump instruction");
                }
            }
            _ => return Err("unsupported bpf instruction"),
        }
        pc += 1;
    }
    Ok(())
}

fn checked_reg(reg: usize) -> Result<usize, &'static str> {
    if reg < MAX_BPF_REG {
        Ok(reg)
    } else {
        Err("invalid register")
    }
}

fn checked_jump_target(pc: usize, off: i16, len: usize) -> Result<usize, &'static str> {
    let target = (pc as isize)
        .checked_add(1)
        .and_then(|base| base.checked_add(off as isize))
        .ok_or("jump target overflow")?;
    if target < 0 || target >= len as isize {
        return Err("jump out of range");
    }
    Ok(target as usize)
}

fn collect_prog_map_refs(
    insns: &[BpfInsn],
) -> Result<BTreeMap<u32, Arc<dyn File + Send + Sync>>, isize> {
    let files = current_files();
    let files = files.lock();
    let mut maps = BTreeMap::new();
    let mut pc = 0usize;
    while pc < insns.len() {
        let insn = insns[pc];
        if (insn.code & BPF_CLASS_MASK) == BPF_LD
            && (insn.code & BPF_MODE_MASK) == BPF_IMM
            && (insn.code & BPF_SIZE_MASK) == BPF_DW
        {
            if pc + 1 >= insns.len() {
                return Err(EINVAL);
            }
            if insn.src_reg() as u8 == BPF_PSEUDO_MAP_FD {
                let fd = insn.imm as u32;
                let file = files.get_file(fd as usize).ok_or(EBADF)?;
                if file.as_any().downcast_ref::<BpfMapFile>().is_none() {
                    return Err(EBADF);
                }
                maps.insert(fd, file);
            }
            pc += 2;
            continue;
        }
        pc += 1;
    }
    Ok(maps)
}

fn copy_user_struct<T: Copy + Default>(user_ptr: usize) -> Result<T, isize> {
    let token = get_current_token();
    let mut value = T::default();
    let dst = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut value as *mut T).cast::<u8>(),
            core::mem::size_of::<T>(),
        )
    };
    if try_copy_from_user(token, user_ptr as *const u8, dst).is_err() {
        return Err(EFAULT);
    }
    Ok(value)
}

fn copy_user_insns(user_ptr: usize, count: usize) -> Result<Vec<BpfInsn>, isize> {
    let size = count
        .checked_mul(core::mem::size_of::<BpfInsn>())
        .ok_or(ENOMEM)?;
    let token = get_current_token();
    let mut raw = vec![0u8; size];
    if try_copy_from_user(token, user_ptr as *const u8, raw.as_mut_slice()).is_err() {
        return Err(EFAULT);
    }
    let mut out = Vec::with_capacity(count);
    for chunk in raw.chunks_exact(core::mem::size_of::<BpfInsn>()) {
        let mut insn = BpfInsn::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                (&mut insn as *mut BpfInsn).cast::<u8>(),
                core::mem::size_of::<BpfInsn>(),
            );
        }
        out.push(insn);
    }
    Ok(out)
}

fn alloc_fd(file: Arc<dyn File + Send + Sync>) -> isize {
    let (files, limit) = current_files_and_nofile_limit();
    files
        .lock()
        .install_fd(file, 0, limit)
        .map(|fd| fd as isize)
        .unwrap_or(EMFILE)
}

fn write_verifier_log(attr: &BpfProgLoadAttr, msg: &str) {
    if attr.log_buf == 0 || attr.log_size == 0 {
        return;
    }
    let token = get_current_token();
    let max_payload = attr.log_size.saturating_sub(1) as usize;
    let bytes = msg.as_bytes();
    let copy_len = bytes.len().min(max_payload);
    let _ = try_copy_to_user(token, attr.log_buf as *mut u8, &bytes[..copy_len]);
    let _ = try_copy_to_user(token, (attr.log_buf as usize + copy_len) as *mut u8, &[0]);
}

pub fn get_prog_clone(fd: usize) -> Option<Arc<BpfProgFile>> {
    let file = current_files().lock().get_file(fd)?;
    let prog = file.as_any().downcast_ref::<BpfProgFile>()?;
    Some(Arc::new(prog.clone()))
}

pub fn syscall_bpf(cmd: usize, attr: usize, size: usize) -> isize {
    match cmd {
        BPF_MAP_CREATE => syscall_bpf_map_create(attr, size),
        BPF_MAP_LOOKUP_ELEM => syscall_bpf_map_lookup_elem(attr, size),
        BPF_MAP_UPDATE_ELEM => syscall_bpf_map_update_elem(attr, size),
        BPF_PROG_LOAD => syscall_bpf_prog_load(attr, size),
        _ => ENOSYS,
    }
}

fn syscall_bpf_map_create(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapCreateAttr>() {
        return EINVAL;
    }
    let Ok(attr) = copy_user_struct::<BpfMapCreateAttr>(attr) else {
        return EFAULT;
    };
    let kind = match attr.map_type {
        BPF_MAP_TYPE_HASH => BpfMapKind::Hash,
        BPF_MAP_TYPE_ARRAY => BpfMapKind::Array,
        BPF_MAP_TYPE_RINGBUF => BpfMapKind::RingBuf,
        _ => return ENOSYS,
    };
    let Ok(file) = BpfMapFile::new(kind, attr.key_size, attr.value_size, attr.max_entries) else {
        return EINVAL;
    };
    alloc_fd(Arc::new(file))
}

fn syscall_bpf_map_lookup_elem(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapElemAttr>() {
        return EINVAL;
    }
    let Ok(attr) = copy_user_struct::<BpfMapElemAttr>(attr) else {
        return EFAULT;
    };
    let Some(file) = current_files().lock().get_file(attr.map_fd as usize) else {
        return EBADF;
    };
    let Some(map) = file.as_any().downcast_ref::<BpfMapFile>() else {
        return EBADF;
    };
    let token = get_current_token();
    let mut key = vec![0u8; map.key_size as usize];
    if try_copy_from_user(token, attr.key as *const u8, key.as_mut_slice()).is_err() {
        return EFAULT;
    }
    let Some(value) = map.lookup(key.as_slice()) else {
        return ENOENT;
    };
    if try_copy_to_user(token, attr.value as *mut u8, value.as_slice()).is_err() {
        return EFAULT;
    }
    0
}

fn syscall_bpf_map_update_elem(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapElemAttr>() {
        return EINVAL;
    }
    let Ok(attr) = copy_user_struct::<BpfMapElemAttr>(attr) else {
        return EFAULT;
    };
    let Some(file) = current_files().lock().get_file(attr.map_fd as usize) else {
        return EBADF;
    };
    let Some(map) = file.as_any().downcast_ref::<BpfMapFile>() else {
        return EBADF;
    };
    let token = get_current_token();
    let mut key = vec![0u8; map.key_size as usize];
    let mut value = vec![0u8; map.value_size as usize];
    if try_copy_from_user(token, attr.key as *const u8, key.as_mut_slice()).is_err() {
        return EFAULT;
    }
    if try_copy_from_user(token, attr.value as *const u8, value.as_mut_slice()).is_err() {
        return EFAULT;
    }
    match map.update(key.as_slice(), value.as_slice(), attr.flags) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn syscall_bpf_prog_load(attr_ptr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfProgLoadAttr>() {
        return EINVAL;
    }
    let Ok(attr) = copy_user_struct::<BpfProgLoadAttr>(attr_ptr) else {
        return EFAULT;
    };
    if attr.prog_type != BPF_PROG_TYPE_SOCKET_FILTER || attr.insn_cnt == 0 {
        write_verifier_log(&attr, "unsupported program type\n");
        return EINVAL;
    }
    if attr.insn_cnt > BPF_MAXINSNS {
        write_verifier_log(&attr, "program too large\n");
        return E2BIG;
    }
    let Ok(insns) = copy_user_insns(attr.insns as usize, attr.insn_cnt as usize) else {
        return EFAULT;
    };
    match verify_program(insns.as_slice()) {
        Ok(()) => {
            let maps = match collect_prog_map_refs(insns.as_slice()) {
                Ok(maps) => maps,
                Err(e) => return e,
            };
            alloc_fd(Arc::new(BpfProgFile::new(insns, maps)))
        }
        Err(msg) => {
            write_verifier_log(&attr, msg);
            EACCES
        }
    }
}
