use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::any::Any;
use spin::Mutex;

use crate::{
    fs::File,
    mm::{UserBuffer, try_copy_from_user, try_copy_to_user},
    syscall::error::{
        SyscallError,
        SyscallError::{
            E2BIG, EACCES, EBADF, EEXIST, EFAULT, EINVAL, EMFILE, ENOENT, ENOMEM, ENOSYS,
        },
        err,
    },
    task::processor::{current_files, current_files_and_nofile_limit},
    trap::get_current_token,
};

type BpfResult<T> = Result<T, SyscallError>;

// ── bpf() 系统调用命令号 ────────────────────────────────────────────────────
const BPF_MAP_CREATE: usize = 0; // 创建 BPF map
const BPF_MAP_LOOKUP_ELEM: usize = 1; // 查找 map 元素
const BPF_MAP_UPDATE_ELEM: usize = 2; // 更新 map 元素
const BPF_PROG_LOAD: usize = 5; // 加载 BPF 程序

// ── BPF map 类型 ────────────────────────────────────────────────────────────
const BPF_MAP_TYPE_HASH: u32 = 1; // 哈希表
const BPF_MAP_TYPE_ARRAY: u32 = 2; // 定长数组
const BPF_MAP_TYPE_RINGBUF: u32 = 27; // 环形缓冲区（仅占位，暂不支持读写）

// ── BPF 程序类型 ────────────────────────────────────────────────────────────
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1; // socket 过滤器

// ── map 更新标志 ────────────────────────────────────────────────────────────
const BPF_ANY: u64 = 0; // 无论是否存在均写入
const BPF_NOEXIST: u64 = 1; // 仅在不存在时创建
const BPF_EXIST: u64 = 2; // 仅在已存在时更新

// ── 特殊 BPF 伪源寄存器 / 辅助函数编号 ─────────────────────────────────────
const BPF_PSEUDO_MAP_FD: u8 = 1; // ldimm64 伪源：立即数为 map fd
const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1; // BPF 辅助函数：map_lookup_elem

// ── BPF 指令编码：指令类别（code 低 3 位）──────────────────────────────────
const BPF_CLASS_MASK: u8 = 0x07;
const BPF_LD: u8 = 0x00; // 立即数加载（双字）
const BPF_LDX: u8 = 0x01; // 从内存/包加载到寄存器
const BPF_ST: u8 = 0x02; // 立即数存储到内存
const BPF_STX: u8 = 0x03; // 寄存器值存储到内存
const BPF_ALU: u8 = 0x04; // 32 位算术/逻辑运算
const BPF_JMP: u8 = 0x05; // 跳转 / CALL / EXIT
const BPF_ALU64: u8 = 0x07; // 64 位算术/逻辑运算

// ── 操作数宽度（code 第 3-4 位）────────────────────────────────────────────
const BPF_SIZE_MASK: u8 = 0x18;
const BPF_W: u8 = 0x00; // 32 位（word）
const BPF_H: u8 = 0x08; // 16 位（half word）
const BPF_B: u8 = 0x10; // 8  位（byte）
const BPF_DW: u8 = 0x18; // 64 位（double word）

// ── 寻址模式（code 高 3 位，仅 LD/ST 类）──────────────────────────────────
const BPF_MODE_MASK: u8 = 0xe0;
const BPF_IMM: u8 = 0x00; // 立即数模式（ldimm64）
const BPF_MEM: u8 = 0x60; // 内存寻址模式

// ── ALU/JMP 源操作数选择（code 第 3 位）────────────────────────────────────
const BPF_SRC_MASK: u8 = 0x08;
const BPF_X: u8 = 0x08; // 源为寄存器（否则为立即数）

// ── ALU/JMP 操作码（code 高 4 位）──────────────────────────────────────────
const BPF_OP_MASK: u8 = 0xf0;
const BPF_ADD: u8 = 0x00; // 加法
const BPF_SUB: u8 = 0x10; // 减法
const BPF_DIV: u8 = 0x30; // 无符号除法（32 位）
const BPF_JEQ: u8 = 0x10; // 条件跳转：相等
const BPF_JNE: u8 = 0x50; // 条件跳转：不相等
const BPF_LSH: u8 = 0x60; // 左移
const BPF_RSH: u8 = 0x70; // 逻辑右移
const BPF_MOD: u8 = 0x90; // 取模（32 位）
const BPF_MOV: u8 = 0xb0; // 移动（赋值）
const BPF_CALL: u8 = 0x80; // 调用 BPF 辅助函数
const BPF_EXIT: u8 = 0x90; // 程序退出，r0 为返回值

// ── 寄存器编号与虚拟机常量 ──────────────────────────────────────────────────
const BPF_REG_0: usize = 0; // 返回值寄存器
const BPF_REG_1: usize = 1; // 第一个参数（packet 指针）
const BPF_REG_2: usize = 2; // 第二个参数（packet 长度 / key 指针）
const BPF_REG_10: usize = 10; // 帧指针（只读，指向栈顶）
const MAX_BPF_REG: usize = 11; // 寄存器总数（r0–r10）
const BPF_STACK_SIZE: usize = 512; // BPF 程序栈大小（字节）
const BPF_MAXINSNS: u32 = 4096; // 单个程序最大指令数

/// bpf(BPF_MAP_CREATE, attr, size) 的用户空间属性结构体，与 Linux ABI 对齐。
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

/// bpf(BPF_MAP_LOOKUP_ELEM / BPF_MAP_UPDATE_ELEM, attr, size) 的属性结构体。
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfMapElemAttr {
    map_fd: u32,
    pad0: u32,  // 对齐填充
    key: u64,   // 指向用户空间 key 的指针
    value: u64, // 指向用户空间 value 的指针
    flags: u64, // BPF_ANY / BPF_NOEXIST / BPF_EXIST
}

/// bpf(BPF_PROG_LOAD, attr, size) 的属性结构体。
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32, // 指令条数
    insns: u64,    // 指向用户空间指令数组的指针
    license: u64,  // 指向 license 字符串的指针
    log_level: u32,
    log_size: u32, // 验证器日志缓冲区大小
    log_buf: u64,  // 指向用户空间日志缓冲区的指针
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// 单条 BPF 指令，与内核 `struct bpf_insn` 内存布局完全一致（8 字节）。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BpfInsn {
    code: u8, // 指令编码（class | size/mode | op）
    regs: u8, // 低 4 位 = dst_reg，高 4 位 = src_reg
    off: i16, // 内存偏移或跳转偏移（以指令为单位）
    imm: i32, // 立即数
}

impl BpfInsn {
    /// 获取目标寄存器编号（regs 低 4 位）。
    fn dst_reg(self) -> usize {
        (self.regs & 0x0f) as usize
    }

    /// 获取源寄存器编号（regs 高 4 位）。
    fn src_reg(self) -> usize {
        (self.regs >> 4) as usize
    }
}

/// BPF map 的内部类型，决定键值存储语义。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BpfMapKind {
    Hash,    // 任意键哈希表，键值均为定长字节数组
    Array,   // 以 u32 下标为键的定长数组，创建时预填充零值
    RingBuf, // 环形缓冲区（当前仅允许创建，不支持元素读写）
}

/// BPF map 的可变内部状态，由 Mutex 保护以支持并发访问。
struct BpfMapInner {
    entries: BTreeMap<Vec<u8>, Vec<u8>>, // key → value 字节数组映射
}

/// BPF map 文件对象，实现 `File` trait 以复用内核文件描述符机制。
pub struct BpfMapFile {
    kind: BpfMapKind,
    pub key_size: u32,
    pub value_size: u32,
    max_entries: u32,
    inner: Mutex<BpfMapInner>,
}

impl BpfMapFile {
    /// 创建新的 BPF map。Array 类型会预填充 `max_entries` 个零值条目。
    fn new(kind: BpfMapKind, key_size: u32, value_size: u32, max_entries: u32) -> BpfResult<Self> {
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
                // RingBuf 不使用键值，key_size/value_size 必须为 0
                if key_size != 0 || value_size != 0 {
                    return Err(EINVAL);
                }
            }
        }
        let mut entries = BTreeMap::new();
        if kind == BpfMapKind::Array {
            // Array：以 little-endian u32 下标为 key，预填充零值
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

    /// 检查 key 长度是否与 map 声明的 key_size 一致。
    fn validate_key(&self, key: &[u8]) -> bool {
        key.len() == self.key_size as usize
    }

    /// 将 key 字节解析为 Array 下标（little-endian u32）。
    fn key_to_index(&self, key: &[u8]) -> Option<u32> {
        if !self.validate_key(key) {
            return None;
        }
        let mut raw = [0u8; 4];
        let n = key.len().min(raw.len());
        raw[..n].copy_from_slice(&key[..n]);
        Some(u32::from_le_bytes(raw))
    }

    /// 查找 key 对应的 value，返回其克隆；不存在或越界返回 None。
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        if !self.validate_key(key) {
            return None;
        }
        if self.kind == BpfMapKind::Array && self.key_to_index(key)? >= self.max_entries {
            return None;
        }
        self.inner.lock().entries.get(key).cloned()
    }

    /// 按 `flags` 语义（ANY/NOEXIST/EXIST）更新或插入条目。
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> BpfResult<()> {
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

    /// 向已有条目的 value 中写入原始字节（BPF 程序内部使用）。
    fn store_bytes(&self, key: &[u8], offset: usize, data: &[u8]) -> BpfResult<()> {
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

// BpfMapFile 不支持普通文件读写；通过专用 bpf() 系统调用操作。
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

/// BPF 程序文件对象，持有已验证的指令序列及其引用的所有 map。
#[derive(Clone)]
pub struct BpfProgFile {
    insns: Vec<BpfInsn>,
    /// 程序中 ldimm64 伪指令引用的 map fd → File 映射
    maps: BTreeMap<u32, Arc<dyn File + Send + Sync>>,
}

impl BpfProgFile {
    fn new(insns: Vec<BpfInsn>, maps: BTreeMap<u32, Arc<dyn File + Send + Sync>>) -> Self {
        Self { insns, maps }
    }

    /// 对 `packet` 运行 socket filter 程序，返回应保留的字节数。
    /// 返回 None 表示丢包，Some(n) 表示保留前 n 字节。
    pub fn filter_len(&self, packet: &[u8]) -> Option<usize> {
        let len = self.execute(packet).ok()? as usize;
        (len != 0).then_some(len.min(packet.len()))
    }

    /// 通过 fd 找到对应的 BpfMapFile 并执行闭包，fd 无效或类型不匹配则返回 None。
    fn with_map<R>(&self, fd: u32, f: impl FnOnce(&BpfMapFile) -> R) -> Option<R> {
        let file = self.maps.get(&fd)?;
        let map = file.as_any().downcast_ref::<BpfMapFile>()?;
        Some(f(map))
    }

    /// 返回指定 map 的 key_size（字节数），用于从栈上读取 key。
    fn map_key_size(&self, fd: u32) -> BpfResult<usize> {
        self.with_map(fd, |map| map.key_size as usize).ok_or(EBADF)
    }

    /// 查找 map 中 key 对应的 value，返回克隆；不存在返回 None。
    fn map_lookup_bytes(&self, fd: u32, key: &[u8]) -> Option<Vec<u8>> {
        self.with_map(fd, |map| map.lookup(key)).flatten()
    }

    /// 从 map value 中读取 [offset, offset+len) 范围的字节。
    fn map_load_bytes(&self, fd: u32, key: &[u8], offset: usize, len: usize) -> BpfResult<Vec<u8>> {
        let value = self.map_lookup_bytes(fd, key).ok_or(ENOENT)?;
        let end = offset.checked_add(len).ok_or(EINVAL)?;
        if end > value.len() {
            return Err(EACCES);
        }
        Ok(value[offset..end].to_vec())
    }

    /// 向 map value 的 [offset, offset+data.len()) 范围写入字节。
    fn map_store_bytes(&self, fd: u32, key: &[u8], offset: usize, data: &[u8]) -> BpfResult<()> {
        self.with_map(fd, |map| map.store_bytes(key, offset, data))
            .ok_or(EBADF)?
    }

    /// 执行 BPF 字节码，以 r0 的值作为返回值。
    ///
    /// 初始状态：r1 = PacketPtr(0)，r2 = 包长度，r10 = FramePtr。
    fn execute(&self, packet: &[u8]) -> BpfResult<u64> {
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

/// 静态验证器中寄存器的抽象类型，用于追踪指针语义。
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegKind {
    Scalar,
    MapFd,
    FramePtr,
    StackPtr,
    MapValuePtr,
    PacketPtr,
}

/// 对 BPF 指令序列做静态安全验证（线性扫描，不支持回跳）。
///
/// 检查内容：
/// - 程序必须以 EXIT 结尾
/// - 所有内存访问必须通过合法指针
/// - ALU 运算的源操作数必须是标量
/// - CALL 只允许 map_lookup_elem，且参数类型必须匹配
/// - 条件跳转只能向前跳，且目标在范围内
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

/// 验证寄存器编号合法（0 ≤ reg < MAX_BPF_REG）。
fn checked_reg(reg: usize) -> Result<usize, &'static str> {
    if reg < MAX_BPF_REG {
        Ok(reg)
    } else {
        Err("invalid register")
    }
}

/// 计算条件跳转的目标 pc（pc + 1 + off），并检查是否在指令范围内。
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

/// 扫描指令序列，收集所有 BPF_PSEUDO_MAP_FD ldimm64 引用的 map fd，
/// 返回 fd → Arc<File> 映射（用于程序运行时快速访问 map）。
fn collect_prog_map_refs(
    insns: &[BpfInsn],
) -> BpfResult<BTreeMap<u32, Arc<dyn File + Send + Sync>>> {
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

/// 从用户空间地址 `user_ptr` 拷贝一个 `T` 类型的结构体。
fn copy_user_struct<T: Copy + Default>(user_ptr: usize) -> BpfResult<T> {
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

/// 从用户空间地址 `user_ptr` 拷贝 `count` 条 BpfInsn 指令。
fn copy_user_insns(user_ptr: usize, count: usize) -> BpfResult<Vec<BpfInsn>> {
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

/// 将文件对象安装到当前进程的文件描述符表，返回分配的 fd 或 EMFILE。
fn alloc_fd(file: Arc<dyn File + Send + Sync>) -> isize {
    let (files, limit) = current_files_and_nofile_limit();
    files
        .lock()
        .install_fd(file, 0, limit)
        .map(|fd| fd as isize)
        .unwrap_or_else(|| err(EMFILE))
}

/// 将验证器错误信息写入用户空间日志缓冲区（若 attr 中指定了 log_buf）。
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

/// 通过文件描述符 `fd` 获取 BPF 程序的克隆（供 socket 过滤器使用）。
pub fn get_prog_clone(fd: usize) -> Option<Arc<BpfProgFile>> {
    let file = current_files().lock().get_file(fd)?;
    let prog = file.as_any().downcast_ref::<BpfProgFile>()?;
    Some(Arc::new(prog.clone()))
}

/// `bpf()` 系统调用入口，根据 `cmd` 分发到各子命令处理函数。
pub fn syscall_bpf(cmd: usize, attr: usize, size: usize) -> isize {
    match cmd {
        BPF_MAP_CREATE => syscall_bpf_map_create(attr, size),
        BPF_MAP_LOOKUP_ELEM => syscall_bpf_map_lookup_elem(attr, size),
        BPF_MAP_UPDATE_ELEM => syscall_bpf_map_update_elem(attr, size),
        BPF_PROG_LOAD => syscall_bpf_prog_load(attr, size),
        _ => err(ENOSYS),
    }
}

/// 处理 BPF_MAP_CREATE：根据 attr 创建 map 并返回新分配的 fd。
fn syscall_bpf_map_create(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapCreateAttr>() {
        return err(EINVAL);
    }
    let attr = match copy_user_struct::<BpfMapCreateAttr>(attr) {
        Ok(attr) => attr,
        Err(e) => return err(e),
    };
    let kind = match attr.map_type {
        BPF_MAP_TYPE_HASH => BpfMapKind::Hash,
        BPF_MAP_TYPE_ARRAY => BpfMapKind::Array,
        BPF_MAP_TYPE_RINGBUF => BpfMapKind::RingBuf,
        _ => return err(ENOSYS),
    };
    let file = match BpfMapFile::new(kind, attr.key_size, attr.value_size, attr.max_entries) {
        Ok(file) => file,
        Err(e) => return err(e),
    };
    alloc_fd(Arc::new(file))
}

/// 处理 BPF_MAP_LOOKUP_ELEM：从用户空间读取 key，查找 map 后将 value 写回用户空间。
fn syscall_bpf_map_lookup_elem(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapElemAttr>() {
        return err(EINVAL);
    }
    let attr = match copy_user_struct::<BpfMapElemAttr>(attr) {
        Ok(attr) => attr,
        Err(e) => return err(e),
    };
    let Some(file) = current_files().lock().get_file(attr.map_fd as usize) else {
        return err(EBADF);
    };
    let Some(map) = file.as_any().downcast_ref::<BpfMapFile>() else {
        return err(EBADF);
    };
    let token = get_current_token();
    let mut key = vec![0u8; map.key_size as usize];
    if try_copy_from_user(token, attr.key as *const u8, key.as_mut_slice()).is_err() {
        return err(EFAULT);
    }
    let Some(value) = map.lookup(key.as_slice()) else {
        return err(ENOENT);
    };
    if try_copy_to_user(token, attr.value as *mut u8, value.as_slice()).is_err() {
        return err(EFAULT);
    }
    0
}

/// 处理 BPF_MAP_UPDATE_ELEM：从用户空间读取 key/value 并按 flags 更新 map。
fn syscall_bpf_map_update_elem(attr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfMapElemAttr>() {
        return err(EINVAL);
    }
    let attr = match copy_user_struct::<BpfMapElemAttr>(attr) {
        Ok(attr) => attr,
        Err(e) => return err(e),
    };
    let Some(file) = current_files().lock().get_file(attr.map_fd as usize) else {
        return err(EBADF);
    };
    let Some(map) = file.as_any().downcast_ref::<BpfMapFile>() else {
        return err(EBADF);
    };
    let token = get_current_token();
    let mut key = vec![0u8; map.key_size as usize];
    let mut value = vec![0u8; map.value_size as usize];
    if try_copy_from_user(token, attr.key as *const u8, key.as_mut_slice()).is_err() {
        return err(EFAULT);
    }
    if try_copy_from_user(token, attr.value as *const u8, value.as_mut_slice()).is_err() {
        return err(EFAULT);
    }
    match map.update(key.as_slice(), value.as_slice(), attr.flags) {
        Ok(()) => 0,
        Err(e) => err(e),
    }
}

/// 处理 BPF_PROG_LOAD：拷贝指令、静态验证、收集 map 引用，成功则返回新 fd。
fn syscall_bpf_prog_load(attr_ptr: usize, size: usize) -> isize {
    if size < core::mem::size_of::<BpfProgLoadAttr>() {
        return err(EINVAL);
    }
    let attr = match copy_user_struct::<BpfProgLoadAttr>(attr_ptr) {
        Ok(attr) => attr,
        Err(e) => return err(e),
    };
    if attr.prog_type != BPF_PROG_TYPE_SOCKET_FILTER || attr.insn_cnt == 0 {
        write_verifier_log(&attr, "unsupported program type\n");
        return err(EINVAL);
    }
    if attr.insn_cnt > BPF_MAXINSNS {
        write_verifier_log(&attr, "program too large\n");
        return err(E2BIG);
    }
    let insns = match copy_user_insns(attr.insns as usize, attr.insn_cnt as usize) {
        Ok(insns) => insns,
        Err(e) => return err(e),
    };
    match verify_program(insns.as_slice()) {
        Ok(()) => {
            let maps = match collect_prog_map_refs(insns.as_slice()) {
                Ok(maps) => maps,
                Err(e) => return err(e),
            };
            alloc_fd(Arc::new(BpfProgFile::new(insns, maps)))
        }
        Err(msg) => {
            write_verifier_log(&attr, msg);
            err(EACCES)
        }
    }
}
