use super::uapi::{
    BPF_ADD, BPF_ALU, BPF_ALU64, BPF_CALL, BPF_CLASS_MASK, BPF_DW, BPF_EXIT,
    BPF_FUNC_MAP_LOOKUP_ELEM, BPF_IMM, BPF_JEQ, BPF_JMP, BPF_JNE, BPF_LD, BPF_LDX, BPF_MEM,
    BPF_MODE_MASK, BPF_MOV, BPF_OP_MASK, BPF_PSEUDO_MAP_FD, BPF_REG_0, BPF_REG_1, BPF_REG_2,
    BPF_REG_10, BPF_SIZE_MASK, BPF_SRC_MASK, BPF_ST, BPF_STX, BPF_SUB, BPF_X, BpfInsn, MAX_BPF_REG,
};

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
pub(super) fn verify_program(insns: &[BpfInsn]) -> Result<(), &'static str> {
    // 程序必须以 EXIT 结尾，防止执行流跑出指令数组末尾
    if !insns.last().is_some_and(|insn| {
        (insn.code & BPF_CLASS_MASK) == BPF_JMP && (insn.code & BPF_OP_MASK) == BPF_EXIT
    }) {
        return Err("program must end with exit");
    }

    // 初始化寄存器类型状态：
    //   r1 = PacketPtr（调用约定：入口时 r1 指向网络包数据）
    //   r10 = FramePtr（栈帧指针，只读）
    //   其余寄存器初始为 Scalar（未知标量，不可用作指针）
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
            // ── BPF_LD | BPF_IMM | BPF_DW：64 位立即数加载（lddw，占两条指令）──────
            //   正常示例（r1 = 0x1122334455667788）：
            //     [pc]:   code=0x18 dst=1 src=0 off=0 imm=0x55667788  ← 低32位
            //     [pc+1]: code=0x00 dst=0 src=0 off=0 imm=0x11223344  ← 高32位
            //   map fd 示例（r1 = map_fd=3）：
            //     [pc]:   code=0x18 dst=1 src=1(PSEUDO_MAP_FD) off=0 imm=3
            //     [pc+1]: code=0x00 dst=0 src=0               off=0 imm=0
            BPF_LD
                if (insn.code & BPF_MODE_MASK) == BPF_IMM
                    && (insn.code & BPF_SIZE_MASK) == BPF_DW =>
            {
                // 必须还有下一条"续集"指令
                // 违例示例：lddw 出现在程序最后一条，后面没有续集
                //   [pc]: code=0x18 dst=1 src=0 off=0 imm=42   ← 后面没有 [pc+1]
                if pc + 1 >= insns.len() {
                    return Err("truncated ldimm64");
                }
                let next = insns[pc + 1];
                // 续集指令的 code/dst/src/off 必须全为 0，只有 imm 携带高 32 位
                // 违例示例：续集的 code 不为 0
                //   [pc+1]: code=0x07 dst=0 src=0 off=0 imm=0x11223344
                if next.code != 0 || next.dst_reg() != 0 || next.src_reg() != 0 || next.off != 0 {
                    return Err("invalid ldimm64 pair");
                }
                // off 字段在 lddw 中保留，必须为 0
                // 违例示例：
                //   [pc]: code=0x18 dst=1 src=0 off=4 imm=42   ← off 不为 0
                if insn.off != 0 {
                    return Err("ldimm64 uses reserved fields");
                }
                // src_reg 只允许 0（普通立即数）或 1（BPF_PSEUDO_MAP_FD）
                // 违例示例：src_reg=2（未定义的伪源）
                //   [pc]: code=0x18 dst=1 src=2 off=0 imm=42
                if !matches!(insn.src_reg() as u8, 0 | BPF_PSEUDO_MAP_FD) {
                    return Err("unsupported ldimm64 pseudo source");
                }
                // BPF_PSEUDO_MAP_FD：dst 寄存器持有 map fd，标记为 MapFd 类型
                regs[dst] = if insn.src_reg() as u8 == BPF_PSEUDO_MAP_FD {
                    RegKind::MapFd
                } else {
                    RegKind::Scalar
                };
                pc += 2; // 跳过续集指令
                continue;
            }

            // ── BPF_LDX | BPF_MEM：从内存加载到寄存器 ──────────────────────────────
            BPF_LDX if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                // src 必须是合法指针才能解引用
                if !matches!(
                    regs[src],
                    RegKind::FramePtr
                        | RegKind::StackPtr
                        | RegKind::MapValuePtr
                        | RegKind::PacketPtr
                ) {
                    return Err("memory load requires valid pointer");
                }
                // 加载结果是内存中的原始数据，类型标记为标量
                regs[dst] = RegKind::Scalar;
            }

            // ── BPF_ST | BPF_MEM：立即数存储到内存 ─────────────────────────────────
            BPF_ST if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                // dst 必须是可写指针（不允许写 PacketPtr，只读网络包）
                if !matches!(
                    regs[dst],
                    RegKind::FramePtr | RegKind::StackPtr | RegKind::MapValuePtr
                ) {
                    return Err("memory store requires valid pointer");
                }
            }

            // ── BPF_STX | BPF_MEM：寄存器值存储到内存 ──────────────────────────────
            BPF_STX if (insn.code & BPF_MODE_MASK) == BPF_MEM => {
                // dst 必须是可写指针
                if !matches!(
                    regs[dst],
                    RegKind::FramePtr | RegKind::StackPtr | RegKind::MapValuePtr
                ) {
                    return Err("memory store requires valid pointer");
                }
                // 存储的值（src）必须是标量，禁止把指针写入内存（防止指针泄漏）
                if !matches!(regs[src], RegKind::Scalar) {
                    return Err("memory store value must be scalar");
                }
            }

            // ── BPF_ALU / BPF_ALU64：算术逻辑运算 ───────────────────────────────────
            BPF_ALU | BPF_ALU64 => {
                let op = insn.code & BPF_OP_MASK;
                let src_is_reg = (insn.code & BPF_SRC_MASK) == BPF_X;
                if op == BPF_MOV {
                    // MOV 直接传播源的类型：寄存器 MOV 复制类型，立即数 MOV 产生标量
                    regs[dst] = if src_is_reg {
                        regs[src]
                    } else {
                        RegKind::Scalar
                    };
                } else {
                    // 非 MOV 运算：源寄存器必须是标量（禁止用指针做算术）
                    if src_is_reg && !matches!(regs[src], RegKind::Scalar) {
                        return Err("alu source must be scalar");
                    }
                    match regs[dst] {
                        // MapFd 不允许任何算术，fd 只能用于 lddw/call
                        RegKind::MapFd => {
                            return Err("map fd arithmetic rejected");
                        }
                        // MapValuePtr 不允许偏移运算，防止越界访问 map value
                        RegKind::MapValuePtr => {
                            return Err("pointer arithmetic on map value rejected");
                        }
                        // 栈/帧/包指针只允许 ADD/SUB 做偏移，结果退化为 StackPtr
                        RegKind::FramePtr | RegKind::StackPtr | RegKind::PacketPtr => {
                            if !matches!(op, BPF_ADD | BPF_SUB) {
                                return Err("unsupported pointer operation");
                            }
                            // PacketPtr 偏移后仍是 PacketPtr；其他指针偏移后变为 StackPtr
                            if regs[dst] != RegKind::PacketPtr {
                                regs[dst] = RegKind::StackPtr;
                            }
                        }
                        // 标量运算结果还是标量
                        _ => regs[dst] = RegKind::Scalar,
                    }
                }
            }

            // ── BPF_JMP：跳转 / CALL / EXIT ─────────────────────────────────────────
            BPF_JMP => {
                let op = insn.code & BPF_OP_MASK;
                if op == BPF_CALL {
                    // 目前只支持 helper #1：map_lookup_elem
                    if insn.imm != BPF_FUNC_MAP_LOOKUP_ELEM {
                        return Err("unsupported bpf helper");
                    }
                    // 调用约定：r1 = map fd，r2 = 指向栈上 key 的指针
                    if !matches!(regs[BPF_REG_1], RegKind::MapFd) {
                        return Err("map_lookup_elem needs map fd in r1");
                    }
                    if !matches!(regs[BPF_REG_2], RegKind::FramePtr | RegKind::StackPtr) {
                        return Err("map_lookup_elem needs stack key pointer in r2");
                    }
                    // 调用后 r0 = 查找结果指针（可能为 NULL，运行时处理）
                    regs[BPF_REG_0] = RegKind::MapValuePtr;
                } else if op == BPF_EXIT {
                    // 中途 EXIT 合法（多个 return site），程序末尾的 EXIT 在函数开头已检查
                } else if matches!(op, BPF_JEQ | BPF_JNE) {
                    // 条件跳转：检查目标在范围内，且只允许向前跳（禁止循环）
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
