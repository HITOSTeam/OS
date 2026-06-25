// ── bpf() 系统调用命令号 ────────────────────────────────────────────────────
pub(super) const BPF_MAP_CREATE: usize = 0; // 创建 BPF map
pub(super) const BPF_MAP_LOOKUP_ELEM: usize = 1; // 查找 map 元素
pub(super) const BPF_MAP_UPDATE_ELEM: usize = 2; // 更新 map 元素
pub(super) const BPF_PROG_LOAD: usize = 5; // 加载 BPF 程序

// ── BPF map 类型 ────────────────────────────────────────────────────────────
pub(super) const BPF_MAP_TYPE_HASH: u32 = 1; // 哈希表
pub(super) const BPF_MAP_TYPE_ARRAY: u32 = 2; // 定长数组
pub(super) const BPF_MAP_TYPE_RINGBUF: u32 = 27; // 环形缓冲区（仅占位，暂不支持读写）

// ── BPF 程序类型 ────────────────────────────────────────────────────────────
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_UNSPEC: u32 = 0; // 未指定
pub(super) const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1; // socket 过滤器（已实现）
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_KPROBE: u32 = 2; // 内核函数动态探针
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_SCHED_CLS: u32 = 3; // TC 流量分类器
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_SCHED_ACT: u32 = 4; // TC 流量动作
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_TRACEPOINT: u32 = 5; // 静态 tracepoint 探针
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_XDP: u32 = 6; // eXpress Data Path，驱动层包处理
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_PERF_EVENT: u32 = 7; // perf 性能事件采样
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8; // cgroup 入/出包过滤
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9; // cgroup socket 创建钩子
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_LWT_IN: u32 = 10; // 轻量隧道入方向
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_LWT_OUT: u32 = 11; // 轻量隧道出方向
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_LWT_XMIT: u32 = 12; // 轻量隧道发送
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_SOCK_OPS: u32 = 13; // socket 操作回调
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_SK_SKB: u32 = 14; // socket 间数据包转发
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15; // cgroup 设备访问控制
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_SK_MSG: u32 = 16; // socket 消息重定向
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17; // 原始 tracepoint（无稳定 ABI）
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18; // cgroup bind/connect 地址控制
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_LWT_SEG6LOCAL: u32 = 19; // SRv6 本地处理
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_LIRC_MODE2: u32 = 20; // 红外遥控器解码
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_SK_REUSEPORT: u32 = 21; // SO_REUSEPORT socket 选择
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_FLOW_DISSECTOR: u32 = 22; // 自定义流分类器
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_CGROUP_SYSCTL: u32 = 23; // cgroup sysctl 读写控制
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: u32 = 24; // 可写原始 tracepoint
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_CGROUP_SOCKOPT: u32 = 25; // cgroup setsockopt/getsockopt
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_TRACING: u32 = 26; // fentry/fexit/iter 追踪
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_STRUCT_OPS: u32 = 27; // 替换内核 struct 函数指针
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_EXT: u32 = 28; // 扩展/替换已有 BPF 程序
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_LSM: u32 = 29; // Linux 安全模块钩子
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_SK_LOOKUP: u32 = 30; // socket 查找重定向
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_SYSCALL: u32 = 31; // 可执行 syscall 的特权程序
#[allow(dead_code)]
pub(super) const BPF_PROG_TYPE_NETFILTER: u32 = 32; // Netfilter 钩子（iptables/nftables 替代）

// ── map 更新标志 ────────────────────────────────────────────────────────────
pub(super) const BPF_ANY: u64 = 0; // 无论是否存在均写入
pub(super) const BPF_NOEXIST: u64 = 1; // 仅在不存在时创建
pub(super) const BPF_EXIST: u64 = 2; // 仅在已存在时更新

// ── 特殊 BPF 伪源寄存器 / 辅助函数编号 ─────────────────────────────────────
pub(super) const BPF_PSEUDO_MAP_FD: u8 = 1; // ldimm64 伪源：立即数为 map fd
pub(super) const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1; // BPF 辅助函数：map_lookup_elem

// ── BPF 指令编码：指令类别（code 低 3 位）──────────────────────────────────
pub(super) const BPF_CLASS_MASK: u8 = 0x07;
pub(super) const BPF_LD: u8 = 0x00; // 立即数加载（双字）
pub(super) const BPF_LDX: u8 = 0x01; // 从内存/包加载到寄存器
pub(super) const BPF_ST: u8 = 0x02; // 立即数存储到内存
pub(super) const BPF_STX: u8 = 0x03; // 寄存器值存储到内存
pub(super) const BPF_ALU: u8 = 0x04; // 32 位算术/逻辑运算
pub(super) const BPF_JMP: u8 = 0x05; // 跳转 / CALL / EXIT
pub(super) const BPF_ALU64: u8 = 0x07; // 64 位算术/逻辑运算

// ── 操作数宽度（code 第 3-4 位）────────────────────────────────────────────
pub(super) const BPF_SIZE_MASK: u8 = 0x18;
pub(super) const BPF_W: u8 = 0x00; // 32 位（word）
pub(super) const BPF_H: u8 = 0x08; // 16 位（half word）
pub(super) const BPF_B: u8 = 0x10; // 8  位（byte）
pub(super) const BPF_DW: u8 = 0x18; // 64 位（double word）

// ── 寻址模式（code 高 3 位，仅 LD/ST 类）──────────────────────────────────
pub(super) const BPF_MODE_MASK: u8 = 0xe0;
pub(super) const BPF_IMM: u8 = 0x00; // 立即数模式（ldimm64）
pub(super) const BPF_MEM: u8 = 0x60; // 内存寻址模式

// ── ALU/JMP 源操作数选择（code 第 3 位）────────────────────────────────────
pub(super) const BPF_SRC_MASK: u8 = 0x08;
pub(super) const BPF_X: u8 = 0x08; // 源为寄存器（否则为立即数）

// ── ALU/JMP 操作码（code 高 4 位）──────────────────────────────────────────
pub(super) const BPF_OP_MASK: u8 = 0xf0;
pub(super) const BPF_ADD: u8 = 0x00; // 加法
pub(super) const BPF_SUB: u8 = 0x10; // 减法
pub(super) const BPF_DIV: u8 = 0x30; // 无符号除法（32 位）
pub(super) const BPF_JEQ: u8 = 0x10; // 条件跳转：相等
pub(super) const BPF_JNE: u8 = 0x50; // 条件跳转：不相等
pub(super) const BPF_LSH: u8 = 0x60; // 左移
pub(super) const BPF_RSH: u8 = 0x70; // 逻辑右移
pub(super) const BPF_MOD: u8 = 0x90; // 取模（32 位）
pub(super) const BPF_MOV: u8 = 0xb0; // 移动（赋值）
pub(super) const BPF_CALL: u8 = 0x80; // 调用 BPF 辅助函数
pub(super) const BPF_EXIT: u8 = 0x90; // 程序退出，r0 为返回值

// ── 寄存器编号与虚拟机常量 ──────────────────────────────────────────────────
pub(super) const BPF_REG_0: usize = 0; // 返回值寄存器
pub(super) const BPF_REG_1: usize = 1; // 第一个参数（packet 指针）
pub(super) const BPF_REG_2: usize = 2; // 第二个参数（packet 长度 / key 指针）
pub(super) const BPF_REG_10: usize = 10; // 帧指针（只读，指向栈顶）
pub(super) const MAX_BPF_REG: usize = 11; // 寄存器总数（r0–r10）
pub(super) const BPF_STACK_SIZE: usize = 512; // BPF 程序栈大小（字节）
pub(super) const BPF_MAXINSNS: u32 = 4096; // 单个程序最大指令数

/// bpf(BPF_MAP_CREATE, attr, size) 的用户空间属性结构体，与 Linux ABI 对齐。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct BpfMapCreateAttr {
    pub(super) map_type: u32,
    pub(super) key_size: u32,
    pub(super) value_size: u32,
    pub(super) max_entries: u32,
    pub(super) map_flags: u32,
    pub(super) inner_map_fd: u32,
    pub(super) numa_node: u32,
    pub(super) map_name: [u8; 16],
    pub(super) map_ifindex: u32,
    pub(super) btf_fd: u32,
    pub(super) btf_key_type_id: u32,
    pub(super) btf_value_type_id: u32,
}

/// bpf(BPF_MAP_LOOKUP_ELEM / BPF_MAP_UPDATE_ELEM, attr, size) 的属性结构体。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct BpfMapElemAttr {
    pub(super) map_fd: u32,
    pub(super) pad0: u32,  // 对齐填充
    pub(super) key: u64,   // 指向用户空间 key 的指针
    pub(super) value: u64, // 指向用户空间 value 的指针
    pub(super) flags: u64, // BPF_ANY / BPF_NOEXIST / BPF_EXIST
}

/// bpf(BPF_PROG_LOAD, attr, size) 的属性结构体。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct BpfProgLoadAttr {
    /// 程序类型，目前只支持 1 (SOCKET_FILTER)
    pub(super) prog_type: u32,
    /// 指令数组的条数
    pub(super) insn_cnt: u32,
    /// 用户空间指针，指向 BpfInsn[] 数组（程序本体）
    pub(super) insns: u64,
    /// 用户空间指针，指向 license 字符串（如 "GPL"）
    pub(super) license: u64,
    /// 日志详细程度（0=不要日志，1=有日志）
    pub(super) log_level: u32,
    /// log_buf 缓冲区的字节大小
    pub(super) log_size: u32,
    /// 用户空间指针，verifier 失败时把错误字符串写到这里
    pub(super) log_buf: u64,
    /// 内核版本（Linux 历史遗留字段，当前忽略）
    pub(super) kern_version: u32,
    /// 加载标志（当前未使用）
    pub(super) prog_flags: u32,
    /// 程序名，纯调试用途
    pub(super) prog_name: [u8; 16],
    /// 网卡索引，offload 到硬件时使用，通常为 0
    pub(super) prog_ifindex: u32,
    /// 期望的挂载点类型（当前未使用）
    pub(super) expected_attach_type: u32,
}

/// 单条 BPF 指令，与内核 `struct bpf_insn` 内存布局完全一致（8 字节）。
/// BpfInstruct
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BpfInsn {
    pub(super) code: u8, // 指令编码（class | size/mode | op）
    pub(super) regs: u8, // 低 4 位 = dst_reg，高 4 位 = src_reg
    pub(super) off: i16, // 内存偏移或跳转偏移（以指令为单位）
    pub(super) imm: i32, // 立即数
}

impl BpfInsn {
    /// 获取目标寄存器编号（regs 低 4 位）。
    pub(super) fn dst_reg(self) -> usize {
        (self.regs & 0x0f) as usize
    }

    /// 获取源寄存器编号（regs 高 4 位）。
    pub(super) fn src_reg(self) -> usize {
        (self.regs >> 4) as usize
    }
}
