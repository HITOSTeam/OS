# Fix Per Day：RISC-V SMP、TLB shootdown 与 I-cache 一致性

本文记录 CongCore 对 RISC-V 多核支持的一次系统性修复。修复目标不只是让多个
hart 启动，而是建立从 CPU 发现、SBI 启动、地址空间切换，到跨 hart TLB 与
I-cache 一致性的完整闭环。

本批次在 QEMU `virt` 的 1、4、8 hart 配置上完成了启动与专项回归。它已经满足
当前连续物理 hart ID、静态 CPU 配置下的核心 SMP 需求，但仍不等同于 Linux 的
完整 RISC-V SMP 能力；逻辑 CPU 映射、hotplug、NUMA、Svinval 和真实硬件覆盖仍
是后续工作。

## 本日修复的问题

原实现存在三个会直接影响正确性或扩展性的缺口：

1. 启动路径按编译期数量假设 hart 存在，SBI 调用仍以 legacy 接口为主，无法
   稳健表达现代 HSM、IPI 和 RFENCE 语义；
2. 页表每次修改都可能退化成同步、过粗的远端 TLB 全失效，多个 PTE 修改会
   重复发送请求；
3. 可执行页内容更新只保证当前 hart 的 `fence.i`，同一地址空间在其他 hart
   运行时可能继续执行旧指令。

修复后的策略是：

- 从 FDT 发现实际 hart，只启动发现到的二级 hart；
- 优先使用 SBI v0.2+ BASE/IPI/RFENCE/HSM，并为 IPI/RFENCE 保留 SBI v0.1
  bitmap 兼容路径；
- 探测硬件 ASID 位宽并使用 generation 分配器；
- 单页做精确失效，小范围合并为一个 range，大范围才退休该 mm 的 ASID；
- 一个页表事务中的多个修改只提交一次同步 RFENCE；
- 对正在运行该 mm 的远端 hart 立即执行 `remote_fence_i`，对非 active hart
  延迟到下一次返回用户态执行本地 `fence.i`。

## Linux 参考模型

实现主要对照 Linux 的以下路径：

- [`arch/riscv/kernel/smpboot.c`](https://github.com/torvalds/linux/blob/master/arch/riscv/kernel/smpboot.c)
  从设备树或 ACPI 建立 CPU 与 hart 的关系，通过 `cpu_ops` 启动二级 CPU，并在
  call-in 后发布 online 状态；
- [`arch/riscv/kernel/cpu_ops_sbi.c`](https://github.com/torvalds/linux/blob/master/arch/riscv/kernel/cpu_ops_sbi.c)
  使用逻辑 CPU 对应的物理 hart ID 调用 SBI HSM `hart_start`；
- [`arch/riscv/kernel/sbi.c`](https://github.com/torvalds/linux/blob/master/arch/riscv/kernel/sbi.c)
  探测 SBI 扩展并封装 IPI、RFENCE 与 HSM；
- [`arch/riscv/mm/context.c`](https://github.com/torvalds/linux/blob/master/arch/riscv/mm/context.c)
  通过 SATP WARL 探测 ASID 位宽，使用 generation 管理 context，并在 ASID
  回绕后安排本地 TLB 清理；
- [`arch/riscv/mm/tlbflush.c`](https://github.com/torvalds/linux/blob/master/arch/riscv/mm/tlbflush.c)
  区分单地址、小范围和全 ASID 失效，默认以 64 个页为 range/full 的分界；
- [`arch/riscv/mm/cacheflush.c`](https://github.com/torvalds/linux/blob/master/arch/riscv/mm/cacheflush.c)
  为 mm 维护 I-cache stale 标记：active CPU 立即跨核同步，inactive CPU 在未来
  切换到该 mm 时延迟执行本地 `fence.i`。

CongCore 沿用了这些语义边界，但没有直接复制 Linux 的通用 CPU hotplug、
`on_each_cpu_mask()`、bitmap ASID allocator 等基础设施，而是按当前内核规模实现
了固定上限、物理 hart 位图版本。

## 启动与 SBI

### FDT 驱动的 hart 拓扑

启动核解析 FDT `/cpus`，生成 `HartTopology`：

```text
HartTopology
 ├─ present_mask   可由当前内核表示的物理 hart 位图
 ├─ discovered     FDT 中发现的 CPU 数量
 └─ ignored        超出 MAX_HARTS 或位图宽度的 CPU 数量
```

FDT 不可用或解析失败时只保留启动 hart。当前位图直接使用物理 hart ID，因此
允许上限内的稀疏 ID，但没有 Linux 的 `cpuid_to_hartid_map()`；超过
`MAX_HARTS` 或 `usize` 位宽的 hart 会被忽略而不会越界。

启动 hart 不再假设为 hart 0。QEMU 的部分验证运行实际从 hart 1 启动，内核仍能
正确生成 present mask、分配 per-hart 启动栈并启动其余 hart。

### HSM 启动与聚合等待

启动流程如下：

1. 启动 hart 清理 BSS，完成共享页表、内存、设备和调度器初始化；
2. 发布 present mask 与全局初始化屏障；
3. 对 FDT 中除自身外的 hart 逐个发起 HSM `hart_start`，不在每次调用后单独
   等待；
4. 所有启动请求发出后，用一个 5 秒窗口等待 aggregate online mask；
5. 二级 hart 安装共享内核页表，执行初始 `sfence.vma`/`fence.i`，初始化 trap
   和 timer，最后才发布 online bit 并进入调度器；
6. 超时时一次打印 present、started、online、missing 与 failed 位图。

这避免了“每个二级 hart 最多等待一次超时”造成的线性启动延迟，也防止未完成
本地 MMU/中断初始化的 hart 被调度器提前选中。

### SBI v0.2+ 与兼容路径

SBI 层实现标准 `SbiRet { error, value }` 返回约定，并在启动时通过 BASE
扩展探测 IPI、RFENCE 和 HSM。现代路径直接传递 `hart_mask + hart_mask_base`，
支持：

- `send_ipi_mask`；
- `remote_fence_i`；
- `remote_sfence_vma`；
- `remote_sfence_vma_asid`；
- `hart_start`。

SBI v0.1 的 IPI/RFENCE 需要传入物理 bitmap 指针。兼容实现使用一块静态 bitmap
并加锁串行化，避免两个 hart 同时发 legacy 请求时覆盖彼此。HSM 没有 v0.1
等价接口，因此旧固件只有在已经预启动二级 hart 时才能进入 SMP；由固件停放且
不提供 HSM 的 hart 无法由 S-mode 内核可靠唤醒。

## ASID 上下文

### 位宽探测与启用条件

启动核在 paging 生效后对 `satp.ASID` 做 write-ones/read-back WARL 探测，然后
恢复原 SATP 并执行本地 `sfence.vma`。与 Linux 一致，只有满足以下条件时才启用
ASID 分配：

```text
ASID 数量 > 2 * possible_harts
```

ASID 0 保留给内核。若硬件没有 ASID，或命名空间太小，则每次用户地址空间切换
都要求本地 TLB 清理，正确性优先于错误复用 ASID。

### generation 与 per-hart context

每个 mm 的状态为：

```text
AsidContext
 ├─ context                 当前 generation 中的新 context
 ├─ hart_contexts[hart]     每个 hart 实际装载过的 generation | ASID
 ├─ resident_harts          仍可能持有该 mm TLB 项的 hart
 ├─ active_harts            正在或即将返回用户态执行该 mm 的 hart
 ├─ invalidation_sequence   页表更新 seqlock
 └─ icache_stale_mask       尚未观察最新指令内容的 hart
```

全局分配器按 ASID 递增。回绕时 generation 加一，并把所有 possible hart 标为
`PENDING_LOCAL_FLUSH`；各 hart 在下一次返回用户态前消费自己的标志并执行本地
non-global TLB 清理。旧 generation 的 context 不会被误认为当前 context。

`resident_harts` 和 `active_harts` 有意分开：

- TLB shootdown 以 `resident_harts` 为目标，因为 hart 即使刚 trap 入内核，仍
  可能保留该用户 ASID 的陈旧翻译；
- I-cache 立即远端同步只针对 `active_harts`，其他 hart 保留 stale bit，在以后
  真正切回该 mm 时处理。

## 页表更新事务与返回用户态竞态

每个 `PageTableUpdateBatch` 对一个 mm 建立奇偶序号事务：

1. invalidator 把 `invalidation_sequence` 从偶数改为奇数；
2. 用户态返回路径看到奇数时等待，不会提交新的 active/resident 状态；
3. PTE 修改被记录到当前批次；
4. 提交前用 Rust 顺序一致 fence 与 RISC-V `fence rw,rw` 发布 PTE store；
5. 完成本地和同步远端失效；
6. 只有远端 RFENCE 返回后，调用路径才释放被撤销映射持有的物理页；
7. 序号恢复为偶数，允许用户态返回继续提交。

用户态返回路径先发布 `hart_contexts`、`resident_harts` 和 `active_harts`，再复查
序号。如果期间出现页表事务，它会撤销 active bit 并重试。这样 invalidator
要么看到该 hart 并同步失效，要么该 hart 在失效完成后才装载新 context，不存在
“刚好漏掉一个正在 sret 的 hart”的窗口。

## 精确 TLB 失效与批量合并

### 三级策略

一个批次把所有修改合并为页对齐包络区间，并按以下规则提交：

| 修改规模 | 本地操作 | 远端操作 | context 处理 |
| --- | --- | --- | --- |
| 1 页 | 一次 `sfence.vma va, asid` | 一次带 4 KiB range 的 SBI RFENCE | 保留 ASID |
| 2–64 页 | 对范围逐页精确 `sfence.vma` | 一次合并 range 的 SBI RFENCE | 保留 ASID |
| 超过 64 页或区间溢出 | `sfence.vma zero, asid` | 一次 full-ASID SBI RFENCE | 退休 mm context |

64 页阈值与 Linux 默认 `tlb_flush_all_threshold` 对齐。当前实现使用最小起点到
最大终点的单个包络，而不是保存多个离散 range；少量但相距很远的修改会主动
退化为 drop ASID，以固定元数据大小换取简单、可预测的提交成本。

### ASID 作用域与安全回退

若所有远端目标对该 mm 使用相同的数值 ASID，提交
`remote_sfence_vma_asid(mask, start, size, asid)`；如果目标处在不同 generation
或持有不同数值 ASID，则退化为地址作用域的 `remote_sfence_vma`，避免用一个
ASID 错漏其他 hart 的旧 context。

大范围路径先把 mm 的新 `context` 清零，再同步清理所有 resident hart 上的旧
context。resident footprint 不会在 RFENCE 后立即丢弃：远端 hart 可能在同步
完成后继续运行并从最新 PTE 回填；保留 footprint 能保证紧随其后的下一次修改
仍然覆盖它。

### 一个事务一次远端请求

`mprotect`、`munmap`、`madvise`、`mremap`、COW、lazy fault、fork 写保护和
文件映射更新等路径使用同一个页表批次。无论一个 syscall 修改多少个 PTE，批次
只在结束时发出一次带目标 mask 的 SBI RFENCE，而不是每修改一个 PTE 就同步
发送一次 IPI/RFENCE。

SBI RFENCE 是同步完成接口：返回时目标 hart 已完成请求。因此从 `munmap`、COW
替换或地址空间重建中移出的 `FrameTracker` 会一直保留到 batch commit 之后，
防止远端陈旧翻译访问已经重新分配给其他对象的物理页。

## 跨 hart I-cache 一致性

RISC-V 的普通数据写入不会自动保证其他 hart 的 instruction fetch 看到新指令。
因此把可写页变为可执行页、修改共享可执行映射或装载 ELF 后，仅做 TLB
shootdown 不够。

实现为每个 mm 维护 `icache_stale_mask`：

1. 发布新指令字节，执行 release fence 与 `fence rw,rw`；
2. 把所有 possible hart 标记为 stale；
3. 当前 hart 立即执行一次 `fence.i` 并清除自己的 stale bit；
4. 读取该 mm 的 active online 远端 hart，一次调用 `remote_fence_i(mask)`；
5. RFENCE 成功后清除这些 active hart 的 stale bit；
6. 未 active 的 hart 保留 stale bit，下次返回该 mm 用户态前执行本地
   `fence.i`。

用户态返回路径先设置 active bit，再消费 stale bit。并发代码更新因此只有两种
合法结果：更新方看到该 hart active 并完成远端 fence，或者返回路径看到仍然
stale 并本地 fence；不会出现先清 stale、后才加入 active mask 而被两边同时
漏掉的竞态。

I-cache 标记已接入以下可执行内容来源：

- ELF program segment 装载和地址空间复制；
- anonymous/file-backed executable mmap 的预填充与按 fault 填充；
- COW 和 lazy allocation 后获得执行权限的 PTE；
- `mprotect` 从不可执行变为可执行；
- 共享文件映射的写入、增长、truncate/restore；
- PTE 替换时新增 execute 权限的通用路径。

批次在 TLB commit 前完成 I-cache 标记，从而保证新的 executable PTE 不会先于
对应指令内容的 fence 对其他 hart 可见。

## 可观测性

打开 `DEBUG_PERF` 后，`/proc/perf` 提供：

- `tlb_page_batches`、`tlb_range_batches`、`tlb_asid_drops`；
- `tlb_batched_edits`、`tlb_merged_ranges`、`tlb_exact_pairs`；
- `tlb_remote_ipis`、`tlb_shootdown_wait_cycles`、`tlb_asid_wraps`；
- `icache_local_fences`、`icache_deferred_fences`；
- `icache_remote_fences`、`icache_remote_targets`。

这些计数器可以判断 workload 是否主要命中精确失效、一次 RFENCE 合并了多少
修改、远端同步等待是否成为热点，以及 I-cache 同步有多少落在延迟路径。

## 验证

### 构建检查

```sh
TMPDIR=$PWD/.tmp cargo check --manifest-path os/Cargo.toml \
  --target riscv64gc-unknown-none-elf

TMPDIR=$PWD/.tmp cargo check --manifest-path os/Cargo.toml \
  --target loongarch64-unknown-none-softfloat
```

两条检查均通过；LoongArch 使用本机已安装的 soft-float target。警告为仓库现有
warning，没有新增编译错误。

### QEMU 启动矩阵

同一 RISC-V release 内核在 QEMU/OpenSBI 环境下验证：

| `-smp` | FDT mask | online mask | 启动 hart | 结果 |
| ---: | ---: | ---: | ---: | --- |
| 1 | `0x1` | `0x1` | 0 | 通过 |
| 4 | `0xf` | `0xf` | 0 或 1 | 通过 |
| 8 | `0xff` | `0xff` | 1 | 通过 |

4/8 hart 启动日志中的 `failed=0x0`，二级 hart 均在完成本地 MMU、trap 和 timer
初始化后进入调度器。非零启动 hart 的运行覆盖了“不假设 hart 0 是 boot hart”
的路径。

### TLB shootdown 专项回归

`tlb_shootdown_smp_smoke` 创建共享同一 mm 的两个线程，分别固定在 CPU 0 和
CPU 1。父线程物化完整 4 MiB 映射并持续读取，子线程依次执行：

- 4 KiB `mprotect` R/RW：单页精确失效；
- 64 KiB `mprotect` R/RW：小范围合并失效；
- 4 MiB `mprotect` R/RW：超过 64 页后 drop ASID。

4 hart 与 8 hart 均通过全部 6 个步骤，并校验映射首尾内容未被错误释放或覆盖。

### I-cache 专项回归

`riscv_icache_smp_smoke` 动态读取 affinity mask，把父线程固定在 CPU 0，并在
其余每个 online CPU 创建一个共享 mm worker，最多覆盖 8 hart。测试反复执行：

```text
RX -> RW -> 写入新的 RISC-V 函数 -> RX -> 所有远端 hart 执行并确认返回值
```

结果：

- 1 hart：按预期跳过远端一致性测试；
- 4 hart：128 次更新 × 3 个远端 worker 通过；
- 8 hart：128 次更新 × 7 个远端 worker 通过。

该用例同时验证即时 `remote_fence_i` 与线程跨 hart 执行时的 mm active/stale
状态更新。

### 镜像构建备注

当前 `make run_ext4` 的系统镜像规则会向 `ext4-fs-packer` 传入 `--kind`，而工作树
中的 packer 源码尚不支持该参数。本次验证没有修改基础镜像，使用 QEMU
`-snapshot` 启动已有系统盘，并用当前 packer 支持的参数生成独立 user ext4。
这是已有构建集成问题，不是本次 SMP 代码回归。

## 完善程度与 Linux 差距

当前完成度可以概括为：**静态、FDT、SBI、1–8 hart QEMU 环境下的核心 SMP
一致性闭环已经完成；面向任意平台和生命周期的 Linux 级 SMP 尚未完成。**

| 能力 | 当前状态 | 与 Linux 的主要差距 |
| --- | --- | --- |
| CPU 发现与启动 | FDT + HSM，启动 hart 可非 0 | 无 ACPI、逻辑 CPU/物理 hart 映射、通用 cpu_ops |
| SBI | v0.2+ BASE/IPI/RFENCE/HSM；legacy IPI/RFENCE | 无 HSM 的旧固件只能依赖预启动 hart |
| 调度与 affinity | online mask、per-hart 调度、测试可绑核 | 无 CPU hotplug、offline/stop、失败恢复 |
| ASID | WARL 探测、generation、回绕本地 flush | 分配器比 Linux bitmap/reserved-context 模型简单 |
| 用户 TLB | 单页、≤64 页 range、大范围 drop ASID、同步批处理 | 无 Svinval、hugepage/NAPOT stride 感知、阈值调优 |
| 内核 TLB | online hart 同步全局失效 | 缺少更细的通用 kernel mapping shootdown 层次 |
| I-cache | active 远端 RFENCE + inactive 延迟 fence | 无按 ISA/平台 errata 的替代实现与复杂 text patch 框架 |
| 拓扑 | 固定上限物理位图 | 无 NUMA、capacity、SMT/cluster/cache topology |
| 验证 | QEMU 1/4/8 hart + TLB/I-cache smoke | 尚缺真实硬件、长时间压力、随机并发和 LTP 全量门禁 |

### 后续优先级

对当前性能影响最大的后续项依次是：

1. **离散 range 表达与阈值度量。** 当前单包络会把相距很远的少量修改变成
   drop ASID；保存少量离散 range 并依据实际页数/固件成本决策，可减少大工作集
   的 TLB 冷启动；
2. **Svinval/本地批量失效。** 支持该扩展的硬件可用 `sinval.vma` 与一次
   `sfence.w.inval`/`sfence.inval.ir` 包围整批，降低逐页 `sfence.vma` 成本；
3. **Linux 级 ASID allocator。** reserved context 与 bitmap 回收可在 ASID
   压力大、mm 数量多时减少 generation rollover 的全 hart 本地 flush；
4. **通用软件 IPI call-function fallback。** 在固件 RFENCE 性能差或不可用时，
   可由内核精确控制目标与批处理，并为其他跨 CPU 操作复用；
5. **hugepage/NAPOT 与拓扑感知。** 当前 4 KiB stride 和扁平 hart mask 对大页
   或大规模 NUMA 平台不是最优。

CPU hotplug、ACPI 与 NUMA 对平台覆盖很重要，但在当前固定 1–8 hart QEMU
workload 中，它们不是首要运行时性能瓶颈。
