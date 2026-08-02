# LoongArch SMP 与决赛短链路验证

## 范围

本批次以 Linux 用户可观察语义和 LoongArch TLB 规则为基准，修复 12 核启动、
IPI/TLB shootdown、线程/进程退出发布以及高并发短任务的资源生命周期。按本批次
约束，没有运行完整 BuildStorm；验证止于 CAgent、工具链探针、最小 Cargo 工程和
双架构静态检查。

基线（2026-08-02）：

- 顶层源码：`b766dae83e2a96af6b15cca10409d25948d95818`
- `os/` 基线：`d21154e86fb50798f8413b4abd37e2835d2168b3`
- `os/` 修复实现：`e699326f17e23e617a2eddbe5ed8103e572c4a3e`
- 决赛测例：`1eac61d3becaa592c8ef12a7535f0ec6bb9e3e36`
- LoongArch 镜像 SHA-256：
  `2ad9d955684297abe9db48d94f1b7fcc488268fc8f481408c55b1ec27f520c6a`
- QEMU 11.0.3，`MEM=8G`，`SMP=12`，raw 镜像只以 snapshot 模式启动

## 关键设计

### LoongArch TLB

- 从 FDT 发现并启动 12 个 hart；online mask 的发布与新 hart 最终本地 full TLB
  flush 配合，封闭 CPU 上线和远程 shootdown 的竞态。
- 用户地址空间使用 ASID 与同步 IPI shootdown。LoongArch 一个 TLB 项覆盖相邻的
  even/odd 4 KiB 页，因此 range/page invalidation 按 8 KiB pair 对齐，并使用
  `INVTLB_ADDR_GFALSE_AND_ASID`；该行为与 Linux
  `arch/loongarch/mm/tlb.c` 一致。
- 新安装的 supervisor-only trap-context PTE 也进入对应用户 ASID 的 invalidation
  batch。此前只记录带 `U` 的映射，会让另一个 hart 保留 pair 另一半的 invalid
  translation，并在首次进入 `alltraps` 时反复 fault。
- kernel stack 与运行期 PCI ECAM/BAR 属于共享高半区映射，不能用任意用户 ASID
  代替。新增映射在可见/可调度前执行同步 shared-kernel shootdown；删除路径继续在
  frame 可复用前完成同类 shootdown。

参考：

- <https://codebrowser.dev/linux/linux/arch/loongarch/mm/tlb.c.html>
- <https://cdn.kernel.org/doc/html/latest/arch/loongarch/introduction.html>

### exit/wait/reparent

- zombie 状态、父进程 exited queue、wait/vfork waiter 与 pidfd waiter 在
  parent -> child 锁序下原子发布；重资源在 waitable 状态发布前完成分离。
- `wait_reaped` 表示一次性的 `EXIT_ZOMBIE -> EXIT_DEAD` claim。`wait4` 和破坏性的
  `waitid` 只能消费一次；`WNOWAIT` 不 claim，从而避免重复返回 PID、重复累计
  `RUSAGE_CHILDREN` 和二次删除 PID。
- `exit_teardown` 与 live-thread count 防止正在退出的进程继续收养 orphan。
  zombie 被 reparent 后，新 reaper 会收到退出信号并唤醒 wait/vfork waiter。
- `CLONE_PARENT` 在 prospective parent -> caller -> child 锁序下重新验证父关系和
  liveness。无法保持语义时在 child 可运行前返回 `EAGAIN`；失败回滚先 claim 并按
  Arc identity 从当前父进程摘除，可抵抗并发 reparent。

### network namespace 生命周期

- process、namespace file、socket 和 fork pin 四类引用由同一个 lifetime 表统一计数；
  `setns()` 的 file -> process 交接和 fork 的 pin -> process 交接都在同一锁内完成，
  teardown 不会再从分离计数中读到撕裂的“全零”快照。
- teardown 只在 lifetime 锁内原子 claim，实际协议栈清理在解锁后进行；完成后保留
  dead tombstone。namespace id 单调且不复用，旧 id 不能在清理完成后复活。
- `setns()` 与 exit/rollback 都在 PCB 锁内串行 owner 状态；后者用一次性 release
  释放 process ref。`/proc/<pid>/ns/net` 文件引用也在同一 PCB 临界区取得。
- fork 在父 PCB 锁内取得短生命周期 namespace pin，并在 child 发布前原子转换成
  process ref，封闭 snapshot/publication 窗口及中间零引用状态。
- socket 创建时在同一 PCB 临界区读取 namespace 并获取独立引用。TCP/UDP、packet、
  raw、UNIX 和 netlink socket 的 namespace 生命周期引用随文件对象而不是当前进程
  namespace 生存，因此 setns 后不会提前销毁旧 socket 依赖的 namespace 状态。
- 最后一个 socket 的 Drop 只排队 cleanup；idle worker 在 weak-socket registry 锁外
  重试，避免析构与 registry retain/upgrade 路径互锁。

## 验证结果

静态检查：

```sh
TMPDIR=$PWD/.tmp ARCH=loongarch64 cargo check \
  --target loongarch64-unknown-none-softfloat
TMPDIR=$PWD/.tmp ARCH=riscv64 cargo check \
  --target riscv64gc-unknown-none-elf
git diff --check
```

三项均通过。完整 `cargo fmt --all -- --check` 仍会命中本批次之前就存在的
`src/syscall/filesystem/perm_utils.rs` 格式差异；本批次修改文件已单独 rustfmt。
最终一次双架构检查已包含统一 netns lifetime/teardown gate 修复。

运行验证：

- 12/12 hart online，mask `0xfff`，failed mask `0x0`。
- `rustc --version` 与 `cargo --version` 连续 12 轮完成，无挂起。
- 离线最小 Cargo `Hello, world!` 构建并运行成功，用时约 1 分 33 秒。
- 单个 kernel agent 首连接连续 20 轮：20 pass / 0 fail。日志：
  `testsuits-final/.tmp/final-runs/20260802-171856-loongarch64-shell/serial.log`。
- 官方并发 CAgent：10/10 pass，199.10/200。日志与评分：
  `testsuits-final/.tmp/final-runs/20260802-174331-loongarch64-cagent/`。
- 最终日志中没有 `remove_from_pid2process: ... already reaped`、panic 或 fatal trap。

## 尚未覆盖

- 按本批次约束没有运行完整 BuildStorm，因此不能据此宣称 BuildStorm 完整版通过。
- `MapArea::append_to()` 的非 lazy、部分映射失败回滚仍只做本地逐页 unmap；当前没有
  安装 PTE 的外部调用者。后续若启用该路径，应改成 batched rollback，并在同步 ASID
  invalidation 完成后再释放 frame。
- 现有 rtnetlink 部分请求处理仍从 `current_process()` 选择 namespace，而不是始终使用
  socket 固定的 `net_ns_id`；本批次只闭合其生命周期，setns 后旧 netlink fd 的完整
  Linux 请求语义仍需单独重构。直接由 `socketpair(AF_UNIX)` 创建的内部 endpoint 也
  尚未作为独立 netns 引用计数；它不访问可被 netns cleanup 删除的协议栈状态。
- 一般无 socket 网络操作仍可能只取得裸 `net_ns_id`。本项目当前把 netns membership
  简化为 PCB 级；若将来允许同一 PCB 的多个线程并发 `setns()`，这些短操作也应改为
  持有 RAII transient pin，或改成 Linux 式 per-task namespace membership。
- 正式 BuildStorm 前仍应先做其工具链检查和最小 Cargo 回归，再由用户明确授权完整
  `/work/tgoskits` 编译。
