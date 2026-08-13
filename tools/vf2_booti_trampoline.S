/*
 * 星光 VisionFive 2 原厂 U-Boot（2021.10）兼容启动镜像。
 *
 * 该版本 bootelf 传入的是 C ABI 的 argc/argv，而非 RISC-V 启动 ABI 所需的
 * hart ID 与 DTB 指针。booti 能保留该 ABI，但要求 Linux Image 头；本文件
 * 生成 4 KiB 兼容头并跳转至链接在 0x80200000 的裸机内核。
 */
.section .text
.global _start
_start:
    /* RV64 的 `lui t0, 0x80200` 会符号扩展；由较小的正立即数构造
     * 物理地址 0x0000000080200000。 */
    li  t0, 0x401
    slli t0, t0, 21
    jr  t0

/* U-Boot arch/riscv/lib/image.c 解析的 struct linux_image_h。 */
.org 8
    .quad 0x70000000 /* DRAM 基址 0x40000000 加偏移后为 0xb0000000 */
    .quad 0x1000     /* 镜像大小 */
    .quad 0          /* 标志 */
    .long 0          /* 版本 */
    .long 0          /* 保留 */
    .quad 0          /* 保留 */
    .quad 0          /* 保留 */
    .long 0x05435352 /* Linux RISC-V Image 魔数 */
    .long 0          /* 保留 */

.org 0x1000
