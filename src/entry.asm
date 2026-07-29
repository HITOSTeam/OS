.section .text.entry
.globl _start

# RISC-V 评测使用 12 个 hart。每个早期启动栈为 64 KiB，且栈向下增长。
# `boot_stack_bottom - hart_id * BOOT_STACK_PER_HART` 必须始终落在
# 本节预留范围内；此前仅预留一个 hart 的空间，次级 hart 会越界写入。
.equ BOOT_STACK_PER_HART, 4096 * 16
.equ BOOT_STACK_HARTS, 12

_start:
    # a0: hart id, a1: dtb / opaque
    # Stack grows downward; start from the end of the reserved stack region.
    la sp, boot_stack_bottom
    # 64KiB per hart => hart_id * 2^16, avoids requiring MUL in early boot.
    slli t0, a0, 16
    sub sp, sp, t0            # pick stack slice for this hart
    mv tp, a0                 # stash hart id in tp for S-mode use
    call rust_main
.section .bss.stack
boot_stack_top:
    .space BOOT_STACK_PER_HART * BOOT_STACK_HARTS
boot_stack_bottom:
