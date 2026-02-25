.section .text.entry
.globl _start
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
    .space 4096*64
boot_stack_bottom:
