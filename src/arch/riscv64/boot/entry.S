.section .text.entry
.globl _start
_start:
    # a0: hart id, a1: dtb / opaque
    # Do not let an unexpected hart ID index below the reserved stack region.
    li t1, {max_harts}
    bgeu a0, t1, .Lunsupported_hart

    # Stack grows downward; start from the end of the reserved stack region.
    la sp, boot_stack_bottom
    # 64KiB per hart => hart_id * 2^16, avoids requiring MUL in early boot.
    slli t0, a0, 16
    sub sp, sp, t0            # pick stack slice for this hart
    mv tp, a0                 # stash hart id in tp for S-mode use
    call rust_main

.Lunsupported_hart:
    wfi
    j .Lunsupported_hart

.section .bss.stack
boot_stack_top:
    # Keep this allocation synchronized with config::MAX_HARTS through the
    # const operand in the RISC-V boot module.
    .space 4096*16*{max_harts}
boot_stack_bottom:
