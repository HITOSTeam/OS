.altmacro
.macro SAVE_GP n
    st.d $r\n, $sp, \n*8
.endm
.macro LOAD_GP n
    ld.d $r\n, $sp, \n*8
.endm

    .section .text.trampoline
    .globl alltraps
    .globl restore
    .globl alltraps_k
    .globl restore_k
    .globl sigreturn_trampoline
    .align 2
alltraps:
    # Swap sp with SAVE0 (CSR 0x30): sp->TrapContext, SAVE0->user sp.
    csrwr $sp, 0x30
    # Save general registers (r0 is constant zero).
    st.d $r1, $sp, 1*8
    st.d $r2, $sp, 2*8
    .set n, 4
    .rept 28
        SAVE_GP %n
        .set n, n+1
    .endr
    # Save PRMD and ERA.
    csrrd $t0, 0x1
    csrrd $t1, 0x6
    st.d $t0, $sp, 32*8
    st.d $t1, $sp, 33*8
    # Save user sp from SAVE0 into x[sp].
    csrrd $t2, 0x30
    st.d $t2, $sp, 3*8
    # Load kernel_tp, kernel_sp, trap_handler, kernel page table.
    ld.d $t0, $sp, 37*8
    ld.d $t1, $sp, 35*8
    ld.d $t2, $sp, 36*8
    ld.d $t3, $sp, 34*8
    slli.d $t3, $t3, 12
    add.d $t4, $t3, $r0
    # Switch to kernel page table so trap_handler/kstack are mapped.
    csrwr $t3, 0x19
    csrwr $t4, 0x1a
    invtlb 0x3, $r0, $r0
    add.d $r2, $t0, $r0
    add.d $sp, $t1, $r0
    jirl $r0, $t2, 0

restore:
    # a0: TrapContext pointer, a1: user page table token
    # Set EENTRY first so any interrupt during page-table switch still
    # vectors to the trampoline handler (which is mapped in both page tables).
    # Reconstruct the trampoline page base from the current PC so we stay
    # entirely within the trampoline mapping and avoid a GOT/literal-pool load.
    # 就是取当前pc,并清零低12位,从rocket
    pcaddi $t0, 0
    srli.d $t0, $t0, 12
    slli.d $t0, $t0, 12
    csrwr $t0, 0xc
    # Now switch PGDL to user page table.
    slli.d $t0, $a1, 12
    csrwr $t0, 0x19
    invtlb 0x3, $r0, $r0
    add.d $sp, $a0, $r0
    # Keep SAVE0 as the TrapContext pointer for the next trap entry.
    csrwr $a0, 0x30
    # Restore PRMD/ERA.
    ld.d $t0, $sp, 32*8
    ld.d $t1, $sp, 33*8
    csrwr $t0, 0x1
    csrwr $t1, 0x6
    # Restore registers except r0/r3.
    ld.d $r1, $sp, 1*8
    .set n, 4
    .rept 28
        LOAD_GP %n
        .set n, n+1
    .endr
    # Save kernel tp and restore user tp.
    st.d $r2, $sp, 37*8
    ld.d $r2, $sp, 2*8
    # Restore user sp and return.
    ld.d $sp, $sp, 3*8
    ertn

    .align 2
sigreturn_trampoline:
    addi.d $r11, $r0, 139
    syscall 0

    .section .text
    .align 2
alltraps_k:
    addi.d $sp, $sp, -38*8
    st.d $r1, $sp, 1*8
    st.d $r2, $sp, 2*8
    .set n, 4
    .rept 28
        SAVE_GP %n
        .set n, n+1
    .endr
    csrrd $t0, 0x1
    csrrd $t1, 0x6
    st.d $t0, $sp, 32*8
    st.d $t1, $sp, 33*8
    st.d $r0, $sp, 34*8
    st.d $r0, $sp, 35*8
    st.d $r0, $sp, 36*8
    st.d $r0, $sp, 37*8
    add.d $a0, $sp, $r0
    bl trap_from_kernel

restore_k:
    ld.d $t0, $sp, 32*8
    ld.d $t1, $sp, 33*8
    csrwr $t0, 0x1
    csrwr $t1, 0x6
    ld.d $r1, $sp, 1*8
    ld.d $r2, $sp, 2*8
    .set n, 4
    .rept 28
        LOAD_GP %n
        .set n, n+1
    .endr
    addi.d $sp, $sp, 38*8
    ertn
