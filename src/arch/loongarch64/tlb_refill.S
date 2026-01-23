.section .text.__rfill
.globl __rfill
.align 12

.equ TLBRSAVE, 0x8b
.equ PGD, 0x1b
.equ TLBRELO0, 0x8c
.equ TLBRELO1, 0x8d
.equ TLBREHI, 0x8e
.equ TLBRBADV, 0x89
.equ TLBEHI, 0x11

__rfill:
    csrwr $t0, TLBRSAVE
    csrrd $t0, PGD

    lddir $t0, $t0, 2
    beqz $t0, construct_invalid
    srli.d $t0, $t0, 12
    slli.d $t0, $t0, 12

    lddir $t0, $t0, 1
    beqz $t0, construct_invalid
    srli.d $t0, $t0, 12
    slli.d $t0, $t0, 12
    ldpte $t0, 0
    ldpte $t0, 1
    tlbfill
    b restore_t0

construct_invalid:
    csrrd $t0, TLBREHI
    ori $t0, $t0, 0xC
    csrwr $t0, TLBEHI

    rotri.d $t0, $t0, 61
    ori $t0, $t0, 3
    rotri.d $t0, $t0, 3

    csrwr $t0, TLBRELO0
    csrrd $t0, TLBRELO0
    csrwr $t0, TLBRELO1
    tlbfill

restore_t0:
    csrrd $t0, TLBRSAVE
    ertn
