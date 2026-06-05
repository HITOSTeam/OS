.section .text.entry
.global _start

.equ CSR_CPUID, 0x20
.equ CSR_DMW0, 0x180
.equ CSR_DMW1, 0x181
.equ UART_THR,  0x1fe001e0

_start:
    csrrd $a0, CSR_CPUID

    li.d $t0, 4096 * 16
    mul.d $t1, $a0, $t0
    la.global $sp, boot_stack_top
    sub.d $sp, $sp, $t1

    pcaddi      $t0,    0x0
    srli.d      $t0,    $t0,    0x30
    slli.d      $t0,    $t0,    0x30
    addi.d      $t0,    $t0,    0x11
    csrwr       $t0,    CSR_DMW1
    sub.d       $t0,    $t0,    $t0
    addi.d      $t1,    $t0,    0x11
    csrwr       $t1,    CSR_DMW0
    pcaddi      $t0,    0x0
    slli.d      $t0,    $t0,    0x10
    srli.d      $t0,    $t0,    0x10
    jirl        $t0,    $t0,    0x10
    sub.d       $t2,    $t1,    $t1
    addi.d      $t2,    $t2,    0x11
    csrwr       $t2,    CSR_DMW1
    csrwr       $t1,    CSR_DMW0

    li.d        $t0,    UART_THR
    li.w        $t1,    0x41
    st.b        $t1,    $t0,    0

    bl rust_main

    .section .bss.stack
    .globl boot_stack
boot_stack:
    .space 4096 * 16 * 4
    .globl boot_stack_top
boot_stack_top:
