.section .text.entry
.global _start

.equ CSR_CPUID, 0x20
.equ CSR_DMW0, 0x180
.equ CSR_DMW1, 0x181

_start:
    csrrd $a0, CSR_CPUID

    # The physical CPU ID indexes the statically reserved early stack array.
    # Reject unsupported IDs before deriving or touching a stack pointer.
    li.d $t0, {max_harts}
    bgeu $a0, $t0, .Lunsupported_hart

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

    bl rust_main

.Lunsupported_hart:
    idle 0
    b .Lunsupported_hart

    .section .bss.stack
    .globl boot_stack
boot_stack:
    # `max_harts` is supplied by the LoongArch QEMU boot module.
    .space 4096 * 16 * {max_harts}
    .globl boot_stack_top
boot_stack_top:
