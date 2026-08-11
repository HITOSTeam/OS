.section .text.entry
.global _start

.equ CSR_CPUID, 0x20
.equ CSR_DMW0, 0x180
.equ CSR_DMW1, 0x181
.equ UART0_BASE, 0x1fe20000

/* Temporary single-byte checkpoints for the first full-kernel board boot. */
.macro UART_MARK byte
    li.d        $t2, UART0_BASE
1:
    ld.bu       $t3, $t2, 5
    andi        $t3, $t3, 0x20
    beqz        $t3, 1b
    li.d        $t3, \byte
    st.b        $t3, $t2, 0
.endm

/*
 * U-Boot loads PT_LOAD segments through its cached 0x9000... DMW alias and
 * starts this code at that alias. The ELF itself is linked at physical
 * 0x0020_0000. Establish the low-address DMW while the current high-address
 * U-Boot window still supplies instruction fetches, then strip the runtime
 * alias. Reversing those two operations raises a TLB refill at the first low
 * instruction because no page table exists yet.
 *
 * a0-a3 are intentionally preserved for the Rust boot record; a4 carries the
 * hardware CPU ID.
 */
_start:
    csrrd       $a4, CSR_CPUID
    li.d        $t0, {max_harts}
    bgeu        $a4, $t0, .Lunsupported_hart

    li.d        $t0, 0x11
    csrwr       $t0, CSR_DMW0
    UART_MARK   0x41
    la.global   $t0, .Lphysical_entry
    slli.d      $t0, $t0, 16
    srli.d      $t0, $t0, 16
    jirl        $zero, $t0, 0

.Lphysical_entry:
    UART_MARK   0x42
    li.d        $t0, 0x11
    csrwr       $t0, CSR_DMW1
    UART_MARK   0x43

    li.d        $t0, 4096 * 16
    mul.d       $t1, $a4, $t0
    la.global   $sp, boot_stack_top
    sub.d       $sp, $sp, $t1
    UART_MARK   0x44
    UART_MARK   0x45
    bl          rust_main

.Lunsupported_hart:
    idle        0
    b           .Lunsupported_hart

.section .bss.stack
.align 12
.global boot_stack
boot_stack:
    .space 4096 * 16 * {max_harts}
.global boot_stack_top
boot_stack_top:
