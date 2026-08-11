.section .text.entry
.global _start

.equ CSR_CPUID, 0x20

/*
 * U-Boot enters through its cached DMW mapping.  Keep that mapping intact for
 * the smoke test, preserve a0-a3 verbatim, and pass the hardware CPU ID in a4.
 */
_start:
    csrrd       $a4, CSR_CPUID
    la.global   $sp, boot_stack_top
    bl          rust_main

.Lpark:
    b           .Lpark

.section .bss.stack
.align 12
.global boot_stack
boot_stack:
    .space 64 * 1024
.global boot_stack_top
boot_stack_top:
