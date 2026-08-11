.section .text.entry
.global _start

.equ CSR_CPUID, 0x20
.equ CSR_DMW0, 0x180
.equ CSR_DMW1, 0x181
.equ CSR_DMW2, 0x182

/*
 * U-Boot loads PT_LOAD segments through its cached 0x9000... DMW alias and
 * starts this code at that alias. The ELF itself is linked at physical
 * 0x0020_0000. DMW0 and DMW1 are the only windows that permit instruction
 * fetches, so temporarily duplicate U-Boot's cached high window in DMW0,
 * repurpose DMW1 for cached low-address fetches, and only then jump low.
 *
 * DMW2 is load/store-only, which makes it a good permanent uncached MMIO
 * window. Keeping device accesses under 0x8000... avoids treating UART and
 * other registers as coherent cacheable memory while the low DMW is active.
 * Only PLV0 is enabled on this window.
 *
 * a0-a3 are intentionally preserved for the Rust boot record; a4 carries the
 * hardware CPU ID.
 */
_start:
    csrrd       $a4, CSR_CPUID
    li.d        $t0, {max_harts}
    bgeu        $a4, $t0, .Lunsupported_hart

    li.d        $t0, 0x8000000000000001
    csrwr       $t0, CSR_DMW2

    li.d        $t0, 0x9000000000000011
    csrwr       $t0, CSR_DMW0

    li.d        $t0, 0x11
    csrwr       $t0, CSR_DMW1

    la.global   $t0, .Lphysical_entry
    slli.d      $t0, $t0, 16
    srli.d      $t0, $t0, 16
    jirl        $zero, $t0, 0

.Lphysical_entry:
    li.d        $t0, 0
    csrwr       $t0, CSR_DMW0

    li.d        $t0, 4096 * 16
    mul.d       $t1, $a4, $t0
    la.global   $sp, boot_stack_top
    sub.d       $sp, $sp, $t1
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
