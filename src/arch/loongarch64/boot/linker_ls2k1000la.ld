/*
 * CongCore executes from LS2K1000LA low physical RAM, while U-Boot's bootelf
 * writes each segment through the cached 0x9000... alias. VMA and LMA name
 * the same physical bytes through those two views.
 */
VMA_BASE = 0x00200000;
LMA_BASE = 0x9000000000200000;
MANAGED_RAM_END = 0x0a000000;

OUTPUT_ARCH("loongarch")
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = VMA_BASE;
    skernel = .;
    stext = .;
    .text : AT(LMA_BASE + ADDR(.text) - VMA_BASE) {
        KEEP(*(.text.entry))
        . = ALIGN(4K);
        strampoline = .;
        KEEP(*(.text.trampoline));
        . = ALIGN(4K);
        *(.text .text.*)
    } :text
    . = ALIGN(4K);
    etext = .;

    srodata = .;
    .rodata : AT(LMA_BASE + ADDR(.rodata) - VMA_BASE) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.eh_frame_hdr)
        *(.eh_frame)
    } :rodata
    . = ALIGN(4K);
    erodata = .;

    sdata = .;
    .data : AT(LMA_BASE + ADDR(.data) - VMA_BASE) {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
        *(.got.plt)
    } :data
    . = ALIGN(4K);
    edata = .;

    sbss_with_stack = .;
    .bss (NOLOAD) : AT(LMA_BASE + ADDR(.bss) - VMA_BASE) {
        *(.bss.stack)
        sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    } :data
    . = ALIGN(4K);
    ebss = .;
    ekernel = .;
}

ASSERT(ekernel <= MANAGED_RAM_END, "LS2K1000LA kernel overlaps RAM filesystems")
