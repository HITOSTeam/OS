/*
 * LS2K1000LA U-Boot exposes RAM through the cached DMW alias beginning at
 * 0x9000_0000_0000_0000. Keep the smoke payload in the first low-memory
 * bank, away from U-Boot's relocation, framebuffer and boot-parameter area.
 */
BASE_ADDRESS = 0x9000000000200000;
OUTPUT_ARCH("loongarch")
ENTRY(_start)

SECTIONS
{
    . = BASE_ADDRESS;
    skernel = .;
    stext = .;
    .text : {
        KEEP(*(.text.entry))
        *(.text .text.*)
    }
    . = ALIGN(4K);
    etext = .;
    srodata = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }
    . = ALIGN(4K);
    erodata = .;
    sdata = .;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }
    . = ALIGN(4K);
    edata = .;
    sbss_with_stack = .;
    .bss (NOLOAD) : {
        *(.bss.stack)
        sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }
    . = ALIGN(4K);
    ebss = .;
    ekernel = .;
}

ASSERT(ekernel - skernel <= 32M, "LS2K1000LA smoke image exceeds its 32 MiB window")
