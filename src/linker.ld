ENTRY(_start)

/* QEMU virt machine RAM starts here. We load the kernel at an offset to leave room for DTB. */
BASE_ADDRESS = 0x40080000;

SECTIONS
{
    . = BASE_ADDRESS;

    /* Code section */
    .text : ALIGN(4K) {
        KEEP(*(.text._start)) /* Ensure the entry point is placed first */
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    /* Initialized data */
    .data : ALIGN(4K) {
        *(.data .data.*)
    }

    /* Uninitialized data (BSS). Must be zeroed during boot. */
    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Boot stack: placed ABOVE the kernel image, grows downward.
     * Isolates the stack from the DTB region (0x40000000-0x40080000)
     * and from the kernel code/data sections.
     * 64KB is sufficient for early boot before we set up proper per-CPU stacks. */
    .boot_stack (NOLOAD) : ALIGN(4K) {
        __boot_stack_bottom = .;
        . += 64K;
        __boot_stack_top = .;
    }

    /* The Physical Memory Manager uses this to find the first free physical page. */
    __kernel_end = .;

    /* Discard debugging and build info sections to keep binary clean */
    /DISCARD/ : {
        *(.comment)
        *(.gnu*)
        *(.note*)
        *(.eh_frame*)
    }
}
