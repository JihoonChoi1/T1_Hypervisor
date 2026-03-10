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

    /* Round up to the next 4 KiB page boundary before marking the end of the
     * kernel image.  Without this guard the PMM's first "free" page could
     * overlap the last partial page of BSS or the boot stack, silently
     * corrupting existing kernel data the moment the allocator hands it out.
     *
     * ALIGN(4096) is cheap — it wastes at most 4095 bytes of address space —
     * and makes every address returned by BuddyAllocator::alloc() safe to use
     * as a page frame without any masking or rounding on the Rust side. */
    . = ALIGN(4096);
    __kernel_end = .;

    /* Discard debugging and build info sections to keep binary clean */
    /DISCARD/ : {
        *(.comment)
        *(.gnu*)
        *(.note*)
        *(.eh_frame*)
    }
}
