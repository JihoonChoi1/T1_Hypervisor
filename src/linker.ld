ENTRY(_start)

/* ── Memory layout ──────────────────────────────────────────────────────────
 *
 * Physical address map (QEMU virt, -m 1G):
 *
 *   0x4000_0000  [2 MiB] DTB region          — RW+NX
 *   0x4020_0000  [2 MiB] .text               — RO+X   ← kernel entry point
 *   0x4040_0000  [2 MiB] .rodata             — RO+NX  ← read-only, not executable
 *   0x4060_0000  [...]   .data / .bss / stack — RW+NX
 *
 * Each section boundary is aligned to 2 MiB so the Stage-1 L2 table can
 * assign distinct permissions to each region via a single Block Descriptor.
 * No L3 page tables needed.  Cost: ≤6 MiB of wasted address space (0.6% of 1 GiB).
 *
 * Permission summary (W^X fully enforced):
 *   .text   RO+X   — hardware blocks writes; code is executable
 *   .rodata RO+NX  — hardware blocks writes AND execution
 *   .data   RW+NX  — hardware blocks execution; data is mutable
 * ─────────────────────────────────────────────────────────────────────────── */

BASE_ADDRESS = 0x40200000;   /* 2 MiB past RAM_START — leaves 2 MiB for DTB */

SECTIONS
{
    . = BASE_ADDRESS;

    /* ── Code (RO+X) ─────────────────────────────────────────────────────── */
    .text : ALIGN(4K) {
        __text_start = .;       /* exported to Rust for dynamic MMU mapping */
        KEEP(*(.text._start))   /* entry point must be first */
        *(.text .text.*)
    }

    /* Advance to the next 2 MiB boundary — .rodata gets its own L2 block. */
    . = ALIGN(2M);

    /* ── Read-Only data (RO+NX) ───────────────────────────────────────────── */
    .rodata : ALIGN(4K) {
        __rodata_start = .;     /* exported to Rust for dynamic MMU mapping */
        *(.rodata .rodata.*)
    }

    /* Advance to the next 2 MiB boundary — mutable data gets its own L2 block. */
    . = ALIGN(2M);

    /* ── Mutable data (RW+NX) ─────────────────────────────────────────────── */
    .data : ALIGN(4K) {
        __data_start = .;       /* exported to Rust for dynamic MMU mapping */
        *(.data .data.*)
    }

    /* Uninitialized data (BSS). Zeroed by boot.s before Rust runs. */
    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Boot stack: 64 KiB, grows downward. */
    .boot_stack (NOLOAD) : ALIGN(4K) {
        __boot_stack_bottom = .;
        . += 64K;
        __boot_stack_top = .;
    }

    /* Round to a 4 KiB page so the PMM's first alloc never overlaps BSS. */
    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.gnu*)
        *(.note*)
        *(.eh_frame*)
    }
}
