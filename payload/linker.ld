/* ============================================================================
 * payload/linker.ld — minimal HFT payload image layout
 *
 * The payload runs inside HftEngineVM as a bare-metal AArch64 binary.
 * The hypervisor's Stage-2 table gives that VM IPAs 0x4000_0000..0x4800_0000
 * (128 MiB, 32 768 × 4 KiB pages — see src/vm/mod.rs + src/vm/ram.rs).
 * Loader copies the raw binary to guest IPA 0x4000_0000 per page and seeds
 * vcpu0.regs.pc = 0x4000_0000 (TODO).
 *
 * The guest starts with SCTLR_EL1.M = 0 (MMU off), so IPA and effective VA
 * are identical for the guest.  All addresses below are IPA-as-VA.
 * ============================================================================ */

ENTRY(_start)

MEMORY {
    /* 128 MiB matches HftEngineVM's ipa_size in src/vm/mod.rs.
       LENGTH is informational only — the binary is a few hundred bytes. */
    RAM (rwx) : ORIGIN = 0x40000000, LENGTH = 0x08000000
}

SECTIONS
{
    . = 0x40000000;

    /* ── Code ────────────────────────────────────────────────────────────
     * `.text._start` is the dedicated section for the guest entry symbol
     * (see payload.s).  KEEP() pins it against `--gc-sections`, and
     * placing the pattern first guarantees _start sits at 0x4000_0000 so
     * ERET to ELR_EL2=0x4000_0000 lands on the first instruction. */
    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    } > RAM

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    } > RAM

    .data : ALIGN(8) {
        *(.data .data.*)
    } > RAM

    /* BSS is NOLOAD so `rust-objcopy -O binary` does not emit zero bytes
       for it — the guest RAM is already zeroed by alloc_hft_ram() in
       src/vm/ram.rs before the loader copies the payload. */
    .bss (NOLOAD) : ALIGN(8) {
        *(.bss .bss.*)
        *(COMMON)
    } > RAM

    /* Strip everything non-loadable so the objcopy output contains only
       executable + data bytes. */
    /DISCARD/ : {
        *(.comment)
        *(.gnu*)
        *(.note*)
        *(.eh_frame*)
    }
}
