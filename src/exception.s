// ============================================================================
// exception.s - EL2 Exception Vector Table (VBAR_EL2)
//
// ARM requires the vector table base to be 2KiB-aligned (minimum).
// I use 2KiB alignment (.balign 0x800 per entry, table at .balign 0x800).
// 0x800 = 2048 bytes = 2KiB — the minimum alignment required by the ARMv8-A spec.
//
// The EL2 vector table has 4 groups × 4 exception types = 16 entries.
// Each entry is exactly 0x80 (128) bytes.
//
// Group layout (from AArch64 reference):
//   Offset 0x000: Current EL with SP_EL0  — Synchronous
//   Offset 0x080:                          — IRQ/vIRQ
//   Offset 0x100:                          — FIQ/vFIQ
//   Offset 0x180:                          — SError/vSError
//   Offset 0x200: Current EL with SP_ELx  — Synchronous
//   Offset 0x280:                          — IRQ/vIRQ
//   Offset 0x300:                          — FIQ/vFIQ
//   Offset 0x380:                          — SError/vSError
//   Offset 0x400: Lower EL using AArch64  — Synchronous  ← guest traps land here
//   Offset 0x480:                          — IRQ/vIRQ
//   Offset 0x500:                          — FIQ/vFIQ
//   Offset 0x580:                          — SError/vSError
//   Offset 0x600: Lower EL using AArch32  — Synchronous
//   Offset 0x680:                          — IRQ/vIRQ
//   Offset 0x700:                          — FIQ/vFIQ
//   Offset 0x780:                          — SError/vSError
// ============================================================================

.section .text.exception_vectors, "ax", @progbits
.global exception_vectors

// The table must start at an address aligned to 0x800 (2KiB).
.balign 0x800
exception_vectors:

// ── Group 1: Current EL, SP_EL0 ─────────────────────────────────────────────
// These fire only while using the EL0 stack pointer — extremely rare in EL2.
// Treat all of them as fatal (we should never be in SP_EL0 mode in EL2).

.balign 0x80        // entry 0: Synchronous
curr_el_sp0_sync:
    b   unhandled_exception

.balign 0x80        // entry 1: IRQ
curr_el_sp0_irq:
    b   unhandled_exception

.balign 0x80        // entry 2: FIQ
curr_el_sp0_fiq:
    b   unhandled_exception

.balign 0x80        // entry 3: SError
curr_el_sp0_serr:
    b   unhandled_exception

// ── Group 2: Current EL, SP_ELx ─────────────────────────────────────────────
// These fire while EL2 is using its own stack pointer (normal operation).
// This is what fires for hypervisor bugs (null-deref, bad instruction…).

.balign 0x80        // entry 4: Synchronous
curr_el_spx_sync:
    b   unhandled_exception

.balign 0x80        // entry 5: IRQ
curr_el_spx_irq:
    b   unhandled_exception

.balign 0x80        // entry 6: FIQ
curr_el_spx_fiq:
    b   unhandled_exception

.balign 0x80        // entry 7: SError
curr_el_spx_serr:
    b   unhandled_exception

// ── Group 3: Lower EL, AArch64 ──────────────────────────────────────────────
// These fire when a 64-bit guest (running at EL1/EL0) takes an exception
// that is routed up to EL2.  This is the *primary* group we will extend in
// Step 2 and Step 3 (HVC calls, Stage-2 page faults, guest IRQs…).

.balign 0x80        // entry 8: Synchronous  ← guest sync traps / HVC
lower_el_aarch64_sync:
    b   unhandled_exception

.balign 0x80        // entry 9: IRQ
lower_el_aarch64_irq:
    b   unhandled_exception

.balign 0x80        // entry 10: FIQ
lower_el_aarch64_fiq:
    b   unhandled_exception

.balign 0x80        // entry 11: SError
lower_el_aarch64_serr:
    b   unhandled_exception

// ── Group 4: Lower EL, AArch32 ──────────────────────────────────────────────
// These fire when a 32-bit guest takes an exception routed to EL2.
// This do not support 32-bit guests — treat as fatal.

.balign 0x80        // entry 12: Synchronous
lower_el_aarch32_sync:
    b   unhandled_exception

.balign 0x80        // entry 13: IRQ
lower_el_aarch32_irq:
    b   unhandled_exception

.balign 0x80        // entry 14: FIQ
lower_el_aarch32_fiq:
    b   unhandled_exception

.balign 0x80        // entry 15: SError
lower_el_aarch32_serr:
    b   unhandled_exception

// ============================================================================
// unhandled_exception
//
// placeholder: spin forever so QEMU does not silently wander into
// random memory.  I will replace this with a proper Rust handler that
// dumps ESR_EL2 / FAR_EL2 over UART before halting.
// ============================================================================
.balign 4
unhandled_exception:
    wfe
    b   unhandled_exception
