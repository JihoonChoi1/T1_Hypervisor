// ============================================================================
// exception.s - EL2 Exception Vector Table (VBAR_EL2)
//
// ARM requires the vector table base to be 2KiB-aligned (minimum).
// I use 2KiB alignment (.balign 0x800 at the table start).
// 0x800 = 2048 bytes = 2KiB — the minimum alignment required by the ARMv8-A spec.
//
// The EL2 vector table has 4 groups × 4 exception types = 16 entries.
// Each entry is exactly 0x80 (128) bytes. The CPU hardware jumps to a FIXED
// offset from VBAR_EL2. These offsets are hard-wired into the ARM silicon;
// they are not arbitrary choices made by us or our compiler. Therefore, every
// label MUST be placed exactly on its 128-byte slot boundary:
//   ARM DDI 0487 — search "Exception entry terminology"
//     Its "Exception vectors" subsection holds the offset tables: 0x400 =
//     Synchronous / 0x480 = IRQ / 0x500 = FIQ / 0x580 = SError, from the row
//     "Lower Exception level, where the implemented level immediately lower
//     than the target level is using AArch64".
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

// ============================================================================
// ExceptionFrame layout (matches the Rust ExceptionFrame struct in exception.rs)
//
// When an exception fires we push all general-purpose caller/callee registers
// plus the three EL2 exception system registers onto the stack so that the
// Rust handler can inspect them.
//
// Stack layout after SAVE_CONTEXT (lowest address = top of stack):
//   [sp +   0] x0
//   [sp +   8] x1
//   ...
//   [sp + 232] x29  (frame pointer)
//   [sp + 240] x30  (link register / return address before exception)
//   [sp + 248] sp_el0   (saved via mrs)
//   [sp + 256] elr_el2  (exception return address)
//   [sp + 264] spsr_el2 (saved program status)
//   Total frame size: 272 bytes  (0x110)
// ============================================================================

// ── SAVE_CONTEXT macro ────────────────────────────────────────────────────────
// Pushes all 31 GPRs plus ELR/SPSR/SP_EL0 onto the current (EL2) stack.
// After this macro the stack pointer (x0) is the first argument to the
// Rust handler (pointer to ExceptionFrame).
.macro SAVE_CONTEXT
    // Allocate 272 bytes on the stack (must remain 16-byte aligned).
    sub     sp,  sp,  #272

    // Store x0–x29 (GPRs).  stp stores a pair with signed offset.
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]

    // Store x30 (LR) and SP_EL0.
    mrs     x0,  sp_el0
    stp     x30, x0,  [sp, #240]

    // Store ELR_EL2 (exception return address) and SPSR_EL2 (saved pstate).
    mrs     x0,  elr_el2
    mrs     x1,  spsr_el2
    stp     x0,  x1,  [sp, #256]

    // Pass pointer to the frame as the first argument (x0) to the Rust handler.
    mov     x0,  sp
.endm

// ── RESTORE_CONTEXT macro ─────────────────────────────────────────────────────
// Restores ELR/SPSR/SP_EL0 and all GPRs, then frees the stack frame.
// Must be called before ERET.
.macro RESTORE_CONTEXT
    // Reload ELR_EL2 and SPSR_EL2.
    ldp     x0,  x1,  [sp, #256]
    msr     elr_el2,  x0
    msr     spsr_el2, x1

    // Reload x30 and SP_EL0.
    ldp     x30, x0,  [sp, #240]
    msr     sp_el0, x0

    // Reload x0–x29.
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8,  x9,  [sp, #64]
    ldp     x6,  x7,  [sp, #48]
    ldp     x4,  x5,  [sp, #32]
    ldp     x2,  x3,  [sp, #16]
    ldp     x0,  x1,  [sp, #0]

    // Free the stack frame.
    add     sp,  sp,  #272
.endm

// ── VECTOR_ENTRY macro ────────────────────────────────────────────────────────
// This macro creates one 128-byte room (slot) in our vector table. It forces
// the starting address to perfectly align with the 0x80 (128-byte) boundary,
// places the room's name (label), and then writes exactly ONE instruction:
// a jump (`b`) to the real code located outside the table.
//
// Why we MUST do it this way:
// Each 128-byte slot can only hold 32 instructions. If we write too much code
// inside a slot, the compiler won't warn us; it will simply push all the
// subsequent slots downward, ruining the strict hardware alignment.
// For example, an oversized 180-byte code in an early slot once pushed our
// critical guest-trap slot from its required 0x400 address down to 0x500,
// causing a crash. By forcing every slot to use this one-line jump macro,
// exceeding the 128-byte limit becomes structurally impossible.
//
// Both reference hypervisors use exactly this shape:
//   Linux kernel, arch/arm64/kvm/hyp/hyp-entry.S — `valid_vect` / `invalid_vect`
//     (.align 7; fixed preamble + `b \target`; slot-size enforced by
//      `check_preamble_length`)
//   Xen, xen/arch/arm/arm64/entry.S — `ventry` (.align 7; single `b \label`)
.macro VECTOR_ENTRY label, target
.balign 0x80
\label:
    b   \target
.endm

// ============================================================================
// Vector table
// ============================================================================

.section .text.exception_vectors, "ax", @progbits
.global exception_vectors

// The table must start at an address aligned to 0x800 (2KiB).
.balign 0x800
exception_vectors:

// ── Group 1: Current EL, SP_EL0 ─────────────────────────────────────────────
// These fire only while using the EL0 stack pointer — extremely rare in EL2.
// Treat all of them as fatal (we should never be in SP_EL0 mode in EL2).

VECTOR_ENTRY curr_el_sp0_sync, unhandled_exception     // entry 0: Synchronous
VECTOR_ENTRY curr_el_sp0_irq,  unhandled_exception     // entry 1: IRQ
VECTOR_ENTRY curr_el_sp0_fiq,  unhandled_exception     // entry 2: FIQ
VECTOR_ENTRY curr_el_sp0_serr, unhandled_exception     // entry 3: SError

// ── Group 2: Current EL, SP_ELx ─────────────────────────────────────────────
// These fire while EL2 is using its own stack pointer (normal operation).
// A synchronous exception here almost certainly means a hypervisor bug.
// Sync and SError branch to out-of-line bodies below the table (a full
// SAVE_CONTEXT + handler call + RESTORE_CONTEXT is 180 bytes — larger than
// the 128-byte slot, so it cannot live inside the table).

VECTOR_ENTRY curr_el_spx_sync, el2_spx_sync_body       // entry 4: Synchronous ← EL2 fault (bug)
VECTOR_ENTRY curr_el_spx_irq,  unhandled_exception     // entry 5: IRQ
VECTOR_ENTRY curr_el_spx_fiq,  unhandled_exception     // entry 6: FIQ
VECTOR_ENTRY curr_el_spx_serr, el2_spx_serr_body       // entry 7: SError ← hw/bus error

// ── Group 3: Lower EL, AArch64 ──────────────────────────────────────────────
// These exceptions occur when a 64-bit Guest OS (running at EL1/EL0) needs
// the Hypervisor at EL2. This is the most important group for 
// running Virtual Machines (handles HVC calls, Stage-2 page faults, Guest IRQs).
//
// Sync and IRQ exceptions will jump to `vm_exit_sync` / `vm_exit_irq` in `src/vm/entry.s`.
// That code saves all the Guest's registers to memory (about 928 bytes) 
// and then hands control over to `rust_vm_exit_handler` in Rust.
//
// FIQ and SError are intentionally left to crash the system (`unhandled_exception`):
//   • FIQ: Our VMs are configured (HCR_EL2.FMO=0) so that physical FIQs are never 
//     sent to EL2. If a guest FIQ arrives here, it means we have a bug in our 
//     configuration, so we want the system to crash immediately to warn us.
//   • SError: This indicates a fatal hardware error from the Guest. It is too 
//     dangerous to resume the Guest in this state. A proper SError handler will 
//     be implemented in the future.

VECTOR_ENTRY lower_el_aarch64_sync, vm_exit_sync       // entry 8: Synchronous ← guest traps / HVC
VECTOR_ENTRY lower_el_aarch64_irq,  vm_exit_irq        // entry 9: IRQ
VECTOR_ENTRY lower_el_aarch64_fiq,  unhandled_exception // entry 10: FIQ
VECTOR_ENTRY lower_el_aarch64_serr, unhandled_exception // entry 11: SError

// ── Group 4: Lower EL, AArch32 ──────────────────────────────────────────────
// These fire when a 32-bit guest takes an exception routed to EL2.
// I do not support 32-bit guests — treat as fatal.

VECTOR_ENTRY lower_el_aarch32_sync, unhandled_exception // entry 12: Synchronous
VECTOR_ENTRY lower_el_aarch32_irq,  unhandled_exception // entry 13: IRQ
VECTOR_ENTRY lower_el_aarch32_fiq,  unhandled_exception // entry 14: FIQ
VECTOR_ENTRY lower_el_aarch32_serr, unhandled_exception // entry 15: SError

// ============================================================================
// Out-of-line handler bodies (Current EL, SP_ELx)
//
// Full context save + Rust handler call + restore.  Live outside the 16-slot
// table because each body is 180 bytes — bigger than one 128-byte slot.
// ============================================================================

// entry 4 body: EL2 synchronous fault → Rust el2_sync_handler.
.balign 4
el2_spx_sync_body:
    SAVE_CONTEXT
    bl      el2_sync_handler       // call Rust: fn el2_sync_handler(frame: &ExceptionFrame)
    // el2_sync_handler is noreturn for fatal faults, but keep RESTORE for
    // future recoverable cases.
    RESTORE_CONTEXT
    eret

// entry 7 body: EL2 SError → Rust el2_serror_handler.
.balign 4
el2_spx_serr_body:
    SAVE_CONTEXT
    bl      el2_serror_handler     // call Rust: fn el2_serror_handler(frame: &ExceptionFrame)
    RESTORE_CONTEXT
    eret

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
