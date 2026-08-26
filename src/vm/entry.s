// ============================================================================
// vm/entry.s — VM entry/exit primitives
//
// Defines `vm_entry(vcpu_regs: *mut VcpuRegs) -> !`: restores guest state from
// a `VcpuRegs` block (passed in x0 per AAPCS64) and ERETs to EL1.
//
// Defines `vm_exit_sync` / `vm_exit_irq`: Assembly routines called when the
// CPU traps from the Guest OS (EL1) back to the Hypervisor (EL2).
// They save the guest's registers onto the stack, call the Rust handler
// `rust_vm_exit_handler`, and then check its return value:
//   - If 0: Restore the guest's registers from the stack and resume the guest.
//   - If non-zero: Halt the virtual CPU.
//
// Caller contract:
//   • Running at EL2 with SP_EL2 16-byte aligned (SCTLR_EL2.SA=1 enforced).
//   • VTTBR_EL2 already loaded with `(vmid << 48) | stage2_root` for this VM.
//   • HCR_EL2 already updated for the target VM (per `cpu::hcr_for_vm`).
//   • TLBI VMALLS12E1IS + DSB ISH + ISB sequence already executed if the
//     VTTBR_EL2 was just changed.
// On return: hardware ERET to EL1 with PC = guest pc, PSTATE = guest pstate.
// Never returns to the caller — control rejoins Rust through a future VM
// exit into vm_exit_*.
//
// VcpuRegs layout (verified by `offset_of!` const assertions in src/vm/mod.rs):
//     0 .. 248   x[0..30]   31 × u64 GPRs (x0–x30)
//   248 .. 256   sp_el1
//   256 .. 264   pc        — written to ELR_EL2
//   264 .. 272   pstate    — written to SPSR_EL2
//   272 .. 392   sys       — VcpuSysRegs, 15 × u64
//                            Field order (mirrored below):
//                              sctlr_el1 / ttbr0_el1 / ttbr1_el1 / tcr_el1 /
//                              mair_el1 / amair_el1 / vbar_el1 /
//                              contextidr_el1 / tpidr_el0 / tpidrro_el0 /
//                              tpidr_el1 / sp_el0 / esr_el1 / far_el1 / par_el1
//   392 .. 400   (8 B padding, VcpuFpRegs.align = 16)
//   400 .. 928   fp        — VcpuFpRegs:
//                              q[0..32]   (512 B)  at +0
//                              fpsr               at +512
//                              fpcr               at +520
//
// References:
//   ARM DDI 0487 — search "Exception entry"
//     Hardware only writes ELR_EL2/SPSR_EL2/ESR_EL2/FAR_EL2/HPFAR_EL2 on EL2 entry from
//     a lower EL for us.  Guest GPRs/FP/SP_EL1 will remain as it was; the hypervisor has 
//     to save/restore across the EL2 round-trip.
//   ARM DDI 0487 — search "Synchronization requirements for AArch64 System registers"
//     A direct write to a System register (the `msr <el1_sysreg>` block above)
//     needs a Context Synchronization Event before its effect is guaranteed.
//     ERET is one — always on Cortex-A72, which lacks FEAT_ExS and so has no
//     way to turn that off — and it synchronizes these EL1 writes before the
//     guest uses them, so the explicit ISB here is defensive, not strictly
//     required (KVM in fact omits it before its guest-entry ERET and relies on
//     the ERET's synchronization).  No DSB: EL1 context is per-core; DSB-and-
//     TLBI sequencing belongs to the `enter_vm` shell.
//   ARM DDI 0487 — search "Instruction Synchronization Barrier"
//     ISB confirms that all earlier instructions complete before later
//     instructions are fetched.
//   ARM DDI 0487 — search "LDP"
//     "This instruction calculates an address from a base register value and an
//     immediate offset, loads two 32-bit words or two 64-bit doublewords from
//     memory, and writes them to two registers."
//   Linux kernel, arch/arm64/kvm/hyp/entry.S — `__guest_enter`
//     Reference for the base-overlap restore pattern: x0 acts as the VcpuRegs
//     base pointer throughout the whole restore process. Because x0 also holds
//     the guest's own x0 data value, its original value is restored at the
//     very last moment by the final LDP (`ldp x0, x1, [x0, #VCPU_X_OFF]`) once
//     pointer access is no longer needed. KVM uses x29 as its base pointer and
//     restores x29/lr last; this file uses x0 passed via AAPCS64, restoring
//     x0/x1 last.
// ============================================================================

// ── Operand substitution layer ─────────────────────────────────────────────
// The seven offset values below are passed in from Rust (`src/vm/mod.rs`) via
// operands in `core::arch::global_asm!`.
//
// We forward each incoming `{{OPERAND}}` into a `.equ` symbol below so that:
//   1. The assembly code throughout this file can use clean, readable symbol
//      names and perform offset arithmetic (e.g. `[x0, #(VCPU_SYS_OFF + 8)]`)
//      instead of substitution braces.
//   2. `VCPU_SIZE` is referenced here to satisfy Rust's requirement that every
//      named operand passed to `global_asm!` is consumed in the template,
//      making it available for stack frame allocation during VM Exit.
.equ VCPU_X_OFF,       {VCPU_X_OFF}
.equ VCPU_SP_EL1_OFF,  {VCPU_SP_EL1_OFF}
.equ VCPU_PC_OFF,      {VCPU_PC_OFF}
.equ VCPU_PSTATE_OFF,  {VCPU_PSTATE_OFF}
.equ VCPU_SYS_OFF,     {VCPU_SYS_OFF}
.equ VCPU_FP_OFF,      {VCPU_FP_OFF}
.equ VCPU_SIZE,        {VCPU_SIZE}

// ── Sub-field offsets within VcpuSysRegs (order: src/vm/mod.rs) ────────────
// Defined here so the field ordering of VcpuSysRegs has a single textual
// representation.  Any future reshuffle of VcpuSysRegs in src/vm/mod.rs
// must update both these symbols and the offset_of! assertions there.
.equ VS_SCTLR_EL1,      0
.equ VS_TTBR0_EL1,      8
.equ VS_TTBR1_EL1,     16
.equ VS_TCR_EL1,       24
.equ VS_MAIR_EL1,      32
.equ VS_AMAIR_EL1,     40
.equ VS_VBAR_EL1,      48
.equ VS_CONTEXTIDR_EL1,56
.equ VS_TPIDR_EL0,     64
.equ VS_TPIDRRO_EL0,   72
.equ VS_TPIDR_EL1,     80
.equ VS_SP_EL0,        88
.equ VS_ESR_EL1,       96
.equ VS_FAR_EL1,      104
.equ VS_PAR_EL1,      112

// ── Sub-field offsets within VcpuFpRegs (order: src/vm/mod.rs) ─────────────
// q[0..32] occupies the first 512 bytes (32 × 16); fpsr / fpcr trail.
.equ VF_FPSR,         512
.equ VF_FPCR,         520

// ── Code section ───────────────────────────────────────────────────────────
.section .text, "ax"

// ────────────────────────────────────────────────────────────────────────────
// vm_entry(vcpu_regs: *mut VcpuRegs) -> !
//
// AAPCS64: x0 holds the pointer to VcpuRegs (the saved guest register state).
// Restores ELR_EL2, SPSR_EL2, EL1 system registers, FP/SIMD registers, and
// SP_EL1. General-purpose registers are restored last so x0 remains valid as
// the base pointer until the final LDP restores x0/x1. Concludes with ISB → ERET.
//
// Exported via `.global vm_entry` so Rust can declare and invoke it.
// ────────────────────────────────────────────────────────────────────────────
.global vm_entry
vm_entry:
    // ── 1. ELR_EL2 ← guest pc ─────────────────────────────────────────────
    ldr     x1, [x0, #VCPU_PC_OFF]
    msr     elr_el2, x1

    // ── 2. SPSR_EL2 ← guest pstate ────────────────────────────────────────
    ldr     x1, [x0, #VCPU_PSTATE_OFF]
    msr     spsr_el2, x1

    // ── 3. Restore 15 EL1 system registers ────────────────────────────────
    // We use x2 as a temporary scratch register to read values from memory
    // and write them into the hardware system registers. x0 is left untouched.
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_SCTLR_EL1)]
    msr     sctlr_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_TTBR0_EL1)]
    msr     ttbr0_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_TTBR1_EL1)]
    msr     ttbr1_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_TCR_EL1)]
    msr     tcr_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_MAIR_EL1)]
    msr     mair_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_AMAIR_EL1)]
    msr     amair_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_VBAR_EL1)]
    msr     vbar_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_CONTEXTIDR_EL1)]
    msr     contextidr_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_TPIDR_EL0)]
    msr     tpidr_el0, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_TPIDRRO_EL0)]
    msr     tpidrro_el0, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_TPIDR_EL1)]
    msr     tpidr_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_SP_EL0)]
    msr     sp_el0, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_ESR_EL1)]
    msr     esr_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_FAR_EL1)]
    msr     far_el1, x2
    ldr     x2, [x0, #(VCPU_SYS_OFF + VS_PAR_EL1)]
    msr     par_el1, x2

    // ── 4. Restore FP / SIMD state ────────────────────────────────────────
    // We calculate a new base pointer (x1) specifically for the FP registers
    // because LDP offsets have a strict distance limit in ARM64. We restore
    // all 32 FP registers (q0-q31) plus the status/control registers.
    // Eagerly restoring these guarantees zero jitter for HFT applications.
    add     x1, x0, #VCPU_FP_OFF
    ldp     q0,  q1,  [x1, #0]
    ldp     q2,  q3,  [x1, #32]
    ldp     q4,  q5,  [x1, #64]
    ldp     q6,  q7,  [x1, #96]
    ldp     q8,  q9,  [x1, #128]
    ldp     q10, q11, [x1, #160]
    ldp     q12, q13, [x1, #192]
    ldp     q14, q15, [x1, #224]
    ldp     q16, q17, [x1, #256]
    ldp     q18, q19, [x1, #288]
    ldp     q20, q21, [x1, #320]
    ldp     q22, q23, [x1, #352]
    ldp     q24, q25, [x1, #384]
    ldp     q26, q27, [x1, #416]
    ldp     q28, q29, [x1, #448]
    ldp     q30, q31, [x1, #480]
    ldr     x2, [x1, #VF_FPSR]
    msr     fpsr, x2
    ldr     x2, [x1, #VF_FPCR]
    msr     fpcr, x2

    // ── 5. SP_EL1 ← guest sp_el1 ──────────────────────────────────────────
    ldr     x1, [x0, #VCPU_SP_EL1_OFF]
    msr     sp_el1, x1

    // ── 6. Restore GPRs LAST (x0 stays valid as VcpuRegs base) ────────────
    // General-purpose registers are restored starting from the back (x2-x29),
    // leaving x0 and x1 for the very last LDP instruction. The hardware reads
    // the pointer from x0 *before* overwriting x0 with the guest's data,
    // making this base-overlap trick perfectly safe.
    ldp     x2,  x3,  [x0, #(VCPU_X_OFF +  16)]
    ldp     x4,  x5,  [x0, #(VCPU_X_OFF +  32)]
    ldp     x6,  x7,  [x0, #(VCPU_X_OFF +  48)]
    ldp     x8,  x9,  [x0, #(VCPU_X_OFF +  64)]
    ldp     x10, x11, [x0, #(VCPU_X_OFF +  80)]
    ldp     x12, x13, [x0, #(VCPU_X_OFF +  96)]
    ldp     x14, x15, [x0, #(VCPU_X_OFF + 112)]
    ldp     x16, x17, [x0, #(VCPU_X_OFF + 128)]
    ldp     x18, x19, [x0, #(VCPU_X_OFF + 144)]
    ldp     x20, x21, [x0, #(VCPU_X_OFF + 160)]
    ldp     x22, x23, [x0, #(VCPU_X_OFF + 176)]
    ldp     x24, x25, [x0, #(VCPU_X_OFF + 192)]
    ldp     x26, x27, [x0, #(VCPU_X_OFF + 208)]
    ldp     x28, x29, [x0, #(VCPU_X_OFF + 224)]
    ldr     x30,      [x0, #(VCPU_X_OFF + 240)]
    ldp     x0,  x1,  [x0, #VCPU_X_OFF]

    // ── 7. ISB → ERET ─────────────────────────────────────────────────────
    // `isb` acts as a barrier, ensuring all the system register changes we
    // just made are fully applied before we jump. `eret` reads ELR_EL2 and
    // SPSR_EL2 to safely land the CPU inside the EL1 Guest OS.
    isb
    eret

// ────────────────────────────────────────────────────────────────────────────
// vm_exit_sync / vm_exit_irq — guest exception save path + continue/halt
//
// These are the landing pads for when a 64-bit Guest OS traps into our Hypervisor.
// The hardware's exception vector table only gives us a tiny 128-byte slot per
// exception type, which isn't enough space to save all 900+ bytes of guest registers.
// Therefore, the vector table will simply contain a jump (`b vm_exit_sync`)
// to this location, where we have plenty of room to do the actual heavy lifting.
// This matches how Linux KVM handles vector table constraints.
//   Linux kernel, arch/arm64/kvm/hyp/hyp-entry.S — `el1_sync` / `entry.S` — `__guest_exit`
//
// Both `vm_exit_sync` and `vm_exit_irq` are two labels on the exact same code
// below — they fall through into one shared save body. We don't try to figure
// out what caused the exit here in assembly; instead, we save everything and
// let the Rust code figure it out by reading the ESR_EL2 (Exception Syndrome)
// register.
//
// On a trap from Guest to Hypervisor, the hardware itself writes only a few
// registers: the guest PC into ELR_EL2 and the guest PSTATE into SPSR_EL2
// (plus syndrome info in ESR_EL2 / FAR_EL2). Everything else still holds the
// Guest's live values, and we save it all — but for two different reasons:
//   • GPRs (x0–x30) and FP/SIMD: our EL2 Rust handler actively uses these
//     registers, so they must be spilled before Rust clobbers them.
//   • EL1 system registers (sctlr_el1 … par_el1): EL2 code does not normally
//     write these; we save them to capture the complete vCPU context for later
//     context-switch / inspection (and to cover par_el1, which an EL2 `AT`
//     instruction can overwrite).
//   ARM DDI 0487 — search "Exception entry"
//
// We save these registers directly onto our Hypervisor stack by subtracting
// VCPU_SIZE (928 bytes) from the stack pointer. Because 928 is a multiple of 16,
// the stack remains perfectly 16-byte aligned. This on-stack "frame" becomes
// the single source of truth: our Rust handler will read from it and modify it
// directly (e.g., advancing the PC after a system call), and then we will
// restore the Guest directly from this same stack frame without any extra copies.
//
// Notice that we save and restore all 32 Floating Point / SIMD registers
// every single time. While this takes a few extra CPU cycles, it completely
// eliminates "lazy FPU" trap delays inside the Guest, guaranteeing the rock-solid
// determinism required for High-Frequency Trading (HFT).
//   ARM DDI 0487 — search "Advanced SIMD and floating-point support"
// ────────────────────────────────────────────────────────────────────────────
.global vm_exit_sync
.global vm_exit_irq
vm_exit_sync:
vm_exit_irq:
    // ── 1. Allocate on-stack VcpuRegs frame ───────────────────────────────
    sub     sp, sp, #VCPU_SIZE

    // ── 2. Save guest GPRs x0–x30 ─────────────────────────────────────────
    // This MUST be the very first thing we do. Later on, we need to use these
    // registers (like x0 and x2) as temporary scratchpads to move system registers
    // into memory. If we didn't save the Guest's original GPR values here first,
    // we would accidentally overwrite and destroy them.
    stp     x0,  x1,  [sp, #(VCPU_X_OFF +   0)]
    stp     x2,  x3,  [sp, #(VCPU_X_OFF +  16)]
    stp     x4,  x5,  [sp, #(VCPU_X_OFF +  32)]
    stp     x6,  x7,  [sp, #(VCPU_X_OFF +  48)]
    stp     x8,  x9,  [sp, #(VCPU_X_OFF +  64)]
    stp     x10, x11, [sp, #(VCPU_X_OFF +  80)]
    stp     x12, x13, [sp, #(VCPU_X_OFF +  96)]
    stp     x14, x15, [sp, #(VCPU_X_OFF + 112)]
    stp     x16, x17, [sp, #(VCPU_X_OFF + 128)]
    stp     x18, x19, [sp, #(VCPU_X_OFF + 144)]
    stp     x20, x21, [sp, #(VCPU_X_OFF + 160)]
    stp     x22, x23, [sp, #(VCPU_X_OFF + 176)]
    stp     x24, x25, [sp, #(VCPU_X_OFF + 192)]
    stp     x26, x27, [sp, #(VCPU_X_OFF + 208)]
    stp     x28, x29, [sp, #(VCPU_X_OFF + 224)]
    str     x30,      [sp, #(VCPU_X_OFF + 240)]

    // ── 3. Save guest PC / PSTATE (hardware parked them in ELR/SPSR) ──────
    mrs     x0, elr_el2
    str     x0, [sp, #VCPU_PC_OFF]
    mrs     x0, spsr_el2
    str     x0, [sp, #VCPU_PSTATE_OFF]

    // ── 4. Save guest SP_EL1 ──────────────────────────────────────────────
    mrs     x0, sp_el1
    str     x0, [sp, #VCPU_SP_EL1_OFF]

    // ── 5. Save 15 EL1 system registers (order: VcpuSysRegs) ──────────────
    mrs     x2, sctlr_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_SCTLR_EL1)]
    mrs     x2, ttbr0_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_TTBR0_EL1)]
    mrs     x2, ttbr1_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_TTBR1_EL1)]
    mrs     x2, tcr_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_TCR_EL1)]
    mrs     x2, mair_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_MAIR_EL1)]
    mrs     x2, amair_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_AMAIR_EL1)]
    mrs     x2, vbar_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_VBAR_EL1)]
    mrs     x2, contextidr_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_CONTEXTIDR_EL1)]
    mrs     x2, tpidr_el0
    str     x2, [sp, #(VCPU_SYS_OFF + VS_TPIDR_EL0)]
    mrs     x2, tpidrro_el0
    str     x2, [sp, #(VCPU_SYS_OFF + VS_TPIDRRO_EL0)]
    mrs     x2, tpidr_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_TPIDR_EL1)]
    mrs     x2, sp_el0
    str     x2, [sp, #(VCPU_SYS_OFF + VS_SP_EL0)]
    mrs     x2, esr_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_ESR_EL1)]
    mrs     x2, far_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_FAR_EL1)]
    mrs     x2, par_el1
    str     x2, [sp, #(VCPU_SYS_OFF + VS_PAR_EL1)]

    // ── 6. Save FP/SIMD state (eager — see header) ────────────────────────
    add     x1, sp, #VCPU_FP_OFF
    stp     q0,  q1,  [x1, #0]
    stp     q2,  q3,  [x1, #32]
    stp     q4,  q5,  [x1, #64]
    stp     q6,  q7,  [x1, #96]
    stp     q8,  q9,  [x1, #128]
    stp     q10, q11, [x1, #160]
    stp     q12, q13, [x1, #192]
    stp     q14, q15, [x1, #224]
    stp     q16, q17, [x1, #256]
    stp     q18, q19, [x1, #288]
    stp     q20, q21, [x1, #320]
    stp     q22, q23, [x1, #352]
    stp     q24, q25, [x1, #384]
    stp     q26, q27, [x1, #416]
    stp     q28, q29, [x1, #448]
    stp     q30, q31, [x1, #480]
    mrs     x2, fpsr
    str     x2, [x1, #VF_FPSR]
    mrs     x2, fpcr
    str     x2, [x1, #VF_FPCR]

    // ── 7. Hand the frame to Rust ─────────────────────────────────────────
    // We pass our stack frame pointer to the Rust handler via x0.
    // Calling the Rust function (`bl`) will overwrite our link register (x30).
    // This is perfectly fine because the Guest's original x30 is already safely
    // stored in the stack frame and will be restored later.
    mov     x0, sp
    bl      rust_vm_exit_handler
    cbnz    x0, .Lvm_exit_halt

    // ── Continue path: restore from the SAME on-stack frame ───────────────
    // The Rust handler might have modified the frame (for example, adding 4 to
    // the PC so the guest doesn't get stuck executing the same trapping instruction
    // over and over). We now restore all registers directly from this updated frame.

    // ── 8. ELR_EL2 / SPSR_EL2 ← frame pc / pstate ─────────────────────────
    ldr     x0, [sp, #VCPU_PC_OFF]
    msr     elr_el2, x0
    ldr     x0, [sp, #VCPU_PSTATE_OFF]
    msr     spsr_el2, x0

    // ── 9. Restore 15 EL1 system registers ────────────────────────────────
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_SCTLR_EL1)]
    msr     sctlr_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_TTBR0_EL1)]
    msr     ttbr0_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_TTBR1_EL1)]
    msr     ttbr1_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_TCR_EL1)]
    msr     tcr_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_MAIR_EL1)]
    msr     mair_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_AMAIR_EL1)]
    msr     amair_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_VBAR_EL1)]
    msr     vbar_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_CONTEXTIDR_EL1)]
    msr     contextidr_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_TPIDR_EL0)]
    msr     tpidr_el0, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_TPIDRRO_EL0)]
    msr     tpidrro_el0, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_TPIDR_EL1)]
    msr     tpidr_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_SP_EL0)]
    msr     sp_el0, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_ESR_EL1)]
    msr     esr_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_FAR_EL1)]
    msr     far_el1, x2
    ldr     x2, [sp, #(VCPU_SYS_OFF + VS_PAR_EL1)]
    msr     par_el1, x2

    // ── 10. Restore FP/SIMD state ─────────────────────────────────────────
    add     x1, sp, #VCPU_FP_OFF
    ldp     q0,  q1,  [x1, #0]
    ldp     q2,  q3,  [x1, #32]
    ldp     q4,  q5,  [x1, #64]
    ldp     q6,  q7,  [x1, #96]
    ldp     q8,  q9,  [x1, #128]
    ldp     q10, q11, [x1, #160]
    ldp     q12, q13, [x1, #192]
    ldp     q14, q15, [x1, #224]
    ldp     q16, q17, [x1, #256]
    ldp     q18, q19, [x1, #288]
    ldp     q20, q21, [x1, #320]
    ldp     q22, q23, [x1, #352]
    ldp     q24, q25, [x1, #384]
    ldp     q26, q27, [x1, #416]
    ldp     q28, q29, [x1, #448]
    ldp     q30, q31, [x1, #480]
    ldr     x2, [x1, #VF_FPSR]
    msr     fpsr, x2
    ldr     x2, [x1, #VF_FPCR]
    msr     fpcr, x2

    // ── 11. Restore SP_EL1 ────────────────────────────────────────────────
    ldr     x0, [sp, #VCPU_SP_EL1_OFF]
    msr     sp_el1, x0

    // ── 12. Restore GPRs (last) ───────────────────────────────────────────
    // Must come after steps 8–11: those use x0/x1/x2 as scratch (load a value,
    // then `msr` it into a sysreg / SP_EL1 / FP), and x0/x1/x2 are themselves
    // guest GPRs — so their guest values can't be put back until that scratch
    // work is done. That is the ONLY ordering constraint. WITHIN this block the
    // order is free: `sp` is the base (never a destination) and no load depends
    // on another GPR, so x0/x1/x2 could equally be restored first. (Contrast
    // `vm_entry`, where x0 IS the base pointer and therefore must be restored
    // last.) x0/x1 are kept for last here only to mirror that shape.
    ldp     x2,  x3,  [sp, #(VCPU_X_OFF +  16)]
    ldp     x4,  x5,  [sp, #(VCPU_X_OFF +  32)]
    ldp     x6,  x7,  [sp, #(VCPU_X_OFF +  48)]
    ldp     x8,  x9,  [sp, #(VCPU_X_OFF +  64)]
    ldp     x10, x11, [sp, #(VCPU_X_OFF +  80)]
    ldp     x12, x13, [sp, #(VCPU_X_OFF +  96)]
    ldp     x14, x15, [sp, #(VCPU_X_OFF + 112)]
    ldp     x16, x17, [sp, #(VCPU_X_OFF + 128)]
    ldp     x18, x19, [sp, #(VCPU_X_OFF + 144)]
    ldp     x20, x21, [sp, #(VCPU_X_OFF + 160)]
    ldp     x22, x23, [sp, #(VCPU_X_OFF + 176)]
    ldp     x24, x25, [sp, #(VCPU_X_OFF + 192)]
    ldp     x26, x27, [sp, #(VCPU_X_OFF + 208)]
    ldp     x28, x29, [sp, #(VCPU_X_OFF + 224)]
    ldr     x30,      [sp, #(VCPU_X_OFF + 240)]
    ldp     x0,  x1,  [sp, #(VCPU_X_OFF +   0)]

    // ── 13. Free the frame (next exit starts from a clean stack base) ─────
    add     sp, sp, #VCPU_SIZE

    // ── 14. ISB → ERET (same rationale as vm_entry step 7) ────────────────
    isb
    eret

// ── Halt path ─────────────────────────────────────────────────────────────
// The Rust handler returned non-zero, requesting termination.
// For now, this is just a stub that parks the CPU. In the future, we will
// safely copy the final register state back to the Management VM so it can
// inspect why this Guest crashed before we put the CPU to sleep.
.Lvm_exit_halt:
    wfe
    b       .Lvm_exit_halt
