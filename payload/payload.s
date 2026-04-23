// ============================================================================
// payload/payload.s — minimal HFT heartbeat guest
//
// Executes at EL1 with MMU OFF (SCTLR_EL1.M = 0).  The hypervisor runs
// with HCR_EL2.DC = 0 (see src/cpu.rs init_hcr_el2).
//
// ── Memory-attribute regime ───────────────────────────────────────────
// With stage-1 translation disabled and HCR_EL2.DC = 0, every EL1 data
// access is forced to Device-nGnRnE regardless of the Stage-2 mapping
// (which is Normal-WB for guest RAM and the shared pages).  The stage
// 1/2 attribute combining rule collapses Normal+Device to Device.
//   ARM DDI 0487 — search "Behavior when stage 1 address translation is
//     disabled"
//   ARM DDI 0487 — search "Stage 2 memory type and Cacheability
//     attributes when FWB is disabled"
//
// Consequence: exclusive and atomic instructions (LDXR/STXR, LDAXR/
// STLXR, LDADD and friends) are UNPREDICTABLE on Device memory.
//   ARM DDI 0487 — search "Load-Exclusive/Store-Exclusive"
//   ARM DDI 0487 — search "Atomic instructions"
// The payload therefore uses plain LDR/STR only; a later milestone
// enables the guest's own Stage-1 MMU so heartbeats can graduate to
// proper release-store semantics (STLR / STADD).
//
// Single-writer invariant: only one HFT vCPU ever executes this code
// against the HFT watchdog page (HftEngineVM vcpu[0], pinned to the
// allotted core by the Stage-2 mapping policy — see src/vm/watchdog.rs).
// That removes the read-modify-write race that would otherwise require
// an exclusive monitor.
//
// ── Entry contract (seeded by src/vm/loader.rs(TODO)) ──────────
//   PC          = 0x4000_0000       (ipa_base; first byte of .text._start)
//   SP_EL1      = 0x4010_0000       (ipa_base + 1 MiB)
//   SPSR_EL2    = 0x3C5             (EL1h, DAIF=1111, nRW=0 — AArch64)
//   SCTLR_EL1   = 0x00D5_0838       (ARMv8.0 RES1 preserved, MMU/caches off)
//   VBAR_EL1    = 0
// The guest never relies on its own vector table; any unexpected
// exception inside EL1 is a bug, and in that case a stale VBAR_EL1 of 0
// sends the fault to IPA 0 which is unmapped and will vector straight
// back to EL2 as a Stage-2 abort.
//
// ── Shared-page layout (fixed IPAs, see src/vm/{watchdog,killswitch}.rs) ─
//   0x5000_0000  WatchdogPage    — offset 0  : heartbeat   (u64 LDR/STR)
//                                   S2AP=RW for HftEngineVM, RO for Mgmt.
//   0x5000_2000  KillPage        — offset 0  : flag        (u8)
//                                   S2AP=RO for HftEngineVM, RW for Mgmt.
// ============================================================================

.section .text._start, "ax"
.global _start

_start:
    // ── Load shared-page IPAs via movz/movk (no literal pool) ─────────
    //
    // Watchdog IPA = 0x5000_0000.  `movz Xd, #imm16, lsl #16` places the
    // immediate at bits[31:16] and zero-extends the full 64-bit register
    // — so the low 16 bits and upper 32 bits are already zero.  Single
    // instruction, no movk needed.
    //   ARM DDI 0487 — search "MOVZ (move wide with zero)"
    movz    x19, #0x5000, lsl #16       // x19 = 0x0000_0000_5000_0000

    // Killswitch IPA = 0x5000_2000.  `movz` seeds the high half, `movk`
    // overwrites bits[15:0] in place (MOVK preserves all other bits,
    // unlike MOVZ which clears them).
    //   ARM DDI 0487 — search "MOVK (move wide with keep)"
    movz    x20, #0x5000, lsl #16       // x20 = 0x0000_0000_5000_0000
    movk    x20, #0x2000                // x20 = 0x0000_0000_5000_2000

.Lloop:
    // ── Kill switch poll ──────────────────────────────────────────────
    // LDRB zero-extends a byte into w0.  Any non-zero flag value
    // (KILL_HALT_REQUESTED=0x01 or KILL_EMERGENCY=0xFF — see
    // src/vm/killswitch.rs) transfers control to the halt path.
    ldrb    w0,  [x20]
    cbnz    w0,  .Lhalt

    // ── Heartbeat publish ─────────────────────────────────────────────
    // Plain 64-bit increment of *heartbeat.  Device-nGnRnE semantics
    // forbid reordering and gathering, so the STR is strictly ordered
    // after the LDR — the Management core observes a monotonically
    // advancing counter without any explicit DMB (the barrier is
    // implicit in the memory type).
    //   ARM DDI 0487 — search "Device memory"
    ldr     x0,  [x19]
    add     x0,  x0, #1
    str     x0,  [x19]

    // ── Busy delay ────────────────────────────────────────────────────
    // 0x1000 (=4096) iterations of SUBS/B.NE.  On Cortex-A72 at 1.5 GHz
    // with a 1-cycle-per-iteration body, this is ~2.7 µs per heartbeat
    // tick — well inside the HFT design envelope for watchdog miss
    // detection (~3 ticks).  Cortex-A72 Software Optimization Guide (UAN 0016A) —
    // search "Instruction Characteristics", Execution Latency of SUBS.
    mov     x1,  #0x1000
.Ldelay:
    subs    x1,  x1, #1
    b.ne    .Ldelay

    b       .Lloop

    // ── Halt path ─────────────────────────────────────────────────────
    // HVC #1 is the payload-to-hypervisor halt rendezvous.  ESR_EL2.EC
    // = 0x16 (HVC) and ESR_EL2.ISS[15:0] = 1 identify this instruction
    // at the handler (TODO).  Until that handler exists,
    // executing HVC traps to EL2 via VBAR_EL2 and the generic sync
    // handler dumps registers and halts — an acceptable fallback for
    // a "stop trading now" signal.
    //   ARM DDI 0487 — search "HVC"
    //   ARM DDI 0487 — search "ESR_EL2, Exception Syndrome Register (EL2)"
.Lhalt:
    hvc     #1

    // Defence in depth: if HVC ever returns (it must not), park the
    // core on WFE.  WFE is architecturally a hint and has no memory
    // side-effects; the watchdog heartbeat will stall, triggering a VM
    // reset from the Management core.
    //   ARM DDI 0487 — search "WFE"
.Lhalt_wait:
    wfe
    b       .Lhalt_wait
