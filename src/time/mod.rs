// ============================================================================
// time/mod.rs — Deterministic Timer & PMU Setup
//
// Every physical core — Management and HFT alike — must call `init_per_core()`
// once during its boot sequence.  The function:
//
//   1. Zeros CNTVOFF_EL2 so the EL1 virtual timer tracks physical time exactly.
//   2. Disables the virtual timer interrupt on this core (IMASK=1).
//      HFT cores must never receive a timer IRQ; Management core uses WFI +
//      GIC for all interrupt handling anyway.
//   3. Enables the PMU cycle counter (PMCCNTR_EL0) in 64-bit mode so that
//      the trading engine (and hypervisor diagnostics) can take nanosecond-
//      accurate timestamps without any kernel support.
//
// Per-core rationale:
//   Timer offset and PMU registers are banked per-CPU.  CPU 0 cannot configure
//   them for CPU 1–3; each core must write its own registers.
//
// Register reference (ARM DDI 0487):
//   CNTFRQ_EL0     — [Counter-timer Frequency register] Set by EL3 firmware.
//   CNTVOFF_EL2    — [Counter-timer Virtual Offset register] Applied to EL1 timer view.
//   CNTV_CTL_EL0   — [Counter-timer Virtual Timer Control register] (ENABLE, IMASK, ISTATUS).
//   MDCR_EL2       — [Monitor Debug Configuration Register] HPME bit gates EL2 PMU access.
//   PMCR_EL0       — [Performance Monitors Control Register] Global enable, 64-bit mode, reset.
//   PMCNTENSET_EL0 — [Performance Monitors Count Enable Set register] Enable individual PMU counters.
//   PMUSERENR_EL0  — [Performance Monitors User Enable Register] Allow EL0/EL1 to read PMU without trapping.
//   PMCCNTR_EL0    — [Performance Monitors Cycle Count Register] 64-bit cycle counter for HFT hot path.
// ============================================================================

use crate::uart::UART;
use core::fmt::Write;

// ── Register bit-field constants ─────────────────────────────────────────────

// CNTV_CTL_EL0 (ARM DDI 0487, search 'CNTV_CTL_EL0')
//
// Bit 0 — ENABLE : Timer enable.  0 = timer disabled (no expiry event).
// Bit 1 — IMASK  : Interrupt mask.  1 = suppress the timer interrupt signal
//                  even if the timer would otherwise fire.  Both ENABLE=0 and
//                  IMASK=1 are set for belt-and-suspenders IRQ suppression.
// Bit 2 — ISTATUS: Read-only status; not written here.
/// Virtual timer: disabled, interrupt masked (for HFT cores).
const CNTV_CTL_IMASK: u64 = 1 << 1; // bit 1: suppress IRQ

/// Virtual timer: disabled, but explicitly UNMASKED (for Management core).
const CNTV_CTL_UNMASK: u64 = 0; // bit 0 (ENABLE) = 0, bit 1 (IMASK) = 0

// PMCR_EL0 (ARM DDI 0487, search 'PMCR_EL0')
//
// Bit 0 — E  : Global enable for all PMU counters.
// Bit 1 — P  : Write 1 to reset all event counters to 0.
// Bit 2 — C  : Write 1 to reset the cycle counter (PMCCNTR_EL0) to 0.
// Bit 6 — LC : Long counter.  1 = PMCCNTR_EL0 counts 64-bit (no overflow at ~4s).
//              Mandatory for HFT — a 32-bit counter overflows every ~4 seconds.
/// PMCR value: enable all counters, 64-bit cycle counter, reset cycle count.
const PMCR_INIT: u64 = (1 << 0)  // E:  global enable
                      | (1 << 1)  // P:  reset all event counters to 0
                      | (1 << 2)  // C:  reset cycle counter to 0
                      | (1 << 6); // LC: 64-bit cycle counter

// PMCNTENSET_EL0 (ARM DDI 0487, search 'PMCNTENSET_EL0')
//
// Writing 1 to a bit enables the corresponding counter.
// Bit 31 — C: Enable PMCCNTR_EL0 (the cycle counter).
/// Enable the hardware cycle counter (PMCCNTR_EL0).
const PMCNTENSET_CYCLE: u64 = 1 << 31;

/// Enable event counter 0 (PMEVCNTR0_EL0) which will track L2D_CACHE_REFILL.
const PMCNTENSET_EVT0: u64 = 1 << 0;

// PMEVTYPER0_EL0 (ARM DDI 0487, search 'PMEVTYPER<n>_EL0')
//
// Selects the event that PMEVCNTR0_EL0 counts.
// Bits [9:0] — evtCount: PMU event ID.
//
// Event 0x17 = L2D_CACHE_REFILL (ARM DDI 0487, search "0x0017, L2D_CACHE_REFILL"):
//   Counts L2 data cache refills — i.e. cache misses that required a fetch
//   from the next memory level (L3 or main memory).
//   On Cortex-A72 this counts per-core accesses that missed the shared 1MB L2.
//
// NOTE: QEMU does not emulate PMU event counters. This register write is
//   accepted without error on QEMU but PMEVCNTR0_EL0 will always read 0.
//   Meaningful measurements require real RPi4/RPi5 hardware.
/// PMU event ID for L2 data cache refills (L2 misses that go to main memory).
const PMEVTYPER_L2D_CACHE_REFILL: u64 = 0x17;

// PMUSERENR_EL0 (ARM DDI 0487, search 'PMUSERENR_EL0')
//
// Bit 0 — EN: Allow EL0 to read PMU registers without trapping to EL1.
//             Note: this controls the EL0→EL1 trap boundary, NOT EL1→EL2.
//             EL1 can already access PMU registers directly — whether EL1
//             accesses trap to EL2 is controlled by MDCR_EL2.TPM (bit 6),
//             which defaults to 0 (no trap).  Set EN=1 so that EL0 user-mode
//             code (if the trading engine ever runs there) can read PMU
//             registers inline without any trap overhead.
/// Allow EL0 PMU register access (no EL0→EL1 trap).
const PMUSERENR_EN: u64 = 1 << 0;

// MDCR_EL2 (ARM DDI 0487, search 'MDCR_EL2')
//
// Bit 7 — HPME: Hypervisor PMU Enable.
//          0 = EL2's own PMU event counters (HPMN..N-1) are RAZ/WI.
//          1 = EL2 PMU registers are writeable; PMCR_EL0.E takes effect.
//
// HPME must be set before writing PMCR_EL0 or PMCNTENSET_EL0 at EL2;
// without it those writes are silently ignored on real hardware.
// Note: on QEMU (cortex-a57/a72), PMCCNTR_EL0 reads as 0 regardless of
// HPME because QEMU does not emulate the cycle counter — this is a QEMU
// limitation, not a hardware behaviour.
// We read-modify-write to preserve debug/trace bits (e.g. TDRA, TDOSA)
// that may have been set by EL3 firmware.
/// MDCR_EL2 bit 7: Hypervisor PMU Enable.
const MDCR_EL2_HPME: u64 = 1 << 7;
/// MDCR_EL2 bit 6: TPM — traps EL0/EL1 PMU counter accesses to EL2.
/// Must be 0; any `mrs pmccntr_el0` in the HFT hot path would become a
/// VM exit (~100–200 cycles), destroying latency determinism.
const MDCR_EL2_TPM: u64 = 1 << 6;
/// MDCR_EL2 bit 5: TPMCR — traps PMCR_EL0 accesses to EL2.
/// Must be 0; PMCR_EL0 is written in init_per_core() itself — a trap
/// here would create an unrecoverable recursive fault path.
const MDCR_EL2_TPMCR: u64 = 1 << 5;
/// MDCR_EL2 bit 17: HPMD — Hypervisor PMU Disable.
/// Controls EL2's *own* PMU event counting (not guest access — that is TPM/TPMCR).
/// Keep 0: EL2 event counting remains active so PMEVCNTR0_EL0 accumulates correctly.
/// Clear defensively in case EL3 firmware left it as 1.
/// Bit 17 — HPMD: Guest Performance Monitors Disable.
/// (Requires FEAT_SPE/PMUv3p1. Cortex-A72 safely ignores write-to-0 if unimplemented).
const MDCR_EL2_HPMD: u64 = 1 << 17;
/// MDCR_EL2 bits[4:0]: HPMN — number of event counters in the first range (accessible from EL1).
/// Counter indices [0, HPMN-1] are ALLOCATED TO EL1. Counters [HPMN, PMCR.N-1] are EL2-exclusive.
/// Reset value is PMCR_EL0.N (all counters open to EL1).
/// If firmware sets HPMN to a lower value, or if we force HPMN=0, guest EL1 accesses to those
/// counters (e.g. PMEVCNTR0_EL0) will trap to EL2 with EC=0x18, destroying latency determinism.
/// We must read PMCR_EL0.N and write it into HPMN to guarantee 100% EL1 PMU accessibility.
const MDCR_EL2_HPMN_MASK: u64 = 0x1F; // mask for bits[4:0] to clear before inserting N

// ── Internal register accessors ──────────────────────────────────────────────

/// Read `CNTFRQ_EL0` — the system counter frequency in Hz.
///
/// Set once by EL3 firmware before handoff to EL2.  Read-only at EL2.
/// On QEMU `virt` this is typically 62_500_000 Hz (62.5 MHz).
/// On RPi 4 (Cortex-A72) this is 54_000_000 Hz.
#[inline]
fn read_cntfrq() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!(
            "mrs {v}, cntfrq_el0",
            v = out(reg) val,
            options(nostack, nomem),
        );
    }
    val
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read the hardware cycle counter (`PMCCNTR_EL0`).
///
/// An `ISB` is issued before reading so that the value is not speculated
/// across a preceding store or branch — critical for fencing measurements.
///
/// # Usage on the HFT hot path
/// ```rust
/// let t0 = time::read_cycle_counter();
/// // ... code under measurement ...
/// let t1 = time::read_cycle_counter();
/// let cycles = t1 - t0;
/// ```
///
/// Convert cycles → nanoseconds: `ns = cycles * 1_000_000_000 / cntfrq()`.
#[inline]
#[allow(dead_code)] // [TEST] Used Later (Latency Measurement Framework).
pub fn read_cycle_counter() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {v}, pmccntr_el0",
            v = out(reg) val,
            options(nostack, nomem),
        );
    }
    val
}

/// Return the counter frequency in Hz (from `CNTFRQ_EL0`).
///
/// Used by diagnostic code to convert cycle counts to nanoseconds.
/// Not on the hot path.
#[inline]
#[allow(dead_code)] // [TEST] Used Later (PMU cache miss counters and Latency Measurement Framework).
pub fn cntfrq() -> u64 {
    read_cntfrq()
}

/// Read the L2 data cache refill counter (`PMEVCNTR0_EL0`).
///
/// Returns the number of L2 cache misses (refills from main memory) accumulated
/// since the last `init_per_core()` call on this core.  The counter is configured
/// in `init_per_core()` via `PMEVTYPER0_EL0 = 0x17` (L2D_CACHE_REFILL event).
///
/// An `ISB` is issued before the read to prevent speculative reordering across
/// preceding memory accesses — essential for accurate before/after measurements.
///
/// # QEMU limitation
/// QEMU does not emulate PMU event counters.  This function will always return 0
/// on QEMU regardless of actual memory access patterns.  Meaningful readings
/// require real Cortex-A72 (RPi4) or Cortex-A76 (RPi5) hardware.
///
/// # Usage
/// ```rust
/// let before = time::read_l2_refill_count();
/// // ... memory accesses under measurement ...
/// let after = time::read_l2_refill_count();
/// let misses = after - before;
/// ```
#[inline]
#[allow(dead_code)]
pub fn read_l2_refill_count() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {v}, pmevcntr0_el0",
            v = out(reg) val,
            options(nostack, nomem),
        );
    }
    val
}

/// Perform per-core deterministic timer and PMU initialisation.
///
/// **Must be called exactly once per physical core**, from that core's own
/// execution context.  CPU 0 calls this in `kmain` after GIC setup.
/// CPU 1–3 call this inside `secondary_main` after the `INIT_DONE_FLAG`
/// spin barrier is released.
///
/// After this call:
/// - Virtual timer is disabled and its IRQ is masked on this core.
/// - `PMCCNTR_EL0` is running, counting 64-bit cycles from 0.
/// - EL1 code on this core may read PMU registers without trapping to EL2.
///
/// # Safety
/// Must be called from EL2.  Register writes without `isb` would be
/// architecturally UNPREDICTABLE; all writes here are followed by `isb`.
pub fn init_per_core(cpu_id: u8) {
    // ── 1. CNTVOFF_EL2 = 0 ────────────────────────────────────────────────
    // The virtual counter seen by EL1 is: CNTPCT_EL0 - CNTVOFF_EL2.
    // Setting the offset to 0 means virtual time == physical time.
    // This ensures the trading engine's timestamps are directly comparable
    // to network adapter hardware timestamps (which use physical time).
    unsafe {
        core::arch::asm!("msr cntvoff_el2, xzr", "isb", options(nostack, nomem),);
    }

    // ── 2. CNTV_CTL_EL0: disable timer, mask interrupt (HFT only) ─────────
    // HFT cores must never be interrupted by a timer; we force IMASK=1.
    // The Management core (CPU 0) will eventually use the timer for its
    // event loop, so we leave its IMASK=0 (unmasked) but ENABLE=0 so it
    // doesn't fire until we actually schedule an event with CVAL.
    let cntv_ctl_val = if cpu_id == 0 {
        CNTV_CTL_UNMASK
    } else {
        CNTV_CTL_IMASK
    };

    unsafe {
        core::arch::asm!(
            "msr cntv_ctl_el0, {v}",
            "isb",
            v = in(reg) cntv_ctl_val,
            options(nostack, nomem),
        );
    }

    // ── 3a. MDCR_EL2.HPME = 1 — unlock EL2 PMU ──────────────────────────
    // MDCR_EL2.HPME (bit 7) is the architectural gate for the entire EL2 PMU.
    // At reset (and after EL3 firmware handoff) it defaults to 0, which means
    // all PMU registers — including PMCR_EL0 and PMCCNTR_EL0 — are RAZ/WI
    // (reads-as-zero, writes-ignored) at EL2.  Setting HPME=1 first is
    // mandatory; all subsequent PMU writes are meaningless without it.
    //
    // Read-modify-write to preserve any debug/trace bits set by EL3 firmware.
    unsafe {
        let mdcr: u64;
        let pmcr: u64;
        core::arch::asm!(
            "mrs {v}, mdcr_el2",
            "mrs {p}, pmcr_el0",
            v = out(reg) mdcr,
            p = out(reg) pmcr,
            options(nostack, nomem),
        );

        let n_counters = (pmcr >> 11) & 0x1F; // extract PMCR_EL0.N

        core::arch::asm!(
            "msr mdcr_el2, {v}",
            "isb",
            // Explicitly clear TPM, TPMCR, HPMD, and HPMN while setting HPME.
            // A plain OR risks inheriting TPM=1 from EL3 firmware (traps every
            // PMU read in the HFT hot path) or a restricted HPMN.
            // HPMN must equal N to expose all counters to EL1. Writing 0 traps everything!
            v = in(reg) (mdcr & !(MDCR_EL2_TPM | MDCR_EL2_TPMCR | MDCR_EL2_HPMD | MDCR_EL2_HPMN_MASK))
                        | MDCR_EL2_HPME
                        | n_counters,
            options(nostack, nomem),
        );
    }

    // ── 3b. PMCR_EL0: global enable + 64-bit cycle counter ───────────────
    // Now that MDCR_EL2.HPME=1, PMCR_EL0 is writeable at EL2.
    // E=1 (enable all), C=1 (reset cycle counter to 0), LC=1 (64-bit mode).
    // The C (reset) bit is a write-only trigger; it reads back as 0.
    unsafe {
        core::arch::asm!(
            "msr pmcr_el0, {v}",
            "isb",
            v = in(reg) PMCR_INIT,
            options(nostack, nomem),
        );
    }

    // ── 4. PMEVTYPER0_EL0: select L2D_CACHE_REFILL event ────────────────
    // Assign PMU event 0x17 (L2D_CACHE_REFILL) to event counter 0 BEFORE
    // enabling the counter.  Configuring the event type first ensures the
    // counter never accumulates cycles against the wrong (reset-value) event.
    //
    // Bit [31] — P: Do not count in EL1.  Leave 0 to count across all ELs.
    //
    // QEMU limitation: event counters are not emulated; PMEVCNTR0_EL0 reads 0.
    // On real Cortex-A72 (RPi4) hardware this counter increments on each L2
    // cache miss, providing a direct measurement of cache pressure.
    unsafe {
        core::arch::asm!(
            "msr pmevtyper0_el0, {v}",
            "isb",
            v = in(reg) PMEVTYPER_L2D_CACHE_REFILL,
            options(nostack, nomem),
        );
    }

    // ── 4b. PMCNTENSET_EL0: enable the cycle counter and event counter 0 ──
    // Writing bit 31 = 1 starts PMCCNTR_EL0 counting.
    // Bit 0 enables event counter 0 (L2D_CACHE_REFILL), which is now armed
    // with the correct event type from the write above.
    unsafe {
        core::arch::asm!(
            "msr pmcntenset_el0, {v}",
            "isb",
            v = in(reg) PMCNTENSET_CYCLE | PMCNTENSET_EVT0,
            options(nostack, nomem),
        );
    }

    // ── 5. PMUSERENR_EL0: allow EL0/EL1 PMU access ───────────────────────
    // Without this, any `mrs pmccntr_el0` in the EL1 trading engine traps
    // to EL2, adding hundreds of nanoseconds per call — unacceptable for HFT.
    unsafe {
        core::arch::asm!(
            "msr pmuserenr_el0, {v}",
            "isb",
            v = in(reg) PMUSERENR_EN,
            options(nostack, nomem),
        );
    }

    // ── 6. Verification: read back and log ────────────────────────────────
    // [TEST] Readback every register to confirm writes were accepted.
    let freq_hz = read_cntfrq();
    let cntvoff: u64;
    let cntv_ctl: u64;
    let pmcr: u64;
    let mdcr: u64;
    let pmccntr0: u64;
    let pmccntr1: u64;
    unsafe {
        core::arch::asm!("mrs {v}, cntvoff_el2",    v = out(reg) cntvoff,  options(nostack, nomem));
        core::arch::asm!("mrs {v}, cntv_ctl_el0",   v = out(reg) cntv_ctl, options(nostack, nomem));
        core::arch::asm!("mrs {v}, pmcr_el0",       v = out(reg) pmcr,     options(nostack, nomem));
        core::arch::asm!("mrs {v}, mdcr_el2",       v = out(reg) mdcr,     options(nostack, nomem));
        // Two consecutive reads to prove the counter is advancing.
        core::arch::asm!("isb", "mrs {v}, pmccntr_el0", v = out(reg) pmccntr0, options(nostack, nomem));
        core::arch::asm!("isb", "mrs {v}, pmccntr_el0", v = out(reg) pmccntr1, options(nostack, nomem));
    }

    writeln!(
        &mut &UART,
        "[time] CPU {}: CNTFRQ={} Hz  CNTVOFF={:#x}  CNTV_CTL={:#x}  PMCR={:#x}  MDCR_EL2={:#x} (HPME={} TPM={} TPMCR={} HPMN={})",
        cpu_id, freq_hz, cntvoff, cntv_ctl, pmcr, mdcr,
        (mdcr >> 7) & 1, (mdcr >> 6) & 1, (mdcr >> 5) & 1, mdcr & 0x1F,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[time] CPU {}: PMCCNTR t0={} t1={}  Δ={} cycles  (counter advancing: {})",
        cpu_id,
        pmccntr0,
        pmccntr1,
        pmccntr1.wrapping_sub(pmccntr0),
        if pmccntr1 > pmccntr0 {
            "YES ✓"
        } else {
            "NO (expected on QEMU — cycle counter not emulated)"
        },
    )
    .ok();
}
