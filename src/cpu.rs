// ============================================================================
// cpu.rs - EL2 System Register Initialisation
//
// This module owns all writes to EL2 system registers during hypervisor boot.
// Every bit-field assignment references the ARMv8-A Architecture Reference
// Manual (DDI 0487) by register name so that the intent is easily auditable
// across any document revision.
//
// Call order (from kmain):
//   1. cpu::init_hcr_el2()    — declare virtualisation mode & trap policy
//   2. cpu::init_cptr_el2()   — open FP/SIMD to EL2 and EL1 guests   [NEXT]
//   3. cpu::init_sctlr_el2()  — CPU control defaults before MMU on    [NEXT]
//   MMU activation belongs to memory::stage1                        [NEXT]
// ============================================================================

use crate::uart::UART;
use core::fmt::Write;

// ── HCR_EL2 bit positions (ARM DDI 0487, search 'HCR_EL2') ──────────────────

/// Bit 0 — VM: Enable EL1&0 Stage-2 address translation.
/// Setting this does NOT activate Stage-2 until VTTBR_EL2 is loaded and
/// valid; but asserting it early locks in the architectural "virtualised"
/// operating mode so that system register traps below work correctly.
const HCR_VM: u64 = 1 << 0;

/// Bit 3 — FMO: Route physical FIQ interrupts to EL2, not EL1.
/// The GIC will route physical FIQs to EL2; after the virtual GIC (vGIC)
/// is wired in Phase 5 we forward them as vFIQs to the guest.
const HCR_FMO: u64 = 1 << 3;

/// Bit 4 — IMO: Route physical IRQ interrupts to EL2.
/// Same rationale as FMO — we intercept and forward to the guest vGIC.
const HCR_IMO: u64 = 1 << 4;

/// Bit 19 — TSC: Trap SMC instructions to EL2 (Secure Monitor Call).
/// Prevents a guest from reaching EL3/secure world directly.
const HCR_TSC: u64 = 1 << 19;

/// Bit 31 — RW: EL1 execution state is AArch64 (not AArch32).
/// Must be 1 for a 64-bit Linux guest; without it the CPU enters
/// AArch32 mode after ERET to EL1, causing an immediate crash.
const HCR_RW: u64 = 1 << 31;

/// Bit 34 — E2H: Enable EL2 Host Extensions (VHE).
/// Intentionally did not set this bit.  VHE collapses EL1 and EL2
/// semantics (used by KVM's non-VHE path and Android's pKVM).  Our
/// design keeps the standard EL2/EL1 split for maximum clarity and
/// compatibility with the ARM spec examples.
// const HCR_E2H: u64 = 1 << 34;  // deliberately left commented out

// ── Public API ───────────────────────────────────────────────────────────────

/// Configure HCR_EL2: declare this is a 64-bit-guest hypervisor, enable
/// Stage-2 translation, and trap SMC/interrupt routing to EL2.
///
/// # Safety
/// Must be called from EL2 only.  Writing HCR_EL2 from any other EL is
/// UNDEFINED BEHAVIOUR per the ARM Architecture Reference Manual.
pub fn init_hcr_el2() {
    let hcr: u64 = HCR_VM       // Stage-2 translation active
                 | HCR_FMO      // FIQs trapped to EL2
                 | HCR_IMO      // IRQs trapped to EL2
                 | HCR_TSC      // SMC trapped to EL2
                 | HCR_RW; // Guest runs in AArch64

    // Safety: we are executing at EL2; writing HCR_EL2 is legal.
    // `isb` ensures subsequent instructions see the updated trap policy.
    unsafe {
        core::arch::asm!(
            "msr hcr_el2, {hcr}",
            "isb",
            hcr = in(reg) hcr,
            options(nostack, nomem),
        );
    }

    writeln!(
        &mut &UART,
        "[cpu ] HCR_EL2 = {:#018x}  (VM|FMO|IMO|TSC|RW)",
        hcr
    )
    .ok();
}

// ── Readback / Verification ───────────────────────────────────────────────────

/// Read the current value of HCR_EL2 and return it.
/// Useful after init to confirm the write was accepted by hardware.
///
/// # Safety
/// Must be called from EL2 only.
pub fn read_hcr_el2() -> u64 {
    let val: u64;
    // Safety: reading a system register at EL2 is architecturally permitted.
    unsafe {
        core::arch::asm!(
            "mrs {val}, hcr_el2",
            val = out(reg) val,
            options(nostack, nomem),
        );
    }
    val
}
