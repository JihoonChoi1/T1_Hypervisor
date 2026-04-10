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
//   2. cpu::init_cptr_el2()   — open FP/SIMD to EL2 and EL1 guests
//   3. cpu::init_sctlr_el2()  — CPU control defaults before MMU on
//   4. cpu::init_mair_el2()   — memory attribute slots for page tables
//   MMU activation (TCR/TTBR/SCTLR.M) belongs to a future MMU module
// ============================================================================

/// CPU frequency pinning: VideoCore mailbox SET_CLOCK_RATE (QEMU no-op).
pub mod freq;

/// CPU topology detection: MPIDR_EL1 decoding, Management/HFT role assignment.
pub mod topology;

/// PSCI (Power State Coordination Interface) SMC calls for secondary core power-on.
pub mod psci;

/// Secondary core wakeup, stack setup, and HFT isolation via GICC masking.
pub mod secondary;

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
/// is wired we forward them as vFIQs to the guest.
///
/// HFT NOTE: This blanket-routes ALL FIQs to EL2, including those on
/// HFT-dedicated cores.  Interim setting — the permanent fix is GIC SPI
/// affinity routing (steer all IRQs/FIQs to management core only).
/// TODO: replace with GIC per-CPU targeting when irq::gic is implemented.
const HCR_FMO: u64 = 1 << 3;

/// Bit 4 — IMO: Route physical IRQ interrupts to EL2.
/// Same rationale as FMO — we intercept and forward to the guest vGIC.
///
/// HFT NOTE: Same caveat as FMO above.  Interim only; GIC affinity routing
/// is the production fix that zeroes interrupt exposure on HFT cores.
/// TODO: replace with GIC per-CPU targeting when irq::gic is implemented.
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

// ── CPTR_EL2 bit positions (ARM DDI 0487, search 'CPTR_EL2') ────────────────
// Applies when HCR_EL2.E2H == 0 (our non-VHE mode).
//
// WHY THIS MATTERS: the reset value of CPTR_EL2 is IMPLEMENTATION DEFINED.
// On several real chips (Cortex-A72, A76, AWS Graviton) TFP resets to an
// UNKNOWN value. If TFP == 1, *any* FP/SIMD instruction at EL1 or EL2 immediately
// traps to EL2. Linux uses NEON very early in boot, so without clearing TFP,
// the guest crashes quickly.
//
// In classic EL2 (E2H=0):
// - Bit 31: TCPAC (Trap CPACR_EL1 accesses to EL2)
// - Bit 20: TTA (Trap Trace Accesses to EL2)
// - Bit 10: TFP (Trap Floating Point and Advanced SIMD to EL2)
//
// We want to write 0 to all these bits to ensure no traps occur.

const CPTR_EL2_NO_TRAPS: u64 = 0;

/// Open FP/SIMD access to EL2 and EL1/EL0 by clearing the TFP bit.
/// Satisfies Layer 1 of the HFT FPU enablement requirement (see block comment above).
///
/// Must be called before any ERET to EL1, i.e. before launching a guest.
/// Failure to call this causes an immediate Undefined Instruction trap the
/// moment the guest kernel executes its first NEON / FP instruction if TFP was 1.
///
/// # Safety
/// Must be called from EL2 only.
pub fn init_cptr_el2() {
    // Build a clean CPTR_EL2 value from scratch.
    // TFP=0 means no FP/SIMD traps.
    // TCPAC=0 means no traps on CPACR_EL1 access.
    // TTA=0 means no traps on trace registers.
    let cptr: u64 = CPTR_EL2_NO_TRAPS;

    unsafe {
        core::arch::asm!(
            "msr cptr_el2, {cptr}",
            "isb",
            cptr = in(reg) cptr,
            options(nostack, nomem),
        );
    }

    writeln!(
        &mut &UART,
        "[cpu ] CPTR_EL2 = {:#018x}  (TFP=0: FP/SIMD open to EL1/EL2)",
        cptr
    )
    .ok();
}

// ── SCTLR_EL2 bit positions (ARM DDI 0487, search 'SCTLR_EL2') ──────────────
// Pre-MMU baseline: we write a clean, deterministic value before the MMU is
// enabled (TODO).  When enable_mmu() runs it only needs to flip bit 0.

/// Bit 0 — M: MMU enable. Left 0 here; Will be set by `memory::stage1::enable_mmu()`.
/// Bit 2 — C: Data cache enable. Left 0 until page tables are coherent.
/// Bit 3 — SA: Stack Alignment Check at EL2. Set 1 — traps a misaligned SP
/// immediately, catching hypervisor stack bugs before they corrupt data.
/// Bit 12 — I: Instruction cache. Left 0 until MMU is on.
/// Bit 25 — EE: Exception Endianness. Left 0 = Little-endian (mandatory for
/// our AArch64 target; setting it wrongly corrupts every register read).
const SCTLR_SA: u64 = 1 << 3;

/// Write a safe, deterministic pre-MMU baseline to SCTLR_EL2.
///
/// The only active feature we enable here is stack alignment checking (SA)
/// so that a misaligned hypervisor stack is caught immediately rather than
/// silently corrupting data.  MMU / cache bits are left 0 and will be set
/// by `memory::stage1::enable_mmu()` (TODO).
///
/// # Safety
/// Must be called from EL2 only.
pub fn init_sctlr_el2() {
    // Write the entire register from scratch — never trust reset values.
    // EE=0 (little-endian) is guaranteed by leaving it unset.
    let sctlr: u64 = SCTLR_SA; // SA=1, everything else safe-zero

    unsafe {
        core::arch::asm!(
            "msr sctlr_el2, {sctlr}",
            "isb",
            sctlr = in(reg) sctlr,
            options(nostack, nomem),
        );
    }

    writeln!(
        &mut &UART,
        "[cpu ] SCTLR_EL2 = {:#018x}  (SA=1, MMU/cache off, LE)",
        sctlr
    )
    .ok();
}

// ── MAIR_EL2 (Memory Attribute Indirection Register) ──────────────────────────
// Purpose: define up to 8 named "memory material" slots (0-7) that page-table
// entries reference via AttrIdx[2:0].  We use two:
//
//   Slot 0 — Normal Memory, Inner/Outer Write-Back Cacheable (0xFF)
//             Used for: kernel code, stack, data, HFT hot-path pages.
//             Why 0xFF? The encoding is:
//               bits [7:4] = Outer attribs = 0b1111 (WB, Read-Allocate/Write-Allocate)
//               bits [3:0] = Inner attribs = 0b1111 (WB, RA/WA)
//             Full caching on both levels → lowest latency for DRAM reads.
//
//   Slot 1 — Device-nGnRnE (0x00)
//             Used for: UART MMIO, NIC MMIO, any memory-mapped peripheral.
//             nGnRnE = non-Gathering, non-Reordering, non-Early-Write-Ack.
//             This is the strictest device type: the CPU guarantees each access
//             hits the device exactly once, in order.  Hardware registers that
//             trigger side-effects (e.g. UART TX FIFO) need this.
//
// Reference: ARM DDI 0487, search 'MAIR_EL2'.

/// MAIR_EL2 Slot 0: Normal WB-Cached (Inner=WB RA/WA, Outer=WB RA/WA).
/// Placed in bits [7:0] of the 64-bit MAIR register.
const MAIR_ATTR0_NORMAL_WB: u64 = 0xFF << 0;

/// MAIR_EL2 Slot 1: Device-nGnRnE (most strictly ordered device type).
/// No caching, no gathering, no reordering — each access is atomic to the device.
/// Placed in bits [15:8].
const MAIR_ATTR1_DEVICE_NGNRNE: u64 = 0x00 << 8;

/// Initialise MAIR_EL2 with the two memory attribute slots used by our
/// Stage-1 page tables (TODO).
///
/// **Slot 0 (AttrIdx=0):** Normal WB-Cached — RAM, HFT pages.
/// **Slot 1 (AttrIdx=1):** Device-nGnRnE  — UART, NIC MMIO.
///
/// Must be called before building Stage-1 page tables (TODO)
/// so that AttrIdx fields in page table descriptors have a defined meaning
/// when the MMU is activated.
///
/// # Safety
/// Must be called from EL2 only.
pub fn init_mair_el2() {
    // Build the MAIR value from scratch — never read-modify-write.
    // Only slots 0 and 1 are populated; slots 2–7 are left 0x00 (Device).
    let mair: u64 = MAIR_ATTR0_NORMAL_WB      // bits [7:0]  = 0xFF (Normal WB-Cached)
                  | MAIR_ATTR1_DEVICE_NGNRNE; // bits [15:8] = 0x00 (Device-nGnRnE)
    // Explicitly OR-ing 0x00 is intentional:
    // Device-nGnRnE encoding IS 0x00 per DDI 0487.
    // Self-documents that Slot 1 is set, not forgotten.

    // Safety: writing MAIR_EL2 at EL2 is architecturally permitted.
    // ISB ensures subsequent page-table walks see the updated attributes.
    unsafe {
        core::arch::asm!(
            "msr mair_el2, {mair}",
            "isb",
            mair = in(reg) mair,
            options(nostack, nomem),
        );
    }

    writeln!(
        &mut &UART,
        "[cpu ] MAIR_EL2  = {:#018x}  (Slot0=Normal-WB 0xFF, Slot1=Device-nGnRnE 0x00)",
        mair
    )
    .ok();
}

// ── Readback / Verification ───────────────────────────────────────────────────

/// Read the current value of CPTR_EL2 and return it.
///
/// # Safety
/// Must be called from EL2 only.
pub fn read_cptr_el2() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!(
            "mrs {val}, cptr_el2",
            val = out(reg) val,
            options(nostack, nomem),
        );
    }
    val
}

/// Read the current value of SCTLR_EL2 and return it.
///
/// # Safety
/// Must be called from EL2 only.
pub fn read_sctlr_el2() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!(
            "mrs {val}, sctlr_el2",
            val = out(reg) val,
            options(nostack, nomem),
        );
    }
    val
}

/// Read the current value of MAIR_EL2 and return it.
///
/// # Safety
/// Must be called from EL2 only.
pub fn read_mair_el2() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!(
            "mrs {val}, mair_el2",
            val = out(reg) val,
            options(nostack, nomem),
        );
    }
    val
}
