// ============================================================================
// cpu/topology.rs — EL2 CPU Topology Detection & Core Role Designation
//
// Reads MPIDR_EL1 (Multiprocessor Affinity Register) on the currently
// executing core.  Decodes the affinity fields to identify the CPU and its
// cluster, then assigns one of two roles:
//
//   • Management  — Core 0, Cluster 0 (Aff0=0, Aff1=0, Aff2=0):
//                   Owns system initialisation, UART, IRQ handling, slow path.
//
//   • Hft         — All other cores:
//                   Interrupt-free, pinned, dedicated to the trading engine.
//                   Must never receive an IRQ/FIQ after GIC steering (NEXT).
//
// DESIGN NOTE — static policy, no runtime allocation:
//   Core roles are determined once at boot by a pure decode of MPIDR_EL1.
//   There is no dynamic table, no heap allocation.  HFT zero-allocation rule
//   is fully respected: this module allocates nothing.
//
// Reference: ARM DDI 0487 — search "MPIDR_EL1, Multiprocessor Affinity Register".
// ============================================================================

use crate::uart::UART;
use core::fmt::Write;

// ── MPIDR_EL1 field masks (ARM DDI 0487, search 'MPIDR_EL1') ─────────────────

/// Bits [7:0]  — Aff0: core index within a cluster.
/// On a standard multi-core SoC, Aff0 uniquely identifies a physical core
/// within its cluster.  On an SMT core (MT bit set), Aff0 is the thread ID.
const MPIDR_AFF0_MASK: u64 = 0x00_00_00_FF;

/// Bits [15:8] — Aff1: cluster identifier.
/// Groups of cores form a cluster (cache-coherent domain).  Different
/// Aff1 values indicate separate physical clusters (e.g. big.LITTLE quad).
const MPIDR_AFF1_MASK: u64 = 0x00_00_FF_00;
const MPIDR_AFF1_SHIFT: u64 = 8;

/// Bits [23:16] — Aff2: secondary cluster / NUMA node identifier.
/// Only relevant on very large SoCs; always 0 on Cortex-A57/A72/N1.
const MPIDR_AFF2_MASK: u64 = 0x00_FF_00_00;
const MPIDR_AFF2_SHIFT: u64 = 16;

/// Bits [39:32] — Aff3: Extended identifier.
/// Introduced in ARMv8-A to allow addressed cores beyond Aff2.
const MPIDR_AFF3_MASK: u64 = 0xFF_00_00_00_00;
const MPIDR_AFF3_SHIFT: u64 = 32;

/// Bit [24] — MT: Multi-Threading indicator.
/// When set, Aff0 encodes the hardware thread (SMT) index, not the core index.
/// Cortex-A series cores set MT=0 (no SMT); this flag is reserved for Neoverse.
const MPIDR_MT_BIT: u64 = 1 << 24;

// ── Core role ─────────────────────────────────────────────────────────────────

/// The operational role assigned to a physical CPU core at boot time.
///
/// This enum is `Copy` so that callers can store roles without lifetime
/// concerns.  There are only two variants — no heap allocation required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreRole {
    /// The bootstrap/management core.
    ///
    /// This core runs the EL2 hypervisor initialisation sequence, owns the
    /// UART driver, and (after GIC setup) is the sole recipient of all
    /// physical IRQs and FIQs.
    Management,

    /// A High-Frequency Trading core.
    ///
    /// Interrupt-free by hardware (GIC affinity routing, Step 12).
    /// Pinned to exactly one vCPU.  Must never execute `WFI`/`WFE` while
    /// the trading engine is active (busy-poll for maximum determinism).
    Hft,
}

// ── CoreInfo — topology descriptor for the running core ──────────────────────

/// A lightweight, stack-allocated descriptor for the currently executing core.
///
/// Populated once by `detect()` and then consulted throughout boot and runtime
/// to gate role-specific behaviour (interrupt masking, wait strategy, etc.).
///
/// Fields are `pub` so that secondary-core startup code (TODO) can read
/// `role` without requiring re-detection.  `#[allow(dead_code)]` is temporary:
/// removed when secondary-core startup code is implemented.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct CoreInfo {
    /// Raw MPIDR_EL1 value (preserved for diagnostic logging).
    pub mpidr_raw: u64,
    /// Aff0: physical core index within `cluster_id`.
    pub core_id: u8,
    /// Aff1: physical cluster identifier.
    pub cluster_id: u8,
    /// Aff2: secondary cluster / node identifier.
    pub aff2: u8,
    /// Aff3: extended affinity identifier.
    pub aff3: u8,
    /// Whether the MT (multi-threading) bit is set in MPIDR_EL1.
    pub multithreaded: bool,
    /// Role assigned to this core.
    pub role: CoreRole,
}

// ── Register access ───────────────────────────────────────────────────────────

/// Read the current value of `MPIDR_EL1`.
///
/// # Safety
/// Legal from EL1 and EL2.  `isb` is not required here because we are only
/// reading an ID register whose value is stable throughout execution.
#[inline]
fn read_mpidr_el1() -> u64 {
    let val: u64;
    // Safety: MPIDR_EL1 is a read-only identification register; reading it
    // has no side effects and is permitted at EL1/EL2.
    unsafe {
        core::arch::asm!(
            "mrs {val}, mpidr_el1",
            val = out(reg) val,
            options(nostack, nomem),
        );
    }
    val
}

// ── Role assignment policy ────────────────────────────────────────────────────

/// Assign a `CoreRole` from decoded affinity fields.
///
/// **Policy (v1.0):**
/// Core 0 on Cluster 0 (Aff0 = 0, Aff1 = 0, Aff2 = 0) → `Management`.
/// Every other physical core → `Hft`.
///
/// This is a deliberate design choice: the bootstrap processor (Core 0) is
/// always the management core because it is the only core alive at reset and
/// owns peripheral access.  Secondary cores (TODO) are
/// exclusively HFT-dedicated to guarantee zero interrupt interference.
#[inline]
fn assign_role(aff0: u8, aff1: u8, aff2: u8, aff3: u8) -> CoreRole {
    if aff0 == 0 && aff1 == 0 && aff2 == 0 && aff3 == 0 {
        CoreRole::Management
    } else {
        CoreRole::Hft
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Detect the topology of the currently executing physical core.
///
/// Reads `MPIDR_EL1`, decodes the affinity fields, assigns a `CoreRole`,
/// and prints a structured diagnostic line to UART.
///
/// Called **once** per core: from the Management core during boot, and later
/// (TODO) from each secondary core immediately after wakeup.
///
/// # Safety
/// Must be called from EL2 (or EL1 on a secondary core after `VBAR_EL2` is
/// set).  The UART `writeln!` calls use the globally-initialised `UART`
/// singleton; the Management core initialises UART in `kmain` before calling
/// this function.
pub fn detect() -> CoreInfo {
    let mpidr = read_mpidr_el1();

    let aff0 = (mpidr & MPIDR_AFF0_MASK) as u8;
    let aff1 = ((mpidr & MPIDR_AFF1_MASK) >> MPIDR_AFF1_SHIFT) as u8;
    let aff2 = ((mpidr & MPIDR_AFF2_MASK) >> MPIDR_AFF2_SHIFT) as u8;
    let aff3 = ((mpidr & MPIDR_AFF3_MASK) >> MPIDR_AFF3_SHIFT) as u8;
    let mt = (mpidr & MPIDR_MT_BIT) != 0;

    let role = assign_role(aff0, aff1, aff2, aff3);

    let role_str = match role {
        CoreRole::Management => "Management (IRQ owner, EL2 init)",
        CoreRole::Hft => "HFT       (interrupt-free, trading engine)",
    };

    writeln!(
        &mut &UART,
        "[topo] MPIDR_EL1 = {:#018x}  Aff3={} Aff2={} Aff1={} Aff0={}  MT={}  → {}",
        mpidr, aff3, aff2, aff1, aff0, mt as u8, role_str,
    )
    .ok();

    CoreInfo {
        mpidr_raw: mpidr,
        core_id: aff0,
        cluster_id: aff1,
        aff2,
        aff3,
        multithreaded: mt,
        role,
    }
}
