// ============================================================================
// irq/gic.rs — GICv2 Distributor & CPU Interface Driver
//
// Implements hardware-enforced IRQ steering for HFT core isolation.
// After `init()` runs on the Management core, the GICv2 guarantees:
//
//   • ALL SPIs (Shared Peripheral Interrupts, e.g. UART, NIC, timer) are
//     delivered exclusively to CPU 0 (Management core) via `GICD_ITARGETSR`.
//   • The Management core CPU interface (`GICC_PMR = 0xFF`) accepts all
//     interrupt priorities.
//   • HFT cores will set `GICC_PMR = 0x00` upon wakeup (TODO), making
//     it hardware-impossible for any interrupt to reach them.
//
// GIC version: GICv2 (`arm,cortex-a15-gic`).
// MMIO layout confirmed from QEMU virt device-tree dump:
//   GICD base: 0x0800_0000 (64 KiB)
//   GICC base: 0x0801_0000 (64 KiB)
//
// Reference: ARM IHI0048B "ARM Generic Interrupt Controller
//            Architecture Version 2.0".
// ============================================================================

use crate::{
    memory::{GICC_BASE, GICD_BASE},
    uart::UART,
};
use core::fmt::Write;

// ── GICD register offsets (ARM IHI0048B_b_gic_architecture_specification, search "Distributor register map") ────────────────────────────────

/// GICD_CTLR — Distributor Control Register.
/// Bit[1] EnableGrp1 | Bit[0] EnableGrp0.
const GICD_CTLR: usize = 0x000;

/// GICD_TYPER — Interrupt Controller Type Register.
/// Bits[4:0] ITLinesNumber: N → supports 32*(N+1) interrupt lines.
const GICD_TYPER: usize = 0x004;

/// GICD_ICENABLER<n> — Interrupt Clear-Enable Registers.
/// 1 register per 32 interrupts.  Writing 1 disables an interrupt.
const GICD_ICENABLER: usize = 0x180;

/// GICD_IPRIORITYR<n> — Interrupt Priority Registers.
/// 1 byte per interrupt; lower value = higher priority.
const GICD_IPRIORITYR: usize = 0x400;

/// GICD_ITARGETSR<n> — Interrupt Processor Targets Registers.
/// 1 byte per interrupt; each bit = one target CPU.  Bit 0 = CPU 0.
/// NOTE: Read-only for SGIs (0–15) and PPIs (16–31); writable for SPIs (32+).
const GICD_ITARGETSR: usize = 0x800;

/// GICD_ICFGR<n> — Interrupt Configuration Registers.
/// 2 bits per interrupt: 0b10 = edge-triggered, 0b00 = level-sensitive.
const GICD_ICFGR: usize = 0xC00;

/// GICD_PIDR2 — Peripheral ID2 Register.
/// Bits[7:4] ArchRev: 0x1 = GICv1, 0x2 = GICv2, 0x3/0x4 = GICv3+.
const GICD_PIDR2: usize = 0xFE8;

// ── GICC register offsets (ARM IHI0048B, search "CPU interface register map") ────────────────────────────────

/// GICC_CTLR — CPU Interface Control Register.
/// Bit[1] EnableGrp1 | Bit[0] EnableGrp0 — enables IRQ/FIQ delivery to CPU.
const GICC_CTLR: usize = 0x000;

/// GICC_PMR — Interrupt Priority Mask Register.
/// Bits[7:0] Priority: Only interrupts with priority < PMR are forwarded.
/// 0x00 = mask everything (no interrupt reaches CPU).
/// 0xFF = accept all priorities.
const GICC_PMR: usize = 0x004;

/// GICC_IAR — Interrupt Acknowledge Register.
/// Reading this register acknowledges the highest-priority pending IRQ.
/// Bits[9:0] = INTID of the acknowledged interrupt.
#[allow(dead_code)]
const GICC_IAR: usize = 0x00C;

/// GICC_EOIR — End Of Interrupt Register.
/// Writing an INTID here signals EOI to the GIC, de-asserts the interrupt.
#[allow(dead_code)]
const GICC_EOIR: usize = 0x010;

// ── GIC version constants ─────────────────────────────────────────────────────

/// Expected GICv2 architecture revision in `GICD_PIDR2` bits[7:4].
const GIC_V2_ARCH_REV: u32 = 0x2;

// ── SPI routing target ────────────────────────────────────────────────────────

/// CPU target bitmask for Management Core (CPU 0) in `GICD_ITARGETSR`.
/// '0x01' = bit 0 set = deliver to CPU 0 only.
const TARGET_CPU0_ONLY: u8 = 0x01;

/// Default SPI priority written to `GICD_IPRIORITYR`.
/// 0xA0 = priority level 160.  Management core's `GICC_PMR` is set to 0xFF,
/// so all levels are accepted; HFT cores' PMR will be 0x00 (TODO).
const DEFAULT_SPI_PRIORITY: u8 = 0xA0;

// ── MMIO helpers ──────────────────────────────────────────────────────────────

/// Read a 32-bit value from a GIC MMIO register.
///
/// # Safety
/// `base` must be a valid, Device-nGnRnE-mapped MMIO region.
/// No DSB/ISB is inserted here; callers that require ordering must add
/// barriers or rely on the surrounding GIC init sequence's barriers.
#[inline]
unsafe fn mmio_read32(base: usize, offset: usize) -> u32 {
    // Safety: caller guarantees the address is valid Device MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Write a 32-bit value to a GIC MMIO register.
///
/// # Safety
/// `base` must be a valid, Device-nGnRnE-mapped MMIO region.
#[inline]
unsafe fn mmio_write32(base: usize, offset: usize, val: u32) {
    // Safety: caller guarantees the address is valid Device MMIO.
    unsafe {
        core::ptr::write_volatile((base + offset) as *mut u32, val);
    }
}

// ── GIC version detection ───────────────────────────────────────────

/// Read and verify the GIC architecture revision from `GICD_PIDR2`.
///
/// # Panics
/// Panics (via the EL2 panic handler) if the detected revision is not GICv2.
/// A mismatch means the DTB-reported GIC version differs from what we
/// compiled for, which is a fatal configuration error.
fn verify_gic_version() -> u32 {
    // Safety: GICD_BASE is a known-valid Device MMIO address on QEMU virt.
    let pidr2 = unsafe { mmio_read32(GICD_BASE, GICD_PIDR2) };
    let arch_rev = (pidr2 >> 4) & 0xF;

    writeln!(
        &mut &UART,
        "[gic ] GICD_PIDR2 = {:#010x}  ArchRev = {}  ({})",
        pidr2,
        arch_rev,
        if arch_rev == GIC_V2_ARCH_REV {
            "GICv2 ✓"
        } else {
            "UNEXPECTED"
        },
    )
    .ok();

    assert!(
        arch_rev == GIC_V2_ARCH_REV,
        "GIC version mismatch: expected GICv2 (ArchRev=2), got {}",
        arch_rev
    );

    arch_rev
}

// ── GICD initialisation ─────────────────────────────────────────────

/// Initialise the GICv2 Distributor.
///
/// Steps (executed with distributor **disabled** to prevent stale routing):
/// 1. Disable GICD.
/// 2. Read `GICD_TYPER` to determine the number of SPI lines.
/// 3. Disable all SPIs via `GICD_ICENABLER`.
/// 4. Set all SPI priorities to `DEFAULT_SPI_PRIORITY` via `GICD_IPRIORITYR`.
/// 5. Route all SPIs to **CPU 0 only** via `GICD_ITARGETSR`.
/// 6. Configure all SPIs as level-sensitive via `GICD_ICFGR`.
/// 7. Re-enable GICD (EnableGrp0 | EnableGrp1).
///
/// # Safety
/// Must be called exactly once, from the Management core, before any
/// secondary cores are brought online (TODO).
unsafe fn init_gicd() {
    // ── 1. Disable distributor ───────────────────────────────────────────────
    unsafe {
        mmio_write32(GICD_BASE, GICD_CTLR, 0x0);
    }

    // ── 2. Determine number of interrupt lines ───────────────────────────────
    let typer = unsafe { mmio_read32(GICD_BASE, GICD_TYPER) };
    let it_lines_num = (typer & 0x1F) as usize;
    let num_groups = it_lines_num + 1;
    let num_spis = it_lines_num * 32;

    writeln!(
        &mut &UART,
        "[gic ] GICD_TYPER = {:#010x}  ITLinesNumber={}  SPIs={}",
        typer, it_lines_num, num_spis,
    )
    .ok();

    // ── 3. Disable all SPIs ──────────────────────────────────────────────────
    // GICD_ICENABLER is indexed by group (32 IRQs per register).
    // Group 0 (reg[0]) = SGIs and PPIs — skip (read-only for targeting).
    // Groups 1..num_groups cover all SPIs.
    for grp in 1..num_groups {
        unsafe {
            mmio_write32(GICD_BASE, GICD_ICENABLER + grp * 4, 0xFFFF_FFFF);
        }
    }

    // ── 4. Set all SPI priorities ────────────────────────────────────────────
    // GICD_IPRIORITYR: 1 byte per interrupt.  Register n covers INTIDs 4n..4n+3.
    // First 32 INTIDs (SGIs+PPIs) start at offset 0; SPIs at offset 32.
    // We set ALL SPI priority bytes (32..32+num_spis) in 4-byte chunks.
    let priority_word = u32::from_le_bytes([
        DEFAULT_SPI_PRIORITY,
        DEFAULT_SPI_PRIORITY,
        DEFAULT_SPI_PRIORITY,
        DEFAULT_SPI_PRIORITY,
    ]);
    for i in (32..32 + num_spis).step_by(4) {
        unsafe {
            mmio_write32(GICD_BASE, GICD_IPRIORITYR + i, priority_word);
        }
    }

    // ── 5. Route all SPIs to CPU 0 only ─────────────────────────────────────
    // GICD_ITARGETSR: 1 byte per interrupt.  Each bit = one CPU.
    // Bit 0 = CPU 0 (Management).  We write 0x01010101 per 4-byte word.
    // INTIDs 0–31 (SGIs/PPIs) are banked per-CPU — skip (read-only for routing).
    let target_word = u32::from_le_bytes([
        TARGET_CPU0_ONLY,
        TARGET_CPU0_ONLY,
        TARGET_CPU0_ONLY,
        TARGET_CPU0_ONLY,
    ]);
    for i in (32..32 + num_spis).step_by(4) {
        unsafe {
            mmio_write32(GICD_BASE, GICD_ITARGETSR + i, target_word);
        }
    }

    // ── 6. Set all SPIs to level-sensitive ──────────────────────────────────
    // GICD_ICFGR: 2 bits per interrupt.  Register n covers INTIDs 16n..16n+15.
    // SPIs start at INTID 32, which is register n=2.
    // Since each register covers 16 interrupts, we need 2 registers per block of 32.
    for grp in 2..(2 + it_lines_num * 2) {
        unsafe {
            mmio_write32(GICD_BASE, GICD_ICFGR + grp * 4, 0x0000_0000);
        }
    }

    // ── 7. Re-enable distributor (Group 0 + Group 1) ────────────────────────
    unsafe {
        mmio_write32(GICD_BASE, GICD_CTLR, 0x3);
    }

    writeln!(
        &mut &UART,
        "[gic ] GICD init done — {} SPIs routed to CPU 0 (target={:#04x})",
        num_spis, TARGET_CPU0_ONLY,
    )
    .ok();
}

// ── GICC initialisation ─────────────────────────────────────────────

/// Initialise the GICv2 CPU Interface for the **Management core** (CPU 0).
///
/// Sets `GICC_PMR = 0xFF` (accept all interrupt priorities) and enables
/// IRQ and FIQ delivery through `GICC_CTLR`.
///
/// **HFT cores** must call `mask_gicc_hft()` instead upon wakeup (TODO),
/// which sets `GICC_PMR = 0x00`, hardware-blocking all interrupts.
///
/// # Safety
/// Writes to GICC MMIO at a fixed physical base.  Must be called from a
/// single core after GICD is fully configured.
unsafe fn init_gicc_management() {
    unsafe {
        mmio_write32(GICC_BASE, GICC_PMR, 0xFF);
        mmio_write32(GICC_BASE, GICC_CTLR, 0x3);
    }
    let ctlr_rb = unsafe { mmio_read32(GICC_BASE, GICC_CTLR) };
    let pmr_rb = unsafe { mmio_read32(GICC_BASE, GICC_PMR) };

    writeln!(
        &mut &UART,
        "[gic ] GICC (CPU 0 / Management) — CTLR={:#010x}  PMR={:#04x}  (all priorities accepted)",
        ctlr_rb, pmr_rb,
    )
    .ok();
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Mask **all** interrupts on an HFT core's CPU interface.
///
/// Sets `GICC_PMR = 0x00`: no interrupt of any priority can be forwarded
/// to this CPU by the GIC hardware, regardless of `GICD_ITARGETSR`.
///
/// Called from each secondary core's startup path immediately
/// after `VBAR_EL2` is set and before the core enters its trading loop.
///
/// # Safety
/// Writes to GICC MMIO.  Safe to call concurrently from different cores
/// because each core accesses its own banked GICC view via the same
/// base address but separate internal hardware state.
#[allow(dead_code)]
pub unsafe fn mask_gicc_hft() {
    // PMR = 0 → every interrupt priority is below threshold → no delivery.
    unsafe {
        mmio_write32(GICC_BASE, GICC_PMR, 0x00);
        // Disable CPU interface entirely on this core for belt-and-suspenders.
        mmio_write32(GICC_BASE, GICC_CTLR, 0x0);
    }
}

/// Acknowledge and end the current interrupt on the Management core.
///
/// Used by the EL2 IRQ handler to complete an interrupt cycle:
/// 1. Read `GICC_IAR` to acknowledge and obtain the INTID.
/// 2. Handle the interrupt.
/// 3. Write the INTID back to `GICC_EOIR` to signal End-Of-Interrupt.
///
/// Returns the INTID. INTID 1023 indicates a spurious interrupt.
///
/// # Safety
/// Must only be called from the Management core's EL2 IRQ handler.
#[allow(dead_code)]
pub unsafe fn acknowledge_irq() -> u32 {
    // Safety: GICC_BASE is valid MMIO; reading IAR has the side-effect of
    // acknowledging the interrupt in hardware (required by GIC protocol).
    unsafe { mmio_read32(GICC_BASE, GICC_IAR) & 0x3FF }
}

/// Signal End-Of-Interrupt to the GIC for the given INTID.
///
/// # Safety
/// Must only be called from the Management core's EL2 IRQ handler,
/// after `acknowledge_irq()` returns a valid INTID (< 1023).
#[allow(dead_code)]
pub unsafe fn end_irq(intid: u32) {
    // Safety: GICC_BASE is valid MMIO; writing EOIR completes the interrupt.
    unsafe {
        mmio_write32(GICC_BASE, GICC_EOIR, intid);
    }
}

/// Initialise the GICv2 for HFT-safe IRQ steering.
///
/// This is the single entry point called from `kmain` on the Management core.
/// It performs the full three-phase GIC initialisation:
///
/// - **Phase A**: Verify GIC version is exactly GICv2 (halt otherwise).
/// - **Phase B**: Configure GICD to route all SPIs exclusively to CPU 0.
/// - **Phase C**: Open CPU 0's GICC to receive all IRQs/FIQs.
///
/// After this function returns, the hardware guarantees that no physical
/// SPI can be delivered to any core other than CPU 0 (Management).
/// HFT cores additionally call `mask_gicc_hft()` on wakeup (TODO)
/// for defence-in-depth: even if an SPI were mis-targeted, `GICC_PMR=0x00`
/// blocks delivery at the CPU interface level.
///
/// # Safety
/// Must be called **once**, from the **Management core**, with no secondary
/// cores alive.  Calling this after secondary cores are up risks concurrent
/// GICD writes, which is undefined behaviour per the GIC specification.
pub fn init() {
    writeln!(&mut &UART, "\n[gic ] Initialising GICv2 IRQ steering...").ok();

    // Safety: we are on the Management core (Core 0) during single-core boot.
    // GICD_BASE and GICC_BASE are valid Device-nGnRnE MMIO on QEMU virt.
    unsafe {
        // Phase A: verify GIC version.
        verify_gic_version();

        // Phase B: initialise GICD — route all SPIs to CPU 0.
        init_gicd();

        // Phase C: initialise GICC on Management core.
        init_gicc_management();
    }

    writeln!(
        &mut &UART,
        "[gic ] IRQ steering active — HFT cores will be shielded on wakeup.",
    )
    .ok();
}
