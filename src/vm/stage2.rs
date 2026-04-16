// ============================================================================
// vm/stage2.rs — Stage-2 (IPA→PA) Translation Tables
//
// Implements the Guest Physical Address (IPA) → Host Physical Address (PA)
// translation used by the hypervisor to enforce memory isolation between
// the ManagementVM and HftEngineVM.
//
// Build order (each sub-step is independently compilable):
//   16-A  S2Prot + VTCR_EL2 + alloc_stage2_root        ← this file
//   16-B  stage2_map_2m + stage2_map_range (2 MiB block path)
//   16-C  stage2_map_4k (4 KiB page path for shared pages)
//   16-D  init_stage2() orchestration + main.rs wiring
//
// ARM DDI 0487 references (search keywords):
//   search "Translation table descriptor formats"
//   search "VMSAv8-64 translation using the 4KB granule"
//   search "Stage 2 permissions"
//   search "Stage 2 memory type and Cacheability attributes when FWB is disabled"
//   search "VTCR_EL2"
//   search "VTTBR_EL2"
//   search "The Access flag"
//   search "Stage 2 Execute-never restrictions"
//   search "Stage 2 Shareability attributes"
// ============================================================================

#![allow(dead_code)] // Public API consumed by later steps; suppress until then.

use core::fmt::Write;
use core::ptr::write_bytes;

use crate::memory::pmm;
use crate::uart::UART;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of entries in a 4 KiB page table (512 × 8-byte descriptors = 4096 B).
pub const TABLE_ENTRIES: usize = 512;

// ── Stage-2 Protection Attributes ────────────────────────────────────────────

/// Stage-2 memory protection policy for an IPA region.
///
/// Encodes three orthogonal ARM Stage-2 descriptor fields.
/// ARM DDI 0487, search "Translation table descriptor formats":
///   - `MemAttr[3:0]` (bits[5:2])  — memory type (Normal-WB or Device-nGnRnE)
///   - `S2AP[1:0]`    (bits[7:6])  — stage-2 access permissions (RO or RW)
///   - `XN`           (bit[54])    — execute-never at all ELs (EL1 + EL0)
///
/// ARM DDI 0487, search "Stage 2 memory type and Cacheability attributes when FWB is disabled":
///   0b0000 = Device-nGnRnE (strongly-ordered, no gathering, no reorder, no early write ack)
///   0b1111 = Normal, Outer Write-Back Cacheable, Inner Write-Back Cacheable
///            (MemAttr[3:2]=0b11 → Outer WB, MemAttr[1:0]=0b11 → Inner WB)
///
/// ARM DDI 0487, search "Stage 2 permissions":
///   S2AP 0b01 = read-only, 0b11 = read/write.
///
/// SH[1:0] (bits[9:8]) is fixed at 0b11 (Inner Shareable) for all variants.
/// ARM DDI 0487, "Stage 2 Shareability attributes": 0b11 = Inner Shareable.
/// All 4 Cortex-A72 cores share a single Inner Shareable domain.
/// AF (bit[10]) is always 1 — pre-set access flag avoids AF faults on first access.
/// ARM DDI 0487, search "The Access flag".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S2Prot {
    /// Normal-WB, read-only, execute-never.
    /// Usage: watchdog page as seen by ManagementVM (RO observer).
    Ro,
    /// Normal-WB, read/write, execute-never.
    /// Usage: guest RAM (non-executable data), IPC page (both VMs), watchdog
    ///        page for HftEngineVM (RW heartbeat writer).
    Rw,
    /// Normal-WB, read-only, execute permitted (XN=0).
    /// Usage: guest code pages (read-only + executable text section).
    RoX,
    /// Device-nGnRnE, read/write, execute-never.
    /// Usage: MMIO passthrough (UART, NIC, GIC).
    Device,
}

impl S2Prot {
    /// MemAttr[3:0] field value (bits[5:2] of the descriptor).
    ///
    /// ARM DDI 0487, search "Stage 2 memory type and Cacheability attributes when FWB is disabled":
    /// Normal WB: MemAttr[3:2]=0b11 (Outer WB), MemAttr[1:0]=0b11 (Inner WB) → 0b1111.
    /// Device-nGnRnE: MemAttr[3:2]=0b00 (device), MemAttr[1:0]=0b00 (nGnRnE) → 0b0000.
    #[inline]
    pub const fn memattr(self) -> u64 {
        match self {
            S2Prot::Ro | S2Prot::Rw | S2Prot::RoX => 0b1111,
            S2Prot::Device => 0b0000,
        }
    }

    /// S2AP[1:0] field value (bits[7:6] of the descriptor).
    ///
    /// ARM DDI 0487, search "Stage 2 permissions":
    /// 0b01 = read-only, 0b11 = read/write.
    #[inline]
    pub const fn s2ap(self) -> u64 {
        match self {
            S2Prot::Ro | S2Prot::RoX => 0b01,
            S2Prot::Rw | S2Prot::Device => 0b11,
        }
    }

    /// XN bit value (bit[54] of the descriptor).
    ///
    /// 0 = execute permitted (EL1 + EL0), 1 = execute-never at all ELs.
    #[inline]
    pub const fn xn(self) -> u64 {
        match self {
            S2Prot::RoX => 0,
            _ => 1,
        }
    }

    /// Assemble the lower attribute bits (bits[10:2]) for a Stage-2 descriptor.
    ///
    /// Bit layout:
    ///   bits[5:2]  = MemAttr[3:0]
    ///   bits[7:6]  = S2AP[1:0]
    ///   bits[9:8]  = SH[1:0] = 0b11 (Inner Shareable — fixed for all variants)
    ///   bit[10]    = AF = 1 (Access Flag pre-set — avoids AF fault on first access)
    ///
    /// Does NOT include bits[1:0] (descriptor type) or bit[54] (XN).
    /// Callers combine: `lower_attr_bits() | type_bits | (oa & OA_MASK) | xn_bit()`.
    #[inline]
    pub const fn lower_attr_bits(self) -> u64 {
        (self.memattr() << 2) | (self.s2ap() << 6) | (0b11u64 << 8) | (1u64 << 10)
    }

    /// XN bit positioned at bit[54] of the descriptor.
    #[inline]
    pub const fn xn_bit(self) -> u64 {
        self.xn() << 54
    }
}

// ── VTCR_EL2 Initialisation ───────────────────────────────────────────────────

/// VTCR_EL2 value used by this hypervisor.
///
/// Field breakdown (ARM DDI 0487, search "VTCR_EL2"):
/// ```text
///   bit[31]   RES1          = 1          → 0x80000000
///   bits[5:0] T0SZ          = 32         → 0x00000020  (IPA size = 2^(64-32) = 4 GiB)
///   bits[7:6] SL0           = 0b01       → 0x00000040  (walk starts at Level 1)
///   bits[9:8] IRGN0         = 0b01       → 0x00000100  (inner WB-RA-WA)
///   bits[11:10] ORGN0       = 0b01       → 0x00000400  (outer WB-RA-WA)
///   bits[13:12] SH0         = 0b11       → 0x00003000  (inner shareable)
///   bits[15:14] TG0         = 0b00       → 0x00000000  (4 KiB granule)
///   bits[18:16] PS          = 0b010      → 0x00020000  (40-bit PA space)
///   Sum                                  = 0x80023560
/// ```
///
/// Note: SL0=01 with T0SZ=32 and 4 KiB granule → walk starts at Level 1.
/// This gives a 2-level walk (L1→L2 for 2 MiB blocks, L1→L2→L3 for 4 KiB pages).
const VTCR_EL2_VAL: u64 = 0x80023560;

/// Initialise VTCR_EL2 — the Stage-2 translation control register.
///
/// Must be called **once** from the Management core (CPU 0) before any VM entry.
/// Subsequent ERET instructions to EL1 will use this configuration for Stage-2
/// address translation.
///
/// # Verification
/// Reads back VTCR_EL2 after writing and logs:
/// ```
/// [s2  ] VTCR_EL2 = 0x80023560  PS=010 SL0=01 T0SZ=32
/// ```
///
/// # Safety
/// Must be called from EL2. No concurrent write to VTCR_EL2 on any core.
/// An ISB after the MSR ensures the new value is visible to subsequent
/// translation table walks. ARM DDI 0487, search "VTCR_EL2".
pub unsafe fn init_vtcr_el2() {
    unsafe {
        core::arch::asm!(
            "msr vtcr_el2, {val}",
            "isb",
            val = in(reg) VTCR_EL2_VAL,
            options(nostack, nomem),
        );
    }

    // Read back to confirm the hardware accepted the value.
    let readback: u64;
    unsafe {
        core::arch::asm!(
            "mrs {val}, vtcr_el2",
            val = out(reg) readback,
            options(nostack, nomem),
        );
    }

    // Decode key fields for log confirmation.
    let ps = (readback >> 16) & 0x7; // bits[18:16]
    let sl0 = (readback >> 6) & 0x3; // bits[7:6]
    let t0sz = readback & 0x3f; // bits[5:0]

    writeln!(
        &mut &UART,
        "[s2  ] VTCR_EL2 = {:#010x}  PS={:03b} SL0={:02b} T0SZ={}",
        readback, ps, sl0, t0sz
    )
    .ok();
}

// ── Stage-2 Root Table Allocation ─────────────────────────────────────────────

/// Allocate and zero-initialise a 4 KiB Stage-2 L1 table.
///
/// The returned PA is used as the base address in `VTTBR_EL2[47:12]`.
/// All 512 entries are zeroed (descriptor bits[1:0]=0b00 = INVALID) so
/// that unmapped IPAs cause a Stage-2 translation fault rather than
/// following stale or garbage descriptors.
///
/// # Returns
/// Host PA of the newly-allocated, zeroed L1 table page.
///
/// # Panics
/// Panics if the PMM is out of memory.
///
/// # Safety
/// `pmm::init()` must have been called. No concurrent PMM access.
/// After return, the caller owns the page and must write VTTBR_EL2 before
/// any ERET to a guest that should use this table.
pub unsafe fn alloc_stage2_root() -> usize {
    let pa = unsafe { pmm::alloc(0) }.expect("[s2  ] FATAL: PMM OOM allocating stage2 root");

    // Zero all 512 entries (4096 bytes).  INVALID descriptor (bits[1:0]=0b00)
    // ensures unmapped IPAs cause a Stage-2 Translation Fault (EC=0x24) to EL2
    // rather than following garbage descriptors.
    //
    // SAFETY: `pa` points to a freshly-allocated, page-aligned physical page.
    // Identity-mapped Stage-1 VA=PA, so this VA is valid.
    unsafe {
        write_bytes(pa as *mut u8, 0, pmm::PAGE_SIZE);
    }

    pa
}
