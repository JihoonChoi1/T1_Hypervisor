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

// ── Descriptor type bits ───────────────────────────────────────────────────────

/// L1 / L2 TABLE descriptor: bits[1:0] = 0b11.
/// Points to the next-level translation table.
/// ARM DDI 0487, search "Translation table descriptor formats".
const DESC_TABLE: u64 = 0b11;

/// L2 BLOCK descriptor: bits[1:0] = 0b01.
/// Leaf mapping of a 2 MiB region (4 KiB granule, walk starting at L1).
/// ARM DDI 0487, search "Translation table descriptor formats".
const DESC_BLOCK: u64 = 0b01;

/// L3 PAGE descriptor: bits[1:0] = 0b11.
///
/// At L3 the encoding 0b11 means a 4 KiB leaf page, not a table pointer.
/// The same bit pattern 0b11 at L1/L2 would be a TABLE; the distinction is
/// purely by level.  Using a separate constant makes call-sites self-documenting.
///
/// ARM DDI 0487, search "Translation table descriptor formats":
const DESC_PAGE: u64 = 0b11;

// ── Stage-2 2 MiB block mapping ───────────────────────────────────────────────

/// Map a single 2 MiB IPA→PA block in a Stage-2 two-level walk table.
///
/// Walk for T0SZ=32, SL0=01, 4 KiB granule (VTCR_EL2 = 0x80023560):
///   L1 table (root): indexed by `ipa[31:30]` → 4 entries covering 0–4 GiB.
///   L2 table:        indexed by `ipa[29:21]` → 512 entries × 2 MiB = 1 GiB.
///
/// If the L1 entry for `ipa[31:30]` is zero (no L2 table yet), a new L2
/// page is allocated from the PMM, zeroed, and a TABLE descriptor is written
/// into the L1 slot.
///
/// # Safety
/// - `root` must be a valid PMM-allocated, zeroed 4 KiB L1 table page (PA).
/// - `ipa` and `pa` must be 2 MiB-aligned (`assert!` panics otherwise).
/// - No concurrent access to the same table entries.
/// - Stage-1 identity-map must be active (VA=PA) so physical addresses are
///   valid virtual addresses for pointer writes.
///
/// # Barrier
/// Issues `dsb ishst` after all descriptor writes to ensure visibility to
/// translation-table-walk hardware on all Cortex-A72 cores (Inner Shareable
/// domain) before the table is activated via VTTBR_EL2.
/// Linux KVM uses the same barrier sequence:
///   torvalds/linux, arch/arm64/kvm/hyp/pgtable.c — `dsb(ishst)` after stage-2 table writes.
///
/// # References
/// ARM DDI 0487, search "VMSAv8-64 Table descriptor formats"
/// ARM DDI 0487, search "VMSAv8-64 Block descriptor and Page descriptor formats"
/// ARM DDI 0487, search "Stage 2 permissions"
/// ARM DDI 0487, search "Stage 2 memory type and Cacheability attributes when FWB is disabled"
/// ARM DDI 0487, search "The Access flag"
/// torvalds/linux, arch/arm64/kvm/hyp/pgtable.c — Stage-2 block descriptor assembly
pub unsafe fn stage2_map_2m(root: usize, ipa: usize, pa: usize, prot: S2Prot) {
    const MB2: usize = 2 * 1024 * 1024;
    assert!(
        ipa & (MB2 - 1) == 0,
        "[s2  ] stage2_map_2m: ipa {:#x} not 2 MiB-aligned",
        ipa
    );
    assert!(
        pa & (MB2 - 1) == 0,
        "[s2  ] stage2_map_2m: pa {:#x} not 2 MiB-aligned",
        pa
    );

    // ── L1 walk ──────────────────────────────────────────────────────────────
    // L1 index = ipa[31:30].  With T0SZ=32 the IPA space is exactly 4 GiB,
    // so the L1 table has 4 entries (indices 0–3).
    // ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule".
    let l1_idx = (ipa >> 30) & 0x3;
    let l1_entry_ptr = (root + l1_idx * 8) as *mut u64;

    // Ensure an L2 table exists for this 1 GiB slot.
    let l2_pa: usize = unsafe {
        let existing = l1_entry_ptr.read_volatile();
        if existing == 0 {
            // Allocate and zero a fresh L2 table (512 × 8 B = 4 KiB page).
            let new_l2 = pmm::alloc(0).expect("[s2  ] FATAL: PMM OOM allocating Stage-2 L2 table");
            write_bytes(new_l2 as *mut u8, 0, pmm::PAGE_SIZE);

            // Write L1 TABLE descriptor.
            // ARM DDI 0487, search "VMSAv8-64 table descriptor format":
            //   bits[1:0]   = 0b11 (table)
            //   bits[47:12] = next-level table PA[47:12]
            let l1_desc = (new_l2 as u64 & 0x0000_FFFF_FFFF_F000) | DESC_TABLE;
            l1_entry_ptr.write_volatile(l1_desc);

            new_l2
        } else {
            // Extract L2 table PA from existing TABLE descriptor bits[47:12].
            (existing & 0x0000_FFFF_FFFF_F000) as usize
        }
    };

    // ── L2 block write ───────────────────────────────────────────────────────
    // L2 index = ipa[29:21] (0–511 within the 1 GiB covered by this L2 table).
    let l2_idx = (ipa >> 21) & 0x1FF;
    let l2_entry_ptr = (l2_pa + l2_idx * 8) as *mut u64;

    // Build L2 BLOCK descriptor.
    // ARM DDI 0487, search "VMSAv8-64 block descriptor format":
    //   bits[1:0]   = 0b01          (block)
    //   bits[5:2]   = MemAttr[3:0]  (Normal-WB=0b1111 or Device=0b0000)
    //   bits[7:6]   = S2AP[1:0]     (RO=0b01, RW=0b11)
    //   bits[9:8]   = SH[1:0]=0b11  (Inner Shareable — fixed)
    //   bit[10]     = AF=1           (Access Flag pre-set; avoids AF fault)
    //   bits[47:21] = OA[47:21]      (2 MiB-aligned output address)
    //   bit[53]     = RES0           (FEAT_XNX not present on ARMv8.0-A)
    //   bit[54]     = XN             (0 = exec permitted, 1 = execute-never)
    //
    // `pa & !0x1F_FFFF` clears bits[20:0], keeping OA in bits[47:21].
    let oa = (pa as u64) & !0x1F_FFFFu64;
    let l2_desc = DESC_BLOCK | prot.lower_attr_bits() | oa | prot.xn_bit();
    unsafe {
        l2_entry_ptr.write_volatile(l2_desc);

        // DSB ISHST: data synchronisation barrier, stores only, Inner Shareable.
        // Ensures all descriptor writes above are visible to translation-table-walk
        // hardware on every Cortex-A72 core before VTTBR_EL2 is activated.
        // ARM DDI 0487, search "General TLB maintenance requirements":
        // "Write the new translation table entry, and execute a DSB instruction to ensure
        // that the new entry is visible."
        // Linux KVM reference: torvalds/linux, arch/arm64/kvm/hyp/pgtable.c, dsb(ishst).
        core::arch::asm!("dsb ishst", options(nostack, nomem));
    }
}

// ── Stage-2 range mapping (2 MiB steps) ───────────────────────────────────────

/// Map a contiguous IPA→PA range in 2 MiB steps using Stage-2 block descriptors.
///
/// Iterates over `size / 2MiB` steps, calling `stage2_map_2m` for each block.
///
/// # Panics
/// Panics if `ipa` or `pa` are not 2 MiB-aligned, or if `size` is not a
/// multiple of 2 MiB.
///
/// # Safety
/// Same requirements as `stage2_map_2m`: root must be a valid L1 table PA,
/// Stage-1 identity-map must be active.
///
/// # References
/// ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule"
pub unsafe fn stage2_map_range(root: usize, ipa: usize, pa: usize, size: usize, prot: S2Prot) {
    const MB2: usize = 2 * 1024 * 1024;

    assert!(
        ipa & (MB2 - 1) == 0,
        "[s2  ] stage2_map_range: ipa {:#x} not 2 MiB-aligned",
        ipa
    );
    assert!(
        pa & (MB2 - 1) == 0,
        "[s2  ] stage2_map_range: pa {:#x} not 2 MiB-aligned",
        pa
    );
    assert!(
        size % MB2 == 0,
        "[s2  ] stage2_map_range: size {:#x} not a multiple of 2 MiB",
        size
    );

    let steps = size / MB2;
    for i in 0..steps {
        unsafe {
            stage2_map_2m(root, ipa + i * MB2, pa + i * MB2, prot);
        }
    }
}

// ── Stage-2 4 KiB page mapping ────────────────────────────────────────────────

/// Map a single 4 KiB IPA→PA page in a Stage-2 three-level walk table.
///
/// Walk for T0SZ=32, SL0=01, 4 KiB granule (VTCR_EL2 = 0x80023560):
///
/// ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule":
///   L1 table (root): indexed by `ipa[31:30]` → 4 entries covering 0–4 GiB.
///   L2 table:        indexed by `ipa[29:21]` → 512 entries × 2 MiB = 1 GiB.
///   L3 table:        indexed by `ipa[20:12]` → 512 entries × 4 KiB = 2 MiB.
///
/// Descriptor type dispatch (ARM DDI 0487, search "Translation table descriptor formats"):
///   L1 entry bits[1:0] = 0b11 → TABLE (points to L2).
///   L2 entry bits[1:0] = 0b01 → BLOCK (2 MiB leaf — cannot coexist with 4 KiB
///                                        mappings in the same 2 MiB region → panic).
///   L2 entry bits[1:0] = 0b11 → TABLE (points to L3).
///   L3 entry bits[1:0] = 0b11 → PAGE  (4 KiB leaf — only valid leaf at L3).
///
/// # L3 PAGE descriptor bit layout
/// ARM DDI 0487, search "VMSAv8-64 table descriptor format":
/// ```text
///   bits[1:0]   = 0b11         page descriptor (valid + leaf at L3)
///   bits[5:2]   = MemAttr[3:0] memory type (Normal-WB=0b1111, Device=0b0000)
///   bits[7:6]   = S2AP[1:0]    stage-2 access permissions
///   bits[9:8]   = SH[1:0]=0b11 inner shareable (fixed)
///   bit[10]     = AF=1          access flag pre-set (avoids AF fault on first access)
///   bits[47:12] = OA[47:12]    4 KiB-aligned output address
///   bit[53]     = RES0          (FEAT_XNX not present on ARMv8.0-A)
///   bit[54]     = XN            execute-never
/// ```
///
/// # Panics
/// Panics if a L2 BLOCK descriptor already exists for the same 2 MiB region —
/// mixing 2 MiB blocks and 4 KiB pages in the same L2 slot is mutually exclusive in descriptor format.
///
/// # Safety
/// - `root` must be a valid PMM-allocated, zeroed 4 KiB L1 table page (PA).
/// - `ipa` and `pa` must be 4 KiB-aligned (`assert!` panics otherwise).
/// - No concurrent access to the same table entries.
/// - Stage-1 identity-map must be active (VA=PA).
///
/// # Barrier
/// Issues `dsb ishst` after the L3 descriptor write, matching the same
/// barrier used in `stage2_map_2m`.
/// Linux KVM reference: torvalds/linux, arch/arm64/kvm/hyp/pgtable.c — `dsb(ishst)`
/// after stage-2 table writes.
///
/// # References
/// ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule"
/// ARM DDI 0487, search "VMSAv8-64 Table descriptor formats"
/// ARM DDI 0487, search "VMSAv8-64 Block descriptor and Page descriptor formats"
/// ARM DDI 0487, search "Stage 2 permissions"
/// ARM DDI 0487, search "Stage 2 memory type and Cacheability attributes when FWB is disabled"
/// ARM DDI 0487, search "The Access flag"
/// torvalds/linux, arch/arm64/kvm/hyp/pgtable.c — stage2_map_walker
pub unsafe fn stage2_map_4k(root: usize, ipa: usize, pa: usize, prot: S2Prot) {
    const PAGE: usize = 4096;
    assert!(
        ipa & (PAGE - 1) == 0,
        "[s2  ] stage2_map_4k: ipa {:#x} not 4 KiB-aligned",
        ipa
    );
    assert!(
        pa & (PAGE - 1) == 0,
        "[s2  ] stage2_map_4k: pa {:#x} not 4 KiB-aligned",
        pa
    );

    // ── L1 walk ──────────────────────────────────────────────────────────────
    // L1 index = ipa[31:30].  T0SZ=32 gives exactly 4 GiB IPA space → 4 L1 entries.
    // ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule".
    let l1_idx = (ipa >> 30) & 0x3;
    let l1_entry_ptr = (root + l1_idx * 8) as *mut u64;

    let l2_pa: usize = unsafe {
        let existing = l1_entry_ptr.read_volatile();
        if existing == 0 {
            // No L2 table yet: allocate one, zero it, write L1 TABLE descriptor.
            let new_l2 =
                pmm::alloc(0).expect("[s2  ] FATAL: PMM OOM allocating Stage-2 L2 table (4k)");
            write_bytes(new_l2 as *mut u8, 0, pmm::PAGE_SIZE);

            // L1 TABLE descriptor: bits[1:0]=0b11, bits[47:12]=L2_PA[47:12].
            // ARM DDI 0487, search "VMSAv8-64 table descriptor format".
            let l1_desc = (new_l2 as u64 & 0x0000_FFFF_FFFF_F000) | DESC_TABLE;
            l1_entry_ptr.write_volatile(l1_desc);
            new_l2
        } else {
            // Reuse existing L2 table: extract PA from bits[47:12].
            (existing & 0x0000_FFFF_FFFF_F000) as usize
        }
    };

    // ── L2 walk ──────────────────────────────────────────────────────────────
    // L2 index = ipa[29:21] (0–511 within the 1 GiB region covered by this L2).
    let l2_idx = (ipa >> 21) & 0x1FF;
    let l2_entry_ptr = (l2_pa + l2_idx * 8) as *mut u64;

    let l3_pa: usize = unsafe {
        let existing = l2_entry_ptr.read_volatile();
        let desc_type = existing & 0x3;

        if existing == 0 {
            // No L3 table yet: allocate one, zero it, write L2 TABLE descriptor.
            let new_l3 =
                pmm::alloc(0).expect("[s2  ] FATAL: PMM OOM allocating Stage-2 L3 table (4k)");
            write_bytes(new_l3 as *mut u8, 0, pmm::PAGE_SIZE);

            // L2 TABLE descriptor: bits[1:0]=0b11, bits[47:12]=L3_PA[47:12].
            // ARM DDI 0487, search "VMSAv8-64 table descriptor format".
            let l2_desc = (new_l3 as u64 & 0x0000_FFFF_FFFF_F000) | DESC_TABLE;
            l2_entry_ptr.write_volatile(l2_desc);
            new_l3
        } else if desc_type == DESC_TABLE {
            // Existing L2 TABLE: reuse the L3 table it points to.
            (existing & 0x0000_FFFF_FFFF_F000) as usize
        } else {
            // desc_type == DESC_BLOCK (0b01) — architecturally forbidden to mix
            // 2 MiB blocks and 4 KiB pages within the same 2 MiB L2 slot.
            panic!(
                "[s2  ] stage2_map_4k: L2 BLOCK exists at ipa {:#x} — \
                 cannot mix 2 MiB block and 4 KiB page in the same 2 MiB region",
                ipa
            );
        }
    };

    // ── L3 page write ────────────────────────────────────────────────────────
    // L3 index = ipa[20:12] (0–511 within the 2 MiB region covered by this L3).
    // ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule".
    let l3_idx = (ipa >> 12) & 0x1FF;
    let l3_entry_ptr = (l3_pa + l3_idx * 8) as *mut u64;

    // Build L3 PAGE descriptor.
    // ARM DDI 0487, search "VMSAv8-64 Block descriptor and Page descriptor formats":
    //   bits[1:0]   = 0b11          (page — only valid leaf descriptor at L3)
    //   bits[5:2]   = MemAttr[3:0]  (Normal-WB=0b1111 or Device=0b0000)
    //   bits[7:6]   = S2AP[1:0]     (RO=0b01, RW=0b11)
    //   bits[9:8]   = SH[1:0]=0b11  (Inner Shareable — fixed)
    //   bit[10]     = AF=1           (Access Flag pre-set; avoids AF fault)
    //   bits[47:12] = OA[47:12]      (4 KiB-aligned output address)
    //   bit[53]     = RES0           (FEAT_XNX not present on ARMv8.0-A)
    //   bit[54]     = XN             (0 = exec permitted, 1 = execute-never)
    let oa = (pa as u64) & 0x0000_FFFF_FFFF_F000; // PA[47:12]
    let l3_desc = DESC_PAGE | prot.lower_attr_bits() | oa | prot.xn_bit();

    unsafe {
        l3_entry_ptr.write_volatile(l3_desc);

        // DSB ISHST: ensure the page descriptor is visible to translation-table-walk
        // hardware on all cores before VTTBR_EL2 activates this table.
        // ARM DDI 0487, search "General TLB maintenance requirements":
        // "Write the new translation table entry, and execute a DSB instruction to ensure
        // that the new entry is visible."
        // Linux KVM: torvalds/linux, arch/arm64/kvm/hyp/pgtable.c, dsb(ishst).
        core::arch::asm!("dsb ishst", options(nostack, nomem));
    }
}

// ── init_stage2() — per-VM Stage-2 orchestration ──────────────────
//
// Constructs one Stage-2 translation table per VM (ManagementVM, HftEngineVM)
// and installs its L1 root PA into the matching global `Vm` descriptor.
// Guest RAM mappings (IPA 0x4000_0000–) are deferred to Guest RAM Allocation.
//
// Shared-page IPA layout (fixed contract between both VMs and the host):
//
//   IPA 0x5000_0000  →  WatchdogPage   (Mgmt: RO,  HFT: RW — HFT writes heartbeat)
//   IPA 0x5000_1000  →  IpcPage        (Mgmt: RW,  HFT: RW — lock-free SPSC rings)
//   IPA 0x5000_2000  →  KillPage       (Mgmt: RW,  HFT: RO — HFT polls kill flag)
//
// The three shared pages are single 4 KiB pages,
// `stage2_map_4k` path is required (a 2 MiB block would expose 511 unrelated
// physical pages to both guests).
//
// MMIO passthrough uses `stage2_map_2m` — peripheral register banks are
// typically small (≤64 KiB) but the host has no reason to deny access to the
// rest of the 2 MiB window, and block descriptors consume one L2 slot vs.
// an entire L3 table.

/// IPA of the watchdog shared page (4 KiB). Same address in both VMs.
const IPA_WATCHDOG: usize = 0x5000_0000;
/// IPA of the IPC shared page (4 KiB). Same address in both VMs.
const IPA_IPC: usize = 0x5000_1000;
/// IPA of the killswitch shared page (4 KiB). Same address in both VMs.
const IPA_KILLSWITCH: usize = 0x5000_2000;

/// 2 MiB block containing the guest-visible PL011 UART passthrough.
///
/// QEMU virt: PL011 UART0 at PA 0x0900_0000 — already 2 MiB-aligned.
/// RPi4 BCM2711: PL011 UART0 at PA 0xFE20_1000 — containing 2 MiB block is
///               0xFE20_0000 (verified: 0xFE20_0000 & 0x1FFFFF == 0).
///               bcm2711.dtsi: `serial@7e201000` → ARM PA 0xFE20_1000.
#[cfg(not(feature = "rpi4"))]
const UART_MMIO_BLOCK: usize = 0x0900_0000;
#[cfg(feature = "rpi4")]
const UART_MMIO_BLOCK: usize = 0xFE20_0000;

/// 2 MiB block containing the BCM2711 Ethernet MAC register bank.
///
/// GENET MAC base = 0xFD58_0000 (bcm2711.dtsi `ethernet@7d580000`).
/// 0xFD58_0000 & 0x1FFFFF = 0x180000 ≠ 0 → not 2 MiB aligned.
/// Containing 2 MiB block = 0xFD40_0000 (maps 0xFD40_0000–0xFD5F_FFFF).
#[cfg(feature = "rpi4")]
const RPI4_GENET_MMIO_BLOCK: usize = 0xFD40_0000;

/// Build and install Stage-2 translation tables for both guest VMs.
///
/// Call order (from `main.rs` after `vm::init_vms()`):
///   1. Initialise VTCR_EL2 once.
///   2. Allocate + populate ManagementVM Stage-2 root; store in `MGMT_VM.stage2_root`.
///   3. Allocate + populate HftEngineVM Stage-2 root; store in `HFT_VM.stage2_root`.
///
/// The three shared-page PAs are supplied by the caller so that the
/// Mgmt-view (RO/RW/RW) and HFT-view (RW/RW/RO) of the same underlying
/// physical pages are installed with opposite S2AP values.
///
/// # Arguments
/// * `watchdog_pa`   — PA returned by `vm::watchdog::init_watchdog()`.
/// * `ipc_pa`        — PA returned by `vm::ipc::init_ipc()`.
/// * `killswitch_pa` — PA returned by `vm::killswitch::init_killswitch()`.
///
/// # Safety
/// - `pmm::init()`, `vm::init_vms()` and the three shared-page init functions
///   must have already run.
/// - Must be called exactly once, on the Management core, before any VM entry.
/// - No other core may access `MGMT_VM`/`HFT_VM` until this returns.
///
/// # Barriers
/// Each `stage2_map_2m` / `stage2_map_4k` call already issues `dsb ishst`
/// after its descriptor writes, so the tables are visible to translation-
/// table-walk hardware before this function returns. No additional ISB is
/// required here — VTTBR_EL2 is written by `enter_vm()` (TODO), which
/// performs its own DSB ISH / TLBI / ISB sequence.
///
/// # References
/// ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule"
pub unsafe fn init_stage2(watchdog_pa: usize, ipc_pa: usize, killswitch_pa: usize) {
    // Configure VTCR_EL2 once — shared by both VMs (VTCR is not VM-specific).
    unsafe { init_vtcr_el2() };

    // ── ManagementVM ──────────────────────────────────────────────────────
    //   UART passthrough : Mgmt owns the console.
    //   Watchdog RO      : Mgmt observes HFT heartbeat, never writes it.
    //   IPC RW           : Mgmt drains h2m channels and publishes m2h messages.
    //   Killswitch RW    : Mgmt sets halt/emergency flag and reason string.
    let mgmt_root = unsafe { alloc_stage2_root() };
    unsafe {
        stage2_map_2m(mgmt_root, UART_MMIO_BLOCK, UART_MMIO_BLOCK, S2Prot::Device);
        stage2_map_4k(mgmt_root, IPA_WATCHDOG, watchdog_pa, S2Prot::Ro);
        stage2_map_4k(mgmt_root, IPA_IPC, ipc_pa, S2Prot::Rw);
        stage2_map_4k(mgmt_root, IPA_KILLSWITCH, killswitch_pa, S2Prot::Rw);
        super::mgmt_vm().stage2_root = mgmt_root;
    }
    writeln!(
        &mut &UART,
        "[s2  ] ManagementVM  stage2_root={:#010x}",
        mgmt_root
    )
    .ok();

    // ── HftEngineVM ───────────────────────────────────────────────────────
    //   Watchdog RW      : HFT increments heartbeat every trading loop tick.
    //   IPC RW           : HFT writes to h2m[core_idx] and reads m2h (core 1 only).
    //   Killswitch RO    : HFT polls flag at loop head; must not forge state.
    //   GENET (RPi4)     : Polling-mode NIC passthrough; no IRQ routing.
    let hft_root = unsafe { alloc_stage2_root() };
    unsafe {
        stage2_map_4k(hft_root, IPA_WATCHDOG, watchdog_pa, S2Prot::Rw);
        stage2_map_4k(hft_root, IPA_IPC, ipc_pa, S2Prot::Rw);
        stage2_map_4k(hft_root, IPA_KILLSWITCH, killswitch_pa, S2Prot::Ro);

        #[cfg(feature = "rpi4")]
        stage2_map_2m(
            hft_root,
            RPI4_GENET_MMIO_BLOCK,
            RPI4_GENET_MMIO_BLOCK,
            S2Prot::Device,
        );

        super::hft_vm().stage2_root = hft_root;
    }
    writeln!(
        &mut &UART,
        "[s2  ] HftEngineVM   stage2_root={:#010x}",
        hft_root
    )
    .ok();
}
