// ============================================================================
// memory/stage1.rs — EL2 Stage-1 Page Table Construction (2-level)
//
// Builds the hypervisor's EL2 Stage-1 address-space translation table.
// The MMU is OFF at this point; enable_mmu() (NEXT) flips it on.
//
// ── Architecture (T0SZ=32, 4KB granule, 2-level walk) ────────────────────────
//
//  With T0SZ=32 and 4KB granule the hardware starts its walk at Level 1.
//  ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule"
//    • Starting level : L1
//    • L1 entry covers: 2^30 = 1 GiB  (TABLE → L2, or 1 GiB Block)
//    • L2 entry covers: 2^21 = 2 MiB  (Block or PAGE → L3)
//    • L1 index       : VA[31:30] — bits above the 1 GiB boundaries
//
//  Our physical memory crosses the 1 GiB boundary (UART at 0x09xx, RAM
//  at 0x4000_0000), so we need TWO L1 TABLE entries, each pointing to a
//  separate L2 page, rather than a single flat list of 2 MiB blocks.
//
// ── Memory map ───────────────────────────────────────────────────────────────
//
//  L1 entry 0 → L2_A (covers 0x0000_0000..0x4000_0000)
//    L2_A[72]  0x0900_0000 + 2 MiB  Device-nGnRnE  RW+NX  (UART MMIO)
//
//  L1 entry 1 → L2_B (covers 0x4000_0000..0x8000_0000)
//    L2_B[0..447]  0x4000_0000..0x7800_0000  Normal-WB  RW+NX  (general RAM)
//    L2_B[448..511] 0x7800_0000..0x8000_0000  Normal-WB  RW+NX  (HFT 2 MiB huge)
//
// ── Resources ────────────────────────────────────────────────────────────────
//  PMM allocations: 3 × Order-0 pages (12 KiB total)
//    • l1_pa  — L1 table
//    • l2a_pa — L2 table for the 0..1 GiB device/low region
//    • l2b_pa — L2 table for the 1..2 GiB RAM region
//
// References:
//   ARM DDI 0487, search "VMSAv8-64 table descriptor format"
// ============================================================================

use crate::{
    memory::{HFT_RESERVED_BASE, HFT_RESERVED_END, RAM_START, UART_MMIO_BASE, pmm},
    uart::UART,
};
use core::fmt::Write;

// ── Sizes ─────────────────────────────────────────────────────────────────────

/// 512 entries × 8 bytes = one 4 KiB page — size of every translation table.
const TABLE_ENTRIES: usize = 512;

/// 2 MiB: size covered by one L2 Block Descriptor.               
/// ARM DDI 0487, search "Translation using the 4kb granule"
const BLOCK_2MIB: usize = 2 * 1024 * 1024;

// ── Bit-field constants ────────────────────────────────────────────────────────
// 64-bit Stage-1 Block/Page descriptor layout
// ARM DDI 0487 search keyword: "Translation table descriptor formats"
//
//  [63]    : ignored
//  [54]    : XN  — Execute Never (EL2 Stage-1 = single-privilege regime)
//  [53]    : RES0 — (PXN in EL1&0 two-privilege regime; RES0 for EL2/nVHE)
//             ARM DDI 0487, search "Stage 1 Block and page descriptor", EL2 regime table.
//  [47:m]  : Output Address  (m=30 for L1 block, m=21 for L2 block)
//  [11]    : RES0 — (nG in two-privilege regimes; RES0 for EL2/nVHE single-privilege)
//  [10]    : AF  — Access Flag   (must be 1 — set by software at boot)
//  [9:8]   : SH[1:0] — Shareability (0b11 = Inner Shareable)
//  [7:6]   : AP[2:1] — Access Permissions (Bit 6 is RES1, Bit 7 is 0 for EL2 R/W)
//  [4:2]   : AttrIdx[2:0] — 3-bit index into MAIR_EL2
//  [1:0]   : 0b11 = Table / 0b01 = Block / 0b00 = Invalid

/// bits [1:0] = 0b11 → TABLE descriptor (L1 → L2).
const DESC_TABLE: u64 = 0b11;

/// bits [1:0] = 0b01 → BLOCK descriptor (L2, 2 MiB).
const DESC_BLOCK: u64 = 0b01;

/// bit [10]: AF = Access Flag.
/// Must be 1; otherwise Access Flag Fault fires on first access.
/// ARM DDI 0487, search "The Access flag"
const DESC_AF: u64 = 1 << 10;

/// bits [7:6]: AP[2:1] = 0b01 → EL2 Read/Write.
/// In EL2 single-privilege regime, bit 6 (AP[1]) is RES1.
/// Bit 7 (AP[2]) = 0 means Read/Write.
/// ARM DDI 0487, search "VMSAv8-64 Block and Page descriptors".
const DESC_AP_RW_EL2: u64 = 0b01 << 6;

/// bits [9:8]: SH[1:0] = 0b11 → Inner Shareable.
/// Required for Normal-WB-Cached pages so all cores see coherent data.
/// Linux: PTE_SHARED = 3 << 8. Must NOT be set for Device memory.
/// ARM DDI 0487, search "Stage 1 Shareability attributes".
const DESC_SH_INNER: u64 = 0b11 << 8;

/// bit [54]: XN (Execute Never) — block may not be executed at EL2.
///
/// In the EL2 Stage-1 single-privilege translation regime (nVHE, HCR_EL2.E2H=0)
/// bit 54 is named XN and bit 53 is RES0. The EL1&0 names UXN(54)/PXN(53)
/// only apply in the two-privilege EL1&0 or VHE (E2H=1) regimes.
/// ARM DDI 0487, search "Stage 1 Block and page descriptor".
const DESC_XN: u64 = 1 << 54;

/// bits [4:2]: AttrIdx — 3-bit index into MAIR_EL2.
/// ARM DDI 0487, search "Stage 1 memory type and Cacheability attributes".
#[inline(always)]
const fn attr_idx(idx: u64) -> u64 {
    idx << 2
}

/// MAIR_EL2 Slot 0 = Normal WB-Cached (set by cpu::init_mair_el2).
const ATTR_NORMAL_WB: u64 = 0;

/// MAIR_EL2 Slot 1 = Device-nGnRnE (set by cpu::init_mair_el2).
const ATTR_DEVICE: u64 = 1;

// ── Index helpers ─────────────────────────────────────────────────────────────

/// L1 table index for a virtual address (T0SZ=32, 4KB granule).
/// VA[31:30] → 2 bits, selects one of 4 possible 1 GiB regions.
/// ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule".
#[inline(always)]
const fn l1_index(va: usize) -> usize {
    (va >> 30) & 0x1FF // bits [31:30]
}

/// L2 table index within a 1 GiB L1 region (T0SZ=32, 4KB granule).
/// VA[29:21] → 9 bits, selects one of 512 possible 2 MiB blocks.
/// ARM DDI 0487, search "VMSAv8-64 translation using the 4KB granule".
#[inline(always)]
const fn l2_index(va: usize) -> usize {
    (va >> 21) & 0x1FF // bits [29:21]
}

// ── Descriptor builders ───────────────────────────────────────────────────────

/// L1 TABLE entry pointing to the physical address of an L2 table page.
/// PA[47:12] is the physical page address of the next-level table.
/// No access/memory attributes here — those come from the final L2 block entry.
#[inline(always)]
fn l1_table_entry(l2_pa: usize) -> u64 {
    let pa_bits = (l2_pa as u64) & 0x0000_FFFF_FFFF_F000; // PA[47:12]
    DESC_TABLE | pa_bits
}

/// L2 BLOCK entry: Normal WB-Cached, EL2 RW, Execute-Never.
/// Used for general RAM and the HFT reserved slab.
/// PA[47:21] is the physical 2 MiB-aligned base address.
#[inline(always)]
fn block_normal_rw_nx(pa: usize) -> u64 {
    let pa_bits = (pa as u64) & 0x0000_FFFF_FFE0_0000; // PA[47:21]
    DESC_BLOCK
        | DESC_AF
        | DESC_AP_RW_EL2
        | DESC_SH_INNER
        | DESC_XN
        | attr_idx(ATTR_NORMAL_WB)
        | pa_bits
}

/// L2 BLOCK entry: Device-nGnRnE, EL2 RW, Execute-Never.
/// Used for UART MMIO and future NIC MMIO.
/// ARM DDI 0487, search "Stage 1 Shareability attributes": Device memory has an effective Shareability attribute of Outer Shareable.
/// We intentionally omit DESC_SH_INNER (leaving SH[9:8] as 0) because hardware ignores these bits.
#[inline(always)]
fn block_device_rw_nx(pa: usize) -> u64 {
    let pa_bits = (pa as u64) & 0x0000_FFFF_FFE0_0000; // PA[47:21]
    DESC_BLOCK | DESC_AF | DESC_AP_RW_EL2 | DESC_XN | attr_idx(ATTR_DEVICE) | pa_bits
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Build the EL2 Stage-1 two-level page tables and return the physical
/// address of the L1 table (to be stored in `TTBR0_EL2`).
///
/// Allocates 3 × Order-0 pages from the global PMM:
///   1. L1 table   (512 × 8 bytes, only 2 entries used)
///   2. L2_A table (covers 0x0000_0000..0x4000_0000 — UART region)
///   3. L2_B table (covers 0x4000_0000..0x8000_0000 — all RAM + HFT)
///
/// # Safety
/// * Called after `pmm::init()` and `pmm::prewarm_hft_region()`.
/// * Called before `enable_mmu()` (NEXT).
/// * Single-core early boot only.
pub unsafe fn build_page_tables() -> usize {
    // ── Compile-time layout invariants ───────────────────────────────────────
    // These assert that the two-level table structure is consistent with the
    // actual constants in memory::mod.  If any constant changes such that
    // UART and RAM end up in the same 1 GiB region (same L1 index), the
    // build will fail with a clear message before any hardware is touched.
    use crate::memory::{RAM_END, UART_MMIO_END};
    const _: () = {
        assert!(
            UART_MMIO_BASE >> 30 == 0,
            "UART must be in L1[0] (below 1 GiB); update build_page_tables if layout changes"
        );
        assert!(
            RAM_START >> 30 == 1,
            "RAM_START must be in L1[1] (1..2 GiB range); update build_page_tables if layout changes"
        );
        assert!(
            RAM_END >> 30 == 2,
            "RAM_END must not exceed L1[1] (must be <= 2 GiB)"
        );
        assert!(
            UART_MMIO_END <= (1 << 30),
            "UART MMIO region must stay within the first 1 GiB (L2_A range)"
        );
    };

    // ── 1. Allocate three 4 KiB pages ───────────────────────────────────────
    // Safety: PMM is initialised; alloc(0) returns a 4KiB-aligned address.
    let l1_pa = unsafe { pmm::alloc(0) }.expect("stage1: OOM — L1 table");
    let l2a_pa = unsafe { pmm::alloc(0) }.expect("stage1: OOM — L2_A table");
    let l2b_pa = unsafe { pmm::alloc(0) }.expect("stage1: OOM — L2_B table");

    // ── 2. Zero all three pages (Invalid descriptor = 0x0) ──────────────────
    // Safety: each address is owned, PAGE_SIZE-aligned, and PAGE_SIZE bytes.
    unsafe {
        core::ptr::write_bytes(l1_pa as *mut u8, 0, pmm::PAGE_SIZE);
        core::ptr::write_bytes(l2a_pa as *mut u8, 0, pmm::PAGE_SIZE);
        core::ptr::write_bytes(l2b_pa as *mut u8, 0, pmm::PAGE_SIZE);
    }

    // Reinterpret each page as a mutable array of 512 u64 descriptors.
    // Safety: 4KiB alignment ≥ u64's 8-byte requirement; we own all three pages.
    let l1 = unsafe { &mut *(l1_pa as *mut [u64; TABLE_ENTRIES]) };
    let l2a = unsafe { &mut *(l2a_pa as *mut [u64; TABLE_ENTRIES]) };
    let l2b = unsafe { &mut *(l2b_pa as *mut [u64; TABLE_ENTRIES]) };

    // ── 3. L1 → TABLE entries pointing to L2 tables ─────────────────────────
    //
    // With T0SZ=32 and 4KB granule, VA[31:30] selects the L1 entry:
    //   VA 0x0000_0000..0x4000_0000  → L1[0] → L2_A (device/low region)
    //   VA 0x4000_0000..0x8000_0000  → L1[1] → L2_B (RAM region)
    //
    // Safety: UART_MMIO_BASE [0x09..] has L1 index 0; RAM_START [0x40..] has index 1.
    l1[l1_index(UART_MMIO_BASE)] = l1_table_entry(l2a_pa); // index 0
    l1[l1_index(RAM_START)] = l1_table_entry(l2b_pa); // index 1

    // ── 4. L2_A: UART MMIO → Device-nGnRnE ─────────────────────────────────
    //
    // UART is at 0x0900_0000. Within the 0..1 GiB L2_A region:
    //   l2_index(0x0900_0000) = (0x0900_0000 >> 21) & 0x1FF = 72
    // The whole 2 MiB block [0x0900_0000, 0x0B00_0000) is mapped as Device.
    let uart_block_base = UART_MMIO_BASE & !(BLOCK_2MIB - 1); // 2 MiB-align down
    l2a[l2_index(uart_block_base)] = block_device_rw_nx(uart_block_base);

    // ── 5. L2_B: General RAM → Normal-WB (0x4000_0000..0x7800_0000) ─────────
    //
    // Within the 1..2 GiB L2_B region:
    //   l2_index(0x4000_0000) = (0x4000_0000 >> 21) & 0x1FF = 0x200 & 0x1FF = 0
    // Each entry maps one 2 MiB block; entries 0..447 cover 896 MiB of RAM.
    let mut pa = RAM_START;
    while pa < HFT_RESERVED_BASE {
        l2b[l2_index(pa)] = block_normal_rw_nx(pa);
        pa += BLOCK_2MIB;
    }

    // ── 6. L2_B: HFT reserved region → Normal-WB huge pages ─────────────────
    //
    // 64 × 2 MiB Block entries (indices 448..511).
    // Identical attribute to general RAM, but identified separately in the log
    // to document the HFT huge-page intent.  Future MPAM / TLB-lock passes
    // will add further differentiation here.
    let mut pa = HFT_RESERVED_BASE;
    while pa < HFT_RESERVED_END {
        l2b[l2_index(pa)] = block_normal_rw_nx(pa);
        pa += BLOCK_2MIB;
    }

    // ── 7. UART diagnostic log ───────────────────────────────────────────────
    writeln!(
        &mut &UART,
        "\r\n[mmu ] Stage-1 page tables built (2-level, T0SZ=32, 4KB granule)",
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mmu ]   L1  @ {:#010x}  (L1[0]→L2_A, L1[1]→L2_B)",
        l1_pa,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mmu ]   L2_A@ {:#010x}  UART idx {:3}  PA {:#010x}  Device-nGnRnE  RW+NX",
        l2a_pa,
        l2_index(uart_block_base),
        uart_block_base,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mmu ]   L2_B@ {:#010x}  RAM  idx {:3}..{:3}  PA {:#010x}..{:#010x}  Normal-WB  RW+NX",
        l2b_pa,
        l2_index(RAM_START),
        l2_index(HFT_RESERVED_BASE) - 1,
        RAM_START,
        HFT_RESERVED_BASE,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mmu ]   L2_B@ {:#010x}  HFT  idx {:3}..{:3}  PA {:#010x}..{:#010x}  Normal-WB  RW+NX  2MiB-huge",
        l2b_pa,
        l2_index(HFT_RESERVED_BASE),
        l2_index(HFT_RESERVED_END - BLOCK_2MIB),
        HFT_RESERVED_BASE,
        HFT_RESERVED_END,
    ).ok();

    l1_pa
}
