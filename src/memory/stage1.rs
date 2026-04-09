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
//    L2_A[64]  0x0800_0000 + 2 MiB  Device-nGnRnE  RW+NX  (GICv2 GICD + GICC MMIO)
//    L2_A[72]  0x0900_0000 + 2 MiB  Device-nGnRnE  RW+NX  (UART MMIO)
//
//  L1 entry 1 → L2_B (covers 0x4000_0000..0x8000_0000)
//    L2_B[0..511]  0x4000_0000..0x8000_0000  Normal-WB  RW+NX  (all RAM, W^X on kernel)
//    HFT pages are scattered through this range via page coloring — no fixed sub-region.
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
    memory::{GICD_BASE, RAM_START, UART_MMIO_BASE, pmm},
    uart::UART,
};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

/// Physical address of the L1 translation table.
/// Written by CPU 0 in `build_page_tables()` and read by secondary cores
/// in `enable_mmu_secondary()` to reuse the same shared tables.
static L1_TABLE_PA: AtomicU64 = AtomicU64::new(0);

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

/// bits [7:6]: AP[2:1] = 0b11 → EL2 Read-Only.
/// Bit 6 (AP[1]) = 1 (RES1), bit 7 (AP[2]) = 1 means Read-Only.
/// Any write attempt from EL2 triggers a Permission Fault, enforcing W^X.
/// ARM DDI 0487, search "VMSAv8-64 Block and Page descriptors".
const DESC_AP_RO_EL2: u64 = 0b11 << 6;

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

/// L2 BLOCK entry: Normal WB-Cached, EL2 **Read-Only**, Executable.
/// Used exclusively for the kernel `.text` + `.rodata` 2 MiB block
/// (`KERNEL_TEXT_BASE = 0x4020_0000`).  Hardware enforces W^X: any
/// data write from EL2 into this block fires a Permission Fault.
/// ARM DDI 0487 search "Stage 1 Block and page descriptor".
#[inline(always)]
fn block_normal_ro_x(pa: usize) -> u64 {
    let pa_bits = (pa as u64) & 0x0000_FFFF_FFE0_0000; // PA[47:21]
    DESC_BLOCK
        | DESC_AF
        | DESC_AP_RO_EL2  // RO — write attempt → Permission Fault
        | DESC_SH_INNER
        // DESC_XN intentionally absent — code must be executable
        | attr_idx(ATTR_NORMAL_WB)
        | pa_bits
}

/// L2 BLOCK entry: Normal WB-Cached, EL2 **Read-Only**, **Execute-Never**.
/// Used exclusively for the kernel `.rodata` 2 MiB block
/// (`KERNEL_RODATA_BASE = 0x4040_0000`).  Completes the full W^X invariant:
/// no page is simultaneously writable and executable, AND no data page is
/// executable.  Hardware: AP=RO prevents writes, XN prevents instruction fetch.
/// ARM DDI 0487 search "VMSAv8-64 Block descriptor and Page descriptor formats".
#[inline(always)]
fn block_normal_ro_nx(pa: usize) -> u64 {
    let pa_bits = (pa as u64) & 0x0000_FFFF_FFE0_0000; // PA[47:21]
    DESC_BLOCK
        | DESC_AF
        | DESC_AP_RO_EL2  // RO — write attempt → Permission Fault
        | DESC_SH_INNER
        | DESC_XN         // NX — execute attempt → Permission Fault
        | attr_idx(ATTR_NORMAL_WB)
        | pa_bits
}

/// L2 BLOCK entry: Normal WB-Cached, EL2 Read-Write, **Execute-Never**.
/// Used for all RAM except the kernel `.text` block: DTB region, kernel
/// `.data`/`.bss`, boot stack, and the PMM heap.  W^X: prevents any
/// dynamically-allocated or mutable memory from being executed as code.
#[inline(always)]
fn block_normal_rw_nx(pa: usize) -> u64 {
    let pa_bits = (pa as u64) & 0x0000_FFFF_FFE0_0000; // PA[47:21]
    DESC_BLOCK
        | DESC_AF
        | DESC_AP_RW_EL2
        | DESC_SH_INNER
        | DESC_XN         // NX — execute attempt → Permission Fault
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
/// * Called after `pmm::init()` and `cache_color::init_hft_pool()`.
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

    // ── 4. L2_A: Device MMIO → Device-nGnRnE ───────────────────────────────
    //
    // GICv2 GICD base: 0x0800_0000 → L2_A index (0x0800_0000 >> 21) & 0x1FF = 64.
    // GICC base: 0x0801_0000 — within the same 2 MiB block [0x0800_0000, 0x0820_0000).
    // One Device-nGnRnE 2 MiB block covers both GICD and GICC.
    let gic_block_base = GICD_BASE & !(BLOCK_2MIB - 1); // 2 MiB-align down → 0x0800_0000
    l2a[l2_index(gic_block_base)] = block_device_rw_nx(gic_block_base);

    // UART is at 0x0900_0000. Within the 0..1 GiB L2_A region:
    // PL011 UART base: 0x0900_0000 → L2_A index (0x0900_0000 >> 21) & 0x1FF = 72.
    // The whole 2 MiB block [0x0900_0000, 0x0920_0000) is mapped as Device.
    let uart_block_base = UART_MMIO_BASE & !(BLOCK_2MIB - 1); // 2 MiB-align down
    l2a[l2_index(uart_block_base)] = block_device_rw_nx(uart_block_base);

    // ── 5. L2_B: General RAM → W^X-enforced mapping (dynamic, from linker symbols) ──
    //
    // We read the actual section start addresses from linker-exported symbols
    // at runtime, then align them DOWN to the 2 MiB block boundary.  This means
    // the mapping is correct regardless of how large each section grows — no
    // hardcoded PA constants that could silently become wrong.
    //
    // Symbol layout (set by linker ALIGN(2M) between sections):
    //   __text_start   → always 2 MiB-aligned (= BASE_ADDRESS = 0x4020_0000 today)
    //   __rodata_start → next 2 MiB boundary after .text
    //   __data_start   → next 2 MiB boundary after .rodata
    //
    // Safety: These are read-only linker symbols; value is the symbol address.
    // `as *const u8 as usize` is the standard no_std idiom for extracting the
    // numeric value of a linker symbol without dereferencing it.
    unsafe extern "C" {
        static __text_start: u8;
        static __rodata_start: u8;
        static __data_start: u8;
    }
    let text_block = unsafe { &__text_start as *const u8 as usize } & !(BLOCK_2MIB - 1);
    let rodata_block = unsafe { &__rodata_start as *const u8 as usize } & !(BLOCK_2MIB - 1);
    let data_block = unsafe { &__data_start as *const u8 as usize } & !(BLOCK_2MIB - 1);

    // ── 6. L2_B: all RAM → Normal-WB huge pages, W^X enforced ──────────────────
    //
    // 512 × 2 MiB Block entries (indices 0..511 covering 0x4000_0000..0x8000_0000).
    // HFT pages are color-filtered at allocation time (cache_color module) and
    // scattered through this range — no separate fixed sub-region needed.
    let mut pa = RAM_START;
    while pa < RAM_END {
        let desc = if pa >= text_block && pa < rodata_block {
            // .text block(s): Read-Only, Executable (W^X)
            block_normal_ro_x(pa)
        } else if pa >= rodata_block && pa < data_block {
            // .rodata block(s): Read-Only, Execute-Never (W^X)
            block_normal_ro_nx(pa)
        } else {
            // DTB / .data / .bss / PMM heap / HFT pages (scattered): RW+NX
            block_normal_rw_nx(pa)
        };
        l2b[l2_index(pa)] = desc;
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
        "[mmu ]   L2_B@ {:#010x}  DTB    idx {:3}       PA {:#010x}..{:#010x}  Normal-WB  RW+NX",
        l2b_pa,
        l2_index(RAM_START),
        RAM_START,
        text_block,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mmu ]   L2_B@ {:#010x}  TEXT   idx {:3}..{:3}  PA {:#010x}..{:#010x}  Normal-WB  RO+X  ← W^X",
        l2b_pa, l2_index(text_block), l2_index(rodata_block) - 1,
        text_block, rodata_block,
    ).ok();
    writeln!(
        &mut &UART,
        "[mmu ]   L2_B@ {:#010x}  RODATA idx {:3}..{:3}  PA {:#010x}..{:#010x}  Normal-WB  RO+NX ← W^X",
        l2b_pa, l2_index(rodata_block), l2_index(data_block) - 1,
        rodata_block, data_block,
    ).ok();
    writeln!(
        &mut &UART,
        "[mmu ]   L2_B@ {:#010x}  DATA   idx {:3}..{:3}  PA {:#010x}..{:#010x}  Normal-WB  RW+NX",
        l2b_pa,
        l2_index(data_block),
        l2_index(RAM_END - BLOCK_2MIB),
        data_block,
        RAM_END,
    )
    .ok();

    // Store l1_pa so secondary cores can reuse the same table.
    L1_TABLE_PA.store(l1_pa as u64, Ordering::Release);

    l1_pa
}

// ── MMU activation ────────────────────────────────────────────────────────────

/// Enable the EL2 Stage-1 MMU.
///
/// Configures `TCR_EL2` and `TTBR0_EL2`, then sets `SCTLR_EL2.M = 1`
/// with the mandatory barrier sequence from ARM DDI 0487.
///
/// # Arguments
/// * `l1_pa` — Physical address of the L1 translation table, as returned by
///             `build_page_tables()`.
///
/// # Safety
/// * `build_page_tables()` must have been called before this.
/// * `VBAR_EL2` must be installed before this call so that any translation
///   fault during activation has a handler registered.
/// * Must be called from EL2 only, on the boot core, before other cores start.
/// * UART MMIO, kernel code, and stack must all be identity-mapped (VA=PA) in
///   the tables at `l1_pa`. The first instruction after the final `ISB`
///   executes under the live MMU.
pub unsafe fn enable_mmu(l1_pa: usize) {
    // ── TCR_EL2 ──────────────────────────────────────────────────────────────
    // ARM DDI 0487, search "TCR_EL2 registers"
    // DS=0 (48-bit output address; our highest PA is 0x8000_0000 < 40-bit).
    //
    // Field   Bits    Value   Meaning
    // ------  ------  ------  -------------------------------------------------
    // T0SZ    [5:0]   32      VA space = 2^(64-32) = 4 GiB  (VA[31:0])
    // IRGN0   [9:8]   0b01    Inner Write-Back, Read/Write-Allocate
    // ORGN0   [11:10] 0b01    Outer Write-Back, Read/Write-Allocate
    // SH0     [13:12] 0b11    Inner Shareable
    // TG0     [15:14] 0b00    4 KiB granule
    // PS      [18:16] 0b010   40-bit Physical Address (1 TiB)
    //                         Minimum PS covering our highest PA 0x8000_0000.
    let tcr: u64 = 32              // T0SZ
        | (0b01  << 8)             // IRGN0 = Inner WB-RA-WA
        | (0b01  << 10)            // ORGN0 = Outer WB-RA-WA
        | (0b11  << 12)            // SH0   = Inner Shareable
        | (0b00  << 14)            // TG0   = 4 KiB granule
        | (0b010 << 16); // PS    = 40-bit PA

    // ── SCTLR_EL2 ────────────────────────────────────────────────────────────
    // Written from scratch — never read-modify-write (reset state is UNKNOWN).
    // ARM DDI 0487, search "SCTLR_EL2 registers"
    //
    // Bit   Name   Value   Meaning
    // ---   ----   -----   ----------------------------------------------------
    //  0    M      1       Enable Stage-1 MMU.
    //  2    C      1       Data cache enable (WB-Cached MAIR slots now active).
    //  3    SA     1       Stack-pointer alignment check.
    // 12    I      1       Instruction cache enable.
    // 19    WXN    1       Write implies XN — hardware W^X enforcement.
    //                      Defence-in-depth: even if a future page-table entry
    //                      accidentally sets RW+X, hardware blocks execution.
    const SCTLR_M: u64 = 1 << 0;
    const SCTLR_C: u64 = 1 << 2;
    const SCTLR_SA: u64 = 1 << 3;
    const SCTLR_I: u64 = 1 << 12;
    const SCTLR_WXN: u64 = 1 << 19;
    let sctlr: u64 = SCTLR_M | SCTLR_C | SCTLR_SA | SCTLR_I | SCTLR_WXN;

    // ── Barrier-sequenced activation ─────────────────────────────────────────
    //  References: Learn the architecture - AArch64 memory management Guide
    //
    //  1. TLBI ALLE2 — Invalidate all EL2 TLB entries on this core.
    //  2. DSB ISH    — Ensure TLB invalidation completes.
    //  3. IC IALLU   — Invalidate all EL2 Instruction Cache lines on this core.
    //  4. DSB ISH    — Ensure I-Cache invalidation completes.
    //  5. ISB        — Flush pipeline.
    //  6. Write TCR_EL2 + TTBR0_EL2.
    //  7. DSB ISH    — Drain page-table writes so the Table Walk Unit sees them.
    //  8. ISB        — Flush pipeline; TCR/TTBR visible before MMU enable.
    //  9. Write SCTLR_EL2 with M=1 (+ C, I, WXN).
    // 10. ISB        — MMU live; subsequent fetches are translated.
    //
    // Safety: UART, stack, and kernel .text are identity-mapped (VA=PA),
    // so the translated PC after Step 9 resolves to the same physical address.
    unsafe {
        core::arch::asm!(
            "tlbi alle2",              // Step 1: invalidate TLBs
            "dsb  ish",                // Step 2: wait for TLB invalidation
            "ic   iallu",              // Step 3: invalidate I-cache
            "dsb  ish",                // Step 4: wait for I-cache invalidation
            "isb",                     // Step 5: flush pipeline
            "msr tcr_el2,    {tcr}",   // Step 6a: translation control
            "msr ttbr0_el2,  {l1pa}",  // Step 6b: L1 table base address
            "dsb ish",                 // Step 7:  drain page-table stores
            "isb",                     // Step 8:  flush pipeline
            "msr sctlr_el2,  {sctlr}", // Step 9:  enable MMU + caches + WXN
            "isb",                     // Step 10: MMU live
            tcr   = in(reg) tcr,
            l1pa  = in(reg) l1_pa as u64,
            sctlr = in(reg) sctlr,
            options(nostack),
        );
    }
}

// ── Secondary-core MMU activation ─────────────────────────────────────────────

/// Activate the Stage-1 MMU on a secondary (HFT) core.
///
/// CPU 0 has already built the page tables and stored the L1 physical address
/// in `TTBR0_EL2`.  Secondary cores share the **same** identity-mapped tables,
/// so we just need to write the same `TCR_EL2` / `TTBR0_EL2` values and set
/// `SCTLR_EL2.M = 1`.
///
/// The L1 physical address is read back from the static variable written by
/// `build_page_tables()` via a shared atomic.
///
/// # Safety
/// * Must be called after `VBAR_EL2` is installed on this core.
/// * CPU 0 must have completed `build_page_tables()` before this is called.
/// * Must be called from EL2 on a secondary core.
pub unsafe fn enable_mmu_secondary() {
    // Read the L1 table physical address stored by CPU 0.
    let l1_pa = L1_TABLE_PA.load(core::sync::atomic::Ordering::Acquire);

    // Structural Assertion: CPU 0 must have written this before waking us.
    if l1_pa == 0 {
        panic!("CRITICAL BUG: L1_TABLE_PA not set by CPU 0 before waking secondaries!");
    }

    // Same TCR_EL2 as CPU 0 (constants, not runtime-derived).
    let tcr: u64 = 32
        | (0b01 << 8)    // IRGN0 = Inner WB-RA-WA
        | (0b01 << 10)   // ORGN0 = Outer WB-RA-WA
        | (0b11 << 12)   // SH0   = Inner Shareable
        | (0b00 << 14)   // TG0   = 4 KiB granule
        | (0b010 << 16); // PS    = 40-bit PA

    // Same SCTLR_EL2 as CPU 0: MMU + D-cache + I-cache + SA + WXN.
    const SCTLR_M: u64 = 1 << 0;
    const SCTLR_C: u64 = 1 << 2;
    const SCTLR_SA: u64 = 1 << 3;
    const SCTLR_I: u64 = 1 << 12;
    const SCTLR_WXN: u64 = 1 << 19;
    let sctlr: u64 = SCTLR_M | SCTLR_C | SCTLR_SA | SCTLR_I | SCTLR_WXN;

    // PSCI firmware may leave stale EL2 TLB entries on secondary cores.
    // Invalidate before loading our page tables to prevent stale translations.
    //
    //  1. TLBI ALLE2 — Invalidate all EL2 TLB entries on this core.
    //  2. DSB ISH    — Ensure TLB invalidation completes.
    //  3. IC IALLU   — Invalidate all EL2 Instruction Cache lines on this core.
    //  4. DSB ISH    — Ensure I-Cache invalidation completes.
    //  5. ISB        — Flush pipeline.
    //  6. Write TCR_EL2 + TTBR0_EL2.
    //  7. DSB ISH    — Drain page-table writes so Table Walk Unit sees them.
    //  8. ISB        — Flush pipeline; TCR/TTBR visible before MMU enable.
    //  9. Write SCTLR_EL2 with M=1 (+ C, I, WXN).
    // 10. ISB        — MMU live.
    unsafe {
        core::arch::asm!(
            "tlbi alle2",              // Step 1: invalidate EL2 TLB on this core
            "dsb  ish",                // Step 2: wait for TLB invalidation
            "ic   iallu",              // Step 3: invalidate I-cache
            "dsb  ish",                // Step 4: wait for I-cache invalidation
            "isb",                     // Step 5: flush pipeline
            "msr tcr_el2,    {tcr}",   // Step 6a: translation control
            "msr ttbr0_el2,  {l1pa}",  // Step 6b: L1 table base address
            "dsb ish",                 // Step 7:  drain page-table stores
            "isb",                     // Step 8:  flush pipeline
            "msr sctlr_el2,  {sctlr}", // Step 9:  enable MMU + caches + WXN
            "isb",                     // Step 10: MMU live
            tcr   = in(reg) tcr,
            l1pa  = in(reg) l1_pa,
            sctlr = in(reg) sctlr,
            options(nostack),
        );
    }
}
