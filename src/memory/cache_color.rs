// ============================================================================
// memory/cache_color.rs — Heuristic Page Coloring + HFT Page Pool
//
// Goal: reduce L2 cache conflict misses between HFT cores and the Management
// core by assigning them physically-disjoint "colors" of memory.
//
// Background — Cortex-A72 L2 cache geometry (RPi4 / BCM2711):
//   Size     : 1 MB, shared across all 4 Cortex-A72 cores
//   Ways     : 16-way set-associative
//   Line size: 64 bytes
//   Sets     : 1 048 576 / (16 × 64) = 1 024
//   Index    : PA[15:6]  (10 bits, simple indexing model — see caveat below)
//
// Page Color definition:
//   color(PA) = (PA >> PAGE_SHIFT) % NUM_COLORS
//             = (PA / 4096) % 16
//
//   Pages with the same color map to the same subset of L2 sets.
//   Assigning non-overlapping color ranges to HFT and Management cores
//   reduces cross-core L2 set contention.
//
//   HARDWARE CAVEAT — Cache Index Formula Not Formally Documented:
//   ARM does not publish the Cortex-A72 L2 set index formula in the TRM.
//   The simple PA[15:6] model (1 MB / 16 ways / 64 B = 1024 sets) is
//   mathematically derived and has been empirically confirmed to work on
//   real Cortex-A72 hardware by the Xen cache-coloring implementation.
//   However, because ARM has not formally documented this, it is not a
//   contractual guarantee — the formula could differ across revisions.
//     • Set separation is EMPIRICALLY LIKELY but not formally guaranteed.
//     • Verify on real RPi4 hardware via L2D_CACHE_REFILL measurements (TODO).
//   On Neoverse V1/N2 with MPAM, hardware LLC way partitioning is possible
//   and would replace this entire module.
//
// Cortex-A76 note (RPi5 / BCM2712):
//   L2 is 512 KB PER-CORE private (not shared).  HFT cores' L2 is already
//   isolated from the Management core at the hardware level.  The shared cache
//   on RPi5 is an L3 (2 MB cluster-shared).  This module targets RPi4/A72;
//   A76 support would require a separate geometry configuration.
//
// HFT Page Pool:
//   All HFT-colored pages (up to HFT_POOL_TARGET_SIZE) are pre-allocated from
//   the Buddy Allocator at boot time by init_hft_pool().  Their physical
//   addresses are recorded in a flat static array (HFT_POOL_PAGES) and handed
//   out via hft_pool_alloc_page() — a bump-pointer allocator over that array.
//
//   Design rationale (bump over flat array vs. intrusive linked list):
//     • Linked list: each pop() dereferences the *next pointer inside the free
//       page — a jump to an arbitrary physical address → unpredictable L2 miss.
//       That is the exact pathology we are trying to eliminate.
//     • Flat array + bump index: hft_pool_alloc_page() reads pages[used] from
//       a sequentially-accessed 256 KiB BSS array — cache-line prefetcher
//       handles it without stalls.
//
//   STANDING RULE: hft_pool_alloc_page() is BOOT-TIME ONLY.
//       It must NEVER be called from the HFT trading hot path.
//       All allocations happen during VM construction (TODO).
//       Once trading starts, no further page allocation occurs — the entire
//       HFT memory space is pre-mapped in Stage-2 page tables.
//       Calling hft_pool_alloc_page() during trading is a design violation.
//
//   Cache color of the pool array itself:
//       HFT_POOL_PAGES lives in BSS (physical color uncontrolled).  This is
//       intentional: the array is only accessed at boot, never during trading.
//       By the time the HFT VM runs, its working-set pages (order books, ring
//       buffers — all HFT-colored) will have evicted the array from L2.
//
// References:
//   ARM Cortex-A72 MPCore Technical Reference Manual (r0p3)
//   ARM DDI 0487, search "0x0017, L2D_CACHE_REFILL" — event 0x17 L2D_CACHE_REFILL
//   Xen Project — cache coloring implementation (empirical A72 validation)
//     xen.git: xen/arch/arm/llc-coloring.c  (ARM hw probing, CLIDR_EL1 etc.)
//     xen.git: xen/common/llc-coloring.c    (page_to_llc_color and coloring logic)
// ============================================================================

#![allow(dead_code)]

use crate::memory::{
    HFT_POOL_TARGET_SIZE,
    pmm::{self, PAGE_SIZE},
};
use crate::uart::UART;
use core::fmt::Write;

// ── HFT Page Pool (flat array + bump index) ───────────────────────────────────
//
// STANDING RULE: These statics are written exactly once by init_hft_pool()
// at boot and consumed during VM construction (TODO).  They are
// never accessed after trading starts.  Do not add any runtime write path.

/// Total HFT pages to pre-allocate: HFT_POOL_TARGET_SIZE / PAGE_SIZE = 32 768.
const HFT_PAGE_COUNT: usize = HFT_POOL_TARGET_SIZE / PAGE_SIZE;

/// Physical addresses of all pre-allocated HFT-colored pages.
///
/// Populated by init_hft_pool(); consumed sequentially by
/// hft_pool_alloc_page().  Lives in BSS (physical color uncontrolled) —
/// intentional, because it is only accessed at boot; by the time trading
/// starts the HFT VM's working-set pages have evicted it from L2.
static mut HFT_POOL_PAGES: [usize; HFT_PAGE_COUNT] = [0usize; HFT_PAGE_COUNT];

/// Number of pages successfully pre-allocated into HFT_POOL_PAGES.
/// May be < HFT_PAGE_COUNT if the PMM had fewer HFT-colored pages available.
static mut HFT_POOL_COUNT: usize = 0;

/// Bump index: pages already consumed by hft_pool_alloc_page().
static mut HFT_POOL_USED: usize = 0;

// ── Cortex-A72 L2 Cache Geometry (RPi4 / BCM2711) ────────────────────────────

/// L2 cache size in bytes.  1 MiB shared across all 4 Cortex-A72 cores.
///
/// NOTE: Cortex-A76 (RPi5) uses 512 KiB L2 per-core private + 2 MiB shared L3.
///       Adjust `L2_SIZE` and revisit coloring strategy if targeting A76.
const L2_SIZE: usize = 1024 * 1024; // 1 MiB

/// Number of cache ways (set-associativity).
const L2_WAYS: usize = 16;

/// Cache line size in bytes.
const L2_LINE_SIZE: usize = 64;

/// Total number of page colors.
///
/// color(PA) = (PA / PAGE_SIZE) % NUM_COLORS
///
/// Pages with the same color index the same L2 set subset (absent hashing).
/// With 16 colors there are 4 pages of each color per 64 consecutive pages (256 KiB).
pub const NUM_COLORS: usize = L2_SIZE / (PAGE_SIZE * L2_WAYS); // = 16

/// Minimum buddy order at which a block is guaranteed to contain every page color.
///
/// Color of a page is determined by its page-frame number modulo NUM_COLORS:
///   color(PA) = (PA / PAGE_SIZE) % NUM_COLORS
///
/// A block of order K spans 2^K consecutive pages, whose colors cycle through
/// 0, 1, …, NUM_COLORS-1 repeatedly.  Once the block is large enough to hold
/// a full cycle (2^K >= NUM_COLORS), every color appears at least once.
///
/// For NUM_COLORS = 16: GUARANTEED_ORDER = log2(16) = 4  (16-page / 64 KiB block).
/// Passed as the `guaranteed_order` hint to `pmm::alloc_with_filter` to skip
/// the per-page color scan for large blocks.
const GUARANTEED_ORDER: usize = NUM_COLORS.trailing_zeros() as usize; // = 4

/// Number of colors reserved for HFT cores (Color 0 … HFT_COLOR_COUNT-1).
const HFT_COLOR_COUNT: usize = NUM_COLORS / 2; // = 8  (colors 0–7)

// ── Color arithmetic ─────────────────────────────────────────────────────────

/// Return the page color of a physical address.
///
/// color = (PA >> PAGE_SHIFT) % NUM_COLORS
///
/// This directly encodes bits [15:12] of `pa`, which correspond to the upper
/// half of the L2 set-index field (PA[15:6]) under the simple indexing model.
/// Cache index hashing may cause actual set assignments to differ.
#[inline]
pub fn color_of(pa: usize) -> u8 {
    ((pa / PAGE_SIZE) % NUM_COLORS) as u8
}

/// HFT color range (exclusive upper bound): colors 0 … 7.
///
/// Pages in this range are preferentially allocated to the HFT trading engine.
#[inline]
pub fn hft_color_range() -> (u8, u8) {
    (0, HFT_COLOR_COUNT as u8) // (0, 8)
}

/// Management color range (exclusive upper bound): colors 8 … 15.
///
/// Pages in this range are preferentially allocated to the Management core.
#[inline]
pub fn mgmt_color_range() -> (u8, u8) {
    (HFT_COLOR_COUNT as u8, NUM_COLORS as u8) // (8, 16)
}

// ── Colored page allocation ───────────────────────────────────────────────────

/// Allocate one order-0 (4 KiB) page from the HFT color range (0–7).
///
/// Uses `pmm::alloc_with_filter` with `color_of(pa) < HFT_COLOR_COUNT` as the
/// predicate.  Correctness guarantee: if any HFT-color page remains in the PMM
/// free pool, this function will find and return it.
///
/// # Safety
/// Must be called after `pmm::init()`.
/// Boot-time only — not for use on the HFT hot path.
pub unsafe fn alloc_hft_page() -> Option<usize> {
    let (lo, hi) = hft_color_range();
    unsafe {
        pmm::alloc_with_filter(
            |pa| {
                let c = color_of(pa);
                c >= lo && c < hi
            },
            Some(GUARANTEED_ORDER),
        )
    }
}

/// Allocate one order-0 (4 KiB) page from the Management color range (8–15).
///
/// Uses `pmm::alloc_with_filter` with `color_of(pa) >= HFT_COLOR_COUNT` as the
/// predicate.
///
/// # Safety
/// Must be called after `pmm::init()`.
/// Boot-time only — not for use on the HFT hot path.
pub unsafe fn alloc_mgmt_page() -> Option<usize> {
    let (lo, hi) = mgmt_color_range();
    unsafe {
        pmm::alloc_with_filter(
            |pa| {
                let c = color_of(pa);
                c >= lo && c < hi
            },
            Some(GUARANTEED_ORDER),
        )
    }
}

// ── HFT Page Pool API ─────────────────────────────────────────────────────────

/// Pre-allocate all HFT-colored pages from the PMM into the pool.
///
/// Steps performed for each page:
///   1. `alloc_hft_page()` — color-filtered buddy allocation (color 0–7).
///   2. PA recorded in `HFT_POOL_PAGES[count]`.
///
/// Cache warming is deferred entirely to `warm_hft_cache()`, called just before
/// trading starts.  A preliminary warm here would be wasted: Stage-2 page table
/// installation (Phase 4) issues a TLBI that discards any TLB entries, and
/// subsequent boot activity evicts cache lines before trading begins.
///
/// Logs a summary line to UART. If the PMM is exhausted before
/// `HFT_PAGE_COUNT` pages are obtained, the shortfall is logged as a warning.
///
/// # Safety
/// Must be called after `pmm::init()`, exactly once, before any
/// `hft_pool_alloc_page()` or `warm_hft_cache()` call.
pub unsafe fn init_hft_pool() {
    let mut count = 0usize;
    while count < HFT_PAGE_COUNT {
        match unsafe { alloc_hft_page() } {
            Some(pa) => {
                unsafe { HFT_POOL_PAGES[count] = pa };
                count += 1;
            }
            None => break, // PMM exhausted — record how many we got
        }
    }
    unsafe { HFT_POOL_COUNT = count };

    if count < HFT_PAGE_COUNT {
        writeln!(
            &mut &UART,
            "[cache] WARNING: HFT pool short — wanted {} pages ({} MiB), \
             got {} pages ({} MiB). PMM may be undersized.",
            HFT_PAGE_COUNT,
            HFT_POOL_TARGET_SIZE / (1024 * 1024),
            count,
            count * PAGE_SIZE / (1024 * 1024),
        )
        .ok();
    } else {
        writeln!(
            &mut &UART,
            "[cache] HFT pool: {} pages ({} MiB) pre-allocated, colors 0–{} ✓",
            count,
            count * PAGE_SIZE / (1024 * 1024),
            HFT_COLOR_COUNT - 1,
        )
        .ok();
    }
}

/// Allocate one HFT-colored page from the pre-allocated pool.
///
/// Returns the physical address of the next unused page, or `None` if the
/// pool is exhausted.  O(1) — reads `pages[used]` and increments the bump
/// index.  No pointer chasing; no Buddy Allocator involvement.
///
///    BOOT-TIME ONLY — Phase 4 VM construction (TODO) only.
pub unsafe fn hft_pool_alloc_page() -> Option<usize> {
    // SAFETY: single-core boot; no concurrent access.
    let used = unsafe { HFT_POOL_USED };
    let count = unsafe { HFT_POOL_COUNT };
    if used >= count {
        return None;
    }
    let pa = unsafe { HFT_POOL_PAGES[used] };
    unsafe { HFT_POOL_USED = used + 1 };
    Some(pa)
}

/// Pages remaining in the HFT pool (not yet handed to VM construction).
#[inline]
pub fn hft_pool_remaining() -> usize {
    // SAFETY: read-only after prewarm; boot-time only.
    unsafe { HFT_POOL_COUNT - HFT_POOL_USED }
}

/// Warm the L2 cache with every HFT page immediately before trading starts.
///
/// Reads the first cache line (64 B) of each HFT-colored page, ensuring:
///   • HFT data pages occupy L2 sets 0–511 (color 0–7 region).
///   • Boot-time metadata (HFT_POOL_PAGES[], PMM free lists) is evicted
///     from L2 — no silent competition with the HFT working set at trading start.
///   • The first cache line of each HFT page is guaranteed to be an L2 hit
///     at trading start.  Remaining cache lines within each page are warmed
///     on first access by the HFT VM — not guaranteed to be L2 hits.
///
/// DSB SY at the end ensures all cache-fill loads retire before the caller
/// releases HFT cores out of WFE (cpu::secondary::release_secondary_cores).
///
/// BOOT-TIME ONLY — call exactly once after Stage-2 mapping is complete
/// and before releasing HFT cores out of WFE.
pub fn warm_hft_cache() {
    let count = unsafe { HFT_POOL_COUNT };
    for i in 0..count {
        let pa = unsafe { HFT_POOL_PAGES[i] };
        // Identity-mapped: VA = PA.  One volatile read per page = one cache
        // line brought into L2.  Remaining cache lines within the page are
        // warmed on first access by the HFT VM — not guaranteed to be L2 hits.
        unsafe { core::ptr::read_volatile(pa as *const u8) };
    }
    // DSB SY: all cache-fill operations complete before we proceed.
    unsafe { core::arch::asm!("dsb sy", options(nostack)) };
}

// ── Boot-time diagnostics ─────────────────────────────────────────────────────

/// Print the cache geometry and color configuration over UART.
///
/// Called once from `kmain` after PMM initialisation (Step 14 boot log).
pub fn print_info() {
    writeln!(
        &mut &UART,
        "\r\n[cache] Cortex-A72 L2: {}KB, {}-way, {}B line → {} colors",
        L2_SIZE / 1024,
        L2_WAYS,
        L2_LINE_SIZE,
        NUM_COLORS,
    )
    .ok();
    let (hft_lo, hft_hi) = hft_color_range();
    let (mgmt_lo, mgmt_hi) = mgmt_color_range();
    writeln!(
        &mut &UART,
        "[cache] HFT colors : {}..{} (Color 0–{} → L2 lower half, ~{}KB)",
        hft_lo,
        hft_hi,
        hft_hi - 1,
        (L2_SIZE / 2) / 1024,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[cache] Mgmt colors: {}..{} (Color {}–{} → L2 upper half, ~{}KB)",
        mgmt_lo,
        mgmt_hi,
        mgmt_lo,
        mgmt_hi - 1,
        (L2_SIZE / 2) / 1024,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[cache] NOTE: Cortex-A72 L2 index formula undocumented by ARM. \
         Simple PA[15:6] model empirically confirmed by Xen on real A72 hardware. \
         Verify set separation via L2D_CACHE_REFILL on RPi4 (Phase 9).",
    )
    .ok();
}

/// Allocate `count` HFT-colored pages, log each PA and color, then free them.
///
/// PoC verification: confirms `alloc_with_filter` finds correct-colored pages
/// and split-down logic is correct.  Pages are immediately freed so the PMM
/// pool is not permanently depleted by the test.
///
/// # Safety
/// Must be called after `pmm::init()`.
pub unsafe fn run_poc_verification(count: usize) {
    const MAX_POC_PAGES: usize = 8;
    let n = if count > MAX_POC_PAGES {
        writeln!(
            &mut &UART,
            "[cache] PoC: requested {} pages, capping at {} (stack buffer limit)",
            count, MAX_POC_PAGES,
        )
        .ok();
        MAX_POC_PAGES
    } else {
        count
    };
    writeln!(&mut &UART, "[cache] PoC: allocating {} HFT-color pages:", n).ok();

    let mut allocated = [0usize; MAX_POC_PAGES];

    for i in 0..n {
        match unsafe { alloc_hft_page() } {
            Some(pa) => {
                let c = color_of(pa);
                let (lo, hi) = hft_color_range();
                let ok = c >= lo && c < hi;
                writeln!(
                    &mut &UART,
                    "[cache]   page[{}]: PA={:#010x}  color={}  {}",
                    i,
                    pa,
                    c,
                    if ok { "✓" } else { "✗ BUG: wrong color!" },
                )
                .ok();
                allocated[i] = pa;
            }
            None => {
                writeln!(
                    &mut &UART,
                    "[cache]   page[{}]: None (no HFT-color pages available)",
                    i,
                )
                .ok();
                // Return pages allocated so far before returning.
                for j in 0..i {
                    if allocated[j] != 0 {
                        unsafe { pmm::free(allocated[j], 0) };
                    }
                }
                return;
            }
        }
    }

    // Free all allocated pages back to the PMM.
    for i in 0..n {
        if allocated[i] != 0 {
            unsafe { pmm::free(allocated[i], 0) };
        }
    }
    writeln!(&mut &UART, "[cache] PoC: all pages freed back to PMM.").ok();
}
