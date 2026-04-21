// ============================================================================
// vm/ram.rs — Guest RAM allocation & Stage-2 mapping
//
// Walks each guest VM's entire IPA window, pulling pages from its pre-colored
// allocator and installing them in the VM's Stage-2 translation table.
//
// STANDING RULE — every guest-RAM mapping must use `stage2_map_4k`, NOT
// `stage2_map_2m`.  Page coloring scatters the 16 color classes at 64 KiB
// stride (color(PA) = (PA / 4096) % 16 — see `memory/cache_color.rs`), so any
// 2 MiB block inevitably spans 512 pages drawn from all 16 colors.  Using a
// 2 MiB block descriptor would therefore pull Management-colored pages (8–15)
// into the HFT VM's address space (or vice-versa), erasing the L2-set
// separation that the whole coloring scheme relies on.  The per-page L3 PAGE
// descriptor is the only mapping grain that preserves coloring.
//
// CACHE-VISIBILITY DISCIPLINE — the guest enters with MMU off initially
// (`SCTLR_EL1.M = 0`).  With our boot
// `HCR_EL2 = 0x80080001` (DC = 0), the ARM defines the Stage-1 output for
// an MMU-off EL1&0 regime as Normal, Outer Shareable, Inner Non-cacheable,
// Outer Non-cacheable.  A Non-cacheable read bypasses the inner-shareable
// cache entirely and reads DRAM directly.  The hypervisor's
// `write_bytes(pa, 0, 4096)` only dirties the cache — the zero bytes are not
// yet in DRAM — so a fresh guest would read stale bytes and the "zero before
// mapping for security" promise would be broken.
//
// Fix: immediately after each `write_bytes`, clean+invalidate the 4 KiB page
// to the Point of Coherency with `DC CIVAC`, then close the whole pass with a
// single `DSB ISH` before returning.  This matches Linux KVM's own pattern:
// `dcache_clean_inval_poc` is invoked before every cacheable Stage-2 PTE
// installation in `arch/arm64/kvm/hyp/pgtable.c`.  The cost is ~14 ms at
// boot for 32 768 pages × 64 cache-line ops (Cortex-A72) — boot-time only,
// no impact on the HFT trading hot path.
//
// The implementation covers HftEngineVM only.  ManagementVM RAM is handled by
// `alloc_mgmt_ram()` (TODO) and reuses the same helper.
//
// References (search keywords — document version-independent):
//   ARM DDI 0487 — search "Stage 2 permissions"
//   ARM DDI 0487 — search "VMSAv8-64 translation using the 4KB granule"
//   ARM DDI 0406 — search "Access permissions for instruction execution"
//   ARM DDI 0487 — search "The Access flag"
//   ARM DDI 0487 — search "DC CIVAC"
//   ARM DDI 0487 — search "About cache maintenance in AArch64 state"
//   ARM DDI 0487 — search "DSB" and "General TLB maintenance requirements"
//   ARM DDI 0601 — search "HCR_EL2" (Stage-1 output type when DC = 0 and
//                                       SCTLR_EL1.M = 0)
//   torvalds/linux, arch/arm64/kvm/hyp/pgtable.c — `dcache_clean_inval_poc`
//     called before Stage-2 PTE install for cacheable mappings.
//   torvalds/linux, arch/arm64/kvm/mmu.c         — user_mem_abort / Stage-2 RW default.
//   xen.git,       xen/arch/arm/p2m.c            — p2m_set_entry (RW guest RAM).
// ============================================================================

#![allow(dead_code)] // Public API consumed by later implementation; suppress until then.

use core::fmt::Write;
use core::ptr::write_bytes;

use crate::memory::cache_color;
use crate::memory::pmm::PAGE_SIZE;
use crate::uart::UART;
use crate::vm::hft_vm;
use crate::vm::stage2::{S2Prot, stage2_map_4k};

// ── Cache maintenance helper ──────────────────────────────────────────────────

/// Cortex-A72 cache-line granule.  From the BCM2711 Cortex-A72 MPCore TRM:
/// `CTR_EL0.DminLine = 4` → `1 << 4` 4-byte words = **64 bytes**.
/// Hardcoded here because this module is A72-specific (the whole coloring
/// design targets A72).  When/if porting to Cortex-A76 or Neoverse N2, read
/// `CTR_EL0.DminLine` at boot and parameterise instead.
const CACHE_LINE: usize = 64;

/// Clean+invalidate one 4 KiB page to the Point of Coherency.
///
/// Issues `DC CIVAC` for every 64-byte cache line in the page (64 ops total)
/// but does **not** issue `DSB ISH` — callers batch a single `dsb ish` at the
/// end of the full allocation pass so we do not pay one barrier per page.
///
/// The page's zero bytes are written back to DRAM and the hypervisor's local
/// cache lines are dropped.  A subsequent MMU-off guest read
/// (Normal Non-cacheable) therefore observes the zeros rather than stale
/// DRAM residue from whatever tenant previously held this physical frame.
///
/// # Safety
/// - `pa` must be 4 KiB-aligned.
/// - `pa` must be identity-mapped in Stage-1 as Normal-WB so the VA `pa` is a
///   valid operand for cache maintenance.
/// - Caller must issue `dsb ish` (reads-and-writes scope — NOT `ishst`) before
///   any observer reads the page with the expectation of seeing the zeros.
///
/// # References
/// ARM DDI 0487 — search "DC CIVAC"
/// ARM DDI 0487 — search "About cache maintenance in AArch64 state"
/// torvalds/linux, arch/arm64/kvm/hyp/pgtable.c — `dcache_clean_inval_poc`
#[inline]
unsafe fn clean_inval_page_to_poc(pa: usize) {
    let mut off = 0;
    while off < PAGE_SIZE {
        unsafe {
            core::arch::asm!(
                "dc civac, {a}",
                a = in(reg) (pa + off),
                options(nostack, preserves_flags),
            );
        }
        off += CACHE_LINE;
    }
}

/// Allocate and Stage-2-map all guest RAM for the HftEngineVM.
///
/// For every IPA in `[ipa_base, ipa_base + ipa_size)` at 4 KiB stride
/// (128 MiB = 32 768 pages):
///
/// 1. Pull the next pre-allocated colored page from `HFT_POOL_PAGES` via
///    `cache_color::hft_pool_alloc_page()` (O(1) bump index, no list
///    traversal — see the design note in `memory/cache_color.rs`).
/// 2. `debug_assert!` the returned PA is in the HFT color class (colors 0–7).
///    Defence-in-depth — catches a future coloring regression that would
///    silently contaminate HFT L2 sets with Management-colored pages.
///    Compiles out in release builds.
/// 3. Zero the 4 KiB page, then `DC CIVAC` every cache line in the page to
///    flush the zeros out of the inner-shareable cache down to DRAM.  Pages
///    in the pool were previously free blocks in the buddy allocator and
///    still carry intrusive FreeBlock pointers plus any earlier boot residue;
///    leaking that content into a guest address space would be an
///    information-disclosure bug.  Simply caching the zeros is not enough:
///    Implementation of Minimal HFT Payload Loader(TODO) launches
///    the guest with `SCTLR_EL1.M = 0` and our `HCR_EL2.DC = 0`,
///    under which Stage-1 outputs Normal Non-cacheable —
///    so the guest reads DRAM directly and would miss the cached zeros.
/// 4. Install a Stage-2 L3 PAGE descriptor with `S2Prot::Rw` — Normal-WB
///    Inner-Shareable, S2AP=0b11, XN=1.  The executable `.text` range is
///    downgraded to `S2Prot::RoX` by the payload loader (TODO);
///    initial XN=1 blanket is intentional W^X discipline at Stage-2,
///    matching KVM/Xen default guest-RAM policy.
/// 5. Once the full pass is complete, issue a single `dsb ish` (reads-and-
///    writes scope — `ishst` does **not** synchronise cache-maintenance ops
///    per ARM DDI 0487 "DSB") so that every `DC CIVAC` above has retired and
///    every zero byte is visible in DRAM before `alloc_hft_ram` returns.
///    VM-Entry's(TODO) `enter_vm()` would sync eventually, but establishing the
///    post-condition locally keeps the function's contract self-contained.
///
/// # Call-order invariant
/// `init_stage2()` must have populated `hft_vm().stage2_root` beforehand.
/// A 0 root would direct every descriptor write into physical page 0,
/// silently corrupting whatever lives there; the `assert!` at the top
/// catches this before any damage is done.
///
/// # UART log
/// ```text
/// [vm  ] HFT RAM: IPA=0x40000000 first_PA=0x........ (128 MiB, 32768 pages, colors 0-7)
/// ```
///
/// # Safety
/// - `pmm::init()`, `cache_color::init_hft_pool()`, `vm::init_vms()`, and
///   `vm::stage2::init_stage2()` must all have completed.
/// - Must be called exactly once, from the Management core (CPU 0), before
///   any VM entry.  Single-core boot — no concurrent access to `HFT_VM` or
///   the HFT page pool.
///
/// # Barriers
/// Two concerns coexist:
/// - *Descriptor visibility*: each `stage2_map_4k` call issues `dsb ishst`
///   after its descriptor write.  VM-Entry's(TODO) `enter_vm()` additionally does
///   `dsb ish ; tlbi vmalls12e1is ; dsb ish ; isb` before activating
///   VTTBR_EL2 — that is the architectural sync point.
/// - *Cache-maintenance completion*: `DC CIVAC` requires a DSB of reads-and-
///   writes scope to be observed as retired (ARM DDI 0487 "DSB").
///   `dsb ishst` (stores-only) inside `stage2_map_4k` is **not** sufficient.
///   A single `dsb ish` at the end of this function batches the completion
///   barrier for all 32 768 cache-maintenance ops issued above.
pub unsafe fn alloc_hft_ram() {
    let vm = unsafe { hft_vm() };

    // Call-order guard: `init_stage2()` must have run so that
    // `stage2_map_4k(root, ...)` writes descriptors into the correct L1 root.
    assert!(
        vm.stage2_root != 0,
        "[vm  ] alloc_hft_ram: stage2_root=0 — init_stage2() must run first"
    );

    let root = vm.stage2_root;
    let ipa_base = vm.ipa_base;
    let num_pages = vm.ipa_size / PAGE_SIZE;

    // Snapshot the first PA for the boot log.  Not used for mapping decisions.
    let mut first_pa: usize = 0;

    for i in 0..num_pages {
        let pa = unsafe { cache_color::hft_pool_alloc_page() }
            .expect("[vm  ] alloc_hft_ram: HFT page pool exhausted before all pages mapped");

        if i == 0 {
            first_pa = pa;
        }

        // HFT color range is colors 0..NUM_COLORS/2 (= 0..8). spec:
        // `debug_assert!(color_of(pa) < 8)`.
        debug_assert!(
            cache_color::color_of(pa) < (cache_color::NUM_COLORS / 2) as u8,
            "[vm  ] alloc_hft_ram: pool returned non-HFT color page PA={:#010x} color={}",
            pa,
            cache_color::color_of(pa),
        );

        // Stage-1 identity map makes `pa` a valid VA for this write.
        // SAFETY: `pa` is a freshly-allocated, page-aligned physical page
        // owned by this allocator; no other CPU touches it during boot.
        unsafe {
            write_bytes(pa as *mut u8, 0, PAGE_SIZE);
            // Push the zeros out of the inner-shareable cache to DRAM so a
            // guest reading with MMU off (Normal Non-cacheable under
            // HCR_EL2.DC=0) sees the zeros, not stale bytes.  Batched
            // `dsb ish` after the loop synchronises all DC CIVAC ops.
            clean_inval_page_to_poc(pa);
        }

        // SAFETY: `root` is a PMM-allocated zeroed L1 table PA returned by
        // `alloc_stage2_root()`; ipa/pa are both 4 KiB-aligned by construction.
        unsafe {
            stage2_map_4k(root, ipa_base + i * PAGE_SIZE, pa, S2Prot::Rw);
        }
    }

    // Drain every `DC CIVAC` issued above.  `dsb ish` uses the default
    // reads-and-writes access type — required by ARM DDI 0487 "DSB" to
    // synchronise cache-maintenance instructions.  The `dsb ishst` inside
    // `stage2_map_4k` is stores-only and does **not** cover cache ops.
    // ARM DDI 0487, search "DSB" and "General TLB maintenance requirements".
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
    }

    writeln!(
        &mut &UART,
        "[vm  ] HFT RAM: IPA={:#010x} first_PA={:#010x} ({} MiB, {} pages, colors 0-{})",
        ipa_base,
        first_pa,
        (num_pages * PAGE_SIZE) / (1024 * 1024),
        num_pages,
        (cache_color::NUM_COLORS / 2) - 1,
    )
    .ok();
}
