// ============================================================================
// vm/loader.rs — Minimal HFT Payload Loader
//
// Copies the pre-built `payload/hft_payload.bin` image into the HftEngineVM's
// guest RAM at IPA 0x4000_0000 and seeds `vcpus[0].regs` so that a future
// VM-Entry step can ERET into it at EL1.  This step performs NO VM entry —
// only the byte-level copy and register seed.
//
// ── Cache-visibility discipline ──────────────────────────────────────────────
// The guest boots with MMU off (`SCTLR_EL1.M = 0`) and the hypervisor runs
// with `HCR_EL2.DC = 0`.  Under that regime, stage-1 forces every EL1 data
// access to Device-nGnRnE and every instruction fetch to Normal Non-cacheable
// (ARM DDI 0487 — search "The effects of disabling an address translation stage").
// Whatever bytes we place in the EL2 Inner-Shareable cache are
// therefore invisible to the guest's first instruction fetch unless we flush
// them out to the Point of Coherency first.  The same trap motivated the
// post-zeroing `DC CIVAC` in `vm/ram.rs::alloc_hft_ram`; we reuse that
// module's `clean_inval_page_to_poc` helper so the two call sites share a
// single cache-maintenance contract.
//
// ── Barriers ─────────────────────────────────────────────────────────────────
// Per-page: `copy_nonoverlapping` → `clean_inval_page_to_poc` (no DSB yet).
// After the full copy loop: one `dsb ish` (reads-and-writes scope — `ishst`
// does NOT synchronise cache-maintenance instructions; ARM DDI 0487 —
// search "DSB").  No ISB is needed here because no subsequent EL2 instruction
// fetches from guest RAM — VM-Entry will perform its own `isb` before ERET.
//
// ── References ───────────────────────────────────────────────────────────────
//   ARM DDI 0487 — search "Behavior when stage 1 address translation is disabled"
//   ARM DDI 0487 — search "DC CIVAC"
//   ARM DDI 0487 — search "DSB"
//   ARM DDI 0487 — search "PSTATE fields that are meaningful in AArch64 state"
//   ARM DDI 0601 — search "SPSR_EL2, Saved Program Status Register (EL2)"
//   ARM DDI 0601 — search "SCTLR_EL1, System Control Register (EL1)"
//   torvalds/linux, arch/arm64/kvm/hyp/pgtable.c — `dcache_clean_inval_poc`
// ============================================================================

#![allow(dead_code)] // Public API consumed by VM-Entry step; suppress until then.

use core::fmt::Write;
use core::ptr::copy_nonoverlapping;

use crate::memory::pmm::PAGE_SIZE;
use crate::uart::UART;
use crate::vm::hft_vm;
use crate::vm::ram::clean_inval_page_to_poc;
use crate::vm::stage2;

// ── Payload image ────────────────────────────────────────────────────────────

/// The HFT guest payload, produced by `payload/build.sh` and committed at
/// `payload/hft_payload.bin`.  Embedded at compile time so a fresh `cargo
/// build` of the main kernel does not depend on an out-of-tree build step.
const PAYLOAD: &[u8] = include_bytes!("../../payload/hft_payload.bin");

// ── Guest boot state constants ───────────────────────────────────────────────

/// Guest stack pointer offset above `ipa_base`.  SP_EL1 = 0x4010_0000.
///
/// Leaves 1 MiB for the descending stack below SP and ~127 MiB of heap/BSS
/// above SP inside the HFT VM's 128 MiB IPA window.  The minimal heartbeat
/// payload never actually touches the stack (no function prologue in
/// `payload.s`) — this value exists so that any later guest build with a
/// real Rust stack frame already has a valid SP.
const GUEST_STACK_OFFSET: usize = 0x0010_0000;

/// Value written into the vCPU's `pstate` (→ SPSR_EL2) before VM entry.
///
/// Bit decomposition (ARM DDI 0487 — search "SPSR_EL2, Saved Program Status
/// Register (EL2)" and "AArch64 PSTATE"):
///   M[3:0] = 0b0101  → target EL1h (SP_EL1 selected)
///   M[4]   = 0       → AArch64 (nRW=0)
///   F      = 1       → FIQ masked
///   I      = 1       → IRQ masked
///   A      = 1       → SError masked
///   D      = 1       → Debug exceptions masked
/// DAIF is fully masked on entry; the guest unmasks selectively only after
/// its own vector table is installed.
const GUEST_SPSR_EL2_VAL: u64 = 0x3C5;

/// Value written into the vCPU's `sys.sctlr_el1` before VM entry.
///
/// ARM DDI 0487 — search "SCTLR_EL1, System Control Register (EL1)".
/// MMU (M), caches (C/I), write-permission-implies-execute-never (WXN),
/// alignment check (A), and endianness (EE, E0E) are all 0 — matching the
/// payload's MMU-off contract.  The non-zero bits combine (a) the complete
/// TF-A `SCTLR_EL1_RES1` mask and (b) a handful of fields Linux and TF-A
/// routinely preserve when handing control to an EL1 boot image:
///
///   RES1 set (ARMv8.0 — bits renamed to DEFINED fields in later revisions):
///   bit 29 (RES1 on ARMv8.0 / LSMAOE in later) — AArch32 EL0 LDM/STM atomicity
///   bit 28 (RES1 on ARMv8.0 / nTLSMD in later) — AArch32 EL0 LDM/STM to Device
///   bit 23 (RES1 on ARMv8.0 / SPAN  in later)
///   bit 22 (RES1 on ARMv8.0 / EIS   in later)
///   bit 20 (RES1 on ARMv8.0 / TSCXT in later)
///   bit 11 (RES1 on ARMv8.0 / EOS   in later)
///
///   Always-preserved fields:
///   bit 3  (SA)      — EL1 SP alignment check enabled
///   bit 4  (SA0)     — EL0 SP alignment check enabled
///   bit 5  (CP15BEN) — AArch32 EL0 CP15 barrier enable (harmless for AArch64)
///   bit 16 (nTWI)    — WFI at EL0 not trapped to EL1
///   bit 18 (nTWE)    — WFE at EL0 not trapped to EL1
///
/// Cortex-A72 enforces bits 28/29 as RAO/WI on ARMv8.0 so writing 0 would be
/// functionally equivalent on this specific target, but writing 1 matches
/// ARM's "Should Be One" guidance and keeps the value portable across any
/// future ARMv8.x core where these bits gain DEFINED meanings.
///
/// References:
///   trusted-firmware-a, `include/arch/aarch64/arch.h` — `SCTLR_EL1_RES1`
///   torvalds/linux, `arch/arm64/include/asm/sysreg.h` — `INIT_SCTLR_EL1_MMU_OFF`
///   torvalds/linux, `arch/arm64/tools/sysreg` — `Sysreg SCTLR_EL1` field map
const GUEST_SCTLR_EL1_VAL: u64 = 0x30D5_0838;

// ── Public API ───────────────────────────────────────────────────────────────

/// Load the HFT payload into guest RAM and seed `vcpus[0].regs`.
///
/// Procedure:
///   1. Validate preconditions (Stage-2 built, payload fits, aligned).
///   2. For every page-sized chunk of the payload:
///        a. Walk Stage-2 to resolve `ipa → pa` (guest RAM is colored, so
///           adjacent IPA pages back onto non-contiguous PAs).
///        b. Copy the chunk into the host PA.
///        c. `DC CIVAC` every cache line in the page — see module header.
///   3. Single `dsb ish` to drain every `DC CIVAC` issued in step 2c.
///   4. Seed the first vCPU's register file: PC = `ipa_base`, SP_EL1 just
///      below the 1 MiB mark, SPSR_EL2 = EL1h/DAIF-masked, SCTLR_EL1 set to
///      the MMU-off baseline documented above, VBAR_EL1 = 0.
///   5. One-line UART log.
///
/// # Safety
/// - `vm::init_vms()`, `vm::stage2::init_stage2()`, and `vm::ram::init_guest_ram()`
///   must all have completed.
/// - Must be called exactly once from the Management core (CPU 0) before any
///   VM entry.  No other core may access `HFT_VM` until this returns.
///
/// # Panics
/// Panics on preconditions (missing Stage-2 root, oversized payload, unaligned
/// payload length) and on any unmapped IPA inside the payload's footprint —
/// every such failure indicates a bug in the boot sequence that must be fixed
/// before VM entry would be safe.
pub unsafe fn load_hft_payload() {
    // SAFETY: single-core boot; caller contract above guarantees `init_vms`
    // has populated the global and no concurrent mutator exists.
    let vm = unsafe { hft_vm() };

    assert!(
        vm.stage2_root != 0,
        "[loader] stage2_root=0 — init_stage2() must run first"
    );
    assert!(
        PAYLOAD.len() <= vm.ipa_size,
        "[loader] payload ({} B) exceeds guest RAM ({} B)",
        PAYLOAD.len(),
        vm.ipa_size,
    );
    assert!(
        PAYLOAD.len() % 4 == 0,
        "[loader] payload length {} not 4-byte aligned",
        PAYLOAD.len(),
    );

    // Per-page copy loop.  The payload IPA range starts at vm.ipa_base and
    // spans PAYLOAD.len() bytes; we walk Stage-2 per page because guest RAM
    // pages are colored → non-contiguous in host PA (see vm/ram.rs header).
    let mut off: usize = 0;
    while off < PAYLOAD.len() {
        let ipa = vm.ipa_base + off;

        // SAFETY: `vm.stage2_root` is non-zero per assert above; init_guest_ram
        // mapped every IPA in [ipa_base, ipa_base + ipa_size) with a 4 KiB PAGE
        // descriptor.  The walker is a pure read helper — no tearing against
        // concurrent writers on a single-core boot.
        let pa = unsafe { stage2::walk_ipa(vm.stage2_root, ipa) }
            .expect("[loader] unmapped guest RAM page during payload copy");

        let remaining = PAYLOAD.len() - off;
        let chunk = if remaining < PAGE_SIZE {
            remaining
        } else {
            PAGE_SIZE
        };

        // SAFETY: `pa` is a freshly-zeroed, page-aligned PA owned by the HFT
        // guest's Stage-2 mapping; single-core boot, no other observer.
        // Source and destination regions do not overlap — PAYLOAD lives in the
        // hypervisor's .rodata (VA/PA ≠ guest PA).
        unsafe {
            copy_nonoverlapping(PAYLOAD.as_ptr().add(off), pa as *mut u8, chunk);
            clean_inval_page_to_poc(pa);
        }

        off += PAGE_SIZE;
    }

    // Batched cache-maintenance completion barrier.  Must be `dsb ish`
    // (reads-and-writes scope); `dsb ishst` would not synchronise the
    // DC CIVAC ops issued above.  ARM DDI 0487 — search "DSB"; Linux KVM
    // reference: arch/arm64/kvm/hyp/pgtable.c — `dcache_clean_inval_poc`.
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
    }

    // Seed vcpu[0] — the sole HFT vCPU that actually runs the payload
    // against the HFT watchdog page (see payload.s single-writer invariant).
    // vcpus[1] and vcpus[2] stay zeroed until a future step gives them work.
    let vcpu0 = &mut vm.vcpus[0];
    vcpu0.regs.pc = vm.ipa_base as u64;
    vcpu0.regs.pstate = GUEST_SPSR_EL2_VAL;
    vcpu0.regs.sys.sctlr_el1 = GUEST_SCTLR_EL1_VAL;
    vcpu0.regs.sys.vbar_el1 = 0;
    vcpu0.regs.sp_el1 = (vm.ipa_base + GUEST_STACK_OFFSET) as u64;

    writeln!(
        &mut &UART,
        "[loader] HFT payload loaded: {} bytes \u{2192} IPA={:#010x}  vcpu0 pc={:#x} sp={:#x}",
        PAYLOAD.len(),
        vm.ipa_base,
        vcpu0.regs.pc,
        vcpu0.regs.sp_el1,
    )
    .ok();
}
