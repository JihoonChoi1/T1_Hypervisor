// ============================================================================
// cpu/secondary.rs — Secondary Core Wakeup & HFT Isolation
//
// Boots CPU 1–3 via PSCI CPU_ON, then applies hardware-level interrupt
// isolation (GICC PMR=0x00) on each HFT core before they enter the
// busy-poll trading loop.
//
// Boot sequence:
//  CPU 0 (Management):
//    1. Calls psci::cpu_on() for CPU IDs 1, 2, 3.
//    2. Spins until CORES_READY == NUM_HFT_CORES.
//    3. Sets INIT_DONE_FLAG + executes SEV to release secondaries.
//
//  CPU 1–3 (HFT, naked asm prologue → secondary_main):
//    1. [NAKED ASM] Initialize EL2 registers (MAIR, HCR, CPTR, SCTLR).
//    2. [NAKED ASM] Load per-core stack into SP_EL2.
//    3. [NAKED ASM] Call secondary_main(cpu_id).
//    4. [RUST]      Install VBAR_EL2, activate MMU.
//    5. [RUST]      Detect topology + mask GICC.
//    6. [RUST]      Increment CORES_READY, spin on INIT_DONE_FLAG + WFE.
//    7. [RUST]      Enter busy-poll trading loop.
//
// Stack layout:
//   SECONDARY_STACKS is a 3×64KiB static array (zero-initialised).
//   CPU 1 = stacks[0..64KiB] top, CPU 2 = stacks[64KiB..128KiB] top, etc.
//
// Reference: ARM DDI 0487; ARM DEN0022D.b (PSCI).
// ============================================================================

use crate::uart::UART;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use super::psci;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of secondary (HFT) cores to wake.
const NUM_HFT_CORES: u32 = 3;

/// Stack size for each secondary core: 64 KiB.
#[allow(dead_code)]
const STACK_SIZE: usize = 64 * 1024;

// ── Static storage ────────────────────────────────────────────────────────────

/// Number of secondary cores that have finished per-core init.
static CORES_READY: AtomicI32 = AtomicI32::new(0);

/// Set to `true` by CPU 0 after all secondaries check in.
/// Secondaries spin on this flag (WFE) before entering the trading loop.
static INIT_DONE_FLAG: AtomicBool = AtomicBool::new(false);

/// Per-secondary stack storage: 3 × 64 KiB, 16-byte aligned.
#[repr(C, align(16))]
#[allow(dead_code)]
struct SecondaryStacks([u8; STACK_SIZE * NUM_HFT_CORES as usize]);

#[unsafe(export_name = "SECONDARY_STACKS")]
#[used]
static mut SECONDARY_STACKS: SecondaryStacks =
    SecondaryStacks([0u8; STACK_SIZE * NUM_HFT_CORES as usize]);

// ── Naked entry point (pure assembly, no Rust prolog) ─────────────────────────
//
// PSCI firmware jumps here with:
//   x0 = context_id (cpu_id: 1, 2, or 3)
//   SP = undefined / unknown
//   EL = EL2
//   All other registers: undefined
//
// We MUST NOT touch the stack until we've set SP ourselves.
// global_asm! contains pure assembly; no Rust function prolog is generated.

core::arch::global_asm!(
    // Export symbol so PSCI can find it via the function pointer we pass.
    ".global secondary_entry",
    ".type secondary_entry, %function",
    "secondary_entry:",
    // ── 1. Initialize critical EL2 registers (no stack needed) ───────────
    // MAIR_EL2: slot0 = Normal-WB (0xFF), slot1 = Device-nGnRnE (0x00)
    "mov  x1, #0xFF",
    "msr  mair_el2, x1",
    // HCR_EL2: VM|TSC|RW = 0x8008_0001 (No IMO/FMO on HFT cores)
    // Bit 0  (VM)  = 1 : Stage-2 translation active
    // Bit 19 (TSC) = 1 : Trap SMC to EL2
    // Bit 31 (RW)  = 1 : EL1 runs AArch64
    // IMO/FMO intentionally CLEAR — HFT cores must be interrupt-free.
    "movz x1, #0x0001",
    "movk x1, #0x8008, lsl #16",
    "msr  hcr_el2, x1",
    // CPTR_EL2: TFP=0 (bit 10) → no FP/SIMD trap in E2H=0 mode.
    // Writing 0 clears TCPAC (bit 31), TTA (bit 20), and TFP (bit 10).
    "mov  x1, #0",
    "msr  cptr_el2, x1",
    // SCTLR_EL2: pre-MMU baseline (ARM DDI 0601, SCTLR_EL2 register, E2H=0 mode).
    // Written from scratch — never read-modify-write (reset state is UNKNOWN).
    //
    // Bit  Name     Value  Status in E2H=0                Meaning
    // ---  ----     -----  ----------------------------   ---------------------------
    //   3  SA       1      Functional                     SP alignment check (EL2)
    //   4  SA0      1      RES1 when E2H=0                (SA0 only applies when E2H=1)
    //   5  CP15BEN  1      RES1 when AArch32 absent       Barrier instruction enable
    //  11  EOS      1      RES1 when FEAT_ExS absent      Exception exit synchronised
    //  16  nTWI     1      RES1 when E2H=0                (nTWI only applies when E2H=1)
    //  18  nTWE     1      RES1 when E2H=0                (nTWE only applies when E2H=1)
    //  22  EIS      1      RES1 when FEAT_ExS absent      Exception entry synchronised
    //  23  SPAN     1      RES1 when E2H=0                (SPAN only applies when E2H=1)
    //  28  nTLSMD   1      RES1 when FEAT_LSMAOC absent   LDM/STM-to-device no-trap
    //  29  LSMAOE   1      RES1 when FEAT_LSMAOC absent   LDM/STM atomicity ordering
    //
    // MMU (bit 0), D-cache (bit 2), and I-cache (bit 12) are 0 here and
    // will be set correctly by enable_mmu_secondary() moments later.
    //
    // Total value: 0x30C5_0838
    //   movz loads bits[15:0]  = 0x0838  (SA=3, SA0=4, CP15BEN=5, EOS=11)
    //   movk loads bits[31:16] = 0x30C5  (nTWI=16, nTWE=18, EIS=22, SPAN=23,
    //                                     nTLSMD=28, LSMAOE=29)
    //   This matches the U-Boot/ATF standard baseline (0x30C5_0830 + SA bit).
    "movz x1, #0x0838",
    "movk x1, #0x30C5, lsl #16",
    "msr  sctlr_el2, x1",
    "isb",
    // ── 2. Set up per-core stack (SP grows downward) ──────────────────────
    // x0 = cpu_id (1, 2, or 3)
    // stack_top = &SECONDARY_STACKS + (cpu_id - 1) * STACK_SIZE + STACK_SIZE
    //           = &SECONDARY_STACKS + cpu_id * STACK_SIZE
    "adrp x1, SECONDARY_STACKS",
    "add  x1, x1, :lo12:SECONDARY_STACKS",
    // x2 = STACK_SIZE = 64 KiB = 0x10000 = 1 << 16
    // MOVZ immediate max is 0xFFFF; use lsl #16 to shift 1 into position.
    "movz x2, #1, lsl #16",
    // x1 = &SECONDARY_STACKS + cpu_id * STACK_SIZE  (top of this core's region)
    "madd x1, x0, x2, x1",
    "mov  sp, x1",
    // ── 3. Tail-call into Rust ────────────────────────────────────────────
    // x0 still holds cpu_id. Jump (not BL) so secondary_main is responsible
    // for the infinite loop — we never return here.
    "b    secondary_main",
);

// ── Rust secondary core main (called from naked asm with valid stack) ─────────

/// Rust entry for secondary cores.  Called from `secondary_entry` assembly
/// with `x0 = cpu_id` and a valid private stack already loaded into SP.
///
/// # Safety
/// Called only from the naked `secondary_entry` stub above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secondary_main(cpu_id: u64) -> ! {
    let cpu_id = cpu_id as usize;

    // ── Step 1: Install VBAR_EL2 ──────────────────────────────────────────
    unsafe {
        unsafe extern "C" {
            static exception_vectors: u8;
        }
        let vbar = &exception_vectors as *const u8 as u64;
        core::arch::asm!(
            "msr vbar_el2, {v}",
            "isb",
            v = in(reg) vbar,
            options(nostack),
        );
    }

    // ── Step 2: Activate the shared Stage-1 MMU ───────────────────────────
    unsafe {
        crate::memory::stage1::enable_mmu_secondary();
    }

    // ── Step 3: Detect topology ───────────────────────────────────────────
    let core_info = crate::cpu::topology::detect();

    // ── Step 4: Hardware-seal this core against all IRQs/FIQs ────────────
    unsafe { crate::irq::gic::mask_gicc_hft() };

    // ── Step 5: Signal CPU 0 ─────────────────────────────────────────────
    CORES_READY.fetch_add(1, Ordering::Release);

    // ── Step 6: Spin on INIT_DONE_FLAG until CPU 0 releases us ───────────
    loop {
        if INIT_DONE_FLAG.load(Ordering::Acquire) {
            break;
        }
        unsafe { core::arch::asm!("wfe", options(nostack)) };
    }

    // ── Step 7: Per-core Timer & PMU init ────────────────────────────────
    // CNTVOFF_EL2, CNTV_CTL_EL0, and PMU cycle counter registers are all
    // banked per-CPU.  CPU 0 configured its own copies in kmain; we must
    // configure ours here — after the barrier so the order is deterministic.
    crate::time::init_per_core(core_info.core_id);

    // ── Step 8: HFT busy-poll trading loop (placeholder) ─────────────────
    writeln!(
        &mut &UART,
        "[hft ] CPU {} entering trading loop (busy-poll placeholder).",
        cpu_id,
    )
    .ok();

    loop {
        core::hint::spin_loop();
    }
}

// ── Management core: boot all secondary cores ─────────────────────────────────

/// Issue PSCI CPU_ON for CPUs 1–3 and wait until all have completed init.
pub fn boot_secondary_cores() {
    unsafe extern "C" {
        fn secondary_entry();
    }
    let entry = secondary_entry as *const () as u64;

    for cpu_id in 1..=(NUM_HFT_CORES as u64) {
        let ret = psci::cpu_on(cpu_id, entry, cpu_id);

        if ret == psci::PSCI_SUCCESS || ret == psci::PSCI_ALREADY_ON {
            writeln!(
                &mut &UART,
                "[boot] CPU {} power-on requested (PSCI ret={}).",
                cpu_id, ret,
            )
            .ok();
        } else {
            writeln!(
                &mut &UART,
                "[boot] CPU {} PSCI CPU_ON failed: ret={}. Halting.",
                cpu_id, ret,
            )
            .ok();
            panic!("PSCI CPU_ON failed for CPU {}", cpu_id);
        }
    }

    writeln!(
        &mut &UART,
        "[boot] Waiting for {} HFT cores...",
        NUM_HFT_CORES
    )
    .ok();
    loop {
        if CORES_READY.load(Ordering::Acquire) >= NUM_HFT_CORES as i32 {
            break;
        }
        core::hint::spin_loop();
    }
    writeln!(&mut &UART, "[boot] All HFT cores ready.").ok();
}

/// Release all secondary cores to enter their trading loops via SEV.
pub fn release_secondary_cores() {
    INIT_DONE_FLAG.store(true, Ordering::Release);
    unsafe {
        core::arch::asm!("sev", options(nostack));
    }
    writeln!(
        &mut &UART,
        "[boot] SEV sent — HFT cores released to trading loop."
    )
    .ok();
}
