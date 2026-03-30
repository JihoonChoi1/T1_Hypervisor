// ============================================================================
// cpu/psci.rs — Power State Coordination Interface (PSCI) SMC Calls
//
// Issues PSCI commands to EL3 firmware via the `smc` instruction.
// The QEMU virt machine uses PSCI 1.0 with SMC calling convention,
// as declared in the DTB (`method = "smc"`, `cpu_on = 0xc4000003`).
//
// Reference: ARM DEN0022D.b — Power State Coordination Interface.
//            ARM DEN0028    - SMC Calling Convention
// ============================================================================

// ── PSCI function identifiers ─────────────────────────────────────────────────

/// PSCI 1.0 — CPU_ON (64-bit calling convention).
/// `x0 = 0xC400_0003`, `x1 = target_cpu` (MPIDR), `x2 = entry_point_address`,
/// `x3 = context_id` (passed as `x0` to entry point on the new core).
const PSCI_CPU_ON_64: u64 = 0xC400_0003;

// ── PSCI return codes ─────────────────────────────────────────────────────────

/// Returned when the called function succeeded.
pub const PSCI_SUCCESS: i64 = 0;
/// The target CPU is already in the "on" state.
pub const PSCI_ALREADY_ON: i64 = -4;

// ── Public API ────────────────────────────────────────────────────────────────

/// Wake up a secondary CPU core via the PSCI `CPU_ON` call.
///
/// # Arguments
/// * `target_cpu`    — The MPIDR affinity value of the target core (e.g. `1`
///                     for Aff0=1, which is CPU 1 on a single-cluster system).
/// * `entry_point`   — Physical address of the `#[no_mangle]` entry function
///                     that the secondary core will jump to.
/// * `context_id`    — Opaque 64-bit value forwarded to the entry point via
///                     `x0`.  We use this to pass the CPU ID to the entry fn.
///
/// # Returns
/// The PSCI return code.  `0` (`PSCI_SUCCESS`) means the core was powered on
/// and will start executing at `entry_point`.
///
/// # Safety
/// * Must be called from EL2 with a valid EL3 firmware present (QEMU always
///   provides PSCI firmware for the `virt` machine).
/// * `entry_point` must be a valid physical address in executable mapped memory.
pub fn cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            // x0: PSCI function ID
            // x1: target CPU (MPIDR)
            // x2: entry point
            // x3: context ID
            "smc #0",
            inlateout("x0") PSCI_CPU_ON_64 => ret,
            in("x1") target_cpu,
            in("x2") entry_point,
            in("x3") context_id,
            // Clobber all caller-saved registers that the SMC may modify.
            lateout("x4") _,
            lateout("x5") _,
            lateout("x6") _,
            lateout("x7") _,
            lateout("x8") _,
            lateout("x9") _,
            lateout("x10") _,
            lateout("x11") _,
            lateout("x12") _,
            lateout("x13") _,
            lateout("x14") _,
            lateout("x15") _,
            lateout("x16") _,
            lateout("x17") _,
            options(nostack),
        );
    }
    ret
}
