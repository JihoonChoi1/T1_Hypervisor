// ============================================================================
// vm/exit.rs — VM-exit handler
//
// `vm_exit_sync` / `vm_exit_irq` in `src/vm/entry.s` save the full guest
// register state into an on-stack `VcpuRegs` frame and hand it here.
//
// Currently, the handler recognises exactly one exit — the payload's `HVC #1`
// halt rendezvous (kill switch) — and panics on everything else.  In future
// updates, the panic will be replaced with actual event handlers that route
// exceptions based on ESR_EL2.EC (HVC calls, SMC, Stage-2 page faults, etc.)
// while keeping the same function signature.
//
// References:
//   ARM DDI 0487 — search "ESR_EL2, Exception Syndrome Register (EL2)"
//     ESR_EL2 holds syndrome information for the exception taken to EL2;
//     EC is bits [31:26], ISS bits [24:0].
//   Linux kernel, arch/arm64/include/asm/esr.h — `ESR_ELx_EC_SHIFT` (26),
//     `ESR_ELx_ISS_MASK` (GENMASK(24, 0))
//     Cross-checked against the Linux kernel's implementation to confirm our
//     bit positions for EC (shift by 26) and ISS (bottom 25 bits) match.
//   Linux kernel, arch/arm64/kvm/handle_exit.c — `kvm_get_exit_handler`,
//     `arm_exit_handlers[]`
//     The architectural blueprint for how we will eventually build our
//     EC-based routing table (dispatching events like HVC, SMC, or Aborts).
// ============================================================================

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::uart::UART;
use crate::vm::VcpuRegs;

/// ESR_EL2.EC value for an HVC instruction executed in AArch64 state.
/// Linux kernel, arch/arm64/include/asm/esr.h — `ESR_ELx_EC_HVC64` (0x16).
const EC_HVC64: u64 = 0x16;

/// `HVC` immediate the payload uses as its "kill switch seen, halting"
/// rendezvous (see `payload/payload.s` `.Lhalt`).
const HVC_IMM_HALT: u64 = 1;

/// Set by the exit handler once the HFT vCPU has acknowledged the kill
/// switch and been parked.  Read by the Management core's observer loop.
pub static GUEST_HALTED: AtomicBool = AtomicBool::new(false);

/// The core Rust handler called by the assembly routines (`vm_exit_sync` / `vm_exit_irq`).
///
/// Only one exit is expected in the current milestone: the payload's
/// `HVC #1` after it observes the kill switch.  That one is acknowledged
/// and the vCPU is parked.  Every other exit is still a bug at this stage
/// and panics with the captured syndrome, so it is loud, not silent.  Full
/// EC routing (Step 21) replaces this body without changing the signature.
///
/// Returns:
///   - `0`      : Continue. The assembly code will restore the guest's state
///                directly from the on-stack frame and resume guest execution
///                via `eret`.
///   - non-zero : Terminate (conventionally `1`). The assembly `cbnz` branches
///                to a halt loop (`.Lvm_exit_halt`) and parks the virtual CPU.
///
/// # Safety
/// The `_frame` pointer must point to a valid, stack-allocated `VcpuRegs` struct
/// created by the assembly save sequence. Its lifetime is strictly managed by the
/// assembly stack frame and ends when the assembly executes `add sp, sp, #VCPU_SIZE`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_vm_exit_handler(_frame: *mut VcpuRegs) -> u64 {
    let esr: u64;
    let elr: u64;
    // SAFETY: at EL2; reads are architecturally permitted.
    unsafe {
        core::arch::asm!("mrs {}, esr_el2", out(reg) esr, options(nostack, nomem));
        core::arch::asm!("mrs {}, elr_el2", out(reg) elr, options(nostack, nomem));
    }

    // EC is ESR_EL2[31:26]; for HVC the ISS[15:0] carries the imm16.
    let ec = (esr >> 26) & 0x3F;
    let imm16 = esr & 0xFFFF;

    if ec == EC_HVC64 && imm16 == HVC_IMM_HALT {
        // For HVC the preferred return address is the instruction after the
        // HVC, so ELR_EL2 points one instruction past the trap site.
        writeln!(
            &mut &UART,
            "[exit] guest trapped to EL2: HVC #{} (ESR_EL2={:#010x}, EC={:#04x} HVC64, ELR_EL2={:#x})",
            imm16, esr, ec, elr,
        )
        .ok();
        writeln!(
            &mut &UART,
            "[exit] kill switch acknowledged by guest. vCPU 0 parked at EL2.",
        )
        .ok();
        GUEST_HALTED.store(true, Ordering::Release);
        return 1;
    }

    panic!(
        "[exit] unhandled VM exit — ESR_EL2={:#018x} (EC={:#04x}) ELR_EL2={:#018x}",
        esr, ec, elr,
    );
}
