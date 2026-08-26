// ============================================================================
// vm/exit.rs — VM-exit handler
//
// `vm_exit_sync` / `vm_exit_irq` in `src/vm/entry.s` save the full guest
// register state into an on-stack `VcpuRegs` frame and hand it here.
//
// Currently, this handler is a temporary stub that panics upon receiving a VM exit.
// In future updates, this temporary panic will be replaced with actual event
// handlers that route exceptions based on ESR_EL2.EC (HVC calls, SMC, Stage-2
// page faults, etc.) while keeping the same function signature.
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

use crate::vm::VcpuRegs;

/// The core Rust handler called by the assembly routines (`vm_exit_sync` / `vm_exit_irq`).
///
/// This function acts as the main dispatcher. It will parse the exception cause (EC)
/// and route the event to the appropriate handler.
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
    panic!(
        "[exit] stub: VM exit caught — ESR_EL2={:#018x} ELR_EL2={:#018x}",
        esr, elr,
    );
}
