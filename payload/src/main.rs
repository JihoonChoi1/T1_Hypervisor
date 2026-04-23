// ============================================================================
// payload/src/main.rs — HFT guest payload entry crate
//
// Rust wrapper around the `_start` symbol defined in payload.s.  All
// guest-visible logic lives in the assembly file; this module exists only
// to:
//   1. Pull the asm into the build via `global_asm!`.
//   2. Satisfy the `no_std` runtime contract (panic handler).
//
// The hypervisor (not libstd) is the environment here — there is no
// eh_personality, no unwind, no allocator.  Any panic is a design bug; we
// park the core on `wfe` so the watchdog can observe the heartbeat stall
// and reset the VM (see src/vm/watchdog.rs).
// ============================================================================

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// Pull in the hand-written entry point + heartbeat loop.
core::arch::global_asm!(include_str!("../payload.s"));

/// Final fallback.  The payload never calls into Rust except through this
/// handler, and the handler itself is only reachable if something panics
/// inside `global_asm!` expansion — which is unreachable at runtime.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        // `wfe` is safe on Device-nGnRnE / MMU-off guests; it is an
        // architecturally-defined hint with no memory side-effects.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack, preserves_flags)) };
    }
}
