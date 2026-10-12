// ============================================================================
// demo.rs — step-through presentation mode (`--features demo`)
//
// With the `demo` feature, kmain pauses at each milestone of the boot
// sequence, prints what happens next, and waits for Enter on the UART.  A
// person at the terminal (or `scripts/capture_demo.py`) drives the boot one
// stage at a time.  Without the feature every gate compiles to nothing and
// the boot path is byte-for-byte the normal one.
//
// Gate line format (parsed by scripts/capture_demo.py — keep in sync):
//   [demo] step <n>/<total> done. Next: <text>  (press Enter)
// ============================================================================

#[cfg(feature = "demo")]
use crate::uart::UART;
#[cfg(feature = "demo")]
use core::fmt::Write;

/// Number of gates in kmain.
#[cfg(feature = "demo")]
const TOTAL_STEPS: u8 = 5;

/// Pause the boot after step `step` until Enter is pressed.
///
/// Before printing, waits ~100 ms so that lines still being written by the
/// secondary cores land above the gate rather than under it.
#[cfg(feature = "demo")]
pub fn gate(step: u8, next: &str) {
    settle_ms(100);

    // Discard keys typed ahead of the prompt so one Enter = one step.
    while UART.try_read_byte().is_some() {}

    writeln!(
        &mut &UART,
        "\n[demo] step {step}/{TOTAL_STEPS} done. Next: {next}  (press Enter)",
    )
    .ok();

    loop {
        match UART.try_read_byte() {
            Some(b'\r') | Some(b'\n') => break,
            _ => core::hint::spin_loop(),
        }
    }
}

#[cfg(not(feature = "demo"))]
#[inline(always)]
pub fn gate(_step: u8, _next: &str) {}

/// Busy-wait for `ms` milliseconds on the physical system counter.
#[cfg(feature = "demo")]
fn settle_ms(ms: u64) {
    let end = crate::time::read_cntpct() + crate::time::cntfrq() * ms / 1000;
    while crate::time::read_cntpct() < end {
        core::hint::spin_loop();
    }
}
