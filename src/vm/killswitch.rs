// ============================================================================
// vm/killswitch.rs — Kill Switch
//
// A single shared page lets the Management core signal the HFT engine to
// halt trading.  The HFT loop polls `is_active()` at the start of each
// iteration; on a non-zero flag it stops and waits for re-entry.
//
// Memory layout (KillPage, 64 B = 1 cache line):
//   offset  0: flag    (AtomicU8, 1 B) — 0x00 trading, 0x01 halt req, 0xFF emergency
//   offset  1: _pad1   ([u8;  7])      — align reason to offset 8
//   offset  8: reason  ([u8; 56])      — null-terminated ASCII reason string
//
// Stage-2 IPA mapping (TODO):
//   HFT  IPA 0x5000_2000 → S2AP = RO  (HFT polls flag, never writes)
//   Mgmt IPA 0x5000_2000 → S2AP = RW  (Mgmt writes flag and reason)
//
// Memory ordering for request_halt():
//   reason bytes are written via plain (non-atomic) stores, then flag is
//   written with Release ordering.  Any observer that loads flag with Acquire
//   and sees the new value is guaranteed to observe the reason bytes too.
//
// References:
//   ARM ARM DDI 0487 — search "LDAR", "STLR" for load-acquire / store-release
//     instruction semantics; search "Load-Acquire, Store-Release" for the
//     ordering guarantees in the memory model chapter.
//   ARM "Learn the architecture — Memory Systems, Ordering, and Barriers"
//     (developer.arm.com/documentation/102336) — practical LDAR/STLR explanation.
//   Rust Acquire/Release → LDAR/STLR mapping is LLVM AArch64 backend behaviour.
//     On Cortex-A72 (no FEAT_LRCPC):
//       Ordering::Acquire load  → LDAR
//       Ordering::Release store → STLR
// ============================================================================

use core::sync::atomic::{AtomicU8, Ordering};

use crate::memory::pmm;
use crate::uart::UART;
use core::fmt::Write;

// ── Flag constants ────────────────────────────────────────────────────────────

/// Normal operation — HFT trading loop continues.
pub const KILL_TRADING_ACTIVE: u8 = 0x00;
/// Graceful halt requested — HFT finishes in-flight orders then stops.
pub const KILL_HALT_REQUESTED: u8 = 0x01;
/// Emergency halt — HFT stops immediately without cleanup.
pub const KILL_EMERGENCY: u8 = 0xFF;

// ── KillPage ──────────────────────────────────────────────────────────────────

/// Shared kill-switch page mapped into both VMs at IPA `0x5000_2000`.
///
/// **Management side** (S2AP=RW): calls `request_halt()` or `emergency_halt()`
/// to set `flag`; writes `reason` before setting the flag (Release ordering).
/// **HFT side** (S2AP=RO): calls `is_active()` at the start of each loop
/// iteration to check whether trading should continue.
#[repr(C, align(64))]
pub struct KillPage {
    /// Halt flag.  See `KILL_*` constants.
    pub flag: AtomicU8,
    /// Padding between flag and reason to keep the struct at 64 bytes total.
    pub _pad1: [u8; 7],
    /// Null-terminated ASCII reason string (max 55 chars + NUL).
    /// Written by Management before setting `flag` (plain stores are
    /// ordered before the subsequent Release store on `flag`).
    pub reason: [u8; 56],
}

const _: () = assert!(core::mem::size_of::<KillPage>() == 64);
const _: () = assert!(core::mem::align_of::<KillPage>() == 64);
const _: () = assert!(core::mem::offset_of!(KillPage, reason) == 8);

// ── Global state ─────────────────────────────────────────────────────────────

/// Physical address of the allocated KillPage.  0 until `init_killswitch()`.
static mut KILLSWITCH_PA: usize = 0;

// ── Public API ────────────────────────────────────────────────────────────────

/// Allocate and zero one 4 KiB page to hold the `KillPage`.
///
/// Stores the PA in `KILLSWITCH_PA` and logs it to UART.
/// Returns the physical address for Stage-2 mapping (Stage-2 Translation Tables).
///
/// # Safety
/// Must be called exactly once after `pmm::init()`, on the Management core,
/// before any guest VM is entered.
pub unsafe fn init_killswitch() -> usize {
    let pa = unsafe { pmm::alloc(0).expect("[killswitch] PMM OOM: cannot allocate KillPage") };

    // Zero the page — flag starts at KILL_TRADING_ACTIVE (0x00), reason is empty.
    unsafe {
        core::ptr::write_bytes(pa as *mut u8, 0, pmm::PAGE_SIZE);
    }

    unsafe { KILLSWITCH_PA = pa };

    writeln!(&mut &UART, "[killswitch] init: PA={:#010x}", pa).ok();
    pa
}

/// Request a graceful halt with an optional reason string.
///
/// Copies up to 55 bytes of `reason` into the page (NUL-terminated), then
/// stores `KILL_HALT_REQUESTED` with Release ordering so any HFT thread that
/// loads `flag` with Acquire sees the reason bytes too.
///
/// # Safety
/// `init_killswitch()` must have been called.
pub unsafe fn request_halt(reason: &[u8]) {
    let page = unsafe { &mut *(KILLSWITCH_PA as *mut KillPage) };

    // Write reason bytes first (plain stores).  The Release store on `flag`
    // below provides the necessary barrier — HFT's Acquire load on `flag`
    // guarantees it sees these bytes.
    let copy_len = reason.len().min(55);
    unsafe {
        core::ptr::copy_nonoverlapping(reason.as_ptr(), page.reason.as_mut_ptr(), copy_len);
    }
    page.reason[copy_len] = 0; // NUL-terminate

    page.flag.store(KILL_HALT_REQUESTED, Ordering::Release);
}

/// Trigger an emergency halt immediately, without a reason string.
///
/// # Safety
/// `init_killswitch()` must have been called.
pub unsafe fn emergency_halt() {
    let page = unsafe { &*(KILLSWITCH_PA as *const KillPage) };
    page.flag.store(KILL_EMERGENCY, Ordering::Release);
}

/// Returns `true` if the HFT trading loop should continue (flag == 0x00).
///
/// Intended to be called at the top of the HFT trading loop.
///
/// # Safety
/// `init_killswitch()` must have been called.
pub unsafe fn is_active() -> bool {
    let page = unsafe { &*(KILLSWITCH_PA as *const KillPage) };
    page.flag.load(Ordering::Acquire) == KILL_TRADING_ACTIVE
}
