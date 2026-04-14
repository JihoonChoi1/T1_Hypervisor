// ============================================================================
// vm/watchdog.rs — vCPU Watchdog
//
// Detects a hung HFT engine by monitoring a heartbeat counter incremented
// by the HFT trading loop every iteration.  The Management core calls
// check_watchdog() periodically; three consecutive misses trigger a VM reset.
//
// Memory layout (WatchdogPage, 64 B = 1 cache line):
//   offset  0: heartbeat   (AtomicU64, 8 B) — HFT increments every loop tick
//   offset  8: reset_count (AtomicU32, 4 B) — cumulative resets since boot
//   offset 12: _pad        ([u8; 52])        — fill to 64 bytes
//
// Stage-2 IPA mapping (TODO):
//   HFT  IPA 0x5000_0000 → S2AP = RW  (HFT writes heartbeat)
//   Mgmt IPA 0x5000_0000 → S2AP = RO  (Mgmt reads heartbeat, never writes)
//
// References:
//   ARM ARM DDI 0487 — search "LDAR", "STLR" for load-acquire / store-release
//     instruction semantics; search "Load-Acquire, Store-Release" for the
//     ordering guarantees in the memory model chapter.
//   ARM "Learn the architecture — Memory Systems, Ordering, and Barriers"
//     (developer.arm.com/documentation/102336) — practical LDAR/STLR explanation.
//   Rust Acquire/Release → LDAR/STLR mapping is LLVM AArch64 backend behaviour,
//     not specified in the Rust nomicon. On Cortex-A72 (no FEAT_LRCPC):
//       Ordering::Acquire load  → LDAR
//       Ordering::Release store → STLR
//     On ARMv8.3+ with FEAT_LRCPC, Acquire may use the weaker LDAPR instead.
// ============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::memory::pmm;
use crate::uart::UART;
use core::fmt::Write;

// ── WatchdogPage ─────────────────────────────────────────────────────────────

/// Shared watchdog page mapped into both VMs at IPA `0x5000_0000`.
///
/// **HFT side** (S2AP=RW): increments `heartbeat` every trading loop iteration
/// via `fetch_add(1, Release)`.
/// **Management side** (S2AP=RO): reads `heartbeat` via `load(Acquire)` in
/// `check_watchdog()`; never writes.
///
/// Fits in one 64-byte cache line — no false sharing concern since only one
/// side writes each field.
#[repr(C, align(64))]
pub struct WatchdogPage {
    /// Monotonically increasing counter.  Wraps at u64::MAX (effectively never).
    pub heartbeat: AtomicU64,
    /// Cumulative number of HFT VM resets since boot.
    /// Incremented by `vm_reset_hft()` on the Management core.
    pub reset_count: AtomicU32,
    /// Padding to fill the struct to exactly 64 bytes (one cache line).
    pub _pad: [u8; 52],
}

const _: () = assert!(core::mem::size_of::<WatchdogPage>() == 64);
const _: () = assert!(core::mem::align_of::<WatchdogPage>() == 64);

// ── Global state ─────────────────────────────────────────────────────────────

/// Physical address of the allocated WatchdogPage.  0 until `init_watchdog()`.
static mut WATCHDOG_PA: usize = 0;

// ── Public API ────────────────────────────────────────────────────────────────

/// Allocate and zero one 4 KiB page to hold the `WatchdogPage`.
///
/// Stores the PA in `WATCHDOG_PA` and logs it to UART.
/// Returns the physical address for Stage-2 mapping (Stage-2 Translation Tables).
///
/// # Safety
/// Must be called exactly once after `pmm::init()`, on the Management core,
/// before any guest VM is entered.
pub unsafe fn init_watchdog() -> usize {
    let pa = unsafe { pmm::alloc(0).expect("[watchdog] PMM OOM: cannot allocate WatchdogPage") };

    // Zero the page — heartbeat and reset_count must both start at 0.
    unsafe {
        core::ptr::write_bytes(pa as *mut u8, 0, pmm::PAGE_SIZE);
    }

    unsafe { WATCHDOG_PA = pa };

    writeln!(&mut &UART, "[watchdog] init: PA={:#010x}", pa).ok();
    pa
}

/// Check the HFT heartbeat and trigger a reset after 3 consecutive misses.
///
/// Intended to be called periodically from the Management event loop.
///
/// - `last_hb`: last observed heartbeat value (caller-owned state).
/// - `miss`:    consecutive miss counter (caller-owned state, reset on progress).
///
/// # Safety
/// `init_watchdog()` must have been called.
pub unsafe fn check_watchdog(last_hb: &mut u64, miss: &mut u8) {
    let page = unsafe { &*(WATCHDOG_PA as *const WatchdogPage) };
    let current = page.heartbeat.load(Ordering::Acquire);

    if current == *last_hb {
        *miss = miss.saturating_add(1);
        if *miss >= 3 {
            unsafe { vm_reset_hft() };
        }
    } else {
        *last_hb = current;
        *miss = 0;
    }
}

/// Reset the HFT engine VM.
///
/// **STUB** — full implementation deferred to Stage-2 Translation Tables + VM-Entry.
/// Currently logs the event and increments `reset_count`.
///
/// # Safety
/// `init_watchdog()` must have been called.
pub unsafe fn vm_reset_hft() {
    let page = unsafe { &*(WATCHDOG_PA as *const WatchdogPage) };
    let prev = page.reset_count.fetch_add(1, Ordering::Release);

    writeln!(
        &mut &UART,
        "[watchdog] HFT VM reset triggered (reset_count={})",
        prev + 1,
    )
    .ok();

    // TODO (Stage-2 + VM-Entry): halt HFT vCPUs, tear down Stage-2 mappings,
    // reload payload, and re-enter the HFT VM.
}
