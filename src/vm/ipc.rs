// ============================================================================
// vm/ipc.rs — HFT ↔ Management IPC
//
// Lock-free, shared-memory inter-VM communication over a single 4 KiB page.
//
// Channel topology:
//   m2h : IpcChannel      — Management → HFT (SPSC; Management produces, HFT consumes)
//   h2m : [IpcChannel; 3] — HFT core N → Management (per-core SPSC; HFT core N uses
//                            h2m[N-1] where N ∈ {1,2,3}).  No shared tail → no Compare-and-Swap.
//
// MPSC race fix:
//   A single shared tail for HFT cores 1/2/3 would require a CAS loop on every
//   enqueue, burning cycles on the hot path and introducing non-deterministic
//   latency.  Per-core channels are strictly SPSC — no atomics stronger than
//   Acquire/Release are needed.
//
// False-sharing fix:
//   `tail` (producer-written) and `head` (consumer-written) are placed on
//   separate 64-byte cache lines via explicit padding.  Without this, a
//   producer increment of `tail` would dirty the cache line that the consumer
//   owns for `head`, causing a coherency transaction on every enqueue/dequeue
//   pair — worst-case +40 ns per operation on Cortex-A72 LPDDR4.
//
// Memory layout (IpcPage, 4096 B):
//   offset    0: m2h        (IpcChannel, 640 B)
//   offset  640: h2m[0..3]  (3 × IpcChannel = 1920 B)
//   offset 2560: _pad       ([u8; 1536])
//   total: 4096 B
//
// Stage-2 IPA mapping (Stage-2 Translation Tables):
//   Both VMs IPA 0x5000_1000 → Stage-2 Access Permissions = RW
//
// Memory ordering (Acquire/Release → LDAR/STLR on Cortex-A72):
//   send:     slot bytes written (plain stores) → tail.store(Release)
//   try_recv: tail.load(Acquire) → slot bytes read → head.store(Release)
//   The Acquire load on `tail` in try_recv provides the barrier: any observer
//   that sees the updated tail is guaranteed to observe the slot bytes written
//   before the Release store.
//
// References:
//   ARM ARM DDI 0487 — "Load-Acquire, Store-Release" memory model chapter;
//     search "LDAR", "STLR" for instruction semantics.
//   ARM "Learn the architecture — Memory Systems, Ordering, and Barriers"
//     (developer.arm.com/documentation/102336) — practical LDAR/STLR walkthrough.
//   Rust Acquire/Release → LDAR/STLR mapping is LLVM AArch64 backend behaviour,
//     not specified in the Rust nomicon. On Cortex-A72 (no FEAT_LRCPC):
//       Ordering::Acquire load  → LDAR
//       Ordering::Release store → STLR
//     Since LLVM 16, CPUs with FEAT_LRCPC (e.g. Neoverse V1) emit LDAPR for
//     Acquire loads instead (weaker RCpc). Cortex-A72 has no FEAT_LRCPC, so
//     LDAR/STLR are used regardless of LLVM version.
// ============================================================================

use core::sync::atomic::{AtomicU32, Ordering};

use crate::memory::pmm;
use crate::uart::UART;
use core::fmt::Write;

// ── Message type constants ────────────────────────────────────────────────────

// Management → HFT
/// Update risk parameters (position limits, max drawdown, etc.).
pub const MSG_RISK_PARAMS: u32 = 0x01;
/// Update per-instrument position limit.
pub const MSG_POSITION_LIMIT: u32 = 0x02;
/// Push market data snapshot (prices, depths) to the HFT engine.
pub const MSG_MARKET_DATA_UPDATE: u32 = 0x03;
/// Signal the HFT engine to reload its configuration.
pub const MSG_CONFIG_RELOAD: u32 = 0x04;

// HFT → Management
/// Acknowledge a completed trade execution.
pub const MSG_TRADE_CONFIRM: u32 = 0x81;
/// Report a runtime error (highest-priority; see `poll_h2m` policy).
pub const MSG_ERROR_REPORT: u32 = 0x82;
/// Periodic heartbeat data (counters, fill stats, etc.).
pub const MSG_HEARTBEAT_DATA: u32 = 0x83;
/// Snapshot of current open positions.
pub const MSG_POSITION_SNAPSHOT: u32 = 0x84;

// ── Ring buffer geometry ──────────────────────────────────────────────────────

/// Number of slots per channel.  Must be a power of two (mask = DEPTH - 1).
const CHANNEL_DEPTH: usize = 8;

// ── IpcSlot ───────────────────────────────────────────────────────────────────

/// One message slot — 64 bytes (one cache line).
///
/// Layout is fixed so that both VMs see identical field offsets regardless of
/// host/guest compiler choices.
#[repr(C)]
pub struct IpcSlot {
    /// Message type identifier.  See `MSG_*` constants.
    pub msg_type: u32,
    /// Monotonic sequence number (producer-assigned, wraps at u32::MAX).
    /// Allows the consumer to detect dropped messages after a ring overflow.
    pub seq: u32,
    /// Application payload.  Encoding is message-type-specific.
    pub payload: [u8; 56],
}

const _: () = assert!(core::mem::size_of::<IpcSlot>() == 64);

// ── IpcChannel ────────────────────────────────────────────────────────────────

/// SPSC ring-buffer channel — 640 bytes.
///
/// `tail` (producer index) lives on cache line 0.
/// `head` (consumer index) lives on cache line 1.
/// Padding between them prevents false sharing on CPUs with ≤ 64-byte lines.
///
/// Both indices are u32 wrapping counters.  The slot index is derived via
/// `index % CHANNEL_DEPTH`.  The ring is full when `(tail - head) == DEPTH`,
/// empty when `tail == head`.  u32 wrapping arithmetic keeps these invariants
/// across rollovers for DEPTH ≤ 2^31.
#[repr(C)]
pub struct IpcChannel {
    /// Producer write index.  Written only by the producer; read by both.
    pub tail: AtomicU32,
    /// Padding: fills the remainder of cache line 0 after `tail`.
    _pad0: [u8; 60],
    /// Consumer read index.  Written only by the consumer; read by both.
    pub head: AtomicU32,
    /// Padding: fills the remainder of cache line 1 after `head`.
    _pad1: [u8; 60],
    /// Ring buffer slots (8 × 64 B = 512 B).
    pub slots: [IpcSlot; CHANNEL_DEPTH],
}

const _: () = assert!(core::mem::size_of::<IpcChannel>() == 640);
const _: () = assert!(core::mem::offset_of!(IpcChannel, head) == 64);
const _: () = assert!(core::mem::offset_of!(IpcChannel, slots) == 128);

impl IpcChannel {
    /// Attempt to enqueue one message.
    ///
    /// Returns `true` on success, `false` if the ring is full (back-pressure:
    /// caller may retry or drop depending on message priority).
    ///
    /// **Producer side only** — must be called exclusively by the core that
    /// owns `tail` for this channel (Management for `m2h`; HFT core N for
    /// `h2m[N-1]`).
    ///
    /// Ordering:
    ///   - Slot bytes are written via plain (non-atomic) stores.
    ///   - `tail` is stored with `Release` so the consumer's `Acquire` load on
    ///     `tail` in `try_recv` guarantees the slot bytes are visible.
    ///   - `head` is loaded with `Acquire` to observe the consumer's latest
    ///     progress before computing available capacity.
    ///
    /// # Safety
    /// The `IpcPage` containing this channel must be zero-initialised
    /// (`init_ipc()` called) and mapped into the caller's address space.
    pub unsafe fn send(&self, msg_type: u32, seq: u32, payload: &[u8]) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        // Acquire: observe the consumer's latest head before computing space.
        let head = self.head.load(Ordering::Acquire);

        if (tail.wrapping_sub(head) as usize) >= CHANNEL_DEPTH {
            return false; // ring full
        }

        let idx = (tail as usize) % CHANNEL_DEPTH;
        // Safety: idx is always in [0, CHANNEL_DEPTH), derived from a u32 modulo.
        let slot = unsafe { &mut *(self.slots.as_ptr().add(idx) as *mut IpcSlot) };

        slot.msg_type = msg_type;
        slot.seq = seq;

        let copy_len = payload.len().min(56);
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), slot.payload.as_mut_ptr(), copy_len);
        }
        // Zero any unused tail of the payload field to prevent stale data leaks.
        if copy_len < 56 {
            unsafe {
                core::ptr::write_bytes(slot.payload.as_mut_ptr().add(copy_len), 0, 56 - copy_len);
            }
        }

        // Release: all slot writes must be visible before the tail increment
        // that signals the consumer.
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Attempt to dequeue one message.
    ///
    /// Returns a copy of the slot on success, `None` if the ring is empty.
    ///
    /// **Consumer side only** — must be called exclusively by the core that
    /// owns `head` for this channel (HFT for `m2h`; Management for `h2m[*]`).
    ///
    /// Ordering:
    ///   - `tail` is loaded with `Acquire` to ensure the slot bytes written by
    ///     the producer before its `Release` store on `tail` are visible here.
    ///   - `head` is stored with `Release` to expose the updated consumer index
    ///     to the producer's next capacity check.
    ///
    /// # Safety
    /// Same requirements as `send`.
    pub unsafe fn try_recv(&self) -> Option<IpcSlot> {
        let head = self.head.load(Ordering::Relaxed);
        // Acquire: guarantee slot bytes are visible after observing the producer's
        // Release store on tail.
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None; // ring empty
        }

        let idx = (head as usize) % CHANNEL_DEPTH;
        let slot = &self.slots[idx];

        let out = IpcSlot {
            msg_type: slot.msg_type,
            seq: slot.seq,
            payload: slot.payload,
        };

        // Release: slot copy is complete; advance head to free the slot for
        // the producer.
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(out)
    }
}

// ── IpcPage ───────────────────────────────────────────────────────────────────

/// Shared IPC page — exactly 4096 bytes, page-aligned.
///
/// Mapped into both VMs at IPA `0x5000_1000` with `S2AP = RW`.
///
/// Channel ownership (who writes `tail`, who writes `head`):
///
/// | Channel  | tail owner        | head owner        |
/// |----------|-------------------|-------------------|
/// | m2h      | Management core   | HFT consumer      |
/// | h2m[0]   | HFT core 1        | Management core   |
/// | h2m[1]   | HFT core 2        | Management core   |
/// | h2m[2]   | HFT core 3        | Management core   |
#[repr(C, align(4096))]
pub struct IpcPage {
    /// Management → HFT channel (SPSC).
    pub m2h: IpcChannel,
    /// Per-HFT-core → Management channels (SPSC each).
    /// HFT core N (N ∈ {1,2,3}) is the sole producer of `h2m[N-1]`.
    pub h2m: [IpcChannel; 3],
    /// Padding to fill the page to exactly 4096 bytes.
    _pad: [u8; 1536],
}

const _: () = assert!(core::mem::size_of::<IpcPage>() == 4096);
const _: () = assert!(core::mem::offset_of!(IpcPage, h2m) == 640);
const _: () = assert!(core::mem::offset_of!(IpcPage, _pad) == 2560);

// ── Global state ─────────────────────────────────────────────────────────────

/// Physical address of the allocated IpcPage.  0 until `init_ipc()`.
static mut IPC_PA: usize = 0;

// ── Public API ────────────────────────────────────────────────────────────────

/// Allocate and zero one 4 KiB page to hold the `IpcPage`.
///
/// Stores the PA in `IPC_PA` and logs it to UART.
/// Returns the physical address for Stage-2 IPA mapping (Stage-2 Translation Tables).
///
/// # Safety
/// Must be called exactly once after `pmm::init()`, on the Management core,
/// before any guest VM is entered.
pub unsafe fn init_ipc() -> usize {
    let pa = unsafe { pmm::alloc(0).expect("[ipc] PMM OOM: cannot allocate IpcPage") };

    // Zero the page — all tail/head indices start at 0, slots are blank.
    unsafe {
        core::ptr::write_bytes(pa as *mut u8, 0, pmm::PAGE_SIZE);
    }

    unsafe { IPC_PA = pa };

    writeln!(&mut &UART, "[ipc] init: PA={:#010x}", pa).ok();
    pa
}

/// Drain all three h2m channels once using round-robin with priority override.
///
/// # Polling policy
///
/// 1. Channels are visited in order h2m[0], h2m[1], h2m[2] (round-robin).
/// 2. All available slots are drained from each channel before moving to the
///    next.
/// 3. When a `MSG_ERROR_REPORT` slot is dequeued, `handler` is invoked
///    immediately and the remaining channels are **skipped this round** — their
///    skip counters are incremented.
/// 4. When a channel's skip counter reaches `≥ 8`, it is **force-drained**:
///    an `MSG_ERROR_REPORT` received from it does not interrupt the drain
///    (starvation cap).  The skip counter is reset to 0 at the start of each
///    drain regardless.
///
/// `handler` receives `(channel_index: usize, slot: IpcSlot)`.
///
/// # Safety
/// `init_ipc()` must have been called.
pub unsafe fn poll_h2m(mut handler: impl FnMut(usize, IpcSlot)) {
    let page = unsafe { &*(IPC_PA as *const IpcPage) };

    // Per-channel skip counters — persist across calls to track starvation.
    static mut SKIP: [u8; 3] = [0; 3];

    for i in 0..3usize {
        let forced = unsafe { SKIP[i] >= 8 };
        // Reset skip counter: we are visiting this channel this round.
        unsafe { SKIP[i] = 0 };

        loop {
            let Some(slot) = (unsafe { page.h2m[i].try_recv() }) else {
                break;
            };
            let is_err = slot.msg_type == MSG_ERROR_REPORT;

            handler(i, slot);

            // Priority interrupt: on MSG_ERROR_REPORT (unless force-draining),
            // skip the remaining channels this round and increment their skip
            // counters to track potential starvation.
            if is_err && !forced {
                for j in (i + 1)..3 {
                    unsafe { SKIP[j] = SKIP[j].saturating_add(1) };
                }
                return;
            }
        }
    }
}

// ── Message send/receive helpers ─────────────────────────────────────────────

/// Send one message on the Management → HFT channel.
///
/// Returns `true` on success, `false` if the ring is full.
///
/// # Safety
/// `init_ipc()` must have been called.  Must be called from the Management core only.
pub unsafe fn m2h_send(msg_type: u32, seq: u32, payload: &[u8]) -> bool {
    let page = unsafe { &*(IPC_PA as *const IpcPage) };
    unsafe { page.m2h.send(msg_type, seq, payload) }
}

/// Dequeue one message from the Management → HFT channel (HFT consumer).
///
/// Returns `Some(slot)` if a message is available, `None` if the ring is empty.
///
/// # Safety
/// `init_ipc()` must have been called.  Must be called from the HFT core only.
pub unsafe fn m2h_recv() -> Option<IpcSlot> {
    let page = unsafe { &*(IPC_PA as *const IpcPage) };
    unsafe { page.m2h.try_recv() }
}

/// Send one message on the HFT core N → Management channel.
///
/// `core_idx` must be in 1..=3 (the HFT core number); maps to `h2m[core_idx - 1]`.
/// Returns `true` on success, `false` if the ring is full.
///
/// # Safety
/// `init_ipc()` must have been called.  Must be called exclusively from HFT core `core_idx`.
pub unsafe fn h2m_send(core_idx: usize, msg_type: u32, seq: u32, payload: &[u8]) -> bool {
    assert!(
        (1..=3).contains(&core_idx),
        "[ipc] h2m_send: core_idx out of range"
    );
    let page = unsafe { &*(IPC_PA as *const IpcPage) };
    unsafe { page.h2m[core_idx - 1].send(msg_type, seq, payload) }
}
