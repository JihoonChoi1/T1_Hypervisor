// ============================================================================
// cpu/freq.rs — CPU Frequency Pinning
//
// BCM2711 (Raspberry Pi 4) Cortex-A72 supports DVFS.  Frequency transitions
// during hypervisor operation would:
//   (a) Invalidate PMCCNTR_EL0 measurements (cycle count ≠ wall-clock time).
//   (b) Cause multi-microsecond pipeline stalls that violate HFT determinism.
//
// This module locks the ARM core clock at EL2 boot time via the VideoCore
// firmware mailbox (property channel 8, tag SET_CLOCK_RATE).  The firmware
// owns DVFS on RPi4; direct CM register writes can be overridden by the
// firmware at any time, so the mailbox interface is the only reliable path.
//
// QEMU: Mailbox MMIO is not emulated.  The write is skipped and a diagnostic
// log line is emitted instead.
//
// Mailbox reference:
//   raspberrypi/firmware wiki "Accessing mailboxes"
//     → MAIL0/MAIL1 read/write procedure, FULL/EMPTY bits, channel 8 exception
//   raspberrypi/firmware wiki "Mailbox property interface"
//     → SET_CLOCK_RATE tag (0x00038002), CLOCK_ID_ARM (0x00000003),
//       message buffer format (size header, tag format, end tag)
//   raspberrypi/linux drivers/mailbox/bcm2835-mailbox.c
//     → MAIL0/MAIL1 register offsets (ARM_0_MAIL1=0x20, MAIL1_STA=0x38, ...)
//   Mailbox base (ARM phys): 0xFE00_B880  (bus: 0x7E00_B880)
//     Covered by the 2 MiB Device-nGnRnE block mapped at 0xFE00_0000 in
//     stage1.rs section 4-B (same block as CM MMIO at 0xFE10_0000).
//   MAIL0_RD  offset 0x00 — ARM reads responses from VideoCore
//   MAIL0_STA offset 0x18 — bit[30]=EMPTY; poll before reading   (MAIL0)
//   MAIL1_WRT offset 0x20 — ARM sends requests to VideoCore
//   MAIL1_STA offset 0x38 — bit[31]=FULL;  poll before writing   (MAIL1)
//   Channel 8: property tags (ARM → VC)
//
// Property tag SET_CLOCK_RATE (0x0003_8002):
//   Request:  [clock_id, rate_hz, skip_turbo]  (12 bytes)
//   Response: [clock_id, actual_rate_hz]        (8 bytes)
//   ARM clock ID = 0x0000_0003
//
// Message buffer must be:
//   • 16-byte aligned — lower 4 bits of the address carry the channel number.
//   • Passed as ARM physical address directly (no VC bus offset).
//     firmware wiki "Accessing mailboxes": "With the exception of the property
//     tags mailbox channel, addresses should be bus addresses as seen from the
//     VC" — channel 8 is that exception; physical address is used as-is.
//   • D-cache cleaned to PoC (DC CIVAC) before sending and after receiving,
//     so the VC reads/writes DRAM directly and not a stale ARM cache line.
//
// Call order (from kmain, CPU 0 only):
//   time::init_per_core()   ← PMU cycle counter armed
//   cpu::freq::init_freq()  ← THIS (frequency locked)
//   cpu::secondary::boot_secondary_cores()
// ============================================================================

use crate::uart::UART;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

// ── Mailbox register addresses (BCM2711 ARM phys) ─────────────────────────────

#[cfg(feature = "rpi4")]
const MBOX_BASE: usize = 0xFE00_B880;

/// MAIL0_RD: ARM reads firmware responses from here.
#[cfg(feature = "rpi4")]
const MAIL0_RD: usize = MBOX_BASE + 0x00;

/// MAIL0_STA: status for the receive side; bit[30]=EMPTY.
/// Poll until EMPTY is clear before reading MAIL0_RD.
/// Source: raspberrypi/linux bcm2835-mailbox.c (MAIL0_STA = +0x18 relative to MAIL0 base).
#[cfg(feature = "rpi4")]
const MAIL0_STA: usize = MBOX_BASE + 0x18;

/// MAIL1_WRT: ARM writes requests to firmware here.
/// Source: raspberrypi/linux bcm2835-mailbox.c (MAIL1_WRT = ARM_0_MAIL1 + 0x00; ARM_0_MAIL1 = 0x20).
#[cfg(feature = "rpi4")]
const MAIL1_WRT: usize = MBOX_BASE + 0x20;

/// MAIL1_STA: status for the send side; bit[31]=FULL.
/// Poll until FULL is clear before writing MAIL1_WRT.
/// Source: raspberrypi/linux bcm2835-mailbox.c (MAIL1_STA = ARM_0_MAIL1 + 0x18 = 0x38).
#[cfg(feature = "rpi4")]
const MAIL1_STA: usize = MBOX_BASE + 0x38;

/// bit[31] of MAIL1_STA: send FIFO is full — do not write.
#[cfg(feature = "rpi4")]
const MBOX_FULL: u32 = 1 << 31;

/// bit[30] of MAIL0_STA: receive FIFO is empty — do not read.
#[cfg(feature = "rpi4")]
const MBOX_EMPTY: u32 = 1 << 30;

/// Channel 8 = property tags (ARM → VideoCore).
#[cfg(feature = "rpi4")]
const MBOX_CH_PROP: u32 = 8;

// ── Property tag constants ────────────────────────────────────────────────────

/// Tag: SET_CLOCK_RATE — ask firmware to set and hold a specific clock rate.
#[cfg(feature = "rpi4")]
const TAG_SET_CLOCK_RATE: u32 = 0x0003_8002;

/// Clock ID for the ARM core clock.
#[cfg(feature = "rpi4")]
const CLOCK_ID_ARM: u32 = 0x0000_0003;

/// Target ARM core frequency: 1.5 GHz.
#[cfg(feature = "rpi4")]
const ARM_FREQ_HZ: u32 = 1_500_000_000;


// ── Message buffer ────────────────────────────────────────────────────────────

/// Mailbox property message for SET_CLOCK_RATE.
///
/// Layout (9 × u32 = 36 bytes; struct padded to 64 bytes to fit one
/// Cortex-A72 cache line, so a single DC CIVAC cleans the whole buffer):
///
///   [0]  total buffer size in bytes (36)
///   [1]  request/response code      (0x0000_0000 request / 0x8000_0000 success)
///   [2]  tag identifier             (TAG_SET_CLOCK_RATE)
///   [3]  tag value buffer size      (12)
///   [4]  tag request/response size  (12 request; bit[31] set in response)
///   [5]  clock_id                   (CLOCK_ID_ARM)
///   [6]  rate_hz                    (ARM_FREQ_HZ in request; actual rate in response)
///   [7]  skip_turbo                 (1 = keep rate even in turbo mode)
///   [8]  end tag                    (0x0000_0000)
///
/// Alignment: 64 bytes (cache-line) so one DC CIVAC covers the full buffer.
#[cfg(feature = "rpi4")]
#[repr(C, align(64))]
struct MboxBuf([u32; 16]); // 64 bytes; only [0..=8] are used by the message

/// Static message buffer.
///
/// Safety invariant: written exclusively by CPU 0 inside `init_freq()`, which
/// runs before secondary cores are released.  No concurrent access is possible.
#[cfg(feature = "rpi4")]
static mut MBOX_BUF: MboxBuf = MboxBuf([0u32; 16]);

// ── Global state ──────────────────────────────────────────────────────────────

/// `true` once `init_freq()` has completed.
static CPUFREQ_LOCKED: AtomicBool = AtomicBool::new(false);

// ── Public API ────────────────────────────────────────────────────────────────

/// Lock the ARM core clock to prevent DVFS during hypervisor operation.
///
/// Must be called **once**, on the Management core (CPU 0), **after** the
/// Stage-1 MMU is enabled and **before** secondary cores are released.
///
/// # QEMU
/// Mailbox MMIO is not emulated.  Logs a no-op message and marks
/// `CPUFREQ_LOCKED` so the rest of the boot sequence proceeds normally.
///
/// # RPi4 (BCM2711, `--features rpi4`)
/// Sends a SET_CLOCK_RATE property message to the VideoCore firmware via
/// mailbox channel 8.  The firmware sets the ARM clock and holds it at the
/// requested rate (skip_turbo = 1 prevents DVFS from overriding the lock).
pub fn init_freq() {
    // ── QEMU path ─────────────────────────────────────────────────────────────
    #[cfg(not(feature = "rpi4"))]
    {
        writeln!(
            &mut &UART,
            "[freq] DVFS lock: QEMU no-op, assuming 1.0 GHz",
        )
        .ok();
        CPUFREQ_LOCKED.store(true, Ordering::Release);
    }

    // ── RPi4 path ─────────────────────────────────────────────────────────────
    // Safety:
    //   • MBOX_BUF is accessed only here, on CPU 0, before secondaries start.
    //   • MBOX_BASE..+0x24 is within the Device-nGnRnE block at 0xFE00_0000
    //     mapped by stage1.rs section 4-B; volatile reads/writes are safe.
    #[cfg(feature = "rpi4")]
    {
        // ── 1. Fill the message buffer ────────────────────────────────────────
        // Safety: single-threaded boot path; MBOX_BUF is not aliased.
        let buf_phys = core::ptr::addr_of_mut!(MBOX_BUF) as usize;
        unsafe {
            let p = buf_phys as *mut u32;
            p.add(0).write_volatile(9 * 4);           // total size = 36 bytes
            p.add(1).write_volatile(0x0000_0000);     // process request
            p.add(2).write_volatile(TAG_SET_CLOCK_RATE);
            p.add(3).write_volatile(12);              // value buffer size (3 × u32)
            p.add(4).write_volatile(12);              // request: bit[31]=0, size=12
            p.add(5).write_volatile(CLOCK_ID_ARM);
            p.add(6).write_volatile(ARM_FREQ_HZ);
            p.add(7).write_volatile(1);               // skip_turbo
            p.add(8).write_volatile(0x0000_0000);     // end tag
        }

        // ── 2. Clean D-cache → PoC so the VC DMA sees our writes ─────────────
        // One DC CIVAC at the 64-byte-aligned buffer address cleans the whole
        // buffer (Cortex-A72 cache line = 64 bytes; buffer fits in one line).
        unsafe {
            core::arch::asm!(
                "dc civac, {addr}",
                "dsb sy",
                addr = in(reg) buf_phys,
                options(nostack, preserves_flags),
            );
        }

        let mail0_rd  = MAIL0_RD  as *const u32;
        let mail0_sta = MAIL0_STA as *const u32;
        let mail1_wrt = MAIL1_WRT as *mut u32;
        let mail1_sta = MAIL1_STA as *const u32;

        // ── 3. Wait until MAIL1 (send side) is not full ───────────────────────
        unsafe {
            while (mail1_sta.read_volatile() & MBOX_FULL) != 0 {}
        }

        // ── 4. Send: buf_phys | channel 8 ────────────────────────────────────
        // Channel 8 (property tags) is the exception to the VC bus address
        // rule: physical address is passed directly (firmware wiki).
        // buf_phys is 64-byte aligned so bits[3:0] = 0 and channel fits.
        let msg = (buf_phys as u32) | MBOX_CH_PROP;
        unsafe {
            mail1_wrt.write_volatile(msg);
        }

        // ── 5. Wait for a response on channel 8 ──────────────────────────────
        unsafe {
            loop {
                while (mail0_sta.read_volatile() & MBOX_EMPTY) != 0 {}
                let r = mail0_rd.read_volatile();
                if (r & 0xF) == MBOX_CH_PROP {
                    break;
                }
                // Response was for a different channel; discard and retry.
            }
        }

        // ── 6. Invalidate D-cache so we read the firmware's response ─────────
        unsafe {
            core::arch::asm!(
                "dc civac, {addr}",
                "dsb sy",
                addr = in(reg) buf_phys,
                options(nostack, preserves_flags),
            );
        }

        // ── 7. Check response and log ─────────────────────────────────────────
        let resp_code   = unsafe { (buf_phys as *const u32).add(1).read_volatile() };
        let actual_rate = unsafe { (buf_phys as *const u32).add(6).read_volatile() };

        if resp_code == 0x8000_0000 {
            writeln!(
                &mut &UART,
                "[freq] DVFS locked via mailbox: ARM clock = {} Hz",
                actual_rate,
            )
            .ok();
        } else {
            writeln!(
                &mut &UART,
                "[freq] DVFS mailbox failed: resp = {:#010x}  proceeding",
                resp_code,
            )
            .ok();
        }

        CPUFREQ_LOCKED.store(true, Ordering::Release);
    }
}

/// Returns `true` if `init_freq()` has completed on this system.
///
/// Hot-path setup code that requires a stable core frequency (e.g. Stage-2
/// VM entry) should assert this is `true` before proceeding.
#[allow(dead_code)]
pub fn is_locked() -> bool {
    CPUFREQ_LOCKED.load(Ordering::Acquire)
}
