// ============================================================================
// memory/mod.rs - Hypervisor Physical Memory Layout Constants
//
// This module is the single source of truth for every physical address
// constant used by the hypervisor.  All values below are derived
// from:
//   • QEMU virt machine memory map (hw/arm/virt.c from https://github.com/qemu/qemu)
//   • ARM PrimeCell PL011 UART (DDI 0183) datasheet
//   • Our own linker script (src/linker.ld)
//
// AUTHORING RULE: never hard-code these addresses anywhere else.
// Every future module (PMM, MMU, GIC, vCPU) must import constants from here.
//
// Call order context (from kmain):
//   1. This module provides memory layout constants, no runtime code yet.
//   2. linker.ld provides ALIGN(4096) guard before __kernel_end.
//   3. pmm.rs builds the Buddy Allocator on top of these constants.
//   4. stage1.rs uses these ranges for MMU page tables.
// ============================================================================

pub mod cache_color;
pub mod pmm;
pub mod stage1;

// ── Physical RAM ─────────────────────────────────────────────────────────────
//
// QEMU virt: the primary RAM bank starts at GPA 0x4000_0000.
// With `-m 1024` (the default 1 GiB QEMU virt config) it extends exactly
// 1 GiB to 0x8000_0000.  Our linker loads the kernel at BASE_ADDRESS
// (0x4008_0000), leaving the first 512 KiB for the DTB passed in x0.
//
// Reference: QEMU hw/arm/virt.c, `virt_memmap[]`, entry MEM.

/// First byte of physical RAM on the QEMU virt machine.
pub const RAM_START: usize = 0x4000_0000;

/// One-past-the-last byte of physical RAM (exclusive upper bound).
/// With the default `-m 1024` flag this equals RAM_START + 1 GiB.
pub const RAM_END: usize = 0x8000_0000;

/// Total physical RAM available, in bytes.
pub const RAM_SIZE: usize = RAM_END - RAM_START; // 1 GiB

// ── UART (PL011) MMIO ────────────────────────────────────────────────────────
//
// The QEMU virt machine places the first PL011 UART at 0x0900_0000.
// This is a Device-nGnRnE region (strongly ordered, non-cacheable) and must
// be mapped as such in the Stage-1 page tables.
//
// WARNING: caching this address (MAIR Normal-WB) would cause writes to be
// buffered and UART output would disappear.  The MMU mapping MUST use the
// Device memory attribute for this region.
//
// Reference: QEMU hw/arm/virt.c, `virt_memmap[]`, entry UART.

/// Base address of PL011 UART0 MMIO region.
pub const UART_MMIO_BASE: usize = 0x0900_0000;

/// Size of the PL011 UART0 MMIO region (4 KiB — one page, sufficient for all
/// PL011 registers which end at offset 0xFFC).
pub const UART_MMIO_SIZE: usize = 0x1000; // 4 KiB

/// One-past-the-last byte of the UART MMIO region (exclusive).
pub const UART_MMIO_END: usize = UART_MMIO_BASE + UART_MMIO_SIZE;

// ── GICv2 (Generic Interrupt Controller v2) MMIO ─────────────────────────────
//
// QEMU virt places a GICv2 (`arm,cortex-a15-gic`) at fixed addresses.
// Confirmed from `qemu-system-aarch64 -machine virt,virtualization=on
// -machine dumpdtb=... | dtc`, which reports:
//
//   reg = <0x00 0x8000000 0x00 0x10000   ← GICD (64 KiB)
//          0x00 0x8010000 0x00 0x10000   ← GICC (64 KiB, virtual CPU I/F)
//          0x00 0x8030000 0x00 0x10000   ← GICH (hypervisor ctrl, 64 KiB)
//          0x00 0x8040000 0x00 0x10000>  ← GICV (virtual GICC, 64 KiB)
//
// These regions are Device-nGnRnE — never cache, never reorder.
// These addresses must be explicitly mapped in the MMU stage-1 page tables
// as Device memory before being accessed.
//
// Reference: ARM IHI0048B "ARM GIC Architecture Specification v2.0".

/// Base address of the GICv2 Distributor (GICD) MMIO region.
pub const GICD_BASE: usize = 0x0800_0000;

/// Size of the GICD MMIO region (64 KiB).
#[allow(dead_code)]
pub const GICD_SIZE: usize = 0x10000;

/// Base address of the GICv2 CPU Interface (GICC) MMIO region.
pub const GICC_BASE: usize = 0x0801_0000;

/// Size of the GICC MMIO region (64 KiB).
#[allow(dead_code)]
pub const GICC_SIZE: usize = 0x10000;

// ── HFT Engine Memory Budget ──────────────────────────────────────────────────
//
// HFT and Management pages are separated by **page coloring**, not by a fixed
// physical address range.  The Buddy Allocator manages the entire RAM from
// __kernel_end to RAM_END; HFT pages are obtained via
// `cache_color::alloc_hft_page()` (colors 0–7) and Management pages via
// `cache_color::alloc_mgmt_page()` (colors 8–15).
//
// Having a dedicated fixed address range for HFT is not needed and would waste
// ~50 % of the reserved pages (those whose page color falls in the Management
// range) while hiding them from both workloads.
//
// Sizing rationale for HFT_POOL_TARGET_SIZE (128 MiB):
//   - Binary image + BSS          ~1 MiB
//   - Order book ring buffers      ~8 MiB × 8 instruments = 64 MiB
//   - Market-data / feed buffers  ~16 MiB
//   - Pre-allocated message arenas~32 MiB
//   - Strategy headroom            ~8 MiB
//   Total: ~129 MiB → rounded to 128 MiB (32768 × 4 KiB pages).
//
// Pages are allocated one at a time via `cache_color::alloc_hft_page()` during
// VM construction (TODO) and mapped into the HFT VM's Stage-2
// page tables.  This means HFT pages are scattered through RAM but all share
// cache colors 0–7, providing the L2 set separation heuristic.

/// Target physical memory budget for the HFT trading engine, in bytes.
///
/// Used by VM construction to know how many colored pages to allocate.
/// There is no fixed base address — pages are scattered through RAM and
/// identified solely by `cache_color::color_of(pa) < 8`.
pub const HFT_POOL_TARGET_SIZE: usize = 128 * 1024 * 1024; // 128 MiB

// ── General Allocator Region ─────────────────────────────────────────────────
//
// The Buddy Allocator manages ALL memory from __kernel_end to RAM_END.
// No sub-range is permanently carved out at boot.  Color filtering at
// allocation time (cache_color::alloc_hft_page / alloc_mgmt_page) provides
// the HFT ↔ Management cache separation without wasting half the pool.

/// Upper bound of the physical memory pool managed by the Buddy Allocator.
///
/// Equals RAM_END: the entire RAM (minus the kernel image) is available.
/// HFT and Management pages are separated by page color at allocation time.
pub const PMM_END: usize = RAM_END;

// ── BCM2711 Peripheral High MMIO (RPi4 only) ─────────────────────────────────
//
// The BCM2711 high peripheral block starts at ARM physical 0xFE00_0000.
// This includes the VideoCore mailbox (0xFE00_B880) used for firmware
// property-tag requests (SET_CLOCK_RATE, etc.).
//
// stage1.rs maps the containing 2 MiB block (0xFE00_0000) as Device-nGnRnE
// using MBOX_MMIO_BASE as the anchor address.
//
// This region is NOT present on the QEMU virt machine; all paths that access
// it are compiled only when `--features rpi4` is set.
//
// Reference: raspberrypi/firmware wiki "Accessing mailboxes";
//            bcm283x.dtsi (compatible = "brcm,bcm2835-mbox", reg = 0x7e00b880);
//            bcm2711.dtsi (ranges = <0x7e000000 0x0 0xfe000000 ...>)
//              → VC bus 0x7E00_B880 maps to ARM physical 0xFE00_B880.

/// Base address of the BCM2711 VideoCore mailbox MMIO region (ARM physical).
/// Bus address 0x7E00_B880 maps to ARM physical 0xFE00_B880 on BCM2711.
/// stage1.rs aligns this down to the 2 MiB block (0xFE00_0000) for mapping.
#[cfg(feature = "rpi4")]
pub const MBOX_MMIO_BASE: usize = 0xFE00_B880;

// ── Compile-time Sanity Checks ───────────────────────────────────────────────
//
// These assertions are evaluated at compile time by the Rust compiler.
// A failure here means the constants are internally inconsistent and the
// binary will not compile.  No runtime overhead.

const _: () = {
    assert!(RAM_START < RAM_END, "RAM_START must be below RAM_END");
    assert!(RAM_SIZE == 1 << 30, "RAM_SIZE must be exactly 1 GiB");
    assert!(PMM_END == RAM_END, "PMM_END must equal RAM_END");
    assert!(UART_MMIO_BASE < RAM_START, "UART MMIO must be outside RAM");
    assert!(
        HFT_POOL_TARGET_SIZE % (2 * 1024 * 1024) == 0,
        "HFT_POOL_TARGET_SIZE must be a multiple of 2 MiB (huge-page boundary)"
    );
};
