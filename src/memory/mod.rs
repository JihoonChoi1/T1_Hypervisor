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

// ── HFT Engine Reserved Region ───────────────────────────────────────────────
//
// A contiguous region of physical RAM exclusively reserved for the HFT
// trading engine VM.  This region is:
//
//   • Pre-allocated at hypervisor boot. (TODO)
//   • Never returned to the general Buddy Allocator free pool.
//   • Mapped with 2 MiB huge pages and WB-Cached attributes. (TODO)
//   • Pinned: the MMU entry is never evicted from the TLB while trading runs.
//   • Zero runtime allocation: the entire HFT heap is carved from here at
//     init and divided into fixed-size arenas.  No malloc on the hot path.
//
// Sizing rationale:
//   128 MiB gives the HFT engine VM enough room for:
//     - Its binary image and BSS (~1 MiB)
//     - Order book ring buffers              (~8 MiB per instrument, ×8 = 64 MiB)
//     - Market data / feed parser buffers    (~16 MiB)
//     - Pre-allocated message arenas         (~32 MiB)
//     - Headroom for future strategy growth  (~8 MiB)
//   Total: ~129 MiB → rounded up to 128 MiB for huge-page alignment.
//
// Placement: top 128 MiB of RAM_END.
//   - Keeps it far from the kernel image at RAM_START+offset.
//   - Keeps it far from the Management VM's Stage-2 region, which will grow
//     upward from just above __kernel_end.

/// Size of the HFT Engine's exclusive physical memory reservation, in bytes.
pub const HFT_RESERVED_SIZE: usize = 128 * 1024 * 1024; // 128 MiB

/// First byte of the HFT reserved region (placed at the top of RAM).
pub const HFT_RESERVED_BASE: usize = RAM_END - HFT_RESERVED_SIZE; // 0x7800_0000

/// One-past-the-last byte of the HFT reserved region (== RAM_END).
pub const HFT_RESERVED_END: usize = RAM_END; // 0x8000_0000

// ── General Allocator Region ─────────────────────────────────────────────────
//
// The Buddy Allocator manages the memory between the end
// of the kernel image and the start of the HFT reserved region.
//
// __kernel_end is a linker-script symbol; its runtime value is used by
// pmm::BuddyAllocator::init() as the lower bound.  We define the upper bound
// here so that pmm.rs does not need to import HFT_RESERVED_BASE directly —
// it imports PMM_END instead, keeping the dependency graph clean.

/// Upper bound of the general-purpose physical memory pool managed by the
/// Buddy Allocator.  Memory from `__kernel_end` up to (but not including)
/// this address is available for Management VM, page tables, and kernel heap.
pub const PMM_END: usize = HFT_RESERVED_BASE; // 0x7800_0000

// ── Compile-time Sanity Checks ───────────────────────────────────────────────
//
// These assertions are evaluated at compile time by the Rust compiler.
// A failure here means the constants are internally inconsistent and the
// binary will not compile.  No runtime overhead.

const _: () = {
    assert!(RAM_START < RAM_END, "RAM_START must be below RAM_END");
    assert!(RAM_SIZE == 1 << 30, "RAM_SIZE must be exactly 1 GiB");
    assert!(
        HFT_RESERVED_BASE >= RAM_START,
        "HFT region must be within RAM"
    );
    assert!(
        HFT_RESERVED_END == RAM_END,
        "HFT region must end at RAM_END"
    );
    assert!(
        HFT_RESERVED_SIZE % (2 * 1024 * 1024) == 0,
        "HFT_RESERVED_SIZE must be a multiple of 2 MiB (huge-page boundary)"
    );
    assert!(
        PMM_END == HFT_RESERVED_BASE,
        "PMM_END must equal HFT_RESERVED_BASE"
    );
    assert!(UART_MMIO_BASE < RAM_START, "UART MMIO must be outside RAM");
};
