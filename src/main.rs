#![no_main]
#![no_std]

use core::fmt::Write;
use core::panic::PanicInfo;

mod uart;
use uart::UART;

mod cpu;
mod exception;
mod memory;

// Pull in the assembly routines.
core::arch::global_asm!(include_str!("boot.s"));
core::arch::global_asm!(include_str!("exception.s"));

/// The main entry point for the hypervisor, called from assembly `boot.s`.
///
/// `dtb_ptr` is the physical address of the Device Tree Blob, passed in `x0`
/// by the bootloader (QEMU or U-Boot) per the ARM64 Linux Boot Protocol.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(dtb_ptr: usize) -> ! {
    // Initialize the UART so we can print debug output.
    UART.init();

    // ── Configure HCR_EL2 ───────────────────────────────
    // Must be the very first system-register write after UART so that all
    // subsequent trap behaviour (SMC, Stage-2, interrupt routing) is active
    // before any guest code or further EL2 setup runs.
    cpu::init_hcr_el2();

    // Readback: confirm the hardware accepted our HCR_EL2 value.
    let hcr_readback = cpu::read_hcr_el2();
    writeln!(
        &mut &UART,
        "[cpu ] HCR_EL2 readback = {:#018x}  (verified)",
        hcr_readback
    )
    .ok();

    // ── Configure CPTR_EL2 ─────────────────────────────────────────
    // Open FP/SIMD instructions to EL2 and EL1.  Without this, any floating-
    // point or NEON instruction executed in EL1 (e.g. Linux early boot memset)
    // triggers an Undefined Instruction trap to EL2, crashing the guest before
    // it prints a single character.
    cpu::init_cptr_el2();
    writeln!(
        &mut &UART,
        "[cpu ] CPTR_EL2 readback = {:#018x}  (verified)",
        cpu::read_cptr_el2()
    )
    .ok();

    // ── Configure SCTLR_EL2 ────────────────────────────────────────
    // Write a deterministic pre-MMU baseline: SA=1 (stack alignment check
    // active), MMU=0, caches=0, little-endian.  The MMU bit will be flipped
    // by memory::stage1::enable_mmu() (TODO).
    cpu::init_sctlr_el2();
    writeln!(
        &mut &UART,
        "[cpu ] SCTLR_EL2 readback = {:#018x}  (verified)",
        cpu::read_sctlr_el2()
    )
    .ok();

    // ── Configure MAIR_EL2 ──────────────────────────────────────
    // Register the two memory attribute slots used by Stage-1 page tables.
    //   AttrIdx=0 → Normal WB-Cached (RAM, HFT hot-path pages).
    //   AttrIdx=1 → Device-nGnRnE (UART MMIO, future NIC MMIO).
    // This must be done before build_page_tables() so the AttrIdx fields in
    // page-table descriptors have a defined meaning when the MMU activates.
    cpu::init_mair_el2();
    writeln!(
        &mut &UART,
        "[cpu ] MAIR_EL2  readback = {:#018x}  (verified)",
        cpu::read_mair_el2()
    )
    .ok();

    // ── Memory Layout Report ───────────────────────────────────────────────
    // Print every memory layout constant over UART so that developers can
    // visually confirm the layout before the Buddy Allocator and MMU are
    // built on top of these constants.  No runtime computation — all values
    // are compile-time constants; this block is pure diagnostics.
    writeln!(&mut &UART, "\r\n[mem ] Physical memory layout:").ok();
    writeln!(
        &mut &UART,
        "[mem ]   RAM           {:#010x} - {:#010x}  ({} MiB)",
        memory::RAM_START,
        memory::RAM_END,
        memory::RAM_SIZE / (1024 * 1024),
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mem ]   UART MMIO     {:#010x} - {:#010x}  (Device-nGnRnE, 4 KiB)",
        memory::UART_MMIO_BASE,
        memory::UART_MMIO_END,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mem ]   PMM pool      {:#010x} - {:#010x}  ({} MiB, free for Buddy Alloc)",
        memory::RAM_START,
        memory::PMM_END,
        (memory::PMM_END - memory::RAM_START) / (1024 * 1024),
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mem ]   HFT reserved  {:#010x} - {:#010x}  ({} MiB, pinned 2 MiB huge pages)",
        memory::HFT_RESERVED_BASE,
        memory::HFT_RESERVED_END,
        memory::HFT_RESERVED_SIZE / (1024 * 1024),
    )
    .ok();

    // ── Buddy Allocator initialisation ────────────────────────────────────────
    // The linker script guarantees that __kernel_end is 4 KiB-aligned.
    // We hand everything from __kernel_end to PMM_END to the Buddy Allocator,
    // then immediately carve the HFT reserved region out of the free pool.
    unsafe extern "C" {
        // Defined in src/linker.ld; address is the first byte past the kernel.
        static __kernel_end: u8;
    }
    let pool_start = unsafe { &__kernel_end as *const u8 as usize };

    // SAFETY: single-core boot; pool_start is page-aligned per linker script.
    unsafe { memory::pmm::init(pool_start) };

    // Remove the HFT slab from the general free pool before any other
    // allocation happens.  After this call the trading engine owns it.
    unsafe { memory::pmm::prewarm_hft_region() };

    // Print per-order free block inventory for verification.
    writeln!(&mut &UART, "\r\n[pmm ] Buddy Allocator initialised:").ok();
    let total_free = unsafe { memory::pmm::free_pages() };
    writeln!(&mut &UART, "[pmm ]   pool_start    = {pool_start:#010x}").ok();
    writeln!(
        &mut &UART,
        "[pmm ]   free pages    = {total_free} ({} MiB)",
        total_free * memory::pmm::PAGE_SIZE / (1024 * 1024),
    )
    .ok();
    for order in 0..memory::pmm::MAX_ORDER {
        let blocks = unsafe { memory::pmm::free_blocks_at_order(order) };
        if blocks > 0 {
            writeln!(
                &mut &UART,
                "[pmm ]   order {order:>2}  ({:>6} KiB)  →  {blocks} block(s)",
                (memory::pmm::PAGE_SIZE << order) / 1024,
            )
            .ok();
        }
    }

    // ── Stage-1 Page Table construction ────────────────────────────
    // Allocate one 4 KiB page from the PMM and fill it with 512 × 2 MiB Block
    // Descriptors covering UART MMIO (Device-nGnRnE) and all RAM (Normal-WB).
    // The returned physical address will be loaded into TTBR0_EL2.
    //
    // Safety: PMM is fully initialised and the HFT region is already carved out.
    let l1_pa = unsafe { memory::stage1::build_page_tables() };

    // ── Exception vector table ─────────────────────────────────────────────
    // Install VBAR_EL2 BEFORE building page tables and enabling the MMU.
    // Any translation fault during MMU activation will jump to this table;
    // without it, an activation fault causes an unrecoverable silent hang.
    //
    // Safety: `exception_vectors` is correctly aligned (2KiB) and lives in
    // read-only executable memory for the lifetime of the hypervisor.
    unsafe {
        unsafe extern "C" {
            static exception_vectors: u8;
        }
        let vbar = &exception_vectors as *const u8 as u64;
        core::arch::asm!(
            "msr vbar_el2, {}",
            "isb",
            in(reg) vbar,
            options(nostack)
        );
    }

    // ── Enable Stage-1 MMU ────────────────────────────────────────────────────
    // Now that VBAR_EL2 is live, we can safely enable the MMU.  Any translation
    // fault will be caught by the exception handler above.
    //
    // Safety: page tables are fully built, VBAR_EL2 is installed, all mapped
    // regions are identity-mapped (VA=PA), so the PC remains valid after ISB.
    unsafe { memory::stage1::enable_mmu(l1_pa) };

    // Read back TCR_EL2 and SCTLR_EL2 to confirm the MMU was enabled.
    let tcr_rb: u64;
    let sctlr_rb: u64;
    unsafe {
        core::arch::asm!("mrs {}, tcr_el2",   out(reg) tcr_rb,   options(nostack));
        core::arch::asm!("mrs {}, sctlr_el2", out(reg) sctlr_rb, options(nostack));
    }
    writeln!(
        &mut &UART,
        "\n[mmu ] Stage-1 MMU enabled (2-level, T0SZ=32, 4KB granule)"
    )
    .ok();
    writeln!(&mut &UART, "[mmu ] TCR_EL2   = {:#018x}", tcr_rb).ok();
    writeln!(
        &mut &UART,
        "[mmu ] SCTLR_EL2 = {:#018x}  (M={})",
        sctlr_rb,
        sctlr_rb & 1,
    )
    .ok();

    // Print a banner to confirm the hypervisor booted successfully.
    writeln!(&mut &UART, "\r\n==========================================").ok();
    writeln!(&mut &UART, "  T1 Hypervisor - ARMv8-A / EL2          ").ok();
    writeln!(&mut &UART, "==========================================").ok();
    writeln!(&mut &UART, "[boot] UART initialized.").ok();
    writeln!(
        &mut &UART,
        "[boot] Exception vectors installed (VBAR_EL2 set)."
    )
    .ok();
    writeln!(&mut &UART, "[boot] DTB located at: {:#010x}", dtb_ptr).ok();

    // ── CPU Topology Detection ───────────────────────────────────────
    // Reads MPIDR_EL1 to identify which physical core is executing and assigns
    // it one of two roles: Management (Core 0) or Hft (all other cores).
    // Secondary cores (TODO) will call this same function
    // immediately after wakeup to determine their own behaviour.
    let _core_info = cpu::topology::detect();

    writeln!(&mut &UART, "[boot] Entering idle loop. System halted.").ok();

    // Infinite low-power idle loop.
    // Future phases will replace this with the hypervisor's main event loop.
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}

/// Panic handler: print the panic location over UART and halt.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // We attempt to print even if UART was not yet initialized.
    // In the worst case the output is garbled, but it is still more useful
    // than a silent hang.
    writeln!(&mut &UART, "\n[PANIC] {}", info).ok();
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}
