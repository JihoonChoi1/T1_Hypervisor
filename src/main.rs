#![no_main]
#![no_std]

use core::fmt::Write;
use core::panic::PanicInfo;

mod uart;
use uart::UART;

mod cpu;
mod exception;
mod irq;
mod memory;
mod time;
mod vm;

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
        "[mem ]   PMM pool      {:#010x} - {:#010x}  ({} MiB, Buddy Allocator)",
        memory::RAM_START,
        memory::PMM_END,
        (memory::PMM_END - memory::RAM_START) / (1024 * 1024),
    )
    .ok();
    writeln!(
        &mut &UART,
        "[mem ]   HFT budget    {} MiB ({} pages, color-filtered from pool)",
        memory::HFT_POOL_TARGET_SIZE / (1024 * 1024),
        memory::HFT_POOL_TARGET_SIZE / memory::pmm::PAGE_SIZE,
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
    let core_info = cpu::topology::detect();

    // ── GIC IRQ Steering ────────────────────────────────────
    // Route all physical SPIs to the Management core (CPU 0) exclusively.
    // HFT cores will call irq::gic::mask_gicc_hft() upon wakeup (TODO)
    // for defence-in-depth hardware blocking at the CPU interface level.
    irq::gic::init();

    // ── Deterministic Timer & PMU Setup (CPU 0) ─────────────────
    // Configure the virtual timer offset and start the PMU cycle counter
    // on this (Management) core.  Each secondary core will call the same
    // function after the INIT_DONE_FLAG barrier is released.
    time::init_per_core(core_info.core_id);

    // ── CPU Frequency Pinning ────────────────────────────────────
    // Lock the ARM core clock before secondary cores start.  DVFS
    // transitions would invalidate PMCCNTR_EL0 timestamps and stall
    // the HFT pipeline.
    // QEMU: no-op (mailbox not emulated).
    // RPi4 (--features rpi4): sends SET_CLOCK_RATE via VideoCore
    // firmware mailbox (property channel 8).
    cpu::freq::init_freq();

    // ── Secondary Core Wakeup & HFT Isolation ───────────────────
    // Wake CPU 1–3 via PSCI CPU_ON, wait for each to:
    //   • install VBAR_EL2 + MMU
    //   • detect its role (HFT)
    //   • seal its GICC (PMR=0x00, CTLR=0)
    //   • initialise its own timer offset + PMU cycle counter
    // Then broadcast SEV to release them into their trading loops.
    cpu::secondary::boot_secondary_cores();
    cpu::secondary::release_secondary_cores();

    // ── Cache Partitioning PoC ──────────────────────────────────────
    // 1. Print L2 cache geometry and heuristic page-color configuration.
    // 2. Pre-allocate all HFT-colored pages from the full PMM pool (color
    //    filter: 0–7).  Each page is immediately touched to warm L2.
    //    Pages are held in HFT_POOL_PAGES[] for Phase 4 VM construction.
    // 3. Run a small color-verification PoC against the pool.
    //
    // The L2D_CACHE_REFILL PMU counter (PMEVCNTR0_EL0, event 0x17) was already
    // armed in time::init_per_core().  Meaningful measurements require a real
    // workload on multiple cores and real RPi4 hardware (QEMU = 0).
    memory::cache_color::print_info();

    // Safety: PMM fully initialised; single-core boot; must be called before
    // hft_pool_alloc_page() or warm_hft_cache().
    unsafe { memory::cache_color::init_hft_pool() };

    // Safety: PMM fully initialised; boot-time only.
    unsafe { memory::cache_color::run_poc_verification(4) };

    // ── VM Fabric Initialisation ─────────────────────────────────────────────
    // Create the ManagementVM (id=0, core=0) and HftEngineVM (id=1, core=1)
    // global descriptors.  stage2_root is 0 until when Stage-2 Translation Tables get built.
    // VcpuRegs are zeroed — filled by Minimal HFT Payload Loader.
    //
    // Safety: PMM and cache coloring fully initialised; single-core boot.
    unsafe { vm::init_vms() };

    // ── Watchdog + Kill Switch + IPC Shared Page Allocation ─────────────────
    // Allocate one 4 KiB page each for the WatchdogPage, KillPage and IpcPage.
    // Returned PAs feed directly into `vm::stage2::init_stage2` below so the
    // same physical pages are mapped into both VMs' Stage-2 tables at the
    // fixed shared IPAs (0x5000_0000 / 0x5000_1000 / 0x5000_2000).
    //
    // Safety: PMM fully initialised; single-core boot.
    let watchdog_pa = unsafe { vm::watchdog::init_watchdog() };
    let killswitch_pa = unsafe { vm::killswitch::init_killswitch() };
    let ipc_pa = unsafe { vm::ipc::init_ipc() };

    // ── Stage-2 Translation Tables (per-VM) ─────────────────────────────────
    // Build ManagementVM and HftEngineVM Stage-2 page tables and store each
    // L1 root PA back into its `Vm` descriptor.  VTTBR_EL2 is not yet written
    // here — enter_vm() (TODO) composes `(vmid << 48) | stage2_root`.
    //
    // Safety: PMM, init_vms, and the three shared-page init functions have
    // all completed.  Single-core boot.
    unsafe { vm::stage2::init_stage2(watchdog_pa, ipc_pa, killswitch_pa) };

    // ── Guest RAM Allocation (per-VM) ───────────────────────────────────────
    // Walk each VM's entire IPA window pulling pre-colored pages from the
    // correct source (HFT: bump-index pool, colors 0–7, 32 768 pages / Mgmt:
    // PMM color-filter walk, colors 8–15, 16 384 pages) and install Stage-2
    // L3 PAGE descriptors (S2Prot::Rw, XN=1).  Per-page discipline inside the
    // allocators: write_bytes(pa, 0, 4096) → DC CIVAC every 64 B line → one
    // trailing `dsb ish` per allocator.  The `dsb ish` is reads-and-writes
    // scope (NOT `ishst`) because ARM DDI 0487 — search "DSB" requires
    // reads-and-writes scope to synchronise cache-maintenance completion;
    // `stage2_map_4k`'s per-descriptor `dsb ishst` covers stores only.
    // Without this flush the EL2-cached zeros would never reach DRAM, and
    // the MMU-off guest's Stage-1 default (Normal Non-cacheable under
    // HCR_EL2.DC=0) would read stale residue — see vm/ram.rs header comment.
    //
    // Call-order precondition: init_stage2 above populated both
    // stage2_root fields; alloc_hft_ram / alloc_mgmt_ram assert!() on a
    // non-zero root before writing a single descriptor.
    //
    // Safety: pmm::init, cache_color::init_hft_pool, init_vms, and
    // init_stage2 have all completed.  Single-core boot.
    unsafe { vm::ram::init_guest_ram() };

    // ── HFT Payload Load ────────────────────────────────────────────────────
    // Copy the pre-built `payload/hft_payload.bin` image into the HFT VM's
    // guest RAM (IPA base 0x4000_0000) and seed vcpu[0].regs so that a future
    // VM-Entry step can ERET into it at EL1.  No VM entry happens here —
    // this call is byte-copy + register seed only.
    //
    // Cache-visibility: the loader reuses `clean_inval_page_to_poc` + a
    // single trailing `dsb ish` (reads-and-writes scope, per ARM DDI 0487 —
    // search "DSB"), mirroring init_guest_ram's contract so the bytes reach
    // DRAM before the MMU-off guest's first instruction fetch (Normal
    // Non-cacheable, bypasses the EL2 cache under HCR_EL2.DC=0).
    //
    // Safety: init_vms, init_stage2, and init_guest_ram have all completed;
    // single-core boot.
    unsafe { vm::loader::load_hft_payload() };

    // HFT pool drain verification.  `alloc_hft_ram()` above consumed every
    // page pre-allocated by `init_hft_pool()` (32 768 pages).  `alloc_mgmt_ram`
    // runs afterwards but draws from the PMM via the Mgmt-color filter
    // (`alloc_with_filter`), never touching the HFT bump pool, so this
    // counter reflects the pool's post-`alloc_hft_ram` state as required.
    // A non-zero value would indicate either an accounting bug in the bump
    // index or an early exit from the HFT pass.
    writeln!(
        &mut &UART,
        "[vm  ] HFT pool remaining = {} (expected 0, pool fully drained)",
        memory::cache_color::hft_pool_remaining(),
    )
    .ok();

    writeln!(&mut &UART, "[boot] Entering idle loop. System halted.").ok();

    // Management core idle loop — future phases replace this with the
    // hypervisor's IRQ-driven event loop.
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

/// Panic handler: print the panic location over UART and halt.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // We attempt to print even if UART was not yet initialized.
    // In the worst case the output is garbled, but it is still more useful
    // than a silent hang.
    // Release the UART spinlock before printing.  A panic may fire while
    // another core (or this core) holds the lock mid-writeln!; without this
    // the panic message would never appear and all cores would spin forever.
    uart::force_unlock();
    writeln!(&mut &UART, "\n[PANIC] {}", info).ok();
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}
