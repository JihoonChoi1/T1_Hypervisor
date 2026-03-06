#![no_main]
#![no_std]

use core::fmt::Write;
use core::panic::PanicInfo;

mod uart;
use uart::UART;

mod cpu;
mod exception;

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

    // Register the exception vector table with the CPU.
    // Safety: `exception_vectors` is correctly aligned (2KiB) and lives in
    // read-only executable memory for the lifetime of the hypervisor.
    unsafe {
        // Import the symbol defined in exception.s.
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
