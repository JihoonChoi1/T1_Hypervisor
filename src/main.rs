#![no_main]
#![no_std]

use core::fmt::Write;
use core::panic::PanicInfo;

mod uart;
use uart::UART;

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
