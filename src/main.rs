#![no_main]
#![no_std]

use core::panic::PanicInfo;

// Pull in the assembly routine where execution starts.
core::arch::global_asm!(include_str!("boot.s"));

/// The main entry point for the hypervisor, called from assembly `boot.s`.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(_dtb_ptr: usize) -> ! {
    // I will initialize the UART here next to print something.

    // Infinite loop to keep the hypervisor running (for now, doing nothing).
    loop {
        // WFE (Wait For Event) puts the CPU into a low-power state until an event or interrupt occurs.
        unsafe { core::arch::asm!("wfe") };
    }
}

/// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        // On panic, just halt. Later I will print the panic message to UART.
        unsafe { core::arch::asm!("wfe") };
    }
}
