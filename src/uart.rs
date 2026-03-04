//! PL011 UART driver for QEMU `virt` machine.
//!
//! The QEMU `virt` machine maps the PL011 UART to physical address 0x09000000.
//! This driver provides a minimal interface for early boot serial output.
//!
//! Reference: ARM PrimeCell UART (PL011) Technical Reference Manual

use core::fmt;

/// Base physical address of the PL011 UART on QEMU `virt` machine.
const PL011_BASE: usize = 0x0900_0000;

/// PL011 register offsets (in bytes from base address).
/// Each register is 32-bit wide.
mod regs {
    /// Data Register: write a byte here to transmit it.
    pub const DR: usize = 0x000;
    /// Flag Register: check this before writing to avoid overflowing the TX FIFO.
    pub const FR: usize = 0x018;
    /// Integer Baud Rate Register.
    pub const IBRD: usize = 0x024;
    /// Fractional Baud Rate Register.
    pub const FBRD: usize = 0x028;
    /// Line Control Register: configure data bits, parity, stop bits, FIFO enable.
    pub const LCR: usize = 0x02C;
    /// Control Register: enable TX, RX, and the UART overall.
    pub const CR: usize = 0x030;
}

/// Flag Register bits.
mod fr_bits {
    /// TX FIFO Full: if set, we must wait before writing to DR.
    pub const TXFF: u32 = 1 << 5;
}

/// A handle to the PL011 UART peripheral.
///
/// `Uart` is a zero-cost abstraction over raw MMIO registers.
/// In a single-core early boot context (which is where we use it),
/// it is safe to use without a mutex. Later phases will need to
/// wrap this in a spinlock-protected structure for SMP safety.
pub struct Uart {
    base: usize,
}

impl Uart {
    /// Creates a new Uart instance at the given MMIO base address.
    ///
    /// # Safety
    /// The caller must guarantee that `base` points to a valid, memory-mapped
    /// PL011 UART peripheral and that no other code is concurrently accessing
    /// those MMIO registers.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Reads a 32-bit value from the UART register at the given offset.
    #[inline]
    fn read_reg(&self, offset: usize) -> u32 {
        // SAFETY: We assume `self.base + offset` is a valid MMIO address.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    /// Writes a 32-bit value to the UART register at the given offset.
    #[inline]
    fn write_reg(&self, offset: usize, val: u32) {
        // SAFETY: We assume `self.base + offset` is a valid MMIO address.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, val) }
    }

    /// Initializes the UART peripheral.
    ///
    /// Sets baud rate to 115200 (assuming a 24 MHz UART clock, as used by QEMU),
    /// 8 data bits, no parity, 1 stop bit (8N1), with TX/RX FIFOs enabled.
    pub fn init(&self) {
        // 1. Disable the UART before reconfiguring it.
        self.write_reg(regs::CR, 0);

        // 2. Set baud rate to 115200.
        //    Divisor = UART_CLK / (16 * BAUD) = 24_000_000 / (16 * 115200) = 13.020833
        //    IBRD (integer part)    = 13
        //    FBRD (fractional part) = round(0.020833 * 64) = 1
        self.write_reg(regs::IBRD, 13);
        self.write_reg(regs::FBRD, 1);

        // 3. Configure: 8-bit words (WLEN=0b11), FIFO enabled (FEN=1).
        //    LCR_H[6:5] = WLEN = 0b11 (8 data bits)
        //    LCR_H[4]   = FEN  = 1    (enable TX/RX FIFOs)
        self.write_reg(regs::LCR, (0b11 << 5) | (1 << 4));

        // 4. Enable the UART, TX, and RX.
        //    CR[0]  = UARTEN = 1 (UART enable)
        //    CR[8]  = TXE    = 1 (Transmit enable)
        //    CR[9]  = RXE    = 1 (Receive enable)
        self.write_reg(regs::CR, (1 << 0) | (1 << 8) | (1 << 9));
    }

    /// Transmits a single byte, blocking until the TX FIFO has space.
    pub fn write_byte(&self, byte: u8) {
        // Spin-wait while the TX FIFO is full.
        while self.read_reg(regs::FR) & fr_bits::TXFF != 0 {
            core::hint::spin_loop();
        }
        self.write_reg(regs::DR, byte as u32);
    }

    /// Transmits a string of bytes.
    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            // Translate '\n' -> '\r\n' for serial terminals.
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

/// Implement `core::fmt::Write` for `&Uart` (a shared reference).
///
/// This is the canonical no_std pattern for global UART statics:
/// `writeln!(&mut &UART, ...)` mutably borrows the *reference*, not the
/// peripheral itself. Since all our MMIO operations only need `&self`,
/// this is correct and sound for single-core use.
impl fmt::Write for &Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Uart::write_str(self, s);
        Ok(())
    }
}

/// The global early-boot UART instance.
///
/// `UART` is used only before memory management and proper synchronization
/// primitives are set up. After SMP is enabled (Phase 6), it must be replaced
/// with a properly synchronized driver.
///
/// # Safety
/// Access to `UART` is safe during single-core boot (Phase 1~3) because only
/// CPU 0 runs at this point. SMP phases must add mutual exclusion.
pub static UART: Uart = unsafe { Uart::new(PL011_BASE) };
