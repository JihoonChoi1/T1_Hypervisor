// ============================================================================
// exception.rs — EL2 Exception Handlers
//
// Each public function in this file is called from the assembly entry stubs
// in exception.s after the CPU registers have been saved onto the stack.
//
// ExceptionFrame is laid out to exactly match the SAVE_CONTEXT macro:
//   x0–x29, x30 (LR), sp_el0, elr_el2, spsr_el2  →  272 bytes total
// ============================================================================

use crate::uart::UART;
use core::fmt::Write;

/// A snapshot of the CPU state at the moment an exception was taken.
///
/// The layout MUST match the SAVE_CONTEXT macro in exception.s exactly.
/// Any change here requires a matching change there and vice-versa.
#[repr(C)]
pub struct ExceptionFrame {
    pub gpr: [u64; 31], // x0–x30 (gpr[30] = LR)
    pub sp_el0: u64,    // stack pointer of EL0 at exception entry
    pub elr_el2: u64,   // exception return address (faulting PC)
    pub spsr_el2: u64,  // saved program status (PSTATE at entry)
}

// ── ESR_EL2 field helpers ─────────────────────────────────────────────────────

/// Extract Exception Class (EC) from ESR_EL2: bits [31:26].
#[inline]
fn esr_ec(esr: u64) -> u64 {
    (esr >> 26) & 0x3f
}

/// Extract Instruction Length (IL) from ESR_EL2: bit 25.
/// 0 = 16-bit (Thumb/T32), 1 = 32-bit AArch64 instruction.
#[inline]
fn esr_il(esr: u64) -> u64 {
    (esr >> 25) & 0x1
}

/// Extract Instruction-Specific Syndrome (ISS) from ESR_EL2: bits [24:0].
#[inline]
fn esr_iss(esr: u64) -> u64 {
    esr & 0x01ff_ffff
}

/// Map the 6-bit Exception Class value to a human-readable description.
///
/// Values are taken directly from the ARMv8-A Architecture Reference Manual,
/// Table D17-2 ("ESR_ELx EC field values").
fn ec_description(ec: u64) -> &'static str {
    match ec {
        0x00 => "Unknown reason",
        0x01 => "Trapped WFI / WFE instruction",
        0x03 => "Trapped MCR/MRC (AArch32)",
        0x04 => "Trapped MCRR/MRRC (AArch32)",
        0x05 => "Trapped MCR/MRC (AArch32, CRn=c14)",
        0x06 => "Trapped LDC/STC (AArch32)",
        0x07 => "SVE / Advanced SIMD / FP access trap",
        0x08 => "VMRS access trap (AArch32)",
        0x09 => "Pointer Authentication trap",
        0x0a => "Trapped LD64B / ST64B* instruction",
        0x0c => "Trapped MRRC (AArch32, opc1=0b01cc)",
        0x0d => "Branch Target Exception",
        0x0e => "Illegal Execution State",
        0x11 => "SVC from AArch32 (EL1)",
        0x12 => "HVC from AArch32 (EL1)",
        0x13 => "SMC from AArch32 (EL1)",
        0x15 => "SVC from AArch64 (EL1)",
        0x16 => "HVC from AArch64 (EL1)",
        0x17 => "SMC from AArch64 (EL1)",
        0x18 => "Trapped system register access (MSR/MRS/SYS)",
        0x19 => "SVE access trap",
        0x1a => "ERET / ERETAx / ERETAB trap",
        0x1c => "PAC failure",
        0x1f => "Implementation-defined (EL3)",
        0x20 => "Instruction Abort from lower EL (Stage-1 or Stage-2 fault)",
        0x21 => "Instruction Abort from current EL",
        0x22 => "PC alignment fault",
        0x24 => "Data Abort from lower EL (Stage-1 or Stage-2 fault)",
        0x25 => "Data Abort from current EL",
        0x26 => "SP alignment fault",
        0x28 => "Trapped FP exception (AArch32)",
        0x2c => "Trapped FP exception (AArch64)",
        0x2f => "SError interrupt",
        0x30 => "Breakpoint from lower EL",
        0x31 => "Breakpoint from current EL",
        0x32 => "Software Step from lower EL",
        0x33 => "Software Step from current EL",
        0x34 => "Watchpoint from lower EL",
        0x35 => "Watchpoint from current EL",
        0x38 => "BKPT (AArch32)",
        0x3a => "Vector Catch (AArch32)",
        0x3c => "BRK instruction (AArch64)",
        _ => "Reserved / unrecognised EC",
    }
}

// ── Data/Instruction Abort ISS helpers ───────────────────────────────────────

/// Fault Status Code (DFSC/IFSC) — ISS bits [5:0].
/// Describes the *cause* of an address-translation fault.
fn fsc_description(fsc: u64) -> &'static str {
    match fsc {
        0x00 => "Address size fault, level 0",
        0x01 => "Address size fault, level 1",
        0x02 => "Address size fault, level 2",
        0x03 => "Address size fault, level 3",
        0x04 => "Translation fault, level 0",
        0x05 => "Translation fault, level 1",
        0x06 => "Translation fault, level 2",
        0x07 => "Translation fault, level 3",
        0x08 => "Access flag fault, level 0",
        0x09 => "Access flag fault, level 1",
        0x0a => "Access flag fault, level 2",
        0x0b => "Access flag fault, level 3",
        0x0c => "Permission fault, level 0",
        0x0d => "Permission fault, level 1",
        0x0e => "Permission fault, level 2",
        0x0f => "Permission fault, level 3",
        0x10 => "Synchronous External Abort (not on page-table walk)",
        0x11 => "Synchronous Tag Check Fault",
        0x13 => "Synchronous External Abort on level 0 table walk",
        0x14 => "Synchronous External Abort on level 1 table walk",
        0x15 => "Synchronous External Abort on level 2 table walk",
        0x16 => "Synchronous External Abort on level 3 table walk",
        0x18 => "Synchronous Parity/ECC error (not on page-table walk)",
        0x1b => "Synchronous Parity/ECC error on level 1 table walk",
        0x1c => "Synchronous Parity/ECC error on level 2 table walk",
        0x1d => "Synchronous Parity/ECC error on level 3 table walk",
        0x21 => "Alignment fault",
        0x30 => "TLB Conflict Abort",
        0x31 => "Unsupported atomic hardware update fault",
        0x34 => "IMPLEMENTATION DEFINED fault (lockdown)",
        0x35 => "IMPLEMENTATION DEFINED fault (unsupported exclusive)",
        _ => "Reserved / unrecognised FSC",
    }
}

/// Print a detailed decode of a Data Abort or Instruction Abort ISS field.
fn print_abort_iss(iss: u64, is_data_abort: bool) {
    let fsc = iss & 0x3f;
    writeln!(
        &mut &UART,
        "    FSC      = {:#04x}  ({})",
        fsc,
        fsc_description(fsc)
    )
    .ok();
    if is_data_abort {
        let wnr = (iss >> 6) & 1; // 1 = write fault, 0 = read fault
        let s1ptw = (iss >> 7) & 1; // 1 = fault on Stage-1 page table walk
        let cm = (iss >> 8) & 1; // 1 = cache maintenance instruction
        let ea = (iss >> 9) & 1; // 1 = external abort type
        writeln!(
            &mut &UART,
            "    WnR      = {}  ({})",
            wnr,
            if wnr == 1 { "write" } else { "read" }
        )
        .ok();
        writeln!(
            &mut &UART,
            "    S1PTW    = {}  ({})",
            s1ptw,
            if s1ptw == 1 {
                "Stage-1 PTW fault"
            } else {
                "not a PTW"
            }
        )
        .ok();
        writeln!(
            &mut &UART,
            "    CM       = {}  ({})",
            cm,
            if cm == 1 {
                "cache maintenance"
            } else {
                "normal"
            }
        )
        .ok();
        writeln!(
            &mut &UART,
            "    EA       = {}  ({})",
            ea,
            if ea == 1 {
                "external abort"
            } else {
                "internal"
            }
        )
        .ok();
    }
}

// ── Common dump routine ───────────────────────────────────────────────────────

/// Print a complete register dump and ESR_EL2 decode over UART.
fn dump_exception(label: &str, frame: &ExceptionFrame, esr: u64, far: u64) {
    let ec = esr_ec(esr);
    let il = esr_il(esr);
    let iss = esr_iss(esr);

    writeln!(
        &mut &UART,
        "\n╔══════════════════════════════════════════════╗"
    )
    .ok();
    writeln!(&mut &UART, "║  HYPERVISOR EXCEPTION: {:24} ║", label).ok();
    writeln!(
        &mut &UART,
        "╚══════════════════════════════════════════════╝"
    )
    .ok();

    // ESR decode
    writeln!(
        &mut &UART,
        "\n── ESR_EL2 decode ──────────────────────────────"
    )
    .ok();
    writeln!(&mut &UART, "  ESR_EL2  = {:#018x}", esr).ok();
    writeln!(
        &mut &UART,
        "    EC     = {:#04x}  ({})",
        ec,
        ec_description(ec)
    )
    .ok();
    writeln!(
        &mut &UART,
        "    IL     = {}  ({}-bit instruction)",
        il,
        if il == 1 { 32 } else { 16 }
    )
    .ok();
    writeln!(&mut &UART, "    ISS    = {:#09x}", iss).ok();

    // Abort-specific ISS decode
    if ec == 0x20 || ec == 0x21 {
        // Instruction Abort
        print_abort_iss(iss, false);
    } else if ec == 0x24 || ec == 0x25 {
        // Data Abort
        print_abort_iss(iss, true);
    }

    // Fault / exception context
    writeln!(
        &mut &UART,
        "\n── Exception context ───────────────────────────"
    )
    .ok();
    writeln!(
        &mut &UART,
        "  ELR_EL2  = {:#018x}  ← faulting PC",
        frame.elr_el2
    )
    .ok();
    writeln!(&mut &UART, "  SPSR_EL2 = {:#018x}", frame.spsr_el2).ok();
    writeln!(&mut &UART, "  FAR_EL2  = {:#018x}  ← faulting address", far).ok();
    writeln!(&mut &UART, "  SP_EL0   = {:#018x}", frame.sp_el0).ok();

    // General-purpose registers
    writeln!(
        &mut &UART,
        "\n── General-purpose registers ───────────────────"
    )
    .ok();
    for i in (0..30).step_by(2) {
        writeln!(
            &mut &UART,
            "  x{:<2} = {:#018x}    x{:<2} = {:#018x}",
            i,
            frame.gpr[i],
            i + 1,
            frame.gpr[i + 1]
        )
        .ok();
    }
    // x30 (LR) is at gpr[30]
    writeln!(&mut &UART, "  x30 = {:#018x}  (LR)", frame.gpr[30]).ok();
    writeln!(
        &mut &UART,
        "────────────────────────────────────────────────"
    )
    .ok();
}

// ── Public handlers (called from exception.s via bl) ─────────────────────────

/// Synchronous exception taken *at EL2* (SP_ELx group, entry 4).
///
/// Fires when the hypervisor itself causes a fault — almost always a bug.
/// Examples: misaligned access, undefined instruction, data abort in EL2 code.
///
/// # Safety
/// Called directly from assembly. `frame` points to a valid ExceptionFrame
/// on the EL2 stack. The function is `extern "C"` to match the `bl` ABI.
#[unsafe(no_mangle)]
pub extern "C" fn el2_sync_handler(frame: &ExceptionFrame) -> ! {
    let esr: u64;
    let far: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el2", out(reg) esr, options(nostack, nomem));
        core::arch::asm!("mrs {}, far_el2", out(reg) far, options(nostack, nomem));
    }
    dump_exception("Synchronous (EL2)", frame, esr, far);
    writeln!(
        &mut &UART,
        "[EXCEPTION] System halted — this is unrecoverable."
    )
    .ok();
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}

/// SError (System Error / bus fault) taken *at EL2* (entry 7).
///
/// Asynchronous external abort — usually ECC memory errors or bad MMIO.
///
/// # Safety
/// Same contract as `el2_sync_handler`.
#[unsafe(no_mangle)]
pub extern "C" fn el2_serror_handler(frame: &ExceptionFrame) -> ! {
    let esr: u64;
    unsafe {
        core::arch::asm!("mrs {}, esr_el2", out(reg) esr, options(nostack, nomem));
    }
    // SError has no FAR.
    dump_exception("SError (EL2)", frame, esr, 0);
    writeln!(
        &mut &UART,
        "[EXCEPTION] System halted — this is unrecoverable."
    )
    .ok();
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}
