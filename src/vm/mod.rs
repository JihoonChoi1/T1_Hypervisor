// ============================================================================
// vm/mod.rs — Vm + Vcpu data structures
#![allow(dead_code)] // Public API consumed by later steps; suppress until then.
//
// Defines the top-level guest VM and vCPU types used throughout Guest VM Fabric implementation.
// All subsequent steps (Stage-2 tables, RAM allocation, payload loading,
// context switch assembly) build on top of the types defined here.
//
// References:
//   EL1 sysreg list:  Linux KVM arch/arm64/kvm/sys_regs.c (torvalds/linux)
//                     14 registers (sctlr..par) confirmed in read/write_sr_from/to_cpu()
//                     via SYS_*_EL12 mappings. sp_el0 confirmed saved in
//                     __guest_enter assembly at CPU_SP_EL0_OFFSET=CPU_XREG_OFFSET(30)+8
//                     ([PATCH] KVM: arm64: Save/restore sp_el0 as part of __guest_enter).
//   repr(C) layout:   https://doc.rust-lang.org/reference/type-layout.html
//                     Field offset algorithm: pad each field to its own alignment,
//                     then struct size rounded to struct alignment.
//   offset_of!:       core::mem::offset_of! stable since Rust 1.77.0.
//                     RFC 3308: "expands to a constant expression of type usize"
//                     → usable in const assertions. Available in core (no_std ok).
//   u128 alignment:   aarch64-unknown-none datalayout (rustc_target/spec):
//                     "e-m:e-...-i128:128-..." → i128:128 means ABI align = 16 B.
//                     Therefore #[repr(C, align(16))] on VcpuFpRegs is REDUNDANT
//                     (u128 already forces 16-byte alignment) but kept for explicit
//                     documentation of the hardware Q-register requirement.
//   Q registers:      AAPCS64 §6.1.2 — each Vn register is 128-bit wide.
//                     v0–v31 each accessible as Q (128b), D (64b), S (32b), H (16b), B (8b).
//   ELR/SPSR:         ARM ARM DDI 0487 — on exception entry to EL2:
//                       ELR_EL2  ← address of interrupted guest instruction
//                       SPSR_EL2 ← PSTATE at time of exception
//   Global pattern:   addr_of_mut!(STATIC) — Rust 2024 static_mut_refs.
//                     Consistent with memory/pmm.rs usage.
// ============================================================================

pub mod ipc;
pub mod killswitch;
pub mod watchdog;

use core::fmt::Write;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use crate::uart::UART;

// ── VM Role ───────────────────────────────────────────────────────────────────

/// Role of a VM in the HFT hypervisor architecture.
///
/// - `Management`: runs on CPU 0. Owns UART, GIC IRQs, risk controls,
///   watchdog supervision. Interrupt-driven event loop.
/// - `HftEngine`: runs on CPUs 1, 2, and 3. Interrupt-free, dedicated trading engine
///   cluster for parallel workload execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmType {
    Management,
    HftEngine,
}

// ── FP / SIMD Register State ──────────────────────────────────────────────────

/// Floating-point and SIMD register state for one vCPU.
///
/// Covers v0–v31 accessed as 128-bit Q views (AAPCS64 §6.1.2: each Vn = 128-bit),
/// plus FPSR and FPCR status/control registers.
///
/// Alignment rationale:
///   `u128` on `aarch64-unknown-none` has ABI alignment of **16 bytes** per the
///   LLVM datalayout string `i128:128` (rust/compiler/rustc_target/src/spec/targets/aarch64_unknown_none.rs).
///   Therefore `VcpuFpRegs` already has 16-byte natural alignment from `[u128; 32]`,
///   and `#[repr(C, align(16))]` is technically redundant.  It is kept explicitly
///   to document the hardware LD1/ST1 Q-register alignment requirement and to guard
///   against any future target change.  Either way, the compiler inserts 8 bytes of
///   padding before `fp` in `VcpuRegs` (sys ends at offset 392; next 16-byte
///   boundary is 400).
///
/// Size: 32 × 16 + 8 + 8 = **528 bytes**.
#[repr(C, align(16))]
pub struct VcpuFpRegs {
    /// v0–v31: 32 × 128-bit Q registers. 512 bytes.
    pub q: [u128; 32],
    /// Floating-Point Status Register. Upper 32 bits are RES0; stored as u64.
    pub fpsr: u64,
    /// Floating-Point Control Register. Upper 32 bits are RES0; stored as u64.
    pub fpcr: u64,
}

// ── EL1 System Registers ──────────────────────────────────────────────────────

/// EL1 system registers saved and restored on every vCPU context switch.
///
/// Register list verified against Linux KVM arm64 sources:
///   - 14 registers (sctlr_el1 through par_el1, excl. sp_el0) present in
///     `read_sr_from_cpu()` / `write_sr_to_cpu()` in arch/arm64/kvm/sys_regs.c
///     via SYS_*_EL12 mappings (VHE EL1→EL12 redirect).
///   - sp_el0: saved in `__guest_enter` assembly at CPU_SP_EL0_OFFSET =
///     CPU_XREG_OFFSET(30)+8 in kvm_cpu_context. KVM patch note: "host
///     arm64 Linux uses sp_el0 to point to 'current' and it must be
///     saved/restored on every entry/exit to/from the guest." Grouped here
///     in VcpuSysRegs; accessed via MSR/MRS SP_EL0.
///
/// Size: 15 × 8 = **120 bytes**. Alignment: 8 bytes.
#[repr(C)]
pub struct VcpuSysRegs {
    pub sctlr_el1: u64,      // System Control Register EL1
    pub ttbr0_el1: u64,      // Translation Table Base Register 0 EL1
    pub ttbr1_el1: u64,      // Translation Table Base Register 1 EL1
    pub tcr_el1: u64,        // Translation Control Register EL1
    pub mair_el1: u64,       // Memory Attribute Indirection Register EL1
    pub amair_el1: u64,      // Auxiliary Memory Attribute Indirection Register EL1
    pub vbar_el1: u64,       // Vector Base Address Register EL1
    pub contextidr_el1: u64, // Context ID Register EL1
    pub tpidr_el0: u64,      // Thread ID Register EL0 (user RW)
    pub tpidrro_el0: u64,    // Thread ID Register EL0 (user RO)
    pub tpidr_el1: u64,      // Thread ID Register EL1
    pub sp_el0: u64,         // Stack Pointer EL0
    pub esr_el1: u64,        // Exception Syndrome Register EL1
    pub far_el1: u64,        // Fault Address Register EL1
    pub par_el1: u64,        // Physical Address Register EL1 (AT instruction result)
}

// ── Full vCPU Register State ──────────────────────────────────────────────────

/// Complete vCPU register state: saved on VM exit, restored on VM entry.
///
/// `#[repr(C)]` is mandatory — later assembly uses the VCPU_REGS_*_OFFSET
/// constants below as literal byte offsets into this struct.
///
/// Field layout (ARM ARM DDI 0487 — exception entry to EL2):
///   ELR_EL2  → `pc`     (address of interrupted guest instruction)
///   SPSR_EL2 → `pstate` (guest PSTATE at time of exception)
///
/// Offset breakdown (verified by const assertions; all values in bytes):
///   x[0..30] :   0, size 248  (31 × u64, 8-byte aligned)
///   sp_el1   : 248, size   8
///   pc       : 256, size   8
///   pstate   : 264, size   8
///   sys      : 272, size 120  (VcpuSysRegs, 8-byte aligned)
///   [8B pad] : 392            (VcpuFpRegs.align=16; 392 % 16 = 8 → pad 8 B)
///   fp       : 400, size 528  (VcpuFpRegs, 16-byte aligned)
///   total    : 928 bytes      (928 % 16 = 0, no trailing padding)
#[repr(C)]
pub struct VcpuRegs {
    /// x0–x30: 31 general-purpose registers. 248 bytes.
    pub x: [u64; 31],
    /// Stack Pointer EL1.
    pub sp_el1: u64,
    /// Guest PC. On VM exit: loaded from ELR_EL2.
    pub pc: u64,
    /// Guest PSTATE. On VM exit: loaded from SPSR_EL2.
    pub pstate: u64,
    /// EL1 system registers. 120 bytes.
    pub sys: VcpuSysRegs,
    /// FP/SIMD state. 528 bytes. Placed last — its align(16) introduces
    /// 8 bytes of implicit padding after `sys` (offsets 392–399).
    pub fp: VcpuFpRegs,
}

// ── Compile-time offset constants (used by Context Save/Restore assembly) ─────────────────

/// Byte offset of `x[0]` within `VcpuRegs`.
pub const VCPU_REGS_X_OFFSET: usize = 0;
/// Byte offset of `sp_el1` within `VcpuRegs`.
pub const VCPU_REGS_SP_EL1_OFFSET: usize = 248;
/// Byte offset of `pc` (ELR_EL2) within `VcpuRegs`.
pub const VCPU_REGS_PC_OFFSET: usize = 256;
/// Byte offset of `pstate` (SPSR_EL2) within `VcpuRegs`.
pub const VCPU_REGS_PSTATE_OFFSET: usize = 264;
/// Byte offset of `sys` within `VcpuRegs`.
pub const VCPU_REGS_SYS_OFFSET: usize = 272;
/// Byte offset of `fp` within `VcpuRegs`.
/// Derivation: sys_start(272) + sys_size(120) = 392; 392 % 16 = 8 → +8 pad → 400.
pub const VCPU_REGS_FP_OFFSET: usize = 400;

// Build-time layout verification.
// offset_of! is stable in core::mem since Rust 1.77.0 (no_std compatible).
// If any constant is wrong the build fails with a clear const-eval error.
const _: () = assert!(core::mem::offset_of!(VcpuRegs, x) == VCPU_REGS_X_OFFSET);
const _: () = assert!(core::mem::offset_of!(VcpuRegs, sp_el1) == VCPU_REGS_SP_EL1_OFFSET);
const _: () = assert!(core::mem::offset_of!(VcpuRegs, pc) == VCPU_REGS_PC_OFFSET);
const _: () = assert!(core::mem::offset_of!(VcpuRegs, pstate) == VCPU_REGS_PSTATE_OFFSET);
const _: () = assert!(core::mem::offset_of!(VcpuRegs, sys) == VCPU_REGS_SYS_OFFSET);
const _: () = assert!(core::mem::offset_of!(VcpuRegs, fp) == VCPU_REGS_FP_OFFSET);
const _: () = assert!(core::mem::size_of::<VcpuFpRegs>() == 528);
const _: () = assert!(core::mem::size_of::<VcpuSysRegs>() == 120);
const _: () = assert!(core::mem::size_of::<VcpuRegs>() == 928);

// ── vCPU ─────────────────────────────────────────────────────────────────────

/// Maximum number of vCPUs per VM.
/// ManagementVM uses 1 (core 0). HftEngineVM uses all 3 (cores 1–3).
pub const MAX_VCPUS: usize = 3;

/// Per-vCPU state: binds a physical core to a complete register save area.
pub struct Vcpu {
    /// Physical core ID running this vCPU.
    /// ManagementVM: core 0. HftEngineVM: cores 1, 2, 3.
    pub core_id: u32,
    /// Complete register state (GPRs + EL1 sysregs + FP/SIMD).
    pub regs: VcpuRegs,
}

// ── VM ────────────────────────────────────────────────────────────────────────

/// Top-level VM descriptor.
///
/// One VM = one isolated guest address space (one Stage-2 page table).
/// Multiple vCPUs share the same address space — they all use the same
/// `stage2_root` and see the same IPA→HPA mapping. Each vCPU has its own
/// register state (`VcpuRegs`) and runs on a dedicated physical core.
///
/// Layout:
///   ManagementVM: vcpu_count=1, vcpus[0]=core 0
///   HftEngineVM:  vcpu_count=3, vcpus[0]=core 1, vcpus[1]=core 2, vcpus[2]=core 3
///
/// `stage2_root` is initialised to 0 — Step 16 allocates and fills it.
pub struct Vm {
    /// VM identifier. 0 = ManagementVM, 1 = HftEngineVM.
    pub id: u32,
    /// Role of this VM.
    pub vm_type: VmType,
    /// Host PA of the Stage-2 L1 page table root (written to VTTBR_EL2).
    /// Initialised to 0; filled when implementing Stage-2 Translation Tables.
    pub stage2_root: usize,
    /// IPA base address of guest RAM (0x4000_0000 for both VMs).
    pub ipa_base: usize,
    /// Size of the guest IPA address space in bytes.
    pub ipa_size: usize,
    /// Number of active vCPUs in `vcpus[]`. ManagementVM=1, HftEngineVM=3.
    pub vcpu_count: u32,
    /// vCPU array. Only `vcpus[0..vcpu_count]` are valid.
    pub vcpus: [Vcpu; MAX_VCPUS],
}

// ── Global VM instances ───────────────────────────────────────────────────────
// MaybeUninit avoids a requirement for const-initializable Vm.
// Access pattern: addr_of_mut!(STATIC) raw pointers — Rust 2024 static_mut_refs.
// Consistent with memory/pmm.rs global PMM pattern.

static mut MGMT_VM: MaybeUninit<Vm> = MaybeUninit::uninit();
static mut HFT_VM: MaybeUninit<Vm> = MaybeUninit::uninit();

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the global ManagementVM and HftEngineVM descriptors.
///
/// IPA layout:
///   ManagementVM : colors 8–15, 64 MiB  → 16 384 pages via alloc_mgmt_page()
///   HftEngineVM  : colors 0–7,  128 MiB → 32 768 pages via hft_pool_alloc_page()
///
/// `stage2_root` is left 0 in both VMs; When implementing Stage-2 Translation Tables, it will be filled.
///
/// # Safety
/// Must be called exactly once from the Management core (CPU 0),
/// after PMM (`memory::pmm::init`) and cache coloring
/// (`memory::cache_color::init_hft_pool`) are fully initialised.
/// No other core may access `MGMT_VM` or `HFT_VM` before this returns.
pub unsafe fn init_vms() {
    // SAFETY: Single-core boot. MaybeUninit::write before any reads.
    // core::mem::zeroed() is valid: VcpuRegs contains only integer types;
    // all-zero bit pattern is a valid (inactive) register state.
    unsafe {
        (*addr_of_mut!(MGMT_VM)).write(Vm {
            id: 0,
            vm_type: VmType::Management,
            stage2_root: 0,
            ipa_base: 0x4000_0000,
            ipa_size: 64 * 1024 * 1024, // 64 MiB; colors 8–15 (Guest RAM Allocation)
            vcpu_count: 1,
            // core_id=0 is the zero value; zeroed() initialises all 3 slots at once.
            vcpus: core::mem::zeroed(),
        });

        let mut hft_vcpus: [Vcpu; MAX_VCPUS] = core::mem::zeroed();
        hft_vcpus[0].core_id = 1;
        hft_vcpus[1].core_id = 2;
        hft_vcpus[2].core_id = 3;
        (*addr_of_mut!(HFT_VM)).write(Vm {
            id: 1,
            vm_type: VmType::HftEngine,
            stage2_root: 0,
            ipa_base: 0x4000_0000,
            ipa_size: 128 * 1024 * 1024, // 128 MiB; colors 0–7 (Guest RAM Allocation)
            vcpu_count: 3,
            vcpus: hft_vcpus,
        });
    }

    // Print boot log. SAFETY: MaybeUninit is now initialised above.
    let mgmt = unsafe { (*addr_of_mut!(MGMT_VM)).assume_init_ref() };
    let hft = unsafe { (*addr_of_mut!(HFT_VM)).assume_init_ref() };

    writeln!(
        &mut &UART,
        "\r\n[vm  ] ManagementVM  id={} vcpus={} cores=[{}] ipa=[{:#010x}, {:#010x})  ({} MiB)",
        mgmt.id,
        mgmt.vcpu_count,
        mgmt.vcpus[0].core_id,
        mgmt.ipa_base,
        mgmt.ipa_base + mgmt.ipa_size,
        mgmt.ipa_size / (1024 * 1024),
    )
    .ok();
    writeln!(
        &mut &UART,
        "[vm  ] HftEngineVM   id={} vcpus={} cores=[{},{},{}] ipa=[{:#010x}, {:#010x})  ({} MiB)",
        hft.id,
        hft.vcpu_count,
        hft.vcpus[0].core_id,
        hft.vcpus[1].core_id,
        hft.vcpus[2].core_id,
        hft.ipa_base,
        hft.ipa_base + hft.ipa_size,
        hft.ipa_size / (1024 * 1024),
    )
    .ok();
    writeln!(
        &mut &UART,
        "[vm  ] VcpuRegs: size={} B  align={} B  fp_offset={} B  (Context Save/Restore Assembly constants)",
        core::mem::size_of::<VcpuRegs>(),
        core::mem::align_of::<VcpuRegs>(),
        VCPU_REGS_FP_OFFSET,
    )
    .ok();
    writeln!(
        &mut &UART,
        "[vm  ] stage2_root: MGMT={:#010x}  HFT={:#010x}  (filled when implementing Stage-2 Translation Tables)",
        mgmt.stage2_root, hft.stage2_root,
    )
    .ok();
}

/// Return a mutable reference to the ManagementVM global instance.
///
/// # Safety
/// `init_vms()` must have been called. No other concurrent mutable access.
#[allow(dead_code)]
pub unsafe fn mgmt_vm() -> &'static mut Vm {
    unsafe { (*addr_of_mut!(MGMT_VM)).assume_init_mut() }
}

/// Return a mutable reference to the HftEngineVM global instance.
///
/// # Safety
/// `init_vms()` must have been called. No other concurrent mutable access.
#[allow(dead_code)]
pub unsafe fn hft_vm() -> &'static mut Vm {
    unsafe { (*addr_of_mut!(HFT_VM)).assume_init_mut() }
}

/// Enter a guest VM on the calling physical core. **VM-Entry (ERET EL2 → EL1) stub.**
///
/// Writes HCR_EL2 per VmType before ERET, ensuring correct interrupt routing:
///   ManagementVM → 0x80080019  (VM|TSC|RW|IMO|FMO — IRQ routing active)
///   HftEngineVM  → 0x80080001  (VM|TSC|RW — interrupt-free)
///
/// # Safety
/// Must be called from EL2. `init_vms()` must have been called.
/// After VM-Entry (ERET EL2 → EL1) fills this in, the stack frame will be invalidated by ERET.
///
/// TODO VM-Entry (ERET EL2 → EL1): write VTTBR_EL2 = (vm.id << 48) | vm.stage2_root
/// TODO VM-Entry (ERET EL2 → EL1): restore VcpuRegs from vm.vcpus[vcpu_idx].regs
/// TODO VM-Entry (ERET EL2 → EL1): ERET to EL1
#[allow(dead_code)]
pub unsafe fn enter_vm(vm: &Vm, _vcpu_idx: usize) {
    let hcr = crate::cpu::hcr_for_vm(vm.vm_type);
    unsafe {
        core::arch::asm!(
            "msr hcr_el2, {hcr}",
            "isb",
            hcr = in(reg) hcr,
            options(nostack, nomem),
        );
    }
}
