# T1_Hypervisor

A Type 1 (bare-metal) hypervisor for ARMv8-A (AArch64), written in `no_std` Rust.
It boots at **EL2**, brings up the MMU, GIC, timers, and all four cores, builds a
two-stage (Stage-1 + Stage-2) translation regime, constructs two guest VMs, and
loads a guest payload into one of them.

The design target is **deterministic, interrupt-free execution for a
high-frequency-trading (HFT) workload**: core 0 runs a *Management* VM (owns the
UART, the GIC, and the slow path), while cores 1–3 are reserved for an *HFT
engine* VM that is shielded from interrupts at the hardware level and given
cache-colored memory to reduce cross-core L2 contention.

Primary target is the **QEMU `virt`** machine; the codebase also carries
**Raspberry Pi 4 (BCM2711 / Cortex-A72)** paths behind a `rpi4` Cargo feature.

> **Current milestone:** boots end-to-end — EL2 setup, Stage-1 MMU, SMP bring-up,
> per-VM Stage-2 tables, guest-RAM allocation, and the HFT guest payload copied
> into guest RAM with `vcpu[0]` seeded — then idles on core 0. Guest execution
> (VM entry) is the next milestone; see [Roadmap](#roadmap).

---

## Target platform

|                 |                                                                 |
|-----------------|-----------------------------------------------------------------|
| Architecture    | ARMv8-A, AArch64, executing at EL2 (non-VHE; `HCR_EL2.E2H = 0`) |
| Default board   | QEMU `virt`, `-cpu cortex-a57 -smp 4 -m 1G`                     |
| Secondary board | Raspberry Pi 4 / BCM2711 (Cortex-A72), `--features rpi4`        |
| Rust target     | `aarch64-unknown-none`                                          |
| Toolchain       | stable Rust, edition 2024 (`no_std`, no nightly features)       |

Boot entry follows the ARM64 Linux boot protocol: the bootloader (QEMU's
internal PSCI firmware, or U-Boot) enters at `_start` with `x0` = physical DTB
pointer.

---

## Architecture overview

Two guest VMs are defined as global descriptors (`src/vm/mod.rs`):

| VM             | id | Cores       | vCPUs | Guest RAM (IPA)         | Page colors |
|----------------|----|-------------|-------|-------------------------|-------------|
| `ManagementVM` | 0  | core 0      | 1     | 64 MiB @ `0x4000_0000`  | 8–15        |
| `HftEngineVM`  | 1  | cores 1,2,3 | 3     | 128 MiB @ `0x4000_0000` | 0–7         |

Both VMs share three 4 KiB pages at fixed IPAs, mapped with asymmetric Stage-2
permissions so each side can only do what it should:

| Shared page          | IPA           | Management | HFT |
|----------------------|---------------|------------|-----|
| Watchdog (heartbeat) | `0x5000_0000` | RO         | RW  |
| IPC ring buffers     | `0x5000_1000` | RW         | RW  |
| Kill switch          | `0x5000_2000` | RW         | RO  |

---

## What's implemented

### Boot & early console
- **`src/boot.s`** — core-0 gate via `MPIDR_EL1` (all affinity fields checked),
  EL2 verification via `CurrentEL`, stack setup from `__boot_stack_top`, BSS
  zeroing, jump to `kmain(dtb_ptr)`.
- **`src/uart.rs`** — PL011 driver (QEMU `virt` UART0 @ `0x0900_0000`),
  configured 115200 8N1 with FIFOs. `core::fmt::Write` over a spinlock-protected
  global; panic handler force-unlocks the lock and dumps the panic location.

### EL2 system-register configuration (`src/cpu.rs`)
- `HCR_EL2 = 0x8008_0001` (`VM | TSC | RW`): Stage-2 enabled, SMC trapped to
  EL2, EL1 forced to AArch64. `IMO`/`FMO` are deliberately **not** set globally;
  they are computed per-VM by `hcr_for_vm()` (Management gets `IMO|FMO`, HFT does
  not) so HFT cores stay interrupt-free.
- `CPTR_EL2 = 0x33FF`: RES1 bits preserved, `TFP = 0` so FP/SIMD is open to
  EL1/EL2 (avoids the very-early NEON trap that would otherwise kill a guest).
- `SCTLR_EL2`: deterministic pre-MMU baseline (`SA = 1`, MMU/caches off, LE).
- `MAIR_EL2`: slot 0 = Normal write-back cacheable (`0xFF`), slot 1 =
  Device-nGnRnE (`0x00`).

### Physical memory manager (`src/memory/pmm.rs`)
- **Buddy allocator**, orders 0–17 (4 KiB → 512 MiB), intrusive doubly-linked
  free lists stored *inside* the free pages (no separate heap). Manages all RAM
  from `__kernel_end` to `0x8000_0000`.
- `alloc` / `free` with XOR-buddy coalescing, plus `alloc_with_filter` — a
  color-aware allocator that finds a page satisfying an arbitrary predicate,
  with a `guaranteed_order` short-circuit hint for page coloring.

### Stage-1 EL2 MMU (`src/memory/stage1.rs`)
- 2-level walk, `T0SZ = 32`, 4 KiB granule, identity-mapped (VA = PA).
- **W^X enforced in hardware**: `.text` RO+X, `.rodata` RO+NX, all other RAM
  (DTB, `.data`/`.bss`, stack, PMM heap) RW+NX, plus `SCTLR_EL2.WXN = 1` as
  defence in depth. UART and GICv2 MMIO mapped as Device-nGnRnE.
- Section permissions are derived at runtime from linker symbols
  (`__text_start`, `__rodata_start`, `__data_start`), so the mapping stays
  correct as sections grow. `enable_mmu()` performs the full TLBI/IC/DSB/ISB
  activation sequence; `enable_mmu_secondary()` lets secondary cores reuse the
  same L1 table.

### Exception handling (`src/exception.s`, `src/exception.rs`)
- Full 16-entry EL2 vector table installed via `VBAR_EL2`, with
  `SAVE_CONTEXT`/`RESTORE_CONTEXT` macros (272-byte frame).
- EL2 synchronous and SError handlers decode `ESR_EL2` (EC + ISS, including
  data/instruction-abort FSC/WnR/S1PTW) and `FAR_EL2`, dump all GPRs over UART,
  and halt.

### CPU topology & SMP bring-up (`src/cpu/`)
- `topology.rs` — decodes `MPIDR_EL1`; core 0 → `Management`, all others →
  `Hft`.
- `psci.rs` — PSCI `CPU_ON` (`0xC400_0003`) over `smc #0`.
- `secondary.rs` — wakes cores 1–3. Each secondary runs a naked-asm prologue
  (sets `MAIR`/`HCR`/`CPTR`/`SCTLR` EL2, loads a private 64 KiB stack), then in
  Rust installs `VBAR_EL2`, enables the shared MMU, detects its role, **masks its
  GIC CPU interface (`GICC_PMR = 0`)**, checks in via an atomic counter, waits on
  a release barrier (`SEV`/`WFE`), initialises its own timer/PMU, and enters a
  busy-poll loop.

### Interrupt controller (`src/irq/gic.rs`)
- GICv2 driver. Verifies the controller is GICv2 via `GICD_PIDR2`, then
  configures the distributor to route **all SPIs to CPU 0 only**
  (`GICD_ITARGETSR`), sets priorities, makes SPIs level-sensitive, and opens
  CPU 0's interface (`GICC_PMR = 0xFF`). HFT cores hard-mask their own interface
  on wakeup. `acknowledge_irq`/`end_irq` helpers are provided for the EL2 IRQ
  handler.

### Timers & PMU (`src/time/mod.rs`)
- Per-core init: `CNTVOFF_EL2 = 0` (virtual time == physical time), virtual
  timer masked on HFT cores, 64-bit cycle counter (`PMCCNTR_EL0`) enabled,
  `L2D_CACHE_REFILL` (event `0x17`) armed on event counter 0.
- `MDCR_EL2` hardened: `HPME = 1`, `TPM`/`TPMCR`/`HPMD` cleared, `HPMN = N` so
  EL1 PMU reads never trap to EL2 (latency determinism). `PMUSERENR_EL0.EN = 1`.
- Note: QEMU does not emulate PMU event/cycle counters, so these read 0 there;
  meaningful values require real Cortex-A72/A76 hardware.

### Frequency pinning (`src/cpu/freq.rs`)
- QEMU: no-op. RPi4 (`--features rpi4`): sends `SET_CLOCK_RATE` to the VideoCore
  firmware over the mailbox (property channel 8) to lock the ARM clock at
  1.5 GHz and prevent DVFS from invalidating cycle-count timestamps.

### Cache coloring (`src/memory/cache_color.rs`)
- Heuristic page coloring for the Cortex-A72 shared L2 (1 MiB, 16-way, 64 B
  line → 16 colors; `color(PA) = (PA / 4096) % 16`). Colors 0–7 reserved for
  HFT, 8–15 for Management.
- All HFT-colored pages (128 MiB / 32 768 pages) are pre-allocated at boot into
  a flat array and handed out via an O(1) bump index (no pointer-chasing on the
  way to the trading VM). A boot-time PoC verifies the allocator returns
  correctly-colored pages.
- The L2 set-index model is documented as empirically-likely (per Xen's A72
  work) but not architecturally guaranteed by ARM.

### VM / vCPU data model (`src/vm/mod.rs`)
- `Vm`, `Vcpu`, and a `repr(C)` `VcpuRegs` (928 bytes: 31 GPRs, `SP_EL1`, PC,
  PSTATE, 15 EL1 sysregs, 32×128-bit FP/SIMD + `FPSR`/`FPCR`). Field offsets are
  verified at compile time with `offset_of!` const-asserts and exported to
  assembly.

### Stage-2 translation (`src/vm/stage2.rs`)
- `VTCR_EL2 = 0x8002_3560` (`T0SZ = 32`, `SL0 = 01`, 4 KiB granule, 40-bit PA).
- `S2Prot` enum (RO / RW / RoX / Device) assembling MemAttr / S2AP / SH / AF / XN
  bits. 2 MiB block mapping (`stage2_map_2m`/`stage2_map_range`), 4 KiB page
  mapping (`stage2_map_4k`), and a read-only `walk_ipa()` IPA→PA resolver.
- `init_stage2()` builds one Stage-2 table per VM, installs the UART (and, on
  RPi4, GENET NIC) MMIO passthrough as Device, and maps the three shared pages
  with the asymmetric permissions in the table above.

### Guest RAM & payload (`src/vm/ram.rs`, `src/vm/loader.rs`, `payload/`)
- `init_guest_ram()` walks each VM's entire IPA window at 4 KiB granularity,
  pulls pages from the correct color source, zeroes each page, **cleans it to the
  Point of Coherency (`DC CIVAC` + batched `DSB ISH`)** so an MMU-off guest
  reading Normal-Non-cacheable sees the zeros (not stale residue), and installs
  per-page Stage-2 L3 descriptors. 4 KiB granularity is mandatory to preserve
  coloring.
- The **guest payload** (`payload/`) is a separate `no_std` crate: a minimal
  AArch64 heartbeat loop (`payload/payload.s`) that polls the kill switch,
  increments the watchdog heartbeat, and issues `HVC #1` on halt. It is built to
  `payload/hft_payload.bin` (committed) and embedded into the kernel via
  `include_bytes!`.
- `load_hft_payload()` copies the image into the HFT VM's guest RAM (resolving
  each IPA through `walk_ipa`, since colored pages are non-contiguous in PA) and
  seeds `vcpu[0]` registers: `PC = 0x4000_0000`, `SP_EL1 = 0x4010_0000`,
  `SPSR_EL2 = 0x3C5` (EL1h, DAIF masked), `SCTLR_EL1` MMU-off baseline.

### Inter-VM communication (`src/vm/watchdog.rs`, `killswitch.rs`, `ipc.rs`)
- **Watchdog**: 64-byte page; HFT writes a heartbeat counter, Management reads
  it (acquire/release) and counts consecutive misses.
- **Kill switch**: flag + reason string; Management writes, HFT polls.
- **IPC**: lock-free SPSC ring buffers on one 4 KiB page — one Management→HFT
  channel plus three per-core HFT→Management channels (avoids an MPSC CAS), with
  producer/consumer indices placed on separate cache lines to avoid false
  sharing.

---

## Boot sequence

The order executed by `kmain` (`src/main.rs`) on core 0:

1. UART, `HCR`/`CPTR`/`SCTLR`/`MAIR` EL2 setup
2. Buddy allocator
3. Stage-1 page tables + MMU on (W^X)
4. `VBAR_EL2` + EL2 exception handlers
5. CPU topology, GICv2 SPI steering to core 0
6. Per-core timer + PMU, frequency pin (no-op on QEMU)
7. PSCI bring-up of cores 1–3 with GICC masking
8. Cache-color pool pre-allocation
9. VM descriptors, shared pages, VTCR + per-VM Stage-2 tables
10. Guest-RAM allocation + Stage-2 mapping for both VMs
11. HFT payload copied into guest RAM, `vcpu[0]` seeded
12. Core 0 enters `WFI` idle loop

---

## Roadmap

The boot path currently ends after the guest payload is loaded. Next:

- **VM entry** — `ERET` EL2→EL1 into the guest (`VTTBR_EL2` + TLBI sequencing).
- **VM-exit handler** — `ESR_EL2` EC routing (HVC, Stage-2 aborts, WFI/WFE traps).
- **Management event loop** — drive the watchdog / kill switch / IPC at runtime.
- **Polling-mode NIC passthrough** for the HFT engine.

---

## Repository layout

```
src/
  main.rs            kmain — the full boot sequence
  boot.s             core-0 reset vector
  linker.ld          kernel layout @ 0x4020_0000, 2 MiB-aligned sections (W^X)
  uart.rs            PL011 driver + global console
  cpu.rs             EL2 sysreg setup (HCR/CPTR/SCTLR/MAIR), per-VM HCR
  cpu/               topology, psci, secondary-core bring-up, freq pinning
  exception.{rs,s}   EL2 vector table + ESR/FAR decoding handlers
  irq/gic.rs         GICv2 distributor/CPU-interface driver
  memory/            pmm (buddy), stage1 (EL2 MMU), cache_color
  time/mod.rs        per-core timer + PMU
  vm/                Vm/Vcpu types, stage2, ram, loader,
                     watchdog, killswitch, ipc
payload/             standalone no_std guest crate → hft_payload.bin
docs/                per-subsystem design notes (Obsidian vault)
```

---

## Build and run

### Prerequisites

```sh
rustup target add aarch64-unknown-none
# QEMU with AArch64 system emulation:
#   macOS:  brew install qemu
#   Debian: apt install qemu-system-arm
```

The build target (`aarch64-unknown-none`) and the QEMU runner are already wired
into `.cargo/config.toml`, so no extra flags are needed.

### Build

```sh
cargo build --release
```

### Run on QEMU

```sh
cargo run --release
```

This invokes (from `.cargo/config.toml`):

```
qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a57 \
    -smp 4 -m 1G -nographic -kernel <binary>
```

`virtualization=on` is required so the CPU starts in EL2. Exit `-nographic` QEMU
with `Ctrl-A X`.

### Debug with GDB

Uncomment the debug `runner` in `.cargo/config.toml` (adds `-s -S`, halting at
boot for GDB on `:1234`), then `cargo run --release` and attach with an
`aarch64` GDB / LLDB.

### Raspberry Pi 4 paths

```sh
cargo build --release --features rpi4
```

Compiles in the BCM2711-specific code (VideoCore mailbox frequency pinning, the
`0xFE00_0000` peripheral block mapping, and GENET NIC MMIO passthrough). QEMU
`virt` is the tested path.

### Rebuilding the guest payload (optional)

The committed `payload/hft_payload.bin` is embedded at compile time, so a normal
kernel build does **not** require rebuilding it. To regenerate it:

```sh
cargo install cargo-binutils && rustup component add llvm-tools-preview
cd payload && ./build.sh        # cargo build + rust-objcopy -O binary
```

---

## Memory map (QEMU `virt`, `-m 1G`)

| Region                      | Physical address               | Attributes           |
|-----------------------------|--------------------------------|----------------------|
| GICv2 (GICD/GICC)           | `0x0800_0000`                  | Device-nGnRnE        |
| PL011 UART0                 | `0x0900_0000`                  | Device-nGnRnE        |
| DTB                         | `0x4000_0000`                  | Normal-WB, RW+NX     |
| Kernel `.text`              | `0x4020_0000`                  | Normal-WB, **RO+X**  |
| Kernel `.rodata`            | `0x4040_0000`                  | Normal-WB, **RO+NX** |
| Kernel `.data`/`.bss`/stack | `0x4060_0000`…                 | Normal-WB, RW+NX     |
| PMM heap                    | `__kernel_end` … `0x8000_0000` | Normal-WB, RW+NX     |

HFT and Management pages are not a fixed sub-range — they are scattered through
the PMM heap and separated by page color at allocation time.

---

## References

The source is heavily annotated with citations to ARM DDI 0487 (the ARMv8-A
Architecture Reference Manual), ARM IHI 0048B (GICv2), ARM DEN 0022 (PSCI), the
Linux KVM arm64 sources, and Xen's cache-coloring implementation. See the
per-subsystem notes under `docs/` for the design rationale behind each module.
