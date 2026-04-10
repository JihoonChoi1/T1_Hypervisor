# Debugging Log: MMU Activation Infinite Exception Loop

**Date:** 2026-03-19
**Module:** MMU (`memory/stage1.rs`)
**Severity:** Critical (System Hang / Infinite Reboot Loop)

## 1. Issue Description
- **Symptom:** When MMU enabling was first implemented, executing the `main.rs` boot sequence resulted in an immediate, silent hang from QEMU exactly after printing the L2 mapping logs.
- **Observation:** The expected output `[mmu ] Stage-1 MMU enabled` was never reached.

## 2. Debugging Process
To diagnose the silent hang, the environment was run with QEMU's internal exception logging enabled:
```bash
cargo run -- -d int 2> qemu_crash.log
```
The resulting log (archived in `debug_state/2026-03-19/qemu_crash.log`) revealed an infinite loop of identical exceptions:
```text
Taking exception 3 [Prefetch Abort] on CPU 0
...from EL2 to EL2
...with ESR 0x21/0x8600000e
...with FAR 0x40085200
```
- **ESR `0x21`**: `Instruction Abort from current EL`.
- **ISS `0x0e`**: `Permission fault, level 2`.
- **FAR `0x40085200`**: This was the exact address of the kernel `.text` executing at that moment.

## 3. Root Cause Analysis
### Tracing the Fault
1.  **Address Verification:** The `FAR` (Faulting Address Register) pointed to `0x40085200`. I verified that this address falls within the 1 GiB RAM region (`0x4000_0000` ~ `0x8000_0000`).
2.  **Page Table Inspection:** I reviewed `memory/stage1.rs` to check the MMU permissions assigned to this specific address range.
3.  **Discovery:** The code showed that the *entire* RAM region was mapped uniformly using the `block_normal_rw_nx` descriptor loop.
4.  **Descriptor Analysis:** Inspecting `block_normal_rw_nx()` revealed that it explicitly sets the `DESC_XN` (Execute Never) bit to protect data regions.

### The Mechanism
- **Context:** The `build_page_tables` function did not distinguish between the kernel's code (`.text`) and data (`.data`/`.bss`).
- **Mechanism:**
    - By applying `DESC_XN` to the entire RAM, I accidentally told the MMU that my own kernel code was non-executable data.
    - The moment the MMU was turned on (`SCTLR_EL2.M = 1`), the processor attempted to fetch the very next instruction from the kernel `.text` section.
    - The hardware MMU correctly blocked the instruction fetch due to the `XN` bit, raising an Instruction Abort.
- **Outcome:** The exception handler itself (`VBAR_EL2`) was also located in RAM. Attempting to jump to the handler raised *another* Instruction Abort, resulting in an inescapable infinite loop (lockup).

## 4. Resolution
- **Initial Fix (Temporary Workaround):**
    - To verify the theory and unblock the boot process, the immediate fix was to remove the `DESC_XN` bit from the RAM mapping entirely (`block_normal_rw_x`).
    - **Result:** The MMU successfully turned on and the hypervisor continued booting, confirming that the Execute-Never bit was the culprit. However, mapping all memory as `RW+X` violates structural security.
- **Final Fix (Hardware-Enforced W^X Isolation):**
    - I enlarged the binary memory layout to fit 2 MiB huge pages and enforced strict `W^X` (Write XOR Execute) isolation using two separate MMU descriptors.
- **Implementation:**
    1.  **Linker Script (`linker.ld`)**:
        - Baseline (`BASE_ADDRESS`) moved to `0x4020_0000` (perfect 2 MiB boundary).
        - Added explicit `. = ALIGN(2M);` directives before **both** `.rodata` and `.data`.
        - This guarantees that Code (`0x4020_0000`), Read-Only Data (`0x4040_0000`), and Mutable Data (`0x4060_0000`) each solidly begin on their own independent 2 MiB boundaries.
    2.  **Page Tables (`stage1.rs`)**:
        - Created three strict descriptors to enforce permission boundaries: 
            - `block_normal_ro_x` (`AP = Read-Only`, `no XN`) for code.
            - `block_normal_ro_nx` (`AP = Read-Only`, `XN set`) for read-only data.
            - `block_normal_rw_nx` (`AP = Read-Write`, `XN set`) for mutable data.
        - The L2 mapping loop explicitly applies `block_normal_ro_x` *only* to the specific 2 MiB block containing the code (`__text_start`).
        - The `.rodata` block receives `block_normal_ro_nx`, enforcing strict W^X even on read-only constants.
        - All mutable memory (DTB, PMM, stack, data) receives `block_normal_rw_nx`.
- **Verification:** By intentionally "wasting" a few megabytes of physical address space with `ALIGN(2M)`, `W^X` memory protection was achieved natively via the hardware L2 Translation Table. As a side effect, the entire `.text` section is covered by a single 2 MiB ITLB entry, reducing instruction TLB misses to at most one cold miss on first execution. The MMU sequence now continues past initialization flawlessly.

---

# Debugging Log: BSS Zeroing Loop Silent Hang

**Date:** 2026-04-09
**Module:** Boot (`src/boot.s`, `src/linker.ld`)
**Severity:** Critical (Silent hang — no UART output, Data Abort at RAM boundary)

## 1. Issue Description

- **Symptom:** After implementing CPU Frequency Pinning, `cargo run` launched QEMU normally but produced **zero UART output**. The terminal was stuck at the QEMU runner line with no log at all — not even the earliest `[cpu]` lines that appear before MMU is enabled.
- **Observation:** Reverting all CPU Frequency Pinning changes with `git stash` immediately restored normal output, confirming the regression was introduced by the new code.

## 2. Debugging Process

Since the hang occurred before any UART output, standard log-based debugging was impossible. QEMU's internal exception logger was used instead:

```bash
qemu-system-aarch64 \
  -machine virt,virtualization=on -cpu cortex-a57 -smp 4 -m 1G \
  -nographic -d int,cpu_reset -D /tmp/qemu_int.log \
  -kernel target/aarch64-unknown-none/debug/T1_Hypervisor
```

The log revealed a two-stage failure pattern:

**Stage 1 — Data Abort at RAM boundary:**
```
Taking exception 4 [Data Abort] on CPU 0
...from EL2 to EL2
...with ESR 0x25/0x96000050
...with FAR 0x80000000
```
- **EC `0x25`**: Data Abort from current EL (EL2 → EL2).
- **DFSC `0x10`** (bits [5:0] of ISS): Synchronous External Abort — not on a translation table walk. This is what QEMU reports when a store targets an address outside the physical memory map.
- **WnR bit [6] = 1**: The faulting access was a **write**.
- **FAR `0x80000000`**: Exactly `RAM_END`. This address is one byte past the end of the 1 GiB QEMU memory region (`0x40000000`–`0x7FFFFFFF`).
- **Timing**: The fault occurred before any UART output, meaning it happened during the assembly boot sequence in `boot.s` — before `kmain` was even called.

**Stage 2 — Undefined Instruction infinite loop:**
```
Taking exception 1 [Undefined Instruction] on CPU 0
...from EL2 to EL2
...with ESR 0x0/0x2000000
...with SPSR 0x3c9
(repeating indefinitely)
```
The Data Abort handler was itself broken by the corrupted state, causing it to execute garbage instructions in an infinite loop. This is why QEMU appeared frozen with no output.

## 3. Root Cause Analysis

### 3-A. The Latent Bug in `boot.s`

The BSS zeroing loop in `boot.s` (present since the initial commit) contained a subtle off-by-one error:

```asm
// BUGGY (original):
.L_bss_loop:
    cmp     x1, x2          // x1 = current write ptr, x2 = __bss_end
    b.eq    .L_bss_done     // ← exits ONLY if x1 == x2 exactly
    str     xzr, [x1], #8  // write 8 zero bytes, advance by 8
    b       .L_bss_loop
```

`str xzr, [x1], #8` writes exactly **8 bytes** per iteration and increments `x1` by 8. For the loop to exit correctly, `__bss_end` must be reachable by a multiple-of-8 increment from `__bss_start`. In other words, `(__bss_end - __bss_start)` must be a multiple of 8.

**If this condition is not met**, `x1` skips over `x2` without ever being equal to it:

```
x1 = __bss_end - 4   (4 bytes before the end)
→ write 8 bytes at x1     ← 4-byte overshoot past __bss_end
→ x1 = __bss_end + 4
→ compare: x1 (end+4) == x2 (end)?  NO → continue
→ x1 = __bss_end + 12
→ compare: NO → continue
→ ... loop never exits, x1 races through all of RAM
→ x1 = 0x80000000 → QEMU External Abort (RAM_END exceeded)
```

### 3-B. Why It Was Never Triggered Before

The linker script placed `__bss_end` immediately after all `.bss` content with no explicit alignment:

```ld
// BUGGY (original):
.bss : ALIGN(4K) {
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    __bss_end = .;   // ← no alignment guarantee here
}
```

The largest BSS object is `HFT_POOL_PAGES: [usize; 32768]` = 32 768 × 8 bytes = **262 144 bytes** (exactly 8-byte aligned). The remaining statics happened to sum to an 8-byte aligned total, so `__bss_end` was coincidentally a multiple of 8. The bug was latent but never exposed.

### 3-C. How CPU Frequency Pinning Triggered It

`src/cpu/freq.rs` introduced a new BSS-resident static:

```rust
static CPUFREQ_LOCKED: AtomicBool = AtomicBool::new(false);
```

`AtomicBool` is **1 byte** with 1-byte alignment. This shifted `__bss_end` by 1 byte, breaking the accidental 8-byte alignment. With BSS size now `262144 + 1 + (other statics)` bytes — no longer a multiple of 8 — `x1` skipped over `__bss_end`, the loop never terminated, and the write pointer eventually reached `0x80000000`.

### 3-D. Why No UART Output

The UART driver (`UART.init()`) is called as the very first statement in `kmain`. However, the BSS zeroing loop runs in `boot.s` **before** `kmain` is called. The crash therefore occurred at the lowest possible level of the boot sequence, before Rust had any opportunity to run.

```
boot.s _start:
  1. Core ID check       ← OK
  2. EL2 check           ← OK
  3. Stack pointer setup ← OK
  4. BSS zeroing         ← CRASH HERE (Data Abort at 0x80000000)
  5. bl kmain            ← never reached
     → UART.init()
     → first writeln!
```

## 4. Resolution

Two coordinated fixes were applied.

### Fix 1 — `src/boot.s`: Replace `b.eq` with `b.hs`

```asm
// FIXED:
.L_bss_loop:
    cmp     x1, x2
    b.hs    .L_bss_done     // Branch if x1 >= x2 (unsigned ≥, not just ==)
    str     xzr, [x1], #8
    b       .L_bss_loop
```

`b.hs` (Branch if Higher or Same) exits the loop as soon as `x1 >= x2`, regardless of alignment. Even if `x1` overshoots `x2` by up to 7 bytes, the loop terminates at the next iteration. The few extra zero bytes written past `__bss_end` land inside the adjacent `.boot_stack` section, which is `NOLOAD` and harmless to zero.

### Fix 2 — `src/linker.ld`: Align `__bss_end` to 8 bytes

```ld
// FIXED:
.bss : ALIGN(4K) {
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(8);   // guarantee __bss_end is 8-byte aligned
    __bss_end = .;
}
```

This eliminates the root alignment assumption entirely. Even if future statics of any size or alignment are added to BSS, `__bss_end` will always be 8-byte aligned and the `b.hs` loop is guaranteed to exit on the first iteration after passing the end.

The two fixes are complementary: the linker fix removes the precondition failure; the `b.hs` fix ensures the loop is robust even if the precondition is violated again in the future.

## 5. Verification

After both fixes, `cargo build` succeeded with zero warnings. QEMU was run with the exception logger to confirm no Data Abort occurred:

```bash
qemu-system-aarch64 \
  -machine virt,virtualization=on -cpu cortex-a57 -smp 4 -m 1G \
  -nographic -d int,cpu_reset -D /tmp/qemu_int.log \
  -kernel target/aarch64-unknown-none/debug/T1_Hypervisor
```

The log showed no `Data Abort` or `Undefined Instruction` entries. Full boot output was restored, including the new CPU Frequency Pinning implemented:

```
[freq] DVFS lock: QEMU no-op, assuming 1.0 GHz
```

The BSS zeroing loop now survives the addition of any size or alignment of static data without risk of overrunning RAM.
