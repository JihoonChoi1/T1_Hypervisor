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

---

# Debugging Log: Exception Vector Table Misalignment

**Date:** 2026-08-26
**Module:** Exceptions (`src/exception.s`)
**Severity:** Critical (Latent bug — the entries in our vector table were shifted, causing the hardware to jump to the wrong code. Luckily, we caught this while inspecting the compiled file before actually running it.)

## 1. Issue Description

- **Symptom:** There were no runtime errors — every boot was successful. The bug was discovered while manually inspecting the compiled code (`objdump`) to verify our new `vm_exit_sync` connection.
- **Observation:** ARM hardware strictly requires the "Guest Trap" (Entry 8) to be located exactly at the `+0x400` address offset. When I checked that exact address (see section 2 for the full command), the slot did not start with our expected `b vm_exit_sync` jump instruction. Instead, I found this:

```
40200c00: d10443ff     sub  sp, sp, #0x110
```

This instruction (`sub sp, sp, #0x110`) is a heavy register-saving code that belongs to an earlier entry, NOT the simple jump instruction we expected. The hardware was going to jump to the wrong code.

## 2. Debugging Process

### Step 1 — The symbol check that started it all

I needed to verify that our three new assembly labels actually made it into the final compiled binary. I also searched for `exception_vectors` to find the base address of our vector table:

```bash
rust-objdump -d target/aarch64-unknown-none/release/T1_Hypervisor \
    | grep -E '<(vm_entry|vm_exit_sync|vm_exit_irq|exception_vectors)>:'
```
```
00000000402000ac <vm_entry>:
00000000402001d8 <vm_exit_sync>:
0000000040200800 <exception_vectors>:
```

This output told us two things:

1. The vector table base address is `0x40200800`.
2. `vm_exit_irq` seemed to be **missing**. However, this was a false alarm: `vm_exit_irq` and `vm_exit_sync` point to the exact same address. The `objdump` tool only prints one label per address. The symbol-table confirmed both exist:

```bash
rust-objdump -t target/aarch64-unknown-none/release/T1_Hypervisor \
    | grep -E 'vm_entry|vm_exit_sync|vm_exit_irq'
```
```
00000000402000ac g       .text	0000000000000000 vm_entry
00000000402001d8 g       .text	0000000000000000 vm_exit_sync
00000000402001d8 g       .text	0000000000000000 vm_exit_irq    ← same address: an alias, not missing
```

This false alarm taught us an important lesson: **just because a symbol exists doesn't mean it's placed at the exact address the hardware expects.** The CPU doesn't read our labels; it just blindly jumps to `VBAR_EL2 + 0x400`. We needed to check the actual address placement.

### Step 2 — Checking the actual hardware addresses → the bug appears

Using the base address from Step 1, I calculated the expected hardware addresses:

```
Entry 8 (guest sync trap): 0x40200800 + 0x400 = 0x40200c00   → must start with: b vm_exit_sync
Entry 9 (guest IRQ):       0x40200800 + 0x480 = 0x40200c80   → must start with: b vm_exit_irq
```

(For the same reason as Step 1, objdump displays both branch targets under the same name, `<vm_exit_sync>` — the two slots are still two distinct branch instructions to the shared address.)

I checked the compiled code exactly at these two addresses. A correct entry must have a jump as its very first instruction:

```bash
rust-objdump -d --start-address=0x40200c00 --stop-address=0x40200c88 \
    target/aarch64-unknown-none/release/T1_Hypervisor | grep -E '^\s*40200c(00|80)'
```
```
40200c00: d10443ff     sub  sp, sp, #0x110
40200c80: a94a57f4     ldp  x20, x21, [sp, #0xa0]
```

Neither entry starts with a jump — this was the actual bug. Both instructions were clearly from the wrong place:

- `sub sp, sp, #0x110` — This allocates 272 bytes, which is our exact `ExceptionFrame` size. This is the **first instruction of our `SAVE_CONTEXT` macro**. It belongs to an earlier handler, not Entry 8.
- `ldp x20, x21, [sp, #0xa0]` — This is the **middle of a `RESTORE_CONTEXT` sequence**. Entry 9's address pointed to the middle of someone else's code.

### Step 3 — Finding where the shift begins

Since the code was in the wrong place, I checked the exact addresses of all the labels in the vector table to see where things went wrong:

```bash
rust-objdump -d --start-address=0x40200a00 --stop-address=0x40200d90 \
    target/aarch64-unknown-none/release/T1_Hypervisor | grep -E '^00000000[0-9a-f]+ <'
```

Expected vs. actual addresses (Assuming the table starts at `0x40200800`):

| Entry | Label | Required Hardware Offset | Expected Address | Actual Address | Shift Amount |
|---|---|---|---|---|---|
| 4 | `curr_el_spx_sync` | +0x200 | 0x40200a00 | 0x40200a00 | 0 |
| 5 | `curr_el_spx_irq` | +0x280 | 0x40200a80 | **0x40200b00** | +0x80 (Delayed by 1 slot) |
| 6 | `curr_el_spx_fiq` | +0x300 | 0x40200b00 | **0x40200b80** | +0x80 |
| 7 | `curr_el_spx_serr` | +0x380 | 0x40200b80 | **0x40200c00** | +0x80 |
| 8 | `lower_el_aarch64_sync` | +0x400 | 0x40200c00 | **0x40200d00** | +0x100 (Delayed by 2 slots) |
| 9 | `lower_el_aarch64_irq` | +0x480 | 0x40200c80 | **0x40200d80** | +0x100 |

Everything after Entry 4 was pushed back by one slot (+0x80 bytes), and everything after Entry 7 was pushed back by two slots (+0x100 bytes). Entries 4 and 7 were the cause of the shift.

## 3. Root Cause Analysis

### 3-A. The Overflowing Entries

Entries 4 and 7 had their massive block of code written directly inside the vector table space:

```asm
// BUGGY (original):
.balign 0x80        // entry 4: Synchronous  ← EL2 hypervisor fault (bug)
curr_el_spx_sync:
    SAVE_CONTEXT                   // 22 instructions =  88 bytes
    bl      el2_sync_handler       //  1 instruction  =   4 bytes
    RESTORE_CONTEXT                // 21 instructions =  84 bytes
    eret                           //  1 instruction  =   4 bytes
                                   // total: 45 instructions = 180 bytes
```

An ARM vector slot is strictly limited to **128 bytes (32 instructions)**. But our code was 180 bytes. The code was too large for the slot and overflowed by 52 bytes.

### 3-B. Why the Compiler Stayed Silent

The `.balign 0x80` command just means "put the next label at the next multiple of 128". It does NOT mean "warn me if the previous code was larger than 128 bytes". 
So the compiler silently pushed Entry 5 to the next available 128-byte boundary, which was one slot too late. The CPU hardware, however, doesn't care about our labels. When an error happens, it blindly jumps exactly `+0x400` bytes forward.

### 3-C. Why It Was Never Triggered Before

This bug has existed since we first wrote the table. We never noticed because the hypervisor had never actually booted a guest OS yet, so Entries 5 through 15 were never triggered. Only Entry 4 was ever used during our early tests, and since Entry 4 was placed *before* the first overflow, it worked perfectly.
 

## 4. Resolution

I adopted the standardized approach used by world-class hypervisors like Linux KVM and Xen: **Every single entry must contain exactly ONE instruction (a jump to the outside).**

### Fix — The `VECTOR_ENTRY` macro

```asm
// FIXED:
.macro VECTOR_ENTRY label, target
.balign 0x80
\label:
    b   \target
.endm

// Now all 16 entries use the macro. Each slot only takes 4 bytes.
// Overflowing is now structurally impossible:
VECTOR_ENTRY curr_el_spx_sync, el2_spx_sync_body       // entry 4
...
VECTOR_ENTRY lower_el_aarch64_sync, vm_exit_sync       // entry 8
```

The massive 180-byte codes were moved to the bottom of the file (outside the table) and named `el2_spx_sync_body`. This costs nothing in performance but completely guarantees that our vector slots will never overflow again.

## 5. Verification

I re-checked the compiled file:

```bash
rust-objdump -d --start-address=0x40200800 --stop-address=0x40201100 \
    target/aarch64-unknown-none/release/T1_Hypervisor | grep -A1 -E '^00000000[0-9a-f]+ <'
```
```
0000000040200800 <exception_vectors>:
40200800: 1400023b      b       0x402010ec <unhandled_exception>
--
0000000040200880 <curr_el_sp0_irq>:
40200880: 1400021b      b       0x402010ec <unhandled_exception>
--
0000000040200900 <curr_el_sp0_fiq>:
40200900: 140001fb      b       0x402010ec <unhandled_exception>
--
0000000040200980 <curr_el_sp0_serr>:
40200980: 140001db      b       0x402010ec <unhandled_exception>
--
0000000040200a00 <curr_el_spx_sync>:
40200a00: 14000161      b       0x40200f84 <el2_spx_sync_body>
--
0000000040200a80 <curr_el_spx_irq>:
40200a80: 1400019b      b       0x402010ec <unhandled_exception>
--
0000000040200b00 <curr_el_spx_fiq>:
40200b00: 1400017b      b       0x402010ec <unhandled_exception>
--
0000000040200b80 <curr_el_spx_serr>:
40200b80: 1400012e      b       0x40201038 <el2_spx_serr_body>
--
0000000040200c00 <lower_el_aarch64_sync>:
40200c00: 17fffd76      b       0x402001d8 <vm_exit_sync>
--
0000000040200c80 <lower_el_aarch64_irq>:
40200c80: 17fffd56      b       0x402001d8 <vm_exit_sync>
--
0000000040200d00 <lower_el_aarch64_fiq>:
40200d00: 140000fb      b       0x402010ec <unhandled_exception>
--
0000000040200d80 <lower_el_aarch64_serr>:
40200d80: 140000db      b       0x402010ec <unhandled_exception>
--
0000000040200e00 <lower_el_aarch32_sync>:
40200e00: 140000bb      b       0x402010ec <unhandled_exception>
--
0000000040200e80 <lower_el_aarch32_irq>:
40200e80: 1400009b      b       0x402010ec <unhandled_exception>
--
0000000040200f00 <lower_el_aarch32_fiq>:
40200f00: 1400007b      b       0x402010ec <unhandled_exception>
--
0000000040200f80 <lower_el_aarch32_serr>:
40200f80: 1400005b      b       0x402010ec <unhandled_exception>
--
0000000040200f84 <el2_spx_sync_body>:
40200f84: d10443ff      sub     sp, sp, #0x110
--
0000000040201038 <el2_spx_serr_body>:
40201038: d10443ff      sub     sp, sp, #0x110
--
00000000402010ec <unhandled_exception>:
402010ec: d503205f      wfe
--
00000000402010f4 <_RNvCsdBezzDwma51_7___rustc17rust_begin_unwind>:
402010f4: d100c3ff      sub     sp, sp, #0x30
```

- All 16 labels now land exactly at their perfect 128-byte boundaries (`0x40200800` + `0x80×N`, N = 0…15).
- Entry 8 (`0x40200c00`) is now correctly placed as `b vm_exit_sync`.
- The code successfully compiled with 0 warnings, and boots cleanly in QEMU. 
- The bug is permanently eradicated.
