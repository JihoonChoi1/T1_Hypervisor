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
