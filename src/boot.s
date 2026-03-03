.section .text._start
.global _start

_start:
    // ------------------------------------------------------------------------
    // 1. Core Identification
    // ------------------------------------------------------------------------
    // Only allow CPU 0 (the Bootstrap Processor) to continue booting.
    // Read the MPIDR_EL1 (Multiprocessor Affinity Register).
    mrs     x1, mpidr_el1
    // Mask Aff0[7:0], Aff1[15:8], Aff2[23:16] fields.
    // Checking all three affinity levels ensures correctness on multi-cluster
    // systems (e.g., big.LITTLE), where Aff0 alone could be 0 on multiple cores.
    // CPU 0 on cluster 0 will have all three fields equal to zero.
    mov     x2, #0x00FFFFFF
    and     x1, x1, x2
    // If not core 0 on cluster 0, sleep forever.
    cbnz    x1, .L_halt

    // ------------------------------------------------------------------------
    // 2. Exception Level Verification
    // ------------------------------------------------------------------------
    // A Type-1 Hypervisor MUST run at EL2.
    // Read the CurrentEL register.
    mrs     x1, CurrentEL
    // Extract the EL (bits [3:2]).
    lsr     x1, x1, #2
    and     x1, x1, #3
    // Compare with EL2 (value 2).
    cmp     x1, #2
    // If not EL2, we can't run the hypervisor. Hang.
    b.ne    .L_halt

    // ------------------------------------------------------------------------
    // 3. Stack Pointer Setup
    // ------------------------------------------------------------------------
    // Load the address of the top of the boot stack, which is defined in the
    // linker script (src/linker.ld) in the `.boot_stack` section.
    // This sits ABOVE all kernel sections (.text, .data, .bss), ensuring
    // the downward-growing stack NEVER collides with our code or the DTB below.
    ldr     x1, =__boot_stack_top
    mov     sp, x1

    // ------------------------------------------------------------------------
    // 4. BSS Zeroing
    // ------------------------------------------------------------------------
    // Clear the .bss section (uninitialized data) to zero as required by C/Rust.
    ldr     x1, =__bss_start
    ldr     x2, =__bss_end
.L_bss_loop:
    cmp     x1, x2
    b.eq    .L_bss_done
    str     xzr, [x1], #8   // Store 0 (xzr) and increment address by 8 bytes
    b       .L_bss_loop

.L_bss_done:
    // ------------------------------------------------------------------------
    // 5. Jump to Rust
    // ------------------------------------------------------------------------
    // x0 currently holds the physical address of the DTB (passed by QEMU).
    // The ARM calling convention (AAPCS64) states that x0 is the first argument.
    // We branch to our Rust entry point `kmain(dtb_ptr)`.
    bl      kmain

    // If kmain ever returns, fall through to halt.

.L_halt:
    // Infinite loop putting the core to sleep.
    wfe
    b       .L_halt
