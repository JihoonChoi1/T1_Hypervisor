// ============================================================================
// irq/mod.rs — Interrupt management module root
//
// This module owns all interrupt-controller initialisation and routing
// logic for the T1 Hypervisor.
//
// Submodules:
//   • gic  — GICv2 Distributor + CPU Interface driver (TODO)
// ============================================================================

/// GICv2 driver: distributor init, SPI routing, CPU-interface masking.
pub mod gic;
