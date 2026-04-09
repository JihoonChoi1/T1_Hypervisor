// ============================================================================
// memory/pmm.rs — Buddy Allocator (Physical Memory Manager)
//
// Design contract:
//   • Zero runtime overhead on the HFT hot path — alloc from the general pool
//     on boot only; the HFT region is pre-carved at init time and never freed.
//   • No heap dependency: list bookkeeping lives *inside* free pages themselves
//     (intrusive doubly-linked list).
//   • Rust 2024 compatible: no references to `static mut` — all global PMM
//     access goes through `addr_of_mut!(PMM)` raw pointers.
//
// References:
//   Mel Gorman, "Understanding the Linux Virtual Memory Manager", Ch 6: Buddy Allocator.
//   ARM DDI 0487 — no direct dependency; this module is pure Rust logic.
//   src/linker.ld — provides __kernel_end (pool lower bound, 4 KiB-aligned).
// ============================================================================

#![allow(dead_code)] // Public API used in later steps; keep silently.

use crate::{
    memory::{RAM_END, RAM_START, UART_MMIO_BASE, UART_MMIO_END},
    // uart::UART,
};
// use core::fmt::Write;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Smallest allocatable unit: 4 KiB (one physical page frame).
pub const PAGE_SIZE: usize = 4096;

/// Number of buddy orders.  Order 0 = 4 KiB … Order 17 = 512 MiB.
/// 18 levels span a 1 GiB address space with no wasted bits.
pub const MAX_ORDER: usize = 18;

// ── Intrusive free-list node ──────────────────────────────────────────────────
//
// When a page frame is free the allocator overlays the first 16 bytes with a
// doubly-linked list node.  When the frame is allocated those bytes belong to
// the caller; the list pointers are irrelevant.

#[repr(C)]
struct FreeBlock {
    next: *mut FreeBlock,
    prev: *mut FreeBlock,
}

impl FreeBlock {
    /// Cast `addr` to a `*mut FreeBlock`.
    ///
    /// # Safety
    /// `addr` must be a valid, writable, page-aligned physical address owned
    /// by the allocator (i.e. free and inside the PMM pool).
    #[inline]
    unsafe fn at(addr: usize) -> *mut Self {
        addr as *mut Self
    }
}

// ── BuddyAllocator ────────────────────────────────────────────────────────────

pub struct BuddyAllocator {
    /// Sentinel heads of the per-order doubly-linked free lists.
    ///
    /// The sentinel lives in the struct (not in a page), so an empty list is
    /// representable: `head.next == head as *mut _`.  Initialised by `init().`
    free_lists: [FreeBlock; MAX_ORDER],

    /// Total free page frames tracked across all orders.
    free_pages: usize,
}

// SAFETY: single-core early-boot use only.  SMP spinlock added before CPU
// bring-up.
unsafe impl Send for BuddyAllocator {}

impl BuddyAllocator {
    /// Returns a zeroed (empty) allocator.  Sentinels are fixed up in `init()`.
    pub const fn new() -> Self {
        const SENTINEL: FreeBlock = FreeBlock {
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
        };
        Self {
            free_lists: [SENTINEL; MAX_ORDER],
            free_pages: 0,
        }
    }

    // ── init ──────────────────────────────────────────────────────────────────

    /// Populate the free lists with every page in `[pool_start, RAM_END)`.
    ///
    /// # Safety
    /// * Called exactly once before any `alloc`/`free`.
    /// * `pool_start` is the 4 KiB-aligned value of `__kernel_end`.
    /// * Single-core execution (early boot).
    ///
    /// The entire physical range `[pool_start, RAM_END)` is added to the free
    /// lists.  HFT and Management pages are separated by page coloring at
    /// allocation time via `cache_color::alloc_hft_page()` (colors 0–7) and
    /// `cache_color::alloc_mgmt_page()` (colors 8–15).  No sub-range is
    /// permanently carved out here.
    pub unsafe fn init(&mut self, pool_start: usize) {
        // 1. Fix up sentinel heads so every list is empty but self-referential.
        for order in 0..MAX_ORDER {
            // SAFETY: taking a raw pointer to our own field, then writing
            // through it — valid because we own `*self`.
            let head: *mut FreeBlock = core::ptr::addr_of_mut!(self.free_lists[order]);
            unsafe {
                (*head).next = head;
                (*head).prev = head;
            }
        }

        // 2. Walk [pool_start, PMM_END) and insert naturally-aligned blocks.
        let mut cursor = align_up(pool_start, PAGE_SIZE);
        while cursor < RAM_END {
            // Largest order whose block fits the remaining space.
            let max_by_size = {
                let rem = RAM_END - cursor;
                let mut o = MAX_ORDER - 1;
                while o > 0 && (PAGE_SIZE << o) > rem {
                    o -= 1;
                }
                // writeln!(&mut &UART, "[pmm ]   max_by_size    = {o}").ok();
                o
            };
            // Largest order whose block is naturally aligned at `cursor`.
            let max_by_align = if cursor == 0 {
                MAX_ORDER - 1
            } else {
                let pages = cursor / PAGE_SIZE;
                (pages.trailing_zeros() as usize).min(MAX_ORDER - 1)
            };

            let order = max_by_size.min(max_by_align);
            let block_size = PAGE_SIZE << order;
            let block_end = cursor + block_size;

            // Skip any accidental overlap with UART MMIO (belt-and-suspenders;
            // UART at 0x0900_0000 is below RAM_START so never reached).
            if cursor < UART_MMIO_END && block_end > UART_MMIO_BASE {
                cursor = align_up(UART_MMIO_END, PAGE_SIZE);
                continue;
            }

            // SAFETY: cursor is page-aligned, inside pool, currently free.
            unsafe { self.push_free(cursor, order) };
            self.free_pages += 1 << order; // track pages added during init
            cursor += block_size;
        }
    }

    // ── alloc ─────────────────────────────────────────────────────────────────

    /// Allocate `PAGE_SIZE << order` contiguous bytes.  Returns the physical
    /// base address, or `None` if OOM.
    ///
    /// Splits a larger block if necessary.
    ///
    /// # Panics
    /// Panics if `order >= MAX_ORDER`.
    pub fn alloc(&mut self, order: usize) -> Option<usize> {
        assert!(order < MAX_ORDER, "pmm: order {order} >= MAX_ORDER");

        // Find smallest available order >= requested.
        let available = (order..MAX_ORDER).find(|&o| !self.list_is_empty(o))?;
        let addr = unsafe { self.pop_free(available) };

        // Split down, returning unused halves.
        let mut cur_order = available;
        while cur_order > order {
            cur_order -= 1;
            let buddy = addr + (PAGE_SIZE << cur_order);
            unsafe { self.push_free(buddy, cur_order) };
        }

        self.free_pages -= 1 << order;
        Some(addr)
    }

    // ── alloc_at ─────────────────────────────────────────────────────────────

    /// Remove a specific block at `addr` (of `order`) from the free pool.
    ///
    /// Removes a specific block at `addr` (of `order`) from the free pool.
    /// Returns `true` on success.
    ///
    /// # Safety
    /// `addr` must be naturally aligned to `PAGE_SIZE << order`.
    pub unsafe fn alloc_at(&mut self, addr: usize, order: usize) -> bool {
        assert!(order < MAX_ORDER, "pmm: alloc_at order >= MAX_ORDER");
        assert_eq!(
            addr % (PAGE_SIZE << order),
            0,
            "pmm: alloc_at addr misaligned"
        );

        for search in order..MAX_ORDER {
            let ancestor = addr & !((PAGE_SIZE << search) - 1);
            // SAFETY: remove_from_list only reads/writes list pointers.
            if unsafe { self.remove_from_list(ancestor, search) } {
                // Split ancestor down to the desired `order`.
                let mut cur_order = search;
                let mut cur_addr = ancestor;
                while cur_order > order {
                    cur_order -= 1;
                    let half = PAGE_SIZE << cur_order;
                    let (left, right) = (cur_addr, cur_addr + half);
                    if addr < right {
                        unsafe { self.push_free(right, cur_order) };
                        cur_addr = left;
                    } else {
                        unsafe { self.push_free(left, cur_order) };
                        cur_addr = right;
                    }
                }
                self.free_pages -= 1 << order;
                return true;
            }
        }
        false
    }

    // ── free ─────────────────────────────────────────────────────────────────

    /// Return `addr` (previously allocated at `order`) to the pool.
    ///
    /// Coalesces with its XOR-buddy until no free buddy remains.
    ///
    /// # Safety
    /// * `addr` must be from `alloc(order)` or `alloc_at`.
    /// * `order` must match the allocation order.
    /// * Double-free is UB and will silently corrupt the allocator.
    ///
    /// # Panics
    /// Panics if `addr` is misaligned or out of pool range.
    pub unsafe fn free(&mut self, mut addr: usize, mut order: usize) {
        assert!(order < MAX_ORDER, "pmm: free order >= MAX_ORDER");
        assert_eq!(
            addr % (PAGE_SIZE << order),
            0,
            "pmm: free {addr:#x} misaligned for order {order}"
        );
        assert!(
            addr >= RAM_START && addr < RAM_END,
            "pmm: free {addr:#x} out of pool"
        );

        self.free_pages += 1 << order;

        // Merge-up loop.
        while order < MAX_ORDER - 1 {
            let buddy = buddy_of(addr, order);
            if buddy < RAM_START || buddy >= RAM_END {
                break;
            }
            // SAFETY: remove_from_list iterates list pointers safely.
            if !unsafe { self.remove_from_list(buddy, order) } {
                break;
            }
            addr = addr.min(buddy);
            order += 1;
        }

        unsafe { self.push_free(addr, order) };
    }

    // ── Diagnostics ───────────────────────────────────────────────────────────

    /// Total free page frames across all orders.
    #[inline]
    pub fn free_pages(&self) -> usize {
        self.free_pages
    }

    /// Number of free blocks at a specific order level.
    pub fn free_blocks_at_order(&self, order: usize) -> usize {
        assert!(order < MAX_ORDER);
        let mut count = 0usize;
        let head: *const FreeBlock = core::ptr::addr_of!(self.free_lists[order]);
        unsafe {
            let mut cur = (*head).next;
            while cur != head as *mut _ {
                count += 1;
                cur = (*cur).next;
            }
        }
        count
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    #[inline]
    fn list_is_empty(&self, order: usize) -> bool {
        let head: *const FreeBlock = core::ptr::addr_of!(self.free_lists[order]);
        unsafe { (*head).next == head as *mut _ }
    }

    /// Push `addr` onto the front of the `order` free list.
    ///
    /// # Safety
    /// `addr` page-aligned, writable, owned by allocator.
    #[inline]
    unsafe fn push_free(&mut self, addr: usize, order: usize) {
        let head: *mut FreeBlock = core::ptr::addr_of_mut!(self.free_lists[order]);
        let node = unsafe { FreeBlock::at(addr) };
        unsafe {
            let old_first = (*head).next;
            (*node).next = old_first;
            (*node).prev = head;
            (*old_first).prev = node;
            (*head).next = node;
        }
    }

    /// Pop and return the address of the first block from the `order` list.
    ///
    /// # Safety
    /// List for `order` must be non-empty.
    #[inline]
    unsafe fn pop_free(&mut self, order: usize) -> usize {
        let head: *mut FreeBlock = core::ptr::addr_of_mut!(self.free_lists[order]);
        unsafe {
            let node = (*head).next;
            let next = (*node).next;
            (*head).next = next;
            (*next).prev = head;
            node as usize
        }
    }

    /// Remove the block at `addr` from the `order` list.
    ///
    /// Returns `true` if found and removed.
    unsafe fn remove_from_list(&mut self, addr: usize, order: usize) -> bool {
        let head: *const FreeBlock = core::ptr::addr_of!(self.free_lists[order]);
        let target = unsafe { FreeBlock::at(addr) };
        let mut cur = unsafe { (*head).next };

        while cur != head as *mut _ {
            if cur == target {
                unsafe {
                    let prev = (*cur).prev;
                    let next = (*cur).next;
                    (*prev).next = next;
                    (*next).prev = prev;
                }
                return true;
            }
            cur = unsafe { (*cur).next };
        }
        false
    }

    /// Allocate an order-0 page (4 KiB) satisfying `predicate(pa) == true`.
    ///
    /// Scans every order's free list from order-0 upward.  When a block is
    /// found that *contains* a matching page, the block is extracted from its
    /// free list and split down to exactly the matching order-0 page.  Halves
    /// that do not contain the target page are returned to their respective
    /// free lists — exactly as `alloc()` does.
    ///
    /// # `guaranteed_order` hint
    /// If the caller can prove that any block of order >= K is guaranteed to
    /// contain at least one page satisfying `predicate`, pass `Some(K)`.
    ///
    /// For page coloring with N colors: `K = log2(N)`.  Proof: a block of
    /// order K has `2^K = N` consecutive pages whose colors are `0..N` mod N
    /// — all N colors appear exactly once, so any color-based predicate matches.
    ///
    /// With the hint the scan short-circuits on the first block at or above K
    /// (no inner sub-page loop), and the split-down phase skips the sub-page
    /// check for halves that are still large enough to guarantee a match.
    /// Pass `None` for a fully generic predicate with no guarantee.
    ///
    /// # Guarantee
    /// If any order-0 page satisfying `predicate` remains in the pool,
    /// this function will find and return it.  False negatives are impossible.
    ///
    /// # Complexity
    /// O(total free blocks across all orders); inner sub-page scans are skipped
    /// once `search_order >= guaranteed_order`.  Boot-time only.
    ///
    /// # Safety
    /// Must be called after `init()`.
    pub unsafe fn alloc_with_filter<F>(
        &mut self,
        predicate: F,
        guaranteed_order: Option<usize>,
    ) -> Option<usize>
    where
        F: Fn(usize) -> bool,
    {
        // `guaranteed` is the threshold above which every block is guaranteed
        // to contain a matching page.  MAX_ORDER (unreachable) disables the hint.
        let guaranteed = guaranteed_order.unwrap_or(MAX_ORDER);

        for search_order in 0..MAX_ORDER {
            let head: *const FreeBlock = core::ptr::addr_of!(self.free_lists[search_order]);

            // Scan this order's free list for a block containing a matching page.
            let mut cur = unsafe { (*head).next };
            let mut found_block: Option<usize> = None;

            'list: while cur != head as *mut _ {
                let block_pa = cur as usize;

                if search_order >= guaranteed {
                    // Every block at this order contains all colors — take the
                    // first one without scanning sub-pages.
                    found_block = Some(block_pa);
                    break 'list;
                }

                // Does this block contain at least one page satisfying predicate?
                // Check each order-0 sub-page within the block.
                let num_pages = 1usize << search_order;
                for i in 0..num_pages {
                    if predicate(block_pa + i * PAGE_SIZE) {
                        found_block = Some(block_pa);
                        break 'list;
                    }
                }
                cur = unsafe { (*cur).next };
            }

            let Some(found_pa) = found_block else {
                continue; // No matching block in this order; try the next order up.
            };

            // Remove the matching block from its free list.
            let removed = unsafe { self.remove_from_list(found_pa, search_order) };
            assert!(
                removed,
                "pmm: alloc_with_filter remove_from_list inconsistency"
            );
            self.free_pages -= 1 << search_order;

            // Split the block down, always keeping the half that contains
            // a page satisfying predicate, returning the other half to its list.
            let mut cur_pa = found_pa;
            let mut cur_order = search_order;

            while cur_order > 0 {
                cur_order -= 1;
                let half = PAGE_SIZE << cur_order;
                let left_pa = cur_pa;
                let right_pa = cur_pa + half;

                // If the left half is still large enough to guarantee a match,
                // skip the sub-page scan and always keep left.
                let left_has_match = if cur_order >= guaranteed {
                    true
                } else {
                    let n = 1usize << cur_order;
                    let mut found = false;
                    for i in 0..n {
                        if predicate(left_pa + i * PAGE_SIZE) {
                            found = true;
                            break;
                        }
                    }
                    found
                };

                if left_has_match {
                    // Keep left, return right to free list.
                    unsafe { self.push_free(right_pa, cur_order) };
                    self.free_pages += 1 << cur_order;
                    cur_pa = left_pa;
                } else {
                    // Keep right, return left to free list.
                    unsafe { self.push_free(left_pa, cur_order) };
                    self.free_pages += 1 << cur_order;
                    cur_pa = right_pa;
                }
            }

            // cur_pa is now an order-0 page satisfying predicate.
            assert!(predicate(cur_pa), "pmm: alloc_with_filter split logic bug");
            return Some(cur_pa);
        }

        None // No page satisfying predicate found anywhere in the pool.
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────────

/// XOR-buddy address: flip the bit at position `log2(PAGE_SIZE << order)`.
///
/// Example: `buddy_of(0x4010_0000, 0)` == `0x4010_1000`
///           `buddy_of(0x4010_0000, 1)` == `0x4010_2000`
#[inline]
fn buddy_of(addr: usize, order: usize) -> usize {
    addr ^ (PAGE_SIZE << order)
}

/// Round `addr` up to the next multiple of `align` (must be a power of two).
#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

// ── Global PMM instance ───────────────────────────────────────────────────────
//
// All access goes through `addr_of_mut!(PMM)` raw pointers to satisfy the
// Rust 2024 `static_mut_refs` lint, which forbids any `&`/`&mut` reference
// to a `static mut`.

static mut PMM: BuddyAllocator = BuddyAllocator::new();

/// Initialise the global PMM.  Must be called once before any `alloc`/`free`.
///
/// # Safety
/// See `BuddyAllocator::init`.
pub unsafe fn init(pool_start: usize) {
    unsafe { (*core::ptr::addr_of_mut!(PMM)).init(pool_start) }
}

/// Allocate `PAGE_SIZE << order` bytes from the global PMM.
///
/// # Safety
/// Must be called after `pmm::init()`.
pub unsafe fn alloc(order: usize) -> Option<usize> {
    unsafe { (*core::ptr::addr_of_mut!(PMM)).alloc(order) }
}

/// Return a block to the global PMM.
///
/// # Safety
/// See `BuddyAllocator::free`.
pub unsafe fn free(addr: usize, order: usize) {
    unsafe { (*core::ptr::addr_of_mut!(PMM)).free(addr, order) }
}

/// Total free page frames in the global PMM.
///
/// # Safety
/// Must be called after `pmm::init()`.
pub unsafe fn free_pages() -> usize {
    unsafe { (*core::ptr::addr_of_mut!(PMM)).free_pages() }
}

/// Free blocks at a given order in the global PMM.
///
/// # Safety
/// Must be called after `pmm::init()`.
pub unsafe fn free_blocks_at_order(order: usize) -> usize {
    unsafe { (*core::ptr::addr_of_mut!(PMM)).free_blocks_at_order(order) }
}

/// Allocate one order-0 page from the global PMM satisfying `predicate`.
///
/// Thin wrapper around `BuddyAllocator::alloc_with_filter`.
/// See that method for full documentation and complexity analysis.
///
/// # Safety
/// Must be called after `pmm::init()`.  Not for use on the HFT hot path.
pub unsafe fn alloc_with_filter<F>(predicate: F, guaranteed_order: Option<usize>) -> Option<usize>
where
    F: Fn(usize) -> bool,
{
    unsafe { (*core::ptr::addr_of_mut!(PMM)).alloc_with_filter(predicate, guaranteed_order) }
}
