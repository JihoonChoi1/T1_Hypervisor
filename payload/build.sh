#!/usr/bin/env bash
# ============================================================================
# payload/build.sh — build the HFT guest payload image
#
# Output: payload/hft_payload.bin  (raw binary, ORG=0x4000_0000)
#
# ── Why cd into payload/ ─────────────────────────────────────────────────
# Cargo's config-file search is rooted at the CURRENT WORKING DIRECTORY,
# not at --manifest-path.  Running `cargo build --manifest-path
# payload/Cargo.toml` from the repo root would therefore read the repo
# root's .cargo/config.toml (with `-Tsrc/linker.ld`) and miss the
# payload's .cargo/config.toml entirely.  Easier and more robust: cd
# into the sub-crate before invoking cargo.
#
# ── Why export RUSTFLAGS ─────────────────────────────────────────────────
# Cargo walks up from cwd looking for .cargo/config.toml files, and
# CONCATENATES target.<triple>.rustflags across every one it finds.
# That means after cd'ing into payload/, cargo would append the repo
# root's `-C link-arg=-Tsrc/linker.ld` onto our `-C link-arg=-Tlinker.ld`
# — two `-T` scripts on the linker command line, which breaks the layout.
# Per the Cargo reference, the RUSTFLAGS env var sits above
# target.<triple>.rustflags in the precedence chain and REPLACES (not
# concatenates) them, so this export cleanly overrides the merge.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export RUSTFLAGS="-C link-arg=-Tlinker.ld"

BIN="target/aarch64-unknown-none/release/hft_payload"
OUT="hft_payload.bin"

echo "[build] cargo build --release  (target = aarch64-unknown-none)"
cargo build --release

echo "[build] rust-objcopy -O binary  ${BIN}  ->  ${OUT}"
rust-objcopy -O binary "${BIN}" "${OUT}"

echo "[build] ------------------------------------------------------------"
ls -l "${OUT}"

SIZE=$(wc -c < "${OUT}" | tr -d ' ')
if (( SIZE % 4 != 0 )); then
    echo "[build] FAIL: ${OUT} is ${SIZE} bytes — AArch64 instructions must be 4-byte aligned" >&2
    exit 1
fi

echo "[build] size   : ${SIZE} bytes  (4-byte aligned: OK)"
echo "[build] head   :"
hexdump -C "${OUT}" | head -1
