#!/usr/bin/env python3
"""Capture a step-through demo run of the hypervisor as JSON.

Builds the kernel with `--features demo`, boots it under QEMU, and plays the
operator: presses Enter at every `[demo] step ...` gate, lets the guest run
for a few heartbeat samples, presses `k`, and stops once the observer reports
the heartbeat frozen.  Every UART line is recorded with its arrival time, and
the run is split into steps at the gates.

The output is what the personal website replays.  It comes from a real run of
the real binary, so it can be regenerated at any commit:

    python3 scripts/capture_demo.py                 # -> demo/transcript.json
    python3 scripts/capture_demo.py -o other.json --samples 8
"""

import argparse
import json
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "target/aarch64-unknown-none/release/T1_Hypervisor"
QEMU = [
    "qemu-system-aarch64",
    "-machine", "virt,virtualization=on",
    "-cpu", "cortex-a57",
    "-smp", "4",
    "-m", "1G",
    "-nographic",
    "-kernel", str(KERNEL),
]

# Must match the format in src/demo.rs.
GATE = re.compile(r"^\[demo\] step (\d+)/(\d+) done\. Next: (.*?)\s+\(press Enter\)$")
KILL_PROMPT = "[demo] press k to pull the kill switch."
HEARTBEAT = re.compile(r"^\[wd  \] heartbeat=\d+ \(misses=0\)$")
FROZEN = re.compile(r"^\[wd  \] guest halted: heartbeat frozen")
PANIC = "[PANIC]"

QUIET_S = 0.3      # output must be idle this long before a key is pressed
TIMEOUT_S = 60.0   # whole run


def git(*args):
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def reader(stream, out):
    """Push (arrival_time, line) for every line QEMU prints."""
    buf = b""
    while True:
        chunk = stream.read1(4096)
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            out.put((time.monotonic(), raw.decode("utf-8", "replace").rstrip("\r")))
    out.put(None)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--out", type=Path, default=ROOT / "demo/transcript.json")
    ap.add_argument("--samples", type=int, default=6,
                    help="healthy heartbeat samples to show before pressing k")
    args = ap.parse_args()

    subprocess.run(["cargo", "build", "--release", "--features", "demo"],
                   cwd=ROOT, check=True)

    qemu = subprocess.Popen(QEMU, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    lines = queue.Queue()
    threading.Thread(target=reader, args=(qemu.stdout, lines), daemon=True).start()

    def press(key):
        qemu.stdin.write(key)
        qemu.stdin.flush()

    t0 = time.monotonic()
    steps = [{"lines": []}]
    pending = None          # key to press once output goes quiet
    last_line_at = t0
    healthy = 0
    in_observer = False
    ok = False

    try:
        while time.monotonic() - t0 < TIMEOUT_S:
            try:
                item = lines.get(timeout=0.05)
            except queue.Empty:
                item = ()
            if item is None:
                break
            if item:
                at, text = item
                last_line_at = at
                if PANIC in text:
                    sys.exit(f"capture: guest panicked: {text}")
                gate = GATE.match(text)
                if gate:
                    steps[-1]["next"] = gate.group(3)
                    pending = b"\r"
                elif text == KILL_PROMPT:
                    in_observer = True
                elif text.strip() or steps[-1]["lines"]:
                    steps[-1]["lines"].append({"t": round(at - t0, 3), "text": text})
                if in_observer and HEARTBEAT.match(text):
                    healthy += 1
                    if healthy == args.samples:
                        pending = b"k"
                if FROZEN.match(text):
                    ok = True
                    break
            if pending and time.monotonic() - last_line_at >= QUIET_S:
                press(pending)
                if pending == b"\r":
                    steps.append({"lines": []})
                else:
                    steps[-1]["kill_at"] = round(time.monotonic() - t0, 3)
                pending = None
    finally:
        qemu.kill()
        qemu.wait()

    if not ok:
        sys.exit("capture: run did not reach the frozen-heartbeat line")

    # Times restart at 0 in every step: the website replays one step per click.
    for step in steps:
        while step["lines"] and not step["lines"][-1]["text"].strip():
            step["lines"].pop()
        if step["lines"]:
            base = step["lines"][0]["t"]
            for line in step["lines"]:
                line["t"] = round(line["t"] - base, 3)
            if "kill_at" in step:
                step["kill_at"] = round(step["kill_at"] - base, 3)

    transcript = {
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": git("rev-parse", "--short", "HEAD"),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "command": "cargo build --release --features demo && " + " ".join(
            QEMU[:-1] + ["target/aarch64-unknown-none/release/T1_Hypervisor"]),
        "steps": steps,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(transcript, indent=2, ensure_ascii=False) + "\n")
    total = sum(len(s["lines"]) for s in steps)
    print(f"capture: {len(steps)} steps, {total} lines -> {args.out}")


if __name__ == "__main__":
    main()
