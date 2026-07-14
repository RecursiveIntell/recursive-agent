#!/usr/bin/env python3
"""M0 negative-tamper test.

Usage: tamper.py <run-dir>

Reads the second receipt in `<run-dir>/receipts.ndjson`, flips the first
hex character of `prev_chain_digest` to a different valid hex character,
and writes the result back. The chain walker MUST reject the result.
"""
import json
import sys
from pathlib import Path


def main() -> int:
    run_dir = Path(sys.argv[1])
    path = run_dir / "receipts.ndjson"
    text = path.read_text()
    lines = [line for line in text.splitlines() if line]
    if len(lines) < 2:
        print("tamper: need at least 2 lines", file=sys.stderr)
        return 2
    receipt = json.loads(lines[1])
    old = receipt["prev_chain_digest"]["hex"]
    new_first = "0" if old[0] != "0" else "1"
    new = new_first + old[1:]
    receipt["prev_chain_digest"]["hex"] = new
    lines[1] = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    print(f"tampered: {old} -> {new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
