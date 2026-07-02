#!/usr/bin/env python3
"""Cross-implementation parity gate.

Runs every reference verifier in this repository over the byte-pinned
fixture set and asserts that all implementations agree per fixture on:

  1. gate status   -- PASS/FAIL against the fixture's pinned `expected` block
  2. verdict       -- ACCEPT vs REJECT
  3. reject category (when REJECT)

The verifiers already self-check against each fixture's `expected` block, so
a green run of each verifier proves agreement with the pinned oracle. This
script makes the cross-implementation agreement explicit and machine-readable:
it fails if any verifier skips a fixture the other saw, disagrees on verdict
or category, or exits non-zero.

Known, documented asymmetry: the Go verifier validates ML-DSA-65 signatures;
the Python verifier records them as present and validates Ed25519 only. That
asymmetry lives below the verdict level, so it does not (and must not) show
up as a verdict or category divergence here.

Usage:
    python3 scripts/parity/parity.py [--json parity-report.json]

Exit codes: 0 = all implementations agree, 1 = divergence or verifier error.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

VERIFIERS = {
    "go": {
        "cwd": REPO_ROOT / "verifiers" / "go",
        "cmd": ["go", "run", ".", "../../fixtures"],
    },
    "python": {
        "cwd": REPO_ROOT / "verifiers" / "python",
        "cmd": [sys.executable, "verify.py", "../../fixtures"],
    },
}

# `PASS  <path>` or `FAIL  <path>` opens a per-fixture block.
BLOCK_RE = re.compile(r"^(PASS|FAIL)\s+(\S+)")
# `observed: ACCEPT` or `observed: REJECT[CATEGORY: reason]`
OBSERVED_RE = re.compile(r"^\s*observed:\s+(ACCEPT|REJECT\[([A-Z_]+))")


def run_verifier(name: str, spec: dict) -> tuple[int, dict[str, dict]]:
    """Run one verifier; return (exit_code, {fixture_basename: record})."""
    proc = subprocess.run(
        spec["cmd"], cwd=spec["cwd"], capture_output=True, text=True
    )
    records: dict[str, dict] = {}
    current: str | None = None
    for line in proc.stdout.splitlines():
        m = BLOCK_RE.match(line)
        if m:
            current = Path(m.group(2)).name
            records[current] = {"gate": m.group(1), "verdict": None, "category": None}
            continue
        if current is None:
            continue
        om = OBSERVED_RE.match(line)
        if om:
            if om.group(1) == "ACCEPT":
                records[current]["verdict"] = "ACCEPT"
            else:
                records[current]["verdict"] = "REJECT"
                records[current]["category"] = om.group(2)
    if proc.returncode != 0:
        sys.stderr.write(f"[parity] {name} verifier exited {proc.returncode}\n")
        sys.stderr.write(proc.stdout[-2000:] + proc.stderr[-2000:] + "\n")
    return proc.returncode, records


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", metavar="PATH", help="write a JSON parity report")
    args = ap.parse_args()

    fixture_files = sorted(p.name for p in (REPO_ROOT / "fixtures").glob("*.json"))
    if not fixture_files:
        sys.stderr.write("[parity] no fixtures found\n")
        return 1

    results: dict[str, dict[str, dict]] = {}
    exit_codes: dict[str, int] = {}
    for name, spec in VERIFIERS.items():
        code, records = run_verifier(name, spec)
        exit_codes[name] = code
        results[name] = records

    divergences: list[str] = []

    for name, code in exit_codes.items():
        if code != 0:
            divergences.append(f"{name} verifier exited {code} (expected 0)")

    for name, records in results.items():
        seen = sorted(records)
        if seen != fixture_files:
            missing = set(fixture_files) - set(seen)
            extra = set(seen) - set(fixture_files)
            divergences.append(
                f"{name} fixture set mismatch: missing={sorted(missing)} extra={sorted(extra)}"
            )

    names = list(VERIFIERS)
    table: dict[str, dict] = {}
    for fx in fixture_files:
        row = {n: results[n].get(fx) for n in names}
        table[fx] = row
        present = [n for n in names if row[n] is not None]
        for field in ("gate", "verdict", "category"):
            vals = {n: row[n][field] for n in present}
            if len(set(vals.values())) > 1:
                divergences.append(f"{fx}: {field} divergence {vals}")

    print(f"parity: {len(fixture_files)} fixtures x {len(names)} verifiers")
    for fx, row in table.items():
        cells = []
        for n in names:
            r = row[n]
            if r is None:
                cells.append(f"{n}=MISSING")
            else:
                v = r["verdict"] or "?"
                cat = f"[{r['category']}]" if r["category"] else ""
                cells.append(f"{n}={r['gate']}:{v}{cat}")
        print(f"  {fx:44s} {'  '.join(cells)}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "fixtures": table,
                    "exitCodes": exit_codes,
                    "divergences": divergences,
                    "agree": not divergences,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    if divergences:
        print("\nPARITY: FAIL")
        for d in divergences:
            print(f"  - {d}")
        return 1
    print("\nPARITY: PASS (all implementations agree on gate, verdict, and category)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
