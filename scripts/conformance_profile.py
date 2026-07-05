#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if committed file is stale
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "atp-conformance",
    "spec": {
        "id": "ATP",
        "name": "Agent Trust Protocol",
        "version": "1.0.0-rc1",
        "ref": "https://github.com/opena2a-standards/agent-trust-protocol/blob/main/ATP-SPEC.md",
    },
    "fixtureManifest": "MANIFEST.sha256",
    "verifiers": [
        {
            "language": "go",
            "path": "verifiers/go",
            "coverage": "full: Ed25519 and ML-DSA-65 (FIPS 204) hybrid signatures",
        },
        {
            "language": "python",
            "path": "verifiers/python",
            "coverage": "Ed25519; ML-DSA-65 signatures recorded as present, verification delegated to the Go verifier",
        },
    ],
    "notCovered": [
        {
            "specSection": "§6 Federation cosignature (Level 3)",
            "reason": "no second production authority exists to source a real cosigned proof from",
        },
        {
            "specSection": "§8.1 response authenticity",
            "reason": "the spec does not sign the revocation body (transport + per-entry transparencyLogIndex carry authenticity); the fixtures cover the structural rules only",
        },
    ],
}


def build() -> dict:
    requirements = []
    for path in sorted((REPO_ROOT / "fixtures").glob("*.json")):
        fx = json.loads(path.read_text())
        expected = fx["expected"]
        outcome = expected["verifyResult"]
        if expected.get("rejectCategory"):
            outcome = f"REJECT[{expected['rejectCategory']}]"
        requirements.append(
            {
                "fixture": f"fixtures/{path.name}",
                "name": fx["name"],
                "fixtureType": fx["fixtureType"],
                "level": "MUST",
                "specRefs": fx["spec"],
                "expected": outcome,
                "description": fx["description"],
            }
        )
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile


def main() -> int:
    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        if OUT.read_text() != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        print("conformance.json is current")
        return 0
    OUT.write_text(rendered)
    print(f"wrote conformance.json ({len(build()['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
