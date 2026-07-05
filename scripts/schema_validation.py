#!/usr/bin/env python3
"""Validate every fixture's embedded ATP payload against the vendored spec schemas.

The schemas are the machine-readable models published by agent-trust-protocol
(schemas/{trust-proof,signed-tree-head,discovery}-v1.schema.json), vendored
under schemas/vendor/agent-trust-protocol/ and byte-drift-gated in CI against
the pinned ATP_SPEC_REF.

Contract: every fixture carries exactly one payload member (trustProof,
signedTreeHead, discoveryResponse, inclusionProof, consistencyProof, or
revocationList) and that payload MUST validate against its schema. All
REJECT fixtures are crypto/state/strict-parse rejects, so they are
shape-valid by design (timestamp formats are schema annotations; the
verifiers enforce RFC 3339 parsing); a fixture failing schema validation
means fixtures and schemas have drifted apart.
"""

import json
import pathlib
import sys

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    print("error: the 'jsonschema' package is required (pip install jsonschema)")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "schemas" / "vendor" / "agent-trust-protocol"

PAYLOAD_SCHEMAS = {
    "trustProof": "trust-proof-v1.schema.json",
    "signedTreeHead": "signed-tree-head-v1.schema.json",
    "discoveryResponse": "discovery-v1.schema.json",
    "inclusionProof": "inclusion-proof-v1.schema.json",
    "consistencyProof": "consistency-proof-v1.schema.json",
    "revocationList": "revocation-list-v1.schema.json",
}


def main() -> int:
    # Cross-schema $refs (the proof schemas embed signed-tree-head-v1 by its
    # $id) resolve from a local registry over the vendored copies — never the
    # network.
    resources = []
    for sf in sorted(VENDOR.glob("*.schema.json")):
        doc = json.loads(sf.read_text(encoding="utf-8"))
        if "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc)))
    registry = Registry().with_resources(resources)

    validators = {}
    for member, filename in PAYLOAD_SCHEMAS.items():
        schema = json.loads((VENDOR / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validators[member] = Draft202012Validator(schema, registry=registry)

    failures = 0
    fixtures = sorted((ROOT / "fixtures").glob("*.json"))
    if not fixtures:
        print("error: no fixtures found")
        return 1

    for path in fixtures:
        doc = json.loads(path.read_text(encoding="utf-8"))
        members = [m for m in PAYLOAD_SCHEMAS if m in doc]
        if len(members) != 1:
            print(f"FAIL  {path.name}: expected exactly one payload member, found {members}")
            failures += 1
            continue
        member = members[0]
        errors = sorted(validators[member].iter_errors(doc[member]), key=lambda e: e.json_path)
        if errors:
            print(f"FAIL  {path.name} ({member}):")
            for err in errors:
                print(f"      {err.json_path}: {err.message}")
            failures += 1
        else:
            print(f"PASS  {path.name} ({member})")

    print(f"\nsummary: {len(fixtures) - failures} pass, {failures} fail ({len(fixtures)} fixtures)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
