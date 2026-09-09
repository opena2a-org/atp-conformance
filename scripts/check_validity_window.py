#!/usr/bin/env python3
"""ATP §10.2 trust-proof validity window guard.

"Trust proofs MUST have a maximum validity period of 24 hours." Every
fixture that carries a trustProof object must declare an
expiresAt - issuedAt of at most 24 hours, so the suite never ships a
proof a §10.2-enforcing verifier would have to refuse on issuance
grounds. The one exception is the suite's own ATP §4.4 step-5 must-reject
vector: a trustProof fixture whose expected block says REJECT with
category SEMANTIC_INVALID for reason "validity window" declares a window
above the maximum on purpose, and is exempted (and not counted) here.
Standard library only; run from the repository root.
"""

import datetime
import json
import pathlib
import sys

MAX_VALIDITY = datetime.timedelta(hours=24)


def parse_rfc3339_utc(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def is_window_reject_vector(fixture):
    """True iff the fixture's expected block labels it as the ATP §4.4
    step-5 must-reject vector (REJECT / SEMANTIC_INVALID / "validity window").
    Only such a fixture may declare a window above the §10.2 maximum."""
    expected = fixture.get("expected")
    if not isinstance(expected, dict):
        return False
    return (
        expected.get("verifyResult") == "REJECT"
        and expected.get("rejectCategory") == "SEMANTIC_INVALID"
        and expected.get("reasonContains") == "validity window"
    )


def main():
    violations = []
    checked = 0
    for path in sorted(pathlib.Path("fixtures").glob("*.json")):
        with open(path, encoding="utf-8") as f:
            fixture = json.load(f)
        proof = fixture.get("trustProof")
        if not isinstance(proof, dict):
            continue
        if is_window_reject_vector(fixture):
            print(
                f"{path.name}: exempt (the suite's ATP §4.4 step-5 must-reject "
                "vector declares a window above the §10.2 maximum on purpose)"
            )
            continue
        checked += 1
        try:
            issued = parse_rfc3339_utc(proof["issuedAt"])
            expires = parse_rfc3339_utc(proof["expiresAt"])
        except (KeyError, TypeError, ValueError) as err:
            print(f"{path.name}: unparseable trustProof timestamp: {err}")
            return 1
        period = expires - issued
        if period > MAX_VALIDITY:
            violations.append((path.name, period))

    if checked == 0:
        print("no fixture carries a trustProof object; refusing to pass vacuously")
        return 1

    if violations:
        print(
            "ATP §10.2: trust proofs MUST have a maximum validity period of "
            "24 hours; these fixtures exceed it:"
        )
        for name, period in violations:
            print(f"  {name}: validity period {period}")
        return 1

    print(f"ATP §10.2 validity window OK over {checked} trust proofs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
