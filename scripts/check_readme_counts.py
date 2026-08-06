#!/usr/bin/env python3
"""Assert the fixture counts stated in README.md match the fixture set.

The README states the expected verifier result in two places: the continuous
verification list ("N pass, 0 fail") and the implementations table ("N / N
PASS"). Both are measurements over fixtures/, so they are enforced here
rather than maintained by hand. Both drifted once already: the list claimed
7 pass and the table claimed 4 / 4 after the fixture set had grown to 13.

Exit 0 when every stated count matches the fixture set, 1 otherwise.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
FIXTURES = ROOT / "fixtures"


def main():
    actual = len(sorted(FIXTURES.glob("*.json")))
    if actual == 0:
        print("no fixtures found; refusing to pass vacuously", file=sys.stderr)
        return 1

    readme = README.read_text(encoding="utf-8")
    failures = []

    # "must report `20 pass, 0 fail`" in the continuous-verification list.
    pass_fail = re.findall(r"`(\d+) pass, (\d+) fail`", readme)
    if not pass_fail:
        failures.append("no `N pass, 0 fail` claim found in README")
    for stated, failed in pass_fail:
        if int(stated) != actual:
            failures.append(
                f"README claims `{stated} pass` but fixtures/ holds {actual}"
            )
        if int(failed) != 0:
            failures.append(f"README claims `{failed} fail`, expected 0")

    # "20 / 20 PASS" rows in the implementations table.
    table = re.findall(r"(\d+)\s*/\s*(\d+)\s+PASS", readme)
    if not table:
        failures.append("no `N / N PASS` row found in README")
    for got, total in table:
        if int(total) != actual:
            failures.append(
                f"README implementations table claims {got} / {total} PASS "
                f"but fixtures/ holds {actual}"
            )
        if got != total:
            failures.append(f"README table row {got} / {total} PASS is not a full pass")

    if failures:
        print("README counts do not match fixtures/:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"README counts match fixtures/: {actual} fixtures, all stated as passing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
