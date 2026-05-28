#!/usr/bin/env python3
"""Python reference verifier for the ATP v1.0.0-rc1 conformance fixture set.

Depends only on the Python standard library plus the `cryptography` package
(for Ed25519 verification). Does NOT import any opena2a-* SDK. The goal is to
demonstrate that an independent verifier in a second language reaches the same
ACCEPT / REJECT verdict as the Go reference verifier for every fixture.

Spec coverage:
  - ATP v1.0.0-rc1 §4.4 trust proof verification (Steps 1-5)
  - ATP §4.3 canonical pipe-delimited 7-field signing form
  - ATP §5.6 Signed Tree Head verification (Ed25519 over raw rootHash bytes)
  - ATP §7.1 well-known discovery structural verification

Out of scope:
  - ML-DSA-65 verification. The post-quantum Python library landscape is
    fragmented (no stdlib support, liboqs / dilithium-py require optional
    native dependencies). The hybrid fixture is annotated and accepted on
    the Ed25519 path alone; the ML-DSA-65 signature is recorded as present
    but its verification is not attempted. For spec-mandate full hybrid
    verification, run the Go reference verifier in ../go.

Usage:
    python verify.py ../../fixtures/trust-proof-baseline.json
    python verify.py ../../fixtures
    python verify.py ../..                 # repo root; walks fixtures/*.json

Exit 0 iff every fixture's observed result matches expected.verifyResult.
"""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write(
        "missing dependency: cryptography. install with `pip install -r requirements.txt`\n"
    )
    sys.exit(2)


SUPPORTED_VERSION = "1.0"
VALID_VERDICTS = {"passed", "warning", "blocked", "listed", "verified", "unknown"}
VALID_KEY_STATUS = {"active", "retired", "revoked"}


@dataclass
class VerifyResult:
    accepted: bool = False
    reject_category: str = ""
    reason: str = ""
    ed25519_valid: bool = False
    mldsa65_present: bool = False
    mldsa65_skipped: bool = False
    sigs_expected: int = 0
    sigs_valid: int = 0

    def __str__(self) -> str:
        if self.accepted:
            return "ACCEPT"
        return f"REJECT[{self.reject_category}: {self.reason}]"


def canonical_proof_payload(tp: dict[str, Any]) -> bytes:
    """Mirror generator/main.go canonicalProofPayload VERBATIM."""
    return (
        f"{tp['did']}|"
        f"{int(tp['trustLevel'])}|"
        f"{float(tp['trustScore']):.6f}|"
        f"{tp['verdict']}|"
        f"{_normalize_rfc3339(tp['issuedAt'])}|"
        f"{_normalize_rfc3339(tp['expiresAt'])}|"
        f"{tp['issuerDid']}"
    ).encode("utf-8")


def sth_signed_bytes(root_hash: str) -> bytes:
    """Literal reading of ATP §5.6: strip "SHA256:" prefix, hex-decode 32 raw bytes."""
    stripped = root_hash[len("SHA256:"):] if root_hash.startswith("SHA256:") else root_hash
    raw = bytes.fromhex(stripped)
    if len(raw) != 32:
        raise ValueError(f"rootHash must decode to 32 bytes, got {len(raw)}")
    return raw


def _normalize_rfc3339(s: str) -> str:
    s2 = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s2).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def index_public_keys(refs: list[dict[str, Any]]):
    eds: list[Ed25519PublicKey] = []
    mldsa_present = False
    for r in refs:
        if r["algorithm"] == "Ed25519":
            raw = bytes.fromhex(r["publicKeyHex"])
            if len(raw) != 32:
                continue
            eds.append(Ed25519PublicKey.from_public_bytes(raw))
        elif r["algorithm"] == "ML-DSA-65":
            mldsa_present = True
    return eds, mldsa_present


# ---------------------------------------------------------------------------
# per-type verifiers
# ---------------------------------------------------------------------------

def verify_discovery(fixture: dict[str, Any]) -> VerifyResult:
    d = fixture.get("discoveryResponse")
    if not d:
        return VerifyResult(reject_category="PARSE_ERROR", reason="discoveryResponse missing")

    if not d.get("authorityDid"):
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason="authorityDid missing")
    if not d.get("version"):
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason="version missing")
    if d["version"] != SUPPORTED_VERSION:
        return VerifyResult(
            reject_category="UNSUPPORTED_VERSION",
            reason=f"unsupported atp version {d['version']!r} (this verifier supports {SUPPORTED_VERSION})",
        )
    cl = d.get("conformanceLevel", 0)
    if not (1 <= cl <= 3):
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason=f"conformanceLevel {cl} out of range [1,3]")
    if not d.get("endpoints"):
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason="endpoints missing")
    if not d.get("publicKeys"):
        return VerifyResult(reject_category="DISCOVERY_INVALID", reason="publicKeys missing")

    vs = fixture["verifierState"]
    if d["authorityDid"] not in vs.get("trustedIssuers", []):
        return VerifyResult(
            reject_category="UNTRUSTED_ISSUER",
            reason=f"authority DID {d['authorityDid']} is not in the verifier's trusted set",
        )

    for i, pk in enumerate(d["publicKeys"]):
        algo = pk.get("algorithm")
        if algo == "Ed25519":
            try:
                raw = bytes.fromhex(pk["publicKeyHex"])
            except ValueError:
                return VerifyResult(
                    reject_category="DISCOVERY_INVALID",
                    reason=f"publicKeys[{i}] Ed25519 publicKeyHex not hex",
                )
            if len(raw) != 32:
                return VerifyResult(
                    reject_category="DISCOVERY_INVALID",
                    reason=f"publicKeys[{i}] Ed25519 publicKeyHex invalid (need 32 bytes)",
                )
        elif algo == "ML-DSA-65":
            try:
                bytes.fromhex(pk["publicKeyHex"])
            except ValueError:
                return VerifyResult(
                    reject_category="DISCOVERY_INVALID",
                    reason=f"publicKeys[{i}] ML-DSA-65 publicKeyHex not hex",
                )
            # Structural-only: ML-DSA-65 parse-validation is out of scope here;
            # the Go verifier performs the full UnmarshalBinary check.
        else:
            return VerifyResult(
                reject_category="DISCOVERY_INVALID",
                reason=f"publicKeys[{i}] unsupported algorithm {algo!r}",
            )
        if pk.get("status") not in VALID_KEY_STATUS:
            return VerifyResult(
                reject_category="DISCOVERY_INVALID",
                reason=f"publicKeys[{i}] status {pk.get('status')!r} not in {sorted(VALID_KEY_STATUS)}",
            )

    return VerifyResult(accepted=True)


def verify_trust_proof(fixture: dict[str, Any]) -> VerifyResult:
    tp = fixture.get("trustProof")
    if not tp:
        return VerifyResult(reject_category="PARSE_ERROR", reason="trustProof missing")
    vs = fixture["verifierState"]
    now = datetime.fromisoformat(vs["clockRfc3339"].replace("Z", "+00:00")).astimezone(timezone.utc)

    # Step 1: expiry.
    try:
        expires = datetime.fromisoformat(tp["expiresAt"].replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=f"bad expiresAt: {exc}")
    if now > expires:
        return VerifyResult(
            reject_category="EXPIRED",
            reason=f"expired at {expires.strftime('%Y-%m-%dT%H:%M:%SZ')}, verifier clock is {now.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        )

    # Step 2: issuer trust.
    if tp["issuerDid"] not in vs.get("trustedIssuers", []):
        return VerifyResult(
            reject_category="UNTRUSTED_ISSUER",
            reason=f"issuer DID {tp['issuerDid']} is not in the verifier's trusted set",
        )

    # Step 5 semantic.
    tl = int(tp["trustLevel"])
    if not (0 <= tl <= 4):
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason=f"trustLevel {tl} out of range [0,4]")
    ts = float(tp["trustScore"])
    if not (0.0 <= ts <= 1.0):
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason=f"trustScore {ts:.6f} out of range [0.0,1.0]")
    if tp["verdict"] not in VALID_VERDICTS:
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason=f"verdict {tp['verdict']} not in {sorted(VALID_VERDICTS)}")
    try:
        issued = datetime.fromisoformat(tp["issuedAt"].replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        return VerifyResult(reject_category="PARSE_ERROR", reason=f"bad issuedAt: {exc}")
    if issued >= expires:
        return VerifyResult(reject_category="SEMANTIC_INVALID", reason="issuedAt must be before expiresAt")

    # Steps 3-4: signature.
    payload = canonical_proof_payload(tp)
    eds, _ = index_public_keys(vs["publicKeys"])
    result = VerifyResult(sigs_expected=len(tp.get("signatures", [])))

    for sig in tp.get("signatures", []):
        try:
            sig_bytes = base64.b64decode(sig["value"])
        except Exception as exc:
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"signature {sig.get('keyId')} has invalid base64: {exc}",
            )
        if sig["algorithm"] == "Ed25519":
            verified = False
            for pk in eds:
                try:
                    pk.verify(sig_bytes, payload)
                    verified = True
                    break
                except InvalidSignature:
                    continue
            if not verified:
                return VerifyResult(
                    reject_category="SIGNATURE_INVALID",
                    reason=f"Ed25519 signature {sig.get('keyId')} did not verify against any configured public key",
                )
            result.ed25519_valid = True
            result.sigs_valid += 1
        elif sig["algorithm"] == "ML-DSA-65":
            # Out of scope for this Python reference verifier. Recorded as present.
            result.mldsa65_present = True
            result.mldsa65_skipped = True
        else:
            return VerifyResult(
                reject_category="SIGNATURE_INVALID",
                reason=f"unsupported signature algorithm {sig['algorithm']}",
            )

    if not result.ed25519_valid:
        return VerifyResult(reject_category="SIGNATURE_INVALID", reason="no valid Ed25519 signature (ATP §4.3 baseline)")

    result.accepted = True
    return result


def verify_sth(fixture: dict[str, Any]) -> VerifyResult:
    sth = fixture.get("signedTreeHead")
    if not sth:
        return VerifyResult(reject_category="PARSE_ERROR", reason="signedTreeHead missing")
    vs = fixture["verifierState"]

    if int(sth.get("treeSize", 0)) <= 0:
        return VerifyResult(reject_category="STH_INVALID", reason=f"treeSize {sth.get('treeSize')} must be > 0")
    try:
        datetime.fromisoformat(sth["timestamp"].replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        return VerifyResult(reject_category="STH_INVALID", reason=f"bad timestamp: {exc}")
    try:
        root_bytes = sth_signed_bytes(sth["rootHash"])
    except (KeyError, ValueError) as exc:
        return VerifyResult(reject_category="STH_INVALID", reason=str(exc))
    try:
        sig_bytes = base64.b64decode(sth["signature"])
    except Exception as exc:
        return VerifyResult(reject_category="SIGNATURE_INVALID", reason=f"STH signature has invalid base64: {exc}")

    eds, _ = index_public_keys(vs["publicKeys"])
    for pk in eds:
        try:
            pk.verify(sig_bytes, root_bytes)
            return VerifyResult(accepted=True, ed25519_valid=True, sigs_expected=1, sigs_valid=1)
        except InvalidSignature:
            continue
    return VerifyResult(reject_category="SIGNATURE_INVALID", reason="STH Ed25519 signature did not verify against any configured public key")


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def verify_fixture(fixture: dict[str, Any]) -> VerifyResult:
    ft = fixture.get("fixtureType")
    if ft == "discovery":
        return verify_discovery(fixture)
    if ft == "trustProof":
        return verify_trust_proof(fixture)
    if ft == "sth":
        return verify_sth(fixture)
    return VerifyResult(reject_category="PARSE_ERROR", reason=f"unknown fixtureType {ft!r}")


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def expand_paths(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        if not p.exists():
            raise FileNotFoundError(a)
        if p.is_dir():
            fixtures_dir = p / "fixtures"
            target = fixtures_dir if fixtures_dir.is_dir() else p
            out.extend(sorted(target.glob("*.json")))
        else:
            out.append(p)
    return sorted(set(out))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: verify.py <fixture.json|dir>...\n")
        return 2
    try:
        paths = expand_paths(argv[1:])
    except FileNotFoundError as exc:
        sys.stderr.write(f"error: path not found: {exc}\n")
        return 2
    if not paths:
        sys.stderr.write("no fixture *.json files found\n")
        return 2

    total_pass = total_fail = 0
    for p in paths:
        try:
            fixture = load_fixture(p)
        except Exception as exc:
            print(f"FAIL  {p}  (load error: {exc})")
            total_fail += 1
            continue

        got = verify_fixture(fixture)
        expected = fixture.get("expected", {})
        want_accept = expected.get("verifyResult", "").upper() == "ACCEPT"

        ok = (want_accept and got.accepted) or (not want_accept and not got.accepted)
        if ok and not want_accept and expected.get("rejectCategory"):
            ok = got.reject_category == expected["rejectCategory"]
        if ok and not want_accept and expected.get("reasonContains"):
            ok = expected["reasonContains"].lower() in got.reason.lower()

        status = "PASS" if ok else "FAIL"
        if ok:
            total_pass += 1
        else:
            total_fail += 1

        try:
            rel = p.relative_to(Path.cwd())
        except ValueError:
            rel = p
        print(f"{status}  {rel}  [{fixture.get('fixtureType', '?')}]")
        print(f"       expected: {expected.get('verifyResult', '')}", end="")
        if expected.get("rejectCategory"):
            print(f" [{expected['rejectCategory']}]")
        else:
            print()
        print(f"       observed: {got}")
        if got.sigs_expected:
            mldsa_note = ""
            if got.mldsa65_present:
                mldsa_note = " (ML-DSA-65 present, verification out of scope for this Python reference; use Go verifier for full hybrid)"
            print(
                f"       signatures: {got.sigs_valid}/{got.sigs_expected} valid (ed25519={got.ed25519_valid}){mldsa_note}"
            )

    print()
    print(f"summary: {total_pass} pass, {total_fail} fail ({total_pass + total_fail} fixtures)")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
