# atp-conformance

Conformance fixtures and reference verifiers for the
[Agent Trust Protocol (ATP) v1.0.0-rc1](https://github.com/opena2a-org/agent-trust-protocol).

Each fixture is a byte-stable JSON file that bundles a pinned ATP protocol
response (discovery, trust proof, or Signed Tree Head) with verifier
configuration and an expected outcome (ACCEPT or REJECT). Two
SDK-independent reference verifiers (Go and Python) walk the fixture set and
report PASS or FAIL per vector. Fixture bytes are pinned in
[`MANIFEST.sha256`](./MANIFEST.sha256).

This suite mirrors the pattern set by
[`atx-conformance`](https://github.com/opena2a-standards/atx-conformance) (which
covers the ATX credential schema) and by
[`a2a-idf-conformance/fixtures/composition/aim-did-rfc9421/`](https://github.com/opena2a-org/a2a-idf-conformance/tree/main/fixtures/composition/aim-did-rfc9421)
(APS interop conformance for A2A-IDF wire signatures). It closes criterion (c)
on the OpenA2A maturity bar tracked in
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885):
"peer-cosigned conformance fixtures for AIP, ATP, or ATX comparable to the
`aim-did-rfc9421/*` set."

License: Apache 2.0. All keypairs, seeds, and identifiers in this repository
are TEST-ONLY.

## Scope

What this suite verifies:

| Item | Covered by |
|---|---|
| ATP §7.1 well-known discovery response shape | `fixtures/discovery-valid.json` |
| ATP §4.2 trust proof shape | `fixtures/trust-proof-baseline.json`, `fixtures/trust-proof-hybrid.json` |
| ATP §4.3 canonical pipe-delimited 7-field signing form | both trust-proof fixtures |
| ATP §4.3 Ed25519 signing (baseline) | both trust-proof fixtures |
| ATP §4.3 hybrid Ed25519 + ML-DSA-65 signing (FIPS 204) | `fixtures/trust-proof-hybrid.json` (Go verifier validates both algorithms; Python validates Ed25519 only) |
| ATP §4.4 verification steps 1-5 (expiry, issuer, key, signature, semantic) | both trust-proof fixtures, all verifiers |
| ATP §4.4 step 1 must-reject: expired proof (valid signature, past expiresAt) | `fixtures/trust-proof-expired.json` |
| ATP §4.4 step 2 must-reject: untrusted issuer (valid signature, issuer not in trusted set) | `fixtures/trust-proof-untrusted-issuer.json` |
| ATP §4.4 step 4 must-reject: tampered Ed25519 signature (first byte XOR 0xFF) | `fixtures/trust-proof-tampered-signature.json` |
| ATP §5.6 Signed Tree Head | `fixtures/transparency-log-sth.json` |

Each negative fixture is valid in every respect except the one defect it
pins, so a verifier that skips that verification step (and only that step)
wrongly ACCEPTs it. Expected outcomes pin the reject category
(`EXPIRED`, `UNTRUSTED_ISSUER`, `SIGNATURE_INVALID`), so rejecting for the
wrong reason also fails.

What this suite does NOT verify in v0.2 (deferred to v0.3+):

- Transparency log inclusion proofs (ATP §5.4). Byte-stability requires a
  pinned tree-state fixture, which is bigger than the marginal coverage.
- Consistency proofs (ATP §5.5). Same reason.
- Revocation CRL entries (ATP §8.1). Revocation events live on the
  transparency log; CRL-style fixtures are redundant once revocation events
  are byte-stable.
- Federation cosignature (ATP §6, Level 3). Production has no second
  authority to source a real cosigned proof from. Will be added once a real
  federation peer exists.

The full requirement-to-fixture mapping is machine-readable in
[`conformance.json`](./conformance.json), regenerated from the fixtures by
[`scripts/conformance_profile.py`](./scripts/conformance_profile.py) and
CI-checked against drift.

## Continuous verification

[`.github/workflows/conformance.yml`](./.github/workflows/conformance.yml)
enforces every claim in this README on each push and pull request:

1. Both reference verifiers run against `fixtures/` and must report
   `7 pass, 0 fail`.
2. The fixture generator re-runs and the committed fixture bytes plus
   `MANIFEST.sha256` must reproduce exactly (byte-pin).
3. The cross-implementation parity gate
   ([`scripts/parity/parity.py`](./scripts/parity/parity.py)) asserts the Go
   and Python verifiers agree per fixture on gate status, verdict, and
   reject category, and publishes `parity-report.json` as a CI artifact.
4. `conformance.json` must match the fixture set.

## Relationship to the existing ATP bash conformance scripts

The ATP spec repo carries a live-endpoint bash conformance suite at
[`agent-trust-protocol/conformance/level{1,2}.sh`](https://github.com/opena2a-org/agent-trust-protocol/tree/main/conformance).
Those scripts hit a running ATP authority (default `https://api.oa2a.org`)
and exercise the discovery, trust-proof, and transparency endpoints
end-to-end. They are complementary to this repository:

| Suite | Style | What it proves |
|---|---|---|
| `agent-trust-protocol/conformance/level*.sh` | Live curl against a running authority | Authority is reachable, returns conforming shapes, signatures verify in real time |
| `atp-conformance` (this repo) | Offline byte-stable fixtures with SDK-independent verifiers | A second-party verifier with only the spec and the public test keypairs can reproduce ACCEPT / REJECT byte-for-byte |

Both are needed for full coverage; neither replaces the other.

## Honest scope notes

This is the section that future reviewers, second-implementation authors,
and A2A coordination-map readers should read before forming judgments.

### Canonicalization: 7 signed fields for trust proofs

ATP §4.3 signs a pipe-delimited canonical string, not the JSON body. The
signature covers exactly 7 fields, defined verbatim in
[`scripts/generate-fixtures/main.go`](./scripts/generate-fixtures/main.go)
`canonicalProofPayload()` and mirrored in both reference verifiers:

```
did | trustLevel | trustScore (%.6f) | verdict |
issuedAt (RFC 3339 UTC) | expiresAt (RFC 3339 UTC) | issuerDid
```

Fields in the JSON body that are NOT covered by the signature include
`signatures` (the signature container itself), `transparencyLogIndex`, and
any future extension fields. A consequence is that an attacker who can
write to a stored trust proof could modify `transparencyLogIndex` without
breaking signature verification. This is a known shape of ATP v1.0.0-rc1
and is documented here so reviewers do not have to discover it from the
code. JCS-canonical JSON signing (RFC 8785) is a candidate hardening for
v1.1.

### Signed Tree Head: literal reading of §5.6

ATP §5.6 says: `"signature": "base64-ed25519-signature-over-rootHash"`. This
suite implements the literal reading: strip the `SHA256:` prefix from the
`rootHash` string, hex-decode the remaining 64 characters to 32 raw bytes,
Ed25519-sign those 32 bytes. The signature is over the raw root-hash bytes
only — it does NOT also cover `treeSize` and `timestamp`.

Practical consequence: an attacker who can rewrite `treeSize` or `timestamp`
on a stored STH without modifying `rootHash` would not break the signature.
Monitors typically compare `rootHash` over time as the primary correctness
check, so this is mitigated in practice, but a v1.1 hardening could extend
the signed payload to include `treeSize || timestamp || rootHash`. Recorded
here as an open spec question.

### Hybrid signing: production status

ATP §4.3 paragraph 2 SHOULDs hybrid Ed25519 + ML-DSA-65 signing. The
production reference authority at `api.oa2a.org` emits hybrid trust proofs
today (per
[opena2a-registry PR #214 + #215](https://github.com/opena2a-org/opena2a-registry)
in the related ATX implementation). Shipping a hybrid fixture in v0.1
makes the SHOULD-path concrete and gives second implementers a wire-format
target.

The Go reference verifier in this repository
([`verifiers/go`](./verifiers/go)) DOES verify ML-DSA-65 signatures per
FIPS 204 via `github.com/cloudflare/circl`. The Python reference verifier
([`verifiers/python`](./verifiers/python)) treats ML-DSA-65 as
present-but-out-of-scope (the post-quantum Python library landscape is
fragmented; no stdlib support). The hybrid fixture is annotated to ACCEPT
on the Ed25519 path alone in Python, with a banner. For full hybrid
verification end to end, run the Go verifier.

### Keypair reuse with atx-conformance

The `issuer-primary` Ed25519 keypair in
[`vectors/issuer-primary.json`](./vectors/issuer-primary.json) is the SAME
bytes as the `issuer-primary` vector in
[`atx-conformance/vectors/issuer-primary.json`](https://github.com/opena2a-standards/atx-conformance/blob/main/vectors/issuer-primary.json):
RFC 8032 §7.1 Test 1 seed, `did:opena2a:authority:opena2a.org` issuer DID.
The ML-DSA-65 seed in [`vectors/mldsa65-seed.json`](./vectors/mldsa65-seed.json)
is also the same 32-byte seed as atx-conformance's. This is deliberate: a
peer cosigner who has already audited the atx-conformance vectors can rely
on the same audit for this suite. Both vector files are TEST-ONLY; the
seeds are publicly known and MUST NOT be used in production.

### DID method

The `did:opena2a:<type>:<id>` identifiers in this suite (issuer and agent
DIDs) are governed by the `did:opena2a` DID method specification at
[`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a)
(Apache-2.0), filed for registration with the W3C DID Extensions registry
on [`w3c/did-extensions#717`](https://github.com/w3c/did-extensions/pull/717).
The method is registry-mediated rather than fully decentralized; trust in
a resolved DID is trust in the OpenA2A Registry that issued it. This
property is acknowledged in the method spec and does not affect the
fixture-level verifier behavior in this repository, which configures
trusted authorities directly from each fixture rather than resolving them
over the network.

## Fixtures

All fixtures use:

- Trusted authority DID: `did:opena2a:authority:opena2a.org`
- Test agent DID: `did:opena2a:mcp_server:agent_conformance_test_001`
- Pinned verifier clock: `2026-05-24T00:00:00Z`
- Ed25519 keypair source: [RFC 8032 §7.1 Test 1](https://datatracker.ietf.org/doc/html/rfc8032#section-7.1)
- ML-DSA-65 keypair source: fixed test seed (incrementing bytes `00..1f`), public key pinned in [`vectors/mldsa65-seed.json`](./vectors/mldsa65-seed.json)

| Fixture | Type | Expected | Exercises |
|---|---|---|---|
| `fixtures/discovery-valid.json` | discovery | ACCEPT | Well-formed `/.well-known/atp` response: required fields, `conformanceLevel` in `[1,3]`, structurally valid `publicKeys` (both Ed25519 and ML-DSA-65 entries). |
| `fixtures/trust-proof-baseline.json` | trustProof | ACCEPT | Trust proof with one Ed25519 signature over the 7-field canonical payload. MUST-implement baseline. |
| `fixtures/trust-proof-hybrid.json` | trustProof | ACCEPT | Trust proof with both Ed25519 AND ML-DSA-65 signatures over the same canonical payload. Production wire format. |
| `fixtures/transparency-log-sth.json` | sth | ACCEPT | Signed Tree Head with Ed25519 signature over the raw 32-byte decoded `rootHash`. Compatible with RFC 6962 §3.5 CT monitor expectations. |

## Running the verifiers

Both verifiers walk every `*.json` file in the directory you point them at
(or you may pass individual fixture files). Exit code is 0 if every
fixture's observed result matches the expected result and the rejection
category matches (when declared).

### Go (full hybrid Ed25519 plus ML-DSA-65)

```bash
cd verifiers/go
go run . ../../fixtures
```

Depends on:

- Go 1.22 or later
- `github.com/cloudflare/circl v1.6.2` (resolved by `go mod tidy`)

### Python (Ed25519, ML-DSA-65 out of scope)

```bash
cd verifiers/python
pip install -r requirements.txt
python verify.py ../../fixtures
```

Depends on:

- Python 3.11 or later
- `cryptography >= 42.0.0`

For full hybrid verification end to end, use the Go verifier.

### Expected output

Both verifiers report `summary: 7 pass, 0 fail (7 fixtures)` against the
shipped fixture set (4 ACCEPT, 3 REJECT). Any divergence on bytes (the
fixture file was modified) or on verifier semantics (the verifier has
drifted from the spec) shows up as one or more FAIL lines.

To additionally assert the two verifiers agree with each other per fixture
(gate status, verdict, reject category):

```bash
python3 scripts/parity/parity.py
```

## Reproducing the fixtures

The fixtures in this repository are deterministic. To regenerate them from
the keypair vectors in [`vectors/`](./vectors):

```bash
cd scripts/generate-fixtures
go run .
```

The generator:

1. Loads each Ed25519 keypair vector. Verifies that the seed-derived public
   key matches the vector's `publicKeyHex`. Panics on drift.
2. Loads the ML-DSA-65 seed. Re-derives the public key from the seed (using
   CIRCL's `mldsa65.NewKeyFromSeed`). Compares against the pinned
   `publicKeyHex`. Panics on drift.
3. Builds each fixture's payload deterministically (no random nonces).
4. Computes the pipe-delimited canonical payload for trust proofs (the same
   7-field function the spec's §4.3 defines, duplicated verbatim in the
   generator and in each reference verifier).
5. Computes the raw 32-byte `rootHash` for the STH (literal reading of §5.6).
6. Ed25519-signs (and ML-DSA-65-signs where applicable) the canonical
   payload or STH bytes.
7. Marshals each fixture to byte-stable JSON (`encoding/json` with 2-space
   indent, fields in struct-declaration order).
8. Writes the fixture file. Recomputes its SHA-256. Updates
   `MANIFEST.sha256` in path-sorted order.

Re-running the generator MUST produce byte-identical fixtures. If the bytes
change, either (a) the generator changed, (b) the canonicalization shifted,
or (c) the CIRCL ML-DSA-65 implementation changed. Any of those is a
breaking change for downstream verifiers.

## Version pinning

| Component | Version | Source |
|---|---|---|
| ATP spec | v1.0.0-rc1 | [`opena2a-org/agent-trust-protocol/ATP-SPEC.md`](https://github.com/opena2a-org/agent-trust-protocol/blob/main/ATP-SPEC.md) |
| `did:opena2a` method | v0.1 (W3C registration filed, PR `w3c/did-extensions#717`) | [`opena2a-standards/did-method-opena2a`](https://github.com/opena2a-standards/did-method-opena2a/blob/main/did-method-opena2a.md) |
| Ed25519 test vector source | RFC 8032 §7.1 Test 1 | [datatracker.ietf.org/doc/html/rfc8032](https://datatracker.ietf.org/doc/html/rfc8032) |
| ML-DSA-65 | FIPS 204 final | [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final) |
| CIRCL (ML-DSA-65 implementation) | v1.6.2 | [github.com/cloudflare/circl](https://github.com/cloudflare/circl) |
| cryptography (Python Ed25519) | >= 42.0.0 | [pyca/cryptography](https://github.com/pyca/cryptography) |
| Conformance fixture format | v1 (this repo) | [`fixtures/trust-proof-baseline.json#$schema`](./fixtures/trust-proof-baseline.json) |

## Implementations that validate against this suite

| Implementation | Verifier | Status |
|---|---|---|
| `opena2a-standards/atp-conformance/verifiers/go` (this repo) | Go, full Ed25519 plus ML-DSA-65 | 4 / 4 PASS |
| `opena2a-standards/atp-conformance/verifiers/python` (this repo) | Python, Ed25519, ML-DSA-65 out of scope | 4 / 4 PASS |

Independent second-party implementations and cosigners are tracked in
[`COSIGNERS.md`](./COSIGNERS.md) and on the sibling issue
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## Cosigning

Second-party cosigners sign [`MANIFEST.sha256`](./MANIFEST.sha256) using
[Sigstore keyless cosign](https://docs.sigstore.dev/cosign/overview/) and
add an entry to [`COSIGNERS.md`](./COSIGNERS.md) recording:

- The commit SHA at which they verified
- The verifier exit summary they observed (e.g., `go=7 pass, 0 fail; python=7 pass, 0 fail`)
- Their identity / organization
- The Sigstore signature artifact path

Cosigners may also produce their own implementation of a verifier against
these fixtures and add it to the implementations table above via PR.

## Repository layout

```
LICENSE                          Apache 2.0
README.md                        this file
MANIFEST.sha256                  per-fixture SHA-256 (path-sorted)
COSIGNERS.md                     second-party cosigner registry
fixtures/                        the 4 conformance fixtures (byte-stable JSON)
vectors/                         test keypair vectors (TEST-ONLY)
verifiers/go/                    Go reference verifier (full hybrid)
verifiers/python/                Python reference verifier (Ed25519)
scripts/generate-fixtures/       deterministic fixture generator (Go)
```

## Versioning and stability

- The conformance fixture file format (`$schema: fixture-v1`) is stable
  across patch revisions of this repository. Adding new fixture fields is
  a minor version bump; renaming or removing fields is a major version
  bump.
- The set of fixtures may grow. New fixtures are additive and do not
  invalidate prior `MANIFEST.sha256` entries; each new fixture appears as
  a new line in the manifest.
- Existing fixtures are immutable once published. If a fixture needs to
  change semantically, it ships under a new name. This is what makes
  `MANIFEST.sha256` a useful regression check.

## Contributing

Issues and PRs welcome on this repository. Substantive coordination on the
ATP wire format itself happens in
[`opena2a-org/agent-trust-protocol`](https://github.com/opena2a-org/agent-trust-protocol)
and in the A2A coordination map on
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## License

Apache 2.0, see [`LICENSE`](./LICENSE).
