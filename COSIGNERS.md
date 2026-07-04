# Cosigners

Second-party cosigners attest that they have independently:

1. Cloned this repository at a specific commit SHA
2. Run BOTH reference verifiers against the published fixture set
3. Observed `summary: N pass, 0 fail (N fixtures)` from each verifier
4. Produced a Sigstore keyless cosign signature over [`MANIFEST.sha256`](./MANIFEST.sha256)

The signature attests to the fixture bytes; the entry below attests that
the verifiers were actually run. Both together close the gap noted in the
A2A coordination map's criterion (c) on
[`a2aproject/A2A#1885`](https://github.com/a2aproject/A2A/issues/1885).

## How to cosign

```bash
# Clone and verify
git clone https://github.com/opena2a-standards/atp-conformance
cd atp-conformance

# Run both verifiers and record exit summaries
(cd verifiers/go && go run . ../../fixtures)
(cd verifiers/python && pip install -r requirements.txt && python verify.py ../../fixtures)

# Sigstore keyless cosign over MANIFEST.sha256
cosign sign-blob MANIFEST.sha256 \
    --output-signature MANIFEST.sha256.sig \
    --output-certificate MANIFEST.sha256.crt

# Open a PR that:
#   - Adds your cosignature + certificate under .sigstore/<your-org>/
#   - Appends an entry to the table below
```

## CI self-cosignature (baseline)

Every push to `main` keyless-signs the current `MANIFEST.sha256` in CI
(`sign-manifest` job in
[`conformance.yml`](./.github/workflows/conformance.yml)), after the full
conformance job (both verifiers, byte-pin, parity, profile) has passed. The
signature is recorded in the public Rekor transparency log — that entry is the
durable artifact; the workflow also uploads the bundle
(`MANIFEST.sha256.cosign.bundle`) as a run artifact for convenience.

To verify a bundle against the pinned CI identity:

```bash
cosign verify-blob \
    --bundle MANIFEST.sha256.cosign.bundle \
    --certificate-identity "https://github.com/opena2a-standards/atp-conformance/.github/workflows/conformance.yml@refs/heads/main" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    MANIFEST.sha256
```

Or look the digest up directly in Rekor (https://search.sigstore.dev) by the
SHA-256 of `MANIFEST.sha256`.

## Cosignature registry

| Cosigner | Commit SHA | Go verifier | Python verifier | Sigstore artifact | Date |
|---|---|---|---|---|---|
| opena2a-org (self-cosigned baseline, CI) | every `main` push (see CI self-cosignature) | `7 pass, 0 fail` | `7 pass, 0 fail` | Rekor entry per push (keyless CI signature) | 2026-07-04 onward |

Self-cosignature exists to anchor the baseline; second-party signatures are
what close criterion (c). Recruiting at least one second-party cosigner per
fixture set is the immediate post-publish objective.
