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
git clone https://github.com/opena2a-org/atp-conformance
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

## Cosignature registry

| Cosigner | Commit SHA | Go verifier | Python verifier | Sigstore artifact | Date |
|---|---|---|---|---|---|
| opena2a-org (self-cosigned, v0.1.0 baseline) | _set on first release_ | `4 pass, 0 fail` | `4 pass, 0 fail` | _set on first release_ | _set on first release_ |

Self-cosignature exists to anchor the baseline; second-party signatures are
what close criterion (c). Recruiting at least one second-party cosigner per
fixture set is the immediate post-publish objective.
