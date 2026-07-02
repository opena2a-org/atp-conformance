// generate-fixtures produces the ATP v1.0.0-rc1 conformance fixture set.
//
// Every fixture is byte-stable: same seeds, same canonicalization, same JSON
// encoding settings. Re-running the generator MUST produce identical bytes;
// MANIFEST.sha256 pins each fixture.
//
// Spec coverage of v0.1:
//   - discovery-valid           ATP §7.1 well-known discovery
//   - trust-proof-baseline      ATP §4.2 + §4.3 single-signer Ed25519
//   - trust-proof-hybrid        ATP §4.3 hybrid Ed25519 + ML-DSA-65
//   - transparency-log-sth      ATP §5.6 Signed Tree Head
//
// Canonical signing form for trust proofs (ATP §4.3):
//
//	canonical = "{did}|{trustLevel}|{trustScore:.6f}|{verdict}|{issuedAt}|{expiresAt}|{issuerDid}"
//	signature = Ed25519.Sign(privKey, canonical)        // and ML-DSA-65 hybrid
//
// STH signing (ATP §5.6, literal reading):
//
//	signature = Ed25519.Sign(privKey, rawRootHashBytes)  // 32 raw bytes; "SHA256:" prefix stripped
//
// Keypair reuse: issuer-primary and mldsa65-seed are the SAME bytes as
// atx-conformance vectors. Cross-link in the repo README.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	atpVersion        = "1.0"
	fixedClockRFC3339 = "2026-05-24T00:00:00Z"
)

var outDir string

// ---------------------------------------------------------------------------
// fixture wrapper (shared across all four fixture shapes)
// ---------------------------------------------------------------------------

type SpecRef struct {
	ID      string `json:"id"`
	Ref     string `json:"ref"`
	Section string `json:"section"`
}

type KeypairRef struct {
	Role         string `json:"role"`
	Path         string `json:"path"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	KeyID        string `json:"keyId"`
}

type VerifierState struct {
	ClockRFC3339   string       `json:"clockRfc3339"`
	TrustedIssuers []string     `json:"trustedIssuers"`
	PublicKeys     []KeypairRef `json:"publicKeys"`
}

type ExpectedOutcome struct {
	VerifyResult   string `json:"verifyResult"`
	RejectCategory string `json:"rejectCategory,omitempty"`
	ReasonContains string `json:"reasonContains,omitempty"`
}

// Fixture is the language-agnostic wrapper. Exactly one of the
// fixtureType-specific payload fields is populated per fixture.
type Fixture struct {
	Schema             string             `json:"$schema"`
	Name               string             `json:"name"`
	Description        string             `json:"description"`
	FixtureType        string             `json:"fixtureType"`
	Spec               []SpecRef          `json:"spec"`
	KeypairRefs        []KeypairRef       `json:"keypairRefs"`
	VerifierState      VerifierState      `json:"verifierState"`
	Expected           ExpectedOutcome    `json:"expected"`
	DiscoveryResponse  *DiscoveryResponse `json:"discoveryResponse,omitempty"`
	TrustProof         *TrustProof        `json:"trustProof,omitempty"`
	SignedTreeHead     *SignedTreeHead    `json:"signedTreeHead,omitempty"`
}

// ---------------------------------------------------------------------------
// payload shapes
// ---------------------------------------------------------------------------

// DiscoveryResponse mirrors ATP §7.1 well-known/atp shape. Field order is
// pinned for byte-stability.
type DiscoveryResponse struct {
	AuthorityDID     string                  `json:"authorityDid"`
	Version          string                  `json:"version"`
	ConformanceLevel int                     `json:"conformanceLevel"`
	Endpoints        DiscoveryEndpoints      `json:"endpoints"`
	PublicKeys       []DiscoveryPublicKey    `json:"publicKeys"`
	SupportedMethods []string                `json:"supportedMethods"`
	Capabilities     []string                `json:"capabilities"`
	FederationPeers  []string                `json:"federationPeers,omitempty"`
}

type DiscoveryEndpoints struct {
	DIDResolve         string `json:"didResolve"`
	TrustProof         string `json:"trustProof"`
	TrustVerify        string `json:"trustVerify"`
	TrustBatch         string `json:"trustBatch"`
	TransparencyLog    string `json:"transparencyLog"`
	TransparencyProof  string `json:"transparencyProof"`
	TransparencySTH    string `json:"transparencySth"`
	Revocations        string `json:"revocations"`
	Federation         string `json:"federation,omitempty"`
}

type DiscoveryPublicKey struct {
	KeyID        string `json:"keyId"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	Status       string `json:"status"`
	ValidFrom    string `json:"validFrom"`
}

// TrustProof mirrors ATP §4.2 proof shape.
type TrustProof struct {
	DID                  string             `json:"did"`
	TrustLevel           int                `json:"trustLevel"`
	TrustScore           float64            `json:"trustScore"`
	Verdict              string             `json:"verdict"`
	IssuedAt             string             `json:"issuedAt"`
	ExpiresAt            string             `json:"expiresAt"`
	IssuerDID            string             `json:"issuerDid"`
	Signatures           []ProofSignature   `json:"signatures"`
	TransparencyLogIndex int64              `json:"transparencyLogIndex,omitempty"`
}

type ProofSignature struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// SignedTreeHead mirrors ATP §5.6. The signature is over the raw 32-byte
// root hash (after stripping the "SHA256:" prefix and hex-decoding).
type SignedTreeHead struct {
	TreeSize  int64  `json:"treeSize"`
	Timestamp string `json:"timestamp"`
	RootHash  string `json:"rootHash"`
	SignedBy  string `json:"signedBy"`
	Signature string `json:"signature"`
}

// ---------------------------------------------------------------------------
// canonicalization
// ---------------------------------------------------------------------------

// canonicalProofPayload is the ATP §4.3 canonical signing form. SEVEN fields.
// Mirror VERBATIM in both reference verifiers.
func canonicalProofPayload(p *TrustProof) []byte {
	return []byte(fmt.Sprintf("%s|%d|%.6f|%s|%s|%s|%s",
		p.DID,
		p.TrustLevel,
		p.TrustScore,
		p.Verdict,
		normalizeRFC3339(p.IssuedAt),
		normalizeRFC3339(p.ExpiresAt),
		p.IssuerDID,
	))
}

// sthSignedBytes is the literal reading of ATP §5.6 "Ed25519 signature over
// rootHash": strip the "SHA256:" prefix and hex-decode to 32 raw bytes.
func sthSignedBytes(rootHash string) []byte {
	stripped := strings.TrimPrefix(rootHash, "SHA256:")
	raw, err := hex.DecodeString(stripped)
	must(err)
	if len(raw) != sha256.Size {
		panic(fmt.Sprintf("STH rootHash must decode to %d bytes, got %d", sha256.Size, len(raw)))
	}
	return raw
}

func normalizeRFC3339(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	must(err)
	return t.UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

func signEd25519(seedHex string, payload []byte) ProofSignature {
	seed, err := hex.DecodeString(seedHex)
	must(err)
	if len(seed) != ed25519.SeedSize {
		panic(fmt.Sprintf("Ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed)))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, payload)
	return ProofSignature{
		Algorithm: "Ed25519",
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
}

func signMLDSA65(seedHex string, payload []byte) (sig ProofSignature, pubKeyHex string) {
	seed, err := hex.DecodeString(seedHex)
	must(err)
	if len(seed) != 32 {
		panic(fmt.Sprintf("ML-DSA-65 seed must be 32 bytes, got %d", len(seed)))
	}
	var seedArr [32]byte
	copy(seedArr[:], seed)
	pub, priv := mldsa65.NewKeyFromSeed(&seedArr)
	sigBytes := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(priv, payload, nil, false, sigBytes); err != nil {
		panic(fmt.Sprintf("ML-DSA-65 sign: %v", err))
	}
	pubBytes, err := pub.MarshalBinary()
	must(err)
	return ProofSignature{
		Algorithm: "ML-DSA-65",
		Value:     base64.StdEncoding.EncodeToString(sigBytes),
	}, hex.EncodeToString(pubBytes)
}

// ---------------------------------------------------------------------------
// fixture builders
// ---------------------------------------------------------------------------

// Pinned values used across fixtures.
var (
	testAgentDID    = "did:opena2a:mcp_server:agent_conformance_test_001"
	testAuthorityDID = "did:opena2a:authority:opena2a.org"
	testIssuedAt    = "2026-05-23T00:00:00Z"
	testExpiresAt   = "2099-12-31T23:59:59Z"
	testValidFrom   = "2026-01-01T00:00:00Z"
	// Deterministic root-hash: SHA-256("opena2a-atp-conformance-sth-v0.1") padded
	// nowhere; computed at init().
	testRootHashHex string
	testRootHash    string
)

func init() {
	h := sha256.Sum256([]byte("opena2a-atp-conformance-sth-v0.1"))
	testRootHashHex = hex.EncodeToString(h[:])
	testRootHash = "SHA256:" + testRootHashHex
}

func main() {
	outDir = mustResolveOutDir()

	primary := mustLoadKeyVector("vectors/issuer-primary.json")
	mldsa := mustLoadKeyVector("vectors/mldsa65-seed.json")

	// Sanity-check ML-DSA-65 pubkey: re-derive and compare to pinned value.
	_, mldsaPubHex := signMLDSA65(mldsa.SeedHex, []byte("__pubkey_resolution__"))
	if mldsa.PublicKeyHex != mldsaPubHex {
		panic(fmt.Sprintf("ML-DSA-65 pubkey drift: vector says %s..., generator computed %s...",
			mldsa.PublicKeyHex[:16], mldsaPubHex[:16]))
	}

	defaultVerifierState := VerifierState{
		ClockRFC3339:   fixedClockRFC3339,
		TrustedIssuers: []string{primary.IssuerDID},
		PublicKeys: []KeypairRef{
			keypairRefFor(primary, "vectors/issuer-primary.json"),
		},
	}

	hybridVerifierState := defaultVerifierState
	hybridVerifierState.PublicKeys = append(append([]KeypairRef{},
		defaultVerifierState.PublicKeys...),
		KeypairRef{
			Role:         mldsa.Role,
			Path:         "vectors/mldsa65-seed.json",
			Algorithm:    mldsa.Algorithm,
			PublicKeyHex: mldsa.PublicKeyHex,
			KeyID:        mldsa.KeyID,
		})

	type fixtureSpec struct {
		writePath string
		build     func() Fixture
	}

	fixtures := []fixtureSpec{
		{"fixtures/discovery-valid.json", func() Fixture {
			disc := newDiscoveryResponse(primary, mldsa)
			return Fixture{
				Schema:        "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:          "atp-v1/discovery-valid",
				Description:   "A well-formed ATP discovery response from /.well-known/atp per ATP §7.1. All required fields present, conformanceLevel within range, publicKeys structurally valid. Verifier MUST ACCEPT.",
				FixtureType:   "discovery",
				Spec:          specRefs("§7.1 Well-Known Endpoint"),
				KeypairRefs:   []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState: hybridVerifierState,
				Expected:      ExpectedOutcome{VerifyResult: "ACCEPT"},
				DiscoveryResponse: &disc,
			}
		}},
		{"fixtures/trust-proof-baseline.json", func() Fixture {
			tp := newBaselineTrustProof()
			sig := signEd25519(primary.SeedHex, canonicalProofPayload(&tp))
			sig.KeyID = primary.KeyID
			tp.Signatures = []ProofSignature{sig}
			return Fixture{
				Schema:        "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:          "atp-v1/trust-proof-baseline",
				Description:   "A trust proof issued by a single trusted authority with one Ed25519 signature over the canonical pipe-delimited 7-field payload per ATP §4.2 + §4.3. This is the MUST-implement baseline for any ATP-conformant verifier. Verifier MUST ACCEPT.",
				FixtureType:   "trustProof",
				Spec:          specRefs("§4.2 Trust Proof Format", "§4.3 Signing"),
				KeypairRefs:   []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState: defaultVerifierState,
				Expected:      ExpectedOutcome{VerifyResult: "ACCEPT"},
				TrustProof:    &tp,
			}
		}},
		{"fixtures/trust-proof-hybrid.json", func() Fixture {
			tp := newBaselineTrustProof()
			ed := signEd25519(primary.SeedHex, canonicalProofPayload(&tp))
			ed.KeyID = primary.KeyID
			pq, _ := signMLDSA65(mldsa.SeedHex, canonicalProofPayload(&tp))
			pq.KeyID = mldsa.KeyID
			tp.Signatures = []ProofSignature{ed, pq}
			return Fixture{
				Schema:        "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:          "atp-v1/trust-proof-hybrid",
				Description:   "A trust proof carrying BOTH an Ed25519 signature AND an ML-DSA-65 signature (FIPS 204) over the same canonical payload per ATP §4.3 hybrid signing path. Production reference at api.oa2a.org emits hybrid proofs today; this fixture pins that wire format. A spec-conformant Go verifier MUST verify BOTH signatures. The Python reference verifier records ML-DSA-65 as present-but-out-of-scope. Verifier MUST ACCEPT.",
				FixtureType:   "trustProof",
				Spec:          specRefs("§4.3 Signing (hybrid mode)", "FIPS 204 ML-DSA-65"),
				KeypairRefs: []KeypairRef{
					keypairRefFor(primary, "vectors/issuer-primary.json"),
					{Role: mldsa.Role, Path: "vectors/mldsa65-seed.json", Algorithm: mldsa.Algorithm, PublicKeyHex: mldsa.PublicKeyHex, KeyID: mldsa.KeyID},
				},
				VerifierState: hybridVerifierState,
				Expected:      ExpectedOutcome{VerifyResult: "ACCEPT"},
				TrustProof:    &tp,
			}
		}},
		{"fixtures/transparency-log-sth.json", func() Fixture {
			sth := newSignedTreeHead(primary)
			return Fixture{
				Schema:        "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:          "atp-v1/transparency-log-sth",
				Description:   "A Signed Tree Head per ATP §5.6: treeSize, timestamp, rootHash (\"SHA256:\" + 64 hex chars), Ed25519 signature over the raw 32-byte decoded rootHash. Compatible with RFC 6962 §3.5 Certificate Transparency monitor expectations. Verifier MUST ACCEPT.",
				FixtureType:   "sth",
				Spec:          specRefs("§5.6 Signed Tree Head", "RFC 6962 §3.5"),
				KeypairRefs:   []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState: defaultVerifierState,
				Expected:      ExpectedOutcome{VerifyResult: "ACCEPT"},
				SignedTreeHead: &sth,
			}
		}},
	}

	type manifestEntry struct {
		path string
		sha  string
	}
	var manifest []manifestEntry

	for _, fs := range fixtures {
		f := fs.build()
		path := filepath.Join(outDir, fs.writePath)
		mustWriteJSONPretty(path, f)
		sha := sha256FileHex(path)
		manifest = append(manifest, manifestEntry{path: fs.writePath, sha: sha})
		fmt.Printf("wrote %s (sha256=%s)\n", fs.writePath, sha)
	}

	sort.Slice(manifest, func(i, j int) bool { return manifest[i].path < manifest[j].path })
	manifestPath := filepath.Join(outDir, "MANIFEST.sha256")
	var manifestLines []byte
	for _, e := range manifest {
		manifestLines = append(manifestLines, []byte(fmt.Sprintf("%s  %s\n", e.sha, e.path))...)
	}
	must(os.WriteFile(manifestPath, manifestLines, 0o644))
	fmt.Printf("wrote MANIFEST.sha256 (%d fixtures)\n", len(manifest))
}

// ---------------------------------------------------------------------------
// fixture content helpers
// ---------------------------------------------------------------------------

func newDiscoveryResponse(primary, mldsa keyVector) DiscoveryResponse {
	return DiscoveryResponse{
		AuthorityDID:     testAuthorityDID,
		Version:          atpVersion,
		ConformanceLevel: 2,
		Endpoints: DiscoveryEndpoints{
			DIDResolve:        "/api/v1/did/{did}",
			TrustProof:        "/api/v1/trust/proof",
			TrustVerify:       "/api/v1/trust/verify",
			TrustBatch:        "/api/v1/trust/batch",
			TransparencyLog:   "/api/v1/transparency/trust-proofs",
			TransparencyProof: "/api/v1/transparency/proof/{index}",
			TransparencySTH:   "/api/v1/transparency/sth",
			Revocations:       "/api/v1/trust/revocations",
		},
		PublicKeys: []DiscoveryPublicKey{
			{
				KeyID:        primary.KeyID,
				Algorithm:    primary.Algorithm,
				PublicKeyHex: primary.PublicKeyHex,
				Status:       "active",
				ValidFrom:    testValidFrom,
			},
			{
				KeyID:        mldsa.KeyID,
				Algorithm:    mldsa.Algorithm,
				PublicKeyHex: mldsa.PublicKeyHex,
				Status:       "active",
				ValidFrom:    testValidFrom,
			},
		},
		SupportedMethods: []string{"did:opena2a"},
		Capabilities: []string{
			"trust-proof",
			"transparency-log",
			"revocation",
			"batch-query",
		},
	}
}

func newBaselineTrustProof() TrustProof {
	return TrustProof{
		DID:                  testAgentDID,
		TrustLevel:           3,
		TrustScore:           0.825,
		Verdict:              "passed",
		IssuedAt:             testIssuedAt,
		ExpiresAt:            testExpiresAt,
		IssuerDID:            testAuthorityDID,
		Signatures:           nil, // filled by builder
		TransparencyLogIndex: 42,
	}
}

func newSignedTreeHead(primary keyVector) SignedTreeHead {
	sig := signEd25519(primary.SeedHex, sthSignedBytes(testRootHash))
	return SignedTreeHead{
		TreeSize:  1847294,
		Timestamp: testIssuedAt,
		RootHash:  testRootHash,
		SignedBy:  primary.KeyID,
		Signature: sig.Value,
	}
}

func specRefs(sections ...string) []SpecRef {
	out := []SpecRef{
		{
			ID:      "ATP",
			Ref:     "https://github.com/opena2a-org/agent-trust-protocol/blob/main/ATP-SPEC.md",
			Section: strings.Join(sections, ", "),
		},
		{
			ID:      "RFC 8032",
			Ref:     "https://datatracker.ietf.org/doc/html/rfc8032",
			Section: "§7.1 Test 1 (Ed25519 keypair source for issuer-primary)",
		},
		{
			ID:      "FIPS 204",
			Ref:     "https://csrc.nist.gov/pubs/fips/204/final",
			Section: "ML-DSA-65 (Module-Lattice-Based DSA)",
		},
	}
	return out
}

// ---------------------------------------------------------------------------
// utility helpers
// ---------------------------------------------------------------------------

type keyVector struct {
	Role         string `json:"role"`
	Algorithm    string `json:"algorithm"`
	SeedHex      string `json:"seedHex"`
	PublicKeyHex string `json:"publicKeyHex"`
	IssuerDID    string `json:"issuerDid"`
	KeyID        string `json:"keyId"`
}

func mustLoadKeyVector(relPath string) keyVector {
	b, err := os.ReadFile(filepath.Join(outDir, relPath)) //nolint:gosec // G304: build-time tool; outDir + constant relPath, no untrusted input
	must(err)
	var v keyVector
	must(json.Unmarshal(b, &v))
	if v.Algorithm == "Ed25519" {
		seed, err := hex.DecodeString(v.SeedHex)
		must(err)
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		want, err := hex.DecodeString(v.PublicKeyHex)
		must(err)
		if string(pub) != string(want) {
			panic(fmt.Sprintf("keypair vector mismatch in %s: seed-derived pubkey does not match", relPath))
		}
	}
	return v
}

func keypairRefFor(v keyVector, path string) KeypairRef {
	return KeypairRef{
		Role:         v.Role,
		Path:         path,
		Algorithm:    v.Algorithm,
		PublicKeyHex: v.PublicKeyHex,
		KeyID:        v.KeyID,
	}
}

func mustWriteJSONPretty(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, append(b, '\n'), 0o644))
}

func sha256FileHex(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // G304: build-time tool hashing files it just wrote under outDir
	must(err)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func mustResolveOutDir() string {
	wd, err := os.Getwd()
	must(err)
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "LICENSE")); err != nil {
		panic(fmt.Sprintf("did not find LICENSE at %s; run generator from scripts/generate-fixtures/", root))
	}
	return root
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
