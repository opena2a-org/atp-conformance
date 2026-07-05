// generate-fixtures produces the ATP v1.0.0-rc1 conformance fixture set.
//
// Every fixture is byte-stable: same seeds, same canonicalization, same JSON
// encoding settings. Re-running the generator MUST produce identical bytes;
// MANIFEST.sha256 pins each fixture.
//
// Spec coverage:
//   - discovery-valid                                       ATP §7.1 well-known discovery
//   - trust-proof-baseline / trust-proof-hybrid             ATP §4.2 + §4.3 (Ed25519, hybrid ML-DSA-65)
//   - trust-proof-{expired,untrusted-issuer,tampered-signature}  ATP §4.4 negatives
//   - transparency-log-sth                                  ATP §5.6 Signed Tree Head
//   - transparency-inclusion-proof-{valid,tampered-path}    ATP §5.4 / RFC 6962 §2.1.1
//   - transparency-consistency-proof-{valid,tampered-path}  ATP §5.5 / RFC 6962 §2.1.2
//   - revocation-list-{valid,malformed-timestamp}           ATP §8.1 structural
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
	Schema            string             `json:"$schema"`
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	FixtureType       string             `json:"fixtureType"`
	Spec              []SpecRef          `json:"spec"`
	KeypairRefs       []KeypairRef       `json:"keypairRefs"`
	VerifierState     VerifierState      `json:"verifierState"`
	Expected          ExpectedOutcome    `json:"expected"`
	DiscoveryResponse *DiscoveryResponse `json:"discoveryResponse,omitempty"`
	TrustProof        *TrustProof        `json:"trustProof,omitempty"`
	SignedTreeHead    *SignedTreeHead    `json:"signedTreeHead,omitempty"`
	InclusionProof    *InclusionProof    `json:"inclusionProof,omitempty"`
	ConsistencyProof  *ConsistencyProof  `json:"consistencyProof,omitempty"`
	RevocationList    *RevocationList    `json:"revocationList,omitempty"`
}

// ---------------------------------------------------------------------------
// payload shapes
// ---------------------------------------------------------------------------

// DiscoveryResponse mirrors ATP §7.1 well-known/atp shape. Field order is
// pinned for byte-stability.
type DiscoveryResponse struct {
	AuthorityDID     string               `json:"authorityDid"`
	Version          string               `json:"version"`
	ConformanceLevel int                  `json:"conformanceLevel"`
	Endpoints        DiscoveryEndpoints   `json:"endpoints"`
	PublicKeys       []DiscoveryPublicKey `json:"publicKeys"`
	SupportedMethods []string             `json:"supportedMethods"`
	Capabilities     []string             `json:"capabilities"`
	FederationPeers  []string             `json:"federationPeers,omitempty"`
}

type DiscoveryEndpoints struct {
	DIDResolve        string `json:"didResolve"`
	TrustProof        string `json:"trustProof"`
	TrustVerify       string `json:"trustVerify"`
	TrustBatch        string `json:"trustBatch"`
	TransparencyLog   string `json:"transparencyLog"`
	TransparencyProof string `json:"transparencyProof"`
	TransparencySTH   string `json:"transparencySth"`
	Revocations       string `json:"revocations"`
	Federation        string `json:"federation,omitempty"`
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
	DID                  string           `json:"did"`
	TrustLevel           int              `json:"trustLevel"`
	TrustScore           float64          `json:"trustScore"`
	Verdict              string           `json:"verdict"`
	IssuedAt             string           `json:"issuedAt"`
	ExpiresAt            string           `json:"expiresAt"`
	IssuerDID            string           `json:"issuerDid"`
	Signatures           []ProofSignature `json:"signatures"`
	TransparencyLogIndex int64            `json:"transparencyLogIndex,omitempty"`
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

// InclusionProof mirrors ATP §5.4: the RFC 6962 §2.1.1 audit path for the
// entry at logIndex, together with the signed tree head the recomputed root
// must equal. Verification is two rules: the STH verifies per §5.6, and
// MTH-recomputation from leafHash along auditPath equals sth.rootHash.
type InclusionProof struct {
	LogIndex       int64           `json:"logIndex"`
	LeafHash       string          `json:"leafHash"`
	AuditPath      []string        `json:"auditPath"`
	SignedTreeHead *SignedTreeHead `json:"signedTreeHead"`
}

// ConsistencyProof mirrors ATP §5.5: the RFC 6962 §2.1.2 consistency path
// between two tree states, together with both signed tree heads. Verification
// is three rules: both STHs verify per §5.6, and the §2.1.2 algorithm
// reproduces BOTH roots from the path.
type ConsistencyProof struct {
	FromSize           int64           `json:"fromSize"`
	ToSize             int64           `json:"toSize"`
	ConsistencyPath    []string        `json:"consistencyPath"`
	FromSignedTreeHead *SignedTreeHead `json:"fromSignedTreeHead"`
	ToSignedTreeHead   *SignedTreeHead `json:"toSignedTreeHead"`
}

// RevocationList mirrors ATP §8.1. The body is structural (unsigned in the
// spec — authenticity rides on TLS and each entry's transparencyLogIndex).
type RevocationList struct {
	Revocations []RevocationEntry `json:"revocations"`
	NextSince   string            `json:"nextSince"`
}

type RevocationEntry struct {
	AgentDID             string `json:"agentDid"`
	RevokedAt            string `json:"revokedAt"`
	Reason               string `json:"reason"`
	TransparencyLogIndex int64  `json:"transparencyLogIndex"`
	RevokedByKeyID       string `json:"revokedByKeyId"`
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
// RFC 6962 Merkle tree (transparency-log proofs, §5.4/§5.5)
//
// leaf = SHA-256(0x00 || entry), node = SHA-256(0x01 || left || right).
// Generation follows RFC 6962 §2.1.1 (PATH) and §2.1.2 (PROOF/SUBPROOF);
// verification follows the iterative algorithms of RFC 9162 §2.1.3.2 and
// §2.1.4.2. The generator VERIFIES every proof it emits (see the self-checks
// in main), so a math error here cannot silently pin bad fixture bytes.
// Mirror the verification algorithms VERBATIM in both reference verifiers.
// ---------------------------------------------------------------------------

func merkleLeafHash(entry []byte) [sha256.Size]byte {
	return sha256.Sum256(append([]byte{0x00}, entry...))
}

func merkleNodeHash(left, right [sha256.Size]byte) [sha256.Size]byte {
	buf := make([]byte, 0, 1+2*sha256.Size)
	buf = append(buf, 0x01)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
}

// largestPowerOfTwoBelow returns the largest power of two STRICTLY less than
// n (RFC 6962's k, with k < n <= 2k). n must be >= 2.
func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// merkleTreeHash computes MTH(D[n]) per RFC 6962 §2.1.
func merkleTreeHash(leaves [][sha256.Size]byte) [sha256.Size]byte {
	switch n := len(leaves); n {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	default:
		k := largestPowerOfTwoBelow(n)
		return merkleNodeHash(merkleTreeHash(leaves[:k]), merkleTreeHash(leaves[k:]))
	}
}

// merkleAuditPath computes PATH(m, D[n]) per RFC 6962 §2.1.1.
func merkleAuditPath(m int, leaves [][sha256.Size]byte) [][sha256.Size]byte {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(n)
	if m < k {
		return append(merkleAuditPath(m, leaves[:k]), merkleTreeHash(leaves[k:]))
	}
	return append(merkleAuditPath(m-k, leaves[k:]), merkleTreeHash(leaves[:k]))
}

// merkleConsistencyProof computes PROOF(m, D[n]) per RFC 6962 §2.1.2.
func merkleConsistencyProof(m int, leaves [][sha256.Size]byte) [][sha256.Size]byte {
	return merkleSubProof(m, leaves, true)
}

func merkleSubProof(m int, leaves [][sha256.Size]byte, b bool) [][sha256.Size]byte {
	n := len(leaves)
	if m == n {
		if b {
			return nil
		}
		return [][sha256.Size]byte{merkleTreeHash(leaves)}
	}
	k := largestPowerOfTwoBelow(n)
	if m <= k {
		return append(merkleSubProof(m, leaves[:k], b), merkleTreeHash(leaves[k:]))
	}
	return append(merkleSubProof(m-k, leaves[k:], false), merkleTreeHash(leaves[:k]))
}

// verifyMerkleInclusion checks an audit path per RFC 9162 §2.1.3.2.
func verifyMerkleInclusion(leafIndex, treeSize int64, leafHash [sha256.Size]byte, path [][sha256.Size]byte, root [sha256.Size]byte) bool {
	if leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize {
		return false
	}
	fn, sn := leafIndex, treeSize-1
	r := leafHash
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = merkleNodeHash(p, r)
			if fn%2 == 0 {
				for fn%2 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = merkleNodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

// verifyMerkleConsistency checks a consistency path per RFC 9162 §2.1.4.2.
func verifyMerkleConsistency(fromSize, toSize int64, path [][sha256.Size]byte, fromRoot, toRoot [sha256.Size]byte) bool {
	if fromSize < 1 || fromSize > toSize {
		return false
	}
	if fromSize == toSize {
		return len(path) == 0 && fromRoot == toRoot
	}
	// If fromSize is an exact power of two, the first component is implicitly
	// the old root itself.
	full := path
	if fromSize&(fromSize-1) == 0 {
		full = append([][sha256.Size]byte{fromRoot}, path...)
	}
	if len(full) == 0 {
		return false
	}
	fn, sn := fromSize-1, toSize-1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := full[0], full[0]
	for _, c := range full[1:] {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			fr = merkleNodeHash(c, fr)
			sr = merkleNodeHash(c, sr)
			if fn%2 == 0 {
				for fn%2 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = merkleNodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && fr == fromRoot && sr == toRoot
}

func hashToWire(h [sha256.Size]byte) string {
	return "SHA256:" + hex.EncodeToString(h[:])
}

// flipFirstHashByte deterministically corrupts a "SHA256:<hex>" wire hash by
// XORing its first raw byte with 0xFF (the same byte-stable corruption
// pattern as flipFirstSignatureByte).
func flipFirstHashByte(wire string) string {
	raw := sthSignedBytes(wire)
	raw[0] ^= 0xFF
	return "SHA256:" + hex.EncodeToString(raw)
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

// flipFirstSignatureByte deterministically corrupts a base64-encoded
// signature by XORing its first raw byte with 0xFF. Used to generate the
// tampered-signature negative fixture: the corruption is byte-stable, so the
// fixture reproduces identically on every generator run.
func flipFirstSignatureByte(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	must(err)
	if len(raw) == 0 {
		panic("empty signature")
	}
	raw[0] ^= 0xFF
	return base64.StdEncoding.EncodeToString(raw)
}

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
	testAgentDID     = "did:opena2a:mcp_server:agent_conformance_test_001"
	testAuthorityDID = "did:opena2a:authority:opena2a.org"
	testIssuedAt     = "2026-05-23T00:00:00Z"
	testExpiresAt    = "2099-12-31T23:59:59Z"
	testValidFrom    = "2026-01-01T00:00:00Z"
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

// Deterministic transparency-log tree for the §5.4/§5.5 fixtures: eight
// fixed leaf entries; the from-state is the first four. The pinned
// transparency-log-sth fixture (constant root) is UNTOUCHED — these fixtures
// carry their own real-tree STHs so the Merkle math is genuinely checkable.
const (
	proofTreeToSize   = 8
	proofTreeFromSize = 4
	proofLeafIndex    = 3
	fromSTHTimestamp  = "2026-05-22T00:00:00Z"
	toSTHTimestamp    = "2026-05-23T00:00:00Z"
)

func proofTreeLeaves(n int) [][sha256.Size]byte {
	leaves := make([][sha256.Size]byte, n)
	for i := 0; i < n; i++ {
		leaves[i] = merkleLeafHash([]byte(fmt.Sprintf("opena2a-atp-conformance-leaf-%d", i)))
	}
	return leaves
}

func newProofSTH(primary keyVector, treeSize int64, timestamp string, rootWire string) SignedTreeHead {
	sig := signEd25519(primary.SeedHex, sthSignedBytes(rootWire))
	return SignedTreeHead{
		TreeSize:  treeSize,
		Timestamp: timestamp,
		RootHash:  rootWire,
		SignedBy:  primary.KeyID,
		Signature: sig.Value,
	}
}

// newInclusionProof builds the §5.4 fixture payload over the deterministic
// 8-leaf tree and panics unless its own verification algorithm accepts it.
func newInclusionProof(primary keyVector) InclusionProof {
	leaves := proofTreeLeaves(proofTreeToSize)
	root := merkleTreeHash(leaves)
	path := merkleAuditPath(proofLeafIndex, leaves)
	if !verifyMerkleInclusion(proofLeafIndex, proofTreeToSize, leaves[proofLeafIndex], path, root) {
		panic("generator self-check failed: inclusion proof does not verify")
	}
	wirePath := make([]string, len(path))
	for i, p := range path {
		wirePath[i] = hashToWire(p)
	}
	sth := newProofSTH(primary, proofTreeToSize, toSTHTimestamp, hashToWire(root))
	return InclusionProof{
		LogIndex:       proofLeafIndex,
		LeafHash:       hashToWire(leaves[proofLeafIndex]),
		AuditPath:      wirePath,
		SignedTreeHead: &sth,
	}
}

// newConsistencyProof builds the §5.5 fixture payload between the 4-leaf and
// 8-leaf states and panics unless its own verification algorithm accepts it.
func newConsistencyProof(primary keyVector) ConsistencyProof {
	from := proofTreeLeaves(proofTreeFromSize)
	to := proofTreeLeaves(proofTreeToSize)
	fromRoot := merkleTreeHash(from)
	toRoot := merkleTreeHash(to)
	path := merkleConsistencyProof(proofTreeFromSize, to)
	if !verifyMerkleConsistency(proofTreeFromSize, proofTreeToSize, path, fromRoot, toRoot) {
		panic("generator self-check failed: consistency proof does not verify")
	}
	wirePath := make([]string, len(path))
	for i, p := range path {
		wirePath[i] = hashToWire(p)
	}
	fromSTH := newProofSTH(primary, proofTreeFromSize, fromSTHTimestamp, hashToWire(fromRoot))
	toSTH := newProofSTH(primary, proofTreeToSize, toSTHTimestamp, hashToWire(toRoot))
	return ConsistencyProof{
		FromSize:           proofTreeFromSize,
		ToSize:             proofTreeToSize,
		ConsistencyPath:    wirePath,
		FromSignedTreeHead: &fromSTH,
		ToSignedTreeHead:   &toSTH,
	}
}

// newRevocationList is the ATP §8.1 example body VERBATIM — the spec example
// and the fixture bytes are the same object, the §5.6 ratification pattern.
func newRevocationList() RevocationList {
	return RevocationList{
		Revocations: []RevocationEntry{
			{
				AgentDID:             "did:opena2a:mcp_server:compromised-package",
				RevokedAt:            "2026-03-22T15:00:00Z",
				Reason:               "Supply chain compromise detected",
				TransparencyLogIndex: 1847300,
				RevokedByKeyID:       "did:opena2a:authority:opena2a.org#key-v3",
			},
		},
		NextSince: "2026-03-22T15:00:00Z",
	}
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
				Schema:            "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:              "atp-v1/discovery-valid",
				Description:       "A well-formed ATP discovery response from /.well-known/atp per ATP §7.1. All required fields present, conformanceLevel within range, publicKeys structurally valid. Verifier MUST ACCEPT.",
				FixtureType:       "discovery",
				Spec:              specRefs("§7.1 Well-Known Endpoint"),
				KeypairRefs:       []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState:     hybridVerifierState,
				Expected:          ExpectedOutcome{VerifyResult: "ACCEPT"},
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
				Schema:      "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:        "atp-v1/trust-proof-hybrid",
				Description: "A trust proof carrying BOTH an Ed25519 signature AND an ML-DSA-65 signature (FIPS 204) over the same canonical payload per ATP §4.3 hybrid signing path. Production reference at api.oa2a.org emits hybrid proofs today; this fixture pins that wire format. A spec-conformant Go verifier MUST verify BOTH signatures. The Python reference verifier records ML-DSA-65 as present-but-out-of-scope. Verifier MUST ACCEPT.",
				FixtureType: "trustProof",
				Spec:        specRefs("§4.3 Signing (hybrid mode)", "FIPS 204 ML-DSA-65"),
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
				Schema:         "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:           "atp-v1/transparency-log-sth",
				Description:    "A Signed Tree Head per ATP §5.6: treeSize, timestamp, rootHash (\"SHA256:\" + 64 hex chars), Ed25519 signature over the raw 32-byte decoded rootHash. Compatible with RFC 6962 §3.5 Certificate Transparency monitor expectations. Verifier MUST ACCEPT.",
				FixtureType:    "sth",
				Spec:           specRefs("§5.6 Signed Tree Head", "RFC 6962 §3.5"),
				KeypairRefs:    []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState:  defaultVerifierState,
				Expected:       ExpectedOutcome{VerifyResult: "ACCEPT"},
				SignedTreeHead: &sth,
			}
		}},
		{"fixtures/trust-proof-expired.json", func() Fixture {
			// Identical to the baseline proof except both timestamps are in the
			// past relative to the fixed verifier clock. The Ed25519 signature is
			// VALID over the canonical payload (signed after the dates are set),
			// so expiry is the only reason to reject: a verifier that skips the
			// ATP §4.4 step-1 expiry check and jumps straight to signature
			// verification would wrongly ACCEPT this fixture.
			tp := newBaselineTrustProof()
			tp.IssuedAt = "2024-01-01T00:00:00Z"
			tp.ExpiresAt = "2025-01-01T00:00:00Z" // fixed clock is 2026-05-24
			sig := signEd25519(primary.SeedHex, canonicalProofPayload(&tp))
			sig.KeyID = primary.KeyID
			tp.Signatures = []ProofSignature{sig}
			return Fixture{
				Schema:        "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:          "atp-v1/trust-proof-expired",
				Description:   "A trust proof whose expiresAt (2025-01-01) is before the fixture's pinned verifier clock (2026-05-24). The Ed25519 signature IS valid over the canonical payload; expiry is the sole defect. Verifier MUST REJECT with category EXPIRED per ATP §4.4 step 1.",
				FixtureType:   "trustProof",
				Spec:          specRefs("§4.4 Verification (step 1: expiry)"),
				KeypairRefs:   []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState: defaultVerifierState,
				Expected:      ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "EXPIRED", ReasonContains: "expired"},
				TrustProof:    &tp,
			}
		}},
		{"fixtures/trust-proof-untrusted-issuer.json", func() Fixture {
			// Identical to the baseline proof — valid signature, in-date — but the
			// verifier's trustedIssuers list names a DIFFERENT authority, so the
			// proof's issuerDid is not trusted. Rejects at ATP §4.4 step 2 before
			// any cryptography runs. A verifier that only checks the signature
			// against configured public keys (and never the issuer allowlist)
			// would wrongly ACCEPT this fixture.
			tp := newBaselineTrustProof()
			sig := signEd25519(primary.SeedHex, canonicalProofPayload(&tp))
			sig.KeyID = primary.KeyID
			tp.Signatures = []ProofSignature{sig}
			untrustedState := defaultVerifierState
			untrustedState.TrustedIssuers = []string{"did:opena2a:authority:partner.example"}
			return Fixture{
				Schema:        "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:          "atp-v1/trust-proof-untrusted-issuer",
				Description:   "A structurally valid, correctly signed, in-date trust proof whose issuerDid (did:opena2a:authority:opena2a.org) is NOT in the verifier's trustedIssuers list (which trusts only did:opena2a:authority:partner.example). Verifier MUST REJECT with category UNTRUSTED_ISSUER per ATP §4.4 step 2.",
				FixtureType:   "trustProof",
				Spec:          specRefs("§4.4 Verification (step 2: issuer trust)"),
				KeypairRefs:   []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState: untrustedState,
				Expected:      ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "UNTRUSTED_ISSUER", ReasonContains: "issuer"},
				TrustProof:    &tp,
			}
		}},
		{"fixtures/trust-proof-tampered-signature.json", func() Fixture {
			// The baseline proof with the first byte of the Ed25519 signature
			// flipped after signing (deterministic XOR 0xFF). Everything else —
			// dates, issuer, payload — is valid, so signature verification is the
			// only step that can catch it.
			tp := newBaselineTrustProof()
			sig := signEd25519(primary.SeedHex, canonicalProofPayload(&tp))
			sig.KeyID = primary.KeyID
			sig.Value = flipFirstSignatureByte(sig.Value)
			tp.Signatures = []ProofSignature{sig}
			return Fixture{
				Schema:        "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:          "atp-v1/trust-proof-tampered-signature",
				Description:   "The baseline trust proof with the first byte of its Ed25519 signature deterministically corrupted (XOR 0xFF) after signing. Dates, issuer, and payload are all valid. Verifier MUST REJECT with category SIGNATURE_INVALID per ATP §4.4 step 4.",
				FixtureType:   "trustProof",
				Spec:          specRefs("§4.4 Verification (step 4: signature)"),
				KeypairRefs:   []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState: defaultVerifierState,
				Expected:      ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "SIGNATURE_INVALID", ReasonContains: "did not verify"},
				TrustProof:    &tp,
			}
		}},
		{"fixtures/transparency-inclusion-proof-valid.json", func() Fixture {
			ip := newInclusionProof(primary)
			return Fixture{
				Schema:         "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:           "atp-v1/transparency-inclusion-proof-valid",
				Description:    "An RFC 6962 audit path for log entry 3 of the deterministic 8-leaf conformance tree, with the signed tree head over that tree's real root. The STH verifies per ATP §5.6 and recomputing the root from leafHash along auditPath reproduces sth.rootHash per §5.4. Verifier MUST ACCEPT.",
				FixtureType:    "inclusionProof",
				Spec:           specRefs("§5.4 Inclusion Proof, RFC 6962 §2.1.1"),
				KeypairRefs:    []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState:  defaultVerifierState,
				Expected:       ExpectedOutcome{VerifyResult: "ACCEPT"},
				InclusionProof: &ip,
			}
		}},
		{"fixtures/transparency-inclusion-proof-tampered-path.json", func() Fixture {
			ip := newInclusionProof(primary)
			ip.AuditPath[0] = flipFirstHashByte(ip.AuditPath[0])
			return Fixture{
				Schema:         "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:           "atp-v1/transparency-inclusion-proof-tampered-path",
				Description:    "The valid inclusion proof with the first byte of auditPath[0] deterministically corrupted (XOR 0xFF). The STH still verifies, so only the RFC 6962 root recomputation can catch it: the recomputed root no longer equals sth.rootHash. Verifier MUST REJECT with category PROOF_INVALID.",
				FixtureType:    "inclusionProof",
				Spec:           specRefs("§5.4 Inclusion Proof, RFC 6962 §2.1.1"),
				KeypairRefs:    []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState:  defaultVerifierState,
				Expected:       ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "PROOF_INVALID", ReasonContains: "root"},
				InclusionProof: &ip,
			}
		}},
		{"fixtures/transparency-consistency-proof-valid.json", func() Fixture {
			cp := newConsistencyProof(primary)
			return Fixture{
				Schema:           "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:             "atp-v1/transparency-consistency-proof-valid",
				Description:      "An RFC 6962 consistency proof between the 4-leaf and 8-leaf states of the deterministic conformance tree, with both signed tree heads over the real roots. Both STHs verify per ATP §5.6 and the §2.1.2 algorithm reproduces both roots from consistencyPath per §5.5 — the append-only property. Verifier MUST ACCEPT.",
				FixtureType:      "consistencyProof",
				Spec:             specRefs("§5.5 Consistency Proof, RFC 6962 §2.1.2"),
				KeypairRefs:      []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState:    defaultVerifierState,
				Expected:         ExpectedOutcome{VerifyResult: "ACCEPT"},
				ConsistencyProof: &cp,
			}
		}},
		{"fixtures/transparency-consistency-proof-tampered-path.json", func() Fixture {
			cp := newConsistencyProof(primary)
			cp.ConsistencyPath[0] = flipFirstHashByte(cp.ConsistencyPath[0])
			return Fixture{
				Schema:           "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:             "atp-v1/transparency-consistency-proof-tampered-path",
				Description:      "The valid consistency proof with the first byte of consistencyPath[0] deterministically corrupted (XOR 0xFF). Both STHs still verify, so only the RFC 6962 §2.1.2 recomputation can catch it — a log that cannot produce a valid path between two published roots has broken its append-only claim. Verifier MUST REJECT with category PROOF_INVALID.",
				FixtureType:      "consistencyProof",
				Spec:             specRefs("§5.5 Consistency Proof, RFC 6962 §2.1.2"),
				KeypairRefs:      []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState:    defaultVerifierState,
				Expected:         ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "PROOF_INVALID", ReasonContains: "root"},
				ConsistencyProof: &cp,
			}
		}},
		{"fixtures/revocation-list-valid.json", func() Fixture {
			rl := newRevocationList()
			return Fixture{
				Schema:         "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:           "atp-v1/revocation-list-valid",
				Description:    "The ATP §8.1 revocation response body, byte-identical to the spec's example. The body is structural: the spec does not sign the CRL (authenticity rides on TLS and each entry's transparencyLogIndex), so verification checks required members and RFC 3339 timestamps. Verifier MUST ACCEPT.",
				FixtureType:    "revocationList",
				Spec:           specRefs("§8.1 Trust Proof Revocation"),
				KeypairRefs:    []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState:  defaultVerifierState,
				Expected:       ExpectedOutcome{VerifyResult: "ACCEPT"},
				RevocationList: &rl,
			}
		}},
		{"fixtures/revocation-list-malformed-timestamp.json", func() Fixture {
			rl := newRevocationList()
			rl.Revocations[0].RevokedAt = "2026-03-22 15:00:00" // space, not RFC 3339
			return Fixture{
				Schema:         "https://atp.opena2a.org/schemas/fixture-v1.json",
				Name:           "atp-v1/revocation-list-malformed-timestamp",
				Description:    "The §8.1 body with revokedAt spelled with a space instead of the RFC 3339 'T' separator. A client that caches revocations keyed on parse failures silently keeps trusting a revoked agent, so malformed timestamps MUST be rejected, not skipped. Verifier MUST REJECT with category PARSE_ERROR.",
				FixtureType:    "revocationList",
				Spec:           specRefs("§8.1 Trust Proof Revocation"),
				KeypairRefs:    []KeypairRef{keypairRefFor(primary, "vectors/issuer-primary.json")},
				VerifierState:  defaultVerifierState,
				Expected:       ExpectedOutcome{VerifyResult: "REJECT", RejectCategory: "PARSE_ERROR", ReasonContains: "revokedAt"},
				RevocationList: &rl,
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
