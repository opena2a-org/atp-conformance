// Package main is the Go reference verifier for the ATP v1.0.0-rc1
// conformance fixture set. It depends only on the Go standard library plus
// github.com/cloudflare/circl (for ML-DSA-65 verification per FIPS 204).
//
// It does NOT import any opena2a-* SDK or registry package. The goal is to
// validate that the conformance fixtures are byte-stable and that an
// independent verifier with only the spec and the public keypair vectors can
// reproduce ACCEPT / REJECT for every fixture.
//
// Spec it implements:
//   - ATP v1.0.0-rc1 §4.4 trust proof verification (Steps 1-5)
//   - ATP §4.3 canonical pipe-delimited 7-field signing form
//   - ATP §5.6 Signed Tree Head verification (Ed25519 over raw rootHash bytes)
//   - ATP §7.1 well-known discovery structural verification
//   - ATP §4.3 hybrid Ed25519 + ML-DSA-65 (FIPS 204) signing path
//
// Usage:
//
//	go run . ../../fixtures/trust-proof-baseline.json
//	go run . ../../fixtures/*.json
//	go run . ../../fixtures              (directory; walks *.json)
//	go run . ../..                       (repo root; walks fixtures/*.json)
//
// Exit 0 iff every fixture's observed result matches expected.verifyResult.
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

// ---------------------------------------------------------------------------
// fixture shape (mirror of generator)
// ---------------------------------------------------------------------------

type fixture struct {
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	FixtureType       string             `json:"fixtureType"`
	KeypairRefs       []keypairRef       `json:"keypairRefs"`
	VerifierState     verifierState      `json:"verifierState"`
	Expected          expectedOutcome    `json:"expected"`
	DiscoveryResponse *discoveryResponse `json:"discoveryResponse,omitempty"`
	TrustProof        *trustProof        `json:"trustProof,omitempty"`
	SignedTreeHead    *signedTreeHead    `json:"signedTreeHead,omitempty"`
	InclusionProof    *inclusionProof    `json:"inclusionProof,omitempty"`
	ConsistencyProof  *consistencyProof  `json:"consistencyProof,omitempty"`
	RevocationList    *revocationList    `json:"revocationList,omitempty"`
}

// inclusionProof mirrors ATP §5.4 (see the generator for the wire contract).
type inclusionProof struct {
	LogIndex       int64           `json:"logIndex"`
	LeafHash       string          `json:"leafHash"`
	AuditPath      []string        `json:"auditPath"`
	SignedTreeHead *signedTreeHead `json:"signedTreeHead"`
}

// consistencyProof mirrors ATP §5.5.
type consistencyProof struct {
	FromSize           int64           `json:"fromSize"`
	ToSize             int64           `json:"toSize"`
	ConsistencyPath    []string        `json:"consistencyPath"`
	FromSignedTreeHead *signedTreeHead `json:"fromSignedTreeHead"`
	ToSignedTreeHead   *signedTreeHead `json:"toSignedTreeHead"`
}

// revocationList mirrors ATP §8.1.
type revocationList struct {
	Revocations []revocationEntry `json:"revocations"`
	NextSince   string            `json:"nextSince"`
}

type revocationEntry struct {
	AgentDID             string `json:"agentDid"`
	RevokedAt            string `json:"revokedAt"`
	Reason               string `json:"reason"`
	TransparencyLogIndex int64  `json:"transparencyLogIndex"`
	RevokedByKeyID       string `json:"revokedByKeyId"`
}

type keypairRef struct {
	Role         string `json:"role"`
	Path         string `json:"path"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	KeyID        string `json:"keyId"`
}

type verifierState struct {
	ClockRFC3339   string       `json:"clockRfc3339"`
	TrustedIssuers []string     `json:"trustedIssuers"`
	PublicKeys     []keypairRef `json:"publicKeys"`
}

type expectedOutcome struct {
	VerifyResult   string `json:"verifyResult"`
	RejectCategory string `json:"rejectCategory,omitempty"`
	ReasonContains string `json:"reasonContains,omitempty"`
}

type discoveryResponse struct {
	AuthorityDID     string               `json:"authorityDid"`
	Version          string               `json:"version"`
	ConformanceLevel int                  `json:"conformanceLevel"`
	Endpoints        map[string]string    `json:"endpoints"`
	PublicKeys       []discoveryPublicKey `json:"publicKeys"`
	SupportedMethods []string             `json:"supportedMethods"`
	Capabilities     []string             `json:"capabilities"`
}

type discoveryPublicKey struct {
	KeyID        string `json:"keyId"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"publicKeyHex"`
	Status       string `json:"status"`
	ValidFrom    string `json:"validFrom"`
}

type proofSignature struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type trustProof struct {
	DID                  string           `json:"did"`
	TrustLevel           int              `json:"trustLevel"`
	TrustScore           float64          `json:"trustScore"`
	Verdict              string           `json:"verdict"`
	IssuedAt             string           `json:"issuedAt"`
	ExpiresAt            string           `json:"expiresAt"`
	IssuerDID            string           `json:"issuerDid"`
	Signatures           []proofSignature `json:"signatures"`
	TransparencyLogIndex int64            `json:"transparencyLogIndex,omitempty"`
}

type signedTreeHead struct {
	TreeSize  int64  `json:"treeSize"`
	Timestamp string `json:"timestamp"`
	RootHash  string `json:"rootHash"`
	SignedBy  string `json:"signedBy"`
	Signature string `json:"signature"`
}

// ---------------------------------------------------------------------------
// canonicalization (mirror of generator VERBATIM)
// ---------------------------------------------------------------------------

func canonicalProofPayload(p *trustProof) []byte {
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

func sthSignedBytes(rootHash string) ([]byte, error) {
	stripped := strings.TrimPrefix(rootHash, "SHA256:")
	raw, err := hex.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("rootHash hex decode: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("rootHash must decode to %d bytes, got %d", sha256.Size, len(raw))
	}
	return raw, nil
}

func normalizeRFC3339(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// verification result
// ---------------------------------------------------------------------------

type result struct {
	Accepted       bool
	RejectCategory string
	Reason         string
	Ed25519Valid   bool
	MLDSA65Valid   bool
	SigsExpected   int
	SigsValid      int
}

func (r result) String() string {
	if r.Accepted {
		return "ACCEPT"
	}
	return fmt.Sprintf("REJECT[%s: %s]", r.RejectCategory, r.Reason)
}

// ---------------------------------------------------------------------------
// per-type verifiers
// ---------------------------------------------------------------------------

func verifyDiscovery(f fixture) result {
	if f.DiscoveryResponse == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "discoveryResponse missing"}
	}
	d := f.DiscoveryResponse

	// ATP §7.1 required fields: authorityDid, version, endpoints, publicKeys.
	if d.AuthorityDID == "" {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: "authorityDid missing"}
	}
	if d.Version == "" {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: "version missing"}
	}
	if d.Version != "1.0" {
		return result{RejectCategory: "UNSUPPORTED_VERSION", Reason: fmt.Sprintf("unsupported atp version %q (this verifier supports 1.0)", d.Version)}
	}
	if d.ConformanceLevel < 1 || d.ConformanceLevel > 3 {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("conformanceLevel %d out of range [1,3]", d.ConformanceLevel)}
	}
	if len(d.Endpoints) == 0 {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: "endpoints missing"}
	}
	if len(d.PublicKeys) == 0 {
		return result{RejectCategory: "DISCOVERY_INVALID", Reason: "publicKeys missing"}
	}

	// authorityDid trust.
	trusted := false
	for _, did := range f.VerifierState.TrustedIssuers {
		if did == d.AuthorityDID {
			trusted = true
			break
		}
	}
	if !trusted {
		return result{
			RejectCategory: "UNTRUSTED_ISSUER",
			Reason:         "authority DID " + d.AuthorityDID + " is not in the verifier's trusted set",
		}
	}

	// publicKeys structural validation.
	for i, pk := range d.PublicKeys {
		switch pk.Algorithm {
		case "Ed25519":
			raw, err := hex.DecodeString(pk.PublicKeyHex)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return result{
					RejectCategory: "DISCOVERY_INVALID",
					Reason:         fmt.Sprintf("publicKeys[%d] Ed25519 publicKeyHex invalid (need %d bytes)", i, ed25519.PublicKeySize),
				}
			}
		case "ML-DSA-65":
			raw, err := hex.DecodeString(pk.PublicKeyHex)
			if err != nil {
				return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("publicKeys[%d] ML-DSA-65 publicKeyHex invalid hex", i)}
			}
			tmp := new(mldsa65.PublicKey)
			if err := tmp.UnmarshalBinary(raw); err != nil {
				return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("publicKeys[%d] ML-DSA-65 publicKey unmarshal: %v", i, err)}
			}
		default:
			return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("publicKeys[%d] unsupported algorithm %q", i, pk.Algorithm)}
		}
		if pk.Status != "active" && pk.Status != "retired" && pk.Status != "revoked" {
			return result{RejectCategory: "DISCOVERY_INVALID", Reason: fmt.Sprintf("publicKeys[%d] status %q not in {active,retired,revoked}", i, pk.Status)}
		}
	}

	return result{Accepted: true}
}

func verifyTrustProof(f fixture) result {
	if f.TrustProof == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "trustProof missing"}
	}
	tp := f.TrustProof

	now, err := time.Parse(time.RFC3339, f.VerifierState.ClockRFC3339)
	if err != nil {
		return result{RejectCategory: "VERIFIER_CONFIG_ERROR", Reason: "bad clockRfc3339: " + err.Error()}
	}
	now = now.UTC()

	// ATP §4.4 Step 1: expiry.
	expires, err := time.Parse(time.RFC3339, tp.ExpiresAt)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "bad expiresAt: " + err.Error()}
	}
	if now.After(expires.UTC()) {
		return result{
			RejectCategory: "EXPIRED",
			Reason:         fmt.Sprintf("expired at %s, verifier clock is %s", expires.UTC().Format(time.RFC3339), now.Format(time.RFC3339)),
		}
	}

	// ATP §4.4 Step 2: issuer trust.
	trusted := false
	for _, did := range f.VerifierState.TrustedIssuers {
		if did == tp.IssuerDID {
			trusted = true
			break
		}
	}
	if !trusted {
		return result{
			RejectCategory: "UNTRUSTED_ISSUER",
			Reason:         "issuer DID " + tp.IssuerDID + " is not in the verifier's trusted set",
		}
	}

	// ATP §4.4 Step 5 semantic validation (early — these are cheap).
	if tp.TrustLevel < 0 || tp.TrustLevel > 4 {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: fmt.Sprintf("trustLevel %d out of range [0,4]", tp.TrustLevel)}
	}
	if tp.TrustScore < 0.0 || tp.TrustScore > 1.0 {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: fmt.Sprintf("trustScore %.6f out of range [0.0,1.0]", tp.TrustScore)}
	}
	if !validVerdict(tp.Verdict) {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: "verdict " + tp.Verdict + " not in {passed,warning,blocked,listed,verified,unknown}"}
	}
	issued, err := time.Parse(time.RFC3339, tp.IssuedAt)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "bad issuedAt: " + err.Error()}
	}
	if !issued.Before(expires) {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: "issuedAt must be before expiresAt"}
	}
	// ATP §4.4 step 5, §10.2 maximum: the declared window may not exceed
	// 24 hours. Exact comparison, no skew tolerance (§10.2: the skew bound
	// MUST NOT extend the 24-hour validity), whatever the verifier's clock.
	if expires.Sub(issued) > 24*time.Hour {
		return result{RejectCategory: "SEMANTIC_INVALID", Reason: "validity window exceeds 24 hours"}
	}

	// ATP §4.4 Steps 3-4: key lookup + signature verification.
	// Spec mandate (§4.3 paragraph 2): in hybrid mode BOTH signatures MUST verify.
	// We enforce: each declared signature MUST verify against some configured key
	// of the same algorithm; at least one valid Ed25519 signature is required.
	payload := canonicalProofPayload(tp)
	edKeys, pqKeys := indexPublicKeys(f.VerifierState.PublicKeys)
	res := result{SigsExpected: len(tp.Signatures)}

	for _, sig := range tp.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
		if err != nil {
			return result{RejectCategory: "SIGNATURE_INVALID", Reason: fmt.Sprintf("signature %s has invalid base64: %v", sig.KeyID, err)}
		}
		switch sig.Algorithm {
		case "Ed25519":
			ok := false
			for _, pk := range edKeys {
				if ed25519.Verify(pk, payload, sigBytes) {
					ok = true
					break
				}
			}
			if !ok {
				return result{RejectCategory: "SIGNATURE_INVALID", Reason: fmt.Sprintf("Ed25519 signature %s did not verify against any configured public key", sig.KeyID)}
			}
			res.Ed25519Valid = true
			res.SigsValid++
		case "ML-DSA-65":
			ok := false
			for _, pk := range pqKeys {
				if mldsa65.Verify(pk, payload, nil, sigBytes) {
					ok = true
					break
				}
			}
			if !ok {
				return result{RejectCategory: "SIGNATURE_INVALID", Reason: fmt.Sprintf("ML-DSA-65 signature %s did not verify against any configured public key", sig.KeyID)}
			}
			res.MLDSA65Valid = true
			res.SigsValid++
		default:
			return result{RejectCategory: "SIGNATURE_INVALID", Reason: "unsupported signature algorithm " + sig.Algorithm}
		}
	}

	if !res.Ed25519Valid {
		return result{RejectCategory: "SIGNATURE_INVALID", Reason: "no valid Ed25519 signature (ATP §4.3 baseline)"}
	}

	res.Accepted = true
	return res
}

func verifySTH(f fixture) result {
	if f.SignedTreeHead == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "signedTreeHead missing"}
	}
	sth := f.SignedTreeHead

	if sth.TreeSize <= 0 {
		return result{RejectCategory: "STH_INVALID", Reason: fmt.Sprintf("treeSize %d must be > 0", sth.TreeSize)}
	}
	if _, err := time.Parse(time.RFC3339, sth.Timestamp); err != nil {
		return result{RejectCategory: "STH_INVALID", Reason: "bad timestamp: " + err.Error()}
	}
	rootBytes, err := sthSignedBytes(sth.RootHash)
	if err != nil {
		return result{RejectCategory: "STH_INVALID", Reason: err.Error()}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sth.Signature)
	if err != nil {
		return result{RejectCategory: "SIGNATURE_INVALID", Reason: "STH signature has invalid base64: " + err.Error()}
	}

	edKeys, _ := indexPublicKeys(f.VerifierState.PublicKeys)
	for _, pk := range edKeys {
		if ed25519.Verify(pk, rootBytes, sigBytes) {
			return result{Accepted: true, Ed25519Valid: true, SigsExpected: 1, SigsValid: 1}
		}
	}
	return result{RejectCategory: "SIGNATURE_INVALID", Reason: "STH Ed25519 signature did not verify against any configured public key"}
}

// checkEmbeddedSTH validates a tree head embedded inside a §5.4/§5.5 proof
// payload — the same rules as verifySTH, factored so the proof verifiers and
// the standalone sth fixtureType stay behaviorally identical. Returns
// (category, reason); empty category means the head verifies.
func checkEmbeddedSTH(label string, sth *signedTreeHead, keys []keypairRef) (string, string) {
	if sth == nil {
		return "PARSE_ERROR", label + " missing"
	}
	if sth.TreeSize <= 0 {
		return "STH_INVALID", fmt.Sprintf("%s.treeSize %d must be > 0", label, sth.TreeSize)
	}
	if _, err := time.Parse(time.RFC3339, sth.Timestamp); err != nil {
		return "STH_INVALID", label + " bad timestamp: " + err.Error()
	}
	rootBytes, err := sthSignedBytes(sth.RootHash)
	if err != nil {
		return "STH_INVALID", label + ": " + err.Error()
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sth.Signature)
	if err != nil {
		return "SIGNATURE_INVALID", label + " signature has invalid base64: " + err.Error()
	}
	edKeys, _ := indexPublicKeys(keys)
	for _, pk := range edKeys {
		if ed25519.Verify(pk, rootBytes, sigBytes) {
			return "", ""
		}
	}
	return "SIGNATURE_INVALID", label + " Ed25519 signature did not verify against any configured public key"
}

// ---------------------------------------------------------------------------
// RFC 6962 Merkle verification (ATP §5.4/§5.5)
//
// leaf = SHA-256(0x00 || entry), node = SHA-256(0x01 || left || right).
// Verification follows RFC 9162 §2.1.3.2 (inclusion) and §2.1.4.2
// (consistency). Mirror VERBATIM in the Python verifier.
// ---------------------------------------------------------------------------

func merkleNodeHash(left, right [sha256.Size]byte) [sha256.Size]byte {
	buf := make([]byte, 0, 1+2*sha256.Size)
	buf = append(buf, 0x01)
	buf = append(buf, left[:]...)
	buf = append(buf, right[:]...)
	return sha256.Sum256(buf)
}

// wireHashBytes decodes a "SHA256:<64 lowercase hex>" wire hash.
func wireHashBytes(wire string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	stripped := strings.TrimPrefix(wire, "SHA256:")
	if stripped == wire {
		return out, fmt.Errorf("hash %q missing SHA256: prefix", wire)
	}
	raw, err := hex.DecodeString(stripped)
	if err != nil {
		return out, fmt.Errorf("hash %q is not hex: %v", wire, err)
	}
	if len(raw) != sha256.Size {
		return out, fmt.Errorf("hash %q must decode to %d bytes, got %d", wire, sha256.Size, len(raw))
	}
	copy(out[:], raw)
	return out, nil
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

// verifyInclusionProof implements ATP §5.4: the embedded tree head verifies
// per §5.6, then the RFC 9162 §2.1.3.2 recomputation from leafHash along
// auditPath must reproduce sth.rootHash.
func verifyInclusionProof(f fixture) result {
	if f.InclusionProof == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "inclusionProof missing"}
	}
	ip := f.InclusionProof

	leaf, err := wireHashBytes(ip.LeafHash)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "leafHash: " + err.Error()}
	}
	path := make([][sha256.Size]byte, len(ip.AuditPath))
	for i, p := range ip.AuditPath {
		path[i], err = wireHashBytes(p)
		if err != nil {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("auditPath[%d]: %v", i, err)}
		}
	}
	if cat, reason := checkEmbeddedSTH("signedTreeHead", ip.SignedTreeHead, f.VerifierState.PublicKeys); cat != "" {
		return result{RejectCategory: cat, Reason: reason}
	}
	root, err := wireHashBytes(ip.SignedTreeHead.RootHash)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "rootHash: " + err.Error()}
	}
	if ip.LogIndex < 0 || ip.LogIndex >= ip.SignedTreeHead.TreeSize {
		return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("logIndex %d out of range for treeSize %d", ip.LogIndex, ip.SignedTreeHead.TreeSize)}
	}
	if !verifyMerkleInclusion(ip.LogIndex, ip.SignedTreeHead.TreeSize, leaf, path, root) {
		return result{RejectCategory: "PROOF_INVALID", Reason: "recomputed root from leafHash along auditPath does not equal signedTreeHead.rootHash"}
	}
	return result{Accepted: true, Ed25519Valid: true, SigsExpected: 1, SigsValid: 1}
}

// verifyConsistencyProof implements ATP §5.5: both embedded tree heads verify
// per §5.6, then the RFC 9162 §2.1.4.2 algorithm must reproduce both roots.
func verifyConsistencyProof(f fixture) result {
	if f.ConsistencyProof == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "consistencyProof missing"}
	}
	cp := f.ConsistencyProof

	if cp.FromSignedTreeHead == nil || cp.ToSignedTreeHead == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "fromSignedTreeHead/toSignedTreeHead missing"}
	}
	if cp.FromSize != cp.FromSignedTreeHead.TreeSize || cp.ToSize != cp.ToSignedTreeHead.TreeSize {
		return result{RejectCategory: "PARSE_ERROR", Reason: "fromSize/toSize must equal the embedded tree heads' treeSize values"}
	}
	if cp.FromSize >= cp.ToSize {
		return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("fromSize %d must be < toSize %d", cp.FromSize, cp.ToSize)}
	}
	path := make([][sha256.Size]byte, len(cp.ConsistencyPath))
	var err error
	for i, p := range cp.ConsistencyPath {
		path[i], err = wireHashBytes(p)
		if err != nil {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("consistencyPath[%d]: %v", i, err)}
		}
	}
	if cat, reason := checkEmbeddedSTH("fromSignedTreeHead", cp.FromSignedTreeHead, f.VerifierState.PublicKeys); cat != "" {
		return result{RejectCategory: cat, Reason: reason}
	}
	if cat, reason := checkEmbeddedSTH("toSignedTreeHead", cp.ToSignedTreeHead, f.VerifierState.PublicKeys); cat != "" {
		return result{RejectCategory: cat, Reason: reason}
	}
	fromRoot, err := wireHashBytes(cp.FromSignedTreeHead.RootHash)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "fromSignedTreeHead.rootHash: " + err.Error()}
	}
	toRoot, err := wireHashBytes(cp.ToSignedTreeHead.RootHash)
	if err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "toSignedTreeHead.rootHash: " + err.Error()}
	}
	if !verifyMerkleConsistency(cp.FromSize, cp.ToSize, path, fromRoot, toRoot) {
		return result{RejectCategory: "PROOF_INVALID", Reason: "consistencyPath does not connect fromSignedTreeHead.rootHash to toSignedTreeHead.rootHash (append-only claim broken)"}
	}
	return result{Accepted: true, Ed25519Valid: true, SigsExpected: 2, SigsValid: 2}
}

// verifyRevocationList implements ATP §8.1: structural verification of the
// unsigned revocation body. A malformed timestamp rejects the WHOLE response
// — a client that skips unparseable entries keeps trusting a revoked agent.
func verifyRevocationList(f fixture) result {
	if f.RevocationList == nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "revocationList missing"}
	}
	rl := f.RevocationList

	if rl.NextSince == "" {
		return result{RejectCategory: "PARSE_ERROR", Reason: "nextSince missing"}
	}
	if _, err := time.Parse(time.RFC3339, rl.NextSince); err != nil {
		return result{RejectCategory: "PARSE_ERROR", Reason: "nextSince is not RFC 3339: " + err.Error()}
	}
	for i, entry := range rl.Revocations {
		if entry.AgentDID == "" || !strings.HasPrefix(entry.AgentDID, "did:") {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].agentDid %q is not a DID", i, entry.AgentDID)}
		}
		if _, err := time.Parse(time.RFC3339, entry.RevokedAt); err != nil {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].revokedAt is not RFC 3339: %v", i, err)}
		}
		if entry.Reason == "" {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].reason missing", i)}
		}
		if entry.TransparencyLogIndex < 0 {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].transparencyLogIndex %d must be >= 0", i, entry.TransparencyLogIndex)}
		}
		if !strings.Contains(entry.RevokedByKeyID, "#") {
			return result{RejectCategory: "PARSE_ERROR", Reason: fmt.Sprintf("revocations[%d].revokedByKeyId %q is not fragment-qualified", i, entry.RevokedByKeyID)}
		}
	}
	return result{Accepted: true}
}

func validVerdict(v string) bool {
	switch v {
	case "passed", "warning", "blocked", "listed", "verified", "unknown":
		return true
	}
	return false
}

func indexPublicKeys(refs []keypairRef) (eds []ed25519.PublicKey, pqs []*mldsa65.PublicKey) {
	for _, r := range refs {
		switch r.Algorithm {
		case "Ed25519":
			raw, err := hex.DecodeString(r.PublicKeyHex)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				continue
			}
			eds = append(eds, ed25519.PublicKey(raw))
		case "ML-DSA-65":
			raw, err := hex.DecodeString(r.PublicKeyHex)
			if err != nil {
				continue
			}
			pk := new(mldsa65.PublicKey)
			if err := pk.UnmarshalBinary(raw); err != nil {
				continue
			}
			pqs = append(pqs, pk)
		}
	}
	return
}

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------

func verify(f fixture) result {
	switch f.FixtureType {
	case "discovery":
		return verifyDiscovery(f)
	case "trustProof":
		return verifyTrustProof(f)
	case "sth":
		return verifySTH(f)
	case "inclusionProof":
		return verifyInclusionProof(f)
	case "consistencyProof":
		return verifyConsistencyProof(f)
	case "revocationList":
		return verifyRevocationList(f)
	default:
		return result{RejectCategory: "PARSE_ERROR", Reason: "unknown fixtureType " + f.FixtureType}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verify <fixture.json|dir>...")
		os.Exit(2)
	}

	paths, err := expandFixturePaths(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "no fixture *.json files found in supplied args")
		os.Exit(2)
	}

	totalPass, totalFail := 0, 0
	for _, p := range paths {
		f, err := loadFixture(p)
		if err != nil {
			fmt.Printf("FAIL  %s  (load error: %v)\n", relPath(p), err)
			totalFail++
			continue
		}
		got := verify(f)
		wantAccept := strings.EqualFold(f.Expected.VerifyResult, "ACCEPT")
		ok := (wantAccept && got.Accepted) || (!wantAccept && !got.Accepted)
		if ok && !wantAccept && f.Expected.RejectCategory != "" {
			if got.RejectCategory != f.Expected.RejectCategory {
				ok = false
			}
		}
		if ok && !wantAccept && f.Expected.ReasonContains != "" {
			if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(f.Expected.ReasonContains)) {
				ok = false
			}
		}
		status := "PASS"
		if !ok {
			status = "FAIL"
			totalFail++
		} else {
			totalPass++
		}
		fmt.Printf("%s  %s  [%s]\n", status, relPath(p), f.FixtureType)
		fmt.Printf("       expected: %s", f.Expected.VerifyResult)
		if f.Expected.RejectCategory != "" {
			fmt.Printf(" [%s]", f.Expected.RejectCategory)
		}
		fmt.Println()
		fmt.Printf("       observed: %s\n", got)
		if got.SigsExpected > 0 {
			fmt.Printf("       signatures: %d/%d valid (ed25519=%t mldsa65=%t)\n",
				got.SigsValid, got.SigsExpected, got.Ed25519Valid, got.MLDSA65Valid)
		}
	}

	fmt.Println()
	fmt.Printf("summary: %d pass, %d fail (%d fixtures)\n", totalPass, totalFail, totalPass+totalFail)
	if totalFail > 0 {
		os.Exit(1)
	}
}

func loadFixture(path string) (fixture, error) {
	// path originates from os.Args[1:] (operator-supplied fixture file/dir); this is a
	// standalone CLI verifier with no network/request surface, so no untrusted taint.
	b, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied CLI arg, not request-derived
	if err != nil {
		return fixture{}, err
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		return fixture{}, err
	}
	return f, nil
}

func expandFixturePaths(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		info, err := os.Stat(a) //nolint:gosec // G703: operator-supplied CLI arg, not request-derived
		if err != nil {
			return nil, err
		}
		switch {
		case info.IsDir():
			fixDir := a
			if _, err := os.Stat(filepath.Join(a, "fixtures")); err == nil { //nolint:gosec // G703: operator-supplied CLI arg
				fixDir = filepath.Join(a, "fixtures")
			}
			entries, err := os.ReadDir(fixDir)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
					out = append(out, filepath.Join(fixDir, e.Name()))
				}
			}
		default:
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out, nil
}

func relPath(p string) string {
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, p); err == nil {
			return rel
		}
	}
	return p
}
