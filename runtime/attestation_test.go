package runtime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
)

type signedAttestation struct {
	docB64 string
	roots  *x509.CertPool
}

// pcr31Commitment returns SHA384(zeros48 ‖ pcr0), the value an honest predecessor
// extends PCR31 to when committing to hand off to pcr0Hex.
func pcr31Commitment(t *testing.T, pcr0Hex string) []byte {
	t.Helper()
	pcr0, err := hex.DecodeString(pcr0Hex)
	if err != nil {
		t.Fatalf("decode pcr0: %v", err)
	}
	sum := sha512.Sum384(append(make([]byte, 48), pcr0...))
	return sum[:]
}

// useAttestationRoots points verifyAttestationDoc at the given pool for the
// duration of the test.
func useAttestationRoots(t *testing.T, pool *x509.CertPool) {
	t.Helper()
	prev := attestationRoots
	attestationRoots = pool
	t.Cleanup(func() { attestationRoots = prev })
}

// buildSignedAttestation produces a COSE Sign1 attestation document with the
// given PCRs, signed by a fresh P-384 CA, matching what nitrite.Verify expects
// (ES384 protected header, "Signature1" structure, ECDSAWithSHA384 leaf chained
// to the CA).
func buildSignedAttestation(t *testing.T, pcrs map[uint][]byte) signedAttestation {
	t.Helper()
	now := time.Now()
	return buildSignedAttestationCustom(t, pcrs, now.Add(-time.Hour), now.Add(time.Hour), now, nil)
}

// buildSignedAttestationCustom lets a test control the cert validity window, the
// document timestamp (to exercise verification as-of the attestation time), and
// the user_data the document carries (nil for none).
func buildSignedAttestationCustom(t *testing.T, pcrs map[uint][]byte, certNotBefore, certNotAfter, timestamp time.Time, userData []byte) signedAttestation {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-nitro-root"},
		NotBefore:             certNotBefore,
		NotAfter:              certNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "test-nitro-leaf"},
		NotBefore:          certNotBefore,
		NotAfter:           certNotAfter,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	doc := nitrite.Document{
		ModuleID:    "test-module",
		Timestamp:   uint64(timestamp.UnixMilli()),
		Digest:      "SHA384",
		PCRs:        pcrs,
		Certificate: leafDER,
		CABundle:    [][]byte{caDER},
		UserData:    userData,
	}
	payload, err := cbor.Marshal(&doc)
	if err != nil {
		t.Fatalf("marshal attestation document: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	return signedAttestation{
		docB64: base64.StdEncoding.EncodeToString(coseSign1(t, payload, leafKey)),
		roots:  roots,
	}
}

// coseEnvelope is the COSE Sign1 array [protected, unprotected, payload, signature].
type coseEnvelope struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// coseProtectedHeader returns the CBOR-encoded protected header {1: -35} (ES384).
func coseProtectedHeader(t *testing.T) []byte {
	t.Helper()
	h, err := cbor.Marshal(struct {
		Alg int64 `cbor:"1,keyasint"`
	}{Alg: -35})
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}
	return h
}

// buildForgedAttestation mimics an attacker (and the QEMU mock NSM): a COSE
// envelope carrying the chosen PCRs but with a zero certificate and zero
// signature. Verification must reject it; only the dev bypass accepts it.
func buildForgedAttestation(t *testing.T, pcrs map[uint][]byte) string {
	t.Helper()
	doc := nitrite.Document{
		ModuleID:    "forged",
		Timestamp:   uint64(time.Now().UnixMilli()),
		Digest:      "SHA384",
		PCRs:        pcrs,
		Certificate: make([]byte, 64),
		CABundle:    [][]byte{make([]byte, 64)},
	}
	payload, err := cbor.Marshal(&doc)
	if err != nil {
		t.Fatalf("marshal forged document: %v", err)
	}
	out, err := cbor.Marshal(&coseEnvelope{
		Protected:   coseProtectedHeader(t),
		Unprotected: cbor.RawMessage{0xa0},
		Payload:     payload,
		Signature:   make([]byte, 96),
	})
	if err != nil {
		t.Fatalf("marshal forged envelope: %v", err)
	}
	return base64.StdEncoding.EncodeToString(out)
}

// predecessorPCRs builds a PCRs map that sets PCR0 to the predecessor's own
// measurement and commits PCR31 to targetPCR0Hex — what an honest predecessor's
// attestation carries when handing off to targetPCR0Hex.
func predecessorPCRs(t *testing.T, prevPCR0Bytes []byte, targetPCR0Hex string) map[uint][]byte {
	t.Helper()
	return map[uint][]byte{
		0:                 prevPCR0Bytes,
		migrationPCRIndex: pcr31Commitment(t, targetPCR0Hex),
	}
}

// coseSign1 wraps payload in a COSE Sign1 envelope signed with key over the
// "Signature1" structure (SHA-384, r‖s).
func coseSign1(t *testing.T, payload []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	protected := coseProtectedHeader(t)

	sigStruct, err := cbor.Marshal(&struct {
		_           struct{} `cbor:",toarray"`
		Context     string
		Protected   []byte
		ExternalAAD []byte
		Payload     []byte
	}{
		Context:     "Signature1",
		Protected:   protected,
		ExternalAAD: []byte{},
		Payload:     payload,
	})
	if err != nil {
		t.Fatalf("marshal Signature1 structure: %v", err)
	}

	digest := sha512.Sum384(sigStruct)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])

	out, err := cbor.Marshal(&coseEnvelope{
		Protected:   protected,
		Unprotected: cbor.RawMessage{0xa0}, // empty map
		Payload:     payload,
		Signature:   sig,
	})
	if err != nil {
		t.Fatalf("marshal COSE Sign1 envelope: %v", err)
	}
	return out
}

func TestAttestationHashesSerialize(t *testing.T) {
	var h AttestationHashes
	for i := range h.tlsKeyHash {
		h.tlsKeyHash[i] = byte(i)
	}
	for i := range h.signingKeyHash {
		h.signingKeyHash[i] = byte(i + 1)
	}

	got := h.Serialize()

	wantLen := sha256.Size*2 + len(hashPrefix)*2 + len(hashSeparator)
	if len(got) != wantLen {
		t.Fatalf("serialized length: got %d, want %d", len(got), wantLen)
	}

	if !bytes.HasPrefix(got, []byte(hashPrefix)) {
		t.Fatalf("missing leading hash prefix: got %q", got[:len(hashPrefix)])
	}
	if !strings.Contains(string(got), hashSeparator+hashPrefix) {
		t.Fatalf("missing separator + second prefix in %q", got)
	}

	tlsStart := len(hashPrefix)
	tlsEnd := tlsStart + sha256.Size
	if !bytes.Equal(got[tlsStart:tlsEnd], h.tlsKeyHash[:]) {
		t.Fatalf("tlsKeyHash bytes: got %x, want %x", got[tlsStart:tlsEnd], h.tlsKeyHash[:])
	}

	sigKeyStart := tlsEnd + len(hashSeparator) + len(hashPrefix)
	if !bytes.Equal(got[sigKeyStart:], h.signingKeyHash[:]) {
		t.Fatalf("signingKeyHash bytes: got %x, want %x", got[sigKeyStart:], h.signingKeyHash[:])
	}
}

func TestAttestationHashesSerializeZeroValue(t *testing.T) {
	var h AttestationHashes
	got := h.Serialize()

	wantLen := sha256.Size*2 + len(hashPrefix)*2 + len(hashSeparator)
	if len(got) != wantLen {
		t.Fatalf("zero-value length: got %d, want %d", len(got), wantLen)
	}
	zero := make([]byte, sha256.Size)
	tlsStart := len(hashPrefix)
	if !bytes.Equal(got[tlsStart:tlsStart+sha256.Size], zero) {
		t.Fatalf("zero-value tlsKeyHash should be all zeros, got %x", got[tlsStart:tlsStart+sha256.Size])
	}
}

func TestVerifyPCR31Commitment_ValidSignedDocPasses(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod") // force the verification path

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
	prevPCR0Bytes := bytes.Repeat([]byte{0x99}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	att := buildSignedAttestation(t, predecessorPCRs(t, prevPCR0Bytes, myPCR0))
	useAttestationRoots(t, att.roots)

	if err := verifyPCR31Commitment(att.docB64, myPCR0, prevPCR0); err != nil {
		t.Fatalf("valid commitment should verify, got: %v", err)
	}
}

// The regression guard for the whole finding: an unsigned/forged document with
// the correct PCR31 must be rejected. Before the fix this returned nil.
func TestVerifyPCR31Commitment_ForgedDocRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
	prevPCR0Bytes := bytes.Repeat([]byte{0x99}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	forged := buildForgedAttestation(t, predecessorPCRs(t, prevPCR0Bytes, myPCR0))

	if err := verifyPCR31Commitment(forged, myPCR0, prevPCR0); err == nil {
		t.Fatal("forged (unsigned) attestation with correct PCR31 must be rejected")
	}
}

// A document signed by a CA that is not in the trust store must be rejected,
// even though its signature is internally valid.
func TestVerifyPCR31Commitment_UntrustedSignerRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xef}, 48))
	prevPCR0Bytes := bytes.Repeat([]byte{0x99}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	att := buildSignedAttestation(t, predecessorPCRs(t, prevPCR0Bytes, myPCR0))
	other := buildSignedAttestation(t, predecessorPCRs(t, prevPCR0Bytes, myPCR0))
	useAttestationRoots(t, other.roots) // trust a different CA

	if err := verifyPCR31Commitment(att.docB64, myPCR0, prevPCR0); err == nil {
		t.Fatal("attestation from an untrusted CA must be rejected")
	}
}

// A validly signed document that commits to a different target PCR0 must fail
// the commitment check.
func TestVerifyPCR31Commitment_WrongTargetRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 48))
	otherPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x22}, 48))
	prevPCR0Bytes := bytes.Repeat([]byte{0x99}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	att := buildSignedAttestation(t, predecessorPCRs(t, prevPCR0Bytes, otherPCR0))
	useAttestationRoots(t, att.roots)

	if err := verifyPCR31Commitment(att.docB64, myPCR0, prevPCR0); err == nil {
		t.Fatal("commitment to a different PCR0 must be rejected")
	}
}

// A validly signed document whose PCR0 does not match the stored predecessor
// PCR0 must be rejected — a different enclave's document cannot be substituted.
func TestVerifyPCR31Commitment_PCR0MismatchRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
	prevPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x99}, 48))
	wrongPCR0Bytes := bytes.Repeat([]byte{0x77}, 48) // doc attests a different PCR0
	att := buildSignedAttestation(t, predecessorPCRs(t, wrongPCR0Bytes, myPCR0))
	useAttestationRoots(t, att.roots)

	if err := verifyPCR31Commitment(att.docB64, myPCR0, prevPCR0); err == nil {
		t.Fatal("attestation whose PCR0 differs from MigrationPreviousPCR0 must be rejected")
	}
}

// A cert that has expired by now but was valid at the attestation timestamp must
// still verify — the document is checked as-of its own timestamp, not boot time.
func TestVerifyPCR31Commitment_ExpiredCertValidAtTimestamp(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")

	now := time.Now()
	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
	prevPCR0Bytes := bytes.Repeat([]byte{0x99}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	// Cert window is entirely in the past; the timestamp falls inside it.
	att := buildSignedAttestationCustom(t, predecessorPCRs(t, prevPCR0Bytes, myPCR0),
		now.Add(-3*time.Hour), now.Add(-1*time.Hour), now.Add(-2*time.Hour), nil)
	useAttestationRoots(t, att.roots)

	if err := verifyPCR31Commitment(att.docB64, myPCR0, prevPCR0); err != nil {
		t.Fatalf("attestation valid at its timestamp must verify despite a now-expired cert, got: %v", err)
	}
}

// The dev deployment prefix bypasses signature verification (for the QEMU mock
// NSM), so the same forged document is accepted there. This documents the
// bypass and locks in that every other prefix enforces verification.
func TestVerifyPCR31Commitment_DevPrefixSkipsVerification(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "dev")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
	prevPCR0Bytes := bytes.Repeat([]byte{0x99}, 48)
	prevPCR0 := hex.EncodeToString(prevPCR0Bytes)
	forged := buildForgedAttestation(t, predecessorPCRs(t, prevPCR0Bytes, myPCR0))

	if err := verifyPCR31Commitment(forged, myPCR0, prevPCR0); err != nil {
		t.Fatalf("dev prefix should skip COSE verification, got: %v", err)
	}
}
