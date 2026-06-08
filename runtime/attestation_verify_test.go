package runtime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
)

// These tests exercise the real attestation-verification path: a synthetic AWS
// Nitro-style COSE Sign1 document signed by a throwaway P-384 CA, verified
// through nitrite.Verify against that CA. They are the source of truth for the
// security property, since the QEMU emulator's NSM produces unsigned mock
// documents that cannot be verified by any root.

// signedAttestation bundles a COSE Sign1 document with the CA pool that verifies it.
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

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-nitro-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
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
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	doc := nitrite.Document{
		ModuleID:    "test-module",
		Timestamp:   uint64(time.Now().UnixMilli()),
		Digest:      "SHA384",
		PCRs:        pcrs,
		Certificate: leafDER,
		CABundle:    [][]byte{caDER},
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

func TestVerifyPCR31Commitment_ValidSignedDocPasses(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod") // force the verification path

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 48))
	att := buildSignedAttestation(t, map[uint][]byte{
		migrationPCRIndex: pcr31Commitment(t, myPCR0),
	})
	useAttestationRoots(t, att.roots)

	if err := verifyPCR31Commitment(att.docB64, myPCR0); err != nil {
		t.Fatalf("valid commitment should verify, got: %v", err)
	}
}

// The regression guard for the whole finding: an unsigned/forged document with
// the correct PCR31 must be rejected. Before the fix this returned nil.
func TestVerifyPCR31Commitment_ForgedDocRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
	forged := buildForgedAttestation(t, map[uint][]byte{
		migrationPCRIndex: pcr31Commitment(t, myPCR0),
	})

	if err := verifyPCR31Commitment(forged, myPCR0); err == nil {
		t.Fatal("forged (unsigned) attestation with correct PCR31 must be rejected")
	}
}

// A document signed by a CA that is not in the trust store must be rejected,
// even though its signature is internally valid.
func TestVerifyPCR31Commitment_UntrustedSignerRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xef}, 48))
	att := buildSignedAttestation(t, map[uint][]byte{
		migrationPCRIndex: pcr31Commitment(t, myPCR0),
	})
	other := buildSignedAttestation(t, map[uint][]byte{migrationPCRIndex: make([]byte, 48)})
	useAttestationRoots(t, other.roots) // trust a different CA

	if err := verifyPCR31Commitment(att.docB64, myPCR0); err == nil {
		t.Fatal("attestation from an untrusted CA must be rejected")
	}
}

// A validly signed document that commits to a different target PCR0 must fail
// the commitment check.
func TestVerifyPCR31Commitment_WrongTargetRejected(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 48))
	otherPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0x22}, 48))
	att := buildSignedAttestation(t, map[uint][]byte{
		migrationPCRIndex: pcr31Commitment(t, otherPCR0),
	})
	useAttestationRoots(t, att.roots)

	if err := verifyPCR31Commitment(att.docB64, myPCR0); err == nil {
		t.Fatal("commitment to a different PCR0 must be rejected")
	}
}

// The dev deployment prefix bypasses signature verification (for the QEMU mock
// NSM), so the same forged document is accepted there. This documents the
// bypass and locks in that every other prefix enforces verification.
func TestVerifyPCR31Commitment_DevPrefixSkipsVerification(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "dev")

	myPCR0 := hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))
	forged := buildForgedAttestation(t, map[uint][]byte{
		migrationPCRIndex: pcr31Commitment(t, myPCR0),
	})

	if err := verifyPCR31Commitment(forged, myPCR0); err != nil {
		t.Fatalf("dev prefix should skip COSE verification, got: %v", err)
	}
}
