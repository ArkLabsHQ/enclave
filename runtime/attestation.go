package runtime

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// AttestationHashRegistrar registers the SHA-256 hash of the enclave
// application's attestation public key so it's embedded in NSM attestation
// documents.
//
// Implemented by *Runtime itself (see SetSigningKeyHash in runtime.go).
// Tests inject a fake.
type AttestationHashRegistrar interface {
	SetSigningKeyHash(hash [32]byte)
}

// Attestation owns the ephemeral secp256k1 attestation key and the
// nitriding registrar. Init() generates the key and registers its hash
// so it appears in NSM attestation documents under signingKeyHash.
type Attestation struct {
	key       *btcec.PrivateKey
	registrar AttestationHashRegistrar
}

// NewAttestation constructs an empty Attestation. Call SetRegistrar
// before Init.
func NewAttestation() *Attestation {
	return &Attestation{}
}

// SetRegistrar wires the in-process nitriding enclave as the recipient
// of the attestation key hash. Call this before Init.
func (a *Attestation) SetRegistrar(r AttestationHashRegistrar) {
	a.registrar = r
}

// Init generates an ephemeral secp256k1 keypair and registers its public
// key hash with the configured registrar.
func (a *Attestation) Init() error {
	keyBytes := make([]byte, 32)
	if _, err := secureRandom(keyBytes); err != nil {
		return fmt.Errorf("generate random bytes: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	if privKey == nil {
		return fmt.Errorf("invalid secp256k1 key from random bytes")
	}
	a.key = privKey

	if a.registrar == nil {
		return fmt.Errorf("no attestation registrar wired; call SetRegistrar before Init")
	}
	hash := sha256.Sum256(privKey.PubKey().SerializeCompressed())
	a.registrar.SetSigningKeyHash(hash)
	return nil
}

// Pubkey returns the hex-encoded compressed public key, or "" if Init
// hasn't run yet.
func (a *Attestation) Pubkey() string {
	if a == nil || a.key == nil {
		return ""
	}
	return hex.EncodeToString(a.key.PubKey().SerializeCompressed())
}

// Sign signs body with BIP-340 Schnorr and returns the hex signature, or
// "" if the key isn't ready or signing fails.
func (a *Attestation) Sign(body []byte) string {
	if a == nil || a.key == nil {
		return ""
	}
	msgHash := sha256.Sum256(body)
	sig, err := schnorr.Sign(a.key, msgHash[:])
	if err != nil {
		slog.Warn("schnorr sign failed", "error", err)
		return ""
	}
	return hex.EncodeToString(sig.Serialize())
}

// Ready returns true once Init has produced a key.
func (a *Attestation) Ready() bool {
	return a != nil && a.key != nil
}

// attestationDocument represents the CBOR structure of a Nitro attestation document.
type attestationDocument struct {
	PCRs map[uint][]byte `cbor:"pcrs"`
}

// AttestationHashes is the user_data payload embedded in NSM attestation
// documents, binding the document to the TLS cert and the response-signing key.
// The fields are mutated (ACME renewal, signing-key registration) while
// Serialize reads them per request, so all access is guarded by mu.
type AttestationHashes struct {
	mu             sync.RWMutex
	tlsKeyHash     [sha256.Size]byte
	signingKeyHash [sha256.Size]byte
}

// SetTLSKeyHash records the fingerprint of the live TLS leaf cert.
func (a *AttestationHashes) SetTLSKeyHash(h [sha256.Size]byte) {
	a.mu.Lock()
	a.tlsKeyHash = h
	a.mu.Unlock()
}

// SetTLSKeyHashIfChanged records h and reports whether it differed from the
// current value. Lets the per-handshake ACME cert wrapper re-bind (and log)
// only when autocert rotates the leaf.
func (a *AttestationHashes) SetTLSKeyHashIfChanged(h [sha256.Size]byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tlsKeyHash == h {
		return false
	}
	a.tlsKeyHash = h
	return true
}

// SetSigningKeyHash records the hash of the app's response-signing key.
func (a *AttestationHashes) SetSigningKeyHash(h [sha256.Size]byte) {
	a.mu.Lock()
	a.signingKeyHash = h
	a.mu.Unlock()
}

// Serialize returns "sha256:<tls>;sha256:<app>" matching the format clients
// expect when verifying the attestation document.
func (a *AttestationHashes) Serialize() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return []byte(fmt.Sprintf("%s%s%s%s%s",
		hashPrefix, a.tlsKeyHash, hashSeparator, hashPrefix, a.signingKeyHash))
}

// buildAttestationDocument creates an attestation document with an RSA public key.
func buildAttestationDocument(session *nsm.Session) ([]byte, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(session, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa key: %w", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(session, nonce); err != nil {
		return nil, nil, fmt.Errorf("read nonce: %w", err)
	}

	resp, err := session.Send(&request.Attestation{
		Nonce:     nonce,
		PublicKey: publicKeyDER,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("attestation request failed: %w", err)
	}
	if resp.Attestation == nil {
		return nil, nil, fmt.Errorf("attestation response missing document")
	}

	return resp.Attestation.Document, privateKey, nil
}

// extractPCR0FromAttestation parses the attestation document and returns PCR0 as hex.
func extractPCR0FromAttestation(attestationDoc []byte) (string, error) {
	pcr, err := extractPCRFromAttestation(attestationDoc, 0)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pcr), nil
}

// extractPCRFromAttestation parses a COSE Sign1 attestation document and
// returns the raw bytes for the given PCR index.
func extractPCRFromAttestation(attestationDoc []byte, index uint) ([]byte, error) {
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(attestationDoc, &coseSign1); err != nil {
		return nil, fmt.Errorf("unmarshal COSE Sign1: %w", err)
	}
	if len(coseSign1) < 3 {
		return nil, fmt.Errorf("invalid COSE Sign1 structure")
	}

	var payload []byte
	if err := cbor.Unmarshal(coseSign1[2], &payload); err != nil {
		return nil, fmt.Errorf("unmarshal COSE payload: %w", err)
	}

	var doc attestationDocument
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal attestation document: %w", err)
	}

	pcr, ok := doc.PCRs[index]
	if !ok {
		return nil, fmt.Errorf("PCR%d not found in attestation document", index)
	}

	return pcr, nil
}

// verifyAttestationDoc verifies a COSE Sign1 document against roots (nil uses
// nitrite's embedded AWS Nitro root) and returns the validated result. The "dev"
// deployment skips the check (its QEMU NSM is unsigned); any other deployment
// rejects a forged or unsigned doc.
func verifyAttestationDoc(doc []byte, roots *x509.CertPool) (*nitrite.Result, error) {
	if skipCOSEVerification() {
		slog.Warn("INSECURE: skipping COSE signature verification of attestation document",
			"deployment", getDeployment())
		return parseCOSEPayloadInsecure(doc)
	}

	// Verify the cert chain as of the attestation's own timestamp, not now: the
	// document is generated at migration time and read by the new enclave at a
	// later boot, so a short-lived Nitro leaf cert that expired in between must
	// not reject an otherwise-valid attestation. The timestamp lives inside the
	// signed payload, so a forged one fails the signature check below.
	pre, err := parseCOSEPayloadInsecure(doc)
	if err != nil {
		return nil, fmt.Errorf("parse attestation timestamp: %w", err)
	}

	// nitrite returns nil only when the cert chains to a trusted root and the
	// signature is valid; reject any failure (untrusted or bad signature).
	res, err := nitrite.Verify(doc, nitrite.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.UnixMilli(int64(pre.Document.Timestamp)),
	})
	if err != nil {
		return nil, fmt.Errorf("attestation verification: %w", err)
	}
	return res, nil
}

// parseCOSEPayloadInsecure decodes a COSE Sign1 envelope without verifying the
// signature or chain. Reached only when skipCOSEVerification() is true.
func parseCOSEPayloadInsecure(doc []byte) (*nitrite.Result, error) {
	var envelope struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected cbor.RawMessage
		Payload     []byte
		Signature   []byte
	}
	if err := cbor.Unmarshal(doc, &envelope); err != nil {
		return nil, fmt.Errorf("decode COSE Sign1 envelope: %w", err)
	}
	if len(envelope.Payload) == 0 {
		return nil, fmt.Errorf("COSE Sign1 payload empty")
	}
	var parsed nitrite.Document
	if err := cbor.Unmarshal(envelope.Payload, &parsed); err != nil {
		return nil, fmt.Errorf("decode attestation document: %w", err)
	}
	return &nitrite.Result{
		Document:    &parsed,
		Protected:   envelope.Protected,
		Payload:     envelope.Payload,
		Signature:   envelope.Signature,
		SignatureOK: false,
	}, nil
}

// getAttestationDocumentB64 generates a minimal NSM attestation document (without
// an RSA public key) and returns it as base64. The document is a COSE Sign1 structure
// signed by AWS Nitro hardware, proving this enclave's PCR values.
func getAttestationDocumentB64() (string, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return "", fmt.Errorf("open NSM session: %w", err)
	}
	defer func() { _ = session.Close() }()

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(session, nonce); err != nil {
		return "", fmt.Errorf("read nonce: %w", err)
	}

	resp, err := session.Send(&request.Attestation{
		Nonce: nonce,
	})
	if err != nil {
		return "", fmt.Errorf("attestation request failed: %w", err)
	}
	if resp.Attestation == nil {
		return "", fmt.Errorf("attestation response missing document")
	}

	return base64.StdEncoding.EncodeToString(resp.Attestation.Document), nil
}

// verifyPCR31Commitment: nil iff the previous enclave's attestation document
// committed to handing off to THIS enclave's PCR0 (by extending PCR31). The doc
// is verified against the AWS Nitro root, and its PCR0 must match the stored
// predecessor PCR0, before PCR31 is trusted.
func verifyPCR31Commitment(attestDocB64, myPCR0, prevPCR0 string) error {
	attestDoc, err := base64.StdEncoding.DecodeString(attestDocB64)
	if err != nil {
		return fmt.Errorf("decode attestation base64: %w", err)
	}
	result, err := verifyAttestationDoc(attestDoc, attestationRoots)
	if err != nil {
		return fmt.Errorf("verify predecessor attestation: %w", err)
	}
	// Bind the attestation to the claimed predecessor: a different, still
	// validly-signed enclave's document must not be substitutable.
	attestedPCR0, ok := result.Document.PCRs[0]
	if !ok {
		return fmt.Errorf("PCR0 not found in attestation document")
	}
	if !strings.EqualFold(hex.EncodeToString(attestedPCR0), prevPCR0) {
		return fmt.Errorf("attested PCR0 does not match stored MigrationPreviousPCR0")
	}
	pcr31, ok := result.Document.PCRs[migrationPCRIndex]
	if !ok {
		return fmt.Errorf("PCR%d not found in attestation document", migrationPCRIndex)
	}
	myPCR0Bytes, err := hex.DecodeString(myPCR0)
	if err != nil {
		return fmt.Errorf("decode own PCR0 hex: %w", err)
	}
	expected := sha512.Sum384(append(make([]byte, 48), myPCR0Bytes...))
	if !bytes.Equal(pcr31, expected[:]) {
		return fmt.Errorf("PCR%d mismatch: previous enclave committed to a different target PCR0", migrationPCRIndex)
	}
	return nil
}
