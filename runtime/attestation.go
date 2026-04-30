package runtime

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// AttestationHashRegistrar registers the SHA-256 hash of the enclave
// application's attestation public key with the in-process nitriding
// instance so it's embedded in NSM attestation documents.
//
// Implemented by *nitriding.Enclave (see runtime/nitriding/setters.go).
// Tests inject a fake.
type AttestationHashRegistrar interface {
	SetAttestationKeyHash(hash [32]byte)
}

// Attestation owns the ephemeral secp256k1 attestation key and the
// nitriding registrar. Init() generates the key and registers its hash
// so it appears in NSM attestation documents under appKeyHash.
type Attestation struct {
	key        *btcec.PrivateKey
	registrar  AttestationHashRegistrar
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
	a.registrar.SetAttestationKeyHash(hash)
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
