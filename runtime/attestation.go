package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	hashPrefix    = "sha256:"
	hashSeparator = ";"
)

type AttestedSigner interface {
	Pubkey() string
	PubkeyHash() [sha256.Size]byte
	Sign(body []byte) string
}

type AttestationHashes interface {
	SetTLSKeyHash(h [sha256.Size]byte)
	SetTLSKeyHashIfChanged(h [sha256.Size]byte) bool
	SetSigningKeyHash(h [sha256.Size]byte)
	Serialize() []byte
}

// AttestedSigner owns the ephemeral secp256k1 response-signing key.
type attestedSigner struct {
	key *btcec.PrivateKey
}

func NewAttestedSigner() (AttestedSigner, error) {
	keyBytes := make([]byte, 32)
	if _, err := secureRandom(keyBytes); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	if privKey == nil {
		return nil, fmt.Errorf("invalid secp256k1 key from random bytes")
	}

	return &attestedSigner{key: privKey}, nil
}

func (a *attestedSigner) Pubkey() string {
	return hex.EncodeToString(a.key.PubKey().SerializeCompressed())
}

func (a *attestedSigner) PubkeyHash() [sha256.Size]byte {
	return sha256.Sum256(a.key.PubKey().SerializeCompressed())
}

// Sign signs body with BIP-340 Schnorr and returns the hex signature
func (a *attestedSigner) Sign(body []byte) string {
	msgHash := sha256.Sum256(body)
	sig, err := schnorr.Sign(a.key, msgHash[:])
	if err != nil {
		slog.Warn("schnorr sign failed", "error", err)
		return ""
	}
	return hex.EncodeToString(sig.Serialize())
}

// attestationDocument represents the CBOR structure of a Nitro attestation document.
type attestationDocument struct {
	PCRs map[uint][]byte `cbor:"pcrs"`
}

// AttestationHashes is the user_data payload embedded in NSM attestation
// documents, binding the document to the TLS cert and the response-signing key.
// The fields are mutated (ACME renewal, signing-key registration) while
// Serialize reads them per request, so all access is guarded by mu.
type attestationHashes struct {
	mu             sync.RWMutex
	tlsKeyHash     [sha256.Size]byte
	signingKeyHash [sha256.Size]byte
}

func NewAttestationHashes() AttestationHashes {
	return &attestationHashes{}
}

// SetTLSKeyHash records the fingerprint of the live TLS leaf cert.
func (a *attestationHashes) SetTLSKeyHash(h [sha256.Size]byte) {
	a.mu.Lock()
	a.tlsKeyHash = h
	a.mu.Unlock()
}

// SetTLSKeyHashIfChanged records h and reports whether it differed from the
// current value. Lets the per-handshake ACME cert wrapper re-bind (and log)
// only when autocert rotates the leaf.
func (a *attestationHashes) SetTLSKeyHashIfChanged(h [sha256.Size]byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tlsKeyHash == h {
		return false
	}
	a.tlsKeyHash = h
	return true
}

// SetSigningKeyHash records the response-signing key hash.
func (a *attestationHashes) SetSigningKeyHash(h [sha256.Size]byte) {
	a.mu.Lock()
	a.signingKeyHash = h
	a.mu.Unlock()
}

// Serialize returns user_data: sha256:<tls>;sha256:<signing>, with raw hash bytes.
func (a *attestationHashes) Serialize() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return []byte(fmt.Sprintf("%s%s%s%s%s",
		hashPrefix, a.tlsKeyHash, hashSeparator, hashPrefix, a.signingKeyHash))
}
