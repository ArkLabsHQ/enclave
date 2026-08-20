package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync/atomic"

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

// TLSKeyHashFunc reports the fingerprint of the TLS leaf currently served; ok is
// false before the first certificate is installed.
type TLSKeyHashFunc func() (hash [sha256.Size]byte, ok bool)

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

// AttestationHashes is the user_data payload of NSM attestation documents,
// binding them to the served TLS leaf and response-signing key. Its zero value
// attests all-zero hashes.
type AttestationHashes struct {
	tlsKeyHash     atomic.Pointer[TLSKeyHashFunc]
	signingKeyHash atomic.Pointer[[sha256.Size]byte]
}

// SetTLSKeyHashSource makes the attested hash track the certificate src reports,
// so a certificate swap can never leave the two disagreeing.
func (a *AttestationHashes) SetTLSKeyHashSource(src TLSKeyHashFunc) {
	a.tlsKeyHash.Store(&src)
}

// SetSigningKeyHash records the response-signing key hash.
func (a *AttestationHashes) SetSigningKeyHash(h [sha256.Size]byte) {
	a.signingKeyHash.Store(&h)
}

// Serialize returns user_data: sha256:<tls>;sha256:<signing>, with raw hash bytes.
func (a *AttestationHashes) Serialize() []byte {
	var tlsHash, signingHash [sha256.Size]byte
	if src := a.tlsKeyHash.Load(); src != nil {
		if live, ok := (*src)(); ok {
			tlsHash = live
		}
	}
	if signing := a.signingKeyHash.Load(); signing != nil {
		signingHash = *signing
	}

	payload := make([]byte, 0, 2*len(hashPrefix)+len(hashSeparator)+2*sha256.Size)
	payload = append(payload, hashPrefix...)
	payload = append(payload, tlsHash[:]...)
	payload = append(payload, hashSeparator...)
	payload = append(payload, hashPrefix...)
	return append(payload, signingHash[:]...)
}

// staticKeyHash is the source for a certificate that never changes.
func staticKeyHash(h [sha256.Size]byte) TLSKeyHashFunc {
	return func() ([sha256.Size]byte, bool) { return h, true }
}
