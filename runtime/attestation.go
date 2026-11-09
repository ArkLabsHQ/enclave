package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"
)

const (
	hashPrefix       = "sha256:"
	signingKeyPrefix = "ed25519:"
	cooldownPrefix   = "cooldown:"
	pcr0Prefix       = "pcr0:"
)

// TLSKeyHashFunc reports the TLS PublicKey hash.
type TLSKeyHashFunc func() (hash [sha256.Size]byte, ok bool)

// MigrationStatusFunc reports the migration status from the intent log.
type MigrationStatusFunc func(ctx context.Context) (*MigrationStatus, error)

// attestationDocument represents the CBOR structure of a Nitro attestation document.
type attestationDocument struct {
	PCRs map[uint][]byte `cbor:"pcrs"`
}

// AttestationData is the user_data payload of NSM attestation documents,
// binding them to the served TLS public key and the response-signing key, and
// disclosing any pending migration and the cooldown left before it.
type AttestationData struct {
	tlsKeyHash  atomic.Pointer[TLSKeyHashFunc]
	responseKey atomic.Pointer[ed25519.PrivateKey]
	migration   atomic.Pointer[MigrationStatusFunc]
}

// SetTLSKeyHashSource makes the attested hash track the certificate src reports,
// so a certificate swap can never leave the two disagreeing.
func (a *AttestationData) SetTLSKeyHashSource(src TLSKeyHashFunc) {
	a.tlsKeyHash.Store(&src)
}

// SetResponseSigningKey sets the key that signs proxied responses. Holding it
// here keeps the attested public key and the signing key one value.
func (a *AttestationData) SetResponseSigningKey(key ed25519.PrivateKey) {
	a.responseKey.Store(&key)
}

// SetMigrationSource sets where UserData reads the pending migration from.
func (a *AttestationData) SetMigrationSource(status MigrationStatusFunc) {
	a.migration.Store(&status)
}

// responseSigningKey returns the key set by SetResponseSigningKey, or nil.
func (a *AttestationData) responseSigningKey() ed25519.PrivateKey {
	if key := a.responseKey.Load(); key != nil {
		return *key
	}
	return nil
}

// Serialize returns "sha256:" followed by the TLS PublicKey hash, then
// "ed25519:" followed by the raw response-signing public key: the 79-byte
// prefix of UserData. Its zero value attests all-zero values.
func (a *AttestationData) Serialize() []byte {
	var tlsHash [sha256.Size]byte
	if src := a.tlsKeyHash.Load(); src != nil {
		if live, ok := (*src)(); ok {
			tlsHash = live
		}
	}
	signingKey := make([]byte, ed25519.PublicKeySize)
	if key := a.responseSigningKey(); key != nil {
		copy(signingKey, key.Public().(ed25519.PublicKey))
	}
	payload := append([]byte(hashPrefix), tlsHash[:]...)
	payload = append(payload, signingKeyPrefix...)
	return append(payload, signingKey...)
}

// UserData returns Serialize followed by the pending migration's Serialize:
// 149 bytes. It fails while the pending migration is unknown rather than attest
// that there is none.
func (a *AttestationData) UserData(ctx context.Context) ([]byte, error) {
	src := a.migration.Load()
	if src == nil {
		return nil, errors.New("no migration source")
	}
	status, err := (*src)(ctx)
	if err != nil {
		return nil, fmt.Errorf("read pending migration: %w", err)
	}
	migration, err := status.Serialize()
	if err != nil {
		return nil, err
	}
	return append(a.Serialize(), migration...), nil
}
