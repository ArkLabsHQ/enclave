package runtime

import (
	"crypto/ed25519"
	"crypto/sha256"
	"sync/atomic"
)

const (
	hashPrefix       = "sha256:"
	signingKeyPrefix = "ed25519:"
)

// TLSKeyHashFunc reports the TLS PublicKey hash.
type TLSKeyHashFunc func() (hash [sha256.Size]byte, ok bool)

// attestationDocument represents the CBOR structure of a Nitro attestation document.
type attestationDocument struct {
	PCRs map[uint][]byte `cbor:"pcrs"`
}

// AttestationHashes is the user_data payload of NSM attestation documents,
// binding them to the served TLS public key and the response-signing key. Its
// zero value attests all-zero values.
type AttestationHashes struct {
	tlsKeyHash  atomic.Pointer[TLSKeyHashFunc]
	responseKey atomic.Pointer[ed25519.PrivateKey]
}

// SetTLSKeyHashSource makes the attested hash track the certificate src reports,
// so a certificate swap can never leave the two disagreeing.
func (a *AttestationHashes) SetTLSKeyHashSource(src TLSKeyHashFunc) {
	a.tlsKeyHash.Store(&src)
}

// SetResponseSigningKey sets the key that signs proxied responses. Holding it
// here keeps the attested public key and the signing key one value.
func (a *AttestationHashes) SetResponseSigningKey(key ed25519.PrivateKey) {
	a.responseKey.Store(&key)
}

// responseSigningKey returns the key set by SetResponseSigningKey, or nil.
func (a *AttestationHashes) responseSigningKey() ed25519.PrivateKey {
	if key := a.responseKey.Load(); key != nil {
		return *key
	}
	return nil
}

// Serialize returns "sha256:" followed by the TLS PublicKey hash, then
// "ed25519:" followed by the raw response-signing public key: 79 bytes.
func (a *AttestationHashes) Serialize() []byte {
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
