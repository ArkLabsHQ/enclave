package runtime

import (
	"crypto/sha256"
	"sync/atomic"
)

const hashPrefix = "sha256:"

// TLSKeyHashFunc reports the TLS PublicKey hash.
type TLSKeyHashFunc func() (hash [sha256.Size]byte, ok bool)

// attestationDocument represents the CBOR structure of a Nitro attestation document.
type attestationDocument struct {
	PCRs map[uint][]byte `cbor:"pcrs"`
}

// AttestationHashes is the user_data payload of NSM attestation documents,
// binding them to the served TLS public key. Its zero value attests an all-zero hash.
type AttestationHashes struct {
	tlsKeyHash atomic.Pointer[TLSKeyHashFunc]
}

// SetTLSKeyHashSource makes the attested hash track the certificate src reports,
// so a certificate swap can never leave the two disagreeing.
func (a *AttestationHashes) SetTLSKeyHashSource(src TLSKeyHashFunc) {
	a.tlsKeyHash.Store(&src)
}

// Serialize returns "sha256:" followed by the TLS PublicKey hash.
func (a *AttestationHashes) Serialize() []byte {
	var tlsHash [sha256.Size]byte
	if src := a.tlsKeyHash.Load(); src != nil {
		if live, ok := (*src)(); ok {
			tlsHash = live
		}
	}
	return append([]byte(hashPrefix), tlsHash[:]...)
}
