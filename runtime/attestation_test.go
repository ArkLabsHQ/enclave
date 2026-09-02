package runtime

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttestationUserData(t *testing.T) {
	t.Run("zero value serializes fixed user_data format", func(t *testing.T) {
		h := &AttestationHashes{}

		var zero [sha256.Size]byte
		want := append([]byte(hashPrefix), zero[:]...)

		require.Equal(t, want, h.Serialize())
	})

	t.Run("set hash serializes exact raw bytes", func(t *testing.T) {
		h := &AttestationHashes{}
		var tlsHash [sha256.Size]byte
		for i := range tlsHash {
			tlsHash[i] = byte(i)
		}

		h.SetTLSKeyHashSource(staticKeyHash(tlsHash))

		want := append([]byte(hashPrefix), tlsHash[:]...)

		require.Equal(t, want, h.Serialize())
	})

	// The wire format is fixed-width and clients slice it by offset, so its
	// length is part of the contract.
	t.Run("user_data is 39 bytes", func(t *testing.T) {
		h := &AttestationHashes{}
		h.SetTLSKeyHashSource(staticKeyHash(sha256.Sum256([]byte("leaf"))))

		require.Len(t, h.Serialize(), 39)
	})
}

// staticKeyHash is the source for a certificate that never changes.
func staticKeyHash(h [sha256.Size]byte) TLSKeyHashFunc {
	return func() ([sha256.Size]byte, bool) { return h, true }
}
