package runtime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttestationUserData(t *testing.T) {
	zeroKey := make([]byte, ed25519.PublicKeySize)
	userData := func(tlsHash [sha256.Size]byte, signingKey []byte) []byte {
		ud := append([]byte(hashPrefix), tlsHash[:]...)
		ud = append(ud, signingKeyPrefix...)
		return append(ud, signingKey...)
	}

	t.Run("zero value serializes fixed user_data format", func(t *testing.T) {
		require.Equal(t, userData([sha256.Size]byte{}, zeroKey), (&AttestationHashes{}).Serialize())
	})

	t.Run("set values serialize exact raw bytes", func(t *testing.T) {
		h := &AttestationHashes{}
		var tlsHash [sha256.Size]byte
		for i := range tlsHash {
			tlsHash[i] = byte(i)
		}
		h.SetTLSKeyHashSource(staticKeyHash(tlsHash))
		require.Equal(t, userData(tlsHash, zeroKey), h.Serialize())

		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
		h.SetResponseSigningKey(key)
		require.Equal(t, userData(tlsHash, key.Public().(ed25519.PublicKey)), h.Serialize())
	})

	// The wire format is fixed-width and clients slice it by offset, so its
	// length is part of the contract.
	t.Run("user_data is 79 bytes", func(t *testing.T) {
		h := &AttestationHashes{}
		h.SetTLSKeyHashSource(staticKeyHash(sha256.Sum256([]byte("leaf"))))
		h.SetResponseSigningKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))

		require.Len(t, h.Serialize(), 79)
	})
}

// staticKeyHash is the source for a certificate that never changes.
func staticKeyHash(h [sha256.Size]byte) TLSKeyHashFunc {
	return func() ([sha256.Size]byte, bool) { return h, true }
}
