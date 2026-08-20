package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestAttestationUserData(t *testing.T) {
	t.Run("zero value serializes fixed user_data format", func(t *testing.T) {
		h := &AttestationHashes{}

		var zero [sha256.Size]byte
		want := append([]byte(hashPrefix), zero[:]...)
		want = append(want, hashSeparator...)
		want = append(want, hashPrefix...)
		want = append(want, zero[:]...)

		require.Equal(t, want, h.Serialize())
	})

	t.Run("set hashes serialize exact raw bytes", func(t *testing.T) {
		h := &AttestationHashes{}
		var tlsHash, signingHash [sha256.Size]byte
		for i := range tlsHash {
			tlsHash[i] = byte(i)
			signingHash[i] = byte(sha256.Size - i)
		}

		h.SetTLSKeyHashSource(staticKeyHash(tlsHash))
		h.SetSigningKeyHash(signingHash)

		want := append([]byte(hashPrefix), tlsHash[:]...)
		want = append(want, hashSeparator...)
		want = append(want, hashPrefix...)
		want = append(want, signingHash[:]...)

		require.Equal(t, want, h.Serialize())
	})

	// The wire format is fixed-width and clients slice it by offset, so its
	// length is part of the contract.
	t.Run("user_data is 79 bytes", func(t *testing.T) {
		h := &AttestationHashes{}
		h.SetTLSKeyHashSource(staticKeyHash(sha256.Sum256([]byte("leaf"))))

		require.Len(t, h.Serialize(), 79)
	})
}

func TestAttestationSigner(t *testing.T) {
	signer, err := NewAttestedSigner()
	require.NoError(t, err)

	pubkeyBytes, err := hex.DecodeString(signer.Pubkey())
	require.NoError(t, err)
	require.Len(t, pubkeyBytes, 33)

	pubkey, err := btcec.ParsePubKey(pubkeyBytes)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(pubkeyBytes), signer.PubkeyHash())

	body := []byte("attested response")
	sigBytes, err := hex.DecodeString(signer.Sign(body))
	require.NoError(t, err)
	sig, err := schnorr.ParseSignature(sigBytes)
	require.NoError(t, err)

	bodyHash := sha256.Sum256(body)
	require.True(t, sig.Verify(bodyHash[:], pubkey))
}
