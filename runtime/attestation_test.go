package runtime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttestationUserData(t *testing.T) {
	const (
		sha256TagHex  = "7368613235363a"   // "sha256:"
		ed25519TagHex = "656432353531393a" // "ed25519:"
		zeroHex       = "0000000000000000000000000000000000000000000000000000000000000000"
		tlsHashHex    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		signingKeyHex = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
	)

	var tlsKeyHash [sha256.Size]byte
	for i := range tlsKeyHash {
		tlsKeyHash[i] = 0xff
	}
	signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

	for _, tc := range []struct {
		name       string
		tlsKeyHash *[sha256.Size]byte
		signingKey ed25519.PrivateKey
		wantHex    string
	}{
		{
			name:    "zero value",
			wantHex: sha256TagHex + zeroHex + ed25519TagHex + zeroHex,
		},
		{
			name:       "TLS hash only",
			tlsKeyHash: &tlsKeyHash,
			wantHex:    sha256TagHex + tlsHashHex + ed25519TagHex + zeroHex,
		},
		{
			name:       "Signing key only",
			signingKey: signingKey,
			wantHex:    sha256TagHex + zeroHex + ed25519TagHex + signingKeyHex,
		},
		{
			name:       "TLS hash and signing key",
			tlsKeyHash: &tlsKeyHash,
			signingKey: signingKey,
			wantHex:    sha256TagHex + tlsHashHex + ed25519TagHex + signingKeyHex,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &AttestationHashes{}
			if tc.tlsKeyHash != nil {
				h.SetTLSKeyHashSource(staticKeyHash(*tc.tlsKeyHash))
			}
			if tc.signingKey != nil {
				h.SetResponseSigningKey(tc.signingKey)
			}

			got := h.Serialize()
			// Clients slice the fixed-width wire format by offset.
			require.Len(t, got, 79)
			require.Equal(t, tc.wantHex, hex.EncodeToString(got))
		})
	}
}

// staticKeyHash is the source for a certificate that never changes.
func staticKeyHash(h [sha256.Size]byte) TLSKeyHashFunc {
	return func() ([sha256.Size]byte, bool) { return h, true }
}
