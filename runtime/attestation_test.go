package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
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
			h := &AttestationData{}
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

func TestAttestationUserDataDisclosesMigration(t *testing.T) {
	const (
		cooldownTagHex = "636f6f6c646f776e3a" // "cooldown:"
		pcr0TagHex     = "706372303a"         // "pcr0:"
	)
	ctx := context.Background()
	h := &AttestationData{}
	_, err := h.UserData(ctx)
	require.Error(t, err, "no source yet: the pending migration is unknown")

	target := [sha512.Size384]byte{0xaa, 47: 0xbb}
	h.SetMigrationSource(staticMigrationStatus(&MigrationStatus{
		State:            migrationStateCoolingDown,
		TargetPCR0:       hex.EncodeToString(target[:]),
		RemainingSeconds: 86400,
	}, nil))
	got, err := h.UserData(ctx)
	require.NoError(t, err)
	// Clients slice the fixed-width wire format by offset.
	require.Len(t, got, 149)
	require.Equal(t, h.Serialize(), got[:79])
	require.Equal(t,
		cooldownTagHex+"0000000000015180"+pcr0TagHex+hex.EncodeToString(target[:]),
		hex.EncodeToString(got[79:]), "the cooldown left in seconds, then the target")

	h.SetMigrationSource(staticMigrationStatus(nil, errors.New("intent log unavailable")))
	_, err = h.UserData(ctx)
	require.ErrorContains(t, err, "intent log unavailable")
}

// staticKeyHash is the source for a certificate that never changes.
func staticKeyHash(h [sha256.Size]byte) TLSKeyHashFunc {
	return func() ([sha256.Size]byte, bool) { return h, true }
}

// staticMigrationStatus is a migration source that always reports status, or err.
func staticMigrationStatus(status *MigrationStatus, err error) MigrationStatusFunc {
	return func(context.Context) (*MigrationStatus, error) { return status, err }
}
