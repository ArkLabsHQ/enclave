package runtime

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDEKSealOpen(t *testing.T) {
	d := testDEK()
	aad := []byte("deployment/app/storage/key")
	plaintext := []byte("hello enclave")

	blob, err := d.Seal(plaintext, aad)
	require.NoError(t, err)
	require.Equal(t, storageFormatV1, blob[0])
	require.Len(t, blob, storageHeaderLen+len(plaintext)+gcmTagSize)

	got, err := d.Open(blob, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestDEKOpenRejectsInvalidBlob(t *testing.T) {
	d := testDEK()
	aad := []byte("deployment/app/storage/key")

	blob, err := d.Seal([]byte("secret"), aad)
	require.NoError(t, err)

	t.Run("wrong aad", func(t *testing.T) {
		_, err := d.Open(blob, []byte("deployment/app/storage/other-key"))
		require.Error(t, err)
	})

	t.Run("wrong dek", func(t *testing.T) {
		other := &dek{key: bytes.Repeat([]byte{0x99}, 32)}
		_, err := other.Open(blob, aad)
		require.Error(t, err)
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		tampered := append([]byte(nil), blob...)
		tampered[len(tampered)-1] ^= 0xff

		_, err := d.Open(tampered, aad)
		require.Error(t, err)
	})

	t.Run("wrong version", func(t *testing.T) {
		tampered := append([]byte(nil), blob...)
		tampered[0] = 0x02

		_, err := d.Open(tampered, aad)
		require.Error(t, err)
	})

	t.Run("short blob", func(t *testing.T) {
		for _, short := range [][]byte{
			nil,
			{storageFormatV1},
			make([]byte, minStorageBlobLen-1),
		} {
			_, err := d.Open(short, aad)
			require.Error(t, err)
		}
	})

	t.Run("legacy unversioned blob", func(t *testing.T) {
		block, err := aes.NewCipher(d.key)
		require.NoError(t, err)
		gcm, err := cipher.NewGCM(block)
		require.NoError(t, err)

		nonce := make([]byte, nonceSize)
		legacy := append(nonce, gcm.Seal(nil, nonce, []byte("old"), nil)...)

		_, err = d.Open(legacy, aad)
		require.Error(t, err)
	})
}

// Replicas and restarts share a signing key, but migration must change it even
// though the successor inherits the same DEK.
func TestDEKResponseSigningKey(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xab}, 48)
	a, err := testDEK().ResponseSigningKey(pcr0)
	require.NoError(t, err)
	b, err := testDEK().ResponseSigningKey(bytes.Clone(pcr0))
	require.NoError(t, err)
	require.Equal(t, a, b)

	other, err := (&dek{key: bytes.Repeat([]byte{0x99}, 32)}).ResponseSigningKey(pcr0)
	require.NoError(t, err)
	require.NotEqual(t, a, other)

	successorPCR0 := bytes.Clone(pcr0)
	successorPCR0[len(successorPCR0)-1] ^= 1
	successor, err := testDEK().ResponseSigningKey(successorPCR0)
	require.NoError(t, err)
	require.NotEqual(t, a.Public(), successor.Public())

	message := []byte("response to a fresh client nonce")
	predecessorSignature := ed25519.Sign(a, message)
	require.True(t, ed25519.Verify(b.Public().(ed25519.PublicKey), message, predecessorSignature))
	successorPublicKey := successor.Public().(ed25519.PublicKey)
	require.False(t, ed25519.Verify(successorPublicKey, message, predecessorSignature))
}

func TestDEKResponseSigningKeyRejectsInvalidPCR0(t *testing.T) {
	for _, size := range []int{0, 47, 49} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			key, err := testDEK().ResponseSigningKey(make([]byte, size))
			require.ErrorContains(t, err, "PCR0 must be exactly 48 bytes")
			require.Nil(t, key)
		})
	}
}

func testDEK() *dek {
	return &dek{key: bytes.Repeat([]byte{0x42}, 32)}
}

func TestDEKExportKeyStoresExactlyWhatItReturns(t *testing.T) {
	d := testDEK()
	kmsf := newFakeKMS()
	successor := &kmsW{
		cfg:   testCfg,
		nsm:   kmsTestNSMWithRecipient(t),
		kms:   kmsf,
		keyID: "successor-key",
	}
	ssmf := &fakeSSM{}

	ciphertext, err := d.ExportKey(context.Background(), testCfg, successor, NewSSM(ssmf))

	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	require.Equal(t, ciphertext, ssmf.params[testCfg.storageDEKCiphertextParam("successor-key")])
}
