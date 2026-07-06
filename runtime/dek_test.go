package runtime

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

func testDEK() *dek {
	return &dek{key: bytes.Repeat([]byte{0x42}, 32)}
}
