package runtime

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Storage blob layout: storageFormatV1 || nonce || ct+tag.
const (
	// nonceSize is the AES-GCM nonce length.
	nonceSize = 12

	// storageFormatV1 prefixes AAD-bound blobs.
	storageFormatV1 byte = 0x01

	// gcmTagSize is the AES-GCM tag length.
	gcmTagSize = 16

	// storageHeaderLen is the plaintext-independent prefix: version byte + nonce.
	storageHeaderLen = 1 + nonceSize

	// minStorageBlobLen is header plus GCM tag.
	minStorageBlobLen = storageHeaderLen + gcmTagSize
)

type dek struct {
	key []byte
}

type DEK interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(blob, aad []byte) ([]byte, error)
	ExportKey(ctx context.Context, kms KMS, ssm SSM) (string, error)
}

// ExportKey stores this DEK encrypted under kms, then verifies round-trip.
func (d *dek) ExportKey(ctx context.Context, kms KMS, ssm SSM) (string, error) {
	ciphertextB64, err := kms.Encrypt(ctx, d.key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt DEK under provided KMS: %w", err)
	}

	dekParam := storageDEKCiphertextParam(kms.KeyID())

	if err := ssm.Set(ctx, dekParam, ciphertextB64); err != nil {
		return "", fmt.Errorf("encrypt DEK with migration key: %w", err)
	}

	decrypted, err := kms.Decrypt(ctx, ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("verify DEK re-encryption: %w", err)
	}

	if !bytes.Equal(decrypted, d.key) {
		return "", fmt.Errorf("verify DEK re-encryption: plaintext mismatch")
	}

	return ciphertextB64, nil
}

// Seal encrypts plaintext with aad as v1: version || nonce || ct+tag.
func (d *dek) Seal(plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(d.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := secureRandom(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)

	blob := make([]byte, 0, storageHeaderLen+len(ct))
	blob = append(blob, storageFormatV1)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)

	return blob, nil
}

// Open decrypts v1 blobs and rejects wrong aad, legacy, or short blobs.
func (d *dek) Open(blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(d.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if len(blob) < minStorageBlobLen || blob[0] != storageFormatV1 {
		return nil, fmt.Errorf("corrupt or unversioned storage object")
	}
	nonce := blob[1:storageHeaderLen]
	ct := blob[storageHeaderLen:]

	plaintext, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
