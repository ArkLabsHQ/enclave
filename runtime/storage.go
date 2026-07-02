package runtime

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/hf/nsm"
)

// ErrNotFound is returned by Load when the key does not exist.
var ErrNotFound = errors.New("key not found")

// nonceSize is the AES-GCM nonce length.
const nonceSize = 12

// Storage blob layout: storageFormatV1 || nonce || ct+tag.
const (
	// storageFormatV1 is the version prefix of an AAD-bound storage blob. It
	// distinguishes the current format from any future one and lets Load reject
	// unversioned (legacy nil-AAD) objects.
	storageFormatV1 byte = 0x01

	// gcmTagSize is the AES-GCM authentication tag length appended by Seal;
	// it always equals cipher.AEAD.Overhead() for standard GCM.
	gcmTagSize = 16

	// storageHeaderLen is the plaintext-independent prefix: version byte + nonce.
	storageHeaderLen = 1 + nonceSize

	// minStorageBlobLen is the smallest valid v1 blob — the header plus a tag,
	// i.e. an envelope wrapping empty plaintext. Anything shorter is corrupt.
	minStorageBlobLen = storageHeaderLen + gcmTagSize
)

// =============================================================================
// Storage subsystem
// =============================================================================

// Storage is the AES-256-GCM encrypted S3 store backing the ACME TLS-cert cache
// (acme_cache.go); Store/Load/Delete AAD-bind each object to its (deployment,
// app, key) location. The DEK is shared with the K/V store.
type Storage struct {
	bucketName string
	dek        []byte
	kms        *KMS
}

// NewStorage constructs the storage subsystem. kms is required for Init().
func NewStorage(kms *KMS) *Storage {
	return &Storage{kms: kms}
}

// HasDEK reports whether the DEK is loaded (storage is operational).
func (s *Storage) HasDEK() bool { return s != nil && s.dek != nil }

// DEK returns the in-memory DEK (used by Migration.exportStorageDEK).
func (s *Storage) DEK() []byte { return s.dek }

// Init loads (or, on the first boot for keyID, generates) the storage DEK from
// its key-scoped SSM path. If no bucket is provisioned (StorageBucketName param
// missing), storage is silently disabled and Store/Load/Delete return errors.
func (s *Storage) Init(ctx context.Context, keyID string) error {
	deployment := getDeployment()
	appName := getAppName()

	// Read bucket name — if not provisioned, storage is disabled.
	bucketName, err := readSSMParam(ctx, s.kms.aws.SSM, fmt.Sprintf("/%s/%s/StorageBucketName", deployment, appName))
	if err != nil {
		return nil // no bucket provisioned, storage disabled
	}
	s.bucketName = bucketName

	dekParam := storageDEKCiphertextParam(keyID)

	ciphertextB64, err := s.kms.LoadCiphertext(ctx, dekParam)
	if err != nil {
		return fmt.Errorf("load DEK from SSM: %w", err)
	}

	if ciphertextB64 == "" {
		// First boot for this KMS key: generate a new DEK. For a locked
		// deployment generateDataKey mints it attested, satisfying the
		// PCR0-gated policy.
		ciphertextBlob, dek, err := s.kms.generateDataKey(ctx, keyID)
		if err != nil {
			return fmt.Errorf("generate DEK: %w", err)
		}
		s.dek = dek

		encoded := base64.StdEncoding.EncodeToString(ciphertextBlob)
		if err := s.kms.StoreCiphertext(ctx, dekParam, encoded); err != nil {
			return fmt.Errorf("store DEK: %w", err)
		}
		return nil
	}

	// Subsequent boot: decrypt existing DEK.
	dek, err := decryptDEK(ctx, s.kms.aws.KMS, keyID, ciphertextB64)
	if err != nil {
		return fmt.Errorf("decrypt DEK: %w", err)
	}
	s.dek = dek
	return nil
}

// ExportDEK re-encrypts the DEK under migrationKeyID into its key-scoped SSM
// path, then verifies by decrypting the result and comparing to the live DEK.
func (s *Storage) ExportDEK(ctx context.Context, migrationKeyID string) error {
	if s.dek == nil {
		return nil
	}
	ciphertextB64, err := s.kms.Encrypt(ctx, migrationKeyID, s.dek)
	if err != nil {
		return fmt.Errorf("encrypt DEK with migration key: %w", err)
	}
	dekParam := storageDEKCiphertextParam(migrationKeyID)
	if err := s.kms.StoreCiphertext(ctx, dekParam, ciphertextB64); err != nil {
		return err
	}
	// Verify: decrypt the stored ciphertext and confirm it matches the in-memory DEK.
	decrypted, err := decryptDEK(ctx, s.kms.aws.KMS, migrationKeyID, ciphertextB64)
	if err != nil {
		return fmt.Errorf("verify DEK re-encryption: %w", err)
	}
	if !bytes.Equal(decrypted, s.dek) {
		return fmt.Errorf("verify DEK re-encryption: plaintext mismatch")
	}
	return nil
}

// decryptDEK decrypts a base64-encoded KMS ciphertext using NSM attestation.
// Retries up to 3 times with exponential backoff on transient failures.
func decryptDEK(ctx context.Context, kmsClient KMSAPI, keyID, ciphertextB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}

		session, err := nsm.OpenDefaultSession()
		if err != nil {
			lastErr = fmt.Errorf("open NSM session: %w", err)
			continue
		}

		attestationDoc, rsaPrivateKey, err := buildAttestationDocument(session)
		_ = session.Close()
		if err != nil {
			lastErr = err
			continue
		}

		input := &kms.DecryptInput{
			KeyId:          aws.String(keyID),
			CiphertextBlob: ciphertext,
			Recipient: &kmstypes.RecipientInfo{
				AttestationDocument:    attestationDoc,
				KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
			},
		}

		out, err := kmsClient.Decrypt(ctx, input)
		if err != nil {
			lastErr = fmt.Errorf("kms decrypt: %w", err)
			continue
		}
		if len(out.CiphertextForRecipient) == 0 {
			lastErr = fmt.Errorf("kms decrypt returned empty CiphertextForRecipient")
			continue
		}
		plaintext, err := cms.DecryptEnvelopedKey(rsaPrivateKey, out.CiphertextForRecipient)
		if err != nil {
			lastErr = fmt.Errorf("decrypt CiphertextForRecipient: %w", err)
			continue
		}
		return plaintext, nil
	}
	return nil, fmt.Errorf("KMS decrypt failed after 3 attempts: %w", lastErr)
}

// storageAAD binds a blob to its (deployment, app, key) location, mirroring the
// S3 object key ("data/"+key). Sealing under it makes relabel/swap and
// cross-deployment replay fail the GCM tag check on Load.
func storageAAD(key string) []byte {
	return []byte(getDeployment() + "/" + getAppName() + "/data/" + key)
}

// sealStorage AES-256-GCM-seals plaintext under dek, authenticating aad, and
// returns the v1 envelope: storageFormatV1 || nonce || ct+tag.
func sealStorage(dek, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
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

// openStorage decrypts a v1 storage blob, requiring the version prefix and the
// matching aad. Unversioned (legacy nil-AAD) or short objects are rejected.
func openStorage(dek, blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
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

// Store encrypts data with the DEK and persists it to S3.
func (s *Storage) Store(ctx context.Context, key string, data []byte) error {
	if s.dek == nil {
		return fmt.Errorf("storage not initialized")
	}

	blob, err := sealStorage(s.dek, data, storageAAD(key))
	if err != nil {
		return err
	}

	_, err = s.kms.aws.S3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String("data/" + key),
		Body:   bytes.NewReader(blob),
	})
	if err != nil {
		return fmt.Errorf("S3 put: %w", err)
	}
	return nil
}

// Load retrieves and decrypts data from S3. Returns ErrNotFound if missing.
func (s *Storage) Load(ctx context.Context, key string) ([]byte, error) {
	if s.dek == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	out, err := s.kms.aws.S3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String("data/" + key),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("S3 get: %w", err)
	}
	defer func() { _ = out.Body.Close() }()

	blob, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("read S3 object: %w", err)
	}

	plaintext, err := openStorage(s.dek, blob, storageAAD(key))
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Delete removes a key from storage.
func (s *Storage) Delete(ctx context.Context, key string) error {
	if s.bucketName == "" {
		return fmt.Errorf("storage not initialized")
	}

	_, err := s.kms.aws.S3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String("data/" + key),
	})
	if err != nil {
		return fmt.Errorf("S3 delete: %w", err)
	}
	return nil
}
