package sdk

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"
	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/hf/nsm"
)

// ErrNotFound is returned by Load when the key does not exist.
var ErrNotFound = errors.New("key not found")

// nonceSize is the AES-GCM nonce length.
const nonceSize = 12

// initStorage initializes the encrypted persistent storage subsystem.
// It creates an S3 client, reads the bucket name from SSM, and loads
// (or generates) the data encryption key (DEK).
//
// If no storage bucket is provisioned (StorageBucketName param missing),
// storage is silently disabled — Store/Load/Delete return errors.
func (e *Enclave) initStorage(ctx context.Context) error {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	ssmClient := ssm.NewFromConfig(awsCfg)
	deployment := getDeployment()
	appName := getAppName()

	// Read bucket name — if not provisioned, storage is disabled.
	bucketName, err := readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/StorageBucketName", deployment, appName))
	if err != nil {
		return nil // no bucket provisioned, storage disabled
	}

	e.s3Client = s3.NewFromConfig(awsCfg)
	e.bucketName = bucketName

	kmsClient := kms.NewFromConfig(awsCfg)
	keyID, err := getKMSKeyID(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("get KMS key ID: %w", err)
	}

	// Check for migrated DEK first (from a previous enclave version).
	migParam := fmt.Sprintf("/%s/%s/Migration/StorageDEK/Ciphertext", deployment, appName)
	if migCiphertext, err := loadCiphertextFromSSM(ctx, ssmClient, migParam); err == nil && migCiphertext != "" {
		dek, err := decryptDEK(ctx, kmsClient, keyID, migCiphertext)
		if err != nil {
			return fmt.Errorf("decrypt migrated DEK: %w", err)
		}
		e.dek = dek

		// Adopt: store as primary DEK and clear migration param.
		primaryParam := fmt.Sprintf("/%s/%s/StorageDEK/Ciphertext", deployment, appName)
		reEncrypted, err := encryptWithKMS(ctx, kmsClient, keyID, dek)
		if err != nil {
			return fmt.Errorf("re-encrypt DEK: %w", err)
		}
		if err := storeCiphertextInSSM(ctx, ssmClient, primaryParam, reEncrypted); err != nil {
			return fmt.Errorf("store adopted DEK: %w", err)
		}
		_ = storeCiphertextInSSM(ctx, ssmClient, migParam, "UNSET")
		return nil
	}

	// Load or generate primary DEK.
	primaryParam := fmt.Sprintf("/%s/%s/StorageDEK/Ciphertext", deployment, appName)
	ciphertextB64, err := loadCiphertextFromSSM(ctx, ssmClient, primaryParam)
	if err != nil {
		return fmt.Errorf("load DEK from SSM: %w", err)
	}

	if ciphertextB64 == "" {
		// First boot: generate a new DEK.
		out, err := kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId:   aws.String(keyID),
			KeySpec: kmstypes.DataKeySpecAes256,
		})
		if err != nil {
			return fmt.Errorf("generate DEK: %w", err)
		}
		e.dek = out.Plaintext

		encoded := base64.StdEncoding.EncodeToString(out.CiphertextBlob)
		if err := storeCiphertextInSSM(ctx, ssmClient, primaryParam, encoded); err != nil {
			return fmt.Errorf("store DEK: %w", err)
		}
		return nil
	}

	// Subsequent boot: decrypt existing DEK.
	dek, err := decryptDEK(ctx, kmsClient, keyID, ciphertextB64)
	if err != nil {
		return fmt.Errorf("decrypt DEK: %w", err)
	}
	e.dek = dek
	return nil
}

// decryptDEK decrypts a base64-encoded KMS ciphertext using NSM attestation.
func decryptDEK(ctx context.Context, kmsClient *kms.Client, keyID, ciphertextB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("open NSM session: %w", err)
	}
	defer session.Close()

	attestationDoc, rsaPrivateKey, err := buildAttestationDocument(session)
	if err != nil {
		return nil, err
	}

	out, err := kmsClient.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(keyID),
		CiphertextBlob: ciphertext,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("KMS decrypt: %w", err)
	}

	if len(out.CiphertextForRecipient) == 0 {
		return nil, fmt.Errorf("KMS decrypt returned empty CiphertextForRecipient")
	}

	plaintext, err := cms.DecryptEnvelopedKey(rsaPrivateKey, out.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("decrypt CiphertextForRecipient: %w", err)
	}

	return plaintext, nil
}

// Store encrypts data with the DEK and persists it to S3.
func (e *Enclave) Store(ctx context.Context, key string, data []byte) error {
	if e.dek == nil {
		return fmt.Errorf("storage not initialized")
	}

	block, err := aes.NewCipher(e.dek)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// S3 object: nonce || ciphertext+tag
	blob := make([]byte, 0, nonceSize+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	_, err = e.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e.bucketName),
		Key:    aws.String("data/" + key),
		Body:   bytes.NewReader(blob),
	})
	if err != nil {
		return fmt.Errorf("S3 put: %w", err)
	}
	return nil
}

// Load retrieves and decrypts data from S3.
// Returns ErrNotFound if the key does not exist.
func (e *Enclave) Load(ctx context.Context, key string) ([]byte, error) {
	if e.dek == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	out, err := e.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(e.bucketName),
		Key:    aws.String("data/" + key),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("S3 get: %w", err)
	}
	defer out.Body.Close()

	blob, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("read S3 object: %w", err)
	}

	if len(blob) < nonceSize+1 {
		return nil, fmt.Errorf("corrupt storage object: too short")
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]

	block, err := aes.NewCipher(e.dek)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// Delete removes a key from storage.
func (e *Enclave) Delete(ctx context.Context, key string) error {
	if e.s3Client == nil {
		return fmt.Errorf("storage not initialized")
	}

	_, err := e.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(e.bucketName),
		Key:    aws.String("data/" + key),
	})
	if err != nil {
		return fmt.Errorf("S3 delete: %w", err)
	}
	return nil
}

// List returns keys under the given prefix in storage.
func (e *Enclave) List(ctx context.Context, prefix string) ([]string, error) {
	if e.s3Client == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	s3Prefix := "data/" + prefix
	var keys []string
	var continuationToken *string

	for {
		out, err := e.s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(e.bucketName),
			Prefix:            aws.String(s3Prefix),
			ContinuationToken: continuationToken,
		})
		if err != nil {
			return nil, fmt.Errorf("S3 list: %w", err)
		}

		for _, obj := range out.Contents {
			if obj.Key != nil {
				keys = append(keys, strings.TrimPrefix(*obj.Key, "data/"))
			}
		}

		if !aws.ToBool(out.IsTruncated) {
			break
		}
		continuationToken = out.NextContinuationToken
	}

	return keys, nil
}

// exportStorageDEK re-encrypts the DEK under a migration KMS key and stores
// it in the migration SSM parameter.
func (e *Enclave) exportStorageDEK(ctx context.Context, kmsClient *kms.Client, ssmClient *ssm.Client, migrationKeyID string) error {
	if e.dek == nil {
		return nil // no storage DEK to export
	}

	deployment := getDeployment()
	appName := getAppName()

	ciphertextB64, err := encryptWithKMS(ctx, kmsClient, migrationKeyID, e.dek)
	if err != nil {
		return fmt.Errorf("encrypt DEK with migration key: %w", err)
	}

	migParam := fmt.Sprintf("/%s/%s/Migration/StorageDEK/Ciphertext", deployment, appName)
	return storeCiphertextInSSM(ctx, ssmClient, migParam, ciphertextB64)
}
