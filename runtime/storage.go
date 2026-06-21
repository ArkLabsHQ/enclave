package runtime

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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

// Storage owns the encrypted persistent K/V store backed by S3 and a single
// AES-256 DEK. The DEK lives only in process memory; it's KMS-decrypted at
// boot from a ciphertext stored in SSM. All Store/Load/Delete operations
// transparently AES-GCM encrypt/decrypt against the DEK.
//
// Each object's AAD binds it to its (deployment, app, key) location (see
// storageAAD), so a host cannot relabel/swap ciphertext between keys or replay
// it across deployments — the GCM tag check fails on Load. Not yet defended:
// rollback/replay of an *older* value of the same key, and deletion (a removed
// object is indistinguishable from a never-written one). Both need a versioned
// manifest with an external monotonic anchor (issue #134, Tier 1/2).
type Storage struct {
	bucketName string
	dek        []byte
	kms        *KMS
	metrics    *Metrics
	auth       func(http.ResponseWriter, *http.Request) bool
}

// NewStorage constructs the storage subsystem. kms is required for Init();
// metrics may be nil. auth is the bearer-token check; nil = no auth.
// Init-state gating is handled by Runtime middleware applied during
// RegisterRoutes — handlers don't check init themselves.
func NewStorage(kms *KMS, metrics *Metrics, auth func(http.ResponseWriter, *http.Request) bool) *Storage {
	return &Storage{
		kms:     kms,
		metrics: metrics,
		auth:    auth,
	}
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
		// First boot for this KMS key: generate a new DEK.
		out, err := s.kms.aws.KMS.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId:   aws.String(keyID),
			KeySpec: kmstypes.DataKeySpecAes256,
		})
		if err != nil {
			return fmt.Errorf("generate DEK: %w", err)
		}
		s.dek = out.Plaintext

		encoded := base64.StdEncoding.EncodeToString(out.CiphertextBlob)
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
	if s.metrics != nil {
		s.metrics.Inc(s.metrics.StorageWrites, "storage_writes_total")
	}
	if s.dek == nil {
		if s.metrics != nil {
			s.metrics.Inc(s.metrics.StorageErrors, "storage_errors_total")
		}
		return fmt.Errorf("storage not initialized")
	}

	blob, err := sealStorage(s.dek, data, storageAAD(key))
	if err != nil {
		if s.metrics != nil {
			s.metrics.Inc(s.metrics.StorageErrors, "storage_errors_total")
		}
		return err
	}

	_, err = s.kms.aws.S3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String("data/" + key),
		Body:   bytes.NewReader(blob),
	})
	if err != nil {
		if s.metrics != nil {
			s.metrics.Inc(s.metrics.StorageErrors, "storage_errors_total")
		}
		return fmt.Errorf("S3 put: %w", err)
	}
	return nil
}

// Load retrieves and decrypts data from S3. Returns ErrNotFound if missing.
func (s *Storage) Load(ctx context.Context, key string) ([]byte, error) {
	if s.metrics != nil {
		s.metrics.Inc(s.metrics.StorageReads, "storage_reads_total")
	}
	if s.dek == nil {
		if s.metrics != nil {
			s.metrics.Inc(s.metrics.StorageErrors, "storage_errors_total")
		}
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
		if s.metrics != nil {
			s.metrics.Inc(s.metrics.StorageErrors, "storage_errors_total")
		}
		return nil, err
	}
	return plaintext, nil
}

// Delete removes a key from storage.
func (s *Storage) Delete(ctx context.Context, key string) error {
	if s.metrics != nil {
		s.metrics.Inc(s.metrics.StorageDeletes, "storage_deletes_total")
	}
	if s.bucketName == "" {
		if s.metrics != nil {
			s.metrics.Inc(s.metrics.StorageErrors, "storage_errors_total")
		}
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

// List returns keys under the given prefix in storage.
func (s *Storage) List(ctx context.Context, prefix string) ([]string, error) {
	if s.bucketName == "" {
		return nil, fmt.Errorf("storage not initialized")
	}

	s3Prefix := "data/" + prefix
	var keys []string
	var continuationToken *string

	for {
		out, err := s.kms.aws.S3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.bucketName),
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

// =============================================================================
// HTTP handlers
// =============================================================================

// RegisterRoutes attaches the storage endpoints on mux.
func (s *Storage) RegisterRoutes(mux Mux) {
	mux.HandleFunc("PUT /v1/storage/{key...}", s.handlePut)
	mux.HandleFunc("GET /v1/storage/{key...}", s.handleGet)
	mux.HandleFunc("DELETE /v1/storage/{key...}", s.handleDelete)
	mux.HandleFunc("GET /v1/storage", s.handleList)
}

// handlePut handles PUT /v1/storage/{key...}. The body is stored as raw bytes.
func (s *Storage) handlePut(w http.ResponseWriter, r *http.Request) {
	if s.auth != nil && !s.auth(w, r) {
		return
	}

	key := r.PathValue("key")
	if key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(key, "secrets/") {
		http.Error(w, "use /v1/secrets endpoints for secret management", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(key, "acme/") {
		http.Error(w, "the acme/ namespace is reserved for the TLS cert cache", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	if err := s.Store(r.Context(), key, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Key    string `json:"key"`
		Status string `json:"status"`
	}{Key: key, Status: "stored"})
}

// handleGet handles GET /v1/storage/{key...}. Returns raw decrypted bytes.
func (s *Storage) handleGet(w http.ResponseWriter, r *http.Request) {
	if s.auth != nil && !s.auth(w, r) {
		return
	}

	key := r.PathValue("key")
	if key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(key, "secrets/") {
		http.Error(w, "use /v1/secrets endpoints for secret management", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(key, "acme/") {
		http.Error(w, "the acme/ namespace is reserved for the TLS cert cache", http.StatusBadRequest)
		return
	}

	data, err := s.Load(r.Context(), key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

// handleDelete handles DELETE /v1/storage/{key...}.
func (s *Storage) handleDelete(w http.ResponseWriter, r *http.Request) {
	if s.auth != nil && !s.auth(w, r) {
		return
	}

	key := r.PathValue("key")
	if key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(key, "secrets/") {
		http.Error(w, "use /v1/secrets endpoints for secret management", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(key, "acme/") {
		http.Error(w, "the acme/ namespace is reserved for the TLS cert cache", http.StatusBadRequest)
		return
	}

	if err := s.Delete(r.Context(), key); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Key    string `json:"key"`
		Status string `json:"status"`
	}{Key: key, Status: "deleted"})
}

// handleList handles GET /v1/storage?prefix=...
func (s *Storage) handleList(w http.ResponseWriter, r *http.Request) {
	if s.auth != nil && !s.auth(w, r) {
		return
	}

	prefix := r.URL.Query().Get("prefix")

	keys, err := s.List(r.Context(), prefix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if keys == nil {
		keys = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(keys)
}

// silenceUnused references unused imports during transitional compile passes.
var _ = slog.Info
