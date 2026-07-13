package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3cmd "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"golang.org/x/crypto/acme/autocert"
)

// acmeStoragePrefix namespaces ACME cache entries in the app S3 bucket.
const acmeStoragePrefix = "data/acme/"

// acmeStorageCache stores autocert material encrypted with the storage DEK in S3.
type acmeStorageCache struct {
	s3     S3API
	dek    DEK
	bucket string
}

func NewAcmeStorageCache(ctx context.Context, s3 S3API, dek DEK, ssm SSM) (autocert.Cache, error) {
	bucketParam := fmt.Sprintf("/%s/%s/StorageBucketName", getDeployment(), getAppName())
	bucketName, err := ssm.MustGet(ctx, bucketParam)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage bucket name SSM param: %w", err)
	}
	return &acmeStorageCache{s3: s3, dek: dek, bucket: bucketName}, nil
}

// Get returns the cached value for key, or autocert.ErrCacheMiss.
func (c *acmeStorageCache) Get(ctx context.Context, key string) ([]byte, error) {
	key = prefixAcmeCacheKey(key)

	out, err := c.s3.GetObject(ctx, &s3cmd.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchKey" {
			return nil, autocert.ErrCacheMiss
		}
		return nil, fmt.Errorf("S3 get: %w", err)
	}
	defer func() { _ = out.Body.Close() }()

	blob, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("read S3 object: %w", err)
	}

	plaintext, err := c.dek.Open(blob, []byte(key))
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Put encrypts and stores data under key.
func (c *acmeStorageCache) Put(ctx context.Context, key string, data []byte) error {
	key = prefixAcmeCacheKey(key)

	blob, err := c.dek.Seal(data, []byte(key))
	if err != nil {
		return err
	}

	_, err = c.s3.PutObject(ctx, &s3cmd.PutObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(blob),
	})
	if err != nil {
		return fmt.Errorf("S3 put: %w", err)
	}
	return nil
}

// Delete removes key from the cache.
func (c *acmeStorageCache) Delete(ctx context.Context, key string) error {
	key = prefixAcmeCacheKey(key)

	_, err := c.s3.DeleteObject(ctx, &s3cmd.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("S3 delete: %w", err)
	}
	return nil
}

func prefixAcmeCacheKey(key string) string {
	return getDeployment() + "/" + getAppName() + acmeStoragePrefix + key
}
