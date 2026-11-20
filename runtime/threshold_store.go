package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// thresholdStoragePrefix keeps threshold-scaling state beside the certificates.
const thresholdStoragePrefix = "data/"

// ErrNotFound is returned by thresholdStore.Load when a name has no object.
var ErrNotFound = errors.New("not found")

// thresholdStore keeps this node's threshold-scaling state (its shares, the
// SDK's recovery blobs and the leader's ban list) in the certificate bucket,
// sealed with the storage DEK the way certStore seals certificates.
type thresholdStore struct {
	cfg    *Config
	s3     S3API
	dek    DEK
	bucket string
}

func (s *thresholdStore) Load(ctx context.Context, name string) ([]byte, error) {
	key := s.key(name)
	out, err := s.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNoSuchKey(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get %q: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()

	sealed, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", key, err)
	}
	plaintext, err := s.dek.Open(sealed, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", key, err)
	}
	return plaintext, nil
}

func (s *thresholdStore) Store(ctx context.Context, name string, blob []byte) error {
	key := s.key(name)
	sealed, err := s.dek.Seal(blob, []byte(key))
	if err != nil {
		return err
	}
	if _, err := s.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(sealed),
	}); err != nil {
		return fmt.Errorf("put %q: %w", key, err)
	}
	return nil
}

// List returns the stored names that start with prefix.
func (s *thresholdStore) List(ctx context.Context, prefix string) ([]string, error) {
	root := s.key("")
	var names []string
	pages := s3.NewListObjectsV2Paginator(s.s3, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(root + prefix),
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list %q: %w", root+prefix, err)
		}
		for _, obj := range page.Contents {
			names = append(names, strings.TrimPrefix(aws.ToString(obj.Key), root))
		}
	}
	return names, nil
}

func (s *thresholdStore) key(name string) string {
	return objectKeyFor(s.cfg, thresholdStoragePrefix, name)
}
