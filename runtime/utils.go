package runtime

// Shared runtime helpers.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hf/nsm"
)

func verifyAttestationUserData(
	nsm NSM,
	attestDocB64 string,
	expectedPCRs map[uint]string,
	expectedUserData []byte,
) error {
	result, err := nsm.VerifyAttestationDocument(attestDocB64, expectedPCRs)
	if err != nil {
		return err
	}
	if !bytes.Equal(result.Document.UserData, expectedUserData) {
		return fmt.Errorf("attested user data does not match expected user data")
	}
	return nil
}

// envMu serializes process env writes.
var envMu sync.Mutex

// safeSetenv wraps os.Setenv under envMu to prevent concurrent env mutations.
func safeSetenv(key, value string) error {
	envMu.Lock()
	defer envMu.Unlock()
	return os.Setenv(key, value)
}

// generateRuntimeToken returns a 32-byte hex bearer token.
func generateRuntimeToken() (string, error) {
	b := make([]byte, 32)
	if _, err := secureRandom(b); err != nil {
		return "", fmt.Errorf("secure random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// secureRandom uses NSM RNG when available, else crypto/rand.
func secureRandom(b []byte) (int, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return rand.Read(b)
	}
	defer func() { _ = session.Close() }()
	return session.Read(b)
}

// prefix16 truncates a string to at most 16 characters for less noisy log fields.
func prefix16(s string) string {
	return s[:min(16, len(s))]
}

// forEachObjectVersion pages a versioned listing
func forEachObjectVersion(
	ctx context.Context,
	s3api S3API,
	bucket, prefix string,
	storeErr error,
	what string,
	visit func(key, versionID string, lastModified *time.Time) (stop bool, err error),
) error {
	var keyMarker, versionMarker *string
	for {
		out, err := s3api.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
			Bucket:          aws.String(bucket),
			Prefix:          aws.String(prefix),
			KeyMarker:       keyMarker,
			VersionIdMarker: versionMarker,
		})
		if err != nil {
			return fmt.Errorf("%w: %s: %w", storeErr, what, err)
		}
		for _, version := range out.Versions {
			stop, err := visit(
				aws.ToString(version.Key),
				aws.ToString(version.VersionId),
				version.LastModified,
			)
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return nil
		}
		if out.NextKeyMarker == nil && out.NextVersionIdMarker == nil {
			return fmt.Errorf(
				"%w: %s: truncated response missing markers",
				storeErr,
				what,
			)
		}
		keyMarker, versionMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
}
