package runtime

// Shared runtime helpers.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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

// readLockedVersion returns one exact version's body if it is a single-part
// upload retained under compliance mode for the configured period. Any other
// version reports false and is logged as what; a failed read is an error
// wrapping storeErr.
func readLockedVersion(
	ctx context.Context,
	s3api S3API,
	bucket, key, versionID string,
	publishedAt time.Time,
	retention, writeBudget time.Duration,
	storeErr error,
	what string,
) ([]byte, bool, error) {
	out, err := s3api.GetObject(ctx, &s3.GetObjectInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		VersionId:  aws.String(versionID),
		PartNumber: aws.Int32(1), // Exposes res.PartsCount if object was a multipart upload
	})
	if err != nil {
		return nil, false, fmt.Errorf(
			"%w: get %s %q version %q: %w", storeErr, what, key, versionID, err,
		)
	}
	defer func() { _ = out.Body.Close() }()
	// Multipart LastModified dates from upload initiation, so a host could
	// replay a record into an old upload to backdate it.
	if out.PartsCount != nil {
		slog.Warn("ignoring multipart "+what, "key", key, "version", versionID)
		return nil, false, nil
	}
	if !compliesWithObjectLock(what, key, versionID, publishedAt, out, retention, writeBudget) {
		return nil, false, nil
	}
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, false, fmt.Errorf(
			"%w: read %s %q version %q: %w", storeErr, what, key, versionID, err,
		)
	}
	return body, true, nil
}

// compliesWithObjectLock accepts only compliance mode, retained for retention
// after publishedAt less writeBudget, the allowance for upload delay and for skew
// between the writer's clock and S3's LastModified.
func compliesWithObjectLock(
	what, key, versionID string,
	publishedAt time.Time,
	out *s3.GetObjectOutput,
	retention, writeBudget time.Duration,
) bool {
	if out.ObjectLockMode != s3types.ObjectLockModeCompliance {
		slog.Warn("ignoring "+what+" that is not retained under compliance mode",
			"key", key, "version", versionID, "mode", string(out.ObjectLockMode))
		return false
	}

	retainUntil := aws.ToTime(out.ObjectLockRetainUntilDate)
	minimum := retention - writeBudget
	if retainUntil.IsZero() || retainUntil.Before(publishedAt.Add(minimum)) {
		slog.Warn("ignoring "+what+" retained for less than the configured period",
			"key", key, "version", versionID,
			"retained_for", retainUntil.Sub(publishedAt), "minimum", minimum)
		return false
	}
	return true
}
