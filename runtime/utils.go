package runtime

// Shared runtime helpers.

import (
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
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

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

func anyValueToGo(v *commonpb.AnyValue) any {
	if v == nil {
		return nil
	}
	switch val := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return val.StringValue
	case *commonpb.AnyValue_IntValue:
		return val.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return val.DoubleValue
	case *commonpb.AnyValue_BoolValue:
		return val.BoolValue
	case *commonpb.AnyValue_BytesValue:
		return fmt.Sprintf("%x", val.BytesValue)
	case *commonpb.AnyValue_ArrayValue:
		if val.ArrayValue == nil {
			return nil
		}
		result := make([]any, len(val.ArrayValue.Values))
		for i, item := range val.ArrayValue.Values {
			result[i] = anyValueToGo(item)
		}
		return result
	case *commonpb.AnyValue_KvlistValue:
		if val.KvlistValue == nil {
			return nil
		}
		result := make(map[string]any, len(val.KvlistValue.Values))
		for _, kv := range val.KvlistValue.Values {
			result[kv.Key] = anyValueToGo(kv.Value)
		}
		return result
	default:
		return nil
	}
}

func anyValueToString(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch val := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return val.StringValue
	default:
		return fmt.Sprintf("%v", anyValueToGo(v))
	}
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
