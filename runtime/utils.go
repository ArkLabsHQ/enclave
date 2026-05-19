package runtime

// OTLP protobuf parsers for the telemetry signals the runtime ingests over
// HTTP from the user's app: structured logs (POST /v1/logs) and metrics
// (POST /v1/metrics). OTLP trace ingest lives alongside its handler in
// tracing.go.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/hf/nsm"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// =============================================================================
// Random source
// =============================================================================

// generateRuntimeToken returns a 32-byte hex-encoded bearer token used to
// authenticate calls to the admin /v1/* endpoints.
func generateRuntimeToken() (string, error) {
	b := make([]byte, 32)
	if _, err := secureRandom(b); err != nil {
		return "", fmt.Errorf("secure random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// secureRandom prefers the NSM hardware RNG when running inside an
// enclave and falls back to crypto/rand otherwise. Inside an enclave
// crypto/rand depends on a starved kernel entropy pool (no disk, no
// network, no HID — only RDRAND), so the NSM RNG is the only fully
// trustworthy source. If /dev/nsm opens but GetRandom fails the error
// surfaces rather than silently falling back to the weak pool.
func secureRandom(b []byte) (int, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return rand.Read(b)
	}
	defer func() { _ = session.Close() }()
	return session.Read(b)
}

// anyValueToGo converts an OTLP AnyValue to a Go value.
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

// anyValueToString extracts a string representation from an AnyValue.
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
