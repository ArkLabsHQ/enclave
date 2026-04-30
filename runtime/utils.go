package runtime

// OTLP protobuf parsers for the telemetry signals the runtime ingests over
// HTTP from the user's app: structured logs (POST /v1/logs) and metrics
// (POST /v1/enclave-metrics). OTLP trace ingest currently lives alongside its
// HTTP handler in tracing_handler.go.

import (
	"fmt"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

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
