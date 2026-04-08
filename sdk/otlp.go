package sdk

import (
	"fmt"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"
)

// parseOTLPLogs parses an OTLP ExportLogsServiceRequest protobuf body
// and converts it to internal LogEntry format.
func parseOTLPLogs(body []byte) ([]LogEntry, error) {
	var req collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal OTLP logs: %w", err)
	}

	var entries []LogEntry
	for _, rl := range req.ResourceLogs {
		// Collect resource attributes (prefixed with "resource.").
		resourceAttrs := make(map[string]any)
		if rl.Resource != nil {
			for _, kv := range rl.Resource.Attributes {
				resourceAttrs["resource."+kv.Key] = anyValueToGo(kv.Value)
			}
		}

		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				entry := logRecordToEntry(lr, resourceAttrs)
				entries = append(entries, entry)
			}
		}
	}
	return entries, nil
}

// logRecordToEntry converts a single OTLP LogRecord to a LogEntry.
func logRecordToEntry(lr *logspb.LogRecord, resourceAttrs map[string]any) LogEntry {
	// Timestamp.
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if lr.TimeUnixNano > 0 {
		ts = time.Unix(0, int64(lr.TimeUnixNano)).UTC().Format(time.RFC3339Nano)
	} else if lr.ObservedTimeUnixNano > 0 {
		ts = time.Unix(0, int64(lr.ObservedTimeUnixNano)).UTC().Format(time.RFC3339Nano)
	}

	// Level from SeverityNumber.
	level := severityToLevel(lr.SeverityNumber)

	// Message from Body.
	message := ""
	if lr.Body != nil {
		message = anyValueToString(lr.Body)
	}

	// Attributes: merge resource attrs + log record attrs.
	attrs := make(map[string]any, len(resourceAttrs)+len(lr.Attributes))
	for k, v := range resourceAttrs {
		attrs[k] = v
	}
	for _, kv := range lr.Attributes {
		attrs[kv.Key] = anyValueToGo(kv.Value)
	}

	// Add severity text if present and different from derived level.
	if lr.SeverityText != "" {
		attrs["severity_text"] = lr.SeverityText
	}

	var attrsResult map[string]any
	if len(attrs) > 0 {
		attrsResult = attrs
	}

	return LogEntry{
		ID:         generateLogID(),
		Timestamp:  ts,
		Level:      level,
		Message:    message,
		Attributes: attrsResult,
		Source:     "app",
	}
}

// severityToLevel maps OTLP SeverityNumber to our level strings.
// OTLP severity: 1-4=TRACE, 5-8=DEBUG, 9-12=INFO, 13-16=WARN, 17-20=ERROR, 21-24=FATAL.
func severityToLevel(sev logspb.SeverityNumber) string {
	switch {
	case sev <= 8:
		return "debug"
	case sev <= 12:
		return "info"
	case sev <= 16:
		return "warn"
	default:
		return "error"
	}
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
