package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"
)

// logEntry is a single structured log entry emitted by the enclave or the app.
type logEntry struct {
	ID         string         `json:"id"`
	Timestamp  string         `json:"timestamp"`
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Source     string         `json:"source"`
}

// generateLogID returns a short random log ID.
func generateLogID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Logging accepts application logs and ships them to CloudWatch. It keeps no
// queryable history: CloudWatch is the record, and a truncated in-memory window
// readable from the enclave would only be a weaker second one.
type Logging struct {
	telemetry *Telemetry
	metrics   *Metrics
}

func NewLogging(telemetry *Telemetry, metrics *Metrics) *Logging {
	return &Logging{telemetry: telemetry, metrics: metrics}
}

// HandleLogsPost accepts OTLP protobuf logs.
func HandleLogsPost(l *Logging) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
		defer func() { _ = body.Close() }()

		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/x-protobuf") {
			http.Error(w, `{"error":"unknown Log Format"}`, http.StatusBadRequest)
			return
		}

		data, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
			return
		}

		entries, err := parseOTLPLogs(data)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"parse OTLP: %s"}`, err), http.StatusBadRequest)
			return
		}

		if len(entries) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]int{"accepted": 0})
			return
		}

		if l.metrics != nil {
			l.metrics.IncBy(metricLogEntries, int64(len(entries)))
		}
		for _, entry := range entries {
			l.telemetry.Send(signalLogs, entryTime(entry.Timestamp), entry)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(entries)})
	}
}

// slogHandler tees the enclave's own records to stderr and to CloudWatch. stderr keeps
// every line whatever CloudWatch is doing, so the console and journal stay
// complete even when shipping is dropping.
type slogHandler struct {
	stderr    slog.Handler
	telemetry *Telemetry
	metrics   *Metrics
	attrs     []slog.Attr
	group     string
}

// NewSlogHandler tees slog to stderr and, when logging is set, to CloudWatch.
func NewSlogHandler(logging *Logging) slog.Handler {
	h := &slogHandler{
		stderr: slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}),
	}
	if logging != nil {
		h.telemetry = logging.telemetry
		h.metrics = logging.metrics
	}
	return h
}

func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *slogHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = h.stderr.Handle(ctx, r)

	if h.telemetry == nil {
		return nil
	}

	entry := logEntry{
		ID:        generateLogID(),
		Timestamp: r.Time.UTC().Format(time.RFC3339Nano),
		Level:     slogLevelToString(r.Level),
		Message:   r.Message,
		Source:    "enclave",
	}

	attrs := make(map[string]any)
	for _, a := range h.attrs {
		attrs[a.Key] = a.Value.Any()
	}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	if len(attrs) > 0 {
		entry.Attributes = attrs
	}

	if h.metrics != nil {
		h.metrics.Inc(metricLogEntries)
	}
	h.telemetry.Send(signalLogs, r.Time, entry)

	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &slogHandler{
		stderr:    h.stderr.WithAttrs(attrs),
		telemetry: h.telemetry,
		metrics:   h.metrics,
		attrs:     append(h.attrs, attrs...),
		group:     h.group,
	}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	return &slogHandler{
		stderr:    h.stderr.WithGroup(name),
		telemetry: h.telemetry,
		metrics:   h.metrics,
		attrs:     h.attrs,
		group:     name,
	}
}

// entryTime reads an RFC3339 timestamp, falling back to now when the app sent
// one we cannot parse.
func entryTime(ts string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t
	}
	return time.Now()
}

// parseOTLPLogs decodes OTLP logs.
func parseOTLPLogs(body []byte) ([]logEntry, error) {
	var req collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal OTLP logs: %w", err)
	}

	var entries []logEntry
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

func logRecordToEntry(lr *logspb.LogRecord, resourceAttrs map[string]any) logEntry {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if lr.TimeUnixNano > 0 {
		ts = time.Unix(0, int64(lr.TimeUnixNano)).UTC().Format(time.RFC3339Nano)
	} else if lr.ObservedTimeUnixNano > 0 {
		ts = time.Unix(0, int64(lr.ObservedTimeUnixNano)).UTC().Format(time.RFC3339Nano)
	}

	level := severityToLevel(lr.SeverityNumber)

	message := ""
	if lr.Body != nil {
		message = anyValueToString(lr.Body)
	}

	// Merge resource and record attrs.
	attrs := make(map[string]any, len(resourceAttrs)+len(lr.Attributes))
	for k, v := range resourceAttrs {
		attrs[k] = v
	}
	for _, kv := range lr.Attributes {
		attrs[kv.Key] = anyValueToGo(kv.Value)
	}

	// Add severity text when present.
	if lr.SeverityText != "" {
		attrs["severity_text"] = lr.SeverityText
	}

	var attrsResult map[string]any
	if len(attrs) > 0 {
		attrsResult = attrs
	}

	return logEntry{
		ID:         generateLogID(),
		Timestamp:  ts,
		Level:      level,
		Message:    message,
		Attributes: attrsResult,
		Source:     "app",
	}
}

// severityToLevel maps OTLP severity bands to debug/info/warn/error.
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

func slogLevelToString(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}
