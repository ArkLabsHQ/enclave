package runtime

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

func newTestEnclave(t *testing.T) *Runtime {
	t.Helper()
	// nil cfg → skip HTTP server setup; tests only need subsystem state.
	enc, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// --- LogBuffer tests ---

func TestLogBuffer_AddAndLen(t *testing.T) {
	buf := NewLogBuffer(10)
	if buf.Len() != 0 {
		t.Fatalf("expected 0, got %d", buf.Len())
	}
	buf.Add(LogEntry{Message: "a"}, LogEntry{Message: "b"})
	if buf.Len() != 2 {
		t.Fatalf("expected 2, got %d", buf.Len())
	}
}

func TestLogBuffer_Eviction(t *testing.T) {
	buf := NewLogBuffer(3)
	buf.Add(LogEntry{Message: "1"}, LogEntry{Message: "2"}, LogEntry{Message: "3"})
	buf.Add(LogEntry{Message: "4"}) // evicts "1"

	entries := buf.Query(time.Time{}, "", 0)
	if len(entries) != 3 {
		t.Fatalf("expected 3, got %d", len(entries))
	}
	if entries[0].Message != "2" {
		t.Fatalf("expected oldest to be '2', got %q", entries[0].Message)
	}
	if entries[2].Message != "4" {
		t.Fatalf("expected newest to be '4', got %q", entries[2].Message)
	}
}

func TestLogBuffer_QueryLevel(t *testing.T) {
	buf := NewLogBuffer(10)
	buf.Add(
		LogEntry{Level: "debug", Message: "d"},
		LogEntry{Level: "info", Message: "i"},
		LogEntry{Level: "warn", Message: "w"},
		LogEntry{Level: "error", Message: "e"},
	)

	entries := buf.Query(time.Time{}, "warn", 0)
	if len(entries) != 2 {
		t.Fatalf("expected 2 (warn+error), got %d", len(entries))
	}
	for _, e := range entries {
		if e.Level != "warn" && e.Level != "error" {
			t.Fatalf("unexpected level %q", e.Level)
		}
	}
}

func TestLogBuffer_QuerySince(t *testing.T) {
	buf := NewLogBuffer(10)
	t1 := time.Now().Add(-10 * time.Second).UTC().Format(time.RFC3339Nano)
	t2 := time.Now().UTC().Format(time.RFC3339Nano)
	buf.Add(LogEntry{Timestamp: t1, Message: "old"}, LogEntry{Timestamp: t2, Message: "new"})

	since := time.Now().Add(-5 * time.Second)
	entries := buf.Query(since, "", 0)
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Message != "new" {
		t.Fatalf("expected 'new', got %q", entries[0].Message)
	}
}

func TestLogBuffer_QueryLimit(t *testing.T) {
	buf := NewLogBuffer(10)
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{Message: "msg"})
	}
	entries := buf.Query(time.Time{}, "", 2)
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
}

func TestLogBuffer_EmptyReturnsEmptySlice(t *testing.T) {
	buf := NewLogBuffer(10)
	entries := buf.Query(time.Time{}, "", 0)
	if entries == nil {
		t.Fatal("expected non-nil empty slice")
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0, got %d", len(entries))
	}
}

func TestLogBuffer_Concurrent(t *testing.T) {
	buf := NewLogBuffer(100)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				buf.Add(LogEntry{Message: "concurrent"})
			}
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				buf.Query(time.Time{}, "", 10)
			}
		}()
	}
	wg.Wait()
	// No race = pass
}

// --- parseOTLPLogs tests ---

func buildOTLPLogRequest(severity logspb.SeverityNumber, body, attrKey, attrVal string) []byte {
	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{{
					Key:   "service.name",
					Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "test"}},
				}},
			},
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					TimeUnixNano:   uint64(time.Now().UnixNano()),
					SeverityNumber: severity,
					Body:           &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: body}},
					Attributes: []*commonpb.KeyValue{{
						Key:   attrKey,
						Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: attrVal}},
					}},
				}},
			}},
		}},
	}
	data, _ := proto.Marshal(req)
	return data
}

func TestParseOTLPLogs_Valid(t *testing.T) {
	data := buildOTLPLogRequest(logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "hello", "key", "val")
	entries, err := parseOTLPLogs(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	e := entries[0]
	if e.Message != "hello" {
		t.Fatalf("expected 'hello', got %q", e.Message)
	}
	if e.Level != "info" {
		t.Fatalf("expected 'info', got %q", e.Level)
	}
	if e.Source != "app" {
		t.Fatalf("expected 'app', got %q", e.Source)
	}
	if e.Attributes["key"] != "val" {
		t.Fatalf("expected attr key=val, got %v", e.Attributes["key"])
	}
	if e.Attributes["resource.service.name"] != "test" {
		t.Fatalf("expected resource attr, got %v", e.Attributes["resource.service.name"])
	}
}

func TestParseOTLPLogs_SeverityMapping(t *testing.T) {
	tests := []struct {
		sev   logspb.SeverityNumber
		level string
	}{
		{logspb.SeverityNumber_SEVERITY_NUMBER_TRACE, "debug"},
		{logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG, "debug"},
		{logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "info"},
		{logspb.SeverityNumber_SEVERITY_NUMBER_WARN, "warn"},
		{logspb.SeverityNumber_SEVERITY_NUMBER_ERROR, "error"},
		{logspb.SeverityNumber_SEVERITY_NUMBER_FATAL, "error"},
	}
	for _, tt := range tests {
		data := buildOTLPLogRequest(tt.sev, "test", "k", "v")
		entries, err := parseOTLPLogs(data)
		if err != nil {
			t.Fatal(err)
		}
		if entries[0].Level != tt.level {
			t.Errorf("severity %d: expected %q, got %q", tt.sev, tt.level, entries[0].Level)
		}
	}
}

func TestParseOTLPLogs_InvalidProtobuf(t *testing.T) {
	_, err := parseOTLPLogs([]byte("not protobuf"))
	requireErrContains(t, err, "unmarshal OTLP logs")
}

// --- HTTP handler tests ---

func TestHandleLogGet_Empty(t *testing.T) {
	enc := newTestEnclave(t)
	req := httptest.NewRequest("GET", "/v1/enclave-logs", nil)
	w := httptest.NewRecorder()
	enc.logging.handleGet(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []LogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0, got %d", len(entries))
	}
}

func TestHandleLogGet_WithEntries(t *testing.T) {
	enc := newTestEnclave(t)
	enc.logging.buf.Add(LogEntry{Level: "info", Message: "a"}, LogEntry{Level: "error", Message: "b"})

	req := httptest.NewRequest("GET", "/v1/enclave-logs?level=error", nil)
	w := httptest.NewRecorder()
	enc.logging.handleGet(w, req)

	var entries []LogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 error entry, got %d", len(entries))
	}
}

func TestHandleLogPost_NoAuth(t *testing.T) {
	enc := newTestEnclave(t)
	body := buildOTLPLogRequest(logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "test", "k", "v")
	req := httptest.NewRequest("POST", "/v1/logs", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	enc.logging.handlePost(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleLogPost_ValidOTLP(t *testing.T) {
	enc := newTestEnclave(t)
	body := buildOTLPLogRequest(logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "test", "k", "v")
	req := httptest.NewRequest("POST", "/v1/logs", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+enc.RuntimeToken())
	w := httptest.NewRecorder()
	enc.logging.handlePost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if enc.logging.buf.Len() != 1 {
		t.Fatalf("expected 1 entry in buffer, got %d", enc.logging.buf.Len())
	}
}

// --- bufferHandler tests ---

func TestBufferHandler_SlogToLogEntry(t *testing.T) {
	buf := NewLogBuffer(10)
	handler := NewBufferHandler(&Logging{buf: buf})
	logger := slog.New(handler)

	logger.Info("test message", "key", "value")

	entries := buf.Query(time.Time{}, "", 0)
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	e := entries[0]
	if e.Message != "test message" {
		t.Fatalf("expected 'test message', got %q", e.Message)
	}
	if e.Level != "info" {
		t.Fatalf("expected 'info', got %q", e.Level)
	}
	if e.Source != "supervisor" {
		t.Fatalf("expected 'supervisor', got %q", e.Source)
	}
}

func TestBufferHandler_ErrorLevel(t *testing.T) {
	buf := NewLogBuffer(10)
	handler := NewBufferHandler(&Logging{buf: buf})
	logger := slog.New(handler)

	logger.Error("fail", "error", "something broke")

	entries := buf.Query(time.Time{}, "", 0)
	if entries[0].Level != "error" {
		t.Fatalf("expected 'error', got %q", entries[0].Level)
	}
}

func TestBufferHandler_NilShipCh(t *testing.T) {
	buf := NewLogBuffer(10)
	handler := NewBufferHandler(&Logging{buf: buf})
	// Should not panic with nil channel.
	_ = handler.Handle(context.Background(), slog.Record{})
}

func TestSlogLevelToString(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "debug"},
		{slog.LevelInfo, "info"},
		{slog.LevelWarn, "warn"},
		{slog.LevelError, "error"},
	}
	for _, tt := range tests {
		got := slogLevelToString(tt.level)
		if got != tt.want {
			t.Errorf("slogLevelToString(%v) = %q, want %q", tt.level, got, tt.want)
		}
	}
}
