package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// --- SpanBuffer tests ---

func TestSpanBuffer_AddAndQuery(t *testing.T) {
	buf := NewSpanBuffer(10)
	buf.Add(SpanEntry{Name: "a"}, SpanEntry{Name: "b"})

	entries := buf.Query(time.Time{}, "", 0)
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
}

func TestSpanBuffer_Eviction(t *testing.T) {
	buf := NewSpanBuffer(3)
	buf.Add(SpanEntry{Name: "1"}, SpanEntry{Name: "2"}, SpanEntry{Name: "3"})
	buf.Add(SpanEntry{Name: "4"})

	entries := buf.Query(time.Time{}, "", 0)
	if len(entries) != 3 {
		t.Fatalf("expected 3, got %d", len(entries))
	}
	if entries[0].Name != "2" {
		t.Fatalf("expected oldest '2', got %q", entries[0].Name)
	}
}

func TestSpanBuffer_QueryService(t *testing.T) {
	buf := NewSpanBuffer(10)
	buf.Add(
		SpanEntry{Name: "a", Source: "app"},
		SpanEntry{Name: "b", Source: "supervisor"},
		SpanEntry{Name: "c", Source: "app"},
	)

	entries := buf.Query(time.Time{}, "app", 0)
	if len(entries) != 2 {
		t.Fatalf("expected 2 app spans, got %d", len(entries))
	}
}

func TestSpanBuffer_QuerySince(t *testing.T) {
	buf := NewSpanBuffer(10)
	old := time.Now().Add(-10 * time.Second).UTC().Format(time.RFC3339Nano)
	recent := time.Now().UTC().Format(time.RFC3339Nano)
	buf.Add(SpanEntry{Start: old, Name: "old"}, SpanEntry{Start: recent, Name: "new"})

	since := time.Now().Add(-5 * time.Second)
	entries := buf.Query(since, "", 0)
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Name != "new" {
		t.Fatalf("expected 'new', got %q", entries[0].Name)
	}
}

func TestSpanBuffer_QueryLimit(t *testing.T) {
	buf := NewSpanBuffer(10)
	for i := 0; i < 5; i++ {
		buf.Add(SpanEntry{Name: "span"})
	}
	entries := buf.Query(time.Time{}, "", 2)
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
}

func TestSpanBuffer_Concurrent(t *testing.T) {
	buf := NewSpanBuffer(100)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				buf.Add(SpanEntry{Name: "c"})
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
}

// --- parseOTLPSpans tests ---

func buildOTLPTraceRequest(name string, statusCode tracepb.Status_StatusCode) []byte {
	req := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{{
					Key:   "service.name",
					Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "test-svc"}},
				}},
			},
			ScopeSpans: []*tracepb.ScopeSpans{{
				Spans: []*tracepb.Span{{
					TraceId:           []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					SpanId:            []byte{1, 2, 3, 4, 5, 6, 7, 8},
					ParentSpanId:      []byte{0, 0, 0, 0, 0, 0, 0, 0},
					Name:              name,
					StartTimeUnixNano: uint64(time.Now().Add(-1 * time.Second).UnixNano()),
					EndTimeUnixNano:   uint64(time.Now().UnixNano()),
					Status:            &tracepb.Status{Code: statusCode},
					Attributes: []*commonpb.KeyValue{{
						Key:   "test.attr",
						Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "val"}},
					}},
				}},
			}},
		}},
	}
	data, _ := proto.Marshal(req)
	return data
}

func TestParseOTLPSpans_Valid(t *testing.T) {
	data := buildOTLPTraceRequest("test.span", tracepb.Status_STATUS_CODE_OK)
	entries, err := parseOTLPSpans(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	e := entries[0]
	if e.Name != "test.span" {
		t.Fatalf("expected 'test.span', got %q", e.Name)
	}
	if e.Status != "ok" {
		t.Fatalf("expected 'ok', got %q", e.Status)
	}
	if e.Source != "app" {
		t.Fatalf("expected 'app', got %q", e.Source)
	}
	if e.Attributes["test.attr"] != "val" {
		t.Fatalf("expected attr test.attr=val, got %v", e.Attributes["test.attr"])
	}
	if e.Attributes["resource.service.name"] != "test-svc" {
		t.Fatalf("expected resource attr, got %v", e.Attributes["resource.service.name"])
	}
}

func TestParseOTLPSpans_StatusCodes(t *testing.T) {
	tests := []struct {
		code   tracepb.Status_StatusCode
		status string
	}{
		{tracepb.Status_STATUS_CODE_OK, "ok"},
		{tracepb.Status_STATUS_CODE_ERROR, "error"},
		{tracepb.Status_STATUS_CODE_UNSET, "unset"},
	}
	for _, tt := range tests {
		data := buildOTLPTraceRequest("s", tt.code)
		entries, _ := parseOTLPSpans(data)
		if entries[0].Status != tt.status {
			t.Errorf("code %d: expected %q, got %q", tt.code, tt.status, entries[0].Status)
		}
	}
}

func TestParseOTLPSpans_InvalidProtobuf(t *testing.T) {
	_, err := parseOTLPSpans([]byte("garbage"))
	requireErrContains(t, err, "unmarshal OTLP traces")
}

// --- HTTP handler tests ---

func TestHandleSpanGet_Empty(t *testing.T) {
	enc := newTestEnclave(t)
	req := httptest.NewRequest("GET", "/v1/enclave-traces", nil)
	w := httptest.NewRecorder()
	enc.tracing.handleGet(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []SpanEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0, got %d", len(entries))
	}
}

func TestHandleSpanPost_NoAuth(t *testing.T) {
	enc := newTestEnclave(t)
	body := buildOTLPTraceRequest("test", tracepb.Status_STATUS_CODE_OK)
	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	enc.tracing.handlePost(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleSpanPost_Valid(t *testing.T) {
	enc := newTestEnclave(t)
	body := buildOTLPTraceRequest("test", tracepb.Status_STATUS_CODE_OK)
	req := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+enc.RuntimeToken())
	w := httptest.NewRecorder()
	enc.tracing.handlePost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	entries := enc.tracing.buf.Query(time.Time{}, "", 0)
	if len(entries) != 1 {
		t.Fatalf("expected 1 span, got %d", len(entries))
	}
}

// --- Tracing.Span noop test ---

func TestTracingSpan_NoopOnNilTracing(t *testing.T) {
	// A nil-receivered call should return a noop span without panicking.
	var nilT *Tracing
	ctx, span := nilT.Span(context.Background(), "test")
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	span.End()
}
