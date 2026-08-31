package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// Tracing accepts application spans and ships them to CloudWatch. Like Logging
// it keeps no queryable history.
type Tracing struct {
	telemetry *Telemetry
	provider  *sdktrace.TracerProvider
}

// NewTracing wires the enclave's own spans through the same stream as app spans.
func NewTracing(telemetry *Telemetry) *Tracing {
	t := &Tracing{telemetry: telemetry}

	t.provider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(&streamSpanExporter{telemetry: telemetry}),
		sdktrace.WithResource(nil),
	)
	otel.SetTracerProvider(t.provider)

	return t
}

// Shutdown flushes the SDK's batcher. Spans sit in it until then, so without
// this the last spans of a run never reach the exporter at all.
func (t *Tracing) Shutdown(ctx context.Context) {
	if t.provider == nil {
		return
	}
	if err := t.provider.Shutdown(ctx); err != nil {
		slog.Warn("tracer provider shutdown", "error", err)
	}
}

func (t *Tracing) Span(ctx context.Context, name string) (context.Context, trace.Span) {
	return otel.GetTracerProvider().Tracer("runtime").Start(ctx, name)
}

// spanEntry is a single trace span from the enclave or the app.
type spanEntry struct {
	ID         string         `json:"id"`
	TraceID    string         `json:"trace_id"`
	ParentID   string         `json:"parent_id,omitempty"`
	Name       string         `json:"name"`
	Start      string         `json:"start"`
	End        string         `json:"end"`
	Status     string         `json:"status"` // "ok", "error", "unset"
	Attributes map[string]any `json:"attributes,omitempty"`
	Source     string         `json:"source"` // "app" or "enclave"
}

// HandleTracingPost accepts OTLP protobuf spans.
func HandleTracingPost(t *Tracing) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := http.MaxBytesReader(w, r.Body, 1<<20)
		defer func() { _ = body.Close() }()

		data, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
			return
		}

		entries, err := parseOTLPSpans(data)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf(`{"error":"parse OTLP traces: %s"}`, err),
				http.StatusBadRequest,
			)
			return
		}

		for _, entry := range entries {
			t.telemetry.Send(signalTraces, entryTime(entry.Start), entry)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(entries)})
	}
}

// parseOTLPSpans decodes OTLP traces.
func parseOTLPSpans(body []byte) ([]spanEntry, error) {
	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal OTLP traces: %w", err)
	}

	var entries []spanEntry
	for _, rs := range req.ResourceSpans {
		resourceAttrs := make(map[string]any)
		if rs.Resource != nil {
			for _, kv := range rs.Resource.Attributes {
				resourceAttrs["resource."+kv.Key] = anyValueToGo(kv.Value)
			}
		}

		for _, ss := range rs.ScopeSpans {
			for _, span := range ss.Spans {
				entries = append(entries, spanToEntry(span, resourceAttrs))
			}
		}
	}
	return entries, nil
}

func spanToEntry(span *tracepb.Span, resourceAttrs map[string]any) spanEntry {
	attrs := make(map[string]any, len(resourceAttrs)+len(span.Attributes))
	for k, v := range resourceAttrs {
		attrs[k] = v
	}
	for _, kv := range span.Attributes {
		attrs[kv.Key] = anyValueToGo(kv.Value)
	}

	var attrsResult map[string]any
	if len(attrs) > 0 {
		attrsResult = attrs
	}

	status := "unset"
	if span.Status != nil {
		switch span.Status.Code {
		case tracepb.Status_STATUS_CODE_OK:
			status = "ok"
		case tracepb.Status_STATUS_CODE_ERROR:
			status = "error"
		}
	}

	return spanEntry{
		ID:         fmt.Sprintf("%x", span.SpanId),
		TraceID:    fmt.Sprintf("%x", span.TraceId),
		ParentID:   fmt.Sprintf("%x", span.ParentSpanId),
		Name:       span.Name,
		Start:      time.Unix(0, int64(span.StartTimeUnixNano)).UTC().Format(time.RFC3339Nano),
		End:        time.Unix(0, int64(span.EndTimeUnixNano)).UTC().Format(time.RFC3339Nano),
		Status:     status,
		Attributes: attrsResult,
		Source:     "app",
	}
}

// streamSpanExporter ships the enclave's own spans through the same stream the app's
// spans take, so both halves of a trace land in one log group.
type streamSpanExporter struct {
	telemetry *Telemetry
}

func (e *streamSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	for _, s := range spans {
		entry := readOnlySpanToEntry(s)
		e.telemetry.Send(signalTraces, s.StartTime(), entry)
	}
	return nil
}

func (e *streamSpanExporter) Shutdown(_ context.Context) error {
	return nil
}

// readOnlySpanToEntry converts an OTEL SDK ReadOnlySpan to our SpanEntry.
func readOnlySpanToEntry(s sdktrace.ReadOnlySpan) spanEntry {
	attrs := make(map[string]any)
	for _, kv := range s.Attributes() {
		attrs[string(kv.Key)] = kv.Value.Emit()
	}
	for _, kv := range s.Resource().Attributes() {
		attrs["resource."+string(kv.Key)] = kv.Value.Emit()
	}

	var attrsResult map[string]any
	if len(attrs) > 0 {
		attrsResult = attrs
	}

	status := "unset"
	switch s.Status().Code {
	case codes.Ok:
		status = "ok"
	case codes.Error:
		status = "error"
	}

	return spanEntry{
		ID:         s.SpanContext().SpanID().String(),
		TraceID:    s.SpanContext().TraceID().String(),
		ParentID:   s.Parent().SpanID().String(),
		Name:       s.Name(),
		Start:      s.StartTime().UTC().Format(time.RFC3339Nano),
		End:        s.EndTime().UTC().Format(time.RFC3339Nano),
		Status:     status,
		Attributes: attrsResult,
		Source:     "enclave",
	}
}
