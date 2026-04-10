package sdk

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// supervisorTracer is the global tracer for supervisor instrumentation.
var supervisorTracer trace.Tracer

// bufferSpanExporter implements sdktrace.SpanExporter by writing spans
// directly to the SpanBuffer. No network hop — spans from the supervisor
// go straight into the in-memory buffer (and optionally to CloudWatch).
type bufferSpanExporter struct {
	buf    *SpanBuffer
	shipCh chan SpanEntry
}

func (e *bufferSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	for _, s := range spans {
		entry := readOnlySpanToEntry(s)
		e.buf.Add(entry)
		if e.shipCh != nil {
			select {
			case e.shipCh <- entry:
			default:
			}
		}
	}
	return nil
}

func (e *bufferSpanExporter) Shutdown(_ context.Context) error {
	return nil
}

// readOnlySpanToEntry converts an OTEL SDK ReadOnlySpan to our SpanEntry.
func readOnlySpanToEntry(s sdktrace.ReadOnlySpan) SpanEntry {
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
	case 1: // OK
		status = "ok"
	case 2: // Error
		status = "error"
	}

	return SpanEntry{
		ID:         s.SpanContext().SpanID().String(),
		TraceID:    s.SpanContext().TraceID().String(),
		ParentID:   s.Parent().SpanID().String(),
		Name:       s.Name(),
		Start:      s.StartTime().UTC().Format(time.RFC3339Nano),
		End:        s.EndTime().UTC().Format(time.RFC3339Nano),
		Status:     status,
		Attributes: attrsResult,
		Source:     "supervisor",
	}
}

// StartSupervisorTracing initializes the OTEL TracerProvider for the supervisor.
// Spans are exported directly into the SpanBuffer (no network).
// Returns a shutdown function.
func StartSupervisorTracing(buf *SpanBuffer, shipCh chan SpanEntry) func(context.Context) error {
	exporter := &bufferSpanExporter{buf: buf, shipCh: shipCh}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(nil), // default resource
	)

	otel.SetTracerProvider(tp)
	supervisorTracer = tp.Tracer("enclave-supervisor")

	return tp.Shutdown
}

// SupervisorSpan starts a new span on the supervisor tracer.
// Usage: ctx, span := sdk.SupervisorSpan(ctx, "init.kms_policy")
// defer span.End()
func SupervisorSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if supervisorTracer == nil {
		return ctx, trace.SpanFromContext(ctx) // noop if tracing not initialized
	}
	return supervisorTracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// SpanError records an error on a span and sets its status to error.
func SpanError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(2, err.Error()) // codes.Error = 2
}

// SpanOK sets a span's status to OK.
func SpanOK(span trace.Span) {
	span.SetStatus(1, "") // codes.Ok = 1
}

// SpanSetAttr adds attributes to a span.
func SpanSetAttr(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(attrs...)
}

// Attr helpers for common span attributes.
func AttrString(key, val string) attribute.KeyValue { return attribute.String(key, val) }
func AttrInt(key string, val int) attribute.KeyValue { return attribute.Int(key, val) }
func AttrError(err error) attribute.KeyValue        { return attribute.String("error", fmt.Sprint(err)) }
