package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// =============================================================================
// SpanEntry + SpanBuffer
// =============================================================================

// SpanEntry is a single trace span from the app or supervisor.
type SpanEntry struct {
	ID         string         `json:"id"`
	TraceID    string         `json:"trace_id"`
	ParentID   string         `json:"parent_id,omitempty"`
	Name       string         `json:"name"`
	Start      string         `json:"start"`
	End        string         `json:"end"`
	Status     string         `json:"status"` // "ok", "error", "unset"
	Attributes map[string]any `json:"attributes,omitempty"`
	Source     string         `json:"source"` // "app" or "supervisor"
}

// SpanBuffer is a bounded ring buffer for span entries.
type SpanBuffer struct {
	mu      sync.Mutex
	entries []SpanEntry
	cap     int
	head    int
	count   int
}

// NewSpanBuffer creates a ring buffer with the given capacity.
func NewSpanBuffer(capacity int) *SpanBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &SpanBuffer{
		entries: make([]SpanEntry, capacity),
		cap:     capacity,
	}
}

// Add appends span entries, evicting oldest when full.
func (sb *SpanBuffer) Add(entries ...SpanEntry) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for _, e := range entries {
		sb.entries[sb.head] = e
		sb.head = (sb.head + 1) % sb.cap
		if sb.count < sb.cap {
			sb.count++
		}
	}
}

// Query returns span entries matching filters, oldest first.
func (sb *SpanBuffer) Query(since time.Time, service string, limit int) []SpanEntry {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	start := 0
	if sb.count == sb.cap {
		start = sb.head
	}

	result := make([]SpanEntry, 0, sb.count)
	for i := 0; i < sb.count; i++ {
		idx := (start + i) % sb.cap
		e := sb.entries[idx]

		if !since.IsZero() {
			if t, err := time.Parse(time.RFC3339Nano, e.Start); err == nil {
				if t.Before(since) {
					continue
				}
			}
		}

		if service != "" && e.Source != service {
			continue
		}

		result = append(result, e)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

// =============================================================================
// Tracing subsystem
// =============================================================================

// Tracing owns the in-memory SpanBuffer, the CloudWatch ship channel, and
// the OTEL tracer used by supervisor instrumentation. Spans from in-process
// tracer.Start calls and from OTLP HTTP ingest both land in the same buf.
type Tracing struct {
	buf     *SpanBuffer
	shipCh  chan SpanEntry
	tracer  trace.Tracer
	tp      *sdktrace.TracerProvider
	metrics *Metrics
	aws     *AWSClient
	auth    func(http.ResponseWriter, *http.Request) bool
}

// NewTracing constructs the tracing subsystem and starts the OTEL
// TracerProvider. Spans are exported directly into the SpanBuffer (no
// network). metrics may be nil for tests; aws is required for the
// CloudWatch shipper but may be nil when shipping is disabled.
func NewTracing(metrics *Metrics, aws *AWSClient, auth func(http.ResponseWriter, *http.Request) bool) *Tracing {
	t := &Tracing{
		buf:     NewSpanBuffer(spanBufferSize()),
		metrics: metrics,
		aws:     aws,
		auth:    auth,
	}
	if cloudwatchLogsEnabled() {
		t.shipCh = make(chan SpanEntry, 1000)
	}

	exporter := &bufferSpanExporter{buf: t.buf, shipCh: t.shipCh}
	t.tp = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(nil), // default resource
	)
	otel.SetTracerProvider(t.tp)
	t.tracer = t.tp.Tracer("runtime")
	return t
}

// Buffer exposes the SpanBuffer.
func (t *Tracing) Buffer() *SpanBuffer { return t.buf }

// Shutdown stops the underlying OTEL TracerProvider, flushing pending spans.
func (t *Tracing) Shutdown(ctx context.Context) error {
	if t == nil || t.tp == nil {
		return nil
	}
	return t.tp.Shutdown(ctx)
}

// Span starts a new span on the supervisor tracer.
// Usage: ctx, span := r.tracing.Span(ctx, "init.kms_policy")
// defer span.End()
func (t *Tracing) Span(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if t == nil || t.tracer == nil {
		return ctx, trace.SpanFromContext(ctx) // noop if tracing not initialized
	}
	return t.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
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
func AttrString(key, val string) attribute.KeyValue  { return attribute.String(key, val) }
func AttrInt(key string, val int) attribute.KeyValue { return attribute.Int(key, val) }
func AttrError(err error) attribute.KeyValue         { return attribute.String("error", fmt.Sprint(err)) }

// RegisterRoutes attaches the trace endpoints on mux.
func (t *Tracing) RegisterRoutes(mux Mux) {
	mux.HandleFunc("POST /v1/enclave-traces", t.handlePost)
	mux.HandleFunc("GET /v1/enclave-traces", t.handleGet)
}

// handlePost accepts OTLP trace spans from the app.
// POST /v1/enclave-traces (Content-Type: application/x-protobuf)
func (t *Tracing) handlePost(w http.ResponseWriter, r *http.Request) {
	if t.auth != nil && !t.auth(w, r) {
		return
	}

	body := http.MaxBytesReader(w, r.Body, 1<<20)
	defer func() { _ = body.Close() }()

	data, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
		return
	}

	entries, err := parseOTLPSpans(data)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"parse OTLP traces: %s"}`, err), http.StatusBadRequest)
		return
	}

	t.buf.Add(entries...)

	if t.shipCh != nil {
		for _, entry := range entries {
			select {
			case t.shipCh <- entry:
			default:
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(entries)})
}

// handleGet returns buffered spans.
// GET /v1/enclave-traces?since=RFC3339&limit=100&service=app|supervisor
func (t *Tracing) handleGet(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			since = t
		} else if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	service := r.URL.Query().Get("service")
	limit := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	entries := t.buf.Query(since, service, limit)
	if entries == nil {
		entries = []SpanEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// RunShipper batches span entries and ships to CloudWatch Logs.
// No-op if shipping is disabled (shipCh is nil) or AWS clients are missing.
func (t *Tracing) RunShipper(ctx context.Context) {
	if t.shipCh == nil || t.aws == nil {
		return
	}
	client := t.aws.CWL
	deployment := getDeployment()
	appName := getAppName()
	logGroup := fmt.Sprintf("/enclave/%s/%s/traces", deployment, appName)
	logStream := time.Now().UTC().Format("2006-01-02T15-04-05Z")

	if err := ensureLogGroupAndStream(ctx, client, logGroup, logStream); err != nil {
		slog.Error("span shipper: failed to create log group/stream", "error", err)
		return
	}

	slog.Info("span shipper started", "log_group", logGroup, "log_stream", logStream)

	ticker := time.NewTicker(logShipInterval())
	defer ticker.Stop()

	var batch []cwltypes.InputLogEvent

	flush := func() {
		if len(batch) == 0 {
			return
		}
		sort.Slice(batch, func(i, j int) bool {
			return *batch[i].Timestamp < *batch[j].Timestamp
		})
		_, err := client.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
			LogGroupName:  aws.String(logGroup),
			LogStreamName: aws.String(logStream),
			LogEvents:     batch,
		})
		if err != nil {
			slog.Warn("span shipper: PutLogEvents failed", "error", err, "count", len(batch))
			return
		}
		batch = nil
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case entry, ok := <-t.shipCh:
			if !ok {
				flush()
				return
			}
			msg, _ := json.Marshal(entry)
			ts := time.Now().UnixMilli()
			if tt, err := time.Parse(time.RFC3339Nano, entry.Start); err == nil {
				ts = tt.UnixMilli()
			}
			batch = append(batch, cwltypes.InputLogEvent{
				Message:   aws.String(string(msg)),
				Timestamp: aws.Int64(ts),
			})
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// =============================================================================
// OTLP ingest helpers (used by handlePost)
// =============================================================================

// parseOTLPSpans parses an OTLP ExportTraceServiceRequest and converts to SpanEntry.
func parseOTLPSpans(body []byte) ([]SpanEntry, error) {
	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("unmarshal OTLP traces: %w", err)
	}

	var entries []SpanEntry
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

// spanToEntry converts an OTLP Span to a SpanEntry.
func spanToEntry(span *tracepb.Span, resourceAttrs map[string]any) SpanEntry {
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

	return SpanEntry{
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

// =============================================================================
// bufferSpanExporter — sdktrace.SpanExporter that writes to SpanBuffer
// =============================================================================

// bufferSpanExporter implements sdktrace.SpanExporter by writing spans
// directly to the SpanBuffer. No network hop — supervisor-emitted spans
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
