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
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// Tracing owns the span buffer and optional CloudWatch shipper.
type Tracing struct {
	buf    *spanBuffer
	shipCh chan spanEntry
	cw     CloudWatchLogsAPI
}

// NewTracing sends supervisor spans to the local span buffer.
func NewTracing(cw CloudWatchLogsAPI) *Tracing {
	t := &Tracing{
		buf: newSpanBuffer(spanBufferSize()),
	}

	if cloudwatchLogsEnabled() {
		t.cw = cw
		t.shipCh = make(chan spanEntry, 1000)
	}

	exporter := &bufferSpanExporter{buf: t.buf, shipCh: t.shipCh}
	otel.SetTracerProvider(sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(nil),
	))

	return t
}

func (t *Tracing) Span(ctx context.Context, name string) (context.Context, trace.Span) {
	return otel.GetTracerProvider().Tracer("runtime").Start(ctx, name)
}

// StartCloudWatchExport ships span batches to CloudWatch; no-op when disabled.
func (t *Tracing) StartCloudWatchExport(ctx context.Context) error {
	if t.shipCh == nil {
		return nil
	}
	deployment := getDeployment()
	appName := getAppName()
	logGroup := fmt.Sprintf("/enclave/%s/%s/traces", deployment, appName)
	logStream := time.Now().UTC().Format("2006-01-02T15-04-05Z")

	if err := ensureLogGroupAndStream(ctx, t.cw, logGroup, logStream); err != nil {
		return err
	}

	var batch []cwltypes.InputLogEvent

	flush := func() {
		if len(batch) == 0 {
			return
		}
		sort.Slice(batch, func(i, j int) bool {
			return *batch[i].Timestamp < *batch[j].Timestamp
		})
		_, err := t.cw.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
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

	go func() {
		ticker := time.NewTicker(logShipInterval())
		defer ticker.Stop()
		slog.Info("span shipper started", "log_group", logGroup, "log_stream", logStream)

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
	}()

	return nil
}

// spanEntry is a single trace span from the app or supervisor.
type spanEntry struct {
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

// spanBuffer is a bounded ring buffer for span entries.
type spanBuffer struct {
	mu      sync.Mutex
	entries []spanEntry
	cap     int
	head    int
	count   int
}

func newSpanBuffer(capacity int) *spanBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &spanBuffer{
		entries: make([]spanEntry, capacity),
		cap:     capacity,
	}
}

// add appends spans, evicting oldest.
func (sb *spanBuffer) add(entries ...spanEntry) {
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

// query filters spans oldest-first.
func (sb *spanBuffer) query(since time.Time, service string, limit int) []spanEntry {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	start := 0
	if sb.count == sb.cap {
		start = sb.head
	}

	result := make([]spanEntry, 0, sb.count)
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

		t.buf.add(entries...)

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
}

// HandleTracingGet returns buffered spans.
// GET /v1/enclave-traces?since=RFC3339&limit=100&service=app|supervisor
func HandleTracingGet(t *Tracing) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		entries := t.buf.query(since, service, limit)
		if entries == nil {
			entries = []spanEntry{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
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

// bufferSpanExporter writes supervisor spans to the local buffer.
type bufferSpanExporter struct {
	buf    *spanBuffer
	shipCh chan spanEntry
}

func (e *bufferSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	for _, s := range spans {
		entry := readOnlySpanToEntry(s)
		e.buf.add(entry)
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
		Source:     "supervisor",
	}
}
