package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

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

// handleSpanPost accepts OTLP trace spans from the app.
// POST /v1/traces (Content-Type: application/x-protobuf)
func (e *Enclave) handleSpanPost(w http.ResponseWriter, r *http.Request) {
	if !e.checkMgmtToken(w, r) {
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

	e.spanBuffer.Add(entries...)

	// Forward to CloudWatch shipper.
	if e.spanShipCh != nil {
		for _, entry := range entries {
			select {
			case e.spanShipCh <- entry:
			default:
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(entries)})
}

// handleSpanGet returns buffered spans.
// GET /v1/enclave-traces?since=RFC3339&limit=100&service=app|supervisor
func (e *Enclave) handleSpanGet(w http.ResponseWriter, r *http.Request) {
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

	entries := e.spanBuffer.Query(since, service, limit)
	if entries == nil {
		entries = []SpanEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

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

// spanBufferSize returns configured span buffer capacity.
func spanBufferSize() int {
	if s := os.Getenv("ENCLAVE_SPAN_BUFFER_SIZE"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return n
		}
	}
	return 1000
}

// runSpanShipper batches span entries and ships to CloudWatch Logs.
func (e *Enclave) runSpanShipper(ctx context.Context) {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		slog.Error("span shipper: failed to load AWS config", "error", err)
		return
	}

	client := newCloudWatchLogsClient(awsCfg)
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
		case entry, ok := <-e.spanShipCh:
			if !ok {
				flush()
				return
			}
			msg, _ := json.Marshal(entry)
			ts := time.Now().UnixMilli()
			if t, err := time.Parse(time.RFC3339Nano, entry.Start); err == nil {
				ts = t.UnixMilli()
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
