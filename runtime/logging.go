package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"
)

// =============================================================================
// LogEntry + LogBuffer (data types)
// =============================================================================

// LogEntry is a single structured log entry emitted by the enclave app or supervisor.
type LogEntry struct {
	ID         string         `json:"id"`
	Timestamp  string         `json:"timestamp"`
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Source     string         `json:"source"`
}

// validTraceLevels defines accepted trace levels and their severity order.
var validTraceLevels = map[string]int{
	"debug": 0,
	"info":  1,
	"warn":  2,
	"error": 3,
}

// LogBuffer is a bounded ring buffer for log entries.
// Safe for concurrent use.
type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
	cap     int
	head    int // next write position
	count   int
}

// NewLogBuffer creates a ring buffer with the given capacity.
func NewLogBuffer(capacity int) *LogBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &LogBuffer{
		entries: make([]LogEntry, capacity),
		cap:     capacity,
	}
}

// Add appends one or more log entries, evicting oldest when full.
func (tb *LogBuffer) Add(entries ...LogEntry) {
	if len(entries) == 0 {
		return
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	for _, e := range entries {
		tb.entries[tb.head] = e
		tb.head = (tb.head + 1) % tb.cap
		if tb.count < tb.cap {
			tb.count++
		}
	}
}

// Query returns log entries matching the given filters, oldest first.
// A zero since returns all entries. An empty level returns all levels.
// limit <= 0 returns all matching entries.
func (tb *LogBuffer) Query(since time.Time, level string, limit int) []LogEntry {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.count == 0 {
		return []LogEntry{}
	}

	// Compute the start position (oldest entry).
	start := 0
	if tb.count == tb.cap {
		start = tb.head
	}

	minSeverity := -1
	if level != "" {
		if s, ok := validTraceLevels[level]; ok {
			minSeverity = s
		}
	}

	result := make([]LogEntry, 0, tb.count)
	for i := 0; i < tb.count; i++ {
		idx := (start + i) % tb.cap
		entry := tb.entries[idx]

		if !since.IsZero() {
			if t, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
				if !t.After(since) {
					continue
				}
			}
		}

		if minSeverity >= 0 {
			if s, ok := validTraceLevels[entry.Level]; !ok || s < minSeverity {
				continue
			}
		}

		result = append(result, entry)
	}

	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

// Len returns the number of entries in the buffer.
func (tb *LogBuffer) Len() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.count
}

// generateLogID returns a short random hex string for trace IDs.
func generateLogID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// =============================================================================
// Logging subsystem
// =============================================================================

// Logging owns the in-memory LogBuffer, the CloudWatch shipper channel, and
// the HTTP endpoints that read/write logs. Holds an *AWSClients reference
// so the shipper can use the shared CloudWatch Logs client without
// rebuilding it per Init.
type Logging struct {
	buf     *LogBuffer
	shipCh  chan LogEntry // nil when CloudWatch shipping is disabled
	metrics *Metrics
	aws     *AWSClient
	auth    func(http.ResponseWriter, *http.Request) bool // bearer-token check; nil = no auth
}

// NewLogging constructs the logging subsystem. metrics may be nil for tests.
// aws is required for the CloudWatch shipper but may be nil when shipping
// is disabled. auth is the bearer-token gate for POST /v1/logs; nil = open.
func NewLogging(metrics *Metrics, aws *AWSClient, auth func(http.ResponseWriter, *http.Request) bool) *Logging {
	var shipCh chan LogEntry
	if cloudwatchLogsEnabled() {
		shipCh = make(chan LogEntry, 1000)
	}
	return &Logging{
		buf:     NewLogBuffer(logBufferSize()),
		shipCh:  shipCh,
		metrics: metrics,
		aws:     aws,
		auth:    auth,
	}
}

// Buffer exposes the LogBuffer for in-process readers (e.g. the slog handler).
func (l *Logging) Buffer() *LogBuffer { return l.buf }

// ShipCh exposes the CloudWatch ship channel (nil when disabled).
func (l *Logging) ShipCh() chan LogEntry { return l.shipCh }

// RegisterRoutes attaches the log endpoints on mux.
func (l *Logging) RegisterRoutes(mux Mux) {
	mux.HandleFunc("POST /v1/logs", l.handlePost)
	mux.HandleFunc("GET /v1/enclave-logs", l.handleGet)
}

// handlePost accepts new log entries from the app.
// POST /v1/logs
// Auth: Bearer ENCLAVE_RUNTIME_TOKEN
//
// Supports application/x-protobuf: OTLP ExportLogsServiceRequest protobuf
func (l *Logging) handlePost(w http.ResponseWriter, r *http.Request) {
	if l.auth != nil && !l.auth(w, r) {
		return
	}

	body := http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	defer func() { _ = body.Close() }()

	// Dispatch based on Content-Type.
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

	l.buf.Add(entries...)
	if l.metrics != nil {
		l.metrics.IncBy(l.metrics.LogEntries, "log_entries_total", int64(len(entries)))
	}

	// Forward to CloudWatch shipper if enabled.
	if l.shipCh != nil {
		for _, entry := range entries {
			select {
			case l.shipCh <- entry:
			default: // drop if channel full
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(entries)})
}

// handleGet returns buffered log entries.
// GET /v1/enclave-logs?since=RFC3339&level=info&limit=100
// No auth required (read-only, same as metrics).
func (l *Logging) handleGet(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			since = t
		} else if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	level := strings.ToLower(r.URL.Query().Get("level"))
	limit := 0
	if lim := r.URL.Query().Get("limit"); lim != "" {
		if n, err := strconv.Atoi(lim); err == nil && n > 0 {
			limit = n
		}
	}

	entries := l.buf.Query(since, level, limit)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// RunShipper batches log entries and ships them to CloudWatch Logs.
// It reads from the shipCh channel and flushes periodically or when the batch
// reaches 100 entries. Runs as a goroutine after Init() completes.
// No-op if the shipper is disabled (shipCh is nil) or AWS clients are missing.
func (l *Logging) RunShipper(ctx context.Context) {
	if l.shipCh == nil || l.aws == nil {
		return
	}
	client := l.aws.CWL
	deployment := getDeployment()
	appName := getAppName()
	logGroup := fmt.Sprintf("/enclave/%s/%s/logs", deployment, appName)
	logStream := time.Now().UTC().Format("2006-01-02T15-04-05Z")

	// Create log group and stream (idempotent).
	if err := ensureLogGroupAndStream(ctx, client, logGroup, logStream); err != nil {
		slog.Error("log shipper: failed to create log group/stream", "error", err)
		return
	}

	slog.Info("log shipper started", "log_group", logGroup, "log_stream", logStream)

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
			slog.Warn("log shipper: PutLogEvents failed", "error", err, "count", len(batch))
			return
		}
		batch = nil
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case entry, ok := <-l.shipCh:
			if !ok {
				flush()
				return
			}
			msg, _ := json.Marshal(entry)
			ts := time.Now().UnixMilli()
			if t, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
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

// ensureLogGroupAndStream creates the CloudWatch log group and stream if they
// don't already exist. Both operations are idempotent.
func ensureLogGroupAndStream(ctx context.Context, client CloudWatchLogsAPI, logGroup, logStream string) error {
	_, err := client.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroup),
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create log group: %w", err)
	}

	// Set retention policy.
	_, _ = client.PutRetentionPolicy(ctx, &cloudwatchlogs.PutRetentionPolicyInput{
		LogGroupName:    aws.String(logGroup),
		RetentionInDays: aws.Int32(logRetentionDays()),
	})

	_, err = client.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(logGroup),
		LogStreamName: aws.String(logStream),
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create log stream: %w", err)
	}

	return nil
}

// isAlreadyExists checks if a CloudWatch error indicates the resource already exists.
func isAlreadyExists(err error) bool {
	var alreadyGroup *cwltypes.ResourceAlreadyExistsException
	return errors.As(err, &alreadyGroup)
}

// =============================================================================
// bufferHandler — slog.Handler that tees into a Logging subsystem
// =============================================================================

// bufferHandler is a slog.Handler that tees log records to:
// 1. JSON stderr (existing behavior)
// 2. LogBuffer as LogEntry with source="supervisor"
// 3. logShipCh for CloudWatch (nil-safe)
type bufferHandler struct {
	stderr  slog.Handler
	buf     *LogBuffer
	shipCh  chan LogEntry
	metrics *Metrics
	attrs   []slog.Attr
	group   string
}

// NewBufferHandler creates a slog.Handler that writes to both stderr and
// the Logging subsystem's buffer. Pass nil for logging if buffer/shipping
// isn't wanted.
func NewBufferHandler(logging *Logging) slog.Handler {
	h := &bufferHandler{
		stderr: slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}),
	}
	if logging != nil {
		h.buf = logging.buf
		h.shipCh = logging.shipCh
		h.metrics = logging.metrics
	}
	return h
}

func (h *bufferHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *bufferHandler) Handle(ctx context.Context, r slog.Record) error {
	// Always write to stderr.
	_ = h.stderr.Handle(ctx, r)

	if h.buf == nil {
		return nil
	}

	// Convert to LogEntry.
	entry := LogEntry{
		ID:        generateLogID(),
		Timestamp: r.Time.UTC().Format(time.RFC3339Nano),
		Level:     slogLevelToString(r.Level),
		Message:   r.Message,
		Source:    "supervisor",
	}

	// Collect attributes.
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

	h.buf.Add(entry)
	if h.metrics != nil {
		h.metrics.Inc(h.metrics.LogEntries, "log_entries_total")
	}

	// Forward to CloudWatch shipper if available.
	if h.shipCh != nil {
		select {
		case h.shipCh <- entry:
		default:
		}
	}

	return nil
}

func (h *bufferHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &bufferHandler{
		stderr:  h.stderr.WithAttrs(attrs),
		buf:     h.buf,
		shipCh:  h.shipCh,
		metrics: h.metrics,
		attrs:   append(h.attrs, attrs...),
		group:   h.group,
	}
}

func (h *bufferHandler) WithGroup(name string) slog.Handler {
	return &bufferHandler{
		stderr:  h.stderr.WithGroup(name),
		buf:     h.buf,
		shipCh:  h.shipCh,
		metrics: h.metrics,
		attrs:   h.attrs,
		group:   name,
	}
}

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

// slogLevelToString converts slog.Level to our level strings.
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
