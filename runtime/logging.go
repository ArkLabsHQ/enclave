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

// logEntry is a single structured log entry emitted by the enclave app or supervisor.
type logEntry struct {
	ID         string         `json:"id"`
	Timestamp  string         `json:"timestamp"`
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Source     string         `json:"source"`
}

// validTraceLevels maps log levels to severity order.
var validTraceLevels = map[string]int{
	"debug": 0,
	"info":  1,
	"warn":  2,
	"error": 3,
}

// logBuffer is a bounded ring buffer for log entries.
// Safe for concurrent use.
type logBuffer struct {
	mu      sync.Mutex
	entries []logEntry
	cap     int
	head    int // next write position
	count   int
}

func newLogBuffer(capacity int) *logBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &logBuffer{
		entries: make([]logEntry, capacity),
		cap:     capacity,
	}
}

// add appends one or more log entries, evicting oldest when full.
func (tb *logBuffer) add(entries ...logEntry) {
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

// query filters logs oldest-first; zero values disable filters.
func (tb *logBuffer) query(since time.Time, level string, limit int) []logEntry {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.count == 0 {
		return []logEntry{}
	}

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

	result := make([]logEntry, 0, tb.count)
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

func (tb *logBuffer) len() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.count
}

// generateLogID returns a short random log ID.
func generateLogID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Logging owns the log buffer and optional CloudWatch shipper.
type Logging struct {
	buf     *logBuffer
	shipCh  chan logEntry // nil when CloudWatch shipping is disabled
	metrics *Metrics
	cw      CloudWatchLogsAPI
}

// NewLogging builds logging; cw is used only when CloudWatch shipping is enabled.
func NewLogging(metrics *Metrics, cw CloudWatchLogsAPI) *Logging {
	buf := newLogBuffer(logBufferSize())

	if !cloudwatchLogsEnabled() {
		return &Logging{buf: buf, metrics: metrics}
	}

	return &Logging{
		buf:     buf,
		shipCh:  make(chan logEntry, 1000),
		metrics: metrics,
		cw:      cw,
	}
}

// StartCloudWatchExport ships log batches to CloudWatch; no-op when disabled.
func (l *Logging) StartCloudWatchExport(ctx context.Context) error {
	if l.shipCh == nil {
		return nil
	}

	deployment := getDeployment()
	appName := getAppName()
	logGroup := fmt.Sprintf("/enclave/%s/%s/logs", deployment, appName)
	logStream := time.Now().UTC().Format("2006-01-02T15-04-05Z")

	if err := ensureLogGroupAndStream(ctx, l.cw, logGroup, logStream); err != nil {
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
		_, err := l.cw.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
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

	go func() {
		slog.Info("log shipper started", "log_group", logGroup, "log_stream", logStream)

		ticker := time.NewTicker(logShipInterval())
		defer ticker.Stop()

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
	}()

	return nil
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

		l.buf.add(entries...)
		if l.metrics != nil {
			l.metrics.IncBy(l.metrics.LogEntries, "log_entries_total", int64(len(entries)))
		}

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
}

// handleLogsGet returns buffered logs; read-only/no auth.
func handleLogsGet(l *Logging) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		entries := l.buf.query(since, level, limit)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}
}

// ensureLogGroupAndStream creates the CloudWatch log group and stream if they
// don't already exist. Both operations are idempotent.
func ensureLogGroupAndStream(
	ctx context.Context,
	client CloudWatchLogsAPI,
	logGroup, logStream string,
) error {
	_, err := client.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(logGroup),
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create log group: %w", err)
	}

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

func isAlreadyExists(err error) bool {
	var alreadyGroup *cwltypes.ResourceAlreadyExistsException
	return errors.As(err, &alreadyGroup)
}

// bufferHandler mirrors slog records to stderr, buffer, and optional CloudWatch.
type bufferHandler struct {
	stderr  slog.Handler
	buf     *logBuffer
	shipCh  chan logEntry
	metrics *Metrics
	attrs   []slog.Attr
	group   string
}

// NewBufferHandler tees slog to stderr and optional Logging.
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
	_ = h.stderr.Handle(ctx, r)

	if h.buf == nil {
		return nil
	}

	entry := logEntry{
		ID:        generateLogID(),
		Timestamp: r.Time.UTC().Format(time.RFC3339Nano),
		Level:     slogLevelToString(r.Level),
		Message:   r.Message,
		Source:    "supervisor",
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

	h.buf.add(entry)
	if h.metrics != nil {
		h.metrics.Inc(h.metrics.LogEntries, "log_entries_total")
	}

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
