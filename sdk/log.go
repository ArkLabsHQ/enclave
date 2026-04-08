package sdk

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

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

	minSeverity := -1
	if level != "" {
		if s, ok := validTraceLevels[level]; ok {
			minSeverity = s
		}
	}

	// Calculate start index (oldest entry).
	start := 0
	if tb.count == tb.cap {
		start = tb.head // ring wrapped, oldest is at head
	}

	result := make([]LogEntry, 0, tb.count)
	for i := 0; i < tb.count; i++ {
		idx := (start + i) % tb.cap
		e := tb.entries[idx]

		// Filter by timestamp.
		if !since.IsZero() {
			if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
				if t.Before(since) {
					continue
				}
			}
		}

		// Filter by level.
		if minSeverity >= 0 {
			if s, ok := validTraceLevels[e.Level]; ok {
				if s < minSeverity {
					continue
				}
			}
		}

		result = append(result, e)
		if limit > 0 && len(result) >= limit {
			break
		}
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
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// handleLogPost accepts new log entries from the app.
// POST /v1/logs
// Auth: Bearer ENCLAVE_MGMT_TOKEN
//
// Supports application/x-protobuf: OTLP ExportLogsServiceRequest protobuf
func (e *Enclave) handleLogPost(w http.ResponseWriter, r *http.Request) {
	if !e.checkMgmtToken(w, r) {
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

	e.logBuffer.Add(entries...)
	enclaveMetrics.LogEntries.Add(int64(len(entries)))

	// Forward to CloudWatch shipper if enabled.
	if e.logShipCh != nil {
		for _, entry := range entries {
			select {
			case e.logShipCh <- entry:
			default: // drop if channel full
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(entries)})
}

// handleLogGet returns buffered log entries.
// GET /v1/logs?since=RFC3339&level=info&limit=100
// No auth required (read-only, same as metrics).
func (e *Enclave) handleLogGet(w http.ResponseWriter, r *http.Request) {
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
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	entries := e.logBuffer.Query(since, level, limit)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// logBufferSize returns the configured log buffer capacity from env.
func logBufferSize() int {
	if s := os.Getenv("ENCLAVE_LOG_BUFFER_SIZE"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return n
		}
	}
	return 1000
}

// cloudwatchLogsEnabled returns true if ENCLAVE_LOG_CLOUDWATCH is "true".
func cloudwatchLogsEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("ENCLAVE_LOG_CLOUDWATCH")), "true")
}

// logShipInterval returns the configured CloudWatch shipping interval.
func logShipInterval() time.Duration {
	if s := os.Getenv("ENCLAVE_LOG_SHIP_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			return d
		}
	}
	return 5 * time.Second
}

// logRetentionDays returns the configured CloudWatch log group retention.
func logRetentionDays() int32 {
	if s := os.Getenv("ENCLAVE_LOG_RETENTION_DAYS"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			return int32(n)
		}
	}
	return 30
}

// newCloudWatchLogsClient creates a CloudWatch Logs client using IMDS credentials.
func newCloudWatchLogsClient(awsCfg aws.Config) *cloudwatchlogs.Client {
	if ep := os.Getenv("AWS_ENDPOINT_URL_LOGS"); ep != "" {
		return cloudwatchlogs.NewFromConfig(awsCfg, func(o *cloudwatchlogs.Options) {
			o.BaseEndpoint = aws.String(ep)
		})
	}
	return cloudwatchlogs.NewFromConfig(awsCfg)
}

// runLogShipper batches log entries and ships them to CloudWatch Logs.
// It reads from the shipCh channel and flushes periodically or when the batch
// reaches 100 entries. Runs as a goroutine after Init() completes.
func (e *Enclave) runLogShipper(ctx context.Context) {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		slog.Error("log shipper: failed to load AWS config", "error", err)
		return
	}

	client := newCloudWatchLogsClient(awsCfg)
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
		case entry, ok := <-e.logShipCh:
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
func ensureLogGroupAndStream(ctx context.Context, client *cloudwatchlogs.Client, logGroup, logStream string) error {
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
