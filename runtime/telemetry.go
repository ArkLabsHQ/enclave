package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// signal identifies one of the three telemetry streams. They ship independently
// so that a flood of one cannot starve another, which is why the queue state
// below is per signal rather than shared.
type signal int

const (
	signalLogs signal = iota
	signalTraces
	signalMetrics
	signalCount
)

func (s signal) String() string {
	switch s {
	case signalLogs:
		return "logs"
	case signalTraces:
		return "traces"
	case signalMetrics:
		return "metrics"
	}
	return "unknown"
}

const (
	// telemetryQueue bounds what may be in flight before events are dropped.
	telemetryQueue = 1000

	telemetryBatch = 250
	// shutdownFlushTimeout bounds the last flush after the context ends.
	shutdownFlushTimeout = 5 * time.Second

	maxBatchBytes = 1_048_576
	maxEventBytes = 262_144
	// eventOverhead is the per-event allowance AWS adds to the message size.
	eventOverhead = 26

	maxEventAge    = time.Hour
	maxEventFuture = time.Hour

	maxFlushAttempts = 3
)

type stream struct {
	group  string
	name   string
	events chan cwltypes.InputLogEvent
}

type Telemetry struct {
	Metrics *Metrics
	Logging *Logging
	Tracing *Tracing

	cw      CloudWatchLogsAPI
	streams [signalCount]*stream

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTelemetry wires the three signals in dependency order.
func NewTelemetry(cw CloudWatchLogsAPI) *Telemetry {
	t := &Telemetry{cw: cw}

	name := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	for sig := signal(0); sig < signalCount; sig++ {
		t.streams[sig] = &stream{
			group: fmt.Sprintf(
				"/enclave/%s/%s/%s", getDeployment(), getAppName(), sig),
			name:   name,
			events: make(chan cwltypes.InputLogEvent, telemetryQueue),
		}
	}

	t.Metrics = NewMetrics()
	t.Logging = NewLogging(t, t.Metrics)
	t.Tracing = NewTracing(t)
	return t
}

func (t *Telemetry) Start(ctx context.Context) error {
	if t.cw == nil {
		return fmt.Errorf("telemetry: no CloudWatch Logs client")
	}
	for sig := signal(0); sig < signalCount; sig++ {
		if err := t.ensureStream(ctx, sig); err != nil {
			return fmt.Errorf("failed to start %s cloudwatch export: %w", sig, err)
		}
	}

	pumpCtx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	for sig := signal(0); sig < signalCount; sig++ {
		t.wg.Add(1)
		go t.pump(pumpCtx, sig)
		slog.Info("cloudwatch shipper started", "signal", sig.String(),
			"log_group", t.streams[sig].group, "log_stream", t.streams[sig].name)
	}

	t.wg.Add(1)
	go t.shipMetricSnapshots(pumpCtx)
	slog.SetDefault(slog.New(NewSlogHandler(t.Logging)))
	return nil
}

func (t *Telemetry) Shutdown() {
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(), shutdownFlushTimeout)
	defer cancel()
	if t.Tracing != nil {
		t.Tracing.Shutdown(shutdownCtx)
	}
	t.Send(signalMetrics, time.Now(), t.Metrics.MetricsSnapshot())

	if t.cancel != nil {
		t.cancel()
	}
	t.wg.Wait()
}

// Dropped is the running count of one signal's lost events.
func (t *Telemetry) Dropped(sig signal) int64 {
	return t.Metrics.Counter(droppedMetric(sig))
}

func (t *Telemetry) Send(sig signal, ts time.Time, payload any) {
	msg, err := json.Marshal(payload)
	if err != nil {
		t.dropN(sig, 1)
		return
	}

	if len(msg)+eventOverhead > maxEventBytes {
		t.dropN(sig, 1)
		slog.Warn("telemetry event too large to ship",
			"signal", sig.String(), "bytes", len(msg))
		return
	}
	select {
	case t.streams[sig].events <- cwltypes.InputLogEvent{
		Message:   aws.String(string(msg)),
		Timestamp: aws.Int64(ts.UnixMilli()),
	}:
	default:
		t.dropN(sig, 1)
	}
}

func (t *Telemetry) dropN(sig signal, n int) {
	if n <= 0 || t.Metrics == nil {
		return
	}
	t.Metrics.IncBy(droppedMetric(sig), int64(n))
}

func (t *Telemetry) shipMetricSnapshots(ctx context.Context) {
	defer t.wg.Done()

	ticker := time.NewTicker(logShipInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			t.Send(signalMetrics, now, t.Metrics.MetricsSnapshot())
		}
	}
}

func (t *Telemetry) pump(ctx context.Context, sig signal) {
	defer t.wg.Done()

	s := t.streams[sig]
	ticker := time.NewTicker(logShipInterval())
	defer ticker.Stop()

	var batch []cwltypes.InputLogEvent
	pending := 0  // bytes held, against the PutLogEvents size limit
	failures := 0 // consecutive flush failures for this batch
	reported := int64(0)

	fits := func(size int) bool { return pending+size <= maxBatchBytes }

	reportDrops := func() {
		if dropped := t.Dropped(sig); dropped > reported {
			slog.Warn("cloudwatch shipper dropped events",
				"signal", sig.String(), "dropped", dropped-reported, "total", dropped)
			reported = dropped
		}
	}

	dropBatch := func() {
		t.dropN(sig, len(batch))
		batch, pending, failures = nil, 0, 0
	}

	// flush returns an error only while a failed batch remains pending. Once the
	// retry limit sheds that batch, it returns nil because the stream has room
	// for new events again.
	flush := func(ctx context.Context) error {
		if len(batch) == 0 {
			return nil
		}
		sort.Slice(batch, func(i, j int) bool {
			return *batch[i].Timestamp < *batch[j].Timestamp
		})

		out, err := t.cw.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
			LogGroupName:  aws.String(s.group),
			LogStreamName: aws.String(s.name),
			LogEvents:     batch,
		})
		if err != nil {
			failures++
			slog.Warn("cloudwatch shipper: PutLogEvents failed", "signal", sig.String(),
				"error", err, "count", len(batch), "attempt", failures)
			if failures >= maxFlushAttempts {
				dropBatch()
				return nil
			}
			return err
		}

		if lost := rejectedCount(out.RejectedLogEventsInfo, len(batch)); lost > 0 {
			t.dropN(sig, lost)
			slog.Warn("cloudwatch rejected events", "signal", sig.String(), "count", lost)
		}
		batch, pending, failures = nil, 0, 0
		return nil
	}

	accept := func(ctx context.Context, event cwltypes.InputLogEvent) {
		now := time.Now()
		ts := aws.ToInt64(event.Timestamp)
		if ts < now.Add(-maxEventAge).UnixMilli() || ts > now.Add(maxEventFuture).UnixMilli() {
			t.dropN(sig, 1)
			return
		}

		size := eventBytes(event)
		if !fits(size) {
			if err := flush(ctx); err != nil {

				t.dropN(sig, 1)
				return
			}
		}
		batch = append(batch, event)
		pending += size
	}

	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(
				context.WithoutCancel(ctx), shutdownFlushTimeout)
			for drained := false; !drained; {
				select {
				case event := <-s.events:
					accept(final, event)
				default:
					drained = true
				}
			}
			for len(batch) > 0 {
				if err := flush(final); err == nil {
					break
				}
				if final.Err() != nil {
					dropBatch()
					break
				}
			}
			reportDrops()
			cancel()
			return
		case event := <-s.events:
			accept(ctx, event)
			if len(batch) >= telemetryBatch {
				_ = flush(ctx)
			}
		case <-ticker.C:
			reportDrops()
			_ = flush(ctx)
		}
	}
}

func (t *Telemetry) ensureStream(ctx context.Context, sig signal) error {
	s := t.streams[sig]

	_, err := t.cw.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(s.group),
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create log group %s: %w", s.group, err)
	}

	_, err = t.cw.PutRetentionPolicy(ctx, &cloudwatchlogs.PutRetentionPolicyInput{
		LogGroupName:    aws.String(s.group),
		RetentionInDays: aws.Int32(logRetentionDays()),
	})
	if err != nil {
		slog.Warn("failed to set log retention", "log_group", s.group, "error", err)
	}

	_, err = t.cw.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(s.group),
		LogStreamName: aws.String(s.name),
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create log stream %s: %w", s.name, err)
	}

	marker, err := json.Marshal(map[string]string{
		"event":  "shipper_started",
		"signal": sig.String(),
		"stream": s.name,
	})
	if err != nil {
		return fmt.Errorf("encode %s startup marker: %w", sig, err)
	}
	if _, err := t.cw.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  aws.String(s.group),
		LogStreamName: aws.String(s.name),
		LogEvents: []cwltypes.InputLogEvent{{
			Message:   aws.String(string(marker)),
			Timestamp: aws.Int64(time.Now().UnixMilli()),
		}},
	}); err != nil {
		return fmt.Errorf("write to log stream %s: %w", s.group, err)
	}
	return nil
}

// rejectedCount reads how many events a successful PutLogEvents refused anyway.
func rejectedCount(info *cwltypes.RejectedLogEventsInfo, sent int) int {
	if info == nil {
		return 0
	}
	lost := int(aws.ToInt32(info.TooOldLogEventEndIndex)) +
		int(aws.ToInt32(info.ExpiredLogEventEndIndex))
	if idx := info.TooNewLogEventStartIndex; idx != nil {
		lost += sent - int(*idx)
	}
	return lost
}

func isAlreadyExists(err error) bool {
	var exists *cwltypes.ResourceAlreadyExistsException
	return errors.As(err, &exists)
}

func eventBytes(e cwltypes.InputLogEvent) int {
	return len(aws.ToString(e.Message)) + eventOverhead
}

func droppedMetric(sig signal) string {
	return fmt.Sprintf("enclave_telemetry_%s_dropped_total", sig)
}
