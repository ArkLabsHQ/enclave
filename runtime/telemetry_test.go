package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/require"
)

func TestNewTelemetryWiresDropCountingThroughMetrics(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")

	telemetry := NewTelemetry(newFakeCloudWatchLogs())

	// Every signal reports drops through the metrics counters, which is the
	// dependency that forces metrics to be built first.
	for sig := signal(0); sig < signalCount; sig++ {
		telemetry.dropN(sig, 1)
		after := telemetry.Metrics.MetricsSnapshot()["enclave"].(map[string]int64)

		require.Equal(t, int64(1), telemetry.Dropped(sig), sig.String())
		require.Equal(t, int64(1), after[droppedMetric(sig)], sig.String(),
			"the count must reach the snapshot, which is the only thing shipped")
	}
}

func TestTelemetryStartsAllThreeSignals(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cw := newFakeCloudWatchLogs()
	telemetry := NewTelemetry(cw)

	startTelemetry(t, ctx, telemetry)

	require.ElementsMatch(t, []string{
		"/enclave/test/app/logs",
		"/enclave/test/app/traces",
		"/enclave/test/app/metrics",
	}, cw.groups)
}

// A failure to start must surface rather than be logged into the sink that
// failed, so slog is redirected only after all three are shipping.
func TestTelemetryLeavesSlogAloneWhenStartFails(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")

	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	sentinel := errors.New("create group failed")
	cw := newFakeCloudWatchLogs()
	cw.createLogGroupErr = sentinel

	err := NewTelemetry(cw).Start(context.Background())

	require.ErrorIs(t, err, sentinel)
	require.ErrorContains(t, err, "cloudwatch export")
	require.Same(t, before, slog.Default())
}

func TestCloudWatchStreamBatches(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")

	t.Run("creates the group and stream once", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		startTelemetry(t, ctx, NewTelemetry(cw))

		require.ElementsMatch(t, []string{
			"/enclave/test/app/logs",
			"/enclave/test/app/traces",
			"/enclave/test/app/metrics",
		}, cw.groups)
		require.Len(t, cw.streams, int(signalCount))
	})

	t.Run("flushes a full batch in timestamp order", func(t *testing.T) {
		// A ship interval long enough that only the count threshold can flush,
		// so a slow run cannot split the batch and make this test lie.
		t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "1h")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(cw)
		startTelemetry(t, ctx, telemetry)

		// Sent newest first, so an unsorted batch would be rejected by CloudWatch.
		for i := 0; i < telemetryBatch; i++ {
			telemetry.Send(signalLogs,
				time.Now().UTC().Add(-time.Duration(i)*time.Second),
				map[string]int{"seq": i})
		}

		put := requireCloudWatchPutTo(t, cw, "/enclave/test/app/logs")
		require.Len(t, put.LogEvents, telemetryBatch)
		for i := 1; i < len(put.LogEvents); i++ {
			require.LessOrEqual(t,
				*put.LogEvents[i-1].Timestamp, *put.LogEvents[i].Timestamp)
		}
	})

	t.Run("flushes a partial batch on the tick", func(t *testing.T) {
		t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(cw)
		startTelemetry(t, ctx, telemetry)

		telemetry.Send(signalLogs, time.Now().UTC(), map[string]string{"msg": "alone"})

		put := requireCloudWatchPutTo(t, cw, "/enclave/test/app/logs")
		require.Len(t, put.LogEvents, 1)
		require.Contains(t, aws.ToString(put.LogEvents[0].Message), `"alone"`)
	})

	t.Run("keeps the event that crosses the byte boundary", func(t *testing.T) {
		t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "1h")
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(cw)

		before := slog.Default()
		t.Cleanup(func() { slog.SetDefault(before) })
		require.NoError(t, telemetry.Start(context.Background()))

		payload := strings.Repeat("x", maxEventBytes-eventOverhead-2)
		for i := 0; i < 5; i++ {
			telemetry.Send(signalLogs, time.Now().UTC(), payload)
		}

		first := requireCloudWatchPutTo(t, cw, "/enclave/test/app/logs")
		require.Len(t, first.LogEvents, 4)
		telemetry.Shutdown()

		cw.mu.Lock()
		defer cw.mu.Unlock()
		shipped := 0
		for _, put := range cw.puts {
			if aws.ToString(put.LogGroupName) == "/enclave/test/app/logs" &&
				!isShipperMarker(put) {
				shipped += len(put.LogEvents)
			}
		}
		require.Equal(t, 5, shipped)
		require.Zero(t, telemetry.Dropped(signalLogs))
	})
}

// Send must never block. It is the reason slog and the request handlers can call
// it, so this is the property to fail on if someone makes the send synchronous.
func TestCloudWatchStreamDropsWithoutBlocking(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "1h") // never flush on the tick

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cw := newFakeCloudWatchLogs()
	release := make(chan struct{})
	cw.putBlock = release
	defer close(release)

	telemetry := NewTelemetry(cw)
	startTelemetry(t, ctx, telemetry)

	const overfill = telemetryQueue * 3
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < overfill; i++ {
			telemetry.Send(signalLogs, time.Now().UTC(), map[string]int{"seq": i})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Send blocked behind a stalled CloudWatch")
	}

	require.Positive(t, telemetry.Dropped(signalLogs),
		"a full queue must drop rather than block")
	enclave := telemetry.Metrics.MetricsSnapshot()["enclave"].(map[string]int64)
	require.GreaterOrEqual(t, enclave[droppedMetric(signalLogs)],
		telemetry.Dropped(signalLogs),
		"drops must be visible in the only telemetry still being shipped")
}

func TestMetricsShipSnapshot(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cw := newFakeCloudWatchLogs()
	telemetry := NewTelemetry(cw)
	telemetry.Metrics.Inc(metricHTTPRequests)
	telemetry.Metrics.SetAppMetric("custom", 2)
	startTelemetry(t, ctx, telemetry)

	put := requireCloudWatchPutTo(t, cw, "/enclave/test/app/metrics")

	// One snapshot per tick, and a flush may carry more than one of them.
	require.NotEmpty(t, put.LogEvents)
	var snapshot struct {
		Enclave map[string]int64   `json:"enclave"`
		App     map[string]float64 `json:"app"`
		Runtime map[string]float64 `json:"runtime"`
	}
	require.NoError(t,
		json.Unmarshal([]byte(aws.ToString(put.LogEvents[0].Message)), &snapshot))
	require.Equal(t, int64(1), snapshot.Enclave[metricHTTPRequests])
	require.Equal(t, 2.0, snapshot.App["custom"])
	require.NotNil(t, snapshot.Runtime)
}

// The read-back endpoints went with the buffers they read. Cheap to assert, and
// it pins the API change against accidental reinstatement.
func TestTelemetryReadEndpointsAreGone(t *testing.T) {
	sm := http.NewServeMux()
	telemetry := NewTelemetry(newFakeCloudWatchLogs())

	sm.HandleFunc("POST /v1/metrics", HandleMetricPost(telemetry.Metrics))
	sm.HandleFunc("POST /v1/logs", HandleLogsPost(telemetry.Logging))
	sm.HandleFunc("POST /v1/traces", HandleTracingPost(telemetry.Tracing))

	for _, path := range []string{
		"/v1/enclave-metrics", "/v1/enclave-logs", "/v1/enclave-traces",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			sm.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			require.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

func TestEnclaveInfoCarriesNoMetrics(t *testing.T) {
	var info map[string]any
	raw, err := json.Marshal(RuntimeInfo{Version: Version})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &info))

	_, present := info["metrics"]
	require.False(t, present, "metrics live in CloudWatch, not in enclave-info")
}

// Creating a log group proves nothing about writing to it. Without the startup
// write, a role missing logs:PutLogEvents boots clean and loses everything.
func TestStartFailsWhenTheStreamIsNotWritable(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")

	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	sentinel := errors.New("AccessDenied: logs:PutLogEvents")
	cw := newFakeCloudWatchLogs()
	cw.putLogEventsErr = sentinel

	err := NewTelemetry(cw).Start(context.Background())

	require.ErrorIs(t, err, sentinel)
	require.ErrorContains(t, err, "write to log stream")
	require.Same(t, before, slog.Default())
}

// A batch AWS keeps refusing must not be retried forever: that would stall the
// stream behind one poisoned event and hold its memory for the whole run.
func TestFlushShedsAPoisonedBatchInsteadOfStalling(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cw := newFakeCloudWatchLogs()
	telemetry := NewTelemetry(cw)
	startTelemetry(t, ctx, telemetry)

	// Refuse everything after the startup write.
	cw.mu.Lock()
	cw.putLogEventsErr = errors.New("InvalidParameterException")
	cw.mu.Unlock()

	for i := 0; i < telemetryBatch; i++ {
		telemetry.Send(signalLogs, time.Now().UTC(), map[string]int{"seq": i})
	}

	require.Eventually(t, func() bool {
		return telemetry.Dropped(signalLogs) >= int64(telemetryBatch)
	}, 5*time.Second, 20*time.Millisecond,
		"a batch refused maxFlushAttempts times must be shed and counted")
}

// Events CloudWatch would reject on age are shed as they arrive, so one stale
// event cannot take the whole batch with it.
func TestSendShedsEventsCloudWatchWouldReject(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")

	telemetry := NewTelemetry(newFakeCloudWatchLogs())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startTelemetry(t, ctx, telemetry)

	now := time.Now().UTC()
	telemetry.Send(signalLogs, now.Add(-15*24*time.Hour), "older than 14 days")
	telemetry.Send(signalLogs, now.Add(3*time.Hour), "further ahead than 2 hours")
	telemetry.Send(signalLogs, now, "acceptable")

	require.Eventually(t, func() bool {
		return telemetry.Dropped(signalLogs) == 2
	}, 5*time.Second, 20*time.Millisecond,
		"both out-of-range events must be shed, and only those")
}

// A successful call can still refuse individual events; ignoring that is how
// telemetry goes missing with nothing reporting an error.
func TestRejectedCountReadsThePutResponse(t *testing.T) {
	require.Zero(t, rejectedCount(nil, 10))

	require.Equal(t, 3, rejectedCount(&cwltypes.RejectedLogEventsInfo{
		TooOldLogEventEndIndex: aws.Int32(3),
	}, 10))

	require.Equal(t, 4, rejectedCount(&cwltypes.RejectedLogEventsInfo{
		TooNewLogEventStartIndex: aws.Int32(6),
	}, 10))
}

// An oversized event would reject every batch it joined, so it is shed at Send.
func TestSendShedsAnOversizedEvent(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")

	telemetry := NewTelemetry(newFakeCloudWatchLogs())
	telemetry.Send(signalLogs, time.Now(), strings.Repeat("x", maxEventBytes))

	require.Equal(t, int64(1), telemetry.Dropped(signalLogs))
}

// Shutdown must wait for the pumps, or Run returning ends the process mid-write.
func TestShutdownFlushesWhatIsStillQueued(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "1h") // only Shutdown can flush this

	cw := newFakeCloudWatchLogs()
	telemetry := NewTelemetry(cw)
	startTelemetry(t, context.Background(), telemetry)

	telemetry.Send(signalLogs, time.Now().UTC(), map[string]string{"msg": "last words"})
	telemetry.Shutdown()

	cw.mu.Lock()
	defer cw.mu.Unlock()
	var shipped bool
	for _, put := range cw.puts {
		for _, e := range put.LogEvents {
			if strings.Contains(aws.ToString(e.Message), "last words") {
				shipped = true
			}
		}
	}
	require.True(t, shipped, "Shutdown must flush before returning")
}

func TestShutdownShedsAFinalBatchAfterRetryLimit(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "1h")

	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	cw := newFakeCloudWatchLogs()
	telemetry := NewTelemetry(cw)
	require.NoError(t, telemetry.Start(context.Background()))

	cw.mu.Lock()
	cw.putLogEventsErr = errors.New("CloudWatch unavailable")
	cw.mu.Unlock()

	telemetry.Send(signalLogs, time.Now().UTC(), "last event")
	telemetry.Shutdown()

	require.Positive(t, telemetry.Dropped(signalLogs),
		"a final batch that exhausts its retries must be counted as lost")
}
