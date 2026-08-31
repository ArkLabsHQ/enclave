package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

func TestParseOTLPLogs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		entries, err := parseOTLPLogs(
			buildOTLPLogRequest(
				t,
				logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
				"hello",
				"key",
				"val",
			),
		)
		require.NoError(t, err)
		require.Len(t, entries, 1)

		entry := entries[0]
		require.NotEmpty(t, entry.ID)
		require.Equal(t, "hello", entry.Message)
		require.Equal(t, "info", entry.Level)
		require.Equal(t, "app", entry.Source)
		require.Equal(t, "val", entry.Attributes["key"])
		require.Equal(t, "test", entry.Attributes["resource.service.name"])
	})

	t.Run("severity", func(t *testing.T) {
		cases := []struct {
			name  string
			sev   logspb.SeverityNumber
			level string
		}{
			{name: "trace", sev: logspb.SeverityNumber_SEVERITY_NUMBER_TRACE, level: "debug"},
			{name: "debug", sev: logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG, level: "debug"},
			{name: "info", sev: logspb.SeverityNumber_SEVERITY_NUMBER_INFO, level: "info"},
			{name: "warn", sev: logspb.SeverityNumber_SEVERITY_NUMBER_WARN, level: "warn"},
			{name: "error", sev: logspb.SeverityNumber_SEVERITY_NUMBER_ERROR, level: "error"},
			{name: "fatal", sev: logspb.SeverityNumber_SEVERITY_NUMBER_FATAL, level: "error"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				entries, err := parseOTLPLogs(buildOTLPLogRequest(t, tc.sev, "test", "k", "v"))
				require.NoError(t, err)
				require.Equal(t, tc.level, entries[0].Level)
			})
		}
	})

	t.Run("invalid protobuf", func(t *testing.T) {
		_, err := parseOTLPLogs([]byte("not protobuf"))
		require.Error(t, err)
	})
}

func TestLogHandlers(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")

	t.Run("post ships otlp", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(cw)
		startTelemetry(t, ctx, telemetry)

		req := httptest.NewRequest(
			http.MethodPost,
			"/v1/logs",
			bytes.NewReader(
				buildOTLPLogRequest(
					t,
					logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
					"test",
					"k",
					"v",
				),
			),
		)
		req.Header.Set("Content-Type", "application/x-protobuf")
		w := httptest.NewRecorder()

		HandleLogsPost(telemetry.Logging)(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `{"accepted":1}`, w.Body.String())
		put := requireCloudWatchPutTo(t, cw, "/enclave/test/app/logs")
		require.Equal(t, "/enclave/test/app/logs", aws.ToString(put.LogGroupName))
		require.Len(t, put.LogEvents, 1)
		require.Contains(t, aws.ToString(put.LogEvents[0].Message), `"message":"test"`)
	})

	t.Run("post rejects unknown format", func(t *testing.T) {
		telemetry := NewTelemetry(newFakeCloudWatchLogs())
		logging := telemetry.Logging
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader([]byte("{}")))
		w := httptest.NewRecorder()

		HandleLogsPost(logging)(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.JSONEq(t, `{"error":"unknown Log Format"}`, w.Body.String())
	})
}

func TestLoggingShipsToCloudWatch(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_RETENTION_DAYS", "7")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")

	t.Run("flushes full batch", func(t *testing.T) {
		// Only the count threshold may flush here, or a slow run splits the batch.
		t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "1h")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(cw)
		startTelemetry(t, ctx, telemetry)

		now := time.Now().UTC()
		for i := 0; i < telemetryBatch; i++ {
			ts := now.Add(-time.Duration(i) * time.Second)
			telemetry.Send(signalLogs, ts, logEntry{
				ID:        fmt.Sprintf("id-%03d", i),
				Timestamp: ts.Format(time.RFC3339Nano),
				Level:     "info",
				Message:   fmt.Sprintf("msg-%03d", i),
				Source:    "app",
			})
		}

		put := requireCloudWatchPutTo(t, cw, "/enclave/test/app/logs")
		require.Equal(t, "/enclave/test/app/logs", aws.ToString(put.LogGroupName))
		require.Len(t, put.LogEvents, telemetryBatch)
		// The oldest event was sent last, so ordering put it first.
		require.Contains(t, aws.ToString(put.LogEvents[0].Message),
			fmt.Sprintf(`"message":"msg-%03d"`, telemetryBatch-1))
	})

	t.Run("flushes on shutdown", func(t *testing.T) {
		ctx := context.Background()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(cw)
		startTelemetry(t, ctx, telemetry)

		now := time.Now().UTC()
		telemetry.Send(signalLogs, now, logEntry{
			ID:        "one",
			Timestamp: now.Format(time.RFC3339Nano),
			Level:     "warn",
			Message:   "flush me",
			Source:    "app",
		})
		telemetry.Shutdown()

		put := requireCloudWatchPutTo(t, cw, "/enclave/test/app/logs")
		require.Len(t, put.LogEvents, 1)
		require.Contains(t, aws.ToString(put.LogEvents[0].Message), `"message":"flush me"`)
	})
}

func TestSlogHandler(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_SHIP_INTERVAL", "10ms")

	t.Run("ships the enclave own entry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		telemetry := NewTelemetry(cw)
		startTelemetry(t, ctx, telemetry)
		logger := slog.New(NewSlogHandler(telemetry.Logging)).With("component", "test")

		logger.Warn("test message", "key", "value")

		put := requireCloudWatchPutTo(t, cw, "/enclave/test/app/logs")
		require.NotEmpty(t, put.LogEvents)
		var entry logEntry
		require.NoError(t,
			json.Unmarshal([]byte(aws.ToString(put.LogEvents[0].Message)), &entry))
		require.Equal(t, "test message", entry.Message)
		require.Equal(t, "warn", entry.Level)
		require.Equal(t, "enclave", entry.Source)
		require.Equal(t, "test", entry.Attributes["component"])
		require.Equal(t, "value", entry.Attributes["key"])
	})

	t.Run("nil logging", func(t *testing.T) {
		handler := NewSlogHandler(nil)
		require.NotPanics(t, func() {
			err := handler.Handle(context.Background(), slog.Record{})
			require.NoError(t, err)
		})
	})
}

func TestSlogLevelToString(t *testing.T) {
	cases := []struct {
		name  string
		level slog.Level
		want  string
	}{
		{name: "debug", level: slog.LevelDebug, want: "debug"},
		{name: "info", level: slog.LevelInfo, want: "info"},
		{name: "warn", level: slog.LevelWarn, want: "warn"},
		{name: "error", level: slog.LevelError, want: "error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, slogLevelToString(tc.level))
		})
	}
}

func buildOTLPLogRequest(
	t *testing.T,
	severity logspb.SeverityNumber,
	body, attrKey, attrVal string,
) []byte {
	t.Helper()
	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{{
					Key:   "service.name",
					Value: stringValue("test"),
				}},
			},
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					TimeUnixNano:   uint64(time.Now().UnixNano()),
					SeverityNumber: severity,
					Body:           stringValue(body),
					Attributes: []*commonpb.KeyValue{{
						Key:   attrKey,
						Value: stringValue(attrVal),
					}},
				}},
			}},
		}},
	}
	data, err := proto.Marshal(req)
	require.NoError(t, err)
	return data
}

func startTelemetry(t *testing.T, ctx context.Context, telemetry *Telemetry) {
	t.Helper()
	before := slog.Default()
	t.Cleanup(func() {
		telemetry.Shutdown()
		slog.SetDefault(before)
	})
	done := make(chan error, 1)
	go func() { done <- telemetry.Start(ctx) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		require.FailNow(t, "Telemetry.Start did not return")
	}
}
