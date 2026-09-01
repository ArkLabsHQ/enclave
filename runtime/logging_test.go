package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
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

func TestLogBuffer(t *testing.T) {
	base := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

	t.Run("evicts oldest", func(t *testing.T) {
		buf := newLogBuffer(3)
		buf.add(
			logEntry{Timestamp: base.Add(time.Second).Format(time.RFC3339Nano), Message: "1"},
			logEntry{Timestamp: base.Add(2 * time.Second).Format(time.RFC3339Nano), Message: "2"},
			logEntry{Timestamp: base.Add(3 * time.Second).Format(time.RFC3339Nano), Message: "3"},
			logEntry{Timestamp: base.Add(4 * time.Second).Format(time.RFC3339Nano), Message: "4"},
		)

		entries := buf.query(time.Time{}, "", 0)
		require.Len(t, entries, 3)
		require.Equal(t, "2", entries[0].Message)
		require.Equal(t, "4", entries[2].Message)
		require.Equal(t, 3, buf.len())
	})

	t.Run("filters", func(t *testing.T) {
		buf := newLogBuffer(10)
		buf.add(
			logEntry{
				Timestamp: base.Add(time.Second).Format(time.RFC3339Nano),
				Level:     "debug",
				Message:   "debug",
			},
			logEntry{
				Timestamp: base.Add(2 * time.Second).Format(time.RFC3339Nano),
				Level:     "info",
				Message:   "info",
			},
			logEntry{
				Timestamp: base.Add(3 * time.Second).Format(time.RFC3339Nano),
				Level:     "warn",
				Message:   "warn",
			},
			logEntry{
				Timestamp: base.Add(4 * time.Second).Format(time.RFC3339Nano),
				Level:     "error",
				Message:   "error",
			},
		)

		entries := buf.query(base.Add(time.Second), "info", 2)
		require.Len(t, entries, 2)
		require.Equal(t, "warn", entries[0].Message)
		require.Equal(t, "error", entries[1].Message)
	})

	t.Run("empty returns slice", func(t *testing.T) {
		entries := newLogBuffer(1).query(time.Time{}, "", 0)
		require.NotNil(t, entries)
		require.Empty(t, entries)
	})

	t.Run("concurrent", func(t *testing.T) {
		buf := newLogBuffer(100)
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					buf.add(logEntry{Message: "concurrent"})
				}
			}()
		}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					_ = buf.query(time.Time{}, "", 10)
				}
			}()
		}
		wg.Wait()
		require.Equal(t, 100, buf.len())
	})
}

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
	t.Run("get filters buffer", func(t *testing.T) {
		logging := &Logging{buf: newLogBuffer(10)}
		logging.buf.add(
			logEntry{Level: "info", Message: "a", Source: "app"},
			logEntry{Level: "error", Message: "b", Source: "app"},
		)

		w := httptest.NewRecorder()
		handleLogsGet(
			logging,
		)(
			w,
			httptest.NewRequest(http.MethodGet, "/v1/logs?level=error", nil),
		)

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `[{
			"id":"",
			"timestamp":"",
			"level":"error",
			"message":"b",
			"source":"app"
		}]`, w.Body.String())
	})

	t.Run("post accepts otlp", func(t *testing.T) {
		logging := &Logging{buf: newLogBuffer(10)}
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

		HandleLogsPost(logging)(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, `{"accepted":1}`, w.Body.String())
		require.Equal(t, 1, logging.buf.len())
	})

	t.Run("post rejects unknown format", func(t *testing.T) {
		logging := &Logging{buf: newLogBuffer(10)}
		req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader([]byte("{}")))
		w := httptest.NewRecorder()

		HandleLogsPost(logging)(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.JSONEq(t, `{"error":"unknown Log Format"}`, w.Body.String())
	})
}

func TestLoggingStartCloudWatchExport(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "test")
	t.Setenv("ENCLAVE_APP_NAME", "app")
	t.Setenv("ENCLAVE_LOG_CLOUDWATCH", "true")
	t.Setenv("ENCLAVE_LOG_RETENTION_DAYS", "7")

	t.Run("disabled noops", func(t *testing.T) {
		cw := newFakeCloudWatchLogs()
		logging := &Logging{buf: newLogBuffer(1), cw: cw}

		require.NoError(t, logging.StartCloudWatchExport(context.Background()))
		require.Empty(t, cw.groups)
	})

	t.Run("returns setup error", func(t *testing.T) {
		sentinel := errors.New("create group failed")
		cw := newFakeCloudWatchLogs()
		cw.createLogGroupErr = sentinel
		logging := NewLogging(nil, cw)

		err := logging.StartCloudWatchExport(context.Background())
		require.ErrorIs(t, err, sentinel)
	})

	t.Run("returns after starting exporter", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		logging := NewLogging(nil, newFakeCloudWatchLogs())

		startCloudWatchExport(t, ctx, logging)
	})

	t.Run("flushes full batch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		logging := NewLogging(nil, cw)
		startCloudWatchExport(t, ctx, logging)

		for i := 0; i < 100; i++ {
			logging.shipCh <- logEntry{
				ID:        fmt.Sprintf("id-%03d", i),
				Timestamp: time.Unix(int64(100-i), 0).UTC().Format(time.RFC3339Nano),
				Level:     "info",
				Message:   fmt.Sprintf("msg-%03d", i),
				Source:    "app",
			}
		}

		put := requireCloudWatchPut(t, cw)
		require.Equal(t, "/enclave/test/app/logs", aws.ToString(put.LogGroupName))
		require.Len(t, put.LogEvents, 100)
		require.JSONEq(t, `{
			"id":"id-099",
			"timestamp":"1970-01-01T00:00:01Z",
			"level":"info",
			"message":"msg-099",
			"source":"app"
		}`, aws.ToString(put.LogEvents[0].Message))
	})

	t.Run("flushes on close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cw := newFakeCloudWatchLogs()
		logging := NewLogging(nil, cw)
		startCloudWatchExport(t, ctx, logging)

		logging.shipCh <- logEntry{
			ID:        "one",
			Timestamp: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
			Level:     "warn",
			Message:   "flush me",
			Source:    "app",
		}
		close(logging.shipCh)

		put := requireCloudWatchPut(t, cw)
		require.Len(t, put.LogEvents, 1)
		require.JSONEq(t, `{
			"id":"one",
			"timestamp":"1970-01-01T00:00:01Z",
			"level":"warn",
			"message":"flush me",
			"source":"app"
		}`, aws.ToString(put.LogEvents[0].Message))
	})
}

func TestBufferHandler(t *testing.T) {
	t.Run("writes supervisor entry", func(t *testing.T) {
		buf := newLogBuffer(10)
		shipCh := make(chan logEntry, 1)
		logger := slog.New(NewBufferHandler(&Logging{buf: buf, shipCh: shipCh})).
			With("component", "test")

		logger.Warn("test message", "key", "value")

		entries := buf.query(time.Time{}, "", 0)
		require.Len(t, entries, 1)
		require.Equal(t, "test message", entries[0].Message)
		require.Equal(t, "warn", entries[0].Level)
		require.Equal(t, "supervisor", entries[0].Source)
		require.Equal(t, "test", entries[0].Attributes["component"])
		require.Equal(t, "value", entries[0].Attributes["key"])
		require.Equal(t, entries[0].ID, (<-shipCh).ID)
	})

	t.Run("nil logging", func(t *testing.T) {
		handler := NewBufferHandler(nil)
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
					TimeUnixNano:   uint64(time.Unix(1, 0).UnixNano()),
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

func startCloudWatchExport(t *testing.T, ctx context.Context, logging *Logging) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- logging.StartCloudWatchExport(ctx) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		require.FailNow(t, "StartCloudWatchExport did not return")
	}
}
